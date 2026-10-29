//! UDP через TUN.
//!
//! Датаграмма приходит готовым IPv4-пакетом, поэтому получатель известен из
//! заголовка — в отличие от TPROXY, где его приходится доставать из
//! контрольного сообщения. Поток (четвёрка адрес/порт) получает свой канал и
//! задачу: она открывает UDP-сессию outbound'а, отправляет датаграммы и
//! возвращает ответы в TUN отдельными пакетами.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::packet::{self, Ipv4};
use super::{FlowKey, TunIo, UdpRegistry};
use crate::engine::router::Engine;
use crate::engine::rules::{Decision, Flow, Target};

/// Сколько живёт UDP-поток без единой датаграммы в любую сторону.
const UDP_IDLE: Duration = Duration::from_secs(60);

pub(crate) struct UdpFlows {
    map: UdpRegistry,
}

impl UdpFlows {
    pub(crate) fn new() -> Self {
        Self {
            map: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    pub(crate) async fn dispatch(
        &self,
        pkt: Ipv4<'_>,
        io: &Arc<TunIo>,
        engine: &Arc<Engine>,
        cancel: &CancellationToken,
        joins: &mut JoinSet<()>,
    ) {
        let Some(udp) = packet::parse_udp(pkt.payload) else {
            return;
        };
        let key: FlowKey = (pkt.src, udp.src_port, pkt.dst, udp.dst_port);
        let data = udp.payload.to_vec();

        // DNS с правилом HIJACK-DNS отвечаем локально: наружу запрос не
        // уходит, приложение получает настоящий адрес сразу. Остальные
        // DNS-запросы идут обычным путём через outbound — это и есть
        // redir-host: настоящий ответ, а карту «IP → домен» заполняет
        // `remember_response` в потоке ниже.
        if udp.dst_port == 53 && answer_hijacked_dns(engine, io, pkt, udp, &data).await {
            return;
        }

        let mut map = self.map.lock().await;
        if let Some(tx) = map.get(&key) {
            // Очередь переполнена — поток не успевает; начинаем заново,
            // иначе датаграммы будут теряться молча.
            if tx.try_send(data.clone()).is_ok() {
                return;
            }
            map.remove(&key);
        }
        let (tx, rx) = mpsc::channel(64);
        map.insert(key, tx);
        drop(map);

        joins.spawn(flow(
            engine.clone(),
            io.clone(),
            cancel.clone(),
            self.map.clone(),
            key,
            rx,
            data,
        ));
    }
}

/// Если правило требует `HIJACK-DNS`, отвечает на запрос локально и
/// возвращает `true`: наружу ничего не уходит, поток не создаётся.
///
/// Иначе — `false`, и запрос идёт обычным UDP-потоком через outbound; ответ
/// на него попадёт в карту «IP → домен» в [`flow`].
async fn answer_hijacked_dns(
    engine: &Arc<Engine>,
    io: &Arc<TunIo>,
    pkt: Ipv4<'_>,
    udp: packet::Udp<'_>,
    query: &[u8],
) -> bool {
    let flow = Flow {
        dst_ip: Some(IpAddr::V4(pkt.dst)),
        dst_port: udp.dst_port,
        src_port: udp.src_port,
        is_tcp: false,
        ..Default::default()
    };
    if !matches!(engine.route(&flow).0, Decision::HijackDns) {
        return false;
    }
    let response = engine.dns.answer_query(query).await;
    engine.stats.add_up(query.len() as u64);
    engine.stats.add_down(response.len() as u64);
    let reply = packet::build_udp(pkt.dst, pkt.src, udp.dst_port, udp.src_port, &response);
    if let Err(e) = io.write(&reply).await {
        tracing::debug!(error = %e, "TUN/DNS: ответ не записан в устройство");
    }
    true
}

/// Один UDP-поток: своя сессия outbound'а и свои ответы в TUN.
async fn flow(
    engine: Arc<Engine>,
    io: Arc<TunIo>,
    cancel: CancellationToken,
    map: UdpRegistry,
    key: FlowKey,
    mut rx: mpsc::Receiver<Vec<u8>>,
    first: Vec<u8>,
) {
    let (src_ip, src_port, dst_ip, dst_port) = key;
    let mut flow = Flow {
        dst_ip: Some(IpAddr::V4(dst_ip)),
        dst_port,
        src_port,
        is_tcp: false,
        ..Default::default()
    };
    // Приложение уже разрешило имя: ответ перехвачен и запомнен, поэтому
    // правило по домену должно сработать и для датаграммы по адресу.
    engine.enrich_domain(&mut flow);
    let (decision, label, rule) = engine.route(&flow);
    if matches!(decision, Decision::Reject | Decision::RejectDrop) {
        tracing::debug!(dst = %dst_ip, dst_port, "TUN/UDP: отклонено правилом");
        map.lock().await.remove(&key);
        return;
    }
    let label = label.unwrap_or_else(|| "DIRECT".to_string());
    let Some(ob) = engine.resolve_outbound(&label) else {
        map.lock().await.remove(&key);
        return;
    };
    let Some(session) = engine.open_udp(&ob).await else {
        // Не все outbound'ы умеют UDP. Честно пишем: приложение получит
        // таймаут и само решит, переходить ли на TCP.
        tracing::debug!(outbound = %ob.name(), dst = %dst_ip, dst_port, "TUN/UDP: outbound не умеет UDP, датаграмма отброшена");
        map.lock().await.remove(&key);
        return;
    };
    let target = Target::from_flow(&flow);
    let limiter = engine
        .outbound_limits
        .get(ob.name())
        .and_then(|l| l.rate.clone());

    if let Some(l) = limiter.as_deref() {
        l.acquire(first.len() as u64).await;
    }
    if session.send_to(&first, &target).await.is_err() {
        map.lock().await.remove(&key);
        return;
    }
    engine.stats.add_up(first.len() as u64);

    // Сумму пишем в breakdown один раз при закрытии потока.
    let mut bytes = first.len() as u64;
    let mut buf = vec![0u8; 65_535];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(UDP_IDLE) => break,
            next = rx.recv() => match next {
                Some(data) => {
                    if let Some(l) = limiter.as_deref() {
                        l.acquire(data.len() as u64).await;
                    }
                    if session.send_to(&data, &target).await.is_err() {
                        break;
                    }
                    engine.stats.add_up(data.len() as u64);
                    bytes += data.len() as u64;
                }
                None => break,
            },
            got = session.recv_from(&mut buf, UDP_IDLE) => match got {
                Ok((n, _from)) => {
                    // Ответ DNS — единственное место, где видно соответствие
                    // «адрес → домен». Запоминаем его до пересылки, чтобы
                    // следующее соединение по этому адресу уже знало имя.
                    if dst_port == 53 {
                        engine.dns.remember_response(&buf[..n]);
                    }
                    engine.stats.add_down(n as u64);
                    bytes += n as u64;
                    // Ответ собираем сами: адрес источника — настоящий
                    // получатель, адрес назначения — приложение.
                    let reply = packet::build_udp(dst_ip, src_ip, dst_port, src_port, &buf[..n]);
                    if io.write(&reply).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    engine.breakdown.record(&rule, ob.name(), bytes);
    map.lock().await.remove(&key);
}
