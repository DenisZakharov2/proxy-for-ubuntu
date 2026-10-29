//! TCP через TUN: минимальный пользовательский стек.
//!
//! Ядро считает, что соединение установлено с настоящим сервером, и ведёт
//! обычный TCP. Мы отвечаем за другую половину: принимаем сегменты из TUN,
//! подтверждаем их, отдаём полезную нагрузку в исходящее соединение движка и
//! заворачиваем ответы обратно в сегменты.
//!
//! Что реализовано сознательно просто (и чего здесь нет):
//! * окно не масштабируется (нет window scaling), максимум 65535 байт;
//! * нет SACK, таймстампов и выборочных подтверждений;
//! * сегменты вне очереди не буферизуются — подтверждаем только принятое
//!   подряд, отправитель переспросит;
//! * повторная передача — по таймеру на каждый неподтверждённый сегмент,
//!   без вычисления RTT (RTO удваивается при каждом повторе).
//!
//! Этого достаточно для HTTP и прочего обычного трафика; для потерь пакетов
//! схема работает медленнее полноценного стека, но корректно.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use super::packet::{self, TcpOut, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN};
use super::{FlowKey, TunIo};
use crate::engine::router::{Engine, RateLimiter};
use crate::engine::rules::{Flow, Target};

/// Окно, которое объявляем приложению. Без масштабирования больше нельзя.
const RCV_WINDOW: u16 = 65_535;
/// Стартовый таймаут повтора. RTT не измеряем: при повторе удваиваем.
const BASE_RTO: Duration = Duration::from_millis(300);
const MAX_RTO: Duration = Duration::from_secs(5);
const MAX_RETRIES: u8 = 6;
/// Предел неподтверждённых сегментов: ограничивает память на соединение.
const MAX_UNACKED: usize = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Сегмент, пришедший из TUN.
pub(crate) struct Segment {
    flags: u8,
    seq: u32,
    ack: u32,
    window: u16,
    payload: Vec<u8>,
}

pub(crate) struct TcpFlows {
    map: Arc<tokio::sync::Mutex<HashMap<FlowKey, mpsc::Sender<Segment>>>>,
}

impl TcpFlows {
    pub(crate) fn new() -> Self {
        Self {
            map: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        }
    }

    pub(crate) async fn dispatch(
        &self,
        pkt: packet::Ipv4<'_>,
        io: &Arc<TunIo>,
        engine: &Arc<Engine>,
        cancel: &CancellationToken,
        joins: &mut JoinSet<()>,
    ) {
        let Some(tcp) = packet::parse_tcp(pkt.payload) else {
            return;
        };
        let key: FlowKey = (pkt.src, tcp.src_port, pkt.dst, tcp.dst_port);
        let seg = Segment {
            flags: tcp.flags,
            seq: tcp.seq,
            ack: tcp.ack,
            window: tcp.window,
            payload: tcp.payload.to_vec(),
        };

        let mut map = self.map.lock().await;
        if let Some(tx) = map.get(&key) {
            // Переполнение канала — не повод рвать соединение: TCP сам
            // переспросит неподтверждённый сегмент.
            let _ = tx.try_send(seg);
            return;
        }
        let is_syn = seg.flags & TCP_SYN != 0 && seg.flags & TCP_ACK == 0;
        if is_syn {
            let (tx, rx) = mpsc::channel(128);
            map.insert(key, tx);
            drop(map);
            joins.spawn(conn(
                engine.clone(),
                io.clone(),
                cancel.clone(),
                self.map.clone(),
                key,
                rx,
                seg,
                tcp.mss.unwrap_or(536),
            ));
        } else {
            drop(map);
            // Сегмент не для существующего соединения — отвечаем RST, иначе
            // приложение будет ждать до таймаута.
            let peer_ack = seg
                .seq
                .wrapping_add(seg.payload.len() as u32)
                .wrapping_add(u32::from(seg.flags & TCP_SYN != 0));
            let rst = packet::build_tcp(
                pkt.dst,
                pkt.src,
                &TcpOut {
                    src_port: tcp.dst_port,
                    dst_port: tcp.src_port,
                    seq: seg.ack,
                    ack: peer_ack,
                    flags: TCP_RST | TCP_ACK,
                    window: 0,
                    mss: None,
                    payload: &[],
                },
            );
            let _ = io.write(&rst).await;
        }
    }
}

enum Action {
    Continue,
    Close,
}

struct OutSeg {
    seq: u32,
    /// Первый порядковый номер за пределами сегмента (FIN занимает один).
    end: u32,
    flags: u8,
    data: Vec<u8>,
    sent_at: Instant,
    retries: u8,
}

struct Conn {
    /// Адрес и порт приложения (наша «вторая половина» соединения).
    app_ip: std::net::Ipv4Addr,
    app_port: u16,
    /// Настоящий получатель — он же адрес источника в наших пакетах.
    remote_ip: std::net::Ipv4Addr,
    remote_port: u16,

    /// Начальный порядковый номер (ISS). Нужен, чтобы повторный SYN получил
    /// тот же SYN-ACK, даже когда snd_una уже ушёл вперёд.
    iss: u32,
    snd_una: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    app_wnd: u32,
    peer_mss: usize,

    unacked: VecDeque<OutSeg>,
    rto: Duration,
    last_activity: Instant,

    fin_sent: bool,
    app_fin: bool,
    upstream_eof: bool,

    bytes_up: u64,
    bytes_down: u64,
    rule: String,
    limiter: Option<Arc<RateLimiter>>,
}

#[allow(clippy::too_many_arguments)]
async fn conn(
    engine: Arc<Engine>,
    io: Arc<TunIo>,
    cancel: CancellationToken,
    map: Arc<tokio::sync::Mutex<HashMap<FlowKey, mpsc::Sender<Segment>>>>,
    key: FlowKey,
    mut rx: mpsc::Receiver<Segment>,
    syn: Segment,
    peer_mss: u16,
) {
    let (app_ip, app_port, remote_ip, remote_port) = key;
    let flow = Flow {
        dst_ip: Some(IpAddr::V4(remote_ip)),
        dst_port: remote_port,
        src_port: app_port,
        is_tcp: true,
        ..Default::default()
    };
    let target = Target::from_flow(&flow);
    let (ob, mut upstream, rule) = match engine.open(&target, &flow).await {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(target = %target.key(), error = %e, "TUN/TCP: соединение не открыто");
            send_rst(&io, app_ip, app_port, remote_ip, remote_port, &syn).await;
            map.lock().await.remove(&key);
            return;
        }
    };

    // MSS ограничиваем и тем, что объявило приложение, и нашим MTU: больше
    // одного пакета TUN всё равно не пролезет.
    let tun_mss = engine.config.tun.mtu.saturating_sub(40) as usize;
    let peer_mss = (peer_mss as usize).clamp(536, 1460).min(tun_mss).max(536);

    let iss: u32 = rand::random();
    let mut c = Conn {
        app_ip,
        app_port,
        remote_ip,
        remote_port,
        iss,
        snd_una: iss,
        snd_nxt: iss.wrapping_add(1),
        rcv_nxt: syn.seq.wrapping_add(1),
        app_wnd: syn.window as u32,
        peer_mss,
        unacked: VecDeque::new(),
        rto: BASE_RTO,
        last_activity: Instant::now(),
        fin_sent: false,
        app_fin: false,
        upstream_eof: false,
        bytes_up: 0,
        bytes_down: 0,
        rule,
        limiter: engine
            .outbound_limits
            .get(ob.name())
            .and_then(|l| l.rate.clone()),
    };

    if let Err(e) = c
        .send(
            &io,
            TCP_SYN | TCP_ACK,
            iss,
            c.rcv_nxt,
            Some(peer_mss as u16),
            &[],
        )
        .await
    {
        tracing::debug!(error = %e, "TUN/TCP: не удалось отправить SYN-ACK");
        map.lock().await.remove(&key);
        engine.stats.conn_closed();
        return;
    }

    let mut ticker = tokio::time::interval(Duration::from_millis(100));
    let mut rbuf = vec![0u8; peer_mss];
    loop {
        // Читать из outbound'а можно, только если приложение готово принять
        // данные: иначе мы завалим его окно.
        let in_flight = c.snd_nxt.wrapping_sub(c.snd_una);
        let can_read = !c.fin_sent
            && !c.upstream_eof
            && c.app_wnd > in_flight
            && c.unacked.len() < MAX_UNACKED;
        tokio::select! {
            _ = cancel.cancelled() => break,
            seg = rx.recv() => {
                let Some(seg) = seg else { break };
                match c.on_segment(&io, seg, &mut upstream).await {
                    Ok(Action::Continue) => {}
                    Ok(Action::Close) => break,
                    Err(e) => {
                        tracing::debug!(error = %e, "TUN/TCP: соединение оборвалось");
                        break;
                    }
                }
            }
            n = upstream.read(&mut rbuf), if can_read => {
                match n {
                    Ok(0) => {
                        c.upstream_eof = true;
                        // Полузакрытие: приложение ещё может слать данные,
                        // но ему пора узнать, что ответа больше не будет.
                        if !c.fin_sent && c.send_fin(&io).await.is_err() {
                            break;
                        }
                    }
                    Ok(n) => {
                        if c.send_data(&io, &rbuf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "TUN/TCP: чтение из outbound не удалось");
                        break;
                    }
                }
            }
            _ = ticker.tick() => {
                if c.should_close() {
                    break;
                }
                if c.retransmit(&io).await.is_err() {
                    break;
                }
                if c.last_activity.elapsed() > IDLE_TIMEOUT {
                    tracing::debug!(target = %target.key(), "TUN/TCP: поток простаивает, закрываем");
                    break;
                }
            }
        }
    }

    engine.stats.add_up(c.bytes_up);
    engine.stats.add_down(c.bytes_down);
    engine
        .breakdown
        .record(&c.rule, ob.name(), c.bytes_up + c.bytes_down);
    engine.stats.conn_closed();
    map.lock().await.remove(&key);
}

impl Conn {
    async fn send(
        &self,
        io: &TunIo,
        flags: u8,
        seq: u32,
        ack: u32,
        mss: Option<u16>,
        payload: &[u8],
    ) -> io::Result<()> {
        let pkt = packet::build_tcp(
            self.remote_ip,
            self.app_ip,
            &TcpOut {
                src_port: self.remote_port,
                dst_port: self.app_port,
                seq,
                ack,
                flags,
                window: RCV_WINDOW,
                mss,
                payload,
            },
        );
        io.write(&pkt).await
    }

    async fn send_data(&mut self, io: &TunIo, data: &[u8]) -> io::Result<()> {
        if let Some(l) = self.limiter.as_deref() {
            l.acquire(data.len() as u64).await;
        }
        let seq = self.snd_nxt;
        let flags = TCP_ACK | TCP_PSH;
        self.send(io, flags, seq, self.rcv_nxt, None, data).await?;
        self.unacked.push_back(OutSeg {
            seq,
            end: seq.wrapping_add(data.len() as u32),
            flags,
            data: data.to_vec(),
            sent_at: Instant::now(),
            retries: 0,
        });
        self.snd_nxt = self.snd_nxt.wrapping_add(data.len() as u32);
        self.bytes_down += data.len() as u64;
        self.last_activity = Instant::now();
        Ok(())
    }

    async fn send_fin(&mut self, io: &TunIo) -> io::Result<()> {
        let seq = self.snd_nxt;
        let flags = TCP_FIN | TCP_ACK;
        self.send(io, flags, seq, self.rcv_nxt, None, &[]).await?;
        self.unacked.push_back(OutSeg {
            seq,
            end: seq.wrapping_add(1),
            flags,
            data: Vec::new(),
            sent_at: Instant::now(),
            retries: 0,
        });
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        self.fin_sent = true;
        self.last_activity = Instant::now();
        Ok(())
    }

    async fn on_segment(
        &mut self,
        io: &TunIo,
        seg: Segment,
        upstream: &mut Box<dyn crate::engine::outbound::AsyncReadWrite>,
    ) -> io::Result<Action> {
        self.last_activity = Instant::now();
        if seg.flags & TCP_RST != 0 {
            return Ok(Action::Close);
        }
        if seg.flags & TCP_SYN != 0 {
            // Повторный SYN — наш SYN-ACK потерялся. Отвечаем тем же seq.
            self.send(
                io,
                TCP_SYN | TCP_ACK,
                self.iss,
                self.rcv_nxt,
                Some(self.peer_mss as u16),
                &[],
            )
            .await?;
            return Ok(Action::Continue);
        }

        if seg.flags & TCP_ACK != 0 {
            self.app_wnd = seg.window as u32;
            let ack = seg.ack;
            if seq_lt(self.snd_una, ack) && seq_le(ack, self.snd_nxt) {
                self.snd_una = ack;
                while let Some(front) = self.unacked.front() {
                    if seq_le(front.end, ack) {
                        self.unacked.pop_front();
                    } else {
                        break;
                    }
                }
                self.rto = BASE_RTO;
            }
        }

        if !seg.payload.is_empty() {
            if seg.seq == self.rcv_nxt {
                if let Some(l) = self.limiter.as_deref() {
                    l.acquire(seg.payload.len() as u64).await;
                }
                upstream.write_all(&seg.payload).await?;
                upstream.flush().await.ok();
                self.rcv_nxt = self.rcv_nxt.wrapping_add(seg.payload.len() as u32);
                self.bytes_up += seg.payload.len() as u64;
                self.ack(io).await?;
            } else {
                // Дубль или разрыв: подтверждаем только принятое подряд,
                // остальное отправитель переспросит.
                self.ack(io).await?;
            }
        }

        if seg.flags & TCP_FIN != 0 {
            let fin_seq = seg.seq.wrapping_add(seg.payload.len() as u32);
            if fin_seq == self.rcv_nxt {
                self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                self.ack(io).await?;
                self.app_fin = true;
                // Приложение больше не будет писать: закрываем свою половину,
                // чтобы сервер увидел EOF.
                let _ = upstream.shutdown().await;
            }
        }

        Ok(Action::Continue)
    }

    async fn ack(&self, io: &TunIo) -> io::Result<()> {
        self.send(io, TCP_ACK, self.snd_nxt, self.rcv_nxt, None, &[])
            .await
    }

    fn should_close(&self) -> bool {
        self.app_fin && self.upstream_eof && self.snd_una == self.snd_nxt
    }

    async fn retransmit(&mut self, io: &TunIo) -> io::Result<()> {
        let now = Instant::now();
        let mut resend: Vec<(u8, u32, Vec<u8>)> = Vec::new();
        let mut expired = Vec::new();
        for seg in &self.unacked {
            if now.duration_since(seg.sent_at) >= self.rto {
                if seg.retries >= MAX_RETRIES {
                    return Err(io::Error::other(
                        "сегмент не подтверждён после всех повторов",
                    ));
                }
                resend.push((seg.flags, seg.seq, seg.data.clone()));
                expired.push(seg.seq);
            }
        }
        if resend.is_empty() {
            return Ok(());
        }
        for (flags, seq, data) in resend {
            self.send(io, flags, seq, self.rcv_nxt, None, &data).await?;
        }
        for seg in &mut self.unacked {
            if expired.contains(&seg.seq) {
                seg.sent_at = now;
                seg.retries += 1;
            }
        }
        self.rto = (self.rto * 2).min(MAX_RTO);
        Ok(())
    }
}

/// RST в ответ на SYN, когда соединение открыть не удалось (REJECT, нет
/// outbound'а, сервер недоступен). Приложение получает отказ сразу, а не
/// ждёт таймаут.
async fn send_rst(
    io: &TunIo,
    app_ip: std::net::Ipv4Addr,
    app_port: u16,
    remote_ip: std::net::Ipv4Addr,
    remote_port: u16,
    syn: &Segment,
) {
    let ack = syn.seq.wrapping_add(1);
    let rst = packet::build_tcp(
        remote_ip,
        app_ip,
        &TcpOut {
            src_port: remote_port,
            dst_port: app_port,
            seq: 0,
            ack,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            mss: None,
            payload: &[],
        },
    );
    let _ = io.write(&rst).await;
}

/// Сравнение порядковых номеров по модулю 2^32 (RFC 1982).
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

fn seq_le(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_comparison_wraps() {
        assert!(seq_lt(1, 2));
        assert!(!seq_lt(2, 1));
        assert!(seq_lt(u32::MAX, 0));
        assert!(!seq_lt(0, u32::MAX));
        assert!(seq_le(5, 5));
        assert!(seq_le(5, 6));
        assert!(!seq_le(6, 5));
    }

    fn conn() -> Conn {
        Conn {
            app_ip: "198.18.0.1".parse().unwrap(),
            app_port: 40000,
            remote_ip: "93.184.216.34".parse().unwrap(),
            remote_port: 443,
            iss: 100,
            snd_una: 100,
            snd_nxt: 100,
            rcv_nxt: 500,
            app_wnd: 65535,
            peer_mss: 1460,
            unacked: VecDeque::new(),
            rto: BASE_RTO,
            last_activity: Instant::now(),
            fin_sent: false,
            app_fin: false,
            upstream_eof: false,
            bytes_up: 0,
            bytes_down: 0,
            rule: "FINAL".into(),
            limiter: None,
        }
    }

    #[test]
    fn close_requires_both_directions_and_acked_fin() {
        let mut c = conn();
        c.snd_nxt = 101;
        c.snd_una = 100;
        assert!(!c.should_close());
        c.app_fin = true;
        c.upstream_eof = true;
        // Наш FIN ещё не подтверждён.
        assert!(!c.should_close());
        c.snd_una = 101;
        assert!(c.should_close());
    }

    #[test]
    fn acked_segments_are_trimmed_from_the_queue() {
        let mut c = conn();
        c.unacked.push_back(OutSeg {
            seq: 100,
            end: 110,
            flags: TCP_ACK,
            data: vec![0; 10],
            sent_at: Instant::now(),
            retries: 0,
        });
        c.unacked.push_back(OutSeg {
            seq: 110,
            end: 120,
            flags: TCP_ACK,
            data: vec![0; 10],
            sent_at: Instant::now(),
            retries: 0,
        });
        c.snd_nxt = 120;
        c.snd_una = 110;
        while let Some(front) = c.unacked.front() {
            if seq_le(front.end, 110) {
                c.unacked.pop_front();
            } else {
                break;
            }
        }
        assert_eq!(c.unacked.len(), 1);
        assert_eq!(c.unacked.front().unwrap().seq, 110);
    }
}
