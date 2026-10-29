//! Слушатели перехваченного трафика.
//!
//! Ядро отдаёт сюда соединения двумя путями:
//! * TCP — nat `redirect to :15000`; настоящий получатель читается из
//!   `SO_ORIGINAL_DST` уже принятого сокета.
//! * UDP — `tproxy to :15001` в prerouting (форвардинг, например Docker);
//!   настоящий получатель приходит контрольным сообщением `IP_ORIGDSTADDR`.
//!
//! Локальный UDP так перехватить нельзя: REDIRECT переписывает адрес
//! получателя, и вернуть его из сокета нечем. Локальный UDP идёт напрямую.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::Interest;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{TcpMode, UdpMode};
use crate::engine::router::{self, Engine};
use crate::engine::rules::{Decision, Flow, Target};
use crate::error::{Error, Result};
use crate::paths;

/// Настоящий адрес получателя у соединения, переписанного REDIRECT'ом.
/// В libc константы нет: это `SOL_IP`-опция номер 80.
const SO_ORIGINAL_DST: libc::c_int = 80;
/// Отдать настоящий адрес получателя в контрольном сообщении (`SOL_IP`).
const IP_RECVORIGDSTADDR: libc::c_int = 20;
/// Настоящий адрес получателя в контрольном сообщении.
const IP_ORIGDSTADDR: libc::c_int = 20;

/// Сколько живёт UDP-поток без единой датаграммы в любую сторону.
const UDP_IDLE: Duration = Duration::from_secs(60);

/// Запущенные слушатели. `stop`/`Drop` закрывают порты: после отключения
/// перехвата приложение не оставляет открытых сокетов.
pub struct Capture {
    tasks: Vec<JoinHandle<()>>,
    /// TUN-стек, если он включён в конфиге. Живёт вместе со слушателями:
    /// без него правила увели бы TCP в устройство, которое никто не читает.
    tun: Option<super::tun::Tun>,
    /// Общий признак остановки. По нему завершаются не только циклы приёма,
    /// но и уже открытые UDP-потоки: каждый держит `Arc<UdpSocket>` и без
    /// этого жил бы до истечения `UDP_IDLE`, не давая закрыть порт 15001.
    cancel: CancellationToken,
}

impl Capture {
    /// Останавливает слушатели и дожидается, пока задачи отпустят сокеты:
    /// повторный `start` (SIGHUP, повторный `connect`) должен найти порты
    /// свободными. TUN останавливается последним — сначала отменяем потоки,
    /// которые пишут в устройство.
    pub async fn stop(&mut self) {
        tracing::info!("слушатели перехвата останавливаются");
        self.abort();
        for t in self.tasks.drain(..) {
            let _ = t.await;
        }
        if let Some(mut tun) = self.tun.take() {
            tun.stop().await;
        }
    }

    fn abort(&mut self) {
        self.cancel.cancel();
        for t in self.tasks.drain(..) {
            t.abort();
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.abort();
    }
}

/// Поднимает слушатели под текущий конфиг. Ошибка (занятый порт) приходит
/// до применения правил, поэтому система остаётся нетронутой.
pub async fn start(engine: Arc<Engine>) -> Result<Capture> {
    let cancel = CancellationToken::new();
    let mut tasks = Vec::new();
    let mut tun = None;

    // TUN первым: он создаёт устройство и маршрут в таблице 101. Если
    // дальше не получится занять порт, устройство снимается ниже — иначе
    // правила увели бы трафик в интерфейс, который никто не читает.
    if engine.config.tun.enabled {
        tun = Some(super::tun::Tun::start(engine.clone()).await?);
    }

    let listeners: Result<()> = async {
        if engine.config.intercept.tcp != TcpMode::Off {
            let port = paths::redirect_port();
            let listener = TcpListener::bind(("0.0.0.0", port)).await.map_err(|e| {
                Error::Internal(format!(
                    "не удалось занять порт {port} для перехвата TCP: {e}"
                ))
            })?;
            tasks.push(tokio::spawn(tcp_loop(
                engine.clone(),
                listener,
                cancel.clone(),
            )));
        }

        if engine.config.intercept.udp != UdpMode::Off {
            let sock = Arc::new(udp_socket(paths::tproxy_port())?);
            tasks.push(tokio::spawn(udp_loop(engine.clone(), sock, cancel.clone())));
        }
        Ok(())
    }
    .await;

    if let Err(e) = listeners {
        if let Some(mut started) = tun.take() {
            started.stop().await;
        }
        return Err(e);
    }

    tracing::info!(
        listeners = tasks.len(),
        tun = tun.is_some(),
        "перехват включён"
    );
    Ok(Capture { tasks, tun, cancel })
}

// ─────────────────────────────────── TCP ───────────────────────────────────

async fn tcp_loop(engine: Arc<Engine>, listener: TcpListener, cancel: CancellationToken) {
    // Под нагрузкой accept ошибается каждые несколько миллисекунд (EMFILE):
    // без паузы и ограничения частоты журнал распухает на десятки тысяч строк
    // и хоронит остальные сообщения.
    let mut last_log: Option<std::time::Instant> = None;

    loop {
        let accepted = tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((client, peer)) => {
                tokio::spawn(tcp_conn(engine.clone(), client, peer, cancel.clone()));
            }
            Err(e) => {
                let exhausted = matches!(e.raw_os_error(), Some(libc::EMFILE | libc::ENFILE));
                let now = std::time::Instant::now();
                let should_log = match last_log {
                    Some(t) => now.duration_since(t) >= Duration::from_secs(1),
                    None => true,
                };
                if should_log {
                    if exhausted {
                        tracing::warn!(
                            error = %e,
                            "accept: кончились файловые дескрипторы — пауза 1 с, проверьте LimitNOFILE"
                        );
                    } else {
                        tracing::warn!(error = %e, "не удалось принять перехваченное соединение");
                    }
                    last_log = Some(now);
                }
                let pause = if exhausted {
                    Duration::from_secs(1)
                } else {
                    Duration::from_millis(50)
                };
                tokio::time::sleep(pause).await;
            }
        }
    }
}

async fn tcp_conn(
    engine: Arc<Engine>,
    client: TcpStream,
    peer: SocketAddr,
    cancel: CancellationToken,
) {
    let Some(dst) = original_dst(&client) else {
        tracing::warn!(%peer, "не удалось узнать настоящий адрес получателя");
        return;
    };
    // Если правило почему-то завернуло собственный сокет демона — не петляем.
    if dst.ip().is_loopback() && dst.port() == paths::redirect_port() {
        return;
    }

    let mut flow = Flow {
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        src_port: peer.port(),
        is_tcp: true,
        ..Default::default()
    };
    // Домен из перехваченного DNS: приложение шло по адресу, правило —
    // по имени.
    engine.enrich_domain(&mut flow);
    let target = Target::from_flow(&flow);

    let (ob, upstream, rule) = match engine.open(&target, &flow).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(target = %target.key(), error = %e, "перехваченное соединение не открыто");
            return;
        }
    };

    let limiter = engine
        .outbound_limits
        .get(ob.name())
        .and_then(|l| l.rate.clone());
    let stats = &engine.stats;
    let relay = router::relay(
        client,
        upstream,
        |up, down| {
            stats.add_up(up);
            stats.add_down(down);
        },
        limiter.as_deref(),
    );
    tokio::pin!(relay);
    let relayed = tokio::select! {
        r = &mut relay => Some(r),
        // Выключение перехвата обрывает и уже открытые соединения: иначе они
        // продолжали бы идти через демон после `disconnect`.
        _ = cancel.cancelled() => None,
    };
    engine.stats.conn_closed();

    match relayed {
        Some(Ok((up, down))) => {
            // Статистика по правилам: раньше `Breakdown::record` вызывался
            // только в тестах, и `metrics.live` всегда отдавал пустые блоки.
            engine.breakdown.record(&rule, ob.name(), up + down);
            tracing::debug!(
                target = %target.key(), outbound = ob.name(), up, down, "соединение закрыто"
            )
        }
        Some(Err(e)) => {
            tracing::debug!(target = %target.key(), error = %e, "соединение оборвалось")
        }
        None => tracing::debug!(target = %target.key(), "соединение закрыто выключением перехвата"),
    }
}

/// Настоящий получатель соединения, переписанного REDIRECT'ом.
fn original_dst(stream: &TcpStream) -> Option<SocketAddr> {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut libc::sockaddr_in as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return None;
    }
    Some(sockaddr_to_addr(&addr))
}

fn sockaddr_to_addr(addr: &libc::sockaddr_in) -> SocketAddr {
    let ip = Ipv4Addr::from(addr.sin_addr.s_addr.to_ne_bytes());
    SocketAddr::new(IpAddr::V4(ip), u16::from_be(addr.sin_port))
}

fn addr_to_sockaddr(addr: SocketAddr) -> libc::sockaddr_in {
    let mut out: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    out.sin_family = libc::AF_INET as libc::sa_family_t;
    out.sin_port = addr.port().to_be();
    if let IpAddr::V4(ip) = addr.ip() {
        out.sin_addr.s_addr = u32::from_ne_bytes(ip.octets());
    }
    out
}

// ─────────────────────────────────── UDP ───────────────────────────────────

/// UDP-сокет, которому ядро отдаёт TPROXY-пакеты: прозрачный (можно
/// принимать чужие адреса) и с контролем настоящего получателя.
fn udp_socket(port: u16) -> Result<UdpSocket> {
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port);
    udp_socket_bound(bind, true, false)
}

/// Сокет для ответов клиенту, привязанный к настоящему получателю.
///
/// Одного `IP_PKTINFO` мало: он подменяет только IP источника, а порт берётся
/// из `bind`. Клиент, отправивший датаграмму на `198.51.100.1:9999`, ждёт
/// ответ именно с порта 9999 и молча отбросит пакет с порта 15001.
/// `SO_REUSEPORT` позволяет держать такой сокет на каждый поток: несколько
/// клиентов могут общаться с одним и тем же получателем.
fn udp_reply_socket(dst: SocketAddr) -> Result<UdpSocket> {
    udp_socket_bound(dst, false, true)
}

fn udp_socket_bound(bind: SocketAddr, recv_orig: bool, reuse_port: bool) -> Result<UdpSocket> {
    unsafe {
        let fd = libc::socket(
            libc::AF_INET,
            libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        );
        if fd < 0 {
            return Err(Error::Internal(format!(
                "не удалось создать UDP-сокет: {}",
                io::Error::last_os_error()
            )));
        }
        let one: libc::c_int = 1;
        let mut opts = vec![
            (libc::SOL_IP, libc::IP_TRANSPARENT),
            (libc::SOL_SOCKET, libc::SO_REUSEADDR),
        ];
        if recv_orig {
            opts.push((libc::SOL_IP, IP_RECVORIGDSTADDR));
        }
        if reuse_port {
            opts.push((libc::SOL_SOCKET, libc::SO_REUSEPORT));
        }
        for (level, opt) in opts {
            let rc = libc::setsockopt(
                fd,
                level,
                opt,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            if rc != 0 {
                let e = io::Error::last_os_error();
                libc::close(fd);
                return Err(Error::Internal(format!(
                    "не удалось настроить UDP-сокет (опция {opt}): {e}"
                )));
            }
        }

        let addr = addr_to_sockaddr(bind);
        let rc = libc::bind(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if rc != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(Error::Internal(format!(
                "не удалось занять {bind} для перехвата UDP: {e}"
            )));
        }

        let std_sock = std::net::UdpSocket::from_raw_fd(fd);
        UdpSocket::from_std(std_sock)
            .map_err(|e| Error::Internal(format!("не удалось перевести UDP-сокет в tokio: {e}")))
    }
}

type FlowKey = (SocketAddr, SocketAddr);
/// Каналы в живые UDP-потоки: ключ — тройка «клиент, получатель».
type FlowSenders = Arc<tokio::sync::Mutex<HashMap<FlowKey, mpsc::Sender<Arc<Vec<u8>>>>>>;

async fn udp_loop(engine: Arc<Engine>, sock: Arc<UdpSocket>, cancel: CancellationToken) {
    let flows: FlowSenders = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 65_535];
    let mut last_err_log: Option<std::time::Instant> = None;
    tracing::info!(port = paths::tproxy_port(), "UDP-слушатель запущен");

    loop {
        let received = tokio::select! {
            _ = cancel.cancelled() => break,
            received = recv_with_origdst(&sock, &mut buf) => received,
        };
        let (n, src, dst) = match received {
            Ok(v) => v,
            Err(e) => {
                // Одна строка в секунду: при потоке пакетов без контрольного
                // сообщения журнал иначе распухает так же, как на accept.
                let now = std::time::Instant::now();
                let should_log = match last_err_log {
                    Some(t) => now.duration_since(t) >= Duration::from_secs(1),
                    None => true,
                };
                if should_log {
                    tracing::warn!(error = %e, "не удалось принять UDP-датаграмму");
                    last_err_log = Some(now);
                }
                continue;
            }
        };
        let key = (src, dst);
        tracing::debug!(%src, %dst, n, "UDP-датаграмма принята");
        let data = Arc::new(buf[..n].to_vec());

        let mut map = flows.lock().await;
        if let Some(tx) = map.get(&key) {
            if tx.try_send(data.clone()).is_ok() {
                continue;
            }
            map.remove(&key);
        }
        let (tx, rx) = mpsc::channel(64);
        map.insert(key, tx);
        drop(map);

        tokio::spawn(udp_flow(
            engine.clone(),
            flows.clone(),
            cancel.clone(),
            key,
            rx,
            data,
        ));
    }
}

/// Один UDP-поток: своя сессия outbound'а, свои датаграммы в обе стороны.
async fn udp_flow(
    engine: Arc<Engine>,
    flows: FlowSenders,
    cancel: CancellationToken,
    key: FlowKey,
    mut rx: mpsc::Receiver<Arc<Vec<u8>>>,
    first: Arc<Vec<u8>>,
) {
    let (client, dst) = key;
    let mut flow = Flow {
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        src_port: client.port(),
        is_tcp: false,
        ..Default::default()
    };
    engine.enrich_domain(&mut flow);
    let (decision, label, rule) = engine.route(&flow);
    if matches!(decision, Decision::Reject | Decision::RejectDrop) {
        flows.lock().await.remove(&key);
        return;
    }
    if matches!(decision, Decision::HijackDns) {
        // Локальный DNS-ответ: отправляем с сокета, привязанного к
        // настоящему получателю, иначе клиент не примет датаграмму.
        let response = engine.dns.answer_query(first.as_slice()).await;
        match udp_reply_socket(dst) {
            Ok(sock) => {
                let _ = send_from(&sock, &response, client).await;
            }
            Err(e) => tracing::debug!(%dst, error = %e, "HIJACK-DNS: нет сокета для ответа"),
        }
        engine.stats.add_up(first.len() as u64);
        engine.stats.add_down(response.len() as u64);
        flows.lock().await.remove(&key);
        return;
    }
    let target = Target::from_flow(&flow);

    let label = label.unwrap_or_else(|| "DIRECT".to_string());
    let Some(ob) = engine.resolve_outbound(&label) else {
        flows.lock().await.remove(&key);
        return;
    };
    let Some(session) = engine.open_udp(&ob).await else {
        tracing::debug!(outbound = %label, "outbound не умеет UDP");
        flows.lock().await.remove(&key);
        return;
    };
    // Ответы клиенту шлём со сокета, привязанного к настоящему получателю:
    // иначе источником будет 15001 и клиент отбросит ответ.
    let reply = match udp_reply_socket(dst) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            tracing::warn!(%dst, error = %e, "не удалось создать сокет для ответов UDP");
            flows.lock().await.remove(&key);
            return;
        }
    };

    if session.send_to(first.as_slice(), &target).await.is_err() {
        flows.lock().await.remove(&key);
        return;
    }
    engine.stats.add_up(first.len() as u64);

    // Сумма по потоку: пишем в breakdown один раз при закрытии, а не на
    // каждую датаграмму — лишний лок и аллокация на горячем пути.
    let mut bytes = first.len() as u64;
    let mut buf = vec![0u8; 65_535];
    loop {
        tokio::select! {
            // Выключение перехвата: поток обязан выйти и отпустить сокет,
            // иначе порт 15001 останется занятым до UDP_IDLE.
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(UDP_IDLE) => break,
            next = rx.recv() => match next {
                Some(data) => {
                    if session.send_to(data.as_slice(), &target).await.is_err() {
                        break;
                    }
                    engine.stats.add_up(data.len() as u64);
                    bytes += data.len() as u64;
                }
                None => break,
            },
            got = session.recv_from(&mut buf, UDP_IDLE) => match got {
                Ok((n, _from)) => {
                    // DNS-ответ: запоминаем «адрес → домен» для правил.
                    if dst.port() == 53 {
                        engine.dns.remember_response(&buf[..n]);
                    }
                    engine.stats.add_down(n as u64);
                    bytes += n as u64;
                    if send_from(&reply, &buf[..n], client).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
        }
    }

    engine.breakdown.record(&rule, ob.name(), bytes);
    flows.lock().await.remove(&key);
}

/// Принимает датаграмму и достаёт из контрольного сообщения настоящего
/// получателя. `IP_ORIGDSTADDR` — единственный способ узнать его для TPROXY.
async fn recv_with_origdst(
    sock: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, SocketAddr)> {
    sock.async_io(Interest::READABLE, || {
        let mut src: libc::sockaddr_in = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut control = [0u8; 64];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut src as *mut libc::sockaddr_in as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control.len() as _;

        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut dst = None;
        let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        while !cmsg.is_null() {
            let hdr = unsafe { &*cmsg };
            if hdr.cmsg_level == libc::SOL_IP && hdr.cmsg_type == IP_ORIGDSTADDR {
                let mut orig: libc::sockaddr_in = unsafe { std::mem::zeroed() };
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        libc::CMSG_DATA(cmsg),
                        &mut orig as *mut libc::sockaddr_in as *mut u8,
                        std::mem::size_of::<libc::sockaddr_in>(),
                    );
                }
                dst = Some(sockaddr_to_addr(&orig));
            }
            cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
        }

        match dst {
            Some(dst) => Ok((n as usize, sockaddr_to_addr(&src), dst)),
            None => Err(io::Error::other("IP_ORIGDSTADDR не пришёл")),
        }
    })
    .await
}

/// Отправляет датаграмму клиенту. Источник уже задан сокетом: он привязан
/// к настоящему получателю, поэтому подменять что-то через `sendmsg` не нужно.
async fn send_from(sock: &UdpSocket, data: &[u8], to: SocketAddr) -> io::Result<()> {
    sock.send_to(data, to).await.map(|_| ())
}
