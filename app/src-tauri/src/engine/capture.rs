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

/// Запущенные слушатели. `Drop` закрывает порты: после отключения перехвата
/// приложение не оставляет открытых сокетов.
pub struct Capture {
    tasks: Vec<JoinHandle<()>>,
}

impl Capture {
    pub fn stop(&mut self) {
        for t in self.tasks.drain(..) {
            t.abort();
        }
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Поднимает слушатели под текущий конфиг. Ошибка (занятый порт) приходит
/// до применения правил, поэтому система остаётся нетронутой.
pub async fn start(engine: Arc<Engine>) -> Result<Capture> {
    let mut tasks = Vec::new();

    if engine.config.intercept.tcp != TcpMode::Off {
        let port = paths::redirect_port();
        let listener = TcpListener::bind(("0.0.0.0", port)).await.map_err(|e| {
            Error::Internal(format!(
                "не удалось занять порт {port} для перехвата TCP: {e}"
            ))
        })?;
        tasks.push(tokio::spawn(tcp_loop(engine.clone(), listener)));
    }

    if engine.config.intercept.udp != UdpMode::Off {
        let sock = Arc::new(udp_socket(paths::tproxy_port())?);
        tasks.push(tokio::spawn(udp_loop(engine.clone(), sock)));
    }

    tracing::info!(listeners = tasks.len(), "перехват включён");
    Ok(Capture { tasks })
}

// ─────────────────────────────────── TCP ───────────────────────────────────

async fn tcp_loop(engine: Arc<Engine>, listener: TcpListener) {
    loop {
        match listener.accept().await {
            Ok((client, peer)) => {
                tokio::spawn(tcp_conn(engine.clone(), client, peer));
            }
            Err(e) => {
                tracing::warn!(error = %e, "не удалось принять перехваченное соединение");
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
}

async fn tcp_conn(engine: Arc<Engine>, client: TcpStream, peer: SocketAddr) {
    let Some(dst) = original_dst(&client) else {
        tracing::warn!(%peer, "не удалось узнать настоящий адрес получателя");
        return;
    };
    // Если правило почему-то завернуло собственный сокет демона — не петляем.
    if dst.ip().is_loopback() && dst.port() == paths::redirect_port() {
        return;
    }

    let flow = Flow {
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        src_port: peer.port(),
        is_tcp: true,
        ..Default::default()
    };
    let target = Target::from_flow(&flow);

    let (ob, upstream) = match engine.open(&target, &flow).await {
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
    let relayed = router::relay(
        client,
        upstream,
        |up, down| {
            stats.add_up(up);
            stats.add_down(down);
        },
        limiter.as_deref(),
    )
    .await;
    engine.stats.conn_closed();

    match relayed {
        Ok((up, down)) => tracing::debug!(
            target = %target.key(), outbound = ob.name(), up, down, "соединение закрыто"
        ),
        Err(e) => tracing::debug!(target = %target.key(), error = %e, "соединение оборвалось"),
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
        for (level, opt) in [
            (libc::SOL_IP, libc::IP_TRANSPARENT),
            (libc::SOL_IP, IP_RECVORIGDSTADDR),
            (libc::SOL_SOCKET, libc::SO_REUSEADDR),
        ] {
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

        let addr = addr_to_sockaddr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port));
        let rc = libc::bind(
            fd,
            &addr as *const libc::sockaddr_in as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        if rc != 0 {
            let e = io::Error::last_os_error();
            libc::close(fd);
            return Err(Error::Internal(format!(
                "не удалось занять порт {port} для перехвата UDP: {e}"
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

async fn udp_loop(engine: Arc<Engine>, sock: Arc<UdpSocket>) {
    let flows: FlowSenders = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    let mut buf = vec![0u8; 65_535];

    loop {
        let (n, src, dst) = match recv_with_origdst(&sock, &mut buf).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "не удалось принять UDP-датаграмму");
                continue;
            }
        };
        let key = (src, dst);
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
            sock.clone(),
            flows.clone(),
            key,
            rx,
            data,
        ));
    }
}

/// Один UDP-поток: своя сессия outbound'а, свои датаграммы в обе стороны.
async fn udp_flow(
    engine: Arc<Engine>,
    sock: Arc<UdpSocket>,
    flows: FlowSenders,
    key: FlowKey,
    mut rx: mpsc::Receiver<Arc<Vec<u8>>>,
    first: Arc<Vec<u8>>,
) {
    let (client, dst) = key;
    let flow = Flow {
        dst_ip: Some(dst.ip()),
        dst_port: dst.port(),
        src_port: client.port(),
        is_tcp: false,
        ..Default::default()
    };
    if matches!(
        engine.route(&flow).0,
        Decision::Reject | Decision::RejectDrop
    ) {
        flows.lock().await.remove(&key);
        return;
    }
    let target = Target::from_flow(&flow);

    let label = engine
        .route(&flow)
        .1
        .unwrap_or_else(|| "DIRECT".to_string());
    let Some(ob) = engine.resolve_outbound(&label) else {
        flows.lock().await.remove(&key);
        return;
    };
    let Some(session) = engine.open_udp(&ob).await else {
        tracing::debug!(outbound = %label, "outbound не умеет UDP");
        flows.lock().await.remove(&key);
        return;
    };

    if session.send_to(first.as_slice(), &target).await.is_err() {
        flows.lock().await.remove(&key);
        return;
    }
    engine.stats.add_up(first.len() as u64);

    let mut buf = vec![0u8; 65_535];
    loop {
        tokio::select! {
            _ = tokio::time::sleep(UDP_IDLE) => break,
            next = rx.recv() => match next {
                Some(data) => {
                    if session.send_to(data.as_slice(), &target).await.is_err() {
                        break;
                    }
                    engine.stats.add_up(data.len() as u64);
                }
                None => break,
            },
            got = session.recv_from(&mut buf, UDP_IDLE) => match got {
                Ok((n, _from)) => {
                    engine.stats.add_down(n as u64);
                    if send_from(&sock, &buf[..n], client, dst.ip()).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            },
        }
    }

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

/// Отправляет датаграмму клиенту с подменой источника на настоящего
/// получателя: иначе клиент не узнает ответ и соединение «зависнет».
async fn send_from(sock: &UdpSocket, data: &[u8], to: SocketAddr, src: IpAddr) -> io::Result<()> {
    let IpAddr::V4(src) = src else {
        return Err(io::Error::other("UDP поддерживает только IPv4"));
    };
    sock.async_io(Interest::WRITABLE, || {
        let mut dst = addr_to_sockaddr(to);
        let mut iov = libc::iovec {
            iov_base: data.as_ptr() as *mut libc::c_void,
            iov_len: data.len(),
        };
        let mut control = [0u8; 64];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut dst as *mut libc::sockaddr_in as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;

        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<libc::in_pktinfo>() as u32) };
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            (*cmsg).cmsg_level = libc::SOL_IP;
            (*cmsg).cmsg_type = libc::IP_PKTINFO;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(std::mem::size_of::<libc::in_pktinfo>() as u32) as usize;
            let info = libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo;
            (*info).ipi_ifindex = 0;
            (*info).ipi_spec_dst.s_addr = u32::from_ne_bytes(src.octets());
            (*info).ipi_addr.s_addr = 0;
        }

        let n = unsafe { libc::sendmsg(sock.as_raw_fd(), &msg, 0) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
    .await
}
