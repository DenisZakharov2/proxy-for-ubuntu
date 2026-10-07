//! Клиенты исходящих протоколов.
//!
//! Каждый протокол — отдельный модуль, реализующий [`Outbound`]. Общая
//! идея: движок спрашивает у правил решение, получает имя outbound'а и
//! просит его открыть соединение к `Target`. Дальше движок просто перекладывает
//! байты между TPROXY-сокетом и этим соединением, ничего не зная о протоколе.

pub mod direct;
pub mod http;
pub mod shadowsocks;
pub mod socks5;
pub mod ssh;
pub mod trojan;
pub mod vless;
pub mod vmess;

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::config::Outbound as OutboundConfig;
use crate::engine::rules::Target;
use crate::error::{Error, Result};

/// Двунаправленный поток. `Box<dyn AsyncReadWrite>` удобнее таскать по ящику,
/// но теряет Send-гарантии для некоторых TLS-типов, поэтому в trait-object
/// сразу зашит `Send + Sync`.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncReadWrite for T {}

/// Запрос на соединение.
#[derive(Debug, Clone)]
pub struct Request {
    pub target: Target,
}

impl Request {
    pub fn tcp(host: impl Into<String>, port: u16) -> Self {
        Self {
            target: Target {
                host: host.into(),
                port,
                is_tcp: true,
            },
        }
    }
}

/// Результат живой проверки outbound'а.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeResult {
    pub ok: bool,
    pub latency_ms: Option<u64>,
    pub resolved_via: Option<&'static str>,
    pub error: Option<String>,
}

/// UDP-канал. Не все протоколы его умеют — см. [`Outbound::supports_udp`].
#[async_trait]
pub trait UdpSession: Send + Sync {
    /// Отправить датаграмму на `dst`.
    async fn send_to(&self, data: &[u8], dst: &Target) -> Result<()>;
    /// Принять датаграмму. `timeout` — чтобы не блокировать сессию вечно.
    async fn recv_from(&self, buf: &mut [u8], timeout: Duration) -> Result<(usize, Target)>;
    /// Локальный адрес, на который приложение шлёт ответы.
    fn local_addr(&self) -> std::net::SocketAddr;
}

/// Исходящий канал.
#[async_trait]
pub trait Outbound: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> &'static str;
    fn supports_udp(&self) -> bool;
    /// Домен передаётся прокси как есть, без локального резолва.
    fn remote_dns(&self) -> bool;
    /// Открыть TCP-соединение к `req.target`.
    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>>;
    /// Открыть UDP-канал (для реализаций, поддерживающих UDP).
    async fn open_udp(&self) -> Result<Arc<dyn UdpSession>>;
    /// Проверка живой связности. По умолчанию — TCP-соединение к тестовой
    /// цели; протоколы с обязательным TLS переопределяют.
    async fn probe(&self, timeout: Duration) -> ProbeResult {
        let started = Instant::now();
        let host = probe_host();
        let req = Request::tcp(host.clone(), 443);
        let result = tokio::time::timeout(timeout, self.connect(&req)).await;
        match result {
            Ok(Ok(_stream)) => ProbeResult {
                ok: true,
                latency_ms: Some(started.elapsed().as_millis() as u64),
                resolved_via: Some(if self.remote_dns() { "remote" } else { "local" }),
                error: None,
            },
            Ok(Err(e)) => ProbeResult {
                ok: false,
                latency_ms: None,
                resolved_via: Some(if self.remote_dns() { "remote" } else { "local" }),
                error: Some(e.to_string()),
            },
            Err(_) => ProbeResult {
                ok: false,
                latency_ms: None,
                resolved_via: Some(if self.remote_dns() { "remote" } else { "local" }),
                error: Some(format!("нет ответа за {}", humantime(timeout))),
            },
        }
    }
}

fn probe_host() -> String {
    "www.gstatic.com".to_string()
}

fn humantime(d: Duration) -> String {
    format!("{:.0} мс", d.as_millis())
}

/// Подключается к серверу прокси с таймаутом и корректным поведением при
/// недоступности: без этого `connect()` может висеть минуту на SYN к
/// недоступному адресу, и Apply «зависнет» вместо отката.
pub async fn connect_proxy(server: std::net::SocketAddr, timeout: Duration) -> Result<TcpStream> {
    match tokio::time::timeout(timeout, TcpStream::connect(server)).await {
        Ok(Ok(s)) => {
            let _ = s.set_nodelay(true);
            Ok(s)
        }
        Ok(Err(e)) => Err(Error::Protocol {
            proto: "connect",
            message: format!("не удалось подключиться к {server}: {e}"),
        }),
        Err(_) => Err(Error::Timeout(format!(
            "сервер прокси {server} не ответил за {}",
            humantime(timeout)
        ))),
    }
}

/// Обёртка над `poll_read`, возвращающая `Poll<usize>` вместо
/// `Poll<Poll<usize>>`. Без неё каждый AsyncRead-impl в проекте писал бы
/// один и тот же неуклюжий разбор `Poll::Ready(...)`.
pub fn poll_read_into<S: AsyncRead + Unpin + ?Sized>(
    s: &mut S,
    cx: &mut std::task::Context<'_>,
    buf: &mut [u8],
) -> std::task::Poll<std::io::Result<usize>> {
    let mut rb = tokio::io::ReadBuf::new(buf);
    match std::pin::Pin::new(s).poll_read(cx, &mut rb) {
        std::task::Poll::Pending => std::task::Poll::Pending,
        std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(rb.filled().len())),
        std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
    }
}

/// Заголовок SOCKS5 для адреса назначения. Общий для SOCKS5, Trojan, VMess.
pub fn socks_addr_bytes(host: &str, port: u16) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(host.len() + 7);
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(Error::protocol(
                    "socks",
                    format!("домен {host:?} длиннее 255 байт"),
                ));
            }
            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

/// Разбор адреса из ответа SOCKS5-сервера.
pub fn parse_socks_addr(buf: &[u8]) -> Result<(String, u16)> {
    if buf.is_empty() {
        return Err(Error::protocol("socks", "пустой ответ"));
    }
    let host = match buf[0] {
        0x01 => {
            if buf.len() < 4 {
                return Err(Error::protocol("socks", "обрезанный IPv4 в ответе"));
            }
            std::net::Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]).to_string()
        }
        0x04 => {
            if buf.len() < 16 {
                return Err(Error::protocol("socks", "обрезанный IPv6 в ответе"));
            }
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[1..17]);
            std::net::Ipv6Addr::from(o).to_string()
        }
        0x03 => {
            let len = *buf
                .get(1)
                .ok_or_else(|| Error::protocol("socks", "нет длины домена"))?
                as usize;
            if buf.len() < 2 + len {
                return Err(Error::protocol("socks", "обрезанный домен в ответе"));
            }
            String::from_utf8_lossy(&buf[2..2 + len]).to_string()
        }
        other => {
            return Err(Error::protocol(
                "socks",
                format!("неизвестный тип адреса {other:#x}"),
            ))
        }
    };
    if buf.len() < 2 + host_port_len(buf) {
        return Err(Error::protocol("socks", "нет порта в ответе"));
    }
    let port = u16::from_be_bytes([buf[buf.len() - 2], buf[buf.len() - 1]]);
    Ok((host, port))
}

fn host_port_len(buf: &[u8]) -> usize {
    match buf.first() {
        Some(0x01) => 4,
        Some(0x04) => 16,
        Some(0x03) => 2 + *buf.get(1).unwrap_or(&0) as usize,
        _ => 0,
    }
}

/// Собирает исполняемый outbound из конфигурации.
pub fn build(cfg: &OutboundConfig) -> Result<Arc<dyn Outbound>> {
    Ok(match cfg {
        OutboundConfig::Direct(o) => Arc::new(direct::Direct::new(o.name.clone())),
        OutboundConfig::Http(o) => Arc::new(http::HttpProxy::new(o.clone())?),
        OutboundConfig::Socks(o) => Arc::new(socks5::SocksProxy::new(o.clone())?),
        OutboundConfig::Shadowsocks(o) => Arc::new(shadowsocks::Shadowsocks::new(o.clone())?),
        OutboundConfig::Trojan(o) => Arc::new(trojan::Trojan::new(o.clone())?),
        OutboundConfig::Vless(o) => Arc::new(vless::Vless::new(o.clone())?),
        OutboundConfig::Vmess(o) => Arc::new(vmess::Vmess::new(o.clone())?),
        OutboundConfig::Ssh(o) => Arc::new(ssh::SshTunnel::new(o.clone())?),
    })
}

/// Человекочитаемое описание для `--dry-run` и логов. Пароли не печатаются.
pub fn describe(cfg: &OutboundConfig) -> String {
    let base = match cfg {
        OutboundConfig::Direct(_) => "прямое соединение".to_string(),
        OutboundConfig::Http(o) => format!("HTTP CONNECT {}:{}", o.server, o.port),
        OutboundConfig::Socks(o) => format!(
            "SOCKS5{} {}:{}",
            if o.remote_dns { "h" } else { "" },
            o.server,
            o.port
        ),
        OutboundConfig::Shadowsocks(o) => {
            format!("Shadowsocks ({}) {}:{}", o.method, o.server, o.port)
        }
        OutboundConfig::Trojan(o) => format!("Trojan {}:{} sni={}", o.server, o.port, o.sni),
        OutboundConfig::Vless(o) => format!("VLESS {}:{} tls={}", o.server, o.port, o.tls),
        OutboundConfig::Vmess(o) => format!("VMess {}:{} alterId={}", o.server, o.port, o.alter_id),
        OutboundConfig::Ssh(o) => format!("SSH {}@{}:{}", o.username, o.server, o.port),
    };
    if cfg.is_experimental() {
        format!("{base}  [НЕ ПРОВЕРЕН на живом сервере]")
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socks_addr_ipv4() {
        let b = socks_addr_bytes("1.2.3.4", 443).unwrap();
        assert_eq!(b, vec![0x01, 1, 2, 3, 4, 0x01, 0xBB]);
    }

    #[test]
    fn socks_addr_ipv6() {
        let b = socks_addr_bytes("2001:db8::1", 80).unwrap();
        assert_eq!(b[0], 0x04);
        assert_eq!(&b[17..19], &[0x00, 0x50]);
    }

    #[test]
    fn socks_addr_domain() {
        let b = socks_addr_bytes("example.com", 8080).unwrap();
        assert_eq!(b[0], 0x03);
        assert_eq!(b[1], 11);
        assert_eq!(&b[2..13], b"example.com");
        assert_eq!(&b[13..15], &[0x1F, 0x90]);
    }

    #[test]
    fn socks_addr_rejects_long_domain() {
        let long = "a".repeat(300);
        assert!(socks_addr_bytes(&long, 80).is_err());
    }

    #[test]
    fn roundtrip_parse_addr() {
        for (host, port) in [
            ("1.2.3.4", 443u16),
            ("2001:db8::1", 80),
            ("example.com", 8080),
        ] {
            let b = socks_addr_bytes(host, port).unwrap();
            let (h, p) = parse_socks_addr(&b).unwrap();
            assert_eq!(h, host);
            assert_eq!(p, port);
        }
    }

    #[test]
    fn parse_addr_rejects_garbage() {
        assert!(parse_socks_addr(&[]).is_err());
        assert!(parse_socks_addr(&[0x09, 1, 2]).is_err());
        assert!(parse_socks_addr(&[0x01, 1, 2]).is_err());
    }

    #[test]
    fn describe_marks_experimental() {
        let vless = OutboundConfig::Vless(crate::config::OutboundVless {
            name: "V".into(),
            server: "a".into(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            flow: String::new(),
            network: None,
            tls: true,
            sni: String::new(),
            path: String::new(),
            host: String::new(),
            skip_cert_verify: false,
            udp: true,
            test_url: None,
            test_timeout_ms: None,
        });
        assert!(describe(&vless).contains("НЕ ПРОВЕРЕН"));
        let dir = OutboundConfig::Direct(crate::config::OutboundDirect {
            name: "DIRECT".into(),
            test_url: None,
            test_timeout_ms: None,
        });
        assert!(!describe(&dir).contains("НЕ ПРОВЕРЕН"));
    }
}
