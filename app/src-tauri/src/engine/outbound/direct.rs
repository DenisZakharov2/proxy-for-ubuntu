//! Прямое соединение без посредников. Базовая линия: если правило выбрало
//! DIRECT, мы просто открываем сокет до настоящего получателя.

use std::time::Duration;

use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::engine::outbound::{AsyncReadWrite, Outbound, Request, UdpSession};
use crate::error::{Error, Result};

pub struct Direct {
    name: String,
}

impl Direct {
    pub fn new(name: String) -> Self {
        Self { name }
    }
}

#[async_trait]
impl Outbound for Direct {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "direct"
    }

    fn supports_udp(&self) -> bool {
        true
    }

    fn remote_dns(&self) -> bool {
        false
    }

    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>> {
        let target = &req.target;
        if target.is_tcp {
            let stream = resolve_and_connect(&target.host, target.port, Duration::from_secs(15))
                .await?;
            Ok(Box::new(stream))
        } else {
            Err(Error::protocol("direct", "UDP обрабатывается через open_udp"))
        }
    }

    async fn open_udp(&self) -> Result<std::sync::Arc<dyn UdpSession>> {
        Ok(std::sync::Arc::new(DirectUdp::new().await?))
    }
}

/// Резолвит хост (или использует готовый IP) и подключается.
pub async fn resolve_and_connect(
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(Error::ConfigInvalid(format!("{host} не разрешается")));
    }
    // Пробуем адреса по очереди: если первый недоступен (например, AAAA без
    // маршрута), не отказываем пользователю сразу.
    let mut last: Option<std::io::Error> = None;
    for a in addrs {
        match tokio::time::timeout(timeout, TcpStream::connect(a)).await {
            Ok(Ok(s)) => {
                let _ = s.set_nodelay(true);
                return Ok(s);
            }
            Ok(Err(e)) => last = Some(e),
            Err(_) => {
                return Err(Error::Timeout(format!("{host}:{port} не ответил за {timeout:?}")))
            }
        }
    }
    Err(Error::Protocol {
        proto: "direct",
        message: format!("не удалось подключиться к {host}:{port}: {}", last.map(|e| e.to_string()).unwrap_or_default()),
    })
}

/// UDP для DIRECT: обычный сокет, ответы приходят напрямую клиенту.
struct DirectUdp {
    sock: tokio::net::UdpSocket,
}

impl DirectUdp {
    async fn new() -> Result<Self> {
        Ok(Self { sock: tokio::net::UdpSocket::bind("0.0.0.0:0").await? })
    }
}

#[async_trait]
impl UdpSession for DirectUdp {
    async fn send_to(&self, data: &[u8], dst: &crate::engine::rules::Target) -> Result<()> {
        let addr = crate::engine::outbound::socks5::resolve_target_addr(dst).await?;
        self.sock.send_to(data, addr).await?;
        Ok(())
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<(usize, crate::engine::rules::Target)> {
        let n = tokio::time::timeout(timeout, self.sock.recv_from(buf))
            .await
            .map_err(|_| Error::Timeout("UDP: нет данных".into()))??;
        let (n, addr) = n;
        Ok((n, crate::engine::rules::Target { host: addr.ip().to_string(), port: addr.port(), is_tcp: false }))
    }

    fn local_addr(&self) -> std::net::SocketAddr {
        self.sock.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connects_to_local_listener() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let d = Direct::new("DIRECT".into());
        let req = Request::tcp("127.0.0.1", addr.port());
        let mut s = d.connect(&req).await.unwrap();
        use tokio::io::AsyncWriteExt;
        s.write_all(b"ping").await.unwrap();
        s.flush().await.unwrap();
        assert_eq!(d.name(), "DIRECT");
    }

    #[tokio::test]
    async fn direct_reports_failure_instead_of_hanging() {
        let d = Direct::new("DIRECT".into());
        // Порт 1 на loopback закрыт: ждать отказа дольше секунды нельзя.
        let r = tokio::time::timeout(
            Duration::from_secs(5),
            d.connect(&Request::tcp("127.0.0.1", 1)),
        )
        .await
        .expect("connect не должен висеть бесконечно");
        assert!(r.is_err());
    }
}
