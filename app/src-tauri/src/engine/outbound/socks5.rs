//! SOCKS5 (RFC 1928) и SOCKS5h.
//!
//! Отличие только одно: при `remote_dns: true` домен уходит на прокси как
//! домен (тип адреса `0x03`), при `false` мы резолвим его сами и отправляем
//! IPv4/IPv6. Первое не течёт DNS, второе — быстрее, но весь список
//! посещённых доменов виден вашему провайдеру. По умолчанию — первое.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::config::OutboundSocks;
use crate::engine::outbound::{
    connect_proxy, parse_socks_addr, socks_addr_bytes, AsyncReadWrite, Outbound, ProbeResult,
    Request, UdpSession,
};
use crate::engine::rules::Target;
use crate::error::{Error, Result};

const VER: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
#[allow(dead_code)]
const ATYP_DOMAIN: u8 = 0x03;
#[allow(dead_code)]
const ATYP_IPV4: u8 = 0x01;

/// Резолвит цель в `SocketAddr`. При `remote_dns=false` вызывающий код обязан
/// передать сюда IP, а не домен.
pub async fn resolve_target_addr(target: &Target) -> Result<SocketAddr> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<_> = (target.host.as_str(), target.port).to_socket_addrs()?.collect();
    addrs
        .first()
        .copied()
        .ok_or_else(|| Error::ConfigInvalid(format!("{} не разрешается", target.host)))
}

pub struct SocksProxy {
    name: String,
    pub(crate) server: SocketAddr,
    username: String,
    password: String,
    udp: bool,
    remote_dns: bool,
}

impl SocksProxy {
    pub fn new(cfg: OutboundSocks) -> Result<Self> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<_> = (cfg.server.as_str(), cfg.port).to_socket_addrs()?.collect();
        let server = addrs
            .first()
            .copied()
            .ok_or_else(|| Error::ConfigInvalid(format!("{} не разрешается", cfg.server)))?;
        Ok(Self {
            name: cfg.name,
            server,
            username: cfg.username,
            password: cfg.password,
            udp: cfg.udp,
            remote_dns: cfg.remote_dns,
        })
    }

    /// Порт локального SOCKS5-сервера. Нужен SSH-туннелю, который создаёт
    /// SocksProxy на loopback после подъёма `ssh -D`.
    pub fn port(&self) -> u16 {
        self.server.port()
    }

    /// Приветствие и аутентификация. Возвращает готовый к работе сокет.
    async fn handshake(&self, tcp: &mut TcpStream) -> Result<()> {
        // Методы: без auth всегда, плюс username/password если задан.
        let use_auth = !self.username.is_empty() || !self.password.is_empty();
        let methods: &[u8] = if use_auth { &[0x00, 0x02] } else { &[0x00] };
        tcp.write_all(&[VER, methods.len() as u8]).await?;
        tcp.write_all(methods).await?;
        tcp.flush().await?;

        let mut reply = [0u8; 2];
        tcp.read_exact(&mut reply).await?;
        if reply[0] != VER {
            return Err(Error::protocol("socks", format!("плохая версия в ответе: {}", reply[0])));
        }
        match reply[1] {
            0x00 => Ok(()),
            0x02 => {
                if !use_auth {
                    return Err(Error::protocol(
                        "socks",
                        "прокси требует логин, а он не задан в конфигурации",
                    ));
                }
                let mut buf = Vec::with_capacity(3 + self.username.len() + self.password.len());
                buf.push(0x01);
                buf.push(self.username.len() as u8);
                buf.extend_from_slice(self.username.as_bytes());
                buf.push(self.password.len() as u8);
                buf.extend_from_slice(self.password.as_bytes());
                tcp.write_all(&buf).await?;
                tcp.flush().await?;
                let mut r = [0u8; 2];
                tcp.read_exact(&mut r).await?;
                if r[1] != 0x00 {
                    return Err(Error::protocol("socks", "неверный логин или пароль"));
                }
                Ok(())
            }
            other => Err(Error::protocol(
                "socks",
                format!("прокси требует неподдерживаемый метод аутентификации {other:#x}"),
            )),
        }
    }

    /// Отправляет запрос CONNECT и проверяет код ответа.
    async fn request(
        &self,
        tcp: &mut TcpStream,
        cmd: u8,
        target: &Target,
    ) -> Result<(String, u16)> {
        let addr = if self.remote_dns || target.host.parse::<std::net::IpAddr>().is_err() {
            socks_addr_bytes(&target.host, target.port)?
        } else {
            let a = resolve_target_addr(target).await?;
            socks_addr_bytes(&a.ip().to_string(), a.port())?
        };

        let mut req = vec![VER, cmd, 0x00];
        req.extend_from_slice(&addr);
        tcp.write_all(&req).await?;
        tcp.flush().await?;

        let mut head = [0u8; 4];
        tcp.read_exact(&mut head).await?;
        if head[0] != VER {
            return Err(Error::protocol("socks", format!("плохая версия в ответе: {}", head[0])));
        }
        if head[1] != 0x00 {
            let reason = match head[1] {
                0x01 => "общий сбой",
                0x02 => "правило запрещает соединение",
                0x03 => "сеть недостижима",
                0x04 => "хост недостижим",
                0x05 => "соединение отклонено",
                0x06 => "TTL истёк",
                0x07 => "команда не поддерживается",
                0x08 => "тип адреса не поддерживается",
                n => return Err(Error::protocol("socks", format!("неизвестный код ответа {n:#x}"))),
            };
            return Err(Error::protocol("socks", format!("прокси отклонил запрос: {reason}")));
        }

        // Точная длина ответа зависит от типа адреса в нём.
        let atyp = head[3];
        let mut rest = vec![atyp];
        match atyp {
            0x01 => {
                let mut b = [0u8; 6];
                tcp.read_exact(&mut b).await?;
                rest.extend_from_slice(&b);
            }
            0x04 => {
                let mut b = [0u8; 18];
                tcp.read_exact(&mut b).await?;
                rest.extend_from_slice(&b);
            }
            0x03 => {
                let mut n = [0u8; 1];
                tcp.read_exact(&mut n).await?;
                rest.push(n[0]);
                let mut b = vec![0u8; n[0] as usize + 2];
                tcp.read_exact(&mut b).await?;
                rest.extend_from_slice(&b);
            }
            other => {
                return Err(Error::protocol("socks", format!("неизвестный тип адреса {other:#x} в ответе")))
            }
        }
        parse_socks_addr(&rest)
    }
}

#[async_trait]
impl Outbound for SocksProxy {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "socks5"
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    fn remote_dns(&self) -> bool {
        self.remote_dns
    }

    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>> {
        let mut tcp = connect_proxy(self.server, Duration::from_secs(10)).await?;
        self.handshake(&mut tcp).await?;
        self.request(&mut tcp, CMD_CONNECT, &req.target).await?;
        Ok(Box::new(tcp))
    }

    async fn open_udp(&self) -> Result<Arc<dyn UdpSession>> {
        if !self.udp {
            return Err(Error::protocol("socks", "UDP отключён в конфигурации outbound'а"));
        }
        let mut tcp = connect_proxy(self.server, Duration::from_secs(10)).await?;
        self.handshake(&mut tcp).await?;
        // UDP ASSOCIATE с адресом 0.0.0.0:0 — прокси сам выберет порт.
        let any = Target { host: "0.0.0.0".into(), port: 0, is_tcp: false };
        let (bind_host, bind_port) = self.request(&mut tcp, CMD_UDP_ASSOCIATE, &any).await?;
        tcp.flush().await?;

        // Если прокси вернул 0.0.0.0, связь с ним держим через тот же TCP.
        let relay_host = if bind_host == "0.0.0.0" || bind_host.is_empty() {
            self.server.ip().to_string()
        } else {
            bind_host
        };
        let relay_port = if bind_port == 0 { self.server.port() } else { bind_port };

        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(format!("{relay_host}:{relay_port}")).await?;

        Ok(Arc::new(SocksUdp { inner: sock, tcp }))
    }

    async fn probe(&self, timeout: Duration) -> ProbeResult {
        let started = std::time::Instant::now();
        let target = Target { host: "www.gstatic.com".into(), port: 443, is_tcp: true };
        let req = Request { target };
        let r = tokio::time::timeout(timeout, self.connect(&req)).await;
        let resolved_via = Some(if self.remote_dns { "remote" } else { "local" });
        match r {
            Ok(Ok(_)) => ProbeResult {
                ok: true,
                latency_ms: Some(started.elapsed().as_millis() as u64),
                resolved_via,
                error: None,
            },
            Ok(Err(e)) => ProbeResult {
                ok: false,
                latency_ms: None,
                resolved_via,
                error: Some(e.to_string()),
            },
            Err(_) => ProbeResult {
                ok: false,
                latency_ms: None,
                resolved_via,
                error: Some("таймаут".into()),
            },
        }
    }
}

/// UDP через SOCKS5 ASSOCIATE: каждый дейтаграмм оборачивается в SOCKS5-заголовок.
struct SocksUdp {
    inner: UdpSocket,
    /// TCP-соединение держим живым: многие серверы закрывают UDP-канал,
    /// как только ассоциированный сокет отвалится. Поле не читается, но
    /// его существование и есть механизм удержания.
    #[allow(dead_code)]
    tcp: TcpStream,
}

#[async_trait]
impl UdpSession for SocksUdp {
    async fn send_to(&self, data: &[u8], dst: &Target) -> Result<()> {
        let mut pkt = Vec::with_capacity(data.len() + 22);
        pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV
        let addr = if dst.host.parse::<std::net::IpAddr>().is_ok() {
            socks_addr_bytes(&dst.host, dst.port)?
        } else {
            socks_addr_bytes(&dst.host, dst.port)?
        };
        pkt.extend_from_slice(&addr);
        pkt.extend_from_slice(data);
        self.inner.send(&pkt).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8], timeout: Duration) -> Result<(usize, Target)> {
        let mut pkt = vec![0u8; 65535];
        let n = tokio::time::timeout(timeout, self.inner.recv(&mut pkt))
            .await
            .map_err(|_| Error::Timeout("UDP: нет данных от прокси".into()))??;
        // Пропускаем RSV(2) + FRAG(1) + ADDR + PORT.
        if n < 5 {
            return Err(Error::protocol("socks", "слишком короткий UDP-ответ"));
        }
        let atyp = pkt[3];
        let addr_len = match atyp {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => 1 + pkt[4] as usize + 2,
            _ => return Err(Error::protocol("socks", "неизвестный тип адреса в UDP-ответе")),
        };
        let payload_at = 4 + addr_len;
        if n <= payload_at {
            return Err(Error::protocol("socks", "пустой UDP-ответ"));
        }
        let (host, port) = parse_socks_addr(&pkt[3..])?;
        let len = n - payload_at;
        let len = len.min(buf.len());
        buf[..len].copy_from_slice(&pkt[payload_at..payload_at + len]);
        Ok((len, Target { host, port, is_tcp: false }))
    }

    fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
    }
}

// ───────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Минимальный SOCKS5-сервер для тестов.
    ///
    /// Читает запрос целиком одним `read` (все байты уже в буфере — клиент
    /// отправляет их одним `write_all`), затем отвечает и держит соединение
    /// открытым. Отдельные `read_exact` здесь давали бы взаимную блокировку:
    /// сервер ждал бы хвоста запроса, которого клиент не отправит, пока не
    /// прочитает ответ.
    async fn fake_socks(rep: u8) -> (SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        use tokio::io::AsyncReadExt as _;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = captured.clone();
        tokio::spawn(async move {
            let (mut s, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            // Фаза 1: приветствие. Клиент шлёт его одним write, читаем одним read.
            let mut buf = vec![0u8; 4096];
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                s.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) => n,
                _ => return,
            };
            sink.lock().unwrap().extend_from_slice(&buf[..n]);
            // Выбор метода: 0x00 = «без аутентификации».
            let _ = s.write_all(&[VER, 0x00]).await;

            // Фаза 2: запрос CONNECT. Он тоже приходит одним write.
            let n = match tokio::time::timeout(
                std::time::Duration::from_secs(2),
                s.read(&mut buf),
            )
            .await
            {
                Ok(Ok(n)) => n,
                _ => return,
            };
            sink.lock().unwrap().extend_from_slice(&buf[..n]);
            // Ответ: VER, REP, RSV, ATYP=IPv4, BND.ADDR, BND.PORT
            let reply = vec![VER, rep, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x01, 0xBB];
            let _ = s.write_all(&reply).await;
            let _ = s.flush().await;
            // Держим соединение живым, пока тест не закончит.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        });
        (addr, captured)
    }

    fn cfg(addr: SocketAddr, remote_dns: bool) -> OutboundSocks {
        OutboundSocks {
            name: "S".into(),
            server: addr.ip().to_string(),
            port: addr.port(),
            username: String::new(),
            password: String::new(),
            udp: true,
            remote_dns,
            test_url: None,
            test_timeout_ms: None,
        }
    }

    #[tokio::test]
    async fn connect_sends_domain_when_remote_dns() {
        let (addr, captured) = fake_socks(0x00).await;
        let p = SocksProxy::new(cfg(addr, true)).unwrap();
        let _s = p.connect(&Request::tcp("example.com", 80)).await.unwrap();
        assert!(p.remote_dns(), "socks5h обязан отдавать домен прокси");

        // В запросе домен должен уйти как домен (ATYP=0x03), а не как IP.
        // Ищем последнее вхождение CMD: приветствие [05,01,00] содержит ту же
        // пару байт, что и начало запроса.
        let req = captured.lock().unwrap().clone();
        assert!(req.len() > 16, "сервер должен был увидеть приветствие и запрос");
        let atyp_pos = req
            .windows(2)
            .rposition(|w| w == [CMD_CONNECT, 0x00])
            .map(|i| i + 2)
            .expect("нет запроса CONNECT");
        assert_eq!(req[atyp_pos], 0x03, "домен обязан передаваться прокси как домен");
        let len = req[atyp_pos + 1] as usize;
        let host = String::from_utf8_lossy(&req[atyp_pos + 2..atyp_pos + 2 + len]);
        assert_eq!(host, "example.com");
        // Порт идёт следом за доменом в сетевом порядке.
        assert_eq!(&req[atyp_pos + 2 + len..atyp_pos + 4 + len], &[0x00, 0x50]);
    }

    #[tokio::test]
    async fn local_dns_sends_ip_instead_of_domain() {
        let (addr, captured) = fake_socks(0x00).await;
        let p = SocksProxy::new(cfg(addr, false)).unwrap();
        let _ = p.connect(&Request::tcp("127.0.0.1", 8080)).await.unwrap();
        let req = captured.lock().unwrap().clone();
        let pos = req
            .windows(2)
            .rposition(|w| w == [CMD_CONNECT, 0x00])
            .map(|i| i + 2)
            .expect("нет запроса CONNECT");
        assert_eq!(req[pos], 0x01, "при remote_dns=false уходит IPv4, а не домен");
        assert_eq!(&req[pos + 1..pos + 5], &[127, 0, 0, 1]);
    }

    #[tokio::test]
    async fn connect_surfaces_proxy_rejection() {
        // REP = 0x02 «правило запрещает».
        let (addr, _) = fake_socks(0x02).await;
        let p = SocksProxy::new(cfg(addr, true)).unwrap();
        let err = p.connect(&Request::tcp("example.com", 80)).await.err().expect("ожидалась ошибка");
        assert!(err.to_string().contains("запрещает"), "{err}");
    }

    #[tokio::test]
    async fn auth_required_without_credentials_fails() {
        use tokio::io::AsyncReadExt as _;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = match listener.accept().await { Ok(v) => v, Err(_) => return };
            let mut buf = vec![0u8; 64];
            let _ = s.read(&mut buf).await;
            // Отвечаем: требуется username/password.
            let _ = s.write_all(&[VER, 0x02]).await;
        });
        let p = SocksProxy::new(cfg(addr, true)).unwrap();
        let err = p.connect(&Request::tcp("example.com", 80)).await.err().expect("ожидалась ошибка");
        assert!(err.to_string().contains("логин"), "{err}");
    }

    use tokio::net::TcpListener;
}
