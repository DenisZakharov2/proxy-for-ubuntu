//! HTTP-прокси по методу CONNECT (RFC 7231 §4.3.6).
//!
//! Только CONNECT: обычные GET через прокси для прозрачного перехвата не
//! нужны, а поддержка означала бы ещё один путь, где можно ошибиться.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::config::OutboundHttp;
use crate::engine::outbound::{connect_proxy, AsyncReadWrite, Outbound, Request, UdpSession};
use crate::error::{Error, Result};

pub struct HttpProxy {
    name: String,
    server: SocketAddr,
    auth_header: Option<String>,
}

impl HttpProxy {
    pub fn new(cfg: OutboundHttp) -> Result<Self> {
        use std::net::ToSocketAddrs;
        // Пароль может лежать в отдельном файле — читаем на старте, в памяти
        // храним уже готовый заголовок.
        let password = match &cfg.password_file {
            Some(p) => std::fs::read_to_string(p)
                .map_err(|e| Error::ConfigInvalid(format!("не удалось прочитать {p}: {e}")))?
                .trim_end()
                .to_string(),
            None => cfg.password.clone(),
        };
        let auth_header = if cfg.username.is_empty() && password.is_empty() {
            None
        } else {
            let raw = format!("{}:{}", cfg.username, password);
            Some(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(raw)
            ))
        };

        let addrs: Vec<_> = (cfg.server.as_str(), cfg.port).to_socket_addrs()?.collect();
        let server = addrs
            .first()
            .copied()
            .ok_or_else(|| Error::ConfigInvalid(format!("{} не разрешается", cfg.server)))?;

        Ok(Self {
            name: cfg.name,
            server,
            auth_header,
        })
    }

    /// CONNECT-запрос. Домен уходит как есть — резолвит прокси.
    async fn connect_tunnel(&self, host: &str, port: u16) -> Result<TcpStream> {
        let mut s = connect_proxy(self.server, Duration::from_secs(10)).await?;

        // Заголовок домена не может содержать пробелов и непечатных символов —
        // иначе можно было бы инъецировать в запрос.
        if host.is_empty()
            || !host.bytes().all(|b| (0x21..=0x7E).contains(&b))
            || host.contains(':') && host.parse::<std::net::IpAddr>().is_err()
        {
            return Err(Error::protocol(
                "http",
                format!("недопустимый домен {host:?}"),
            ));
        }

        let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
        if let Some(a) = &self.auth_header {
            req.push_str(&format!("Proxy-Authorization: {a}\r\n"));
        }
        req.push_str("Proxy-Connection: keep-alive\r\n\r\n");

        s.write_all(req.as_bytes()).await?;
        s.flush().await?;

        // Ответ приходит построчно. Нас интересует только код статуса,
        // остальное читаем до пустой строки, чтобы не оставить мусор в буфере.
        let mut status_line = String::new();
        loop {
            let mut byte = [0u8; 1];
            s.read_exact(&mut byte).await?;
            if byte[0] == b'\n' {
                break;
            }
            if byte[0] != b'\r' {
                status_line.push(byte[0] as char);
            }
            if status_line.len() > 512 {
                return Err(Error::protocol("http", "слишком длинная строка статуса"));
            }
        }
        // Остальные заголовки до конца блока.
        let mut prev_cr = false;
        loop {
            let mut byte = [0u8; 1];
            if s.read_exact(&mut byte).await.is_err() {
                break;
            }
            if byte[0] == b'\n' {
                if prev_cr {
                    break;
                }
                prev_cr = false;
            } else {
                prev_cr = byte[0] == b'\r';
            }
        }

        let code: u16 = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse().ok())
            .ok_or_else(|| Error::protocol("http", format!("непонятный ответ: {status_line:?}")))?;

        match code {
            200 => {
                let _ = s.set_nodelay(true);
                Ok(s)
            }
            407 => Err(Error::protocol(
                "http",
                "прокси требует логин и пароль (407)",
            )),
            403 => Err(Error::protocol(
                "http",
                "прокси запретил доступ к этому хосту (403)",
            )),
            502..=504 => Err(Error::protocol(
                "http",
                format!("прокси не смог связаться с {host}:{port} ({code})"),
            )),
            other => Err(Error::protocol(
                "http",
                format!("неожиданный код ответа {other}"),
            )),
        }
    }
}

#[async_trait]
impl Outbound for HttpProxy {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "http"
    }

    fn supports_udp(&self) -> bool {
        false
    }

    fn remote_dns(&self) -> bool {
        true
    }

    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>> {
        let s = self
            .connect_tunnel(&req.target.host, req.target.port)
            .await?;
        Ok(Box::new(s))
    }

    async fn open_udp(&self) -> Result<std::sync::Arc<dyn UdpSession>> {
        Err(Error::protocol(
            "http",
            "HTTP-прокси не умеет UDP — QUIC и DNS пойдут через другой outbound",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    async fn fake_connect_proxy(
        status: &'static str,
        capture_auth: bool,
    ) -> (SocketAddr, Arc<tokio::sync::Mutex<Option<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let slot = Arc::new(tokio::sync::Mutex::new(None));
        let s2 = slot.clone();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 2048];
            let n = s.read(&mut buf).await.unwrap();
            let text = String::from_utf8_lossy(&buf[..n]).to_string();
            if capture_auth {
                // Сравниваем в нижнем регистре, но берём значение из
                // исходной строки: base64 чувствителен к регистру.
                for line in text.lines() {
                    let lower = line.to_ascii_lowercase();
                    if let Some(pos) = lower.strip_prefix("proxy-authorization: ") {
                        let _ = pos;
                        let value = line["proxy-authorization: ".len()..].trim();
                        *s2.lock().await = Some(value.to_string());
                    }
                }
            }
            s.write_all(status.as_bytes()).await.unwrap();
            s.flush().await.unwrap();
            let _ = tokio::time::sleep(Duration::from_millis(30)).await;
        });
        (addr, slot)
    }

    #[tokio::test]
    async fn successful_connect_returns_stream() {
        let (addr, _) =
            fake_connect_proxy("HTTP/1.1 200 Connection established\r\n\r\n", false).await;
        let p = HttpProxy::new(OutboundHttp {
            name: "H".into(),
            server: addr.ip().to_string(),
            port: addr.port(),
            username: String::new(),
            password: String::new(),
            password_file: None,
            test_url: None,
            test_timeout_ms: None,
        })
        .unwrap();
        let s = p.connect(&Request::tcp("example.com", 443)).await.unwrap();
        assert!(!p.supports_udp());
        drop(s);
    }

    #[tokio::test]
    async fn maps_407_to_readable_error() {
        let (addr, _) =
            fake_connect_proxy("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n", false).await;
        let p = HttpProxy::new(OutboundHttp {
            name: "H".into(),
            server: addr.ip().to_string(),
            port: addr.port(),
            username: String::new(),
            password: String::new(),
            password_file: None,
            test_url: None,
            test_timeout_ms: None,
        })
        .unwrap();
        let err = p
            .connect(&Request::tcp("example.com", 443))
            .await
            .err()
            .expect("ожидалась ошибка");
        assert!(err.to_string().contains("407"), "{err}");
    }

    #[tokio::test]
    async fn sends_basic_auth_header() {
        let (addr, slot) = fake_connect_proxy("HTTP/1.1 200 OK\r\n\r\n", true).await;
        let p = HttpProxy::new(OutboundHttp {
            name: "H".into(),
            server: addr.ip().to_string(),
            port: addr.port(),
            username: "user".into(),
            password: "pass".into(),
            password_file: None,
            test_url: None,
            test_timeout_ms: None,
        })
        .unwrap();
        let _ = p.connect(&Request::tcp("example.com", 443)).await.unwrap();
        let got = slot.lock().await.clone().unwrap();
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("user:pass")
        );
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn rejects_header_injection_in_hostname() {
        let (addr, _) = fake_connect_proxy("HTTP/1.1 200 OK\r\n\r\n", false).await;
        let p = HttpProxy::new(OutboundHttp {
            name: "H".into(),
            server: addr.ip().to_string(),
            port: addr.port(),
            username: String::new(),
            password: String::new(),
            password_file: None,
            test_url: None,
            test_timeout_ms: None,
        })
        .unwrap();
        // Пробел позволяет дописать свой заголовок — такое имя обязано быть
        // отвергнуто до отправки в сокет.
        let err = p
            .connect(&Request::tcp("evil.com HTTP/1.1\r\nX: y", 443))
            .await
            .err()
            .expect("ожидалась ошибка");
        assert!(err.to_string().contains("недопустимый"), "{err}");
    }
}
