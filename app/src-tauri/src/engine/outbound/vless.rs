//! VLESS (v2fly/Xray-совместимый).
//!
//! Формат запроса: `ver(1)=0, uuid(16), addonsLen(1)=0, cmd(1), port(2), atyp(1), addr, payload`.
//! **Важно:** типы адресов здесь свои, не как в SOCKS5 — `0x01` IPv4,
//! `0x02` домен с префиксом длины, `0x03` IPv6. Путать их — типовая ошибка,
//! из-за которой соединение молча не работает.
//!
//! Транспорты: `tcp` (сырой) и `ws` (WebSocket поверх HTTP Upgrade).
//! `Reality`/`XTLS` не поддерживаются: для них нужен не TLS, а особый
//! криптографический хендшейк с серверным ключом, и обычный клиент сюда не
//! подходит. Конфиг с `flow` отвергается на этапе валидации.
//!
//! ⚠ Статус: написан по спецификации, проверен синтетическими тестами, но
//! **не проверен против живого xray-сервера**. GUI помечает такие outbound'ы.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::config::OutboundVless;
use crate::engine::outbound::{
    connect_proxy, poll_read_into, AsyncReadWrite, Outbound, Request, UdpSession,
};
use crate::engine::rules::Target;
use crate::engine::tls::build_tls_config;
use crate::error::{Error, Result};

/// Типы адресов VLESS. Не совпадают с SOCKS5.
pub const ATYP_V4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x02;
pub const ATYP_V6: u8 = 0x03;

const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;

pub struct Vless {
    name: String,
    server: SocketAddr,
    uuid: [u8; 16],
    use_tls: bool,
    use_ws: bool,
    path: String,
    host_header: String,
    tls_connector: tokio_rustls::TlsConnector,
    udp: bool,
}

impl Vless {
    pub fn new(cfg: OutboundVless) -> Result<Self> {
        use std::net::ToSocketAddrs;
        let uuid = cfg.uuid.parse::<uuid::Uuid>()?.as_bytes().to_vec();
        let mut u = [0u8; 16];
        u.copy_from_slice(&uuid);

        let addrs: Vec<_> = (cfg.server.as_str(), cfg.port).to_socket_addrs()?.collect();
        let server = addrs
            .first()
            .copied()
            .ok_or_else(|| Error::ConfigInvalid(format!("{} не разрешается", cfg.server)))?;

        let sni = if cfg.sni.is_empty() {
            cfg.server.clone()
        } else {
            cfg.sni.clone()
        };
        let use_ws = cfg.network.as_deref() == Some("ws");
        // Без TLS WebSocket тоже возможен (ws://), но сервер без TLS почти
        // всегда означает «забыли включить», поэтому требуем TLS для ws.
        let use_tls = cfg.tls || use_ws;
        let tls_connector = build_tls_config(
            &sni,
            &["h2".to_string(), "http/1.1".to_string()],
            cfg.skip_cert_verify,
        )?;

        Ok(Self {
            name: cfg.name,
            server,
            uuid: u,
            use_tls,
            use_ws,
            path: if cfg.path.is_empty() {
                "/".into()
            } else {
                cfg.path.clone()
            },
            host_header: if cfg.host.is_empty() {
                sni
            } else {
                cfg.host.clone()
            },
            tls_connector,
            udp: cfg.udp,
        })
    }

    /// Собирает первые байты запроса: заголовок VLESS + адрес назначения.
    pub fn build_request_header(target: &Target, is_udp: bool) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(24 + target.host.len());
        out.push(0x00); // версия
                        // uuid добавит вызывающий: держим функцию чистой для тестирования.
        out.push(0x00); // addonsLen
        out.push(if is_udp { CMD_UDP } else { CMD_TCP });
        out.extend_from_slice(&target.port.to_be_bytes());
        out.extend_from_slice(&encode_addr(&target.host)?);
        Ok(out)
    }

    fn header(&self, target: &Target, is_udp: bool) -> Result<Vec<u8>> {
        let mut out = vec![0x00];
        out.extend_from_slice(&self.uuid);
        out.extend_from_slice(&Self::build_request_header(target, is_udp)?[1..]);
        Ok(out)
    }

    async fn open_transport(&self) -> Result<Box<dyn AsyncReadWrite>> {
        let tcp = connect_proxy(self.server, Duration::from_secs(10)).await?;
        if self.use_tls {
            let sni = rustls::pki_types::ServerName::try_from(self.host_header.clone())
                .map_err(|e| Error::Tls(format!("плохое SNI {:?}: {e}", self.host_header)))?;
            let tls: TlsStream<TcpStream> = self
                .tls_connector
                .connect(sni, tcp)
                .await
                .map_err(|e| Error::Tls(format!("TLS handshake: {e}")))?;
            if self.use_ws {
                Ok(Box::new(self.ws_handshake(tls).await?))
            } else {
                Ok(Box::new(tls))
            }
        } else {
            if self.use_ws {
                Ok(Box::new(self.ws_handshake(tcp).await?))
            } else {
                Ok(Box::new(tcp))
            }
        }
    }

    /// HTTP/1.1 Upgrade до WebSocket. Ответ сервера не читаем целиком: если
    /// он не 101, соединение надо честно закрыть.
    async fn ws_handshake<S>(&self, stream: S) -> Result<WebSocket<S>>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    {
        let mut s = stream;
        let key = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            rand::random::<[u8; 16]>(),
        );
        let req = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            self.path, self.host_header, key
        );
        s.write_all(req.as_bytes()).await?;
        s.flush().await?;

        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if s.read_exact(&mut byte).await.is_err() {
                return Err(Error::protocol(
                    "vless",
                    "сервер закрыл соединение на WS-рукопожатии",
                ));
            }
            head.push(byte[0]);
            if head.len() > 4096 {
                return Err(Error::protocol(
                    "vless",
                    "неразумный размер ответа на WS-рукопожатии",
                ));
            }
        }
        let text = String::from_utf8_lossy(&head);
        if !text.starts_with("HTTP/1.1 101") {
            let code = text
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .unwrap_or("?");
            return Err(Error::protocol(
                "vless",
                format!("WS Upgrade отклонён, код {code}"),
            ));
        }
        Ok(WebSocket::<S>::new(s))
    }
}

/// Адрес в формате VLESS: `atyp | addr | port`.
pub fn encode_addr(host: &str) -> Result<Vec<u8>> {
    use std::net::IpAddr;
    let mut out = Vec::new();
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            out.push(ATYP_V4);
            out.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            out.push(ATYP_V6);
            out.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(Error::protocol(
                    "vless",
                    format!("домен {host:?} длиннее 255 байт"),
                ));
            }
            out.push(ATYP_DOMAIN);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    Ok(out)
}

/// Минимальная обёртка WebSocket: маскирует исходящие кадры, размаскирует
/// входящие и склеивает фрагментированные сообщения в непрерывный поток.
pub struct WebSocket<S> {
    inner: S,
    /// Остаток непрочитанного сообщения.
    pending: Vec<u8>,
    pending_pos: usize,
    closed: bool,
}

impl<S> WebSocket<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            pending: Vec::new(),
            pending_pos: 0,
            closed: false,
        }
    }

    /// Кадр с маской (клиент обязан маскировать) и payload <= 125 байт.
    /// Большие порции режем на части.
    fn frames(data: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        for chunk in data.chunks(120) {
            let mut f = Vec::with_capacity(chunk.len() + 14);
            f.push(0x82); // FIN + binary
            let mask = [0u8; 4];
            f.push(0x80 | chunk.len() as u8);
            f.extend_from_slice(&mask);
            for (i, b) in chunk.iter().enumerate() {
                f.push(b ^ mask[i % 4]);
            }
            out.push(f);
        }
        out
    }
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for WebSocket<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.pending_pos < me.pending.len() {
                let n = (me.pending.len() - me.pending_pos).min(buf.remaining());
                buf.put_slice(&me.pending[me.pending_pos..me.pending_pos + n]);
                me.pending_pos += n;
                return std::task::Poll::Ready(Ok(()));
            }
            if me.closed {
                return std::task::Poll::Ready(Ok(()));
            }
            // Заголовок кадра: 2 байта минимум.
            let mut head = [0u8; 2];
            let n = match poll_read_into(&mut me.inner, cx, &mut head) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(n)) => n,
            };
            if n == 0 {
                me.closed = true;
                return std::task::Poll::Ready(Ok(()));
            }
            if n < 2 {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "ws: обрыв заголовка кадра",
                )));
            }
            let masked = head[1] & 0x80 != 0;
            let len = head[1] & 0x7F;
            let mut payload_len = match len {
                126 => 2usize,
                127 => 8,
                n => n as usize,
            };
            if len > 125 {
                let mut ext = [0u8; 8];
                let want = payload_len.min(8);
                let got = match poll_read_into(&mut me.inner, cx, &mut ext[..want]) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(n)) => n,
                };
                if got < want {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "ws: обрыв длины кадра",
                    )));
                }
                payload_len = if len == 126 {
                    u16::from_be_bytes([ext[0], ext[1]]) as usize
                } else {
                    u64::from_be_bytes(ext) as usize
                };
            }
            let mut mask = [0u8; 4];
            if masked {
                let got = match poll_read_into(&mut me.inner, cx, &mut mask) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(n)) => n,
                };
                if got < 4 {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "ws: обрыв маски кадра",
                    )));
                }
            }
            if payload_len > 1 << 20 {
                return std::task::Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ws: кадр больше 1 МиБ",
                )));
            }
            let mut payload = vec![0u8; payload_len];
            let mut filled = 0;
            while filled < payload_len {
                let got = match poll_read_into(&mut me.inner, cx, &mut payload[filled..]) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(n)) => n,
                };
                if got == 0 {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "ws: обрыв тела кадра",
                    )));
                }
                filled += got;
            }
            if masked {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= mask[i % 4];
                }
            }
            let opcode = head[0] & 0x0F;
            match opcode {
                0x8 => {
                    me.closed = true;
                    return std::task::Poll::Ready(Ok(()));
                }
                0x9 => continue, // ping — отвечаем ниже в write, пока игнорируем
                0xA => continue, // pong
                0x0..=0x2 => {
                    me.pending = payload;
                    me.pending_pos = 0;
                }
                other => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("ws: неизвестный код операции {other}"),
                    )))
                }
            }
        }
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for WebSocket<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        let mut pending = data.len();
        for frame in WebSocket::<S>::frames(data) {
            match std::pin::Pin::new(&mut me.inner).poll_write(cx, &frame) {
                std::task::Poll::Pending => {
                    return if pending == data.len() {
                        std::task::Poll::Pending
                    } else {
                        std::task::Poll::Ready(Ok(data.len() - pending))
                    };
                }
                std::task::Poll::Ready(Ok(0)) => break,
                std::task::Poll::Ready(Ok(n)) => pending = pending.saturating_sub(n),
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            }
        }
        std::task::Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl Outbound for Vless {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vless"
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    fn remote_dns(&self) -> bool {
        true
    }

    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>> {
        let mut stream = self.open_transport().await?;
        let head = self.header(&req.target, false)?;
        stream.write_all(&head).await?;
        stream.flush().await?;
        Ok(stream)
    }

    async fn open_udp(&self) -> Result<Arc<dyn UdpSession>> {
        Err(Error::protocol(
            "vless",
            "UDP для VLESS не реализован; используйте SOCKS5h для QUIC",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_types_differ_from_socks5() {
        // Ключевое отличие, из-за которого чаще всего ломается реализация.
        let v4 = encode_addr("1.2.3.4").unwrap();
        assert_eq!(v4[0], 0x01, "IPv4 в VLESS — 0x01");
        let dom = encode_addr("example.com").unwrap();
        assert_eq!(dom[0], 0x02, "домен в VLESS — 0x02, не 0x03 как в SOCKS5");
        assert_eq!(dom[1], 11);
        let v6 = encode_addr("2001:db8::1").unwrap();
        assert_eq!(v6[0], 0x03, "IPv6 в VLESS — 0x03, не 0x04 как в SOCKS5");
    }

    #[test]
    fn header_layout() {
        let t = Target {
            host: "example.com".into(),
            port: 443,
            is_tcp: true,
        };
        let h = Vless::build_request_header(&t, false).unwrap();
        assert_eq!(h[0], 0x00, "версия");
        assert_eq!(h[1], 0x00, "длина addons");
        assert_eq!(h[2], CMD_TCP);
        assert_eq!(&h[3..5], &[0x01, 0xBB]);
        assert_eq!(h[5], ATYP_DOMAIN);
    }

    #[test]
    fn udp_command_is_2() {
        let t = Target {
            host: "1.1.1.1".into(),
            port: 53,
            is_tcp: false,
        };
        let h = Vless::build_request_header(&t, true).unwrap();
        assert_eq!(h[2], CMD_UDP);
    }

    #[test]
    fn rejects_overlong_domain() {
        assert!(encode_addr(&"a".repeat(300)).is_err());
    }

    #[test]
    fn ws_frames_are_masked_and_split() {
        let frames = WebSocket::<tokio::io::DuplexStream>::frames(&[0u8; 300]);
        assert_eq!(frames.len(), 3, "300 байт режутся на 3 кадра по 120");
        for f in &frames {
            assert_eq!(f[0], 0x82, "FIN + binary");
            assert_ne!(f[1] & 0x80, 0, "клиент обязан маскировать кадры");
        }
    }

    #[test]
    fn construction_rejects_bad_uuid() {
        let cfg = OutboundVless {
            name: "V".into(),
            server: "127.0.0.1".into(),
            port: 443,
            uuid: "не-uuid".into(),
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
        };
        assert!(Vless::new(cfg).is_err());
    }

    #[test]
    fn ws_forces_tls_on() {
        let cfg = OutboundVless {
            name: "V".into(),
            server: "127.0.0.1".into(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            flow: String::new(),
            network: Some("ws".into()),
            tls: false,
            sni: "example.com".into(),
            path: "/ws".into(),
            host: String::new(),
            skip_cert_verify: false,
            udp: true,
            test_url: None,
            test_timeout_ms: None,
        };
        let v = Vless::new(cfg).unwrap();
        assert!(v.use_tls);
        assert!(v.use_ws);
        assert_eq!(v.path, "/ws");
    }
}
