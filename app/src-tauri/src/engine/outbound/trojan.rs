//! Trojan по схеме trojango/go-trojan.
//!
//! Протокол подозрительно похож на SOCKS5, но внутри TLS и с проверкой
//! пароля на каждом пакете: клиент шлёт `CMD, ADDR, CRLF, payload, SHA224(pass), CRLF`.
//! Проверка на каждом пакете — защита от подмены данных внутри TLS (в отличие
//! от SOCKS5, где пароль проверяется один раз на рукопожатии).
//!
//! Реализация UDP намеренно не сделана: протокол требует отдельного
//! согласования UDP-сессии, а недоделанный QUIC-туннель хуже, чем честный
//! отказ с внятной ошибкой, по которой движок уведёт поток в DIRECT.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
#[allow(unused_imports)]
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::config::OutboundTrojan;
use crate::engine::outbound::{
    connect_proxy, poll_read_into, socks_addr_bytes, AsyncReadWrite, Outbound, Request, UdpSession,
};
use crate::engine::tls::build_tls_config;
use crate::error::{Error, Result};

/// Длина подписи: 56 hex-символов SHA224 плюс CRLF.
const SIG_LEN: usize = 58;

pub struct Trojan {
    name: String,
    server: SocketAddr,
    host_header: String,
    password_hash: [u8; 56],
    tls_connector: tokio_rustls::TlsConnector,
    udp: bool,
}

/// SHA224 от пароля в hex-нижнем регистре — ровно то, что требует протокол.
pub fn trojan_hash(password: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha224::digest(password.as_bytes()))
}

impl Trojan {
    pub fn new(cfg: OutboundTrojan) -> Result<Self> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<_> = (cfg.server.as_str(), cfg.port).to_socket_addrs()?.collect();
        let server = addrs
            .first()
            .copied()
            .ok_or_else(|| Error::ConfigInvalid(format!("{} не разрешается", cfg.server)))?;
        let host_header = if cfg.sni.is_empty() {
            cfg.server.clone()
        } else {
            cfg.sni.clone()
        };
        let tls_connector = build_tls_config(&host_header, &cfg.alpn, cfg.skip_cert_verify)?;
        let hash = trojan_hash(&cfg.password);
        let mut password_hash = [0u8; 56];
        password_hash.copy_from_slice(hash.as_bytes());
        Ok(Self {
            name: cfg.name,
            server,
            host_header,
            password_hash,
            tls_connector,
            udp: cfg.udp,
        })
    }

    async fn open_tls(&self) -> Result<TlsStream<TcpStream>> {
        let tcp = connect_proxy(self.server, Duration::from_secs(10)).await?;
        let name =
            rustls::pki_types::ServerName::try_from(self.host_header.clone()).map_err(|e| {
                Error::Tls(format!(
                    "недопустимое имя сервера {:?}: {e}",
                    self.host_header
                ))
            })?;
        self.tls_connector
            .connect(name, tcp)
            .await
            .map_err(|e| Error::Tls(format!("TLS handshake: {e}")))
    }
}

#[async_trait]
impl Outbound for Trojan {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "trojan"
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    fn remote_dns(&self) -> bool {
        true
    }

    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>> {
        let mut tls = self.open_tls().await?;
        let mut head = Vec::with_capacity(96);
        head.push(0x01u8); // CMD_CONNECT
        head.extend_from_slice(&socks_addr_bytes(&req.target.host, req.target.port)?);
        head.extend_from_slice(b"\r\n");
        head.extend_from_slice(&self.password_hash);
        head.extend_from_slice(b"\r\n");
        tls.write_all(&head).await?;
        tls.flush().await?;
        Ok(Box::new(TrojanStream {
            inner: tls,
            password_hash: self.password_hash,
            out: VecDeque::new(),
            sig: [0u8; SIG_LEN],
            sig_filled: 0,
        }))
    }

    async fn open_udp(&self) -> Result<Arc<dyn UdpSession>> {
        let _ = self.udp;
        Err(Error::protocol(
            "trojan",
            "UDP через Trojan в этой версии не реализован. \
             Для QUIC и DNS добавьте outbound SOCKS5h с udp: true и направьте \
             на него правило NETWORK,udp",
        ))
    }
}

/// TLS-поток с посыпанием исходящих кадров подписью и проверкой входящих.
struct TrojanStream {
    inner: TlsStream<TcpStream>,
    password_hash: [u8; 56],
    /// Очередь исходящих кадров и смещение в первом из них.
    out: VecDeque<(Vec<u8>, usize)>,
    /// Накопитель входящей подписи.
    sig: [u8; SIG_LEN],
    sig_filled: usize,
}

impl AsyncRead for TrojanStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();

        // 1. Снимаем подпись: 56 hex-символов SHA224(пароль) + CRLF.
        //    Накапливаем по частям — TCP не обязан прислать её целиком.
        while me.sig_filled < SIG_LEN {
            let n = match poll_read_into(&mut me.inner, cx, &mut me.sig[me.sig_filled..]) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(n)) => n,
            };
            if n == 0 {
                return std::task::Poll::Ready(if me.sig_filled == 0 {
                    // Ровно на границе: поток закрылся штатно.
                    Ok(())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "trojan: поток оборвался внутри подписи",
                    ))
                });
            }
            me.sig_filled += n;
        }

        if me.sig[..56] != me.password_hash {
            return std::task::Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "trojan: сервер прислал неверную подпись пароля",
            )));
        }
        me.sig_filled = 0;

        // 2. Читаем полезную нагрузку прямо в буфер вызывающего: промежуточный
        //    буфер означал бы лишний memcpy на каждом пакете.
        let n = match poll_read_into(&mut me.inner, cx, buf.initialize_unfilled()) {
            std::task::Poll::Pending => return std::task::Poll::Pending,
            std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            std::task::Poll::Ready(Ok(n)) => n,
        };
        buf.advance(n);
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TrojanStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        if data.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        let mut frame = Vec::with_capacity(data.len() + SIG_LEN);
        frame.extend_from_slice(data);
        frame.extend_from_slice(&me.password_hash);
        frame.extend_from_slice(b"\r\n");
        me.out.push_back((frame, 0));
        std::task::Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        while let Some((frame, off)) = me.out.front_mut() {
            match std::pin::Pin::new(&mut me.inner).poll_write(cx, &frame[*off..]) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "trojan: сервер закрыл соединение",
                    )))
                }
                std::task::Poll::Ready(Ok(n)) => {
                    *off += n;
                    if *off >= frame.len() {
                        me.out.pop_front();
                    }
                }
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_sha224_hex_of_password() {
        use sha2::Digest;
        let expected = hex::encode(sha2::Sha224::digest(b"hunter2"));
        assert_eq!(trojan_hash("hunter2"), expected);
        assert_eq!(trojan_hash("hunter2").len(), 56);
        assert_ne!(trojan_hash("hunter2"), trojan_hash("hunter3"));
    }

    fn cfg() -> OutboundTrojan {
        OutboundTrojan {
            name: "T".into(),
            server: "127.0.0.1".into(),
            port: 443,
            password: "p".into(),
            sni: "example.com".into(),
            alpn: vec!["h2".into(), "http/1.1".into()],
            skip_cert_verify: false,
            udp: true,
            test_url: None,
            test_timeout_ms: None,
        }
    }

    #[test]
    fn construction_resolves_sniffed_name_without_network() {
        let t = Trojan::new(cfg()).unwrap();
        assert_eq!(t.host_header, "example.com");
        assert_eq!(t.password_hash.len(), 56);
    }

    #[tokio::test]
    async fn udp_returns_actionable_error_not_panic() {
        let t = Trojan::new(cfg()).unwrap();
        let err = t.open_udp().await.err().expect("ожидалась ошибка");
        let msg = err.to_string();
        assert!(
            msg.contains("SOCKS5h"),
            "ошибка должна подсказывать решение: {msg}"
        );
    }

    #[test]
    fn request_head_layout_is_socks5_shaped() {
        // CMD=0x01, ATYP=0x03, len, домен, порт, CRLF
        let mut head = vec![0x01u8];
        head.extend_from_slice(&socks_addr_bytes("example.com", 443).unwrap());
        head.extend_from_slice(b"\r\n");
        assert_eq!(&head[..2], &[0x01, 0x03]);
        assert_eq!(head[2] as usize, 11);
        assert_eq!(&head[3..14], b"example.com");
        assert_eq!(&head[14..16], &[0x01, 0xBB]);
        assert_eq!(&head[16..], b"\r\n");
    }
}
