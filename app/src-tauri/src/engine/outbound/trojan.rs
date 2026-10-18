//! Trojan по схеме trojango/go-trojan.
//!
//! Протокол подозрительно похож на SOCKS5, но внутри TLS и с проверкой
//! пароля на каждом пакете: клиент шлёт `CMD, ADDR, CRLF, payload, SHA224(pass), CRLF`.
//! Проверка на каждом пакете — защита от подмены данных внутри TLS (в отличие
//! от SOCKS5, где пароль проверяется один раз на рукопожатии).
//!
//! UDP: каждая датаграмма — самостоятельная Trojan-сессия. Клиент шлёт
//! `ADDR, payload, SHA224(pass), CRLF` на UDP-порт сервера и получает
//! ответ в том же формате. Постоянного TCP/TLS-крыла не держим — это
//! упрощённая модель, достаточная для DNS и QUIC через Trojan.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
#[allow(unused_imports)]
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpStream, UdpSocket};
use tokio_rustls::client::TlsStream;

use crate::config::OutboundTrojan;
use crate::engine::outbound::{
    connect_proxy, parse_socks_addr, poll_read_into, socks_addr_bytes, AsyncReadWrite, Outbound,
    Request, UdpSession,
};
use crate::engine::rules::Target;
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
        if !self.udp {
            return Err(Error::protocol(
                "trojan",
                "UDP отключён в конфигурации outbound'а",
            ));
        }
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(self.server).await?;
        Ok(Arc::new(TrojanUdp {
            sock,
            password_hash: self.password_hash,
        }))
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

/// Длина адресного блока в начале UDP-датаграммы Trojan (ATYP + адрес + порт).
fn udp_addr_len(pkt: &[u8]) -> Result<usize> {
    if pkt.is_empty() {
        return Err(Error::protocol("trojan", "пустая UDP-датаграмма"));
    }
    Ok(match pkt[0] {
        0x01 => 1 + 4 + 2,  // ATYP + IPv4 + порт
        0x04 => 1 + 16 + 2, // ATYP + IPv6 + порт
        0x03 => {
            if pkt.len() < 2 {
                return Err(Error::protocol("trojan", "обрезанная длина домена"));
            }
            1 + 1 + pkt[1] as usize + 2 // ATYP + длина + домен + порт
        }
        other => {
            return Err(Error::protocol(
                "trojan",
                format!("неизвестный тип адреса {other:#x}"),
            ))
        }
    })
}

/// Собирает исходящую UDP-датаграмму: `[ADDR][DATA][SHA224(pass)][CRLF]`.
fn build_udp_datagram(addr: &[u8], data: &[u8], hash: &[u8; 56]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(addr.len() + data.len() + SIG_LEN);
    pkt.extend_from_slice(addr);
    pkt.extend_from_slice(data);
    pkt.extend_from_slice(hash);
    pkt.extend_from_slice(b"\r\n");
    pkt
}

/// Разбирает входящую UDP-датаграмму и проверяет подпись. Возвращает смещение
/// и длину полезной нагрузки плюс цель.
fn parse_udp_datagram(pkt: &[u8], hash: &[u8; 56]) -> Result<(usize, usize, Target)> {
    let addr_len = udp_addr_len(pkt)?;
    if pkt.len() < addr_len + SIG_LEN {
        return Err(Error::protocol("trojan", "слишком короткая UDP-датаграмма"));
    }
    let trailer = &pkt[pkt.len() - SIG_LEN..];
    if &trailer[..56] != hash || &trailer[56..] != b"\r\n" {
        return Err(Error::protocol(
            "trojan",
            "неверная подпись пароля в UDP-ответе",
        ));
    }
    let (host, port) = parse_socks_addr(&pkt[..addr_len])?;
    let data_start = addr_len;
    let data_len = pkt.len() - addr_len - SIG_LEN;
    Ok((
        data_start,
        data_len,
        Target {
            host,
            port,
            is_tcp: false,
        },
    ))
}

/// UDP-сессия Trojan без постоянного TCP: каждая датаграмма подписывается
/// хешем пароля и содержит адрес назначения.
///
/// shortcut: нет предварительного TCP-рукопожатия UDP ASSOCIATE, как у SOCKS5;
/// сервер, который требует установления сессии через connect() с CMD=0x03,
/// будет отбрасывать такие датаграммы — тогда в open_udp() добавить prologue.
struct TrojanUdp {
    sock: UdpSocket,
    password_hash: [u8; 56],
}

#[async_trait]
impl UdpSession for TrojanUdp {
    async fn send_to(&self, data: &[u8], dst: &Target) -> Result<()> {
        let addr = socks_addr_bytes(&dst.host, dst.port)?;
        let pkt = build_udp_datagram(&addr, data, &self.password_hash);
        self.sock.send(&pkt).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8], timeout: Duration) -> Result<(usize, Target)> {
        let mut pkt = vec![0u8; 65535];
        let n = tokio::time::timeout(timeout, self.sock.recv(&mut pkt))
            .await
            .map_err(|_| Error::Timeout("trojan UDP: нет данных от сервера".into()))??;
        let (start, len, target) = parse_udp_datagram(&pkt[..n], &self.password_hash)?;
        let data = &pkt[start..start + len];
        let copied = data.len().min(buf.len());
        buf[..copied].copy_from_slice(data);
        Ok((copied, target))
    }

    fn local_addr(&self) -> SocketAddr {
        self.sock
            .local_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
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

    #[test]
    fn udp_datagram_roundtrip_with_signature() {
        let addr = socks_addr_bytes("example.com", 443).unwrap();
        let data = b"hello udp";
        let hash = [42u8; 56];
        let pkt = build_udp_datagram(&addr, data, &hash);
        let (start, len, target) = parse_udp_datagram(&pkt, &hash).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
        assert!(!target.is_tcp);
        assert_eq!(&pkt[start..start + len], data);
        // Подпись неверна — ошибка.
        let mut bad = hash;
        bad[0] ^= 1;
        assert!(parse_udp_datagram(&pkt, &bad).is_err());
    }

    #[test]
    fn udp_rejects_short_packet_and_bad_trailer() {
        let hash = [1u8; 56];
        assert!(parse_udp_datagram(&[], &hash).is_err());
        assert!(parse_udp_datagram(&[0x03, 5, b'e'], &hash).is_err());
        // IPv4 без хвостовой подписи.
        let addr = socks_addr_bytes("1.2.3.4", 80).unwrap();
        assert!(parse_udp_datagram(&addr, &hash).is_err());
    }

    #[tokio::test]
    async fn open_udp_succeeds_when_enabled_and_fails_when_disabled() {
        let mut enabled = cfg();
        enabled.udp = true;
        let t = Trojan::new(enabled).unwrap();
        let _s = t.open_udp().await.expect("UDP-сессия должна открываться");

        let mut disabled = cfg();
        disabled.udp = false;
        let t = Trojan::new(disabled).unwrap();
        let err = t.open_udp().await.err().expect("ожидалась ошибка");
        assert!(err.to_string().contains("отключён"), "{err}");
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
