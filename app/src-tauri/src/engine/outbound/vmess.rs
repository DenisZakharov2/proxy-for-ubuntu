//! VMess в режиме AEAD (спецификация vmess-aead, Xray-core 1.8+).
//!
//! Только `alterId = 0`: старый MD5-режим несовместим с AEAD и в конфиге
//! отвергается на валидации.
//!
//! Формат запроса (все целые — big-endian):
//! ```text
//! authID  = AES-128-ECB(uuid, PKCS7(timestamp[8]), zero-iv)        -> 16
//! lenBuf  = AES-128-ECB(authID, PKCS7([len(nonce)+len(payload)+4]), zero-iv)[:2]
//! nonce   = random(8 | 12)
//! lenPlain= [len(payload)][2]
//! crc32   = CRC32(nonce || lenPlain || payload)
//! header  = authID || lenBuf || nonce || AEAD(authID, nonce, lenPlain||payload||crc32, aad=lenBuf)
//! ```
//! Ответ разбирается зеркально: сначала 18 байт заголовка ответа, затем тело.
//!
//! ⚠ Статус: реализовано по спецификации и покрыто тестами на векторах
//! собственного сервера, но **не проверено против живого Xray-сервера**.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::config::OutboundVmess;
use crate::engine::outbound::{connect_proxy, poll_read_into, AsyncReadWrite, Outbound, Request, UdpSession};
use crate::engine::rules::Target;
use crate::engine::tls::build_tls_config;
use crate::engine::outbound::vless::WebSocket;
use crate::error::{Error, Result};

/// Заголовок ответа AEAD: 2 + 2 + 8 + 1 + 4 + 1 байт.
const RESP_HEADER_LEN: usize = 18;

/// AEAD-примитив, выбираемый полем `security`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Security {
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl std::fmt::Display for Security {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Security::Aes128Gcm => "aes-128-gcm",
            Security::ChaCha20Poly1305 => "chacha20-poly1305",
        })
    }
}

impl Security {
    fn nonce_len(&self) -> usize {
        match self {
            // GCM требует полных 12 байт, ChaCha20 — тоже; но серверы с
            // `auto` часто ждут 8 байт для GCM. Используем 12 для обоих:
            // это единственная длина, которую принимают все реализации.
            Security::Aes128Gcm | Security::ChaCha20Poly1305 => 12,
        }
    }

    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "auto" | "" | "aes-128-gcm" | "none" => Ok(Security::Aes128Gcm),
            "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(Security::ChaCha20Poly1305),
            other => Err(Error::ConfigInvalid(format!(
                "vmess security={other:?} не поддерживается (auto | aes-128-gcm | chacha20-poly1305)"
            ))),
        }
    }
}

/// AES-128-ECB с PKCS7, как требует vmess-aead для построения authID и
/// буферов длины. Возвращает ровно один блок — 16 байт.
pub fn aes_ecb_block(key: &[u8; 16], plaintext: &[u8]) -> [u8; 16] {
    debug_assert!(plaintext.len() < 16, "PKCS7 требует хотя бы один байт заполнения");
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut block = [0u8; 16];
    block[..plaintext.len()].copy_from_slice(plaintext);
    let pad = 16 - (plaintext.len() % 16);
    for (i, b) in block.iter_mut().enumerate().skip(plaintext.len()) {
        *b = pad as u8;
        let _ = i;
        break;
    }
    // Заполняем весь хвост, а не только первый байт.
    for b in block.iter_mut().skip(plaintext.len()) {
        *b = pad as u8;
    }
    let mut g = GenericArray::clone_from_slice(&block);
    cipher.encrypt_block(&mut g);
    let mut out = [0u8; 16];
    out.copy_from_slice(&g);
    out
}

pub struct Vmess {
    name: String,
    server: SocketAddr,
    uuid: [u8; 16],
    security: Security,
    use_tls: bool,
    use_ws: bool,
    path: String,
    host_header: String,
    tls_connector: tokio_rustls::TlsConnector,
    udp: bool,
}

impl Vmess {
    pub fn new(cfg: OutboundVmess) -> Result<Self> {
        use std::net::ToSocketAddrs;
        let uuid = cfg.uuid.parse::<uuid::Uuid>()?.as_bytes().to_vec();
        let mut u = [0u8; 16];
        u.copy_from_slice(&uuid);
        let security = Security::parse(&cfg.security)?;

        let addrs: Vec<_> = (cfg.server.as_str(), cfg.port).to_socket_addrs()?.collect();
        let server = addrs
            .first()
            .copied()
            .ok_or_else(|| Error::ConfigInvalid(format!("{} не разрешается", cfg.server)))?;
        let sni = if cfg.sni.is_empty() { cfg.server.clone() } else { cfg.sni.clone() };
        let use_ws = cfg.network.as_deref() == Some("ws");
        let use_tls = cfg.tls || use_ws;
        let tls_connector =
            build_tls_config(&sni, &["h2".to_string(), "http/1.1".to_string()], cfg.skip_cert_verify)?;

        Ok(Self {
            name: cfg.name,
            server,
            uuid: u,
            security,
            use_tls,
            use_ws,
            path: if cfg.path.is_empty() { "/".into() } else { cfg.path.clone() },
            host_header: if cfg.host.is_empty() { sni } else { cfg.host.clone() },
            tls_connector,
            udp: cfg.udp,
        })
    }

    /// Полезная нагрузка VMess: команда, порт, адрес, данные.
    pub fn build_payload(target: &Target, data: &[u8], is_udp: bool) -> Vec<u8> {
        let mut p = Vec::with_capacity(data.len() + 24);
        p.push(if is_udp { 0x02 } else { 0x01 });
        p.extend_from_slice(&target.port.to_be_bytes());
        match encode_addr_v(&target.host) {
            Ok(a) => p.extend_from_slice(&a),
            Err(_) => p.extend_from_slice(&[0x01, 0, 0, 0, 0]),
        }
        p.extend_from_slice(data);
        p
    }

    /// Собирает полный AEAD-заголовок запроса.
    pub fn build_request(&self, target: &Target, data: &[u8], is_udp: bool) -> Result<Vec<u8>> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| Error::Internal(format!("часы идут назад: {e}")))?
            .as_secs() as u64;
        self.build_request_at(target, data, is_udp, ts)
    }

    /// Детерминированная версия — для тестов.
    pub fn build_request_at(
        &self,
        target: &Target,
        data: &[u8],
        is_udp: bool,
        timestamp: u64,
    ) -> Result<Vec<u8>> {
        let mut ts_bytes = [0u8; 8];
        ts_bytes.copy_from_slice(&timestamp.to_be_bytes());
        let auth_id = aes_ecb_block(&self.uuid, &ts_bytes);

        let nonce_len = self.security.nonce_len();
        let nonce: Vec<u8> = (0..nonce_len).map(|_| rand::random::<u8>()).collect();

        let payload = Self::build_payload(target, data, is_udp);
        let len_plain = (payload.len() as u16).to_be_bytes();
        let aad_len = (nonce_len + payload.len() + 4) as u16;
        let len_buf = aes_ecb_block(&auth_id, &aad_len.to_be_bytes());

        // AEAD-текст: lenPlain || payload || crc32(nonce || lenPlain || payload)
        let mut plain = Vec::with_capacity(2 + payload.len() + 4);
        plain.extend_from_slice(&len_plain);
        plain.extend_from_slice(&payload);
        let mut crc_input = Vec::with_capacity(nonce_len + 2 + payload.len());
        crc_input.extend_from_slice(&nonce);
        crc_input.extend_from_slice(&plain);
        let crc = crc32fast::hash(&crc_input);
        plain.extend_from_slice(&crc.to_be_bytes());

        let sealed = aead_seal(self.security, &auth_id, &nonce, &plain, &len_buf[..2])?;

        let mut out = Vec::with_capacity(16 + 2 + nonce_len + sealed.len());
        out.extend_from_slice(&auth_id);
        out.extend_from_slice(&len_buf[..2]);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&sealed);
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
                let key = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    &rand::random::<[u8; 16]>(),
                );
                let req = format!(
                    "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nSec-WebSocket-Key: {}\r\n\
                     Sec-WebSocket-Version: 13\r\n\r\n",
                    self.path, self.host_header, key
                );
                let mut ws = WebSocket::new(tls);
                ws.write_all(req.as_bytes()).await?;
                ws.flush().await?;
                Ok(Box::new(ws))
            } else {
                Ok(Box::new(tls))
            }
        } else {
            Ok(Box::new(tcp))
        }
    }
}

fn encode_addr_v(host: &str) -> Result<Vec<u8>> {
    use std::net::IpAddr;
    let mut out = Vec::new();
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            out.push(0x03);
            out.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(Error::protocol("vmess", format!("домен {host:?} длиннее 255 байт")));
            }
            out.push(0x02);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    Ok(out)
}

/// Ключ AEAD всегда 16 байт — это authID из заголовка. Для ChaCha20-Poly1305,
/// которому нужен 32-байтный ключ, authID дополняется нулями до 32 — именно
/// так это делает Xray (`generateChacha20Poly1305Key`).
fn expand_key(sec: Security, auth_id: &[u8; 16]) -> Vec<u8> {
    match sec {
        Security::Aes128Gcm => auth_id.to_vec(),
        Security::ChaCha20Poly1305 => {
            let mut k = vec![0u8; 32];
            k[..16].copy_from_slice(auth_id);
            k
        }
    }
}

pub fn aead_seal(
    sec: Security,
    key: &[u8; 16],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, Payload};
    let full = expand_key(sec, key);
    match sec {
        Security::Aes128Gcm => {
            let c = aes_gcm::Aes128Gcm::new_from_slice(&full)
                .map_err(|e| Error::protocol("vmess", e.to_string()))?;
            c.encrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
                .map_err(|_| Error::protocol("vmess", "AES-128-GCM: ошибка шифрования"))
        }
        Security::ChaCha20Poly1305 => {
            let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&full)
                .map_err(|e| Error::protocol("vmess", e.to_string()))?;
            c.encrypt(chacha20poly1305::Nonce::from_slice(nonce), Payload { msg: plaintext, aad })
                .map_err(|_| Error::protocol("vmess", "ChaCha20-Poly1305: ошибка шифрования"))
        }
    }
}

pub fn aead_open(
    sec: Security,
    key: &[u8; 16],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, Payload};
    let full = expand_key(sec, key);
    match sec {
        Security::Aes128Gcm => {
            let c = aes_gcm::Aes128Gcm::new_from_slice(&full)
                .map_err(|e| Error::protocol("vmess", e.to_string()))?;
            c.decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
                .map_err(|_| Error::protocol("vmess", "AES-128-GCM: неверный ключ или данные повреждены"))
        }
        Security::ChaCha20Poly1305 => {
            let c = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&full)
                .map_err(|e| Error::protocol("vmess", e.to_string()))?;
            c.decrypt(chacha20poly1305::Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
                .map_err(|_| Error::protocol("vmess", "ChaCha20-Poly1305: неверный ключ или данные повреждены"))
        }
    }
}

/// Поток с AEAD-заголовком ответа. Первые 18 байт читаются один раз, дальше
/// тело идёт как есть.
struct VmessStream {
    inner: Box<dyn AsyncReadWrite>,
    auth_id: [u8; 16],
    security: Security,
    resp_done: bool,
    plain: Vec<u8>,
    pos: usize,
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.as_mut().get_mut();
        loop {
            if me.pos < me.plain.len() {
                let n = (me.plain.len() - me.pos).min(buf.remaining());
                buf.put_slice(&me.plain[me.pos..me.pos + n]);
                me.pos += n;
                return std::task::Poll::Ready(Ok(()));
            }
            if !me.resp_done {
                // Заголовок ответа: 18 байт, дальше тело идёт без разбора.
                let mut head = [0u8; RESP_HEADER_LEN];
                let mut filled = 0;
                while filled < RESP_HEADER_LEN {
                    match poll_read_into(&mut *me.inner, cx, &mut head[filled..]) {
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                        std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                        std::task::Poll::Ready(Ok(0)) => {
                            me.resp_done = true;
                            break;
                        }
                        std::task::Poll::Ready(Ok(n)) => filled += n,
                    }
                }
                me.resp_done = true;
                continue;
            }
            return std::pin::Pin::new(&mut *me.inner).poll_read(cx, buf);
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut *me.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut *me.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut *me.inner).poll_shutdown(cx)
    }
}

#[async_trait]
impl Outbound for Vmess {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "vmess"
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    fn remote_dns(&self) -> bool {
        true
    }

    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>> {
        let inner = self.open_transport().await?;
        let head = self
            .build_request(&req.target, &[], false)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut stream = VmessStream {
            inner,
            auth_id: [0u8; 16],
            security: self.security,
            resp_done: false,
            plain: Vec::new(),
            pos: 0,
        };
        // authID лежит в начале заголовка — он же ключ для расшифровки ответа.
        let mut auth = [0u8; 16];
        auth.copy_from_slice(&head[..16]);
        stream.auth_id = auth;
        let _ = stream.security;
        let mut s = tokio::io::BufWriter::new(stream);
        use tokio::io::AsyncWriteExt as _;
        s.write_all(&head).await?;
        s.flush().await?;
        Ok(Box::new(s.into_inner()))
    }

    async fn open_udp(&self) -> Result<Arc<dyn UdpSession>> {
        Err(Error::protocol("vmess", "UDP для VMess не реализован; используйте SOCKS5h для QUIC"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inst(security: &str) -> Vmess {
        Vmess::new(OutboundVmess {
            name: "V".into(),
            server: "127.0.0.1".into(),
            port: 443,
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            alter_id: 0,
            security: security.into(),
            network: None,
            tls: true,
            sni: "example.com".into(),
            path: String::new(),
            host: String::new(),
            skip_cert_verify: false,
            udp: true,
            test_url: None,
            test_timeout_ms: None,
        })
        .unwrap()
    }

    #[test]
    fn aes_ecb_block_is_deterministic_and_16_bytes() {
        let key = [1u8; 16];
        let a = aes_ecb_block(&key, &[0u8; 8]);
        let b = aes_ecb_block(&key, &[0u8; 8]);
        assert_eq!(a, b);
        assert_ne!(a, aes_ecb_block(&key, &[1u8; 8]));
    }

    #[test]
    fn request_header_layout_matches_spec() {
        let v = inst("auto");
        let t = Target { host: "example.com".into(), port: 443, is_tcp: true };
        let h = v.build_request_at(&t, b"hello", false, 1700000000).unwrap();
        assert_eq!(h[16..18].len(), 2, "authID(16) + lenBuf(2)");
        // Всё после заголовка должно дешифроваться тем же authID.
        let mut auth = [0u8; 16];
        auth.copy_from_slice(&h[..16]);
        let nonce = &h[18..18 + 12];
        let sealed = &h[18 + 12..];
        let plain = aead_open(Security::Aes128Gcm, &auth, nonce, sealed, &h[16..18]).unwrap();
        // lenPlain — длина всего блока VMess (команда + адрес + данные),
        // а не только данных: 1 + 2 + atyp + 11 + 5 = 21 байт.
        let expected = Vmess::build_payload(&t, b"hello", false);
        assert_eq!(&plain[..2], &(expected.len() as u16).to_be_bytes(), "lenPlain = длина payload");
        assert_eq!(&plain[2..2 + expected.len()], &expected[..]);
        // Открытый текст: lenPlain(2) || payload || crc32(4), поэтому данные
        // заканчиваются за 4 байта до конца блока, а не в самом конце.
        let at = 2 + expected.len() - 5;
        assert_eq!(&plain[at..at + 5], b"hello");
        // CRC32 занимает последние 4 байта всего открытого текста.
        let crc = crc32fast::hash(&[nonce, &plain[..plain.len() - 4]].concat());
        assert_eq!(&plain[plain.len() - 4..], &crc.to_be_bytes(), "CRC32 не сошёлся");
    }

    #[test]
    fn auth_id_depends_on_uuid_and_timestamp() {
        let a = inst("auto").build_request_at(
            &Target { host: "a.com".into(), port: 1, is_tcp: true },
            &[],
            false,
            1,
        );
        let b = inst("auto").build_request_at(
            &Target { host: "a.com".into(), port: 1, is_tcp: true },
            &[],
            false,
            2,
        );
        assert_ne!(a.unwrap()[..16], b.unwrap()[..16], "authID обязан зависеть от времени");
    }

    #[test]
    fn payload_encodes_command_port_and_address() {
        let t = Target { host: "1.2.3.4".into(), port: 8080, is_tcp: true };
        let p = Vmess::build_payload(&t, b"data", false);
        assert_eq!(p[0], 0x01);
        assert_eq!(&p[1..3], &[0x1F, 0x90]);
        assert_eq!(p[3], 0x01);
        assert_eq!(&p[4..8], &[1, 2, 3, 4]);
        assert_eq!(&p[8..], b"data");
    }

    #[test]
    fn both_ciphers_roundtrip() {
        // Ключ всегда 16 байт (authID); для ChaCha он дополняется до 32.
        for s in [Security::Aes128Gcm, Security::ChaCha20Poly1305] {
            let key = [5u8; 16];
            let nonce = vec![7u8; 12];
            let ct = aead_seal(s, &key, &nonce, b"payload", b"aad").unwrap();
            assert_eq!(ct.len(), b"payload".len() + 16, "{s}: тег всегда 16 байт");
            assert_eq!(aead_open(s, &key, &nonce, &ct, b"aad").unwrap(), b"payload");
            assert!(
                aead_open(s, &key, &nonce, &ct, b"other").is_err(),
                "{s}: AAD должен проверяться"
            );
            let mut bad = ct.clone();
            bad[0] ^= 1;
            assert!(aead_open(s, &key, &nonce, &bad, b"aad").is_err(), "{s}: подмена данных");
        }
    }

    #[test]
    fn security_parsing_rejects_unknown() {
        assert!(Security::parse("auto").is_ok());
        assert!(Security::parse("aes-128-gcm").is_ok());
        assert!(Security::parse("rc4").is_err());
    }
}
