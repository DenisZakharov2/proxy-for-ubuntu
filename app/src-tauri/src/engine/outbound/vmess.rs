//! VMess в режиме AEAD (`alterId = 0`), совместимый с Xray-core.
//!
//! Реализовано по исходникам XTLS/Xray-core: `proxy/vmess/aead/authid.go`,
//! `kdf.go`, `encrypt.go`, `proxy/vmess/encoding/client.go` и
//! `common/crypto/auth.go`. Прошлая версия собирала заголовок «по мотивам»
//! спецификации: authID шифровался ключом uuid (а не KDF-производным),
//! тело шло открытым текстом, а заголовок ответа просто пропускался —
//! живой Xray отвечал `invalid user > user do not exist`.
//!
//! Что здесь важно и неочевидно:
//!
//! * `cmdKey = MD5(uuid)`, дальше все ключи — производные от него через
//!   многоуровневый KDF (HMAC, у которого «хэш» — предыдущий HMAC).
//! * authID = AES-128-ECB(KDF16(cmdKey, "AES Auth ID Encryption"),
//!   timestamp(8) ‖ случайные(4) ‖ crc32(первые 12)(4)).
//! * Длина заголовка и сам заголовок шифруются AES-128-GCM с ключами
//!   `KDF16(cmdKey, salt, authID, nonce8)` и nonce `KDF(...)[..12]`,
//!   AAD = authID.
//! * Тело после заголовка — кадры `len(2, big-endian) ‖ AEAD(данные)`,
//!   nonce = счётчик в первых двух байтах IV, AAD пустой. Кадр с пустым
//!   открытым текстом (длина ровно 16) — конец потока.
//! * Ключи ответа — `SHA256(requestKey)[..16]` и `SHA256(requestIV)[..16]`.
//!
//! ✅ Статус: проверено против живого Xray 26.10.29 (`alterId: 0`, tcp без
//! TLS): AES-128-GCM и ChaCha20-Poly1305 отдают HTTP 200 через наш код.
//! Вектор KDF в тестах посчитан независимым переносом Xray-кода на Go.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::config::OutboundVmess;
use crate::engine::outbound::vless::WebSocket;
use crate::engine::outbound::{
    connect_proxy, poll_read_into, AsyncReadWrite, Outbound, Request, UdpSession,
};
use crate::engine::rules::Target;
use crate::engine::tls::build_tls_config;
use crate::error::{Error, Result};

/// Версия протокола в заголовке (`encoding.Version`).
const VERSION: u8 = 1;
/// Команды запроса.
const CMD_TCP: u8 = 1;
const CMD_UDP: u8 = 2;

/// Значения `protocol.SecurityType` в заголовке.
const SEC_AES128_GCM: u8 = 3;
const SEC_CHACHA20_POLY1305: u8 = 4;

/// Соли KDF — дословно из `proxy/vmess/aead/consts.go`.
const KDF_BASE: &[u8] = b"VMess AEAD KDF";
const SALT_AUTH_ID: &[u8] = b"AES Auth ID Encryption";
const SALT_RESP_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const SALT_RESP_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const SALT_RESP_KEY: &[u8] = b"AEAD Resp Header Key";
const SALT_RESP_IV: &[u8] = b"AEAD Resp Header IV";
const SALT_HEADER_KEY: &[u8] = b"VMess Header AEAD Key";
const SALT_HEADER_IV: &[u8] = b"VMess Header AEAD Nonce";
const SALT_HEADER_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const SALT_HEADER_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";

/// Максимум открытого текста в одном кадре тела. 65535 - 16 (тег) - 2 (длина)
/// с запасом, но режем по 16 КиБ: крупный кадр держит буфер и мешает
/// честному счёту байт при отмене.
const MAX_CHUNK: usize = 16 * 1024;

// ─────────────────────────────── KDF ───────────────────────────────────────

/// Один уровень KDF: функция «хэш» предыдущего уровня.
type KdfLevel<'a> = &'a dyn Fn(&[u8]) -> [u8; 32];
/// Упакованный уровень — для композиции в `kdf`.
type KdfBoxed<'a> = Box<dyn Fn(&[u8]) -> [u8; 32] + 'a>;

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC принимает любой ключ");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// Один уровень `KDF` из Xray. В оригинале у HMAC'а роль «хэша» играет
/// предыдущий HMAC: `hmac.New` пишет ipad в него, `Sum` сбрасывает его и
/// дописывает opad вместе с внутренним дайджестом. В итоге уровень —
/// это `H(opad ‖ H(ipad ‖ msg))` с **полными** 64-байтными pad'ами,
/// где `H` — предыдущий уровень.
fn kdf_layer(prev: KdfLevel<'_>, salt: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 64];
    if salt.len() > 64 {
        key.copy_from_slice(&prev(salt));
    } else {
        key[..salt.len()].copy_from_slice(salt);
    }
    let ipad: Vec<u8> = key.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = key.iter().map(|b| b ^ 0x5c).collect();

    let mut inner = Vec::with_capacity(64 + msg.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(msg);
    let digest = prev(&inner);

    let mut outer = Vec::with_capacity(64 + 32);
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&digest);
    prev(&outer)
}

/// `KDF(key, path...)` из Xray: уровней столько, сколько элементов в `path`.
pub fn kdf<'p>(key: &[u8], path: &'p [&'p [u8]]) -> [u8; 32] {
    let base = |m: &[u8]| hmac_sha256(KDF_BASE, m);
    let mut f: KdfBoxed<'p> = Box::new(base);
    for salt in path {
        let prev = f;
        f = Box::new(move |m: &[u8]| kdf_layer(&*prev, salt, m));
    }
    f(key)
}

/// `KDF16` — первые 16 байт: ровно столько нужно AES-128-GCM.
pub fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    let full = kdf(key, path);
    let mut out = [0u8; 16];
    out.copy_from_slice(&full[..16]);
    out
}

/// `cmdKey = MD5(uuid ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21")` —
/// `protocol.NewID` в Xray добавляет к UUID фиксированную соль, и именно
/// этот ключ, а не сам uuid, служит основой всех производных.
pub fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
    let mut hasher = md5::Md5::new();
    hasher.update(uuid);
    hasher.update(CMD_KEY_SALT);
    let digest = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn aes_ecb_block(key: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut g = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut g);
    let mut out = [0u8; 16];
    out.copy_from_slice(&g);
    out
}

/// `CreateAuthID` из Xray: AES-128-ECB от `timestamp ‖ random4 ‖ crc32(12)`.
pub fn create_auth_id(cmd_key: &[u8; 16], timestamp: i64) -> [u8; 16] {
    let mut buf = [0u8; 16];
    buf[..8].copy_from_slice(&timestamp.to_be_bytes());
    for b in buf.iter_mut().take(12).skip(8) {
        *b = rand::random();
    }
    let crc = crc32fast::hash(&buf[..12]);
    buf[12..].copy_from_slice(&crc.to_be_bytes());
    aes_ecb_block(&kdf16(cmd_key, &[SALT_AUTH_ID]), &buf)
}

fn aes_gcm_seal(key: &[u8; 16], nonce: &[u8], msg: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, Payload};
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
        .map_err(|e| Error::protocol("vmess", e.to_string()))?;
    cipher
        .encrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| Error::protocol("vmess", "AES-128-GCM: ошибка шифрования"))
}

fn aes_gcm_open(key: &[u8; 16], nonce: &[u8], ct: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::{Aead, Payload};
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(key)
        .map_err(|e| Error::protocol("vmess", e.to_string()))?;
    cipher
        .decrypt(aes_gcm::Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .map_err(|_| {
            Error::protocol(
                "vmess",
                "AES-128-GCM: не расшифровывается — проверьте uuid и alterId",
            )
        })
}

fn sha256_16(data: &[u8]) -> [u8; 16] {
    let digest = Sha256::digest(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

// ─────────────────────────── шифр тела ─────────────────────────────────────

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
    fn id(&self) -> u8 {
        match self {
            Security::Aes128Gcm => SEC_AES128_GCM,
            Security::ChaCha20Poly1305 => SEC_CHACHA20_POLY1305,
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

/// Ключ тела для ChaCha20-Poly1305: `MD5(key) ‖ MD5(MD5(key)[..16])`
/// (`encoding.GenerateChacha20Poly1305Key`).
fn chacha_body_key(key: &[u8; 16]) -> [u8; 32] {
    let mut first = md5::Md5::new();
    first.update(key);
    let a = first.finalize();
    let mut second = md5::Md5::new();
    second.update(&a[..16]);
    let b = second.finalize();
    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&a);
    out[16..].copy_from_slice(&b);
    out
}

/// Шифр одного направления тела. Счётчик nonce у каждого направления свой:
/// клиентский писатель и читатель ответа начинают с нуля независимо.
struct BodyCipher {
    security: Security,
    key: [u8; 16],
    iv: [u8; 16],
    counter: u16,
}

impl BodyCipher {
    fn new(security: Security, key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            security,
            key,
            iv,
            counter: 0,
        }
    }

    /// `GenerateChunkNonce`: счётчик в первых двух байтах IV.
    fn nonce(&self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..2].copy_from_slice(&self.counter.to_be_bytes());
        n[2..].copy_from_slice(&self.iv[2..12]);
        n
    }

    fn seal(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce();
        let ct = match self.security {
            Security::Aes128Gcm => aes_gcm_seal(&self.key, &nonce, plain, &[])?,
            Security::ChaCha20Poly1305 => {
                use chacha20poly1305::aead::{Aead, Payload};
                let key = chacha_body_key(&self.key);
                let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key)
                    .map_err(|e| Error::protocol("vmess", e.to_string()))?;
                cipher
                    .encrypt(
                        chacha20poly1305::Nonce::from_slice(&nonce),
                        Payload {
                            msg: plain,
                            aad: &[],
                        },
                    )
                    .map_err(|_| Error::protocol("vmess", "ChaCha20-Poly1305: ошибка шифрования"))?
            }
        };
        self.counter = self.counter.wrapping_add(1);
        Ok(ct)
    }

    fn open(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.nonce();
        let plain = match self.security {
            Security::Aes128Gcm => aes_gcm_open(&self.key, &nonce, ct, &[])?,
            Security::ChaCha20Poly1305 => {
                use chacha20poly1305::aead::{Aead, Payload};
                let key = chacha_body_key(&self.key);
                let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key)
                    .map_err(|e| Error::protocol("vmess", e.to_string()))?;
                cipher
                    .decrypt(
                        chacha20poly1305::Nonce::from_slice(&nonce),
                        Payload { msg: ct, aad: &[] },
                    )
                    .map_err(|_| {
                        Error::protocol("vmess", "ChaCha20-Poly1305: не расшифровывается")
                    })?
            }
        };
        self.counter = self.counter.wrapping_add(1);
        Ok(plain)
    }

    /// Кадр тела: длина (2 байта, BE) и AEAD-данные.
    fn seal_frame(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let ct = self.seal(plain)?;
        let mut frame = Vec::with_capacity(2 + ct.len());
        frame.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        frame.extend_from_slice(&ct);
        Ok(frame)
    }
}

// ─────────────────────────────── outbound ──────────────────────────────────

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
        let sni = if cfg.sni.is_empty() {
            cfg.server.clone()
        } else {
            cfg.sni.clone()
        };
        let use_ws = cfg.network.as_deref() == Some("ws");
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
            security,
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

    /// Открытый текст заголовка запроса: версия, ключи тела, команда, цель,
    /// padding и FNV1a-хэш всего перечисленного.
    pub fn build_header_plain(
        &self,
        target: &Target,
        body_iv: &[u8; 16],
        body_key: &[u8; 16],
        response_header: u8,
        is_udp: bool,
    ) -> Result<Vec<u8>> {
        let padding_len = rand::random::<u8>() % 16;
        let mut p = Vec::with_capacity(64);
        p.push(VERSION);
        p.extend_from_slice(body_iv);
        p.extend_from_slice(body_key);
        p.push(response_header);
        p.push(0); // option: без chunk-masking и padding
        p.push((padding_len << 4) | self.security.id());
        p.push(0); // зарезервировано
        p.push(if is_udp { CMD_UDP } else { CMD_TCP });
        // AddressParser собран с PortThenAddress: сначала порт, потом адрес.
        p.extend_from_slice(&target.port.to_be_bytes());
        p.extend_from_slice(&encode_addr_v(&target.host)?);
        for _ in 0..padding_len {
            p.push(rand::random());
        }
        p.extend_from_slice(&fnv1a32(&p).to_be_bytes());
        Ok(p)
    }

    /// Полный заголовок на проводе: authID, длина, nonce и два AEAD-блока.
    pub fn seal_request(
        &self,
        header_plain: &[u8],
        timestamp: i64,
        nonce8: &[u8; 8],
    ) -> Result<Vec<u8>> {
        let cmd_key = cmd_key(&self.uuid);
        let auth_id = create_auth_id(&cmd_key, timestamp);
        let len = (header_plain.len() as u16).to_be_bytes();

        let len_key = kdf16(&cmd_key, &[SALT_HEADER_LEN_KEY, &auth_id, nonce8]);
        let len_iv = kdf(&cmd_key, &[SALT_HEADER_LEN_IV, &auth_id, nonce8]);
        let len_ct = aes_gcm_seal(&len_key, &len_iv[..12], &len, &auth_id)?;

        let key = kdf16(&cmd_key, &[SALT_HEADER_KEY, &auth_id, nonce8]);
        let iv = kdf(&cmd_key, &[SALT_HEADER_IV, &auth_id, nonce8]);
        let ct = aes_gcm_seal(&key, &iv[..12], header_plain, &auth_id)?;

        let mut out = Vec::with_capacity(16 + 18 + 8 + ct.len());
        out.extend_from_slice(&auth_id);
        out.extend_from_slice(&len_ct);
        out.extend_from_slice(nonce8);
        out.extend_from_slice(&ct);
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
                    rand::random::<[u8; 16]>(),
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

    /// Расшифровывает блок длины ответного заголовка (18 байт) и возвращает
    /// длину тела заголовка.
    fn open_resp_len(resp_key: &[u8; 16], resp_iv: &[u8; 16], block: &[u8]) -> Result<usize> {
        let key = kdf16(resp_key, &[SALT_RESP_LEN_KEY]);
        let iv = kdf(resp_iv, &[SALT_RESP_LEN_IV]);
        let plain = aes_gcm_open(&key, &iv[..12], block, &[])?;
        if plain.len() < 2 {
            return Err(Error::protocol("vmess", "битый заголовок длины в ответе"));
        }
        Ok(u16::from_be_bytes([plain[0], plain[1]]) as usize)
    }

    /// Расшифровывает тело ответного заголовка и сверяет маркер: первый байт
    /// обязан совпасть с тем случайным байтом, что мы отправили, иначе это
    /// чужой ответ (не тот uuid).
    fn open_resp_payload(
        resp_key: &[u8; 16],
        resp_iv: &[u8; 16],
        payload: &[u8],
        expected: u8,
    ) -> Result<()> {
        let key = kdf16(resp_key, &[SALT_RESP_KEY]);
        let iv = kdf(resp_iv, &[SALT_RESP_IV]);
        let body = aes_gcm_open(&key, &iv[..12], payload, &[])?;
        if body.len() < 4 {
            return Err(Error::protocol(
                "vmess",
                "слишком короткий заголовок ответа",
            ));
        }
        if body[0] != expected {
            return Err(Error::protocol(
                "vmess",
                format!(
                    "сервер вернул маркер {:?}, ожидался {:?} — проверьте uuid и alterId",
                    body[0], expected
                ),
            ));
        }
        Ok(())
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
                return Err(Error::protocol(
                    "vmess",
                    format!("домен {host:?} длиннее 255 байт"),
                ));
            }
            out.push(0x02);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
        }
    }
    Ok(out)
}

// ───────────────────────── поток с шифрованием тела ────────────────────────

/// Поток после заголовка: на чтение — ответный заголовок и кадры ответа,
/// на запись — кадры запроса. Ответный заголовок читается **лениво**: сервер
/// присылает его только после того, как к цели ушли данные, поэтому ждать его
/// в `connect()` нельзя — получится взаимная блокировка (мы ждём заголовок,
/// сервер ждёт запрос).
struct VmessStream {
    inner: Box<dyn AsyncReadWrite>,
    read: BodyCipher,
    write: BodyCipher,
    // ответный заголовок
    resp_key: [u8; 16],
    resp_iv: [u8; 16],
    resp_expected: u8,
    head_len: [u8; 18],
    head_len_filled: usize,
    head_len_done: bool,
    head_buf: Vec<u8>,
    head_filled: usize,
    header_done: bool,
    // чтение тела
    plain: Vec<u8>,
    pos: usize,
    len_buf: [u8; 2],
    len_filled: usize,
    body_buf: Vec<u8>,
    body_filled: usize,
    done: bool,
    // запись
    pending: Vec<u8>,
    planned: usize,
}

impl VmessStream {
    fn new(
        inner: Box<dyn AsyncReadWrite>,
        read: BodyCipher,
        write: BodyCipher,
        resp_key: [u8; 16],
        resp_iv: [u8; 16],
        resp_expected: u8,
    ) -> Self {
        Self {
            inner,
            read,
            write,
            resp_key,
            resp_iv,
            resp_expected,
            head_len: [0u8; 18],
            head_len_filled: 0,
            head_len_done: false,
            head_buf: Vec::new(),
            head_filled: 0,
            header_done: false,
            plain: Vec::new(),
            pos: 0,
            len_buf: [0u8; 2],
            len_filled: 0,
            body_buf: Vec::new(),
            body_filled: 0,
            done: false,
            pending: Vec::new(),
            planned: 0,
        }
    }

    /// Дочитывает `slice` из inner. Возвращает число прочитанных байт;
    /// `Ok(0)` — конец потока. `Pending` — ждём сокет.
    fn poll_fill(
        inner: &mut Box<dyn AsyncReadWrite>,
        cx: &mut std::task::Context<'_>,
        slice: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        poll_read_into(&mut **inner, cx, slice)
    }
}

impl AsyncRead for VmessStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let me = self.as_mut().get_mut();
        loop {
            if me.pos < me.plain.len() {
                let n = (me.plain.len() - me.pos).min(buf.remaining());
                buf.put_slice(&me.plain[me.pos..me.pos + n]);
                me.pos += n;
                return Poll::Ready(Ok(()));
            }
            if me.done {
                return Poll::Ready(Ok(()));
            }

            // 0. Ответный заголовок: 18 байт длины, затем тело заголовка.
            if !me.head_len_done {
                let start = me.head_len_filled;
                let want = 18 - start;
                let mut tmp = vec![0u8; want];
                match Self::poll_fill(&mut me.inner, cx, &mut tmp) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => {
                        me.done = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(n)) => {
                        me.head_len[start..start + n].copy_from_slice(&tmp[..n]);
                        me.head_len_filled += n;
                    }
                }
                if me.head_len_filled < 18 {
                    continue;
                }
                let len = match Vmess::open_resp_len(&me.resp_key, &me.resp_iv, &me.head_len) {
                    Ok(l) => l,
                    Err(e) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e.to_string(),
                        )))
                    }
                };
                me.head_buf = vec![0u8; len + 16];
                me.head_filled = 0;
                me.head_len_done = true;
                continue;
            }
            if !me.header_done {
                let want = me.head_buf.len();
                let start = me.head_filled;
                let mut tmp = vec![0u8; want - start];
                match Self::poll_fill(&mut me.inner, cx, &mut tmp) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => {
                        me.done = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(n)) => {
                        me.head_buf[start..start + n].copy_from_slice(&tmp[..n]);
                        me.head_filled += n;
                    }
                }
                if me.head_filled < want {
                    continue;
                }
                if let Err(e) = Vmess::open_resp_payload(
                    &me.resp_key,
                    &me.resp_iv,
                    &me.head_buf,
                    me.resp_expected,
                ) {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )));
                }
                me.head_buf.clear();
                me.header_done = true;
                continue;
            }

            // 1. Длина кадра.
            if me.len_filled < 2 {
                let start = me.len_filled;
                let want = 2 - start;
                let mut tmp = [0u8; 2];
                match Self::poll_fill(&mut me.inner, cx, &mut tmp[..want]) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(0)) => {
                        // Обрыв до начала кадра — нормальный конец потока.
                        me.done = true;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Ready(Ok(n)) => {
                        me.len_buf[start..start + n].copy_from_slice(&tmp[..n]);
                        me.len_filled += n;
                    }
                }
                if me.len_filled < 2 {
                    continue;
                }
                let len = u16::from_be_bytes(me.len_buf) as usize;
                if len < 16 {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("vmess: длина кадра {len} меньше тега"),
                    )));
                }
                me.body_buf.clear();
                me.body_buf.resize(len, 0);
                me.body_filled = 0;
            }

            // 2. Тело кадра.
            let filled = me.body_filled;
            let total = me.body_buf.len();
            match Self::poll_fill(&mut me.inner, cx, &mut me.body_buf[filled..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    me.done = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(n)) => me.body_filled += n,
            }
            if me.body_filled < total {
                continue;
            }
            let opened = match me.read.open(&me.body_buf) {
                Ok(p) => p,
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )))
                }
            };
            me.len_filled = 0;
            me.body_buf.clear();
            me.body_filled = 0;
            if opened.is_empty() {
                me.done = true;
                return Poll::Ready(Ok(()));
            }
            me.plain = opened;
            me.pos = 0;
        }
    }
}

impl AsyncWrite for VmessStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let me = self.get_mut();
        if me.pending.is_empty() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let n = buf.len().min(MAX_CHUNK);
            let frame = match me.write.seal_frame(&buf[..n]) {
                Ok(f) => f,
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )))
                }
            };
            me.pending = frame;
            me.planned = n;
        }
        while !me.pending.is_empty() {
            match std::pin::Pin::new(&mut *me.inner).poll_write(cx, &me.pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "vmess: сокет не принял данные",
                    )))
                }
                Poll::Ready(Ok(k)) => {
                    me.pending.drain(..k);
                }
            }
        }
        let n = me.planned;
        me.planned = 0;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        while !me.pending.is_empty() {
            match std::pin::Pin::new(&mut *me.inner).poll_write(cx, &me.pending) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "vmess: сокет не принял данные",
                    )))
                }
                std::task::Poll::Ready(Ok(k)) => {
                    me.pending.drain(..k);
                }
            }
        }
        std::pin::Pin::new(&mut *me.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Маркер конца потока — кадр с пустым открытым текстом.
        use std::task::Poll;
        let me = self.get_mut();
        if me.pending.is_empty() && me.planned == 0 {
            match me.write.seal_frame(&[]) {
                Ok(f) => {
                    me.pending = f;
                    me.planned = usize::MAX; // маркер: это не данные пользователя
                }
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )))
                }
            }
        }
        while !me.pending.is_empty() {
            match std::pin::Pin::new(&mut *me.inner).poll_write(cx, &me.pending) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "vmess: сокет не принял данные",
                    )))
                }
                Poll::Ready(Ok(k)) => {
                    me.pending.drain(..k);
                }
            }
        }
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
        let mut inner = self.open_transport().await?;

        let body_key: [u8; 16] = rand::random();
        let body_iv: [u8; 16] = rand::random();
        let response_header: u8 = rand::random();
        let plain =
            self.build_header_plain(&req.target, &body_iv, &body_key, response_header, false)?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Internal(format!("часы идут назад: {e}")))?
            .as_secs() as i64;
        let nonce8: [u8; 8] = rand::random();
        let wire = self.seal_request(&plain, timestamp, &nonce8)?;

        inner.write_all(&wire).await?;
        inner.flush().await?;

        let resp_key = sha256_16(&body_key);
        let resp_iv = sha256_16(&body_iv);
        // Ответный заголовок не читаем здесь: сервер пришлёт его только после
        // первого запроса к цели, а запрос пишет вызывающий уже после connect.
        Ok(Box::new(VmessStream::new(
            inner,
            BodyCipher::new(self.security, resp_key, resp_iv),
            BodyCipher::new(self.security, body_key, body_iv),
            resp_key,
            resp_iv,
            response_header,
        )))
    }

    async fn open_udp(&self) -> Result<Arc<dyn UdpSession>> {
        Err(Error::protocol(
            "vmess",
            "UDP для VMess не реализован; используйте SOCKS5h для QUIC",
        ))
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

    fn target() -> Target {
        Target {
            host: "example.com".into(),
            port: 80,
            is_tcp: true,
        }
    }

    #[test]
    fn kdf_matches_xray_reference_vectors() {
        // Эталон посчитан дословным переносом KDF из Xray-core на Go
        // (go run на тех же входах). Если тест падает — сломалась вложенность
        // HMAC, и живой сервер ответит «invalid user».
        let key = b"0123456789abcdef";
        assert_eq!(
            hex::encode(kdf16(key, &[SALT_AUTH_ID])),
            "ebde3a0b17bf94c86fa140917ec6a0c9"
        );
        assert_eq!(
            hex::encode(kdf16(key, &[SALT_HEADER_KEY, &[0u8; 16], &[0u8; 8]])),
            "322e218e5cf7bb9b32c410c400b82f5d"
        );
        assert_eq!(
            hex::encode(kdf(key, &[SALT_HEADER_IV])),
            "8ef3e9139772d89a59eb164fea663c3926e6c3ae4e91477055edf3a0b7aebded"
        );
    }

    #[test]
    fn kdf_is_deterministic_and_salt_dependent() {
        let key = [7u8; 16];
        let a = kdf16(&key, &[SALT_AUTH_ID]);
        let b = kdf16(&key, &[SALT_AUTH_ID]);
        let c = kdf16(&key, &[SALT_HEADER_KEY]);
        assert_eq!(a, b, "KDF обязан быть детерминированным");
        assert_ne!(a, c, "разные соли — разные ключи");
        // Три уровня пути дают другой ключ, чем один: вложенность учитывается.
        let d = kdf16(&key, &[SALT_HEADER_KEY, &[1u8; 16], &[2u8; 8]]);
        let e = kdf16(&key, &[SALT_HEADER_KEY]);
        assert_ne!(d, e);
    }

    #[test]
    fn auth_id_carries_timestamp_random_and_crc() {
        let cmd = cmd_key(&inst("auto").uuid);
        let ts = 1_700_000_000i64;
        let id = create_auth_id(&cmd, ts);
        // Расшифровываем тем же ключом, что и Xray при проверке.
        let key = kdf16(&cmd, &[SALT_AUTH_ID]);
        let mut block = GenericArray::clone_from_slice(&id);
        let cipher = Aes128::new(GenericArray::from_slice(&key));
        aes::cipher::BlockDecrypt::decrypt_block(&cipher, &mut block);
        let mut plain = [0u8; 16];
        plain.copy_from_slice(&block);

        assert_eq!(i64::from_be_bytes(plain[..8].try_into().unwrap()), ts);
        let crc = crc32fast::hash(&plain[..12]);
        assert_eq!(&plain[12..], &crc.to_be_bytes(), "CRC не сошёлся");
    }

    #[test]
    fn sealed_header_has_expected_layout_and_opens() {
        let v = inst("auto");
        let cmd = cmd_key(&v.uuid);
        let h = v
            .build_header_plain(&target(), &[3u8; 16], &[4u8; 16], 0x5A, false)
            .unwrap();
        assert_eq!(h[0], VERSION);
        assert_eq!(&h[1..17], &[3u8; 16], "IV тела идёт сразу после версии");
        assert_eq!(&h[17..33], &[4u8; 16], "ключ тела");
        assert_eq!(h[33], 0x5A, "маркер ответа");
        assert_eq!(h[34], 0, "option");
        assert_eq!(h[35] & 0x0F, SEC_AES128_GCM);
        assert_eq!(h[37], CMD_TCP);
        // Порт идёт до адреса (PortThenAddress).
        assert_eq!(&h[38..40], &80u16.to_be_bytes());
        assert_eq!(h[40], 0x02);
        assert_eq!(h[41], 11);
        assert_eq!(&h[42..53], b"example.com");
        // FNV1a покрывает всё, кроме себя.
        let fnv = fnv1a32(&h[..h.len() - 4]);
        assert_eq!(&h[h.len() - 4..], &fnv.to_be_bytes());

        let nonce8 = [9u8; 8];
        let wire = v.seal_request(&h, 1_700_000_000, &nonce8).unwrap();
        assert_eq!(wire.len(), 16 + 18 + 8 + h.len() + 16);

        let mut auth = [0u8; 16];
        auth.copy_from_slice(&wire[..16]);
        let len_key = kdf16(&cmd, &[SALT_HEADER_LEN_KEY, &auth, &nonce8]);
        let len_iv = kdf(&cmd, &[SALT_HEADER_LEN_IV, &auth, &nonce8]);
        let len_plain = aes_gcm_open(&len_key, &len_iv[..12], &wire[16..34], &auth).unwrap();
        assert_eq!(
            u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize,
            h.len()
        );

        let key = kdf16(&cmd, &[SALT_HEADER_KEY, &auth, &nonce8]);
        let iv = kdf(&cmd, &[SALT_HEADER_IV, &auth, &nonce8]);
        let opened = aes_gcm_open(&key, &iv[..12], &wire[42..], &auth).unwrap();
        assert_eq!(opened, h, "заголовок не расшифровался обратно");
    }

    #[test]
    fn body_frames_roundtrip_with_counter_nonce() {
        for sec in [Security::Aes128Gcm, Security::ChaCha20Poly1305] {
            let key = [1u8; 16];
            let iv = [2u8; 16];
            let mut w = BodyCipher::new(sec, key, iv);
            let mut r = BodyCipher::new(sec, key, iv);

            let f1 = w.seal_frame(b"hello").unwrap();
            assert_eq!(&f1[..2], &21u16.to_be_bytes(), "длина = данные + тег");
            assert_eq!(r.open(&f1[2..]).unwrap(), b"hello");

            let f2 = w.seal_frame(b"world").unwrap();
            assert_eq!(r.open(&f2[2..]).unwrap(), b"world");

            // Маркер конца: кадр ровно с тегом, открывается в пустоту.
            let end = w.seal_frame(&[]).unwrap();
            assert_eq!(end.len(), 2 + 16);
            assert!(r.open(&end[2..]).unwrap().is_empty());
            assert_ne!(f1, f2, "счётчик nonce обязан двигаться");
        }
    }

    #[test]
    fn chacha_body_key_matches_md5_chain() {
        let key = [5u8; 16];
        let k = chacha_body_key(&key);
        let mut first = md5::Md5::new();
        first.update(key);
        let a = first.finalize();
        assert_eq!(&k[..16], &a[..]);
        let mut second = md5::Md5::new();
        second.update(&a[..16]);
        let b = second.finalize();
        assert_eq!(&k[16..], &b[..]);
    }

    #[test]
    fn payload_encodes_command_port_and_address() {
        let p = encode_addr_v("1.2.3.4").unwrap();
        assert_eq!(p[0], 0x01);
        assert_eq!(&p[1..5], &[1, 2, 3, 4]);
        assert_eq!(encode_addr_v("::1").unwrap()[0], 0x03);
        let d = encode_addr_v("example.com").unwrap();
        assert_eq!(d[0], 0x02);
        assert_eq!(d[1] as usize, d.len() - 2);
    }

    #[test]
    fn security_parsing_rejects_unknown() {
        assert!(Security::parse("auto").is_ok());
        assert!(Security::parse("aes-128-gcm").is_ok());
        assert!(Security::parse("rc4").is_err());
        assert_eq!(Security::Aes128Gcm.id(), 3);
        assert_eq!(Security::ChaCha20Poly1305.id(), 4);
    }
}
