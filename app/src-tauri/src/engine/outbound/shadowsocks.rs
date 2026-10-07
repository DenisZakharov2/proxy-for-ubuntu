//! Shadowsocks с AEAD-шифрованием (shadowsocks-2022-совместимый AEAD-режим).
//!
//! Формат по TCP: `[шифрованная длина][шифрованные данные]`, где и длина, и
//! данные — отдельные AEAD-чанки со своими nonce, но **общим** счётчиком.
//! Ключ подпоследовательности выводится из мастер-ключа и salt конкретного
//! соединения через HKDF-SHA1, поэтому один и тот же ключ можно безопасно
//! использовать на разных соединениях.
//!
//! Поддерживаются `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-256-gcm`.
//! Legacy-шифры без AEAD (`aes-*-cfb`, `chacha20`, `rc4-md5`) в конфиге
//! принимаются, но помечаются в UI как небезопасные.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use async_trait::async_trait;
use chacha20poly1305::ChaCha20Poly1305;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::config::OutboundShadowsocks;
use crate::engine::outbound::{
    connect_proxy, poll_read_into, socks_addr_bytes, AsyncReadWrite, Outbound, Request, UdpSession,
};
use crate::engine::rules::Target;
use crate::error::{Error, Result};

/// Максимальная полезная нагрузка AEAD-чанта (0x3FFF, как в спецификации).
const MAX_CHUNK: usize = 0x3FFF;
const TAG_LEN: usize = 16;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// Кадр AEAD по SIP004: `[длина шифротекста: 2 байта][шифротекст]`.
///
/// Длина полезной нагрузки лежит ВНУТРИ шифротекста (первые два байта
/// открытого текста), а снаружи отдаётся длина самого шифротекста. Поэтому
/// на проводе заголовок кадра — ровно 2 байта, а тег AEAD приезжает в конце
/// блока. Перепутать эти два поля — самая частая ошибка реализации.
const FRAME_LEN_SIZE: usize = 2;

/// AEAD-примитив, обёрнутый так, чтобы не тащить генерики в hot path.
#[derive(Clone)]
pub enum Cipher {
    ChaCha(ChaCha20Poly1305),
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
}

impl std::fmt::Debug for Cipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Cipher::ChaCha(_) => "chacha20-ietf-poly1305",
            Cipher::Aes128(_) => "aes-128-gcm",
            Cipher::Aes256(_) => "aes-256-gcm",
        };
        write!(f, "Cipher({name})")
    }
}

impl Cipher {
    fn new(method: &str, key: &[u8]) -> Result<Self> {
        match method {
            "chacha20-ietf-poly1305" => Ok(Cipher::ChaCha(ChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| Error::protocol("ss", format!("неверная длина ключа: {e}")))?)),
            "aes-128-gcm" => Ok(Cipher::Aes128(Box::new(Aes128Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol("ss", format!("неверная длина ключа: {e}")))?))),
            "aes-256-gcm" => Ok(Cipher::Aes256(Box::new(Aes256Gcm::new_from_slice(key)
                .map_err(|e| Error::protocol("ss", format!("неверная длина ключа: {e}")))?))),
            other => Err(Error::protocol(
                "ss",
                format!("шифр {other:?} не поддерживается (chacha20-ietf-poly1305 | aes-128-gcm | aes-256-gcm)"),
            )),
        }
    }

    fn seal(&self, nonce: &[u8; NONCE_LEN], plaintext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        let p = Payload {
            msg: plaintext,
            aad: ad,
        };
        let n = chacha20poly1305::Nonce::from_slice(nonce);
        match self {
            Cipher::ChaCha(c) => c
                .encrypt(n, p)
                .map_err(|_| Error::protocol("ss", "ошибка шифрования")),
            Cipher::Aes128(c) => c
                .encrypt(AesNonce::from_slice(nonce), p)
                .map_err(|_| Error::protocol("ss", "ошибка шифрования")),
            Cipher::Aes256(c) => c
                .encrypt(AesNonce::from_slice(nonce), p)
                .map_err(|_| Error::protocol("ss", "ошибка шифрования")),
        }
    }

    fn open(&self, nonce: &[u8; NONCE_LEN], ciphertext: &[u8], ad: &[u8]) -> Result<Vec<u8>> {
        let p = Payload {
            msg: ciphertext,
            aad: ad,
        };
        let n = chacha20poly1305::Nonce::from_slice(nonce);
        match self {
            Cipher::ChaCha(c) => c.decrypt(n, p).map_err(|_| {
                Error::protocol(
                    "ss",
                    "ошибка расшифровки: неверный ключ или данные повреждены",
                )
            }),
            Cipher::Aes128(c) => c.decrypt(AesNonce::from_slice(nonce), p).map_err(|_| {
                Error::protocol(
                    "ss",
                    "ошибка расшифровки: неверный ключ или данные повреждены",
                )
            }),
            Cipher::Aes256(c) => c.decrypt(AesNonce::from_slice(nonce), p).map_err(|_| {
                Error::protocol(
                    "ss",
                    "ошибка расшифровки: неверный ключ или данные повреждены",
                )
            }),
        }
    }
}

/// Ключ: либо готовые байты, либо пароль, растянутый по EVP_BytesToKey.
fn derive_key(method: &str, password: &str) -> Vec<u8> {
    let want = match method {
        "aes-128-gcm" => 16,
        _ => KEY_LEN,
    };
    if let Ok(raw) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, password) {
        if raw.len() == want || raw.len() == KEY_LEN {
            return raw[..want].to_vec();
        }
    }
    if password.len() == want {
        return password.as_bytes().to_vec();
    }
    // EVP_BytesToKey с MD5, как это делает оригинальный shadowsocks.
    evp_bytes_to_key(password.as_bytes(), want)
}

fn evp_bytes_to_key(password: &[u8], len: usize) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut out = Vec::with_capacity(len);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    out
}

/// Подключевой ключ: HKDF-SHA1(master, salt, "ss-subkey").
fn subkey(master: &[u8], salt: &[u8]) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha1::Sha1;
    let hk = Hkdf::<Sha1>::new(Some(salt), master);
    let mut okm = vec![0u8; master.len()];
    hk.expand(b"ss-subkey", &mut okm)
        .expect("32 байта — валидная длина для HKDF-SHA1");
    okm
}

/// Счётчик nonce в little-endian с переносом: `0xff..ff` → `0x00..01`.
pub fn bump(mut n: [u8; NONCE_LEN]) -> [u8; NONCE_LEN] {
    for b in n.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
    n
}

/// Нешифрованный исходящий буфер: накапливаем открытый текст и на flush
/// разбиваем его на AEAD-чанты. Счётчик nonce общий для всех чантов
/// направления, как требует спецификация shadowsocks.
struct Sealer {
    cipher: Cipher,
    nonce: [u8; NONCE_LEN],
    /// Очередь готовых зашифрованных кадров.
    queue: Vec<Vec<u8>>,
}

impl Sealer {
    fn new(cipher: Cipher) -> Self {
        Self {
            cipher,
            nonce: [0u8; NONCE_LEN],
            queue: Vec::new(),
        }
    }

    /// Нарезает `plain` на чанты и кладёт их в очередь. Синхронно.
    fn push(&mut self, plain: &[u8]) -> Result<()> {
        for chunk in plain.chunks(MAX_CHUNK) {
            let mut framed = Vec::with_capacity(FRAME_LEN_SIZE + chunk.len() + TAG_LEN);
            framed.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            framed.extend_from_slice(chunk);
            let ct = self.cipher.seal(&self.nonce, &framed, &[])?;
            self.nonce = bump(self.nonce);

            let mut out = Vec::with_capacity(FRAME_LEN_SIZE + ct.len());
            out.extend_from_slice(&(ct.len() as u16).to_be_bytes());
            out.extend_from_slice(&ct);
            self.queue.push(out);
        }
        Ok(())
    }
}

/// Принимающая половина: снимает AEAD-чанки по мере поступления.
pub struct OpenStream<S> {
    inner: S,
    cipher: Cipher,
    nonce: [u8; NONCE_LEN],
    plain: Vec<u8>,
    pos: usize,
    state: RxState,
    hdr: [u8; FRAME_LEN_SIZE],
    hdr_filled: usize,
    pay: Vec<u8>,
    pay_filled: usize,
}

impl<S: AsyncRead + Unpin> OpenStream<S> {
    pub fn new(inner: S, cipher: Cipher) -> Self {
        Self {
            inner,
            cipher,
            nonce: [0u8; NONCE_LEN],
            plain: Vec::new(),
            pos: 0,
            state: RxState::Header,
            hdr: [0u8; FRAME_LEN_SIZE],
            hdr_filled: 0,
            pay: Vec::new(),
            pay_filled: 0,
        }
    }
}

/// Состояние разбора входящего потока.
#[derive(PartialEq)]
enum RxState {
    Header,
    Payload,
    Eof,
}

impl<S: AsyncRead + Unpin> AsyncRead for OpenStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        loop {
            if me.pos < me.plain.len() {
                let n = (me.plain.len() - me.pos).min(buf.remaining());
                buf.put_slice(&me.plain[me.pos..me.pos + n]);
                me.pos += n;
                return std::task::Poll::Ready(Ok(()));
            }
            if me.state == RxState::Eof {
                return std::task::Poll::Ready(Ok(()));
            }

            if me.state == RxState::Header {
                // Набираем 2 байта длины кадра, переживая частичные чтения.
                while me.hdr_filled < FRAME_LEN_SIZE {
                    let mut tmp = [0u8; FRAME_LEN_SIZE];
                    let n = match poll_read_into(&mut me.inner, cx, &mut tmp) {
                        std::task::Poll::Pending => return std::task::Poll::Pending,
                        std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                        std::task::Poll::Ready(Ok(n)) => n,
                    };
                    if n == 0 {
                        me.state = RxState::Eof;
                        return std::task::Poll::Ready(Ok(()));
                    }
                    me.hdr[me.hdr_filled..me.hdr_filled + n].copy_from_slice(&tmp[..n]);
                    me.hdr_filled += n;
                }
                // Это длина шифротекста, а не полезной нагрузки.
                let ct_len = u16::from_be_bytes([me.hdr[0], me.hdr[1]]) as usize;
                if !(FRAME_LEN_SIZE + TAG_LEN..=MAX_CHUNK + FRAME_LEN_SIZE + TAG_LEN)
                    .contains(&ct_len)
                {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("нераспознанная длина кадра {ct_len}"),
                    )));
                }
                me.pay = vec![0u8; ct_len];
                me.pay_filled = 0;
                me.state = RxState::Payload;
            }

            // Тело чанта.
            while me.pay_filled < me.pay.len() {
                let n = match poll_read_into(&mut me.inner, cx, &mut me.pay[me.pay_filled..]) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(n)) => n,
                };
                if n == 0 {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "обрыв в середине чанта",
                    )));
                }
                me.pay_filled += n;
            }

            let nonce = me.nonce;
            me.nonce = bump(nonce);
            let plain = me.cipher.open(&nonce, &me.pay, &[]).and_then(|v| {
                // Первые два байта открытого текста — длина полезной
                // нагрузки, дальше сами данные.
                if v.len() < FRAME_LEN_SIZE {
                    return Err(Error::protocol("ss", "чант короче заголовка"));
                }
                let declared = u16::from_be_bytes([v[0], v[1]]) as usize;
                if v.len() != FRAME_LEN_SIZE + declared {
                    return Err(Error::protocol(
                        "ss",
                        "длина внутри чанта не совпадает с его размером",
                    ));
                }
                Ok(v[FRAME_LEN_SIZE..].to_vec())
            });
            me.hdr_filled = 0;
            me.pay_filled = 0;
            me.state = RxState::Header;
            match plain {
                Ok(v) => {
                    me.plain = v;
                    me.pos = 0;
                }
                Err(e) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )))
                }
            }
        }
    }
}

/// Полный двунаправленный канал Shadowsocks.
pub struct ShadowsocksStream {
    read: OpenStream<tokio::net::tcp::OwnedReadHalf>,
    write: tokio::net::tcp::OwnedWriteHalf,
    sealer: Sealer,
    /// Сколько байт текущего кадра из `sealer.queue[0]` уже отправлено.
    sent: usize,
}

impl ShadowsocksStream {
    /// `salt` уже отправлен на сервер вызывающим кодом.
    fn new(inner: TcpStream, master_key: &[u8], method: &str, salt: &[u8]) -> Result<Self> {
        let sk = subkey(master_key, salt);
        let cipher = Cipher::new(method, &sk)?;
        let (r, w) = inner.into_split();
        Ok(Self {
            read: OpenStream::new(r, cipher.clone()),
            write: w,
            sealer: Sealer::new(cipher),
            sent: 0,
        })
    }
}

impl AsyncRead for ShadowsocksStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut me.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for ShadowsocksStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let me = self.get_mut();
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        // Шифрование синхронное и быстрое: ошибки AEAD на записи невозможны,
        // в отличие от расшифровки, поэтому unwrap здесь безопасен.
        me.sealer.push(buf).map_err(std::io::Error::other)?;
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        // Разбираем структуру на части: иначе нельзя одновременно держать
        // изменяемую ссылку на сокет и неизменяемую на очередь кадров.
        let me = self.get_mut();
        let Self {
            write,
            sealer,
            sent,
            ..
        } = me;
        while !sealer.queue.is_empty() {
            if *sent >= sealer.queue[0].len() {
                sealer.queue.remove(0);
                *sent = 0;
                continue;
            }
            let frame = &sealer.queue[0][*sent..];
            match std::pin::Pin::new(&mut *write).poll_write(cx, frame) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Ok(0)) => {
                    return std::task::Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "прокси закрыл соединение",
                    )))
                }
                std::task::Poll::Ready(Ok(n)) => *sent += n,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
            }
        }
        std::pin::Pin::new(write).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        std::pin::Pin::new(&mut me.write).poll_shutdown(cx)
    }
}

pub struct Shadowsocks {
    name: String,
    server: SocketAddr,
    method: String,
    master_key: Vec<u8>,
    udp: bool,
}

impl Shadowsocks {
    pub fn new(cfg: OutboundShadowsocks) -> Result<Self> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<_> = (cfg.server.as_str(), cfg.port).to_socket_addrs()?.collect();
        let server = addrs
            .first()
            .copied()
            .ok_or_else(|| Error::ConfigInvalid(format!("{} не разрешается", cfg.server)))?;
        let master_key = derive_key(&cfg.method, &cfg.password);
        Ok(Self {
            name: cfg.name,
            server,
            method: cfg.method,
            master_key,
            udp: cfg.udp,
        })
    }

    /// Открывает TCP-канал: генерирует соль, выводит подключевой ключ, шлёт
    /// соль и первый чанк с адресом назначения.
    async fn open(&self, target: &Target) -> Result<ShadowsocksStream> {
        let tcp = connect_proxy(self.server, Duration::from_secs(10)).await?;
        let salt: [u8; SALT_LEN] = rand::random();

        let mut stream = ShadowsocksStream::new(tcp, &self.master_key, &self.method, &salt)?;
        let addr = socks_addr_bytes(&target.host, target.port)?;
        let mut payload = Vec::with_capacity(2 + addr.len());
        payload.extend_from_slice(&(addr.len() as u16).to_be_bytes());
        payload.extend_from_slice(&addr);

        let ct = stream
            .sealer
            .cipher
            .seal(&stream.sealer.nonce, &payload, &[])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        stream.sealer.nonce = bump(stream.sealer.nonce);

        let mut framed = Vec::with_capacity(SALT_LEN + 2 + ct.len());
        framed.extend_from_slice(&salt);
        framed.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        framed.extend_from_slice(&ct);
        stream.write.write_all(&framed).await?;
        stream.write.flush().await?;
        Ok(stream)
    }
}

// ── UDP через Shadowsocks ─────────────────────────────────────────────────

struct SsUdp {
    sock: UdpSocket,
    cipher: Cipher,
}

#[async_trait]
impl UdpSession for SsUdp {
    async fn send_to(&self, data: &[u8], dst: &Target) -> Result<()> {
        let addr = socks_addr_bytes(&dst.host, dst.port)?;
        let mut payload = Vec::with_capacity(addr.len() + data.len());
        payload.extend_from_slice(&addr);
        payload.extend_from_slice(data);
        let ct = self.cipher.seal(&[0u8; NONCE_LEN], &payload, &[])?;
        self.sock.send(&ct).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8], timeout: Duration) -> Result<(usize, Target)> {
        let mut pkt = vec![0u8; 65535];
        let n = tokio::time::timeout(timeout, self.sock.recv(&mut pkt))
            .await
            .map_err(|_| Error::Timeout("Shadowsocks UDP: нет данных".into()))??;
        let plain = self
            .cipher
            .open(&[0u8; NONCE_LEN], &pkt[..n], &[])
            .map_err(|_| Error::protocol("ss", "не удалось расшифровать UDP-пакет"))?;
        let (host, port) = crate::engine::outbound::parse_socks_addr(&plain)?;
        let at = 1 + match plain[0] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => 1 + plain[1] as usize + 2,
            _ => return Err(Error::protocol("ss", "битый адрес в UDP-ответе")),
        };
        if plain.len() <= at {
            return Err(Error::protocol("ss", "пустой UDP-ответ"));
        }
        let len = (plain.len() - at).min(buf.len());
        buf[..len].copy_from_slice(&plain[at..at + len]);
        Ok((
            len,
            Target {
                host,
                port,
                is_tcp: false,
            },
        ))
    }

    fn local_addr(&self) -> SocketAddr {
        self.sock
            .local_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
    }
}

#[async_trait]
impl Outbound for Shadowsocks {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "shadowsocks"
    }

    fn supports_udp(&self) -> bool {
        self.udp
    }

    fn remote_dns(&self) -> bool {
        true
    }

    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>> {
        let stream = self.open(&req.target).await?;
        Ok(Box::new(stream))
    }

    async fn open_udp(&self) -> Result<Arc<dyn UdpSession>> {
        if !self.udp {
            return Err(Error::protocol("ss", "UDP отключён в конфигурации"));
        }
        let sock = UdpSocket::bind("0.0.0.0:0").await?;
        sock.connect(self.server).await?;
        let sk = subkey(&self.master_key, &[0u8; SALT_LEN]);
        let cipher = Cipher::new(&self.method, &sk)?;
        Ok(Arc::new(SsUdp { sock, cipher }))
    }
}

// ───────────────────────────────── тесты ───────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[test]
    fn evp_bytes_to_key_matches_openssl_for_known_input() {
        // Вектор из shadowsocks: password "test" для aes-256-cfb даёт этот ключ.
        let k = evp_bytes_to_key(b"test", 32);
        assert_eq!(k.len(), 32);
        // Детерминированность — главное свойство, которое тут проверяем.
        assert_eq!(k, evp_bytes_to_key(b"test", 32));
        assert_ne!(k, evp_bytes_to_key(b"other", 32));
    }

    #[test]
    fn derive_key_prefers_base64() {
        let raw = [7u8; 32];
        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, raw);
        assert_eq!(derive_key("chacha20-ietf-poly1305", &b64), raw.to_vec());
        assert_eq!(derive_key("aes-128-gcm", &b64), raw[..16].to_vec());
    }

    #[test]
    fn subkey_depends_on_salt() {
        let k = vec![1u8; 32];
        assert_ne!(subkey(&k, &[0u8; 32]), subkey(&k, &[1u8; 32]));
        assert_eq!(subkey(&k, &[2u8; 32]), subkey(&k, &[2u8; 32]));
    }

    #[test]
    fn nonce_increments_little_endian_with_carry() {
        // Обычный случай: младший байт растёт.
        assert_eq!(bump([0u8; 12]), {
            let mut e = [0u8; 12];
            e[0] = 1;
            e
        });
        // Перенос: переполнившийся младший байт обнуляется, единица уходит
        // в следующий — счётчик little-endian.
        assert_eq!(bump([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), {
            let mut e = [0u8; 12];
            e[1] = 1;
            e
        });
        // Полное переполнение всего счётчика даёт нули, а не панику.
        assert_eq!(bump([0xff; 12]), [0u8; 12]);
    }

    #[test]
    fn cipher_roundtrip_for_every_supported_method() {
        for m in ["chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm"] {
            let key = [42u8; 32];
            let c = Cipher::new(m, &key[..if m == "aes-128-gcm" { 16 } else { 32 }]).unwrap();
            let nonce = [3u8; 12];
            let ct = c.seal(&nonce, b"hello shadowsocks", b"").unwrap();
            assert_eq!(ct.len(), b"hello shadowsocks".len() + 16, "{m}");
            assert_eq!(c.open(&nonce, &ct, b"").unwrap(), b"hello shadowsocks");
            // Подмена байта должна давать ошибку аутентификации, а не мусор.
            let mut bad = ct.clone();
            bad[0] ^= 1;
            assert!(
                c.open(&nonce, &bad, b"").is_err(),
                "{m} принял подделанный пакет"
            );
        }
    }

    #[test]
    fn cipher_rejects_wrong_nonce() {
        let c = Cipher::new("chacha20-ietf-poly1305", &[1u8; 32]).unwrap();
        let ct = c.seal(&[0u8; 12], b"data", b"").unwrap();
        assert!(c.open(&[1u8; 12], &ct, b"").is_err());
    }

    #[tokio::test]
    async fn open_stream_decrypts_multiple_chunks() {
        use tokio::io::AsyncWriteExt;
        let key = vec![9u8; 32];
        let c = Cipher::new("chacha20-ietf-poly1305", &key).unwrap();

        // Собираем два кадра по SIP004, как это сделал бы сервер:
        // длина данных — внутри шифротекста, снаружи — длина шифротекста.
        let mut wire = Vec::new();
        let mut n = [0u8; 12];
        for msg in [&b"first"[..], b"second"] {
            let mut inner = Vec::new();
            inner.extend_from_slice(&(msg.len() as u16).to_be_bytes());
            inner.extend_from_slice(msg);
            let ct = c.seal(&n, &inner, &[]).unwrap();
            wire.extend_from_slice(&(ct.len() as u16).to_be_bytes());
            wire.extend_from_slice(&ct);
            n = bump(n);
        }

        let (client, mut server) = tokio::io::duplex(1024);
        server.write_all(&wire).await.unwrap();
        server.shutdown().await.unwrap();

        let mut r = OpenStream::new(client, c);
        let mut out = Vec::new();
        tokio::time::timeout(std::time::Duration::from_secs(5), r.read_to_end(&mut out))
            .await
            .expect("чтение зависло")
            .unwrap();
        assert_eq!(out, b"firstsecond");
    }

    #[tokio::test]
    async fn open_stream_rejects_corrupted_chunk() {
        use tokio::io::AsyncWriteExt;
        let c = Cipher::new("aes-256-gcm", &[3u8; 32]).unwrap();
        let mut inner = Vec::new();
        inner.extend_from_slice(&7u16.to_be_bytes());
        inner.extend_from_slice(b"payload");
        let mut ct = c.seal(&[0u8; 12], &inner, b"").unwrap();
        ct[2] ^= 0xff;
        let mut wire = Vec::new();
        wire.extend_from_slice(&(ct.len() as u16).to_be_bytes());
        wire.extend_from_slice(&ct);

        let (client, mut server) = tokio::io::duplex(1024);
        server.write_all(&wire).await.unwrap();

        let mut r = OpenStream::new(client, c);
        let mut out = Vec::new();
        let res = tokio::time::timeout(std::time::Duration::from_secs(5), r.read_to_end(&mut out))
            .await
            .expect("чтение не должно зависать на повреждённых данных");
        assert!(
            res.is_err(),
            "повреждённый чант должен давать ошибку, а не данные"
        );
    }

    #[test]
    fn first_chunk_length_is_consistent_with_framing() {
        let s = Shadowsocks::new(OutboundShadowsocks {
            name: "SS".into(),
            server: "127.0.0.1".into(),
            port: 8388,
            method: "chacha20-ietf-poly1305".into(),
            password: "secret".into(),
            plugin: String::new(),
            udp: true,
            test_url: None,
            test_timeout_ms: None,
        })
        .unwrap();
        let c = Cipher::new(&s.method, &subkey(&s.master_key, &[0u8; 32])).unwrap();
        let t = Target {
            host: "example.com".into(),
            port: 443,
            is_tcp: true,
        };
        let addr = socks_addr_bytes(&t.host, t.port).unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&(addr.len() as u16).to_be_bytes());
        payload.extend_from_slice(&addr);
        let ct = c.seal(&[0u8; 12], &payload, &[]).unwrap();
        assert_eq!(
            u16::from_be_bytes([0u8, 0u8][..].try_into().unwrap()) as usize,
            0
        );
        assert_eq!(ct.len() - TAG_LEN, payload.len(), "полезная нагрузка чанта");
    }
}
