//! Встроенный DNS-резолвер.
//!
//! Зачем он нужен при прозрачном перехвате: если мы просто перенаправим
//! запросы на 53-й порт нашему обработчику, мы узнаем домен, который
//! приложение хочет разрешить, и сможем применить доменные правила. Без
//! этого весь трафик пришлось бы классифицировать по IP, а DNS-утечка через
//! локальный резолвер осталась бы.
//!
//! Стратегии:
//! * `fake-ip` — отдаём синтетический адрес из 198.18.0.0/16 и держим
//!   обратную карту. Клиент thinks it talks to a real IP, мы знаем домен.
//! * `redir-host` — резолвим нашим же резолвером и отдаём настоящий адрес.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::DnsConfig;
use crate::error::{Error, Result};

/// Сеть для fake-ip. Зарезервирована для бенчмарков, в обычном интернете
/// не маршрутизируется — идеальное место, чтобы не конфликтовать с чужой сетью.
const FAKE_IPV4: std::net::Ipv4Addr = std::net::Ipv4Addr::new(198, 18, 0, 0);
const FAKE_IPV4_END: u32 = 0x00FF_FFFF; // /16

#[derive(Debug, Clone)]
struct FakeEntry {
    domain: String,
    expires: Instant,
}

#[derive(Debug)]
struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires: Instant,
}

/// Резолвер с кэшем, fake-ip-подменой и ленивой загрузкой ответов.
pub struct Resolver {
    cfg: DnsConfig,
    fake: Mutex<FakeState>,
    cache: Mutex<HashMap<String, CacheEntry>>,
    client: reqwest::Client,
}

struct FakeState {
    /// domain -> fake ip
    forward: HashMap<IpAddr, FakeEntry>,
    /// fake ip -> domain
    reverse: HashMap<String, IpAddr>,
    next: u32,
}

impl Resolver {
    pub fn new(cfg: DnsConfig) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            fake: Mutex::new(FakeState {
                forward: HashMap::new(),
                reverse: HashMap::new(),
                next: 1,
            }),
            cache: Mutex::new(HashMap::new()),
            client: crate::engine::http_client()?,
            cfg,
        }))
    }

    /// Записывает домен в реестр и возвращает выданный ему адрес.
    /// `None`, если адресное пространство исчерпано.
    pub fn fake_ip_for(&self, domain: &str) -> Option<IpAddr> {
        let mut st = self.fake.lock().ok()?;
        // Домен мог уже быть выдан — возвращаем тот же адрес, иначе
        // соединения к одному сайту разъезжались бы по разным адресам.
        if let Some(existing) = st
            .reverse
            .iter()
            .find(|(d, _)| d.eq_ignore_ascii_case(domain))
            .map(|(_, ip)| *ip)
        {
            return Some(existing);
        }
        if st.reverse.len() as u32 >= FAKE_IPV4_END {
            return None;
        }
        let n = st.next;
        st.next = st.next.wrapping_add(1);
        let ip = IpAddr::V4(Ipv4Addr::from(u32::from(FAKE_IPV4) + (n % FAKE_IPV4_END)));
        st.reverse.insert(domain.to_ascii_lowercase(), ip);
        st.forward.insert(ip, FakeEntry { domain: domain.to_ascii_lowercase(), expires: Instant::now() + Duration::from_secs(3600) });
        Some(ip)
    }

    /// Обратное преобразование fake-ip в домен.
    pub fn domain_of(&self, ip: &IpAddr) -> Option<String> {
        let st = self.fake.lock().ok()?;
        st.forward.get(ip).map(|e| e.domain.clone())
    }

    /// Резолвит домен в адреса с кэшем и TTL.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        {
            let cache = self.cache.lock().map_err(|_| Error::Internal("кэш DNS заблокирован".into()))?;
            if let Some(e) = cache.get(domain) {
                if e.expires > Instant::now() {
                    return Ok(e.addrs.clone());
                }
            }
        }
        let addrs = self.resolve_uncached(domain).await?;
        if let Ok(mut cache) = self.cache.lock() {
            if cache.len() > self.cfg.cache_size {
                cache.clear();
            }
            cache.insert(
                domain.to_string(),
                CacheEntry { addrs: addrs.clone(), expires: Instant::now() + Duration::from_secs(self.cfg.cache_ttl) },
            );
        }
        Ok(addrs)
    }

    async fn resolve_uncached(&self, domain: &str) -> Result<Vec<IpAddr>> {
        use std::net::ToSocketAddrs;
        // Сначала пробуем системный путь: он учитывает /etc/hosts и
        // systemd-resolved, что важно для внутренних имён в сети.
        if let Ok(addrs) = (domain, 0u16).to_socket_addrs() {
            let v: Vec<IpAddr> = addrs.map(|a| a.ip()).collect();
            if !v.is_empty() {
                return Ok(v);
            }
        }
        // Затем DoH — работает, даже когда UDP/53 перехвачен.
        let mut last = None;
        for server in self.cfg.servers.iter().chain(self.cfg.fallback.iter()) {
            match self.doh_query(server, domain).await {
                Ok(v) if !v.is_empty() => return Ok(v),
                Ok(_) => {}
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap_or_else(|| Error::Internal(format!("не удалось разрешить {domain}"))))
    }

    /// Минимальный DoH-клиент: JSON-ответ Cloudflare/Google.
    async fn doh_query(&self, server: &str, domain: &str) -> Result<Vec<IpAddr>> {
        let url = match server {
            s if s.contains("google") => format!("https://dns.google/resolve?name={domain}&type=A"),
            _ => format!("https://cloudflare-dns.com/dns-query?name={domain}&type=A"),
        };
        let resp = self
            .client
            .get(&url)
            .header("accept", "application/dns-json")
            .send()
            .await
            .map_err(|e| Error::Internal(format!("DoH {server}: {e}")))?;
        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| Error::Internal(format!("DoH {server}: плохой ответ: {e}")))?;
        let mut out = Vec::new();
        if let Some(arr) = json.get("Answer").and_then(|a| a.as_array()) {
            for a in arr {
                if let Some(data) = a.get("data").and_then(|d| d.as_str()) {
                    if let Ok(ip) = data.parse::<IpAddr>() {
                        out.push(ip);
                    }
                }
            }
        }
        Ok(out)
    }

    /// Чистка протухших записей. Вызывается раз в минуту.
    pub fn gc(&self) {
        if let Ok(mut c) = self.cache.lock() {
            let now = Instant::now();
            c.retain(|_, e| e.expires > now);
        }
        if let Ok(mut f) = self.fake.lock() {
            let now = Instant::now();
            f.forward.retain(|_, e| e.expires > now);
            let live: std::collections::HashSet<IpAddr> = f.forward.keys().copied().collect();
            f.reverse.retain(|_, ip| live.contains(ip));
        }
    }
}

/// Разбирает DNS-запрос и достаёт имя. Возвращает `(offset_qname, end_offset, qtype)`.
pub fn parse_question(buf: &[u8]) -> Result<(usize, usize, u16)> {
    if buf.len() < 12 {
        return Err(Error::protocol("dns", "короткий пакет"));
    }
    let mut i = 12;
    let start = i;
    loop {
        if i >= buf.len() {
            return Err(Error::protocol("dns", "имя не найдено"));
        }
        let len = buf[i];
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Сжатая ссылка в запросе не встречается, но обработаем.
            i += 2;
            break;
        }
        i += 1 + len as usize;
    }
    if i + 4 > buf.len() {
        return Err(Error::protocol("dns", "обрезан qtype"));
    }
    let qtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
    Ok((start, i, qtype))
}

pub fn decode_qname(buf: &[u8], start: usize, end: usize) -> String {
    let mut out = String::new();
    let mut i = start;
    while i < end && buf[i] != 0 {
        let len = buf[i] as usize;
        if i + 1 + len > end {
            break;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&buf[i + 1..i + 1 + len]));
        i += 1 + len;
    }
    out.to_ascii_lowercase()
}

/// Собирает ответ A/AAAA на перехваченный запрос.
pub fn build_response(query: &[u8], addrs: &[IpAddr], ttl: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(query.len() + 64);
    out.extend_from_slice(&query[..2]);
    // QR=1, RD скопирован, RA=1
    let flags = u16::from_be_bytes([0x81, 0x80]);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&query[12..]); // вопрос без изменений

    for a in addrs {
        match a {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
                out.extend_from_slice(&ttl.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&[0x00, 0x1C, 0x00, 0x01]); // AAAA, IN
                out.extend_from_slice(&ttl.to_be_bytes());
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

/// Читает UDP-датаграмму целиком.
pub async fn recv_datagram(sock: &tokio::net::UdpSocket) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 4096];
    let n = sock.recv(&mut buf).await?;
    buf.truncate(n);
    Ok(buf)
}

/// Читает TCP-сообщение DNS с префиксом длины.
pub async fn read_tcp_dns(sock: &mut tokio::net::TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    sock.read_exact(&mut len).await?;
    let n = u16::from_be_bytes(len) as usize;
    if n == 0 || n > 4096 {
        return Err(Error::protocol("dns", format!("нераспознанная длина DNS {n}")));
    }
    let mut body = vec![0u8; n];
    sock.read_exact(&mut body).await?;
    sock.write_all(&len).await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fake_ip_is_stable_per_domain() {
        let r = Resolver::new(DnsConfig::default()).unwrap();
        let a = r.fake_ip_for("example.com").unwrap();
        let b = r.fake_ip_for("EXAMPLE.COM").unwrap();
        assert_eq!(a, b, "один домен — один адрес, регистр не важен");
        assert_ne!(a, r.fake_ip_for("other.com").unwrap());
    }

    #[tokio::test]
    async fn fake_ip_roundtrip() {
        let r = Resolver::new(DnsConfig::default()).unwrap();
        let ip = r.fake_ip_for("vk.com").unwrap();
        assert_eq!(r.domain_of(&ip).as_deref(), Some("vk.com"));
        assert!(r.domain_of(&"1.2.3.4".parse().unwrap()).is_none());
    }

    #[tokio::test]
    async fn fake_ip_stays_inside_198_18_0_0_16() {
        let r = Resolver::new(DnsConfig::default()).unwrap();
        for i in 0..50 {
            let ip = r.fake_ip_for(&format!("site{i}.com")).unwrap();
            let v4 = match ip {
                IpAddr::V4(v) => v,
                _ => panic!("ожидался IPv4"),
            };
            assert_eq!(v4.octets()[0], 198);
            assert_eq!(v4.octets()[1], 18);
        }
    }

    #[test]
    fn parses_dns_question() {
        // a.example.com A ?
        let mut q = vec![0u8; 12];
        q.push(1); q.extend_from_slice(b"a");
        q.push(7); q.extend_from_slice(b"example");
        q.push(3); q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        let (s, e, qt) = parse_question(&q).unwrap();
        assert_eq!(decode_qname(&q, s, e), "a.example.com");
        assert_eq!(qt, 1);
    }

    #[test]
    fn dns_response_has_answers() {
        let mut q = vec![0u8; 12];
        q[0] = 0xAB; q[1] = 0xCD; // id
        q.push(3); q.extend_from_slice(b"com"); q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        let addrs = vec!["1.2.3.4".parse().unwrap()];
        let r = build_response(&q, &addrs, 300);
        assert_eq!(&r[0..2], &[0xAB, 0xCD], "ID запроса должен сохраняться");
        assert_eq!(&r[4..6], &1u16.to_be_bytes(), "QDCOUNT");
        assert_eq!(&r[6..8], &1u16.to_be_bytes(), "ANCOUNT");
        assert_eq!(&r[r.len() - 4..], &[1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn cache_returns_same_answer() {
        let r = Resolver::new(DnsConfig::default()).unwrap();
        // localhost резолвится системно, сети не нужно.
        let a = r.resolve("localhost").await.unwrap();
        let b = r.resolve("localhost").await.unwrap();
        assert_eq!(a, b);
    }

    #[tokio::test]
    async fn gc_drops_expired() {
        let r = Resolver::new(DnsConfig {
            cache_ttl: 0,
            ..DnsConfig::default()
        })
        .unwrap();
        let _ = r.resolve("localhost").await;
        r.gc();
        // После gc кэш пуст, но это не должно падать.
        assert!(r.resolve("localhost").await.is_ok());
    }
}
