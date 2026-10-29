//! DNS: карта «адрес → имя» и локальный ответ для правила `HIJACK-DNS`.
//!
//! При прозрачном перехвате приложение обращается к IP, а правилам и
//! remote-DNS прокси нужен домен. Поэтому DNS-запросы, проходящие через
//! перехват, не только проксируются, но и запоминаются: из ответа берутся
//! A/AAAA-записи, и дальше любой поток к этому адресу получает имя в
//! `Flow::domain`.
//!
//! Стратегия одна — `redir-host`: приложению возвращается настоящий адрес,
//! а соответствие «IP → домен» держит демон. `fake-ip` не реализован и
//! отклоняется валидацией конфига: настройка, которая молча ничего не
//! делает, хуже отказа.
//!
//! `Resolver` нужен для правила `HIJACK-DNS`: ответ собирается локально,
//! запрос не уходит наружу. Обычный путь DNS — проксирование через
//! выбранный правилами outbound (`engine::tun::udp`, `engine::capture`).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::DnsConfig;
use crate::error::{Error, Result};

/// Запись «адрес → имя» из настоящего DNS-ответа.
#[derive(Debug, Clone)]
struct NameEntry {
    domain: String,
    expires: Instant,
}

#[derive(Debug)]
struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires: Instant,
}

/// Резолвер с кэшем и картой «IP → домен», заполняемой из перехваченных
/// DNS-ответов.
pub struct Resolver {
    cfg: DnsConfig,
    cache: Mutex<HashMap<String, CacheEntry>>,
    names: Mutex<HashMap<IpAddr, NameEntry>>,
    /// Клиент DoH создаётся при первом обращении: большинство запросов
    /// закрывается кэшем или системным резолвером.
    client: OnceLock<reqwest::Client>,
}

/// Что удалось достать из ответа: домен из вопроса и адреса из A/AAAA.
#[derive(Debug, Default)]
pub struct Answer {
    pub domain: String,
    pub addrs: Vec<IpAddr>,
}

impl Resolver {
    pub fn new(cfg: DnsConfig) -> Result<Arc<Self>> {
        Ok(Arc::new(Self {
            cfg,
            cache: Mutex::new(HashMap::new()),
            names: Mutex::new(HashMap::new()),
            client: OnceLock::new(),
        }))
    }

    /// Имя, которое приложение разрешало в этот адрес. `None` — адрес не
    /// встречался в перехваченных ответах (или запись протухла).
    pub fn name_of(&self, ip: IpAddr) -> Option<String> {
        let names = self.names.lock().ok()?;
        let e = names.get(&ip)?;
        (e.expires > Instant::now()).then(|| e.domain.clone())
    }

    /// Сколько адресов сейчас в карте — для диагностики и тестов.
    pub fn names_len(&self) -> usize {
        self.names.lock().map(|n| n.len()).unwrap_or(0)
    }

    /// Разбирает настоящий DNS-ответ и запоминает «адрес → имя вопроса».
    /// Возвращает число запомненных адресов. Битый пакет — не ошибка:
    /// перехват не должен падать из-за чужих байтов.
    pub fn remember_response(&self, response: &[u8]) -> usize {
        let Some(answer) = parse_response(response) else {
            return 0;
        };
        if answer.domain.is_empty() || answer.addrs.is_empty() {
            return 0;
        }
        self.remember(&answer.domain, &answer.addrs);
        answer.addrs.len()
    }

    /// Записывает соответствие напрямую (используется `answer_query`,
    /// `remember_response` и тестами).
    pub fn remember(&self, domain: &str, addrs: &[IpAddr]) {
        if domain.is_empty() || addrs.is_empty() {
            return;
        }
        let ttl = Duration::from_secs(self.cfg.cache_ttl.clamp(60, 3600));
        let Ok(mut names) = self.names.lock() else {
            return;
        };
        if names.len() > self.cfg.cache_size.saturating_mul(8) {
            names.clear();
        }
        let now = Instant::now();
        for ip in addrs {
            names.insert(
                *ip,
                NameEntry {
                    domain: domain.to_ascii_lowercase(),
                    expires: now + ttl,
                },
            );
        }
    }

    /// Ответ для правила `HIJACK-DNS`: локальное разрешение имени.
    /// Всегда возвращает валидный DNS-ответ — при неудаче `SERVFAIL`,
    /// чтобы приложение сразу перешло к следующему серверу, а не ждало
    /// таймаут.
    pub async fn answer_query(&self, query: &[u8]) -> Vec<u8> {
        let Ok((start, end, qtype)) = parse_question(query) else {
            return servfail(query);
        };
        let domain = decode_qname(query, start, end);
        if domain.is_empty() {
            return servfail(query);
        }
        if qtype != 1 && qtype != 28 {
            // Прочие типы (TXT, HTTPS, SRV) локально не отвечаем честно —
            // лучше SERVFAIL, чем пустой ответ, который приложение примет
            // за «записи нет».
            return servfail(query);
        }
        let addrs = match self.resolve(&domain).await {
            Ok(a) => a,
            Err(e) => {
                tracing::debug!(domain = %domain, error = %e, "HIJACK-DNS: имя не разрешено");
                return servfail(query);
            }
        };
        let filtered: Vec<IpAddr> = addrs
            .into_iter()
            .filter(|a| matches!((a, qtype), (IpAddr::V4(_), 1) | (IpAddr::V6(_), 28)))
            .collect();
        let ttl = self.cfg.cache_ttl.clamp(60, 3600);
        let out = build_response(query, &filtered, ttl as u32);
        // Ответ собран из настоящих адресов — запоминаем их, иначе
        // доменные правила для последующих соединений не сработают.
        self.remember(&domain, &filtered);
        out
    }

    /// Резолвит домен в адреса с кэшем и TTL.
    pub async fn resolve(&self, domain: &str) -> Result<Vec<IpAddr>> {
        {
            let cache = self
                .cache
                .lock()
                .map_err(|_| Error::Internal("кэш DNS заблокирован".into()))?;
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
                CacheEntry {
                    addrs: addrs.clone(),
                    expires: Instant::now() + Duration::from_secs(self.cfg.cache_ttl),
                },
            );
        }
        Ok(addrs)
    }

    async fn resolve_uncached(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // Сначала пробуем системный путь: он учитывает /etc/hosts и
        // systemd-resolved, что важно для внутренних имён в сети.
        //
        // `getaddrinfo` блокирующий, и на рабочем потоке tokio он остановил
        // бы чужие задачи на всё время таймаута резолвера. С DNS-заглушкой
        // системного резолвера этот путь вызывается часто, поэтому уводим
        // его в блокирующий пул.
        let name = domain.to_string();
        let resolved = tokio::task::spawn_blocking(move || {
            use std::net::ToSocketAddrs;
            (name.as_str(), 0u16)
                .to_socket_addrs()
                .map(|it| it.map(|a| a.ip()).collect::<Vec<IpAddr>>())
                .unwrap_or_default()
        })
        .await
        .unwrap_or_default();
        if !resolved.is_empty() {
            return Ok(resolved);
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

    /// HTTP-клиент для DoH. Адреса закреплены, чтобы запрос не зависел от
    /// системного резолвера: иначе `cloudflare-dns.com` пришлось бы
    /// разрешать тем же DNS, который мы перехватываем.
    fn client(&self) -> &reqwest::Client {
        self.client.get_or_init(|| {
            reqwest::Client::builder()
                .user_agent(concat!("proxy-for-ubuntu/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(10))
                .resolve("cloudflare-dns.com", ([1, 1, 1, 1], 443).into())
                .resolve("dns.google", ([8, 8, 8, 8], 443).into())
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        })
    }

    /// Минимальный DoH-клиент: JSON-ответ Cloudflare/Google.
    async fn doh_query(&self, server: &str, domain: &str) -> Result<Vec<IpAddr>> {
        let url = match server {
            s if s.contains("google") => format!("https://dns.google/resolve?name={domain}&type=A"),
            _ => format!("https://cloudflare-dns.com/dns-query?name={domain}&type=A"),
        };
        let resp = self
            .client()
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
        let now = Instant::now();
        if let Ok(mut c) = self.cache.lock() {
            c.retain(|_, e| e.expires > now);
        }
        if let Ok(mut n) = self.names.lock() {
            n.retain(|_, e| e.expires > now);
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

/// Читает имя из ответа с поддержкой сжатия (`0xC0`-указатели).
fn read_name(buf: &[u8], mut i: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut jumps = 0;
    let mut next = i;
    loop {
        if i >= buf.len() {
            return None;
        }
        let len = buf[i] as usize;
        if len & 0xC0 == 0xC0 {
            if i + 1 >= buf.len() {
                return None;
            }
            let ptr = ((len & 0x3F) << 8) | buf[i + 1] as usize;
            if jumps == 0 {
                next = i + 2;
            }
            jumps += 1;
            if jumps > 32 || ptr >= buf.len() {
                return None;
            }
            i = ptr;
            continue;
        }
        if len == 0 {
            if jumps == 0 {
                next = i + 1;
            }
            return Some((out.to_ascii_lowercase(), next));
        }
        if i + 1 + len > buf.len() {
            return None;
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(&buf[i + 1..i + 1 + len]));
        i += 1 + len;
    }
}

/// Разбирает ответ: имя из вопроса и адреса из A/AAAA-записей.
pub fn parse_response(buf: &[u8]) -> Option<Answer> {
    if buf.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return None; // это не ответ
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    if qd == 0 || an == 0 {
        return None;
    }
    let (start, end, _qtype) = parse_question(buf).ok()?;
    let domain = decode_qname(buf, start, end);
    let mut i = end + 4;
    // Пропускаем остальные вопросы, если они есть.
    for _ in 1..qd {
        let (_, next) = read_name(buf, i)?;
        i = next + 4;
    }
    let mut addrs = Vec::new();
    for _ in 0..an {
        let (_, next) = read_name(buf, i)?;
        i = next;
        if i + 10 > buf.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([buf[i], buf[i + 1]]);
        let rdlen = u16::from_be_bytes([buf[i + 8], buf[i + 9]]) as usize;
        i += 10;
        if i + rdlen > buf.len() {
            return None;
        }
        match (rtype, rdlen) {
            (1, 4) => addrs.push(IpAddr::V4(Ipv4Addr::new(
                buf[i],
                buf[i + 1],
                buf[i + 2],
                buf[i + 3],
            ))),
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[i..i + 16]);
                addrs.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
        i += rdlen;
    }
    Some(Answer { domain, addrs })
}

/// Собирает ответ A/AAAA на перехваченный запрос. Копируется только сам
/// вопрос: лишние секции (EDNS0 OPT) в ответе не нужны, а их хвост сделал
/// бы пакет несогласованным с ARCOUNT.
pub fn build_response(query: &[u8], addrs: &[IpAddr], ttl: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(query.len() + 64);
    out.extend_from_slice(&query[..2]);
    // QR=1, RD — как в запросе, RA=1, RCODE=0.
    let rd = query[2] & 0x01;
    let flags: u16 = 0x8000 | ((rd as u16) << 8) | 0x0080;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&(addrs.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());

    // Вопрос целиком: имя + qtype + qclass.
    let question_end = parse_question(query)
        .map(|(_, end, _)| end + 4)
        .unwrap_or(query.len())
        .min(query.len());
    out.extend_from_slice(&query[12..question_end]);

    // Имя записи — указатель на имя вопроса (offset 12): так делают все
    // настоящие серверы, и пакет остаётся коротким. Пустое имя (0x00) здесь
    // было бы корнем, а не вопросом.
    for a in addrs {
        out.extend_from_slice(&[0xC0, 0x0C]);
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

/// Ответ SERVFAIL на запрос: заголовок вопроса сохраняется, ответов нет.
pub fn servfail(query: &[u8]) -> Vec<u8> {
    let mut out = build_response(query, &[], 0);
    if out.len() >= 4 {
        // RCODE=2 в младших 4 битах флагов.
        out[3] |= 0x02;
    }
    out
}

/// Адрес вышестоящего DNS-сервера из строки конфига (`dns.servers`,
/// `dns.fallback`). Понимает `1.1.1.1`, `1.1.1.1:5353`, `[::1]:53`.
///
/// Имя хоста намеренно не принимается: чтобы его разрешить, понадобился бы
/// ровно тот DNS, который мы и перехватываем, — получился бы цикл.
pub fn upstream_addr(server: &str) -> Option<SocketAddr> {
    let s = server.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(addr);
    }
    s.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, 53))
}

/// Первый пригодный адрес из `servers`, затем из `fallback`. Если не
/// разобралась ни одна строка — Cloudflare: остаться совсем без DNS хуже,
/// чем взять общеизвестный сервер.
pub fn first_upstream(servers: &[String], fallback: &[String]) -> SocketAddr {
    servers
        .iter()
        .chain(fallback.iter())
        .find_map(|s| upstream_addr(s))
        .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53))
}

/// Ответ ли это на наш запрос. Сессия UDP своя на каждый запрос, но проверка
/// дешёвая и отсекает чужие или запоздавшие датаграммы, которые иначе ушли бы
/// приложению как ответ.
pub fn is_reply_to(query: &[u8], reply: &[u8]) -> bool {
    reply.len() >= 12 && query.len() >= 2 && reply[..2] == query[..2]
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
        return Err(Error::protocol(
            "dns",
            format!("нераспознанная длина DNS {n}"),
        ));
    }
    let mut body = vec![0u8; n];
    sock.read_exact(&mut body).await?;
    sock.write_all(&len).await?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0u8; 12];
        q[0] = 0xAB;
        q[1] = 0xCD;
        q[2] = 0x01; // RD
        for part in name.split('.') {
            q.push(part.len() as u8);
            q.extend_from_slice(part.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&1u16.to_be_bytes());
        q
    }

    #[tokio::test]
    async fn response_is_remembered_as_name() {
        let r = Resolver::new(DnsConfig::default()).unwrap();
        let q = query("echo.dns.test", 1);
        let resp = build_response(&q, &["203.0.113.7".parse().unwrap()], 300);
        assert_eq!(r.remember_response(&resp), 1);
        assert_eq!(
            r.name_of("203.0.113.7".parse().unwrap()).as_deref(),
            Some("echo.dns.test")
        );
        assert!(r.name_of("203.0.113.8".parse().unwrap()).is_none());
    }

    #[tokio::test]
    async fn remember_ignores_request_and_garbage() {
        let r = Resolver::new(DnsConfig::default()).unwrap();
        let q = query("echo.dns.test", 1);
        assert_eq!(r.remember_response(&q), 0, "запрос — не ответ");
        assert_eq!(r.remember_response(&[0, 1, 2]), 0);
        assert_eq!(r.names_len(), 0);
    }

    #[test]
    fn uncompressed_answer_names_are_parsed() {
        // Не все серверы сжимают имя записи. Полное имя в ответе должно
        // разбираться так же, как указатель.
        let q = query("example.com", 1);
        let mut resp = build_response(&q, &[], 300);
        resp[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT=1
        resp.extend_from_slice(&q[12..25]); // имя целиком
        resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[93, 184, 216, 34]);
        let parsed = parse_response(&resp).expect("ответ разобран");
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(
            parsed.addrs,
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
    }

    #[tokio::test]
    async fn hijack_answers_localhost_with_a_record() {
        let r = Resolver::new(DnsConfig::default()).unwrap();
        let q = query("localhost", 1);
        let resp = r.answer_query(&q).await;
        assert_eq!(&resp[0..2], &[0xAB, 0xCD], "ID запроса сохраняется");
        assert_eq!(&resp[6..8], &1u16.to_be_bytes(), "один ответ");
        // localhost есть в /etc/hosts — внешняя сеть не нужна.
        assert!(parse_response(&resp)
            .unwrap()
            .addrs
            .contains(&"127.0.0.1".parse().unwrap()));
    }

    #[tokio::test]
    async fn hijack_unsupported_type_is_servfail() {
        let r = Resolver::new(DnsConfig::default()).unwrap();
        let resp = r.answer_query(&query("localhost", 16)).await;
        assert_eq!(resp[3] & 0x0F, 2, "RCODE=SERVFAIL");
        assert_eq!(&resp[6..8], &0u16.to_be_bytes(), "ответов нет");
    }

    #[test]
    fn parses_dns_question() {
        let q = query("a.example.com", 1);
        let (s, e, qt) = parse_question(&q).unwrap();
        assert_eq!(decode_qname(&q, s, e), "a.example.com");
        assert_eq!(qt, 1);
    }

    #[test]
    fn dns_response_has_answers() {
        let q = query("com", 1);
        let addrs = vec!["1.2.3.4".parse().unwrap()];
        let r = build_response(&q, &addrs, 300);
        assert_eq!(&r[0..2], &[0xAB, 0xCD], "ID запроса должен сохраняться");
        assert_eq!(&r[4..6], &1u16.to_be_bytes(), "QDCOUNT");
        assert_eq!(&r[6..8], &1u16.to_be_bytes(), "ANCOUNT");
        assert_eq!(&r[r.len() - 4..], &[1, 2, 3, 4]);
    }

    #[test]
    fn response_keeps_only_the_question() {
        // Запрос с EDNS0 OPT в additional: в ответе не должно быть его хвоста,
        // иначе пакет противоречит ARCOUNT=0.
        let mut q = query("example.com", 1);
        q[10] = 0;
        q[11] = 1; // ARCOUNT=1
        q.extend_from_slice(&[0x00, 0x00, 0x29, 0x10, 0x00, 0, 0, 0, 0, 0, 0]); // OPT
        let r = build_response(&q, &["1.2.3.4".parse().unwrap()], 60);
        assert_eq!(r.len(), 12 + 17 + 16, "вопрос 17 байт + один ответ 16");
        assert_eq!(&r[10..12], &[0, 0], "ARCOUNT=0");
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

    #[test]
    fn upstream_accepts_plain_and_explicit_port() {
        assert_eq!(
            upstream_addr("1.1.1.1"),
            Some("1.1.1.1:53".parse().unwrap()),
            "без порта — стандартный 53"
        );
        assert_eq!(
            upstream_addr(" 9.9.9.9:5353 "),
            Some("9.9.9.9:5353".parse().unwrap())
        );
        assert_eq!(
            upstream_addr("[2606:4700:4700::1111]:53"),
            Some("[2606:4700:4700::1111]:53".parse().unwrap())
        );
        // Имя хоста не принимается: его разрешение снова потребовало бы DNS.
        assert_eq!(upstream_addr("dns.google"), None);
        assert_eq!(upstream_addr(""), None);
    }

    #[test]
    fn first_upstream_skips_bad_entries_and_falls_back() {
        let servers = vec!["dns.google".to_string(), "1.0.0.1:5353".to_string()];
        let fallback = vec!["9.9.9.9".to_string()];
        assert_eq!(
            first_upstream(&servers, &fallback),
            "1.0.0.1:5353".parse().unwrap()
        );
        // Ни одной пригодной строки — Cloudflare, а не паника и не пустой адрес.
        assert_eq!(
            first_upstream(&["bad".into()], &[]),
            "1.1.1.1:53".parse().unwrap()
        );
    }

    #[test]
    fn reply_is_matched_by_transaction_id() {
        let query = query("example.com", 1);
        let reply = build_response(&query, &["1.2.3.4".parse().unwrap()], 60);
        assert!(is_reply_to(&query, &reply));
        let mut other = reply.clone();
        other[0] ^= 0xFF;
        assert!(!is_reply_to(&query, &other), "чужой ID — не наш ответ");
        assert!(!is_reply_to(&query, &[0xAB]), "обрезанный пакет");
    }
}
