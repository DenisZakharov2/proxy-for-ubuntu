//! Маршрутизатор: связывает правила, outbound'ы и реальные сокеты.
//!
//! Схема работы одного соединения:
//! 1. Ядро перенаправляет пакеты в сокет демона (REDIRECT/TPROXY).
//! 2. Демон узнаёт настоящего получателя и домен.
//! 3. [`Router::route`] спрашивает rule engine.
//! 4. Полученный outbound открывает соединение.
//! 5. [`relay`] гоняет байты между двумя сторонами, считая трафик.
//!
//! Всё, что может завершиться ошибкой (валидация конфига, создание
//! соединения), происходит до того, как пользователь увидит «подключено».

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::config::Config;
use crate::engine::outbound::{self, Outbound, Request, UdpSession};
use crate::engine::rules::{Decision, Flow, RuleSet, Target};
use crate::engine::stats::{Breakdown, Counters};
use crate::error::{Error, Result};

/// Токен-ведро: ограничивает скорость передачи в байт/сек.
/// `rate == 0` означает «нет лимита» — `acquire` возвращается сразу.
pub struct RateLimiter {
    rate: u64,  // долгосрочная скорость, байт/сек
    burst: u64, // допустимый скачок, байт
    state: std::sync::Mutex<BucketState>,
}

struct BucketState {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate,
            burst,
            state: std::sync::Mutex::new(BucketState {
                tokens: burst as f64,
                last: Instant::now(),
            }),
        }
    }

    /// Ждёт, пока в ведре наберется хотя бы `n` токенов, и забирает их.
    /// Мьютекс не удерживается через `.await`: блокируется только на момент
    /// проверки и списания токенов.
    pub async fn acquire(&self, n: u64) {
        if self.rate == 0 || n == 0 {
            return;
        }
        let n = n as f64;
        loop {
            let wait = {
                let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
                let now = Instant::now();
                g.tokens = (g.tokens + now.duration_since(g.last).as_secs_f64() * self.rate as f64)
                    .min(self.burst as f64);
                g.last = now;
                if g.tokens >= n {
                    g.tokens -= n;
                    return;
                }
                (n - g.tokens) / self.rate as f64
            };
            tokio::time::sleep(Duration::from_secs_f64(wait)).await;
        }
    }
}

/// Настоящие лимиты одного outbound'а, собранные из раздела `limits`
/// конфига при сборке движка (`Engine::build`).
pub struct OutboundLimit {
    pub rate: Option<Arc<RateLimiter>>,
    pub max_connections: Option<u64>,
    /// Сколько соединений к этому outbound'у открыто прямо сейчас.
    pub active: Arc<AtomicU64>,
}

/// Немедленно загруженный движок. Подменяется целиком при перезагрузке
/// конфига, поэтому читается без блокировок — [`RwLock`] только на саму
/// ссылку.
pub struct Engine {
    pub config: Config,
    pub rules: RuleSet,
    pub outbounds: HashMap<String, Arc<dyn Outbound>>,
    /// Состояние групп: для `select` — выбранный вручную, для `url-test` —
    /// победитель по задержке.
    pub group_choice: RwLock<HashMap<String, String>>,
    pub stats: Counters,
    pub breakdown: Breakdown,
    pub cache: RwLock<HashMap<String, (Decision, Option<usize>)>>,
    pub enabled: AtomicBool,

    /// Лимиты скорости и числа соединений на каждый outbound, собранные из
    /// раздела `limits` конфига при сборке движка.
    pub outbound_limits: HashMap<String, Arc<OutboundLimit>>,
}

impl Engine {
    pub fn build(config: Config, geo: &crate::engine::geo::GeoRegistry) -> Result<Arc<Self>> {
        let rules = RuleSet::compile(&config.rules, &config.final_policy, geo)?;

        let mut outbounds = HashMap::new();
        for ob in &config.outbounds {
            outbounds.insert(ob.name().to_string(), outbound::build(ob)?);
        }

        // Лимиты из раздела `limits`: глобальные `rate_limit` /
        // `max_connections`, с переопределением через
        // `limits.outbound.<имя>`. У каждого outbound'а своё ведро — глобальная
        // цифра не делится поровну между всеми прокси автоматически.
        let global_rate = config.limits.rate_limit;
        let global_max = config.limits.max_connections;
        let mut outbound_limits = HashMap::new();
        for ob in &config.outbounds {
            let per = config.limits.outbound.get(ob.name());
            let rate = per.and_then(|l| l.rate_limit).or(global_rate);
            let max = per.and_then(|l| l.max_connections).or(global_max);
            let mut lim = OutboundLimit {
                rate: None,
                max_connections: max,
                active: Arc::new(AtomicU64::new(0)),
            };
            if let Some(rate) = rate.filter(|&r| r > 0) {
                // Разрешаем скачок на одну секунду во всю скорость.
                lim.rate = Some(Arc::new(RateLimiter::new(rate, rate)));
            }
            outbound_limits.insert(ob.name().to_string(), Arc::new(lim));
        }

        let missing = rules.missing_geo();
        if !missing.is_empty() {
            tracing::warn!(
                count = missing.len(),
                rules = ?missing,
                "часть правил не сработает: geo-наборы не скачаны"
            );
        }

        Ok(Arc::new(Self {
            config,
            rules,
            outbounds,
            group_choice: RwLock::new(HashMap::new()),
            stats: Counters::default(),
            breakdown: Breakdown::default(),
            cache: RwLock::new(HashMap::new()),
            enabled: AtomicBool::new(false),
            outbound_limits,
        }))
    }

    /// Ищет outbound с учётом раскрытия групп: правило может указывать на
    /// группу, а не на конкретный прокси.
    pub fn resolve_outbound(&self, name: &str) -> Option<Arc<dyn Outbound>> {
        if let Some(ob) = self.outbounds.get(name) {
            return Some(ob.clone());
        }
        let group = self.config.find_group(name)?;
        // Явный выбор пользователя важнее автоматики.
        if let Some(chosen) = self
            .group_choice
            .read()
            .ok()
            .and_then(|g| g.get(name).cloned())
        {
            if let Some(ob) = self.resolve_outbound(&chosen) {
                return Some(ob);
            }
        }
        // Иначе — первый доступный участник группы.
        for member in &group.outbounds {
            if let Some(ob) = self.resolve_outbound(member) {
                return Some(ob);
            }
        }
        None
    }

    /// Решение по потоку: имя outbound'а либо терминальное действие.
    pub fn route(&self, flow: &Flow) -> (Decision, Option<String>) {
        let decision = {
            let mut cache = self.cache.write().unwrap_or_else(|e| e.into_inner());
            self.rules.decide_cached(flow, &mut cache).0
        };
        let label = match &decision {
            Decision::Proxy(name) => self
                .resolve_outbound(name)
                .map(|o| o.name().to_string())
                .unwrap_or_else(|| "DIRECT".to_string()),
            other => other.label(),
        };
        (decision, Some(label))
    }

    /// Открывает соединение по решению правил. `REJECT` и отсутствие
    /// outbound'а — разные ошибки, и это видно в логе.
    pub async fn open(
        &self,
        target: &Target,
        flow: &Flow,
    ) -> Result<(Arc<dyn Outbound>, Box<dyn outbound::AsyncReadWrite>)> {
        let (decision, label) = self.route(flow);
        match decision {
            Decision::Reject | Decision::RejectDrop => {
                return Err(Error::Reject(format!(
                    "соединение с {} отклонено правилом {}",
                    target.key(),
                    label.unwrap_or_default()
                )));
            }
            Decision::HijackDns => {
                return Err(Error::Internal(
                    "HIJACK-DNS обрабатывается DNS-модулем".into(),
                ));
            }
            Decision::Direct | Decision::Proxy(_) => {}
        }

        let label = label.clone().unwrap_or_else(|| "DIRECT".to_string());
        let ob = match self.resolve_outbound(&label) {
            Some(o) => o,
            None if label == "DIRECT" => return Err(Error::NoOutbound),
            None => {
                return Err(Error::ConfigInvalid(format!(
                    "правило ссылается на {:?}, но такого outbound'а нет",
                    label
                )))
            }
        };

        // Лимит числа соединений: резервируем место перед попыткой соединения
        // и освобождаем при неудаче connect() или когда поток закрывается
        // (MeteredStream::drop).
        if let Some(lim) = self.outbound_limits.get(&label) {
            if let Some(max) = lim.max_connections {
                let taken = lim.active.fetch_add(1, Ordering::Relaxed);
                if taken >= max {
                    lim.active.fetch_sub(1, Ordering::Relaxed);
                    return Err(Error::Limit(format!(
                        "достигнут лимит {max} соединений для outbound {label}"
                    )));
                }
            }
        }

        // UDP у DIRECT и у прокси без UDP идёт вниз по TCP-протоколу клиента
        // (например, QUIC сам переподключится по TCP). Лучше один
        // переподключившийся запрос, чем молчаливая потеря пакетов.
        let stream = ob
            .connect(&Request {
                target: target.clone(),
            })
            .await;
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                if let Some(lim) = self.outbound_limits.get(&label) {
                    lim.active.fetch_sub(1, Ordering::Relaxed);
                }
                return Err(e);
            }
        };
        if let Some(lim) = self.outbound_limits.get(&label) {
            stream = Box::new(MeteredStream::new(stream, Arc::clone(&lim.active)));
        }
        self.stats.conn_opened();
        Ok((ob, stream))
    }

    /// Открывает UDP-канал, если outbound его умеет. `None` — честный
    /// отказ, вызывающий решает, что делать.
    pub async fn open_udp(&self, ob: &Arc<dyn Outbound>) -> Option<Arc<dyn UdpSession>> {
        if !ob.supports_udp() {
            return None;
        }
        ob.open_udp().await.ok()
    }
}

/// Дописать ошибку в тип: REJECT — это не «внутренняя ошибка», а штатное
/// решение правил, и в логе оно должно выглядеть иначе.
impl Engine {
    pub fn is_reject(e: &Error) -> bool {
        matches!(e, Error::Reject(_))
    }
}

/// Прогоняет байты между клиентским и проксированным сокетами с учётом
/// токен-ведра (если задан). Возвращает `(вверх, вниз)` — сколько байтов
/// ушло в интернет и сколько пришло обратно.
pub async fn relay<A, B>(
    client: A,
    proxy: B,
    on_bytes: impl Fn(u64, u64) + Copy,
    limiter: Option<&RateLimiter>,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut pr, mut pw) = tokio::io::split(proxy);
    let up = pump(cr, pw, limiter);
    let down = pump(pr, cw, limiter);
    let (u, d) = tokio::join!(up, down);
    let (up_bytes, down_bytes) = (u.unwrap_or(0), d.unwrap_or(0));
    on_bytes(up_bytes, down_bytes);
    Ok((up_bytes, down_bytes))
}

/// Перекладывает байты из `reader` в `writer`, дозируя скорость токен-ведром.
/// Возвращает число переложенных байт.
async fn pump<R, W>(
    mut reader: R,
    mut writer: W,
    limiter: Option<&RateLimiter>,
) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(total);
        }
        if let Some(lim) = limiter {
            lim.acquire(n as u64).await;
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

/// Поток, который при удалении уменьшает счётчик активных соединений
/// outbound'а, чтобы `max_connections` не терял занятые слоты.
struct MeteredStream<S> {
    inner: S,
    active: Arc<AtomicU64>,
}

impl<S> MeteredStream<S> {
    fn new(inner: S, active: Arc<AtomicU64>) -> Self {
        Self { inner, active }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S> Drop for MeteredStream<S> {
    fn drop(&mut self) {
        let _ = self.active.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Короткий таймаут на установление соединения к прокси. Без него Apply
/// «зависнет» на мёртвом сервере вместо того, чтобы откатиться.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{config::*, Error};

    fn engine(yaml: &str) -> Arc<Engine> {
        let cfg = Config::parse(yaml, &HashMap::new()).unwrap();
        Engine::build(cfg, &crate::engine::geo::GeoRegistry::empty()).unwrap()
    }

    const BASE: &str = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: Локальный, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - DOMAIN,blocked.com,REJECT
  - DOMAIN,proxy.example,Локальный
  - MATCH,DIRECT
"#;

    #[tokio::test]
    async fn routes_by_domain() {
        let e = engine(BASE);
        let f = Flow {
            domain: Some("proxy.example".into()),
            dst_port: 80,
            is_tcp: true,
            ..Default::default()
        };
        let (d, label) = e.route(&f);
        assert!(matches!(d, Decision::Proxy(_)));
        assert_eq!(label.as_deref(), Some("Локальный"));
    }

    #[tokio::test]
    async fn reject_short_circuits_before_connect() {
        let e = engine(BASE);
        let f = Flow {
            domain: Some("blocked.com".into()),
            dst_port: 80,
            is_tcp: true,
            ..Default::default()
        };
        let t = Target {
            host: "blocked.com".into(),
            port: 80,
            is_tcp: true,
        };
        let err = e.open(&t, &f).await.err().expect("ожидалась ошибка");
        assert!(Engine::is_reject(&err), "ожидался REJECT, получен {err}");
    }

    #[tokio::test]
    async fn direct_fallback_works() {
        let e = engine(BASE);
        let f = Flow {
            domain: Some("unknown.net".into()),
            dst_port: 80,
            is_tcp: true,
            ..Default::default()
        };
        let (d, label) = e.route(&f);
        assert_eq!(d, Decision::Direct);
        assert_eq!(label.as_deref(), Some("DIRECT"));
    }

    #[tokio::test]
    async fn group_resolves_to_member() {
        let yaml = format!(
            "{}\ngroups:\n  - name: Авто\n    type: select\n    outbounds: [Локальный, DIRECT]\n",
            BASE.trim_end()
        );
        let e = engine(&yaml);
        let ob = e.resolve_outbound("Авто").unwrap();
        assert_eq!(
            ob.name(),
            "Локальный",
            "первый участник группы по умолчанию"
        );
    }

    #[tokio::test]
    async fn explicit_group_choice_wins() {
        let yaml = format!(
            "{}\ngroups:\n  - name: Авто\n    type: select\n    outbounds: [Локальный, DIRECT]\n",
            BASE.trim_end()
        );
        let e = engine(&yaml);
        e.group_choice
            .write()
            .unwrap()
            .insert("Авто".into(), "DIRECT".into());
        assert_eq!(e.resolve_outbound("Авто").unwrap().name(), "DIRECT");
    }

    #[tokio::test]
    async fn decision_cache_does_not_change_outcome() {
        let e = engine(BASE);
        let f = Flow {
            domain: Some("proxy.example".into()),
            dst_port: 80,
            is_tcp: true,
            ..Default::default()
        };
        let first = e.route(&f);
        for _ in 0..100 {
            assert_eq!(e.route(&f), first);
        }
    }

    #[tokio::test]
    async fn relay_counts_bytes_in_both_directions() {
        use tokio::io::AsyncReadExt;
        // Схема: клиент ↔ relay ↔ «прокси».
        //   duplex1: (client_side, relay_client) — сторона приложения
        //   duplex2: (relay_proxy, proxy_side)  — сторона удалённого узла
        let (client_side, relay_client) = tokio::io::duplex(1024);
        let (relay_proxy, mut proxy_side) = tokio::io::duplex(1024);

        // Удалённый узел читает запрос и отвечает.
        let peer = tokio::spawn(async move {
            let mut buf = [0u8; 5];
            proxy_side.read_exact(&mut buf).await.unwrap();
            assert_eq!(
                &buf, b"hello",
                "relay должен передавать байты без изменений"
            );
            proxy_side.write_all(b"world!").await.unwrap();
            proxy_side.flush().await.ok();
            // Держим сокет открытым, пока relay не завершит подсчёт.
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        });

        // Приложение пишет и читает ответ.
        let app = tokio::spawn(async move {
            let mut c = client_side;
            c.write_all(b"hello").await.unwrap();
            c.flush().await.unwrap();
            let mut sink = [0u8; 6];
            c.read_exact(&mut sink).await.unwrap();
            assert_eq!(&sink, b"world!");
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let (u, d) = relay(relay_client, relay_proxy, |_, _| {}, None)
            .await
            .unwrap();
        peer.abort();
        app.abort();
        assert!(u >= 5, "5 байт ушло в прокси, получили {u}");
        assert!(d >= 6, "6 байт пришло обратно, получили {d}");
    }

    #[tokio::test]
    async fn rate_limiter_passes_burst_immediately() {
        let lim = Arc::new(RateLimiter::new(10_000, 10_000));
        let start = Instant::now();
        lim.acquire(10_000).await;
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "в пределах bursts задержки быть не должно: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn rate_limiter_waits_after_exhausting_burst() {
        let lim = Arc::new(RateLimiter::new(10_000, 10_000));
        lim.acquire(10_000).await; // опустошаем ведро
        let start = Instant::now();
        lim.acquire(10_000).await; // ещё 10 КБ при 10 КБ/сек — около 1 секунды
        assert!(
            start.elapsed() >= Duration::from_millis(700),
            "слишком быстро: {:?}",
            start.elapsed()
        );
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "слишком долго: {:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn rate_limiter_zero_rate_is_unlimited() {
        let lim = Arc::new(RateLimiter::new(0, 0));
        let start = Instant::now();
        lim.acquire(u64::MAX).await;
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "без лимита задержки не должно быть"
        );
    }

    #[tokio::test]
    async fn max_connections_blocks_and_releases() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Две принятые но не закрытые соединения — второй open() не должен
        // дойти до connect(), а упереться в лимит.
        let holder = tokio::spawn(async move {
            let (s1, _) = listener.accept().await.unwrap();
            let (s2, _) = listener.accept().await.unwrap();
            drop((s1, s2));
        });

        let yaml = format!("{}\nlimits:\n  max_connections: 1\n", BASE.trim_end());
        let e = engine(&yaml);
        let target = Target {
            host: addr.ip().to_string(),
            port: addr.port(),
            is_tcp: true,
        };
        let flow = Flow {
            dst_port: addr.port(),
            is_tcp: true,
            ..Default::default()
        };

        let (_, stream) = e.open(&target, &flow).await.expect("первое соединение");
        let err = e
            .open(&target, &flow)
            .await
            .err()
            .expect("второе — ошибка лимита");
        assert!(
            matches!(err, Error::Limit(_)),
            "ожидалась Error::Limit, получена {err}"
        );
        // Освобождаем слот — следующее открытие снова доходит до connect().
        drop(stream);
        let (_, stream) = e.open(&target, &flow).await.expect("снова открыто");
        drop(stream);
        holder.abort();
    }
}
