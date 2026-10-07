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
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use crate::config::Config;
use crate::engine::outbound::{self, Outbound, Request, UdpSession};
use crate::engine::rules::{Decision, Flow, RuleSet, Target};
use crate::engine::stats::{Breakdown, Counters};
use crate::error::{Error, Result};

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
}

impl Engine {
    pub fn build(config: Config, geo: &crate::engine::geo::GeoRegistry) -> Result<Arc<Self>> {
        let rules = RuleSet::compile(&config.rules, &config.final_policy, geo)?;

        let mut outbounds = HashMap::new();
        for ob in &config.outbounds {
            outbounds.insert(ob.name().to_string(), outbound::build(ob)?);
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

        let ob = match self.resolve_outbound(&label.clone().unwrap_or_else(|| "DIRECT".into())) {
            Some(o) => o,
            None if label.as_deref() == Some("DIRECT") => {
                return Err(Error::NoOutbound);
            }
            None => {
                return Err(Error::ConfigInvalid(format!(
                    "правило ссылается на {:?}, но такого outbound'а нет",
                    label.unwrap_or_default()
                )))
            }
        };

        // UDP у DIRECT и у прокси без UDP идёт вниз по TCP-протоколу клиента
        // (например, QUIC сам переподключится по TCP). Лучше один
        // переподключившийся запрос, чем молчаливая потеря пакетов.
        let stream = ob
            .connect(&Request {
                target: target.clone(),
            })
            .await?;
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

/// Прогоняет байты между клиентским и проксированным сокетами.
///
/// Возвращает `(вверх, вниз)` — сколько байтов ушло в интернет и сколько
/// пришло обратно.
pub async fn relay<A, B>(
    client: A,
    proxy: B,
    on_bytes: impl Fn(u64, u64) + Copy,
) -> std::io::Result<(u64, u64)>
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (mut cr, mut cw) = tokio::io::split(client);
    let (mut pr, mut pw) = tokio::io::split(proxy);
    let up = tokio::io::copy(&mut cr, &mut pw);
    let down = tokio::io::copy(&mut pr, &mut cw);
    let (u, d) = tokio::join!(up, down);
    // Одна из сторон всегда завершится ошибкой: это нормальный способ
    // закончить relay, когда удалённый узел закрыл соединение.
    let _ = tokio::time::timeout(Duration::from_secs(2), async {
        let _ = cw.shutdown().await;
        let _ = pw.shutdown().await;
    })
    .await;
    let (up_bytes, down_bytes) = (u.unwrap_or(0), d.unwrap_or(0));
    on_bytes(up_bytes, down_bytes);
    Ok((up_bytes, down_bytes))
}

/// Короткий таймаут на установление соединения к прокси. Без него Apply
/// «зависнет» на мёртвом сервере вместо того, чтобы откатиться.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

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

        let (u, d) = relay(relay_client, relay_proxy, |_, _| {}).await.unwrap();
        peer.abort();
        app.abort();
        assert!(u >= 5, "5 байт ушло в прокси, получили {u}");
        assert!(d >= 6, "6 байт пришло обратно, получили {d}");
    }
}
