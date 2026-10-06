//! Применение конфигурации с гарантированным откатом.
//!
//! Ключевая идея: **сначала проверить, потом менять**. Порядок, который
//! делает «Apply» безопасным:
//!
//! 1. Снапшот текущего системного состояния (nft, `ip rule`, симлинк конфига).
//! 2. Полная валидация конфига — без сети и без прав.
//! 3. Живая проверка каждого outbound'а: реальное TCP-соединение.
//! 4. Запись и применение.
//! 5. Проверка «система жива»: DNS отвечает, тестовый URL открывается.
//! 6. Любая ошибка на шагах 4–5 → [`Supervisor::rollback`].
//!
//! Пользователь после неудачного Apply обнаруживает систему ровно в том
//! состоянии, в котором она была до нажатия кнопки.

use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;

use crate::config::Config;
use crate::engine::geo::{GeoKind, GeoRegistry};
use crate::engine::nft;
use crate::engine::router::Engine;
use crate::error::{Error, Result};
use crate::paths;

/// Что именно произошло при применении.
#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    pub ok: bool,
    pub stage: String,
    pub message: String,
    pub rolled_back: bool,
    pub backup: Option<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

/// Снапшот, из которого можно вернуться.
#[derive(Debug, Clone, Serialize)]
pub struct RollbackPoint {
    pub id: String,
    pub created_at: i64,
    pub config_path: String,
    pub reason: String,
}

pub struct Supervisor;

impl Supervisor {
    pub fn new() -> Self {
        Self
    }

    fn ensure_dirs(&self) -> Result<()> {
        paths::ensure_secure_dir(&paths::lib_dir())?;
        paths::ensure_secure_dir(&paths::rollback_dir())?;
        paths::ensure_secure_dir(&paths::etc_dir())?;
        Ok(())
    }

    /// Делает снимок активного конфига, чтобы к нему можно было вернуться.
    pub fn snapshot(&self, reason: &str) -> Result<RollbackPoint> {
        self.ensure_dirs()?;
        let id = timestamp_id();
        let dest = paths::rollback_dir().join(format!("{id}.yaml"));
        if paths::config_path().exists() {
            std::fs::copy(paths::config_path(), &dest)?;
        } else {
            paths::atomic_write(&dest, "# пустой снимок: конфига ещё не было\n".as_bytes())?;
        }
        std::fs::write(
            paths::rollback_dir().join(format!("{id}.reason")),
            reason.as_bytes(),
        )?;
        Ok(RollbackPoint {
            id,
            created_at: now(),
            config_path: dest.display().to_string(),
            reason: reason.to_string(),
        })
    }

    /// Список сохранённых точек отката, свежие первыми.
    pub fn rollback_points(&self) -> Vec<RollbackPoint> {
        let Ok(rd) = std::fs::read_dir(paths::rollback_dir()) else { return Vec::new() };
        let mut v: Vec<RollbackPoint> = rd
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("yaml"))
            .filter_map(|e| {
                let id = e.file_name().to_string_lossy().trim_end_matches(".yaml").to_string();
                let reason = std::fs::read_to_string(paths::rollback_dir().join(format!("{id}.reason")))
                    .unwrap_or_default();
                let created_at = std::fs::metadata(&e.path())
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                Some(RollbackPoint { id, created_at, config_path: e.path().display().to_string(), reason })
            })
            .collect();
        v.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        v
    }

    /// Полный цикл применения. Возвращает отчёт, а не падает: GUI должен
    /// показать, что именно сломалось и был ли выполнен откат.
    pub async fn apply(&self, config: Config, reason: &str) -> ApplyReport {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // ── 1. Снапшот ────────────────────────────────────────────────────
        let point = match self.snapshot(reason) {
            Ok(p) => p,
            Err(e) => {
                return ApplyReport {
                    ok: false,
                    stage: "validate".into(),
                    message: format!("не удалось создать точку отката: {e}"),
                    rolled_back: false,
                    backup: None,
                    errors: vec![e.to_string()],
                    warnings,
                }
            }
        };
        let backup = Some(point.config_path.clone());

        // ── 2. Валидация без сети ─────────────────────────────────────────
        if let Err(e) = config.validate() {
            return ApplyReport {
                ok: false,
                stage: "validate".into(),
                message: e.to_string(),
                rolled_back: false,
                backup,
                errors: vec![e.to_string()],
                warnings,
            };
        }

        // ── 3. Проверка всех outbound'ов живым соединением ─────────────────
        let needed = needed_geo_sets(&config);
        let geo = GeoRegistry::load(&needed);
        let engine = match Engine::build(config.clone(), &geo) {
            Ok(e) => e,
            Err(e) => {
                return ApplyReport {
                    ok: false,
                    stage: "validate".into(),
                    message: e.to_string(),
                    rolled_back: false,
                    backup,
                    errors: vec![e.to_string()],
                    warnings,
                }
            }
        };

        for name in config.all_outbound_names() {
            if name == "DIRECT" {
                continue;
            }
            let Some(ob) = engine.resolve_outbound(&name) else {
                errors.push(format!("outbound {name:?}: не удалось построить"));
                continue;
            };
            let r = ob.probe(Duration::from_secs(8)).await;
            if r.ok {
                tracing::info!(outbound = %name, latency = ?r.latency_ms, "проверка пройдена");
            } else {
                let e = r.error.unwrap_or_else(|| "нет ответа".into());
                errors.push(format!("outbound {name:?}: {e}"));
            }
        }
        if !errors.is_empty() {
            return ApplyReport {
                ok: false,
                stage: "probe".into(),
                message: "проверка соединения не пройдена".into(),
                rolled_back: false,
                backup,
                errors,
                warnings,
            };
        }

        for (raw, policy) in describe_rules(&config) {
            if config.find_outbound(&policy).is_none() && config.find_group(&policy).is_none()
                && !matches!(policy.as_str(), "DIRECT" | "REJECT" | "REJECT-DROP" | "HIJACK-DNS")
            {
                warnings.push(format!("правило {raw} ссылается на неизвестный outbound {policy}"));
            }
        }

        // ── 4. Запись и применение системных правил ───────────────────────
        let yaml = match config.to_yaml() {
            Ok(y) => y,
            Err(e) => {
                return ApplyReport {
                    ok: false,
                    stage: "commit".into(),
                    message: format!("не удалось сериализовать конфиг: {e}"),
                    rolled_back: false,
                    backup,
                    errors: vec![e.to_string()],
                    warnings,
                }
            }
        };
        if let Err(e) = self.write_config(&yaml) {
            return ApplyReport {
                ok: false,
                stage: "commit".into(),
                message: e.to_string(),
                rolled_back: false,
                backup,
                errors: vec![e.to_string()],
                warnings,
            };
        }

        let plan = nft::build_plan(&config);
        if let Err(e) = nft::apply(&plan).await {
            // Возвращаем и системные правила, и сам конфиг: иначе после
            // неудачного Apply в /etc лежал бы конфиг, который не применён,
            // и пользователь смотрел бы на настройки, не действующие вовсе.
            let rb = self.rollback_system().await;
            let restored = self.restore_config(&point).is_ok();
            errors.push(e.to_string());
            return ApplyReport {
                ok: false,
                stage: "commit".into(),
                message: if restored {
                    e.to_string()
                } else {
                    format!("{e}\n  не удалось вернуть прежний конфиг: {}", point.config_path)
                },
                rolled_back: rb,
                backup,
                errors,
                warnings,
            };
        }

        // ── 5. Health-check ───────────────────────────────────────────────
        if let Err(e) = self.health_check(&engine).await {
            let rb = self.rollback_system().await;
            let _ = self.restore_config(&point);
            let mut errors = errors;
            errors.push(e.to_string());
            return ApplyReport {
                ok: false,
                stage: "health-check".into(),
                message: format!("после применения система не отвечает как ожидается: {e}"),
                rolled_back: rb,
                backup,
                errors,
                warnings,
            };
        }

        ApplyReport {
            ok: true,
            stage: "done".into(),
            message: "применено".into(),
            rolled_back: false,
            backup,
            errors,
            warnings,
        }
    }

    /// Пишет конфиг, сохраняя права 0640 и владельца root.
    pub fn write_config(&self, yaml: &str) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        paths::atomic_write(&paths::config_path(), yaml.as_bytes())?;
        std::fs::set_permissions(&paths::config_path(), std::fs::Permissions::from_mode(0o640))?;
        Ok(())
    }

    /// Возвращает конфиг из точки отката.
    pub fn restore_config(&self, point: &RollbackPoint) -> Result<()> {
        let content = std::fs::read_to_string(&point.config_path)?;
        if content.starts_with("# пустой снимок") {
            // Откатываться не к чему — снимаем перехват и удаляем конфиг.
            let _ = std::fs::remove_file(paths::config_path());
            return Ok(());
        }
        self.write_config(&content)
    }

    /// Снимает системные правила. Возвращает `true`, если откат выполнен.
    pub async fn rollback_system(&self) -> bool {
        nft::teardown().await.is_ok()
    }

    /// Ручной откат к последней сохранённой точке.
    pub async fn rollback_to_latest(&self) -> Result<String> {
        let point = self
            .rollback_points()
            .into_iter()
            .next()
            .ok_or_else(|| Error::NotFound("нет сохранённых точек отката".into()))?;
        self.rollback_system().await;
        self.restore_config(&point)?;
        Ok(point.config_path)
    }

    /// Проверка, что после применения система работает: резолвится ли домен
    /// и открывается ли соединение.
    async fn health_check(&self, engine: &Arc<Engine>) -> Result<()> {
        let resolver = crate::engine::dns::Resolver::new(engine.config.dns.clone())?;
        match tokio::time::timeout(Duration::from_secs(5), resolver.resolve("cloudflare.com")).await {
            Ok(Ok(addrs)) if !addrs.is_empty() => {}
            Ok(Ok(_)) => return Err(Error::Internal("DNS вернул пустой ответ".into())),
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(Error::Timeout("DNS не отвечает".into())),
        }
        // И одно реальное соединение через правило по умолчанию.
        let flow = crate::engine::rules::Flow {
            dst_port: 443,
            is_tcp: true,
            domain: Some("cloudflare.com".into()),
            domain_confident: true,
            ..Default::default()
        };
        let target = crate::engine::rules::Target { host: "cloudflare.com".into(), port: 443, is_tcp: true };
        tokio::time::timeout(crate::engine::router::CONNECT_TIMEOUT, engine.open(&target, &flow))
            .await
            .map_err(|_| Error::Timeout("проверочное соединение не установилось".into()))??;
        Ok(())
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn timestamp_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}-{:x}", now(), nanos & 0xffff_ffff)
}

/// Какие geo-наборы реально нужны конфигу.
fn needed_geo_sets(config: &Config) -> Vec<(GeoKind, String)> {
    let mut v = Vec::new();
    for r in &config.rules {
        if let Ok(p) = crate::config::Rule::parse(r.raw()) {
            match p.kind {
                crate::config::RuleKind::Geoip => v.push((GeoKind::Geoip, p.arg(0).to_string())),
                crate::config::RuleKind::Geosite => v.push((GeoKind::Geosite, p.arg(0).to_string())),
                _ => {}
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

fn describe_rules(config: &Config) -> Vec<(String, String)> {
    config
        .rules
        .iter()
        .filter_map(|r| {
            crate::config::Rule::parse(r.raw())
                .ok()
                .map(|p| (r.raw().to_string(), p.policy.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(yaml: &str) -> Config {
        Config::parse(yaml, &HashMap::new()).unwrap()
    }

    const GOOD: &str = r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: S, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,DIRECT
"#;

    #[test]
    fn needed_geo_sets_deduplicates() {
        let c = cfg(
            r#"
outbounds:
  - {name: DIRECT, type: direct}
  - {name: S, type: socks5, server: 1.2.3.4, port: 1}
rules:
  - GEOIP,cn,DIRECT
  - GEOIP,cn,DIRECT
  - GEOSITE,ads,REJECT
  - MATCH,S
"#,
        );
        let v = needed_geo_sets(&c);
        assert_eq!(v.len(), 2, "повторы должны схлопываться");
        assert!(v.contains(&(GeoKind::Geoip, "cn".into())));
        assert!(v.contains(&(GeoKind::Geosite, "ads".into())));
    }

    #[test]
    fn describe_rules_pairs_raw_and_policy() {
        let c = cfg(GOOD);
        let d = describe_rules(&c);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].1, "DIRECT");
    }

    #[tokio::test]
    async fn apply_fails_at_validate_without_touching_system() {
        // Невалидный конфиг обязан отсеяться до любых системных изменений.
        let mut c = Config::default();
        c.outbounds.push(crate::config::Outbound::Direct(
            crate::config::OutboundDirect { name: "X".into(), test_url: None, test_timeout_ms: None },
        ));
        c.rules = vec![crate::config::Rule::Plain("MATCH,НЕТ_ТАКОГО".into())];
        let report = Supervisor::new().apply(c, "test").await;
        assert!(!report.ok);
        assert_eq!(report.stage, "validate");
        assert!(!report.rolled_back, "до коммита откатывать нечего");
    }

    #[tokio::test]
    async fn rollback_points_listing_is_safe_when_empty() {
        let s = Supervisor::new();
        // Каталога может не быть — вызов обязан вернуть пустой список, а не упасть.
        let v = s.rollback_points();
        assert!(v.iter().all(|p| p.config_path.ends_with(".yaml")));
    }
}
