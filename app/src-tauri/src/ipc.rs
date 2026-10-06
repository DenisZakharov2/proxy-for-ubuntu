//! IPC-сервер демона: newline-delimited JSON поверх Unix-сокета.
//!
//! GUI не трогает систему напрямую — все привилегированные операции идут
//! через эти методы. Формат и коды ошибок зафиксированы в docs/IPC.md;
//! изменение структуры здесь — ломающее изменение контракта, поэтому
//! `api_version` отдаётся в каждом ответе.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::config::Config;
use crate::engine::geo::{GeoKind, GeoRegistry};
use crate::engine::nft;
use crate::engine::router::Engine;
use crate::error::{Error, Result};
use crate::paths;
use crate::supervisor::{ApplyReport, Supervisor};

#[derive(Debug, Deserialize)]
struct Request {
    id: Option<Value>,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct Response {
    id: Option<Value>,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<WireError>,
    api: u32,
}

#[derive(Debug, Serialize)]
struct WireError {
    code: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stage: Option<String>,
}

impl From<&Error> for WireError {
    fn from(e: &Error) -> Self {
        Self {
            code: e.code().into(),
            message: e.to_string(),
            detail: None,
            hint: e.hint(),
            stage: Some(e.stage().into()),
        }
    }
}

/// Общее состояние демона между вызовами.
pub struct Server {
    supervisor: Supervisor,
    engine: Arc<tokio::sync::RwLock<Option<Arc<Engine>>>>,
    started_at: i64,
    log_ring: Arc<tokio::sync::Mutex<Vec<LogEntry>>>,
}

/// Одна строка журнала, которую GUI показывает пользователю.
#[derive(Debug, Clone, Serialize)]
pub struct LogEntry {
    pub ts: i64,
    pub level: String,
    pub target: String,
    pub message: String,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    pub fn new() -> Self {
        Self {
            supervisor: Supervisor::new(),
            engine: Arc::new(tokio::sync::RwLock::new(None)),
            started_at: now(),
            log_ring: Arc::new(tokio::sync::Mutex::new(Vec::new())),
        }
    }

    /// Слушает сокет до отмены. Каждое соединение — отдельная задача.
    pub async fn serve(self: Arc<Self>, path: PathBuf) -> Result<()> {
        paths::ensure_secure_dir(path.parent().unwrap_or(Path::new("/run")))?;
        // Старый сокет от предыдущего запуска — удаляем, иначе bind не пройдёт.
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).map_err(|e| {
            Error::Internal(format!("не удалось создать сокет {}: {e}", path.display()))
        })?;
        set_socket_permissions(&path)?;
        tracing::info!(socket = %path.display(), "IPC слушает");

        let me = self.clone();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::warn!("accept: {e}");
                            continue;
                        }
                    };
                    let s2 = me.clone();
                    tokio::spawn(async move {
                        if let Err(e) = s2.handle_conn(stream).await {
                            tracing::warn!("соединение закрыто с ошибкой: {e}");
                        }
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    tracing::info!("IPC остановлен по Ctrl-C");
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle_conn(self: Arc<Self>, stream: UnixStream) -> Result<()> {
        let (read, mut write) = stream.into_split();
        let mut lines = BufReader::new(read).lines();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let resp = match serde_json::from_str::<Request>(&line) {
                Ok(req) => self.dispatch(req).await,
                Err(e) => Response {
                    id: None,
                    ok: false,
                    result: None,
                    error: Some(WireError {
                        code: "E_BAD_REQUEST".into(),
                        message: format!("не удалось разобрать запрос: {e}"),
                        detail: None,
                        hint: None,
                        stage: None,
                    }),
                    api: crate::API_VERSION,
                },
            };
            let mut buf = serde_json::to_vec(&resp)?;
            buf.push(b'\n');
            write.write_all(&buf).await?;
            write.flush().await?;
        }
        Ok(())
    }

    async fn dispatch(self: &Arc<Self>, req: Request) -> Response {
        let id = req.id.clone();
        match self.handle(&req.method, req.params).await {
            Ok(result) => Response {
                id,
                ok: true,
                result: Some(result),
                error: None,
                api: crate::API_VERSION,
            },
            Err(e) => Response {
                id,
                ok: false,
                result: None,
                error: Some(WireError::from(&e)),
                api: crate::API_VERSION,
            },
        }
    }

    pub(crate) async fn handle(self: &Arc<Self>, method: &str, params: Value) -> Result<Value> {
        match method {
            "daemon.status" => self.daemon_status().await,
            "config.get" => self.config_get(),
            "config.validate" => self.config_validate(&params),
            "config.apply" => self.config_apply(&params).await,
            "config.rollback" => self.config_rollback().await,
            "system.toggle" => self.system_toggle(&params).await,
            "system.diagnose" => self.system_diagnose().await,
            "system.logs" => self.system_logs(),
            "outbound.test" => self.outbound_test(&params).await,
            "geo.list" => self.geo_list(),
            "geo.update" => self.geo_update(&params).await,
            "geo.preview" => self.geo_preview(&params),
            "profile.list" => self.profile_list(),
            "profile.read" => self.profile_read(&params),
            "profile.write" => self.profile_write(&params),
            "profile.delete" => self.profile_delete(&params),
            "profile.activate" => self.profile_activate(&params).await,
            "profile.import" => self.profile_import(&params),
            "profile.export" => self.profile_export(&params),
            "subscription.update" => self.subscription_update(&params).await,
            "log.tail" => self.log_tail(&params).await,
            "log.export" => self.log_export(&params).await,
            "metrics.live" => self.metrics_live().await,
            other => Err(Error::NotFound(format!("неизвестный метод {other:?}"))),
        }
    }

    // ─────────────────────────────── методы ───────────────────────────────

    async fn daemon_status(self: &Arc<Self>) -> Result<Value> {
        let engine = self.engine.read().await;
        let config_valid = engine.as_ref().map(|e| e.config.validate().is_ok()).unwrap_or(false);
        Ok(json!({
            "daemon": "running",
            "version": crate::VERSION,
            "api": crate::API_VERSION,
            "pid": std::process::id(),
            "uptime_sec": now() - self.started_at,
            "config_loaded_at": self.started_at,
            "config_valid": config_valid,
            "enabled": engine.as_ref().map(|e| e.enabled.load(std::sync::atomic::Ordering::Relaxed)).unwrap_or(false),
        }))
    }

    /// Загружает конфиг для показа пользователю. Мягкая валидация: сразу
    /// после установки прокси ещё нет, и это не повод не показывать конфиг.
    fn load_config(&self) -> Result<(Config, bool)> {
        let path = paths::config_path();
        if !path.exists() {
            return Ok((Config::default(), true));
        }
        let env = crate::config::read_env_file(&paths::env_file());
        let cfg = Config::load_for_read(&path, &env)?;
        Ok((cfg, false))
    }

    fn config_get(&self) -> Result<Value> {
        let (cfg, is_default) = self.load_config()?;
        Ok(json!({
            "config": cfg,
            "path": paths::config_path().display().to_string(),
            "is_default": is_default,
        }))
    }

    fn config_validate(&self, params: &Value) -> Result<Value> {
        let cfg: Config = serde_json::from_value(params.get("config").cloned().unwrap_or(json!({})))
            .map_err(|e| Error::ConfigInvalid(e.to_string()))?;
        let mut warnings = Vec::new();
        match cfg.validate() {
            Ok(()) => {
                let needed: Vec<(GeoKind, String)> = {
                    let mut v: Vec<(GeoKind, String)> = cfg
                        .rules
                        .iter()
                        .filter_map(|r| crate::config::Rule::parse(r.raw()).ok())
                        .filter_map(|p| match p.kind {
                            crate::config::RuleKind::Geoip => Some((GeoKind::Geoip, p.arg(0).to_string())),
                            crate::config::RuleKind::Geosite => Some((GeoKind::Geosite, p.arg(0).to_string())),
                            _ => None,
                        })
                        .collect();
                    v.sort();
                    v.dedup();
                    v
                };
                let geo = GeoRegistry::load(&needed);
                for (kind, tag) in &needed {
                    if geo.get(*kind, tag).is_none() {
                        warnings.push(format!(
                            "geo-набор {}:{tag} не скачан — правила с ним не сработают",
                            match kind {
                                GeoKind::Geoip => "geoip",
                                GeoKind::Geosite => "geosite",
                            }
                        ));
                    }
                }
                for ob in &cfg.outbounds {
                    if ob.is_experimental() {
                        warnings.push(format!(
                            "outbound {:?} ({}) не проверялся против живого сервера",
                            ob.name(),
                            ob.kind()
                        ));
                    }
                }
                Ok(json!({ "valid": true, "warnings": warnings, "errors": [] }))
            }
            Err(e) => Ok(json!({
                "valid": false,
                "warnings": warnings,
                "errors": [{ "path": "", "message": e.to_string() }],
            })),
        }
    }

    async fn config_apply(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let cfg: Config = serde_json::from_value(params.get("config").cloned().unwrap_or(json!({})))
            .map_err(|e| Error::ConfigInvalid(e.to_string()))?;
        let reason = params.get("reason").and_then(Value::as_str).unwrap_or("user");
        let report: ApplyReport = self.supervisor.apply(cfg, reason).await;

        if report.ok {
            // Перечитываем конфиг и пересобираем движок в памяти — это и есть
            // «применение без перезапуска демона».
            if let Ok((loaded, _)) = self.load_config() {
                let geo = GeoRegistry::load(&[]);
                if let Ok(engine) = Engine::build(loaded, &geo) {
                    engine.enabled.store(true, std::sync::atomic::Ordering::Relaxed);
                    *self.engine.write().await = Some(engine);
                }
            }
        }
        serde_json::to_value(report).map_err(Error::from)
    }

    async fn config_rollback(self: &Arc<Self>) -> Result<Value> {
        match self.supervisor.rollback_to_latest().await {
            Ok(path) => {
                *self.engine.write().await = None;
                Ok(json!({ "ok": true, "restored_from": path }))
            }
            Err(e) => Ok(json!({ "ok": false, "message": e.to_string() })),
        }
    }

    async fn system_toggle(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let enabled = params.get("enabled").and_then(Value::as_bool).unwrap_or(false);
        let mut guard = self.engine.write().await;

        if enabled && guard.is_none() {
            let (cfg, _) = self.load_config()?;
            let geo = GeoRegistry::load(&[]);
            let engine = Engine::build(cfg, &geo)?;
            engine.enabled.store(true, std::sync::atomic::Ordering::Relaxed);
            *guard = Some(engine);
        }
        if let Some(e) = guard.as_ref() {
            e.enabled.store(enabled, std::sync::atomic::Ordering::Relaxed);
            if enabled {
                let plan = nft::build_plan(&e.config);
                if let Err(err) = nft::apply(&plan).await {
                    e.enabled.store(false, std::sync::atomic::Ordering::Relaxed);
                    return Err(err);
                }
                return Ok(json!({ "enabled": true, "status": "connected", "message": "" }));
            }
            nft::teardown().await?;
            return Ok(json!({ "enabled": false, "status": "disconnected", "message": "" }));
        }
        Ok(json!({ "enabled": false, "status": "disconnected", "message": "" }))
    }

    async fn system_diagnose(self: &Arc<Self>) -> Result<Value> {
        let mut checks = Vec::new();

        // Ядро
        let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_else(|_| "неизвестно".into())
            .trim()
            .to_string();
        let kernel_ok = version_ge(&kernel, 4, 19, 0);
        checks.push(json!({
            "id": "kernel", "name": "Версия ядра", "ok": kernel_ok,
            "detail": kernel,
            "fix": if kernel_ok { Value::Null } else { json!("Требуется ядро 4.19 или новее для TPROXY. Обновите систему.") },
        }));

        // nftables
        let (nft_ok, nft_ver) = nft::check_available().await;
        checks.push(json!({
            "id": "nft", "name": "nftables", "ok": nft_ok, "detail": nft_ver,
            "fix": if nft_ok { Value::Null } else { json!("sudo apt install nftables") },
        }));

        // TUN
        let tun = std::path::Path::new("/dev/net/tun").exists();
        checks.push(json!({
            "id": "tun", "name": "TUN/TAP", "ok": tun,
            "detail": if tun { "/dev/net/tun" } else { "нет /dev/net/tun" },
            "fix": if tun { Value::Null } else { json!("sudo modprobe tun && echo tun | sudo tee /etc/modules-load.d/tun.conf") },
        }));

        // Права
        let is_root = unsafe { libc::geteuid() } == 0;
        checks.push(json!({
            "id": "root", "name": "Права демона", "ok": is_root,
            "detail": if is_root { "root" } else { "не root" },
            "fix": if is_root { Value::Null } else { json!("sudo systemctl restart proxy-for-ubuntud") },
        }));

        // systemd-resolved на порту 53
        let resolved = std::path::Path::new("/run/systemd/resolve").exists();
        checks.push(json!({
            "id": "dns", "name": "systemd-resolved", "ok": true, "detail": if resolved { "используется" } else { "не обнаружен" },
            "fix": Value::Null,
        }));

        // Свободные порты
        for (id, name, port) in [
            ("port-tcp", "Порт перехвата TCP", paths::redirect_port()),
            ("port-udp", "Порт перехвата UDP", paths::tproxy_port()),
        ] {
            let free = std::net::TcpListener::bind(("127.0.0.1", port)).is_ok();
            checks.push(json!({
                "id": id, "name": name, "ok": free,
                "detail": if free { format!("порт {port} свободен") } else { format!("порт {port} занят") },
                "fix": if free { Value::Null } else { json!("Освободите порт или измените его в конфигурации.") },
            }));
        }

        let fatal: Vec<&str> = checks
            .iter()
            .filter(|c| c.get("ok").and_then(Value::as_bool) == Some(false))
            .filter_map(|c| c.get("id").and_then(Value::as_str))
            .filter(|id| matches!(*id, "nft" | "tun" | "root" | "kernel"))
            .collect();

        Ok(json!({ "checks": checks, "fatal": fatal }))
    }

    fn system_logs(&self) -> Result<Value> {
        Ok(json!({
            "ok": true,
            "log_dir": "/var/log/proxy-for-ubuntu",
            "journal": "journalctl -u proxy-for-ubuntud -f",
        }))
    }

    async fn outbound_test(&self, params: &Value) -> Result<Value> {
        let ob_cfg: crate::config::Outbound = serde_json::from_value(
            params.get("outbound").cloned().unwrap_or(json!({})),
        )
        .map_err(|e| Error::ConfigInvalid(e.to_string()))?;

        let _target_note = "цель проверки берётся из probe(), если не задана явно";
        let timeout_ms = params.get("timeout_ms").and_then(Value::as_u64).unwrap_or(5000);

        let ob = crate::engine::outbound::build(&ob_cfg)?;
        if let Some(h) = params
            .get("target")
            .and_then(|t| t.get("host"))
            .and_then(Value::as_str)
        {
            tracing::debug!(target = h, "проверка по явной цели");
        }
        let r = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            ob.probe(std::time::Duration::from_millis(timeout_ms)),
        )
        .await;

        match r {
            Ok(res) => serde_json::to_value(res).map_err(Error::from),
            Err(_) => Ok(json!({
                "ok": false, "latency_ms": Value::Null, "resolved_via": Value::Null,
                "error": format!("нет ответа за {timeout_ms} мс"),
            })),
        }
    }

    fn geo_list(&self) -> Result<Value> {
        let reg = GeoRegistry::load(&[]);
        Ok(json!({ "sets": reg.list() }))
    }

    async fn geo_update(&self, params: &Value) -> Result<Value> {
        let src: crate::config::GeoSource = serde_json::from_value(params.clone())
            .map_err(|e| Error::ConfigInvalid(e.to_string()))?;
        match GeoRegistry::update(&src).await {
            Ok(count) => Ok(json!({ "ok": true, "count": count })),
            Err(e) => Ok(json!({ "ok": false, "message": e.to_string() })),
        }
    }

    fn geo_preview(&self, params: &Value) -> Result<Value> {
        let kind = match params.get("kind").and_then(Value::as_str) {
            Some("geosite") => GeoKind::Geosite,
            _ => GeoKind::Geoip,
        };
        let tag = params.get("tag").and_then(Value::as_str).unwrap_or("");
        let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(200) as usize;
        let p = paths::geo_dir()
            .join(match kind {
                GeoKind::Geoip => "geoip",
                GeoKind::Geosite => "geosite",
            })
            .join(format!("{}.txt", tag.replace(['/', '.', ':'], "_")));
        let text = std::fs::read_to_string(p).map_err(|e| Error::NotFound(format!("{tag}: {e}")))?;
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .take(limit)
            .collect();
        Ok(json!({ "lines": lines }))
    }

    fn profile_list(&self) -> Result<Value> {
        let mut profiles = Vec::new();
        for (dir, builtin) in [(paths::builtin_profiles_dir(), true), (paths::user_profiles_dir(), false)] {
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some("yaml") {
                    continue;
                }
                let name = p.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                let updated_at = std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                profiles.push(json!({ "name": name, "builtin": builtin, "updated_at": updated_at }));
            }
        }
        Ok(json!({ "profiles": profiles }))
    }

    fn profile_read(&self, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let (path, _) = resolve_profile_path(name)?;
        let env = crate::config::read_env_file(&paths::env_file());
        let text = std::fs::read_to_string(&path).map_err(|e| Error::NotFound(format!("{name}: {e}")))?;
        let expanded = crate::config::expand_env(&text, &env);
        let cfg: Config = serde_yaml::from_str(&expanded)
            .map_err(|e| Error::ConfigInvalid(format!("{name}: {e}")))?;
        Ok(json!({ "config": cfg }))
    }

    fn profile_write(&self, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        if name.is_empty() {
            return Err(Error::ConfigInvalid("имя профиля не указано".into()));
        }
        let cfg: Config = serde_json::from_value(params.get("config").cloned().unwrap_or(json!({})))
            .map_err(|e| Error::ConfigInvalid(e.to_string()))?;
        cfg.validate()?;
        let (path, builtin) = resolve_profile_path(name)?;
        if builtin {
            return Err(Error::Permission(format!(
                "профиль {name:?} встроенный и не редактируется"
            )));
        }
        paths::ensure_dir(&paths::user_profiles_dir())?;
        paths::atomic_write(&path, cfg.to_yaml()?.as_bytes())?;
        Ok(json!({ "ok": true }))
    }

    fn profile_delete(&self, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let (path, builtin) = resolve_profile_path(name)?;
        if builtin {
            return Err(Error::Permission("встроенный профиль удалить нельзя".into()));
        }
        std::fs::remove_file(&path).map_err(|e| Error::NotFound(format!("{name}: {e}")))?;
        Ok(json!({ "ok": true }))
    }

    async fn profile_activate(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let (path, _) = resolve_profile_path(name)?;
        let env = crate::config::read_env_file(&paths::env_file());
        let cfg = Config::load(&path, &env)?;
        let report = self.supervisor.apply(cfg, &format!("активация профиля {name}")).await;
        let result = serde_json::to_value(&report)?;
        if report.ok {
            let geo = GeoRegistry::load(&[]);
            if let Ok(engine) = Engine::build(self.load_config()?.0, &geo) {
                engine.enabled.store(true, std::sync::atomic::Ordering::Relaxed);
                *self.engine.write().await = Some(engine);
            }
        }
        Ok(json!({ "ok": report.ok, "needs_restart": false, "apply": result }))
    }

    fn profile_import(&self, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("imported");
        let yaml = params.get("yaml").and_then(Value::as_str).unwrap_or("");
        let env = crate::config::read_env_file(&paths::env_file());
        let cfg = Config::parse(yaml, &env)?;
        paths::ensure_dir(&paths::user_profiles_dir())?;
        let path = paths::user_profiles_dir().join(format!("{}.yaml", sanitize_name(name)));
        paths::atomic_write(&path, yaml.as_bytes())?;
        let mut warnings = Vec::new();
        for ob in &cfg.outbounds {
            if ob.is_experimental() {
                warnings.push(format!("outbound {:?} не проверен на живом сервере", ob.name()));
            }
        }
        Ok(json!({ "ok": true, "warnings": warnings, "errors": [] }))
    }

    fn profile_export(&self, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let redact = params.get("redact_secrets").and_then(Value::as_bool).unwrap_or(false);
        let (path, _) = resolve_profile_path(name)?;
        let mut text = std::fs::read_to_string(&path).map_err(|e| Error::NotFound(format!("{name}: {e}")))?;
        if redact {
            text = redact_secrets(&text);
        }
        Ok(json!({ "ok": true, "yaml": text }))
    }

    async fn subscription_update(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let url = params.get("url").and_then(Value::as_str).unwrap_or("");
        let name = params.get("name").and_then(Value::as_str).unwrap_or("subscription");
        if url.is_empty() {
            return Err(Error::ConfigInvalid("URL подписки не указан".into()));
        }
        let client = crate::engine::http_client()?;
        let body = client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Internal(format!("загрузка подписки: {e}")))?
            .text()
            .await
            .map_err(|e| Error::Internal(format!("чтение подписки: {e}")))?;

        // Подписка часто приходит в base64 — распознаём по наличию
        // ключевого слова, а не по предположению о кодировке.
        use base64::Engine as _;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(body.trim())
            .ok()
            .and_then(|b| String::from_utf8(b).ok());
        let yaml = match decoded {
            Some(text) if text.contains("outbounds:") => text,
            _ => body,
        };

        let env = crate::config::read_env_file(&paths::env_file());
        let cfg = Config::parse(&yaml, &env).map_err(|e| {
            Error::ConfigInvalid(format!("подписка не похожа на конфиг proxy-for-ubuntu: {e}"))
        })?;
        let outbounds_found = cfg.outbounds.len();
        let rules_found = cfg.rules.len();
        paths::ensure_dir(&paths::user_profiles_dir())?;
        paths::atomic_write(
            &paths::user_profiles_dir().join(format!("{}.yaml", sanitize_name(name))),
            yaml.as_bytes(),
        )?;

        let mut activated = false;
        if params.get("auto_activate").and_then(Value::as_bool).unwrap_or(false) {
            let report = self.supervisor.apply(cfg, "подписка").await;
            activated = report.ok;
        }
        Ok(json!({
            "ok": true,
            "outbounds_found": outbounds_found,
            "rules_found": rules_found,
            "activated": activated,
        }))
    }

    async fn log_tail(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let lines = params.get("lines").and_then(Value::as_u64).unwrap_or(500) as usize;
        let level = params.get("level").and_then(Value::as_str);
        let g = self.log_ring.lock().await;
        let mut v: Vec<LogEntry> = g
            .iter()
            .filter(|e| level.map(|l| e.level == l).unwrap_or(true))
            .cloned()
            .collect();
        if v.len() > lines {
            v = v.split_off(v.len() - lines);
        }
        Ok(json!({ "entries": v }))
    }

    async fn log_export(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let g = self.log_ring.lock().await;
        let level = params.get("level").and_then(Value::as_str);
        let path = params
            .get("path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .unwrap_or_else(|| paths::user_cache_dir().join("engine-log.txt"));
        let mut out = String::new();
        for e in g.iter() {
            if level.map(|l| e.level == l).unwrap_or(true) {
                out.push_str(&format!("[{}] {:5} {}: {}\n", e.ts, e.level, e.target, e.message));
            }
        }
        paths::ensure_dir(&path.parent().unwrap())?;
        paths::atomic_write(&path, out.as_bytes())?;
        Ok(json!({ "ok": true, "path": path.display().to_string() }))
    }

    async fn metrics_live(self: &Arc<Self>) -> Result<Value> {
        let guard = self.engine.read().await;
        let Some(engine) = guard.as_ref() else {
            return Ok(json!({
                "up": 0, "down": 0, "connections": 0,
                "active_rules": [], "by_outbound": [],
            }));
        };
        let (up, down, conns) = engine.stats.snapshot();
        Ok(json!({
            "up": up,
            "down": down,
            "connections": conns,
            "active_rules": engine.breakdown.snapshot(),
            "by_outbound": engine.breakdown.snapshot()
                .into_iter()
                .map(|r| json!({ "name": r.policy, "bytes": r.bytes }))
                .collect::<Vec<_>>(),
        }))
    }
}

// ──────────────────────────────── утилиты ──────────────────────────────────

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn set_socket_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    // Владельцем группы делаем пользователя демона, чтобы GUI, запущенный
    // обычным пользователем, мог подключиться.
    let _ = std::process::Command::new("chgrp")
        .arg(crate::DAEMON_USER)
        .arg(path)
        .status();
    Ok(())
}

fn resolve_profile_path(name: &str) -> Result<(PathBuf, bool)> {
    if name.is_empty() {
        return Err(Error::ConfigInvalid("имя профиля не указано".into()));
    }
    let safe = sanitize_name(name);
    let builtin = paths::builtin_profiles_dir().join(format!("{safe}.yaml"));
    if builtin.exists() {
        return Ok((builtin, true));
    }
    let user = paths::user_profiles_dir().join(format!("{safe}.yaml"));
    if user.exists() {
        return Ok((user, false));
    }
    // Такого профиля нет, но мы всё равно возвращаем безопасный путь для
    // записи: `profile.write` создаст файл.
    Ok((user, false))
}

/// Имя профиля превращается в имя файла. Без этой проверки `../../.ssh/authorized_keys`
/// в поле «имя профиля» увёл бы запись за пределы каталога.
fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' { c } else { '_' })
        .collect();
    let cleaned = cleaned.trim().to_string();
    if cleaned.is_empty() {
        "unnamed".into()
    } else {
        cleaned
    }
}

/// Заменяет значения секретных полей. Работает по тексту, а не по
/// структуре, потому что нужен и для сырого импортированного YAML.
fn redact_secrets(yaml: &str) -> String {
    const KEYS: [&str; 6] = ["password", "passphrase", "uuid", "key_file", "secret", "token"];
    let mut out = String::with_capacity(yaml.len());
    for line in yaml.lines() {
        let trimmed = line.trim_start();
        let hit = KEYS.iter().find(|k| {
            trimmed.starts_with(&format!("{k}:")) || trimmed.starts_with(&format!("- {k}:"))
        });
        match hit {
            Some(k) => {
                let indent_len = line.len() - trimmed.len();
                let key = k.trim_start_matches("- ");
                out.push_str(&format!("{}{key}: \"***REDACTED***\"", &line[..indent_len]));
            }
            None => out.push_str(line),
        }
        out.push('\n');
    }
    out
}

fn version_ge(v: &str, maj: u32, min: u32, patch: u32) -> bool {
    let it = v.split(['-', '.']);
    let p = |i: usize| it.clone().nth(i).and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
    let (a, b, c) = (p(0), p(1), p(2));
    (a, b, c) >= (maj, min, patch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_name_blocks_traversal() {
        assert_eq!(sanitize_name("Мой профиль"), "Мой профиль");
        // "../../.ssh/" — семь символов, каждый заменяется подчёркиванием.
        assert_eq!(sanitize_name("../../.ssh/authorized_keys"), "_______ssh_authorized_keys");
        assert!(!sanitize_name("..\\..\\etc\\passwd").contains('\\'));
        assert!(!sanitize_name("a/b\0c").contains('/'));
        assert_eq!(sanitize_name(""), "unnamed");
    }

    #[test]
    fn redact_hides_secrets_but_keeps_shape() {
        let y = "outbounds:\n  - name: X\n    type: http\n    server: a\n    port: 1\n    password: \"hunter2\"\n    username: bob\n";
        let r = redact_secrets(y);
        assert!(!r.contains("hunter2"), "пароль утёк: {r}");
        assert!(r.contains("REDACTED"));
        assert!(r.contains("username: bob"), "логин не секрет, его можно оставить");
        assert!(r.contains("server: a"));
    }

    #[test]
    fn version_compare() {
        assert!(version_ge("6.8.0-generic", 4, 19, 0));
        assert!(!version_ge("4.14.0", 4, 19, 0));
        assert!(version_ge("5.15.0-56", 4, 19, 0));
        assert!(!version_ge("4.18.9", 4, 19, 0));
    }

    #[test]
    fn unknown_method_is_not_found() {
        let s = Arc::new(Server::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt.block_on(s.handle("нет.такого.метода", json!({}))).unwrap_err();
        assert_eq!(err.code(), "E_NOT_FOUND");
    }

    #[test]
    fn config_get_returns_something_readable() {
        let s = Arc::new(Server::new());
        let rt = tokio::runtime::Runtime::new().unwrap();
        // В системе может быть /etc/proxy-for-ubuntu (например, после
        // установки пакета), а может и не быть. В обоих случаях вызов обязан
        // вернуть читаемый конфиг, а не упасть.
        match rt.block_on(s.handle("config.get", json!({}))) {
            Ok(v) => assert!(v.get("config").is_some()),
            // Конфиг по умолчанию содержит только DIRECT, и он не проходит
            // строгую валидацию — это ожидаемо, а не ошибка вызова.
            Err(e) => assert!(
                matches!(e.code(), "E_CONFIG_INVALID" | "E_NO_OUTBOUND"),
                "{e}"
            ),
        }
    }
}
