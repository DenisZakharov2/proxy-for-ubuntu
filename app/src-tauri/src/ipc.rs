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
use crate::engine::capture;
use crate::engine::geo::{GeoKind, GeoRegistry};
use crate::engine::nft;
use crate::engine::router::Engine;
use crate::error::{Error, Result};
use crate::paths;
use crate::supervisor::{ApplyReport, Supervisor};

// age-шифрование для защищённого экспорта профилей.
use age::secrecy::SecretString;
use age::Encryptor;
use std::io::Write;

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
    /// Слушатели перехвата. Живут, пока включён перехват: при выключении
    /// порты закрываются, иначе трафик уходил бы в никуда.
    capture: tokio::sync::Mutex<Option<capture::Capture>>,
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
            capture: tokio::sync::Mutex::new(None),
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

        // Планировщик обновления подписок (`REQ-005`). Живёт столько же,
        // сколько сервер: отдельного места запуска в демоне не требуется.
        let scheduler = self.clone();
        tokio::spawn(async move { scheduler.subscription_loop().await });

        let me = self.clone();
        let mut last_log: Option<std::time::Instant> = None;
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, _) = match accepted {
                        Ok(v) => v,
                        Err(e) => {
                            // Та же история, что и в перехвате: при EMFILE
                            // accept ошибается постоянно, а warn на каждом
                            // витке превращает журнал в мусор.
                            let now = std::time::Instant::now();
                            let should_log = match last_log {
                                Some(t) => now.duration_since(t) >= std::time::Duration::from_secs(1),
                                None => true,
                            };
                            if should_log {
                                tracing::warn!("accept: {e}");
                                last_log = Some(now);
                            }
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
            "profile.import_uri" => self.profile_import_uri(&params),
            "profile.import_links" => self.profile_import_links(&params),
            "subscription.update" => self.subscription_update(&params).await,
            "subscription.preview" => self.subscription_preview(&params).await,
            "subscription.apply" => self.subscription_apply(&params, true).await,
            "subscription.list" => self.subscription_list(),
            "subscription.refresh" => self.subscription_refresh(&params).await,
            "subscription.remove" => self.subscription_remove(&params),
            "log.tail" => self.log_tail(&params).await,
            "log.search" => self.log_search(&params).await,
            "log.export" => self.log_export(&params).await,
            "metrics.live" => self.metrics_live().await,
            other => Err(Error::NotFound(format!("неизвестный метод {other:?}"))),
        }
    }

    // ─────────────────────────────── методы ───────────────────────────────

    async fn daemon_status(self: &Arc<Self>) -> Result<Value> {
        let engine = self.engine.read().await;
        let engine_loaded = engine.is_some();
        let config_valid = engine
            .as_ref()
            .map(|e| e.config.validate().is_ok())
            .unwrap_or(false);
        Ok(json!({
            "daemon": "running",
            "version": crate::VERSION,
            "api": crate::API_VERSION,
            "pid": std::process::id(),
            "uptime_sec": now() - self.started_at,
            "config_loaded_at": self.started_at,
            // `config_valid` без загруженного движка всегда false — это не
            // «битый конфиг», поэтому рядом едет отдельный признак.
            "engine_loaded": engine_loaded,
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
        let cfg: Config =
            serde_json::from_value(params.get("config").cloned().unwrap_or(json!({})))
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
                            crate::config::RuleKind::Geoip => {
                                Some((GeoKind::Geoip, p.arg(0).to_string()))
                            }
                            crate::config::RuleKind::Geosite => {
                                Some((GeoKind::Geosite, p.arg(0).to_string()))
                            }
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
        let cfg: Config =
            serde_json::from_value(params.get("config").cloned().unwrap_or(json!({})))
                .map_err(|e| Error::ConfigInvalid(e.to_string()))?;
        let reason = params
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("user");
        let report: ApplyReport = self.supervisor.apply(cfg, reason).await;

        if report.ok {
            // Перечитываем конфиг и пересобираем движок в памяти — это и есть
            // «применение без перезапуска демона».
            if let Ok((loaded, _)) = self.load_config() {
                let geo = GeoRegistry::load(&[]);
                if let Ok(engine) = Engine::build(loaded, &geo) {
                    engine
                        .enabled
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    *self.engine.write().await = Some(engine);
                    self.sync_capture().await;
                }
            }
        }
        serde_json::to_value(report).map_err(Error::from)
    }

    /// Перечитать конфиг с диска и применить транзакционно (как
    /// `config.apply`), но по сигналу — вызвается по SIGHUP
    /// (`systemctl reload`). Состояние демона (TUN, nftables, текущие
    /// соединения) сохраняется: меняется только активная конфигурация.
    pub async fn reload_config(&self) -> Result<ApplyReport> {
        let (cfg, _) = self.load_config()?;
        let report = self.supervisor.apply(cfg, "reload").await;
        if report.ok {
            // Перечитываем конфиг и пересобираем движок в памяти — так же,
            // как в `config.apply`, чтобы новые настройки вступили сразу.
            if let Ok((loaded, _)) = self.load_config() {
                let geo = GeoRegistry::load(&[]);
                if let Ok(engine) = Engine::build(loaded, &geo) {
                    engine
                        .enabled
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    *self.engine.write().await = Some(engine);
                    self.sync_capture().await;
                }
            }
        }
        Ok(report)
    }

    /// Переподнимает слушатели под текущий движок: после нового конфига
    /// старые задачи держали бы старые правила.
    async fn sync_capture(&self) {
        let engine = self.engine.read().await.clone();
        let mut guard = self.capture.lock().await;
        if let Some(mut old) = guard.take() {
            // Дожидаемся закрытия сокетов: иначе повторный bind на те же порты
            // может упасть с «address already in use».
            old.stop().await;
        }
        let Some(engine) = engine.filter(|e| e.enabled.load(std::sync::atomic::Ordering::Relaxed))
        else {
            return;
        };
        match capture::start(engine.clone()).await {
            Ok(c) => *guard = Some(c),
            Err(e) => {
                // Без слушателей правила увели бы трафик в закрытые порты.
                tracing::error!(error = %e, "не удалось переподнять перехват — выключаю");
                engine
                    .enabled
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                if let Err(t) = nft::teardown().await {
                    tracing::error!(error = %t, "не удалось снять правила после сбоя перехвата");
                }
            }
        }
    }

    async fn config_rollback(self: &Arc<Self>) -> Result<Value> {
        match self.supervisor.rollback_to_latest().await {
            Ok(path) => {
                *self.engine.write().await = None;
                if let Some(mut c) = self.capture.lock().await.take() {
                    c.stop().await;
                }
                Ok(json!({ "ok": true, "restored_from": path }))
            }
            Err(e) => Ok(json!({ "ok": false, "message": e.to_string() })),
        }
    }

    async fn system_toggle(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let enabled = params
            .get("enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        tracing::info!(enabled, "system.toggle: переключение перехвата");
        let mut guard = self.engine.write().await;

        if enabled && guard.is_none() {
            let (cfg, _) = self.load_config()?;
            let geo = GeoRegistry::load(&[]);
            let engine = Engine::build(cfg, &geo)?;
            engine
                .enabled
                .store(true, std::sync::atomic::Ordering::Relaxed);
            *guard = Some(engine);
        }
        if let Some(e) = guard.as_ref() {
            e.enabled
                .store(enabled, std::sync::atomic::Ordering::Relaxed);
            if enabled {
                // Повторный `connect` не должен падать на уже занятом порту:
                // перехват уже работает, состояние менять не нужно.
                if self.capture.lock().await.is_some() {
                    return Ok(json!({
                        "enabled": true, "status": "connected",
                        "message": "перехват уже включён",
                    }));
                }
                let plan = nft::build_plan(&e.config);
                // Сначала слушатели, потом правила: если порт занят, система
                // остаётся в прежнем состоянии, а не уходит в никуда.
                let mut capture = match capture::start(e.clone()).await {
                    Ok(c) => c,
                    Err(err) => {
                        // Иначе status показывал бы «включено» без слушателей.
                        e.enabled.store(false, std::sync::atomic::Ordering::Relaxed);
                        return Err(err);
                    }
                };
                if let Err(err) = nft::apply(&plan).await {
                    capture.stop().await;
                    e.enabled.store(false, std::sync::atomic::Ordering::Relaxed);
                    return Err(err);
                }
                *self.capture.lock().await = Some(capture);
                return Ok(json!({ "enabled": true, "status": "connected", "message": "" }));
            }
            // Выключаем: сперва закрываем порты, потом снимаем правила.
            if let Some(mut old) = self.capture.lock().await.take() {
                old.stop().await;
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

        // Файловые дескрипторы: при 1024 демон ловит EMFILE под браузером.
        let (fd_open, fd_soft) = fd_usage();
        let fd_ok = fd_soft >= 65_536;
        checks.push(json!({
            "id": "fds", "name": "Файловые дескрипторы", "ok": fd_ok,
            "detail": format!("открыто {fd_open}, soft-лимит {fd_soft}"),
            "fix": if fd_ok { Value::Null } else {
                json!("Добавьте LimitNOFILE=65536 в [Service] юнита proxy-for-ubuntud и выполните systemctl daemon-reload")
            },
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
        let ob_cfg: crate::config::Outbound =
            serde_json::from_value(params.get("outbound").cloned().unwrap_or(json!({})))
                .map_err(|e| Error::ConfigInvalid(e.to_string()))?;

        let _target_note = "цель проверки берётся из probe(), если не задана явно";
        let timeout_ms = params
            .get("timeout_ms")
            .and_then(Value::as_u64)
            .unwrap_or(5000);

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
        let text =
            std::fs::read_to_string(p).map_err(|e| Error::NotFound(format!("{tag}: {e}")))?;
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .take(limit)
            .collect();
        Ok(json!({ "lines": lines }))
    }

    fn profile_list(&self) -> Result<Value> {
        let mut profiles = Vec::new();
        for (dir, builtin) in [
            (paths::builtin_profiles_dir(), true),
            (paths::user_profiles_dir(), false),
        ] {
            let Ok(rd) = std::fs::read_dir(&dir) else {
                continue;
            };
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().and_then(|x| x.to_str()) != Some("yaml") {
                    continue;
                }
                let name = p
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let updated_at = std::fs::metadata(&p)
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                profiles
                    .push(json!({ "name": name, "builtin": builtin, "updated_at": updated_at }));
            }
        }
        Ok(json!({ "profiles": profiles }))
    }

    fn profile_read(&self, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let (path, _) = resolve_profile_path(name)?;
        let env = crate::config::read_env_file(&paths::env_file());
        let text =
            std::fs::read_to_string(&path).map_err(|e| Error::NotFound(format!("{name}: {e}")))?;
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
        let cfg: Config =
            serde_json::from_value(params.get("config").cloned().unwrap_or(json!({})))
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
            return Err(Error::Permission(
                "встроенный профиль удалить нельзя".into(),
            ));
        }
        std::fs::remove_file(&path).map_err(|e| Error::NotFound(format!("{name}: {e}")))?;
        Ok(json!({ "ok": true }))
    }

    async fn profile_activate(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let (path, _) = resolve_profile_path(name)?;
        let env = crate::config::read_env_file(&paths::env_file());
        let cfg = Config::load(&path, &env)?;
        let report = self
            .supervisor
            .apply(cfg, &format!("активация профиля {name}"))
            .await;
        let result = serde_json::to_value(&report)?;
        if report.ok {
            let geo = GeoRegistry::load(&[]);
            if let Ok(engine) = Engine::build(self.load_config()?.0, &geo) {
                engine
                    .enabled
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                *self.engine.write().await = Some(engine);
            }
        }
        Ok(json!({ "ok": report.ok, "needs_restart": false, "apply": result }))
    }

    fn profile_import(&self, params: &Value) -> Result<Value> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("imported");
        let yaml = params.get("yaml").and_then(Value::as_str).unwrap_or("");
        let env = crate::config::read_env_file(&paths::env_file());
        Config::parse(yaml, &env)?;
        paths::ensure_dir(&paths::user_profiles_dir())?;
        let path = paths::user_profiles_dir().join(format!("{}.yaml", sanitize_name(name)));
        paths::atomic_write(&path, yaml.as_bytes())?;
        Ok(json!({ "ok": true, "warnings": Vec::<String>::new(), "errors": [] }))
    }

    fn profile_export(&self, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let redact = params
            .get("redact_secrets")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let age_passphrase = params.get("age_passphrase").and_then(Value::as_str);
        let (path, _) = resolve_profile_path(name)?;
        let mut text =
            std::fs::read_to_string(&path).map_err(|e| Error::NotFound(format!("{name}: {e}")))?;
        if redact {
            text = redact_secrets(&text);
        }
        if let Some(passphrase) = age_passphrase {
            let passphrase = SecretString::new(passphrase.to_string());
            let encryptor = Encryptor::with_user_passphrase(passphrase);
            let mut buf = Vec::new();
            use base64::Engine as _;
            {
                let mut writer = encryptor
                    .wrap_output(&mut buf)
                    .map_err(|e| Error::Internal(e.to_string()))?;
                writer.write_all(text.as_bytes())?;
                writer.finish()?;
            }
            let encoded = base64::engine::general_purpose::STANDARD.encode(&buf);
            return Ok(json!({ "ok": true, "encrypted": encoded }));
        }
        Ok(json!({ "ok": true, "yaml": text }))
    }

    async fn subscription_update(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let url = params.get("url").and_then(Value::as_str).unwrap_or("");
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("subscription");
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
            Error::ConfigInvalid(format!(
                "подписка не похожа на конфиг proxy-for-ubuntu: {e}"
            ))
        })?;
        let outbounds_found = cfg.outbounds.len();
        let rules_found = cfg.rules.len();
        paths::ensure_dir(&paths::user_profiles_dir())?;
        paths::atomic_write(
            &paths::user_profiles_dir().join(format!("{}.yaml", sanitize_name(name))),
            yaml.as_bytes(),
        )?;

        let mut activated = false;
        if params
            .get("auto_activate")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
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

    /// Импорт одной ссылки (`REQ-003`): `vless://`, `vmess://`, `ss://`,
    /// `trojan://`, `socks5://`, `http://`.
    ///
    /// Ссылка разбирается и проверяется **до** записи файла: невалидная строка
    /// не должна оставлять после себя полупустой профиль.
    fn profile_import_uri(&self, params: &Value) -> Result<Value> {
        let uri = params.get("uri").and_then(Value::as_str).unwrap_or("");
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("imported");
        let (path, builtin) = resolve_profile_path(name)?;
        if builtin {
            return Err(Error::Permission(format!(
                "профиль {name:?} встроенный и не редактируется"
            )));
        }
        let env = crate::config::read_env_file(&paths::env_file());
        let base = load_or_empty_config(&path, &env)?;
        let (cfg, outbound) = config_with_uri(base, uri)?;
        let yaml = cfg.to_yaml()?;
        paths::ensure_dir(&paths::user_profiles_dir())?;
        paths::atomic_write(&path, yaml.as_bytes())?;

        let warnings = Vec::<String>::new();
        Ok(json!({
            "ok": true,
            "name": name,
            "outbound": outbound,
            "warnings": warnings,
        }))
    }

    /// Импорт набора ссылок, вставленных вручную (`REQ-003`).
    ///
    /// Одна строка — одна ссылка. Как и в подписке, битая строка не отменяет
    /// остальные: пользователь получает «принято N, отклонено M» с номерами
    /// строк, а профиль перезаписывается один раз — после разбора всего
    /// списка. Одиночная ссылка идёт через `profile.import_uri`: там ответ
    /// содержит разобранный outbound, здесь важнее отчёт по строкам.
    fn profile_import_links(&self, params: &Value) -> Result<Value> {
        let text = params.get("text").and_then(Value::as_str).unwrap_or("");
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("imported");
        let (path, builtin) = resolve_profile_path(name)?;
        if builtin {
            return Err(Error::Permission(format!(
                "профиль {name:?} встроенный и не редактируется"
            )));
        }
        let parsed = crate::subscription::parse_body(text)
            .map_err(|e| Error::ConfigInvalid(format!("{}: {e}", e.code())))?;
        // YAML — это готовый конфиг, а не список ссылок: сливать его в
        // существующий профиль значило бы молча потерять его правила.
        if parsed.format == Some(crate::subscription::SubscriptionFormat::Yaml) {
            return Err(Error::ConfigInvalid(
                "E_LINKS_IS_YAML: это YAML-конфиг целиком, используйте «Импорт»".into(),
            ));
        }
        let env = crate::config::read_env_file(&paths::env_file());
        let base = load_or_empty_config(&path, &env)?;
        let (cfg, accepted) = config_with_parsed(base, &parsed)?;
        let yaml = cfg.to_yaml()?;
        paths::ensure_dir(&paths::user_profiles_dir())?;
        paths::atomic_write(&path, yaml.as_bytes())?;
        let rejected: Vec<Value> = parsed
            .rejected
            .iter()
            .map(|r| json!({ "line": r.line, "code": r.code, "reason": r.reason }))
            .collect();
        Ok(json!({
            "ok": true,
            "name": name,
            "accepted": accepted,
            "rejected": rejected,
            "summary": format!("принято {}, отклонено {}", accepted, rejected.len()),
        }))
    }

    /// Что придёт из подписки — без записи в профиль (`REQ-002`).
    ///
    /// Пользователь должен увидеть «принято N, отклонено M» до того, как
    /// подписка заменит его рабочий конфиг.
    async fn subscription_preview(&self, params: &Value) -> Result<Value> {
        let url = params.get("url").and_then(Value::as_str).unwrap_or("");
        let body = fetch_subscription_body(url).await?;
        let parsed = crate::subscription::parse_body(&body)
            .map_err(|e| Error::ConfigInvalid(format!("{}: {e}", e.code())))?;

        // YAML-подписка — это конфиг целиком, а не список ссылок: разбираем её
        // тем же парсером, что и `subscription.update`.
        let outbounds = if parsed.format == Some(crate::subscription::SubscriptionFormat::Yaml) {
            let env = crate::config::read_env_file(&paths::env_file());
            let cfg = Config::parse(&body, &env)?;
            cfg.outbounds
        } else {
            parsed.outbounds.clone()
        };
        let rejected: Vec<Value> = parsed
            .rejected
            .iter()
            .map(|r| json!({ "line": r.line, "code": r.code, "reason": r.reason }))
            .collect();
        Ok(json!({
            "format": parsed.format.map(|f| f.as_str()).unwrap_or("unknown"),
            "accepted": outbounds.len(),
            "rejected": rejected,
            "outbounds": outbounds,
            "summary": format!("принято {}, отклонено {}", outbounds.len(), rejected.len()),
        }))
    }

    /// Загрузка подписки и запись её в профиль (`REQ-002`).
    ///
    /// `remember=false` — вызов из планировщика: запись в реестр делает он сам,
    /// иначе таймер перезаписал бы `last_error` собственным успехом.
    async fn subscription_apply(self: &Arc<Self>, params: &Value, remember: bool) -> Result<Value> {
        let url = params.get("url").and_then(Value::as_str).unwrap_or("");
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("subscription");
        let (path, builtin) = resolve_profile_path(name)?;
        if builtin {
            return Err(Error::Permission(format!(
                "профиль {name:?} встроенный и не редактируется"
            )));
        }
        let env = crate::config::read_env_file(&paths::env_file());

        // 1. Загрузка и разбор. Любая ошибка здесь оставляет профиль как был.
        let body = fetch_subscription_body(url).await?;
        let parsed = crate::subscription::parse_body(&body)
            .map_err(|e| Error::ConfigInvalid(format!("{}: {e}", e.code())))?;
        let (cfg, accepted) =
            if parsed.format == Some(crate::subscription::SubscriptionFormat::Yaml) {
                let cfg = Config::parse(&body, &env)?;
                cfg.validate()?;
                let found = cfg.outbounds.len();
                (cfg, found)
            } else {
                let base = load_or_empty_config(&path, &env)?;
                config_with_parsed(base, &parsed)?
            };
        let rejected: Vec<Value> = parsed
            .rejected
            .iter()
            .map(|r| json!({ "line": r.line, "code": r.code, "reason": r.reason }))
            .collect();

        // 2. Запись. `to_yaml` считается до `atomic_write`: если сериализация
        // упала, старый файл остаётся нетронутым.
        let yaml = cfg.to_yaml()?;
        paths::ensure_dir(&paths::user_profiles_dir())?;
        paths::atomic_write(&path, yaml.as_bytes())?;

        // 3. Реестр подписок: когда удалось в последний раз (`REQ-005`).
        if remember {
            let store = crate::subscription::store_path();
            let mut records = crate::subscription::load_store(&store);
            let interval = params
                .get("interval_hours")
                .and_then(Value::as_u64)
                .unwrap_or(crate::subscription::DEFAULT_INTERVAL_HOURS);
            let mut record = records
                .iter()
                .find(|r| r.name == name)
                .cloned()
                .unwrap_or_else(|| {
                    crate::subscription::SubscriptionRecord::new(name, url, interval)
                });
            record.url = url.to_string();
            if params
                .get("interval_hours")
                .and_then(Value::as_u64)
                .is_some()
            {
                record.interval_hours = interval;
            }
            record.last_attempt_unix = now();
            record.last_success_unix = now();
            record.last_error = None;
            crate::subscription::upsert_record(&mut records, record);
            if let Err(e) = crate::subscription::save_store(&store, &records) {
                tracing::warn!("реестр подписок не сохранён: {e}");
            }
        }

        // 4. Активация — только по явной просьбе и только после успешной записи.
        let mut activated = false;
        if params
            .get("auto_activate")
            .and_then(Value::as_bool)
            .unwrap_or(false)
        {
            let cfg = Config::load(&path, &env)?;
            let report = self.supervisor.apply(cfg, "подписка").await;
            activated = report.ok;
            if report.ok {
                let geo = GeoRegistry::load(&[]);
                if let Ok(engine) = Engine::build(self.load_config()?.0, &geo) {
                    engine
                        .enabled
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                    *self.engine.write().await = Some(engine);
                }
            }
        }

        Ok(json!({
            "ok": true,
            "name": name,
            "accepted": accepted,
            "rejected": rejected,
            "activated": activated,
            "summary": format!("принято {}, отклонено {}", accepted, rejected.len()),
        }))
    }

    /// Подписки из реестра (`REQ-005`) — для экрана профилей.
    ///
    /// Без этого списка пользователь не видит, какие подписки вообще
    /// обновляются по расписанию, и не может обновить одну из них кнопкой.
    fn subscription_list(&self) -> Result<Value> {
        let records = crate::subscription::load_store(&crate::subscription::store_path());
        let tick = now();
        let list: Vec<Value> = records
            .iter()
            .map(|r| {
                json!({
                    "name": r.name,
                    "url": r.url,
                    "interval_hours": r.interval_hours,
                    "last_success_unix": r.last_success_unix,
                    "last_attempt_unix": r.last_attempt_unix,
                    "last_error": r.last_error,
                    "due": r.due(tick),
                })
            })
            .collect();
        Ok(json!({ "subscriptions": list }))
    }

    /// Немедленное обновление одной подписки из реестра — кнопкой, а не по
    /// таймеру. Профиль при неудаче не меняется, причина остаётся в
    /// `last_error` без URL и секретов.
    async fn subscription_refresh(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let store = crate::subscription::store_path();
        let mut records = crate::subscription::load_store(&store);
        let index = records
            .iter()
            .position(|r| r.name == name)
            .ok_or_else(|| Error::NotFound(format!("подписка {name:?} не найдена")))?;
        let url = records[index].url.clone();
        let profile = records[index].name.clone();
        records[index].last_attempt_unix = now();
        let attempted = self
            .subscription_apply(
                &json!({ "url": url, "name": profile, "auto_activate": false }),
                false,
            )
            .await;
        match &attempted {
            Ok(_) => {
                records[index].last_success_unix = now();
                records[index].last_error = None;
            }
            Err(e) => {
                records[index].last_error = Some(error_without_url(&e.to_string(), &url));
            }
        }
        if let Err(e) = crate::subscription::save_store(&store, &records) {
            tracing::warn!("реестр подписок не сохранён: {e}");
        }
        attempted
    }

    /// Убирает запись из реестра: расписание перестаёт ходить по URL.
    /// Файл профиля остаётся — его удаляют отдельно, как обычный профиль.
    fn subscription_remove(&self, params: &Value) -> Result<Value> {
        let name = params.get("name").and_then(Value::as_str).unwrap_or("");
        let store = crate::subscription::store_path();
        let mut records = crate::subscription::load_store(&store);
        let before = records.len();
        records.retain(|r| r.name != name);
        if records.len() == before {
            return Err(Error::NotFound(format!("подписка {name:?} не найдена")));
        }
        crate::subscription::save_store(&store, &records)?;
        Ok(json!({ "ok": true, "name": name }))
    }

    /// Обновляет подписки, у которых вышел срок (`REQ-005`).
    ///
    /// Ошибка одной подписки не мешает остальным и не меняет рабочий конфиг:
    /// профиль пишется только после успешного разбора и валидации.
    pub async fn refresh_due_subscriptions(self: &Arc<Self>) -> Result<()> {
        let store = crate::subscription::store_path();
        let mut records = crate::subscription::load_store(&store);
        if records.is_empty() {
            return Ok(());
        }
        let tick = now();
        let mut due = Vec::new();
        for (index, record) in records.iter().enumerate() {
            if record.due(tick) {
                due.push(index);
            }
        }
        if due.is_empty() {
            return Ok(());
        }
        for index in due {
            let (url, name) = {
                let r = &records[index];
                (r.url.clone(), r.name.clone())
            };
            records[index].last_attempt_unix = tick;
            let attempt = self
                .subscription_apply(
                    &json!({ "url": url, "name": name, "auto_activate": false }),
                    false,
                )
                .await;
            match attempt {
                Ok(_) => {
                    records[index].last_success_unix = tick;
                    records[index].last_error = None;
                }
                Err(e) => {
                    // Сообщение об ошибке может содержать URL подписки с
                    // токеном — в реестр и журнал он попадать не должен.
                    let reason = error_without_url(&e.to_string(), &url);
                    records[index].last_error = Some(reason.clone());
                    tracing::warn!(name = %name, "подписка не обновлена: {reason}");
                }
            }
        }
        crate::subscription::save_store(&store, &records)?;
        Ok(())
    }

    /// Проверяет срок раз в минуту. Срок измеряется в часах, поэтому минута
    /// опоздания ничего не меняет, а таймер почти не жжёт процессор.
    async fn subscription_loop(self: Arc<Self>) {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(SUBSCRIPTION_TICK_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(e) = self.refresh_due_subscriptions().await {
                tracing::warn!("обновление подписок по расписанию: {e}");
            }
        }
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

    /// Поиск по журналу. Без него пользователю с 500 строками приходится
    /// читать всё подряд, чтобы найти одно сообщение об ошибке.
    async fn log_search(self: &Arc<Self>, params: &Value) -> Result<Value> {
        let query = params
            .get("query")
            .and_then(Value::as_str)
            .unwrap_or("")
            // Именно to_lowercase, а не to_ascii_lowercase: журнал и
            // интерфейс русские, а ascii-вариант кириллицу не трогает,
            // и поиск «ПРАВИЛА» не нашёл бы «правила».
            .to_lowercase();
        let level = params.get("level").and_then(Value::as_str);
        let limit = params
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(200)
            .min(5000) as usize;

        let g = self.log_ring.lock().await;
        let mut matched: Vec<&LogEntry> = g
            .iter()
            .filter(|e| level.map(|l| e.level == l).unwrap_or(true))
            .filter(|e| {
                query.is_empty()
                    || e.message.to_lowercase().contains(&query)
                    || e.target.to_lowercase().contains(&query)
            })
            .collect();
        // Свежие записи в конце — их и показываем первыми.
        if matched.len() > limit {
            matched = matched.split_off(matched.len() - limit);
        }
        Ok(json!({ "entries": matched, "total": matched.len() }))
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
                out.push_str(&format!(
                    "[{}] {:5} {}: {}\n",
                    e.ts, e.level, e.target, e.message
                ));
            }
        }
        // Путь приходит от GUI, поэтому родитель может отсутствовать
        // (`"log.txt"`), а не быть `Some("")`. Раньше здесь стоял
        // `unwrap()` и попытка выгрузить лог без каталога давала ошибку
        // вместо записи в текущий.
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                paths::ensure_dir(dir)?;
            }
        }
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

/// Как часто планировщик проверяет, не пора ли обновить подписку (`REQ-005`).
/// Срок измеряется часами, поэтому минута проверки ничего не сдвигает.
const SUBSCRIPTION_TICK_SECS: u64 = 60;

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

/// Минимальный валидный конфиг: `DIRECT` обязателен, поэтому пустой список
/// серверов сам по себе валидацию не проходит.
const EMPTY_PROFILE_YAML: &str = "outbounds:\n  - name: DIRECT\n    type: direct\n";

/// Заготовка профиля для первого импорта.
///
/// Строгая `Config::validate` считает конфиг без единого прокси ошибкой
/// (`E_NO_OUTBOUND`) — это правильно перед применением, но неверно для файла,
/// который мы собираемся наполнить. Поэтому здесь мягкая проверка.
fn base_profile(env: &std::collections::HashMap<String, String>) -> Result<Config> {
    let text = crate::config::expand_env(EMPTY_PROFILE_YAML, env);
    let cfg: Config = serde_yaml::from_str(&text)
        .map_err(|e| Error::ConfigInvalid(format!("заготовка профиля: {e}")))?;
    cfg.validate_for_read()?;
    Ok(cfg)
}

/// Загружает профиль, а если файла ещё нет — заготовку.
/// Импорт первой ссылки/подписки не должен требовать «сначала создайте профиль».
fn load_or_empty_config(
    path: &Path,
    env: &std::collections::HashMap<String, String>,
) -> Result<Config> {
    if path.exists() {
        Config::load(path, env)
    } else {
        base_profile(env)
    }
}

/// Добавляет разобранную ссылку к конфигу. Чистая функция: файл пишет
/// вызывающий, поэтому правило «сначала проверили, потом записали» видно в коде.
fn config_with_uri(mut cfg: Config, uri: &str) -> Result<(Config, crate::config::Outbound)> {
    let parsed = crate::link::parse(uri)
        .map_err(|e| Error::ConfigInvalid(crate::subscription::rejection_note(&e)))?;
    cfg.outbounds = crate::subscription::merge_outbounds(&cfg.outbounds, vec![parsed]);
    cfg.validate()?;
    // Возвращаем тот сервер, который реально лёг в конфиг: при совпадении имён
    // `merge_outbounds` переименовывает копию, и GUI должен увидеть новое имя,
    // а не исходное из ссылки.
    let effective = cfg.outbounds.last().cloned().ok_or(Error::NoOutbound)?;
    Ok((cfg, effective))
}

/// Добавляет к конфигу всё принятое из подписки. Если не принято ни одной
/// ссылки — ошибка: пустая подписка не должна затирать рабочий профиль.
fn config_with_parsed(
    mut cfg: Config,
    parsed: &crate::subscription::ParsedSubscription,
) -> Result<(Config, usize)> {
    if parsed.outbounds.is_empty() {
        return Err(Error::ConfigInvalid(format!(
            "E_SUB_NO_LINKS: ни одной ссылки не принято, отклонено {}",
            parsed.rejected.len()
        )));
    }
    let accepted = parsed.outbounds.len();
    cfg.outbounds = crate::subscription::merge_outbounds(&cfg.outbounds, parsed.outbounds.clone());
    cfg.validate()?;
    Ok((cfg, accepted))
}

/// Загружает тело подписки: только http/https, только разумный размер.
///
/// Проверка схемы идёт **до** запроса: `file://` в поле URL — это чтение
/// произвольного файла с правами демона (`REQ-013`).
async fn fetch_subscription_body(url: &str) -> Result<String> {
    crate::subscription::validate_url(url)
        .map_err(|e| Error::ConfigInvalid(format!("{}: {e}", e.code())))?;
    let client = crate::engine::http_client()?;
    let response = client
        .get(url.trim())
        .send()
        .await
        .map_err(|e| Error::Internal(format!("загрузка подписки: {e}")))?;
    let status = response.status();
    if !status.is_success() {
        return Err(Error::Internal(format!("сервер подписки ответил {status}")));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|e| Error::Internal(format!("чтение подписки: {e}")))?;
    if bytes.len() > crate::subscription::MAX_BODY_BYTES {
        return Err(Error::ConfigInvalid(format!(
            "E_SUB_TOO_LARGE: ответ подписки больше {} байт",
            crate::subscription::MAX_BODY_BYTES
        )));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| Error::ConfigInvalid("E_SUB_ENCODING: тело подписки не UTF-8".into()))
}

/// Убирает URL подписки из текста ошибки: в нём бывает токен, а `last_error`
/// и журнал читает человек и `journalctl`.
fn error_without_url(message: &str, url: &str) -> String {
    let url = url.trim();
    let cleaned = if url.is_empty() {
        message.to_string()
    } else {
        message.replace(url, "<URL подписки>")
    };
    // Длинный ответ сервера тоже не нужен в реестре.
    if cleaned.chars().count() > 300 {
        cleaned.chars().take(300).collect::<String>() + "…"
    } else {
        cleaned
    }
}

/// Имя профиля превращается в имя файла. Без этой проверки `../../.ssh/authorized_keys`
/// в поле «имя профиля» увёл бы запись за пределы каталога.
fn sanitize_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' || c == ' ' {
                c
            } else {
                '_'
            }
        })
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
    const KEYS: [&str; 6] = [
        "password",
        "passphrase",
        "uuid",
        "key_file",
        "secret",
        "token",
    ];
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
    let p = |i: usize| {
        it.clone()
            .nth(i)
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0)
    };
    let (a, b, c) = (p(0), p(1), p(2));
    (a, b, c) >= (maj, min, patch)
}

/// Сколько дескрипторов открыто и каков soft-лимит (`/proc/self/limits`).
fn fd_usage() -> (usize, u64) {
    let open = std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count())
        .unwrap_or(0);
    let soft = std::fs::read_to_string("/proc/self/limits")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|l| l.starts_with("Max open files"))
                // Max open files  1024  1048576  files
                .and_then(|l| l.split_whitespace().nth(3)?.parse::<u64>().ok())
        })
        .unwrap_or(0);
    (open, soft)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Тесты, меняющие `XDG_CONFIG_HOME`, не должны идти параллельно: это
    /// переменная процесса, а каталоги у тестов разные — иначе `apply`
    /// пишет профиль в чужой временный каталог.
    static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Мини-сервер на localhost: один запрос — один ответ. Внешняя сеть не
    /// трогается, поэтому тест годится и для машины, где живой сети нет.
    async fn serve_once(body: String) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind localhost");
        let addr = listener.local_addr().expect("адрес слушателя");
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn preview_reports_partial_subscription() {
        use base64::Engine as _;
        let raw = "vless://11111111-1111-1111-1111-111111111111@example.net:443?security=tls#A\n\
                   trojan://secret@203.0.113.4:443#B\n\
                   мусор\n";
        let body = base64::engine::general_purpose::STANDARD.encode(raw.as_bytes());
        let addr = serve_once(body).await;
        let server = Arc::new(Server::new());
        let result = server
            .handle(
                "subscription.preview",
                json!({ "url": format!("http://{addr}/sub") }),
            )
            .await
            .expect("предпросмотр подписки");

        assert_eq!(result["format"], "base64-link-list");
        assert_eq!(result["accepted"], 2);
        let rejected = result["rejected"].as_array().expect("rejected[]");
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0]["line"], 3);
        assert_eq!(result["summary"], "принято 2, отклонено 1");
    }

    #[tokio::test]
    async fn preview_rejects_file_scheme_before_any_request() {
        let server = Arc::new(Server::new());
        let err = server
            .handle(
                "subscription.preview",
                json!({ "url": "file:///etc/shadow" }),
            )
            .await
            .expect_err("file:// должен быть отклонён");
        assert_eq!(err.code(), "E_CONFIG_INVALID");
        assert!(err.to_string().contains("E_SUB_URL_SCHEME"), "{err}");
    }

    #[test]
    fn uri_import_keeps_existing_outbounds_and_renames_duplicates() {
        let env = std::collections::HashMap::new();
        let base = base_profile(&env).expect("заготовка профиля");
        let (cfg, outbound) = config_with_uri(
            base,
            "vless://11111111-1111-1111-1111-111111111111@example.net:443?security=tls#DIRECT",
        )
        .expect("импорт ссылки");
        assert_eq!(cfg.outbounds.len(), 2, "старый сервер не должен исчезнуть");
        assert_eq!(outbound.name(), "DIRECT (2)", "дубль имени переименован");
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn uri_import_rejects_unsupported_scheme() {
        let env = std::collections::HashMap::new();
        let base = base_profile(&env).expect("заготовка профиля");
        let err = config_with_uri(base, "gopher://example.net:70").expect_err("схема отклонена");
        assert!(err.to_string().contains("E_LINK_SCHEME"), "{err}");
    }

    #[test]
    fn empty_subscription_does_not_touch_the_profile() {
        let env = std::collections::HashMap::new();
        let base = base_profile(&env).expect("заготовка профиля");
        let parsed = crate::subscription::parse_body("текст без единой ссылки").expect("тело");
        let err = config_with_parsed(base, &parsed).expect_err("пустая подписка — ошибка");
        assert!(err.to_string().contains("E_SUB_NO_LINKS"), "{err}");
    }

    #[test]
    fn error_text_drops_the_subscription_url() {
        let url = "https://example.net/sub?token=SECRET-TOKEN";
        let text = error_without_url(
            &format!("загрузка подписки: error sending request for url ({url})"),
            url,
        );
        assert!(!text.contains("SECRET-TOKEN"), "токен утёк: {text}");
        assert!(text.contains("<URL подписки>"), "{text}");
    }

    #[tokio::test]
    async fn import_links_keeps_good_lines_and_reports_bad_ones() {
        let _guard = ENV_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("pfu-ipc-links-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        let server = Arc::new(Server::new());
        let text = "vless://11111111-1111-1111-1111-111111111111@example.net:443?security=tls#A\n\
                    мусор\n\
                    trojan://secret@203.0.113.4:443#B\n";
        let result = server
            .handle(
                "profile.import_links",
                json!({ "text": text, "name": "links" }),
            )
            .await
            .expect("импорт списка ссылок");
        assert_eq!(result["accepted"], 2);
        assert_eq!(result["rejected"][0]["line"], 2);
        assert_eq!(result["summary"], "принято 2, отклонено 1");
        let written = std::fs::read_to_string(paths::user_profiles_dir().join("links.yaml"))
            .expect("профиль записан");
        assert!(written.contains("A") && written.contains("B"), "{written}");

        // YAML целиком в поле ссылок — отказ, а не молчаливое слияние.
        let err = server
            .handle(
                "profile.import_links",
                json!({ "text": "outbounds:\n  - name: A\n    type: trojan\n", "name": "links" }),
            )
            .await
            .expect_err("YAML не список ссылок");
        assert!(err.to_string().contains("E_LINKS_IS_YAML"), "{err}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn subscription_registry_lists_refreshes_and_removes() {
        let _guard = ENV_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("pfu-ipc-subs-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        let raw = "vless://11111111-1111-1111-1111-111111111111@example.net:443?security=tls#A\n";
        let addr = serve_once(raw.to_string()).await;
        let store = crate::subscription::store_path();
        crate::subscription::save_store(
            &store,
            &[crate::subscription::SubscriptionRecord::new(
                "live",
                &format!("http://{addr}/sub"),
                crate::subscription::DEFAULT_INTERVAL_HOURS,
            )],
        )
        .expect("реестр записан");

        let server = Arc::new(Server::new());
        let listed = server
            .handle("subscription.list", json!({}))
            .await
            .expect("список подписок");
        assert_eq!(listed["subscriptions"].as_array().map(Vec::len), Some(1));
        assert_eq!(listed["subscriptions"][0]["name"], "live");
        assert_eq!(
            listed["subscriptions"][0]["due"], true,
            "ещё ни разу не обновлялась"
        );

        let refreshed = server
            .handle("subscription.refresh", json!({ "name": "live" }))
            .await
            .expect("обновление по кнопке");
        assert_eq!(refreshed["accepted"], 1);
        let after = crate::subscription::load_store(&store);
        assert!(after[0].last_success_unix > 0);
        assert!(after[0].last_error.is_none());

        // Недоступный сервер: ошибка возвращается, профиль не меняется,
        // причина неудачи остаётся в реестре без URL с токеном.
        let profile = paths::user_profiles_dir().join("live.yaml");
        let before = std::fs::read_to_string(&profile).expect("профиль записан");
        let mut records = crate::subscription::load_store(&store);
        records[0].url = "http://127.0.0.1:1/sub?token=SECRET-TOKEN".into();
        crate::subscription::save_store(&store, &records).expect("реестр");
        let err = server
            .handle("subscription.refresh", json!({ "name": "live" }))
            .await
            .expect_err("недоступный сервер должен дать ошибку");
        assert!(err.to_string().contains("загрузка подписки"), "{err}");
        assert_eq!(
            std::fs::read_to_string(&profile).expect("профиль на месте"),
            before,
            "профиль изменился при неудаче"
        );
        let failed = crate::subscription::load_store(&store);
        assert!(
            failed[0].last_error.is_some(),
            "причина неудачи не сохранена"
        );
        assert!(
            !failed[0]
                .last_error
                .as_deref()
                .unwrap_or("")
                .contains("SECRET-TOKEN"),
            "токен утёк в реестр"
        );

        let removed = server
            .handle("subscription.remove", json!({ "name": "live" }))
            .await
            .expect("удаление подписки");
        assert_eq!(removed["ok"], true);
        assert!(crate::subscription::load_store(&store).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn apply_writes_profile_and_keeps_it_on_failure() {
        // Свой каталог конфигурации: тест не должен трогать профили человека.
        let _guard = ENV_LOCK.lock().await;
        let dir = std::env::temp_dir().join(format!("pfu-ipc-apply-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::env::set_var("XDG_CONFIG_HOME", &dir);

        let raw = "vless://11111111-1111-1111-1111-111111111111@example.net:443?security=tls#A\n\
                   trojan://secret@203.0.113.4:443#B\n";
        let addr = serve_once(raw.to_string()).await;
        let server = Arc::new(Server::new());
        let result = server
            .handle(
                "subscription.apply",
                json!({ "url": format!("http://{addr}/sub"), "name": "e2e" }),
            )
            .await
            .expect("импорт подписки");
        assert_eq!(result["accepted"], 2);
        assert_eq!(result["activated"], false);

        let profile = paths::user_profiles_dir().join("e2e.yaml");
        let written = std::fs::read_to_string(&profile).expect("профиль записан");
        assert!(written.contains("A") && written.contains("B"), "{written}");

        // Реестр знает, когда обновление удалось в последний раз (REQ-005).
        let store = crate::subscription::load_store(&crate::subscription::store_path());
        assert_eq!(store.len(), 1);
        assert_eq!(store[0].name, "e2e");
        assert!(store[0].last_success_unix > 0);

        // Неудачная загрузка не меняет рабочий профиль и не двигает дату успеха.
        let err = server
            .handle(
                "subscription.apply",
                json!({ "url": "http://127.0.0.1:1/sub", "name": "e2e" }),
            )
            .await
            .expect_err("недоступный сервер должен дать ошибку");
        assert!(err.to_string().contains("загрузка подписки"), "{err}");
        let after_failure = std::fs::read_to_string(&profile).expect("профиль на месте");
        assert_eq!(written, after_failure, "рабочий конфиг изменился");
        let store_after = crate::subscription::load_store(&crate::subscription::store_path());
        assert_eq!(
            store_after[0].last_success_unix, store[0].last_success_unix,
            "дата успешного обновления сдвинулась после неудачи"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_name_blocks_traversal() {
        assert_eq!(sanitize_name("Мой профиль"), "Мой профиль");
        // "../../.ssh/" — семь символов, каждый заменяется подчёркиванием.
        assert_eq!(
            sanitize_name("../../.ssh/authorized_keys"),
            "_______ssh_authorized_keys"
        );
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
        assert!(
            r.contains("username: bob"),
            "логин не секрет, его можно оставить"
        );
        assert!(r.contains("server: a"));
    }

    #[tokio::test]
    async fn log_search_filters_by_level_and_substring() {
        use std::sync::Arc;
        let s = Arc::new(Server::new());
        {
            let mut g = s.log_ring.lock().await;
            g.push(LogEntry {
                ts: 1,
                level: "info".into(),
                target: "engine::nft".into(),
                message: "правила применены".into(),
            });
            g.push(LogEntry {
                ts: 2,
                level: "error".into(),
                target: "engine::outbound".into(),
                message: "соединение отклонено".into(),
            });
            g.push(LogEntry {
                ts: 3,
                level: "warn".into(),
                target: "engine::nft".into(),
                message: "geo-набор не скачан".into(),
            });
        }

        // По подстроке в тексте сообщения.
        let r = s.log_search(&json!({ "query": "nft" })).await.unwrap();
        let n = r["entries"].as_array().unwrap().len();
        // Совпадение идёт и по полю target, поэтому берём оба.
        assert!(n >= 1, "поиск по 'nft' ничего не нашёл");

        // По уровню.
        let r = s.log_search(&json!({ "level": "error" })).await.unwrap();
        let e = r["entries"].as_array().unwrap();
        assert_eq!(e.len(), 1, "уровень error должен дать ровно одну запись");
        assert_eq!(e[0]["level"], "error");

        // Несуществующая подстрока — пусто, а не ошибка.
        let r = s
            .log_search(&json!({ "query": "такого-текста-нет" }))
            .await
            .unwrap();
        assert!(r["entries"].as_array().unwrap().is_empty());

        // Поиск регистронезависим.
        let r = s.log_search(&json!({ "query": "ПРАВИЛА" })).await.unwrap();
        assert!(
            !r["entries"].as_array().unwrap().is_empty(),
            "поиск должен быть без учёта регистра"
        );
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
        let err = rt
            .block_on(s.handle("нет.такого.метода", json!({})))
            .unwrap_err();
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
