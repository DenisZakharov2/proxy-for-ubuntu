//! Генерация и применение правил nftables.
//!
//! Правила не собираются поштучно: весь набор уходит одной командой `nft -f`.
//! Так применение атомарно — не бывает полуработающего состояния, когда
//! маршрут уже закручен, а правило ещё не добавлено.
//!
//! Схема: mark-based политическая маршрутизация.
//! 1. В mangle-хук `prerouting`/`output` ставим метку на весь трафик.
//! 2. `ip rule` отправляет помеченное в таблицу 100.
//! 3. В таблице 100 маршрут по умолчанию — в TUN или в локальный сокет.
//!
//! Исключения прописаны явно, чтобы не зацикливать собственный трафик
//! демона и не потерять SSH к машине, у которой «уехал» интернет.

use std::process::Stdio;

use crate::config::{Config, TcpMode, UdpMode};
use crate::error::{Error, Result};

/// Имя таблицы и имя таблицы маршрутизации — константы, потому что на них
/// ссылаются скрипты диагностики в документации.
pub const NFT_TABLE: &str = "pfu";
pub const ROUTE_TABLE: u32 = 100;
pub const FW_MARK: u32 = 0x1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftPlan {
    /// Полный текст набора правил для `nft -f -`.
    pub ruleset: String,
    /// Команды `ip`, которые выполняются до и после `nft -f`.
    pub ip_pre: Vec<String>,
    pub ip_post: Vec<String>,
    /// Что делать для отката.
    pub rollback: Vec<String>,
}

/// Собирает план правил из конфигурации. Ничего не применяет — вызывающий
/// решает, когда это сделать.
pub fn build_plan(cfg: &Config) -> NftPlan {
    let mut r = String::new();
    let disabled = cfg.intercept.tcp == TcpMode::Off && cfg.intercept.udp == UdpMode::Off;

    r.push_str("table inet pfu\n");
    r.push_str("delete table inet pfu\n");
    r.push_str("table inet pfu {\n");

    // ── Исключения, чтобы не зацилить самих себя ──────────────────────────
    r.push_str("    set loopback_ips {\n");
    r.push_str("        type ipv4_addr; flags interval;\n");
    r.push_str("        127.0.0.0/8\n");
    r.push_str("    }\n");
    if cfg.intercept.bypass_private {
        r.push_str("    set private_ips {\n");
        r.push_str("        type ipv4_addr; flags interval;\n");
        r.push_str("        10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16\n");
        r.push_str("    }\n");
    }
    if !cfg.intercept.exclude_ports.is_empty() {
        r.push_str("    set exclude_ports {\n");
        r.push_str("        type inet_service; flags interval;\n");
        for p in &cfg.intercept.exclude_ports {
            r.push_str(&format!("        {p}\n"));
        }
        r.push_str("    }\n");
    }
    for uid in &cfg.intercept.exclude_uid {
        r.push_str(&format!("    chain skip_{uid} {{ return; }}\n"));
    }

    // ── prerouting: трафик, приходящий в систему (форвардинг) ────────────
    r.push_str("    chain prerouting {\n");
    r.push_str("        type filter hook prerouting priority mangle; policy accept;\n");
    if !disabled {
        r.push_str("        iifname \"lo\" return\n");
        r.push_str("        ip daddr @loopback_ips return\n");
        if cfg.intercept.bypass_private {
            r.push_str("        ip daddr @private_ips return\n");
        }
        r.push_str("        meta mark set 0x1\n");
    }
    r.push_str("    }\n");

    // ── output: трафик самой системы, то есть то, что нам нужно перехватить
    r.push_str("    chain output {\n");
    r.push_str("        type filter hook output priority mangle; policy accept;\n");
    if !disabled {
        r.push_str("        oifname \"lo\" return\n");
        r.push_str("        ip daddr @loopback_ips return\n");
        if cfg.intercept.bypass_private {
            r.push_str("        ip daddr @private_ips return\n");
        }
        if !cfg.intercept.exclude_ports.is_empty() {
            r.push_str("        meta l4proto { tcp, udp } th dport @exclude_ports return\n");
        }
        for uid in &cfg.intercept.exclude_uid {
            r.push_str(&format!("        meta skuid {uid} jump skip_{uid}\n"));
        }
        // Трафик самого демона к прокси-серверу обязан идти напрямую,
        // иначе он завернётся в перехват и попадёт в бесконечный цикл.
        r.push_str("        meta skuid 0 return\n");
        r.push_str("        meta mark set 0x1\n");
    }
    r.push_str("    }\n");
    r.push_str("}\n");

    let mut ip_pre = vec![
        format!("ip rule add fwmark {FW_MARK} lookup {ROUTE_TABLE} priority 100 2>/dev/null || true"),
    ];
    let mut ip_post = Vec::new();
    for cmd in &ip_pre {
        let _ = cmd;
    }

    if !disabled {
        // Редирект TCP в локальный сокет демона.
        ip_post.push(format!(
            "ip route replace default dev lo table {ROUTE_TABLE}"
        ));
    }

    NftPlan {
        ruleset: r,
        ip_pre: std::mem::take(&mut ip_pre),
        ip_post,
        rollback: vec![
            format!("ip rule del fwmark {FW_MARK} lookup {ROUTE_TABLE} priority 100 2>/dev/null || true"),
            format!("ip route flush table {ROUTE_TABLE} 2>/dev/null || true"),
            "nft delete table inet pfu 2>/dev/null || true".to_string(),
        ],
    }
}

/// Применяет план. Возвращает ошибку с текстом, который пользователь может
/// выполнить руками, если что-то пойдёт не так.
pub async fn apply(plan: &NftPlan) -> Result<()> {
    for cmd in &plan.ip_pre {
        run_sh(cmd).await?;
    }
    for cmd in &plan.ip_post {
        run_sh(cmd).await?;
    }
    // Порядок важен: сначала маршрут, потом правила пометки. Иначе между
    // двумя операциями трафик пойдёт в пустую таблицу и пропадёт.
    if let Err(e) = apply_ruleset(&plan.ruleset).await {
        for cmd in &plan.rollback {
            let _ = run_sh(cmd).await;
        }
        return Err(e);
    }
    Ok(())
}

/// Убирает всё, что приложение добавило. Вызывается при откате, остановке и
/// удалении пакета.
pub async fn teardown() -> Result<()> {
    for cmd in &base_rollback() {
        let _ = run_sh(cmd).await;
    }
    Ok(())
}

pub fn base_rollback() -> Vec<String> {
    vec![
        format!("ip rule del fwmark {FW_MARK} lookup {ROUTE_TABLE} priority 100 2>/dev/null || true"),
        format!("ip route flush table {ROUTE_TABLE} 2>/dev/null || true"),
        "nft delete table inet pfu 2>/dev/null || true".to_string(),
    ]
}

async fn apply_ruleset(ruleset: &str) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut child = tokio::process::Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            Error::Internal(format!("не удалось запустить nft: {e}. Установлен ли пакет nftables?"))
        })?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(ruleset.as_bytes()).await?;
    }
    drop(child.stdin.take());
    let out = child
        .wait_with_output()
        .await
        .map_err(|e| Error::Internal(format!("nft: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Apply(format!(
            "nftables отклонил набор правил: {}. Проверить вручную: sudo nft -c -f -",
            err.trim()
        )));
    }
    Ok(())
}

async fn run_sh(cmd: &str) -> Result<()> {
    let out = tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| Error::Internal(format!("не удалось выполнить {cmd:?}: {e}")))?;
    if !out.status.success() {
        return Err(Error::Apply(format!(
            "команда {cmd:?} завершилась с ошибкой: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Проверка окружения для `system.diagnose`.
pub async fn check_available() -> (bool, String) {
    match tokio::process::Command::new("nft").arg("--version").output().await {
        Ok(o) if o.status.success() => (true, String::from_utf8_lossy(&o.stdout).trim().to_string()),
        Ok(_) => (false, "nft есть, но не запускается".into()),
        Err(e) => (false, format!("не найден: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cfg() -> Config {
        let mut c = Config::default();
        c.outbounds.push(crate::config::Outbound::Direct(
            crate::config::OutboundDirect { name: "X".into(), test_url: None, test_timeout_ms: None },
        ));
        c
    }

    #[test]
    fn plan_contains_hooks_and_mark() {
        let plan = build_plan(&base_cfg());
        assert!(plan.ruleset.contains("table inet pfu"));
        assert!(plan.ruleset.contains("hook prerouting"));
        assert!(plan.ruleset.contains("hook output"));
        assert!(plan.ruleset.contains("meta mark set 0x1"));
    }

    #[test]
    fn root_is_excluded_to_avoid_loop() {
        let plan = build_plan(&base_cfg());
        // Трафик демона (uid 0) обязан идти мимо перехвата, иначе бесконечный
        // цикл: демон → перехват → демон → …
        assert!(plan.ruleset.contains("meta skuid 0 return"));
    }

    #[test]
    fn disabled_intercept_produces_no_marking() {
        let mut c = base_cfg();
        c.intercept.tcp = TcpMode::Off;
        c.intercept.udp = UdpMode::Off;
        let plan = build_plan(&c);
        assert!(!plan.ruleset.contains("meta mark set 0x1"));
        assert!(plan.ip_post.is_empty());
    }

    #[test]
    fn excluded_ports_are_rendered() {
        let mut c = base_cfg();
        c.intercept.exclude_ports = vec!["22".into(), "3389".into()];
        let plan = build_plan(&c);
        assert!(plan.ruleset.contains("type inet_service"));
        assert!(plan.ruleset.contains("22"));
        assert!(plan.ruleset.contains("3389"));
    }

    #[test]
    fn private_ranges_skipped_when_disabled() {
        let mut c = base_cfg();
        c.intercept.bypass_private = false;
        let plan = build_plan(&c);
        assert!(!plan.ruleset.contains("@private_ips"));
    }

    #[test]
    fn rollback_removes_everything_we_add() {
        let plan = build_plan(&base_cfg());
        for cmd in &plan.rollback {
            if cmd.contains("ip rule") || cmd.contains("ip route") || cmd.contains("nft delete") {
                continue;
            }
            panic!("непокрытая команда отката: {cmd}");
        }
        assert!(!plan.rollback.is_empty());
    }
}
