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

use std::process::{Output, Stdio};
use std::time::Duration;

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
}

/// Собирает план правил из конфигурации. Ничего не применяет — вызывающий
/// решает, когда это сделать.
pub fn build_plan(cfg: &Config) -> NftPlan {
    let mut r = String::new();
    let tcp_on = cfg.intercept.tcp != TcpMode::Off;
    let udp_on = cfg.intercept.udp != UdpMode::Off;
    let disabled = !tcp_on && !udp_on;

    r.push_str("table inet pfu\n");
    r.push_str("delete table inet pfu\n");
    r.push_str("table inet pfu {\n");

    // ── Наборы исключений ─────────────────────────────────────────────────
    // Внутри блока set элементы пишутся только через `elements = { ... }`:
    // «сырой» список nft отвергает с syntax error.
    r.push_str("    set loopback_ips {\n");
    r.push_str("        type ipv4_addr; flags interval;\n");
    r.push_str("        elements = { 127.0.0.0/8 }\n");
    r.push_str("    }\n");
    if cfg.intercept.bypass_private {
        r.push_str("    set private_ips {\n");
        r.push_str("        type ipv4_addr; flags interval;\n");
        r.push_str(
            "        elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 }\n",
        );
        r.push_str("    }\n");
    }
    if !cfg.intercept.exclude_ports.is_empty() {
        r.push_str("    set exclude_ports {\n");
        r.push_str("        type inet_service; flags interval;\n");
        r.push_str(&format!(
            "        elements = {{ {} }}\n",
            cfg.intercept.exclude_ports.join(", ")
        ));
        r.push_str("    }\n");
    }

    // ── prerouting: форвардинг (Docker и другие чужие пакеты) ────────────
    // UDP отдаём в TPROXY-сокет, TCP — в nat-хуке ниже. Метка нужна TPROXY:
    // по ней `ip rule` отправляет пакет в таблицу 100 с локальным маршрутом.
    if !disabled {
        r.push_str("    chain prerouting {\n");
        r.push_str("        type filter hook prerouting priority mangle; policy accept;\n");
        r.push_str("        iifname \"lo\" return\n");
        // Таблица `inet` видит оба семейства, а слушатели демона — только
        // IPv4. Без явного возврата IPv6-TCP уходит в `redirect` и падает:
        // получателя из IPv4-сокета не восстановить.
        r.push_str("        meta nfproto ipv6 return\n");
        // TPROXY в prerouting видит и входящий трафик к самой машине. Без этих
        // исключений mDNS (224.0.0.251), NTP-ответы и любые пакеты на локальный
        // адрес уходят в прокси-сокет вместо приложения: службы ломаются, а
        // демон захлёбывается десятками тысяч датаграмм.
        r.push_str("        fib daddr type local return\n");
        r.push_str("        ip daddr 224.0.0.0/4 return\n");
        r.push_str("        ip daddr 255.255.255.255 return\n");
        r.push_str("        ip daddr @loopback_ips return\n");
        if cfg.intercept.bypass_private {
            r.push_str("        ip daddr @private_ips return\n");
        }
        if !cfg.intercept.exclude_ports.is_empty() {
            r.push_str("        meta l4proto { tcp, udp } th dport @exclude_ports return\n");
        }
        if udp_on {
            r.push_str("        meta l4proto udp meta mark set 0x1 tproxy to :");
            r.push_str(&crate::paths::tproxy_port().to_string());
            r.push('\n');
        }
        r.push_str("    }\n");
    }

    // ── nat output: трафик самой системы ────────────────────────────────
    // REDIRECT переписывает адрес получателя на локальный сокет демона и
    // сохраняет настоящий адрес доступным через SO_ORIGINAL_DST.
    if !disabled {
        r.push_str("    chain nat_output {\n");
        r.push_str("        type nat hook output priority -100; policy accept;\n");
        r.push_str("        oifname \"lo\" return\n");
        // См. prerouting: IPv6 идёт напрямую, пока нет v6-слушателей.
        r.push_str("        meta nfproto ipv6 return\n");
        r.push_str("        fib daddr type local return\n");
        r.push_str("        ip daddr 224.0.0.0/4 return\n");
        r.push_str("        ip daddr 255.255.255.255 return\n");
        r.push_str("        ip daddr @loopback_ips return\n");
        if cfg.intercept.bypass_private {
            r.push_str("        ip daddr @private_ips return\n");
        }
        if !cfg.intercept.exclude_ports.is_empty() {
            r.push_str("        meta l4proto { tcp, udp } th dport @exclude_ports return\n");
        }
        // Трафик демона (uid 0) обязан идти напрямую, иначе бесконечный цикл.
        r.push_str("        meta skuid 0 return\n");
        for uid in &cfg.intercept.exclude_uid {
            r.push_str(&format!("        meta skuid {uid} return\n"));
        }
        if tcp_on {
            r.push_str("        meta l4proto tcp redirect to :");
            r.push_str(&crate::paths::redirect_port().to_string());
            r.push('\n');
        }
        // UDP здесь не перехватываем: REDIRECT переписывает адрес получателя,
        // и настоящий адрес из сокета уже не достать (IP_ORIGDSTADDR вернёт
        // 127.0.0.1). Локальный UDP идёт напрямую, TPROXY работает только
        // для форвардинга — см. цепочку prerouting.
        r.push_str("    }\n");
    }

    // ── nat prerouting: TCP из контейнеров (только при `docker: true`) ───
    // Приоритет dstnat (-100) ниже mangle (-150), поэтому TPROXY успевает
    // разобрать UDP раньше, а TCP уходит в REDIRECT.
    if !disabled && cfg.intercept.docker {
        r.push_str("    chain nat_prerouting {\n");
        r.push_str("        type nat hook prerouting priority -100; policy accept;\n");
        r.push_str("        iifname \"lo\" return\n");
        r.push_str("        meta nfproto ipv6 return\n");
        // Тот же принцип, что в mangle prerouting: не трогаем трафик,
        // адресованный самой машине (входящие сервисы), и multicast.
        r.push_str("        fib daddr type local return\n");
        r.push_str("        ip daddr 224.0.0.0/4 return\n");
        r.push_str("        ip daddr 255.255.255.255 return\n");
        r.push_str("        ip daddr @loopback_ips return\n");
        if cfg.intercept.bypass_private {
            r.push_str("        ip daddr @private_ips return\n");
        }
        if !cfg.intercept.exclude_ports.is_empty() {
            r.push_str("        meta l4proto { tcp, udp } th dport @exclude_ports return\n");
        }
        if tcp_on {
            r.push_str("        meta l4proto tcp redirect to :");
            r.push_str(&crate::paths::redirect_port().to_string());
            r.push('\n');
        }
        r.push_str("    }\n");
    }

    r.push_str("}\n");

    // Правило добавляется только если его ещё нет: после неудачного teardown
    // и повторного `connect` дубликаты копились, и убрать их потом было нечем.
    let mut ip_pre = vec![format!(
        "ip -o rule show | grep -q 'fwmark {FW_MARK:#x} lookup {ROUTE_TABLE}' \
         || ip rule add fwmark {FW_MARK} lookup {ROUTE_TABLE} priority 100"
    )];
    let mut ip_post = Vec::new();

    // `local` обязателен: без него помеченный пакет не доставляется локально
    // в TPROXY-сокет, а уходит в никуда по маршруту через lo.
    if !disabled && udp_on {
        ip_post.push(format!(
            "ip route replace local default dev lo table {ROUTE_TABLE}"
        ));
    }

    NftPlan {
        ruleset: r,
        ip_pre: std::mem::take(&mut ip_pre),
        ip_post,
    }
}

/// Применяет план. Возвращает ошибку с текстом, который пользователь может
/// выполнить руками, если что-то пойдёт не так.
pub async fn apply(plan: &NftPlan) -> Result<()> {
    // Сначала маршрут, потом правило пометки: пакетов с меткой до применения
    // nft ещё нет, поэтому трафик не может уйти в пустую таблицу 100.
    for cmd in plan.ip_post.iter().chain(plan.ip_pre.iter()) {
        if let Err(e) = run_sh(cmd).await {
            rollback_after_failure().await;
            return Err(e);
        }
    }
    if let Err(e) = apply_ruleset(&plan.ruleset).await {
        rollback_after_failure().await;
        return Err(e);
    }
    Ok(())
}

/// Откат после неудачного применения: ошибки не глотаются, иначе машина
/// остаётся с полуприменёнными правилами и без следа в журнале.
async fn rollback_after_failure() {
    if let Err(e) = teardown().await {
        tracing::error!(error = %e, "откат после неудачного применения не удался");
    }
}

/// Убирает всё, что приложение добавило. Идемпотентен: отсутствие таблицы,
/// правила или маршрута — норма, а вот неудачное удаление существующего
/// объекта возвращается ошибкой и пишется в журнал.
pub async fn teardown() -> Result<()> {
    let mut failures = Vec::new();
    remove_ip_rules(&mut failures).await;
    remove_route_table(&mut failures).await;
    remove_nft_table(&mut failures).await;

    if failures.is_empty() {
        return Ok(());
    }
    for failure in &failures {
        tracing::error!(failure = %failure, "teardown: не удалось снять");
    }
    Err(Error::Apply(format!(
        "перехват снят не полностью: {}",
        failures.join("; ")
    )))
}

/// Селектор наших правил в выводе `ip rule show`.
fn rule_selector() -> String {
    format!("fwmark {FW_MARK:#x} lookup {ROUTE_TABLE}")
}

/// Удаляет все наши правила, а не одно: при повторных `connect` их могло
/// накопиться несколько, в том числе с другими приоритетами.
async fn remove_ip_rules(failures: &mut Vec<String>) {
    let show = match run_capture("ip rule show").await {
        Ok(v) => v,
        Err(e) => {
            failures.push(format!("ip rule show: {e}"));
            return;
        }
    };
    let needle = rule_selector();
    for line in show.lines().filter(|l| l.contains(&needle)) {
        // Строка вида `100:\tfrom all fwmark 0x1 lookup 100`.
        let Some((prio, _)) = line.split_once(':') else {
            continue;
        };
        let prio = prio.trim();
        if prio.parse::<u32>().is_err() {
            continue;
        }
        let cmd = format!("ip rule del priority {prio} fwmark {FW_MARK} lookup {ROUTE_TABLE}");
        if let Err(e) = run_sh(&cmd).await {
            failures.push(format!("{cmd}: {e}"));
        }
    }
    match run_capture("ip rule show").await {
        Ok(after) if after.contains(&needle) => {
            failures.push(format!("правило «{needle}» осталось после удаления"));
        }
        Err(e) => failures.push(format!("ip rule show (проверка): {e}")),
        Ok(_) => {}
    }
}

async fn remove_route_table(failures: &mut Vec<String>) {
    // На системе, где таблица 100 ещё ни разу не создавалась, ядро отвечает
    // «Error: ipv4: FIB table does not exist». Это не сбой очистки: удалять
    // нечего. Раньше такая строка попадала в журнал как ERROR при каждом
    // первом старте демона и обесценивала диагностику.
    if let Err(e) = run_sh(&format!("ip route flush table {ROUTE_TABLE}")).await {
        let text = e.to_string();
        if is_missing_table_error(&text) {
            return;
        }
        failures.push(format!("ip route flush table {ROUTE_TABLE}: {e}"));
    }
}

/// Отличает «таблицы ещё нет» от настоящей ошибки. Вынесено отдельно, чтобы
/// правило проверялось тестом без root и без реального `ip route`.
fn is_missing_table_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("fib table does not exist")
        || (lower.contains("table does not exist") && lower.contains("ipv4"))
}

async fn remove_nft_table(failures: &mut Vec<String>) {
    // `nft delete` на отсутствующей таблице — ошибка, поэтому сначала смотрим,
    // есть ли она: teardown должен быть идемпотентным.
    match run_output("nft list table inet pfu").await {
        Ok(out) if out.status.success() => {
            let mut last = String::new();
            // Ядро может быть занято другим экземпляром nft — короткий повтор
            // дешевле, чем оставленная таблица, уводящая трафик в никуда.
            for attempt in 0..3 {
                match run_sh("nft delete table inet pfu").await {
                    Ok(()) => return,
                    Err(e) => {
                        last = e.to_string();
                        if attempt < 2 {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
            failures.push(format!("nft delete table inet pfu: {last}"));
        }
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr);
            if !err.contains("No such file or directory") {
                failures.push(format!("nft list table inet pfu: {}", err.trim()));
            }
        }
        Err(e) => failures.push(format!("nft list table inet pfu: {e}")),
    }
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
            Error::Internal(format!(
                "не удалось запустить nft: {e}. Установлен ли пакет nftables?"
            ))
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
    let out = run_output(cmd).await?;
    if !out.status.success() {
        return Err(Error::Apply(format!(
            "команда {cmd:?} завершилась с ошибкой: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

/// Выполняет команду и возвращает stdout. Ненулевой код — ошибка с текстом
/// stderr: вызывающий решает, считается ли она нормальной.
async fn run_capture(cmd: &str) -> Result<String> {
    let out = run_output(cmd).await?;
    if !out.status.success() {
        return Err(Error::Apply(format!(
            "команда {cmd:?} завершилась с ошибкой: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

async fn run_output(cmd: &str) -> Result<Output> {
    tokio::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|e| Error::Internal(format!("не удалось выполнить {cmd:?}: {e}")))
}

/// Проверка окружения для `system.diagnose`.
pub async fn check_available() -> (bool, String) {
    match tokio::process::Command::new("nft")
        .arg("--version")
        .output()
        .await
    {
        Ok(o) if o.status.success() => {
            (true, String::from_utf8_lossy(&o.stdout).trim().to_string())
        }
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
            crate::config::OutboundDirect {
                name: "X".into(),
                test_url: None,
                test_timeout_ms: None,
            },
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
    fn plan_uses_valid_set_syntax_and_redirects() {
        let plan = build_plan(&base_cfg());
        // Элементы внутри блока set пишутся только так: «сырой» список nft
        // отвергает с syntax error, и перехват не включается.
        assert!(plan.ruleset.contains("elements = {"));
        // TCP уходит в сокет демона через nat REDIRECT.
        assert!(plan.ruleset.contains("meta l4proto tcp redirect to :"));
        // UDP — через TPROXY с локальным маршрутом в таблице 100.
        assert!(plan.ruleset.contains("tproxy to :"));
        assert!(plan
            .ip_post
            .iter()
            .any(|c| c.contains("local default dev lo table")));
    }

    #[test]
    fn root_is_excluded_to_avoid_loop() {
        let plan = build_plan(&base_cfg());
        // Трафик демона (uid 0) обязан идти мимо перехвата, иначе бесконечный
        // цикл: демон → перехват → демон → …
        assert!(plan.ruleset.contains("meta skuid 0 return"));
    }

    #[test]
    fn ip_rule_is_added_once() {
        let plan = build_plan(&base_cfg());
        // Повторный connect не должен плодить правила: перед add стоит проверка.
        assert_eq!(
            plan.ip_pre,
            vec!["ip -o rule show | grep -q 'fwmark 0x1 lookup 100' \
                 || ip rule add fwmark 1 lookup 100 priority 100"
                .to_string()]
        );
    }

    #[test]
    fn prerouting_skips_local_and_multicast_traffic() {
        let plan = build_plan(&base_cfg());
        let pre = plan
            .ruleset
            .split("chain prerouting")
            .nth(1)
            .expect("цепочка prerouting есть");
        // TPROXY видит и входящий трафик к самой машине: без этих исключений
        // mDNS и ответы локальным службам уходят в прокси-сокет.
        assert!(pre.contains("fib daddr type local return"));
        assert!(pre.contains("ip daddr 224.0.0.0/4 return"));
        assert!(pre.contains("ip daddr 255.255.255.255 return"));
    }

    #[test]
    fn ipv6_is_never_intercepted() {
        let mut c = base_cfg();
        // С docker включён третий хук — все три обязаны пропускать IPv6.
        c.intercept.docker = true;
        let plan = build_plan(&c);
        // Таблица `inet` покрывает оба семейства, а слушатели демона — только
        // IPv4: без guard'а IPv6-соединения уходят в `redirect` и рвутся.
        assert_eq!(plan.ruleset.matches("meta nfproto ipv6 return").count(), 3);
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
    fn missing_fib_table_is_not_a_teardown_failure() {
        // Точный текст ядра на системе, где таблица 100 ещё не создавалась.
        assert!(is_missing_table_error(
            "ip route flush table 100: Error: ipv4: FIB table does not exist."
        ));
        assert!(is_missing_table_error("FIB table does not exist"));
        assert!(is_missing_table_error("ipv4: table does not exist"));
    }

    #[test]
    fn real_teardown_errors_are_still_failures() {
        assert!(!is_missing_table_error("Operation not permitted"));
        assert!(!is_missing_table_error(
            "RTNETLINK answers: Invalid argument"
        ));
        // «таблица не существует» без ipv4 — не наш случай, такое молча
        // проглатывать нельзя.
        assert!(!is_missing_table_error("table does not exist"));
    }
}
