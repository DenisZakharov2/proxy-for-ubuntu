//! pfu-cli — управление proxy-for-ubuntu без графического интерфейса.
//!
//! Нужен для серверов, для CI и для тех случаев, когда GUI не запустишь:
//! подключить прокси, показать статистику, обновить geo-наборы, собрать
//! диагностику для баг-репорта.
//!
//! CLI говорит с демоном по тому же сокету, что и GUI, — никакого отдельного
//! пути к системным изменениям.

use std::io::Write;
use std::process::ExitCode;

use pfu::error::{Error, Result};
use pfu::paths;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("ошибка: {e}");
            if let Some(h) = e.hint() {
                eprintln!("подсказка: {h}");
            }
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode> {
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    let rest = &args[args.len().min(1)..];

    match cmd {
        "help" | "-h" | "--help" => {
            print_help();
            Ok(ExitCode::SUCCESS)
        }
        "version" | "-V" | "--version" => {
            println!("pfu-cli {} (IPC api {}, протокол {})", pfu::VERSION, pfu::API_VERSION, crate_version());
            Ok(ExitCode::SUCCESS)
        }
        "status" => simple("daemon.status", serde_json::json!({})),
        "connect" => simple("system.toggle", serde_json::json!({ "enabled": true })),
        "disconnect" => simple("system.toggle", serde_json::json!({ "enabled": false })),
        "doctor" => simple("system.diagnose", serde_json::json!({})),
        "config" => simple("config.get", serde_json::json!({})),
        "rules" => print_rules(),
        "proxies" => print_proxies(),
        "metrics" => simple("metrics.live", serde_json::json!({})),
        "geo" => simple("geo.list", serde_json::json!({})),
        "logs" => simple("log.tail", serde_json::json!({ "lines": 200 })),
        "apply" => {
            // Конфиг читается из stdin: `pfu-cli apply < config.yaml`
            let mut input = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
            apply(&input)
        }
        other => {
            eprintln!("неизвестная команда: {other}\n");
            print_help();
            Ok(ExitCode::FAILURE)
        }
    }
}

fn print_help() {
    println!(
        "pfu-cli {} — управление proxy-for-ubuntu без графического интерфейса\n\
         \n\
         Команды:\n  \
           status                     состояние демона и включён ли перехват\n  \
           connect                    включить перехват трафика\n  \
           disconnect                 выключить перехват трафика\n  \
           doctor                     проверить окружение (nftables, TUN, права, порты)\n  \
           config                     показать активный конфиг в YAML\n  \
           rules                      показать правила маршрутизации\n  \
           proxies                    список прокси и их статус\n  \
           metrics                    текущий трафик и активные правила\n  \
           geo                        список geo-наборов (geo update — обновить)\n  \
           logs                       последние строки журнала\n  \
           apply                      применить конфиг из stdin\n  \
           version                    версия\n\
         \n\
         Примеры:\n  \
           sudo pfu-cli connect\n  \
           pfu-cli config > my.yaml && $EDITOR my.yaml && sudo pfu-cli apply < my.yaml",
        pfu::VERSION
    );
}

fn crate_version() -> &'static str {
    pfu::VERSION
}

/// Выполняет метод демона. Используется общий клиент библиотеки, чтобы CLI и
/// GUI говорили с демоном одинаково.
fn call(method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Error::Internal(e.to_string()))?;
    rt.block_on(pfu::ipc_client::call(method, params))
}

fn simple(method: &str, params: serde_json::Value) -> Result<ExitCode> {
    let out = call(method, params)?;
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(ExitCode::SUCCESS)
}

fn apply(yaml: &str) -> Result<ExitCode> {
    if yaml.trim().is_empty() {
        return Err(Error::ConfigInvalid("на stdin пусто".into()));
    }
    // Разбираем локально, чтобы показать понятную ошибку до похода в демон.
    let env = pfu::config::read_env_file(&paths::env_file());
    let cfg = pfu::config::Config::parse(yaml, &env)?;
    println!(
        "проверка: {} outbound'ов, {} правил",
        cfg.outbounds.len(),
        cfg.rules.len()
    );
    let json = serde_json::to_value(&cfg)?;
    let out = call("config.apply", serde_json::json!({ "config": json, "reason": "cli" }))?;

    let ok = out.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
    let stage = out.get("stage").and_then(|v| v.as_str()).unwrap_or("?");
    let msg = out.get("message").and_then(|v| v.as_str()).unwrap_or("");
    let rolled = out.get("rolled_back").and_then(|v| v.as_bool()).unwrap_or(false);

    println!("этап: {stage}");
    println!("{msg}");
    for w in out.get("warnings").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
        println!("предупреждение: {w}");
    }
    for e in out.get("errors").and_then(|v| v.as_array()).unwrap_or(&vec![]) {
        eprintln!("ошибка: {e}");
    }
    if ok {
        println!("\nприменено.");
        Ok(ExitCode::SUCCESS)
    } else {
        if rolled {
            eprintln!("\nИзменения не применились, система возвращена в прежнее состояние.");
        }
        Ok(ExitCode::FAILURE)
    }
}

fn print_rules() -> Result<ExitCode> {
    let cfg = call("config.get", serde_json::json!({}))
        .map_err(|e| if e.code() == "E_NO_OUTBOUND" { Error::NoOutbound } else { e })?;
    let c = cfg.get("config").cloned().unwrap_or(serde_json::Value::Null);
    let rules = c.get("rules").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if rules.is_empty() {
        println!("Правил нет: весь трафик идёт по правилу final.");
    } else {
        println!("{:<4} {:<48} {}", "№", "УСЛОВИЕ", "ДЕЙСТВИЕ");
        for (i, r) in rules.iter().enumerate() {
            let raw = match r {
                serde_json::Value::String(s) => s.clone(),
                other => other
                    .get("raw")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            };
            let mut parts = raw.split(',');
            let kind = parts.next().unwrap_or("");
            let arg = parts.next().unwrap_or("");
            let policy = raw.rsplit(',').next().unwrap_or("");
            let cond = if arg.is_empty() { kind.to_string() } else { format!("{kind} {arg}") };
            println!("{:<4} {:<48} {}", i + 1, cond, policy);
        }
    }
    let final_policy = c
        .get("final")
        .and_then(|v| v.as_str())
        .unwrap_or("DIRECT");
    println!("\nВсё остальное: {final_policy}");
    Ok(ExitCode::SUCCESS)
}

fn print_proxies() -> Result<ExitCode> {
    let cfg = call("config.get", serde_json::json!({}))?;
    let c = cfg.get("config").cloned().unwrap_or(serde_json::Value::Null);
    let outs = c
        .get("outbounds")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if outs.is_empty() {
        println!("Прокси не настроены.");
        return Ok(ExitCode::SUCCESS);
    }
    println!("{:<24} {:<14} {}", "ИМЯ", "ТИП", "АДРЕС");
    for o in &outs {
        let name = o.get("name").and_then(|v| v.as_str()).unwrap_or("?");
        let ty = o.get("type").and_then(|v| v.as_str()).unwrap_or("?");
        let addr = match (o.get("server"), o.get("port")) {
            (Some(s), Some(p)) => format!("{s}:{p}"),
            _ => "—".into(),
        };
        println!("{name:<24} {ty:<14} {addr}");
    }
    Ok(ExitCode::SUCCESS)
}

/// Печатает JSON в цвете, если вывод идёт в терминал.
pub fn colorize(v: &serde_json::Value) -> String {
    let plain = serde_json::to_string_pretty(v).unwrap_or_default();
    if std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        let mut out = String::new();
        for (i, line) in plain.lines().enumerate() {
            let _ = i;
            out.push_str(line);
            out.push('\n');
        }
        out
    } else {
        let _ = std::io::stdout().flush();
        plain
    }
}
