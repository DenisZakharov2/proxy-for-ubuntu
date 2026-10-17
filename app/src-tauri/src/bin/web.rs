//! pfu-web — отдельный непривилегированный процесс с веб-интерфейсом.
//! Вариант Б дорожной карты №17: HTTP только на 127.0.0.1, проксирует
//! JSON-RPC в démon по Unix-сокету, не требует root. Демон не меняется.

use axum::{
    extract::ConnectInfo,
    response::{Html, Json},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use serde_json::Value;
use std::net::SocketAddr;

use pfu::{ipc_client, API_VERSION};

/// Тело JSON-RPC-запроса от веб-интерфейса.
#[derive(Deserialize)]
struct RpcRequest {
    method: String,
    #[serde(default)]
    params: Value,
    #[serde(default)]
    id: Option<Value>,
}

/// Ответ в том же формате, что и IPC демонa.
#[derive(serde::Serialize)]
struct RpcResponse {
    id: Option<Value>,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Value>,
    api: u32,
}

/// HTML одной страницы. Встроено в бинарник — отдельных статических файлов
/// при доставке через deb-пакет таскать не нужно.
const INDEX_HTML: &str = r#"<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
title>proxy-for-ubuntu Web UI</title>
<style>
* { box-sizing: border-box; }
body { font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; background: #f2f2f7; color: #1d1d1f; }
header { background: #1d1d1f; color: #fff; padding: 14px 24px; font-size: 17px; font-weight: 600; }
main { max-width: 700px; margin: 0 auto; padding: 20px; }
.card { background: #fff; border-radius: 12px; padding: 16px 20px; margin: 12px 0; box-shadow: 0 1px 2px rgba(0,0,0,0.06); }
.card h2 { margin: 0 0 12px 0; font-size: 13px; text-transform: uppercase; letter-spacing: 0.08em; color: #6e6e73; }
.row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
.btn { border: none; border-radius: 8px; padding: 8px 14px; font-size: 14px; cursor: pointer; font-weight: 500; }
.btn.primary { background: #0a84ff; color: #fff; }
.btn.primary:disabled { opacity: 0.55; cursor: not-allowed; }
.btn.secondary { background: #f2f2f7; color: #1d1d1f; }
.btn.secondary:disabled { opacity: 0.55; cursor: not-allowed; }
.badge { display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px; font-weight: 600; }
.ok { background: #d4fcd8; color: #1e6b3a; }
.bad { background: #fecfd3; color: #c00; }
.metrics { display: flex; gap: 16px; margin-top: 8px; }
.metric { flex: 1; }
.metric .val { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
.metric .lbl { font-size: 12px; color: #6e6e73; }
pre { background: #f2f2f7; border-radius: 8px; padding: 12px; font-size: 12px; overflow: auto; max-height: 260px; }
#log { font-size: 13px; color: #6e6e73; min-height: 1.3em; margin-top: 6px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style>
</head>
<body>
<header>proxy-for-ubuntu Web UI</header>
<main>
<div class="card">
  <h2>Статус</h2>
  <div class="row">
    <span id="status" class="badge bad">запуск…</span>
    <span id="version" class="mono"></span>
    <button id="btnConnect" class="btn primary" disabled>Включить</button>
    <button id="btnDisconnect" class="btn secondary" disabled>Выключить</button>
  </div>
  <div id="log"></div>
</div>
<div class="card">
  <h2>Трафик</h2>
  <div class="metrics">
    <div class="metric"><div class="val" id="mUp">—</div><div class="lbl">вверх</div></div>
    <div class="metric"><div class="val" id="mDown">—</div><div class="lbl">вниз</div></div>
    <div class="metric"><div class="val" id="mConns">—</div><div class="lbl">соединений</div></div>
  </div>
</div>
<div class="card">
  <h2>Конфиг</h2>
  <button id="btnConfig" class="btn secondary">Показать конфигурацию</button>
  <pre id="config" style="display:none"></pre>
</div>
</main>
<script>
let enabled = false;
async function rpc(method, params = {}) {
  const resp = await fetch("/rpc", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ method, params, id: 1 })
  });
  return resp.json();
}
function log(msg) { document.getElementById("log").textContent = msg; }
function setStatus(ok, text, ver) {
  const el = document.getElementById("status");
  el.textContent = text;
  el.className = "badge " + (ok ? "ok" : "bad");
  document.getElementById("version").textContent = ver ? "v" + ver : "";
  const c = document.getElementById("btnConnect");
  const d = document.getElementById("btnDisconnect");
  c.disabled = !ok || enabled;
  d.disabled = !ok || !enabled;
}
async function refresh() {
  try {
    const st = await rpc("daemon.status");
    if (st.ok) {
      enabled = st.result.enabled;
      setStatus(true, enabled ? "работает" : "остановлен", st.result.version);
      const met = await rpc("metrics.live");
      if (met.ok) {
        const m = met.result;
        document.getElementById("mUp").textContent = m.up;
        document.getElementById("mDown").textContent = m.down;
        document.getElementById("mConns").textContent = m.connections;
      }
    } else {
      setStatus(false, "демон недоступен", "");
      log("ошибка: " + (st.error && st.error.message || "неизвестно"));
    }
  } catch (e) {
    setStatus(false, "демон недоступен", "");
    log("сеть: " + e.message);
  }
}
document.getElementById("btnConnect").onclick = async () => {
  await rpc("system.toggle", { enabled: true });
  log("включаю…");
  refresh();
};
document.getElementById("btnDisconnect").onclick = async () => {
  await rpc("system.toggle", { enabled: false });
  log("выключаю…");
  refresh();
};
document.getElementById("btnConfig").onclick = async () => {
  const pre = document.getElementById("config");
  if (pre.style.display === "none") {
    pre.style.display = "block";
    const cfg = await rpc("config.get");
    pre.textContent = cfg.ok ? JSON.stringify(cfg.result.config, null, 2) : (cfg.error && cfg.error.message || "ошибка");
  } else {
    pre.style.display = "none";
  }
};
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>
"#;

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// Проксирует JSON-RPC в démon. Ошибки демона возвращаются в теле ответа с
/// ok: false, чтобы фронтенд мог показать подсказку (код, сообщение, hint).
async fn rpc_handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<RpcRequest>,
) -> Json<RpcResponse> {
    // Сервер слушает только на 127.0.0.1, но перепроверим на случай ошибки связи.
    if !addr.ip().is_loopback() {
        return Json(RpcResponse {
            id: req.id,
            ok: false,
            result: None,
            error: Some(serde_json::json!({
                "code": "E_FORBIDDEN",
                "message": "только локальные соединения"
            })),
            api: API_VERSION,
        });
    }
    match ipc_client::call(&req.method, req.params).await {
        Ok(value) => Json(RpcResponse {
            id: req.id,
            ok: true,
            result: Some(value),
            error: None,
            api: API_VERSION,
        }),
        Err(e) => Json(RpcResponse {
            id: req.id,
            ok: false,
            result: None,
            error: Some(serde_json::json!({
                "code": e.code(),
                "message": e.to_string(),
                "hint": e.hint(),
            })),
            api: API_VERSION,
        }),
    }
}

fn parse_port() -> u16 {
    let mut port: u16 = 17471;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" => {
                port = args
                    .get(i + 1)
                    .expect("--port требует значение")
                    .parse()
                    .expect("--port должен быть числом 1-65535");
                i += 2;
            }
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            other => {
                eprintln!("неизвестный аргумент: {other}");
                print_help();
                std::process::exit(1);
            }
        }
    }
    if let Ok(p) = std::env::var("PFU_WEB_PORT") {
        port = p.parse().expect("PFU_WEB_PORT должен быть числом");
    }
    port
}

fn print_help() {
    eprintln!(
        "pfu-web {} — веб-интерфейс proxy-for-ubuntu (вариант Б, без root)\n\
         \n\
         Использование:\n  pfu-web [--port <порт>] [--help]\n\
         Переменная PFU_WEB_PORT переопределяет порт.\n\
         HTTP слушает только 127.0.0.1; сокет démonа — /run/proxy-for-ubuntu/ctl.sock\n",
        pfu::VERSION
    );
}

#[tokio::main]
async fn main() {
    let port = parse_port();
    let app = Router::new()
        .route("/", get(index))
        .route("/rpc", post(rpc_handler));
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("не удалось слушать 127.0.0.1:{port}");
    tracing::info!(%addr, "pfu-web стартовал");
    axum::serve(listener, app)
        .await
        .expect("ошибка HTTP-сервера");
}
