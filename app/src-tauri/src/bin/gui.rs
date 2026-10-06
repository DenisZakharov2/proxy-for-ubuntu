//! Графическое приложение proxy-for-ubuntu.
//!
//! GUI не имеет никаких системных прав: единственная его привилегированная
//! возможность — `ipc`-команда, которая пересылает запрос в сокет демона.
//! Всё, что меняет сеть, делает демон от root.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};

/// Запрос к демону в формате docs/IPC.md.
#[derive(Debug, Deserialize)]
struct IpcRequest {
    #[allow(dead_code)]
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// Ответ демона, проксируемый фронтенду без изменений.
#[derive(Debug, Serialize)]
struct IpcResponse {
    id: Option<serde_json::Value>,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<serde_json::Value>,
    api: u32,
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![ipc])
        .run(tauri::generate_context!())
        .expect("не удалось запустить окно приложения");
}

/// Единственная команда фронтенда. Формат запроса и все коды ошибок заданы
/// в docs/IPC.md и дублируются в протоколе демона.
#[tauri::command]
async fn ipc(request: IpcRequest) -> IpcResponse {
    match pfu::ipc_client::call(&request.method, request.params).await {
        Ok(result) => IpcResponse {
            id: request.id,
            ok: true,
            result: Some(result),
            error: None,
            api: pfu::API_VERSION,
        },
        Err(e) => IpcResponse {
            id: request.id,
            ok: false,
            result: None,
            error: Some(serde_json::json!({
                "code": e.code(),
                "message": e.to_string(),
                "hint": e.hint(),
                "stage": e.stage(),
            })),
            api: pfu::API_VERSION,
        },
    }
}
