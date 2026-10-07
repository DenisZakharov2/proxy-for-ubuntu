//! Клиент управляющего сокета демона.
//!
//! Живёт в библиотеке, потому что им пользуются и GUI, и `pfu-cli` —
//! оба должны говорить с демоном на одном языке, иначе расходятся версии.

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::error::{Error, Result};
use crate::paths;

/// Выполняет метод демона и возвращает `result`.
///
/// Отдельные ошибки прозрачно отличаются: `E_NO_DAEMON` доходит до GUI как
/// подсказка «запустите systemctl», а `E_CONFIG_INVALID` — как список полей.
pub async fn call(method: &str, params: Value) -> Result<Value> {
    let path = paths::ctl_socket();
    if !path.exists() {
        return Err(Error::NoDaemon(format!(
            "управляющий сокет {} не найден. Демон не запущен?",
            path.display()
        )));
    }

    let stream = tokio::net::UnixStream::connect(&path).await.map_err(|e| {
        Error::NoDaemon(format!("не удалось подключиться к {}: {e}", path.display()))
    })?;

    let (read, mut write) = stream.into_split();
    let request = serde_json::json!({ "method": method, "params": params });
    let mut buf = serde_json::to_vec(&request).map_err(Error::from)?;
    buf.push(b'\n');
    write.write_all(&buf).await?;
    write.flush().await?;

    let mut lines = BufReader::new(read).lines();
    let line = lines
        .next_line()
        .await
        .map_err(Error::from)?
        .ok_or_else(|| Error::NoDaemon("демон закрыл соединение без ответа".into()))?;

    let resp: Value = serde_json::from_str(&line)?;
    if resp
        .get("api")
        .and_then(Value::as_u64)
        .is_some_and(|v| v > crate::API_VERSION as u64)
    {
        tracing::warn!("демон новее GUI: обновите пакет");
    }
    if resp.get("ok").and_then(Value::as_bool) == Some(false) {
        return Err(decode_error(&resp));
    }
    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

/// Разбирает ошибку демона обратно в тип нашей библиотеки, чтобы GUI получил
/// подсказку и код этапа, а не голый текст.
fn decode_error(resp: &Value) -> Error {
    let e = resp.get("error").cloned().unwrap_or(Value::Null);
    let code = e
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("E_INTERNAL");
    let msg = e
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("неизвестная ошибка демона")
        .to_string();
    let hint = e
        .get("hint")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    let base = match code {
        "E_NO_DAEMON" => Error::NoDaemon(msg),
        "E_CONFIG_INVALID" => Error::ConfigInvalid(msg),
        "E_NO_OUTBOUND" => Error::NoOutbound,
        "E_PROBE_FAILED" => Error::ProbeFailed(msg),
        "E_ROLLED_BACK" => Error::RolledBack(msg),
        "E_PERM" => Error::Permission(msg),
        "E_NOT_FOUND" => Error::NotFound(msg),
        "E_REJECT" => Error::Reject(msg),
        _ => Error::Internal(msg),
    };
    if hint.is_empty() {
        base
    } else {
        // Подсказку не теряем: она объясняет пользователю, что делать дальше.
        Error::Internal(format!("{base}\n  {hint}"))
    }
}

/// Проверяет, отвечает ли демон. Используется GUI при старте, чтобы сразу
/// показать понятное сообщение, а не пустые экраны.
pub async fn is_alive() -> bool {
    call("daemon.status", serde_json::json!({})).await.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_known_codes() {
        let resp = serde_json::json!({
            "ok": false,
            "error": { "code": "E_NO_OUTBOUND", "message": "нет прокси" }
        });
        assert!(matches!(decode_error(&resp), Error::NoOutbound));

        let resp = serde_json::json!({
            "ok": false,
            "error": { "code": "E_NOT_FOUND", "message": "нет такого профиля" }
        });
        assert!(matches!(decode_error(&resp), Error::NotFound(_)));
    }

    #[test]
    fn unknown_code_degrades_to_internal() {
        let resp =
            serde_json::json!({ "ok": false, "error": { "code": "E_WHAT", "message": "?" } });
        assert!(matches!(decode_error(&resp), Error::Internal(_)));
    }

    #[tokio::test]
    async fn daemon_reachable_or_cleanly_unavailable() {
        // Тест не должен зависеть от того, запущен ли демон на этой машине:
        // либо отвечает настоящий демон, либо приходит понятная ошибка.
        // Второе важнее — «зависнуть молча» здесь нельзя.
        match call("daemon.status", serde_json::json!({})).await {
            Ok(v) => assert_eq!(v.get("daemon").and_then(|d| d.as_str()), Some("running")),
            Err(e) => {
                assert_eq!(e.code(), "E_NO_DAEMON", "{e}");
                assert!(e.hint().is_some(), "у ошибки должна быть подсказка");
            }
        }
    }
}
