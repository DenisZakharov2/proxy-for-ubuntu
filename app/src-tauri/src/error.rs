//! Типизированные ошибки.
//!
//! Коды ошибок из этого enum попадают в GUI без преобразований (см. docs/IPC.md),
//! поэтому переименование варианта — ломающее изменение контракта.

use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("демон не отвечает: {0}")]
    NoDaemon(String),

    #[error("конфигурация некорректна: {0}")]
    ConfigInvalid(String),

    #[error("в конфигурации нет ни одного outbound")]
    NoOutbound,

    #[error("проверка соединения не пройдена: {0}")]
    ProbeFailed(String),

    #[error("сбой при применении конфигурации: {0}")]
    Apply(String),

    #[error("изменения откачены, система в прежнем состоянии: {0}")]
    RolledBack(String),

    #[error("недостаточно прав: {0}")]
    Permission(String),

    #[error("не найдено: {0}")]
    NotFound(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("tls: {0}")]
    Tls(String),

    #[error("протокол {proto}: {message}")]
    Protocol { proto: &'static str, message: String },

    #[error("таймаут: {0}")]
    Timeout(String),

    /// Соединение отклонено правилом маршрутизации. Это не ошибка, а штатное
    /// решение: в лог пишется отдельным уровнем, пользователю не показывается.
    #[error("отклонено правилом: {0}")]
    Reject(String),

    #[error("внутренняя ошибка: {0}")]
    Internal(String),
}

impl Error {
    /// Машиночитаемый код для IPC-ответа. Соответствует таблице в docs/IPC.md.
    pub fn code(&self) -> &'static str {
        match self {
            Error::NoDaemon(_) => "E_NO_DAEMON",
            Error::ConfigInvalid(_) => "E_CONFIG_INVALID",
            Error::NoOutbound => "E_NO_OUTBOUND",
            Error::ProbeFailed(_) => "E_PROBE_FAILED",
            Error::Apply(_) => "E_APPLY",
            Error::RolledBack(_) => "E_ROLLED_BACK",
            Error::Permission(_) => "E_PERM",
            Error::NotFound(_) => "E_NOT_FOUND",
            Error::Io(_) | Error::Yaml(_) | Error::Json(_) | Error::Internal(_) => "E_INTERNAL",
            Error::Tls(_) | Error::Protocol { .. } | Error::Timeout(_) => "E_PROBE_FAILED",
            Error::Reject(_) => "E_REJECT",
        }
    }

    /// Подсказка для пользователя: что конкретно сделать. Показывается в GUI
    /// под текстом ошибки, а не в логе.
    pub fn hint(&self) -> Option<String> {
        match self {
            Error::NoDaemon(_) => Some(
                "Запустите демон: sudo systemctl start proxy-for-ubuntud".into(),
            ),
            Error::Permission(_) => Some("Нужны права root. Проверьте, что демон запущен.".into()),
            Error::Tls(_) => Some(
                "Проверьте SNI и сертификат сервера. Временно можно включить \
                 skip_cert_verify, но это отключает проверку и небезопасно."
                    .into(),
            ),
            Error::Protocol { proto, .. } => {
                Some(format!("Проверьте параметры протокола {proto} и версию сервера."))
            }
            _ => None,
        }
    }

    /// Этап, на котором произошла ошибка — для поля `stage` в `config.apply`.
    pub fn stage(&self) -> &'static str {
        match self {
            Error::ConfigInvalid(_) | Error::NoOutbound => "validate",
            Error::ProbeFailed(_) => "probe",
            Error::RolledBack(_) => "health-check",
            _ => "commit",
        }
    }

    pub fn protocol(proto: &'static str, message: impl Into<String>) -> Self {
        Error::Protocol { proto, message: message.into() }
    }
}

impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Error::Internal(e.to_string())
    }
}

impl From<tokio::task::JoinError> for Error {
    fn from(e: tokio::task::JoinError) -> Self {
        Error::Internal(format!("task join: {e}"))
    }
}

impl From<rustls::Error> for Error {
    fn from(e: rustls::Error) -> Self {
        Error::Tls(e.to_string())
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(e: std::net::AddrParseError) -> Self {
        Error::ConfigInvalid(format!("некорректный адрес: {e}"))
    }
}

impl From<uuid::Error> for Error {
    fn from(e: uuid::Error) -> Self {
        Error::ConfigInvalid(format!("некорректный UUID: {e}"))
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Хелпер для ошибок протоколов с контекстом.
pub trait ProtocolExt<T> {
    fn proto_err(self, proto: &'static str) -> Result<T>;
}

impl<T, E: fmt::Display> ProtocolExt<T> for std::result::Result<T, E> {
    fn proto_err(self, proto: &'static str) -> Result<T> {
        self.map_err(|e| Error::protocol(proto, e.to_string()))
    }
}
