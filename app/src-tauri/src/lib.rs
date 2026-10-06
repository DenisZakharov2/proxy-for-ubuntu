//! proxy-for-ubuntu — системная маршрутизация трафика через прокси.
//!
//! Крейт разделён на два процесса: GUI (`proxy-for-ubuntu`) и демон
//! (`proxy-for-ubuntud`). Общая логика движка лежит здесь и используется обоими,
//! а также CLI (`pfu-cli`) для headless-конфигурации.

pub mod config;
pub mod engine;
pub mod error;
pub mod ipc;
pub mod ipc_client;
pub mod paths;
pub mod supervisor;

pub use error::{Error, Result};

/// Версия пакета. Дублируется в `Cargo.toml` и в tauri.conf.json — расхождение
/// ловится тестом `test_version_consistency`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Версия IPC-контракта. Несовместимое изменение структур требует бамп-мажора.
pub const API_VERSION: u32 = 1;

/// Имя демона в systemd и его пользователь.
pub const DAEMON_NAME: &str = "proxy-for-ubuntud";
pub const DAEMON_USER: &str = "proxy-for-ubuntu";
pub const APP_NAME: &str = "proxy-for-ubuntu";
