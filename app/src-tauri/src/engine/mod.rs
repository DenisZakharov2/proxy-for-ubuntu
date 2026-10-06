//! Движок: правила, исходящие соединения, перехват трафика, DNS.
//!
//! Модуль собирает всё воедино и не содержит привилегированных вызовов
//! напрямую — они живут в [`crate::supervisor`]. Это позволяет держать
//! движок полностью тестируемым без root.

pub mod dns;
pub mod geo;
pub mod nft;
pub mod outbound;
pub mod router;
pub mod rules;
pub mod stats;
pub mod tls;

/// HTTP-клиент для обновления geo-наборов и подписок. Один на процесс:
/// переиспользование соединений к одному и тому же CDN заметно ускоряет
/// обновление десятков наборов.
pub fn http_client() -> crate::error::Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("proxy-for-ubuntu/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(60))
        .connect_timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| crate::error::Error::Internal(format!("не удалось создать HTTP-клиент: {e}")))
}
