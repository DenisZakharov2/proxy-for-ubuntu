//! Разбор тела подписки: списки ссылок, base64-список и YAML конфига.
//!
//! Подписки в природе встречаются в трёх видах, и определять их надо по
//! содержимому, а не по расширению или Content-Type — продавцы отдают
//! `text/plain` и для base64, и для открытого списка:
//!
//! 1. **YAML** конфига proxy-for-ubuntu (то, что уже умел `subscription.update`)
//! 2. **открытый список** ссылок, по одной в строке
//! 3. **base64** от такого списка (самый частый вариант V2Ray-подписок)
//!
//! Главный принцип: одна битая строка не отменяет импорт. Пользователь
//! получает «принято N, отклонено M» с номерами строк и причинами, а не
//! сообщение «подписка не разобрана».

use std::path::{Path, PathBuf};

use crate::config::Outbound;
use crate::link::{self, LinkError};

/// Ответ подписки ограничен: 1 МиБ. Реальная подписка на сотни серверов —
/// десятки килобайт; всё, что больше, — либо ошибка, либо атака.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Длина URL подписки. Реальный URL — десятки байт; килобайт означает, что в
/// поле вставили что-то не то.
pub const MAX_URL_LEN: usize = 2048;

/// Интервал обновления по умолчанию, часы (`REQ-005`: «по умолчанию 24 ч»).
pub const DEFAULT_INTERVAL_HOURS: u64 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionFormat {
    /// YAML конфига: разбирается не здесь, а `Config::parse`.
    Yaml,
    /// Открытый список ссылок.
    LinkList,
    /// base64 от списка ссылок.
    Base64LinkList,
}

impl SubscriptionFormat {
    pub fn as_str(&self) -> &'static str {
        match self {
            SubscriptionFormat::Yaml => "yaml",
            SubscriptionFormat::LinkList => "link-list",
            SubscriptionFormat::Base64LinkList => "base64-link-list",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedLine {
    /// Номер строки в теле подписки (для base64 — в декодированном тексте).
    pub line: usize,
    pub code: &'static str,
    pub reason: String,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedSubscription {
    pub format: Option<SubscriptionFormat>,
    pub outbounds: Vec<Outbound>,
    pub rejected: Vec<RejectedLine>,
}

impl ParsedSubscription {
    pub fn accepted(&self) -> usize {
        self.outbounds.len()
    }

    /// Человеческая строка для GUI: «принято 3, отклонено 1».
    pub fn summary(&self) -> String {
        format!(
            "принято {}, отклонено {}",
            self.outbounds.len(),
            self.rejected.len()
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubscriptionError {
    #[error("ответ подписки пуст")]
    Empty,
    #[error("ответ подписки больше {MAX_BODY_BYTES} байт")]
    TooLarge,
    #[error("в подписке нет ни одной ссылки и это не YAML-конфиг")]
    NoLinks,
    #[error("URL подписки не указан")]
    UrlEmpty,
    #[error("URL подписки длиннее {MAX_URL_LEN} байт")]
    UrlTooLong,
    #[error("подписка загружается только по http или https, а не {0:?}")]
    UrlScheme(String),
    #[error("в URL подписки нет адреса сервера")]
    UrlNoHost,
}

impl SubscriptionError {
    pub fn code(&self) -> &'static str {
        match self {
            SubscriptionError::Empty => "E_SUB_EMPTY",
            SubscriptionError::TooLarge => "E_SUB_TOO_LARGE",
            SubscriptionError::NoLinks => "E_SUB_NO_LINKS",
            SubscriptionError::UrlEmpty => "E_SUB_URL_EMPTY",
            SubscriptionError::UrlTooLong => "E_SUB_URL_TOO_LONG",
            SubscriptionError::UrlScheme(_) => "E_SUB_URL_SCHEME",
            SubscriptionError::UrlNoHost => "E_SUB_URL_NO_HOST",
        }
    }
}

/// Проверка URL до сетевого запроса.
///
/// `file://` и `data:` здесь не «просто не поддерживаются»: подмена URL
/// подписки на локальный файл — это чтение произвольного файла с правами root
/// по команде из GUI. Схема проверяется до `reqwest`, а не после.
pub fn validate_url(url: &str) -> Result<(), SubscriptionError> {
    let url = url.trim();
    if url.is_empty() {
        return Err(SubscriptionError::UrlEmpty);
    }
    if url.len() > MAX_URL_LEN {
        return Err(SubscriptionError::UrlTooLong);
    }
    let parsed = url::Url::parse(url).map_err(|_| SubscriptionError::UrlScheme(url.to_string()))?;
    match parsed.scheme() {
        "http" | "https" => {}
        other => return Err(SubscriptionError::UrlScheme(other.to_string())),
    }
    if parsed.host_str().unwrap_or("").is_empty() {
        return Err(SubscriptionError::UrlNoHost);
    }
    Ok(())
}

/// Похоже ли тело на YAML конфига proxy-for-ubuntu.
///
/// Проверяем не «валидный ли это YAML» (для этого есть `Config::parse`), а
/// наличие ключа `outbounds:`, который в подписке-списке ссылок не встречается.
fn looks_like_yaml(body: &str) -> bool {
    body.lines()
        .take(200)
        .any(|line| line.trim_start().starts_with("outbounds:"))
}

/// Пытается декодировать тело как base64-список ссылок.
fn decode_base64_body(body: &str) -> Option<String> {
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.len() < 16 {
        return None;
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(cleaned.as_str()) {
            if let Ok(text) = String::from_utf8(bytes) {
                if text.contains("://") {
                    return Some(text);
                }
            }
        }
    }
    None
}

/// Разбирает тело подписки. YAML не парсится здесь: возвращается только
/// формат и пустой список, решение принимает вызывающий код.
pub fn parse_body(body: &str) -> Result<ParsedSubscription, SubscriptionError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(SubscriptionError::TooLarge);
    }
    let body = body.trim();
    if body.is_empty() {
        return Err(SubscriptionError::Empty);
    }

    if looks_like_yaml(body) {
        return Ok(ParsedSubscription {
            format: Some(SubscriptionFormat::Yaml),
            outbounds: Vec::new(),
            rejected: Vec::new(),
        });
    }

    let (format, text) = match decode_base64_body(body) {
        Some(decoded) => (SubscriptionFormat::Base64LinkList, decoded),
        None => (SubscriptionFormat::LinkList, body.to_string()),
    };

    let mut parsed = ParsedSubscription {
        format: Some(format),
        outbounds: Vec::new(),
        rejected: Vec::new(),
    };

    for (index, raw) in text.lines().enumerate() {
        let line_no = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        match link::parse(line) {
            Ok(outbound) => parsed.outbounds.push(outbound),
            Err(err) => parsed.rejected.push(RejectedLine {
                line: line_no,
                code: err.code(),
                reason: err.to_string(),
            }),
        }
    }

    if parsed.outbounds.is_empty() && parsed.rejected.is_empty() {
        return Err(SubscriptionError::NoLinks);
    }
    Ok(parsed)
}

/// Объединяет новые серверы с существующими, не теряя рабочие и не создавая
/// двух серверов с одинаковым именем (иначе правило не поймёт, какой имелся
/// в виду). Совпадение определяется по имени; конфликт разрешается суффиксом.
pub fn merge_outbounds(existing: &[Outbound], incoming: Vec<Outbound>) -> Vec<Outbound> {
    let mut result: Vec<Outbound> = existing.to_vec();
    for mut candidate in incoming {
        let base = candidate.name().to_string();
        let mut name = base.clone();
        let mut counter = 2;
        while result.iter().any(|ob| ob.name() == name) {
            name = format!("{base} ({counter})");
            counter += 1;
            if counter > 99 {
                break;
            }
        }
        if name != base {
            rename(&mut candidate, &name);
        }
        result.push(candidate);
    }
    result
}

fn rename(outbound: &mut Outbound, name: &str) {
    use crate::config::Outbound::*;
    match outbound {
        Direct(o) => o.name = name.into(),
        Http(o) => o.name = name.into(),
        Socks(o) => o.name = name.into(),
        Shadowsocks(o) => o.name = name.into(),
        Trojan(o) => o.name = name.into(),
        Vless(o) => o.name = name.into(),
        Vmess(o) => o.name = name.into(),
        Ssh(o) => o.name = name.into(),
    }
}

/// Удобная обёртка для отчёта об импорте: причина отказа без секрета.
pub fn rejection_note(err: &LinkError) -> String {
    format!("{}: {}", err.code(), err)
}

// ───────────────────────── реестр подписок ─────────────────────────

/// Что известно о подписке между запусками демона.
///
/// Без этой записи «обновление по расписанию» невозможно: после перезапуска
/// демон не знает ни URL, ни когда обновление удалось в последний раз, и
/// либо не обновляет ничего, либо обновляет всё при каждом старте.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SubscriptionRecord {
    /// Имя профиля, в который пишется подписка.
    pub name: String,
    pub url: String,
    #[serde(default = "default_interval_hours")]
    pub interval_hours: u64,
    /// Unix-время последнего **успешного** обновления; 0 — ещё ни разу.
    #[serde(default)]
    pub last_success_unix: i64,
    #[serde(default)]
    pub last_attempt_unix: i64,
    /// Причина последней неудачи — без URL с токеном и без секретов.
    #[serde(default)]
    pub last_error: Option<String>,
}

fn default_interval_hours() -> u64 {
    DEFAULT_INTERVAL_HOURS
}

impl SubscriptionRecord {
    pub fn new(name: &str, url: &str, interval_hours: u64) -> Self {
        Self {
            name: name.to_string(),
            url: url.to_string(),
            interval_hours: if interval_hours == 0 {
                DEFAULT_INTERVAL_HOURS
            } else {
                interval_hours
            },
            last_success_unix: 0,
            last_attempt_unix: 0,
            last_error: None,
        }
    }

    /// Пора ли обновлять. Ноль в `last_success_unix` — «ещё ни разу», значит
    /// пора; интервал 0 трактуется как значение по умолчанию, а не как
    /// «дёргать сервер на каждом витке таймера».
    pub fn due(&self, now_unix: i64) -> bool {
        if self.url.trim().is_empty() {
            return false;
        }
        if self.last_success_unix <= 0 {
            return true;
        }
        let interval = self.interval_hours.max(1) as i64;
        now_unix.saturating_sub(self.last_success_unix) >= interval * 3600
    }
}

/// Файл реестра подписок рядом с профилями пользователя.
pub fn store_path() -> PathBuf {
    crate::paths::user_profiles_dir().join("subscriptions.json")
}

/// Читает реестр. Битый или отсутствующий файл — пустой реестр, а не ошибка:
/// сломанный реестр не должен мешать демону стартовать.
pub fn load_store(path: &Path) -> Vec<SubscriptionRecord> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Записывает реестр атомарно (`tempfile` + `rename`).
pub fn save_store(path: &Path, records: &[SubscriptionRecord]) -> crate::Result<()> {
    if let Some(dir) = path.parent() {
        crate::paths::ensure_dir(dir)?;
    }
    let text = serde_json::to_vec_pretty(records)?;
    crate::paths::atomic_write(path, &text)
}

/// Вставляет запись или обновляет существующую с тем же именем. Одна
/// подписка — один профиль, иначе два таймера пишут в один файл.
pub fn upsert_record(records: &mut Vec<SubscriptionRecord>, record: SubscriptionRecord) {
    match records.iter_mut().find(|r| r.name == record.name) {
        Some(slot) => *slot = record,
        None => records.push(record),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;

    const VLESS: &str =
        "vless://11111111-1111-1111-1111-111111111111@example.net:443?security=tls#A";
    const TROJAN: &str = "trojan://secret@203.0.113.4:443#B";

    #[test]
    fn plain_list_parses_all_lines() {
        let body = format!("{VLESS}\n{TROJAN}\n");
        let parsed = parse_body(&body).expect("список должен разобраться");
        assert_eq!(parsed.format, Some(SubscriptionFormat::LinkList));
        assert_eq!(parsed.accepted(), 2);
        assert!(parsed.rejected.is_empty());
    }

    #[test]
    fn base64_list_is_detected_and_parsed() {
        let raw = format!("{VLESS}\n{TROJAN}");
        let body = STANDARD.encode(raw.as_bytes());
        let parsed = parse_body(&body).expect("base64 должен распознаться");
        assert_eq!(parsed.format, Some(SubscriptionFormat::Base64LinkList));
        assert_eq!(parsed.accepted(), 2);
    }

    #[test]
    fn one_bad_line_does_not_break_import() {
        let body = format!("{VLESS}\nне-ссылка\n{TROJAN}");
        let parsed = parse_body(&body).expect("импорт не должен падать");
        assert_eq!(parsed.accepted(), 2);
        assert_eq!(parsed.rejected.len(), 1);
        assert_eq!(parsed.rejected[0].line, 2);
        assert_eq!(parsed.rejected[0].code, "E_LINK_MALFORMED");
        assert!(parsed.summary().contains("принято 2"));
    }

    #[test]
    fn comments_and_blank_lines_are_skipped() {
        let body = format!("# подписка\n\n{VLESS}\n// служебная строка\n");
        let parsed = parse_body(&body).expect("комментарии пропускаются");
        assert_eq!(parsed.accepted(), 1);
        assert!(parsed.rejected.is_empty());
    }

    #[test]
    fn yaml_subscription_is_recognised_not_parsed() {
        let body = "api: 1\noutbounds:\n  - name: DIRECT\n    type: direct\n";
        let parsed = parse_body(body).expect("YAML распознаётся");
        assert_eq!(parsed.format, Some(SubscriptionFormat::Yaml));
        assert!(parsed.outbounds.is_empty());
    }

    #[test]
    fn empty_and_oversized_bodies_are_rejected() {
        assert_eq!(parse_body("   ").unwrap_err().code(), "E_SUB_EMPTY");
        let huge = "a".repeat(MAX_BODY_BYTES + 1);
        assert_eq!(parse_body(&huge).unwrap_err().code(), "E_SUB_TOO_LARGE");
    }

    #[test]
    fn body_without_any_link_reports_every_line_rejected() {
        // Тело без ссылок — не «пустая подписка», а набор строк, каждая из
        // которых отклонена с причиной. Так пользователь видит, что именно
        // не так, вместо общего «подписка не разобрана».
        let parsed = parse_body("просто текст без ссылок").expect("тело читается");
        assert_eq!(parsed.accepted(), 0);
        assert_eq!(parsed.rejected.len(), 1);
        assert_eq!(parsed.rejected[0].code, "E_LINK_MALFORMED");
    }

    #[test]
    fn body_with_only_comments_has_no_links() {
        assert_eq!(
            parse_body("# только комментарий\n\n").unwrap_err().code(),
            "E_SUB_NO_LINKS"
        );
    }

    #[test]
    fn merge_keeps_existing_and_renames_duplicates() {
        let existing = vec![link::parse(VLESS).expect("vless")];
        let incoming = vec![link::parse(VLESS).expect("vless")];
        let merged = merge_outbounds(&existing, incoming);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[1].name(), "A (2)");
    }

    #[test]
    fn merge_does_not_touch_non_conflicting_names() {
        let existing = vec![link::parse(VLESS).expect("vless")];
        let incoming = vec![link::parse(TROJAN).expect("trojan")];
        let merged = merge_outbounds(&existing, incoming);
        assert_eq!(merged[1].name(), "B");
    }

    #[test]
    fn url_scheme_is_checked_before_the_request() {
        assert!(validate_url("https://example.net/sub?token=abc").is_ok());
        assert!(validate_url("http://127.0.0.1:8080/sub").is_ok());
        // file:// — это чтение произвольного файла с правами демона.
        for bad in [
            "file:///etc/shadow",
            "data:text/plain,vless://x",
            "gopher://example.net/",
            "",
            "   ",
            "https://",
        ] {
            let err = validate_url(bad).expect_err("схема должна быть отклонена");
            assert!(
                matches!(
                    err,
                    SubscriptionError::UrlScheme(_)
                        | SubscriptionError::UrlEmpty
                        | SubscriptionError::UrlNoHost
                ),
                "{bad:?} дал {err:?}"
            );
        }
        let long = format!("https://example.net/{}", "a".repeat(MAX_URL_LEN));
        assert_eq!(
            validate_url(&long).unwrap_err().code(),
            "E_SUB_URL_TOO_LONG"
        );
    }

    #[test]
    fn record_is_due_only_after_the_interval() {
        let mut record = SubscriptionRecord::new("sub", "https://example.net/s", 24);
        // Ни разу не обновлялась — обновляем при первой возможности.
        assert!(record.due(1_000_000));
        record.last_success_unix = 1_000_000;
        assert!(!record.due(1_000_000));
        assert!(!record.due(1_000_000 + 23 * 3600));
        assert!(record.due(1_000_000 + 24 * 3600));
        // Интервал из конфига уважается: 1 час — это не 24.
        record.interval_hours = 1;
        assert!(record.due(1_000_000 + 3600));
        // Пустой URL — нечего обновлять, даже если срок вышел.
        record.url = String::new();
        assert!(!record.due(9_999_999));
    }

    #[test]
    fn zero_interval_means_default_not_hammering() {
        let record = SubscriptionRecord::new("sub", "https://example.net/s", 0);
        assert_eq!(record.interval_hours, DEFAULT_INTERVAL_HOURS);
    }

    #[test]
    fn store_roundtrip_and_upsert_by_name() {
        let dir = std::env::temp_dir().join(format!("pfu-sub-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("subscriptions.json");

        // Отсутствующий файл — пустой реестр, а не ошибка.
        assert!(load_store(&path).is_empty());

        let mut records = vec![SubscriptionRecord::new("sub", "https://a.example/1", 24)];
        records[0].last_success_unix = 42;
        upsert_record(
            &mut records,
            SubscriptionRecord::new("other", "https://b.example/2", 12),
        );
        assert_eq!(records.len(), 2);
        save_store(&path, &records).expect("запись реестра");

        let loaded = load_store(&path);
        assert_eq!(loaded, records);
        assert_eq!(loaded[0].last_success_unix, 42);

        // Одно имя — одна запись: таймер не должен задваивать профиль.
        let mut one = vec![SubscriptionRecord::new("sub", "https://a.example/1", 24)];
        let mut replacement = SubscriptionRecord::new("sub", "https://a.example/9", 6);
        replacement.last_success_unix = 77;
        upsert_record(&mut one, replacement);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].url, "https://a.example/9");
        assert_eq!(one[0].last_success_unix, 77);

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn broken_store_does_not_stop_the_daemon() {
        let dir = std::env::temp_dir().join(format!("pfu-sub-broken-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("subscriptions.json");
        std::fs::write(&path, "{ не json").expect("битый файл");
        assert!(load_store(&path).is_empty());
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
