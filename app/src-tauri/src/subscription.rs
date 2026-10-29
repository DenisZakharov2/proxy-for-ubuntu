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

use crate::config::Outbound;
use crate::link::{self, LinkError};

/// Ответ подписки ограничен: 1 МиБ. Реальная подписка на сотни серверов —
/// десятки килобайт; всё, что больше, — либо ошибка, либо атака.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

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
}

impl SubscriptionError {
    pub fn code(&self) -> &'static str {
        match self {
            SubscriptionError::Empty => "E_SUB_EMPTY",
            SubscriptionError::TooLarge => "E_SUB_TOO_LARGE",
            SubscriptionError::NoLinks => "E_SUB_NO_LINKS",
        }
    }
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
}
