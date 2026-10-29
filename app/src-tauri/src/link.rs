//! Разбор ссылок-конфигов в `Outbound`.
//!
//! Пользователь приходит не с YAML, а со строкой от продавца прокси:
//! `vless://…`, `vmess://…`, `ss://…`, `trojan://…`. Здесь эта строка
//! превращается в обычный `Outbound`, который дальше живёт как любой другой
//! сервер из конфига.
//!
//! Правила, которые важнее удобства:
//!
//! 1. Неподдерживаемое **отклоняется с причиной**, а не подменяется молча.
//!    Например, `security=reality` или `type=grpc` наш движок не умеет —
//!    пользователь должен узнать это при импорте, а не при подключении.
//! 2. Секреты не попадают в `Debug`-вывод ошибок: сообщение содержит поле и
//!    причину, но не значение.
//! 3. Разбор не паникует на мусоре: любая строка возвращает `Result`.

use std::collections::HashMap;

use base64::Engine as _;
use percent_encoding::percent_decode_str;
use url::Url;

use crate::config::{
    Outbound, OutboundHttp, OutboundShadowsocks, OutboundSocks, OutboundTrojan, OutboundVless,
    OutboundVmess,
};

/// Верхняя граница длины ссылки. Реальная ссылка vmess со всеми полями —
/// меньше 2 КиБ; всё, что длиннее, почти наверняка не ссылка, а мусор.
pub const MAX_LINK_LEN: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LinkError {
    #[error("ссылка пустая")]
    Empty,
    #[error("ссылка длиннее {0} байт")]
    TooLong(usize),
    #[error("неизвестная схема {0:?}: поддержаны vless, vmess, ss, trojan, socks5, http")]
    UnknownScheme(String),
    #[error("не удалось разобрать ссылку: {0}")]
    Malformed(String),
    #[error("в ссылке нет UUID")]
    MissingUuid,
    #[error("в ссылке нет пароля")]
    MissingPassword,
    #[error("некорректный порт {0:?}")]
    BadPort(String),
    #[error("не поддерживается: {0}")]
    Unsupported(String),
}

impl LinkError {
    /// Короткий код для GUI и для отчёта об импорте подписки.
    pub fn code(&self) -> &'static str {
        match self {
            LinkError::Empty => "E_LINK_EMPTY",
            LinkError::TooLong(_) => "E_LINK_TOO_LONG",
            LinkError::UnknownScheme(_) => "E_LINK_SCHEME",
            LinkError::Malformed(_) => "E_LINK_MALFORMED",
            LinkError::MissingUuid => "E_LINK_NO_UUID",
            LinkError::MissingPassword => "E_LINK_NO_PASSWORD",
            LinkError::BadPort(_) => "E_LINK_BAD_PORT",
            LinkError::Unsupported(_) => "E_LINK_UNSUPPORTED",
        }
    }
}

/// Разбирает одну ссылку в `Outbound`.
pub fn parse(uri: &str) -> Result<Outbound, LinkError> {
    let uri = uri.trim();
    if uri.is_empty() {
        return Err(LinkError::Empty);
    }
    if uri.len() > MAX_LINK_LEN {
        return Err(LinkError::TooLong(uri.len()));
    }
    let (scheme, rest) = uri
        .split_once("://")
        .ok_or_else(|| LinkError::Malformed("нет схемы вида scheme://".into()))?;
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => parse_vless(uri),
        "vmess" => parse_vmess(rest),
        "ss" => parse_shadowsocks(rest),
        "trojan" => parse_trojan(uri),
        "socks5" | "socks5h" | "socks" => parse_socks(uri),
        "http" | "https" => parse_http(uri),
        other => Err(LinkError::UnknownScheme(other.into())),
    }
}

// ──────────────────────────────── helpers ────────────────────────────────

/// Достаёт тег из фрагмента `#…` и возвращает тело ссылки без фрагмента.
fn split_fragment(body: &str) -> (&str, Option<String>) {
    match body.split_once('#') {
        Some((head, tag)) => {
            let decoded = percent_decode_str(tag)
                .decode_utf8_lossy()
                .trim()
                .to_string();
            let tag = if decoded.is_empty() {
                None
            } else {
                Some(decoded)
            };
            (head, tag)
        }
        None => (body, None),
    }
}

/// Имя сервера: тег из ссылки, иначе схема и адрес — чтобы в списке было
/// что показать, даже если продавец не подписал сервер.
fn fallback_name(tag: Option<String>, kind: &str, host: &str, port: u16) -> String {
    match tag {
        Some(tag) => tag,
        None => format!("{kind}-{host}:{port}"),
    }
}

/// base64 в том виде, в каком его отдают подписки: с паддингом и без,
/// стандартный и url-safe. Все четыре варианта встречаются в дикой природе.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(cleaned.as_str()) {
            return Some(bytes);
        }
    }
    None
}

fn required_port(url: &Url) -> Result<u16, LinkError> {
    url.port().filter(|p| *p != 0).ok_or_else(|| {
        LinkError::BadPort(
            url.port()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "нет".into()),
        )
    })
}

fn query_map(url: &Url) -> HashMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.to_ascii_lowercase(), v.to_string()))
        .collect()
}

fn truthy(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes"
    )
}

/// Приводит `type` из ссылки к тому, что умеет движок: `tcp`/пусто → `None`,
/// `ws` → `Some("ws")`, остальное — отказ с причиной.
fn transport_of(raw: Option<&String>) -> Result<Option<String>, LinkError> {
    match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("tcp") | Some("none") => Ok(None),
        Some("ws") | Some("websocket") => Ok(Some("ws".into())),
        Some(other) => Err(LinkError::Unsupported(format!(
            "транспорт {other:?}; движок умеет tcp и ws"
        ))),
    }
}

// ──────────────────────────────── vless ────────────────────────────────

fn parse_vless(uri: &str) -> Result<Outbound, LinkError> {
    let url = Url::parse(uri).map_err(|e| LinkError::Malformed(e.to_string()))?;
    let uuid = percent_decode_str(url.username())
        .decode_utf8_lossy()
        .to_string();
    if uuid.trim().is_empty() {
        return Err(LinkError::MissingUuid);
    }
    let host = url
        .host_str()
        .ok_or_else(|| LinkError::Malformed("нет адреса сервера".into()))?
        .to_string();
    let port = required_port(&url)?;
    let q = query_map(&url);

    let security = q.get("security").map(String::as_str).unwrap_or("none");
    if security == "reality" {
        return Err(LinkError::Unsupported(
            "vless reality (pbk/sid/fp) — движок пока не умеет".into(),
        ));
    }
    let tls = matches!(security, "tls" | "xtls");
    let network = transport_of(q.get("type"))?;

    let name = fallback_name(split_fragment(uri).1, "vless", &host, port);
    Ok(Outbound::Vless(OutboundVless {
        name,
        server: host,
        port,
        uuid,
        flow: q.get("flow").cloned().unwrap_or_default(),
        network,
        tls,
        sni: q
            .get("sni")
            .or_else(|| q.get("peer"))
            .cloned()
            .unwrap_or_default(),
        path: q.get("path").cloned().unwrap_or_default(),
        host: q.get("host").cloned().unwrap_or_default(),
        skip_cert_verify: q.get("allowinsecure").map(|v| truthy(v)).unwrap_or(false),
        udp: true,
        test_url: None,
        test_timeout_ms: None,
    }))
}

// ──────────────────────────────── vmess ────────────────────────────────

fn parse_vmess(rest: &str) -> Result<Outbound, LinkError> {
    let (body, tag) = split_fragment(rest);
    let decoded =
        decode_base64(body).ok_or_else(|| LinkError::Malformed("vmess: тело не base64".into()))?;
    let text = String::from_utf8(decoded)
        .map_err(|_| LinkError::Malformed("vmess: base64 не UTF-8".into()))?;
    let value: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| LinkError::Malformed(format!("vmess: JSON не разобран: {e}")))?;

    let str_of = |key: &str| -> String {
        match value.get(key) {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Number(n)) => n.to_string(),
            _ => String::new(),
        }
    };

    let uuid = str_of("id");
    if uuid.trim().is_empty() {
        return Err(LinkError::MissingUuid);
    }
    let host = str_of("add");
    if host.trim().is_empty() {
        return Err(LinkError::Malformed("vmess: нет адреса сервера".into()));
    }
    let port_raw = str_of("port");
    let port: u16 = port_raw
        .trim()
        .parse()
        .map_err(|_| LinkError::BadPort(port_raw.clone()))?;
    if port == 0 {
        return Err(LinkError::BadPort(port_raw));
    }

    let net = if str_of("net").is_empty() {
        None
    } else {
        Some(str_of("net"))
    };
    let network = transport_of(net.as_ref())?;
    let tls = matches!(
        str_of("tls").to_ascii_lowercase().as_str(),
        "tls" | "reality"
    );
    if str_of("tls").eq_ignore_ascii_case("reality") {
        return Err(LinkError::Unsupported(
            "vmess reality — движок не умеет".into(),
        ));
    }

    let alter_id = str_of("aid").trim().parse().unwrap_or(0);
    let security = {
        let s = str_of("scy");
        if s.trim().is_empty() {
            "auto".to_string()
        } else {
            s
        }
    };
    let name = fallback_name(
        Some(if str_of("ps").is_empty() {
            tag.unwrap_or_default()
        } else {
            str_of("ps")
        }),
        "vmess",
        &host,
        port,
    );

    Ok(Outbound::Vmess(OutboundVmess {
        name,
        server: host,
        port,
        uuid,
        alter_id,
        security,
        network,
        tls,
        sni: str_of("sni"),
        path: str_of("path"),
        host: str_of("host"),
        skip_cert_verify: false,
        udp: true,
        test_url: None,
        test_timeout_ms: None,
    }))
}

// ──────────────────────────────── shadowsocks ────────────────────────────────

fn parse_shadowsocks(rest: &str) -> Result<Outbound, LinkError> {
    let (body, tag) = split_fragment(rest);
    let body = body.trim();

    // Три исторических формы:
    //   1. ss://base64(method:password)@host:port      (SIP002)
    //   2. ss://method:password@host:port              (SIP002 без base64)
    //   3. ss://base64(method:password@host:port)      (legacy)
    let (userinfo, hostport) = if let Some((left, right)) = body.rsplit_once('@') {
        (left.to_string(), right.to_string())
    } else {
        let decoded =
            decode_base64(body).ok_or_else(|| LinkError::Malformed("ss: тело не base64".into()))?;
        let text = String::from_utf8(decoded)
            .map_err(|_| LinkError::Malformed("ss: base64 не UTF-8".into()))?;
        text.rsplit_once('@')
            .map(|(l, r)| (l.to_string(), r.to_string()))
            .ok_or_else(|| LinkError::Malformed("ss: нет разделителя @".into()))?
    };

    let userinfo = if userinfo.contains(':') {
        percent_decode_str(&userinfo)
            .decode_utf8_lossy()
            .to_string()
    } else {
        let decoded = decode_base64(&userinfo)
            .ok_or_else(|| LinkError::Malformed("ss: userinfo не base64".into()))?;
        String::from_utf8(decoded)
            .map_err(|_| LinkError::Malformed("ss: userinfo не UTF-8".into()))?
    };

    let (method, password) = userinfo
        .split_once(':')
        .ok_or_else(|| LinkError::Malformed("ss: нет method:password".into()))?;
    if method.trim().is_empty() {
        return Err(LinkError::Malformed("ss: пустой метод шифрования".into()));
    }
    if password.is_empty() {
        return Err(LinkError::MissingPassword);
    }

    let (host, port_raw) = split_host_port(&hostport)?;
    let port: u16 = port_raw
        .parse()
        .map_err(|_| LinkError::BadPort(port_raw.clone()))?;
    if port == 0 {
        return Err(LinkError::BadPort(port_raw));
    }

    let name = fallback_name(tag, "ss", &host, port);
    Ok(Outbound::Shadowsocks(OutboundShadowsocks {
        name,
        server: host,
        port,
        method: method.to_string(),
        password: password.to_string(),
        plugin: String::new(),
        udp: true,
        test_url: None,
        test_timeout_ms: None,
    }))
}

/// `host:port`, где host может быть в квадратных скобках для IPv6.
fn split_host_port(input: &str) -> Result<(String, String), LinkError> {
    let input = input.trim();
    if let Some(rest) = input.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| LinkError::Malformed("незакрытая скобка IPv6".into()))?;
        let port = tail
            .strip_prefix(':')
            .ok_or_else(|| LinkError::BadPort("нет порта".into()))?;
        return Ok((host.to_string(), port.to_string()));
    }
    match input.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && !port.is_empty() => {
            Ok((host.to_string(), port.to_string()))
        }
        _ => Err(LinkError::BadPort(input.to_string())),
    }
}

// ──────────────────────────────── trojan ────────────────────────────────

fn parse_trojan(uri: &str) -> Result<Outbound, LinkError> {
    let url = Url::parse(uri).map_err(|e| LinkError::Malformed(e.to_string()))?;
    let password = percent_decode_str(url.username())
        .decode_utf8_lossy()
        .to_string();
    if password.trim().is_empty() {
        return Err(LinkError::MissingPassword);
    }
    let host = url
        .host_str()
        .ok_or_else(|| LinkError::Malformed("нет адреса сервера".into()))?
        .to_string();
    let port = required_port(&url)?;
    let q = query_map(&url);
    let name = fallback_name(split_fragment(uri).1, "trojan", &host, port);

    Ok(Outbound::Trojan(OutboundTrojan {
        name,
        server: host,
        port,
        password,
        sni: q
            .get("sni")
            .or_else(|| q.get("peer"))
            .cloned()
            .unwrap_or_default(),
        alpn: q
            .get("alpn")
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_else(|| vec!["h2".into(), "http/1.1".into()]),
        skip_cert_verify: q.get("allowinsecure").map(|v| truthy(v)).unwrap_or(false),
        udp: true,
        test_url: None,
        test_timeout_ms: None,
    }))
}

// ──────────────────────────────── socks / http ────────────────────────────────

fn parse_socks(uri: &str) -> Result<Outbound, LinkError> {
    let url = Url::parse(uri).map_err(|e| LinkError::Malformed(e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| LinkError::Malformed("нет адреса сервера".into()))?
        .to_string();
    let port = url.port().unwrap_or(1080);
    let name = fallback_name(split_fragment(uri).1, "socks5", &host, port);
    Ok(Outbound::Socks(OutboundSocks {
        name,
        server: host,
        port,
        username: percent_decode_str(url.username())
            .decode_utf8_lossy()
            .to_string(),
        password: url
            .password()
            .map(|p| percent_decode_str(p).decode_utf8_lossy().to_string())
            .unwrap_or_default(),
        udp: true,
        remote_dns: true,
        test_url: None,
        test_timeout_ms: None,
    }))
}

fn parse_http(uri: &str) -> Result<Outbound, LinkError> {
    let url = Url::parse(uri).map_err(|e| LinkError::Malformed(e.to_string()))?;
    let host = url
        .host_str()
        .ok_or_else(|| LinkError::Malformed("нет адреса сервера".into()))?
        .to_string();
    let port = url.port().unwrap_or(8080);
    let name = fallback_name(split_fragment(uri).1, "http", &host, port);
    Ok(Outbound::Http(OutboundHttp {
        name,
        server: host,
        port,
        username: percent_decode_str(url.username())
            .decode_utf8_lossy()
            .to_string(),
        password: url
            .password()
            .map(|p| percent_decode_str(p).decode_utf8_lossy().to_string())
            .unwrap_or_default(),
        password_file: None,
        test_url: None,
        test_timeout_ms: None,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(input: &str) -> String {
        use base64::engine::general_purpose::STANDARD;
        STANDARD.encode(input)
    }

    #[test]
    fn vless_tls_ws_is_parsed() {
        let outbound = parse(
            "vless://11111111-1111-1111-1111-111111111111@example.net:443?type=ws&security=tls&sni=example.net&path=%2Fws&host=example.net#%D0%9C%D0%BE%D1%81%D0%BA%D0%B2%D0%B0",
        )
        .expect("vless должен разобраться");
        match outbound {
            Outbound::Vless(v) => {
                assert_eq!(v.server, "example.net");
                assert_eq!(v.port, 443);
                assert_eq!(v.uuid, "11111111-1111-1111-1111-111111111111");
                assert_eq!(v.network.as_deref(), Some("ws"));
                assert!(v.tls);
                assert_eq!(v.sni, "example.net");
                assert_eq!(v.path, "/ws");
                assert_eq!(v.name, "Москва");
            }
            other => panic!("ожидался vless, получено {:?}", other.kind()),
        }
    }

    #[test]
    fn vless_plain_tcp_has_no_transport() {
        let outbound =
            parse("vless://11111111-1111-1111-1111-111111111111@192.0.2.10:8080?security=none")
                .expect("vless без TLS");
        match outbound {
            Outbound::Vless(v) => {
                assert_eq!(v.network, None);
                assert!(!v.tls);
                assert_eq!(v.name, "vless-192.0.2.10:8080");
            }
            other => panic!("ожидался vless, получено {:?}", other.kind()),
        }
    }

    #[test]
    fn vless_reality_is_rejected_with_reason() {
        let err = parse(
            "vless://11111111-1111-1111-1111-111111111111@example.net:443?security=reality&pbk=x",
        )
        .expect_err("reality не поддерживается");
        assert_eq!(err.code(), "E_LINK_UNSUPPORTED");
        assert!(err.to_string().contains("reality"), "{err}");
    }

    #[test]
    fn vless_grpc_is_rejected_with_reason() {
        let err = parse(
            "vless://11111111-1111-1111-1111-111111111111@example.net:443?type=grpc&security=tls",
        )
        .expect_err("grpc не поддерживается");
        assert_eq!(err.code(), "E_LINK_UNSUPPORTED");
    }

    #[test]
    fn vmess_json_is_parsed() {
        let json = r#"{"v":"2","ps":"Токио","add":"198.51.100.7","port":"8443","id":"22222222-2222-2222-2222-222222222222","aid":"0","scy":"auto","net":"ws","path":"/v","host":"cdn.example","tls":"tls","sni":"cdn.example"}"#;
        let outbound = parse(&format!("vmess://{}", b64(json))).expect("vmess должен разобраться");
        match outbound {
            Outbound::Vmess(v) => {
                assert_eq!(v.name, "Токио");
                assert_eq!(v.server, "198.51.100.7");
                assert_eq!(v.port, 8443);
                assert_eq!(v.network.as_deref(), Some("ws"));
                assert!(v.tls);
                assert_eq!(v.path, "/v");
                assert_eq!(v.host, "cdn.example");
            }
            other => panic!("ожидался vmess, получено {:?}", other.kind()),
        }
    }

    #[test]
    fn vmess_without_padding_is_parsed() {
        let json = r#"{"ps":"x","add":"198.51.100.8","port":443,"id":"33333333-3333-3333-3333-333333333333"}"#;
        let encoded = b64(json).trim_end_matches('=').to_string();
        let outbound = parse(&format!("vmess://{encoded}")).expect("vmess без паддинга");
        match outbound {
            Outbound::Vmess(v) => assert_eq!(v.port, 443),
            other => panic!("ожидался vmess, получено {:?}", other.kind()),
        }
    }

    #[test]
    fn shadowsocks_sip002_and_legacy_are_equal() {
        let sip002 = "ss://YWVzLTI1Ni1nY206c2VjcmV0LXBhc3M=@203.0.113.5:8388#Первый";
        let legacy = format!("ss://{}", b64("aes-256-gcm:secret-pass@203.0.113.5:8388"));
        for uri in [sip002, legacy.as_str()] {
            match parse(uri).expect("ss должен разобраться") {
                Outbound::Shadowsocks(s) => {
                    assert_eq!(s.server, "203.0.113.5");
                    assert_eq!(s.port, 8388);
                    assert_eq!(s.method, "aes-256-gcm");
                    assert_eq!(s.password, "secret-pass");
                }
                other => panic!("ожидался ss, получено {:?}", other.kind()),
            }
        }
    }

    #[test]
    fn shadowsocks_plain_userinfo_is_parsed() {
        match parse("ss://aes-128-gcm:pass123@203.0.113.6:9000").expect("ss plain") {
            Outbound::Shadowsocks(s) => assert_eq!(s.method, "aes-128-gcm"),
            other => panic!("ожидался ss, получено {:?}", other.kind()),
        }
    }

    #[test]
    fn trojan_is_parsed_with_alpn() {
        match parse("trojan://secret@203.0.113.9:443?sni=t.example&alpn=h2,http/1.1#Т")
            .expect("trojan")
        {
            Outbound::Trojan(t) => {
                assert_eq!(t.password, "secret");
                assert_eq!(t.sni, "t.example");
                assert_eq!(t.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
            }
            other => panic!("ожидался trojan, получено {:?}", other.kind()),
        }
    }

    #[test]
    fn socks_and_http_defaults_apply() {
        assert!(matches!(
            parse("socks5://user:pass@203.0.113.2").expect("socks"),
            Outbound::Socks(_)
        ));
        assert!(matches!(
            parse("http://203.0.113.3:3128").expect("http"),
            Outbound::Http(_)
        ));
    }

    #[test]
    fn garbage_is_rejected_without_panic() {
        for bad in [
            "",
            "   ",
            "не ссылка",
            "vless://",
            "vless://@example.net:443",
            "vmess://не-base64",
            "ss://%%%",
            "trojan://203.0.113.1:443",
            "ftp://example.net",
            "vless://11111111-1111-1111-1111-111111111111@example.net:0",
        ] {
            let err = parse(bad).expect_err(&format!("должно быть отклонено: {bad:?}"));
            assert!(!err.to_string().is_empty());
        }
    }

    #[test]
    fn huge_input_is_rejected_before_parsing() {
        let long = format!("vless://{}", "a".repeat(MAX_LINK_LEN + 1));
        assert_eq!(
            parse(&long).expect_err("слишком длинная").code(),
            "E_LINK_TOO_LONG"
        );
    }
}
