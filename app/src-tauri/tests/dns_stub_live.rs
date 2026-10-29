//! Живой тест перехвата системного резолвера (`127.0.0.53:53`).
//!
//! В CI не запускается: нужен root, nftables и две netns. Стенд поднимается
//! скриптом `материалы сессии 19/dns-stub-stand.sh`, тест выполняется внутри
//! клиентской namespace:
//!
//! ```text
//! ip netns exec pfu-dns <test-binary> --ignored --nocapture --test-threads=1
//! ```
//!
//! Что доказывается: запрос приложения к системному резолверу перехватывается
//! правилом nat output, уходит вышестоящему DNS (`dns.servers`) через
//! выбранный правилами outbound, ответ возвращается приложению с адреса
//! `127.0.0.53:53`, а пара «адрес → домен» попадает в карту движка.
//!
//! Ответы на стенде разные намеренно: локальная заглушка резолвера отвечает
//! `203.0.113.99`, вышестоящий DNS — `203.0.113.1`. Если перехват не
//! сработает, тест увидит `.99` и упадёт — пройти «мимо» он не может.

use std::sync::atomic::Ordering;

use pfu::config::Config;
use pfu::engine::capture;
use pfu::engine::geo::GeoRegistry;
use pfu::engine::nft;
use pfu::engine::router::Engine;

/// Адрес, который слушает systemd-resolved (на стенде — его заглушка).
const RESOLVED: &str = "127.0.0.53";
/// Ответ локальной заглушки: признак того, что перехват не сработал.
const LOCAL_ANSWER: &str = "203.0.113.99";
/// Ответ настоящего вышестоящего DNS из серверной netns.
const UPSTREAM_ANSWER: &str = "203.0.113.1";

const RULES: &str = r#"
intercept: {tcp: redirect, udp: off}
dns:
  strategy: redir-host
  intercept_stub: true
  servers: ["203.0.113.53"]
rules:
  - DOMAIN-SUFFIX,blocked.test,REJECT
  - MATCH,DIRECT
outbounds:
  - {name: DIRECT, type: direct}
  - {name: PROXY, type: socks5h, server: 203.0.113.9, port: 1080}
"#;

/// То же, но перехват системного резолвера выключен — контрольный опыт.
const RULES_STUB_OFF: &str = r#"
intercept: {tcp: redirect, udp: off}
dns:
  strategy: redir-host
  intercept_stub: false
  servers: ["203.0.113.53"]
rules:
  - MATCH,DIRECT
outbounds:
  - {name: DIRECT, type: direct}
  - {name: PROXY, type: socks5h, server: 203.0.113.9, port: 1080}
"#;

/// `HIJACK-DNS`: ответ собирает сам демон, наружу запрос не уходит.
const RULES_HIJACK: &str = r#"
intercept: {tcp: redirect, udp: off}
dns:
  strategy: redir-host
  intercept_stub: true
  servers: ["203.0.113.53"]
rules:
  - DST-PORT,53,HIJACK-DNS
  - MATCH,DIRECT
outbounds:
  - {name: DIRECT, type: direct}
  - {name: PROXY, type: socks5h, server: 203.0.113.9, port: 1080}
"#;

async fn stand(rules: &str) -> (std::sync::Arc<Engine>, capture::Capture) {
    let cfg =
        Config::parse(rules, &std::collections::HashMap::new()).expect("конфиг стенда валиден");
    let engine = Engine::build(cfg.clone(), &GeoRegistry::load(&[])).expect("движок собран");
    engine.enabled.store(true, Ordering::Relaxed);
    let capture = capture::start(engine.clone())
        .await
        .expect("слушатели подняты");
    nft::apply(&nft::build_plan(&cfg))
        .await
        .expect("правила применены");
    (engine, capture)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен root и стенд материалы сессии 19/dns-stub-stand.sh"]
async fn stub_query_goes_through_upstream() {
    let (engine, mut capture) = stand(RULES).await;

    let out = run_client("echo.dns.test").await;
    let mapped = engine.dns.name_of(UPSTREAM_ANSWER.parse().unwrap());
    let rows = engine.breakdown.snapshot();

    capture.stop().await;
    nft::teardown().await.expect("правила сняты");

    assert_eq!(
        out.trim(),
        format!("rcode=0 source={RESOLVED}:53 answers={UPSTREAM_ANSWER}"),
        "приложение должно получить ответ вышестоящего DNS через демон: {out}"
    );
    assert_eq!(
        mapped.as_deref(),
        Some("echo.dns.test"),
        "карта «IP → домен» не заполнена из перехваченного ответа"
    );
    assert!(
        rows.iter().any(|r| r.policy == "DIRECT" && r.bytes > 0),
        "DNS-запрос не попал в статистику по правилам: {rows:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен root и стенд материалы сессии 19/dns-stub-stand.sh"]
async fn without_stub_the_local_resolver_answers() {
    let (engine, mut capture) = stand(RULES_STUB_OFF).await;

    let out = run_client("echo.dns.test").await;
    let mapped = engine.dns.name_of(LOCAL_ANSWER.parse().unwrap());

    capture.stop().await;
    nft::teardown().await.expect("правила сняты");

    // Контрольный опыт: без перехвата отвечает локальная заглушка. Значит,
    // первый тест доказывает именно перехват, а не «и так работает».
    assert_eq!(
        out.trim(),
        format!("rcode=0 source={RESOLVED}:53 answers={LOCAL_ANSWER}"),
        "без перехвата должен ответить локальный резолвер: {out}"
    );
    assert!(
        mapped.is_none(),
        "карта заполнилась, хотя перехват выключен"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен root и стенд материалы сессии 19/dns-stub-stand.sh"]
async fn rejected_name_returns_servfail() {
    let (_engine, mut capture) = stand(RULES).await;

    let out = run_client("blocked.test").await;

    capture.stop().await;
    nft::teardown().await.expect("правила сняты");

    assert_eq!(
        out.trim(),
        format!("rcode=2 source={RESOLVED}:53 answers=-"),
        "REJECT должен вернуть SERVFAIL сразу, а не молчание: {out}"
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен root и стенд материалы сессии 19/dns-stub-stand.sh"]
async fn hijack_dns_answers_locally() {
    let (_engine, mut capture) = stand(RULES_HIJACK).await;

    // `localhost` есть в /etc/hosts: такой ответ может дать только сам демон.
    let out = run_client("localhost").await;

    capture.stop().await;
    nft::teardown().await.expect("правила сняты");

    assert_eq!(
        out.trim(),
        format!("rcode=0 source={RESOLVED}:53 answers=127.0.0.1"),
        "HIJACK-DNS должен отвечать локально: {out}"
    );
}

/// Клиент от uid 1000: трафик root'а исключён правилом `meta skuid != 0`,
/// поэтому проверять надо обычного пользователя.
async fn run_client(name: &str) -> String {
    let out = tokio::process::Command::new("setpriv")
        .args([
            "--reuid",
            "1000",
            "--regid",
            "1000",
            "--clear-groups",
            "python3",
            "-c",
            CLIENT,
            RESOLVED,
            name,
        ])
        .output()
        .await
        .expect("python-клиент запущен");
    if !out.status.success() {
        panic!(
            "клиент завершился с ошибкой: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Подключённый UDP-сокет: ответ принимается только с того адреса:порта, куда
/// сокет подключён. Поэтому печатается и источник — перехват обязан вернуть
/// его как `127.0.0.53:53`.
const CLIENT: &str = r#"
import socket, struct, sys
server, name = sys.argv[1], sys.argv[2]
q = b"\x12\x34\x01\x00" + struct.pack("!HHHH", 1, 0, 0, 0)
for part in name.split("."):
    q += bytes([len(part)]) + part.encode()
q += b"\x00" + struct.pack("!HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(6)
s.connect((server, 53))
s.send(q)
try:
    data, src = s.recvfrom(4096)
except socket.timeout:
    print("rcode=- source=- answers=timeout")
    sys.exit(2)
rcode = data[3] & 0x0F
an = struct.unpack("!H", data[6:8])[0]
i = 12
while data[i]:
    i += 1 + data[i]
i += 5
ips = []
for _ in range(an):
    if data[i] & 0xC0 == 0xC0:
        i += 2
    else:
        while data[i]:
            i += 1 + data[i]
        i += 1
    rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[i:i + 10])
    i += 10
    if rtype == 1 and rdlen == 4:
        ips.append(socket.inet_ntoa(data[i:i + 4]))
    i += rdlen
print(f"rcode={rcode} source={src[0]}:{src[1]} answers={','.join(ips) or '-'}")
"#;
