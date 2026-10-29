//! Живая проверка TUN-стека в одноразовом netns-стенде.
//!
//! В CI не запускается: нужен root, `/dev/net/tun` и две сетевые namespace
//! (клиент с TUN и сервер с адресом 203.0.113.1). Стенд поднимается скриптом
//! `материалы сессии 15/tun-stand.sh`; сам тест выполняется внутри
//! клиентской namespace командой
//!
//! ```text
//! ip netns exec pfu-tun <test-binary> --ignored --nocapture
//! ```
//!
//! Проверяются оба протокола настоящими пакетами: UDP-датаграмма и TCP-сессия
//! на 256 КБ проходят через `pfu0`, userspace-стек открывает соединение
//! движком, гоняет данные в обе стороны и закрывает поток по FIN.

use std::sync::atomic::Ordering;
use std::time::Duration;

use pfu::config::{Config, TcpMode, UdpMode};
use pfu::engine::capture;
use pfu::engine::geo::GeoRegistry;
use pfu::engine::nft;
use pfu::engine::router::Engine;

const TARGET: &str = "203.0.113.1";

#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен root, /dev/net/tun и стенд материалы сессии 15/tun-stand.sh"]
async fn tun_udp_and_tcp_roundtrip() {
    let mut cfg = Config::default();
    cfg.intercept.tcp = TcpMode::Redirect;
    cfg.intercept.udp = UdpMode::Off;
    cfg.tun.enabled = true;
    cfg.tun.device = "pfu0".into();
    cfg.tun.mtu = 1500;
    cfg.tun.address = "198.18.0.1/15".into();
    cfg.validate_for_read().expect("конфиг стенда валиден");

    let engine = Engine::build(cfg.clone(), &GeoRegistry::load(&[])).expect("движок собран");
    engine.enabled.store(true, Ordering::Relaxed);

    // Сначала устройство и маршрут, потом правила: иначе метка отправила бы
    // пакеты в таблицу 101, где ещё нет маршрута.
    let mut capture = capture::start(engine.clone())
        .await
        .expect("TUN и слушатели подняты");
    nft::apply(&nft::build_plan(&cfg))
        .await
        .expect("правила применены");

    let udp = run_client("udp").await;
    let tcp = run_client("tcp").await;

    // Сколько байт реально прошло через устройство. Без этой проверки
    // «успех» мог бы означать, что трафик ушёл по обычному маршруту мимо
    // TUN: клиент и сервер соединены напрямую, и эхо вернулось бы всё равно.
    let through_tun = stat("rx_bytes") + stat("tx_bytes");

    // Снимаем всё до проверок: стенд одноразовый, но правила должны уйти
    // в любом случае.
    capture.stop().await;
    let teardown = nft::teardown().await;
    let leftover_link = std::process::Command::new("ip")
        .args(["link", "show", "pfu0"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    let leftover_rules = std::process::Command::new("ip")
        .args(["rule", "show"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("fwmark 0x2"))
        .unwrap_or(false);
    let leftover_nft = std::process::Command::new("nft")
        .args(["list", "table", "inet", "pfu"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    assert_eq!(udp.trim(), "ok-udp", "UDP через TUN не вернулся: {udp}");
    assert_eq!(tcp.trim(), "ok-tcp", "TCP через TUN не вернулся: {tcp}");
    teardown.expect("правила сняты");
    assert!(!leftover_link, "устройство pfu0 осталось после остановки");
    assert!(
        !leftover_rules,
        "правило fwmark 0x2 осталось после teardown"
    );
    assert!(!leftover_nft, "таблица inet pfu осталась после teardown");
    assert!(
        through_tun >= 500_000,
        "через pfu0 прошло только {through_tun} байт — трафик шёл мимо TUN"
    );

    // Статистика: TCP закрылся штатно, UDP-поток записывается при остановке
    // перехвата. 256 КБ вверх и вниз плюс 1,2 КБ UDP.
    let (up, down, _) = engine.stats.snapshot();
    assert!(up >= 262_144, "учтено вверх только {up} байт");
    assert!(down >= 262_144, "учтено вниз только {down} байт");
    let rows = engine.breakdown.snapshot();
    assert!(
        rows.iter()
            .any(|r| r.policy == "DIRECT" && r.bytes >= 512 * 1024),
        "breakdown пуст или мал: {rows:?}"
    );
}

/// Конфиг стенда для DNS-проверок: правило по домену отклоняет соединение,
/// всё остальное идёт напрямую. Один прокси-аутбеунд нужен валидации.
const DNS_RULES_REJECT: &str = r#"
intercept: {tcp: redirect, udp: off}
tun: {enabled: true, device: pfu0, mtu: 1500, address: "198.18.0.1/15"}
dns: {strategy: redir-host}
rules:
  - DOMAIN-SUFFIX,echo.dns.test,REJECT
  - MATCH,DIRECT
outbounds:
  - {name: DIRECT, type: direct}
  - {name: PROXY, type: socks5h, server: 203.0.113.9, port: 1080}
"#;

/// То же, но DNS отвечает сам демон (`HIJACK-DNS`): запрос не уходит наружу.
const DNS_RULES_HIJACK: &str = r#"
intercept: {tcp: redirect, udp: off}
tun: {enabled: true, device: pfu0, mtu: 1500, address: "198.18.0.1/15"}
dns: {strategy: redir-host}
rules:
  - DST-PORT,53,HIJACK-DNS
  - MATCH,DIRECT
outbounds:
  - {name: DIRECT, type: direct}
  - {name: PROXY, type: socks5h, server: 203.0.113.9, port: 1080}
"#;

async fn stand(rules: &str) -> (std::sync::Arc<Engine>, capture::Capture, Config) {
    let cfg =
        Config::parse(rules, &std::collections::HashMap::new()).expect("конфиг стенда валиден");
    let engine = Engine::build(cfg.clone(), &GeoRegistry::load(&[])).expect("движок собран");
    engine.enabled.store(true, Ordering::Relaxed);
    let capture = capture::start(engine.clone())
        .await
        .expect("TUN и слушатели подняты");
    nft::apply(&nft::build_plan(&cfg))
        .await
        .expect("правила применены");
    (engine, capture, cfg)
}

/// Redir-host: приложение получает настоящий адрес, а следующее соединение
/// к этому адресу попадает под правило по домену.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен root, /dev/net/tun и стенд материалы сессии 16"]
async fn dns_redir_host_names_the_following_connection() {
    let (engine, mut capture, _cfg) = stand(DNS_RULES_REJECT).await;

    // Без DNS домен неизвестен — соединение по адресу проходит.
    let before = run_client("tcp_ok").await;
    // Настоящий DNS-ответ приходит через прокси и запоминается.
    let dns = run_client("dns").await;
    let name = engine.dns.name_of("203.0.113.1".parse().unwrap());
    // Теперь тот же адрес обязан попасть под DOMAIN-SUFFIX,…,REJECT.
    let after = run_client("tcp_reject").await;

    capture.stop().await;
    nft::teardown().await.expect("правила сняты");

    assert_eq!(before.trim(), "connected", "TCP до DNS: {before}");
    assert_eq!(dns.trim(), "ok-dns 203.0.113.1", "DNS-ответ: {dns}");
    assert_eq!(
        name.as_deref(),
        Some("echo.dns.test"),
        "карта «IP → домен» не заполнена"
    );
    assert_eq!(
        after.trim(),
        "rejected",
        "правило по домену не сработало: {after}"
    );
}

/// `HIJACK-DNS`: ответ собирает сам демон, запрос наружу не уходит.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "нужен root, /dev/net/tun и стенд материалы сессии 16"]
async fn dns_hijack_answers_without_upstream() {
    let (engine, mut capture, _cfg) = stand(DNS_RULES_HIJACK).await;
    // Имя есть только в /etc/hosts контейнера: ответ может дать лишь
    // локальный резолвер.
    let dns = run_client("dns_hijack").await;
    capture.stop().await;
    nft::teardown().await.expect("правила сняты");
    assert_eq!(dns.trim(), "ok-dns 127.0.0.1", "локальный ответ: {dns}");
    let _ = engine;
}

/// Запускает python-клиента от uid 1000: трафик root'а исключён из перехвата
/// (`meta skuid 0 return`), поэтому проверять надо именно обычного пользователя.
async fn run_client(mode: &str) -> String {
    let script = r#"
import socket, struct, sys, threading

mode, host = sys.argv[1], sys.argv[2]


def ask(name, qtype=1):
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    for part in name.split("."):
        q += bytes([len(part)]) + part.encode()
    q += b"\x00" + struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(q, (host, 53))
    data, _ = s.recvfrom(2048)
    i, ips, ancount = 12, [], struct.unpack("!H", data[6:8])[0]
    while data[i]:
        i += 1 + data[i]
    i += 5
    for _ in range(ancount):
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while data[i]:
                i += 1 + data[i]
            i += 1
        rtype, _, _, rdlen = struct.unpack("!HHIH", data[i:i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(data[i:i + 4]))
        i += rdlen
    print("ok-dns " + ",".join(ips) if ips else "bad-dns " + data.hex(), flush=True)


if mode == "udp":
    payload = bytes((i * 7) % 251 for i in range(1200))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(payload, (host, 9999))
    data, _ = s.recvfrom(4096)
    print("ok-udp" if data == payload else f"bad-udp {len(data)}", flush=True)
elif mode == "dns":
    ask("echo.dns.test")
elif mode == "dns_hijack":
    ask("localhost")
elif mode == "tcp_ok":
    s = socket.create_connection((host, 9998), timeout=5)
    print("connected", flush=True)
    s.close()
elif mode == "tcp_reject":
    try:
        s = socket.create_connection((host, 9998), timeout=5)
        s.close()
        print("connected", flush=True)
    except OSError:
        print("rejected", flush=True)
else:
    # 256 КБ: несколько десятков сегментов, окно 65 535 и закрытие по FIN.
    payload = bytes((i * 13) % 251 for i in range(256 * 1024))
    s = socket.create_connection((host, 9998), timeout=10)

    def sender():
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)

    t = threading.Thread(target=sender)
    t.start()
    got = bytearray()
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        got += chunk
    t.join()
    print("ok-tcp" if bytes(got) == payload else f"bad-tcp {len(got)} из {len(payload)}", flush=True)
"#;
    let out = tokio::process::Command::new("setpriv")
        .args([
            "--reuid",
            "1000",
            "--regid",
            "1000",
            "--clear-groups",
            "python3",
            "-c",
            script,
            mode,
            TARGET,
        ])
        .output()
        .await
        .expect("python-клиент запущен");
    if !out.status.success() {
        panic!(
            "клиент {mode} завершился с ошибкой: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Счётчик интерфейса из sysfs. `rx_bytes` — пакеты, записанные в устройство
/// из userspace, `tx_bytes` — прочитанные из него; для проверки «трафик шёл
/// через TUN» годится сумма.
fn stat(name: &str) -> u64 {
    std::fs::read_to_string(format!("/sys/class/net/pfu0/statistics/{name}"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}
