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
}

/// Запускает python-клиента от uid 1000: трафик root'а исключён из перехвата
/// (`meta skuid 0 return`), поэтому проверять надо именно обычного пользователя.
async fn run_client(mode: &str) -> String {
    let script = r#"
import socket, sys, threading

mode, host = sys.argv[1], sys.argv[2]
if mode == "udp":
    payload = bytes((i * 7) % 251 for i in range(1200))
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)
    s.sendto(payload, (host, 9999))
    data, _ = s.recvfrom(4096)
    print("ok-udp" if data == payload else f"bad-udp {len(data)}", flush=True)
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
