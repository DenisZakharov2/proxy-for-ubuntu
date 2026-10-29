# Материалы сессии 12 (26 октября 2026)

Продолжение сессии 11: выпуск 0.1.3 по плану `../HANDOFF.md` §7.1.
Код — коммит `721d6d3`, тег `v0.1.3`.

## Что изменилось

| Пункт | Где |
|---|---|
| IPv6 больше не заворачивается в IPv4-слушатель: `meta nfproto ipv6 return` в трёх цепочках | `engine/nft.rs`, README, ARCHITECTURE (RU/EN) |
| Статистика по правилам: имя правила из `Engine::route/open`, запись при закрытии TCP и UDP | `engine/rules.rs`, `engine/router.rs`, `engine/capture.rs` |
| `daemon.status` отдаёт `engine_loaded` | `ipc.rs`, `docs/IPC.md`, `IPC.en.md` |
| `/dev/net/tun` не блокирует `--check` | `bin/daemon.rs` |
| Релиз грузит `.deb` только из джобы 22.04 | `.github/workflows/release.yml` |
| ROADMAP сверен с кодом | `ROADMAP.md` |

## Проверки

Регресс в `app/src-tauri`:

```
cargo fmt --all -- --check                  # OK
cargo clippy --all-targets -- -D warnings   # OK
cargo test                                  # 139 passed (было 137)
```

Живой TCP (отладочный демон 0.1.3, конфиг с одним DIRECT, перехват включён):

```
curl https://example.com                    # http=200
pfu-cli metrics
  active_rules: [{"rule": "FINAL", "policy": "DIRECT", "bytes": 46349}]
  by_outbound:  [{"name": "DIRECT", "bytes": 46349}]
  connections: 6, up: 8517, down: 37832
```

UDP-стенд из сессии 10 (два netns, получатель `198.51.100.1:9999`):

```
ip netns exec pfutest python3 pfu-udp-probe.py
  reply b'pong:ping-0' ... reply b'pong:ping-4' from ('198.51.100.1', 9999)
  replies: 5 of 5
```

После `disconnect` (поток UDP закрылся по отмене):

```
active_rules: [{"rule": "FINAL", "policy": "DIRECT", "bytes": 85}]  # 30 up + 55 down
```

Чистота после выключения: порты 15000/15001 закрыты, `ip rule fwmark 0x1`
нет, таблица 100 пуста, `curl` → 200.

`proxy-for-ubuntud --check` (не root, без `--strict`): exit 0, строка
`/dev/net/tun: есть (необязательно: TUN не реализован)`.

## Найденный дефект (не исправлялся)

На первом старте, пока таблица 100 ещё не создана, `teardown` пишет две
строки ERROR: `ip route flush table 100` → «FIB table does not exist».
Работе не мешает; записано в `../HANDOFF.md` §6.9 как P2 на 0.1.4.

## release/

`proxy-for-ubuntu_0.1.3_amd64.deb` (3 629 246 байт) и `.sha256`
(`802b0b1fd67e264923ca1653cc34f118ad87358d48b294bb2348a74ad0b856fd`) из
GitHub Release. `sha256sum -c` — OK, `pfu-cli version` из пакета печатает
`0.1.3`, пакет — `0.1.3-1`.

## Как повторить

```bash
cd <clone>/app/src-tauri
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo build --bins

systemctl stop proxy-for-ubuntud
systemd-run --system --collect --unit=pfu-devd13 --property=Restart=no \
  --property=LimitNOFILE=65536 "$PWD/target/debug/proxy-for-ubuntud" --daemon
./target/debug/pfu-cli connect
curl -m 8 -sS -o /dev/null -w 'http=%{http_code}\n' https://example.com
./target/debug/pfu-cli metrics
./target/debug/pfu-cli disconnect
systemctl start proxy-for-ubuntud
```
