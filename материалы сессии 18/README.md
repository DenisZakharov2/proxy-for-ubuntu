# Сессия 18 (29.10.2026): нагрузка, пересоздание TUN и `reload`

Стенд — две netns в привилегированном контейнере (как в сессиях 15–16) плюс
линк в root netns с masquerade: `supervisor.apply` при `reload` делает
health-check и probe, без интернета они падают и проверить пересоздание
нельзя.

| Файл | Что |
|---|---|
| `load-stand.sh` | `setup` / `serve` / `daemon` / `stop` / `teardown`; поднимает netns, veth, NAT и демон в клиентской netns |
| `load-echo.py` | эхо TCP `203.0.113.1:9998` (backlog 1024) и UDP `:9999` |
| `load-client.py` | `tcp-burst`, `tcp-hold --echo-every`, `udp-burst`; запускается от uid 1000 (`meta skuid 0 return` иначе пропустит root) |
| `reload-test.sh` | 50 соединений держатся, в середине SIGHUP: проверяет, что TUN и соединения выжили |
| `long-test.sh` | длинная сессия с echo каждые N секунд, SIGHUP на середине, сэмплы RSS/fd |
| `cycles-test.sh` | 5× (`connect`, повторный `connect`, трафик, `disconnect`) с проверкой остатков |
| `config.yaml` | конфиг стенда: TUN включён, `DIRECT` + `DIRECT2` (для строгой проверки `apply`) |

## Найдено

1. **`reload` рвал TUN и все соединения.** `Capture` владел и слушателями, и
   TUN: `sync_capture` на SIGHUP делал `stop()` → устройство удалялось,
   фоновые задачи TUN обрывались. Замер: 50 соединений → `after=0/50`.
   Комментарий в `ipc.rs` при этом обещал, что TUN и соединения сохраняются.
2. **`reload` не мог переподнять слушатели — `EADDRINUSE` на 15000.**
   `Capture::abort()` забирал `JoinHandle`-ы из `self.tasks`, и следующий за
   ним `for t in self.tasks.drain(..) { t.await }` был пустым: сокет ещё не
   закрыт, `bind` падает, перехват выключается целиком (`ERROR … Address
   already in use`).
3. **`reload` включал перехват, если он был выключен.** `reload_config`
   строил движок и безусловно писал `enabled = true`; после SIGHUP на
   выключенном демоне поднимались TUN и правила. Заодно `reload` при
   выключенном перехвате возвращал nftables и `ip rule` на место.
4. **`reload` с конфигом без прокси молча ничего не делал**: строгая
   `Config::validate` отвергала конфиг с единственным `DIRECT` — ровно тот,
   с которым `connect` работает. Теперь `reload` идёт мягкой проверкой
   (`apply_with(..., strict=false)`), `apply` из GUI остался строгим.
5. **`pfu-cli` паниковал на закрытом пайпе** (`pfu-cli status | head -1` →
   `failed printing to stdout: Broken pipe`). Rust игнорирует SIGPIPE;
   возвращён `SIG_DFL`, как у обычных unix-утилит.
6. **Флоу TUN после `reload` пишут статистику в старый движок.** Открытые до
   reload соединения живут на своём снимке движка; их байты не попадают в
   `metrics` нового. Осознанный компромисс: рвать их ради счётчиков хуже.

## Результаты (после исправлений)

| Проверка | Результат |
|---|---|
| 200 TCP × 8 КБ | 200/200, p50 46 мс, p95 82 мс, 0,36 с |
| 500 TCP × 4 КБ | 500/500, p50 42 мс, p95 66 мс, 0,67 с |
| UDP 100 сокетов × 20 датаграмм | 2000/2000, 0,36 с; 113 fd в работе, через 70 с простоя — 13 (idle-таймаут закрывает потоки) |
| Длинная сессия 300 с, 50 соединений, echo каждые 15 с | 20 раундов, 50/50 живых до конца, SIGHUP на 4-м раунде — соединения выжили, RSS 19,0 МБ и 63 fd стабильны |
| `reload` при 50 живых соединениях | pfu0 не пересоздавался, `after=50/50`, новое соединение сразу после — 5/5 |
| `reload` со сменой `tun.mtu` 1500 → 1400 | устройство пересоздано, MTU применён, трафик 20/20 |
| `reload` на выключенном перехвате | `enabled: false` остался, nft и `ip rule` не появились |
| 5 циклов `connect`/`disconnect` | каждый раз dev=1, ports=2, rules=2 после включения и 0/0/0 после выключения, трафик 20/20 |

## Как повторить

```bash
docker run -d --privileged --name pfu-load -v /dev/net/tun:/dev/net/tun \
  -v "/home/anony/Documents/Личное/Проект proxy for ubuntu:/src:ro" \
  ubuntu:24.04 sleep infinity
docker exec pfu-load bash -c 'apt-get update -qq && apt-get install -y -qq \
  iproute2 nftables python3 util-linux procps curl'
docker cp app/src-tauri/target/debug/pfu-cli pfu-load:/usr/local/bin/
docker cp app/src-tauri/target/debug/proxy-for-ubuntud pfu-load:/usr/local/bin/
docker exec pfu-load bash -c '
  chmod +x /usr/local/bin/pfu-cli /usr/local/bin/proxy-for-ubuntud
  bash "/src/материалы сессии 18/load-stand.sh" setup
  bash "/src/материалы сессии 18/load-stand.sh" serve
  bash "/src/материалы сессии 18/load-stand.sh" daemon
  pfu-cli connect
  bash "/src/материалы сессии 18/reload-test.sh" 25
  bash "/src/материалы сессии 18/long-test.sh" 300 15
  bash "/src/материалы сессии 18/cycles-test.sh" 5
  pfu-cli disconnect
  bash "/src/материалы сессии 18/load-stand.sh" teardown'
```

Ожидание: `HOLD after=50/50`, `итог: ok`, в журнале нет `ERROR`, после
`teardown` в контейнере не остаётся `pfu0`, правил `fwmark` и таблицы
`inet pfu`.
