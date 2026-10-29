# Архитектура proxy-for-ubuntu

Документ описывает внутреннее устройство проекта. Для пользователя основная документация —
[README.md](../README.md).

## 1. Общая схема

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Рабочий стол Ubuntu                          │
│                                                                      │
│   ┌──────────────────────────┐        Unix socket                     │
│   │  proxy-for-ubuntu (GUI)  │◄─────── /run/proxy-for-ubuntu/ctl.sock │
│   │  Tauri + WebView (user)  │                                        │
│   └──────────────────────────┘                                        │
└───────────────────────────────────┬──────────────────────────────────┘
                                    │  JSON-RPC (запрос-ответ + события)
┌───────────────────────────────────▼──────────────────────────────────┐
│                    proxy-for-ubuntud (демон, root)                   │
│                                                                      │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ Supervisor │  │  Rule engine │  │   Outbounds  │  │  DNS core  │ │
│  │ apply/     │  │  (Clash-like)│  │  7 протоколов│  │  резолвер  │ │
│  │ rollback   │  │  geoip/site  │  │              │  │  + кэш     │ │
│  └────────────┘  └──────────────┘  └──────────────┘  └────────────┘ │
│         │               │                  │                │        │
│         └───────────────┴──────────────────┴────────────────┘        │
│                              │                                       │
│                    ┌─────────▼──────────┐                            │
│                    │  nftables          │                            │
│                    │  REDIRECT/TPROXY   │                            │
│                    │  → слушатели       │                            │
│                    └────────────────────┘                            │
└──────────────────────────────────────────────────────────────────────┘
```

GUI работает от имени пользователя, демон — от root. Между ними Unix-сокет в
`/run/proxy-for-ubuntu/ctl.sock`, права `0660`, группа `proxy-for-ubuntu`. Никакого
`sudo` из GUI: единственная точка входа в привилегированный код — системный демон,
который запускает systemd и слушает сокет.

## 2. Разделение на два процесса и почему так

| | GUI | Демон |
|---|---|---|
| Запускается | из `.desktop` от пользователя | `systemd`, `Type=simple`, от root |
| Права | обычные | root |
| Файлы | `~/.config/proxy-for-ubuntu/` | `/etc/proxy-for-ubuntu/`, `/var/lib/proxy-for-ubuntu/` |
| Что делает | рисует интерфейс, шлёт команды | держит nftables, слушатели, сокеты, правила |

Причины разделения:

1. **nftables, `ip rule` и прозрачные сокеты требуют `CAP_NET_ADMIN`.** Выдавать его GUI-процессу — плохая
   практика: упавший или взломанный WebView-процесс получил бы права менять сеть.
2. **Системные изменения переживают перезапуск GUI.** Закрыли окно — трафик идёт
   через прокси дальше, как и должен.
3. **systemd даёт автозапуск, восстановление и контроль.** `Restart=always`,
   `WatchdogSec`, `ExecStartPre` для проверки окружения.

## 3. Конфигурация

`/etc/proxy-for-ubuntu/config.yaml` — Clash-подобный YAML. Полная схема —
[CONFIG.md](CONFIG.md). Пользовательские профили лежат в
`~/.config/proxy-for-ubuntu/profiles/<name>.yaml`, системный (активный) — симлинк
или копия в `/etc`.

Перезагрузка конфигурации **без перезапуска процесса**: `SIGHUP` → демон перечитывает
файл, собирает новый `Router`, валидирует, и только потом атомарно подменяет старый
`Arc<Router>`. Упал валидатор — остаётся старый рабочий конфиг, в лог уходит ошибка.
Это и есть «Apply без перезапуска демона» из требований.

## 4. Rule engine

Классический Clash-подобный пайплайн, первое совпадение выигрывает:

```
Пакет/поток
   │
   ├─► ProcessRule?    совпадение по имени процесса (cgroup/binary path)
   │
   ├─► PortRule?       совпадение по порту назначения
   │
   ├─► IpCidrRule?     точное совпадение адреса
   │
   ├─► DomainRule?     извлечено из TLS SNI / HTTP Host / DNS-запроса
   │                   ├─ domain          exact
   │                   ├─ domain-suffix   .example.com
   │                   ├─ domain-keyword  substring
   │                   ├─ domain-regex    PCRE-подобный
   │                   └─ geosite:<tag>   из локальных наборов
   │
   ├─► GeoIpRule?      geosite-agnostic: IP попадает в набор CIDR
   │                   └─ geoip:<tag>
   │
   └─► Final: DIRECT   (или что указано в `final:`)
```

Реализация: `src-tauri/src/engine/rules.rs`. Правила компилируются один раз в
`Vec<CompiledRule>` — на каждый пакет это линейный проход с предвычисленными
хеш-сетами для доменов и битовыми масками для CIDR (дерево поиска — при >
256 правил одного типа, иначе линейка быстрее).

### Geo-данные

Своё хранилище, не чужие бинарные базы:

```
/var/lib/proxy-for-ubuntu/geo/
├── geoip/
│   ├── cn.txt        # CIDR, по одному на строку
│   ├── ru.txt
│   └── ...
├── geosite/
│   ├── category-ads-all.txt
│   └── ...
└── manifest.json     # url + sha256 + дата последнего обновления
```

Формат — обычный текст, `#` для комментариев. Так файлы можно читать глазами,
править руками и диффы. Обновление: `pfu-cli geo update` (или кнопка в GUI),
скачивание с URL из конфига, проверка sha256, атомарная замена.

## 5. Outbound-протоколы

Все клиенты написаны с нуля на Rust, без sing-box/Xray/clash. Общий интерфейс:

```rust
#[async_trait]
trait Outbound {
    fn name(&self) -> &str;
    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>>;
    async fn udp(&self) -> Result<Box<dyn UdpSession>>;   // для UDP/QUIC
    fn test(&self) -> Probe;
}
```

| Протокол | Состояние | Реализация | Замечания |
|---|---|---|---|
| `direct` | рабочий | `outbound/direct.rs` | — |
| `http` (CONNECT) | рабочий | `outbound/http.rs` | Basic-аутентификация, keep-alive пул |
| `socks5` / `socks5h` | рабочий | `outbound/socks5.rs` | UDP ASSOCIATE, remote DNS для `socks5h` |
| `ssh` | рабочий | `outbound/ssh.rs` | `russh`, динамический форвардинг |
| `shadowsocks` | рабочий | `outbound/shadowsocks.rs` | AEAD, ChaCha20-Poly1305 и AES-256-GCM, HKDF-SHA1, TCP+UDP |
| `trojan` | рабочий | `outbound/trojan.rs` | rustls, SHA224 от пароля, SOCKS5-подобный запрос |
| `vless` | **не проверен с живым сервером** | `outbound/vless.rs` | UUID, X25519/Reality нет — только TLS и WebSocket |
| `vmess` | **не проверен с живым сервером** | `outbound/vmess.rs` | AEAD-режим (VMessAEAD) |

Статус «не проверен с живым сервером» — это честная пометка: код компилируется,
проходит тесты на синтетическом сервере, но не проверялся против настоящего
xray-сервера. Формально в UI такие протоколы помечены значком ⚠.

### Криптография

Используются проверенные crates, а не самописный код: `chacha20poly1305`,
`aes-gcm`, `aes`, `cbc`, `hmac`, `sha1`, `sha2`, `hkdf`, `md-5`, `x25519-dalek`,
`ed25519-dalek`, `rustls`. Собственная реализация только парсинга форматов
протоколов (AEAD-заголовки, base64, порядок байт), что безопасно и покрыто тестами.

## 6. Системный слой

### 6.1 Перехват трафика

Два независимых пути: сокеты демона (REDIRECT/TPROXY) и TUN. Первый —
по умолчанию, второй включается `tun.enabled` и нужен для локального UDP.

- **TCP.** Цепочка `nat output` (hook `output`, priority `dstnat`) делает
  `redirect to :15000` для локального TCP. Демон принимает соединение
  слушателем на `0.0.0.0:15000` и читает настоящего получателя из
  `SO_ORIGINAL_DST` (`SOL_IP`-опция 80) уже принятого сокета.
- **UDP форвардинга.** В `prerouting` (priority `mangle`) UDP помечается
  `meta mark set 0x1` и уходит в `tproxy to :15001`. По метке `ip rule`
  отправляет пакет в таблицу 100, где лежит `local default dev lo`;
  настоящий получатель приходит контрольным сообщением `IP_ORIGDSTADDR`.
  На каждый поток создаётся сокет, привязанный к этому получателю
  (`IP_TRANSPARENT` + `SO_REUSEPORT`): ответ уходит с правильного порта, а
  не с 15001 — иначе клиент его отбросит.
- **TCP из контейнеров** (`intercept.docker: true`) перехватывается в
  `nat prerouting` тем же `redirect to :15000`.

- **TUN** (`tun.enabled: true`, интерфейс `pfu0`). Цепочка `mangle output`
  **типа `route`** ставит метку `0x2` (с типом `filter` netfilter не
  пересчитывает маршрут, и пакет уходит мимо TUN), `ip rule fwmark 0x2`
  отправляет пакет в таблицу 101, где лежит `default dev pfu0`. Демон читает IPv4-пакеты из `pfu0`, разбирает TCP/UDP
  собственным userspace-стеком (`engine/tun/`) и открывает соединение через
  обычные outbound'ы. Ответ собирается в IP-пакет и пишется в `pfu0` — ядро
  доставляет его приложению. В этом режиме `nat output` с REDIRECT для TCP
  не создаётся; UDP форвардинга по-прежнему идёт через TPROXY. Ограничения:
  только IPv4, без пересборки фрагментов, TCP без window scaling и SACK,
  ICMP не проксируется.

Что не перехватывается и почему:

- **локальный UDP** (DNS, QUIC, игры) без TUN: `redirect` для локально
  сгенерированной датаграммы переписывает адрес получателя, и
  `IP_ORIGDSTADDR` возвращает уже `127.0.0.1:15001`, а не настоящий адрес —
  восстановить его нечем. С `tun.enabled: true` этот трафик идёт через TUN;
- **IPv6**: слушатели демона и стек TUN — IPv4-only, поэтому в `prerouting`,
  `mangle output`, `nat output` и `nat prerouting` стоит `meta nfproto ipv6
  return` и v6-трафик идёт напрямую. Полная поддержка (v6-наборы,
  `sockaddr_in6`, `IP6T_SO_ORIGINAL_DST`, `IPV6_TRANSPARENT`) — отдельная
  задача;
- трафик `uid 0` (сам демон), `lo`, локальные адреса (`fib daddr type
  local`), multicast `224.0.0.0/4`, broadcast, приватные сети при
  `bypass_private: true` и порты из `exclude_ports`.

Слушатели живут ровно столько, сколько включён перехват: `Capture` держит
`CancellationToken`, `disconnect` отменяет циклы и дожидается, пока задачи
закроют сокеты. В юните `LimitNOFILE=65536`; при `EMFILE`/`ENFILE` цикл
accept спит секунду и пишет одно предупреждение в секунду, а не в каждом
витке.

### 6.2 Маршрутизация (nftables)

Маршруты системы не трогаются. Фактический набор правил (`nft list table
inet pfu`) после `connect`:

```
table inet pfu {
    set loopback_ips  { elements = { 127.0.0.0/8 } }
    set private_ips   { elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } }
    set exclude_ports { elements = { 22 } }

    chain prerouting {
        type filter hook prerouting priority mangle; policy accept;
        iifname "lo" return
        meta nfproto ipv6 return
        fib daddr type local return
        ip daddr 224.0.0.0/4 return
        ip daddr 255.255.255.255 return
        ip daddr @loopback_ips return
        ip daddr @private_ips return
        meta l4proto { tcp, udp } th dport @exclude_ports return
        meta l4proto udp meta mark set 0x1 tproxy to :15001
    }

    chain nat_output {
        type nat hook output priority -100; policy accept;
        oifname "lo" return
        meta nfproto ipv6 return
        fib daddr type local return
        ip daddr 224.0.0.0/4 return
        ip daddr 255.255.255.255 return
        ip daddr @loopback_ips return
        ip daddr @private_ips return
        meta l4proto { tcp, udp } th dport @exclude_ports return
        meta skuid 0 return
        meta l4proto tcp redirect to :15000
    }

    chain nat_prerouting {          # только при intercept.docker: true
        type nat hook prerouting priority -100; policy accept;
        ...
        meta l4proto tcp redirect to :15000
    }
}
ip rule add fwmark 0x1 lookup 100 priority 100
ip route replace local default dev lo table 100
```

Правила генерируются в `engine/nft.rs` и применяются одним `nft -f`, а не
поштучно — это атомарно и быстро. `ip rule` добавляется только если его
ещё нет; `teardown` удаляет все свои правила, маршрут и таблицу, проверяет
результат и возвращает ошибку со списком неудач, а не глотает её.

Цепочка `prerouting` без исключений забирала трафик, адресованный самой
машине: mDNS уходил в прокси-сокет десятками тысяч датаграмм. Поэтому там
стоят `fib daddr type local`, multicast и broadcast.

### 6.3 DNS

С TUN (`tun.enabled: true`) DNS перехватывается: датаграмма к любому
внешнему `:53` попадает в `pfu0`, поднимается userspace-стеком и уходит
обычным UDP-потоком через outbound, который выбрали правила. Ответ
возвращается приложению как есть — это режим `redir-host`, и приложение
видит настоящий адрес.

Побочный, но главный эффект: из ответа берутся A/AAAA-записи, и
`engine/dns.rs` запоминает «IP → домен» на `cache_ttl` секунд. Перед
принятием решения `Engine::enrich_domain` подставляет имя в `Flow`, поэтому
правила `DOMAIN`, `DOMAIN-SUFFIX`, `GEOSITE` работают и для соединения,
которое приложение открыло уже по адресу (TUN TCP/UDP и перехваченный
REDIRECT-TCP).

`fake-ip` не реализован и отклоняется валидацией: настройка, которая молча
ничего не делает, хуже отказа. `HIJACK-DNS` в правилах означает «ответить
самим»: резолвер разрешает имя локально (системный резолвер, затем DoH с
закреплёнными адресами) и собирает ответ A/AAAA, запрос наружу не уходит.

Домены не теряются и там, где DNS не участвует: `socks5h`, `vless`, `vmess`,
`trojan` передают имя хоста на прокси, и резолвит его уже он.

### 6.4 Apply и откат

`Supervisor::apply()`:

1. **Снапшот.** Текущие `ip rule`, `ip route table 100`, таблица `inet pfu`,
   симлинк активного конфига — всё пишется в `/var/lib/proxy-for-ubuntu/rollback/`.
2. **Dry-run валидация.** YAML парсится, правила компилируются, каждый outbound
   проверяется на успешное TCP-соединение до цели. Ничего не применено.
3. **Commit.** Записывается новый конфиг, генерируются nft-правила, `nft -f`,
   поднимаются слушатели перехвата, перечитывается конфиг демоном.
4. **Health-check.** Проверяется, что DNS отвечает и тестовый URL открывается.
5. **Любая ошибка → `rollback()`.** Восстановление снапшота, откат symlink,
   в журнал — причина. Конфиг, который не прошёл health-check, не остаётся активным.

Кнопка «Применить» в GUI вызывает ровно этот путь. Кнопка «Откатить» в логе
ошибок — ручной вызов `rollback()` из снапшота последней неудачной попытки.

## 7. GUI

Tauri 2 + React + TypeScript. Тёмная и светлая темы, без тяжёлых UI-китов
(собственные CSS-переменные, шрифт Inter). Экраны:

- **Обзор** — статус, тумблер подключения, круговая диаграмма трафика
- **Прокси** — список outbound'ов, добавить/редактировать/проверить
- **Правила** — редактор правил с подсветкой синтаксиса, drag-and-drop сортировка
- **Профили** — импорт/экспорт YAML, подписки на обновления по URL
- **Geo** — наборы, обновление, ручная правка
- **Журнал** — системный лог с фильтрами, экспорт

Обновления состояния — через события Tauri (`state://changed`), GUI не опрашивает
демон в цикле.

## 8. Упаковка

Собирается `dpkg-deb` напрямую (`scripts/build-deb.sh`), без `debuild` — чтобы не
тянуть зависимости на машине сборки. Состав пакета:

```
/usr/bin/proxy-for-ubuntu          GUI
/usr/bin/proxy-for-ubuntud         демон
/usr/bin/pfu-cli                   CLI для headless-конфигурации и CI
/usr/lib/proxy-for-ubuntu/         встроенные geo-наборы по умолчанию
/etc/proxy-for-ubuntu/             конфиг, состояние
/var/lib/proxy-for-ubuntu/         снапшоты отката, логи
/usr/share/applications/           .desktop
/usr/share/icons/                  иконки
/usr/lib/systemd/system/           юниты
/usr/share/polkit-1/actions/       .policy для GUI (чтение статуса, запрос Apply)
```

`postinst` создаёт пользователя `proxy-for-ubuntu`, ставит группу, инициализирует
конфиг из дефолта, `systemctl daemon-reload`, не стартует демон автоматически —
пользователь сам включает тумблер в GUI. `prerm` гасит демон и **снимает
nftables-правила** (иначе после удаления пакета система остаётся без сети).

## 9. Тестирование

- `cargo test` — юнит-тесты на протоколы (векторы из спецификаций), rule engine,
  парсер конфига
- `tests/integration.rs` — поднимает локальный SOCKS5/HTTP/SS-сервер, гоняет через
  него реальные TCP-обмены
- Ручной чек-лист в [docs/TESTING.md](TESTING.md) — снятие в VM, проверка
  утечки DNS, автозапуск, восстановление после `systemctl restart network`
