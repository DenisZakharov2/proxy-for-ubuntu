# HANDOFF — proxy-for-ubuntu: статус на 29 октября 2026

Точка входа для следующей сессии. Всё, что ниже, проверено на этой машине;
где не проверено — сказано прямо.

- **Репозиторий:** https://github.com/DenisZakharov2/proxy-for-ubuntu
- **Ветка:** `main`, рабочее дерево чистое
- **HEAD:** `c8b02f0` — перехват DNS (`redir-host`) и честное сообщение для `HIJACK-DNS` на TCP; поверх только документы; точный HEAD смотри `git log --oneline -1`
- **База документации:** `a1613a4` (рабочие документы, материалы сессий 9–12) + `48ac264` (`feat(0.2.0)`: `link.rs`, `subscription.rs`, `test-outbound`, teardown без ложных ERROR) + `29861e2`, `144a99b`, `a3f4405` (сессия 13) + `40e9bc9`, `84db96f`, `0953d4a` (сессия 14) + `affe6f0`, `1096674` (сессия 15, TUN) + `94b8bbf`, `08e76c6`, `c8b02f0` (сессия 16, DNS)
- **Теги:** `v0.2.0` — на `050b29e`, опубликован (`.deb` + `.sha256`), ранее `v0.1.3` на `721d6d3`
- **Версия кода:** 0.2.0 + TUN + DNS (0.3.0 не выпущена); **установленный пакет:** 0.1.2
- **TUN:** реализован для IPv4 (TCP и UDP), проверен на netns-стенде; **DNS перехватывается в режиме `redir-host`**; IPv6 — следующая сессия
- **Тесты:** `cargo test --lib` — **208** passed (203 в сессии 15, 182 на релизе 0.2.0)
- **История по сессиям:** `PROGRESS_2026-10-29.md` (сессии 13–16), `PROGRESS_2026-10-26.md` (§9 — сессия 10, §10 — сессия 11, §11 — сессия 12), `SESSION_SUMMARY.md` (сессии 1–8), `материалы сессии 14/README.md`, `материалы сессии 16/README.md`

---

## 0. С чего начать следующую сессию

1. Прочитать этот файл целиком; за деталями сессий — `PROGRESS_2026-10-29.md`.
2. Проверить состояние машины: `pfu-cli status`, `ss -ltn | grep 15000`,
   `ip rule show | grep fwmark`.
3. Рабочее дерево — `/home/anony/Documents/Личное/Проект proxy for ubuntu`
   (собственный checkout пользователя). Если его нет: `git clone`, попросить
   GitHub-токен; `gh` на машине авторизован.
4. Базовый регресс: `cargo fmt --all -- --check`,
   `cargo clippy --all-targets -- -D warnings`, `cargo test --lib` (ожидается 208).
5. 0.2.0 выпущена (`v0.2.0`), §7.2 и §7.2а закрыты. TUN для IPv4 сделан
   (§7.3): устройство, маршрут по метке, TCP и UDP через userspace-стек.
   DNS перехватывается в режиме `redir-host` (§6.4): запрос идёт через
   прокси, карта «IP → домен» питает доменные правила. Следующее по плану —
   запросы к `127.0.0.53` (systemd-resolved), затем IPv6 в TUN.
6. После релиза обновить §2, §4 и §7 этого файла — он должен оставаться
   актуальным, а не превращаться в историю.
7. Фабрика `pfu-1-0` (`/home/anony/autonomous-sw-factory`): состояние и
   принятые задачи — §2.4. Полный `factory verify --stage s4_build` запускать
   только когда приняты все 13 задач, иначе он красный на несделанных
   `deliverable.md` и это не дефект.

---

## 1. Коротко: что есть и чего нет

Приложение — системный прокси для Ubuntu: демон на Rust перехватывает трафик
через nftables и гонит его через rule engine в духе Clash. Своя реализация
протоколов, без sing-box/Xray/clash.

| Возможность | Состояние |
|---|---|
| Перехват TCP всей системы | **Работает**, проверено живым трафиком |
| UDP форвардинга (Docker/контейнеры) | **Работает**, проверено на netns-стенде (5/5) и через Docker |
| UDP локальный (DNS, QUIC, игры) | **Работает при `tun.enabled: true`**, проверено на netns-стенде; по умолчанию выключено |
| DNS | **Работает при `tun.enabled: true`, режим `redir-host`**: запрос к внешнему `:53` идёт через прокси, из ответа строится карта «IP → домен»; `HIJACK-DNS` отвечает локально. Запросы к `127.0.0.53` идут мимо (§6.4) |
| IPv6 | **Не поддерживается**, но больше не ломается: guard возвращает v6 напрямую (§6.1) |
| TUN (`pfu0`) | **Реализован для IPv4**: TCP и UDP через userspace-стек (`engine/tun/`), живой стенд 3/3 |
| Статистика по правилам | **Работает**: `metrics.live` отдаёт `active_rules` и `by_outbound`, проверено TCP и UDP |
| Протоколы | direct, http, socks5/socks5h, shadowsocks, trojan, ssh — рабочие; **vless и vmess проверены живым Xray 26.10.29** (tcp без TLS), ⚠ снят |
| Импорт ссылок и подписок | Работает: `link.rs` + `subscription.rs`, IPC, GUI (вставка списка, предпросмотр, реестр с обновлением по кнопке) |
| GUI (Tauri) | 7 экранов, реальный IPC, без моков; проверено в headless Chromium (`--dump-dom`) на демо-данных: рендер, тумблер, форма, валидация. На живом рабочем столе не запускалось |
| Web UI (`pfu-web`) | Реализован (вариант Б: 127.0.0.1 → Unix-сокет демона) |
| CLI (`pfu-cli`) | status/connect/disconnect/doctor/config/rules/proxies/metrics/geo/logs/apply/validate/version/test-outbound |
| Geo-наборы | Обновление по кнопке и по расписанию (`geo.auto_update`) |
| Лимиты | `limits.rate_limit`, `limits.max_connections` (+ переопределение на outbound) |
| Пакет | `.deb` для 22.04/24.04 собирается в CI по тегу |
| apt-репозиторий / автообновление | **Нет** — только ручная установка `.deb` |

Сессия 12 выпустила 0.1.3. Сессия 13 сделала 0.2.0: импорт ссылок и подписок,
IPC и GUI, безопасность, честная проверка протоколов в CI. Сессия 14 довела её
до конца: VMess переписан по протоколу Xray и проверен живым сервером, ⚠ снят,
матрица совместимости заполнена. Сессия 15 начала 0.3.0: TUN, устройство
`pfu0`, собственный userspace-стек IPv4 — локальный UDP (DNS, QUIC) теперь
идёт через прокси. Сессия 16 сделала перехват DNS: `redir-host`, карта
«IP → домен» для правил, настоящий `HIJACK-DNS`, `fake-ip` отклоняется
валидацией. Осталось: `127.0.0.53`, IPv6, apt-репозиторий.

---

## 2. Репозиторий, коммиты, CI

### 2.1 Коммиты, вошедшие в 0.1.2 и 0.1.3 (после `d982270`)

| Коммит | Что |
|---|---|
| `9b4c2e4` | перехват TCP REDIRECT + UDP TPROXY, слушатели, `sync_capture` |
| `572eac8` | P0: shutdown UDP/соединений, идемпотентный `teardown`, `LimitNOFILE`, EMFILE-backoff |
| `5ce1b54` | `intercept.tcp: tproxy` отклоняется валидацией; вариант убран из GUI |
| `b037839` | документация под фактическую схему (ARCHITECTURE RU/EN, README, CONFIG, TESTING, CHANGELOG, ROADMAP, WEB_UI) |
| `d0f83f0` | `packaging/profiles/default.yaml`: убран ложный комментарий про fake-ip |
| `6d66efe` | версия 0.1.2, CHANGELOG, бейдж |
| `721d6d3` | 0.1.3: `meta nfproto ipv6 return` в трёх цепочках, `Breakdown::record` на закрытии TCP/UDP, `engine_loaded`, `/dev/net/tun` не блокирует `--check`, релиз только с 22.04, ROADMAP сверен с кодом |
| `262008e` | бейдж версии в `README.en.md` (после релиза; код не менялся) |

Ветка `wip/redirect-tproxy` влита fast-forward и **удалена** (локально и на
GitHub). На remote осталась только `main`.

### 2.2 CI на релизном `721d6d3`

| Workflow | Что делает | Результат |
|---|---|---|
| `ci.yml` → «Форматирование, clippy и тесты» | `cargo fmt --check`, `clippy -D warnings`, `cargo test --all` | success |
| `ci.yml` → «Фронтенд и упаковка» | `node --check app/ui/app.js`, `build-deb.sh --skip-tests`, проверка состава пакета | success |
| `protocols.yml` | Xray в Docker + «проверка» vless/vmess (см. §6.5 — проверка не настоящая) | success |
| `release.yml` | по тегу `v*`: `.deb` на ubuntu-22.04 и 24.04; публикация ассетов только из 22.04 | success |

Все три прогона на `721d6d3` — success. `protocols.yml` в этот раз шёл ~28
минут: почти всё время занял `apt-get update/install` на раннере, а у job
`timeout-minutes: 30`. При медленных зеркалах он может не уложиться — это
инфраструктура, не код; при повторе просто перезапустить job.

Пуш `262008e` (только бейдж в `README.en.md`) заново прогнал CI и Protocols —
оба success; Release на него не запускается, тега нет.

### 2.2a CI на `0953d4a` (29.10.2026, сессия 14)

| Workflow | Run | Результат |
|---|---|---|
| `ci.yml` | `40917305076` | success — fmt, clippy, 182 теста, `node --check`, сборка пакета |
| `protocols.yml` | `40917305307` | **success** — `vless` 200/930 Б/37 мс, `vmess` 200/923 Б/38 мс через наш outbound |

`Protocols` на промежуточном `40e9bc9` был failure по vmess — это и был тот
самый честный сигнал, после которого `vmess.rs` переписали (`84db96f`).

### 2.3 Release v0.2.0

- URL: https://github.com/DenisZakharov2/proxy-for-ubuntu/releases/tag/v0.2.0
- `proxy-for-ubuntu_0.2.0_amd64.deb` — 4 300 396 байт (сборка 22.04)
- sha256: `f5f6de41940af7acca99cd8c534fe22cb3e66119231ca81c337306739ab13cea`
- Проверено: скачанный `.deb` сходится с `.sha256`, пакет `0.2.0-1`,
  `pfu-cli version` из пакета печатает `pfu-cli 0.2.0 (IPC api 1, протокол 0.2.0)`.
- Копия — `материалы сессии 14/release/`.
- Пакет вырос с 3,63 до 4,30 МБ: в зависимостях появился `age` (шифрование
  экспорта), плюс новый код. Посторонних файлов в пакете нет (28 файлов).
- Наблюдение: пуш аннотированного тега сразу после пуша ветки создал **два**
  прогона `release.yml` на один SHA; оба success, ассеты в релизе по одному
  (загрузка перезаписывает). Если это повторится — не дефект сборки.

Release v0.1.3 (для истории)

- URL: https://github.com/DenisZakharov2/proxy-for-ubuntu/releases/tag/v0.1.3
- `proxy-for-ubuntu_0.1.3_amd64.deb` — 3 629 246 байт (сборка 22.04)
- sha256: `802b0b1fd67e264923ca1653cc34f118ad87358d48b294bb2348a74ad0b856fd`
- Проверено: скачанный `.deb` сходится с `.sha256`, `pfu-cli version` из него
  печатает `0.1.3`, пакет — `0.1.3-1`.
- Ассеты грузит только джоба 22.04 (§6.6), поэтому имя и содержимое
  однозначны. Копия — `материалы сессии 12/release/`.

Release v0.1.2 (для истории): `.deb` 3 629 108 байт, sha256
`689c92d9e5229a7acc59c2f3fcab84dd05c939277c9e0a075606e9123dca45dd`,
сборка 22.04.

---

### 2.4 Сессии 13–14 (29.10.2026): 0.2.0 готова, фабрика `pfu-1-0`

Запушено в `main` 29.10.2026 (`262008e..0953d4a`):

| Коммит | Что |
|---|---|
| `a1613a4` | рабочие документы: `HANDOFF`, `PROGRESS`, `SESSION_SUMMARY`, `материалы сессий 9–12` |
| `48ac264` | `feat(0.2.0)`: `link.rs` (vless/vmess/ss SIP002+legacy/trojan/socks5/http, reality и grpc отклоняются с причиной), `subscription.rs` (YAML / список / base64, `rejected[]` с номерами строк), `pfu-cli test-outbound` + `outbound::http_check`, teardown без ложных ERROR на отсутствующей FIB-таблице. 163 теста (было 139) |
| `29861e2` | IPC импорта: `profile.import_uri`, `subscription.preview`, `subscription.apply`, реестр `subscriptions.json`, планировщик обновления в `Server::serve`. 175 тестов |
| `144a99b` | GUI: хелпер `ipc` → `rpc` (WRY ставит свой `window.ipc`, из-за чего окно в поставочной сборке оставалось мёртвым), `enabled` из `daemon.status`, `engine_loaded` в окне, транспорт `tcp/ws` у vless/vmess, проверка формы до сохранения |
| `a3f4405` | безопасность: `Debug` для `Outbound` редактирует пароли/UUID/passphrase, `${VAR}` без значения — ошибка разбора, `env`/`config.yaml` 0600 root при каждом `configure`, `UMask=0077` и `RestrictAddressFamilies` в юните. 178 тестов |
| `b98e84b` | `protocols.yml`: шаги «обмен байтами с портом Xray» заменены на `pfu-cli test-outbound`, образ Xray закреплён по digest `sha256:192de110…`, матрица строится из фактических JSON-ответов (`TASK-004`) |
| `40e9bc9` | GUI: `profile.import_links`, `subscription.list/refresh/remove`, предпросмотр подписки до записи, таблица подписок; `docs/IPC.md` + EN. 180 тестов |
| `84db96f` | `vmess.rs` переписан по исходникам Xray: KDF (вложенный HMAC), `cmdKey` с солью `c48619fe-…`, AEAD-заголовок, кадры тела, ленивое чтение ответного заголовка. 182 теста |
| `0953d4a` | `is_experimental` удалён, GUI без ⚠, README/README.en — матрица совместимости, CHANGELOG 0.2.0 |

Первый прогон на `b98e84b` (29.10.2026):

- **CI** — success, 4 мин 57 с (fmt, clippy, тесты, синтаксис `app.js`, сборка пакета).
- **Protocols** — failure, 4 мин 23 с: `vless` прошёл (HTTP 200, 930 байт, 71 мс),
  `vmess` — `ответ не пришёл за 15000 мс`. Причина — `vmess.rs` не совпадал с
  протоколом; переписан в сессии 14 (§6.5).

Сессия 14 проверила протоколы на локальном стенде
(`материалы сессии 14/`): `VLESS-Test` 200/930 Б, `VMESS-Test` (aes-128-gcm)
200/928 Б, `VMESS-Chacha` 200/928 Б. Журнал Xray до переписывания:
`invalid user > user do not exist`.

Состояние фабрики (`/home/anony/autonomous-sw-factory`, прогон `pfu-1-0`,
режим brownfield, 56 событий в журнале):

- приняты: `TASK-001` (ссылки и подписки), `TASK-002` (IPC), `TASK-003` (GUI),
  `TASK-005` (teardown), `TASK-011` (безопасность);
- открыт: `TASK-004` — `protocols.yml` не переключён на `test-outbound`
  (инструмент готов, нужен прогон workflow);
- ждут очереди: `TASK-006`…`TASK-010`, `TASK-012`, `TASK-013` (TUN, DNS, IPv6,
  apt-репозиторий, документация, netns-стенд, приёмка).

### 2.5 Сессия 15 (29.10.2026): TUN

| Коммит | Что |
|---|---|
| `affe6f0` | `engine/tun/` — устройство `pfu0`, маршрут по метке `0x2` (таблица 101), IPv4-стек: разбор/сборка пакетов, TCP (рукопожатие, данные, окно, повторы, FIN), UDP; `tun.address`, `mtu` 1500; `--check`/`diagnose` учитывают TUN; живой тест `tests/tun_live.rs`; стенд `материалы сессии 15/`; документация |
| `1096674` | цепочка `mangle output` типа `route`: с `filter` метка ставилась, но маршрут не пересчитывался, и трафик молча шёл мимо TUN. Тест теперь требует ≥ 500 КБ через `pfu0` и ненулевую статистику |

Проверено на этом коммите:

- `cargo fmt --check`, `clippy --all-targets -- -D warnings` — чисто;
- `cargo test --lib` — 203 passed;
- netns-стенд (привилегированный контейнер): UDP 1200 Б и TCP 256 КБ в обе
  стороны через `pfu0`, 3 прогона подряд, `teardown` без остатков;
- `proxy-for-ubuntud --check` печатает состояние TUN из конфига;
- CI и Protocols на `f4ed865` — **success** (CI: fmt/clippy/тесты/пакет,
  4 мин; Protocols: vless и vmess против живого Xray, 4 мин 37 с).

### 2.6 Сессия 16 (29.10.2026): перехват DNS

| Коммит | Что |
|---|---|
| `94b8bbf` | `engine/dns.rs`: карта «IP → домен» из настоящих DNS-ответов (`parse_response` с поддержкой сжатия имён, `remember_response`, `name_of`), `answer_query` для `HIJACK-DNS`, `build_response` с указателем на вопрос и `SERVFAIL`; `Engine::dns` + `enrich_domain`; перехват в `tun/udp.rs`, `tun/tcp.rs`, `capture.rs`; `fake-ip` отклоняется валидацией, реализация удалена; `paths::dns_port()` удалён; `postinst` мигрирует конфиг; GUI без `fake-ip`; стенд `материалы сессии 16/`; документация |

Проверено на этом коммите:

- `cargo fmt --check`, `clippy --all-targets -- -D warnings` — чисто;
- `cargo test --lib` — **208** passed (было 203: +5 тестов DNS и правил);
- netns-стенд (привилегированный контейнер, `материалы сессии 16/`): три
  живых теста `tests/tun_live.rs`, все ok — DNS-ответ через прокси, после него
  TCP к тому же адресу попадает под `DOMAIN-SUFFIX,…,REJECT` (до запроса
  проходит), `HIJACK-DNS` отвечает `127.0.0.1` без выхода в сеть;
- GUI в headless Chromium: экран настроек отдаёт только `redir-host`, подсказка
  обновлена, `state.config` загружается (SMOKE-прогон);
- `postinst` (`sh -n`) и миграция `strategy: fake-ip → redir-host` проверены на
  копии конфига;
- CI на `c8b02f0` (run `40937355596`) — **success**: fmt, clippy, 208 тестов,
  синтаксис `app.js`, сборка пакета;
- Protocols на `c8b02f0` (run `40937355722`) — **success**: vless и vmess
  против живого Xray по-прежнему проходят, DNS-изменения их не задели.

Найдено по дороге: `build_response` писал имя записи как `[0x00, 0x01, 0x00,
0x01]` — это корень плюс битый тип, а не «A, IN». Пакет был невалидным DNS, и
никто этого не замечал, потому что функция до сессии 16 не вызывалась. Теперь
имя — указатель `0xC0 0x0C` на вопрос, а на разбор добавлены тесты со сжатым и
полным именем.

## 3. Машина и окружение (важно для следующей сессии)

| Что | Значение |
|---|---|
| ОС | Ubuntu 26.04.1 LTS |
| CPU / RAM | 4 ядра / 7,2 ГБ |
| Rust | `rustc 1.99.1`, `cargo 1.99.1`, лежат в `~/.cargo/bin` |
| Docker | 29.9.1, пользователь `anony` в группе `docker` |
| IPv6 | **глобального маршрута нет**: `curl -6` не работает и без перехвата |
| `sudo` | требует пароль и инструментам недоступен |
| Root-команды | **`systemd-run` больше не работает**: polkit отвечает `FAILED to authenticate ... manage-units`. `unshare -Urn` запрещён. Для привилегированных проверок — контейнер `docker run --privileged` (сеть хоста не трогается, у контейнера своя netns) |
| systemctl | работает без пароля (polkit) |

Пути и права:

| Что | Где |
|---|---|
| Конфиг | `/etc/proxy-for-ubuntu/config.yaml`, `root:proxy-for-ubuntu`, 0640 |
| Сокет управления | `/run/proxy-for-ubuntu/ctl.sock`, `srw-rw---- root:proxy-for-ubuntu` |
| Юнит демона | `/usr/lib/systemd/system/proxy-for-ubuntud.service` |
| Логи | `journalctl -u proxy-for-ubuntud` |
| Состояние/geo/rollback | `/var/lib/proxy-for-ubuntu/` |
| Профили (пользователь) | `~/.config/proxy-for-ubuntu/profiles/` |

Пользователь `anony` в группе `proxy-for-ubuntu`, поэтому `pfu-cli` работает
без sudo.

**Рабочее дерево:** `/home/anony/Documents/Личное/Проект proxy for ubuntu` —
это собственный checkout пользователя, не временный клон. Коммитить только
явные пути (`git commit -o`), `git add -A` запрещён: в каталоге может лежать
чужое. Прежний клон в `~/.hermes/cache/scratch` удалён как временный.

---

## 4. Что установлено и в каком состоянии

- Установлен `proxy-for-ubuntu 0.1.2-1` — локальная сборка под хост 26.04;
  для раздачи она не годится, только релизный `.deb` с 22.04.
- Релизные `.deb` 0.1.3 и 0.2.0 на этой машине **не устанавливались**:
  пакет 0.2.0 скачан, `sha256sum -c` сходится, `pfu-cli version` из него
  печатает 0.2.0. Обновление при необходимости:
  `sudo apt install ./proxy-for-ubuntu_0.2.0_amd64.deb` → `systemctl reload proxy-for-ubuntud`.
- Код 0.2.0 + TUN + DNS проверен из рабочего дерева (`target/debug`):
  протоколы — на стенде Xray (`материалы сессии 14/`), TUN и DNS — на
  netns-стенде (`материалы сессии 15/`, `материалы сессии 16/`), регресс —
  208 тестов. Живой перехват на сетевых интерфейсах хоста не включался: все
  проверки в изолированных netns.
- `proxy-for-ubuntud` — `active`, `enabled`, `LimitNOFILE=65536`.
- Перехват **выключен**: `pfu-cli status` → `enabled: false`.
- Порты 15000/15001 закрыты, таблицы `inet pfu` нет, `ip rule fwmark 0x1` нет,
  таблица 100 пуста.
- Сеть работает: `curl https://example.com` → 200.
- В `/etc/proxy-for-ubuntu/config.yaml` остался старый комментарий про fake-ip
  (postinst не перезаписывает существующий конфиг). Сам конфиг корректный:
  `tcp: redirect`, `udp: tproxy`, `exclude_ports: ["22"]`,
  `bypass_private: true`, `docker` не задан (false). **При обновлении до
  0.3.0** postinst переведёт `strategy: fake-ip` на `redir-host` и оставит
  копию `config.yaml.pre-0.3.0`; проверено на копии конфига.

---

## 5. Архитектура — как есть на самом деле

### 5.1 Процессы

| Бинарник | Роль |
|---|---|
| `proxy-for-ubuntu` | GUI на Tauri 2 (пользователь) |
| `proxy-for-ubuntud` | демон (root), nftables, слушатели, outbound'ы |
| `pfu-cli` | управление без GUI |
| `pfu-web` | веб-UI, слушает 127.0.0.1, форвардит JSON-RPC в сокет демона |

Связь — newline-delimited JSON-RPC по Unix-сокету. GUI не имеет прав менять
сеть: единственная привилегированная точка — демон.

### 5.2 Перехват

```
table inet pfu {
    set loopback_ips  { elements = { 127.0.0.0/8 } }
    set private_ips   { elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16 } }
    set exclude_ports { elements = { 22 } }

    chain prerouting {            # priority mangle, для форвардинга (контейнеры)
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

    chain nat_output {            # при tun.enabled: true не создаётся для TCP
        oifname "lo" return
        meta nfproto ipv6 return
        fib daddr type local return
        ip daddr 224.0.0.0/4 return
        ip daddr 255.255.255.255 return
        ip daddr @loopback_ips return
        ip daddr @private_ips return
        meta l4proto { tcp, udp } th dport @exclude_ports return
        meta skuid 0 return        # трафик самого демона — напрямую
        meta l4proto tcp redirect to :15000
    }

    chain mangle_output {         # только при tun.enabled: true
        type route hook output priority mangle; policy accept;
        … те же исключения, что выше …
        meta l4proto udp meta mark set 0x2
        meta l4proto tcp meta mark set 0x2   # если intercept.tcp != off
    }

    chain nat_prerouting {        # только при intercept.docker: true
        type nat hook prerouting priority -100; policy accept;
        …
        meta l4proto tcp redirect to :15000
    }
}
ip rule add fwmark 0x1 lookup 100 priority 100
ip route replace local default dev lo table 100
ip rule add fwmark 0x2 lookup 101 priority 100
ip route replace default dev pfu0 table 101
```

- **TCP:** слушатель `0.0.0.0:15000`, настоящий получатель — `SO_ORIGINAL_DST`
  (`SOL_IP`-опция 80).
- **UDP форвардинга:** слушатель `0.0.0.0:15001` с `IP_TRANSPARENT` и
  `IP_RECVORIGDSTADDR`; на каждый поток — сокет, привязанный к настоящему
  получателю (`IP_TRANSPARENT` + `SO_REUSEPORT`), поэтому ответ уходит с
  правильного порта, а не с 15001.
- **Локальный UDP без TUN:** не перехватывается. `redirect` для локально
  сгенерированной датаграммы переписывает адрес, и `IP_ORIGDSTADDR` возвращает
  уже `127.0.0.1:15001` — восстановить получателя нечем. С TUN этот путь
  заменяется: метка `0x2` → таблица 101 → `pfu0`.
- **TUN** (`config.tun`, `pfu0`): при `tun.enabled: true` локальный трафик
  идёт в устройство, userspace-стек (`engine/tun/`) поднимает TCP и UDP,
  REDIRECT для TCP не создаётся (§6.9). `--check` считает отсутствие
  `/dev/net/tun` проблемой только в этом режиме.
- **DNS:** при TUN поток с `:53` дополнительно разбирается: ответ питает карту
  «IP → домен», а правило `HIJACK-DNS` отвечает локально (§6.4).
- Слушатели живут только при включённом перехвате: `Capture` держит
  `CancellationToken`, `disconnect` отменяет `udp_loop`, все `udp_flow` и
  `tcp_conn`, ждёт закрытия сокетов. Выключение занимает ~0,06–0,09 с.
- `teardown` идемпотентен: удаляет все свои `ip rule`, маршрут и таблицу,
  проверяет результат, возвращает ошибку со списком неудач. `apply` при сбое
  вызывает его же.

Порты — константы в `app/src-tauri/src/paths.rs` (`redirect_port()` 15000,
`tproxy_port()` 15001).

### 5.3 Код (размеры на 29.10.2026)

| Файл | Строк | Что |
|---|---:|---|
| `app/src-tauri/src/engine/capture.rs` | 594 | TCP/UDP-слушатели, потоки, отмена, breakdown, домен из DNS |
| `app/src-tauri/src/engine/nft.rs` | 635 | план правил, apply/teardown, `is_missing_table_error` |
| `app/src-tauri/src/engine/router.rs` | 708 | Engine, выбор outbound, relay, лимиты, `enrich_domain` |
| `app/src-tauri/src/engine/stats.rs` | 153 | счётчики и breakdown |
| `app/src-tauri/src/engine/dns.rs` | 625 | резолвер, карта «IP → домен», разбор ответов, `HIJACK-DNS` |
| `app/src-tauri/src/link.rs` | 665 | разбор `vless/vmess/ss/trojan/socks5/http` в `Outbound` |
| `app/src-tauri/src/subscription.rs` | 550 | тело подписки, `rejected[]`, реестр и срок обновления |
| `app/src-tauri/src/config.rs` | 2049 | схема YAML, валидация, `missing_env_refs`, редактирующий `Debug` |
| `app/src-tauri/src/engine/tun/mod.rs` | 334 | TUN: устройство, маршрут, чтение пакетов, диспетчер |
| `app/src-tauri/src/engine/tun/packet.rs` | 422 | IPv4/UDP/TCP: разбор, сборка, контрольные суммы |
| `app/src-tauri/src/engine/tun/tcp.rs` | 630 | минимальный TCP: рукопожатие, данные, окно, повторы, FIN |
| `app/src-tauri/src/engine/tun/udp.rs` | 214 | UDP-потоки, запоминание DNS-ответов, `HIJACK-DNS` |
| `app/src-tauri/src/ipc.rs` | 1961 | JSON-RPC, импорт ссылок и подписок, реестр, apply/rollback |
| `app/src-tauri/src/engine/outbound/vmess.rs` | 1157 | VMess AEAD: KDF, заголовок, кадры тела, ответный заголовок |
| `app/ui/app.js` / `index.html` / `style.css` | 1073 / 258 / 297 | GUI: 7 экранов, хелпер `rpc`, импорт ссылок, подписки |

Модули движка: `engine/{nft,capture,router,rules,stats,geo,dns,tls}.rs`,
outbound'ы — `engine/outbound/*`.

### 5.4 Конфигурация

`/etc/proxy-for-ubuntu/config.yaml`, YAML в духе Clash, `api: 1`. Ключевое:

- `intercept.tcp`: `redirect | off` (**`tproxy` для TCP отклоняется валидацией**);
- `intercept.udp`: `tproxy | off`;
- `intercept.docker` (bool, по умолчанию false) — цепочка `nat_prerouting`;
- `intercept.exclude_ports` (по умолчанию `["22"]`), `exclude_uid`,
  `bypass_private`, `loop_protect`;
- `dns.strategy`: только `redir-host` (по умолчанию); `fake-ip` отклоняется
  проверкой конфига с подсказкой — реализация удалена, `postinst` переводит
  старый конфиг и оставляет копию `config.yaml.pre-0.3.0`. При включённом TUN
  запрос к внешнему `:53` идёт через outbound, ответ запоминается как
  «IP → домен»;
- `tun.enabled`/`device`/`mtu`/`address` — TUN для IPv4 (см. §6.9);
- `geo.auto_update`, `geo.update_interval_hours`;
- `limits.rate_limit`, `limits.max_connections` (+ на outbound);
- `outbounds`, `groups`, `rules`, `final`.

Строгая валидация: конфиг без второго outbound (только `DIRECT`) для
`apply` и `pfu-cli validate` считается ошибкой. `connect` при этом работает —
это осознанное расхождение, описано в README.

---

## 6. Известные дефекты и ограничения (с точками в коде)

### 6.1 IPv6 не поддерживается, но при перехвате больше не рвётся

- Слушатель: `capture.rs:86` — `TcpListener::bind(("0.0.0.0", port))`, только
  IPv4; получатель читается как `sockaddr_in` через `SO_ORIGINAL_DST`.
- В nft-плане теперь `meta nfproto ipv6 return` в `prerouting`, `nat_output`
  и `nat_prerouting` (`nft.rs`): IPv6 идёт напрямую и не попадает в
  IPv4-слушатель. До 0.1.3 таблица `inet` заворачивала v6-TCP в `redirect`,
  и соединение падало.
- Полной поддержки нет: нужны v6-наборы адресов, `sockaddr_in6`,
  `IP6T_SO_ORIGINAL_DST`, `IPV6_TRANSPARENT` — отдельная задача (0.3.0).
- Живой проверки не было: на этой машине нет глобального IPv6-маршрута.
  Проверять на хосте с v6: `curl -6 https://example.com` при включённом
  перехвате должен работать.

### 6.2 Статистика по правилам — исправлено в 0.1.3

`RuleSet::label` отдаёт текст сработавшего правила (`raw` или `FINAL`),
`Engine::route/open` пробрасывают его в `capture.rs`, и на закрытии
TCP-соединения или UDP-потока вызывается
`Breakdown::record(rule, outbound, up+down)`. Живая проверка: `curl` дал
`{"rule": "FINAL", "policy": "DIRECT", "bytes": 46349}`, UDP-стенд — 85 байт.
Ограничение: у TCP обрыв по `disconnect` байты не пишет — `relay` отдаёт итог
только при штатном завершении. UDP-поток при отмене успевает записать сумму.

### 6.3 `config_valid` на свежем демоне — исправлено в 0.1.3

`daemon.status` теперь отдаёт отдельное поле `engine_loaded`.
`config_valid` остался «загруженный конфиг проходит валидацию» и без движка
по-прежнему `false` — но теперь это не двусмысленно. GUI поле не читает;
CLI печатает JSON как есть. Документация: `docs/IPC.md`, `docs/IPC.en.md`.

### 6.4 Локальный UDP/DNS/QUIC — закрыто TUN'ом для IPv4

До 0.3.0 локальный UDP обходил прокси: `REDIRECT` не сохраняет настоящего
получателя датаграммы. С `tun.enabled: true` пакет попадает в `pfu0`, стек
читает адрес из заголовка, и DNS/QUIC идут через прокси (проверено стендом).

DNS перехватывается отдельно от остального UDP: в `tun/udp.rs` поток с
`dst_port == 53` (и такой же поток в `capture.rs` для форвардинга) отдаёт
ответ в `Resolver::remember_response`, откуда берётся карта «IP → домен»;
`Engine::enrich_domain` подставляет имя в `Flow` перед решением правил. Правило
`HIJACK-DNS` отвечает на месте (`Resolver::answer_query`), не открывая
outbound. Подробности — `docs/ARCHITECTURE.md` §6.3, стенд —
`материалы сессии 16/`.

Что осталось:

- **`127.0.0.53` (systemd-resolved) не перехватывается**: loopback исключён из
  всех цепочек (`oifname "lo" return`, `ip daddr @loopback_ips return`), так
  что системные приложения разрешают имена как раньше, а resolved спрашивает
  upstream напрямую. Перехват работает для запросов к внешним адресам;
- DNS over TCP (53/tcp) проксируется, но в карту не попадает;
- IPv6 в TUN не поддержан.

### 6.5 Проверка vless/vmess в CI — настоящая, оба проходят

`b98e84b` заменил шаги «сырые байты в порт Xray» на `pfu-cli test-outbound`:
GET уходит через `engine::outbound`, ответ обязан быть 2xx–3xx, образ Xray
закреплён по digest `sha256:192de110…`.

История:

| Прогон | vless | vmess |
|---|---|---|
| `b98e84b`, run `40912785270` | ✅ HTTP 200, 930 Б, 71 мс | ❌ «ответ не пришёл за 15000 мс» |
| `0953d4a`, run `40917305307` | ✅ HTTP 200, 930 Б, 37 мс | ✅ HTTP 200, 923 Б, 38 мс — после переписывания `vmess.rs` в `84db96f` |

Почему vmess не работал (исправлено в `84db96f`): реализация расходилась с
протоколом Xray в трёх местах.

1. `cmdKey` — это `MD5(uuid ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21")`
   (`protocol.NewID`), а не `MD5(uuid)`.
2. KDF — вложенный HMAC: на каждом уровне роль «хэша» играет предыдущий HMAC
   (`hmac.New` пишет ipad в него, `Sum` сбрасывает и дописывает opad).
   Закреплено тестом `kdf_matches_xray_reference_vectors` — векторы посчитаны
   независимым переносом кода Xray на Go.
3. Тело — кадры `len(2, BE) ‖ AEAD` со счётчиком в первых двух байтах IV;
   ответный заголовок читается лениво (в `connect()` это даёт дедлок: сервер
   присылает его только после данных).

Локальный стенд и воспроизведение — `материалы сессии 14/README.md`.

### 6.6 Релизный workflow: одинаковые имена ассетов — исправлено в 0.1.3

Загрузка осталась только в джобе `ubuntu-22.04`
(`if: matrix.target == 'ubuntu-22.04'`). Джоба 24.04 собирает и проверяет
пакет, но ничего не грузит.

### 6.7 Проверка окружения требовала TUN — исправлено в 0.1.3

`run_check` (`bin/daemon.rs`) больше не считает отсутствие `/dev/net/tun`
проблемой: строка печатается как информационная. На системе без модуля
`tun` демон стартует. Живьём проверено только наличие устройства (на этой
машине оно есть); отрицательный сценарий покрыт кодом, не тестом.

### 6.8 Мелочи

- `metrics.connections` — число **активных** соединений, не всего за сеанс;
  в документации не сказано.
- Установленный `/etc/config.yaml` хранит старый комментарий про fake-ip
  (postinst не трогает существующий файл).
- GUI ни разу не запускался на живом рабочем столе в сессиях 9–12
  (проверялись только `node --check`, сборка пакета и IPC-контракт).

### 6.9 TUN: что уже работает и чего ещё нет (0.3.0)

Сделано и проверено живым стендом (`материалы сессии 15/`):

- устройство `pfu0` (`IFF_TUN | IFF_NO_PI`), адрес из `tun.address`, MTU,
  `rp_filter=0`, маршрут `default dev pfu0 table 101`;
- nftables `mangle output`: UDP (и TCP, если `intercept.tcp` не `off`) получает
  метку `0x2`; `ip rule fwmark 0x2 lookup 101`; при TUN REDIRECT для TCP не
  создаётся;
- IPv4 TCP: SYN → SYN-ACK с MSS, данные в обе стороны, окно 65 535, ACK на
  каждый сегмент, повторы по таймеру (RTO 300 мс с удвоением), FIN в обе
  стороны, RST при отказе правил или недоступном сервере;
- IPv4 UDP: поток на четвёрку адрес/порт, ответ собирается как IP-пакет и
  пишется в TUN;
- статистика: байты в `stats`, `breakdown` по правилу при закрытии потока;
  лимиты `rate_limit`/`max_connections` учитываются.

Чего нет (осознанно, это следующие сессии):

- **DNS через `127.0.0.53`**: loopback исключён, systemd-resolved ходит к
  upstream сам; перехватываются только запросы к внешним адресам (§6.4);
- **IPv6**: `inet6`-адрес, маршрут и разбор v6-заголовков;
- **фрагменты**: отбрасываются, пересборки нет;
- **ICMP** не проксируется;
- TCP без window scaling, SACK и таймстампов: на потерях медленнее ядра;
- нет переключателя TUN в GUI (только YAML и `config.apply`);
- `tun.strict_route` удалено из схемы: поле никогда ничего не делало.

### 6.10 `teardown` на первом старте пишет ERROR — исправлено в `48ac264`

Если таблица 100 ещё ни разу не создавалась, `ip route flush table 100`
завершается с «FIB table does not exist», и `teardown` возвращал ошибку
(две строки ERROR в журнале при старте демона). Исправлено: правило вынесено
в `is_missing_table_error` (`nft.rs`), любая другая ошибка `ip route flush`
по-прежнему считается сбоем. Покрыто тестами
`missing_fib_table_is_not_a_teardown_failure` и
`real_teardown_errors_are_still_failures`. Живой первый старт в свежем netns
не воспроизводился — проверка правила unit-тестом, живая — в `TASK-012`/`TASK-013`.

---

## 7. План до «работа закончена»

### 7.1 Сделано в 0.1.3 (сессия 12)

1. IPv6-guard `meta nfproto ipv6 return` в трёх цепочках + README/ARCHITECTURE.
2. Breakdown-статистика: имя правила из `Engine::route`, запись на закрытии
   TCP и UDP; проверено живым трафиком.
3. `engine_loaded` в `daemon.status`, документация IPC.
4. `/dev/net/tun` больше не блокирует `--check`.
5. Релиз: `.deb` грузит только джоба 22.04.
6. `ROADMAP.md` сверен с кодом.
7. Регресс: fmt, clippy `-D warnings`, 139 тестов; живой прогон
   `connect → curl → metrics → disconnect` и UDP-стенд 5/5.

### 7.2 0.2.0 — сделано в сессиях 13–14

- ✅ `pfu-cli test-outbound` / `http_check`: реальный HTTP-обмен через
  `engine::outbound` (`48ac264`).
- ✅ `protocols.yml` переключён на новый тест, образ Xray по digest (`b98e84b`).
- ✅ ⚠ снят с vless и vmess **после** прохождения теста; матрица совместимости
  заполнена (`0953d4a`). Для этого пришлось переписать `vmess.rs` (`84db96f`).
- ✅ Импорт ссылок и подписок целиком: парсер `48ac264`, IPC `29861e2`,
  GUI — вставка списка ссылок, предпросмотр подписки, таблица подписок с
  «Обновить»/«Удалить» (`40e9bc9`).
- ✅ Issue #2 (совместимость vless/vmess) закрывается этим релизом — проверить
  и закрыть после тега.

### 7.2а 0.2.0 — выпуск — ✅ сделано в сессии 14 (тег `v0.2.0`)

1. Версия 0.2.0 в `app/src-tauri/Cargo.toml` и `app/src-tauri/tauri.conf.json`;
   бейджи в `README.md` и `README.en.md` (`git grep -n 'badge/version-'`).
2. `cargo fmt --check`, `clippy -D warnings`, `cargo test --lib` (182).
3. Коммит «0.2.0: …», тег `v0.2.0`, `git push origin main v0.2.0`.
4. Дождаться `release.yml`; скачать `.deb` + `.sha256`, `sha256sum -c`,
   `pfu-cli version` из пакета — должно быть `0.2.0`.
5. Обновить §2.2, §2.3, §4 этого файла и CHANGELOG датой релиза.

### 7.3 0.3.0 — TUN и локальный UDP

Сделано в сессиях 15–16 (код `affe6f0`, `1096674`, `94b8bbf`):

- ✅ устройство `pfu0`, адрес `198.18.0.1/15`, маршрут в таблице 101, метка
  `0x2` в `mangle output`, `ip rule fwmark 0x2`;
- ✅ собственный userspace-стек IPv4 (решение пользователя: без smoltcp):
  разбор IPv4/UDP/TCP, контрольные суммы, TCP-рукопожатие, данные, окно,
  повторы, FIN/RST, UDP-потоки;
- ✅ `tun.enabled`/`mtu`/`address` в конфиге и валидации; `--check` и
  `system.diagnose` учитывают TUN;
- ✅ живой netns-стенд: UDP 1200 Б и TCP 256 КБ в обе стороны, 3/3 прогона,
  teardown без остатков;
- ✅ **DNS-перехват** в режиме `redir-host`: запрос через прокси, карта
  «IP → домен», доменные правила для соединений по адресу, настоящий
  `HIJACK-DNS`, `fake-ip` отклоняется валидацией (§2.6, §6.4).

Осталось на следующие сессии:

- ⬜ **`127.0.0.53` / systemd-resolved**: перехватывать запросы системного
  резолвера. Варианты (нужно решение пользователя): слушатель на loopback и
  правка `resolv.conf`/resolved, либо оставить как есть и держать ограничение
  в документации.
- ⬜ **IPv6 в TUN**: `inet6`-адрес и маршрут, разбор v6-заголовков; слушатели
  REDIRECT/TPROXY остаются IPv4-only.
- ⬜ **Нагрузка и пересоздание**: длинная сессия, сотни соединений,
  `reload`/`connect` при живом TUN (проверить `EADDRINUSE`/`EBUSY`).
- ⬜ **GUI**: переключатель TUN на экране настроек (сейчас только YAML).
- ⬜ **CI**: TUN требует root, в GitHub Actions его нет — тест
  `tests/tun_live.rs` помечен `#[ignore]` и запускается на стенде вручную.

### 7.4 0.1.4 — мелкое (можно вместе с 0.2.0)

- ~~Убрать ERROR из `teardown` на первом старте (§6.10)~~ — сделано в `48ac264`.
- Дописать в `CONFIG.md`/`IPC.md`, что `metrics.connections` — активные
  соединения (§6.8).
- При случае прогнать GUI и `pfu-web` на живом рабочем столе.

### 7.5 До 1.0

- apt-репозиторий/PPA и автообновление (сейчас только ручной `.deb`).
- Прогон GUI и `pfu-web` на живых Ubuntu 22.04 и 24.04.
- Интеграционные тесты ядра (nft/capture/netns) в CI.
- Доки: `WEB_UI_ARCHITECTURE` без английской версии; проверить остальные на
  расхождения.

---

## 8. Рецепты (проверены в этой сессии)

### 8.1 Отладочный демон из клона

```bash
cd /home/anony/.hermes/cache/scratch/proxy-for-ubuntu/app/src-tauri
cargo build --bins
systemctl stop proxy-for-ubuntud
systemd-run --system --unit=pfu-devd --property=Restart=no --property=LimitNOFILE=65536 \
  /home/anony/.hermes/cache/scratch/proxy-for-ubuntu/app/src-tauri/target/debug/proxy-for-ubuntud --daemon
./target/debug/pfu-cli status
```

Остановка: `systemctl stop pfu-devd`.

### 8.2 Живой прогон

```bash
pfu-cli connect
ss -ltn | grep 15000
ss -lun | grep 15001
curl -m 8 -sS -o /dev/null -w 'http=%{http_code}\n' https://example.com
pfu-cli metrics            # active_rules/by_outbound должны быть непустыми
pfu-cli disconnect
ss -ltn | grep 15000; ss -lun | grep 15001
ip rule show | grep 'fwmark 0x1'; ip route show table 100
curl -m 8 -sS -o /dev/null -w 'net=%{http_code}\n' https://example.com
```

### 8.3 Проверка чистоты после выключения

```bash
ss -ltn | grep 15000        # пусто
ss -lun | grep 15001        # пусто
ip rule show | grep 'fwmark 0x1'   # пусто
ip route show table 100            # пусто
systemd-run --system --wait --collect --unit=pfu-nft \
  /bin/sh -c 'nft list table inet pfu'   # No such file or directory
```

### 8.4 Docker TCP

Полный сценарий — `материалы сессии 11/pfu-docker-check.md`. Кратко: добавить
`intercept.docker: true` в конфиг, перезапустить демон, `connect`, затем

```bash
docker run --rm curlimages/curl -s -m 15 https://ifconfig.me
docker run --rm curlimages/curl -s -m 20 -o /dev/null https://speed.hetzner.de/100MB.bin &
sleep 3
ss -tn state established '( sport = :15000 )'   # видно адрес контейнера
```

### 8.5 Нагрузка

```bash
python3 "/home/anony/Documents/Личное/Проект proxy for ubuntu/материалы сессии 11/pfu-load.py"
PID=$(systemctl show -p MainPID --value pfu-devd)
systemd-run --system --wait --collect --unit=pfu-fd /bin/sh -c "ls /proc/$PID/fd | wc -l"
```

Ожидание: 250/250, после — около 14 fd, `EMFILE` в журнале нет.

### 8.6 Сборка пакета и релиз

```bash
# сначала поднять версию в Cargo.toml и tauri.conf.json, затем:
./scripts/build-deb.sh --version 0.1.3 --output dist
# локальная сборка — для этого хоста; для раздачи релизный .deb из CI
git tag -a v0.1.3 -m '0.1.3: …'
git push origin main v0.1.3
```

Версия — в `app/src-tauri/Cargo.toml` и `app/src-tauri/tauri.conf.json`
(дублируется), CHANGELOG — новый раздел, бейдж в README. Тег запускает
`release.yml`; проверить, что оба matrix-джоба зелёные и ассеты на месте.

### 8.7 TUN и DNS на netns-стенде

На этой машине `systemd-run` недоступен (polkit), поэтому стенд идёт в
привилегированном контейнере — сеть хоста не трогается. В серверной netns
нужны оба сервера: эхо TCP/UDP и мини-DNS для `echo.dns.test`:

```bash
docker run -d --privileged --name pfu-stand \
  -v /dev/net/tun:/dev/net/tun \
  -v "/home/anony/Documents/Личное/Проект proxy for ubuntu:/src:ro" \
  ubuntu:24.04 sleep infinity
docker exec pfu-stand bash -c 'apt-get update -qq && apt-get install -y -qq iproute2 nftables python3 util-linux'

cd app/src-tauri && cargo test --test tun_live --no-run
docker cp target/debug/deps/tun_live-<hash> pfu-stand:/bin/tun_live
docker exec pfu-stand bash -c '
  bash "/src/материалы сессии 16/tun-stand.sh" setup
  ip netns exec pfu-tun-srv python3 -u "/src/материалы сессии 16/tun-echo.py" &
  ip netns exec pfu-tun-srv python3 -u "/src/материалы сессии 16/dns-echo.py" &
  sleep 1
  bash "/src/материалы сессии 16/tun-stand.sh" test /bin/tun_live
  bash "/src/материалы сессии 16/tun-stand.sh" teardown'
```

Ожидание: `3 passed` (TUN roundtrip, DNS `redir-host`, DNS `HIJACK-DNS`),
после `teardown` нет `pfu0`, правила `fwmark 0x2` и таблицы `inet pfu`.

### 8.8 Аварийная очистка (если сеть «пропала»)

```bash
systemctl stop proxy-for-ubuntud pfu-devd
systemd-run --system --wait --collect --unit=pfu-clean /bin/sh -c '
  nft delete table inet pfu 2>/dev/null
  ip rule del fwmark 0x1 lookup 100 2>/dev/null
  ip route flush table 100 2>/dev/null'
curl -m 8 -sS -o /dev/null -w '%{http_code}\n' https://example.com
```

---

## 9. Материалы прошлых сессий

| Путь | Что внутри |
|---|---|
| `материалы сессии 9/` | патч `wip-redirect-tproxy.patch`, эксперимент с UDP `udp_origdst_test.py`, nft-стенд `pfutest2.nft` |
| `материалы сессии 10/` | патч `572eac8`, UDP-стенд из двух netns (`pfu-udp-stand.sh`, `pfu-udp-echo.py`, `pfu-udp-probe.py`), `pfu-state-check.sh` |
| `материалы сессии 11/` | `pfu-load.py` (нагрузка), `pfu-docker-check.md` (Docker TCP), `release/` — релизный `.deb` 0.1.2 + `.sha256` |
| `материалы сессии 12/` | `README.md` — что проверено живьём (TCP, UDP 5/5, статистика); `release/` — `.deb` 0.1.3 + `.sha256` |
| `материалы сессии 14/` | стенд Xray для проверки протоколов: `xray.config.json`, `pfu-config.yaml`, `README.md` с командами и разбором дефекта VMess |
| `материалы сессии 15/` | TUN: netns-стенд (`tun-stand.sh`), эхо-сервер (`tun-echo.py`), `README.md` с результатами и запуском через привилегированный контейнер |
| `материалы сессии 16/` | DNS: тот же стенд плюс мини-DNS (`dns-echo.py`) для `echo.dns.test`, `README.md` с тем, что именно доказывает каждый шаг |

`PROGRESS_2026-10-29.md` — хронология сессий 13–16.
`PROGRESS_2026-10-26.md` — хронология сессий 9–12 (§11).
`SESSION_SUMMARY.md` — итог сессий 1–8. Подробности сессий 14–16 — в
`PROGRESS_2026-10-29.md`, `материалы сессии 14/README.md`,
`материалы сессии 16/README.md` и §2, §6.4, §6.5, §7.

---

## 10. Открытые вопросы к пользователю (решить до крупных работ)

1. **IPv6:** пока только guard (v6 напрямую) или полноценная поддержка в TUN
   отдельной сессией? Сейчас v6 идёт напрямую.
2. ~~**DNS:** `fake-ip` или `redir-host`?~~ Решено 29.10.2026: **`redir-host`**,
   сделано в сессии 16 (§6.4).
3. **`127.0.0.53` (systemd-resolved):** перехватывать запросы системного
   резолвера (нужен слушатель на loopback и правка настройки resolved) или
   оставить как есть и держать ограничение в документации? Сейчас мимо идут
   все запросы через резолвер.
4. **PPA/apt-репозиторий:** есть ли аккаунт Launchpad и готовность подписывать
   пакеты, или оставить установку вручную?
5. **Живые серверы для протоколов:** есть ли Xray/VLESS/VMess-сервер, на
   котором можно проверить e2e помимо контейнера в CI?
6. **Целевые версии Ubuntu:** 22.04 и 24.04 — подтверждаем? Пакет в CI
   собирается на обеих, но релизный ассет один.

Решено в сессии 15: TUN — собственный минимальный стек, без `smoltcp`.
Решено в сессии 16: `fake-ip` не реализуем, валидация его отклоняет;
`HIJACK-DNS` отвечает локально.
