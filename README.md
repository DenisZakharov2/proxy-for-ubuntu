<div align="center">

# proxy-for-ubuntu

**Системная маршрутизация трафика через прокси для Ubuntu**

<img src="packaging/icons/proxy-for-ubuntu.svg" width="96" alt="proxy-for-ubuntu">

Весь TCP и UDP-трафик системы — включая DNS и QUIC — направляется через прокси
по правилам в духе Clash. Ядро написано с нуля на Rust, без sing-box, Xray и clash.

[![Лицензия](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Версия](https://img.shields.io/badge/version-0.1.0-blue.svg)](CHANGELOG.md)
[![Платформа](https://img.shields.io/badge/Ubuntu-22.04%20|%2024.04-orange.svg)](https://ubuntu.com/)

</div>

<!--
  СКРИНШОТЫ: заменить после первого публичного запуска.
  Снимки делать на виртуальной машине с включённым перехватом, без личных
  данных и без видимых адресов прокси.
  1. Обзор — главный экран со статистикой
  2. Редактор правил
  3. Диагностика окружения
-->

---

## Что это

Обычный прокси настраивается в приложении, которое его запустило. Браузер
узнаёт о нём, `apt` — нет. `docker pull`, `git`, игровой клиент, `systemd` —
тоже нет.

`proxy-for-ubuntu` перехватывает трафик на уровне ядра через `nftables` и
пропускает каждое соединение через rule engine. Правила выглядят так же,
как в Clash, и читаются без документации:

```yaml
rules:
  - GEOSITE,category-ads-all,REJECT     # рекламу — в стену
  - DOMAIN-SUFFIX,mail.ru,DIRECT        # почту — напрямую
  - GEOIP,cn,DIRECT                     # китайские адреса — напрямую
  - MATCH,Основной                      # всё остальное — через прокси
```

## Быстрый старт

```bash
# 1. Скачать .deb из релизов и поставить
sudo apt install ./proxy-for-ubuntu_0.1.0_amd64.deb

# 2. Запустить демон
sudo systemctl start proxy-for-ubuntud

# 3. Открыть приложение
proxy-for-ubuntu
```

В приложении: **Прокси → Добавить** (впишите адрес своего сервера) →
**Проверить** → **Применить**. Тумблер на экране «Обзор» включает сам перехват.

Установка пакета намеренно **не** включает перехват: менять маршрутизацию
всей системы без явного действия пользователя — плохая идея.

## Как это работает

```
┌─ приложение (ваш пользователь) ─┐
│  общается с демоном по сокету    │
└──────────────┬───────────────────┘
               │ JSON-RPC
┌──────────────▼───────────────────┐
│  демон (root, systemd)           │
│                                 │
│  nftables: пометка пакетов      │
│  ip rule:  таблица 100          │
│      ↓                          │
│  rule engine → outbound         │
│      ↓                          │
│  SOCKS5 · HTTP · Shadowsocks ·  │
│  Trojan · VLESS · VMess · SSH    │
└─────────────────────────────────┘
```

Маршруты не меняются. Используется политическая маршрутизация по метке: пакеты
помечаются, помеченные уходят в таблицу 100, где их встречает наш обработчик.
Нетронутым остаётся всё, что не перехватывается, — и после `apt remove`
система возвращается в обычное состояние самостоятельно.

Подробности: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Протоколы

| Протокол | Состояние | Замечания |
|---|:--:|---|
| `direct` | ✅ рабочий | прямое соединение |
| `http` | ✅ рабочий | CONNECT с Basic-аутентификацией |
| `socks5` / `socks5h` | ✅ рабочий | UDP ASSOCIATE; `socks5h` резолвит домен на прокси |
| `shadowsocks` | ✅ рабочий | AEAD: ChaCha20-Poly1305, AES-128/256-GCM |
| `trojan` | ✅ рабочий | проверка пароля на каждом пакете |
| `ssh` | ✅ рабочий | делегирован системному OpenSSH (`ssh -D`) |
| `vless` | ⚠ не проверен | написан по спецификации, не сверялся с живым Xray-сервером |
| `vmess` | ⚠ не проверен | то же; только AEAD-режим с `alterId: 0` |

Честно про последние два: код компилируется и проходит тесты на собственных
серверах, но **ни разу не подключался к настоящему xray-серверу**. Проверив
свой случай, напишите issue — снимок экрана из лога будет лучшим
подтверждением, чем слово. В интерфейсе такие прокси помечены значком ⚠.

Не поддерживается: Reality/XTLS в VLESS, gRPC-транспорт, плагины
Shadowsocks, `alterId != 0` у VMess.

## Пример конфигурации

```yaml
api: 1

dns:
  strategy: fake-ip      # домен известен движку, локальный резолвер ничего не видит
  servers: [1.1.1.1, 8.8.8.8]

intercept:
  tcp: redirect
  udp: tproxy
  exclude_ports: ["22"] # SSH наружу — иначе потеряете доступ к машине

outbounds:
  - name: DIRECT
    type: direct
  - name: Мой прокси
    type: socks5h
    server: 1.2.3.4
    port: 1080
    udp: true

rules:
  - GEOSITE,category-ads-all,REJECT
  - DOMAIN-SUFFIX,sberbank.ru,DIRECT
  - PROCESS-NAME,ssh,DIRECT
  - MATCH,Мой прокси

final: DIRECT
```

Полный список полей, типов правил и групп — [docs/CONFIG.md](docs/CONFIG.md).
Готовые примеры лежат в `packaging/profiles/`.

## Применение с откатом

Кнопка «Применить» не просто пишет конфиг:

1. **Снапшот** текущих правил nftables и `ip rule` — `/var/lib/proxy-for-ubuntu/rollback/`.
2. **Валидация** конфига без сети и без прав.
3. **Живая проверка** каждого прокси настоящим TCP-соединением.
4. **Применение** и health-check: DNS отвечает, тестовое соединение проходит.
5. Любая ошибка на шагах 3–5 → **система возвращается в прежнее состояние**.

Если после «Применить» интернет пропал — скорее всего, вы это уже увидели в
виде красного уведомления, а машина при этом работает как до нажатия кнопки.

## Приватность

- **DNS не течёт** при `fake-ip` и при прокси с `remote_dns`: домен уходит
  прокси, локальный резолвер не знает ваших запросов.
- **Секреты не в конфиге.** Пароль можно вынести в `/etc/proxy-for-ubuntu/env`
  и сослаться как `${SS_PASSWORD}` — в YAML он не лежит открытым текстом.
- **Логи** содержат адреса назначения и названия правил, но не пароли.
  Экспорт профиля для баг-репорта умеет заменять секреты на `***REDACTED***`.
- Весь трафик идёт через сервер, который **вы** выбрали и **вы** оплачиваете.
  У проекта нет серверов, телеметрии и аккаунтов.

## CLI

Пригодится на сервере и в CI:

```bash
sudo pfu-cli connect          # включить перехват
pfu-cli status                # состояние демона
pfu-cli doctor                # проверить окружение
pfu-cli rules                 # правила маршрутизации
pfu-cli proxies               # список прокси
pfu-cli metrics               # текущий трафик

# конфиг в файл → правка → применение
pfu-cli config > my.yaml
$EDITOR my.yaml
sudo pfu-cli apply < my.yaml
```

## Решение проблем

| Симптом | Причина и что делать |
|---|---|
| После `apt install` тумблер не работает | Не запущен демон: `sudo systemctl start proxy-for-ubuntud` |
| «nftables отклонил набор правил» | Нет прав или правила заняты: `sudo nft list ruleset` |
| QUIC/игры не идут через прокси | Нужен `intercept.udp: tproxy` и outbound с `udp: true` |
| Интернет пропал после Apply | Демон не откатил изменения: `sudo systemctl stop proxy-for-ubuntud && sudo nft delete table inet pfu; sudo ip rule del fwmark 0x1 lookup 100; sudo ip route flush table 100` |
| `Permission denied` на `/run/proxy-for-ubuntu/ctl.sock` | Пользователь не в группе `proxy-for-ubuntu`. При установке через `sudo apt` группа добавляется автоматически; если ставили из графического менеджера — `sudo usermod -aG proxy-for-ubuntu $USER` и повторный вход в систему |
| Окно приложения открывается пустым | WebKitGTK не рисует интерфейс на LXQt/Xfce с Openbox. `proxy-for-ubuntu` сам выставляет `WEBKIT_DISABLE_DMABUF_RENDERER=1`; если не помогло — `LIBGL_ALWAYS_SOFTWARE=1 proxy-for-ubuntu`. Диагностика: `proxy-for-ubuntu --diagnose` |
| `proxy-for-ubuntu --version` ничего не выводит | Устаревшая сборка: команда добавлена в 0.1.1. Переустановите пакет |
| `ssh` перестал работать | Он по умолчанию исключён из перехвата (`exclude_ports: ["22"]`). Проверьте, не переписали ли это |
| Docker не использует прокси | Трафик контейнеров идёт через `FORWARD`, а не `OUTPUT`. Смотрите [docs/TESTING.md](docs/TESTING.md) |
| Часть правил не срабатывает | Не скачаны geo-наборы: вкладка «Geo-наборы» → «Обновить» |
| `systemd-resolved` ругается на порт 53 | Перехват DNS перехватывает и его — это ожидаемо, в логе будет информационная запись |

Подробный чек-лист: [docs/TESTING.md](docs/TESTING.md).

## Сборка из исходников

```bash
sudo apt install build-essential pkg-config libwebkit2gtk-4.1-dev \
     libayatana-appindicator3-dev librsvg2-dev nftables
git clone https://github.com/DenisZakharov2/proxy-for-ubuntu
cd proxy-for-ubuntu
./scripts/build-deb.sh --output dist
sudo apt install ./dist/proxy-for-ubuntu_0.1.0_amd64.deb
```

## Документация

| Файл | О чём |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | устройство движка, перехвата, отката |
| [docs/CONFIG.md](docs/CONFIG.md) | все поля конфигурации и типы правил |
| [docs/IPC.md](docs/IPC.md) | контракт GUI ↔ демон, коды ошибок |
| [docs/PROTOCOLS.md](docs/PROTOCOLS.md) | реализация каждого протокола и ограничения |
| [docs/TESTING.md](docs/TESTING.md) | чек-лист ручной проверки перед релизом |
| [English README](README.en.md) | the same, in English |

## Участие

Приветствуются issue и PR. Особенно нужны:

- отчёты о работоспособности `vless` и `vmess` против живых серверов;
- дополнительные geo-наборы;
- переводы интерфейса (сейчас ru и en).

Подробности — [CONTRIBUTING.md](CONTRIBUTING.md).

## Лицензия

MIT © 2026 Denis Zakharov. См. [LICENSE](LICENSE).
