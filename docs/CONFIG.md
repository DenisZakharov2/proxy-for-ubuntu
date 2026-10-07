# Схема конфигурации

Активный конфиг: `/etc/proxy-for-ubuntu/config.yaml`. Формат — YAML, совместимый
по духу с Clash, но с расширениями (см. ниже). Чужие Clash-конфиги **не**
импортируются один в один: конвертер `pfu-cli convert clash.yaml` переносит
`proxies` → `outbounds` и `proxy-groups` → `groups`.

Полный пример — [`/usr/share/proxy-for-ubuntu/profiles/example.yaml`](../packaging/profiles/example.yaml).

## Верхний уровень

```yaml
api: 1                  # версия IPC-контракта
log:
  level: info           # trace|debug|info|warn|error
  journal: true         # писать в journald
  file: /var/log/proxy-for-ubuntu/engine.log
dns:
  strategy: fake-ip     # fake-ip | redir-host
  cache_size: 4096
  cache_ttl: 300
  servers:
    - 1.1.1.1
    - 8.8.8.8
  fallback: [9.9.9.9, 1.0.0.1]

tun:
  enabled: false        # см. раздел «Режимы перехвата»
  device: pfu0
  mtu: 9000
  strict_route: true

intercept:
  tcp: redirect          # redirect | tproxy
  udp: tproxy            # tproxy | off
  exclude_uid: []        # uid, чей трафик не трогаем (например, сам демон = 0)
  exclude_ports: [22]    # SSH наружу, чтобы не потерять доступ к машине
  bypass_private: true   # 10/8, 172.16/12, 192.168/16, 127/8 — напрямую
  loop_protect: true     # не заворачивать трафик самого демона обратно в демон

outbounds:
  - name: DIRECT
    type: direct
  - name: Работа
    type: socks5
    server: 1.2.3.4
    port: 1080
    username: ""         # необязательно
    password: ""
    udp: true
    remote_dns: true     # true == socks5h: домен не резолвится локально

rules:
  - DOMAIN-SUFFIX,ads.example,REJECT
  - GEOSITE,category-ads-all,REJECT
  - GEOIP,cn,DIRECT
  - DOMAIN-SUFFIX,vk.com,Работа
  - PROCESS,firefox,Работа
  - DST-PORT,443,Работа
  - MATCH,DIRECT

final: DIRECT
```

## Режимы перехвата

| Режим | Что захватывает | Требования | Когда включать |
|---|---|---|---|
| `redirect` (TCP) | весь исходящий TCP | `nftables`, root | по умолчанию, быстрее всего |
| `tproxy` (TCP/UDP) | TCP + UDP, включая QUIC | `nftables` + `IP_TRANSPARENT` | нужен UDP/QUIC/игры |
| `off` | ничего, только системные переменные | — | проверка, что всё работает после установки |

Почему не TUN как основной режим: TUN требует пользовательского сетевого стека
в userspace, чтобы разбирать IP-пакеты целиком, и в 10 раз дороже по CPU. Задача
«перехватить весь системный трафик, включая DNS и QUIC, и направить его по
правилам» решается парой правил nftables точнее и надёжнее. Режим `tun` оставлен
для сценариев, где нужен не-TCP трафик (ESP, GRE), и по умолчанию выключен.

## `outbounds`

Общие поля для всех типов: `name` (уникальное), `type`, `udp` (разрешён ли UDP через
этот outbound), `test_url`, `test_timeout_ms`.

### `direct`
Ничего не настраивает.

### `http`
CONNECT-прокси.

```yaml
- name: HTTP
  type: http
  server: proxy.local
  port: 8080
  username: user
  password: pass    # или password_file: /etc/proxy-for-ubuntu/secrets/http
```

### `socks5` / `socks5h`

```yaml
- name: SOCKS
  type: socks5h
  server: 1.2.3.4
  port: 1080
  username: ""
  password: ""
  udp: true
```

Разница только в `remote_dns`: у `socks5` домен резолвится локально (DNS-утечка),
у `socks5h` домен передаётся прокси как есть.

### `shadowsocks`

```yaml
- name: SS
  type: shadowsocks
  server: 1.2.3.4
  port: 8388
  method: chacha20-ietf-poly1305   # или aes-256-gcm
  password: "base64-ключ-или-пароль"
  plugin: ""                       # не поддерживается, оставлено для совместимости
  udp: true
```

Методы: `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-256-gcm`, `aes-128-cfb`,
`aes-256-cfb`, `chacha20`, `rc4-md5`. AEAD-режим (по умолчанию) — обязателен;
legacy-шифры без AEAD помечены в UI как небезопасные.

### `trojan`

```yaml
- name: Trojan
  type: trojan
  server: trojan.example
  port: 443
  password: "пароль"
  sni: trojan.example
  alpn: [h2, http/1.1]
  skip_cert_verify: false
  udp: true
```

### `vless`

```yaml
- name: VLESS
  type: vless
  server: v.example
  port: 443
  uuid: "b831381d-6324-4d53-ad4f-8cda48b30811"
  flow: ""                 # xtls-rprx-vision требует Reality, не поддержан
  network: tcp             # tcp | ws
  tls: true
  sni: v.example
  path: /                  # для ws
  host: ""                 # ws Host
  skip_cert_verify: false
  udp: true
```

### `vmess`

```yaml
- name: VMess
  type: vmess
  server: v.example
  port: 443
  uuid: "…"
  alter_id: 0              # AEAD-режим только с alterId = 0
  security: auto           # auto | aes-128-gcm | chacha20-poly1305 | none
  network: tcp             # tcp | ws
  tls: true
  sni: v.example
  path: /
  host: ""
  skip_cert_verify: false
  udp: true
```

### `ssh`

```yaml
- name: SSH
  type: ssh
  server: jump.example
  port: 22
  username: user
  password: ""             # либо
  key_file: "~/.ssh/id_ed25519"
  passphrase: ""
  host_key_algorithms: [ssh-ed25519, rsa-sha2-512]
  keepalive: 30
```

Реализовано как локальный SOCKS5 `DIRECT` по `ssh -D`: протокол SSH целиком
делегирован системному OpenSSH, а не написан с нуля. Направление, SNI, маршрут по
правилам и учёт трафика работают как у всех остальных outbound'ов.

## `rules`

Список выполняется сверху вниз, первое совпадение выигрывает. Формат строки —
`ТИП,ПАРАМЕТРЫ,ДЕЙСТВИЕ[,ДОПОЛНИТЕЛЬНО]`.

### Типы

| Тип | Параметры | Пример |
|---|---|---|
| `DOMAIN` | домен целиком | `DOMAIN,example.com,REJECT` |
| `DOMAIN-SUFFIX` | суффикс с точкой | `DOMAIN-SUFFIX,vk.com,Работа` |
| `DOMAIN-KEYWORD` | подстрока | `DOMAIN-KEYWORD,google,Работа` |
| `DOMAIN-REGEX` | регулярное выражение | `DOMAIN-REGEX,^ads[0-9]*,REJECT` |
| `IP-CIDR` | `адрес/маска` | `IP-CIDR,10.0.0.0/8,DIRECT` |
| `GEOIP` | тег набора | `GEOIP,cn,DIRECT` |
| `GEOSITE` | тег набора | `GEOSITE,category-ads-all,REJECT` |
| `DST-PORT` | порт или `1000-2000` | `DST-PORT,443,Работа` |
| `SRC-PORT` | порт | `SRC-PORT,5000-5010,DIRECT` |
| `PROCESS-NAME` | имя процесса | `PROCESS-NAME,firefox,Работа` |
| `PROCESS-PATH` | полный путь | `PROCESS-PATH,/usr/bin/ssh,DIRECT` |
| `UID` | числовой uid | `UID,1000,DIRECT` |
| `NETWORK` | `tcp` / `udp` | `NETWORK,udp,DIRECT` |
| `MATCH` | — | `MATCH,DIRECT` |

### Действия

- имя outbound'а из `outbounds` — трафик пойдёт через него
- `DIRECT` — напрямую (встроенный outbound, создаётся всегда)
- `REJECT` — соединение закрывается сразу, RST/ICMP unreachable
- `REJECT-DROP` — пакет молча теряется
- `HIJACK-DNS` — принудительно наш DNS-резолвер

### Группы

```yaml
groups:
  - name: Правила РФ
    type: select          # select | url-test | fallback | load-balance
    outbounds: [Работа, DIRECT]
    interval_sec: 300     # для url-test и fallback
    url: https://www.gstatic.com/generate_204
```

`select` — ручной выбор, `url-test` — автопроверка задержки с переключением на
лучший, `fallback` — первый рабочий по списку, `load-balance` — round-robin по
соединениям.

## `geo`

```yaml
geo:
  auto_update: true
  update_interval_hours: 24
  sources:
    - { kind: geoip,   tag: cn, url: "https://…/cn.txt",     sha256: "" }
    - { kind: geosite, tag: category-ads-all,
        url: "https://…/ads.txt", sha256: "" }
```

`sha256` необязателен, но если задан — файл принимается только при совпадении
хэша. Пустой `tag` (без имени) означает «все наборы этого вида».

## `groups` и «что делать банку»

Активный профиль хранится симлинком:

```
/etc/proxy-for-ubuntu/config.yaml -> /etc/proxy-for-ubuntu/profiles/Работа.yaml
```

`profile.activate` переключает симлинк и вызывает `config.apply`. Откат —
`config.rollback` возвращает предыдущий снапшот целиком.

## Переменные окружения

Подстановка `${VAR}` работает в строковых полях, включая пароли:

```yaml
password: "${SS_PASSWORD}"
```

Значения берутся из `/etc/proxy-for-ubuntu/env` (режим `0600`, владелец root) и из
окружения демона. Это позволяет не хранить секреты в YAML.
