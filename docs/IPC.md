# IPC-контракт GUI ↔ демон

Демон слушает Unix-сокет `/run/proxy-for-ubuntu/ctl.sock` (права `0660`, группа
`proxy-for-ubuntu`). Протокол — newline-delimited JSON: одно JSON-сообщение на
строку. Запрос:

```json
{ "id": 7, "method": "config.get", "params": {} }
```

Ответ:

```json
{ "id": 7, "ok": true, "result": { ... } }
{ "id": 7, "ok": false, "error": { "code": "E_CONFIG_INVALID", "message": "...", "detail": "..." } }
```

События (id отсутствует) шлются в тот же сокет:

```json
{ "event": "state", "data": { ... } }
{ "event": "log", "data": { "ts": 1728261234, "level": "warn", "message": "..." } }
{ "event": "metrics", "data": { "rx": 12345, "tx": 67890, "conns": 12 } }
```

GUI (Tauri) — тонкая обёртка: команда фронтенда уходит по сокету в демон и
возвращает `result`. Никакой бизнес-логики на стороне GUI.

---

## Методы

### `daemon.status`

```json
→ { "daemon": "running"|"stopped"|"degraded",
    "version": "0.1.0",
    "pid": 1234,
    "uptime_sec": 3600,
    "config_loaded_at": 1728261234,
    "config_valid": true }
```

### `config.get`

Возвращает активный конфиг целиком.

```json
→ { "config": { /* Config, см. CONFIG.md */ },
    "path": "/etc/proxy-for-ubuntu/config.yaml",
    "is_default": false }
```

### `config.validate`

Принимает черновик конфига, **ничего не применяет**.

```json
← { "config": { ... } }
→ { "valid": true,  "warnings": ["geoip:cn пуст — правило не сработает"] }
→ { "valid": false, "errors": [
      { "path": "outbounds[2].port", "message": "порт вне диапазона 1-65535" }
    ] }
```

### `config.apply`

Главный вызов. Выполняет полный цикл из `ARCHITECTURE.md` §6.4: снапшот →
валидация → dry-run проверка outbound'ов → commit → health-check, с откатом при
любой ошибке.

```json
← { "config": { ... }, "activate": true, "reason": "user" }
→ { "ok": true, "backup": "/var/lib/proxy-for-ubuntu/rollback/1728261234.yaml" }
→ { "ok": false, "stage": "health-check",
    "message": "DNS не отвечает через новый маршрут",
    "rolled_back": true,
    "errors": [ ... ] }
```

`stage` — одно из `validate` | `probe` | `commit` | `health-check`.
`rolled_back: true` означает, что система уже возвращена в рабочее состояние и
пользователю не нужно ничего делать руками.

### `config.rollback`

Возвращает снапшот последней неудачной попытки.

```json
→ { "ok": true, "restored_from": "/var/lib/proxy-for-ubuntu/rollback/1728261230.yaml" }
→ { "ok": false, "message": "нет сохранённых снапшотов" }
```

### `system.toggle`

```json
← { "enabled": true }
→ { "enabled": true, "status": "connected", "message": "" }
```

### `system.diagnose`

Диагностика окружения: версия ядра, права, наличие `nft`/`ip`, доступность
TUN, состояние таблиц, последние ошибки.

```json
→ { "checks": [
      { "id": "kernel", "name": "Версия ядра", "ok": true,  "detail": "6.8.0-generic" },
      { "id": "nft",    "name": "nftables",    "ok": true,  "detail": "v1.0.6" },
      { "id": "tun",    "name": "TUN/TAP",     "ok": false, "detail": "нет /dev/net/tun",
        "fix": "sudo modprobe tun && echo tun > /etc/modules-load.d/tun.conf" }
    ],
    "fatal": ["tun"] }
```

### `outbound.test`

Живая проверка соединения. `target` по умолчанию `example.com:443`.

```json
← { "outbound": { ... }, "target": { "host": "example.com", "port": 443 }, "timeout_ms": 5000 }
→ { "ok": true,  "latency_ms": 214, "resolved_via": "remote"|"local", "detail": "" }
→ { "ok": false, "latency_ms": null, "error": "TLS handshake failed: cert verify failed" }
```

`resolved_via: "local"` для SOCKS5 (не `socks5h`) — предупреждение об утечке DNS,
GUI подсвечивает его жёлтым.

### `geo.list` / `geo.update` / `geo.preview`

```json
geo.list   → { "sets": [ { "kind": "geoip", "tag": "cn", "count": 8421,
                            "updated_at": 1728200000, "sha256": "ab12…", "source": "…" } ] }
geo.update ← { "kind": "geoip", "tag": "cn" }
           → { "ok": true, "count": 8430, "added": 9, "removed": 0 }
geo.preview ← { "kind": "geoip", "tag": "cn", "limit": 200 }
           → { "lines": ["1.0.1.0/24", "1.0.2.0/23", …] }
```

### `profile.list` / `profile.read` / `profile.write` / `profile.delete` / `profile.activate`

Профили в `~/.config/proxy-for-ubuntu/profiles/*.yaml`.

```json
profile.list    → { "profiles": [ { "name": "Работа", "builtin": false, "updated_at": 1728200000 } ] }
profile.read    ← { "name": "Работа" }        → { "config": { ... } }
profile.write   ← { "name": "Работа", "config": { ... } }  → { "ok": true }
profile.delete  ← { "name": "Работа" }        → { "ok": true }
profile.activate ← { "name": "Работа" }       → { "ok": true, "needs_restart": false }
```

`builtin: true` — профиль из `/usr/share/proxy-for-ubuntu/profiles/default.yaml`,
защищён от удаления и редактирования.

### `profile.import` / `profile.export`

```json
profile.import ← { "name": "SS", "yaml": "…", "activate": false, "validate": true }
              → { "ok": true, "warnings": [ … ], "errors": [] }
profile.export ← { "name": "Работа", "redact_secrets": true }
              → { "ok": true, "yaml": "…", "path": null }
```

`redact_secrets: true` заменяет пароли, UUID и private-ключи на
`***REDACTED***` — для баг-репортов.

### `subscription.update`

```json
← { "name": "Мой SS", "url": "https://…", "interval_hours": 24,
    "auto_activate": true }
→ { "ok": true, "outbounds_found": 14, "rules_found": 87, "activated": true }
```

### `log.tail` / `log.search` / `log.export`

```json
log.tail   ← { "lines": 500, "level": "info"|"warn"|"error"|null }
          → { "entries": [ { "ts": 1728261234, "level": "info",
                              "target": "engine::nft", "message": "…" } ] }
log.export ← { "level": null, "since": null }
          → { "ok": true, "path": "/home/u/Desktop/pfu-log.txt" }
```

### `metrics.live`

```json
→ { "up": 1048576, "down": 5242880, "connections": 12,
    "active_rules": [ { "rule": "geosite:category-ads-all", "policy": "REJECT",
                        "bytes": 1024, "conns": 40 } ],
    "by_outbound": [ { "name": "Мой VPS", "bytes": 6291456, "conns": 88 } ] }
```

### `system.logs`

Единая точка для всех сообщений, которые GUI должен показать пользователю.

```json
→ { "ok": false, "stage": "commit", "message": "…", "fix": "sudo nft list ruleset" }
```

---

## Коды ошибок

| Код | Значение | Что показывать пользователю |
|---|---|---|
| `E_NO_DAEMON` | демон не отвечает | «Запустите демон: `sudo systemctl start proxy-for-ubuntud`» |
| `E_CONFIG_INVALID` | YAML/YAML-схема | список с путями |
| `E_NO_OUTBOUND` | ни одного outbound | «Добавьте хотя бы один прокси» |
| `E_PROBE_FAILED` | проверка связи не прошла | текст ошибки протокола |
| `E_APPLY` | сбой при применении | этап + подсказка |
| `E_ROLLED_BACK` | применение провалено, откат выполнен | «Изменения не применились, система в прежнем состоянии» |
| `E_PERM` | нет прав | polkit-подсказка |
| `E_NOT_FOUND` | профиль/набор не найден | — |

## Правила совместимости

Контракт версионируется: демон шлёт поле `"api": 1` в ответе. GUI при `api < 1`
показывает баннер «Версия демона устарела, обновите пакет», при `api > 1` —
«Пакет GUI устарел». Миноры обратно совместимы: новое поле в `result` —
нормально, удаление или смена типа — нет.
