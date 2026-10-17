# IPC contract GUI ↔ daemon

The daemon listens on the Unix socket `/run/proxy-for-ubuntu/ctl.sock` (mode
`0660`, group `proxy-for-ubuntu`). Protocol — newline-delimited JSON: one JSON
message per line. Request:

```json
{ "id": 7, "method": "config.get", "params": {} }
```

Response:

```json
{ "id": 7, "ok": true, "result": { ... } }
{ "id": 7, "ok": false, "error": { "code": "E_CONFIG_INVALID", "message": "...", "detail": "..." } }
```

Events (without `id`) are sent to the same socket:

```json
{ "event": "state", "data": { ... } }
{ "event": "log", "data": { "ts": 1728261234, "level": "warn", "message": "..." } }
{ "event": "metrics", "data": { "rx": 12345, "tx": 67890, "conns": 12 } }
```

GUI (Tauri) — a thin wrapper: a frontend command goes over the socket to the
daemon and returns `result`. No business logic on the GUI side.

---

## Methods

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

Returns the entire active config.

```json
→ { "config": { /* Config, see CONFIG.en.md */ },
    "path": "/etc/proxy-for-ubuntu/config.yaml",
    "is_default": false }
```

### `config.validate`

Accepts a config draft, **applies nothing**.

```json
← { "config": { ... } }
→ { "valid": true,  "warnings": ["geoip:cn is empty — the rule will not match"] }
→ { "valid": false, "errors": [
      { "path": "outbounds[2].port", "message": "port out of range 1-65535" }
    ] }
```

### `config.apply`

The main call. Performs the full cycle from `ARCHITECTURE.en.md` §6.4:
snapshot → validation → dry-run probe of outbounds → commit → health-check,
with rollback on any error.

```json
← { "config": { ... }, "activate": true, "reason": "user" }
→ { "ok": true, "backup": "/var/lib/proxy-for-ubuntu/rollback/1728261234.yaml" }
→ { "ok": false, "stage": "health-check",
    "message": "DNS is not responding via the new route",
    "rolled_back": true,
    "errors": [ ... ] }
```

`stage` is one of `validate` | `probe` | `commit` | `health-check`.
`rolled_back: true` means the system has been returned to a working state and
the user does not need to do anything manually.

### `config.rollback`

Restores the snapshot of the last failed attempt.

```json
→ { "ok": true, "restored_from": "/var/lib/proxy-for-ubuntu/rollback/1728261230.yaml" }
→ { "ok": false, "message": "no stored snapshots" }
```

### `system.toggle`

```json
← { "enabled": true }
→ { "enabled": true, "status": "connected", "message": "" }
```

### `system.diagnose`

Environment diagnostics: kernel version, permissions, availability of `nft`/
`ip`, TUN availability, table state, latest errors.

```json
→ { "checks": [
      { "id": "kernel", "name": "Kernel version", "ok": true,  "detail": "6.8.0-generic" },
      { "id": "nft",    "name": "nftables",    "ok": true,  "detail": "v1.0.6" },
      { "id": "tun",    "name": "TUN/TAP",     "ok": false, "detail": "no /dev/net/tun",
        "fix": "sudo modprobe tun && echo tun > /etc/modules-load.d/tun.conf" }
    ],
    "fatal": ["tun"] }
```

### `outbound.test`

Live connection check. `target` defaults to `example.com:443`.

```json
← { "outbound": { ... }, "target": { "host": "example.com", "port": 443 }, "timeout_ms": 5000 }
→ { "ok": true,  "latency_ms": 214, "resolved_via": "remote"|"local", "detail": "" }
→ { "ok": false, "latency_ms": null, "error": "TLS handshake failed: cert verify failed" }
```

`resolved_via: "local"` for SOCKS5 (not `socks5h`) — DNS leak warning,
highlighted yellow in the GUI.

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

Profiles in `~/.config/proxy-for-ubuntu/profiles/*.yaml`.

```json
profile.list    → { "profiles": [ { "name": "Work", "builtin": false, "updated_at": 1728200000 } ] }
profile.read    ← { "name": "Work" }        → { "config": { ... } }
profile.write   ← { "name": "Work", "config": { ... } }  → { "ok": true }
profile.delete  ← { "name": "Work" }        → { "ok": true }
profile.activate ← { "name": "Work" }       → { "ok": true, "needs_restart": false }
```

`builtin: true` — a profile from
`/usr/share/proxy-for-ubuntu/profiles/default.yaml`, protected from deletion
and editing.

### `profile.import` / `profile.export`

```json
profile.import ← { "name": "SS", "yaml": "…", "activate": false, "validate": true }
              → { "ok": true, "warnings": [ … ], "errors": [] }
profile.export ← { "name": "Work", "redact_secrets": true }
              → { "ok": true, "yaml": "…", "path": null }
```

`redact_secrets: true` replaces passwords, UUIDs, and private keys with
`***REDACTED***` — for bug reports.

### `subscription.update`

```json
← { "name": "My SS", "url": "https://…", "interval_hours": 24,
    "auto_activate": true }
→ { "ok": true, "outbounds_found": 14, "rules_found": 87, "activated": true }
```

### `log.tail` / `log.search` / `log.export`

```json
log.tail    ← { "lines": 500, "level": "info"|"warn"|"error"|null }
           → { "entries": [ { "ts": 1728261234, "level": "info",
                               "target": "engine::nft", "message": "…" } ] }

log.search  ← { "query": "nft", "level": null, "limit": 200 }
           → { "entries": [ … ], "total": 3 }

log.export  ← { "level": null }
           → { "ok": true, "path": "/home/u/.cache/proxy-for-ubuntu/engine-log.txt" }
```

`log.search` searches for a substring, case-insensitive, in the `message` and
`target` fields. An empty `query` returns all entries. `limit` defaults to 200,
maximum 5000; the latest matches are returned.

### `metrics.live`

```json
→ { "up": 1048576, "down": 5242880, "connections": 12,
    "active_rules": [ { "rule": "geosite:category-ads-all", "policy": "REJECT",
                        "bytes": 1024, "conns": 40 } ],
    "by_outbound": [ { "name": "My VPS", "bytes": 6291456, "conns": 88 } ] }
```

### `system.logs`

Single point for all messages the GUI must show the user.

```json
→ { "ok": false, "stage": "commit", "message": "…", "fix": "sudo nft list ruleset" }
```

---

## Error codes

| Code | Meaning | What to show the user |
|---|---|---|
| `E_NO_DAEMON` | daemon not responding | "Start the daemon: `sudo systemctl start proxy-for-ubuntud`" |
| `E_CONFIG_INVALID` | YAML / YAML-schema | list with paths |
| `E_NO_OUTBOUND` | no outbound configured | "Add at least one proxy" |
| `E_PROBE_FAILED` | connectivity check failed | protocol error text |
| `E_APPLY` | apply failure | stage + hint |
| `E_ROLLED_BACK` | apply failed, rollback performed | "Changes were not applied, system is in its previous state" |
| `E_PERM` | no permissions | polkit hint |
| `E_NOT_FOUND` | profile / set not found | — |

## Compatibility rules

The contract is versioned: the daemon sends the `"api": 1` field in responses.
The GUI shows a banner "Daemon version is outdated, update the package" when
`api < 1`, and "GUI package is outdated" when `api > 1`. Minors are backward
compatible: a new field in `result` is fine, removal or type change is not.
