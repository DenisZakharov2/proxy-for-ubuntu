<div align="center">

# proxy-for-ubuntu

**System-wide proxy routing for Ubuntu**

<img src="packaging/icons/proxy-for-ubuntu.svg" width="96" alt="proxy-for-ubuntu">

All of the system's TCP and UDP traffic — DNS and QUIC included — is routed
through a proxy according to Clash-style rules. The core is written from
scratch in Rust: no sing-box, no Xray, no clash.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](CHANGELOG.md)
[![Platform](https://img.shields.io/badge/Ubuntu-22.04%20|%2024.04-orange.svg)](https://ubuntu.com/)

</div>

<!--
  SCREENSHOTS: to be replaced after the first public run.
  Capture on a virtual machine with interception enabled, with no personal
  data and no visible proxy addresses.
  1. Overview — main screen with traffic statistics
  2. Rule editor
  3. Environment diagnostics
-->

---

## What this is

A regular proxy is configured inside the app that uses it. The browser learns
about it. `apt` does not. Neither do `docker pull`, `git`, a game client, or
`systemd`.

`proxy-for-ubuntu` intercepts traffic in the kernel via `nftables` and runs
every connection through a rule engine. Rules read like Clash's, because
Clash's rules read well:

```yaml
rules:
  - GEOSITE,category-ads-all,REJECT     # ads go nowhere
  - DOMAIN-SUFFIX,mail.ru,DIRECT        # mail goes direct
  - GEOIP,cn,DIRECT                     # Chinese IPs go direct
  - MATCH,Основной                      # everything else through the proxy
```

## Quick start

```bash
# 1. Grab the .deb from the releases and install it
sudo apt install ./proxy-for-ubuntu_0.1.0_amd64.deb

# 2. Start the daemon
sudo systemctl start proxy-for-ubuntud

# 3. Launch the app
proxy-for-ubuntu
```

In the app: **Proxies → Add** (enter your server) → **Test** → **Apply**.
The toggle on the Overview screen turns interception on.

Installing the package deliberately does **not** enable interception: silently
rerouting an entire system is not something a package should do on your behalf.

## How it works

```
┌─ the app (your user) ────────────┐
│  talks to the daemon over a      │
│  Unix socket                     │
└──────────────┬───────────────────┘
               │ JSON-RPC
┌──────────────▼───────────────────┐
│  daemon (root, systemd)          │
│                                 │
│  nftables: mark packets         │
│  ip rule:  lookup table 100     │
│      ↓                          │
│  rule engine → outbound         │
│      ↓                          │
│  SOCKS5 · HTTP · Shadowsocks ·  │
│  Trojan · VLESS · VMess · SSH    │
└─────────────────────────────────┘
```

Routes are never modified. Instead, packets are marked and marked traffic is
sent to routing table 100, where the daemon picks it up. Everything not
intercepted keeps working normally — and `apt remove` restores the system on
its own.

Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Protocols

| Protocol | Status | Notes |
|---|:--:|---|
| `direct` | ✅ working | plain connection |
| `http` | ✅ working | CONNECT with Basic authentication |
| `socks5` / `socks5h` | ✅ working | UDP ASSOCIATE; `socks5h` resolves domains at the proxy |
| `shadowsocks` | ✅ working | AEAD: ChaCha20-Poly1305, AES-128/256-GCM |
| `trojan` | ✅ working | password verified on every packet |
| `ssh` | ✅ working | delegated to the system OpenSSH (`ssh -D`) |
| `vless` | ⚠ unverified | written from the spec, never tested against a live Xray server |
| `vmess` | ⚠ unverified | same; AEAD mode with `alterId: 0` only |

Being straight about the last two: the code compiles and passes tests against
our own servers, but it has **never connected to a real Xray server**. If you
confirm yours works, please open an issue — a log screenshot is better evidence
than a word. The UI marks such proxies with ⚠.

Not supported: Reality/XTLS in VLESS, the gRPC transport, Shadowsocks plugins,
`alterId != 0` for VMess.

## Example configuration

```yaml
api: 1

dns:
  strategy: fake-ip      # the engine knows the domain; the local resolver does not
  servers: [1.1.1.1, 8.8.8.8]

intercept:
  tcp: redirect
  udp: tproxy
  exclude_ports: ["22"] # keep SSH out of interception, or you lose the machine

outbounds:
  - name: DIRECT
    type: direct
  - name: My proxy
    type: socks5h
    server: 1.2.3.4
    port: 1080
    udp: true

rules:
  - GEOSITE,category-ads-all,REJECT
  - DOMAIN-SUFFIX,sberbank.ru,DIRECT
  - PROCESS-NAME,ssh,DIRECT
  - MATCH,My proxy

final: DIRECT
```

Every field, rule type and group option: [docs/CONFIG.md](docs/CONFIG.md).
Ready-made examples live in `packaging/profiles/`.

## Apply with rollback

The Apply button does more than write a config file:

1. **Snapshot** the current nftables rules and `ip rule` into `/var/lib/proxy-for-ubuntu/rollback/`.
2. **Validate** the config with no network access and no privileges.
3. **Probe** every proxy with a real TCP connection.
4. **Apply**, then health-check: DNS answers, a test connection goes through.
5. Any failure in steps 3–5 → **the system returns to its previous state**.

If the internet disappears after Apply, you almost certainly already saw a red
notification — and the machine is working exactly as it did before you pressed
the button.

## Privacy

- **DNS does not leak** with `fake-ip` and with proxies that resolve remotely:
  the domain goes to the proxy and the local resolver never sees your lookups.
- **Secrets stay out of the config.** Put a password in
  `/etc/proxy-for-ubuntu/env` and reference it as `${SS_PASSWORD}`.
- **Logs** record destination addresses and rule names, never passwords. The
  profile export can redact secrets to `***REDACTED***` for bug reports.
- Traffic goes through the server **you** chose and **you** pay for. The
  project runs no servers, no telemetry and no accounts.

## CLI

Useful on servers and in CI:

```bash
sudo pfu-cli connect          # enable interception
pfu-cli status                # daemon state
pfu-cli doctor                # check the environment
pfu-cli rules                 # routing rules
pfu-cli proxies               # list proxies
pfu-cli metrics               # live traffic

# dump config → edit → apply
pfu-cli config > my.yaml
$EDITOR my.yaml
sudo pfu-cli apply < my.yaml
```

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Toggle does nothing after `apt install` | Daemon not running: `sudo systemctl start proxy-for-ubuntud` |
| "nftables rejected the ruleset" | Missing privileges or conflicting rules: `sudo nft list ruleset` |
| QUIC/games bypass the proxy | Needs `intercept.udp: tproxy` and an outbound with `udp: true` |
| Internet gone after Apply | Daemon did not roll back: `sudo systemctl stop proxy-for-ubuntud && sudo nft delete table inet pfu; sudo ip rule del fwmark 0x1 lookup 100; sudo ip route flush table 100` |
| `Permission denied` на `/run/proxy-for-ubuntu/ctl.sock` | Пользователь не в группе `proxy-for-ubuntu`. При установке через `sudo apt` группа добавляется автоматически; если ставили из графического менеджера — `sudo usermod -aG proxy-for-ubuntu $USER` и повторный вход в систему |
| Окно приложения открывается пустым | WebKitGTK не рисует интерфейс на LXQt/Xfce с Openbox. `proxy-for-ubuntu` сам выставляет `WEBKIT_DISABLE_DMABUF_RENDERER=1`; если не помогло — `LIBGL_ALWAYS_SOFTWARE=1 proxy-for-ubuntu`. Диагностика: `proxy-for-ubuntu --diagnose` |
| `proxy-for-ubuntu --version` ничего не выводит | Устаревшая сборка: команда добавлена в 0.1.1. Переустановите пакет |
| `ssh` stopped working | SSH is excluded from interception by default (`exclude_ports: ["22"]`). Check you did not override it |
| Docker ignores the proxy | Container traffic goes through `FORWARD`, not `OUTPUT`. See [docs/TESTING.md](docs/TESTING.md) |
| Some rules never match | Geo sets not downloaded: Geo sets tab → Update |
| `systemd-resolved` complains about port 53 | DNS interception catches it too; an informational log line is expected |

Full checklist: [docs/TESTING.md](docs/TESTING.md).

## Building from source

```bash
sudo apt install build-essential pkg-config libwebkit2gtk-4.1-dev \
     libayatana-appindicator3-dev librsvg2-dev nftables
git clone https://github.com/DenisZakharov2/proxy-for-ubuntu
cd proxy-for-ubuntu
./scripts/build-deb.sh --output dist
sudo apt install ./dist/proxy-for-ubuntu_0.1.0_amd64.deb
```

## Documentation

| File | About |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | engine, interception and rollback internals |
| [docs/CONFIG.md](docs/CONFIG.md) | every config field and rule type |
| [docs/IPC.md](docs/IPC.md) | GUI ↔ daemon contract, error codes |
| [docs/PROTOCOLS.md](docs/PROTOCOLS.md) | per-protocol implementation notes and limits |
| [docs/TESTING.md](docs/TESTING.md) | manual pre-release checklist |
| [README (Russian)](README.md) | документация на русском |

## Contributing

Issues and pull requests are welcome. Most wanted:

- reports that `vless` and `vmess` work against a live server;
- additional geo sets;
- UI translations (currently ru and en).

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT © 2026 Denis Zakharov. See [LICENSE](LICENSE).
