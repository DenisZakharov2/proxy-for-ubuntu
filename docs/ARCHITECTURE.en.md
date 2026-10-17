# Architecture of proxy-for-ubuntu

This document describes the internal structure of the project. End-user documentation is [README.md](../README.md).

## 1. Overall scheme

```
┌──────────────────────────────────────────────────────────────────────┐
│                          Ubuntu Desktop                              │
│                                                                      │
│   ┌──────────────────────────┐        Unix socket                     │
│   │  proxy-for-ubuntu (GUI)  │◄─────── /run/proxy-for-ubuntu/ctl.sock │
│   │  Tauri + WebView (user)  │                                        │
│   └──────────────────────────┘                                        │
└───────────────────────────────────┬──────────────────────────────────┘
                                    │  JSON-RPC (request-response + events)
┌───────────────────────────────────▼──────────────────────────────────┐
│                   proxy-for-ubuntud (daemon, root)                   │
│                                                                      │
│  ┌────────────┐  ┌──────────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ Supervisor │  │  Rule engine │  │   Outbounds  │  │  DNS core  │ │
│  │ apply/     │  │  (Clash-like)│  │  7 protocols │  │  resolver  │ │
│  │ rollback   │  │  geoip/site  │  │              │  │  + cache   │ │
│  └────────────┘  └──────────────┘  └──────────────┘  └────────────┘ │
│         │               │                  │                │        │
│         └───────────────┴──────────────────┴────────────────┘        │
│                              │                                       │
│                    ┌─────────▼──────────┐                            │
│                    │  TUN + nftables    │                            │
│                    │  policy-based      │                            │
│                    │  routing           │                            │
│                    └────────────────────┘                            │
└──────────────────────────────────────────────────────────────────────┘
```

GUI runs as the user, the daemon — as root. Between them a Unix socket at `/run/proxy-for-ubuntu/ctl.sock`, mode `0660`, group `proxy-for-ubuntu`. No `sudo` from the GUI: the only entry point to privileged code is the system daemon, started by systemd and listening on the socket.

## 2. Two-process split and why

| | GUI | Daemon |
|---|---|---|
| Started by | `.desktop` as the user | `systemd`, `Type=simple`, as root |
| Rights | regular | root |
| Files | `~/.config/proxy-for-ubuntu/` | `/etc/proxy-for-ubuntu/`, `/var/lib/proxy-for-ubuntu/` |
| What it does | draws the UI, sends commands | holds TUN, nftables, sockets, rules |

Reasons for the split:

1. **TUN and nftables require `CAP_NET_ADMIN`.** Granting it to the GUI process is bad practice: a crashed or compromised WebView process would get rights to change the network.
2. **System changes survive GUI restarts.** Close the window — traffic keeps going through the proxy, as it should.
3. **systemd provides autostart, recovery, and control.** `Restart=always`, `WatchdogSec`, `ExecStartPre` for environment checks.

## 3. Configuration

`/etc/proxy-for-ubuntu/config.yaml` — Clash-like YAML. Full schema — [CONFIG.en.md](CONFIG.en.md). User profiles live in `~/.config/proxy-for-ubuntu/profiles/<name>.yaml`, the system (active) one — a symlink or copy in `/etc`.

Configuration reload **without restarting the process**: `SIGHUP` → the daemon re-reads the file, builds a new `Router`, validates it, and only then atomically replaces the old `Arc<Router>`. Validator fails — the old working config stays, the error goes to the log. That is "Apply without restarting the daemon".

## 4. Rule engine

Classic Clash-like pipeline, first match wins:

```
Packet/flow
   │
   ├─► ProcessRule?    match by process name (cgroup / binary path)
   │
   ├─► PortRule?       match by destination port
   │
   ├─► IpCidrRule?     exact address match
   │
   ├─► DomainRule?     extracted from TLS SNI / HTTP Host / DNS query
   │                   ├─ domain          exact
   │                   ├─ domain-suffix   .example.com
   │                   ├─ domain-keyword  substring
   │                   ├─ domain-regex    PCRE-like
   │                   └─ geosite:<tag>   from local sets
   │
   ├─► GeoIpRule?      IP falls into a CIDR set
   │                   └─ geoip:<tag>
   │
   └─► Final: DIRECT   (or whatever `final:` specifies)
```

Implementation: `src-tauri/src/engine/rules.rs`. Rules compile once into `Vec<CompiledRule>` — per-packet this is a linear pass with precomputed hash sets for domains and bit masks for CIDR (search tree — when there are more than 256 rules of one type, otherwise linear scan is faster).

### Geo data

Own storage, not foreign binary bases:

```
/var/lib/proxy-for-ubuntu/geo/
├── geoip/
│   ├── cn.txt        # CIDR, one per line
│   ├── ru.txt
│   └── ...
├── geosite/
│   ├── category-ads-all.txt
│   └── ...
└── manifest.json     # url + sha256 + last update date
```

Format — plain text, `#` for comments. Files can be read by eye, edited by hand, and diffed. Update: `pfu-cli geo update` (or GUI button), download from the URL in config, verify sha256, atomic replacement.

## 5. Outbound protocols

All clients are written from scratch in Rust, without sing-box/Xray/Clash. Common interface:

```rust
#[async_trait]
trait Outbound {
    fn name(&self) -> &str;
    async fn connect(&self, req: &Request) -> Result<Box<dyn AsyncReadWrite>>;
    async fn udp(&self) -> Result<Box<dyn UdpSession>>;   // for UDP/QUIC
    fn test(&self) -> Probe;
}
```

| Protocol | Status | Implementation | Notes |
|---|---|---|---|
| `direct` | working | `outbound/direct.rs` | — |
| `http` (CONNECT) | working | `outbound/http.rs` | Basic auth, keep-alive pool |
| `socks5` / `socks5h` | working | `outbound/socks5.rs` | UDP ASSOCIATE, remote DNS for `socks5h` |
| `ssh` | working | `outbound/ssh.rs` | `russh`, dynamic forwarding |
| `shadowsocks` | working | `outbound/shadowsocks.rs` | AEAD, ChaCha20-Poly1305 and AES-256-GCM, HKDF-SHA1, TCP+UDP |
| `trojan` | working | `outbound/trojan.rs` | rustls, SHA224 of password, SOCKS5-like request |
| `vless` | **not checked against a live server** | `outbound/vless.rs` | UUID, X25519/Reality not — only TLS and WebSocket |
| `vmess` | **not checked against a live server** | `outbound/vmess.rs` | AEAD mode (VMessAEAD) |

"Not checked against a live server" is an honest note: the code compiles and passes tests against a synthetic server, but it has not been tested against a real xray server. Formally such protocols are marked ⚠ in the UI.

### Cryptography

Vetted crates are used, not hand-written code: `chacha20poly1305`, `aes-gcm`, `aes`, `cbc`, `hmac`, `sha1`, `sha2`, `hkdf`, `md-5`, `x25519-dalek`, `ed25519-dalek`, `rustls`. Own implementation only covers protocol format parsing (AEAD headers, base64, byte order) — that is safe and covered by tests.

## 6. System layer

### 6.1 TUN

`/dev/net/tun`, ioctl `TUNSETIFF`, name `pfu0`, address `172.19.0.1/30`, MTU 9000. MTU 9000 is mandatory: proxying TCP adds headers, and with 1500 large transfers stall. Additionally the kernel is enabled with `tcp_mtu_probing=1` to robustly survive packet loss on large sizes.

### 6.2 Routing (nftables)

Routes are not touched. **Policy routing by mark** is used:

```
table inet pfu {
    chain prerouting { type filter hook prerouting priority mangle; meta mark set 0x1 }
    chain output      { type filter hook output  priority mangle; meta mark set 0x1 }
}
ip rule add fwmark 0x1 lookup 100 priority 100
ip route add default dev pfu0 table 100
```

Plus an `nft` set for exceptions to avoid looping the daemon's own traffic:

```
oifname "pfu0" accept          # already in TUN
meta mark 0x1 tcp dport 22 accept   # SSH, to not lose access
```

Rules are generated in `engine/nft.rs` and applied with a single `nft -f` — atomic and fast, not one-by-one.

### 6.3 DNS

All DNS (UDP/53 and TCP/53) is intercepted and handled by the built-in resolver (`engine/dns.rs`): cache with TTL, parallel A/AAAA, fallback to DoH/DoT on failure. For proxied domains, resolution happens through the proxy's own DNS (for `socks5h`/`vless`/`vmess` — implicit remote DNS), for direct ones — through system resolvers. This prevents DNS leaks, where "the proxy is on but the traffic is still exposed".

### 6.4 Apply and rollback

`Supervisor::apply()`:

1. **Snapshot.** Current `ip rule`, `ip route table 100`, `inet pfu` table, active config symlink — everything written to `/var/lib/proxy-for-ubuntu/rollback/`.
2. **Dry-run validation.** YAML is parsed, rules compiled, each outbound checked for a successful TCP connection to the target. Nothing applied.
3. **Commit.** New config written, nft rules generated, `nft -f`, TUN brought up, daemon re-reads the config.
4. **Health check.** DNS responds and the test URL opens.
5. **Any error → `rollback()`.** Snapshot restored, symlink reverted, reason logged. A config that fails the health check does not remain active.

The GUI "Apply" button invokes exactly this path. The "Rollback" button in the error log — a manual `rollback()` call from the snapshot of the last failed attempt.

## 7. GUI

Tauri 2 + React + TypeScript. Dark and light themes, no heavy UI kits (custom CSS variables, Inter font). Screens:

- **Overview** — status, connect toggle, circular traffic chart
- **Proxy** — outbound list, add / edit / check
- **Rules** — rule editor with syntax highlighting, drag-and-drop sorting
- **Profiles** — YAML import/export, URL subscriptions
- **Geo** — sets, updates, manual editing
- **Log** — system log with filters, export

State updates — via Tauri events (`state://changed`), the GUI does not poll the daemon in a loop.

## 8. Packaging

Built with `dpkg-deb` directly (`scripts/build-deb.sh`), without `debuild` — to avoid pulling build dependencies onto the build machine. Package contents:

```
/usr/bin/proxy-for-ubuntu          GUI
/usr/bin/proxy-for-ubuntud         daemon
/usr/bin/pfu-cli                   CLI for headless configuration and CI
/usr/lib/proxy-for-ubuntu/         built-in default geo sets
/etc/proxy-for-ubuntu/             config, state
/var/lib/proxy-for-ubuntu/         rollback snapshots, logs
/usr/share/applications/           .desktop
/usr/share/icons/                  icons
/usr/lib/systemd/system/           units
/usr/share/polkit-1/actions/       .policy for GUI (status read, Apply request)
```

`postinst` creates the `proxy-for-ubuntu` user, sets up the group, initializes the config from the default, runs `systemctl daemon-reload`, and does not start the daemon automatically — the user switches it on in the GUI. `prerm` stops the daemon and **removes nftables rules** (otherwise the system is left without network after package removal).

## 9. Testing

- `cargo test` — unit tests for protocols (spec vectors), rule engine, config parser
- `tests/integration.rs` — brings up a local SOCKS5/HTTP/SSH server, runs real TCP exchanges through it
- Manual checklist in [docs/TESTING.md](TESTING.md) — VM testing, DNS leak check, autostart, recovery after `systemctl restart network`
