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
│                    │  nftables          │                            │
│                    │  REDIRECT/TPROXY   │                            │
│                    │  → listeners       │                            │
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
| What it does | draws the UI, sends commands | holds nftables, listeners, sockets, rules |

Reasons for the split:

1. **nftables, `ip rule` and transparent sockets require `CAP_NET_ADMIN`.** Granting it to the GUI process is bad practice: a crashed or compromised WebView process would get rights to change the network.
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

### 6.1 Traffic interception

No TUN: the kernel hands connections to the daemon's sockets itself.

- **TCP.** The `nat output` chain (hook `output`, priority `dstnat`) does
  `redirect to :15000` for local TCP. The daemon accepts on `0.0.0.0:15000`
  and reads the real destination from `SO_ORIGINAL_DST` (`SOL_IP` option 80)
  of the accepted socket.
- **Forwarded UDP.** In `prerouting` (priority `mangle`) UDP is marked with
  `meta mark set 0x1` and sent to `tproxy to :15001`. The mark makes
  `ip rule` route the packet through table 100, which holds
  `local default dev lo`; the real destination arrives in an
  `IP_ORIGDSTADDR` control message. Each flow gets a socket bound to that
  destination (`IP_TRANSPARENT` + `SO_REUSEPORT`), so the reply leaves from
  the correct port instead of 15001 — otherwise the client drops it.
- **Container TCP** (`intercept.docker: true`) is intercepted in
  `nat prerouting` with the same `redirect to :15000`.

What is not intercepted, and why:

- **local UDP** (DNS, QUIC, games). `redirect` for a locally generated
  datagram rewrites the destination address, and `IP_ORIGDSTADDR` then
  returns `127.0.0.1:15001` instead of the real destination — there is no
  way to recover it. Such traffic goes direct, past the proxy;
- **IPv6**: the daemon's listeners are IPv4-only, so `prerouting`,
  `nat output` and `nat prerouting` all contain `meta nfproto ipv6 return`
  and v6 traffic goes direct. Full support (v6 sets, `sockaddr_in6`,
  `IP6T_SO_ORIGINAL_DST`, `IPV6_TRANSPARENT`) is a separate task;
- traffic of `uid 0` (the daemon itself), `lo`, local addresses
  (`fib daddr type local`), multicast `224.0.0.0/4`, broadcast, private
  networks with `bypass_private: true`, and `exclude_ports`.

TUN (`config.tun`, interface `pfu0`) is **not implemented**: the field is
left over from the original plan, and the `/dev/net/tun` check in `--check`
is now informational only. TUN is what closing local UDP would need; until
then the limitation above stands.

Listeners live exactly as long as interception is on: `Capture` holds a
`CancellationToken`, `disconnect` cancels the loops and waits for the tasks
to close their sockets. The unit sets `LimitNOFILE=65536`; on
`EMFILE`/`ENFILE` the accept loop sleeps one second and logs one warning
per second instead of one per iteration.

### 6.2 Routing (nftables)

The system's routes are not touched. The actual ruleset (`nft list table
inet pfu`) after `connect`:

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

    chain nat_prerouting {          # only with intercept.docker: true
        type nat hook prerouting priority -100; policy accept;
        ...
        meta l4proto tcp redirect to :15000
    }
}
ip rule add fwmark 0x1 lookup 100 priority 100
ip route replace local default dev lo table 100
```

Rules are generated in `engine/nft.rs` and applied with a single `nft -f`
— atomic and fast, not one by one. The `ip rule` is added only if missing;
`teardown` removes all of its rules, the route and the table, checks the
result and returns an error listing failures instead of swallowing them.

Without its exceptions the `prerouting` chain captured traffic addressed to
the machine itself: mDNS went into the proxy socket tens of thousands of
datagrams at a time. Hence `fib daddr type local`, multicast and broadcast
there.

### 6.3 DNS

With TUN (`tun.enabled: true`) DNS is intercepted: a datagram to any external
`:53` lands in `pfu0`, is parsed by the userspace stack and leaves as an
ordinary UDP flow through the outbound chosen by the rules. The answer is
returned to the application unchanged — this is `redir-host`, and the
application sees the real address.

The main side effect: A/AAAA records are taken from the answer, and
`engine/dns.rs` remembers "IP → domain" for `cache_ttl` seconds. Before a
decision is made, `Engine::enrich_domain` puts the name into `Flow`, so
`DOMAIN`, `DOMAIN-SUFFIX` and `GEOSITE` rules apply to a connection the
application opens by address (TUN TCP/UDP and redirected TCP).

`fake-ip` is not implemented and is rejected by validation: a setting that
silently does nothing is worse than a refusal. `HIJACK-DNS` in the rules means
"answer it ourselves": the resolver resolves the name locally (system
resolver, then DoH with pinned addresses) and builds an A/AAAA answer; the
query never leaves the machine.

Hostnames are also preserved where DNS is not involved: `socks5h`, `vless`,
`vmess` and `trojan` pass the hostname to the proxy, and the proxy resolves it.

### 6.4 Apply and rollback

`Supervisor::apply()`:

1. **Snapshot.** Current `ip rule`, `ip route table 100`, `inet pfu` table, active config symlink — everything written to `/var/lib/proxy-for-ubuntu/rollback/`.
2. **Dry-run validation.** YAML is parsed, rules compiled, each outbound checked for a successful TCP connection to the target. Nothing applied.
3. **Commit.** New config written, nft rules generated, `nft -f`, interception listeners started, daemon re-reads the config.
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
