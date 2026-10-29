# Configuration schema

Active config: `/etc/proxy-for-ubuntu/config.yaml`. Format — YAML, Clash-like in
spirit, with extensions (see below). Foreign Clash configs are **not** imported
as-is: the converter `pfu-cli convert clash.yaml` moves `proxies` → `outbounds`
and `proxy-groups` → `groups`.

Full example — [`/usr/share/proxy-for-ubuntu/profiles/example.yaml`](../packaging/profiles/example.yaml).

## Top level

```yaml
api: 1                  # IPC contract version
log:
  level: info           # trace|debug|info|warn|error
  journal: true         # write to journald
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
  enabled: false        # intercept local traffic via pfu0, see "Interception modes"
  device: pfu0
  mtu: 1500             # 576..9000; above 1500 breaks large datagrams
  address: 198.18.0.1/15  # RFC 2544 test range

intercept:
  tcp: redirect          # redirect | off (tproxy for TCP is not implemented)
  udp: tproxy            # tproxy | off
  exclude_uid: []        # uid whose traffic is not touched (e.g. the daemon itself = 0)
  exclude_ports: [22]    # SSH outbound, so as not to lose access to the machine
  bypass_private: true   # 10/8, 172.16/12, 192.168/16, 127/8 — direct
  loop_protect: true     # do not loop the daemon's own traffic back to the daemon

outbounds:
  - name: DIRECT
    type: direct
  - name: Work
    type: socks5
    server: 1.2.3.4
    port: 1080
    username: ""         # optional
    password: ""
    udp: true
    remote_dns: true     # true == socks5h: domain is not resolved locally

rules:
  - DOMAIN-SUFFIX,ads.example,REJECT
  - GEOSITE,category-ads-all,REJECT
  - GEOIP,cn,DIRECT
  - DOMAIN-SUFFIX,vk.com,Work
  - PROCESS,firefox,Work
  - DST-PORT,443,Work
  - MATCH,DIRECT

final: DIRECT
```

## Interception modes

| Mode | Captures | Requirements | When to enable |
|---|---|---|---|
| `redirect` (TCP) | all outgoing TCP | `nftables`, root | default, works without TUN |
| `tproxy` (UDP) | forwarded UDP (containers) | `nftables`, `IP_TRANSPARENT` | UDP from containers; does not capture local UDP |
| `tun.enabled` | local IPv4: TCP and UDP (DNS, QUIC) | `nftables`, `/dev/net/tun`, root | when local UDP and DNS must go through the proxy |
| `off` | nothing, system environment variables only | — | checking everything works after install |

TUN (`tun.enabled: true`) sends local traffic into the `pfu0` interface: the
kernel hands whole IP packets to the daemon, which parses them with its own
userspace stack and opens connections through the regular outbounds. This
captures what REDIRECT and TPROXY cannot: local UDP (DNS, QUIC, games). With
TUN enabled, TCP also goes through `pfu0` — REDIRECT is not used in this mode.

How it is wired: `mangle output` sets mark `0x2`, `ip rule fwmark 0x2` sends the
packet to table 101, which holds `default dev pfu0`. Forwarded UDP (containers)
still uses TPROXY (mark `0x1`, table 100).

First-version limits (0.3.0):

* IPv4 only; IPv6 still goes direct;
* fragmented packets are dropped: there is no reassembly;
* TCP: no window scaling (65,535 bytes), no SACK or timestamps, timer-based
  retransmission — slower than the kernel stack on lossy links;
* ICMP is not proxied;
* `dns.strategy: fake-ip` still does not work: the built-in resolver is not
  wired into interception, DNS travels through TUN as plain UDP.

## `outbounds`

Common fields for all types: `name` (unique), `type`, `udp` (whether UDP is allowed
through this outbound), `test_url`, `test_timeout_ms`.

### `direct`

Configures nothing.

### `http`

CONNECT proxy.

```yaml
- name: HTTP
  type: http
  server: proxy.local
  port: 8080
  username: user
  password: pass    # or password_file: /etc/proxy-for-ubuntu/secrets/http
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

The difference is only in `remote_dns`: `socks5` resolves the domain locally
(DNS leak), `socks5h` passes the domain to the proxy as-is.

### `shadowsocks`

```yaml
- name: SS
  type: shadowsocks
  server: 1.2.3.4
  port: 8388
  method: chacha20-ietf-poly1305   # or aes-256-gcm
  password: "base64-key-or-password"
  plugin: ""                       # not supported, kept for compatibility
  udp: true
```

Methods: `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-256-gcm`, `aes-128-cfb`,
`aes-256-cfb`, `chacha20`, `rc4-md5`. AEAD mode (default) is mandatory;
legacy ciphers without AEAD are marked as unsafe in the UI.

### `trojan`

```yaml
- name: Trojan
  type: trojan
  server: trojan.example
  port: 443
  password: "password"
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
  flow: ""                 # xtls-rprx-vision requires Reality, not supported
  network: tcp             # tcp | ws
  tls: true
  sni: v.example
  path: /                  # for ws
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
  alter_id: 0              # AEAD mode only with alterId = 0
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
  password: ""             # or
  key_file: "~/.ssh/id_ed25519"
  passphrase: ""
  host_key_algorithms: [ssh-ed25519, rsa-sha2-512]
  keepalive: 30
```

Implemented as a local SOCKS5 `DIRECT` via `ssh -D`: the SSH protocol itself is
delegated to the system OpenSSH, not written from scratch. Direction, SNI, rule
routing, and traffic accounting work like all other outbounds.

## `rules`

The list executes top to bottom, first match wins. Line format —
`TYPE,PARAMS,ACTION[,EXTRA]`.

### Types

| Type | Parameters | Example |
|---|---|---|
| `DOMAIN` | full domain | `DOMAIN,example.com,REJECT` |
| `DOMAIN-SUFFIX` | suffix with dot | `DOMAIN-SUFFIX,vk.com,Work` |
| `DOMAIN-KEYWORD` | substring | `DOMAIN-KEYWORD,google,Work` |
| `DOMAIN-REGEX` | regular expression | `DOMAIN-REGEX,^ads[0-9]*,REJECT` |
| `IP-CIDR` | `address/mask` | `IP-CIDR,10.0.0.0/8,DIRECT` |
| `GEOIP` | set tag | `GEOIP,cn,DIRECT` |
| `GEOSITE` | set tag | `GEOSITE,category-ads-all,REJECT` |
| `DST-PORT` | port or `1000-2000` | `DST-PORT,443,Work` |
| `SRC-PORT` | port | `SRC-PORT,5000-5010,DIRECT` |
| `PROCESS-NAME` | process name | `PROCESS-NAME,firefox,Work` |
| `PROCESS-PATH` | full path | `PROCESS-PATH,/usr/bin/ssh,DIRECT` |
| `UID` | numeric uid | `UID,1000,DIRECT` |
| `NETWORK` | `tcp` / `udp` | `NETWORK,udp,DIRECT` |
| `MATCH` | — | `MATCH,DIRECT` |

### Actions

- an outbound name from `outbounds` — traffic goes through it
- `DIRECT` — direct (built-in outbound, always created)
- `REJECT` — connection closed immediately, RST/ICMP unreachable
- `REJECT-DROP` — packet silently dropped
- `HIJACK-DNS` — force our DNS resolver

### Groups

```yaml
groups:
  - name: Rules RF
    type: select          # select | url-test | fallback | load-balance
    outbounds: [Work, DIRECT]
    interval_sec: 300     # for url-test and fallback
    url: https://www.gstatic.com/generate_204
```

`select` — manual choice, `url-test` — automatic latency check with switching to
the best, `fallback` — first working by list, `load-balance` — round-robin over
connections.

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

`sha256` is optional, but if set, the file is accepted only on hash match.
Empty `tag` (no name) means "all sets of this kind".

## `groups` and "what to do with the bank"

The active profile is stored as a symlink:

```
/etc/proxy-for-ubuntu/config.yaml -> /etc/proxy-for-ubuntu/profiles/Work.yaml
```

`profile.activate` switches the symlink and calls `config.apply`. Rollback —
`config.rollback` restores the previous snapshot in full.

## Environment variables

`${VAR}` substitution works in string fields, including passwords:

```yaml
password: "${SS_PASSWORD}"
```

Values are taken from `/etc/proxy-for-ubuntu/env` (mode `0600`, owner root) and
from the daemon's environment. This allows not storing secrets in YAML.

## Traffic limits

The `limits` section restricts proxied traffic: rate (token bucket) and the
number of simultaneous connections.

```yaml
limits:
  # Long-term rate of all proxied traffic, bytes/sec.
  # 0 or missing — no limit.
  rate_limit: 1048576
  # Maximum number of concurrently open connections.
  max_connections: 100
  # Per-outbound override — key is the outbound name.
  outbound:
    Work:
      rate_limit: 524288
      max_connections: 10
```

The token bucket is a long-term rate plus one full-speed second burst, so
short requests aren't dribbled. Each outbound gets its own bucket: the global
`rate_limit` without `outbound.<name>` applies to every proxy separately,
it's not split between them.

When `max_connections` is exceeded, the connection is not established and
`E_LIMIT` is returned; the slot is released when the stream is closed. Limits
are applied without restarting the daemon on `systemctl reload` or
`config.apply`.
