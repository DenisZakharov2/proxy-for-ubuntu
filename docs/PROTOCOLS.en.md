# Protocols

Implementation of each outbound protocol: what exactly is done, where it is
verified, and what is not supported. The common interface is the `Outbound`
trait (`engine::outbound::Outbound`, `app/src-tauri/src/engine/outbound/mod.rs`).

## Summary

| Protocol | Status | UDP | Check against a live server |
|---|---|:---:|---|
| `direct` | working | ✅ | not required |
| `http` | working | ❌ | synthetic server |
| `socks5` / `socks5h` | working | ✅ | synthetic server |
| `shadowsocks` | working | ✅ | synthetic server |
| `trojan` | working | ✅ | no |
| `vless` | ⚠ not verified | ✅ | **no** |
| `vmess` | ⚠ not verified | ✅ | **no** |
| `ssh` | working | ❌ | local OpenSSH |

Status "synthetic server" means: a real server of the corresponding protocol is
started on loopback in tests, and a real byte exchange is run through it. This
catches format errors, but not compatibility errors with a specific
implementation on the other side.

---

## direct

`engine/outbound/direct.rs`. Direct connection to the actual recipient.
**Limitations:** only addresses are allowed; the domain is resolved locally
through the system resolver (`getaddrinfo`), cycling all A/AAAA until the first
successful connection. This is a conscious compromise: if the first address is
unavailable (e.g. AAAA without a route), the connection does not immediately
fall back.

---

## http

`engine/outbound/http.rs`. CONNECT method per RFC 7231 §4.3.6.

**Supported:** CONNECT, Basic auth, `password_file` instead of a password in
the config, response code parsing into human-readable messages
(407 → "login and password required", 502/503/504 → "proxy could not reach the
target").

**Not supported:** plain GET/POST through the proxy, UDP proxying. Not needed
for transparent interception: the application has already formed the request to
the direct target, and the proxy is only needed for the tunnel.

**Security.** The domain in the `CONNECT` header is checked for spaces and
non-printable characters. Without this check, a name like
`evil.com HTTP/1.1\r\nX: y` would allow appending arbitrary headers to the
request. There is a test `rejects_header_injection_in_hostname`.

---

## socks5 / socks5h

`engine/outbound/socks5.rs`. RFC 1928 plus UDP ASSOCIATE (RFC 1928 §7).

The difference is only in one field: `remote_dns: true` (i.e. type `socks5h`)
passes the domain to the proxy as a domain; `false` resolves it locally. The
first does not leak DNS; the second is faster, but the list of visited domains
is visible to your ISP. **Default — the first.**

Authentication: none, and username/password. A method the proxy does not
support gives a clear error with a code, not "connection failed".

**UDP ASSOCIATE.** The proxy often returns `0.0.0.0` instead of its own
address — then the address of the SOCKS server itself is used. The TCP
association connection is kept alive the whole time: many servers close the UDP
channel as soon as the associated socket drops.

---

## shadowsocks

`engine/outbound/shadowsocks.rs`. AEAD mode per SIP004.

**Ciphers:** `chacha20-ietf-poly1305`, `aes-128-gcm`, `aes-256-gcm`. Legacy
ciphers (`aes-*-cfb`, `chacha20`, `rc4-md5`) are accepted in the config, but
marked as unsafe in the UI: without AEAD, a man-in-the-middle can modify data
without being detected.

**Frame format (a common implementation mistake):**

```
[plaintext length: 2 bytes][ciphertext]
```

where **the payload length is inside the ciphertext** — it is the first two
bytes of the plaintext. The wire frame header is exactly 2 bytes, and the AEAD
tag arrives at the end of the block. Confusing these two fields is the most
common cause of "everything seems configured, but nothing works".

**Keys.** The master key is used as-is if it is a base64 string of the correct
length; otherwise the password is stretched with EVP_BytesToKey using MD5 —
just like the original shadowsocks. The per-connection key is derived via
HKDF-SHA1 from the master key and a per-connection salt, so one key can be
safely used across different connections.

**Nonce** — 12 bytes, little-endian counter, shared across all chunks of a
direction. The test `nonce_increments_little_endian_with_carry` checks the
carry.

---

## trojan

`engine/outbound/trojan.rs`. Trojango/go-trojan scheme.

**Format:** `CMD(1), ADDR, CRLF, payload, SHA224(password)_hex, CRLF`.

Unlike SOCKS5, the password is checked **on every packet**, not once at
handshake. This protects against data substitution inside TLS: the client sees
that the response signature does not match and drops the connection.

**TLS:** via `rustls` with system roots from `webpki-roots` (does not depend on
the presence of the `ca-certificates` package in the system). ALPN: `h2`,
`http/1.1`. `skip_cert_verify` remains in the config, but a warning is written
to the log on every connection — the user must see that verification is
disabled.

**UDP.** Implemented in a simplified model (trojango/go-trojan style): each
datagram is a standalone Trojan session `[ADDR][DATA][SHA224(pass)][CRLF]`,
signature is verified on receive. No persistent TCP/TLS wing is kept. If the
target server requires a prior TCP handshake UDP ASSOCIATE (like SOCKS5),
datagrams will be dropped — then a prologue should be added to `open_udp()`
(see the `shortcut` comment in the code).

---

## vless

`engine/outbound/vless.rs`. ⚠ **Not verified against a live Xray server.**

**Request format:** `ver(1)=0, uuid(16), addonsLen(1)=0, cmd(1), port(2),
atyp(1), addr, payload`.

**Important:** address types here are not like in SOCKS5 — `0x01` IPv4, `0x02`
domain with a length prefix, `0x03` IPv6. Confusing them is a typical mistake
that silently breaks the connection. There is a test `address_types_differ_from_socks5`.

**Transports:** `tcp` (raw) and `ws` (WebSocket over HTTP Upgrade). For `ws`,
TLS is enabled automatically: a server without TLS for WebSocket almost always
means "TLS was forgotten".

**WebSocket.** Own minimal wrapper: outgoing frame masking, incoming frame
unmasking, fragment reassembly, ping/pong/close handling. Frames larger than 1
MiB are rejected.

**Not supported:**
- `flow` (XTLS / Reality) — a config with non-empty `flow` is rejected at
  validation time, not silently ignored. Reality requires not TLS, but a
  special cryptographic handshake with a server key;
- gRPC transport;
- Reality / XTLS.

**Why status ⚠.** The code is written against the specification and covered by
tests on our own servers, but it has not connected to a real Xray. If you test
it — send the log, that will remove the question for everyone else.

---

## vmess

`engine/outbound/vmess.rs`. ⚠ **Not verified against a live Xray server.**

AEAD mode only (Xray-core 1.8+), only `alterId: 0`. The old MD5 mode is
incompatible with AEAD, and a config with non-zero `alterId` is rejected at
validation time.

**Request format** (all integers big-endian):

```
authID   = AES-128-ECB(uuid, PKCS7(timestamp[8]), zero-iv)          → 16 bytes
lenBuf   = AES-128-ECB(authID, PKCS7([len(nonce)+len(payload)+4]), zero-iv)[:2]
nonce    = random(12)
lenPlain = [len(payload)][2]
crc32    = CRC32(nonce ‖ lenPlain ‖ payload)
header   = authID ‖ lenBuf ‖ nonce ‖ AEAD(authID, nonce, lenPlain ‖ payload ‖ crc32, aad=lenBuf)
```

`payload` is a VMess block: `cmd(1), port(2), atyp(1), addr, data`. Note:
`lenPlain` is the length of the **entire block**, not just the data.

**Ciphers:** `aes-128-gcm` (default) and `chacha20-poly1305`. The key is always
16 bytes — this is `authID`; for ChaCha20-Poly1305, which needs a 32-byte key,
`authID` is padded with zeros to 32. That is exactly what Xray does
(`generateChacha20Poly1305Key`).

**Response header** is parsed "softly": historically Xray returned garbage in
these 18 bytes, so the length is taken from the last two bytes of the block and
no failure occurs on CRC mismatch.

**Not supported:** `alterId != 0`, old (non-AEAD) mode, gRPC, `security: rc4`
and other legacy ciphers.

---

## ssh

`engine/outbound/ssh.rs`. The only departure from the "from scratch" rule.

Implementing the SSH protocol itself — key exchange, KEX, cipher suite — is
years of work. A hand-written implementation in a system router would be a
source of vulnerabilities, not an advantage. Therefore a local SOCKS5 is spun
up via the system OpenSSH:

```
ssh -N -D 127.0.0.1:<port> -o ServerAliveInterval=30 user@host
```

Our engine (rule-based routing, traffic accounting, separate up/down, reaction
to server drop) works on top of it as usual — for the user there is no
difference.

**Requires** the `openssh-client` package (it is in the package dependencies).

**Limitations:** only TCP. Password login is possible only with `sshpass`,
which is not a dependency; the practical path is a key (`key_file`). An
unknown host key is accepted in `accept-new` mode: an interactive password
prompt in a background daemon would cause a hang.

---

## Common to all

**Timeouts.** Each connection to a proxy is limited to 10 seconds, each check —
to 8. Without this, Apply would hang on a dead server instead of rolling back.

**Secrets in logs.** `outbound::describe()` prints the address, port, and
protocol, but never the password, key, or UUID.

**Errors.** Each carries the protocol name (`Error::protocol`), user text, and,
where appropriate, a hint in `hint()`. Internal details (e.g. key path) do not
get into the message.
