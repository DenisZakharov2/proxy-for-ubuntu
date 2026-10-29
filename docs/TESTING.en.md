# Manual pre-release checklist

Automatic tests cover the engine, rules, and protocol formats. Everything
related to the Linux kernel, `nftables`, and real networking is checked only
manually — and necessarily **in a virtual machine**, so as not to lose the
working internet connection on the main machine.

## Preparation

```bash
# VM snapshot before starting — your insurance
sudo systemctl stop proxy-for-ubuntud
sudo nft delete table inet pfu 2>/dev/null
sudo ip rule del fwmark 0x1 lookup 100 2>/dev/null
sudo ip route flush table 100 2>/dev/null
```

Take a snapshot **before** each step involving "dangerous" changes.

## 1. Installation

```bash
sudo apt install ./dist/proxy-for-ubuntu_0.1.0_amd64.deb

# The daemon is enabled for autostart, but interception is not turned on
systemctl is-enabled proxy-for-ubuntud
sudo systemctl start proxy-for-ubuntud    # start the daemon (interception still off)
sudo pfu-cli doctor                       # nft, TUN, rights, ports — all ok

# Interception is NOT yet on: this is correct behavior right after installation
nft list table inet pfu 2>&1 | head -2   # expect "No such file"
```

- [ ] The package installs without manual dependency fixes
- [ ] `pfu-cli doctor` shows no critical problems
- [ ] No nftables rules after installation
- [ ] `ssh` works (it must not be broken by installing the package)

## 2. First GUI launch

- [ ] `proxy-for-ubuntu` opens, dark theme, all seven screens in the menu
- [ ] If the daemon is not running — a clear message with the command
  `sudo systemctl start proxy-for-ubuntud`, not empty screens
- [ ] Language switch ru ⇄ EN translates the entire interface
- [ ] Theme switch works, readability is not degraded

## 3. Checking outbounds

For each protocol you intend to declare as working:

- [ ] The "Check" button gives a latency in ms, not an error
- [ ] After turning off the proxy server, "Check" shows an error, not a hang
      (check that it returns within 8 seconds)
- [ ] For `socks5` (not `socks5h`) the GUI shows a yellow DNS leak warning
- [ ] For `vless` and `vmess` the ⚠ marker is shown

## 4. Interception and routing

```bash
# Turn interception on from the GUI, then:
nft list table inet pfu | head -20
ip rule show | grep fwmark
ip route show table 100
```

- [ ] After turning on, the `inet pfu` table and `fwmark 0x1` rule appear
- [ ] `curl https://ifconfig.me` shows the proxy server address
- [ ] The rule `DOMAIN-SUFFIX,<your-domain>,DIRECT` really passes traffic
  directly
- [ ] The rule `REJECT` really drops the connection
- [ ] Rule order works: swapping two rules changes the result

### Checking that interception works

```bash
# Daemon listeners and rules
ss -ltn | grep 15000          # TCP REDIRECT
ss -lun | grep 15001          # UDP TPROXY (forwarded traffic only)
nft list table inet pfu | head -30
pfu-cli metrics               # connection and byte counters
```

- [ ] `apt update` goes through the proxy (not just the browser)
- [ ] `git clone` from an external host goes through the proxy
- [ ] `curl https://example.com` → 200, and `pfu-cli metrics` shows growing
      `connections` and bytes once connections close
- [ ] DNS to external servers goes through the daemon with `tun.enabled: true`:
      `dig @8.8.8.8 +short example.com` answers and `pfu-cli metrics` grows;
      queries to 127.0.0.53 (systemd-resolved) still bypass it — see §5

## 5. DNS

With `tun.enabled: true` and `dns.strategy: redir-host`, queries to external
DNS servers are intercepted: the datagram enters `pfu0`, leaves through the
outbound chosen by the rules, the answer is returned to the application, and
the "IP → domain" pair is remembered for later connections to that address
(`docs/ARCHITECTURE.md` §6.3).

What it does not do:

- **`127.0.0.53` (systemd-resolved) is not intercepted** — it is loopback and
  is excluded from every chain. System applications that use the stub resolver
  resolve names as before, and resolved asks its upstream (usually a private
  router address) directly.
- DNS over TCP is proxied but not recorded in the "IP → domain" map.

- [ ] After `connect` DNS still works: `dig +short example.com`
- [ ] `dig @8.8.8.8 +short example.com` returns the real address, not
      `198.18.x.x`
- [ ] `DOMAIN-SUFFIX,example.com,REJECT` with TUN enabled breaks
      `curl https://example.com` after the DNS query, while
      `curl https://1.1.1.1` still works
- [ ] `HIJACK-DNS` on a `DST-PORT,53` rule answers locally: the same `dig`
      gets an answer and byte counters grow without any outbound
- [ ] The limits are described in README and CONFIG, not hidden

## 6. UDP and QUIC

Local UDP is not intercepted. Only forwarding is checked — containers, TCP
with `intercept.docker: true`, UDP with `intercept.udp: tproxy`.

- [ ] `docker run --rm curlimages/curl -s https://ifconfig.me` shows the
      proxy server address (container TCP is intercepted)
- [ ] UDP from a container reaches the destination, and replies come from the
      real port, not 15001 (echo server on another host)
- [ ] Local QUIC (`curl --http3 https://cloudflare.com`) goes direct —
      expected until TUN exists
- [ ] With a proxy that does not support UDP, the engine does not silently
      drop packets, but writes a clear message to the log

## 7. Apply and rollback — the most important part

| Scenario | Expectation |
|---|---|
| Invalid port in config | Error at `validate` stage, system untouched |
| Non-existent proxy server | Error at `probe` stage, system untouched |
| Wrong password | `probe` error with text from the protocol, rollback |
| Rule refers to a non-existent outbound | Error at `validate` |
| YAML syntax error | Clear error with line number |
| Port 15000 occupied | Diagnostics shows the occupied port, Apply does not proceed |
| No `nftables` | `doctor` shows what to do |

- [ ] In all cases the system remains in a working state
- [ ] The notification says the rollback was performed
- [ ] `sudo pfu-cli rules` shows the **old** configuration
- [ ] `nft list table inet pfu` matches the old state

Manual rollback check on health-check failure:

```bash
# Supply a guaranteed broken route and apply
sudo pfu-cli apply <<'YAML'
outbounds:
  - {name: DIRECT, type: direct}
  - {name: Broken, type: socks5h, server: 127.0.0.1, port: 1}
rules: [MATCH,Broken]
YAML
```

- [ ] The apply fails
- [ ] Internet works
- [ ] `nft list table inet pfu` does not show new rules

## 8. Resilience

- [ ] `sudo systemctl restart proxy-for-ubuntud` — traffic recovers
- [ ] `sudo systemctl restart systemd-networkd` — rules reinstall
- [ ] `sudo systemctl restart NetworkManager` — same
- [ ] Physical network disconnect/reconnect — traffic resumes
- [ ] `sudo reboot` — after daemon autostart, interception is in the required
  state (if it was on)
- [ ] Daemon killed with `kill -9` — after `Restart=always` it comes up on its
  own, rules are not left in a "half-broken" state

## 9. Removal

```bash
sudo apt remove proxy-for-ubuntu
```

- [ ] `nft list table inet pfu` — the table is gone
- [ ] `ip rule show | grep fwmark` — the rule is gone
- [ ] `ip route show table 100` — empty
- [ ] **Internet works** (the key item: if the network does not come back after
  package removal, `prerm` missed something)
- [ ] `sudo apt purge proxy-for-ubuntu` — config and data removed

## 10. Security

- [ ] The password in the config is replaced with `${VARIABLE}` in
  `/etc/proxy-for-ubuntu/env` and does not leak into logs
- [ ] `journalctl -u proxy-for-ubuntud | grep -i password` — empty
- [ ] `grep -r` through logs finds no UUIDs or passwords
- [ ] Profile export with "hide secrets" replaces them with `***REDACTED***`
- [ ] There is a warning in the logs about `skip_cert_verify: true` if enabled
- [ ] GUI runs as a regular user: `ps -o user= -C proxy-for-ubuntu` shows not
  root

## 11. Docker and virtual machines

Container traffic goes through the `FORWARD` chain, not `OUTPUT`, so
`intercept.docker: true` adds a `nat prerouting` chain with `redirect`.

- [ ] With `intercept.docker: true`, `docker run --rm curlimages/curl -s
      https://ifconfig.me` shows the proxy server address
- [ ] Without the flag container traffic stays direct
- [ ] Container UDP is intercepted through `tproxy` in `prerouting` and
      replies come from the real port
- [ ] The limitation is described in README, not concealed

## 12. Documentation

- [ ] All commands from README/README.en.md run without edits
- [ ] Links in README/README.en.md point to existing files
- [ ] The protocols table matches actual status
- [ ] `docs/PROTOCOLS.md` / `docs/PROTOCOLS.en.md` do not promise what the code
  does not have
