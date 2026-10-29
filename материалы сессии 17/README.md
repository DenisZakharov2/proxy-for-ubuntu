# Сессия 17 (29.10.2026): живая проверка TUN + DNS на хосте, выпуск 0.3.0

Что здесь лежит:

| Файл | Что |
|---|---|
| `config-live.yaml` | конфиг для живой проверки: `tun.enabled: true`, `mtu: 1500`, `dns.strategy: redir-host`, единственный outbound `DIRECT` (как в установленном конфиге) |
| `live-check.sh` | измерения `before` / `traffic` / `after`; сам перехват не включает |
| `quic-probe.py` | QUIC-рукопожатие (ALPN `h3`) через `aioquic` — на машине нет curl с HTTP/3 |
| `release/` | релизный `.deb` 0.3.0 из CI + `.sha256`; появляется после публикации тега |

## Что проверено на этой машине

Пакет: `proxy-for-ubuntu_0.3.0_amd64.deb`, `0.3.0-1`, установлен поверх `0.1.2-1`
(`sudo apt install`). postinst сделал `config.yaml.pre-0.3.0` и перевёл
`dns.strategy: fake-ip → redir-host`. Затем поставлен `config-live.yaml`.

В `release/` после публикации лежит **релизный** `.deb` из CI — он собран на
22.04 и это единственный артефакт, который стоит раздавать. Живой прогон шёл
на локальной сборке под этот хост (4 291 960 байт, sha256 `6fed1307…3fad0a`,
`0.3.0-1`); после правки `--check` она пересобрана (4 293 224 байта, sha256
`74b3af53…9983b33`) — разница только в чтении конфига для `--check`, путь
перехвата не менялся. Локальные `.deb` в git не попадают (`*.deb` в
`.gitignore`).

До включения: `enabled: false`, порты 15000/15001 закрыты, устройства `pfu0`
нет, таблица 101 пуста, правил `fwmark` нет.

После `pfu-cli connect`:

- `pfu0` — `inet 198.18.0.1/15`, `default dev pfu0` в таблице 101;
- слушатели 15000 (TCP) и 15001 (UDP) подняты;
- TCP через перехват: `curl https://example.com` → `http=200`, 577 байт, 0,29 с;
- скачивание 3 МБ через перехват: `http=200`, 3 000 000 байт, 745 КБ/с,
  при этом счётчик `pfu0` `rx_bytes` вырос на **3 103 425** байт — трафик
  действительно прошёл через устройство, а не мимо;
- UDP/DNS: `dig @1.1.1.1 example.com` и `dig @8.8.8.8` вернули `8.6.112.0`,
  `8.47.69.0` — то есть UDP-поток к внешнему `:53` дошёл и вернулся через
  тот же стек;
- QUIC: рукопожатие с `test.privateoctopus.com:4433` завершилось
  (`quic handshake ok`) — порт 4433, чтобы не путать с блокировкой UDP 443
  у провайдера: `www.google.com:443` и `cloudflare.com:443` не отвечают и
  **без** прокси, так что это ограничение сети, а не демона;
- статистика: `metrics` во время передачи — `connections: 2`,
  `active_rules: FINAL/DIRECT 5 559 351 Б`;
- журнал: за 10 минут ни одного `warning`/`error`.

После `pfu-cli disconnect`: порты 15000/15001 закрыты, `pfu0` исчез, таблица
101 пуста, правил `fwmark` нет, `curl` напрямую — `http=200`, в журнале тихо.

Ограничение проверки: таблицу `inet pfu` без root не посмотреть (`nft list`
требует `CAP_NET_ADMIN`); отсутствие правил подтверждено портами, устройством,
таблицей 101 и `ip rule`, а также `pfu-cli doctor`.

## Найдено по дороге

`proxy-for-ubuntud --check` читал конфиг строгим `Config::load`, а тот
отвергает конфиг без единого прокси — ровно состояние сразу после установки.
Из-за `unwrap_or(false)` строка в журнале при `tun.enabled: true` говорила
«TUN выключен в конфиге», а отсутствующий `/dev/net/tun` не считался
проблемой даже в `--strict`. Исправлено на `Config::load_for_read`, тест
`load_for_read_sees_tun_in_a_direct_only_config`; тестов стало 209.

Ещё: `packaging/profiles/default.yaml` (файл, который пакет ставит новым
пользователям) содержал `tun.mtu: 9000`, хотя CHANGELOG и `docs/CONFIG.md`
обещают 1500. Исправлено до сборки пакета.

## Как повторить

```bash
cd "/home/anony/Documents/Личное/Проект proxy for ubuntu"
bash "материалы сессии 17/live-check.sh" before
pfu-cli connect
bash "материалы сессии 17/live-check.sh" traffic
~/.hermes/cache/scratch/quic-venv/bin/python "материалы сессии 17/quic-probe.py" \
    test.privateoctopus.com 4433
pfu-cli disconnect
bash "материалы сессии 17/live-check.sh" after
```

QUIC-проба требует `aioquic`:

```bash
python3 -m venv ~/.hermes/cache/scratch/quic-venv
~/.hermes/cache/scratch/quic-venv/bin/pip install aioquic
```

## Вернуть конфиг после проверки

`config-live.yaml` оставляет `tun.enabled: true` — при выключенном перехвате
это ни на что не влияет, но следующий `connect` поднимет TUN. Если TUN не
нужен:

```bash
sudo install -m 0600 -o root -g root \
  /etc/proxy-for-ubuntu/config.yaml.pre-0.3.0 /etc/proxy-for-ubuntu/config.yaml
sudo systemctl restart proxy-for-ubuntud
```

Копия `config.yaml.pre-0.3.0` — исходный конфиг 0.1.2 с `fake-ip`; после
установки 0.3.0 его снова переведёт postinst, если ставить пакет заново.
