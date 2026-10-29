# Сессия 16 — перехват DNS (`redir-host`)

Что сделано в этой сессии: DNS перестал быть «обычным UDP, который просто
проксируется». Теперь демон понимает DNS-ответы и помнит соответствие
«адрес → домен», поэтому правила по домену работают и для соединений, которые
приложение открывает уже по IP.

## Как это работает

1. Приложение шлёт запрос на внешний `:53` (например `dig @8.8.8.8`).
2. Пакет попадает в `pfu0`, userspace-стек поднимает его как обычный
   UDP-поток, правила выбирают outbound — запрос уходит через прокси.
3. Ответ возвращается приложению как есть (`redir-host`: настоящий адрес,
   никакой подмены).
4. `engine/dns.rs::remember_response` разбирает A/AAAA-записи и запоминает
   «IP → домен» на `cache_ttl` секунд.
5. Перед решением по следующему соединению `Engine::enrich_domain`
   подставляет имя в `Flow` — работают `DOMAIN`, `DOMAIN-SUFFIX`, `GEOSITE`,
   и прокси с `remote_dns` получает домен, а не адрес.

`HIJACK-DNS` в правилах теперь означает «ответить самим»: резолвер разрешает
имя локально и собирает ответ A/AAAA, запрос наружу не уходит. На прочие типы
записей и на неудачу — `SERVFAIL`, чтобы приложение сразу шло к следующему
серверу.

`fake-ip` не реализован: валидация отклоняет его с указанием на `redir-host`,
а `postinst` переводит уже установленный конфиг и оставляет копию
`config.yaml.pre-0.3.0`.

## Чего нет

- запросы к `127.0.0.53` (systemd-resolved) идут мимо: это loopback, он
  исключён из всех цепочек;
- DNS over TCP (53/tcp) проксируется, но в карту не попадает;
- `fake-ip` не будет реализован.

## Стенд

Две netns (как в сессии 15): клиент `pfu-tun` с устройством `pfu0` и сервер
`pfu-tun-srv` с адресом `203.0.113.1`. В серверной netns поднимаются
эхо-сервер TCP/UDP и мини-DNS, который отвечает `A 203.0.113.1` на
`echo.dns.test`; больше ничего не нужно — интернет стенду не требуется.

```bash
docker run -d --privileged --name pfu-stand \
  -v /dev/net/tun:/dev/net/tun \
  -v "/home/anony/Documents/Личное/Проект proxy for ubuntu:/src:ro" \
  ubuntu:24.04 sleep infinity
docker exec pfu-stand bash -c 'apt-get update -qq && apt-get install -y -qq iproute2 nftables python3 util-linux'

cd app/src-tauri && cargo test --test tun_live --no-run
docker cp target/debug/deps/tun_live-<hash> pfu-stand:/bin/tun_live

docker exec pfu-stand bash -c '
  bash "/src/материалы сессии 16/tun-stand.sh" setup
  ip netns exec pfu-tun-srv python3 -u "/src/материалы сессии 16/tun-echo.py" &
  ip netns exec pfu-tun-srv python3 -u "/src/материалы сессии 16/dns-echo.py" &
  sleep 1
  bash "/src/материалы сессии 16/tun-stand.sh" test /bin/tun_live
  bash "/src/материалы сессии 16/tun-stand.sh" teardown'
```

## Результат прогона

```
running 3 tests
test dns_hijack_answers_without_upstream ... ok
test dns_redir_host_names_the_following_connection ... ok
test tun_udp_and_tcp_roundtrip ... ok

test result: ok. 3 passed; 0 failed
```

Что именно доказывает `dns_redir_host_names_the_following_connection`:

| Шаг | Ожидание | Что видно |
|---|---|---|
| TCP на `203.0.113.1:9998` до DNS | соединение проходит | `connected` |
| DNS-запрос `echo.dns.test` → `203.0.113.1:53` | настоящий ответ через прокси | `ok-dns 203.0.113.1` |
| `engine.dns.name_of(203.0.113.1)` | имя запомнено | `echo.dns.test` |
| тот же TCP после DNS | правило `DOMAIN-SUFFIX,echo.dns.test,REJECT` | `rejected` |

Без строки с `name_of` тест ничего бы не доказывал: «соединение не
установилось» бывает и по другим причинам. С ней видно, что изменилось
именно состояние карты.

`dns_hijack_answers_without_upstream` проверяет ветку `HIJACK-DNS`: запрос
`localhost` уходит на `203.0.113.1:53`, где никто не слушает DNS, а ответ
`127.0.0.1` приходит — значит его собрал демон.

## Файлы

| Файл | Что |
|---|---|
| `tun-stand.sh` | две netns, адреса, маршрут — копия из сессии 15 |
| `tun-echo.py` | эхо TCP/UDP на `203.0.113.1` — копия из сессии 15 |
| `dns-echo.py` | мини-DNS: `A 203.0.113.1` на `echo.dns.test` |

Живые тесты лежат в `app/src-tauri/tests/tun_live.rs` и помечены `#[ignore]`:
в CI их не запустить (нужен root и `/dev/net/tun`).
