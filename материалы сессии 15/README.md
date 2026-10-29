# Материалы сессии 15 — TUN и локальный UDP

## Что проверено

TUN-стек собран целиком: устройство `pfu0`, маршрут по метке `0x2`, разбор
IPv4/UDP/TCP и возврат ответов приложению. Живой стенд — две сетевые
namespace, настоящие пакеты.

| Проверка | Результат |
|---|---|
| UDP-датаграмма 1200 Б через `pfu0` | ✅ вернулась без изменений |
| TCP-сессия 256 КБ в обе стороны (окно 65 535, FIN с обеих сторон) | ✅ байты совпали побайтово |
| Три прогона подряд (повторное создание `pfu0`) | ✅ 3/3 |
| `teardown` после стенда | ✅ нет устройства, правила `fwmark 0x2`, таблицы `inet pfu` |
| `cargo test --lib` | 203 passed |
| `cargo clippy --all-targets -- -D warnings` | чисто |

Скорость на стенде (debug-сборка, veth): 256 КБ вверх + 256 КБ вниз за
~0,5 с. Это не замер производительности: release-сборка не проверялась.

## Стенд

`tun-stand.sh` — две namespace:

```
pfu-tun (клиент)                     pfu-tun-srv (сервер)
  veth-c 10.210.0.2/24  ── veth ──  veth-s 10.210.0.1/24
  pfu0 198.18.0.1/15                 203.0.113.1/32 (эхо 9999/udp, 9998/tcp)
  приложение — uid 1000
```

Получатель `203.0.113.1` не принадлежит клиентской машине: иначе
`fib daddr type local return` законно пропустил бы трафик мимо TUN и тест
проверял бы пустоту. Приложение запускается от uid 1000, потому что трафик
root'а (сам демон) исключён из перехвата.

### Запуск

Нужен root, `/dev/net/tun` и `ip`, `nft`, `python3`, `setpriv`. На машине
без `sudo` и без рабочего polkit стенд запускается в привилегированном
контейнере — сеть хоста при этом не трогается, у контейнера своя netns:

```bash
# один раз
docker run -d --privileged --name pfu-stand \
  -v /dev/net/tun:/dev/net/tun \
  -v "/home/anony/Documents/Личное/Проект proxy for ubuntu:/src:ro" \
  ubuntu:24.04 sleep infinity
docker exec pfu-stand bash -c 'apt-get update -qq && apt-get install -y -qq iproute2 nftables python3 util-linux'

# сборка теста и прогон
cd app/src-tauri
cargo test --test tun_live --no-run
docker cp target/debug/deps/tun_live-<hash> pfu-stand:/bin/tun_live
docker exec pfu-stand bash -c '
  bash "/src/материалы сессии 15/tun-stand.sh" setup
  ip netns exec pfu-tun-srv python3 -u "/src/материалы сессии 15/tun-echo.py" &
  sleep 1
  ip netns exec pfu-tun /bin/tun_live --ignored --nocapture
  bash "/src/материалы сессии 15/tun-stand.sh" teardown'
```

Почему контейнер, а не `systemd-run`: на этой машине polkit отвечает
`FAILED to authenticate ... manage-units`, а `unshare -Urn` запрещён
(`/proc/self/uid_map: Operation not permitted`). Привилегированный контейнер
даёт CAP_NET_ADMIN в собственной network namespace, и этого достаточно.

## Файлы

| Файл | Что |
|---|---|
| `tun-stand.sh` | netns-пара: setup / serve / test `<бинарник>` / teardown |
| `tun-echo.py` | эхо TCP :9998 и UDP :9999 на `203.0.113.1`, отвечает теми же байтами |
| `README.md` | этот файл |

## Грабли (обе стоили прогона)

1. **`mangle output` должен быть `type route`, а не `type filter`.** С
   `filter` nftables ставит метку, но маршрут не пересчитывает: пакет уходит
   по прежнему маршруту мимо TUN. Внешне всё работает — клиент и сервер в
   стенде соединены напрямую, эхо возвращается, тест зелёный, а стек не
   участвует. Поймано счётчиками `/sys/class/net/pfu0/statistics/*`; теперь
   тест требует, чтобы через устройство прошло ≥ 500 КБ.
2. **Эхо-сервер не должен добавлять префикс к каждому `recv`.** Первая версия
   отвечала `echo:` на каждый чанк, и 256 КБ вернулись как 262 469 байт
   (64 чанка × 5 байт). Данные стека были целы — виноват стенд.

## Что осталось на следующие сессии

1. Перехват DNS: слушатель на 53, `fake-ip`/`redir-host` по-настоящему,
   подключить `engine/dns.rs` к TUN (сейчас DNS идёт как обычный UDP).
2. IPv6 в TUN: `sockaddr_in6`, `IP6T_SO_ORIGINAL_DST`/`IPV6_TRANSPARENT` не
   нужны (TUN читает пакеты целиком), но нужны v6-адреса, `inet6`-маршрут и
   разбор заголовков.
3. Нагрузка и утечки: длинная сессия, много соединений, `EADDRINUSE` при
   пересоздании `pfu0` после `reload`.
4. Проверка на живом рабочем столе с системным DNS и браузером.
