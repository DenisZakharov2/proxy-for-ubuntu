# Материалы сессии 10 (26 октября 2026)

Продолжение сессии 9: закрытие P0 из `../PROGRESS_2026-10-26.md` §5.

## Содержимое

| Файл | Что это |
|------|---------|
| `p0-shutdown-teardown-limit-572eac8.patch` | Полный патч коммита `572eac8` (`git am` на чистом клоне ветки `wip/redirect-tproxy`). |
| `pfu-udp-stand.sh` | Стенд UDP TPROXY: два netns (клиент `pfutest`, сервер `pfuserver`), veth-пары, маршрут на `198.51.100.1` через серверный netns. Команды: `setup`, `serve`, `teardown`. |
| `pfu-udp-echo.py` | Эхо-сервер, слушает `198.51.100.1:9999` внутри серверного netns. |
| `pfu-udp-probe.py` | Клиент: 5 датаграмм из `10.200.0.2:40000`, печатает ответы и их источник. |
| `pfu-state-check.sh` | Проверка чистоты после `disconnect`: порты, таблица `inet pfu`, `ip rule`, таблица 100. |

## Как повторить проверку

Все команды — от root (через `systemd-run --system`, см. §1 прогресса).

```bash
# 1. Стенд и эхо-сервер
systemd-run --system --wait --collect --unit=pfu-stand ./pfu-udp-stand.sh setup
systemd-run --system --unit=pfu-udp-echo ./pfu-udp-stand.sh serve

# 2. Демон (отладочная сборка) и перехват
systemd-run --system --unit=pfu-devd --property=Restart=no \
  --property=LimitNOFILE=65536 \
  <clone>/app/src-tauri/target/debug/proxy-for-ubuntud --daemon
./target/debug/pfu-cli connect

# 3. Проба: ожидается 5/5 ответов от 198.51.100.1:9999
ip netns exec pfutest python3 ./pfu-udp-probe.py

# 4. Выключение: порт 15001 и сокеты потока должны исчезнуть сразу
./target/debug/pfu-cli disconnect
./pfu-state-check.sh

# 5. Уборка
systemd-run --system --wait --collect --unit=pfu-stand-down ./pfu-udp-stand.sh teardown
```

## Почему стенд из двух netns

`tproxy` в `prerouting` теперь пропускает трафик, адресованный самой машине
(`fib daddr type local return`), и multicast. Поэтому проверять перехват на
адресе, поднятом на `lo` хоста, нельзя: пакет пойдёт напрямую в локальный
сокет, минуя прокси. Получатель должен быть за пределами хоста — в отдельном
netns за veth.
