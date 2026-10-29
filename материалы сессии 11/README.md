# Материалы сессии 11 (26 октября 2026)

Продолжение сессии 10: закрыт P1, проверены Docker TCP и нагрузка, выпущена 0.1.2.

## Содержимое

| Файл | Что это |
|------|---------|
| `pfu-load.py` | 250 параллельных HTTPS-запросов через перехват. Печатает число успешных и время; ошибки — по тексту. |
| `pfu-docker-check.md` | Как проверялся перехват TCP из контейнера и как вернуть конфиг. |
| `release/` | Релизный `.deb` 0.1.2 и его `.sha256` (скачаны с GitHub, сумма проверена). |

## Нагрузка

```bash
systemd-run --system --unit=pfu-devd --property=Restart=no --property=LimitNOFILE=65536 \
  <clone>/app/src-tauri/target/debug/proxy-for-ubuntud --daemon
./target/debug/pfu-cli connect
python3 ./pfu-load.py
PID=$(systemctl show -p MainPID --value pfu-devd)
systemd-run --system --wait --collect --unit=pfu-fd /bin/sh -c "ls /proc/$PID/fd | wc -l"
```

Результат прогона: `ok=250/250 elapsed=1.33s`, открытых дескрипторов после — 14.
