#!/bin/bash
# Длинная сессия: 50 соединений через TUN держатся и переписываются каждые
# ECHO секунд; на середине — `reload`. Пишем RSS и число дескрипторов, чтобы
# увидеть утечки и рост.
#
#   bash long-test.sh [секунды] [интервал_echo]
set -u
SECONDS_RUN="${1:-300}"
ECHO="${2:-15}"
NS=pfu-tun
PID=$(cat /run/pfu-stand/daemon.pid)
LOG=/run/pfu-stand/long.log
CLIENT="/src/материалы сессии 18/load-client.py"
: >"$LOG"

ip netns exec "$NS" setpriv --reuid 1000 --regid 1000 --keep-groups \
    python3 "$CLIENT" tcp-hold --conns 50 --seconds "$SECONDS_RUN" \
    --echo-every "$ECHO" >"$LOG" 2>&1 &
HOLD=$!

sleep 3
echo "start rss=$(ps -o rss= -p "$PID")kB fds=$(ls "/proc/$PID/fd" | wc -l)"
sent_reload=0
while kill -0 "$HOLD" 2>/dev/null; do
    sleep 20
    line="rss=$(ps -o rss= -p "$PID" 2>/dev/null || echo -)kB fds=$(ls "/proc/$PID/fd" 2>/dev/null | wc -l)"
    echo "$(date +%H:%M:%S) $line"
    if [ "$sent_reload" -eq 0 ] && [ "$SECONDS_RUN" -ge 120 ]; then
        if grep -q 'PING round=4' "$LOG"; then
            echo "$(date +%H:%M:%S) SIGHUP (reload под нагрузкой)"
            kill -HUP "$PID"
            sent_reload=1
        fi
    fi
done
wait "$HOLD"
STATUS=$?
echo "== хвост журнала клиента =="
tail -6 "$LOG"
echo "exit=$STATUS end rss=$(ps -o rss= -p "$PID")kB fds=$(ls "/proc/$PID/fd" | wc -l)"
echo "== ошибки демона =="
grep -cE "ERROR|WARN" /run/pfu-stand/daemon.log
