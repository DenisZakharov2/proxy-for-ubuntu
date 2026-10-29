#!/bin/bash
# Проверка пересоздания TUN при `reload` (SIGHUP) под живыми соединениями.
#
#   bash reload-test.sh [секунды_удержания]
#
# Открывает 50 TCP-соединений через TUN, отправляет SIGHUP демону, смотрит,
# пережили ли соединения пересоздание устройства, и проверяет новое
# соединение сразу после reload.
set -u

SECONDS_HOLD="${1:-30}"
NS=pfu-tun
PID=$(cat /run/pfu-stand/daemon.pid)
OUT=/run/pfu-stand/hold.log
CLIENT="/src/материалы сессии 18/load-client.py"
: >"$OUT"

ip netns exec "$NS" setpriv --reuid 1000 --regid 1000 --keep-groups \
    python3 "$CLIENT" tcp-hold --conns 50 --seconds "$SECONDS_HOLD" >"$OUT" 2>&1 &
HOLD=$!

for _ in $(seq 1 200); do
    grep -q '^HOLD open=' "$OUT" 2>/dev/null && break
    sleep 0.1
done
echo "== до reload =="
cat "$OUT"

echo "== SIGHUP =="
kill -HUP "$PID"

sleep 2
echo "== состояние после reload =="
ip netns exec "$NS" ip -o addr show pfu0 2>/dev/null || echo "pfu0 отсутствует"
ip netns exec "$NS" ip route show table 101 2>/dev/null || true
echo "-- новое соединение сразу после reload --"
ip netns exec "$NS" setpriv --reuid 1000 --regid 1000 --keep-groups \
    python3 "$CLIENT" tcp-burst --conns 5 --payload 1024
echo "-- журнал --"
grep -E "TUN|перехват|rollback|ERROR|WARN|примен" /run/pfu-stand/daemon.log | tail -25

wait "$HOLD"
STATUS=$?
echo "== после удержания =="
cat "$OUT"
echo "exit=$STATUS"
