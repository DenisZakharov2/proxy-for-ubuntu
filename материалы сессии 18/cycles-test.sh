#!/bin/bash
# Повторные connect/disconnect при живом TUN: ищем EBUSY/EADDRINUSE и
# остатки после выключения. Проверка идёт в клиентской netns стенда.
#
#   bash cycles-test.sh [число_циклов]
set -u
NS=pfu-tun
N="${1:-5}"
fail=0

state() {
    local dev ports rules
    dev=$(ip netns exec "$NS" ip -o link show pfu0 2>/dev/null | wc -l)
    ports=$(ip netns exec "$NS" ss -ltnH '( sport = :15000 )' | wc -l)
    ports=$((ports + $(ip netns exec "$NS" ss -lunH '( sport = :15001 )' | wc -l)))
    rules=$(ip netns exec "$NS" ip rule show | grep -c 'fwmark 0x[12] lookup' || true)
    printf 'dev=%s ports=%s rules=%s' "$dev" "$ports" "$rules"
}

for i in $(seq 1 "$N"); do
    echo "== цикл $i =="
    /usr/local/bin/pfu-cli connect >/dev/null || { echo "connect FAILED"; fail=1; }
    # Повторный connect должен быть идемпотентным, а не EADDRINUSE.
    /usr/local/bin/pfu-cli connect | grep -q 'уже включён' \
        || { echo "повторный connect не идемпотентен"; fail=1; }
    echo -n "  после connect:  "; state; echo
    ip netns exec "$NS" setpriv --reuid 1000 --regid 1000 --keep-groups \
        python3 "/src/материалы сессии 18/load-client.py" tcp-burst --conns 20 --payload 1024 \
        | sed 's/^/  /'
    /usr/local/bin/pfu-cli disconnect >/dev/null || { echo "disconnect FAILED"; fail=1; }
    echo -n "  после disconnect: "; state; echo
    st=$(state)
    case "$st" in
        "dev=0 ports=0 rules=0") ;;
        *) echo "  ОСТАТКИ после выключения"; fail=1 ;;
    esac
done

echo "== итог: $([ "$fail" -eq 0 ] && echo ok || echo FAIL) =="
exit "$fail"
