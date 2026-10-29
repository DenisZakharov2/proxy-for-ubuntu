#!/bin/bash
# Стенд перехвата системного резолвера (127.0.0.53).
#
# Клиентская netns `pfu-dns` — там применяются nft-правила, живёт демон
# (тестовый бинарник) и «системный резолвер»: он слушает 127.0.0.53:53 и
# отвечает 203.0.113.99. Серверная `pfu-dns-srv` держит настоящий вышестоящий
# DNS на 203.0.113.53:53 и отвечает 203.0.113.1.
#
# Разные ответы и делают проверку честной: если перехват не сработал,
# приложение получит .99 (ответ локального резолвера), а не .1.
#
# Запуск (root, лучше в привилегированном контейнере):
#   bash dns-stub-stand.sh all <тестовый-бинарник>
# или по шагам: setup | serve | test <bin> | teardown
set -u

CLIENT_NS=pfu-dns
SERVER_NS=pfu-dns-srv
CLIENT=10.211.0.2
SERVER=10.211.0.1
UPSTREAM=203.0.113.53
HERE="$(cd "$(dirname "$0")" && pwd)"

cleanup() {
  ip netns del "$CLIENT_NS" 2>/dev/null
  ip netns del "$SERVER_NS" 2>/dev/null
}

case "${1:-}" in
  setup)
    cleanup
    ip netns add "$CLIENT_NS"
    ip netns add "$SERVER_NS"
    ip link add veth-c type veth peer name veth-s
    ip link set veth-c netns "$CLIENT_NS"
    ip link set veth-s netns "$SERVER_NS"
    ip netns exec "$CLIENT_NS" ip addr add "$CLIENT/24" dev veth-c
    ip netns exec "$CLIENT_NS" ip link set veth-c up
    ip netns exec "$CLIENT_NS" ip link set lo up
    ip netns exec "$CLIENT_NS" ip route add default via "$SERVER"
    ip netns exec "$SERVER_NS" ip addr add "$SERVER/24" dev veth-s
    ip netns exec "$SERVER_NS" ip addr add "$UPSTREAM/32" dev veth-s
    ip netns exec "$SERVER_NS" ip link set veth-s up
    ip netns exec "$SERVER_NS" ip link set lo up
    # «Системный резолвер» клиента: настоящий systemd-resolved слушает
    # 127.0.0.53:53, здесь — его заглушка с узнаваемым ответом.
    ip netns exec "$CLIENT_NS" python3 -u "$HERE/dns-echo.py" 127.0.0.53 53 203.0.113.99 >/tmp/fake-resolved.log 2>&1 &
    # Вышестоящий DNS в серверной netns.
    ip netns exec "$SERVER_NS" python3 -u "$HERE/dns-echo.py" "$UPSTREAM" 53 203.0.113.1 echo.dns.test >/tmp/upstream.log 2>&1 &
    sleep 1
    echo "stand ready"
    ip netns exec "$CLIENT_NS" ip -br addr show veth-c
    ip netns exec "$SERVER_NS" ip -br addr show veth-s
    ;;
  serve)
    echo "серверы уже запущены в setup (см. /tmp/fake-resolved.log и /tmp/upstream.log)"
    ;;
  test)
    BIN="${2:?нужен путь к тестовому бинарнику}"
    ip netns exec "$CLIENT_NS" "$BIN" --ignored --nocapture --test-threads=1
    ;;
  logs)
    echo "== fake resolved =="; cat /tmp/fake-resolved.log
    echo "== upstream =="; cat /tmp/upstream.log
    ;;
  teardown)
    pkill -f "dns-echo.py" 2>/dev/null
    cleanup
    echo "stand removed"
    ;;
  all)
    BIN="${2:?нужен путь к тестовому бинарнику}"
    bash "$0" setup
    bash "$0" test "$BIN"
    rc=$?
    bash "$0" logs
    bash "$0" teardown
    exit $rc
    ;;
  *)
    echo "usage: $0 setup|serve|test <bin>|logs|teardown|all <bin>" >&2
    exit 2
    ;;
esac
