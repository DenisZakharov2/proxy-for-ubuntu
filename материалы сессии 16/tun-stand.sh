#!/bin/bash
# Стенд для живого теста TUN-стека.
#
# Клиентская netns `pfu-tun` — там создаётся pfu0, применяются nft-правила и
# живёт тестовое приложение (uid 1000). Серверная `pfu-tun-srv` держит
# 203.0.113.1:9999/9998, поэтому адрес получателя не локальный для клиента —
# иначе `fib daddr type local return` законно пропустил бы трафик мимо TUN.
#
# Запуск (root): systemd-run --system --wait --collect --unit=<имя> \
#   bash "материалы сессии 15/tun-stand.sh" setup|serve|test <бинарник>|teardown
set -u

CLIENT_NS=pfu-tun
SERVER_NS=pfu-tun-srv
CLIENT=10.210.0.2
SERVER=10.210.0.1
TARGET=203.0.113.1
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
    ip netns exec "$SERVER_NS" ip addr add "$TARGET/32" dev veth-s
    ip netns exec "$SERVER_NS" ip link set veth-s up
    ip netns exec "$SERVER_NS" ip link set lo up
    echo "stand ready"
    ip netns exec "$CLIENT_NS" ip -br addr show veth-c
    ip netns exec "$SERVER_NS" ip -br addr show veth-s
    ;;
  serve)
    ip netns exec "$SERVER_NS" python3 -u "$HERE/tun-echo.py"
    ;;
  test)
    BIN="${2:?нужен путь к тестовому бинарнику}"
    ip netns exec "$CLIENT_NS" "$BIN" --ignored --nocapture --test-threads=1
    ;;
  teardown)
    cleanup
    echo "stand removed"
    ;;
  *)
    echo "usage: $0 setup|serve|test <bin>|teardown" >&2
    exit 2
    ;;
esac
