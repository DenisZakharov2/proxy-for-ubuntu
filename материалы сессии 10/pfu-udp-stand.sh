#!/bin/bash
# Стенд для проверки UDP TPROXY: клиент и сервер в разных netns, между ними
# хост с демоном. Получатель 198.51.100.1 НЕ принадлежит хосту, поэтому
# tproxy-правило обязано его перехватить (в отличие от адреса на lo).
set -u
CLIENT_NS=pfutest
SERVER_NS=pfuserver
HOST_CLIENT=10.200.0.1
CLIENT=10.200.0.2
HOST_SERVER=10.201.0.1
SERVER=10.201.0.2
TARGET=198.51.100.1

cleanup() {
  ip netns del "$CLIENT_NS" 2>/dev/null
  ip netns del "$SERVER_NS" 2>/dev/null
  ip link del veth0 2>/dev/null
  ip link del vsrv0 2>/dev/null
  ip route del "$TARGET/32" 2>/dev/null
  ip addr del "$TARGET/32" dev lo 2>/dev/null
}

case "${1:-setup}" in
  setup)
    cleanup
    # клиентская сторона
    ip netns add "$CLIENT_NS"
    ip link add veth0 type veth peer name veth1
    ip link set veth1 netns "$CLIENT_NS"
    ip addr add "$HOST_CLIENT/24" dev veth0
    ip link set veth0 up
    ip netns exec "$CLIENT_NS" ip addr add "$CLIENT/24" dev veth1
    ip netns exec "$CLIENT_NS" ip link set veth1 up
    ip netns exec "$CLIENT_NS" ip link set lo up
    ip netns exec "$CLIENT_NS" ip route add default via "$HOST_CLIENT"
    # серверная сторона: 198.51.100.1 живёт там, а не на хосте
    ip netns add "$SERVER_NS"
    ip link add vsrv0 type veth peer name vsrv1
    ip link set vsrv1 netns "$SERVER_NS"
    ip addr add "$HOST_SERVER/24" dev vsrv0
    ip link set vsrv0 up
    ip netns exec "$SERVER_NS" ip addr add "$SERVER/24" dev vsrv1
    ip netns exec "$SERVER_NS" ip addr add "$TARGET/32" dev vsrv1
    ip netns exec "$SERVER_NS" ip link set vsrv1 up
    ip netns exec "$SERVER_NS" ip link set lo up
    ip netns exec "$SERVER_NS" ip route add default via "$HOST_SERVER"
    ip route add "$TARGET/32" via "$SERVER" dev vsrv0
    sysctl -qw net.ipv4.ip_forward=1
    echo "stand ready"
    ip -br addr show veth0
    ip -br addr show vsrv0
    ip route show "$TARGET/32"
    ;;
  serve)
    ip netns exec "$SERVER_NS" python3 -u /home/anony/.hermes/cache/scratch/pfu-udp-echo.py
    ;;
  teardown)
    cleanup
    echo "stand removed"
    ;;
esac
