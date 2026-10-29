#!/bin/bash
# Стенд нагрузки TUN: две netns в привилегированном контейнере.
#
#   bash load-stand.sh setup      # netns + veth, как в материалах сессии 15
#   bash load-stand.sh serve      # эхо-сервер TCP/UDP в серверной netns
#   bash load-stand.sh daemon     # конфиг + proxy-for-ubuntud в клиентской netns
#   bash load-stand.sh stop       # disconnect и остановка демона
#   bash load-stand.sh teardown   # stop + удалить netns и конфиг
#
# Трафик гоняет load-client.py от uid 1000 (root в цепочках демона
# возвращается напрямую и прошёл бы мимо перехвата).
set -u

CLIENT_NS=pfu-tun
SERVER_NS=pfu-tun-srv
CLIENT=10.210.0.2
SERVER=10.210.0.1
TARGET=203.0.113.1
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN=/run/pfu-stand
DAEMON=/usr/local/bin/proxy-for-ubuntud
CLI=/usr/local/bin/pfu-cli
CONF=/etc/proxy-for-ubuntu/config.yaml

cleanup_ns() {
    ip netns del "$CLIENT_NS" 2>/dev/null
    ip netns del "$SERVER_NS" 2>/dev/null
}

stop_daemon() {
    if [ -x "$CLI" ]; then
        "$CLI" disconnect >/dev/null 2>&1 || true
    fi
    if [ -f "$RUN/daemon.pid" ]; then
        kill "$(cat "$RUN/daemon.pid")" 2>/dev/null || true
        for _ in $(seq 1 20); do
            kill -0 "$(cat "$RUN/daemon.pid" 2>/dev/null)" 2>/dev/null || break
            sleep 0.2
        done
        rm -f "$RUN/daemon.pid"
    fi
    if [ -f "$RUN/serve.pid" ]; then
        kill "$(cat "$RUN/serve.pid")" 2>/dev/null || true
        rm -f "$RUN/serve.pid"
    fi
}

case "${1:-}" in
  setup)
    mkdir -p "$RUN"
    cleanup_ns
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
    # Выход в интернет для health-check и probe при `reload`: серверная netns
    # получает линк в root netns контейнера, root — masquerade. Без этого
    # supervisor.apply всегда падает на проверке соединения, и проверять
    # пересоздание бессмысленно.
    ip link add veth-r type veth peer name veth-rs
    ip link set veth-rs netns "$SERVER_NS"
    ip addr add 10.211.0.1/30 dev veth-r
    ip link set veth-r up
    ip netns exec "$SERVER_NS" ip addr add 10.211.0.2/30 dev veth-rs
    ip netns exec "$SERVER_NS" ip link set veth-rs up
    ip netns exec "$SERVER_NS" ip route replace default via 10.211.0.1
    ip route replace 10.210.0.0/24 via 10.211.0.2 dev veth-r
    sysctl -qw net.ipv4.ip_forward=1
    ip netns exec "$SERVER_NS" sysctl -qw net.ipv4.ip_forward=1
    nft delete table ip pfu-stand 2>/dev/null
    nft add table ip pfu-stand
    nft 'add chain ip pfu-stand post { type nat hook postrouting priority 100; }'
    nft add rule ip pfu-stand post ip saddr 10.210.0.0/24 masquerade
    nft add rule ip pfu-stand post ip saddr 10.211.0.0/30 masquerade
    # `supervisor.apply` (reload/config.apply) делает health-check: резолвит
    # cloudflare.com и открывает TCP 443. В netns резолвер вернул бы IPv6
    # (маршрута нет), поэтому фиксируем IPv4 в /etc/hosts контейнера.
    grep -q '^1.1.1.1 cloudflare.com' /etc/hosts ||
        printf '1.1.1.1 cloudflare.com\n8.8.8.8 www.gstatic.com\n' >>/etc/hosts
    echo "stand ready: $CLIENT_NS/$SERVER_NS, target $TARGET"
    ;;
  serve)
    ip netns exec "$SERVER_NS" nohup python3 -u "$HERE/load-echo.py" \
        >"$RUN/serve.log" 2>&1 &
    echo $! >"$RUN/serve.pid"
    sleep 1
    cat "$RUN/serve.log"
    ;;
  daemon)
    install -d -m 0750 /etc/proxy-for-ubuntu /run/proxy-for-ubuntu \
        /var/lib/proxy-for-ubuntu/rollback
    cp "$HERE/config.yaml" "$CONF"
    chmod 0600 "$CONF"
    ip netns exec "$CLIENT_NS" nohup "$DAEMON" --daemon \
        >"$RUN/daemon.log" 2>&1 &
    echo $! >"$RUN/daemon.pid"
    for _ in $(seq 1 50); do
        if "$CLI" status >/dev/null 2>&1; then
            echo "daemon up (pid $(cat "$RUN/daemon.pid"))"
            "$CLI" status
            exit 0
        fi
        sleep 0.2
    done
    echo "daemon did not start; log:" >&2
    tail -20 "$RUN/daemon.log" >&2
    exit 1
    ;;
  stop)
    stop_daemon
    echo "stopped"
    ;;
  teardown)
    stop_daemon
    cleanup_ns
    nft delete table ip pfu-stand 2>/dev/null || true
    ip link del veth-r 2>/dev/null || true
    rm -rf "$RUN" /etc/proxy-for-ubuntu
    echo "stand removed"
    ;;
  *)
    echo "usage: $0 setup|serve|daemon|stop|teardown" >&2
    exit 2
    ;;
esac
