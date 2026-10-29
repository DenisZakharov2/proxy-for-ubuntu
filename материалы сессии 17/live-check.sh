#!/usr/bin/env bash
# Живая проверка перехвата на хосте (сессия 17).
#
# Только измеряет. Не включает и не выключает перехват: это делает
# `pfu-cli connect` / `pfu-cli disconnect` вручную, с подтверждением
# пользователя.
#
#   bash "материалы сессии 17/live-check.sh" before
#   pfu-cli connect ...
#   bash "материалы сессии 17/live-check.sh" traffic
#   pfu-cli disconnect
#   bash "материалы сессии 17/live-check.sh" after
set -uo pipefail

mode="${1:-traffic}"
dev="${PFU_TUN_DEV:-pfu0}"

counters() {
    printf 'tx_bytes=%s rx_bytes=%s\n' \
        "$(cat "/sys/class/net/$dev/statistics/tx_bytes" 2>/dev/null || echo -)" \
        "$(cat "/sys/class/net/$dev/statistics/rx_bytes" 2>/dev/null || echo -)"
}

case "$mode" in
    before)
        echo "== состояние до включения =="
        pfu-cli status | tr -d '\n' ; echo
        echo -n "port 15000: "; ss -ltnH '( sport = :15000 )' | wc -l
        echo -n "port 15001: "; ss -lunH '( sport = :15001 )' | wc -l
        echo -n "pfu0 in addr: "; (ip -o addr show "$dev" 2>/dev/null || echo 'нет устройства')
        echo -n "table 101: "; (ip route show table 101 2>/dev/null | head -3 || true)
        echo -n "fwmark rules: "; (ip rule show | grep -c 'fwmark 0x[12] lookup' || true)
        ;;
    traffic)
        echo "== трафик через перехват =="
        echo -n "до: "; counters
        echo "-- TCP (curl https://example.com) --"
        curl -m 15 -sS -o /dev/null -w 'http=%{http_code} bytes=%{size_download} time=%{time_total}\n' \
            https://example.com
        echo "-- UDP/DNS (dig @1.1.1.1 example.com) --"
        dig +time=5 +tries=1 +short @1.1.1.1 example.com A | head -3
        echo "-- UDP/DNS (dig @8.8.8.8, второй сервер) --"
        dig +time=5 +tries=1 +short @8.8.8.8 example.com A | head -3
        echo -n "после: "; counters
        echo "-- device --"
        ip -o addr show "$dev" 2>/dev/null || echo 'нет устройства'
        ip route show table 101 2>/dev/null | head -3
        echo "-- metrics (два чтения с паузой: breakdown пишется на закрытии) --"
        sleep 2
        pfu-cli metrics
        ;;
    after)
        echo "== состояние после выключения =="
        pfu-cli status | tr -d '\n' ; echo
        echo -n "port 15000 (должно быть 0): "; ss -ltnH '( sport = :15000 )' | wc -l
        echo -n "port 15001 (должно быть 0): "; ss -lunH '( sport = :15001 )' | wc -l
        echo -n "pfu0 (должно быть пусто): "; (ip -o addr show "$dev" 2>/dev/null || echo 'нет устройства')
        echo -n "table 101 (должно быть пусто): "; (ip route show table 101 2>/dev/null | head -3 || true)
        echo -n "fwmark rules (должно быть 0): "; (ip rule show | grep -c 'fwmark 0x[12] lookup' || true)
        echo -n "сеть напрямую: "; curl -m 8 -sS -o /dev/null -w 'http=%{http_code}\n' https://example.com
        echo "-- ошибки в журнале за последние 5 минут --"
        journalctl -u proxy-for-ubuntud --since '-5min' -p warning --no-pager -o cat | tail -20
        ;;
    *)
        echo "использование: $0 {before|traffic|after}" >&2
        exit 2
        ;;
esac
