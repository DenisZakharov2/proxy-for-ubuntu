#!/bin/bash
# Проверка чистоты системы после disconnect: запускается от root через systemd-run.
echo "-- ports --"
ss -ltn | grep -E ':15000\b' || echo "tcp 15000 free"
ss -lun | grep -E ':15001\b' || echo "udp 15001 free"
echo "-- nft --"
nft list table inet pfu 2>&1 | head -5
echo "-- ip rule --"
ip rule show | grep "fwmark 0x1" || echo "no ip rule"
echo "-- table 100 --"
ip route show table 100
