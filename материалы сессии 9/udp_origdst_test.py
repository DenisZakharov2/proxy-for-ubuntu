#!/usr/bin/env python3
"""Проверка: отдаёт ли ядро настоящий адрес получателя для UDP,
переписанного nat REDIRECT'ом в output. Нужен root (IP_TRANSPARENT)."""
import socket
import struct
import sys

IP_TRANSPARENT = 19
IP_RECVORIGDSTADDR = 20
IP_ORIGDSTADDR = 20
IP_PKTINFO = 8
SOL_IP = 0

rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rx.setsockopt(SOL_IP, IP_TRANSPARENT, 1)
rx.setsockopt(SOL_IP, IP_RECVORIGDSTADDR, 1)
rx.bind(("0.0.0.0", 19999))

tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tx.bind(("0.0.0.0", 0))
tx.sendto(b"ping", ("192.0.2.1", 9999))

data, anc, flags, src = rx.recvmsg(1500, 256)
print("получено:", data, "от", src)
orig = None
for level, typ, payload in anc:
    if level == SOL_IP and typ == IP_ORIGDSTADDR:
        # sockaddr_in: family (2 байта), port (2, network order), addr (4)
        port, addr = struct.unpack("!H4s", payload[2:8])
        orig = (socket.inet_ntoa(addr), port)
print("original dst:", orig)

if orig is None:
    print("ОТВЕТ: IP_ORIGDSTADDR не приходит для локального REDIRECT")
    sys.exit(1)

# Ответ клиенту с подменой источника на original dst — тем же сокетом.
pktinfo = struct.pack("!I4s4s", 0, socket.inet_aton(orig[0]), b"\x00" * 4)
rx.sendmsg([b"pong"], [(SOL_IP, IP_PKTINFO, pktinfo)], 0, src)

tx.settimeout(2)
got, frm = tx.recvfrom(1500)
print("ответ клиенту:", got, "от", frm)
print("ОТВЕТ: работает" if frm == orig else "ОТВЕТ: источник не совпал")
