#!/usr/bin/env python3
"""Клиент стенда: спрашивает имя у сервера подключённым UDP-сокетом.

    dns-client.py <сервер> <имя>

Подключённый сокет принимает датаграмму только с того адреса:порта, куда он
подключён. Поэтому печатается и источник ответа: перехват обязан вернуть его
как 127.0.0.53:53, иначе glibc такой ответ отбросила бы.

Вывод: `rcode=<n> source=<ip:port> answers=<ip,ip|-|timeout>`
"""
import socket
import struct
import sys

server, name = sys.argv[1], sys.argv[2]

query = b"\x12\x34\x01\x00" + struct.pack("!HHHH", 1, 0, 0, 0)
for part in name.split("."):
    query += bytes([len(part)]) + part.encode()
query += b"\x00" + struct.pack("!HH", 1, 1)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(6)
sock.connect((server, 53))
sock.send(query)
try:
    data, src = sock.recvfrom(4096)
except socket.timeout:
    print("rcode=- source=- answers=timeout")
    sys.exit(2)

rcode = data[3] & 0x0F
ancount = struct.unpack("!H", data[6:8])[0]
i = 12
while data[i]:
    i += 1 + data[i]
i += 5
ips = []
for _ in range(ancount):
    if data[i] & 0xC0 == 0xC0:
        i += 2
    else:
        while data[i]:
            i += 1 + data[i]
        i += 1
    rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[i:i + 10])
    i += 10
    if rtype == 1 and rdlen == 4:
        ips.append(socket.inet_ntoa(data[i:i + 4]))
    i += rdlen

print(f"rcode={rcode} source={src[0]}:{src[1]} answers={','.join(ips) or '-'}")
