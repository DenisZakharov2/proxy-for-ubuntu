#!/usr/bin/env python3
"""Мини-DNS-сервер стенда: отвечает A 203.0.113.1 на `echo.dns.test`.

Запускается в серверной netns (адрес 203.0.113.1), чтобы клиент шёл в
нелокальный адрес — иначе `fib daddr type local return` законно пропустил бы
запрос мимо TUN и проверка ничего не доказала бы.

Остальные имена получают пустой ответ (NOERROR, 0 записей): стенд не должен
зависеть от интернета.
"""
import socket
import struct

ADDR = "203.0.113.1"
NAME = "echo.dns.test"


def read_qname(data: bytes, i: int):
    labels = []
    while i < len(data) and data[i]:
        n = data[i]
        labels.append(data[i + 1:i + 1 + n].decode("latin-1"))
        i += 1 + n
    return ".".join(labels).lower(), i + 1


def main() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ADDR, 53))
    print(f"dns-echo слушает {ADDR}:53, отвечает на {NAME}", flush=True)
    while True:
        data, peer = s.recvfrom(2048)
        if len(data) < 12:
            continue
        name, end = read_qname(data, 12)
        if end + 4 > len(data):
            continue
        qtype, _qclass = struct.unpack("!HH", data[end:end + 4])
        question = data[12:end + 4]
        answer = b""
        if qtype == 1 and name == NAME:
            answer = (
                b"\xc0\x0c"
                + struct.pack("!HHIH", 1, 1, 60, 4)
                + socket.inet_aton(ADDR)
            )
        header = data[0:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1 if answer else 0, 0, 0)
        s.sendto(header + question + answer, peer)


if __name__ == "__main__":
    main()
