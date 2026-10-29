#!/usr/bin/env python3
"""Мини-DNS для стенда: A-запись на заданное имя.

    dns-echo.py <адрес> <порт> <адрес-в-ответе> [имя|-]

`-` вместо имени — отвечать на любое имя. Пустой ответ (NOERROR, 0 записей)
на остальные имена: стенд не должен зависеть от интернета.
"""
import socket
import struct
import sys

bind_ip, bind_port, answer_ip = sys.argv[1], int(sys.argv[2]), sys.argv[3]
only_name = None if len(sys.argv) < 5 or sys.argv[4] == "-" else sys.argv[4].lower()


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
    s.bind((bind_ip, bind_port))
    print(f"dns-echo {bind_ip}:{bind_port} -> {answer_ip} (имя: {only_name or '*'})", flush=True)
    while True:
        data, peer = s.recvfrom(2048)
        if len(data) < 12:
            continue
        name, end = read_qname(data, 12)
        if end + 4 > len(data):
            continue
        qtype, _qclass = struct.unpack("!HH", data[end:end + 4])
        print(f"query {name} type={qtype} from {peer[0]}:{peer[1]}", flush=True)
        question = data[12:end + 4]
        answer = b""
        if qtype == 1 and (only_name is None or name == only_name):
            answer = (
                b"\xc0\x0c"
                + struct.pack("!HHIH", 1, 1, 60, 4)
                + socket.inet_aton(answer_ip)
            )
        header = data[0:2] + b"\x81\x80" + struct.pack("!HHHH", 1, 1 if answer else 0, 0, 0)
        s.sendto(header + question + answer, peer)


if __name__ == "__main__":
    main()
