#!/usr/bin/env python3
"""Эхо-сервер стенда TUN: TCP и UDP на адресе, которого нет на клиентской
машине (203.0.113.1 живёт в отдельной netns). Возвращает данные как есть."""
import socket
import threading

HOST = "203.0.113.1"


def tcp() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, 9998))
    s.listen(8)
    print("tcp listening", flush=True)
    while True:
        conn, _ = s.accept()

        def handle(c=conn):
            with c:
                while True:
                    data = c.recv(4096)
                    if not data:
                        break
                    c.sendall(data)

        threading.Thread(target=handle, daemon=True).start()


def udp() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, 9999))
    print("udp listening", flush=True)
    while True:
        data, addr = s.recvfrom(65535)
        s.sendto(data, addr)


if __name__ == "__main__":
    threading.Thread(target=udp, daemon=True).start()
    tcp()
