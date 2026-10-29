#!/usr/bin/env python3
"""Эхо-сервер стенда нагрузки.

TCP на 203.0.113.1:9998 с большим backlog (стенд открывает сотни соединений
одновременно), UDP на 203.0.113.1:9999. Отвечает теми же байтами.
"""
import socket
import threading

HOST = "203.0.113.1"
TCP_PORT = 9998
UDP_PORT = 9999
BACKLOG = 1024


def tcp() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, TCP_PORT))
    s.listen(BACKLOG)
    print(f"tcp listening {HOST}:{TCP_PORT} backlog={BACKLOG}", flush=True)
    while True:
        conn, _ = s.accept()

        def handle(c=conn):
            with c:
                while True:
                    data = c.recv(65536)
                    if not data:
                        break
                    c.sendall(data)

        threading.Thread(target=handle, daemon=True).start()


def udp() -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((HOST, UDP_PORT))
    print(f"udp listening {HOST}:{UDP_PORT}", flush=True)
    while True:
        data, addr = s.recvfrom(65535)
        s.sendto(data, addr)


if __name__ == "__main__":
    threading.Thread(target=udp, daemon=True).start()
    tcp()
