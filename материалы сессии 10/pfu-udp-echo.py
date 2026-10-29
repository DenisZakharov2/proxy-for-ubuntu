import socket

# Внутри серверного netns адрес 198.51.100.1 принадлежит ему.
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("198.51.100.1", 9999))
print("echo listening on 198.51.100.1:9999", flush=True)
while True:
    data, addr = s.recvfrom(4096)
    print("got", data, "from", addr, flush=True)
    s.sendto(b"pong:" + data, addr)
