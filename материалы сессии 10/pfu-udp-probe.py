import socket
import time

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("10.200.0.2", 40000))
s.settimeout(1.5)
got = 0
for i in range(5):
    s.sendto(b"ping-%d" % i, ("198.51.100.1", 9999))
    try:
        data, addr = s.recvfrom(4096)
        got += 1
        print("reply", data, "from", addr)
    except socket.timeout:
        print("timeout on", i)
    time.sleep(0.2)
print("replies:", got, "of 5")
