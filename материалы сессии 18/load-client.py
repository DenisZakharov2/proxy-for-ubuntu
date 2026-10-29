#!/usr/bin/env python3
"""Клиент стенда нагрузки: гоняет трафик через TUN и считает результат.

Запускается НЕ от root: в цепочках демона есть `meta skuid 0 return`, и
root-трафик прошёл бы мимо перехвата (ложный успех).

    setpriv --reuid 1000 --regid 1000 --keep-groups \
        python3 load-client.py tcp-burst --conns 200 --payload 8192

Режимы:
  tcp-burst   N одновременных соединений: echo, закрытие; латентности;
  tcp-hold    N соединений держатся открытыми S секунд, затем повторный echo
              в каждое — так видно, пережили ли они reload/пересоздание;
  udp-burst   N сокетов по M датаграмм.
"""
import argparse
import socket
import sys
import threading
import time

HOST = "203.0.113.1"
TCP_PORT = 9998
UDP_PORT = 9999


def percentile(values, q):
    if not values:
        return 0.0
    values = sorted(values)
    k = min(len(values) - 1, int(round((len(values) - 1) * q)))
    return values[k]


def tcp_roundtrip(payload: bytes, timeout: float, hold: float = 0.0):
    """Один echo-раунд. Возвращает (ok, ms, ошибка)."""
    started = time.monotonic()
    try:
        with socket.create_connection((HOST, TCP_PORT), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(payload)
            got = 0
            while got < len(payload):
                chunk = s.recv(len(payload) - got)
                if not chunk:
                    raise RuntimeError("сервер закрыл соединение")
                got += len(chunk)
            if hold:
                time.sleep(hold)
            return True, (time.monotonic() - started) * 1000, ""
    except Exception as exc:  # noqa: BLE001 — нужен текст любой ошибки
        return False, (time.monotonic() - started) * 1000, repr(exc)


def cmd_tcp_burst(args) -> int:
    payload = b"x" * args.payload
    results = []
    lock = threading.Lock()

    def worker():
        r = tcp_roundtrip(payload, args.timeout)
        with lock:
            results.append(r)

    started = time.monotonic()
    threads = [threading.Thread(target=worker) for _ in range(args.conns)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - started
    ok = [r for r in results if r[0]]
    lat = [r[1] for r in ok]
    errors = {}
    for r in results:
        if not r[0]:
            errors[r[2]] = errors.get(r[2], 0) + 1
    print(
        f"tcp-burst conns={args.conns} payload={args.payload} "
        f"ok={len(ok)} fail={len(results) - len(ok)} "
        f"elapsed={elapsed:.2f}s p50={percentile(lat, 0.5):.0f}ms "
        f"p95={percentile(lat, 0.95):.0f}ms max={max(lat) if lat else 0:.0f}ms"
    )
    for err, count in sorted(errors.items(), key=lambda kv: -kv[1])[:5]:
        print(f"  fail x{count}: {err}")
    return 0 if len(ok) == args.conns else 1


def echo_all(socks, payload):
    """Один echo-раунд по всем открытым сокетам; возвращает число живых."""
    alive = 0
    for s in socks:
        try:
            s.sendall(payload)
            got = 0
            while got < len(payload):
                chunk = s.recv(len(payload) - got)
                if not chunk:
                    raise RuntimeError("EOF")
                got += len(chunk)
            alive += 1
        except Exception:  # noqa: BLE001
            pass
    return alive


def cmd_tcp_hold(args) -> int:
    """Открывает соединения, сообщает READY, держит, потом проверяет их."""
    payload = b"y" * args.payload
    socks = []
    for _ in range(args.conns):
        try:
            s = socket.create_connection((HOST, TCP_PORT), timeout=args.timeout)
            s.settimeout(args.timeout)
            s.sendall(payload)
            got = 0
            while got < len(payload):
                chunk = s.recv(len(payload) - got)
                if not chunk:
                    raise RuntimeError("сервер закрыл соединение")
                got += len(chunk)
            socks.append(s)
        except Exception as exc:  # noqa: BLE001
            print(f"  open fail: {exc!r}", file=sys.stderr)
    print(f"HOLD open={len(socks)}/{args.conns} seconds={args.seconds}", flush=True)
    if args.echo_every > 0:
        deadline = time.monotonic() + args.seconds
        rounds = 0
        while time.monotonic() < deadline:
            time.sleep(min(args.echo_every, max(0.0, deadline - time.monotonic())))
            alive = echo_all(socks, payload)
            rounds += 1
            print(f"PING round={rounds} alive={alive}/{len(socks)}", flush=True)
    else:
        time.sleep(args.seconds)
    alive = echo_all(socks, payload)
    for s in socks:
        try:
            s.close()
        except OSError:
            pass
    print(f"HOLD after={alive}/{len(socks)} alive")
    return 0 if alive == len(socks) == args.conns else 1


def cmd_udp_burst(args) -> int:
    payload = b"u" * args.payload
    results = []
    lock = threading.Lock()

    def worker():
        ok = 0
        err = ""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(args.timeout)
            for _ in range(args.datagrams):
                s.sendto(payload, (HOST, UDP_PORT))
                data, _ = s.recvfrom(65535)
                if data == payload:
                    ok += 1
            s.close()
        except Exception as exc:  # noqa: BLE001
            err = repr(exc)
        with lock:
            results.append((ok, err))

    started = time.monotonic()
    threads = [threading.Thread(target=worker) for _ in range(args.sockets)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - started
    total_ok = sum(r[0] for r in results)
    wanted = args.sockets * args.datagrams
    errors = {}
    for _, err in results:
        if err:
            errors[err] = errors.get(err, 0) + 1
    print(
        f"udp-burst sockets={args.sockets} each={args.datagrams} "
        f"ok={total_ok}/{wanted} elapsed={elapsed:.2f}s"
    )
    for err, count in sorted(errors.items(), key=lambda kv: -kv[1])[:5]:
        print(f"  fail x{count}: {err}")
    return 0 if total_ok == wanted else 1


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    p = sub.add_parser("tcp-burst")
    p.add_argument("--conns", type=int, default=200)
    p.add_argument("--payload", type=int, default=8192)
    p.add_argument("--timeout", type=float, default=15.0)
    p.set_defaults(func=cmd_tcp_burst)

    p = sub.add_parser("tcp-hold")
    p.add_argument("--conns", type=int, default=50)
    p.add_argument("--payload", type=int, default=1024)
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--seconds", type=float, default=30.0)
    p.add_argument("--echo-every", type=float, default=0.0,
                   help="слать echo по всем соединениям каждые N секунд")
    p.set_defaults(func=cmd_tcp_hold)

    p = sub.add_parser("udp-burst")
    p.add_argument("--sockets", type=int, default=100)
    p.add_argument("--datagrams", type=int, default=20)
    p.add_argument("--payload", type=int, default=512)
    p.add_argument("--timeout", type=float, default=5.0)
    p.set_defaults(func=cmd_udp_burst)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
