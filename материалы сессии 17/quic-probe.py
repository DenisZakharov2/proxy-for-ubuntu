#!/usr/bin/env python3
"""QUIC-проба: завершает QUIC-рукопожатие (ALPN h3) с публичным сервером.

Нужна, чтобы проверить, что UDP 443 проходит через перехват: curl на этой
машине собран без HTTP/3, поэтому обычным `curl --http3` QUIC не проверить.

    ~/.hermes/cache/scratch/quic-venv/bin/python "материалы сессии 17/quic-probe.py" \
        cloudflare-quic.com 443
"""
import asyncio
import ssl
import sys

from aioquic.asyncio.client import connect
from aioquic.quic.configuration import QuicConfiguration


async def probe(host: str, port: int) -> int:
    cfg = QuicConfiguration(is_client=True, alpn_protocols=["h3"])
    cfg.server_name = host
    cfg.verify_mode = ssl.CERT_NONE
    try:
        async with connect(host, port, configuration=cfg, wait_connected=True):
            print(f"quic handshake ok: {host}:{port}")
            return 0
    except Exception as exc:  # noqa: BLE001 — проба, нужен любой текст ошибки
        print(f"quic handshake failed: {host}:{port}: {exc!r}")
        return 1


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "cloudflare-quic.com"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443
    raise SystemExit(asyncio.run(probe(host, port)))
