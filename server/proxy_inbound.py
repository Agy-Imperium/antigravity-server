"""
proxy_inbound.py - Authenticated SOCKS5 and HTTP CONNECT Inbound Proxy Servers (Facade)
Re-exports from antigravity_unlocker.server.proxy_service for backward compatibility.
"""

import sys
from pathlib import Path

_src_dir = Path(__file__).resolve().parent.parent / "src"
if _src_dir.exists() and str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))

from antigravity_unlocker.server.proxy_service import *

if __name__ == "__main__":
    import argparse
    import asyncio
    import logging

    parser = argparse.ArgumentParser(description="Proxy Inbound Standalone Server")
    parser.add_argument("--socks-port", type=int, default=SOCKS5_PORT, help="SOCKS5 port")
    parser.add_argument("--http-port", type=int, default=HTTP_CONNECT_PORT, help="HTTP CONNECT port")
    parser.add_argument("--auth-token", default=AUTH_TOKEN, help="Optional auth token")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    lvl = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=lvl, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    server = ProxyInboundServer(
        socks5_port=args.socks_port,
        http_port=args.http_port,
        auth_token=args.auth_token,
    )
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        pass
