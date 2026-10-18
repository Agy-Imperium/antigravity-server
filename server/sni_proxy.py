"""
sni_proxy.py - Non-Terminating SNI Proxy Engine & Dynamic Google Edge IP Resolver (Facade)
Re-exports from antigravity_unlocker.server.sni_service for backward compatibility.
"""

import sys
from pathlib import Path

_src_dir = Path(__file__).resolve().parent.parent / "src"
if _src_dir.exists() and str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))

from antigravity_unlocker.server.sni_service import *

if __name__ == "__main__":
    import argparse
    import asyncio
    import logging

    parser = argparse.ArgumentParser(description="SNI Proxy Standalone Server")
    parser.add_argument("--host", default=SNI_LISTEN_HOST, help="Bind IP")
    parser.add_argument("--port", type=int, default=SNI_PRIMARY_PORT, help="Primary port (443)")
    parser.add_argument("--fallback-port", type=int, default=SNI_FALLBACK_PORT, help="Fallback port (8443)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()

    lvl = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=lvl, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    proxy = SniProxy(bind_ip=args.host, port=args.port, fallback_port=args.fallback_port)
    try:
        asyncio.run(proxy.server.run_forever())
    except KeyboardInterrupt:
        pass
