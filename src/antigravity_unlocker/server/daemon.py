"""
daemon.py - Master Unified Server Daemon Orchestrator.
Part of the Antigravity & agy-cli Zero-Privilege Bypass System.
Implements Feature F6 (Managed Systemd Service Daemon).
Pure Python Standard Library (zero external dependencies).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import sys
from typing import List, Optional

from antigravity_unlocker.common.config import (
    AUTH_TOKEN,
    DNS_PORT,
    HTTP_CONNECT_PORT,
    LOG_LEVEL,
    SNI_FALLBACK_PORT,
    SNI_LISTEN_HOST,
    SNI_PRIMARY_PORT,
    SOCKS5_PORT,
    VPS_PUBLIC_IP,
    ServerConfig,
)
from antigravity_unlocker.common.logging import setup_logging
from antigravity_unlocker.server.dns_service import DNSRouter, DNSServer, DnsEngine
from antigravity_unlocker.server.proxy_service import ProxyInboundServer
from antigravity_unlocker.server.sni_service import SniProxy

logger = logging.getLogger("unlocker_daemon")


def parse_cli_args() -> argparse.Namespace:
    """Parses command-line arguments with environment variable fallbacks."""
    parser = argparse.ArgumentParser(
        description="Antigravity Zero-Privilege Unlocker Daemon",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dns-ip",
        default=os.getenv("UNLOCKER_DNS_IP", VPS_PUBLIC_IP),
        help="IP address to bind DNS interceptor",
    )
    parser.add_argument(
        "--dns-port",
        type=int,
        default=int(os.getenv("UNLOCKER_DNS_PORT", str(DNS_PORT))),
        help="DNS port (UDP/TCP)",
    )
    parser.add_argument(
        "--sni-ip",
        default=os.getenv("UNLOCKER_SNI_IP", SNI_LISTEN_HOST),
        help="IP address to bind SNI proxy",
    )
    parser.add_argument(
        "--sni-port",
        type=int,
        default=int(os.getenv("UNLOCKER_SNI_PORT", str(SNI_PRIMARY_PORT))),
        help="SNI Proxy primary port",
    )
    parser.add_argument(
        "--sni-fallback-port",
        type=int,
        default=int(os.getenv("UNLOCKER_SNI_FALLBACK_PORT", str(SNI_FALLBACK_PORT))),
        help="SNI Proxy fallback port",
    )
    parser.add_argument(
        "--socks5-port",
        type=int,
        default=int(os.getenv("UNLOCKER_SOCKS5_PORT", str(SOCKS5_PORT))),
        help="SOCKS5 inbound proxy port",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=int(os.getenv("UNLOCKER_HTTP_PORT", str(HTTP_CONNECT_PORT))),
        help="HTTP CONNECT inbound proxy port",
    )
    parser.add_argument(
        "--auth-token",
        default=os.getenv("UNLOCKER_AUTH_TOKEN", AUTH_TOKEN),
        help="Optional authentication token for SOCKS5 and HTTP CONNECT",
    )
    parser.add_argument(
        "--log-level",
        default=os.getenv("UNLOCKER_LOG_LEVEL", LOG_LEVEL),
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity level",
    )
    return parser.parse_args()


class UnlockerDaemon:
    """Master orchestrator daemon for DNS Interceptor, SNI Proxy, and Inbound Proxies."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.stop_event = asyncio.Event()

        # Inbound Forwarders (SOCKS5 + HTTP CONNECT)
        self.proxy_inbound = ProxyInboundServer(
            socks5_host="0.0.0.0",
            socks5_port=args.socks5_port,
            http_host="0.0.0.0",
            http_port=args.http_port,
            auth_token=args.auth_token,
        )

        # SNI Proxy Engine (Ports 443 & 8443 or custom)
        self.sni_proxy = SniProxy(
            bind_ip=args.sni_ip,
            port=args.sni_port,
            fallback_port=args.sni_fallback_port,
        )

        # DNS Interceptor Engine (UDP & TCP Port 53)
        dns_bind: List[str] = []
        if args.dns_ip in ("0.0.0.0", "", "auto"):
            pub_ip = VPS_PUBLIC_IP
            dns_bind = [pub_ip, "127.0.0.1"] if pub_ip != "127.0.0.1" else ["0.0.0.0", "127.0.0.1"]
        elif args.dns_ip == VPS_PUBLIC_IP:
            dns_bind = [VPS_PUBLIC_IP, "127.0.0.1"]
        else:
            dns_bind = [args.dns_ip]

        router = DNSRouter(intercept_ip=VPS_PUBLIC_IP)
        self.dns_engine = DNSServer(
            router=router,
            hosts=dns_bind,
            port=args.dns_port,
        )

    async def start(self) -> None:
        """Initializes and starts all unlocker subsystems."""
        logger.info("==================================================")
        logger.info(" Starting Antigravity Zero-Privilege Unlocker Daemon ")
        logger.info("==================================================")

        # 1. Start Inbound Forwarders
        try:
            await self.proxy_inbound.start()
            auth_status = "ENABLED" if self.args.auth_token else "DISABLED (Open Mode)"
            logger.info(
                f"[*] Inbound Forwarders: SOCKS5={self.args.socks5_port}, "
                f"HTTP={self.args.http_port} [Auth: {auth_status}]"
            )
        except Exception as e:
            logger.critical(f"Failed to start Inbound Forwarders: {e}")
            raise

        # 2. Start SNI Proxy
        try:
            await self.sni_proxy.start()
            logger.info(
                f"[*] SNI Proxy Engine: Ports {self.args.sni_port}, {self.args.sni_fallback_port}"
            )
        except Exception as e:
            logger.critical(f"Failed to start SNI Proxy Engine: {e}")
            await self.proxy_inbound.stop()
            raise

        # 3. Start DNS Interceptor
        try:
            await self.dns_engine.start()
            logger.info(
                f"[*] DNS Interceptor Engine: {self.args.dns_ip}:{self.args.dns_port} (UDP/TCP)"
            )
        except Exception as e:
            logger.critical(f"Failed to start DNS Interceptor Engine: {e}")
            await self.sni_proxy.stop()
            await self.proxy_inbound.stop()
            raise

        logger.info("[+] All unlocker subsystems operational.")

    async def stop(self) -> None:
        """Gracefully drains connections and shuts down all subsystems."""
        logger.info("Commencing graceful shutdown of unlocker subsystems...")
        try:
            if self.dns_engine:
                await self.dns_engine.stop()
        except Exception as e:
            logger.warning(f"Error stopping DNS Engine: {e}")

        try:
            if self.sni_proxy:
                await self.sni_proxy.stop()
        except Exception as e:
            logger.warning(f"Error stopping SNI Proxy: {e}")

        try:
            if self.proxy_inbound:
                await self.proxy_inbound.stop()
        except Exception as e:
            logger.warning(f"Error stopping Inbound Forwarders: {e}")

        logger.info("All unlocker subsystems stopped.")

    async def run(self) -> None:
        """Main lifecycle runner with POSIX signal handlers."""
        loop = asyncio.get_running_loop()

        def signal_handler(sig_name: str) -> None:
            logger.info(f"Caught signal {sig_name}; initiating graceful shutdown.")
            self.stop_event.set()

        for s in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(s, signal_handler, s.name)
            except NotImplementedError:
                pass

        await self.start()
        await self.stop_event.wait()
        await self.stop()


def main() -> None:
    """Daemon process entry point."""
    args = parse_cli_args()
    setup_logging(args.log_level, "unlocker_daemon", include_timestamp=True)
    daemon = UnlockerDaemon(args)
    try:
        asyncio.run(daemon.run())
        sys.exit(0)
    except (KeyboardInterrupt, SystemExit):
        sys.exit(0)
    except Exception as e:
        logger.critical(f"Unlocker Daemon failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
