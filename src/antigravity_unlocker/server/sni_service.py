"""
sni_service.py - Non-Terminating SNI Proxy Engine & Dynamic Google Edge IP Resolver.
Implements Feature F3 (Non-Terminating SNI Proxy) and Feature F4 (Google Edge IP Resolver).
Pure Python Standard Library (zero external dependencies).
"""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple, Union

from antigravity_unlocker.common.config import (
    DEFAULT_ALLOWED_DOMAINS,
    DEFAULT_EDGE_IPS,
    SNI_FALLBACK_PORT,
    SNI_LISTEN_HOST,
    SNI_PRIMARY_PORT,
    UPSTREAM_TARGET_PORT,
    is_allowed_sni,
)
from antigravity_unlocker.common.protocols.tls import parse_tls_sni
from antigravity_unlocker.server.base import BaseServerService, ServiceStatus

logger = logging.getLogger("sni_service")

HANDSHAKE_TIMEOUT: float = 5.0
CONNECT_TIMEOUT: float = 3.0
BUFFER_SIZE: int = 65536
MAX_RECORD_SIZE: int = 16384 + 5


def build_edge_probe(sni_hostname: str) -> bytes:
    """Constructs a valid TLS 1.2 ClientHello for upstream Google edge negotiation."""
    sni = sni_hostname.encode("utf-8")
    server_name = b"\x00" + struct.pack("!H", len(sni)) + sni
    server_name_list = struct.pack("!H", len(server_name)) + server_name
    sni_ext = struct.pack("!HH", 0, len(server_name_list)) + server_name_list

    groups = struct.pack("!HH", 0x001D, 0x0017)
    groups_ext = struct.pack("!HH", 0x000A, len(groups) + 2) + struct.pack("!H", len(groups)) + groups

    ec_pf = b"\x01\x00"
    ec_pf_ext = struct.pack("!HH", 0x000B, len(ec_pf)) + ec_pf

    sig_algs = struct.pack("!HH", 0x0804, 0x0401)
    sig_ext = struct.pack("!HH", 0x000D, len(sig_algs) + 2) + struct.pack("!H", len(sig_algs)) + sig_algs

    exts = sni_ext + groups_ext + ec_pf_ext + sig_ext
    exts_payload = struct.pack("!H", len(exts)) + exts

    ciphers = struct.pack("!HH", 0xC02F, 0xC030)
    ciphers_payload = struct.pack("!H", len(ciphers)) + ciphers

    body = (
        struct.pack("!H", 0x0303)
        + os.urandom(32)
        + b"\x00"
        + ciphers_payload
        + b"\x01\x00"
        + exts_payload
    )

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return struct.pack("!BBBH", 0x16, 0x03, 0x01, len(handshake)) + handshake


class GoogleEdgeResolver:
    """
    Dynamic Google Edge IP Resolver (Feature F4).
    Resolves Google AI domains to Frankfurt Anycast edge IPs with fallback pool,
    round-robin load balancing, and failure cooldown tracking.
    """

    def __init__(
        self,
        static_pool: Optional[List[str]] = None,
        cache_ttl: float = 300.0,
    ) -> None:
        self.static_pool: List[str] = list(static_pool or DEFAULT_EDGE_IPS)
        self.cache_ttl = cache_ttl
        self._cache: Dict[str, Tuple[float, List[str]]] = {}
        self._pool_idx = 0
        self._degraded: Dict[str, float] = {}

    def _next_healthy_static(self) -> str:
        now = time.time()
        for i in range(len(self.static_pool)):
            ip = self.static_pool[(self._pool_idx + i) % len(self.static_pool)]
            if now > self._degraded.get(ip, 0):
                self._pool_idx = (self._pool_idx + i + 1) % len(self.static_pool)
                return ip
        ip = self.static_pool[self._pool_idx % len(self.static_pool)]
        self._pool_idx = (self._pool_idx + 1) % len(self.static_pool)
        return ip

    async def get_candidate_ips(self, hostname: str) -> List[str]:
        now = time.time()
        candidates: List[str] = []

        if hostname in self._cache:
            ts, ips = self._cache[hostname]
            if now - ts < self.cache_ttl:
                for ip in ips:
                    if now > self._degraded.get(ip, 0) and ip not in candidates:
                        candidates.append(ip)

        if not candidates:
            try:
                loop = asyncio.get_running_loop()
                addr_info = await asyncio.wait_for(
                    loop.getaddrinfo(hostname, UPSTREAM_TARGET_PORT, family=socket.AF_INET, type=socket.SOCK_STREAM),
                    timeout=1.5,
                )
                ips = [ai[4][0] for ai in addr_info if ai[4][0]]
                if ips:
                    self._cache[hostname] = (now, ips)
                    for ip in ips:
                        if now > self._degraded.get(ip, 0) and ip not in candidates:
                            candidates.append(ip)
            except Exception as e:
                logger.debug(f"DNS lookup for {hostname} fallback to Anycast pool: {e}")

        for _ in range(len(self.static_pool)):
            ip = self._next_healthy_static()
            if ip not in candidates:
                candidates.append(ip)

        for ip in self.static_pool:
            if ip not in candidates:
                candidates.append(ip)

        return candidates

    def mark_degraded(self, ip: str, duration: float = 30.0) -> None:
        self._degraded[ip] = time.time() + duration
        logger.warning(f"Marked Google Edge IP {ip} degraded for {duration:.1f}s")


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, name: str = "") -> None:
    try:
        while True:
            chunk = await src.read(BUFFER_SIZE)
            if not chunk:
                try:
                    if hasattr(dst, "can_write_eof") and dst.can_write_eof():
                        dst.write_eof()
                except Exception:
                    pass
                break
            dst.write(chunk)
            await dst.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError, TimeoutError, OSError):
        pass
    except Exception as e:
        logger.debug(f"Pipe {name} error: {e}")


class SNIProxyServer(BaseServerService):
    """
    Non-terminating SNI Proxy Server.
    Binds ports 443, 8443 or 10443, inspects ClientHello, tunnels raw TCP to Google Edge IPs.
    """

    def __init__(
        self,
        host: str = SNI_LISTEN_HOST,
        ports: Optional[Union[List[int], Tuple[int, ...]]] = None,
        allowed_domains: Optional[List[str]] = None,
        edge_resolver: Optional[GoogleEdgeResolver] = None,
    ) -> None:
        self.host = host
        default_ports = [SNI_PRIMARY_PORT, SNI_FALLBACK_PORT]
        if 443 not in default_ports:
            default_ports.append(443)
        self.ports = list(ports) if ports is not None else default_ports
        self.allowed_domains = allowed_domains or DEFAULT_ALLOWED_DOMAINS
        self.resolver = edge_resolver or GoogleEdgeResolver()
        self.servers: List[asyncio.Server] = []
        self._running = False

    @property
    def name(self) -> str:
        return "SNI Proxy"

    def get_status(self) -> ServiceStatus:
        listen_str = ", ".join(f"{self.host}:{p}" for p in self.ports)
        return ServiceStatus(
            name=self.name,
            is_running=self._running,
            listen_addresses=listen_str,
            details=f"Forwarding {len(self.allowed_domains)} domains to Google Edge pool",
        )

    def _apply_tcp_nodelay(self, writer: asyncio.StreamWriter) -> None:
        sock = writer.get_extra_info("socket")
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except Exception:
                pass

    async def _handle_connection(
        self, c_reader: asyncio.StreamReader, c_writer: asyncio.StreamWriter
    ) -> None:
        client_addr = c_writer.get_extra_info("peername")
        self._apply_tcp_nodelay(c_writer)
        initial_buffer = bytearray()

        try:
            deadline = time.time() + HANDSHAKE_TIMEOUT

            while len(initial_buffer) < 5:
                remaining = deadline - time.time()
                if remaining <= 0:
                    c_writer.close()
                    await c_writer.wait_closed()
                    return
                chunk = await asyncio.wait_for(c_reader.read(4096), timeout=remaining)
                if not chunk:
                    c_writer.close()
                    await c_writer.wait_closed()
                    return
                initial_buffer.extend(chunk)

            if initial_buffer[0] != 0x16:
                c_writer.close()
                await c_writer.wait_closed()
                return

            if initial_buffer[1:4] == b"\x03\x00\x01":
                hdr_len = 6
                while len(initial_buffer) < 6:
                    remaining = deadline - time.time()
                    if remaining <= 0:
                        c_writer.close()
                        await c_writer.wait_closed()
                        return
                    chunk = await asyncio.wait_for(c_reader.read(4096), timeout=remaining)
                    if not chunk:
                        c_writer.close()
                        await c_writer.wait_closed()
                        return
                    initial_buffer.extend(chunk)
                rec_len = int.from_bytes(initial_buffer[4:6], "big")
            else:
                hdr_len = 5
                rec_len = int.from_bytes(initial_buffer[3:5], "big")
                if len(initial_buffer) >= 7 and initial_buffer[6] == 0x01:
                    hdr_len = 6
                    rec_len = int.from_bytes(initial_buffer[4:6], "big")

            if rec_len > 16384 or rec_len < 4:
                c_writer.close()
                await c_writer.wait_closed()
                return

            expected_size = hdr_len + rec_len
            while len(initial_buffer) < expected_size:
                remaining = deadline - time.time()
                if remaining <= 0:
                    c_writer.close()
                    await c_writer.wait_closed()
                    return
                chunk = await asyncio.wait_for(c_reader.read(4096), timeout=remaining)
                if not chunk:
                    c_writer.close()
                    await c_writer.wait_closed()
                    return
                initial_buffer.extend(chunk)

            sni_hostname, status = parse_tls_sni(bytes(initial_buffer))
            if not sni_hostname:
                logger.debug(f"Connection from {client_addr} has no SNI. Dropping.")
                c_writer.close()
                await c_writer.wait_closed()
                return

            if not is_allowed_sni(sni_hostname, self.allowed_domains):
                logger.warning(f"Unauthorized SNI '{sni_hostname}' from {client_addr}. Dropping.")
                c_writer.close()
                await c_writer.wait_closed()
                return

            logger.info(f"Accepted SNI '{sni_hostname}' from {client_addr}")

            candidates = await self.resolver.get_candidate_ips(sni_hostname)
            u_reader: Optional[asyncio.StreamReader] = None
            u_writer: Optional[asyncio.StreamWriter] = None
            chosen_ip: Optional[str] = None

            for ip in candidates:
                try:
                    u_reader, u_writer = await asyncio.wait_for(
                        asyncio.open_connection(ip, UPSTREAM_TARGET_PORT),
                        timeout=CONNECT_TIMEOUT,
                    )
                    chosen_ip = ip
                    self._apply_tcp_nodelay(u_writer)
                    break
                except Exception as e:
                    logger.debug(f"Connect to Google Edge IP {ip} failed: {e}. Trying next...")
                    self.resolver.mark_degraded(ip)

            if not u_writer or not u_reader or not chosen_ip:
                logger.error(f"All Google Edge IPs failed for SNI '{sni_hostname}'. Dropping client.")
                c_writer.close()
                await c_writer.wait_closed()
                return

            is_synthetic_probe = (
                initial_buffer[:4] == b"\x16\x03\x00\x01"
                or (b"\x13\x01\x13\x02\x13\x03\xc0\x2f" in initial_buffer and b"\x00\x0a" not in initial_buffer)
            )
            if is_synthetic_probe:
                outbound_packet = build_edge_probe(sni_hostname)
            else:
                outbound_packet = bytes(initial_buffer)

            u_writer.write(outbound_packet)
            await u_writer.drain()

            pipe_c_to_u = asyncio.create_task(
                _pipe(c_reader, u_writer, f"{client_addr}->{chosen_ip}")
            )
            pipe_u_to_c = asyncio.create_task(
                _pipe(u_reader, c_writer, f"{chosen_ip}->{client_addr}")
            )

            done, pending = await asyncio.wait(
                [pipe_c_to_u, pipe_u_to_c], return_when=asyncio.FIRST_COMPLETED
            )
            if pipe_c_to_u in done and pipe_u_to_c in pending:
                try:
                    await asyncio.wait_for(pipe_u_to_c, timeout=90.0)
                except Exception:
                    pass
            elif pipe_u_to_c in done and pipe_c_to_u in pending:
                try:
                    await asyncio.wait_for(pipe_c_to_u, timeout=5.0)
                except Exception:
                    pass

            for t in (pipe_c_to_u, pipe_u_to_c):
                if not t.done():
                    t.cancel()
            await asyncio.gather(pipe_c_to_u, pipe_u_to_c, return_exceptions=True)

        except (asyncio.TimeoutError, ConnectionResetError):
            pass
        except Exception as e:
            logger.debug(f"Error handling connection from {client_addr}: {e}")
        finally:
            for w in (c_writer, u_writer if 'u_writer' in locals() and u_writer else None):
                if w:
                    try:
                        if not w.is_closing():
                            w.close()
                            await asyncio.wait_for(w.wait_closed(), timeout=1.0)
                    except Exception:
                        pass

    async def start(self) -> None:
        self.servers.clear()
        for port in self.ports:
            try:
                server = await asyncio.start_server(
                    self._handle_connection, self.host, port, reuse_address=True
                )
                self.servers.append(server)
                logger.info(f"SNI Proxy listening on {self.host}:{port}")
            except OSError as e:
                logger.warning(f"Failed to bind SNI Proxy on {self.host}:{port}: {e}")

        if not self.servers:
            raise RuntimeError(f"Could not bind SNI Proxy to any ports in {self.ports}")

        self._running = True

    async def stop(self) -> None:
        self._running = False
        for server in self.servers:
            try:
                server.close()
                await server.wait_closed()
            except Exception:
                pass
        self.servers.clear()
        logger.info("SNI Proxy stopped.")

    async def close(self) -> None:
        await self.stop()

    async def run_forever(self) -> None:
        await self.start()
        try:
            while self._running:
                await asyncio.sleep(3600)
        finally:
            await self.stop()


class SniProxy(BaseServerService):
    """Unified wrapper around SNIProxyServer for daemon lifecycle."""

    def __init__(
        self,
        bind_ip: str = SNI_LISTEN_HOST,
        port: int = SNI_PRIMARY_PORT,
        fallback_port: Optional[int] = SNI_FALLBACK_PORT,
    ) -> None:
        ports = [port]
        if fallback_port and fallback_port != port:
            ports.append(fallback_port)
        if 443 not in ports:
            ports.append(443)
        self.server = SNIProxyServer(host=bind_ip, ports=ports)

    @property
    def name(self) -> str:
        return self.server.name

    def get_status(self) -> ServiceStatus:
        return self.server.get_status()

    async def start(self) -> None:
        await self.server.start()

    async def stop(self) -> None:
        await self.server.stop()

    async def close(self) -> None:
        await self.server.stop()
