"""
dns_service.py - High-Performance Pure Python DNS Router & Record Synthesizer.
Implements Feature F1 (DNS UDP/TCP Router) and Feature F2 (DNS Record Synthesis).
Pure Python Standard Library (zero external dependencies).
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
from typing import List, Optional, Set, Tuple, Union

from antigravity_unlocker.common.config import (
    DNS_LISTEN_HOSTS,
    DNS_PORT,
    DNS_TTL,
    EXACT_INTERCEPT_DOMAINS,
    INTERCEPT_SUFFIXES,
    UPSTREAM_RESOLVERS,
    UPSTREAM_TIMEOUT,
    VPS_PUBLIC_IP,
    DnsConfig,
    is_intercepted_domain,
)
from antigravity_unlocker.common.protocols.dns import (
    QTYPE_A,
    QTYPE_AAAA,
    QTYPE_HTTPS,
    QTYPE_SVCB,
    RCODE_FORMERR,
    RCODE_NOERROR,
    RCODE_NXDOMAIN,
    RCODE_SERVFAIL,
)
from antigravity_unlocker.server.base import BaseServerService, ServiceStatus

logger = logging.getLogger("dns_service")


class DNSRouter:
    """Core DNS wire-format parser, synthesizer, and upstream forwarder."""

    def __init__(
        self,
        intercept_ip: str = VPS_PUBLIC_IP,
        upstream_servers: Tuple[str, ...] = UPSTREAM_RESOLVERS,
        timeout: float = UPSTREAM_TIMEOUT,
        ttl: int = DNS_TTL,
        allowed_suffixes: Tuple[str, ...] = INTERCEPT_SUFFIXES,
        exact_domains: Set[str] = EXACT_INTERCEPT_DOMAINS,
    ) -> None:
        self.intercept_ip = intercept_ip
        self.upstream_servers = upstream_servers
        self.timeout = timeout
        self.ttl = ttl
        self.allowed_suffixes = allowed_suffixes
        try:
            self._intercept_ip_bytes = socket.inet_aton(self.intercept_ip)
        except (OSError, ValueError):
            self._intercept_ip_bytes = b"\x00\x00\x00\x00"

    def parse_query(self, data: bytes) -> Tuple[int, int, str, int, int, bytes]:
        """
        Parses an RFC 1035 DNS query packet.
        Returns: (txid, flags, qname, qtype, qclass, raw_question)
        Raises ValueError if packet is malformed.
        """
        if len(data) < 12:
            raise ValueError(f"Packet too short for DNS header ({len(data)} bytes)")

        txid, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", data[:12])
        if (flags & 0x8000) != 0:
            raise ValueError("Packet has QR=1 (response, not a query)")
        if qdcount == 0:
            raise ValueError("Query has QDCOUNT=0")

        labels: List[str] = []
        curr = 12
        jumped = False
        next_question_offset = -1
        jumps = 0
        max_jumps = 10

        while True:
            if curr >= len(data):
                raise ValueError("Packet truncated during QNAME traversal")

            length = data[curr]
            if length == 0:
                curr += 1
                if not jumped:
                    next_question_offset = curr
                break
            elif (length & 0xC0) == 0xC0:
                if curr + 1 >= len(data):
                    raise ValueError("Packet truncated in compression pointer")
                if not jumped:
                    next_question_offset = curr + 2
                    jumped = True
                curr = ((length & 0x3F) << 8) | data[curr + 1]
                jumps += 1
                if jumps > max_jumps:
                    raise ValueError("Compression pointer loop detected")
            elif 0 < length <= 63:
                curr += 1
                if curr + length > len(data):
                    raise ValueError("Packet truncated in label bytes")
                label_bytes = data[curr : curr + length]
                labels.append(label_bytes.decode("latin1", errors="replace"))
                curr += length
                if not jumped:
                    next_question_offset = curr
            else:
                raise ValueError(f"Invalid label length byte: {length}")

        if next_question_offset + 4 > len(data):
            raise ValueError("Packet truncated before QTYPE/QCLASS")

        qtype, qclass = struct.unpack("!HH", data[next_question_offset : next_question_offset + 4])
        qname = ".".join(labels).lower() if labels else "."
        raw_question = data[12 : next_question_offset + 4]

        return txid, flags, qname, qtype, qclass, raw_question

    def is_intercepted(self, qname: str) -> bool:
        """Checks if domain should be intercepted and resolved to VPS."""
        if not qname or qname == ".":
            return False
        d = qname.rstrip(".").lower()
        if d in self.exact_domains:
            return True
        for suffix in self.allowed_suffixes:
            norm_s = suffix.lower().strip().lstrip(".")
            if d == norm_s or d.endswith("." + norm_s):
                return True
        return False

    def build_a_response(self, txid: int, query_flags: int, raw_question: bytes) -> bytes:
        """Synthesizes Authoritative Type A answer pointing to VPS IP."""
        resp_flags = 0x8580 | (query_flags & 0x0100)  # QR=1, AA=1, RA=1, NOERROR, preserve RD
        header = struct.pack("!HHHHHH", txid, resp_flags, 1, 1, 0, 0)
        answer = b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_A, 1, self.ttl, 4) + self._intercept_ip_bytes
        return header + raw_question + answer

    def build_nodata_response(self, txid: int, query_flags: int, raw_question: bytes) -> bytes:
        """Synthesizes NOERROR response with ANCOUNT=0 (NODATA) for IPv6/ECH suppression."""
        resp_flags = 0x8580 | (query_flags & 0x0100)  # QR=1, AA=1, RA=1, NOERROR, preserve RD
        header = struct.pack("!HHHHHH", txid, resp_flags, 1, 0, 0, 0)
        return header + raw_question

    def build_servfail_response(self, data: bytes) -> bytes:
        """Synthesizes SERVFAIL (RCODE=2) response."""
        if len(data) < 2:
            return b""
        txid = data[:2]
        flags = 0x8182  # QR=1, RA=1, SERVFAIL
        if len(data) >= 12:
            return txid + struct.pack("!HHHHH", flags, 1, 0, 0, 0) + data[12:]
        return txid + struct.pack("!HHHHH", flags, 0, 0, 0, 0)

    def build_formerr_response(self, data: bytes) -> bytes:
        """Synthesizes FORMERR (RCODE=1) response on malformed input."""
        if len(data) < 2:
            return b""
        txid = data[:2]
        flags = 0x8001  # QR=1, FORMERR
        return txid + struct.pack("!HHHHH", flags, 0, 0, 0, 0)

    async def forward_query_udp(self, query_data: bytes) -> Optional[bytes]:
        """Asynchronously proxies query to upstream recursive resolvers over UDP."""
        loop = asyncio.get_running_loop()
        for server in self.upstream_servers:
            try:
                addrinfo = socket.getaddrinfo(server, 53, type=socket.SOCK_DGRAM)
                af = addrinfo[0][0] if addrinfo else socket.AF_INET
            except Exception:
                af = socket.AF_INET
            sock = socket.socket(af, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_sendto(sock, query_data, (server, 53))
                resp, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout=self.timeout)
                return resp
            except Exception as e:
                logger.debug(f"Upstream UDP query to {server} failed: {e}")
                continue
            finally:
                sock.close()
        return None

    async def forward_query_tcp(self, query_data: bytes) -> Optional[bytes]:
        """Asynchronously proxies query to upstream recursive resolvers over TCP."""
        for server in self.upstream_servers:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(server, 53), timeout=self.timeout
                )
                try:
                    wire = len(query_data).to_bytes(2, "big") + query_data
                    writer.write(wire)
                    await writer.drain()
                    prefix = await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
                    resp_len = int.from_bytes(prefix, "big")
                    return await asyncio.wait_for(reader.readexactly(resp_len), timeout=self.timeout)
                finally:
                    writer.close()
                    await writer.wait_closed()
            except Exception as e:
                logger.debug(f"Upstream TCP query to {server} failed: {e}")
                continue
        return None

    async def handle_query(self, query_data: bytes, is_tcp: bool = False) -> Optional[bytes]:
        """
        Main query router: parses query, checks domain interception, synthesizes answer or forwards upstream.
        """
        try:
            txid, flags, qname, qtype, qclass, raw_question = self.parse_query(query_data)
        except Exception as e:
            logger.debug(f"Malformed DNS query ({len(query_data)} bytes): {e}")
            return self.build_formerr_response(query_data)

        if self.is_intercepted(qname):
            if qtype == QTYPE_A:
                logger.debug(f"Intercepted A query for {qname} -> {self.intercept_ip}")
                return self.build_a_response(txid, flags, raw_question)
            elif qtype in (QTYPE_AAAA, QTYPE_SVCB, QTYPE_HTTPS):
                logger.debug(f"Suppressed QTYPE {qtype} query for {qname} -> NODATA")
                return self.build_nodata_response(txid, flags, raw_question)
            else:
                resp = await (self.forward_query_tcp(query_data) if is_tcp else self.forward_query_udp(query_data))
                return resp if resp else self.build_servfail_response(query_data)
        else:
            resp = await (self.forward_query_tcp(query_data) if is_tcp else self.forward_query_udp(query_data))
            return resp if resp else self.build_servfail_response(query_data)


class DNSDatagramProtocol(asyncio.DatagramProtocol):
    """Asynchronous UDP DNS protocol adapter with concurrency rate-limiting."""

    def __init__(self, router: DNSRouter, max_concurrent: int = 500) -> None:
        self.router = router
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        if self.semaphore.locked():
            logger.warning(f"Dropping DNS UDP packet from {addr}: concurrency limit reached")
            return
        asyncio.create_task(self._process_datagram(data, addr))

    async def _process_datagram(self, data: bytes, addr: Tuple[str, int]) -> None:
        async with self.semaphore:
            try:
                resp = await self.router.handle_query(data, is_tcp=False)
                if resp and self.transport and not self.transport.is_closing():
                    self.transport.sendto(resp, addr)
            except Exception as e:
                logger.debug(f"Error handling UDP datagram from {addr}: {e}")


class DNSServer(BaseServerService):
    """Manages multi-interface UDP datagram endpoints and TCP stream servers."""

    def __init__(
        self,
        router: Optional[DNSRouter] = None,
        hosts: Union[str, Tuple[str, ...], List[str]] = DNS_LISTEN_HOSTS,
        port: int = DNS_PORT,
    ) -> None:
        self.router = router or DNSRouter()
        if isinstance(hosts, str):
            if hosts in ("0.0.0.0", "", "auto"):
                pub = VPS_PUBLIC_IP
                self.hosts = (pub, "127.0.0.1") if pub != "127.0.0.1" else ("0.0.0.0", "127.0.0.1")
            elif hosts == VPS_PUBLIC_IP:
                self.hosts = (VPS_PUBLIC_IP, "127.0.0.1")
            else:
                self.hosts = (hosts,)
        else:
            self.hosts = tuple(hosts)
        self.port = port
        self.udp_transports: List[asyncio.DatagramTransport] = []
        self.tcp_servers: List[asyncio.Server] = []
        self._running = False

    @property
    def name(self) -> str:
        return "DNS Interceptor"

    def get_status(self) -> ServiceStatus:
        listen_str = ", ".join(f"{h}:{self.port}" for h in self.hosts)
        return ServiceStatus(
            name=self.name,
            is_running=self._running,
            listen_addresses=listen_str,
            details=f"Intercepting {len(self.router.allowed_suffixes)} domain suffixes to {self.router.intercept_ip}",
        )

    async def _handle_tcp_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        addr = writer.get_extra_info("peername")
        try:
            while True:
                try:
                    len_bytes = await asyncio.wait_for(reader.readexactly(2), timeout=10.0)
                except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                    break
                msg_len = int.from_bytes(len_bytes, "big")
                if msg_len == 0 or msg_len > 65535:
                    break
                try:
                    query_data = await asyncio.wait_for(reader.readexactly(msg_len), timeout=10.0)
                except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                    break
                resp = await self.router.handle_query(query_data, is_tcp=True)
                if resp:
                    writer.write(len(resp).to_bytes(2, "big") + resp)
                    await writer.drain()
        except Exception as e:
            logger.debug(f"TCP DNS client error ({addr}): {e}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self.udp_transports.clear()
        self.tcp_servers.clear()

        # Bind UDP datagram endpoints per host
        for host in self.hosts:
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: DNSDatagramProtocol(self.router), local_addr=(host, self.port)
                )
                self.udp_transports.append(transport)
                logger.info(f"DNS UDP listening on {host}:{self.port}")
            except OSError as e:
                logger.warning(f"Failed to bind DNS UDP on {host}:{self.port}: {e}")

        # Bind TCP stream server per host
        for host in self.hosts:
            try:
                server = await asyncio.start_server(
                    self._handle_tcp_client, host=host, port=self.port, reuse_address=True
                )
                self.tcp_servers.append(server)
                logger.info(f"DNS TCP listening on {host}:{self.port}")
            except OSError as e:
                logger.warning(f"Failed to bind DNS TCP on {host}:{self.port}: {e}")

        if not self.udp_transports and not self.tcp_servers:
            raise RuntimeError(f"Could not bind DNS engine on any hosts in {self.hosts}:{self.port}")

        self._running = True

    async def stop(self) -> None:
        self._running = False
        for t in self.udp_transports:
            try:
                t.close()
            except Exception:
                pass
        self.udp_transports.clear()

        for s in self.tcp_servers:
            try:
                s.close()
                await s.wait_closed()
            except Exception:
                pass
        self.tcp_servers.clear()
        logger.info("DNS Engine stopped.")


# Alias for backward compatibility
DnsEngine = DNSServer
