"""
proxy_service.py - Authenticated SOCKS5 and HTTP CONNECT Inbound Proxy Servers.
Implements Feature F5 (Authenticated Remote Proxy Inbound).
Pure Python Standard Library (zero external dependencies).
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import logging
import socket
import struct
import ipaddress
from typing import List, Optional, Set, Tuple

from antigravity_unlocker.common.config import (
    AUTH_TOKEN,
    HTTP_CONNECT_HOST,
    HTTP_CONNECT_PORT,
    SOCKS5_HOST,
    SOCKS5_PORT,
    is_allowed_sni,
    is_intercepted_domain,
)
from antigravity_unlocker.common.protocols.http_connect import parse_http_connect_request as _proto_parse_http
from antigravity_unlocker.common.protocols.socks5 import (
    parse_socks5_auth,
    parse_socks5_greeting,
    parse_socks5_request,
)
from antigravity_unlocker.server.base import BaseServerService, ServiceStatus

logger = logging.getLogger("proxy_service")


def is_restricted_ssrf_destination(host: str) -> bool:
    """Blocks connections to local, private, multicast, unspecified, and cloud metadata addresses."""
    norm = host.lower().strip().rstrip(".")
    if norm in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "::", "metadata", "metadata.google.internal"):
        return True
    if norm.startswith("[") and norm.endswith("]"):
        norm = norm[1:-1]
    try:
        ip = ipaddress.ip_address(norm)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
            or str(ip).startswith("169.254.")
        )
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(norm, None, proto=socket.IPPROTO_TCP)
        for _, _, _, _, sockaddr in infos:
            ip_str = sockaddr[0]
            ip = ipaddress.ip_address(ip_str)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
                or str(ip).startswith("169.254.")
            ):
                return True
    except Exception:
        pass

    return False


def is_destination_allowed(host: str, is_authenticated: bool = False) -> bool:
    """
    Validates destination against SSRF and domain restrictions:
    - Never allow private / loopback / metadata IPs (SSRF mitigation).
    - If authenticated (valid token), allow all public internet destinations.
    - If anonymous (no token), strictly restrict to Google AI domains.
    """
    if is_restricted_ssrf_destination(host):
        return False
    if is_authenticated:
        return True
    return is_allowed_sni(host) or is_intercepted_domain(host)


def verify_token(provided: Optional[str], expected: Optional[str]) -> bool:
    """Timing-safe token authentication verification."""
    if not expected:
        return True
    if not provided:
        return False
    if hmac.compare_digest(provided, expected):
        return True
    if ":" in provided:
        u, p = provided.split(":", 1)
        if hmac.compare_digest(p, expected) or hmac.compare_digest(u, expected):
            return True
    return False


def parse_http_connect_request(
    raw_header: bytes,
) -> Tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
    """
    Parse HTTP CONNECT request headers.
    Returns (host, port, auth_credential, error_message).
    """
    lines = raw_header.split(b"\r\n")
    if not lines or not lines[0]:
        return None, None, None, "Empty request"

    req_line = lines[0].decode("latin1", errors="replace").strip()
    parts = req_line.split()
    if len(parts) < 2:
        return None, None, None, "Malformed request line"

    method, target = parts[0], parts[1]
    if method.upper() != "CONNECT":
        return None, None, None, f"Method not allowed: {method}"

    if target.startswith("["):
        if "]:" in target:
            h_part, p_part = target.split("]:", 1)
            host = h_part[1:]
            try:
                port = int(p_part)
            except ValueError:
                return None, None, None, "Invalid port"
        elif target.endswith("]"):
            host = target[1:-1]
            port = 443
        else:
            return None, None, None, "Malformed IPv6 literal"
    elif ":" in target:
        host, port_str = target.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            return None, None, None, "Invalid port"
    else:
        host = target
        port = 443

    auth_cred = None
    for line in lines[1:]:
        if line.lower().startswith(b"proxy-authorization:"):
            val = line.split(b":", 1)[1].strip()
            if val.lower().startswith(b"basic "):
                b64 = val.split(b" ", 1)[1].strip()
                try:
                    auth_cred = base64.b64decode(b64).decode("utf-8", errors="replace")
                except Exception:
                    pass

    return host, port, auth_cred, None


async def bidirectional_relay(
    client_r: asyncio.StreamReader,
    client_w: asyncio.StreamWriter,
    remote_r: asyncio.StreamReader,
    remote_w: asyncio.StreamWriter,
    buffer_size: int = 65536,
) -> Tuple[int, int]:
    """Relays data bidirectionally between client and remote sockets until closure."""
    up_bytes = 0
    down_bytes = 0

    async def pipe(r: asyncio.StreamReader, w: asyncio.StreamWriter, is_up: bool) -> None:
        nonlocal up_bytes, down_bytes
        try:
            while True:
                chunk = await r.read(buffer_size)
                if not chunk:
                    try:
                        if hasattr(w, "can_write_eof") and w.can_write_eof():
                            w.write_eof()
                    except Exception:
                        pass
                    break
                if is_up:
                    up_bytes += len(chunk)
                else:
                    down_bytes += len(chunk)
                w.write(chunk)
                await w.drain()
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            pass

    t1 = asyncio.create_task(pipe(client_r, remote_w, True))
    t2 = asyncio.create_task(pipe(remote_r, client_w, False))

    done, pending = await asyncio.wait([t1, t2], return_when=asyncio.FIRST_COMPLETED)

    if t1 in done and t2 in pending:
        try:
            await asyncio.wait_for(t2, timeout=90.0)
        except Exception:
            pass
    elif t2 in done and t1 in pending:
        try:
            await asyncio.wait_for(t1, timeout=5.0)
        except Exception:
            pass

    for p in (t1, t2):
        if not p.done():
            p.cancel()
    await asyncio.gather(t1, t2, return_exceptions=True)

    for w in (client_w, remote_w):
        try:
            if not w.is_closing():
                w.close()
                await w.wait_closed()
        except Exception:
            pass

    return up_bytes, down_bytes


class ProxyInboundConfig:
    """Configuration dataclass for ProxyInboundServer."""

    def __init__(
        self,
        socks5_host: str = SOCKS5_HOST,
        socks5_port: int = SOCKS5_PORT,
        http_host: str = HTTP_CONNECT_HOST,
        http_port: int = HTTP_CONNECT_PORT,
        auth_token: Optional[str] = AUTH_TOKEN,
        connect_timeout: float = 10.0,
        buffer_size: int = 65536,
    ) -> None:
        self.socks5_host = socks5_host
        self.socks5_port = socks5_port
        self.http_host = http_host
        self.http_port = http_port
        self.auth_token = auth_token
        self.connect_timeout = connect_timeout
        self.buffer_size = buffer_size


class ProxyInboundServer(BaseServerService):
    """Manages SOCKS5 (port 48328) and HTTP CONNECT (port 48329) inbound proxy services."""

    def __init__(
        self,
        socks5_host: str = SOCKS5_HOST,
        socks5_port: int = SOCKS5_PORT,
        http_host: str = HTTP_CONNECT_HOST,
        http_port: int = HTTP_CONNECT_PORT,
        auth_token: Optional[str] = AUTH_TOKEN,
        connect_timeout: float = 10.0,
        buffer_size: int = 65536,
        config: Optional[ProxyInboundConfig] = None,
    ) -> None:
        if config:
            self.socks5_host = config.socks5_host
            self.socks5_port = config.socks5_port
            self.http_host = config.http_host
            self.http_port = config.http_port
            self.auth_token = config.auth_token
            self.connect_timeout = config.connect_timeout
            self.buffer_size = config.buffer_size
        else:
            self.socks5_host = socks5_host
            self.socks5_port = socks5_port
            self.http_host = http_host
            self.http_port = http_port
            self.auth_token = auth_token
            self.connect_timeout = connect_timeout
            self.buffer_size = buffer_size

        self.socks5_server: Optional[asyncio.Server] = None
        self.http_server: Optional[asyncio.Server] = None
        self._active_connections: Set[asyncio.Task] = set()
        self._running = False

    @property
    def name(self) -> str:
        return "Proxy Inbound Server"

    def get_status(self) -> ServiceStatus:
        listen_str = f"SOCKS5={self.socks5_host}:{self.socks5_port}, HTTP={self.http_host}:{self.http_port}"
        auth_status = "Token Auth Enabled" if self.auth_token else "Anonymous Access"
        return ServiceStatus(
            name=self.name,
            is_running=self._running,
            listen_addresses=listen_str,
            details=auth_status,
        )

    async def handle_socks5(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        client_addr = writer.get_extra_info("peername")
        task = asyncio.current_task()
        if task:
            self._active_connections.add(task)
        try:
            header = await asyncio.wait_for(reader.readexactly(2), timeout=self.connect_timeout)
            ver, nmethods = header[0], header[1]
            if ver != 5:
                writer.close()
                await writer.wait_closed()
                return

            methods = await asyncio.wait_for(
                reader.readexactly(nmethods), timeout=self.connect_timeout
            )
            if self.auth_token:
                if 2 not in methods:
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
                writer.write(b"\x05\x02")
                await writer.drain()

                sub_ver = (await asyncio.wait_for(reader.readexactly(1), timeout=self.connect_timeout))[0]
                if sub_ver != 1:
                    writer.close()
                    await writer.wait_closed()
                    return
                ulen = (await reader.readexactly(1))[0]
                uname = (await reader.readexactly(ulen)).decode("utf-8", errors="replace")
                plen = (await reader.readexactly(1))[0]
                passwd = (await reader.readexactly(plen)).decode("utf-8", errors="replace")

                cred = f"{uname}:{passwd}"
                if verify_token(passwd, self.auth_token) or verify_token(cred, self.auth_token):
                    writer.write(b"\x01\x00")
                    await writer.drain()
                else:
                    logger.warning(f"[SOCKS5] Auth failure from {client_addr} (user: {uname})")
                    writer.write(b"\x01\x01")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
            else:
                if 0 not in methods:
                    writer.write(b"\x05\xff")
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return
                writer.write(b"\x05\x00")
                await writer.drain()

            req_hdr = await asyncio.wait_for(reader.readexactly(4), timeout=self.connect_timeout)
            ver, cmd, rsv, atyp = req_hdr[0], req_hdr[1], req_hdr[2], req_hdr[3]
            if ver != 5:
                writer.close()
                await writer.wait_closed()
                return

            if cmd != 1:  # Only CONNECT supported
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if atyp == 1:
                dst_addr = socket.inet_ntoa(await reader.readexactly(4))
            elif atyp == 3:
                dlen = (await reader.readexactly(1))[0]
                raw_domain = await reader.readexactly(dlen)
                try:
                    dst_addr = raw_domain.decode("idna")
                except Exception:
                    dst_addr = raw_domain.decode("utf-8", errors="replace")
            elif atyp == 4:
                dst_addr = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            dst_port = struct.unpack("!H", await reader.readexactly(2))[0]
            is_auth = bool(self.auth_token)
            if not is_destination_allowed(dst_addr, is_auth):
                logger.warning(
                    f"[SOCKS5] Denied unauthorized/SSRF target {dst_addr}:{dst_port} from {client_addr}"
                )
                writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            logger.debug(f"[SOCKS5] Connecting {dst_addr}:{dst_port} for client {client_addr}")

            try:
                remote_r, remote_w = await asyncio.wait_for(
                    asyncio.open_connection(dst_addr, dst_port),
                    timeout=self.connect_timeout,
                )
            except Exception as e:
                logger.debug(f"[SOCKS5] Connect to {dst_addr}:{dst_port} failed: {e}")
                writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()

            up_b, down_b = await bidirectional_relay(
                reader, writer, remote_r, remote_w, self.buffer_size
            )
            logger.debug(f"[SOCKS5] Closed tunnel {dst_addr}:{dst_port} (up={up_b}B, down={down_b}B)")

        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except Exception as e:
            logger.debug(f"[SOCKS5] Error from {client_addr}: {e}")
        finally:
            if task:
                self._active_connections.discard(task)
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass

    async def handle_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        client_addr = writer.get_extra_info("peername")
        task = asyncio.current_task()
        if task:
            self._active_connections.add(task)
        try:
            req_buf = b""
            while b"\r\n\r\n" not in req_buf and b"\n\n" not in req_buf:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=self.connect_timeout)
                if not chunk:
                    break
                req_buf += chunk
                if len(req_buf) > 65536:
                    writer.write(
                        b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"
                    )
                    await writer.drain()
                    writer.close()
                    await writer.wait_closed()
                    return

            if not req_buf:
                writer.close()
                await writer.wait_closed()
                return

            host, port, auth_cred, err = parse_http_connect_request(req_buf)
            if err:
                logger.debug(f"[HTTP] Bad request from {client_addr}: {err}")
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            if self.auth_token and not verify_token(auth_cred, self.auth_token):
                logger.warning(f"[HTTP] Auth required/failed from {client_addr}")
                writer.write(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                    b'Proxy-Authenticate: Basic realm="Antigravity Unlocker"\r\n'
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            is_auth = bool(self.auth_token and auth_cred and verify_token(auth_cred, self.auth_token))
            if not is_destination_allowed(host, is_auth):
                logger.warning(
                    f"[HTTP] Denied unauthorized/SSRF target {host}:{port} from {client_addr}"
                )
                writer.write(
                    b"HTTP/1.1 403 Forbidden\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Connection: close\r\n\r\n"
                    b"Target destination is not permitted by unlocker security policy.\r\n"
                )
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            logger.debug(f"[HTTP] Dialing {host}:{port} for client {client_addr}")
            try:
                remote_r, remote_w = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.connect_timeout,
                )
            except asyncio.TimeoutError:
                writer.write(
                    b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return
            except Exception as e:
                logger.debug(f"[HTTP] Connect to {host}:{port} failed: {e}")
                writer.write(
                    b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            up_b, down_b = await bidirectional_relay(
                reader, writer, remote_r, remote_w, self.buffer_size
            )
            logger.debug(f"[HTTP] Closed tunnel {host}:{port} (up={up_b}B, down={down_b}B)")

        except (asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except Exception as e:
            logger.debug(f"[HTTP] Error from {client_addr}: {e}")
        finally:
            if task:
                self._active_connections.discard(task)
            try:
                if not writer.is_closing():
                    writer.close()
                    await writer.wait_closed()
            except Exception:
                pass

    async def start(self) -> None:
        self.socks5_server = await asyncio.start_server(
            self.handle_socks5, self.socks5_host, self.socks5_port, reuse_address=True
        )
        self.http_server = await asyncio.start_server(
            self.handle_http, self.http_host, self.http_port, reuse_address=True
        )
        self._running = True
        logger.info(f"SOCKS5 Proxy listening on {self.socks5_host}:{self.socks5_port}")
        logger.info(f"HTTP CONNECT Proxy listening on {self.http_host}:{self.http_port}")

    async def stop(self) -> None:
        self._running = False
        if self.socks5_server:
            self.socks5_server.close()
            await self.socks5_server.wait_closed()
            self.socks5_server = None
        if self.http_server:
            self.http_server.close()
            await self.http_server.wait_closed()
            self.http_server = None

        for task in list(self._active_connections):
            task.cancel()
        if self._active_connections:
            await asyncio.gather(*self._active_connections, return_exceptions=True)
            self._active_connections.clear()
        logger.info("Proxy inbound services stopped cleanly.")

    async def close(self) -> None:
        await self.stop()

    async def serve_forever(self) -> None:
        await self.start()
        try:
            await asyncio.gather(
                self.socks5_server.serve_forever(),
                self.http_server.serve_forever(),
            )
        except asyncio.CancelledError:
            await self.stop()


# Alias for backward-compatibility
ProxyInbound = ProxyInboundServer
