"""
forwarder.py - Zero-Privilege Selective Routing Engine & Local Loopback Proxy.
Implements Feature F9 (Zero-Admin Selective Routing Engine).
Pure Python Standard Library (zero external dependencies).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import signal
import socket
import struct
import sys
from typing import Optional, Set, Tuple

from antigravity_unlocker.client.routing.rules import is_intercepted_domain
from antigravity_unlocker.common.discovery import get_client_target_server

logger = logging.getLogger("local_forwarder")

DEFAULT_SERVER_HOST = get_client_target_server()
DEFAULT_SOCKS_PORT = int(os.getenv("ANTIGRAVITY_SOCKS_PORT", "18444"))
DEFAULT_HTTP_PORT = int(os.getenv("ANTIGRAVITY_HTTP_PORT", "18443"))
DEFAULT_SNI_PORT = int(os.getenv("ANTIGRAVITY_SNI_PORT", "443"))
DEFAULT_BUFFER_SIZE = 65536


def find_available_port(preferred: int, max_trials: int = 50) -> int:
    """Finds next available free port on 127.0.0.1 if preferred is occupied."""
    for port in range(preferred, preferred + max_trials):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    return preferred


async def bidirectional_relay(
    client_r: asyncio.StreamReader,
    client_w: asyncio.StreamWriter,
    remote_r: asyncio.StreamReader,
    remote_w: asyncio.StreamWriter,
    buffer_size: int = DEFAULT_BUFFER_SIZE,
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


class LocalSelectiveForwarder:
    """Dual-protocol (SOCKS5 + HTTP CONNECT) loopback forwarder with selective routing."""

    def __init__(
        self,
        server_host: str = DEFAULT_SERVER_HOST,
        socks_port: int = DEFAULT_SOCKS_PORT,
        http_port: int = DEFAULT_HTTP_PORT,
        sni_port: int = DEFAULT_SNI_PORT,
        upstream_socks_port: int = DEFAULT_SOCKS_PORT,
        upstream_http_port: int = DEFAULT_HTTP_PORT,
        listen_ip: str = "127.0.0.1",
        auth_token: Optional[str] = None,
    ) -> None:
        self.server_host = server_host
        self.socks_port = socks_port
        self.http_port = http_port
        self.sni_port = sni_port
        self.upstream_socks_port = upstream_socks_port
        self.upstream_http_port = upstream_http_port
        self.listen_ip = listen_ip
        self.auth_token = auth_token

        self.socks_server: Optional[asyncio.Server] = None
        self.http_server: Optional[asyncio.Server] = None
        self._active_tasks: Set[asyncio.Task] = set()

    async def handle_http_connect(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handles incoming HTTP CONNECT requests on loopback port."""
        task = asyncio.current_task()
        if task:
            self._active_tasks.add(task)
        remote_w: Optional[asyncio.StreamWriter] = None
        remote_r: Optional[asyncio.StreamReader] = None
        try:
            req_buf = b""
            while b"\r\n\r\n" not in req_buf and b"\n\n" not in req_buf:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=10.0)
                if not chunk:
                    break
                req_buf += chunk
                if len(req_buf) > 65536:
                    writer.write(b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    return

            if not req_buf:
                return

            delimiter = b"\r\n\r\n" if b"\r\n\r\n" in req_buf else b"\n\n"
            delim_pos = req_buf.find(delimiter)
            header_bytes = req_buf[:delim_pos]
            early_data = req_buf[delim_pos + len(delimiter):]

            header_text = header_bytes.decode("latin1", errors="replace")
            lines = header_text.splitlines()
            if not lines:
                return

            req_line = lines[0].strip()
            parts = req_line.split()
            if len(parts) < 2 or parts[0].upper() != "CONNECT":
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
                await writer.drain()
                return

            target = parts[1]
            if target.startswith("[") and "]:" in target:
                h_part, p_part = target.split("]:", 1)
                host = h_part[1:]
                try:
                    port = int(p_part)
                except ValueError:
                    port = 443
            elif ":" in target and not target.startswith("["):
                host, port_str = target.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 443
            else:
                host, port = target, 443

            use_tunnel = is_intercepted_domain(host)
            route_mode = "tunnel" if use_tunnel else "direct"
            logger.debug(f"[HTTP] Target {host}:{port} -> {route_mode} route")

            if use_tunnel:
                if port == 443:
                    # For HTTPS traffic to intercepted domains (Google AI), connect directly
                    # to the remote VPS TLS SNI proxy (port 443).
                    try:
                        remote_r, remote_w = await asyncio.wait_for(
                            asyncio.open_connection(self.server_host, self.sni_port),
                            timeout=10.0,
                        )
                    except Exception as e:
                        logger.warning(f"[HTTP] Upstream SNI proxy connect failed for {host}:{port}: {e}")
                        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                        await writer.drain()
                        return
                else:
                    # Non-443 fallback via upstream HTTP CONNECT proxy
                    try:
                        remote_r, remote_w = await asyncio.wait_for(
                            asyncio.open_connection(self.server_host, self.upstream_http_port),
                            timeout=10.0,
                        )
                    except Exception as e:
                        logger.warning(f"[HTTP] Upstream VPS connect failed for {host}:{port}: {e}")
                        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                        await writer.drain()
                        return

                    conn_lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
                    if self.auth_token:
                        b64_tok = base64.b64encode(f":{self.auth_token}".encode()).decode()
                        conn_lines.append(f"Proxy-Authorization: Basic {b64_tok}")
                    conn_lines.extend(["\r\n", ""])
                    remote_w.write("\r\n".join(conn_lines).encode())
                    await remote_w.drain()

                    vps_resp = b""
                    while b"\r\n\r\n" not in vps_resp and b"\n\n" not in vps_resp:
                        v_chunk = await asyncio.wait_for(remote_r.read(4096), timeout=10.0)
                        if not v_chunk:
                            break
                        vps_resp += v_chunk
                    if b" 200 " not in vps_resp:
                        writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                        await writer.drain()
                        remote_w.close()
                        return
            else:
                # Direct route for non-target domains / IP literals
                try:
                    remote_r, remote_w = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=10.0,
                    )
                except asyncio.TimeoutError:
                    writer.write(b"HTTP/1.1 504 Gateway Timeout\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    return
                except Exception as e:
                    logger.debug(f"[HTTP] Direct connection failed to {host}:{port}: {e}")
                    writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    await writer.drain()
                    return

            # Acknowledge connection established to client
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            if early_data and remote_w:
                remote_w.write(early_data)
                await remote_w.drain()

            await bidirectional_relay(reader, writer, remote_r, remote_w)

        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.debug(f"[HTTP] Exception handling client connection: {e}")
        finally:
            if task:
                self._active_tasks.discard(task)
            for w in (writer, remote_w):
                if w:
                    try:
                        if not w.is_closing():
                            w.close()
                            await w.wait_closed()
                    except Exception:
                        pass

    async def handle_socks5(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handles incoming SOCKS5 requests on loopback port."""
        task = asyncio.current_task()
        if task:
            self._active_tasks.add(task)
        remote_w: Optional[asyncio.StreamWriter] = None
        remote_r: Optional[asyncio.StreamReader] = None
        try:
            # 1. Greeting negotiation (RFC 1928)
            head = await asyncio.wait_for(reader.read(2), timeout=10.0)
            if len(head) < 2 or head[0] != 0x05:
                return
            nmethods = head[1]
            methods = await asyncio.wait_for(reader.read(nmethods), timeout=10.0)
            writer.write(b"\x05\x00")  # NO AUTHENTICATION REQUIRED on local loopback
            await writer.drain()

            # 2. Request phase (RFC 1928)
            req_head = await asyncio.wait_for(reader.read(4), timeout=10.0)
            if len(req_head) < 4 or req_head[0] != 0x05:
                return
            cmd, atyp = req_head[1], req_head[3]
            if cmd != 0x01:  # Only CONNECT is supported
                writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            if atyp == 1:  # IPv4
                addr_bytes = await asyncio.wait_for(reader.read(4), timeout=10.0)
                dst_addr = socket.inet_ntoa(addr_bytes)
            elif atyp == 3:  # Domain
                dlen_byte = await asyncio.wait_for(reader.read(1), timeout=10.0)
                if not dlen_byte:
                    return
                dlen = dlen_byte[0]
                domain_bytes = await asyncio.wait_for(reader.read(dlen), timeout=10.0)
                dst_addr = domain_bytes.decode("utf-8", errors="replace")
            elif atyp == 4:  # IPv6
                addr_bytes = await asyncio.wait_for(reader.read(16), timeout=10.0)
                dst_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            else:
                writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            port_bytes = await asyncio.wait_for(reader.read(2), timeout=10.0)
            dst_port = struct.unpack("!H", port_bytes)[0]

            use_tunnel = is_intercepted_domain(dst_addr)
            route_mode = "tunnel" if use_tunnel else "direct"
            logger.debug(f"[SOCKS5] Target {dst_addr}:{dst_port} -> {route_mode} route")

            if use_tunnel:
                if dst_port == 443:
                    # For HTTPS traffic to intercepted domains (Google AI), connect directly
                    # to the remote VPS TLS SNI proxy (port 443).
                    try:
                        remote_r, remote_w = await asyncio.wait_for(
                            asyncio.open_connection(self.server_host, self.sni_port),
                            timeout=10.0,
                        )
                    except Exception as e:
                        logger.warning(f"[SOCKS5] Upstream SNI proxy connect failed for {dst_addr}:{dst_port}: {e}")
                        writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                        await writer.drain()
                        return
                else:
                    # Route through remote VPS SOCKS5 proxy
                    try:
                        remote_r, remote_w = await asyncio.wait_for(
                            asyncio.open_connection(self.server_host, self.upstream_socks_port),
                            timeout=10.0,
                        )
                    except Exception as e:
                        logger.warning(f"[SOCKS5] Upstream VPS connect failed for {dst_addr}:{dst_port}: {e}")
                        writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                        await writer.drain()
                        return

                    # Negotiate greeting with remote VPS
                    if self.auth_token:
                        remote_w.write(b"\x05\x01\x02")  # Username/password
                        await remote_w.drain()
                        m_resp = await asyncio.wait_for(remote_r.read(2), timeout=10.0)
                        if len(m_resp) < 2 or m_resp[1] != 0x02:
                            writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                            await writer.drain()
                            remote_w.close()
                            return
                        tok_bytes = self.auth_token.encode("utf-8")
                        auth_pkt = b"\x01\x00" + bytes([len(tok_bytes)]) + tok_bytes
                        remote_w.write(auth_pkt)
                        await remote_w.drain()
                        a_resp = await asyncio.wait_for(remote_r.read(2), timeout=10.0)
                        if len(a_resp) < 2 or a_resp[1] != 0x00:
                            writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                            await writer.drain()
                            remote_w.close()
                            return
                    else:
                        remote_w.write(b"\x05\x01\x00")  # NO AUTH
                        await remote_w.drain()
                        m_resp = await asyncio.wait_for(remote_r.read(2), timeout=10.0)
                        if len(m_resp) < 2 or m_resp[1] != 0x00:
                            writer.write(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
                            await writer.drain()
                            remote_w.close()
                            return

                    # Send CONNECT request to VPS
                    d_bytes = dst_addr.encode("utf-8")
                    conn_pkt = (
                        b"\x05\x01\x00\x03"
                        + bytes([len(d_bytes)])
                        + d_bytes
                        + struct.pack("!H", dst_port)
                    )
                    remote_w.write(conn_pkt)
                    await remote_w.drain()

                    c_resp = await asyncio.wait_for(remote_r.read(4), timeout=10.0)
                    if len(c_resp) < 4 or c_resp[1] != 0x00:
                        writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                        await writer.drain()
                        remote_w.close()
                        return

                    resp_atyp = c_resp[3]
                    if resp_atyp == 1:
                        await remote_r.read(4 + 2)
                    elif resp_atyp == 3:
                        r_len = (await remote_r.read(1))[0]
                        await remote_r.read(r_len + 2)
                    elif resp_atyp == 4:
                        await remote_r.read(16 + 2)
            else:
                # Direct route for non-target destination / IP literals
                try:
                    remote_r, remote_w = await asyncio.wait_for(
                        asyncio.open_connection(dst_addr, dst_port),
                        timeout=10.0,
                    )
                except asyncio.TimeoutError:
                    writer.write(b"\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00")
                    await writer.drain()
                    return
                except Exception as e:
                    logger.debug(f"[SOCKS5] Direct connection failed to {dst_addr}:{dst_port}: {e}")
                    writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
                    await writer.drain()
                    return

            # Respond success to client
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", dst_port))
            await writer.drain()

            await bidirectional_relay(reader, writer, remote_r, remote_w)

        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.debug(f"[SOCKS5] Exception handling client connection: {e}")
        finally:
            if task:
                self._active_tasks.discard(task)
            for w in (writer, remote_w):
                if w:
                    try:
                        if not w.is_closing():
                            w.close()
                            await w.wait_closed()
                    except Exception:
                        pass

    async def start(self) -> None:
        """Starts loopback listeners on SOCKS5 and HTTP CONNECT with collision avoidance."""
        self.socks_port = find_available_port(self.socks_port)
        self.http_port = find_available_port(self.http_port)

        self.socks_server = await asyncio.start_server(
            self.handle_socks5, self.listen_ip, self.socks_port, reuse_address=True
        )
        self.http_server = await asyncio.start_server(
            self.handle_http_connect, self.listen_ip, self.http_port, reuse_address=True
        )
        logger.info(f"Local SOCKS5 proxy listening on {self.listen_ip}:{self.socks_port}")
        logger.info(f"Local HTTP CONNECT proxy listening on {self.listen_ip}:{self.http_port}")
        logger.info(f"Selective routing target VPS: {self.server_host}")

        # Persist active ports for client tools and wrappers
        try:
            p_file = os.path.expanduser("~/.antigravity_ports.json")
            with open(p_file, "w") as f:
                json.dump({"http_port": self.http_port, "socks_port": self.socks_port, "pid": os.getpid()}, f)
        except Exception:
            pass

    async def stop(self) -> None:
        """Gracefully shuts down servers and terminates active connections."""
        if self.socks_server:
            self.socks_server.close()
            await self.socks_server.wait_closed()
            self.socks_server = None
        if self.http_server:
            self.http_server.close()
            await self.http_server.wait_closed()
            self.http_server = None
        for t in list(self._active_tasks):
            t.cancel()
        if self._active_tasks:
            await asyncio.gather(*self._active_tasks, return_exceptions=True)
            self._active_tasks.clear()

        try:
            p_file = os.path.expanduser("~/.antigravity_ports.json")
            if os.path.exists(p_file):
                os.remove(p_file)
        except Exception:
            pass

        logger.info("Forwarder stopped cleanly.")

    async def serve_forever(self) -> None:
        """Runs the loopback servers indefinitely."""
        await self.start()
        if self.socks_server and self.http_server:
            await asyncio.gather(
                self.socks_server.serve_forever(),
                self.http_server.serve_forever(),
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Antigravity Zero-Privilege Local Forwarder & Selective Router",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-s", "--server",
        default=DEFAULT_SERVER_HOST,
        help="Frankfurt VPS upstream IP or hostname",
    )
    parser.add_argument(
        "--socks-port",
        type=int,
        default=DEFAULT_SOCKS_PORT,
        help="Local loopback SOCKS5 listening port",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=DEFAULT_HTTP_PORT,
        help="Local loopback HTTP CONNECT listening port",
    )
    parser.add_argument(
        "--sni-port",
        type=int,
        default=DEFAULT_SNI_PORT,
        help="Upstream VPS TLS SNI proxy port (default: 443)",
    )
    parser.add_argument(
        "--upstream-socks-port",
        type=int,
        default=int(os.getenv("ANTIGRAVITY_UPSTREAM_SOCKS", "48328")),
        help="Upstream VPS SOCKS5 port (default: 48328)",
    )
    parser.add_argument(
        "--upstream-http-port",
        type=int,
        default=int(os.getenv("ANTIGRAVITY_UPSTREAM_HTTP", "48329")),
        help="Upstream VPS HTTP CONNECT port (default: 48329)",
    )
    parser.add_argument(
        "--listen-ip", "--bind",
        dest="listen_ip",
        default="127.0.0.1",
        help="Local loopback binding interface IP",
    )
    parser.add_argument(
        "-a", "--auth-token",
        default=None,
        help="Optional upstream VPS proxy authentication token",
    )
    parser.add_argument(
        "-c", "--check",
        action="store_true",
        help="Dry run: verify loopback socket binding and upstream VPS reachability",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity level",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    lvl = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(level=lvl, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    if args.check:
        logger.info(f"Performing check: probing upstream VPS SNI proxy {args.server}:{args.sni_port}...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((args.server, args.sni_port))
            logger.info("Check PASSED: Upstream VPS reachable.")
            s.close()
            return 0
        except Exception as e:
            logger.warning(f"Check FAILED: Unable to reach VPS: {e}")
            return 1

    forwarder = LocalSelectiveForwarder(
        server_host=args.server,
        socks_port=args.socks_port,
        http_port=args.http_port,
        sni_port=args.sni_port,
        upstream_socks_port=args.upstream_socks_port,
        upstream_http_port=args.upstream_http_port,
        listen_ip=args.listen_ip,
        auth_token=args.auth_token,
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    stop_event = asyncio.Event()

    def signal_handler() -> None:
        logger.info("Termination signal received. Shutting down...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, signal_handler)
        except (NotImplementedError, RuntimeError):
            pass

    async def run() -> None:
        await forwarder.start()
        await stop_event.wait()
        await forwarder.stop()

    try:
        loop.run_until_complete(run())
    except KeyboardInterrupt:
        loop.run_until_complete(forwarder.stop())
    finally:
        loop.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
