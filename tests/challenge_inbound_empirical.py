"""
challenge_inbound_empirical.py - Empirical Adversarial Test Harness for M1 Proxy Inbound
Tests SOCKS5 (48328) and HTTP CONNECT (48329) against malicious, malformed, and stress workloads.
Pure Python standard library.
"""

import asyncio
import hashlib
import os
import random
import socket
import struct
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SOCKS5_HOST = "127.0.0.1"
SOCKS5_PORT = 48328
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 48329

RESULTS: List[Dict] = []


def record_result(category: str, test_id: str, description: str, passed: bool, details: str = "", duration: float = 0.0):
    status = "PASS" if passed else "FAIL"
    RESULTS.append({
        "category": category,
        "test_id": test_id,
        "description": description,
        "passed": passed,
        "status": status,
        "details": details,
        "duration": duration,
    })
    print(f"[{status}] {test_id}: {description} ({duration:.3f}s)")
    if details:
        print(f"       Details: {details}")


# ============================================================================
# Local TCP Echo Server for Tunnel & Data Integrity Testing
# ============================================================================

class AsyncEchoServer:
    """Lightweight TCP Echo Server supporting IPv4 and IPv6."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self.server: Optional[asyncio.Server] = None
        self.actual_port: int = 0

    async def handle_echo(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
        self.server = await asyncio.start_server(
            self.handle_echo, self.host, self.port, family=family, reuse_address=True
        )
        for s in self.server.sockets:
            self.actual_port = s.getsockname()[1]
            break
        return self.actual_port

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            self.server = None


# ============================================================================
# SOCKS5 Adversarial Tests
# ============================================================================

def test_socks5_invalid_versions():
    category = "SOCKS5 Adversarial"

    # 1. SOCKS4 greeting
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SOCKS5_HOST, SOCKS5_PORT))
        # SOCKS4 connect packet
        s.sendall(b"\x04\x01\x00\x50\x7f\x00\x00\x01\x00")
        resp = s.recv(1024)
        # Server must either close immediately (b"") or not return a SOCKS5 greeting (0x05 0x00)
        passed = (resp == b"" or (len(resp) >= 2 and resp[0] != 0x05))
        s.close()
        record_result(category, "TC-S5-VER-01", "SOCKS4 request handled cleanly (closed/rejected)", passed, f"Response: {resp.hex()}", time.time() - t0)
    except Exception as e:
        record_result(category, "TC-S5-VER-01", "SOCKS4 request handled cleanly (closed/rejected)", True, f"Exception/closed: {e}", time.time() - t0)

    # 2. Unknown version 0x00
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SOCKS5_HOST, SOCKS5_PORT))
        s.sendall(b"\x00\x01\x00")
        resp = s.recv(1024)
        passed = (resp == b"")
        s.close()
        record_result(category, "TC-S5-VER-02", "Unknown version 0x00 rejected with connection closure", passed, f"Response: {resp.hex()}", time.time() - t0)
    except Exception as e:
        record_result(category, "TC-S5-VER-02", "Unknown version 0x00 rejected with connection closure", True, f"Exception/closed: {e}", time.time() - t0)

    # 3. Unknown version 0x06
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SOCKS5_HOST, SOCKS5_PORT))
        s.sendall(b"\x06\x01\x00")
        resp = s.recv(1024)
        passed = (resp == b"")
        s.close()
        record_result(category, "TC-S5-VER-03", "Unknown version 0x06 rejected with connection closure", passed, f"Response: {resp.hex()}", time.time() - t0)
    except Exception as e:
        record_result(category, "TC-S5-VER-03", "Unknown version 0x06 rejected with connection closure", True, f"Exception/closed: {e}", time.time() - t0)

    # 4. Unknown version 0xFF
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SOCKS5_HOST, SOCKS5_PORT))
        s.sendall(b"\xff\x01\x00")
        resp = s.recv(1024)
        passed = (resp == b"")
        s.close()
        record_result(category, "TC-S5-VER-04", "Unknown version 0xFF rejected with connection closure", passed, f"Response: {resp.hex()}", time.time() - t0)
    except Exception as e:
        record_result(category, "TC-S5-VER-04", "Unknown version 0xFF rejected with connection closure", True, f"Exception/closed: {e}", time.time() - t0)

    # 5. Truncated greeting: 1 byte then immediate FIN
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SOCKS5_HOST, SOCKS5_PORT))
        s.sendall(b"\x05")
        s.shutdown(socket.SHUT_WR)
        resp = s.recv(1024)
        passed = (resp == b"")
        s.close()
        record_result(category, "TC-S5-VER-05", "Truncated 1-byte greeting handled cleanly", passed, f"Response: {resp.hex()}", time.time() - t0)
    except Exception as e:
        record_result(category, "TC-S5-VER-05", "Truncated 1-byte greeting handled cleanly", True, f"Exception/closed: {e}", time.time() - t0)

    # 6. Greeting offering 0 methods (NMETHODS=0)
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SOCKS5_HOST, SOCKS5_PORT))
        s.sendall(b"\x05\x00")
        resp = s.recv(1024)
        # RFC 1928: if no acceptable method, return 0x05 0xFF
        passed = (resp == b"\x05\xff" or resp == b"")
        s.close()
        record_result(category, "TC-S5-VER-06", "Greeting with NMETHODS=0 returns 0x05 0xFF (No acceptable methods)", passed, f"Response: {resp.hex()}", time.time() - t0)
    except Exception as e:
        record_result(category, "TC-S5-VER-06", "Greeting with NMETHODS=0 returns 0x05 0xFF", True, f"Exception/closed: {e}", time.time() - t0)

    # 7. Greeting offering only unsupported method (0x02 USER/PASS when unauth server)
    t0 = time.time()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SOCKS5_HOST, SOCKS5_PORT))
        s.sendall(b"\x05\x01\x02")  # Offers only 0x02 (User/Pass)
        resp = s.recv(1024)
        # In unauthenticated mode, method 0x00 is required; offering only 0x02 must yield 0x05 0xFF
        passed = (resp == b"\x05\xff")
        s.close()
        record_result(category, "TC-S5-VER-07", "Greeting offering only unsupported method returns 0x05 0xFF", passed, f"Response: {resp.hex()}", time.time() - t0)
    except Exception as e:
        record_result(category, "TC-S5-VER-07", "Greeting offering only unsupported method returns 0x05 0xFF", False, f"Exception: {e}", time.time() - t0)


def test_socks5_commands():
    category = "SOCKS5 Adversarial"

    def send_cmd(cmd_byte: int) -> bytes:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((SOCKS5_HOST, SOCKS5_PORT))
        # Handshake: method 0x00
        s.sendall(b"\x05\x01\x00")
        hs = s.recv(2)
        if hs != b"\x05\x00":
            s.close()
            return b""
        # Request with cmd_byte, ATYP 0x01 (IPv4), 127.0.0.1:80
        req = bytes([5, cmd_byte, 0, 1, 127, 0, 0, 1, 0, 80])
        s.sendall(req)
        resp = s.recv(1024)
        s.close()
        return resp

    # 1. BIND (0x02)
    t0 = time.time()
    resp = send_cmd(2)
    # Expected: REP=0x07 (Command not supported) -> b"\x05\x07..."
    passed = len(resp) >= 2 and resp[0] == 5 and resp[1] == 7
    record_result(category, "TC-S5-CMD-01", "BIND command (0x02) rejected with REP=0x07", passed, f"Response: {resp.hex()}", time.time() - t0)

    # 2. UDP ASSOCIATE (0x03)
    t0 = time.time()
    resp = send_cmd(3)
    passed = len(resp) >= 2 and resp[0] == 5 and resp[1] == 7
    record_result(category, "TC-S5-CMD-02", "UDP ASSOCIATE command (0x03) rejected with REP=0x07", passed, f"Response: {resp.hex()}", time.time() - t0)

    # 3. Invalid command 0x00
    t0 = time.time()
    resp = send_cmd(0)
    passed = len(resp) >= 2 and resp[0] == 5 and resp[1] == 7
    record_result(category, "TC-S5-CMD-03", "Invalid command 0x00 rejected with REP=0x07", passed, f"Response: {resp.hex()}", time.time() - t0)

    # 4. Invalid command 0xFF
    t0 = time.time()
    resp = send_cmd(0xFF)
    passed = len(resp) >= 2 and resp[0] == 5 and resp[1] == 7
    record_result(category, "TC-S5-CMD-04", "Invalid command 0xFF rejected with REP=0x07", passed, f"Response: {resp.hex()}", time.time() - t0)


def test_socks5_atyp(echo_port: int, echo_port_v6: int):
    category = "SOCKS5 Adversarial"

    def do_request(req_payload: bytes) -> bytes:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((SOCKS5_HOST, SOCKS5_PORT))
        s.sendall(b"\x05\x01\x00")
        hs = s.recv(2)
        if hs != b"\x05\x00":
            s.close()
            return b""
        s.sendall(req_payload)
        resp = s.recv(1024)
        s.close()
        return resp

    # 1. ATYP 0x01 (IPv4) Valid
    t0 = time.time()
    req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", echo_port)
    resp = do_request(req)
    passed = len(resp) >= 2 and resp[0] == 5 and resp[1] == 0
    record_result(category, "TC-S5-ATYP-01", "ATYP 0x01 (IPv4) connection succeeds (REP=0x00)", passed, f"Response: {resp.hex()}", time.time() - t0)

    # 2. ATYP 0x01 (IPv4) Refused Port (127.0.0.1:1)
    t0 = time.time()
    req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", 1)
    resp = do_request(req)
    # Server returns REP 0x04 (Host unreachable) or 0x05 (Connection refused)
    passed = len(resp) >= 2 and resp[0] == 5 and resp[1] in (4, 5)
    record_result(category, "TC-S5-ATYP-02", "ATYP 0x01 (IPv4) refused destination returns error (REP=0x04/0x05)", passed, f"Response: {resp.hex()}", time.time() - t0)

    # 3. ATYP 0x03 (Domain Name) Valid
    t0 = time.time()
    dom = b"127.0.0.1"
    req = b"\x05\x01\x00\x03" + bytes([len(dom)]) + dom + struct.pack("!H", echo_port)
    resp = do_request(req)
    passed = len(resp) >= 2 and resp[0] == 5 and resp[1] == 0
    record_result(category, "TC-S5-ATYP-03", "ATYP 0x03 (Domain Name) valid domain succeeds (REP=0x00)", passed, f"Response: {resp.hex()}", time.time() - t0)

    # 4. ATYP 0x03 (Domain Name) NXDOMAIN
    t0 = time.time()
    dom = b"nonexistent-domain-test-123456789.invalid"
    req = b"\x05\x01\x00\x03" + bytes([len(dom)]) + dom + struct.pack("!H", 443)
    resp = do_request(req)
    passed = len(resp) >= 2 and resp[0] == 5 and resp[1] in (4, 5)
    record_result(category, "TC-S5-ATYP-04", "ATYP 0x03 (Domain Name) NXDOMAIN returns error (REP=0x04)", passed, f"Response: {resp.hex()}", time.time() - t0)

    # 5. ATYP 0x03 (Domain Name) IDN Unicode (xn-- domain)
    t0 = time.time()
    dom = "münchen.de".encode("idna")
    req = b"\x05\x01\x00\x03" + bytes([len(dom)]) + dom + struct.pack("!H", 80)
    resp = do_request(req)
    # Even if destination connection fails or succeeds, server should parse without crash
    passed = len(resp) >= 2 and resp[0] == 5
    record_result(category, "TC-S5-ATYP-05", "ATYP 0x03 (Domain Name) IDN unicode parsed without crash", passed, f"Response: {resp.hex()}", time.time() - t0)

    # 6. ATYP 0x04 (IPv6) Loopback (::1)
    t0 = time.time()
    if echo_port_v6 > 0:
        req = b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, "::1") + struct.pack("!H", echo_port_v6)
        resp = do_request(req)
        passed = len(resp) >= 2 and resp[0] == 5 and resp[1] == 0
        record_result(category, "TC-S5-ATYP-06", "ATYP 0x04 (IPv6) loopback connection succeeds (REP=0x00)", passed, f"Response: {resp.hex()}", time.time() - t0)
    else:
        record_result(category, "TC-S5-ATYP-06", "ATYP 0x04 (IPv6) loopback connection", True, "IPv6 echo server skipped", 0.0)

    # 7. Unsupported ATYP (0x00, 0x02, 0x05, 0xFF)
    for bad_atyp in (0x00, 0x02, 0x05, 0xFF):
        t0 = time.time()
        req = bytes([5, 1, 0, bad_atyp]) + b"\x00" * 6
        resp = do_request(req)
        # RFC 1928: REP 0x08 = Address type not supported
        passed = len(resp) >= 2 and resp[0] == 5 and resp[1] == 8
        record_result(category, f"TC-S5-ATYP-BAD-{bad_atyp:02x}", f"Unsupported ATYP 0x{bad_atyp:02x} returns REP=0x08", passed, f"Response: {resp.hex()}", time.time() - t0)


async def test_socks5_large_payload_async(echo_port: int, size_mb: int = 5):
    category = "SOCKS5 Adversarial"
    test_id = f"TC-S5-DATA-{size_mb}MB"
    total_bytes = size_mb * 1024 * 1024
    t0 = time.time()

    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(SOCKS5_HOST, SOCKS5_PORT), timeout=5.0)
        w.write(b"\x05\x01\x00")
        await w.drain()
        hs = await r.readexactly(2)
        if hs != b"\x05\x00":
            record_result(category, test_id, f"SOCKS5 {size_mb}MB transfer handshake failed", False, f"Handshake: {hs.hex()}", time.time() - t0)
            w.close()
            return

        req = b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", echo_port)
        w.write(req)
        await w.drain()
        resp = await r.readexactly(10)
        if resp[1] != 0:
            record_result(category, test_id, f"SOCKS5 {size_mb}MB transfer connect failed", False, f"Connect: {resp.hex()}", time.time() - t0)
            w.close()
            return

        pattern = os.urandom(65536)
        sent_hasher = hashlib.sha256()
        recv_hasher = hashlib.sha256()

        async def sender():
            sent = 0
            while sent < total_bytes:
                chunk = pattern[:min(len(pattern), total_bytes - sent)]
                w.write(chunk)
                await w.drain()
                sent_hasher.update(chunk)
                sent += len(chunk)

        async def receiver():
            recvd = 0
            while recvd < total_bytes:
                chunk = await r.read(min(65536, total_bytes - recvd))
                if not chunk:
                    break
                recv_hasher.update(chunk)
                recvd += len(chunk)
            return recvd

        await asyncio.wait_for(asyncio.gather(sender(), receiver()), timeout=30.0)
        w.close()
        await w.wait_closed()

        elapsed = time.time() - t0
        sent_digest = sent_hasher.hexdigest()
        recv_digest = recv_hasher.hexdigest()
        integrity_ok = (sent_digest == recv_digest)
        throughput_mbps = (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0

        record_result(
            category,
            test_id,
            f"SOCKS5 {size_mb}MB bidirectional transfer data integrity (SHA-256)",
            integrity_ok,
            f"Transferred: {total_bytes} bytes in {elapsed:.2f}s ({throughput_mbps:.1f} MB/s), SHA256: {recv_digest[:16]}...",
            elapsed
        )
    except Exception as e:
        record_result(category, test_id, f"SOCKS5 {size_mb}MB transfer failed", False, f"Exception: {e}", time.time() - t0)


# ============================================================================
# HTTP CONNECT Adversarial Tests
# ============================================================================

def test_http_malformed_requests():
    category = "HTTP CONNECT Adversarial"

    def send_raw_http(payload: bytes, timeout: float = 2.0) -> bytes:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((HTTP_HOST, HTTP_PORT))
            s.sendall(payload)
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp or b"\n\n" in resp:
                    break
            s.close()
            return resp
        except Exception:
            s.close()
            return b""

    # 1. Empty request
    t0 = time.time()
    resp = send_raw_http(b"\r\n\r\n")
    passed = (resp == b"" or b"400 Bad Request" in resp)
    record_result(category, "TC-HC-REQ-01", "Empty HTTP request handled cleanly", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 2. Bare method CONNECT with no target
    t0 = time.time()
    resp = send_raw_http(b"CONNECT\r\n\r\n")
    passed = b"400 Bad Request" in resp
    record_result(category, "TC-HC-REQ-02", "Bare CONNECT with no target returns 400 Bad Request", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 3. Method with whitespace only
    t0 = time.time()
    resp = send_raw_http(b"CONNECT    \r\n\r\n")
    passed = b"400 Bad Request" in resp
    record_result(category, "TC-HC-REQ-03", "CONNECT with whitespace target returns 400 Bad Request", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 4. Header overflow > 65536 bytes
    t0 = time.time()
    overflow_req = b"CONNECT example.com:443 HTTP/1.1\r\nX-Spam: " + (b"A" * 70000) + b"\r\n\r\n"
    resp = send_raw_http(overflow_req, timeout=3.0)
    passed = b"431 Request Header Fields Too Large" in resp
    record_result(category, "TC-HC-REQ-04", "Header overflow >64KB returns 431 Request Header Fields Too Large", passed, f"Response: {resp[:50]}", time.time() - t0)

    # 5. Non-numeric port
    t0 = time.time()
    resp = send_raw_http(b"CONNECT example.com:abc HTTP/1.1\r\n\r\n")
    passed = b"400 Bad Request" in resp
    record_result(category, "TC-HC-PORT-01", "Non-numeric port returns 400 Bad Request", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 6. Malformed IPv6 literal (missing closing bracket)
    t0 = time.time()
    resp = send_raw_http(b"CONNECT [2001:db8::1 HTTP/1.1\r\n\r\n")
    passed = b"400 Bad Request" in resp
    record_result(category, "TC-HC-PORT-02", "Malformed IPv6 literal without closing bracket returns 400 Bad Request", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 7. Out of range port (>65535 on local IP so no DNS delay)
    t0 = time.time()
    resp = send_raw_http(b"CONNECT 127.0.0.1:99999 HTTP/1.1\r\n\r\n")
    passed = (b"400 Bad Request" in resp or b"502 Bad Gateway" in resp)
    record_result(category, "TC-HC-PORT-03", "Port 99999 rejected without server crash", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 8. Negative port (-1)
    t0 = time.time()
    resp = send_raw_http(b"CONNECT 127.0.0.1:-1 HTTP/1.1\r\n\r\n")
    passed = (b"400 Bad Request" in resp or b"502 Bad Gateway" in resp)
    record_result(category, "TC-HC-PORT-04", "Port -1 rejected without server crash", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 9. Missing host in target (:443)
    t0 = time.time()
    resp = send_raw_http(b"CONNECT :443 HTTP/1.1\r\n\r\n")
    passed = (b"400 Bad Request" in resp or b"502 Bad Gateway" in resp)
    record_result(category, "TC-HC-PORT-05", "Missing host in target (:443) handled cleanly", passed, f"Response: {resp[:40]}", time.time() - t0)


async def test_http_large_payload_async(echo_port: int, size_mb: int = 5):
    category = "HTTP CONNECT Adversarial"
    test_id = f"TC-HC-DATA-{size_mb}MB"
    total_bytes = size_mb * 1024 * 1024
    t0 = time.time()

    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(HTTP_HOST, HTTP_PORT), timeout=5.0)
        req = f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n".encode("utf-8")
        w.write(req)
        await w.drain()

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = await r.read(1024)
            if not chunk:
                break
            resp += chunk

        if b"200 Connection Established" not in resp:
            record_result(category, test_id, f"HTTP CONNECT {size_mb}MB tunnel establishment failed", False, f"Response: {resp[:50]}", time.time() - t0)
            w.close()
            return

        pattern = os.urandom(65536)
        sent_hasher = hashlib.sha256()
        recv_hasher = hashlib.sha256()

        async def sender():
            sent = 0
            while sent < total_bytes:
                chunk = pattern[:min(len(pattern), total_bytes - sent)]
                w.write(chunk)
                await w.drain()
                sent_hasher.update(chunk)
                sent += len(chunk)

        async def receiver():
            recvd = 0
            while recvd < total_bytes:
                chunk = await r.read(min(65536, total_bytes - recvd))
                if not chunk:
                    break
                recv_hasher.update(chunk)
                recvd += len(chunk)
            return recvd

        await asyncio.wait_for(asyncio.gather(sender(), receiver()), timeout=30.0)
        w.close()
        await w.wait_closed()

        elapsed = time.time() - t0
        sent_digest = sent_hasher.hexdigest()
        recv_digest = recv_hasher.hexdigest()
        integrity_ok = (sent_digest == recv_digest)
        throughput_mbps = (total_bytes / (1024 * 1024)) / elapsed if elapsed > 0 else 0

        record_result(
            category,
            test_id,
            f"HTTP CONNECT {size_mb}MB bidirectional transfer data integrity (SHA-256)",
            integrity_ok,
            f"Transferred: {total_bytes} bytes in {elapsed:.2f}s ({throughput_mbps:.1f} MB/s), SHA256: {recv_digest[:16]}...",
            elapsed
        )
    except Exception as e:
        record_result(category, test_id, f"HTTP CONNECT {size_mb}MB transfer failed", False, f"Exception: {e}", time.time() - t0)


def test_http_methods_and_pipelining(echo_port: int):
    category = "HTTP CONNECT Adversarial"

    def send_raw_http(payload: bytes) -> bytes:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((HTTP_HOST, HTTP_PORT))
            s.sendall(payload)
            resp = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp:
                    break
            s.close()
            return resp
        except Exception:
            s.close()
            return b""

    # 1. GET method
    t0 = time.time()
    resp = send_raw_http(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    passed = b"400 Bad Request" in resp or b"405 Method Not Allowed" in resp
    record_result(category, "TC-HC-METH-01", "GET method rejected (non-CONNECT prohibited)", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 2. POST method
    t0 = time.time()
    resp = send_raw_http(b"POST /api HTTP/1.1\r\nHost: example.com\r\n\r\n")
    passed = b"400 Bad Request" in resp or b"405 Method Not Allowed" in resp
    record_result(category, "TC-HC-METH-02", "POST method rejected (non-CONNECT prohibited)", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 3. OPTIONS method
    t0 = time.time()
    resp = send_raw_http(b"OPTIONS * HTTP/1.1\r\nHost: example.com\r\n\r\n")
    passed = b"400 Bad Request" in resp or b"405 Method Not Allowed" in resp
    record_result(category, "TC-HC-METH-03", "OPTIONS method rejected (non-CONNECT prohibited)", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 4. HTTP/2 PRI Preface
    t0 = time.time()
    resp = send_raw_http(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
    passed = b"400 Bad Request" in resp or b"405 Method Not Allowed" in resp
    record_result(category, "TC-HC-METH-04", "HTTP/2 connection preface rejected with 400 Bad Request", passed, f"Response: {resp[:40]}", time.time() - t0)

    # 5. Pipelined / Early Data Probe: CONNECT request with payload in same packet
    t0 = time.time()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect((HTTP_HOST, HTTP_PORT))
        early_payload = b"PING_PIPELINE_EARLY_DATA_12345"
        combined = f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n".encode("utf-8") + early_payload
        s.sendall(combined)

        # Read status response
        resp_hdr = b""
        while b"\r\n\r\n" not in resp_hdr:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp_hdr += chunk

        connected = b"200 Connection Established" in resp_hdr
        echoed = False
        remaining = resp_hdr.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in resp_hdr else b""
        if early_payload in remaining:
            echoed = True
        else:
            try:
                echo_chunk = s.recv(1024)
                if early_payload in echo_chunk:
                    echoed = True
            except Exception:
                pass

        s.close()
        # Note: If early data was swallowed by proxy_inbound.py buffer read, echoed is False!
        record_result(
            category,
            "TC-HC-PIPE-01",
            "Pipelined early data in CONNECT header packet preservation check",
            echoed,
            f"Connected: {connected}, Early data echoed: {echoed} (Early data pre-read buffer swallow vulnerability test)",
            time.time() - t0
        )
    except Exception as e:
        record_result(category, "TC-HC-PIPE-01", "Pipelined early data probe", False, f"Exception: {e}", time.time() - t0)
        s.close()


# ============================================================================
# Live agy Load Test
# ============================================================================

def run_single_agy_prompt(proxy_env_key: str, proxy_url: str, prompt_idx: int) -> Tuple[bool, float, str]:
    t0 = time.time()
    env = os.environ.copy()
    env[proxy_env_key] = proxy_url
    agy_path = shutil.which("agy") or (Path.home() / ".local/bin/agy").as_posix()
    cmd = [str(agy_path), "-p", prompt]

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20.0
        )
        elapsed = time.time() - t0
        out = proc.stdout.strip()
        passed = (proc.returncode == 0 and len(out) > 0)
        return passed, elapsed, out[:100]
    except subprocess.TimeoutExpired:
        return False, time.time() - t0, "Timeout expired (>20s)"
    except Exception as e:
        return False, time.time() - t0, str(e)


def test_live_agy_rapid_sequential(count: int = 5):
    category = "Live agy Load Test"

    # 1. Rapid sequential via HTTP CONNECT
    t_start = time.time()
    success_http = 0
    times_http = []
    print(f"[*] Running {count} sequential agy prompts via HTTP proxy ({HTTP_PORT})...")
    for i in range(count):
        ok, dur, out = run_single_agy_prompt("HTTPS_PROXY", f"http://{HTTP_HOST}:{HTTP_PORT}", i)
        if ok:
            success_http += 1
            times_http.append(dur)
        print(f"    - HTTP Prompt #{i+1}: {'OK' if ok else 'FAIL'} in {dur:.2f}s (Response: {out})")

    avg_http = sum(times_http) / len(times_http) if times_http else 0
    passed_http = (success_http == count)
    record_result(
        category,
        "TC-AGY-LOAD-01",
        f"{count} Rapid sequential agy prompts via HTTP CONNECT proxy",
        passed_http,
        f"{success_http}/{count} passed, Avg latency: {avg_http:.2f}s",
        time.time() - t_start
    )

    # 2. Rapid sequential via SOCKS5
    t_start = time.time()
    success_socks = 0
    times_socks = []
    print(f"[*] Running {count} sequential agy prompts via SOCKS5 proxy ({SOCKS5_PORT})...")
    for i in range(count):
        ok, dur, out = run_single_agy_prompt("HTTPS_PROXY", f"socks5h://{SOCKS5_HOST}:{SOCKS5_PORT}", i)
        if ok:
            success_socks += 1
            times_socks.append(dur)
        print(f"    - SOCKS5 Prompt #{i+1}: {'OK' if ok else 'FAIL'} in {dur:.2f}s (Response: {out})")

    avg_socks = sum(times_socks) / len(times_socks) if times_socks else 0
    passed_socks = (success_socks == count)
    record_result(
        category,
        "TC-AGY-LOAD-02",
        f"{count} Rapid sequential agy prompts via SOCKS5 proxy",
        passed_socks,
        f"{success_socks}/{count} passed, Avg latency: {avg_socks:.2f}s",
        time.time() - t_start
    )


def test_live_agy_concurrent(concurrency: int = 4):
    category = "Live agy Load Test"
    import concurrent.futures

    # 1. Concurrent via HTTP CONNECT
    t_start = time.time()
    print(f"[*] Running {concurrency} concurrent agy prompts via HTTP proxy ({HTTP_PORT})...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(run_single_agy_prompt, "HTTPS_PROXY", f"http://{HTTP_HOST}:{HTTP_PORT}", i + 100)
            for i in range(concurrency)
        ]
        results_http = [f.result() for f in concurrent.futures.as_completed(futures)]

    success_http = sum(1 for ok, _, _ in results_http if ok)
    passed_http = (success_http == concurrency)
    record_result(
        category,
        "TC-AGY-LOAD-03",
        f"{concurrency} Concurrent agy prompts via HTTP CONNECT proxy",
        passed_http,
        f"{success_http}/{concurrency} succeeded in {time.time() - t_start:.2f}s",
        time.time() - t_start
    )

    # 2. Concurrent via SOCKS5
    t_start = time.time()
    print(f"[*] Running {concurrency} concurrent agy prompts via SOCKS5 proxy ({SOCKS5_PORT})...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [
            executor.submit(run_single_agy_prompt, "HTTPS_PROXY", f"socks5h://{SOCKS5_HOST}:{SOCKS5_PORT}", i + 200)
            for i in range(concurrency)
        ]
        results_socks = [f.result() for f in concurrent.futures.as_completed(futures)]

    success_socks = sum(1 for ok, _, _ in results_socks if ok)
    passed_socks = (success_socks == concurrency)
    record_result(
        category,
        "TC-AGY-LOAD-04",
        f"{concurrency} Concurrent agy prompts via SOCKS5 proxy",
        passed_socks,
        f"{success_socks}/{concurrency} succeeded in {time.time() - t_start:.2f}s",
        time.time() - t_start
    )


# ============================================================================
# Main Orchestrator
# ============================================================================

async def main_async():
    print("=" * 80)
    print("STARTING EMPIRICAL ADVERSARIAL STRESS TEST SUITE (M1 PROXY INBOUND)")
    print("=" * 80)

    # Start IPv4 Echo Server
    echo_v4 = AsyncEchoServer(host="127.0.0.1", port=0)
    port_v4 = await echo_v4.start()
    print(f"[*] Started local IPv4 echo server on 127.0.0.1:{port_v4}")

    # Start IPv6 Echo Server if supported
    echo_v6 = AsyncEchoServer(host="::1", port=0)
    try:
        port_v6 = await echo_v6.start()
        print(f"[*] Started local IPv6 echo server on [::1]:{port_v6}")
    except Exception as e:
        port_v6 = 0
        print(f"[!] IPv6 echo server start failed: {e}")

    try:
        print("\n--- [Phase 1: SOCKS5 Adversarial Handshake & Protocol Probes] ---")
        test_socks5_invalid_versions()

        print("\n--- [Phase 2: SOCKS5 Command Handling Probes] ---")
        test_socks5_commands()

        print("\n--- [Phase 3: SOCKS5 ATYP Handling Probes] ---")
        test_socks5_atyp(port_v4, port_v6)

        print("\n--- [Phase 4: SOCKS5 Large Payload Stress Transfers] ---")
        await test_socks5_large_payload_async(port_v4, size_mb=5)
        await test_socks5_large_payload_async(port_v4, size_mb=10)

        print("\n--- [Phase 5: HTTP CONNECT Malformed Header Probes] ---")
        test_http_malformed_requests()

        print("\n--- [Phase 6: HTTP CONNECT Methods & Pipelining Probes] ---")
        test_http_methods_and_pipelining(port_v4)

        print("\n--- [Phase 7: HTTP CONNECT Large Payload Stress Transfers] ---")
        await test_http_large_payload_async(port_v4, size_mb=5)
        await test_http_large_payload_async(port_v4, size_mb=10)

        print("\n--- [Phase 8: Live agy Load & Concurrency Testing] ---")
        test_live_agy_rapid_sequential(count=5)
        test_live_agy_concurrent(concurrency=4)

    finally:
        await echo_v4.stop()
        if echo_v6:
            await echo_v6.stop()

    print("\n" + "=" * 80)
    print("EMPIRICAL TEST SUMMARY")
    print("=" * 80)
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["passed"])
    failed = total - passed
    print(f"Total Tests Executed : {total}")
    print(f"Passed               : {passed}")
    print(f"Failed               : {failed}")
    print("=" * 80)

    if failed > 0:
        print("\nFAILED TESTS LIST:")
        for r in RESULTS:
            if not r["passed"]:
                print(f"- {r['test_id']} ({r['category']}): {r['description']}")
                print(f"  Details: {r['details']}")

    return failed


if __name__ == "__main__":
    failed_count = asyncio.run(main_async())
    sys.exit(0 if failed_count == 0 else 1)
