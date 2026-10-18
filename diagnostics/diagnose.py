#!/usr/bin/env python3
"""
diagnose.py - Cross-Platform Self-Test Diagnostics for Antigravity Zero-Privilege Bypass
Probes DNS interception, TLS SNI forwarding, proxy tunnels, and agy prompt execution.
Operates 100% in unprivileged user space using Python 3 standard library.
"""

import argparse
import json
import os
import random
import socket
import ssl
import struct
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple
def _resolve_default_server() -> str:
    env_host = os.environ.get("ANTIGRAVITY_SERVER_HOST")
    if env_host:
        return env_host.strip()
    host_file = os.path.expanduser("~/.antigravity-bypass/server_host.txt")
    if os.path.isfile(host_file):
        try:
            with open(host_file, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val:
                    return val
        except Exception:
            pass
    try:
        from antigravity_unlocker.common.discovery import get_client_target_server
        return get_client_target_server()
    except Exception:
        pass
    return "127.0.0.1"


DEFAULT_SERVER = _resolve_default_server()
TARGET_DOMAIN = "daily-cloudcode-pa.googleapis.com"


def build_dns_query(domain: str, qtype: int = 1) -> bytes:
    """Build a standard RFC 1035 UDP DNS query packet."""
    tx_id = random.randint(1, 65535)
    flags = 0x0100  # Standard query with recursion desired
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0
    header = struct.pack(">HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    question = b""
    for part in domain.split("."):
        question += bytes([len(part)]) + part.encode("ascii")
    question += b"\x00"
    question += struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN

    return header + question


def parse_dns_response(data: bytes) -> Dict[str, Any]:
    """Parse minimal DNS response to extract answer IP addresses."""
    if len(data) < 12:
        return {"valid": False, "answers": []}

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    rcode = flags & 0x000F
    offset = 12

    # Skip question section
    for _ in range(qdcount):
        while offset < len(data) and data[offset] != 0:
            if (data[offset] & 0xC0) == 0xC0:
                offset += 2
                break
            else:
                offset += 1 + data[offset]
        else:
            if offset < len(data) and data[offset] == 0:
                offset += 1
        offset += 4  # QTYPE + QCLASS

    answers = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        # Skip name
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while offset < len(data) and data[offset] != 0:
                offset += 1 + data[offset]
            if offset < len(data) and data[offset] == 0:
                offset += 1

        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlength = struct.unpack(">HHIH", data[offset : offset + 10])
        offset += 10
        if rtype == 1 and rdlength == 4 and offset + 4 <= len(data):
            ip = socket.inet_ntoa(data[offset : offset + 4])
            answers.append(ip)
        offset += rdlength

    return {"valid": True, "rcode": rcode, "ancount": ancount, "answers": answers}


def probe_dns_interception(server: str, port: int, timeout: float) -> Dict[str, Any]:
    """Probe DNS UDP resolution of Google AI domain on server."""
    query = build_dns_query(TARGET_DOMAIN, qtype=1)
    start_time = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (server, port))
        resp, _ = sock.recvfrom(4096)
        elapsed = (time.perf_counter() - start_time) * 1000.0
        parsed = parse_dns_response(resp)
        if parsed.get("valid") and (parsed.get("answers") or parsed.get("ancount") == 0):
            return {
                "name": "DNS Interception",
                "status": "PASS",
                "critical": True,
                "latency_ms": round(elapsed, 2),
                "details": f"Resolved {TARGET_DOMAIN} -> {parsed.get('answers')}",
            }
        else:
            return {
                "name": "DNS Interception",
                "status": "FAIL",
                "critical": True,
                "latency_ms": round(elapsed, 2),
                "details": f"DNS response invalid or empty (rcode {parsed.get('rcode')})",
            }
    except Exception as err:
        elapsed = (time.perf_counter() - start_time) * 1000.0
        return {
            "name": "DNS Interception",
            "status": "FAIL",
            "critical": True,
            "latency_ms": round(elapsed, 2),
            "details": f"DNS query failed: {err}",
        }
    finally:
        sock.close()


def probe_sni_proxy(server: str, port: int, timeout: float) -> Dict[str, Any]:
    """Probe direct TLS SNI proxy forwarding on server port (443 / 8443 / 10443)."""
    candidate_ports = [port]
    if port == 443:
        for p in [8443, 10443]:
            if p not in candidate_ports:
                candidate_ports.append(p)

    last_err: Optional[Exception] = None
    elapsed = 0.0
    for p in candidate_ports:
        start_time = time.perf_counter()
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        try:
            raw_sock.connect((server, p))
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw_sock, server_hostname=TARGET_DOMAIN) as tls_sock:
                tls_sock.settimeout(timeout)
                tls_sock.sendall(
                    f"HEAD / HTTP/1.1\r\nHost: {TARGET_DOMAIN}\r\nConnection: close\r\n\r\n".encode("utf-8")
                )
                resp = tls_sock.recv(1024)
                elapsed = (time.perf_counter() - start_time) * 1000.0
                if resp:
                    status_line = resp.split(b"\r\n")[0].decode("latin-1", errors="replace")
                    return {
                        "name": "TLS SNI Proxy",
                        "status": "PASS",
                        "critical": True,
                        "latency_ms": round(elapsed, 2),
                        "details": f"TLS handshake success with {TARGET_DOMAIN} (port {p}): {status_line}",
                    }
                return {
                    "name": "TLS SNI Proxy",
                    "status": "FAIL",
                    "critical": True,
                    "latency_ms": round(elapsed, 2),
                    "details": f"Port {p} connected but empty response received",
                }
        except (ConnectionRefusedError, OSError) as err:
            last_err = err
            elapsed = (time.perf_counter() - start_time) * 1000.0
            if isinstance(err, socket.timeout) or "timed out" in str(err).lower():
                break
            continue
        finally:
            try:
                raw_sock.close()
            except Exception:
                pass

    return {
        "name": "TLS SNI Proxy",
        "status": "FAIL",
        "critical": True,
        "latency_ms": round(elapsed, 2),
        "details": f"TLS SNI forward check failed: {last_err}",
    }


def probe_http_connect_tunnel(server: str, port: int, timeout: float) -> Dict[str, Any]:
    """Probe HTTP CONNECT tunnel forwarder."""
    candidate_ports = [port]
    if port in (18443, 48329):
        for p in [48329]:
            if p not in candidate_ports:
                candidate_ports.append(p)

    last_err: Optional[Exception] = None
    elapsed = 0.0
    for p in candidate_ports:
        start_time = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((server, p))
            connect_req = (
                f"CONNECT {TARGET_DOMAIN}:443 HTTP/1.1\r\n"
                f"Host: {TARGET_DOMAIN}:443\r\n"
                f"Proxy-Connection: Keep-Alive\r\n\r\n"
            ).encode("utf-8")
            sock.sendall(connect_req)
            resp = sock.recv(1024)
            elapsed = (time.perf_counter() - start_time) * 1000.0
            if b" 200 " in resp or b"200 Connection Established" in resp:
                return {
                    "name": "HTTP CONNECT Tunnel",
                    "status": "PASS",
                    "critical": False,
                    "latency_ms": round(elapsed, 2),
                    "details": f"HTTP CONNECT 200 Connection Established (port {p})",
                }
            return {
                "name": "HTTP CONNECT Tunnel",
                "status": "FAIL",
                "critical": False,
                "latency_ms": round(elapsed, 2),
                "details": f"HTTP CONNECT rejected on port {p}: {resp[:80]!r}",
            }
        except (ConnectionRefusedError, OSError) as err:
            last_err = err
            elapsed = (time.perf_counter() - start_time) * 1000.0
            if isinstance(err, socket.timeout) or "timed out" in str(err).lower():
                break
            continue
        finally:
            try:
                sock.close()
            except Exception:
                pass

    return {
        "name": "HTTP CONNECT Tunnel",
        "status": "INFO",
        "critical": False,
        "latency_ms": round(elapsed, 2),
        "details": f"WAN proxy ports filtered or unreachable ({last_err})",
    }


def probe_socks5_tunnel(server: str, port: int, timeout: float) -> Dict[str, Any]:
    """Probe SOCKS5 proxy tunnel forwarder."""
    candidate_ports = [port]
    if port in (18444, 48328):
        for p in [48328]:
            if p not in candidate_ports:
                candidate_ports.append(p)

    last_err: Optional[Exception] = None
    elapsed = 0.0
    for p in candidate_ports:
        start_time = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((server, p))
            # SOCKS5 greeting
            sock.sendall(b"\x05\x01\x00")
            auth_resp = sock.recv(2)
            if auth_resp != b"\x05\x00":
                elapsed = (time.perf_counter() - start_time) * 1000.0
                return {
                    "name": "SOCKS5 Proxy Tunnel",
                    "status": "FAIL",
                    "critical": False,
                    "latency_ms": round(elapsed, 2),
                    "details": f"Unexpected SOCKS5 auth response on port {p}: {auth_resp!r}",
                }
            # SOCKS5 CONNECT to domain
            domain_bytes = TARGET_DOMAIN.encode("ascii")
            req = b"\x05\x01\x00\x03" + bytes([len(domain_bytes)]) + domain_bytes + struct.pack(">H", 443)
            sock.sendall(req)
            resp = sock.recv(10)
            elapsed = (time.perf_counter() - start_time) * 1000.0
            if len(resp) >= 4 and resp[1] == 0x00:
                return {
                    "name": "SOCKS5 Proxy Tunnel",
                    "status": "PASS",
                    "critical": False,
                    "latency_ms": round(elapsed, 2),
                    "details": f"SOCKS5 CONNECT 0x00 (Success, port {p})",
                }
            return {
                "name": "SOCKS5 Proxy Tunnel",
                "status": "FAIL",
                "critical": False,
                "latency_ms": round(elapsed, 2),
                "details": f"SOCKS5 CONNECT failed with REP code on port {p}: {resp[1] if len(resp) > 1 else 'empty'}",
            }
        except (ConnectionRefusedError, OSError) as err:
            last_err = err
            elapsed = (time.perf_counter() - start_time) * 1000.0
            if isinstance(err, socket.timeout) or "timed out" in str(err).lower():
                break
            continue
        finally:
            try:
                sock.close()
            except Exception:
                pass

    return {
        "name": "SOCKS5 Proxy Tunnel",
        "status": "INFO",
        "critical": False,
        "latency_ms": round(elapsed, 2),
        "details": f"WAN proxy ports filtered or unreachable ({last_err})",
    }


def probe_local_loopback(http_port: int, socks_port: int) -> Dict[str, Any]:
    """Probe local loopback forwarder ports (127.0.0.1)."""
    http_open = False
    socks_open = False
    for port, is_http in [(http_port, True), (socks_port, False)]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        try:
            s.connect(("127.0.0.1", port))
            if is_http:
                http_open = True
            else:
                socks_open = True
        except Exception:
            pass
        finally:
            s.close()

    if http_open and socks_open:
        return {
            "name": "Local Loopback Ports",
            "status": "PASS",
            "critical": False,
            "details": f"Active on 127.0.0.1 HTTP:{http_port} and SOCKS5:{socks_port}",
        }
    elif http_open or socks_open:
        return {
            "name": "Local Loopback Ports",
            "status": "PASS",
            "critical": False,
            "details": f"Partially active (HTTP:{http_open}, SOCKS5:{socks_open})",
        }
    else:
        return {
            "name": "Local Loopback Ports",
            "status": "WARN",
            "critical": False,
            "details": "Not running on 127.0.0.1 (Start via antigravity-ui [1])",
        }


def probe_agy_cli(skip_prompt: bool) -> Dict[str, Any]:
    """Probe agy executable presence, version, and live prompt execution."""
    agy_bin = shutil.which("agy")
    if not agy_bin:
        for candidate in [
            os.path.expanduser("~/.local/bin/agy"),
            "/root/.local/bin/agy",
            os.path.expanduser("~/.gemini/antigravity-cli/bin/agy"),
        ]:
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                agy_bin = candidate
                break

    if not agy_bin:
        return {
            "name": "agy CLI Execution",
            "status": "WARN",
            "critical": False,
            "details": "agy binary not found in PATH or standard user directories",
        }

    if skip_prompt:
        return {
            "name": "agy CLI Execution",
            "status": "PASS",
            "critical": False,
            "details": f"Found {agy_bin} (prompt skipped via flag)",
        }

    # Resolve active local HTTP port (default 18443 or from ports file)
    active_http = int(os.getenv("ANTIGRAVITY_HTTP_PORT", "18443"))
    ports_file = os.path.expanduser("~/.antigravity_ports.json")
    if os.path.exists(ports_file):
        try:
            with open(ports_file) as pf:
                active_http = json.load(pf).get("http_port", active_http)
        except Exception:
            pass

    # If local forwarder is not running, do not block waiting for a 12s timeout
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.2)
    try:
        s.connect(("127.0.0.1", active_http))
        s.close()
    except Exception:
        s.close()
        return {
            "name": "agy CLI Execution",
            "status": "WARN",
            "critical": False,
            "details": f"Found {agy_bin} (start forwarder via Option [1] to test)",
        }

    try:
        env = os.environ.copy()
        env["HTTPS_PROXY"] = f"http://127.0.0.1:{active_http}"
        env["HTTP_PROXY"] = f"http://127.0.0.1:{active_http}"
        env["AG_LS_PROXY"] = f"http://127.0.0.1:{active_http}"
        proc = subprocess.run(
            [agy_bin, "-p", "ping", "--print-timeout", "10s"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=12.0,
        )
        if proc.returncode == 0 and "pong" in proc.stdout.lower():
            return {
                "name": "agy CLI Execution",
                "status": "PASS",
                "critical": False,
                "details": f"Live prompt success: '{proc.stdout.strip()[:60]}'",
            }
        else:
            return {
                "name": "agy CLI Execution",
                "status": "WARN",
                "critical": False,
                "details": f"Prompt exited with code {proc.returncode}: {proc.stderr.strip()[:60]}",
            }
    except Exception as err:
        return {
            "name": "agy CLI Execution",
            "status": "WARN",
            "critical": False,
            "details": f"Prompt invocation error: {err}",
        }


import shutil


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Cross-platform self-test diagnostics for Antigravity Zero-Privilege Bypass.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--server",
        type=str,
        default=DEFAULT_SERVER,
        help="Target Frankfurt VPS IP or hostname",
    )
    default_http = int(os.getenv("ANTIGRAVITY_HTTP_PORT", "18443"))
    default_socks = int(os.getenv("ANTIGRAVITY_SOCKS_PORT", "18444"))
    ports_file = os.path.expanduser("~/.antigravity_ports.json")
    if os.path.exists(ports_file):
        try:
            with open(ports_file) as pf:
                pj = json.load(pf)
                default_http = pj.get("http_port", default_http)
                default_socks = pj.get("socks_port", default_socks)
        except Exception:
            pass

    parser.add_argument("--dns-port", type=int, default=53, help="VPS DNS service port")
    parser.add_argument("--sni-port", type=int, default=443, help="VPS TLS SNI-Proxy port")
    parser.add_argument("--http-port", type=int, default=default_http, help="HTTP CONNECT proxy port")
    parser.add_argument("--socks-port", type=int, default=default_socks, help="SOCKS5 proxy port")
    parser.add_argument("--timeout", type=float, default=3.0, help="Per-check network timeout in seconds")
    parser.add_argument(
        "--format",
        type=str,
        choices=["text", "json"],
        default="text",
        help="Output format (text table or JSON envelope)",
    )
    parser.add_argument(
        "--skip-prompt",
        action="store_true",
        help="Skip live agy prompt ping test",
    )

    args = parser.parse_args()

    # Run diagnostics checks
    results: List[Dict[str, Any]] = []

    # 1. DNS Resolution Check
    dns_res = probe_dns_interception(args.server, args.dns_port, args.timeout)
    results.append(dns_res)

    # 2. TLS SNI Proxy Check
    sni_res = probe_sni_proxy(args.server, args.sni_port, args.timeout)
    results.append(sni_res)

    # 3. HTTP CONNECT Tunnel Check
    http_res = probe_http_connect_tunnel(args.server, args.http_port, args.timeout)
    results.append(http_res)

    # 4. SOCKS5 Tunnel Check
    socks_res = probe_socks5_tunnel(args.server, args.socks_port, args.timeout)
    results.append(socks_res)

    # 5. Local Loopback Forwarder Check
    loop_res = probe_local_loopback(args.http_port, args.socks_port)
    results.append(loop_res)

    # 6. agy CLI Status and Prompt Check
    agy_res = probe_agy_cli(args.skip_prompt)
    results.append(agy_res)

    # Determine overall status: critical checks failing triggers non-zero exit
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = sum(1 for r in results if r["status"] == "FAIL")
    warned = sum(1 for r in results if r["status"] == "WARN")

    has_critical_failure = any(r["status"] == "FAIL" and r.get("critical", False) for r in results)
    overall_status = "FAIL" if has_critical_failure else "PASS"

    if args.format == "json":
        output_payload = {
            "status": overall_status,
            "server": args.server,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "summary": {
                "total": len(results),
                "passed": passed,
                "failed": failed,
                "warned": warned,
            },
            "checks": results,
        }
        print(json.dumps(output_payload, indent=2))
    else:
        print("=" * 72)
        print("  Antigravity Zero-Privilege Bypass - Diagnostic Self-Test")
        print(f"  Target Server : {args.server}")
        print(f"  Timeout       : {args.timeout}s")
        print("=" * 72)
        print(f"{'CHECK':<25} | {'STATUS':<6} | {'DETAILS'}")
        print("-" * 72)
        for r in results:
            stat = r["status"]
            print(f"{r['name']:<25} | {stat:<6} | {r['details']}")
        print("=" * 72)
        print(f"Overall Result: [{overall_status}] (Pass: {passed}, Fail: {failed}, Warn: {warned})")
        print("=" * 72)

    return 1 if has_critical_failure else 0


if __name__ == "__main__":
    sys.exit(main())
