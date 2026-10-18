"""
Antigravity Zero-Privilege Bypass System - Opaque-Box Protocol Helpers
Provides pure Python protocol encoders, parsers, and socket clients for:
- DNS (RFC 1035 UDP & TCP framing, Type A, AAAA, HTTPS 65, NODATA)
- TLS ClientHello & SNI (RFC 5246, 8446, 6066)
- SOCKS5 Proxy (RFC 1928, RFC 1929 username/password auth)
- HTTP CONNECT Proxy (RFC 7231, Proxy-Authorization Basic)
- Subprocess and Environment Helpers
All implemented with zero third-party dependencies using standard library only.
"""

import base64
import os
import random
import socket
import ssl
import struct
import subprocess
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union

# Default Network Constants
DEFAULT_VPS_IP = os.environ.get("ANTIGRAVITY_SERVER_HOST", "127.0.0.1")
DEFAULT_DNS_PORT = int(os.environ.get("ANTIGRAVITY_DNS_PORT", "53"))
DEFAULT_SNI_PORT = int(os.environ.get("ANTIGRAVITY_SNI_PORT", "10443"))
DEFAULT_SOCKS_PORT = int(os.environ.get("ANTIGRAVITY_SOCKS_PORT", "48328"))
DEFAULT_HTTP_PORT = int(os.environ.get("ANTIGRAVITY_HTTP_PORT", "48329"))

# Known Google AI Endpoints
GOOGLE_AI_DOMAINS = [
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "antigravity-unleash.goog",
    "ai.studio",
    "aicode.googleapis.com",
    "oauth2.googleapis.com",
]

# Known Anycast Google Edge IPs (Frankfurt)
GOOGLE_EDGE_IPS = [
    "172.217.112.4",
    "172.217.113.4",
    "172.217.114.4",
    "172.217.115.4",
    "172.217.116.4",
    "172.217.117.4",
    "172.217.118.4",
    "172.217.119.4",
]


# ============================================================================
# 1. DNS Protocol Helpers (RFC 1035)
# ============================================================================

def encode_dns_name(domain: str) -> bytes:
    """Encode FQDN string into DNS wire format labels."""
    if not domain or domain == ".":
        return b"\x00"
    parts = domain.strip(".").split(".")
    encoded = bytearray()
    for part in parts:
        b_part = part.encode("utf-8")
        encoded.append(len(b_part))
        encoded.extend(b_part)
    encoded.append(0)
    return bytes(encoded)


def decode_dns_name(data: bytes, offset: int = 0) -> Tuple[str, int]:
    """Decode DNS labels starting at offset, handling compression pointers."""
    labels = []
    curr = offset
    jumped = False
    next_offset = offset

    while curr < len(data):
        length = data[curr]
        if length == 0:
            if not jumped:
                next_offset = curr + 1
            break
        elif (length & 0xC0) == 0xC0:
            # Compression pointer
            if curr + 1 >= len(data):
                break
            pointer = struct.unpack("!H", data[curr:curr+2])[0] & 0x3FFF
            if not jumped:
                next_offset = curr + 2
                jumped = True
            curr = pointer
        else:
            curr += 1
            if curr + length > len(data):
                break
            labels.append(data[curr:curr+length].decode("utf-8", errors="replace"))
            curr += length
            if not jumped:
                next_offset = curr

    return ".".join(labels), next_offset


def build_dns_query(domain: str, qtype: int = 1, tx_id: Optional[int] = None) -> bytes:
    """
    Construct a raw DNS query packet.
    qtype: 1=A, 28=AAAA, 65=HTTPS, 64=SVCB, 16=TXT, 15=MX
    """
    if tx_id is None:
        tx_id = random.randint(1, 65535)
    # Header: ID, Flags (RD=1: 0x0100), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", tx_id, 0x0100, 1, 0, 0, 0)
    question = encode_dns_name(domain) + struct.pack("!HH", qtype, 1)  # QCLASS=IN (1)
    return header + question


def parse_dns_response(data: bytes) -> Dict:
    """
    Parse a raw DNS response packet into structured metadata.
    """
    if len(data) < 12:
        return {"valid": False, "error": "Packet too short"}

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    qr = (flags >> 15) & 1
    opcode = (flags >> 11) & 0x0F
    aa = (flags >> 10) & 1
    tc = (flags >> 9) & 1
    rd = (flags >> 8) & 1
    ra = (flags >> 7) & 1
    rcode = flags & 0x0F

    offset = 12
    questions = []
    for _ in range(qdcount):
        if offset >= len(data):
            break
        qname, offset = decode_dns_name(data, offset)
        if offset + 4 <= len(data):
            qtype, qclass = struct.unpack("!HH", data[offset:offset+4])
            offset += 4
            questions.append({"qname": qname, "qtype": qtype, "qclass": qclass})

    answers = []
    for _ in range(ancount):
        if offset >= len(data):
            break
        aname, offset = decode_dns_name(data, offset)
        if offset + 10 <= len(data):
            rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
            offset += 10
            rdata_raw = data[offset:offset+rdlength]
            offset += rdlength

            ip_str = None
            if rtype == 1 and rdlength == 4:  # Type A
                ip_str = socket.inet_ntoa(rdata_raw)
            elif rtype == 28 and rdlength == 16:  # Type AAAA
                ip_str = socket.inet_ntop(socket.AF_INET6, rdata_raw)

            answers.append({
                "name": aname,
                "type": rtype,
                "class": rclass,
                "ttl": ttl,
                "ip": ip_str,
                "data_raw": rdata_raw
            })

    return {
        "valid": True,
        "tx_id": tx_id,
        "qr": qr,
        "opcode": opcode,
        "aa": aa,
        "tc": tc,
        "rd": rd,
        "ra": ra,
        "rcode": rcode,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "questions": questions,
        "answers": answers,
    }


def send_dns_query_udp(domain: str, server: str, port: int = 53, qtype: int = 1, timeout: float = 2.0) -> Dict:
    """Send DNS query over UDP and return parsed response."""
    packet = build_dns_query(domain, qtype)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        resp_data, _ = sock.recvfrom(4096)
        return parse_dns_response(resp_data)
    finally:
        sock.close()


def send_dns_query_tcp(domain: str, server: str, port: int = 53, qtype: int = 1, timeout: float = 2.0) -> Dict:
    """Send DNS query over TCP (with 2-byte length prefix) and return parsed response."""
    packet = build_dns_query(domain, qtype)
    prefixed = struct.pack("!H", len(packet)) + packet
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((server, port))
        sock.sendall(prefixed)
        len_prefix = sock.recv(2)
        if len(len_prefix) < 2:
            return {"valid": False, "error": "Incomplete TCP prefix"}
        resp_len = struct.unpack("!H", len_prefix)[0]
        data = bytearray()
        while len(data) < resp_len:
            chunk = sock.recv(resp_len - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return parse_dns_response(bytes(data))
    finally:
        sock.close()


# ============================================================================
# 2. TLS ClientHello & SNI Protocol Helpers (RFC 5246, 8446, 6066)
# ============================================================================

def build_tls_client_hello(
    sni_hostname: Optional[str],
    include_alpn: bool = True,
    client_version: int = 0x0303,  # TLS 1.2 / TLS 1.3 outer record
    malformed: bool = False
) -> bytes:
    """
    Construct a raw binary TLS ClientHello handshake packet.
    """
    if malformed:
        # Return invalid TLS header
        return b"\x16\x03\x01\x00\x10INVALID_TLS_DATA_STREAM"

    random_bytes = os.urandom(32)
    session_id = os.urandom(32)

    # Standard cipher suites (AES_128_GCM_SHA256, AES_256_GCM_SHA384, CHACHA20_POLY1305_SHA256)
    cipher_suites = struct.pack("!HHHH", 0x1301, 0x1302, 0x1303, 0xC02F)
    cipher_suites_len = struct.pack("!H", len(cipher_suites))

    compression = b"\x01\x00"  # 1 method: null compression

    # Extensions
    ext_data = bytearray()

    # Extension 0x0000: Server Name Indication (SNI)
    if sni_hostname is not None:
        host_bytes = sni_hostname.encode("utf-8")
        server_name = b"\x00" + struct.pack("!H", len(host_bytes)) + host_bytes
        server_name_list = struct.pack("!H", len(server_name)) + server_name
        sni_ext = struct.pack("!HH", 0x0000, len(server_name_list)) + server_name_list
        ext_data.extend(sni_ext)

    # Extension 0x0010: ALPN (Application-Layer Protocol Negotiation)
    if include_alpn:
        alpn_protocols = b"\x02h2\x08http/1.1"
        alpn_list = struct.pack("!H", len(alpn_protocols)) + alpn_protocols
        alpn_ext = struct.pack("!HH", 0x0010, len(alpn_list)) + alpn_list
        ext_data.extend(alpn_ext)

    # Extension 0x002b: Supported Versions (TLS 1.3, TLS 1.2)
    supported_versions = b"\x04\x03\x04\x03\x03"
    sv_ext = struct.pack("!HH", 0x002B, len(supported_versions)) + supported_versions
    ext_data.extend(sv_ext)

    ext_len = struct.pack("!H", len(ext_data))
    ext_payload = ext_len + ext_data

    # ClientHello body
    session_id_len = bytes([len(session_id)])
    handshake_body = (
        struct.pack("!H", client_version) +
        random_bytes +
        session_id_len + session_id +
        cipher_suites_len + cipher_suites +
        compression +
        ext_payload
    )

    # Handshake header: type=0x01 (ClientHello), 3-byte length
    handshake_header = b"\x01" + struct.pack("!I", len(handshake_body))[1:]
    handshake_record = handshake_header + handshake_body

    # TLS Record Layer: 0x16 (Handshake), Version 0x0301 (TLS 1.0 compatibility), 2-byte record len
    record_header = struct.pack("!BBH", 0x16, 0x03, 0x01) + struct.pack("!H", len(handshake_record))

    return record_header + handshake_record


def send_sni_client_hello(
    server_host: str,
    server_port: int,
    sni_hostname: Optional[str],
    timeout: float = 3.0,
    fragmented: bool = False
) -> Dict:
    """
    Send raw TLS ClientHello to an SNI proxy and inspect returned ServerHello / Google edge response.
    """
    packet = build_tls_client_hello(sni_hostname)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((server_host, server_port))

        if fragmented:
            # Send 5-byte header first, then remainder
            sock.sendall(packet[:5])
            time.sleep(0.05)
            sock.sendall(packet[5:])
        else:
            sock.sendall(packet)

        # Receive initial Server response
        resp = sock.recv(4096)
        if not resp:
            return {"connected": True, "received_bytes": 0, "status": "CLOSED_BY_PEER"}

        # Inspect if response is a valid TLS ServerHello (0x16 Handshake, 0x02 ServerHello)
        is_tls = len(resp) >= 5 and resp[0] == 0x16
        is_server_hello = len(resp) >= 6 and resp[0] == 0x16 and resp[5] == 0x02

        return {
            "connected": True,
            "received_bytes": len(resp),
            "is_tls": is_tls,
            "is_server_hello": is_server_hello,
            "raw_preview": resp[:32].hex(),
            "status": "OK" if is_tls else "NON_TLS_RESPONSE"
        }
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError) as e:
        return {"connected": False, "error": str(e), "status": "FAILED"}
    finally:
        sock.close()


# ============================================================================
# 3. SOCKS5 Proxy Helpers (RFC 1928, RFC 1929)
# ============================================================================

def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
    dest_is_domain: bool = True,
    timeout: float = 3.0
) -> Dict:
    """
    Perform SOCKS5 handshake, authentication (if required), and CONNECT command.
    Returns socket connection and status.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((proxy_host, proxy_port))

        # Greeting: Methods
        if username is not None and password is not None:
            # Methods: 0x00 (NO AUTH) and 0x02 (USER/PASS)
            sock.sendall(b"\x05\x02\x00\x02")
        else:
            sock.sendall(b"\x05\x01\x00")

        method_resp = sock.recv(2)
        if len(method_resp) < 2 or method_resp[0] != 0x05:
            sock.close()
            return {"success": False, "error": "Invalid SOCKS5 greeting response", "sock": None}

        chosen_method = method_resp[1]
        if chosen_method == 0xFF:
            sock.close()
            return {"success": False, "error": "No acceptable authentication methods", "sock": None}

        # Subnegotiation for Username/Password (RFC 1929)
        if chosen_method == 0x02:
            if username is None or password is None:
                sock.close()
                return {"success": False, "error": "Proxy requires auth, but none provided", "sock": None}

            u_bytes = username.encode("utf-8")
            p_bytes = password.encode("utf-8")
            auth_req = b"\x01" + bytes([len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes
            sock.sendall(auth_req)

            auth_resp = sock.recv(2)
            if len(auth_resp) < 2 or auth_resp[1] != 0x00:
                sock.close()
                return {"success": False, "error": "SOCKS5 authentication failed", "auth_status": auth_resp[1] if len(auth_resp) >= 2 else None, "sock": None}

        # CONNECT Request (CMD=0x01)
        if dest_is_domain:
            host_bytes = dest_host.encode("utf-8")
            req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", dest_port)
        else:
            ipv4_bytes = socket.inet_aton(dest_host)
            req = b"\x05\x01\x00\x01" + ipv4_bytes + struct.pack("!H", dest_port)

        sock.sendall(req)
        conn_resp = sock.recv(10)
        if len(conn_resp) < 4 or conn_resp[0] != 0x05:
            sock.close()
            return {"success": False, "error": "Invalid SOCKS5 connect response", "sock": None}

        rep = conn_resp[1]
        if rep != 0x00:
            sock.close()
            return {"success": False, "error": f"SOCKS5 connect error REP={rep}", "rep": rep, "sock": None}

        return {"success": True, "rep": 0, "sock": sock}

    except Exception as e:
        sock.close()
        return {"success": False, "error": str(e), "sock": None}


# ============================================================================
# 4. HTTP CONNECT Proxy Helpers (RFC 7231 / RFC 9110)
# ============================================================================

def http_connect_tunnel(
    proxy_host: str,
    proxy_port: int,
    dest_host: str,
    dest_port: int,
    username: Optional[str] = None,
    password: Optional[str] = None,
    timeout: float = 3.0
) -> Dict:
    """
    Establish HTTP CONNECT tunnel to destination through proxy.
    Returns status line, headers, and active socket for bidirectional streaming.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        sock.connect((proxy_host, proxy_port))

        req_lines = [
            f"CONNECT {dest_host}:{dest_port} HTTP/1.1",
            f"Host: {dest_host}:{dest_port}",
        ]

        if username is not None and password is not None:
            creds = f"{username}:{password}".encode("utf-8")
            b64_creds = base64.b64encode(creds).decode("ascii")
            req_lines.append(f"Proxy-Authorization: Basic {b64_creds}")

        req_lines.append("\r\n")
        req_data = "\r\n".join(req_lines).encode("utf-8")
        sock.sendall(req_data)

        # Read HTTP status response
        response_bytes = bytearray()
        while b"\r\n\r\n" not in response_bytes:
            chunk = sock.recv(1024)
            if not chunk:
                break
            response_bytes.extend(chunk)

        header_part = bytes(response_bytes).split(b"\r\n\r\n")[0].decode("utf-8", errors="replace")
        status_line = header_part.split("\r\n")[0] if header_part else ""

        # Parse status code
        status_code = None
        parts = status_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])

        if status_code == 200:
            return {
                "success": True,
                "status_code": status_code,
                "status_line": status_line,
                "headers": header_part,
                "sock": sock
            }
        else:
            sock.close()
            return {
                "success": False,
                "status_code": status_code,
                "status_line": status_line,
                "headers": header_part,
                "sock": None
            }

    except Exception as e:
        sock.close()
        return {"success": False, "error": str(e), "sock": None}


# ============================================================================
# 5. Socket Port Probing & Subprocess Utilities
# ============================================================================

def is_tcp_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a TCP port is currently listening and accepting connections."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        s.close()


def is_udp_dns_responsive(host: str, port: int, timeout: float = 0.5) -> bool:
    """Check if a DNS server responds on UDP port."""
    try:
        res = send_dns_query_udp("daily-cloudcode-pa.googleapis.com", host, port, timeout=timeout)
        return res.get("valid", False)
    except Exception:
        return False


def run_command_capture(
    cmd: List[str],
    env: Optional[Dict[str, str]] = None,
    timeout: float = 20.0,
    cwd: Optional[Union[str, Path]] = None,
) -> Tuple[int, str, str]:
    """Execute command in subprocess and capture exit code, stdout, stderr."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)

    try:
        proc = subprocess.run(
            cmd,
            env=merged_env,
            cwd=str(cwd) if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)
