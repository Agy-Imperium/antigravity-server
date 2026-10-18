"""
http_connect.py - RFC 7231 HTTP CONNECT parser & response generator.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import base64
from typing import Optional, Tuple


def parse_http_connect_request(
    data: bytes,
) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    """
    Parses an HTTP CONNECT request header.
    Returns (target_host, target_port, auth_header_value).
    """
    try:
        header_text = data.decode("utf-8", errors="replace")
    except Exception:
        return None, None, None

    lines = header_text.split("\r\n")
    if not lines or not lines[0]:
        lines = header_text.split("\n")

    request_line = lines[0].strip()
    parts = request_line.split()
    if len(parts) < 2 or parts[0].upper() != "CONNECT":
        return None, None, None

    authority = parts[1]
    if authority.startswith("["):
        if "]:" in authority:
            h_part, p_part = authority.split("]:", 1)
            host = h_part[1:]
            try:
                port = int(p_part)
            except ValueError:
                return None, None, None
        elif authority.endswith("]"):
            host = authority[1:-1]
            port = 443
        else:
            return None, None, None
    elif ":" in authority:
        host, port_str = authority.rsplit(":", 1)
        try:
            port = int(port_str)
        except ValueError:
            return None, None, None
    else:
        host = authority
        port = 443

    auth_val: Optional[str] = None
    for line in lines[1:]:
        if ":" in line:
            name, val = line.split(":", 1)
            if name.strip().lower() == "proxy-authorization":
                auth_val = val.strip()
                break

    return host, port, auth_val


def parse_basic_auth(auth_header: str) -> Tuple[Optional[str], Optional[str]]:
    """Extracts (username, password) from 'Basic <base64>' authorization header."""
    if not auth_header.lower().startswith("basic "):
        return None, None
    b64_part = auth_header[6:].strip()
    try:
        decoded = base64.b64decode(b64_part).decode("utf-8", errors="replace")
        if ":" in decoded:
            u, p = decoded.split(":", 1)
            return u, p
        return decoded, ""
    except Exception:
        return None, None


def build_http_connect_response(
    status_code: int = 200,
    reason: str = "Connection Established",
) -> bytes:
    """Builds an HTTP CONNECT status response."""
    if status_code == 200:
        return f"HTTP/1.1 200 {reason}\r\n\r\n".encode("ascii")
    elif status_code == 407:
        return (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b'Proxy-Authenticate: Basic realm="Antigravity"\r\n'
            b"Content-Length: 0\r\n\r\n"
        )
    elif status_code == 400:
        return b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
    elif status_code == 403:
        return b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
    elif status_code == 502:
        return b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"
    elif status_code == 504:
        return b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n"
    else:
        return f"HTTP/1.1 {status_code} {reason}\r\nContent-Length: 0\r\n\r\n".encode("ascii")
