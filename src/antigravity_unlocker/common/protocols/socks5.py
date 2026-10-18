"""
socks5.py - RFC 1928 / RFC 1929 SOCKS5 wire-format codecs and handlers.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import socket
import struct
from typing import List, Optional, Tuple


def parse_socks5_greeting(data: bytes) -> Tuple[Optional[int], List[int]]:
    """Parses SOCKS5 client greeting. Returns (version, auth_methods)."""
    if len(data) < 2:
        return None, []
    ver, nmethods = data[0], data[1]
    if len(data) < 2 + nmethods:
        return None, []
    return ver, list(data[2 : 2 + nmethods])


def parse_socks5_auth(data: bytes) -> Tuple[Optional[str], Optional[str]]:
    """Parses RFC 1929 username/password auth packet. Returns (username, password)."""
    if len(data) < 2:
        return None, None
    auth_ver = data[0]
    if auth_ver != 1:
        return None, None
    ulen = data[1]
    if len(data) < 2 + ulen + 1:
        return None, None
    uname = data[2 : 2 + ulen].decode("utf-8", errors="replace")
    plen = data[2 + ulen]
    if len(data) < 3 + ulen + plen:
        return None, None
    passwd = data[3 + ulen : 3 + ulen + plen].decode("utf-8", errors="replace")
    return uname, passwd


def parse_socks5_request(
    data: bytes,
) -> Tuple[Optional[int], Optional[int], Optional[str], Optional[int]]:
    """
    Parses SOCKS5 request packet.
    Returns (cmd, atyp, dst_addr, dst_port).
    """
    if len(data) < 4:
        return None, None, None, None
    ver, cmd, rsv, atyp = data[0], data[1], data[2], data[3]
    if ver != 5:
        return None, None, None, None

    pos = 4
    if atyp == 1:  # IPv4 (4 bytes)
        if len(data) < pos + 4 + 2:
            return None, None, None, None
        dst_addr = socket.inet_ntoa(data[pos : pos + 4])
        pos += 4
    elif atyp == 3:  # Domain name (1 byte length + domain)
        if len(data) < pos + 1:
            return None, None, None, None
        dlen = data[pos]
        pos += 1
        if len(data) < pos + dlen + 2:
            return None, None, None, None
        dst_addr = data[pos : pos + dlen].decode("utf-8", errors="replace")
        pos += dlen
    elif atyp == 4:  # IPv6 (16 bytes)
        if len(data) < pos + 16 + 2:
            return None, None, None, None
        dst_addr = socket.inet_ntop(socket.AF_INET6, data[pos : pos + 16])
        pos += 16
    else:
        return None, None, None, None

    dst_port = struct.unpack(">H", data[pos : pos + 2])[0]
    return cmd, atyp, dst_addr, dst_port


def build_socks5_reply(
    rep: int = 0,
    bind_ip: str = "0.0.0.0",
    bind_port: int = 0,
) -> bytes:
    try:
        addr_bytes = socket.inet_aton(bind_ip)
    except (OSError, ValueError):
        addr_bytes = b"\x00\x00\x00\x00"
    port_bytes = struct.pack(">H", bind_port)
    return b"\x05" + bytes([rep]) + b"\x00\x01" + addr_bytes + port_bytes
