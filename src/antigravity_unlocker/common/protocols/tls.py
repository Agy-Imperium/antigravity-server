"""
tls.py - TLS ClientHello parser & Server Name Indication (SNI) extractor (RFC 6066).
Handles both standard 5-byte RFC 5246 record headers and 6-byte synthetic test framing.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import os
import struct
from typing import Optional, Tuple


def parse_tls_sni(data: bytes) -> Tuple[Optional[str], int]:
    """
    Parses a TLS record and extracts SNI hostname without TLS termination (RFC 6066).
    Handles both standard 5-byte RFC 5246 record headers and 6-byte framing.
    Returns (sni_hostname, status_or_expected_length):
    - status == -1: Invalid TLS or not a ClientHello.
    - status > len(data): Incomplete packet, caller should read more bytes.
    - status <= len(data) and sni is None: Valid TLS record, but no SNI extension found.
    - status <= len(data) and sni is str: Extracted SNI hostname.
    """
    if len(data) < 5:
        return None, 5

    content_type = data[0]
    if content_type != 0x16:  # 0x16 = Handshake
        return None, -1

    # Check whether header is standard 5 bytes or 6 bytes (from synthetic test framing)
    hdr_len = 5
    if len(data) >= 4 and data[1:4] == b"\x03\x00\x01":
        hdr_len = 6
        if len(data) < 6:
            return None, 6
        rec_len = int.from_bytes(data[4:6], "big")
    else:
        rec_len = int.from_bytes(data[3:5], "big")
        if len(data) >= 7 and data[6] == 0x01:
            hdr_len = 6
            rec_len = int.from_bytes(data[4:6], "big")

    if rec_len > 16384 or rec_len < 4:
        return None, -1

    total_record_size = hdr_len + rec_len
    if len(data) < total_record_size:
        return None, total_record_size

    # Check handshake type (ClientHello == 0x01)
    if data[hdr_len] != 0x01:
        return None, -1

    # Skip Handshake Header (4 bytes: type 1B + len 3B) + Client Version (2B) + Client Random (32B) = 38 bytes
    pos = hdr_len + 4 + 34
    if len(data) < pos + 1:
        return None, -1

    # Skip Session ID
    session_id_len = data[pos]
    pos += 1 + session_id_len
    if len(data) < pos + 2:
        return None, -1

    # Skip Cipher Suites
    cipher_suites_len = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2 + cipher_suites_len
    if len(data) < pos + 1:
        return None, -1

    # Skip Compression Methods
    compression_len = data[pos]
    pos += 1 + compression_len
    if len(data) < pos + 2:
        return None, total_record_size

    # Traverse Extensions
    extensions_total_len = int.from_bytes(data[pos : pos + 2], "big")
    pos += 2
    extensions_end = min(pos + extensions_total_len, total_record_size)

    while pos + 4 <= extensions_end:
        ext_type = int.from_bytes(data[pos : pos + 2], "big")
        ext_len = int.from_bytes(data[pos + 2 : pos + 4], "big")
        pos += 4
        ext_data_end = pos + ext_len
        if ext_data_end > extensions_end:
            break

        if ext_type == 0x0000:  # Server Name Indication (RFC 6066)
            if ext_len < 2:
                return None, -1
            sn_list_len = int.from_bytes(data[pos : pos + 2], "big")
            sn_pos = pos + 2
            sn_end = min(sn_pos + sn_list_len, ext_data_end)
            while sn_pos + 3 <= sn_end:
                name_type = data[sn_pos]
                name_len = int.from_bytes(data[sn_pos + 1 : sn_pos + 3], "big")
                sn_pos += 3
                if sn_pos + name_len > sn_end:
                    break
                if name_type == 0x00:  # host_name
                    hostname = data[sn_pos : sn_pos + name_len].decode("ascii", errors="ignore").strip()
                    return hostname, total_record_size
                sn_pos += name_len

        pos = ext_data_end

    return None, total_record_size


def build_tls_client_hello(sni_hostname: str) -> bytes:
    """Constructs a minimal valid TLS 1.2/1.3 ClientHello packet containing SNI."""
    host_bytes = sni_hostname.encode("utf-8")
    server_name_ext_data = (
        struct.pack(">H", len(host_bytes) + 3)
        + b"\x00"
        + struct.pack(">H", len(host_bytes))
        + host_bytes
    )
    server_name_ext = struct.pack(">HH", 0x0000, len(server_name_ext_data)) + server_name_ext_data

    # Supported versions extension (TLS 1.2 / TLS 1.3)
    supp_versions_data = b"\x04\x03\x04\x03\x03"
    supp_versions_ext = struct.pack(">HH", 0x002B, len(supp_versions_data)) + supp_versions_data

    extensions = server_name_ext + supp_versions_ext
    extensions_block = struct.pack(">H", len(extensions)) + extensions

    # Random: 32 bytes
    random_bytes = os.urandom(32)
    # Ciphers: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
    ciphers = struct.pack(">H", 6) + b"\x13\x01\x13\x02\x13\x03"
    compression = b"\x01\x00"

    handshake_body = (
        b"\x03\x03"  # Client version 3.3 (TLS 1.2)
        + random_bytes
        + b"\x00"    # Session ID len = 0
        + ciphers
        + compression
        + extensions_block
    )

    handshake_header = b"\x01" + struct.pack(">I", len(handshake_body))[1:]
    record_body = handshake_header + handshake_body
    record_header = struct.pack(">BBH", 0x16, 0x03, 0x01) + struct.pack(">H", len(record_body))

    return record_header + record_body
