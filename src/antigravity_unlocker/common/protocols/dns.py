"""
dns.py - RFC 1035 wire-format encoder, decoder, and synthesizer.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from antigravity_unlocker.common.exceptions import DNSProtocolError

# DNS Record Type Constants
QTYPE_A = 1
QTYPE_AAAA = 28
QTYPE_SVCB = 64
QTYPE_HTTPS = 65

# DNS RCODE Constants
RCODE_NOERROR = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3


@dataclass
class DNSQuestion:
    name: str
    qtype: int
    qclass: int = 1


@dataclass
class DNSRecord:
    name: str
    rtype: int
    rclass: int = 1
    ttl: int = 60
    rdata: bytes = b""
    ip: Optional[str] = None


@dataclass
class DNSPacket:
    tx_id: int
    flags: int
    questions: List[DNSQuestion] = field(default_factory=list)
    answers: List[DNSRecord] = field(default_factory=list)
    raw_query: bytes = b""

    @property
    def rcode(self) -> int:
        return self.flags & 0x000F

    @property
    def is_query(self) -> bool:
        return (self.flags & 0x8000) == 0


def encode_dns_name(domain: str) -> bytes:
    """Encodes a dot-separated domain into DNS wire format labels."""
    if not domain or domain == ".":
        return b"\x00"
    clean = domain.strip().rstrip(".")
    out = bytearray()
    for label in clean.split("."):
        enc = label.encode("ascii", errors="replace")
        if len(enc) > 63:
            raise DNSProtocolError(f"DNS label too long: {len(enc)} bytes")
        out.append(len(enc))
        out.extend(enc)
    out.append(0)
    return bytes(out)


def decode_dns_name(data: bytes, offset: int = 0) -> Tuple[str, int]:
    """Decodes a DNS name from wire format with pointer compression support."""
    labels: List[str] = []
    curr = offset
    visited_ptrs = set()
    initial_length: Optional[int] = None

    while True:
        if curr >= len(data):
            raise DNSProtocolError("Malformed DNS packet: truncated name")
        length = data[curr]

        # Check for pointer (top two bits set: 0xC0)
        if (length & 0xC0) == 0xC0:
            if curr + 1 >= len(data):
                raise DNSProtocolError("Malformed DNS packet: truncated compression pointer")
            ptr_offset = ((length & 0x3F) << 8) | data[curr + 1]
            if initial_length is None:
                initial_length = curr + 2 - offset
            if ptr_offset in visited_ptrs or ptr_offset >= len(data):
                raise DNSProtocolError(f"DNS compression loop detected at pointer {ptr_offset}")
            visited_ptrs.add(ptr_offset)
            curr = ptr_offset
            continue

        if length == 0:
            curr += 1
            if initial_length is None:
                initial_length = curr - offset
            break

        curr += 1
        if curr + length > len(data):
            raise DNSProtocolError("Malformed DNS packet: label exceeds packet length")
        labels.append(data[curr : curr + length].decode("ascii", errors="replace"))
        curr += length

    name = ".".join(labels).lower()
    return name, (initial_length if initial_length is not None else (curr - offset))


def parse_dns_query(data: bytes) -> DNSPacket:
    """Parses a raw RFC 1035 DNS query packet."""
    if len(data) < 12:
        raise DNSProtocolError(f"Truncated DNS packet: {len(data)} bytes (minimum 12)")

    tx_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(">HHHHHH", data[:12])
    packet = DNSPacket(tx_id=tx_id, flags=flags, raw_query=data)

    offset = 12
    for _ in range(qdcount):
        name, consumed = decode_dns_name(data, offset)
        offset += consumed
        if offset + 4 > len(data):
            raise DNSProtocolError("Truncated question section")
        qtype, qclass = struct.unpack(">HH", data[offset : offset + 4])
        offset += 4
        packet.questions.append(DNSQuestion(name=name, qtype=qtype, qclass=qclass))

    return packet


def build_dns_query(domain: str, qtype: int = 1, tx_id: Optional[int] = None) -> bytes:
    """Builds a standard RFC 1035 UDP DNS query packet."""
    t_id = random.randint(1, 65535) if tx_id is None else tx_id
    flags = 0x0100  # Recursion Desired
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack(">HHHHHH", t_id, flags, qdcount, ancount, nscount, arcount)
    qname = encode_dns_name(domain)
    question = qname + struct.pack(">HH", qtype, 1)  # QTYPE, QCLASS=IN
    return header + question


def build_dns_a_response(
    query_packet: DNSPacket,
    ip_address: str,
    ttl: int = 60,
) -> bytes:
    """Synthesizes an authoritative A-record DNS response."""
    tx_id = query_packet.tx_id
    # Flags: QR=1 (response), AA=1 (authoritative), RD=1, RA=1, RCODE=0
    flags = 0x8580
    qdcount = len(query_packet.questions)
    ancount = 1
    nscount = 0
    arcount = 0

    header = struct.pack(">HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    # Question section echoed verbatim
    if query_packet.questions:
        q = query_packet.questions[0]
        qname_bytes = encode_dns_name(q.name)
        question_section = qname_bytes + struct.pack(">HH", q.qtype, q.qclass)
    else:
        question_section = b""

    # Answer section: pointer to question name (0xC00C), Type=1, Class=1, TTL, DataLen=4, IP
    answer_ptr = b"\xc0\x0c"
    ip_parts = [int(p) for p in ip_address.split(".")]
    ip_bytes = struct.pack(">BBBB", *ip_parts)
    answer_section = answer_ptr + struct.pack(">HHIH", QTYPE_A, 1, ttl, 4) + ip_bytes

    return header + question_section + answer_section


def build_nodata_response(query_packet: DNSPacket) -> bytes:
    """
    Synthesizes a NODATA response (RCODE=NOERROR, ANCOUNT=0).
    Suppresses IPv6 AAAA and Type 65 (HTTPS/SVCB) queries to prevent Encrypted Client Hello (ECH).
    """
    tx_id = query_packet.tx_id
    # Flags: QR=1, AA=1, RD=1, RA=1, RCODE=0 (NOERROR)
    flags = 0x8580
    qdcount = len(query_packet.questions)
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack(">HHHHHH", tx_id, flags, qdcount, ancount, nscount, arcount)

    if query_packet.questions:
        q = query_packet.questions[0]
        qname_bytes = encode_dns_name(q.name)
        question_section = qname_bytes + struct.pack(">HH", q.qtype, q.qclass)
    else:
        question_section = b""

    return header + question_section
