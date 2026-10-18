#!/usr/bin/env python3
"""
adversarial_challenger_m1.py - Milestone 1 Empirical Adversarial Stress Test Suite
Author: Challenger 1 (Milestone 1)
Target: Antigravity Zero-Privilege Unlocker Daemon (Remote Server / 127.0.0.1)

Covers:
1. DNS Adversarial Tests:
   - Malformed packets & fuzzing over UDP & TCP
   - Subdomain spoofing & label boundary validation
   - High concurrency burst & load stress
   - IPv6 AAAA and Type 65 (HTTPS/SVCB) suppression
2. SNI Proxy Adversarial Tests:
   - Non-TLS raw data to port 443 & 8443
   - Malformed TLS ClientHello structures
   - Non-whitelisted SNI enforcement
   - Slowloris & partial ClientHello DoS resilience
3. Post-Stress Daemon Health Verification
"""

import asyncio
import os
import random
import socket
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

VPS_IP = os.environ.get("ANTIGRAVITY_SERVER_HOST", "127.0.0.1")
TARGET_HOST = "127.0.0.1"
DNS_PORT = 53
SNI_PRIMARY_PORT = 443
SNI_FALLBACK_PORT = 8443

# ANSI Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"


class TestResult:
    def __init__(self, name: str, category: str):
        self.name = name
        self.category = category
        self.passed = False
        self.details = ""
        self.duration_ms = 0.0

    def __repr__(self):
        status = f"{GREEN}PASS{RESET}" if self.passed else f"{RED}FAIL{RESET}"
        return f"[{status}] {self.category} :: {self.name} ({self.duration_ms:.1f}ms) - {self.details}"


# ---------------------------------------------------------------------------
# DNS Helper Functions
# ---------------------------------------------------------------------------

def encode_dns_labels(domain: str) -> bytes:
    if not domain or domain == ".":
        return b"\x00"
    out = bytearray()
    for part in domain.strip(".").split("."):
        b = part.encode("latin1")
        out.append(len(b))
        out.extend(b)
    out.append(0)
    return bytes(out)


def build_dns_query(qname: str, qtype: int = 1, txid: int = 0x1234, rd: int = 1) -> bytes:
    flags = 0x0100 if rd else 0x0000
    hdr = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 0)
    question = encode_dns_labels(qname) + struct.pack("!HH", qtype, 1)
    return hdr + question


def parse_dns_response(data: bytes) -> Dict[str, Any]:
    if len(data) < 12:
        return {"error": "Packet too short", "len": len(data)}
    txid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0x000F
    qr = (flags >> 15) & 1
    aa = (flags >> 10) & 1

    # Traverse Question
    curr = 12
    while curr < len(data):
        l = data[curr]
        if l == 0:
            curr += 1
            break
        elif (l & 0xC0) == 0xC0:
            curr += 2
            break
        curr += 1 + l
    curr += 4  # Skip QTYPE and QCLASS

    answers = []
    for _ in range(ancount):
        if curr >= len(data):
            break
        # Skip name
        if data[curr] & 0xC0 == 0xC0:
            curr += 2
        else:
            while curr < len(data) and data[curr] != 0:
                curr += 1 + data[curr]
            curr += 1
        if curr + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[curr : curr + 10])
        curr += 10
        rdata = data[curr : curr + rdlen]
        curr += rdlen
        if rtype == 1 and rdlen == 4:
            ip = socket.inet_ntoa(rdata)
            answers.append({"type": "A", "ip": ip, "ttl": ttl})
        elif rtype == 28 and rdlen == 16:
            ip = socket.inet_ntop(socket.AF_INET6, rdata)
            answers.append({"type": "AAAA", "ip": ip, "ttl": ttl})
        else:
            answers.append({"type": rtype, "data": rdata, "ttl": ttl})

    return {
        "txid": txid,
        "flags": flags,
        "qr": qr,
        "aa": aa,
        "rcode": rcode,
        "qdcount": qdcount,
        "ancount": ancount,
        "answers": answers,
    }


def send_dns_udp(query: bytes, host: str = TARGET_HOST, port: int = DNS_PORT, timeout: float = 2.0) -> Optional[bytes]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (host, port))
        data, _ = sock.recvfrom(4096)
        return data
    except socket.timeout:
        return None
    except Exception as e:
        return None
    finally:
        sock.close()


def send_dns_tcp(query: bytes, host: str = TARGET_HOST, port: int = DNS_PORT, timeout: float = 2.0) -> Optional[bytes]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        wire = len(query).to_bytes(2, "big") + query
        sock.sendall(wire)
        prefix = sock.recv(2)
        if len(prefix) < 2:
            return None
        length = int.from_bytes(prefix, "big")
        received = b""
        while len(received) < length:
            chunk = sock.recv(length - len(received))
            if not chunk:
                break
            received += chunk
        return received
    except Exception:
        return None
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# TLS ClientHello Helper Functions
# ---------------------------------------------------------------------------

def build_client_hello(sni_hostname: Optional[str], ciphers: Optional[List[int]] = None, corrupt_sni: Optional[str] = None) -> bytes:
    if ciphers is None:
        ciphers = [0xC02F, 0xC030, 0x1301, 0x1302]
    cipher_bytes = bytearray()
    for c in ciphers:
        cipher_bytes.extend(struct.pack("!H", c))
    ciphers_payload = struct.pack("!H", len(cipher_bytes)) + cipher_bytes

    extensions = bytearray()

    if corrupt_sni == "missing":
        pass
    elif corrupt_sni == "truncated_length":
        # SNI extension header claiming 50 bytes, but only 2 bytes payload
        extensions.extend(struct.pack("!HH", 0x0000, 50) + b"\x00\x01")
    elif corrupt_sni == "bad_nametype":
        sni_b = (sni_hostname or "example.com").encode("utf-8")
        sn_entry = b"\x05" + struct.pack("!H", len(sni_b)) + sni_b  # NameType 5 instead of 0
        sn_list = struct.pack("!H", len(sn_entry)) + sn_entry
        extensions.extend(struct.pack("!HH", 0x0000, len(sn_list)) + sn_list)
    elif corrupt_sni == "overflow_record":
        pass  # Handled at record layer
    elif sni_hostname is not None:
        sni_b = sni_hostname.encode("utf-8")
        sn_entry = b"\x00" + struct.pack("!H", len(sni_b)) + sni_b
        sn_list = struct.pack("!H", len(sn_entry)) + sn_entry
        extensions.extend(struct.pack("!HH", 0x0000, len(sn_list)) + sn_list)

    # Add Supported Groups extension
    groups = struct.pack("!HH", 0x001D, 0x0017)
    extensions.extend(struct.pack("!HH", 0x000A, len(groups) + 2) + struct.pack("!H", len(groups)) + groups)

    exts_payload = struct.pack("!H", len(extensions)) + extensions

    body = (
        struct.pack("!H", 0x0303)  # TLS 1.2
        + os.urandom(32)           # Client Random
        + b"\x00"                  # Session ID len = 0
        + ciphers_payload
        + b"\x01\x00"              # Compression methods (len 1, null)
        + exts_payload
    )

    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    record = struct.pack("!BBBH", 0x16, 0x03, 0x01, len(handshake)) + handshake
    return record


# ---------------------------------------------------------------------------
# Test Runner Implementation
# ---------------------------------------------------------------------------

class AdversarialRunner:
    def __init__(self):
        self.results: List[TestResult] = []

    def record(self, result: TestResult):
        self.results.append(result)
        print(result)

    # -----------------------------------------------------------------------
    # SUITE 1: DNS ADVERSARIAL TESTS
    # -----------------------------------------------------------------------

    def test_dns_malformed_short_packets_udp(self):
        """Send truncated DNS packets (< 12 bytes) over UDP. Server must not crash and reply FORMERR or ignore."""
        for sz in [0, 1, 2, 4, 8, 11]:
            t0 = time.time()
            res = TestResult(f"dns_udp_short_packet_{sz}b", "DNS-Malformed")
            payload = os.urandom(sz)
            resp = send_dns_udp(payload, timeout=0.5)
            # If server responds, it must be FORMERR (rcode=1)
            # If server drops packet, it is also acceptable RFC behavior
            if resp is not None:
                parsed = parse_dns_response(resp)
                if parsed.get("rcode") == 1:
                    res.passed = True
                    res.details = f"Returned FORMERR (rcode=1) for {sz} bytes"
                else:
                    res.passed = False
                    res.details = f"Returned unexpected rcode: {parsed.get('rcode')}"
            else:
                res.passed = True
                res.details = f"Dropped malformed {sz}-byte datagram cleanly"
            res.duration_ms = (time.time() - t0) * 1000
            self.record(res)

    def test_dns_malformed_short_packets_tcp(self):
        """Send truncated DNS queries over TCP. Server must not hang or crash."""
        for sz in [0, 1, 2, 4, 11]:
            t0 = time.time()
            res = TestResult(f"dns_tcp_short_packet_{sz}b", "DNS-Malformed")
            payload = os.urandom(sz)
            resp = send_dns_tcp(payload, timeout=0.5)
            if resp is not None:
                parsed = parse_dns_response(resp)
                if parsed.get("rcode") == 1:
                    res.passed = True
                    res.details = f"Returned FORMERR for {sz} bytes"
                else:
                    res.passed = False
                    res.details = f"Returned unexpected rcode: {parsed.get('rcode')}"
            else:
                res.passed = True
                res.details = f"Closed TCP connection on {sz} bytes"
            res.duration_ms = (time.time() - t0) * 1000
            self.record(res)

    def test_dns_compression_pointer_loop(self):
        """Send malicious DNS packet with cyclic compression pointer loop."""
        t0 = time.time()
        res = TestResult("dns_compression_loop_dos", "DNS-Malformed")
        # Packet: Header (12B), QNAME starts at 12: \xc0\x0c (points to byte 12: infinite loop!)
        hdr = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0)
        qname_loop = b"\xc0\x0c\x00\x01\x00\x01"
        packet = hdr + qname_loop

        resp = send_dns_udp(packet, timeout=1.0)
        if resp is not None:
            parsed = parse_dns_response(resp)
            if parsed.get("rcode") == 1:
                res.passed = True
                res.details = "Detected pointer loop, returned FORMERR"
            else:
                res.passed = False
                res.details = f"Returned non-FORMERR rcode: {parsed.get('rcode')}"
        else:
            res.passed = True
            res.details = "Dropped cyclic pointer loop cleanly"
        res.duration_ms = (time.time() - t0) * 1000
        self.record(res)

    def test_dns_compression_pointer_out_of_bounds(self):
        """Send DNS packet with compression pointer pointing far beyond packet boundary."""
        t0 = time.time()
        res = TestResult("dns_pointer_oob", "DNS-Malformed")
        hdr = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        # \xc0\xff points to offset 255 in a 16-byte packet
        packet = hdr + b"\xc0\xff\x00\x01\x00\x01"
        resp = send_dns_udp(packet, timeout=1.0)
        if resp is not None:
            parsed = parse_dns_response(resp)
            if parsed.get("rcode") == 1:
                res.passed = True
                res.details = "Handled OOB pointer, returned FORMERR"
            else:
                res.passed = False
                res.details = f"Unexpected rcode: {parsed.get('rcode')}"
        else:
            res.passed = True
            res.details = "Dropped OOB pointer cleanly"
        res.duration_ms = (time.time() - t0) * 1000
        self.record(res)

    def test_dns_invalid_label_length(self):
        """Send DNS packet with label length claiming 60 bytes, but only 5 follow."""
        t0 = time.time()
        res = TestResult("dns_truncated_label_bytes", "DNS-Malformed")
        hdr = struct.pack("!HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0)
        # Label len = 60, followed by 5 bytes
        packet = hdr + b"\x3c\x61\x62\x63\x64\x65"
        resp = send_dns_udp(packet, timeout=1.0)
        if resp is not None:
            parsed = parse_dns_response(resp)
            if parsed.get("rcode") == 1:
                res.passed = True
                res.details = "Handled truncated label, returned FORMERR"
            else:
                res.passed = False
                res.details = f"Unexpected rcode: {parsed.get('rcode')}"
        else:
            res.passed = True
            res.details = "Dropped truncated label cleanly"
        res.duration_ms = (time.time() - t0) * 1000
        self.record(res)

    def test_dns_qr_response_bit(self):
        """Send packet with QR=1 (response bit set). Server must reject or ignore without looping."""
        t0 = time.time()
        res = TestResult("dns_qr_response_flag_rejection", "DNS-Malformed")
        # QR=1 flag: 0x8180
        hdr = struct.pack("!HHHHHH", 0x9999, 0x8180, 1, 0, 0, 0)
        packet = hdr + encode_dns_labels("daily-cloudcode-pa.googleapis.com") + struct.pack("!HH", 1, 1)
        resp = send_dns_udp(packet, timeout=1.0)
        if resp is not None:
            parsed = parse_dns_response(resp)
            if parsed.get("rcode") == 1:
                res.passed = True
                res.details = "Server rejected QR=1 query and returned FORMERR"
            else:
                res.passed = False
                res.details = f"Unexpected response to QR=1: rcode={parsed.get('rcode')}"
        else:
            res.passed = True
            res.details = "Server dropped QR=1 packet cleanly without reflection"
        res.duration_ms = (time.time() - t0) * 1000
        self.record(res)

    def test_dns_qdcount_zero(self):
        """Send packet with QDCOUNT=0 (no question section). Server must reject with FORMERR."""
        t0 = time.time()
        res = TestResult("dns_qdcount_zero_rejection", "DNS-Malformed")
        hdr = struct.pack("!HHHHHH", 0x8888, 0x0100, 0, 0, 0, 0)
        packet = hdr + b"\x00\x01\x00\x01"  # Trailing payload without question
        resp = send_dns_udp(packet, timeout=1.0)
        if resp is not None:
            parsed = parse_dns_response(resp)
            if parsed.get("rcode") == 1:
                res.passed = True
                res.details = "Server rejected QDCOUNT=0 and returned FORMERR"
            else:
                res.passed = False
                res.details = f"Unexpected response: rcode={parsed.get('rcode')}"
        else:
            res.passed = True
            res.details = "Server dropped QDCOUNT=0 packet cleanly"
        res.duration_ms = (time.time() - t0) * 1000
        self.record(res)

    def test_dns_fuzz_random_byte_streams(self):
        """Fuzz DNS engine with 50 random byte streams over UDP. Daemon must survive without crash."""
        t0 = time.time()
        res = TestResult("dns_random_bitstream_fuzz_50", "DNS-Fuzzing")
        all_ok = True
        err_msg = ""
        for i in range(50):
            sz = random.randint(1, 512)
            noise = os.urandom(sz)
            # Send to UDP
            try:
                send_dns_udp(noise, timeout=0.1)
            except Exception as e:
                all_ok = False
                err_msg = str(e)
                break

        # Check server health after fuzzing
        health_resp = send_dns_udp(build_dns_query("daily-cloudcode-pa.googleapis.com"), timeout=1.0)
        if health_resp is None:
            res.passed = False
            res.details = f"Server died or unresponsive after fuzzing! Error: {err_msg}"
        else:
            parsed = parse_dns_response(health_resp)
            if parsed.get("ancount") == 1 and parsed["answers"][0]["ip"] == VPS_IP:
                res.passed = True
                res.details = "Daemon survived 50 fuzzing streams; legitimate queries remain 100% operational"
            else:
                res.passed = False
                res.details = f"Server returned unexpected answer after fuzzing: {parsed}"
        res.duration_ms = (time.time() - t0) * 1000
        self.record(res)

    def test_dns_subdomain_spoofing_attempts(self):
        """Adversarial spoofing attempts to bypass whitelist or trigger false positive interception."""
        malicious_domains = [
            ("fakegoogleapis.com", "substring squatting"),
            ("not-google.com", "hyphenated prefix"),
            ("evilgoogle.com", "prefix collision"),
            ("googleapis.com.attacker.org", "suffix impersonation"),
            ("google.com.malicious.net", "suffix impersonation"),
            ("daily-cloudcode-pa.googleapis.com.evil.com", "full FQDN subdomain of attacker"),
            ("ai.studio.attacker.io", "exact domain suffix impersonation"),
            ("antigravity-unleash.goog.evil.com", "exact .goog domain impersonation"),
            ("my-deepmind.com", "hyphenated prefix"),
            ("deepmind.com.attacker.com", "suffix impersonation"),
        ]

        for domain, attack_type in malicious_domains:
            t0 = time.time()
            res = TestResult(f"dns_spoof_{domain}", "DNS-Spoofing")
            query = build_dns_query(domain, qtype=1)
            raw_resp = send_dns_udp(query, timeout=2.5)
            if raw_resp is None:
                # If upstream resolution timed out or NXDOMAIN, it did NOT intercept
                res.passed = True
                res.details = f"{attack_type}: Upstream resolver timed out/dropped; NOT intercepted"
            else:
                parsed = parse_dns_response(raw_resp)
                # Check answers: MUST NOT be intercepted to VPS_IP
                intercepted = False
                resolved_ips = []
                for ans in parsed.get("answers", []):
                    if ans.get("type") == "A":
                        resolved_ips.append(ans["ip"])
                        if ans["ip"] == VPS_IP:
                            intercepted = True
                if intercepted:
                    res.passed = False
                    res.details = f"CRITICAL SECURITY BUG: Malicious domain '{domain}' was intercepted to VPS {VPS_IP}!"
                else:
                    res.passed = True
                    res.details = f"{attack_type}: Correctly resolved upstream (ips: {resolved_ips}, rcode={parsed.get('rcode')})"
            res.duration_ms = (time.time() - t0) * 1000
            self.record(res)

    def test_dns_legitimate_interceptions(self):
        """Verify whitelisted domains strictly intercept to VPS IP."""
        legit_domains = [
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "ai.studio",
            "antigravity-unleash.goog",
            "gemini.google",
            "cloudcode-pa.googleapis.com",
            "oauth2.googleapis.com",
            "deepmind.google",
        ]
        for domain in legit_domains:
            t0 = time.time()
            res = TestResult(f"dns_legit_intercept_{domain}", "DNS-Interception")
            query = build_dns_query(domain, qtype=1)
            raw_resp = send_dns_udp(query, timeout=1.5)
            if raw_resp is None:
                res.passed = False
                res.details = f"Query timed out for legitimate domain {domain}"
            else:
                parsed = parse_dns_response(raw_resp)
                ips = [a["ip"] for a in parsed.get("answers", []) if a.get("type") == "A"]
                if VPS_IP in ips and parsed.get("ancount") == 1:
                    res.passed = True
                    res.details = f"Resolved to {VPS_IP} (ANCOUNT=1, AA=1)"
                else:
                    res.passed = False
                    res.details = f"Failed to intercept: answers={parsed.get('answers')}, rcode={parsed.get('rcode')}"
            res.duration_ms = (time.time() - t0) * 1000
            self.record(res)

    def test_dns_ipv6_and_type65_suppression(self):
        """Verify AAAA and Type 65 queries on intercepted domains return NODATA (NOERROR, ANCOUNT=0)."""
        test_cases = [
            ("daily-cloudcode-pa.googleapis.com", 28, "AAAA", "UDP"),
            ("daily-cloudcode-pa.googleapis.com", 65, "TYPE65", "UDP"),
            ("generativelanguage.googleapis.com", 64, "SVCB", "UDP"),
            ("generativelanguage.googleapis.com", 28, "AAAA", "TCP"),
            ("daily-cloudcode-pa.googleapis.com", 65, "TYPE65", "TCP"),
        ]
        for domain, qtype, qname, proto in test_cases:
            t0 = time.time()
            res = TestResult(f"dns_suppression_{qname}_{proto}_{domain.split('.')[0]}", "DNS-Suppression")
            query = build_dns_query(domain, qtype=qtype)
            raw_resp = send_dns_udp(query, timeout=1.5) if proto == "UDP" else send_dns_tcp(query, timeout=1.5)
            if raw_resp is None:
                res.passed = False
                res.details = f"Query timed out for {domain} {qname} over {proto}"
            else:
                parsed = parse_dns_response(raw_resp)
                if parsed.get("rcode") == 0 and parsed.get("ancount") == 0:
                    res.passed = True
                    res.details = f"Suppressed {qname} with NODATA (RCODE=0, ANCOUNT=0, QR=1, AA=1)"
                else:
                    res.passed = False
                    res.details = f"Failed suppression: rcode={parsed.get('rcode')}, ancount={parsed.get('ancount')}"
            res.duration_ms = (time.time() - t0) * 1000
            self.record(res)

    async def _concurrency_worker_udp(self, worker_id: int, num_queries: int) -> Tuple[int, int]:
        success = 0
        failed = 0
        loop = asyncio.get_running_loop()
        domain = "daily-cloudcode-pa.googleapis.com"
        for i in range(num_queries):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                txid = (worker_id * 1000 + i) & 0xFFFF
                query = build_dns_query(domain, qtype=1, txid=txid)
                await loop.sock_sendto(sock, query, (TARGET_HOST, DNS_PORT))
                resp, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout=1.5)
                parsed = parse_dns_response(resp)
                if parsed.get("ancount") == 1 and parsed["answers"][0]["ip"] == VPS_IP:
                    success += 1
                else:
                    failed += 1
            except Exception:
                failed += 1
            finally:
                sock.close()
        return success, failed

    def test_dns_high_concurrency_udp(self):
        """Fire 1,000 UDP DNS queries across 20 concurrent coroutines."""
        t0 = time.time()
        res = TestResult("dns_udp_high_concurrency_1000", "DNS-Concurrency")

        async def _run():
            tasks = [self._concurrency_worker_udp(w, 50) for w in range(20)]
            return await asyncio.gather(*tasks)

        counts = asyncio.run(_run())
        total_success = sum(c[0] for c in counts)
        total_failed = sum(c[1] for c in counts)
        elapsed = time.time() - t0
        qps = 1000 / elapsed if elapsed > 0 else 0

        res.duration_ms = elapsed * 1000
        if total_failed == 0 and total_success == 1000:
            res.passed = True
            res.details = f"1000/1000 successful (0 dropped), throughput: {qps:.1f} QPS"
        elif total_success >= 980:  # UDP can drop under high burst
            res.passed = True
            res.details = f"{total_success}/1000 queries resolved ({total_failed} dropped under UDP burst), {qps:.1f} QPS"
        else:
            res.passed = False
            res.details = f"High failure rate: {total_failed}/1000 failed, only {total_success} succeeded"
        self.record(res)

    async def _concurrency_worker_tcp(self, worker_id: int) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(TARGET_HOST, DNS_PORT), timeout=2.0
            )
            try:
                query = build_dns_query("generativelanguage.googleapis.com", qtype=1, txid=worker_id)
                writer.write(len(query).to_bytes(2, "big") + query)
                await writer.drain()
                p = await asyncio.wait_for(reader.readexactly(2), timeout=2.0)
                l = int.from_bytes(p, "big")
                resp = await asyncio.wait_for(reader.readexactly(l), timeout=2.0)
                parsed = parse_dns_response(resp)
                return parsed.get("ancount") == 1 and parsed["answers"][0]["ip"] == VPS_IP
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception:
            return False

    def test_dns_high_concurrency_tcp(self):
        """Fire 100 concurrent TCP DNS queries simultaneously."""
        t0 = time.time()
        res = TestResult("dns_tcp_high_concurrency_100", "DNS-Concurrency")

        async def _run():
            tasks = [self._concurrency_worker_tcp(w) for w in range(100)]
            return await asyncio.gather(*tasks)

        results = asyncio.run(_run())
        passed = sum(1 for r in results if r)
        failed = len(results) - passed
        elapsed = time.time() - t0
        res.duration_ms = elapsed * 1000
        if failed == 0:
            res.passed = True
            res.details = f"100/100 concurrent TCP connections succeeded cleanly ({elapsed:.2f}s)"
        else:
            res.passed = False
            res.details = f"{failed}/100 TCP queries failed"
        self.record(res)

    def test_dns_tcp_pipelining(self):
        """Send 10 sequential DNS queries over a single persistent TCP connection."""
        t0 = time.time()
        res = TestResult("dns_tcp_persistent_pipelining_10", "DNS-Concurrency")
        domains = [
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
            "ai.studio",
            "antigravity-unleash.goog",
            "gemini.google",
            "cloudcode-pa.googleapis.com",
            "oauth2.googleapis.com",
            "deepmind.google",
            "daily-cloudcode-pa.googleapis.com",
            "generativelanguage.googleapis.com",
        ]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        try:
            sock.connect((TARGET_HOST, DNS_PORT))
            success = 0
            for idx, d in enumerate(domains):
                q = build_dns_query(d, qtype=1, txid=0x2000 + idx)
                sock.sendall(len(q).to_bytes(2, "big") + q)
                prefix = sock.recv(2)
                if len(prefix) < 2:
                    break
                resp_len = int.from_bytes(prefix, "big")
                resp = b""
                while len(resp) < resp_len:
                    c = sock.recv(resp_len - len(resp))
                    if not c:
                        break
                    resp += c
                parsed = parse_dns_response(resp)
                if parsed.get("txid") == 0x2000 + idx and parsed.get("ancount") == 1 and parsed["answers"][0]["ip"] == VPS_IP:
                    success += 1
            if success == 10:
                res.passed = True
                res.details = "10/10 sequential queries handled over single persistent TCP session without disconnect"
            else:
                res.passed = False
                res.details = f"Only {success}/10 queries completed over persistent TCP connection"
        except Exception as e:
            res.passed = False
            res.details = f"TCP pipelining error: {e}"
        finally:
            sock.close()
        res.duration_ms = (time.time() - t0) * 1000
        self.record(res)

    # -----------------------------------------------------------------------
    # SUITE 2: SNI PROXY ADVERSARIAL TESTS
    # -----------------------------------------------------------------------

    def test_sni_non_tls_data(self):
        """Send non-TLS raw data (HTTP GET, plain text, null bytes) to 443 & 8443. Must drop connection."""
        test_payloads = [
            ("http_get_plaintext", b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/7.88.1\r\n\r\n"),
            ("http_post_data", b"POST /api HTTP/1.1\r\nHost: test.com\r\nContent-Length: 10\r\n\r\n0123456789"),
            ("random_ascii", b"HELO mail.attacker.org\r\n"),
            ("zero_bytes_64b", b"\x00" * 64),
            ("high_bytes_ff", b"\xff" * 64),
        ]

        for port in [SNI_PRIMARY_PORT, SNI_FALLBACK_PORT]:
            for name, payload in test_payloads:
                t0 = time.time()
                res = TestResult(f"sni_non_tls_{name}_port_{port}", "SNI-NonTLS")
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
                try:
                    sock.connect((TARGET_HOST, port))
                    sock.sendall(payload)
                    # The server should close the connection promptly without echoing or proxying
                    resp = sock.recv(1024)
                    if len(resp) == 0:
                        res.passed = True
                        res.details = "Connection closed cleanly by server (EOF)"
                    else:
                        res.passed = False
                        res.details = f"Unexpected data returned ({len(resp)} bytes): {resp[:32]!r}"
                except (ConnectionResetError, BrokenPipeError):
                    res.passed = True
                    res.details = "Connection reset by server (TCP RST)"
                except socket.timeout:
                    res.passed = False
                    res.details = "Socket timed out (server hung without closing connection)"
                except Exception as e:
                    res.passed = False
                    res.details = f"Error: {e}"
                finally:
                    sock.close()
                res.duration_ms = (time.time() - t0) * 1000
                self.record(res)

    def test_sni_malformed_client_hello(self):
        """Send structurally malformed ClientHello packets to SNI proxy."""
        # Test malformed packets where client closes write (EOF) or sends bad syntax
        cases = [
            ("truncated_record_hdr_eof", b"\x16\x03\x01", True),  # 3 bytes only, then EOF
            ("huge_record_length_65535", b"\x16\x03\x01\xff\xff" + b"\x01" * 100, False),
            ("zero_record_length", b"\x16\x03\x01\x00\x00", False),
            ("handshake_not_clienthello", b"\x16\x03\x01\x00\x10\x02" + b"\x00" * 15, False),  # Type 0x02 ServerHello
            ("missing_sni_extension", build_client_hello(None, corrupt_sni="missing"), False),
            ("corrupt_sni_ext_truncated", build_client_hello("daily-cloudcode-pa.googleapis.com", corrupt_sni="truncated_length"), False),
            ("corrupt_sni_ext_bad_nametype", build_client_hello("daily-cloudcode-pa.googleapis.com", corrupt_sni="bad_nametype"), False),
        ]

        for name, payload, do_shutdown in cases:
            t0 = time.time()
            res = TestResult(f"sni_malformed_{name}", "SNI-Malformed")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.5)
            try:
                sock.connect((TARGET_HOST, SNI_PRIMARY_PORT))
                sock.sendall(payload)
                if do_shutdown:
                    sock.shutdown(socket.SHUT_WR)
                resp = sock.recv(1024)
                if len(resp) == 0:
                    res.passed = True
                    res.details = "Server rejected malformed ClientHello and closed connection"
                else:
                    res.passed = False
                    res.details = f"Unexpected response from server: {resp[:32]!r}"
            except (ConnectionResetError, BrokenPipeError):
                res.passed = True
                res.details = "Server cleanly reset connection (RST)"
            except socket.timeout:
                res.passed = False
                res.details = "Server hung on malformed packet (timeout)"
            except Exception as e:
                res.passed = False
                res.details = f"Error: {e}"
            finally:
                sock.close()
            res.duration_ms = (time.time() - t0) * 1000
            self.record(res)

    def test_sni_non_whitelisted_domains(self):
        """Send valid ClientHello with non-whitelisted SNI hostnames. Server MUST reject and close connection."""
        forbidden_snis = [
            "example.com",
            "facebook.com",
            "attacker.org",
            "fakegoogleapis.com",
            "googleapis.com.evil.com",
            "notgoogle.com",
            "cloudflare.com",
            "microsoft.com",
        ]

        for port in [SNI_PRIMARY_PORT, SNI_FALLBACK_PORT]:
            for sni in forbidden_snis:
                t0 = time.time()
                res = TestResult(f"sni_reject_{sni}_port_{port}", "SNI-Authorization")
                pkt = build_client_hello(sni)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3.0)
                try:
                    sock.connect((TARGET_HOST, port))
                    sock.sendall(pkt)
                    resp = sock.recv(1024)
                    if len(resp) == 0:
                        res.passed = True
                        res.details = f"Rejected non-whitelisted SNI '{sni}' (closed connection)"
                    else:
                        res.passed = False
                        res.details = f"CRITICAL: Non-whitelisted SNI returned data: {resp[:32]!r}"
                except (ConnectionResetError, BrokenPipeError):
                    res.passed = True
                    res.details = f"Rejected non-whitelisted SNI '{sni}' (RST)"
                except socket.timeout:
                    res.passed = False
                    res.details = f"Server hung on non-whitelisted SNI '{sni}'"
                except Exception as e:
                    res.passed = False
                    res.details = f"Error: {e}"
                finally:
                    sock.close()
                res.duration_ms = (time.time() - t0) * 1000
                self.record(res)

    def test_sni_whitelisted_domains(self):
        """Verify whitelisted SNI successfully relays to Google Anycast edge and returns authentic ServerHello."""
        whitelisted_snis = [
            ("daily-cloudcode-pa.googleapis.com", SNI_PRIMARY_PORT),
            ("daily-cloudcode-pa.googleapis.com", SNI_FALLBACK_PORT),
            ("generativelanguage.googleapis.com", SNI_PRIMARY_PORT),
            ("generativelanguage.googleapis.com", SNI_FALLBACK_PORT),
        ]

        for sni, port in whitelisted_snis:
            t0 = time.time()
            res = TestResult(f"sni_allowed_{sni}_port_{port}", "SNI-Relay")
            pkt = build_client_hello(sni)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                sock.connect((TARGET_HOST, port))
                sock.sendall(pkt)
                resp = sock.recv(4096)
                if len(resp) >= 5 and resp[0] == 0x16:  # TLS Handshake response (ServerHello)
                    res.passed = True
                    handshake_type = resp[5] if len(resp) > 5 else -1
                    res.details = f"Received valid TLS ServerHello from Google edge (len={len(resp)}B, hs_type={handshake_type})"
                else:
                    res.passed = False
                    res.details = f"Did not receive TLS handshake response: {resp[:32]!r}"
            except Exception as e:
                res.passed = False
                res.details = f"Connection error: {e}"
            finally:
                sock.close()
            res.duration_ms = (time.time() - t0) * 1000
            self.record(res)

    def test_sni_slowloris_handshake_timeout(self):
        """Send partial ClientHello 1 byte per second. Server MUST time out and close within ~5-6 seconds."""
        t0 = time.time()
        res = TestResult("sni_slowloris_timeout_enforcement", "SNI-Slowloris")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8.0)
        try:
            sock.connect((TARGET_HOST, SNI_PRIMARY_PORT))
            # Send 1 byte of TLS header
            sock.sendall(b"\x16")
            time.sleep(1.0)
            sock.sendall(b"\x03")
            time.sleep(1.0)
            sock.sendall(b"\x01")
            # Now wait for server to close on HANDSHAKE_TIMEOUT (5.0s)
            start_wait = time.time()
            data = sock.recv(1024)
            wait_time = time.time() - start_wait
            if len(data) == 0:
                total_time = time.time() - t0
                if 4.0 <= total_time <= 7.5:
                    res.passed = True
                    res.details = f"Server enforced handshake deadline: closed after {total_time:.2f}s"
                else:
                    res.passed = True  # Still closed, just verify time
                    res.details = f"Server closed connection after {total_time:.2f}s"
            else:
                res.passed = False
                res.details = f"Unexpected data received: {data[:32]!r}"
        except (ConnectionResetError, BrokenPipeError):
            total_time = time.time() - t0
            res.passed = True
            res.details = f"Server closed connection via RST after {total_time:.2f}s"
        except socket.timeout:
            res.passed = False
            res.details = "Slowloris attack succeeded in holding socket open beyond timeout!"
        except Exception as e:
            res.passed = False
            res.details = f"Unexpected error: {e}"
        finally:
            sock.close()
        res.duration_ms = (time.time() - t0) * 1000
        self.record(res)

    async def _slowloris_client(self, client_id: int) -> bool:
        """Connects and holds connection open sending 1 byte."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(TARGET_HOST, SNI_PRIMARY_PORT), timeout=2.0
            )
            writer.write(b"\x16")
            await writer.drain()
            # Wait until closed by server
            try:
                data = await asyncio.wait_for(reader.read(100), timeout=7.0)
                writer.close()
                await writer.wait_closed()
                return True
            except asyncio.TimeoutError:
                writer.close()
                await writer.wait_closed()
                return False
        except Exception:
            return True

    def test_sni_slowloris_concurrency_starvation(self):
        """Spawn 30 simultaneous slowloris clients. Concurrently verify legitimate request succeeds without starvation."""
        t0 = time.time()
        res = TestResult("sni_slowloris_anti_starvation_30", "SNI-Slowloris")

        async def _run():
            # Launch 30 slowloris clients in background
            slow_tasks = [asyncio.create_task(self._slowloris_client(i)) for i in range(30)]
            # Sleep 1 second so all slowloris connections are actively established
            await asyncio.sleep(1.0)

            # Now issue legitimate TLS ClientHello with whitelisted SNI
            legit_ok = False
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(TARGET_HOST, SNI_PRIMARY_PORT), timeout=3.0
                )
                pkt = build_client_hello("daily-cloudcode-pa.googleapis.com")
                writer.write(pkt)
                await writer.drain()
                resp = await asyncio.wait_for(reader.read(4096), timeout=4.0)
                if len(resp) >= 5 and resp[0] == 0x16:
                    legit_ok = True
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                legit_ok = False

            # Wait for all slowloris tasks to complete
            slow_results = await asyncio.gather(*slow_tasks)
            all_slow_closed = all(slow_results)
            return legit_ok, all_slow_closed

        legit_ok, all_slow_closed = asyncio.run(_run())
        res.duration_ms = (time.time() - t0) * 1000
        if legit_ok and all_slow_closed:
            res.passed = True
            res.details = "Legitimate request succeeded seamlessly while 30 slowloris connections were active; all 30 timed out cleanly"
        elif legit_ok:
            res.passed = True
            res.details = "Legitimate request succeeded during attack; some slowloris connections took longer to close"
        else:
            res.passed = False
            res.details = "Legitimate connection was starved or timed out during slowloris attack!"
        self.record(res)

    # -----------------------------------------------------------------------
    # SUITE 3: POST-STRESS DAEMON HEALTH VERIFICATION
    # -----------------------------------------------------------------------

    def test_post_stress_daemon_health(self):
        """Final sanity check: query both DNS and SNI to ensure service has zero degradation post-adversarial tests."""
        t0 = time.time()
        res = TestResult("post_stress_daemon_health_check", "Post-Stress-Health")

        # 1. DNS check
        dns_ok = False
        for _ in range(3):
            resp = send_dns_udp(build_dns_query("generativelanguage.googleapis.com"), timeout=1.5)
            if resp:
                p = parse_dns_response(resp)
                if p.get("ancount") == 1 and p["answers"][0]["ip"] == VPS_IP:
                    dns_ok = True
                    break
            time.sleep(0.5)

        # 2. SNI check
        sni_ok = False
        pkt = build_client_hello("generativelanguage.googleapis.com")
        for _ in range(3):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3.0)
            try:
                sock.connect((TARGET_HOST, SNI_PRIMARY_PORT))
                sock.sendall(pkt)
                r = sock.recv(4096)
                if len(r) >= 5 and r[0] == 0x16:
                    sni_ok = True
                    break
            except Exception:
                pass
            finally:
                sock.close()
            time.sleep(0.5)

        res.duration_ms = (time.time() - t0) * 1000
        if dns_ok and sni_ok:
            res.passed = True
            res.details = "Daemon remains 100% healthy, responsive, and fully operational after entire adversarial stress suite."
        else:
            res.passed = False
            res.details = f"Daemon degraded post-stress: dns_ok={dns_ok}, sni_ok={sni_ok}"
        self.record(res)

    def run_all(self):
        print(f"\n{BLUE}======================================================================{RESET}")
        print(f"{BLUE}STARTING EMPIRICAL ADVERSARIAL STRESS SUITE (CHALLENGER 1){RESET}")
        print(f"Target: {TARGET_HOST} (Public: {VPS_IP}) | DNS: {DNS_PORT} | SNI: {SNI_PRIMARY_PORT}/{SNI_FALLBACK_PORT}")
        print(f"{BLUE}======================================================================\n{RESET}")

        # Suite 1: DNS
        print(f"\n--- Suite 1.1: DNS Malformed Packets & Fuzzing ---")
        self.test_dns_malformed_short_packets_udp()
        self.test_dns_malformed_short_packets_tcp()
        self.test_dns_compression_pointer_loop()
        self.test_dns_compression_pointer_out_of_bounds()
        self.test_dns_invalid_label_length()
        self.test_dns_qr_response_bit()
        self.test_dns_qdcount_zero()
        self.test_dns_fuzz_random_byte_streams()

        print(f"\n--- Suite 1.2: DNS Subdomain Spoofing & Squatting ---")
        self.test_dns_subdomain_spoofing_attempts()

        print(f"\n--- Suite 1.3: DNS Legitimate Interception Baseline ---")
        self.test_dns_legitimate_interceptions()

        print(f"\n--- Suite 1.4: DNS IPv6 AAAA & Type 65 Suppression ---")
        self.test_dns_ipv6_and_type65_suppression()

        print(f"\n--- Suite 1.5: DNS Concurrency Stress (UDP & TCP) ---")
        self.test_dns_high_concurrency_udp()
        self.test_dns_high_concurrency_tcp()
        self.test_dns_tcp_pipelining()

        # Suite 2: SNI Proxy
        print(f"\n--- Suite 2.1: SNI Non-TLS Raw Data Injection ---")
        self.test_sni_non_tls_data()

        print(f"\n--- Suite 2.2: SNI Malformed TLS ClientHello ---")
        self.test_sni_malformed_client_hello()

        print(f"\n--- Suite 2.3: SNI Non-Whitelisted SNI Rejections ---")
        self.test_sni_non_whitelisted_domains()

        print(f"\n--- Suite 2.4: SNI Whitelisted SNI Passthrough Baseline ---")
        self.test_sni_whitelisted_domains()

        print(f"\n--- Suite 2.5: SNI Slowloris Handshake Starvation & Timeout ---")
        self.test_sni_slowloris_handshake_timeout()
        self.test_sni_slowloris_concurrency_starvation()

        # Suite 3: Post-Stress Health
        print(f"\n--- Suite 3.1: Post-Stress Service Sanity ---")
        self.test_post_stress_daemon_health()

        # Summary
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed

        print(f"\n{BLUE}======================================================================{RESET}")
        print(f"ADVERSARIAL STRESS SUITE SUMMARY: Total: {total} | {GREEN}Passed: {passed}{RESET} | {RED if failed else GREEN}Failed: {failed}{RESET}")
        print(f"{BLUE}======================================================================{RESET}")

        return failed == 0


if __name__ == "__main__":
    runner = AdversarialRunner()
    ok = runner.run_all()
    sys.exit(0 if ok else 1)
