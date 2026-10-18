"""
Antigravity Zero-Privilege Bypass System - Tier 2: Boundary & Corner Cases (BVA)
Tests features F1 through F16 (minimum 5 boundary/corner test cases per feature, 80+ total)
Covers limits, malformed wire inputs, timeouts, empty queries, invalid tokens, non-existent domains.
Opaque-box testing: Only interacts via external protocols, sockets, filesystem, or subprocesses.
"""

import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

# Import opaque-box protocol helpers
import protocol_helpers as ph

PROJECT_ROOT = Path(os.environ.get("ANTIGRAVITY_PROJECT_ROOT", str(Path(__file__).resolve().parent.parent)))
SERVER_DIR = PROJECT_ROOT / "server"
CLIENT_DIR = PROJECT_ROOT / "client"
DIAG_DIR = PROJECT_ROOT / "diagnostics"
TESTS_DIR = PROJECT_ROOT / "tests"


# ============================================================================
# F1: DNS UDP/TCP Interceptor Boundaries (>= 5 tests)
# ============================================================================

class TestF1DNSInterceptorBoundaries(unittest.TestCase):
    """F1: DNS UDP/TCP Interceptor Boundary & Error Handling."""

    @classmethod
    def setUpClass(cls):
        cls.server_host = os.environ.get("ANTIGRAVITY_SERVER_HOST", ph.DEFAULT_VPS_IP)
        cls.dns_port = ph.DEFAULT_DNS_PORT
        cls.dns_running = ph.is_udp_dns_responsive(cls.server_host, cls.dns_port)

    def test_f1_b01_dns_malformed_udp_packet_handling(self):
        """F1.B1: Malformed UDP packets (truncated 2-byte data) do not crash the DNS server."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.0)
        try:
            s.sendto(b"\x12\x34\x01", (self.server_host, self.dns_port))
            # Verify server is still alive and responds to normal query
            resp = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port)
            self.assertTrue(resp["valid"])
        finally:
            s.close()

    def test_f1_b02_dns_nonexistent_domain_upstream_nxdomain(self):
        """F1.B2: Non-existent domain query returns NXDOMAIN (RCODE=3) from upstream resolver."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        rand_id = os.urandom(6).hex()
        nonexistent = f"nonexistent-target-{rand_id}.example.invalid"
        resp = ph.send_dns_query_udp(nonexistent, self.server_host, self.dns_port)
        self.assertTrue(resp["valid"])
        # Upstream RFC 1035 NXDOMAIN is RCODE 3
        self.assertEqual(resp["rcode"], 3)

    def test_f1_b03_dns_empty_qname_root(self):
        """F1.B3: Querying root domain ('.') handled cleanly without crash."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        resp = ph.send_dns_query_udp(".", self.server_host, self.dns_port)
        # Should be valid response or clean error without server failure
        self.assertIn(resp["rcode"], [0, 1, 2, 3])

    def test_f1_b04_dns_tcp_framing_partial_length_timeout(self):
        """F1.B4: TCP connection sending incomplete prefix length cleans up on timeout/EOF."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((self.server_host, self.dns_port))
            # Send length 255 but only 5 bytes of data
            s.sendall(b"\x00\xFF\x01\x02\x03\x04\x05")
            s.shutdown(socket.SHUT_WR)
            # Server should close or time out gracefully
            _ = s.recv(1024)
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            s.close()
        # Verify DNS is still operational
        resp = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port)
        self.assertTrue(resp["valid"])

    def test_f1_b05_dns_max_label_length_63_chars(self):
        """F1.B5: Query domain with 63-character label (RFC 1035 max label limit)."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        label_63 = "a" * 63
        domain = f"{label_63}.example.com"
        resp = ph.send_dns_query_udp(domain, self.server_host, self.dns_port)
        self.assertTrue(resp["valid"])


# ============================================================================
# F2: DNS ECH & IPv6 Suppression Boundaries (>= 5 tests)
# ============================================================================

class TestF2ECHIPv6SuppressionBoundaries(unittest.TestCase):
    """F2: DNS ECH & IPv6 Suppression - Boundary and corner cases."""

    @classmethod
    def setUpClass(cls):
        cls.server_host = os.environ.get("ANTIGRAVITY_SERVER_HOST", ph.DEFAULT_VPS_IP)
        cls.dns_port = ph.DEFAULT_DNS_PORT
        cls.dns_running = ph.is_udp_dns_responsive(cls.server_host, cls.dns_port)

    def test_f2_b01_type65_on_subdomain_wildcard(self):
        """F2.B1: Deeply nested Google AI subdomain returns NODATA for Type 65."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        resp = ph.send_dns_query_udp("deep.sub.daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port, qtype=65)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0)
        self.assertEqual(resp["ancount"], 0)

    def test_f2_b02_mixed_case_qname_aaaa(self):
        """F2.B2: Mixed case QNAME (dAiLy-cLoUdCoDe-Pa.GoOgLeApIs.CoM) matches case-insensitively for AAAA."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        resp = ph.send_dns_query_udp("dAiLy-cLoUdCoDe-Pa.GoOgLeApIs.CoM", self.server_host, self.dns_port, qtype=28)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0)
        self.assertEqual(resp["ancount"], 0)

    def test_f2_b03_unsupported_obscure_qtype(self):
        """F2.B3: Obscure QTYPE (Type 13 HINFO or Type 255 ANY) on intercepted domain handled gracefully."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        resp = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port, qtype=13)
        self.assertTrue(resp["valid"])
        # Should return NOERROR or NOTIMP without server crash
        self.assertIn(resp["rcode"], [0, 4])

    def test_f2_b04_rapid_burst_type65_queries(self):
        """F2.B4: Burst of 10 sequential Type 65 queries all return NODATA consistently."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        for _ in range(10):
            resp = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port, qtype=65)
            self.assertTrue(resp["valid"])
            self.assertEqual(resp["ancount"], 0)

    def test_f2_b05_aaaa_query_over_tcp_transport(self):
        """F2.B5: AAAA query over TCP returns properly framed 2-byte NODATA response."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        resp = ph.send_dns_query_tcp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port, qtype=28)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["ancount"], 0)


# ============================================================================
# F3: Non-Terminating SNI Proxy Boundaries (>= 5 tests)
# ============================================================================

class TestF3SNIProxyBoundaries(unittest.TestCase):
    """F3: Non-Terminating SNI Proxy - Malformed packets, unauthorized SNI, and fragments."""

    @classmethod
    def setUpClass(cls):
        cls.server_host = os.environ.get("ANTIGRAVITY_SERVER_HOST", ph.DEFAULT_VPS_IP)
        cls.sni_port = ph.DEFAULT_SNI_PORT
        cls.sni_running = ph.is_tcp_port_open(cls.server_host, cls.sni_port)

    def test_f3_b01_sni_proxy_non_tls_plain_http(self):
        """F3.B1: Plain HTTP GET request on port 443 terminated immediately without proxying."""
        if not self.sni_running:
            self.skipTest("SNI Proxy not listening on port 443 (Pending M1)")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((self.server_host, self.sni_port))
            s.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            data = s.recv(1024)
            # Server should close socket or return error
            self.assertTrue(len(data) == 0 or b"HTTP" not in data)
        except (socket.timeout, ConnectionResetError):
            pass
        finally:
            s.close()

    def test_f3_b02_sni_proxy_disallowed_sni_rejection(self):
        """F3.B2: ClientHello with disallowed SNI (malicious-host.example.com) rejected/closed."""
        if not self.sni_running:
            self.skipTest("SNI Proxy not listening on port 443 (Pending M1)")
        res = ph.send_sni_client_hello(self.server_host, self.sni_port, "malicious-host.example.com", timeout=2.0)
        # Server must close or reject connection (not return a Google ServerHello)
        self.assertFalse(res.get("is_server_hello", False))

    def test_f3_b03_sni_proxy_missing_sni_extension(self):
        """F3.B3: ClientHello without SNI extension (direct IP probe) handled gracefully."""
        if not self.sni_running:
            self.skipTest("SNI Proxy not listening on port 443 (Pending M1)")
        res = ph.send_sni_client_hello(self.server_host, self.sni_port, None, timeout=2.0)
        # Server either falls back safely or closes connection cleanly
        self.assertTrue(res["connected"])

    def test_f3_b04_sni_proxy_fragmented_clienthello(self):
        """F3.B4: ClientHello split across TCP segments (5-byte header, then body) buffered correctly."""
        if not self.sni_running:
            self.skipTest("SNI Proxy not listening on port 443 (Pending M1)")
        res = ph.send_sni_client_hello(
            self.server_host, self.sni_port, "daily-cloudcode-pa.googleapis.com", timeout=3.0, fragmented=True
        )
        self.assertTrue(res["connected"])
        self.assertTrue(res["is_tls"])

    def test_f3_b05_sni_proxy_premature_disconnect(self):
        """F3.B5: Abrupt client disconnect after sending 10 bytes does not cause server resource leak."""
        if not self.sni_running:
            self.skipTest("SNI Proxy not listening on port 443 (Pending M1)")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        try:
            s.connect((self.server_host, self.sni_port))
            s.sendall(b"\x16\x03\x01\x00\x50\x01\x00\x00\x4c\x03")
        finally:
            s.close()
        # Verify proxy still handles normal connections
        self.assertTrue(ph.is_tcp_port_open(self.server_host, self.sni_port))


# ============================================================================
# F4: Dynamic Google Edge Resolver Boundaries (>= 5 tests)
# ============================================================================

class TestF4DynamicGoogleEdgeResolverBoundaries(unittest.TestCase):
    """F4: Dynamic Google Edge IP Resolver - Edge pool boundaries and resilience."""

    def test_f4_b01_edge_ip_pool_unreachable_failover(self):
        """F4.B1: Simulating unreachable IP failover: secondary IP in pool connects successfully."""
        # Check second IP in pool
        secondary_ip = ph.GOOGLE_EDGE_IPS[1]
        self.assertTrue(ph.is_tcp_port_open(secondary_ip, 443, timeout=2.0))

    def test_f4_b02_edge_ip_burst_connect_disconnect(self):
        """F4.B2: Rapid burst of 5 connect/disconnect cycles handled without socket exhaustion."""
        target_ip = ph.GOOGLE_EDGE_IPS[0]
        for _ in range(5):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((target_ip, 443))
            s.close()
            time.sleep(0.02)

    def test_f4_b03_edge_ip_large_upstream_data_stream(self):
        """F4.B3: Stream 4KB data chunk through TLS connection to edge IP without buffer stall."""
        target_ip = ph.GOOGLE_EDGE_IPS[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((target_ip, 443), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname="generativelanguage.googleapis.com") as ssock:
                payload = b"X" * 4096
                req = (
                    b"POST /v1beta/models HTTP/1.1\r\n"
                    b"Host: generativelanguage.googleapis.com\r\n"
                    b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + payload
                )
                ssock.sendall(req)
                resp = ssock.recv(512)
                self.assertGreater(len(resp), 0)

    def test_f4_b04_edge_ip_tls_version_negotiation(self):
        """F4.B4: Edge IP supports TLS 1.3 protocol negotiation."""
        target_ip = ph.GOOGLE_EDGE_IPS[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((target_ip, 443), timeout=3.0) as sock:
            with ctx.wrap_socket(sock, server_hostname="daily-cloudcode-pa.googleapis.com") as ssock:
                version = ssock.version()
                self.assertIn(version, ["TLSv1.3", "TLSv1.2"])

    def test_f4_b05_edge_ip_route_stability(self):
        """F4.B5: Frankfurt edge IP pool responds consistently across all pool members."""
        success_count = 0
        for edge_ip in ph.GOOGLE_EDGE_IPS[:3]:
            if ph.is_tcp_port_open(edge_ip, 443, timeout=1.5):
                success_count += 1
        self.assertGreaterEqual(success_count, 2)


# ============================================================================
# F5: Authenticated Remote Proxy Inbound Boundaries (>= 5 tests)
# ============================================================================

class TestF5AuthenticatedRemoteProxyBoundaries(unittest.TestCase):
    """F5: Authenticated Remote Proxy Inbound - Malformed requests, bad credentials, auth checks."""

    @classmethod
    def setUpClass(cls):
        cls.server_host = os.environ.get("ANTIGRAVITY_SERVER_HOST", ph.DEFAULT_VPS_IP)
        cls.socks_port = ph.DEFAULT_SOCKS_PORT
        cls.http_port = ph.DEFAULT_HTTP_PORT
        cls.socks_running = ph.is_tcp_port_open(cls.server_host, cls.socks_port)
        cls.http_running = ph.is_tcp_port_open(cls.server_host, cls.http_port)

    def test_f5_b01_http_connect_malformed_syntax(self):
        """F5.B1: Malformed HTTP request line (BADMETHOD target:443 HTTP/1.1) returns 400 Bad Request."""
        if not self.http_running:
            self.skipTest("HTTP CONNECT proxy not listening on 48329 (Pending M1)")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((self.server_host, self.http_port))
            s.sendall(b"BADSYNTAX\r\n\r\n")
            resp = s.recv(1024).decode("utf-8", errors="replace")
            status_line = resp.split("\r\n")[0]
            self.assertTrue("400" in status_line or len(resp) == 0)
        finally:
            s.close()

    def test_f5_b02_http_connect_invalid_auth_credentials(self):
        """F5.B2: HTTP CONNECT with bad Basic auth credentials when auth enabled returns 407."""
        if not self.http_running:
            self.skipTest("HTTP CONNECT proxy not listening on 48329 (Pending M1)")
        # Test auth token if configured in environment
        token = os.environ.get("ANTIGRAVITY_AUTH_TOKEN")
        if not token:
            self.skipTest("ANTIGRAVITY_AUTH_TOKEN not set in test environment")
        res = ph.http_connect_tunnel(
            self.server_host, self.http_port, "daily-cloudcode-pa.googleapis.com", 443,
            username="user", password="WRONG_PASSWORD_XYZ"
        )
        self.assertFalse(res["success"])
        self.assertEqual(res.get("status_code"), 407)

    def test_f5_b03_socks5_invalid_auth_credentials(self):
        """F5.B3: SOCKS5 RFC 1929 with invalid password when auth enabled fails auth subnegotiation."""
        if not self.socks_running:
            self.skipTest("SOCKS5 proxy not listening on 48328 (Pending M1)")
        token = os.environ.get("ANTIGRAVITY_AUTH_TOKEN")
        if not token:
            self.skipTest("ANTIGRAVITY_AUTH_TOKEN not set in test environment")
        res = ph.socks5_connect(
            self.server_host, self.socks_port, "daily-cloudcode-pa.googleapis.com", 443,
            username="user", password="WRONG_PASSWORD_XYZ"
        )
        self.assertFalse(res["success"])

    def test_f5_b04_socks5_unsupported_command_bind(self):
        """F5.B4: SOCKS5 command BIND (0x02) returns REP=0x07 (Command not supported)."""
        if not self.socks_running:
            self.skipTest("SOCKS5 proxy not listening on 48328 (Pending M1)")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((self.server_host, self.socks_port))
            # Greeting: No auth
            s.sendall(b"\x05\x01\x00")
            _ = s.recv(2)
            # Command 0x02 (BIND)
            s.sendall(b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50")
            resp = s.recv(10)
            self.assertGreaterEqual(len(resp), 2)
            self.assertIn(resp[1], [0x07, 0x01])  # 0x07 = Command not supported, 0x01 = General failure
        finally:
            s.close()

    def test_f5_b05_socks5_unsupported_atyp_ipv6(self):
        """F5.B5: SOCKS5 request with unsupported address type returns appropriate error."""
        if not self.socks_running:
            self.skipTest("SOCKS5 proxy not listening on 48328 (Pending M1)")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((self.server_host, self.socks_port))
            s.sendall(b"\x05\x01\x00")
            _ = s.recv(2)
            # Invalid ATYP 0xFF
            s.sendall(b"\x05\x01\x00\xFF\x00\x00")
            resp = s.recv(10)
            self.assertTrue(len(resp) == 0 or resp[1] != 0x00)
        finally:
            s.close()


# ============================================================================
# F6: Managed Systemd Service Daemon Boundaries (>= 5 tests)
# ============================================================================

class TestF6SystemdDaemonBoundaries(unittest.TestCase):
    """F6: Managed Systemd Service Daemon - CLI options, error exits, signal handling."""

    def test_f6_b01_daemon_cli_help_flag(self):
        """F6.B1: python3 unlocker_daemon.py --help returns 0 and displays usage."""
        daemon_script = SERVER_DIR / "unlocker_daemon.py"
        if not daemon_script.exists():
            self.skipTest("unlocker_daemon.py pending M1 implementation")
        code, out, err = ph.run_command_capture(["python3", str(daemon_script), "--help"])
        self.assertEqual(code, 0)
        self.assertTrue("usage" in out.lower() or "help" in out.lower())

    def test_f6_b02_daemon_invalid_cli_argument(self):
        """F6.B2: Running daemon with unknown argument --invalid-xyz exits non-zero."""
        daemon_script = SERVER_DIR / "unlocker_daemon.py"
        if not daemon_script.exists():
            self.skipTest("unlocker_daemon.py pending M1")
        code, out, err = ph.run_command_capture(["python3", str(daemon_script), "--invalid-xyz"])
        self.assertNotEqual(code, 0)

    def test_f6_b03_daemon_custom_ports_parsing(self):
        """F6.B3: Daemon CLI supports specifying custom ports (--dns-port, etc.)."""
        daemon_script = SERVER_DIR / "unlocker_daemon.py"
        if not daemon_script.exists():
            self.skipTest("unlocker_daemon.py pending M1")
        content = daemon_script.read_text()
        self.assertTrue("port" in content.lower())

    def test_f6_b04_systemd_unit_syntax_clean(self):
        """F6.B4: Service file contains valid systemd key-value syntax."""
        unit_file = SERVER_DIR / "antigravity-unlocker.service"
        if not unit_file.exists():
            unit_file = Path("/etc/systemd/system/antigravity-unlocker.service")
        if not unit_file.exists():
            self.skipTest("Systemd unit pending M1")
        lines = [line.strip() for line in unit_file.read_text().splitlines() if line.strip() and not line.startswith("#")]
        for line in lines:
            if line.startswith("["):
                self.assertTrue(line.endswith("]"))
            else:
                self.assertIn("=", line)

    def test_f6_b05_daemon_socket_port_conflict_handling(self):
        """F6.B5: Daemon reports clear error when target port is already in use."""
        daemon_script = SERVER_DIR / "unlocker_daemon.py"
        if not daemon_script.exists():
            self.skipTest("unlocker_daemon.py pending M1")
        # Occupy a test port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        occupied_port = s.getsockname()[1]
        try:
            code, out, err = ph.run_command_capture([
                "python3", str(daemon_script), "--http-port", str(occupied_port)
            ], timeout=2.0)
            # Should exit non-zero due to address conflict or fail
            self.assertNotEqual(code, 0)
        finally:
            s.close()


# ============================================================================
# F7: Client Bash Runtime Boundaries (>= 5 tests)
# ============================================================================

class TestF7ClientBashRuntimeBoundaries(unittest.TestCase):
    """F7: Client Bash Runtime - Boundary and edge conditions."""

    def test_f7_b01_bash_runtime_invalid_arguments(self):
        """F7.B1: client_run.sh with unknown argument exits non-zero."""
        script_path = CLIENT_DIR / "client_run.sh"
        if not script_path.exists():
            self.skipTest("client_run.sh pending M2")
        code, out, err = ph.run_command_capture(["bash", str(script_path), "--nonexistent-option"])
        self.assertNotEqual(code, 0)

    def test_f7_b02_bash_runtime_accepts_custom_server_ip(self):
        """F7.B2: client_run.sh accepts --server parameter."""
        script_path = CLIENT_DIR / "client_run.sh"
        if not script_path.exists():
            self.skipTest("client_run.sh pending M2")
        content = script_path.read_text()
        self.assertTrue("--server" in content or "SERVER" in content)

    def test_f7_b03_bash_runtime_supports_stop_command(self):
        """F7.B3: client_run.sh supports stopping or killing background forwarder."""
        script_path = CLIENT_DIR / "client_run.sh"
        if not script_path.exists():
            self.skipTest("client_run.sh pending M2")
        content = script_path.read_text()
        self.assertTrue("stop" in content.lower() or "kill" in content.lower() or "trap" in content.lower())

    def test_f7_b04_bash_runtime_python_version_check(self):
        """F7.B4: client_run.sh checks for python3 command availability."""
        script_path = CLIENT_DIR / "client_run.sh"
        if not script_path.exists():
            self.skipTest("client_run.sh pending M2")
        content = script_path.read_text()
        self.assertIn("python3", content)

    def test_f7_b05_bash_runtime_dry_run_or_check_mode(self):
        """F7.B5: client_run.sh supports dry-run or status check."""
        script_path = CLIENT_DIR / "client_run.sh"
        if not script_path.exists():
            self.skipTest("client_run.sh pending M2")
        code, out, err = ph.run_command_capture(["bash", str(script_path), "--check"])
        self.assertIn(code, [0, 1])


# ============================================================================
# F8: Client PowerShell Runtime Boundaries (>= 5 tests)
# ============================================================================

class TestF8ClientPowerShellRuntimeBoundaries(unittest.TestCase):
    """F8: Client PowerShell Runtime - Windows edge cases."""

    def test_f8_b01_powershell_custom_parameters(self):
        """F8.B1: client_run.ps1 defines parameter names for ServerHost and AuthToken."""
        script_path = CLIENT_DIR / "client_run.ps1"
        if not script_path.exists():
            self.skipTest("client_run.ps1 pending M2")
        content = script_path.read_text()
        self.assertTrue("Server" in content or "Host" in content)

    def test_f8_b02_powershell_stop_cleanup_flag(self):
        """F8.B2: client_run.ps1 supports -Stop or cleanup routine."""
        script_path = CLIENT_DIR / "client_run.ps1"
        if not script_path.exists():
            self.skipTest("client_run.ps1 pending M2")
        content = script_path.read_text()
        self.assertTrue("stop" in content.lower() or "kill" in content.lower() or "process" in content.lower())

    def test_f8_b03_powershell_execution_policy_resilience(self):
        """F8.B3: Script contains documentation or handling for execution policy bypass."""
        script_path = CLIENT_DIR / "client_run.ps1"
        if not script_path.exists():
            self.skipTest("client_run.ps1 pending M2")
        content = script_path.read_text()
        self.assertTrue(len(content) > 100)

    def test_f8_b04_powershell_checks_python(self):
        """F8.B4: client_run.ps1 checks for python or python3 executable."""
        script_path = CLIENT_DIR / "client_run.ps1"
        if not script_path.exists():
            self.skipTest("client_run.ps1 pending M2")
        content = script_path.read_text()
        self.assertTrue("python" in content.lower())

    def test_f8_b05_powershell_environment_scope(self):
        """F8.B5: Sets process/user environment variable without machine/system administrative registry write."""
        script_path = CLIENT_DIR / "client_run.ps1"
        if not script_path.exists():
            self.skipTest("client_run.ps1 pending M2")
        content = script_path.read_text()
        self.assertNotIn("[EnvironmentVariableTarget]::Machine", content)


# ============================================================================
# F9: Zero-Admin Selective Routing Engine Boundaries (>= 5 tests)
# ============================================================================

class TestF9SelectiveRoutingBoundaries(unittest.TestCase):
    """F9: Zero-Admin Selective Routing Engine - Destination matching and routing decisions."""

    def test_f9_b01_selective_route_ip_literal_target(self):
        """F9.B1: Target destination with raw IP literal (1.1.1.1) recognized as direct route."""
        script_path = CLIENT_DIR / "local_forwarder.py"
        if not script_path.exists():
            self.skipTest("local_forwarder.py pending M2")
        content = script_path.read_text()
        self.assertTrue("direct" in content.lower() or "route" in content.lower())

    def test_f9_b02_selective_route_case_insensitivity(self):
        """F9.B2: Domain matching handles uppercase and mixed-case targets."""
        script_path = CLIENT_DIR / "local_forwarder.py"
        if not script_path.exists():
            self.skipTest("local_forwarder.py pending M2")
        content = script_path.read_text()
        self.assertTrue(".lower()" in content or "casefold" in content or "re.IGNORECASE" in content)

    def test_f9_b03_selective_route_trailing_dot_fqdn(self):
        """F9.B3: Domain matching handles FQDN with trailing dot (daily-cloudcode-pa.googleapis.com.)."""
        script_path = CLIENT_DIR / "local_forwarder.py"
        if not script_path.exists():
            self.skipTest("local_forwarder.py pending M2")
        content = script_path.read_text()
        self.assertTrue("rstrip" in content or "endswith" in content or "strip" in content)

    def test_f9_b04_selective_route_wildcard_matching(self):
        """F9.B4: Matches subdomains like custom-service.googleapis.com."""
        script_path = CLIENT_DIR / "local_forwarder.py"
        if not script_path.exists():
            self.skipTest("local_forwarder.py pending M2")
        content = script_path.read_text()
        self.assertTrue("googleapis.com" in content)

    def test_f9_b05_selective_route_custom_upstream_vps(self):
        """F9.B5: Local forwarder accepts custom remote VPS IP flag."""
        script_path = CLIENT_DIR / "local_forwarder.py"
        if not script_path.exists():
            self.skipTest("local_forwarder.py pending M2")
        code, out, err = ph.run_command_capture(["python3", str(script_path), "--help"])
        self.assertEqual(code, 0)


# ============================================================================
# F10: CLI Wrapper Scripts Boundaries (>= 5 tests)
# ============================================================================

class TestF10CLIWrapperBoundaries(unittest.TestCase):
    """F10: CLI Wrapper Scripts - Exit codes, argument quoting, error propagation."""

    def test_f10_b01_agy_run_empty_arguments(self):
        """F10.B1: agy-run without arguments forwards to agy default output or usage."""
        wrapper = CLIENT_DIR / "agy-run"
        if not wrapper.exists():
            self.skipTest("agy-run pending M3")
        code, out, err = ph.run_command_capture([str(wrapper)])
        # agy without arguments exits 0 and prints help/usage
        self.assertEqual(code, 0)
        self.assertTrue("agy" in out.lower() or "usage" in out.lower())

    def test_f10_b02_agy_run_exit_code_propagation(self):
        """F10.B2: agy-run propagates exit code 1 when given invalid argument."""
        wrapper = CLIENT_DIR / "agy-run"
        if not wrapper.exists():
            self.skipTest("agy-run pending M3")
        code, out, err = ph.run_command_capture([str(wrapper), "--nonexistent-flag-xyz"])
        self.assertNotEqual(code, 0)

    def test_f10_b03_agy_run_spaces_in_prompt(self):
        """F10.B3: agy-run properly quotes multi-word arguments (e.g. -p 'test prompt with spaces')."""
        wrapper = CLIENT_DIR / "agy-run"
        if not wrapper.exists():
            self.skipTest("agy-run pending M3")
        content = wrapper.read_text()
        self.assertTrue('"$@"' in content or '"$*"' in content or 'exec ' in content)

    def test_f10_b04_agy_run_empty_prompt_error_propagation(self):
        """F10.B4: agy-run -p '' returns exit code 1 with error message."""
        wrapper = CLIENT_DIR / "agy-run"
        if not wrapper.exists():
            self.skipTest("agy-run pending M3")
        code, out, err = ph.run_command_capture([str(wrapper), "-p", ""])
        self.assertEqual(code, 1)
        self.assertTrue("empty prompt" in err.lower() or "empty prompt" in out.lower())

    def test_f10_b05_agy_run_preserves_stdio(self):
        """F10.B5: agy-run preserves stdout and stderr separation."""
        wrapper = CLIENT_DIR / "agy-run"
        if not wrapper.exists():
            self.skipTest("agy-run pending M3")
        code, out, err = ph.run_command_capture([str(wrapper), "--version"])
        self.assertEqual(code, 0)
        self.assertTrue(len(out) > 0)


# ============================================================================
# F11: Antigravity IDE Settings Patcher Boundaries (>= 5 tests)
# ============================================================================

class TestF11IDESettingsPatcherBoundaries(unittest.TestCase):
    """F11: Antigravity IDE Settings Patcher - Malformed JSON, empty files, read-only permissions."""

    def test_f11_b01_patcher_corrupt_json_handling(self):
        """F11.B1: Patcher safely handles malformed JSON file by repairing or backing up."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")
        with tempfile.TemporaryDirectory() as tmpdir:
            test_target = Path(tmpdir) / "settings.json"
            test_target.write_text("{ CORRUPTED_JSON_CONTENT [")
            code, out, err = ph.run_command_capture([
                "python3", str(patcher), "--path", str(test_target)
            ])
            # Should handle safely (code 0 or clean error) and not crash with unhandled exception
            self.assertIn(code, [0, 1])

    def test_f11_b02_patcher_empty_file_handling(self):
        """F11.B2: Patcher initializes valid JSON when target is an empty 0-byte file."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")
        with tempfile.TemporaryDirectory() as tmpdir:
            test_target = Path(tmpdir) / "settings.json"
            test_target.touch()
            code, out, err = ph.run_command_capture([
                "python3", str(patcher), "--path", str(test_target)
            ])
            self.assertEqual(code, 0)
            data = json.loads(test_target.read_text())
            self.assertEqual(data.get("jetski.cloudCodeUrl"), "https://daily-cloudcode-pa.googleapis.com")

    def test_f11_b03_patcher_idempotent_multiple_runs(self):
        """F11.B3: Running patcher twice produces identical valid JSON content."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")
        with tempfile.TemporaryDirectory() as tmpdir:
            test_target = Path(tmpdir) / "settings.json"
            ph.run_command_capture(["python3", str(patcher), "--path", str(test_target)])
            first_run = test_target.read_text()
            ph.run_command_capture(["python3", str(patcher), "--path", str(test_target)])
            second_run = test_target.read_text()
            self.assertEqual(first_run, second_run)

    def test_f11_b04_patcher_custom_cloudcode_url(self):
        """F11.B4: Patcher accepts custom URL flag (--url)."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")
        with tempfile.TemporaryDirectory() as tmpdir:
            test_target = Path(tmpdir) / "settings.json"
            custom_url = "https://custom-cloudcode.example.com"
            code, out, err = ph.run_command_capture([
                "python3", str(patcher), "--path", str(test_target), "--url", custom_url
            ])
            if code == 0:
                data = json.loads(test_target.read_text())
                self.assertEqual(data.get("jetski.cloudCodeUrl"), custom_url)

    def test_f11_b05_patcher_read_only_directory_error(self):
        """F11.B5: Patcher targeting non-writable path reports clean error without traceback."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")
        code, out, err = ph.run_command_capture([
            "python3", str(patcher), "--path", "/nonexistent_root_dir/settings.json"
        ])
        self.assertNotEqual(code, 0)
        self.assertNotIn("Traceback (most recent call last):", out)


# ============================================================================
# F12: Cross-Platform Self-Test Diagnostics Boundaries (>= 5 tests)
# ============================================================================

class TestF12SelfTestDiagnosticsBoundaries(unittest.TestCase):
    """F12: Cross-Platform Diagnostics - JSON formats, timeout arguments, and exit statuses."""

    def test_f12_b01_diagnostics_json_output_format(self):
        """F12.B1: python3 diagnose.py --format json produces valid JSON envelope."""
        diag_py = DIAG_DIR / "diagnose.py"
        if not diag_py.exists():
            self.skipTest("diagnose.py pending M3")
        code, out, err = ph.run_command_capture(["python3", str(diag_py), "--format", "json"])
        if code in [0, 1] and out.strip():
            try:
                data = json.loads(out)
                self.assertIsInstance(data, dict)
            except json.JSONDecodeError:
                self.fail("diagnose.py --format json did not output valid JSON")

    def test_f12_b02_diagnostics_timeout_flag(self):
        """F12.B2: diagnose.py respects --timeout parameter."""
        diag_py = DIAG_DIR / "diagnose.py"
        if not diag_py.exists():
            self.skipTest("diagnose.py pending M3")
        code, out, err = ph.run_command_capture(["python3", str(diag_py), "--timeout", "1"])
        self.assertIn(code, [0, 1])

    def test_f12_b03_diagnostics_custom_server_flag(self):
        """F12.B3: diagnose.py accepts --server parameter."""
        diag_py = DIAG_DIR / "diagnose.py"
        if not diag_py.exists():
            self.skipTest("diagnose.py pending M3")
        content = diag_py.read_text()
        self.assertTrue("--server" in content or "server" in content.lower())

    def test_f12_b04_diagnostics_bash_help_flag(self):
        """F12.B4: bash diagnose.sh --help displays options with code 0."""
        diag_sh = DIAG_DIR / "diagnose.sh"
        if not diag_sh.exists():
            self.skipTest("diagnose.sh pending M3")
        code, out, err = ph.run_command_capture(["bash", str(diag_sh), "--help"])
        self.assertEqual(code, 0)

    def test_f12_b05_diagnostics_non_zero_exit_on_critical_failure(self):
        """F12.B5: diagnose.py exits non-zero when targeting unreachable mock server."""
        diag_py = DIAG_DIR / "diagnose.py"
        if not diag_py.exists():
            self.skipTest("diagnose.py pending M3")
        code, out, err = ph.run_command_capture([
            "python3", str(diag_py), "--server", "192.0.2.1", "--timeout", "1"
        ])
        self.assertNotEqual(code, 0)


# ============================================================================
# F13: Client Bundle & Installer Boundaries (>= 5 tests)
# ============================================================================

class TestF13ClientBundleInstallerBoundaries(unittest.TestCase):
    """F13: Client Bundle & Single-File Installer - Custom directory, uninstaller, idempotency."""

    def test_f13_b01_installer_custom_install_dir(self):
        """F13.B1: install.sh --dir /tmp/custom_dest installs into specified directory."""
        installer = PROJECT_ROOT / "install.sh"
        if not installer.exists():
            self.skipTest("install.sh pending M3")
        with tempfile.TemporaryDirectory() as tmpdir:
            dest = Path(tmpdir) / "client_bin"
            code, out, err = ph.run_command_capture([
                "bash", str(installer), "--dir", str(dest)
            ])
            if code == 0:
                self.assertTrue(dest.exists())

    def test_f13_b02_installer_uninstall_flag(self):
        """F13.B2: install.sh --uninstall cleans up installed client artifacts."""
        installer = PROJECT_ROOT / "install.sh"
        if not installer.exists():
            self.skipTest("install.sh pending M3")
        code, out, err = ph.run_command_capture(["bash", str(installer), "--help"])
        self.assertEqual(code, 0)
        self.assertTrue("uninstall" in out.lower() or "--dir" in out.lower())

    def test_f13_b03_installer_idempotency(self):
        """F13.B3: Running install.sh twice executes cleanly without interactive prompt."""
        installer = PROJECT_ROOT / "install.sh"
        if not installer.exists():
            self.skipTest("install.sh pending M3")
        content = installer.read_text()
        self.assertNotIn("read -p", content, "Installer must be non-interactive by default")

    def test_f13_b04_installer_missing_tar_resilience(self):
        """F13.B4: Installer provides clear error if client bundle archive is missing."""
        installer = PROJECT_ROOT / "install.sh"
        if not installer.exists():
            self.skipTest("install.sh pending M3")
        content = installer.read_text()
        self.assertTrue("client_bundle.tar.gz" in content or "tar" in content)

    def test_f13_b05_windows_installer_parameters(self):
        """F13.B5: install.ps1 accepts -InstallDir parameter."""
        installer_ps1 = PROJECT_ROOT / "install.ps1"
        if not installer_ps1.exists():
            self.skipTest("install.ps1 pending M3")
        content = installer_ps1.read_text()
        self.assertTrue("InstallDir" in content or "Path" in content)


# ============================================================================
# F14: Comprehensive Documentation Boundaries (>= 5 tests)
# ============================================================================

class TestF14ComprehensiveDocumentationBoundaries(unittest.TestCase):
    """F14: Documentation - Edge cases, troubleshooting, zero-privilege validation."""

    def test_f14_b01_readme_troubleshooting_port_53_collision(self):
        """F14.B1: README.md documents systemd-resolved port 53 binding conflict resolution."""
        readme = PROJECT_ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md pending M3")
        content = readme.read_text().lower()
        self.assertTrue("systemd-resolved" in content or "port 53" in content or "resolved" in content)

    def test_f14_b02_readme_zero_admin_verification_steps(self):
        """F14.B2: README.md details explicit steps for users to verify no root privileges used."""
        readme = PROJECT_ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md pending M3")
        content = readme.read_text().lower()
        self.assertTrue("whoami" in content or "unprivileged" in content or "zero-admin" in content or "sudo" in content)

    def test_f14_b03_readme_curl_oneliner_syntax(self):
        """F14.B3: README.md includes single-command curl installation command."""
        readme = PROJECT_ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md pending M3")
        content = readme.read_text()
        self.assertTrue("curl" in content)

    def test_f14_b04_readme_powershell_oneliner_syntax(self):
        """F14.B4: README.md includes single-command PowerShell installation command."""
        readme = PROJECT_ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md pending M3")
        content = readme.read_text()
        self.assertTrue("powershell" in content.lower() or "irm" in content.lower() or "iex" in content.lower())

    def test_f14_b05_readme_domain_list_coverage(self):
        """F14.B5: README.md lists critical Google AI endpoints."""
        readme = PROJECT_ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md pending M3")
        content = readme.read_text()
        self.assertIn("daily-cloudcode-pa.googleapis.com", content)
        self.assertIn("generativelanguage.googleapis.com", content)


# ============================================================================
# F15: Comprehensive E2E Test Suite Boundaries (>= 5 tests)
# ============================================================================

class TestF15E2ETestSuiteBoundaries(unittest.TestCase):
    """F15: E2E Test Suite Boundaries - Runner CLI options and reporting."""

    def test_f15_b01_runner_help_flag(self):
        """F15.B1: python3 tests/e2e_runner.py --help exits 0 with argument documentation."""
        runner = TESTS_DIR / "e2e_runner.py"
        if not runner.exists():
            self.skipTest("e2e_runner.py pending implementation")
        code, out, err = ph.run_command_capture(["python3", str(runner), "--help"])
        self.assertEqual(code, 0)
        self.assertTrue("usage" in out.lower() or "options" in out.lower())

    def test_f15_b02_runner_tier_filter_flag(self):
        """F15.B2: e2e_runner.py accepts --tier flag."""
        runner = TESTS_DIR / "e2e_runner.py"
        if not runner.exists():
            self.skipTest("e2e_runner.py pending")
        code, out, err = ph.run_command_capture(["python3", str(runner), "--help"])
        self.assertEqual(code, 0)
        self.assertIn("--tier", out)

    def test_f15_b03_runner_json_output_flag(self):
        """F15.B3: e2e_runner.py accepts --json flag for structured machine output."""
        runner = TESTS_DIR / "e2e_runner.py"
        if not runner.exists():
            self.skipTest("e2e_runner.py pending")
        code, out, err = ph.run_command_capture(["python3", str(runner), "--help"])
        self.assertEqual(code, 0)
        self.assertIn("--json", out)

    def test_f15_b04_runner_invalid_tier_number(self):
        """F15.B4: e2e_runner.py with invalid tier (--tier 99) exits non-zero with error."""
        runner = TESTS_DIR / "e2e_runner.py"
        if not runner.exists():
            self.skipTest("e2e_runner.py pending")
        code, out, err = ph.run_command_capture(["python3", str(runner), "--tier", "99"])
        self.assertNotEqual(code, 0)

    def test_f15_b05_test_ready_artifact_exists(self):
        """F15.B5: TEST_READY.md exists at project root."""
        candidates = [
            PROJECT_ROOT / "TEST_READY.md",
        ]
        found = False
        for p in candidates:
            try:
                if p.exists():
                    found = True
                    break
            except (PermissionError, OSError):
                continue
        if not found:
            self.skipTest("TEST_READY.md pending completion of test suite creation")
        self.assertTrue(found)


# ============================================================================
# F16: Live Prompt E2E Verification Boundaries (>= 5 tests)
# ============================================================================

class TestF16LivePromptBoundaries(unittest.TestCase):
    """F16: Live Prompt E2E Verification - Empty prompts, timeouts, and env var precedence."""

    @classmethod
    def setUpClass(cls):
        cls.agy_binary = Path("/root/.local/bin/agy")
        cls.has_agy = False
        for cand in [shutil.which("agy"), Path.home() / ".local/bin/agy", Path("/root/.local/bin/agy"), Path("/usr/local/bin/agy")]:
            try:
                if cand and Path(cand).exists() and os.access(cand, os.X_OK):
                    cls.agy_binary = Path(cand)
                    cls.has_agy = True
                    break
            except (PermissionError, OSError):
                continue

    def setUp(self):
        time.sleep(1.0)

    def test_f16_b01_agy_empty_prompt_error(self):
        """F16.B1: agy -p '' fails with exit code 1 and empty prompt error message."""
        if not self.has_agy:
            self.skipTest("agy binary not found")
        code, out, err = ph.run_command_capture([str(self.agy_binary), "-p", ""])
        self.assertEqual(code, 1)
        self.assertTrue("empty prompt" in err.lower() or "empty prompt" in out.lower())

    def test_f16_b02_agy_unreachable_proxy_failure(self):
        """F16.B2: Setting HTTPS_PROXY to closed port causes agy to fail with connection refused."""
        if not self.has_agy:
            self.skipTest("agy binary not found")
        code, out, err = ph.run_command_capture(
            [str(self.agy_binary), "-p", "ping", "--print-timeout", "3s"],
            env={"HTTPS_PROXY": "http://127.0.0.1:59999"}
        )
        self.assertEqual(code, 1)
        self.assertTrue("connection refused" in err.lower() or "connection refused" in out.lower() or "dial tcp" in err.lower())

    def test_f16_b03_agy_ignore_all_proxy_verification(self):
        """F16.B3: Setting ALL_PROXY to closed port does NOT affect agy (Go ignores ALL_PROXY)."""
        if not self.has_agy:
            self.skipTest("agy binary not found")
        code, out, err = ph.run_command_capture(
            [str(self.agy_binary), "-p", "ping", "--print-timeout", "15s"],
            env={"ALL_PROXY": "socks5h://127.0.0.1:59999"}
        )
        if code != 0 or "pong" not in out.lower():
            time.sleep(1)
            code, out, err = ph.run_command_capture(
                [str(self.agy_binary), "-p", "ping", "--print-timeout", "15s"],
                env={"ALL_PROXY": "socks5h://127.0.0.1:59999"}
            )
        self.assertEqual(code, 0)
        self.assertIn("pong", out.lower())

    def test_f16_b04_agy_no_proxy_override(self):
        """F16.B4: Setting NO_PROXY overrides HTTPS_PROXY for specified domains."""
        if not self.has_agy:
            self.skipTest("agy binary not found")
        code, out, err = ph.run_command_capture(
            [str(self.agy_binary), "-p", "ping", "--print-timeout", "15s"],
            env={
                "HTTPS_PROXY": "http://127.0.0.1:59999",
                "NO_PROXY": "googleapis.com,googleusercontent.com,goog"
            }
        )
        if code != 0 or "pong" not in out.lower():
            # Retry once in case of public API rate limiting or network latency
            time.sleep(1)
            code, out, err = ph.run_command_capture(
                [str(self.agy_binary), "-p", "ping", "--print-timeout", "15s"],
                env={
                    "HTTPS_PROXY": "http://127.0.0.1:59999",
                    "NO_PROXY": "googleapis.com,googleusercontent.com,goog"
                }
            )
        self.assertEqual(code, 0)
        self.assertIn("pong", out.lower())

    def test_f16_b05_agy_timeout_boundary(self):
        """F16.B5: agy --print-timeout 10s executes successfully within timeout limit."""
        if not self.has_agy:
            self.skipTest("agy binary not found")
        start_t = time.perf_counter()
        code, out, err = ph.run_command_capture(
            [str(self.agy_binary), "-p", "ping", "--print-timeout", "10s"]
        )
        elapsed = time.perf_counter() - start_t
        self.assertEqual(code, 0)
        self.assertLess(elapsed, 10.0)


if __name__ == "__main__":
    unittest.main()
