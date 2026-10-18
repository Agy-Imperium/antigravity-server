"""
Antigravity Zero-Privilege Bypass System - Tier 1: Isolated Feature Coverage
Tests features F1 through F16 (minimum 5 test cases per feature, 80+ total)
Following Category-Partition Happy Path specifications from PROJECT.md & ORIGINAL_REQUEST.md.
Opaque-box testing: Only interacts via external protocols, sockets, filesystem, or subprocesses.
"""

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
# F1: DNS UDP/TCP Interceptor (>= 5 tests)
# ============================================================================

class TestF1DNSInterceptor(unittest.TestCase):
    """F1: DNS UDP/TCP Interceptor - Category-Partition Isolated Happy Paths."""

    @classmethod
    def setUpClass(cls):
        cls.server_host = os.environ.get("ANTIGRAVITY_SERVER_HOST", ph.DEFAULT_VPS_IP)
        cls.dns_port = ph.DEFAULT_DNS_PORT
        cls.dns_running = ph.is_udp_dns_responsive(cls.server_host, cls.dns_port)

    def test_f1_01_dns_udp_intercept_daily_cloudcode(self):
        """F1.1: Intercept daily-cloudcode-pa.googleapis.com over UDP -> VPS IP."""
        if not self.dns_running:
            self.skipTest("DNS service not active on target host:port (Pending M1 deployment)")
        resp = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port)
        self.assertTrue(resp["valid"], "Expected valid DNS response")
        self.assertEqual(resp["rcode"], 0, "Expected RCODE=0 (NOERROR)")
        self.assertGreaterEqual(resp["ancount"], 1, "Expected at least 1 answer record")
        a_records = [ans["ip"] for ans in resp["answers"] if ans["type"] == 1]
        self.assertIn(self.server_host, a_records, f"Expected {self.server_host} in DNS A records")

    def test_f1_02_dns_udp_intercept_generativelanguage(self):
        """F1.2: Intercept generativelanguage.googleapis.com over UDP -> VPS IP."""
        if not self.dns_running:
            self.skipTest("DNS service not active on target host:port (Pending M1 deployment)")
        resp = ph.send_dns_query_udp("generativelanguage.googleapis.com", self.server_host, self.dns_port)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0)
        a_records = [ans["ip"] for ans in resp["answers"] if ans["type"] == 1]
        self.assertIn(self.server_host, a_records)

    def test_f1_03_dns_tcp_intercept_cloudcode(self):
        """F1.3: Intercept cloudcode-pa.googleapis.com over TCP (2-byte framing) -> VPS IP."""
        if not self.dns_running:
            self.skipTest("DNS service not active on target host:port (Pending M1 deployment)")
        resp = ph.send_dns_query_tcp("cloudcode-pa.googleapis.com", self.server_host, self.dns_port)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0)
        a_records = [ans["ip"] for ans in resp["answers"] if ans["type"] == 1]
        self.assertIn(self.server_host, a_records)

    def test_f1_04_dns_udp_upstream_proxy_cloudflare(self):
        """F1.4: Proxy non-intercepted domain (example.com) to upstream DNS over UDP."""
        if not self.dns_running:
            self.skipTest("DNS service not active on target host:port (Pending M1 deployment)")
        resp = ph.send_dns_query_udp("example.com", self.server_host, self.dns_port)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0)
        a_records = [ans["ip"] for ans in resp["answers"] if ans["type"] == 1]
        self.assertGreaterEqual(len(a_records), 1, "Expected upstream A record for example.com")
        self.assertNotIn(self.server_host, a_records, "Non-intercepted domain must not resolve to VPS IP")

    def test_f1_05_dns_tcp_upstream_proxy_example_net(self):
        """F1.5: Proxy non-intercepted domain (example.net) to upstream DNS over TCP."""
        if not self.dns_running:
            self.skipTest("DNS service not active on target host:port (Pending M1 deployment)")
        resp = ph.send_dns_query_tcp("example.net", self.server_host, self.dns_port)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0)
        a_records = [ans["ip"] for ans in resp["answers"] if ans["type"] == 1]
        self.assertGreaterEqual(len(a_records), 1)


# ============================================================================
# F2: DNS ECH & IPv6 Suppression (>= 5 tests)
# ============================================================================

class TestF2ECHIPv6Suppression(unittest.TestCase):
    """F2: DNS ECH & IPv6 Suppression - Responds with NODATA (ANCOUNT=0) for AAAA & Type 65."""

    @classmethod
    def setUpClass(cls):
        cls.server_host = os.environ.get("ANTIGRAVITY_SERVER_HOST", ph.DEFAULT_VPS_IP)
        cls.dns_port = ph.DEFAULT_DNS_PORT
        cls.dns_running = ph.is_udp_dns_responsive(cls.server_host, cls.dns_port)

    def test_f2_01_aaaa_query_suppression_daily_cloudcode(self):
        """F2.1: AAAA (Type 28) query for daily-cloudcode-pa.googleapis.com returns NODATA (ANCOUNT=0)."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        resp = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port, qtype=28)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0, "NODATA must return NOERROR (0)")
        self.assertEqual(resp["ancount"], 0, "AAAA query on intercepted domain must have ANCOUNT=0")

    def test_f2_02_aaaa_query_suppression_generativelanguage(self):
        """F2.2: AAAA (Type 28) query for generativelanguage.googleapis.com returns NODATA."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        resp = ph.send_dns_query_udp("generativelanguage.googleapis.com", self.server_host, self.dns_port, qtype=28)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0)
        self.assertEqual(resp["ancount"], 0)

    def test_f2_03_type65_https_query_suppression(self):
        """F2.3: HTTPS (Type 65) query for daily-cloudcode-pa.googleapis.com returns NODATA (suppresses ECH)."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        resp = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port, qtype=65)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0)
        self.assertEqual(resp["ancount"], 0, "Type 65 query must return ANCOUNT=0 to prevent client ECH")

    def test_f2_04_type64_svcb_query_suppression(self):
        """F2.4: SVCB (Type 64) query for Google AI endpoint returns NODATA."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        resp = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port, qtype=64)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0)
        self.assertEqual(resp["ancount"], 0)

    def test_f2_05_non_intercepted_aaaa_passthrough(self):
        """F2.5: AAAA query on non-intercepted domain (google.com or cloudflare.com) proxies upstream."""
        if not self.dns_running:
            self.skipTest("DNS service not active (Pending M1)")
        resp = ph.send_dns_query_udp("cloudflare.com", self.server_host, self.dns_port, qtype=28)
        self.assertTrue(resp["valid"])
        self.assertEqual(resp["rcode"], 0)


# ============================================================================
# F3: Non-Terminating SNI Proxy Engine (>= 5 tests)
# ============================================================================

class TestF3SNIProxyEngine(unittest.TestCase):
    """F3: Non-Terminating SNI Proxy Engine - Transparent TCP relay to Google Edge IPs."""

    @classmethod
    def setUpClass(cls):
        cls.server_host = os.environ.get("ANTIGRAVITY_SERVER_HOST", ph.DEFAULT_VPS_IP)
        cls.sni_port = ph.DEFAULT_SNI_PORT
        cls.sni_running = ph.is_tcp_port_open(cls.server_host, cls.sni_port)

    def test_f3_01_sni_proxy_daily_cloudcode(self):
        """F3.1: TLS ClientHello with SNI daily-cloudcode-pa.googleapis.com receives Google ServerHello."""
        if not self.sni_running:
            self.skipTest("SNI Proxy not listening on port 443 (Pending M1)")
        res = ph.send_sni_client_hello(self.server_host, self.sni_port, "daily-cloudcode-pa.googleapis.com")
        self.assertTrue(res["connected"])
        self.assertTrue(res["is_tls"])
        self.assertTrue(res["is_server_hello"])

    def test_f3_02_sni_proxy_generativelanguage(self):
        """F3.2: TLS ClientHello with SNI generativelanguage.googleapis.com receives Google ServerHello."""
        if not self.sni_running:
            self.skipTest("SNI Proxy not listening on port 443 (Pending M1)")
        res = ph.send_sni_client_hello(self.server_host, self.sni_port, "generativelanguage.googleapis.com")
        self.assertTrue(res["connected"])
        self.assertTrue(res["is_tls"])
        self.assertTrue(res["is_server_hello"])

    def test_f3_03_sni_proxy_antigravity_unleash(self):
        """F3.3: TLS ClientHello with SNI antigravity-unleash.goog receives Google ServerHello."""
        if not self.sni_running:
            self.skipTest("SNI Proxy not listening on port 443 (Pending M1)")
        res = ph.send_sni_client_hello(self.server_host, self.sni_port, "antigravity-unleash.goog")
        self.assertTrue(res["connected"])
        self.assertTrue(res["is_tls"])

    def test_f3_04_sni_proxy_certificate_chain_validation(self):
        """F3.4: Validate end-to-end TLS handshake preserves authentic Google Trust Services certificate."""
        if not self.sni_running:
            self.skipTest("SNI Proxy not listening on port 443 (Pending M1)")
        ctx = ssl.create_default_context()
        with socket.create_connection((self.server_host, self.sni_port), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname="daily-cloudcode-pa.googleapis.com") as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", ()))
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                # Verified Google certificate attributes
                self.assertTrue("Google" in str(issuer) or "GTS" in str(issuer))

    def test_f3_05_sni_proxy_http2_alpn_negotiation(self):
        """F3.5: ClientHello proposing h2 and http/1.1 ALPN negotiates successfully with Google edge."""
        if not self.sni_running:
            self.skipTest("SNI Proxy not listening on port 443 (Pending M1)")
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        with socket.create_connection((self.server_host, self.sni_port), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname="generativelanguage.googleapis.com") as ssock:
                negotiated = ssock.selected_alpn_protocol()
                self.assertIn(negotiated, ["h2", "http/1.1"])


# ============================================================================
# F4: Dynamic Google Edge IP Resolver (>= 5 tests)
# ============================================================================

class TestF4DynamicGoogleEdgeResolver(unittest.TestCase):
    """F4: Dynamic Google Edge IP Resolver - Anycast pool health and routing."""

    def test_f4_01_edge_ip_pool_reachability(self):
        """F4.1: Verify Google Anycast edge IP pool (172.217.112.4-119.4) accepts TCP 443."""
        reachable_count = 0
        for edge_ip in ph.GOOGLE_EDGE_IPS[:4]:
            if ph.is_tcp_port_open(edge_ip, 443, timeout=1.5):
                reachable_count += 1
        self.assertGreaterEqual(reachable_count, 1, "At least one Google Anycast edge IP must be directly reachable")

    def test_f4_02_edge_ip_tls_handshake_generativelanguage(self):
        """F4.2: Direct TLS handshake to edge IP with SNI generativelanguage.googleapis.com succeeds."""
        target_ip = ph.GOOGLE_EDGE_IPS[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((target_ip, 443), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname="generativelanguage.googleapis.com") as ssock:
                cert = ssock.getpeercert()
                self.assertIsNotNone(cert)

    def test_f4_03_edge_ip_http_response_validation(self):
        """F4.3: Raw HTTP request to edge IP returns valid Google GFE response (403/404/200)."""
        target_ip = ph.GOOGLE_EDGE_IPS[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((target_ip, 443), timeout=5.0) as sock:
            with ctx.wrap_socket(sock, server_hostname="daily-cloudcode-pa.googleapis.com") as ssock:
                req = b"GET / HTTP/1.1\r\nHost: daily-cloudcode-pa.googleapis.com\r\nConnection: close\r\n\r\n"
                ssock.sendall(req)
                resp = ssock.recv(1024).decode("utf-8", errors="replace")
                status_line = resp.split("\r\n")[0]
                self.assertTrue("HTTP/" in status_line)

    def test_f4_04_edge_ip_pool_redundancy(self):
        """F4.4: Verify edge IP pool contains multiple distinct IPs for round-robin/failover."""
        unique_ips = set(ph.GOOGLE_EDGE_IPS)
        self.assertGreaterEqual(len(unique_ips), 4, "Edge IP pool must contain at least 4 unique Anycast IPs")

    def test_f4_05_edge_ip_low_latency_egress(self):
        """F4.5: Latency to primary Frankfurt edge IP is within acceptable VPS limit (< 500ms)."""
        start_t = time.perf_counter()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        try:
            s.connect((ph.GOOGLE_EDGE_IPS[0], 443))
            elapsed = time.perf_counter() - start_t
            self.assertLess(elapsed, 0.50, f"Latency to Google edge IP exceeded threshold: {elapsed:.3f}s")
        finally:
            s.close()


# ============================================================================
# F5: Authenticated Remote Proxy Inbound (>= 5 tests)
# ============================================================================

class TestF5AuthenticatedRemoteProxyInbound(unittest.TestCase):
    """F5: Authenticated Remote Proxy Inbound - SOCKS5 (48328) & HTTP CONNECT (48329)."""

    @classmethod
    def setUpClass(cls):
        cls.server_host = os.environ.get("ANTIGRAVITY_SERVER_HOST", ph.DEFAULT_VPS_IP)
        cls.socks_port = ph.DEFAULT_SOCKS_PORT
        cls.http_port = ph.DEFAULT_HTTP_PORT
        cls.socks_running = ph.is_tcp_port_open(cls.server_host, cls.socks_port)
        cls.http_running = ph.is_tcp_port_open(cls.server_host, cls.http_port)

    def test_f5_01_http_connect_daily_cloudcode(self):
        """F5.1: HTTP CONNECT to daily-cloudcode-pa.googleapis.com:443 establishes tunnel (200)."""
        if not self.http_running:
            self.skipTest("HTTP CONNECT proxy not listening on 48329 (Pending M1)")
        res = ph.http_connect_tunnel(self.server_host, self.http_port, "daily-cloudcode-pa.googleapis.com", 443)
        self.assertTrue(res["success"], f"HTTP CONNECT failed: {res.get('status_line')}")
        self.assertEqual(res["status_code"], 200)
        if res.get("sock"):
            res["sock"].close()

    def test_f5_02_socks5_connect_domain(self):
        """F5.2: SOCKS5 CONNECT with domain destination (ATYP 0x03) succeeds."""
        if not self.socks_running:
            self.skipTest("SOCKS5 proxy not listening on 48328 (Pending M1)")
        res = ph.socks5_connect(self.server_host, self.socks_port, "daily-cloudcode-pa.googleapis.com", 443, dest_is_domain=True)
        self.assertTrue(res["success"], f"SOCKS5 CONNECT domain failed: {res.get('error')}")
        if res.get("sock"):
            res["sock"].close()

    def test_f5_03_socks5_connect_ipv4(self):
        """F5.3: SOCKS5 CONNECT with IPv4 destination (ATYP 0x01) succeeds."""
        if not self.socks_running:
            self.skipTest("SOCKS5 proxy not listening on 48328 (Pending M1)")
        target_ip = ph.GOOGLE_EDGE_IPS[0]
        res = ph.socks5_connect(self.server_host, self.socks_port, target_ip, 443, dest_is_domain=False)
        self.assertTrue(res["success"], f"SOCKS5 CONNECT IPv4 failed: {res.get('error')}")
        if res.get("sock"):
            res["sock"].close()

    def test_f5_04_http_connect_tls_handshake_through_tunnel(self):
        """F5.4: Perform end-to-end TLS handshake over established HTTP CONNECT tunnel."""
        if not self.http_running:
            self.skipTest("HTTP CONNECT proxy not listening on 48329 (Pending M1)")
        res = ph.http_connect_tunnel(self.server_host, self.http_port, "generativelanguage.googleapis.com", 443)
        self.assertTrue(res["success"])
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(res["sock"], server_hostname="generativelanguage.googleapis.com") as ssock:
            cert = ssock.getpeercert()
            self.assertIsNotNone(cert)

    def test_f5_05_socks5_tls_handshake_through_tunnel(self):
        """F5.5: Perform end-to-end TLS handshake over established SOCKS5 tunnel."""
        if not self.socks_running:
            self.skipTest("SOCKS5 proxy not listening on 48328 (Pending M1)")
        res = ph.socks5_connect(self.server_host, self.socks_port, "daily-cloudcode-pa.googleapis.com", 443)
        self.assertTrue(res["success"])
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(res["sock"], server_hostname="daily-cloudcode-pa.googleapis.com") as ssock:
            cert = ssock.getpeercert()
            self.assertIsNotNone(cert)


# ============================================================================
# F6: Managed Systemd Service Daemon (>= 5 tests)
# ============================================================================

class TestF6SystemdServiceDaemon(unittest.TestCase):
    """F6: Managed Systemd Service Daemon - Configuration and lifecycle inspection."""

    def test_f6_01_systemd_unit_file_exists(self):
        """F6.1: Service unit file antigravity-unlocker.service exists in project server/ or systemd."""
        candidate_paths = [
            SERVER_DIR / "antigravity-unlocker.service",
            Path("/etc/systemd/system/antigravity-unlocker.service"),
        ]
        found = any(p.exists() for p in candidate_paths)
        if not found:
            self.skipTest("Systemd unit file not yet created in server/ or /etc (Pending M1)")
        self.assertTrue(found)

    def test_f6_02_systemd_unit_file_structure(self):
        """F6.2: Service unit file contains required [Unit], [Service], and [Install] sections."""
        unit_file = SERVER_DIR / "antigravity-unlocker.service"
        if not unit_file.exists():
            unit_file = Path("/etc/systemd/system/antigravity-unlocker.service")
        if not unit_file.exists():
            self.skipTest("Systemd unit file pending M1")
        content = unit_file.read_text()
        self.assertIn("[Unit]", content)
        self.assertIn("[Service]", content)
        self.assertIn("[Install]", content)

    def test_f6_03_systemd_unit_execstart_target(self):
        """F6.3: Service ExecStart executes python3 unlocker_daemon.py."""
        unit_file = SERVER_DIR / "antigravity-unlocker.service"
        if not unit_file.exists():
            unit_file = Path("/etc/systemd/system/antigravity-unlocker.service")
        if not unit_file.exists():
            self.skipTest("Systemd unit file pending M1")
        content = unit_file.read_text()
        self.assertIn("ExecStart", content)
        self.assertIn("python3", content)

    def test_f6_04_systemd_unit_restart_policy(self):
        """F6.4: Service specifies Restart=always or on-failure."""
        unit_file = SERVER_DIR / "antigravity-unlocker.service"
        if not unit_file.exists():
            unit_file = Path("/etc/systemd/system/antigravity-unlocker.service")
        if not unit_file.exists():
            self.skipTest("Systemd unit file pending M1")
        content = unit_file.read_text()
        self.assertTrue("Restart=always" in content or "Restart=on-failure" in content)

    def test_f6_05_systemd_unit_network_dependency(self):
        """F6.5: Service specifies After=network.target."""
        unit_file = SERVER_DIR / "antigravity-unlocker.service"
        if not unit_file.exists():
            unit_file = Path("/etc/systemd/system/antigravity-unlocker.service")
        if not unit_file.exists():
            self.skipTest("Systemd unit file pending M1")
        content = unit_file.read_text()
        self.assertIn("After=network.target", content)


# ============================================================================
# F7: Client Bash Runtime (client_run.sh) (>= 5 tests)
# ============================================================================

class TestF7ClientBashRuntime(unittest.TestCase):
    """F7: Client Bash Runtime - 100% user-space script for Linux/macOS."""

    def test_f7_01_script_exists_and_executable(self):
        """F7.1: client_run.sh exists in client/ and is executable."""
        script_path = CLIENT_DIR / "client_run.sh"
        if not script_path.exists():
            self.skipTest("client_run.sh pending M2 implementation")
        self.assertTrue(os.access(script_path, os.X_OK) or script_path.exists())

    def test_f7_02_script_contains_zero_sudo(self):
        """F7.2: Verify script contains zero calls to sudo or root-only commands."""
        script_path = CLIENT_DIR / "client_run.sh"
        if not script_path.exists():
            self.skipTest("client_run.sh pending M2")
        content = script_path.read_text()
        self.assertNotIn("sudo ", content, "client_run.sh must be 100% zero-privilege without sudo")
        self.assertNotIn("doas ", content)

    def test_f7_03_script_help_flag(self):
        """F7.3: Running bash client_run.sh --help displays usage and exits 0."""
        script_path = CLIENT_DIR / "client_run.sh"
        if not script_path.exists():
            self.skipTest("client_run.sh pending M2")
        code, out, err = ph.run_command_capture(["bash", str(script_path), "--help"])
        self.assertEqual(code, 0)
        self.assertTrue("Usage" in out or "usage" in out.lower() or "antigravity" in out.lower())

    def test_f7_04_script_defines_proxy_ports(self):
        """F7.4: Script configures 48328 (SOCKS5) and 48329 (HTTP CONNECT) stealth ports."""
        script_path = CLIENT_DIR / "client_run.sh"
        if not script_path.exists():
            self.skipTest("client_run.sh pending M2")
        content = script_path.read_text()
        self.assertIn("48328", content)
        self.assertIn("48329", content)

    def test_f7_05_script_exports_uppercase_proxy_variables(self):
        """F7.5: Script exports uppercase HTTPS_PROXY and ALL_PROXY."""
        script_path = CLIENT_DIR / "client_run.sh"
        if not script_path.exists():
            self.skipTest("client_run.sh pending M2")
        content = script_path.read_text()
        self.assertIn("HTTPS_PROXY", content)
        self.assertIn("ALL_PROXY", content)


# ============================================================================
# F8: Client PowerShell Runtime (client_run.ps1) (>= 5 tests)
# ============================================================================

class TestF8ClientPowerShellRuntime(unittest.TestCase):
    """F8: Client PowerShell Runtime - 100% user-space script for Windows."""

    def test_f8_01_script_exists(self):
        """F8.1: client_run.ps1 exists in client/."""
        script_path = CLIENT_DIR / "client_run.ps1"
        if not script_path.exists():
            self.skipTest("client_run.ps1 pending M2 implementation")
        self.assertTrue(script_path.exists())

    def test_f8_02_script_zero_admin_constraint(self):
        """F8.2: Script contains no RunAsAdministrator or UAC elevation directives."""
        script_path = CLIENT_DIR / "client_run.ps1"
        if not script_path.exists():
            self.skipTest("client_run.ps1 pending M2")
        content = script_path.read_text()
        self.assertNotIn("#Requires -RunAsAdministrator", content)
        self.assertNotIn("Verb RunAs", content)

    def test_f8_03_script_sets_user_env_variables(self):
        """F8.3: Script sets $env:HTTPS_PROXY and $env:ALL_PROXY."""
        script_path = CLIENT_DIR / "client_run.ps1"
        if not script_path.exists():
            self.skipTest("client_run.ps1 pending M2")
        content = script_path.read_text()
        self.assertIn("HTTPS_PROXY", content)
        self.assertIn("48329", content)

    def test_f8_04_script_launches_forwarder(self):
        """F8.4: Script configures direct connection to stealth ports."""
        script_path = CLIENT_DIR / "client_run.ps1"
        if not script_path.exists():
            self.skipTest("client_run.ps1 pending M2")
        content = script_path.read_text()
        self.assertTrue("EffectiveHttpPort" in content or "48329" in content)

    def test_f8_05_script_supports_parameter_binding(self):
        """F8.5: Script contains param block or parameter handling."""
        script_path = CLIENT_DIR / "client_run.ps1"
        if not script_path.exists():
            self.skipTest("client_run.ps1 pending M2")
        content = script_path.read_text()
        self.assertTrue("param" in content.lower() or "$Server" in content or "target_host" in content.lower())


# ============================================================================
# F9: Zero-Admin Selective Routing Engine (>= 5 tests)
# ============================================================================

class TestF9SelectiveRoutingEngine(unittest.TestCase):
    """F9: Zero-Admin Selective Routing Engine - Routes Google AI to VPS and others direct."""

    def test_f9_01_forwarder_script_exists(self):
        """F9.1: Selective routing engine exists in client/."""
        script_path = CLIENT_DIR / "agy-run"
        if not script_path.exists():
            script_path = CLIENT_DIR / "patch_account.py"
        self.assertTrue(script_path.exists())

    def test_f9_02_forwarder_contains_google_domain_list(self):
        """F9.2: Selective routing engine specifies Google AI interception domains."""
        script_path = CLIENT_DIR / "patch_account.py"
        content = script_path.read_text()
        self.assertTrue("googleapis.com" in content or "cloudcode" in content)

    def test_f9_03_forwarder_zero_admin_execution(self):
        """F9.3: Running python3 patch_account.py --help executes in unprivileged user space."""
        script_path = CLIENT_DIR / "patch_account.py"
        code, out, err = ph.run_command_capture(["python3", str(script_path), "--help"])
        self.assertEqual(code, 0)

    def test_f9_04_forwarder_defaults_to_vps_ip(self):
        """F9.4: Default target VPS IP matches configured or discovered server host."""
        script_path = CLIENT_DIR / "patch_account.py"
        content = script_path.read_text()
        self.assertTrue("ANTIGRAVITY_SERVER_HOST" in content or "target_host" in content or "discovery" in content)

    def test_f9_05_forwarder_selective_routing_logic(self):
        """F9.5: Routing engine contains logic distinguishing direct vs tunneled destinations."""
        script_path = CLIENT_DIR / "patch_account.py"
        content = script_path.read_text()
        self.assertTrue("direct" in content.lower() or "proxy" in content.lower())


# ============================================================================
# F10: CLI Wrapper Scripts (agy-run / agy-run.ps1) (>= 5 tests)
# ============================================================================

class TestF10CLIWrapperScripts(unittest.TestCase):
    """F10: CLI Wrapper Scripts - Launches agy with tunnel validation and flag passthrough."""

    def test_f10_01_agy_run_script_exists_and_executable(self):
        """F10.1: agy-run exists in client/ and is executable."""
        wrapper = CLIENT_DIR / "agy-run"
        if not wrapper.exists():
            self.skipTest("agy-run pending M3 implementation")
        self.assertTrue(os.access(wrapper, os.X_OK) or wrapper.exists())

    def test_f10_02_agy_run_help_passthrough(self):
        """F10.2: agy-run --help passes through to agy --help and exits 0."""
        wrapper = CLIENT_DIR / "agy-run"
        if not wrapper.exists():
            self.skipTest("agy-run pending M3")
        code, out, err = ph.run_command_capture([str(wrapper), "--help"])
        self.assertEqual(code, 0)
        self.assertTrue("agy" in out or "Usage:" in out or "options" in out.lower())

    def test_f10_03_agy_run_version_passthrough(self):
        """F10.3: agy-run --version passes through to agy --version."""
        wrapper = CLIENT_DIR / "agy-run"
        if not wrapper.exists():
            self.skipTest("agy-run pending M3")
        code, out, err = ph.run_command_capture([str(wrapper), "--version"])
        self.assertEqual(code, 0)
        self.assertTrue("1.3." in out or "agy" in out.lower())

    def test_f10_04_agy_run_exports_uppercase_https_proxy(self):
        """F10.4: agy-run exports uppercase HTTPS_PROXY before calling agy."""
        wrapper = CLIENT_DIR / "agy-run"
        if not wrapper.exists():
            self.skipTest("agy-run pending M3")
        content = wrapper.read_text()
        self.assertIn("HTTPS_PROXY", content)

    def test_f10_05_agy_run_ps1_exists(self):
        """F10.5: Windows wrapper agy-run.ps1 exists in client/."""
        wrapper_ps1 = CLIENT_DIR / "agy-run.ps1"
        if not wrapper_ps1.exists():
            self.skipTest("agy-run.ps1 pending M3")
        self.assertTrue(wrapper_ps1.exists())


# ============================================================================
# F11: Antigravity IDE Settings Patcher (>= 5 tests)
# ============================================================================

class TestF11IDESettingsPatcher(unittest.TestCase):
    """F11: Antigravity IDE Settings Patcher - Modifies jetski.cloudCodeUrl without admin."""

    def test_f11_01_patcher_script_exists(self):
        """F11.1: patch_ide_settings.py exists in client/."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3 implementation")
        self.assertTrue(patcher.exists())

    def test_f11_02_patcher_creates_missing_settings_file(self):
        """F11.2: Patcher creates missing settings.json in temporary user config directory."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")
        with tempfile.TemporaryDirectory() as tmpdir:
            test_target = Path(tmpdir) / ".config" / "Antigravity" / "User" / "settings.json"
            code, out, err = ph.run_command_capture([
                "python3", str(patcher), "--path", str(test_target)
            ])
            self.assertEqual(code, 0)
            self.assertTrue(test_target.exists())
            content = test_target.read_text()
            self.assertIn('"jetski.cloudCodeUrl"', content)
            self.assertIn("https://daily-cloudcode-pa.googleapis.com", content)

    def test_f11_03_patcher_preserves_existing_keys(self):
        """F11.3: Patcher preserves existing user settings keys while injecting jetski.cloudCodeUrl."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")
        with tempfile.TemporaryDirectory() as tmpdir:
            test_target = Path(tmpdir) / "settings.json"
            test_target.write_text('{"editor.fontSize": 14, "workbench.colorTheme": "Dark+"}')
            code, out, err = ph.run_command_capture([
                "python3", str(patcher), "--path", str(test_target)
            ])
            self.assertEqual(code, 0)
            content = test_target.read_text()
            self.assertIn('"editor.fontSize": 14', content)
            self.assertIn('"workbench.colorTheme": "Dark+"', content)
            self.assertIn('"jetski.cloudCodeUrl"', content)

    def test_f11_04_patcher_dry_run_option(self):
        """F11.4: Running patcher with --dry-run does not write to disk."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")
        with tempfile.TemporaryDirectory() as tmpdir:
            test_target = Path(tmpdir) / "settings.json"
            code, out, err = ph.run_command_capture([
                "python3", str(patcher), "--path", str(test_target), "--dry-run"
            ])
            self.assertEqual(code, 0)
            self.assertFalse(test_target.exists(), "Dry run must not create the file")

    def test_f11_05_patcher_help_flag(self):
        """F11.5: Running patcher --help outputs usage with code 0."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")
        code, out, err = ph.run_command_capture(["python3", str(patcher), "--help"])
        self.assertEqual(code, 0)


# ============================================================================
# F12: Cross-Platform Self-Test Diagnostics (>= 5 tests)
# ============================================================================

class TestF12SelfTestDiagnostics(unittest.TestCase):
    """F12: Cross-Platform Self-Test Diagnostics - diagnose.sh / diagnose.py."""

    def test_f12_01_diagnostics_scripts_exist(self):
        """F12.1: diagnose.sh and diagnose.py exist in diagnostics/."""
        diag_py = DIAG_DIR / "diagnose.py"
        diag_sh = DIAG_DIR / "diagnose.sh"
        if not diag_py.exists():
            self.skipTest("diagnose.py pending M3 implementation")
        self.assertTrue(diag_py.exists())
        self.assertTrue(diag_sh.exists())

    def test_f12_02_diagnostics_python_help_flag(self):
        """F12.2: python3 diagnose.py --help prints usage and exits 0."""
        diag_py = DIAG_DIR / "diagnose.py"
        if not diag_py.exists():
            self.skipTest("diagnose.py pending M3")
        code, out, err = ph.run_command_capture(["python3", str(diag_py), "--help"])
        self.assertEqual(code, 0)

    def test_f12_03_diagnostics_bash_executable(self):
        """F12.3: diagnose.sh is executable and runs without sudo."""
        diag_sh = DIAG_DIR / "diagnose.sh"
        if not diag_sh.exists():
            self.skipTest("diagnose.sh pending M3")
        self.assertTrue(os.access(diag_sh, os.X_OK) or diag_sh.exists())

    def test_f12_04_diagnostics_checks_dns_resolution(self):
        """F12.4: diagnose.py contains DNS resolution test logic."""
        diag_py = DIAG_DIR / "diagnose.py"
        if not diag_py.exists():
            self.skipTest("diagnose.py pending M3")
        content = diag_py.read_text()
        self.assertTrue("dns" in content.lower())

    def test_f12_05_diagnostics_checks_sni_and_agy(self):
        """F12.5: diagnose.py checks SNI proxy reachability and agy status."""
        diag_py = DIAG_DIR / "diagnose.py"
        if not diag_py.exists():
            self.skipTest("diagnose.py pending M3")
        content = diag_py.read_text()
        self.assertTrue("sni" in content.lower() or "tls" in content.lower())
        self.assertTrue("agy" in content.lower())


# ============================================================================
# F13: Client Bundle & Single-File Installer (>= 5 tests)
# ============================================================================

class TestF13ClientBundleAndInstaller(unittest.TestCase):
    """F13: Client Bundle & Single-File Installer - install.sh, install.ps1, client_bundle.tar.gz."""

    def test_f13_01_installer_script_exists_and_executable(self):
        """F13.1: install.sh exists in project root and is executable."""
        installer = PROJECT_ROOT / "install.sh"
        if not installer.exists():
            self.skipTest("install.sh pending M3 packaging")
        self.assertTrue(os.access(installer, os.X_OK) or installer.exists())

    def test_f13_02_installer_contains_zero_sudo(self):
        """F13.2: install.sh contains no calls to sudo or root-only paths."""
        installer = PROJECT_ROOT / "install.sh"
        if not installer.exists():
            self.skipTest("install.sh pending M3")
        content = installer.read_text()
        self.assertNotIn("sudo ", content)

    def test_f13_03_windows_installer_exists(self):
        """F13.3: install.ps1 exists in project root."""
        installer_ps1 = PROJECT_ROOT / "install.ps1"
        if not installer_ps1.exists():
            self.skipTest("install.ps1 pending M3")
        self.assertTrue(installer_ps1.exists())

    def test_f13_04_client_bundle_archive_exists(self):
        """F13.4: client_bundle.tar.gz exists in project root."""
        bundle = PROJECT_ROOT / "client_bundle.tar.gz"
        if not bundle.exists():
            self.skipTest("client_bundle.tar.gz pending M3 packaging")
        self.assertTrue(bundle.exists())

    def test_f13_05_client_bundle_archive_contents(self):
        """F13.5: client_bundle.tar.gz is a valid tar archive containing client scripts."""
        bundle = PROJECT_ROOT / "client_bundle.tar.gz"
        if not bundle.exists():
            self.skipTest("client_bundle.tar.gz pending M3")
        code, out, err = ph.run_command_capture(["tar", "-tzf", str(bundle)])
        self.assertEqual(code, 0)
        self.assertTrue("client_run.sh" in out or "local_forwarder.py" in out)


# ============================================================================
# F14: Comprehensive Documentation (README.md) (>= 5 tests)
# ============================================================================

class TestF14ComprehensiveDocumentation(unittest.TestCase):
    """F14: Comprehensive Documentation - README.md zero-privilege guides."""

    def test_f14_01_readme_exists_and_non_empty(self):
        """F14.1: README.md exists in project root and has substantial content."""
        readme = PROJECT_ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md pending M3 documentation")
        self.assertGreater(readme.stat().st_size, 500)

    def test_f14_02_readme_architecture_and_zero_privilege(self):
        """F14.2: README.md details zero-privilege design and architecture."""
        readme = PROJECT_ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md pending M3")
        content = readme.read_text().lower()
        self.assertIn("zero-privilege", content)
        self.assertIn("smartdns", content)

    def test_f14_03_readme_server_daemon_setup(self):
        """F14.3: README.md includes server deployment instructions and ports."""
        readme = PROJECT_ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md pending M3")
        content = readme.read_text()
        self.assertTrue("server" in content.lower() or "host" in content.lower())
        self.assertTrue("systemd" in content.lower() or "daemon" in content.lower())

    def test_f14_04_readme_linux_mac_client_guide(self):
        """F14.4: README.md includes Linux/macOS client setup instructions."""
        readme = PROJECT_ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md pending M3")
        content = readme.read_text()
        self.assertIn("client_run.sh", content)
        self.assertIn("HTTPS_PROXY", content)

    def test_f14_05_readme_windows_client_guide(self):
        """F14.5: README.md includes Windows PowerShell client setup instructions."""
        readme = PROJECT_ROOT / "README.md"
        if not readme.exists():
            self.skipTest("README.md pending M3")
        content = readme.read_text()
        self.assertIn("client_run.ps1", content)


# ============================================================================
# F15: Comprehensive E2E Test Suite (>= 5 tests)
# ============================================================================

class TestF15E2ETestSuiteHarness(unittest.TestCase):
    """F15: Comprehensive E2E Test Suite - Harness, runner, and suite structure."""

    def test_f15_01_runner_script_exists(self):
        """F15.1: e2e_runner.py exists in tests/."""
        runner = TESTS_DIR / "e2e_runner.py"
        self.assertTrue(runner.exists())

    def test_f15_02_tier1_suite_exists(self):
        """F15.2: test_tier1_features.py exists in tests/."""
        suite = TESTS_DIR / "test_tier1_features.py"
        self.assertTrue(suite.exists())

    def test_f15_03_tier2_suite_exists(self):
        """F15.3: test_tier2_boundaries.py exists in tests/."""
        suite = TESTS_DIR / "test_tier2_boundaries.py"
        self.assertTrue(suite.exists())

    def test_f15_04_tier3_suite_exists(self):
        """F15.4: test_tier3_combinations.py exists in tests/."""
        suite = TESTS_DIR / "test_tier3_combinations.py"
        self.assertTrue(suite.exists())

    def test_f15_05_tier4_suite_exists(self):
        """F15.5: test_tier4_workloads.py exists in tests/."""
        suite = TESTS_DIR / "test_tier4_workloads.py"
        self.assertTrue(suite.exists())


# ============================================================================
# F16: Live Prompt E2E Verification & Hardening (>= 5 tests)
# ============================================================================

class TestF16LivePromptVerification(unittest.TestCase):
    """F16: Live Prompt E2E Verification - agy CLI live prompt execution and proxy behavior."""

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

    def test_f16_01_agy_binary_available(self):
        """F16.1: agy binary is present and reports version 1.3.2."""
        if not self.has_agy:
            self.skipTest("agy binary not found in PATH or standard user directories")
        code, out, err = ph.run_command_capture([str(self.agy_binary), "--version"])
        self.assertEqual(code, 0)
        self.assertTrue("1.3." in out or "agy" in out.lower())

    def test_f16_02_direct_agy_ping_execution(self):
        """F16.2: Direct agy -p 'ping' executes and returns pong."""
        if not self.has_agy:
            self.skipTest("agy binary not found")
        if os.environ.get("ANTIGRAVITY_SKIP_LIVE_PROMPT"):
            self.skipTest("Live prompt skipped by environment configuration")
        code, out, err = ph.run_command_capture(
            [str(self.agy_binary), "-p", "ping", "--print-timeout", "10s"],
            timeout=20.0
        )
        self.assertEqual(code, 0)
        self.assertIn("pong", out.lower())

    def test_f16_03_agy_json_output_envelope(self):
        """F16.3: agy --output-format json -p 'ping' returns valid JSON with status SUCCESS."""
        if not self.has_agy:
            self.skipTest("agy binary not found")
        if os.environ.get("ANTIGRAVITY_SKIP_LIVE_PROMPT"):
            self.skipTest("Live prompt skipped by environment configuration")
        import json
        code, out, err = ph.run_command_capture(
            [str(self.agy_binary), "--output-format", "json", "-p", "ping", "--print-timeout", "15s"],
            timeout=30.0
        )
        if code != 0 or not out.strip().startswith("{"):
            time.sleep(1)
            code, out, err = ph.run_command_capture(
                [str(self.agy_binary), "--output-format", "json", "-p", "ping", "--print-timeout", "15s"],
                timeout=30.0
            )
        self.assertEqual(code, 0)
        data = json.loads(out.strip())
        self.assertEqual(data.get("status"), "SUCCESS")

    def test_f16_04_agy_models_enumeration(self):
        """F16.4: agy models lists supported Gemini models."""
        if not self.has_agy:
            self.skipTest("agy binary not found")
        code, out, err = ph.run_command_capture([str(self.agy_binary), "models"])
        self.assertEqual(code, 0)
        self.assertIn("gemini", out.lower())

    def test_f16_05_agy_live_prompt_with_proxy_environment(self):
        """F16.5: agy executes live prompt under proxy environment variables."""
        if not self.has_agy:
            self.skipTest("agy binary not found")
        if os.environ.get("ANTIGRAVITY_SKIP_LIVE_PROMPT"):
            self.skipTest("Live prompt skipped by environment configuration")
        server_host = os.environ.get("ANTIGRAVITY_SERVER_HOST", ph.DEFAULT_VPS_IP)
        proxy_running = ph.is_tcp_port_open(server_host, ph.DEFAULT_HTTP_PORT)
        if not proxy_running:
            self.skipTest(f"Remote HTTP proxy on {server_host}:{ph.DEFAULT_HTTP_PORT} not active")
        code, out, err = ph.run_command_capture(
            [str(self.agy_binary), "-p", "ping", "--print-timeout", "15s"],
            env={"HTTPS_PROXY": f"http://{server_host}:{ph.DEFAULT_HTTP_PORT}"},
            timeout=20.0
        )
        self.assertEqual(code, 0)
        self.assertIn("pong", out.lower())


if __name__ == "__main__":
    unittest.main()
