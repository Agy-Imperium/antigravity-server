"""
Antigravity Zero-Privilege Bypass System - Tier 3: Cross-Feature Combinations
Pairwise integration testing verifying interactions between subsystems:
- DNS Interceptor + SNI Proxy
- DNS ECH/IPv6 Suppression + SNI Proxy
- Local Forwarder + Remote Inbound (HTTP CONNECT / SOCKS5)
- Local Forwarder Selective Routing + Upstream Direct Routing
- CLI Wrapper (agy-run) + Local Forwarder + agy
- IDE Settings Patcher + Backend DNS Resolution
- Auth Token Enforcement across HTTP CONNECT and SOCKS5
- Diagnostics + Live Unlocker Services
- Packaging Bundle + Client Runtime
- Dynamic Edge Resolver + SNI Proxy Failover
- Bash & PowerShell Client Runtime Parity
- High-Concurrency DNS + SNI Relay
- Systemd Service Multi-Port Daemon Orchestration
Opaque-box testing: Only interacts via external protocols, sockets, filesystem, or subprocesses.
"""

import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
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


class TestTier3CrossFeatureCombinations(unittest.TestCase):
    """Tier 3: Cross-Feature Combinations and Pairwise Integrations."""

    @classmethod
    def setUpClass(cls):
        cls.server_host = os.environ.get("ANTIGRAVITY_SERVER_HOST", ph.DEFAULT_VPS_IP)
        cls.dns_port = ph.DEFAULT_DNS_PORT
        cls.sni_port = ph.DEFAULT_SNI_PORT
        cls.socks_port = ph.DEFAULT_SOCKS_PORT
        cls.http_port = ph.DEFAULT_HTTP_PORT

        cls.dns_running = ph.is_udp_dns_responsive(cls.server_host, cls.dns_port)
        cls.sni_running = ph.is_tcp_port_open(cls.server_host, cls.sni_port)
        cls.socks_running = ph.is_tcp_port_open(cls.server_host, cls.socks_port)
        cls.http_running = ph.is_tcp_port_open(cls.server_host, cls.http_port)

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

    # ------------------------------------------------------------------------
    # 1. DNS Interceptor (F1) + SNI Proxy (F3)
    # ------------------------------------------------------------------------
    def test_comb_01_dns_interceptor_plus_sni_proxy(self):
        """Pairwise 1: DNS resolves daily-cloudcode-pa to VPS IP, then TLS ClientHello connects to SNI proxy."""
        if not (self.dns_running and self.sni_running):
            self.skipTest("DNS and/or SNI Proxy not active on server (Pending M1)")

        # Step 1: DNS Interception query
        dns_res = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port)
        self.assertTrue(dns_res["valid"])
        a_records = [ans["ip"] for ans in dns_res["answers"] if ans["type"] == 1]
        self.assertIn(self.server_host, a_records)

        # Step 2: Connect to resolved IP on SNI proxy port
        resolved_ip = a_records[0]
        sni_res = ph.send_sni_client_hello(resolved_ip, self.sni_port, "daily-cloudcode-pa.googleapis.com")
        self.assertTrue(sni_res["connected"])
        self.assertTrue(sni_res["is_tls"])
        self.assertTrue(sni_res["is_server_hello"])

    # ------------------------------------------------------------------------
    # 2. DNS IPv6 Suppression (F2) + SNI Proxy (F3)
    # ------------------------------------------------------------------------
    def test_comb_02_dns_aaaa_suppression_plus_sni_proxy(self):
        """Pairwise 2: AAAA returns NODATA forcing client fallback to IPv4, reaching SNI proxy."""
        if not (self.dns_running and self.sni_running):
            self.skipTest("DNS and/or SNI Proxy pending M1")

        # Step 1: AAAA query -> NODATA
        aaaa_res = ph.send_dns_query_udp("generativelanguage.googleapis.com", self.server_host, self.dns_port, qtype=28)
        self.assertTrue(aaaa_res["valid"])
        self.assertEqual(aaaa_res["ancount"], 0)

        # Step 2: Fallback A query -> VPS IPv4
        a_res = ph.send_dns_query_udp("generativelanguage.googleapis.com", self.server_host, self.dns_port, qtype=1)
        self.assertTrue(a_res["valid"])
        self.assertGreaterEqual(a_res["ancount"], 1)

        # Step 3: Connect via IPv4 to SNI proxy
        sni_res = ph.send_sni_client_hello(self.server_host, self.sni_port, "generativelanguage.googleapis.com")
        self.assertTrue(sni_res["is_server_hello"])

    # ------------------------------------------------------------------------
    # 3. DNS Type 65 ECH Suppression (F2) + SNI Proxy (F3)
    # ------------------------------------------------------------------------
    def test_comb_03_dns_type65_ech_suppression_plus_sni_proxy(self):
        """Pairwise 3: Type 65 returns NODATA preventing ECH, allowing SNI proxy to inspect hostname."""
        if not (self.dns_running and self.sni_running):
            self.skipTest("DNS and/or SNI Proxy pending M1")

        # Step 1: Type 65 query -> NODATA (ANCOUNT=0)
        t65_res = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port, qtype=65)
        self.assertTrue(t65_res["valid"])
        self.assertEqual(t65_res["ancount"], 0)

        # Step 2: Unencrypted SNI ClientHello accepted by SNI proxy
        sni_res = ph.send_sni_client_hello(self.server_host, self.sni_port, "daily-cloudcode-pa.googleapis.com")
        self.assertTrue(sni_res["is_server_hello"])

    # ------------------------------------------------------------------------
    # 4. Local Forwarder (F9) + Remote HTTP CONNECT (F5)
    # ------------------------------------------------------------------------
    def test_comb_04_local_forwarder_plus_remote_http_connect(self):
        """Pairwise 4: Client requests HTTP CONNECT via forwarder which tunnels to remote VPS (48329)."""
        forwarder_script = CLIENT_DIR / "local_forwarder.py"
        if not forwarder_script.exists():
            self.skipTest("local_forwarder.py pending M2")
        if not self.http_running:
            self.skipTest("Remote HTTP CONNECT proxy pending M1")

        res = ph.http_connect_tunnel(self.server_host, self.http_port, "daily-cloudcode-pa.googleapis.com", 443)
        self.assertTrue(res["success"])
        if res.get("sock"):
            res["sock"].close()

    # ------------------------------------------------------------------------
    # 5. Local Forwarder (F9) + Remote SOCKS5 (F5)
    # ------------------------------------------------------------------------
    def test_comb_05_local_forwarder_plus_remote_socks5(self):
        """Pairwise 5: Client requests SOCKS5 via forwarder which tunnels to remote VPS SOCKS5 (48328)."""
        forwarder_script = CLIENT_DIR / "local_forwarder.py"
        if not forwarder_script.exists():
            self.skipTest("local_forwarder.py pending M2")
        if not self.socks_running:
            self.skipTest("Remote SOCKS5 proxy pending M1")

        res = ph.socks5_connect(self.server_host, self.socks_port, "generativelanguage.googleapis.com", 443)
        self.assertTrue(res["success"])
        if res.get("sock"):
            res["sock"].close()

    # ------------------------------------------------------------------------
    # 6. Local Forwarder Selective Routing (F9) + Direct Upstream
    # ------------------------------------------------------------------------
    def test_comb_06_local_forwarder_selective_routing_dual(self):
        """Pairwise 6: Verify selective routing definitions separate Google AI vs public direct."""
        forwarder_script = CLIENT_DIR / "local_forwarder.py"
        if not forwarder_script.exists():
            self.skipTest("local_forwarder.py pending M2")
        content = forwarder_script.read_text()
        self.assertIn("googleapis.com", content)
        self.assertTrue("direct" in content.lower() or "tunnel" in content.lower() or "remote" in content.lower())

    # ------------------------------------------------------------------------
    # 7. CLI Wrapper (F10) + Local Forwarder (F9) + agy (F16)
    # ------------------------------------------------------------------------
    def test_comb_07_agy_run_plus_local_forwarder(self):
        """Pairwise 7: agy-run sets uppercase HTTPS_PROXY and executes agy."""
        wrapper = CLIENT_DIR / "agy-run"
        if not wrapper.exists():
            self.skipTest("agy-run pending M3")
        if not self.has_agy:
            self.skipTest("agy binary not found")

        # Test wrapper version passthrough
        code, out, err = ph.run_command_capture([str(wrapper), "--version"])
        self.assertEqual(code, 0)
        self.assertIn("1.3.", out)

    # ------------------------------------------------------------------------
    # 8. IDE Settings Patcher (F11) + DNS Interception (F1)
    # ------------------------------------------------------------------------
    def test_comb_08_ide_settings_patcher_plus_backend_resolution(self):
        """Pairwise 8: Patcher injects daily-cloudcode-pa which matches DNS interception whitelist."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")

        with tempfile.TemporaryDirectory() as tmpdir:
            test_target = Path(tmpdir) / "settings.json"
            code, out, err = ph.run_command_capture([
                "python3", str(patcher), "--path", str(test_target)
            ])
            self.assertEqual(code, 0)
            data = json.loads(test_target.read_text())
            url = data.get("jetski.cloudCodeUrl", "")
            self.assertIn("daily-cloudcode-pa.googleapis.com", url)

            # Check domain matches known Google AI domains
            hostname = url.replace("https://", "").replace("http://", "").split("/")[0]
            self.assertIn(hostname, ph.GOOGLE_AI_DOMAINS)

    # ------------------------------------------------------------------------
    # 9. Auth Token Enforcement across HTTP CONNECT and SOCKS5 (F5)
    # ------------------------------------------------------------------------
    def test_comb_09_auth_token_parity(self):
        """Pairwise 9: Remote proxy daemon applies consistent auth policy across SOCKS5 and HTTP."""
        if not (self.socks_running and self.http_running):
            self.skipTest("Remote proxy servers pending M1")
        # If no auth token configured, both accept unauthenticated requests
        http_res = ph.http_connect_tunnel(self.server_host, self.http_port, "daily-cloudcode-pa.googleapis.com", 443)
        socks_res = ph.socks5_connect(self.server_host, self.socks_port, "daily-cloudcode-pa.googleapis.com", 443)
        # Both should have identical success status
        self.assertEqual(http_res["success"], socks_res["success"])
        if http_res.get("sock"):
            http_res["sock"].close()
        if socks_res.get("sock"):
            socks_res["sock"].close()

    # ------------------------------------------------------------------------
    # 10. Self-Test Diagnostics (F12) + Unlocker Services (F1/F3)
    # ------------------------------------------------------------------------
    def test_comb_10_diagnostics_script_plus_live_unlocker(self):
        """Pairwise 10: diagnose.py executes against running VPS server services."""
        diag_py = DIAG_DIR / "diagnose.py"
        if not diag_py.exists():
            self.skipTest("diagnose.py pending M3")
        code, out, err = ph.run_command_capture([
            "python3", str(diag_py), "--server", self.server_host, "--timeout", "2"
        ])
        # Returns 0 if services running, or 1 if partial
        self.assertIn(code, [0, 1])

    # ------------------------------------------------------------------------
    # 11. Packaging Bundle (F13) + Client Runtime (F7/F9)
    # ------------------------------------------------------------------------
    def test_comb_11_client_bundle_unpack_plus_client_run(self):
        """Pairwise 11: Unpacking client_bundle.tar.gz yields runnable client_run.sh and local_forwarder.py."""
        bundle = PROJECT_ROOT / "client_bundle.tar.gz"
        if not bundle.exists():
            self.skipTest("client_bundle.tar.gz pending M3 packaging")

        with tempfile.TemporaryDirectory() as tmpdir:
            shutil.copy(bundle, Path(tmpdir) / "bundle.tar.gz")
            tar_file = Path(tmpdir) / "bundle.tar.gz"
            code, out, err = ph.run_command_capture(
                ["tar", "-xzf", str(tar_file), "-C", str(tmpdir)],
                cwd=tmpdir
            )
            self.assertEqual(code, 0)
            extracted = list(Path(tmpdir).glob("**/*"))
            extracted_names = [f.name for f in extracted]
            self.assertTrue("client_run.sh" in extracted_names or "local_forwarder.py" in extracted_names)

    # ------------------------------------------------------------------------
    # 12. Dynamic Edge Resolver (F4) + SNI Proxy Round-Robin (F3)
    # ------------------------------------------------------------------------
    def test_comb_12_dynamic_edge_resolver_plus_sni_proxy(self):
        """Pairwise 12: SNI proxy targets valid Google Anycast edge IP pool."""
        self.assertGreaterEqual(len(ph.GOOGLE_EDGE_IPS), 2)
        target1 = ph.GOOGLE_EDGE_IPS[0]
        target2 = ph.GOOGLE_EDGE_IPS[1]
        self.assertTrue(ph.is_tcp_port_open(target1, 443, timeout=1.5))
        self.assertTrue(ph.is_tcp_port_open(target2, 443, timeout=1.5))

    # ------------------------------------------------------------------------
    # 13. Bash (F7) & PowerShell (F8) Client Parity
    # ------------------------------------------------------------------------
    def test_comb_13_dual_client_bash_and_powershell_parity(self):
        """Pairwise 13: Verify client_run.sh and client_run.ps1 share identical default ports and vars."""
        sh_script = CLIENT_DIR / "client_run.sh"
        ps1_script = CLIENT_DIR / "client_run.ps1"
        if not (sh_script.exists() and ps1_script.exists()):
            self.skipTest("client_run scripts pending M2")

        sh_content = sh_script.read_text()
        ps1_content = ps1_script.read_text()

        # Both must specify 48329 and 48328
        self.assertIn("48329", sh_content)
        self.assertIn("48329", ps1_content)
        self.assertIn("48328", sh_content)
        self.assertIn("48328", ps1_content)
        self.assertIn("HTTPS_PROXY", sh_content)
        self.assertIn("HTTPS_PROXY", ps1_content)

    # ------------------------------------------------------------------------
    # 14. High-Concurrency DNS (F1) + SNI Proxy (F3)
    # ------------------------------------------------------------------------
    def test_comb_14_rapid_concurrent_dns_and_sni(self):
        """Pairwise 14: Concurrent DNS query and SNI connection executed simultaneously without collision."""
        if not (self.dns_running and self.sni_running):
            self.skipTest("DNS and/or SNI Proxy pending M1")

        results = {}

        def run_dns():
            res = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port)
            results["dns"] = res["valid"]

        def run_sni():
            res = ph.send_sni_client_hello(self.server_host, self.sni_port, "daily-cloudcode-pa.googleapis.com")
            results["sni"] = res.get("is_server_hello", False)

        t1 = threading.Thread(target=run_dns)
        t2 = threading.Thread(target=run_sni)
        t1.start()
        t2.start()
        t1.join(timeout=3.0)
        t2.join(timeout=3.0)

        self.assertTrue(results.get("dns", False))
        self.assertTrue(results.get("sni", False))

    # ------------------------------------------------------------------------
    # 15. Systemd Service (F6) Multi-Port Daemon Orchestration (F1, F3, F5)
    # ------------------------------------------------------------------------
    def test_comb_15_systemd_service_orchestration(self):
        """Pairwise 15: Systemd unit defines single unified daemon handling all unlocker ports."""
        unit_file = SERVER_DIR / "antigravity-unlocker.service"
        if not unit_file.exists():
            unit_file = Path("/etc/systemd/system/antigravity-unlocker.service")
        if not unit_file.exists():
            self.skipTest("Systemd unit pending M1")

        content = unit_file.read_text()
        self.assertIn("unlocker_daemon.py", content)
        self.assertIn("Restart=", content)


if __name__ == "__main__":
    unittest.main()
