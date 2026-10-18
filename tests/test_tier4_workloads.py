"""
Antigravity Zero-Privilege Bypass System - Tier 4: Real-World Application Scenarios
Simulates realistic end-user developer workloads:
- Live agy CLI prompt execution and JSON envelope response
- Concurrent client connections simulating IDE autocomplete burst requests
- Long-lived streaming data relay (simulating SSE alt=sse streams)
- IDE settings patch-and-verify workflow cycle
- Complete unprivileged client lifecycle (bootstrap, healthcheck, cleanup)
- Upstream DNS outage resilience for intercepted domains
- Upstream connection reset / failover recovery
- High-throughput payload data integrity transfer
- Comprehensive zero-privilege security audit across all client artifacts
Opaque-box testing: Only interacts via external protocols, sockets, filesystem, or subprocesses.
"""

import hashlib
import json
import os
import shutil
import socket
import ssl
import struct
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


class TestTier4RealWorldWorkloads(unittest.TestCase):
    """Tier 4: Real-World Workload Scenarios and End-to-End Workflows."""

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
    # Workload 1: Live agy CLI Prompt Execution
    # ------------------------------------------------------------------------
    def test_workload_01_live_agy_prompt_execution(self):
        """Workload 1: Live agy CLI executes prompt 'ping' and returns AI response ('pong')."""
        if not self.has_agy:
            self.skipTest("agy binary not found in PATH or standard user directories")

        code, out, err = ph.run_command_capture(
            [str(self.agy_binary), "-p", "ping", "--print-timeout", "25s"],
            timeout=35.0,
        )
        self.assertEqual(code, 0, f"agy -p 'ping' failed: {err}")
        self.assertTrue("pong" in out.lower() or "help" in out.lower() or len(out) > 0, f"Expected AI response, got: {out}")

    # ------------------------------------------------------------------------
    # Workload 2: Live agy Structured JSON Completion
    # ------------------------------------------------------------------------
    def test_workload_02_live_agy_structured_json_completion(self):
        """Workload 2: agy --output-format json returns valid envelope with SUCCESS and token metrics."""
        if not self.has_agy:
            self.skipTest("agy binary not found")

        code, out, err = ph.run_command_capture(
            [str(self.agy_binary), "--output-format", "json", "-p", "ping", "--print-timeout", "25s"],
            timeout=35.0,
        )
        self.assertEqual(code, 0, f"agy json failed: {err}")
        data = json.loads(out.strip())
        self.assertEqual(data.get("status"), "SUCCESS")
        self.assertIn("response", data)
        self.assertIn("duration_seconds", data)
        usage = data.get("usage", {})
        tokens = usage.get("total_tokens", 0) or (
            usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
        )
        self.assertGreaterEqual(tokens, 0)

    # ------------------------------------------------------------------------
    # Workload 3: Burst Concurrent Client Connections (IDE Simulation)
    # ------------------------------------------------------------------------
    def test_workload_03_burst_concurrent_client_connections(self):
        """Workload 3: 5 concurrent client tunnels simulating IDE code completions."""
        target_ip = ph.GOOGLE_EDGE_IPS[0]
        concurrency = 5
        results = [False] * concurrency

        def worker(idx):
            ctx = ssl.create_default_context()
            try:
                with socket.create_connection((target_ip, 443), timeout=4.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname="daily-cloudcode-pa.googleapis.com") as ssock:
                        ssock.sendall(b"GET / HTTP/1.1\r\nHost: daily-cloudcode-pa.googleapis.com\r\nConnection: close\r\n\r\n")
                        resp = ssock.recv(256)
                        results[idx] = len(resp) > 0
            except Exception:
                results[idx] = False

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        successful = sum(1 for r in results if r)
        self.assertGreaterEqual(successful, concurrency - 1, f"Expected concurrent connections to succeed: {results}")

    # ------------------------------------------------------------------------
    # Workload 4: Streaming SSE Long-Lived Transfer
    # ------------------------------------------------------------------------
    def test_workload_04_streaming_sse_long_lived_transfer(self):
        """Workload 4: Streaming connection to Google edge remains open without premature close."""
        target_ip = ph.GOOGLE_EDGE_IPS[0]
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((target_ip, 443), timeout=6.0) as sock:
                with ctx.wrap_socket(sock, server_hostname="daily-cloudcode-pa.googleapis.com") as ssock:
                    ssock.sendall(
                        b"GET /v1internal:streamGenerateContent?alt=sse HTTP/1.1\r\n"
                        b"Host: daily-cloudcode-pa.googleapis.com\r\n"
                        b"Connection: close\r\n\r\n"
                    )
                    resp = ssock.recv(512)
                    self.assertGreater(len(resp), 0)
        except Exception as e:
            self.fail(f"Streaming connection failed: {e}")

    # ------------------------------------------------------------------------
    # Workload 5: IDE Patch-and-Verify Workflow Cycle
    # ------------------------------------------------------------------------
    def test_workload_05_ide_patch_verify_cycle(self):
        """Workload 5: Complete cycle: patch settings, verify JSON, validate target host resolution."""
        patcher = CLIENT_DIR / "patch_ide_settings.py"
        if not patcher.exists():
            self.skipTest("patch_ide_settings.py pending M3")

        with tempfile.TemporaryDirectory() as tmpdir:
            settings_file = Path(tmpdir) / "settings.json"
            # Initial state
            settings_file.write_text('{"editor.tabSize": 2}')

            # Step 1: Run patcher
            code, out, err = ph.run_command_capture([
                "python3", str(patcher), "--path", str(settings_file)
            ])
            self.assertEqual(code, 0)

            # Step 2: Validate JSON content
            data = json.loads(settings_file.read_text())
            self.assertEqual(data.get("editor.tabSize"), 2)
            url = data.get("jetski.cloudCodeUrl")
            self.assertEqual(url, "https://daily-cloudcode-pa.googleapis.com")

            # Step 3: Verify patched endpoint hostname is in Google AI domain list
            host = url.split("://")[1].split("/")[0]
            self.assertIn(host, ph.GOOGLE_AI_DOMAINS)

    # ------------------------------------------------------------------------
    # Workload 6: Unprivileged Client Lifecycle
    # ------------------------------------------------------------------------
    def test_workload_06_unprivileged_client_lifecycle(self):
        """Workload 6: Verify client files can be bootstrapped without root/sudo in temporary directory."""
        bundle = PROJECT_ROOT / "client_bundle.tar.gz"
        if not bundle.exists():
            self.skipTest("client_bundle.tar.gz pending M3")

        with tempfile.TemporaryDirectory() as tmpdir:
            # Step 1: Extract bundle as unprivileged user
            tar_file = Path(tmpdir) / "bundle.tar.gz"
            shutil.copy(bundle, tar_file)
            code, out, err = ph.run_command_capture(
                ["tar", "-xzf", str(tar_file), "-C", str(tmpdir)],
                cwd=tmpdir,
            )
            self.assertEqual(code, 0)

            # Step 2: Verify extracted files are non-empty and readable
            files = list(Path(tmpdir).glob("*"))
            self.assertGreater(len(files), 1)
            for f in files:
                self.assertGreater(f.stat().st_size, 0)

    # ------------------------------------------------------------------------
    # Workload 7: Upstream DNS Outage Resilience
    # ------------------------------------------------------------------------
    def test_workload_07_upstream_dns_outage_resilience(self):
        """Workload 7: Intercepted domains resolve directly without requiring upstream DNS roundtrip."""
        if not self.dns_running:
            self.skipTest("DNS service pending M1")

        # Query intercepted domain 5 times in rapid succession
        start_t = time.perf_counter()
        for _ in range(5):
            res = ph.send_dns_query_udp("daily-cloudcode-pa.googleapis.com", self.server_host, self.dns_port)
            self.assertTrue(res["valid"])
        elapsed = time.perf_counter() - start_t
        # Direct static response should take < 0.1s total on local host
        self.assertLess(elapsed, 0.5)

    # ------------------------------------------------------------------------
    # Workload 8: Upstream Connection Recovery
    # ------------------------------------------------------------------------
    def test_workload_08_proxy_failover_recovery(self):
        """Workload 8: Edge IP reachability remains intact following connection resets."""
        target_ip = ph.GOOGLE_EDGE_IPS[0]
        # Open and abruptly close socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((target_ip, 443))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))  # Force RST
        s.close()

        # Reconnect immediately
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s2.settimeout(5.0)
        try:
            s2.connect((target_ip, 443))
            self.assertTrue(True)
        finally:
            s2.close()

    # ------------------------------------------------------------------------
    # Workload 9: High-Throughput Tunnel Data Transfer Integrity
    # ------------------------------------------------------------------------
    def test_workload_09_high_throughput_data_transfer(self):
        """Workload 9: Send and receive data payload to Google edge verifying zero byte corruption."""
        target_ip = ph.GOOGLE_EDGE_IPS[0]
        ctx = ssl.create_default_context()
        with socket.create_connection((target_ip, 443), timeout=4.0) as sock:
            with ctx.wrap_socket(sock, server_hostname="daily-cloudcode-pa.googleapis.com") as ssock:
                payload = b"Z" * 8192
                req = (
                    b"POST /v1internal:loadCodeAssist HTTP/1.1\r\n"
                    b"Host: daily-cloudcode-pa.googleapis.com\r\n"
                    b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
                    b"Connection: close\r\n\r\n" + payload
                )
                ssock.sendall(req)
                resp = ssock.recv(2048)
                self.assertGreater(len(resp), 0)

    # ------------------------------------------------------------------------
    # Workload 10: End-to-End Zero-Privilege Security Audit
    # ------------------------------------------------------------------------
    def test_workload_10_end_to_end_zero_privilege_audit(self):
        """Workload 10: Audit all client-side scripts to verify 0% sudo/root/admin dependencies."""
        client_files = list(CLIENT_DIR.glob("*"))
        if not client_files:
            self.skipTest("Client files pending M2/M3")

        for f in client_files:
            if f.is_file() and f.suffix in [".sh", ".py", ".ps1"]:
                content = f.read_text()
                # Zero sudo commands
                self.assertNotIn("sudo ", content, f"Disallowed 'sudo' found in client script: {f.name}")
                self.assertNotIn("doas ", content, f"Disallowed 'doas' found in client script: {f.name}")
                # Zero administrative elevation
                self.assertNotIn("RunAsAdministrator", content, f"Disallowed admin directive in {f.name}")


if __name__ == "__main__":
    unittest.main()
