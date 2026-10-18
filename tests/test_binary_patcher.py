#!/usr/bin/env python3
"""
test_binary_patcher.py - Unit Tests for Native Binary Patcher & Direct Proxy Logic
"""

import os
import tempfile
import unittest
from pathlib import Path

# Add project root and src to path
import sys
_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_root / "src"))
sys.path.insert(0, str(_root / "client"))

from antigravity_unlocker.client.patchers.binary import (
    FIELD_FROM,
    FIELD_TO,
    PROXY_FROM,
    PROXY_TO,
    patch_cli_binary,
    unpatch_cli_binary,
    inspect_binary_state,
)
from antigravity_unlocker.client.patchers.env import clean_stale_local_proxies
from antigravity_unlocker.common.system import is_running_on_vps


class TestBinaryPatcher(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_byte_exact_length(self):
        self.assertEqual(len(FIELD_FROM), len(FIELD_TO), "ineligible and inexigible must be identical byte length")
        self.assertEqual(len(PROXY_FROM), len(PROXY_TO), "https_proxy and AG_LS_PROXY must be identical byte length")

    def test_patch_and_unpatch_cycle(self):
        dummy_bin = self.dir_path / "mock_agy"
        original_bytes = (
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"prefix_ineligible_middle_https_proxy_suffix_ineligible_end"
        )
        dummy_bin.write_bytes(original_bytes)
        dummy_bin.chmod(0o755)

        # 1. Inspect before patch
        st1 = inspect_binary_state(dummy_bin)
        self.assertFalse(st1["is_patched"])
        self.assertEqual(st1["ineligible_count"], 2)
        self.assertEqual(st1["https_proxy_count"], 1)

        # 2. Apply patch
        ok, count, msg = patch_cli_binary(dummy_bin)
        self.assertTrue(ok)
        self.assertEqual(count, 2)

        st2 = inspect_binary_state(dummy_bin)
        self.assertTrue(st2["is_patched"])
        self.assertEqual(st2["ineligible_count"], 0)
        self.assertEqual(st2["inexigible_count"], 2)
        self.assertEqual(st2["https_proxy_count"], 0)
        self.assertEqual(st2["ag_ls_proxy_count"], 1)
        self.assertEqual(len(dummy_bin.read_bytes()), len(original_bytes))

        # 3. Revert patch
        ok_rev, count_rev, msg_rev = unpatch_cli_binary(dummy_bin)
        self.assertTrue(ok_rev)

        st3 = inspect_binary_state(dummy_bin)
        self.assertFalse(st3["is_patched"])
        self.assertEqual(dummy_bin.read_bytes(), original_bytes, "Reverted bytes must be 100% identical to original")

    def test_vps_detection(self):
        # On Frankfurt VPS host, this must return True
        self.assertTrue(is_running_on_vps())


if __name__ == "__main__":
    unittest.main()
