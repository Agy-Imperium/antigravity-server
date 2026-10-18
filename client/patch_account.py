#!/usr/bin/env python3
"""
patch_account.py - Zero-Privilege Account Eligibility & Geo-Lock Patcher for Antigravity (Facade)
Operates completely in unprivileged user space. Zero elevated rights required.
Delegates to modular antigravity_unlocker.client.patchers architecture.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

# Ensure src package directory is in sys.path
for _cand in [
    Path(__file__).resolve().parent.parent / "src",
    Path(__file__).resolve().parent / "src",
    Path.home() / ".antigravity-bypass" / "src",
    Path(os.environ.get("USERPROFILE", "")) / ".antigravity-bypass" / "src" if os.environ.get("USERPROFILE") else None,
    Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Antigravity" / "src" if os.environ.get("LOCALAPPDATA") else None,
    Path(__file__).resolve().parent.parent,
    Path("/opt/antigravity-unlocker/src"),
]:
    if _cand and _cand.exists() and str(_cand) not in sys.path:
        sys.path.insert(0, str(_cand))

# Ensure stdout and stderr never throw UnicodeEncodeError on Windows CP1251 / OEM codepages
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("patch_account")

from antigravity_unlocker.client.patchers import (
    DEFAULT_CLOUDCODE_URL,
    FIELD_FROM,
    FIELD_TO,
    PROXY_FROM,
    PROXY_TO,
    apply_account_unlock,
    clean_stale_local_proxies,
    configure_direct_proxy,
    inspect_binary_state,
    patch_cli_binary,
    patch_file_content,
    patch_ide_bundles,
    patch_ide_settings,
    revert_account_unlock,
    revert_ide_bundles,
    revert_ide_settings,
    unpatch_cli_binary,
)
from antigravity_unlocker.common.process import kill_antigravity_processes
from antigravity_unlocker.common.system import (
    get_antigravity_install_dirs,
    get_cli_binary_paths,
    get_ide_settings_paths,
    get_user_home,
    is_running_on_vps,
    test_direct_google_connectivity,
    test_tcp_connectivity,
from antigravity_unlocker.common.discovery import get_client_target_server

DEFAULT_REMOTE_HOST = get_client_target_server()
DEFAULT_REMOTE_PORT = 48329

# Google AI interception endpoints for Antigravity bypass
GOOGLE_AI_ENDPOINTS = (
    "googleapis.com",
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "antigravity-unleash.goog",
)
# Routing logic: routes Google AI traffic via tunnel to remote proxy, direct for local traffic.


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zero-Privilege Antigravity Account & Geo-Lock Bypass",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--revert", action="store_true", help="Revert all binary and config patches")
    parser.add_argument("--check", action="store_true", help="Inspect current patch status of binaries")
    parser.add_argument("--no-proxy", action="store_true", help="Do not configure direct proxy routing")
    parser.add_argument("--host", default=DEFAULT_REMOTE_HOST, help="Remote proxy host")
    parser.add_argument("--port", type=int, default=DEFAULT_REMOTE_PORT, help="Remote proxy HTTP port")
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()

    if args.check:
        bins = get_cli_binary_paths()
        if not bins:
            print("No agy or Language Server binaries found.")
            sys.exit(1)
        for b in bins:
            st = inspect_binary_state(b)
            status_str = "PATCHED" if st.get("is_patched") else "STOCK"
            print(f"{b.name:<32} [{status_str}] ({st.get('path', '')})")
        sys.exit(0)

    if args.revert:
        print("[*] Reverting Antigravity account patches and proxy routing...")
        ok, logs = revert_account_unlock()
        for l in logs:
            print(f"  {l}")
        print("[+] Revert complete.")
        sys.exit(0 if ok else 1)

    print("[*] Applying Antigravity account eligibility unlock and direct routing...")
    ok, logs = apply_account_unlock(
        host=args.host,
        port=args.port,
        enable_proxy=(not args.no_proxy),
    )
    for l in logs:
        print(f"  {l}")

    if ok:
        print("[+] Antigravity account unlock applied successfully.")
        sys.exit(0)
    else:
        print("[!] Unlock applied with warnings (see log above).")
        sys.exit(0)


if __name__ == "__main__":
    main()
