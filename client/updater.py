#!/usr/bin/env python3
"""
updater.py - Zero-Privilege Auto-Updater & Boot Synchronizer for Antigravity Bypass (Facade)
Checks for updates against Frankfurt VPS and applies atomic updates in user space.
Configures boot/login startup checks on Linux, WSL, macOS, and Windows.
Pure Python standard library (zero external dependencies).
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

from antigravity_unlocker.client.updater import (
    apply_update,
    cleanup_legacy_autostart_hooks,
    fetch_remote_version_info,
    get_install_dir,
    get_local_version_info,
    is_engine_running,
    restart_local_engine,
    setup_boot_autostart,
)
from antigravity_unlocker.client.updater.engine import (
    CHECK_TIMEOUT,
    DEFAULT_SERVER,
)

VERSION_ENDPOINT = f"http://{DEFAULT_SERVER}/version.json"


def run_updater(quiet: bool = False, force: bool = False, check_only: bool = False, server: str = DEFAULT_SERVER) -> int:
    install_dir = get_install_dir()
    local_info = get_local_version_info(install_dir)
    local_build = local_info.get("build", 0)

    if not quiet:
        print(f"[*] Checking for updates against {server}...")
        print(f"[*] Local Version: {local_info.get('version', '1.0.0')} (Build {local_build})")

    remote_info = fetch_remote_version_info(server)
    if not remote_info:
        if not quiet:
            print("[!] Unable to reach update server (offline or filtered). Skipping update check.")
        return 0

    remote_build = remote_info.get("build", 0)
    remote_version = remote_info.get("version", "1.0.0")

    if not quiet:
        print(f"[*] Remote Version: {remote_version} (Build {remote_build})")

    if remote_build > local_build or force:
        if check_only:
            if not quiet:
                print(f"[+] Update Available: Build {remote_build} > Build {local_build}")
            return 10

        if not quiet:
            print(f"[+] New update detected! Upgrading to Build {remote_build}...")
        success = apply_update(remote_info, install_dir, force=force)
        if success:
            if not quiet:
                print(f"[+] Successfully updated to {remote_version} (Build {remote_build})!")
            return 0
        else:
            if not quiet:
                print("[X] Update failed to apply.")
            return 1
    else:
        if not quiet:
            print("[+] System is up-to-date. No action needed.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="AGY Zero-Privilege Boot Auto-Updater")
    parser.add_argument("--quiet", "-q", action="store_true", help="Silent execution for boot/background jobs")
    parser.add_argument("--force", "-f", action="store_true", help="Force re-download of latest release")
    parser.add_argument("--check", "-c", action="store_true", help="Check only, do not download")
    parser.add_argument("--server", "-s", default=DEFAULT_SERVER, help="Update server IP/hostname")
    parser.add_argument("--setup-boot", action="store_true", help="Install boot/login autostart hooks")
    parser.add_argument("--cleanup", action="store_true", help="Scrub legacy shell background hooks")
    args = parser.parse_args()

    log_level = logging.ERROR if args.quiet else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s [%(levelname)s] %(message)s")

    if args.cleanup:
        cleaned = cleanup_legacy_autostart_hooks()
        if not args.quiet:
            print(f"[+] Cleaned {len(cleaned)} legacy shell hooks.")
        return 0

    if args.setup_boot:
        actions = setup_boot_autostart(get_install_dir())
        if not args.quiet:
            print("[+] Boot autostart registered:")
            for a in actions:
                print(f"    - {a}")
        return 0

    return run_updater(quiet=args.quiet, force=args.force, check_only=args.check, server=args.server)


if __name__ == "__main__":
    sys.exit(main())
