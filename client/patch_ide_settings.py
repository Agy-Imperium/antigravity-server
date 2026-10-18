#!/usr/bin/env python3
"""
patch_ide_settings.py - Zero-Privilege Antigravity IDE Settings Patcher (Facade)
Safely configures jetski.cloudCodeUrl in Antigravity settings.json without requiring elevated privileges.
Delegates to modular antigravity_unlocker.client.patchers.ide architecture.
"""

from __future__ import annotations

import argparse
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

from antigravity_unlocker.client.patchers.ide import (
    DEFAULT_CLOUDCODE_URL,
    patch_ide_settings,
    revert_ide_settings,
)
from antigravity_unlocker.common.system import get_ide_settings_paths


def get_default_settings_path() -> Path:
    paths = get_ide_settings_paths()
    return paths[0] if paths else Path.home() / ".config" / "Antigravity" / "User" / "settings.json"


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Zero-privilege Antigravity IDE settings patcher for jetski.cloudCodeUrl.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--path",
        type=str,
        default=None,
        help="Target settings.json file path (auto-detects based on OS if omitted)",
    )
    parser.add_argument(
        "--url",
        type=str,
        default=DEFAULT_CLOUDCODE_URL,
        help="Custom CloudCode backend URL to configure",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview changes without modifying the filesystem",
    )
    parser.add_argument(
        "--revert",
        action="store_true",
        help="Revert settings.json from existing backup file (.bak)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_arguments()
    target_path = Path(args.path) if args.path else None

    if args.revert:
        backup_path = Path(str(target_path) + ".bak") if target_path else None
        if backup_path and not backup_path.exists():
            sys.stderr.write(f"Error: Backup file {backup_path} does not exist. Cannot revert.\n")
            sys.exit(1)
        logs = revert_ide_settings(custom_path=target_path)
        for l in logs:
            print(f"[+] {l}")
        sys.exit(0)

    if args.dry_run:
        eff_path = target_path or get_default_settings_path()
        print(f"[Dry Run] Would configure jetski.cloudCodeUrl: {args.url}")
        print(f"[Dry Run] Target file: {eff_path}")
        sys.exit(0)

    try:
        eff_path = (target_path or get_default_settings_path()).resolve()
        target_parent = eff_path.parent
        ancestor = target_parent
        while not ancestor.exists() and ancestor != ancestor.parent:
            ancestor = ancestor.parent
        if ancestor == Path("/"):
            raise PermissionError(f"Target directory '{target_parent}' is in a non-writable root filesystem location.")

        logs = patch_ide_settings(cloudcode_url=args.url, custom_path=eff_path)
        if not logs:
            sys.stderr.write(f"Error: Failed to patch IDE settings at {eff_path}\n")
            sys.exit(1)
        for l in logs:
            print(f"[+] {l}")
        sys.exit(0)
    except (OSError, PermissionError) as err:
        sys.stderr.write(f"Error: Unable to modify settings file: {err}\n")
        sys.exit(1)
    except Exception as err:
        sys.stderr.write(f"Error: Unexpected failure during settings patch: {err}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
