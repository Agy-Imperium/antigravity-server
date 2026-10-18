#!/usr/bin/env python3
"""
agy_ui.py - Zero-Privilege Brutalist Console Manager for Antigravity & agy CLI (Facade)
Operates 100% in unprivileged user space.
Interactive arrow-key navigation, stark red/white/gray aesthetic, zero dependencies.
Delegates to modular antigravity_unlocker.client.ui architecture.
"""

from __future__ import annotations

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

from antigravity_unlocker.client.ui import (
    BOX_WIDTH,
    Color,
    build_frame,
    check_binary_patch_status,
    check_cli_hook_status,
    cleanup_terminal,
    get_menu_items,
    init_windows_vt,
    install_cli_hook,
    main,
    pad_box,
    probe_tcp_port,
    read_key,
    run_integrity_test,
    supports_color,
    sync_shell_profiles,
    uninstall_cli_hook,
    visible_len,
)
from antigravity_unlocker.client.ui.app import (
    DEFAULT_SERVER,
    UPSTREAM_HTTP,
    UPSTREAM_SOCKS,
    WRAPPER_SIGNATURE,
    get_relay_status,
    get_version_data,
)

if __name__ == "__main__":
    main()
