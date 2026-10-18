#!/usr/bin/env python3
"""
unlocker_daemon.py - Master Unified Server Daemon Orchestrator (Facade)
Part of the Antigravity & agy-cli Zero-Privilege Bypass System.
Implements Feature F6 (Managed Systemd Service Daemon).
Delegates directly to canonical antigravity_unlocker.server.daemon implementation.
"""

import sys
from pathlib import Path

# Ensure src package directory is in sys.path
_src_dir = Path(__file__).resolve().parent.parent / "src"
if _src_dir.exists() and str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))

from antigravity_unlocker.server.daemon import (
    UnlockerDaemon,
    main,
    parse_cli_args,
)

if __name__ == "__main__":
    main()
