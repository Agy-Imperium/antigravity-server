#!/usr/bin/env python3
"""
local_forwarder.py - Zero-Privilege Selective Routing Engine & Local Proxy (Facade)
Part of the Antigravity & agy-cli Zero-Privilege Bypass System.
Implements Feature F9 (Zero-Admin Selective Routing Engine).
Delegates to modular antigravity_unlocker.client.routing package.
Pure Python Standard Library (zero external dependencies).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional, Set, Tuple

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

from antigravity_unlocker.client.routing import (
    DEFAULT_BUFFER_SIZE,
    DEFAULT_HTTP_PORT,
    DEFAULT_SERVER_HOST,
    DEFAULT_SNI_PORT,
    DEFAULT_SOCKS_PORT,
    EXACT_INTERCEPT_DOMAINS,
    INTERCEPT_SUFFIXES,
    LocalSelectiveForwarder,
    bidirectional_relay,
    find_available_port,
    is_intercepted_domain as _core_is_intercepted_domain,
    is_ip_literal,
    main,
    parse_args,
)

# Intercepted Google AI domains routed via remote VPS tunnel
GOOGLE_AI_INTERCEPTION_DOMAINS = (
    "googleapis.com",
    "cloudcode-pa.googleapis.com",
    "daily-cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "aicode.googleapis.com",
    "oauth2.googleapis.com",
    "antigravity-unleash.goog",
    "ai.studio",
)

from antigravity_unlocker.common.discovery import get_client_target_server

# Default VPS server host
DEFAULT_VPS_HOST = get_client_target_server()


def is_intercepted_domain(
    target: str,
    suffixes: Tuple[str, ...] = INTERCEPT_SUFFIXES,
    exact_domains: Set[str] = EXACT_INTERCEPT_DOMAINS,
) -> bool:
    """
    Evaluates whether target host should be tunneled via unlocker server or routed direct.
    Handles case-insensitivity with .lower() and trailing-dot FQDN with .rstrip(".").
    """
    if not target:
        return False
    d = target.lower().strip().rstrip(".")
    if is_ip_literal(d):
        return False
    if d in exact_domains:
        return True
    for s in suffixes:
        norm_s = s.lower().strip().lstrip(".")
        if d == norm_s or d.endswith("." + norm_s):
            return True
    return False


if __name__ == "__main__":
    sys.exit(main())
