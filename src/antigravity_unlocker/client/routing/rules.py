"""
rules.py - Target Google AI domain classifier & selective interception rules.
Implements Feature F9 (Zero-Admin Selective Routing Engine).
Pure Python Standard Library (zero external dependencies).
"""

from __future__ import annotations

import ipaddress
from typing import Set, Tuple


# Intercepted suffixes for Google AI / Antigravity services
INTERCEPT_SUFFIXES: Tuple[str, ...] = (
    "googleapis.com",
    "google.com",
    "gstatic.com",
    "googleusercontent.com",
    "goog",
    "google",
    "ai.studio",
    "deepmind.com",
    "deepmind.google",
    "gvt1.com",
    "ggpht.com",
)

# Exact domains explicitly intercepted
EXACT_INTERCEPT_DOMAINS: Set[str] = {
    "ai.studio",
    "antigravity-unleash.goog",
    "gemini.google",
    "notebooklm.google",
    "aistudio.google.com",
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "aicode.googleapis.com",
    "oauth2.googleapis.com",
}


def is_ip_literal(target: str) -> bool:
    """Check if target host is a valid IPv4 or IPv6 literal."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_intercepted_domain(
    target: str,
    suffixes: Tuple[str, ...] = INTERCEPT_SUFFIXES,
    exact_domains: Set[str] = EXACT_INTERCEPT_DOMAINS,
) -> bool:
    """
    Evaluates whether target host should be tunneled via unlocker server
    or routed direct.
    Enforces IP literal bypass, case-insensitivity (.lower()), trailing-dot FQDN (.rstrip(".")),
    and strict label boundary matching.
    """
    if not target:
        return False
    d = target.lower().strip().rstrip(".")
    if not d or "/" in d or "\\" in d:
        return False

    # Strip port if host:port or [ipv6]:port format is provided
    if d.startswith("[") and "]" in d:
        d = d[1 : d.index("]")]
    elif ":" in d:
        if d.count(":") == 1:
            d = d.split(":", 1)[0]

    # Rule 1: IP literal targets (e.g. 1.1.1.1, 8.8.8.8) always route direct
    if is_ip_literal(d):
        return False

    # Rule 2: Exact whitelist matches -> tunnel
    if d in exact_domains:
        return True

    # Rule 3: Suffix matches with strict label boundary -> tunnel
    for s in suffixes:
        norm_s = s.lower().strip().lstrip(".")
        if d == norm_s or d.endswith("." + norm_s):
            return True

    # All other domains route direct
    return False
