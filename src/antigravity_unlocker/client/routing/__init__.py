"""
routing - Client selective routing engine and loopback proxy package.
Feature F9 (Zero-Admin Selective Routing Engine).
"""

from __future__ import annotations

from antigravity_unlocker.client.routing.rules import (
    EXACT_INTERCEPT_DOMAINS,
    INTERCEPT_SUFFIXES,
    is_intercepted_domain,
    is_ip_literal,
)
from antigravity_unlocker.client.routing.forwarder import (
    DEFAULT_BUFFER_SIZE,
    DEFAULT_HTTP_PORT,
    DEFAULT_SERVER_HOST,
    DEFAULT_SNI_PORT,
    DEFAULT_SOCKS_PORT,
    LocalSelectiveForwarder,
    bidirectional_relay,
    find_available_port,
    main,
    parse_args,
)

__all__ = [
    "EXACT_INTERCEPT_DOMAINS",
    "INTERCEPT_SUFFIXES",
    "is_intercepted_domain",
    "is_ip_literal",
    "DEFAULT_BUFFER_SIZE",
    "DEFAULT_HTTP_PORT",
    "DEFAULT_SERVER_HOST",
    "DEFAULT_SNI_PORT",
    "DEFAULT_SOCKS_PORT",
    "LocalSelectiveForwarder",
    "bidirectional_relay",
    "find_available_port",
    "main",
    "parse_args",
]
