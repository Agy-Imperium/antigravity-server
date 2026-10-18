"""
exceptions.py - Unified domain exception hierarchy for Antigravity Unlocker System.
"""

from __future__ import annotations


class UnlockerError(Exception):
    """Base exception for all Antigravity Unlocker operations."""
    pass


class ConfigurationError(UnlockerError):
    """Raised when configuration validation fails."""
    pass


class ProtocolError(UnlockerError):
    """Raised when parsing or encoding wire protocols fails."""
    pass


class DNSProtocolError(ProtocolError):
    """Raised when DNS wire format decoding or synthesis fails."""
    pass


class TLSProtocolError(ProtocolError):
    """Raised when TLS ClientHello or SNI parsing fails."""
    pass


class ProxyProtocolError(ProtocolError):
    """Raised when SOCKS5 or HTTP CONNECT wire frames are malformed."""
    pass


class PatchError(UnlockerError):
    """Raised when patching binary or configuration fails."""
    pass


class ProcessError(UnlockerError):
    """Raised when terminating or discovering target processes fails."""
    pass


class RoutingError(UnlockerError):
    """Raised when selective routing or loopback forwarding encounters an error."""
    pass
