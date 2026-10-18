"""
config.py - Central strongly-typed configuration for Antigravity Unlocker.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple


@dataclass(frozen=True)
class DnsConfig:
    listen_hosts: Tuple[str, ...] = ("0.0.0.0", "127.0.0.1")
    port: int = 53
    ttl: int = 60
    upstream_resolvers: Tuple[str, ...] = ("8.8.8.8", "8.8.4.4", "1.1.1.1")
    upstream_timeout: float = 2.0


@dataclass(frozen=True)
class SniConfig:
    listen_host: str = "0.0.0.0"
    primary_port: int = 10443
    fallback_port: int = 8443
    upstream_target_port: int = 443
    connect_timeout: float = 3.0
    handshake_timeout: float = 5.0
    buffer_size: int = 65536


@dataclass(frozen=True)
class ProxyInboundConfig:
    socks5_host: str = "0.0.0.0"
    socks5_port: int = 48328
    http_host: str = "0.0.0.0"
    http_port: int = 48329
    auth_token: Optional[str] = None
    timeout: float = 10.0


from antigravity_unlocker.common.discovery import get_server_public_ip, get_server_listen_hosts


@dataclass(frozen=True)
class ServerConfig:
    vps_ip: str = field(default_factory=get_server_public_ip)
    dns: DnsConfig = field(default_factory=DnsConfig)
    sni: SniConfig = field(default_factory=SniConfig)
    proxy: ProxyInboundConfig = field(default_factory=ProxyInboundConfig)
    log_level: str = "INFO"


# Global Defaults & Environment Overrides
VPS_PUBLIC_IP: str = get_server_public_ip()
DNS_LISTEN_HOSTS: Tuple[str, ...] = ("0.0.0.0", "127.0.0.1")
DNS_PORT: int = int(os.getenv("UNLOCKER_DNS_PORT", "53"))
DNS_TTL: int = int(os.getenv("UNLOCKER_DNS_TTL", "60"))

SNI_LISTEN_HOST: str = os.getenv("UNLOCKER_SNI_IP", "0.0.0.0")
SNI_PRIMARY_PORT: int = int(os.getenv("UNLOCKER_SNI_PORT", "10443"))
SNI_FALLBACK_PORT: int = int(os.getenv("UNLOCKER_SNI_FALLBACK_PORT", "8443"))
UPSTREAM_TARGET_PORT: int = 443

SOCKS5_HOST: str = os.getenv("UNLOCKER_SOCKS5_IP", "0.0.0.0")
SOCKS5_PORT: int = int(os.getenv("UNLOCKER_SOCKS5_PORT", "48328"))

HTTP_CONNECT_HOST: str = os.getenv("UNLOCKER_HTTP_IP", "0.0.0.0")
HTTP_CONNECT_PORT: int = int(os.getenv("UNLOCKER_HTTP_PORT", "48329"))

AUTH_TOKEN: Optional[str] = os.getenv("UNLOCKER_AUTH_TOKEN", None)
LOG_LEVEL: str = os.getenv("UNLOCKER_LOG_LEVEL", "INFO")

UPSTREAM_RESOLVERS: Tuple[str, ...] = ("8.8.8.8", "8.8.4.4", "1.1.1.1")
UPSTREAM_TIMEOUT: float = 2.0

GOOGLE_EDGE_IPS: List[str] = [
    "172.217.116.4",
    "172.217.112.4",
    "172.217.113.4",
    "172.217.114.4",
    "172.217.115.4",
    "172.217.117.4",
    "172.217.118.4",
    "172.217.119.4",
    "142.250.154.100",
    "142.251.127.95",
]

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

EXACT_INTERCEPT_DOMAINS: Set[str] = {
    "ai.studio",
    "antigravity-unleash.goog",
    "gemini.google",
    "notebooklm.google",
}

ALLOWED_DOMAIN_SUFFIXES: List[str] = list(INTERCEPT_SUFFIXES)
DEFAULT_ALLOWED_DOMAINS: List[str] = [
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "generativelanguage.googleapis.com",
    "antigravity-unleash.goog",
    "ai.studio",
    "aistudio.google.com",
    "googleapis.com",
    "google.com",
    "gstatic.com",
    "googleusercontent.com",
    "goog",
    "google",
    "deepmind.com",
    "deepmind.google",
    "gvt1.com",
    "ggpht.com",
]
DEFAULT_EDGE_IPS: List[str] = list(GOOGLE_EDGE_IPS)


def is_intercepted_domain(
    domain: str,
    allowed_suffixes: Tuple[str, ...] = INTERCEPT_SUFFIXES,
    exact_domains: Set[str] = EXACT_INTERCEPT_DOMAINS,
) -> bool:
    """Checks if a domain name matches Google AI intercept rules."""
    if not domain:
        return False
    norm = domain.lower().strip().rstrip(".")
    if norm in exact_domains:
        return True
    for suffix in allowed_suffixes:
        if norm == suffix or norm.endswith("." + suffix):
            return True
    return False


def is_allowed_sni(
    sni: Optional[str],
    allowed_domains: Optional[List[str]] = None,
) -> bool:
    """Checks if a TLS SNI header should be forwarded to Google Edge."""
    if not sni:
        return False
    targets = allowed_domains or DEFAULT_ALLOWED_DOMAINS
    norm_sni = sni.lower().strip().rstrip(".")
    for allowed in targets:
        norm_allowed = allowed.lower().strip().lstrip(".")
        if norm_sni == norm_allowed or norm_sni.endswith("." + norm_allowed):
            return True
    return False
