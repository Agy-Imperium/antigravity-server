"""
server - Server-side components for Antigravity Unlocker.
"""

from antigravity_unlocker.server.base import BaseServerService, ServiceStatus
from antigravity_unlocker.server.daemon import UnlockerDaemon, parse_cli_args
from antigravity_unlocker.server.dns_service import (
    DNSDatagramProtocol,
    DNSRouter,
    DNSServer,
    DnsEngine,
)
from antigravity_unlocker.server.proxy_service import (
    ProxyInbound,
    ProxyInboundConfig,
    ProxyInboundServer,
    bidirectional_relay,
    parse_http_connect_request,
    parse_socks5_auth,
    parse_socks5_greeting,
    parse_socks5_request,
    verify_token,
)
from antigravity_unlocker.server.sni_service import (
    GoogleEdgeResolver,
    SNIProxyServer,
    SniProxy,
    build_edge_probe,
    is_allowed_sni,
    parse_tls_sni,
)

__all__ = [
    "BaseServerService",
    "ServiceStatus",
    "UnlockerDaemon",
    "parse_cli_args",
    "DNSRouter",
    "DNSServer",
    "DnsEngine",
    "DNSDatagramProtocol",
    "GoogleEdgeResolver",
    "SNIProxyServer",
    "SniProxy",
    "build_edge_probe",
    "is_allowed_sni",
    "parse_tls_sni",
    "ProxyInboundServer",
    "ProxyInbound",
    "ProxyInboundConfig",
    "verify_token",
    "parse_socks5_greeting",
    "parse_socks5_auth",
    "parse_socks5_request",
    "parse_http_connect_request",
    "bidirectional_relay",
]
