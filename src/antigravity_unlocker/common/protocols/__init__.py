"""
protocols - Wire format protocol codecs for DNS, TLS SNI, SOCKS5, and HTTP CONNECT.
"""

from antigravity_unlocker.common.protocols.dns import (
    DNSPacket,
    DNSQuestion,
    DNSRecord,
    build_dns_a_response,
    build_dns_query,
    build_nodata_response,
    decode_dns_name,
    encode_dns_name,
    parse_dns_query,
)
from antigravity_unlocker.common.protocols.http_connect import (
    build_http_connect_response,
    parse_basic_auth,
    parse_http_connect_request,
)
from antigravity_unlocker.common.protocols.socks5 import (
    build_socks5_reply,
    parse_socks5_auth,
    parse_socks5_greeting,
    parse_socks5_request,
)
from antigravity_unlocker.common.protocols.tls import (
    build_tls_client_hello,
    parse_tls_sni,
)

__all__ = [
    "DNSPacket",
    "DNSQuestion",
    "DNSRecord",
    "build_dns_a_response",
    "build_dns_query",
    "build_nodata_response",
    "decode_dns_name",
    "encode_dns_name",
    "parse_dns_query",
    "build_tls_client_hello",
    "parse_tls_sni",
    "build_socks5_reply",
    "parse_socks5_auth",
    "parse_socks5_greeting",
    "parse_socks5_request",
    "build_http_connect_response",
    "parse_basic_auth",
    "parse_http_connect_request",
]
