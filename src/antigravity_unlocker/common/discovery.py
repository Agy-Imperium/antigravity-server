"""
discovery.py - Dynamic Network and Public IP Auto-Discovery for Universal Server.
Enables antigravity-unlocker-server to deploy on ANY VPS (Hetzner, AWS, DO, Oracle, KVM)
without any hardcoded IP addresses. Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("discovery")

_CACHED_PUBLIC_IP: Optional[str] = None


def is_public_ipv4(ip_str: str) -> bool:
    """Checks whether the given IP string is a valid, globally routable public IPv4 address."""
    if not ip_str:
        return False
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return ip.version == 4 and not (
            ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
        )
    except Exception:
        return False


def get_server_public_ip(cached: bool = True) -> str:
    """
    Dynamically discovers the public IP of the host server.
    Order of precedence:
      1. Environment variables: UNLOCKER_SERVER_HOST, ANTIGRAVITY_SERVER_HOST, SERVER_IP
      2. Configuration file: /etc/antigravity/server_ip.txt or local server_ip.txt
      3. Outbound kernel route interface resolution (for public-facing VPS interfaces)
      4. Standard external provider query (for cloud VPS behind 1:1 NAT like AWS EC2, GCP, Oracle)
      5. Safe fallback: 127.0.0.1
    """
    global _CACHED_PUBLIC_IP
    if cached and _CACHED_PUBLIC_IP:
        return _CACHED_PUBLIC_IP

    # 1. Environment variable override
    for env_var in ["UNLOCKER_SERVER_HOST", "ANTIGRAVITY_SERVER_HOST", "SERVER_IP", "VPS_PUBLIC_IP"]:
        val = os.getenv(env_var, "").strip()
        if val:
            _CACHED_PUBLIC_IP = val
            return val

    # 2. Server configuration files
    for conf_candidate in [
        Path("/etc/antigravity/server_ip.txt"),
        Path("/etc/antigravity/server.conf"),
        Path(__file__).resolve().parent.parent.parent.parent / "server_ip.txt",
    ]:
        if conf_candidate.exists():
            try:
                txt = conf_candidate.read_text(encoding="utf-8").strip()
                # Parse plain IP or KEY=VALUE line
                for line in txt.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        if k.strip().upper() in ("SERVER_IP", "HOST", "IP", "PUBLIC_IP"):
                            val = v.strip().strip('"').strip("'")
                            if val:
                                _CACHED_PUBLIC_IP = val
                                return val
                    elif line and not line.startswith("["):
                        _CACHED_PUBLIC_IP = line
                        return line
            except Exception:
                pass

    # 3. Kernel route interface resolution (works instantly on bare-metal and standard VPS)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 80))
        local_ip = s.getsockname()[0]
        s.close()
        if is_public_ipv4(local_ip):
            _CACHED_PUBLIC_IP = local_ip
            return local_ip
    except Exception:
        pass

    # 4. External NAT discovery providers (for cloud instances behind NAT)
    providers = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ]
    for prov in providers:
        try:
            req = urllib.request.Request(prov, headers={"User-Agent": "curl/7.88.1"})
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    ip_str = resp.read().decode("utf-8").strip()
                    if is_public_ipv4(ip_str):
                        _CACHED_PUBLIC_IP = ip_str
                        return ip_str
        except Exception:
            continue

    _CACHED_PUBLIC_IP = "127.0.0.1"
    return _CACHED_PUBLIC_IP


def get_server_listen_hosts() -> Tuple[str, ...]:
    """Returns bind hosts for server listening sockets."""
    pub_ip = get_server_public_ip()
    if pub_ip and pub_ip != "127.0.0.1":
        return ("0.0.0.0", "127.0.0.1", pub_ip)
    return ("0.0.0.0", "127.0.0.1")


def get_client_target_server() -> str:
    """
    Determines target unlocker server host on client machines:
      1. Environment variable: ANTIGRAVITY_SERVER_HOST or UNLOCKER_SERVER_HOST
      2. Client install config: ~/.antigravity-bypass/server_host.txt or config.json
      3. Dynamic host discovery fallback
    """
    env_h = os.getenv("ANTIGRAVITY_SERVER_HOST", "").strip() or os.getenv("UNLOCKER_SERVER_HOST", "").strip()
    if env_h:
        return env_h

    # Check local client installation directory
    for cand in [
        Path.home() / ".antigravity-bypass" / "server_host.txt",
        Path.home() / ".antigravity-bypass" / "config.json",
        Path(os.environ.get("USERPROFILE", "")) / ".antigravity-bypass" / "server_host.txt" if os.environ.get("USERPROFILE") else None,
        Path(os.environ.get("USERPROFILE", "")) / ".antigravity-bypass" / "config.json" if os.environ.get("USERPROFILE") else None,
    ]:
        if cand and cand.exists():
            try:
                txt = cand.read_text(encoding="utf-8").strip()
                if txt.startswith("{"):
                    import json
                    d = json.loads(txt)
                    if "server_host" in d and d["server_host"]:
                        return str(d["server_host"]).strip()
                elif txt:
                    return txt.splitlines()[0].strip()
            except Exception:
                pass

    return get_server_public_ip()

