"""
system.py - System environment detection, filesystem paths, and network probing.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import socket
import urllib.error
import urllib.request
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("system")


def get_user_home() -> Path:
    """Returns the user home directory."""
    return Path.home()


def is_running_on_vps(vps_ip: Optional[str] = None) -> bool:
    """Detects if the code is executing directly on the Unlocker Server/VPS."""
    try:
        # Check systemd service file or config on VPS
        if (
            Path("/etc/systemd/system/antigravity-unlocker.service").exists()
            or Path("/etc/antigravity/server.conf").exists()
            or Path("/etc/antigravity/server_ip.txt").exists()
        ):
            return True
        target_ip = vps_ip
        if not target_ip:
            from antigravity_unlocker.common.discovery import get_server_public_ip
            target_ip = get_server_public_ip()
        # Check local network interface IP
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip and ip == target_ip:
                return True
    except Exception:
        pass
    return False


def test_tcp_connectivity(host: str, port: int, timeout: float = 1.0) -> bool:
    """Tests if a remote or local TCP port is reachable."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def test_direct_google_connectivity(
    url: str = "https://daily-cloudcode-pa.googleapis.com",
    timeout: float = 1.0,
) -> bool:
    """Tests if Google Cloud Code endpoint is directly reachable without proxies."""
    try:
        req = urllib.request.Request(url, method="POST")
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=timeout) as _:
            return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


def get_ide_settings_paths() -> List[Path]:
    """Returns candidate paths for Antigravity IDE settings.json across OSes."""
    candidates: List[Path] = []
    sys_plat = platform.system()
    home = get_user_home()

    if sys_plat == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            candidates.append(Path(appdata) / "Antigravity" / "User" / "settings.json")
            candidates.append(Path(appdata) / "Antigravity IDE" / "User" / "settings.json")
        candidates.append(home / "AppData" / "Roaming" / "Antigravity" / "User" / "settings.json")
    elif sys_plat == "Darwin":
        candidates.append(home / "Library" / "Application Support" / "Antigravity" / "User" / "settings.json")
    else:
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config:
            candidates.append(Path(xdg_config) / "Antigravity" / "User" / "settings.json")
        candidates.append(home / ".config" / "Antigravity" / "User" / "settings.json")
        candidates.append(home / ".config" / "Antigravity IDE" / "User" / "settings.json")

    return [p for p in candidates if p is not None]


def get_antigravity_install_dirs() -> List[Path]:
    """Returns directory paths where Antigravity IDE installation files reside."""
    dirs: List[Path] = []
    sys_plat = platform.system()
    home = get_user_home()

    if sys_plat == "Windows":
        local_app = os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local"))
        prog_files = os.environ.get("PROGRAMFILES", "C:\\Program Files")
        prog_files_x86 = os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")
        for base in [local_app, prog_files, prog_files_x86]:
            dirs.append(Path(base) / "Programs" / "Antigravity")
            dirs.append(Path(base) / "Programs" / "Antigravity IDE")
            dirs.append(Path(base) / "Antigravity")
            dirs.append(Path(base) / "Antigravity IDE")
    elif sys_plat == "Darwin":
        dirs.append(Path("/Applications/Antigravity.app/Contents/Resources"))
        dirs.append(home / "Applications/Antigravity.app/Contents/Resources")
    else:
        dirs.append(home / ".local" / "share" / "Antigravity")
        dirs.append(home / ".local" / "share" / "Antigravity IDE")
        dirs.append(Path("/opt/Antigravity"))
        dirs.append(Path("/opt/antigravity"))
        dirs.append(Path("/usr/share/Antigravity"))
        # WSL: Check Windows host installations if /mnt/c exists
        if Path("/mnt/c/Users").exists():
            try:
                for u_dir in Path("/mnt/c/Users").iterdir():
                    if u_dir.is_dir() and not u_dir.name.startswith((".", "Public", "Default")):
                        dirs.append(u_dir / "AppData" / "Local" / "Programs" / "Antigravity")
                        dirs.append(u_dir / "AppData" / "Local" / "Programs" / "Antigravity IDE")
            except Exception:
                pass

    return [d for d in dirs if d.exists()]


def get_cli_binary_paths() -> List[Path]:
    """Returns candidate paths for agy CLI binary and language server executables."""
    home = get_user_home()
    sys_plat = platform.system()
    candidates: List[Path] = []

    # Which lookups
    for name in ["agy.real", "agy.real.exe", "agy", "agy.exe", "language_server", "language_server.exe"]:
        p = shutil.which(name)
        if p:
            candidates.append(Path(p))

    # Standard user home paths
    common_dirs = [
        home / ".local" / "bin",
        home / ".gemini" / "antigravity-cli" / "bin",
        home / ".antigravity-bypass",
        home / ".antigravity-bypass" / "bin",
        home / ".antigravity" / "bin",
        Path("/root/.local/bin"),
        Path("/usr/local/bin"),
        Path("/usr/bin"),
    ]

    for d in common_dirs:
        for name in [
            "agy.real",
            "agy.real.exe",
            "agy",
            "agy.exe",
            "language_server",
            "language_server.exe",
            "language_server_linux_x64",
            "language_server_windows_x64.exe",
        ]:
            candidates.append(d / name)

    # Windows specific paths
    if sys_plat == "Windows":
        local_app = os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local"))
        user_prof = os.environ.get("USERPROFILE", str(home))
        prog_dirs = [
            Path(local_app) / "Programs" / "Antigravity" / "bin",
            Path(local_app) / "Programs" / "Antigravity",
            Path(user_prof) / ".local" / "bin",
            Path(user_prof) / ".gemini" / "antigravity-cli" / "bin",
            Path(user_prof) / ".antigravity-bypass",
            Path(user_prof) / ".antigravity-bypass" / "bin",
        ]
        for d in prog_dirs:
            for name in [
                "agy.real.exe",
                "agy.exe",
                "language_server.exe",
                "language_server_windows_x64.exe",
            ]:
                candidates.append(d / name)

    # WSL paths
    if sys_plat != "Windows" and Path("/mnt/c/Users").exists():
        try:
            for u_dir in Path("/mnt/c/Users").iterdir():
                if u_dir.is_dir() and not u_dir.name.startswith((".", "Public", "Default")):
                    w_dirs = [
                        u_dir / "AppData" / "Local" / "Programs" / "Antigravity" / "bin",
                        u_dir / "AppData" / "Local" / "Programs" / "Antigravity",
                        u_dir / ".local" / "bin",
                        u_dir / ".gemini" / "antigravity-cli" / "bin",
                        u_dir / ".antigravity-bypass",
                    ]
                    for wd in w_dirs:
                        for name in [
                            "agy.real.exe",
                            "agy.exe",
                            "language_server.exe",
                            "language_server_windows_x64.exe",
                        ]:
                            candidates.append(wd / name)
        except Exception:
            pass

    # Search in IDE install dirs (targeted subdirs only, skip heavy recursive walks)
    for inst_dir in get_antigravity_install_dirs():
        if not inst_dir.exists():
            continue
        search_dirs = [
            inst_dir / "bin",
            inst_dir / "resources" / "app" / "bin",
            inst_dir / "resources" / "app" / "out",
            inst_dir,
        ]
        for sdir in search_dirs:
            if not sdir.exists():
                continue
            for pat in [
                "language_server*",
                "languageServer*",
                "language-server*",
                "agy*",
            ]:
                try:
                    for match in sdir.glob(pat):
                        if match.is_file() and "node_modules" not in match.parts:
                            candidates.append(match)
                except Exception:
                    pass

    seen = set()
    res: List[Path] = []
    for cand in candidates:
        try:
            if not cand.exists() or not cand.is_file():
                continue
            r = cand.resolve()
            if r in seen:
                continue

            # Skip non-executable extensions
            if r.suffix.lower() in [
                ".sh", ".bat", ".cmd", ".ps1", ".py", ".json", ".md", ".txt", ".bak", ".agy_bak",
            ]:
                # But inspect wrapper scripts for referenced target binary
                if r.suffix.lower() in [".cmd", ".bat", ".sh", ".ps1"]:
                    try:
                        content = r.read_text(encoding="utf-8", errors="ignore")
                        for match in re.finditer(
                            r'([A-Za-z0-9_./\\-]+\b(?:agy\.real(?:\.exe)?|language_server[A-Za-z0-9_.-]*))',
                            content,
                        ):
                            found_p = Path(match.group(1))
                            if not found_p.is_absolute():
                                found_p = r.parent / found_p
                            if found_p.exists() and found_p.is_file():
                                candidates.append(found_p)
                    except Exception:
                        pass
                continue

            # Skip shebang scripts and non-native binaries
            with open(r, "rb") as f:
                head = f.read(4)
                if head.startswith(b"#!"):
                    try:
                        content = r.read_text(encoding="utf-8", errors="ignore")
                        for match in re.finditer(
                            r'([A-Za-z0-9_./-]+\b(?:agy\.real|language_server[A-Za-z0-9_.-]*))',
                            content,
                        ):
                            found_p = Path(match.group(1))
                            if not found_p.is_absolute():
                                found_p = r.parent / found_p
                            if found_p.exists() and found_p.is_file():
                                candidates.append(found_p)
                    except Exception:
                        pass
                    continue
                if not (head == b"\x7fELF" or head.startswith(b"MZ") or head in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")):
                    continue

            seen.add(r)
            res.append(cand)
        except Exception:
            pass
    return res
