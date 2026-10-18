"""
env.py - Environment variable configuration and stale forwarder cleanup.
Operates completely in unprivileged user space.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import logging
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import List

from antigravity_unlocker.common.system import (
    get_user_home,
    is_running_on_vps,
    test_tcp_connectivity,
)

logger = logging.getLogger("env_patcher")


def clean_stale_local_proxies() -> List[str]:
    """
    Purges dangling local forwarder references (18443, 127.0.0.1:18443)
    and system-wide HTTP_PROXY / HTTPS_PROXY variables from user environment,
    environment.d, shell profiles, and process memory.
    """
    messages: List[str] = []
    home = get_user_home()
    sys_plat = platform.system()

    # 1. Clean environment.d file
    env_conf = home / ".config" / "environment.d" / "10-antigravity-bypass.conf"
    if env_conf.exists():
        try:
            txt = env_conf.read_text(encoding="utf-8", errors="ignore")
            cleaned_lines = [
                line for line in txt.splitlines()
                if not line.startswith(("HTTPS_PROXY=", "HTTP_PROXY=", "http_proxy=", "https_proxy="))
                and not any(p in line for p in ["18443", "127.0.0.1:18443"])
            ]
            if cleaned_lines:
                env_conf.write_text("\n".join(cleaned_lines) + "\n", encoding="utf-8")
                messages.append("Cleaned system-wide proxy exports from environment.d")
            else:
                env_conf.unlink()
                messages.append("Removed stale environment.d proxy drop-in")
        except Exception as e:
            logger.debug(f"Could not clean {env_conf}: {e}")

    # 2. Clean shell profiles
    hook_tag = "# >>> antigravity-bypass proxy hook >>>"
    hook_end = "# <<< antigravity-bypass proxy hook <<<"
    for prof in [home / ".bashrc", home / ".zshrc", home / ".profile", home / ".bash_profile"]:
        if prof.exists() and prof.is_file():
            try:
                txt = prof.read_text(encoding="utf-8", errors="ignore")
                if "18443" in txt or hook_tag in txt or "export HTTPS_PROXY=" in txt or "export HTTP_PROXY=" in txt:
                    pat = re.compile(rf"\n?{re.escape(hook_tag)}[\s\S]*?{re.escape(hook_end)}\n?")
                    cleaned = pat.sub("\n", txt)
                    cleaned_lines = [
                        line for line in cleaned.splitlines()
                        if "18443" not in line
                        and not line.startswith(("export HTTPS_PROXY=", "export HTTP_PROXY=", "export https_proxy=", "export http_proxy="))
                    ]
                    prof.write_text("\n".join(cleaned_lines) + "\n", encoding="utf-8")
                    messages.append(f"Purged system proxy exports from {prof.name}")
            except Exception as e:
                logger.debug(f"Could not clean profile {prof}: {e}")

    # 3. Clean systemd user environment
    if shutil.which("systemctl"):
        try:
            subprocess.run(
                ["systemctl", "--user", "unset-environment", "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=1.0,
            )
            messages.append("Cleared systemctl --user HTTP_PROXY/HTTPS_PROXY variables")
        except Exception:
            pass

    # 4. Clean Windows User environment variables
    if sys_plat == "Windows":
        cleaned_any = False
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE) as key:
                for v in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "AG_LS_PROXY"]:
                    try:
                        winreg.DeleteValue(key, v)
                        cleaned_any = True
                    except FileNotFoundError:
                        pass
            if cleaned_any:
                messages.append("Purged Windows User variables HTTP_PROXY, HTTPS_PROXY, and AG_LS_PROXY")
        except Exception:
            try:
                ps_cmd = (
                    "[Environment]::SetEnvironmentVariable('HTTPS_PROXY', $null, 'User'); "
                    "[Environment]::SetEnvironmentVariable('HTTP_PROXY', $null, 'User'); "
                    "[Environment]::SetEnvironmentVariable('https_proxy', $null, 'User'); "
                    "[Environment]::SetEnvironmentVariable('http_proxy', $null, 'User'); "
                    "[Environment]::SetEnvironmentVariable('AG_LS_PROXY', $null, 'User')"
                )
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1.5,
                )
                messages.append("Purged Windows User variables HTTP_PROXY, HTTPS_PROXY, and AG_LS_PROXY")
            except Exception:
                pass

    # 5. Clear current process environment
    for var in ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]:
        if var in os.environ:
            del os.environ[var]
            messages.append(f"Unset current process variable {var}")

    return messages


from antigravity_unlocker.common.discovery import get_client_target_server


def configure_direct_proxy(host: Optional[str] = None, port: int = 48329) -> List[str]:
    """
    Configures direct routing to the Unlocker Server HTTP proxy.
    Tests TCP connectivity before setting to avoid broken routes.
    """
    target_host = host or get_client_target_server()
    messages: List[str] = []
    if is_running_on_vps(target_host):
        messages.append("Running directly on Unlocker Server — proxy routing bypassed (direct connection).")
        return messages

    if not test_tcp_connectivity(target_host, port, timeout=0.4):
        messages.append(f"Warning: Remote proxy {target_host}:{port} is currently unreachable. Proxy route NOT set.")
        return messages

    proxy_url = f"http://{target_host}:{port}"
    sys_plat = platform.system()
    home = get_user_home()

    # 1. Linux/WSL: environment.d (systemd user environment)
    if sys_plat not in ("Windows", "Darwin"):
        env_d = home / ".config" / "environment.d"
        try:
            env_d.mkdir(parents=True, exist_ok=True)
            conf_file = env_d / "10-antigravity-bypass.conf"
            conf_content = (
                f"# Antigravity Language Server Direct Route (Isolated to patched Go LS)\n"
                f"AG_LS_PROXY={proxy_url}\n"
            )
            conf_file.write_text(conf_content, encoding="utf-8")
            messages.append(f"Configured isolated AG_LS_PROXY in environment.d: {proxy_url}")
        except Exception as e:
            logger.debug(f"Could not write environment.d: {e}")

        if shutil.which("systemctl"):
            try:
                subprocess.run(
                    ["systemctl", "--user", "set-environment", f"AG_LS_PROXY={proxy_url}"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1.0,
                )
                subprocess.run(
                    ["systemctl", "--user", "unset-environment", "HTTPS_PROXY", "HTTP_PROXY"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1.0,
                )
                messages.append("Updated systemctl --user (AG_LS_PROXY set, HTTPS_PROXY/HTTP_PROXY purged)")
            except Exception:
                pass

        # Shell profiles: Ensure NO system-wide HTTP_PROXY / HTTPS_PROXY is exported
        hook_tag = "# >>> antigravity-bypass proxy hook >>>"
        hook_end = "# <<< antigravity-bypass proxy hook <<<"
        for prof in [home / ".bashrc", home / ".zshrc", home / ".profile"]:
            if prof.exists() or prof.name == ".bashrc":
                try:
                    txt = prof.read_text(encoding="utf-8", errors="ignore") if prof.exists() else ""
                    if hook_tag in txt or "export HTTPS_PROXY=" in txt or "export HTTP_PROXY=" in txt:
                        pat = re.compile(rf"{re.escape(hook_tag)}[\s\S]*?{re.escape(hook_end)}")
                        cleaned = pat.sub("", txt)
                        lines = [
                            l for l in cleaned.splitlines()
                            if not l.startswith(("export HTTPS_PROXY=", "export HTTP_PROXY=", "export https_proxy=", "export http_proxy="))
                        ]
                        prof.write_text("\n".join(lines) + "\n", encoding="utf-8")
                        messages.append(f"Purged system-wide proxy exports from {prof.name}")
                except Exception as e:
                    logger.debug(f"Profile update error: {e}")

    elif sys_plat == "Windows":
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE) as key:
                for v in ["AG_LS_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]:
                    try:
                        winreg.DeleteValue(key, v)
                    except FileNotFoundError:
                        pass
            messages.append("Windows User registry kept clean (proxy routing isolated strictly to process scope)")
        except Exception:
            try:
                ps_cmd = (
                    "[Environment]::SetEnvironmentVariable('AG_LS_PROXY', $null, 'User'); "
                    "[Environment]::SetEnvironmentVariable('HTTPS_PROXY', $null, 'User'); "
                    "[Environment]::SetEnvironmentVariable('HTTP_PROXY', $null, 'User'); "
                    "[Environment]::SetEnvironmentVariable('https_proxy', $null, 'User'); "
                    "[Environment]::SetEnvironmentVariable('http_proxy', $null, 'User')"
                )
                subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_cmd],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1.5,
                )
                messages.append("Windows User registry kept clean (proxy routing isolated strictly to process scope)")
            except Exception as e:
                messages.append(f"Windows environment clean warning: {e}")

    os.environ["AG_LS_PROXY"] = proxy_url
    os.environ.pop("HTTPS_PROXY", None)
    os.environ.pop("HTTP_PROXY", None)
    os.environ.pop("https_proxy", None)
    os.environ.pop("http_proxy", None)
    return messages
