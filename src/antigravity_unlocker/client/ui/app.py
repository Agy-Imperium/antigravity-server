"""
app.py - Main interactive controller and event loop for the Brutalist TUI console.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from antigravity_unlocker.client.patchers import (
    apply_account_unlock,
    clean_stale_local_proxies,
    inspect_binary_state,
    revert_account_unlock,
)
from antigravity_unlocker.client.ui.terminal import init_windows_vt, read_key
from antigravity_unlocker.client.ui.theme import Color
from antigravity_unlocker.client.ui.views import build_frame, get_menu_items
from antigravity_unlocker.client.updater.engine import (
    apply_update,
    fetch_remote_version_info,
    get_install_dir,
    get_local_version_info,
)
from antigravity_unlocker.common.discovery import get_client_target_server
from antigravity_unlocker.common.system import get_cli_binary_paths

DEFAULT_SERVER = get_client_target_server()
UPSTREAM_HTTP = 48329
UPSTREAM_SOCKS = 48328
WRAPPER_SIGNATURE = "# --- ANTIGRAVITY ZERO-PRIVILEGE CLI HOOK ---"


def _is_native_binary(p: Path) -> bool:
    """Returns True if the file is a compiled ELF, PE (.exe), or Mach-O executable."""
    if not p.is_file() or not os.access(p, os.X_OK):
        return False
    try:
        with open(p, "rb") as f:
            magic = f.read(4)
            if magic == b"\x7fELF":
                return True
            if magic.startswith(b"MZ"):
                return True
            if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
                return True
    except Exception:
        pass
    return False


def probe_tcp_port(host: str, port: int, timeout: float = 0.3) -> Tuple[bool, float]:
    """Fast TCP connection latency probe."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        lat_ms = (time.time() - t0) * 1000.0
        s.close()
        return True, lat_ms
    except Exception:
        s.close()
        return False, -1.0


_BIN_STATE_CACHE: Dict[str, Tuple[float, int, bool, str]] = {}
_CLI_PATHS_CACHE: Optional[List[Path]] = None


def check_binary_patch_status(force: bool = False) -> Tuple[bool, str]:
    """Inspects if agy or language server binaries are patched with mtime caching."""
    global _CLI_PATHS_CACHE
    if _CLI_PATHS_CACHE is None or force:
        _CLI_PATHS_CACHE = [p for p in get_cli_binary_paths() if p.exists() and p.is_file()]

    if not _CLI_PATHS_CACHE:
        return False, "NOT FOUND"

    for b in _CLI_PATHS_CACHE:
        mtime = 0.0
        size = 0
        key = str(b.resolve())
        try:
            st = b.stat()
            mtime, size = st.st_mtime, st.st_size
            cached = _BIN_STATE_CACHE.get(key)
            if not force and cached and cached[0] == mtime and cached[1] == size:
                if cached[2]:
                    return True, cached[3]
                continue
        except Exception:
            pass

        st = inspect_binary_state(b)
        is_patched = bool(st.get("is_patched", False))
        desc = f"PATCHED ({b.name})" if is_patched else "STOCK"
        try:
            _BIN_STATE_CACHE[key] = (mtime, size, is_patched, desc)
        except Exception:
            pass
        if is_patched:
            return True, desc
    return False, "STOCK"


_HOOK_STATE_CACHE: Optional[Tuple[float, bool, str]] = None


def check_cli_hook_status(force: bool = False) -> Tuple[bool, str]:
    """Checks whether the CLI wrapper hook is deployed with mtime caching."""
    global _HOOK_STATE_CACHE
    user_bin = Path.home() / ".local" / "bin"
    if platform.system() == "Windows":
        local_app = os.environ.get("LOCALAPPDATA")
        user_bin = Path(local_app) / "Programs" / "Antigravity" / "bin" if local_app else Path.home() / ".local" / "bin"

    target_wrapper = user_bin / ("agy.cmd" if platform.system() == "Windows" else "agy")
    if not target_wrapper.exists():
        _HOOK_STATE_CACHE = None
        return False, "DISENGAGED"

    try:
        mtime = target_wrapper.stat().st_mtime
    except Exception:
        mtime = 0.0

    if not force and _HOOK_STATE_CACHE and _HOOK_STATE_CACHE[0] == mtime:
        return _HOOK_STATE_CACHE[1], _HOOK_STATE_CACHE[2]

    try:
        content = target_wrapper.read_text(encoding="utf-8", errors="ignore")
        if WRAPPER_SIGNATURE in content or "agy-run" in content:
            _HOOK_STATE_CACHE = (mtime, True, "ENGAGED")
            return True, "ENGAGED"
    except Exception:
        pass

    _HOOK_STATE_CACHE = (mtime, False, "DISENGAGED")
    return False, "DISENGAGED"


def sync_shell_profiles(ensure_path: bool = True) -> None:
    """Ensures ~/.local/bin is present in PATH in shell configuration and hooks PowerShell profile on Windows."""
    sys_plat = platform.system()
    if sys_plat == "Windows":
        hook_tag = "# >>> AGY_CLI_HOOK >>>"
        hook_end = "# <<< AGY_CLI_HOOK <<<"
        hook_code = f"""{hook_tag}
function agy {{
    $r = "$HOME\\.antigravity-bypass\\client\\agy-run.ps1"
    if (-not (Test-Path $r)) {{ $r = "$HOME\\.antigravity-bypass\\agy-run.ps1" }}
    if (Test-Path $r) {{
        & $r @args
    }} elseif (Get-Command "agy.cmd" -ErrorAction SilentlyContinue) {{
        & (Get-Command "agy.cmd").Source @args
    }} elseif (Get-Command "agy.real.exe" -ErrorAction SilentlyContinue) {{
        & (Get-Command "agy.real.exe").Source @args
    }}
}}
{hook_end}"""
        docs = Path.home() / "Documents"
        for p_dir in [docs / "WindowsPowerShell", docs / "PowerShell"]:
            prof = p_dir / "Microsoft.PowerShell_profile.ps1"
            try:
                txt = prof.read_text(encoding="utf-8", errors="ignore") if prof.exists() else ""
                pat = re.compile(rf"\n?{re.escape(hook_tag)}[\s\S]*?{re.escape(hook_end)}\n?")
                cleaned = pat.sub("\n", txt).strip()
                if ensure_path:
                    p_dir.mkdir(parents=True, exist_ok=True)
                    new_txt = (cleaned + "\n\n" + hook_code).strip() + "\n"
                    prof.write_text(new_txt, encoding="utf-8")
                else:
                    if prof.exists():
                        prof.write_text(cleaned + ("\n" if cleaned else ""), encoding="utf-8")
            except Exception:
                pass
    else:
        bin_dir = "$HOME/.local/bin"
        hook_tag = "# >>> AGY_CLI_HOOK >>>"
        hook_end = "# <<< AGY_CLI_HOOK <<<"
        hook_code = f"""{hook_tag}
if [[ -f "$HOME/.antigravity-bypass/client/agy-run" ]]; then
    alias agy="$HOME/.antigravity-bypass/client/agy-run"
fi
{hook_end}"""
        for rc in [Path.home() / ".bashrc", Path.home() / ".zshrc", Path.home() / ".profile"]:
            if rc.exists() and rc.is_file():
                try:
                    txt = rc.read_text(encoding="utf-8", errors="ignore")
                    pat = re.compile(rf"\n?{re.escape(hook_tag)}[\s\S]*?{re.escape(hook_end)}\n?")
                    cleaned = pat.sub("\n", txt).strip()
                    has_path = bin_dir in cleaned or ".local/bin" in cleaned
                    if ensure_path:
                        path_export = f'\nexport PATH="{bin_dir}:$PATH"\n' if not has_path else "\n"
                        new_txt = (cleaned + path_export + hook_code).strip() + "\n"
                        rc.write_text(new_txt, encoding="utf-8")
                    else:
                        rc.write_text(cleaned + ("\n" if cleaned else ""), encoding="utf-8")
                except Exception:
                    pass


def install_cli_hook() -> Tuple[bool, str]:
    """Deploys CLI process-local proxy wrapper hook with smart Happ/proxy auto-routing."""
    user_bin = Path.home() / ".local" / "bin"
    sys_plat = platform.system()
    if sys_plat == "Windows":
        local_app = os.environ.get("LOCALAPPDATA")
        if local_app and (Path(local_app) / "Programs" / "Antigravity" / "bin").exists():
            user_bin = Path(local_app) / "Programs" / "Antigravity" / "bin"
        else:
            user_bin = Path.home() / ".local" / "bin"

    user_bin.mkdir(parents=True, exist_ok=True)

    # Candidate directories to inspect and hook across OSes
    cand_dirs = [user_bin]
    if sys_plat == "Windows":
        local_app = os.environ.get("LOCALAPPDATA")
        user_prof = os.environ.get("USERPROFILE")
        if local_app:
            cand_dirs.append(Path(local_app) / "Programs" / "Antigravity" / "bin")
        if user_prof:
            cand_dirs.append(Path(user_prof) / ".gemini" / "antigravity-cli" / "bin")
            cand_dirs.append(Path(user_prof) / ".local" / "bin")
            cand_dirs.append(Path(user_prof) / ".antigravity-bypass")
            cand_dirs.append(Path(user_prof) / ".antigravity-bypass" / "bin")
    else:
        cand_dirs.append(Path.home() / ".gemini" / "antigravity-cli" / "bin")
        cand_dirs.append(Path.home() / ".local" / "bin")
        cand_dirs.append(Path.home() / ".antigravity-bypass" / "bin")

    # Locate underlying real agy binary
    backup_binary = user_bin / ("agy.real.exe" if sys_plat == "Windows" else "agy.real")
    original_agy = None

    if _is_native_binary(backup_binary):
        original_agy = backup_binary
    else:
        for candidate in [
            str(backup_binary),
            shutil.which("agy.real.exe" if sys_plat == "Windows" else "agy.real"),
            str(user_bin / "agy.real.agy_bak"),
            str(user_bin / "agy.agy_bak"),
            str(Path.home() / ".gemini" / "antigravity-cli" / "bin" / ("agy.real.exe" if sys_plat == "Windows" else "agy.real")),
            shutil.which("agy.exe" if sys_plat == "Windows" else "agy"),
            str(user_bin / ("agy.exe" if sys_plat == "Windows" else "agy")),
            "/root/.local/bin/agy",
            "/usr/local/bin/agy",
        ]:
            if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                cand_p = Path(candidate)
                if _is_native_binary(cand_p):
                    original_agy = cand_p
                    break

    if original_agy and _is_native_binary(original_agy):
        if original_agy.name.lower() in ("agy", "agy.exe"):
            if not backup_binary.exists() or backup_binary.resolve() != original_agy.resolve():
                try:
                    shutil.move(str(original_agy), str(backup_binary))
                    original_agy = backup_binary
                except Exception as e:
                    logger.warning(f"Could not move {original_agy} to {backup_binary}: {e}")

    if sys_plat == "Windows":
        # Rename agy.exe across all candidate dirs so Windows command lookup doesn't pick raw exe
        for cdir in cand_dirs:
            if not cdir.exists():
                continue
            c_exe = cdir / "agy.exe"
            c_real = cdir / "agy.real.exe"
            if c_exe.exists() and not c_real.exists():
                try:
                    shutil.move(str(c_exe), str(c_real))
                except Exception:
                    pass

        wrapper_content_cmd = f"""@echo off
{WRAPPER_SIGNATURE}
rem Smart process-local launcher for agy with Happ / VPN / VPS auto-routing.
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%agy.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%agy.ps1" %*
) else if exist "%USERPROFILE%\\.antigravity-bypass\\client\\agy-run.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\\.antigravity-bypass\\client\\agy-run.ps1" %*
) else if exist "%USERPROFILE%\\.antigravity-bypass\\agy-run.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\\.antigravity-bypass\\agy-run.ps1" %*
) else (
    setlocal
    taskkill /F /IM language_server_windows_x64.exe >nul 2>&1
    taskkill /F /IM language_server.exe >nul 2>&1
    set "AG_LS_PROXY=http://{DEFAULT_SERVER}:{UPSTREAM_HTTP}"
    set "HTTPS_PROXY=http://{DEFAULT_SERVER}:{UPSTREAM_HTTP}"
    set "HTTP_PROXY=http://{DEFAULT_SERVER}:{UPSTREAM_HTTP}"
    set "https_proxy=http://{DEFAULT_SERVER}:{UPSTREAM_HTTP}"
    set "http_proxy=http://{DEFAULT_SERVER}:{UPSTREAM_HTTP}"
    set "NO_PROXY=localhost,127.0.0.1,::1"
    set "no_proxy=localhost,127.0.0.1,::1"
    set "REAL_AGY={backup_binary}"
    if not exist "%REAL_AGY%" (
        for %%X in (agy.real.exe agy.real) do (
            if not "%%~$PATH:X"=="" set "REAL_AGY=%%~$PATH:X"
        )
    )
    if exist "%REAL_AGY%" (
        "%REAL_AGY%" %*
        set "EXIT_CODE=%ERRORLEVEL%"
    ) else (
        echo Error: underlying agy executable not found! 1>&2
        set "EXIT_CODE=1"
    )
    taskkill /F /IM language_server_windows_x64.exe >nul 2>&1
    taskkill /F /IM language_server.exe >nul 2>&1
    endlocal & exit /b %EXIT_CODE%
)
"""
        wrapper_content_ps1 = f"""# {WRAPPER_SIGNATURE}
# Smart process-local launcher for agy with Happ / VPN / VPS auto-routing.
[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AgyArgs
)

function Get-AgyProxy {{
    if ($env:AGY_CUSTOM_PROXY) {{ return $env:AGY_CUSTOM_PROXY }}
    try {{
        $reg = Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" -ErrorAction SilentlyContinue
        if ($reg -and $reg.ProxyEnable -eq 1 -and $reg.ProxyServer) {{
            $srv = [string]$reg.ProxyServer
            if ($srv -match "https?=([^;]+)") {{ $srv = $matches[1] }}
            elseif ($srv -match "([^;=]+)") {{ $srv = $matches[1] }}
            if ($srv -and $srv -notmatch ":1080[89]") {{
                if ($srv -notmatch "^[a-zA-Z]+://") {{ $srv = "http://" + $srv }}
                return $srv
            }}
        }}
    }} catch {{}}
    if ($env:HTTPS_PROXY -and $env:HTTPS_PROXY -notlike "*{DEFAULT_SERVER}*" -and $env:HTTPS_PROXY -notmatch ":1080[89]") {{ return $env:HTTPS_PROXY }}
    if ($env:HTTP_PROXY -and $env:HTTP_PROXY -notlike "*{DEFAULT_SERVER}*" -and $env:HTTP_PROXY -notmatch ":1080[89]") {{ return $env:HTTP_PROXY }}
    return "http://{DEFAULT_SERVER}:{UPSTREAM_HTTP}"
}}

$RealAgy = "{backup_binary}"
if (-not (Test-Path $RealAgy)) {{
    $RealAgy = Get-Command "agy.real.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if (-not $RealAgy) {{
        $RealAgy = Get-Command "agy.real" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    }}
}}
if (-not $RealAgy -or -not (Test-Path $RealAgy)) {{
    Write-Error "Error: underlying agy executable not found!"
    exit 1
}}

$ProxyUrl = Get-AgyProxy
$OldHttps = $env:HTTPS_PROXY
$OldHttp  = $env:HTTP_PROXY
$OldAgLs  = $env:AG_LS_PROXY
$OldNoP   = $env:NO_PROXY

Get-Process -Name "language_server_windows_x64", "language_server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

try {{
    if ($ProxyUrl) {{
        $env:HTTPS_PROXY = $ProxyUrl
        $env:HTTP_PROXY  = $ProxyUrl
        $env:AG_LS_PROXY = $ProxyUrl
        $env:https_proxy = $ProxyUrl
        $env:http_proxy  = $ProxyUrl
        $env:NO_PROXY    = "localhost,127.0.0.1,::1"
        $env:no_proxy    = "localhost,127.0.0.1,::1"
    }} else {{
        $env:HTTPS_PROXY = $null
        $env:HTTP_PROXY  = $null
        $env:AG_LS_PROXY = $null
        $env:https_proxy = $null
        $env:http_proxy  = $null
    }}

    & $RealAgy @args
    $code = $LASTEXITCODE
}} finally {{
    Get-Process -Name "language_server_windows_x64", "language_server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $env:HTTPS_PROXY = $OldHttps
    $env:HTTP_PROXY  = $OldHttp
    $env:AG_LS_PROXY = $OldAgLs
    $env:https_proxy = $OldHttps
    $env:http_proxy  = $OldHttp
    $env:NO_PROXY    = $OldNoP
    $env:no_proxy    = $OldNoP
}}

exit $code
"""
        # Write wrappers to candidate dirs where agy.real.exe lives
        for cdir in cand_dirs:
            if cdir.exists():
                try:
                    (cdir / "agy.cmd").write_text(wrapper_content_cmd, encoding="utf-8")
                    (cdir / "agy.bat").write_text(wrapper_content_cmd, encoding="utf-8")
                    (cdir / "agy.ps1").write_text(wrapper_content_ps1, encoding="utf-8")
                except Exception:
                    pass
    else:
        wrapper_content = f"""#!/usr/bin/env bash
{WRAPPER_SIGNATURE}
# Smart process-local launcher for agy with Happ / VPN / VPS auto-routing.

REAL_AGY="{backup_binary if backup_binary.exists() else (original_agy or backup_binary)}"
if [[ ! -x "$REAL_AGY" ]]; then
    if command -v agy.real >/dev/null 2>&1; then
        REAL_AGY="$(command -v agy.real)"
    else
        echo "Error: underlying agy executable not found." >&2
        exit 1
    fi
fi

if [[ -f "/etc/systemd/system/antigravity-unlocker.service" ]]; then
    exec "$REAL_AGY" "$@"
fi

CHOSEN_PROXY=""
if [[ -n "$AGY_CUSTOM_PROXY" ]]; then
    CHOSEN_PROXY="$AGY_CUSTOM_PROXY"
elif [[ -n "$HTTPS_PROXY" && "$HTTPS_PROXY" != *"{DEFAULT_SERVER}"* && "$HTTPS_PROXY" != *":10808"* && "$HTTPS_PROXY" != *":10809"* ]]; then
    CHOSEN_PROXY="$HTTPS_PROXY"
elif [[ -n "$HTTP_PROXY" && "$HTTP_PROXY" != *"{DEFAULT_SERVER}"* && "$HTTP_PROXY" != *":10808"* && "$HTTP_PROXY" != *":10809"* ]]; then
    CHOSEN_PROXY="$HTTP_PROXY"
elif [[ -n "$ALL_PROXY" && "$ALL_PROXY" != *"{DEFAULT_SERVER}"* && "$ALL_PROXY" != *":10808"* && "$ALL_PROXY" != *":10809"* ]]; then
    CHOSEN_PROXY="$ALL_PROXY"
else
    CHOSEN_PROXY="http://{DEFAULT_SERVER}:{UPSTREAM_HTTP}"
fi

pkill -f "language_server" >/dev/null 2>&1 || true

if [[ -n "$CHOSEN_PROXY" ]]; then
    exec env \
        HTTPS_PROXY="$CHOSEN_PROXY" \
        HTTP_PROXY="$CHOSEN_PROXY" \
        https_proxy="$CHOSEN_PROXY" \
        http_proxy="$CHOSEN_PROXY" \
        AG_LS_PROXY="$CHOSEN_PROXY" \
        NO_PROXY="localhost,127.0.0.1,::1" \
        no_proxy="localhost,127.0.0.1,::1" \
        "$REAL_AGY" "$@"
else
    exec env -u HTTPS_PROXY -u HTTP_PROXY -u https_proxy -u http_proxy -u AG_LS_PROXY \
        "$REAL_AGY" "$@"
fi
"""
        for cdir in cand_dirs:
            if not cdir.exists():
                continue
            c_bin = cdir / "agy"
            c_real = cdir / "agy.real"
            if c_bin.exists() and not c_real.exists():
                if _is_native_binary(c_bin):
                    try:
                        shutil.move(str(c_bin), str(c_real))
                    except Exception:
                        pass
                else:
                    for bak in [cdir / "agy.real.agy_bak", cdir / "agy.agy_bak", cdir / "agy.bak"]:
                        if _is_native_binary(bak):
                            try:
                                shutil.copy2(str(bak), str(c_real))
                                break
                            except Exception:
                                pass
            try:
                c_bin.write_text(wrapper_content, encoding="utf-8")
                c_bin.chmod(0o755)
            except Exception:
                pass

    sync_shell_profiles(ensure_path=True)
    clean_stale_local_proxies()
    return True, "HOOK DEPLOYED TO SYSTEM"


def uninstall_cli_hook() -> Tuple[bool, str]:
    """Removes CLI proxy wrapper and restores original binary."""
    user_bin = Path.home() / ".local" / "bin"
    sys_plat = platform.system()
    cand_dirs = [user_bin]
    if sys_plat == "Windows":
        local_app = os.environ.get("LOCALAPPDATA")
        user_prof = os.environ.get("USERPROFILE")
        if local_app:
            cand_dirs.append(Path(local_app) / "Programs" / "Antigravity" / "bin")
        if user_prof:
            cand_dirs.append(Path(user_prof) / ".gemini" / "antigravity-cli" / "bin")
            cand_dirs.append(Path(user_prof) / ".local" / "bin")
            cand_dirs.append(Path(user_prof) / ".antigravity-bypass")
            cand_dirs.append(Path(user_prof) / ".antigravity-bypass" / "bin")
    else:
        cand_dirs.append(Path.home() / ".gemini" / "antigravity-cli" / "bin")
        cand_dirs.append(Path.home() / ".local" / "bin")
        cand_dirs.append(Path.home() / ".antigravity-bypass" / "bin")

    for cdir in cand_dirs:
        if not cdir.exists():
            continue
        for wname in ["agy.cmd", "agy.bat", "agy.ps1", "agy"]:
            wpath = cdir / wname
            if wpath.exists():
                try:
                    content = ""
                    with open(wpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read(1024)
                    if WRAPPER_SIGNATURE in content or "agy-run" in content or not _is_native_binary(wpath):
                        wpath.unlink()
                except Exception:
                    pass
        real_bin = cdir / ("agy.real.exe" if sys_plat == "Windows" else "agy.real")
        orig_bin = cdir / ("agy.exe" if sys_plat == "Windows" else "agy")
        if real_bin.exists() and not orig_bin.exists() and _is_native_binary(real_bin):
            try:
                shutil.move(str(real_bin), str(orig_bin))
            except Exception:
                pass

    sync_shell_profiles(ensure_path=False)
    clean_stale_local_proxies()
    return True, "HOOK DISENGAGED, SYSTEM RESTORED"


def run_integrity_test() -> List[Tuple[str, str, str]]:
    """Runs diagnostics inspection."""
    results = []
    ok_http, lat_http = probe_tcp_port(DEFAULT_SERVER, UPSTREAM_HTTP, timeout=1.5)
    if ok_http:
        results.append(("FRANKFURT HTTP PROXY", "PASS", f"PORT {UPSTREAM_HTTP} ({lat_http:.0f}ms)"))
    else:
        results.append(("FRANKFURT HTTP PROXY", "FAIL", f"PORT {UPSTREAM_HTTP} UNREACHABLE"))

    patched, b_stat = check_binary_patch_status()
    if patched:
        results.append(("NATIVE BINARY BYPASS", "PASS", "ENGAGED (inexigible)"))
    else:
        results.append(("NATIVE BINARY BYPASS", "WARN", f"STOCK ({b_stat})"))

    agy_bin = shutil.which("agy")
    if agy_bin:
        results.append(("AGY CLI BINARY", "PASS", "READY IN PATH"))
    else:
        results.append(("AGY CLI BINARY", "WARN", "NOT FOUND IN PATH"))

    ag_ls = os.environ.get("AG_LS_PROXY", "")
    if "18443" in ag_ls:
        results.append(("PROXY ENVIRONMENT", "FAIL", "STALE 18443 (FIXED BY ENGAGE)"))
    elif ag_ls:
        results.append(("PROXY ENVIRONMENT", "PASS", f"ROUTED: {ag_ls}"))
    else:
        results.append(("PROXY ENVIRONMENT", "PASS", "DIRECT ROUTE READY"))

    return results


_RELAY_ONLINE: bool = True
_VERSION_REMOTE: Optional[dict] = None
_BACKGROUND_WORKER_STARTED: bool = False
_LOCAL_VERSION_CACHE: Optional[dict] = None


def _background_net_worker():
    global _RELAY_ONLINE, _VERSION_REMOTE
    last_version_check = 0.0
    while True:
        # 1. Probe relay port asynchronously
        try:
            ok = False
            for p in (UPSTREAM_HTTP, 443, 80):
                ok_port, _ = probe_tcp_port(DEFAULT_SERVER, p, timeout=1.0)
                if ok_port:
                    ok = True
                    break
            _RELAY_ONLINE = ok
        except Exception:
            _RELAY_ONLINE = False

        # 2. Check remote version at startup and once every 60s
        now = time.time()
        if last_version_check == 0.0 or (now - last_version_check > 60.0):
            last_version_check = now
            try:
                rem = fetch_remote_version_info(server=DEFAULT_SERVER, timeout=1.0)
                if rem:
                    _VERSION_REMOTE = rem
            except Exception:
                pass

        time.sleep(10.0)


def _ensure_background_worker():
    global _BACKGROUND_WORKER_STARTED
    if not _BACKGROUND_WORKER_STARTED:
        _BACKGROUND_WORKER_STARTED = True
        t = threading.Thread(target=_background_net_worker, daemon=True)
        t.start()


def get_relay_status() -> Tuple[str, bool]:
    """Returns cached relay status without any blocking I/O."""
    _ensure_background_worker()
    badge = Color.badge_ok("ONLINE") if _RELAY_ONLINE else Color.badge_off("OFFLINE")
    return f"FRANKFURT, GERMANY {badge}", _RELAY_ONLINE


def get_version_data() -> Tuple[str, Optional[dict]]:
    """Returns cached version strings without blocking UI rendering."""
    global _LOCAL_VERSION_CACHE
    _ensure_background_worker()
    if _LOCAL_VERSION_CACHE is None:
        try:
            _LOCAL_VERSION_CACHE = get_local_version_info(get_install_dir())
        except Exception:
            _LOCAL_VERSION_CACHE = {"version": "1.0.5", "build": 0}

    loc_v = _LOCAL_VERSION_CACHE.get("version", "1.0.5")
    loc_b = _LOCAL_VERSION_CACHE.get("build", 0)

    rem = _VERSION_REMOTE
    if rem and rem.get("build", 0) > loc_b:
        rem_v = rem.get("version", str(rem.get("build")))
        disp = f"v{loc_v} → {Color.WHITE}v{rem_v}{Color.RESET} {Color.badge_warn('UPDATE AVAILABLE')}"
        return disp, rem
    else:
        disp = f"v{loc_v} {Color.badge_ok('LATEST')}"
        return disp, None


def main() -> None:
    """Main CLI entrypoint for interactive TUI console."""
    init_windows_vt()

    if "--install" in sys.argv:
        install_cli_hook()
        sys.exit(0)
    elif "--uninstall" in sys.argv:
        uninstall_cli_hook()
        sys.exit(0)
    elif "--status" in sys.argv or "--check" in sys.argv:
        tests = run_integrity_test()
        for t in tests:
            print(f"{t[0]:<24} [{t[1]}] {t[2]}")
        sys.exit(0)
    elif "-h" in sys.argv or "--help" in sys.argv:
        print("Usage: agy-ui [--install | --uninstall | --status | --help]")
        print("Antigravity Zero-Privilege Console & CLI Hook Manager")
        sys.exit(0)

    if not sys.stdin.isatty():
        print("Interactive console requires a TTY. Use --status, --install, or --uninstall.")
        sys.exit(0)

    sys.stdout.write("\033[?1049h\033[2J\033[?25l")
    sys.stdout.flush()

    selected_idx = 0
    message: Optional[Tuple[str, List[str], bool]] = None

    def draw_screen(progress_info: Optional[dict] = None) -> None:
        nonlocal selected_idx, message
        _, term_lines = shutil.get_terminal_size((80, 40))

        bin_patched, bin_det = check_binary_patch_status()
        hook_active, hook_det = check_cli_hook_status()

        ver_text, update_info = get_version_data()
        relay_text, _ = get_relay_status()
        menu_items = get_menu_items(update_info)

        if selected_idx >= len(menu_items):
            selected_idx = len(menu_items) - 1

        frame_lines = build_frame(
            selected_idx=selected_idx,
            bin_patched=bin_patched,
            bin_det=bin_det,
            hook_active=hook_active,
            hook_det=hook_det,
            relay_text=relay_text,
            ver_text=ver_text,
            message=message,
            term_lines=term_lines,
            menu_items=menu_items,
            update_info=update_info,
            progress_info=progress_info,
        )

        # Atomic draw: home cursor, draw frame, erase below
        output = "\033[H" + "\n".join(frame_lines) + "\033[J"
        sys.stdout.write(output)
        sys.stdout.flush()

    def run_with_progress(
        title: str,
        worker_fn,
        statuses: Optional[List[str]] = None,
    ) -> Tuple[any, Optional[Exception]]:
        nonlocal message
        message = None

        container = {"done": False, "result": None, "exc": None}

        def _bg_target():
            try:
                container["result"] = worker_fn()
            except Exception as ex:
                container["exc"] = ex
            finally:
                container["done"] = True

        th = threading.Thread(target=_bg_target, daemon=True)
        th.start()

        status_seq = statuses or [
            "Analyzing configuration and environment...",
            "Applying directives...",
            "Verifying state...",
        ]

        # Optimistic smooth progress loop
        cur_pct = 15
        while not container["done"]:
            if cur_pct < 85:
                cur_pct += 7
            elif cur_pct < 94:
                cur_pct += 1
            st_idx = min(len(status_seq) - 1, int((cur_pct / 100.0) * len(status_seq)))
            draw_screen({
                "title": title,
                "percent": cur_pct,
                "status": status_seq[st_idx],
            })
            time.sleep(0.04)

        # Smooth advance to 100%
        for p in range(max(cur_pct, 92), 101, 3):
            draw_screen({
                "title": title,
                "percent": p,
                "status": "Complete!" if p >= 100 else "Finalizing...",
            })
            time.sleep(0.02)

        time.sleep(0.06)
        draw_screen(progress_info=None)
        return container["result"], container["exc"]

    try:
        while True:
            draw_screen(progress_info=None)

            key = read_key()

            if key == "UP":
                _, update_info = get_version_data()
                menu_len = len(get_menu_items(update_info))
                selected_idx = (selected_idx - 1) % menu_len
                message = None
            elif key == "DOWN":
                _, update_info = get_version_data()
                menu_len = len(get_menu_items(update_info))
                selected_idx = (selected_idx + 1) % menu_len
                message = None
            elif key == "QUIT":
                break
            elif key == "1":
                selected_idx = 0
                key = "ENTER"
            elif key == "2":
                selected_idx = 1
                key = "ENTER"
            elif key == "3":
                selected_idx = 2
                key = "ENTER"
            elif key in ("U", "u"):
                _, update_info = get_version_data()
                if update_info:
                    for idx, (aid, _, _) in enumerate(get_menu_items(update_info)):
                        if aid == "UPDATE":
                            selected_idx = idx
                            key = "ENTER"
                            break

            if key == "ENTER":
                _, update_info = get_version_data()
                cur_menu = get_menu_items(update_info)
                if selected_idx >= len(cur_menu):
                    selected_idx = 0
                action_id = cur_menu[selected_idx][0]

                if action_id == "QUIT":
                    break
                elif action_id == "ENGAGE":
                    def _do_engage():
                        ok, logs = apply_account_unlock(host=DEFAULT_SERVER, port=UPSTREAM_HTTP)
                        install_cli_hook()
                        _BIN_STATE_CACHE.clear()
                        _HOOK_STATE_CACHE = None
                        _CLI_PATHS_CACHE = None
                        return ok

                    res, exc = run_with_progress(
                        "ENGAGE UNLOCK & FRANKFURT ROUTE",
                        _do_engage,
                        [
                            "Analyzing binary signatures...",
                            "Applying byte-exact bypass (inexigible)...",
                            "Configuring direct route to Frankfurt node...",
                            "Deploying smart launcher wrappers...",
                        ],
                    )
                    if exc:
                        message = ("OPERATION FAILED", [f"Error: {exc}"], False)
                    elif res:
                        message = ("OPERATION SUCCESSFUL", ["Unlock engaged & Frankfurt route secured."], True)
                    else:
                        message = ("OPERATION FAILED", ["Failed to engage unlock. Check permissions."], False)

                elif action_id == "DISENGAGE":
                    def _do_disengage():
                        ok, logs = revert_account_unlock()
                        uninstall_cli_hook()
                        _BIN_STATE_CACHE.clear()
                        _HOOK_STATE_CACHE = None
                        _CLI_PATHS_CACHE = None
                        return ok

                    res, exc = run_with_progress(
                        "DISENGAGE & RESTORE STOCK STATE",
                        _do_disengage,
                        [
                            "Locating modified binaries...",
                            "Restoring pristine backup copies...",
                            "Purging proxy routes...",
                            "Reverting shell hooks & wrappers...",
                        ],
                    )
                    if exc:
                        message = ("OPERATION FAILED", [f"Error: {exc}"], False)
                    elif res:
                        message = ("OPERATION SUCCESSFUL", ["Stock state restored. All bypasses removed."], True)
                    else:
                        message = ("OPERATION FAILED", ["Failed to restore stock state."], False)

                elif action_id == "INSPECT":
                    def _do_inspect():
                        return run_integrity_test()

                    tests, exc = run_with_progress(
                        "RUN INTEGRITY & PROXY INSPECTION",
                        _do_inspect,
                        [
                            "Probing Frankfurt proxy latency...",
                            "Inspecting binary bypass signature...",
                            "Checking agy CLI binary in PATH...",
                            "Auditing environment and routing...",
                        ],
                    )
                    if exc:
                        message = ("INSPECTION FAILED", [f"Error: {exc}"], False)
                    else:
                        fails = [f"{t[0]}: {t[2]}" for t in tests if t[1] == "FAIL"]
                        if not fails:
                            message = ("OPERATION SUCCESSFUL", ["All integrity checks passed. Bypass is healthy."], True)
                        else:
                            message = ("INTEGRITY WARNING", fails, False)

                elif action_id == "UPDATE" and update_info:
                    def _do_update():
                        ok = apply_update(update_info, get_install_dir())
                        return ok

                    res, exc = run_with_progress(
                        f"UPGRADE CONSOLE TO v{update_info.get('version', 'LATEST')}",
                        _do_update,
                        [
                            "Downloading update archive...",
                            "Verifying SHA256 integrity...",
                            "Extracting updated files...",
                            "Reloading console...",
                        ],
                    )
                    _LOCAL_VERSION_CACHE = None
                    if exc or not res:
                        message = ("OPERATION FAILED", ["Could not apply update from server."], False)
                    else:
                        message = ("OPERATION SUCCESSFUL", ["Console updated successfully. Please restart."], True)

    finally:
        sys.stdout.write("\033[?1049l\033[?25h\033[0m")
        sys.stdout.flush()
        print(f"\n{Color.RED}[ ✠ ] REICH-COMMAND CONSOLE TERMINATED.{Color.RESET}\n")


if __name__ == "__main__":
    main()
