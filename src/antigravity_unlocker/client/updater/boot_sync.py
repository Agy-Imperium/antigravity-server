"""
boot_sync.py - Machine boot and user login autostart hooks configuration.
Operates completely in unprivileged user space.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import logging
import os
import platform
import sys
from pathlib import Path
from typing import List

logger = logging.getLogger("boot_sync")


def cleanup_legacy_autostart_hooks() -> List[str]:
    """
    Scrubs legacy shell profile background hooks (.bashrc, .profile, etc.)
    and PowerShell profile hooks that spawn background jobs.
    """
    cleaned: List[str] = []
    hook_tag = "# AGY_AUTO_UPDATE_ON_LOGIN"
    for rc_name in [".bashrc", ".profile", ".zshrc", ".bash_profile"]:
        rc_file = Path.home() / rc_name
        if rc_file.exists():
            try:
                txt = rc_file.read_text(encoding="utf-8", errors="ignore")
                if hook_tag in txt or "updater.py" in txt:
                    lines = txt.splitlines()
                    new_lines = []
                    modified = False
                    for line in lines:
                        if hook_tag in line or ("updater.py" in line and ("--quiet" in line or "&" in line)):
                            modified = True
                            continue
                        new_lines.append(line)
                    if modified:
                        rc_file.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
                        cleaned.append(f"Scrubbed background hook from {rc_name}")
            except Exception as e:
                logger.debug(f"Failed to scrub {rc_name}: {e}")

    if platform.system() == "Windows":
        docs = Path.home() / "Documents"
        for ps_profile in [
            docs / "WindowsPowerShell" / "Microsoft.PowerShell_profile.ps1",
            docs / "PowerShell" / "Microsoft.PowerShell_profile.ps1",
        ]:
            if ps_profile.exists():
                try:
                    txt = ps_profile.read_text(encoding="utf-8", errors="ignore")
                    lines = [
                        l for l in txt.splitlines()
                        if "updater.py" not in l
                        and "# AGY Auto-Updater" not in l
                        and not l.strip().startswith("export ")
                        and "AGY-UI" not in l
                    ]
                    if len(lines) != len(txt.splitlines()):
                        ps_profile.write_text("\n".join(lines) + "\n", encoding="utf-8")
                        cleaned.append(f"Scrubbed invalid hooks from {ps_profile.name}")
                except Exception:
                    pass

    return cleaned


def setup_boot_autostart(install_dir: Path) -> List[str]:
    """
    Configures automatic background update check upon machine boot / user login.
    Operates 100% in user space without requiring elevated privileges.
    """
    actions: List[str] = []
    scrubbed = cleanup_legacy_autostart_hooks()
    actions.extend(scrubbed)

    sys_plat = platform.system()
    updater_script = install_dir / "client" / "updater.py"

    if sys_plat == "Windows":
        appdata = os.environ.get("APPDATA")
        if appdata:
            startup_dir = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if startup_dir.exists():
                py_exe = sys.executable or "python"
                bat_content = f"""@echo off
rem AGY Zero-Privilege Boot Auto-Updater
start "" /B "{py_exe}" "{updater_script.as_posix()}" --quiet
"""
                try:
                    bat_file.write_text(bat_content, encoding="utf-8")
                    actions.append(f"Windows Startup script registered: {bat_file.name}")
                except Exception as e:
                    logger.debug(f"Startup folder write error: {e}")

    else:
        autostart_dir = Path.home() / ".config" / "autostart"
        try:
            autostart_dir.mkdir(parents=True, exist_ok=True)
            desktop_file = autostart_dir / "agy-autoupdate.desktop"
            desktop_content = f"""[Desktop Entry]
Type=Application
Name=AGY Command Auto-Updater
Exec=python3 {updater_script} --quiet
Hidden=false
NoDisplay=true
X-GNOME-Autostart-enabled=true
"""
            desktop_file.write_text(desktop_content, encoding="utf-8")
            actions.append("XDG Autostart desktop entry created")
        except Exception:
            pass

    return actions
