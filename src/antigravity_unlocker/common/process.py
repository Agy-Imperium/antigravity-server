"""
process.py - Cross-platform discovery and termination of Antigravity processes.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import logging
import platform
import subprocess
from typing import List

logger = logging.getLogger("process")

WINDOWS_TARGET_PROCESSES = [
    "agy.exe",
    "agy.real.exe",
    "Antigravity.exe",
    "language_server.exe",
    "language_server_windows_x64.exe",
]

POSIX_TARGET_PATTERNS = [
    "language_server",
    "agy.real",
]


def kill_antigravity_processes() -> List[str]:
    """
    Terminates running Antigravity IDE and Language Server processes so that
    file locks on binaries and extension scripts are released.
    Does NOT terminate the caller process or terminal shell.
    """
    killed: List[str] = []
    sys_plat = platform.system()

    if sys_plat == "Windows":
        cmd = ["taskkill", "/F", "/T"]
        for proc_name in WINDOWS_TARGET_PROCESSES:
            cmd.extend(["/IM", proc_name])
        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2.0,
            )
            if res.returncode == 0:
                killed.extend(WINDOWS_TARGET_PROCESSES)
        except Exception as e:
            logger.debug(f"Failed taskkill: {e}")
    else:
        # Linux / Darwin / WSL
        for proc_pattern in POSIX_TARGET_PATTERNS:
            try:
                res = subprocess.run(
                    ["pkill", "-9", "-f", proc_pattern],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=1.0,
                )
                if res.returncode == 0:
                    killed.append(proc_pattern)
            except Exception as e:
                logger.debug(f"Failed pkill for {proc_pattern}: {e}")

    return killed
