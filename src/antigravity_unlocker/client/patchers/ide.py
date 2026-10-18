"""
ide.py - Antigravity IDE settings.json and JavaScript bundle patcher.
Configures jetski.cloudCodeUrl and neutralizes client-side eligibility checks.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from antigravity_unlocker.client.patchers.base import BasePatcher, PatchResult
from antigravity_unlocker.common.system import (
    get_antigravity_install_dirs,
    get_ide_settings_paths,
    is_running_on_vps,
    test_tcp_connectivity,
)

from antigravity_unlocker.common.discovery import get_client_target_server

logger = logging.getLogger("ide_patcher")

DEFAULT_CLOUDCODE_URL = "https://daily-cloudcode-pa.googleapis.com"


def patch_ide_settings(
    host: Optional[str] = None,
    port: int = 48329,
    cloudcode_url: str = DEFAULT_CLOUDCODE_URL,
    custom_path: Optional[Path] = None,
) -> List[str]:
    """Updates Antigravity IDE settings.json with daily cloudCodeUrl and proxy."""
    target_host = host or get_client_target_server()
    messages: List[str] = []
    proxy_url = f"http://{target_host}:{port}"
    all_paths = [custom_path] if custom_path else get_ide_settings_paths()

    target_paths = [p for p in all_paths if p.exists() or p.parent.exists()]
    if not target_paths and all_paths:
        target_paths = [all_paths[0]]

    for target_path in target_paths:
        try:
            existing: Dict[str, Any] = {}
            if target_path.exists():
                try:
                    raw = target_path.read_text(encoding="utf-8")
                    if raw.strip():
                        existing = json.loads(raw)
                        bak = target_path.with_name(target_path.name + ".bak")
                        if not bak.exists():
                            shutil.copy2(target_path, bak)
                except Exception:
                    existing = {}

            target_path.parent.mkdir(parents=True, exist_ok=True)
            existing["jetski.cloudCodeUrl"] = cloudcode_url

            if not is_running_on_vps(host) and test_tcp_connectivity(host, port, timeout=1.0):
                existing["http.proxy"] = proxy_url
                existing["http.proxyStrictSSL"] = True
            elif "http.proxy" in existing and "18443" in str(existing["http.proxy"]):
                del existing["http.proxy"]

            target_path.write_text(json.dumps(existing, indent=2) + "\n", encoding="utf-8")
            messages.append(f"Configured IDE settings in {target_path.parent.name}/{target_path.name}")
        except Exception as e:
            logger.debug(f"Failed to patch IDE settings at {target_path}: {e}")

    return messages


def revert_ide_settings(custom_path: Optional[Path] = None) -> List[str]:
    """Reverts settings.json from existing backup file (.bak)."""
    messages: List[str] = []
    paths = [custom_path] if custom_path else get_ide_settings_paths()
    for spath in paths:
        bak = spath.with_name(spath.name + ".bak")
        if bak.exists():
            try:
                shutil.copy2(bak, spath)
                bak.unlink()
                messages.append(f"Reverted settings: {spath.name}")
            except Exception as e:
                logger.debug(f"Failed to revert settings at {spath}: {e}")
    return messages


def patch_file_content(path: Path) -> bool:
    """Neutralizes isEligible check in JS bundle files."""
    try:
        data = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False

    modified = False

    if re.search(r"isEligible\s*:\s*false", data):
        data = re.sub(r"isEligible\s*:\s*false", "isEligible: true", data)
        modified = True

    if '?.case==="ineligible"' in data:
        data = data.replace('?.case==="ineligible"', '?.case==="inexigible"')
        modified = True

    if 'case==="ineligible"?this._authActor.send({type:"SET_INELIGIBLE"' in data:
        data = data.replace(
            'case==="ineligible"?this._authActor.send({type:"SET_INELIGIBLE"',
            'case==="NEVER_MATCH"?this._authActor.send({type:"SET_INELIGIBLE"',
        )
        modified = True

    if modified:
        bak = Path(str(path) + ".agy_bak")
        if not bak.exists():
            try:
                shutil.copy2(path, bak)
            except Exception:
                pass
        path.write_text(data, encoding="utf-8")
        return True

    return False


def patch_ide_bundles() -> List[str]:
    """Finds and patches candidate extension/workbench JS files."""
    messages: List[str] = []
    install_dirs = get_antigravity_install_dirs()
    candidate_files: List[Path] = []
    for inst in install_dirs:
        if not inst.exists():
            continue
        # Scan target bundle subdirectories and skip node_modules for high performance
        target_subdirs = [
            inst / "resources" / "app" / "out",
            inst / "resources" / "app" / "extensions",
            inst / "extensions",
            inst / "out",
        ]
        subdirs_to_check = [s for s in target_subdirs if s.exists()]
        if not subdirs_to_check:
            subdirs_to_check = [inst]
        for sdir in subdirs_to_check:
            for pat in ["*.js", "*.cjs", "*/*.js", "*/*.cjs"]:
                for match in sdir.glob(pat):
                    if match.is_file() and "node_modules" not in match.parts:
                        if any(k in match.name for k in ["extension", "workbench", "main", "bundle"]):
                            candidate_files.append(match)

    patched_count = 0
    for cand in candidate_files:
        if patch_file_content(cand):
            patched_count += 1
            messages.append(f"Patched bundle: {cand.name}")

    if patched_count > 0:
        messages.append(f"Patched {patched_count} IDE bundle file(s)")
    return messages


def revert_ide_bundles() -> List[str]:
    """Reverts JS bundle patches from backups."""
    messages: List[str] = []
    for inst in get_antigravity_install_dirs():
        for bak in inst.glob("**/*.agy_bak"):
            orig = bak.with_suffix("")
            try:
                shutil.copy2(bak, orig)
                bak.unlink()
                messages.append(f"Reverted bundle: {orig.name}")
            except Exception as e:
                logger.debug(f"Failed to revert bundle {bak}: {e}")
    return messages


class IdePatcher(BasePatcher):
    """Patcher implementation for Antigravity IDE configuration and bundles."""

    @property
    def name(self) -> str:
        return "IDE Patcher"

    def inspect(self, target: Path) -> Dict[str, Any]:
        if not target.exists():
            return {"exists": False}
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
            return {
                "exists": True,
                "cloudCodeUrl": data.get("jetski.cloudCodeUrl"),
                "proxy": data.get("http.proxy"),
                "is_patched": data.get("jetski.cloudCodeUrl") == DEFAULT_CLOUDCODE_URL,
            }
        except Exception as e:
            return {"exists": True, "error": str(e)}

    def apply(self, target: Path) -> PatchResult:
        logs = patch_ide_settings(custom_path=target)
        return PatchResult(success=len(logs) > 0, modified_count=len(logs), message="; ".join(logs))

    def revert(self, target: Path) -> PatchResult:
        logs = revert_ide_settings(custom_path=target)
        return PatchResult(success=len(logs) > 0, modified_count=len(logs), message="; ".join(logs))
