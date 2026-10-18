"""
patchers - Modular patching framework for Antigravity Unlocker.
Operates 100% in unprivileged user space.
"""

from __future__ import annotations

import logging
from typing import List, Tuple

from antigravity_unlocker.client.patchers.base import BasePatcher, PatchResult, PatchRule
from antigravity_unlocker.client.patchers.binary import (
    FIELD_FROM,
    FIELD_TO,
    PROXY_FROM,
    PROXY_TO,
    BinaryPatcher,
    inspect_binary_state,
    patch_cli_binary,
    unpatch_cli_binary,
)
from antigravity_unlocker.client.patchers.env import (
    clean_stale_local_proxies,
    configure_direct_proxy,
)
from antigravity_unlocker.client.patchers.ide import (
    DEFAULT_CLOUDCODE_URL,
    IdePatcher,
    patch_file_content,
    patch_ide_bundles,
    patch_ide_settings,
    revert_ide_bundles,
    revert_ide_settings,
)
from antigravity_unlocker.common.process import kill_antigravity_processes
from antigravity_unlocker.common.system import (
    get_antigravity_install_dirs,
    get_cli_binary_paths,
    get_ide_settings_paths,
    get_user_home,
    is_running_on_vps,
)

from antigravity_unlocker.common.discovery import get_client_target_server

logger = logging.getLogger("patchers")


def apply_account_unlock(
    host: Optional[str] = None,
    port: int = 48329,
    enable_proxy: bool = True,
) -> Tuple[bool, List[str]]:
    """Master unlock routine coordinating all patchers."""
    target_host = host or get_client_target_server()
    logs: List[str] = []

    # 1. Clean stale local proxies
    logs.extend(clean_stale_local_proxies())

    # 2. Terminate running processes to release file locks
    killed = kill_antigravity_processes()
    if killed:
        logs.append(f"[PROCESS] Released file locks by closing: {', '.join(killed)}")

    # 3. Patch native CLI and Language Server binaries
    bin_paths = get_cli_binary_paths()
    patched_bins = 0
    already_patched_bins = 0

    if not bin_paths:
        logs.append("[BINARY WARNING] No Antigravity or agy binaries discovered.")

    for b in bin_paths:
        ok, count, msg = patch_cli_binary(b)
        if ok and "already patched" in msg:
            already_patched_bins += 1
            logs.append(f"[BINARY STATUS] {msg}")
        elif ok and count > 0:
            patched_bins += 1
            logs.append(f"[BINARY PATCH] {msg}")
        elif ok:
            logs.append(f"[BINARY STATUS] {msg}")
        else:
            logs.append(f"[BINARY ERROR] {msg}")

    # 4. Patch IDE JS bundles
    logs.extend(patch_ide_bundles())

    # 5. Patch IDE settings
    logs.extend(patch_ide_settings(host=target_host, port=port))

    # 6. Direct proxy routing
    if enable_proxy and not is_running_on_vps(target_host):
        logs.extend(configure_direct_proxy(host=target_host, port=port))
    elif is_running_on_vps(target_host):
        logs.append("[HOST] Localhost is Unlocker Server: Direct unproxied connection enabled.")

    success = (patched_bins > 0 or already_patched_bins > 0)
    return success, logs


def revert_account_unlock() -> Tuple[bool, List[str]]:
    """Reverts all binary patches, restores backups, and resets proxy config."""
    logs: List[str] = []

    # 1. Clean proxy configs
    logs.extend(clean_stale_local_proxies())

    # 2. Revert native binaries
    for b in get_cli_binary_paths():
        ok, count, msg = unpatch_cli_binary(b)
        if ok:
            logs.append(f"[BINARY REVERT] {msg}")

    # 3. Revert IDE settings
    logs.extend(revert_ide_settings())

    # 4. Revert JS bundles
    logs.extend(revert_ide_bundles())

    return True, logs


__all__ = [
    "BasePatcher",
    "PatchRule",
    "PatchResult",
    "BinaryPatcher",
    "IdePatcher",
    "FIELD_FROM",
    "FIELD_TO",
    "PROXY_FROM",
    "PROXY_TO",
    "DEFAULT_CLOUDCODE_URL",
    "patch_cli_binary",
    "unpatch_cli_binary",
    "inspect_binary_state",
    "patch_ide_settings",
    "revert_ide_settings",
    "patch_file_content",
    "patch_ide_bundles",
    "revert_ide_bundles",
    "clean_stale_local_proxies",
    "configure_direct_proxy",
    "apply_account_unlock",
    "revert_account_unlock",
]
