"""
client - Client-side components for Antigravity Unlocker.
"""

from antigravity_unlocker.client.patchers import (
    BinaryPatcher,
    IdePatcher,
    apply_account_unlock,
    clean_stale_local_proxies,
    configure_direct_proxy,
    inspect_binary_state,
    patch_cli_binary,
    patch_ide_bundles,
    patch_ide_settings,
    revert_account_unlock,
    revert_ide_bundles,
    revert_ide_settings,
    unpatch_cli_binary,
)

__all__ = [
    "BinaryPatcher",
    "IdePatcher",
    "apply_account_unlock",
    "revert_account_unlock",
    "patch_cli_binary",
    "unpatch_cli_binary",
    "inspect_binary_state",
    "patch_ide_settings",
    "revert_ide_settings",
    "patch_ide_bundles",
    "revert_ide_bundles",
    "clean_stale_local_proxies",
    "configure_direct_proxy",
]
