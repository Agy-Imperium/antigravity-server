"""
updater - Self-update and boot synchronization subsystem.
"""

from antigravity_unlocker.client.updater.boot_sync import (
    cleanup_legacy_autostart_hooks,
    setup_boot_autostart,
)
from antigravity_unlocker.client.updater.engine import (
    apply_update,
    fetch_remote_version_info,
    get_install_dir,
    get_local_version_info,
    is_engine_running,
    restart_local_engine,
)

__all__ = [
    "get_install_dir",
    "get_local_version_info",
    "fetch_remote_version_info",
    "is_engine_running",
    "restart_local_engine",
    "apply_update",
    "cleanup_legacy_autostart_hooks",
    "setup_boot_autostart",
]
