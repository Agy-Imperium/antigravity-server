"""
ui - Brutalist console TUI management components.
"""

from antigravity_unlocker.client.ui.app import (
    check_binary_patch_status,
    check_cli_hook_status,
    install_cli_hook,
    main,
    probe_tcp_port,
    run_integrity_test,
    sync_shell_profiles,
    uninstall_cli_hook,
)
from antigravity_unlocker.client.ui.terminal import (
    cleanup_terminal,
    init_windows_vt,
    read_key,
    supports_color,
)
from antigravity_unlocker.client.ui.theme import (
    BOX_WIDTH,
    Color,
    pad_box,
    visible_len,
)
from antigravity_unlocker.client.ui.views import build_frame, get_menu_items

__all__ = [
    "main",
    "init_windows_vt",
    "supports_color",
    "cleanup_terminal",
    "read_key",
    "Color",
    "BOX_WIDTH",
    "pad_box",
    "visible_len",
    "build_frame",
    "get_menu_items",
    "probe_tcp_port",
    "check_binary_patch_status",
    "check_cli_hook_status",
    "sync_shell_profiles",
    "install_cli_hook",
    "uninstall_cli_hook",
    "run_integrity_test",
]
