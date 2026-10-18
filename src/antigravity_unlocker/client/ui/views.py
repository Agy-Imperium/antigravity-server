"""
views.py - Frame and dialog rendering components for the Brutalist TUI console.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from antigravity_unlocker.client.ui.theme import (
    BOX_WIDTH,
    MANIFEST_SLOGANS,
    RAW_ASCII_CROSS,
    RAW_ASCII_CROSS_6,
    RAW_ASCII_CROSS_COMPACT,
    RAW_ASCII_TEXT,
    Color,
    pad_box,
    style_cross_line,
    style_imperium_line,
    visible_len,
)


def get_menu_items(update_info: Optional[dict] = None) -> List[Tuple[str, str, str]]:
    """Returns list of (action_id, title, description) for the interactive menu."""
    items = [
        (
            "ENGAGE",
            "COMMAND I   : ENGAGE UNLOCK & FRANKFURT ROUTE",
            "Applies byte-exact binary patch (inexigible) and secures direct route.",
        ),
        (
            "DISENGAGE",
            "COMMAND II  : DISENGAGE & RESTORE STOCK STATE",
            "Restores original binary bytes and purges all proxy configurations.",
        ),
        (
            "INSPECT",
            "COMMAND III : RUN INTEGRITY & PROXY INSPECTION",
            "Probes Frankfurt node, checks binary patches, and audits environment.",
        ),
    ]

    if update_info:
        target_v = update_info.get("version", "LATEST")
        b_val = update_info.get("build")
        b_str = f" #{b_val}" if b_val else ""
        items.append((
            "UPDATE",
            f"COMMAND [U] : UPGRADE CONSOLE TO v{target_v}",
            f"Downloads build{b_str} from server and hot-reloads console.",
        ))

    items.append((
        "QUIT",
        "COMMAND [Q] : TERMINATE COMMAND CONSOLE" if update_info else "COMMAND IV  : TERMINATE COMMAND CONSOLE",
        "Exits console session; active background relays persist.",
    ))
    return items


def build_frame(
    selected_idx: int,
    bin_patched: bool,
    bin_det: str,
    hook_active: bool,
    hook_det: str,
    relay_text: str,
    ver_text: str,
    message: Optional[Tuple[str, List[str], bool]],
    term_lines: int,
    menu_items: List[Tuple[str, str, str]],
    update_info: Optional[dict],
    progress_info: Optional[dict] = None,
) -> List[str]:
    """Builds complete TUI frame lines tailored to terminal dimensions."""
    lines: List[str] = []
    inner_w = BOX_WIDTH - 4

    # 1. Header Banner
    banner = "✠ REICH-COMMAND DIREKTORAT ✠"
    pad_left = (BOX_WIDTH - len(banner)) // 2
    pad_right = BOX_WIDTH - len(banner) - pad_left
    lines.append(f"{Color.GRAY}{'═' * BOX_WIDTH}{Color.RESET}")
    lines.append(f"{' ' * pad_left}{Color.WHITE}{banner}{Color.RESET}{' ' * pad_right}")
    lines.append(f"{Color.GRAY}{'─' * BOX_WIDTH}{Color.RESET}")

    # 2. Symmetrical Cross Emblem
    if message and term_lines <= 30:
        mini_1 = "                      ▲  [ ✠ ]  ▲                      "
        mini_2 = "               ◄══════╡  ░░░░░  ╞══════►               "
        lines.append(style_cross_line(mini_1))
        lines.append(style_cross_line(mini_2))
    else:
        if term_lines <= 26:
            cross_data = RAW_ASCII_CROSS_6
        elif term_lines <= 34:
            cross_data = RAW_ASCII_CROSS_COMPACT
        else:
            cross_data = RAW_ASCII_CROSS
        for r in cross_data:
            lines.append(style_cross_line(r))

    # 3. 3D AGY IMPERIUM Text (tall terminals)
    if term_lines >= 38 and not message:
        lines.append(f"{Color.GRAY}{'─' * BOX_WIDTH}{Color.RESET}")
        for t in RAW_ASCII_TEXT:
            lines.append(style_imperium_line(t))

    if term_lines > 30:
        lines.append(f"{Color.GRAY}{'─' * BOX_WIDTH}{Color.RESET}")

    # 4. Status Monitor
    bin_badge = f"{Color.WHITE}[{Color.RED}PATCHED{Color.WHITE}]{Color.RESET}" if bin_patched else f"{Color.GRAY}[STOCK]{Color.RESET}"
    hk_badge = f"{Color.WHITE}[{Color.RED}ACTIVE{Color.WHITE}]{Color.RESET}" if hook_active else f"{Color.GRAY}[DISENGAGED]{Color.RESET}"

    if term_lines <= 28:
        m_row1 = f"  BINARY: {bin_badge} │ HOOK: {hk_badge} │ RELAY: {relay_text}"
        m_row2 = f"  VERSION: {ver_text}"
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(m_row1, inner_w)} {Color.GRAY}│{Color.RESET}")
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(m_row2, inner_w)} {Color.GRAY}│{Color.RESET}")
    else:
        r1 = f"  BINARY PATCH (CLI/GO): {bin_badge}"
        r2 = f"  AGY-HOOK (INTERCEPT) : {hk_badge}"
        r3 = f"  RELAY NODE           : {relay_text}"
        r4 = f"  SOFTWARE VERSION     : {ver_text}"
        lines.append(f"{Color.GRAY}┌── REICH-COMMAND MONITOR {'─' * (BOX_WIDTH - 27)}┐{Color.RESET}")
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(r1, inner_w)} {Color.GRAY}│{Color.RESET}")
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(r2, inner_w)} {Color.GRAY}│{Color.RESET}")
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(r3, inner_w)} {Color.GRAY}│{Color.RESET}")
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(r4, inner_w)} {Color.GRAY}│{Color.RESET}")
        lines.append(f"{Color.GRAY}└{'─' * (BOX_WIDTH - 2)}┘{Color.RESET}")

    # 5. Alert Dialog (hidden while operation is actively progressing)
    if message and not progress_info:
        m_title, m_lines, m_succ = message
        clr = Color.RED if m_succ else Color.DARK_RED
        head_txt = f"╔══ {m_title} "
        top_bar = head_txt + "═" * max(0, BOX_WIDTH - 2 - visible_len(head_txt)) + "╗"
        lines.append(f"{clr}{top_bar}{Color.RESET}")
        for l in m_lines:
            content = f"  {Color.WHITE}{l}{Color.RESET}"
            lines.append(f"{clr}║{Color.RESET} {pad_box(content, inner_w)} {clr}║{Color.RESET}")
        lines.append(f"{clr}╚" + "═" * (BOX_WIDTH - 2) + f"╝{Color.RESET}")

    # 6. Directives Box OR Optimistic Progress Indicator
    if progress_info:
        p_title = progress_info.get("title", "EXECUTING DIRECTIVE")
        p_pct = max(0, min(100, int(progress_info.get("percent", 0))))
        p_status = progress_info.get("status", "Processing...")

        lines.append(f"{Color.GRAY}┌── OPERATION IN PROGRESS {'─' * max(0, BOX_WIDTH - 27)}┐{Color.RESET}")
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(f'  {Color.WHITE}{Color.BOLD}{p_title}{Color.RESET}', inner_w)} {Color.GRAY}│{Color.RESET}")
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box('', inner_w)} {Color.GRAY}│{Color.RESET}")

        bar_len = 46
        filled = int(bar_len * (p_pct / 100.0))
        unfilled = bar_len - filled
        bar_visual = f"{Color.RED}{'█' * filled}{Color.DARK_GRAY}{'░' * unfilled}{Color.RESET}"
        bar_line = f"   [{bar_visual}] {Color.WHITE}{Color.BOLD}{p_pct:3d}%{Color.RESET}"
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(bar_line, inner_w)} {Color.GRAY}│{Color.RESET}")

        status_line = f"   {Color.STEEL}► {p_status}{Color.RESET}"
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(status_line, inner_w)} {Color.GRAY}│{Color.RESET}")
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box('', inner_w)} {Color.GRAY}│{Color.RESET}")
        lines.append(f"{Color.GRAY}└{'─' * (BOX_WIDTH - 2)}┘{Color.RESET}")
    else:
        lines.append(f"{Color.GRAY}┌── REICH-COMMAND DIRECTIVES {'─' * (BOX_WIDTH - 30)}┐{Color.RESET}")
        for idx, (aid, title, _) in enumerate(menu_items):
            is_sel = (idx == selected_idx)
            if is_sel:
                item_text = f"  ►  [ {title} ]"
                lines.append(f"{Color.GRAY}│{Color.RESET} {Color.SEL_BAR}{pad_box(item_text, inner_w)}{Color.RESET} {Color.GRAY}│{Color.RESET}")
            else:
                item_text = f"     [ {title} ]"
                lines.append(f"{Color.GRAY}│{Color.RESET} {Color.STEEL}{pad_box(item_text, inner_w)}{Color.RESET} {Color.GRAY}│{Color.RESET}")

        cur_desc = f"  {menu_items[selected_idx][2]}"
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(f'{Color.WHITE}{cur_desc}{Color.RESET}', inner_w)} {Color.GRAY}│{Color.RESET}")

    # 7. Slogans
    lines.append(f"{Color.GRAY}├── REICHS-MANIFEST {'─' * (BOX_WIDTH - 21)}┤{Color.RESET}")
    slogans_count = 1 if (term_lines <= 26 or (term_lines <= 28 and update_info)) else (2 if term_lines < 34 else 3)
    for s in MANIFEST_SLOGANS[:slogans_count]:
        s_str = f"  {Color.RED}✠{Color.RESET}  {Color.WHITE}{s}{Color.RESET}"
        lines.append(f"{Color.GRAY}│{Color.RESET} {pad_box(s_str, inner_w)} {Color.GRAY}│{Color.RESET}")

    lines.append(f"{Color.GRAY}└{'─' * (BOX_WIDTH - 2)}┘{Color.RESET}")
    if progress_info:
        lines.append(f"{Color.GRAY}  Executing command... please stand by.{Color.RESET}")
    else:
        nav_help = "  ▲/▼ Navigate  •  [ENTER] Execute  •  [Q] Terminate"
        if update_info:
            nav_help = "  ▲/▼ Navigate  •  [U] Apply Update  •  [ENTER] Execute  •  [Q] Terminate"
        lines.append(f"{Color.GRAY}{nav_help}{Color.RESET}")

    return lines
