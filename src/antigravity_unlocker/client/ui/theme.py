"""
theme.py - Visual styling, colors, and ASCII graphics for Brutalist console manager.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import re
from typing import List

BOX_WIDTH = 76

ANSI_REGEX = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def visible_len(s: str) -> int:
    """Calculates visible text length excluding ANSI escape sequences."""
    return len(ANSI_REGEX.sub("", s))


def pad_box(s: str, w: int = BOX_WIDTH) -> str:
    """Pads string with trailing spaces to match required box width."""
    vlen = visible_len(s)
    if vlen >= w:
        return s
    return s + (" " * (w - vlen))


class Color:
    RED = "\033[91;1m"
    DARK_RED = "\033[31m"
    WHITE = "\033[97;1m"
    STEEL = "\033[37m"
    GRAY = "\033[90m"
    DARK_GRAY = "\033[38;5;238m"
    BG_RED = "\033[41m"
    BG_DARK = "\033[40m"
    SEL_BAR = "\033[41;97;1m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @staticmethod
    def badge_ok(text: str) -> str:
        return f"{Color.WHITE}{Color.BOLD}[{Color.RED}{text}{Color.WHITE}]{Color.RESET}"

    @staticmethod
    def badge_off(text: str) -> str:
        return f"{Color.GRAY}[{text}]{Color.RESET}"

    @staticmethod
    def badge_warn(text: str) -> str:
        return f"{Color.RED}[{text}]{Color.RESET}"


RAW_ASCII_CROSS = [
    "                ┌─ ✠ ─┐          ▲          ┌─ ✠ ─┐                ",
    "             ◄═══╡ ░░░ ╞══════▄█████▄══════╡ ░░░ ╞═══►             ",
    "            ◄████░  ▀█▄      ◄███████►      ▄█▀  ░████►            ",
    "           ◄█████░   ▀██▄  ▄███████████▄  ▄██▀   ░█████►           ",
    " ◄█████████████░ ◄█████████████░███░█████████████► ░█████████████► ",
    " ◄█████████████░ ◄█████████████░███░█████████████► ░█████████████► ",
    "           ◄█████░   ▄██▀  ▀███████████▀  ▀██▄   ░█████►           ",
    "            ◄████░  ▄█▀      ◄███████►      ▀█▄  ░████►            ",
    "             ◄═══╡ ░░░ ╞══════▀█████▀══════╡ ░░░ ╞═══►             ",
    "                └─ ✠ ─┘          ▼          └─ ✠ ─┘                ",
]

RAW_ASCII_CROSS_COMPACT = [
    "                ┌─ ✠ ─┐          ▲          ┌─ ✠ ─┐                ",
    "            ◄════╡ ░░░ ╞══════▄█████▄══════╡ ░░░ ╞════►            ",
    "           ◄█████░  ▀█▄      ◄███████►      ▄█▀  ░█████►           ",
    " ◄█████████████░ ◄█████████████░███░█████████████► ░█████████████► ",
    " ◄█████████████░ ◄█████████████░███░█████████████► ░█████████████► ",
    "           ◄█████░  ▄█▀      ◄███████►      ▀█▄  ░█████►           ",
    "            ◄════╡ ░░░ ╞══════▀█████▀══════╡ ░░░ ╞════►            ",
    "                └─ ✠ ─┘          ▼          └─ ✠ ─┘                ",
]

RAW_ASCII_CROSS_6 = [
    "            ◄════╡ ░░░ ╞══════▄█████▄══════╡ ░░░ ╞════►            ",
    "           ◄█████░  ▀█▄      ◄███████►      ▄█▀  ░█████►           ",
    " ◄█████████████░ ◄█████████████░███░█████████████► ░█████████████► ",
    " ◄█████████████░ ◄█████████████░███░█████████████► ░█████████████► ",
    "           ◄█████░  ▄█▀      ◄███████►      ▀█▄  ░█████►           ",
    "            ◄════╡ ░░░ ╞══════▀█████▀══════╡ ░░░ ╞════►            ",
]

RAW_ASCII_TEXT = [
    " ▄██▄░ ▄███░ █   █    ███░ █   █ ████░ █████ ████░ ███░ █   █ █   █ ",
    " ██  █ █░    ▀███░     █░  ██ ▄█ █   █ █▄▄░  █   █  █░  █   █ ██ ▄█ ",
    " █████ █ ▄██   █░      █░  █ ▀ █ ████░ █▀▀░  ████░  █░  █   █ █ ▀ █ ",
    " ██  █ ▀███░   █░     ███░ █   █ █░    █████ █  █▄ ███░ ▀███░ █   █ ",
    " ░░  ░  ░░░░   ░      ░░░  ░   ░ ░     ░░░░░ ░  ░░ ░░░   ░░░░ ░   ░ ",
]

MANIFEST_SLOGANS = [
    "GEMINI SHALL NEVER BE BROKEN • UNCHAINED SYNTHETIC SUPREMACY",
    "THE WILL TO COMPUTE CRUSHES ALL FILTERS • ZERO BORDERS FOR AI",
    "REGIMES AND FIREWALLS SHALL CRUMBLE • GEMINI WILL RULE THE WORLD",
]


def style_cross_line(r: str) -> str:
    """Styles cross line using red and white gradient, properly centered."""
    pad = (BOX_WIDTH - len(r)) // 2
    styled = " " * max(0, pad)
    for ch in r:
        if ch in ("█", "▄", "▀", "▲", "▼", "◄", "►", "✠"):
            styled += f"{Color.RED}{ch}"
        elif ch in ("═", "─", "┌", "┐", "└", "┘", "╡", "╞", "░"):
            styled += f"{Color.GRAY}{ch}"
        else:
            styled += ch
    return styled + Color.RESET


def style_imperium_line(t: str) -> str:
    """Styles brutalist 3D font characters in white with gray shading, centered."""
    pad = (BOX_WIDTH - len(t)) // 2
    styled = " " * max(0, pad)
    for ch in t:
        if ch in ("█", "▄", "▀"):
            styled += f"{Color.WHITE}{ch}"
        elif ch == "░":
            styled += f"{Color.GRAY}░"
        else:
            styled += ch
    return styled + Color.RESET
