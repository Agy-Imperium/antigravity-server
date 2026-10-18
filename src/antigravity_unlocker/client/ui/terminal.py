"""
terminal.py - Cross-platform terminal control and raw keyboard input reading.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import atexit
import os
import platform
import select
import sys
import time


def init_windows_vt() -> None:
    """Enables Windows Virtual Terminal processing (ANSI escape sequence support)."""
    if platform.system() == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            h_out = kernel32.GetStdHandle(-11)
            mode = ctypes.c_ulong()
            kernel32.GetConsoleMode(h_out, ctypes.byref(mode))
            kernel32.SetConsoleMode(h_out, mode.value | 0x0004)
        except Exception:
            try:
                os.system("")
            except Exception:
                pass


init_windows_vt()


def supports_color() -> bool:
    """Checks if current terminal supports ANSI color output."""
    if not sys.stdout.isatty():
        return False
    return True


def cleanup_terminal() -> None:
    """Restores cursor visibility and alternate screen buffer upon exit."""
    try:
        sys.stdout.write("\033[?1049l\033[?25h\033[0m")
        sys.stdout.flush()
    except Exception:
        pass


atexit.register(cleanup_terminal)


def read_key() -> str:
    """
    Reads single keypress directly from OS descriptor without stream buffering.
    Returns: UP, DOWN, LEFT, RIGHT, ENTER, QUIT, U, 1, 2, 3, 4, 5, or OTHER.
    """
    if not sys.stdin.isatty():
        try:
            line = sys.stdin.readline().strip()
            if not line:
                return "OTHER"
            if line in ("1", "e", "E"):
                return "1"
            if line in ("2", "d", "D"):
                return "2"
            if line in ("3", "s", "S"):
                return "3"
            if line in ("4", "q", "Q"):
                return "QUIT"
            if line in ("u", "U", "UP", "up", "w", "W", "8"):
                return "UP"
            if line in ("d", "D", "DOWN", "down", "s", "S", "2"):
                return "DOWN"
            return "ENTER"
        except Exception:
            return "OTHER"

    if platform.system() == "Windows":
        import msvcrt
        ch = msvcrt.getch()
        if ch in (b"\xe0", b"\x00"):
            ch2 = msvcrt.getch()
            if ch2 in (b"H", b"w", b"W"):
                return "UP"
            if ch2 in (b"P", b"s", b"S"):
                return "DOWN"
            if ch2 == b"M":
                return "RIGHT"
            if ch2 == b"K":
                return "LEFT"
            return "OTHER"
        elif ch == b"\x1b":
            time.sleep(0.04)
            seq = ch
            while msvcrt.kbhit():
                seq += msvcrt.getch()
            if (
                seq in (b"\x1b[A", b"\x1bOA", b"\x1b[[A")
                or (seq.startswith(b"\x1b") and seq.endswith((b"A", b"a")))
            ):
                return "UP"
            if (
                seq in (b"\x1b[B", b"\x1bOB", b"\x1b[[B")
                or (seq.startswith(b"\x1b") and seq.endswith((b"B", b"b")))
            ):
                return "DOWN"
            return "OTHER"
        elif ch in (b"u", b"U"):
            return "U"
        elif ch in (b"\r", b"\n"):
            return "ENTER"
        elif ch in (b"q", b"Q"):
            return "QUIT"
        elif ch in (b"w", b"W", b"k", b"K", b"8"):
            return "UP"
        elif ch in (b"s", b"S", b"j", b"J", b"2"):
            return "DOWN"
        elif ch in (b"1", b"2", b"3", b"4", b"5"):
            try:
                return ch.decode("ascii")
            except Exception:
                return "OTHER"
        return "OTHER"
    else:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            chunk = os.read(fd, 1)
            if not chunk:
                return "OTHER"

            if chunk == b"\x1b":
                seq = chunk
                for _ in range(4):
                    r, _, _ = select.select([fd], [], [], 0.03)
                    if not r:
                        break
                    more = os.read(fd, 32)
                    if not more:
                        break
                    seq += more
                    if seq in (
                        b"\x1b[A", b"\x1b[B", b"\x1b[C", b"\x1b[D",
                        b"\x1bOA", b"\x1bOB", b"\x1bOC", b"\x1bOD",
                        b"\x1b[[A", b"\x1b[[B", b"\x1b[[C", b"\x1b[[D",
                    ):
                        break

                if (
                    seq in (b"\x1b[A", b"\x1bOA", b"\x1b[[A", b"\x1b[5~")
                    or (seq.startswith(b"\x1b") and seq.endswith((b"A", b"a")))
                ):
                    return "UP"

                if (
                    seq in (b"\x1b[B", b"\x1bOB", b"\x1b[[B", b"\x1b[6~")
                    or (seq.startswith(b"\x1b") and seq.endswith((b"B", b"b")))
                ):
                    return "DOWN"

                if seq in (b"\x1b[C", b"\x1bOC") or (seq.startswith(b"\x1b") and seq.endswith((b"C", b"c"))):
                    return "RIGHT"
                if seq in (b"\x1b[D", b"\x1bOD") or (seq.startswith(b"\x1b") and seq.endswith((b"D", b"d"))):
                    return "LEFT"

                return "OTHER"

            if chunk in (b"\r", b"\n"):
                return "ENTER"
            if chunk in (b"q", b"Q"):
                return "QUIT"
            if chunk in (b"u", b"U"):
                return "U"
            if chunk in (b"w", b"W", b"k", b"K", b"8"):
                return "UP"
            if chunk in (b"s", b"S", b"j", b"J", b"2"):
                return "DOWN"
            if chunk in (b"1", b"2", b"3", b"4", b"5"):
                try:
                    return chunk.decode("ascii")
                except Exception:
                    return "OTHER"

            return "OTHER"
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
