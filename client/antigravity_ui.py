#!/usr/bin/env python3
"""
antigravity_ui.py - Backward compatibility shim for agy_ui.py
Delegates directly to canonical agy_ui.py implementation.
"""

import sys
from pathlib import Path

_client_dir = Path(__file__).resolve().parent
if str(_client_dir) not in sys.path:
    sys.path.insert(0, str(_client_dir))

import agy_ui

if __name__ == "__main__":
    agy_ui.main()
