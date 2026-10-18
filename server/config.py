"""
config.py - Central Configuration for Antigravity Zero-Privilege Unlocker Server (Facade)
Re-exports from antigravity_unlocker.common.config for backward compatibility.
"""

import sys
from pathlib import Path

_src_dir = Path(__file__).resolve().parent.parent / "src"
if _src_dir.exists() and str(_src_dir) not in sys.path:
    sys.path.insert(0, str(_src_dir))

from antigravity_unlocker.common.config import *
