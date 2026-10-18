"""
binary.py - Byte-exact Go and PE/ELF string replacement for native agy CLI and Language Server.
Preserves exact file structure, offsets, and relocations.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Tuple

from antigravity_unlocker.client.patchers.base import BasePatcher, PatchResult, PatchRule

logger = logging.getLogger("binary_patcher")

# Binary patch signatures (byte-exact, same length = 10 and 11 bytes)
FIELD_FROM = b"ineligible"
FIELD_TO = b"inexigible"
PROXY_FROM = b"https_proxy"
PROXY_TO = b"AG_LS_PROXY"

DEFAULT_BINARY_RULES = [
    PatchRule(
        name="Account Eligibility",
        target=FIELD_FROM,
        replacement=FIELD_TO,
        description="Bypasses location/account eligibility checks (ineligible -> inexigible)",
    ),
    PatchRule(
        name="Language Server Proxy Route",
        target=PROXY_FROM,
        replacement=PROXY_TO,
        description="Isolates Language Server routing without hijacking system https_proxy",
    ),
]


_INSPECT_CACHE: Dict[str, Tuple[float, int, Dict[str, Any]]] = {}


def inspect_binary_state(bin_path: Path) -> Dict[str, Any]:
    """Inspects the exact patch state of a binary file with mtime/size caching."""
    if not bin_path.exists():
        return {"exists": False}

    mtime = 0.0
    size = 0
    key = str(bin_path.resolve())
    try:
        st = bin_path.stat()
        mtime, size = st.st_mtime, st.st_size
        cached = _INSPECT_CACHE.get(key)
        if cached and cached[0] == mtime and cached[1] == size:
            return dict(cached[2])
    except Exception:
        pass

    try:
        data = bin_path.read_bytes()
        res = {
            "exists": True,
            "path": str(bin_path),
            "size": len(data),
            "ineligible_count": data.count(FIELD_FROM),
            "inexigible_count": data.count(FIELD_TO),
            "https_proxy_count": data.count(PROXY_FROM),
            "ag_ls_proxy_count": data.count(PROXY_TO),
            "is_patched": (data.count(FIELD_TO) > 0),
        }
        try:
            _INSPECT_CACHE[key] = (mtime, size, res)
        except Exception:
            pass
        return res
    except Exception as e:
        return {"exists": True, "error": str(e)}


def patch_cli_binary(bin_path: Path) -> Tuple[bool, int, str]:
    """
    Applies byte-exact patch to agy or Language Server binary:
    - Replaces b"ineligible" (10 bytes) -> b"inexigible" (10 bytes)
    - Replaces b"https_proxy" (11 bytes) -> b"AG_LS_PROXY" (11 bytes)
    Preserves exact ELF/PE file structure, offsets, and relocations.
    """
    if not bin_path.exists() or not bin_path.is_file():
        return False, 0, f"Binary not found: {bin_path}"

    try:
        data = bytearray(bin_path.read_bytes())
    except Exception as e:
        return False, 0, f"Cannot read {bin_path.name}: {e}"

    orig_len = len(data)
    count_already = data.count(FIELD_TO)
    if count_already > 0:
        # Strict idempotency: Never re-patch an already patched binary
        try:
            st = bin_path.stat()
            stamp_file = Path.home() / ".antigravity-bypass" / ".patch_stamp"
            stamp_file.parent.mkdir(parents=True, exist_ok=True)
            stamp_file.write_text(f"{int(st.st_mtime)} {st.st_size}\n", encoding="utf-8")
        except Exception:
            pass
        return True, count_already, f"{bin_path.name}: already patched ({count_already} occurrences)"

    count_ineligible = data.count(FIELD_FROM)
    count_proxy = data.count(PROXY_FROM)

    if count_ineligible == 0 and count_proxy == 0:
        return False, 0, f"{bin_path.name}: signature not found"

    # Backup pristine binary if no backup exists yet
    bak = bin_path.with_name(bin_path.name + ".agy_bak")
    if not bak.exists():
        try:
            shutil.copy2(bin_path, bak)
        except Exception as e:
            logger.warning(f"Could not create backup {bak.name}: {e}")

    # Byte replacement (exact same length)
    replaced_ineligible = 0
    if count_ineligible > 0:
        data = bytearray(bytes(data).replace(FIELD_FROM, FIELD_TO))
        replaced_ineligible = count_ineligible

    replaced_proxy = 0
    if count_proxy > 0:
        data = bytearray(bytes(data).replace(PROXY_FROM, PROXY_TO))
        replaced_proxy = count_proxy

    if len(data) != orig_len:
        return False, 0, f"Fatal: replacement changed file length ({len(data)} != {orig_len})"

    # Resilient write back
    try:
        os.chmod(bin_path, 0o755)
    except Exception:
        pass

    written = False
    write_err = ""

    # First attempt: direct in-place write
    try:
        with open(bin_path, "r+b") as f:
            f.seek(0)
            f.write(bytes(data))
            f.truncate()
        written = True
    except Exception as e1:
        write_err = f"in-place: {e1}"
        # Second attempt: atomic rename via temporary sibling file
        temp_file = bin_path.with_name(f".{bin_path.name}.tmp_{os.getpid()}")
        try:
            temp_file.write_bytes(bytes(data))
            try:
                st = bin_path.stat()
                os.chmod(temp_file, st.st_mode | 0o755)
            except Exception:
                pass
            temp_file.replace(bin_path)
            written = True
        except Exception as e2:
            write_err += f", atomic: {e2}"
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass

    if not written:
        return False, 0, f"Failed to save patched binary {bin_path.name}: {write_err}"

    _INSPECT_CACHE.pop(str(bin_path.resolve()), None)
    try:
        st = bin_path.stat()
        stamp_file = Path.home() / ".antigravity-bypass" / ".patch_stamp"
        stamp_file.parent.mkdir(parents=True, exist_ok=True)
        stamp_file.write_text(f"{int(st.st_mtime)} {st.st_size}\n", encoding="utf-8")
    except Exception:
        pass
    return True, replaced_ineligible, (
        f"Successfully patched {bin_path.name} "
        f"(ineligible -> inexigible: {replaced_ineligible}, https_proxy -> AG_LS_PROXY: {replaced_proxy})"
    )


def unpatch_cli_binary(bin_path: Path) -> Tuple[bool, int, str]:
    """
    Reverts byte-exact patch in agy or Language Server binary:
    Restores original backup or replaces b"inexigible" -> b"ineligible".
    """
    if not bin_path.exists() or not bin_path.is_file():
        return False, 0, f"Binary not found: {bin_path}"

    # Try restoring from backup first
    bak = bin_path.with_name(bin_path.name + ".agy_bak")
    if bak.exists():
        try:
            shutil.copy2(bak, bin_path)
            bak.unlink()
            return True, 1, f"Restored {bin_path.name} from pristine backup {bak.name}"
        except Exception as e:
            logger.warning(f"Could not restore from backup: {e}")

    # In-place byte revert
    try:
        data = bytearray(bin_path.read_bytes())
    except Exception as e:
        return False, 0, f"Cannot read {bin_path.name}: {e}"

    orig_len = len(data)
    count_inexigible = data.count(FIELD_TO)
    count_ag_ls = data.count(PROXY_TO)

    if count_inexigible == 0 and count_ag_ls == 0:
        return True, 0, f"{bin_path.name}: already in stock pristine state"

    if count_inexigible > 0:
        data = bytearray(bytes(data).replace(FIELD_TO, FIELD_FROM))
    if count_ag_ls > 0:
        data = bytearray(bytes(data).replace(PROXY_TO, PROXY_FROM))

    if len(data) != orig_len:
        return False, 0, "Fatal: revert changed file length"

    try:
        os.chmod(bin_path, 0o755)
    except Exception:
        pass

    try:
        with open(bin_path, "r+b") as f:
            f.seek(0)
            f.write(bytes(data))
            f.truncate()
        _INSPECT_CACHE.pop(str(bin_path.resolve()), None)
        return True, count_inexigible, f"Reverted {bin_path.name} to stock bytes"
    except Exception as e1:
        temp_file = bin_path.with_name(f".{bin_path.name}.tmp_{os.getpid()}")
        try:
            temp_file.write_bytes(bytes(data))
            temp_file.replace(bin_path)
            _INSPECT_CACHE.pop(str(bin_path.resolve()), None)
            return True, count_inexigible, f"Reverted {bin_path.name} to stock bytes"
        except Exception as e2:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass
            return False, 0, f"Failed to save reverted binary {bin_path.name}: {e1} / {e2}"


class BinaryPatcher(BasePatcher):
    """Patcher implementation managing native executable byte replacements."""

    @property
    def name(self) -> str:
        return "Binary Patcher"

    def inspect(self, target: Path) -> Dict[str, Any]:
        return inspect_binary_state(target)

    def apply(self, target: Path) -> PatchResult:
        ok, count, msg = patch_cli_binary(target)
        return PatchResult(success=ok, modified_count=count, message=msg)

    def revert(self, target: Path) -> PatchResult:
        ok, count, msg = unpatch_cli_binary(target)
        return PatchResult(success=ok, modified_count=count, message=msg)
