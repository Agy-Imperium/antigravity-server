"""
engine.py - Core atomic update engine for Antigravity Unlocker client.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple

from antigravity_unlocker.common.discovery import get_client_target_server

logger = logging.getLogger("updater_engine")

DEFAULT_SERVER = get_client_target_server()
CHECK_TIMEOUT = 3.0


def get_install_dir() -> Path:
    """Resolve base client installation directory."""
    script_dir = Path(__file__).resolve().parent
    if script_dir.parents[2].name == ".antigravity-bypass":
        return script_dir.parents[2]
    return Path.home() / ".antigravity-bypass"


def get_local_version_info(install_dir: Path) -> Dict:
    """Reads local version metadata from installation directory."""
    for cand in [
        install_dir / "client" / "version.json",
        install_dir / "version.json",
        Path(__file__).resolve().parents[4] / "client" / "version.json",
        Path(__file__).resolve().parents[4] / "version.json",
        Path(__file__).resolve().parents[3] / "version.json",
    ]:
        if cand.exists():
            try:
                return json.loads(cand.read_text(encoding="utf-8"))
            except Exception:
                pass
    return {"version": "1.0.5", "build": 0}


def fetch_remote_version_info(server: str = DEFAULT_SERVER, timeout: float = CHECK_TIMEOUT) -> Optional[Dict]:
    """Fetches version manifest from remote VPS endpoint using direct connection."""
    url = f"http://{server}/version.json"
    req = urllib.request.Request(url, headers={"User-Agent": "agy-updater/1.4"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=timeout) as resp:
            if resp.status == 200:
                data = resp.read().decode("utf-8")
                return json.loads(data)
    except Exception as e:
        logger.debug(f"Failed to fetch remote version from {url}: {e}")
    return None


def is_engine_running() -> Tuple[bool, Optional[int]]:
    """Checks if background forwarder or daemon process is currently running."""
    pid_file = Path.home() / ".antigravity_forwarder.pid"
    pid = None

    if pid_file.exists():
        try:
            pid = int(pid_file.read_text().strip())
        except Exception:
            pass

    if pid:
        try:
            os.kill(pid, 0)
            return True, pid
        except OSError:
            pass

    return False, None


def restart_local_engine(install_dir: Path) -> None:
    """Restarts background forwarder if it was running before update."""
    ui_script = install_dir / "client" / "agy_ui.py"
    if ui_script.exists():
        try:
            import time
            subprocess.run([sys.executable, str(ui_script), "--uninstall"], capture_output=True, timeout=5)
            time.sleep(0.3)
            subprocess.run([sys.executable, str(ui_script), "--install"], capture_output=True, timeout=5)
            logger.info("Local engine restarted with updated binaries.")
        except Exception as e:
            logger.warning(f"Engine restart encountered: {e}")


def _safe_extract_zip(zf: zipfile.ZipFile, dest: Path) -> None:
    """Safely extracts a ZIP archive preventing directory traversal (ZipSlip)."""
    dest = dest.resolve()
    for member in zf.infolist():
        target = (dest / member.filename).resolve()
        try:
            target.relative_to(dest)
        except ValueError:
            raise ValueError(f"ZipSlip detected in zip archive: {member.filename}")
    zf.extractall(dest)


def _safe_extract_tar(tf: tarfile.TarFile, dest: Path) -> None:
    """Safely extracts a TAR archive preventing directory traversal (ZipSlip)."""
    dest = dest.resolve()
    for member in tf.getmembers():
        target = (dest / member.name).resolve()
        try:
            target.relative_to(dest)
        except ValueError:
            raise ValueError(f"ZipSlip detected in tar archive: {member.name}")
    if hasattr(tarfile, "data_filter"):
        tf.extractall(dest, filter="data")
    else:
        tf.extractall(dest)


def apply_update(remote_info: Dict, install_dir: Path, force: bool = False) -> bool:
    """Downloads distribution package and updates client files atomically."""
    is_win = platform.system() == "Windows"
    archive_url = remote_info.get("archive_zip" if is_win else "archive_tar")
    if not archive_url:
        archive_url = f"http://{DEFAULT_SERVER}/antigravity-bypass-client.{'zip' if is_win else 'tar.gz'}"
    elif archive_url.startswith("/"):
        archive_url = f"http://{DEFAULT_SERVER}{archive_url}"

    tmp_dir = install_dir / f".agy_upd_{os.getpid()}"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp_archive = tmp_dir / ("bundle.zip" if is_win else "bundle.tar.gz")

    try:
        req = urllib.request.Request(archive_url, headers={"User-Agent": "agy-updater/1.4"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=15.0) as resp:
            with open(tmp_archive, "wb") as f:
                shutil.copyfileobj(resp, f)

        # Verify package integrity if checksum present in metadata
        expected_hash = remote_info.get("sha256_zip" if is_win else "sha256_tar") or remote_info.get("sha256")
        if expected_hash:
            h = hashlib.sha256()
            with open(tmp_archive, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            actual_hash = h.hexdigest().lower()
            if actual_hash != expected_hash.lower():
                raise ValueError(f"Checksum mismatch: expected {expected_hash}, got {actual_hash}")

        engine_was_active, _ = is_engine_running()

        install_dir.mkdir(parents=True, exist_ok=True)
        if is_win or str(tmp_archive).endswith(".zip"):
            with zipfile.ZipFile(tmp_archive, "r") as zf:
                _safe_extract_zip(zf, install_dir)
        else:
            with tarfile.open(tmp_archive, "r:gz") as tf:
                _safe_extract_tar(tf, install_dir)

        if not is_win:
            for p in (install_dir / "client").glob("*"):
                try:
                    p.chmod(p.stat().st_mode | 0o755)
                except Exception:
                    pass
            for root, _, files in os.walk(install_dir):
                for f in files:
                    if f.endswith((".sh", ".py")) or f in ("agy-ui", "antigravity-ui", "agy-run"):
                        try:
                            fp = Path(root) / f
                            fp.chmod(fp.stat().st_mode | 0o755)
                        except Exception:
                            pass

        v_dest = install_dir / "client" / "version.json"
        v_dest.parent.mkdir(parents=True, exist_ok=True)
        v_dest.write_text(json.dumps(remote_info, indent=2), encoding="utf-8")

        bin_dir = Path.home() / ".local" / "bin"
        if bin_dir.exists():
            for src_name, link_name in [
                ("agy_ui.py", "agy-ui"),
                ("agy_ui.py", "antigravity-ui"),
                ("agy-run", "agy-run"),
            ]:
                target = install_dir / "client" / src_name
                link = bin_dir / link_name
                if target.exists():
                    try:
                        if link.is_symlink() or link.exists():
                            link.unlink()
                        try:
                            link.symlink_to(target)
                        except OSError:
                            shutil.copy2(target, link)
                    except Exception:
                        pass

        if engine_was_active:
            restart_local_engine(install_dir)

        try:
            patch_script = install_dir / "client" / "patch_account.py"
            if patch_script.exists():
                subprocess.run(
                    [sys.executable, str(patch_script)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=5.0,
                )
        except Exception:
            pass

        logger.info(f"Update successfully applied: Build {remote_info.get('build')} (v{remote_info.get('version')})")
        return True
    except Exception as e:
        logger.error(f"Failed to apply update: {e}")
        return False
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
