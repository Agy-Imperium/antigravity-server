#!/usr/bin/env python3
"""
build_dist.py - Build distribution archives (tar.gz and zip) for client delivery.
Generates clean antigravity-bypass-client.tar.gz and antigravity-bypass-client.zip
excluding bytecode caches (__pycache__) and unneeded artifacts.
Dynamically resolves and injects server host into client manifests.
Pure Python standard library (zero external dependencies).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:
    from antigravity_unlocker.common.discovery import get_server_public_ip
except ImportError:
    def get_server_public_ip() -> str:
        return "127.0.0.1"


def build_archives(server_host: Optional[str] = None) -> None:
    target_server = server_host or get_server_public_ip()
    print(f"Building client distribution packages from {PROJECT_ROOT} for server: {target_server}...")

    dist_dir = PROJECT_ROOT / "dist"
    dist_dir.mkdir(parents=True, exist_ok=True)

    tar_path = dist_dir / "antigravity-bypass-client.tar.gz"
    zip_path = dist_dir / "antigravity-bypass-client.zip"

    # Temporary staging directory
    staging_dir = PROJECT_ROOT / ".dist_staging"
    if staging_dir.exists():
        shutil.rmtree(staging_dir)
    staging_dir.mkdir(parents=True, exist_ok=True)

    pycache_filter = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".git*")

    # Copy client directory
    shutil.copytree(PROJECT_ROOT / "client", staging_dir / "client", dirs_exist_ok=True, ignore=pycache_filter)

    # Copy src package
    shutil.copytree(PROJECT_ROOT / "src", staging_dir / "src", dirs_exist_ok=True, ignore=pycache_filter)

    # Copy diagnostics if exists
    if (PROJECT_ROOT / "diagnostics").exists():
        shutil.copytree(PROJECT_ROOT / "diagnostics", staging_dir / "diagnostics", dirs_exist_ok=True, ignore=pycache_filter)

    # Copy root metadata and installers
    for fname in ["version.json", "install.sh", "install.ps1", "README.md", "QUICKSTART.md", "pyproject.toml"]:
        fpath = PROJECT_ROOT / fname
        if fpath.exists():
            shutil.copy2(fpath, staging_dir / fname)

    # Copy bin scripts if exists
    if (PROJECT_ROOT / "bin").exists():
        shutil.copytree(PROJECT_ROOT / "bin", staging_dir / "bin", dirs_exist_ok=True, ignore=pycache_filter)

    # Inject server_host.txt into client and staging root
    (staging_dir / "server_host.txt").write_text(f"{target_server}\n", encoding="utf-8")
    (staging_dir / "client" / "server_host.txt").write_text(f"{target_server}\n", encoding="utf-8")

    # Create tar.gz
    with tarfile.open(tar_path, "w:gz") as tar:
        for item in staging_dir.iterdir():
            tar.add(item, arcname=item.name)
    print(f"[+] Created {tar_path} ({tar_path.stat().st_size} bytes)")

    # Create zip
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(staging_dir):
            for file in files:
                abs_path = Path(root) / file
                rel_path = abs_path.relative_to(staging_dir)
                zf.write(abs_path, arcname=str(rel_path))
    print(f"[+] Created {zip_path} ({zip_path.stat().st_size} bytes)")

    def calc_sha256(filepath: Path) -> str:
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()

    tar_hash = calc_sha256(tar_path)
    zip_hash = calc_sha256(zip_path)
    (dist_dir / "antigravity-bypass-client.tar.gz.sha256").write_text(f"{tar_hash}  antigravity-bypass-client.tar.gz\n", encoding="utf-8")
    (dist_dir / "antigravity-bypass-client.zip.sha256").write_text(f"{zip_hash}  antigravity-bypass-client.zip\n", encoding="utf-8")
    print(f"[+] SHA256 (tar.gz): {tar_hash}")
    print(f"[+] SHA256 (zip):    {zip_hash}")

    for vj in [PROJECT_ROOT / "version.json", PROJECT_ROOT / "client" / "version.json"]:
        if vj.exists():
            try:
                vdata = json.loads(vj.read_text(encoding="utf-8"))
                vdata["sha256_tar"] = tar_hash
                vdata["sha256_zip"] = zip_hash
                if target_server and target_server != "127.0.0.1":
                    vdata["archive_tar"] = f"http://{target_server}/antigravity-bypass-client.tar.gz"
                    vdata["archive_zip"] = f"http://{target_server}/antigravity-bypass-client.zip"
                else:
                    vdata["archive_tar"] = "/antigravity-bypass-client.tar.gz"
                    vdata["archive_zip"] = "/antigravity-bypass-client.zip"
                vj.write_text(json.dumps(vdata, indent=2) + "\n", encoding="utf-8")
            except Exception as e:
                print(f"[!] Warning: failed updating {vj}: {e}")

    # Link / copy to root for legacy installer & test contract compatibility
    for p in [PROJECT_ROOT / "antigravity-bypass-client.tar.gz", PROJECT_ROOT / "client_bundle.tar.gz"]:
        if p.is_symlink() or p.exists():
            p.unlink()
        p.symlink_to(Path("dist/antigravity-bypass-client.tar.gz"))

    for p in [PROJECT_ROOT / "antigravity-bypass-client.zip", PROJECT_ROOT / "client_bundle.zip"]:
        if p.is_symlink() or p.exists():
            p.unlink()
        p.symlink_to(Path("dist/antigravity-bypass-client.zip"))

    # Deploy to web distribution portal if present and writable
    web_dist = Path("/var/www/antigravity-dist")
    if web_dist.exists() and os.access(web_dist, os.W_OK):
        def safe_web_copy(src: Path, dst: Path) -> None:
            try:
                shutil.copyfile(src, dst)
            except Exception as ex:
                print(f"[!] Warning: could not sync {src.name} to {dst}: {ex}")

        for p in [tar_path, zip_path]:
            safe_web_copy(p, web_dist / p.name)
        if (PROJECT_ROOT / "version.json").exists():
            safe_web_copy(PROJECT_ROOT / "version.json", web_dist / "version.json")

        sh_path = PROJECT_ROOT / "install.sh"
        if sh_path.exists():
            sh_content = sh_path.read_text(encoding="utf-8")
            if target_server:
                sh_content = re.sub(
                    r'SERVER="\$\{ANTIGRAVITY_SERVER_HOST:-\}"',
                    f'SERVER="${{ANTIGRAVITY_SERVER_HOST:-{target_server}}}"',
                    sh_content,
                )
            (web_dist / "install.sh").write_text(sh_content, encoding="utf-8")
            try:
                (web_dist / "install.sh").chmod(0o755)
            except Exception:
                pass

        ps_path = PROJECT_ROOT / "install.ps1"
        if ps_path.exists():
            ps_content = ps_path.read_text(encoding="utf-8")
            if target_server:
                ps_content = re.sub(
                    r'\[string\]\$Server = "",',
                    f'[string]$Server = "{target_server}",',
                    ps_content,
                )
            (web_dist / "install.ps1").write_text(ps_content, encoding="utf-8")
        print(f"[+] Synced artifacts to {web_dist}")

    # Clean up staging
    shutil.rmtree(staging_dir, ignore_errors=True)
    print("[+] Distribution packages built and linked successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Build Antigravity client distribution packages")
    parser.add_argument("--server-ip", "-s", default=None, help="Target server IP or domain for package injection")
    args = parser.parse_args()
    build_archives(server_host=args.server_ip)
