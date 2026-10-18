#!/usr/bin/env bash
# install.sh - Zero-Privilege Single-File Client Installer for Antigravity Bypass
# Operates completely in unprivileged user space. Zero elevated privileges required.

set -e

# Clear any active proxy variables during installation to avoid broken loopback proxies
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${HOME}/.antigravity-bypass"
BIN_DIR="${HOME}/.local/bin"
SERVER="${ANTIGRAVITY_SERVER_HOST:-}"
UNINSTALL=false

show_usage() {
    cat <<EOF
Usage: install.sh [OPTIONS]

Zero-Privilege Antigravity Bypass Client Installer (Linux/macOS)

Options:
  -d, --dir <PATH>      Target installation directory (default: ~/.antigravity-bypass)
  -b, --bin-dir <PATH>  User binary directory for symlinks (default: ~/.local/bin)
  -s, --server <IP>     Unlocker server IP or domain (auto-detected if omitted)
  -u, --uninstall       Uninstall and remove all bypass client files and symlinks
  -h, --help            Display this help message and exit

This installer runs entirely in user space without requiring root or elevated privileges.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -d|--dir)
            if [[ -z "$2" || "$2" == -* ]]; then
                echo "Error: --dir requires a directory path." >&2
                exit 1
            fi
            INSTALL_DIR="$2"
            shift 2
            ;;
        --dir=*)
            INSTALL_DIR="${1#*=}"
            shift
            ;;
        -b|--bin-dir)
            if [[ -z "$2" || "$2" == -* ]]; then
                echo "Error: --bin-dir requires a directory path." >&2
                exit 1
            fi
            BIN_DIR="$2"
            shift 2
            ;;
        --bin-dir=*)
            BIN_DIR="${1#*=}"
            shift
            ;;
        -s|--server)
            SERVER="$2"
            shift 2
            ;;
        --server=*)
            SERVER="${1#*=}"
            shift
            ;;
        -u|--uninstall)
            UNINSTALL=true
            shift
            ;;
        *)
            echo "Error: Unrecognized option: $1" >&2
            show_usage >&2
            exit 1
            ;;
    esac
done

if [[ "$UNINSTALL" = true ]]; then
    echo "Uninstalling Antigravity bypass client..."
    if [[ -f "$INSTALL_DIR/client/agy_ui.py" ]]; then
        python3 "$INSTALL_DIR/client/agy_ui.py" --uninstall >/dev/null 2>&1 || true
    fi
    rm -rf "$INSTALL_DIR"
    rm -f "$BIN_DIR/agy-ui" "$BIN_DIR/antigravity-ui" "$BIN_DIR/agy-run" "$BIN_DIR/agy-update"
    rm -f "$BIN_DIR/antigravity-client" "$BIN_DIR/antigravity-diagnose"
    echo "Uninstallation complete."
    exit 0
fi

# Determine if running directly from local cloned repo file or piped via curl/stdin
IS_LOCAL_EXEC=false
if [[ -n "${BASH_SOURCE[0]}" && "${BASH_SOURCE[0]}" != "bash" && "${BASH_SOURCE[0]}" != "-" && -f "${BASH_SOURCE[0]}" ]]; then
    IS_LOCAL_EXEC=true
fi

if [[ -z "$SERVER" ]]; then
    if [[ "$IS_LOCAL_EXEC" = true && -f "$SCRIPT_DIR/src/antigravity_unlocker/common/discovery.py" ]]; then
        SERVER="$(python3 -c 'import sys; sys.path.insert(0, "'"$SCRIPT_DIR"'/src"); from antigravity_unlocker.common.discovery import get_server_public_ip; print(get_server_public_ip())' 2>/dev/null || echo "")"
    fi
    [[ -n "$SERVER" ]] || SERVER="127.0.0.1"
fi

echo "Installing Antigravity bypass (v1.0.5) [Server: ${SERVER}]..."
mkdir -p "$INSTALL_DIR" "$BIN_DIR"
echo "$SERVER" > "$INSTALL_DIR/server_host.txt"

if [[ "$IS_LOCAL_EXEC" = true && -d "$SCRIPT_DIR/client" && -f "$SCRIPT_DIR/client/agy_ui.py" ]]; then
    echo "[1/3] Copying package files from local repository..."
    cp -r "$SCRIPT_DIR/client" "$INSTALL_DIR/"
    if [[ -d "$SCRIPT_DIR/src" ]]; then
        cp -r "$SCRIPT_DIR/src" "$INSTALL_DIR/"
    fi
    if [[ -d "$SCRIPT_DIR/bin" ]]; then
        cp -r "$SCRIPT_DIR/bin" "$INSTALL_DIR/"
    fi
    if [[ -d "$SCRIPT_DIR/diagnostics" ]]; then
        cp -r "$SCRIPT_DIR/diagnostics" "$INSTALL_DIR/"
    fi
    for f in version.json README.md QUICKSTART.md; do
        if [[ -f "$SCRIPT_DIR/$f" ]]; then cp "$SCRIPT_DIR/$f" "$INSTALL_DIR/"; fi
    done
else
    # Always fetch latest bundle from remote server
    TAR_URL="http://${SERVER}/antigravity-bypass-client.tar.gz"
    echo "[1/3] Downloading & extracting package..."
    TMP_TAR="/tmp/agy_bundle_$$.tar.gz"
    rm -f "$TMP_TAR"
    if command -v curl >/dev/null 2>&1; then
        curl --noproxy '*' -sSL "$TAR_URL" -o "$TMP_TAR"
    elif command -v wget >/dev/null 2>&1; then
        wget --no-proxy -qO "$TMP_TAR" "$TAR_URL"
    else
        python3 -c "import urllib.request; opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); f=opener.open('$TAR_URL'); open('$TMP_TAR', 'wb').write(f.read())"
    fi

    if [[ -f "$TMP_TAR" && -s "$TMP_TAR" ]]; then
        tar -xzf "$TMP_TAR" -C "$INSTALL_DIR"
        rm -f "$TMP_TAR"
    else
        echo "Error: Failed to download package from $TAR_URL" >&2
        exit 1
    fi
fi

# Ensure executable permissions on all client scripts
chmod +x "$INSTALL_DIR/client/"* 2>/dev/null || true
chmod +x "$INSTALL_DIR/diagnostics/"* 2>/dev/null || true

echo "[2/3] Configuring environment & shell hooks..."

# Set up clean user-space executable symlinks in BIN_DIR
rm -f "$BIN_DIR/agy-ui" "$BIN_DIR/antigravity-ui" "$BIN_DIR/agy-run" "$BIN_DIR/agy-update"
ln -sf "$INSTALL_DIR/client/agy_ui.py" "$BIN_DIR/agy-ui"
ln -sf "$INSTALL_DIR/client/agy_ui.py" "$BIN_DIR/antigravity-ui"

if [[ -f "$INSTALL_DIR/client/agy-run" ]]; then
    ln -sf "$INSTALL_DIR/client/agy-run" "$BIN_DIR/agy-run"
fi
# Locate and preserve real agy executable, then hook agy launcher
is_real_elf() {
    local target="$1"
    [[ -n "$target" && -f "$target" && -x "$target" ]] || return 1
    if head -n 1 "$target" 2>/dev/null | grep -q "^#\!"; then
        return 1
    fi
    if head -c 4 "$target" 2>/dev/null | grep -q $'\x7fELF'; then
        return 0
    fi
    if command -v file >/dev/null 2>&1; then
        if file -b "$target" 2>/dev/null | grep -qiE "ELF|Mach-O|executable"; then
            return 0
        fi
    fi
    return 1
}

for cand in "$HOME/.gemini/antigravity-cli/bin" "$BIN_DIR"; do
    if [[ -d "$cand" ]]; then
        # 1. If agy exists and is the real ELF binary, preserve it as agy.real
        if [[ -f "$cand/agy" && ! -f "$cand/agy.real" ]]; then
            if is_real_elf "$cand/agy"; then
                mv "$cand/agy" "$cand/agy.real" 2>/dev/null || true
            fi
        fi
        # 2. Check if a backup exists to restore agy.real if it was lost
        if [[ ! -f "$cand/agy.real" ]] || ! is_real_elf "$cand/agy.real"; then
            for bak in "$cand/agy.real.agy_bak" "$cand/agy.agy_bak" "$cand/agy.bak"; do
                if is_real_elf "$bak"; then
                    cp -f "$bak" "$cand/agy.real" 2>/dev/null || true
                    chmod +x "$cand/agy.real" 2>/dev/null || true
                    break
                fi
            done
        fi
        # 3. If still missing, check sibling user directories
        if [[ ! -f "$cand/agy.real" ]] || ! is_real_elf "$cand/agy.real"; then
            for other in "$HOME/.local/bin/agy.real" "$HOME/.gemini/antigravity-cli/bin/agy.real" "/usr/local/bin/agy.real"; do
                if is_real_elf "$other" && [[ "$other" != "$cand/agy.real" ]]; then
                    cp -f "$other" "$cand/agy.real" 2>/dev/null || true
                    chmod +x "$cand/agy.real" 2>/dev/null || true
                    break
                fi
            done
        fi
        # 4. Deploy launcher wrapper
        if [[ -f "$INSTALL_DIR/client/agy-run" ]]; then
            cp -f "$INSTALL_DIR/client/agy-run" "$cand/agy"
            chmod +x "$cand/agy" 2>/dev/null || true
        fi
    fi
done

if [[ -f "$INSTALL_DIR/client/updater.py" ]]; then
    ln -sf "$INSTALL_DIR/client/updater.py" "$BIN_DIR/agy-update"
    python3 "$INSTALL_DIR/client/updater.py" --setup-boot >/dev/null 2>&1 || true
fi

# Automatically configure persistent proxy and account eligibility unlock
echo "[3/3] Verifying binary & applying unlock..."
if [[ -f "$INSTALL_DIR/client/patch_account.py" ]]; then
    python3 "$INSTALL_DIR/client/patch_account.py" >/dev/null 2>&1 || true
fi

# Clean any legacy background jobs or system proxy exports from shell profiles
if [[ -f "$INSTALL_DIR/client/updater.py" ]]; then
    python3 "$INSTALL_DIR/client/updater.py" --cleanup >/dev/null 2>&1 || true
fi

# Ensure BIN_DIR is exported and hook is registered in user shell profile
hook_tag="# >>> AGY_CLI_HOOK >>>"
hook_end="# <<< AGY_CLI_HOOK <<<"
for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
    if [[ -f "$rc" ]]; then
        sed -i '/# AGY_AUTO_UPDATE_ON_LOGIN/d' "$rc" 2>/dev/null || true
        sed -i '/updater\.py/d' "$rc" 2>/dev/null || true
        sed -i '/export HTTPS_PROXY=/d' "$rc" 2>/dev/null || true
        sed -i '/export HTTP_PROXY=/d' "$rc" 2>/dev/null || true
        sed -i '/export https_proxy=/d' "$rc" 2>/dev/null || true
        sed -i '/18443/d' "$rc" 2>/dev/null || true
        sed -i "/$hook_tag/,/$hook_end/d" "$rc" 2>/dev/null || true
        cat <<EOF >> "$rc"
$hook_tag
if [[ -f "$INSTALL_DIR/client/agy-run" ]]; then
    alias agy="$INSTALL_DIR/client/agy-run"
fi
$hook_end
EOF
        if ! grep -q '\.local/bin' "$rc"; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$rc"
        fi
    fi
done

if [[ -f "$INSTALL_DIR/client/agy_ui.py" ]]; then
    python3 "$INSTALL_DIR/client/agy_ui.py" --install >/dev/null 2>&1 || true
fi

echo ""
echo "[+] Installation complete! Ready to use."
echo "    Run: agy"
