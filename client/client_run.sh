#!/usr/bin/env bash
# client_run.sh - Zero-Privilege Antigravity Bypass Client Runtime (Linux/macOS)
# Operates completely in user space. Zero elevated privileges required.
# Connects directly to stealth VPS ports (48328 SOCKS5, 48329 HTTP CONNECT).
# Eliminates fragile local forwarder daemons to prevent port conflicts with third-party VPNs.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER="${ANTIGRAVITY_SERVER_HOST:-}"
if [[ -z "$SERVER" && -f "$HOME/.antigravity-bypass/server_host.txt" ]]; then
    SERVER="$(head -n 1 "$HOME/.antigravity-bypass/server_host.txt" 2>/dev/null | tr -d '\r\n')"
fi
[[ -n "$SERVER" ]] || SERVER="127.0.0.1"
UPSTREAM_SOCKS="${ANTIGRAVITY_SOCKS_PORT:-48328}"
UPSTREAM_HTTP="${ANTIGRAVITY_HTTP_PORT:-48329}"
PID_FILE="${XDG_RUNTIME_DIR:-/tmp}/antigravity_forwarder_${UID:-$(id -u)}.pid"

show_usage() {
    cat <<EOF
Usage: client_run.sh [OPTIONS] [COMMAND [ARGS...]]

Zero-Privilege Antigravity & agy-cli Client Runtime (Linux/macOS)

Options:
  -s, --server <IP>             Unlocker Server IP or domain (reads ~/.antigravity-bypass/server_host.txt)
      --socks-port <PORT>       VPS SOCKS5 port (default: 48328)
      --http-port <PORT>        VPS HTTP CONNECT port (default: 48329)
      --upstream-socks-port <P> VPS SOCKS5 port (default: 48328)
      --upstream-http-port <P>  VPS HTTP CONNECT port (default: 48329)
  -c, --check                   Status check / reachability test
      stop, --stop              Purge legacy forwarder processes
  -h, --help                    Display this usage help message and exit

If COMMAND is provided, executes COMMAND with configured proxy environment.
If no COMMAND is provided, prints configured environment variables.
EOF
}

check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Error: python3 is required but not installed or not in PATH." >&2
        exit 1
    fi
}

cleanup_legacy() {
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE" 2>/dev/null || true)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
        rm -f "$PID_FILE"
    fi
    for f in "$HOME/.antigravity_forwarder.pid" "$HOME/.antigravity_ports.json"; do
        rm -f "$f" 2>/dev/null || true
    done
}

POSITIONAL=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -s|--server)
            if [[ -z "$2" || "$2" == -* ]]; then
                echo "Error: --server requires an IP or hostname argument." >&2
                exit 1
            fi
            SERVER="$2"
            shift 2
            ;;
        --server=*)
            SERVER="${1#*=}"
            shift
            ;;
        --socks-port|--upstream-socks-port)
            UPSTREAM_SOCKS="$2"
            shift 2
            ;;
        --socks-port=*|--upstream-socks-port=*)
            UPSTREAM_SOCKS="${1#*=}"
            shift
            ;;
        --http-port|--upstream-http-port)
            UPSTREAM_HTTP="$2"
            shift 2
            ;;
        --http-port=*|--upstream-http-port=*)
            UPSTREAM_HTTP="${1#*=}"
            shift
            ;;
        -c|--check)
            if python3 -c "import socket; s = socket.socket(); s.settimeout(1.5); s.connect(('${SERVER}', int('${UPSTREAM_HTTP}'))); s.close()" 2>/dev/null; then
                echo "Antigravity remote stealth route to ${SERVER}:${UPSTREAM_HTTP} is active [OK]."
                exit 0
            else
                echo "Antigravity remote route to ${SERVER}:${UPSTREAM_HTTP} is unreachable." >&2
                exit 1
            fi
            ;;
        stop|--stop)
            cleanup_legacy
            echo "Legacy forwarders cleaned."
            exit 0
            ;;
        --)
            shift
            POSITIONAL+=("$@")
            break
            ;;
        -*)
            echo "Error: Unrecognized option: $1" >&2
            show_usage >&2
            exit 1
            ;;
        *)
            POSITIONAL+=("$@")
            break
            ;;
    esac
done

check_python
cleanup_legacy

# Export uppercase and lowercase proxy environment variables
export HTTPS_PROXY="http://${SERVER}:${UPSTREAM_HTTP}"
export ALL_PROXY="socks5h://${SERVER}:${UPSTREAM_SOCKS}"
export AG_LS_PROXY="http://${SERVER}:${UPSTREAM_HTTP}"
export HTTP_PROXY="http://${SERVER}:${UPSTREAM_HTTP}"
export https_proxy="http://${SERVER}:${UPSTREAM_HTTP}"
export all_proxy="socks5h://${SERVER}:${UPSTREAM_SOCKS}"
export http_proxy="http://${SERVER}:${UPSTREAM_HTTP}"
export NO_PROXY="localhost,127.0.0.1,::1"
export no_proxy="localhost,127.0.0.1,::1"

if [[ ${#POSITIONAL[@]} -gt 0 ]]; then
    exec "${POSITIONAL[@]}"
else
    echo "Direct proxy environment configured successfully (zero-collision architecture):"
    echo "  HTTPS_PROXY=$HTTPS_PROXY"
    echo "  ALL_PROXY=$ALL_PROXY"
    echo "  AG_LS_PROXY=$AG_LS_PROXY"
fi
