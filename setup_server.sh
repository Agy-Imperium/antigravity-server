#!/usr/bin/env bash
# setup_server.sh - Universal Automated Server Setup for Antigravity Unlocker
# Enables deploying the Antigravity Unlocker server daemon on ANY Linux VPS (Ubuntu, Debian, CentOS, AlmaLinux, etc.)
# Automatically detects public IP, sets up systemd services, builds client packages, and exposes web downloads.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_IP=""
SERVER_PORT=48329
WEB_DIR="/var/www/antigravity-dist"

show_usage() {
    cat <<EOF
Usage: ./setup_server.sh [OPTIONS]

Universal Antigravity Unlocker Server Setup Script

Options:
  -i, --ip, --host <IP/DOMAIN>  Public IP or domain of this server (auto-detected if omitted)
  -p, --port <PORT>             HTTP Proxy upstream port (default: 48329)
  -w, --web-dir <PATH>          Client distribution download directory (default: /var/www/antigravity-dist)
  -h, --help                    Display this help message and exit

EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_usage
            exit 0
            ;;
        -i|--ip|--host)
            SERVER_IP="$2"
            shift 2
            ;;
        --ip=*|--host=*)
            SERVER_IP="${1#*=}"
            shift
            ;;
        -p|--port)
            SERVER_PORT="$2"
            shift 2
            ;;
        -w|--web-dir)
            WEB_DIR="$2"
            shift 2
            ;;
        *)
            echo "Error: Unrecognized option: $1" >&2
            show_usage >&2
            exit 1
            ;;
    esac
done

echo "========================================================================"
echo "  ANTIGRAVITY UNLOCKER SERVER — UNIVERSAL SETUP"
echo "========================================================================"

# 1. Resolve Server Public IP
if [[ -z "$SERVER_IP" ]]; then
    echo "[*] Auto-detecting server public IP..."
    if command -v python3 >/dev/null 2>&1; then
        SERVER_IP="$(python3 -c 'import sys; sys.path.insert(0, "'"$SCRIPT_DIR"'/src"); from antigravity_unlocker.common.discovery import get_server_public_ip; print(get_server_public_ip())' 2>/dev/null || echo "")"
    fi
    if [[ -z "$SERVER_IP" || "$SERVER_IP" == "127.0.0.1" ]]; then
        SERVER_IP="$(curl -s --max-time 2 https://api.ipify.org 2>/dev/null || curl -s --max-time 2 https://icanhazip.com 2>/dev/null || echo "")"
    fi
fi

if [[ -z "$SERVER_IP" || "$SERVER_IP" == "127.0.0.1" ]]; then
    read -r -p "Enter this server's public IP or domain: " SERVER_IP
fi

echo "[+] Server Public Host: $SERVER_IP"

# 2. Check Python 3 and basic tools
if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] Python 3 is required. Please install python3 (e.g. apt update && apt install -y python3)."
    exit 1
fi

# 3. Create persistent server config directory and save server_ip.txt
CONFIG_DIR="/etc/antigravity"
if [[ -w "/etc" ]]; then
    mkdir -p "$CONFIG_DIR"
    echo "SERVER_IP=${SERVER_IP}" > "$CONFIG_DIR/server.conf"
    echo "${SERVER_IP}" > "$CONFIG_DIR/server_ip.txt"
    echo "[+] Saved server configuration to $CONFIG_DIR/server.conf"
else
    echo "${SERVER_IP}" > "$SCRIPT_DIR/server_ip.txt"
    echo "[+] Saved server configuration to $SCRIPT_DIR/server_ip.txt"
fi

# 4. Create Web Distribution Directory
if [[ -w "/var/www" || -d "$WEB_DIR" && -w "$WEB_DIR" ]]; then
    mkdir -p "$WEB_DIR"
fi

# 5. Build distribution packages with injected server host
echo "[*] Building client distribution packages for ${SERVER_IP}..."
python3 "$SCRIPT_DIR/scripts/build_dist.py" --server-ip "$SERVER_IP"

# 6. Configure Systemd Services if running with sudo / root
if [[ $EUID -eq 0 && -d "/etc/systemd/system" ]]; then
    echo "[*] Configuring systemd services..."
    
    # Create antigravity system user if missing
    if ! id -u antigravity >/dev/null 2>&1; then
        useradd -r -s /usr/sbin/nologin antigravity 2>/dev/null || true
    fi

    # Deploy antigravity-unlocker.service
    cat <<EOF > /etc/systemd/system/antigravity-unlocker.service
[Unit]
Description=Antigravity Zero-Privilege Unlocker Daemon
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $SCRIPT_DIR/server/unlocker_daemon.py
WorkingDirectory=$SCRIPT_DIR/server
Restart=always
RestartSec=3
KillMode=mixed
TimeoutStopSec=10
LimitNOFILE=65536
Environment=PYTHONUNBUFFERED=1
Environment=UNLOCKER_SERVER_HOST=$SERVER_IP

# Ambient capabilities to allow binding port 53 (DNS) if needed
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF

    # Deploy antigravity-dl.service (HTTP download portal on port 80)
    if [[ -d "$WEB_DIR" ]]; then
        cat <<EOF > /etc/systemd/system/antigravity-dl.service
[Unit]
Description=Antigravity Bypass Client Download Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$WEB_DIR
ExecStart=/usr/bin/python3 -m http.server 80 --directory $WEB_DIR
Restart=always
RestartSec=3
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    fi

    systemctl daemon-reload
    systemctl restart antigravity-unlocker.service || true
    systemctl restart antigravity-dl.service 2>/dev/null || true
    systemctl enable antigravity-unlocker.service 2>/dev/null || true
    systemctl enable antigravity-dl.service 2>/dev/null || true
    echo "[+] Systemd services installed and active."
fi

echo ""
echo "========================================================================"
echo "  [ + ] ANTIGRAVITY UNLOCKER SERVER IS READY"
echo "========================================================================"
echo "  Server Host : $SERVER_IP"
echo "  Proxy Port  : $SERVER_PORT (HTTP CONNECT)"
echo ""
echo "  TO INSTALL CLIENT ON WINDOWS (POWERSHELL):"
echo "    irm http://${SERVER_IP}/install.ps1 | iex"
echo ""
echo "  TO INSTALL CLIENT ON LINUX / MACOS (BASH):"
echo "    curl -sSL http://${SERVER_IP}/install.sh | bash"
echo "========================================================================"
