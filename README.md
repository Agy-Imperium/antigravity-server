# Antigravity Server

[![Release](https://img.shields.io/github/v/release/Agy-Imperium/antigravity-server?color=blue&style=flat-square)](https://github.com/Agy-Imperium/antigravity-server/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg?style=flat-square)]()
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg?style=flat-square)](https://www.python.org/)

A high-performance, zero-privilege bypass server and client runtime designed to unlock Google Antigravity IDE and `agy-cli` in geographically restricted regions.

Deployable on **any Linux server or VPS** with automatic dynamic public IP resolution, selective SmartDNS routing, and zero-privilege client runtimes.

---

## ⚡ Quickstart

### 1. Server Setup (Run on your VPS)

Deploy the unlocker daemon and client distribution endpoint in a single command:

```bash
git clone https://github.com/Agy-Imperium/antigravity-server.git
cd antigravity-server
sudo ./setup_server.sh
```

> **What this does:**
> - Automatically discovers the server's public IP address (via kernel routing & NAT probe).
> - Installs required dependencies and registers `antigravity-unlocker.service` systemd daemon.
> - Builds and stages pre-configured client packages (`.tar.gz` and `.zip`).
> - Starts HTTP distribution on port `80` for one-command client installation.

---

### 2. Client Setup (Run on developer machine)

Zero administrator or root rights required (`100% user-space`). Choose any of the following methods:

#### Method A: One-Command from Server (Recommended)
If your server's HTTP distribution port `80` is reachable, the installer automatically detects the server address:

- **Linux / macOS:**
  ```bash
  curl -sSL http://<YOUR_SERVER_IP>/install.sh | bash
  ```
- **Windows (PowerShell):**
  ```powershell
  irm http://<YOUR_SERVER_IP>/install.ps1 | iex
  ```

#### Method B: Direct from GitHub
If port `80` on the server is behind a firewall, install directly from GitHub while specifying your server address:

- **Linux / macOS:**
  ```bash
  curl -sSL https://raw.githubusercontent.com/Agy-Imperium/antigravity-server/main/install.sh | bash -s -- --server <YOUR_SERVER_IP>
  ```
  *(or via environment variable: `ANTIGRAVITY_SERVER_HOST=<YOUR_SERVER_IP> bash -c "$(curl -sSL https://raw.githubusercontent.com/Agy-Imperium/antigravity-server/main/install.sh)"`)*
- **Windows (PowerShell):**
  ```powershell
  $env:ANTIGRAVITY_SERVER_HOST="<YOUR_SERVER_IP>"; irm https://raw.githubusercontent.com/Agy-Imperium/antigravity-server/main/install.ps1 | iex
  ```

#### Method C: Manual / Offline from GitHub Releases
1. Download `antigravity-bypass-client.zip` (Windows) or `antigravity-bypass-client.tar.gz` (Linux/macOS) from [Releases](https://github.com/Agy-Imperium/antigravity-server/releases).
2. Extract to `~/.antigravity-bypass` (on Windows: `%USERPROFILE%\.antigravity-bypass`).
3. Create a text file `server_host.txt` in that directory containing your server IP or domain (e.g. `1.2.3.4`).
4. Run `~/.antigravity-bypass/bin/agy-ui` (or `.\bin\agy-ui.ps1`) and select **`[1] One-Click Auto-Unlock`**.

---

### Verification
Once installed, simply run `agy` in your terminal:
```bash
agy -p "Hello from Antigravity!"
```

---

## 🧠 How It Works (Architecture)

Antigravity Server utilizes a split-horizon **SmartDNS** and **Non-Terminating SNI Proxy** pipeline combined with user-space proxy redirection:

```
[ Developer Client (Linux / macOS / Windows) ]
      │
      ├──> User-Space Tools (client_run.sh / client_run.ps1)
      │      ├── Auto-detects server from ~/.antigravity-bypass/server_host.txt
      │      ├── Injects proxy environment (HTTPS_PROXY, ALL_PROXY, AG_LS_PROXY)
      │      └── Transparently hooks `agy` CLI calls & IDE settings
      │
      ▼
[ Antigravity Unlocker Server (<YOUR_SERVER_IP>) ]
      │
      ├── SmartDNS (UDP/TCP :53)
      │     ├── Google AI domains ───> Resolves to server public IP
      │     └── All other domains ───> Upstream DNS resolvers (1.1.1.1 / 8.8.8.8)
      │
      ├── Non-Terminating SNI Proxy (TCP :443 / :8443 / :10443)
      │     └── RFC 6066 ClientHello Parser:
      │           Directs TLS traffic to official Google Edge IPs
      │           (Zero TLS termination, no root CA installation required)
      │
      └── Stealth Tunnel Inbounds (TCP :48328 SOCKS5 / :48329 HTTP CONNECT)
            └── Dedicated, isolated proxy forwarders for CLI & Language Server
```

### Whitelisted Endpoints
Traffic is selectively proxied **only** for Google AI and Antigravity endpoints:
- `daily-cloudcode-pa.googleapis.com` (Antigravity IDE & CodeAssist backend)
- `generativelanguage.googleapis.com` (Gemini API inference)
- `cloudcode-pa.googleapis.com` (Cloud Code services)
- `antigravity-unleash.goog` (Feature release flags)
- `ai.studio` & `aicode.googleapis.com` (Developer portal and completions)
- `oauth2.googleapis.com` (Authentication endpoints)

All standard, non-whitelisted user traffic remains completely local and direct.

---

## 🖥 Interactive Client Manager (`antigravity-ui`)

For an interactive control panel, launch the built-in terminal UI:

```bash
# Linux / macOS
~/.antigravity-bypass/bin/antigravity-ui

# Windows
~\.antigravity-bypass\bin\antigravity-ui.ps1
```

Features available in the TUI:
- **`[1] One-Click Auto-Unlock`**: Automatically starts the background forwarder, patches IDE `settings.json`, and configures shell hooks.
- **`[2] Start Forwarder`**: Launches the local background forwarder.
- **`[3] Patch agy CLI`**: Deploys transparent shell wrappers.
- **`[4] Patch IDE Settings`**: Automatically locates and updates Antigravity IDE configuration.
- **`[5] Run Diagnostics`**: Tests end-to-end DNS, TLS SNI, HTTP CONNECT, and SOCKS5 tunnels.
- **`[6] Check Status`**: Displays daemon and proxy connection state.
- **`[7] Restore & Clean Rollback`**: Restores original configurations cleanly with zero residue.

---

## ⚙️ Configuration & Environment

### Environment Variables
| Variable | Description | Default |
| :--- | :--- | :--- |
| `ANTIGRAVITY_SERVER_HOST` | Hostname or IP of the Antigravity Server | Auto-detected / read from config |
| `HTTPS_PROXY` | HTTP proxy tunnel | `http://<SERVER_IP>:48329` |
| `ALL_PROXY` | SOCKS5 proxy tunnel | `socks5h://<SERVER_IP>:48328` |
| `AG_LS_PROXY` | Dedicated Go Language Server proxy variable | `http://<SERVER_IP>:48329` |

### Server Port Allocations
| Port | Protocol | Purpose |
| :--- | :--- | :--- |
| `53` | UDP / TCP | SmartDNS Selective Interceptor |
| `443` | TCP | Primary Non-Terminating SNI Proxy |
| `8443` / `10443` | TCP | Fallback SNI Proxy Ports |
| `48328` | TCP | Stealth SOCKS5 Proxy Tunnel |
| `48329` | TCP | Stealth HTTP CONNECT Proxy Tunnel |
| `80` | TCP | HTTP Distribution Endpoint (installers & packages) |

---

## 🔍 Diagnostics & Verification

### End-to-End Diagnostics
Verify all services and tunnel paths:
```bash
# Linux / macOS
~/.antigravity-bypass/bin/diagnose.sh

# Or directly via Python with JSON output:
python3 diagnostics/diagnose.py --format json
```

### Server Management
```bash
# Check service status
sudo systemctl status antigravity-unlocker.service

# Stream live service logs
sudo journalctl -u antigravity-unlocker.service -f

# Restart daemon
sudo systemctl restart antigravity-unlocker.service
```

---

## 🛠 Troubleshooting

### Port 53 conflict on Ubuntu/Debian (`systemd-resolved`)
If `systemd-resolved` is already listening on `127.0.0.53:53`:
```bash
# Edit /etc/systemd/resolved.conf and set:
# DNSStubListener=no

# Then restart systemd-resolved:
sudo systemctl restart systemd-resolved
```
*(Clients do not bind port 53; this applies only to the server).*

---

## 📄 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
