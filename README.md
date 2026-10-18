# Universal Antigravity Unlocker Server

A lightweight, zero-privilege, cross-platform unlocker server and client runtime for Google AI and Antigravity services (`agy-cli` and Antigravity IDE).
**Universal Edition**: Deployable on **any server or VPS** with zero hardcoded IPs and automatic dynamic public IP resolution.

---

## 1. Zero-Privilege Architecture & SmartDNS Design

The bypass operates using a custom user-space **SmartDNS** and **non-terminating SNI-Proxy** engine (Xbox-DNS style architecture) combined with zero-admin client runtimes:

```
[ Restricted Client (Linux / macOS / Windows) ]
      │
      ├──> User-Space Tools (client_run.sh / client_run.ps1)
      │      ├── Direct Stealth Proxy (<SERVER_IP>:48328 SOCKS5 / 48329 HTTP CONNECT)
      │      ├── Or Local Loopback Forwarder (127.0.0.1:18443)
      │      └── Selective Routing:
      │            ├── Target Google AI Endpoints ──> Tunnel to VPS
      │            └── All other traffic ──────────────> Direct Local
      │
      ├──> agy CLI & IDE (agy-run / agy-run.ps1 / settings.json patcher)
      │      ├── HTTPS_PROXY="http://<SERVER_IP>:48329"
      │      ├── ALL_PROXY="socks5h://<SERVER_IP>:48328"
      │      └── jetski.cloudCodeUrl = "https://daily-cloudcode-pa.googleapis.com"
      │
      ▼
[ Remote VPS (<SERVER_IP> - Auto-detected) ]
      ├── DNS Interceptor (UDP/TCP <SERVER_IP>:53)
      │     ├── Google AI domains -> resolves to <SERVER_IP> (NODATA for AAAA/Type 65)
      │     └── Other queries -> upstream DNS (1.1.1.1 / 8.8.8.8)
      │
      ├── Non-Terminating SNI-Proxy Engine (TCP 443 / 8443 / 10443)
      │     └── RFC 6066 ClientHello parser -> Bidirectional TCP relay to Google Edge IPs
      │
      ├── Authenticated Remote Inbound (TCP 48328 SOCKS5 / 48329 HTTP CONNECT)
      │
      └── Managed Systemd Daemon (antigravity-unlocker.service)
```

### Core Zero-Privilege Guarantee
- **No `sudo` or root rights required on clients**: The client scripts (`client_run.sh`, `agy-run`, `patch_ide_settings.py`, `diagnose.sh`) run 100% in unprivileged user space.
- **No kernel drivers, VPN adapters, or network interface changes**: Uses standard loopback proxy environment variables (`HTTPS_PROXY`, `ALL_PROXY`, `AG_LS_PROXY`).
- **Selective routing**: Only queries destined for whitelisted Google AI endpoints pass through the VPS tunnel; all normal user traffic remains direct.
- **Dynamic IP Auto-Discovery**: No IP addresses are hardcoded. The server dynamically discovers its public IP on startup; clients connect using their configured server host.

---

## 2. Whitelisted Google AI Endpoints

The SmartDNS interceptor and SNI-proxy selectively forward traffic for:
- `daily-cloudcode-pa.googleapis.com` (Antigravity IDE & CodeAssist backend)
- `generativelanguage.googleapis.com` (Gemini API & model inference)
- `cloudcode-pa.googleapis.com` (Cloud Code services)
- `antigravity-unleash.goog` (Feature release flags)
- `ai.studio` & `aicode.googleapis.com` (Developer portal and completions)
- `oauth2.googleapis.com` (Authentication endpoints)

---

## 3. Server Deployment on Any VPS

### Quick Automated Setup (`setup_server.sh`)
Clone and run the automated installer on your server:

```bash
git clone https://github.com/Agy-Imperium/antigravity-unlocker-server.git
cd antigravity-unlocker-server
sudo ./setup_server.sh
```

The script will automatically:
1. Detect your public IP address (via kernel routing and NAT probe).
2. Install Python package and system dependencies.
3. Build client distribution bundles for Linux/macOS and Windows.
4. Deploy and start `antigravity-unlocker.service` systemd daemon.
5. Set up HTTP distribution endpoint for one-command client installers.

The server daemon listens on:
- UDP/TCP `:53`: SmartDNS interceptor
- TCP `:443`, `:8443`, & `:10443`: Non-terminating SNI-Proxy
- TCP `:48328`: Remote SOCKS5 forwarder (dedicated stealth port)
- TCP `:48329`: Remote HTTP CONNECT forwarder (dedicated stealth port)

Server management commands:
```bash
systemctl status antigravity-unlocker.service
journalctl -u antigravity-unlocker.service -f
```

---

## 4. Single-Command Client Installation

### Linux & macOS (Unprivileged User)
Install via `curl` into `~/.antigravity-bypass`:
```bash
curl -sSL http://<SERVER_IP>/install.sh | bash
```
Or with custom installation directory:
```bash
bash install.sh --dir ~/.my-bypass
```

### Windows (Unprivileged PowerShell)
Install via single-command `powershell` (no UAC / Admin required):
```powershell
irm http://<SERVER_IP>/install.ps1 | iex
```

---

## 5. Client Usage Guide

### Linux & macOS Runtime (`client_run.sh`)
Start the background local forwarder and export proxy environment:
```bash
# Start background forwarder
client/client_run.sh

# Or run any command directly with proxy environment
client/client_run.sh agy -p "ping"
```

Environment variables configured automatically:
- `HTTPS_PROXY="http://<SERVER_IP>:48329"`
- `HTTP_PROXY="http://<SERVER_IP>:48329"`
- `ALL_PROXY="socks5h://<SERVER_IP>:48328"`
- `AG_LS_PROXY="http://<SERVER_IP>:48329"`

### Windows Runtime (`client_run.ps1`)
In standard unprivileged PowerShell:
```powershell
.\client\client_run.ps1
```

---

## 6. CLI Integration (`agy-run`)

Launch `agy` with automatic proxy environment and full argument forwarding:
```bash
client/agy-run -p "ping" --print-timeout 10s
```
On Windows:
```powershell
.\client\agy-run.ps1 -p "ping"
```

---

## 7. Antigravity IDE Integration (`patch_ide_settings.py`)

Safely patch Antigravity IDE `settings.json` to route through Frankfurt VPS:
```bash
# Auto-detects Linux/macOS (~/.config/Antigravity/User/settings.json) or Windows (%APPDATA%)
python3 client/patch_ide_settings.py

# Custom path or dry-run inspection
python3 client/patch_ide_settings.py --dry-run
python3 client/patch_ide_settings.py --path /path/to/settings.json
```

---

## 8. Cross-Platform Diagnostics (`diagnose.sh` / `diagnose.py`)

Verify complete end-to-end connectivity across all components:
```bash
diagnostics/diagnose.sh
# Or with structured JSON output:
python3 diagnostics/diagnose.py --format json
```

Checks performed:
1. DNS UDP interception of `daily-cloudcode-pa.googleapis.com` to VPS `<SERVER_IP>`.
2. TLS SNI forwarder handshake on port 443 / 8443 / 10443.
3. HTTP CONNECT proxy tunnel on port 48329.
4. SOCKS5 proxy tunnel on port 48328.
5. Local loopback forwarder ports on `127.0.0.1`.
6. Live `agy` prompt execution (`agy -p "ping"`).

---

## 9. Zero-Admin Verification Steps

To audit and confirm that zero elevated privileges are used:
1. Check current unprivileged identity:
   ```bash
   whoami
   ```
2. Confirm no root/sudo commands are invoked:
   ```bash
   grep -rn "sudo " client/ install.sh
   # Expected result: zero matches
   ```
3. Verify stealth proxy and loopback ports (>1024):
   ```bash
   ss -tulnp | grep -E "18443|48328|48329"
   ```

---

## 10. Troubleshooting

### Port 53 Collision with `systemd-resolved` on VPS
On Ubuntu/Debian VPS hosts, `systemd-resolved` may bind `127.0.0.53:53` on port 53.
To resolve the port 53 conflict on the server:
```bash
# Disable DNSStubListener in /etc/systemd/resolved.conf:
# DNSStubListener=no
# Then restart systemd-resolved:
systemctl restart systemd-resolved
```
Note: Remote client machines do NOT bind port 53; clients connect exclusively via user-space proxy ports (48328/48329 or loopback 18443), avoiding port 53 collisions completely.
