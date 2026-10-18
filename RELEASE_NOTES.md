# Antigravity Unlocker Release Notes

## Version 1.0.5 (Build 2026101803) - 2026-10-18
- **Smart Auto-Patch on New `agy` Version Detection**:
  - Automatically detects when Google updates or replaces the official `agy` / `agy.real` executable on disk by comparing file size and mtime against a cached `.patch_stamp`.
  - When a binary modification is detected and the binary contains the unpatched `ineligible` signature, `agy-run` and `agy-run.ps1` automatically invoke the patcher in the background, update the stamp, and proceed to execute seamlessly (<100ms overhead).
- **Strict Idempotency in Binary Patcher**:
  - Prevented unnecessary writes and redundant re-patching: if a binary already contains the patched signature (`inexigible`), the patcher immediately logs and exits with success without modifying the file.
- **PowerShell Installer Fixes (`install.ps1`)**:
  - Fixed `ParameterBindingException: Cannot convert 'System.Object[]' to the type 'System.String'` in `Join-Path` caused by comma-delimited path array syntax.
  - Mitigated Internet Explorer DOM parsing security warnings by utilizing `-UseBasicParsing` and recommending `irm http://<SERVER_IP>/install.ps1 | iex` (`Invoke-RestMethod`).
- **Optimistic Execution & Freeze Elimination**:
  - **IDE Patching Speedup**: Targeted `.js` bundle scanning in `ide.py` to specific IDE subdirectories (`resources/app/out`, `extensions`), skipping massive `node_modules` trees (reducing scan time from 25s down to 0.05s).
  - **Process Recycling Optimization**: Combined multiple sequential Windows `taskkill` calls into a single atomic invocation (`taskkill /F /T /IM ...`).
  - **Environment Discovery**: Eliminated full-drive recursive globs in `get_cli_binary_paths()`, reduced proxy TCP probe timeout from 1.5s to 0.4s, and replaced slow PowerShell subprocess calls with direct `winreg` registry manipulation on Windows.
- **TUI Console Progress Bar & Clean Notifications**:
  - Hides menu buttons immediately upon selecting any directive and renders an animated optimistic progress bar (`[████████░░░░░░░░] XX%`) executing in a non-blocking background thread.
  - Replaced 10-line debug log dumps with clean, concise single-line success/failure notifications.
- **Clean Minimalist Installer UI**:
  - Replaced verbose ASCII banners with a clean, modern 3-step progress display (`[1/3] Downloading...`, `[2/3] Configuring...`, `[3/3] Verifying & applying...`).

## Version 1.0.4 (Build 2026101802) - 2026-10-18
- **Strict Port 10808 & 10809 Exclusion**:
  - Completely eliminated all active TCP probes to ports 10808 and 10809 from Windows PowerShell (`agy-run.ps1`), Linux/WSL bash (`agy-run`), and interactive wrapper generation.
  - Added strict exclusion rules to ignore WinINET and environment proxy variables pointing to 10808 or 10809, guaranteeing zero interference or hijacking of user VPNs (Happ, Xray, v2ray).
- **Eliminated `DIRECT_TUN` Trap (Fix for `User location is not supported`)**:
  - Removed the faulty adapter inspection heuristic that cleared proxy environment variables to `$null` whenever virtual or TUN network adapters (WSL, Hyper-V, WireGuard, Happ) were detected.
  - All Antigravity CLI and Language Server traffic now reliably routes through the remote VPS proxy tunnel (`http://<SERVER_IP>:48329`) by default, providing guaranteed European exit and unblocking Google Gemini API.
- **SSRF Filter Hardening**:
  - Added check for `ip.is_unspecified` (`0.0.0.0` and `::`) in `proxy_service.py` to prevent Linux loopback aliasing.
  - Added DNS resolution validation in `is_restricted_ssrf_destination()` to block hostnames resolving to private, loopback, or cloud metadata addresses.
- **Protocol & Network Resilience**:
  - Protected `socket.inet_aton` across `dns_service.py` and `socks5.py` against IPv6 and invalid addresses.
  - Dynamically resolved socket address family (`AF_INET`/`AF_INET6`) for upstream DNS forwarders in `dns_service.py`.
  - Added support for IPv6 bracket literals (e.g. `[2001:db8::1]:443`) in `http_connect.py`.
- **Client & Platform Fixes**:
  - **Windows Symlink Fallback**: Caught `OSError` on Windows when unprivileged users lack `SeCreateSymbolicLinkPrivilege` in `updater/engine.py`, falling back to file copying.
  - **IDE Multi-Profile Patching**: Fixed early `break` in `patch_ide_settings()`, ensuring all installed Antigravity IDE configuration directories are updated.
  - **Windows Sibling Discovery**: Added `%SCRIPT_DIR%agy.ps1` check to `agy-run.bat` and `bin/agy-run.bat`.
  - **Boot Autostart Interpreter**: `boot_sync.py` now uses `sys.executable` to guarantee correct Python invocation.
  - **TTY Detection in UI**: `app.py` now exits cleanly with help or status when invoked non-interactively without a TTY.

## Version 1.0.3 (Build 2026101801) - 2026-10-18
- **PowerShell Seamless `agy` Command Interception**:
  - Automatically renames `agy.exe` to `agy.real.exe` in all standard directories (`%LOCALAPPDATA%\Programs\Antigravity\bin`, `%USERPROFILE%\.gemini\antigravity-cli\bin`, `%USERPROFILE%\.local\bin`, etc.) and deploys `agy.cmd`, `agy.bat`, `agy.ps1` wrappers.
  - Automatically defines `function agy` in PowerShell profiles (`WindowsPowerShell` and `PowerShell 7+`), guaranteeing that typing `agy` in any terminal session executes through the smart bypass launcher rather than falling back to unproxied binaries.
- **Happ / Third-Party Proxy Co-existence & Auto-Routing**:
  - Automatically detects Happ / v2rayN / Clash in **System Proxy mode** by querying Windows WinINET settings (`ProxyEnable`, `ProxyServer`) and propagating them to Go's `net/http` (`AG_LS_PROXY`, `HTTPS_PROXY`).
  - Probes local proxy inbounds (`127.0.0.1:10809` HTTP, `127.0.0.1:10808` SOCKS5, `127.0.0.1:7890` Clash) and seamlessly routes through Happ when active.
  - Detects active TUN/VPN adapters (Wintun, sing-box, WireGuard) to allow seamless L3 encapsulation without enforcing high-port proxy rules.
  - Removed all aggressive legacy code that previously purged ports 10808 and 10809 from environment variables and configuration files.
- **Language Server Process Recycling**:
  - Proactively kills any stale `language_server` processes *before* launching `agy`, preventing connection leaks to unproxied background daemons that caused `FAILED_PRECONDITION (code 400): User location is not supported`.

---

## Version 1.0.0 (Build 2026101104) - 2026-10-11

## Highlights

### 1. Security Hardening
- **Anti-SSRF Protection**: Strict filtering on inbound proxy requests to forbid access to private networks (RFC1918), loopback (`127.0.0.0/8`), link-local (`169.254.0.0/16`), IPv6 loopback (`::1`), and cloud metadata services.
- **Whitelist Enforcement**: Unauthenticated proxy connections are restricted exclusively to whitelisted Google AI and Gemini endpoints (`daily-cloudcode-pa.googleapis.com`, `generativelanguage.googleapis.com`, `aistudio.google.com`, etc.). Open relay / open proxy exploitation is blocked.
- **ZipSlip Mitigation**: Archive extraction in the updater engine verifies that all extracted member paths resolve strictly within the designated installation directory.
- **SHA-256 Distribution Integrity**: Packages are verified against SHA-256 manifests prior to extraction.
- **Strict SSL Validation**: Enabled `http.proxyStrictSSL: true` in IDE settings by default, preserving end-to-end TLS security through CONNECT tunnels.
- **DNS Flood Limiter**: Async bounded semaphore added to the DNS datagram protocol to protect against UDP amplification/exhaustion attacks.

### 2. Port Architecture (Zero-Conflict Policy)
- **Forbidden Ports 10808 & 10809 Eliminated**: Completely removed all usage and bindings of ports 10808 and 10809 to prevent collisions with third-party VPN/proxy clients (Xray, v2ray, Clash).
- **Stealth Remote Proxy Ports**:
  - `48328`: SOCKS5 proxy tunnel
  - `48329`: HTTP CONNECT proxy tunnel
- **Non-Terminating SNI Proxy**:
  - `443` / `8443` / `10443`: Adaptive TLS handshake forwarder to Google Edge IPs.
- **SmartDNS Interceptor**:
  - `53`: UDP/TCP DNS interceptor with authoritative Google AI routing and fallback to public resolvers.

### 3. Client & UI Modernization
- **Brutalist TUI Manager (`agy-ui`)**: Fixed missing symbol exports, resolving UI launch crashes.
- **Single-Line Zero-Admin Installers**: Updated `install.sh` and `install.ps1` to configure user-space wrappers without `sudo`.
- **Adaptive Diagnostics (`diagnose.sh` / `diagnose.py`)**: Self-test probes DNS, TLS SNI, HTTP CONNECT, and SOCKS5 tunnels dynamically.

---

## Distribution Packages & Checksums

| Package | Format | SHA-256 Checksum |
| :--- | :--- | :--- |
| `antigravity-bypass-client.tar.gz` | Linux / macOS | `f554752749f445472b4134be49aa23a5639971eb740b0bec4569be7411fcf722` |
| `antigravity-bypass-client.zip` | Windows | `4adbf9933e49941d9fa0bd67177fc0ca3603e2bc7d0e94b97d6cd0c7d9d5db70` |

---

## Verification & Testing
- **E2E Test Suite**: 183 Passed, 2 Skipped (token-authenticated endpoints), 0 Failed across all 4 Tiers.
