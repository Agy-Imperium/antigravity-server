# agy-run.ps1 - Resilient CLI Launcher for Antigravity (Windows)
# Smartly detects Happ / V2Ray / Clash proxies or routes via Frankfurt VPS.
# Operates 100% in unprivileged user space. Zero elevated privileges or UAC required.

[CmdletBinding()]
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$AgyArgs
)

# 1. Resolve Best Proxy Route (Frankfurt VPS by default, or AGY_CUSTOM_PROXY)
function Get-AgyProxyEndpoint {
    # A. Explicit override via AGY_CUSTOM_PROXY
    if ($env:AGY_CUSTOM_PROXY) {
        return $env:AGY_CUSTOM_PROXY
    }

    # B. Third-party System Proxy via Windows WinINET Settings (strictly ignoring forbidden VPN ports 10808/10809)
    try {
        $reg = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
        if ($reg -and $reg.ProxyEnable -eq 1 -and $reg.ProxyServer) {
            $srv = [string]$reg.ProxyServer
            if ($srv -match "https?=([^;]+)") {
                $srv = $matches[1]
            } elseif ($srv -match "([^;=]+)") {
                $srv = $matches[1]
            }
            if ($srv -and $srv -notmatch ":1080[89]") {
                if ($srv -notmatch "^[a-zA-Z]+://") { $srv = "http://" + $srv }
                return $srv
            }
        }
    } catch {}

    # Determine configured unlocker server host
    $RemoteHost = if ($env:ANTIGRAVITY_SERVER_HOST) { $env:ANTIGRAVITY_SERVER_HOST } else {
        $cfg = "$env:USERPROFILE\.antigravity-bypass\server_host.txt"
        if (Test-Path $cfg) { (Get-Content -Path $cfg -Raw -ErrorAction SilentlyContinue).Trim() } else { "127.0.0.1" }
    }
    $RemotePort = 48329

    # C. Pre-existing caller environment proxy (if set and not pointing to forbidden VPN ports 10808/10809)
    if ($env:HTTPS_PROXY -and $env:HTTPS_PROXY -notlike "*$RemoteHost*" -and $env:HTTPS_PROXY -notmatch ":1080[89]") {
        return $env:HTTPS_PROXY
    }
    if ($env:HTTP_PROXY -and $env:HTTP_PROXY -notlike "*$RemoteHost*" -and $env:HTTP_PROXY -notmatch ":1080[89]") {
        return $env:HTTP_PROXY
    }

    # D. Default: Remote Unlocker Server Proxy (HTTP CONNECT on 48329)
    return "http://${RemoteHost}:${RemotePort}"
}

$ProxyTarget = Get-AgyProxyEndpoint

# Store prior environment state for clean process isolation
$OldHttps = $env:HTTPS_PROXY
$OldHttp  = $env:HTTP_PROXY
$OldAgLs  = $env:AG_LS_PROXY
$OldNoP   = $env:NO_PROXY

if ($ProxyTarget) {
    $env:HTTPS_PROXY = $ProxyTarget
    $env:HTTP_PROXY  = $ProxyTarget
    $env:AG_LS_PROXY = $ProxyTarget
    $env:https_proxy = $ProxyTarget
    $env:http_proxy  = $ProxyTarget
    $env:NO_PROXY    = "localhost,127.0.0.1,::1"
    $env:no_proxy    = "localhost,127.0.0.1,::1"
} else {
    $env:HTTPS_PROXY = $null
    $env:HTTP_PROXY  = $null
    $env:AG_LS_PROXY = $null
    $env:https_proxy = $null
    $env:http_proxy  = $null
}

# 2. Terminate any stale background Language Server before running
# Ensures new Language Server inherits updated proxy environment variables
Get-Process -Name "language_server_windows_x64", "language_server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# 3. Locate agy executable
$AgyExe = $null
$Candidates = @(
    "$env:LOCALAPPDATA\Programs\Antigravity\bin\agy.real.exe",
    "$env:USERPROFILE\.gemini\antigravity-cli\bin\agy.real.exe",
    "$env:USERPROFILE\.local\bin\agy.real.exe",
    "$env:USERPROFILE\.antigravity-bypass\agy.real.exe",
    "$env:LOCALAPPDATA\Programs\Antigravity\bin\agy.exe",
    "$env:USERPROFILE\.gemini\antigravity-cli\bin\agy.exe",
    "$env:USERPROFILE\.local\bin\agy.exe",
    "$env:USERPROFILE\.antigravity-bypass\agy.exe"
)

foreach ($cand in $Candidates) {
    if (Test-Path $cand) {
        $AgyExe = $cand
        break
    }
}

if (-not $AgyExe) {
    $found = Get-Command "agy.real.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if ($found) { $AgyExe = $found }
}
if (-not $AgyExe) {
    $found = Get-Command "agy.exe" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source
    if ($found -and $found -ne $PSCommandPath) { $AgyExe = $found }
}

if (-not $AgyExe) {
    [Console]::Error.WriteLine("Error: agy binary not found in PATH or standard user directories.")
    exit 1
}

# 3b. Autopatch detection for newly placed or updated agy binaries
$StampDir = "$env:USERPROFILE\.antigravity-bypass"
$StampFile = Join-Path $StampDir ".patch_stamp"
$NeedPatch = $false

if ($AgyExe -and (Test-Path $AgyExe)) {
    try {
        $item = Get-Item -Path $AgyExe -ErrorAction SilentlyContinue
        $curStat = "$($item.LastWriteTimeUtc.Ticks) $($item.Length)"
        $cachedStat = if (Test-Path $StampFile) { (Get-Content -Path $StampFile -Raw -ErrorAction SilentlyContinue).Trim() } else { "" }
        if (-not $cachedStat -or $cachedStat -ne $curStat) {
            # Inspect binary for unpatched ineligible signature
            $bytes = [System.IO.File]::ReadAllBytes($AgyExe)
            $text = [System.Text.Encoding]::ASCII.GetString($bytes)
            if ($text.Contains("ineligible")) {
                $NeedPatch = $true
            } else {
                if (-not (Test-Path $StampDir)) { New-Item -ItemType Directory -Path $StampDir -Force | Out-Null }
                Set-Content -Path $StampFile -Value $curStat -Force -ErrorAction SilentlyContinue
            }
        }
    } catch {}
}

if ($NeedPatch) {
    $Patcher = Join-Path $StampDir "client\patch_account.py"
    if (-not (Test-Path $Patcher)) { $Patcher = Join-Path $StampDir "patch_account.py" }
    if (Test-Path $Patcher) {
        $Py = if (Get-Command "python" -ErrorAction SilentlyContinue) { "python" } else { "py" }
        try { & $Py -X utf8 $Patcher | Out-Null } catch {}
    }
    try {
        $item = Get-Item -Path $AgyExe -ErrorAction SilentlyContinue
        $curStat = "$($item.LastWriteTimeUtc.Ticks) $($item.Length)"
        if (-not (Test-Path $StampDir)) { New-Item -ItemType Directory -Path $StampDir -Force | Out-Null }
        Set-Content -Path $StampFile -Value $curStat -Force -ErrorAction SilentlyContinue
    } catch {}
}

# 4. Forward all arguments and propagate process exit code with cleanup
$exitCode = 0
try {
    & $AgyExe @AgyArgs
    $exitCode = $LASTEXITCODE
} finally {
    Get-Process -Name "language_server_windows_x64", "language_server" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $env:HTTPS_PROXY = $OldHttps
    $env:HTTP_PROXY  = $OldHttp
    $env:AG_LS_PROXY = $OldAgLs
    $env:https_proxy = $OldHttps
    $env:http_proxy  = $OldHttp
    $env:NO_PROXY    = $OldNoP
    $env:no_proxy    = $OldNoP
}

exit $exitCode
