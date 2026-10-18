<#
.SYNOPSIS
Antigravity Zero-Privilege Client Runtime for Windows PowerShell.
Operates completely in user-space without administrative elevation.

.DESCRIPTION
Configures direct stealth proxy environment for Antigravity & agy-cli.
Routes directly to remote VPS stealth ports (48329 HTTP CONNECT, 48328 SOCKS5).
Zero local daemon requirement; eliminates all port collisions with third-party VPNs.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Server = "",

    [Parameter(Mandatory=$false)]
    [string]$ServerHost = "",

    [Parameter(Mandatory=$false)]
    [int]$SocksPort = 48328,

    [Parameter(Mandatory=$false)]
    [int]$HttpPort = 48329,

    [Parameter(Mandatory=$false)]
    [int]$UpstreamSocksPort = 48328,

    [Parameter(Mandatory=$false)]
    [int]$UpstreamHttpPort = 48329,

    [Parameter(Mandatory=$false)]
    [string]$AuthToken = "",

    [Parameter(Mandatory=$false)]
    [switch]$Stop,

    [Parameter(Mandatory=$false)]
    [switch]$Check,

    [Parameter(Mandatory=$false)]
    [switch]$Help
)

function Check-Python {
    $hasPython = Get-Command "python" -ErrorAction SilentlyContinue
    if (-not $hasPython) {
        $hasPython = Get-Command "python3" -ErrorAction SilentlyContinue
    }
    return [bool]$hasPython
}

$DefaultHost = if ($env:ANTIGRAVITY_SERVER_HOST) { $env:ANTIGRAVITY_SERVER_HOST } else {
    $cfg = "$env:USERPROFILE\.antigravity-bypass\server_host.txt"
    if (Test-Path $cfg) { (Get-Content -Path $cfg -Raw -ErrorAction SilentlyContinue).Trim() } else { "127.0.0.1" }
}
$TargetHost = if ($PSBoundParameters.ContainsKey('ServerHost') -and $ServerHost) { $ServerHost } elseif ($PSBoundParameters.ContainsKey('Server') -and $Server) { $Server } else { $DefaultHost }
$EffectiveHttpPort = if ($PSBoundParameters.ContainsKey('UpstreamHttpPort')) { $UpstreamHttpPort } else { $HttpPort }
$EffectiveSocksPort = if ($PSBoundParameters.ContainsKey('UpstreamSocksPort')) { $UpstreamSocksPort } else { $SocksPort }
$PidFile = Join-Path $env:TEMP "antigravity_forwarder.pid"

if ($Help) {
    Write-Host @"
Usage: .\client_run.ps1 [OPTIONS]

Zero-Privilege Antigravity & agy-cli Client Runtime for Windows

Options:
  -Server, -ServerHost <IP>    Unlocker Server IP or domain (reads ~/.antigravity-bypass/server_host.txt)
  -SocksPort <PORT>            VPS SOCKS5 port (default: 48328)
  -HttpPort <PORT>             VPS HTTP port (default: 48329)
  -UpstreamSocksPort <PORT>    Upstream VPS SOCKS5 port (default: 48328)
  -UpstreamHttpPort <PORT>     Upstream VPS HTTP port (default: 48329)
  -Check                       Check reachability of remote VPS stealth route
  -Stop                        Clean any legacy forwarder process files
  -Help                        Show this help message
"@
    exit 0
}

function Cleanup-Legacy {
    if (Test-Path $PidFile) {
        $procId = Get-Content $PidFile -ErrorAction SilentlyContinue
        if ($procId) {
            Stop-Process -Id $procId -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
}

if ($Stop) {
    Cleanup-Legacy
    Write-Host "Legacy forwarder state cleaned."
    exit 0
}

if ($Check) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $iar = $client.BeginConnect($TargetHost, $EffectiveHttpPort, $null, $null)
        $wh = $iar.AsyncWaitHandle
        if (-not $wh.WaitOne(1500, $false)) {
            $client.Close()
            Write-Host "Antigravity remote route to $TargetHost`:$EffectiveHttpPort is unreachable."
            exit 1
        }
        $client.EndConnect($iar)
        $client.Close()
        Write-Host "Antigravity remote route to $TargetHost`:$EffectiveHttpPort is active [OK]."
        exit 0
    } catch {
        Write-Host "Antigravity remote route to $TargetHost`:$EffectiveHttpPort is unreachable: $_"
        exit 1
    }
}

Cleanup-Legacy

# Configure Process-Scope Environment Variables for Direct Stealth Route
$env:HTTPS_PROXY = "http://$TargetHost`:$EffectiveHttpPort"
$env:ALL_PROXY = "socks5h://$TargetHost`:$EffectiveSocksPort"
$env:AG_LS_PROXY = "http://$TargetHost`:$EffectiveHttpPort"
$env:HTTP_PROXY = "http://$TargetHost`:$EffectiveHttpPort"

Write-Host "Direct proxy environment configured for current user session (zero-collision architecture):"
Write-Host "  `$env:HTTPS_PROXY = $env:HTTPS_PROXY"
Write-Host "  `$env:ALL_PROXY   = $env:ALL_PROXY"
Write-Host "  `$env:AG_LS_PROXY = $env:AG_LS_PROXY"
