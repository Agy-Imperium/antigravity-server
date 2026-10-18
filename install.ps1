# install.ps1 - Zero-Privilege Client Installer for Antigravity Bypass (Windows)
# Operates completely in unprivileged user space. Zero elevated privileges or UAC required.

[CmdletBinding()]
param(
    [Alias("Path")]
    [string]$InstallDir = "$HOME\.antigravity-bypass",
    [string]$Server = "",
    [switch]$Uninstall,
    [switch]$Help
)

if ($Help) {
    Write-Host "Usage: install.ps1 [-InstallDir <PATH>] [-Server <IP>] [-Uninstall]"
    Write-Host "Zero-privilege Antigravity bypass Windows client installer."
    exit 0
}

if ($Uninstall) {
    Write-Host "Uninstalling Antigravity bypass client from $InstallDir..."
    $AgyUi = Join-Path $InstallDir "client\agy_ui.py"
    if (-not (Test-Path $AgyUi)) { $AgyUi = Join-Path $InstallDir "agy_ui.py" }
    if (Test-Path $AgyUi) {
        $PyCmd = if (Get-Command "python" -ErrorAction SilentlyContinue) { "python" } else { "py" }
        try { & $PyCmd $AgyUi --uninstall | Out-Null } catch {}
    }
    # Clean PowerShell profile function
    $Docs = [Environment]::GetFolderPath("MyDocuments")
    if (-not $Docs) { $Docs = "$env:USERPROFILE\Documents" }
    $ProfPaths = @(
        "$Docs\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
        "$Docs\PowerShell\Microsoft.PowerShell_profile.ps1"
    )
    foreach ($ProfPath in $ProfPaths) {
        if (Test-Path $ProfPath) {
            try {
                $txt = Get-Content -Path $ProfPath -Raw -ErrorAction SilentlyContinue
                if ($txt -match "AGY_CLI_HOOK") {
                    $cleaned = $txt -replace "(?ms)\r?\n?# >>> AGY_CLI_HOOK >>>.*?# <<< AGY_CLI_HOOK <<<\r?\n?", ""
                    Set-Content -Path $ProfPath -Value $cleaned.Trim() -Force
                }
            } catch {}
        }
    }
    if (Test-Path $InstallDir) {
        Remove-Item -Recurse -Force $InstallDir
    }
    $UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($UserPath -like "*$InstallDir*") {
        $CleanedPath = ($UserPath -split ";" | Where-Object { $_ -ne $InstallDir -and $_ -ne "$InstallDir\client" }) -join ";"
        [Environment]::SetEnvironmentVariable("PATH", $CleanedPath, "User")
    }
    Write-Host "Uninstallation complete."
    exit 0
}

if (-not $Server) {
    if ($env:ANTIGRAVITY_SERVER_HOST) {
        $Server = $env:ANTIGRAVITY_SERVER_HOST
    } else {
        $Server = "127.0.0.1"
    }
}

Write-Host "Installing Antigravity bypass (v1.0.5) [Server: $Server]..." -ForegroundColor Cyan
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
Set-Content -Path (Join-Path $InstallDir "server_host.txt") -Value $Server -Force

$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { $null }
$SourceClient = if ($ScriptDir) { Join-Path $ScriptDir "client" } else { $null }

# Normalize TEMP and TMP away from 8.3 short paths if present
if ($env:TEMP -and (Test-Path "$HOME\AppData\Local\Temp")) {
    $env:TEMP = "$HOME\AppData\Local\Temp"
    $env:TMP  = "$HOME\AppData\Local\Temp"
}

if ($SourceClient -and (Test-Path (Join-Path $SourceClient "agy_ui.py"))) {
    Write-Host "[1/3] Copying package files from local repository..." -ForegroundColor Gray
    Copy-Item -Recurse -Force (Join-Path $ScriptDir "*") $InstallDir
} else {
    # Fetch bundle from remote server
    $ZipUrl = "http://$Server/antigravity-bypass-client.zip"
    Write-Host "[1/3] Downloading & extracting package..." -ForegroundColor Gray
    $TempZip = Join-Path $InstallDir "antigravity_bypass_client_$PID.zip"
    try {
        if (Test-Path $TempZip) { Remove-Item -Force $TempZip }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $ZipUrl -OutFile $TempZip -UseBasicParsing
        Expand-Archive -Path $TempZip -DestinationPath $InstallDir -Force
        Remove-Item -Force $TempZip -ErrorAction SilentlyContinue
    } catch {
        Write-Error "Failed to download or extract package: $_"
        exit 1
    }
}

# Prepend $InstallDir and $InstallDir\client to User PATH for highest resolution priority
$UserPath = [Environment]::GetEnvironmentVariable("PATH", "User")
$AddPaths = @($InstallDir, "$InstallDir\client")
$ExistingParts = if ($UserPath) { $UserPath -split ";" } else { @() }
$NewParts = @()
foreach ($ap in $AddPaths) {
    if ($ExistingParts -notcontains $ap) {
        $NewParts += $ap
    }
}
if ($NewParts.Count -gt 0) {
    $Combined = ($NewParts + $ExistingParts) -join ";"
    [Environment]::SetEnvironmentVariable("PATH", $Combined, "User")
}

# Update current session Path
if ($env:Path -notlike "*$InstallDir*") {
    $env:Path = "$InstallDir;$InstallDir\client;" + $env:Path
}

# Check Python availability
if (-not (Get-Command "python" -ErrorAction SilentlyContinue) -and -not (Get-Command "py" -ErrorAction SilentlyContinue)) {
    Write-Host ""
    Write-Warning "Python 3 is not detected in your PATH."
    Write-Host "Please ensure Python 3 is installed (python.org or 'winget install Python.Python.3.11') with 'Add to PATH' enabled." -ForegroundColor Yellow
}

# Ensure no system-wide proxy is set in Windows User registry (keep all other apps 100% direct)
[Environment]::SetEnvironmentVariable('HTTP_PROXY', $null, 'User')
[Environment]::SetEnvironmentVariable('HTTPS_PROXY', $null, 'User')
[Environment]::SetEnvironmentVariable('http_proxy', $null, 'User')
[Environment]::SetEnvironmentVariable('https_proxy', $null, 'User')
[Environment]::SetEnvironmentVariable('AG_LS_PROXY', $null, 'User')
$env:HTTP_PROXY = $null
$env:HTTPS_PROXY = $null
$env:http_proxy = $null
$env:https_proxy = $null
$env:AG_LS_PROXY = $null
$env:PYTHONIOENCODING = "utf-8"

# Hook PowerShell Profile function so typing 'agy' always executes through smart proxy wrapper
$Docs = [Environment]::GetFolderPath("MyDocuments")
$HookBlock = @"

# >>> AGY_CLI_HOOK >>>
function agy {
    `$r = "`$HOME\.antigravity-bypass\client\agy-run.ps1"
    if (-not (Test-Path `$r)) { `$r = "`$HOME\.antigravity-bypass\agy-run.ps1" }
    if (Test-Path `$r) {
        & `$r @args
    } elseif (Get-Command "agy.cmd" -ErrorAction SilentlyContinue) {
        & (Get-Command "agy.cmd").Source @args
    } elseif (Get-Command "agy.real.exe" -ErrorAction SilentlyContinue) {
        & (Get-Command "agy.real.exe").Source @args
    }
}
# <<< AGY_CLI_HOOK <<<
"@

Write-Host "[2/3] Configuring environment & shell hooks..." -ForegroundColor Gray
$Docs = [Environment]::GetFolderPath("MyDocuments")
if (-not $Docs) { $Docs = "$env:USERPROFILE\Documents" }
$ProfPaths = @(
    "$Docs\WindowsPowerShell\Microsoft.PowerShell_profile.ps1",
    "$Docs\PowerShell\Microsoft.PowerShell_profile.ps1"
)
foreach ($ProfPath in $ProfPaths) {
    try {
        $pDir = Split-Path $ProfPath -Parent
        if (-not (Test-Path $pDir)) { New-Item -ItemType Directory -Path $pDir -Force | Out-Null }
        $curr = if (Test-Path $ProfPath) { Get-Content -Path $ProfPath -Raw -ErrorAction SilentlyContinue } else { "" }
        if ($curr -notmatch "AGY_CLI_HOOK") {
            Add-Content -Path $ProfPath -Value $HookBlock -Force
        }
    } catch {}
}

# Locate and rename agy.exe -> agy.real.exe across all standard directories and install wrappers
$CandDirs = @(
    "$env:LOCALAPPDATA\Programs\Antigravity\bin",
    "$env:USERPROFILE\.gemini\antigravity-cli\bin",
    "$env:USERPROFILE\.local\bin",
    "$InstallDir",
    "$InstallDir\client"
)
foreach ($cdir in $CandDirs) {
    if (Test-Path $cdir) {
        $realExe = Join-Path $cdir "agy.real.exe"
        $origExe = Join-Path $cdir "agy.exe"
        if ((Test-Path $origExe) -and -not (Test-Path $realExe)) {
            try {
                Get-Process -Name "language_server_windows_x64", "language_server", "agy" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
                Rename-Item -Path $origExe -NewName "agy.real.exe" -Force -ErrorAction SilentlyContinue
            } catch {}
        }
        # Copy agy-run wrapper files as agy.cmd and agy.ps1
        $srcAgyRun = Join-Path $InstallDir "client\agy-run.ps1"
        if (-not (Test-Path $srcAgyRun)) { $srcAgyRun = Join-Path $InstallDir "agy-run.ps1" }
        $srcAgyBat = Join-Path $InstallDir "client\agy-run.bat"
        if (-not (Test-Path $srcAgyBat)) { $srcAgyBat = Join-Path $InstallDir "agy-run.bat" }

        if (Test-Path $srcAgyRun) {
            Copy-Item -Path $srcAgyRun -Destination (Join-Path $cdir "agy.ps1") -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path $srcAgyBat) {
            Copy-Item -Path $srcAgyBat -Destination (Join-Path $cdir "agy.cmd") -Force -ErrorAction SilentlyContinue
            Copy-Item -Path $srcAgyBat -Destination (Join-Path $cdir "agy.bat") -Force -ErrorAction SilentlyContinue
        }
    }
}

# Register Windows boot autostart
$UpdaterScript = Join-Path $InstallDir "client\updater.py"
if (-not (Test-Path $UpdaterScript)) { $UpdaterScript = Join-Path $InstallDir "updater.py" }
if (Test-Path $UpdaterScript) {
    try {
        $PyCmd = if (Get-Command "python" -ErrorAction SilentlyContinue) { "python" } else { "py" }
        & $PyCmd -X utf8 $UpdaterScript --setup-boot | Out-Null
    } catch {}
}

# Deploy CLI process-local proxy wrappers via agy_ui.py --install
$AgyUiScript = Join-Path $InstallDir "client\agy_ui.py"
if (-not (Test-Path $AgyUiScript)) { $AgyUiScript = Join-Path $InstallDir "agy_ui.py" }
if (Test-Path $AgyUiScript) {
    try {
        $PyCmd = if (Get-Command "python" -ErrorAction SilentlyContinue) { "python" } else { "py" }
        & $PyCmd -X utf8 $AgyUiScript --install | Out-Null
    } catch {}
}

# Automatically configure binary patches and account eligibility unlock
Write-Host "[3/3] Verifying binary & applying unlock..." -ForegroundColor Gray
$PatcherScript = Join-Path $InstallDir "client\patch_account.py"
if (-not (Test-Path $PatcherScript)) { $PatcherScript = Join-Path $InstallDir "patch_account.py" }
if (Test-Path $PatcherScript) {
    try {
        $PyCmd = if (Get-Command "python" -ErrorAction SilentlyContinue) { "python" } else { "py" }
        & $PyCmd -X utf8 $PatcherScript | Out-Null
    } catch {}
}

Write-Host ""
Write-Host "[+] Installation complete! Ready to use." -ForegroundColor Green
Write-Host "    Type 'agy' to start." -ForegroundColor Yellow
