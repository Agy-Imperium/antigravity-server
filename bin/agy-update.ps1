$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
$TargetPy = if (Test-Path "$ScriptDir\updater.py") { "$ScriptDir\updater.py" } else { "$ScriptDir\client\updater.py" }
$PyCmd = if (Get-Command "python" -ErrorAction SilentlyContinue) { "python" } else { "py" }
& $PyCmd $TargetPy @args
