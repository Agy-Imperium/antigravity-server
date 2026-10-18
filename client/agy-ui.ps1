$ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $PSCommandPath }
$TargetPy = if (Test-Path "$ScriptDir\agy_ui.py") { "$ScriptDir\agy_ui.py" } else { "$ScriptDir\client\agy_ui.py" }
$PyCmd = if (Get-Command "python" -ErrorAction SilentlyContinue) { "python" } else { "py" }
& $PyCmd $TargetPy @args
