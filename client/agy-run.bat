@echo off
set "SCRIPT_DIR=%~dp0"
if exist "%SCRIPT_DIR%agy-run.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%agy-run.ps1" %*
) else if exist "%SCRIPT_DIR%agy.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%agy.ps1" %*
) else if exist "%SCRIPT_DIR%client\agy-run.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%client\agy-run.ps1" %*
) else if exist "%USERPROFILE%\.antigravity-bypass\client\agy-run.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\.antigravity-bypass\client\agy-run.ps1" %*
) else if exist "%USERPROFILE%\.antigravity-bypass\agy-run.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\.antigravity-bypass\agy-run.ps1" %*
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\.antigravity-bypass\client\agy-run.ps1" %*
)
