@echo off
set "SCRIPT_DIR=%~dp0"
set "PY_CMD=python"
where python >nul 2>nul
if %errorlevel% neq 0 (
    where py >nul 2>nul
    if %errorlevel% equ 0 (
        set "PY_CMD=py"
    )
)
if exist "%SCRIPT_DIR%updater.py" (
    %PY_CMD% "%SCRIPT_DIR%updater.py" %*
) else (
    %PY_CMD% "%SCRIPT_DIR%client\updater.py" %*
)
