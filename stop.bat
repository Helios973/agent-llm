@echo off
setlocal

cd /d "%~dp0"

set "PYTHON_CMD="
where py >nul 2>nul
if %errorlevel%==0 set "PYTHON_CMD=py -3"

if not defined PYTHON_CMD (
    where python >nul 2>nul
    if %errorlevel%==0 set "PYTHON_CMD=python"
)

if not defined PYTHON_CMD (
    echo Python 3.12+ was not found.
    echo Install Python first or set PYTHON_EXECUTABLE in .env.
    pause
    exit /b 1
)

%PYTHON_CMD% dev.py stop
set "EXIT_CODE=%errorlevel%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo AuditPilot failed to stop cleanly.
    pause
    exit /b %EXIT_CODE%
)

echo.
echo AuditPilot has been stopped.
pause
