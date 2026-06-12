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

%PYTHON_CMD% dev.py start --open-browser
set "EXIT_CODE=%errorlevel%"

if not "%EXIT_CODE%"=="0" (
    echo.
    echo AuditPilot failed to start.
    pause
    exit /b %EXIT_CODE%
)

echo.
echo AuditPilot is starting in the background.
echo Frontend: http://127.0.0.1:3000
echo Admin:    http://127.0.0.1:3000/admin.html
echo Backend:  http://127.0.0.1:8000
echo.
pause
