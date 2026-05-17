@echo off
setlocal

echo ============================================================
echo   Voidwatch Agent Installer
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH.
    echo Download Python from https://python.org and try again.
    pause & exit /b 1
)

REM Install dependencies
echo Installing dependencies...
pip install -r "%~dp0requirements.txt" -q
if errorlevel 1 (
    echo ERROR: Failed to install dependencies.
    pause & exit /b 1
)

REM Prompt for server URL
set /p SERVER_URL="Enter server URL [http://localhost:8000]: "
if "%SERVER_URL%"=="" set SERVER_URL=http://localhost:8000

REM Prompt for enrollment token
set /p ENROLL_TOKEN="Enter enrollment token (leave blank to use API key): "

if not "%ENROLL_TOKEN%"=="" (
    echo.
    echo Enrolling agent with server...
    python "%~dp0enroll.py" "%SERVER_URL%" "%ENROLL_TOKEN%"
    if errorlevel 1 (
        echo ERROR: Enrollment failed. Check token and server URL.
        pause & exit /b 1
    )
) else (
    set /p API_KEY="Enter API key: "
    REM Write config
    echo { > "%~dp0config.json"
    echo   "server_url": "%SERVER_URL%", >> "%~dp0config.json"
    echo   "api_key": "%API_KEY%", >> "%~dp0config.json"
    echo   "mode": "detect" >> "%~dp0config.json"
    echo } >> "%~dp0config.json"
)

REM Install as Windows scheduled task
echo.
echo Installing as Windows Scheduled Task...
schtasks /create /tn "VoidwatchAgent" /tr "python \"%~dp0main.py\"" /sc onlogon /rl highest /f >nul 2>&1
if errorlevel 1 (
    echo WARNING: Could not create scheduled task. Run as Administrator for auto-start.
) else (
    echo Scheduled task created — agent will start on logon.
)

REM Start agent now
echo.
echo Starting Voidwatch Agent...
start /min "VoidwatchAgent" python "%~dp0main.py"

echo.
echo ============================================================
echo   Voidwatch Agent installed successfully.
echo ============================================================
pause
