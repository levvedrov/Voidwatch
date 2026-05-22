@echo off
setlocal

echo ============================================================
echo   Voidwatch Agent Installer
echo ============================================================
echo.

REM Build if exe missing
if not exist "%~dp0voidwatch_agent.exe" (
    echo voidwatch_agent.exe not found. Attempting to build...
    call "%~dp0compile.bat"
    if not exist "%~dp0voidwatch_agent.exe" (
        echo ERROR: Build failed. Cannot install.
        pause & exit /b 1
    )
)

REM Prompt for server URL
set /p SERVER_URL="Enter server URL [http://localhost:8000]: "
if "%SERVER_URL%"=="" set SERVER_URL=http://localhost:8000

REM Prompt for enrollment token
set /p ENROLL_TOKEN="Enter enrollment token (leave blank to use API key): "

if not "%ENROLL_TOKEN%"=="" (
    echo.
    echo Enrolling agent with server...
    "%~dp0voidwatch_agent.exe" --enroll "%SERVER_URL%" "%ENROLL_TOKEN%"
    if errorlevel 1 (
        echo ERROR: Enrollment failed. Check token and server URL.
        pause & exit /b 1
    )
) else (
    set /p API_KEY="Enter API key (leave blank for none): "
    REM Write config.json
    (
        echo {
        echo   "server_url": "%SERVER_URL%",
        echo   "api_key": "%API_KEY%",
        echo   "mode": "detect",
        echo   "collection_interval": 5,
        echo   "collect_command_line": true,
        echo   "collect_network": true,
        echo   "anonymize_paths": false
        echo }
    ) > "%~dp0config.json"
)

REM Install as Windows scheduled task (runs on logon, highest privilege)
echo.
echo Installing as Windows Scheduled Task...
schtasks /create /tn "VoidwatchAgent" /tr "\"%~dp0voidwatch_agent.exe\"" /sc onlogon /rl highest /f >nul 2>&1
if errorlevel 1 (
    echo WARNING: Could not create scheduled task. Run as Administrator for auto-start.
) else (
    echo Scheduled task created — agent will start on next logon.
)

REM Start agent immediately in background
echo.
echo Starting Voidwatch Agent...
start /min "VoidwatchAgent" "%~dp0voidwatch_agent.exe"

echo.
echo ============================================================
echo   Voidwatch Agent installed successfully.
echo ============================================================
pause
