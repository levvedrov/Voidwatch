@echo off
echo Stopping Voidwatch Agent...
taskkill /f /im python.exe /fi "WINDOWTITLE eq VoidwatchAgent" >nul 2>&1
schtasks /delete /tn "VoidwatchAgent" /f >nul 2>&1
del /q "%~dp0.agent_id" >nul 2>&1
del /q "%~dp0.agent_secret" >nul 2>&1
echo Voidwatch Agent uninstalled.
pause
