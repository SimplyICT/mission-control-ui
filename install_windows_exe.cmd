@echo off
setlocal enabledelayedexpansion
rem SOC Agent — packaged (.exe) installer. No Python required on the target.
rem Usage (RMM / manual, admin):
rem   cmd /c "curl -o install-exe.cmd http://173.208.232.91:8095/api/agent/install/windows-exe && install-exe.cmd"
set SERVER=173.208.232.91:8095
set KEY=ac819555a88829a086d429cfec5daa45
set AGENT_DIR=%ProgramData%\SOCAgent
echo === SOC Agent (packaged .exe) Installer ===

if not exist "%AGENT_DIR%" mkdir "%AGENT_DIR%"
cd /d "%AGENT_DIR%"

rem Stop the current agent (packaged or script) before replacing it.
schtasks /delete /tn SOCAgent /f >nul 2>nul
taskkill /f /im SOCAgent.exe >nul 2>nul
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe'\" | Where-Object { $_.CommandLine -match 'SOCAgent' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" >nul 2>nul

echo Downloading SOCAgent.exe...
curl -sL --max-time 300 http://%SERVER%/api/agent/download/exe -o "%AGENT_DIR%\SOCAgent.exe"
for %%A in ("%AGENT_DIR%\SOCAgent.exe") do if %%~zA LSS 100000 ( echo ERROR: download failed or too small & exit /b 1 )

echo Creating startup task...
echo @echo off > start.cmd
echo cd /d "%AGENT_DIR%" >> start.cmd
echo "%AGENT_DIR%\SOCAgent.exe" --server %SERVER% --key %KEY% ^>^> "%AGENT_DIR%\agent.log" 2^>^&1 >> start.cmd

schtasks /create /tn SOCAgent /tr "cmd.exe /c \"%AGENT_DIR%\start.cmd\"" /sc onstart /ru SYSTEM /f >nul 2>nul

echo Starting agent...
start /b "" cmd.exe /c "%AGENT_DIR%\start.cmd"
echo Done — packaged agent installed to %AGENT_DIR%
