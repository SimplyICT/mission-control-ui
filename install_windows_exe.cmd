@echo off
setlocal enabledelayedexpansion
rem SOC Agent -- packaged (.exe) installer. No Python required on the target.
rem Usage (RMM / manual, admin):
rem   cmd /c "curl -o install-exe.cmd http://173.208.232.91:8095/api/agent/install/windows-exe && install-exe.cmd"
set SERVER=173.208.232.91:8095
set KEY=ac819555a88829a086d429cfec5daa45
set AGENT_DIR=%ProgramData%\SOCAgent
echo === SOC Agent (packaged .exe) Installer ===

if not exist "%AGENT_DIR%" mkdir "%AGENT_DIR%"
cd /d "%AGENT_DIR%"

rem Stop the current agent (packaged or script) before replacing it. The script
rem agent's command line is "<python> agent.py --server ...", so matching on
rem 'SOCAgent' alone misses it and the old process keeps the WebSocket, which made
rem an "installed" run look like a no-op in the console.
schtasks /delete /tn SOCAgent /f >nul 2>nul
taskkill /f /im SOCAgent.exe >nul 2>nul
sc stop SOCAgent >nul 2>nul
sc delete SOCAgent >nul 2>nul
powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='python.exe' or Name='pythonw.exe' or Name='SOCAgent.exe'\" | Where-Object { $_.CommandLine -match 'agent\.py|SOCAgent' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }" >nul 2>nul
timeout /t 2 /nobreak >nul 2>nul

echo Downloading SOCAgent.exe...
call :download "http://%SERVER%/api/agent/download/exe" "%AGENT_DIR%\SOCAgent.exe"
if errorlevel 1 exit /b 1
for %%A in ("%AGENT_DIR%\SOCAgent.exe") do if %%~zA LSS 100000 ( echo ERROR: download failed or too small & exit /b 1 )

echo Creating startup task...
echo @echo off > start.cmd
echo cd /d "%AGENT_DIR%" >> start.cmd
echo "%AGENT_DIR%\SOCAgent.exe" --server %SERVER% --key %KEY% ^>^> "%AGENT_DIR%\agent.log" 2^>^&1 >> start.cmd

rem Repeat trigger, not just onstart: a crash or a killed process then recovers on its
rem own within five minutes instead of waiting for the next reboot.
schtasks /create /tn SOCAgent /tr "cmd.exe /c \"%AGENT_DIR%\start.cmd\"" /sc minute /mo 5 /ru SYSTEM /f >nul 2>nul

echo Starting agent...
rem Start through the Task Scheduler: a child of this installer dies with the RMM
rem session, and the task is onstart-only, so the host would keep the old agent
rem until the next reboot. /run starts it detached, as SYSTEM.
schtasks /run /tn SOCAgent >nul 2>nul
if errorlevel 1 start /b "" cmd.exe /c "%AGENT_DIR%\start.cmd"
echo Done -- packaged agent installed to %AGENT_DIR%

rem ---------------------------------------------------------------------------
rem Download helper. Some endpoints cannot download with the usual tools: an old
rem curl fails to open a socket at all (getsockname errno 10022) and certutil
rem -urlcache is blocked by policy as a LOLBin. Try each stack the host has and
rem keep the first that produces a real file.

exit /b 0

:download
set "DL_URL=%~1"
set "DL_DEST=%~2"
if exist "%DL_DEST%" del "%DL_DEST%" >nul 2>&1
curl.exe -sSL --max-time 300 "%DL_URL%" -o "%DL_DEST%" >nul 2>&1
if exist "%DL_DEST%" for %%A in ("%DL_DEST%") do if %%~zA GTR 1000 goto :eof
certutil -urlcache -split -f "%DL_URL%" "%DL_DEST%" >nul 2>&1
if exist "%DL_DEST%" for %%A in ("%DL_DEST%") do if %%~zA GTR 1000 goto :eof
powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing '%DL_URL%' -OutFile '%DL_DEST%'" >nul 2>&1
if exist "%DL_DEST%" for %%A in ("%DL_DEST%") do if %%~zA GTR 1000 goto :eof
echo ERROR: could not download %DL_URL%
exit /b 1
