@echo off
setlocal enabledelayedexpansion
set SERVER=173.208.232.91:8095
set KEY=ac819555a88829a086d429cfec5daa45
set AGENT_DIR=%ProgramData%\SOCAgent
echo === SOC Agent Installer ===

if not exist "%AGENT_DIR%" mkdir "%AGENT_DIR%"
cd /d "%AGENT_DIR%"

sc delete SOCAgent >nul 2>nul
schtasks /delete /tn SOCAgent /f >nul 2>nul

del "%LOCALAPPDATA%\Microsoft\WindowsApps\python.exe" 2>nul
del "%LOCALAPPDATA%\Microsoft\WindowsApps\python3.exe" 2>nul

set PY_CMD=
if exist "C:\Program Files\Python312\python.exe" set PY_CMD="C:\Program Files\Python312\python.exe"
if "!PY_CMD!"=="" (
  python --version >nul 2>nul
  if not errorlevel 1 set PY_CMD="python"
)
if "!PY_CMD!"=="" (
  py -3.12 --version >nul 2>nul
  if not errorlevel 1 set PY_CMD="py -3.12"
)

if not "!PY_CMD!"=="" goto :install

echo Downloading Python 3.12 (25MB)...
curl -sL --max-time 120 https://www.python.org/ftp/python/3.12.5/python-3.12.5-amd64.exe -o "%TEMP%\py-installer.exe"
echo Installing Python...
"%TEMP%\py-installer.exe" /quiet InstallAllUsers=1 PrependPath=1 Include_test=0
set PATH=%PATH%;C:\Program Files\Python312
if exist "C:\Program Files\Python312\python.exe" ( set PY_CMD="C:\Program Files\Python312\python.exe" ) else ( set PY_CMD="python" )
del "%TEMP%\py-installer.exe" 2>nul

:install
if "!PY_CMD!"=="" ( echo ERROR: Python not found & exit /b 1 )
echo Python found

echo Downloading agent...
curl -sL http://%SERVER%/api/agent/download/windows -o agent.py

echo Installing aiohttp...
%PY_CMD% -m pip install aiohttp -q
if errorlevel 1 (
  echo pip failed, trying --break-system-packages...
  %PY_CMD% -m pip install aiohttp --break-system-packages -q
)
if errorlevel 1 (
  echo Trying python -m pip...
  python -m pip install aiohttp -q
)

echo Creating startup task...
del start.cmd 2>nul
echo @echo off >> start.cmd
echo cd /d "%AGENT_DIR%" >> start.cmd
echo "%PY_CMD%" agent.py --server %SERVER% --key %KEY% >> start.cmd
schtasks /create /tn SOCAgent /tr "cmd.exe /c \"%AGENT_DIR%\start.cmd\"" /sc onstart /ru SYSTEM /f >nul 2>nul

echo Starting agent...
start /b "" cmd.exe /c "%AGENT_DIR%\start.cmd"
echo Done
