# Build the Windows SOC Agent as a standalone .exe (PyInstaller).
#
# Run on any Windows machine with Python (the SOC's own admin box is fine); the
# result is uploaded to the SOC server and published to packaged agents.
#
#   powershell -ExecutionPolicy Bypass -File build_windows_exe.ps1
#   powershell -ExecutionPolicy Bypass -File build_windows_exe.ps1 -Server 173.208.232.91:8095
#
# The version is read from the agent being built, so the server can tell agents
# whether their .exe is current (a compiled binary cannot be parsed for it).

param(
  [string]$Server = "173.208.232.91:8095",
  [switch]$KeepBuildDir
)

$ErrorActionPreference = "Stop"
# PyInstaller refuses to run from a directory whose name looks like a build output,
# so build in a plain workspace directory instead of a *-build temp path.
$BuildDir = Join-Path $env:ProgramData "socagent-exe"
$AgentScript = Join-Path $BuildDir "agent.py"
$ExePath = Join-Path $BuildDir "dist\SOCAgent.exe"

Write-Host "=== Building SOC Agent .exe from $Server ===" -ForegroundColor Cyan

if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
New-Item -ItemType Directory -Force -Path $BuildDir | Out-Null
Set-Location $BuildDir

Write-Host "[..] Downloading agent script..." -ForegroundColor Yellow
Invoke-WebRequest -Uri "http://$Server/api/agent/download/windows" -OutFile $AgentScript

$Version = (Select-String -Path $AgentScript -Pattern '^AGENT_VERSION\s*=\s*"([^"]+)"').Matches[0].Groups[1].Value
if (-not $Version) { Write-Host "ERROR: could not read AGENT_VERSION" -ForegroundColor Red; exit 1 }
Write-Host "[OK] Agent version $Version"

try { pyinstaller --version | Out-Null } catch {
  Write-Host "[..] Installing PyInstaller..." -ForegroundColor Yellow
  python -m pip install --quiet --upgrade pyinstaller
}

Write-Host "[..] Building SOCAgent.exe (this takes a few minutes)..." -ForegroundColor Yellow
python -m PyInstaller --onefile --console --name SOCAgent --noconfirm --clean `
  --hidden-import aiohttp --hidden-import aiohttp.web --hidden-import aiohttp.http_writer `
  --collect-submodules aiohttp $AgentScript
if (-not (Test-Path $ExePath)) { Write-Host "ERROR: build failed" -ForegroundColor Red; exit 1 }

$Hash = (Get-FileHash -Algorithm SHA256 $ExePath).Hash.ToLower()
$Size = (Get-Item $ExePath).Length
Write-Host "[OK] Built $ExePath ($Size bytes, sha256 $Hash)" -ForegroundColor Green

Write-Host "[..] Uploading to $Server ..." -ForegroundColor Yellow
# curl first (reliable under PowerShell 5.1 and when the caller kills the shell
# late), Invoke-RestMethod -Form as the fallback.
$Uploaded = $false
& curl.exe -sS --max-time 300 -X POST -F "file=@$ExePath" -F "version=$Version" "http://$Server/api/agent/upload-exe"
if ($LASTEXITCODE -eq 0) { $Uploaded = $true }
if (-not $Uploaded) {
  try {
    $Form = @{ file = Get-Item -Path $ExePath; version = $Version }
    $Result = Invoke-RestMethod -Uri "http://$Server/api/agent/upload-exe" -Method Post -Form $Form
    $Uploaded = $true
    Write-Host "[OK] Uploaded (fallback): $($Result | ConvertTo-Json -Compress)" -ForegroundColor Green
  } catch {
    Write-Host "[WARN] Upload failed: $_" -ForegroundColor Yellow
    Write-Host "       Local build kept at: $ExePath" -ForegroundColor Yellow
    Write-Host ('       Manual upload: curl.exe -X POST -F "file=@' + $ExePath + '" -F "version=' + $Version + '" http://' + $Server + '/api/agent/upload-exe') -ForegroundColor Yellow
  }
}

if ($Uploaded -and -not $KeepBuildDir) { Remove-Item -Recurse -Force $BuildDir }
Write-Host "=== Done - packaged agent v$Version is published ===" -ForegroundColor Cyan
