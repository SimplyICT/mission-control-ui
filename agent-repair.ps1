<#
  SOC agent repair -- find out why a Windows host is not running the agent, and optionally fix it.

  Report-only by default; nothing is changed without -Fix.

  Run (RMM as SYSTEM, or an elevated prompt):
    cmd /c "curl -o %TEMP%\agent-repair.ps1 http://173.208.232.91:8095/api/agent/tools/agent-repair.ps1"
    powershell -NoProfile -ExecutionPolicy Bypass -File %TEMP%\agent-repair.ps1            # diagnose
    powershell -NoProfile -ExecutionPolicy Bypass -File %TEMP%\agent-repair.ps1 -Fix       # repair

  Why this exists: installers were seen completing (files present, correct version) while the
  agent never started -- the scheduled task stayed "Queued" and agent.log stopped. This reports
  the task state, process state, Defender history and a bounded foreground run, then (with -Fix)
  re-creates the task with a repeating trigger, starts it and verifies.
#>
param(
    [switch]$Fix,
    [string]$Server = "173.208.232.91:8095",
    [string]$Key = "ac819555a88829a086d429cfec5daa45",
    [string]$Dir = "C:\ProgramData\SOCAgent"
)

$ErrorActionPreference = "Continue"
function Say($m) { Write-Output $m }

Say "=== SOC agent repair -- $env:COMPUTERNAME -- $(Get-Date -Format s) ==="
if ($Fix) { Say "mode: FIX (changes will be applied)" } else { Say "mode: REPORT ONLY (add -Fix to apply)" }
Say ""

# -- 1. files -------------------------------------------------------------
Say "--- files in $Dir ---"
if (Test-Path $Dir) {
    Get-ChildItem $Dir | Select-Object Name, Length, LastWriteTime | ForEach-Object {
        Say ("  {0,-14} {1,12}  {2}" -f $_.Name, $_.Length, $_.LastWriteTime)
    }
} else {
    Say "  MISSING -- the installer never completed here"
}

$exe = Join-Path $Dir "SOCAgent.exe"
$py  = Join-Path $Dir "agent.py"
$startCmd = Join-Path $Dir "start.cmd"
if (Test-Path $startCmd) { Say "--- start.cmd ---"; Get-Content $startCmd | ForEach-Object { Say "  $_" } }

# -- 2. task --------------------------------------------------------------
Say ""
Say "--- scheduled task SOCAgent ---"
$q = schtasks /query /tn SOCAgent /v /fo LIST 2>&1
if ($LASTEXITCODE -ne 0) {
    Say "  task NOT PRESENT ($q)"
} else {
    $q | Where-Object { $_ -match "TaskName|Status|Last Run Time|Last Result|Run As User|Task To Run|Schedule Type|Start In|Repeat" } | ForEach-Object { Say "  $_" }
}

# -- 3. processes ---------------------------------------------------------
Say ""
Say "--- running agent processes ---"
$procs = Get-CimInstance Win32_Process -Filter "Name='SOCAgent.exe' or Name='python.exe' or Name='pythonw.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'SOCAgent|agent\.py' }
if ($procs) {
    $procs | ForEach-Object { Say ("  pid {0} {1} :: {2}" -f $_.ProcessId, $_.Name, $_.CommandLine) }
} else {
    Say "  none"
}

# -- 4. agent log ---------------------------------------------------------
$log = Join-Path $Dir "agent.log"
Say ""
Say "--- agent.log (last write + last 15 lines) ---"
if (Test-Path $log) {
    $f = Get-Item $log
    Say ("  size {0:N0} bytes, last written {1}" -f $f.Length, $f.LastWriteTime)
    Get-Content $log -Tail 15 | ForEach-Object { Say "  $_" }
} else {
    Say "  no agent.log -- the agent has never run from $Dir"
}

# -- 5. Defender ----------------------------------------------------------
Say ""
Say "--- Microsoft Defender ---"
try {
    $pref = Get-MpPreference -ErrorAction Stop
    Say ("  exclusions -- paths: {0} | processes: {1}" -f (($pref.ExclusionPath -join '; ')), (($pref.ExclusionProcess -join '; ')))
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Where-Object { ($_.Resources -join ' ') -match 'SOCAgent|agent\.py' } | Select-Object -First 5
    if ($threats) {
        Say "  DETECTIONS recorded for the agent:"
        $threats | ForEach-Object { Say ("    {0}  {1}  {2}" -f $_.InitialDetectionTime, $_.ThreatID, ($_.Resources -join ',')) }
    } else {
        Say "  no detections mentioning the agent"
    }
} catch {
    Say "  Defender cmdlets unavailable: $($_.Exception.Message)"
}

# -- 6. bounded foreground run (proves whether the binary itself works) ---
Say ""
Say "--- 15 s foreground run ---"
$target = if (Test-Path $exe) { $exe } elseif (Test-Path $py) { $py } else { $null }
if (-not $target) {
    Say "  nothing to run -- no SOCAgent.exe and no agent.py"
} else {
    $out = Join-Path $env:TEMP "socagent-fg.out"
    $err = Join-Path $env:TEMP "socagent-fg.err"
    Remove-Item $out, $err -ErrorAction SilentlyContinue
    if ($target -eq $exe) {
        $p = Start-Process -FilePath $exe -ArgumentList @("--server", $Server, "--key", $Key) -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
    } else {
        $p = Start-Process -FilePath "python" -ArgumentList @($py, "--server", $Server, "--key", $Key) -PassThru -WindowStyle Hidden -RedirectStandardOutput $out -RedirectStandardError $err
    }
    Start-Sleep -Seconds 15
    if ($p -and -not $p.HasExited) {
        Say "  RESULT: the agent RUNS when started directly (pid $($p.Id)) -- the binary is fine, the task is the problem"
        if ($Fix) { Say "  (leaving it running; -Fix also re-creates the task)" }
    } else {
        Say ("  RESULT: the agent EXITED immediately (code {0}) -- this is why it never connects" -f $p.ExitCode)
    }
    if (Test-Path $out) { Say "  stdout:"; Get-Content $out -Tail 15 | ForEach-Object { Say "    $_" } }
    if (Test-Path $err) { Say "  stderr:"; Get-Content $err -Tail 15 | ForEach-Object { Say "    $_" } }
}

# -- 7. fixes -------------------------------------------------------------
if (-not $Fix) {
    Say ""
    Say "Report only. Re-run with -Fix to apply: Defender exclusions, task re-create (5-minute repeat trigger), start, verify."
    exit 0
}

Say ""
Say "--- applying fixes ---"

try {
    Add-MpPreference -ExclusionPath $Dir -ErrorAction Stop
    Add-MpPreference -ExclusionProcess "SOCAgent.exe" -ErrorAction Stop
    Say "  Defender exclusions added for $Dir and SOCAgent.exe"
} catch {
    Say "  could not add Defender exclusions: $($_.Exception.Message)"
}

if (-not (Test-Path $startCmd)) {
    if (Test-Path $exe) {
        "@echo off`r`ncd /d `"$Dir`"`r`n`"$exe`" --server $Server --key $Key >> `"$Dir\agent.log`" 2>&1" | Set-Content -Path $startCmd -Encoding ASCII
    } else {
        "@echo off`r`ncd /d `"$Dir`"`r`npython `"$py`" --server $Server --key $Key >> `"$Dir\agent.log`" 2>&1" | Set-Content -Path $startCmd -Encoding ASCII
    }
    Say "  start.cmd written"
}

# Stop whatever half-running instance exists, then re-create the task with a
# repeating trigger so a host that fails to start is retried instead of waiting
# for a reboot (the old task was onstart-only).
schtasks /delete /tn SOCAgent /f > $null 2>&1
taskkill /f /im SOCAgent.exe > $null 2>&1
if ($procs) { $procs | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } }
Start-Sleep -Seconds 2

# Build the /tr value as one string: PowerShell does not treat \" as an escape,
# so interpolating quotes inline is unreliable on older hosts.
$tr = 'cmd.exe /c "' + $startCmd + '"'
schtasks /create /tn SOCAgent /tr $tr /sc minute /mo 5 /ru SYSTEM /f > $null 2>&1
if ($LASTEXITCODE -eq 0) { Say "  task re-created (every 5 minutes, as SYSTEM)" } else { Say "  task create FAILED -- create it manually from an elevated prompt" }
schtasks /run /tn SOCAgent > $null 2>&1

Say "  waiting 25 s for the agent to register..."
Start-Sleep -Seconds 25
$now = Get-CimInstance Win32_Process -Filter "Name='SOCAgent.exe' or Name='python.exe'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'SOCAgent|agent\.py' }
if ($now) {
    Say ("  RESULT: agent running (pid {0})" -f ($now[0].ProcessId))
} else {
    Say "  RESULT: still not running -- check the task's Last Run Result above and any AV/AppLocker policy that blocks execution from $Dir"
}
if (Test-Path $log) { Say "  agent.log tail:"; Get-Content $log -Tail 8 | ForEach-Object { Say "    $_" } }
Say ""
Say "When it works the host shows up in the SOC Agents page within a minute (WS + check-in)."
