# AegisCloud AI - start everything with one command.
#
#   cd C:\Users\dell\Desktop\aegiscloud-ai
#   . .\start-all.ps1 -WithAttack
#
# Keep the dot and the space at the start (dot-sourcing), so the access keys created by
# start-lab.ps1 stay available in this window for the attack scripts.
#
#   -WithAttack   also runs attack 1 once the lab is up (creates a fresh incident)

param([switch]$WithAttack)

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

function Test-Port($port) {
    return [bool](Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
}

function Test-Running($pattern) {
    $hit = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and $_.CommandLine -like "*$pattern*" -and $_.Name -like "python*" }
    return [bool]$hit
}

function Open-Window($title, $dir, $command) {
    $cmd = "`$Host.UI.RawUI.WindowTitle = '$title'; Set-Location '$dir'; $command"
    Start-Process powershell -ArgumentList '-NoExit', '-Command', $cmd | Out-Null
    Write-Host "  started: $title"
}

# ---- 1. the lab (containers, cloud resources, keys, backend, incident engine) ----
Write-Host ""
Write-Host "== Step 1 of 3: starting the lab (this is your existing start-lab.ps1) =="
if ($WithAttack) { . "$root\start-lab.ps1" -WithAttack } else { . "$root\start-lab.ps1" }
Set-Location $root

# ---- 2. services that sit on top of the lab ----
Write-Host ""
Write-Host "== Step 2 of 3: starting the pipeline, the dashboard API and the dashboard =="

if (Test-Running "pipeline.py") {
    Write-Host "  already running: pipeline (skipped)"
} else {
    Open-Window "AegisCloud pipeline" "$root\incident-engine" "..\backend\venv\Scripts\python.exe pipeline.py"
}

if (Test-Port 8001) {
    Write-Host "  already running: dashboard API on port 8001 (skipped)"
} else {
    Open-Window "AegisCloud dashboard API" "$root\backend" ".\venv\Scripts\python.exe -m uvicorn dashboard_api:app --reload --port 8001"
}

if (Test-Port 5173) {
    Write-Host "  already running: dashboard on port 5173 (skipped)"
} else {
    Open-Window "Kestrel dashboard" "$root\dashboard" "npm run dev"
}

# ---- 3. wait until the dashboard answers, then open it ----
Write-Host ""
Write-Host "== Step 3 of 3: waiting for the dashboard =="
$ready = $false
for ($i = 0; $i -lt 40; $i++) {
    try {
        $r = Invoke-WebRequest -UseBasicParsing -Uri "http://localhost:5173/dash/health" -TimeoutSec 2
        if ($r.StatusCode -eq 200) { $ready = $true; break }
    } catch { }
    Start-Sleep -Seconds 2
}
if ($ready) {
    Write-Host "  dashboard is up: http://localhost:5173"
    Start-Process "http://localhost:5173"
} else {
    Write-Host "  the dashboard did not answer yet. Check the 'Kestrel dashboard' and 'dashboard API' windows for errors."
}

Write-Host ""
Write-Host "Done. New incidents are analysed automatically (see the 'AegisCloud pipeline' window)."
Write-Host "Stop everything: Ctrl+C in each window, then  .\stop-lab.ps1"
