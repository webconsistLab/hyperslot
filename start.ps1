# start.ps1 — Parent launcher
# Location: D:\HyperSlot\start.ps1

param(
    [Parameter(Mandatory=$true)]
    [string]$Source,

    [string]$ExtractorListen = "127.0.0.1:1111",
    [string]$LocalPoolPort = "2222",
    [string]$PanelPort = "8080",
    [string]$MaxWait = "30m",
    [switch]$KeepInfra
)

$ErrorActionPreference = "Stop"

$rootDir      = $PSScriptRoot
$extractorDir = Join-Path $rootDir "oee"
$panelDir     = Join-Path $rootDir "hyperpanel"
$poolDir      = Join-Path $rootDir "local-pool"

# ── Verify ──
foreach ($d in @($extractorDir, $panelDir, $poolDir)) {
    if (-not (Test-Path $d)) {
        Write-Host "[LAUNCHER] ❌ Not found: $d" -ForegroundColor Red
        exit 1
    }
}

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " 🚀 HyperSlot Parallel Launch" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host " Root        : $rootDir"
Write-Host " Extractor   : $extractorDir"
Write-Host " Local Pool  : $poolDir"
Write-Host " Panel       : $panelDir"
Write-Host " Source      : $Source"
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# ═══════════════════════════════════════════════════════════
# 1. Extractor background-এ
# ═══════════════════════════════════════════════════════════
Write-Host "[LAUNCHER] Starting extractor (oee)..." -ForegroundColor Yellow

$extractorArgs = @("run", ".", "-source", $Source, "-listen", $ExtractorListen, "-max-wait", $MaxWait)
if ($KeepInfra) { $extractorArgs += "-keep-infra" }

$extractorProcess = Start-Process -FilePath "go" `
    -ArgumentList $extractorArgs `
    -WorkingDirectory $extractorDir `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $rootDir "extractor.log") `
    -RedirectStandardError  (Join-Path $rootDir "extractor.err.log")

Write-Host "[LAUNCHER] ✅ Extractor PID: $($extractorProcess.Id)" -ForegroundColor Green

# ═══════════════════════════════════════════════════════════
# 2. Local Pool background-এ
# ═══════════════════════════════════════════════════════════
Write-Host "[LAUNCHER] Starting local-pool on :$LocalPoolPort..." -ForegroundColor Yellow

$poolProcess = Start-Process -FilePath "go" `
    -ArgumentList @("run", ".") `
    -WorkingDirectory $poolDir `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput (Join-Path $rootDir "pool.log") `
    -RedirectStandardError  (Join-Path $rootDir "pool.err.log")

Write-Host "[LAUNCHER] ✅ Local Pool PID: $($poolProcess.Id)" -ForegroundColor Green

Start-Sleep -Seconds 2

# ═══════════════════════════════════════════════════════════
# 3. Hyper Panel foreground-এ
# ═══════════════════════════════════════════════════════════
Write-Host "[LAUNCHER] Starting hyper-panel..." -ForegroundColor Yellow
Write-Host ""
Write-Host "[LAUNCHER] 🚀 All running. Press Ctrl+C to stop all." -ForegroundColor Green
Write-Host ""

Push-Location $panelDir

try {
    $env:EXTRACTOR_URL = "http://$ExtractorListen"
    go run . -port ":$PanelPort"
}
finally {
    Pop-Location

    Write-Host ""
    Write-Host "[LAUNCHER] Shutting down..." -ForegroundColor Yellow
    Stop-Process -Id $extractorProcess.Id -Force -ErrorAction SilentlyContinue
    Stop-Process -Id $poolProcess.Id -Force -ErrorAction SilentlyContinue
    Write-Host "[LAUNCHER] Done." -ForegroundColor Cyan
}