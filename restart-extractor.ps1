# D:\HyperSlot\restart-extractor.ps1
param(
    [string]$Source  = "https://hypers.com.bd/slot.html",
    [string]$Listen  = "127.0.0.1:1111",
    [string]$MaxWait = "30m"
)

$rootDir = $PSScriptRoot
$oeeDir  = Join-Path $rootDir "oee"

Write-Host "[1/3] Killing old extractor on port 1111..."
Get-NetTCPConnection -LocalPort 1111 -State Listen -ErrorAction SilentlyContinue | ForEach-Object {
    Write-Host "  → kill PID $($_.OwningProcess)"
    Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
}
Get-Process | Where-Object { $_.Path -like "*\oee\*" -or $_.ProcessName -eq "main" } |
    Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

Write-Host "[2/3] Starting new extractor..."
$logFile = Join-Path $rootDir "extractor.log"
$errFile = Join-Path $rootDir "extractor.err.log"

# Log truncate (append mode চাইলে Remove-Item বাদ দিন)
if (Test-Path $logFile) { Remove-Item $logFile -Force -ErrorAction SilentlyContinue }
if (Test-Path $errFile) { Remove-Item $errFile -Force -ErrorAction SilentlyContinue }

$proc = Start-Process -FilePath "go" `
    -ArgumentList @("run", ".", "-source", $Source, "-listen", $Listen, "-max-wait", $MaxWait) `
    -WorkingDirectory $oeeDir `
    -PassThru -NoNewWindow `
    -RedirectStandardOutput $logFile `
    -RedirectStandardError  $errFile

Write-Host "  → new PID: $($proc.Id)"

Write-Host "[3/3] Waiting for port $Listen (max 60s)..."
for ($i = 1; $i -le 60; $i++) {
    Start-Sleep -Seconds 1
    if (Get-NetTCPConnection -LocalPort 1111 -State Listen -ErrorAction SilentlyContinue) {
        Write-Host "READY: extractor listening on $Listen (took ${i}s)"
        exit 0
    }
    if ($proc.HasExited) {
        Write-Host "FAILED: extractor exited early (code $($proc.ExitCode))"
        if (Test-Path $errFile) {
            Write-Host "----- extractor.err.log (last 30) -----"
            Get-Content $errFile -Tail 30
        }
        exit 1
    }
}
Write-Host "TIMEOUT: port not listening after 60s"
if (Test-Path $errFile) {
    Write-Host "----- extractor.err.log (last 30) -----"
    Get-Content $errFile -Tail 30
}
exit 2