# keep-alive.ps1 - Auto-restart localtunnel
while ($true) {
    $proc = Start-Process -FilePath "npx" -ArgumentList "localtunnel --port 3000" -PassThru -NoNewWindow
    Write-Host "Tunnel started, PID: $($proc.Id)"
    $proc.WaitForExit()
    Write-Host "Tunnel died, restarting in 3 seconds..."
    Start-Sleep -Seconds 3
}
