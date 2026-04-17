# Run on SERVER machine to force regenerate the CA certificate
# Then re-run install_cert_client.ps1 on CLIENT with the new cert
# powershell -ExecutionPolicy Bypass -File .\regenerate_cert.ps1

Write-Host ""
Write-Host "=== Regenerate DLP Proxy CA Certificate ===" -ForegroundColor Cyan
Write-Host ""

$certDir = Join-Path $PSScriptRoot "certs"

# Delete old certs so server will regenerate them on next start
if (Test-Path $certDir) {
    Write-Host "Deleting old certificates in: $certDir" -ForegroundColor Yellow
    Remove-Item "$certDir\*" -Force -ErrorAction SilentlyContinue
    Write-Host "Deleted." -ForegroundColor Green
} else {
    Write-Host "Cert directory not found: $certDir" -ForegroundColor Yellow
}

# Also delete mitmproxy's own cert cache
$mitmDir = "$env:USERPROFILE\.mitmproxy"
if (Test-Path $mitmDir) {
    Write-Host ""
    Write-Host "Deleting mitmproxy cert cache: $mitmDir" -ForegroundColor Yellow
    Remove-Item "$mitmDir\*" -Force -Recurse -ErrorAction SilentlyContinue
    Write-Host "Deleted." -ForegroundColor Green
}

Write-Host ""
Write-Host "Done. Now:" -ForegroundColor Green
Write-Host "  1. Start the server: python server/server_main.py"
Write-Host "  2. New certs will be generated automatically"
Write-Host "  3. Run install_cert_client.ps1 on CLIENT to install the new cert"
Write-Host ""
Read-Host "Press Enter to exit"
