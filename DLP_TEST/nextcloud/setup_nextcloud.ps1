# Nextcloud HTTPS - Setup for DLP Testing
# Run: powershell -ExecutionPolicy Bypass -File .\setup_nextcloud.ps1

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nextcloud HTTPS - DLP Test Setup"      -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

# --- Step 1: Check Docker ---
Write-Host "[1/3] Checking Docker..." -ForegroundColor Yellow

$dockerOk = $false
try {
    $dv = docker --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  OK: $dv" -ForegroundColor Green
        $dockerOk = $true
    }
} catch {
    $dockerOk = $false
}

if (-not $dockerOk) {
    Write-Host "  ERROR: Docker not installed!" -ForegroundColor Red
    Write-Host "  Download: https://www.docker.com/products/docker-desktop/" -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "not running" }
} catch {
    Write-Host "  ERROR: Docker Desktop is not running!" -ForegroundColor Red
    Write-Host "  Start Docker Desktop and try again." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

# --- Step 2: Generate SSL certificate ---
Write-Host ""
Write-Host "[2/3] Generating SSL certificate..." -ForegroundColor Yellow

$certDir = Join-Path $scriptDir "certs"
if (-not (Test-Path $certDir)) {
    New-Item -ItemType Directory -Path $certDir -Force | Out-Null
}

$certFile = Join-Path $certDir "server.crt"
$keyFile  = Join-Path $certDir "server.key"

if ((Test-Path $certFile) -and (Test-Path $keyFile)) {
    Write-Host "  Certificate already exists - skipping" -ForegroundColor Green
}
else {
    # Detect server IP
    $serverIP = $null
    $addrs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
    foreach ($a in $addrs) {
        if ($a.IPAddress -notlike "127.*" -and $a.IPAddress -notlike "169.*") {
            $serverIP = $a.IPAddress
            break
        }
    }
    if (-not $serverIP) { $serverIP = "127.0.0.1" }
    Write-Host "  Server IP: $serverIP" -ForegroundColor Cyan

    # Generate cert via Docker openssl
    Write-Host "  Generating via Docker openssl..." -ForegroundColor Gray

    $subj = "/CN=DLP Nextcloud Test/O=DLP Test/C=RU"
    $san  = "subjectAltName=IP:${serverIP},IP:127.0.0.1,DNS:localhost"
    $opensslArgs = "req -x509 -newkey rsa:2048 -keyout /certs/server.key -out /certs/server.crt -days 365 -nodes -subj ""$subj"" -addext ""$san"""

    docker run --rm -v "${certDir}:/certs" alpine/openssl sh -c "openssl $opensslArgs" 2>&1 | Out-Null

    if ((Test-Path $certFile) -and (Test-Path $keyFile)) {
        Write-Host "  Certificate created!" -ForegroundColor Green
    }
    else {
        Write-Host "  Docker openssl failed. Trying alternative..." -ForegroundColor Yellow

        # Fallback: use openssl from Git for Windows
        $opensslPath = $null
        $gitOpenssl = "C:\Program Files\Git\usr\bin\openssl.exe"
        if (Test-Path $gitOpenssl) { $opensslPath = $gitOpenssl }

        if ($opensslPath) {
            Write-Host "  Found openssl at: $opensslPath" -ForegroundColor Gray
            $argList = @(
                "req", "-x509", "-newkey", "rsa:2048",
                "-keyout", $keyFile,
                "-out", $certFile,
                "-days", "365", "-nodes",
                "-subj", "/CN=DLP Nextcloud Test/O=DLP Test/C=RU"
            )
            & $opensslPath $argList 2>&1 | Out-Null

            if ((Test-Path $certFile) -and (Test-Path $keyFile)) {
                Write-Host "  Certificate created via Git openssl!" -ForegroundColor Green
            }
            else {
                Write-Host "  FAILED to create certificate." -ForegroundColor Red
                Read-Host "Press Enter to exit"
                exit 1
            }
        }
        else {
            Write-Host "  No openssl found." -ForegroundColor Red
            Write-Host "  Install Git for Windows or create certs manually." -ForegroundColor Yellow
            Read-Host "Press Enter to exit"
            exit 1
        }
    }
}

# --- Step 3: Start Docker Compose ---
Write-Host ""
Write-Host "[3/3] Starting Nextcloud..." -ForegroundColor Yellow

docker-compose down 2>&1 | Out-Null
docker-compose up -d 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: docker-compose failed!" -ForegroundColor Red
    Write-Host "  Check Docker Desktop is running." -ForegroundColor Yellow
    Read-Host "Press Enter to exit"
    exit 1
}

Start-Sleep -Seconds 3

# Detect IP again for final output
$serverIP = $null
$addrs = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
foreach ($a in $addrs) {
    if ($a.IPAddress -notlike "127.*" -and $a.IPAddress -notlike "169.*") {
        $serverIP = $a.IPAddress
        break
    }
}
if (-not $serverIP) { $serverIP = "127.0.0.1" }

# Open firewall port
Write-Host ""
Write-Host "  Opening firewall port 8443..." -ForegroundColor Gray
netsh advfirewall firewall add rule name="DLP Nextcloud 8443" dir=in action=allow protocol=TCP localport=8443 2>&1 | Out-Null

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Nextcloud is running!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  URL:      https://${serverIP}:8443" -ForegroundColor White
Write-Host "  Login:    admin" -ForegroundColor White
Write-Host "  Password: admin123" -ForegroundColor White
Write-Host ""
Write-Host "  First start may take 1-2 minutes." -ForegroundColor Yellow
Write-Host ""
Write-Host "  Stop:  docker-compose down" -ForegroundColor Gray
Write-Host "  Logs:  docker-compose logs -f" -ForegroundColor Gray
Write-Host ""
Write-Host "  DLP Testing:" -ForegroundColor Cyan
Write-Host "  1. On VM open https://${serverIP}:8443" -ForegroundColor White
Write-Host "  2. Login with admin / admin123" -ForegroundColor White
Write-Host "  3. Upload a file with personal data" -ForegroundColor White
Write-Host "  4. DLP proxy will intercept and analyze traffic" -ForegroundColor White
Write-Host ""

Read-Host "Press Enter to exit"
