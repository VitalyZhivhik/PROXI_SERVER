# DLP Proxy - Client Setup v2.1 (diagnostic + all browsers + auto HSTS)
# powershell -ExecutionPolicy Bypass -File .\install_cert_client.ps1
# Supports -ServerIP / -CertPort / -ProxyPort overrides

param(
    [string]$ServerIP  = "192.168.142.31",
    [int]   $CertPort  = 8000,
    [int]   $ProxyPort = 8080
)

Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  DLP Proxy Client Setup v2.1"                    -ForegroundColor Cyan
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: Run as Administrator!" -ForegroundColor Red
    Read-Host "Press Enter to exit"; exit 1
}
Write-Host "[OK] Administrator" -ForegroundColor Green

# --------------------------------------------------------------------------
# PRE-CHECK: connectivity to server
# --------------------------------------------------------------------------
Write-Host ""
Write-Host "[PRE] Checking connectivity to $ServerIP`:$CertPort ..."
$pingOK = Test-Connection $ServerIP -Count 1 -Quiet -ErrorAction SilentlyContinue
if ($pingOK) {
    Write-Host "  Ping $ServerIP : OK" -ForegroundColor Green
} else {
    Write-Host "  Ping $ServerIP : FAILED" -ForegroundColor Yellow
    Write-Host "  (Ping may be blocked by firewall - continuing anyway)"
}

$portOK = $false
try {
    $tc = [System.Net.Sockets.TcpClient]::new()
    $ar = $tc.BeginConnect($ServerIP, $CertPort, $null, $null)
    $w  = $ar.AsyncWaitHandle.WaitOne(3000, $false)
    if ($w -and -not $tc.Client.Connected) { $w = $false }
    $tc.Close()
    $portOK = $w
} catch {}

if ($portOK) {
    Write-Host "  Port $CertPort : OPEN" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "  Port $CertPort : CLOSED or server not running!" -ForegroundColor Red
    Write-Host ""
    Write-Host "  Possible causes:" -ForegroundColor Yellow
    Write-Host "    1. DLP server is not started on $ServerIP"
    Write-Host "       -> Run: python server\server_main.py"
    Write-Host ""
    Write-Host "    2. Windows Firewall is blocking port $CertPort on the server"
    Write-Host "       -> On SERVER run: netsh advfirewall firewall add rule"
    Write-Host "          name='DLP Cert Server' dir=in action=allow protocol=TCP localport=$CertPort"
    Write-Host ""
    Write-Host "    3. Wrong server IP. Your IP is: " -NoNewline
    (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notmatch '^127\.'} | Select-Object -First 1).IPAddress
    Write-Host ""
    Write-Host "    4. VMs on different network. Check VMware/VirtualBox network adapter mode"
    Write-Host "       -> Should be 'NAT' or 'Host-only', not 'Isolated'"
    Write-Host ""
    $cont = Read-Host "Continue anyway? (y/n)"
    if ($cont -ne "y") { exit 1 }
}

# --------------------------------------------------------------------------
# STEP 1: Download cert (bypass proxy)
# --------------------------------------------------------------------------
Write-Host ""
Write-Host "[1/5] Downloading CA certificate..."
$certPath = "$env:TEMP\dlp_proxy_ca.der"

$downloaded = $false
# Method 1: WebClient with no proxy
try {
    $wc = New-Object System.Net.WebClient
    $wc.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy()
    $wc.DownloadFile("http://$ServerIP`:$CertPort/ca.der", $certPath)
    $sz = (Get-Item $certPath -ErrorAction SilentlyContinue).Length
    if ($sz -and $sz -gt 200) { $downloaded = $true }
} catch { Write-Host "  Method1 failed: $_" -ForegroundColor DarkYellow }

# Method 2: Invoke-WebRequest with no proxy
if (-not $downloaded) {
    try {
        Invoke-WebRequest -Uri "http://$ServerIP`:$CertPort/ca.der" `
            -OutFile $certPath -Proxy "" -NoProxy -UseBasicParsing -TimeoutSec 10
        $sz = (Get-Item $certPath -ErrorAction SilentlyContinue).Length
        if ($sz -and $sz -gt 200) { $downloaded = $true }
    } catch { Write-Host "  Method2 failed: $_" -ForegroundColor DarkYellow }
}

# Method 3: .NET HttpClient no proxy
if (-not $downloaded) {
    try {
        $handler = [System.Net.Http.HttpClientHandler]::new()
        $handler.UseProxy = $false
        $client = [System.Net.Http.HttpClient]::new($handler)
        $bytes = $client.GetByteArrayAsync("http://$ServerIP`:$CertPort/ca.der").GetAwaiter().GetResult()
        [System.IO.File]::WriteAllBytes($certPath, $bytes)
        $sz = $bytes.Length
        if ($sz -gt 200) { $downloaded = $true }
    } catch { Write-Host "  Method3 failed: $_" -ForegroundColor DarkYellow }
}

if (-not $downloaded) {
    Write-Host "  ALL METHODS FAILED - cannot reach $ServerIP`:$CertPort" -ForegroundColor Red
    Write-Host ""
    Write-Host "  TRY MANUALLY:" -ForegroundColor Yellow
    Write-Host "    1. Open browser (without proxy settings)"
    Write-Host "    2. Go to: http://$ServerIP`:$CertPort"
    Write-Host "    3. Download ca.der from the page"
    Write-Host "    4. Run: certutil -addstore -f ROOT <path_to_ca.der>"
    Read-Host "Press Enter to exit"; exit 1
}

$dlCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
Write-Host "  OK: $($dlCert.Subject)" -ForegroundColor Green
Write-Host "      Thumb: $($dlCert.Thumbprint)"
Write-Host "      Expires: $($dlCert.NotAfter)"

# --------------------------------------------------------------------------
# STEP 2: Remove old certs
# --------------------------------------------------------------------------
Write-Host ""
Write-Host "[2/5] Removing old DLP/mitmproxy certs..."
foreach ($loc in @("LocalMachine", "CurrentUser")) {
    try {
        $s = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", $loc)
        $s.Open("ReadWrite")
        $old = $s.Certificates | Where-Object {
            $_.Subject -like "*DLP*" -or $_.Subject -like "*mitmproxy*" -or $_.Issuer -like "*mitmproxy*"
        }
        foreach ($c in $old) {
            Write-Host "  Removed [$loc]: $($c.Subject)" -ForegroundColor Yellow
            $s.Remove($c)
        }
        $s.Close()
    } catch { Write-Host "  Warning ($loc): $_" -ForegroundColor DarkYellow }
}

# --------------------------------------------------------------------------
# STEP 3: Install into LocalMachine\Root
# --------------------------------------------------------------------------
Write-Host ""
Write-Host "[3/5] Installing into LocalMachine\Root..."
$installed = $false
try {
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath)
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $store.Open("ReadWrite")
    $store.Add($cert)
    $store.Close()
    Write-Host "  Windows store: OK" -ForegroundColor Green
    $installed = $true
} catch {
    Write-Host "  .NET failed: $_ - trying certutil..." -ForegroundColor Yellow
    certutil -addstore -f "ROOT" $certPath | Out-Null
    if ($LASTEXITCODE -eq 0) { Write-Host "  certutil: OK" -ForegroundColor Green; $installed = $true }
    else { Write-Host "  FAILED!" -ForegroundColor Red; Read-Host "Press Enter to exit"; exit 1 }
}

# Verify
$found = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*DLP*" }
if ($found) { Write-Host "  Verified: $($found[0].Subject)" -ForegroundColor Green }
else { Write-Host "  WARNING: Not found after install" -ForegroundColor Yellow }

# Firefox
Write-Host "  Checking Firefox..."
foreach ($base in @("$env:APPDATA\Mozilla\Firefox\Profiles", "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles")) {
    if (Test-Path $base) {
        Get-ChildItem $base -Directory | ForEach-Object {
            if (Test-Path (Join-Path $_.FullName "cert9.db")) {
                try {
                    & certutil -A -n "DLP Proxy CA" -t "CT,," -i $certPath -d "sql:$($_.FullName)" 2>$null
                    Write-Host "  Firefox $($_.Name): OK" -ForegroundColor Green
                } catch {}
            }
        }
    }
}

# --------------------------------------------------------------------------
# STEP 4: Set system proxy
# --------------------------------------------------------------------------
Write-Host ""
Write-Host "[4/5] Setting proxy $ServerIP`:$ProxyPort..."
$rp = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
Set-ItemProperty $rp ProxyEnable  1
Set-ItemProperty $rp ProxyServer  "$ServerIP`:$ProxyPort"
Set-ItemProperty $rp ProxyOverride "localhost;127.0.0.1;$ServerIP;<local>"
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class WinInetDLP2 {
    [DllImport("wininet.dll")] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);
}
"@
[WinInetDLP2]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
[WinInetDLP2]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null
Write-Host "  Proxy set." -ForegroundColor Green

# --------------------------------------------------------------------------
# STEP 5: Kill browsers + clear HSTS
# --------------------------------------------------------------------------
Write-Host ""
Write-Host "[5/5] Clearing HSTS caches..."
@("msedge","chrome","firefox","brave","opera") | ForEach-Object {
    Get-Process -Name $_ -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1

@(
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\TransportSecurity",
    "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Network\TransportSecurity",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\TransportSecurity",
    "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Network\TransportSecurity",
    "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\TransportSecurity",
    "$env:APPDATA\Opera Software\Opera Stable\TransportSecurity"
) | ForEach-Object {
    if (Test-Path $_) { Remove-Item $_ -Force -ErrorAction SilentlyContinue; Write-Host "  Cleared: $_" -ForegroundColor Green }
}
if (Test-Path "$env:APPDATA\Mozilla\Firefox\Profiles") {
    Get-ChildItem "$env:APPDATA\Mozilla\Firefox\Profiles" -Recurse -Filter "SiteSecurityServiceState.bin" |
        ForEach-Object { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue; Write-Host "  Firefox HSTS: cleared" -ForegroundColor Green }
}
Write-Host "  Done." -ForegroundColor Green

# --------------------------------------------------------------------------
# SUMMARY
# --------------------------------------------------------------------------
Write-Host ""
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host "  SETUP COMPLETE"                                  -ForegroundColor Green
Write-Host "=================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Certificate : LocalMachine\Root"
Write-Host "  Proxy       : $ServerIP`:$ProxyPort"
Write-Host "  HSTS        : Cleared for Edge, Chrome, Firefox, Brave, Opera"
Write-Host ""
Write-Host "Open browser -> https://yandex.ru (no warnings expected)" -ForegroundColor Cyan
Write-Host "Admin panel  -> http://$ServerIP`:$CertPort/admin/" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to exit"
