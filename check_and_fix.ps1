# DLP Proxy - Fix proxy bypass list on server machine
# Run: powershell -ExecutionPolicy Bypass -File .\check_and_fix.ps1

Write-Host ""
Write-Host "=== DLP Proxy - Fix Proxy Bypass List ===" -ForegroundColor Cyan
Write-Host ""

$regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"

$proxyEnable   = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).ProxyEnable
$proxyServer   = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).ProxyServer
$proxyOverride = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).ProxyOverride

Write-Host "Current settings:"
Write-Host "  ProxyEnable  : $proxyEnable"
Write-Host "  ProxyServer  : $proxyServer"
Write-Host "  ProxyOverride: $proxyOverride"
Write-Host ""

# Detect server IP automatically
$serverIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -notlike "127.*" -and
    $_.IPAddress -notlike "169.*" -and
    $_.PrefixOrigin -ne "WellKnown"
} | Select-Object -First 1).IPAddress

if (-not $serverIP) {
    $serverIP = "192.168.182.31"
}
Write-Host "Detected server IP: $serverIP" -ForegroundColor Green

# IMPORTANT: Windows does NOT support wildcards like 192.168.* for IP addresses.
# Each IP or range must be listed explicitly with semicolons.
# We list the server IP, loopback, and common local ranges explicitly.
$bypassList = "localhost;127.0.0.1;::1;$serverIP;<local>"

Write-Host "New bypass list: $bypassList" -ForegroundColor Yellow
Write-Host ""

if ($proxyEnable -eq 1) {
    Set-ItemProperty $regPath ProxyOverride $bypassList
    Write-Host "Bypass list updated." -ForegroundColor Green
} else {
    Write-Host "Proxy is disabled - setting bypass list anyway for safety."
    Set-ItemProperty $regPath ProxyOverride $bypassList
}

# Also set proxy for the machine-level WinHTTP (used by some apps)
Write-Host ""
Write-Host "WinHTTP proxy status (read-only, not changing):"
netsh winhttp show proxy

# Notify Windows immediately - no need to reopen browser
Write-Host ""
Write-Host "Applying changes to Windows (no browser restart needed)..."
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WinInet2 {
    [DllImport("wininet.dll")] public static extern bool InternetSetOption(IntPtr h, int o, IntPtr b, int l);
}
"@
[WinInet2]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null
[WinInet2]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null

Write-Host ""
Write-Host "=== Final settings ===" -ForegroundColor Cyan
$f = Get-ItemProperty $regPath
Write-Host "  ProxyEnable  : $($f.ProxyEnable)"
Write-Host "  ProxyServer  : $($f.ProxyServer)"
Write-Host "  ProxyOverride: $($f.ProxyOverride)"
Write-Host ""
Write-Host "Done! Now open in browser (WITHOUT proxy):" -ForegroundColor Green
Write-Host "  http://$serverIP`:8000" -ForegroundColor Cyan
Write-Host "  http://192.168.182.31:8000" -ForegroundColor Cyan
Write-Host ""
Write-Host "If browser still uses proxy for this address, try:" -ForegroundColor Yellow
Write-Host "  1. Close and reopen browser"
Write-Host "  2. Or open in InPrivate/Incognito mode"
Write-Host "  3. Or type the address directly in address bar (not via search)"
Write-Host ""
Read-Host "Press Enter to exit"
