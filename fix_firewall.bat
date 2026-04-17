@echo off
:: DLP Proxy — One-time firewall setup (run as Administrator)
:: This must be done ONCE. After this, server works without admin rights.

net session >nul 2>&1
if errorlevel 1 (
    echo Запустите от имени Администратора!
    pause
    exit /b 1
)

echo Открываю порты 8000 и 8080 в Windows Firewall...

netsh advfirewall firewall delete rule name="DLP Proxy Cert Server" >nul 2>&1
netsh advfirewall firewall delete rule name="DLP Proxy MITM" >nul 2>&1

netsh advfirewall firewall add rule name="DLP Proxy Cert Server" ^
    dir=in action=allow protocol=TCP localport=8000 profile=any
if errorlevel 1 (echo ОШИБКА порт 8000) else (echo [OK] Порт 8000 открыт)

netsh advfirewall firewall add rule name="DLP Proxy MITM" ^
    dir=in action=allow protocol=TCP localport=8080 profile=any
if errorlevel 1 (echo ОШИБКА порт 8080) else (echo [OK] Порт 8080 открыт)

echo.
echo Готово. Теперь сервер можно запускать без прав администратора.
pause
