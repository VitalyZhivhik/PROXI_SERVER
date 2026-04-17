r"""
DLP Proxy — EndPoint Agent v6.0

Изменения v6.0:
  - Переименован в EndPoint Agent (не просто клиент настройки)
  - Автоматическая настройка прокси при запуске (endpoint-агент)
  - Автозагрузка при входе в Windows (реестр Run)
  - Новая вкладка «🌐 Интернет» — заявки на доступ в интернет
  - Сохранение настроек сервера в dlp_agent.json
  - Автопоиск сервера при первом запуске
  - Вкладки: Настройка / Уведомления / Чат / Интернет

Изменения v5.0:
  - Вкладки: Настройка / Уведомления / Чат
  - Всплывающие уведомления при блокировке файлов
  - Одобрение/отклонение запросов доступа от администратора
  - Чат с администратором
  - Фоновый опрос /api/notifications каждые 10 сек
"""

import sys
import os
import json
import ctypes
import subprocess
import tempfile
import urllib.request
import urllib.error
import socket
import threading
from pathlib import Path
from datetime import datetime

try:
    import winreg
except ImportError:
    winreg = None

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QLineEdit, QTextEdit, QGroupBox,
    QProgressBar, QFrame, QCheckBox, QMessageBox,
    QTabWidget, QScrollArea, QSplitter,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QTextCursor, QPalette, QColor

# ─────────────────────────────────────────────────────────────────────────────
STYLE = """
QMainWindow,QWidget{background:#0d1117;color:#c9d1d9;font-family:'Segoe UI',Arial;font-size:13px}
QGroupBox{border:1px solid #30363d;border-radius:8px;margin-top:16px;padding-top:12px;
          font-weight:700;color:#58a6ff;font-size:11px;letter-spacing:.3px}
QGroupBox::title{subcontrol-origin:margin;left:12px;padding:0 6px}
QPushButton{background:#21262d;border:1px solid #30363d;border-radius:7px;
            padding:9px 18px;color:#c9d1d9;font-size:13px;min-height:34px}
QPushButton:hover{background:#30363d;border-color:#8b949e}
QPushButton:disabled{background:#161b22;color:#484f58;border-color:#21262d}
QPushButton#btnInstall{background:#1a4731;border-color:#2ea043;color:#a8edbb;
                       font-weight:700;font-size:14px;min-height:44px;border-radius:9px}
QPushButton#btnInstall:hover{background:#2ea043}
QPushButton#btnCheck{background:#1a3550;border-color:#1f6feb;color:#79c0ff;font-weight:600}
QPushButton#btnCheck:hover{background:#1f6feb;color:#fff}
QPushButton#btnScan{background:#1a2a1a;border-color:#2ea043;color:#a6e3a1;font-weight:600}
QPushButton#btnScan:hover{background:#2ea043;color:#fff}
QPushButton#btnRemove{background:#2d1515;border-color:#6e2a2a;color:#f38ba8}
QPushButton#btnRemove:hover{background:#6e2a2a}
QPushButton#btnOpen{background:#1a2a40;border-color:#2d5a8a;color:#79c0ff;
                    padding:6px 14px;min-height:28px;font-size:12px}
QPushButton#btnOpen:hover{background:#2d5a8a}
QLineEdit{background:#161b22;border:1px solid #30363d;border-radius:7px;
          padding:8px 12px;color:#c9d1d9;font-size:13px}
QLineEdit:focus{border-color:#58a6ff;background:#1a1f2a}
QTextEdit{background:#0a0c10;border:1px solid #21262d;border-radius:7px;
          color:#8b949e;font-family:Consolas,'Courier New',monospace;font-size:12px}
QProgressBar{background:#21262d;border:none;border-radius:5px;height:8px}
QProgressBar::chunk{background:qlineargradient(x1:0,y1:0,x2:1,y2:0,
    stop:0 #1f6feb,stop:0.5 #58a6ff,stop:1 #79c0ff);border-radius:5px}
QCheckBox{spacing:8px;padding:3px 0}
QCheckBox::indicator{width:16px;height:16px;border:1px solid #30363d;
                     border-radius:4px;background:#21262d}
QCheckBox::indicator:checked{background:#1f6feb;border-color:#58a6ff}
QFrame#header{background:qlineargradient(x1:0,y1:0,x2:1,y2:1,
              stop:0 #161b22,stop:1 #1f2d3d);border-bottom:1px solid #30363d}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _notify_wininet():
    try:
        w = ctypes.windll.wininet
        w.InternetSetOptionW(0, 39, 0, 0)
        w.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass


def _is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "?"


# ─────────────────────────────────────────────────────────────────────────────
# Agent config (saved between sessions)
# ─────────────────────────────────────────────────────────────────────────────
_AGENT_CFG_PATH = Path(os.environ.get("APPDATA", ".")) / "DLP_Agent" / "dlp_agent.json"

def _load_agent_config() -> dict:
    """Load saved agent config (server IP, ports, autostart, etc.)"""
    try:
        if _AGENT_CFG_PATH.exists():
            return json.loads(_AGENT_CFG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}

def _save_agent_config(cfg: dict):
    """Save agent config"""
    try:
        _AGENT_CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _AGENT_CFG_PATH.write_text(
            json.dumps(cfg, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# Autostart (Windows Run registry)
# ─────────────────────────────────────────────────────────────────────────────

def _get_autostart_enabled() -> bool:
    """Check if DLP Agent is in Windows Run startup"""
    if not winreg:
        return False
    try:
        reg = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg) as k:
            val, _ = winreg.QueryValueEx(k, "DLP_Agent")
            return bool(val)
    except Exception:
        return False


def _set_autostart(enable: bool) -> bool:
    """Enable/disable autostart on Windows login"""
    if not winreg:
        return False
    try:
        reg = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg, 0,
                            winreg.KEY_WRITE) as k:
            if enable:
                # Use sys.executable for .py, or frozen exe path
                if getattr(sys, 'frozen', False):
                    exe_path = sys.executable
                else:
                    exe_path = f'"{sys.executable}" "{os.path.abspath(sys.argv[0])}"'
                winreg.SetValueEx(k, "DLP_Agent", 0, winreg.REG_SZ, exe_path)
            else:
                try:
                    winreg.DeleteValue(k, "DLP_Agent")
                except FileNotFoundError:
                    pass
        return True
    except Exception:
        return False


def _proxy_is_set(server_ip: str, proxy_port: int) -> bool:
    """Check if system proxy is already configured for our server"""
    if not winreg:
        return False
    try:
        reg = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg) as k:
            en, _ = winreg.QueryValueEx(k, "ProxyEnable")
            srv, _ = winreg.QueryValueEx(k, "ProxyServer")
            expected = f"{server_ip}:{proxy_port}"
            return en == 1 and expected in str(srv)
    except Exception:
        return False


def _tcp_open(ip: str, port: int, timeout_ms: int = 800) -> bool:
    try:
        s = socket.create_connection((ip, port), timeout=timeout_ms / 1000)
        s.close()
        return True
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Auto-scan worker
# ─────────────────────────────────────────────────────────────────────────────

class ScanWorker(QThread):
    """Scans local subnet for DLP server port"""
    found    = pyqtSignal(str)          # emitted with IP when found
    progress = pyqtSignal(int, str)     # (percent, status_text)
    done     = pyqtSignal(bool)         # True=found, False=not found

    def __init__(self, cert_port: int = 8000):
        super().__init__()
        self.cert_port = cert_port
        self._stop     = False

    def stop(self):
        self._stop = True

    def run(self):
        my_ip = _local_ip()
        self.progress.emit(0, f"Ваш IP: {my_ip} — сканирую подсеть...")

        if my_ip == "?":
            self.progress.emit(100, "Не удалось определить локальный IP")
            self.done.emit(False)
            return

        parts  = my_ip.split(".")
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"

        # Fast pass: common last octets first
        priority = [1, 2, 10, 20, 30, 31, 32, 50, 100, 101, 110, 150, 200, 254]
        all_hosts = priority + [i for i in range(1, 255) if i not in priority]

        total = len(all_hosts)
        results = {}

        def check(ip):
            if self._stop:
                return
            if _tcp_open(ip, self.cert_port, 500):
                results[ip] = True

        # Thread pool for speed
        threads = []
        for idx, last in enumerate(all_hosts):
            if self._stop:
                break
            candidate = f"{subnet}.{last}"
            if candidate == my_ip:
                continue
            t = threading.Thread(target=check, args=(candidate,), daemon=True)
            t.start()
            threads.append(t)

            # Emit progress every 10 hosts
            if idx % 10 == 0:
                pct = int(idx / total * 100)
                self.progress.emit(pct, f"Сканирую {subnet}.0/24 ... {pct}%")

            # Check results early (priority hosts)
            if idx < len(priority):
                t.join(timeout=0.6)
                if results:
                    break

        # Wait for remaining threads
        for t in threads:
            t.join(timeout=0.3)

        self.progress.emit(100, "Сканирование завершено")

        if results:
            found_ip = list(results.keys())[0]
            self.found.emit(found_ip)
            self.done.emit(True)
        else:
            self.done.emit(False)


# ─────────────────────────────────────────────────────────────────────────────
# Check worker
# ─────────────────────────────────────────────────────────────────────────────

class CheckWorker(QThread):
    result = pyqtSignal(list)

    def __init__(self, ip, cp, pp):
        super().__init__()
        self.ip, self.cp, self.pp = ip, cp, pp

    def run(self):
        out = []
        def a(m, lv="info"): out.append((m, lv))

        my_ip = _local_ip()
        a(f"Ваш IP: {my_ip}  |  Сервер: {self.ip}", "section")

        # Port checks
        for port, name in [(self.cp, "cert:8000"), (self.pp, "proxy:8080")]:
            if _tcp_open(self.ip, port, 3000):
                a(f"  ✓ {self.ip}:{port} ({name}) — доступен", "ok")
            else:
                a(f"  ✗ {self.ip}:{port} ({name}) — НЕДОСТУПЕН", "error")
                a(f"    → Сервер запущен? Firewall разрешает порт {port}?", "warn")

        # Certificate check
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ChildItem Cert:\\LocalMachine\\Root | "
                 "Where-Object {$_.Subject -like '*DLP*'} | "
                 "Select-Object Subject, NotAfter | Format-List"],
                capture_output=True, text=True, timeout=10
            )
            if "DLP" in r.stdout:
                lines = [l.strip() for l in r.stdout.splitlines() if l.strip()][:6]
                a("  ✓ Сертификат DLP установлен:", "ok")
                for l in lines:
                    a(f"    {l}", "ok")
            else:
                a("  ✗ Сертификат DLP НЕ найден в LocalMachine\\Root", "error")
                a("    → Нажмите «▶ Установить всё»", "warn")
        except Exception as e:
            a(f"  ? Проверка сертификата: {e}", "warn")

        # Proxy settings
        if winreg:
            try:
                reg = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg) as k:
                    def _r(n):
                        try:
                            v, _ = winreg.QueryValueEx(k, n)
                            return v
                        except Exception:
                            return None
                    en  = _r("ProxyEnable")
                    srv = _r("ProxyServer") or ""
                    byp = _r("ProxyOverride") or ""
                    exp = f"{self.ip}:{self.pp}"
                    if en == 1 and exp in srv:
                        a(f"  ✓ Системный прокси: {srv}", "ok")
                        a(f"    Исключения: {byp}", "info")
                    elif en == 1:
                        a(f"  ⚠ Прокси включён, но указывает на: {srv}", "warn")
                        a(f"    Ожидался: {exp}", "warn")
                    else:
                        a(f"  ✗ Системный прокси выключен", "error")
                        a("    → Нажмите «▶ Установить всё»", "warn")
            except Exception as e:
                a(f"  ? Реестр: {e}", "warn")

        self.result.emit(out)


# ─────────────────────────────────────────────────────────────────────────────
# Setup worker
# ─────────────────────────────────────────────────────────────────────────────

class SetupWorker(QThread):
    log_line = pyqtSignal(str, str)
    progress = pyqtSignal(int)
    finished = pyqtSignal(bool, str)

    def __init__(self, ip, cp, pp, do_cert, do_proxy, do_hsts):
        super().__init__()
        self.ip, self.cp, self.pp = ip, cp, pp
        self.do_cert, self.do_proxy, self.do_hsts = do_cert, do_proxy, do_hsts

    def _l(self, m, lv="info"):
        self.log_line.emit(m, lv)

    def run(self):
        errors, done = [], []

        # 1. Download cert
        cert_path = None
        if self.do_cert:
            self._l("▶ Шаг 1/5: Скачиваю CA-сертификат...", "section")
            self.progress.emit(5)
            cert_path = self._download()
            if cert_path:
                self._l(f"  ✓ Скачан успешно", "ok")
            else:
                self._l("  ✗ Не удалось скачать сертификат", "error")
                self._l(f"    Убедитесь: http://{self.ip}:{self.cp} открывается в браузере", "warn")
                errors.append("Сертификат не скачан")

        # 2. Remove old certs
        if self.do_cert and cert_path:
            self._l("▶ Шаг 2/5: Удаляю старые DLP/mitmproxy сертификаты...", "section")
            self.progress.emit(20)
            n = self._remove_old()
            self._l(f"  {'✓ Удалено старых: ' + str(n) if n else '— Старых не найдено'}", "ok" if n else "info")

        # 3. Install cert
        if self.do_cert and cert_path:
            self._l("▶ Шаг 3/5: Устанавливаю в Windows (LocalMachine\\Root)...", "section")
            self.progress.emit(40)
            ok, msg = self._install_win(cert_path)
            if ok:
                self._l(f"  ✓ {msg}", "ok")
                done.append("Сертификат установлен")
                # Verify immediately
                if self._verify_cert():
                    self._l("  ✓ Верификация: сертификат найден в хранилище", "ok")
                else:
                    self._l("  ⚠ Верификация: не найден — попробуйте перезапустить браузер", "warn")
            else:
                self._l(f"  ✗ {msg}", "error")
                errors.append("Сертификат не установлен")

            # Firefox
            if self._install_ff(cert_path):
                self._l("  ✓ Firefox: установлен", "ok")
            else:
                self._l("  — Firefox не найден или уже установлен", "info")

        # 4. Set proxy
        if self.do_proxy:
            self._l(f"▶ Шаг 4/5: Настраиваю системный прокси → {self.ip}:{self.pp}...", "section")
            self.progress.emit(65)
            ok, msg = self._set_proxy()
            if ok:
                self._l(f"  ✓ {msg}", "ok")
                done.append(f"Прокси {self.ip}:{self.pp}")
            else:
                self._l(f"  ✗ {msg}", "error")
                errors.append("Прокси не настроен")

        # 5. Clear HSTS
        if self.do_hsts:
            self._l("▶ Шаг 5/5: Закрываю браузеры, очищаю HSTS-кэш...", "section")
            self.progress.emit(85)
            n = self._clear_hsts()
            self._l(f"  ✓ Очищено кэш-файлов: {n}", "ok")
            done.append("HSTS очищен")

        self.progress.emit(100)
        success = len(errors) == 0
        summary = ("Готово:\n" + "\n".join(f"• {d}" for d in done)) if success else \
                  ("Ошибки:\n" + "\n".join(f"• {e}" for e in errors))
        self.finished.emit(success, summary)

    # ── Implementation ────────────────────────────────────────────────────────

    def _download(self) -> str:
        url  = f"http://{self.ip}:{self.cp}/ca.der"
        dest = Path(tempfile.gettempdir()) / "dlp_proxy_ca.der"

        self._l(f"    URL: {url}", "info")

        # Method 0: raw socket HTTP (most direct — bypasses ALL proxy settings)
        try:
            import socket as _sock
            s = _sock.create_connection((self.ip, self.cp), timeout=8)
            req = (f"GET /ca.der HTTP/1.0\r\n"
                   f"Host: {self.ip}:{self.cp}\r\n"
                   f"Connection: close\r\n\r\n")
            s.sendall(req.encode())
            resp = b""
            while True:
                chunk = s.recv(8192)
                if not chunk:
                    break
                resp += chunk
            s.close()
            # Split headers from body
            if b"\r\n\r\n" in resp:
                header_part, body = resp.split(b"\r\n\r\n", 1)
                headers = header_part.decode("utf-8", errors="replace")
                if "200" in headers.split("\n")[0] and len(body) > 200:
                    dest.write_bytes(body)
                    self._l(f"    Raw socket OK ({len(body)} байт)", "info")
                    return str(dest)
                else:
                    self._l(f"    Raw socket: HTTP status не 200 или пустой ответ", "warn")
        except Exception as e:
            self._l(f"    Raw socket: {e}", "warn")

        # Method 1: urllib with no proxy, explicit socket timeout
        try:
            # Temporarily disable system proxy via env
            old_http  = os.environ.pop("http_proxy",  None)
            old_HTTP  = os.environ.pop("HTTP_PROXY",  None)
            old_https = os.environ.pop("https_proxy", None)
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(url, timeout=10) as r:
                    data = r.read()
            finally:
                if old_http:  os.environ["http_proxy"]  = old_http
                if old_HTTP:  os.environ["HTTP_PROXY"]  = old_HTTP
                if old_https: os.environ["https_proxy"] = old_https
            if len(data) > 200:
                dest.write_bytes(data)
                self._l(f"    urllib OK ({len(data)} байт)", "info")
                return str(dest)
        except Exception as e:
            self._l(f"    urllib: {e}", "warn")

        # Method 2: PowerShell WebClient (no proxy, longer timeout)
        try:
            dest2 = Path(tempfile.gettempdir()) / "dlp_ca_ps.der"
            dest2_str = str(dest2).replace("\\", "\\\\")
            ps = ('$wc=New-Object System.Net.WebClient;'
                  '$wc.Proxy=[System.Net.GlobalProxySelection]::GetEmptyWebProxy();'
                  '$wc.Headers.Add("User-Agent","DLP-Client/4.0");'
                  f'$wc.DownloadFile("{url}","{dest2_str}")')
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, text=True, timeout=20)
            if r.returncode == 0 and dest2.exists() and dest2.stat().st_size > 200:
                self._l(f"    PowerShell OK ({dest2.stat().st_size} байт)", "info")
                return str(dest2)
            if r.stderr:
                self._l(f"    PowerShell stderr: {r.stderr.strip()[:100]}", "warn")
        except Exception as e:
            self._l(f"    PowerShell: {e}", "warn")

        # Method 3: .NET HttpClient with timeout
        try:
            ps = ('$h=[System.Net.Http.HttpClientHandler]::new();'
                  '$h.UseProxy=$false;'
                  '$c=[System.Net.Http.HttpClient]::new($h);'
                  '$c.Timeout=[System.TimeSpan]::FromSeconds(15);'
                  f'$b=$c.GetByteArrayAsync("{url}").GetAwaiter().GetResult();'
                  '[Convert]::ToBase64String($b)')
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, text=True, timeout=20)
            if r.returncode == 0 and r.stdout.strip():
                import base64
                data = base64.b64decode(r.stdout.strip())
                if len(data) > 200:
                    dest.write_bytes(data)
                    self._l(f"    HttpClient OK ({len(data)} байт)", "info")
                    return str(dest)
        except Exception as e:
            self._l(f"    HttpClient: {e}", "warn")

        # All methods failed — give diagnosis
        self._l("", "info")
        self._l("    Все методы не сработали. Диагностика:", "warn")
        # Check if port is actually open
        try:
            import socket as _sock2
            s2 = _sock2.create_connection((self.ip, self.cp), timeout=3)
            s2.close()
            self._l(f"    Порт {self.cp} на {self.ip} — ОТКРЫТ (TCP)", "warn")
            self._l("    → Проблема в Windows Firewall на сервере. На сервере выполните:", "warn")
            self._l(f'    netsh advfirewall firewall add rule name="DLP Cert" dir=in action=allow protocol=TCP localport={self.cp}', "warn")
        except Exception:
            self._l(f"    Порт {self.cp} на {self.ip} — НЕДОСТУПЕН", "error")
            self._l("    → Убедитесь что server_main.py запущен на сервере", "warn")

        return None

    def _remove_old(self) -> int:
        ps = r"""
$n=0
foreach ($loc in @("LocalMachine","CurrentUser")) {
    $s=[System.Security.Cryptography.X509Certificates.X509Store]::new("Root",$loc)
    $s.Open("ReadWrite")
    $del=$s.Certificates|Where-Object{
        $_.Subject -like "*DLP*" -or $_.Subject -like "*mitmproxy*" -or $_.Issuer -like "*mitmproxy*"
    }
    foreach($c in $del){$s.Remove($c);$n++}
    $s.Close()
}
Write-Output $n"""
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, text=True, timeout=15)
            val = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "0"
            return int(val) if val.isdigit() else 0
        except Exception:
            return 0

    def _install_win(self, cert_path: str) -> tuple[bool, str]:
        # Try certutil first
        try:
            r = subprocess.run(
                ["certutil", "-addstore", "-f", "ROOT", cert_path],
                capture_output=True, text=True, timeout=20
            )
            if r.returncode == 0:
                return True, "certutil — установлен в LocalMachine\\Root"
        except Exception as e:
            self._l(f"    certutil: {e}", "warn")

        # Fallback: PowerShell .NET
        try:
            cp = cert_path.replace("\\", "\\\\")
            ps = (f'$c=[System.Security.Cryptography.X509Certificates.X509Certificate2]::new("{cp}");'
                  f'$s=[System.Security.Cryptography.X509Certificates.X509Store]::new("Root","LocalMachine");'
                  f'$s.Open("ReadWrite");$s.Add($c);$s.Close()')
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                return True, "PowerShell .NET — установлен в LocalMachine\\Root"
            return False, r.stderr.strip()[:200] or "Неизвестная ошибка"
        except Exception as e:
            return False, str(e)

    def _verify_cert(self) -> bool:
        """Check cert actually appeared in the store"""
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object {$_.Subject -like '*DLP*'} | Measure-Object | Select-Object -ExpandProperty Count"],
                capture_output=True, text=True, timeout=8
            )
            count = r.stdout.strip()
            return count.isdigit() and int(count) > 0
        except Exception:
            return False

    def _install_ff(self, cert_path: str) -> bool:
        bases = [
            Path(os.environ.get("APPDATA", "")) / "Mozilla" / "Firefox" / "Profiles",
            Path(os.environ.get("LOCALAPPDATA", "")) / "Mozilla" / "Firefox" / "Profiles",
        ]
        found = False
        for base in bases:
            if not base.exists():
                continue
            for profile in base.iterdir():
                if (profile / "cert9.db").exists():
                    try:
                        r = subprocess.run(
                            ["certutil", "-A", "-n", "DLP Proxy CA",
                             "-t", "CT,,", "-i", cert_path, "-d", f"sql:{profile}"],
                            capture_output=True, timeout=10
                        )
                        if r.returncode == 0:
                            found = True
                    except Exception:
                        pass
        return found

    def _set_proxy(self) -> tuple[bool, str]:
        if not winreg:
            return False, "winreg недоступен (не Windows)"
        try:
            reg = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg, 0, winreg.KEY_WRITE) as k:
                winreg.SetValueEx(k, "ProxyEnable",   0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(k, "ProxyServer",   0, winreg.REG_SZ,
                                  f"{self.ip}:{self.pp}")
                winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ,
                                  f"localhost;127.0.0.1;{self.ip};<local>")
            _notify_wininet()
            return True, f"Прокси {self.ip}:{self.pp} активен"
        except Exception as e:
            return False, str(e)

    def _clear_hsts(self) -> int:
        # Kill browsers
        for br in ["msedge", "chrome", "firefox", "brave", "opera"]:
            try:
                subprocess.run(["taskkill", "/F", "/IM", f"{br}.exe"],
                               capture_output=True, timeout=4)
            except Exception:
                pass

        import time
        time.sleep(1)

        la = os.environ.get("LOCALAPPDATA", "")
        ap = os.environ.get("APPDATA", "")
        paths = [
            Path(la) / "Microsoft/Edge/User Data/Default/TransportSecurity",
            Path(la) / "Microsoft/Edge/User Data/Default/Network/TransportSecurity",
            Path(la) / "Google/Chrome/User Data/Default/TransportSecurity",
            Path(la) / "Google/Chrome/User Data/Default/Network/TransportSecurity",
            Path(la) / "BraveSoftware/Brave-Browser/User Data/Default/TransportSecurity",
            Path(ap) / "Opera Software/Opera Stable/TransportSecurity",
        ]
        n = 0
        for p in paths:
            try:
                if p.exists():
                    p.unlink()
                    n += 1
                    self._l(f"    HSTS: {p.parent.parent.parent.name}", "info")
            except Exception:
                pass

        ff = Path(ap) / "Mozilla/Firefox/Profiles"
        if ff.exists():
            for f in ff.rglob("SiteSecurityServiceState.bin"):
                try:
                    f.unlink()
                    n += 1
                except Exception:
                    pass
        return n


# ─────────────────────────────────────────────────────────────────────────────
# Remove worker
# ─────────────────────────────────────────────────────────────────────────────

class RemoveWorker(QThread):
    log_line = pyqtSignal(str, str)
    finished = pyqtSignal()

    def run(self):
        def _l(m, lv="info"):
            self.log_line.emit(m, lv)

        _l("▶ Удаляю сертификаты DLP...", "section")
        ps = r"""
foreach ($loc in @("LocalMachine","CurrentUser")) {
    $s=[System.Security.Cryptography.X509Certificates.X509Store]::new("Root",$loc)
    $s.Open("ReadWrite")
    $s.Certificates | Where-Object {
        $_.Subject -like "*DLP*" -or $_.Subject -like "*mitmproxy*"
    } | ForEach-Object {
        $s.Remove($_)
        Write-Output "Удалён: $($_.Subject)"
    }
    $s.Close()
}"""
        try:
            r = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                               capture_output=True, text=True, timeout=15)
            _l("  " + (r.stdout.strip() or "— Сертификатов не найдено"), "ok")
        except Exception as e:
            _l(f"  ✗ {e}", "error")

        _l("▶ Отключаю системный прокси...", "section")
        if winreg:
            try:
                reg = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg, 0,
                                    winreg.KEY_WRITE) as k:
                    winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                _notify_wininet()
                _l("  ✓ Прокси отключён", "ok")
            except Exception as e:
                _l(f"  ✗ {e}", "error")

        self.finished.emit()


# ─────────────────────────────────────────────────────────────────────────────
# API helpers (bypass system proxy — talk directly to DLP server)
# ─────────────────────────────────────────────────────────────────────────────

def _api_get(ip: str, port: int, path: str) -> dict:
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        req = urllib.request.Request(f"http://{ip}:{port}{path}",
                                     headers={"Accept": "application/json"})
        with opener.open(req, timeout=5) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None

def _api_post(ip: str, port: int, path: str, data: dict) -> dict:
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        body = json.dumps(data).encode("utf-8")
        req = urllib.request.Request(f"http://{ip}:{port}{path}", data=body,
                                     method="POST",
                                     headers={"Content-Type": "application/json"})
        with opener.open(req, timeout=5) as r:
            return json.loads(r.read().decode("utf-8"))
    except Exception:
        return None


class NotificationPoller(QThread):
    """Background poller for /api/notifications, /api/messages, /api/internet_status"""
    new_notifications = pyqtSignal(list)
    new_messages      = pyqtSignal(list)
    internet_status   = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.server_ip = ""
        self.port = 8000
        self.client_ip = ""
        self._stop = False
        self._seen_ids: set = set()
        self._last_msg_time = ""

    def stop(self):
        self._stop = True

    def run(self):
        import time
        while not self._stop:
            if self.server_ip and self.client_ip:
                # Notifications
                try:
                    d = _api_get(self.server_ip, self.port,
                                 f"/api/notifications?client_ip={self.client_ip}&unread_only=1")
                    if d and d.get("notifications"):
                        new = [n for n in d["notifications"] if n.get("id") not in self._seen_ids]
                        for n in new:
                            self._seen_ids.add(n["id"])
                        if new:
                            self.new_notifications.emit(new)
                except Exception:
                    pass
                # Messages
                try:
                    p = f"/api/messages?client_ip={self.client_ip}"
                    if self._last_msg_time:
                        p += f"&since={self._last_msg_time}"
                    d = _api_get(self.server_ip, self.port, p)
                    if d and d.get("messages"):
                        self.new_messages.emit(d["messages"])
                        self._last_msg_time = d["messages"][-1].get("time", "")
                except Exception:
                    pass
                # Internet access status
                try:
                    d = _api_get(self.server_ip, self.port,
                                 f"/api/internet_status?client_ip={self.client_ip}")
                    if d is not None:
                        self.internet_status.emit(d)
                except Exception:
                    pass
            time.sleep(8)


# ─────────────────────────────────────────────────────────────────────────────
# Main Window
# ─────────────────────────────────────────────────────────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DLP Agent — EndPoint v6.0")
        self.setMinimumSize(800, 780)
        self.resize(840, 820)
        self._admin   = _is_admin()
        self._workers = []
        self._scan_worker = None
        self._agent_cfg = _load_agent_config()
        self._internet_status = {}
        self._poller  = NotificationPoller()
        self._poller.new_notifications.connect(self._on_new_notifications)
        self._poller.new_messages.connect(self._on_new_messages)
        self._poller.internet_status.connect(self._on_internet_status)
        self._poller.start()
        self._notif_items: list[dict] = []
        self._chat_msgs: list[dict] = []
        self._build_ui()
        self._log("DLP EndPoint Agent v6.0 — готов к работе", "ok")
        if not self._admin:
            self._log("ВНИМАНИЕ: нет прав администратора!", "error")
        else:
            self._log(f"Ваш IP: {_local_ip()}", "info")
        # Load saved server IP
        saved_ip = self._agent_cfg.get("server_ip", "")
        if saved_ip:
            self.ip_edit.setText(saved_ip)
            saved_cp = str(self._agent_cfg.get("cert_port", 8000))
            saved_pp = str(self._agent_cfg.get("proxy_port", 8080))
            self.cert_port_edit.setText(saved_cp)
            self.proxy_port_edit.setText(saved_pp)
            self._log(f"Загружены настройки: сервер {saved_ip}:{saved_cp}", "info")
            self._start_poller()
            # Auto-setup proxy on launch if enabled
            if self._agent_cfg.get("auto_setup", True):
                QTimer.singleShot(1500, self._auto_setup_proxy)
        else:
            # First launch — auto-scan
            self._log("Первый запуск — автопоиск сервера...", "section")
            QTimer.singleShot(500, self._run_scan)
        # Update autostart checkbox
        self.cb_autostart.setChecked(_get_autostart_enabled())

    def closeEvent(self, event):
        self._poller.stop()
        self._poller.wait(2000)
        super().closeEvent(event)

    # ══════════════════════════════════════════════════════════════════════════
    # UI BUILD
    # ══════════════════════════════════════════════════════════════════════════

    def _build_ui(self):
        root = QWidget(); self.setCentralWidget(root)
        lay = QVBoxLayout(root); lay.setContentsMargins(0,0,0,0); lay.setSpacing(0)

        # Header
        hdr = QFrame(); hdr.setObjectName("header"); hdr.setFixedHeight(66)
        hl = QHBoxLayout(hdr); hl.setContentsMargins(22,0,22,0)
        title = QLabel("🛡  DLP EndPoint Agent")
        title.setStyleSheet("background:transparent;color:#58a6ff;font-size:17px;font-weight:700")
        b_text = "✓ Администратор" if self._admin else "⚠ Нет прав"
        b_style = "background:#1a4731;color:#a8edbb" if self._admin else "background:#3d1515;color:#f38ba8"
        badge = QLabel(b_text)
        badge.setStyleSheet(f"{b_style};border-radius:12px;padding:4px 14px;font-size:11px;font-weight:600")
        self.notif_badge = QLabel("")
        self.notif_badge.setStyleSheet("background:#f38ba8;color:#fff;border-radius:10px;"
                                        "padding:2px 8px;font-size:11px;font-weight:700")
        self.notif_badge.setVisible(False)
        hl.addWidget(title); hl.addStretch()
        hl.addWidget(self.notif_badge); hl.addWidget(badge)
        lay.addWidget(hdr)

        # Tabs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane{border:none;background:#0d1117}
            QTabBar::tab{background:#161b22;color:#8b949e;padding:10px 20px;
                         border:1px solid #30363d;border-bottom:none;border-radius:6px 6px 0 0;
                         margin-right:2px;font-size:12px}
            QTabBar::tab:selected{background:#0d1117;color:#58a6ff;font-weight:700;
                                  border-bottom:2px solid #58a6ff}
            QTabBar::tab:hover{color:#c9d1d9}""")
        self.tabs.addTab(self._build_setup_tab(), "⚙️ Настройка")
        self.tabs.addTab(self._build_notif_tab(), "🔔 Уведомления")
        self.tabs.addTab(self._build_chat_tab(),  "💬 Чат")
        self.tabs.addTab(self._build_internet_tab(), "🌐 Интернет")
        lay.addWidget(self.tabs, stretch=1)

        self.status_lbl = QLabel("Готов к работе")
        self.status_lbl.setStyleSheet("color:#3fb950;font-size:11px;padding:4px 8px")
        lay.addWidget(self.status_lbl)

    # ── Tab 1: Setup ─────────────────────────────────────────────────────────

    def _build_setup_tab(self) -> QWidget:
        body = QWidget()
        body.setStyleSheet("background:#0d1117")
        bl = QVBoxLayout(body)
        bl.setContentsMargins(20, 14, 20, 12)
        bl.setSpacing(10)

        # ── Server settings ───────────────────────────────────────────────────
        srv_grp = QGroupBox("Настройки сервера")
        sl      = QHBoxLayout(srv_grp)
        sl.setSpacing(8)

        sl.addWidget(QLabel("IP сервера:"))
        self.ip_edit = QLineEdit()
        self.ip_edit.setPlaceholderText("напр. 192.168.101.31")
        self.ip_edit.setMaximumWidth(175)
        self.ip_edit.editingFinished.connect(self._start_poller)
        self.ip_edit.setToolTip(
            "IP-адрес машины где запущен server_main.py\n"
            "Посмотрите в консоли сервера: строка 'Сервер IP: ...'\n"
            "Или нажмите «🔍 Найти сервер»"
        )
        sl.addWidget(self.ip_edit)

        # Auto-scan button
        self.btn_scan = QPushButton("🔍 Найти сервер")
        self.btn_scan.setObjectName("btnScan")
        self.btn_scan.setToolTip(
            "Автоматически найти DLP-сервер в локальной сети.\n"
            "Сканирует вашу подсеть по порту 8000."
        )
        self.btn_scan.clicked.connect(self._run_scan)
        sl.addWidget(self.btn_scan)

        sl.addSpacing(8)
        sl.addWidget(QLabel("Cert:"))
        self.cert_port_edit = QLineEdit("8000")
        self.cert_port_edit.setMaximumWidth(58)
        sl.addWidget(self.cert_port_edit)

        sl.addWidget(QLabel("Proxy:"))
        self.proxy_port_edit = QLineEdit("8080")
        self.proxy_port_edit.setMaximumWidth(58)
        sl.addWidget(self.proxy_port_edit)

        self.btn_open = QPushButton("🌐 Страница сервера")
        self.btn_open.setObjectName("btnOpen")
        self.btn_open.setToolTip("Открыть http://IP:8000 — инструкция и скачать сертификат")
        self.btn_open.clicked.connect(self._open_page)
        sl.addWidget(self.btn_open)

        sl.addStretch()
        bl.addWidget(srv_grp)

        # Scan progress bar (hidden by default)
        self.scan_progress = QProgressBar()
        self.scan_progress.setFixedHeight(6)
        self.scan_progress.setVisible(False)
        self.scan_progress.setRange(0, 100)
        bl.addWidget(self.scan_progress)

        self.scan_label = QLabel("")
        self.scan_label.setStyleSheet("color:#6c7086;font-size:11px;padding:2px 0")
        self.scan_label.setVisible(False)
        bl.addWidget(self.scan_label)

        # ── Options ───────────────────────────────────────────────────────────
        opt_grp = QGroupBox("Шаги установки")
        ol      = QVBoxLayout(opt_grp)
        ol.setSpacing(4)
        self.cb_cert  = QCheckBox("Скачать и установить CA-сертификат  (Windows LocalMachine\\Root + Firefox)")
        self.cb_proxy = QCheckBox("Настроить системный прокси  (реестр HKCU + WinInet refresh)")
        self.cb_hsts  = QCheckBox("Закрыть браузеры и очистить HSTS-кэш  (Edge / Chrome / Firefox / Brave / Opera)")
        for cb in (self.cb_cert, self.cb_proxy, self.cb_hsts):
            cb.setChecked(True)
            ol.addWidget(cb)
        bl.addWidget(opt_grp)

        # ── Agent options ─────────────────────────────────────────────────────
        agent_grp = QGroupBox("EndPoint Agent")
        al = QVBoxLayout(agent_grp)
        al.setSpacing(4)
        self.cb_autostart = QCheckBox("Автозапуск при входе в Windows  (реестр HKCU\\Run)")
        self.cb_autostart.stateChanged.connect(self._toggle_autostart)
        al.addWidget(self.cb_autostart)
        self.cb_auto_setup = QCheckBox("Автоматически настраивать прокси при запуске агента")
        self.cb_auto_setup.setChecked(self._agent_cfg.get("auto_setup", True))
        self.cb_auto_setup.stateChanged.connect(self._toggle_auto_setup)
        al.addWidget(self.cb_auto_setup)
        bl.addWidget(agent_grp)

        # ── Action buttons ────────────────────────────────────────────────────
        bw  = QWidget()
        bwl = QHBoxLayout(bw)
        bwl.setContentsMargins(0, 0, 0, 0)
        bwl.setSpacing(10)

        self.btn_install = QPushButton("▶  Установить всё")
        self.btn_install.setObjectName("btnInstall")
        self.btn_install.setToolTip(
            "Скачивает сертификат с сервера,\n"
            "устанавливает в Windows, настраивает прокси,\n"
            "очищает HSTS-кэш браузеров."
        )
        self.btn_install.clicked.connect(self._run_install)

        self.btn_check = QPushButton("🔍  Проверить")
        self.btn_check.setObjectName("btnCheck")
        self.btn_check.setToolTip("Проверить доступность сервера и статус настроек")
        self.btn_check.clicked.connect(self._run_check)

        self.btn_remove = QPushButton("🗑  Удалить / Отключить")
        self.btn_remove.setObjectName("btnRemove")
        self.btn_remove.setToolTip("Удалить сертификат и отключить системный прокси")
        self.btn_remove.clicked.connect(self._run_remove)

        bwl.addWidget(self.btn_install, 3)
        bwl.addWidget(self.btn_check,   2)
        bwl.addWidget(self.btn_remove,  2)
        bl.addWidget(bw)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setFixedHeight(8)
        self.progress.setVisible(False)
        bl.addWidget(self.progress)

        # Divider
        div = QFrame()
        div.setStyleSheet("background:#30363d")
        div.setFixedHeight(1)
        bl.addWidget(div)

        # Log
        log_grp = QGroupBox("Журнал выполнения")
        ll = QVBoxLayout(log_grp)
        ll.setContentsMargins(8, 8, 8, 8)
        self.log_edit = QTextEdit()
        self.log_edit.setReadOnly(True)
        self.log_edit.setMinimumHeight(230)
        ll.addWidget(self.log_edit)
        clr = QPushButton("Очистить журнал")
        clr.setFixedSize(120, 24)
        clr.setStyleSheet(
            "font-size:11px;padding:0;min-height:0;"
            "background:#21262d;border-color:#30363d"
        )
        clr.clicked.connect(self.log_edit.clear)
        ll.addWidget(clr, alignment=Qt.AlignmentFlag.AlignRight)
        bl.addWidget(log_grp, stretch=1)

        return body

    # ── Tab 2: Notifications ─────────────────────────────────────────────────

    def _build_notif_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:#0d1117")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(20, 14, 20, 12)

        hdr = QLabel("🔔 Уведомления от системы DLP")
        hdr.setStyleSheet("color:#58a6ff;font-size:15px;font-weight:700;padding-bottom:8px")
        lay.addWidget(hdr)

        info = QLabel("Здесь отображаются уведомления о заблокированных файлах и запросы доступа от администратора.")
        info.setStyleSheet("color:#8b949e;font-size:12px;padding-bottom:12px")
        info.setWordWrap(True)
        lay.addWidget(info)

        # Scrollable notifications area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea{border:1px solid #21262d;border-radius:8px;background:#0a0c10}")
        self.notif_container = QWidget()
        self.notif_layout = QVBoxLayout(self.notif_container)
        self.notif_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.notif_layout.setSpacing(8)
        self.notif_layout.setContentsMargins(8, 8, 8, 8)

        placeholder = QLabel("Нет уведомлений")
        placeholder.setStyleSheet("color:#484f58;font-size:13px;padding:40px")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder.setObjectName("notif_placeholder")
        self.notif_layout.addWidget(placeholder)

        scroll.setWidget(self.notif_container)
        lay.addWidget(scroll, stretch=1)
        return w

    # ── Tab 3: Chat ──────────────────────────────────────────────────────────

    def _build_chat_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:#0d1117")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(20, 14, 20, 12)

        hdr = QLabel("💬 Чат с администратором")
        hdr.setStyleSheet("color:#58a6ff;font-size:15px;font-weight:700;padding-bottom:8px")
        lay.addWidget(hdr)

        # Messages area
        self.chat_area = QTextEdit()
        self.chat_area.setReadOnly(True)
        self.chat_area.setStyleSheet(
            "background:#0a0c10;border:1px solid #21262d;border-radius:8px;"
            "padding:12px;font-size:13px;color:#c9d1d9")
        self.chat_area.setHtml(
            '<p style="color:#484f58;text-align:center;padding:40px">'
            'Нет сообщений. Введите IP сервера на вкладке «Настройка» для начала.</p>')
        lay.addWidget(self.chat_area, stretch=1)

        # Input area
        input_w = QWidget()
        il = QHBoxLayout(input_w)
        il.setContentsMargins(0, 8, 0, 0)
        il.setSpacing(8)
        self.chat_input = QLineEdit()
        self.chat_input.setPlaceholderText("Написать сообщение...")
        self.chat_input.returnPressed.connect(self._send_chat)
        il.addWidget(self.chat_input, stretch=1)
        btn = QPushButton("Отправить")
        btn.setObjectName("btnCheck")
        btn.clicked.connect(self._send_chat)
        il.addWidget(btn)
        lay.addWidget(input_w)
        return w

    # ── Tab 4: Internet Access ───────────────────────────────────────────────

    def _build_internet_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet("background:#0d1117")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(20, 14, 20, 12)

        hdr = QLabel("🌐 Доступ в интернет")
        hdr.setStyleSheet("color:#58a6ff;font-size:15px;font-weight:700;padding-bottom:8px")
        lay.addWidget(hdr)

        # Status card
        self.inet_status_card = QFrame()
        self.inet_status_card.setStyleSheet(
            "QFrame{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px}")
        sc_lay = QVBoxLayout(self.inet_status_card)
        sc_lay.setSpacing(8)
        self.inet_status_icon = QLabel("🔒 Статус: проверяю...")
        self.inet_status_icon.setStyleSheet("color:#e3b341;font-size:14px;font-weight:700;background:transparent")
        sc_lay.addWidget(self.inet_status_icon)
        self.inet_status_detail = QLabel("Подключитесь к серверу для проверки")
        self.inet_status_detail.setStyleSheet("color:#8b949e;font-size:12px;background:transparent")
        self.inet_status_detail.setWordWrap(True)
        sc_lay.addWidget(self.inet_status_detail)
        lay.addWidget(self.inet_status_card)

        # Request form
        req_grp = QGroupBox("Отправить заявку на доступ в интернет")
        rl = QVBoxLayout(req_grp)
        rl.setSpacing(8)

        reason_lbl = QLabel("Укажите причину, зачем вам нужен доступ в интернет:")
        reason_lbl.setStyleSheet("color:#8b949e;font-size:12px")
        rl.addWidget(reason_lbl)

        self.inet_reason = QTextEdit()
        self.inet_reason.setPlaceholderText(
            "Например: Необходим доступ к сайту example.com для скачивания обновлений ПО.\n"
            "Или: Требуется доступ к внешнему API для работы приложения X.")
        self.inet_reason.setMaximumHeight(100)
        self.inet_reason.setStyleSheet(
            "background:#0a0c10;border:1px solid #21262d;border-radius:7px;"
            "padding:10px;font-size:13px;color:#c9d1d9")
        rl.addWidget(self.inet_reason)

        self.inet_submit_btn = QPushButton("📨 Отправить заявку администратору")
        self.inet_submit_btn.setObjectName("btnCheck")
        self.inet_submit_btn.clicked.connect(self._submit_internet_request)
        rl.addWidget(self.inet_submit_btn)

        self.inet_submit_status = QLabel("")
        self.inet_submit_status.setStyleSheet("color:#8b949e;font-size:12px")
        self.inet_submit_status.setWordWrap(True)
        rl.addWidget(self.inet_submit_status)

        lay.addWidget(req_grp)

        # Info
        info = QLabel(
            "ℹ️ Данная сеть работает в режиме закрытой корпоративной сети.\n"
            "Доступ к внешним ресурсам (интернету) возможен только с разрешения администратора.\n"
            "Внутренние ресурсы сети доступны без ограничений.")
        info.setStyleSheet("color:#6c7086;font-size:11px;padding-top:8px")
        info.setWordWrap(True)
        lay.addWidget(info)

        lay.addStretch()
        return w

    # ══════════════════════════════════════════════════════════════════════════
    # NOTIFICATION HANDLERS
    # ══════════════════════════════════════════════════════════════════════════

    def _start_poller(self):
        """Update poller with current server settings and trigger immediate load"""
        ip, cp, _ = self._get_params()
        if ip:
            old_ip = self._poller.server_ip
            self._poller.server_ip = ip
            self._poller.port = cp
            self._poller.client_ip = _local_ip()
            # Save config
            self._save_server_config()
            # Reset message time to get full history on new server / first connect
            if old_ip != ip:
                self._poller._last_msg_time = ""
            # Immediate load in background
            def _quick_load():
                import time as _t; _t.sleep(0.5)
                try:
                    d = _api_get(ip, cp, f"/api/messages?client_ip={_local_ip()}")
                    if d and d.get("messages"):
                        self._poller.new_messages.emit(d["messages"])
                except Exception:
                    pass
            threading.Thread(target=_quick_load, daemon=True).start()

    def _on_new_notifications(self, notifs: list):
        """Called when poller finds new notifications"""
        # Group: blocked + access_request for same incident
        blocked_map = {}  # incident_id -> blocked notif
        access_map = {}   # incident_id -> access_request notif
        other = []

        for n in notifs:
            self._add_notif_card(n)
            ntype = n.get("type", "")
            inc_id = n.get("details", {}).get("incident_id", "")
            if ntype == "blocked" and inc_id:
                blocked_map[inc_id] = n
            elif ntype == "access_request" and inc_id:
                access_map[inc_id] = n
            elif ntype == "message":
                self.tabs.setTabText(2, "💬 Чат ●")
            elif ntype in ("internet_approved", "internet_denied"):
                self.tabs.setTabText(3, "🌐 Интернет ●")
                # Show popup
                QMessageBox.information(self,
                    "Доступ в интернет", n.get("text", ""))

        # Show combined popups for blocked files
        shown_ids = set()
        for inc_id, blk_n in blocked_map.items():
            acc_n = access_map.get(inc_id)
            self._show_combined_popup(blk_n, acc_n)
            shown_ids.add(inc_id)

        # Show standalone access requests (not paired with block)
        for inc_id, acc_n in access_map.items():
            if inc_id not in shown_ids:
                self._show_access_popup(acc_n)

        # Update badge
        self.tabs.setTabText(1, "🔔 Уведомления ●")
        count = sum(1 for n in self._notif_items if not n.get("read"))
        if count > 0:
            self.notif_badge.setText(str(count))
            self.notif_badge.setVisible(True)

    def _add_notif_card(self, n: dict):
        """Add a notification card to the notifications tab"""
        self._notif_items.append(n)

        # Remove placeholder
        ph = self.notif_container.findChild(QLabel, "notif_placeholder")
        if ph:
            ph.setVisible(False)

        ntype = n.get("type", "")
        details = n.get("details", {})
        text = n.get("text", "")
        time_str = n.get("time", "")[-8:]

        card = QFrame()
        card.setStyleSheet(
            "QFrame{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:0px}"
            "QFrame:hover{border-color:#58a6ff}")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(14, 10, 14, 10)
        cl.setSpacing(6)

        # Header
        icon = {"blocked": "🚫", "access_request": "🔑", "message": "💬",
                "internet_approved": "✅", "internet_denied": "❌"}.get(ntype, "ℹ️")
        color = {"blocked": "#f38ba8", "access_request": "#e3b341", "message": "#79c0ff",
                 "internet_approved": "#a6e3a1", "internet_denied": "#f38ba8"}.get(ntype, "#8b949e")
        h = QLabel(f'<span style="color:{color};font-weight:700">{icon} {ntype.upper()}</span>'
                    f'<span style="color:#484f58;font-size:11px;margin-left:12px">{time_str}</span>')
        h.setStyleSheet("background:transparent")
        cl.addWidget(h)

        # Body text
        body = QLabel(text.replace('\n', '<br>'))
        body.setWordWrap(True)
        body.setStyleSheet(f"color:#c9d1d9;font-size:12px;background:transparent")
        cl.addWidget(body)

        # Action buttons for access requests
        if ntype == "access_request":
            event_id = details.get("incident_id", "")
            if event_id:
                btn_row = QWidget()
                btn_row.setStyleSheet("background:transparent")
                bl2 = QHBoxLayout(btn_row)
                bl2.setContentsMargins(0, 4, 0, 0)
                bl2.setSpacing(8)
                btn_ok = QPushButton("✅ Разрешить просмотр")
                btn_ok.setStyleSheet(
                    "background:#1a4731;border:1px solid #2ea043;color:#a8edbb;"
                    "border-radius:6px;padding:6px 16px;font-weight:600")
                btn_ok.clicked.connect(lambda ch, eid=event_id: self._respond_access(eid, True))
                btn_deny = QPushButton("❌ Отклонить")
                btn_deny.setStyleSheet(
                    "background:#2d1515;border:1px solid #6e2a2a;color:#f38ba8;"
                    "border-radius:6px;padding:6px 16px;font-weight:600")
                btn_deny.clicked.connect(lambda ch, eid=event_id: self._respond_access(eid, False))
                bl2.addWidget(btn_ok)
                bl2.addWidget(btn_deny)
                bl2.addStretch()
                cl.addWidget(btn_row)

        self.notif_layout.insertWidget(0, card)

    def _show_combined_popup(self, block_notif: dict, access_notif):
        """Show combined popup: file blocked + optional access request"""
        details = block_notif.get("details", {})
        fname = details.get("filename", "файл")
        reason = details.get("reason", "Конфиденциальные данные")
        quotes = details.get("quotes", [])
        score = details.get("score", 0)
        event_id = details.get("incident_id", "")

        msg = (
            f"🚫 ФАЙЛ ЗАБЛОКИРОВАН\n\n"
            f"Файл: {fname}\n"
            f"Причина: {reason}\n"
        )
        if quotes:
            msg += "\nОбнаруженные данные:\n" + "\n".join(f"  • {q}" for q in quotes[:5])

        if access_notif:
            acc_details = access_notif.get("details", {})
            acc_msg = acc_details.get("message", "")
            msg += (
                f"\n\n{'─' * 40}\n\n"
                f"🔑 ЗАПРОС ДОСТУПА\n\n"
                f"{acc_msg}\n\n"
                f"Разрешить администратору просмотреть содержимое файла?"
            )
            reply = QMessageBox.question(
                self, "Файл заблокирован — Запрос доступа",
                msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
            approved = (reply == QMessageBox.StandardButton.Yes)
            self._respond_access(event_id, approved)
        else:
            msg += (
                f"\n\nАдминистратор получил уведомление, но НЕ видит "
                f"содержимое вашего файла."
            )
            QMessageBox.warning(self, "Файл заблокирован", msg)

    def _show_access_popup(self, n: dict):
        """Show popup when admin requests access (standalone)"""
        details = n.get("details", {})
        event_id = details.get("incident_id", "")
        fname = details.get("filename", "файл")
        admin = details.get("admin", "Администратор")
        message = details.get("message", "")
        reason = details.get("reason", "")

        msg = f"🔑 ЗАПРОС ДОСТУПА\n\n"
        if message:
            msg += f"{message}\n\n"
        msg += f"Файл: {fname}\n"
        if reason:
            msg += f"Причина блокировки: {reason}\n"
        msg += (
            f"\nРазрешить {admin} просмотреть содержимое файла?\n\n"
            f"• «Да» — администратор сможет увидеть содержимое\n"
            f"• «Нет» — содержимое останется скрытым"
        )
        reply = QMessageBox.question(
            self, "Запрос доступа к файлу", msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        self._respond_access(event_id, reply == QMessageBox.StandardButton.Yes)

    def _respond_access(self, event_id: str, approved: bool):
        """Send access response to server"""
        ip, cp, _ = self._get_params()
        if not ip or not event_id:
            return
        result = _api_post(ip, cp, "/api/access_response",
                           {"event_id": event_id, "approved": approved})
        status = "разрешён" if approved else "отклонён"
        self._log(f"[Доступ] {event_id}: {status}", "ok" if approved else "warn")
        if result and result.get("ok"):
            QMessageBox.information(self, "Готово", f"Доступ {status}.")
        else:
            QMessageBox.warning(self, "Ошибка", "Не удалось отправить ответ серверу.")

    # ══════════════════════════════════════════════════════════════════════════
    # CHAT HANDLERS
    # ══════════════════════════════════════════════════════════════════════════

    def _on_new_messages(self, msgs: list):
        """Called when poller finds new/all chat messages"""
        if not msgs:
            return
        # Merge: keep existing messages, add new ones by ID
        existing_ids = {m.get("id") for m in self._chat_msgs}
        for m in msgs:
            if m.get("id") not in existing_ids:
                self._chat_msgs.append(m)
                existing_ids.add(m.get("id"))
        # Sort by time
        self._chat_msgs.sort(key=lambda x: x.get("time", ""))
        self._rebuild_chat()

    def _rebuild_chat(self):
        """Rebuild chat HTML from messages"""
        html = ""
        for m in self._chat_msgs:
            is_admin = m.get("from") == "admin"
            name = m.get("from_name", m.get("from", "?"))
            text = m.get("text", "")
            time_s = m.get("time", "")[-8:]
            if is_admin:
                html += (
                    f'<div style="margin:6px 0;text-align:left">'
                    f'<div style="display:inline-block;background:#1f3a5a;'
                    f'border:1px solid #2d5a8a;border-radius:12px;padding:8px 14px;'
                    f'max-width:75%">'
                    f'<div style="font-size:10px;color:#6c7086">👤 {name} · {time_s}</div>'
                    f'<div style="color:#c9d1d9">{text}</div>'
                    f'</div></div>'
                )
            else:
                html += (
                    f'<div style="margin:6px 0;text-align:right">'
                    f'<div style="display:inline-block;background:#1a4731;'
                    f'border:1px solid #2ea043;border-radius:12px;padding:8px 14px;'
                    f'max-width:75%">'
                    f'<div style="font-size:10px;color:#6c7086">Вы · {time_s}</div>'
                    f'<div style="color:#c9d1d9">{text}</div>'
                    f'</div></div>'
                )
        if not html:
            html = '<p style="color:#484f58;text-align:center;padding:40px">Нет сообщений</p>'
        self.chat_area.setHtml(html)
        self.chat_area.moveCursor(QTextCursor.MoveOperation.End)

    def _send_chat(self):
        """Send chat message to admin"""
        text = self.chat_input.text().strip()
        if not text:
            return
        ip, cp, _ = self._get_params()
        if not ip:
            QMessageBox.warning(self, "Ошибка", "Введите IP сервера на вкладке «Настройка»!")
            return
        client_ip = _local_ip()
        result = _api_post(ip, cp, "/api/messages",
                           {"client_ip": client_ip, "text": text})
        if result and result.get("ok"):
            self.chat_input.clear()
            # Add to local display immediately
            self._chat_msgs.append({
                "from": "client", "from_name": "Вы",
                "text": text, "time": datetime.now().isoformat(timespec="seconds")
            })
            self._rebuild_chat()
        else:
            self._log("[Чат] Ошибка отправки", "error")

    # ══════════════════════════════════════════════════════════════════════════
    # ENDPOINT AGENT: AUTO-SETUP & AUTOSTART
    # ══════════════════════════════════════════════════════════════════════════

    def _auto_setup_proxy(self):
        """Called on startup: auto-set proxy if server is reachable"""
        ip, cp, pp = self._get_params()
        if not ip:
            return
        # Check if proxy already set
        if _proxy_is_set(ip, pp):
            self._log("Прокси уже настроен — пропуск авто-настройки", "ok")
            return
        # Check if server is reachable
        if not _tcp_open(ip, cp, 2000):
            self._log(f"Сервер {ip}:{cp} недоступен — авто-настройка отложена", "warn")
            return
        self._log("Авто-настройка прокси при запуске...", "section")
        # Set proxy silently
        if winreg:
            try:
                reg = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg, 0, winreg.KEY_WRITE) as k:
                    winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                    winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, f"{ip}:{pp}")
                    winreg.SetValueEx(k, "ProxyOverride", 0, winreg.REG_SZ,
                                      f"localhost;127.0.0.1;{ip};<local>")
                _notify_wininet()
                self._log(f"  ✓ Прокси настроен: {ip}:{pp}", "ok")
            except Exception as e:
                self._log(f"  ✗ Ошибка настройки прокси: {e}", "error")

    def _toggle_autostart(self, state):
        enabled = bool(state)
        ok = _set_autostart(enabled)
        if ok:
            self._log(f"Автозапуск {'включён' if enabled else 'выключен'}", "ok")
        else:
            self._log("Не удалось изменить автозапуск", "error")

    def _toggle_auto_setup(self, state):
        self._agent_cfg["auto_setup"] = bool(state)
        _save_agent_config(self._agent_cfg)

    def _save_server_config(self):
        """Save current server params to agent config"""
        ip, cp, pp = self._get_params()
        if ip:
            self._agent_cfg["server_ip"] = ip
            self._agent_cfg["cert_port"] = cp
            self._agent_cfg["proxy_port"] = pp
            _save_agent_config(self._agent_cfg)

    # ══════════════════════════════════════════════════════════════════════════
    # INTERNET ACCESS HANDLERS
    # ══════════════════════════════════════════════════════════════════════════

    def _on_internet_status(self, status: dict):
        """Called by poller with internet status update"""
        self._internet_status = status
        policy = status.get("policy", "block")
        has_access = status.get("has_access", False)
        pending = status.get("pending_request")

        if policy == "allow":
            self.inet_status_icon.setText("🌐 Доступ в интернет: РАЗРЕШЁН (открытая сеть)")
            self.inet_status_icon.setStyleSheet("color:#a6e3a1;font-size:14px;font-weight:700;background:transparent")
            self.inet_status_detail.setText("Интернет доступен всем пользователям.")
            self.inet_status_card.setStyleSheet(
                "QFrame{background:#0d1f15;border:1px solid #2ea043;border-radius:8px;padding:16px}")
            self.inet_submit_btn.setEnabled(False)
            self.inet_submit_btn.setText("Заявка не требуется")
        elif has_access:
            details = status.get("details", {})
            exp = details.get("expires", "")
            exp_str = f"до {exp[:16]}" if exp else "бессрочно"
            approved_by = details.get("approved_by", "")
            self.inet_status_icon.setText("✅ Доступ в интернет: РАЗРЕШЁН")
            self.inet_status_icon.setStyleSheet("color:#a6e3a1;font-size:14px;font-weight:700;background:transparent")
            self.inet_status_detail.setText(
                f"Одобрил: {approved_by}\n"
                f"Действует: {exp_str}")
            self.inet_status_card.setStyleSheet(
                "QFrame{background:#0d1f15;border:1px solid #2ea043;border-radius:8px;padding:16px}")
            self.inet_submit_btn.setEnabled(False)
            self.inet_submit_btn.setText("Доступ уже разрешён")
        elif pending:
            self.inet_status_icon.setText("⏳ Заявка на рассмотрении")
            self.inet_status_icon.setStyleSheet("color:#e3b341;font-size:14px;font-weight:700;background:transparent")
            self.inet_status_detail.setText(
                f"Ваша заявка отправлена: {pending.get('time','')[:16]}\n"
                f"Причина: {pending.get('reason','')[:100]}\n"
                f"Ожидайте решения администратора.")
            self.inet_status_card.setStyleSheet(
                "QFrame{background:#1f1a08;border:1px solid #e3b341;border-radius:8px;padding:16px}")
            self.inet_submit_btn.setEnabled(False)
            self.inet_submit_btn.setText("Заявка уже отправлена")
        else:
            self.inet_status_icon.setText("🔒 Доступ в интернет: ЗАБЛОКИРОВАН")
            self.inet_status_icon.setStyleSheet("color:#f38ba8;font-size:14px;font-weight:700;background:transparent")
            self.inet_status_detail.setText(
                "У вас нет разрешения на доступ в интернет.\n"
                "Отправьте заявку администратору, указав причину.")
            self.inet_status_card.setStyleSheet(
                "QFrame{background:#1f0d0d;border:1px solid #f38ba8;border-radius:8px;padding:16px}")
            self.inet_submit_btn.setEnabled(True)
            self.inet_submit_btn.setText("📨 Отправить заявку администратору")

    def _submit_internet_request(self):
        """Submit internet access request to server"""
        reason = self.inet_reason.toPlainText().strip()
        if not reason:
            QMessageBox.warning(self, "Ошибка",
                "Укажите причину, зачем вам нужен доступ в интернет.")
            return
        ip, cp, _ = self._get_params()
        if not ip:
            QMessageBox.warning(self, "Ошибка",
                "Введите IP сервера на вкладке «Настройка»!")
            return
        client_ip = _local_ip()
        result = _api_post(ip, cp, "/api/internet_request",
                           {"client_ip": client_ip, "reason": reason})
        if result and result.get("ok"):
            self.inet_submit_status.setText("✅ Заявка отправлена! Ожидайте решения администратора.")
            self.inet_submit_status.setStyleSheet("color:#a6e3a1;font-size:12px")
            self.inet_reason.clear()
            self.inet_submit_btn.setEnabled(False)
            self.inet_submit_btn.setText("Заявка отправлена")
            self._log(f"[Интернет] Заявка отправлена: {reason[:60]}", "ok")
        elif result and result.get("error") == "already_pending":
            self.inet_submit_status.setText("⏳ У вас уже есть активная заявка. Ожидайте решения.")
            self.inet_submit_status.setStyleSheet("color:#e3b341;font-size:12px")
        elif result and result.get("error") == "already_has_access":
            self.inet_submit_status.setText("✅ У вас уже есть доступ в интернет!")
            self.inet_submit_status.setStyleSheet("color:#a6e3a1;font-size:12px")
        else:
            self.inet_submit_status.setText("❌ Ошибка отправки заявки. Проверьте подключение к серверу.")
            self.inet_submit_status.setStyleSheet("color:#f38ba8;font-size:12px")
            self._log("[Интернет] Ошибка отправки заявки", "error")

    # ══════════════════════════════════════════════════════════════════════════
    # EXISTING HELPERS (unchanged)
    # ══════════════════════════════════════════════════════════════════════════

    def _get_params(self) -> tuple[str, int, int]:
        ip    = self.ip_edit.text().strip()
        cport = int(self.cert_port_edit.text().strip() or "8000")
        pport = int(self.proxy_port_edit.text().strip() or "8080")
        return ip, cport, pport

    def _set_status(self, text: str, color: str):
        self.status_lbl.setText(text)
        self.status_lbl.setStyleSheet(f"color:{color};font-size:11px;padding:4px 0")

    def _open_page(self):
        """Open server instructions page (not admin panel)"""
        ip, cp, _ = self._get_params()
        if not ip:
            QMessageBox.warning(self, "Ошибка", "Введите IP сервера!")
            return
        url = f"http://{ip}:{cp}/"     # инструкции по установке
        try:
            os.startfile(url)
        except Exception:
            subprocess.Popen(["start", url], shell=True)

    # ── Auto-scan ─────────────────────────────────────────────────────────────

    def _run_scan(self):
        cp = int(self.cert_port_edit.text().strip() or "8000")
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("⏳ Сканирую...")
        self.scan_progress.setVisible(True)
        self.scan_progress.setValue(0)
        self.scan_label.setVisible(True)
        self.scan_label.setText("Поиск DLP-сервера в сети...")
        self._log("─" * 48, "sep")
        self._log("Автопоиск DLP-сервера в сети...", "section")

        w = ScanWorker(cp)
        w.found.connect(self._on_server_found)
        w.progress.connect(self._on_scan_progress)
        w.done.connect(self._on_scan_done)
        self._scan_worker = w
        self._workers.append(w)
        w.start()

    def _on_server_found(self, ip: str):
        self.ip_edit.setText(ip)
        self._log(f"  ✓ Найден сервер: {ip}", "ok")
        self._start_poller()

    def _on_scan_progress(self, pct: int, text: str):
        self.scan_progress.setValue(pct)
        self.scan_label.setText(text)

    def _on_scan_done(self, found: bool):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("🔍 Найти сервер")
        self.scan_progress.setVisible(False)
        self.scan_label.setVisible(False)
        if not found:
            self._log("  ✗ Сервер не найден в сети", "error")
            self._log("    → Убедитесь что server_main.py запущен", "warn")
            self._log("    → Введите IP вручную", "warn")
            QMessageBox.warning(
                self, "Сервер не найден",
                "DLP-сервер не обнаружен в локальной сети.\n\n"
                "Убедитесь что:\n"
                "1. server_main.py запущен на сервере\n"
                "2. Обе машины в одной сети\n"
                "3. Firewall разрешает порт 8000\n\n"
                "Введите IP сервера вручную."
            )

    # ── Check ─────────────────────────────────────────────────────────────────

    def _run_check(self):
        ip, cp, pp = self._get_params()
        if not ip:
            QMessageBox.warning(self, "Ошибка", "Введите IP сервера!"); return
        self._start_poller()
        self._log("─" * 48, "sep")
        self._log(f"Проверка {ip}...", "section")
        self.btn_check.setEnabled(False)
        w = CheckWorker(ip, cp, pp)
        w.result.connect(lambda lines: [self._log(t, lv) for t, lv in lines])
        w.result.connect(lambda _: self.btn_check.setEnabled(True))
        self._workers.append(w)
        w.start()

    # ── Install ───────────────────────────────────────────────────────────────

    def _run_install(self):
        ip, cp, pp = self._get_params()
        if not ip:
            QMessageBox.warning(self, "Ошибка",
                "Введите IP-адрес сервера!\n\n"
                "Нажмите «🔍 Найти сервер» для автопоиска\n"
                "или введите IP вручную."
            )
            return

        self._log("─" * 48, "sep")
        self._log(f"Установка — сервер {ip}:{cp}  |  прокси {ip}:{pp}", "section")

        for b in (self.btn_install, self.btn_check, self.btn_remove, self.btn_scan):
            b.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self._set_status("Установка...", "#e3b341")

        w = SetupWorker(ip, cp, pp,
                        self.cb_cert.isChecked(),
                        self.cb_proxy.isChecked(),
                        self.cb_hsts.isChecked())
        w.log_line.connect(self._log)
        w.progress.connect(self.progress.setValue)
        w.finished.connect(self._on_install_done)
        self._workers.append(w)
        w.start()

    def _on_install_done(self, success: bool, summary: str):
        for b in (self.btn_install, self.btn_check, self.btn_remove, self.btn_scan):
            b.setEnabled(True)
        self.progress.setVisible(False)

        if success:
            self._log("✅ УСТАНОВКА ЗАВЕРШЕНА УСПЕШНО", "ok")
            self._log(summary, "ok")
            self._set_status("✅ Установка завершена", "#3fb950")
            self._start_poller()
            ip, cp, _ = self._get_params()
            QMessageBox.information(
                self, "Готово",
                "✅ Установка завершена!\n\n"
                "Откройте браузер и проверьте:\n"
                "  • https://yandex.ru\n"
                "  • https://ru.wikipedia.org\n"
                "  • https://chat.qwen.ai\n\n"
                "Предупреждений о сертификате быть не должно."
            )
        else:
            self._log("❌ ОШИБКИ ПРИ УСТАНОВКЕ", "error")
            self._log(summary, "error")
            self._set_status("❌ Ошибки при установке", "#f38ba8")

    # ── Remove ────────────────────────────────────────────────────────────────

    def _run_remove(self):
        if QMessageBox.question(
            self, "Удаление",
            "Удалить DLP-сертификат и отключить прокси?\n\n"
            "После этого трафик не будет идти через DLP.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        ) != QMessageBox.StandardButton.Yes:
            return

        self._log("─" * 48, "sep")
        self._log("Удаление настроек DLP...", "section")
        self.btn_remove.setEnabled(False)
        w = RemoveWorker()
        w.log_line.connect(self._log)
        w.finished.connect(lambda: self.btn_remove.setEnabled(True))
        w.finished.connect(lambda: self._log("Удаление завершено", "ok"))
        w.finished.connect(lambda: self._set_status("Настройки удалены", "#8b949e"))
        self._workers.append(w)
        w.start()

    # ── Log ───────────────────────────────────────────────────────────────────

    def _log(self, text: str, level: str = "info"):
        COLORS = {
            "ok":      "#3fb950",
            "error":   "#f38ba8",
            "warn":    "#e3b341",
            "section": "#79c0ff",
            "info":    "#8b949e",
            "sep":     "#21262d",
        }
        color = COLORS.get(level, "#8b949e")
        ts    = datetime.now().strftime("%H:%M:%S")

        if level == "sep":
            self.log_edit.append(
                '<hr style="border:1px solid #21262d;margin:2px 0">'
            )
            return

        for line in text.split("\n"):
            if not line.strip():
                continue
            self.log_edit.append(
                f'<span style="color:#484f58">[{ts}]</span> '
                f'<span style="color:{color}">{line}</span>'
            )
        self.log_edit.moveCursor(QTextCursor.MoveOperation.End)


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Request UAC elevation if not admin
    if not _is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable,
            " ".join(f'"{a}"' for a in sys.argv),
            None, 1
        )
        sys.exit(0)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(STYLE)

    p = app.palette()
    p.setColor(QPalette.ColorRole.Window,          QColor("#0d1117"))
    p.setColor(QPalette.ColorRole.WindowText,      QColor("#c9d1d9"))
    p.setColor(QPalette.ColorRole.Base,            QColor("#161b22"))
    p.setColor(QPalette.ColorRole.Text,            QColor("#c9d1d9"))
    p.setColor(QPalette.ColorRole.Button,          QColor("#21262d"))
    p.setColor(QPalette.ColorRole.ButtonText,      QColor("#c9d1d9"))
    p.setColor(QPalette.ColorRole.Highlight,       QColor("#1f6feb"))
    p.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    app.setPalette(p)

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
