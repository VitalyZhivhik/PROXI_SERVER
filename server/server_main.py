"""
DLP Proxy Server v4.0

Changes v4.0:
  - NEW: Internet access control for closed networks
  - NEW: /admin/internet — manage internet access requests
  - NEW: API /api/internet_request, /api/internet_status
  - NEW: Clients can request internet access, admins approve/deny
  - NEW: internet_access.py shared module
  - Kept backward compatibility with open network mode

Changes v3.0:
  - FIXED: --ignore-hosts patterns now use valid regex (not glob *.domain)
  - FIXED: config.json reads both 'admin_login' and 'admin_user' keys
  - NEW: Auto-opens admin panel in browser on startup
  - NEW: Multi-admin support (manage admins from admin panel)
  - NEW: /admin/users — add/remove admins, change passwords
  - Admins stored in config.json under "admins" list
"""

import sys
import json
import re
import time
import signal
import socket
import hashlib
import logging
import secrets
import threading
import subprocess
import webbrowser
import mimetypes
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime, timedelta

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.log_config import setup_logging
from shared.internet_access import (
    get_all_data as ia_get_all_data,
    get_pending_count as ia_get_pending_count,
    approve_request as ia_approve_request,
    deny_request as ia_deny_request,
    grant_access as ia_grant_access,
    revoke_access as ia_revoke_access,
    submit_internet_request as ia_submit_request,
    get_internet_status as ia_get_internet_status,
)
from server.cert_manager import (
    generate_ca_certificate, get_cert_info,
    CA_CERT_FILE, CA_CERT_DER_FILE,
)

# Transparency: always use direct file access (no shared module import)
# This avoids the race condition where shared.transparency reads from
# transparency.json (chat) but incidents are in incidents.json
_tp = None
_HAS_TP = False

# Fallback: direct JSON reader/writer if transparency.py not found
_TP_FILE  = Path(__file__).parent.parent / "logs" / "transparency.json"   # chat only
_INC_FILE = Path(__file__).parent.parent / "logs" / "incidents.json"      # incidents (dlp_addon writes)
_NTF_FILE = Path(__file__).parent.parent / "logs" / "client_notifications.json"  # notifications (dlp_addon writes)

class _TpFallback:
    """Transparency operations via direct JSON file access.
    Uses SEPARATE files to avoid race conditions with dlp_addon process:
      - incidents.json: written by dlp_addon, read by server
      - client_notifications.json: written by dlp_addon, read/modified by server
      - transparency.json: chat messages, written by server only
    """
    @staticmethod
    def _read_json(path):
        try:
            if path.exists():
                return json.loads(path.read_text(encoding="utf-8"))
        except Exception: pass
        return None

    @staticmethod
    def _write_json(path, data):
        try:
            path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str),
                            encoding="utf-8")
        except Exception: pass

    # ── Incidents (read from incidents.json) ──────────────────────────────

    def get_incidents(self, status="", client_ip="", limit=100):
        items = self._read_json(_INC_FILE) or []
        if status: items = [i for i in items if i.get("status") == status]
        if client_ip: items = [i for i in items if i.get("client_ip") == client_ip]
        return list(reversed(items[-limit:]))

    def get_incident(self, eid):
        for i in (self._read_json(_INC_FILE) or []):
            if i["id"] == eid: return dict(i)
        return None

    def update_incident(self, eid, **kw):
        items = self._read_json(_INC_FILE) or []
        for i in items:
            if i["id"] == eid:
                i.update(kw)
                self._write_json(_INC_FILE, items)
                return True
        return False

    # ── Chat messages (read/write transparency.json) ─────────────────────

    def _read_chat(self):
        return self._read_json(_TP_FILE) or {"messages": {}}

    def _write_chat(self, data):
        self._write_json(_TP_FILE, data)

    def get_messages(self, ip, since=""):
        msgs = self._read_chat().get("messages", {}).get(ip, [])
        return [m for m in msgs if m["time"] > since] if since else msgs

    def mark_messages_read(self, ip, reader):
        d = self._read_chat()
        changed = False
        for m in d.get("messages", {}).get(ip, []):
            if m["from"] != reader and not m.get("read"):
                m["read"] = True
                changed = True
        if changed:
            self._write_chat(d)

    def send_message(self, ip, sender, text, sender_name=""):
        d = self._read_chat()
        msg = {"id": f"msg_{datetime.now().strftime('%H%M%S%f')[:10]}",
               "from": sender, "from_name": sender_name or sender,
               "text": text[:2000], "time": datetime.now().isoformat(timespec="seconds"),
               "read": False}
        d.setdefault("messages", {}).setdefault(ip, []).append(msg)
        d["messages"][ip] = d["messages"][ip][-200:]
        self._write_chat(d)
        # Notification for client (write to separate file)
        if sender == "admin":
            notifs = self._read_json(_NTF_FILE) or {}
            notifs.setdefault(ip, []).append({
                "id": f"n_m_{msg['id']}",
                "type": "message", "text": f"💬 {sender_name or 'Админ'}: {text[:100]}",
                "time": msg["time"], "read": False, "details": {},
            })
            notifs[ip] = notifs[ip][-100:]
            self._write_json(_NTF_FILE, notifs)
        return msg

    def get_all_chats_summary(self):
        d = self._read_chat()
        result = []
        for ip, msgs in d.get("messages", {}).items():
            if not msgs: continue
            unread = sum(1 for m in msgs if m["from"] == "client" and not m["read"])
            result.append({"client_ip": ip, "total": len(msgs), "unread": unread,
                           "last_text": msgs[-1]["text"][:80], "last_time": msgs[-1]["time"]})
        return sorted(result, key=lambda x: x["last_time"], reverse=True)

    # ── Notifications (read from client_notifications.json) ──────────────

    def get_notifications(self, ip, unread_only=False):
        notifs = (self._read_json(_NTF_FILE) or {}).get(ip, [])
        return [n for n in notifs if not n["read"]] if unread_only else notifs

    def get_unread_notifications_count(self, ip):
        return sum(1 for n in (self._read_json(_NTF_FILE) or {}).get(ip, []) if not n["read"])

    def respond_access(self, eid, approved):
        # Update incident
        items = self._read_json(_INC_FILE) or []
        status = "approved" if approved else "denied"
        for i in items:
            if i["id"] == eid: i["access_status"] = status; break
        self._write_json(_INC_FILE, items)
        return True

    def request_access(self, eid, admin_user):
        return True  # Handled by _handle_access_request directly

# Use fallback if import failed
if not _HAS_TP:
    _tp = _TpFallback()
    _HAS_TP = True

logger = setup_logging("server", log_dir="logs")

# ── Config ────────────────────────────────────────────────────────────────────
_DEFAULT_CONFIG = {
    "cert_port": 8000,
    "proxy_port": 8080,
    "upstream_proxy": "http://127.0.0.1:10809",
    "proxy_host": "0.0.0.0",
    # Primary admin (fallback if no "admins" list)
    "admin_user": "admin",
    "admin_password": "dlp2024",
    # Multi-admin list: [{"user": "...", "password": "...", "role": "admin"}]
    "admins": [],
    # Open browser on startup?
    "open_browser": True,
}

_CONFIG_PATH = Path(__file__).parent.parent / "config.json"


def load_config() -> dict:
    cfg = dict(_DEFAULT_CONFIG)
    if _CONFIG_PATH.exists():
        try:
            loaded = json.loads(_CONFIG_PATH.read_text(encoding="utf-8"))
            cfg.update(loaded)
            logger.info(f"[Config] Загружен: {_CONFIG_PATH}")
        except Exception as e:
            logger.warning(f"[Config] Ошибка чтения: {e}, используем defaults")
    else:
        try:
            _CONFIG_PATH.write_text(
                json.dumps(_DEFAULT_CONFIG, ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
        except Exception:
            pass
    # Compatibility: support both 'admin_login' (old) and 'admin_user' (new)
    if "admin_login" in cfg and "admin_user" not in cfg:
        cfg["admin_user"] = cfg["admin_login"]
    logger.info(f"[Config] Настройки: {cfg}")
    return cfg


def save_config(cfg: dict) -> bool:
    """Save config back to disk (used when admins are updated via panel)"""
    try:
        # Strip internal runtime keys before saving
        saveable = {k: v for k, v in cfg.items() if not k.startswith("_rt_")}
        _CONFIG_PATH.write_text(
            json.dumps(saveable, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        return True
    except Exception as e:
        logger.error(f"[Config] Ошибка сохранения: {e}")
        return False


# ── Paths ─────────────────────────────────────────────────────────────────────
EVENTS_FILE  = Path(__file__).parent.parent / "logs" / "dlp_events.json"
CAPTURES_DIR = Path(__file__).parent.parent / "logs" / "captures"
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)

# ── Traffic stats ─────────────────────────────────────────────────────────────
_traffic_log:   list[dict] = []
_traffic_lock   = threading.Lock()
_proxy_clients: set[str]  = set()
_blocked_count  = 0
_allowed_count  = 0

# ── Client heartbeat (from agent polling) ────────────────────────────────
_heartbeat_clients: dict[str, float] = {}  # ip -> last_seen timestamp
_heartbeat_lock = threading.Lock()

def _register_heartbeat(client_ip: str):
    """Register client as online (called from API endpoints)"""
    if client_ip and client_ip != "?" and not client_ip.startswith("127."):
        with _heartbeat_lock:
            _heartbeat_clients[client_ip] = time.time()
            _proxy_clients.add(client_ip)

# ── Session store ─────────────────────────────────────────────────────────────
_sessions: dict[str, dict] = {}   # token → {user, expiry}
_session_lock = threading.Lock()
SESSION_TTL   = timedelta(hours=8)

# ── Global config ref (set in main, used by handler) ─────────────────────────
_CFG: dict = {}
CERT_PORT = 8000

# ── DLP Settings (UI-configurable) ──────────────────────────────────────────
SETTINGS_FILE = Path(__file__).parent.parent / "logs" / "dlp_settings.json"
_DLP_SETTINGS: dict = {
    "theme": "dark",                   # dark / light
    "score_threshold": 80,
    "dlp_enabled": True,
    "rules_enabled": {
        "DSP_PHRASE": True, "PASSPORT_FULL": True, "SNILS": True,
        "INN_CTX": True, "INN_BARE": True, "CARD": True,
        "PHONE": True, "EMAIL": True, "FULL_NAME": True,
        "ADDRESS": True, "BANK_ACCOUNT": True, "BIRTH_DATE": True,
    },
    "auto_access_request": False,      # auto-send access request on block
    "access_request_message": "Администратор запрашивает разрешение на просмотр содержимого заблокированного файла для проверки.",
}

def _load_settings():
    global _DLP_SETTINGS
    try:
        if SETTINGS_FILE.exists():
            d = json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
            _DLP_SETTINGS.update(d)
    except Exception:
        pass

def _save_settings():
    try:
        SETTINGS_FILE.write_text(
            json.dumps(_DLP_SETTINGS, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
    except Exception:
        pass

_load_settings()


def _get_admins() -> list[dict]:
    """Return full admins list (primary + extras from 'admins' list)"""
    primary = {
        "user":     _CFG.get("admin_user", "admin"),
        "password": _CFG.get("admin_password", "dlp2024"),
        "role":     "superadmin",
        "primary":  True,
    }
    extras = _CFG.get("admins", [])
    return [primary] + [dict(a, primary=False) for a in extras]


def _check_credentials(user: str, pwd: str) -> bool:
    for a in _get_admins():
        if a["user"] == user and a["password"] == pwd:
            return True
    return False


def _create_session(user: str) -> str:
    token = secrets.token_hex(32)
    with _session_lock:
        _sessions[token] = {
            "user":   user,
            "expiry": datetime.now() + SESSION_TTL,
        }
    return token


def _session_user(token: str) -> str | None:
    """Returns username if session valid, else None"""
    with _session_lock:
        info = _sessions.get(token)
        if not info:
            return None
        if datetime.now() > info["expiry"]:
            del _sessions[token]
            return None
        info["expiry"] = datetime.now() + SESSION_TTL
        return info["user"]


def _check_auth(headers) -> str | None:
    """Extract session token from Cookie, return username or None"""
    cookie = headers.get("Cookie", "")
    for part in cookie.split(";"):
        k, _, v = part.strip().partition("=")
        if k.strip() == "dlp_session":
            return _session_user(v.strip())
    return None


# ── Windows helpers ───────────────────────────────────────────────────────────
def get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _notify_wininet():
    try:
        import ctypes
        w = ctypes.windll.wininet
        w.InternetSetOptionW(0, 39, 0, 0)
        w.InternetSetOptionW(0, 37, 0, 0)
    except Exception:
        pass


def fix_proxy_bypass(server_ip: str, proxy_port: int) -> None:
    try:
        import winreg
        reg = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg, 0,
                            winreg.KEY_READ | winreg.KEY_WRITE) as key:
            def _r(n):
                try: v, _ = winreg.QueryValueEx(key, n); return v
                except FileNotFoundError: return None

            override = str(_r("ProxyOverride") or "")
            required = ["localhost", "127.0.0.1", "::1", server_ip, "<local>"]
            current  = [e.strip() for e in override.replace(",", ";").split(";") if e.strip()]
            missing  = [r for r in required if r not in current]
            if missing:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ,
                                  ";".join(current + missing))
                _notify_wininet()
                logger.info(f"[LoopCheck] Bypass добавлено: {missing}")
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"[LoopCheck] Bypass: {e}")


def check_proxy_loop(server_ip: str, proxy_port: int, upstream: str) -> bool:
    loop = False
    try:
        import winreg
        reg = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg) as key:
            def _r(n):
                try: v, _ = winreg.QueryValueEx(key, n); return v
                except FileNotFoundError: return None
            enabled  = _r("ProxyEnable")
            srv_val  = str(_r("ProxyServer") or "")
            override = str(_r("ProxyOverride") or "")
            logger.info(
                f"[LoopCheck] WinInet: enabled={enabled}, "
                f"server='{srv_val}', override='{override}'"
            )
            if enabled == 1 and str(proxy_port) in srv_val:
                if server_ip in srv_val or "127.0.0.1" in srv_val:
                    logger.error(f"[LoopCheck] ПЕТЛЯ на порту {proxy_port}!")
                    loop = True
            elif enabled == 1:
                logger.info(f"[LoopCheck] Системный прокси: '{srv_val}' (VPN, нормально)")
            else:
                logger.info("[LoopCheck] Системный прокси отключён — OK")
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"[LoopCheck] {e}")
    if upstream:
        logger.info(f"[LoopCheck] Upstream (VPN): {upstream}")
    return loop


def _check_upstream_available(upstream: str) -> bool:
    """Check if upstream proxy (VPN) is available by connecting to its port."""
    if not upstream:
        return False
    try:
        # Parse upstream URL: http://127.0.0.1:10809
        from urllib.parse import urlparse
        p = urlparse(upstream)
        host = p.hostname or "127.0.0.1"
        port = p.port or 10809
        s = socket.create_connection((host, port), timeout=2)
        s.close()
        return True
    except Exception:
        return False


def record_traffic(client_ip: str, url: str, blocked: bool):
    global _blocked_count, _allowed_count
    with _traffic_lock:
        if blocked: _blocked_count += 1
        else:       _allowed_count += 1
        _proxy_clients.add(client_ip)
        _traffic_log.append({
            "time":    datetime.now().strftime("%H:%M:%S"),
            "client":  client_ip,
            "url":     url[:80],
            "blocked": blocked,
        })
        if len(_traffic_log) > 200:
            _traffic_log.pop(0)


# ── mitmproxy ignore-hosts (MUST be valid regex, NOT glob) ───────────────────
# mitmproxy compiles these with re.compile(), so * is invalid at position 0.
# Use proper regex: .*\.domain\.com instead of *.domain.com
IGNORE_HOSTS_REGEX = [
    # ── Microsoft / Windows ───────────────────────────────────────────────────
    r"ntp\.msn\.com",
    r".*\.msn\.com",
    r"login\.live\.com",
    r"login\.microsoftonline\.com",
    r".*\.microsoftonline\.com",
    r".*\.live\.com",
    r".*\.windowsupdate\.com",
    r"ctldl\.windowsupdate\.com",
    r".*\.microsoft\.com",
    r".*\.msftconnecttest\.com",
    r".*\.msftstatic\.com",
    r".*\.delivery\.mp\.microsoft\.com",
    # ── Certificate authorities ───────────────────────────────────────────────
    r".*\.digicert\.com",
    r"ocsp\.digicert\.com",
    r"ocsp2\.globalsign\.com",
    r"crl\.microsoft\.com",
    r".*\.verisign\.com",
    r".*\.ocsp\.msocsp\.com",
    r".*\.globalsign\.com",
    r".*\.letsencrypt\.org",
    # ── Google / YouTube ──────────────────────────────────────────────────────
    r".*\.googleapis\.com",
    r".*\.gstatic\.com",
    r".*\.google\.com",
    r".*\.google\.ru",
    r"accounts\.google\.com",
    r".*\.googlevideo\.com",   # YouTube video streams
    r".*\.ytimg\.com",         # YouTube images/thumbnails
    r"youtube\.com",
    r".*\.youtube\.com",
    r"youtu\.be",
    # ── Yandex + все CDN поддомены ────────────────────────────────────────────
    r"yandex\.ru",
    r".*\.yandex\.ru",
    r"yandex\.net",
    r".*\.yandex\.net",        # avatars.mds, static-mon и т.д.
    r"yandex\.com",
    r".*\.yandex\.com",
    r"ya\.ru",
    r".*\.ya\.ru",
    r"yastatic\.net",           # ГЛАВНЫЙ CDN Яндекса — картинки, скрипты, видео
    r".*\.yastatic\.net",
    r"dzen\.ru",
    r".*\.dzen\.ru",
    r".*\.dzeninfra\.ru",      # CDN Дзена — видео, аватары, статика
    r".*\.yandex-video\.net",
    r"strm\.yandex\.net",
    # ── Bing + все поддомены ──────────────────────────────────────────────────
    r"bing\.com",
    r".*\.bing\.com",
    r".*\.virtualearth\.net",
    # ── Mail.ru + CDN ─────────────────────────────────────────────────────────
    r"mail\.ru",
    r".*\.mail\.ru",
    r".*\.imgsmail\.ru",       # my2.imgsmail.ru — аватары и картинки mail.ru
    r"vk\.com",
    r".*\.vk\.com",
    r".*\.vk-cdn\.net",        # VK Video CDN
    r".*\.vkuser\.net",
    # ── Rutube ────────────────────────────────────────────────────────────────
    r"rutube\.ru",
    r".*\.rutube\.ru",
    r".*\.rambler\.ru",
    # ── Wikipedia ─────────────────────────────────────────────────────────────
    r"wikipedia\.org",
    r".*\.wikipedia\.org",
    r".*\.wikimedia\.org",
    r"upload\.wikimedia\.org",  # картинки Wikipedia
    # ── AI сервисы (стриминг/WebSocket — ломаются под MITM) ──────────────────
    r"chat\.qwen\.ai",
    r"qwen\.ai",
    r".*\.qwen\.ai",
    r".*\.alicdn\.com",        # CDN Qwen — КРИТИЧНО, без него Qwen не работает
    r".*\.aliyuncs\.com",      # Alibaba Cloud storage
    r".*\.alibabacloud\.com",
    r".*\.taobao\.com",
    r"claude\.ai",
    r".*\.anthropic\.com",
    r"chat\.openai\.com",
    r".*\.openai\.com",
    r"gemini\.google\.com",
    # ── DeepSeek — CDN passthrough, chat MITM ───────────────────────────
    r"cdn\.deepseek\.com",
    r"fe-static\.deepseek\.com",
    r"static\.deepseek\.com",
    r".*\.deepseekstatic\.com",
    # ── GigaChat / Сбер ──────────────────────────────────────────────────────
    r"gigachat\.ru",
    r".*\.gigachat\.ru",
    r"giga\.chat",
    r".*\.giga\.chat",
    r".*\.sber\.ru",
    r".*\.sberdevices\.ru",
    r"ngw\.devices\.sberbank\.ru",
    r"developers\.sber\.ru",
    # ── CDN сети (Akamai, Cloudflare и т.д.) ─────────────────────────────────
    r".*\.akamai\.net",
    r".*\.akamaihd\.net",
    r".*\.akamaized\.net",     # img-s-msn-com.akamaized.net — картинки MSN
    r".*\.cloudfront\.net",
    r".*\.fastly\.net",
    r".*\.cdn\.cloudflare\.net",
    r"challenges\.cloudflare\.com",
    r".*\.cdninstagram\.com",
    # ── Аналитика / счётчики (не несут ДСП, но вызывают TLS ошибки) ──────────
    r".*\.scorecardresearch\.com",
    r".*\.adnxs\.com",
    r".*\.mediago\.io",
    # ── Microsoft Azure / Blob Storage ────────────────────────────────────────
    r".*\.blob\.core\.windows\.net",
    r".*\.azure\.net",
    r".*\.azureedge\.net",
    # ── Skype ─────────────────────────────────────────────────────────────────
    r".*\.skype\.com",
    r"config\.edge\.skype\.com",
    # ── OK (Одноклассники) CDN ────────────────────────────────────────────────
    r".*\.okcdn\.ru",
    r".*\.mycdn\.me",
    r"ok\.ru",
    r".*\.ok\.ru",
    # ── Yandex дополнительные ─────────────────────────────────────────────────
    r".*\.yandex\.md",          # mc.yandex.md — Metrica
    r"mc\.yandex\.ru",
    r"mc\.yandex\.md",
    r".*\.yandex-team\.ru",
    # ── Google дополнительные ─────────────────────────────────────────────────
    r".*\.ggpht\.com",           # yt3.ggpht.com — YouTube avatars
    r".*\.googleusercontent\.com",
    r".*\.googletagmanager\.com",
    r".*\.doubleclick\.net",
    # ── Alibaba дополнительные ────────────────────────────────────────────────
    r".*\.alibaba\.com",         # fourier.alibaba.com
    r".*\.aliapp\.org",
    # ── JS/CSS CDN ────────────────────────────────────────────────────────────
    r"cdn\.jsdelivr\.net",
    r"cdnjs\.cloudflare\.com",
    r"unpkg\.com",
    r".*\.bootstrapcdn\.com",
    # ── Реклама / аналитика (не несут ДСП, только мешают) ────────────────────
    r".*\.adfox\.ru",
    r"vk\.ru",
    r".*\.mradx\.net",
    r".*\.rtbcdn\.ru",
    r".*\.tns-counter\.ru",
    r".*\.apptracer\.ru",
    r".*\.wace\.ai",
    # r"deepseek-ai\.press",
    r".*\.sbdv\.ru",
    # ── Microsoft Office Online / Word Online ─────────────────────────────────
    r"word\.cloud\.microsoft",
    r".*\.cloud\.microsoft",
    r".*\.officeapps\.live\.com",
    r".*\.office\.com",
    r".*\.office\.net",
    r".*\.office365\.com",
    r".*\.sharepoint\.com",
    r".*\.onedrive\.com",
    r"onedrive\.live\.com",
    r".*\.onenote\.com",
    r".*\.outlook\.com",
    r".*\.microsoftonline\.com",
    r"smtp\.office365\.com",
    # ── Claude / AI services (strict passthrough — uses SSE streams) ──────────
    r"claude\.ai",
    r".*\.claude\.ai",
    r".*\.anthropic\.com",
    # ── Qwen — all CDN and API domains ────────────────────────────────────────
    r"chat\.qwen\.ai",
    r".*\.qwen\.ai",
    r"qwen\.ai",
    r".*\.alicdn\.com",
    r".*\.aliyuncs\.com",
    r".*\.alibabacloud\.com",
    r".*\.alibaba\.com",
    r".*\.aliapp\.org",
    r"fourier\.alibaba\.com",
    r"tongyi\.aliyun\.com",
    r".*\.tongyi\.com",
    # ── VK extended ───────────────────────────────────────────────────────────
    r".*\.userapi\.com",         # sun1-95.userapi.com — VK photos
    r".*\.vk-portal\.net",       # stacks.vk-portal.net
    r".*\.vkontakte\.ru",
    # ── OK.ru extended ────────────────────────────────────────────────────────
    r".*\.okcdn\.ru",
    r"iv\.okcdn\.ru",
    # ── Analytics / telemetry (не ДСП, только мешают) ─────────────────────────
    r".*\.clarity\.ms",          # Microsoft Clarity
    r".*\.adhigh\.net",
    r".*\.telecid\.ru",
    r".*\.vigo\.tech",
    r".*\.doubleclick\.net",
    r"static\.doubleclick\.net",
    r"googleads\.g\.doubleclick\.net",
    r"code\.jquery\.com",
    r"static\.rutubelist\.ru",
    r"www\.clarity\.ms",
    r".*\.google-analytics\.com",
    r"mc\.webvisor\.org",
    r".*\.webvisor\.org",
    r"yastatic-net\.ru",
    r".*\.yastatic-net\.ru",
    r"widget\.payselection\.com",
    r"widget\.cloudpayments\.ru",
    r".*\.cloudpayments\.ru",
    # ── Rutube дополнительно ─────────────────────────────────────────────────
    r"rutube\.ru",
    r".*\.rutube\.ru",
    r"static\.rutubelist\.ru",
]


# ── HTML helpers ──────────────────────────────────────────────────────────────
_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial;background:#0d1117;color:#c9d1d9;min-height:100vh}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
code{background:#161b22;border:1px solid #30363d;padding:2px 6px;border-radius:4px;
     font-family:Consolas,monospace;color:#79c0ff;font-size:.9em}
.nav{background:#161b22;border-bottom:1px solid #30363d;padding:10px 24px;
     display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.nav .logo{color:#58a6ff;font-weight:700;font-size:1.1em;margin-right:12px}
.nav a{color:#8b949e;font-size:.9em}.nav a:hover{color:#c9d1d9}
.nav a.active{color:#58a6ff}
.container{max-width:1200px;margin:0 auto;padding:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:20px;margin-bottom:20px}
.stats{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:20px}
.stat{background:#161b22;border:1px solid #30363d;border-radius:10px;
      padding:16px 22px;text-align:center;min-width:110px}
.stat .v{font-size:2em;font-weight:700}.stat .l{color:#6c7086;font-size:.8em;margin-top:3px}
table{width:100%;border-collapse:collapse}
th{background:#21262d;color:#89b4fa;padding:9px 12px;text-align:left;
   font-size:.8em;text-transform:uppercase;white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid #21262d;font-size:.88em;vertical-align:middle}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 10px;border-radius:12px;font-size:.78em;font-weight:600}
.badge-block{background:#3d1a1a;color:#f38ba8;border:1px solid #5a2828}
.badge-upload{background:#3d2a12;color:#fab387;border:1px solid #5a3c18}
.badge-ok{background:#152a1e;color:#a6e3a1;border:1px solid #1f4332}
.btn{display:inline-block;padding:8px 16px;border-radius:7px;font-size:.9em;
     border:1px solid transparent;text-decoration:none;cursor:pointer}
.btn-primary{background:#1f6feb;color:#fff;border-color:#388bfd}
.btn-danger{background:#3d1a1a;color:#f38ba8;border-color:#5a2828}
.btn-warn{background:#3d2a12;color:#e3b341;border-color:#5a3c18}
.btn-sm{padding:4px 10px;font-size:.8em}
input[type=text],input[type=password]{background:#0d1117;border:1px solid #30363d;
  border-radius:7px;padding:9px 14px;color:#c9d1d9;font-size:14px;width:100%}
input:focus{outline:none;border-color:#58a6ff}
.form-row{margin-bottom:14px}
.form-row label{display:block;color:#8b949e;font-size:.85em;margin-bottom:5px}
.alert{padding:10px 16px;border-radius:7px;margin-bottom:16px;font-size:.9em}
.alert-ok{background:#152a1e;color:#a6e3a1;border:1px solid #1f4332}
.alert-err{background:#3d1a1a;color:#f38ba8;border:1px solid #5a2828}
"""


def _nav(active: str = "", user: str = "") -> str:
    # Count pending internet requests for badge
    ia_pending = 0
    try:
        ia_pending = ia_get_pending_count()
    except Exception:
        pass
    ia_badge = f' <span style="background:#f38ba8;color:#fff;border-radius:8px;padding:1px 6px;font-size:.7em">{ia_pending}</span>' if ia_pending else ""

    links = [
        ("/admin/",         "📊 Дашборд"),
        ("/admin/incidents","🔴 Инциденты"),
        ("/admin/events",   "🔍 События"),
        ("/admin/files",    "📁 Файлы"),
        ("/admin/chat",     "💬 Чат"),
        ("/admin/activity", "👁 Активность"),
        ("/admin/internet", f"🌐 Интернет{ia_badge}"),
        ("/admin/sites",    "🌐 Сайты"),
        ("/admin/users",    "👥 Админы"),
        ("/admin/settings", "⚙️ Настройки"),
    ]
    items = "".join(
        f'<a href="{h}" class="{"active" if active==h else ""}">{l}</a>'
        for h, l in links
    )
    user_info = f'<span style="color:#6c7086;font-size:.85em">👤 {user}</span>' if user else ""
    return (
        f'<nav class="nav"><span class="logo">🛡 DLP Proxy</span>'
        f'{items}{user_info}'
        f'<a href="/admin/logout" style="margin-left:auto;color:#6c7086;font-size:.85em">Выйти</a>'
        f'</nav>'
    )


# ── HTTP Handler ──────────────────────────────────────────────────────────────
class CertDistributionHandler(BaseHTTPRequestHandler):
    server_ip:      str = "127.0.0.1"
    proxy_port:     int = 8080
    upstream_proxy: str = ""

    def log_message(self, fmt, *args):
        logger.info(f"[CertServer] {self.address_string()} - {fmt % args}")

    def do_GET(self):
        try:
            self._handle_get()
        except Exception as e:
            logger.error(f"[CertServer] do_GET error: {e}", exc_info=True)
            try:
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"<h1>500 — Внутренняя ошибка</h1><pre>{e}</pre>".encode("utf-8"))
            except Exception:
                pass

    def _handle_get(self):
        path = urlparse(self.path).path
        qs = parse_qs(urlparse(self.path).query)

        # ── Public routes ────────────────────────────────────────────────────
        if path == "/":           self._serve_index(); return
        if path == "/ca.crt":     self._serve_pem();   return
        if path == "/ca.der":     self._serve_der();   return
        if path == "/status":     self._serve_status();return
        if path == "/health":     self._serve_health();return
        if path == "/traffic":    self._serve_traffic();return
        if path == "/admin/login":self._serve_login(); return

        # ── Client API (no auth — identified by IP) ──────────────────────────
        if path == "/api/notifications":
            self._api_notifications(qs); return
        if path == "/api/messages":
            self._api_get_messages(qs); return
        if path == "/api/internet_status":
            self._api_internet_status(qs); return
        if path == "/api/heartbeat":
            self._api_heartbeat(qs); return

        # ── Auth-required routes ─────────────────────────────────────────────
        user = _check_auth(dict(self.headers))
        if (path.startswith("/admin") or path.startswith("/capture")) and not user:
            self._redirect("/admin/login"); return

        if path in ("/admin/logout",):   self._do_logout(); return
        if path in ("/admin/", "/admin"):self._serve_dashboard(user); return
        if path == "/admin/events":      self._serve_events(user); return
        if path == "/admin/files":       self._serve_files(user); return
        if path == "/admin/activity":    self._serve_activity(user); return
        if path == "/admin/sites":       self._serve_sites(user); return
        if path == "/admin/users":       self._serve_users(user); return
        if path == "/admin/incidents":   self._serve_incidents(user); return
        if path == "/admin/chat":        self._serve_chat(user); return
        if path == "/admin/settings":    self._serve_settings(user); return
        if path == "/admin/internet":    self._serve_internet(user); return
        if path.startswith("/capture/"): self._serve_capture(path[9:]); return

        self.send_response(404); self.end_headers()
        self.wfile.write(b"Not found")

    def do_POST(self):
        try:
            self._handle_post()
        except Exception as e:
            logger.error(f"[CertServer] do_POST error: {e}", exc_info=True)
            try:
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"<h1>500 — Ошибка</h1><pre>{e}</pre>".encode("utf-8"))
            except Exception:
                pass

    def _handle_post(self):
        path = urlparse(self.path).path
        if path == "/admin/login":
            self._handle_login(); return

        # ── Client API (no auth) ─────────────────────────────────────────────
        if path == "/api/access_response":
            self._api_access_response(); return
        if path == "/api/messages":
            self._api_send_message(); return
        if path == "/api/internet_request":
            self._api_internet_request(); return

        user = _check_auth(dict(self.headers))
        if not user:
            self._redirect("/admin/login"); return

        if path == "/admin/users/add":       self._handle_add_user(user); return
        if path == "/admin/users/delete":    self._handle_delete_user(user); return
        if path == "/admin/users/passwd":    self._handle_change_passwd(user); return
        if path == "/admin/sites/block":     self._handle_site_block(user); return
        if path == "/admin/sites/unblock":   self._handle_site_unblock(user); return
        if path == "/admin/sites/allow":     self._handle_site_allow(user); return
        if path == "/admin/sites/unallow":   self._handle_site_unallow(user); return
        if path == "/admin/chat/send":       self._handle_chat_send(user); return
        if path == "/admin/incident/resolve":self._handle_incident_resolve(user); return
        if path == "/admin/settings/save":  self._handle_settings_save(user); return
        if path == "/admin/internet/approve": self._handle_internet_approve(user); return
        if path == "/admin/internet/deny":    self._handle_internet_deny(user); return
        if path == "/admin/internet/grant":   self._handle_internet_grant(user); return
        if path == "/admin/internet/revoke":  self._handle_internet_revoke(user); return

        self.send_response(405); self.end_headers()

    # ── Auth ──────────────────────────────────────────────────────────────────
    def _serve_login(self):
        qs  = parse_qs(urlparse(self.path).query)
        err = qs.get("err", [""])[0]
        msg = {
            "1": "Неверный логин или пароль",
            "2": "Сессия истекла, войдите снова",
        }.get(err, "")
        alert = f'<div class="alert alert-err">{msg}</div>' if msg else ""
        html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8"><title>DLP — Вход</title>
<style>{_CSS}
.wrap{{display:flex;align-items:center;justify-content:center;min-height:100vh}}
.box{{background:#161b22;border:1px solid #30363d;border-radius:14px;
     padding:44px 40px;width:100%;max-width:380px}}
.box h1{{color:#58a6ff;margin-bottom:6px;font-size:1.5em;text-align:center}}
.box p{{color:#6c7086;text-align:center;margin-bottom:24px;font-size:.9em}}
.submit{{width:100%;padding:11px;background:#1f6feb;color:#fff;border:none;
         border-radius:7px;font-size:1em;cursor:pointer;margin-top:8px}}
.submit:hover{{background:#388bfd}}
</style></head>
<body><div class="wrap"><div class="box">
  <h1>🛡 DLP Proxy</h1>
  <p>Вход в панель администратора</p>
  {alert}
  <form method="POST" action="/admin/login">
    <div class="form-row"><label>Логин</label>
      <input type="text" name="user" autofocus autocomplete="username"></div>
    <div class="form-row"><label>Пароль</label>
      <input type="password" name="pass" autocomplete="current-password"></div>
    <button class="submit" type="submit">Войти →</button>
  </form>
</div></div></body></html>"""
        self._send_html(html)

    def _handle_login(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(body)
        user   = params.get("user", [""])[0]
        pwd    = params.get("pass", [""])[0]
        if _check_credentials(user, pwd):
            token = _create_session(user)
            self.send_response(302)
            self.send_header("Set-Cookie",
                f"dlp_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800")
            self.send_header("Location", "/admin/")
            self.end_headers()
            logger.info(f"[Auth] Вход: user='{user}' от {self.client_address[0]}")
        else:
            logger.warning(f"[Auth] Неверный пароль: user='{user}' от {self.client_address[0]}")
            self._redirect("/admin/login?err=1")

    def _do_logout(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k.strip() == "dlp_session":
                with _session_lock:
                    _sessions.pop(v.strip(), None)
        self.send_response(302)
        self.send_header("Set-Cookie", "dlp_session=; Path=/; Max-Age=0")
        self.send_header("Location", "/admin/login")
        self.end_headers()

    # ── Users management ──────────────────────────────────────────────────────
    # ── Sites management ──────────────────────────────────────────────────────

    def _serve_activity(self, user: str):
        """Per-client activity — sites list first, click site to see events"""
        qs     = parse_qs(urlparse(self.path).query)
        sel_ip = qs.get("ip",   [""])[0]
        sel_host = qs.get("host", [""])[0]

        # Load activity + bandwidth
        activity_data, bw_data = {}, {}
        try:
            if EVENTS_FILE.exists():
                d = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
                activity_data = d.get("activity", {})
                bw_data       = d.get("bandwidth", {})
        except Exception as e:
            logger.warning(f"[Activity] Read error: {e}")

        clients = sorted(activity_data.keys())

        # ── Client selector ────────────────────────────────────────────────────
        client_btns = ""
        for ip in clients:
            bw      = bw_data.get(ip, {})
            n_acts  = len(activity_data.get(ip, []))
            active  = "background:#1f6feb;color:#fff;border-color:#388bfd" if ip == sel_ip else "background:#21262d;color:#8b949e;border-color:#30363d"
            client_btns += f'<a href="/admin/activity?ip={ip}" class="btn btn-sm" style="{active};margin:3px">{ip} ({n_acts})</a>'
        if not client_btns:
            client_btns = '<span style="color:#6c7086">Нет клиентов — ждите подключения</span>'

        # ── Bandwidth card ─────────────────────────────────────────────────────
        bw_html = ""
        if sel_ip and sel_ip in bw_data:
            bw = bw_data[sel_ip]
            def _spd(b):
                if b >= 1048576: return f"{b/1048576:.1f} MB/s"
                if b >= 1024:    return f"{b/1024:.1f} KB/s"
                return f"{b:.0f} B/s"
            def _tot(b):
                if b >= 1073741824: return f"{b/1073741824:.1f} GB"
                if b >= 1048576:    return f"{b/1048576:.1f} MB"
                if b >= 1024:       return f"{b/1024:.1f} KB"
                return f"{b} B"
            bw_html = (
                f'<div class="card" style="margin-bottom:0;display:flex;gap:20px;flex-wrap:wrap;align-items:center">' +
                f'<div><div style="color:#6c7086;font-size:.78em">Клиент</div><code style="font-size:1.05em">{sel_ip}</code></div>' +
                f'<div><div style="color:#6c7086;font-size:.78em">↓ Скорость</div><span style="color:#a6e3a1;font-weight:700">{_spd(bw.get("speed_in",0))}</span></div>' +
                f'<div><div style="color:#6c7086;font-size:.78em">↑ Скорость</div><span style="color:#fab387;font-weight:700">{_spd(bw.get("speed_out",0))}</span></div>' +
                f'<div><div style="color:#6c7086;font-size:.78em">Принято</div><span style="color:#89b4fa">{_tot(bw.get("total_in",0))}</span></div>' +
                f'<div><div style="color:#6c7086;font-size:.78em">Отправлено</div><span style="color:#89b4fa">{_tot(bw.get("total_out",0))}</span></div>' +
                f'<div><div style="color:#6c7086;font-size:.78em">Запросов</div><span>{bw.get("requests",0)}</span></div>' +
                f'</div>'
            )

        # ── Sites list for selected client ─────────────────────────────────────
        sites_html = ""
        events_html = ""

        if sel_ip:
            acts = activity_data.get(sel_ip, [])

            # Group by host
            from collections import defaultdict, Counter
            sites: dict[str, dict] = defaultdict(lambda: {
                "count":0, "blocked":0, "uploads":0, "downloads":0,
                "last_time":"", "statuses": []
            })
            for a in acts:
                host = a.get("host","") or "—"
                st   = a.get("status","ok")
                # Skip pure system hosts in the sites list
                if any(x in host for x in ["msftconnect","windowsupdate","microsoft.com",
                                            "msn.com","bing.com"]):
                    continue
                sites[host]["count"] += 1
                sites[host]["last_time"] = a.get("time","")
                if st == "blocked":  sites[host]["blocked"]   += 1
                if st == "upload":   sites[host]["uploads"]   += 1
                if st == "download": sites[host]["downloads"] += 1

            # Sort: blocked first, then by count
            sorted_sites = sorted(
                sites.items(),
                key=lambda x: (-(x[1]["blocked"] > 0), -x[1]["count"])
            )

            site_cards = ""
            for host, info in sorted_sites:
                is_sel   = host == sel_host
                has_block = info["blocked"] > 0
                border   = "border-color:#f38ba8" if has_block else ("border-color:#1f6feb" if is_sel else "border-color:#30363d")
                bg       = "background:#1c1010" if has_block else ("background:#0c1520" if is_sel else "background:#161b22")
                badges   = ""
                if info["blocked"]:
                    badges += f'<span class="badge badge-block" style="font-size:.72em">🚫 {info["blocked"]}</span> '
                if info["uploads"]:
                    badges += f'<span class="badge badge-upload" style="font-size:.72em">📤 {info["uploads"]}</span> '
                if info["downloads"]:
                    badges += f'<span class="badge" style="font-size:.72em;background:#0c1520;color:#79c0ff;border-color:#1f6feb">⬇ {info["downloads"]}</span> '

                site_cards += (
                    f'<a href="/admin/activity?ip={sel_ip}&host={host}" ' +
                    f'style="text-decoration:none;display:block;border:1px solid;border-radius:8px;' +
                    f'padding:12px 16px;margin-bottom:6px;{border};{bg};transition:all .15s">' +
                    f'<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px">' +
                    f'<div style="color:#58a6ff;font-weight:600;font-size:.95em">{host}</div>' +
                    f'<div style="display:flex;align-items:center;gap:8px">' +
                    f'{badges}' +
                    f'<span style="color:#6c7086;font-size:.78em">{info["count"]} запросов</span>' +
                    f'<span style="color:#484f58;font-size:.75em">{info["last_time"]}</span>' +
                    f'</div></div>' +
                    f'</a>'
                )

            if not site_cards:
                site_cards = '<p style="color:#6c7086;padding:16px">Нет активности. Клиент пока ничего не делал.</p>'

            sites_html = (
                f'<div class="card" style="flex:0 0 360px;min-width:280px;max-height:600px;overflow-y:auto">' +
                f'<h3 style="color:#89b4fa;margin-bottom:12px">🌐 Сайты</h3>' +
                f'<div style="margin-bottom:8px;font-size:.8em;color:#6c7086">' +
                f'Скрыты системные домены Microsoft/Windows</div>' +
                f'{site_cards}</div>'
            )

            # ── Events for selected site ─────────────────────────────────────
            if sel_host:
                host_acts = [
                    a for a in acts
                    if a.get("host","") == sel_host
                ]
                status_styles = {
                    "ok":       ("✅ OK",       "#a6e3a1", ""),
                    "blocked":  ("🚫 БЛОК",     "#f38ba8", "background:#1c1010"),
                    "upload":   ("📤 Загрузка", "#fab387", "background:#1c1208"),
                    "download": ("⬇ Скачано",  "#79c0ff", "background:#0c1520"),
                }
                ev_rows = ""
                for a in reversed(host_acts[-200:]):
                    st    = a.get("status","ok")
                    label, color, rbg = status_styles.get(st, ("?","#8b949e",""))
                    ftype = a.get("type","")
                    fsize = a.get("size",0)
                    fsize_s = (f"{fsize/1024/1024:.1f}MB" if fsize>1048576
                               else f"{fsize//1024}KB" if fsize>1024
                               else f"{fsize}B" if fsize else "")
                    url   = a.get("url","")
                    # Protocol badge
                    if url.startswith("https"):
                        proto_badge = '<span style="color:#a6e3a1;font-size:.7em;font-weight:700">HTTPS</span>'
                    else:
                        proto_badge = '<span style="color:#e3b341;font-size:.7em;font-weight:700">HTTP</span>'
                    path_part = url.split(sel_host)[-1][:60] if sel_host in url else url[:60]
                    ev_rows += (
                        f'<tr style="{rbg}">' +
                        f'<td style="color:#6c7086;white-space:nowrap;font-size:.78em">{a.get("time","")}</td>' +
                        f'<td style="font-size:.8em;color:#8b949e">{a.get("method","")}</td>' +
                        f'<td>{proto_badge}</td>' +
                        f'<td style="font-weight:600;color:{color};white-space:nowrap">{label}</td>' +
                        f'<td style="font-size:.8em;color:#89b4fa;max-width:280px;overflow:hidden;'  +
                        f'white-space:nowrap" title="{url}">{path_part or "/"}</td>' +
                        f'<td style="font-size:.78em;color:#6c7086">{ftype} {fsize_s}</td>' +
                        f'</tr>'
                    )

                empty_ev = '<tr><td colspan="6" style="text-align:center;color:#6c7086;padding:20px">Нет событий</td></tr>'
                events_html = (
                    f'<div class="card" style="flex:1;min-width:0;max-height:600px;overflow-y:auto;padding:0">' +
                    f'<div style="padding:14px 16px 10px;border-bottom:1px solid #21262d;display:flex;align-items:center;gap:10px">' +
                    f'<h3 style="color:#89b4fa">📋 {sel_host}</h3>' +
                    f'<span style="color:#6c7086;font-size:.82em">{len(host_acts)} запросов</span></div>' +
                    f'<table style="width:100%">' +
                    f'<thead><tr><th>Время</th><th>Метод</th><th>Прот.</th><th>Статус</th><th>URL</th><th>Файл</th></tr></thead>' +
                    f'<tbody>{ev_rows or empty_ev}</tbody></table></div>'
                )
            else:
                events_html = (
                    f'<div class="card" style="flex:1;display:flex;align-items:center;' +
                    f'justify-content:center;min-height:200px;color:#484f58">' +
                    f'← Выберите сайт для просмотра событий</div>'
                )

        hint_html = "" if sel_ip else "<p style=\'color:#6c7086;margin-top:12px\'>Выберите клиента</p>"

        if sel_ip:
            main_content = "<div class='two-col'>" + sites_html + events_html + "</div>"
        else:
            main_content = hint_html

        html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="5">
<title>DLP — Активность</title><style>{_CSS}
.two-col{{display:flex;gap:16px;align-items:flex-start;margin-top:16px}}
@media(max-width:900px){{.two-col{{flex-direction:column}}}}
</style></head>
<body>{_nav("/admin/activity", user)}
<div class="container">
  <h2 style="color:#f0f6fc;margin-bottom:16px">👁 Активность клиентов</h2>

  <div class="card" style="margin-bottom:12px">
    <h3 style="color:#89b4fa;margin-bottom:10px;font-size:.9em">Клиенты:</h3>
    {client_btns}
  </div>

  {bw_html}

  {main_content}

  <p style="color:#6c7086;font-size:.75em;margin-top:10px">Обновляется каждые 5 сек.</p>
</div></body></html>"""
        self._send_html(html)


    def _serve_sites(self, user: str):
        qs  = parse_qs(urlparse(self.path).query)
        msg = qs.get("msg", [""])[0]
        err = qs.get("err", [""])[0]
        alert = ""
        if msg: alert = f'<div class="alert alert-ok">✓ {msg}</div>'
        if err: alert = f'<div class="alert alert-err">✗ {err}</div>'

        blocked = sorted(_CFG.get("blocked_domains", []))
        allowed = sorted(_CFG.get("allowed_domains", []))

        def _rows(domains, action_unblock, action_label, badge_style, badge_text):
            if not domains:
                return '<tr><td colspan="3" style="color:#6c7086;padding:14px">Список пуст</td></tr>'
            rows = ""
            for d in domains:
                rows += (
                    f'<tr><td><code>{d}</code></td>'
                    f'<td><span class="badge" style="{badge_style}">{badge_text}</span></td>'
                    f'<td>'
                    f'<form method="POST" action="/admin/sites/{action_unblock}" style="display:inline">'
                    f'<input type="hidden" name="domain" value="{d}">'
                    f'<button class="btn btn-sm btn-danger" type="submit">Удалить</button>'
                    f'</form></td></tr>'
                )
            return rows

        blocked_rows = _rows(blocked, "unblock", "Разблокировать",
                             "background:#3d1a1a;color:#f38ba8;border:1px solid #5a2828",
                             "🚫 Заблокирован")
        allowed_rows = _rows(allowed, "unallow", "Удалить из разрешённых",
                             "background:#152a1e;color:#a6e3a1;border:1px solid #1f4332",
                             "✅ Разрешён явно")

        html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8"><title>DLP — Управление сайтами</title>
<style>{_CSS}</style></head><body>
{_nav("/admin/sites", user)}
<div class="container">
  <h2 style="color:#f0f6fc;margin-bottom:8px">🌐 Управление сайтами</h2>
  <p style="color:#6c7086;margin-bottom:20px;font-size:.9em">
    По умолчанию <strong style="color:#a6e3a1">все сайты разрешены</strong> — DLP анализирует контент, но не блокирует сайты целиком.<br>
    Добавьте домен в список <strong style="color:#f38ba8">Заблокировать</strong> чтобы полностью запретить доступ к нему.<br>
    Список <strong style="color:#a6e3a1">Явно разрешить</strong> добавляет домены в белый список (DLP не проверяет).
  </p>
  {alert}

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
    <!-- Add blocked -->
    <div class="card">
      <h3 style="color:#f38ba8;margin-bottom:14px">🚫 Заблокировать домен</h3>
      <p style="color:#6c7086;font-size:.85em;margin-bottom:12px">
        Все запросы к домену будут немедленно заблокированы.
      </p>
      <form method="POST" action="/admin/sites/block">
        <div class="form-row">
          <label>Домен (напр. <code>telegram.org</code>)</label>
          <input type="text" name="domain" placeholder="example.com" required>
        </div>
        <button type="submit" class="btn btn-danger">🚫 Заблокировать</button>
      </form>
    </div>

    <!-- Add allowed -->
    <div class="card">
      <h3 style="color:#a6e3a1;margin-bottom:14px">✅ Явно разрешить домен</h3>
      <p style="color:#6c7086;font-size:.85em;margin-bottom:12px">
        DLP не будет проверять трафик этого домена (добавляется в белый список).
      </p>
      <form method="POST" action="/admin/sites/allow">
        <div class="form-row">
          <label>Домен (напр. <code>corp.company.ru</code>)</label>
          <input type="text" name="domain" placeholder="example.com" required>
        </div>
        <button type="submit" class="btn btn-primary">✅ Разрешить</button>
      </form>
    </div>
  </div>

  <!-- Blocked list -->
  <div class="card" style="margin-top:0">
    <h3 style="color:#f38ba8;margin-bottom:12px">Заблокированные домены</h3>
    <div style="overflow:hidden;border-radius:8px;border:1px solid #30363d">
    <table>
      <thead><tr><th>Домен</th><th>Статус</th><th>Действие</th></tr></thead>
      <tbody>{blocked_rows}</tbody>
    </table>
    </div>
  </div>

  <!-- Allowed list -->
  <div class="card">
    <h3 style="color:#a6e3a1;margin-bottom:12px">Явно разрешённые домены (белый список)</h3>
    <div style="overflow:hidden;border-radius:8px;border:1px solid #30363d">
    <table>
      <thead><tr><th>Домен</th><th>Статус</th><th>Действие</th></tr></thead>
      <tbody>{allowed_rows}</tbody>
    </table>
    </div>
    <p style="color:#6c7086;font-size:.8em;margin-top:8px">
      Системные домены (yandex.ru, google.com и т.д.) уже в белом списке — их не нужно добавлять.
    </p>
  </div>
</div></body></html>"""
        self._send_html(html)

    def _handle_site_block(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(body)
        domain = params.get("domain", [""])[0].strip().lower().lstrip(".")
        if not domain or "." not in domain:
            self._redirect("/admin/sites?err=Неверный+домен"); return
        blocked = _CFG.setdefault("blocked_domains", [])
        if domain not in blocked:
            blocked.append(domain)
            save_config(_CFG)
            logger.info(f"[Sites] Заблокирован {domain} пользователем {user}")
        self._redirect(f"/admin/sites?msg=Домен+{domain}+заблокирован")

    def _handle_site_unblock(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(body)
        domain = params.get("domain", [""])[0].strip()
        blocked = _CFG.get("blocked_domains", [])
        if domain in blocked:
            blocked.remove(domain)
            save_config(_CFG)
        self._redirect(f"/admin/sites?msg=Домен+{domain}+разблокирован")

    def _handle_site_allow(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(body)
        domain = params.get("domain", [""])[0].strip().lower().lstrip(".")
        if not domain or "." not in domain:
            self._redirect("/admin/sites?err=Неверный+домен"); return
        allowed = _CFG.setdefault("allowed_domains", [])
        if domain not in allowed:
            allowed.append(domain)
            save_config(_CFG)
        self._redirect(f"/admin/sites?msg=Домен+{domain}+добавлен+в+белый+список")

    def _handle_site_unallow(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(body)
        domain = params.get("domain", [""])[0].strip()
        allowed = _CFG.get("allowed_domains", [])
        if domain in allowed:
            allowed.remove(domain)
            save_config(_CFG)
        self._redirect(f"/admin/sites?msg=Домен+{domain}+удалён+из+белого+списка")

    def _serve_users(self, user: str):
        qs  = parse_qs(urlparse(self.path).query)
        msg = qs.get("msg", [""])[0]
        err = qs.get("err", [""])[0]

        alert = ""
        if msg: alert = f'<div class="alert alert-ok">✓ {msg}</div>'
        if err: alert = f'<div class="alert alert-err">✗ {err}</div>'

        admins = _get_admins()
        rows   = ""
        for a in admins:
            role_badge = (
                '<span class="badge" style="background:#1a3550;color:#79c0ff'
                ';border:1px solid #1f6feb">superadmin</span>'
                if a.get("primary") else
                '<span class="badge badge-ok">admin</span>'
            )
            del_btn = (
                "" if a.get("primary") else
                f'<form method="POST" action="/admin/users/delete" style="display:inline">'
                f'<input type="hidden" name="user" value="{a["user"]}">'
                f'<button class="btn btn-danger btn-sm" type="submit" '
                f'onclick="return confirm(\'Удалить {a["user"]}?\')">Удалить</button></form>'
            )
            rows += (
                f"<tr><td><strong>{a['user']}</strong></td>"
                f"<td>{role_badge}</td>"
                f"<td>{'(первичный — менять в config.json)' if a.get('primary') else '—'}</td>"
                f"<td>{del_btn}</td></tr>"
            )

        html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8"><title>DLP — Администраторы</title>
<style>{_CSS}</style></head><body>
{_nav("/admin/users", user)}
<div class="container">
  <h2 style="color:#f0f6fc;margin-bottom:20px">👥 Управление администраторами</h2>
  {alert}

  <div class="card">
    <h3 style="color:#89b4fa;margin-bottom:16px">Текущие администраторы</h3>
    <div style="overflow:hidden;border-radius:8px;border:1px solid #30363d">
    <table>
      <thead><tr>
        <th>Логин</th><th>Роль</th><th>Заметка</th><th>Действия</th>
      </tr></thead>
      <tbody>{rows}</tbody>
    </table>
    </div>
    <p style="color:#6c7086;font-size:.8em;margin-top:10px">
      Superadmin (первичный) задаётся только через
      <code>config.json</code> → <code>admin_user</code> / <code>admin_password</code>
    </p>
  </div>

  <div style="display:grid;grid-template-columns:1fr 1fr;gap:20px;flex-wrap:wrap">
    <div class="card">
      <h3 style="color:#89b4fa;margin-bottom:16px">➕ Добавить администратора</h3>
      <form method="POST" action="/admin/users/add">
        <div class="form-row"><label>Логин (латиница, без пробелов)</label>
          <input type="text" name="user" pattern="[a-zA-Z0-9_]+" required></div>
        <div class="form-row"><label>Пароль (мин. 6 символов)</label>
          <input type="password" name="pass" minlength="6" required></div>
        <div class="form-row"><label>Повтор пароля</label>
          <input type="password" name="pass2" minlength="6" required></div>
        <button type="submit" class="btn btn-primary">Добавить</button>
      </form>
    </div>

    <div class="card">
      <h3 style="color:#89b4fa;margin-bottom:16px">🔑 Сменить пароль</h3>
      <form method="POST" action="/admin/users/passwd">
        <div class="form-row"><label>Логин</label>
          <input type="text" name="user" required></div>
        <div class="form-row"><label>Новый пароль (мин. 6 символов)</label>
          <input type="password" name="pass" minlength="6" required></div>
        <div class="form-row"><label>Повтор нового пароля</label>
          <input type="password" name="pass2" minlength="6" required></div>
        <button type="submit" class="btn btn-warn">Сменить пароль</button>
      </form>
    </div>
  </div>

  <div class="card" style="border-color:#30363d">
    <h3 style="color:#6c7086;margin-bottom:8px;font-size:.9em">
      ℹ️ Доступ с других компьютеров
    </h3>
    <p style="color:#6c7086;font-size:.85em;line-height:1.6">
      Панель администратора доступна по адресу
      <code>http://{self.server_ip}:{CERT_PORT}/admin/</code> с любого компьютера в сети.<br>
      Создайте отдельные учётные записи для каждого администратора. Пароль primary-admin
      меняется только в <code>config.json</code> → <code>admin_password</code>.
    </p>
  </div>
</div></body></html>"""
        self._send_html(html)

    def _handle_add_user(self, current_user: str):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(body)
        new_user = params.get("user", [""])[0].strip()
        pwd      = params.get("pass", [""])[0]
        pwd2     = params.get("pass2", [""])[0]

        if not new_user or not pwd:
            self._redirect("/admin/users?err=Заполните+все+поля"); return
        if pwd != pwd2:
            self._redirect("/admin/users?err=Пароли+не+совпадают"); return
        if len(pwd) < 6:
            self._redirect("/admin/users?err=Пароль+минимум+6+символов"); return

        existing = [a["user"] for a in _get_admins()]
        if new_user in existing:
            self._redirect(f"/admin/users?err=Пользователь+{new_user}+уже+существует"); return

        _CFG.setdefault("admins", []).append({"user": new_user, "password": pwd, "role": "admin"})
        save_config(_CFG)
        logger.info(f"[Users] Добавлен admin '{new_user}' пользователем '{current_user}'")
        self._redirect(f"/admin/users?msg=Администратор+{new_user}+добавлен")

    def _handle_delete_user(self, current_user: str):
        length  = int(self.headers.get("Content-Length", 0))
        body    = self.rfile.read(length).decode("utf-8", errors="replace")
        params  = parse_qs(body)
        del_user = params.get("user", [""])[0].strip()

        # Cannot delete primary admin
        if del_user == _CFG.get("admin_user", "admin"):
            self._redirect("/admin/users?err=Нельзя+удалить+основного+администратора"); return

        admins = _CFG.get("admins", [])
        before = len(admins)
        _CFG["admins"] = [a for a in admins if a["user"] != del_user]
        if len(_CFG["admins"]) < before:
            save_config(_CFG)
            logger.info(f"[Users] Удалён admin '{del_user}' пользователем '{current_user}'")
            self._redirect(f"/admin/users?msg=Администратор+{del_user}+удалён")
        else:
            self._redirect("/admin/users?err=Пользователь+не+найден")

    def _handle_change_passwd(self, current_user: str):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(body)
        target = params.get("user", [""])[0].strip()
        pwd    = params.get("pass", [""])[0]
        pwd2   = params.get("pass2", [""])[0]

        if pwd != pwd2:
            self._redirect("/admin/users?err=Пароли+не+совпадают"); return
        if len(pwd) < 6:
            self._redirect("/admin/users?err=Пароль+минимум+6+символов"); return

        # Primary admin
        if target == _CFG.get("admin_user", "admin"):
            _CFG["admin_password"] = pwd
            save_config(_CFG)
            logger.info(f"[Users] Пароль primary admin изменён пользователем '{current_user}'")
            self._redirect("/admin/users?msg=Пароль+изменён"); return

        # Extra admin
        found = False
        for a in _CFG.get("admins", []):
            if a["user"] == target:
                a["password"] = pwd
                found = True
                break
        if found:
            save_config(_CFG)
            logger.info(f"[Users] Пароль '{target}' изменён пользователем '{current_user}'")
            self._redirect("/admin/users?msg=Пароль+изменён")
        else:
            self._redirect("/admin/users?err=Пользователь+не+найден")

    # ── Admin dashboard ───────────────────────────────────────────────────────
    def _serve_dashboard(self, user: str):
        events, stats = self._load_events()
        clients = self._get_all_clients()
        bw_data = {}
        try:
            if EVENTS_FILE.exists():
                ev_data = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
                bw_data = ev_data.get("bandwidth", {})
        except Exception:
            pass

        blocked_recent = [e for e in reversed(events[-50:]) if e.get("blocked")][:5]

        def _fmt_speed(bps):
            if bps >= 1024*1024: return f"{bps/1024/1024:.1f} MB/s"
            if bps >= 1024: return f"{bps/1024:.1f} KB/s"
            return f"{bps:.0f} B/s"

        bw_rows = ""
        for ip, d in sorted(bw_data.items()):
            sp_out = d.get("speed_out", 0)
            sp_in  = d.get("speed_in",  0)
            tot_out = d.get("total_out", 0)
            tot_in  = d.get("total_in",  0)
            bw_rows += (
                f'<div style="display:flex;align-items:center;gap:16px;'
                f'padding:8px 0;border-bottom:1px solid #21262d;flex-wrap:wrap">'
                f'<span style="font-family:monospace;color:#79c0ff;min-width:130px">{ip}</span>'
                f'<span style="color:#a6e3a1">↓ {_fmt_speed(sp_in)}</span>'
                f'<span style="color:#fab387">↑ {_fmt_speed(sp_out)}</span>'
                f'<span style="color:#6c7086;font-size:.82em">'
                f'всего: ↓{_fmt_speed(tot_in)} ↑{_fmt_speed(tot_out)}</span>'
                f'</div>'
            )
        bw_html = bw_rows or '<span style="color:#6c7086">Нет данных (трафик ещё не проходил)</span>'

        blocked_rows   = "".join(
            f'<tr>'
            f'<td style="white-space:nowrap;color:#6c7086">{e.get("time","")}</td>'
            f'<td><code>{e.get("client","")}</code></td>'
            f'<td style="color:#e3b341;font-size:.85em">{e.get("details","")[:60]}</td>'
            f'<td><a href="/admin/files?id={e.get("id","")}" class="btn btn-sm btn-danger">Открыть</a></td>'
            f'</tr>'
            for e in blocked_recent
        )

        # ── Client last-seen data ─────────────────────────────────────────
        last_seen = {}
        try:
            if EVENTS_FILE.exists():
                ev_data2 = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
                last_seen = ev_data2.get("client_last_seen", {})
        except Exception:
            pass

        # Merge heartbeat data (from agent API polling)
        with _heartbeat_lock:
            for ip, ts in _heartbeat_clients.items():
                existing = last_seen.get(ip, 0)
                try:
                    existing = float(existing)
                except (ValueError, TypeError):
                    existing = 0
                if ts > existing:
                    last_seen[ip] = ts

        import time as _time
        now_ts = _time.time()
        ONLINE_THRESHOLD = 60  # 60 seconds (agent polls every 8 sec)

        online_clients = []
        offline_clients = []
        for c in clients:
            ts = last_seen.get(c, 0)
            try:
                ts = float(ts)
            except (ValueError, TypeError):
                ts = 0
            if ts and (now_ts - ts) < ONLINE_THRESHOLD:
                online_clients.append(c)
            else:
                offline_clients.append(c)

        online_badges = "".join(
            f'<span style="background:#1a4731;color:#a8edbb;padding:4px 12px;'
            f'border-radius:12px;margin:3px;display:inline-block;font-size:.85em">'
            f'🟢 {c}</span>'
            for c in online_clients
        )
        offline_badges = "".join(
            f'<span style="background:#21262d;color:#6c7086;padding:4px 12px;'
            f'border-radius:12px;margin:3px;display:inline-block;font-size:.85em">'
            f'⚫ {c}</span>'
            for c in offline_clients
        )
        client_badges = (online_badges + offline_badges) or \
            '<span style="color:#6c7086">Клиентов нет</span>'

        html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="5">
<title>DLP — Дашборд</title><style>{_CSS}</style></head>
<body>{_nav("/admin/", user)}
<div class="container">
  <h2 style="color:#f0f6fc;margin-bottom:20px">📊 Дашборд</h2>
  <div class="stats">
    <div class="stat"><div class="v" style="color:#fab387">{stats["total"]}</div><div class="l">Запросов</div></div>
    <div class="stat"><div class="v" style="color:#f38ba8">{stats["blocked"]}</div><div class="l">Заблокировано</div></div>
    <div class="stat"><div class="v" style="color:#fab387">{stats["uploads"]}</div><div class="l">Загрузок ↑</div></div>
    <div class="stat"><div class="v" style="color:#89b4fa">{stats.get("downloads",0)}</div><div class="l">Скачиваний ↓</div></div>
    <div class="stat"><div class="v" style="color:#a6e3a1">{stats["passed"]}</div><div class="l">Пропущено</div></div>
    <div class="stat"><div class="v" style="color:#cba6f7">{len(online_clients)}<span style="color:#6c7086;font-size:.5em">/{len(clients)}</span></div><div class="l">Онлайн / Всего</div></div>
  </div>
  <div class="card">
    <h3 style="color:#89b4fa;margin-bottom:12px">🖥 Клиенты <span style="color:#a6e3a1;font-size:.8em">{len(online_clients)} онлайн</span> <span style="color:#6c7086;font-size:.8em">{len(offline_clients)} офлайн</span></h3>
    {client_badges}
  </div>
  <div class="card" id="bw_card">
    <h3 style="color:#89b4fa;margin-bottom:12px">📡 Скорость клиентов <span style="color:#6c7086;font-size:.8em;font-weight:400">(обновляется каждые 5 сек)</span></h3>
    {bw_html}
  </div>
  <div class="card">
    <h3 style="color:#f38ba8;margin-bottom:12px">🚫 Последние блокировки</h3>
    {'<div style="border-radius:8px;overflow:hidden;border:1px solid #30363d"><table><thead><tr><th>Время</th><th>Клиент</th><th>Причина</th><th></th></tr></thead><tbody>' + blocked_rows + '</tbody></table></div>' if blocked_rows else '<p style="color:#6c7086">Блокировок не было</p>'}
  </div>
</div></body></html>"""
        self._send_html(html)

    # ── Events ────────────────────────────────────────────────────────────────
    def _serve_events(self, user: str):
        events, stats = self._load_events()
        qs  = parse_qs(urlparse(self.path).query)
        flt = qs.get("filter", ["all"])[0]

        filtered = events
        if flt == "blocked": filtered = [e for e in events if e.get("blocked")]
        elif flt == "upload":  filtered = [e for e in events if e.get("type") == "upload"]

        rows = ""
        for e in reversed(filtered[-100:]):
            blocked = e.get("blocked", False)
            etype   = e.get("type", "")
            if blocked:      badge = '<span class="badge badge-block">🚫 БЛОК</span>'
            elif etype == "upload": badge = '<span class="badge badge-upload">📤 Загрузка</span>'
            else:            badge = '<span class="badge badge-ok">✅ OK</span>'
            capture = e.get("capture") or ""
            fsize   = e.get("size", 0)
            fsize_s = f"{fsize//1024}KB" if fsize > 1024 else f"{fsize}B"
            file_cell = (
                f'<a href="/admin/files?id={e.get("id","")}" class="btn btn-sm btn-primary">'
                f'📄 {e.get("filename") or capture} ({fsize_s})</a>'
            ) if capture else ""
            details   = e.get("details") or e.get("reason") or ""
            detail_cell = (
                f'<span style="color:#e3b341">{details[:70]}</span>' if blocked else
                f'<span style="color:#6c7086">{details[:50]}</span>'
            )
            bg = "#1c1010" if blocked else "#0f1c0f" if etype == "upload" else ""
            ev_url = e.get("url","")
            proto_b = ('<span style="color:#a6e3a1;font-size:.72em;font-weight:700">S</span>'
                       if ev_url.startswith("https") else
                       '<span style="color:#e3b341;font-size:.72em;font-weight:700">H</span>')
            rows += (
                f'<tr style="background:{bg}">'
                f'<td style="white-space:nowrap;color:#6c7086;font-size:.8em">{e.get("time","")}</td>'
                f'<td><code>{e.get("client","")}</code></td>'
                f'<td>{badge}</td>'
                f'<td style="font-size:.82em;color:#8b949e;max-width:160px;overflow:hidden;'
                f'white-space:nowrap" title="{ev_url}">{proto_b} {e.get("host","")}</td>'
                f'<td>{file_cell}</td>'
                f'<td>{detail_cell}</td>'
                f'</tr>'
            )
        filter_btns = "".join(
            f'<a href="/admin/events?filter={k}" class="btn btn-sm" '
            f'style="margin-right:6px;{"background:#1f6feb;color:#fff;border-color:#388bfd" if flt==k else "background:#21262d;color:#8b949e;border-color:#30363d"}">{l}</a>'
            for k, l in [("all","Все"),("blocked","🚫 Блоки"),("upload","📤 Загрузки")]
        )
        html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="10">
<title>DLP — События</title><style>{_CSS}</style></head>
<body>{_nav("/admin/events", user)}
<div class="container">
  <h2 style="color:#f0f6fc;margin-bottom:16px">🔍 Все события</h2>
  <div class="stats">
    <div class="stat"><div class="v" style="color:#fab387">{stats["total"]}</div><div class="l">Всего</div></div>
    <div class="stat"><div class="v" style="color:#f38ba8">{stats["blocked"]}</div><div class="l">Заблокировано</div></div>
    <div class="stat"><div class="v" style="color:#fab387">{stats["uploads"]}</div><div class="l">Загрузок</div></div>
  </div>
  <div style="margin-bottom:14px">{filter_btns}</div>
  <div class="card" style="padding:0;overflow:hidden">
    <table>
      <thead><tr><th>Время</th><th>Клиент</th><th>Статус</th>
      <th>Сайт</th><th>Файл</th><th>Причина</th></tr></thead>
      <tbody>{rows or '<tr><td colspan="6" style="text-align:center;color:#6c7086;padding:30px">Событий нет</td></tr>'}</tbody>
    </table>
  </div>
</div></body></html>"""
        self._send_html(html)

    # ── Files viewer ──────────────────────────────────────────────────────────
    def _serve_files(self, user: str):
        qs       = parse_qs(urlparse(self.path).query)
        event_id = qs.get("id", [""])[0]
        events, _ = self._load_events()
        event = next((e for e in events if e.get("id") == event_id), None)
        if not event:
            self._serve_files_list(events, user); return

        capture  = event.get("capture") or ""
        filename = event.get("filename") or capture
        fpath    = CAPTURES_DIR / Path(capture).name if capture else None
        fsize    = event.get("size", 0)
        matches  = event.get("matches", [])
        details  = event.get("details", "")
        rules    = event.get("rules", [])
        blocked  = event.get("blocked", False)

        orig_ext = Path(filename).suffix.lower() if filename else ""

        preview_html = ""
        download_btn = ""
        if fpath and fpath.exists():
            ext = orig_ext or fpath.suffix.lower()
            download_btn = (
                f'<a href="/capture/{fpath.name}" class="btn btn-primary" '
                f'style="margin-right:8px">⬇ Скачать ({filename})</a>'
            )
            if ext in (".txt", ".json", ".xml", ".csv", ".html", ".log"):
                try:
                    raw = fpath.read_text(encoding="utf-8", errors="replace")
                    display_text = raw
                    if ext == ".json":
                        try:
                            import json as _json
                            obj = _json.loads(raw)
                            display_text = _json.dumps(obj, ensure_ascii=False, indent=2)
                        except Exception:
                            display_text = raw
                    hilit = self._highlight_dlp(display_text, matches)
                    preview_html = f"""
<div class="card" style="margin-top:16px">
  <h3 style="color:#89b4fa;margin-bottom:12px">📄 Содержимое файла
    <span style="color:#6c7086;font-size:.8em;font-weight:400;margin-left:8px">
      Жёлтым подсвечены найденные ДСП-данные
    </span>
  </h3>
  <pre id="file_content" style="background:#0d1117;border:1px solid #30363d;border-radius:8px;
    padding:16px;overflow:auto;max-height:600px;font-family:Consolas,monospace;
    font-size:.84em;line-height:1.65;white-space:pre-wrap;word-break:break-all;tab-size:2">
{hilit}</pre>
</div>"""
                except Exception as ex:
                    preview_html = f'<p style="color:#f38ba8">Ошибка: {ex}</p>'
            elif ext == ".pdf":
                preview_html = f"""
<div class="card" style="margin-top:16px">
  <h3 style="color:#89b4fa;margin-bottom:12px">📄 PDF</h3>
  <embed src="/capture/{fpath.name}" type="application/pdf"
         width="100%" height="600px" style="border-radius:8px;border:1px solid #30363d">
</div>"""
            elif ext in (".doc",".docx",".xls",".xlsx"):
                extracted = ""
                try:
                    raw = fpath.read_bytes()
                    import zipfile, io
                    if ext in (".docx",".doc"):
                        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                            parts = []
                            for n in zf.namelist():
                                if n.endswith(".xml") and any(k in n for k in
                                        ["word/document","word/header","word/footer"]):
                                    x = zf.read(n).decode("utf-8", errors="replace")
                                    c = re.sub(r'<[^>]+>', ' ', x)
                                    c = re.sub(r'\s+', ' ', c).strip()
                                    if c: parts.append(c)
                            extracted = "\n\n".join(parts)
                    elif ext in (".xlsx",".xls"):
                        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                            # 1) Load shared strings
                            shared = []
                            if "xl/sharedStrings.xml" in zf.namelist():
                                ss_xml = zf.read("xl/sharedStrings.xml").decode("utf-8", errors="replace")
                                shared = re.findall(r'<t[^>]*>([^<]+)</t>', ss_xml)

                            # 2) Parse each worksheet into rows
                            table_html_parts = []
                            for sname in sorted(zf.namelist()):
                                if not (sname.startswith("xl/worksheets/sheet") and sname.endswith(".xml")):
                                    continue
                                ws_xml = zf.read(sname).decode("utf-8", errors="replace")
                                sheet_label = sname.split("/")[-1].replace(".xml","")

                                # Parse rows: <row r="1"><c r="A1" t="s"><v>0</v></c>...</row>
                                rows_data = {}
                                max_col = 0
                                for row_m in re.finditer(r'<row[^>]*>(.*?)</row>', ws_xml, re.DOTALL):
                                    row_xml = row_m.group(1)
                                    for cell_m in re.finditer(
                                        r'<c\s+r="([A-Z]+)(\d+)"[^>]*?(?:t="([^"]*)")?[^>]*>'
                                        r'(?:.*?<v>([^<]*)</v>)?', row_xml, re.DOTALL):
                                        col_letters, row_num, cell_type, val = cell_m.groups()
                                        row_num = int(row_num)
                                        # Convert column letters to index
                                        col_idx = 0
                                        for ch in col_letters:
                                            col_idx = col_idx * 26 + (ord(ch) - ord('A') + 1)
                                        col_idx -= 1
                                        if col_idx > max_col:
                                            max_col = col_idx
                                        # Resolve shared string
                                        display = val or ""
                                        if cell_type == "s" and val and val.isdigit():
                                            idx = int(val)
                                            display = shared[idx] if idx < len(shared) else val
                                        if row_num not in rows_data:
                                            rows_data[row_num] = {}
                                        rows_data[row_num][col_idx] = display

                                if not rows_data:
                                    continue

                                # Build HTML table (limit to 50 rows, 20 cols)
                                max_col = min(max_col, 19)
                                sorted_rows = sorted(rows_data.keys())[:50]
                                tbl = f'<div style="margin-bottom:16px"><strong style="color:#89b4fa">{sheet_label}</strong></div>'
                                tbl += '<div style="overflow-x:auto"><table style="border-collapse:collapse;width:100%;font-size:.82em">'
                                for rn in sorted_rows:
                                    tbl += '<tr>'
                                    rd = rows_data[rn]
                                    for ci in range(max_col + 1):
                                        val = rd.get(ci, "")
                                        bg = "#161b22" if rn == sorted_rows[0] else "#0d1117"
                                        fw = "600" if rn == sorted_rows[0] else "400"
                                        tbl += (f'<td style="border:1px solid #30363d;padding:4px 8px;'
                                                f'background:{bg};font-weight:{fw};color:#c9d1d9;'
                                                f'white-space:nowrap">{val}</td>')
                                    tbl += '</tr>'
                                tbl += '</table></div>'
                                if len(sorted(rows_data.keys())) > 50:
                                    tbl += f'<p style="color:#6c7086;font-size:.8em">Показано 50 из {len(rows_data)} строк</p>'
                                table_html_parts.append(tbl)

                            if table_html_parts:
                                extracted = "TABLE_HTML:" + "".join(table_html_parts)
                            else:
                                # Fallback to text
                                parts = []
                                if shared:
                                    parts.append(" | ".join(shared[:100]))
                                extracted = "\n".join(parts) if parts else ""
                except Exception as ex:
                    extracted = f"(Ошибка: {ex})"
                import html as _html
                icon = '📝' if 'doc' in ext else '📊'
                if extracted and extracted.startswith("TABLE_HTML:"):
                    # Excel table — already HTML
                    table_content = extracted[len("TABLE_HTML:"):]
                    preview_html = f"""
<div class="card" style="margin-top:16px">
  <h3 style="color:#89b4fa;margin-bottom:12px">{icon} Содержимое таблицы</h3>
  {table_content}
</div>"""
                elif extracted:
                    safe = _html.escape(extracted[:8000])
                    hilit = self._highlight_dlp(safe, matches) if matches else safe
                    preview_html = f"""
<div class="card" style="margin-top:16px">
  <h3 style="color:#89b4fa;margin-bottom:12px">{icon} Содержимое (извлечённый текст)</h3>
  <pre style="background:#0d1117;border:1px solid #30363d;border-radius:8px;
    padding:16px;overflow:auto;max-height:600px;font-family:Consolas,monospace;
    font-size:.84em;line-height:1.65;white-space:pre-wrap;word-break:break-all">
{hilit}</pre>
</div>"""
                else:
                    preview_html = f"""
<div class="card" style="margin-top:16px">
  <div style="background:#21262d;border-radius:8px;padding:28px;text-align:center">
    <div style="font-size:3em;margin-bottom:12px">{icon}</div>
    <p style="color:#8b949e">Не удалось извлечь текст — скачайте файл</p>
  </div>
</div>"""
            elif ext in (".jpg",".jpeg",".png",".gif",".webp"):
                preview_html = f"""
<div class="card" style="margin-top:16px">
  <h3 style="color:#89b4fa;margin-bottom:12px">🖼 Изображение</h3>
  <img src="/capture/{fpath.name}"
       style="max-width:100%;max-height:500px;border-radius:8px">
</div>"""

        matches_html = ""
        if matches:
            items = ""
            for m in matches:
                sc = "#f38ba8" if m.get("severity") == "HIGH" else "#e3b341"
                items += (
                    f'<div style="background:#1c1010;border:1px solid #3d2020;'
                    f'border-radius:6px;padding:10px 14px;margin-bottom:8px">'
                    f'<span style="color:{sc};font-weight:600">'
                    f'[{m.get("severity","?")}] {m.get("rule","")}</span> — '
                    f'{m.get("description","")} | '
                    f'<code style="color:#fab387">{m.get("sample",m.get("keyword",""))[:60]}</code>'
                    f'</div>'
                )
            matches_html = f"""
<div class="card" style="margin-top:16px">
  <h3 style="color:#f38ba8;margin-bottom:12px">⚠️ Обнаруженные ДСП-данные</h3>
  {items}
</div>"""

        status_badge = (
            '<span class="badge badge-block">🚫 ЗАБЛОКИРОВАНО</span>' if blocked else
            '<span class="badge" style="background:#0c1520;color:#79c0ff;border-color:#1f6feb">⬇ Скачано</span>'
            if event.get("type") == "download" else
            '<span class="badge badge-upload">📤 Загрузка</span>'
        )
        fsize_s = f"{fsize//1024}KB" if fsize > 1024 else f"{fsize}B"

        html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<title>DLP — {filename}</title><style>{_CSS}</style></head>
<body>{_nav("/admin/files", user)}
<div class="container">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap">
    <h2 style="color:#f0f6fc">📄 {filename or "Файл"}</h2>
    {status_badge}
    <a href="/admin/files" style="margin-left:auto;color:#6c7086;font-size:.9em">← Все файлы</a>
  </div>
  <div class="card">
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px">
      <div><div style="color:#6c7086;font-size:.8em">Клиент</div><div><code>{event.get("client","")}</code></div></div>
      <div><div style="color:#6c7086;font-size:.8em">Время</div><div>{event.get("time","")}</div></div>
      <div><div style="color:#6c7086;font-size:.8em">Сайт</div><div><code>{event.get("host","")}</code></div></div>
      <div><div style="color:#6c7086;font-size:.8em">Размер</div><div>{fsize_s}</div></div>
      <div><div style="color:#6c7086;font-size:.8em">Тип</div><div>{event.get("filetype","—")}</div></div>
      <div><div style="color:#6c7086;font-size:.8em">Правила</div><div style="color:#f38ba8">{", ".join(rules) or "—"}</div></div>
    </div>
    {f'<div style="margin-top:14px;padding-top:14px;border-top:1px solid #30363d;color:#e3b341">{details}</div>' if details else ""}
  </div>
  {matches_html}
  <div style="margin:16px 0">{download_btn}</div>
  {preview_html}
</div></body></html>"""
        self._send_html(html)

    def _serve_files_list(self, events: list, user: str):
        qs = parse_qs(urlparse(self.path).query)
        # Active filters from URL params
        f_host   = qs.get("host",   [""])[0].strip()
        f_type   = qs.get("type",   [""])[0].strip()
        f_status = qs.get("status", [""])[0].strip()
        f_client = qs.get("client", [""])[0].strip()
        f_search = qs.get("search", [""])[0].strip().lower()

        # All file events (has capture or is an upload/download/blocked)
        file_events_raw = [
            e for e in reversed(events)
            if e.get("capture") or e.get("type") in ("upload","download","blocked")
        ][:500]

        # Collect distinct filter values for dropdowns
        all_hosts   = sorted({e.get("host","")  for e in file_events_raw if e.get("host")})
        all_types   = sorted({e.get("filetype","") for e in file_events_raw if e.get("filetype")})
        all_clients = sorted({e.get("client","") for e in file_events_raw if e.get("client")})

        # Apply filters
        def _matches(e):
            if f_host   and e.get("host","")     != f_host:   return False
            if f_type   and e.get("filetype","") != f_type:   return False
            if f_client and e.get("client","")   != f_client: return False
            if f_status == "blocked"  and not e.get("blocked"):           return False
            if f_status == "allowed"  and e.get("blocked"):               return False
            if f_status == "upload"   and e.get("type") != "upload":      return False
            if f_status == "download" and e.get("type") != "download":    return False
            if f_search:
                haystack = (
                    (e.get("filename") or "") + " " +
                    (e.get("host") or "") + " " +
                    (e.get("url") or "") + " " +
                    (e.get("filetype") or "") + " " +
                    (e.get("details") or "")
                ).lower()
                if f_search not in haystack:
                    return False
            return True

        file_events = [e for e in file_events_raw if _matches(e)]

        # Build filter bar
        def _opts(vals, cur, label):
            opts = f'<option value="">Все {label}</option>'
            for v in vals:
                sel = "selected" if v == cur else ""
                opts += f'<option value="{v}" {sel}>{v}</option>'
            return opts

        active_filters = sum(1 for x in [f_host,f_type,f_status,f_client,f_search] if x)
        filter_badge   = f' <span style="background:#1f6feb;color:#fff;border-radius:10px;padding:1px 8px;font-size:.75em">{active_filters}</span>' if active_filters else ""

        # Build rows
        rows = ""
        for e in file_events:
            blocked  = e.get("blocked", False)
            etype    = e.get("type", "")
            capture  = e.get("capture", "") or ""
            filename = e.get("filename") or capture or "—"
            fsize    = e.get("size", 0)
            fsize_s  = (f"{fsize/1024/1024:.1f}MB" if fsize > 1024*1024
                        else f"{fsize//1024}KB" if fsize > 1024
                        else f"{fsize}B")
            rules    = ", ".join(e.get("rules", []))
            host     = e.get("host", "")
            ftype    = e.get("filetype", "")
            client   = e.get("client", "")
            details  = e.get("details", "")

            if blocked:
                badge = '<span class="badge badge-block">🚫 Заблокирован</span>'
                row_bg = "background:#1c1010"
            elif etype == "upload":
                badge = '<span class="badge badge-upload">📤 Загрузка</span>'
                row_bg = "background:#1c1208"
            elif etype == "download":
                badge = '<span class="badge" style="background:#0c1520;color:#79c0ff;border-color:#1f6feb">⬇ Скачано</span>'
                row_bg = ""
            else:
                badge = '<span class="badge">📄 Файл</span>'
                row_bg = ""

            # File type icon
            icons = {"pdf":"📕","docx":"📝","doc":"📝","xlsx":"📊","xls":"📊",
                     "pptx":"📋","ppt":"📋","txt":"📄","csv":"📊","zip":"🗜",
                     "rar":"🗜","7z":"🗜","json":"📋","xml":"📋","image":"🖼",
                     "jpeg":"🖼","png":"🖼","video":"🎬","audio":"🎵","binary":"📦",
                     "exe":"⚙️","msi":"⚙️","iso":"💿","sql":"🗄"}
            icon = icons.get(ftype, "📄")

            open_btn = ""
            dl_btn   = ""
            if capture:
                cap_name = Path(capture).name
                open_btn = f'<a href="/admin/files?id={e.get("id","")}" class="btn btn-sm btn-primary" style="padding:3px 10px">👁 Открыть</a> '
                dl_btn   = f'<a href="/capture/{cap_name}" class="btn btn-sm" style="background:#21262d;color:#8b949e;border-color:#30363d;padding:3px 8px">⬇</a>'

            # Truncate long filename
            fname_display = filename[:40] + "…" if len(filename) > 40 else filename
            url_short = (e.get("url",""))[:60] + "…" if len(e.get("url","")) > 60 else e.get("url","")

            rows += (
                f'<tr style="{row_bg}">' +
                f'<td style="white-space:nowrap;color:#6c7086;font-size:.78em">{e.get("time","")[:19]}</td>' +
                f'<td>{badge}</td>' +
                f'<td><code style="font-size:.82em">{client}</code></td>' +
                f'<td style="color:#89b4fa;font-weight:500">' +
                f'  <a href="/admin/files?host={host}&{self._qs_keep(f_type,f_status,f_client,f_search)}" ' +
                f'  style="color:#58a6ff;text-decoration:none">{host}</a></td>' +
                f'<td title="{filename}">{icon} {fname_display}</td>' +
                f'<td><span style="background:#21262d;border-radius:4px;padding:2px 8px;font-size:.8em">{ftype}</span></td>' +
                f'<td style="color:#8b949e">{fsize_s}</td>' +
                f'<td style="color:#f38ba8;font-size:.82em">{rules or "—"}</td>' +
                f'<td style="white-space:nowrap">{open_btn}{dl_btn}</td>' +
                f'</tr>'
            )

        empty8 = '<tr><td colspan="9" style="text-align:center;color:#6c7086;padding:30px">Файлов нет — попробуйте изменить фильтры</td></tr>'

        html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="10">
<title>DLP — Файлы</title><style>{_CSS}
.filter-bar{{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:16px}}
.filter-bar select,.filter-bar input{{background:#161b22;border:1px solid #30363d;
  border-radius:6px;color:#c9d1d9;padding:6px 10px;font-size:.85em}}
.filter-bar select:focus,.filter-bar input:focus{{border-color:#58a6ff;outline:none}}
.filter-bar input{{min-width:180px}}
.filter-bar .btn-filter{{background:#1f6feb;border-color:#388bfd}}
.filter-bar .btn-reset{{background:#21262d;color:#8b949e;border-color:#30363d}}
.count-badge{{background:#21262d;border:1px solid #30363d;border-radius:20px;
  padding:3px 12px;font-size:.82em;color:#8b949e}}
</style></head>
<body>{_nav("/admin/files", user)}
<div class="container">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap">
    <h2 style="color:#f0f6fc">📁 Перехваченные файлы</h2>
    <span class="count-badge">{len(file_events)} из {len(file_events_raw)}{filter_badge}</span>
  </div>

  <!-- Filter bar -->
  <form method="GET" action="/admin/files">
  <div class="filter-bar">
    <input type="text" name="search" placeholder="🔍 Поиск по имени, сайту, правилу..."
           value="{f_search}" style="flex:1;min-width:220px">
    <select name="host">   {_opts(all_hosts,   f_host,   "сайты")}</select>
    <select name="type">   {_opts(all_types,   f_type,   "типы")}</select>
    <select name="client"> {_opts(all_clients, f_client, "клиенты")}</select>
    <select name="status">
      <option value="" {"selected" if not f_status else ""}>Все статусы</option>
      <option value="upload"   {"selected" if f_status=="upload"   else ""}>📤 Загрузки</option>
      <option value="download" {"selected" if f_status=="download" else ""}>⬇ Скачивания</option>
      <option value="blocked"  {"selected" if f_status=="blocked"  else ""}>🚫 Заблокированные</option>
      <option value="allowed"  {"selected" if f_status=="allowed"  else ""}>✅ Разрешённые</option>
    </select>
    <button type="submit" class="btn btn-filter">Применить</button>
    <a href="/admin/files" class="btn btn-reset">✕ Сброс</a>
  </div>
  </form>

  <div class="card" style="padding:0;overflow:hidden">
    <table>
      <thead><tr>
        <th>Время</th><th>Статус</th><th>Клиент</th><th>Сайт</th>
        <th>Файл</th><th>Тип</th><th>Размер</th><th>Правила ДСП</th><th></th>
      </tr></thead>
      <tbody>{rows or empty8}</tbody>
    </table>
  </div>
  <p style="color:#6c7086;font-size:.78em;margin-top:8px">
    Обновляется каждые 10 сек. Нажмите на сайт для фильтрации.
  </p>
</div></body></html>"""
        self._send_html(html)

    def _qs_keep(self, f_type="", f_status="", f_client="", f_search=""):
        """Build query string keeping existing filters"""
        parts = []
        if f_type:   parts.append(f"type={f_type}")
        if f_status: parts.append(f"status={f_status}")
        if f_client: parts.append(f"client={f_client}")
        if f_search: parts.append(f"search={f_search}")
        return "&".join(parts)

    def _highlight_dlp(self, text: str, matches: list) -> str:
        """Highlight DLP matches in text with colored markers"""
        import html as hm
        esc = hm.escape(text)
        if not matches:
            return esc
        for m in matches:
            # Use keyword for keyword-based matches, sample for pattern matches
            sample = m.get("keyword") or m.get("sample") or ""
            if not sample or len(sample) < 2:
                continue
            rule = m.get("rule","")
            desc = m.get("description","")
            sev  = m.get("severity","HIGH")
            # Color by severity
            if sev == "HIGH":
                bg, fg = "#5a2000", "#ffb347"
            else:
                bg, fg = "#1a3a00", "#a6e3a1"
            s = hm.escape(sample)
            marked = (
                f'<mark style="background:{bg};color:{fg};border-radius:3px;'
                f'padding:1px 4px;border:1px solid {fg}33;font-weight:600"'
                f' title="{rule}: {desc}">{s}</mark>'
            )
            # Replace up to 20 occurrences (case-insensitive)
            import re as _re
            def _repl(mo):
                return marked
            esc = _re.sub(_re.escape(s), _repl, esc, count=20, flags=_re.IGNORECASE)
        return esc

    # ── Public pages ──────────────────────────────────────────────────────────
    def _serve_index(self):
        ip, pp = self.server_ip, self.proxy_port
        html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8"><title>DLP Proxy</title>
<style>{_CSS}
.hero{{background:linear-gradient(135deg,#161b22,#1f2937);border-bottom:1px solid #30363d;
      padding:50px;text-align:center}}
.hero h1{{font-size:2.4em;color:#58a6ff;margin-bottom:8px}}
.badge2{{display:inline-block;background:#21262d;border:1px solid #30363d;
         padding:3px 12px;border-radius:20px;font-size:.85em;margin:3px}}
.step{{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:22px;margin-bottom:16px}}
.sn{{background:#58a6ff;color:#000;width:30px;height:30px;border-radius:50%;
     display:inline-flex;align-items:center;justify-content:center;font-weight:700;margin-right:10px}}
.code{{background:#0d1117;border:1px solid #30363d;border-radius:7px;padding:14px;
       margin-top:10px;font-family:Consolas,monospace;font-size:.88em;color:#a5d6ff;white-space:pre-wrap}}
</style></head>
<body>
<div class="hero">
  <h1>🛡️ DLP Proxy</h1>
  <p>Система защиты от утечки данных (ДСП)</p>
  <div style="margin-top:16px">
    <span class="badge2">Сервер: <b style="color:#3fb950">{ip}</b></span>
    <span class="badge2">Прокси: <b style="color:#3fb950">{pp}</b></span>
    <span class="badge2">Порт: <b style="color:#3fb950">{CERT_PORT}</b></span>
  </div>
</div>
<div style="max-width:800px;margin:40px auto;padding:0 20px">
  <div class="step">
    <div style="display:flex;align-items:center">
      <span class="sn">1</span><h2 style="color:#f0f6fc">Скачайте CA-сертификат</h2>
    </div>
    <div style="margin-top:12px">
      <a href="/ca.der" class="btn btn-primary" style="margin-right:8px">⬇ Windows (.der)</a>
      <a href="/ca.crt" class="btn" style="background:#21262d;border-color:#30363d">⬇ PEM (.crt)</a>
    </div>
  </div>
  <div class="step">
    <div style="display:flex;align-items:center">
      <span class="sn">2</span><h2 style="color:#f0f6fc">Установите (PowerShell от Администратора)</h2>
    </div>
    <div class="code">certutil -addstore -f "ROOT" dlp_proxy_ca.der</div>
  </div>
  <div class="step">
    <div style="display:flex;align-items:center">
      <span class="sn">3</span><h2 style="color:#f0f6fc">Или запустите EXE-установщик</h2>
    </div>
    <p style="color:#8b949e;margin-top:8px">
      Используйте <code>DLP_Client_Setup.exe</code> — он сделает всё автоматически.
    </p>
  </div>
  <div class="step">
    <div style="display:flex;align-items:center">
      <span class="sn">4</span><h2 style="color:#f0f6fc">Панель администратора</h2>
    </div>
    <div style="margin-top:12px">
      <a href="/admin/" class="btn btn-primary">🔐 Войти в панель</a>
    </div>
  </div>
</div></body></html>"""
        self._send_html(html)


    def _serve_health(self):
        """Simple health check — always returns 200 if web server is alive"""
        data = json.dumps({
            "status": "ok",
            "server_ip": self.server_ip,
            "cert_port": CERT_PORT,
            "proxy_port": self.proxy_port,
            "time": datetime.now().isoformat(timespec="seconds"),
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_pem(self):
        if not CA_CERT_FILE.exists():
            self.send_response(404); self.end_headers(); return
        data = CA_CERT_FILE.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-pem-file")
        self.send_header("Content-Disposition", "attachment; filename=dlp_proxy_ca.crt")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def _serve_der(self):
        if not CA_CERT_DER_FILE.exists():
            self.send_response(404); self.end_headers(); return
        data = CA_CERT_DER_FILE.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-x509-ca-cert")
        self.send_header("Content-Disposition", "attachment; filename=dlp_proxy_ca.der")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def _serve_status(self):
        clients = self._get_all_clients()
        data = json.dumps({
            "status": "running", "server_ip": self.server_ip,
            "proxy_port": self.proxy_port, "cert_port": CERT_PORT,
            "upstream_proxy": self.upstream_proxy or None,
            "proxy_clients": clients,
            "stats": {"allowed": _allowed_count, "blocked": _blocked_count,
                      "total": _allowed_count + _blocked_count},
            "certificate": get_cert_info(),
        }, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.end_headers(); self.wfile.write(data)

    def _serve_traffic(self):
        clients = self._get_all_clients()
        with _traffic_lock:
            recent  = list(reversed(_traffic_log[-50:]))
            bl, al  = _blocked_count, _allowed_count
        rows = "".join(
            f'<tr><td>{e["time"]}</td><td><code>{e["client"]}</code></td>'
            f'<td style="color:{"#f38ba8" if e["blocked"] else "#a6e3a1"};font-weight:bold">'
            f'{"БЛОК" if e["blocked"] else "ОК"}</td>'
            f'<td style="font-size:.85em;color:#8b949e">{e["url"]}</td></tr>'
            for e in recent
        )
        badges = "".join(
            f'<span style="background:#1f3a5a;color:#79c0ff;padding:4px 12px;'
            f'border-radius:12px;margin:3px;display:inline-block">🖥 {c}</span>'
            for c in clients
        ) or '<span style="color:#f38ba8">Клиентов нет</span>'
        html = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="5">
<title>DLP — Трафик</title><style>{_CSS}</style></head>
<body><div style="padding:24px">
<p style="margin-bottom:16px">
  <a href="/">← Главная</a>
  <a href="/admin/" style="margin-left:16px">🔐 Панель</a>
  <span style="color:#6c7086;font-size:.85em;margin-left:16px">Обновление каждые 5 сек</span>
</p>
<div class="stats">
  <div class="stat"><div class="v" style="color:#a6e3a1">{al}</div><div class="l">Пропущено</div></div>
  <div class="stat"><div class="v" style="color:#f38ba8">{bl}</div><div class="l">Заблокировано</div></div>
  <div class="stat"><div class="v" style="color:#89b4fa">{len(clients)}</div><div class="l">Клиентов</div></div>
</div>
<div class="card" style="margin-bottom:16px">
  <h3 style="color:#89b4fa;margin-bottom:10px">Клиенты</h3>{badges}
</div>
<div class="card" style="padding:0">
<table><thead><tr><th>Время</th><th>Клиент</th><th>Решение</th><th>URL</th></tr></thead>
<tbody>{rows or '<tr><td colspan="4" style="text-align:center;color:#6c7086;padding:30px">Нет данных</td></tr>'}</tbody>
</table></div>
</div></body></html>"""
        self._send_html(html)

    # ══════════════════════════════════════════════════════════════════════════
    # INCIDENTS PAGE
    # ══════════════════════════════════════════════════════════════════════════

    def _serve_incidents(self, user: str):
        if not _HAS_TP:
            self._send_html(f"<!DOCTYPE html><html><head><style>{_CSS}</style></head>"
                            f"<body>{_nav('/admin/incidents', user)}"
                            f"<div class='container'><h2>Модуль transparency.py не найден</h2>"
                            f"<p>Скопируйте transparency.py в shared/</p></div></body></html>")
            return

        qs = parse_qs(urlparse(self.path).query)
        sel_id = qs.get("id", [""])[0]
        f_status = qs.get("status", [""])[0]
        f_client = qs.get("client", [""])[0]

        incidents = _tp.get_incidents(status=f_status, client_ip=f_client, limit=200)

        # ── Single incident detail ────────────────────────────────────────────
        if sel_id:
            inc = _tp.get_incident(sel_id)
            if not inc:
                self._redirect("/admin/incidents"); return

            # Matches display
            matches_html = ""
            for m in inc.get("matches", []):
                sc = "#f38ba8" if m.get("severity") == "HIGH" else "#e3b341"
                matches_html += (
                    f'<div style="background:#1c1010;border:1px solid #3d2020;'
                    f'border-radius:6px;padding:10px 14px;margin-bottom:6px">'
                    f'<span style="color:{sc};font-weight:600">'
                    f'[{m.get("severity","")}] {m.get("rule","")}</span> — '
                    f'{m.get("description","")} | '
                    f'<code style="color:#fab387">{m.get("sample","")}</code>'
                    f' <span style="color:#6c7086">({m.get("score",0)} б.)</span>'
                    f'</div>'
                )

            # ── Access control: admin CANNOT see content until employee approves
            access_st = inc.get("access_status", "locked")
            can_view = (access_st == "approved")

            # Access request button / status
            access_html = ""
            default_msg = _DLP_SETTINGS.get("access_request_message", "")
            if access_st == "locked":
                access_html = (
                    f'<form method="POST" action="/admin/access_request">'
                    f'<input type="hidden" name="event_id" value="{sel_id}">'
                    f'<div style="margin:8px 0">'
                    f'<label style="color:#8b949e;font-size:.85em">Сообщение сотруднику:</label>'
                    f'<textarea name="message" rows="2" style="width:100%;margin-top:4px;'
                    f'background:#161b22;border:1px solid #30363d;border-radius:6px;'
                    f'padding:8px;color:#c9d1d9;font-size:12px;resize:vertical">{default_msg}</textarea>'
                    f'</div>'
                    f'<button type="submit" class="btn" style="background:#1a3550;'
                    f'border-color:#1f6feb;color:#79c0ff;font-weight:600">'
                    f'🔑 Запросить доступ к содержимому</button></form>'
                )
            elif access_st == "requested":
                access_html = '<p style="color:#e3b341;margin-top:8px">⏳ Ожидание одобрения от сотрудника...</p>'
            elif access_st == "approved":
                access_html = '<p style="color:#a6e3a1;margin-top:8px">✅ Сотрудник разрешил просмотр</p>'
            elif access_st == "denied":
                access_html = '<p style="color:#f38ba8;margin-top:8px">❌ Сотрудник отклонил доступ</p>'

            # File preview — ONLY if access approved
            preview_html = ""
            download_btn = ""
            if can_view and inc.get("capture"):
                cap_path = CAPTURES_DIR / Path(inc["capture"]).name
                if cap_path.exists():
                    download_btn = (
                        f'<a href="/capture/{cap_path.name}" class="btn btn-primary">'
                        f'⬇ Скачать {inc.get("filename","файл")}</a>'
                    )
                    fname = inc.get("filename", "")
                    ext = Path(fname).suffix.lower() if fname else cap_path.suffix.lower()
                    if ext in (".txt", ".csv", ".json", ".xml", ".log"):
                        try:
                            raw = cap_path.read_text(encoding="utf-8", errors="replace")[:8000]
                            import html as _html
                            preview_html = f"""
<div class="card" style="margin-top:16px">
  <h3 style="color:#89b4fa;margin-bottom:12px">📄 Содержимое файла</h3>
  <pre style="background:#0d1117;border:1px solid #30363d;border-radius:8px;
    padding:16px;overflow:auto;max-height:500px;font-family:Consolas,monospace;
    font-size:.84em;line-height:1.6;white-space:pre-wrap">{_html.escape(raw)}</pre>
</div>"""
                        except Exception: pass
                    elif ext in (".docx", ".doc"):
                        try:
                            import zipfile, io, html as _html
                            with zipfile.ZipFile(io.BytesIO(cap_path.read_bytes())) as zf:
                                parts = []
                                for n in zf.namelist():
                                    if n.endswith(".xml") and "word/document" in n:
                                        x = zf.read(n).decode("utf-8", errors="replace")
                                        c = re.sub(r'<[^>]+>', ' ', x)
                                        c = re.sub(r'\s+', ' ', c).strip()
                                        if c: parts.append(c)
                            if parts:
                                preview_html = f"""
<div class="card" style="margin-top:16px">
  <h3 style="color:#89b4fa;margin-bottom:12px">📝 Содержимое DOCX</h3>
  <pre style="background:#0d1117;border:1px solid #30363d;border-radius:8px;
    padding:16px;overflow:auto;max-height:500px;font-family:Consolas,monospace;
    font-size:.84em;line-height:1.6;white-space:pre-wrap">{_html.escape(chr(10).join(parts)[:8000])}</pre>
</div>"""
                        except Exception: pass
                    elif ext in (".xlsx", ".xls"):
                        try:
                            import zipfile, io, html as _html
                            with zipfile.ZipFile(io.BytesIO(cap_path.read_bytes())) as zf:
                                parts = []
                                if "xl/sharedStrings.xml" in zf.namelist():
                                    ss = zf.read("xl/sharedStrings.xml").decode("utf-8", errors="replace")
                                    strings = re.findall(r'<t[^>]*>([^<]+)</t>', ss)
                                    if strings: parts.append(" | ".join(strings[:200]))
                            if parts:
                                preview_html = f"""
<div class="card" style="margin-top:16px">
  <h3 style="color:#89b4fa;margin-bottom:12px">📊 Содержимое XLSX</h3>
  <pre style="background:#0d1117;border:1px solid #30363d;border-radius:8px;
    padding:16px;overflow:auto;max-height:500px;font-family:Consolas,monospace;
    font-size:.84em;line-height:1.6;white-space:pre-wrap">{_html.escape(chr(10).join(parts)[:8000])}</pre>
</div>"""
                        except Exception: pass

            # If access not approved — show locked placeholder
            if not can_view:
                preview_html = f"""
<div class="card" style="margin-top:16px">
  <div style="background:#21262d;border-radius:8px;padding:40px;text-align:center">
    <div style="font-size:3.5em;margin-bottom:16px">🔒</div>
    <p style="color:#c9d1d9;font-size:1.1em;font-weight:600">Содержимое скрыто</p>
    <p style="color:#8b949e;margin-top:8px">
      Для просмотра содержимого файла необходимо разрешение сотрудника.<br>
      Нажмите «Запросить доступ» — сотрудник получит уведомление.
    </p>
    {access_html}
  </div>
</div>"""
                download_btn = ""  # No download without access

            st = inc.get("status", "new")
            st_badges = {
                "new": '<span class="badge" style="background:#3d1a1a;color:#f38ba8;border-color:#5a2828">🔴 Новый</span>',
                "reviewed": '<span class="badge" style="background:#2d2a10;color:#e3b341;border-color:#4a4520">🟡 Рассмотрен</span>',
                "resolved": '<span class="badge" style="background:#152a1e;color:#a6e3a1;border-color:#1f4332">🟢 Закрыт</span>',
            }
            resolve_html = ""
            if st != "resolved":
                resolve_html = f"""
<form method="POST" action="/admin/incident/resolve" style="margin-top:12px">
  <input type="hidden" name="event_id" value="{sel_id}">
  <input type="text" name="notes" placeholder="Комментарий (опционально)" style="width:60%;margin-right:8px">
  <button type="submit" class="btn" style="background:#1a4731;border-color:#2ea043;color:#a8edbb">
    ✅ Закрыть инцидент</button>
</form>"""

            fsize = inc.get("filesize", 0)
            fsize_s = f"{fsize//1024}KB" if fsize > 1024 else f"{fsize}B"

            html = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<title>Инцидент #{sel_id}</title><style>{_CSS}</style></head>
<body>{_nav("/admin/incidents", user)}
<div class="container">
  <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;flex-wrap:wrap">
    <h2 style="color:#f0f6fc">🔴 Инцидент #{sel_id}</h2>
    {st_badges.get(st, st)}
    <a href="/admin/incidents" style="margin-left:auto;color:#6c7086">← Все</a>
  </div>
  <div class="card">
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px">
      <div><div style="color:#6c7086;font-size:.8em">Сотрудник</div><code>{inc.get("client_ip","")}</code></div>
      <div><div style="color:#6c7086;font-size:.8em">Время</div>{inc.get("time","")}</div>
      <div><div style="color:#6c7086;font-size:.8em">Файл</div><strong>{inc.get("filename","—")}</strong></div>
      <div><div style="color:#6c7086;font-size:.8em">Размер</div>{fsize_s}</div>
      <div><div style="color:#6c7086;font-size:.8em">Куда</div><code>{inc.get("host","")}</code></div>
      <div><div style="color:#6c7086;font-size:.8em">Score</div><span style="color:#f38ba8;font-weight:700">{inc.get("score",0)}</span></div>
    </div>
  </div>
  <div class="card" style="margin-top:16px">
    <h3 style="color:#f38ba8;margin-bottom:12px">⚠️ Сработавшие правила</h3>
    {matches_html or '<p style="color:#6c7086">Нет данных</p>'}
  </div>
  <div style="margin:16px 0;display:flex;gap:8px;align-items:center">
    {download_btn}
    {'<span style="color:#a6e3a1">✅ Доступ одобрен сотрудником</span>' if can_view else ''}
  </div>
  {preview_html}
  {resolve_html}
  <div style="margin-top:16px">
    <a href="/admin/chat?ip={inc.get('client_ip','')}" class="btn btn-primary">💬 Написать сотруднику</a>
  </div>
</div></body></html>"""
            self._send_html(html); return

        # ── Incidents list ────────────────────────────────────────────────────
        rows = ""
        for inc in incidents:
            st = inc.get("status", "new")
            st_dot = {"new": "🔴", "reviewed": "🟡", "resolved": "🟢"}.get(st, "⚪")
            rules_str = ", ".join(inc.get("rules", []))
            rows += (
                f'<tr>'
                f'<td style="color:#6c7086;font-size:.82em">{inc.get("time","")[:16]}</td>'
                f'<td>{st_dot} {st}</td>'
                f'<td><code>{inc.get("client_ip","")}</code></td>'
                f'<td><strong>{inc.get("filename","—")}</strong></td>'
                f'<td><code>{inc.get("host","")}</code></td>'
                f'<td style="color:#f38ba8">{inc.get("score",0)}</td>'
                f'<td style="color:#e3b341;font-size:.85em">{rules_str[:40]}</td>'
                f'<td><a href="/admin/incidents?id={inc["id"]}" class="btn btn-sm btn-danger">Открыть</a></td>'
                f'</tr>'
            )
        empty = '<tr><td colspan="8" style="text-align:center;color:#6c7086;padding:30px">Инцидентов нет</td></tr>'

        html = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<meta http-equiv="refresh" content="10">
<title>DLP — Инциденты</title><style>{_CSS}</style></head>
<body>{_nav("/admin/incidents", user)}
<div class="container">
  <h2 style="color:#f0f6fc;margin-bottom:20px">🔴 Инциденты DLP</h2>
  <div style="margin-bottom:16px;display:flex;gap:8px">
    <a href="/admin/incidents" class="btn btn-sm {'btn-primary' if not f_status else ''}">Все</a>
    <a href="/admin/incidents?status=new" class="btn btn-sm {'btn-primary' if f_status=='new' else ''}">🔴 Новые</a>
    <a href="/admin/incidents?status=reviewed" class="btn btn-sm {'btn-primary' if f_status=='reviewed' else ''}">🟡 Рассмотренные</a>
    <a href="/admin/incidents?status=resolved" class="btn btn-sm {'btn-primary' if f_status=='resolved' else ''}">🟢 Закрытые</a>
  </div>
  <div style="border-radius:8px;overflow:hidden;border:1px solid #30363d">
  <table><thead><tr>
    <th>Время</th><th>Статус</th><th>Клиент</th><th>Файл</th>
    <th>Сайт</th><th>Score</th><th>Правила</th><th></th>
  </tr></thead><tbody>{rows or empty}</tbody></table></div>
</div></body></html>"""
        self._send_html(html)

    # ══════════════════════════════════════════════════════════════════════════
    # CHAT PAGE
    # ══════════════════════════════════════════════════════════════════════════

    def _serve_chat(self, user: str):
        if not _HAS_TP:
            self._send_html(f"<!DOCTYPE html><html><head><style>{_CSS}</style></head>"
                            f"<body>{_nav('/admin/chat', user)}"
                            f"<div class='container'><p>Модуль не найден</p></div></body></html>")
            return

        qs = parse_qs(urlparse(self.path).query)
        sel_ip = qs.get("ip", [""])[0]

        chats = _tp.get_all_chats_summary()
        # Also add clients without messages
        all_clients = self._get_all_clients()
        chat_ips = {c["client_ip"] for c in chats}
        for ip in all_clients:
            if ip not in chat_ips:
                chats.append({"client_ip": ip, "total_messages": 0, "unread": 0,
                              "last_message": "", "last_time": "", "last_from": ""})

        # Client list
        client_list = ""
        for c in chats:
            ip = c["client_ip"]
            unread = c.get("unread", 0)
            badge = f' <span style="background:#f38ba8;color:#fff;border-radius:10px;padding:1px 7px;font-size:.75em">{unread}</span>' if unread else ""
            active = "background:#1f6feb;color:#fff" if ip == sel_ip else "background:#21262d;color:#8b949e"
            last = (c.get("last_message") or c.get("last_text") or "")[:30]
            client_list += (
                f'<a href="/admin/chat?ip={ip}" style="{active};display:block;padding:10px 14px;'
                f'border-radius:8px;margin-bottom:4px;text-decoration:none;border:1px solid #30363d">'
                f'<div style="font-weight:600">{ip}{badge}</div>'
                f'<div style="font-size:.8em;color:#6c7086;margin-top:2px">{last}</div></a>'
            )

        # Messages
        messages_html = ""
        if sel_ip:
            _tp.mark_messages_read(sel_ip, "admin")
            msgs = _tp.get_messages(sel_ip)
            for m in msgs:
                is_admin = m["from"] == "admin"
                align = "flex-end" if is_admin else "flex-start"
                bg = "#1f3a5a" if is_admin else "#21262d"
                label = f"👤 {m.get('from_name', m['from'])}"
                messages_html += (
                    f'<div style="display:flex;justify-content:{align};margin-bottom:8px">'
                    f'<div style="background:{bg};border-radius:12px;padding:10px 16px;'
                    f'max-width:70%;border:1px solid #30363d">'
                    f'<div style="font-size:.75em;color:#6c7086;margin-bottom:4px">{label} · {m["time"][-8:]}</div>'
                    f'<div style="color:#c9d1d9">{m["text"]}</div>'
                    f'</div></div>'
                )
            if not messages_html:
                messages_html = '<p style="color:#6c7086;text-align:center;padding:40px">Нет сообщений</p>'

        send_form = ""
        if sel_ip:
            send_form = f"""
<form method="POST" action="/admin/chat/send" style="display:flex;gap:8px;margin-top:12px">
  <input type="hidden" name="client_ip" value="{sel_ip}">
  <input type="text" name="text" placeholder="Написать сообщение..."
         style="flex:1" autocomplete="off" required>
  <button type="submit" class="btn btn-primary">Отправить</button>
</form>"""

        html = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<title>DLP — Чат</title><style>{_CSS}</style></head>
<body>{_nav("/admin/chat", user)}
<div class="container">
  <h2 style="color:#f0f6fc;margin-bottom:20px">💬 Чат с сотрудниками</h2>
  <div style="display:grid;grid-template-columns:250px 1fr;gap:16px;min-height:500px">
    <div style="border:1px solid #30363d;border-radius:8px;padding:8px;overflow-y:auto;max-height:600px">
      <div style="color:#6c7086;font-size:.8em;padding:8px;border-bottom:1px solid #21262d;margin-bottom:8px">Клиенты</div>
      {client_list or '<p style="color:#6c7086;padding:8px">Нет клиентов</p>'}
    </div>
    <div style="border:1px solid #30363d;border-radius:8px;padding:16px;display:flex;flex-direction:column">
      <div style="flex:1;overflow-y:auto;max-height:450px;padding-right:8px" id="msgs">
        {messages_html if sel_ip else '<p style="color:#6c7086;text-align:center;padding:40px">← Выберите клиента</p>'}
      </div>
      {send_form}
    </div>
  </div>
</div>
<script>
var d=document.getElementById('msgs');
if(d) d.scrollTop=d.scrollHeight;
{'var _chatIp="'+sel_ip+'";' if sel_ip else 'var _chatIp="";'}
if(_chatIp) setInterval(function(){{
  fetch('/api/messages?client_ip='+_chatIp)
    .then(r=>r.json())
    .then(data=>{{
      if(!data.messages||!data.messages.length) return;
      var h='';
      data.messages.forEach(function(m){{
        var isAdmin=(m.from==='admin');
        var align=isAdmin?'flex-start':'flex-end';
        var bg=isAdmin?'#1f3a5a':'#21262d';
        var label=m.from_name||m.from;
        var t=(m.time||'').slice(-8);
        h+='<div style="display:flex;justify-content:'+align+';margin-bottom:8px">'
          +'<div style="background:'+bg+';border-radius:12px;padding:10px 16px;max-width:70%;border:1px solid #30363d">'
          +'<div style="font-size:10px;color:#6c7086">'+label+' · '+t+'</div>'
          +'<div style="color:#c9d1d9">'+m.text+'</div></div></div>';
      }});
      var box=document.getElementById('msgs');
      var atBottom=(box.scrollHeight-box.scrollTop-box.clientHeight)<50;
      box.innerHTML=h;
      if(atBottom) box.scrollTop=box.scrollHeight;
    }}).catch(function(){{}});
}}, 4000);
</script>
</body></html>"""
        self._send_html(html)

    # ══════════════════════════════════════════════════════════════════════════
    # ADMIN POST HANDLERS (transparency)
    # ══════════════════════════════════════════════════════════════════════════

    def _handle_chat_send(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = parse_qs(body)
        client_ip = params.get("client_ip", [""])[0]
        text = params.get("text", [""])[0]
        if _HAS_TP and client_ip and text:
            _tp.send_message(client_ip, "admin", text, sender_name=user)
        self._redirect(f"/admin/chat?ip={client_ip}")

    def _handle_incident_resolve(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = parse_qs(body)
        event_id = params.get("event_id", [""])[0]
        notes = params.get("notes", [""])[0]
        if _HAS_TP and event_id:
            _tp.update_incident(event_id, status="resolved",
                                admin_notes=f"[{user}] {notes}" if notes else f"[{user}] закрыт")
        self._redirect(f"/admin/incidents?id={event_id}")

    def _handle_access_request(self, user: str):
        """Admin requests access to view blocked file contents"""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = parse_qs(body)
        event_id = params.get("event_id", [""])[0]
        message = params.get("message", [_DLP_SETTINGS.get("access_request_message", "")])[0]

        if event_id:
            try:
                # Update incident in incidents.json
                items = []
                if _INC_FILE.exists():
                    items = json.loads(_INC_FILE.read_text(encoding="utf-8"))
                client_ip = ""
                filename = ""
                for inc in items:
                    if inc["id"] == event_id:
                        inc["access_status"] = "requested"
                        client_ip = inc.get("client_ip", "")
                        filename = inc.get("filename", "")
                        break
                _INC_FILE.write_text(json.dumps(items, ensure_ascii=False, indent=2, default=str),
                                     encoding="utf-8")
                # Write notification to client_notifications.json
                if client_ip:
                    now = datetime.now().isoformat(timespec="seconds")
                    notifs = {}
                    if _NTF_FILE.exists():
                        try: notifs = json.loads(_NTF_FILE.read_text(encoding="utf-8"))
                        except Exception: notifs = {}
                    notifs.setdefault(client_ip, []).append({
                        "id": f"n_ar_{event_id}",
                        "type": "access_request",
                        "text": f"🔑 {message}\nФайл: «{filename}»",
                        "time": now, "read": False,
                        "details": {"incident_id": event_id, "filename": filename,
                                    "admin": user, "message": message},
                    })
                    notifs[client_ip] = notifs[client_ip][-100:]
                    _NTF_FILE.write_text(json.dumps(notifs, ensure_ascii=False, indent=2, default=str),
                                         encoding="utf-8")
                logger.info(f"[AccessReq] {user} → {event_id}")
            except Exception as e:
                logger.error(f"[AccessReq] Error: {e}")

        self._redirect(f"/admin/incidents?id={event_id}")

    # ══════════════════════════════════════════════════════════════════════════
    # CLIENT API (JSON, no auth — identified by IP)
    # ══════════════════════════════════════════════════════════════════════════

    def _api_json(self, data: dict, status: int = 200):
        body = json.dumps(data, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def _api_notifications(self, qs: dict):
        if not _HAS_TP:
            self._api_json({"notifications": [], "unread": 0}); return
        client_ip = qs.get("client_ip", [""])[0]
        if not client_ip:
            # Try to get from remote address
            client_ip = self.client_address[0] if self.client_address else ""
        _register_heartbeat(client_ip)
        unread = qs.get("unread_only", [""])[0] == "1"
        notifs = _tp.get_notifications(client_ip, unread_only=unread)
        self._api_json({
            "notifications": notifs,
            "unread": _tp.get_unread_notifications_count(client_ip),
        })

    def _api_get_messages(self, qs: dict):
        if not _HAS_TP:
            self._api_json({"messages": []}); return
        client_ip = qs.get("client_ip", [""])[0]
        if not client_ip:
            client_ip = self.client_address[0] if self.client_address else ""
        since = qs.get("since", [""])[0]
        msgs = _tp.get_messages(client_ip, since=since)
        _tp.mark_messages_read(client_ip, "client")
        self._api_json({"messages": msgs})

    def _api_send_message(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        try:
            data = json.loads(body)
        except Exception:
            data = parse_qs(body)
            data = {k: v[0] if isinstance(v, list) else v for k, v in data.items()}
        client_ip = data.get("client_ip", "")
        text = data.get("text", "")
        if not client_ip:
            client_ip = self.client_address[0] if self.client_address else ""
        if _HAS_TP and client_ip and text:
            msg = _tp.send_message(client_ip, "client", text, sender_name=client_ip)
            self._api_json({"ok": True, "message": msg})
        else:
            self._api_json({"ok": False, "error": "missing data"}, 400)

    def _api_access_response(self):
        """Employee responds to admin's request to view file contents"""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        try:
            data = json.loads(body)
        except Exception:
            data = parse_qs(body)
            data = {k: v[0] if isinstance(v, list) else v for k, v in data.items()}
        event_id = data.get("event_id", "")
        approved = data.get("approved", "false")
        if isinstance(approved, str):
            approved = approved.lower() in ("true", "1", "yes")
        if _HAS_TP and event_id:
            _tp.respond_access(event_id, approved)
            self._api_json({"ok": True, "status": "approved" if approved else "denied"})
        else:
            self._api_json({"ok": False, "error": "missing event_id"}, 400)

    # ══════════════════════════════════════════════════════════════════════════
    # INTERNET ACCESS MANAGEMENT
    # ══════════════════════════════════════════════════════════════════════════

    def _api_internet_status(self, qs: dict):
        """Client checks their internet access status"""
        client_ip = qs.get("client_ip", [""])[0]
        if not client_ip:
            client_ip = self.client_address[0] if self.client_address else ""
        # Register heartbeat
        _register_heartbeat(client_ip)
        policy = _CFG.get("internet_default_policy", "block")
        if policy == "allow":
            self._api_json({"has_access": True, "policy": "allow",
                            "pending_request": None, "details": {}})
            return
        status = ia_get_internet_status(client_ip)
        status["policy"] = policy
        self._api_json(status)

    def _api_heartbeat(self, qs: dict):
        """Client pings to register as online"""
        client_ip = qs.get("client_ip", [""])[0]
        if not client_ip:
            client_ip = self.client_address[0] if self.client_address else ""
        _register_heartbeat(client_ip)
        self._api_json({"ok": True, "ip": client_ip})

    def _api_internet_request(self):
        """Client submits a request for internet access"""
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        try:
            data = json.loads(body)
        except Exception:
            data = parse_qs(body)
            data = {k: v[0] if isinstance(v, list) else v for k, v in data.items()}
        client_ip = data.get("client_ip", "")
        reason = data.get("reason", "")
        if not client_ip:
            client_ip = self.client_address[0] if self.client_address else ""
        if not reason:
            self._api_json({"ok": False, "error": "reason_required"}, 400)
            return
        result = ia_submit_request(client_ip, reason)
        logger.info(f"[InternetReq] {client_ip}: {reason[:80]} -> {result}")
        # Send notification to admin about new request
        if result.get("ok"):
            try:
                notifs = {}
                if _NTF_FILE.exists():
                    try: notifs = json.loads(_NTF_FILE.read_text(encoding="utf-8"))
                    except Exception: notifs = {}
                # Admin notification via transparency chat
                now = datetime.now().isoformat(timespec="seconds")
                _tp.send_message(client_ip, "client", 
                    f"🌐 Заявка на доступ в интернет:\n{reason[:300]}",
                    sender_name=client_ip)
            except Exception:
                pass
        self._api_json(result)

    def _handle_internet_approve(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = parse_qs(body)
        req_id = params.get("request_id", [""])[0]
        expires = params.get("expires", [""])[0]
        if req_id:
            ok = ia_approve_request(req_id, user, expires)
            if ok:
                logger.info(f"[Internet] {user} approved {req_id}")
                # Notify client
                try:
                    data = ia_get_all_data()
                    for req in data.get("pending_requests", []):
                        if req["id"] == req_id:
                            client_ip = req["client_ip"]
                            _tp.send_message(client_ip, "admin",
                                "✅ Ваша заявка на доступ в интернет ОДОБРЕНА.",
                                sender_name=user)
                            # Also send notification
                            notifs = {}
                            if _NTF_FILE.exists():
                                try: notifs = json.loads(_NTF_FILE.read_text(encoding="utf-8"))
                                except Exception: notifs = {}
                            notifs.setdefault(client_ip, []).append({
                                "id": f"n_ia_{req_id}",
                                "type": "internet_approved",
                                "text": f"✅ Доступ в интернет РАЗРЕШЁН администратором {user}.",
                                "time": datetime.now().isoformat(timespec="seconds"),
                                "read": False,
                                "details": {"request_id": req_id},
                            })
                            _NTF_FILE.write_text(
                                json.dumps(notifs, ensure_ascii=False, indent=2),
                                encoding="utf-8")
                            break
                except Exception as e:
                    logger.warning(f"[Internet] Notify error: {e}")
        self._redirect("/admin/internet")

    def _handle_internet_deny(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = parse_qs(body)
        req_id = params.get("request_id", [""])[0]
        comment = params.get("comment", [""])[0]
        if req_id:
            ok = ia_deny_request(req_id, user, comment)
            if ok:
                logger.info(f"[Internet] {user} denied {req_id}")
                try:
                    data = ia_get_all_data()
                    for req in data.get("pending_requests", []):
                        if req["id"] == req_id:
                            client_ip = req["client_ip"]
                            reason_text = f"Комментарий: {comment}" if comment else ""
                            _tp.send_message(client_ip, "admin",
                                f"❌ Ваша заявка на доступ в интернет отклонена. {reason_text}",
                                sender_name=user)
                            notifs = {}
                            if _NTF_FILE.exists():
                                try: notifs = json.loads(_NTF_FILE.read_text(encoding="utf-8"))
                                except Exception: notifs = {}
                            notifs.setdefault(client_ip, []).append({
                                "id": f"n_ia_{req_id}",
                                "type": "internet_denied",
                                "text": f"❌ Доступ в интернет ОТКЛОНЁН. {reason_text}",
                                "time": datetime.now().isoformat(timespec="seconds"),
                                "read": False,
                                "details": {"request_id": req_id, "comment": comment},
                            })
                            _NTF_FILE.write_text(
                                json.dumps(notifs, ensure_ascii=False, indent=2),
                                encoding="utf-8")
                            break
                except Exception:
                    pass
        self._redirect("/admin/internet")

    def _handle_internet_grant(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = parse_qs(body)
        client_ip = params.get("client_ip", [""])[0]
        reason = params.get("reason", ["Выдано администратором"])[0]
        expires = params.get("expires", [""])[0]
        if client_ip:
            ia_grant_access(client_ip, user, reason, expires)
            logger.info(f"[Internet] {user} granted access to {client_ip}")
        self._redirect("/admin/internet")

    def _handle_internet_revoke(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = parse_qs(body)
        client_ip = params.get("client_ip", [""])[0]
        if client_ip:
            ia_revoke_access(client_ip, user)
            logger.info(f"[Internet] {user} revoked access for {client_ip}")
            try:
                _tp.send_message(client_ip, "admin",
                    "🔒 Доступ в интернет отозван администратором.",
                    sender_name=user)
            except Exception:
                pass
        self._redirect("/admin/internet")

    def _serve_internet(self, user: str):
        """Admin page: Internet Access Management"""
        data = ia_get_all_data()
        policy = _CFG.get("internet_default_policy", "block")
        allowed = data.get("allowed_clients", {})
        pending = [r for r in data.get("pending_requests", []) if r.get("status") == "pending"]
        history = data.get("history", [])[-50:]
        history.reverse()

        # All known clients
        all_clients = self._get_all_clients()

        policy_badge = (
            '<span class="badge badge-block">🔒 ЗАБЛОКИРОВАН</span>'
            if policy == "block" else
            '<span class="badge badge-ok">🌐 РАЗРЕШЁН</span>'
        )

        # Pending requests table
        pending_html = ""
        if pending:
            rows = ""
            for r in pending:
                rows += f"""<tr>
                    <td><code>{r['client_ip']}</code></td>
                    <td>{r.get('reason','—')}</td>
                    <td>{r.get('time','')[-19:]}</td>
                    <td>
                      <form method="POST" action="/admin/internet/approve" style="display:inline">
                        <input type="hidden" name="request_id" value="{r['id']}">
                        <button class="btn btn-sm" style="background:#1a4731;color:#a8edbb;border-color:#2ea043">
                          ✅ Одобрить</button>
                      </form>
                      <form method="POST" action="/admin/internet/deny" style="display:inline;margin-left:4px">
                        <input type="hidden" name="request_id" value="{r['id']}">
                        <button class="btn btn-sm btn-danger">❌ Отклонить</button>
                      </form>
                    </td></tr>"""
            pending_html = f"""
            <div class="card" style="border-color:#e3b341">
              <h3 style="color:#e3b341;margin-bottom:12px">⏳ Ожидающие заявки ({len(pending)})</h3>
              <table><thead><tr>
                <th>IP клиента</th><th>Причина</th><th>Время</th><th>Действия</th>
              </tr></thead><tbody>{rows}</tbody></table>
            </div>"""
        else:
            pending_html = '<div class="card"><p style="color:#6c7086">Нет ожидающих заявок</p></div>'

        # Allowed clients table
        allowed_html = ""
        if allowed:
            rows = ""
            for ip, info in sorted(allowed.items()):
                exp = info.get("expires", "")
                exp_str = exp[-19:] if exp else "бессрочно"
                rows += f"""<tr>
                    <td><code>{ip}</code></td>
                    <td>{info.get('approved_by','—')}</td>
                    <td>{info.get('reason','—')[:60]}</td>
                    <td>{info.get('time','')[-19:]}</td>
                    <td>{exp_str}</td>
                    <td>
                      <form method="POST" action="/admin/internet/revoke" style="display:inline">
                        <input type="hidden" name="client_ip" value="{ip}">
                        <button class="btn btn-sm btn-danger">🔒 Отозвать</button>
                      </form>
                    </td></tr>"""
            allowed_html = f"""
            <div class="card">
              <h3 style="color:#a6e3a1;margin-bottom:12px">✅ Клиенты с доступом ({len(allowed)})</h3>
              <table><thead><tr>
                <th>IP</th><th>Одобрил</th><th>Причина</th><th>Дата</th><th>Истекает</th><th></th>
              </tr></thead><tbody>{rows}</tbody></table>
            </div>"""

        # Grant access form
        client_options = "".join(f'<option value="{ip}">{ip}</option>' for ip in all_clients)
        grant_html = f"""
        <div class="card">
          <h3 style="color:#89b4fa;margin-bottom:12px">➕ Выдать доступ вручную</h3>
          <form method="POST" action="/admin/internet/grant"
                style="display:flex;gap:10px;align-items:end;flex-wrap:wrap">
            <div>
              <label style="color:#8b949e;font-size:.85em;display:block;margin-bottom:4px">IP клиента</label>
              <select name="client_ip" style="background:#0d1117;border:1px solid #30363d;
                      border-radius:7px;padding:8px 12px;color:#c9d1d9;font-size:14px">
                <option value="">— выберите —</option>
                {client_options}
              </select>
            </div>
            <div>
              <label style="color:#8b949e;font-size:.85em;display:block;margin-bottom:4px">Причина</label>
              <input type="text" name="reason" value="Выдано администратором"
                     style="width:250px">
            </div>
            <div>
              <label style="color:#8b949e;font-size:.85em;display:block;margin-bottom:4px">
                Истекает (пусто = бессрочно)</label>
              <input type="datetime-local" name="expires"
                     style="background:#0d1117;border:1px solid #30363d;border-radius:7px;
                            padding:8px 12px;color:#c9d1d9;font-size:14px">
            </div>
            <button class="btn btn-primary" type="submit">Выдать доступ</button>
          </form>
        </div>"""

        # History table
        hist_rows = ""
        for h in history[:30]:
            action_badge = {
                "approved": '<span style="color:#a6e3a1">✅ одобрено</span>',
                "denied":   '<span style="color:#f38ba8">❌ отклонено</span>',
                "granted":  '<span style="color:#89b4fa">➕ выдано</span>',
                "revoked":  '<span style="color:#e3b341">🔒 отозвано</span>',
                "expired":  '<span style="color:#6c7086">⏰ истекло</span>',
            }.get(h.get("action", ""), h.get("action", ""))
            hist_rows += f"""<tr>
                <td><code>{h.get('client_ip','')}</code></td>
                <td>{action_badge}</td>
                <td>{h.get('admin','')}</td>
                <td>{h.get('time','')[-19:]}</td>
            </tr>"""
        history_html = f"""
        <div class="card">
          <h3 style="color:#6c7086;margin-bottom:12px">📋 История ({len(history)})</h3>
          <table><thead><tr>
            <th>IP</th><th>Действие</th><th>Админ</th><th>Время</th>
          </tr></thead><tbody>{hist_rows}</tbody></table>
        </div>""" if hist_rows else ""

        html = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<title>DLP — Доступ в интернет</title><style>{_CSS}</style></head>
<body>{_nav("/admin/internet", user)}
<div class="container">
  <h2 style="color:#f0f6fc;margin-bottom:8px">🌐 Управление доступом в интернет</h2>
  <p style="color:#8b949e;margin-bottom:20px">
    Политика по умолчанию: {policy_badge}
    <span style="color:#6c7086;font-size:.85em;margin-left:12px">
      (изменить в config.json: internet_default_policy)</span>
  </p>

  {pending_html}
  {allowed_html}
  {grant_html}
  {history_html}
</div></body></html>"""
        self._send_html(html)

    # ══════════════════════════════════════════════════════════════════════════
    # SETTINGS PAGE
    # ══════════════════════════════════════════════════════════════════════════

    def _serve_settings(self, user: str):
        s = _DLP_SETTINGS
        qs = parse_qs(urlparse(self.path).query)
        saved = qs.get("saved", [""])[0]
        alert = ""
        if saved == "1":
            alert = '<div class="alert alert-ok">✅ Настройки сохранены</div>'

        # Theme radio
        theme = s.get("theme", "dark")
        theme_html = "".join(
            f'<label style="margin-right:16px;cursor:pointer">'
            f'<input type="radio" name="theme" value="{t}" '
            f'{"checked" if theme == t else ""}> {label}</label>'
            for t, label in [("dark", "🌙 Тёмная"), ("light", "☀️ Светлая")]
        )

        # DLP rules checkboxes
        rules_info = {
            "DSP_PHRASE":    ("Гриф ДСП", "«Для служебного пользования», «совершенно секретно»"),
            "PASSPORT_FULL": ("Паспорт РФ", "Серия + номер с контекстом"),
            "SNILS":         ("СНИЛС", "Формат XXX-XXX-XXX XX"),
            "INN_CTX":       ("ИНН (с маркером)", "Слово «ИНН» + 10/12 цифр"),
            "INN_BARE":      ("ИНН (число)", "10/12 цифр с контр. суммой + контекст"),
            "CARD":          ("Банковская карта", "16 цифр, проверка Luhn"),
            "PHONE":         ("Телефон РФ", "+7/8 (XXX) XXX-XX-XX"),
            "EMAIL":         ("Email", "user@domain.com"),
            "FULL_NAME":     ("ФИО", "Три слова с заглавной буквы"),
            "ADDRESS":       ("Почтовый адрес", "ул./пр./пер. + дом"),
            "BANK_ACCOUNT":  ("Банковский счёт", "20 цифр + контекст"),
            "BIRTH_DATE":    ("Дата рождения", "ДД.ММ.ГГГГ с маркером"),
        }
        enabled = s.get("rules_enabled", {})
        rules_html = ""
        for rule_id, (name, desc) in rules_info.items():
            checked = "checked" if enabled.get(rule_id, True) else ""
            rules_html += (
                f'<div style="display:flex;align-items:center;gap:10px;'
                f'padding:8px 12px;border-bottom:1px solid #21262d">'
                f'<input type="checkbox" name="rule_{rule_id}" {checked} '
                f'style="width:18px;height:18px">'
                f'<div><strong style="color:#c9d1d9">{name}</strong>'
                f'<div style="color:#6c7086;font-size:.82em">{desc}</div></div>'
                f'</div>'
            )

        # Access request settings
        auto_req = s.get("auto_access_request", False)
        default_msg = s.get("access_request_message", "")

        html = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<title>DLP — Настройки</title><style>{_CSS}</style></head>
<body>{_nav("/admin/settings", user)}
<div class="container">
  <h2 style="color:#f0f6fc;margin-bottom:20px">⚙️ Настройки</h2>
  {alert}
  <form method="POST" action="/admin/settings/save">

  <div class="card" style="margin-bottom:16px">
    <h3 style="color:#89b4fa;margin-bottom:12px">🎨 Оформление</h3>
    <div style="padding:8px 0">{theme_html}</div>
  </div>

  <div class="card" style="margin-bottom:16px">
    <h3 style="color:#89b4fa;margin-bottom:12px">🛡 Правила DLP</h3>
    <p style="color:#8b949e;font-size:.88em;margin-bottom:12px">
      Выберите какие типы данных система будет обнаруживать и блокировать.
      Порог блокировки: score ≥ <strong>{s.get('score_threshold', 80)}</strong>.
    </p>
    <div style="margin-bottom:12px">
      <label>Порог score:
        <input type="number" name="score_threshold" value="{s.get('score_threshold', 80)}"
               min="10" max="500" style="width:80px;margin-left:8px">
      </label>
    </div>
    <div style="border:1px solid #21262d;border-radius:8px;overflow:hidden">
      {rules_html}
    </div>
  </div>

  <div class="card" style="margin-bottom:16px">
    <h3 style="color:#89b4fa;margin-bottom:12px">🔑 Взаимодействие с сотрудником</h3>
    <div style="padding:8px 0">
      <label style="display:flex;align-items:center;gap:10px;margin-bottom:12px">
        <input type="checkbox" name="auto_access_request" {"checked" if auto_req else ""}
               style="width:18px;height:18px">
        <div>
          <strong style="color:#c9d1d9">Автоматически запрашивать доступ к файлу</strong>
          <div style="color:#6c7086;font-size:.82em">
            При блокировке сразу отправлять сотруднику запрос на просмотр содержимого
          </div>
        </div>
      </label>
      <div style="margin-top:8px">
        <label style="color:#8b949e;font-size:.88em">Текст запроса по умолчанию:</label>
        <textarea name="access_request_message" rows="3"
                  style="width:100%;margin-top:6px;background:#161b22;border:1px solid #30363d;
                         border-radius:8px;padding:10px;color:#c9d1d9;font-size:13px;
                         resize:vertical">{default_msg}</textarea>
      </div>
    </div>
  </div>

  <button type="submit" class="btn btn-primary" style="font-size:14px;padding:12px 32px">
    💾 Сохранить настройки</button>
  </form>
</div></body></html>"""
        self._send_html(html)

    def _handle_settings_save(self, user: str):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else ""
        params = parse_qs(body)

        _DLP_SETTINGS["theme"] = params.get("theme", ["dark"])[0]
        try:
            _DLP_SETTINGS["score_threshold"] = int(params.get("score_threshold", ["80"])[0])
        except ValueError:
            pass
        _DLP_SETTINGS["auto_access_request"] = "auto_access_request" in params

        msg = params.get("access_request_message", [""])[0]
        if msg:
            _DLP_SETTINGS["access_request_message"] = msg

        # Update rules
        for rule_id in _DLP_SETTINGS.get("rules_enabled", {}):
            _DLP_SETTINGS["rules_enabled"][rule_id] = f"rule_{rule_id}" in params

        _save_settings()
        logger.info(f"[Settings] Saved by {user}")
        self._redirect("/admin/settings?saved=1")

    # ══════════════════════════════════════════════════════════════════════════

    def _serve_capture(self, filename: str):
        filename = Path(filename).name
        fpath    = CAPTURES_DIR / filename
        if not fpath.exists():
            self.send_response(404); self.end_headers()
            self.wfile.write(b"Not found"); return
        data = fpath.read_bytes()

        # Try to find original filename from events
        original_name = filename
        try:
            events, _ = self._load_events()
            for e in events:
                if e.get("capture") == filename and e.get("filename"):
                    original_name = e["filename"]
                    break
        except Exception:
            pass

        ext = Path(original_name).suffix.lower()
        mime_map = {
            ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
            ".doc": "application/msword", ".xls": "application/vnd.ms-excel",
            ".pdf": "application/pdf", ".txt": "text/plain; charset=utf-8",
            ".csv": "text/csv; charset=utf-8", ".json": "application/json",
            ".xml": "text/xml", ".html": "text/html",
            ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
            ".gif": "image/gif", ".exe": "application/x-msdownload",
        }
        ctype = mime_map.get(ext, mimetypes.guess_type(original_name)[0] or "application/octet-stream")

        inline_exts = {".txt",".json",".xml",".html",".csv",".pdf",
                       ".jpg",".jpeg",".png",".gif",".webp"}
        if ext in inline_exts:
            disp = "inline"
        else:
            # RFC 5987 encoding for non-ASCII filenames
            from urllib.parse import quote
            safe_name = quote(original_name, safe='')
            disp = f"attachment; filename*=UTF-8''{safe_name}"

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", disp)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    _LIGHT_CSS = """<style>
body,html{background:#f6f8fa!important;color:#1f2328!important}
.nav{background:#fff!important;border-bottom:1px solid #d1d9e0!important}
.nav a{color:#656d76!important}
.nav a.active,.nav a:hover{color:#0969da!important;background:#ddf4ff!important}
.logo{color:#0969da!important}
.container{background:#f6f8fa!important}
.card{background:#fff!important;border-color:#d1d9e0!important}
.stats{background:#fff!important;border-color:#d1d9e0!important}
.stat .v{color:#1f2328!important}
.stat .l{color:#656d76!important}
table{background:#fff!important}
thead{background:#f6f8fa!important}
th{color:#1f2328!important;border-color:#d1d9e0!important}
td{border-color:#d1d9e0!important;color:#1f2328!important}
tr:hover{background:#f6f8fa!important}
pre{background:#f6f8fa!important;border-color:#d1d9e0!important;color:#1f2328!important}
code{color:#0550ae!important}
input,textarea,select{background:#fff!important;border-color:#d1d9e0!important;color:#1f2328!important}
.badge{border-color:#d1d9e0!important}
.alert-ok{background:#dafbe1!important;color:#1a7f37!important;border-color:#aceebb!important}
.alert-err{background:#ffebe9!important;color:#d1242f!important;border-color:#ffcecb!important}
a{color:#0969da!important}
</style>"""

    def _send_html(self, html: str):
        if _DLP_SETTINGS.get("theme") == "light":
            html = html.replace("</head>", self._LIGHT_CSS + "</head>", 1)
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header("Location", location)
        self.end_headers()

    def _load_events(self) -> tuple[list, dict]:
        events = []; stats = {"total":0,"blocked":0,"uploads":0,"passed":0}
        try:
            if EVENTS_FILE.exists():
                # Read with timeout protection — don't hang if file is locked
                raw = EVENTS_FILE.read_text(encoding="utf-8")
                d = json.loads(raw)
                events = d.get("events", [])
                stats  = d.get("stats", stats)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            # File is being written — use empty data, will refresh in 5 sec
            logger.debug(f"[Events] JSON parse error (file being written?): {e}")
        except Exception as e:
            logger.warning(f"[Events] {e}")
        return events, stats

    def _get_all_clients(self) -> list[str]:
        with _traffic_lock:
            result = set(_proxy_clients)
        try:
            if EVENTS_FILE.exists():
                raw = EVENTS_FILE.read_text(encoding="utf-8")
                d = json.loads(raw)
                for ip in d.get("activity", {}).keys():
                    result.add(ip)
                for ip in d.get("bandwidth", {}).keys():
                    result.add(ip)
                for e in d.get("events", []):
                    cip = e.get("client", "")
                    if cip and cip != "?":
                        result.add(cip)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass  # File being written — will retry on next refresh
        except Exception:
            pass
        return sorted(result)


# ── ProxyServer ───────────────────────────────────────────────────────────────
class ProxyServer:
    def __init__(self, proxy_port, proxy_host, upstream, addon_path,
                 server_ip: str = "", cert_port: int = 8000):
        self.proxy_port = proxy_port
        self.proxy_host = proxy_host
        self.upstream   = upstream
        self.addon_path = addon_path
        self.server_ip  = server_ip
        self.cert_port  = cert_port
        self.process: subprocess.Popen | None = None

    def start(self) -> bool:
        logger.info(f"[ProxyServer] Запуск на {self.proxy_host}:{self.proxy_port}...")
        cmd = [
            "mitmdump",
            "-s", str(self.addon_path),
            "--listen-host", self.proxy_host,
            "--listen-port", str(self.proxy_port),
            "--set", "termlog_verbosity=info",
            "--ssl-insecure",
        ]

        # ── ignore-hosts зависит от политики интернета ────────────────────────
        # В закрытой сети (block) — НЕ игнорируем внешние сайты,
        # чтобы аддон мог заблокировать интернет-трафик.
        # В открытой сети (allow) — игнорируем как раньше (для стабильности).
        internet_policy = _CFG.get("internet_default_policy", "block")

        if internet_policy == "allow":
            # Открытая сеть — игнорируем проблемные сайты как раньше
            logger.info("[ProxyServer] Политика: ALLOW — используем полный ignore-hosts")
            for pattern in IGNORE_HOSTS_REGEX:
                cmd += ["--ignore-hosts", pattern]
        else:
            # Закрытая сеть — НЕ игнорируем внешние сайты!
            # Аддон увидит ВСЕ запросы и заблокирует интернет.
            # Игнорируем только то, что реально ломается без passthrough.
            logger.info("[ProxyServer] Политика: BLOCK — минимальный ignore-hosts")
            _MINIMAL_IGNORE = [
                # Windows Update и CRL (без них ОС зависает)
                r".*\.windowsupdate\.com",
                r"ctldl\.windowsupdate\.com",
                r".*\.msftconnecttest\.com",
                # Certificate revocation (OCSP)
                r".*\.digicert\.com",
                r"ocsp\.digicert\.com",
                r".*\.globalsign\.com",
                r".*\.verisign\.com",
                r"crl\.microsoft\.com",
            ]
            for pattern in _MINIMAL_IGNORE:
                cmd += ["--ignore-hosts", pattern]

        # Bypass для IP сервера:
        # - HTTP (port 8000 cert page, 9090 test server): mitmproxy всё равно
        #   пропускает HTTP через аддон — DLP-анализ работает для HTTP.
        # - HTTPS: ignore-hosts пропускает TLS напрямую, без MITM.
        #   Это нужно чтобы cert page была доступна до установки сертификата.
        if self.server_ip:
            _escaped_host = self.server_ip.replace(".", "\\.")
            cmd += ["--ignore-hosts", _escaped_host]

        if self.upstream:
            cmd += ["--mode", f"upstream:{self.upstream}"]
            logger.info(f"[ProxyServer] Upstream: {self.upstream}")

        logger.info(f"[ProxyServer] CMD: {' '.join(cmd)}")
        try:
            self.process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
            )
            logger.info(f"[ProxyServer] PID={self.process.pid}")
            threading.Thread(target=self._read_logs, daemon=True).start()
            return True
        except FileNotFoundError:
            logger.error("[ProxyServer] mitmdump не найден!")
            return False
        except Exception as e:
            logger.error(f"[ProxyServer] Ошибка: {e}")
            return False

    def _read_logs(self):
        import re
        req_re   = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+:\s+\w+\s+(https?://\S+)')
        block_re = re.compile(r'ЗАБЛОКИРОВАН|БЛОКИРОВКА')
        pending  = None
        for raw in self.process.stdout:
            line = raw.strip()
            if not line: continue
            logger.info(f"[mitmproxy] {line}")
            if block_re.search(line):
                if pending:
                    record_traffic(pending["ip"], pending["url"], blocked=True)
                    pending = None
                continue
            m = req_re.search(line)
            if m:
                ip, url = m.group(1), m.group(2)
                if ip == "127.0.0.1": continue
                if pending:
                    record_traffic(pending["ip"], pending["url"], blocked=False)
                pending = {"ip": ip, "url": url}
        if pending:
            record_traffic(pending["ip"], pending["url"], blocked=False)
        logger.info("[ProxyServer] поток завершён")

    def stop(self):
        if self.process:
            logger.info(f"[ProxyServer] Остановка PID={self.process.pid}...")
            self.process.terminate()
            try: self.process.wait(timeout=5)
            except subprocess.TimeoutExpired: self.process.kill()
            logger.info("[ProxyServer] Остановлен")

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None


# ── main ──────────────────────────────────────────────────────────────────────
def _open_firewall_ports(cert_port, proxy_port):
    """Open Windows Firewall ports so clients can reach the cert/admin server."""
    import subprocess
    rules = [
        ("DLP Proxy Cert Server port " + str(cert_port), cert_port),
        ("DLP Proxy port " + str(proxy_port), proxy_port),
    ]
    for rule_name, port in rules:
        try:
            check = subprocess.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 "name=" + rule_name],
                capture_output=True, text=True, timeout=5
            )
            if "No rules match" in check.stdout or check.returncode != 0:
                result = subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     "name=" + rule_name,
                     "dir=in", "action=allow", "protocol=TCP",
                     "localport=" + str(port),
                     "profile=any"],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0:
                    logger.info("[Firewall] Открыт порт " + str(port))
                else:
                    logger.warning(
                        "[Firewall] Не удалось открыть порт " + str(port) +
                        " (нужны права администратора). Откройте вручную:\n" +
                        "  netsh advfirewall firewall add rule name=\"DLP\" " +
                        "dir=in action=allow protocol=TCP localport=" + str(port)
                    )
            else:
                logger.info("[Firewall] Порт " + str(port) + " уже разрешён")
        except Exception as e:
            logger.warning("[Firewall] Ошибка: " + str(e))


def main():
    global _CFG, CERT_PORT

    logger.info("=" * 65)
    logger.info("  DLP Proxy Server v3.0")
    logger.info("=" * 65)

    _CFG      = load_config()
    CERT_PORT = _CFG["cert_port"]

    cert_port  = _CFG["cert_port"]
    proxy_port = _CFG["proxy_port"]
    proxy_host = _CFG["proxy_host"]
    upstream   = _CFG.get("upstream_proxy") or ""

    server_ip  = get_local_ip()
    logger.info(f"[Main] IP={server_ip} proxy={proxy_port} cert={cert_port}")

    logger.info("[Main] Шаг 0: Проверка прокси...")
    check_proxy_loop(server_ip, proxy_port, upstream)
    fix_proxy_bypass(server_ip, proxy_port)

    # ── Auto-detect upstream (VPN) availability ──────────────────────────────
    actual_upstream = ""
    if upstream:
        if _check_upstream_available(upstream):
            actual_upstream = upstream
            logger.info(f"[Main] ✓ VPN upstream доступен: {upstream}")
        else:
            logger.warning(
                f"[Main] ⚠ VPN upstream НЕДОСТУПЕН: {upstream}\n"
                f"  → Запуск в ПРЯМОМ режиме (без VPN).\n"
                f"  → Когда VPN появится — перезапустите сервер."
            )
    else:
        logger.info("[Main] Upstream не настроен — прямой режим")

    logger.info("[Main] Шаг 1: Сертификаты...")
    generate_ca_certificate()

    logger.info("[Main] Шаг 2: Запуск DLP прокси...")
    addon_path = Path(__file__).parent / "dlp_addon.py"
    proxy      = ProxyServer(proxy_port, proxy_host, actual_upstream, addon_path, server_ip=server_ip, cert_port=cert_port)
    proxy_ok   = proxy.start()

    logger.info("[Main] Шаг 2.5: Открываю порты в Windows Firewall...")
    _open_firewall_ports(cert_port, proxy_port)

    logger.info(f"[Main] Шаг 3: Веб-сервер порт {cert_port}...")
    CertDistributionHandler.server_ip     = server_ip
    CertDistributionHandler.proxy_port    = proxy_port
    CertDistributionHandler.upstream_proxy = actual_upstream
    cert_server = ThreadingHTTPServer(("0.0.0.0", cert_port), CertDistributionHandler)
    threading.Thread(target=cert_server.serve_forever, daemon=True).start()

    # Print credentials
    admins = _get_admins()
    mode_str = f"upstream → {actual_upstream}" if actual_upstream else "ПРЯМОЙ (без VPN)"
    logger.info("=" * 65)
    logger.info(f"  Сертификаты : http://{server_ip}:{cert_port}")
    logger.info(f"  DLP Прокси  : {server_ip}:{proxy_port}")
    logger.info(f"  Режим       : {mode_str}")
    logger.info(f"  Панель адм. : http://{server_ip}:{cert_port}/admin/")
    logger.info(f"  Логин       : {admins[0]['user']} / {admins[0]['password']}")
    if len(admins) > 1:
        logger.info(f"  Доп. админы : {', '.join(a['user'] for a in admins[1:])}")
    logger.info("=" * 65)

    # ── Auto-open admin panel in browser ─────────────────────────────────────
    if _CFG.get("open_browser", True):
        url = f"http://{server_ip}:{cert_port}/admin/"
        logger.info(f"[Main] Открываю панель администратора: {url}")
        def _open():
            time.sleep(2)  # wait for server to be ready
            try:
                webbrowser.open(url)
            except Exception as e:
                logger.warning(f"[Main] Не удалось открыть браузер: {e}")
        threading.Thread(target=_open, daemon=True).start()

    def shutdown(sig, frame):
        logger.info("[Main] Остановка...")
        proxy.stop()
        cert_server.shutdown()
        logger.info("[Main] Остановлен.")
        sys.exit(0)

    signal.signal(signal.SIGINT,  shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    logger.info("[Main] Работаю. Ctrl+C для остановки.")

    # Web server (cert/admin) always stays up even if proxy crashes
    # Proxy gets unlimited restarts with exponential backoff
    crash_count = 0
    last_crash  = 0.0
    RESET_WINDOW = 120  # reset crash counter after 2 min stable

    logger.info("[Main] Мониторинг запущен. Веб-сервер работает независимо от прокси.")

    while True:
        time.sleep(3)
        if not proxy_ok:
            # Proxy failed to start initially — retry every 30 sec
            if time.time() - last_crash > 30:
                logger.info("[Main] Повторная попытка запуска mitmproxy...")
                proxy_ok = proxy.start()
                last_crash = time.time()
            continue

        if proxy.is_running():
            # Reset crash counter after stable period
            if crash_count > 0 and (time.time() - last_crash) > RESET_WINDOW:
                logger.info("[Main] mitmproxy стабилен, сброс счётчика")
                crash_count = 0
            continue

        # Proxy crashed — restart with backoff
        crash_count += 1
        last_crash   = time.time()
        # Delay: 5s, 10s, 20s, 30s, 60s max
        delay = min(5 * (2 ** min(crash_count - 1, 3)), 60)
        logger.warning(
            f"[Main] mitmproxy упал (#{crash_count}). "
            f"Перезапуск через {delay}с... "
            f"(Веб-сервер и панель администратора продолжают работать)"
        )
        time.sleep(delay)
        proxy.start()


if __name__ == "__main__":
    main()