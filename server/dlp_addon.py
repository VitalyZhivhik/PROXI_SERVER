"""
DLP Proxy Addon for mitmproxy v6.0

Changes v6.0:
  - DLP blocking DISABLED (monitor-only mode) — all uploads pass through
  - Files saved with original names (URL-safe)
  - detect_filetype: filename extension has priority over magic bytes
  - DOCX/XLSX correctly detected (not as binary/zip)
  - Fixed Cyrillic filenames in captures
"""

import sys
import json
import time
import hashlib
import threading
import re
import mimetypes
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, unquote_plus

sys.path.insert(0, str(Path(__file__).parent.parent))

from shared.dlp_rules import DLPEngine, SKIP_CONTENT_TYPES
from shared.log_config import setup_logging
from shared.internet_access import (
    is_local_host, client_has_internet_access,
)
from mitmproxy import http

logger = setup_logging("proxy", log_dir="logs")

# ── Load config for internet policy ─────────────────────────────────────────
_ADDON_CFG = {}
try:
    _cfg_path = Path(__file__).parent.parent / "config.json"
    if _cfg_path.exists():
        _ADDON_CFG = json.loads(_cfg_path.read_text(encoding="utf-8"))
except Exception:
    pass

_INTERNET_POLICY = _ADDON_CFG.get("internet_default_policy", "block")
_LOCAL_RANGES    = _ADDON_CFG.get("local_network_ranges", [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16",
])
_LOCAL_DOMAINS   = _ADDON_CFG.get("local_domains", [])
_SERVER_IP       = ""  # set in DLPAddon.__init__

EVENTS_FILE    = Path(__file__).parent.parent / "logs" / "dlp_events.json"
CAPTURES_DIR   = Path(__file__).parent.parent / "logs" / "captures"
ACTIVITY_DIR   = Path(__file__).parent.parent / "logs" / "activity"
TRANSPARENCY_FILE = Path(__file__).parent.parent / "logs" / "transparency.json"

# ── SEPARATE files to avoid race conditions with server process ──────────────
INCIDENTS_FILE     = Path(__file__).parent.parent / "logs" / "incidents.json"
NOTIFICATIONS_FILE = Path(__file__).parent.parent / "logs" / "client_notifications.json"

_tp_lock = threading.Lock()

def _create_incident_and_notify(event_id: str, client_ip: str, filename: str,
                                 host: str, url: str, filetype: str,
                                 filesize: int, rules: list[str],
                                 matches: list[dict], score: int,
                                 capture: str = ""):
    """Write incident and notification to SEPARATE files.
    Never touches transparency.json (server writes there for chat).
    This eliminates the race condition that erased incidents."""
    now = datetime.now().isoformat(timespec="seconds")
    quotes = [m.get("sample", "")[:60] for m in matches if m.get("sample")]
    rules_desc = "; ".join(
        f"{m.get('rule','')}: {m.get('description','')}" for m in matches[:3]
    )
    incident = {
        "id": event_id, "time": now,
        "client_ip": client_ip, "filename": filename,
        "host": host, "url": url[:200],
        "filetype": filetype, "filesize": filesize,
        "rules": rules, "score": score, "capture": capture,
        "status": "new", "access_status": "locked", "admin_notes": "",
        "matches": [{"rule": m.get("rule",""), "description": m.get("description",""),
                      "severity": m.get("severity",""), "sample": m.get("sample","")[:60],
                      "score": m.get("score", 0)} for m in matches[:10]],
    }
    block_notif = {
        "id": f"n_blk_{event_id}",
        "type": "blocked",
        "text": (f"🚫 Файл «{filename}» заблокирован системой DLP.\n"
                 f"Причина: {rules_desc}\n"
                 f"{'Обнаружено: ' + ', '.join(f'«{q}»' for q in quotes[:5]) if quotes else ''}"),
        "time": now, "read": False,
        "details": {
            "incident_id": event_id, "filename": filename,
            "rules": rules, "score": score,
            "quotes": quotes[:5], "reason": rules_desc,
        },
    }
    with _tp_lock:
        try:
            # ── Write incident to incidents.json ─────────────────────────────
            inc_list = []
            if INCIDENTS_FILE.exists():
                try:
                    inc_list = json.loads(INCIDENTS_FILE.read_text(encoding="utf-8"))
                except Exception:
                    inc_list = []
            inc_list.append(incident)
            inc_list = inc_list[-500:]
            INCIDENTS_FILE.write_text(
                json.dumps(inc_list, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8"
            )
            # ── Write notification to client_notifications.json ──────────────
            notifs = {}
            if NOTIFICATIONS_FILE.exists():
                try:
                    notifs = json.loads(NOTIFICATIONS_FILE.read_text(encoding="utf-8"))
                except Exception:
                    notifs = {}
            notifs.setdefault(client_ip, []).append(block_notif)

            # Auto-access-request if enabled
            try:
                settings_file = Path(__file__).parent.parent / "logs" / "dlp_settings.json"
                if settings_file.exists():
                    settings = json.loads(settings_file.read_text(encoding="utf-8"))
                    if settings.get("auto_access_request"):
                        msg_text = settings.get("access_request_message",
                            "Администратор запрашивает разрешение на просмотр.")
                        # Update incident access status
                        for inc in inc_list:
                            if inc["id"] == event_id:
                                inc["access_status"] = "requested"
                                break
                        INCIDENTS_FILE.write_text(
                            json.dumps(inc_list, ensure_ascii=False, indent=2, default=str),
                            encoding="utf-8"
                        )
                        # Add access request notification
                        access_notif = {
                            "id": f"n_ar_{event_id}",
                            "type": "access_request",
                            "text": f"🔑 {msg_text}\nФайл: «{filename}»\n\nПричина блокировки: {rules_desc}",
                            "time": now, "read": False,
                            "details": {
                                "incident_id": event_id, "filename": filename,
                                "admin": "system (авто)", "message": msg_text,
                                "reason": rules_desc, "quotes": quotes[:5],
                            },
                        }
                        notifs[client_ip].append(access_notif)
                        logger.info(f"[AutoAccess] Request sent for #{event_id}")
            except Exception:
                pass

            notifs[client_ip] = notifs[client_ip][-100:]
            NOTIFICATIONS_FILE.write_text(
                json.dumps(notifs, ensure_ascii=False, indent=2, default=str),
                encoding="utf-8"
            )
            logger.info(f"[Incident] #{event_id} | {client_ip} | {filename} | score={score}")
        except Exception as e:
            logger.error(f"[Incident] Write error: {e}")
        except Exception as e:
            logger.error(f"[Incident] Write error: {e}")
CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
ACTIVITY_DIR.mkdir(parents=True, exist_ok=True)

# ══════════════════════════════════════════════════════════════════════════════
# DLP BLOCKING: True = block uploads with DLP matches (score >= threshold)
# ══════════════════════════════════════════════════════════════════════════════
DLP_BLOCKING_ENABLED = True

_events_lock  = threading.Lock()
_events: list[dict] = []
_stats = {"total": 0, "blocked": 0, "uploads": 0, "downloads": 0, "passed": 0}

# ── Client last-seen tracking ────────────────────────────────────────────────
_client_last_seen: dict[str, float] = {}  # ip -> timestamp

# ── Per-client activity store ─────────────────────────────────────────────────
# {ip: [{"time","method","url","host","status","size","type"}]}
_activity_lock  = threading.Lock()
_activity: dict[str, list] = {}
MAX_ACTIVITY_PER_CLIENT = 500

# ── Bandwidth ─────────────────────────────────────────────────────────────────
_bw_lock   = threading.Lock()
_bandwidth: dict[str, dict] = {}
BW_WINDOW  = 5.0


def _update_bw(ip: str, out: int = 0, inp: int = 0):
    now = time.time()
    with _bw_lock:
        if ip not in _bandwidth:
            _bandwidth[ip] = {
                "bytes_out": 0, "bytes_in": 0,
                "window_out": 0, "window_in": 0,
                "window_start": now,
                "speed_out": 0.0, "speed_in": 0.0,
                "total_out": 0, "total_in": 0,
                "requests": 0,
            }
        d = _bandwidth[ip]
        d["bytes_out"]  += out;  d["bytes_in"]   += inp
        d["window_out"] += out;  d["window_in"]  += inp
        d["total_out"]  += out;  d["total_in"]   += inp
        d["requests"]   += 1
        elapsed = now - d["window_start"]
        if elapsed >= BW_WINDOW:
            d["speed_out"]    = d["window_out"] / elapsed
            d["speed_in"]     = d["window_in"]  / elapsed
            d["window_out"]   = 0; d["window_in"] = 0
            d["window_start"] = now


def _record_activity(ip: str, method: str, url: str, host: str,
                     status: str, size: int = 0, ftype: str = ""):
    """Record a request in per-client activity log"""
    entry = {
        "time":   datetime.now().strftime("%H:%M:%S"),
        "method": method,
        "url":    url[:200],
        "host":   host,
        "status": status,  # "ok", "blocked", "upload", "download"
        "size":   size,
        "type":   ftype,
    }
    with _activity_lock:
        if ip not in _activity:
            _activity[ip] = []
        _activity[ip].append(entry)
        if len(_activity[ip]) > MAX_ACTIVITY_PER_CLIENT:
            _activity[ip].pop(0)
        # Save activity to per-client file
        _save_activity(ip)


def _save_activity(ip: str):
    try:
        fname = ACTIVITY_DIR / f"client_{ip.replace('.', '_')}.json"
        fname.write_text(
            json.dumps({"ip": ip, "activity": _activity.get(ip, [])},
                       ensure_ascii=False, indent=2, default=str),
            encoding="utf-8"
        )
    except Exception as e:
        logger.debug(f"[Activity] Save error {ip}: {e}")


def get_all_activity() -> dict:
    with _activity_lock:
        return {ip: list(acts) for ip, acts in _activity.items()}


def get_bandwidth_stats() -> dict:
    with _bw_lock:
        return {ip: dict(d) for ip, d in _bandwidth.items()}


def _save_events():
    try:
        EVENTS_FILE.write_text(
            json.dumps(
                {"stats": _stats, "events": _events[-500:],
                 "bandwidth": get_bandwidth_stats(),
                 "activity": get_all_activity(),
                 "client_last_seen": dict(_client_last_seen)},
                ensure_ascii=False, indent=2, default=str
            ),
            encoding="utf-8"
        )
    except Exception as e:
        logger.debug(f"[Events] Save error: {e}")


def _add_event(event: dict):
    with _events_lock:
        _events.append(event)
        if len(_events) > 500:
            _events.pop(0)
        _save_events()


# ── File type detection ───────────────────────────────────────────────────────
CT_TYPE_MAP = [
    ("application/pdf",                                               ("pdf",  "pdf")),
    ("application/msword",                                            ("doc",  "doc")),
    ("application/vnd.openxmlformats-officedocument.wordprocessingml",("docx", "docx")),
    ("application/vnd.ms-excel",                                      ("xls",  "xls")),
    ("application/vnd.openxmlformats-officedocument.spreadsheetml",   ("xlsx", "xlsx")),
    ("application/vnd.ms-powerpoint",                                 ("ppt",  "ppt")),
    ("application/vnd.openxmlformats-officedocument.presentationml",  ("pptx", "pptx")),
    ("application/zip",                                               ("zip",  "zip")),
    ("application/x-zip",                                             ("zip",  "zip")),
    ("application/x-rar",                                             ("rar",  "rar")),
    ("application/x-7z-compressed",                                   ("7z",   "7z")),
    ("application/json",                                              ("json", "json")),
    ("application/xml",                                               ("xml",  "xml")),
    ("text/xml",                                                      ("xml",  "xml")),
    ("text/csv",                                                      ("csv",  "csv")),
    ("text/plain",                                                    ("txt",  "txt")),
    ("text/html",                                                     ("html", "html")),
    ("image/jpeg",                                                    ("jpeg", "jpg")),
    ("image/png",                                                     ("png",  "png")),
    ("image/",                                                        ("image","bin")),
    ("audio/",                                                        ("audio","bin")),
    ("video/",                                                        ("video","bin")),
    ("multipart/form-data",                                           ("form", "bin")),
    ("application/x-www-form-urlencoded",                             ("form", "txt")),
    ("application/octet-stream",                                      ("binary","bin")),
]

MAGIC = [
    (b"\x25\x50\x44\x46", "pdf",  "pdf"),
    (b"\x50\x4b\x03\x04", "zip",  "zip"),
    (b"\xd0\xcf\x11\xe0", "doc",  "doc"),
    (b"\xff\xd8\xff",     "jpeg", "jpg"),
    (b"\x89PNG",          "png",  "png"),
    (b"GIF8",             "gif",  "gif"),
    (b"\x1f\x8b",         "gzip", "gz"),
    (b"Rar!\x1a\x07",     "rar",  "rar"),
    (b"7z\xbc\xaf",       "7z",   "7z"),
    (b"MZ",               "exe",  "exe"),
]


def detect_filetype(data: bytes | None, ct: str, fname: str = "") -> tuple[str, str]:
    """Returns (type_label, extension).
    Priority: 1) filename ext  2) content-type  3) magic bytes + zipfile"""
    # ── 1. Filename extension — most reliable ─────────────────────────────
    if fname:
        fext = Path(fname).suffix.lstrip(".").lower()
        ext_map = {
            "pdf":"pdf","doc":"doc","docx":"docx","xls":"xls","xlsx":"xlsx",
            "ppt":"ppt","pptx":"pptx","txt":"txt","csv":"csv","xml":"xml",
            "json":"json","zip":"zip","rar":"rar","7z":"7z",
            "jpg":"jpeg","jpeg":"jpeg","png":"png","gif":"gif",
            "mp4":"video","avi":"video","mp3":"audio",
            "exe":"exe","msi":"msi","dmg":"dmg","deb":"deb",
        }
        if fext in ext_map:
            return ext_map[fext], fext
    # ── 2. Content-Type header ────────────────────────────────────────────
    ct_clean = (ct or "").split(";")[0].strip().lower()
    for prefix, (label, ext) in CT_TYPE_MAP:
        if ct_clean.startswith(prefix):
            return label, ext
    # ── 3. Magic bytes ────────────────────────────────────────────────────
    if data and len(data) >= 4:
        for magic, label, ext in MAGIC:
            if data[:len(magic)] == magic:
                if label == "zip":
                    try:
                        import zipfile, io
                        with zipfile.ZipFile(io.BytesIO(data)) as zf:
                            names = zf.namelist()
                            if any("word/" in n for n in names): return "docx", "docx"
                            if any("xl/" in n for n in names):   return "xlsx", "xlsx"
                            if any("ppt/" in n for n in names):  return "pptx", "pptx"
                    except Exception:
                        pass
                return label, ext
    return "binary", "bin"


# ── Text extraction from Office files ────────────────────────────────────────

def _extract_text_from_docx(data: bytes) -> str:
    """Extract plain text from DOCX (ZIP with word/document.xml)"""
    try:
        import zipfile
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            # Try word/document.xml
            names = zf.namelist()
            text_parts = []
            for name in names:
                if name.endswith(".xml") and any(k in name for k in
                        ["word/document", "word/header", "word/footer",
                         "xl/shared", "xl/worksheets", "ppt/slides"]):
                    xml = zf.read(name).decode("utf-8", errors="replace")
                    # Strip XML tags, keep text
                    clean = re.sub(r'<[^>]+>', ' ', xml)
                    clean = re.sub(r'\s+', ' ', clean).strip()
                    text_parts.append(clean)
            return "\n".join(text_parts)
    except Exception as e:
        logger.debug(f"[DOCX] Extract error: {e}")
        return ""


def _extract_text_from_xlsx(data: bytes) -> str:
    """Extract plain text from XLSX"""
    try:
        import zipfile
        import io
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            text_parts = []
            # shared strings
            if "xl/sharedStrings.xml" in zf.namelist():
                xml = zf.read("xl/sharedStrings.xml").decode("utf-8", errors="replace")
                texts = re.findall(r'<t[^>]*>([^<]+)</t>', xml)
                text_parts.extend(texts)
            # worksheets
            for name in zf.namelist():
                if name.startswith("xl/worksheets/") and name.endswith(".xml"):
                    xml = zf.read(name).decode("utf-8", errors="replace")
                    values = re.findall(r'<v>([^<]+)</v>', xml)
                    text_parts.extend(values)
            return "\n".join(text_parts)
    except Exception as e:
        logger.debug(f"[XLSX] Extract error: {e}")
        return ""


def _get_body_text(data: bytes, ct: str, ftype: str) -> str:
    """Get analyzable text from request body based on file type"""
    if not data:
        return ""
    ct_lower = ct.lower()

    # Skip pure binary types with no text
    if any(ct_lower.startswith(s) for s in
           ("image/", "audio/", "video/", "font/")):
        return ""

    # DOCX — extract XML text
    if ftype in ("docx", "doc") or "wordprocessingml" in ct_lower:
        extracted = _extract_text_from_docx(data)
        if extracted:
            logger.debug(f"[DLP] DOCX text extracted: {len(extracted)} chars")
            return extracted

    # XLSX — extract cell values
    if ftype in ("xlsx", "xls") or "spreadsheetml" in ct_lower:
        extracted = _extract_text_from_xlsx(data)
        if extracted:
            return extracted

    # PDF — try basic text extraction (just raw bytes for keywords)
    if ftype == "pdf":
        try:
            text = data.decode("latin-1", errors="replace")
            # Extract text between BT/ET markers
            parts = re.findall(r'\(([^)]{2,200})\)', text)
            return " ".join(parts[:200])
        except Exception:
            return ""

    # Text types — decode directly
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _extract_multipart(content: bytes, ct: str) -> tuple[bytes | None, str, str]:
    """Returns (file_bytes, filename, content_type_of_file)"""
    bm = re.search(rb'boundary=([^\s;]+)', ct.encode(), re.IGNORECASE)
    if not bm:
        return None, "", ""
    boundary = bm.group(1).strip(b'"\'')
    parts = content.split(b"--" + boundary)
    for part in parts[1:]:
        if b"filename=" not in part:
            continue
        hdr_end = part.find(b"\r\n\r\n")
        if hdr_end == -1:
            continue
        headers = part[:hdr_end].decode("utf-8", errors="replace")
        body    = part[hdr_end + 4:].rstrip(b"\r\n--")
        fname = ""
        m = re.search(r'filename\*?=["\']?([^"\';\r\n]+)', headers, re.IGNORECASE)
        if m:
            fname = m.group(1).strip().strip('"\'')
        file_ct = ""
        m2 = re.search(r'Content-Type:\s*([^\r\n]+)', headers, re.IGNORECASE)
        if m2:
            file_ct = m2.group(1).strip()
        if body:
            return body, fname, file_ct
    return None, "", ""


def _save_capture(data: bytes, event_id: str, ext: str,
                  original_name: str = "") -> str | None:
    """Save captured file. Returns capture filename (URL-safe, no Cyrillic).
    Original filename is stored in the event JSON, not in the filesystem."""
    try:
        if not data or len(data) < 10:
            return None
        # Use clean filename: eventid.ext (no Cyrillic — safe for HTTP URLs)
        if ext and ext != "bin":
            fname = f"{event_id}.{ext}"
        elif original_name:
            orig_ext = Path(original_name).suffix.lstrip(".")
            fname = f"{event_id}.{orig_ext}" if orig_ext else f"{event_id}.bin"
        else:
            fname = f"{event_id}.bin"
        fpath = CAPTURES_DIR / fname
        fpath.write_bytes(data)
        logger.info(f"[Capture] {fname} ({len(data)} байт) orig={original_name or '—'}")
        return fname
    except Exception as e:
        logger.debug(f"[Capture] Ошибка: {e}")
        return None


# ── Domains where proxy headers must be stripped ─────────────────────────────
# These domains are NOT in --ignore-hosts, so mitmproxy intercepts their TLS.
# We strip proxy-reveal headers so they don't detect they're behind a proxy.
STRIP_PROXY_HEADERS = {
    "chat.qwen.ai", "qwen.ai", "tongyi.aliyun.com",
    "claude.ai", "api.anthropic.com",
    "chat.openai.com", "api.openai.com",
    "gemini.google.com",
    "giga.chat", "gigachat.ru",
    "deepseek.com", "chat.deepseek.com", "coder.deepseek.com",
    "nicebot.ru", "chatgptspeed.ru",
}

PASSTHROUGH_UPLOAD_HOSTS = set()

PROXY_HEADERS = [
    "via", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
    "x-real-ip", "proxy-connection", "x-proxy-id", "forwarded",
    "x-bluecoat-via", "x-original-host",
]

DOWNLOAD_CONTENT_TYPES = {
    "application/pdf", "application/msword",
    "application/vnd.openxmlformats-officedocument",
    "application/vnd.ms-excel", "application/vnd.ms-powerpoint",
    "application/zip", "application/x-zip",
    "application/x-rar", "application/x-7z-compressed",
    "application/octet-stream", "text/csv",
}


def _load_persisted_state():
    """Load events and activity from previous session on startup."""
    global _events, _stats, _bandwidth, _activity
    try:
        if not EVENTS_FILE.exists():
            return
        data = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
        with _events_lock:
            _events = data.get("events", [])[-500:]
        saved_stats = data.get("stats", {})
        for k in _stats:
            if k in saved_stats:
                _stats[k] = saved_stats[k]
        saved_bw = data.get("bandwidth", {})
        with _bw_lock:
            for ip, d in saved_bw.items():
                _bandwidth[ip] = d
        saved_act = data.get("activity", {})
        with _activity_lock:
            for ip, acts in saved_act.items():
                _activity[ip] = acts[-MAX_ACTIVITY_PER_CLIENT:]
        logger.info(
            f"[DLPAddon] Загружено из предыдущей сессии: "
            f"{len(_events)} событий, {len(_activity)} клиентов"
        )
    except Exception as e:
        logger.warning(f"[DLPAddon] Не удалось загрузить предыдущее состояние: {e}")



class DLPAddon:
    def __init__(self):
        global _SERVER_IP
        try:
            cfg_path = Path(__file__).parent.parent / "config.json"
            cfg = json.loads(cfg_path.read_text(encoding="utf-8")) if cfg_path.exists() else {}
        except Exception:
            cfg = {}
        self.engine = DLPEngine(config=cfg)
        # Detect server IP for local host checking
        try:
            import socket as _sock
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            _SERVER_IP = s.getsockname()[0]
            s.close()
        except Exception:
            _SERVER_IP = "127.0.0.1"
        # Load persisted events and activity from previous session
        _load_persisted_state()
        logger.info(f"[DLPAddon] v6.0 инициализация (policy={_INTERNET_POLICY})")
        logger.info(f"[DLPAddon] Server IP={_SERVER_IP}")
        logger.info(f"[DLPAddon] Правил: {len(self.engine.rules)}")

    def request(self, flow: http.HTTPFlow) -> None:
        _stats["total"] += 1
        url       = flow.request.pretty_url
        method    = flow.request.method
        host      = flow.request.pretty_host
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "?"
        ct        = flow.request.headers.get("content-type", "")
        req_size  = len(flow.request.content) if flow.request.content else 0

        # Track client last seen
        _client_last_seen[client_ip] = time.time()

        _update_bw(client_ip, out=req_size)

        # ── Internet access check (closed network mode) ──────────────────────
        if _INTERNET_POLICY == "block":
            host_is_local = is_local_host(
                host, _LOCAL_RANGES, _LOCAL_DOMAINS, _SERVER_IP
            )
            if not host_is_local:
                # Whitelist system domains (OS updates, cert validation)
                # These must work even without internet permission
                _SYSTEM_DOMAINS = (
                    "windowsupdate.com", "ctldl.windowsupdate.com",
                    "msftconnecttest.com", "delivery.mp.microsoft.com",
                    "dl.delivery.mp.microsoft.com",
                    "microsoft.com", "edge.microsoft.com",
                    "go.microsoft.com", "crl.microsoft.com",
                    "crl2.microsoft.com", "oneocsp.microsoft.com",
                    "ocsp.digicert.com", "digicert.com",
                    "globalsign.com", "verisign.com",
                    "letsencrypt.org",
                )
                is_system = any(
                    host == d or host.endswith("." + d)
                    for d in _SYSTEM_DOMAINS
                )
                # Also whitelist raw IPs of Windows Update CDN
                if not is_system and host.replace(".", "").isdigit():
                    # Known Microsoft CDN IP ranges
                    _MS_PREFIXES = ("20.215.", "20.190.", "13.107.", "72.144.",
                                    "2.tlu.", "23.32.", "23.35.", "104.16.")
                    is_system = any(host.startswith(p) for p in _MS_PREFIXES)

                if not is_system:
                    # External host — check if client has permission
                    if not client_has_internet_access(client_ip):
                        # Determine protocol for activity log
                        proto = "HTTPS" if url.startswith("https") else "HTTP"
                        logger.info(f"[Internet] BLOCKED {client_ip} -> {host} [{proto}] (no access)")
                        _stats["blocked"] += 1
                        _record_activity(client_ip, method, url, host, "blocked",
                                         req_size, proto)
                        self._make_internet_block(flow, host, client_ip)
                        return

        # ── Blocked domain ────────────────────────────────────────────────────
        if self.engine.is_blocked_domain(host):
            logger.warning(f"[DLP] ДОМЕН ЗАБЛОКИРОВАН: {host}")
            _stats["blocked"] += 1
            _record_activity(client_ip, method, url, host, "blocked", req_size)
            self._make_403(flow, f"Домен {host} заблокирован администратором", [])
            self._add_block_event(flow, [], "Домен заблокирован", client_ip, "", "", url, None, "bin")
            return

        # ── Whitelisted ───────────────────────────────────────────────────────
        if self.engine.is_whitelisted_domain(host):
            _stats["passed"] += 1
            # Still record for activity log (brief)
            if method in ("GET", "POST"):
                _record_activity(client_ip, method, url, host, "ok", req_size)
            return

        # ── Strip proxy-reveal headers for AI services ────────────────────────
        if any(host == d or host.endswith("." + d) for d in STRIP_PROXY_HEADERS):
            for h in PROXY_HEADERS:
                if h in flow.request.headers:
                    del flow.request.headers[h]

            # ── Record file uploads (monitor only — never block AI uploads) ──
            if method.upper() in ("POST", "PUT", "PATCH") and req_size > 100:
                ct_up = flow.request.headers.get("content-type", "")
                upload_bytes = None
                upload_fname = ""
                upload_ct = ct_up

                if "multipart" in ct_up.lower() and flow.request.content:
                    file_data, fname, file_ct = _extract_multipart(
                        flow.request.content, ct_up
                    )
                    if file_data:
                        upload_bytes = file_data
                        upload_fname = fname
                        upload_ct = file_ct or ct_up

                if upload_bytes and len(upload_bytes) > 50:
                    ftype, fext = detect_filetype(
                        upload_bytes, upload_ct, upload_fname
                    )

                    # DLP analysis
                    dlp_flagged = False
                    dlp_matches = []
                    dlp_score = 0
                    try:
                        body_text = _get_body_text(upload_bytes, upload_ct, ftype)
                        if body_text:
                            block, matches = self.engine.should_block(
                                body_text, f"BODY:{host}", host=host,
                                content_type=upload_ct
                            )
                            if block:
                                dlp_flagged = True
                                dlp_matches = matches
                                dlp_score = sum(m.get("score", 0) for m in matches)
                    except Exception as e:
                        logger.debug(f"[DLP] Check error: {e}")

                    # Save captured file
                    event_id = hashlib.md5(
                        f"up_{time.time()}{url}".encode()
                    ).hexdigest()[:10]
                    capture = _save_capture(
                        upload_bytes, event_id, fext,
                        original_name=upload_fname
                    )
                    rules_list = list({m.get("rule","") for m in dlp_matches})

                    if dlp_flagged and DLP_BLOCKING_ENABLED:
                        # ── BLOCK: file doesn't pass to AI service ────────────
                        _stats["blocked"] += 1
                        _record_activity(client_ip, method, url, host,
                                         "blocked", req_size, ftype)
                        self._make_403(flow, self._details(dlp_matches),
                                       dlp_matches, event_id=event_id,
                                       filename=upload_fname)
                        _add_event({
                            "id": event_id, "type": "blocked",
                            "time": datetime.now().isoformat(timespec="seconds"),
                            "client": client_ip, "method": method,
                            "url": url[:200], "host": host,
                            "filename": upload_fname, "filetype": ftype,
                            "size": len(upload_bytes),
                            "capture": capture, "blocked": True,
                            "rules": rules_list,
                            "reason": self._details(dlp_matches),
                            "details": self._details(dlp_matches),
                            "matches": dlp_matches[:10],
                            "dlp_score": dlp_score,
                        })
                        # Create incident + notify client
                        try:
                            _create_incident_and_notify(
                                event_id, client_ip, upload_fname,
                                host, url[:200], ftype,
                                len(upload_bytes), rules_list,
                                dlp_matches, dlp_score, capture or "",
                            )
                        except Exception as e:
                            logger.warning(f"[Incident] Error: {e}")
                        return
                    else:
                        # ── PASS (no DLP match or monitoring mode) ────────────
                        _stats["uploads"] += 1
                        _add_event({
                            "id": event_id, "type": "upload",
                            "time": datetime.now().isoformat(timespec="seconds"),
                            "client": client_ip, "method": method,
                            "url": url[:200], "host": host,
                            "filename": upload_fname, "filetype": ftype,
                            "size": len(upload_bytes),
                            "capture": capture, "blocked": False,
                            "rules": [], "reason": "",
                        })
                        logger.info(
                            f"[Upload] {client_ip} -> {host} | "
                            f"{upload_fname or '—'} {ftype} "
                            f"{len(upload_bytes)//1024}KB"
                        )
                    _record_activity(client_ip, method, url, host,
                                     "upload", req_size, ftype)
                    _stats["passed"] += 1
                    return

            _stats["passed"] += 1
            _record_activity(client_ip, method, url, host, "ok", req_size)
            return

        # ── Extract upload content ────────────────────────────────────────────
        upload_bytes = None
        upload_fname = ""
        upload_ct    = ct
        upload_ftype = "binary"
        upload_ext   = "bin"
        is_upload    = method.upper() in ("POST", "PUT", "PATCH") and req_size > 100

        if is_upload and flow.request.content:
            ct_lower = ct.lower()
            if "multipart" in ct_lower:
                file_data, fname, file_ct = _extract_multipart(flow.request.content, ct)
                if file_data:
                    upload_bytes = file_data
                    upload_fname = fname
                    upload_ct    = file_ct or ct
                else:
                    upload_bytes = flow.request.content
            else:
                upload_bytes = flow.request.content

            upload_ftype, upload_ext = detect_filetype(
                upload_bytes if upload_bytes else None,
                upload_ct, upload_fname
            )

        # ── DLP: analyze URL params ───────────────────────────────────────────
        parsed = urlparse(url)
        if parsed.query:
            q_text = unquote_plus(parsed.query)
            block, matches = self.engine.should_block(q_text, f"URL:{url[:80]}", host=host)
            if block and DLP_BLOCKING_ENABLED:
                _stats["blocked"] += 1
                _record_activity(client_ip, method, url, host, "blocked", req_size, upload_ftype)
                self._make_403(flow, self._details(matches), matches)
                self._add_block_event(flow, matches, "URL параметры",
                                      client_ip, upload_fname, upload_ftype, url,
                                      upload_bytes, upload_ext)
                return

        # ── DLP: analyze body + ALWAYS record upload ─────────────────────────
        if is_upload and upload_bytes:
            body_text = _get_body_text(upload_bytes, upload_ct, upload_ftype)
            dlp_flagged = False
            dlp_matches = []
            dlp_score = 0

            if body_text:
                block, matches = self.engine.should_block(
                    body_text, f"BODY:{host}", host=host, content_type=upload_ct
                )
                if block:
                    dlp_flagged = True
                    dlp_matches = matches
                    dlp_score = sum(m.get("score", 0) for m in matches)

                    if DLP_BLOCKING_ENABLED:
                        _stats["blocked"] += 1
                        _record_activity(client_ip, method, url, host, "blocked",
                                         req_size, upload_ftype)
                        self._make_403(flow, self._details(matches), matches)
                        self._add_block_event(flow, matches, "Тело запроса",
                                              client_ip, upload_fname, upload_ftype, url,
                                              upload_bytes, upload_ext)
                        return

            # ── Always record the upload ──────────────────────────────────────
            self._add_upload_event(flow, client_ip, upload_fname,
                                   upload_ftype, upload_ext, url, upload_bytes)
            _record_activity(client_ip, method, url, host, "upload",
                             req_size, upload_ftype)

            # ── Create incident if DLP flagged ───────────────────────────────
            if dlp_flagged:
                try:
                    inc_id = hashlib.md5(
                        f"inc_{time.time()}{url}".encode()
                    ).hexdigest()[:10]
                    _create_incident_and_notify(
                        inc_id, client_ip, upload_fname,
                        host, url[:200], upload_ftype,
                        len(upload_bytes),
                        list({m.get("rule","") for m in dlp_matches}),
                        dlp_matches, dlp_score,
                    )
                except Exception as e:
                    logger.warning(f"[Incident] Error: {e}")
        else:
            _record_activity(client_ip, method, url, host, "ok", req_size)

        _stats["passed"] += 1

    # Hosts whose downloads we never record (system updates, etc.)
    _SKIP_DOWNLOAD_HOSTS = {
        "windowsupdate.com", "download.windowsupdate.com",
        "au.download.windowsupdate.com", "delivery.mp.microsoft.com",
        "download.microsoft.com", "tlu.dl.delivery.mp.microsoft.com",
        "2.tlu.dl.delivery.mp.microsoft.com",
    }

    def response(self, flow: http.HTTPFlow) -> None:
        if not flow.response:
            return
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else "?"
        resp_ct   = flow.response.headers.get("content-type", "").split(";")[0].strip().lower()
        resp_disp = flow.response.headers.get("content-disposition", "").lower()
        resp_size = len(flow.response.content) if flow.response.content else 0

        _update_bw(client_ip, inp=resp_size)

        # Skip system update downloads (Windows Defender, Windows Update .exe chunks)
        host = flow.request.pretty_host
        if any(host == h or host.endswith("." + h) for h in self._SKIP_DOWNLOAD_HOSTS):
            return

        # Also skip raw IP addresses that serve Windows Update
        # (20.215.104.x, 72.144.231.x are Microsoft CDN IPs for Defender updates)
        if (host.startswith("20.215.") or host.startswith("72.144.") or
                host.startswith("13.107.") or host.startswith("2.tlu.")):
            return

        # Detect download
        is_attach    = "attachment" in resp_disp
        is_dl_type   = any(resp_ct.startswith(t) for t in DOWNLOAD_CONTENT_TYPES)
        skip_types   = ("text/javascript", "application/javascript", "text/css",
                        "font/", "text/html")
        is_skip      = any(resp_ct.startswith(s) for s in skip_types)

        if resp_size < 2048 or is_skip or (not is_attach and not is_dl_type):
            return

        # Get filename
        fname = ""
        m = re.search(r'filename\*?=["\']?([^"\';\r\n]+)', resp_disp, re.IGNORECASE)
        if m:
            fname = m.group(1).strip().strip('"\'')
        if not fname:
            path_parts = urlparse(flow.request.pretty_url).path.split("/")
            fname = unquote_plus(path_parts[-1]) if path_parts else ""

        ftype, fext = detect_filetype(
            flow.response.content if flow.response.content else None,
            resp_ct, fname
        )
        event_id = hashlib.md5(f"dl_{time.time()}{flow.request.pretty_url}".encode()).hexdigest()[:10]
        capture  = None
        if flow.response.content and resp_size < 10 * 1024 * 1024:
            capture = _save_capture(flow.response.content, event_id, fext,
                                    original_name=fname)

        _stats["downloads"] += 1
        _record_activity(client_ip, "DL", flow.request.pretty_url,
                         flow.request.pretty_host, "download", resp_size, ftype)
        _add_event({
            "id":       event_id,
            "type":     "download",
            "time":     datetime.now().isoformat(timespec="seconds"),
            "client":   client_ip,
            "method":   "GET",
            "url":      flow.request.pretty_url[:200],
            "host":     flow.request.pretty_host,
            "filename": fname,
            "filetype": ftype,
            "size":     resp_size,
            "capture":  capture,
            "blocked":  False,
            "rules":    [],
            "reason":   f"Скачивание: {fname or ftype}",
        })
        logger.info(f"[Download] {client_ip} ← {flow.request.pretty_host} "
                    f"| {fname or '—'} {ftype} {resp_size//1024}KB")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _details(self, matches: list) -> str:
        parts = []
        for m in matches:
            if "keyword" in m:
                parts.append(f"{m['rule']}: «{m['keyword']}»")
            else:
                parts.append(f"{m['rule']}: {m['description']} ({m.get('count',1)} совп.)")
        return "; ".join(parts)

    def _make_internet_block(self, flow: http.HTTPFlow, host: str, client_ip: str):
        """Block page when client has no internet access (closed network)"""
        server_ip = _SERVER_IP
        cert_port = _ADDON_CFG.get("cert_port", 8000)
        html = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<title>Доступ в интернет заблокирован — DLP</title><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial;background:#0d1117;color:#c9d1d9;
     display:flex;justify-content:center;align-items:center;min-height:100vh}}
.card{{background:#161b22;border:2px solid #e3b341;border-radius:14px;
       padding:40px;max-width:650px;width:90%}}
h1{{color:#e3b341;font-size:1.6em;margin-bottom:12px;text-align:center}}
.subtitle{{text-align:center;color:#8b949e;margin-bottom:20px}}
.host{{font-family:monospace;background:#0d1117;border:1px solid #30363d;
      padding:8px 12px;border-radius:6px;color:#79c0ff;margin:12px 0;
      font-size:.9em;text-align:center}}
.info{{background:#1a2a12;border:1px solid #2ea043;border-radius:8px;
       padding:14px;margin-top:16px;font-size:.88em;color:#a6e3a1}}
.warn{{background:#2a1a08;border:1px solid #e3b341;border-radius:8px;
       padding:14px;margin-top:12px;font-size:.88em;color:#e3b341}}
.footer{{color:#6c7086;font-size:.78em;margin-top:20px;text-align:center}}
</style></head><body><div class="card">
<h1>🔒 Доступ в интернет заблокирован</h1>
<p class="subtitle">Данная сеть работает в режиме закрытой корпоративной сети.</p>
<div class="host">Запрошенный адрес: <strong>{host}</strong></div>

<div class="info">
  <strong>Как получить доступ:</strong><br><br>
  1. Откройте клиентское приложение DLP Agent<br>
  2. Перейдите на вкладку «🌐 Интернет»<br>
  3. Опишите причину и отправьте заявку<br>
  4. Дождитесь одобрения администратора
</div>

<div class="warn">
  <strong>ℹ️ Внутренние ресурсы доступны.</strong><br>
  Ресурсы локальной сети (intranet, файловые серверы, внутренние сервисы)
  работают без ограничений.
</div>

<p class="footer">
  Клиент: {client_ip} &nbsp;|&nbsp;
  Сервер DLP: <a href="http://{server_ip}:{cert_port}/" style="color:#58a6ff">{server_ip}:{cert_port}</a>
</p>
</div></body></html>"""
        flow.response = http.Response.make(
            403, html.encode("utf-8"), {"Content-Type": "text/html; charset=utf-8"}
        )

    def _make_403(self, flow: http.HTTPFlow, details: str, matches: list,
                  event_id: str = "", filename: str = ""):
        url = flow.request.pretty_url
        if not event_id:
            event_id = hashlib.md5(f"blk_{time.time()}{url}".encode()).hexdigest()[:10]

        # Build detailed rules + quotes for employee
        rules_html = ""
        for m in matches[:5]:
            rule = m.get("rule", "")
            desc = m.get("description", "")
            sample = m.get("sample", "")
            severity = m.get("severity", "")
            score = m.get("score", 0)
            sev_color = "#f38ba8" if severity == "HIGH" else "#e3b341"
            quote_html = ""
            if sample:
                quote_html = (
                    f'<div style="background:#0d1117;border:1px solid #30363d;'
                    f'border-radius:4px;padding:6px 10px;margin-top:4px;'
                    f'font-family:monospace;font-size:.82em;color:#fab387">'
                    f'«{sample[:80]}»</div>'
                )
            rules_html += (
                f'<div class="r">'
                f'<span style="color:{sev_color};font-weight:600">[{severity}]</span> '
                f'{desc}'
                f'{quote_html}'
                f'</div>'
            )

        fname_html = ""
        if filename:
            fname_html = (
                f'<div style="margin:12px 0;padding:8px 14px;background:#21262d;'
                f'border-radius:6px;color:#89b4fa;font-size:.95em">'
                f'📄 Файл: <strong>{filename}</strong></div>'
            )

        html = f"""<!DOCTYPE html><html lang="ru"><head><meta charset="UTF-8">
<title>Заблокировано — DLP</title><style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Segoe UI',Arial;background:#0d1117;color:#c9d1d9;
     display:flex;justify-content:center;align-items:center;min-height:100vh}}
.card{{background:#161b22;border:2px solid #f38ba8;border-radius:14px;
       padding:40px;max-width:700px;width:90%}}
h1{{color:#f38ba8;font-size:1.8em;margin-bottom:12px;text-align:center}}
.subtitle{{text-align:center;color:#8b949e;margin-bottom:20px}}
.url{{font-family:monospace;background:#0d1117;border:1px solid #30363d;
      padding:8px 12px;border-radius:6px;word-break:break-all;color:#79c0ff;
      margin:12px 0;font-size:.82em}}
.r{{background:#21262d;border-left:3px solid #f38ba8;padding:10px 14px;
    margin:8px 0;border-radius:4px;font-size:.9em;color:#c9d1d9}}
.section{{margin-top:20px;padding-top:16px;border-top:1px solid #30363d}}
.info{{background:#0d1520;border:1px solid #1f3a5a;border-radius:8px;
       padding:14px;margin-top:16px;font-size:.88em;color:#79c0ff}}
.footer{{color:#6c7086;font-size:.78em;margin-top:20px;text-align:center}}
</style></head><body><div class="card">
<h1>🚫 Передача заблокирована</h1>
<p class="subtitle">Система DLP обнаружила конфиденциальные данные в вашем файле.</p>
{fname_html}
<div class="url">Адрес: {url[:150]}</div>

<div class="section">
  <div style="color:#f38ba8;font-weight:600;margin-bottom:10px">Причины блокировки:</div>
  {rules_html}
</div>

<div class="info">
  <strong>ℹ️ Что делать:</strong><br>
  • Администратор получил уведомление об этом инциденте<br>
  • Он может запросить у вас доступ к файлу для проверки<br>
  • Вы получите уведомление в клиентском приложении<br>
  • Если блокировка ошибочна — свяжитесь с администратором через чат
</div>

<p class="footer">
  Инцидент <strong>#{event_id}</strong> зарегистрирован.
  Администратор видит факт блокировки, но НЕ видит содержимое файла.
</p>
</div></body></html>"""
        flow.response = http.Response.make(
            403, html.encode("utf-8"), {"Content-Type": "text/html; charset=utf-8"}
        )
        logger.warning(
            f"[DLP] ЗАБЛОКИРОВАН | "
            f"{flow.client_conn.peername[0] if flow.client_conn.peername else '?'} | "
            f"{filename or url[:60]} | {details[:80]}"
        )

    def _add_block_event(self, flow, matches, reason, client_ip,
                         fname, ftype, url, data, ext):
        event_id = hashlib.md5(f"blk_{time.time()}{url}".encode()).hexdigest()[:10]
        capture  = _save_capture(data, event_id, ext,
                                 original_name=fname) if data else None
        _add_event({
            "id": event_id, "type": "blocked",
            "time": datetime.now().isoformat(timespec="seconds"),
            "client": client_ip, "method": flow.request.method,
            "url": url[:200], "host": flow.request.pretty_host,
            "filename": fname, "filetype": ftype,
            "size": len(flow.request.content) if flow.request.content else 0,
            "capture": capture, "blocked": True,
            "rules": list({m["rule"] for m in matches}),
            "reason": reason, "details": self._details(matches),
            "matches": matches[:10],
        })

    def _add_upload_event(self, flow, client_ip, fname, ftype, ext, url, data):
        if not fname:
            from urllib.parse import urlparse as _up
            path = _up(url).path
            if path and path != "/":
                candidate = path.rstrip("/").split("/")[-1]
                if "." in candidate:
                    fname = candidate
        _stats["uploads"] += 1
        event_id = hashlib.md5(f"up_{time.time()}{url}".encode()).hexdigest()[:10]
        capture  = None
        if data and len(data) < 10 * 1024 * 1024:
            capture = _save_capture(data, event_id, ext,
                                    original_name=fname)
        _add_event({
            "id": event_id, "type": "upload",
            "time": datetime.now().isoformat(timespec="seconds"),
            "client": client_ip, "method": flow.request.method,
            "url": url[:200], "host": flow.request.pretty_host,
            "filename": fname, "filetype": ftype,
            "size": len(flow.request.content) if flow.request.content else 0,
            "capture": capture, "blocked": False, "rules": [], "reason": "",
        })
        logger.info(f"[Upload] {client_ip} -> {flow.request.pretty_host} "
                    f"| {fname or '—'} {ftype} {(len(flow.request.content) if flow.request.content else 0)//1024}KB")

    def done(self):
        logger.info(
            f"[DLPAddon] v6.0 завершено. "
            f"Всего:{_stats['total']} блок:{_stats['blocked']} "
            f"загрузок:{_stats['uploads']} скачиваний:{_stats['downloads']} "
            f"пропущено:{_stats['passed']}"
        )
        _save_events()


addons = [DLPAddon()]
