"""
DLP Transparency Module v1.0 — Инциденты, чат, уведомления.
Файлы с ДСП БЛОКИРУЮТСЯ. Админ видит содержимое. Сотрудник получает причину.
"""

import json, threading, logging
from pathlib import Path
from datetime import datetime

logger = logging.getLogger("dlp.transparency")
DATA_FILE = Path(__file__).parent.parent / "logs" / "transparency.json"
DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()
_data = {"incidents": [], "messages": {}, "notifications": {}}

def _load():
    global _data
    try:
        if DATA_FILE.exists():
            d = json.loads(DATA_FILE.read_text(encoding="utf-8"))
            _data["incidents"] = d.get("incidents", [])[-500:]
            _data["messages"] = d.get("messages", {})
            _data["notifications"] = d.get("notifications", {})
    except Exception as e:
        logger.warning(f"[TP] Load: {e}")

def _save():
    try:
        DATA_FILE.write_text(json.dumps(_data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    except Exception: pass

_load()

# ── INCIDENTS ────────────────────────────────────────────────────────────────
def create_incident(event_id, client_ip, filename, host, url, filetype,
                    filesize, rules_triggered, matches, score, capture_file=""):
    inc = {
        "id": event_id, "time": datetime.now().isoformat(timespec="seconds"),
        "client_ip": client_ip, "filename": filename, "host": host,
        "url": url[:200], "filetype": filetype, "filesize": filesize,
        "rules": rules_triggered, "score": score, "capture": capture_file,
        "status": "new", "access_status": "locked", "admin_notes": "",
        "matches": [{"rule": m.get("rule",""), "description": m.get("description",""),
                      "severity": m.get("severity",""), "sample": m.get("sample","")[:60],
                      "score": m.get("score",0)} for m in matches[:10]],
    }
    with _lock:
        _data["incidents"].append(inc)
        _data["incidents"] = _data["incidents"][-500:]
        _save()
    details_text = "; ".join(f"{m.get('rule','')}: {m.get('description','')}" for m in matches[:3])
    # Build quotes for employee notification
    quotes = []
    for m in matches[:5]:
        s = m.get("sample", "")
        if s:
            quotes.append(f"«{s[:60]}»")
    _notify_client(client_ip, "blocked",
        f"🚫 Файл «{filename}» заблокирован системой DLP.\n"
        f"Причина: {details_text}\n"
        f"{'Обнаружено: ' + ', '.join(quotes) if quotes else ''}",
        {"incident_id": event_id, "filename": filename,
         "rules": rules_triggered, "score": score,
         "quotes": quotes,
         "reason": details_text})
    return inc

def get_incidents(status="", client_ip="", limit=100):
    with _lock: result = list(_data["incidents"])
    if status: result = [i for i in result if i.get("status") == status]
    if client_ip: result = [i for i in result if i.get("client_ip") == client_ip]
    return list(reversed(result[-limit:]))

def get_incident(event_id):
    with _lock:
        for i in _data["incidents"]:
            if i["id"] == event_id: return dict(i)
    return None

def update_incident(event_id, **kw):
    with _lock:
        for i in _data["incidents"]:
            if i["id"] == event_id: i.update(kw); _save(); return True
    return False

# ── CHAT ─────────────────────────────────────────────────────────────────────
def request_access(event_id, admin_user):
    """Admin requests to view file contents"""
    inc = get_incident(event_id)
    if not inc: return False
    update_incident(event_id, access_status="requested")
    _notify_client(
        inc["client_ip"], "access_request",
        f"🔑 Администратор {admin_user} запрашивает доступ к файлу «{inc['filename']}».\n"
        f"Одобрите или отклоните запрос в клиентском приложении.",
        {"incident_id": event_id, "admin": admin_user, "filename": inc["filename"]}
    )
    logger.info(f"[Access] Запрос: {admin_user} → {event_id}")
    return True

def respond_access(event_id, approved):
    """Employee responds to access request"""
    status = "approved" if approved else "denied"
    update_incident(event_id, access_status=status)
    logger.info(f"[Access] Ответ: {event_id} → {status}")
    return True

def is_content_viewable(event_id):
    """Check if admin can view file contents"""
    inc = get_incident(event_id)
    return inc.get("access_status") == "approved" if inc else False

def get_unread_notifications_count(client_ip):
    return get_unread_count(client_ip)

# ── MESSAGING ────────────────────────────────────────────────────────────────
def send_message(client_ip, sender, text, sender_name=""):
    msg = {"id": f"msg_{datetime.now().strftime('%H%M%S%f')[:10]}",
           "from": sender, "from_name": sender_name or sender,
           "text": text[:2000], "time": datetime.now().isoformat(timespec="seconds"),
           "read": False}
    with _lock:
        _data["messages"].setdefault(client_ip, []).append(msg)
        _data["messages"][client_ip] = _data["messages"][client_ip][-200:]
        _save()
    if sender == "admin":
        _notify_client(client_ip, "message", f"💬 {sender_name or 'Админ'}: {text[:100]}", {})
    return msg

def get_messages(client_ip, since=""):
    with _lock: msgs = list(_data["messages"].get(client_ip, []))
    return [m for m in msgs if m["time"] > since] if since else msgs

def mark_messages_read(client_ip, reader):
    with _lock:
        for m in _data["messages"].get(client_ip, []):
            if m["from"] != reader: m["read"] = True
        _save()

def get_all_chats_summary():
    with _lock:
        result = []
        for ip, msgs in _data["messages"].items():
            if not msgs: continue
            unread = sum(1 for m in msgs if m["from"] == "client" and not m["read"])
            result.append({"client_ip": ip, "total": len(msgs), "unread": unread,
                           "last_text": msgs[-1]["text"][:80], "last_time": msgs[-1]["time"]})
    return sorted(result, key=lambda x: x["last_time"], reverse=True)

# ── NOTIFICATIONS ────────────────────────────────────────────────────────────
def _notify_client(client_ip, ntype, text, details=None):
    notif = {"id": f"n_{datetime.now().strftime('%Y%m%d%H%M%S%f')[:18]}",
             "type": ntype, "text": text,
             "time": datetime.now().isoformat(timespec="seconds"),
             "read": False, "details": details or {}}
    with _lock:
        _data["notifications"].setdefault(client_ip, []).append(notif)
        _data["notifications"][client_ip] = _data["notifications"][client_ip][-50:]
        _save()

def get_notifications(client_ip, unread_only=False):
    with _lock: notifs = list(_data["notifications"].get(client_ip, []))
    return [n for n in notifs if not n["read"]] if unread_only else notifs

def mark_notification_read(client_ip, notif_id):
    with _lock:
        for n in _data["notifications"].get(client_ip, []):
            if n["id"] == notif_id: n["read"] = True; break
        _save()

def get_unread_count(client_ip):
    with _lock:
        return sum(1 for n in _data["notifications"].get(client_ip, []) if not n["read"])
