"""
DLP Transparency Module.

Хранение работает в двух режимах:
- PostgreSQL, если настроен `database_url`
- JSON fallback, если БД ещё не настроена
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime
from pathlib import Path

from shared.storage_config import load_storage_settings

try:
    import psycopg
except ImportError:
    psycopg = None


logger = logging.getLogger("dlp.transparency")
DATA_FILE = Path(__file__).parent.parent / "logs" / "transparency.json"
DATA_FILE.parent.mkdir(parents=True, exist_ok=True)
_lock = threading.Lock()
_schema_lock = threading.Lock()
_schema_ready = False
_data = {"incidents": [], "messages": {}, "notifications": {}}


def _database_url() -> str:
    return (load_storage_settings().get("database_url") or "").strip()


def _pg_enabled() -> bool:
    return bool(_database_url()) and psycopg is not None


def _pg_connect():
    _ensure_schema()
    return psycopg.connect(_database_url())


def _ensure_schema():
    global _schema_ready
    if _schema_ready or not _pg_enabled():
        return

    with _schema_lock:
        if _schema_ready:
            return
        with psycopg.connect(_database_url(), autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tp_incidents (
                        id TEXT PRIMARY KEY,
                        time TEXT NOT NULL,
                        client_ip TEXT NOT NULL,
                        filename TEXT NOT NULL,
                        host TEXT NOT NULL,
                        url TEXT NOT NULL,
                        filetype TEXT NOT NULL,
                        filesize BIGINT NOT NULL,
                        rules_json JSONB NOT NULL,
                        score INTEGER NOT NULL,
                        capture TEXT NOT NULL DEFAULT '',
                        status TEXT NOT NULL DEFAULT 'new',
                        access_status TEXT NOT NULL DEFAULT 'locked',
                        admin_notes TEXT NOT NULL DEFAULT '',
                        matches_json JSONB NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tp_messages (
                        id TEXT PRIMARY KEY,
                        client_ip TEXT NOT NULL,
                        sender TEXT NOT NULL,
                        sender_name TEXT NOT NULL,
                        text TEXT NOT NULL,
                        time TEXT NOT NULL,
                        is_read BOOLEAN NOT NULL DEFAULT FALSE
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS tp_notifications (
                        id TEXT PRIMARY KEY,
                        client_ip TEXT NOT NULL,
                        type TEXT NOT NULL,
                        text TEXT NOT NULL,
                        time TEXT NOT NULL,
                        is_read BOOLEAN NOT NULL DEFAULT FALSE,
                        details_json JSONB NOT NULL
                    )
                    """
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_tp_incidents_time "
                    "ON tp_incidents(time DESC)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_tp_incidents_client_status "
                    "ON tp_incidents(client_ip, status, time DESC)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_tp_messages_client_time "
                    "ON tp_messages(client_ip, time DESC)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_tp_notifications_client_time "
                    "ON tp_notifications(client_ip, time DESC)"
                )
        _schema_ready = True


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _message_id() -> str:
    return f"msg_{datetime.now().strftime('%H%M%S%f')[:10]}"


def _notification_id(prefix: str = "n") -> str:
    return f"{prefix}_{datetime.now().strftime('%Y%m%d%H%M%S%f')[:18]}"


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
        DATA_FILE.write_text(
            json.dumps(_data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
    except Exception:
        pass


_load()


def _incident_to_dict(row) -> dict:
    return {
        "id": row[0],
        "time": row[1],
        "client_ip": row[2],
        "filename": row[3],
        "host": row[4],
        "url": row[5],
        "filetype": row[6],
        "filesize": row[7],
        "rules": row[8] or [],
        "score": row[9],
        "capture": row[10] or "",
        "status": row[11],
        "access_status": row[12],
        "admin_notes": row[13] or "",
        "matches": row[14] or [],
    }


def _message_to_dict(row) -> dict:
    return {
        "id": row[0],
        "from": row[1],
        "from_name": row[2],
        "text": row[3],
        "time": row[4],
        "read": bool(row[5]),
    }


def _notification_to_dict(row) -> dict:
    return {
        "id": row[0],
        "type": row[1],
        "text": row[2],
        "time": row[3],
        "read": bool(row[4]),
        "details": row[5] or {},
    }


def add_notification(client_ip, ntype, text, details=None, notif_id=""):
    notif = {
        "id": notif_id or _notification_id("n"),
        "type": ntype,
        "text": text,
        "time": _now(),
        "read": False,
        "details": details or {},
    }
    if _pg_enabled():
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tp_notifications
                        (id, client_ip, type, text, time, is_read, details_json)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            notif["id"], client_ip, ntype, text[:4000], notif["time"],
                            False, json.dumps(notif["details"], ensure_ascii=False),
                        ),
                    )
                conn.commit()
        return notif

    with _lock:
        _data["notifications"].setdefault(client_ip, []).append(notif)
        _data["notifications"][client_ip] = _data["notifications"][client_ip][-100:]
        _save()
    return notif


def _notify_client(client_ip, ntype, text, details=None):
    return add_notification(client_ip, ntype, text, details)


def create_incident(event_id, client_ip, filename, host, url, filetype,
                    filesize, rules_triggered, matches, score, capture_file=""):
    now = _now()
    quotes = [m.get("sample", "")[:60] for m in matches if m.get("sample")]
    details_text = "; ".join(
        f"{m.get('rule', '')}: {m.get('description', '')}" for m in matches[:3]
    )
    inc = {
        "id": event_id,
        "time": now,
        "client_ip": client_ip,
        "filename": filename,
        "host": host,
        "url": url[:200],
        "filetype": filetype,
        "filesize": filesize,
        "rules": rules_triggered,
        "score": score,
        "capture": capture_file,
        "status": "new",
        "access_status": "locked",
        "admin_notes": "",
        "matches": [
            {
                "rule": m.get("rule", ""),
                "description": m.get("description", ""),
                "severity": m.get("severity", ""),
                "sample": m.get("sample", "")[:60],
                "score": m.get("score", 0),
            }
            for m in matches[:10]
        ],
    }

    if _pg_enabled():
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tp_incidents
                        (id, time, client_ip, filename, host, url, filetype, filesize,
                         rules_json, score, capture, status, access_status, admin_notes, matches_json)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (id) DO NOTHING
                        """,
                        (
                            event_id, now, client_ip, filename, host, url[:200], filetype,
                            int(filesize or 0), json.dumps(rules_triggered, ensure_ascii=False),
                            int(score or 0), capture_file or "", "new", "locked", "",
                            json.dumps(inc["matches"], ensure_ascii=False),
                        ),
                    )
                conn.commit()
    else:
        with _lock:
            _data["incidents"].append(inc)
            _data["incidents"] = _data["incidents"][-500:]
            _save()

    add_notification(
        client_ip,
        "blocked",
        f"🚫 Файл «{filename}» заблокирован системой DLP.\n"
        f"Причина: {details_text}\n"
        f"{'Обнаружено: ' + ', '.join(f'«{q}»' for q in quotes[:5]) if quotes else ''}",
        {
            "incident_id": event_id,
            "filename": filename,
            "rules": rules_triggered,
            "score": score,
            "quotes": quotes[:5],
            "reason": details_text,
        },
        notif_id=f"n_blk_{event_id}",
    )
    return inc


def get_incidents(status="", client_ip="", limit=100):
    if _pg_enabled():
        clauses = []
        params = []
        if status:
            clauses.append("status = %s")
            params.append(status)
        if client_ip:
            clauses.append("client_ip = %s")
            params.append(client_ip)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = (
            "SELECT id, time, client_ip, filename, host, url, filetype, filesize, "
            "rules_json, score, capture, status, access_status, admin_notes, matches_json "
            f"FROM tp_incidents {where_sql} ORDER BY time DESC LIMIT %s"
        )
        params.append(limit)
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(query, params)
                    rows = cur.fetchall()
                conn.commit()
        return [_incident_to_dict(row) for row in rows]

    with _lock:
        result = list(_data["incidents"])
    if status:
        result = [i for i in result if i.get("status") == status]
    if client_ip:
        result = [i for i in result if i.get("client_ip") == client_ip]
    return list(reversed(result[-limit:]))


def get_incident(event_id):
    if _pg_enabled():
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id, time, client_ip, filename, host, url, filetype, filesize,
                               rules_json, score, capture, status, access_status, admin_notes, matches_json
                        FROM tp_incidents
                        WHERE id=%s
                        """,
                        (event_id,),
                    )
                    row = cur.fetchone()
                conn.commit()
        return _incident_to_dict(row) if row else None

    with _lock:
        for incident in _data["incidents"]:
            if incident["id"] == event_id:
                return dict(incident)
    return None


def update_incident(event_id, **kw):
    if _pg_enabled():
        allowed = {
            "client_ip", "filename", "host", "url", "filetype", "filesize",
            "rules", "score", "capture", "status", "access_status",
            "admin_notes", "matches",
        }
        updates = []
        params = []
        column_map = {
            "rules": "rules_json",
            "matches": "matches_json",
        }
        for key, value in kw.items():
            if key not in allowed:
                continue
            column = column_map.get(key, key)
            updates.append(f"{column} = %s")
            if key in {"rules", "matches"}:
                params.append(json.dumps(value, ensure_ascii=False))
            else:
                params.append(value)
        if not updates:
            return False
        params.append(event_id)
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        f"UPDATE tp_incidents SET {', '.join(updates)} WHERE id = %s",
                        params,
                    )
                    updated = cur.rowcount > 0
                conn.commit()
        return updated

    with _lock:
        for incident in _data["incidents"]:
            if incident["id"] == event_id:
                incident.update(kw)
                _save()
                return True
    return False


def request_access(event_id, admin_user, message=""):
    inc = get_incident(event_id)
    if not inc:
        return False
    update_incident(event_id, access_status="requested")
    prompt = message or "Администратор запрашивает разрешение на просмотр содержимого файла."
    add_notification(
        inc["client_ip"],
        "access_request",
        f"🔑 {prompt}\nФайл: «{inc['filename']}»",
        {
            "incident_id": event_id,
            "admin": admin_user,
            "filename": inc["filename"],
            "message": prompt,
            "reason": "; ".join(
                f"{m.get('rule', '')}: {m.get('description', '')}"
                for m in inc.get("matches", [])[:3]
            ),
            "quotes": [
                m.get("sample", "")[:60]
                for m in inc.get("matches", [])[:5]
                if m.get("sample")
            ],
        },
        notif_id=f"n_ar_{event_id}",
    )
    logger.info(f"[Access] Запрос: {admin_user} -> {event_id}")
    return True


def respond_access(event_id, approved):
    status = "approved" if approved else "denied"
    ok = update_incident(event_id, access_status=status)
    if ok:
        logger.info(f"[Access] Ответ: {event_id} -> {status}")
    return ok


def is_content_viewable(event_id):
    inc = get_incident(event_id)
    return inc.get("access_status") == "approved" if inc else False


def get_unread_notifications_count(client_ip):
    return get_unread_count(client_ip)


def send_message(client_ip, sender, text, sender_name=""):
    msg = {
        "id": _message_id(),
        "from": sender,
        "from_name": sender_name or sender,
        "text": text[:2000],
        "time": _now(),
        "read": False,
    }

    if _pg_enabled():
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO tp_messages
                        (id, client_ip, sender, sender_name, text, time, is_read)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            msg["id"], client_ip, sender, msg["from_name"],
                            msg["text"], msg["time"], False,
                        ),
                    )
                conn.commit()
    else:
        with _lock:
            _data["messages"].setdefault(client_ip, []).append(msg)
            _data["messages"][client_ip] = _data["messages"][client_ip][-200:]
            _save()

    if sender == "admin":
        add_notification(
            client_ip,
            "message",
            f"💬 {sender_name or 'Админ'}: {text[:100]}",
            {},
            notif_id=f"n_m_{msg['id']}",
        )
    return msg


def get_messages(client_ip, since=""):
    if _pg_enabled():
        params = [client_ip]
        sql = (
            "SELECT id, sender, sender_name, text, time, is_read "
            "FROM tp_messages WHERE client_ip=%s"
        )
        if since:
            sql += " AND time > %s"
            params.append(since)
        sql += " ORDER BY time ASC"
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                    rows = cur.fetchall()
                conn.commit()
        return [_message_to_dict(row) for row in rows]

    with _lock:
        msgs = list(_data["messages"].get(client_ip, []))
    return [m for m in msgs if m["time"] > since] if since else msgs


def mark_messages_read(client_ip, reader):
    if _pg_enabled():
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE tp_messages
                        SET is_read = TRUE
                        WHERE client_ip=%s AND sender <> %s AND is_read = FALSE
                        """,
                        (client_ip, reader),
                    )
                conn.commit()
        return

    with _lock:
        for msg in _data["messages"].get(client_ip, []):
            if msg["from"] != reader:
                msg["read"] = True
        _save()


def get_all_chats_summary():
    if _pg_enabled():
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT client_ip,
                               COUNT(*) AS total,
                               COALESCE(SUM(CASE WHEN sender='client' AND is_read=FALSE THEN 1 ELSE 0 END), 0) AS unread,
                               MAX(time) AS last_time
                        FROM tp_messages
                        GROUP BY client_ip
                        ORDER BY MAX(time) DESC
                        """
                    )
                    rows = cur.fetchall()
                conn.commit()
        result = []
        for client_ip, total, unread, last_time in rows:
            messages = get_messages(client_ip)
            last_text = messages[-1]["text"][:80] if messages else ""
            result.append(
                {
                    "client_ip": client_ip,
                    "total": int(total),
                    "unread": int(unread),
                    "last_text": last_text,
                    "last_time": last_time,
                }
            )
        return result

    with _lock:
        result = []
        for ip, msgs in _data["messages"].items():
            if not msgs:
                continue
            unread = sum(1 for m in msgs if m["from"] == "client" and not m["read"])
            result.append(
                {
                    "client_ip": ip,
                    "total": len(msgs),
                    "unread": unread,
                    "last_text": msgs[-1]["text"][:80],
                    "last_time": msgs[-1]["time"],
                }
            )
    return sorted(result, key=lambda x: x["last_time"], reverse=True)


def get_notifications(client_ip, unread_only=False):
    if _pg_enabled():
        sql = (
            "SELECT id, type, text, time, is_read, details_json "
            "FROM tp_notifications WHERE client_ip=%s"
        )
        params = [client_ip]
        if unread_only:
            sql += " AND is_read = FALSE"
        sql += " ORDER BY time DESC"
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(sql, params)
                    rows = cur.fetchall()
                conn.commit()
        return [_notification_to_dict(row) for row in rows]

    with _lock:
        notifications = list(_data["notifications"].get(client_ip, []))
    return [n for n in notifications if not n["read"]] if unread_only else notifications


def mark_notification_read(client_ip, notif_id):
    if _pg_enabled():
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        UPDATE tp_notifications
                        SET is_read = TRUE
                        WHERE client_ip=%s AND id=%s
                        """,
                        (client_ip, notif_id),
                    )
                conn.commit()
        return

    with _lock:
        for notif in _data["notifications"].get(client_ip, []):
            if notif["id"] == notif_id:
                notif["read"] = True
                break
        _save()


def get_unread_count(client_ip):
    if _pg_enabled():
        with _lock:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT COUNT(*)
                        FROM tp_notifications
                        WHERE client_ip=%s AND is_read = FALSE
                        """,
                        (client_ip,),
                    )
                    row = cur.fetchone()
                conn.commit()
        return int(row[0] if row else 0)

    with _lock:
        return sum(1 for notif in _data["notifications"].get(client_ip, []) if not notif["read"])
