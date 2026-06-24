"""
Internet Access Manager.

При наличии `database_url` в config.json или переменной окружения
`DLP_DATABASE_URL` модуль хранит данные в PostgreSQL.
Если БД не настроена, используется прежний JSON fallback.
"""

from __future__ import annotations

import ipaddress
import json
import threading
from datetime import datetime
from pathlib import Path

from shared.storage_config import load_storage_settings

try:
    import psycopg
except ImportError:
    psycopg = None


_IA_FILE = Path(__file__).parent.parent / "logs" / "internet_access.json"
_IA_LOCK = threading.Lock()
_SCHEMA_LOCK = threading.Lock()
_SCHEMA_READY = False

_DEFAULT_DATA = {
    "allowed_clients": {},
    "pending_requests": [],
    "history": [],
}


def _database_url() -> str:
    return (load_storage_settings().get("database_url") or "").strip()


def _pg_enabled() -> bool:
    return bool(_database_url()) and psycopg is not None


def _ensure_schema():
    global _SCHEMA_READY
    if _SCHEMA_READY or not _pg_enabled():
        return

    with _SCHEMA_LOCK:
        if _SCHEMA_READY:
            return
        with psycopg.connect(_database_url(), autocommit=True) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ia_allowed_clients (
                        client_ip TEXT PRIMARY KEY,
                        approved_by TEXT NOT NULL,
                        reason TEXT NOT NULL DEFAULT '',
                        time TEXT NOT NULL,
                        expires TEXT,
                        request_id TEXT NOT NULL DEFAULT ''
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ia_pending_requests (
                        id TEXT PRIMARY KEY,
                        client_ip TEXT NOT NULL,
                        reason TEXT NOT NULL,
                        time TEXT NOT NULL,
                        status TEXT NOT NULL,
                        approved_by TEXT,
                        approved_time TEXT,
                        denied_by TEXT,
                        denied_time TEXT,
                        admin_comment TEXT NOT NULL DEFAULT ''
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ia_history (
                        id TEXT PRIMARY KEY,
                        client_ip TEXT NOT NULL,
                        action TEXT NOT NULL,
                        admin_name TEXT NOT NULL,
                        time TEXT NOT NULL,
                        reason TEXT NOT NULL DEFAULT '',
                        comment TEXT NOT NULL DEFAULT ''
                    )
                    """
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ia_pending_status "
                    "ON ia_pending_requests(status, client_ip, time)"
                )
                cur.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ia_history_client_time "
                    "ON ia_history(client_ip, time)"
                )
        _SCHEMA_READY = True


def _pg_connect():
    _ensure_schema()
    return psycopg.connect(_database_url())


def _read() -> dict:
    try:
        if _IA_FILE.exists():
            data = json.loads(_IA_FILE.read_text(encoding="utf-8"))
            for key in _DEFAULT_DATA:
                data.setdefault(key, type(_DEFAULT_DATA[key])())
            return data
    except Exception:
        pass
    return {
        key: type(value)() if isinstance(value, (dict, list)) else value
        for key, value in _DEFAULT_DATA.items()
    }


def _write(data: dict):
    try:
        _IA_FILE.parent.mkdir(parents=True, exist_ok=True)
        _IA_FILE.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )
    except Exception:
        pass


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _is_expired(expires: str | None) -> bool:
    if not expires:
        return False
    try:
        return datetime.fromisoformat(expires) < datetime.now()
    except Exception:
        return False


def _history_id() -> str:
    return f"h_{datetime.now().strftime('%Y%m%d%H%M%S')}"


def _cleanup_expired_access_db(conn, client_ip: str | None = None):
    with conn.cursor() as cur:
        if client_ip:
            cur.execute(
                "SELECT client_ip, expires FROM ia_allowed_clients WHERE client_ip=%s",
                (client_ip,),
            )
        else:
            cur.execute(
                "SELECT client_ip, expires FROM ia_allowed_clients "
                "WHERE expires IS NOT NULL AND expires <> ''"
            )
        expired = [
            ip for ip, expires in cur.fetchall()
            if _is_expired(expires)
        ]
        for ip in expired:
            cur.execute("DELETE FROM ia_allowed_clients WHERE client_ip=%s", (ip,))
            cur.execute(
                """
                INSERT INTO ia_history (id, client_ip, action, admin_name, time, reason, comment)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (_history_id(), ip, "expired", "system", _now(), "", ""),
            )


def _pg_get_allowed_entry(conn, client_ip: str) -> dict | None:
    _cleanup_expired_access_db(conn, client_ip)
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT approved_by, reason, time, expires, request_id
            FROM ia_allowed_clients
            WHERE client_ip=%s
            """,
            (client_ip,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "approved_by": row[0],
        "reason": row[1],
        "time": row[2],
        "expires": row[3] or "",
        "request_id": row[4] or "",
    }


def _pg_get_pending_request(conn, client_ip: str) -> dict | None:
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT id, client_ip, reason, time, status,
                   approved_by, approved_time, denied_by, denied_time, admin_comment
            FROM ia_pending_requests
            WHERE client_ip=%s AND status='pending'
            ORDER BY time DESC
            LIMIT 1
            """,
            (client_ip,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "id": row[0],
        "client_ip": row[1],
        "reason": row[2],
        "time": row[3],
        "status": row[4],
        "approved_by": row[5] or "",
        "approved_time": row[6] or "",
        "denied_by": row[7] or "",
        "denied_time": row[8] or "",
        "admin_comment": row[9] or "",
    }


# ═══════════════════════════════════════════════════════════════════════════════
#  Проверка: хост внутренний или внешний (интернет)?
# ═══════════════════════════════════════════════════════════════════════════════

def is_local_host(host: str, local_ranges: list[str] = None,
                  local_domains: list[str] = None,
                  server_ip: str = "") -> bool:
    """
    Определяет, является ли хост локальным (внутренняя сеть).

    Проверки:
      1. IP-адрес попадает в local_ranges (RFC 1918 и т.д.)
      2. Домен совпадает с local_domains из конфига
      3. Хост = IP сервера
      4. localhost / 127.x.x.x
    """
    if not host:
        return True

    if local_ranges is None:
        local_ranges = [
            "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
            "127.0.0.0/8", "169.254.0.0/16",
        ]
    if local_domains is None:
        local_domains = []

    # Убираем порт если есть
    pure_host = host.split(":")[0].strip().lower()

    # Localhost
    if pure_host in ("localhost", "::1"):
        return True

    # Совпадение с IP сервера
    if server_ip and pure_host == server_ip:
        return True

    # Проверяем как IP-адрес
    try:
        addr = ipaddress.ip_address(pure_host)
        # Приватные адреса
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return True
        # Проверяем по сетям из конфига
        for net_str in local_ranges:
            try:
                if addr in ipaddress.ip_network(net_str, strict=False):
                    return True
            except ValueError:
                continue
        return False
    except ValueError:
        pass  # Не IP — значит доменное имя

    # Проверяем домен по списку локальных доменов
    for ld in local_domains:
        ld = ld.strip().lower()
        if not ld:
            continue
        if pure_host == ld or pure_host.endswith("." + ld):
            return True

    # Домены .local, .lan, .internal — всегда локальные
    local_tlds = (".local", ".lan", ".internal", ".corp", ".intranet", ".home")
    if any(pure_host.endswith(t) for t in local_tlds):
        return True

    return False


# ═══════════════════════════════════════════════════════════════════════════════
#  Проверка: разрешён ли клиенту доступ в интернет?
# ═══════════════════════════════════════════════════════════════════════════════

def client_has_internet_access(client_ip: str) -> bool:
    """Проверяет, есть ли у клиента разрешение на интернет."""
    if _pg_enabled():
        with _IA_LOCK:
            with _pg_connect() as conn:
                return _pg_get_allowed_entry(conn, client_ip) is not None

    with _IA_LOCK:
        data = _read()
        entry = data.get("allowed_clients", {}).get(client_ip)
        if not entry:
            return False
        # Проверяем expires
        exp = entry.get("expires", "")
        if exp:
            try:
                if datetime.fromisoformat(exp) < datetime.now():
                    # Истёк — удаляем
                    del data["allowed_clients"][client_ip]
                    data["history"].append({
                        "id": f"h_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                        "client_ip": client_ip,
                        "action": "expired",
                        "admin": "system",
                        "time": datetime.now().isoformat(timespec="seconds"),
                    })
                    _write(data)
                    return False
            except Exception:
                pass
        return True


def get_internet_status(client_ip: str) -> dict:
    """Возвращает статус доступа клиента: {has_access, pending_request, details}"""
    if _pg_enabled():
        with _IA_LOCK:
            with _pg_connect() as conn:
                details = _pg_get_allowed_entry(conn, client_ip) or {}
                pending = _pg_get_pending_request(conn, client_ip)
                return {
                    "has_access": bool(details),
                    "pending_request": pending,
                    "details": details,
                }

    with _IA_LOCK:
        data = _read()
        has_access = client_ip in data.get("allowed_clients", {})
        details = data.get("allowed_clients", {}).get(client_ip, {})

        # Проверяем expire
        if has_access and details.get("expires"):
            try:
                if datetime.fromisoformat(details["expires"]) < datetime.now():
                    has_access = False
                    details = {}
            except Exception:
                pass

        pending = None
        for req in data.get("pending_requests", []):
            if req.get("client_ip") == client_ip and req.get("status") == "pending":
                pending = req
                break

        return {
            "has_access": has_access,
            "pending_request": pending,
            "details": details,
        }


# ═══════════════════════════════════════════════════════════════════════════════
#  Заявки от клиентов
# ═══════════════════════════════════════════════════════════════════════════════

def submit_internet_request(client_ip: str, reason: str) -> dict:
    """Клиент отправляет заявку на доступ в интернет."""
    if _pg_enabled():
        with _IA_LOCK:
            with _pg_connect() as conn:
                if _pg_get_allowed_entry(conn, client_ip):
                    return {"ok": False, "error": "already_has_access"}
                if _pg_get_pending_request(conn, client_ip):
                    pending = _pg_get_pending_request(conn, client_ip)
                    return {
                        "ok": False,
                        "error": "already_pending",
                        "request_id": pending["id"],
                    }

                req_id = (
                    f"ir_{datetime.now().strftime('%Y%m%d_%H%M%S')}_"
                    f"{client_ip.replace('.', '_')}"
                )
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ia_pending_requests
                        (id, client_ip, reason, time, status, approved_by, approved_time,
                         denied_by, denied_time, admin_comment)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (req_id, client_ip, reason[:500], _now(), "pending",
                         "", "", "", "", ""),
                    )
                conn.commit()
                return {"ok": True, "request_id": req_id}

    with _IA_LOCK:
        data = _read()
        # Проверяем: уже есть активный доступ?
        if client_ip in data.get("allowed_clients", {}):
            return {"ok": False, "error": "already_has_access"}
        # Есть ли уже pending заявка?
        for req in data.get("pending_requests", []):
            if req.get("client_ip") == client_ip and req.get("status") == "pending":
                return {"ok": False, "error": "already_pending",
                        "request_id": req["id"]}

        req_id = f"ir_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{client_ip.replace('.','_')}"
        request = {
            "id": req_id,
            "client_ip": client_ip,
            "reason": reason[:500],
            "time": datetime.now().isoformat(timespec="seconds"),
            "status": "pending",
        }
        data.setdefault("pending_requests", []).append(request)
        data["pending_requests"] = data["pending_requests"][-200:]
        _write(data)
        return {"ok": True, "request_id": req_id}


# ═══════════════════════════════════════════════════════════════════════════════
#  Действия администратора
# ═══════════════════════════════════════════════════════════════════════════════

def approve_request(request_id: str, admin: str,
                    expires: str = "") -> bool:
    """Администратор одобряет заявку."""
    if _pg_enabled():
        with _IA_LOCK:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT client_ip, reason
                        FROM ia_pending_requests
                        WHERE id=%s AND status='pending'
                        FOR UPDATE
                        """,
                        (request_id,),
                    )
                    row = cur.fetchone()
                    if not row:
                        return False
                    client_ip, reason = row
                    now = _now()
                    cur.execute(
                        """
                        UPDATE ia_pending_requests
                        SET status='approved', approved_by=%s, approved_time=%s
                        WHERE id=%s
                        """,
                        (admin, now, request_id),
                    )
                    cur.execute(
                        """
                        INSERT INTO ia_allowed_clients
                        (client_ip, approved_by, reason, time, expires, request_id)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (client_ip) DO UPDATE SET
                            approved_by=EXCLUDED.approved_by,
                            reason=EXCLUDED.reason,
                            time=EXCLUDED.time,
                            expires=EXCLUDED.expires,
                            request_id=EXCLUDED.request_id
                        """,
                        (client_ip, admin, reason or "", now, expires or "", request_id),
                    )
                    cur.execute(
                        """
                        INSERT INTO ia_history
                        (id, client_ip, action, admin_name, time, reason, comment)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (_history_id(), client_ip, "approved", admin, now, reason or "", ""),
                    )
                conn.commit()
                return True

    with _IA_LOCK:
        data = _read()
        for req in data.get("pending_requests", []):
            if req["id"] == request_id and req["status"] == "pending":
                req["status"] = "approved"
                req["approved_by"] = admin
                req["approved_time"] = datetime.now().isoformat(timespec="seconds")

                # Добавляем в allowed
                data.setdefault("allowed_clients", {})[req["client_ip"]] = {
                    "approved_by": admin,
                    "reason": req.get("reason", ""),
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "expires": expires,
                    "request_id": request_id,
                }
                data.setdefault("history", []).append({
                    "id": f"h_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    "client_ip": req["client_ip"],
                    "action": "approved",
                    "admin": admin,
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "reason": req.get("reason", ""),
                })
                _write(data)
                return True
        return False


def deny_request(request_id: str, admin: str,
                 comment: str = "") -> bool:
    """Администратор отклоняет заявку."""
    if _pg_enabled():
        with _IA_LOCK:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT client_ip
                        FROM ia_pending_requests
                        WHERE id=%s AND status='pending'
                        FOR UPDATE
                        """,
                        (request_id,),
                    )
                    row = cur.fetchone()
                    if not row:
                        return False
                    client_ip = row[0]
                    now = _now()
                    cur.execute(
                        """
                        UPDATE ia_pending_requests
                        SET status='denied', denied_by=%s, denied_time=%s, admin_comment=%s
                        WHERE id=%s
                        """,
                        (admin, now, comment, request_id),
                    )
                    cur.execute(
                        """
                        INSERT INTO ia_history
                        (id, client_ip, action, admin_name, time, reason, comment)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (_history_id(), client_ip, "denied", admin, now, "", comment),
                    )
                conn.commit()
                return True

    with _IA_LOCK:
        data = _read()
        for req in data.get("pending_requests", []):
            if req["id"] == request_id and req["status"] == "pending":
                req["status"] = "denied"
                req["denied_by"] = admin
                req["denied_time"] = datetime.now().isoformat(timespec="seconds")
                req["admin_comment"] = comment

                data.setdefault("history", []).append({
                    "id": f"h_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                    "client_ip": req["client_ip"],
                    "action": "denied",
                    "admin": admin,
                    "time": datetime.now().isoformat(timespec="seconds"),
                    "comment": comment,
                })
                _write(data)
                return True
        return False


def grant_access(client_ip: str, admin: str,
                 reason: str = "Предоставлено администратором",
                 expires: str = "") -> bool:
    """Администратор вручную даёт доступ клиенту (без заявки)."""
    if _pg_enabled():
        with _IA_LOCK:
            with _pg_connect() as conn:
                now = _now()
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ia_allowed_clients
                        (client_ip, approved_by, reason, time, expires, request_id)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        ON CONFLICT (client_ip) DO UPDATE SET
                            approved_by=EXCLUDED.approved_by,
                            reason=EXCLUDED.reason,
                            time=EXCLUDED.time,
                            expires=EXCLUDED.expires,
                            request_id=EXCLUDED.request_id
                        """,
                        (client_ip, admin, reason, now, expires or "", ""),
                    )
                    cur.execute(
                        """
                        INSERT INTO ia_history
                        (id, client_ip, action, admin_name, time, reason, comment)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (_history_id(), client_ip, "granted", admin, now, reason, ""),
                    )
                conn.commit()
                return True

    with _IA_LOCK:
        data = _read()
        data.setdefault("allowed_clients", {})[client_ip] = {
            "approved_by": admin,
            "reason": reason,
            "time": datetime.now().isoformat(timespec="seconds"),
            "expires": expires,
            "request_id": "",
        }
        data.setdefault("history", []).append({
            "id": f"h_{datetime.now().strftime('%Y%m%d%H%M%S')}",
            "client_ip": client_ip,
            "action": "granted",
            "admin": admin,
            "time": datetime.now().isoformat(timespec="seconds"),
        })
        _write(data)
        return True


def revoke_access(client_ip: str, admin: str) -> bool:
    """Администратор отзывает доступ."""
    if _pg_enabled():
        with _IA_LOCK:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "DELETE FROM ia_allowed_clients WHERE client_ip=%s RETURNING client_ip",
                        (client_ip,),
                    )
                    deleted = cur.fetchone()
                    if not deleted:
                        conn.commit()
                        return False
                    cur.execute(
                        """
                        INSERT INTO ia_history
                        (id, client_ip, action, admin_name, time, reason, comment)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (_history_id(), client_ip, "revoked", admin, _now(), "", ""),
                    )
                conn.commit()
                return True

    with _IA_LOCK:
        data = _read()
        if client_ip in data.get("allowed_clients", {}):
            del data["allowed_clients"][client_ip]
            data.setdefault("history", []).append({
                "id": f"h_{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "client_ip": client_ip,
                "action": "revoked",
                "admin": admin,
                "time": datetime.now().isoformat(timespec="seconds"),
            })
            _write(data)
            return True
        return False


# ═══════════════════════════════════════════════════════════════════════════════
#  Данные для админ-панели
# ═══════════════════════════════════════════════════════════════════════════════

def get_all_data() -> dict:
    """Все данные для страницы управления интернетом."""
    if _pg_enabled():
        with _IA_LOCK:
            with _pg_connect() as conn:
                _cleanup_expired_access_db(conn)
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT client_ip, approved_by, reason, time, expires, request_id
                        FROM ia_allowed_clients
                        ORDER BY client_ip
                        """
                    )
                    allowed_clients = {
                        row[0]: {
                            "approved_by": row[1],
                            "reason": row[2],
                            "time": row[3],
                            "expires": row[4] or "",
                            "request_id": row[5] or "",
                        }
                        for row in cur.fetchall()
                    }
                    cur.execute(
                        """
                        SELECT id, client_ip, reason, time, status,
                               approved_by, approved_time, denied_by, denied_time, admin_comment
                        FROM ia_pending_requests
                        ORDER BY time DESC
                        """
                    )
                    pending_requests = [
                        {
                            "id": row[0],
                            "client_ip": row[1],
                            "reason": row[2],
                            "time": row[3],
                            "status": row[4],
                            "approved_by": row[5] or "",
                            "approved_time": row[6] or "",
                            "denied_by": row[7] or "",
                            "denied_time": row[8] or "",
                            "admin_comment": row[9] or "",
                        }
                        for row in cur.fetchall()
                    ]
                    cur.execute(
                        """
                        SELECT id, client_ip, action, admin_name, time, reason, comment
                        FROM ia_history
                        ORDER BY time DESC
                        """
                    )
                    history = [
                        {
                            "id": row[0],
                            "client_ip": row[1],
                            "action": row[2],
                            "admin": row[3],
                            "time": row[4],
                            "reason": row[5] or "",
                            "comment": row[6] or "",
                        }
                        for row in cur.fetchall()
                    ]
                conn.commit()
                return {
                    "allowed_clients": allowed_clients,
                    "pending_requests": pending_requests,
                    "history": history,
                }

    with _IA_LOCK:
        return _read()


def get_pending_count() -> int:
    """Количество ожидающих заявок (для badge в навигации)."""
    if _pg_enabled():
        with _IA_LOCK:
            with _pg_connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT COUNT(*) FROM ia_pending_requests WHERE status='pending'"
                    )
                    count = cur.fetchone()
                conn.commit()
                return int(count[0] if count else 0)

    with _IA_LOCK:
        data = _read()
        return sum(1 for r in data.get("pending_requests", [])
                   if r.get("status") == "pending")
