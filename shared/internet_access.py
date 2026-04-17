"""
Internet Access Manager — управление доступом в интернет для закрытой сети.

Хранит:
  - allowed_clients: {ip: {approved_by, reason, time, expires}}
  - pending_requests: [{id, client_ip, reason, time, status}]
  - history: [{id, client_ip, action, admin, time}]

Файл: logs/internet_access.json
"""

import json
import ipaddress
import threading
from pathlib import Path
from datetime import datetime

_IA_FILE = Path(__file__).parent.parent / "logs" / "internet_access.json"
_IA_LOCK = threading.Lock()

_DEFAULT_DATA = {
    "allowed_clients": {},
    "pending_requests": [],
    "history": [],
}


def _read() -> dict:
    try:
        if _IA_FILE.exists():
            data = json.loads(_IA_FILE.read_text(encoding="utf-8"))
            for k in _DEFAULT_DATA:
                data.setdefault(k, type(_DEFAULT_DATA[k])())
            return data
    except Exception:
        pass
    return {k: type(v)() if isinstance(v, (dict, list)) else v
            for k, v in _DEFAULT_DATA.items()}


def _write(data: dict):
    try:
        _IA_FILE.parent.mkdir(parents=True, exist_ok=True)
        _IA_FILE.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8"
        )
    except Exception:
        pass


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
    with _IA_LOCK:
        return _read()


def get_pending_count() -> int:
    """Количество ожидающих заявок (для badge в навигации)."""
    with _IA_LOCK:
        data = _read()
        return sum(1 for r in data.get("pending_requests", [])
                   if r.get("status") == "pending")
