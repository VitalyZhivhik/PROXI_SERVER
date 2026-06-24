from __future__ import annotations

import hashlib
import mimetypes
from datetime import datetime
from pathlib import Path

from shared.storage_config import get_capture_local_dir, load_storage_settings

try:
    import boto3
except ImportError:
    boto3 = None


def _build_capture_name(event_id: str, ext: str, original_name: str = "") -> str:
    normalized_ext = (ext or "").strip().lstrip(".")
    if normalized_ext and normalized_ext != "bin":
        return f"{event_id}.{normalized_ext}"
    if original_name:
        original_ext = Path(original_name).suffix.lstrip(".")
        if original_ext:
            return f"{event_id}.{original_ext}"
    return f"{event_id}.bin"


def _s3_enabled(settings: dict) -> bool:
    return settings.get("capture_storage") == "s3" and bool(settings.get("s3_bucket"))


def _get_s3_client(settings: dict):
    if not boto3:
        return None

    client_args = {
        "service_name": "s3",
        "region_name": settings.get("s3_region") or "us-east-1",
        "aws_access_key_id": settings.get("s3_access_key") or None,
        "aws_secret_access_key": settings.get("s3_secret_key") or None,
        "use_ssl": settings.get("s3_use_ssl", False),
    }
    if settings.get("s3_endpoint_url"):
        client_args["endpoint_url"] = settings["s3_endpoint_url"]

    return boto3.client(**client_args)


def store_capture(data: bytes, event_id: str, ext: str, original_name: str = "") -> str | None:
    if not data or len(data) < 10:
        return None

    filename = _build_capture_name(event_id, ext, original_name)
    settings = load_storage_settings()

    if _s3_enabled(settings):
        s3 = _get_s3_client(settings)
        if s3:
            try:
                key = datetime.utcnow().strftime(f"captures/%Y/%m/%d/{filename}")
                s3.put_object(
                    Bucket=settings["s3_bucket"],
                    Key=key,
                    Body=data,
                    ContentType=mimetypes.guess_type(original_name or filename)[0]
                    or "application/octet-stream",
                    Metadata={
                        "event-id": event_id,
                        "original-name": (original_name or filename)[:200],
                        "sha256": hashlib.sha256(data).hexdigest(),
                    },
                )
                return key
            except Exception:
                pass

    local_dir = get_capture_local_dir()
    local_dir.mkdir(parents=True, exist_ok=True)
    fpath = local_dir / filename
    fpath.write_bytes(data)
    return filename


def get_capture_bytes(capture_ref: str) -> bytes | None:
    if not capture_ref:
        return None

    local_path = get_capture_local_dir() / Path(capture_ref).name
    if local_path.exists():
        return local_path.read_bytes()

    settings = load_storage_settings()
    if _s3_enabled(settings):
        s3 = _get_s3_client(settings)
        if s3:
            response = s3.get_object(Bucket=settings["s3_bucket"], Key=capture_ref)
            return response["Body"].read()

    return None


def get_capture_display_name(capture_ref: str) -> str:
    return Path(capture_ref).name if capture_ref else ""
