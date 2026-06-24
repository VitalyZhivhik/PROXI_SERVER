from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT_DIR / "config.json"


def _as_bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _load_config_file() -> dict:
    try:
        if CONFIG_PATH.exists():
            return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


@lru_cache(maxsize=1)
def load_storage_settings() -> dict:
    cfg = _load_config_file()

    database_url = os.getenv("DLP_DATABASE_URL") or cfg.get("database_url", "")
    s3_bucket = os.getenv("DLP_S3_BUCKET") or cfg.get("s3_bucket", "")
    s3_endpoint_url = os.getenv("DLP_S3_ENDPOINT_URL") or cfg.get("s3_endpoint_url", "")
    s3_access_key = os.getenv("DLP_S3_ACCESS_KEY") or cfg.get("s3_access_key", "")
    s3_secret_key = os.getenv("DLP_S3_SECRET_KEY") or cfg.get("s3_secret_key", "")
    s3_region = os.getenv("DLP_S3_REGION") or cfg.get("s3_region", "us-east-1")
    s3_use_ssl = _as_bool(
        os.getenv("DLP_S3_USE_SSL", cfg.get("s3_use_ssl", False)),
        default=False,
    )

    capture_storage = (
        os.getenv("DLP_CAPTURE_STORAGE")
        or cfg.get("capture_storage")
        or ("s3" if s3_bucket else "local")
    ).strip().lower()

    capture_local_dir = (
        os.getenv("DLP_CAPTURE_LOCAL_DIR")
        or cfg.get("capture_local_dir")
        or str(ROOT_DIR / "logs" / "captures")
    )

    return {
        "database_url": database_url,
        "s3_bucket": s3_bucket,
        "s3_endpoint_url": s3_endpoint_url,
        "s3_access_key": s3_access_key,
        "s3_secret_key": s3_secret_key,
        "s3_region": s3_region,
        "s3_use_ssl": s3_use_ssl,
        "capture_storage": capture_storage,
        "capture_local_dir": capture_local_dir,
    }


def get_capture_local_dir() -> Path:
    return Path(load_storage_settings()["capture_local_dir"])
