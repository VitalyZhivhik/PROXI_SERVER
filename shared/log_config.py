"""
Unified logging configuration for DLP Proxy system
"""

import logging
import logging.handlers
from pathlib import Path
from datetime import datetime, timedelta


def cleanup_old_logs(log_dir: str = "logs", keep_days: int = 7) -> None:
    """
    Delete log files older than `keep_days` days from the log directory.
    Called automatically on every setup_logging() call.
    """
    log_path = Path(log_dir)
    if not log_path.exists():
        return

    cutoff = datetime.now() - timedelta(days=keep_days)
    deleted = []

    for f in log_path.glob("*.log*"):
        try:
            mtime = datetime.fromtimestamp(f.stat().st_mtime)
            if mtime < cutoff:
                f.unlink()
                deleted.append(f.name)
        except Exception:
            pass  # Skip locked or inaccessible files

    if deleted:
        # Print directly — logger may not be ready yet
        print(f"[LogCleanup] Удалено устаревших логов (>{keep_days} дней): {deleted}")


def setup_logging(
    component: str,
    log_dir: str = "logs",
    level: int = logging.DEBUG,
    console: bool = True,
    keep_log_days: int = 7,
) -> logging.Logger:
    """
    Setup structured logging for a component.

    Args:
        component:     Name of component (e.g. 'server', 'client', 'proxy')
        log_dir:       Directory for log files
        level:         Logging level
        console:       Whether to also log to console
        keep_log_days: Auto-delete logs older than this many days (0 = off)
    """
    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    # ── Auto-cleanup old logs on startup ──────────────────────────────────────
    if keep_log_days > 0:
        cleanup_old_logs(log_dir, keep_log_days)

    logger = logging.getLogger(component)
    logger.setLevel(level)

    # Remove existing handlers to avoid duplication on re-init
    logger.handlers.clear()

    fmt = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)-20s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # ── File handler (rotating by size: 5 MB, 10 backups) ────────────────────
    log_file = log_path / f"{component}_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=5 * 1024 * 1024,  # 5 MB per file
        backupCount=10,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    # ── Separate file for DLP block events only ───────────────────────────────
    dlp_file = log_path / "dlp_events.log"
    dlp_handler = logging.handlers.RotatingFileHandler(
        dlp_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=20,
        encoding="utf-8",
    )
    dlp_handler.setLevel(logging.WARNING)
    dlp_handler.setFormatter(fmt)
    dlp_handler.addFilter(lambda r: "DLP" in r.getMessage() or "БЛОКИРОВКА" in r.getMessage())
    logger.addHandler(dlp_handler)

    # ── Console handler ────────────────────────────────────────────────────────
    if console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(fmt)
        logger.addHandler(console_handler)

    logger.info(
        f"[Logging] Инициализирован: компонент='{component}', "
        f"файл={log_file}, хранить={keep_log_days} дней"
    )
    return logger
