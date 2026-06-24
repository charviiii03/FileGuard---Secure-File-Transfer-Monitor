# src/logger.py
# Handles all logging: activity log, alert log, and structured CSV audit trail.

import os
import csv
import json
import logging

from src.utils import get_timestamp, get_iso_timestamp, get_current_user, ensure_dir

# ──────────────────────────────────────────────
# FILE PATHS  (can be overridden by config)
# ──────────────────────────────────────────────
ACTIVITY_LOG = "logs/file_activity.log"
ALERT_LOG    = "logs/alerts.log"
AUDIT_CSV    = "logs/audit_events.csv"

# CSV column headers – must stay in sync with _build_csv_row()
CSV_HEADERS = [
    "timestamp",
    "event_type",
    "src_path",
    "dest_path",
    "is_sensitive",
    "dest_category",
    "severity",
    "hash_status",
    "current_hash",
    "stored_hash",
    "user",
    "alert_message",
]

# ──────────────────────────────────────────────
# PYTHON LOGGING SETUP
# ──────────────────────────────────────────────

def setup_loggers(config=None):
    """
    Configure Python's built-in logging for activity and alert streams.
    Call once at startup, before any events are processed.
    """
    log_cfg = (config or {}).get("log_settings", {})

    activity_path = log_cfg.get("activity_log", ACTIVITY_LOG)
    alert_path    = log_cfg.get("alert_log",    ALERT_LOG)

    ensure_dir(os.path.dirname(activity_path))
    ensure_dir(os.path.dirname(alert_path))
    ensure_dir(os.path.dirname(log_cfg.get("audit_csv", AUDIT_CSV)))

    fmt = logging.Formatter("%(asctime)s  %(levelname)-8s  %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")

    # ── Activity logger ──
    activity_logger = logging.getLogger("activity")
    activity_logger.setLevel(logging.DEBUG)
    if not activity_logger.handlers:
        fh = logging.FileHandler(activity_path, encoding="utf-8")
        fh.setFormatter(fmt)
        activity_logger.addHandler(fh)
        activity_logger.propagate = False   # Don't bubble to root logger

    # ── Alert logger ──
    alert_logger = logging.getLogger("alert")
    alert_logger.setLevel(logging.WARNING)
    if not alert_logger.handlers:
        fh = logging.FileHandler(alert_path, encoding="utf-8")
        fh.setFormatter(fmt)
        alert_logger.addHandler(fh)
        alert_logger.propagate = False

    # ── Initialise CSV if it doesn't exist yet ──
    _init_csv(log_cfg.get("audit_csv", AUDIT_CSV))

    return activity_logger, alert_logger


def _init_csv(csv_path):
    """Create the CSV with headers if it doesn't exist."""
    if not os.path.exists(csv_path):
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()


# ──────────────────────────────────────────────
# PUBLIC LOG FUNCTIONS
# ──────────────────────────────────────────────

def log_event(analysis, config=None):
    """
    Log a single file event to:
      1. The activity log  (all events)
      2. The alert log     (WARNING and CRITICAL only)
      3. The CSV audit file

    Parameters:
        analysis – dict returned by detector.analyse_event()
        config   – loaded configuration dict (for file paths)
    """
    log_cfg   = (config or {}).get("log_settings", {})
    csv_path  = log_cfg.get("audit_csv", AUDIT_CSV)

    activity_logger = logging.getLogger("activity")
    alert_logger    = logging.getLogger("alert")

    msg = analysis.get("alert_message", "No message")

    # ── 1. Activity log (all events) ──
    activity_logger.info(msg)

    # ── 2. Alert log (WARNING / CRITICAL only) ──
    severity = analysis.get("severity", "INFO")
    if severity == "WARNING":
        alert_logger.warning(msg)
    elif severity == "CRITICAL":
        alert_logger.critical(msg)

    # ── 3. CSV audit trail ──
    _append_csv_row(analysis, csv_path)


def log_raw(message, level="INFO", config=None):
    """
    Write a freeform message directly to the activity log.
    Useful for startup/shutdown banners.
    """
    activity_logger = logging.getLogger("activity")
    level_map = {
        "DEBUG":    activity_logger.debug,
        "INFO":     activity_logger.info,
        "WARNING":  activity_logger.warning,
        "ERROR":    activity_logger.error,
        "CRITICAL": activity_logger.critical,
    }
    log_fn = level_map.get(level.upper(), activity_logger.info)
    log_fn(message)


# ──────────────────────────────────────────────
# CSV HELPERS
# ──────────────────────────────────────────────

def _build_csv_row(analysis):
    """Convert an analysis dict to a flat CSV row dict."""
    return {
        "timestamp":     get_iso_timestamp(),
        "event_type":    analysis.get("event_type", ""),
        "src_path":      analysis.get("src_path", ""),
        "dest_path":     analysis.get("dest_path", "") or "",
        "is_sensitive":  str(analysis.get("is_sensitive", False)),
        "dest_category": analysis.get("dest_category", "NORMAL"),
        "severity":      analysis.get("severity", "INFO"),
        "hash_status":   analysis.get("hash_status", "") or "",
        "current_hash":  (analysis.get("current_hash") or "")[:16] + "...",
        "stored_hash":   (analysis.get("stored_hash")  or "")[:16] + "...",
        "user":          get_current_user(),
        "alert_message": analysis.get("alert_message", ""),
    }


def _append_csv_row(analysis, csv_path):
    """Append a single row to the CSV audit file."""
    row = _build_csv_row(analysis)
    file_exists = os.path.exists(csv_path)
    try:
        with open(csv_path, "a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)
    except IOError as e:
        print(f"  [LOGGER ERROR] Could not write to CSV: {e}")


# ──────────────────────────────────────────────
# READ-BACK HELPERS (used by reporter)
# ──────────────────────────────────────────────

def read_audit_csv(config=None):
    """
    Read all rows from the CSV audit file and return them as a list of dicts.
    Returns an empty list if the file does not exist.
    """
    log_cfg  = (config or {}).get("log_settings", {})
    csv_path = log_cfg.get("audit_csv", AUDIT_CSV)

    if not os.path.exists(csv_path):
        return []

    rows = []
    try:
        with open(csv_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    except IOError as e:
        print(f"  [LOGGER ERROR] Could not read CSV: {e}")
    return rows
