# src/utils.py
# Shared utility functions used across the project.

import os
import json
import datetime
import getpass
import platform

# ──────────────────────────────────────────────
# CONFIG LOADER
# ──────────────────────────────────────────────

def load_config(config_path="config/config.json"):
    """
    Load and return the JSON configuration file.
    Raises a clear error if the file is missing or malformed.
    """
    if not os.path.exists(config_path):
        raise FileNotFoundError(
            f"[CONFIG ERROR] Config file not found: {config_path}\n"
            "Please make sure config/config.json exists."
        )
    with open(config_path, "r", encoding="utf-8") as f:
        try:
            config = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"[CONFIG ERROR] Invalid JSON in config file: {e}")
    return config


# ──────────────────────────────────────────────
# TIMESTAMP
# ──────────────────────────────────────────────

def get_timestamp():
    """Return current timestamp as a formatted string."""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_iso_timestamp():
    """Return ISO 8601 timestamp for structured logs."""
    return datetime.datetime.now().isoformat()


# ──────────────────────────────────────────────
# USER & SYSTEM INFO
# ──────────────────────────────────────────────

def get_current_user():
    """Return the currently logged-in OS username."""
    try:
        return getpass.getuser()
    except Exception:
        return "unknown_user"


def get_system_info():
    """Return basic system information as a dictionary."""
    return {
        "os": platform.system(),
        "os_version": platform.version(),
        "hostname": platform.node(),
        "python_version": platform.python_version(),
        "current_user": get_current_user(),
    }


# ──────────────────────────────────────────────
# PATH HELPERS
# ──────────────────────────────────────────────

def normalize_path(path):
    """
    Normalize a file path for consistent comparison.
    Converts backslashes to forward slashes and resolves '..'.
    """
    return os.path.normpath(path).replace("\\", "/")


def ensure_dir(path):
    """Create a directory (and parents) if it does not exist."""
    os.makedirs(path, exist_ok=True)


def get_file_size(path):
    """Return file size in bytes, or -1 if the file is inaccessible."""
    try:
        return os.path.getsize(path)
    except (OSError, FileNotFoundError):
        return -1


def get_file_extension(path):
    """Return the lowercase file extension including the dot, e.g. '.pdf'."""
    _, ext = os.path.splitext(path)
    return ext.lower()


def path_matches_pattern(path, patterns):
    """
    Check whether a file path matches any of the given glob-style patterns.
    Used to skip temporary/system files.
    """
    import fnmatch
    name = os.path.basename(path)
    for pattern in patterns:
        if fnmatch.fnmatch(name, pattern):
            return True
    return False


# ──────────────────────────────────────────────
# PROCESS INFO (optional, uses psutil)
# ──────────────────────────────────────────────

def get_process_info(pid=None):
    """
    Try to return the name of the process that owns the given PID.
    Falls back gracefully if psutil is not installed or PID is unknown.
    """
    try:
        import psutil
        if pid is None:
            return "unknown"
        proc = psutil.Process(pid)
        return proc.name()
    except Exception:
        return "unknown"
