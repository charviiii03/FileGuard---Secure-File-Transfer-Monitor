# src/detector.py
# Classifies file system events as normal, sensitive, or suspicious.
# Also identifies the type of suspicious destination (USB, cloud, network, etc.).

import os
from src.utils import normalize_path, get_file_extension


# ──────────────────────────────────────────────
# SENSITIVITY CLASSIFICATION
# ──────────────────────────────────────────────

def is_sensitive_file(file_path, config):
    """
    Determine whether a file is considered sensitive.

    A file is sensitive if:
      1. It lives inside one of the configured sensitive directories, OR
      2. Its extension is in the sensitive_extensions list.

    Returns:
        bool – True if the file is sensitive
    """
    norm_path = normalize_path(file_path)

    # Check against sensitive directory prefixes
    sensitive_dirs = config.get("sensitive_paths", [])
    for sens_dir in sensitive_dirs:
        norm_dir = normalize_path(sens_dir)
        if norm_path.startswith(norm_dir):
            return True

    # Check file extension
    ext = get_file_extension(file_path)
    sensitive_exts = config.get("sensitive_extensions", [])
    if ext in sensitive_exts:
        return True

    return False


# ──────────────────────────────────────────────
# DESTINATION CLASSIFICATION
# ──────────────────────────────────────────────

def classify_destination(dest_path, config):
    """
    Classify the destination of a file move/copy as one of:
      - "USB_DRIVE"
      - "NETWORK_SHARE"
      - "CLOUD_SYNC"
      - "UNKNOWN_DESTINATION"
      - "NORMAL"

    Returns:
        tuple (str, str) – (category, reason_message)
    """
    if dest_path is None:
        return ("NORMAL", "No destination path provided.")

    norm_dest = normalize_path(dest_path)

    suspicious = config.get("suspicious_destinations", {})

    # ── USB / external drives ──
    usb_paths = suspicious.get("usb_drives", [])
    for usb in usb_paths:
        if norm_dest.startswith(normalize_path(usb)):
            return ("USB_DRIVE", f"Destination matches USB/external drive path: {usb}")

    # ── Network shares ──
    net_paths = suspicious.get("network_shares", [])
    for net in net_paths:
        if net in dest_path:  # Use original path for UNC check (\\ etc.)
            return ("NETWORK_SHARE", f"Destination appears to be a network share: {net}")

    # ── Cloud sync folders ──
    cloud_names = suspicious.get("cloud_sync_folders", [])
    for cloud in cloud_names:
        if cloud.lower() in dest_path.lower():
            return ("CLOUD_SYNC", f"Destination matches cloud sync folder: {cloud}")

    # ── Configured unknown/suspicious destinations ──
    unknown_paths = suspicious.get("unknown_destinations", [])
    for unk in unknown_paths:
        if norm_dest.startswith(normalize_path(unk)):
            return ("UNKNOWN_DESTINATION", f"Destination is in suspicious location: {unk}")

    return ("NORMAL", "Destination appears safe.")


# ──────────────────────────────────────────────
# MAIN EVENT ANALYSER
# ──────────────────────────────────────────────

def analyse_event(event_type, src_path, dest_path=None, config=None, integrity_result=None):
    """
    Produce a full analysis dictionary for a file system event.

    Parameters:
        event_type       – "created" | "modified" | "deleted" | "moved"
        src_path         – source file path
        dest_path        – destination path (for moves/renames), or None
        config           – loaded configuration dictionary
        integrity_result – result dict from hashing.verify_integrity(), or None

    Returns a dict with:
        {
            "event_type":    str,
            "src_path":      str,
            "dest_path":     str or None,
            "is_sensitive":  bool,
            "dest_category": str,          # "NORMAL", "USB_DRIVE", etc.
            "dest_reason":   str,
            "severity":      str,          # "INFO" | "WARNING" | "CRITICAL"
            "alert_message": str,
            "hash_status":   str or None,
            "current_hash":  str or None,
            "stored_hash":   str or None,
        }
    """
    if config is None:
        config = {}

    sensitive = is_sensitive_file(src_path, config)

    # Classify destination (relevant for moves)
    target_path = dest_path if dest_path else src_path
    dest_category, dest_reason = classify_destination(target_path, config)

    # ── Determine severity ──
    severity = _determine_severity(
        event_type=event_type,
        is_sensitive=sensitive,
        dest_category=dest_category,
        integrity_result=integrity_result,
    )

    # ── Build human-readable alert message ──
    alert_message = _build_alert_message(
        event_type=event_type,
        src_path=src_path,
        dest_path=dest_path,
        is_sensitive=sensitive,
        dest_category=dest_category,
        dest_reason=dest_reason,
        integrity_result=integrity_result,
        severity=severity,
    )

    # Extract hash fields
    hash_status   = integrity_result["status"]        if integrity_result else None
    current_hash  = integrity_result["current_hash"]  if integrity_result else None
    stored_hash   = integrity_result["stored_hash"]   if integrity_result else None

    return {
        "event_type":    event_type,
        "src_path":      src_path,
        "dest_path":     dest_path,
        "is_sensitive":  sensitive,
        "dest_category": dest_category,
        "dest_reason":   dest_reason,
        "severity":      severity,
        "alert_message": alert_message,
        "hash_status":   hash_status,
        "current_hash":  current_hash,
        "stored_hash":   stored_hash,
    }


# ──────────────────────────────────────────────
# INTERNAL HELPERS
# ──────────────────────────────────────────────

def _determine_severity(event_type, is_sensitive, dest_category, integrity_result):
    """
    Map the combination of event characteristics to a severity level.

    Rules (highest wins):
      CRITICAL – sensitive file moved to suspicious destination
               – hash mismatch detected
      WARNING  – sensitive file created/modified/deleted
               – any file moved to suspicious destination
      INFO     – everything else
    """
    # Hash mismatch is always critical
    if integrity_result and integrity_result.get("status") == "MISMATCH":
        return "CRITICAL"

    # Sensitive file moved anywhere suspicious
    if is_sensitive and dest_category != "NORMAL":
        return "CRITICAL"

    # Any file going to a suspicious destination
    if dest_category != "NORMAL":
        return "WARNING"

    # Sensitive file activity (create/modify/delete)
    if is_sensitive:
        return "WARNING"

    return "INFO"


def _build_alert_message(event_type, src_path, dest_path, is_sensitive,
                          dest_category, dest_reason, integrity_result, severity):
    """Compose a clear, human-readable alert string."""
    parts = [f"[{severity}] {event_type.upper()}"]

    if is_sensitive:
        parts.append("⚠ SENSITIVE FILE")

    parts.append(f"| File: {src_path}")

    if dest_path:
        parts.append(f"| Dest: {dest_path}")

    if dest_category != "NORMAL":
        parts.append(f"| ⚠ Suspicious destination ({dest_category}): {dest_reason}")

    if integrity_result:
        status = integrity_result.get("status", "")
        if status == "MISMATCH":
            parts.append(
                f"| ❌ HASH MISMATCH! "
                f"stored={integrity_result.get('stored_hash','?')[:12]}... "
                f"current={integrity_result.get('current_hash','?')[:12]}..."
            )
        elif status == "MATCH":
            parts.append("| ✔ Hash OK")
        elif status == "NO_BASELINE":
            parts.append("| ℹ New file – baseline hash recorded")
        elif status == "HASH_FAILED":
            parts.append("| ⚠ Could not compute hash (file may be deleted)")

    return "  ".join(parts)
