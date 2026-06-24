# dashboard/app.py
# SentinelShield Dashboard — Flask backend
# Serves the web UI and exposes REST API endpoints that read live log/CSV data.
#
# Run from the project root:
#   python dashboard/app.py
# Then open:  http://127.0.0.1:5000

import os
import sys
import csv
import json
import datetime
from pathlib import Path
from flask import Flask, jsonify, render_template, send_from_directory

# ── resolve project root so imports work regardless of cwd ──
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.utils   import load_config
from src.reporter import generate_report

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────

def _cfg():
    try:
        return load_config(str(ROOT / "config" / "config.json"))
    except Exception:
        return {}


def _csv_path():
    cfg = _cfg()
    return ROOT / cfg.get("log_settings", {}).get("audit_csv", "logs/audit_events.csv")


def _alert_log_path():
    cfg = _cfg()
    return ROOT / cfg.get("log_settings", {}).get("alert_log", "logs/alerts.log")


def _activity_log_path():
    cfg = _cfg()
    return ROOT / cfg.get("log_settings", {}).get("activity_log", "logs/file_activity.log")


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def _read_csv():
    """Return all audit CSV rows as a list of dicts."""
    path = _csv_path()
    if not path.exists():
        return []
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def _read_log_tail(path, n=200):
    """Return last N lines of a log file."""
    if not path.exists():
        return []
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.readlines()
    return [l.rstrip() for l in lines[-n:]]


def _compute_stats(rows):
    from collections import Counter
    total        = len(rows)
    sensitive    = [r for r in rows if r.get("is_sensitive","").lower() == "true"]
    criticals    = [r for r in rows if r.get("severity") == "CRITICAL"]
    warnings     = [r for r in rows if r.get("severity") == "WARNING"]
    mismatches   = [r for r in rows if r.get("hash_status") == "MISMATCH"]
    unauthorized = [r for r in rows if r.get("dest_category") not in ("NORMAL","","None")]

    event_counts = Counter(r.get("event_type","unknown") for r in rows)
    dest_counts  = Counter(
        r.get("dest_category","NORMAL")
        for r in rows
        if r.get("dest_category") not in ("NORMAL","","None")
    )
    severity_counts = Counter(r.get("severity","INFO") for r in rows)

    # Timeline: events per minute (last 60 minutes)
    timeline = {}
    now = datetime.datetime.now()
    for r in rows:
        ts_str = r.get("timestamp","")
        try:
            ts = datetime.datetime.fromisoformat(ts_str)
            bucket = ts.strftime("%H:%M")
            timeline[bucket] = timeline.get(bucket, 0) + 1
        except Exception:
            pass

    return {
        "total":             total,
        "sensitive_count":   len(sensitive),
        "critical_count":    len(criticals),
        "warning_count":     len(warnings),
        "integrity_fails":   len(mismatches),
        "unauthorized":      len(unauthorized),
        "event_counts":      dict(event_counts),
        "dest_counts":       dict(dest_counts),
        "severity_counts":   dict(severity_counts),
        "timeline":          timeline,
    }


# ──────────────────────────────────────────────
# ROUTES — Pages
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ──────────────────────────────────────────────
# ROUTES — API
# ──────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    rows = _read_csv()
    return jsonify(_compute_stats(rows))


@app.route("/api/events")
def api_events():
    """Return all audit events, newest first."""
    rows = _read_csv()
    rows.reverse()
    return jsonify(rows[:500])  # cap at 500 for browser performance


@app.route("/api/alerts")
def api_alerts():
    """Return last 200 lines of the alert log."""
    lines = _read_log_tail(_alert_log_path(), 200)
    return jsonify({"lines": lines})


@app.route("/api/activity")
def api_activity():
    """Return last 200 lines of the activity log."""
    lines = _read_log_tail(_activity_log_path(), 200)
    return jsonify({"lines": lines})


@app.route("/api/config")
def api_config():
    """Return sanitised config (no internal paths)."""
    cfg = _cfg()
    safe = {
        "monitored_directories": cfg.get("monitored_directories", []),
        "sensitive_paths":       cfg.get("sensitive_paths", []),
        "sensitive_extensions":  cfg.get("sensitive_extensions", []),
        "hash_algorithm":        cfg.get("hash_algorithm", "sha256"),
        "allowed_users":         cfg.get("allowed_users", []),
        "monitoring_settings":   cfg.get("monitoring_settings", {}),
    }
    return jsonify(safe)


@app.route("/api/baseline")
def api_baseline():
    """Return the stored hash baseline."""
    bl_path = ROOT / "logs" / "hash_baseline.json"
    if not bl_path.exists():
        return jsonify({})
    with open(bl_path, encoding="utf-8") as f:
        return jsonify(json.load(f))


@app.route("/api/report/generate", methods=["POST"])
def api_generate_report():
    """Trigger report generation and return the report text."""
    cfg = _cfg()
    try:
        path = generate_report(config=cfg, print_report=False)
        with open(path, encoding="utf-8") as f:
            text = f.read()
        return jsonify({"success": True, "report": text, "path": str(path)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/health")
def api_health():
    return jsonify({
        "status":    "ok",
        "timestamp": datetime.datetime.now().isoformat(),
        "version":   "1.0.0",
    })


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  ╔═══════════════════════════════════════╗")
    print("  ║   SentinelShield Dashboard v1.0       ║")
    print("  ║   http://127.0.0.1:5000               ║")
    print("  ╚═══════════════════════════════════════╝\n")
    app.run(debug=True, host="127.0.0.1", port=5000)