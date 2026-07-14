# dashboard/app.py
# FileGuard Dashboard — Flask backend
# Run:  python dashboard/app.py
# Open: http://127.0.0.1:5001

import sys
import csv
import json
import datetime
from pathlib import Path

from flask import (
    Flask,
    jsonify,
    render_template,
    send_from_directory,
    url_for,
)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.utils import load_config
from src.reporter import generate_report
from src.pdf_reporter import create_pdf_report


app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static",
)

# Folder in which generated PDF reports will be stored.
PDF_REPORT_DIR = ROOT / "reports" / "pdf"
PDF_REPORT_DIR.mkdir(parents=True, exist_ok=True)


# ── CONFIG ───────────────────────────────────────────────────────────────────

def _cfg():
    try:
        return load_config(str(ROOT / "config" / "config.json"))
    except Exception as exc:
        print(f"[FileGuard] Could not load configuration: {exc}")
        return {}


def _csv_path():
    cfg = _cfg()
    return ROOT / cfg.get(
        "log_settings", {}
    ).get(
        "audit_csv",
        "logs/audit_events.csv",
    )


def _alert_log_path():
    cfg = _cfg()
    return ROOT / cfg.get(
        "log_settings", {}
    ).get(
        "alert_log",
        "logs/alerts.log",
    )


def _activity_log_path():
    cfg = _cfg()
    return ROOT / cfg.get(
        "log_settings", {}
    ).get(
        "activity_log",
        "logs/file_activity.log",
    )


# ── HELPERS ──────────────────────────────────────────────────────────────────

def _read_csv():
    path = _csv_path()

    if not path.exists():
        return []

    rows = []

    try:
        with open(path, newline="", encoding="utf-8") as file:
            for row in csv.DictReader(file):
                rows.append(row)
    except Exception as exc:
        print(f"[FileGuard] Could not read audit CSV: {exc}")

    return rows


def _read_log_tail(path, n=200):
    if not path.exists():
        return []

    try:
        with open(path, encoding="utf-8", errors="replace") as file:
            lines = file.readlines()

        return [line.rstrip() for line in lines[-n:]]
    except Exception as exc:
        print(f"[FileGuard] Could not read log file: {exc}")
        return []


def _compute_stats(rows):
    from collections import Counter

    total = len(rows)

    sensitive = [
        row
        for row in rows
        if row.get("is_sensitive", "").lower() == "true"
    ]

    criticals = [
        row
        for row in rows
        if row.get("severity", "").upper() == "CRITICAL"
    ]

    warnings = [
        row
        for row in rows
        if row.get("severity", "").upper() == "WARNING"
    ]

    mismatches = [
        row
        for row in rows
        if row.get("hash_status", "").upper() == "MISMATCH"
    ]

    unauthorized = [
        row
        for row in rows
        if row.get("dest_category") not in (
            "NORMAL",
            "",
            None,
            "None",
        )
    ]

    event_counts = Counter(
        row.get("event_type", "unknown")
        for row in rows
    )

    dest_counts = Counter(
        row.get("dest_category", "NORMAL")
        for row in rows
        if row.get("dest_category") not in (
            "NORMAL",
            "",
            None,
            "None",
        )
    )

    severity_counts = Counter(
        row.get("severity", "INFO")
        for row in rows
    )

    timeline = {}

    for row in rows:
        timestamp_text = row.get("timestamp", "")

        try:
            timestamp = datetime.datetime.fromisoformat(timestamp_text)
            bucket = timestamp.strftime("%H:%M")
            timeline[bucket] = timeline.get(bucket, 0) + 1
        except (TypeError, ValueError):
            continue

    return {
        "total": total,
        "sensitive_count": len(sensitive),
        "critical_count": len(criticals),
        "warning_count": len(warnings),
        "integrity_fails": len(mismatches),
        "unauthorized": len(unauthorized),
        "event_counts": dict(event_counts),
        "dest_counts": dict(dest_counts),
        "severity_counts": dict(severity_counts),
        "timeline": timeline,
    }


# ── ROUTES — PAGE ────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


# ── ROUTES — API ─────────────────────────────────────────────────────────────

@app.route("/api/stats")
def api_stats():
    return jsonify(_compute_stats(_read_csv()))


@app.route("/api/events")
def api_events():
    rows = _read_csv()
    rows.reverse()
    return jsonify(rows[:500])


@app.route("/api/alerts")
def api_alerts():
    return jsonify({
        "lines": _read_log_tail(_alert_log_path(), 200),
    })


@app.route("/api/activity")
def api_activity():
    return jsonify({
        "lines": _read_log_tail(_activity_log_path(), 200),
    })


@app.route("/api/config")
def api_config():
    cfg = _cfg()

    return jsonify({
        "monitored_directories": cfg.get(
            "monitored_directories",
            [],
        ),
        "sensitive_paths": cfg.get(
            "sensitive_paths",
            [],
        ),
        "sensitive_extensions": cfg.get(
            "sensitive_extensions",
            [],
        ),
        "hash_algorithm": cfg.get(
            "hash_algorithm",
            "sha256",
        ),
        "allowed_users": cfg.get(
            "allowed_users",
            [],
        ),
        "monitoring_settings": cfg.get(
            "monitoring_settings",
            {},
        ),
    })


@app.route("/api/baseline")
def api_baseline():
    baseline_path = ROOT / "logs" / "hash_baseline.json"

    if not baseline_path.exists():
        return jsonify({})

    try:
        with open(baseline_path, encoding="utf-8") as file:
            return jsonify(json.load(file))
    except (OSError, json.JSONDecodeError) as exc:
        return jsonify({
            "success": False,
            "error": f"Could not read baseline file: {exc}",
        }), 500


# ── TEXT REPORT ──────────────────────────────────────────────────────────────

@app.route("/api/report/generate", methods=["POST"])
def api_generate_report():
    """
    Generate the normal text report and return it for dashboard preview.
    """
    try:
        report_path = Path(
            generate_report(
                config=_cfg(),
                print_report=False,
            )
        )

        report_text = report_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        return jsonify({
            "success": True,
            "report": report_text,
            "path": str(report_path),
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 500


# ── PDF REPORT ───────────────────────────────────────────────────────────────

@app.route("/api/report/pdf/generate", methods=["POST"])
def api_generate_pdf_report():
    """
    Generate a fresh text report, convert it to PDF, and return
    the URL that the frontend can use to download it.
    """
    try:
        # First create/update the normal text audit report.
        text_report_path = Path(
            generate_report(
                config=_cfg(),
                print_report=False,
            )
        )

        report_text = text_report_path.read_text(
            encoding="utf-8",
            errors="replace",
        )

        # Use a unique timestamp so previous reports are not overwritten.
        timestamp = datetime.datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )

        filename = (
            f"fileguard_security_report_{timestamp}.pdf"
        )

        pdf_path = PDF_REPORT_DIR / filename

        # Convert the text report into a downloadable PDF.
        create_pdf_report(
            report_text=report_text,
            output_path=pdf_path,
        )

        return jsonify({
            "success": True,
            "message": "PDF report generated successfully.",
            "report": report_text,
            "filename": filename,
            "download_url": url_for(
                "api_download_pdf_report",
                filename=filename,
            ),
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 500


@app.route("/api/report/pdf/download/<path:filename>")
def api_download_pdf_report(filename):
    """
    Download a previously generated PDF report.
    """

    # Remove directory components to prevent path traversal.
    safe_filename = Path(filename).name

    if safe_filename != filename:
        return jsonify({
            "success": False,
            "error": "Invalid report filename.",
        }), 400

    if not safe_filename.lower().endswith(".pdf"):
        return jsonify({
            "success": False,
            "error": "Only PDF reports can be downloaded.",
        }), 400

    report_path = PDF_REPORT_DIR / safe_filename

    if not report_path.is_file():
        return jsonify({
            "success": False,
            "error": "The requested PDF report was not found.",
        }), 404

    return send_from_directory(
        directory=str(PDF_REPORT_DIR),
        path=safe_filename,
        as_attachment=True,
        download_name=safe_filename,
        mimetype="application/pdf",
    )


@app.route("/api/health")
def api_health():
    return jsonify({
        "status": "ok",
        "timestamp": datetime.datetime.now().isoformat(),
        "version": "2.1.0",
        "pdf_reports": True,
    })


# ── MAIN ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n  ╔══════════════════════════════════════════╗")
    print("  ║   FileGuard Dashboard v2.1              ║")
    print("  ║   http://127.0.0.1:5001                 ║")
    print("  ║   PDF report generation enabled         ║")
    print("  ╚══════════════════════════════════════════╝\n")

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5001,
    )