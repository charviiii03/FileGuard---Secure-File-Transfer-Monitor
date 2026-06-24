#!/usr/bin/env python3
# demo_test.py
# ─────────────────────────────────────────────────────────────────────────────
# Automated demo that tests the core components WITHOUT needing a running
# monitor.  It directly invokes hashing, detector, logger, and reporter so
# you can verify everything works before starting the live monitor.
#
# Run with:
#   python demo_test.py
# ─────────────────────────────────────────────────────────────────────────────

import os
import sys
import time
import shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils    import load_config, ensure_dir, get_timestamp
from src.hashing  import compute_hash, store_baseline, verify_integrity, load_baseline_from_disk
from src.detector import analyse_event, is_sensitive_file, classify_destination
from src.logger   import setup_loggers, log_event
from src.reporter import generate_report

# ── Optional colour ──
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    G = Fore.GREEN;  Y = Fore.YELLOW;  R = Fore.RED;  C = Fore.CYAN;  RST = Style.RESET_ALL
except ImportError:
    G = Y = R = C = RST = ""

PASS = f"{G}PASS{RST}"
FAIL = f"{R}FAIL{RST}"

results = []  # collect (test_name, passed)


def section(title):
    print(f"\n{C}{'─'*60}{RST}")
    print(f"{C}  {title}{RST}")
    print(f"{C}{'─'*60}{RST}")


def check(label, condition):
    status = PASS if condition else FAIL
    print(f"    [{status}] {label}")
    results.append((label, condition))


# ──────────────────────────────────────────────
# TEST 1 – Config loading
# ──────────────────────────────────────────────

section("TEST 1: Config Loading")
try:
    config = load_config("config/config.json")
    check("Config loaded successfully", True)
    check("monitored_directories present", "monitored_directories" in config)
    check("sensitive_paths present",       "sensitive_paths"       in config)
    check("hash_algorithm is sha256",      config.get("hash_algorithm") == "sha256")
except Exception as e:
    check(f"Config load FAILED: {e}", False)
    config = {}


# ──────────────────────────────────────────────
# TEST 2 – Hashing
# ──────────────────────────────────────────────

section("TEST 2: SHA-256 Hashing")

test_file = "test_data/sensitive/employee_records.txt"
ensure_dir("test_data/sensitive")

# Create if it doesn't exist
if not os.path.exists(test_file):
    with open(test_file, "w") as f:
        f.write("Original sensitive content.\n")

h1 = compute_hash(test_file)
check("Hash computed for existing file",   h1 is not None)
check("Hash is 64 hex chars (SHA-256)",    h1 and len(h1) == 64)

# Hash a non-existent file
h_missing = compute_hash("test_data/does_not_exist.txt")
check("Returns None for missing file",     h_missing is None)

# Baseline store/retrieve
store_baseline(test_file, h1)
retrieved = verify_integrity(test_file)
check("Baseline stored and verified",      retrieved["status"] == "MATCH")

# Simulate modification (write different content, re-verify)
with open(test_file, "w") as f:
    f.write("TAMPERED content!\n")

tampered_result = verify_integrity(test_file)
check("Detects hash mismatch after modification", tampered_result["status"] == "MISMATCH")

# Restore original content
with open(test_file, "w") as f:
    f.write("Original sensitive content.\n")

# Rebuild baseline for restored file
new_hash = compute_hash(test_file)
store_baseline(test_file, new_hash)


# ──────────────────────────────────────────────
# TEST 3 – Sensitivity Detection
# ──────────────────────────────────────────────

section("TEST 3: Sensitivity Detection")

check("employee_records.txt is sensitive",
      is_sensitive_file("test_data/sensitive/employee_records.txt", config))

check("normal/photo.jpg is NOT sensitive",
      not is_sensitive_file("test_data/normal/photo.jpg", config))

check(".pdf extension is sensitive",
      is_sensitive_file("test_data/normal/report.pdf", config))

check(".jpg extension is NOT sensitive",
      not is_sensitive_file("test_data/normal/photo.jpg", config))

# Note: .txt IS in the sensitive_extensions list in config.json, so
# test_data/normal/readme_normal.txt correctly counts as sensitive.
check(".txt extension is sensitive (per config)",
      is_sensitive_file("test_data/normal/readme_normal.txt", config))


# ──────────────────────────────────────────────
# TEST 4 – Destination Classification
# ──────────────────────────────────────────────

section("TEST 4: Destination Classification")

cat_usb,   _ = classify_destination("/media/usb_drive/file.txt",   config)
cat_cloud, _ = classify_destination("C:/Users/Me/OneDrive/doc.pdf", config)
cat_net,   _ = classify_destination("\\\\server\\share\\file.txt", config)
cat_unk,   _ = classify_destination("test_data/suspicious_dest/x", config)
cat_norm,  _ = classify_destination("test_data/normal/x.txt",      config)

check("USB path classified as USB_DRIVE",         cat_usb   == "USB_DRIVE")
check("OneDrive path classified as CLOUD_SYNC",   cat_cloud == "CLOUD_SYNC")
check("UNC path classified as NETWORK_SHARE",     cat_net   == "NETWORK_SHARE")
check("suspicious_dest classified UNKNOWN_DEST",  cat_unk   == "UNKNOWN_DESTINATION")
check("Normal path classified as NORMAL",         cat_norm  == "NORMAL")


# ──────────────────────────────────────────────
# TEST 5 – Event Analysis (detector)
# ──────────────────────────────────────────────

section("TEST 5: Event Analysis & Severity")

# Sensitive file → WARNING
a1 = analyse_event("created", "test_data/sensitive/secret.pdf", config=config)
check("Sensitive CREATE is WARNING",  a1["severity"] == "WARNING")
check("is_sensitive is True",         a1["is_sensitive"] is True)

# Non-sensitive file (.jpg not in sensitive_extensions) → INFO
a2 = analyse_event("created", "test_data/normal/photo.jpg", config=config)
check("Normal CREATE is INFO",        a2["severity"] == "INFO")

# Sensitive moved to USB → CRITICAL
a3 = analyse_event(
    "moved",
    "test_data/sensitive/payroll.xlsx",
    dest_path="/media/usb/payroll.xlsx",
    config=config,
)
check("Sensitive file moved to USB is CRITICAL",   a3["severity"] == "CRITICAL")
check("Destination category is USB_DRIVE",         a3["dest_category"] == "USB_DRIVE")

# Hash mismatch → CRITICAL
mismatch_result = {
    "status": "MISMATCH",
    "current_hash": "aaaa" * 16,
    "stored_hash":  "bbbb" * 16,
}
a4 = analyse_event(
    "modified",
    "test_data/sensitive/employee_records.txt",
    config=config,
    integrity_result=mismatch_result,
)
check("Hash mismatch event is CRITICAL",  a4["severity"] == "CRITICAL")


# ──────────────────────────────────────────────
# TEST 6 – Logging
# ──────────────────────────────────────────────

section("TEST 6: Logging to Files")

setup_loggers(config)

# Log a few test events
events_to_log = [a1, a2, a3, a4]
for ev in events_to_log:
    ev["timestamp"] = get_timestamp()
    log_event(ev, config)

activity_log = config.get("log_settings", {}).get("activity_log", "logs/file_activity.log")
alert_log    = config.get("log_settings", {}).get("alert_log",    "logs/alerts.log")
audit_csv    = config.get("log_settings", {}).get("audit_csv",    "logs/audit_events.csv")

check("Activity log exists",       os.path.exists(activity_log))
check("Alert log exists",          os.path.exists(alert_log))
check("Audit CSV exists",          os.path.exists(audit_csv))
check("Activity log has content",  os.path.getsize(activity_log) > 0)


# ──────────────────────────────────────────────
# TEST 7 – Report Generation
# ──────────────────────────────────────────────

section("TEST 7: Report Generation")

report_path = generate_report(config=config, print_report=False)
check("Report file created",       os.path.exists(report_path))
check("Report has content",        os.path.getsize(report_path) > 100)

with open(report_path, "r") as f:
    report_text = f.read()
check("Report contains SUMMARY",    "SUMMARY" in report_text)
check("Report contains event types","EVENT TYPE BREAKDOWN" in report_text)

print(f"\n  {Y}Preview of report (first 600 chars):{RST}")
print(report_text[:600])


# ──────────────────────────────────────────────
# FINAL SUMMARY
# ──────────────────────────────────────────────

section("FINAL RESULTS")

passed = sum(1 for _, ok in results if ok)
failed = sum(1 for _, ok in results if not ok)
total  = len(results)

print(f"\n  {G}{passed}/{total} tests passed.{RST}")
if failed:
    print(f"  {R}{failed} test(s) FAILED:{RST}")
    for name, ok in results:
        if not ok:
            print(f"    {R}✗ {name}{RST}")
else:
    print(f"  {G}All tests passed! The project is ready.{RST}")
    print(f"\n  Next step: run  {C}python main.py{RST}  to start live monitoring.")

print()
