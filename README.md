# 🔒 Secure File Transfer Monitoring System

A Python-based cybersecurity tool that monitors file system activity, detects
unauthorized movement of sensitive files, verifies file integrity with SHA-256
hashing, and generates structured audit reports.

---

## 📁 Project Structure

```
secure_file_transfer_monitor/
│
├── main.py                    ← Entry point
├── requirements.txt
├── README.md
│
├── config/
│   └── config.json            ← All settings (paths, extensions, destinations)
│
├── src/
│   ├── __init__.py
│   ├── monitor.py             ← watchdog Observer + event handler
│   ├── hashing.py             ← SHA-256 hashing + baseline management
│   ├── detector.py            ← Classifies events (normal/sensitive/suspicious)
│   ├── logger.py              ← Activity log, alert log, CSV audit trail
│   ├── reporter.py            ← Generates final audit report
│   └── utils.py               ← Shared helpers (config loader, timestamps, etc.)
│
├── logs/
│   ├── file_activity.log      ← All file events
│   ├── alerts.log             ← WARNING + CRITICAL alerts only
│   ├── audit_events.csv       ← Structured event audit trail
│   └── hash_baseline.json     ← Persisted SHA-256 baselines (auto-created)
│
├── reports/
│   └── audit_report.txt       ← Final human-readable report
│
└── test_data/
    ├── sensitive/             ← Simulated sensitive files (monitored)
    ├── normal/                ← Normal files (monitored)
    └── suspicious_dest/       ← Simulated suspicious destination
```

---

## ⚙️ Setup

### 1. Prerequisites
- Python 3.8 or newer
- pip

### 2. Install dependencies

```bash
cd secure_file_transfer_monitor
pip install -r requirements.txt
```

Dependencies:
| Package    | Purpose                             |
|------------|-------------------------------------|
| watchdog   | Real-time file system monitoring    |
| psutil     | Process name lookup (optional)      |
| colorama   | Coloured terminal output            |

---

## 🚀 Running the Monitor

### Start monitoring (normal mode)

```bash
python main.py
```

- Loads `config/config.json`
- Builds SHA-256 baselines for all files in monitored directories
- Starts watching for file events
- Prints coloured alerts to the terminal in real time
- Press **Ctrl+C** to stop — a final audit report is auto-generated

### Generate a report from existing logs (no monitoring)

```bash
python -m src.reporter
# or
python main.py --report
```

### Rebuild hash baselines only

```bash
python main.py --build-baseline
```

### Use a custom config file

```bash
python main.py --config path/to/my_config.json
```

---

## 🧪 Testing Step-by-Step

Open **two terminal windows**. In terminal 1, start the monitor:

```bash
python main.py
```

In terminal 2, run these operations and watch terminal 1 for alerts:

### Test 1 – Create a normal file (INFO)
```bash
echo "hello" > test_data/normal/new_file.txt
```
Expected: `[INFO] CREATED | File: test_data/normal/new_file.txt`

### Test 2 – Create a sensitive file (WARNING)
```bash
echo "secret data" > test_data/sensitive/secret.txt
```
Expected: `[WARNING] CREATED ⚠ SENSITIVE FILE | ...`

### Test 3 – Modify a sensitive file to trigger hash mismatch (CRITICAL)
```bash
# First, let the baseline be created (step 2 above).
# Then modify it:
echo "tampered content" >> test_data/sensitive/secret.txt
```
Expected: `[CRITICAL] MODIFIED ... ❌ HASH MISMATCH!`

### Test 4 – Move a sensitive file to suspicious destination (CRITICAL)
```bash
# Linux/macOS
mv test_data/sensitive/employee_records.txt test_data/suspicious_dest/

# Windows
move test_data\sensitive\employee_records.txt test_data\suspicious_dest\
```
Expected: `[CRITICAL] MOVED ⚠ SENSITIVE FILE | ⚠ Suspicious destination (UNKNOWN_DESTINATION)`

### Test 5 – Delete a file
```bash
rm test_data/normal/new_file.txt          # Linux/macOS
del test_data\normal\new_file.txt         # Windows
```
Expected: `[INFO] DELETED | File: ...`

### Test 6 – Generate report
Press Ctrl+C in terminal 1, or in terminal 2 run:
```bash
python main.py --report
```

---

## 📊 Expected Output

### Terminal (coloured)
```
  2025-01-15 14:23:01  [INFO] CREATED  | File: test_data/normal/new_file.txt  | ℹ New file – baseline hash recorded
  2025-01-15 14:23:15  [WARNING] CREATED ⚠ SENSITIVE FILE  | File: test_data/sensitive/secret.txt
  2025-01-15 14:23:30  [CRITICAL] MODIFIED ⚠ SENSITIVE FILE  | File: test_data/sensitive/secret.txt  | ❌ HASH MISMATCH! stored=3a7f... current=9b2c...
```

### Audit Report (`reports/audit_report.txt`)
```
=================================================================
    SECURE FILE TRANSFER MONITORING SYSTEM – AUDIT REPORT
    Generated: 2025-01-15 14:30:00
=================================================================

  SUMMARY
-----------------------------------------------------------------
    Total events recorded        : 12
    Sensitive file events        : 5
    WARNING-level events         : 3
    CRITICAL-level events        : 2
    Unauthorized movements       : 1
    Integrity failures (mismatch): 1

  EVENT TYPE BREAKDOWN
-----------------------------------------------------------------
    created              : 4
    deleted              : 2
    modified             : 5
    moved                : 1
```

---

## ⚙️ Configuration Reference (`config/config.json`)

| Key                        | Description                                              |
|----------------------------|----------------------------------------------------------|
| `monitored_directories`    | Directories to watch for file events                     |
| `sensitive_paths`          | Directories whose files are always treated as sensitive  |
| `sensitive_extensions`     | File extensions treated as sensitive (e.g. `.pdf`, `.csv`) |
| `suspicious_destinations`  | Paths/keywords that flag a move as unauthorized          |
| `allowed_users`            | Users considered trusted (informational)                 |
| `hash_algorithm`           | Hash algorithm (`sha256` recommended)                    |
| `monitoring_settings`      | `recursive`, `ignore_patterns`, hash-on-event toggles    |
| `log_settings`             | File paths for all log outputs                           |
| `alert_settings`           | Terminal print toggle, severity colour mapping           |

### Adding your own sensitive directories
Edit `config/config.json`:
```json
"monitored_directories": [
  "C:/Users/YourName/Documents",
  "C:/Projects/SecretProject"
],
"sensitive_paths": [
  "C:/Users/YourName/Documents"
]
```

---

## 🛡️ How It Works

```
File Event (watchdog)
       │
       ▼
 SecureFileEventHandler
       │
       ├── Filter ignored patterns (.tmp, .pyc …)
       ├── Compute SHA-256 hash
       ├── Compare against stored baseline
       │
       ▼
 detector.analyse_event()
       │
       ├── is_sensitive_file()  ← checks path + extension
       ├── classify_destination() ← USB? cloud? network? unknown?
       ├── _determine_severity() ← INFO / WARNING / CRITICAL
       │
       ▼
 logger.log_event()
       │
       ├── logs/file_activity.log  (all events)
       ├── logs/alerts.log         (WARNING + CRITICAL)
       └── logs/audit_events.csv   (structured rows)
```

---

## 📝 Notes

- **Cross-platform**: Works on Windows, macOS, and Linux.
  Paths in `config.json` use forward slashes by default but the code normalises
  both `/` and `\` for comparison.
- **No crash on missing files**: If a file is deleted before it can be hashed,
  the system logs a warning and continues.
- **psutil is optional**: Process name lookup is attempted but falls back to
  `"unknown"` gracefully.
- **Baseline persistence**: Hash baselines are saved to `logs/hash_baseline.json`
  and reloaded on the next run, so integrity checks survive restarts.

---

## 📄 License

For educational and internal security auditing use.
