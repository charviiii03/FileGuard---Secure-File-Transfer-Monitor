# src/reporter.py
# Reads the CSV audit log and generates a human-readable audit report.
# Can be run standalone:  python -m src.reporter

import os
from collections import Counter
from src.logger  import read_audit_csv
from src.utils   import load_config, get_timestamp, ensure_dir

REPORT_FILE = "reports/audit_report.txt"


# ──────────────────────────────────────────────
# STAT BUILDERS
# ──────────────────────────────────────────────

def _compute_stats(rows):
    """
    Crunch the CSV rows into a summary statistics dict.
    """
    total          = len(rows)
    sensitive      = [r for r in rows if r.get("is_sensitive", "").lower() == "true"]
    warnings       = [r for r in rows if r.get("severity") == "WARNING"]
    criticals      = [r for r in rows if r.get("severity") == "CRITICAL"]
    mismatches     = [r for r in rows if r.get("hash_status") == "MISMATCH"]
    unauthorized   = [r for r in rows if r.get("dest_category") not in ("NORMAL", "")]

    event_counts     = Counter(r.get("event_type", "unknown") for r in rows)
    dest_categories  = Counter(
        r.get("dest_category", "NORMAL")
        for r in rows
        if r.get("dest_category") not in ("NORMAL", "")
    )

    return {
        "total":           total,
        "sensitive_count": len(sensitive),
        "warning_count":   len(warnings),
        "critical_count":  len(criticals),
        "integrity_fails": len(mismatches),
        "unauthorized":    len(unauthorized),
        "event_counts":    dict(event_counts),
        "dest_breakdown":  dict(dest_categories),
        "sensitive_rows":  sensitive,
        "mismatch_rows":   mismatches,
        "unauthorized_rows": unauthorized,
    }


# ──────────────────────────────────────────────
# REPORT BUILDER
# ──────────────────────────────────────────────

def generate_report(config=None, output_path=None, print_report=True):
    """
    Read the audit CSV and write a formatted report.

    Parameters:
        config      – loaded config dict (optional; used for file paths)
        output_path – override the output path (optional)
        print_report – if True, also print to terminal

    Returns:
        str – path to the written report file
    """
    rows = read_audit_csv(config)
    stats = _compute_stats(rows)

    log_cfg = (config or {}).get("log_settings", {})
    report_path = output_path or log_cfg.get("report_file", REPORT_FILE)
    ensure_dir(os.path.dirname(report_path))

    lines = _build_report_lines(stats)
    report_text = "\n".join(lines)

    # Write to file
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    if print_report:
        print(report_text)

    print(f"\n  [REPORT] Report saved to: {os.path.abspath(report_path)}")
    return report_path


def _build_report_lines(stats):
    """Return the report as a list of strings (one per line)."""
    sep = "=" * 65
    thin = "-" * 65
    ts = get_timestamp()

    lines = [
        sep,
        "    SECURE FILE TRANSFER MONITOR – AUDIT REPORT",
        f"    Generated: {ts}",
        sep,
        "",
        "  SUMMARY",
        thin,
        f"    Total events recorded       : {stats['total']}",
        f"    Sensitive file events       : {stats['sensitive_count']}",
        f"    WARNING-level events        : {stats['warning_count']}",
        f"    CRITICAL-level events       : {stats['critical_count']}",
        f"    Unauthorized movements      : {stats['unauthorized']}",
        f"    Integrity failures (mismatch): {stats['integrity_fails']}",
        "",
        "  EVENT TYPE BREAKDOWN",
        thin,
    ]

    if stats["event_counts"]:
        for etype, count in sorted(stats["event_counts"].items()):
            lines.append(f"    {etype:<20} : {count}")
    else:
        lines.append("    No events recorded.")

    lines += [
        "",
        "  SUSPICIOUS DESTINATION BREAKDOWN",
        thin,
    ]

    if stats["dest_breakdown"]:
        for category, count in sorted(stats["dest_breakdown"].items()):
            lines.append(f"    {category:<25} : {count}")
    else:
        lines.append("    No suspicious transfers detected.")

    # ── Integrity failures ──
    if stats["mismatch_rows"]:
        lines += [
            "",
            "  INTEGRITY FAILURES (Hash Mismatches)",
            thin,
        ]
        for row in stats["mismatch_rows"]:
            lines.append(f"    [{row.get('timestamp','')}]  {row.get('src_path','')}")
            lines.append(f"      Stored hash : {row.get('stored_hash','')}")
            lines.append(f"      Current hash: {row.get('current_hash','')}")

    # ── Unauthorised movements ──
    if stats["unauthorized_rows"]:
        lines += [
            "",
            "  UNAUTHORIZED TRANSFER DETAILS",
            thin,
        ]
        for row in stats["unauthorized_rows"]:
            lines.append(
                f"    [{row.get('timestamp','')}]  "
                f"{row.get('event_type','').upper():<10}  "
                f"{row.get('dest_category',''):<20}  "
                f"{row.get('src_path','')}"
            )
            if row.get("dest_path"):
                lines.append(f"      → {row['dest_path']}")

    # ── Sensitive events ──
    if stats["sensitive_rows"]:
        lines += [
            "",
            "  SENSITIVE FILE EVENTS",
            thin,
        ]
        for row in stats["sensitive_rows"][:50]:  # cap at 50 for readability
            lines.append(
                f"    [{row.get('timestamp','')}]  "
                f"[{row.get('severity','INFO'):<8}]  "
                f"{row.get('event_type','').upper():<10}  "
                f"{row.get('src_path','')}"
            )
        if len(stats["sensitive_rows"]) > 50:
            lines.append(f"    ... and {len(stats['sensitive_rows'])-50} more.")

    lines += [
        "",
        sep,
        "    END OF REPORT",
        sep,
        "",
    ]
    return lines


# ──────────────────────────────────────────────
# CLI ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    try:
        cfg = load_config("config/config.json")
    except FileNotFoundError:
        cfg = {}
    generate_report(config=cfg, print_report=True)
