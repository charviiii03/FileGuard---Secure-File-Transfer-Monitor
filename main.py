#!/usr/bin/env python3
# main.py
# Entry point for the Secure File Transfer Monitoring System.
#
# Usage:
#   python main.py                  – start monitoring (Ctrl+C to stop + report)
#   python main.py --report         – generate report from existing logs and exit
#   python main.py --build-baseline – scan monitored dirs and build hash baselines
#   python main.py --help           – show help

import os
import sys
import argparse

# ── Make sure we can import from 'src' whether we run from the project root
#    or from somewhere else. ──
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils    import load_config, get_timestamp, ensure_dir
from src.hashing  import load_baseline_from_disk, build_baseline_for_directory
from src.logger   import setup_loggers, log_raw
from src.monitor  import FileSystemMonitor
from src.reporter import generate_report

# ── Optional colour output ──
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    def banner_color(text): return Fore.CYAN + text + Style.RESET_ALL
    def ok_color(text):     return Fore.GREEN + text + Style.RESET_ALL
except ImportError:
    def banner_color(text): return text
    def ok_color(text):     return text


# ──────────────────────────────────────────────
# BANNER
# ──────────────────────────────────────────────

BANNER = r"""
  ╔══════════════════════════════════════════════════════════╗
  ║      SECURE FILE TRANSFER MONITORING SYSTEM              ║
  ║      Powered by watchdog + hashlib + psutil              ║
  ╚══════════════════════════════════════════════════════════╝
"""


def print_banner():
    print(banner_color(BANNER))


# ──────────────────────────────────────────────
# ARGUMENT PARSING
# ──────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Secure File Transfer Monitoring System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py                       Start monitoring (Ctrl+C to stop)
  python main.py --report              Generate audit report from existing logs
  python main.py --build-baseline      Scan dirs and create SHA-256 baselines
  python main.py --config my.json      Use a custom config file
        """,
    )
    parser.add_argument(
        "--config",
        default="config/config.json",
        help="Path to JSON config file (default: config/config.json)",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate an audit report from existing logs and exit",
    )
    parser.add_argument(
        "--build-baseline",
        action="store_true",
        help="Build or refresh SHA-256 baselines for all monitored directories",
    )
    return parser.parse_args()


# ──────────────────────────────────────────────
# SETUP HELPERS
# ──────────────────────────────────────────────

def ensure_project_dirs():
    """Create required directories if they don't already exist."""
    for d in ["logs", "reports", "test_data/sensitive", "test_data/normal",
              "test_data/suspicious_dest"]:
        ensure_dir(d)


def _build_baselines(config):
    """Build hash baselines for every monitored directory in config."""
    dirs = config.get("monitored_directories", [])
    algo = config.get("hash_algorithm", "sha256")

    if not dirs:
        print("  No monitored_directories in config — nothing to baseline.")
        return

    total = 0
    for directory in dirs:
        total += build_baseline_for_directory(directory, algo)

    print(ok_color(f"\n  Baseline complete: {total} files hashed.\n"))


# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────

def main():
    print_banner()

    args = parse_args()

    # ── Load configuration ──
    print(f"  Loading config from: {args.config}")
    try:
        config = load_config(args.config)
    except (FileNotFoundError, ValueError) as e:
        print(f"  ERROR: {e}")
        sys.exit(1)

    # ── Make sure required directories exist ──
    ensure_project_dirs()

    # ── Initialise logging ──
    setup_loggers(config)
    log_raw(f"=== Secure File Transfer Monitor started at {get_timestamp()} ===")

    # ──────────────────────────────────────────
    # MODE: generate report only
    # ──────────────────────────────────────────
    if args.report:
        print("  Generating audit report...\n")
        generate_report(config=config, print_report=True)
        sys.exit(0)

    # ──────────────────────────────────────────
    # MODE: build / refresh hash baselines
    # ──────────────────────────────────────────
    if args.build_baseline:
        print("  Building hash baselines...\n")
        _build_baselines(config)
        sys.exit(0)

    # ──────────────────────────────────────────
    # MODE: normal monitoring
    # ──────────────────────────────────────────

    # Load any previously saved baseline hashes
    load_baseline_from_disk()

    # Build baselines for directories that have files but no stored hashes
    print("  Building initial baselines for monitored directories...")
    _build_baselines(config)

    # Start the file system monitor
    monitor = FileSystemMonitor(config)

    try:
        monitor.start()   # blocks until Ctrl+C
    except Exception as e:
        print(f"\n  [FATAL] Monitor crashed: {e}")
        log_raw(f"Monitor crashed: {e}", level="ERROR")
    finally:
        # Always generate a final report when monitoring stops
        print("\n  Generating final audit report...")
        log_raw(f"=== Monitor stopped at {get_timestamp()} ===")
        generate_report(config=config, print_report=True)


if __name__ == "__main__":
    main()
