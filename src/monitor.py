# src/monitor.py
# Core file system monitoring using the watchdog library.
# Registers a FileSystemEventHandler that reacts to create/modify/delete/move events.

import os
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from src import hashing, detector, logger
from src.utils import (
    get_current_user,
    get_timestamp,
    path_matches_pattern,
    normalize_path,
)

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False


# ──────────────────────────────────────────────
# COLOUR HELPERS
# ──────────────────────────────────────────────

def _color(text, severity):
    """Wrap text in a terminal colour based on severity level."""
    if not HAS_COLOR:
        return text
    color_map = {
        "INFO":     Fore.GREEN,
        "WARNING":  Fore.YELLOW,
        "CRITICAL": Fore.RED,
    }
    return color_map.get(severity, "") + text + Style.RESET_ALL


# ──────────────────────────────────────────────
# EVENT HANDLER
# ──────────────────────────────────────────────

class SecureFileEventHandler(FileSystemEventHandler):
    """
    Watchdog event handler that processes every file system event.

    For each event it:
      1. Filters out ignored patterns (tmp, pyc, etc.)
      2. Computes/verifies the file hash (where applicable)
      3. Runs the detector to classify sensitivity and destination
      4. Logs the result
      5. Prints a coloured alert to the terminal
    """

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.algorithm = config.get("hash_algorithm", "sha256")
        self.ignore_patterns = config.get("monitoring_settings", {}).get(
            "ignore_patterns", []
        )
        self.print_to_terminal = (
            config.get("alert_settings", {}).get("print_to_terminal", True)
        )

    # ── helpers ────────────────────────────────

    def _should_ignore(self, path):
        """Return True if this path matches a user-defined ignore pattern."""
        return path_matches_pattern(path, self.ignore_patterns)

    def _hash_and_verify(self, file_path):
        """
        Hash the file and compare against stored baseline.
        Returns a verification result dict, or None on failure.
        """
        if not os.path.isfile(file_path):
            return None
        return hashing.verify_integrity(file_path, self.algorithm)

    def _process(self, event_type, src_path, dest_path=None):
        """
        Central processing pipeline for any file event.
        """
        if self._should_ignore(src_path):
            return

        # Skip directory events (we only care about files)
        if os.path.isdir(src_path):
            return

        integrity_result = None

        # Hash the file when relevant
        mon_settings = self.config.get("monitoring_settings", {})
        if event_type == "created"  and mon_settings.get("hash_on_create", True):
            integrity_result = self._hash_and_verify(src_path)
        elif event_type == "modified" and mon_settings.get("hash_on_modify", True):
            integrity_result = self._hash_and_verify(src_path)
            # Update baseline after modification
            if integrity_result and integrity_result["status"] != "HASH_FAILED":
                hashing.store_baseline(src_path, integrity_result["current_hash"])
        elif event_type == "moved" and mon_settings.get("hash_on_move", True):
            # Hash at destination
            if dest_path and os.path.isfile(dest_path):
                integrity_result = hashing.verify_integrity(dest_path, self.algorithm)
            # Remove old baseline for the source path
            hashing.remove_baseline(src_path)
        elif event_type == "deleted":
            # Can't hash a deleted file; just remove its baseline
            hashing.remove_baseline(src_path)

        # Classify the event
        analysis = detector.analyse_event(
            event_type=event_type,
            src_path=src_path,
            dest_path=dest_path,
            config=self.config,
            integrity_result=integrity_result,
        )

        # Add timestamp and user
        analysis["timestamp"] = get_timestamp()
        analysis["user"]      = get_current_user()

        # Log to files
        logger.log_event(analysis, self.config)

        # Print to terminal
        if self.print_to_terminal:
            self._print_alert(analysis)

    def _print_alert(self, analysis):
        """Print a formatted, coloured line to the terminal."""
        severity = analysis.get("severity", "INFO")
        message  = analysis.get("alert_message", "")
        ts       = analysis.get("timestamp", get_timestamp())
        print(f"  {ts}  {_color(message, severity)}")

    # ── watchdog callbacks ─────────────────────

    def on_created(self, event):
        if not event.is_directory:
            self._process("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self._process("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self._process("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            self._process("moved", event.src_path, event.dest_path)


# ──────────────────────────────────────────────
# OBSERVER LIFECYCLE
# ──────────────────────────────────────────────

class FileSystemMonitor:
    """
    Manages one watchdog Observer that watches multiple directories.
    """

    def __init__(self, config):
        self.config    = config
        self.observer  = Observer()
        self.handler   = SecureFileEventHandler(config)
        self._running  = False

    def start(self):
        """Schedule all monitored directories and start the Observer thread."""
        recursive = self.config.get("monitoring_settings", {}).get("recursive", True)
        watched_dirs = self.config.get("monitored_directories", [])

        if not watched_dirs:
            print("  [MONITOR] No directories configured. Check config/config.json.")
            return

        scheduled = 0
        for directory in watched_dirs:
            if not os.path.isdir(directory):
                print(f"  [MONITOR] Skipping non-existent directory: {directory}")
                continue
            self.observer.schedule(self.handler, path=directory, recursive=recursive)
            print(f"  [MONITOR] Watching: {os.path.abspath(directory)}")
            scheduled += 1

        if scheduled == 0:
            print("  [MONITOR] No valid directories to watch. Exiting.")
            return

        self.observer.start()
        self._running = True
        print(f"\n  [MONITOR] Observer started. Watching {scheduled} director(ies). Press Ctrl+C to stop.\n")

        try:
            while self._running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Gracefully stop the Observer."""
        print("\n  [MONITOR] Stopping observer...")
        self.observer.stop()
        self.observer.join()
        self._running = False
        print("  [MONITOR] Observer stopped.")
