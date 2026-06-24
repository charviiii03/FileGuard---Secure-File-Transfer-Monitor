# src/hashing.py
# Handles SHA-256 file hashing and baseline hash management.
# Baseline hashes are stored in memory and optionally persisted to a JSON file.

import os
import json
import hashlib

# Default file to persist the hash baseline between runs
BASELINE_FILE = "logs/hash_baseline.json"

# In-memory store: { normalized_path: sha256_hex_string }
_baseline_store = {}


# ──────────────────────────────────────────────
# CORE HASHING
# ──────────────────────────────────────────────

def compute_hash(file_path, algorithm="sha256", chunk_size=65536):
    """
    Compute the hash of a file using the specified algorithm (default: sha256).

    Reads the file in chunks to handle large files without loading them
    entirely into memory.

    Returns:
        str  – hex digest on success
        None – if the file cannot be read (deleted, permission error, etc.)
    """
    try:
        hasher = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hasher.update(chunk)
        return hasher.hexdigest()
    except (FileNotFoundError, PermissionError, OSError) as e:
        # File may have been deleted before we could hash it — that's okay.
        print(f"  [HASH WARNING] Could not hash '{file_path}': {e}")
        return None


# ──────────────────────────────────────────────
# BASELINE MANAGEMENT
# ──────────────────────────────────────────────

def store_baseline(file_path, hash_value):
    """
    Save (or update) the baseline hash for a given file path.
    Also persists the baseline to disk so it survives restarts.
    """
    norm = os.path.normpath(file_path)
    _baseline_store[norm] = hash_value
    _save_baseline_to_disk()


def get_baseline(file_path):
    """
    Retrieve the stored baseline hash for a file.

    Returns:
        str  – stored hex digest
        None – if no baseline exists for this file
    """
    norm = os.path.normpath(file_path)
    return _baseline_store.get(norm)


def remove_baseline(file_path):
    """Remove a file's baseline hash (e.g., when it is deleted)."""
    norm = os.path.normpath(file_path)
    if norm in _baseline_store:
        del _baseline_store[norm]
        _save_baseline_to_disk()


def load_baseline_from_disk():
    """
    Load persisted baseline hashes from the JSON file on startup.
    Call this once at application start.
    """
    global _baseline_store
    if os.path.exists(BASELINE_FILE):
        try:
            with open(BASELINE_FILE, "r", encoding="utf-8") as f:
                _baseline_store = json.load(f)
            print(f"  [HASH] Loaded {len(_baseline_store)} baseline hashes from disk.")
        except (json.JSONDecodeError, IOError) as e:
            print(f"  [HASH WARNING] Could not load baseline file: {e}. Starting fresh.")
            _baseline_store = {}
    else:
        print("  [HASH] No existing baseline found. Starting fresh.")


def _save_baseline_to_disk():
    """Internal helper: persist the in-memory baseline store to disk."""
    os.makedirs(os.path.dirname(BASELINE_FILE), exist_ok=True)
    try:
        with open(BASELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(_baseline_store, f, indent=2)
    except IOError as e:
        print(f"  [HASH WARNING] Could not save baseline to disk: {e}")


# ──────────────────────────────────────────────
# INTEGRITY VERIFICATION
# ──────────────────────────────────────────────

def verify_integrity(file_path, algorithm="sha256"):
    """
    Compare the current hash of a file against its stored baseline.

    Returns a dict:
        {
            "status":       "MATCH" | "MISMATCH" | "NO_BASELINE" | "HASH_FAILED",
            "current_hash": str or None,
            "stored_hash":  str or None,
            "file_path":    str
        }
    """
    result = {
        "file_path": file_path,
        "current_hash": None,
        "stored_hash": None,
        "status": "UNKNOWN",
    }

    current_hash = compute_hash(file_path, algorithm)
    result["current_hash"] = current_hash

    if current_hash is None:
        result["status"] = "HASH_FAILED"
        return result

    stored_hash = get_baseline(file_path)
    result["stored_hash"] = stored_hash

    if stored_hash is None:
        result["status"] = "NO_BASELINE"
        # Auto-create a baseline for new files
        store_baseline(file_path, current_hash)
        return result

    if current_hash == stored_hash:
        result["status"] = "MATCH"
    else:
        result["status"] = "MISMATCH"

    return result


# ──────────────────────────────────────────────
# BULK BASELINE BUILDER
# ──────────────────────────────────────────────

def build_baseline_for_directory(directory, algorithm="sha256", recursive=True):
    """
    Walk a directory and compute + store baseline hashes for every file.
    Useful for initialising the baseline at first run.

    Returns the number of files hashed.
    """
    count = 0
    if not os.path.isdir(directory):
        print(f"  [HASH] Directory not found, skipping baseline build: {directory}")
        return count

    walker = os.walk(directory) if recursive else [(directory, [], os.listdir(directory))]

    for root, _dirs, files in walker:
        for filename in files:
            file_path = os.path.join(root, filename)
            h = compute_hash(file_path, algorithm)
            if h:
                store_baseline(file_path, h)
                count += 1

    print(f"  [HASH] Baseline built for '{directory}': {count} files hashed.")
    return count
