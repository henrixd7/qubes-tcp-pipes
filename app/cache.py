# ── cache.py ──────────────────────────────────────────────────────────────
# Port cache persistence (reads/writes ports.json).
# Depends on: utils (CACHE_DIR, CACHE_FILE)
# When concatenated into a single-file build this module is loaded third.

import json
import threading
import os

_cache_lock = threading.Lock()


def save_port_cache(vm_name, ports):
    """Atomically write *ports* for *vm_name* into the JSON cache file."""
    with _cache_lock:
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            cache = {}
            if os.path.exists(CACHE_FILE):
                try:
                    with open(CACHE_FILE, "r") as f:
                        cache = json.load(f)
                except (json.JSONDecodeError, OSError):
                    cache = {}  # corrupted or unreadable — start fresh

            cache[vm_name] = ports
            tmp_file = CACHE_FILE + ".tmp"
            with open(tmp_file, "w") as f:
                json.dump(cache, f)
            os.replace(tmp_file, CACHE_FILE)
        except Exception as e:
            print(f"Warning: failed to save port cache: {e}")


def load_port_cache():
    """Return the full port cache dict (or {} on failure)."""
    with _cache_lock:
        try:
            if os.path.exists(CACHE_FILE):
                try:
                    with open(CACHE_FILE, "r") as f:
                        return json.load(f)
                except (json.JSONDecodeError, OSError):
                    print("Warning: port cache corrupted, returning empty")
                    return {}
        except Exception as e:
            print(f"Warning: failed to load port cache: {e}")
    return {}
