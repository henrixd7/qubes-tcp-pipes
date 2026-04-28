# ── utils.py ──────────────────────────────────────────────────────────────
# Shared constants, theme, and helper utilities.
# When concatenated into a single-file build this module is loaded second.

import subprocess
import os
import sys

# ── Configuration ────────────────────────────────────────────────────────

POLICY_FILE = "/etc/qubes/policy.d/30-dev-tcp-temp.policy"
EXCLUDED_VMS = ["dom0", "mirage-firewall", "snitch-ui", "vault"]

# Cache configuration
CACHE_DIR = os.path.expanduser("~/.cache/qubes-tcp-pipes")
CACHE_FILE = os.path.join(CACHE_DIR, "ports.json")
CACHE_REFRESH_INTERVAL = 30

# Visual Theme
THEME = {
    "bg": "#F0F2F5",
    "panel_bg": "#FFFFFF",
    "text_main": "#333333",
    "text_muted": "#666666",
    "vm_bg": "#FFFFFF",
    "vm_border": "#CED4DA",
    "vm_sel_bg": "#E7F1FF",
    "vm_sel_border": "#0D6EFD",
    "vm_hover_bg": "#F8F9FA",
    "port_fill": "#20C997",
    "port_border": "#198754",
    "line": "#0D6EFD",
    "shadow": "#D0D4D8",
    "status_bg": "#F0F2F5",
    "status_text": "#666666",
}
# Layout geometry — single source of truth for all canvas math.  Every
# hardcoded coordinate in ui.py must derive from these values.
LAYOUT = {
    "vm_half_w":       55,       # half of VM box width  (full = 110)
    "vm_half_h":       45,       # half of VM box height (full = 90)
    "grid_origin_x":   140,      # x of first column centre
    "grid_origin_y":   80,       # y of first row centre
    "col_spacing":     280,      # horizontal distance between column centres
    "row_spacing":     160,      # vertical distance between row centres
    "v_chan_offset":   95,       # x-offset from column centre → vertical routing channel
    "min_canvas_width": 1200,    # fallback width when winfo_width is unreliable
    "resize_threshold": 20,      # px delta that triggers a full re-render
}

FONT_MAIN = ("Helvetica", 10)
FONT_BOLD = ("Helvetica", 10, "bold")
FONT_LARGE = ("Helvetica", 11)
FONT_SMALL = ("Helvetica", 8)


# ── Helpers ──────────────────────────────────────────────────────────────

def run_cmd(cmd, silent=False, timeout=10):
    """Run a command (given as an arg list) and return stdout (or empty string on failure).

    *cmd* must be a list of strings, e.g. ["qvm-run", "-q", "vmname", "ss -ltn"].
    Never uses shell=True — all arguments are passed directly to execve.
    """
    try:
        result = subprocess.run(
            cmd,
            shell=False,
            stdout=subprocess.DEVNULL if silent else subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=not silent,
            check=False,
            timeout=timeout,
        )
        return "" if silent else result.stdout
    except subprocess.TimeoutExpired:
        print(f"Warning: command timed out ({timeout}s): {' '.join(cmd)}")
        return ""
    except Exception as e:
        print(f"Error running command {' '.join(cmd)}: {e}")
        return ""


def get_port_color(port_str):
    """Deterministic color from a port string."""
    palette = [
        "#0D6EFD", "#6610F2", "#6F42C1", "#D63384", "#DC3545",
        "#FD7E14", "#F5C211", "#0DCAF0", "#FF4500", "#8A2BE2",
        "#E83E8C", "#00796B",
    ]
    return palette[sum(ord(c) for c in str(port_str)) % len(palette)]
