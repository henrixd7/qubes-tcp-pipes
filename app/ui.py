# ── ui.py ─────────────────────────────────────────────────────────────────
# Tkinter UI: QubePipesApp class, canvas rendering, event handling.
# Depends on: utils (THEME, FONT_*, …), models (VM, Connection),
#             cache (save/load_port_cache), qubes (all public functions).
# When concatenated into a single-file build this module is loaded fifth.

import math
import signal
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox

try:
    # Package mode: explicit imports from sibling modules
    from app.utils import (
        THEME, FONT_MAIN, FONT_BOLD, FONT_LARGE, FONT_SMALL,
        LAYOUT, MIN_ROW_GAP, CACHE_REFRESH_INTERVAL, get_port_color,
    )
    from app.models import VM
    from app.cache import save_port_cache, load_port_cache
    from app.qubes import (
        create_connection, kill_connection_process, remove_policy_rule,
        cleanup_policy_file, get_running_vms, get_listening_ports,
        is_connection_alive,
    )
    from app.routing import build_grid, route_connection, Route
except ImportError:
    # Concatenated mode: routing symbols should be in global scope.
    # If not, something went wrong with the build order.
    if 'build_grid' not in globals():
        raise RuntimeError(
            "Routing module not available. Make sure app/routing.py is "
            "loaded before app/ui.py (check build.sh order)."
        )

# ── Channel-grid routing (imported from app.routing) ─────────────────────
# RoutingGrid, VChannel, HChannel, Route, build_grid(), route_connection()
# are all defined in app/routing.py to keep the UI module focused.
# ── End channel-grid model ───────────────────────────────────────────────


class QubePipesApp:
    """Main application controller and Tkinter UI."""

    def __init__(self, root):
        self.root = root
        self.root.title("Qubes TCP Pipes")
        self.root.configure(bg=THEME["bg"])
        self._setup_ui()
        self.vms = {}
        self.connections = []
        self.selected_source_vm = None
        self.known_source_ports = {}
        self._state_lock = threading.Lock()
        self._background_refresh_running = False
        self._last_refresh_time = None
        self.last_width = self.root.winfo_width()
        self._hover_bind_ids = {}
        self._status_timer_id = None
        self.setup_signals()
        self.refresh_vms()
        self.canvas.bind("<Button-1>", self.on_click)
        self.canvas.bind("<Button-3>", self.on_right_click)
        self.canvas.bind("<Configure>", self.on_resize)
        self.start_background_refresh()
        self._update_status_timer()

    def _setup_ui(self):
        self.top_frame = tk.Frame(self.root, bg=THEME["panel_bg"], height=50, bd=1, relief=tk.RIDGE)
        self.top_frame.pack(fill=tk.X, side=tk.TOP)
        self.refresh_btn = tk.Button(self.top_frame, text="\u27f3 Refresh VMs", command=self.refresh_vms,
            bg="#F8F9FA", activebackground="#E2E6EA", relief=tk.GROOVE, padx=10)
        self.refresh_btn.pack(side=tk.LEFT, padx=15, pady=10)
        instructions = tk.Label(self.top_frame,
            text="1. Click a VM box to select Client   |   2. Click a green port on another VM to connect",
            bg=THEME["panel_bg"], fg=THEME["text_muted"], font=FONT_LARGE)
        instructions.pack(side=tk.LEFT, padx=20)
        self.canvas = tk.Canvas(self.root, width=1200, height=800, bg=THEME["bg"], highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.status_frame = tk.Frame(self.root, bg=THEME["status_bg"], height=26, bd=1, relief=tk.RIDGE)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        self.lbl_conn_count = tk.Label(self.status_frame, text="Connections: 0",
            bg=THEME["status_bg"], fg=THEME["status_text"], font=FONT_SMALL)
        self.lbl_conn_count.pack(side=tk.LEFT, padx=10, pady=2)
        self.lbl_vm_count = tk.Label(self.status_frame, text="VMs: 0",
            bg=THEME["status_bg"], fg=THEME["status_text"], font=FONT_SMALL)
        self.lbl_vm_count.pack(side=tk.LEFT, padx=10, pady=2)
        self.lbl_last_refresh = tk.Label(self.status_frame, text="Last refresh: --",
            bg=THEME["status_bg"], fg=THEME["status_text"], font=FONT_SMALL)
        self.lbl_last_refresh.pack(side=tk.LEFT, padx=10, pady=2)

    def setup_signals(self):
        signal.signal(signal.SIGINT, self.handle_exit)
        signal.signal(signal.SIGTERM, self.handle_exit)
        self.root.protocol("WM_DELETE_WINDOW", self.handle_exit_gui)

    def handle_exit(self, signum, frame):
        self.cleanup()
        sys.exit(0)

    def handle_exit_gui(self):
        self._background_refresh_running = False
        if self._status_timer_id:
            self.root.after_cancel(self._status_timer_id)
            self._status_timer_id = None
        self.cleanup()
        self.root.destroy()
        sys.exit(0)

    def cleanup(self):
        self._background_refresh_running = False
        if self._status_timer_id:
            # May be called from a signal handler (arbitrary thread).
            # after_cancel is a Tk call — guard against threading errors.
            try:
                self.root.after_cancel(self._status_timer_id)
            except Exception:
                pass
            self._status_timer_id = None
        print("Cleaning up temporary pipes...")
        with self._state_lock:
            conns = list(self.connections)
            self.connections.clear()
        for conn in conns:
            kill_connection_process(conn)
        cleanup_policy_file()

    def refresh_vms(self):
        self.selected_source_vm = None
        current_vms = get_running_vms()
        cache = load_port_cache()
        with self._state_lock:
            self.vms = {name: self.vms.get(name, VM(name, 0, 0)) for name in current_vms}
            self.connections = [conn for conn in self.connections
                if conn.client_name in self.vms and conn.server_name in self.vms]
            for name, vm in self.vms.items():
                if name in cache:
                    vm.update_ports(cache[name])
        self.render_vms()
        self._last_refresh_time = time.time()
        self.update_status_bar()
        threading.Thread(target=self.discover_ports_worker, daemon=True).start()

    def discover_ports_worker(self):
        with self._state_lock:
            vm_names = list(self.vms.keys())
            conns = list(self.connections)
        for name in vm_names:
            try:
                ports = get_listening_ports(name)
                save_port_cache(name, ports)

                # Task 2: track error ports — rebuild from scratch each cycle
                # so orphaned ports (whose connection was pruned) are cleaned up.
                with self._state_lock:
                    vm = self.vms.get(name)
                    if vm is None:
                        continue
                    new_error = set()
                    # For each connection involving this VM, check its ports.
                    for conn in conns:
                        if conn.server_name == name:
                            rp = str(conn.remote_port)
                            if rp not in ports:
                                new_error.add(rp)
                        if conn.client_name == name:
                            lp = str(conn.local_port)
                            if lp not in ports:
                                new_error.add(lp)
                    vm.error_ports = new_error
                self.root.after(0, self.update_vm_ports_ui, name, ports)
            except Exception as e:
                print(f"Warning: failed to scan ports for {name}: {e}")

    def start_background_refresh(self):
        self._background_refresh_running = True
        def _loop():
            while self._background_refresh_running:
                time.sleep(CACHE_REFRESH_INTERVAL)
                if not self._background_refresh_running:
                    break
                self.discover_ports_worker()
                # Defer all state + UI updates to the Tk thread
                now = time.time()
                self.root.after(0, self._on_background_refresh_done, now)
        threading.Thread(target=_loop, daemon=True).start()

    def _on_background_refresh_done(self, timestamp):
        """Called on the Tk thread after a background port refresh cycle."""
        self._last_refresh_time = timestamp
        self.update_status_bar()

    def _prune_dead_connections(self):
        """Remove connections whose qvm-run process has exited."""
        pruned = False
        with self._state_lock:
            still_alive = []
            for conn in self.connections:
                if is_connection_alive(conn):
                    still_alive.append(conn)
                else:
                    remove_policy_rule(conn)
                    pruned = True

            if pruned:
                self.connections = still_alive
        if pruned:
            self.redraw_connections()

    def _update_status_timer(self):
        self._prune_dead_connections()
        self.update_status_bar()
        self._status_timer_id = self.root.after(1000, self._update_status_timer)

    def update_status_bar(self):
        self.lbl_conn_count.config(text=f"Connections: {len(self.connections)}")
        self.lbl_vm_count.config(text=f"VMs: {len(self.vms)}")
        if self._last_refresh_time:
            ago = int(time.time() - self._last_refresh_time)
            self.lbl_last_refresh.config(text=f"Last refresh: {ago}s ago")

    def delete_connection(self, conn):
        kill_connection_process(conn)
        with self._state_lock:
            if conn in self.connections:
                self.connections.remove(conn)
        remove_policy_rule(conn)
        self.redraw_connections()
        self.update_status_bar()

    def create_connection(self, client_name, local_port, server_name, remote_port):
        conn, err = create_connection(client_name, local_port, server_name, remote_port)
        if conn is None:
            messagebox.showerror("Connection Failed", err or "Unknown error")
            return

        port_str = str(local_port)
        client_vm = None
        with self._state_lock:
            self.connections.append(conn)
            if client_name not in self.known_source_ports:
                self.known_source_ports[client_name] = set()
            self.known_source_ports[client_name].add(port_str)

            # Optimistically add the source port to the client VM so the
            # connection line renders from the correct position immediately.
            # The next background port-scan will reconcile with reality.
            client_vm = self.vms.get(client_name)
            if client_vm and port_str not in client_vm.ports:
                client_vm.ports.append(port_str)

        if client_vm:
            save_port_cache(client_name, client_vm.ports)
            self.update_vm_ports_ui(client_name, client_vm.ports)
        self.redraw_connections()
        self.update_status_bar()

    def on_resize(self, event):
        if abs(event.width - self.last_width) > LAYOUT["resize_threshold"]:
            self.last_width = event.width
            self.render_vms(event.width)

    def render_vms(self, width=None):
        self.canvas.delete("vm_element")
        self._hover_bind_ids.clear()
        width = width or self.canvas.winfo_width()
        if width < 10:
            width = LAYOUT["min_canvas_width"]
        cols = max(1, width // LAYOUT["col_spacing"])

        # --- Phase 1: compute per-VM heights from port counts ---
        for vm in self.vms.values():
            vm.half_h = self._vm_height(vm.ports) // 2

        # --- Phase 2: determine row boundaries and cumulative y positions ---
        n_vms = len(self.vms)
        max_row_idx = (n_vms - 1) // cols if n_vms else 0
        row_max_heights = {}   # tallest VM in each row
        row_max_top = {}       # highest top edge (= shortest VM's top) — for safe-zone routing
        for i, vm in enumerate(self.vms.values()):
            row = i // cols
            h = vm.half_h * 2
            row_max_heights[row] = max(row_max_heights.get(row, 0), h)

        row_y_positions = {}
        y = LAYOUT["grid_origin_y"]
        for r in range(max_row_idx + 1):
            row_y_positions[r] = y
            h = row_max_heights.get(r, LAYOUT["base_vm_h"])
            y += h + MIN_ROW_GAP

        # Compute row_max_top with actual y positions now known.
        for i, vm in enumerate(self.vms.values()):
            row = i // cols
            top_edge = vm.y - vm.half_h
            row_max_top[row] = max(row_max_top.get(row, float('-inf')), top_edge)

        # Store row boundary info for routing (used by channel grid)
        self._row_starts = dict(row_y_positions)
        self._row_max_heights = dict(row_max_heights)
        self._row_max_tops = dict(row_max_top)

        # Build the channel-grid model from layout data.
        self._build_routing_grid()

        # --- Phase 3: position VMs and draw them ---
        for i, (name, vm) in enumerate(self.vms.items()):
            row, col = divmod(i, cols)
            vm.x = LAYOUT["grid_origin_x"] + col * LAYOUT["col_spacing"]
            vm.y = row_y_positions[row]
            self.draw_vm_box(vm)
            if vm.ports:
                self.update_vm_ports_ui(name, vm.ports, redraw_lines=False)
        self.redraw_connections()

    # ── Channel-grid routing ────────────────────────────────────────────

    def _build_routing_grid(self):
        """Build the channel grid from current VM layout data."""
        n_vms = len(self.vms)
        cols = max(1, self.canvas.winfo_width() // LAYOUT["col_spacing"])
        canvas_h = self.canvas.winfo_height()
        self._routing_grid = build_grid(
            n_vms, cols,
            self._row_starts, self._row_max_heights,
            self.canvas.winfo_width(), canvas_h,
            LAYOUT,
        )

    def _route_connection(self, conn):
        """Compute a route through the channel grid for one connection."""
        grid = getattr(self, '_routing_grid', None)
        if not grid:
            return None

        client_vm = self.vms.get(conn.client_name)
        server_vm = self.vms.get(conn.server_name)
        if not client_vm or not server_vm:
            return None

        return route_connection(
            grid, client_vm, server_vm,
            conn.local_port, conn.remote_port,
            self._port_side, self._vm_column, self._row_for_y,
        )

    def draw_vm_box(self, vm):
        px = LAYOUT["vm_half_w"]
        py = getattr(vm, 'half_h', None) or (LAYOUT["base_vm_h"] // 2)
        vm.shadow_id = self.canvas.create_rectangle(
            vm.x - px + 2, vm.y - py + 2, vm.x + px + 2, vm.y + py + 2,
            fill=THEME["shadow"], outline="", tags=("vm_element", "vm_box", vm.name))
        vm.canvas_id = self.canvas.create_rectangle(
            vm.x - px, vm.y - py, vm.x + px, vm.y + py,
            fill=THEME["vm_bg"], outline=THEME["vm_border"], width=2,
            tags=("vm_element", "vm_box", vm.name))
        cx = vm.x
        cy = vm.y - py + 15   # 15 px from top edge instead of hardcoded offset
        c_tag = ("vm_element", "vm_box", vm.name)
        vm.icon_ids = [
            self.canvas.create_rectangle(cx - 8, cy - 6, cx + 8, cy + 6, outline=THEME["text_muted"], tags=c_tag),
            self.canvas.create_line(cx - 5, cy + 10, cx + 5, cy + 10, fill=THEME["text_muted"], tags=c_tag),
            self.canvas.create_line(cx, cy + 6, cx, cy + 10, fill=THEME["text_muted"], tags=c_tag)]
        self.canvas.create_text(vm.x, vm.y, text=vm.name, font=FONT_BOLD, fill=THEME["text_main"], tags=c_tag)
        if any(c.client_name == vm.name or c.server_name == vm.name for c in self.connections):
            dot = self.canvas.create_oval(
                vm.x + px - 14, vm.y - py + 6, vm.x + px - 6, vm.y - py + 14,
                fill=THEME["port_fill"], outline="", tags=c_tag)
            vm.icon_ids.append(dot)

        def on_enter(_e):
            if self.selected_source_vm != vm:
                self.canvas.itemconfig(vm.canvas_id, fill=THEME["vm_hover_bg"])
                vm.hovered = True
        def on_leave(_e):
            if self.selected_source_vm != vm and vm.hovered:
                self.canvas.itemconfig(vm.canvas_id, fill=THEME["vm_bg"])
                vm.hovered = False
        self.canvas.tag_bind(vm.canvas_id, "<Enter>", on_enter)
        self.canvas.tag_bind(vm.canvas_id, "<Leave>", on_leave)

    def update_vm_ports_ui(self, name, ports, redraw_lines=True):
        with self._state_lock:
            if name not in self.vms:
                return
            vm = self.vms[name]
            sorted_ports = sorted(ports, key=lambda p: int(p) if p.isdigit() else p)

            # Task 2: merge error ports into the display list so they stay visible.
            error_set = set(getattr(vm, '_error_ports', set()))
            all_display_ports = list(sorted_ports)
            for ep in sorted(error_set, key=lambda p: int(p) if p.isdigit() else p):
                if ep not in all_display_ports:
                    all_display_ports.append(ep)

            vm.update_ports(all_display_ports)
            # Recalculate VM height based on new port count.
            old_half_h = getattr(vm, 'half_h', None)
            vm.half_h = self._vm_height(vm.ports) // 2
            half_h_changed = old_half_h is not None and old_half_h != vm.half_h

        for pid in vm.port_ids.values():
            self.canvas.delete(pid)
        vm.port_ids.clear()
        self.canvas.delete(f"vm_port_{name}")
        px = LAYOUT["vm_half_w"]
        py_val = getattr(vm, 'half_h', None) or (LAYOUT["base_vm_h"] // 2)
        y1, y2 = vm.y - py_val, vm.y + py_val
        max_per_side = self._max_ports_per_side(vm)
        n_right = min(len(all_display_ports), max_per_side)
        n_left = len(all_display_ports) - max_per_side
        for i, port in enumerate(all_display_ports):
            if i < max_per_side:
                # Right side
                x2 = vm.x + px
                py_pos = y1 + (i + 1) * (y2 - y1) / (n_right + 1)
                text_x = x2 + 10  # Task 3: inside VM box, near edge
            else:
                # Left side
                local_idx = i - max_per_side
                x2 = vm.x - px
                py_pos = y1 + (local_idx + 1) * (y2 - y1) / (n_left + 1)
                text_x = x2 - 10  # Task 3: inside VM box, near edge
            port_tag = f"vm_port_{name}"

            # Task 2: color error ports red instead of green.
            is_error = port in error_set
            fill_color = THEME["error_port_fill"] if is_error else THEME["port_fill"]
            border_color = THEME["error_port_border"] if is_error else THEME["port_border"]

            port_id = self.canvas.create_oval(
                x2 - 6, py_pos - 6, x2 + 6, py_pos + 6,
                fill=fill_color, outline=border_color, width=1,
                tags=("vm_element", "port", port_tag))
            # Task 3: bold font for port numbers
            self.canvas.create_text(text_x, py_pos, text=port, font=FONT_BOLD,
                fill=THEME["text_main"], anchor=tk.E if i >= max_per_side else tk.W,
                tags=("vm_element", "port_text", port_tag))
            vm.port_ids[port] = port_id

        # Task 5: when VM height changes, defer a full re-render so that
        # all port updates from discover_ports_worker complete first.
        if half_h_changed:
            self.root.after(0, self.render_vms)
        elif redraw_lines:
            self.redraw_connections()

    # ── Port-side helpers ───────────────────────────────────────────────

    def _vm_height(self, ports):
        """Compute the required full height for a VM given its port list.

        per_side = ceil(n / 2), then H = max(base_vm_h, (per_side + 1) * 14).
        Each additional pair of ports adds exactly 14 px."""
        n = len(ports) if ports else 0
        per_side = math.ceil(n / 2) if n > 0 else 0
        return max(LAYOUT["base_vm_h"], (per_side + 1) * 14) if per_side > 0 else LAYOUT["base_vm_h"]

    def _max_ports_per_side(self, vm):
        """Calculate how many ports can fit on one edge without circles overlapping.

        Spacing between port centres = H / (N + 1).  We need at least
        MIN_PORT_SPACING px so that the 12 px-diameter circles don't overlap.
        Returns max N such that H / (N + 1) >= MIN_PORT_SPACING, clamped to >= 1."""
        height = 2 * vm.half_h if hasattr(vm, 'half_h') and vm.half_h else LAYOUT["base_vm_h"]
        min_spacing = 14  # px between centres; circles are 12 px diameter
        return max(1, int(height / min_spacing) - 1)

    def _port_side(self, vm, port):
        """Return 'right' or 'left' depending on which edge a port lives on."""
        all_ports = sorted(vm.ports, key=lambda p: int(p) if p.isdigit() else p)
        try:
            idx = all_ports.index(str(port))
        except ValueError:
            return "right"
        return "left" if idx >= self._max_ports_per_side(vm) else "right"

    def _vm_column(self, vm):
        """Return the grid column index of a VM."""
        return int((vm.x - LAYOUT["grid_origin_x"]) // LAYOUT["col_spacing"])

    def _row_for_y(self, y):
        """Return the row index that contains the given y-coordinate.

        Scans stored row boundaries in reverse order (bottom → top).
        """
        if not hasattr(self, '_row_starts') or not self._row_starts:
            return 0
        for r in sorted(self._row_starts.keys(), reverse=True):
            if y >= self._row_starts[r]:
                return r
        return 0

    def get_port_coords(self, vm, port):
        """Pure mathematical alignment calculation. Prevents Tkinter race-condition jitter.

        Returns (x, y) where x is on the right or left edge depending on which
        side the port lives on."""
        px = LAYOUT["vm_half_w"]
        py = getattr(vm, 'half_h', None) or (LAYOUT["base_vm_h"] // 2)
        y1, y2 = vm.y - py, vm.y + py
        all_ports = sorted(vm.ports, key=lambda p: int(p) if p.isdigit() else p)
        if not all_ports:
            return vm.x + px, (y1 + y2) / 2
        try:
            idx = all_ports.index(str(port))
        except ValueError:
            idx = 0
        max_per_side = self._max_ports_per_side(vm)
        if idx < max_per_side:
            # Right side — spacing among right-side ports only
            n_right = min(len(all_ports), max_per_side)
            py_pos = y1 + (idx + 1) * (y2 - y1) / (n_right + 1)
            return vm.x + px, py_pos
        else:
            # Left side — spacing among left-side ports only
            n_left = len(all_ports) - max_per_side
            local_idx = idx - max_per_side
            py_pos = y1 + (local_idx + 1) * (y2 - y1) / (n_left + 1)
            return vm.x - px, py_pos

    def on_click(self, event):
        for vm in self.vms.values():
            for port, pid in vm.port_ids.items():
                coords = self.canvas.coords(pid)
                if coords and abs(event.x - (coords[0] + coords[2]) / 2) < 25 and abs(
                    event.y - (coords[1] + coords[3]) / 2) < 15:
                    self.handle_target_port_click(vm, port)
                    return
        item = self.canvas.find_closest(event.x, event.y, 10)
        if item and "vm_box" in self.canvas.gettags(item[0]):
            vm_name = self.canvas.gettags(item[0])[2]
            self.handle_source_vm_click(self.vms[vm_name])

    def handle_source_vm_click(self, vm):
        if self.selected_source_vm:
            self.canvas.itemconfig(self.selected_source_vm.canvas_id,
                fill=THEME["vm_bg"], outline=THEME["vm_border"])
            if self.selected_source_vm == vm:
                self.selected_source_vm = None
                return
        self.selected_source_vm = vm
        self.canvas.itemconfig(vm.canvas_id, fill=THEME["vm_sel_bg"], outline=THEME["vm_sel_border"])

    def handle_target_port_click(self, target_vm, remote_port):
        if not self.selected_source_vm:
            messagebox.showinfo("Select Client",
                "Please click a VM box first to select the source Client.")
            return
        client_vm = self.selected_source_vm
        if client_vm.name == target_vm.name:
            messagebox.showwarning("Warning", "Cannot connect a VM to itself.")
        else:
            self.create_connection(client_vm.name, remote_port, target_vm.name, remote_port)
        self.canvas.itemconfig(client_vm.canvas_id, fill=THEME["vm_bg"], outline=THEME["vm_border"])
        self.selected_source_vm = None

    def on_right_click(self, event):
        item = self.canvas.find_closest(event.x, event.y, 10)
        if not item:
            return
        tags = self.canvas.gettags(item[0])
        conn_tag = next((t for t in tags if t.startswith("conn_")), None)
        if not conn_tag:
            return
        target_conn = next((c for c in self.connections if f"conn_{id(c)}" == conn_tag), None)
        if target_conn and messagebox.askyesno("Delete Connection",
            f"Sever connection from {target_conn.client_name} to {target_conn.server_name}:{target_conn.remote_port}?"):
            self.delete_connection(target_conn)

    def _smooth_path(self, path, radius=15):
        """Mathematically generates a smooth, curved path to avoid Tkinter's finicky spline rendering."""
        if len(path) < 3:
            return path
        result = [path[0]]
        for i in range(1, len(path) - 1):
            p0 = result[-1] if len(result) > 1 else path[i - 1]
            p1, p2 = path[i], path[i + 1]
            d1 = math.hypot(p1[0] - p0[0], p1[1] - p0[1])
            d2 = math.hypot(p2[0] - p1[0], p2[1] - p1[1])
            r = min(radius, d1 / 2, d2 / 2)
            if r <= 0:
                result.append(p1)
                continue
            dx1, dy1 = (p0[0] - p1[0]) / d1, (p0[1] - p1[1]) / d1
            dx2, dy2 = (p2[0] - p1[0]) / d2, (p2[1] - p1[1]) / d2
            result.extend([
                (p1[0] + dx1 * r, p1[1] + dy1 * r),
                (p1[0] + (dx1 + dx2) * r * 0.414, p1[1] + (dy1 + dy2) * r * 0.414),
                (p1[0] + dx2 * r, p1[1] + dy2 * r)])
        result.append(path[-1])
        return result

    def draw_connection_line(self, conn, idx, total, labels_list):
        client_vm = self.vms.get(conn.client_name)
        server_vm = self.vms.get(conn.server_name)
        if not client_vm or not server_vm:
            return
        src_port_str = str(conn.local_port)
        if (client_vm.name in self.known_source_ports and
                src_port_str in self.known_source_ports[client_vm.name]):
            src_x, src_y = self.get_port_coords(client_vm, src_port_str)
        else:
            src_x, src_y = client_vm.x, client_vm.y
        dst_x, dst_y = self.get_port_coords(server_vm, str(conn.remote_port))

        # Route through the channel grid.
        route = getattr(conn, '_route', None)
        if not route:
            return  # no valid route — skip this connection

        grid = self._routing_grid
        v_src_ch = grid.v_channels.get(route.v_src_idx)
        v_dst_ch = grid.v_channels.get(route.v_dst_idx)
        if not v_src_ch or not v_dst_ch:
            return

        # Lane registration happens automatically in lane_x/lane_y.
        vc_x_src = v_src_ch.lane_x(conn)
        vc_x_dst = v_dst_ch.lane_x(conn)

        conn_tag = f"conn_{id(conn)}"
        line_color = get_port_color(conn.remote_port)

        if route.h_chan_idx is None:
            # Same V-channel — vertical routing only.
            path = [(src_x, src_y), (vc_x_src, src_y),
                    (vc_x_src, dst_y), (dst_x, dst_y)]
            label_x = vc_x_src + 6
            label_y = (src_y + dst_y) / 2
        else:
            # Cross-column routing through an H-channel.
            h_ch = grid.h_channels.get(route.h_chan_idx)
            if not h_ch:
                # No H-channel available — compute a fallback horizontal position
                # below both VMs (below the tallest one in their row).
                starts = getattr(self, '_row_starts', {})
                max_h = getattr(self, '_row_max_heights', {})
                same_row = self._row_for_y(client_vm.y)
                h_y = (starts.get(same_row, 0) + max_h.get(same_row, LAYOUT["base_vm_h"])
                       + MIN_ROW_GAP // 2)
            else:
                h_y = h_ch.lane_y(conn)

            path = [(src_x, src_y),
                    (vc_x_src, src_y), (vc_x_src, h_y),
                    (vc_x_dst, h_y), (vc_x_dst, dst_y),
                    (dst_x, dst_y)]
            label_x = (vc_x_src + vc_x_dst) / 2
            label_y = h_y - 12

        smoothed_path = self._smooth_path(path, radius=8)
        flat_coords = [c for pt in smoothed_path for c in pt]
        conn.line_id = self.canvas.create_line(
            *flat_coords, fill=line_color, width=2.5, smooth=False,
            tags=("vm_element", "connection", conn_tag))
        for x, y in [(src_x, src_y), (dst_x, dst_y)]:
            self.canvas.create_rectangle(x - 3, y - 3, x + 3, y + 3,
                fill=line_color, outline="", tags=("vm_element", "connection", conn_tag))
        labels_list.append((label_x, label_y,
            f" {conn.local_port}\u2192{conn.remote_port} ", line_color, conn_tag))

    def redraw_connections(self):
        self.canvas.delete("connection")
        self.canvas.delete("connection_label")

        # Clear channel occupancy from previous render.
        grid = getattr(self, '_routing_grid', None)
        if grid:
            for ch in list(grid.v_channels.values()) + list(grid.h_channels.values()):
                ch.lanes.clear()

        sorted_conns = sorted(self.connections, key=lambda c: (
            c.server_name, c.remote_port, c.client_name, c.local_port))

        # Phase 1: route all connections through the grid.
        for conn in sorted_conns:
            route = self._route_connection(conn)
            conn._route = route

        # Phase 2: draw all connections.
        labels = []
        for i, conn in enumerate(sorted_conns):
            self.draw_connection_line(conn, i, len(sorted_conns), labels)

        # Task 4: collision detection — track placed label bboxes to avoid overlap.
        placed_bboxes = []  # list of (x1, y1, x2, y2) for each placed label+bg

        def _bboxes_overlap(b1, b2, margin=4):
            """Check if two bounding boxes overlap (with a small margin)."""
            return not (b1[2] + margin < b2[0] or b2[2] + margin < b1[0]
                        or b1[3] + margin < b2[1] or b2[3] + margin < b1[1])

        # Sort labels by y-position so topmost labels claim their preferred spot first.
        for lx, ly, text, color, tag in sorted(labels, key=lambda l: l[1]):
            cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
            lx, ly = max(10, min(cw - 10, lx)), max(10, min(ch - 10, ly))

            # Measure text size to predict bbox before drawing.
            text_id_tmp = self.canvas.create_text(lx, ly, text=text,
                font=FONT_BOLD, fill=color, tags=("vm_element", "connection_label", tag))
            tmp_bbox = self.canvas.bbox(text_id_tmp)
            if not tmp_bbox:
                continue
            tw = tmp_bbox[2] - tmp_bbox[0]
            th = tmp_bbox[3] - tmp_bbox[1]
            self.canvas.delete(text_id_tmp)

            # Try to find a non-overlapping y-shift.
            # Strategy: try original position first, then expand outward
            # (above and below simultaneously) until a free slot is found.
            shift = 0
            for attempt in range(25):
                test_y = ly + shift
                test_bbox = (lx - tw // 2, test_y - th // 2,
                             lx + tw // 2, test_y + th // 2)
                if not any(_bboxes_overlap(test_bbox, pb) for pb in placed_bboxes):
                    break
                # Expand outward: alternate above and below with increasing distance.
                step = (attempt // 2 + 1) * 8
                shift = -step if attempt % 2 == 0 else step
            else:
                shift = 0  # give up after max iterations

            final_ly = ly + shift
            text_id = self.canvas.create_text(lx, final_ly, text=text,
                font=FONT_BOLD, fill=color,
                tags=("vm_element", "connection_label", tag))
            bbox = self.canvas.bbox(text_id)
            if bbox:
                bg_rect = self.canvas.create_rectangle(
                    bbox[0] - 2, bbox[1] - 2, bbox[2] + 2, bbox[3] + 2,
                    fill=THEME["bg"], outline=color, width=1,
                    tags=("vm_element", "connection_label", tag))
                self.canvas.tag_lower(bg_rect, text_id)
                placed_bboxes.append((bbox[0] - 2, bbox[1] - 2, bbox[2] + 2, bbox[3] + 2))

        self.canvas.tag_raise("connection_label")
        if self.canvas.find_withtag("connection"):
            for vm in self.vms.values():
                for pid in vm.port_ids.values():
                    self.canvas.tag_raise(pid)
                self.canvas.tag_raise(f"vm_port_{vm.name}")
