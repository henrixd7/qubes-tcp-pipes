#!/usr/bin/python3

import tkinter as tk
from tkinter import messagebox
import subprocess
import signal
import atexit
import os
import sys
import threading
import time
import json
import math
import qubesadmin

# Configuration
POLICY_FILE = "/etc/qubes/policy.d/30-dev-tcp-temp.policy"
EXCLUDED_VMS = ["dom0", "mirage-firewall", "snitch-ui", "vault"]

# Cache configuration
CACHE_DIR = os.path.expanduser("~/.cache/qubes-tcp-pipes")
CACHE_FILE = os.path.join(CACHE_DIR, "ports.json")
CACHE_REFRESH_INTERVAL = 30
_cache_lock = threading.Lock()

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
FONT_MAIN = ("Helvetica", 10)
FONT_BOLD = ("Helvetica", 10, "bold")
FONT_LARGE = ("Helvetica", 11)
FONT_SMALL = ("Helvetica", 8)


def save_port_cache(vm_name, ports):
    with _cache_lock:
        try:
            os.makedirs(CACHE_DIR, exist_ok=True)
            cache = {}
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE, "r") as f:
                    cache = json.load(f)
            
            cache[vm_name] = ports
            tmp_file = CACHE_FILE + ".tmp"
            with open(tmp_file, "w") as f:
                json.dump(cache, f)
            os.replace(tmp_file, CACHE_FILE)
        except Exception as e:
            print(f"Warning: failed to save port cache: {e}")


def load_port_cache():
    with _cache_lock:
        try:
            if os.path.exists(CACHE_FILE):
                with open(CACHE_FILE, "r") as f:
                    return json.load(f)
        except Exception as e:
            print(f"Warning: failed to load port cache: {e}")
    return {}


class VM:
    def __init__(self, name, x, y):
        self.name = name
        self.x = x
        self.y = y
        self.ports = []
        self.canvas_id = None
        self.port_ids = {}
        self.shadow_id = None
        self.icon_ids = []
        self.hovered = False

    def update_ports(self, ports):
        self.ports = ports


class Connection:
    def __init__(self, client_name, local_port, server_name, remote_port):
        self.client_name = client_name
        self.local_port = local_port
        self.server_name = server_name
        self.remote_port = remote_port
        self.line_id = None
        self.process = None


class QubePipesApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Qubes TCP Pipes")
        self.root.configure(bg=THEME["bg"])

        self._setup_ui()
        
        # State
        self.vms = {}
        self.connections = []
        self.selected_source_vm = None
        self.known_source_ports = {}
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
        """Initializes the main UI components."""
        self.top_frame = tk.Frame(self.root, bg=THEME["panel_bg"], height=50, bd=1, relief=tk.RIDGE)
        self.top_frame.pack(fill=tk.X, side=tk.TOP)

        self.refresh_btn = tk.Button(
            self.top_frame, text="\u27f3 Refresh VMs", command=self.refresh_vms,
            bg="#F8F9FA", activebackground="#E2E6EA", relief=tk.GROOVE, padx=10
        )
        self.refresh_btn.pack(side=tk.LEFT, padx=15, pady=10)

        instructions = tk.Label(
            self.top_frame,
            text="1. Click a VM box to select Client   |   2. Click a green port on another VM to connect",
            bg=THEME["panel_bg"], fg=THEME["text_muted"], font=FONT_LARGE
        )
        instructions.pack(side=tk.LEFT, padx=20)

        self.canvas = tk.Canvas(self.root, width=1200, height=800, bg=THEME["bg"], highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)

        self.status_frame = tk.Frame(self.root, bg=THEME["status_bg"], height=26, bd=1, relief=tk.RIDGE)
        self.status_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.lbl_conn_count = tk.Label(self.status_frame, text="Connections: 0", bg=THEME["status_bg"], fg=THEME["status_text"], font=FONT_SMALL)
        self.lbl_conn_count.pack(side=tk.LEFT, padx=10, pady=2)

        self.lbl_vm_count = tk.Label(self.status_frame, text="VMs: 0", bg=THEME["status_bg"], fg=THEME["status_text"], font=FONT_SMALL)
        self.lbl_vm_count.pack(side=tk.LEFT, padx=10, pady=2)

        self.lbl_last_refresh = tk.Label(self.status_frame, text="Last refresh: --", bg=THEME["status_bg"], fg=THEME["status_text"], font=FONT_SMALL)
        self.lbl_last_refresh.pack(side=tk.LEFT, padx=10, pady=2)

    def setup_signals(self):
        signal.signal(signal.SIGINT, self.handle_exit)
        signal.signal(signal.SIGTERM, self.handle_exit)
        self.root.protocol("WM_DELETE_WINDOW", self.handle_exit_gui)
        atexit.register(self.cleanup)

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
            try:
                self.root.after_cancel(self._status_timer_id)
            except Exception:
                pass
            self._status_timer_id = None
            
        print("Cleaning up temporary pipes...")
        for conn in self.connections:
            self.kill_connection(conn)
            
        if os.path.exists(POLICY_FILE):
            try:
                os.remove(POLICY_FILE)
            except Exception:
                pass
        self.connections.clear()

    def run_cmd(self, cmd, silent=False, timeout=10):
        try:
            kwargs = {
                "shell": True, 
                "stdout": subprocess.DEVNULL if silent else subprocess.PIPE,
                "stderr": subprocess.DEVNULL,
                "check": False, 
                "timeout": timeout
            }
            if not silent:
                kwargs["text"] = True
                
            result = subprocess.run(cmd, **kwargs)
            return "" if silent else result.stdout
        except subprocess.TimeoutExpired:
            print(f"Warning: command timed out ({timeout}s): {cmd}")
            return ""
        except Exception as e:
            print(f"Error running command {cmd}: {e}")
            return ""

    def get_port_color(self, port_str):
        palette = [
            "#0D6EFD", "#6610F2", "#6F42C1", "#D63384", "#DC3545",
            "#FD7E14", "#F5C211", "#0DCAF0", "#FF4500", "#8A2BE2",
            "#E83E8C", "#00796B"
        ]
        return palette[sum(ord(c) for c in str(port_str)) % len(palette)]

    def get_running_vms(self):
        try:
            qapp = qubesadmin.Qubes()
            return [
                vm.name for vm in qapp.domains 
                if vm.is_running() 
                and vm.klass not in ['TemplateVM', 'AdminVM'] 
                and not vm.name.startswith("sys-") 
                and vm.name not in EXCLUDED_VMS
            ]
        except Exception as e:
            print(f"Error accessing qubesadmin: {e}")
            return []

    def get_listening_ports(self, vm_name):
        cmd = f'qvm-run -q --pass-io --no-gui --no-autostart {vm_name} "ss -ltn"'
        output = self.run_cmd(cmd)
        ports = set()
        
        for line in output.splitlines():
            if not line.startswith("LISTEN"):
                continue
            parts = line.split()
            if len(parts) >= 4 and ":" in parts[3]:
                addr, port = parts[3].rsplit(":", 1)
                addr = addr.strip("[]")
                if addr in ["*", "0.0.0.0", "::"] or addr.startswith("127.") or addr == "::1":
                    if port.isdigit():
                        ports.add(port)
        return list(ports)

    def refresh_vms(self):
        self.selected_source_vm = None
        
        # Keep existing VM instances if possible to prevent UI jitter
        current_vms = self.get_running_vms()
        self.vms = {name: self.vms.get(name, VM(name, 0, 0)) for name in current_vms}

        self.connections = [
            conn for conn in self.connections 
            if conn.client_name in self.vms and conn.server_name in self.vms
        ]

        cache = load_port_cache()
        for name, vm in self.vms.items():
            if name in cache:
                vm.update_ports(cache[name])

        self.render_vms()
        self._last_refresh_time = time.time()
        self.update_status_bar()

        threading.Thread(target=self.discover_ports_worker, daemon=True).start()

    def discover_ports_worker(self):
        for name in list(self.vms.keys()):
            try:
                ports = self.get_listening_ports(name)
                save_port_cache(name, ports)
                self.root.after(0, self.update_vm_ports_ui, name, ports)
            except Exception as e:
                print(f"Warning: failed to scan ports for {name}: {e}")

    def _update_status_timer(self):
        self.update_status_bar()
        self._status_timer_id = self.root.after(1000, self._update_status_timer)

    def start_background_refresh(self):
        self._background_refresh_running = True

        def _loop():
            while self._background_refresh_running:
                time.sleep(CACHE_REFRESH_INTERVAL)
                if not self._background_refresh_running:
                    break
                self.discover_ports_worker()
                self._last_refresh_time = time.time()
                self.root.after(0, self.update_status_bar)

        threading.Thread(target=_loop, daemon=True).start()

    def kill_connection(self, conn):
        if conn.process:
            conn.process.terminate()
            try:
                conn.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                conn.process.kill()
        
        kill_cmd = (f'qvm-run -q --no-gui --no-autostart {conn.client_name} '
                    f'"pkill -f \'socat TCP-LISTEN:{conn.local_port}\'"')
        self.run_cmd(kill_cmd, silent=True, timeout=5)

    def delete_connection(self, conn):
        self.kill_connection(conn)
        if conn in self.connections:
            self.connections.remove(conn)
        self.remove_policy_rule(conn)
        self.redraw_connections()
        self.update_status_bar()

    def remove_policy_rule(self, conn):
        rule = f"qubes.ConnectTCP +{conn.remote_port} {conn.client_name} {conn.server_name} allow\n"
        if not os.path.exists(POLICY_FILE):
            return
            
        try:
            with open(POLICY_FILE, "r") as f:
                lines = f.readlines()
            with open(POLICY_FILE, "w") as f:
                for line in lines:
                    if line != rule:
                        f.write(line)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update policy file: {e}")

    def create_connection(self, client_name, local_port, server_name, remote_port):
        rule = f"qubes.ConnectTCP +{remote_port} {client_name} {server_name} allow\n"
        try:
            with open(POLICY_FILE, "a") as f:
                f.write(rule)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write policy: {e}")
            return

        time.sleep(0.5)

        cmd = (f'qvm-run --pass-io --no-gui --no-autostart {client_name} '
               f'"qvm-connect-tcp {local_port}:{server_name}:{remote_port}"')
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        conn = Connection(client_name, local_port, server_name, remote_port)
        conn.process = process
        self.connections.append(conn)

        if client_name not in self.known_source_ports:
            self.known_source_ports[client_name] = set()
        self.known_source_ports[client_name].add(str(local_port))

        self.redraw_connections()
        self.update_status_bar()

    def update_status_bar(self):
        self.lbl_conn_count.config(text=f"Connections: {len(self.connections)}")
        self.lbl_vm_count.config(text=f"VMs: {len(self.vms)}")
        if self._last_refresh_time:
            ago = int(time.time() - self._last_refresh_time)
            self.lbl_last_refresh.config(text=f"Last refresh: {ago}s ago")

    # ── Canvas rendering ───────────────────────────────────────────────

    def on_resize(self, event):
        if abs(event.width - self.last_width) > 20:
            self.last_width = event.width
            self.render_vms(event.width)

    def render_vms(self, width=None):
        self.canvas.delete("vm_element")
        self._hover_bind_ids.clear()

        width = width or self.canvas.winfo_width()
        if width < 10: width = 1200
        cols = max(1, width // 280)

        for i, (name, vm) in enumerate(self.vms.items()):
            row, col = divmod(i, cols)
            vm.x = 140 + col * 280
            vm.y = 80 + row * 160
            self.draw_vm_box(vm)
            if vm.ports:
                self.update_vm_ports_ui(name, vm.ports, redraw_lines=False)

        self.redraw_connections()

    def draw_vm_box(self, vm):
        px, py = 55, 45
        
        # Shadow
        vm.shadow_id = self.canvas.create_rectangle(
            vm.x - px + 2, vm.y - py + 2, vm.x + px + 2, vm.y + py + 2,
            fill=THEME["shadow"], outline="", tags=("vm_element", "vm_box", vm.name)
        )

        # Card
        vm.canvas_id = self.canvas.create_rectangle(
            vm.x - px, vm.y - py, vm.x + px, vm.y + py,
            fill=THEME["vm_bg"], outline=THEME["vm_border"], width=2,
            tags=("vm_element", "vm_box", vm.name)
        )

        # Terminal Icon
        cx, cy = vm.x, vm.y - 30
        c_tag = ("vm_element", "vm_box", vm.name)
        vm.icon_ids = [
            self.canvas.create_rectangle(cx - 8, cy - 6, cx + 8, cy + 6, outline=THEME["text_muted"], tags=c_tag),
            self.canvas.create_line(cx - 5, cy + 10, cx + 5, cy + 10, fill=THEME["text_muted"], tags=c_tag),
            self.canvas.create_line(cx, cy + 6, cx, cy + 10, fill=THEME["text_muted"], tags=c_tag)
        ]

        self.canvas.create_text(
            vm.x, vm.y, text=vm.name, font=FONT_BOLD, fill=THEME["text_main"], tags=c_tag
        )

        # Active connection dot
        if any(c.client_name == vm.name or c.server_name == vm.name for c in self.connections):
            dot = self.canvas.create_oval(
                vm.x + px - 14, vm.y - py + 6, vm.x + px - 6, vm.y - py + 14,
                fill=THEME["port_fill"], outline="", tags=c_tag
            )
            vm.icon_ids.append(dot)

        # Hover binds
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
        if name not in self.vms: return
        vm = self.vms[name]
        
        sorted_ports = sorted(ports, key=lambda p: int(p) if p.isdigit() else p)
        vm.update_ports(sorted_ports)

        # Clear old items safely
        for pid in vm.port_ids.values():
            self.canvas.delete(pid)
        vm.port_ids.clear()
        self.canvas.delete(f"vm_port_{name}")

        px, py_val = 55, 45
        x2 = vm.x + px
        y1, y2 = vm.y - py_val, vm.y + py_val

        for i, port in enumerate(sorted_ports):
            py_pos = y1 + (i + 1) * (y2 - y1) / (len(sorted_ports) + 1)
            port_tag = f"vm_port_{name}"
            
            port_id = self.canvas.create_oval(
                x2 - 6, py_pos - 6, x2 + 6, py_pos + 6,
                fill=THEME["port_fill"], outline=THEME["port_border"], width=1,
                tags=("vm_element", "port", port_tag)
            )
            self.canvas.create_text(
                x2 + 24, py_pos, text=port, font=FONT_MAIN, fill=THEME["text_main"],
                tags=("vm_element", "port_text", port_tag)
            )
            vm.port_ids[port] = port_id

        # Trigger line recalculation now that ports have shifted
        if redraw_lines:
            self.redraw_connections()

    def get_port_coords(self, vm, port):
        """Pure mathematical alignment calculation. Prevents Tkinter race-condition jitter."""
        px, py = 55, 45
        x2 = vm.x + px
        y1, y2 = vm.y - py, vm.y + py
        
        all_ports = sorted(vm.ports, key=lambda p: int(p) if p.isdigit() else p)
        if not all_ports:
            return x2, (y1 + y2) / 2
            
        try:
            idx = all_ports.index(str(port))
        except ValueError:
            idx = 0
            
        py_pos = y1 + (idx + 1) * (y2 - y1) / (len(all_ports) + 1)
        return x2, py_pos

    def on_click(self, event):
        # Click priority: Port > VM Box
        for vm in self.vms.values():
            for port, pid in vm.port_ids.items():
                coords = self.canvas.coords(pid)
                if coords and abs(event.x - (coords[0] + coords[2])/2) < 25 and abs(event.y - (coords[1] + coords[3])/2) < 15:
                    self.handle_target_port_click(vm, port)
                    return

        item = self.canvas.find_closest(event.x, event.y, 10)
        if item and "vm_box" in self.canvas.gettags(item[0]):
            vm_name = self.canvas.gettags(item[0])[2]
            self.handle_source_vm_click(self.vms[vm_name])

    def handle_source_vm_click(self, vm):
        if self.selected_source_vm:
            self.canvas.itemconfig(self.selected_source_vm.canvas_id, fill=THEME["vm_bg"], outline=THEME["vm_border"])
            if self.selected_source_vm == vm:
                self.selected_source_vm = None
                return

        self.selected_source_vm = vm
        self.canvas.itemconfig(vm.canvas_id, fill=THEME["vm_sel_bg"], outline=THEME["vm_sel_border"])

    def handle_target_port_click(self, target_vm, remote_port):
        if not self.selected_source_vm:
            messagebox.showinfo("Select Client", "Please click a VM box first to select the source Client.")
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
        if not item: return

        tags = self.canvas.gettags(item[0])
        conn_tag = next((t for t in tags if t.startswith("conn_")), None)
        if not conn_tag: return

        target_conn = next((c for c in self.connections if f"conn_{id(c)}" == conn_tag), None)
        if target_conn and messagebox.askyesno(
            "Delete Connection",
            f"Sever connection from {target_conn.client_name} to {target_conn.server_name}:{target_conn.remote_port}?"
        ):
            self.delete_connection(target_conn)

    def _compute_route(self, src_x, src_y, dst_x, dst_y, idx, total):
        """Orthogonal channel routing strictly avoiding VM boxes and nesting parallel lanes."""
        # Use connection index to create deterministic, perfectly parallel non-overlapping lanes
        lane_spacing = 10
        offset = (idx - (total - 1) / 2.0) * lane_spacing

        # Calculate logical grid coordinates
        col_src = int((src_x - 140) // 280)
        col_dst = int((dst_x - 140) // 280)
        row_src = int((src_y - 80 + 45) // 160)
        row_dst = int((dst_y - 80 + 45) // 160)
        
        path = [(src_x, src_y)]
        
        # Vertical channels immediately to the right of the respective VMs
        v_chan_src = (140 + col_src * 280) + 95 + offset
        v_chan_dst = (140 + col_dst * 280) + 95 + offset
        
        max_row = max(row_src, row_dst)
        
        if col_src == col_dst:
            if row_src == row_dst:
                path.extend([(v_chan_src, src_y), (v_chan_src, dst_y), (dst_x, dst_y)])
            else:
                path.extend([(v_chan_src, src_y), (v_chan_src, dst_y), (dst_x, dst_y)])
            return path, v_chan_src + 6, (src_y + dst_y) / 2
            
        # Horizontal channel safely placed exactly between grid rows to avoid VM boxes
        # (Rows are at y=80, 240, 400. Safe gaps are at y=160, 320, 480.)
        if row_src == row_dst:
            h_chan = 160 * (row_src + 1) + offset
        else:
            h_chan = 160 * max_row + offset
            
        path.extend([
            (v_chan_src, src_y),
            (v_chan_src, h_chan),
            (v_chan_dst, h_chan),
            (v_chan_dst, dst_y),
            (dst_x, dst_y)
        ])
        
        label_x = (v_chan_src + v_chan_dst) / 2
        label_y = h_chan - 12
        
        return path, label_x, label_y

    def _smooth_path(self, path, radius=15):
        """Mathematically generates a smooth, curved path to avoid Tkinter's finicky spline rendering."""
        if len(path) < 3: return path
        result = [path[0]]
        
        for i in range(1, len(path) - 1):
            p0 = result[-1] if len(result) > 1 else path[i-1]
            p1, p2 = path[i], path[i+1]
            
            d1 = math.hypot(p1[0] - p0[0], p1[1] - p0[1])
            d2 = math.hypot(p2[0] - p1[0], p2[1] - p1[1])
            r = min(radius, d1 / 2, d2 / 2)
            
            if r <= 0:
                result.append(p1)
                continue
                
            dx1, dy1 = (p0[0] - p1[0]) / d1, (p0[1] - p1[1]) / d1
            dx2, dy2 = (p2[0] - p1[0]) / d2, (p2[1] - p1[1]) / d2
            
            # Create a 3-point approximation for a soft, rounded corner
            result.extend([
                (p1[0] + dx1 * r, p1[1] + dy1 * r),
                (p1[0] + (dx1 + dx2) * r * 0.414, p1[1] + (dy1 + dy2) * r * 0.414),
                (p1[0] + dx2 * r, p1[1] + dy2 * r)
            ])
            
        result.append(path[-1])
        return result

    def draw_connection_line(self, conn, idx, total, labels_list):
        client_vm = self.vms.get(conn.client_name)
        server_vm = self.vms.get(conn.server_name)
        if not client_vm or not server_vm: return

        src_port_str = str(conn.local_port)
        src_x, src_y = self.get_port_coords(client_vm, src_port_str) if (client_vm.name in self.known_source_ports and src_port_str in self.known_source_ports[client_vm.name]) else (client_vm.x, client_vm.y)
        dst_x, dst_y = self.get_port_coords(server_vm, str(conn.remote_port))

        conn_tag = f"conn_{id(conn)}"
        line_color = self.get_port_color(conn.remote_port)

        path, label_x, label_y = self._compute_route(src_x, src_y, dst_x, dst_y, idx, total)
        smoothed_path = self._smooth_path(path, radius=8)
        
        flat_coords = [c for pt in smoothed_path for c in pt]

        # Draw main smoothed connection line
        conn.line_id = self.canvas.create_line(
            *flat_coords, fill=line_color, width=2.5, smooth=False,
            tags=("vm_element", "connection", conn_tag)
        )

        # Connection endpoints
        for x, y in [(src_x, src_y), (dst_x, dst_y)]:
            self.canvas.create_rectangle(
                x - 3, y - 3, x + 3, y + 3, fill=line_color, outline="", 
                tags=("vm_element", "connection", conn_tag)
            )

        # Defer connection label rendering to fix Z-ordering visibility bug
        labels_list.append((label_x, label_y, f" {conn.local_port}→{conn.remote_port} ", line_color, conn_tag))

    def redraw_connections(self):
        self.canvas.delete("connection")
        self.canvas.delete("connection_label")
        
        labels = []
        # Sort connections to ensure predictable parallel lane assignments (nesting)
        sorted_conns = sorted(self.connections, key=lambda c: (
            c.server_name, c.remote_port, c.client_name, c.local_port
        ))
        
        for i, conn in enumerate(sorted_conns):
            self.draw_connection_line(conn, i, len(sorted_conns), labels)

        # Draw labels on top of all lines
        for lx, ly, text, color, tag in labels:
            cw, ch = self.canvas.winfo_width(), self.canvas.winfo_height()
            lx, ly = max(10, min(cw - 10, lx)), max(10, min(ch - 10, ly))
            
            text_id = self.canvas.create_text(
                lx, ly, text=text, font=FONT_BOLD, fill=color, tags=("vm_element", "connection_label", tag)
            )
            bbox = self.canvas.bbox(text_id)
            if bbox:
                bg_rect = self.canvas.create_rectangle(
                    bbox[0] - 2, bbox[1] - 2, bbox[2] + 2, bbox[3] + 2,
                    fill=THEME["bg"], outline=color, width=1,
                    tags=("vm_element", "connection_label", tag)
                )
                self.canvas.tag_lower(bg_rect, text_id)

        # Fix final Z-ordering: Labels highest, then Ports, then Lines
        self.canvas.tag_raise("connection_label")
        
        if self.canvas.find_withtag("connection"):
            for vm in self.vms.values():
                for pid in vm.port_ids.values():
                    self.canvas.tag_raise(pid)
                self.canvas.tag_raise(f"vm_port_{vm.name}")

if __name__ == "__main__":
    root = tk.Tk()
    root.minsize(800, 600)
    app = QubePipesApp(root)
    root.mainloop()
