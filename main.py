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
import qubesadmin

# Configuration
POLICY_FILE = "/etc/qubes/policy.d/30-dev-tcp-temp.policy"
EXCLUDED_VMS = ["dom0", "mirage-firewall", "snitch-ui", "vault"]

# Visual Theme
THEME = {
    "bg": "#F0F2F5",             # Main canvas background
    "panel_bg": "#FFFFFF",       # Top bar background
    "text_main": "#333333",      # Standard text
    "text_muted": "#666666",     # Instructions text
    "vm_bg": "#FFFFFF",          # VM Card background
    "vm_border": "#CED4DA",      # VM Card border
    "vm_sel_bg": "#E7F1FF",      # Selected VM background
    "vm_sel_border": "#0D6EFD",  # Selected VM border
    "port_fill": "#20C997",      # Port circle
    "port_border": "#198754",    # Port border
    "line": "#0D6EFD",           # Connection line
}
FONT_MAIN = ("Helvetica", 10)
FONT_BOLD = ("Helvetica", 10, "bold")
FONT_LARGE = ("Helvetica", 11)

class VM:
    def __init__(self, name, x, y):
        self.name = name
        self.x = x
        self.y = y
        self.ports = []
        self.canvas_id = None
        self.port_ids = {} # port -> canvas item ID

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
        
        # --- UI Layout ---
        # Top Control Panel
        self.top_frame = tk.Frame(root, bg=THEME["panel_bg"], height=50, bd=1, relief=tk.RIDGE)
        self.top_frame.pack(fill=tk.X, side=tk.TOP)
        
        self.refresh_btn = tk.Button(
            self.top_frame, text="⟳ Refresh VMs", command=self.refresh_vms, 
            bg="#F8F9FA", activebackground="#E2E6EA", relief=tk.GROOVE, padx=10
        )
        self.refresh_btn.pack(side=tk.LEFT, padx=15, pady=10)

        instructions = tk.Label(
            self.top_frame, 
            text="1. Click a VM box to select Client   |   2. Click a green port on another VM to connect", 
            bg=THEME["panel_bg"], fg=THEME["text_muted"], font=FONT_LARGE
        )
        instructions.pack(side=tk.LEFT, padx=20)

        # Main Canvas
        self.canvas = tk.Canvas(root, width=1200, height=800, bg=THEME["bg"], highlightthickness=0)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        
        # --- State Variables ---
        self.vms = {}
        self.connections = []
        self.selected_source_vm = None
        
        self.setup_signals()
        self.refresh_vms()
        
        self.canvas.bind("<Button-1>", self.on_click)
        self.canvas.bind("<Button-3>", self.on_right_click)
        self.canvas.bind("<Configure>", self.on_resize)
        self.last_width = self.root.winfo_width()

    def setup_signals(self):
        signal.signal(signal.SIGINT, self.handle_exit)
        signal.signal(signal.SIGTERM, self.handle_exit)
        self.root.protocol("WM_DELETE_WINDOW", self.handle_exit_gui)
        atexit.register(self.cleanup)

    def handle_exit(self, signum, frame):
        self.cleanup()
        sys.exit(0)
        
    def handle_exit_gui(self):
        self.cleanup()
        self.root.destroy()
        sys.exit(0)

    def run_cmd(self, cmd, silent=False):
        try:
            if silent:
                subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                return ""
            else:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
                return result.stdout
        except Exception as e:
            print(f"Error running command {cmd}: {e}")
            return ""

    def get_port_color(self, port_str):
        # Expanded palette, explicitly avoiding the UI's port green
        palette = [
            "#0D6EFD", # Blue
            "#6610F2", # Indigo
            "#6F42C1", # Purple
            "#D63384", # Pink
            "#DC3545", # Red
            "#FD7E14", # Orange
            "#F5C211", # Yellow (dark enough for white bg)
            "#0DCAF0", # Cyan
            "#FF4500", # OrangeRed
            "#8A2BE2", # BlueViolet
            "#E83E8C", # Hot Pink
            "#00796B"  # Dark Teal
        ]
        color_index = sum(ord(c) for c in str(port_str)) % len(palette)
        return palette[color_index]

    def get_running_vms(self):
        try:
            qapp = qubesadmin.Qubes()
            filtered = []
            for vm in qapp.domains:
                if (vm.is_running() and 
                    vm.klass not in ['TemplateVM', 'AdminVM'] and 
                    not vm.name.startswith("sys-") and 
                    vm.name not in EXCLUDED_VMS):
                    filtered.append(vm.name)
            return filtered
        except Exception as e:
            print(f"Error accessing qubesadmin: {e}")
            return []

    def get_listening_ports(self, vm):
        # Removed the grep so we get all listening TCP ports
        cmd = f'qvm-run -q --pass-io --no-gui --no-autostart {vm} "ss -ltn"'
        output = self.run_cmd(cmd)
        ports = []
        
        for line in output.splitlines():
            # Only process lines representing actively listening sockets
            if not line.startswith("LISTEN"):
                continue
                
            parts = line.split()
            # ss -ltn columns: State, Recv-Q, Send-Q, Local Address:Port, Peer Address:Port
            if len(parts) >= 4:
                addr_port = parts[3]
                
                if ":" in addr_port:
                    # rsplit(":", 1) splits by the LAST colon to safely handle IPv6 addresses
                    addr, port = addr_port.rsplit(":", 1)
                    
                    # Strip brackets from IPv6 formats (e.g., [::])
                    addr = addr.strip("[]")
                    
                    # Include it if it listens on all interfaces (*, 0.0.0.0, ::) 
                    # or explicitly on localhost (127.x.x.x, ::1)
                    if addr in ["*", "0.0.0.0", "::"] or addr.startswith("127.") or addr == "::1":
                        if port.isdigit():
                            ports.append(port)
                            
        return list(set(ports))

    def refresh_vms(self):
        self.selected_source_vm = None
        
        vm_names = self.get_running_vms()
        new_vms = {}
        for name in vm_names:
            new_vms[name] = VM(name, 0, 0)
            
        self.vms = new_vms
        
        # Keep valid connections, cleanup orphaned ones
        active_connections = []
        for conn in self.connections:
            # If either the client or server VM was shut down, kill the pipe
            if conn.client_name in self.vms and conn.server_name in self.vms:
                active_connections.append(conn)
            else:
                self.kill_connection(conn)
        self.connections = active_connections
            
        self.render_vms()
        threading.Thread(target=self.discover_ports_worker, daemon=True).start()

    def kill_connection(self, conn):
        if conn.process:
            conn.process.terminate()
            try:
                conn.process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                conn.process.kill()
                
        kill_cmd = f'qvm-run -q --no-gui --no-autostart {conn.client_name} "pkill -f \'socat TCP-LISTEN:{conn.local_port}\'"'
        subprocess.Popen(kill_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def on_resize(self, event):
        if abs(event.width - self.last_width) > 20:
            self.last_width = event.width
            self.render_vms(event.width)

    def render_vms(self, width=None):
        self.canvas.delete("vm_element")
        
        if not width:
            width = self.canvas.winfo_width()
        if width < 10: 
            width = 1200
            
        # Adjusted columns to account for wider screen space
        cols = max(1, width // 280) 
        
        for i, (name, vm) in enumerate(self.vms.items()):
            row = i // cols
            col = i % cols
            # Calculate center point for the VM box
            vm.x = 140 + col * 280
            vm.y = 80 + row * 160 
            self.draw_vm_box(vm)
            
            if vm.ports:
                self.update_vm_ports_ui(name, vm.ports)

        self.redraw_connections()
                
        for conn in self.connections:
            self.draw_connection_line(conn)

    def draw_vm_box(self, vm):
        # Increased padding slightly for a "card" look
        padding_x = 55
        padding_y = 45
        x1, y1 = vm.x - padding_x, vm.y - padding_y
        x2, y2 = vm.x + padding_x, vm.y + padding_y
        
        # Draw the main card body
        vm.canvas_id = self.canvas.create_rectangle(
            x1, y1, x2, y2, 
            fill=THEME["vm_bg"], outline=THEME["vm_border"], width=2, 
            tags=("vm_element", "vm_box", vm.name)
        )
        
        # Draw the VM Name text
        self.canvas.create_text(
            vm.x, vm.y, 
            text=vm.name, font=FONT_BOLD, fill=THEME["text_main"], 
            tags=("vm_element", "vm_box", vm.name)
        )

    def discover_ports_worker(self):
        for name, vm in self.vms.items():
            ports = self.get_listening_ports(name)
            self.root.after(0, self.update_vm_ports_ui, name, ports)

    def handle_source_vm_click(self, vm):
        if self.selected_source_vm == vm:
            self.canvas.itemconfig(vm.canvas_id, fill=THEME["vm_bg"], outline=THEME["vm_border"])
            self.selected_source_vm = None
            return

        if self.selected_source_vm:
            self.canvas.itemconfig(self.selected_source_vm.canvas_id, fill=THEME["vm_bg"], outline=THEME["vm_border"])
        
        self.selected_source_vm = vm
        self.canvas.itemconfig(vm.canvas_id, fill=THEME["vm_sel_bg"], outline=THEME["vm_sel_border"])

    def update_vm_ports_ui(self, name, ports):
        vm = self.vms[name]
        # Sort ports numerically for consistent display
        sorted_ports = sorted(ports, key=lambda p: int(p) if p.isdigit() else p)
        vm.update_ports(sorted_ports)
        
        padding_x = 55
        padding_y = 45
        x2 = vm.x + padding_x
        y1 = vm.y - padding_y
        y2 = vm.y + padding_y
        
        for i, port in enumerate(sorted_ports):
            py = y1 + (i + 1) * (y2 - y1) / (len(sorted_ports) + 1)
            
            # Draw port circle
            port_id = self.canvas.create_oval(
                x2-6, py-6, x2+6, py+6, 
                fill=THEME["port_fill"], outline=THEME["port_border"], width=1, 
                tags=("vm_element", "port")
            )
            # Draw port text
            self.canvas.create_text(
                x2+24, py, 
                text=port, font=FONT_MAIN, fill=THEME["text_main"], 
                tags=("vm_element", "port_text")
            )
            vm.port_ids[port] = port_id

        # Redraw connections now that new port coordinates are known
        self.redraw_connections()

    def on_click(self, event):
        item = self.canvas.find_closest(event.x, event.y)
        if not item:
            return
        
        item_id = item[0]
        tags = self.canvas.gettags(item_id)
        
        if "port" in tags or "port_text" in tags:
            # User clicked near/on a destination port
            for vm in self.vms.values():
                for port, pid in vm.port_ids.items():
                    # Check distance manually to be generous with clicks if they hit the text
                    coords = self.canvas.coords(pid)
                    if coords:
                        cx = (coords[0] + coords[2]) / 2
                        cy = (coords[1] + coords[3]) / 2
                        if abs(event.x - cx) < 40 and abs(event.y - cy) < 15:
                            self.handle_target_port_click(vm, port)
                            return
        elif "vm_box" in tags:
            vm_name = tags[2]
            self.handle_source_vm_click(self.vms[vm_name])

    def handle_target_port_click(self, target_vm, remote_port):
        if not self.selected_source_vm:
            messagebox.showinfo("Select Client", "Please click a VM box first to select the source Client.")
            return
            
        client_vm = self.selected_source_vm
        
        if client_vm.name == target_vm.name:
            messagebox.showwarning("Warning", "Cannot connect a VM to itself.")
            self.canvas.itemconfig(client_vm.canvas_id, fill=THEME["vm_bg"], outline=THEME["vm_border"])
            self.selected_source_vm = None
            return

        local_port = remote_port
        self.create_connection(client_vm.name, local_port, target_vm.name, remote_port)
        
        # Reset visual selection
        self.canvas.itemconfig(client_vm.canvas_id, fill=THEME["vm_bg"], outline=THEME["vm_border"])
        self.selected_source_vm = None

    def create_connection(self, client_name, local_port, server_name, remote_port):
        rule = f"qubes.ConnectTCP +{remote_port} {client_name} {server_name} allow\n"
        try:
            with open(POLICY_FILE, "a") as f:
                f.write(rule)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to write policy: {e}")
            return

        time.sleep(0.5)

        cmd = f'qvm-run --pass-io --no-gui --no-autostart {client_name} "qvm-connect-tcp {local_port}:{server_name}:{remote_port}"'
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        conn = Connection(client_name, local_port, server_name, remote_port)
        conn.process = process
        
        self.connections.append(conn)
        self.redraw_connections()

    def on_right_click(self, event):
        item = self.canvas.find_closest(event.x, event.y)
        if not item:
            return
            
        tags = self.canvas.gettags(item[0])
        if "connection" not in tags:
            return
            
        # Find the unique connection tag we assigned
        conn_tag = next((t for t in tags if t.startswith("conn_")), None)
        if not conn_tag:
            return
            
        # Match the tag to the connection object
        target_conn = next((c for c in self.connections if f"conn_{id(c)}" == conn_tag), None)
        if not target_conn:
            return
            
        if messagebox.askyesno(
            "Delete Connection", 
            f"Sever connection from {target_conn.client_name} to {target_conn.server_name}:{target_conn.remote_port}?"
        ):
            self.delete_connection(target_conn)

    def delete_connection(self, conn):
        # 1. Kill the socat process
        self.kill_connection(conn)
        
        # 2. Remove from active connections list
        if conn in self.connections:
            self.connections.remove(conn)
            
        # 3. Remove rule from policy file
        self.remove_policy_rule(conn)
        
        # 4. Refresh UI
        self.redraw_connections()

    def remove_policy_rule(self, conn):
        rule_to_remove = f"qubes.ConnectTCP +{conn.remote_port} {conn.client_name} {conn.server_name} allow\n"
        if not os.path.exists(POLICY_FILE):
            return
            
        try:
            # Read all lines, keep everything except the one we want to delete
            with open(POLICY_FILE, "r") as f:
                lines = f.readlines()
                
            with open(POLICY_FILE, "w") as f:
                for line in lines:
                    if line != rule_to_remove:
                        f.write(line)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update policy file: {e}")

    def draw_connection_line(self, conn):
        client_vm = self.vms.get(conn.client_name)
        server_vm = self.vms.get(conn.server_name)
        
        if not client_vm or not server_vm or conn.remote_port not in server_vm.port_ids:
            return 
            
        # Back to basics: Start from the center of the source VM
        src_x, src_y = client_vm.x, client_vm.y
        
        dst_coords = self.canvas.coords(server_vm.port_ids[conn.remote_port])
        if not dst_coords:
            return
            
        dst_x = (dst_coords[0] + dst_coords[2]) / 2
        dst_y = (dst_coords[1] + dst_coords[3]) / 2
        
        line_color = self.get_port_color(conn.remote_port)
        conn_tag = f"conn_{id(conn)}"
        
        # 1. Draw a clean, straight line
        conn.line_id = self.canvas.create_line(
            src_x, src_y, dst_x, dst_y, 
            fill=line_color, width=2.5, arrow=tk.LAST, 
            tags=("vm_element", "connection", conn_tag)
        )
        
        # 2. Stagger the text position based on port number
        # This scatters the labels along the line so they don't stack on top of each other
        # Yields a ratio between 0.25 and 0.74
        ratio = 0.25 + ((int(conn.remote_port) * 17) % 50) / 100.0
        
        text_x = src_x + (dst_x - src_x) * ratio
        text_y = src_y + (dst_y - src_y) * ratio
        
        text_id = self.canvas.create_text(
            text_x, text_y, 
            text=f" L:{conn.local_port} ", font=FONT_BOLD, fill=line_color, 
            tags=("vm_element", "connection", conn_tag)
        )
        
        bbox = self.canvas.bbox(text_id)
        if bbox:
            bg_rect = self.canvas.create_rectangle(
                bbox[0]-2, bbox[1]-2, bbox[2]+2, bbox[3]+2, 
                fill=THEME["bg"], outline=line_color, width=1, 
                tags=("vm_element", "connection", conn_tag)
            )
            self.canvas.tag_lower(bg_rect, text_id)
            self.canvas.tag_lower(conn.line_id, bg_rect)

    def redraw_connections(self):
        self.canvas.delete("connection")
        for conn in self.connections:
            self.draw_connection_line(conn)
        
    def cleanup(self):
        print("Cleaning up temporary pipes...")
        for conn in self.connections:
            self.kill_connection(conn)
            
        if os.path.exists(POLICY_FILE):
            try:
                os.remove(POLICY_FILE)
            except Exception:
                pass 
                
        self.connections = []

if __name__ == "__main__":
    root = tk.Tk()
    # Set a minimum window size so the UI doesn't crush
    root.minsize(800, 600)
    app = QubePipesApp(root)
    root.mainloop()
