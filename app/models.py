# ── models.py ─────────────────────────────────────────────────────────────
# Data classes: VM and Connection.
# When concatenated into a single-file build this module is loaded second.


class VM:
    """Represents a running Qubes VM on the canvas."""

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
    """Represents an active TCP pipe between two VMs."""

    def __init__(self, client_name, local_port, server_name, remote_port):
        self.client_name = client_name
        self.local_port = local_port
        self.server_name = server_name
        self.remote_port = remote_port
        self.line_id = None
        self.process = None
