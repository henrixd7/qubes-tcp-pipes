# ── qubes.py ──────────────────────────────────────────────────────────────
# Qubes-specific logic: VM discovery, port scanning, policy management,
# and connection lifecycle (create / delete / kill).
# Depends on: utils (run_cmd, POLICY_FILE, EXCLUDED_VMS), models (Connection)
# When concatenated into a single-file build this module is loaded fourth.

import os
import subprocess
import time
import qubesadmin


def get_running_vms():
    """Return names of running, non-system VMs."""
    try:
        qapp = qubesadmin.Qubes()
        return [
            vm.name
            for vm in qapp.domains
            if vm.is_running()
            and vm.klass not in ["TemplateVM", "AdminVM"]
            and not vm.name.startswith("sys-")
            and vm.name not in EXCLUDED_VMS
        ]
    except Exception as e:
        print(f"Error accessing qubesadmin: {e}")
        return []


def get_listening_ports(vm_name, run_cmd_fn=None):
    """Scan listening TCP ports on *vm_name* via ``ss -ltn``."""
    if run_cmd_fn is None:
        try:
            from app import utils
            run_cmd_fn = utils.run_cmd
        except ImportError:
            run_cmd_fn = run_cmd  # single-file build: global scope

    cmd = f'qvm-run -q --pass-io --no-gui --no-autostart {vm_name} "ss -ltn"'
    output = run_cmd_fn(cmd)
    ports = set()

    for line in output.splitlines():
        if not line.startswith("LISTEN"):
            continue
        parts = line.split()
        if len(parts) >= 4 and ":" in parts[3]:
            addr, port = parts[3].rsplit(":", 1)
            addr = addr.strip("[]")
            if (
                addr in ["*", "0.0.0.0", "::"]
                or addr.startswith("127.")
                or addr == "::1"
            ):
                if port.isdigit():
                    ports.add(port)
    return list(ports)


# ── Policy helpers ───────────────────────────────────────────────────────

def add_policy_rule(client_name, remote_port, server_name):
    """Append a qubes.ConnectTCP allow rule to the policy file."""
    rule = f"qubes.ConnectTCP +{remote_port} {client_name} {server_name} allow\n"
    try:
        with open(POLICY_FILE, "a") as f:
            f.write(rule)
    except Exception as e:
        print(f"Failed to write policy: {e}")
        return False
    return True


def remove_policy_rule(conn):
    """Remove a single policy rule matching *conn*."""
    rule = (
        f"qubes.ConnectTCP +{conn.remote_port} "
        f"{conn.client_name} {conn.server_name} allow\n"
    )
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
        print(f"Failed to update policy file: {e}")


def cleanup_policy_file():
    """Remove the temporary policy file entirely."""
    if os.path.exists(POLICY_FILE):
        try:
            os.remove(POLICY_FILE)
        except Exception:
            pass


# ── Connection lifecycle ─────────────────────────────────────────────────

def kill_connection_process(conn, run_cmd_fn=None):
    """Terminate the socat subprocess and clean up on the client VM."""
    if run_cmd_fn is None:
        try:
            from app import utils
            run_cmd_fn = utils.run_cmd
        except ImportError:
            run_cmd_fn = run_cmd  # single-file build: global scope

    if conn.process:
        conn.process.terminate()
        try:
            conn.process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            conn.process.kill()

    kill_cmd = (
        f'qvm-run -q --no-gui --no-autostart {conn.client_name} '
        f'"pkill -f \'socat TCP-LISTEN:{conn.local_port}\'"'
    )
    run_cmd_fn(kill_cmd, silent=True, timeout=5)


def create_connection(client_name, local_port, server_name, remote_port):
    """Create a new qvm-connect-tcp pipe and return a Connection object."""
    if not add_policy_rule(client_name, remote_port, server_name):
        return None

    time.sleep(0.5)

    cmd = (
        f'qvm-run --pass-io --no-gui --no-autostart {client_name} '
        f'"qvm-connect-tcp {local_port}:{server_name}:{remote_port}"'
    )
    process = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )

    conn = Connection(client_name, local_port, server_name, remote_port)
    conn.process = process
    return conn
