# ── qubes.py ──────────────────────────────────────────────────────────────
# Qubes-specific logic: VM discovery, port scanning, policy management,
# and connection lifecycle (create / delete / kill).
# Depends on: utils (run_cmd, POLICY_FILE, EXCLUDED_VMS), models (Connection)
# When concatenated into a single-file build this module is loaded fourth.

import os
import subprocess
import tempfile
import threading
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

    cmd = [
        "qvm-run", "-q", "--pass-io", "--no-gui", "--no-autostart",
        vm_name, "ss -ltn",
    ]
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

_policy_lock = threading.Lock()

# Valid rule: "qubes.ConnectTCP +<port> <client> <server> allow"
_RULE_PATTERN = "qubes.ConnectTCP +{port} {client} {server} allow"


def _read_policy_rules():
    """Read and validate existing policy rules. Returns a list of rule strings."""
    if not os.path.exists(POLICY_FILE):
        return []
    rules = []
    try:
        with open(POLICY_FILE, "r") as f:
            for line in f:
                rule = line.rstrip("\n")
                if _validate_policy_rule(rule):
                    rules.append(rule)
    except Exception as e:
        print(f"Warning: failed to read policy file: {e}")
    return rules


def _validate_policy_rule(rule):
    """Check that *rule* matches the expected qubes.ConnectTCP format."""
    if not rule:
        return False
    parts = rule.split()
    # Expected: ["qubes.ConnectTCP", "+<port>", "<client>", "<server>", "allow"]
    if len(parts) != 5:
        return False
    if parts[0] != "qubes.ConnectTCP":
        return False
    if not parts[1].startswith("+") or not parts[1][1:].isdigit():
        return False
    if parts[4] != "allow":
        return False
    return True


def _write_policy_rules(rules):
    """Atomically write *rules* (list of strings) to the policy file."""
    dir_name = os.path.dirname(POLICY_FILE)
    try:
        os.makedirs(dir_name, exist_ok=True)
    except OSError:
        pass

    content = "\n".join(rules) + "\n" if rules else ""
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, prefix=".policy-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp_path, POLICY_FILE)
    except Exception:
        os.unlink(tmp_path)
        raise


def add_policy_rule(client_name, remote_port, server_name):
    """Add a qubes.ConnectTCP allow rule (deduplicated, atomic write)."""
    rule = _RULE_PATTERN.format(
        port=remote_port, client=client_name, server=server_name
    )
    with _policy_lock:
        existing = _read_policy_rules()
        if rule in existing:
            return True  # already present
        existing.append(rule)
        try:
            _write_policy_rules(existing)
        except Exception as e:
            print(f"Failed to write policy: {e}")
            return False
    return True


def remove_policy_rule(conn):
    """Remove a single policy rule matching *conn* (atomic write)."""
    rule = _RULE_PATTERN.format(
        port=conn.remote_port, client=conn.client_name, server=conn.server_name
    )
    with _policy_lock:
        existing = _read_policy_rules()
        try:
            existing.remove(rule)
        except ValueError:
            return  # rule not present — nothing to do
        try:
            _write_policy_rules(existing)
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

def is_connection_alive(conn):
    """Check whether the qvm-run process for *conn* is still running."""
    return conn.process is not None and conn.process.poll() is None


def kill_connection_process(conn):
    """Terminate the qvm-connect-tcp pipe via the local Popen handle.

    The Popen object is the authoritative handle — killing it severs the
    tunnel.  Remote cleanup inside the client VM is strictly a best-effort
    fallback for orphaned socat processes.
    """
    proc = conn.process
    if proc is not None:
        conn.process = None  # prevent double-kill
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        except Exception as e:
            print(f"Warning: failed to terminate process: {e}")

    # Fallback: kill orphaned socat inside the client VM.
    fallback_cmd = [
        "qvm-run", "-q", "--no-gui", "--no-autostart",
        conn.client_name,
        f"pkill -f 'socat TCP-LISTEN:{conn.local_port}'",
    ]
    try:
        subprocess.run(fallback_cmd, shell=False, timeout=5,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"Warning: fallback cleanup failed: {e}")


def create_connection(client_name, local_port, server_name, remote_port):
    """Create a new qvm-connect-tcp pipe and return a Connection object.

    After writing the policy rule, retries the qvm-run spawn with exponential
    backoff until the process stays alive (policy is picked up by qubesd) or
    max retries is reached.  This replaces the old non-deterministic
    ``time.sleep(0.5)`` hack.
    """
    if not add_policy_rule(client_name, remote_port, server_name):
        return None

    cmd = [
        "qvm-run", "--pass-io", "--no-gui", "--no-autostart",
        client_name,
        f"qvm-connect-tcp {local_port}:{server_name}:{remote_port}",
    ]

    max_retries = 5
    for attempt in range(max_retries):
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print(f"Failed to start connection: {e}")
            return None

        # Brief probe: if the process is still running after 100 ms the
        # policy was accepted and the tunnel is live.
        time.sleep(0.1)
        if process.poll() is None:
            conn = Connection(client_name, local_port, server_name, remote_port)
            conn.process = process
            return conn

        # Process exited immediately — policy likely not yet in effect.
        # Clean up the zombie and retry with backoff.
        try:
            process.wait(timeout=1)
        except Exception:
            pass

        if attempt < max_retries - 1:
            backoff = 0.2 * (2 ** attempt)  # 0.2, 0.4, 0.8, 1.6
            print(f"Policy not ready yet, retrying in {backoff:.1f}s "
                  f"(attempt {attempt + 1}/{max_retries})")
            time.sleep(backoff)

    print("Failed to establish connection: policy not picked up after "
          f"{max_retries} retries")
    return None
