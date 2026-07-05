import sys
import threading
import types
import unittest
from unittest import mock

if "tkinter" not in sys.modules:
    tk_stub = types.ModuleType("tkinter")
    tk_stub.X = "x"
    tk_stub.BOTH = "both"
    tk_stub.TOP = "top"
    tk_stub.BOTTOM = "bottom"
    tk_stub.LEFT = "left"
    tk_stub.RIDGE = "ridge"
    tk_stub.GROOVE = "groove"
    tk_stub.E = "e"
    tk_stub.W = "w"
    tk_stub.Frame = mock.Mock()
    tk_stub.Button = mock.Mock()
    tk_stub.Label = mock.Mock()
    tk_stub.Canvas = mock.Mock()
    messagebox_stub = types.SimpleNamespace(
        showerror=mock.Mock(),
        showinfo=mock.Mock(),
        showwarning=mock.Mock(),
        askyesno=mock.Mock(return_value=True),
    )
    tk_stub.messagebox = messagebox_stub
    sys.modules["tkinter"] = tk_stub
    sys.modules["tkinter.messagebox"] = messagebox_stub

from app.models import Connection, VM
from app.ui import QubePipesApp


class FakeRoot:
    def __init__(self):
        self.after_calls = []

    def after(self, delay, callback, *args):
        self.after_calls.append((delay, callback, args))


def make_app():
    app = QubePipesApp.__new__(QubePipesApp)
    app.root = FakeRoot()
    app._state_lock = threading.Lock()
    app.connections = []
    app.vms = {}
    app.selected_source_vm = None
    app._last_refresh_time = None
    app.redraw_connections = mock.Mock()
    app.update_status_bar = mock.Mock()
    app.render_vms = mock.Mock()
    return app


def make_conn(client="client", server="server"):
    return Connection(client, "1234", server, "4321")


class ShutdownCleanupTests(unittest.TestCase):
    def setUp(self):
        self.print_patcher = mock.patch("app.ui.print")
        self.print_mock = self.print_patcher.start()
        self.addCleanup(self.print_patcher.stop)

    @mock.patch("app.ui.remove_policy_rule")
    @mock.patch("app.ui.kill_connection_process")
    def test_cleanup_for_vm_removes_and_cleans_after_releasing_lock(
            self, kill_connection_process, remove_policy_rule):
        app = make_app()
        target = make_conn()
        other = make_conn("other-client", "other-server")
        app.connections = [target, other]

        def assert_lock_released(_conn):
            self.assertFalse(app._state_lock.locked())

        kill_connection_process.side_effect = assert_lock_released

        removed = app._cleanup_connections_for_vm("client", "test shutdown")

        self.assertEqual(removed, [target])
        self.assertEqual(app.connections, [other])
        kill_connection_process.assert_called_once_with(target)
        remove_policy_rule.assert_called_once_with(target)
        self.assertEqual(len(app.root.after_calls), 2)

    @mock.patch("app.ui.threading.Thread")
    @mock.patch("app.ui.load_port_cache", return_value={})
    @mock.patch("app.ui.try_get_running_vms", return_value=["client"])
    @mock.patch("app.ui.remove_policy_rule")
    @mock.patch("app.ui.kill_connection_process")
    def test_refresh_cleans_connection_when_server_disappears(
            self, kill_connection_process, remove_policy_rule,
            _try_get_running_vms, _load_port_cache, _thread):
        app = make_app()
        conn = make_conn("client", "server")
        app.connections = [conn]
        app.vms = {"client": VM("client", 0, 0), "server": VM("server", 0, 0)}

        app.refresh_vms()

        self.assertEqual(app.connections, [])
        self.assertEqual(list(app.vms.keys()), ["client"])
        kill_connection_process.assert_called_once_with(conn)
        remove_policy_rule.assert_called_once_with(conn)
        app.render_vms.assert_called_once()
        app.update_status_bar.assert_called_once()

    @mock.patch("app.ui.threading.Thread")
    @mock.patch("app.ui.try_get_running_vms", return_value=None)
    @mock.patch("app.ui.remove_policy_rule")
    @mock.patch("app.ui.kill_connection_process")
    def test_refresh_discovery_failure_keeps_connections(
            self, kill_connection_process, remove_policy_rule,
            _try_get_running_vms, _thread):
        app = make_app()
        conn = make_conn("client", "server")
        app.connections = [conn]

        app.refresh_vms()

        self.assertEqual(app.connections, [conn])
        kill_connection_process.assert_not_called()
        remove_policy_rule.assert_not_called()
        app.render_vms.assert_not_called()
        app.update_status_bar.assert_called_once()

    @mock.patch("app.ui.remove_policy_rule")
    @mock.patch("app.ui.kill_connection_process")
    def test_shutdown_event_uses_subject_name(self, kill_connection_process,
                                              remove_policy_rule):
        app = make_app()
        conn = make_conn("client", "server")
        app.connections = [conn]
        subject = mock.Mock(name="subject")
        subject.name = "server"

        app._on_domain_shutdown(subject, "domain-shutdown")

        self.assertEqual(app.connections, [])
        kill_connection_process.assert_called_once_with(conn)
        remove_policy_rule.assert_called_once_with(conn)

    @mock.patch("app.ui.qubesadmin.Qubes", side_effect=RuntimeError("down"))
    def test_event_watcher_start_failure_is_non_fatal(self, _qubes):
        app = make_app()

        app._run_vm_event_watcher()

        self.assertTrue(self.print_mock.called)


if __name__ == "__main__":
    unittest.main()
