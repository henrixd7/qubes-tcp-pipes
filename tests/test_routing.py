import unittest

from app.models import Connection, VM
from app.routing import build_grid, route_connection
from app.utils import LAYOUT


def vm_column(vm):
    return int((vm.x - LAYOUT["grid_origin_x"]) // LAYOUT["col_spacing"])


def row_for_y(y):
    return 1 if y >= 300 else 0


def port_side(_vm, port):
    return "left" if str(port) == "22" else "right"


class RoutingTests(unittest.TestCase):
    def make_grid(self):
        return build_grid(
            n_vms=4,
            cols=2,
            row_starts={0: 100, 1: 300},
            row_max_heights={0: LAYOUT["base_vm_h"], 1: LAYOUT["base_vm_h"]},
            canvas_width=1200,
            canvas_height=800,
            layout=LAYOUT,
        )

    def test_supported_ui_signature_routes_vm_objects(self):
        grid = self.make_grid()
        client_vm = VM("client", LAYOUT["grid_origin_x"], 100)
        server_vm = VM("server", LAYOUT["grid_origin_x"] + LAYOUT["col_spacing"], 300)

        route = route_connection(
            grid, client_vm, server_vm,
            "1234", "443",
            port_side, vm_column, row_for_y,
        )

        self.assertEqual(route.v_src_idx, 0)
        self.assertEqual(route.v_dst_idx, 1)
        self.assertEqual(route.h_chan_idx, 0)

    def test_conn_id_preserves_lane_registration_for_drawing(self):
        grid = self.make_grid()
        conn = Connection("client", "1234", "server", "443")
        client_vm = VM("client", LAYOUT["grid_origin_x"], 100)
        server_vm = VM("server", LAYOUT["grid_origin_x"] + LAYOUT["col_spacing"], 300)

        route = route_connection(
            grid, client_vm, server_vm,
            conn.local_port, conn.remote_port,
            port_side, vm_column, row_for_y,
            conn_id=conn,
        )

        self.assertIn(id(conn), grid.v_channels[route.v_src_idx].lanes)
        self.assertIn(id(conn), grid.v_channels[route.v_dst_idx].lanes)
        self.assertIn(id(conn), grid.h_channels[route.h_chan_idx].lanes)


if __name__ == "__main__":
    unittest.main()
