# ── routing.py ────────────────────────────────────────────────────────────
# Grid-based connection routing. Fixed to position the column 0 left-gutter 
# safely inside visible canvas bounds and pack lines efficiently.

from __future__ import annotations

LANE_SPACING_V = 10     # Visual separation between parallel vertical lines
LANE_SPACING_H = 12     # Margins for parallel horizontal distribution
V_CHANNEL_HALF_WIDTH = 35 


# ── Channel types ───────────────────────────────────────────────────────

class VChannel:
    """Vertical channel at a fixed x-position. Lanes are assigned dynamically."""
    __slots__ = ('x', 'lanes', 'side_preference')

    def __init__(self, x, side_preference="left_to_right"):
        self.x = x
        self.lanes = []  
        self.side_preference = side_preference

    @property
    def occupied(self):
        max_lanes = max(1, (V_CHANNEL_HALF_WIDTH * 2) // LANE_SPACING_V)
        return len(self.lanes) >= max_lanes

    def lane_x(self, conn):
        """X-position of the given connection's lane within this channel."""
        mid = self.x
        if conn not in self.lanes:
            self.lanes.append(conn)

        n = len(self.lanes)
        idx = self.lanes.index(conn)
        left_bound = mid - V_CHANNEL_HALF_WIDTH + 6
        
        if self.side_preference == "left_to_right":
            return left_bound + idx * LANE_SPACING_V
        else:
            right_bound = mid + V_CHANNEL_HALF_WIDTH - 6
            return right_bound - idx * LANE_SPACING_V


class HChannel:
    """Horizontal channel at a fixed y-position. Lanes assigned dynamically."""
    __slots__ = ('y', 'safe_zone', 'lanes')

    def __init__(self, y, safe_zone=None):
        self.y = y
        self.safe_zone = safe_zone   
        self.lanes = []              

    @property
    def occupied(self):
        if self.safe_zone is None:
            return len(self.lanes) >= 24
        span = self.safe_zone[1] - self.safe_zone[0]
        max_lanes = max(1, int(span / LANE_SPACING_H))
        return len(self.lanes) >= max_lanes

    def lane_y(self, conn):
        if conn not in self.lanes:
            self.lanes.append(conn)

        if self.safe_zone is None:
            return self.y

        top = self.safe_zone[0]
        idx = self.lanes.index(conn)
        return top + 8 + idx * LANE_SPACING_H


# ── Routing grid ────────────────────────────────────────────────────────

class RoutingGrid:
    """Channel grid built from VM layout data."""
    __slots__ = ('v_channels', 'h_channels')

    def __init__(self):
        self.v_channels = {}   
        self.h_channels = {}   


def build_grid(n_vms, cols, row_starts, row_max_heights,
               canvas_width, canvas_height, layout):
    """Build the channel grid from VM layout data."""
    grid = RoutingGrid()
    max_row_idx = (n_vms - 1) // cols if n_vms else 0
    MIN_ROW_GAP = 80

    # ── V-channels ──
    # Dynamic Left Gutter: Stays safely on-screen, positioned exactly between 
    # the left edge of column 0 VMs and the window frame boundary.
    col0_x = layout["grid_origin_x"]
    left_gutter_x = col0_x - layout["vm_half_w"] - 45  
    grid.v_channels[-1] = VChannel(left_gutter_x, side_preference="right_to_left")

    for c in range(cols):
        vx = (layout["grid_origin_x"] + c * layout["col_spacing"] + layout["v_chan_offset"])
        grid.v_channels[c] = VChannel(vx, side_preference="left_to_right")

    # ── H-channels ──
    # 1. Inter-row channels
    for r in range(max_row_idx):
        bottom_above = row_starts.get(r, 0) + (row_max_heights.get(r, layout["base_vm_h"]) // 2)
        top_below = row_starts.get(r + 1, 0) - (row_max_heights.get(r + 1, layout["base_vm_h"]) // 2)
        
        if bottom_above < top_below:
            mid_y = (bottom_above + top_below) / 2.0
            grid.h_channels[r] = HChannel(mid_y, (bottom_above + 4, top_below - 4))

    # 2. Below-row fallback channels (index 1000+r)
    for r in range(max_row_idx + 1):
        bottom_r = row_starts.get(r, 0) + (row_max_heights.get(r, layout["base_vm_h"]) // 2)
        idx = 1000 + r
        grid.h_channels[idx] = HChannel(
            y=bottom_r + MIN_ROW_GAP // 2,
            safe_zone=(bottom_r + 4, min(canvas_height - 10, bottom_r + MIN_ROW_GAP - 4)),
        )

    return grid


# ── Routing algorithm ───────────────────────────────────────────────────

class Route:
    """Routing plan for one connection. Stores the sequence of hops."""
    __slots__ = ('v_src_idx', 'v_dst_idx', 'h_chan_idx')

    def __init__(self, v_src_idx, v_dst_idx, h_chan_idx=None):
        self.v_src_idx = v_src_idx
        self.v_dst_idx = v_dst_idx
        self.h_chan_idx = h_chan_idx


def route_connection(grid, client_vm, server_vm, local_port, remote_port,
                     port_side_fn, vm_column_fn, row_for_y_fn):
    """Route one connection through the grid using your exact native signature."""
    src_col = vm_column_fn(client_vm)
    dst_col = vm_column_fn(server_vm)
    src_row = row_for_y_fn(client_vm.y)
    dst_row = row_for_y_fn(server_vm.y)

    src_side = port_side_fn(client_vm, local_port)
    v_src = _nearest_v_channel(src_col, src_side)

    dst_side = port_side_fn(server_vm, remote_port)
    v_dst = _nearest_v_channel(dst_col, dst_side)

    if v_src == v_dst and src_row == dst_row:
        return Route(v_src, v_dst, None)

    h_idx = _find_nearest_free_h_channel(grid, src_row, dst_row)
    return Route(v_src, v_dst, h_idx)


def _nearest_v_channel(col, side):
    """Selects the nearest valid structural vertical lane."""
    if side == "left":
        return col - 1  
    return col


def _find_nearest_free_h_channel(grid, src_row, dst_row):
    """Finds or dynamically generates the correct horizontal lane channel."""
    if src_row == dst_row:
        below_idx = 1000 + src_row
        if below_idx in grid.h_channels and not grid.h_channels[below_idx].occupied:
            return below_idx

        above_idx = src_row - 1
        if above_idx in grid.h_channels and not grid.h_channels[above_idx].occupied:
            return above_idx

        return below_idx if below_idx in grid.h_channels else 1000

    min_row = min(src_row, dst_row)
    max_row = max(src_row, dst_row)

    for r in range(min_row, max_row):
        ch = grid.h_channels.get(r)
        if ch is not None and not ch.occupied:
            return r

    return 1000 + src_row
