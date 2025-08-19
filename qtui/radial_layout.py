"""
Module radial_layout - compute node positions for SOC map using static radial layout.
"""
import math
from PyQt5.QtCore import QPointF

class RadialLayout:
    """
    Compute positions for nodes in concentric rings around a center point.

    Each ring n has capacity 8 * 2^(n-1) and fixed spacing.
    """
    def __init__(self, ring_spacing=80, node_radius=10):
        self.ring_spacing = ring_spacing
        self.node_radius = node_radius

    def compute_positions(self, nodes, width, height):
        """
        Compute 2D positions for each node within the given view dimensions.

        Parameters
        ----------
        nodes : list
            List of node identifiers.
        width : float
            Width of drawing area.
        height : float
            Height of drawing area.

        Returns
        -------
        dict
            Mapping node -> QPointF(x, y) representing center of node.
        """
        positions = {}
        center_x, center_y = width / 2.0, height / 2.0
        for idx, node in enumerate(nodes):
            # determine ring and slot
            ring = 1
            capacity = 8 * (2 ** (ring - 1))
            pos = idx
            while pos >= capacity:
                pos -= capacity
                ring += 1
                capacity = 8 * (2 ** (ring - 1))
            if idx == 0:
                # first node at center
                cx, cy = center_x, center_y
            else:
                angle = 2 * math.pi * pos / capacity
                radius = ring * self.ring_spacing
                cx = center_x + radius * math.cos(angle)
                cy = center_y + radius * math.sin(angle)
            positions[node] = QPointF(cx, cy)
        return positions
