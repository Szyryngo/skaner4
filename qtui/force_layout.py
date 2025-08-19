"""
Module force_layout - compute node positions for SOC map using a force-directed (spring) layout via NetworkX.
"""
import networkx as nx
from PyQt5.QtCore import QPointF

class ForceLayout:
    """
    Compute positions for nodes in a graph using a force-directed algorithm.

    Parameters
    ----------
    k : float
        Optimal distance between nodes in the layout (spring constant).
    iterations : int
        Number of iterations to run the layout algorithm.
    """
    def __init__(self, k=0.1, iterations=50):
        self.k = k
        self.iterations = iterations

    def compute_positions(self, nodes, edges, width, height):
        """
        Compute 2D positions for each node within the given view dimensions.

        Parameters
        ----------
        nodes : Iterable
            List of node identifiers (e.g., IP addresses).
        edges : Iterable of tuple
            List of edges as (src, dst) pairs.
        width : float
            Width of the target drawing area.
        height : float
            Height of the target drawing area.

        Returns
        -------
        dict
            Mapping from node identifier to QPointF(x, y) in view coordinates.
        """
        G = nx.Graph()
        G.add_nodes_from(nodes)
        G.add_edges_from(edges)

        # spring_layout returns positions in range [-1,1]
        pos_norm = nx.spring_layout(G, k=self.k, iterations=self.iterations)
        positions = {}
        for node, (nx_pos, ny_pos) in pos_norm.items():
            # normalize to [0,1] then scale to view
            cx = (nx_pos + 1) * (width / 2)
            cy = (ny_pos + 1) * (height / 2)
            positions[node] = QPointF(cx, cy)
        return positions
