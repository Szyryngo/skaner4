"""Network Interface utilities - list system network interfaces."""
import psutil
from scapy.all import get_if_list


def list_interfaces():
    """Return a sorted list of available network interface names.

    Attempts to use psutil for human-friendly interface names,
    falls back to Scapy's get_if_list() if necessary.

    Returns
    -------
    list of str
        Names of network interfaces detected on the system.
    """
    try:
        # Use psutil to retrieve human-friendly interface names
        return sorted(psutil.net_if_addrs().keys())
    except Exception:
        # Fallback to raw scapy interface list
        return get_if_list()
