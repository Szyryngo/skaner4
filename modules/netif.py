import psutil
from scapy.all import get_if_list


def list_interfaces():
    """Zwraca listę dostępnych interfejsów sieciowych (nazwa scapy)."""
    try:
        # Use psutil to retrieve human-friendly interface names
        return sorted(psutil.net_if_addrs().keys())
    except Exception:
        # Fallback to raw scapy interface list
        return get_if_list()
