"""Pretty Network Interface utilities - generate user-friendly interface listings."""
import sys
from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
try:
    if sys.platform == 'win32':
        from scapy.all import get_windows_if_list
        _USE_WINDOWS_IFACES = True
    else:
        _USE_WINDOWS_IFACES = False
except ImportError:
    _USE_WINDOWS_IFACES = False


def _iface_type_label(iface):
    """Return a human-readable label for interface type based on name.

    Parameters
    ----------
    iface : str
        Technical interface name.

    Returns
    -------
    str
        One of 'Wi-Fi', 'Ethernet', 'Loopback', 'VPN', 'Bluetooth', or 'Inny'.
    """
    name = iface.lower()
    if 'wi-fi' in name or 'wlan' in name or 'wireless' in name:
        return 'Wi-Fi'
    if 'eth' in name or 'ethernet' in name:
        return 'Ethernet'
    if 'loopback' in name or 'lo' in name:
        return 'Loopback'
    if 'vpn' in name or 'tap' in name or 'tun' in name:
        return 'VPN'
    if 'bluetooth' in name:
        return 'Bluetooth'
    return 'Inny'


def get_interfaces_pretty():
    """Return list of tuples (iface_name, pretty_label) for each network interface.

    For Windows, uses get_windows_if_list to include description and IP;
    for other platforms, uses Scapy to fetch address and MAC.

    Returns
    -------
    list of (str, str)
        Tuples of (interface name, pretty description).
    """
    result = []
    if _USE_WINDOWS_IFACES:
        # Windows: show only human-friendly description, type, and IP
        for info in get_windows_if_list():
            name = info.get('name') or ''  # technical name used internally
            desc = info.get('description') or ''  # OS-friendly name
            ip = info.get('addr') or info.get('ip', '-')
            label = _iface_type_label(name)
            # Build readable label: Type and description with IP
            pretty = f'{label}: {desc} ({ip})'
            result.append((name, pretty))
    else:
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
            except Exception:
                ip = '-'
            try:
                mac = get_if_hwaddr(iface)
            except Exception:
                mac = '-'
            label = _iface_type_label(iface)
            pretty = f'{label} ({iface}, {ip}, {mac})'
            result.append((iface, pretty))
    return result
