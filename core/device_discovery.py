"""Device Discovery utilities - infer device types via nmap and update MAC prefix mapping."""
import os
import yaml
import threading

try:
    import nmap  # python-nmap library  # type: ignore
except ImportError:
    nmap = None

CONFIG_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'mac_devices.yaml'))

# Mapping common service to device types
SERVICE_TYPE_MAP = {
    'http': 'Web Server',
    'ssh': 'Computer/Server',
    'rtsp': 'Network Camera',
    'sip': 'VoIP Phone',
    'mqtt': 'IoT Device',
    'snmp': 'Networking Device',
    'mdns': 'Service Discovery Device',
    'ftp': 'File Server',
}


def guess_type_from_nmap(ip):
    """Perform an Nmap scan on the given IP to infer device type.

    Parameters
    ----------
    ip : str
        IPv4 address to scan.

    Returns
    -------
    str or None
        Guessed device type (e.g., 'Web Server', 'Mobile Device') or None if unknown or nmap unavailable.
    """
    if nmap is None:
        return None
    try:
        scanner = nmap.PortScanner()
        # -Pn: no ping, -sV: service/version, -O: OS detection
        scanner.scan(hosts=ip, arguments='-Pn -sV -O')
        if ip not in scanner.all_hosts():
            return None
        host = scanner[ip]
        # Try OS match
        if 'osmatch' in host and host['osmatch']:
            osname = host['osmatch'][0]['name'].lower()
            if 'windows' in osname:
                return 'Computer'
            if 'linux' in osname:
                return 'Server'
            if 'ios' in osname or 'android' in osname:
                return 'Mobile Device'
        # Try service detection
        if 'tcp' in host:
            for port, svc in host['tcp'].items():
                name = svc.get('name', '').lower()
                for key, dtype in SERVICE_TYPE_MAP.items():
                    if key in name:
                        return dtype
        return None
    except Exception:
        return None


def update_yaml(prefix, manufacturer, dtype):
    """Update the MAC prefix mapping YAML with device type information.

    Parameters
    ----------
    prefix : str
        MAC address prefix (first bytes) as key.
    manufacturer : str
        Name of the device manufacturer.
    dtype : str or None
        Device type inferred, stored under 'type'. If None, existing type is preserved.
    """
    # Load existing mapping
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        data = {}
    # Update entry
    entry = data.get(prefix, {})
    entry['manufacturer'] = entry.get('manufacturer', manufacturer)
    entry['type'] = dtype or entry.get('type', 'Unknown')
    data[prefix] = entry
    # Write back
    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        yaml.safe_dump(data, f, default_flow_style=False, sort_keys=True)


def discover_and_update(ip, mac, prefix, manufacturer, callback=None):
    """Discover device type via Nmap, update YAML mapping, and invoke callback if provided.

    Parameters
    ----------
    ip : str
        IPv4 address of the device.
    mac : str
        MAC address of the device.
    prefix : str
        Manufacturer prefix extracted from MAC.
    manufacturer : str
        Manufacturer name inferred from MAC prefix.
    callback : callable or None
        Optional function to call with (prefix, device_type) on update.
    """
    dtype = guess_type_from_nmap(ip)
    if dtype:
        update_yaml(prefix, manufacturer, dtype)
        if callback:
            callback(prefix, dtype)
