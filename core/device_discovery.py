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
    dtype = guess_type_from_nmap(ip)
    if dtype:
        update_yaml(prefix, manufacturer, dtype)
        if callback:
            callback(prefix, dtype)
