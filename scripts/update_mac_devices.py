#!/usr/bin/env python3
"""
Script to update config/mac_devices.yaml by parsing the IEEE OUI registry.
If online, fetches the latest oui.txt from IEEE. Otherwise, uses local cache at scripts/oui.txt.
"""
import os
import sys

try:
    import requests
except ImportError:
    print("The 'requests' package is required. Please install with 'pip install requests'.")
    sys.exit(1)

import yaml

# Default device type mapping by manufacturer for common devices
DEFAULT_TYPES = {
    "Apple Inc.": "Computer/Mobile Device",
    "Dell Inc.": "Computer",
    "Hewlett-Packard Company": "Printer",
    "Cisco Systems, Inc.": "Networking Device",
    "Samsung Electronics Co., Ltd.": "Mobile Device/Smart TV",
    "Raspberry Pi Foundation": "Single Board Computer",
    "Amazon Technologies Inc.": "Smart Speaker",
    "Xiaomi Communications Co., Ltd.": "Mobile Device/IoT Device",
    # extend with other manufacturer-to-type mappings as needed
}

OUI_URLS = [
    "https://standards-oui.ieee.org/oui/oui.txt",
    "http://standards-oui.ieee.org/oui/oui.txt"
]
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
LOCAL_OUI_FILE = os.path.join(SCRIPT_DIR, "oui.txt")
OUTPUT_FILE = os.path.abspath(os.path.join(SCRIPT_DIR, "..", "config", "mac_devices.yaml"))


def fetch_oui_text():
    # Try multiple URLs (HTTPS then HTTP) before falling back to cache
    for url in OUI_URLS:
        try:
            print(f"Fetching OUI registry from {url}...")
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            text = resp.text
            # Save a local copy for offline use
            with open(LOCAL_OUI_FILE, "w", encoding="utf-8") as f:
                f.write(text)
            return text
        except Exception as e:
            print(f"Failed to fetch from {url}: {e}")
    # All fetch attempts failed, attempt to load local cache
    if os.path.exists(LOCAL_OUI_FILE):
        print(f"Loading OUI registry from local cache: {LOCAL_OUI_FILE}")
        with open(LOCAL_OUI_FILE, encoding="utf-8") as f:
            return f.read()
    print("No local cache found. Exiting.")
    sys.exit(1)


def parse_oui(text):
    mapping = {}
    for line in text.splitlines():
        if "(hex)" in line:
            parts = line.split()
            if len(parts) >= 3:
                raw = parts[0]  # e.g. "00-1A-79"
                vendor = " ".join(parts[2:])
                prefix = raw.replace('-', ':').upper()
                mapping[prefix] = {"manufacturer": vendor, "type": "Unknown"}
    return mapping


def write_yaml(mapping):
    header = (
        "# MAC address OUI lookup for identifying device manufacturer and type in internal LAN\n"
        "# Auto-generated from IEEE OUI registry.\n"
    )
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        yaml.safe_dump(mapping, f, default_flow_style=False, sort_keys=True)
    print(f"Wrote {len(mapping)} entries to {OUTPUT_FILE}")


def main():
    text = fetch_oui_text()
    parsed = parse_oui(text)
    # Load existing mapping to preserve custom 'type' fields
    existing = {}
    try:
        with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
            existing = yaml.safe_load(f) or {}
    except FileNotFoundError:
        existing = {}
    # Merge: use parsed manufacturer, preserve existing type when available
    merged = {}
    for prefix, info in parsed.items():
        # Determine type: preserve existing, else use default mapping, else Unknown
        existing_info = existing.get(prefix, {})
        if 'type' in existing_info and existing_info['type']:
            dtype = existing_info['type']
        else:
            manu = info.get('manufacturer', '')
            dtype = DEFAULT_TYPES.get(manu, info.get('type', 'Unknown'))
        merged[prefix] = {
            'manufacturer': info.get('manufacturer', 'Unknown'),
            'type': dtype
        }
    # Include any custom prefixes not in parsed
    for prefix, info in existing.items():
        if prefix not in merged:
            merged[prefix] = info
    write_yaml(merged)


if __name__ == '__main__':
    main()
