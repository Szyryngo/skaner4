#!/usr/bin/env python3
"""
Script to sort config/mac_devices.yaml by OUI prefix.
"""
import yaml
import os

# Determine path to mac_devices.yaml
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.abspath(os.path.join(SCRIPT_DIR, '..', 'config', 'mac_devices.yaml'))

# Read existing file, preserve header comments
with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
    lines = f.readlines()
# Extract header comments (lines starting with '#' or blank)
header = []
body_lines = []
for line in lines:
    if line.strip().startswith('#') or not line.strip():
        header.append(line)
    else:
        # first non-comment line: rest is YAML body
        body_lines = lines[len(header):]
        break
# Load mapping from body
mapping = yaml.safe_load(''.join(body_lines)) or {}
# Write back header and sorted mapping
with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
    f.writelines(header)
    yaml.safe_dump(mapping, f, default_flow_style=False, sort_keys=True)
print(f"Sorted {len(mapping)} entries in {CONFIG_PATH}")
