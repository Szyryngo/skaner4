"""
Test SnortRulesPlugin: load rules, simulate a packet matching the ICMP test rule, and verify SNORT_ALERT event.
"""
# Popraw import modułu time
import sys, os, time
# Ensure project root on PYTHONPATH
dir_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if dir_path not in sys.path:
    sys.path.insert(0, dir_path)

from plugins.snort_rules_plugin import SnortRulesPlugin
from core.events import Event

if __name__ == '__main__':
    print("Starting SnortRulesPlugin test...", flush=True)
    config = {'rule_file': 'config/snort.rules'}
    plugin = SnortRulesPlugin()
    plugin.initialize(config)
    # Allow initial load and debug prints
    time.sleep(2)
    # Print loaded SIDs
    try:
        sids = [rule['sid'] for rule in plugin.rules]
        print(f"Loaded Snort rule SIDs: {sids}", flush=True)
    except Exception as e:
        print(f"Error listing rules: {e}")
    # Create a dummy NEW_PACKET event for ICMP echo (type 8)
    packet = {
        'protocol': 1,  # ICMP
        'icmp_type': 8,
        'src_ip': '192.168.0.1',
        'dst_ip': '192.168.0.2',
        'src_port': None,
        'dst_port': None,
        'tcp_flags': '',
        'raw_bytes': b''
    }
    print("Simulating NEW_PACKET for ICMP type 8", flush=True)
    ev = plugin.handle_event(Event('NEW_PACKET', packet))
    if ev:
        print(f"Detected SNORT_ALERT: sid={ev.data.get('sid')}, msg={ev.data.get('msg')}", flush=True)
    else:
        print("No SNORT_ALERT generated.", flush=True)
