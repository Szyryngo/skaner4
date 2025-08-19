"""
Test CapturePlugin: start it, print a few NEW_PACKET events, then stop.
"""
import sys, os
# Ensure project root is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import time
from plugins.capture_plugin import CapturePlugin
from core.events import Event

if __name__ == '__main__':
    print("Starting CapturePlugin test...")
    # Auto-select a network interface for capture
    try:
        from scapy.all import get_if_list
        ifaces = get_if_list()
        iface = ifaces[0] if ifaces else None
    except Exception:
        iface = None
    plugin = CapturePlugin()
    plugin.initialize({'network_interface': iface, 'filter': ''})
    # Allow worker to start and capture packets
    # Duration to listen for packet events (seconds)
    timeout = 60
    start = time.time()
    count = 0
    print(f"Capturing on interface: {iface}")
    while time.time() - start < timeout:
        ev = plugin.generate_event()
        if ev:
            print(f"Event: {ev.type}, data: {ev.data}")
            count += 1
        else:
            # Ask user to generate traffic (e.g., ping) to see events
            time.sleep(0.5)
    print(f"Captured {count} events in {timeout}s.")
