"""
Unit tests for SOCTab device detection and inactivity handling via DevicesModule.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication
# Add project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.soc_tab import SOCTab
from core.events import Event

# Ensure QApplication exists
app = QApplication.instance() or QApplication([])

class DummyCapture:
    def __init__(self, events):
        self.events = events
    def generate_event(self):
        if self.events:
            return self.events.pop(0)
        return None

class DummyDevicesModule:
    def __init__(self, handle_events, gen_events):
        self.handle_events = handle_events
        self.gen_events = gen_events
    def handle_event(self, ev):
        # return list of events to simulate generator
        return self.handle_events.get(ev.type, [])
    def generate_event(self):
        if self.gen_events:
            return self.gen_events.pop(0)
        return None

class TestSOCTabDevices(unittest.TestCase):
    def setUp(self):
        self.tab = SOCTab()
        # Replace capture and devices modules
        # Prepare a NEW_PACKET event
        pkt_ev = Event('NEW_PACKET', {'src_ip': '1.2.3.4', 'src_mac': 'AA:BB:CC'})
        self.tab._capture = DummyCapture([pkt_ev])
        # DevicesModule should yield DEVICE_DETECTED for that packet
        dev_detect = Event('DEVICE_DETECTED', {'ip': '1.2.3.4', 'mac': 'AA:BB:CC'})
        self.tab._devices = DummyDevicesModule(handle_events={'NEW_PACKET': [dev_detect]}, gen_events=[])
        # Ensure no nodes initially
        self.tab._nodes = {}
    def test_device_detected_added(self):
        # Run poll loop
        self.tab._poll_loop()
        # Node should be added
        self.assertIn('1.2.3.4', self.tab._nodes)
        # Text item shows IP
        _, text_item, _ = self.tab._nodes['1.2.3.4']
        self.assertTrue(text_item.toPlainText().startswith('1.2.3.4'))
    def test_device_inactive_removed(self):
        # First add
        self.tab._poll_loop()
        self.assertIn('1.2.3.4', self.tab._nodes)
        # Now simulate inactivity
        inact_ev = Event('DEVICE_INACTIVE', {'ip': '1.2.3.4'})
        # No new packets, so capture returns None
        self.tab._capture = DummyCapture([])
        # Devices generate_event yields inact
        self.tab._devices = DummyDevicesModule(handle_events={}, gen_events=[inact_ev])
        # Run poll loop
        self.tab._poll_loop()
        # Node should be removed
        self.assertNotIn('1.2.3.4', self.tab._nodes)

if __name__ == '__main__':
    unittest.main()
