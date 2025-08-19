"""
Unit tests for DevicesTab: verify that _process_device_events adds and removes table rows based on device events.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication, QTableWidgetItem
# Add project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.devices_tab import DevicesTab
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
    def __init__(self, handle_map=None, gen_list=None):
        self.handle_map = handle_map or {}
        self.gen_list = gen_list or []
    def handle_event(self, ev):
        # Return events list or None
        return self.handle_map.get(ev.type)
    def generate_event(self):
        if self.gen_list:
            return self.gen_list.pop(0)
        return None

class TestDevicesTab(unittest.TestCase):
    def setUp(self):
        self.tab = DevicesTab()
        # Disable real capture and devices
        pkt_ev = Event('NEW_PACKET', {'src_ip': '192.168.0.10', 'src_mac': 'AA:BB:CC:DD:EE:FF'})
        self.tab._capture = DummyCapture([pkt_ev])
        dev_ev = Event('DEVICE_DETECTED', {'ip': '192.168.0.10', 'mac': 'AA:BB:CC:DD:EE:FF', 'first_seen': 1234567890})
        self.tab._devices_module = DummyDevicesModule(handle_map={'NEW_PACKET': [dev_ev]}, gen_list=[])
        # Clear table
        self.tab.ctrls['devices'].setRowCount(0)
        # Clear log
        self.tab.ctrls['cmd_log'].clear()

    def test_add_device_row(self):
        # Process events
        self.tab._process_device_events()
        tbl = self.tab.ctrls['devices']
        # One row should be added
        self.assertEqual(tbl.rowCount(), 1)
        self.assertEqual(tbl.item(0,0).text(), '192.168.0.10')
        self.assertEqual(tbl.item(0,1).text(), 'AA:BB:CC:DD:EE:FF')
        # Status should be Active
        self.assertEqual(tbl.item(0,4).text(), 'Active')
        # Log should contain detection
        logs = [self.tab.ctrls['cmd_log'].toPlainText()]
        self.assertIn('Wykryto urządzenie', logs[0])

    def test_remove_device_row(self):
        # First add
        self.tab._process_device_events()
        self.assertEqual(self.tab.ctrls['devices'].rowCount(), 1)
        # Now simulate inactivity
        self.tab._capture = DummyCapture([])
        inact_ev = Event('DEVICE_INACTIVE', {'ip': '192.168.0.10'})
        self.tab._devices_module = DummyDevicesModule(handle_map={}, gen_list=[inact_ev])
        self.tab._process_device_events()
        # Table should be empty now
        self.assertEqual(self.tab.ctrls['devices'].rowCount(), 0)
        # Log should mention inactivity
        logs = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Urządzenie nieaktywne', logs)

if __name__ == '__main__':
    unittest.main()
