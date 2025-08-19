"""
Unit tests for ScannerTab: verify that port scan and discovery finished handlers populate the results table and log correctly.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication
# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.scanner_tab import ScannerTab

# Ensure QApplication exists
app = QApplication.instance() or QApplication([])

class TestScannerTab(unittest.TestCase):
    def setUp(self):
        # Instantiate ScannerTab
        self.tab = ScannerTab()
        # Clear results table and log
        self.tab.ctrls['results_table'].setRowCount(0)
        self.tab.ctrls['cmd_log'].clear()
        # Set predictable IP and manufacturer mapping
        self.tab.ctrls['target_input'].setText('192.168.1.100')
        # Override mac_map for consistent manufacturer lookup
        self.tab._mac_map = {'AA:BB:CC': {'manufacturer': 'TestCorp'}}

    def test_port_scan_finished(self):
        # Simulate port scan finished event
        open_ports = [22, 80]
        mac = 'AA:BB:CC:DD:EE:FF'
        self.tab._on_port_scan_finished(open_ports, mac)
        tbl = self.tab.ctrls['results_table']
        # Verify one row added
        self.assertEqual(tbl.rowCount(), 1)
        # Check IP, ports, MAC, manufacturer
        self.assertEqual(tbl.item(0, 0).text(), '192.168.1.100')
        self.assertEqual(tbl.item(0, 1).text(), '22,80')
        self.assertEqual(tbl.item(0, 2).text(), mac)
        self.assertEqual(tbl.item(0, 3).text(), 'TestCorp')
        # Check log contains expected message
        log_text = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Port scan finished for 192.168.1.100: ports=22,80, mac=AA:BB:CC:DD:EE:FF', log_text)

    def test_discovery_finished(self):
        # Simulate discovery finished event
        hosts = [{'ip': '10.0.0.1', 'mac': '11:22:33:44:55:66'}]
        # Override mapping for discovery
        self.tab._mac_map = {'11:22:33': {'manufacturer': 'OtherCorp'}}
        self.tab._on_discovery_finished(hosts)
        tbl = self.tab.ctrls['results_table']
        # Verify one row added
        self.assertEqual(tbl.rowCount(), 1)
        # Check IP column
        self.assertEqual(tbl.item(0, 0).text(), '10.0.0.1')
        # Ports column should be empty
        self.assertEqual(tbl.item(0, 1).text(), '')
        # Check MAC and manufacturer
        self.assertEqual(tbl.item(0, 2).text(), '11:22:33:44:55:66')
        self.assertEqual(tbl.item(0, 3).text(), 'OtherCorp')
        # Check log contains expected message
        log_text = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Discovery finished: 10.0.0.1 11:22:33:44:55:66', log_text)

    def test_export(self):
        # Simulate and record the SIEM export event
        # Prepare a row in the table
        self.tab._on_port_scan_finished([22], 'AA:BB:CC:DD:EE:FF')
        # Override scanner_module to capture events
        events = []
        class DummyMod:
            def handle_event(self, ev):
                events.append(ev)
        self.tab._scanner_module = DummyMod()
        # Call export handler
        self.tab._on_export()
        # Check one event was emitted
        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev.type, 'SIEM_EXPORT')
        results = ev.data.get('results')
        self.assertIsInstance(results, list)
        self.assertEqual(results[0]['ip'], '192.168.1.100')

    def test_save(self):
        # Simulate a table row and test saving to CSV
        self.tab._on_port_scan_finished([80], 'AA:BB:CC:DD:EE:FF')
        self.tab.ctrls['cmd_log'].clear()
        # Perform save
        self.tab._on_save()
        # Check log entry
        log_text = self.tab.ctrls['cmd_log'].toPlainText()
        import re
        self.assertRegex(log_text, r'Zapisano wyniki do scan_results_\d{8}_\d{6}\.csv')
        # Verify file creation
        import glob, os
        files = glob.glob('scan_results_*.csv')
        self.assertTrue(files)
        # Cleanup created file(s)
        for f in files:
            os.remove(f)

if __name__ == '__main__':
    unittest.main()
