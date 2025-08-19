"""
Unit tests for SOCTab SCAN_COMPLETED handling: verify scan_table and _add_device integration.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication
# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.soc_tab import SOCTab
from core.events import Event

# Ensure QApplication exists
app = QApplication.instance() or QApplication([])

class TestSOCTabScan(unittest.TestCase):
    def setUp(self):
        self.tab = SOCTab()
        # Ensure scan_table exists and is empty
        tbl = self.tab.ctrls.get('scan_table')
        self.assertIsNotNone(tbl)
        tbl.setRowCount(0)
        # Clear nodes
        self.tab._nodes = {}

    def test_scan_completed_populates_table_and_nodes(self):
        fake_result = [{'ip': '10.0.0.5', 'mac': 'AA:BB:CC:DD:EE:FF', 'ports': [22, 80]}]
        fake_event = Event('SCAN_COMPLETED', {'result': fake_result})
        # Monkeypatch scanner.generate_event
        self.tab._scanner.generate_event = lambda: fake_event
        # Run poll loop
        self.tab._poll_loop()
        # Check scan_table row inserted
        tbl = self.tab.ctrls.get('scan_table')
        self.assertEqual(tbl.rowCount(), 1)
        self.assertEqual(tbl.item(0, 0).text(), '10.0.0.5')
        self.assertEqual(tbl.item(0, 1).text(), 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(tbl.item(0, 2).text(), '22,80')
        # Check node added
        self.assertIn('10.0.0.5', self.tab._nodes)
        # Text item label contains IP
        _, text_item, _ = self.tab._nodes['10.0.0.5']
        self.assertTrue(text_item.toPlainText().startswith('10.0.0.5'))

if __name__ == '__main__':
    unittest.main()
