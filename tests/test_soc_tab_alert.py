"""
Unit tests for SOCTab._add_alert: verify log table, summary labels, and group table update.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication
# Add project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.soc_tab import SOCTab
from core.events import Event

# Ensure QApplication for widget tests
app = QApplication.instance() or QApplication([])

class TestSOCTabAlert(unittest.TestCase):
    def setUp(self):
        # Create a new SOC tab and enable live mode
        self.tab = SOCTab()
        self.tab._live = True
        self.tab._scheduled = False
        # Clear any existing logs/groups
        self.tab._group_counts = {}
        # Ensure no blacklist
        self.tab._blacklist = []
    
    def test_add_single_alert(self):
        # Create a NEW_THREAT event with low severity (confidence 0.2)
        data = {'timestamp': '12:34:56', 'src_ip': '1.2.3.4', 'dst_ip': '4.3.2.1', 'confidence': 0.2, 'ai_weight': 0.2}
        ev = Event('NEW_THREAT', data)
        # Call add_alert
        self.tab._add_alert(ev)
        # Check log_table
        tbl = self.tab.ctrls.get('log_table')
        self.assertIsNotNone(tbl)
        self.assertEqual(tbl.rowCount(), 1)
        # Columns: Timestamp, Event, Severity, Src, Dst, Confidence
        self.assertEqual(tbl.item(0, 0).text(), '12:34:56')
        self.assertEqual(tbl.item(0, 1).text(), 'NEW_THREAT')
        self.assertEqual(tbl.item(0, 2).text(), 'Low')
        self.assertEqual(tbl.item(0, 3).text(), '1.2.3.4')
        self.assertEqual(tbl.item(0, 4).text(), '4.3.2.1')
        self.assertEqual(tbl.item(0, 5).text(), '0.20')
        # Check summary labels
        self.assertEqual(self.tab.ctrls['low_label'].text(), 'Low: 1')
        self.assertEqual(self.tab.ctrls['medium_label'].text(), 'Medium: 0')
        self.assertEqual(self.tab.ctrls['high_label'].text(), 'High: 0')
        # Check group_table updated
        grp = self.tab.ctrls.get('group_table')
        self.assertIsNotNone(grp)
        self.assertEqual(grp.rowCount(), 1)
        self.assertEqual(grp.item(0, 0).text(), '1.2.3.4')
        self.assertEqual(grp.item(0, 1).text(), '1')

    def test_add_multiple_alerts_increments_group_count(self):
        # Send two alerts from same src
        for ts in ['10:00', '10:01']:
            data = {'timestamp': ts, 'src_ip': '5.6.7.8', 'dst_ip': '9.9.9.9', 'confidence': 1.0, 'ai_weight': 1.0}
            ev = Event('NEW_THREAT', data)
            self.tab._add_alert(ev)
        # Now group count for 5.6.7.8 should be 2
        grp = self.tab.ctrls.get('group_table')
        self.assertEqual(grp.rowCount(), 1)
        self.assertEqual(grp.item(0, 0).text(), '5.6.7.8')
        self.assertEqual(grp.item(0, 1).text(), '2')
        # Summary: Medium? weight=1.0 -> Medium
        self.assertEqual(self.tab.ctrls['low_label'].text(), 'Low: 0')
        self.assertEqual(self.tab.ctrls['medium_label'].text(), 'Medium: 2')
        self.assertEqual(self.tab.ctrls['high_label'].text(), 'High: 0')

if __name__ == '__main__':
    unittest.main()
