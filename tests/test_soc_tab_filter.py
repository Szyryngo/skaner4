"""
Unit tests for SOC tab filtering: verify that _on_filter_alerts hides/unhides rows properly.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication
# Add project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.soc_tab import SOCTab
from PyQt5.QtWidgets import QTableWidgetItem

app = QApplication.instance() or QApplication([])

class TestSOCTabFilter(unittest.TestCase):
    def setUp(self):
        self.tab = SOCTab()
        self.tab._live = True
        # clear log_table and add rows for testing
        tbl = self.tab.ctrls.get('log_table')
        tbl.setRowCount(0)
        # add three rows with varying content
        data = ['error', 'warning', 'info']
        for i, text in enumerate(data):
            tbl.insertRow(i)
            tbl.setItem(i, 0, QTableWidgetItem(f"time{i}"))
            tbl.setItem(i, 1, QTableWidgetItem(text))
            tbl.setItem(i, 2, QTableWidgetItem('Low'))
            tbl.setItem(i, 3, QTableWidgetItem('IP'))
            tbl.setItem(i, 4, QTableWidgetItem('IP'))
            tbl.setItem(i, 5, QTableWidgetItem('0.1'))
            tbl.setRowHidden(i, False)

    def test_filter_hides_nonmatching(self):
        self.tab._on_filter_alerts('warn')
        tbl = self.tab.ctrls['log_table']
        # Only second row matches 'warn'
        self.assertTrue(tbl.isRowHidden(0))
        self.assertFalse(tbl.isRowHidden(1))
        self.assertTrue(tbl.isRowHidden(2))

    def test_filter_empty_shows_all(self):
        self.tab._on_filter_alerts('')
        tbl = self.tab.ctrls['log_table']
        # All rows visible
        for r in range(tbl.rowCount()):
            self.assertFalse(tbl.isRowHidden(r))

if __name__ == '__main__':
    unittest.main()
