"""
Unit tests for InfoTab: verify that _on_info_ready correctly populates the table widget.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.info_tab import InfoTab

# Ensure QApplication exists
app = QApplication.instance() or QApplication([])

class TestInfoTab(unittest.TestCase):
    def setUp(self):
        # Instantiate InfoTab
        self.tab = InfoTab()
        # Clear any rows
        self.tab.table.setRowCount(0)

    def test_on_info_ready_populates_table(self):
        # Prepare test data
        rows = [('Param1', 'Val1'), ('Param2', 'Val2')]
        # Call handler directly
        self.tab._on_info_ready(rows)
        table = self.tab.table
        # Check row count and items
        self.assertEqual(table.rowCount(), 2)
        self.assertEqual(table.item(0, 0).text(), 'Param1')
        self.assertEqual(table.item(0, 1).text(), 'Val1')
        self.assertEqual(table.item(1, 0).text(), 'Param2')
        self.assertEqual(table.item(1, 1).text(), 'Val2')

if __name__ == '__main__':
    unittest.main()
