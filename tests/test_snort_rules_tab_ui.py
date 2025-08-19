"""
Unit tests for SnortRulesTab: verify that rules table is populated and enabling/disabling via checkbox calls plugin methods.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication, QTableWidget, QCheckBox
# Ensure project root is in path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.snort_rules_tab import SnortRulesTab

# Dummy plugin mimicking SnortRulesPlugin interface
class DummySnortPlugin:
    def __init__(self):
        # Define a couple of rules
        self.rules = [
            {'sid': '100', 'msg': 'Test rule', 'raw': 'alert ip any any -> any any (sid:100;)'},
            {'sid': '200', 'msg': 'Another rule', 'raw': 'alert ip any any -> any any (sid:200;)'}
        ]
        # initially only first rule enabled
        self.enabled_sids = ['100']
        self.enable_calls = []
        self.disable_calls = []
    def enable_rule(self, sid):
        self.enable_calls.append(sid)
    def disable_rule(self, sid):
        self.disable_calls.append(sid)

# Ensure QApplication exists
app = QApplication.instance() or QApplication([])

class TestSnortRulesTabUI(unittest.TestCase):
    def setUp(self):
        self.plugin = DummySnortPlugin()
        # Initialize tab with dummy plugin
        self.tab = SnortRulesTab(plugins=[self.plugin])

    def test_table_creation(self):
        # Find table widget
        table = self.tab.findChild(QTableWidget)
        self.assertIsNotNone(table)
        # Should have two rows, four columns
        self.assertEqual(table.rowCount(), 2)
        self.assertEqual(table.columnCount(), 4)
        # Check first row content
        item = table.item(0, 0)
        self.assertEqual(item.text(), '100')
        item_desc = table.item(0, 1)
        self.assertEqual(item_desc.text(), 'Test rule')
        # Checkbox widget on first row should be checked
        cb = table.cellWidget(0, 3)
        self.assertIsInstance(cb, QCheckBox)
        self.assertTrue(cb.isChecked())

    def test_checkbox_toggle(self):
        table = self.tab.findChild(QTableWidget)
        # Toggle second rule checkbox (initially unchecked)
        cb2 = table.cellWidget(1, 3)
        self.assertFalse(cb2.isChecked())
        # Check it
        cb2.setChecked(True)
        # Should have called enable_rule for sid '200'
        self.assertIn('200', self.plugin.enable_calls)
        # Uncheck first rule
        cb1 = table.cellWidget(0, 3)
        cb1.setChecked(False)
        self.assertIn('100', self.plugin.disable_calls)

if __name__ == '__main__':
    unittest.main()
