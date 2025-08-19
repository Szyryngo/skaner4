"""
Unit test for SOCTab: verify that _on_device_discovered updates node label.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication
# Insert project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.soc_tab import SOCTab

# Ensure a QApplication exists for widget creation
app = QApplication.instance() or QApplication([])

class TestSOCTab(unittest.TestCase):
    def setUp(self):
        self.tab = SOCTab()
        # Simulate that a device was added with initial label
        ip = '192.0.2.10'
        # Manually insert a fake node: ellipse, text_item, group
        # Use zero-size ellipse and group None, only text_item matters
        # Create a text item with plain IP
        from PyQt5.QtGui import QFont
        text_item = self.tab.scene.addText(ip)
        text_item.setPlainText(ip)
        self.tab._nodes[ip] = (None, text_item, None)

    def test_on_device_discovered_appends_type(self):
        ip = '192.0.2.10'
        prefix = 'AA:BB:CC'
        dev_type = 'TestDevice'
        # Call the callback
        self.tab._on_device_discovered(ip, prefix, dev_type)
        # After discovery, text_item should contain IP and device type on new line
        _, text_item, _ = self.tab._nodes[ip]
        label = text_item.toPlainText()
        lines = label.splitlines()
        self.assertEqual(lines[0], ip)
        self.assertEqual(lines[1], dev_type)

if __name__ == '__main__':
    unittest.main()
