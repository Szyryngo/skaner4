"""
Unit tests for ConfigTab: verify AI engine buttons and window size application.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.config_tab import ConfigTab

# Ensure QApplication exists
app = QApplication.instance() or QApplication([])

class TestConfigTab(unittest.TestCase):
    def setUp(self):
        self.tab = ConfigTab()
        # Clear initial log
        self.tab.ctrls['cmd_log'].clear()

    def test_ai_check_button(self):
        # Click the check AI button
        self.tab.ctrls['check_ai_btn'].click()
        log = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Sprawdzenie silnika AI zakończone', log)

    def test_ai_switch_button(self):
        # Select second AI engine
        combo = self.tab.ctrls['ai_combo']
        idx = combo.findText('Neural Net')
        combo.setCurrentIndex(idx)
        # Click switch button
        self.tab.ctrls['switch_ai_btn'].click()
        log = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Zmieniono silnik AI na Neural Net', log)
        # Verify label update
        lbl = self.tab.ctrls.get('current_label')
        self.assertIsNotNone(lbl)
        self.assertEqual(lbl.text(), 'Aktualnie używany: Neural Net')

    def test_apply_size(self):
        combo = self.tab.ctrls['res_combo']
        # Choose a known resolution
        idx = combo.findText('800x600')
        combo.setCurrentIndex(idx)
        # Click apply
        self.tab.ctrls['apply_btn'].click()
        # Check log
        log = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Rozdzielczość ustawiona na: 800x600', log)

if __name__ == '__main__':
    unittest.main()
