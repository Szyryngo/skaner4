"""
Unit tests for NNTab: verify AI check, training, cancellation, and evaluation handlers.
"""
import os
import sys
import unittest
from PyQt5.QtWidgets import QApplication

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.nn_tab import NNTab

# Ensure QApplication exists
app = QApplication.instance() or QApplication([])

class DummyModel:
    """Dummy model to test evaluation path."""
    def predict(self, X):
        import numpy as np
        # return zeros indicating normal
        return np.zeros((len(X),))
    def predict_proba(self, X):
        import numpy as np
        # simulate probability of anomaly as zeros
        probs = np.zeros((len(X), 2))
        return probs

class TestNNTab(unittest.TestCase):
    def setUp(self):
        # Instantiate NNTab
        self.tab = NNTab()
        # Clear initial log and results view
        self.tab.ctrls['cmd_log'].clear()
        self.tab.ctrls['results_view'].clear()
        # Override heavy training
        self.tab.layout_obj._train_model = lambda lr, epochs, batch: None

    def test_ai_check_button(self):
        # Simulate AI engine check
        self.tab.ctrls['check_btn'].click()
        log = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Sprawdzenie AI zakończone', log)

    def test_train_and_cancel(self):
        # Click train button
        self.tab.ctrls['train_btn'].click()
        # After click, train starts and cancel is enabled
        log1 = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Rozpoczynam trening sieci', log1)
        # Click cancel
        self.tab.ctrls['cancel_btn'].click()
        log2 = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Anulowano trening sieci', log2)

    def test_evaluate_without_model(self):
        # Ensure no model set
        self.tab.layout_obj.nn_model = None
        # Click evaluate
        self.tab.ctrls['eval_btn'].click()
        log = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Błąd: brak wytrenowanego modelu', log)

    def test_evaluate_with_model(self):
        # Assign dummy model
        self.tab.layout_obj.nn_model = DummyModel()
        # Click evaluate
        self.tab.ctrls['threshold_input'].setValue(0.5)
        self.tab.ctrls['eval_btn'].click()
        # Check results_view contains evaluation header
        html = self.tab.ctrls['results_view'].toHtml()
        self.assertIn('Wyniki ewaluacji modelu', html)
        log = self.tab.ctrls['cmd_log'].toPlainText()
        self.assertIn('Ewaluacja zakończona', log)

if __name__ == '__main__':
    unittest.main()
