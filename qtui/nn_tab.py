from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qtui.nn_layout import NNLayout
from datetime import datetime

class NNTab(QWidget):
    """Zakładka NN: trening i ewaluacja sieci neuronowej"""
    def __init__(self, parent=None):
        super().__init__(parent)
        # Store layout instance to maintain signal connections
        self.layout_obj = NNLayout()
        widget, ctrls = self.layout_obj.build()
        # Set up layout for this tab
        layout = QVBoxLayout()
        layout.addWidget(widget)
        self.setLayout(layout)
        # Remember controls and wiring
        self.ctrls = ctrls
        # Initial log entry
        self.ctrls['cmd_log'].append(
            f"[{datetime.now().strftime('%H:%M:%S')}] NNTab załadowany"
        )
        # Wiring for test AI engine check if available
        if 'check_btn' in self.ctrls:
            self.ctrls['check_btn'].clicked.connect(
                lambda: self.ctrls['cmd_log'].append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] Sprawdzenie AI zakończone"))
