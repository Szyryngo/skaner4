"""Module config_tab - description."""
from PyQt5.QtWidgets import QWidget, QVBoxLayout
from qtui.config_layout import ConfigLayout
from datetime import datetime

class ConfigTab(QWidget):
    """Zakładka Config: ustawienia okna i AI"""
    def __init__(self, parent=None):
        '''Function __init__ - description.'''
        super().__init__(parent)
        # Zbuduj i osadź layout
        widget, ctrls = ConfigLayout().build()
        layout = QVBoxLayout()
        layout.addWidget(widget)
        self.setLayout(layout)
        # Zapamiętaj kontrolki na przyszłość
        self.ctrls = ctrls
        # Wire AI engine test button
        if 'check_ai_btn' in self.ctrls:
            self.ctrls['check_ai_btn'].clicked.connect(
                lambda: self.ctrls['cmd_log'].append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] Sprawdzenie silnika AI zakończone"))
    # Wire switch AI engine button log
        if 'switch_ai_btn' in self.ctrls:
            self.ctrls['switch_ai_btn'].clicked.connect(
                lambda: self.ctrls['cmd_log'].append(
                    f"[{datetime.now().strftime('%H:%M:%S')}] Zmieniono silnik AI na {self.ctrls['ai_combo'].currentText()}"))
        # Wire apply size button to resize window
        if 'apply_btn' in self.ctrls:
            self.ctrls['apply_btn'].clicked.connect(self._on_apply_size)
        # Initial log entry
        if 'cmd_log' in self.ctrls:
            self.ctrls['cmd_log'].append(
                f"[{datetime.now().strftime('%H:%M:%S')}] ConfigTab załadowany"
            )

    def _on_apply_size(self):
        """Apply GUI window size from spinboxes."""
        # Parse resolution from single input field
        res_combo = self.ctrls.get('res_combo', None)
        if res_combo:
            text = res_combo.currentText()
            try:
                w_str, h_str = text.lower().split('x')
                w, h = int(w_str), int(h_str)
            except Exception as e:
                self.ctrls['cmd_log'].append(f"Błędny format rozdzielczości: {text}")
                return
        else:
            return
        # Resize main window
        try:
            self.window().resize(w, h)
            ts = datetime.now().strftime('%H:%M:%S')
            self.ctrls['cmd_log'].append(
                f"[{ts}] Rozdzielczość ustawiona na: {w}x{h}"
            )
        except Exception as e:
            self.ctrls['cmd_log'].append(f"Błąd przy zmianie rozdzielczości: {e}")
