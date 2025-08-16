from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QGroupBox, QHBoxLayout,
    QComboBox, QPushButton, QLineEdit, QApplication
)
from qtui.cmd_log_widget import create_cmd_log
from datetime import datetime


class ConfigLayout:
    """
    Configuration tab layout: window size presets, AI engine selection, and command log.
    """

    def build(self):
        widget = QWidget()
        layout = QVBoxLayout()

        # Title
        title = QLabel('Konfiguracja okna GUI')
        title.setStyleSheet('font-size: 14px; font-weight: bold; margin-bottom: 10px;')
        layout.addWidget(title)

        # Group: Rozdzielczość okna jako dropdown
        size_group = QGroupBox('Rozdzielczość okna')
        size_layout = QHBoxLayout()
        screen = QApplication.primaryScreen()
        geom = screen.availableGeometry()
        default_res = f"{geom.width()}x{geom.height()}"
        res_combo = QComboBox()
        popular_res = [
            default_res,
            '800x600', '1024x768', '1280x720', '1280x800', '1366x768',
            '1440x900', '1600x900', '1680x1050', '1920x1080',
            '2560x1440', '3840x2160'
        ]
        res_combo.addItems(popular_res)
        res_combo.setToolTip('Wybierz rozdzielczość okna')
        size_layout.addWidget(QLabel('Rozdzielczość:'))
        size_layout.addWidget(res_combo)
        apply_btn = QPushButton('Zastosuj rozdzielczość')
        size_layout.addWidget(apply_btn)
        size_group.setLayout(size_layout)
        layout.addWidget(size_group)

        # Group: Wybór silnika AI
        ai_group = QGroupBox('Wybór silnika AI')
        ai_layout = QHBoxLayout()
        ai_combo = QComboBox()
        ai_combo.addItems(['Isolation Forest', 'Neural Net'])
        switch_btn = QPushButton('Zmień silnik AI')
        check_btn = QPushButton('Sprawdź silnik AI')
        ai_layout.addWidget(ai_combo)
        ai_layout.addWidget(switch_btn)
        ai_layout.addWidget(check_btn)
        ai_group.setLayout(ai_layout)
        layout.addWidget(ai_group)

        # Current AI engine label
        current_label = QLabel(f'Aktualnie używany: {ai_combo.currentText()}')
        layout.addWidget(current_label)
        ai_combo.currentIndexChanged.connect(
            lambda idx, combo=ai_combo, lbl=current_label: lbl.setText(f'Aktualnie używany: {combo.itemText(idx)}')
        )

        layout.addStretch()

        # Command log
        cmd_log = create_cmd_log()
        layout.addWidget(cmd_log)

        widget.setLayout(layout)
        return widget, {
            'res_combo': res_combo,
            'apply_btn': apply_btn,
            'ai_combo': ai_combo,
            'switch_ai_btn': switch_btn,
            'check_ai_btn': check_btn,
            'current_label': current_label,
            'cmd_log': cmd_log
        }
