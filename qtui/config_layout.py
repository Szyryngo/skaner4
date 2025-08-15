from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QGroupBox, QFormLayout, QComboBox, QLineEdit, QHBoxLayout, QPushButton


class ConfigLayout:
    """
Attributes
----------

Methods
-------

"""
    PRESETS = [('800 x 600', 800, 600), ('1024 x 768', 1024, 768), (
        '1280 x 800', 1280, 800), ('1366 x 768', 1366, 768), ('1600 x 900',
        1600, 900), ('1920 x 1080', 1920, 1080), ('2560 x 1440', 2560, 1440
        ), ('3840 x 2160', 3840, 2160)]

    def build(self):
        widget = QWidget()
        layout = QVBoxLayout()
        title = QLabel('Konfiguracja okna GUI')
        title.setStyleSheet(
            'font-size: 16px; font-weight: bold; margin-bottom: 10px;')
        layout.addWidget(title)
        group = QGroupBox('Rozmiar okna')
        form = QFormLayout()
        preset_combo = QComboBox()
        for label, w, h in self.PRESETS:
            preset_combo.addItem(label, (w, h))
        width_input = QLineEdit()
        height_input = QLineEdit()
        width_input.setMaximumWidth(80)
        height_input.setMaximumWidth(80)
        wh_box = QHBoxLayout()
        wh_box.addWidget(QLabel('Szerokość:'))
        wh_box.addWidget(width_input)
        wh_box.addWidget(QLabel('Wysokość:'))
        wh_box.addWidget(height_input)
        wh_box.addStretch()
        form.addRow('Wybierz rozmiar:', preset_combo)
        form.addRow('Ręcznie:', wh_box)

        def on_preset(idx):
            dims = preset_combo.itemData(idx)
            if isinstance(dims, tuple) and len(dims) == 2:
                width_input.setText(str(dims[0]))
                height_input.setText(str(dims[1]))
        preset_combo.currentIndexChanged.connect(on_preset)
        on_preset(preset_combo.currentIndex())
        apply_btn = QPushButton('Zastosuj rozmiar okna')
        form.addRow(apply_btn)
        group.setLayout(form)
        layout.addWidget(group)
        layout.addStretch()
        widget.setLayout(layout)
        return widget, {'preset_combo': preset_combo, 'width_input':
            width_input, 'height_input': height_input, 'apply_btn': apply_btn}
