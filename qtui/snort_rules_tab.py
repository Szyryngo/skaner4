import os
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit

class SnortRulesTab(QWidget):
    """Tab displaying the contents of the Snort rules file."""
    def __init__(self, plugins, parent=None):
        super().__init__(parent)
        # Find the SnortRulesPlugin instance
        from plugins.snort_rules_plugin import SnortRulesPlugin
        snort = next((p for p in plugins if isinstance(p, SnortRulesPlugin)), None)
        layout = QVBoxLayout()
        if snort and hasattr(snort, 'rules'):
            # List rules with checkboxes
            from PyQt5.QtWidgets import QScrollArea, QCheckBox, QLabel
            scroll = QScrollArea()
            container = QWidget()
            vlay = QVBoxLayout()
            if not snort.rules:
                vlay.addWidget(QLabel('Brak reguł do wyświetlenia'))
            for rule in snort.rules:
                sid = rule.get('sid')
                msg = rule.get('msg')
                cb = QCheckBox(f"{sid}: {msg}")
                cb.setChecked(sid in getattr(snort, 'enabled_sids', []))
                # Toggle rule enable/disable
                cb.stateChanged.connect(lambda state, sid=sid, plugin=snort: plugin.enable_rule(sid) if state else plugin.disable_rule(sid))
                vlay.addWidget(cb)
            container.setLayout(vlay)
            scroll.setWidget(container)
            scroll.setWidgetResizable(True)
            layout.addWidget(scroll)
        else:
            lbl = QLabel('Plugin SnortRulesPlugin nie został załadowany')
            layout.addWidget(lbl)
        self.setLayout(layout)
