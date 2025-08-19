import os
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem, QCheckBox, QLabel
from PyQt5.QtGui import QFont

class SnortRulesTab(QWidget):
    """Tab displaying the contents of the Snort rules file."""
    def __init__(self, plugins, parent=None):
        super().__init__(parent)
        # Find the SnortRulesPlugin instance
        from plugins.snort_rules_plugin import SnortRulesPlugin
        snort = next((p for p in plugins if isinstance(p, SnortRulesPlugin)), None)
        layout = QVBoxLayout()
        # Table for rules: ID, Opis, Reguła, Włączone
        if snort and hasattr(snort, 'rules'):
            rules = snort.rules or []
            # Deduplicate rules by SID to avoid duplicates in UI
            unique_rules = []
            seen_sids = set()
            for rule in rules:
                sid = rule.get('sid')
                if sid not in seen_sids:
                    seen_sids.add(sid)
                    unique_rules.append(rule)
            rules = unique_rules
            if not rules:
                layout.addWidget(QLabel('Brak reguł do wyświetlenia'))
            else:
                table = QTableWidget(len(rules), 4)
                table.setHorizontalHeaderLabels(['ID', 'Opis', 'Reguła', 'Włączone'])
                for row, rule in enumerate(rules):
                    sid = rule.get('sid', '')
                    msg = rule.get('msg', '')
                    raw = rule.get('raw', '')
                    # ID
                    table.setItem(row, 0, QTableWidgetItem(str(sid)))
                    # Description
                    table.setItem(row, 1, QTableWidgetItem(msg))
                    # Raw rule text
                    item_raw = QTableWidgetItem(raw)
                    item_raw.setToolTip(raw)
                    table.setItem(row, 2, item_raw)
                    # Enable/disable checkbox
                    cb = QCheckBox()
                    cb.setChecked(sid in getattr(snort, 'enabled_sids', []))
                    cb.stateChanged.connect(lambda state, sid=sid, plugin=snort: plugin.enable_rule(sid) if state else plugin.disable_rule(sid))
                    table.setCellWidget(row, 3, cb)
                table.resizeColumnsToContents()
                table.resizeRowsToContents()
                layout.addWidget(table)
        else:
            layout.addWidget(QLabel('Plugin SnortRulesPlugin nie został załadowany'))
        self.setLayout(layout)
