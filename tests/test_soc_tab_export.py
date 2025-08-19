"""
Unit tests for SOCTab _export_siem: test CSV and JSON export of log_table.
"""
import os
import sys
import unittest
import tempfile
from PyQt5.QtWidgets import QApplication, QFileDialog
# Add project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from qtui.soc_tab import SOCTab
from PyQt5.QtWidgets import QTableWidgetItem
from core.events import Event

app = QApplication.instance() or QApplication([])

class TestSOCTabExport(unittest.TestCase):
    def setUp(self):
        self.tab = SOCTab()
        # prepare log_table with sample data
        tbl = self.tab.ctrls.get('log_table')
        tbl.setRowCount(0)
        # add 2 rows
        rows = [
            {'Timestamp':'09:00:00','Src IP':'1.1.1.1','Dst IP':'2.2.2.2','Event':'NEW_THREAT','Source':'ai','Severity':'Low','Details':'{}'},
            {'Timestamp':'09:01:00','Src IP':'3.3.3.3','Dst IP':'4.4.4.4','Event':'NEW_THREAT','Source':'snort','Severity':'High','Details':'{}'}
        ]
        for i, row in enumerate(rows):
            tbl.insertRow(i)
            for j, header in enumerate([tbl.horizontalHeaderItem(k).text() for k in range(tbl.columnCount())]):
                tbl.setItem(i, j, QTableWidgetItem(row[header]))
        # clear cmd_log
        self.tab.ctrls['cmd_log'].clear()
    
    def test_export_csv(self):
        # create temp file
        fd, path = tempfile.mkstemp(suffix='.csv')
        os.close(fd)
        # patch QFileDialog
        QFileDialog.getSaveFileName = staticmethod(lambda *args, **kwargs: (path, 'CSV (*.csv)'))
        # call export
        self.tab._export_siem()
        # verify file exists
        self.assertTrue(os.path.exists(path))
        # read CSV and check header and first row
        import csv
        with open(path, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            rows = list(reader)
        # header row length
        self.assertGreater(len(rows), 2)
        self.assertEqual(rows[0][0], 'Timestamp')
        self.assertEqual(rows[1][0], '09:00:00')
        # cleanup
        os.remove(path)

    def test_export_json(self):
        # create temp file
        fd, path = tempfile.mkstemp(suffix='.json')
        os.close(fd)
        QFileDialog.getSaveFileName = staticmethod(lambda *args, **kwargs: (path, 'JSON (*.json)'))
        self.tab._export_siem()
        self.assertTrue(os.path.exists(path))
        import json
        with open(path, encoding='utf-8') as f:
            data = json.load(f)
        self.assertIsInstance(data, list)
        self.assertEqual(data[0]['Timestamp'], '09:00:00')
        os.remove(path)

if __name__ == '__main__':
    unittest.main()
