

import sys
import yaml
from core.orchestrator import Orchestrator

def run_qt_gui():
	from qtui.qt_dashboard import MainWindow
	from PyQt5.QtWidgets import QApplication
	app = QApplication(sys.argv)
	window = MainWindow()
	window.show()
	sys.exit(app.exec_())

if __name__ == "__main__":
	# Sprawdź config.yaml czy gui: qt, domyślnie uruchom GUI
	try:
		with open('config/config.yaml', 'r', encoding='utf-8') as f:
			cfg = yaml.safe_load(f)
		gui_mode = cfg.get('gui', 'qt')
	except Exception:
		gui_mode = 'qt'

	if gui_mode == 'qt':
		run_qt_gui()
	else:
		orchestrator = Orchestrator()
		orchestrator.run()
