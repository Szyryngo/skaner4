import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget
from .dashboard_tab import DashboardTab
from .devices_tab import DevicesTab
from .scanner_tab import ScannerTab
from .nn_tab import NNTab
from .config_tab import ConfigTab

class MainWindow(QMainWindow):
    """Główne okno aplikacji z zakładkami"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle('AI Network Packet Analyzer Pro')
        tabs = QTabWidget()
        self.setCentralWidget(tabs)
        # Stwórz instancje zakładek dla dalszych połączeń
        dash_tab = DashboardTab()
        dev_tab = DevicesTab()
        scan_tab = ScannerTab()
        nn_tab = NNTab()
        config_tab = ConfigTab()
        # Dodaj zakładki
        tabs.addTab(dash_tab, 'Dashboard')
        tabs.addTab(dev_tab, 'Devices')
        tabs.addTab(scan_tab, 'Scanner')
        tabs.addTab(nn_tab, 'NN')
        tabs.addTab(config_tab, 'Config')
    # Propaguj zmianę silnika AI z Config do Dashboard
        if 'switch_ai_btn' in config_tab.ctrls and 'ai_combo' in config_tab.ctrls:
            config_tab.ctrls['switch_ai_btn'].clicked.connect(
                lambda: (
                    setattr(dash_tab._detection_module, 'use_nn',
                            config_tab.ctrls['ai_combo'].currentText() == 'Neural Net'),
                    dash_tab.log_status(f'Aktualny silnik AI: {config_tab.ctrls['ai_combo'].currentText()}')
                )
            )
        # Ustaw domyślny rozmiar okna na 80% rozdzielczości ekranu
        screen = QApplication.primaryScreen()
        rect = screen.availableGeometry()
        w = int(rect.width() * 0.8)
        h = int(rect.height() * 0.8)
        self.resize(w, h)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
