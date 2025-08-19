"""MainWindow module - define the primary Qt window with tabs and system metrics toolbar."""
import sys
VERSION = '1.7.0-alpha'
import psutil
from PyQt5.QtWidgets import QApplication, QMainWindow, QTabWidget, QToolBar, QLabel, QWidget, QSizePolicy
from PyQt5.QtCore import QTimer, Qt
from .qt_dashboard import DashboardTab
from .devices_tab import DevicesTab
from .scanner_tab import ScannerTab
from .nn_tab import NNTab
from .config_tab import ConfigTab
from .soc_tab import SOCTab
from .snort_rules_tab import SnortRulesTab
from .info_tab import InfoTab

class MainWindow(QMainWindow):
    """Primary application window containing all feature tabs and system metrics toolbar."""
    def __init__(self):
        """Initialize main window: set up tabs, metrics toolbar, and signal connections.

        Creates QTabWidget with Dashboard, Devices, Scanner, SOC, NN, Config, Snort Rules, and Info tabs.
        Configures a toolbar to display CPU, per-core, RAM, threads, and cores metrics updated every second.
        Ensures SOC background threads are cleaned up on application exit.
        """
        super().__init__()
        # Set fixed application version
        self.setWindowTitle(f'AI Network Packet Analyzer Pro v{VERSION}')
        tabs = QTabWidget()
        self.setCentralWidget(tabs)
        # Stwórz instancje zakładek dla dalszych połączeń
        # Stwórz instancje zakładek dla dalszych połączeń
        dash_tab = DashboardTab()
        dev_tab = DevicesTab(auto_timer=True)
        scan_tab = ScannerTab()
        soc_tab = SOCTab()
        nn_tab = NNTab()
        config_tab = ConfigTab()
        snort_rules_tab = SnortRulesTab(
            soc_tab._snort_plugins  # pass plugin instances
        )
        # Keep reference for proper thread shutdown
        self._soc_tab = soc_tab
        info_tab = InfoTab(auto_thread=True)
        # Dodaj zakładki do widżetu kart
        tabs.addTab(dash_tab, 'Dashboard')
        tabs.addTab(dev_tab, 'Devices')
        tabs.addTab(scan_tab, 'Scanner')
        tabs.addTab(soc_tab, 'SOC')
        tabs.addTab(nn_tab, 'NN')
        tabs.addTab(config_tab, 'Config')
        tabs.addTab(snort_rules_tab, 'Reguły SNORT')
        tabs.addTab(info_tab, 'Info')
        # Przechowaj referencję do DashboardTab
        self.dash_tab = dash_tab
        # Propaguj zmianę silnika AI z Config do Dashboard
        if 'switch_ai_btn' in config_tab.ctrls and 'ai_combo' in config_tab.ctrls:
            config_tab.ctrls['switch_ai_btn'].clicked.connect(
                lambda: (
                    setattr(dash_tab._detection_module, 'use_nn',
                            config_tab.ctrls['ai_combo'].currentText() == 'Neural Net'),
                    dash_tab.log_status(
                        f"Aktualny silnik AI: {config_tab.ctrls['ai_combo'].currentText()}"
                    )
                )
            )
        # Ustaw domyślny rozmiar okna na 80% rozdzielczości ekranu
        screen = QApplication.primaryScreen()
        rect = screen.availableGeometry()
        w = int(rect.width() * 0.8)
        h = int(rect.height() * 0.8)
        self.resize(w, h)
        # Toolbar for system metrics
        self._toolbar = QToolBar()
        self._toolbar.setMovable(False)
        self.addToolBar(Qt.TopToolBarArea, self._toolbar)
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self._toolbar.addWidget(spacer)
        # Overall CPU percentage
        self._cpu_label = QLabel()
        self._cpu_label.setMargin(5)
        self._toolbar.addWidget(self._cpu_label)
        # Per-core usage percentages
        self._percore_labels = []
        core_count = psutil.cpu_count(logical=True) or 0
        if core_count > 1:
            for i in range(core_count):
                lbl = QLabel(f"C{i}: 0%")
                lbl.setMargin(5)
                self._toolbar.addWidget(lbl)
                self._percore_labels.append(lbl)
        # RAM, threads, cores
        self._ram_label = QLabel()
        self._threads_label = QLabel()
        self._cores_label = QLabel()
        for lbl in (self._ram_label, self._threads_label, self._cores_label):
            lbl.setMargin(5)
            self._toolbar.addWidget(lbl)
        # Timer to update metrics every second
        timer = QTimer(self)
        timer.timeout.connect(self._update_metrics)
        timer.start(1000)
        self._update_metrics()
        # Ensure SOC thread stops when application quits
        from PyQt5.QtWidgets import qApp
        qApp.aboutToQuit.connect(self._cleanup)

    def _update_metrics(self):
        """Refresh system performance metrics in the toolbar.

        Updates overall CPU, per-core usage, RAM percentage, and thread/core counts every second.
        """
        # CPU usage
        cpu = psutil.cpu_percent()
        self._cpu_label.setText(f"CPU: {cpu}%")
        # Per-core usage
        percore = psutil.cpu_percent(percpu=True)
        for i, pct in enumerate(percore):
            if i < len(self._percore_labels):
                self._percore_labels[i].setText(f"C{i}: {pct}%")
        # RAM usage
        vm = psutil.virtual_memory()
        self._ram_label.setText(f"RAM: {vm.percent}%")
        # Threads and cores
        threads = psutil.cpu_count(logical=True)
        cores = psutil.cpu_count(logical=False)
        self._threads_label.setText(f"Wątki: {threads}")
        self._cores_label.setText(f"Rdzenie: {cores}")
    def _cleanup(self):
        """Stop SOC background thread cleanly."""
        try:
            if hasattr(self, '_soc_tab'):
                worker = getattr(self._soc_tab, '_worker', None)
                thread = getattr(self._soc_tab, '_thread', None)
                if worker:
                    worker.running = False
                if thread:
                    thread.quit()
                    thread.wait()
        except Exception:
            pass

    def closeEvent(self, event):
        """Handle window close event by cleaning up threads."""
        self._cleanup()
        super().closeEvent(event)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())
