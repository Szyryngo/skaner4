"""
Dashboard plugin that launches the Qt GUI using the existing MainWindow.
"""
from core.plugin_base import PluginBase
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QApplication
from qtui.main_window import MainWindow

class DashboardPlugin(PluginBase, QObject):
    """Dashboard GUI plugin; receives events via signal and updates UI asynchronously."""
    evReceived = pyqtSignal(object)

    def __init__(self):
        QObject.__init__(self)
        super().__init__()
        self.app = None
        self.window = None

    def initialize(self, config: dict):
        """Prepare QApplication and MainWindow, and connect event signal."""
        self.config = config
        # Ensure QApplication exists
        self.app = QApplication.instance() or QApplication([])
        # Instantiate main window
        self.window = MainWindow()
        # Connect incoming events to DashboardTab
        if hasattr(self.window, 'dash_tab'):
            self.evReceived.connect(self.window.dash_tab.handle_event)

    def start(self):
        """Show the main window without blocking."""
        if self.window:
            self.window.show()

    def stop(self):
        """Quit the Qt application."""
        try:
            from PyQt5.QtWidgets import qApp
            qApp.quit()
        except Exception:
            pass

    def handle_event(self, event):
        """Emit incoming event to the GUI via signal."""
        self.evReceived.emit(event)

    def generate_event(self):
        """Dashboard plugin does not generate events."""
        return None
