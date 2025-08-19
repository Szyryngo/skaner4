"""
Capture plugin using PluginBase, runs sniffing asynchronously in QThread.
"""
import sys
import queue
from PyQt5.QtCore import QThread, pyqtSignal
from plugins.capture_worker import CaptureWorker
from core.plugin_base import PluginBase
from core.events import Event

class CapturePlugin(PluginBase):
    def initialize(self, config: dict):
        self.config = config
        self.event_queue = queue.Queue()
        # Start worker thread
        self.worker = CaptureWorker(config, self.event_queue)
        self.worker.start()

    def start(self):
        # Already started in initialize
        return

    def stop(self):
        self.worker.stop()
        self.worker.wait()

    def handle_event(self, event):
        return None

    def generate_event(self):
        try:
            return self.event_queue.get_nowait()
        except queue.Empty:
            return None
