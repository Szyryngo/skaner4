"""
Detection plugin wrapping the existing DetectionModule.
"""
from core.plugin_base import PluginBase
from modules.detection import DetectionModule
from core.events import Event

class DetectionPlugin(PluginBase):
    def initialize(self, config: dict):
        """Initialize detection module synchronously."""
        self.config = config
        # Synchronous initialization to ensure module is ready immediately
        self._module = DetectionModule()
        self._module.initialize(config)

    def start(self):
        # No separate thread
        return

    def stop(self):
        return

    def handle_event(self, event):
        # Poczekaj na zakończenie inicjalizacji modułu
        if not hasattr(self, '_module'):
            return None
        try:
            return self._module.handle_event(event)
        except Exception:
            return None

    def generate_event(self):
        # Poczekaj na zakończenie inicjalizacji modułu
        if not hasattr(self, '_module'):
            return None
        try:
            return self._module.generate_event()
        except Exception:
            return None
