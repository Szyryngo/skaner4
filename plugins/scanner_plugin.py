"""
Scanner plugin wrapping the existing ScannerModule.
"""
from core.plugin_base import PluginBase
from modules.scanner import ScannerModule
from core.events import Event

class ScannerPlugin(PluginBase):
    def initialize(self, config: dict):
        self._module = ScannerModule()
        self._module.initialize(config)

    def start(self):
        return

    def stop(self):
        return

    def handle_event(self, event):
        try:
            return self._module.handle_event(event)
        except Exception:
            return None

    def generate_event(self):
        try:
            return self._module.generate_event()
        except Exception:
            return None
