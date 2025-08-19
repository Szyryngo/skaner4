"""
Devices plugin wrapping the existing DevicesModule.
"""
from core.plugin_base import PluginBase
from modules.devices import DevicesModule
from core.events import Event

class DevicesPlugin(PluginBase):
    def initialize(self, config: dict):
        self._module = DevicesModule()
        self._module.initialize(config)

    def start(self):
        # No separate thread; logic triggered via handle_event/generate_event
        return

    def stop(self):
        return

    def handle_event(self, event):
        # Underlying handle_event is a generator yielding events
        try:
            results = list(self._module.handle_event(event) or [])
            return results if results else None
        except Exception:
            return None

    def generate_event(self):
        # Underlying generate_event yields events
        try:
            results = list(self._module.generate_event() or [])
            return results if results else None
        except Exception:
            return None
