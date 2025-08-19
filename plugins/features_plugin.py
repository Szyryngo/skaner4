"""
Features plugin wrapping the existing FeaturesModule.
"""
from core.plugin_base import PluginBase
from modules.features import FeaturesModule
from core.events import Event

class FeaturesPlugin(PluginBase):
    def initialize(self, config: dict):
        self._module = FeaturesModule()
        self._module.initialize(config)

    def start(self):
        # No separate thread; events are handled via orchestrator
        return

    def stop(self):
        # Nothing to stop
        return

    def handle_event(self, event):
        # Pass incoming event through features module
        try:
            return self._module.handle_event(event)
        except Exception:
            return None

    def generate_event(self):
        # Return any generated feature events
        try:
            return self._module.generate_event()
        except Exception:
            return None
