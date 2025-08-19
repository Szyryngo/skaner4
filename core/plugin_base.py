"""
Plugin base class for all plugins in Skaner4.
"""

from abc import ABC, abstractmethod

class PluginBase(ABC):
    @abstractmethod
    def initialize(self, config: dict):
        """Prepare the plugin with configuration dictionary."""
        pass

    @abstractmethod
    def start(self):
        """Start plugin execution (e.g., start sniffing or GUI elements)."""
        pass

    @abstractmethod
    def stop(self):
        """Stop plugin execution and cleanup."""
        pass

    @abstractmethod
    def handle_event(self, event):
        """Process incoming events; may return new Event or list of Events."""
        pass

    @abstractmethod
    def generate_event(self):
        """Generate outgoing events; return an Event or None if no event."""
        pass
