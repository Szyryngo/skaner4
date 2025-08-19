"""Core interfaces module - define base class for application modules and plugins."""

class ModuleBase:
    """Abstract base class that all modules and plugins must extend.

    Defines initialize, handle_event, and generate_event lifecycle methods.
    """

    def initialize(self, config):
        """Initialize the module or plugin with the provided config dictionary."""
        pass

    def handle_event(self, event):
        """Handle an incoming event dispatched by the orchestrator."""
        pass

    def generate_event(self):
        """Generate a new event to dispatch, or return None if no event to send."""
        return None
