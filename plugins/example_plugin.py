"""Example Plugin - sample plugin demonstrating how to react to NEW_THREAT events."""
from core.interfaces import ModuleBase
from core.events import Event


class ExamplePlugin(ModuleBase):
    """Sample plugin that counts threat events and issues a block after threshold."""

    def initialize(self, config):
        """Initialize plugin with configuration settings.

        Parameters
        ----------
        config : dict
            Plugin-specific configuration data.
        """
        self.config = config
        self.incident_counter = {}

    def handle_event(self, event):
        """Handle incoming events; block IP after reaching incident threshold.

        Parameters
        ----------
        event : Event
            The event object; triggers on type 'NEW_THREAT'.

        Returns
        -------
        Event or None
            'BLOCK_IP' event if threshold reached, else None.
        """
        if event.type == 'NEW_THREAT':
            ip = event.data.get('ip')
            if ip:
                self.incident_counter[ip] = self.incident_counter.get(ip, 0
                    ) + 1
                if self.incident_counter[ip] >= 3:
                    return Event('BLOCK_IP', {'ip': ip})

    def generate_event(self):
        """Generate next pending event, if any (none for this plugin)."""
        return None
