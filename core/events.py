"""Event system module - define Event class for inter-module communication."""

class Event:
    """Event object carrying type and data payload between modules and plugins."""

    def __init__(self, event_type, data=None):
        """Initialize an Event with a type and optional data.

        Parameters
        ----------
        event_type : str
            Identifier for the event type.
        data : dict, optional
            Payload associated with the event.
        """
        self.type = event_type
        self.data = data or {}

    def __repr__(self):
        """Return a string representation of the Event for debugging."""
        return f'<Event {self.type} {self.data}>'
