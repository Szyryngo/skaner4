"""Features Module - aggregate packets into flows and generate traffic features.

This module listens for NEW_PACKET events, aggregates packets into flows,
and emits NEW_FEATURES events containing summarized flow statistics."""
from core.interfaces import ModuleBase
from core.events import Event


class FeaturesModule(ModuleBase):
    """Module to process packet events and generate feature events.

    On receiving a NEW_PACKET event, stores packet data for flow aggregation.
    Periodically outputs NEW_FEATURES events containing flow statistics.
    """

    def initialize(self, config):
        """Initialize module with configuration settings.

        Parameters
        ----------
        config : dict
            Configuration parameters for feature computation (timeout, thresholds, etc.).
        """
        self.config = config
        self.flows = {}

    def handle_event(self, event):
        """Handle NEW_PACKET events by storing packet for later feature generation.

        Parameters
        ----------
        event : Event
            The incoming event; if type is NEW_PACKET, packet data saved.
        """
        if event.type == 'NEW_PACKET':
            # Debug logging disabled to avoid stdout contention
            # print(f'[FeaturesModule] Otrzymano NEW_PACKET: {event.data}')
            self._last_packet = event.data

    def generate_event(self):
        """Generate a NEW_FEATURES event based on stored packet data.

        Constructs a basic feature set including packet count and byte totals.

        Returns
        -------
        Event or None
            NEW_FEATURES event with feature dict, or None if no data.
        """
        if hasattr(self, '_last_packet'):
            pkt = self._last_packet
            # build feature set including packet origin
            features = {
                'flow_id': '1',
                'packet_count': 1,
                'total_bytes': pkt.get('payload_size', 0),
                'src_ip': pkt.get('src_ip'),
                'dst_ip': pkt.get('dst_ip')
            }
            # Debug logging disabled to avoid stdout contention
            # print(f'[FeaturesModule] Generuję NEW_FEATURES: {features}')
            del self._last_packet
            return Event('NEW_FEATURES', features)
        return None
