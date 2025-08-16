from core.interfaces import ModuleBase
from core.events import Event


class FeaturesModule(ModuleBase):
    """
	Moduł agregujący pakiety w flow i generujący cechy ruchu.
	Odbiera NEW_PACKET, publikuje NEW_FEATURES.
	"""

    def initialize(self, config):
        """Inicjalizuje moduł (np. parametry agregacji)."""
        self.config = config
        self.flows = {}

    def handle_event(self, event):
        """Obsługuje event NEW_PACKET, agreguje do flow i loguje do konsoli."""
        if event.type == 'NEW_PACKET':
            print(f'[FeaturesModule] Otrzymano NEW_PACKET: {event.data}')
            self._last_packet = event.data

    def generate_event(self):
        """
		Generuje event NEW_FEATURES na podstawie ostatniego pakietu (symulacja).
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
            print(f'[FeaturesModule] Generuję NEW_FEATURES: {features}')
            del self._last_packet
            return Event('NEW_FEATURES', features)
        return None
