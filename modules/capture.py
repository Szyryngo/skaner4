
from core.interfaces import ModuleBase
from core.events import Event

class CaptureModule(ModuleBase):
	"""
	Moduł przechwytujący pakiety w trybie promiscuous.
	Publikuje event NEW_PACKET.
	"""
	def initialize(self, config):
		"""Inicjalizuje moduł z konfiguracją (np. interfejs sieciowy, filtr)."""
		self.config = config
		self._last_packet = None
		self._start_sniffing()

	def _start_sniffing(self):
		from scapy.all import sniff, raw
		import threading
		def pkt_callback(pkt):
			try:
				if pkt.haslayer('IP'):
					ip = pkt['IP']
					event = {
						'src_ip': ip.src,
						'dst_ip': ip.dst,
						'protocol': pkt.proto if hasattr(pkt, 'proto') else 'N/A',
						'payload_size': len(pkt),
						'raw_bytes': bytes(raw(pkt))
					}
					self._last_packet = event
			except Exception as e:
				print(f"[CaptureModule] Błąd przy analizie pakietu: {e}")
		iface = self.config.get('network_interface', None)
		flt = self.config.get('filter', '')
		t = threading.Thread(target=lambda: sniff(prn=pkt_callback, filter=flt, iface=iface, store=0), daemon=True)
		t.start()

	def handle_event(self, event):
		"""Nie obsługuje eventów (sniffing jest pasywny)."""
		pass

	def generate_event(self):
		"""
		Zwraca event NEW_PACKET na podstawie przechwyconego pakietu przez scapy.
		"""
		if self._last_packet:
			pkt = self._last_packet
			self._last_packet = None
			return Event('NEW_PACKET', pkt)
		return None
