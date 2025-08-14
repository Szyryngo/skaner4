
from core.interfaces import ModuleBase
from core.events import Event

class CaptureModule(ModuleBase):
	def test_all_interfaces(self):
		"""Testuje sniffing na wszystkich interfejsach i loguje, czy pojawiają się pakiety."""
		from modules.netif import list_interfaces
		from scapy.all import sniff
		print("[CaptureModule] Testowanie sniffingu na wszystkich interfejsach...")
		results = {}
		for iface in list_interfaces():
			print(f"[CaptureModule] Test interfejsu: {iface}")
			packets = []
			try:
				sniff(prn=lambda pkt: packets.append(pkt), iface=iface, timeout=2, count=1, store=0)
				results[iface] = len(packets)
				if packets:
					print(f"[CaptureModule] Interfejs {iface}: wykryto pakiet!")
				else:
					print(f"[CaptureModule] Interfejs {iface}: brak pakietów.")
			except Exception as e:
				print(f"[CaptureModule] Błąd na interfejsie {iface}: {e}")
				results[iface] = f"Błąd: {e}"
		print("[CaptureModule] Wyniki testu interfejsów:")
		for iface, res in results.items():
			print(f"  {iface}: {res}")
		return results
	def set_interface(self, iface):
		"""Ustawia interfejs i restartuje sniffing."""
		self.config['network_interface'] = iface
		self._start_sniffing()
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
		def sniff_thread():
			if flt and flt.strip().lower() not in ('', 'nie filtruj', 'none'):
				sniff(prn=pkt_callback, filter=flt, iface=iface, store=0)
			else:
				sniff(prn=pkt_callback, iface=iface, store=0)
		t = threading.Thread(target=sniff_thread, daemon=True)
		t.start()

	def handle_event(self, event):
		"""Nie obsługuje eventów (sniffing jest pasywny)."""
		pass

	def generate_event(self):
		"""
		Zwraca event NEW_PACKET na podstawie przechwyconego pakietu przez scapy.
		"""
		print(f"[CaptureModule] generate_event: self._last_packet={self._last_packet}")
		if self._last_packet:
			pkt = self._last_packet
			print(f"[CaptureModule] generate_event: zwracam event z pkt={pkt}")
			self._last_packet = None
			return Event('NEW_PACKET', pkt)
		return None
