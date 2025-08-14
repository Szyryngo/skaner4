
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
		self.sniffing = False

	def handle_event(self, event):
		"""Nie obsługuje eventów (sniffing jest pasywny)."""
		pass

	def generate_event(self):
		"""
		Przechwytuje pakiet i zwraca event NEW_PACKET (szkielet, bez realnego sniffingu).
		Wersja docelowa: scapy.sniff lub pyshark.LiveCapture.
		"""
		# TODO: implement real packet sniffing
		return None
