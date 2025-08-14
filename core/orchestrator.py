
from core.events import Event
from core.plugin_loader import load_plugins
from core.config_manager import ConfigManager
from modules.capture import CaptureModule
from modules.features import FeaturesModule
from modules.detection import DetectionModule
from modules.optimizer import OptimizerModule
from modules.devices import DevicesModule
from modules.scanner import ScannerModule
from modules.ui import UIModule

import os

class Orchestrator:
	"""
	Główna pętla eventów, ładowanie i integracja modułów oraz pluginów.
	"""
	def __init__(self, config_dir='config', plugins_dir='plugins'):
		self.config_dir = config_dir
		self.plugins_dir = plugins_dir
		self.modules = []
		self.plugins = []
		self.event_queue = []

	def initialize(self):
		"""Inicjalizuje wszystkie moduły i pluginy."""
		# Ładowanie konfiguracji
		config_path = os.path.join(self.config_dir, 'config.yaml')
		plugins_config_path = os.path.join(self.config_dir, 'plugins_config.yaml')
		config = ConfigManager(config_path).load()

		# Inicjalizacja modułów
		self.modules = [
			CaptureModule(),
			FeaturesModule(),
			DetectionModule(),
			OptimizerModule(),
			DevicesModule(),
			ScannerModule(),
			UIModule(),
		]
		for module in self.modules:
			module.initialize(config)

		# Inicjalizacja pluginów
		self.plugins = load_plugins(plugins_config_path, self.plugins_dir)
		for plugin in self.plugins:
			plugin.initialize(config)

	def run(self):
		"""Główna pętla eventów."""
		self.initialize()
		while True:
			# 1. Zbierz eventy z generate_event() wszystkich modułów i pluginów
			for obj in self.modules + self.plugins:
				event = obj.generate_event()
				if event:
					self.event_queue.append(event)

			# 2. Obsłuż eventy z kolejki
			while self.event_queue:
				event = self.event_queue.pop(0)
				for obj in self.modules + self.plugins:
					try:
						result = obj.handle_event(event)
						if isinstance(result, Event):
							self.event_queue.append(result)
					except Exception as e:
						print(f"Błąd w module/pluginie {obj.__class__.__name__}: {e}")

			# Pętla nieskończona, aby serwer Flask działał cały czas
			import time
			time.sleep(1)
