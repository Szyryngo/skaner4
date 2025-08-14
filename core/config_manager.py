
import yaml

class ConfigManager:
	"""
	Zarządza ładowaniem i zapisem plików konfiguracyjnych YAML.
	"""
	def __init__(self, config_path):
		self.config_path = config_path
		self.config = None

	def load(self):
		"""Ładuje konfigurację z pliku YAML."""
		with open(self.config_path, 'r', encoding='utf-8') as f:
			self.config = yaml.safe_load(f)
		return self.config

	def save(self, config=None):
		"""Zapisuje konfigurację do pliku YAML."""
		to_save = config if config is not None else self.config
		with open(self.config_path, 'w', encoding='utf-8') as f:
			yaml.safe_dump(to_save, f, allow_unicode=True)
