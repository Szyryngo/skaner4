

from core.interfaces import ModuleBase
from flask import Flask
import threading

class UIModule(ModuleBase):
	"""
	Moduł interfejsu webowego (Flask dashboard).
	"""
	def initialize(self, config):
		"""Inicjalizuje moduł UI (konfiguracja Flask)."""
		self.config = config
		self.app = Flask(__name__)
		self._setup_routes()
		self.thread = threading.Thread(target=self._run_flask, daemon=True)
		self.thread.start()

	def _setup_routes(self):
		@self.app.route("/")
		def index():
			return "<h1>AI Network Packet Analyzer Pro</h1><p>Dashboard działa!</p>"

	def _run_flask(self):
		port = self.config.get('ui_port', 5000)
		self.app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)

	def handle_event(self, event):
		pass

	def generate_event(self):
		return None
