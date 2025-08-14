
from core.interfaces import ModuleBase
from core.events import Event

class ExamplePlugin(ModuleBase):
	"""
	Przykładowy plugin reagujący na event NEW_THREAT.
	"""
	def initialize(self, config):
		self.config = config
		self.incident_counter = {}

	def handle_event(self, event):
		if event.type == 'NEW_THREAT':
			ip = event.data.get('ip')
			if ip:
				self.incident_counter[ip] = self.incident_counter.get(ip, 0) + 1
				if self.incident_counter[ip] >= 3:
					# Po przekroczeniu progu publikuj BLOCK_IP
					return Event('BLOCK_IP', {'ip': ip})

	def generate_event(self):
		return None
