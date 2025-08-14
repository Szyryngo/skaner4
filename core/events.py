
class Event:
	"""
	Klasa reprezentująca event przesyłany między modułami.
	"""
	def __init__(self, event_type, data=None):
		self.type = event_type
		self.data = data or {}

	def __repr__(self):
		return f"<Event {self.type} {self.data}>"
