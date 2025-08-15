class ModuleBase:
    """
	Bazowa klasa interfejsu dla wszystkich modułów i pluginów.
	Każdy moduł musi ją implementować.
	"""

    def initialize(self, config):
        """Inicjalizuje moduł z podaną konfiguracją."""
        pass

    def handle_event(self, event):
        """Obsługuje event przekazany przez orchestratora."""
        pass

    def generate_event(self):
        """Zwraca nowy event do rozesłania (lub None jeśli brak)."""
        return None
