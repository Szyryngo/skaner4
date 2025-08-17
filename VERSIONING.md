# Polityka wersjonowania

# Ten projekt używa [Semantycznego Wersjonowania](https://semver.org/) do śledzenia wydań i zmian.

## Format wersji

# Wersje mają format `MAJOR.MINOR.PATCH`:

	- **MAJOR** — wersja główna, używana przy wprowadzaniu niekompatybilnych zmian w API lub istotnych kamieniach milowych.
	- **MINOR** — wersja drugorzędna, gdy dodajesz funkcjonalność w sposób kompatybilny wstecz.
	- **PATCH** — wersja poprawkowa, gdy wprowadzasz poprawki błędów kompatybilne wstecz.

# Zaczynamy od początkowego, stabilnego wydania:

	- **1.0.0** — początkowe stabilne wydanie AI Network Packet Analyzer Pro.
	- **1.1.0** — dodano asynchroniczny Ping-Sweep (Discovery) w osobnym wątku oraz ulepszono ScannerTab.

	 - **1.2.0** — poprawki i nowe funkcje GUI:
		 - eksport pakietów do CSV i PCAP (okno zapisu, domyślne nazwy z timestamp);
		 - wyświetlanie szczegółów pakietu (dekodowanie warstw, HEX, ASCII);
		 - mapowanie numerów protokołów z `config/protocols.yaml`;
		 - czytelne etykiety interfejsów na Windows (typ, opis, IP zamiast identyfikatorów).

## Wytyczne dotyczące wydań

	- Zwiększ **MAJOR**, gdy wprowadzasz zmiany łamiące kompatybilność (np. zmiana lub usunięcie publicznych interfejsów, zmiana formatu danych).
	- Zwiększ **MINOR**, gdy dodajesz nowe funkcje lub moduły w sposób kompatybilny wstecz.
	- Zwiększ **PATCH**, gdy wprowadzasz poprawki błędów, ulepszenia wydajności lub drobne modyfikacje bez dodawania nowych funkcji.

## Utrzymanie po wydaniu

1. Po połączeniu zmian dla następnego wydania, zaktualizuj numer wersji w tytule aplikacji (jeśli wyświetlany).
2. Oznacz commit w Git tagiem `vMAJOR.MINOR.PATCH` (np. `v1.0.0`).
3. Zaktualizuj ten plik `VERSIONING.md`, dodając notatki dotyczące zmian lub kroków migracji.

---

*Wygenerowane przez zespół maintainerów projektu. Stosuj wytyczne Semantycznego Wersjonowania dla zachowania spójności.*
