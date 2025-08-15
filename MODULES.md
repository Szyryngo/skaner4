## 📄 MODULES.md
```markdown
# MODULES DETAILS – AI Network Packet Analyzer Pro

Opis wszystkich modułów, ich interfejsów i przeznaczenia.

---

## core/
- **orchestrator.py** – 
  - Ładuje wszystkie moduły i pluginy.
  - Pętla komunikacji oparta o eventy.
  - Rozsyła eventy między modułami.
- **plugin_loader.py** – 
  - Wczytuje dynamicznie pluginy z katalogu `/plugins` zgodnie z `plugins_config.yaml`.
- **interfaces.py** – 
  - API modułowe (`ModuleBase`), które muszą implementować wszystkie moduły i pluginy.
- **events.py** – 
  - Definicja obiektu `Event` z typem i danymi.
- **config_manager.py** – 
  - Ładowanie i zapisywanie konfiguracji (`config.yaml`).

---

## modules/
- **capture.py** – 
  - Przechwytuje pakiety w trybie promiscuous.
  - Tworzy event `NEW_PACKET` z metadanymi.
- **features.py** – 
  - Odbiera `NEW_PACKET`, buduje cechy ruchu (flow features).
  - Tworzy event `NEW_FEATURES`.
- **detection.py** –
  - Odbiera `NEW_FEATURES`.
  - Analiza AI: detekcja anomalii i klasyfikacja znanych zagrożeń.
  - Tworzy event `NEW_THREAT`.
- **scanner.py** –
  - Ręczne skanowanie sieci.
  - Tryb light (ARP sniff/ping sweep).
  - Tryb full (port scan, OS detection).
  - Tworzy event `SCAN_COMPLETED`.
- **devices.py** –
  - Analiza pakietów pod kątem urządzeń w sieci (ARP/IP).
  - Tworzy event `DEVICE_DETECTED`.
- **optimizer.py** – 
  - Analiza zasobów komputera (CPU, RAM, OS).
  - Dobór trybu low/high performance.
  - Tworzy event `CONFIG_UPDATED`.
-- **qtui/qt_dashboard.py** –
  - Natywny GUI PyQt5 (dashboard, zakładki: alerty, urządzenia, skaner, konfiguracja).
  - Dodano metody `_on_export_csv` i `_on_export_pcap` do eksportu pakietów (CSV, PCAP) z domyślnymi nazwami plików zawierającymi timestamp (YYYYMMDD_HHMMSS).

---

## plugins/
- Wtyczki (pluginy) działają jak moduły.
- Muszą implementować `ModuleBase`.
- Nowy plugin → nowy plik `.py` w `/plugins` + wpis w `plugins_config.yaml`.
- Plugin może reagować na dowolne eventy i generować swoje.

---

## config/
- **config.yaml** –
  - Główne ustawienia programu (interfejs sieci, parametry AI, ustawienia UI).
- **plugins_config.yaml** –
  - Lista pluginów do wczytania, ich ścieżki i status (enabled/disabled).

---

## Event Flow
1. `capture.py` → `NEW_PACKET`
2. `features.py` → `NEW_FEATURES` (na podstawie NEW_PACKET)
3. `detection.py` → `NEW_THREAT` (jeśli zagrożenie)
4. `qt_dashboard.py` → wyświetlenie alertu
5. dodatkowe moduły/pluginy mogą reagować na dowolnym etapie

---

## Zasada komunikacji
- Moduły nie komunikują się bezpośrednio.
- Wymiana danych wyłącznie poprzez eventy (`core/events.py`).

---

📌 Dzięki temu projekt jest:
- łatwy w utrzymaniu,
- bezpieczny w rozbudowie,
- odporny na awarie pojedynczych modułów.
```
