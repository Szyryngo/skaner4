## 📄 DEVELOPMENT.md
```markdown
# DEVELOPMENT GUIDE – AI Network Packet Analyzer Pro

Ten plik jest przewodnikiem po implementacji kodu, przeznaczonym również dla GitHub Copilota.
Zawiera opis wszystkich modułów i kroków, jakie trzeba wykonać.

---

## 🧠 Architektura event-driven plugin-based
- Główna pętla w `core/orchestrator.py`
- Moduły implementują `ModuleBase` z `core/interfaces.py`
- Eventy przesyłane pomiędzy modułami przez orchestrator
- Pluginy ładowane dynamicznie z `/plugins` wg pliku `config/plugins_config.yaml`

---

## 📋 Lista modułów i ich cel

### **modules/capture.py**
- Sniffing pakietów w trybie promiscuous (`scapy.sniff` lub `pyshark.LiveCapture`).
- Publikuje event `NEW_PACKET`.

### **modules/features.py**
- Odbiera `NEW_PACKET`.
- Agreguje pakiety w flow.
- Publikuje `NEW_FEATURES`.

### **modules/detection.py**
- Odbiera `NEW_FEATURES`.
- AI detection + klasyfikacja.
- Publikuje `NEW_THREAT`.

### **modules/scanner.py**
- Ręczne skanowanie sieci.
- Light scan = ping + ARP sniff.
- Full scan = porty + OS detection.
- Publikuje `SCAN_COMPLETED`.

### **modules/devices.py**
- Śledzenie urządzeń w LAN z pakietów ARP/IP.
- Publikuje `DEVICE_DETECTED`.

### **modules/optimizer.py**
- Analiza zasobów hosta (CPU, RAM).
- Ustawia tryb pracy (low/high perf).
- Publikuje `CONFIG_UPDATED`.


### **qtui/qt_dashboard.py**
- Natywny GUI PyQt5 – dashboard, zakładki (alerty, urządzenia, skaner, konfiguracja).

---

## 🗂 API modułów (interfaces.py)
```python
class ModuleBase:
    def initialize(self, config):
        pass
    def handle_event(self, event):
        pass
    def generate_event(self):
        return None
```

---

## ⚙️ Eventy (events.py)
- `NEW_PACKET`
- `NEW_FEATURES`
- `NEW_THREAT`
- `DEVICE_DETECTED`
- `SCAN_COMPLETED`
- `CONFIG_UPDATED`

Przykład:
```python
Event("TYPE", {"key": value})
```

---

## 🚧 Kolejność implementacji
1. core/interfaces.py, events.py, plugin_loader.py, config_manager.py
2. modules/capture.py
3. modules/features.py
4. modules/detection.py
5. modules/optimizer.py
6. modules/devices.py
7. modules/scanner.py
8. qtui/qt_dashboard.py
9. Integracja orchestratora
10. Plugin testowy (plugins/example_plugin.py)

---

## 📌 Zasady pisania kodu dla Copilota
- Każda funkcja z modułu = komentarz opisujący dokładnie działanie (Copilot bazuje na tym przy pisaniu kodu).
- W `generate_event()` – tworzenie eventów z danymi.
- W `handle_event()` – reagowanie na odpowiednie typy eventów.
- Zero bezpośrednich wywołań kodu innego modułu (tylko eventy).
```

---

Chcesz, żebym teraz podał **cały trzeci plik `MODULES.md`** w gotowym bloku, żeby lecieliśmy po kolei? Potem dam Ci ostatni plik `TODO.md`. Wtedy będziesz miał cały komplet dokumentów dla Copilota.
