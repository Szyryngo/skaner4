# AI Network Packet Analyzer Pro

## 📌 Cel projektu
Jest to modularny, rozszerzalny system do:
- przechwytywania pakietów sieciowych w trybie promiscuous,
- analizy ruchu w czasie rzeczywistym przy użyciu AI,
- ręcznego skanowania sieci (light/stealth i full scan),
- monitorowania urządzeń w sieci na żywo,
- automatycznej analizy i dostosowywania wydajności (AI optimizer),
- dodawania nowych funkcjonalności poprzez **pluginy**, bez ingerencji w kod główny.

---

## 🛠 Technologia
- **Python** 3.11+
- **Sniffing**: scapy, pyshark
- **AI/ML**: scikit-learn, numpy, pandas
- **UI**: Flask (multi-tab dashboard)
- **System / Config**: psutil, platform, yaml

---

## 📂 Struktura projektu
ai-network-analyzer/
├── core/ # logika główna, ładowanie modułów i pluginów, system eventów
├── modules/ # główne funkcje: sniffing, features, detection, scanner, devices, optimizer, ui
├── plugins/ # dodatkowe funkcje użytkownika
├── config/ # pliki konfiguracyjne
├── data/ # modele AI, blacklisty
├── tests/ # testy jednostkowe
└── main.py # punkt startowy

---

## 🚀 Uruchomienie
```bash
pip install -r requirements.txt
python main.py

Filozofia modułowa
Każdy moduł implementuje ModuleBase z core/interfaces.py.
Wszystkie moduły komunikują się przez eventy (klasa Event w core/events.py).
Dodanie nowej funkcji = dodanie nowego modułu lub pluginu, bez modyfikowania reszty kodu.

📖 Dokumentacja developerska
Patrz DEVELOPMENT.md – znajdziesz tam szczegółowe instrukcje implementacji krok po kroku (dla ludzi i GitHub Copilota).


---

## 📄 Plik: `DEVELOPMENT.md`
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

### **modules/ui.py**
- Flask UI – dashboard (alerty, skaner, urządzenia, konfiguracja).

---

### 🗂 API modułów (interfaces.py)

```python
class ModuleBase:
    def initialize(self, config):
        pass
    def handle_event(self, event):
        pass
    def generate_event(self):
        return None

### ⚙️ Eventy (events.py)
NEW_PACKET
NEW_FEATURES
NEW_THREAT
DEVICE_DETECTED
SCAN_COMPLETED
CONFIG_UPDATED
Event = Event("TYPE", {"key": value})

Świetnie – przygotuję Ci teraz komplet plików **README.md**, **DEVELOPMENT.md** i **MODULES.md** (plus propozycję **TODO.md**), tak żebyś mógł dodać je od razu do repozytorium.  

To będą **„dane pomocnicze”** dla GitHub Copilota – wczyta je jako kontekst projektu i będzie dokładnie wiedział, co ma robić, jak są zorganizowane moduły, jak wygląda pętla zdarzeń i w jaki sposób dodawać funkcje/pluginy.  

Dzięki temu zaczynasz z repozytorium, które jest „samodokumentujące” i **Copilot-friendly**: AI rozumie cele, strukturę, API, oraz krok po kroku wie, co uzupełniać.

---

## 📄 Plik: `README.md`
```markdown
# AI Network Packet Analyzer Pro

## 📌 Cel projektu
Jest to modularny, rozszerzalny system do:
- przechwytywania pakietów sieciowych w trybie promiscuous,
- analizy ruchu w czasie rzeczywistym przy użyciu AI,
- ręcznego skanowania sieci (light/stealth i full scan),
- monitorowania urządzeń w sieci na żywo,
- automatycznej analizy i dostosowywania wydajności (AI optimizer),
- dodawania nowych funkcjonalności poprzez **pluginy**, bez ingerencji w kod główny.

---

## 🛠 Technologia
- **Python** 3.11+
- **Sniffing**: scapy, pyshark
- **AI/ML**: scikit-learn, numpy, pandas
- **UI**: Flask (multi-tab dashboard)
- **System / Config**: psutil, platform, yaml

---

## 📂 Struktura projektu
```
ai-network-analyzer/
├── core/               # logika główna, ładowanie modułów i pluginów, system eventów
├── modules/            # główne funkcje: sniffing, features, detection, scanner, devices, optimizer, ui
├── plugins/            # dodatkowe funkcje użytkownika
├── config/             # pliki konfiguracyjne
├── data/               # modele AI, blacklisty
├── tests/              # testy jednostkowe
└── main.py             # punkt startowy
```

---

## 🚀 Uruchomienie
```bash
pip install -r requirements.txt
python main.py
```

---

## 🔌 Filozofia modułowa
- Każdy moduł implementuje `ModuleBase` z `core/interfaces.py`.
- Wszystkie moduły komunikują się przez eventy (klasa `Event` w `core/events.py`).
- Dodanie nowej funkcji = dodanie nowego modułu lub pluginu, bez modyfikowania reszty kodu.

---

## 📖 Dokumentacja developerska
Patrz **DEVELOPMENT.md** – znajdziesz tam szczegółowe instrukcje implementacji krok po kroku (dla ludzi i GitHub Copilota).
```

---

## 📄 Plik: `DEVELOPMENT.md`
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

### **modules/ui.py**
- Flask UI – dashboard (alerty, skaner, urządzenia, konfiguracja).

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

Event = `Event("TYPE", {"key": value})`

---

## 🚧 Kolejność implementacji
1. core/interfaces.py, events.py, plugin_loader.py, config_manager.py
2. modules/capture.py
3. modules/features.py
4. modules/detection.py
5. modules/optimizer.py
6. modules/devices.py
7. modules/scanner.py
8. modules/ui.py
9. Integracja orchestratora
10. Plugin testowy (plugins/example_plugin.py)

---

## 📌 Zasady pisania kodu dla Copilota
- Każda funkcja z modułu = opis w komentarzu z działaniem.
- W `generate_event()` – tworzenie eventów z danymi.
- W `handle_event()` – reagowanie na odpowiednie typy eventów.
- Zero wywołań kodu innego modułu bez eventów.
```

---

## 📄 Plik: `MODULES.md`
```markdown
# MODULES DETAILS – AI Network Packet Analyzer Pro

Opis wszystkich modułów i ich interfejsów.

---

## core/
- **orchestrator.py** – ładowanie modułów, pętla eventów, dispatch.
- **plugin_loader.py** – import pluginów z config.
- **interfaces.py** – klasa bazowa dla modułów.
- **events.py** – definicja klasy Event.
- **config_manager.py** – ładowanie/zapisywanie konfiguracji.

---

## modules/
- **capture.py** – przechwytuje pakiety → NEW_PACKET.
- **features.py** – wyciąga cechy → NEW_FEATURES.
- **detection.py** – AI analiza → NEW_THREAT.
- **scanner.py** – skanowanie sieci → SCAN_COMPLETED.
- **devices.py** – wykrywanie hostów → DEVICE_DETECTED.
- **optimizer.py** – dobór trybu pracy → CONFIG_UPDATED.
- **ui.py** – interfejs webowy.

---

## plugins/
- Wtyczki działają jak moduły.
- Dodajesz nowy plik .py w `/plugins` i wpis w `plugins_config.yaml`.

---

## config/
- **config.yaml** – parametry programu.
- **plugins_config.yaml** – lista wtyczek i ich ścieżki.

---

Każdy moduł publikuje/dostaje eventy – zero bezpośrednich zależności.
```
