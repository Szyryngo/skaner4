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
- **Sniffing**: scapy (w późniejszym etapie pyshark jako plugin)
- **AI/ML**: scikit-learn, numpy, pandas
- **UI**: PyQt5 (natywny GUI, multi-tab dashboard)
- **System / Config**: psutil, platform, yaml

---

## 📂 Struktura projektu

```
skaner4/
├── core/               # logika główna, orchestrator, eventy, pluginy
├── modules/            # sniffing, features, detection, devices, optimizer, scanner, netif
├── plugins/            # pluginy użytkownika
├── qtui/               # natywny GUI PyQt5 (qt_dashboard.py)
├── config/             # pliki konfiguracyjne (config.yaml, plugins_config.yaml)
├── data/               # modele AI, blacklisty
├── tests/              # testy jednostkowe
└── main.py             # punkt startowy
```

---

## 📄 README.md
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
├── modules/            # główne funkcje: sniffing, features, detection, scanner, devices, optimizer
├── plugins/            # dodatkowe funkcje użytkownika
├── qtui/               # natywny GUI PyQt5 (qt_dashboard.py)
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
Program domyślnie uruchamia natywny GUI PyQt5 (main.py → qtui/qt_dashboard.py).

### Funkcje GUI:
- Dynamiczny wybór interfejsu sieciowego przez użytkownika (QComboBox)
- Przycisk "Testuj interfejsy" – testuje sniffing na wszystkich interfejsach i pokazuje wyniki w oknie dialogowym
- Dashboard, Live Devices, Network Scanner, Configuration – wszystko w jednym oknie

---

## 🔌 Filozofia modułowa
- Każdy moduł implementuje `ModuleBase` z `core/interfaces.py`.
- Wszystkie moduły komunikują się przez eventy (klasa `Event` w `core/events.py`).
- Dodanie nowej funkcji = dodanie nowego modułu lub pluginu, bez modyfikowania reszty kodu.

---

## 📖 Dokumentacja developerska
- Szczegółowy opis architektury, API i eventów: **DEVELOPMENT.md**
- Opis wszystkich modułów i ich przeznaczenia: **MODULES.md**
- Lista zadań implementacyjnych i testowych: **TODO.md**
```
