# AI Network Packet Analyzer Pro

## 📦 Repozytorium GitHub
[![Build Status](https://github.com/Szyryngo/skaner4/actions/workflows/python-app.yml/badge.svg)](https://github.com/Szyryngo/skaner4/actions)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
Repozytorium: https://github.com/Szyryngo/skaner4

## 🆕 Ostatnie zmiany (sierpień 2025)
- Naprawiono i uproszczono kod dashboardu (qtui/qt_dashboard.py):
	- Usunięto powielone fragmenty i błędne wcięcia w klasie DashboardTab.
	- Wszystkie przyciski i pola wyboru są zawsze widoczne i nie znikają.
	- Dodano dolną belkę logów (status bar) z informacjami o działaniach użytkownika.
	- Przycisk "Pauza" i "Stop" poprawnie zatrzymują cykliczne pobieranie pakietów.
	- Pakiety wyświetlane są tylko w GUI, nie pojawiają się już w konsoli.
	- QTimer cyklicznie pobiera pakiety do tabeli, gdy sniffing jest aktywny.
	- Czytelny wybór interfejsu sieciowego (QComboBox, testowanie i użycie wybranego interfejsu).
	- Integracja orchestratora z GUI, automatyczne przekazywanie eventów.
	- Kod jest gotowy do dalszej rozbudowy i testów.
	 - Usprawniono przepływ eventów AI (pakiet → FeaturesModule → DetectionModule) za pomocą sygnałów Qt.
	 - Dodano przyciski eksportu pakietów (CSV, PCAP) z domyślnymi nazwami zawierającymi timestamp (YYYYMMDD_HHMMSS).
 	- Rozbudowano panel szczegółów: dekodowanie warstw protokołu (Scapy) oraz tłumaczenie numerów protokołów z config/protocols.yaml.
 - Dodano zakładkę `Info` z informacjami o podzespołach komputera (CPU, RAM, GPU, BIOS, płyta główna, dyski, karty sieciowe).
 - Dodano pasek narzędzi z metrykami systemu (CPU%, RAM%, liczba wątków i rdzeni) odświeżany co sekundę.
- Ustalono wersję **1.4.0** w tytule aplikacji oraz zaktualizowano `VERSIONING.md` z polityką wersjonowania; dodano:
	 - eksport przechwyconych pakietów do CSV i PCAP (okno zapisu, domyślne nazwy z timestamp);
	 - panel szczegółów pakietu (dekodowanie warstw, HEX, ASCII);
	 - mapowanie numerów protokołów z `config/protocols.yaml`;
	 - czytelne etykiety interfejsów na Windows (typ, opis, IP zamiast identyfikatorów).  
 - Dodano asynchroniczną zakładkę `Discovery` przeniesioną do osobnego wątku z raportowaniem postępu.
 - Usprawniono `ScannerTab`: skanowanie portów i ping-sweep wykonuje się w oddzielnych wątkach, UI pozostaje responsywne.
 - Dostosowano plan optymalizacji: profile CPU/I/O, przeniesienie blokujących operacji do wątków, batch‐owe aktualizacje GUI, rozważenie multiprocessing dla AI.

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
- **Python** 3.13+
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
- Każdy moduł implementuje `ModuleBase` z `core/interfaces.py`.
- Dodanie nowej funkcji = dodanie nowego modułu lub pluginu, bez modyfikowania reszty kodu.

- Lista zadań implementacyjnych i testowych: **TODO.md**
## Opcjonalne modele AI
- IsolationForest (zewnętrzny model w `data/models/isolation_forest.joblib`)
- Sieć neuronowa (TensorFlow/Keras) – jeśli dodasz `tensorflow` do `requirements.txt`, w `DetectionModule` możesz wczytać `nn_model.h5` i używać predykcji pravdopodobieństwa anomalii.
```
