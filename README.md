# AI Network Packet Analyzer Pro

## Wersja
- Obecna wersja: **1.7.0-alpha**

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
- Ustalono wersję **1.5.10** w tytule aplikacji oraz zaktualizowano `VERSIONING.md`; dodano:
		- [ ] eksport przechwyconych pakietów do CSV i PCAP (okno zapisu, domyślne nazwy z timestamp)
		- [ ] panel szczegółów pakietu (dekodowanie warstw, HEX, ASCII)
		- [ ] mapowanie numerów protokołów z `config/protocols.yaml`
		- [ ] czytelne etykiety interfejsów na Windows (typ, opis, IP zamiast identyfikatorów)
		- Pełna obsługa składni Snort:
			• header, content (offset/depth/within/distance/nocase), pcre, itype, flags
			• threshold, dsize, length, byte_test, flow, flowbits
			• http_* (method, uri, client_body), dns.* (query, query_type)
			• uricontent, rawbytes, isdataat, byte_extract, byte_jump
			• fragbits, fragoffset, ttl, tos, ip_flags
			• rate_filter, metadata, classtype, priority, reference
		- Testy jednostkowe Snort z użyciem PCAP/Scapy
		- Integracja SNORT_ALERT z GUI (logi w dashboard, zakładka SOC)
		- Optymalizacja indeksowania reguł Snort (triple-key index)
 - Dodano asynchroniczną zakładkę `Discovery` przeniesioną do osobnego wątku z raportowaniem postępu.
 - Usprawniono `ScannerTab`: skanowanie portów i ping-sweep wykonuje się w oddzielnych wątkach, UI pozostaje responsywne.
 - Dostosowano plan optymalizacji: profile CPU/I/O, przeniesienie blokujących operacji do wątków, batch‐owe aktualizacje GUI, rozważenie multiprocessing dla AI.
 - Uzupełniono `config/snort.rules` o reguły SSH, FTP, HTTP POST, SQLi, XSS, SMB, floody TCP/UDP, tunneling DNS, NXDOMAIN, cache poisoning, random subdomain i phantom domain.
 - Dodano regułę detekcji skanów Telnet (5 SYN/60s) i reguły monitorowania specyficznej IP poprzez BPF filtr.
 - Wyjaśniono obsługę `network_interface` i BPF filtrów w `config/config.yaml`.
 - Rozszerzono dokumentację TODO i Versioning zgodnie z semver.

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

## 🔄 Przepływ danych end-to-end
- CaptureModule (Scapy) wychwytuje pakiet → wysyła event `NEW_PACKET`.
- `SnortRulesPlugin` (plugin) w Orchestratorze przy każdym `NEW_PACKET` porównuje go z regułami i – jeśli pasuje – generuje `SNORT_ALERT`.
- Orchestrator przechwytuje `SNORT_ALERT` i dorzuca do kolejki eventów.
- `DetectionModule` w Orchestratorze odbiera `SNORT_ALERT`, dodaje SID do wewnętrznego zbioru `_snort_sids`.
- `FeaturesModule` (równolegle) dla każdego `NEW_PACKET` tworzy event `NEW_FEATURES` z podstawowymi cechami pakietu.
- `DetectionModule` po otrzymaniu `NEW_FEATURES` buduje wektor cech:
	- [packet_count, total_bytes, flow_id]
	- plus flagi 0/1 dla każdego SID z `_snort_sids`
	- czyści `_snort_sids`
- `DetectionModule` na podstawie tego wektora (IsolationForest lub NN) oblicza score/`ai_weight` i generuje `NEW_THREAT`.
- GUI (`qt_dashboard.py`) subskrybuje `DetectionModule` i przy wstawianiu wiersza do tabeli bierze `ai_weight` z metadanych.

Dzięki temu każdy pakiet, który wyzwolił przynajmniej jedną regułę Snort, ma wektor cech z odpowiednimi jedynkami, a model AI nadaje mu wyższą wartość `ai_weight`. W GUI zobaczysz tę wagę w kolumnie **Waga AI** i odpowiednie kolorowanie wiersza.

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

## Plany dotyczące czarnej listy IP
- Dodanie czarnej listy adresów IP: przy wykryciu adresu z czarnej listy automatyczny, natychmiastowy alert oraz wyróżnienie w SOC kolorem czarnym
```
