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
Jasne 🙂  
Zaczynamy więc **spokojnie, od pierwszego pliku** – czyli od **📄 README.md**.  
Wkleisz go do repozytorium w katalogu głównym jako `README.md`.

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
