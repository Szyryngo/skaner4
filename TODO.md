- [x] Wszystkie zakładki korzystają z layoutów .ui (Qt Designer), logika w Pythonie
- [x] Test interfejsów loguje tylko interfejs przechwytujący pakiety do dolnej belki logów
- [x] Dokumentacja uzupełniona (qt_dashboard.py.docstring.txt)
- [x] Dashboard PyQt5: oddzielne przyciski, wybór interfejsu, dolna belka logów, panel szczegółów, pole filtra BPF
- [x] Przechwytywanie pakietów, dynamiczna tabela, panel szczegółów, HEX/ASCII (po kliknięciu wiersza wyświetla się HEX/ASCII)
- [x] Integracja orchestratora z GUI, cykliczne pobieranie pakietów (QTimer)
- [x] AI: każdemu pakietowi przypisywana jest waga (ai_weight), kolorowanie wierszy
- [x] Wyświetlanie protokołu jako nazwa (TCP/UDP/ICMP)
- [x] Nowe pakiety pojawiają się na górze tabeli
- [x] Naprawa wcięć, usunięcie powielonych konstruktorów, stabilność dashboardu
- [x] Automatyczne ustawianie rozmiaru okna (config.yaml lub domyślnie)
- [x] Uzupełniono dokumentację qtui/qt_dashboard.py (patrz qt_dashboard.py.docstring.txt)

## Najbliższe zadania
- [x] Dodano panele Raw Events i AI Scores w zakładce SOC
- [x] Uzupełniono obsługę wypełniania `raw_table` i `ai_table` w `soc_tab.py`
- [ ] Priorytet: praca nad optymalizacją i wydajnością programu
- [ ] Dodanie testów jednostkowych/integracyjnych dla wielowątkowości i synchroniczności
- [ ] Monitoring metryk CPU/RAM dla poszczególnych modułów w UI
- [ ] Konfiguracja CI z benchmarkami wydajności
- [ ] Dalsze optymalizacje: cache ARP, ponowne użycie socketów, minimalizacja syscalli
- [x] Priorytet: praca nad optymalizacją i wydajnością programu
- [x] Profilowanie CPU i I/O (cProfile, py-spy)
- [x] Przechwytywanie pakietów w QThread/QThreadPool zamiast wątku głównym
- [x] Równoległe skanowanie sieci za pomocą QRunnable/QThreadPool z ograniczonymi wątkami
- [x] Przeniesienie AI-pipeline do ThreadPoolExecutor
- [x] Batch-owe aktualizacje GUI QTableWidget (wyłączanie aktualizacji podczas wstawiania)
- [ ] Dodanie testów jednostkowych/integracyjnych dla wielowątkowości i synchroniczności
- [ ] Monitoring metryk CPU/RAM dla poszczególnych modułów w UI
- [ ] Konfiguracja CI z benchmarkami wydajności
- [ ] Dalsze optymalizacje: cache ARP, ponowne użycie socketów, minimalizacja syscalli
- [x] Dodano zakładkę `InfoTab` z informacjami o podzespołach komputera (CPU, RAM, GPU, BIOS, płyta główna, dyski, karty sieciowe)
- [x] Dodano pasek narzędzi z metrykami systemu (CPU%, RAM%, liczba wątków i rdzeni) odświeżany co sekundę
- [x] Ustalono wersję aplikacji na **1.5.10** i zaktualizowano `VERSIONING.md` z opisem nowych funkcji
 - [x] Pełna obsługa składni Snort: header, content (offset/depth/within/distance/nocase), pcre, itype, flags
 - [x] Obsługa threshold, dsize, length, byte_test, flow, flowbits
 - [x] Parsowanie opcji http_* i dns.* (http_method, http_uri, http_client_body, dns_query, dns_query_type)
 - [x] Obsługa uricontent, rawbytes, isdataat, byte_extract, byte_jump
 - [x] Obsługa fragbits, fragoffset, ttl, tos, ip_flags
 - [x] Implementacja rate_filter, metadata, classtype, priority, reference
 - [x] Dodano testy jednostkowe Snort z PCAP/Scapy
 - [x] Integracja SNORT_ALERT z GUI (logi w dashboard, zakładka SOC)
 - [x] Optymalizacja indeksowania reguł Snort (triple-key index)
  
  <!-- dotychczasowe zadania -->
  - [x] Usprawniono przepływ eventów AI (każdy pakiet → cechy → AI → waga)  <!-- zaimplementowano pipeline w Orchestrator: CaptureModule → FeaturesModule → DetectionModule, sygnały Qt -->
- [x] Rozbudować panel szczegółów o dekodowanie warstw protokołu  <!-- zaimplementowano: wyświetlanie warstw Scapy oraz tłumaczenie numerów protokołów z config/protocols.yaml -->
- [x] Umożliwiono eksport przechwyconych pakietów do pliku (CSV, PCAP)  <!-- zaimplementowano przyciski Eksport CSV/PCAP, domyślne nazwy z timestampem (YYYYMMDD_HHMMSS) -->
- [ ] Dodać testy jednostkowe dla orchestratora i GUI
- [ ] Plugin: integracja z pyshark jako alternatywny backend sniffingu
- [ ] Plugin: automatyczne powiadomienia (np. email, webhook)
- [ ] Uprościć konfigurację filtrów BPF (UX)
- [ ] Dodać testy jednostkowe dla zakładki Neural Net (NNLayout)
- [ ] Rozszerzyć wielowątkowość programu: przenieść wszystkie blokujące operacje do workerów lub QThreadPool
- [ ] Zoptymalizować wydajność skanowania i ogólną responsywność UI
 - [x] Rozbić `qtui/qt_dashboard.py` na:
     - `qtui/main_window.py` (klasa MainWindow)
     - `qtui/dashboard_tab.py`, `devices_tab.py`, `scanner_tab.py`, `nn_tab.py`, `config_tab.py` (oddzielne klasy zakładek)
       (układ i logika każdej zakładki w osobnym pliku)
- [x] Uzupełnić dokumentację projektu o instrukcje instalacji TensorFlow i obsługi długich ścieżek na Windows  <!-- zaimplementowano w requirements.txt -->
- [ ] Rozbudować analyze_nn_model.py o generowanie raportu metryk trenowanego modelu
- [x] Dodać walidację i obsługę błędów dla przycisków Trenuj/Oceń w NNLayout
- [ ] Dodać internacjonalizację (i18n) komunikatów w zakładce NNLayout
- [x] Uzupełnić dokumentację NNLayout o opis funkcji treningu, oceny sieci i wyświetlania wyników w tabeli HTML
 - [x] Wyświetlanie wyników ewaluacji modelu w profesjonalnej tabeli HTML

# Filtrowanie pakietów
- [x] Dodano przycisk `Ustaw filtr` i integrację BPF-filtra z CaptureModule.
- [x] Filtrowanie BPF działa w locie – restartuje przechwytywanie z nowym filtrem.
         
## Pomysły na przyszłość
- [ ] Wizualizacja ruchu sieciowego (wykresy, heatmapy)
- [ ] Wsparcie dla IPv6, VLAN, tuneli
- [ ] Rozbudowa systemu pluginów (np. pluginy do analizy malware)
- [ ] Publikować event `SCAN_COMPLETED`.
- [ ] Dodanie czarnej listy adresów IP: przy wykryciu wpisu na czarnej liście natychmiastowy alert i wyróżnienie w SOC kolorem czarnym

---

### modules/devices.py
- [x] Nasłuch pakietów ARP i IP.
- [x] Wykrywać nowe urządzenia w sieci i aktualizować listę aktywnych hostów.
- [x] Publikować event `DEVICE_DETECTED` dla nowych hostów.
- [x] Oznaczać hosty nieaktywne po określonym czasie.

---

### modules/optimizer.py
- [ ] Pobierać dane o CPU, RAM, OS (psutil, platform).
- [ ] Dobierać tryb pracy:
  - Low resource = mniejsze bufory, prostsze modele.
  - High performance = pełne AI i analizy.
- [ ] Publikować event `CONFIG_UPDATED`.

---



### qtui/qt_dashboard.py
- [x] GUI PyQt5 z zakładkami:
  - Dashboard – lista alertów (NEW_THREAT).
  - Live Devices – lista hostów z DEVICE_DETECTED.
  - Network Scanner – przyciski do uruchamiania light/full scan + wyniki SCAN_COMPLETED.
  - Configuration – ustawienia i tryb pracy z CONFIG_UPDATED.
- [x] Dynamiczna aktualizacja widoków na podstawie eventów backendu.
- [x] Obsługa akcji użytkownika (np. uruchom skanowanie, wybór interfejsu).
- [x] Refaktoryzacja dashboardu: usunięcie powielonych fragmentów, poprawa wcięć, czytelny layout.
- [x] Dodanie dolnej belki logów (status bar) z informacjami o działaniach użytkownika.
- [x] Przycisk "Pauza" i "Stop" poprawnie zatrzymują cykliczne pobieranie pakietów.
- [x] Pakiety wyświetlane są tylko w GUI, nie pojawiają się już w konsoli.
- [x] QTimer cyklicznie pobiera pakiety do tabeli, gdy sniffing jest aktywny.
- [x] Czytelny wybór interfejsu sieciowego (QComboBox, testowanie i użycie wybranego interfejsu).

---

### plugins/example_plugin.py
- [x] Przykładowa implementacja reagująca na NEW_THREAT (deprecated)
- [x] Licznik powtarzających się incydentów z tego samego IP (wbudowane w SOC)
- [x] Po przekroczeniu progu (np. 3) publikować event BLOCK_IP (możliwość email)

---

### tests/
- [ ] Testy jednostkowe każdego modułu (mock eventów).
- [ ] Test integracyjny: capture → features → detection → threat → ui.

### Zakładka Reguły SNORT (snort_rules_tab.py)
- [x] Tabela z regułami SNORT: kolumny ID, Opis, Reguła, Stan włączony/wyłączony
- [x] Checkboxy do włączania/dezaktywowania reguł
- [x] Wyświetlanie surowych reguł i tooltipy
