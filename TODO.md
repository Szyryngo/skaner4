## 📄 TODO.md
```markdown
# TODO – AI Network Packet Analyzer Pro

Lista szczegółowych kroków implementacyjnych dla poszczególnych modułów.  
Każdy punkt jest tak zapisany, aby można było na jego podstawie łatwo poprosić GitHub Copilota o napisanie kodu.

---

### core/orchestrator.py
- [ ] Zaimplementować główną pętlę eventów:
  - Iteruj po module.generate_event()
  - Wysyłaj eventy do wszystkich modułów przez handle_event()
- [ ] Obsłużyć kolejkę eventów.
- [ ] Obsłużyć try/catch dla odporności na awarie modułów.
- [ ] Rozważyć implementację wersji asynchronicznej (asyncio).

---

### modules/capture.py
- [ ] Wczytać interfejs i filtr z config.yaml.
- [ ] Uruchomić sniffing pakietów:
  - Za pomocą scapy.sniff() lub pyshark.LiveCapture().
  - Tryb promiscuous.
- [ ] Wyodrębniać dane:
  - src_ip, dst_ip, src_port, dst_port, protocol, payload_size, timestamp.
- [ ] Publikować event `NEW_PACKET`.

---

### modules/features.py
- [ ] Obsługiwać event `NEW_PACKET`.
- [ ] Grupować pakiety w przepływy (flow): src_ip, dst_ip, src_port, dst_port, protocol.
- [ ] Liczyć cechy:
  - liczba pakietów,
  - sumaryczny rozmiar bajtów,
  - czas trwania przepływu,
  - bitrate.
- [ ] Publikować event `NEW_FEATURES`.

---

### modules/detection.py
- [ ] Wczytać modele AI z katalogu `data/models/`.
- [ ] Obsługiwać event `NEW_FEATURES`.
- [ ] Wykrywać anomalie (Isolation Forest lub Autoencoder).
- [ ] Klasyfikować znane zagrożenia (model nadzorowany).
- [ ] Publikować event `NEW_THREAT` z:
  - ip, typ zagrożenia, confidence, details.

---

### modules/scanner.py
- [ ] Obsługiwać polecenie z UI: "Light scan" lub "Full scan".
- [ ] Light scan:
  - Ping sweep (podsiec z configa).
  - ARP sniff.
- [ ] Full scan:
  - Skan portów (socket lub python-nmap).
  - Identyfikacja systemu operacyjnego.
- [ ] Publikować event `SCAN_COMPLETED`.

---

### modules/devices.py
- [ ] Nasłuch pakietów ARP i IP.
- [ ] Wykrywać nowe urządzenia w sieci i aktualizować listę aktywnych hostów.
- [ ] Publikować event `DEVICE_DETECTED` dla nowych hostów.
- [ ] Oznaczać hosty nieaktywne po określonym czasie.

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
- [ ] Przykładowa implementacja reagująca na NEW_THREAT.
- [ ] Licznik powtarzających się incydentów z tego samego IP.
- [ ] Po przekroczeniu progu (np. 3) publikować event BLOCK_IP.

---

### tests/
- [ ] Testy jednostkowe każdego modułu (mock eventów).
- [ ] Test integracyjny: capture → features → detection → threat → ui.
```
