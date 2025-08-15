from core.interfaces import ModuleBase
from core.events import Event
from scapy.all import AsyncSniffer, raw, sniff


class CaptureModule(ModuleBase):
    """
Attributes
----------

Methods
-------

"""

    def test_all_interfaces(self):
        """Testuje sniffing na wszystkich interfejsach i loguje, czy pojawiają się pakiety."""
        from modules.netif import list_interfaces
        from scapy.all import sniff
        print(
            '[CaptureModule] Testowanie sniffingu na wszystkich interfejsach...'
            )
        results = {}
        for iface in list_interfaces():
            print(f'[CaptureModule] Test interfejsu: {iface}')
            packets = []
            try:
                sniff(prn=lambda pkt: packets.append(pkt), iface=iface,
                    timeout=2, count=1, store=0)
                results[iface] = len(packets)
                if packets:
                    print(f'[CaptureModule] Interfejs {iface}: wykryto pakiet!'
                        )
                else:
                    print(f'[CaptureModule] Interfejs {iface}: brak pakietów.')
            except Exception as e:
                print(f'[CaptureModule] Błąd na interfejsie {iface}: {e}')
                results[iface] = f'Błąd: {e}'
        print('[CaptureModule] Wyniki testu interfejsów:')
        for iface, res in results.items():
            print(f'  {iface}: {res}')
        return results

    def set_interface(self, iface):
        """Ustawia interfejs i restartuje sniffing."""
        self.config['network_interface'] = iface
        self._start_sniffing()

    def initialize(self, config):
        """Inicjalizuje moduł z konfiguracją (np. interfejs sieciowy, filtr)."""
        self.config = config
        self._last_packet = None
        self._sniffer = None

    def _start_sniffing(self):
        """Startuje lub restartuje Sniffer z aktualnym filtrem i interfejsem"""
        if hasattr(self, '_sniffer') and self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass

        def pkt_callback(pkt):
            try:
                print(
                    f'[CaptureModule][DEBUG] Otrzymałem pakiet: {pkt.summary()}'
                    )
                print(
                    f'[CaptureModule][DEBUG] Typ warstwy głównej: {pkt.__class__.__name__}'
                    )
            except Exception:
                pass
            try:
                if pkt.haslayer('IP'):
                    ip = pkt['IP']
                    event = {'src_ip': ip.src, 'dst_ip': ip.dst, 'protocol':
                        pkt.proto if hasattr(pkt, 'proto') else 'N/A',
                        'payload_size': len(pkt), 'raw_bytes': bytes(raw(pkt))}
                    self._last_packet = event
            except Exception as e:
                print(f'[CaptureModule] Błąd przy analizie pakietu: {e}')
        iface = self.config.get('network_interface', None)
        flt = self.config.get('filter', '')
        print(
            f"[CaptureModule] Starting AsyncSniffer on iface={iface}, filter='{flt}'"
            )
        kwargs = {'prn': pkt_callback, 'iface': iface, 'store': False}
        if flt and flt.strip().lower() not in ('', 'nie filtruj', 'none'):
            kwargs['filter'] = flt
        self._sniffer = AsyncSniffer(**kwargs)
        self._sniffer.daemon = True
        self._sniffer.start()

    def stop_sniffing(self):
        """Zatrzymuje aktywny sniffer"""
        if hasattr(self, '_sniffer') and self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass

    def set_filter(self, bpf):
        """Ustawia nowy BPF-filter i resetuje sniffer"""
        self.config['filter'] = bpf
        self._start_sniffing()

    def handle_event(self, event):
        """Nie obsługuje eventów (sniffing jest pasywny)."""
        pass

    def generate_event(self):
        """
		Zwraca event NEW_PACKET na podstawie przechwyconego pakietu przez scapy.
		"""
        print(
            f'[CaptureModule] generate_event: self._last_packet={self._last_packet}'
            )
        if self._last_packet:
            pkt = self._last_packet
            print(f'[CaptureModule] generate_event: zwracam event z pkt={pkt}')
            self._last_packet = None
            return Event('NEW_PACKET', pkt)
        return None
