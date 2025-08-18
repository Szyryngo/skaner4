from core.interfaces import ModuleBase
from core.events import Event
from scapy.all import AsyncSniffer, raw, sniff, Ether, ARP
from scapy.layers.inet import TCP, UDP, ICMP


class CaptureModule(ModuleBase):
    """
Attributes
----------

Methods
-------

"""

    def test_all_interfaces(self):
        """Testuje sniffing na wszystkich interfejsach (diagnostyka)."""
        from modules.netif import list_interfaces
        from scapy.all import sniff
        # Debug logging suppressed
        results = {}
        for iface in list_interfaces():
            packets = []
            try:
                sniff(prn=lambda pkt: packets.append(pkt), iface=iface,
                      timeout=2, count=1, store=0)
                results[iface] = len(packets)
            except Exception:
                results[iface] = 'Error'
        # Return dict of interface: packet count or 'Error'
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
        # Stop existing sniffer if running
        if hasattr(self, '_sniffer') and self._sniffer:
            try:
                self._sniffer.stop()
            except Exception:
                pass

        # Callback for each captured packet
        def pkt_callback(pkt):
            try:
                if pkt.haslayer('IP') or pkt.haslayer(ARP):
                    # przygotuj domyślne transport layer info
                    src_port = None
                    dst_port = None
                    tcp_flags = ''
                    icmp_type = None
                    if pkt.haslayer('IP'):
                        ip_layer = pkt['IP']
                        dst_ip = ip_layer.dst
                        src_mac = pkt[Ether].src if pkt.haslayer(Ether) else None
                        dst_mac = pkt[Ether].dst if pkt.haslayer(Ether) else None
                        # detekcja warstwy transport
                        if pkt.haslayer(TCP):
                            tcp = pkt[TCP]
                            src_port = tcp.sport
                            dst_port = tcp.dport
                            tcp_flags = str(tcp.flags)
                            protocol = 'tcp'
                        elif pkt.haslayer(UDP):
                            udp = pkt[UDP]
                            src_port = udp.sport
                            dst_port = udp.dport
                            protocol = 'udp'
                        elif pkt.haslayer(ICMP):
                            icmp = pkt[ICMP]
                            icmp_type = icmp.type
                            protocol = 'icmp'
                        else:
                            protocol = pkt.proto if hasattr(pkt, 'proto') else 'N/A'
                    else:
                        arp = pkt['ARP']
                        ip_layer = arp
                        dst_ip = arp.pdst
                        src_mac = arp.hwsrc
                        dst_mac = arp.hwdst if hasattr(arp, 'hwdst') else None
                        protocol = 'ARP'
                    # zbuduj event z pełnymi danymi
                    event = {
                        'src_ip': ip_layer.src,
                        'dst_ip': dst_ip,
                        'src_mac': src_mac,
                        'dst_mac': dst_mac,
                        'protocol': protocol,
                        'src_port': src_port,
                        'dst_port': dst_port,
                        'tcp_flags': tcp_flags,
                        'icmp_type': icmp_type,
                        'payload_size': len(pkt),
                        'raw_bytes': bytes(raw(pkt))
                    }
                    # debug: show captured event protocol and ICMP type
                    print(f"[DEBUG CAPTURE] built event: protocol={protocol}, icmp_type={icmp_type}, src={ip_layer.src}, dst={dst_ip}")
                    self._last_packet = event
            except Exception:
                pass

        # Configure and start AsyncSniffer
        iface = self.config.get('network_interface', None)
        flt = self.config.get('filter', '')
        kwargs = {
            'prn': pkt_callback,
            'iface': iface,
            'store': False
        }

        if flt and flt.strip().lower() not in ('', 'nie filtruj', 'none'):
            kwargs['filter'] = flt

        self._sniffer = AsyncSniffer(**kwargs)
        try:
            self._sniffer.daemon = False
        except Exception:
            pass

        self._sniffer.start()

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
        # Debug prints disabled to avoid buffered stdout issues
        if self._last_packet:
            pkt = self._last_packet
            self._last_packet = None
            return Event('NEW_PACKET', pkt)
        return None
