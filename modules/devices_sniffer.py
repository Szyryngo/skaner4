"""Devices Sniffer Module - sniff ARP and IP packets in a background thread to detect devices.

Provides a threaded interface using scapy.sniff to capture ARP/IP packets and emit DEVICE_DETECTED events."""
from scapy.all import sniff, ARP, IP
from core.events import Event
import threading


class DevicesSniffer:
    """Threaded network sniffer for device discovery.

    Captures ARP and IP packets on a specified interface and invokes a callback
    with DEVICE_DETECTED events for each host seen.
    """

    def __init__(self, iface=None, event_callback=None):
        """Initialize the DevicesSniffer.

        Parameters
        ----------
        iface : str or None
            Network interface to sniff on (None for default).
        event_callback : callable or None
            Function to call with Event('DEVICE_DETECTED', data) on packet capture.
        """
        self.iface = iface
        self.event_callback = event_callback
        self._thread = None
        self._stop = threading.Event()

    def start(self):
        """Start the background sniffing thread.

        Begins packet capture loop in a daemon thread until stop() is called.
        """
        self._stop.clear()
        self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the background sniffing thread.

        Signals the thread to stop and waits for it to join (timeout 2 seconds).
        """
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _sniff_loop(self):
        """Internal loop method for scapy.sniff.

        Runs sniff on the interface with ARP and IP filters, calling _handle_packet on each packet,
        and stops when stop event is set.
        """
        sniff(iface=self.iface, filter='arp or ip', prn=self._handle_packet,
            store=0, stop_filter=lambda x: self._stop.is_set())

    def _handle_packet(self, pkt):
        """Process a captured packet and emit a DEVICE_DETECTED event.

        Detects ARP and IP packets, builds event data dict, and calls the event_callback if set.

        Parameters
        ----------
        pkt : scapy.Packet
            Captured packet object to inspect.
        """
        if ARP in pkt:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            event = Event('DEVICE_DETECTED', {'ip': ip, 'mac': mac, 'proto':
                'ARP'})
            if self.event_callback:
                self.event_callback(event)
        elif IP in pkt:
            ip = pkt[IP].src
            event = Event('DEVICE_DETECTED', {'ip': ip, 'proto': 'IP'})
            if self.event_callback:
                self.event_callback(event)
