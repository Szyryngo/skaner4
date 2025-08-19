"""
TwistedSnifferPlugin - a plugin for network sniffing using Twisted reactor and PcapProtocol.

This plugin replaces Scapy AsyncSniffer with an integrated Twisted-based sniffer.
It uses qtreactor to integrate Twisted reactor into the Qt event loop.
"""
from collections import deque
from core.interfaces import ModuleBase
from core.events import Event

# Install qtreactor integration for Qt (must happen before QApplication is created)
try:
    from twisted.internet import qtreactor
    qtreactor.install()
except Exception:
    # Already installed or unavailable
    pass

from twisted.internet import reactor
from twisted.protocols.pcap import PcapProtocol

class TwistedSnifferPlugin(ModuleBase, PcapProtocol):
    """Plugin capturing raw packets via Twisted PcapProtocol."""
    def initialize(self, config):
        """
        Initialize the sniffer plugin.

        config keys:
          - network_interface: (str) interface name or None for default
          - filter: (str) BPF filter expression
        """
        self.config = config
        self._iface = config.get('network_interface', None)
        self._filter = config.get('filter', '')
        self._event_queue = deque()

        # Bind protocol callbacks
        # PcapProtocol provides connectionMade/packetReceived handlers
        # We override packetReceived below

        # Start capturing when reactor is running
        reactor.callWhenRunning(self._start_sniffer)

    def _start_sniffer(self):
        """
        Hook this protocol into the reactor to begin packet capture.
        Actual listening method may vary; e.g., reactor.listenPcap or adopt socket FD.
        """
        # TODO: attach this protocol to pcap source
        # Example (pseudo-code):
        # reactor.listenPcap(iface=self._iface, filter=self._filter, protocolFactory=lambda: self)
        pass

    def packetReceived(self, pcap_header, pcap_packet):  # PcapProtocol callback
        """Called by Twisted when a raw packet arrives."""
        # TODO: parse raw Ethernet/IP/TCP/UDP/ICMP headers
        # Example placeholder:
        data = {}  # build dict with src_ip, dst_ip, src_mac, dst_mac, protocol, etc.
        ev = Event('NEW_PACKET', data)
        # enqueue for processing
        self._event_queue.append(ev)

    def handle_event(self, event):
        """Not used; this plugin only generates events."""
        return None

    def generate_event(self):
        """Return next pending NEW_PACKET event if available."""
        try:
            return self._event_queue.popleft()
        except IndexError:
            return None

    def shutdown(self):
        """Cleanly stop packet capture and reactor hooks if needed."""
        # TODO: stop pcap capture and cleanup
        return None
