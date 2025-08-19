"""Capture Module - network sniffing based on Twisted reactor and PcapProtocol."""

from collections import deque
from core.events import Event
from core.interfaces import ModuleBase
from modules.event_buffer import EventBuffer
# integrate Twisted reactor with Qt and import PcapProtocol
try:
    from twisted.internet import qtreactor  # type: ignore
    qtreactor.install()
    from twisted.internet import reactor  # type: ignore
    from twisted.protocols.pcap import PcapProtocol  # type: ignore
except ImportError:
    # Twisted not available; define stubs
    reactor = None
    class PcapProtocol:
        """Stub PcapProtocol if Twisted is not installed."""
        pass
# integrate Twisted reactor with Qt
try:
    from twisted.internet import qtreactor  # type: ignore
    qtreactor.install()
except ImportError:
    pass

# import reactor (stub if unavailable)
try:
    from twisted.internet import reactor  # type: ignore
except ImportError:
    reactor = None

# import PcapProtocol (stub if unavailable)
try:
    from twisted.protocols.pcap import PcapProtocol  # type: ignore
except ImportError:
    class PcapProtocol:
        """Stub PcapProtocol if Twisted is not installed."""
        pass


class CaptureModule(ModuleBase, PcapProtocol):
    """Capture network packets via Twisted PcapProtocol."""

    def test_all_interfaces(self):
        """Not implemented for Twisted sniffer."""
        raise NotImplementedError("Interface testing not available in Twisted plugin")

    def set_interface(self, iface):
        """Update interface and restart sniffer."""
        self.config['network_interface'] = iface
        reactor.callLater(0, self._start_sniffer)

    def initialize(self, config):
        """Initialize sniffer plugin with configuration."""
        self.config = config
        self._iface = config.get('network_interface', None)
        self._filter = config.get('filter', '')
        # persistent buffer for incoming events
        self._buffer = EventBuffer()
        # Start packet capture: use Twisted on non-Windows if available and interface set, else use Scapy AsyncSniffer (all interfaces if none specified)
        import sys
        if reactor and not sys.platform.startswith('win') and self._iface:
            reactor.callWhenRunning(self._start_sniffer)
        else:
            try:
                from scapy.all import AsyncSniffer
                self._sniffer = AsyncSniffer(
                    prn=self._scapy_pkt_callback,
                    iface=self._iface or None,
                    filter=self._filter or None,
                    store=False
                )
                self._sniffer.start()
            except Exception:
                pass

    def _start_sniffer(self):
        """(Skeleton) Attach PcapProtocol to reactor for packet capture."""
        import sys
        # On Windows or if Twisted reactor unavailable, use AsyncSniffer
        if reactor is None or sys.platform.startswith('win'):
            if hasattr(self, '_sniffer'):
                try:
                    self._sniffer.start()
                except Exception:
                    pass
            return
        try:
            # Use Twisted PcapProtocol for non-Windows
            reactor.listenPcap(iface=self._iface, filter=self._filter,
                              protocolFactory=lambda: self)  # type: ignore
        except Exception:
            # Pcap support not configured or API differs
            pass
    def _scapy_pkt_callback(self, pkt):
        """Callback for Scapy AsyncSniffer to enqueue NEW_PACKET events."""
        try:
            from scapy.all import Ether, ARP, TCP, UDP, ICMP, raw
            data = {}
            # MAC layer
            if pkt.haslayer(Ether):
                eth = pkt[Ether]
                data['src_mac'] = eth.src
                data['dst_mac'] = eth.dst
            # ARP or IP
            if pkt.haslayer(ARP) or pkt.haslayer('IP'):
                if pkt.haslayer(ARP):
                    arp = pkt[ARP]
                    data['src_ip'] = arp.psrc
                    data['dst_ip'] = arp.pdst
                    data['protocol'] = 'arp'
                else:
                    ip = pkt['IP']
                    data['src_ip'] = ip.src
                    data['dst_ip'] = ip.dst
                    # transport
                    if pkt.haslayer(TCP):
                        tcp = pkt[TCP]
                        data.update({'protocol': 'tcp', 'src_port': tcp.sport, 'dst_port': tcp.dport, 'tcp_flags': str(tcp.flags)})
                    elif pkt.haslayer(UDP):
                        udp = pkt[UDP]
                        data.update({'protocol': 'udp', 'src_port': udp.sport, 'dst_port': udp.dport})
                    elif pkt.haslayer(ICMP):
                        ic = pkt[ICMP]
                        data.update({'protocol': 'icmp', 'icmp_type': ic.type})
                    else:
                        data['protocol'] = ip.proto if hasattr(ip, 'proto') else 'ip'
            # raw bytes
            data['raw_bytes'] = bytes(raw(pkt))
            ev = Event('NEW_PACKET', data)
            self._buffer.insert_event(ev)
        except Exception:
            pass

    def packetReceived(self, pcap_header, pcap_packet):  # PcapProtocol callback
        """Called by Twisted when a raw packet arrives; enqueue as NEW_PACKET event."""
        try:
            import dpkt  # type: ignore
            import socket
            # Decode Ethernet frame
            eth = dpkt.ethernet.Ethernet(pcap_packet)
            # MAC addresses
            src_mac = ":".join(f"%02x" % b for b in eth.src)
            dst_mac = ":".join(f"%02x" % b for b in eth.dst)
            data = {
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'raw_bytes': pcap_packet
            }
            # IP layer
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                src_ip = socket.inet_ntoa(ip.src)
                dst_ip = socket.inet_ntoa(ip.dst)
                data.update({'src_ip': src_ip, 'dst_ip': dst_ip, 'payload_size': len(ip)})
                # Transport layer
                trans = ip.data
                if isinstance(trans, dpkt.tcp.TCP):
                    data.update({
                        'protocol': 'tcp',
                        'src_port': trans.sport,
                        'dst_port': trans.dport,
                        'tcp_flags': trans.flags
                    })
                elif isinstance(trans, dpkt.udp.UDP):
                    data.update({
                        'protocol': 'udp',
                        'src_port': trans.sport,
                        'dst_port': trans.dport
                    })
                elif isinstance(trans, dpkt.icmp.ICMP):
                    data.update({
                        'protocol': 'icmp',
                        'icmp_type': trans.type
                    })
                else:
                    data['protocol'] = str(ip.p)
            else:
                data['protocol'] = 'non-ip'
            ev = Event('NEW_PACKET', data)
            self._buffer.insert_event(ev)
        except Exception:
            # Fallback raw event
            ev = Event('NEW_PACKET', {'raw_bytes': pcap_packet})
            self._buffer.insert_event(ev)

    def set_filter(self, bpf):
        """Update BPF filter and restart sniffer."""
        self.config['filter'] = bpf
        reactor.callLater(0, self._start_sniffer)

    def handle_event(self, event):
        """This module only generates events; does not handle incoming events."""
        return None

    def generate_event(self):
        """Return next pending NEW_PACKET event, if any."""
        # retrieve next event from persistent buffer
        return self._buffer.get_event()
    # Alias methods for UI compatibility
    _start_sniffing = _start_sniffer
    start_sniffing = _start_sniffer
