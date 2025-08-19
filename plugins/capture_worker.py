"""
Worker thread for packet capture, pushes Event objects into a Queue.
"""
import sys
import time
import queue
from PyQt5.QtCore import QThread
from core.events import Event

def default_parser(pkt):
    """Convert scapy packet into Event data."""
    try:
        from scapy.all import Ether, ARP, raw, TCP, UDP, ICMP
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
        data['raw_bytes'] = bytes(raw(pkt))
        return Event('NEW_PACKET', data)
    except Exception:
        return None

class CaptureWorker(QThread):
    """QThread-based capture worker using Scapy AsyncSniffer."""
    def __init__(self, config: dict, out_queue: queue.Queue):
        super().__init__()
        self.config = config
        self.out_queue = out_queue
        self._running = False

    def run(self):
        """Thread entry point: start sniffer and loop until stopped."""
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            return
        iface = self.config.get('network_interface')
        flt = self.config.get('filter') or None
        self._running = True
        self.sniffer = AsyncSniffer(prn=self._packet_callback, iface=iface, filter=flt, store=False)
        try:
            self.sniffer.start()
        except Exception:
            pass
        # Keep thread alive
        while self._running:
            time.sleep(0.5)
        try:
            self.sniffer.stop()
        except Exception:
            pass

    def _packet_callback(self, pkt):
        ev = default_parser(pkt)
        if ev:
            try:
                self.out_queue.put_nowait(ev)
            except queue.Full:
                pass

    def stop(self):
        """Stop the capture loop and exit thread."""
        self._running = False
