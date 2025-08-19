"""Scanner Module - perform network scans on demand and report results.

This module executes ping sweeps and port scans on the configured subnet,
and emits SCAN_COMPLETED events with discovery details."""
from core.interfaces import ModuleBase
from core.events import Event


class ScannerModule(ModuleBase):
    """CLI-driven network scanner module for active scanning tasks.

    Initiates ping sweeps and TCP port scans based on UI commands,
    then emits SCAN_COMPLETED events with scan results.
    """

    def initialize(self, config):
        """Initialize scanner module with configuration settings.

        Parameters
        ----------
        config : dict
            Configuration including default scan parameters and network settings.
        """
        self.config = config
        self._scan_requested = False
        self._scan_result = None
        self.ports = []

    def handle_event(self, event):
        """Handle SCAN_REQUEST events to trigger a network scan.

        Parameters
        ----------
        event : Event
            Should have type 'SCAN_REQUEST' and optional data with 'ports' and 'subtype'.
        """
        if event.type == 'SCAN_REQUEST':
            self._scan_requested = True
            # Save ports and subtype for scan
            data = getattr(event, 'data', {})
            self.ports = data.get('ports', [])
            self.subtype = data.get('subtype')

    def generate_event(self):
        """Perform the network scan and generate SCAN_COMPLETED event with results.

        Executes a ping sweep across the /24 subnet, port scans for requested ports,
        and ARP lookups for MAC addresses.

        Returns
        -------
        Event or None
            SCAN_COMPLETED event containing 'result' list, or None if no scan requested.
        """
        if self._scan_requested:
            self._scan_requested = False
            import platform, subprocess, socket
            # Ping sweep to discover hosts
            base = '192.168.0.'
            discovered = []
            for i in range(1, 255):
                ip = f'{base}{i}'
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                try:
                    result = subprocess.run(['ping', param, '1', ip],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=1)
                    if b'TTL=' in result.stdout.lower():
                        discovered.append(ip)
                except Exception:
                    continue
            results = []
            # For each host, scan selected ports and get MAC
            for ip in discovered:
                open_ports = []
                for port in self.ports:
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.5)
                        if sock.connect_ex((ip, port)) == 0:
                            open_ports.append(port)
                        sock.close()
                    except Exception:
                        continue
                # Try to get MAC address via ARP table
                mac = ''
                try:
                    arp = subprocess.run(['arp', '-a', ip],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        timeout=1)
                    text = arp.stdout.decode(errors='ignore')
                    for line in text.splitlines():
                        if ip in line:
                            parts = line.split()
                            if len(parts) >= 2:
                                mac = parts[1]
                                break
                except Exception:
                    pass
                results.append({'ip': ip, 'ports': open_ports, 'mac': mac})
            # Store and emit completed event
            self._scan_result = results
            return Event('SCAN_COMPLETED', {'result': results})
        return None
