from core.interfaces import ModuleBase
from core.events import Event


class ScannerModule(ModuleBase):
    """
	Moduł do ręcznego skanowania sieci (light/stealth i full scan).
	Publikuje event SCAN_COMPLETED.
	"""

    def initialize(self, config):
        """Inicjalizuje moduł (np. parametry skanowania)."""
        self.config = config
        self._scan_requested = False
        self._scan_result = None
        self.ports = []

    def handle_event(self, event):
        """Obsługuje eventy (np. polecenia z UI)."""
        if event.type == 'SCAN_REQUEST':
            self._scan_requested = True
            # Save ports and subtype for scan
            data = getattr(event, 'data', {})
            self.ports = data.get('ports', [])
            self.subtype = data.get('subtype')

    def generate_event(self):
        """
		Generuje event SCAN_COMPLETED po zakończeniu skanowania (ping sweep na podsieci 192.168.0.0/24).
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
