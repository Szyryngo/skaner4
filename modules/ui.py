from core.interfaces import ModuleBase
from core.events import Event
from flask import Flask, request, redirect, url_for
import threading
import psutil
import yaml


class UIModule(ModuleBase):
    """
    Moduł interfejsu webowego (Flask dashboard).
    """

    def _get_real_interfaces(self):
        ignore_keywords = ['virtual', 'vmware', 'loopback', 'bluetooth',
                           'tunnel', 'pseudo', 'miniport', 'tap', 'vpn', 'docker',
                           'hyper-v', 'npf']
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            lname = name.lower()
            if any(kw in lname for kw in ignore_keywords):
                continue
            if not addrs:
                continue
            interfaces.append(name)
        return interfaces
    """
	Moduł interfejsu webowego (Flask dashboard).
	"""

    def initialize(self, config):
        """Inicjalizuje moduł UI (konfiguracja Flask)."""
        self.config = config
        self.app = Flask(__name__)
        self._last_threat = None
        self._devices = []
        self._scan_results = []
        self._scan_request_flag = False
        self._setup_routes()
        self.thread = threading.Thread(target=self._run_flask, daemon=True)
        self.thread.start()

    def _setup_routes(self):

        @self.app.route('/config', methods=['GET', 'POST'])
        def config():
            msg = ''
            if request.method == 'POST':
                iface = request.form.get('iface')
                if iface:
                    with open('config/config.yaml', 'r', encoding='utf-8') as f:
                        cfg = yaml.safe_load(f)
                    cfg['network_interface'] = iface
                    with open('config/config.yaml', 'w', encoding='utf-8') as f:
                        yaml.safe_dump(cfg, f, allow_unicode=True)
                    msg = f"<p style='color:green;'>Wybrano interfejs: <b>{iface}</b></p>"
            interfaces = self._get_real_interfaces()
            html = '<h2>Configuration</h2>' + msg
            html += "<form method='post'><label for='iface'>Wybierz interfejs sieciowy:</label>"
            html += "<select name='iface' id='iface'>"
            for iface in interfaces:
                html += f"<option value='{iface}'>{iface}</option>"
            html += "</select> <button type='submit'>Zapisz</button></form>"
            html += '<p>Obecny interfejs: <b>' + str(self.config.get('network_interface', 'brak')) + '</b></p>'
            return self._render_nav('config', html)

        @self.app.route('/')
        @self.app.route('/dashboard', methods=['GET'])
        def dashboard():
            html = '<h2>Dashboard</h2>'
            if self._last_threat:
                html += f'<h3>Ostatni wykryty NEW_THREAT:</h3><pre>{self._last_threat}</pre>'
            else:
                html += '<p>Brak wykrytych zagrożeń.</p>'
            return self._render_nav('dashboard', html)

        @self.app.route('/dashboard')
        def dashboard():
            html = '<h2>Dashboard</h2>'
            if self._last_threat:
                html += (
                    f'<h3>Ostatni wykryty NEW_THREAT:</h3><pre>{self._last_threat}</pre>'
                    )
            else:
                html += '<p>Brak wykrytych zagrożeń.</p>'
            return self._render_nav('dashboard', html)

        @self.app.route('/devices')
        def devices():
            html = '<h2>Live Devices</h2>'
            if self._devices:
                html += '<ul>' + ''.join(f'<li>{d}</li>' for d in self._devices
                    ) + '</ul>'
            else:
                html += '<p>Brak wykrytych urządzeń.</p>'
            return self._render_nav('devices', html)

        @self.app.route('/devices', methods=['GET'])
        def devices():
            html = '<h2>Live Devices</h2>'
            if self._devices:
                html += '<ul>' + ''.join(f'<li>{d}</li>' for d in self._devices) + '</ul>'
            else:
                html += '<p>Brak wykrytych urządzeń.</p>'
            return self._render_nav('devices', html)

        @self.app.route('/scanner', methods=['GET'])
        def scanner():
            html = (
                "<h2>Network Scanner</h2>"
                "<form method='post' action='/scanner/scan'>"
                "<button type='submit'>Uruchom skanowanie</button>"
                "</form>"
            )
            if self._scan_results:
                html += '<ul>' + ''.join(f'<li>{r}</li>' for r in self._scan_results) + '</ul>'
            else:
                html += '<p>Brak wyników skanowania.</p>'
            return self._render_nav('scanner', html)

        @self.app.route('/scanner/scan', methods=['POST'])
        def scanner_scan():
            self._scan_request_flag = True
            return redirect(url_for('scanner'))

    def generate_event(self):
        if self._scan_request_flag:
            self._scan_request_flag = False
            return Event('SCAN_REQUEST', {})
        return None

    def _render_nav(self, active, content=None):
        nav = f"""
		<nav style='margin-bottom:20px;'>
			<a href='/dashboard' style='margin-right:10px;{'font-weight:bold;' if active == 'dashboard' else ''}'>Dashboard</a>
			<a href='/devices' style='margin-right:10px;{'font-weight:bold;' if active == 'devices' else ''}'>Live Devices</a>
			<a href='/scanner' style='margin-right:10px;{'font-weight:bold;' if active == 'scanner' else ''}'>Network Scanner</a>
			<a href='/config' style='margin-right:10px;{'font-weight:bold;' if active == 'config' else ''}'>Configuration</a>
		</nav>
		"""
        html = (content if content else
            '<h1>AI Network Packet Analyzer Pro</h1>')
        return nav + html

    def _run_flask(self):
        port = self.config.get('ui_port', 5000)
        self.app.run(host='0.0.0.0', port=port, debug=False, use_reloader=False)

    def handle_event(self, event):
        if event.type == 'NEW_THREAT':
            self._last_threat = event.data
        elif event.type == 'DEVICE_DETECTED':
            dev = event.data.get('ip', str(event.data))
            if dev not in self._devices:
                self._devices.append(dev)
        elif event.type == 'SCAN_COMPLETED':
            result = event.data.get('result', str(event.data))
            self._scan_results.append(result)

    def generate_event(self):
        return None
