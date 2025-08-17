import os
import re
from core.interfaces import ModuleBase
from core.events import Event


class SnortRulesPlugin(ModuleBase):
    """
    Plugin dla reguł Snort: skanuje przechwycone pakiety pod kątem wzorców z pliku config/snort.rules
    Generuje eventy SNORT_ALERT przy wykryciu zgodności.
    """
    def __init__(self):
        super().__init__()
        self.config = {}
        self.rules = []

    def initialize(self, config):
        self.config = config
        # Wczytaj reguły Snort z pliku
        rules_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'snort.rules'))
        self.rules = []
        try:
            with open(rules_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    # znajdź opcje wewnątrz nawiasów
                    m = re.search(r"\((.*)\)", line)
                    if not m:
                        continue
                    opts = m.group(1)
                    # rozdziel opcje po średnikach
                    fields = [o.strip() for o in opts.split(';') if o.strip()]
                    rule = {}
                    for field in fields:
                        if ':' not in field:
                            continue
                        key, val = field.split(':', 1)
                        rule[key] = val.strip().strip('"')
                    # zachowaj tylko ciekawsze pola
                    sid = rule.get('sid')
                    msg = rule.get('msg')
                    content = rule.get('content')
                    if content:
                        self.rules.append({'sid': sid, 'msg': msg, 'content': content})
        except FileNotFoundError:
            print(f"SnortRulesPlugin: nie znaleziono pliku reguł: {rules_path}")
        # By default all rules enabled
        try:
            self.enabled_sids = {rule.get('sid') for rule in self.rules if rule.get('sid')}
        except Exception:
            self.enabled_sids = set()

    def handle_event(self, event):
        # ensure rules loaded
        if not hasattr(self, 'rules'):
            self.rules = []
        # Sprawdzaj tylko pakiety NEW_PACKET
        if event.type != 'NEW_PACKET':
            return None
        raw = event.data.get('raw_bytes', b'')
        try:
            payload = raw.decode('utf-8', errors='ignore')
        except Exception:
            payload = ''
        # Przeszukaj payload
        for rule in self.rules:
            # skip disabled rules
            if rule.get('sid') not in getattr(self, 'enabled_sids', []):
                continue
            if rule['content'] in payload:
                # wykryto regułę Snort
                return Event('SNORT_ALERT', {
                    'sid': rule.get('sid'),
                    'msg': rule.get('msg'),
                    'content': rule.get('content'),
                    'src_ip': event.data.get('src_ip'),
                    'dst_ip': event.data.get('dst_ip')
                })
        return None

    def generate_event(self):
        # plugin generuje eventy bezpośrednio w handle_event
        return None
    # Methods to enable/disable individual rules
    def enable_rule(self, sid):
        if not hasattr(self, 'enabled_sids'):
            self.enabled_sids = set()
        self.enabled_sids.add(sid)

    def disable_rule(self, sid):
        if hasattr(self, 'enabled_sids'):
            self.enabled_sids.discard(sid)
