"""Unit tests for SnortRulesPlugin covering rule loading, custom configs, and packet matching."""
import os
import sys
import time
import unittest
# ensure top-level project folder is on sys.path for importing plugins and core
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from plugins.snort_rules_plugin import SnortRulesPlugin
from core.events import Event

class TestSnortRulesPlugin(unittest.TestCase):
    """Test suite for verifying SnortRulesPlugin loads rules and emits SNORT_ALERT appropriately."""
    def setUp(self):
        """Prepare a SnortRulesPlugin instance and load test rule files before each test."""
        # Przygotuj plik z regułami testowymi
        self.plugin = SnortRulesPlugin()
        # tymczasowy plik z regułami
        test_rules = os.path.abspath(os.path.join(os.path.dirname(__file__), 'snort_test.rules'))
        with open(test_rules, 'w', encoding='utf-8') as f:
            f.write('alert icmp any any -> any any (msg:"Ping test"; itype:8; sid:1000; rev:1;)\n')
            f.write('alert tcp any any -> any any (msg:"SYN flood test"; flags:S; threshold:type threshold, track by_src, count 2, seconds 1; sid:1001; rev:1;)\n')
        # ustaw ścieżkę do pliku i załaduj reguły
        self.plugin.rules_path = test_rules
        if hasattr(self.plugin, 'rules_mtime'):
            del self.plugin.rules_mtime
        self.plugin._load_rules()

    def test_icmp_ping_detection(self):
        """Verify that an ICMP echo request packet triggers a SNORT_ALERT with the correct SID and message."""
        # symulacja pakietu ICMP typu 8 (ping)
        data = {'protocol':'icmp', 'src_ip':'10.0.0.1', 'dst_ip':'10.0.0.2', 'icmp_type':8, 'raw_bytes': b''}
        ev = self.plugin.handle_event(Event('NEW_PACKET', data))
        self.assertIsNotNone(ev)
        self.assertEqual(ev.data.get('sid'), '1000')
        self.assertIn('Ping test', ev.data.get('msg', ''))

    def test_threshold_syn_detection(self):
        """Test SYN flood threshold rule: only after count threshold is met should SNORT_ALERT be emitted."""
        # pierwsze wywołanie nie powinno wyzwolić alertu
        data = {'protocol':'tcp', 'src_ip':'10.0.0.1', 'dst_ip':'10.0.0.2', 'src_port':1234, 'dst_port':80, 'tcp_flags':'S', 'raw_bytes': b''}
        ev1 = self.plugin.handle_event(Event('NEW_PACKET', data))
        self.assertIsNone(ev1)
        # drugie w krótkim czasie powinno wystrzelić alert
        time.sleep(0.1)
        ev2 = self.plugin.handle_event(Event('NEW_PACKET', data))
        self.assertIsNotNone(ev2)
        self.assertEqual(ev2.data.get('sid'), '1001')
    
    def test_custom_rule_file_config(self):
        """Check that SnortRulesPlugin uses a custom rule file specified in configuration."""
        # przygotuj niestandardowy plik reguł i nadpisanie w config
        custom_rules = os.path.abspath(os.path.join(os.path.dirname(__file__), 'custom.rules'))
        with open(custom_rules, 'w', encoding='utf-8') as f:
            f.write('alert icmp any any -> any any (msg:"Custom ping"; itype:8; sid:2000; rev:1;)\n')
        plugin = SnortRulesPlugin()
        # inicjalizacja z opcją rule_file
        plugin.initialize({'rule_file': custom_rules})
        # symulacja pakietu ICMP typu 8 (ping)
        data = {'protocol':'icmp', 'src_ip':'1.1.1.1', 'dst_ip':'1.1.1.2', 'icmp_type':8, 'raw_bytes': b''}
        ev = plugin.handle_event(Event('NEW_PACKET', data))
        self.assertIsNotNone(ev)
        self.assertEqual(ev.data.get('sid'), '2000')
        self.assertIn('Custom ping', ev.data.get('msg', ''))

    def test_scapy_icmp_packet(self):
        """Use a Scapy-crafted ICMP packet to confirm detection logic works with raw packet data."""
        # Test ICMP detection using scapy-crafted packet
        from scapy.all import IP, ICMP, raw
        pkt = IP(src='10.0.0.3', dst='10.0.0.4')/ICMP(type=8)
        data = {
            'protocol': pkt.proto,
            'src_ip': pkt.src,
            'dst_ip': pkt.dst,
            'icmp_type': pkt[ICMP].type,
            'raw_bytes': raw(pkt)
        }
        ev = self.plugin.handle_event(Event('NEW_PACKET', data))
        self.assertIsNotNone(ev)
        self.assertEqual(ev.data.get('sid'), '1000')

if __name__ == '__main__':
    unittest.main()
