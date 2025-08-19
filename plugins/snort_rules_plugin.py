import os
import re
import threading
import time
import ipaddress
import operator
import yaml

from core.interfaces import ModuleBase
from core.events import Event
# Suppress print statements to prevent stdout locking at shutdown
print = lambda *args, **kwargs: None

try:
    import snort_parser  # type: ignore
except ImportError:
    snort_parser = None


class SnortRulesPlugin(ModuleBase):
    """
    Plugin dla reguł Snort: skanuje przechwycone pakiety pod kątem wzorców z pliku config/snort.rules
    Generuje eventy SNORT_ALERT przy wykryciu zgodności.
    """
    def __init__(self):
        super().__init__()
        self.config = {}
        self.rules = []
        self.rules_path = None
        self.rules_mtime = None
        # stany dla threshold
        self.threshold_states = {}
        # stany dla flowbits
        self.flowbit_states = {}
        # enabled rule IDs persistence
        self.enabled_sids = set()
        # state file for persisting enabled/disabled rule states
        config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config'))
        self.state_file = os.path.join(config_dir, 'snort_rules_state.yaml')

    def initialize(self, config):
        self.config = config
        default_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'config', 'snort.rules'))
        rule_file = self.config.get('rule_file') or self.config.get('rule_files')
        if rule_file:
            self.rules_path = os.path.abspath(rule_file) if os.path.isabs(rule_file) else os.path.abspath(os.path.join(os.getcwd(), rule_file))
        else:
            self.rules_path = default_path
        self.rules_mtime = None
        self._load_rules()
        # load persisted enabled/disabled states
        try:
            with open(self.state_file, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f) or {}
                sids = data.get('enabled_sids', [])
                self.enabled_sids = set(sids)
        except FileNotFoundError:
            pass
        except Exception:
            pass

        def _watch_rules():
            while True:
                try:
                    mtime = os.path.getmtime(self.rules_path)
                    if mtime != self.rules_mtime:
                        self._load_rules()
                        print(f"SnortRulesPlugin: przeładowano reguły (mtime: {mtime})", flush=True)
                except Exception:
                    pass
                time.sleep(5)
        threading.Thread(target=_watch_rules, daemon=True).start()

    def handle_event(self, event):
        print(f"[DEBUG SNORT] handle_event pkt: type={event.data.get('protocol')} "
              f"src={event.data.get('src_ip')} dst={event.data.get('dst_ip')} "
              f"flags={event.data.get('tcp_flags')} itype={event.data.get('icmp_type')}", flush=True)

        # obsługa tylko nowych pakietów
        if event.type != 'NEW_PACKET':
            return None
        # debug: start handle_event for matching
        print(f"[DEBUG SNORT] handle_event start: protocol={proto}, icmp_type={data.get('icmp_type')}", flush=True)
        if proto == 'icmp':
            print(f"[DEBUG SNORT] ICMP debug: listing all rules' protocols and itype options:", flush=True)
            for rule in self.rules:
                print(f"  rule sid={rule['sid']} proto={rule['protocol']} itype_opt={rule['options'].get('itype')}", flush=True)
        data = event.data
        # protokół
        proto_val = data.get('protocol', '')
        if isinstance(proto_val, int):
            if proto_val == 1:
                proto = 'icmp'
            elif proto_val == 6:
                proto = 'tcp'
            elif proto_val == 17:
                proto = 'udp'
            else:
                proto = str(proto_val)
        else:
            proto = str(proto_val).lower()

        src_ip = data.get('src_ip')
        dst_ip = data.get('dst_ip')
        src_port = str(data.get('src_port')) if data.get('src_port') is not None else ''
        dst_port = str(data.get('dst_port')) if data.get('dst_port') is not None else ''
        raw = data.get('raw_bytes', b'')
        try:
            payload = raw.decode('utf-8', errors='ignore')
        except:
            payload = ''
        now = time.time()

        # Select candidate rules by protocol and port using index
        # fast lookup using triple-index: (protocol, dst_port, src_port)
        keys = [
            (proto, dst_port, src_port),
            (proto, dst_port, 'any'),
            (proto, 'any', src_port),
            (proto, 'any', 'any'),
            ('any', 'any', 'any')
        ]
        candidates = []
        for k in keys:
            if k in self.rule_index:
                candidates = self.rule_index[k]
                break
        # Iterate over candidates
        for rule in candidates:
            # skip disabled rules
            if hasattr(self, 'enabled_sids') and rule['sid'] not in self.enabled_sids:
                continue
            opts = rule['options']
            # header matching: protocol already filtered via index
            # source address/ network
            src_rule = rule['src_addr']
            if src_rule != 'any':
                if '/' in src_rule:
                    net = ipaddress.ip_network(src_rule, strict=False)
                    if ipaddress.ip_address(src_ip) not in net:
                        continue
                elif src_rule != src_ip:
                    continue
            # source port
            if rule['src_port'] != 'any' and rule['src_port'] != src_port:
                continue
            # destination address/ network
            dst_rule = rule['dst_addr']
            if dst_rule != 'any':
                if '/' in dst_rule:
                    net = ipaddress.ip_network(dst_rule, strict=False)
                    if ipaddress.ip_address(dst_ip) not in net:
                        continue
                elif dst_rule != dst_ip:
                    continue
            # destination port
            if rule['dst_port'] != 'any' and rule['dst_port'] != dst_port:
                continue

            itype = opts.get('itype')
            if itype and data.get('icmp_type') != int(itype):
                continue

            flags = opts.get('flags')
            if flags:
                tf = data.get('tcp_flags', '')
                if any(f not in tf for f in flags):
                    continue

            # przygotowanie segmentu payload według offset/depth
            payload_seg = payload
            offset_opt = opts.get('offset')
            if offset_opt:
                try:
                    off = int(offset_opt)
                    payload_seg = payload_seg[off:]
                except ValueError:
                    pass
            depth_opt = opts.get('depth')
            if depth_opt:
                try:
                    dp = int(depth_opt)
                    payload_seg = payload_seg[:dp]
                except ValueError:
                    pass
            # opcje within/distance dla content
            content = opts.get('content')
            if content:
                nocase = opts.get('nocase') is not None
                if nocase:
                    hay = payload_seg.lower()
                    needle = content.lower()
                else:
                    hay = payload_seg
                    needle = content
                # distance: min offset
                dist = opts.get('distance')
                if dist:
                    try:
                        dmin = int(dist)
                        idx = hay.find(needle)
                        if idx == -1 or idx < dmin:
                            continue
                    except ValueError:
                        pass
                # within: max offset
                within = opts.get('within')
                if within:
                    try:
                        wmax = int(within)
                        idx = hay.find(needle)
                        if idx == -1 or idx > wmax:
                            continue
                    except ValueError:
                        pass
                if needle not in hay:
                    continue
            # PCRE
            regex = opts.get('_compiled_pcre')
            if regex and not regex.search(payload_seg):
                continue

            # numeric payload size options
            dsize = opts.get('dsize')
            if dsize and not self._check_numeric_size(dsize, len(payload)):
                continue
            length_opt = opts.get('length')
            if length_opt and not self._check_numeric_size(length_opt, len(raw)):
                continue
            # byte_test: size,op,value,offset
            bt = opts.get('byte_test')
            if bt and not self._check_byte_test(bt, raw):
                continue
            # flow: match TCP flow options
            flow_opt = opts.get('flow')
            if flow_opt and proto == 'tcp':
                parts = [p.strip() for p in flow_opt.split(',')]
                # established: ACK flag must be set
                if 'established' in parts and 'A' not in data.get('tcp_flags', ''):
                    continue
                # to_server/from_client can be added here
            # flowbits: stateful flags
            fb_opt = opts.get('flowbits')
            if fb_opt:
                st = self.flowbit_states.setdefault(rule['sid'], {})
                parts = fb_opt.split(',', 1)
                op = parts[0]
                bit = parts[1] if len(parts) > 1 else ''
                if op == 'set':
                    st[bit] = True
                elif op == 'unset':
                    st[bit] = False
                elif op == 'isset':
                    if not st.get(bit, False):
                        continue
                elif op == 'isnotset':
                    if st.get(bit, False):
                        continue

            # http_* options
            if proto == 'tcp' and payload.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                lines = payload.split('\r\n')
                # request line
                parts = lines[0].split()
                method = parts[0] if len(parts) > 0 else ''
                uri = parts[1] if len(parts) > 1 else ''
                http_method = opts.get('http_method')
                if http_method and method.upper() != http_method.upper():
                    continue
                http_uri = opts.get('http_uri')
                if http_uri and http_uri not in uri:
                    continue
                http_client_body = opts.get('http_client_body')
                if http_client_body:
                    # body follows empty line
                    if '\r\n\r\n' in payload:
                        body = payload.split('\r\n\r\n', 1)[1]
                    else:
                        body = ''
                    if http_client_body not in body:
                        continue
            # dns.* options (simple substring match)
            if proto == 'udp' and payload:
                dns_query = opts.get('dns_query')
                if dns_query and dns_query not in payload:
                    continue
                dns_qtype = opts.get('dns_query_type')
                if dns_qtype and dns_qtype not in payload:
                    continue

            # uricontent: content after URL decoding
            uricontent = opts.get('uricontent')
            if uricontent and proto == 'tcp':
                try:
                    from urllib.parse import unquote_plus
                    url_decoded = unquote_plus(payload)
                except:
                    url_decoded = payload
                if uricontent not in url_decoded:
                    continue
            # rawbytes: match hex sequence
            rawbytes = opts.get('rawbytes')
            if rawbytes:
                try:
                    hb = bytes.fromhex(rawbytes)
                    if hb not in raw:
                        continue
                except ValueError:
                    continue
            # byte_extract: similar to byte_test but extract into variable (not used here)
            byte_extract = opts.get('byte_extract')
            if byte_extract:
                # not implemented: stub for future
                pass
            # isdataat: check that raw length > offset+size
            isdataat = opts.get('isdataat')
            if isdataat:
                parts = isdataat.split(',')
                try:
                    size = int(parts[0]); off = int(parts[1])
                    if len(raw) < off + size:
                        continue
                except Exception:
                    continue
            # IP-level options
            fragbits = opts.get('fragbits')
            if fragbits and data.get('ip_frag_bits') != fragbits:
                continue
            fragoffset = opts.get('fragoffset')
            if fragoffset and data.get('ip_frag_offset') != int(fragoffset):
                continue
            ttl_opt = opts.get('ttl')
            if ttl_opt and data.get('ip_ttl') != int(ttl_opt):
                continue
            tos_opt = opts.get('tos')
            if tos_opt and data.get('ip_tos') != int(tos_opt):
                continue
            ip_flags = opts.get('ip_flags')
            if ip_flags and data.get('ip_flags', '') != ip_flags:
                continue
            # rate_filter: rate limiting alerts
            rate = opts.get('rate_filter')
            if rate:
                rid = rule['sid']
                state = getattr(self, 'rate_states', {})
                rlist = state.setdefault(rid, [])
                try:
                    # format: count/sec
                    c, s = rate.split('/')
                    c = int(c); s = int(s)
                    now = time.time()
                    rlist = [t for t in rlist if now - t < s]
                    if len(rlist) >= c:
                        continue
                    rlist.append(now)
                    state[rid] = rlist
                    self.rate_states = state
                except Exception:
                    pass
            # informational metadata
            meta = opts.get('metadata')
            cls = opts.get('classtype') or opts.get('classtype:')
            prio = opts.get('priority')
            ref = opts.get('reference')
            # pass through metadata in event if present
            info = {}
            if meta: info['metadata'] = meta
            if cls: info['classtype'] = cls
            if prio: info['priority'] = prio
            if ref: info['reference'] = ref
            # on match, include info
            print(f"[DEBUG SNORT] matched rule sid={rule['sid']} proto={proto} src={src_ip} dst={dst_ip} itype={data.get('icmp_type')}", flush=True)
            ev = Event('SNORT_ALERT', {
                'sid': rule['sid'],
                'msg': rule.get('msg'),
                'raw_rule': rule.get('raw'),
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'protocol': proto,
                'src_port': src_port,
                'dst_port': dst_port,
                **info
            })
            return ev
        return None

    def generate_event(self):
        return None

    def enable_rule(self, sid):
        self.enabled_sids.add(sid)
        # persist state
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, 'w', encoding='utf-8') as f:
                yaml.safe_dump({'enabled_sids': list(self.enabled_sids)}, f)
        except Exception:
            pass

    def disable_rule(self, sid):
        self.enabled_sids.discard(sid)
        # persist state
        try:
            os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
            with open(self.state_file, 'w', encoding='utf-8') as f:
                yaml.safe_dump({'enabled_sids': list(self.enabled_sids)}, f)
        except Exception:
            pass

    def reload_rules(self):
        self._load_rules()

    def _load_rules(self):
        """Wczytuje i parsuje reguły z pliku, aktualizuje self.rules i self.rules_mtime"""
        try:
            mtime = os.path.getmtime(self.rules_path)
        except FileNotFoundError:
            print(f"SnortRulesPlugin: nie znaleziono pliku reguł: {self.rules_path}", flush=True)
            return

        old_mtime = getattr(self, 'rules_mtime', None)
        if old_mtime is not None and mtime == old_mtime:
            return
        self.rules_mtime = mtime

        new_rules = []
        if snort_parser:
            # użyj zewnętrznego parsera Snort
            try:
                parsed = snort_parser.parse_file(self.rules_path)
                for r in parsed:
                    opts = {k: r.options[k] for k in r.options}
                    if 'pcre' in opts:
                        try:
                            opts['_compiled_pcre'] = re.compile(opts['pcre'])
                        except re.error:
                            opts['_compiled_pcre'] = None
                    new_rules.append({
                        'sid': str(r.sid),
                        'msg': r.msg,
                        'protocol': r.protocol,
                        'src_addr': r.src_addr,
                        'src_port': r.src_port,
                        'dst_addr': r.dst_addr,
                        'dst_port': r.dst_port,
                        'options': opts,
                        'raw': r.raw or ''
                    })
            except Exception as e:
                print(f"SnortRulesPlugin: błąd parsera snort-parser: {e}", flush=True)
        else:
            # ręczne parsowanie (fallback)
            with open(self.rules_path, 'r', encoding='utf-8') as f:
                for line in f:
                    raw = line.strip()
                    if not raw or raw.startswith('#') or '(' not in raw or ')' not in raw:
                        continue
                    header, opts = raw.split('(', 1)
                    opts_str = opts.rsplit(')', 1)[0]
                    hdr = header.strip().split()
                    if len(hdr) < 7 or hdr[4] != '->':
                        continue
                    proto, src_addr, src_port, dst_addr, dst_port = hdr[1], hdr[2], hdr[3], hdr[5], hdr[6]
                    fields = [o.strip() for o in opts_str.split(';') if o.strip()]
                    opts_dict = {}
                    for fld in fields:
                        if ':' not in fld:
                            continue
                        k, v = fld.split(':', 1)
                        key = k.strip()
                        val = v.strip().strip('"')
                        opts_dict[key] = val
                        if key == 'pcre':
                            try:
                                opts_dict['_compiled_pcre'] = re.compile(val)
                            except re.error:
                                opts_dict['_compiled_pcre'] = None
                    sid = opts_dict.get('sid')
                    if not sid:
                        continue
                    new_rules.append({
                        'sid': sid,
                        'msg': opts_dict.get('msg'),
                        'protocol': proto,
                        'src_addr': src_addr,
                        'src_port': src_port,
                        'dst_addr': dst_addr,
                        'dst_port': dst_port,
                        'options': opts_dict,
                        'raw': raw
                    })
                    if len(hdr) < 7 or hdr[4] != '->':
                        continue
                    proto, src_addr, src_port, dst_addr, dst_port = hdr[1], hdr[2], hdr[3], hdr[5], hdr[6]
                    fields = [o.strip() for o in opts_str.split(';') if o.strip()]
                    opts_dict = {}
                    for fld in fields:
                        if ':' not in fld:
                            continue
                        k, v = fld.split(':', 1)
                        key = k.strip()
                        val = v.strip().strip('"')
                        opts_dict[key] = val
                        if key == 'pcre':
                            try:
                                opts_dict['_compiled_pcre'] = re.compile(val)
                            except re.error:
                                opts_dict['_compiled_pcre'] = None
                    sid = opts_dict.get('sid')
                    if not sid:
                        continue
                    new_rules.append({
                        'sid': sid,
                        'msg': opts_dict.get('msg'),
                        'protocol': hdr[1],
                        'src_addr': hdr[2],
                        'src_port': hdr[3],
                        'dst_addr': hdr[5],
                        'dst_port': hdr[6],
                        'options': opts_dict,
                        'raw': raw
                    })

        self.rules = new_rules
        print(f"[DEBUG SNORT] _load_rules: loaded {len(self.rules)} rules from {self.rules_path}", flush=True)
        # debug: list all loaded rule SIDs
        try:
            sids = [rule.get('sid') for rule in self.rules]
            print(f"[DEBUG SNORT] loaded rule SIDs: {sids}", flush=True)
            if '2000001' in sids:
                print("[DEBUG SNORT] ICMP test rule SID=2000001 is loaded", flush=True)
            else:
                print("[DEBUG SNORT] ICMP test rule SID=2000001 NOT loaded", flush=True)
        except Exception:
            pass
        # indeks reguł dla szybkiego filtrowania (protocol, dst_port, src_port)
        self.rule_index = {}
        for rule in self.rules:
            p = rule['protocol'].lower()
            d = rule['dst_port']
            s = rule['src_port']
            for proto_key in (p, 'any'):
                for dst_key in (d, 'any'):
                    for src_key in (s, 'any'):
                        self.rule_index.setdefault((proto_key, dst_key, src_key), []).append(rule)

            # wszystkie reguły włączone domyślnie
            self.enabled_sids = {rule['sid'] for rule in self.rules if rule.get('sid')}
            # inicjalizacja stanów flowbits
            self.flowbit_states = {rule['sid']: {} for rule in self.rules}

            # inicjalizacja stanów progów
            self.threshold_states = {}
            for rule in self.rules:
                thr = rule['options'].get('threshold')
                if thr:
                    parts = [pt.strip() for pt in thr.split(',')]
                    params = {}
                    for part in parts:
                        if part.startswith('type '):
                            params['type'] = part.split(' ', 1)[1]
                        elif part.startswith('track '):
                            params['track'] = part.split(' ', 1)[1]
                        elif part.startswith('count '):
                            try:
                                params['count'] = int(part.split(' ', 1)[1])
                            except ValueError:
                                pass
                        elif part.startswith('seconds '):
                            try:
                                params['seconds'] = int(part.split(' ', 1)[1])
                            except ValueError:
                                pass
                    self.threshold_states[rule['sid']] = {'params': params, 'counters': {}}

    def _check_numeric_size(self, expr, size):
        # expr format: '<value>' or '><value>' or '=value'
        # support operators: >, <, =
        m = re.match(r'([<>]?)(\d+)', expr)
        if not m:
            return False
        op, val = m.group(1), int(m.group(2))
        ops = {'': operator.eq, '>': operator.gt, '<': operator.lt}
        func = ops.get(op)
        return func(size, val)

    def _check_byte_test(self, expr, raw):
        # expr format: 'size,operator,value,offset'
        parts = expr.split(',')
        if len(parts) < 4:
            return False
        try:
            size = int(parts[0])
            op = parts[1]
            val = int(parts[2])
            offset = int(parts[3])
            data = raw[offset:offset+size]
            if len(data) < size:
                return False
            # interpret data as big-endian integer
            num = int.from_bytes(data, byteorder='big')
            # map operators
            op_map = {'=': operator.eq, '!=': operator.ne, '>': operator.gt, '<': operator.lt, '>=': operator.ge, '<=': operator.le}
            func = op_map.get(op)
            if not func:
                return False
            return func(num, val)
        except Exception:
            return False