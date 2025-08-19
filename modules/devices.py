"""Devices Module - track devices on the network and emit detection events.

Listens for NEW_PACKET events, maintains active host list, and emits DEVICE_DETECTED
when a new host appears and DEVICE_INACTIVE when a host times out."""
from core.interfaces import ModuleBase
from core.events import Event
import time


class DevicesModule(ModuleBase):
    """Module to detect and track network devices based on captured packets.

    Maintains counts and last seen timestamps for hosts and emits DEVICE_DETECTED
    and DEVICE_INACTIVE events according to activity.
    """

    def initialize(self, config):
        """Initialize device tracking with configuration settings.

        Parameters
        ----------
        config : dict
            Configuration parameters including timeouts and thresholds.
        """
        self.config = config
        # devices: mapping ip -> {'mac': mac, 'count': packet_count, 'last_seen': timestamp}
        self.devices = {}
        # active_hosts: mapping ip -> last seen timestamp for timeout logic
        self.active_hosts = {}
        # timeout (seconds) for marking hosts inactive
        self.timeout = 300

    def handle_event(self, event):
        """Handle NEW_PACKET events to identify and update device records.

        Parameters
        ----------
        event : Event
            Incoming NEW_PACKET event containing packet data to process.

        Yields
        ------
        Event
            DEVICE_DETECTED when a new device is seen.
        """
        if event.type == 'NEW_PACKET':
            pkt = event.data
            src_ip = pkt.get('src_ip')
            mac = pkt.get('src_mac')
            now = time.time()
            if src_ip and mac:
                is_new = src_ip not in self.active_hosts
                # update last seen timestamp for timeout logic
                self.active_hosts[src_ip] = now
                if is_new:
                    # first time seen; initialize device record
                    self.devices[src_ip] = {'mac': mac, 'count': 1, 'last_seen': now}
                    yield Event('DEVICE_DETECTED', {'ip': src_ip, 'mac': mac, 'first_seen': now})
                else:
                    # update existing device record
                    info = self.devices.get(src_ip, {})
                    info['count'] = info.get('count', 0) + 1
                    info['last_seen'] = now
                    self.devices[src_ip] = info

    def generate_event(self):
        """Generate DEVICE_INACTIVE events for hosts that have timed out.

        Compares current time to last seen timestamps and yields events
        for hosts inactive longer than the configured timeout.

        Yields
        ------
        Event
            DEVICE_INACTIVE for each inactive host.
        """
        now = time.time()
        to_remove = [ip for ip, ts in self.active_hosts.items() if now - ts > self.timeout]
        for ip in to_remove:
            # remove inactive host
            del self.active_hosts[ip]
            if ip in self.devices:
                del self.devices[ip]
            yield Event('DEVICE_INACTIVE', {'ip': ip})
