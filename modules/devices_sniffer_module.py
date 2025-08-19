"""Devices Sniffer Module - integrate DevicesSniffer into orchestrator as a ModuleBase.

This module starts a background DevicesSniffer instance and publishes DEVICE_DETECTED events
into the orchestrator event loop."""
from modules.devices_sniffer import DevicesSniffer
from core.events import Event
from core.interfaces import ModuleBase


class DevicesSnifferModule(ModuleBase):
    """Module wrapper for DevicesSniffer, producing DEVICE_DETECTED events.

    Controls sniffer lifecycle and queues detected device events for the orchestrator."""

    def set_interface(self, iface):
        """Set network interface for sniffing and restart sniffer.

        Stops existing sniffer (if any), updates interface, and starts a new DevicesSniffer.

        Parameters
        ----------
        iface : str
            Network interface name to sniff on.
        """
        if hasattr(self, '_sniffer') and self._sniffer:
            self._sniffer.stop()
        self._iface = iface
        self._sniffer = DevicesSniffer(iface=self._iface, event_callback=
            self._on_device_detected)
        self._sniffer.start()
    """
    Moduł uruchamiający DevicesSniffer i publikujący eventy DEVICE_DETECTED do orchestratora.
    """

    def initialize(self, config):
        """Initialize module with configuration and start DevicesSniffer.

        Parameters
        ----------
        config : dict
            Configuration settings including 'network_interface'.
        """
        self.config = config
        self._iface = config.get('network_interface', None)
        self._sniffer = DevicesSniffer(iface=self._iface, event_callback=
            self._on_device_detected)
        self._event_queue = []
        self._sniffer.start()

    def _on_device_detected(self, event):
        """Internal callback for DevicesSniffer events.

        Enhances the raw DEVICE_DETECTED event with timestamp, packet count, and status,
        then queues it for later retrieval by generate_event().

        Parameters
        ----------
        event : Event
            Raw event from DevicesSniffer with device data.
        """
        import datetime
        data = dict(event.data)
        data['last_seen'] = datetime.datetime.now().strftime(
            '%Y-%m-%d %H:%M:%S')
        data['packets'] = 1
        data['status'] = 'online'
        self._event_queue.append(Event('DEVICE_DETECTED', data))

    def handle_event(self, event):
        """Handle incoming events (no-op for this module)."""
        pass

    def generate_event(self):
        """Return the next queued DEVICE_DETECTED event, or None if queue is empty.

        Yields
        ------
        Event or None
            Next DEVICE_DETECTED event from the internal queue.
        """
        if self._event_queue:
            return self._event_queue.pop(0)
        return None
