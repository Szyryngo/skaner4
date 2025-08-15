from modules.devices_sniffer import DevicesSniffer
from core.events import Event
from core.interfaces import ModuleBase


class DevicesSnifferModule(ModuleBase):
    """
Attributes
----------

Methods
-------

"""

    def set_interface(self, iface):
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
        self.config = config
        self._iface = config.get('network_interface', None)
        self._sniffer = DevicesSniffer(iface=self._iface, event_callback=
            self._on_device_detected)
        self._event_queue = []
        self._sniffer.start()

    def _on_device_detected(self, event):
        import datetime
        data = dict(event.data)
        data['last_seen'] = datetime.datetime.now().strftime(
            '%Y-%m-%d %H:%M:%S')
        data['packets'] = 1
        data['status'] = 'online'
        self._event_queue.append(Event('DEVICE_DETECTED', data))

    def handle_event(self, event):
        pass

    def generate_event(self):
        if self._event_queue:
            return self._event_queue.pop(0)
        return None
