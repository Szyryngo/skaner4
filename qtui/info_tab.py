from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem
from PyQt5.QtCore import QObject, QThread, pyqtSignal
import psutil
import platform

# Worker to fetch hardware info
class InfoWorker(QObject):
    finished = pyqtSignal(list)
    def run(self):
        rows = []
        # CPU info
        try:
            import cpuinfo
            cpu_brand = cpuinfo.get_cpu_info().get('brand_raw', platform.processor())
        except ImportError:
            cpu_brand = platform.processor() or 'Unknown'
        rows.append(('Procesor', cpu_brand))
        rows.append(('Rdzenie fizyczne', str(psutil.cpu_count(logical=False))))
        rows.append(('Rdzenie logiczne', str(psutil.cpu_count(logical=True))))
        try:
            freq = psutil.cpu_freq()
            if freq:
                rows.append(('Częstotliwość maks.', f"{freq.max:.2f} MHz"))
        except:
            pass
        # RAM info
        vm = psutil.virtual_memory()
        rows.append(('RAM całkowita', f"{vm.total / (1024**3):.2f} GB"))
        sm = psutil.swap_memory()
        if sm.total:
            rows.append(('Swap', f"{sm.total / (1024**3):.2f} GB"))
        # GPU info
        try:
            import GPUtil
            gpus = GPUtil.getGPUs()
        except ImportError:
            gpus = []
        if gpus:
            for gpu in gpus:
                rows.append((f"GPU: {gpu.name}", f"Memory: {gpu.memoryTotal}MB, Driver: {gpu.driver}"))
        else:
            rows.append(('GPU', 'Brak lub nieznany'))
        # Windows WMI
        if platform.system() == 'Windows':
            try:
                import wmi
                c = wmi.WMI()
                bios = c.Win32_BIOS()[0]
                rows.append(('BIOS producent', bios.Manufacturer))
                rows.append(('Wersja BIOS', bios.SMBIOSBIOSVersion))
                board = c.Win32_BaseBoard()[0]
                rows.append(('Płyta główna', board.Product))
                rows.append(('Producent płyty', board.Manufacturer))
                for mem in c.Win32_PhysicalMemory():
                    rows.append((f"RAM moduł {mem.DeviceLocator}",
                                 f"{int(int(mem.Capacity)/(1024**3))} GB, {mem.Speed} MHz"))
                for disk in c.Win32_DiskDrive():
                    rows.append((f"Dysk {disk.Model}",
                                 f"{int(int(disk.Size)/(1024**3))} GB"))
                for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    ip = nic.IPAddress[0] if nic.IPAddress else ''
                    rows.append((f"NIC {nic.Description}",
                                 f"MAC {nic.MACAddress}, IP {ip}"))
            except Exception:
                rows.append(('WMI', 'Błąd podczas ładowania WMI'))
        # emit results
        self.finished.emit(rows)

class InfoTab(QWidget):
    """Zakładka z informacjami o podzespołach komputera"""
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(['Parametr', 'Wartość'])
        layout.addWidget(self.table)
        # start background thread
        self._thread = QThread(self)
        self._worker = InfoWorker()
        self._worker.moveToThread(self._thread)
        self._thread.started.connect(self._worker.run)
        self._worker.finished.connect(self._on_info_ready)
        self._worker.finished.connect(self._thread.quit)
        self._thread.start()

    def _on_info_ready(self, rows):
        self.table.setRowCount(len(rows))
        for i, (param, val) in enumerate(rows):
            self.table.setItem(i, 0, QTableWidgetItem(param))
            self.table.setItem(i, 1, QTableWidgetItem(val))
        self.table.resizeColumnsToContents()
