from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTableWidget, QTableWidgetItem
import psutil
import platform

# Try to get detailed CPU info if cpuinfo is available
try:
    import cpuinfo
    _CPU_INFO = cpuinfo.get_cpu_info()
    CPU_BRAND = _CPU_INFO.get('brand_raw', platform.processor())
except ImportError:
    CPU_BRAND = platform.processor() or 'Unknown'

# Try to get GPU info if GPUtil is available
try:
    import GPUtil
    GPUS = GPUtil.getGPUs()
except ImportError:
    GPUS = []

class InfoTab(QWidget):
    """Zakładka z informacjami o podzespołach komputera"""
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout()
        table = QTableWidget()
        table.setColumnCount(2)
        table.setHorizontalHeaderLabels(['Parametr', 'Wartość'])
        rows = []
        # CPU info
        rows.append(('Procesor', CPU_BRAND))
        rows.append(('Rdzenie fizyczne', str(psutil.cpu_count(logical=False))))
        rows.append(('Rdzenie logiczne', str(psutil.cpu_count(logical=True))))
        try:
            freq = psutil.cpu_freq()
            if freq:
                rows.append(('Częstotliwość maks.', f"{freq.max:.2f} MHz"))
        except Exception:
            pass
        # RAM info
        vm = psutil.virtual_memory()
        total_gb = vm.total / (1024 ** 3)
        rows.append(('RAM całkowita', f"{total_gb:.2f} GB"))
        # Swap info
        sm = psutil.swap_memory()
        if sm.total:
            swap_gb = sm.total / (1024 ** 3)
            rows.append(('Swap', f"{swap_gb:.2f} GB"))
        # GPU info
        if GPUS:
            for gpu in GPUS:
                rows.append((f"GPU: {gpu.name}", f"Memory: {gpu.memoryTotal}MB, Driver: {gpu.driver}"))
        else:
            rows.append(('GPU', 'Brak lub nieznany'))
        # Detailed Windows hardware info via WMI
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
                # RAM modules
                for mem in c.Win32_PhysicalMemory():
                    cap_gb = int(int(mem.Capacity) / (1024**3))
                    rows.append((f"RAM moduł {mem.DeviceLocator}", f"{cap_gb} GB, {mem.Speed} MHz"))
                # Dyski
                for disk in c.Win32_DiskDrive():
                    size_gb = int(int(disk.Size) / (1024**3))
                    rows.append((f"Dysk {disk.Model}", f"{size_gb} GB"))
                # Karty sieciowe
                for nic in c.Win32_NetworkAdapterConfiguration(IPEnabled=True):
                    ip = nic.IPAddress[0] if nic.IPAddress else ''
                    rows.append((f"NIC {nic.Description}", f"MAC {nic.MACAddress}, IP {ip}"))
            except ImportError:
                rows.append(('WMI', 'Moduł wmi nie jest zainstalowany'))
        # Populate table
        table.setRowCount(len(rows))
        for i, (param, val) in enumerate(rows):
            table.setItem(i, 0, QTableWidgetItem(param))
            table.setItem(i, 1, QTableWidgetItem(val))
        table.resizeColumnsToContents()
        layout.addWidget(table)
        self.setLayout(layout)
        self.table = table
