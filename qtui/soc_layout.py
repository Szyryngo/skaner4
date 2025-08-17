from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, QGraphicsView, QTableWidget, QHeaderView, QLineEdit, QLabel
from PyQt5.QtCore import Qt
from qtui.cmd_log_widget import create_cmd_log
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class ZoomableGraphicsView(QGraphicsView):
    """QGraphicsView that supports zooming with the mouse wheel"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setInteractive(True)

    def wheelEvent(self, event):
        zoomInFactor = 1.25
        zoomOutFactor = 1 / zoomInFactor
        self.scale(zoomInFactor if event.angleDelta().y() > 0 else zoomOutFactor,
                   zoomInFactor if event.angleDelta().y() > 0 else zoomOutFactor)

class SOCLayout:
    """
    Layout for SIEM/SOC mode: dashboard of security alerts and logs.
    """
    def build(self):
        widget = QWidget()
        main_layout = QVBoxLayout(widget)

        # Top navigation
        nav_layout = QHBoxLayout()
        live_btn = QPushButton('Live Monitoring')
        sched_btn = QPushButton('Scheduled Scanning')
        for btn in (live_btn, sched_btn):
            btn.setCheckable(True)
            nav_layout.addWidget(btn)
        nav_layout.addStretch()
        main_layout.addLayout(nav_layout)

        # Left: Network Map
        map_group = QGroupBox('Network Map')
        map_layout = QVBoxLayout()
        map_view = ZoomableGraphicsView()
        map_layout.addWidget(map_view)
        map_group.setLayout(map_layout)

        # Right: Logs, Grouped alerts, Chart
        # Logs and alerts
        log_group = QGroupBox('Logs and Alerts')
        log_layout = QVBoxLayout()
        filter_input = QLineEdit()
        filter_input.setPlaceholderText('Filtruj alerty (tekst)...')
        log_layout.addWidget(filter_input)
        summary_layout = QHBoxLayout()
        low_label = QLabel('Low: 0')
        medium_label = QLabel('Medium: 0')
        high_label = QLabel('High: 0')
        for lbl in (low_label, medium_label, high_label):
            summary_layout.addWidget(lbl)
        log_layout.addLayout(summary_layout)
        log_table = QTableWidget(0, 6)
        log_table.setHorizontalHeaderLabels(['Time','Event','Severity','Source','Destination','Confidence'])
        log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        log_layout.addWidget(log_table)
        act_layout = QHBoxLayout()
        export_btn = QPushButton('Export to SIEM')
        email_btn = QPushButton('Email Notifications')
        report_btn = QPushButton('Generate PDF Report')
        for btn in (export_btn, email_btn, report_btn):
            act_layout.addWidget(btn)
        act_layout.addStretch()
        log_layout.addLayout(act_layout)
        log_group.setLayout(log_layout)

        # Grouped by source IP
        group_box = QGroupBox('Alerty wg źródłowego IP')
        group_layout = QVBoxLayout()
        group_table = QTableWidget(0,2)
        group_table.setHorizontalHeaderLabels(['Source IP','Count'])
        group_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        group_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        group_layout.addWidget(group_table)
        group_box.setLayout(group_layout)

        # Chart
        chart_group = QGroupBox('Alert Severity Chart')
        chart_layout2 = QVBoxLayout()
        canvas = FigureCanvas(Figure(figsize=(4,2)))
        chart_layout2.addWidget(canvas)
        chart_group.setLayout(chart_layout2)

        # Compose central splitter
        content_layout = QHBoxLayout()
        content_layout.addWidget(map_group, stretch=3)
        right_layout = QVBoxLayout()
        right_layout.addWidget(log_group, stretch=2)
        right_layout.addWidget(group_box, stretch=1)
        right_layout.addWidget(chart_group, stretch=1)
        content_layout.addLayout(right_layout, stretch=2)
        main_layout.addLayout(content_layout)

        # Command log full width
        cmd_log = create_cmd_log()
        main_layout.addWidget(cmd_log)

        return widget, {
            'live_btn': live_btn,
            'scheduled_btn': sched_btn,
            'map_view': map_view,
            'filter_input': filter_input,
            'log_table': log_table,
            'low_label': low_label,
            'medium_label': medium_label,
            'high_label': high_label,
            'export_btn': export_btn,
            'email_btn': email_btn,
            'report_btn': report_btn,
            'cmd_log': cmd_log,
            'chart_canvas': canvas
        }