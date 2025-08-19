"""SOC Layout module - build the SIEM/SOC dashboard UI layout using PyQt5 widgets and Matplotlib."""
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QPushButton, QGraphicsView, QTableWidget, QHeaderView, QLineEdit, QLabel
from PyQt5.QtCore import Qt
from qtui.cmd_log_widget import create_cmd_log
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

class ZoomableGraphicsView(QGraphicsView):
    """Custom QGraphicsView enabling interactive panning and zooming via mouse wheel."""
    def __init__(self, parent=None):
        """Initialize ZoomableGraphicsView with drag and interactive mode enabled."""
        super().__init__(parent)
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setInteractive(True)

    def wheelEvent(self, event):
        """Handle mouse wheel events to zoom in or out on the graphics view.

        Zooms by a fixed factor per wheel notch.
        """
        zoomInFactor = 1.25
        zoomOutFactor = 1 / zoomInFactor
        self.scale(zoomInFactor if event.angleDelta().y() > 0 else zoomOutFactor,
                   zoomInFactor if event.angleDelta().y() > 0 else zoomOutFactor)

class SOCLayout:
    """Construct the layout for the SOC dashboard, including map, logs, tables, and chart."""
    def build(self):
        """Build and return the main SOC UI widget and control mapping.

        Returns
        -------
        tuple
            The QWidget containing the layout and a dict of control widgets.
        """
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
        # Legend for node colors
        legend_layout = QHBoxLayout()
        # Color indicators as small colored squares
        for color, desc in [('lightgray', 'No activity'), ('green', 'Raw event'), ('yellow', 'Medium alert'), ('red', 'High/Threat')] :
            square = QLabel()
            square.setFixedSize(15, 15)
            square.setStyleSheet(f'background-color: {color}; border: 1px solid black;')
            legend_layout.addWidget(square)
            lbl = QLabel(desc)
            legend_layout.addWidget(lbl)
        legend_layout.addStretch()
        map_layout.addLayout(legend_layout)
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
        # Logs table: Timestamp, Src IP, Dst IP, Event type, Source, Severity, Details
        log_table = QTableWidget(0, 7)
        log_table.setHorizontalHeaderLabels([
            'Timestamp', 'Src IP', 'Dst IP', 'Event', 'Source', 'Severity', 'Details'
        ])
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

        # Raw Events panel
        raw_group = QGroupBox('Raw Events')
        raw_layout = QVBoxLayout()
        raw_table = QTableWidget(0, 4)
        raw_table.setHorizontalHeaderLabels(['Timestamp', 'Src IP', 'Dst IP', 'Type'])
        raw_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        raw_layout.addWidget(raw_table)
        raw_group.setLayout(raw_layout)

        # Grouped by source IP
        group_box = QGroupBox('Alerty wg źródłowego IP')
        group_layout = QVBoxLayout()
        group_table = QTableWidget(0,2)
        group_table.setHorizontalHeaderLabels(['Source IP','Count'])
        group_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        group_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        group_layout.addWidget(group_table)
        group_box.setLayout(group_layout)

        # AI Scores panel
        ai_group = QGroupBox('AI Scores')
        ai_layout = QVBoxLayout()
        ai_table = QTableWidget(0, 5)
        ai_table.setHorizontalHeaderLabels(['Timestamp', 'Src IP', 'Dst IP', 'Score', 'Details'])
        ai_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        ai_layout.addWidget(ai_table)
        ai_group.setLayout(ai_layout)

        # Scan Results panel
        scan_group = QGroupBox('Scan Results')
        scan_layout = QVBoxLayout()
        scan_table = QTableWidget(0, 3)
        scan_table.setHorizontalHeaderLabels(['IP', 'MAC', 'Ports'])
        scan_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        scan_layout.addWidget(scan_table)
        scan_group.setLayout(scan_layout)

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
        right_layout.addWidget(raw_group, stretch=1)
        right_layout.addWidget(group_box, stretch=1)
        right_layout.addWidget(ai_group, stretch=1)
        right_layout.addWidget(scan_group, stretch=1)
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
            'raw_table': raw_table,
            'low_label': low_label,
            'medium_label': medium_label,
            'high_label': high_label,
            'export_btn': export_btn,
            'email_btn': email_btn,
            'report_btn': report_btn,
            'cmd_log': cmd_log,
            'group_table': group_table,
            'ai_table': ai_table,
            'chart_canvas': canvas,
            'scan_table': scan_table
        }