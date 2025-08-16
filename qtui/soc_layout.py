from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
    QPushButton, QGraphicsView, QTableWidget, QHeaderView, QPushButton
)
from PyQt5.QtCore import Qt
from qtui.cmd_log_widget import create_cmd_log


class ZoomableGraphicsView(QGraphicsView):
    """QGraphicsView that supports zooming with the mouse wheel"""
    def __init__(self, parent=None):
        super().__init__(parent)
        # Enable dragging (panning) with mouse
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setInteractive(True)
    
    def wheelEvent(self, event):
        zoomInFactor = 1.25
        zoomOutFactor = 1 / zoomInFactor
        # Zoom in or out
        if event.angleDelta().y() > 0:
            self.scale(zoomInFactor, zoomInFactor)
        else:
            self.scale(zoomOutFactor, zoomOutFactor)


class SOCLayout:
    """
    Layout for SIEM/SOC mode: dashboard of security alerts and logs.
    """
    def build(self):
        widget = QWidget()
        main_layout = QVBoxLayout(widget)

        # Top navigation buttons (no Settings button)
        nav_layout = QHBoxLayout()
        live_btn = QPushButton('Live Monitoring')
        sched_btn = QPushButton('Scheduled Scanning')
        for btn in (live_btn, sched_btn):
            btn.setCheckable(True)
            nav_layout.addWidget(btn)
        nav_layout.addStretch()
        main_layout.addLayout(nav_layout)

        # Network map area
        map_group = QGroupBox('Network Map')
        map_layout = QVBoxLayout()
        # Placeholder for graphic view with zoom
        map_view = ZoomableGraphicsView()
        map_layout.addWidget(map_view)
        map_group.setLayout(map_layout)
        main_layout.addWidget(map_group, stretch=2)

        # Logs and alerts table
        log_group = QGroupBox('Logs and Alerts')
        log_layout = QVBoxLayout()
        # Columns: Time, Event, Severity, Source IP, Destination IP, Confidence
        log_table = QTableWidget(0, 6)
        log_table.setHorizontalHeaderLabels([
            'Time', 'Event', 'Severity', 'Source', 'Destination', 'Confidence'
        ])
        log_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        log_layout.addWidget(log_table)

        # Action buttons
        act_layout = QHBoxLayout()
        export_btn = QPushButton('Export to SIEM')
        email_btn = QPushButton('Email Notifications')
        report_btn = QPushButton('Generate PDF Report')
        act_layout.addWidget(export_btn)
        act_layout.addWidget(email_btn)
        act_layout.addWidget(report_btn)
        act_layout.addStretch()
        log_layout.addLayout(act_layout)

        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group, stretch=1)
        # Command log styled like other tabs
        cmd_log = create_cmd_log()
        main_layout.addWidget(cmd_log)

        return widget, {
            'live_btn': live_btn,
            'scheduled_btn': sched_btn,
            'map_view': map_view,
            'log_table': log_table,
            'export_btn': export_btn,
            'email_btn': email_btn,
            'report_btn': report_btn,
            'cmd_log': cmd_log
        }
