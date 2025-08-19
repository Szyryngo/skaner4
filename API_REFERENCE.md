# API Reference for Skaner4

This document provides an overview of modules, classes, and key functions based on their docstrings.

---

## 1. Core Components (`core/`)

### core/config_manager.py
```python
"""Configuration Manager - load and save YAML configuration files."""
```
- Class `ConfigManager`
  - `__init__(config_path)`: Initialize with path to YAML file.
  - `load()`: Load configuration from file.
  - `save(config=None)`: Save configuration to file.

### core/device_discovery.py
```python
"""Device Discovery utilities - infer device types via nmap and update MAC prefix mapping."""
```
- `guess_type_from_nmap(ip)`: Perform Nmap scan to guess device type.
- `update_yaml(prefix, manufacturer, dtype)`: Update YAML mapping for OUI prefixes.
- `discover_and_update(ip, mac, prefix, manufacturer, callback=None)`: Discover type and update mapping.

### core/events.py
```python
"""Event system module - define Event class for inter-module communication."""
```
- Class `Event(event_type, data=None)`: Carries type and payload between components.

### core/interfaces.py
```python
"""Core interfaces module - define base class for application modules and plugins."""
```
- Class `ModuleBase`
  - `initialize(config)`, `handle_event(event)`, `generate_event()`.

### core/plugin_loader.py
```python
"""Plugin Loader - load and initialize plugins defined in YAML configuration."""
```
- `load_plugins(config_path, plugins_dir)`: Load and return plugin instances.

---

## 2. Functional Modules (`modules/`)

### modules/capture.py
```python
"""Capture Module - capture network packets asynchronously and generate NEW_PACKET events."""
```
- Class `CaptureModule`
  - `test_all_interfaces()`: Sniff test on all interfaces.
  - `set_interface(iface)`: Change interface and restart sniffing.
  - `initialize(config)`: Set up packet capture parameters.
  - `_start_sniffing()`: Configure and start AsyncSniffer.
  - `set_filter(bpf)`: Update BPF filter.
  - `handle_event(event)`: No-op (passive sniffing).
  - `generate_event()`: Return `NEW_PACKET` event if available.

### modules/features.py
```python
"""Features Module - aggregate packets into flows and generate traffic features."""
```
- Class `FeaturesModule`
  - `initialize(config)`: Prepare flow aggregation.
  - `handle_event(event)`: Store packet for features.
  - `generate_event()`: Emit `NEW_FEATURES` event.

### modules/detection.py
```python
"""Detection Module - detect anomalies and classify threats using AI models and Snort rules."""
```
- Class `DetectionModule`
  - `initialize(config)`: Load AI models and Snort rules.
  - `handle_event(event)`: Collect SNORT_ALERT and process NEW_FEATURES.
  - `generate_event()`: Perform inference and emit `NEW_THREAT`.

### modules/devices.py
```python
"""Devices Module - track devices on the network and emit detection events."""
```
- Class `DevicesModule`
  - `initialize(config)`: Set up device tracking.
  - `handle_event(event)`: Handle `NEW_PACKET` and yield `DEVICE_DETECTED`.
  - `generate_event()`: Yield `DEVICE_INACTIVE` for timed-out hosts.

### modules/devices_sniffer.py
```python
"""Devices Sniffer Module - sniff ARP and IP packets in a background thread to detect devices."""
```
- Class `DevicesSniffer`
  - `start()`, `stop()`, `_sniff_loop()`, `_handle_packet(pkt)`.

### modules/devices_sniffer_module.py
```python
"""Devices Sniffer Module - integrate DevicesSniffer into orchestrator as a ModuleBase."""
```
- Class `DevicesSnifferModule`
  - `initialize(config)`, `set_interface(iface)`, `_on_device_detected(event)`, `generate_event()`.

### modules/netif.py
```python
"""Network Interface utilities - list system network interfaces."""
```
- `list_interfaces()`: Return list of interface names.

### modules/netif_pretty.py
```python
"""Pretty Network Interface utilities - generate user-friendly interface listings."""
```
- `_iface_type_label(iface)`: Label interface type.
- `get_interfaces_pretty()`: Return pretty interface tuples.

### modules/optimizer.py
```python
"""Optimizer Module - analyze host resources and adjust application configuration."""
```
- Class `OptimizerModule`
  - `initialize(config)`, `handle_event(event)`, `generate_event()`.

### modules/scanner.py
```python
"""Scanner Module - perform network scans on demand and report results."""
```
- Class `ScannerModule`
  - `initialize(config)`, `handle_event(event)`, `generate_event()`.

### modules/ui.py
```python
"""UI Module - provide a Flask-based web dashboard for Skaner4."""
```
- Class `UIModule`
  - `_get_real_interfaces()`, `initialize(config)`, `_setup_routes()`, `generate_event()`, `_render_nav()`, `_run_flask()`, `handle_event(event)`.

---

## 3. Plugins (`plugins/`)

### plugins/example_plugin.py
```python
"""Example Plugin - sample plugin demonstrating how to react to NEW_THREAT events."""
```
- Class `ExamplePlugin`
  - `initialize(config)`, `handle_event(event)`, `generate_event()`.

### plugins/snort_rules_plugin.py
```python
"""Snort Rules Plugin - detect Snort rule matches in captured packets."""
```
- Class `SnortRulesPlugin`
  - `__init__()`, `initialize(config)`, `handle_event(event)`, `disable_rule(sid)`, `reload_rules()`, `_load_rules()`.

---

## 4. GUI Components (`qtui/`)

### qtui/main_window.py
```python
"""MainWindow module - define the primary Qt window with tabs and system metrics toolbar."""
```
- Class `MainWindow`
  - `__init__()`, `_update_metrics()`, `_cleanup()`, `closeEvent(event)`.

### qtui/snort_rules_tab.py
```python
"""UI Tab for Snort Rules - display and manage Snort rule states via table."""
```
- Class `SnortRulesTab`
  - `__init__(plugins, parent)`.

### qtui/soc_layout.py
```python
"""SOC Layout module - build the SIEM/SOC dashboard UI layout using PyQt5 widgets and Matplotlib."""
```
- Class `ZoomableGraphicsView`
  - `__init__(parent)`, `wheelEvent(event)`.
- Class `SOCLayout`
  - `build()`.

### qtui/soc_tab.py
```python
"""SOC Tab module - coordinate background processing of events and update SOC UI."""
```
- Class `SOCWorker`
  - `__init__(capture, features, detection, snort_plugins)`, `run()`.
- Class `SOCTab`
  - `__init__(parent)`, `_on_raw_event(event)`, `_on_ai_score(event)`, `_on_worker_threat(event)`, `_toggle_live()`, `_toggle_scheduled()`, `_export_siem()`, `_stop_worker_thread()`.

---

## 5. Scripts and Tools (`scripts/`, `tools/`)

- `scripts/add_docstrings.py`: Insert placeholder docstrings in Python files.
- `tools/add_numpy_docstrings.py`: Add NumPy-style docstring stubs.
- `scripts/sort_mac_devices.py`: Sort MAC prefix mapping YAML.
- `scripts/update_mac_devices.py`: Fetch and update OUI registry.
- `analyze_nn_model.py`: Print neural network model summary.
- `test_ifaces.py`: CLI test for interface listing.

---

*Generated from docstrings for complete project overview.*
