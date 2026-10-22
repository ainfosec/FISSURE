#!/usr/bin/env python3
"""FISSURE Action routing: Full Scan (legacy name) and HD Radio Quick Scan."""
from typing import Any, Dict

from fissure.Sensor_Node.SensorNode import SensorNode


PLUGIN_NAME = "HD-Radio"

ACTION_TAGS = {
    "scan_hd_radio": ["All", "sa.survey"],
    "hd_radio_quick_scan": ["All", "sa.survey"],
}

ACTION_HARDWARE = {
    "scan_hd_radio": ["RTL2832U"],
    "hd_radio_quick_scan": ["RTL2832U"],
}

scan_hd_radio_schema = {
    "params": [
        {"name": "start_frequency_mhz", "label": "Start FM Frequency (MHz)", "type": "number", "default": 88.1, "min": 88.1, "max": 107.9, "step": 0.2, "decimals": 1},
        {"name": "stop_frequency_mhz", "label": "Stop FM Frequency (MHz)", "type": "number", "default": 107.9, "min": 88.1, "max": 107.9, "step": 0.2, "decimals": 1},
        {"name": "sdr_index", "label": "RTL-SDR Device (index)", "type": "number", "default": 0, "min": 0, "max": 31, "step": 1, "decimals": 0},
        {"name": "gain_db", "label": "RTL-SDR Gain (dB; -1 = Auto)", "type": "number", "default": -1, "min": -1, "max": 50, "step": 0.1, "decimals": 1},
        {"name": "acquisition_time_s", "label": "Time per Channel (s)", "type": "number", "default": 15, "min": 3, "max": 120, "step": 1, "decimals": 0},
    ]
}

hd_radio_quick_scan_schema = {
    "params": [
        {"name": "start_frequency_mhz", "label": "Start FM Frequency (MHz)", "type": "number", "default": 88.1, "min": 88.1, "max": 107.9, "step": 0.2, "decimals": 1},
        {"name": "stop_frequency_mhz", "label": "Stop FM Frequency (MHz)", "type": "number", "default": 107.9, "min": 88.1, "max": 107.9, "step": 0.2, "decimals": 1},
        {"name": "sdr_index", "label": "RTL-SDR Device (index)", "type": "number", "default": 0, "min": 0, "max": 31, "step": 1, "decimals": 0},
        {"name": "gain_db", "label": "RTL-SDR Gain (dB; -1 = Auto)", "type": "number", "default": -1, "min": -1, "max": 50, "step": 0.1, "decimals": 1},
        {"name": "acquisition_time_s", "label": "Time per Channel (s)", "type": "number", "default": 7, "min": 3, "max": 120, "step": 1, "decimals": 0},
        {"name": "max_candidates", "label": "Max Frequencies to Check (0 = all)", "type": "number", "default": 40, "min": 0, "max": 100, "step": 1, "decimals": 0},
    ]
}


async def scan_hd_radio(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    """HD Radio Full Scan — preserve the original Action and its parameters."""
    await component.run_plugin_operation(component, PLUGIN_NAME, "scan_hd_radio.py", parameters, node_uid)


async def hd_radio_quick_scan(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    """HD Radio Quick Scan — survey analog occupancy then decode candidates."""
    await component.run_plugin_operation(component, PLUGIN_NAME, "scan_hd_radio_quick.py", parameters, node_uid)
