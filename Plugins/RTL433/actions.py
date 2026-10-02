"""Expose the 433 MHz Device Monitor through FISSURE Tactical Actions."""
from typing import Any, Dict

from fissure.Sensor_Node.SensorNode import SensorNode


PLUGIN_NAME = "RTL433"

ACTION_TAGS = {
    "device_monitor_433mhz": [
        "All", "tactical.detection", "tsi.detector", "tsi.detector.type.rf",
        "tsi.detector.mode.continuous", "protocol.iot", "frequency.433mhz",
    ],
}

ACTION_HARDWARE = {
    "device_monitor_433mhz": ["RTL2832U"],
}

device_monitor_433mhz_schema = {
    "params": [
        {"name": "sdr_device", "label": "RTL-SDR Index or :Serial", "type": "string", "default": "0"},
        {"name": "frequency_mhz", "label": "Center Frequency (MHz)", "type": "number", "default": 433.92,
         "min": 1, "max": 2000, "decimals": 4},
        {"name": "sample_rate_hz", "label": "Sample Rate (Hz)", "type": "number", "default": 250000,
         "min": 200000, "max": 3200000},
        {"name": "gain_db", "label": "RTL-SDR Gain (dB; auto or number)", "type": "string", "default": "auto"},
        {"name": "ppm", "label": "Frequency Correction (PPM)", "type": "number", "default": 0},
        {"name": "status_interval_s", "label": "Status Interval (s)", "type": "number", "default": 5,
         "min": 1, "max": 300},
        {"name": "detection_interval_s", "label": "Seconds Between Detections per Device (0=all)",
         "type": "number", "default": 10, "min": 0, "max": 3600},
        {"name": "save_artifact", "label": "Save Artifact", "type": "string", "default": "false",
         "options": ["false", "true"]},
    ],
}


async def device_monitor_433mhz(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    """Start exactly one FISSURE-managed long-running Operation."""
    await component.run_plugin_operation(
        component, PLUGIN_NAME, "device_monitor_433mhz.py", dict(parameters or {}), node_uid,
    )
