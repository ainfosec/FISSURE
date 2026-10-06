"""FISSURE Action exposure for the APRS receiver; implementation is in operations/."""

from typing import Any, Dict

from fissure.Sensor_Node.SensorNode import SensorNode


PLUGIN_NAME = "APRS"

ACTION_TAGS = {
    "aprs_monitor": [
        "All", "APRS", "tsi.detector", "tsi.detector.type.rf",
        "tsi.detector.mode.fixed", "tactical.detection",
    ],
}

ACTION_HARDWARE = {"aprs_monitor": ["RTL2832U"]}

_COMMON = [
    {"name": "log_artifact", "label": "Log Packet Artifact", "type": "string",
     "default": "false", "options": ["true", "false"]},
    {"name": "emit_targets", "label": "Create/Update Station Targets", "type": "string",
     "default": "true", "options": ["true", "false"]},
]


aprs_monitor_schema = {
    "params": [
        {"name": "rtl_device", "label": "RTL-SDR Device Index / Serial", "type": "string", "default": "0"},
        {"name": "rtl_gain_db", "label": "RTL-SDR Gain dB (blank = auto)", "type": "string", "default": ""},
    ] + _COMMON,
}


async def aprs_monitor(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(
        component, PLUGIN_NAME, "aprs_monitor.py",
        {**dict(parameters or {}), "input_mode": "rtl"}, node_uid,
    )
