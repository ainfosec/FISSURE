#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""X10 Plugin Actions"""

from typing import Any, Dict

from fissure.Sensor_Node.SensorNode import SensorNode


PLUGIN_NAME = "X10"


ACTION_TAGS = {
    "x10_ook_field_fuzzer": [
        "All",
        "fuzzing.data",
        "ui.fuzzing",
        "protocol.x10",
    ],
}


ACTION_HARDWARE = {
    "x10_ook_field_fuzzer": [
        "USRP B20xmini",
        "USRP B2x0",
    ],
}


x10_ook_field_fuzzer_schema = {
    "params": [
        {"name": "tx_frequency_mhz", "label": "Frequency (MHz)", "type": "number", "default": 310.7, "min": 1.0, "max": 6000.0, "step": 0.1, "decimals": 6},
        {"name": "sample_rate_msps", "label": "Sample Rate (MS/s)", "type": "number", "default": 1.0, "min": 0.1, "max": 61.44, "step": 0.1, "decimals": 6},
        {"name": "tx_gain", "label": "TX Gain", "type": "number", "default": 60.0, "min": 0.0, "max": 100.0, "step": 1.0, "decimals": 1},
        {"name": "tx_channel", "label": "TX Channel", "type": "string", "default": "A:A"},
        {"name": "transmit_interval_s", "label": "Transmit Interval (s)", "type": "number", "default": 4.0, "min": 0.1, "max": 3600.0, "step": 0.1, "decimals": 3},
    ]
}


async def x10_ook_field_fuzzer(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"X10 OOK Field Fuzzer action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "x10_ook_field_fuzzer.py", parameters, node_uid)