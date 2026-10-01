#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""ADS-B Plugin Actions."""

from typing import Any, Dict

from fissure.Sensor_Node.SensorNode import SensorNode


PLUGIN_NAME = "ADS-B"


ACTION_TAGS = {
    "ads_b_aircraft_tracker": [
        "All",
        "ADS-B",
        "Mode S",
        "tactical.detection",
    ],
    "ads_b_aircraft_logger": [
        "All",
        "ADS-B",
        "Mode S",
    ],
}


ACTION_HARDWARE = {
    "ads_b_aircraft_tracker": ["RTL2832U"],
    "ads_b_aircraft_logger": ["RTL2832U"],
}


_COMMON_PARAMS = [
    {
        "name": "device_index",
        "label": "RTL-SDR Device Index",
        "type": "number",
        "default": 0,
        "min": 0,
        "step": 1,
    },
    {
        "name": "status_interval_s",
        "label": "Status Interval (s)",
        "type": "number",
        "default": 5.0,
        "min": 1.0,
        "max": 300.0,
        "step": 1.0,
    },
]


ads_b_aircraft_tracker_schema = {
    "params": _COMMON_PARAMS + [
        {
            "name": "poll_interval_s",
            "label": "ADS-B Poll Interval (s)",
            "type": "number",
            "default": 1.0,
            "min": 0.25,
            "max": 30.0,
            "step": 0.25,
        },
        {
            "name": "emit_interval_s",
            "label": "Aircraft Update Interval (s)",
            "type": "number",
            "default": 1.0,
            "min": 0.25,
            "max": 60.0,
            "step": 0.25,
            "description": "Minimum time between FISSURE updates for the same aircraft.",
        },
    ]
}


async def ads_b_aircraft_tracker(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"ADS-B Aircraft Tracker action with parameters: {parameters}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "ads_b_aircraft_tracker.py",
        dict(parameters or {}),
        node_uid,
    )


ads_b_aircraft_logger_schema = {
    "params": _COMMON_PARAMS + [
        {
            "name": "duration_s",
            "label": "Duration (s)",
            "type": "number",
            "default": 60.0,
            "min": 1.0,
            "max": 86400.0,
            "step": 1.0,
        },
        {
            "name": "poll_interval_s",
            "label": "Log Interval (s)",
            "type": "number",
            "default": 1.0,
            "min": 0.25,
            "max": 30.0,
            "step": 0.25,
        },
        {
            "name": "artifact_name",
            "label": "Artifact Name",
            "type": "string",
            "default": "ADS-B Aircraft Log",
        },
    ]
}


async def ads_b_aircraft_logger(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"ADS-B Aircraft Logger action with parameters: {parameters}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "ads_b_aircraft_logger.py",
        dict(parameters or {}),
        node_uid,
    )
