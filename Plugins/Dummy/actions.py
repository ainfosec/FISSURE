#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dummy Plugin Actions"""

from typing import Any, Dict, Union

from fissure.Sensor_Node.SensorNode import SensorNode


PLUGIN_NAME = "Dummy"


ACTION_TAGS = {
    "dummy_artifact": ["All"],
    "dummy_alert": ["All"],
    "dummy_alert_burst": ["All"],
    "dummy_detection": [
        "All",
        "tsi.detector",
        "tsi.detector.type.rf",
        "tsi.detector.mode.simulation",
        "tsi.detector.view.rf_raster",
        "tactical.detection",
    ],
    "dummy_soi": ["All"],
    "dummy_target": ["All"],
    "dummy_status": ["All"],
    "dummy_cot_types": ["All"],
}


dummy_artifact_schema = {
    "params": [
        {"name": "file_count", "label": "File Count", "type": "number", "default": 3},
        {"name": "file_size_kb", "label": "File Size (KB)", "type": "number", "default": 64},
        {"name": "description", "label": "Description", "type": "string", "default": "Create a dummy zip artifact"},
    ]
}

async def dummy_artifact(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(f"Dummy Artifact action with parameters: {parameters}")

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "dummy_artifact.py",
        parameters,
        node_uid,
    )


dummy_alert_schema = {
    "params": [
        {"name": "period_s", "label": "Period (s)", "type": "number", "default": 60.0},
        {"name": "uid", "label": "TAK UID", "type": "string", "default": "dummy_alert"},
        {"name": "description", "label": "Description", "type": "string", "default": "Periodic dummy alert"},
        {
            "name": "plot_pin",
            "label": "Plot as Pin",
            "type": "string",
            "default": "true",
            "options": ["true", "false"],
        },
    ]
}

async def dummy_alert(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(f"Dummy Alert action with parameters: {parameters}")

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "dummy_alert.py",
        parameters,
        node_uid,
    )


dummy_alert_burst_schema = {
    "params": [
        {"name": "interval_seconds", "label": "Interval (s)", "type": "number", "default": 10},
        {"name": "count", "label": "Count", "type": "number", "default": 10},
        {
            "name": "plot_pin",
            "label": "Plot as Pin",
            "type": "string",
            "default": "true",
            "options": ["true", "false"],
        },
        {"name": "description", "label": "Description", "type": "string", "default": "Dummy alert burst"},
    ]
}

async def dummy_alert_burst(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(f"Dummy Alert Burst action with parameters: {parameters}")

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "dummy_alert_burst.py",
        parameters,
        node_uid,
    )


dummy_detection_schema = {
    "params": [
        {"name": "period_s", "label": "Period (s)", "type": "number", "default": 60.0},
        {"name": "freq_mhz", "label": "Frequency (MHz)", "type": "number", "default": 915.0},
        {"name": "power_dbm", "label": "Power (dBm)", "type": "number", "default": -40.0},
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Periodic simulated RF detection for testing detector workflows",
        },
    ]
}

async def dummy_detection(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(f"Dummy Detection action with parameters: {parameters}")

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "dummy_detection.py",
        parameters,
        node_uid,
    )


dummy_soi_schema = {
    "params": [
        {"name": "frequency_mhz", "label": "Frequency (MHz)", "type": "number", "default": 915.0},
        {"name": "model_label", "label": "Model Label", "type": "string", "default": "dummy_protocol"},
        {"name": "model_confidence", "label": "Model Confidence (%)", "type": "number", "default": 87},
        {"name": "description", "label": "Description", "type": "string", "default": "Dummy SOI"},
    ]
}

async def dummy_soi(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(f"Dummy SOI action with parameters: {parameters}")

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "dummy_soi.py",
        parameters,
        node_uid,
    )


dummy_target_schema = {
    "params": [
        {
            "name": "target_id",
            "label": "Existing Target ID",
            "type": "string",
            "default": "",
            "description": (
                "Leave blank to create a new Target. "
                "Enter an existing Target ID to append "
                "another artifact and history entry."
            ),
        },
        {
            "name": "source_soi_id",
            "label": "Source SOI ID",
            "type": "string",
            "default": "",
            "description": (
                "Optional link to the SOI that identified "
                "this Target."
            ),
        },
        {
            "name": "frequency_mhz",
            "label": "Frequency (MHz)",
            "type": "number",
            "default": 315.0,
        },
        {
            "name": "display_label",
            "label": "Display Label",
            "type": "string",
            "default": "Garage Door Opener",
            "options": [
                "Garage Door Opener",
                "Key Fob",
                "TPMS",
                "Wireless Camera",
                "Weather Station",
                "Wi-Fi Access Point",
                "Unknown",
            ],
        },
        {
            "name": "protocol",
            "label": "Protocol",
            "type": "string",
            "default": "OOK",
        },
        {
            "name": "subtype",
            "label": "Subtype",
            "type": "string",
            "default": "Fixed Code Remote",
        },
        {
            "name": "manufacturer",
            "label": "Manufacturer",
            "type": "string",
            "default": "FISSURE Test Devices",
        },
        {
            "name": "model",
            "label": "Model",
            "type": "string",
            "default": "DT-315",
        },
        {
            "name": "device_id",
            "label": "Device ID",
            "type": "string",
            "default": "DUMMY-315-0001",
        },
        {
            "name": "serial_number",
            "label": "Serial Number",
            "type": "string",
            "default": "SN-DUMMY-0001",
        },
        {
            "name": "channel",
            "label": "Channel",
            "type": "number",
            "default": 1,
        },
        {
            "name": "state",
            "label": "State",
            "type": "string",
            "default": "active",
            "options": [
                "detected",
                "active",
                "monitoring",
                "inactive",
                "lost",
            ],
        },
        {
            "name": "confidence_pct",
            "label": "Confidence (%)",
            "type": "number",
            "default": 96.0,
            "min": 0,
            "max": 100,
        },
        {
            "name": "rssi_dbm",
            "label": "RSSI (dBm)",
            "type": "number",
            "default": -43.5,
        },
        {
            "name": "ce_m",
            "label": "CE (m)",
            "type": "number",
            "default": 25.0,
        },
        {
            "name": "use_node_location",
            "label": "Use Current Node Location",
            "type": "string",
            "default": "true",
            "options": [
                "true",
                "false",
            ],
        },
        {
            "name": "observation_count",
            "label": "Observation Count",
            "type": "number",
            "default": 5,
            "min": 1,
            "max": 100,
        },
        {
            "name": "blob_size_kb",
            "label": "Sample Capture Size (KB)",
            "type": "number",
            "default": 128,
            "min": 1,
            "max": 10240,
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": (
                "Dummy Target reference implementation"
            ),
        },
    ]
}
async def dummy_target(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(f"Dummy Target action with parameters: {parameters}")

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "dummy_target.py",
        parameters,
        node_uid,
    )


dummy_status_schema = {
    "params": [
        {
            "name": "profile",
            "label": "Profile",
            "type": "string",
            "default": "phases",
            "options": [
                "phases",
                "processing",
                "busy",
                "idle",
            ],
        },
        {"name": "step_s", "label": "Step Duration (s)", "type": "number", "default": 2.0},
        {"name": "description", "label": "Description", "type": "string", "default": "Dummy Status"},
    ]
}

async def dummy_status(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(f"Dummy Status action with parameters: {parameters}")

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "dummy_status.py",
        parameters,
        node_uid,
    )


dummy_cot_types_schema = {
    "params": [
        {
            "name": "scope",
            "label": "Scope",
            "type": "string",
            "default": "b-*",
            "options": ["all", "a-*", "b-*"],
        },
        {
            "name": "limit_mode",
            "label": "Limit Mode",
            "type": "string",
            "default": "first_n",
            "options": ["all", "first_n"],
        },
        {
            "name": "first_n",
            "label": "First N",
            "type": "number",
            "default": 5,
        },
        {
            "name": "expand_dots",
            "label": "Expand '.' Wildcards",
            "type": "string",
            "default": "no",
            "options": ["yes", "no"],
        },
        {
            "name": "base_lat",
            "label": "Start Latitude",
            "type": "number",
            "default": 40.703052,
        },
        {
            "name": "base_lat",
            "label": "Base Latitude",
            "type": "number",
            "default": 42.0898,
            "min": -90,
            "max": 90,
            "decimals": 6,
        },
        {
            "name": "base_lon",
            "label": "Base Longitude",
            "type": "number",
            "default": -76.8077,
            "min": -180,
            "max": 180,
            "decimals": 6,
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Dummy CoT Types",
        },
    ]
}

async def dummy_cot_types(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(f"Dummy CoT Types action with parameters: {parameters}")

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "dummy_cot_types.py",
        parameters,
        node_uid,
    )