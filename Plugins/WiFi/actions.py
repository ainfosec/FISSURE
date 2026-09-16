#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wi-Fi Plugin Actions"""

from typing import Any, Dict

from fissure.Sensor_Node.SensorNode import SensorNode
from fissure.utils.hardware import get_default_wifi_interface


PLUGIN_NAME = "WiFi"


ACTION_TAGS = {
    "wifi_discovery_edge_light": ["All", "WiFi", "802.11x"],
    "wifi_discovery_edge_oui": ["All", "WiFi", "802.11x"],
    "wifi_discovery_edge_logger": ["All", "WiFi", "802.11x"],
    "wifi_geolocate_target": ["All", "WiFi", "802.11x"],
    "wifi_geolocate_all": ["All", "WiFi", "802.11x"],
}


ACTION_HARDWARE = {
    "wifi_discovery_edge_light": ["802.11x Adapter"],
    "wifi_discovery_edge_oui": ["802.11x Adapter"],
    "wifi_discovery_edge_logger": ["802.11x Adapter"],
    "wifi_geolocate_target": ["802.11x Adapter"],
    "wifi_geolocate_all": ["802.11x Adapter"],
}


_COMMON_WIFI_PARAMS = [
    {
        "name": "wifi_interface",
        "label": "Wi-Fi Interface",
        "type": "string",
        "default": "",
    },
]


wifi_discovery_edge_light_schema = {
    "params": _COMMON_WIFI_PARAMS + [
        {
            "name": "scan_interval_s",
            "label": "Scan Refresh Interval (s)",
            "type": "number",
            "default": 0.5,
        },
        {
            "name": "reemit_interval_s",
            "label": "BSSID Re-emit Interval (s)",
            "type": "number",
            "default": 15.0,
        },
        {
            "name": "alert_on_new_detection",
            "label": "Alert on New BSSID",
            "type": "string",
            "default": "false",
            "options": ["true", "false"],
        },
    ]
}
async def wifi_discovery_edge_light(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"WiFi light discovery action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    if not str(op_params.get("wifi_interface") or "").strip():
        op_params["wifi_interface"] = get_default_wifi_interface(
            getattr(component, "settings_dict", {}) or {}
        )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "wifi_discovery_edge_light.py",
        {"parameters": op_params},
        node_uid,
    )


wifi_discovery_edge_oui_schema = {
    "params": _COMMON_WIFI_PARAMS + [
        {
            "name": "oui_filter",
            "label": "Wi-Fi Filter",
            "type": "string",
            "default": "00:11:22",
        },
        {
            "name": "scan_interval_s",
            "label": "Scan Refresh Interval (s)",
            "type": "number",
            "default": 0.5,
        },
        {
            "name": "reemit_interval_s",
            "label": "BSSID Re-emit Interval (s)",
            "type": "number",
            "default": 15.0,
        },
        {
            "name": "auto_create_targets",
            "label": "Auto-create Matching Targets",
            "type": "string",
            "default": "false",
            "options": ["true", "false"],
        },
        {
            "name": "alert_on_new_detection",
            "label": "Alert on New Match",
            "type": "string",
            "default": "false",
            "options": ["true", "false"],
        },
    ]
}
async def wifi_discovery_edge_oui(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"WiFi OUI discovery action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    if not str(op_params.get("wifi_interface") or "").strip():
        op_params["wifi_interface"] = get_default_wifi_interface(
            getattr(component, "settings_dict", {}) or {}
        )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "wifi_discovery_edge_oui.py",
        {"parameters": op_params},
        node_uid,
    )



wifi_discovery_edge_logger_schema = {
    "params": _COMMON_WIFI_PARAMS + [
        {
            "name": "scan_interval_s",
            "label": "Scan Refresh Interval (s)",
            "type": "number",
            "default": 0.5,
        },
        {
            "name": "observation_interval_s",
            "label": "BSSID Observation Interval (s)",
            "type": "number",
            "default": 2.0,
        },
        {
            "name": "batch_unique_devices",
            "label": "Batch Unique BSSIDs",
            "type": "number",
            "default": 500,
        },
        {
            "name": "batch_observation_rows",
            "label": "Batch Observation Rows",
            "type": "number",
            "default": 5000,
        },
        {
            "name": "batch_duration_s",
            "label": "Batch Duration (s)",
            "type": "number",
            "default": 300.0,
        },
        {
            "name": "alert_every_unique",
            "label": "Summary Alert Every Unique BSSIDs (0=Off)",
            "type": "number",
            "default": 0,
        },
        {
            "name": "alert_on_batch",
            "label": "Alert When Batch Saved",
            "type": "string",
            "default": "false",
            "options": ["true", "false"],
        },
        {
            "name": "artifact_name_prefix",
            "label": "Artifact Name Prefix",
            "type": "string",
            "default": "Wi-Fi Wardrive Batch",
        },
    ]
}
async def wifi_discovery_edge_logger(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"WiFi wardrive logger action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    if not str(op_params.get("wifi_interface") or "").strip():
        op_params["wifi_interface"] = get_default_wifi_interface(
            getattr(component, "settings_dict", {}) or {}
        )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "wifi_discovery_edge_logger.py",
        {"parameters": op_params},
        node_uid,
    )


wifi_geolocate_target_schema = {
    "params": _COMMON_WIFI_PARAMS + [
        {
            "name": "target_id",
            "label": "Target ID",
            "type": "string",
            "default": "",
        },
        {
            "name": "emit_every_s",
            "label": "Emit Interval (s)",
            "type": "number",
            "default": 1.0,
        },
        {
            "name": "meas_every_s",
            "label": "Measurement Interval (s)",
            "type": "number",
            "default": 0.2,
        },
        {
            "name": "aggregation_window_s",
            "label": "RSSI Median Window (s)",
            "type": "number",
            "default": 3.0,
        },
        {
            "name": "search_similar_targets",
            "label": "Search Similar Targets",
            "type": "string",
            "default": "false",
            "options": ["true", "false"],
        },
    ]
}
async def wifi_geolocate_target(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"WiFi target geolocation action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    if not str(op_params.get("wifi_interface") or "").strip():
        op_params["wifi_interface"] = get_default_wifi_interface(
            getattr(component, "settings_dict", {}) or {}
        )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "wifi_geolocate_target.py",
        {"parameters": op_params},
        node_uid,
    )


wifi_geolocate_all_schema = {
    "params": _COMMON_WIFI_PARAMS + [
        {
            "name": "max_targets",
            "label": "Max Auto-created Targets (0 = unlimited)",
            "type": "number",
            "default": 25,
        },
        {
            "name": "emit_every_s",
            "label": "Observation Emit Interval (s)",
            "type": "number",
            "default": 1.0,
        },
        {
            "name": "meas_every_s",
            "label": "Scan Refresh Interval (s)",
            "type": "number",
            "default": 0.5,
        },
        {
            "name": "aggregation_window_s",
            "label": "RSSI Median Window (s)",
            "type": "number",
            "default": 3.0,
        },
    ]
}
async def wifi_geolocate_all(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"WiFi geolocate all action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    if not str(op_params.get("wifi_interface") or "").strip():
        op_params["wifi_interface"] = get_default_wifi_interface(
            getattr(component, "settings_dict", {}) or {}
        )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "wifi_geolocate_all.py",
        {"parameters": op_params},
        node_uid,
    )
