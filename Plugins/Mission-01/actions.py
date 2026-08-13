#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mission-01 Plugin Actions

Example mission plugin showing two ways to provide actions:

1. Reuse an action that already exists in another plugin.
2. Define a new action that belongs specifically to this mission.

Existing actions should be delegated instead of copied. This keeps their
schemas, tags, hardware support, validation, and implementations synchronized
with the source plugin.
"""

from typing import Any, Dict

from fissure.Sensor_Node.SensorNode import SensorNode
from fissure.utils.plugin import register_delegated_actions


PLUGIN_NAME = "Mission-01"


# =============================================================================
# REUSE ACTIONS FROM OTHER PLUGINS
# =============================================================================
#
# To expose an action that already exists in another plugin, add ONE line:
#
#     "action_name": "SourcePlugin",
#
# Example:
#
#     "iq_record": "Base",
#
# The source plugin remains the single source of truth for that action's:
# - schema
# - tags
# - hardware compatibility
# - validation and parameter handling
# - operation behavior
#
# Do not copy the source action or schema into Mission-01.
# =============================================================================

DELEGATED_ACTIONS = {
    # WiFi
    "wifi_discovery_edge_light": "WiFi",
    "wifi_discovery_edge_oui": "WiFi",
    "wifi_discovery_edge_logger": "WiFi",
    "wifi_geolocate_target": "WiFi",
    "wifi_geolocate_all": "WiFi",

    # Base RF / Geolocation
    "signal_geolocate": "Base",
    "lfm_beacon_geolocate": "Base",
    "usrp_b2x0_geolocate": "Base",

    # Base Detection
    "fixed_detection": "Base",
    "scan_detection": "Base",
    "hackrf_sweep_detection": "Base",
    "rtl_power_detection": "Base",
    "lfm_beacon_detection": "Base",

    # Base Trigger-Style Detectors
    "sensor_node_time": "Base",
    "timer": "Base",
    "sound_threshold": "Base",
    "file_modified": "Base",
    "folder_modified": "Base",
    "temperature": "Base",
    "weather": "Base",
    "wind": "Base",
    "sunrise_sunset": "Base",
    "detect_ssid": "Base",
    "gps_point": "Base",
    "gps_line": "Base",
    "x10_demod": "Base",
    "plane_spotting": "Base",
    "rds_keyword": "Base",
    "cellular_tower": "Base",
    "webserver_curl": "Base",

    # Base IQ Data
    "iq_record": "Base",
    "iq_playback": "Base",

    # Base SOI / Processing
    "promote_to_soi": "Base",

    # Dummy / Testing
    "dummy_artifact": "Dummy",
    "dummy_alert": "Dummy",
    "dummy_alert_burst": "Dummy",
    "dummy_detection": "Dummy",
    "dummy_soi": "Dummy",
    "dummy_target": "Dummy",
    "dummy_status": "Dummy",
    "dummy_cot_types": "Dummy",

    # Base Camera / Physical
    "take_photo": "Base",
    "motion_detector": "Base",
    "take_video": "Base",
}


# These receive inherited metadata for delegated actions.
# Mission-owned actions can add their own entries below.
ACTION_TAGS = {}
ACTION_HARDWARE = {}


register_delegated_actions(
    globals(),
    DELEGATED_ACTIONS,
)


# =============================================================================
# DEFINE NEW ACTIONS FOR THIS PLUGIN
# =============================================================================
#
# Put an action here when the behavior is unique to Mission-01 and does not
# already belong in another plugin.
#
# A normal mission-owned action uses the same pattern as any other FISSURE
# plugin:
#
#   1. Add ACTION_TAGS.
#   2. Add ACTION_HARDWARE only when hardware is required.
#   3. Add <action_name>_schema when parameters are customizable.
#   4. Define async def <action_name>(...).
#   5. Add a Mission-01 operation when the action needs one.
#
# Copy the example below as a starting point.
# =============================================================================


# -----------------------------------------------------------------------------
# Mission-owned action example
# -----------------------------------------------------------------------------
#
# ACTION_TAGS["mission_example"] = [
#     "All",
#     "mission.example",
# ]
#
#
# ACTION_HARDWARE["mission_example"] = [
#     "USRP B20xmini",
#     "USRP B2x0",
# ]
#
#
# mission_example_schema = {
#     "params": [
#         {
#             "name": "description",
#             "label": "Description",
#             "type": "string",
#             "default": "Mission-01 example",
#         },
#     ]
# }
#
#
# async def mission_example(
#     component: SensorNode,
#     parameters: Dict[str, Any],
#     node_uid: str = "",
# ) -> None:
#     component.logger.info(
#         f"Mission-01 example action with parameters: {parameters}"
#     )
#
#     await component.run_plugin_operation(
#         component,
#         PLUGIN_NAME,
#         "mission_example.py",
#         parameters,
#         node_uid,
#     )
#
#
# Optional capability tags:
#
#     "client.dashboard"
#     "client.tak"
#     "node.local"
#     "node.remote"
#
# No client.* tags means the action is available to all clients.
# No node.* tags means the action is available on local and remote nodes.
# -----------------------------------------------------------------------------