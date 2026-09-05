#! /usr/bin/env python3
# -*- coding: utf-8 -*-
"""Base Plugin Actions"""

import json
import os
import time
import uuid
from typing import Any, Dict, Union

from fissure.Sensor_Node.SensorNode import SensorNode
from fissure.utils import FISSURE_ROOT
import fissure.utils.hardware


PLUGIN_NAME = "Base"


ACTION_TAGS = {
    "signal_geolocate": ["All"],

    "fixed_detection": [
        "All",
        "tsi.detector",
        "tsi.detector.type.rf",
        "tsi.detector.mode.fixed",
        "tsi.detector.view.rf_raster",
        "tactical.detection",
    ],
    "scan_detection": [
        "All",
        "tsi.detector",
        "tsi.detector.type.rf",
        "tsi.detector.mode.sweep",
        "tsi.detector.view.rf_raster",
        "tactical.detection",
    ],
    "hackrf_sweep_detection": [
        "All",
        "tsi.detector",
        "tsi.detector.type.rf",
        "tsi.detector.mode.sweep",
        "tsi.detector.view.rf_raster",
        "tactical.detection",
    ],
    "rtl_power_detection": [
        "All",
        "tsi.detector",
        "tsi.detector.type.rf",
        "tsi.detector.mode.sweep",
        "tsi.detector.view.rf_raster",
        "tactical.detection",
    ],

    "lfm_beacon_detection": ["All"],
    "lfm_beacon_geolocate": ["All"],
    "usrp_b2x0_geolocate": ["All"],

    "iq_record": [
        "All",
        "iq.record",
        "sa.capture",
    ],
    "iq_playback": [
        "All",
        "iq.playback",
    ],
    "iq_inspection_live": [
        "All",
        "iq.inspection",
        "iq.inspection.source.radio",
        "sa.survey",
        "tactical.inspection",
        "client.dashboard",
        "node.local",
        "node.remote",
    ],
    "iq_inspection_file": [
        "All",
        "iq.inspection",
        "iq.inspection.source.file",
        "client.dashboard",
        "node.local",
    ],

    "promote_to_soi": ["All"],

    "take_photo": ["All"],
    "take_video": ["All"],

    "signal_conditioning": [
        "All",
        "tsi.conditioner",
        "tsi.conditioner.category.energy",
        "tsi.conditioner.method.normal_decay",
        "tsi.conditioner.source.frequencies",
    ],
    "signal_conditioning_file": [
        "All",
        "tsi.conditioner",
        "tsi.conditioner.category.energy",
        "tsi.conditioner.method.normal",
        "tsi.conditioner.method.normal_decay",
        "tsi.conditioner.method.power_squelch",
        "tsi.conditioner.method.lowpass",
        "tsi.conditioner.method.power_squelch_lowpass",
        "tsi.conditioner.method.bandpass",
        "tsi.conditioner.method.strongest_frequency_bandpass",
        "tsi.conditioner.source.file",
        "tsi.conditioner.source.folder",
    ],
    "feature_extract_time_domain": [
        "All",
        "tsi.feature_extractor",
        "tsi.feature_extractor.profile.time_domain",
        "tsi.feature_extractor.profile.all_available",
        "tsi.feature_extractor.source.file",
        "tsi.feature_extractor.source.folder",
    ],
    "feature_extract_frequency_domain": [
        "All",
        "tsi.feature_extractor",
        "tsi.feature_extractor.profile.frequency_domain",
        "tsi.feature_extractor.profile.all_available",
        "tsi.feature_extractor.source.file",
        "tsi.feature_extractor.source.folder",
    ],
    "feature_extract_time_frequency": [
        "All",
        "tsi.feature_extractor",
        "tsi.feature_extractor.profile.time_frequency",
        "tsi.feature_extractor.profile.all_available",
        "tsi.feature_extractor.source.file",
        "tsi.feature_extractor.source.folder",
    ],
    "feature_extract_custom": [
        "All",
        "tsi.feature_extractor",
        "tsi.feature_extractor.profile.custom",
        "tsi.feature_extractor.profile.all_available",
        "tsi.feature_extractor.source.file",
        "tsi.feature_extractor.source.folder",
    ],
    "sensor_node_time": [
        "All",
        "tsi.detector",
        "tsi.detector.type.time",
        "tsi.detector.mode.scheduled",
    ],
    "timer": [
        "All",
        "tsi.detector",
        "tsi.detector.type.time",
        "tsi.detector.mode.scheduled",
    ],
    "sound_threshold": [
        "All",
        "tsi.detector",
        "tsi.detector.type.sensor",
        "tsi.detector.mode.threshold",
    ],
    "file_modified": [
        "All",
        "tsi.detector",
        "tsi.detector.type.system",
        "tsi.detector.mode.change",
    ],
    "folder_modified": [
        "All",
        "tsi.detector",
        "tsi.detector.type.system",
        "tsi.detector.mode.change",
    ],
    "temperature": [
        "All",
        "tsi.detector",
        "tsi.detector.type.environmental",
        "tsi.detector.mode.threshold",
    ],
    "weather": [
        "All",
        "tsi.detector",
        "tsi.detector.type.environmental",
        "tsi.detector.mode.condition",
    ],
    "wind": [
        "All",
        "tsi.detector",
        "tsi.detector.type.environmental",
        "tsi.detector.mode.threshold",
    ],
    "sunrise_sunset": [
        "All",
        "tsi.detector",
        "tsi.detector.type.time",
        "tsi.detector.mode.scheduled",
    ],
    "detect_ssid": [
        "All",
        "tsi.detector",
        "tsi.detector.type.wifi",
        "tsi.detector.mode.presence",
    ],
    "motion_detector": [
        "All",
        "tsi.detector",
        "tsi.detector.type.sensor",
        "tsi.detector.mode.presence",
    ],
    "gps_point": [
        "All",
        "tsi.detector",
        "tsi.detector.type.location",
        "tsi.detector.mode.proximity",
    ],
    "gps_line": [
        "All",
        "tsi.detector",
        "tsi.detector.type.location",
        "tsi.detector.mode.boundary",
    ],
    "x10_demod": [
        "All",
        "tsi.detector",
        "tsi.detector.type.protocol",
        "tsi.detector.mode.match",
    ],
    "plane_spotting": [
        "All",
        "tsi.detector",
        "tsi.detector.type.rf",
        "tsi.detector.mode.presence",
    ],
    "rds_keyword": [
        "All",
        "tsi.detector",
        "tsi.detector.type.protocol",
        "tsi.detector.mode.match",
    ],
    "cellular_tower": [
        "All",
        "tsi.detector",
        "tsi.detector.type.rf",
        "tsi.detector.mode.presence",
    ],
    "webserver_curl": [
        "All",
        "tsi.detector",
        "tsi.detector.type.network",
        "tsi.detector.mode.request",
    ],
    "scapy_transmit": [
        "All",
        "scapy.transmit",
        "packet.transmit",
    ],
}


ACTION_HARDWARE = {
    "hackrf_sweep_detection": ["HackRF"],
    "rtl_power_detection": ["RTL2832U"],
    "signal_geolocate": ["USRP B20xmini", "USRP B2x0"],
    "fixed_detection": ["USRP B20xmini", "USRP B2x0"],
    "scan_detection": ["USRP B20xmini", "USRP B2x0"],
    "lfm_beacon_detection": ["RTL2832U"],
    "lfm_beacon_geolocate": ["RTL2832U"],
    "usrp_b2x0_geolocate": ["USRP B20xmini", "USRP B2x0"],
    "iq_record": [
        "USRP X3x0",
        "USRP B2x0",
        "HackRF",
        "RTL2832U",
        "USRP B20xmini",
        "LimeSDR",
        "bladeRF",
        "PlutoSDR",
        "USRP2",
        "USRP N2xx",
        "bladeRF 2.0",
        "USRP X410",
        "RSPduo",
        "RSPdx",
        "RSPdx R2",
        "CaribouLite",
    ],
    "iq_playback": [
        "USRP X3x0",
        "USRP B2x0",
        "HackRF",
        "USRP B20xmini",
        "LimeSDR",
        "bladeRF",
        "PlutoSDR",
        "USRP2",
        "USRP N2xx",
        "bladeRF 2.0",
        "USRP X410",
        "CaribouLite",
    ],
    "iq_inspection_live": [
        "USRP B20xmini",
        "USRP B2x0",
        "bladeRF",
        "bladeRF 2.0",
        "HackRF",
        "LimeSDR",
        "PlutoSDR",
        "RTL2832U",
        "USRP2",
        "USRP N2xx",
        "USRP X3x0",
        "USRP X410",
        "CaribouLite",
        "RSPduo",
        "RSPdx",
        "RSPdx R2",
    ],
    "signal_conditioning": ["USRP B20xmini", "USRP B2x0"],
    "x10_demod": ["USRP B20xmini", "USRP B2x0"],
    "rds_keyword": ["USRP B20xmini", "USRP B2x0"],
    "plane_spotting": ["RTL2832U"],
    "cellular_tower": ["RTL2832U"],
    "detect_ssid": ["802.11x Adapter"],

}


# =============================================================================
# Trigger-Style Detector Actions
# =============================================================================

sensor_node_time_schema = {
    "params": [
        {"name": "trigger_time", "label": "Trigger Time", "type": "string", "default": ""},
        {"name": "description", "label": "Description", "type": "string", "default": "Sensor Node time reached"},
    ]
}

async def sensor_node_time(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Sensor Node time action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "sensor_node_time.py", parameters, node_uid, wait=True)


timer_schema = {
    "params": [
        {"name": "timer_seconds", "label": "Timer (s)", "type": "number", "default": 10.0},
        {"name": "description", "label": "Description", "type": "string", "default": "Timer expired"},
    ]
}

async def timer(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Timer action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "timer.py", parameters, node_uid, wait=True)


sound_threshold_schema = {
    "params": [
        {"name": "get_threshold", "label": "Threshold", "type": "number", "default": 0.02},
        {"name": "get_duration", "label": "Sample Duration (s)", "type": "number", "default": 0.1},
        {"name": "get_sample_rate", "label": "Sample Rate (Hz)", "type": "number", "default": 44100.0},
        {"name": "warmup_s", "label": "Warmup (s)", "type": "number", "default": 0.0},
        {"name": "description", "label": "Description", "type": "string", "default": "Sound threshold exceeded"},
    ]
}

async def sound_threshold(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Sound threshold action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "sound_threshold.py", parameters, node_uid, wait=True)


file_modified_schema = {
    "params": [
        {"name": "file_modified", "label": "File Path", "type": "string", "default": ""},
        {"name": "poll_interval_s", "label": "Poll Interval (s)", "type": "number", "default": 0.1},
        {"name": "description", "label": "Description", "type": "string", "default": "File modified"},
    ]
}

async def file_modified(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"File modified action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "file_modified.py", parameters, node_uid, wait=True)


folder_modified_schema = {
    "params": [
        {"name": "folder_modified", "label": "Folder Path", "type": "string", "default": ""},
        {"name": "poll_interval_s", "label": "Poll Interval (s)", "type": "number", "default": 0.1},
        {"name": "description", "label": "Description", "type": "string", "default": "Folder modified"},
    ]
}

async def folder_modified(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Folder modified action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "folder_modified.py", parameters, node_uid, wait=True)


temperature_schema = {
    "params": [
        {"name": "comparison", "label": "Comparison", "type": "string", "default": ">", "options": ["<", "=", ">"]},
        {"name": "temperature", "label": "Temperature (F)", "type": "number", "default": 70},
        {"name": "city_name", "label": "City", "type": "string", "default": ""},
        {"name": "state_code", "label": "State Code", "type": "string", "default": ""},
        {"name": "country_code", "label": "Country Code", "type": "string", "default": ""},
        {"name": "poll_interval_s", "label": "Poll Interval (s)", "type": "number", "default": 10.0},
        {"name": "description", "label": "Description", "type": "string", "default": "Temperature condition met"},
    ]
}

async def temperature(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Temperature action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "temperature.py", parameters, node_uid, wait=True)


weather_schema = {
    "params": [
        {"name": "conditions", "label": "Conditions", "type": "string", "default": "Rain", "options": ["Rain", "Snow/Sleet", "Clear", "Cloudy/Fog"]},
        {"name": "city_name", "label": "City", "type": "string", "default": ""},
        {"name": "state_code", "label": "State Code", "type": "string", "default": ""},
        {"name": "country_code", "label": "Country Code", "type": "string", "default": ""},
        {"name": "poll_interval_s", "label": "Poll Interval (s)", "type": "number", "default": 10.0},
        {"name": "description", "label": "Description", "type": "string", "default": "Weather condition met"},
    ]
}

async def weather(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Weather action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "weather.py", parameters, node_uid, wait=True)


wind_schema = {
    "params": [
        {"name": "wind_threshold", "label": "Wind Threshold (mph)", "type": "number", "default": 10},
        {"name": "city_name", "label": "City", "type": "string", "default": ""},
        {"name": "state_code", "label": "State Code", "type": "string", "default": ""},
        {"name": "country_code", "label": "Country Code", "type": "string", "default": ""},
        {"name": "poll_interval_s", "label": "Poll Interval (s)", "type": "number", "default": 10.0},
        {"name": "description", "label": "Description", "type": "string", "default": "Wind threshold reached"},
    ]
}

async def wind(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Wind action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "wind.py", parameters, node_uid, wait=True)


sunrise_sunset_schema = {
    "params": [
        {"name": "sunrise_sunset", "label": "Event", "type": "string", "default": "Sunrise", "options": ["Sunrise", "Sunset"]},
        {"name": "city_name", "label": "City", "type": "string", "default": ""},
        {"name": "state_code", "label": "State Code", "type": "string", "default": ""},
        {"name": "country_code", "label": "Country Code", "type": "string", "default": ""},
        {"name": "poll_interval_s", "label": "Poll Interval (s)", "type": "number", "default": 10.0},
        {"name": "description", "label": "Description", "type": "string", "default": "Sunrise/sunset reached"},
    ]
}

async def sunrise_sunset(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Sunrise/sunset action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "sunrise_sunset.py", parameters, node_uid, wait=True)


detect_ssid_schema = {
    "params": [
        {"name": "interface", "label": "Interface", "type": "string", "default": "wlan0"},
        {"name": "ssid", "label": "SSID", "type": "string", "default": ""},
        {"name": "poll_interval_s", "label": "Poll Interval (s)", "type": "number", "default": 10.0},
        {"name": "description", "label": "Description", "type": "string", "default": "SSID detected"},
    ]
}

async def detect_ssid(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Detect SSID action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "detect_ssid.py", parameters, node_uid, wait=True)


gps_point_schema = {
    "params": [
        {"name": "target_latitude", "label": "Target Latitude", "type": "number", "default": 0.0},
        {"name": "target_longitude", "label": "Target Longitude", "type": "number", "default": 0.0},
        {"name": "distance", "label": "Distance (m)", "type": "number", "default": 100.0},
        {"name": "poll_interval_s", "label": "Poll Interval (s)", "type": "number", "default": 5.0},
        {"name": "description", "label": "Description", "type": "string", "default": "GPS point reached"},
    ]
}

async def gps_point(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"GPS point action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "gps_point.py", parameters, node_uid, wait=True)


gps_line_schema = {
    "params": [
        {"name": "latitude", "label": "Latitude Threshold", "type": "string", "default": "None"},
        {"name": "longitude", "label": "Longitude Threshold", "type": "string", "default": "None"},
        {"name": "comparison", "label": "Comparison", "type": "string", "default": ">", "options": ["<", ">"]},
        {"name": "poll_interval_s", "label": "Poll Interval (s)", "type": "number", "default": 5.0},
        {"name": "description", "label": "Description", "type": "string", "default": "GPS line crossed"},
    ]
}

async def gps_line(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"GPS line action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "gps_line.py", parameters, node_uid, wait=True)


x10_demod_schema = {
    "params": [
        {"name": "matching_text", "label": "Matching Text", "type": "string", "default": "Bits: 01100000100111110000000011111111"},
        {"name": "description", "label": "Description", "type": "string", "default": "X10 message detected"},
    ]
}

async def x10_demod(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"X10 demod action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "x10_demod.py", parameters, node_uid, wait=True)


plane_spotting_schema = {
    "params": [
        {"name": "icao", "label": "ICAO", "type": "string", "default": ""},
        {"name": "description", "label": "Description", "type": "string", "default": "Aircraft detected"},
    ]
}

async def plane_spotting(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Plane spotting action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "plane_spotting.py", parameters, node_uid, wait=True)


rds_keyword_schema = {
    "params": [
        {"name": "keyword", "label": "Keyword", "type": "string", "default": ""},
        {"name": "frequency", "label": "Frequency (MHz)", "type": "number", "default": 102.5},
        {"name": "description", "label": "Description", "type": "string", "default": "RDS keyword detected"},
    ]
}

async def rds_keyword(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"RDS keyword action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "rds_keyword.py", parameters, node_uid, wait=True)


cellular_tower_schema = {
    "params": [
        {"name": "pci", "label": "PCI", "type": "number", "default": 0},
        {"name": "frequency", "label": "Frequency (MHz)", "type": "number", "default": 900.0},
        {"name": "retry_interval_s", "label": "Retry Interval (s)", "type": "number", "default": 10.0},
        {"name": "description", "label": "Description", "type": "string", "default": "Cellular tower detected"},
    ]
}

async def cellular_tower(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Cellular tower action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "cellular_tower.py", parameters, node_uid, wait=True)


webserver_curl_schema = {
    "params": [
        {"name": "ip_address", "label": "IP Address", "type": "string", "default": "0.0.0.0"},
        {"name": "port", "label": "Port", "type": "number", "default": 8080},
        {"name": "description", "label": "Description", "type": "string", "default": "Web request received"},
    ]
}

async def webserver_curl(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    component.logger.info(f"Webserver curl action with parameters: {parameters}")
    await component.run_plugin_operation(component, PLUGIN_NAME, "webserver_curl.py", parameters, node_uid, wait=True)


async def signal_geolocate(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"Signal geolocation with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "signal_geolocate.py",
        {"parameters": op_params},
        node_uid,
    )


fixed_detection_schema = {
    "params": [
        {
            "name": "freq_mhz",
            "label": "Frequency (MHz)",
            "type": "number",
            "default": 915.0,
        },
        {
            "name": "sample_rate",
            "label": "Sample Rate (S/s)",
            "type": "number",
            "default": 1000000.0,
        },
        {
            "name": "threshold",
            "label": "Threshold",
            "type": "number",
            "default": -60.0,
        },
        {
            "name": "gain",
            "label": "RX Gain",
            "type": "number",
            "default": 65.0,
        },
        {
            "name": "channel",
            "label": "RX Channel",
            "type": "string",
            "default": "A:A",
            "options": ["A:A", "A:B"],
        },
        {
            "name": "antenna",
            "label": "RX Antenna",
            "type": "string",
            "default": "TX/RX",
            "options": ["TX/RX", "RX2"],
        },
        {
            "name": "min_detection_interval_s",
            "label": "Min. interval (s)",
            "type": "number",
            "default": 1.0,
        },
        {
            "name": "run_mode",
            "label": "Run Mode",
            "type": "string",
            "default": "gui",
            "options": ["headless", "gui"],
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Fixed detection",
        },
    ]
}
async def fixed_detection(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"Fixed Detection action with parameters: {parameters}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "fixed_detection.py",
        parameters,
        node_uid,
        wait=True,
    )


scan_detection_schema = {
    "params": [
        {
            "name": "band_plan",
            "label": "Band Plan",
            "type": "string",
            "default": "902-928 MHz ISM",
            "options": [
                "315 MHz ISM",
                "433 MHz ISM",
                "868 MHz ISM",
                "902-928 MHz ISM",
                "2.4 GHz Wi-Fi",
                "Common RF Sweep",
                "Custom Single Band",
            ],
        },
        {
            "name": "custom_start_mhz",
            "label": "Custom Start (MHz)",
            "type": "number",
            "default": 2400.0,
            "min": 0.0,
            "max": 6000.0,
            "step": 1.0,
            "decimals": 3,
        },
        {
            "name": "custom_end_mhz",
            "label": "Custom End (MHz)",
            "type": "number",
            "default": 2500.0,
            "min": 0.0,
            "max": 6000.0,
            "step": 1.0,
            "decimals": 3,
        },
        {
            "name": "custom_step_mhz",
            "label": "Custom Step (MHz)",
            "type": "number",
            "default": 5.0,
            "min": 0.001,
            "max": 1000.0,
            "step": 1.0,
            "decimals": 3,
        },
        {
            "name": "dwell_s",
            "label": "Dwell (s)",
            "type": "number",
            "default": 3.0,
            "min": 0.1,
            "max": 3600.0,
            "step": 0.5,
            "decimals": 2,
        },
        {
            "name": "threshold",
            "label": "Threshold (dB)",
            "type": "number",
            "default": -60.0,
            "min": -150.0,
            "max": 50.0,
            "step": 1.0,
            "decimals": 1,
        },
        {
            "name": "alert_interval_s",
            "label": "Min Alert Interval (s)",
            "type": "number",
            "default": 3.0,
            "min": 0.0,
            "max": 3600.0,
            "step": 1.0,
            "decimals": 2,
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Sweep scan detection",
        },
    ]
}
async def scan_detection(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    """
    Run B2x0 scan/sweep detection.

    The public schema above is intentionally small for TAK/Tactical use.

    The Dashboard TSI Sweep tab may still pass additional parameters directly
    without exposing them in the schema, including:
        bands_json
        blacklist_json
        sample_rate
        gain
        channel
        antenna
        run_mode
        retune_settle_s
        hardware_type / hardware_uid / serial / interface fields

    The operation owns defaults and parameter normalization.
    """
    component.logger.info(
        f"Scan Detection action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    if not str(op_params.get("hardware_type", "") or "").strip():
        compatible_types = ["USRP B20xmini", "USRP B2x0"]

        sdr_uid, sdr_entry = fissure.utils.hardware.get_compatible_sdr(
            getattr(component, "settings_dict", {}) or {},
            compatible_types,
        )

        if not sdr_entry:
            raise ValueError(
                "No compatible SDR configured for scan_detection. "
                f"Compatible types: {compatible_types}"
            )

        op_params.update(
            fissure.utils.hardware.sdr_entry_to_operation_parameters(
                sdr_uid,
                sdr_entry,
            )
        )

    op_params.setdefault(
        "source_id",
        node_uid or getattr(component, "uuid", "") or "sensor_node",
    )

    component.logger.info(
        f"Scan Detection resolved parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "scan_detection.py",
        op_params,
        node_uid,
    )


hackrf_sweep_detection_schema = {
    "params": [
        {
            "name": "band_range_mhz",
            "label": "Band Range (MHz)",
            "type": "string",
            "default": "300-600",
            "options": [
                "1-300",
                "300-600",
                "600-900",
                "900-1500",
                "1500-2000",
                "2000-2600",
                "2600-3000",
            ],
        },
        {
            "name": "alert_interval_s",
            "label": "Alert Interval (s)",
            "type": "number",
            "default": 5.0,
        },
        {
            "name": "detection_threshold_db",
            "label": "Detection Threshold (dB)",
            "type": "number",
            "default": 12.0,
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "HackRF sweep detection",
        },
    ]
}

async def hackrf_sweep_detection(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"HackRF sweep detection action with parameters: {parameters}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "hackrf_sweep_detection.py",
        parameters,
        node_uid,
    )


rtl_power_detection_schema = {
    "params": [
        {
            "name": "segment_range_mhz",
            "label": "Segment Range (MHz)",
            "type": "string",
            "default": "300-600",
            "options": [
                "24-300",
                "300-600",
                "600-900",
                "900-1200",
                "1200-1500",
                "1500-1764",
            ],
        },
        {
            "name": "alert_interval_s",
            "label": "Alert Interval (s)",
            "type": "number",
            "default": 5.0,
        },
        {
            "name": "detection_threshold_db",
            "label": "Detection Threshold (dB)",
            "type": "number",
            "default": 8.0,
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "RTL-SDR rtl_power detection",
        },
    ]
}

async def rtl_power_detection(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"rtl_power detection action with parameters: {parameters}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "rtl_power_detection.py",
        parameters,
        node_uid,
    )


lfm_beacon_detection_schema = {
    "params": [
        {
            "name": "freq_mhz",
            "label": "Frequency (MHz)",
            "type": "number",
            "default": 433.0,
        },
        {
            "name": "min_detection_interval_s",
            "label": "Min. interval (s)",
            "type": "number",
            "default": 1.0,
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "LFM beacon detection",
        },
    ]
}

async def lfm_beacon_detection(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"LFM Beacon Detection action with parameters: {parameters}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "lfm_beacon_detection.py",
        parameters,
        node_uid,
        wait=True,
    )


async def lfm_beacon_geolocate(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"LFM beacon geolocation with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "lfm_beacon_geolocate.py",
        {"parameters": op_params},
        node_uid,
    )


usrp_b2x0_geolocate_schema = {
    "params": [
        {
            "name": "target_id",
            "label": "Target ID",
            "type": "string",
            "default": "",
        },
        {
            "name": "frequency_mhz",
            "label": "Frequency (MHz)",
            "type": "number",
            "default": 2412.0,
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
            "default": 0.20,
        },
        {
            "name": "sample_rate",
            "label": "Sample Rate (S/s)",
            "type": "number",
            "default": 1000000.0,
        },
        {
            "name": "gain_db",
            "label": "RX Gain (dB)",
            "type": "number",
            "default": 65.0,
        },
        {
            "name": "detect_frequency",
            "label": "Detect Frequency",
            "type": "string",
            "default": "true",
            "options": [
                "true",
                "false",
            ],
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "USRP B2x0 geolocation",
        },
    ]
}

async def usrp_b2x0_geolocate(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"USRP B2x0 geolocation with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    if not str(op_params.get("hardware_type", "") or "").strip():
        compatible_types = ["USRP B20xmini", "USRP B2x0"]

        sdr_uid, sdr_entry = fissure.utils.hardware.get_compatible_sdr(
            getattr(component, "settings_dict", {}) or {},
            compatible_types,
        )

        if not sdr_entry:
            raise ValueError(
                "No compatible SDR configured for usrp_b2x0_geolocate. "
                f"Compatible types: {compatible_types}"
            )

        op_params.update(
            fissure.utils.hardware.sdr_entry_to_operation_parameters(
                sdr_uid,
                sdr_entry,
            )
        )

    op_params.setdefault(
        "source_id",
        node_uid or getattr(component, "uuid", "") or "sensor_node",
    )

    component.logger.info(
        f"USRP B2x0 geolocation resolved parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "usrp_b2x0_geolocate.py",
        {"parameters": op_params},
        node_uid,
    )


signal_conditioning_schema = {
    "params": [
        {
            "name": "frequency_mhz",
            "label": "Frequency (MHz)",
            "type": "number",
            "default": 915.0,
            "decimals": 6,
            "min": 0.0,
            "max": 6000.0,
            "step": 1.0,
        },
        {
            "name": "dwell_s",
            "label": "Dwell (s)",
            "type": "number",
            "default": 10.0,
            "min": 0.1,
            "max": 3600.0,
            "step": 1.0,
            "decimals": 1,
        },
        {
            "name": "max_files",
            "label": "Max Files / Frequency",
            "type": "int",
            "default": 5,
            "min": 1,
            "max": 999,
            "step": 1,
        },
        {
            "name": "sample_rate",
            "label": "Sample Rate (S/s)",
            "type": "number",
            "default": 1000000.0,
            "min": 1.0,
            "max": 100000000.0,
            "step": 100000.0,
            "decimals": 0,
        },
        {
            "name": "threshold",
            "label": "Threshold",
            "type": "number",
            "default": 0.004,
            "min": 0.0,
            "max": 1.0,
            "step": 0.001,
            "decimals": 6,
        },
        {
            "name": "decay",
            "label": "Decay",
            "type": "number",
            "default": 0.0002,
            "min": 0.0,
            "max": 1.0,
            "step": 0.0001,
            "decimals": 6,
        },
        {
            "name": "gain",
            "label": "RX Gain",
            "type": "number",
            "default": 60.0,
            "min": 0.0,
            "max": 100.0,
            "step": 1.0,
            "decimals": 1,
        },
        {
            "name": "channel",
            "label": "RX Channel",
            "type": "string",
            "default": "A:A",
            "options": ["A:A", "A:B"],
        },
        {
            "name": "antenna",
            "label": "RX Antenna",
            "type": "string",
            "default": "TX/RX",
            "options": ["TX/RX", "RX2"],
        },
        {
            "name": "emit_alert",
            "label": "Emit Alert",
            "type": "string",
            "default": "false",
            "options": ["false", "true"],
        },
        {
            "name": "emit_tak",
            "label": "Emit TAK",
            "type": "string",
            "default": "false",
            "options": ["false", "true"],
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Signal conditioning capture",
        },
    ]
}
async def signal_conditioning(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"Signal Conditioning action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    if not str(op_params.get("hardware_type", "") or "").strip():
        compatible_types = ["USRP B20xmini", "USRP B2x0"]

        sdr_uid, sdr_entry = fissure.utils.hardware.get_compatible_sdr(
            getattr(component, "settings_dict", {}) or {},
            compatible_types,
        )

        if not sdr_entry:
            raise ValueError(
                "No compatible SDR configured for signal_conditioning. "
                f"Compatible types: {compatible_types}"
            )

        op_params.update(
            fissure.utils.hardware.sdr_entry_to_operation_parameters(
                sdr_uid,
                sdr_entry,
            )
        )

    op_params.setdefault(
        "source_id",
        node_uid or getattr(component, "uuid", "") or "sensor_node",
    )

    op_params.setdefault(
        "serial",
        op_params.get("hardware_serial_argument", "False"),
    )
    op_params.setdefault(
        "ip_address",
        op_params.get("hardware_ip", ""),
    )
    op_params.setdefault(
        "channel",
        op_params.get("rx_channel", "A:A"),
    )
    op_params.setdefault(
        "antenna",
        op_params.get("rx_antenna", "TX/RX"),
    )
    op_params.setdefault(
        "gain",
        op_params.get("rx_gain", 60.0),
    )

    component.logger.info(
        f"Signal Conditioning resolved parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "signal_conditioning.py",
        op_params,
        node_uid,
    )


signal_conditioning_file_schema = {
    "params": [
        {
            "name": "data_type",
            "label": "Data Type",
            "type": "string",
            "default": "Complex Float 32",
            "options": [
                "Complex Float 32",
                "Complex Int 16",
            ],
        },
        {
            "name": "sample_rate",
            "label": "Sample Rate (S/s)",
            "type": "number",
            "default": 1000000.0,
            "min": 1.0,
            "max": 100000000.0,
            "step": 100000.0,
            "decimals": 0,
        },
        {
            "name": "threshold",
            "label": "Threshold",
            "type": "number",
            "default": 0.004,
            "min": 0.0,
            "max": 1.0,
            "step": 0.001,
            "decimals": 6,
        },
        {
            "name": "decay",
            "label": "Decay",
            "type": "number",
            "default": 0.0002,
            "min": 0.0,
            "max": 1.0,
            "step": 0.0001,
            "decimals": 6,
        },
        {
            "name": "max_files",
            "label": "Max Files",
            "type": "int",
            "default": 15,
            "min": 1,
            "max": 9999,
            "step": 1,
        },
        {
            "name": "min_samples",
            "label": "Min Samples",
            "type": "int",
            "default": 1,
            "min": 0,
            "max": 100000000,
            "step": 1,
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Local file/folder signal conditioning using file-source Conditioner flow graphs",
        },
    ]
}
async def signal_conditioning_file(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"Signal Conditioning File action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    op_params.setdefault(
        "source_id",
        node_uid or getattr(component, "uuid", "") or "sensor_node",
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "signal_conditioning_file.py",
        op_params,
        node_uid,
        wait=True,
    )



feature_extract_time_domain_schema = {
    "params": [
        {
            "name": "preset",
            "label": "Feature Preset",
            "type": "string",
            "default": "all",
            "options": [
                "core",
                "statistical",
                "all",
            ],
        },
        {
            "name": "core_includes",
            "label": "Core Includes",
            "type": "label",
            "default": (
                "Mean, Max, Peak, RMS, Variance, Standard Deviation, "
                "Power, Samples"
            ),
        },
        {
            "name": "statistical_includes",
            "label": "Statistical Includes",
            "type": "label",
            "default": (
                "Mean, Variance, Standard Deviation, Kurtosis, "
                "Skewness, Zero Crossings, Samples"
            ),
        },
        {
            "name": "all_includes",
            "label": "All Includes",
            "type": "label",
            "default": (
                "Mean, Max, Peak, Peak to Peak, RMS, Variance, "
                "Standard Deviation, Power, Crest Factor, Pulse Indicator, "
                "Margin, Kurtosis, Skewness, Zero Crossings, Samples"
            ),
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Extract time-domain IQ features",
        },
    ]
}


async def feature_extract_time_domain(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    """
    Run the reusable Feature Extractor operation with the time-domain profile.
    """
    op_params = dict(parameters or {})
    op_params["profile"] = "time_domain"

    op_params.pop("core_includes", None)
    op_params.pop("statistical_includes", None)
    op_params.pop("all_includes", None)

    op_params.setdefault(
        "source_id",
        node_uid or getattr(component, "uuid", "") or "sensor_node",
    )

    component.logger.info(
        f"Feature Extractor time-domain action with parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "feature_extraction.py",
        op_params,
        node_uid,
        wait=True,
    )


feature_extract_frequency_domain_schema = {
    "params": [
        {
            "name": "preset",
            "label": "Feature Preset",
            "type": "string",
            "default": "all",
            "options": [
                "core",
                "statistical",
                "all",
            ],
        },
        {
            "name": "core_includes",
            "label": "Core Includes",
            "type": "label",
            "default": (
                "Mean of Band Power Spectrum, Max of Band Power Spectrum, "
                "Sum of Total Band Power, Peak of Band Power, "
                "Relative Spectral Peak per Band"
            ),
        },
        {
            "name": "statistical_includes",
            "label": "Statistical Includes",
            "type": "label",
            "default": (
                "Mean of Band Power Spectrum, Variance of Band Power, "
                "Standard Deviation of Band Power, Skewness of Band Power, "
                "Kurtosis of Band Power"
            ),
        },
        {
            "name": "all_includes",
            "label": "All Includes",
            "type": "label",
            "default": (
                "Mean of Band Power Spectrum, Max of Band Power Spectrum, "
                "Sum of Total Band Power, Peak of Band Power, "
                "Variance of Band Power, Standard Deviation of Band Power, "
                "Skewness of Band Power, Kurtosis of Band Power, "
                "Relative Spectral Peak per Band"
            ),
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Extract frequency-domain IQ features",
        },
    ]
}


async def feature_extract_frequency_domain(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    """
    Run the reusable Feature Extractor operation with the frequency-domain profile.
    """
    op_params = dict(parameters or {})
    op_params["profile"] = "frequency_domain"

    op_params.pop("core_includes", None)
    op_params.pop("statistical_includes", None)
    op_params.pop("all_includes", None)

    op_params.setdefault(
        "source_id",
        node_uid or getattr(component, "uuid", "") or "sensor_node",
    )

    component.logger.info(
        f"Feature Extractor frequency-domain action with parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "feature_extraction.py",
        op_params,
        node_uid,
        wait=True,
    )


feature_extract_time_frequency_schema = {
    "params": [
        {
            "name": "preset",
            "label": "Feature Preset",
            "type": "string",
            "default": "all",
            "options": [
                "balanced",
                "statistical",
                "all",
            ],
        },
        {
            "name": "balanced_includes",
            "label": "Balanced Includes",
            "type": "label",
            "default": (
                "Mean, Max, Peak, RMS, Variance, Standard Deviation, "
                "Power, Samples, Mean of Band Power Spectrum, "
                "Max of Band Power Spectrum, Sum of Total Band Power, "
                "Peak of Band Power, Relative Spectral Peak per Band"
            ),
        },
        {
            "name": "statistical_includes",
            "label": "Statistical Includes",
            "type": "label",
            "default": (
                "Mean, Variance, Standard Deviation, Kurtosis, Skewness, "
                "Zero Crossings, Samples, Mean of Band Power Spectrum, "
                "Variance of Band Power, Standard Deviation of Band Power, "
                "Skewness of Band Power, Kurtosis of Band Power"
            ),
        },
        {
            "name": "all_includes",
            "label": "All Includes",
            "type": "label",
            "default": (
                "Mean, Max, Peak, Peak to Peak, RMS, Variance, "
                "Standard Deviation, Power, Crest Factor, Pulse Indicator, "
                "Margin, Kurtosis, Skewness, Zero Crossings, Samples, "
                "Mean of Band Power Spectrum, Max of Band Power Spectrum, "
                "Sum of Total Band Power, Peak of Band Power, "
                "Variance of Band Power, Standard Deviation of Band Power, "
                "Skewness of Band Power, Kurtosis of Band Power, "
                "Relative Spectral Peak per Band"
            ),
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Extract time-domain and frequency-domain IQ features",
        },
    ]
}


async def feature_extract_time_frequency(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    """
    Run the reusable Feature Extractor operation with the combined profile.
    """
    op_params = dict(parameters or {})
    op_params["profile"] = "time_frequency"

    op_params.pop("balanced_includes", None)
    op_params.pop("statistical_includes", None)
    op_params.pop("all_includes", None)

    op_params.setdefault(
        "source_id",
        node_uid or getattr(component, "uuid", "") or "sensor_node",
    )

    component.logger.info(
        f"Feature Extractor time/frequency action with parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "feature_extraction.py",
        op_params,
        node_uid,
        wait=True,
    )


feature_extract_custom_schema = {
    "params": [
        {
            "name": "features",
            "label": "Features",
            "type": "string",
            "default": "Mean, RMS, Variance, Power",
        },
        {
            "name": "supported_time_domain",
            "label": "Time-Domain Options",
            "type": "label",
            "default": (
                "Mean, Max, Peak, Peak to Peak, RMS, Variance, "
                "Standard Deviation, Power, Crest Factor, Pulse Indicator, "
                "Margin, Kurtosis, Skewness, Zero Crossings, Samples"
            ),
        },
        {
            "name": "supported_frequency_domain",
            "label": "Frequency-Domain Options",
            "type": "label",
            "default": (
                "Mean of Band Power Spectrum, Max of Band Power Spectrum, "
                "Sum of Total Band Power, Peak of Band Power, "
                "Variance of Band Power, Standard Deviation of Band Power, "
                "Skewness of Band Power, Kurtosis of Band Power, "
                "Relative Spectral Peak per Band"
            ),
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": (
                "Advanced mode: enter supported feature names separated by commas"
            ),
        },
    ]
}


async def feature_extract_custom(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    """
    Run the reusable Feature Extractor operation with a custom feature list.
    """
    op_params = dict(parameters or {})
    op_params["profile"] = "custom"

    op_params.pop("supported_time_domain", None)
    op_params.pop("supported_frequency_domain", None)

    op_params.setdefault(
        "source_id",
        node_uid or getattr(component, "uuid", "") or "sensor_node",
    )

    component.logger.info(
        f"Feature Extractor custom action with parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "feature_extraction.py",
        op_params,
        node_uid,
        wait=True,
    )


promote_to_soi_schema = {
    "params": [
        {
            "name": "frequency_mhz",
            "label": "Frequency (MHz)",
            "type": "number",
            "default": 915.0,
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Promote to SOI",
        },
    ]
}
async def promote_to_soi(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:

    component.logger.info(
        f"Promote to SOI action with parameters: {parameters}"
    )

    freq = parameters.get("frequency_mhz")

    if freq is None:
        raise ValueError("Missing required parameter: frequency_mhz")

    try:
        freq = float(freq)
    except Exception:
        raise ValueError(f"Invalid frequency_mhz: {freq!r}")

    data_type = parameters.get(
        "data_type",
        "Complex Float 32",
    )

    soi_id = str(uuid.uuid4())

    operation_id = ""
    artifact_id = ""
    model_label = None
    model_conf_pct = None

    STAGE_ORDER = {
        "STARTED": 10,
        "CAPTURE_COMPLETE": 20,
        "FEATURES_READY": 30,
        "MODEL_ANALYZED": 40,
        "EVIDENCE_READY": 50,
        "FAILED": 90,
    }

    async def _send(
        status: str,
        stage: str,
        extra: Dict[str, Any] = None,
    ) -> None:

        summary = {
            "stage": stage,
            "stage_order": STAGE_ORDER.get(status, 0),
            "folder": None,
            "files_present": None,
            "model_classification": model_label,
            "model_confidence": model_conf_pct,
        }

        if extra:
            summary.update(extra)

        try:
            await component.send_soi_update(
                node_uid=node_uid,
                soi_id=soi_id,
                frequency_mhz=freq,
                status=status,
                operation_id=operation_id,
                artifact_id=artifact_id,
                summary=summary,
                lat=True,
                lon=True,
                alt=True,
                observation_time=True,
            )
        except Exception:
            component.logger.exception(
                f"SOI update failed (status={status})"
            )

    def _has_capture_files(folder: str) -> bool:
        if not folder or not os.path.isdir(folder):
            return False

        try:
            for name in os.listdir(folder):
                p = os.path.join(folder, name)

                if os.path.isfile(p) and os.path.getsize(p) > 0:
                    return True
        except Exception:
            return False

        return False

    def _exists(folder: str, filename: str) -> bool:
        return bool(folder) and os.path.isfile(
            os.path.join(folder, filename)
        )

    async def _abort(stage: str, msg: str) -> None:
        component.logger.warning(msg)

        await _send(
            status="FAILED",
            stage=stage,
            extra={"error": msg},
        )

    await _send(
        status="STARTED",
        stage="starting",
        extra={"files_present": False},
    )

    try:
        op1_params = {
            "frequency_mhz": freq
        }

        op1_id = await component.run_plugin_operation(
            component,
            PLUGIN_NAME,
            "signal_conditioning.py",
            op1_params,
            node_uid,
            wait=True,
        )

        operation_id = op1_id

        _, capture_folder = (
            component.artifact_manager.create_operation_dir(op1_id)
        )

        if not _has_capture_files(capture_folder):
            await _abort(
                stage="capture_failed",
                msg=f"Capture produced no files. folder={capture_folder}",
            )
            return

        await _send(
            status="CAPTURE_COMPLETE",
            stage="capture_complete",
            extra={
                "folder": capture_folder,
                "files_present": True,
            },
        )

    except Exception as e:
        component.logger.error(
            f"signal_conditioning failed: {e!r}"
        )

        await _send(
            status="FAILED",
            stage="capture_failed",
            extra={"error": repr(e)},
        )

        return

    try:
        op2_params = {
            "folder": capture_folder,
            "data_type": data_type,
        }

        await component.run_plugin_operation(
            component,
            PLUGIN_NAME,
            "feature_extraction.py",
            op2_params,
            node_uid,
            wait=True,
        )

        if not _exists(capture_folder, "tsi_features.json"):
            await _abort(
                stage="features_failed",
                msg=f"Feature extraction missing tsi_features.json",
            )
            return

        await _send(
            status="FEATURES_READY",
            stage="features_ready",
            extra={
                "folder": capture_folder,
                "features_file": "tsi_features.json",
            },
        )

    except Exception as e:
        component.logger.error(
            f"feature_extraction failed: {e!r}"
        )

        await _send(
            status="FAILED",
            stage="features_failed",
            extra={
                "folder": capture_folder,
                "error": repr(e),
            },
        )

        return

    try:
        op3_params = {
            "folder": capture_folder,
            "features_file": "tsi_features.json",
            "min_models": 2,
            "use_batch_consensus": True,
        }

        await component.run_plugin_operation(
            component,
            PLUGIN_NAME,
            "classify_features_dt.py",
            op3_params,
            node_uid,
            wait=True,
        )

        report_path = os.path.join(
            capture_folder,
            "classification_report.json",
        )

        if not os.path.isfile(report_path):
            await _abort(
                stage="classification_failed",
                msg="Classifier missing classification_report.json",
            )
            return

        try:
            with open(report_path, "r", encoding="utf-8") as f:
                rep = json.load(f)

            model_label = rep.get("batch", {}).get("label")

            conf01 = rep.get("batch", {}).get("confidence")

            model_conf_pct = (
                round(conf01 * 100)
                if conf01 is not None
                else None
            )

        except Exception as e:
            component.logger.warning(
                f"Failed reading classification report: {e!r}"
            )

        await _send(
            status="MODEL_ANALYZED",
            stage="model_analyzed",
            extra={
                "folder": capture_folder,
                "model_classification": model_label,
                "model_confidence": model_conf_pct,
            },
        )

    except Exception as e:
        component.logger.error(
            f"classify_features_dt failed: {e!r}"
        )

        await _send(
            status="FAILED",
            stage="classification_failed",
            extra={
                "folder": capture_folder,
                "error": repr(e),
            },
        )

        return

    try:
        artifact = component.artifact_manager.create_zip_artifact_from_folder(
            source_id=node_uid or getattr(component, "uuid", "") or "sensor_node",
            operation_id=operation_id,
            folder=capture_folder,
            name=f"SOI evidence @ {freq} MHz",
            metadata={
                "kind": "artifact",
                "event_type": "artifact",
                "role": "soi_evidence_v1",
                "node_uid": node_uid,
                "source_id": node_uid or getattr(component, "uuid", "") or "sensor_node",
                "frequency_mhz": freq,
                "soi_id": soi_id,
                "operation_id": operation_id,
                "model_classification": model_label,
                "model_confidence": model_conf_pct,
            },
            arc_prefix=f"soi_{operation_id}",
        )

        artifact_id = str(
            getattr(artifact, "id", artifact) if artifact else ""
        )

        component.logger.info(
            f"SOI evidence artifact registered: {artifact_id}"
        )

        await _send(
            status="EVIDENCE_READY",
            stage="evidence_ready",
            extra={
                "folder": capture_folder,
                "artifact_id": artifact_id,
                "model_classification": model_label,
                "model_confidence": model_conf_pct,
            },
        )

    except Exception as e:
        component.logger.error(
            f"artifact bundling failed: {e!r}"
        )

        await _send(
            status="FAILED",
            stage="evidence_bundle_failed",
            extra={
                "folder": capture_folder,
                "error": repr(e),
            },
        )

        return

    component.logger.info(
        f"promote_to_soi complete: "
        f"soi_id={soi_id}, "
        f"op_id={operation_id}, "
        f"label={model_label}, "
        f"conf={model_conf_pct}%"
    )


take_photo_schema = {
    "params": [
        {
            "name": "count",
            "label": "Photo Count",
            "type": "number",
            "default": 5,
        },
        {
            "name": "interval_s",
            "label": "Interval (s)",
            "type": "number",
            "default": 0.3,
        },
        {
            "name": "name",
            "label": "Artifact Name",
            "type": "string",
            "default": "Photo capture evidence",
        },
    ]
}

async def take_photo(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:

    component.logger.info(
        f"take_photo action with parameters: {parameters}"
    )

    op_id = str(
        parameters.get("operation_id") or uuid.uuid4()
    )

    op_params = dict(parameters or {})
    op_params["operation_id"] = op_id

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "take_photo.py",
        op_params,
        node_uid,
        wait=True,
    )


motion_detector_schema = {
    "params": [
        {
            "name": "sensitivity",
            "label": "Sensitivity",
            "type": "string",
            "default": "medium",
            "options": ["low", "medium", "high"],
        },
        {
            "name": "max_watch_s",
            "label": "Max Watch (s)",
            "type": "number",
            "default": 300.0,
        },
        {
            "name": "photo_count",
            "label": "Photo Count",
            "type": "number",
            "default": 5,
        },
    ]
}

async def motion_detector(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:

    component.logger.info(
        f"motion_detector action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    op_params.setdefault(
        "operation_id",
        str(uuid.uuid4()),
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "motion_detector.py",
        op_params,
        node_uid,
        wait=True,
    )


take_video_schema = {
    "params": [
        {
            "name": "duration_s",
            "label": "Duration (s)",
            "type": "number",
            "default": 10.0,
        },
        {
            "name": "fps",
            "label": "FPS",
            "type": "number",
            "default": 30.0,
        },
        {
            "name": "artifact_name",
            "label": "Artifact Name",
            "type": "string",
            "default": "Video capture evidence",
        },
    ]
}

async def take_video(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:

    component.logger.info(
        f"take_video action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    op_params.setdefault(
        "operation_id",
        str(uuid.uuid4()),
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "take_video.py",
        op_params,
        node_uid,
        wait=True,
    )


iq_record_schema = {
    "params": [
        {
            "name": "base_file_name",
            "label": "Base File Name",
            "type": "string",
            "default": "capture.sigmf-data",
        },
        {
            "name": "artifact_format",
            "label": "Artifact Packaging",
            "type": "string",
            "default": "raw",
            "options": ["raw", "zip"],
        },
        {
            "name": "frequency_mhz",
            "label": "Frequency (MHz)",
            "type": "number",
            "default": 915.0,
        },
        {
            "name": "sample_rate_msps",
            "label": "Sample Rate (MS/s)",
            "type": "number",
            "default": 1.0,
        },
        {
            "name": "rx_gain",
            "label": "RX Gain",
            "type": "number",
            "default": 70.0,
        },
        {
            "name": "rx_channel",
            "label": "RX Channel",
            "type": "string",
            "default": "A:A",
        },
        {
            "name": "rx_antenna",
            "label": "RX Antenna",
            "type": "string",
            "default": "TX/RX",
        },
        {
            "name": "duration_s",
            "label": "Duration per Capture (s)",
            "type": "number",
            "default": 0.1,
            "min": 0.001,
            "step": 0.1,
            "decimals": 3,
        },
        {
            "name": "number_of_files",
            "label": "Number of Captures",
            "type": "int",
            "default": 1,
            "min": 1,
        },
        {
            "name": "file_interval",
            "label": "Interval Between Captures (s)",
            "type": "number",
            "default": 0.0,
            "min": 0.0,
            "step": 0.1,
            "decimals": 3,
        },
        {
            "name": "data_type",
            "label": "Data Type",
            "type": "string",
            "default": "Complex Float 32",
            "options": ["Complex Float 32"],
        },
        {
            "name": "sigmf_enabled",
            "label": "SigMF Metadata",
            "type": "string",
            "default": "true",
            "options": ["true", "false"],
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "IQ recording",
        },
    ]
}
async def iq_record(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"IQ Record action with parameters: {parameters}"
    )

    op_params = dict(parameters or {})

    if not str(op_params.get("hardware_type", "") or "").strip():
        compatible_types = ACTION_HARDWARE["iq_record"]

        sdr_uid, sdr_entry = fissure.utils.hardware.get_compatible_sdr(
            getattr(component, "settings_dict", {}) or {},
            compatible_types,
        )

        if not sdr_entry:
            raise ValueError(
                "No compatible SDR configured for iq_record. "
                f"Compatible types: {compatible_types}"
            )

        op_params.update(
            fissure.utils.hardware.sdr_entry_to_operation_parameters(
                sdr_uid,
                sdr_entry,
            )
        )

    component.logger.info(
        f"IQ Record resolved parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "iq_record.py",
        op_params,
        node_uid,
    )


iq_playback_schema = {
    "params": [
        {
            "name": "playback_mode",
            "label": "Playback Mode",
            "type": "string",
            "default": "continuous",
            "options": [
                "continuous",
                "single",
            ],
        },
        {
            "name": "playback_file_mode",
            "label": "Playback File Mode",
            "type": "string",
            "default": "node_path",
            "options": [
                "node_path",
                # "transfer",
            ],
        },
        {
            "name": "filepath",
            "label": "File Path",
            "type": "string",
            "default": "",
        },
        {
            "name": "tx_frequency",
            "label": "TX Frequency (MHz)",
            "type": "number",
            "default": 915.0,
        },
        {
            "name": "sample_rate_msps",
            "label": "Sample Rate (MS/s)",
            "type": "number",
            "default": 1.0,
        },
        {
            "name": "tx_gain",
            "label": "TX Gain",
            "type": "number",
            "default": 70.0,
        },
        {
            "name": "tx_channel",
            "label": "TX Channel",
            "type": "string",
            "default": "A:A",
        },
        {
            "name": "tx_antenna",
            "label": "TX Antenna",
            "type": "string",
            "default": "TX/RX",
        },
        {
            "name": "data_type",
            "label": "Data Type",
            "type": "string",
            "default": "Complex Float 32",
            "options": [
                "Complex Float 32",
            ],
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "IQ playback",
        },
    ]
}
async def iq_playback(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"IQ Playback action with parameters: {parameters}"
    )

    op_params = dict(
        parameters
        or {}
    )

    playback_mode = str(
        op_params.get(
            "playback_mode",
            "continuous",
        )
        or "continuous"
    ).strip().lower()

    if playback_mode not in {
        "continuous",
        "single",
    }:
        raise ValueError(
            "Unsupported IQ playback mode: "
            f"{playback_mode}"
        )

    op_params[
        "playback_mode"
    ] = playback_mode

    if not str(
        op_params.get(
            "hardware_type",
            "",
        )
        or ""
    ).strip():
        compatible_types = (
            ACTION_HARDWARE[
                "iq_playback"
            ]
        )

        sdr_uid, sdr_entry = (
            fissure.utils.hardware.get_compatible_sdr(
                getattr(
                    component,
                    "settings_dict",
                    {},
                )
                or {},
                compatible_types,
            )
        )

        if not sdr_entry:
            raise ValueError(
                "No compatible SDR configured for iq_playback. "
                f"Compatible types: {compatible_types}"
            )

        op_params.update(
            fissure.utils.hardware.sdr_entry_to_operation_parameters(
                sdr_uid,
                sdr_entry,
            )
        )

    component.logger.info(
        f"IQ Playback resolved parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "iq_playback.py",
        op_params,
        node_uid,
    )


iq_inspection_live_schema = {
    "params": [
        {
            "name": "inspection_method",
            "label": "Inspection Method",
            "type": "string",
            "default": "waterfall",
            "options": [
                "instantaneous_frequency",
                "signal_envelope",
                "time_sink",
                "time_sink_1_10_100",
                "waterfall",
            ],
        },
        {
            "name": "rx_channel",
            "label": "RX Channel",
            "type": "string",
            "default": "A:A",
            "options": [
                "A:A",
                "A:B",
            ],
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Live IQ inspection",
        },
    ]
}
async def iq_inspection_live(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"IQ Inspection Live action with parameters: {parameters}"
    )

    op_params = dict(
        parameters
        or {}
    )

    supported_methods = {
        "instantaneous_frequency",
        "signal_envelope",
        "time_sink",
        "time_sink_1_10_100",
        "waterfall",
    }

    inspection_method = str(
        op_params.get(
            "inspection_method",
            "waterfall",
        )
        or "waterfall"
    ).strip().lower()

    if inspection_method not in supported_methods:
        raise ValueError(
            "Unsupported live IQ Inspection method: "
            f"{inspection_method}"
        )

    op_params[
        "inspection_method"
    ] = inspection_method

    if not str(
        op_params.get(
            "hardware_type",
            "",
        )
        or ""
    ).strip():
        compatible_types = (
            ACTION_HARDWARE[
                "iq_inspection_live"
            ]
        )

        sdr_uid, sdr_entry = (
            fissure.utils.hardware.get_compatible_sdr(
                getattr(
                    component,
                    "settings_dict",
                    {},
                )
                or {},
                compatible_types,
            )
        )

        if not sdr_entry:
            raise ValueError(
                "No compatible SDR configured for iq_inspection_live. "
                f"Compatible types: {compatible_types}"
            )

        op_params.update(
            fissure.utils.hardware.sdr_entry_to_operation_parameters(
                sdr_uid,
                sdr_entry,
            )
        )

    component.logger.info(
        f"IQ Inspection Live resolved parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "iq_inspection_live.py",
        op_params,
        node_uid,
    )


iq_inspection_file_schema = {
    "params": [
        {
            "name": "inspection_method",
            "label": "Inspection Method",
            "type": "string",
            "default": "waterfall",
            "options": [
                "instantaneous_frequency",
                "signal_envelope",
                "waterfall",
            ],
        },
        {
            "name": "filepath",
            "label": "File Path",
            "type": "string",
            "default": "",
        },
        {
            "name": "sample_rate",
            "label": "Sample Rate (S/s)",
            "type": "number",
            "default": 1000000.0,
            "min": 1.0,
            "max": 100000000.0,
            "step": 100000.0,
            "decimals": 0,
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "IQ file inspection",
        },
    ]
}
async def iq_inspection_file(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    component.logger.info(
        f"IQ Inspection File action with parameters: {parameters}"
    )

    op_params = dict(
        parameters
        or {}
    )

    supported_methods = {
        "instantaneous_frequency",
        "signal_envelope",
        "waterfall",
    }

    inspection_method = str(
        op_params.get(
            "inspection_method",
            "waterfall",
        )
        or "waterfall"
    ).strip().lower()

    if inspection_method not in supported_methods:
        raise ValueError(
            "Unsupported IQ file Inspection method: "
            f"{inspection_method}"
        )

    op_params[
        "inspection_method"
    ] = inspection_method

    component.logger.info(
        f"IQ Inspection File resolved parameters: {op_params}"
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "iq_inspection_file.py",
        op_params,
        node_uid,
    )


scapy_transmit_schema = {
    "params": [
        {
            "name": "packet_hex",
            "label": "Packet Hex",
            "type": "string",
            "default": "",
            "description": "Serialized packet bytes as hexadecimal.",
        },
        {
            "name": "root_layer",
            "label": "Root Layer",
            "type": "string",
            "default": "Ether",
            "description": "Scapy class used to rebuild the packet, such as Ether, RadioTap, or IP.",
        },
        {
            "name": "interface",
            "label": "Interface",
            "type": "string",
            "default": "",
            "description": "Network interface on the executing Sensor Node.",
        },
        {
            "name": "method",
            "label": "Method",
            "type": "string",
            "default": "Auto",
            "options": [
                "Auto",
                "sendp (Layer 2)",
                "send (Layer 3)",
            ],
        },
        {
            "name": "interval",
            "label": "Interval (s)",
            "type": "number",
            "default": 0.1,
            "min": 0.0,
            "max": 3600.0,
            "step": 0.1,
            "decimals": 3,
        },
        {
            "name": "count",
            "label": "Count",
            "type": "int",
            "default": 1,
            "min": 1,
            "max": 1000000000,
        },
        {
            "name": "loop",
            "label": "Loop",
            "type": "string",
            "default": "false",
            "options": [
                "false",
                "true",
            ],
        },
        {
            "name": "description",
            "label": "Description",
            "type": "string",
            "default": "Scapy packet transmission",
        },
    ]
}
async def scapy_transmit(
    component: SensorNode,
    parameters: Dict[str, Any],
    node_uid: str = "",
) -> None:
    """Transmit a serialized Scapy packet on the executing Sensor Node."""
    op_params = dict(parameters or {})

    op_params.setdefault(
        "operation_id",
        str(uuid.uuid4()),
    )
    op_params.setdefault(
        "requester",
        "plugin_action",
    )

    await component.run_plugin_operation(
        component,
        PLUGIN_NAME,
        "scapy_transmit.py",
        op_params,
        node_uid,
    )