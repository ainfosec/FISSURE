"""FISSURE AIS Action exposure; implementation remains in Operations."""
from typing import Any, Dict
from pathlib import Path
import sys
from fissure.Sensor_Node.SensorNode import SensorNode

# The Sensor Node's configured SDR inventory is the source of truth for serials.
_AIS_SCRIPT_PATH = str(Path(__file__).resolve().parent / 'scripts')
if _AIS_SCRIPT_PATH not in sys.path:
    sys.path.insert(0, _AIS_SCRIPT_PATH)
from ais_node_hardware_v099 import configured_b210_parameters

PLUGIN_NAME = "AIS"

ACTION_TAGS = {
    "ais_nmea_udp_file_receive": ["All", "AIS", "protocol.maritime", "tactical.detection"],
    "ais_nmea_udp_simulate": ["All", "AIS", "protocol.maritime"],
    "ais_iq_file_decode": ["All", "AIS", "protocol.maritime", "signal_analysis.iq"],
    "ais_iq_offline_loopback": ["All", "AIS", "protocol.maritime", "signal_analysis.iq"],
}

# Neither Action directly claims an SDR. Receive consumes already-decoded AIS
# NMEA; simulation sends *network* NMEA, never RF. GR hardware sits upstream.
ais_nmea_udp_file_receive_schema = {"params": [
    {"name": "input_mode", "label": "Input Mode", "description": "Input", "type": "string", "default": "udp", "options": ["udp", "file"]},
    {"name": "source_file", "label": "NMEA File", "description": "Path to a local NMEA file on the Sensor Node (used for file input). Original: NMEA File (Sensor Node path; file input).", "type": "string", "default": ""},
    {"name": "listen_host", "label": "Bind Host", "description": "UDP Bind Address", "type": "string", "default": "127.0.0.1"},
    {"name": "listen_port", "label": "UDP Port", "description": "UDP NMEA Port", "type": "integer", "default": 10110, "min": 1024, "max": 65535, "step": 1},
    {"name": "duration_s", "label": "Duration (s)", "description": "UDP listen window: 0 runs until Stop. File mode reads a finite NMEA file once.", "type": "integer", "default": 60, "min": 0, "max": 86400, "step": 1},
    {"name": "simulated_input", "label": "Simulated Input", "description": "Mark incoming NMEA observations as simulated; NMEA alone does not indicate the RF source.", "type": "string",
     "default": "false", "options": ["true", "false"]},
    {"name": "emit_targets", "label": "Update Targets", "description": "Create or update FISSURE vessel Targets using self-reported AIS coordinates, not RF geolocation. Original: Create / Update Vessel Targets.", "type": "string", "default": "true", "options": ["true", "false"]},
    {"name": "save_artifact", "label": "Save Artifact", "description": "Save AIS Artifact", "type": "string", "default": "true", "options": ["true", "false"]},
]}


async def ais_nmea_udp_file_receive(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(component, PLUGIN_NAME, "ais_receive.py", dict(parameters or {}), node_uid)


ais_nmea_udp_simulate_schema = {"params": [
    {"name": "vessel_count", "label": "Vessels", "description": "Simulated Vessels", "type": "integer", "default": 3, "min": 1, "max": 20, "step": 1},
    {"name": "position_updates", "label": "Position Reports", "description": "Position Updates per Vessel", "type": "integer", "default": 5, "min": 1, "max": 1000, "step": 1},
    {"name": "interval_s", "label": "Update Gap (s)", "description": "Seconds Between Updates", "type": "number", "decimals": 1, "default": 1.0, "min": 0.1, "max": 30.0, "step": 0.1},
    {"name": "udp_host", "label": "UDP Host", "description": "UDP Destination", "type": "string", "default": "127.0.0.1"},
    {"name": "udp_port", "label": "UDP Port", "description": "UDP Destination Port", "type": "integer", "default": 10110, "min": 1024, "max": 65535, "step": 1},
    {"name": "base_latitude", "label": "Latitude (°)", "description": "Starting simulated vessel latitude in decimal degrees. Original: Starting Latitude (degrees).", "type": "number", "default": 40.722, "min": -90, "max": 90, "decimals": 6},
    {"name": "base_longitude", "label": "Longitude (°)", "description": "Starting simulated vessel longitude in decimal degrees. Original: Starting Longitude (degrees).", "type": "number", "default": -74.020, "min": -180, "max": 180, "decimals": 6},
]}


async def ais_nmea_udp_simulate(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(component, PLUGIN_NAME, "ais_simulate.py", dict(parameters or {}), node_uid)


# Offline IQ to AIS: uses existing gr-ais hierarchy, requires no radio.
ais_iq_file_decode_schema = {"params": [
    {"name": "iq_file", "label": "IQ File", "description": "Complex64 IQ filepath on the Sensor Node. Original: IQ File (Sensor Node path; complex64).", "type": "string", "default": ""},
    {"name": "sample_rate", "label": "IQ Rate (Hz)", "description": "IQ Sample Rate (Hz)", "type": "integer", "default": 200000,
     "min": 100000, "max": 5000000, "step": 1000, "decimals": 0},
    {"name": "center_frequency", "label": "Center (Hz)", "description": "IQ Center Frequency (Hz)", "type": "integer", "default": 162000000,
     "min": 100000000, "max": 200000000, "step": 25000, "decimals": 0},
    {"name": "channel", "label": "AIS Channels", "description": "AIS Channel(s)", "type": "string", "default": "both",
     "options": ["both", "A", "B"]},
    {"name": "emit_targets", "label": "Update Targets", "description": "Create or update FISSURE vessel Targets using self-reported AIS coordinates, not RF geolocation. Original: Create / Update Vessel Targets.", "type": "string", "default": "true",
     "options": ["true", "false"]},
    {"name": "save_artifact", "label": "Save Artifact", "description": "Save AIS Artifact", "type": "string", "default": "true",
     "options": ["true", "false"]},
]}


async def ais_iq_file_decode(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(component, PLUGIN_NAME, "ais_iq_receive.py", dict(parameters or {}), node_uid)


# Offline finite AIS HDLC/GMSK -> complex64 IQ -> gr-ais -> FISSURE.
# Simulated position reports, NO SDR hardware or RF transmission.
ais_iq_offline_loopback_schema = {"params": [
    {"name": "vessel_count", "label": "Vessels", "description": "Synthetic Vessels", "type": "integer", "default": 3,
     "min": 1, "max": 6, "step": 1, "decimals": 0},
    {"name": "position_updates", "label": "Position Reports", "description": "Reports per Vessel", "type": "integer", "default": 3,
     "min": 1, "max": 4, "step": 1, "decimals": 0},
    {"name": "base_latitude", "label": "Latitude (°)", "description": "Starting simulated vessel latitude in decimal degrees. Original: Starting Latitude (NYC Hudson River).",
     "type": "number", "default": 40.722, "min": 40.0, "max": 41.5, "decimals": 6},
    {"name": "base_longitude", "label": "Longitude (°)", "description": "Starting simulated vessel longitude in decimal degrees. Original: Starting Longitude (NYC Hudson River).",
     "type": "number", "default": -74.020, "min": -75.0, "max": -73.0, "decimals": 6},
]}


async def ais_iq_offline_loopback(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(component, PLUGIN_NAME, "ais_iq_loopback.py", dict(parameters or {}), node_uid)

# FISSURE Action availability filters use configured Sensor Node hardware type
# strings (not OsmoSDR/UHD driver argument names). No hardware filter is used for
# NMEA, file, or offline IQ-only Actions.
ACTION_HARDWARE = {
    "ais_b210_loopback": ["USRP B2x0"],
    "ais_usrp_b210_transmit": ["USRP B2x0"],
    "ais_usrp_b210_receive": ["USRP B2x0"],
    "ais_hackrf_transmit": ["HackRF"],
    "ais_hackrf_receive": ["HackRF"],
    "ais_rtlsdr_receive": ["RTL2832U"],
}


# B210 hardware loopback: one GNU Radio top block opens the same USRP for
# simultaneous TX (TX/RX) and RX (RX2). Verify physical RF path externally.
# The RF center is a separate lab frequency; the baseband remains AIS channel
# A/B +/-25 kHz. This does not transmit on maritime AIS frequencies.
ACTION_TAGS["ais_b210_loopback"] = ["All", "AIS", "protocol.maritime", "signal_analysis.iq"]
ais_b210_loopback_schema = {"params": [
    {"name": "vessel_count", "label": "Vessels", "description": "Synthetic Vessels", "type": "integer", "default": 3,
     "min": 1, "max": 6, "step": 1, "decimals": 0},
    {"name": "position_updates", "label": "Position Reports", "description": "Position Reports per Vessel", "type": "integer", "default": 3,
     "min": 1, "max": 4, "step": 1, "decimals": 0},
    {"name": "base_latitude", "label": "Latitude (°)", "description": "Starting simulated vessel latitude in decimal degrees. Original: NYC Hudson Start Latitude.", "type": "number",
     "default": 40.722, "min": 40.0, "max": 41.5, "decimals": 6},
    {"name": "base_longitude", "label": "Longitude (°)", "description": "Starting simulated vessel longitude in decimal degrees. Original: NYC Hudson Start Longitude.", "type": "number",
     "default": -74.020, "min": -75.0, "max": -73.0, "decimals": 6},
    {"name": "rf_frequency", "label": "RF Center (Hz)", "description": "Center frequency in Hz. Use matching transmit and receive laboratory frequencies. Do not transmit on maritime AIS channels without authorization. Original: LAB TX Center (Hz; match RX; NOT maritime AIS).",
     "type": "number", "default": 915000000, "min": 500000000, "max": 3000000000,
     "step": 1000000, "decimals": 0},
    {"name": "device_args", "label": "Device Args", "description": "SDR selection arguments; for example type=b200, rtl=0 or hackrf=0. Original: B210 UHD Device Args.", "type": "string", "default": "type=b200"},
    {"name": "tx_gain", "label": "TX Gain (dB)", "description": "B210 TX Gain (dB)", "type": "number",
     "default": 40, "min": 0, "max": 90, "step": 0.5, "decimals": 1},
    {"name": "rx_gain", "label": "RX Gain (dB)", "description": "B210 RX Gain (dB)", "type": "integer",
     "default": 40, "min": 0, "max": 60, "step": 1},
]}


async def ais_b210_loopback(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(component, PLUGIN_NAME, "ais_b210_loopback.py", configured_b210_parameters(component, parameters), node_uid)


# Standalone USRP B210 TX/RX. Keep B210 hardware-specific Action names.
# Avoid real maritime AIS TX channels; RF TX only in properly isolated lab.
ACTION_TAGS["ais_usrp_b210_transmit"] = ["All", "AIS", "protocol.maritime", "signal_analysis.iq"]
ais_usrp_b210_transmit_schema = {"params": [
    {"name": "vessel_count", "label": "Vessels", "description": "Synthetic Vessels", "type": "integer", "default": 3,
     "min": 1, "max": 6, "step": 1},
    {"name": "position_updates", "label": "Position Reports", "description": "Reports per Vessel", "type": "integer",
     "default": 3, "min": 1, "max": 4, "step": 1},
    {"name": "base_latitude", "label": "Latitude (°)", "description": "Starting simulated vessel latitude in decimal degrees. Original: Synthetic Vessel Latitude.", "type": "number",
     "default": 40.722, "min": 40.0, "max": 41.5, "decimals": 6},
    {"name": "base_longitude", "label": "Longitude (°)", "description": "Starting simulated vessel longitude in decimal degrees. Original: Synthetic Vessel Longitude.", "type": "number",
     "default": -74.020, "min": -75.0, "max": -73.0, "decimals": 6},
    {"name": "rf_frequency", "label": "RF Center (Hz)", "description": "Center frequency in Hz. Use matching transmit and receive laboratory frequencies. Do not transmit on maritime AIS channels without authorization. Original: LAB TX Center (Hz; match RX).",
     "type": "number", "decimals": 0, "default": 915000000, "min": 500000000,
     "max": 3000000000, "step": 1000000},
    {"name": "tx_gain", "label": "TX Gain (dB)", "description": "B210 TX Gain (dB)", "type": "number",
     "default": 60, "min": 0, "max": 90, "step": 0.5, "decimals": 1},
    {"name": "repeat_count", "label": "Repeat Batches", "description": "Number of AIS TX batches. 0 repeats until the Action is stopped. Use only in an authorized, isolated RF test. Original: Repeat Batches (0 = until Stop; lab only).", "type": "integer", "default": 0, "min": 0, "max": 10000, "step": 1},
    {"name": "serial_number", "label": "USRP Serial", "description": "Optional UHD serial. Blank selects the first available B210.", "type": "string", "default": ""},
    {"name": "rf_channel", "label": "RF Channel", "description": "B210 RF frontend: channel 0 (A:A) or channel 1 (A:B).", "type": "string", "default": "0 (A:A)", "options": ["0 (A:A)", "1 (A:B)"]},
]}


async def ais_usrp_b210_transmit(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(component, PLUGIN_NAME, "ais_usrp_b210_transmit.py", configured_b210_parameters(component, parameters), node_uid)


ACTION_TAGS["ais_usrp_b210_receive"] = ["All", "AIS", "protocol.maritime", "tactical.detection"]
ais_usrp_b210_receive_schema = {"params": [
    {"name": "duration_s", "label": "Duration (s)", "description": "0 streams until stopped; any positive duration streams for that many seconds. No IQ recording is saved.", "type": "integer",
     "default": 0, "min": 0, "max": 86400, "step": 1},
    {"name": "rf_frequency", "label": "RF Center (Hz)", "description": "Center frequency in Hz. Use matching transmit and receive laboratory frequencies. Do not transmit on maritime AIS channels without authorization. Original: RX Center (Hz; AIS 162 MHz / lab match TX).",
     "type": "number", "decimals": 0, "default": 162000000, "min": 70000000,
     "max": 3000000000, "step": 25000},
    {"name": "rx_gain", "label": "RX Gain (dB)", "description": "B210 RX Gain (dB)", "type": "integer",
     "default": 70, "min": 0, "max": 76, "step": 1},
    {"name": "emit_targets", "label": "Update Targets", "description": "Create or update FISSURE vessel Targets using self-reported AIS coordinates, not RF geolocation. Original: Create / Update AIS Targets.", "type": "string",
     "default": "true", "options": ["true", "false"]},
    {"name": "serial_number", "label": "USRP Serial", "description": "Optional UHD serial. Blank selects the first available B210.", "type": "string", "default": ""},
    {"name": "rf_channel", "label": "RF Channel", "description": "B210 RF frontend: channel 0 (A:A) or channel 1 (A:B).", "type": "string", "default": "0 (A:A)", "options": ["0 (A:A)", "1 (A:B)"]},
    {"name": "rx_antenna", "label": "RX Antenna", "description": "B210 receive connector. TX/RX is the default.", "type": "string", "default": "TX/RX", "options": ["TX/RX", "RX2"]},
]}


async def ais_usrp_b210_receive(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(component, PLUGIN_NAME, "ais_usrp_b210_receive.py", configured_b210_parameters(component, parameters), node_uid)

# HackRF is half-duplex. GNU Radio 3.10 receives at 2.4 MS/s natively,
# decimates to 200 kS/s, then uses the proven B210/standalone 3.10 DSP.
# TX stays at 240 kS/s baseband and remains unchanged.
ACTION_TAGS["ais_hackrf_transmit"] = ["All", "AIS", "protocol.maritime", "signal_analysis.iq"]
ais_hackrf_transmit_schema = {"params": [
    {"name": "vessel_count", "label": "Vessels", "description": "Synthetic Vessels", "type": "integer", "default": 3, "min": 1, "max": 6, "step": 1},
    {"name": "position_updates", "label": "Position Reports", "description": "Reports per Vessel", "type": "integer", "default": 3, "min": 1, "max": 4, "step": 1},
    {"name": "base_latitude", "label": "Latitude (°)", "description": "Starting simulated vessel latitude in decimal degrees. Original: NYC Hudson Latitude.", "type": "number", "default": 40.722, "min": 40.0, "max": 41.5, "decimals": 6},
    {"name": "base_longitude", "label": "Longitude (°)", "description": "Starting simulated vessel longitude in decimal degrees. Original: NYC Hudson Longitude.", "type": "number", "default": -74.020, "min": -75.0, "max": -73.0, "decimals": 6},
    {"name": "rf_frequency", "label": "RF Center (Hz)", "description": "Center frequency in Hz. Use matching transmit and receive laboratory frequencies. Do not transmit on maritime AIS channels without authorization. Original: LAB TX Center (Hz; match RX; NOT maritime AIS).", "type": "number", "decimals": 0, "default": 915000000, "min": 500000000, "max": 3000000000, "step": 1000000},
    {"name": "device_args", "label": "Device Args", "description": "Optional HackRF device selection override (e.g., hackrf=0). Blank automatically selects the first available HackRF.", "type": "string", "default": ""},
    {"name": "tx_gain", "label": "TX Gain (dB)", "description": "HackRF TX IF VGA Gain (dB)", "type": "integer", "default": 40, "min": 0, "max": 47, "step": 1},
    {"name": "repeat_count", "label": "Repeat Batches", "description": "Number of AIS TX batches. 0 repeats until the Action is stopped. Use only in an authorized, isolated RF test. Original: Repeat Batches (0 = until Stop; lab only).", "type": "integer", "default": 0, "min": 0, "max": 10000, "step": 1},
]}

async def ais_hackrf_transmit(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(component, PLUGIN_NAME, "ais_hackrf_transmit.py", dict(parameters or {}), node_uid)


ACTION_TAGS["ais_hackrf_receive"] = ["All", "AIS", "protocol.maritime", "tactical.detection"]
ais_hackrf_receive_schema = {"params": [
    {"name": "duration_s", "label": "Duration (s)", "description": "0 streams until stopped; any positive duration streams for that many seconds. No IQ recording is saved.", "type": "integer", "default": 0, "min": 0, "max": 86400, "step": 1},
    {"name": "rf_frequency", "label": "RF Center (Hz)", "description": "Center frequency in Hz. Use matching transmit and receive laboratory frequencies. Do not transmit on maritime AIS channels without authorization. Original: RX Center (Hz; AIS 162 MHz / lab match TX).", "type": "number", "decimals": 0, "default": 162000000, "min": 70000000, "max": 1750000000, "step": 25000},
    {"name": "device_args", "label": "Device Args", "description": "Optional HackRF device selection override (e.g., hackrf=0). Blank automatically selects the first available HackRF.", "type": "string", "default": ""},
    {"name": "lna_gain", "label": "LNA Gain (dB)", "description": "HackRF RX IF / LNA Gain (dB)", "type": "integer", "default": 16, "min": 0, "max": 40, "step": 8},
    {"name": "vga_gain", "label": "VGA Gain (dB)", "description": "HackRF RX Baseband VGA Gain (dB)", "type": "integer", "default": 16, "min": 0, "max": 62, "step": 2},
    {"name": "emit_targets", "label": "Update Targets", "description": "Create or update FISSURE vessel Targets using self-reported AIS coordinates, not RF geolocation. Original: Create / Update AIS Targets.", "type": "string", "default": "true", "options": ["true", "false"]},
]}

async def ais_hackrf_receive(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(component, PLUGIN_NAME, "ais_hackrf_receive.py", dict(parameters or {}), node_uid)


ACTION_TAGS["ais_rtlsdr_receive"] = ["All", "AIS", "protocol.maritime", "tactical.detection"]
ais_rtlsdr_receive_schema = {"params": [
    {"name": "duration_s", "label": "Duration (s)", "description": "0 streams until stopped; any positive duration streams for that many seconds. No IQ recording is saved.", "type": "integer", "default": 0, "min": 0, "max": 86400, "step": 1},
    {"name": "rf_frequency", "label": "RF Center (Hz)", "description": "Center frequency in Hz. Use matching transmit and receive laboratory frequencies. Do not transmit on maritime AIS channels without authorization. Original: RX Center (Hz; AIS 162 MHz / lab match TX).", "type": "number", "decimals": 0, "default": 162000000, "min": 70000000, "max": 1750000000, "step": 25000},
    {"name": "device_args", "label": "Device Args", "description": "SDR selection arguments; for example type=b200, rtl=0 or hackrf=0. Original: RTL-SDR Device Args.", "type": "string", "default": "rtl=0"},
    {"name": "rx_gain", "label": "RX Gain (dB)", "description": "RTL-SDR Tuner Gain (dB)", "type": "integer", "default": 35, "min": 0, "max": 50, "step": 1},
    {"name": "emit_targets", "label": "Update Targets", "description": "Create or update FISSURE vessel Targets using self-reported AIS coordinates, not RF geolocation. Original: Create / Update AIS Targets.", "type": "string", "default": "true", "options": ["true", "false"]},
]}

async def ais_rtlsdr_receive(component: SensorNode, parameters: Dict[str, Any], node_uid: str = "") -> None:
    await component.run_plugin_operation(component, PLUGIN_NAME, "ais_rtlsdr_receive.py", dict(parameters or {}), node_uid)
