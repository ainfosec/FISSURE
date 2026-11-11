#!/usr/bin/env python3
"""Standalone B210 live AIS reception with no raw IQ recordings."""
from __future__ import annotations

import math
import importlib.util
import logging
from pathlib import Path
import sys
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parents[1]
for loc in (ROOT / "operations", ROOT / "scripts"):
    if str(loc) not in sys.path:
        sys.path.insert(0, str(loc))

# Load the shared receive/codec class graph from the installed revision.
# FISSURE may reload leaf Actions in a persistent Sensor Node after upgrade;
# keeping an older ais_receive class would omit newly added Detection fields.
_AIS_CURRENT_REVISION = "ais-plugin-2026-11-10-v1.0"
for _module_name, _relative_path in (
    ("ais_codec", "scripts/ais_codec.py"),
    ("ais_receive", "operations/ais_receive.py"),
    ("ais_iq_receive", "operations/ais_iq_receive.py"),
):
    _existing = sys.modules.get(_module_name)
    if _existing is None or getattr(_existing, "FISSURE_AIS_API_REVISION", None) == _AIS_CURRENT_REVISION:
        continue
    _origin = getattr(_existing, "__file__", None)
    if _origin and Path(_origin).resolve() == (ROOT / _relative_path).resolve():
        del sys.modules[_module_name]

from ais_codec import boolean
from ais_iq_receive import OperationMain as AISIQReceiver
from ais_sdr_operation_runtime import AISB210OperationRuntime
from ais_b210_frontend_v097 import make_device_args, channel_details, validate_antenna
# Load the runtime from this installed plugin revision, not from a stale
# Sensor Node sys.modules entry retained across hot plugin updates.
_stream_path = ROOT / 'scripts' / 'ais_stream_runtime_v090.py'
_stream_spec = importlib.util.spec_from_file_location(
    'fissure_ais_stream_runtime_current', str(_stream_path))
_stream = importlib.util.module_from_spec(_stream_spec)
_stream_spec.loader.exec_module(_stream)
run_stream_monitor = _stream.run_stream_monitor
# Load installed helper, not a stale module left by an earlier plugin release.
_hardware_path = ROOT / 'scripts' / 'ais_sdr_hardware.py'
_hardware_spec = importlib.util.spec_from_file_location('fissure_ais_ais_sdr_hardware_v084', str(_hardware_path))
_hardware = importlib.util.module_from_spec(_hardware_spec)
_hardware_spec.loader.exec_module(_hardware)
validate_rx = _hardware.validate_rx


from ais_status_runtime_v091 import AISStatusMixin


class OperationMain(AISStatusMixin, AISIQReceiver, AISB210OperationRuntime):
    def __init__(self, duration_s=0, rf_frequency=162000000,
                 sample_rate=240000, device_args="type=b200", rx_gain=70,
                 serial_number="", rf_channel=0, rx_antenna="TX/RX",
                 simulated_input=False, emit_targets=True, detection_interval_s=5,
                 node_uid="", logger=logging.getLogger(__name__),
                 detection_callback: Optional[Callable] = None,
                 target_callback: Optional[Callable] = None,
                 status_callback: Optional[Callable] = None,
                 artifact_manager=None):
        super().__init__(iq_file="", sample_rate=sample_rate,
                         # gr-ais should see nominal AIS channel offsets, even
                         # if an isolated RF replay used a different carrier.
                         center_frequency=162000000.0, channel="both",
                         decoder_timeout_s=180, emit_targets=emit_targets,
                         save_artifact=True, node_uid=node_uid, logger=logger,
                         detection_callback=detection_callback,
                         target_callback=target_callback,
                         status_callback=status_callback,
                         artifact_manager=artifact_manager)
        self.duration_s = float(duration_s)
        self.rf_frequency = float(rf_frequency)
        self.device_args = make_device_args(device_args, serial_number)
        self.serial_number = str(serial_number or "").strip()
        self.rf_channel = str(rf_channel)
        channel_details(self.rf_channel)
        self.rx_antenna = validate_antenna(rx_antenna)
        self.rx_gain = float(rx_gain)
        self.detection_interval_s = float(detection_interval_s)
        self._lab_replay = not (161900000 <= self.rf_frequency <= 162100000)
        self._simulated = boolean(simulated_input, False) or self._lab_replay
        self._simulated_source = ("lab_band_rf_replay" if self._lab_replay else
                                  "user_declared_simulated_b210_rf" if self._simulated else "")
        if not math.isfinite(self.duration_s) or not (self.duration_s == 0 or 1 <= self.duration_s <= 86400):
            raise ValueError('RX duration must be 0 (until stopped) or 1..86400 seconds')
        validate_rx(self.sample_rate, self.rf_frequency, self.rx_gain,
                    self.device_args, min(20.0, self.duration_s) if self.duration_s else 20.0)

    @staticmethod
    def get_resources():
        return {}  # Shared local advisory lock; FISSURE-wide reservation not verified.

    async def run(self):
        """Use the same uninterrupted streaming decoder for every duration.

        Standalone receive never saves IQ; the separate B210 loopback retains
        its explicitly requested diagnostic IQ capture behavior.
        """
        return await run_stream_monitor(self, 'b210')
