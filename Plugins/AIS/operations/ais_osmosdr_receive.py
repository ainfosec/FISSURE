#!/usr/bin/env python3
"""Live AIS receive for HackRF and RTL-SDR on GNU Radio 3.8/3.10.

All receive durations use streaming IQ-to-NMEA decoding; no IQ recordings or
raw IQ Artifacts are created. Vessel state, Detections and Targets remain live.
"""
from __future__ import annotations
import importlib.util
import math
import logging
from pathlib import Path
import sys
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parents[1]
for loc in (ROOT / 'operations', ROOT / 'scripts'):
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
# Load the runtime from this installed plugin revision, not from a stale
# Sensor Node sys.modules entry retained across hot plugin updates.
_stream_path = ROOT / 'scripts' / 'ais_stream_runtime_v090.py'
_stream_spec = importlib.util.spec_from_file_location(
    'fissure_ais_stream_runtime_current', str(_stream_path))
_stream = importlib.util.module_from_spec(_stream_spec)
_stream_spec.loader.exec_module(_stream)
run_stream_monitor = _stream.run_stream_monitor
# Load installed helper, not a stale module left by an earlier plugin release.
_hardware_path = ROOT / 'scripts' / 'ais_osmosdr_hardware.py'
_hardware_spec = importlib.util.spec_from_file_location('fissure_ais_ais_osmosdr_hardware_v084', str(_hardware_path))
_hardware = importlib.util.module_from_spec(_hardware_spec)
_hardware_spec.loader.exec_module(_hardware)
validate_rx = _hardware.validate_rx
from ais_device_lock_v081 import lock_radio as _lock_radio, unlock_radio as _unlock_radio


from ais_status_runtime_v091 import AISStatusMixin


class AISOsmoReceiver(AISStatusMixin, AISIQReceiver, AISB210OperationRuntime):
    lock_radio = _lock_radio
    unlock_radio = _unlock_radio

    def __init__(self, radio_kind='rtl', duration_s=0, rf_frequency=162000000,
                 device_args=None, rx_gain=35, lna_gain=16, vga_gain=16,
                 simulated_input=False, emit_targets=True, detection_interval_s=5,
                 node_uid='', logger=logging.getLogger(__name__),
                 detection_callback: Optional[Callable] = None,
                 target_callback: Optional[Callable] = None,
                 status_callback: Optional[Callable] = None,
                 artifact_manager=None):
        if device_args is None:
            device_args = '' if radio_kind == 'hackrf' else 'rtl=0'
        super().__init__(iq_file='', sample_rate=240000,
                         center_frequency=162000000.0, channel='both',
                         decoder_timeout_s=180, emit_targets=emit_targets,
                         save_artifact=True, node_uid=node_uid, logger=logger,
                         detection_callback=detection_callback,
                         target_callback=target_callback,
                         status_callback=status_callback,
                         artifact_manager=artifact_manager)
        self.radio_kind = radio_kind
        self.duration_s = float(duration_s)
        self.rf_frequency = float(rf_frequency)
        self.device_args = str(device_args or '').strip()
        self.rx_gain = float(rx_gain)
        self.lna_gain = float(lna_gain)
        self.vga_gain = float(vga_gain)
        self.detection_interval_s = float(detection_interval_s)
        # Traffic outside the maritime AIS allocation is a laboratory replay,
        # not independently observed vessel traffic. Prevent a lab test from
        # silently creating 'live' FISSURE Targets if the user leaves the
        # simulation selector at its receive-only default.
        self._lab_replay = not (161900000 <= self.rf_frequency <= 162100000)
        self._simulated = boolean(simulated_input, False) or self._lab_replay
        self._simulated_source = ('lab_band_rf_replay' if self._lab_replay else
                                  'user_declared_simulated_%s_rf' % radio_kind if self._simulated else '')
        if not math.isfinite(self.duration_s) or not (self.duration_s == 0 or 1 <= self.duration_s <= 86400):
            raise ValueError('RX duration must be 0 (until stopped) or 1..86400 seconds')
        validate_rx(self.radio_kind, self.rf_frequency, min(20.0, self.duration_s) if self.duration_s else 20.0,
                    self.device_args or ('hackrf=0' if self.radio_kind == 'hackrf' else 'rtl=0'),
                    self.rx_gain, self.lna_gain, self.vga_gain)

    @staticmethod
    def get_resources():
        return {}

    async def run(self):
        """Stream throughout the requested duration, including short sessions.

        Duration 0 runs until Stop; all positive durations are wall-clock limits.
        IQ is never written to a file or registered as an Artifact.
        """
        return await run_stream_monitor(self, self.radio_kind)
