#!/usr/bin/env python3
"""Single-B210, cabled, simultaneous RF TX/RX loopback of synthetic AIS IQ.

Creates Type 18/24 synthetic vessel traffic, generates *verified* offline IQ,
transmits at a NON-AIS lab frequency, captures the B210 RX2 path, then
reuses the existing gr-ais decoder and FISSURE AIS Target/Artifact pipeline.
"""
from __future__ import annotations

import asyncio
from collections import Counter
import fcntl
import importlib.util
import inspect
import json
import logging
import math
import tempfile
from pathlib import Path
import sys
from typing import Callable, Optional

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
for extra in (str(PLUGIN_ROOT / "scripts"), str(PLUGIN_ROOT / "operations")):
    if extra not in sys.path:
        sys.path.insert(0, extra)

# Reuse the verified offline generator's vessel/identity creation and FISSURE
# operation base; do not fork parallel implementations of Target/Detection logic.
from ais_iq_loopback import OperationMain as OfflineLoopback, sha256_file
from ais_iq_receive import OperationMain as IQReceiver
from ais_codec import boolean, require_pyais


from ais_status_runtime_v091 import AISStatusMixin


class OperationMain(AISStatusMixin, OfflineLoopback):
    def __init__(self,
                 vessel_count=3, position_updates=3, include_static_data=True,
                 base_latitude=40.722, base_longitude=-74.020,
                 sample_rate=240000, gap_ms=350, emit_targets=True,
                 rf_frequency=915000000, device_args="type=b200",
                 tx_gain=40, rx_gain=40,
                 node_uid="", logger=logging.getLogger(__name__),
                 detection_callback: Optional[Callable] = None,
                 target_callback: Optional[Callable] = None,
                 status_callback: Optional[Callable] = None,
                 artifact_manager=None):
        super().__init__(
            vessel_count=vessel_count, position_updates=position_updates,
            include_static_data=include_static_data,
            base_latitude=base_latitude, base_longitude=base_longitude,
            sample_rate=sample_rate, gap_ms=gap_ms, emit_targets=emit_targets,
            node_uid=node_uid, logger=logger, detection_callback=detection_callback,
            target_callback=target_callback, status_callback=status_callback,
            artifact_manager=artifact_manager)
        self.rf_frequency = float(rf_frequency)
        self.device_args = str(device_args)
        self.tx_gain = float(tx_gain)
        self.rx_gain = float(rx_gain)
        self.tx_amplitude = 0.15  # Fixed internal baseband scaling, not a UI gain.
        self._simulated_source = "isolated_b210_rf_loopback"
        self._hardware_proc = None
        self._capture_artifact_id = ""
        self._generator_succeeded = False
        self._hardware_succeeded = False
        self._hardware_attempted = False
        self._lock_handle = None
        self._rf_signal_diagnostics = {}

    @staticmethod
    def get_resources():
        # Important: one B210 handles TX and RX in one UHD top block. The
        # actual FISSURE-wide SDR reservation integration is still unverified.
        # A process-local advisory lock below prevents concurrent AIS B210
        # loopbacks, but not unrelated GNU Radio programs using the same radio.
        return {}

    async def _stop_hardware(self):
        proc = self._hardware_proc
        if proc is not None and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

    async def _call(self, command, timeout, phase):
        proc = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, cwd=str(PLUGIN_ROOT))
        self._hardware_proc = proc
        gather = asyncio.create_task(proc.communicate())
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        try:
            while not gather.done():
                if self._stop:
                    await self._stop_hardware()
                    raise asyncio.CancelledError("AIS B210 Action stopped")
                if loop.time() >= deadline:
                    await self._stop_hardware()
                    raise RuntimeError("AIS %s timed out" % phase)
                await asyncio.wait({gather}, timeout=0.25)
            stdout, stderr = await gather
        except BaseException:
            await self._stop_hardware()
            if not gather.done():
                await asyncio.wait({gather}, timeout=5)
            raise
        if self._stop:
            raise asyncio.CancelledError("AIS B210 Action stopped")
        if proc.returncode != 0:
            raise RuntimeError("AIS %s failed (%d): %s %s" % (
                phase, proc.returncode, stdout.decode("utf-8", "replace")[-700:],
                stderr.decode("utf-8", "replace")[-1600:]))
        self.logger.info("AIS %s: %s", phase, stdout.decode("utf-8", "replace")[-1000:])
        self._hardware_proc = None

    def _validate_rf_settings(self):
        # FISSURE can reload Actions without restarting its Sensor Node.
        # Importing by the shared module name may reuse an old in-memory
        # helper whose validate_settings still expects attenuation_db and
        # confirmed. Load the on-disk helper under an isolated name instead.
        helper_path = PLUGIN_ROOT / "scripts" / "ais_b210_rf_hardware.py"
        spec = importlib.util.spec_from_file_location(
            "_fissure_ais_b210_rf_settings_current", str(helper_path))
        if spec is None or spec.loader is None:
            raise RuntimeError("Cannot load AIS B210 hardware helper: %s" % helper_path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        validator = getattr(helper, "validate_settings", None)
        if not callable(validator):
            raise RuntimeError("AIS B210 hardware helper is missing validate_settings: %s" % helper_path)
        parameters = inspect.signature(validator).parameters
        if "attenuation_db" in parameters or "confirmed" in parameters:
            raise RuntimeError(
                "Outdated AIS B210 hardware helper on disk; replace "
                "Plugins/AIS/scripts/ais_b210_rf_hardware.py with the current release")
        return validator(
            self.sample_rate, self.rf_frequency, self.tx_gain, self.rx_gain,
            self.device_args)

    def _lock_b210(self):
        self._lock_handle = (Path(tempfile.gettempdir()) / "fissure_ais_b210_loopback.lock").open("a+")
        try:
            fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._lock_handle.close()
            self._lock_handle = None
            raise RuntimeError("Another AIS B210 loopback is already running on this node")

    def _unlock_b210(self):
        if self._lock_handle:
            fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
            self._lock_handle.close()
            self._lock_handle = None

    def _link_capture(self, state, reason=""):
        ids = [self._stimulus_artifact_id, self._capture_artifact_id, self._received_artifact_id]
        for index, artifact_id in enumerate(ids):
            if not artifact_id:
                continue
            roles = {
                (0, 1): "captured_as", (0, 2): "decoded_as",
                (1, 0): "transmitted_from", (1, 2): "decoded_as",
                (2, 0): "transmitted_from", (2, 1): "decoded_from_capture",
            }
            relations = [
                {"entity_type": "artifact", "entity_id": other,
                 "role": roles[index, j]}
                for j, other in enumerate(ids) if j != index and other]
            self.update_artifact(artifact_id,
                metadata={"rf_roundtrip_validation": state,
                          "rf_roundtrip_reason": str(reason)[:450],
                          "stimulus_artifact_id": ids[0] or None,
                          "capture_artifact_id": ids[1] or None,
                          "received_artifact_id": ids[2] or None,
                          "decoded_messages": self._message_count,
                          "rf_transmitted_verified": self._hardware_succeeded,
                          "rf_tx_may_have_occurred": self._hardware_attempted},
                relations=relations)

    async def run(self):
        # Validate numerical parameters before creating a UHD stream.
        # Software cannot verify attenuation or RF input power.
        self._validate_rf_settings()
        require_pyais()
        if not self.artifact_manager:
            raise RuntimeError("B210 loopback requires FISSURE ArtifactManager")
        self._lock_b210()
        _, folder = self.artifact_manager.create_operation_dir(self.opid)
        root = Path(folder)
        source = root / "ais_b210_source.nmea"
        tx_iq = root / "ais_b210_tx_baseband.cf32"
        tx_manifest = root / "ais_b210_tx_manifest.json"
        rx_iq = root / "ais_b210_rx_capture.cf32"
        rx_manifest = root / "ais_b210_rx_manifest.json"
        validation = root / "ais_b210_validation.json"
        error = ""
        state = "failed"
        try:
            count = self._create_nmea(source)
            await self._status("AIS B210: create %d synthetic AIS frames (no RF yet)" % count)
            gen_script = PLUGIN_ROOT / "scripts" / "ais_iq_generator.py"
            await self._call([
                sys.executable, "-u", str(gen_script), "--input", str(source),
                "--output", str(tx_iq), "--manifest", str(tx_manifest),
                "--sample-rate", str(int(self.sample_rate)), "--gap-ms", str(self.gap_ms),
                "--max-frames", str(count)], 180, "offline IQ generation")
            manifest = json.loads(tx_manifest.read_text(encoding="utf-8"))
            if (manifest.get("frame_count") != count or manifest.get("skipped_nmea_sentences") or
                    manifest.get("rf_transmitted") is not False):
                raise RuntimeError("B210 TX IQ manifest does not match the requested AIS messages")
            self._generator_succeeded = True
            self._stimulus_artifact_id = str(self.create_artifact(
                files=[str(source), str(tx_iq), str(tx_manifest)],
                name="AIS B210 Synthetic TX Stimulus", artifact_type="ais_b210_tx_stimulus",
                metadata={"schema": "fissure.ais.b210_tx.v1", "node_uid": self.node_uid,
                          "operation_id": self.opid, "simulated": True, "lab_rf_only": True,
                          "rf_transmitted": False, "rf_frequency_hz": self.rf_frequency,
                          "message_count": count, "expected_mmsis": sorted(self._expected_mmsis),
                          "nmea_sha256": sha256_file(source), "tx_iq_sha256": sha256_file(tx_iq)}) or "")
            if not self._stimulus_artifact_id:
                raise RuntimeError("TX stimulus Artifact registration failed")
            if self._stop:
                state = "stopped"
                return
            await self._status("AIS B210: starting simultaneous cabled TX/RX, no antennas")
            hardware = PLUGIN_ROOT / "scripts" / "ais_b210_rf_hardware.py"
            # The helper performs its own independent parameter checks.
            self._hardware_attempted = True
            await self._call([
                sys.executable, "-u", str(hardware), "--input", str(tx_iq),
                "--output", str(rx_iq), "--manifest", str(rx_manifest),
                "--sample-rate", str(int(self.sample_rate)),
                "--rf-frequency", str(self.rf_frequency),
                "--device-args", self.device_args,
                "--tx-gain", str(self.tx_gain), "--rx-gain", str(self.rx_gain)],
                180, "B210 cabled RF TX/RX")
            hw = json.loads(rx_manifest.read_text(encoding="utf-8"))
            if hw.get("rf_transmitted") is not True or not rx_iq.is_file():
                raise RuntimeError("B210 did not confirm RF capture completion")
            self._hardware_succeeded = True
            # Characterize actual RX samples BEFORE decoding; a completed UHD
            # capture alone does not establish that any RF burst arrived.
            diagnostic_file = root / "ais_b210_signal_diagnostics.json"
            diagnostic_files = []
            try:
                from ais_b210_diagnostics import analyze_capture
                self._rf_signal_diagnostics = analyze_capture(rx_iq, int(self.sample_rate))
                diagnostic_file.write_text(
                    json.dumps(self._rf_signal_diagnostics, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8")
                diagnostic_files = [str(diagnostic_file)]
                if not self._rf_signal_diagnostics.get("visible_power_bursts"):
                    await self._status(
                        "AIS B210: capture contains no detectable RF bursts; "
                        "inspect coax/ports and UHD TX streaming before AIS decode")
            except Exception as diagnose_exc:
                # Do not discard successfully captured RF if a diagnostic fails.
                self._rf_signal_diagnostics = {
                    "diagnostic_error": "%s: %s" % (
                        type(diagnose_exc).__name__, diagnose_exc)}
                self.logger.warning("B210 receive power diagnostic unavailable: %s", diagnose_exc)
            self._capture_artifact_id = str(self.create_artifact(
                files=[str(rx_iq), str(rx_manifest)] + diagnostic_files,
                name="AIS B210 RF RX Capture", artifact_type="ais_b210_rx_iq",
                metadata={"schema": "fissure.ais.b210_rx.v1", "node_uid": self.node_uid,
                          "operation_id": self.opid, "simulated_vessels": True,
                          "rf_transmitted": True, "rf_frequency_hz": self.rf_frequency,
                          "sample_rate_hz": self.sample_rate,
                          "source_stimulus_artifact_id": self._stimulus_artifact_id,
                          "received_iq_sha256": sha256_file(rx_iq),
                          "rx_power_diagnostics": self._rf_signal_diagnostics}) or "")
            if not self._capture_artifact_id:
                raise RuntimeError("B210 RX IQ Artifact registration failed")
            self.iq_file = str(rx_iq)
            self._input_metadata.update({
                "simulated": True, "simulation_source": self._simulated_source,
                "rf_transmitted": True, "rf_center_frequency_hz": self.rf_frequency,
                "virtual_ais_iq_center_frequency_hz": 162000000.0,
                "source_operation_id": self.opid,
                "stimulus_artifact_id": self._stimulus_artifact_id,
                "rx_capture_artifact_id": self._capture_artifact_id,
                "expected_messages": count, "expected_mmsis": sorted(self._expected_mmsis),
                "rx_iq_sha256": sha256_file(rx_iq),
            })
            await self._status("AIS B210 capture saved; decoding received RF IQ with gr-ais")
            # Invoke only IQReceiver.run, not OfflineLoopback.run (which would
            # create another entirely offline TX IQ file).
            await IQReceiver.run(self)
            if self._stop:
                state = "stopped"
                return
            actual_raw = self._files.get("raw")
            if not actual_raw or not actual_raw.is_file():
                raise RuntimeError("B210 receiver did not save decoded NMEA output")
            expected = Counter(source.read_text(encoding="ascii").splitlines())
            observed = Counter(actual_raw.read_text(encoding="ascii").splitlines())
            missing = expected - observed
            extra = observed - expected
            absent = self._expected_mmsis.difference(self._vessels)
            identity_errors = [m for m, (name, callsign) in self._expected_names.items()
                               if self._vessels.get(m, {}).get("ship_name") != name or
                                  self._vessels.get(m, {}).get("callsign") != callsign]
            if missing or extra or absent or identity_errors or self._message_count != count:
                power_hint = (
                    "; RX IQ has no detectable burst power: verify physical coax, "
                    "TX/RX and RX2 ports, and UHD TX stream"
                    if self._rf_signal_diagnostics.get("visible_power_bursts") is False else "")
                raise RuntimeError("RF roundtrip incomplete: decoded %d/%d messages; missing=%d, "
                                   "unexpected=%d, absent MMSIs=%s, bad identities=%s%s" % (
                                       self._message_count, count, sum(missing.values()),
                                       sum(extra.values()), sorted(absent), identity_errors,
                                       power_hint))
            state = "passed"
            await self._status("AIS B210 cabled RF verified: %d/%d messages, %d vessels" % (
                self._message_count, count, len(self._expected_mmsis)))
        except asyncio.CancelledError:
            state = "stopped" if self._stop else "cancelled"
            raise
        except Exception as exc:
            error = "%s: %s" % (type(exc).__name__, exc)
            await self._status("AIS B210 RF test failed: " + error[:230])
            raise
        finally:
            await self._stop_hardware()
            await self._stop_generator()
            self._unlock_b210()
            # Store a final, immutable report rather than leaving a stale
            # 'pending' state in a registered Artifact's original JSON file.
            record = {
                "schema": "fissure.ais.b210_validation.v1", "state": state,
                "error": error, "operation_id": self.opid,
                "simulated_vessels": True, "rf_lab_transmitted": self._hardware_succeeded,
                "rf_tx_may_have_occurred": self._hardware_attempted,
                "rf_frequency_hz": self.rf_frequency,
                "stimulus_generated": self._generator_succeeded,
                "rx_power_diagnostics": self._rf_signal_diagnostics,
                "expected_messages": self.vessel_count * (self.position_updates + (2 if self.include_static_data else 0)),
                "decoded_messages": self._message_count,
                "mmsis": sorted(self._vessels),
                "stimulus_artifact_id": self._stimulus_artifact_id or None,
                "capture_artifact_id": self._capture_artifact_id or None,
                "received_artifact_id": self._received_artifact_id or None,
            }
            validation.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            if self._stimulus_artifact_id or self._capture_artifact_id or self._received_artifact_id:
                self._link_capture(state, error)
            self.create_artifact(
                files=[str(validation)], name="AIS B210 RF Loopback Validation",
                artifact_type="ais_b210_validation", metadata=record)
