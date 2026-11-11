#!/usr/bin/env python3
"""Offline AIS Type 18/24 (or legacy Type 1) -> GMSK IQ -> gr-ais -> FISSURE.

No SDR or RF transmission. GNU Radio 3.8 or 3.10 is required for IQ generation.
The received AIS Artifact links directly to the originating IQ stimulus Artifact.
"""
from __future__ import annotations

import asyncio
from collections import Counter
import hashlib
import json
import logging
from pathlib import Path
import sys
from typing import Callable, Optional

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
for extra in (str(PLUGIN_ROOT / "scripts"), str(PLUGIN_ROOT / "operations")):
    if extra not in sys.path:
        sys.path.insert(0, extra)

# SensorNode loads Action scripts dynamically but Python caches their ordinary
# imports. On a plugin upgrade, e.g. v0.4.4 -> v0.5.0, ``ais_codec`` may still
# reference the old class/function definitions even though the file on disk
# contains the new implementation. Load the versioned local helper *graph*
# afresh, without in-place mutation of any already running Operation objects.
FISSURE_AIS_API_REVISION = "ais-plugin-2026-11-10-v1.0"
_LOCAL_HELPERS = (
    ("ais_codec", PLUGIN_ROOT / "scripts" / "ais_codec.py"),
    ("ais_receive", PLUGIN_ROOT / "operations" / "ais_receive.py"),
    ("ais_iq_receive", PLUGIN_ROOT / "operations" / "ais_iq_receive.py"),
)
for _module_name, _expected_path in _LOCAL_HELPERS:
    _cached = sys.modules.get(_module_name)
    if _cached is None or getattr(_cached, "FISSURE_AIS_API_REVISION", None) == FISSURE_AIS_API_REVISION:
        continue
    _cached_path = getattr(_cached, "__file__", None)
    if not _cached_path or Path(_cached_path).resolve() != _expected_path.resolve():
        raise ImportError(
            "AIS helper module name collision for %s (loaded from %s); "
            "restart the Sensor Node to clear stale modules" % (_module_name, _cached_path)
        )
    # Removing the cache entry only affects *new imports*, not references held
    # by an already running Operation. Keep the dependency order codec -> RX -> IQ.
    del sys.modules[_module_name]

from ais_iq_receive import OperationMain as IQReceiver
from ais_codec import boolean, encode_class_b_static, encode_position, require_pyais


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


class OperationMain(IQReceiver):
    def __init__(
        self,
        vessel_count: int = 3,
        position_updates: int = 3,
        include_static_data: bool = True,
        base_latitude: float = 40.722,
        base_longitude: float = -74.020,
        sample_rate: float = 240000,
        gap_ms: float = 350,
        emit_targets: bool = True,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        detection_callback: Optional[Callable] = None,
        target_callback: Optional[Callable] = None,
        status_callback: Optional[Callable] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(iq_file="", sample_rate=sample_rate, center_frequency=162000000.0,
                         channel="both", decoder_timeout_s=120,
                         emit_targets=emit_targets, save_artifact=True,
                         node_uid=node_uid, logger=logger,
                         detection_callback=detection_callback,
                         target_callback=target_callback,
                         status_callback=status_callback,
                         artifact_manager=artifact_manager)
        self.vessel_count = int(float(vessel_count))
        self.position_updates = int(float(position_updates))
        self.include_static_data = boolean(include_static_data, True)
        self.base_latitude = float(base_latitude)
        self.base_longitude = float(base_longitude)
        self.gap_ms = int(float(gap_ms))
        if not 1 <= self.vessel_count <= 6 or not 1 <= self.position_updates <= 4:
            raise ValueError("AIS IQ loopback supports 1-6 vessels and 1-4 position updates")
        if self.vessel_count * (self.position_updates + (2 if self.include_static_data else 0)) > 48:
            raise ValueError("AIS IQ loopback is capped at 48 radio frames")
        if not (40.0 <= self.base_latitude <= 41.5 and -75.0 <= self.base_longitude <= -73.0):
            raise ValueError("Offline NYC demonstration latitude/longitude are outside demo area")
        if not 150 <= self.gap_ms <= 2000:
            raise ValueError("Gap must be 150–2000 milliseconds")
        if int(self.sample_rate) % 48000 or not 192000 <= self.sample_rate <= 960000:
            raise ValueError("Sample rate must be a 48000-Hz multiple, 192000–960000")
        self._simulated = True
        self._simulated_source = "offline_gmsk_iq_loopback"
        self._generator_proc = None
        self._expected_mmsis = set()
        self._expected_names = {}
        self._stimulus_artifact_id = ""

    @staticmethod
    def get_resources():
        return {}  # Offline file-based signal processing only.

    async def _stop_generator(self):
        proc = self._generator_proc
        if proc is not None and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=3)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

    def _create_nmea(self, path):
        frames = []
        for vessel in range(self.vessel_count):
            mmsi = "%09d" % (200000001 + vessel)
            self._expected_mmsis.add(mmsi)
            if self.include_static_data:
                name = "FISSURE DEMO %02d" % (vessel + 1)
                callsign = "SIM%04d" % (vessel + 1)
                self._expected_names[mmsi] = (name, callsign)
                channel = "A" if vessel % 2 == 0 else "B"
                frames.extend(encode_class_b_static(mmsi, name, callsign, channel))
        # With static Type 24 A/B present, use matching Class B Type 18
        # position reports. Keep the earlier verified Type 1 route selectable.
        for step in range(self.position_updates):
            for vessel in range(self.vessel_count):
                mmsi = "%09d" % (200000001 + vessel)
                lat = self.base_latitude + vessel * 0.003 + step * 0.0006
                lon = self.base_longitude + vessel * 0.0006 + step * 0.0001
                channel = "A" if vessel % 2 == 0 else "B"
                message_type = 18 if self.include_static_data else 1
                sentences = encode_position(mmsi, lat, lon, 6.0 + vessel, 10.0,
                                            channel, message_type=message_type)
                if len(sentences) != 1:
                    raise RuntimeError("Single-slot position report was unexpectedly fragmented")
                frames.extend(sentences)
        path.write_text("\n".join(frames) + "\n", encoding="ascii")
        return len(frames)

    def _record_verification(self, state, reason="", expected_count=0):
        """Persist the result to both managed Artifact manifests, when present."""
        metadata = {"roundtrip_validation": state, "roundtrip_validation_reason": str(reason)[:500],
                    "expected_messages": int(expected_count),
                    "decoded_messages": self._message_count,
                    "received_artifact_id": self._received_artifact_id or None,
                    "stimulus_artifact_id": self._stimulus_artifact_id or None}
        for artifact_id, other_id, relation_role in (
            (self._stimulus_artifact_id, self._received_artifact_id, "decoded_into"),
            (self._received_artifact_id, self._stimulus_artifact_id, "decoded_from"),
        ):
            if artifact_id:
                relations = ([{"entity_type": "artifact", "entity_id": other_id,
                              "role": relation_role}] if other_id else None)
                if not self.update_artifact(artifact_id, metadata=metadata, relations=relations):
                    self.logger.warning("AIS could not persist %s validation to Artifact %s", state, artifact_id)

    async def run(self):
        require_pyais()
        if not self.artifact_manager:
            raise RuntimeError("AIS IQ loopback requires FISSURE ArtifactManager")
        _, folder = self.artifact_manager.create_operation_dir(self.opid)
        workdir = Path(folder)
        source = workdir / "ais_iq_stimulus.nmea"
        iq_file = workdir / "ais_loopback.cf32"
        manifest = workdir / "ais_iq_stimulus_manifest.json"
        complete = False
        try:
            count = self._create_nmea(source)
            await self._status("AIS offline IQ loopback: generating %d radio frames (NO RF)" % count)
            generator = PLUGIN_ROOT / "scripts" / "ais_iq_generator.py"
            self._generator_proc = await asyncio.create_subprocess_exec(
                sys.executable, "-u", str(generator), "--input", str(source),
                "--output", str(iq_file), "--manifest", str(manifest),
                "--sample-rate", str(int(self.sample_rate)), "--gap-ms", str(self.gap_ms),
                "--max-frames", str(count),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                cwd=str(PLUGIN_ROOT))
            try:
                stdout, stderr = await asyncio.wait_for(self._generator_proc.communicate(), timeout=150)
            except asyncio.TimeoutError:
                await self._stop_generator()
                raise RuntimeError("AIS IQ modulation timed out")
            if self._generator_proc.returncode != 0:
                raise RuntimeError("AIS IQ generator exited %s: %s" % (
                    self._generator_proc.returncode, stderr.decode("utf-8", "replace")[-1200:]))
            if self._stop:
                await self._status("AIS offline IQ loopback stopped after waveform generation")
                return
            if not iq_file.is_file() or not manifest.is_file():
                raise RuntimeError("IQ generator did not produce the IQ file and manifest")
            generated_manifest = json.loads(manifest.read_text(encoding="utf-8"))
            if (generated_manifest.get("frame_count") != count or
                    generated_manifest.get("skipped_nmea_sentences") != 0 or
                    generated_manifest.get("rf_transmitted") is not False):
                raise RuntimeError("IQ manifest does not match the requested AIS test stimulus")
            complete = True
            hashes = {"nmea_sha256": sha256_file(source), "iq_sha256": sha256_file(iq_file),
                      "manifest_sha256": sha256_file(manifest)}
            source_metadata = {
                "schema": "fissure.ais.iq_loopback.v2", "node_uid": self.node_uid,
                "operation_id": self.opid, "simulated": True, "rf_transmitted": False,
                "input_mode": "offline_iq_loopback", "iq_generation_complete": True,
                "expected_frames": count, "expected_mmsis": sorted(self._expected_mmsis),
                "expected_message_types": [18, 24] if self.include_static_data else [1],
                "sample_rate_hz": self.sample_rate, "center_frequency_hz": self.center_frequency,
                **hashes,
            }
            # Register the source first so the *received* Artifact can reference
            # a known managed Artifact ID, not just the filename in an op dir.
            self._stimulus_artifact_id = str(self.create_artifact(
                files=[str(source), str(iq_file), str(manifest)],
                name="AIS Offline GMSK IQ Stimulus",
                artifact_type="ais_iq_simulation", metadata=source_metadata,
                file_metadata={"ais_iq_stimulus.nmea": {"content_type": "text/plain"},
                               "ais_iq_stimulus_manifest.json": {"content_type": "application/json"},
                               "ais_loopback.cf32": {"content_type": "application/octet-stream"}}) or "")
            if not self._stimulus_artifact_id:
                raise RuntimeError("AIS IQ stimulus Artifact registration failed")
            self.iq_file = str(iq_file)
            self._input_metadata.update({
                "roundtrip_validation": "pending",
                "simulated": True, "simulation_source": self._simulated_source,
                "source_operation_id": self.opid,
                "stimulus_artifact_id": self._stimulus_artifact_id,
                "iq_generator": "finite AIS HDLC / GNU Radio GMSK (NO RF)",
                "expected_frames": count, "expected_mmsis": sorted(self._expected_mmsis),
                "source_nmea": source.name, **hashes,
            })
            await self._status("AIS IQ ready: %d bytes; decoding gr-ais" % iq_file.stat().st_size)
            await super().run()
            if self._stop:
                self._record_verification("stopped", expected_count=count)
                return
            received = self._files.get("raw")
            if not received or not received.is_file():
                raise RuntimeError("IQ receiver did not retain NMEA messages for verification")
            expected = Counter(source.read_text(encoding="ascii").splitlines())
            observed = Counter(received.read_text(encoding="ascii").splitlines())
            missing_sentences = expected - observed
            extra_sentences = observed - expected
            missing_mmsis = self._expected_mmsis.difference(self._vessels)
            if missing_sentences or extra_sentences or self._message_count != count or missing_mmsis:
                raise RuntimeError("AIS IQ roundtrip mismatch: expected %d messages, got %d; "
                                   "missing %d, extra %d NMEA sentences; missing MMSIs %s" % (
                                       count, self._message_count, sum(missing_sentences.values()),
                                       sum(extra_sentences.values()), sorted(missing_mmsis)))
            if self.include_static_data:
                bad_identity = [mmsi for mmsi, (name, callsign) in self._expected_names.items()
                                if (self._vessels.get(mmsi, {}).get("ship_name") != name or
                                    self._vessels.get(mmsi, {}).get("callsign") != callsign)]
                if bad_identity:
                    raise RuntimeError("AIS static identity decoding mismatch for MMSIs: %s" % bad_identity)
            self._record_verification("passed", expected_count=count)
            await self._status("AIS IQ verified: %d/%d messages, %d named vessels, receive Artifact %s" % (
                self._message_count, count, len(self._expected_names), self._received_artifact_id))
        except asyncio.CancelledError:
            self._record_verification("cancelled")
            raise
        except Exception as exc:
            self._record_verification("failed", str(exc))
            raise
        finally:
            await self._stop_generator()
            # Even a failing generator leaves useful diagnostics. Never register
            # a partially created CF32 file as though it were complete.
            if not self._stimulus_artifact_id:
                files = [str(p) for p in (source, iq_file if complete else None, manifest if complete else None)
                         if p is not None and p.is_file()]
                if files:
                    self.create_artifact(files=files, name="AIS Offline IQ Diagnostic Stimulus",
                                         artifact_type="ais_iq_simulation",
                                         metadata={"schema": "fissure.ais.iq_loopback.v2",
                                                   "node_uid": self.node_uid, "operation_id": self.opid,
                                                   "simulated": True, "rf_transmitted": False,
                                                   "iq_generation_complete": complete,
                                                   "expected_mmsis": sorted(self._expected_mmsis)})
