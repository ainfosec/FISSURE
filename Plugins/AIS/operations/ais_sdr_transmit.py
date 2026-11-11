#!/usr/bin/env python3
"""Generate synthetic AIS and send its modulated IQ through a standalone B210 TX.

Receive is deliberately not started: use the verified combined B210 Action for
one-device hardware loopback. Standalone actions are for independent SDRs.
"""
from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
import sys
from typing import Callable, Optional

ROOT = Path(__file__).resolve().parents[1]
for loc in (ROOT / "operations", ROOT / "scripts"):
    if str(loc) not in sys.path:
        sys.path.insert(0, str(loc))

from ais_iq_loopback import OperationMain as AISIQLoopback, sha256_file
from ais_codec import require_pyais, boolean
from ais_sdr_operation_runtime import AISB210OperationRuntime
from ais_sdr_hardware import validate_tx
from ais_b210_frontend_v097 import make_device_args, channel_details


from ais_status_runtime_v091 import AISStatusMixin
from ais_tx_repeat_v093 import validate_repeat_settings, send_repeated_batches


class OperationMain(AISStatusMixin, AISIQLoopback, AISB210OperationRuntime):
    def __init__(self, vessel_count=3, position_updates=3, include_static_data=True,
                 base_latitude=40.722, base_longitude=-74.020, sample_rate=240000,
                 gap_ms=350, rf_frequency=915000000, device_args="type=b200",
                 tx_gain=60, save_tx_artifact=False, repeat_count=0, repeat_pause_s=2.0,
                 serial_number="", rf_channel=0,
                 node_uid="", logger=logging.getLogger(__name__),
                 detection_callback: Optional[Callable] = None,
                 target_callback: Optional[Callable] = None,
                 status_callback: Optional[Callable] = None,
                 artifact_manager=None):
        super().__init__(
            vessel_count=vessel_count, position_updates=position_updates,
            include_static_data=include_static_data,
            base_latitude=base_latitude, base_longitude=base_longitude,
            sample_rate=sample_rate, gap_ms=gap_ms, emit_targets=False,
            node_uid=node_uid, logger=logger,
            detection_callback=detection_callback, target_callback=target_callback,
            status_callback=status_callback, artifact_manager=artifact_manager)
        self.rf_frequency = float(rf_frequency)
        self.device_args = make_device_args(device_args, serial_number)
        self.serial_number = str(serial_number or "").strip()
        self.rf_channel = str(rf_channel)
        channel_details(self.rf_channel)
        self.tx_gain = float(tx_gain)
        self.save_tx_artifact = boolean(save_tx_artifact, False)
        self.repeat_count, self.repeat_pause_s = validate_repeat_settings(repeat_count, repeat_pause_s)
        self.tx_batches_completed = 0
        validate_tx(self.sample_rate, self.rf_frequency, self.tx_gain, self.device_args)

    @staticmethod
    def get_resources():
        return {}  # Shared advisory lock; FISSURE-wide SDR reservations still unverified.

    async def run(self):
        require_pyais()
        if not self.artifact_manager:
            raise RuntimeError("AIS standalone TX requires FISSURE ArtifactManager")
        self.lock_b210()
        _, folder = self.artifact_manager.create_operation_dir(self.opid)
        folder = Path(folder)
        source = folder / "ais_sdr_tx.nmea"
        iq = folder / "ais_sdr_tx.cf32"
        generator_manifest = folder / "ais_sdr_tx_iq_manifest.json"
        hw_manifest = folder / "ais_sdr_tx_hardware.json"
        result_file = folder / "ais_sdr_tx_result.json"
        state = "failed"
        error = ""
        sent = False
        stimulus_id = ""
        try:
            count = self._create_nmea(source)
            await self._status("AIS standalone TX: generating %d simulated messages" % count)
            await self.call_sdr_process([
                sys.executable, "-u", str(ROOT / "scripts" / "ais_iq_generator.py"),
                "--input", str(source), "--output", str(iq),
                "--manifest", str(generator_manifest), "--sample-rate", str(int(self.sample_rate)),
                "--gap-ms", str(self.gap_ms), "--max-frames", str(count),
            ], 180, "AIS IQ generation", ROOT)
            generated = json.loads(generator_manifest.read_text())
            if generated.get("frame_count") != count or generated.get("skipped_nmea_sentences"):
                raise RuntimeError("Standalone TX generated an incomplete AIS waveform")
            if self.save_tx_artifact:
                stimulus_id = str(self.create_artifact(
                    files=[str(source), str(iq), str(generator_manifest)],
                    name="AIS Standalone B210 TX IQ Stimulus", artifact_type="ais_sdr_tx_stimulus",
                    metadata={"schema": "fissure.ais.sdr_tx_stimulus.v1",
                              "operation_id": self.opid, "simulated": True,
                              "rf_transmitted": False, "messages": count,
                              "iq_sha256": sha256_file(iq), "nmea_sha256": sha256_file(source)}) or "")
                if not stimulus_id:
                    raise RuntimeError("AIS TX stimulus Artifact registration failed")
            # NOTE: 60 dB default TX gain is NOT safe through an unattenuated
            # coax path. Only repeat at an authorized, attenuated lab test setup.
            await self._status("AIS B210 TX: %d AIS messages/batch, repeat=%s, pause=%gs (lab only)" % (
                count, "until Stop" if not self.repeat_count else str(self.repeat_count),
                self.repeat_pause_s))

            async def transmit_once(batch_index):
                # Hardware graph remains finite; launch a fresh batch as needed.
                await self.call_sdr_process([
                    sys.executable, "-u", str(ROOT / "scripts" / "ais_sdr_hardware.py"),
                    "--mode", "tx", "--input", str(iq), "--manifest", str(hw_manifest),
                    "--sample-rate", str(int(self.sample_rate)),
                    "--rf-frequency", str(self.rf_frequency),
                    "--device-args", self.device_args, "--tx-gain", str(self.tx_gain),
                    "--rf-channel", self.rf_channel,
                ], 180, "AIS B210 RF transmission batch %d" % batch_index, ROOT)
                info = json.loads(hw_manifest.read_text())
                if info.get("rf_transmitted") is not True:
                    raise RuntimeError("B210 TX batch %d did not finish" % batch_index)

            batches = await send_repeated_batches(self, transmit_once, count, "AIS B210 TX")
            sent = bool(batches)
            state = "stopped" if self._stop else "complete"
            await self._status("AIS B210 TX %s: %d batches / %d messages" % (
                state, batches, batches * count))
        except asyncio.CancelledError:
            state = "stopped"
            raise
        except Exception as exc:
            error = "%s: %s" % (type(exc).__name__, exc)
            await self._status("AIS standalone TX failed: " + error[:220])
            raise
        finally:
            await self.stop_sdr_process()
            await self._stop_generator()
            self.unlock_b210()
            record = {"schema": "fissure.ais.sdr_tx_result.v1", "state": state,
                      "operation_id": self.opid, "error": error,
                      "simulated_vessels": True, "rf_transmitted_completed": sent,
                      "rf_frequency_hz": self.rf_frequency,
                      "tx_gain_db": self.tx_gain, "repeat_count": self.repeat_count,
                      "repeat_pause_s": self.repeat_pause_s,
                      "completed_batches": self.tx_batches_completed,
                      "total_messages_sent": self.tx_batches_completed * (count if "count" in locals() else 0),
                      "stimulus_artifact_id": stimulus_id or None}
            result_file.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
            files = [str(result_file)] + ([str(hw_manifest)] if hw_manifest.exists() else [])
            if self.save_tx_artifact:
                self.create_artifact(files=files, name="AIS Standalone TX Result",
                                     artifact_type="ais_sdr_tx_result", metadata=record)
