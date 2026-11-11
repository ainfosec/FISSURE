#!/usr/bin/env python3
"""Decode a node-local complex64 IQ recording with GNU Radio 3.8/3.10 and gr-ais.

No RF transmit hardware or live receiver is started. The subprocess uses
The installed gr-ais `ais_rx` hierarchy (3.8 / 3.10), without a copied graph.
Decoded NMEA is processed through the same AIS Detection/Target/Artifact path
used by AIS Receive, preserving the protocol integration in one place.
"""
from __future__ import annotations

import asyncio
from collections import deque
import logging
from pathlib import Path
import sys
from typing import Callable, Optional

# Imported by a long-running Sensor Node; see the loopback version check.
FISSURE_AIS_API_REVISION = "ais-plugin-2026-11-10-v1.0"

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
FISSURE_ROOT = PLUGIN_ROOT.parent.parent
if str(PLUGIN_ROOT / "operations") not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT / "operations"))

# Keep offline IQ decoding aligned with the Detection builder on disk after
# an in-place plugin upgrade (live SDR parents refresh the full class graph).
_previous_receive = sys.modules.get("ais_receive")
if (_previous_receive is not None and
        getattr(_previous_receive, "FISSURE_AIS_API_REVISION", None) != FISSURE_AIS_API_REVISION):
    _origin = getattr(_previous_receive, "__file__", None)
    if (_origin and Path(_origin).resolve() ==
            (PLUGIN_ROOT / "operations" / "ais_receive.py").resolve()):
        del sys.modules["ais_receive"]
from ais_receive import OperationMain as NMEAReceiver
from ais_codec import require_pyais


class OperationMain(NMEAReceiver):
    def __init__(
        self,
        iq_file: str = "",
        sample_rate: float = 200000.0,
        center_frequency: float = 162000000.0,
        channel: str = "both",
        decoder_timeout_s: float = 300.0,
        emit_targets: bool = True,
        save_artifact: bool = True,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        detection_callback: Optional[Callable] = None,
        target_callback: Optional[Callable] = None,
        status_callback: Optional[Callable] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(input_mode="file", source_file=iq_file,
                         emit_targets=emit_targets, save_artifact=save_artifact,
                         node_uid=node_uid, logger=logger,
                         detection_callback=detection_callback,
                         target_callback=target_callback,
                         status_callback=status_callback,
                         artifact_manager=artifact_manager)
        self.input_mode = "iq_file"
        self.iq_file = str(iq_file).strip()
        self.sample_rate = float(sample_rate)
        self.center_frequency = float(center_frequency)
        self.channel = str(channel or "both").strip()
        self.decoder_timeout_s = float(decoder_timeout_s)
        if self.channel not in {"both", "A", "B"}:
            raise ValueError("AIS IQ channel must be both, A or B")
        import math
        if not (math.isfinite(self.sample_rate) and 100000 <= self.sample_rate <= 5000000):
            raise ValueError("AIS IQ sample rate must be between 100000 and 5000000 Hz")
        if not (math.isfinite(self.center_frequency) and 100000000 <= self.center_frequency <= 200000000):
            raise ValueError("AIS IQ center frequency must be between 100 and 200 MHz")
        if not (math.isfinite(self.decoder_timeout_s) and 1 <= self.decoder_timeout_s <= 86400):
            raise ValueError("AIS IQ decoder timeout must be between 1 and 86400 seconds")
        self._proc = None
        self._decoder_errors = deque(maxlen=40)
        self._input_metadata = {
            "iq_file": self.iq_file,
            "iq_format": "complex64_le_interleaved_iq",
            "sample_rate_hz": self.sample_rate,
            "center_frequency_hz": self.center_frequency,
            "ais_channels": self.channel,
            "backend": "gr-ais ais_rx receiver hierarchy (GNU Radio 3.8/3.10)",
            "rf_transmitted": False,
        }

    @staticmethod
    def get_resources():
        # File source: no SDR claimed. The operation is safe on a remote node
        # with GNU Radio dependencies and an accessible local IQ path.
        return {}

    def _decoder_command(self, file_path):
        helper = PLUGIN_ROOT / "scripts" / "ais_iq_decoder.py"
        return [sys.executable, "-u", str(helper), "--input", str(file_path),
                "--sample-rate", str(self.sample_rate),
                "--center-freq", str(self.center_frequency),
                "--channel", self.channel]

    async def _drain_stderr(self, reader):
        while True:
            line = await reader.readline()
            if not line:
                break
            msg = line.decode("utf-8", errors="replace").strip()
            if msg:
                self._decoder_errors.append(msg[:500])
                self.logger.debug("AIS IQ decoder: %s", msg)

    async def _terminate_child(self):
        proc = self._proc
        if proc is None or proc.returncode is not None:
            return
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

    async def run(self) -> None:
        require_pyais()
        if not self.iq_file:
            raise ValueError("AIS IQ file path is required")
        path = Path(self.iq_file).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError("AIS IQ file not found on executing Sensor Node: %s" % path)
        if path.stat().st_size < 8 or path.stat().st_size % 8:
            raise ValueError("AIS IQ file must contain raw interleaved complex float32 samples")

        if self.save_artifact:
            self._open_logs()
        await self._status("AIS IQ file decode started: %s (gr-ais; no RF TX)" % path.name)
        stderr_task = None
        reason = "complete"
        error = ""
        try:
            self._proc = await asyncio.create_subprocess_exec(
                *self._decoder_command(path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(PLUGIN_ROOT),
            )
            stderr_task = asyncio.create_task(self._drain_stderr(self._proc.stderr))
            loop = asyncio.get_running_loop()
            deadline = loop.time() + self.decoder_timeout_s
            while not self._stop:
                if loop.time() >= deadline:
                    reason = "timeout"
                    break
                try:
                    line = await asyncio.wait_for(self._proc.stdout.readline(), timeout=0.25)
                except asyncio.TimeoutError:
                    continue
                if not line:
                    break
                await self._receive(line.decode("ascii", errors="replace"))
            if self._stop:
                reason = "stopped"
            if reason == "complete":
                try:
                    # EOF on a pipe does not always imply that the subprocess
                    # return code is already available. Allow graceful exit.
                    await asyncio.wait_for(self._proc.wait(), timeout=3.0)
                except asyncio.TimeoutError:
                    reason = "timeout"
            if reason != "complete":
                await self._terminate_child()
            if stderr_task is not None:
                await stderr_task
            if reason == "complete" and self._proc.returncode != 0:
                raise RuntimeError("GNU Radio AIS IQ decoder exited %s: %s" % (
                    self._proc.returncode,
                    "; ".join(list(self._decoder_errors)[-5:]) or "no diagnostic output"))
            if reason == "timeout":
                await self._status("AIS IQ decoder timed out; inspect capture sample rate and file length")
            elif reason == "complete" and not self._message_count:
                await self._status("AIS IQ decode complete: no AIS frames found (check center frequency / sample rate / core)")
        except asyncio.CancelledError:
            reason = "cancelled"
            raise
        except Exception as exc:
            reason = "error"
            error = "%s: %s" % (type(exc).__name__, exc)
            await self._status("AIS IQ decode error: " + error[:220])
            raise
        finally:
            try:
                await self._terminate_child()
                if stderr_task is not None and not stderr_task.done():
                    await stderr_task
            finally:
                if self.save_artifact:
                    self._finish_logs(reason, error)
                await self._status("AIS IQ %s: %d messages / %d MMSIs" % (
                    reason, self._message_count, len(self._vessels)))
