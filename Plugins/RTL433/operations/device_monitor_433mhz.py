#!/usr/bin/env python3
"""RTL-SDR 433 MHz IoT monitoring through the existing FISSURE Operation API.

The full rtl_433 JSON is retained for every observation; generic FISSURE
Detection fields are additive. All files are managed by ArtifactManager.
"""
import asyncio
from collections import Counter, deque
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
from pathlib import Path
import shutil
import sys
import time
from typing import Any, Callable, Dict, Optional

# Operations are imported by path by FISSURE, not as normal Python packages.
REPO_ROOT = str(Path(__file__).resolve().parents[3])
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from fissure.utils.plugins.operations import Operation


FREQUENCY_MHZ = 433.92
CALLBACK_TIMEOUT_S = 2.0
IDENTITY_KEYS = ("id", "device_id", "sensor_id", "serial", "unit", "house_code", "house_id")
MEASUREMENT_EXCLUSIONS = {
    "time", "model", "brand", "manufacturer", "id", "device_id", "sensor_id", "serial",
    "unit", "house_code", "house_id", "protocol", "channel", "mic",
}


def _float_in_range(value: Any, default: float, minimum: float, maximum: float) -> float:
    try:
        result = float(value)
        if math.isfinite(result) and minimum <= result <= maximum:
            return result
    except (TypeError, ValueError, OverflowError):
        pass
    raise ValueError("Invalid parameter %r; expected a number in [%s, %s]" %
                     (value, minimum, maximum))


def _iso_now(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _identity(message: Dict[str, Any]) -> tuple:
    """Avoid collisions across rtl_433 decoders; never use changing measurement fields."""
    model = str(message.get("model") or "Unknown").strip()
    brand = str(message.get("brand") or message.get("manufacturer") or "").strip()
    protocol = str(message.get("protocol") or "").strip()
    identifier = next(("%s=%s" % (key, message[key]) for key in IDENTITY_KEYS
                       if message.get(key) is not None and str(message[key]).strip()), "")
    channel = str(message.get("channel") if message.get("channel") is not None else "")
    # No stable transmitted ID? Group by model/channel but explicitly mark the
    # identity ambiguous rather than claiming the packets came from one device.
    key = json.dumps([brand, model, protocol, identifier, channel], ensure_ascii=False)
    label = " ".join(piece for piece in (brand, model, identifier, "ch:%s" % channel if channel else "") if piece)
    return key, label, bool(identifier)


class OperationMain(Operation):
    """RTL-SDR-only, stop-aware rtl_433 process and Artifact logger."""

    def __init__(
        self,
        sdr_device: str = "0",
        frequency_mhz: float = FREQUENCY_MHZ,
        sample_rate_hz: float = 250000,
        gain_db: str = "auto",
        ppm: float = 0,
        status_interval_s: float = 5,
        detection_interval_s: float = 10,
        save_artifact: bool = False,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        detection_callback: Optional[Callable] = None,
        status_callback: Optional[Callable] = None,
        alert_callback: Optional[Callable] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(
            node_uid=node_uid, logger=logger, detection_callback=detection_callback,
            status_callback=status_callback, alert_callback=alert_callback,
            artifact_manager=artifact_manager,
        )
        self.sdr_device = str(sdr_device or "0").strip()
        if not self.sdr_device or self.sdr_device.startswith("-"):
            raise ValueError("sdr_device must be an RTL-SDR index or :serial")
        self.frequency_mhz = _float_in_range(frequency_mhz, FREQUENCY_MHZ, 1, 2000)
        self.sample_rate_hz = int(_float_in_range(sample_rate_hz, 250000, 200000, 3200000))
        self.ppm = _float_in_range(ppm, 0, -1000, 1000)
        self.gain_db = str(gain_db if gain_db is not None else "auto").strip().lower()
        if self.gain_db != "auto":
            self.gain_db = str(_float_in_range(self.gain_db, 0, 0, 60))
        self.status_interval_s = _float_in_range(status_interval_s, 5, 1, 300)
        self.detection_interval_s = _float_in_range(detection_interval_s, 10, 0, 3600)
        # Schema-driven Actions supply a boolean; accept explicit string values
        # as well when invoked programmatically.
        if isinstance(save_artifact, str):
            if save_artifact.strip().lower() not in ("true", "false"):
                raise ValueError("save_artifact must be true or false")
            self.save_artifact = save_artifact.strip().lower() == "true"
        elif isinstance(save_artifact, bool):
            self.save_artifact = save_artifact
        else:
            raise ValueError("save_artifact must be a boolean")
        self.resource_args = {"sdr_device": self.sdr_device}
        self._process = None
        self._stderr_task = None
        self._stderr_tail = deque(maxlen=16)
        self._observation_file = None
        self._observation_path = ""
        self._files_dir = ""
        self._started_at = 0.0
        self._last_status = 0.0
        self._last_detection = {}
        self._devices: Dict[str, Dict[str, Any]] = {}
        self._model_counts = Counter()
        self._message_count = 0
        self._detection_count = 0
        self._malformed_count = 0
        self._artifact_id = ""
        self._error = ""
        self._completion_reason = "stopped"
        self._finalized = False

    @staticmethod
    def get_resources(sdr_device: str = "0") -> dict:
        return {"rtl_sdr": {"type": "RTL2832U", "model": "", "serial": sdr_device}}

    async def setup(self) -> bool:
        if not shutil.which("rtl_433"):
            self._error = "rtl_433 not found in Sensor Node PATH"
            self.logger.error(self._error)
            return False
        if self.save_artifact and self.artifact_manager is None:
            self._error = "FISSURE ArtifactManager is unavailable"
            self.logger.error(self._error)
            return False
        return True

    def _command(self) -> list:
        cmd = [
            shutil.which("rtl_433") or "rtl_433", "-f", "%d" % round(self.frequency_mhz * 1_000_000),
            "-s", str(self.sample_rate_hz), "-F", "json", "-M", "time:iso", "-M", "level",
        ]
        cmd += ["-d", self.sdr_device, "-p", str(self.ppm)]
        if self.gain_db != "auto":
            cmd += ["-g", self.gain_db]
        return cmd

    async def _send(self, callback: Callable, *args) -> None:
        if callback is None:
            return False
        try:
            await asyncio.wait_for(callback(*args), timeout=CALLBACK_TIMEOUT_S)
            return True
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("RTL433 framework callback failed")
            return False

    def _status_text(self) -> str:
        uptime = max(0.001, time.time() - self._started_at)
        return ("433 LIVE: %d groups | %d msgs | %.1f/s" %
                (len(self._devices), self._message_count, self._message_count / uptime))

    async def _periodic_status(self, force: bool = False) -> None:
        now = time.time()
        if force or now - self._last_status >= self.status_interval_s:
            self._last_status = now
            await self._send(self.status_callback, self._status_text())

    async def _drain_stderr(self, stream) -> None:
        while True:
            line = await stream.readline()
            if not line:
                return
            text = line.decode("utf-8", errors="replace").strip()
            if text:
                self._stderr_tail.append(text)
                self.logger.debug("rtl_433: %s", text)

    async def _handle_message(self, line: bytes) -> None:
        try:
            decoded = json.loads(line.decode("utf-8", errors="replace"))
        except (ValueError, UnicodeError):
            self._malformed_count += 1
            return
        if not isinstance(decoded, dict) or not decoded.get("model"):
            # rtl_433 can emit informational JSON as well as decoded devices.
            return
        timestamp = time.time()
        key, label, has_id = _identity(decoded)
        summary = self._devices.get(key)
        if summary is None:
            summary = {
                "device_key": key, "label": label, "identity_has_transmitted_id": has_id,
                "model": str(decoded.get("model")), "brand": decoded.get("brand") or decoded.get("manufacturer"),
                "first_seen": _iso_now(timestamp), "last_seen": _iso_now(timestamp),
                "observation_count": 0, "last_measurements": {}, "last_message": {},
            }
            self._devices[key] = summary
        summary["observation_count"] += 1
        summary["last_seen"] = _iso_now(timestamp)
        summary["last_message"] = decoded
        measurements = {k: v for k, v in decoded.items() if k not in MEASUREMENT_EXCLUSIONS}
        summary["last_measurements"] = measurements
        self._message_count += 1
        self._model_counts[str(decoded.get("model"))] += 1
        if self.save_artifact:
            # Save every decoded event when enabled, regardless of Detection throttling.
            record = {
                "received_at": _iso_now(timestamp), "timestamp": timestamp,
                "node_uid": self.node_uid, "opid": self.opid,
                "device_key": key, "device_label": label,
                "identity_has_transmitted_id": has_id,
                "frequency_hz": round(self.frequency_mhz * 1_000_000),
                "measurements": measurements, "rtl_433": decoded,
            }
            self._observation_file.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
            self._observation_file.flush()
        last = self._last_detection.get(key, float("-inf"))
        if timestamp - last >= self.detection_interval_s:
            identity_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
            detection = {
                "kind": "detection", "event_type": "detection", "node_uid": self.node_uid,
                "source_id": self.node_uid, "opid": self.opid,
                "detection_id": "rtl433-%s-%s-%s" % (self.node_uid, self.opid, identity_hash),
                # This stable event UID updates one Tactical row per device, even across runs.
                "event_uid": "rtl433-%s-%s" % (self.node_uid, identity_hash),
                "timestamp": timestamp, "frequency_hz": round(self.frequency_mhz * 1_000_000),
                "detector": "rtl_433", "protocol": "rtl_433", "model": decoded.get("model"),
                "device_id": key, "label": label, "device_identity_stable": has_id,
                "measurements": measurements, "rtl_433": decoded,
                # No explicit position: FISSURE uses the receiving Sensor Node's
                # configured position as this Detection's observation location.
                # This is not a geolocation measurement of the device itself.
            }
            if await self._send(self.detection_callback, detection):
                self._last_detection[key] = timestamp
                self._detection_count += 1

    async def _terminate_process(self) -> None:
        process = self._process
        if process is None:
            return
        if process.returncode is None:
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
        self._process = None
        if self._stderr_task is not None:
            try:
                await asyncio.wait_for(self._stderr_task, timeout=1.0)
            except asyncio.TimeoutError:
                self._stderr_task.cancel()
                await asyncio.gather(self._stderr_task, return_exceptions=True)
            self._stderr_task = None

    def _save_artifact(self) -> None:
        if not self.save_artifact:
            return
        if self._finalized:
            return
        self._finalized = True
        if self._observation_file is not None:
            self._observation_file.close()
            self._observation_file = None
        if not self._files_dir:
            return
        ended_at = time.time()
        devices_path = os.path.join(self._files_dir, "devices.json")
        session_path = os.path.join(self._files_dir, "session.json")
        with open(devices_path, "w", encoding="utf-8") as handle:
            json.dump({"devices": list(self._devices.values())}, handle, indent=2, ensure_ascii=False)
        session = {
            "plugin": "RTL433", "action": "device_monitor_433mhz", "node_uid": self.node_uid,
            "operation_id": self.opid, "source": "rtl_sdr", "sdr_device": self.sdr_device,
            "completion_reason": self._completion_reason,
            "frequency_hz": round(self.frequency_mhz * 1_000_000),
            "sample_rate_hz": self.sample_rate_hz, "started_at": _iso_now(self._started_at),
            "ended_at": _iso_now(ended_at), "duration_seconds": round(ended_at - self._started_at, 3),
            "message_count": self._message_count, "unique_device_groups": len(self._devices),
            "emitted_detections": self._detection_count, "malformed_lines": self._malformed_count,
            "model_counts": dict(self._model_counts),
            "error": self._error, "rtl_433_stderr_tail": list(self._stderr_tail),
            "interpretation": "Device groups without transmitted IDs may combine multiple physical devices.",
        }
        with open(session_path, "w", encoding="utf-8") as handle:
            json.dump(session, handle, indent=2, ensure_ascii=False)
        artifact_id = self.create_artifact(
            files=[self._observation_path, devices_path, session_path],
            name="433 MHz IoT observations %s" % time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self._started_at)),
            artifact_type="rtl_433_device_monitor",
            metadata={"frequency_hz": session["frequency_hz"], "message_count": self._message_count,
                      "device_count": len(self._devices), "model_counts": dict(self._model_counts),
                      "source": session["source"], "completion_reason": self._completion_reason,
                      "started_at": session["started_at"], "ended_at": session["ended_at"]},
            file_metadata={
                "observations.jsonl": {"role": "observations", "content_type": "application/x-ndjson"},
                "devices.json": {"role": "summary", "content_type": "application/json"},
                "session.json": {"role": "provenance", "content_type": "application/json"},
            },
        )
        self._artifact_id = artifact_id
        self.logger.info("RTL433 saved Artifact %s with %d observations", artifact_id, self._message_count)

    async def run(self) -> None:
        self._started_at = time.time()
        try:
            if self.save_artifact:
                _, self._files_dir = self.artifact_manager.create_operation_dir(self.opid)
                self._observation_path = os.path.join(self._files_dir, "observations.jsonl")
                self._observation_file = open(self._observation_path, "w", encoding="utf-8")
            await self._periodic_status(force=True)
            while not self._stop:
                self._process = await asyncio.create_subprocess_exec(
                    *self._command(), stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE, stdin=asyncio.subprocess.DEVNULL,
                )
                self._stderr_task = asyncio.create_task(self._drain_stderr(self._process.stderr))
                while not self._stop:
                    try:
                        line = await asyncio.wait_for(self._process.stdout.readline(), timeout=0.25)
                    except asyncio.TimeoutError:
                        await self._periodic_status()
                        continue
                    if not line:
                        break
                    await self._handle_message(line)
                    await self._periodic_status()
                if self._stop:
                    break
                exit_code = await self._process.wait()
                await self._terminate_process()
                self._error = "rtl_433 exited (%s): %s" % (exit_code, "; ".join(self._stderr_tail)[-500:])
                self._completion_reason = "decoder_error"
                self.logger.error(self._error)
                await self._send(self.status_callback, "433 monitor ERROR: " + self._error[:100])
                break
        except asyncio.CancelledError:
            self._completion_reason = "cancelled"
            raise
        except Exception as exc:
            self._error = "%s: %s" % (type(exc).__name__, exc)
            self._completion_reason = "operation_error"
            self.logger.exception("RTL433 monitor failed")
            await self._send(self.status_callback, "433 monitor ERROR: " + self._error[:100])
        finally:
            # FISSURE's decorated stop() waits for run(); register the partial
            # Artifact in this path on normal stop, decoder error, or exception.
            await self._terminate_process()
            self._save_artifact()
            if self._error:
                final_status = "433 ERROR: %d msgs | %d groups" % (
                    self._message_count, len(self._devices))
                if self._artifact_id:
                    final_status += " | Artifact %s" % self._artifact_id
            elif self._artifact_id:
                final_status = "433 stopped: %d msgs | %d groups | Artifact %s" % (
                    self._message_count, len(self._devices), self._artifact_id)
            elif self.save_artifact:
                final_status = "433 stopped: %d msgs | %d groups | no Artifact" % (
                    self._message_count, len(self._devices))
            else:
                final_status = "433 stopped: %d msgs | %d groups" % (
                    self._message_count, len(self._devices))
            await self._send(self.status_callback, final_status)

    async def stop(self) -> None:
        """The inherited decorator sets _stop and waits for run() to finalize."""
        return


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
