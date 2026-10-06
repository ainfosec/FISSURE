#!/usr/bin/env python3
"""Receive-only 144.390 MHz APRS Operation for FISSURE.

Live: rtl_fm -> 22,050 Hz signed 16-bit PCM -> multimon-ng AFSK1200.
Replay: multimon-ng text output/TNC2 file, or multimon-ng WAV/raw audio input.
This Operation never transmits, contacts APRS-IS, or invents RF geolocation.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime, timezone
import inspect
import json
import logging
import os
from pathlib import Path
import shutil
import sys
import time
import uuid
from typing import Any, Callable, Dict, Optional


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
if str(PLUGIN_ROOT) not in sys.path:
    sys.path.insert(0, str(PLUGIN_ROOT))
from scripts.aprs_codec import parse_line  # noqa: E402

try:
    from fissure.utils.plugins.operations import Operation
except ImportError:
    repo_root = PLUGIN_ROOT.parent.parent
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from fissure.utils.plugins.operations import Operation


FREQUENCY_HZ = 144_390_000
CALLBACK_TIMEOUT_S = 2.0


def _boolean(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    value = str(value).strip().lower()
    if value in {"yes", "true", "1", "on"}:
        return True
    if value in {"no", "false", "0", "off"}:
        return False
    return default


def _utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")


class OperationMain(Operation):
    """Long-running APRS monitor; FISSURE owns setup, stop, and teardown."""

    def __init__(
        self,
        input_mode: str = "rtl",
        source_file: str = "",
        rtl_device: str = "0",
        rtl_gain_db: str = "",
        rtl_ppm: float = 0,
        log_artifact: bool = False,
        artifact_update_packets: int = 25,
        emit_targets: bool = True,
        target_refresh_s: float = 120,
        replay_delay_s: float = 0,
        max_packets: int = 0,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        detection_callback: Optional[Callable] = None,
        target_callback: Optional[Callable] = None,
        status_callback: Optional[Callable] = None,
        artifact_manager=None,
    ) -> None:
        """Configure live RTL reception or offline APRS replay.

        Parameters
        ----------
        input_mode : str, optional
            rtl, tnc2_file, or audio_file; replay does not claim an SDR.
        source_file : str, optional
            Local node path to a decoded text or APRS audio replay file.
        rtl_device : str, optional
            RTL-SDR device index or serial, default 0.
        rtl_gain_db : str, optional
            Optional tuner gain in dB; blank enables default automatic gain.
        rtl_ppm : float, optional
            RTL-SDR frequency correction in parts per million.
        log_artifact : bool, optional
            Write received APRS packets to a FISSURE JSONL Artifact.
        artifact_update_packets : int, optional
            Refresh the Artifact manifest every N received packets.
        emit_targets : bool, optional
            Publish one Target per APRS station and separate APRS objects.
        target_refresh_s : float, optional
            Maximum age before an unchanged Target is published again.
        replay_delay_s : float, optional
            Artificial inter-packet delay for decoded text replay.
        max_packets : int, optional
            Stop after N packets; zero means unlimited.
        node_uid : str, optional
            Framework-supplied Sensor Node identifier.
        logger : logging.Logger, optional
            Framework logger.
        detection_callback : Callable, optional
            Framework structured Detection publisher.
        target_callback : Callable, optional
            Framework Target-patch publisher.
        status_callback : Callable, optional
            Framework Sensor Node status publisher.
        artifact_manager : ArtifactManager, optional
            Framework Artifact manager for optional packet logging.
        """
        # Operation's decorated base __init__ calls prepare_resources() before
        # it returns. Set mode-dependent claims *first*: a simulated replay must
        # work on a node that has no RTL2832U allocated or even installed.
        requested_mode = str(input_mode or "rtl").strip().lower()
        if requested_mode not in {"rtl", "tnc2_file", "audio_file"}:
            raise ValueError("input_mode must be rtl, tnc2_file, or audio_file")
        requested_device = str(rtl_device if rtl_device is not None else "0").strip() or "0"
        self.resource_args = {"input_mode": requested_mode, "rtl_device": requested_device}
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            detection_callback=detection_callback,
            target_callback=target_callback,
            status_callback=status_callback,
            artifact_manager=artifact_manager,
        )
        self.input_mode = requested_mode
        self.source_file = str(source_file or "").strip()
        self.rtl_device = requested_device
        self.rtl_gain_db = str(rtl_gain_db if rtl_gain_db is not None else "").strip()
        self.rtl_ppm = int(float(rtl_ppm))
        self.log_artifact = _boolean(log_artifact)
        self.artifact_update_packets = max(1, int(float(artifact_update_packets)))
        self.emit_targets = _boolean(emit_targets, True)
        self.target_refresh_s = max(0.0, float(target_refresh_s))
        self.replay_delay_s = max(0.0, float(replay_delay_s))
        self.max_packets = max(0, int(float(max_packets)))
        self.source_id = str(node_uid or "sensor_node").strip()

        self.packets = 0
        self.replay_lines_checked = 0
        self.replay_lines_skipped = 0
        self.decoder_lines_ignored = 0
        self.stations: Dict[str, Dict[str, Any]] = {}
        self.mapped_objects: Dict[str, Dict[str, Any]] = {}
        self._procs: list[asyncio.subprocess.Process] = []
        self._tasks: list[asyncio.Task] = []
        self._stderr_tail: deque[str] = deque(maxlen=8)
        self._artifact_file = None
        self._artifact_path: Optional[Path] = None
        self._artifact_id = ""
        self._artifact_synced_at = 0
        self._last_status_at = 0.0

    @staticmethod
    def get_resources(input_mode: str = "rtl", rtl_device: str = "0") -> Dict[str, Any]:
        """Claim only the receiver actually used; offline simulation needs no SDR."""
        if input_mode == "rtl":
            return {"rtl_receiver": {
                "type": "sdr", "model": "RTL2832U", "serial": str(rtl_device),
            }}
        return {}

    async def _call(self, callback, *args, **kwargs) -> Any:
        result = callback(*args, **kwargs)
        if inspect.isawaitable(result):
            return await asyncio.wait_for(result, timeout=CALLBACK_TIMEOUT_S)
        return result

    async def _status(self, message: str) -> None:
        try:
            await self._call(self.status_callback, message)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("APRS status callback failed")

    def _artifact_metadata(self) -> Dict[str, Any]:
        return {
            "schema": "fissure.aprs.packet_log.v1",
            "protocol": "APRS/AX.25/AFSK1200", "frequency_hz": FREQUENCY_HZ,
            "node_uid": self.node_uid, "operation_id": self.opid,
            "input_mode": self.input_mode, "source_file": self.source_file or None,
            "rtl_device": self.rtl_device if self.input_mode == "rtl" else None,
            "packet_count": self.packets, "station_count": len(self.stations),
            "object_count": len(self.mapped_objects),
            "position_semantics": "self_reported_not_rf_geolocation",
        }

    def _prepare_log(self) -> None:
        if not self.log_artifact:
            return
        if not self.artifact_manager:
            raise RuntimeError("Artifact logging requested, but no ArtifactManager is available")
        _, folder = self.artifact_manager.create_operation_dir(self.opid)
        self._artifact_path = Path(folder) / "aprs_packets.jsonl"
        self._artifact_file = self._artifact_path.open("w", encoding="utf-8")

    def _write_log(self, record: Dict[str, Any]) -> None:
        if not self._artifact_file:
            return
        self._artifact_file.write(json.dumps(record, ensure_ascii=True, sort_keys=True) + "\n")
        self._artifact_file.flush()
        if not self._artifact_id:
            self._artifact_id = self.create_artifact(
                files=[str(self._artifact_path)],
                name=f"APRS 144.390 MHz packets ({self.node_uid or 'sensor_node'})",
                artifact_type="protocol_packets",
                metadata=self._artifact_metadata(),
                file_metadata={str(self._artifact_path): {
                    "role": "aprs_packet_log", "content_type": "application/x-ndjson",
                    "schema": "fissure.aprs.packet_log.v1",
                }},
            )
            if not self._artifact_id:
                raise RuntimeError("FISSURE Artifact registration failed")
            self._artifact_synced_at = self.packets
        elif self.packets - self._artifact_synced_at >= self.artifact_update_packets:
            self._refresh_artifact()

    def _refresh_artifact(self) -> None:
        if self._artifact_id and self._artifact_synced_at != self.packets:
            ok = self.update_artifact(
                self._artifact_id, files=[str(self._artifact_path)],
                metadata=self._artifact_metadata(),
            )
            if ok:
                self._artifact_synced_at = self.packets
            else:
                self.logger.error("APRS Artifact refresh failed (id=%s)", self._artifact_id)

    async def _target(self, identity: str, packet: Dict[str, Any], timestamp: float,
                      position: Optional[Dict[str, Any]], is_object: bool = False) -> None:
        if not self.emit_targets:
            return
        state_map = self.mapped_objects if is_object else self.stations
        state = state_map[identity]
        old_position = state.get("last_published_position")
        current_position = (position["latitude"], position["longitude"]) if position else None
        changed = current_position is not None and current_position != old_position
        # First observation, newly reported/moved position, or periodic heartbeat.
        if (state.get("published") and not changed
                and timestamp - state.get("last_publish_at", 0) < self.target_refresh_s):
            return
        target_namespace = (
            f"fissure/aprs/{packet['packet_type']}/{identity}"
            if is_object else f"fissure/aprs/station/{identity}"
        )
        target_id = "tgt-" + str(uuid.uuid5(uuid.NAMESPACE_URL, target_namespace))
        iso = _utc(timestamp)
        label = ("APRS Item" if packet["packet_type"] == "item" else "APRS Object") if is_object else "APRS Station"
        patch = {
            "target_id": target_id, "node_uid": self.node_uid,
            "frequency_mhz": FREQUENCY_HZ / 1e6, "state": "active",
            "classification": {"display_label": label, "selected_source": "aprs_packet"},
            "identity": {
                "protocol": "APRS", "callsign": packet["source"],
                "device_id": identity, "subtype": packet["packet_type"],
            },
            "rf": {
                "center_frequency_mhz": FREQUENCY_HZ / 1e6,
                "modulation": "FM/AFSK1200", "last_observation_time": iso,
            },
            "observation_summary": {
                "count": state["count"], "first_seen": state["first_seen"],
                "last_seen": iso,
            },
            "description": f"{label}: {identity}; APRS coordinates are self-reported",
        }
        if position:
            # Never replace APRS coordinates with the receiver's GPS position.
            patch["location"] = {
                "lat": position["latitude"], "lon": position["longitude"],
                "timestamp": iso, "source": "aprs_reported",
            }
            if "altitude_m" in position:
                patch["location"]["hae_m"] = position["altitude_m"]
        history = {
            "event": "aprs_target_updated" if state.get("published") else "aprs_target_discovered",
            "plugin": "APRS", "action": "aprs_monitor" if self.input_mode == "rtl" else "aprs_replay",
            "operation_id": self.opid, "node_uid": self.node_uid, "timestamp": iso,
            "callsign": packet["source"], "packet_type": packet["packet_type"],
            "frequency_mhz": FREQUENCY_HZ / 1e6,
        }
        try:
            await self._call(self.target_callback, target_id=target_id,
                             patch=patch, history_entry=history)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("APRS target callback failed for %s", identity)
            return
        state["published"] = True
        state["last_publish_at"] = timestamp
        if current_position is not None:
            state["last_published_position"] = current_position

    async def _receive_line(self, line: str) -> bool:
        packet = parse_line(line)
        if not packet:
            return False
        timestamp = time.time()
        source = packet["source"]
        new_station = source not in self.stations
        if new_station:
            self.stations[source] = {"count": 0, "first_seen": _utc(timestamp)}
        self.stations[source]["count"] += 1
        self.packets += 1
        position = packet["position"]
        reported_object = packet["position_entity"] if packet["packet_type"] in {"object", "item"} else ""
        detection = {
            "kind": "detection", "event_type": "detection",
            "detection_kind": "aprs_packet", "detector": "aprs_monitor",
            "event_uid": f"aprs-{self.opid}-{self.packets}",
            "node_uid": self.node_uid, "source_id": self.source_id,
            "opid": self.opid, "operation_id": self.opid,
            "timestamp": timestamp, "frequency_hz": FREQUENCY_HZ,
            "modulation": "FM/AFSK1200", "protocol": "APRS",
            "callsign": source, "destination": packet["destination"],
            "digipeater_path": packet["path"],
            "packet_type": packet["packet_type"],
            "information": packet["information"], "raw_packet": packet["raw_packet"],
            "packet_number": self.packets, "first_seen": new_station,
            "location_valid": bool(position),
            "location_semantics": "aprs_object_reported" if reported_object else "aprs_station_reported",
        }
        if reported_object:
            detection["position_entity"] = reported_object
        if position:
            detection["latitude"] = position["latitude"]
            detection["longitude"] = position["longitude"]
            detection["position_format"] = position["position_format"]
            detection["aprs_symbol_table"] = position["symbol_table"]
            detection["aprs_symbol_code"] = position["symbol_code"]
            if "altitude_m" in position:
                detection["altitude"] = position["altitude_m"]

        # Detection per decoded packet; failures do not prevent logging or Targets.
        try:
            await self._call(self.detection_callback, detection)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("APRS detection callback failed")

        if self.emit_targets:
            await self._target(source, packet, timestamp,
                               None if reported_object else position)
            if reported_object and position:
                key = f"{source}:{packet['packet_type']}:{reported_object}"
                if key not in self.mapped_objects:
                    self.mapped_objects[key] = {"count": 0, "first_seen": _utc(timestamp)}
                self.mapped_objects[key]["count"] += 1
                await self._target(key, packet, timestamp, position, is_object=True)
        self._write_log({**detection, "artifact_schema": "fissure.aprs.packet_log.v1"})
        if timestamp - self._last_status_at > 30:
            self._last_status_at = timestamp
            await self._status(
                f"Running: APRS 144.390 MHz — {self.packets} packets / {len(self.stations)} stations"
            )
        return self.max_packets > 0 and self.packets >= self.max_packets

    async def _read_text_file(self) -> None:
        path = Path(self.source_file).expanduser()
        if not path.is_file():
            raise FileNotFoundError(f"APRS replay file not found on Sensor Node: {path}")
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if self._stop:
                    break
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                self.replay_lines_checked += 1
                before = self.packets
                limit_reached = await self._receive_line(line)
                if self.packets == before:
                    self.replay_lines_skipped += 1
                if limit_reached:
                    break
                if self.replay_delay_s > 0:
                    await self._sleep_stop_aware(self.replay_delay_s)
                else:
                    await asyncio.sleep(0)

    async def _stderr_reader(self, proc, label: str) -> None:
        if proc.stderr is None:
            return
        while True:
            chunk = await proc.stderr.readline()
            if not chunk:
                break
            message = chunk.decode("utf-8", errors="replace").strip()
            if message:
                self._stderr_tail.append(f"{label}: {message[:400]}")
                self.logger.debug("APRS %s stderr: %s", label, message[:400])

    async def _pump_audio(self, rtl_proc, decoder_proc) -> None:
        """Bridge asyncio subprocess pipes without shell or unbounded buffering."""
        try:
            while not self._stop:
                chunk = await rtl_proc.stdout.read(16384)
                if not chunk:
                    break
                decoder_proc.stdin.write(chunk)
                await decoder_proc.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            if decoder_proc.stdin and not decoder_proc.stdin.is_closing():
                decoder_proc.stdin.close()

    async def _read_decoder(self, proc) -> None:
        if proc.stdout is None:
            raise RuntimeError("APRS decoder stdout pipe unavailable")
        while not self._stop:
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=0.25)
            except asyncio.TimeoutError:
                if proc.returncode is not None:
                    break
                continue
            if not line:
                break
            before = self.packets
            if await self._receive_line(line.decode("latin-1", errors="replace")):
                break
            if self.packets == before:
                self.decoder_lines_ignored += 1

    async def _start_decoder(self) -> None:
        decoder = shutil.which("multimon-ng")
        if not decoder:
            raise RuntimeError("multimon-ng missing on Sensor Node (required for RTL/audio input)")
        # -A selects APRS/TNC2 output. Without it, multimon-ng emits its
        # human-oriented AX.25 monitor format, which parse_line cannot consume.
        cmd = [decoder, "-q", "-A", "-a", "AFSK1200"]
        if self.input_mode == "rtl":
            rtl_fm = shutil.which("rtl_fm")
            if not rtl_fm:
                raise RuntimeError("rtl_fm missing on Sensor Node (install rtl-sdr tools)")
            rtl_args = [rtl_fm, "-d", self.rtl_device, "-f", str(FREQUENCY_HZ),
                        "-M", "fm", "-s", "22050", "-l", "0", "-p", str(self.rtl_ppm)]
            if self.rtl_gain_db:
                rtl_args.extend(["-g", str(float(self.rtl_gain_db))])
            rtl_proc = await asyncio.create_subprocess_exec(
                *rtl_args, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self.get_subprocess_environment(),
            )
            self._procs.append(rtl_proc)
            self._tasks.append(asyncio.create_task(self._stderr_reader(rtl_proc, "rtl_fm")))
            decoder_proc = await asyncio.create_subprocess_exec(
                *cmd, "-t", "raw", "-", stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=self.get_subprocess_environment(),
            )
            self._procs.append(decoder_proc)
            self._tasks.append(asyncio.create_task(self._pump_audio(rtl_proc, decoder_proc)))
        else:
            path = Path(self.source_file).expanduser()
            if not path.is_file():
                raise FileNotFoundError(f"APRS audio replay not found on Sensor Node: {path}")
            fmt = {".wav": "wav", ".raw": "raw"}.get(path.suffix.lower())
            if not fmt:
                raise ValueError("audio_file must be .wav or 22050-Hz mono s16le .raw")
            decoder_proc = await asyncio.create_subprocess_exec(
                *cmd, "-t", fmt, str(path),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                env=self.get_subprocess_environment(),
            )
            self._procs.append(decoder_proc)
        self._tasks.append(asyncio.create_task(self._stderr_reader(decoder_proc, "multimon-ng")))
        await self._read_decoder(decoder_proc)
        if not self._stop and not (self.max_packets and self.packets >= self.max_packets):
            # End-of-input in audio mode is normal; RTL mode is meant to run
            # until Stop and an early process exit is a useful error to surface.
            if self.input_mode == "rtl":
                raise RuntimeError("APRS RTL/decoder pipeline exited unexpectedly: "
                                   + "; ".join(self._stderr_tail))
            rc = await decoder_proc.wait()
            if rc != 0:
                raise RuntimeError(f"multimon-ng exited with status {rc}: "
                                   + "; ".join(self._stderr_tail))

    async def _cleanup_processes(self) -> None:
        for proc in reversed(self._procs):
            if proc.returncode is None:
                try:
                    proc.terminate()
                except ProcessLookupError:
                    pass
        for proc in reversed(self._procs):
            if proc.returncode is None:
                try:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
        for task in self._tasks:
            if not task.done():
                task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        self._procs.clear()

    async def run(self) -> None:
        """FISSURE starts this once, and sets _stop for this Operation on Stop."""
        if self.input_mode == "rtl" and self.source_file:
            self.logger.info("APRS RTL mode ignores source_file")
        if self.input_mode != "rtl" and not self.source_file:
            raise ValueError("source_file is required for APRS replay")
        self._prepare_log()
        await self._status(f"Running: APRS 144.390 MHz ({self.input_mode})")
        failed = False
        try:
            if self.input_mode == "tnc2_file":
                await self._read_text_file()
            else:
                await self._start_decoder()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            failed = True
            await self._status(f"Error: APRS monitor: {str(exc)[:160]}")
            raise
        finally:
            await self._cleanup_processes()
            if not failed and not self.packets and not self._stop:
                if self.input_mode == "tnc2_file":
                    detail = (f"Checked {self.replay_lines_checked} non-comment lines; "
                              f"skipped {self.replay_lines_skipped}. Expected SRC>DEST:info "
                              "or APRS:/AFSK1200: prefixed TNC2 text. "
                              "Use scripts/check_replay.py to inspect the source file.")
                else:
                    detail = (f"Ignored {self.decoder_lines_ignored} non-packet decoder lines. "
                              "Check multimon-ng/rtl_fm installation and that input "
                              "contains 1200-baud APRS AFSK audio (not IQ data).")
                self.logger.warning("APRS: zero valid packets. %s", detail)
                await self._status("Warning: APRS replay/monitor: 0 valid packets. " + detail)
            if self._artifact_file:
                self._artifact_file.close()
                self._artifact_file = None
                self._refresh_artifact()
            if not failed:
                await self._status(
                    f"{'Stopped' if self._stop else 'Finished'}: APRS — "
                    f"{self.packets} packets, {len(self.stations)} stations"
                )


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {"input_mode": "tnc2_file", "source_file": str(PLUGIN_ROOT / "resources/example_aprs.tnc2")}, {})
