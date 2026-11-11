#!/usr/bin/env python3
"""Decode AIS NMEA from UDP or a node-local file into FISSURE data types.

IMPORTANT: AIS lat/lon is a self-reported *vessel* location, not independent RF
geolocation. The UDP source may be an external AIS-catcher or GNU Radio bridge;
this Operation does not falsely claim to acquire RF signals on its own.
"""
from __future__ import annotations

import asyncio
import csv
from datetime import datetime, timezone
import inspect
import json
import logging
import math
from pathlib import Path
import socket
import sys
import time
import uuid
from typing import Any, Callable, Dict, Optional

# Imported by a long-running Sensor Node; see the loopback version check.
FISSURE_AIS_API_REVISION = "ais-plugin-2026-11-10-v1.0"

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
FISSURE_ROOT = PLUGIN_ROOT.parent.parent
for item in (str(FISSURE_ROOT), str(PLUGIN_ROOT / "scripts"), str(PLUGIN_ROOT)):
    if item not in sys.path:
        sys.path.insert(0, item)

from fissure.utils.plugins.operations import Operation
from ais_codec import AISMessageAssembler, boolean, require_pyais, to_nmea_lines
from ais_status_runtime_v091 import emit_status


def utc(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat().replace("+00:00", "Z")


async def safe_callback(callback: Callable, *args, **kwargs):
    if callback is None:
        return None
    result = callback(*args, **kwargs)
    if inspect.isawaitable(result):
        return await asyncio.wait_for(result, timeout=3.0)
    return result


class OperationMain(Operation):
    """Finite-duration NMEA receiver, including offline replay and managed Artifacts."""

    def __init__(
        self,
        input_mode: str = "udp",
        source_file: str = "",
        listen_host: str = "127.0.0.1",
        listen_port: int = 10110,
        duration_s: float = 60.0,
        simulated_input: bool = False,
        emit_targets: bool = True,
        save_artifact: bool = True,
        target_refresh_s: float = 30.0,
        max_messages: int = 0,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        detection_callback: Optional[Callable] = None,
        target_callback: Optional[Callable] = None,
        status_callback: Optional[Callable] = None,
        artifact_manager=None,
    ) -> None:
        """Initialize AIS NMEA reception.

        Parameters
        ----------
        input_mode : str, optional
            udp for already-decoded NMEA over UDP, or file for node-local replay.
        source_file : str, optional
            Local Sensor Node path for file mode.
        listen_host : str, optional
            UDP IPv4 bind address.
        listen_port : int, optional
            UDP port accepting NMEA sentences.
        duration_s : float, optional
            Maximum monitoring duration in seconds for UDP mode.
        simulated_input : bool, optional
            Explicitly mark the input stream as simulated; do not infer it from
            the MMSI or vessel name. Prevents test Targets mixing with live ones.
        emit_targets : bool, optional
            Publish per-MMSI FISSURE Target patches.
        save_artifact : bool, optional
            Store NMEA, observations, and summaries in a managed Artifact.
        target_refresh_s : float, optional
            Maximum repeat-publish interval for stationary MMSIs.
        max_messages : int, optional
            Stop after N decoded messages; 0 means unlimited.
        """
        super().__init__(node_uid=node_uid, logger=logger,
                         detection_callback=detection_callback,
                         target_callback=target_callback,
                         status_callback=status_callback,
                         artifact_manager=artifact_manager)
        self.input_mode = str(input_mode).strip().lower()
        if self.input_mode not in {"udp", "file"}:
            raise ValueError("AIS input_mode must be udp or file")
        self.source_file = str(source_file or "").strip()
        self.listen_host = str(listen_host or "127.0.0.1").strip()
        self.listen_port = int(float(listen_port))
        if not 1024 <= self.listen_port <= 65535:
            raise ValueError("AIS UDP port must be between 1024 and 65535")
        self.duration_s = float(duration_s)
        if not (0 <= self.duration_s <= 86400):
            raise ValueError('AIS UDP duration must be 0 (until stopped) or greater than 0 up to 86400 seconds')
        self._simulated = boolean(simulated_input, False)
        self._simulated_source = "user_declared_simulated_nmea" if self._simulated else ""
        self.emit_targets = boolean(emit_targets, True)
        self.save_artifact = boolean(save_artifact, True)
        self.target_refresh_s = max(0.0, float(target_refresh_s))
        self.max_messages = max(0, int(float(max_messages)))
        self._assembler = AISMessageAssembler()
        self._vessels: Dict[str, Dict[str, Any]] = {}
        self._message_count = 0
        self._line_count = 0
        self._invalid_lines = 0
        self._sock = None
        self._files = {}
        self._record_file = None
        self._raw_file = None
        self._received_artifact_id = ""

    @staticmethod
    def get_resources() -> Dict[str, Any]:
        # This Operation does not access an SDR directly.
        return {}

    async def _status(self, message: str) -> None:
        await emit_status(self, message)

    def _open_logs(self):
        if not self.save_artifact:
            return
        if not self.artifact_manager:
            raise RuntimeError("AIS Artifact requested but no ArtifactManager exists")
        _, folder = self.artifact_manager.create_operation_dir(self.opid)
        root = Path(folder)
        self._files = {
            "raw": root / "ais_received.nmea",
            "jsonl": root / "ais_observations.jsonl",
            "csv": root / "ais_vessels.csv",
            "summary": root / "ais_summary.txt",
            "metadata": root / "ais_metadata.json",
        }
        self._raw_file = self._files["raw"].open("w", encoding="ascii")
        self._record_file = self._files["jsonl"].open("w", encoding="utf-8")

    def _save_line(self, line: str) -> None:
        if self._raw_file is not None:
            self._raw_file.write(line + "\n")

    async def _emit_target(self, mmsi: str, state: Dict[str, Any], message: Dict[str, Any]) -> None:
        if not self.emit_targets:
            return
        epoch = float(message["observed_epoch"])
        current_pos = (state.get("latitude"), state.get("longitude"))
        old_pos = state.get("last_published_position")
        identity = (state.get("ship_name") or "", state.get("callsign") or "")
        has_new_identity = identity != state.get("last_published_identity", ("", ""))
        if (state.get("published") and not has_new_identity and current_pos == old_pos
                and epoch - state.get("last_publish_at", 0.0) < self.target_refresh_s):
            return
        simulated = bool(getattr(self, "_simulated", False))
        namespace = "fissure/ais/simulated/vessel/" if simulated else "fissure/ais/vessel/"
        target_id = "tgt-" + str(uuid.uuid5(uuid.NAMESPACE_URL, namespace + mmsi))
        msg_type = message["message_type"]
        category = "AIS Aid to Navigation" if msg_type == 21 else "AIS Vessel"
        label = state.get("ship_name") or (category + " " + mmsi)
        if simulated:
            label = "SIM " + label
        patch = {
            "target_id": target_id, "node_uid": self.node_uid, "state": "active",
            "classification": {"display_label": label, "selected_source": "ais_nmea"},
            "identity": {"protocol": "AIS", "device_id": mmsi, "subtype": category,
                         "callsign": state.get("callsign", "")},
            "observation_summary": {"count": state["count"],
                                    "first_seen": state["first_seen"],
                                    "last_seen": utc(epoch)},
            "description": ("SIMULATED AIS TEST TRAFFIC - not a real vessel observation"
                            if simulated else "AIS-reported identity/coordinates; not verified RF geolocation"),
        }
        # A received NMEA sentence does not itself prove the RF channel or receiver.
        if state.get("latitude") is not None and state.get("longitude") is not None:
            patch["location"] = {"lat": state["latitude"], "lon": state["longitude"],
                                 "timestamp": utc(epoch), "source": "ais_reported"}
        history = {"event": "ais_target_updated" if state.get("published") else "ais_target_discovered",
                   "plugin": "AIS", "action": "ais_receive", "operation_id": self.opid,
                   "node_uid": self.node_uid, "timestamp": utc(epoch), "mmsi": mmsi,
                   "message_type": msg_type, "input_mode": self.input_mode}
        if simulated:
            patch["simulated"] = True
            history["simulated"] = True
        try:
            await safe_callback(self.target_callback, target_id=target_id,
                                patch=patch, history_entry=history)
        except asyncio.CancelledError:
            raise
        except Exception:
            self.logger.exception("AIS Target callback failed for MMSI %s", mmsi)
            return
        state["published"] = True
        state["last_publish_at"] = epoch
        state["last_published_position"] = current_pos
        state["last_published_identity"] = identity

    async def _receive(self, line: str) -> None:
        self._line_count += 1
        expected = [part.strip() for part in str(line).splitlines()
                    if part.strip().startswith(("!AIVDM,", "!AIVDO,"))]
        valid_sentences = to_nmea_lines(line)
        self._invalid_lines += max(0, len(expected) - len(valid_sentences))
        for sentence in valid_sentences:
            self._save_line(sentence)
            row = self._assembler.push(sentence)
            if not row:
                continue
            if getattr(self, "_simulated", False):
                row["simulated"] = True
                row["simulation_source"] = getattr(self, "_simulated_source", "offline_demo")
            self._message_count += 1
            mmsi = row["mmsi"]
            epoch = row["observed_epoch"]
            state = self._vessels.setdefault(mmsi, {
                "count": 0, "first_seen": utc(epoch), "last_seen": utc(epoch),
                "latitude": None, "longitude": None, "ship_name": "",
                "callsign": "", "published": False,
            })
            state["count"] += 1
            state["last_seen"] = utc(epoch)
            state["last_message_type"] = row["message_type"]
            for key in ("latitude", "longitude", "speed_kt", "course_deg", "heading_deg", "ship_name", "callsign", "destination", "ship_type"):
                if key in row:
                    state[key] = row[key]
            if self._record_file is not None:
                self._record_file.write(json.dumps(row, sort_keys=True, default=str) + "\n")
            detection = {
                "kind": "detection", "event_type": "detection", "detector": "ais_receive",
                "detection_kind": "ais_message", "event_uid": "ais-%s-%s" % (self.opid, self._message_count),
                "timestamp": epoch, "observation_time": utc(epoch),
                "node_uid": self.node_uid, "source_id": self.node_uid or "sensor_node",
                "opid": self.opid, "operation_id": self.opid,
                "protocol": "AIS", "mmsi": mmsi, "message_type": row["message_type"],
                "description": "AIS message %s from MMSI %s" % (row["message_type"], mmsi),
                "label": state.get("ship_name") or mmsi,
                "location_valid": row["reported_position_valid"],
                "location_semantics": "ais_self_reported_not_rf_geolocation",
                "input_mode": self.input_mode,
                "raw_nmea": row["raw_nmea"],
            }
            # When the channel is known, report the actual nominal AIS A/B
            # frequency relative to this SDR's selected RF center. gr-ais
            # versions and NMEA sources may use A/B, 1/2 or an empty field.
            # Channel-less RF observations must still have a frequency for
            # FISSURE's Detector workbench, but must *not* be falsely assigned
            # to one of the two AIS channels.
            raw_channel = str(row.get("nmea_channel") or "").strip().upper()
            channel = {"A": "A", "1": "A", "B": "B", "2": "B"}.get(raw_channel)
            if channel:
                detection["channel"] = channel
                detection["ais_channel"] = channel
            elif raw_channel:
                detection["nmea_channel_code"] = raw_channel

            # A live SDR knows its actual tuned RF center. An IQ recording
            # knows its capture center only when an IQ file is supplied. UDP
            # and plain NMEA file inputs have no independent RF provenance.
            center = getattr(self, "rf_frequency", None)
            if center is None and self.input_mode == "iq_file" and getattr(self, "iq_file", ""):
                center = getattr(self, "center_frequency", None)
            try:
                center = float(center) if center is not None else None
                if center is not None and math.isfinite(center) and center > 0:
                    frequency_hz = center + (-25000.0 if channel == "A" else
                                              25000.0 if channel == "B" else 0.0)
                    detection["frequency_hz"] = frequency_hz
                    detection["frequency_mhz"] = frequency_hz / 1e6
                    detection["frequency_semantics"] = (
                        "nominal_ais_channel_center" if channel else
                        "receiver_center_channel_unknown")
            except (ValueError, TypeError, OverflowError):
                pass
            if getattr(self, "_simulated", False):
                detection["simulated"] = True
                detection["simulation_source"] = getattr(self, "_simulated_source", "offline_demo")
                detection["description"] = ("SIMULATED LAB RF REPLAY: " if getattr(
                    self, "_simulated_source", "") == "lab_band_rf_replay"
                    else "SIMULATED INPUT: ") + detection["description"]
                detection["label"] = "SIM " + detection["label"]
            # Static AIS messages have no position. Deliberately do not copy the
            # vessel's previous position into a *new* static-message detection.
            if row["reported_position_valid"]:
                detection["latitude"] = row["latitude"]
                detection["longitude"] = row["longitude"]
                detection["altitude"] = 0.0
                detection["altitude_valid"] = False
            for key in ("speed_kt", "course_deg", "heading_deg", "ship_name", "callsign", "ship_type", "static_part"):
                if key in row:
                    detection[key] = row[key]
            try:
                await safe_callback(self.detection_callback, detection)
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.exception("AIS Detection callback failed")
            await self._emit_target(mmsi, state, row)

    def _finish_logs(self, reason: str, error: str = "") -> str:
        for f in (self._raw_file, self._record_file):
            if f:
                f.flush()
                f.close()
        self._raw_file = self._record_file = None
        if not self._files:
            return ""
        csv_columns = ["mmsi", "ship_name", "callsign", "ship_type", "first_seen", "last_seen", "count",
                       "latitude", "longitude", "speed_kt", "course_deg", "heading_deg", "destination", "last_message_type"]
        with self._files["csv"].open("w", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=csv_columns)
            writer.writeheader()
            for mmsi, state in sorted(self._vessels.items()):
                writer.writerow({k: (mmsi if k == "mmsi" else state.get(k, "")) for k in csv_columns})
        summary_lines = ["FISSURE AIS Reception Summary", "", "Input: %s" % self.input_mode,
                         "Completion: %s" % reason, "Decoded messages: %d" % self._message_count,
                         "Unique MMSIs: %d" % len(self._vessels),
                         "Invalid NMEA: %d" % (self._invalid_lines + self._assembler.invalid_count),
                         "Unfinished multipart groups: %d" % len(self._assembler.pending),
                         "", "Locations are AIS-reported, NOT independent RF geolocation.", ""]
        for mmsi, state in sorted(self._vessels.items()):
            summary_lines.append("%s  %s  %d messages  last lat/lon: %s, %s" % (
                mmsi, state.get("ship_name") or "Unnamed", state["count"],
                state.get("latitude"), state.get("longitude")))
        if error:
            summary_lines.append("Error: " + error)
        self._files["summary"].write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
        metadata = {"schema": "fissure.ais.receive.v1", "node_uid": self.node_uid,
                    "operation_id": self.opid, "input_mode": self.input_mode,
                    "nmea_messages": self._message_count, "unique_mmsi": len(self._vessels),
                    "completion_reason": reason, "error": error,
                    "position_semantics": "ais_self_reported_not_rf_geolocation",
                    "simulated": bool(getattr(self, "_simulated", False))}
        metadata.update(getattr(self, "_input_metadata", {}))
        self._files["metadata"].write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        file_paths = [str(self._files[k]) for k in ("summary", "csv", "jsonl", "raw", "metadata")]
        stimulus_id = metadata.get("stimulus_artifact_id")
        relations = ([{"entity_type": "artifact", "entity_id": str(stimulus_id),
                      "role": "decoded_from"}] if stimulus_id else None)
        file_metadata = {
            "ais_received.nmea": {"content_type": "text/plain"},
            "ais_observations.jsonl": {"content_type": "application/x-ndjson"},
        }
        identifier = self.create_artifact(files=file_paths, name="AIS NMEA Reception (%s)" % self.input_mode,
                                          artifact_type="ais_nmea_observations",
                                          metadata=metadata, relations=relations,
                                          file_metadata=file_metadata)
        if not identifier:
            raise RuntimeError("AIS reception Artifact registration failed")
        self._received_artifact_id = str(identifier)
        return identifier

    async def _from_file(self):
        path = Path(self.source_file).expanduser()
        if not path.is_file():
            raise FileNotFoundError("AIS NMEA file not found on Sensor Node: %s" % path)
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if self._stop or (self.max_messages and self._message_count >= self.max_messages):
                    break
                if line.lstrip().startswith("#"):
                    continue
                await self._receive(line)
                await asyncio.sleep(0)

    async def _from_udp(self):
        # One datagram may contain one or several newline-delimited NMEA sentences.
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock = sock
        sock.setblocking(False)
        sock.bind((self.listen_host, self.listen_port))
        loop = asyncio.get_running_loop()
        deadline = (loop.time() + self.duration_s) if self.duration_s else None
        last_status = loop.time()
        while not self._stop and (deadline is None or loop.time() < deadline):
            if self.max_messages and self._message_count >= self.max_messages:
                break
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, 8192), timeout=(min(0.25, max(0.01, deadline-loop.time())) if deadline is not None else 0.25))
            except asyncio.TimeoutError:
                data = b""
            if data:
                await self._receive(data.decode("ascii", errors="replace"))
            if loop.time() - last_status > 5:
                last_status = loop.time()
                await self._status("AIS RX: %d messages / %d MMSIs" % (self._message_count, len(self._vessels)))

    async def run(self) -> None:
        require_pyais()
        if self.input_mode == "file" and not self.source_file:
            raise ValueError("source_file is required when AIS input_mode=file")
        if self.save_artifact:
            self._open_logs()
        await self._status("AIS RX: %s started" % self.input_mode)
        reason = "complete"
        error = ""
        try:
            if self.input_mode == "file":
                await self._from_file()
            else:
                await self._from_udp()
            if self._stop:
                reason = "stopped"
        except asyncio.CancelledError:
            reason = "cancelled"
            raise
        except Exception as exc:
            reason = "error"
            error = "%s: %s" % (type(exc).__name__, exc)
            await self._status("AIS RX error: " + error[:160])
            raise
        finally:
            if self._sock is not None:
                self._sock.close()
                self._sock = None
            try:
                if self.save_artifact:
                    self._finish_logs(reason, error)
            finally:
                await self._status("AIS RX %s: %d messages / %d MMSIs" % (
                    reason, self._message_count, len(self._vessels)))
