#!/usr/bin/env python3
"""Generate synthetic AIS vessel NMEA and optionally send over UDP.

No SDR commands, RF emissions, or physical transmitter are used. This is a
controlled network/recording demo that can feed ais_receive and OpenCPN.
"""
from __future__ import annotations

import asyncio
import csv
import json
import logging
import ipaddress
from pathlib import Path
import socket
import sys
from typing import Callable, Dict, Optional

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
FISSURE_ROOT = PLUGIN_ROOT.parent.parent
for item in (str(FISSURE_ROOT), str(PLUGIN_ROOT / "scripts"), str(PLUGIN_ROOT)):
    if item not in sys.path:
        sys.path.insert(0, item)

from fissure.utils.plugins.operations import Operation
from ais_codec import boolean, encode_position, encode_static, require_pyais
from ais_status_runtime_v091 import emit_status


class OperationMain(Operation):
    def __init__(
        self,
        vessel_count: int = 3,
        position_updates: int = 5,
        interval_s: float = 1.0,
        send_udp: bool = True,
        udp_host: str = "127.0.0.1",
        udp_port: int = 10110,
        base_latitude: float = 40.722,
        base_longitude: float = -74.020,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        status_callback: Optional[Callable] = None,
        artifact_manager=None,
    ) -> None:
        """Initialize a synthetic network-only AIS sender.

        Parameters
        ----------
        vessel_count : int, optional
            Number of distinct synthetic MMSIs.
        position_updates : int, optional
            Position reports generated for each MMSI.
        interval_s : float, optional
            Delay between rounds of position reports.
        send_udp : bool, optional
            Send NMEA over the loopback interface; never over RF.
        udp_host : str, optional
            IPv4 loopback destination for safe test traffic.
        udp_port : int, optional
            Local test receiver UDP destination port.
        base_latitude : float, optional
            Starting synthetic latitude in decimal degrees (default: NYC Hudson River).
        base_longitude : float, optional
            Starting synthetic longitude in decimal degrees (default: NYC Hudson River).
        """
        super().__init__(node_uid=node_uid, logger=logger, status_callback=status_callback,
                         artifact_manager=artifact_manager)
        self.vessel_count = int(float(vessel_count))
        self.position_updates = int(float(position_updates))
        self.interval_s = float(interval_s)
        self.send_udp = boolean(send_udp, True)
        self.udp_host = str(udp_host or "127.0.0.1").strip()
        try:
            ip = ipaddress.ip_address(self.udp_host)
            if not ip.is_loopback or ip.version != 4:
                raise ValueError("AIS simulation UDP destination must be loopback (127.0.0.1)")
        except ValueError as exc:
            raise ValueError("AIS simulation requires an IPv4 loopback UDP destination") from exc
        self.udp_port = int(float(udp_port))
        self.base_latitude = float(base_latitude)
        self.base_longitude = float(base_longitude)
        if not 1 <= self.vessel_count <= 20 or not 1 <= self.position_updates <= 1000:
            raise ValueError("AIS demo vessel_count or position_updates out of range")
        if not 0.1 <= self.interval_s <= 30 or not 1024 <= self.udp_port <= 65535:
            raise ValueError("AIS demo interval or UDP port out of range")
        if not (-89 <= self.base_latitude <= 89 and -179 <= self.base_longitude <= 179):
            raise ValueError("AIS demo starting coordinates too close to geographic limits")
        self.sentences = 0
        self._sock = None

    @staticmethod
    def get_resources() -> Dict:
        # No RF hardware is claimed or used by network-only transmission.
        return {}

    async def _status(self, message: str):
        await emit_status(self, message)

    async def run(self) -> None:
        require_pyais()
        if not self.artifact_manager:
            raise RuntimeError("AIS simulator requires FISSURE ArtifactManager")
        _, folder = self.artifact_manager.create_operation_dir(self.opid)
        output = Path(folder)
        nmea_path = output / "ais_simulated.nmea"
        csv_path = output / "ais_simulated_vessels.csv"
        summary_path = output / "ais_simulation_summary.txt"
        meta_path = output / "ais_simulation_metadata.json"
        rows = []
        error = ""
        outcome = "complete"
        if self.send_udp:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        await self._status("AIS simulated NMEA TX started (network/file only, NO RF)")
        try:
            with nmea_path.open("w", encoding="ascii") as out:
                for step in range(self.position_updates):
                    if self._stop:
                        outcome = "stopped"
                        break
                    for vessel in range(self.vessel_count):
                        if self._stop:
                            outcome = "stopped"
                            break
                        # Deliberately synthetic identifiers and routes. They are not
                        # real vessel tracks, and transmission never reaches AIS RF.
                        mmsi = "%09d" % (200000001 + vessel)
                        name = "FISSURE DEMO %02d" % (vessel + 1)
                        lat = self.base_latitude + vessel * 0.008 + step * 0.0007
                        lon = self.base_longitude + vessel * 0.0007 + step * 0.0002
                        speed = 6.0 + vessel * 2
                        course = (35 + vessel * 60) % 360
                        channel = "A" if vessel % 2 == 0 else "B"
                        frames = []
                        if step == 0:
                            frames.extend(encode_static(mmsi, name, channel))
                        frames.extend(encode_position(mmsi, lat, lon, speed, course, channel))
                        for frame in frames:
                            out.write(frame + "\n")
                            out.flush()
                            if self._sock is not None:
                                self._sock.sendto(frame.encode("ascii") + b"\r\n", (self.udp_host, self.udp_port))
                            self.sentences += 1
                        rows.append({"mmsi": mmsi, "ship_name": name, "update": step + 1,
                                     "latitude": lat, "longitude": lon, "speed_kt": speed,
                                     "course_deg": course, "nmea_channel": channel})
                        await asyncio.sleep(0)
                    if step + 1 < self.position_updates and not self._stop:
                        await self._sleep_stop_aware(self.interval_s)
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        except Exception as exc:
            outcome = "error"
            error = "%s: %s" % (type(exc).__name__, exc)
            await self._status("AIS NMEA simulation error: " + error[:160])
            raise
        finally:
            if self._sock is not None:
                self._sock.close()
                self._sock = None
            with csv_path.open("w", newline="", encoding="utf-8") as stream:
                writer = csv.DictWriter(stream, fieldnames=["mmsi", "ship_name", "update", "latitude", "longitude", "speed_kt", "course_deg", "nmea_channel"])
                writer.writeheader()
                writer.writerows(rows)
            metadata = {"schema": "fissure.ais.simulation.v1", "node_uid": self.node_uid,
                        "operation_id": self.opid, "simulated": True, "rf_transmitted": False,
                        "transport": "udp" if self.send_udp else "file_only",
                        "udp_destination": "%s:%d" % (self.udp_host, self.udp_port) if self.send_udp else None,
                        "sentences": self.sentences, "position_reports": len(rows),
                        "completion_reason": outcome, "error": error}
            summary_path.write_text("FISSURE Synthetic AIS Demo\n\n"
                                    "Transport: %s; NO RF TRANSMISSION\n" % metadata["transport"]
                                    + "NMEA sentences: %d\nPosition reports: %d\n" % (self.sentences, len(rows))
                                    + "Vessels configured: %d\nCompletion: %s\n" % (self.vessel_count, outcome)
                                    + ("Error: %s\n" % error if error else ""), encoding="utf-8")
            meta_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            artifact = self.create_artifact(
                files=[str(p) for p in (summary_path, csv_path, nmea_path, meta_path)],
                name="Synthetic AIS NMEA Transmission", artifact_type="ais_nmea_simulation",
                metadata=metadata)
            if not artifact:
                raise RuntimeError("AIS simulation Artifact registration failed")
            await self._status("AIS NMEA simulation %s: %d sentences (Artifact %s)" % (
                outcome, self.sentences, artifact))
