#! /usr/bin/env python3
"""Timed ADS-B aircraft-state logging operation for FISSURE."""

from __future__ import annotations

import asyncio
import csv
import json
import logging
import os
import sys
import time

from typing import Any, Callable, Dict, Optional


OPERATIONS_DIR = os.path.abspath(os.path.dirname(__file__))
PLUGIN_ROOT = os.path.abspath(os.path.join(OPERATIONS_DIR, ".."))
SCRIPTS_DIR = os.path.join(PLUGIN_ROOT, "scripts")
FISSURE_ROOT = os.path.abspath(os.path.join(PLUGIN_ROOT, "..", ".."))
for path in (FISSURE_ROOT, PLUGIN_ROOT, SCRIPTS_DIR):
    if path not in sys.path:
        sys.path.insert(0, path)

from fissure.utils.plugins.operations import Operation
from adsb_common import Dump1090Receiver, to_float, to_int, utc_iso


CALLBACK_TIMEOUT_S = 3.0


class OperationMain(Operation):
    """Receive ADS-B for a configured duration and return a FISSURE Artifact."""

    def __init__(
        self,
        device_index: int = 0,
        status_interval_s: float = 5.0,
        duration_s: float = 60.0,
        poll_interval_s: float = 1.0,
        artifact_name: str = "ADS-B Aircraft Log",
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        status_callback: Optional[Callable] = None,
        artifact_manager=None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            status_callback=status_callback,
            artifact_manager=artifact_manager,
        )

        self.device_index = max(0, to_int(device_index, 0))
        self.status_interval_s = max(1.0, float(to_float(status_interval_s, 5.0)))
        self.duration_s = max(1.0, float(to_float(duration_s, 60.0)))
        self.poll_interval_s = max(0.25, float(to_float(poll_interval_s, 1.0)))
        self.artifact_name = str(artifact_name or "ADS-B Aircraft Log").strip()
        self.resource_args = {"device_index": self.device_index}

        self._receiver = None

    @staticmethod
    def get_resources(device_index=None) -> Dict[str, Any]:
        serial = "" if device_index is None else str(max(0, to_int(device_index, 0)))
        return {
            "rtl_sdr": {
                "type": "RTL2832U",
                "model": "",
                "serial": serial,
                "description": "RTL-SDR used for 1090 MHz ADS-B reception",
                "required": True,
            }
        }

    async def _call(self, callback: Callable, *args, **kwargs):
        result = callback(*args, **kwargs)
        if asyncio.iscoroutine(result) or isinstance(result, asyncio.Future):
            return await asyncio.wait_for(result, timeout=CALLBACK_TIMEOUT_S)
        return result

    async def _set_status(self, text: str) -> None:
        if not self.status_callback:
            return
        try:
            await self._call(self.status_callback, text)
        except Exception:
            self.logger.exception("ADS-B aircraft logger status_callback failed")

    @staticmethod
    def _summary_row(icao: str, summary: Dict[str, Any]) -> Dict[str, Any]:
        latest = summary.get("latest") or {}
        return {
            "icao": icao,
            "callsign": latest.get("callsign", ""),
            "first_seen_utc": summary.get("first_seen_utc", ""),
            "last_seen_utc": summary.get("last_seen_utc", ""),
            "observation_count": summary.get("observation_count", 0),
            "last_latitude": latest.get("latitude"),
            "last_longitude": latest.get("longitude"),
            "last_altitude_ft": latest.get("altitude_ft"),
            "last_altitude_m": latest.get("altitude_m"),
            "last_altitude_source": latest.get("altitude_source"),
            "last_speed_kt": latest.get("speed_kt"),
            "last_heading_deg": latest.get("heading_deg"),
            "last_signal_rssi_dbfs": latest.get("signal_rssi_dbfs"),
            "last_signal_level": latest.get("signal_level"),
            "last_message_count": latest.get("messages"),
        }

    async def run(self) -> None:
        if not self.artifact_manager:
            raise RuntimeError("ADS-B Aircraft Logger requires artifact_manager")

        operation_id = str(self.opid)
        _, folder = self.artifact_manager.create_operation_dir(operation_id)

        observations_path = os.path.join(folder, "adsb_observations.ndjson")
        summary_path = os.path.join(folder, "adsb_aircraft_summary.csv")
        metadata_path = os.path.join(folder, "adsb_log_metadata.json")

        started_epoch = None
        started_monotonic = None
        final_reason = "duration_complete"
        failure = None
        summaries = {}
        observation_count = 0
        last_message_count = 0
        last_status_time = 0.0

        receiver = Dump1090Receiver(
            logger=self.logger,
            device_index=self.device_index,
            environment=self.get_subprocess_environment(),
        )
        self._receiver = receiver

        await self._set_status("ADS-B Log: starting")

        try:
            await receiver.start()
            if not await receiver.wait_until_ready(timeout_s=8.0):
                raise RuntimeError(
                    "dump1090 JSON interface did not become ready within 8 seconds"
                )

            # Count requested recording time from decoder readiness, not
            # from process launch and its potentially lengthy startup.
            started_epoch = time.time()
            started_monotonic = time.monotonic()

            with open(observations_path, "w", encoding="utf-8") as observations_file:
                while not self._stop:
                    elapsed_total = time.monotonic() - started_monotonic
                    if elapsed_total >= self.duration_s:
                        break

                    poll_started = time.monotonic()
                    aircraft_rows, message_count = await receiver.poll()
                    last_message_count = max(last_message_count, message_count)

                    for aircraft in aircraft_rows:
                        icao = str(aircraft.get("icao") or "").strip().upper()
                        if not icao:
                            continue

                        row = dict(aircraft)
                        row["receiver_node"] = self.node_uid
                        row["operation_id"] = operation_id
                        row["frequency_mhz"] = 1090.0
                        observations_file.write(
                            json.dumps(row, sort_keys=True, default=str) + "\n"
                        )
                        observation_count += 1

                        current = summaries.setdefault(
                            icao,
                            {
                                "first_seen_utc": aircraft.get("observation_time"),
                                "last_seen_utc": aircraft.get("observation_time"),
                                "observation_count": 0,
                                "latest": {},
                            },
                        )
                        current["last_seen_utc"] = aircraft.get("observation_time")
                        current["observation_count"] += 1
                        current["latest"] = {
                            key: value
                            for key, value in aircraft.items()
                            if key != "raw"
                        }

                    observations_file.flush()

                    now = time.monotonic()
                    if now - last_status_time >= self.status_interval_s:
                        remaining = max(
                            0.0,
                            self.duration_s - (now - started_monotonic),
                        )
                        await self._set_status(
                            "ADS-B Log: %d ac | %d msg | %.0fs"
                            % (len(summaries), last_message_count, remaining)
                        )
                        last_status_time = now

                    elapsed = time.monotonic() - poll_started
                    sleep_s = max(0.05, self.poll_interval_s - elapsed)
                    await self._sleep_stop_aware(sleep_s, check_interval_s=0.1)

            if self._stop:
                final_reason = "stopped"

        except Exception as exc:
            # Preserve any observations already written even if dump1090 dies
            # or another run-time failure interrupts the requested duration.
            failure = exc
            final_reason = "error"
            self.logger.exception("ADS-B Aircraft Logger interrupted")
        finally:
            try:
                await receiver.stop()
            except Exception as exc:
                self.logger.exception("ADS-B Aircraft Logger decoder cleanup failed")
                if failure is None:
                    failure = exc
                    final_reason = "error"
            self._receiver = None

        if not os.path.isfile(observations_path):
            # Startup failure: there is no partial recording to preserve.
            if failure is not None:
                raise failure
            raise RuntimeError("ADS-B Aircraft Logger has no observation file")

        finished_epoch = time.time()

        summary_fields = [
            "icao",
            "callsign",
            "first_seen_utc",
            "last_seen_utc",
            "observation_count",
            "last_latitude",
            "last_longitude",
            "last_altitude_ft",
            "last_altitude_m",
            "last_altitude_source",
            "last_speed_kt",
            "last_heading_deg",
            "last_signal_rssi_dbfs",
            "last_signal_level",
            "last_message_count",
        ]
        with open(summary_path, "w", encoding="utf-8", newline="") as summary_file:
            writer = csv.DictWriter(summary_file, fieldnames=summary_fields)
            writer.writeheader()
            for icao in sorted(summaries):
                writer.writerow(self._summary_row(icao, summaries[icao]))

        metadata = {
            "schema": "fissure.adsb.log.v1",
            "node_uid": self.node_uid,
            "operation_id": operation_id,
            "frequency_mhz": 1090.0,
            "decoder": "dump1090",
            "device_index": self.device_index,
            "started_utc": utc_iso(started_epoch),
            "finished_utc": utc_iso(finished_epoch),
            "duration_requested_s": self.duration_s,
            "duration_actual_s": max(0.0, finished_epoch - started_epoch),
            "completion_reason": final_reason,
            "unique_aircraft": len(summaries),
            "observation_count": observation_count,
            "message_count": last_message_count,
            "dump1090_endpoint": receiver.endpoint,
        }
        if failure is not None:
            metadata["error"] = "%s: %s" % (type(failure).__name__, failure)
        with open(metadata_path, "w", encoding="utf-8") as metadata_file:
            json.dump(metadata, metadata_file, indent=2, sort_keys=True)

        files = [observations_path, summary_path, metadata_path]
        file_metadata = {
            observations_path: {
                "role": "adsb_observations",
                "content_type": "application/x-ndjson",
                "schema": "fissure.adsb.observation.v1",
                "observation_count": observation_count,
            },
            summary_path: {
                "role": "adsb_aircraft_summary",
                "content_type": "text/csv",
                "unique_aircraft": len(summaries),
            },
            metadata_path: {
                "role": "adsb_log_metadata",
                "content_type": "application/json",
                "schema": "fissure.adsb.log.v1",
            },
        }

        artifact_id = self.create_artifact(
            files=files,
            name=self.artifact_name,
            artifact_type="adsb_aircraft_log",
            metadata=metadata,
            file_metadata=file_metadata,
        )
        if not artifact_id:
            raise RuntimeError("ADS-B Aircraft Logger failed to register its Artifact")

        self.logger.info(
            "ADS-B Aircraft Logger artifact registered: artifact_id=%s opid=%s observations=%d aircraft=%d",
            artifact_id,
            operation_id,
            observation_count,
            len(summaries),
        )
        if failure is not None:
            await self._set_status("ADS-B Log: partial saved (error)")
            raise failure

        await self._set_status("ADS-B Log: saved %d ac" % len(summaries))


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
