#! /usr/bin/env python3
"""Live ADS-B aircraft tracking operation for FISSURE."""

from __future__ import annotations

import asyncio
import logging
import os
import re
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
from adsb_common import Dump1090Receiver, to_float, to_int


CALLBACK_TIMEOUT_S = 3.0


def _safe_uid_piece(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.~-]+", "-", str(value or "").strip())
    return text.strip("-") or "unknown"


class OperationMain(Operation):
    """Continuously decode ADS-B traffic and publish native FISSURE detections."""

    def __init__(
        self,
        device_index: int = 0,
        status_interval_s: float = 5.0,
        poll_interval_s: float = 1.0,
        emit_interval_s: float = 1.0,
        node_uid: str = "",
        logger: logging.Logger = logging.getLogger(__name__),
        detection_callback: Optional[Callable] = None,
        status_callback: Optional[Callable] = None,
    ) -> None:
        super().__init__(
            node_uid=node_uid,
            logger=logger,
            detection_callback=detection_callback,
            status_callback=status_callback,
        )

        self.device_index = max(0, to_int(device_index, 0))
        self.status_interval_s = max(1.0, float(to_float(status_interval_s, 5.0)))
        self.poll_interval_s = max(0.25, float(to_float(poll_interval_s, 1.0)))
        self.emit_interval_s = max(0.25, float(to_float(emit_interval_s, 1.0)))
        self.resource_args = {"device_index": self.device_index}

        self._receiver = None
        self._last_emit_by_icao = {}
        self._last_message_count = 0
        self._last_status_time = 0.0

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
            self.logger.exception("ADS-B tracker status_callback failed")

    def _build_detection(self, aircraft: Dict[str, Any]) -> Dict[str, Any]:
        icao = str(aircraft.get("icao") or "").strip().upper()
        callsign = str(aircraft.get("callsign") or "").strip()
        label = callsign or icao or "ADS-B Aircraft"
        has_position = bool(aircraft.get("location_valid"))

        detection = {
            "kind": "detection",
            "event_type": "detection",
            "detector": "ads_b_aircraft_tracker",
            "description": "ADS-B aircraft %s" % label,
            "label": label,
            "event_uid": "adsb-aircraft-%s-%s" % (
                _safe_uid_piece(self.node_uid or "node"),
                _safe_uid_piece(icao),
            ),
            "timestamp": float(aircraft.get("observed_epoch") or time.time()),
            "observation_time": aircraft.get("observation_time"),
            "opid": self.opid,
            "frequency_mhz": 1090.0,
            "frequency_hz": 1090000000,
            "protocol": "ADS-B",
            "icao": icao,
            "altitude_ft": aircraft.get("altitude_ft"),
            "altitude_m": aircraft.get("altitude_m"),
            "altitude_source": aircraft.get("altitude_source"),
            "speed_kt": aircraft.get("speed_kt"),
            "heading_deg": aircraft.get("heading_deg"),
            "vertical_rate_fpm": aircraft.get("vertical_rate_fpm"),
            "signal_rssi_dbfs": aircraft.get("signal_rssi_dbfs"),
            "signal_level": aircraft.get("signal_level"),
            "squawk": aircraft.get("squawk"),
            "category": aircraft.get("category"),
            "emergency": aircraft.get("emergency"),
            "on_ground": aircraft.get("on_ground"),
            "message_count": aircraft.get("messages"),
            "seen_s": aircraft.get("seen_s"),
            "receiver_node": self.node_uid,
            "source_id": self.node_uid,
            "location_valid": has_position,
        }

        # The transmitted aircraft callsign is optional metadata. Keep it
        # separate from the generic display label and the TAK contact callsign.
        if callsign:
            detection["callsign"] = callsign

        # dump1090 may expose uncalibrated decoder signal measurements. The
        # generic Detection metric supports their actual units without
        # presenting RSSI as calibrated power or falsely claiming peak power.
        rssi_dbfs = aircraft.get("signal_rssi_dbfs")
        signal_level = aircraft.get("signal_level")
        if rssi_dbfs is not None:
            detection["metric"] = rssi_dbfs
            detection["metric_units"] = "dBFS"
        elif signal_level is not None:
            detection["metric"] = signal_level
            detection["metric_units"] = "relative"

        # If ADS-B has no aircraft position, explicitly prevent the Sensor Node
        # detection path from substituting the receiver's GPS position.
        if has_position:
            detection["latitude"] = aircraft.get("latitude")
            detection["longitude"] = aircraft.get("longitude")

            # FISSURE's shared position path expects altitude in meters. Avoid
            # falling back to Sensor Node altitude when the aircraft altitude is
            # unavailable by supplying a neutral value and preserving validity.
            altitude_m = aircraft.get("altitude_m")
            detection["altitude"] = 0.0 if altitude_m is None else altitude_m
            detection["altitude_valid"] = altitude_m is not None

        return detection

    async def _emit_aircraft(self, aircraft: Dict[str, Any]) -> None:
        if not self.detection_callback:
            return

        try:
            await self._call(
                self.detection_callback,
                self._build_detection(aircraft),
            )
        except Exception:
            self.logger.exception(
                "ADS-B tracker detection_callback failed for %s",
                aircraft.get("icao"),
            )

    async def run(self) -> None:
        await self._set_status("Starting: ADS-B Aircraft Tracker")

        receiver = Dump1090Receiver(
            logger=self.logger,
            device_index=self.device_index,
            environment=self.get_subprocess_environment(),
        )
        self._receiver = receiver

        try:
            await receiver.start()
            if not await receiver.wait_until_ready(timeout_s=8.0):
                raise RuntimeError(
                    "dump1090 JSON interface did not become ready within 8 seconds"
                )

            await self._set_status("ADS-B Tracker: waiting for aircraft")

            while not self._stop:
                poll_started = time.monotonic()
                aircraft_rows, message_count = await receiver.poll()
                now = time.monotonic()

                current_icaos = set()
                for aircraft in aircraft_rows:
                    icao = str(aircraft.get("icao") or "").strip().upper()
                    if not icao:
                        continue

                    current_icaos.add(icao)
                    last_emit = float(self._last_emit_by_icao.get(icao, 0.0))
                    if now - last_emit >= self.emit_interval_s:
                        await self._emit_aircraft(aircraft)
                        self._last_emit_by_icao[icao] = now

                self._last_message_count = max(self._last_message_count, message_count)

                if now - self._last_status_time >= self.status_interval_s:
                    await self._set_status(
                        "ADS-B: %d ac | %d msg"
                        % (len(current_icaos), self._last_message_count)
                    )
                    self._last_status_time = now

                elapsed = time.monotonic() - poll_started
                sleep_s = max(0.05, self.poll_interval_s - elapsed)
                await self._sleep_stop_aware(sleep_s, check_interval_s=0.1)

        finally:
            await receiver.stop()
            self._receiver = None


if __name__ == "__main__":
    from fissure.utils.plugins.test_operation import run_test
    run_test(OperationMain, {}, {})
