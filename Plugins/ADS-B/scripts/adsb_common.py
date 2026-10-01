#! /usr/bin/env python3
"""Shared dump1090 support for the ADS-B plugin.

The implementation intentionally uses dump1090's existing HTTP/JSON interface.
That keeps RTL-SDR reception and Mode S / ADS-B decoding in the application
FISSURE already installs and uses, while the plugin focuses on translating
live aircraft state into native FISSURE records.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import time
import urllib.error
import urllib.request

from typing import Any, Dict, List, Optional, Tuple


DUMP1090_CANDIDATES = (
    os.path.expanduser("~/Installed_by_FISSURE/dump1090/dump1090"),
    "dump1090",
)

AIRCRAFT_ENDPOINTS = (
    "/data/aircraft.json",
    "/aircraft.json",
    "/data.json",
)

FEET_TO_METERS = 0.3048
MAX_CONSECUTIVE_POLL_FAILURES = 3


class Dump1090UnavailableError(RuntimeError):
    """Raised when the decoder process or its JSON interface becomes unavailable."""


def to_float(value: Any, default: Optional[float] = None) -> Optional[float]:
    try:
        if value in (None, "", "None"):
            return default
        return float(value)
    except Exception:
        return default


def to_int(value: Any, default: int = 0) -> int:
    try:
        if value in (None, "", "None"):
            return int(default)
        return int(float(value))
    except Exception:
        return int(default)


def utc_iso(epoch: Optional[float] = None) -> str:
    when = time.time() if epoch is None else float(epoch)
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(when))


def _first(record: Dict[str, Any], *names: str) -> Any:
    for name in names:
        value = record.get(name)
        if value not in (None, "", "None"):
            return value
    return None


def _normalized_altitudes(
    record: Dict[str, Any],
) -> Tuple[Optional[float], Optional[float], str, bool]:
    """Return display altitude feet, map altitude meters, source, and on-ground."""
    ground_value = record.get("ground")
    on_ground = bool(ground_value)

    baro_value = record.get("alt_baro")
    if isinstance(baro_value, str) and baro_value.strip().lower() == "ground":
        on_ground = True
        baro_value = 0.0

    legacy_value = record.get("altitude")
    if isinstance(legacy_value, str) and legacy_value.strip().lower() == "ground":
        on_ground = True
        legacy_value = 0.0

    baro_ft = to_float(baro_value)
    geom_ft = to_float(record.get("alt_geom"))
    legacy_ft = to_float(legacy_value)

    if on_ground and all(value is None for value in (baro_ft, geom_ft, legacy_ft)):
        baro_ft = 0.0

    altitude_ft = baro_ft
    if altitude_ft is None:
        altitude_ft = geom_ft
    if altitude_ft is None:
        altitude_ft = legacy_ft

    map_altitude_ft = geom_ft
    altitude_source = "geometric"
    if map_altitude_ft is None:
        map_altitude_ft = baro_ft
        altitude_source = "barometric"
    if map_altitude_ft is None:
        map_altitude_ft = legacy_ft
        altitude_source = "reported"
    if map_altitude_ft is None:
        altitude_source = "unknown"

    altitude_m = (
        float(map_altitude_ft) * FEET_TO_METERS
        if map_altitude_ft is not None
        else None
    )

    return altitude_ft, altitude_m, altitude_source, on_ground


def normalize_aircraft(
    record: Dict[str, Any],
    observed_epoch: float,
) -> Optional[Dict[str, Any]]:
    """Normalize old dump1090, dump1090-mutability, and readsb-style fields."""
    if not isinstance(record, dict):
        return None

    raw_hex = str(_first(record, "hex", "icao", "icao24") or "").strip().upper()
    if not raw_hex:
        return None

    callsign = str(_first(record, "flight", "callsign") or "").strip()
    latitude = to_float(_first(record, "lat", "latitude"))
    longitude = to_float(_first(record, "lon", "longitude"))

    valid_position = record.get("validposition")
    has_position = latitude is not None and longitude is not None
    if valid_position is False or str(valid_position).strip() == "0":
        has_position = False

    altitude_ft, altitude_m, altitude_source, on_ground = _normalized_altitudes(
        record
    )
    speed_kt = to_float(_first(record, "gs", "speed", "tas", "ias"))
    heading_deg = to_float(_first(record, "track", "true_heading", "mag_heading"))
    # Older dump1090 provides a validtrack flag even while reporting track=0.
    # Do not turn an unavailable heading into a false northbound heading.
    valid_track = record.get("validtrack")
    if valid_track is False or str(valid_track).strip().lower() in ("0", "false"):
        heading_deg = None
    vertical_rate_fpm = to_float(_first(record, "baro_rate", "geom_rate", "vert_rate"))
    signal_rssi_dbfs = to_float(record.get("rssi"))
    signal_level = to_float(_first(record, "signal", "signalLevel"))
    seen_s = to_float(_first(record, "seen", "seen_pos"))
    message_count = to_int(_first(record, "messages", "msgs"), 0)

    return {
        "icao": raw_hex,
        "callsign": callsign,
        "latitude": latitude if has_position else None,
        "longitude": longitude if has_position else None,
        "location_valid": has_position,
        "altitude_ft": altitude_ft,
        "altitude_m": altitude_m,
        "altitude_source": altitude_source,
        "speed_kt": speed_kt,
        "heading_deg": heading_deg,
        "vertical_rate_fpm": vertical_rate_fpm,
        "squawk": str(record.get("squawk") or "").strip(),
        "category": str(record.get("category") or "").strip(),
        "emergency": str(record.get("emergency") or "").strip(),
        "on_ground": on_ground,
        "signal_rssi_dbfs": signal_rssi_dbfs,
        "signal_level": signal_level,
        "messages": message_count,
        "seen_s": seen_s,
        "observed_epoch": observed_epoch,
        "observation_time": utc_iso(observed_epoch),
        "raw": dict(record),
    }


def summarize_message_count(payload: Any, aircraft: List[Dict[str, Any]]) -> int:
    if isinstance(payload, dict):
        direct = to_int(payload.get("messages"), -1)
        if direct >= 0:
            return direct

    total = 0
    for item in aircraft:
        total += max(0, to_int(item.get("messages"), 0))
    return total


def parse_aircraft_payload(
    payload: Any,
    observed_epoch: Optional[float] = None,
) -> Tuple[List[Dict[str, Any]], int]:
    when = time.time() if observed_epoch is None else float(observed_epoch)

    if isinstance(payload, dict):
        rows = payload.get("aircraft")
        if not isinstance(rows, list):
            rows = payload.get("data")
        if not isinstance(rows, list):
            rows = []
    elif isinstance(payload, list):
        rows = payload
    else:
        rows = []

    aircraft = []
    for row in rows:
        normalized = normalize_aircraft(row, when)
        if normalized is not None:
            aircraft.append(normalized)

    return aircraft, summarize_message_count(payload, aircraft)


def _find_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def resolve_dump1090() -> str:
    for candidate in DUMP1090_CANDIDATES:
        if os.path.isabs(candidate):
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        else:
            resolved = shutil.which(candidate)
            if resolved:
                return resolved
    raise FileNotFoundError(
        "dump1090 was not found. Expected ~/Installed_by_FISSURE/dump1090/dump1090 "
        "or a dump1090 executable in PATH."
    )


def _http_json(url: str, timeout_s: float = 0.75) -> Any:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "FISSURE-ADS-B/1.0"},
    )
    with urllib.request.urlopen(request, timeout=timeout_s) as response:
        data = response.read()
    return json.loads(data.decode("utf-8", errors="replace"))


class Dump1090Receiver(object):
    """Own one dump1090 process and poll its local JSON interface."""

    def __init__(
        self,
        logger,
        device_index: int = 0,
        frequency_hz: int = 1090000000,
        environment: Optional[Dict[str, str]] = None,
    ) -> None:
        self.logger = logger
        self.device_index = max(0, int(device_index))
        self.frequency_hz = int(frequency_hz)
        self.environment = dict(environment or os.environ.copy())
        self.http_port = _find_free_port()
        self.base_url = "http://127.0.0.1:%d" % self.http_port
        self.executable = ""
        self.cwd = ""
        self.process = None
        self.stderr_task = None
        self.last_output = []
        self.endpoint = ""
        self._consecutive_poll_failures = 0

    def _diagnostic_detail(self) -> str:
        return " | ".join(self.last_output[-5:]) or "no diagnostic output"

    def _raise_if_exited(self) -> None:
        process = self.process
        if process is None:
            raise Dump1090UnavailableError("dump1090 is not running")
        if process.returncode is not None:
            raise Dump1090UnavailableError(
                "dump1090 exited with code %s: %s"
                % (process.returncode, self._diagnostic_detail())
            )

    async def _drain_stderr(self) -> None:
        process = self.process
        if process is None or process.stderr is None:
            return

        while True:
            line = await process.stderr.readline()
            if not line:
                break
            text = line.decode(errors="ignore").strip()
            if text:
                self.last_output.append(text)
                self.last_output = self.last_output[-20:]
                self.logger.debug("dump1090: %s", text)

    async def start(self) -> None:
        self.executable = resolve_dump1090()
        self.cwd = os.path.dirname(self.executable) or os.getcwd()

        cmd = [
            self.executable,
            "--device-index",
            str(self.device_index),
            "--freq",
            str(self.frequency_hz),
            "--net",
            "--net-http-port",
            str(self.http_port),
        ]

        self.logger.info("Starting dump1090: %s", " ".join(cmd))
        self.process = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=self.cwd,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            env=self.environment,
            start_new_session=True,
        )
        self.stderr_task = asyncio.create_task(self._drain_stderr())

        await asyncio.sleep(0.75)
        if self.process.returncode is not None:
            if self.stderr_task is not None:
                await asyncio.gather(self.stderr_task, return_exceptions=True)
            self._raise_if_exited()

    async def stop(self) -> None:
        process = self.process
        if process is not None and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=4.0)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()

        if self.stderr_task is not None:
            await asyncio.gather(self.stderr_task, return_exceptions=True)

    async def _fetch_endpoint(self, endpoint: str) -> Any:
        loop = asyncio.get_running_loop()
        url = self.base_url + endpoint
        return await loop.run_in_executor(None, _http_json, url)

    async def poll(
        self,
        tolerate_unready: bool = False,
    ) -> Tuple[List[Dict[str, Any]], int]:
        self._raise_if_exited()

        endpoints = []
        if self.endpoint:
            endpoints.append(self.endpoint)
        endpoints.extend(
            endpoint
            for endpoint in AIRCRAFT_ENDPOINTS
            if endpoint not in endpoints
        )

        last_error = None
        for endpoint in endpoints:
            try:
                payload = await self._fetch_endpoint(endpoint)
                self.endpoint = endpoint
                self._consecutive_poll_failures = 0
                return parse_aircraft_payload(payload)
            except (
                urllib.error.URLError,
                urllib.error.HTTPError,
                OSError,
                ValueError,
                json.JSONDecodeError,
            ) as exc:
                last_error = exc
            except Exception as exc:
                last_error = exc

        self._raise_if_exited()
        self._consecutive_poll_failures += 1

        if last_error is not None:
            self.logger.debug("dump1090 JSON poll unavailable: %s", last_error)

        if tolerate_unready or not self.endpoint:
            return [], 0

        if self._consecutive_poll_failures >= MAX_CONSECUTIVE_POLL_FAILURES:
            raise Dump1090UnavailableError(
                "dump1090 JSON interface unavailable for %d consecutive polls: %s"
                % (
                    self._consecutive_poll_failures,
                    last_error or "unknown error",
                )
            )

        return [], 0

    async def wait_until_ready(self, timeout_s: float = 8.0) -> bool:
        deadline = asyncio.get_running_loop().time() + max(0.5, float(timeout_s))
        while asyncio.get_running_loop().time() < deadline:
            self._raise_if_exited()
            await self.poll(tolerate_unready=True)
            if self.endpoint:
                return True
            await asyncio.sleep(0.25)
        return bool(self.endpoint)
