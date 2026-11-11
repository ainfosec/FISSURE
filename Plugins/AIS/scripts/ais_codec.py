"""AIS NMEA framing and normalization, shared by receiver and simulator.

pyais handles AIS payload bits. This module verifies NMEA 0183 XOR checksums,
assembles multipart messages, and keeps reported vessel positions distinct from
receiver GPS or independent RF geolocation.
"""
from __future__ import annotations

import math
import time
from typing import Any, Dict, List, Optional

# Identify the loaded API to prevent stale imports after a plugin refresh.
FISSURE_AIS_API_REVISION = "ais-plugin-2026-11-10-v1.0"


def boolean(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    value = str(value).strip().lower()
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off"}:
        return False
    raise ValueError("Expected true or false, received %r" % value)


def require_pyais():
    try:
        import pyais
        return pyais
    except ImportError as exc:
        raise RuntimeError("pyais is required on the executing Sensor Node; enable its FISSURE installer item") from exc


def checksum_valid(sentence: str) -> bool:
    """Validate a bare !AIVDM/!AIVDO NMEA 0183 sentence."""
    text = str(sentence).strip()
    if not text.startswith(("!AIVDM,", "!AIVDO,")) or "*" not in text:
        return False
    data, checksum = text.rsplit("*", 1)
    if len(checksum) != 2:
        return False
    try:
        expected = int(checksum, 16)
    except ValueError:
        return False
    actual = 0
    for character in data[1:]:
        actual ^= ord(character)
    return actual == expected


def to_nmea_lines(raw: str) -> List[str]:
    """Accept newline-separated NMEA with optional NMEA-4 tag block."""
    output = []
    for candidate in str(raw).splitlines():
        candidate = candidate.strip().replace("\x00", "")
        if not candidate or len(candidate) > 1024:
            continue
        # Preserve tag-block text in a recorder only if needed; pyais gets bare NMEA.
        if candidate.startswith("\\"):
            end = candidate.find("\\", 1)
            if end < 0:
                continue
            candidate = candidate[end + 1:]
        if checksum_valid(candidate):
            output.append(candidate)
    return output


def _finite_number(value, lo, hi):
    try:
        number = float(value)
        if math.isfinite(number) and lo <= number <= hi:
            return number
    except (ValueError, TypeError, OverflowError):
        pass
    return None


def normalize_message(fields: Dict[str, Any], raw_parts: List[str], observed_epoch: Optional[float] = None) -> Dict[str, Any]:
    """Return a JSON-safe observation without claiming RF location accuracy."""
    mmsi_raw = fields.get("mmsi")
    try:
        mmsi_number = int(mmsi_raw)
        if not 0 <= mmsi_number <= 999999999:
            raise ValueError("invalid MMSI")
        mmsi = "%09d" % mmsi_number
    except (TypeError, ValueError):
        raise ValueError("Decoded AIS message has invalid MMSI")
    msg_type = int(fields.get("type", fields.get("msg_type", 0)))
    if not 1 <= msg_type <= 27:
        raise ValueError("Decoded AIS message has invalid type")
    lat = _finite_number(fields.get("lat", fields.get("latitude")), -90, 90)
    lon = _finite_number(fields.get("lon", fields.get("longitude")), -180, 180)
    # Only the position-bearing message types may directly update location.
    has_position = msg_type in {1, 2, 3, 4, 9, 18, 19, 21, 27} and lat is not None and lon is not None
    epoch = time.time() if observed_epoch is None else float(observed_epoch)
    row = {
        "mmsi": mmsi, "message_type": msg_type, "observed_epoch": epoch,
        "nmea_channel": raw_parts[0].split(",")[4] if raw_parts else "",
        "raw_nmea": raw_parts,
        "reported_position_valid": has_position,
        "position_semantics": "ais_self_reported_not_rf_geolocation",
        "source_format": "NMEA_0183",
        "decoded": fields,
    }
    if has_position:
        row["latitude"], row["longitude"] = lat, lon
    for source, dest, lo, hi in (
        ("speed", "speed_kt", 0, 102.2), ("course", "course_deg", 0, 360),
        ("heading", "heading_deg", 0, 359),
    ):
        value = _finite_number(fields.get(source), lo, hi)
        if value is not None:
            row[dest] = value
    for source, dest in (("shipname", "ship_name"), ("callsign", "callsign"),
                         ("destination", "destination")):
        value = str(fields.get(source) or "").replace("@", "").strip()
        if value:
            row[dest] = value
    if msg_type == 24 and fields.get("partno") is not None:
        row["static_part"] = int(fields["partno"])
    if fields.get("ship_type") is not None:
        try:
            row["ship_type"] = int(fields["ship_type"])
        except (TypeError, ValueError):
            pass
    return row


class AISMessageAssembler:
    """Bounded and expiring assembly of multipart NMEA sentences."""
    def __init__(self, fragment_ttl_s: float = 30.0):
        self.pending: Dict[tuple, Dict[str, Any]] = {}
        self.ttl = max(1.0, float(fragment_ttl_s))
        self.invalid_count = 0

    def push(self, line: str, observed_epoch: Optional[float] = None) -> Optional[Dict[str, Any]]:
        line = str(line).strip()
        if not checksum_valid(line):
            self.invalid_count += 1
            return None
        parts = line.split("*")[0].split(",")
        if len(parts) != 7:
            self.invalid_count += 1
            return None
        try:
            total, number = int(parts[1]), int(parts[2])
        except (ValueError, TypeError):
            self.invalid_count += 1
            return None
        if not (1 <= total <= 9 and 1 <= number <= total):
            self.invalid_count += 1
            return None
        epoch = time.time() if observed_epoch is None else observed_epoch
        self.pending = {k: v for k, v in self.pending.items() if epoch - v["at"] <= self.ttl}
        if len(self.pending) > 128:
            self.pending.clear()
        if total == 1:
            collected = [line]
        else:
            key = (parts[0], total, parts[3], parts[4])
            if number == 1:
                self.pending[key] = {"at": epoch, "parts": {1: line}}
                return None
            item = self.pending.get(key)
            if not item:
                return None
            if number in item["parts"]:
                self.invalid_count += 1
                self.pending.pop(key, None)
                return None
            item["parts"][number] = line
            if len(item["parts"]) < total:
                return None
            collected = [item["parts"][n] for n in range(1, total + 1)]
            self.pending.pop(key, None)
        pyais = require_pyais()
        try:
            msg = pyais.decode(*collected)
            return normalize_message(msg.asdict(), collected, epoch)
        except Exception:
            self.invalid_count += 1
            return None


def encode_position(mmsi: str, lat: float, lon: float, speed: float, course: float, channel: str,
                    message_type: int = 1) -> List[str]:
    require_pyais()
    from pyais.encode import encode_dict
    if int(message_type) not in (1, 18):
        raise ValueError("AIS synthetic position message_type must be 1 or 18")
    row = {"type": int(message_type), "mmsi": str(mmsi), "lat": float(lat), "lon": float(lon),
           "speed": float(speed), "course": float(course), "heading": int(course) % 360}
    if int(message_type) == 1:
        row["status"] = 0
    return _normalize_encoded(encode_dict(row, radio_channel=channel, talker_id="AIVDM"))


def encode_static(mmsi: str, name: str, channel: str) -> List[str]:
    require_pyais()
    from pyais.encode import encode_dict
    row = {"type": 5, "mmsi": str(mmsi), "shipname": str(name)[:20],
           "callsign": "DEMO", "destination": "SIMULATION ONLY"}
    return _normalize_encoded(encode_dict(row, radio_channel=channel, talker_id="AIVDM"))



def encode_class_b_static(mmsi: str, name: str, callsign: str, channel: str) -> List[str]:
    """Generate independent Type 24 Part A (name) and Part B (callsign) AIS slots.

    Unlike Type 5, Type 24 is composed of two *separately framed* radio
    messages. Each one fits in a single AIS TDMA slot and can be demodulated
    without constructing a multi-slot over-the-air packet.
    """
    require_pyais()
    from pyais.encode import encode_dict
    a = {"type": 24, "partno": 0, "mmsi": str(mmsi), "shipname": str(name)[:20]}
    b = {"type": 24, "partno": 1, "mmsi": str(mmsi), "ship_type": 60,
         "vendorid": "SIM", "model": 1, "serial": 0,
         "callsign": str(callsign)[:7], "to_bow": 10, "to_stern": 8,
         "to_port": 3, "to_starboard": 3}
    result = _normalize_encoded(encode_dict(a, radio_channel=channel, talker_id="AIVDM"))
    result.extend(_normalize_encoded(encode_dict(b, radio_channel=channel, talker_id="AIVDM")))
    if len(result) != 2 or any(line.split(",")[1:3] != ["1", "1"] for line in result):
        raise RuntimeError("AIS Type 24 should encode as two independent single-sentence messages")
    return result

def _normalize_encoded(result) -> List[str]:
    if isinstance(result, (str, bytes)):
        result = [result]
    lines = [line.decode("ascii") if isinstance(line, bytes) else str(line) for line in result]
    lines = [line.strip() for line in lines]
    if not lines or any(not checksum_valid(line) for line in lines):
        raise RuntimeError("pyais produced an invalid NMEA sentence")
    return lines
