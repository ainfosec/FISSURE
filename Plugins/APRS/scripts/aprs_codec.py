"""Strict-enough TNC2/APRS decoder for receive-only discovery and position reports.

A position is an unverified APRS *reported* position, never an RF geolocation.
Unsupported packet types are still reported as packets, without fabricated coords.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional


_CALL = re.compile(r"^[A-Z0-9]{1,6}(?:-(?:[0-9]|1[0-5]))?$")
_TNC2 = re.compile(r"^(?P<src>[^>:,\s]+)>(?P<header>[^:\s]+):(?P<info>.*)$")
_UNCOMPRESSED = re.compile(
    r"^(?P<lat_deg>[0-8][0-9]|90)(?P<lat_min>[0-5][0-9]\.\d{2})(?P<ns>[NS])"
    r"(?P<table>[/\\A-Z0-9])"
    r"(?P<lon_deg>0[0-9][0-9]|1[0-7][0-9]|180)"
    r"(?P<lon_min>[0-5][0-9]\.\d{2})(?P<ew>[EW])(?P<symbol>.)"
)
_OBJECT = re.compile(r"^;(?P<name>.{9})(?P<alive>[*_])(?P<time>.{7})(?P<body>.*)$")
_ITEM = re.compile(r"^\)(?P<name>[^!_]{1,9})(?P<alive>[!_])(?P<body>.*)$")
_ALTITUDE = re.compile(r"/A=(\d{6})")


def _decode_position(body: str) -> Optional[Dict[str, Any]]:
    """Decode normal APRS lat/lon or base-91 compressed coordinates."""
    match = _UNCOMPRESSED.match(body)
    if match:
        m = match.groupdict()
        lat = int(m["lat_deg"]) + float(m["lat_min"]) / 60.0
        lon = int(m["lon_deg"]) + float(m["lon_min"]) / 60.0
        if lat > 90 or lon > 180:
            return None
        if m["ns"] == "S":
            lat = -lat
        if m["ew"] == "W":
            lon = -lon
        remaining = body[match.end():]
        result = {
            "latitude": round(lat, 6), "longitude": round(lon, 6),
            "symbol_table": m["table"], "symbol_code": m["symbol"],
            "position_format": "uncompressed",
        }
    elif re.match(r"^\d{4}\.\d{2}[NS]", body):
        # A damaged *uncompressed* coordinate must not be reinterpreted as base91.
        return None
    elif (len(body) >= 10 and body[0] in "/\\0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
          and all(33 <= ord(c) <= 123 for c in body[1:9])):
        # APRS 1.2, chapter 9: symbol table + 4 base91 lat + 4 base91 lon + symbol.
        def base91(chars: str) -> int:
            number = 0
            for character in chars:
                number = number * 91 + ord(character) - 33
            return number

        lat = 90.0 - base91(body[1:5]) / 380926.0
        lon = -180.0 + base91(body[5:9]) / 190463.0
        if not (-90 <= lat <= 90 and -180 <= lon <= 180):
            return None
        remaining = body[10:]
        result = {
            "latitude": round(lat, 6), "longitude": round(lon, 6),
            "symbol_table": body[0], "symbol_code": body[9],
            "position_format": "compressed",
        }
    else:
        return None

    # APRS may append human-readable altitude in *feet*. It is not always present.
    altitude = _ALTITUDE.search(remaining)
    if altitude:
        result["altitude_m"] = round(int(altitude.group(1)) * 0.3048, 2)
    return result


def _position_from_info(info: str) -> tuple[str, Optional[Dict[str, Any]], str]:
    """Return (message kind, position, mapped entity); entity is empty for station."""
    if not info:
        return "other", None, ""
    prefix = info[0]
    if prefix in ("!", "="):
        return "position", _decode_position(info[1:]), ""
    if prefix in ("/", "@"):
        # DHMMSSz / HHMMSSh / MMDDHHz timestamps occupy exactly seven bytes.
        return "position", _decode_position(info[8:]) if len(info) >= 9 else None, ""
    if prefix == ";":
        obj = _OBJECT.match(info)
        if obj:
            pos = _decode_position(obj["body"]) if obj["alive"] == "*" else None
            return "object", pos, obj["name"].strip()
        return "object", None, ""
    if prefix == ")":
        item = _ITEM.match(info)
        if item:
            pos = _decode_position(item["body"]) if item["alive"] == "!" else None
            return "item", pos, item["name"].strip()
        return "item", None, ""
    if prefix == ":":
        return "message", None, ""
    if prefix == ">":
        return "status", None, ""
    if prefix == "T" and len(info) > 1 and info[1] == "#":
        return "telemetry", None, ""
    if prefix == "_":
        return "weather", None, ""
    if prefix == "}":
        # Third-party encapsulated position belongs to the enclosed station, NOT
        # to the gateway in the outer frame. Do not misattribute its position.
        return "third_party", None, ""
    return "other", None, ""


def parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Read TNC2 lines or rtl_fm/multimon-ng AFSK1200/APRS lines.

    Returns None for noise, unrelated decoder lines, and malformed AX.25 headers.
    """
    text = line.strip().replace("\x00", "")
    if len(text) > 8192:
        return None
    # Prefixes often seen in multimon-ng: 'APRS: ...' and 'AFSK1200: ...'.
    for _ in range(2):
        prefix = re.match(r"^(?:APRS|AFSK1200):\s*", text, re.IGNORECASE)
        if not prefix:
            break
        text = text[prefix.end():]
    m = _TNC2.match(text)
    if not m:
        return None
    source = m["src"].upper()
    if not _CALL.fullmatch(source):
        return None
    header = m["header"].split(",")
    destination = header[0].upper()
    if not re.fullmatch(r"[A-Z0-9-]{1,12}", destination):
        return None
    path = header[1:]
    if len(path) > 8 or any(not re.fullmatch(r"[A-Za-z0-9-]{1,12}\*?", p) for p in path):
        return None
    info = m["info"]
    kind, position, entity = _position_from_info(info)
    return {
        "source": source, "destination": destination, "path": path,
        "information": info, "raw_packet": text,
        "packet_type": kind, "position": position, "position_entity": entity,
    }
