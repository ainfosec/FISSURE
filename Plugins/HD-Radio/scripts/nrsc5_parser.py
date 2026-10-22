#!/usr/bin/env python3
"""Parse the documented log output of theori-io/nrsc5's C CLI (not RDS).

NRSC-5 synchronization by itself is a *candidate*; decoded NRSC-5 station
identity or service-guide data in the same acquisition confirms HD Radio.
Analog FM, RDS, or an energy peak cannot satisfy the confirmation rule.
"""
import re
from typing import Any, Dict, Iterable, List


LOG_PREFIX = re.compile(r"^\s*\d{2}:\d{2}:\d{2}\s+")
SIG_SERVICE = re.compile(r"^SIG Service: type=(audio|data) number=(\d+) name=(.*)$")
STATION_ID = re.compile(r"^Country:\s*([^,]+),\s*FCC facility ID:\s*(\d+)\s*$")
AUDIO_PROGRAM = re.compile(r"^Audio program (\d+):\s*(public|restricted),\s*type:\s*(.*?),\s*sound experience\s*(\d+)\s*$")
AUDIO_SERVICE = re.compile(r"^Audio service (\d+):\s*(public|restricted),\s*type:\s*(.*?),\s*codec:")


def parse_nrsc5_output(lines: Iterable[str], frequency_mhz: float) -> Dict[str, Any]:
    """Return one scan record, keeping signal observations distinct from identity."""
    result = {
        "frequency_mhz": round(float(frequency_mhz), 1),
        "classification": "no_hd_confirmed",
        "nrsc5_synchronized": False,
        "station_identifiers": {
            "station_name": None,
            "country_code": None,
            "fcc_facility_id": None,
            "slogan": None,
        },
        "programs": [],
        "data_services": [],
        "notes": [],
    }
    programs = {}
    data_services = {}
    for raw_line in lines:
        line = LOG_PREFIX.sub("", str(raw_line).strip())
        if line == "Synchronized":
            result["nrsc5_synchronized"] = True
            continue
        match = STATION_ID.fullmatch(line)
        if match:
            result["station_identifiers"]["country_code"] = match.group(1).strip()
            result["station_identifiers"]["fcc_facility_id"] = int(match.group(2))
            continue
        if line.startswith("Station name: "):
            result["station_identifiers"]["station_name"] = line.partition(": ")[2].strip() or None
            continue
        if line.startswith("Slogan: "):
            result["station_identifiers"]["slogan"] = line.partition(": ")[2].strip() or None
            continue
        match = SIG_SERVICE.fullmatch(line)
        if match:
            service_type, number_str, name = match.groups()
            number = int(number_str)
            if service_type == "audio":
                program = programs.setdefault(number, {"program_number": number, "hd_channel": "HD%d" % (number + 1)})
                program["name"] = name.strip() or None
            else:
                data_services[number] = {"service_number": number, "name": name.strip() or None}
            continue
        match = AUDIO_PROGRAM.fullmatch(line)
        if match:
            number_str, access, program_type, sound_experience = match.groups()
            number = int(number_str)
            program = programs.setdefault(number, {"program_number": number, "hd_channel": "HD%d" % (number + 1)})
            program.update({"access": access, "program_type": program_type, "sound_experience": int(sound_experience)})
            continue
        match = AUDIO_SERVICE.match(line)
        if match:
            number_str, access, program_type = match.groups()
            number = int(number_str)
            program = programs.setdefault(number, {"program_number": number, "hd_channel": "HD%d" % (number + 1)})
            program.update({"access": access, "program_type": program_type})
            continue

    result["programs"] = [programs[k] for k in sorted(programs)]
    result["data_services"] = [data_services[k] for k in sorted(data_services)]
    ident = result["station_identifiers"]
    decoded = bool(
        ident["station_name"]
        or ident["fcc_facility_id"] is not None
        or result["programs"]
        or result["data_services"]
    )
    if result["nrsc5_synchronized"] and decoded:
        result["classification"] = "confirmed_hd_radio"
    elif result["nrsc5_synchronized"]:
        result["classification"] = "sync_only_unconfirmed"
        result["notes"].append("NRSC-5 synchronization observed, but SIS/SIG/service metadata was not decoded during dwell.")
    elif decoded:
        # Guard against a stray parsed line from a broken acquisition/log fixture.
        result["notes"].append("NRSC-5 metadata without synchronized demodulator; not confirmed.")
    return result
