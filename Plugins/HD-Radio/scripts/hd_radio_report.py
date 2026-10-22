"""Common FISSURE Artifact payload and readable station reports."""
import csv
import io
import json


def counts(payload):
    obs = payload["observations"]
    return {
        "channels_requested": len(payload["channels_mhz"]),
        "channels_acquired": len(obs),
        "channels_completed": sum(r.get("acquisition_status") == "complete" for r in obs),
        "channels_failed": sum(r.get("acquisition_status") == "failed" for r in obs),
        "confirmed": len(payload["confirmed_stations"]),
        "sync_only": len(payload["synchronization_candidates"]),
        "not_checked": len(payload["channels_not_checked"]),
        "seconds_elapsed": payload["duration_seconds"],
    }


def summarize(payload):
    observations = payload["observations"]
    payload["confirmed_stations"] = sorted(
        (r for r in observations if r.get("acquisition_status") == "complete" and
         r.get("classification") == "confirmed_hd_radio"), key=lambda r: r["frequency_mhz"])
    payload["synchronization_candidates"] = sorted(
        (r for r in observations if r.get("acquisition_status") == "complete" and
         r.get("classification") == "sync_only_unconfirmed"), key=lambda r: r["frequency_mhz"])
    checked = {r["frequency_mhz"] for r in observations}
    payload["channels_not_checked"] = [f for f in payload["channels_mhz"] if f not in checked]
    payload["statistics"] = counts(payload)
    return payload


def program_description(record):
    parts = []
    for program in record.get("programs", []):
        desc = program.get("hd_channel", "HD?")
        if program.get("name"):
            desc += " " + str(program["name"])
        if program.get("program_type"):
            desc += " (" + str(program["program_type"]) + ")"
        parts.append(desc)
    return "; ".join(parts) if parts else "not decoded"


def station_line(record):
    ident = record.get("station_identifiers", {})
    name = ident.get("station_name") or "Unknown callsign/name"
    details = ["%.1f MHz" % record["frequency_mhz"], str(name)]
    if ident.get("fcc_facility_id") is not None:
        details.append("FCC facility ID %s" % ident["fcc_facility_id"])
    if ident.get("country_code"):
        details.append(str(ident["country_code"]))
    return " | ".join(details)


def render_text(payload):
    stats = payload["statistics"]
    lines = ["HD RADIO STATION SCAN", "=====================", "",
             "Mode: %s" % payload["mode"].title(),
             "Result: %s" % payload["status"].upper(),
             "Started (UTC): %s" % payload["started_at_utc"],
             "Finished (UTC): %s" % payload["finished_at_utc"],
             "Runtime: %.1fs" % stats["seconds_elapsed"],
             "Range: %.1f–%.1f MHz (200 kHz grid)" % (
                 payload["parameters"]["start_frequency_mhz"],
                 payload["parameters"]["stop_frequency_mhz"]),
             "Channels: %d requested; %d acquired; %d complete; %d untested" % (
                 stats["channels_requested"], stats["channels_acquired"],
                 stats["channels_completed"], stats["not_checked"]),
             "Confirmed: %d | Sync-only: %d | Acquisition failures: %d" % (
                 stats["confirmed"], stats["sync_only"], stats["channels_failed"]),
             "", "CONFIRMED HD RADIO STATIONS", "---------------------------"]
    if not payload["confirmed_stations"]:
        lines.append("None confirmed during this scan.")
    for record in payload["confirmed_stations"]:
        lines.append(station_line(record))
        ident = record["station_identifiers"]
        if ident.get("slogan"):
            lines.append("  Slogan: " + str(ident["slogan"]))
        lines.append("  Programs: " + program_description(record))
        services = record.get("data_services") or []
        if services:
            lines.append("  Data services: " + ", ".join(str(s.get("name") or s.get("service_number")) for s in services))
        lines.append("  Acquisition: %.1fs" % record.get("acquisition_seconds", 0.0))
    lines.extend(["", "SYNC-ONLY / UNCONFIRMED CANDIDATES", "----------------------------------"])
    if not payload["synchronization_candidates"]:
        lines.append("None.")
    for record in payload["synchronization_candidates"]:
        lines.append("%.1f MHz | NRSC-5 synchronized; SIS/SIG not decoded" % record["frequency_mhz"])
    if payload.get("survey"):
        survey = payload["survey"]
        lines.extend(["", "QUICK SCAN SPECTRUM SURVEY", "--------------------------",
                      "Selected %d of %d channel centers; %.1f dB threshold above reference floor" % (
                          survey["selected_count"], len(payload["channels_mhz"]), survey["threshold_db"]),
                      survey["caveat"]])
    if payload["channels_not_checked"]:
        lines.extend(["", "CHANNELS NOT ACQUIRED", "---------------------",
                      ", ".join("%.1f" % f for f in payload["channels_not_checked"]) + " MHz"])
    if payload["errors"]:
        lines.extend(["", "ERRORS", "------"])
        for error in payload["errors"]:
            lines.append(("%.1f MHz: " % error["frequency_mhz"] if "frequency_mhz" in error else "") + error["error"])
    lines.extend(["", "NOTES", "-----",
                  "Confirmation requires NRSC-5 synchronization AND decoded station/service metadata in a valid acquisition.",
                  "Sync-only entries are not confirmed HD broadcasts.",
                  "Undetected or unscanned frequencies are NOT evidence that HD Radio is absent.",
                  "See hd_radio_scan.json for channel-by-channel observations and survey scores.", ""])
    return "\n".join(lines)


def render_csv(payload):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["frequency_mhz", "classification", "station_name", "country_code", "fcc_facility_id",
                     "slogan", "programs", "data_services", "acquisition_seconds"])
    for record in payload["confirmed_stations"] + payload["synchronization_candidates"]:
        ident = record["station_identifiers"]
        writer.writerow(["%.1f" % record["frequency_mhz"], record["classification"],
                         ident.get("station_name") or "", ident.get("country_code") or "",
                         ident.get("fcc_facility_id") if ident.get("fcc_facility_id") is not None else "",
                         ident.get("slogan") or "", program_description(record),
                         json.dumps(record.get("data_services", [])), record.get("acquisition_seconds", "")])
    return output.getvalue()
