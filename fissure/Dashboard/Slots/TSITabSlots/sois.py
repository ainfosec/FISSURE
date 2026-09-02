from PyQt5 import QtCore, QtWidgets

from datetime import datetime, timezone
import asyncio
import html
import inspect
import json
import time
import uuid

import qasync

from fissure.Dashboard.SoiEvidenceController import build_soi_evidence_folder, collect_soi_artifact_ids
from fissure.Dashboard.UI_Components import Qt5


SA_SOI_FILTERS = [
    ("All SOIs", "all"),
    ("Has Evidence", "evidence"),
    ("Has Detections", "detections"),
    ("Has Analysis", "analysis"),
    ("Has Location", "location"),
    ("Classified", "classified"),
]


def _sa_sois_summary(soi):
    """
    Return the best merged SOI summary from the Dashboard record and raw hub record.
    """
    if not isinstance(soi, dict):
        return {}

    merged = {}
    raw = soi.get("raw", {})

    if isinstance(raw, dict):
        raw_summary = raw.get("summary", {})
        if isinstance(raw_summary, dict):
            merged.update(raw_summary)

    summary = soi.get("summary", {})
    if isinstance(summary, dict):
        merged.update(summary)

    return merged


def _sa_sois_value(soi, *keys, default=""):
    """
    Return the first populated value from the Dashboard record, merged summary, or raw hub record.
    """
    if not isinstance(soi, dict):
        return default

    summary = _sa_sois_summary(soi)
    raw = soi.get("raw", {})
    if not isinstance(raw, dict):
        raw = {}

    for key in keys:
        for source in (soi, summary, raw):
            if key not in source:
                continue

            value = source.get(key)
            if value not in (None, "", "None"):
                return value

    return default


def _sa_sois_display_name(soi):
    """
    Return the best human-readable name available for an SOI.
    """
    name = _sa_sois_value(soi, "name", "label", "title")
    if name:
        return str(name).strip()

    frequency = _sa_sois_value(soi, "frequency_mhz", "center_frequency_mhz")
    if frequency not in (None, "", "None"):
        try:
            return f"{float(frequency):.3f} MHz SOI"
        except Exception:
            return f"{frequency} SOI"

    soi_id = str(soi.get("soi_id", "") or soi.get("uid", "") or soi.get("id", "") or "SOI").strip()
    if len(soi_id) > 18:
        soi_id = f"{soi_id[:8]}…{soi_id[-6:]}"

    return soi_id or "SOI"


def _sa_sois_classification(soi):
    """
    Return the preferred classification, favoring analyst results over model and database results.
    """
    analyst = _sa_sois_value(soi, "analyst_classification", "confirmed_classification")
    if analyst:
        return str(analyst)

    model = _sa_sois_value(soi, "model_classification_display", "model_classification", "classification")
    if model:
        model = str(model)

        if "(" not in model:
            confidence = _sa_sois_value(
                soi, "model_confidence_pct", "model_confidence", "classification_confidence"
            )
            if confidence not in (None, "", "None"):
                try:
                    confidence_value = float(confidence)
                    if 0.0 <= confidence_value <= 1.0:
                        confidence_value *= 100.0
                    model += f" ({confidence_value:.0f}%)"
                except Exception:
                    pass

        return model

    database = _sa_sois_value(soi, "database_classification", "database_match")
    return str(database or "")


def _sa_sois_protocol(soi):
    """
    Return the preferred protocol value for an SOI.
    """
    value = _sa_sois_value(
        soi, "analyst_protocol", "confirmed_protocol", "detected_protocol", "protocol", "protocol_candidate"
    )
    return str(value or "")


def _sa_sois_stage(soi):
    """
    Return the current stage or status of an SOI.
    """
    return str(_sa_sois_value(soi, "stage", "status") or "")


def _sa_sois_format_frequency(value):
    """
    Format an SOI frequency value for display.
    """
    if value in (None, "", "None"):
        return "—"

    try:
        return f"{float(value):.6f} MHz"
    except Exception:
        return str(value)


def _sa_sois_format_bandwidth(soi):
    """
    Format an SOI bandwidth using the most appropriate available units.
    """
    value = _sa_sois_value(soi, "bandwidth_mhz", "bandwidth_hz", "bandwidth")
    if value in (None, "", "None"):
        return "—"

    if _sa_sois_value(soi, "bandwidth_mhz") not in (None, "", "None"):
        try:
            return f"{float(value):.6f} MHz"
        except Exception:
            return str(value)

    if _sa_sois_value(soi, "bandwidth_hz") not in (None, "", "None"):
        try:
            return f"{float(value) / 1e3:.3f} kHz"
        except Exception:
            return str(value)

    try:
        numeric = float(value)
        if abs(numeric) >= 1e5:
            return f"{numeric / 1e6:.6f} MHz"
        if abs(numeric) >= 1e3:
            return f"{numeric / 1e3:.3f} kHz"
    except Exception:
        pass

    return str(value)


def _sa_sois_format_time(value):
    """
    Format a timestamp-like value as UTC when possible.
    """
    if value in (None, "", "None"):
        return "—"

    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return str(value)

    text = str(value).strip()

    try:
        return datetime.fromtimestamp(float(text), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        pass

    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return text


def _sa_sois_time_sort_value(value):
    """
    Convert a timestamp-like value to a numeric value suitable for sorting.
    """
    if value in (None, "", "None"):
        return 0.0

    try:
        return float(value)
    except Exception:
        pass

    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return 0.0


def _sa_sois_format_location(soi):
    """
    Format the stored SOI latitude, longitude, and optional altitude.
    """
    lat = _sa_sois_value(soi, "lat", "latitude", default=None)
    lon = _sa_sois_value(soi, "lon", "longitude", default=None)
    alt = _sa_sois_value(soi, "hae_m", "alt", "altitude", default=None)

    if lat in (None, "", "None") or lon in (None, "", "None"):
        return "—"

    try:
        text = f"{float(lat):.6f}, {float(lon):.6f}"
    except Exception:
        text = f"{lat}, {lon}"

    if alt not in (None, "", "None"):
        try:
            text += f" ({float(alt):.1f} m)"
        except Exception:
            text += f" ({alt})"

    return text


def _sa_sois_column_text(soi, heading):
    """
    Return the display text for one SOI table column.
    """
    heading = str(heading or "").strip().casefold()

    if heading == "name":
        return _sa_sois_display_name(soi)

    if heading == "frequency":
        value = _sa_sois_value(soi, "frequency_mhz", "center_frequency_mhz")
        if value in (None, "", "None"):
            return ""
        try:
            return f"{float(value):.3f}"
        except Exception:
            return str(value)

    if heading == "bandwidth":
        text = _sa_sois_format_bandwidth(soi)
        return "" if text == "—" else text

    if heading == "classification":
        return _sa_sois_classification(soi)

    if heading == "protocol":
        return _sa_sois_protocol(soi)

    if heading == "stage":
        return _sa_sois_stage(soi)

    if heading in {"last seen", "updated", "updated at"}:
        value = _sa_sois_value(soi, "updated_at", "observation_time", "time")
        text = _sa_sois_format_time(value)
        return "" if text == "—" else text.replace(" UTC", "")

    return ""


def _sa_sois_record_search_text(soi):
    """
    Build a normalized searchable text string from the important SOI fields.
    """
    parts = [
        _sa_sois_display_name(soi),
        _sa_sois_classification(soi),
        _sa_sois_protocol(soi),
        _sa_sois_stage(soi),
        str(_sa_sois_value(soi, "frequency_mhz", default="")),
        str(_sa_sois_value(soi, "bandwidth", "bandwidth_mhz", default="")),
        str(_sa_sois_value(soi, "modulation", default="")),
        str(_sa_sois_value(soi, "source", "created_by", default="")),
        str(_sa_sois_value(soi, "notes", "description", default="")),
        str(soi.get("soi_id", "")),
        str(soi.get("node_uid", "")),
    ]
    return " ".join(parts).casefold()


def _sa_sois_matches_filter(soi, mode):
    """
    Return whether an SOI matches the selected list filter.
    """
    if mode == "all":
        return True
    if mode == "evidence":
        return bool(collect_soi_artifact_ids(soi))
    if mode == "detections":
        return bool(soi.get("detection_snapshots") or soi.get("detection_ids"))
    if mode == "analysis":
        return bool(soi.get("analysis_history"))
    if mode == "location":
        return _sa_sois_format_location(soi) != "—"
    if mode == "classified":
        return bool(_sa_sois_classification(soi))

    return True


def _sa_sois_selected_key(dashboard):
    """
    Return the SOI store key associated with the currently selected table row.
    """
    table = dashboard.ui.tableWidget_sa_sois_list
    row = table.currentRow()
    if row < 0:
        return None

    item = table.item(row, 0)
    if item is None:
        return None

    return item.data(QtCore.Qt.UserRole)


def get_selected_sa_soi(dashboard):
    """
    Return the selected SOI store key and SOI record.
    """
    soi_key = _sa_sois_selected_key(dashboard)
    if not soi_key:
        return None, None

    soi = (getattr(dashboard, "tactical_sois", {}) or {}).get(soi_key)
    if not isinstance(soi, dict) or not soi:
        return None, None

    return soi_key, soi


def _sa_sois_set_selected_widgets_enabled(dashboard, enabled):
    """
    Enable or disable controls that require a selected SOI.
    """
    widgets = [
        dashboard.ui.pushButton_sa_sois_list_edit,
        dashboard.ui.pushButton_sa_sois_list_delete,
        dashboard.ui.pushButton_sa_sois_selected_promote_to_target,
        dashboard.ui.pushButton_sa_sois_selected_capture,
        dashboard.ui.pushButton_sa_sois_selected_inspect,
        dashboard.ui.pushButton_sa_sois_selected_classify,
        dashboard.ui.pushButton_sa_sois_selected_protocol_discovery,
        dashboard.ui.pushButton_sa_sois_selected_direction_finding,
        dashboard.ui.tabWidget_sa_sois,
    ]

    for widget in widgets:
        widget.setEnabled(bool(enabled))


def clear_sa_sois_selected(dashboard):
    """
    Clear the selected-SOI summary and detail panels.
    """
    dashboard.selected_sa_soi_key = None
    dashboard.ui.label_sa_sois_selected_title.setText("Selected SOI:")

    value_labels = [
        dashboard.ui.label2_sa_sois_selected_name,
        dashboard.ui.label2_sa_sois_selected_soi_id,
        dashboard.ui.label2_sa_sois_selected_frequency,
        dashboard.ui.label2_sa_sois_selected_bandwidth,
        dashboard.ui.label2_sa_sois_selected_modulation,
        dashboard.ui.label2_sa_sois_selected_classification,
        dashboard.ui.label2_sa_sois_selected_protocol,
        dashboard.ui.label2_sa_sois_selected_stage,
        dashboard.ui.label2_sa_sois_selected_first_seen,
        dashboard.ui.label2_sa_sois_selected_last_seen,
        dashboard.ui.label2_sa_sois_selected_location,
        dashboard.ui.label2_sa_sois_selected_notes,
    ]

    for label in value_labels:
        label.setText("—")
        label.setToolTip("")

    dashboard.ui.label2_sa_sois_selected_snapshot_status.setText("No snapshot available")
    dashboard.ui.plainTextEdit_sa_sois_record_details.setPlainText("Select an SOI to view the complete record.")
    dashboard.ui.label_sa_sois_evidence_details.setText("Select an SOI to view linked evidence.")
    dashboard.ui.label_sa_sois_detections_details.setText("Select an SOI to view contributing detections.")
    dashboard.ui.label_sa_sois_analysis_details.setText("Select an SOI to view analysis results.")
    dashboard.ui.label_sa_sois_history_details.setText("Select an SOI to view record history.")
    _sa_sois_set_selected_widgets_enabled(dashboard, False)


def _sa_sois_link_color(dashboard):
    """
    Return a readable rich-text link color for the active Dashboard theme.
    """
    settings = getattr(dashboard.backend, "settings", {}) or {}
    color_mode = str(settings.get("color_mode", "") or "")

    if "Dark" in color_mode or "Custom" in color_mode:
        return "#66B3FF"

    return "#0057B8"


def _sa_sois_link(dashboard, href, text):
    """
    Render one theme-aware HTML link.
    """
    color = _sa_sois_link_color(dashboard)
    return (
        f"<a href='{html.escape(str(href), quote=True)}' "
        f"style='color:{color};'>{html.escape(str(text))}</a>"
    )


def _sa_sois_html_scalar(label, value):
    """
    Render one label/value pair as an HTML table row.
    """
    if value in (None, "", "None"):
        value = "—"

    return (
        "<tr>"
        f"<td style='padding-right:14px;'><b>{html.escape(str(label))}</b></td>"
        f"<td>{html.escape(str(value))}</td>"
        "</tr>"
    )


def _sa_sois_dict_html(data, skip_keys=None):
    """
    Render dictionary content as a compact HTML table for the detail panels.
    """
    if not isinstance(data, dict):
        return html.escape(str(data))

    skip_keys = set(skip_keys or [])
    rows = []

    for key, value in data.items():
        if key in skip_keys or value in (None, "", "None", [], {}):
            continue

        label = str(key).replace("_", " ").strip().title()
        if isinstance(value, (dict, list, tuple)):
            rendered = html.escape(json.dumps(value, indent=2, default=str)).replace("\n", "<br>").replace(
                "  ", "&nbsp;&nbsp;"
            )
        else:
            rendered = html.escape(str(value))

        rows.append(
            "<tr>"
            f"<td style='vertical-align:top;padding-right:14px;'><b>{html.escape(label)}</b></td>"
            f"<td>{rendered}</td>"
            "</tr>"
        )

    if not rows:
        return "<i>No additional values.</i>"

    return "<table cellspacing='3'>" + "".join(rows) + "</table>"


def _render_sa_sois_record(dashboard, soi):
    """
    Render the complete normalized SOI record without raw transport XML.
    """
    canonical = soi.get("raw") if isinstance(soi.get("raw"), dict) else soi
    record = dict(canonical)

    for key in ("raw_xml", "cot_xml", "xml", "raw_message", "raw_payload"):
        record.pop(key, None)

    rendered = json.dumps(record, indent=2, sort_keys=True, default=str)
    dashboard.ui.plainTextEdit_sa_sois_record_details.setPlainText(rendered)


def _render_sa_sois_evidence(dashboard, soi_key, soi):
    """
    Render linked artifacts and evidence-folder actions for the selected SOI.
    """
    artifact_ids = collect_soi_artifact_ids(soi)
    artifacts = getattr(dashboard, "tactical_artifacts", {}) or {}
    artifact_links = soi.get("artifact_links", []) or []
    roles = {}

    if isinstance(artifact_links, dict):
        artifact_links = [artifact_links]

    if isinstance(artifact_links, list):
        for link in artifact_links:
            if not isinstance(link, dict):
                continue

            artifact_id = str(link.get("artifact_id", "") or "").strip()
            if artifact_id:
                roles[artifact_id] = str(link.get("role", "") or "").strip()

    folder_link = _sa_sois_link(dashboard, f"soi-evidence:{soi_key}", "Open complete evidence folder")
    parts = [f"<b>Linked Evidence</b>&nbsp;&nbsp;{folder_link}<br><br>"]

    if not artifact_ids:
        parts.append("No artifacts are currently linked to this SOI.")
    else:
        for artifact_id in artifact_ids:
            record = artifacts.get(artifact_id, {})
            name = str(record.get("name", "") or "Artifact") if isinstance(record, dict) else "Artifact"
            artifact_type = str(record.get("artifact_type", "") or "") if isinstance(record, dict) else ""
            file_count = record.get("file_count", "") if isinstance(record, dict) else ""
            role = roles.get(artifact_id, "")

            details = []
            if role:
                details.append(role)
            if artifact_type:
                details.append(artifact_type)
            if file_count not in (None, ""):
                details.append(f"{file_count} file(s)")

            detail_text = f" — {html.escape(', '.join(details))}" if details else ""
            open_link = _sa_sois_link(dashboard, f"artifact:{artifact_id}", "Download / Open")

            parts.append(
                f"<b>{html.escape(name)}</b>{detail_text}&nbsp;&nbsp;{open_link}<br>"
                f"<span style='font-family:monospace;'>{html.escape(artifact_id)}</span><br><br>"
            )

    dashboard.ui.label_sa_sois_evidence_details.setText("".join(parts))


def _render_sa_sois_detections(dashboard, soi):
    """
    Render detections that contributed to the selected SOI.
    """
    snapshots = soi.get("detection_snapshots", []) or []
    if not isinstance(snapshots, list):
        snapshots = [snapshots]

    snapshots = [entry for entry in snapshots if isinstance(entry, dict)]

    if not snapshots:
        detection_ids = soi.get("detection_ids", []) or []
        if detection_ids:
            dashboard.ui.label_sa_sois_detections_details.setText(
                "<b>Detection IDs</b><br>" + "<br>".join(html.escape(str(value)) for value in detection_ids)
            )
        else:
            dashboard.ui.label_sa_sois_detections_details.setText(
                "No contributing detections are stored for this SOI."
            )
        return

    parts = []
    for index, snapshot in enumerate(snapshots, start=1):
        detection_id = (
            snapshot.get("detection_id")
            or snapshot.get("event_uid")
            or snapshot.get("uid")
            or snapshot.get("event_id")
            or f"Detection {index}"
        )

        parts.append(f"<b>{html.escape(str(detection_id))}</b><br>")
        parts.append(_sa_sois_dict_html(snapshot))

        if index != len(snapshots):
            parts.append("<hr>")

    dashboard.ui.label_sa_sois_detections_details.setText("".join(parts))


def _render_sa_sois_analysis(dashboard, soi):
    """
    Render classification, protocol, metadata, and analysis-history results for an SOI.
    """
    summary = _sa_sois_summary(soi)

    rows = [
        _sa_sois_html_scalar(
            "Analyst Classification", _sa_sois_value(soi, "analyst_classification", "confirmed_classification")
        ),
        _sa_sois_html_scalar(
            "Model Classification", _sa_sois_value(soi, "model_classification_display", "model_classification")
        ),
        _sa_sois_html_scalar(
            "Database Classification", _sa_sois_value(soi, "database_classification", "database_match")
        ),
        _sa_sois_html_scalar("Analyst Protocol", _sa_sois_value(soi, "analyst_protocol", "confirmed_protocol")),
        _sa_sois_html_scalar("Detected Protocol", _sa_sois_value(soi, "detected_protocol", "protocol")),
        _sa_sois_html_scalar("Protocol Candidate", _sa_sois_value(soi, "protocol_candidate")),
    ]

    skip_keys = {
        "artifact_links",
        "artifact_ids",
        "detection_snapshots",
        "detection_ids",
        "analysis_history",
        "name",
        "label",
        "title",
        "bandwidth",
        "bandwidth_mhz",
        "bandwidth_hz",
        "modulation",
        "stage",
        "source",
        "created_by",
        "notes",
        "description",
        "analyst_classification",
        "confirmed_classification",
        "analyst_protocol",
        "confirmed_protocol",
        "detected_protocol",
        "protocol",
        "protocol_candidate",
    }

    parts = ["<b>Classification & Protocol</b>", "<table cellspacing='3'>", "".join(rows), "</table>"]
    additional_html = _sa_sois_dict_html(summary, skip_keys=skip_keys)

    if additional_html != "<i>No additional values.</i>":
        parts.extend(["<br><br><b>Additional Analysis Metadata</b>", additional_html])

    analysis_history = soi.get("analysis_history", []) or []
    if isinstance(analysis_history, dict):
        analysis_history = [analysis_history]

    if analysis_history:
        parts.append("<br><b>Analysis Entries</b><br>")

        for index, entry in enumerate(analysis_history, start=1):
            if not isinstance(entry, dict):
                continue

            title = (
                entry.get("name")
                or entry.get("event")
                or entry.get("stage")
                or entry.get("operation_id")
                or f"Analysis {index}"
            )
            parts.append(f"<b>{html.escape(str(title))}</b><br>")
            parts.append(_sa_sois_dict_html(entry))

            if index != len(analysis_history):
                parts.append("<hr>")

    dashboard.ui.label_sa_sois_analysis_details.setText("".join(parts))


def _render_sa_sois_history(dashboard, soi):
    """
    Render a reverse-chronological history from stored SOI, detection, and analysis timestamps.
    """
    events = []

    created_at = soi.get("created_at")
    if created_at not in (None, "", "None"):
        events.append((created_at, "SOI Created", {"timestamp": _sa_sois_format_time(created_at)}))

    snapshots = soi.get("detection_snapshots", []) or []
    if isinstance(snapshots, dict):
        snapshots = [snapshots]

    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            continue

        timestamp = snapshot.get("timestamp") or snapshot.get("observation_time") or snapshot.get("time") or 0
        label = snapshot.get("detection_id") or snapshot.get("event_uid") or "Detection Observed"
        events.append((timestamp, f"Detection: {label}", snapshot))

    analysis_history = soi.get("analysis_history", []) or []
    if isinstance(analysis_history, dict):
        analysis_history = [analysis_history]

    for entry in analysis_history:
        if not isinstance(entry, dict):
            continue

        timestamp = (
            entry.get("timestamp")
            or entry.get("observation_time")
            or entry.get("created_at")
            or entry.get("updated_at")
            or 0
        )
        label = (
            entry.get("event")
            or entry.get("stage")
            or entry.get("name")
            or entry.get("operation_id")
            or "Analysis Updated"
        )
        events.append((timestamp, str(label), entry))

    updated_at = soi.get("updated_at")
    if updated_at not in (None, "", "None"):
        events.append((updated_at, "SOI Updated", {"timestamp": _sa_sois_format_time(updated_at)}))

    if not events:
        dashboard.ui.label_sa_sois_history_details.setText("No chronological history is stored for this SOI yet.")
        return

    events.sort(key=lambda item: _sa_sois_time_sort_value(item[0]), reverse=True)

    parts = []
    for index, (timestamp, label, payload) in enumerate(events):
        time_text = _sa_sois_format_time(timestamp)
        parts.append(f"<b>{html.escape(time_text)}</b> — {html.escape(str(label))}<br>")

        if isinstance(payload, dict) and len(payload) > 1:
            parts.append(_sa_sois_dict_html(payload, skip_keys={"timestamp"}))

        if index != len(events) - 1:
            parts.append("<hr>")

    dashboard.ui.label_sa_sois_history_details.setText("".join(parts))


def populate_sa_sois_selected(dashboard, soi_key, soi):
    """
    Populate the selected-SOI summary and lower detail tabs.
    """
    dashboard.selected_sa_soi_key = soi_key

    name = _sa_sois_display_name(soi)
    raw = soi.get("raw", {})
    if not isinstance(raw, dict):
        raw = {}

    first_seen = soi.get("created_at") or raw.get("created_at")
    last_seen = soi.get("updated_at") or raw.get("updated_at")

    dashboard.ui.label_sa_sois_selected_title.setText(f"Selected SOI: {name}")

    field_values = [
        (dashboard.ui.label2_sa_sois_selected_name, name),
        (dashboard.ui.label2_sa_sois_selected_soi_id, soi.get("soi_id", "") or "—"),
        (
            dashboard.ui.label2_sa_sois_selected_frequency,
            _sa_sois_format_frequency(_sa_sois_value(soi, "frequency_mhz", "center_frequency_mhz")),
        ),
        (dashboard.ui.label2_sa_sois_selected_bandwidth, _sa_sois_format_bandwidth(soi)),
        (dashboard.ui.label2_sa_sois_selected_modulation, _sa_sois_value(soi, "modulation", default="—") or "—"),
        (dashboard.ui.label2_sa_sois_selected_classification, _sa_sois_classification(soi) or "—"),
        (dashboard.ui.label2_sa_sois_selected_protocol, _sa_sois_protocol(soi) or "—"),
        (dashboard.ui.label2_sa_sois_selected_stage, _sa_sois_stage(soi) or "—"),
        (dashboard.ui.label2_sa_sois_selected_first_seen, _sa_sois_format_time(first_seen)),
        (dashboard.ui.label2_sa_sois_selected_last_seen, _sa_sois_format_time(last_seen)),
        (dashboard.ui.label2_sa_sois_selected_location, _sa_sois_format_location(soi)),
        (dashboard.ui.label2_sa_sois_selected_notes, _sa_sois_value(soi, "notes", "description", default="—") or "—"),
    ]

    for label, value in field_values:
        text = str(value)
        label.setText(text)
        label.setToolTip(text if text != "—" else "")

    dashboard.ui.label2_sa_sois_selected_snapshot_status.setText("No snapshot available")
    _render_sa_sois_evidence(dashboard, soi_key, soi)
    _render_sa_sois_detections(dashboard, soi)
    _render_sa_sois_analysis(dashboard, soi)
    _render_sa_sois_history(dashboard, soi)
    _render_sa_sois_record(dashboard, soi)
    _sa_sois_set_selected_widgets_enabled(dashboard, True)
    

def refresh_sa_sois_selected_details(dashboard):
    """
    Refresh the visible selected SOI without clearing a stable table selection.
    """
    soi_key = _sa_sois_selected_key(dashboard) or getattr(dashboard, "selected_sa_soi_key", None)
    if not soi_key:
        return

    soi = (getattr(dashboard, "tactical_sois", {}) or {}).get(soi_key)

    # A background cache replacement can temporarily remove the selected record.
    # Keep the existing UI intact and let the final table refresh repopulate it.
    if not isinstance(soi, dict) or not soi:
        return

    populate_sa_sois_selected(dashboard, soi_key, soi)


def refresh_sa_sois_table(dashboard, preserve_selection=True):
    """
    Rebuild the SOI table while preserving and refreshing the user's selected SOI.
    """
    table = dashboard.ui.tableWidget_sa_sois_list

    previous_key = None
    if preserve_selection:
        previous_key = _sa_sois_selected_key(dashboard) or getattr(dashboard, "selected_sa_soi_key", None)

    search_text = dashboard.ui.lineEdit_sa_sois_list_search.text().strip().casefold()
    filter_mode = getattr(dashboard, "sa_sois_filter_mode", "all")
    soi_store = getattr(dashboard, "tactical_sois", {}) or {}

    if isinstance(soi_store, dict):
        records = [(str(key), value) for key, value in soi_store.items() if isinstance(value, dict)]
    else:
        records = []

    records.sort(
        key=lambda item: _sa_sois_time_sort_value(
            item[1].get("updated_at") or item[1].get("created_at") or 0
        ),
        reverse=True,
    )

    visible_records = []
    for soi_key, soi in records:
        if search_text and search_text not in _sa_sois_record_search_text(soi):
            continue
        if not _sa_sois_matches_filter(soi, filter_mode):
            continue
        visible_records.append((soi_key, soi))

    dashboard.sa_sois_table_refreshing = True
    table.blockSignals(True)

    try:
        table.setSortingEnabled(False)
        table.clearContents()
        table.setRowCount(len(visible_records))

        selected_row = -1

        for row, (soi_key, soi) in enumerate(visible_records):
            for column in range(table.columnCount()):
                header_item = table.horizontalHeaderItem(column)
                heading = header_item.text() if header_item is not None else ""
                text = _sa_sois_column_text(soi, heading)

                item = QtWidgets.QTableWidgetItem(str(text))
                item.setData(QtCore.Qt.UserRole, soi_key)
                item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
                item.setToolTip(
                    f"{text}\n\nSOI ID: {soi.get('soi_id', '')}\nNode UID: {soi.get('node_uid', '')}"
                )
                table.setItem(row, column, item)

            if previous_key and soi_key == previous_key:
                selected_row = row

        dashboard.ui.label2_sa_sois_list_info.setText(
            f"Showing {len(visible_records)} of {len(records)} SOIs"
        )

        if not visible_records:
            clear_sa_sois_selected(dashboard)
            return

        if selected_row < 0:
            selected_row = 0

        table.selectRow(selected_row)
        table.setCurrentCell(selected_row, 0)

        soi_key, soi = visible_records[selected_row]
        populate_sa_sois_selected(dashboard, soi_key, soi)

    finally:
        table.blockSignals(False)
        dashboard.sa_sois_table_refreshing = False


def _set_sa_sois_filter_mode(dashboard, mode):
    """
    Set the active SOI list filter and refresh the table.
    """
    dashboard.sa_sois_filter_mode = mode

    button = dashboard.ui.toolButton_sa_sois_list_search_filter
    label = next((display for display, value in SA_SOI_FILTERS if value == mode), "Filter")
    button.setText(label if mode != "all" else "Filter")
    refresh_sa_sois_table(dashboard, preserve_selection=True)


def initialize_sa_sois_controls(dashboard):
    """
    Initialize SOI table behavior, filters, rich-text panels, and default selection state.
    """
    dashboard.selected_sa_soi_key = None
    dashboard.sa_sois_filter_mode = "all"
    dashboard.signal_analysis_prefill_soi_key = None
    dashboard.sa_sois_table_refreshing = False

    table = dashboard.ui.tableWidget_sa_sois_list
    table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    table.setWordWrap(False)

    table.setColumnCount(3)
    table.setHorizontalHeaderLabels(["Name", "Frequency", "Stage"])

    header = table.horizontalHeader()
    header.setMinimumSectionSize(50)
    header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
    header.setSectionResizeMode(1, QtWidgets.QHeaderView.Fixed)
    header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
    table.setColumnWidth(1, 95)

    table.verticalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)

    dashboard.ui.tabWidget_sa_sois.setCurrentIndex(0)

    for label in [
        dashboard.ui.label_sa_sois_evidence_details,
        dashboard.ui.label_sa_sois_detections_details,
        dashboard.ui.label_sa_sois_analysis_details,
        dashboard.ui.label_sa_sois_history_details,
    ]:
        label.setWordWrap(True)
        label.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
        label.setTextFormat(QtCore.Qt.RichText)
        label.setTextInteractionFlags(QtCore.Qt.TextBrowserInteraction)
        label.setOpenExternalLinks(False)

    record_view = dashboard.ui.plainTextEdit_sa_sois_record_details
    record_view.setReadOnly(True)
    record_view.setLineWrapMode(QtWidgets.QPlainTextEdit.NoWrap)

    filter_button = dashboard.ui.toolButton_sa_sois_list_search_filter
    filter_button.setText("Filter")
    filter_button.setPopupMode(QtWidgets.QToolButton.InstantPopup)

    filter_menu = QtWidgets.QMenu(filter_button)
    filter_group = QtWidgets.QActionGroup(filter_menu)
    filter_group.setExclusive(True)

    for display, mode in SA_SOI_FILTERS:
        action = filter_menu.addAction(display)
        action.setCheckable(True)
        action.setChecked(mode == "all")
        filter_group.addAction(action)
        action.triggered.connect(
            lambda _checked=False, selected_mode=mode: _set_sa_sois_filter_mode(dashboard, selected_mode)
        )

    filter_button.setMenu(filter_menu)
    dashboard.sa_sois_filter_menu = filter_menu
    dashboard.sa_sois_filter_group = filter_group

    dashboard.ui.pushButton_sa_sois_list_merge.setEnabled(False)
    dashboard.ui.pushButton_sa_sois_list_merge.setToolTip(
        "SOI merge will be added after the first Signal Analysis pass."
    )

    clear_sa_sois_selected(dashboard)
    refresh_sa_sois_table(dashboard, preserve_selection=False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_SOIsSearchChanged(dashboard: QtCore.QObject):
    """
    Refresh the SOI table when the search text changes.
    """
    refresh_sa_sois_table(dashboard, preserve_selection=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_SOIsListSelectionChanged(dashboard: QtCore.QObject):
    """
    Populate details for a user-selected SOI and ignore transient rebuild states.
    """
    if getattr(dashboard, "sa_sois_table_refreshing", False):
        return

    soi_key, soi = get_selected_sa_soi(dashboard)

    if not soi_key or not soi:
        if dashboard.ui.tableWidget_sa_sois_list.rowCount() == 0:
            clear_sa_sois_selected(dashboard)
        return

    populate_sa_sois_selected(dashboard, soi_key, soi)


async def _sa_sois_wait_for_dialog(dialog):
    """
    Open a QDialog without starting a nested Qt event loop.
    """
    loop = asyncio.get_running_loop()
    result_future = loop.create_future()

    def _finished(result):
        """
        Resolve the waiting asyncio Future when the Qt dialog finishes.
        """
        if not result_future.done():
            result_future.set_result(result)

    dialog.finished.connect(_finished)
    dialog.open()

    try:
        return await result_future
    finally:
        try:
            dialog.finished.disconnect(_finished)
        except (TypeError, RuntimeError):
            pass


async def _sa_sois_show_editor(dashboard, soi=None):
    """
    Show the qasync-safe Add/Edit SOI editor and prefill existing analyst-editable values.
    """
    soi = soi if isinstance(soi, dict) else {}
    editing = bool(soi)

    dialog = QtWidgets.QDialog(dashboard)
    dialog.setWindowTitle("Edit SOI" if editing else "Add SOI")
    dialog.setWindowModality(QtCore.Qt.WindowModal)
    dialog.resize(500, 520)

    root_layout = QtWidgets.QVBoxLayout(dialog)
    form_layout = QtWidgets.QFormLayout()
    form_layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.AllNonFixedFieldsGrow)

    def add_line(label_text, value=""):
        """
        Add a labeled QLineEdit to the SOI editor form.
        """
        editor = QtWidgets.QLineEdit(dialog)
        editor.setText(str(value if value not in (None, "None") else ""))
        form_layout.addRow(label_text, editor)
        return editor

    name = _sa_sois_value(soi, "name", "label", "title")
    if editing and not name:
        name = _sa_sois_display_name(soi)

    source = _sa_sois_value(soi, "source", "created_by")
    if editing and not source:
        source = soi.get("node_uid", "") or _sa_sois_value(soi, "node_uid")
    elif not editing and not source:
        source = "manual"

    name_edit = add_line("Name:", name)
    frequency_edit = add_line(
        "Frequency (MHz):", _sa_sois_value(soi, "frequency_mhz", "center_frequency_mhz")
    )
    bandwidth_edit = add_line(
        "Bandwidth:", _sa_sois_value(soi, "bandwidth_mhz", "bandwidth_hz", "bandwidth")
    )
    modulation_edit = add_line("Modulation:", _sa_sois_value(soi, "modulation"))
    stage_edit = add_line("Stage:", _sa_sois_stage(soi) or ("MANUAL" if not editing else ""))
    source_edit = add_line("Source:", source)
    classification_edit = add_line(
        "Analyst Classification:", _sa_sois_value(soi, "analyst_classification", "confirmed_classification")
    )
    protocol_edit = add_line(
        "Analyst Protocol:", _sa_sois_value(soi, "analyst_protocol", "confirmed_protocol")
    )
    latitude_edit = add_line("Latitude:", _sa_sois_value(soi, "lat", "latitude"))
    longitude_edit = add_line("Longitude:", _sa_sois_value(soi, "lon", "longitude"))

    notes_edit = QtWidgets.QPlainTextEdit(dialog)
    notes_edit.setPlainText(str(_sa_sois_value(soi, "notes", "description") or ""))
    notes_edit.setMaximumHeight(90)
    form_layout.addRow("Notes:", notes_edit)
    root_layout.addLayout(form_layout)

    buttons = QtWidgets.QDialogButtonBox(
        QtWidgets.QDialogButtonBox.Save | QtWidgets.QDialogButtonBox.Cancel, parent=dialog
    )
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    root_layout.addWidget(buttons)

    def optional_float(editor, field_name):
        """
        Convert an optional editor value to float and raise a friendly validation error when invalid.
        """
        text = editor.text().strip()
        if not text:
            return None

        try:
            return float(text)
        except Exception:
            raise ValueError(f"{field_name} must be numeric.")

    try:
        while True:
            result = await _sa_sois_wait_for_dialog(dialog)
            if result != QtWidgets.QDialog.Accepted:
                return None

            try:
                frequency_mhz = optional_float(frequency_edit, "Frequency")
                latitude = optional_float(latitude_edit, "Latitude")
                longitude = optional_float(longitude_edit, "Longitude")
            except ValueError as error:
                await Qt5.async_ok_dialog(dashboard, str(error))
                continue

            return {
                "name": name_edit.text().strip(),
                "frequency_mhz": frequency_mhz,
                "bandwidth": bandwidth_edit.text().strip(),
                "modulation": modulation_edit.text().strip(),
                "stage": stage_edit.text().strip(),
                "source": source_edit.text().strip(),
                "analyst_classification": classification_edit.text().strip(),
                "analyst_protocol": protocol_edit.text().strip(),
                "lat": latitude,
                "lon": longitude,
                "notes": notes_edit.toPlainText().strip(),
            }
    finally:
        dialog.deleteLater()


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_SOIsAddClicked(dashboard: QtCore.QObject):
    """
    Open the Add SOI editor and submit the new record to HIPRFISR.
    """
    values = await _sa_sois_show_editor(dashboard)
    if values is None:
        return

    soi_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    summary = {
        "name": values["name"],
        "bandwidth": values["bandwidth"],
        "modulation": values["modulation"],
        "stage": values["stage"] or "MANUAL",
        "source": values["source"] or "manual",
        "analyst_classification": values["analyst_classification"],
        "analyst_protocol": values["analyst_protocol"],
        "notes": values["notes"],
    }

    await dashboard.backend.signalAnalysisSoiUpdate(
        node_uid="",
        soi_id=soi_id,
        frequency_mhz=values["frequency_mhz"],
        status="MANUAL",
        summary=summary,
        lat=values["lat"],
        lon=values["lon"],
        observation_time=timestamp,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_SOIsEditClicked(dashboard: QtCore.QObject):
    """
    Open the selected SOI in the editor and submit the updated values.
    """
    soi_key, soi = get_selected_sa_soi(dashboard)
    if not soi_key or not soi:
        return

    values = await _sa_sois_show_editor(dashboard, soi)
    if values is None:
        return

    summary = {
        "name": values["name"],
        "bandwidth": values["bandwidth"],
        "modulation": values["modulation"],
        "stage": values["stage"],
        "source": values["source"],
        "analyst_classification": values["analyst_classification"],
        "analyst_protocol": values["analyst_protocol"],
        "notes": values["notes"],
    }

    await dashboard.backend.signalAnalysisSoiUpdate(
        node_uid=str(soi.get("node_uid", "") or ""),
        soi_id=str(soi.get("soi_id", "") or ""),
        frequency_mhz=values["frequency_mhz"],
        status=str(soi.get("status", "") or ""),
        operation_id=str(soi.get("operation_id", "") or ""),
        artifact_id=str(soi.get("artifact_id", "") or ""),
        summary=summary,
        lat=values["lat"],
        lon=values["lon"],
        observation_time=None,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_SOIsDeleteClicked(dashboard: QtCore.QObject):
    """
    Confirm and delete the selected SOI record without deleting linked artifacts.
    """
    soi_key, soi = get_selected_sa_soi(dashboard)
    if not soi_key or not soi:
        return

    name = _sa_sois_display_name(soi)
    result = await Qt5.async_yes_no_dialog(
        dashboard,
        f"Delete '{name}'?\n\nThis removes the SOI record from HIPRFISR for this session. Linked artifacts are not deleted.",
    )

    if result != QtWidgets.QMessageBox.Yes:
        return

    await dashboard.backend.signalAnalysisSoiDelete(
        soi_key=soi_key,
        node_uid=str(soi.get("node_uid", "") or ""),
        soi_id=str(soi.get("soi_id", "") or ""),
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_SOIsMergeClicked(dashboard: QtCore.QObject):
    """
    Show the current placeholder message for the deferred SOI merge workflow.
    """
    await Qt5.async_ok_dialog(dashboard, "SOI merge is reserved for the next pass.")


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_SOIsRefreshClicked(dashboard: QtCore.QObject):
    """
    Request the latest SOI store from HIPRFISR while preventing duplicate refresh clicks.
    """
    dashboard.ui.pushButton_sa_sois_list_refresh.setEnabled(False)

    try:
        await dashboard.backend.signalAnalysisSoisRefresh()
    finally:
        dashboard.ui.pushButton_sa_sois_list_refresh.setEnabled(True)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_SOIsPromoteToTargetClicked(dashboard: QtCore.QObject):
    """
    Reuse the Tactical SOI promotion workflow for the selected Signal Analysis SOI.
    """
    soi_key, _soi = get_selected_sa_soi(dashboard)
    if not soi_key:
        return

    from fissure.Dashboard.Slots import TacticalTabSlots

    previous_key = getattr(dashboard, "selected_tactical_node_soi_id", None)

    try:
        dashboard.selected_tactical_node_soi_id = soi_key
        await TacticalTabSlots._slotTacticalNodeSoiPromoteToTargetClicked(dashboard)
    finally:
        dashboard.selected_tactical_node_soi_id = previous_key


@QtCore.pyqtSlot(QtCore.QObject, str)
def _slotSA_SOIsWorkflowClicked(dashboard: QtCore.QObject, destination: str):
    """
    Open the requested Signal Analysis workspace and remember the SOI to prefill there.
    """
    soi_key, _soi = get_selected_sa_soi(dashboard)
    if not soi_key:
        return

    dashboard.signal_analysis_prefill_soi_key = soi_key

    pages = {
        "capture": dashboard.ui.tab_capture,
        "inspection": dashboard.ui.tab_inspection,
        "classifier": dashboard.ui.tab_tsi_classifier,
        "protocol_discovery": dashboard.ui.tab_protocol_discovery,
        "direction_finding": dashboard.ui.tab_direction_finding,
    }

    page = pages.get(destination)
    if page is not None:
        dashboard.ui.tabWidget_signal_analysis.setCurrentWidget(page)


@qasync.asyncSlot(QtCore.QObject, str)
async def _slotSA_SOIsEvidenceLinkActivated(dashboard: QtCore.QObject, link: str):
    """
    Open linked artifacts or build the selected SOI's complete evidence folder.
    """
    link = str(link or "")

    if link.startswith("artifact:"):
        artifact_id = link.split(":", 1)[1].strip()
        if not artifact_id:
            return

        try:
            await dashboard.backend.requestDashboardArtifactDownload(artifact_id, open_when_complete=True)
        except Exception as error:
            await Qt5.async_ok_dialog(dashboard, f"Unable to open artifact.\n\n{error}")

        return

    if link.startswith("soi-evidence:"):
        soi_key = link.split(":", 1)[1].strip()
        soi = (getattr(dashboard, "tactical_sois", {}) or {}).get(soi_key)

        if not isinstance(soi, dict) or not soi:
            return

        try:
            await build_soi_evidence_folder(dashboard, soi)
        except Exception as error:
            await Qt5.async_ok_dialog(dashboard, f"Unable to prepare the evidence folder.\n\n{error}")


__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value) and value.__module__ == __name__
]
