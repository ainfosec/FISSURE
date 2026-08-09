#!/usr/bin/env python3

import json
import xml.etree.ElementTree as ET
from fissure.Dashboard.Slots import (
    TacticalTabSlots,
    IQDataTabSlots,
    TSITabSlots,
)

# ---------------------------------------------------------
# CoT Parsing
# ---------------------------------------------------------

def parse_cot_xml(raw_xml):
    if raw_xml is None:
        return None

    if isinstance(raw_xml, bytes):
        raw_xml = raw_xml.decode(
            "utf-8"
        )

    root = ET.fromstring(raw_xml)

    cot_message = {
        "kind": "unknown",

        "uid": root.get("uid"),
        "cot_type": root.get("type"),
        "time": root.get("time"),
        "start": root.get("start"),
        "stale": root.get("stale"),
        "how": root.get("how"),
        "access": root.get("access"),

        "lat": None,
        "lon": None,
        "hae": None,
        "ce": None,
        "le": None,

        "callsign": None,

        "node_status": None,
        "node_version": None,

        "alert_kind": None,
        "alert_summary": None,

        "detection_node_uid": None,
        "detection_frequency_hz": None,
        "detection_power_dbm": None,
        "detection_timestamp": None,
        "detection_detector": None,
        "detection_opid": None,

        "target_id": None,
        "target_label": None,
        "target_state": None,
        "target_frequency_mhz": None,
        "target_geolocation_status": None,
        "target_identity": {},
        "target_artifact_ids": [],
        "target_artifact_links": [],
        "target_history": [],
        "node_uid": None,
        "ssid": None,
        "bssid": None,
        "rssi_dbm": None,
        "last_observation_time": None,
        "source_soi_id": None,

        "soi_node_uid": None,
        "soi_id": None,
        "soi_frequency_mhz": None,
        "soi_status": None,
        "soi_operation_id": None,
        "soi_artifact_id": None,
        "soi_database_classification": None,
        "soi_model_classification": None,
        "soi_model_confidence": None,
        "soi_stage": None,
        "soi_stage_order": None,

        "artifact_name": None,
        "artifact_timestamp": None,
        "artifact_id": None,
        "artifact_operation_id": None,
        "artifact_node_uid": None,

        "raw_xml": raw_xml,
    }

    point = root.find("point")

    if point is not None:
        cot_message["lat"] = _safe_float(
            point.get("lat")
        )
        cot_message["lon"] = _safe_float(
            point.get("lon")
        )
        cot_message["hae"] = _safe_float(
            point.get("hae")
        )
        cot_message["ce"] = _safe_float(
            point.get("ce")
        )
        cot_message["le"] = _safe_float(
            point.get("le")
        )

    detail = root.find("detail")

    if detail is not None:
        contact = detail.find("contact")

        if contact is not None:
            cot_message["callsign"] = (
                contact.get("callsign")
            )

        # -----------------------------------------------------------------
        # Node
        # -----------------------------------------------------------------
        fissure_node = detail.find(
            "./fissure/node"
        )

        if fissure_node is not None:
            cot_message["kind"] = "node"
            cot_message["node_status"] = (
                fissure_node.findtext(
                    "status"
                )
            )
            cot_message["node_version"] = (
                fissure_node.findtext(
                    "version"
                )
            )

        # -----------------------------------------------------------------
        # Alert
        # -----------------------------------------------------------------
        fissure_alert = detail.find(
            "./fissure/alert"
        )

        if fissure_alert is not None:
            cot_message["kind"] = "alert"
            cot_message["alert_kind"] = (
                fissure_alert.findtext(
                    "kind"
                )
            )
            cot_message["alert_summary"] = (
                fissure_alert.findtext(
                    "summary"
                )
            )

        # -----------------------------------------------------------------
        # Detection
        # -----------------------------------------------------------------
        fissure_detection = detail.find(
            "./fissure/detection"
        )

        if fissure_detection is not None:
            cot_message["kind"] = (
                "detection"
            )
            cot_message[
                "detection_node_uid"
            ] = fissure_detection.findtext(
                "node_uid"
            )
            cot_message[
                "detection_frequency_hz"
            ] = fissure_detection.findtext(
                "frequency_hz"
            )
            cot_message[
                "detection_power_dbm"
            ] = fissure_detection.findtext(
                "power_dbm"
            )
            cot_message[
                "detection_timestamp"
            ] = fissure_detection.findtext(
                "timestamp"
            )
            cot_message[
                "detection_detector"
            ] = fissure_detection.findtext(
                "detector"
            )
            cot_message[
                "detection_opid"
            ] = fissure_detection.findtext(
                "opid"
            )

        # -----------------------------------------------------------------
        # Target
        # -----------------------------------------------------------------
        fissure_target = detail.find(
            "./fissure/target"
        )

        if fissure_target is not None:
            cot_message["kind"] = "target"

            cot_message["target_id"] = (
                fissure_target.findtext(
                    "target_id"
                )
            )
            cot_message["target_label"] = (
                fissure_target.findtext(
                    "display_label"
                )
            )
            cot_message["target_state"] = (
                fissure_target.findtext(
                    "state"
                )
            )

            cot_message["node_uid"] = (
                fissure_target.findtext(
                    "node_uid"
                )
            )
            cot_message["ssid"] = (
                fissure_target.findtext(
                    "ssid"
                )
            )
            cot_message["bssid"] = (
                fissure_target.findtext(
                    "bssid"
                )
            )
            cot_message["rssi_dbm"] = (
                fissure_target.findtext(
                    "rssi_dbm"
                )
            )
            cot_message[
                "last_observation_time"
            ] = fissure_target.findtext(
                "last_observation_time"
            )
            cot_message["source_soi_id"] = (
                fissure_target.findtext(
                    "source_soi_id"
                )
            )

            cot_message[
                "target_geolocation_status"
            ] = (
                fissure_target.findtext(
                    "geolocation_status"
                )
                or fissure_target.findtext(
                    "geolocate_status"
                )
            )

            cot_message[
                "target_frequency_mhz"
            ] = (
                fissure_target.findtext(
                    "frequency_mhz"
                )
                or fissure_target.findtext(
                    "target_frequency_mhz"
                )
            )

            target_json_fields = (
                (
                    "identity_json",
                    "target_identity",
                    {},
                ),
                (
                    "artifact_ids_json",
                    "target_artifact_ids",
                    [],
                ),
                (
                    "artifact_links_json",
                    "target_artifact_links",
                    [],
                ),
                (
                    "history_json",
                    "target_history",
                    [],
                ),
            )

            for (
                xml_field,
                message_field,
                fallback,
            ) in target_json_fields:
                field_text = (
                    fissure_target.findtext(
                        xml_field
                    )
                )

                if not field_text:
                    cot_message[
                        message_field
                    ] = fallback
                    continue

                try:
                    parsed_value = json.loads(
                        field_text
                    )
                except Exception:
                    parsed_value = fallback

                cot_message[
                    message_field
                ] = parsed_value

            target_lat = _safe_float(
                fissure_target.findtext(
                    "lat"
                )
            )
            target_lon = _safe_float(
                fissure_target.findtext(
                    "lon"
                )
            )
            target_hae = _safe_float(
                fissure_target.findtext(
                    "hae_m"
                )
            )
            target_ce = _safe_float(
                fissure_target.findtext(
                    "ce_m"
                )
            )

            if target_lat is not None:
                cot_message["lat"] = (
                    target_lat
                )

            if target_lon is not None:
                cot_message["lon"] = (
                    target_lon
                )

            if target_hae is not None:
                cot_message["hae"] = (
                    target_hae
                )

            if target_ce is not None:
                cot_message["ce"] = (
                    target_ce
                )

        # -----------------------------------------------------------------
        # SOI
        # -----------------------------------------------------------------
        fissure_soi = detail.find(
            "./fissure/soi"
        )

        if fissure_soi is not None:
            cot_message["kind"] = "soi"

            cot_message["soi_node_uid"] = (
                fissure_soi.findtext(
                    "node_uid"
                )
            )
            cot_message["soi_id"] = (
                fissure_soi.findtext(
                    "soi_id"
                )
            )
            cot_message[
                "soi_frequency_mhz"
            ] = fissure_soi.findtext(
                "frequency_mhz"
            )
            cot_message["soi_status"] = (
                fissure_soi.findtext(
                    "status"
                )
            )
            cot_message[
                "soi_operation_id"
            ] = fissure_soi.findtext(
                "operation_id"
            )
            cot_message[
                "soi_artifact_id"
            ] = fissure_soi.findtext(
                "artifact_id"
            )
            cot_message[
                "soi_database_classification"
            ] = fissure_soi.findtext(
                "database_classification"
            )
            cot_message[
                "soi_model_classification"
            ] = fissure_soi.findtext(
                "model_classification"
            )
            cot_message[
                "soi_model_confidence"
            ] = fissure_soi.findtext(
                "model_confidence"
            )
            cot_message["soi_stage"] = (
                fissure_soi.findtext(
                    "stage"
                )
            )

            stage_order_text = (
                fissure_soi.findtext(
                    "stage_order"
                )
            )

            try:
                cot_message[
                    "soi_stage_order"
                ] = int(stage_order_text)
            except (
                TypeError,
                ValueError,
            ):
                cot_message[
                    "soi_stage_order"
                ] = None

        # -----------------------------------------------------------------
        # Artifact Metadata
        # -----------------------------------------------------------------
        fissure_artifact = detail.find(
            "./fissure/artifact_metadata"
        )

        if fissure_artifact is not None:
            name_text = (
                fissure_artifact.findtext(
                    "name"
                )
            )
            timestamp_text = (
                fissure_artifact.findtext(
                    "timestamp"
                )
            )
            artifact_id = (
                fissure_artifact.findtext(
                    "artid"
                )
            )

            if (
                name_text
                and timestamp_text
                and artifact_id
            ):
                cot_message["kind"] = (
                    "artifact"
                )
                cot_message[
                    "artifact_name"
                ] = name_text
                cot_message[
                    "artifact_timestamp"
                ] = timestamp_text
                cot_message[
                    "artifact_id"
                ] = artifact_id
                cot_message[
                    "artifact_operation_id"
                ] = (
                    fissure_artifact.findtext(
                        "operation_id"
                    )
                )
                cot_message[
                    "artifact_node_uid"
                ] = (
                    fissure_artifact.findtext(
                        "source_id"
                    )
                )

    return cot_message


def _safe_float(value):
    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------
# CoT → Tactical Records
# ---------------------------------------------------------

def cot_to_tactical_node_record(cot_message):
    if not cot_message:
        return None

    uid = cot_message.get("uid")
    if not uid:
        return None

    return {
        "uid": uid,
        "callsign": cot_message.get("callsign") or uid,
        "status": cot_message.get("node_status") or "",
        "version": cot_message.get("node_version") or "",

        "lat": cot_message.get("lat"),
        "lon": cot_message.get("lon"),
        "hae": cot_message.get("hae"),
        "ce": cot_message.get("ce"),
        "le": cot_message.get("le"),

        "time": cot_message.get("time"),
        "start": cot_message.get("start"),
        "stale": cot_message.get("stale"),
        "cot_type": cot_message.get("cot_type"),
        "how": cot_message.get("how"),

        "raw": cot_message,
    }


def cot_to_tactical_alert_record(cot_message):
    if not cot_message:
        return None

    uid = cot_message.get("uid")
    if not uid:
        return None

    return {
        "uid": uid,
        "type": cot_message.get("alert_kind") or "",
        "cot_type": cot_message.get("cot_type") or "",
        "time": cot_message.get("time") or "",
        "summary": cot_message.get("alert_summary") or "",
        "callsign": cot_message.get("callsign") or uid,
        "lat": cot_message.get("lat"),
        "lon": cot_message.get("lon"),
        "raw_xml": cot_message.get("raw_xml"),
    }


def cot_to_tactical_detection_record(cot_message):
    if not cot_message:
        return None

    uid = cot_message.get("uid")
    if not uid:
        return None

    freq_hz = _safe_float(cot_message.get("detection_frequency_hz"))
    power_dbm = _safe_float(cot_message.get("detection_power_dbm"))

    frequency_display = ""
    if freq_hz is not None:
        frequency_display = f"{freq_hz / 1e6:.3f}"

    power_display = ""
    if power_dbm is not None:
        power_display = f"{power_dbm:.1f}"

    timestamp = (
        cot_message.get("detection_timestamp")
        or cot_message.get("time")
        or ""
    )

    return {
        "uid": uid,
        "node_uid": cot_message.get("detection_node_uid") or "",
        "frequency": frequency_display,
        "power": power_display,
        "time": timestamp,
        "detector": cot_message.get("detection_detector") or "",
        "operation_id": cot_message.get("detection_opid") or "",
        "event_uid": uid,
        "raw_xml": cot_message.get("raw_xml"),

        "lat": cot_message.get("lat"),
        "lon": cot_message.get("lon"),
        "hae": cot_message.get("hae"),
    }


# ---------------------------------------------------------
# Tactical CoT Handling
# ---------------------------------------------------------

def handle_tactical_cot_message(dashboard, cot_message):
    if not cot_message:
        return

    kind = cot_message.get("kind")

    if kind == "node":
        handle_tactical_node_message(dashboard, cot_message)
    elif kind == "target":
        handle_tactical_target_message(dashboard, cot_message)
    elif kind == "alert":
        handle_tactical_alert_message(dashboard, cot_message)
    elif kind == "detection":
        handle_tactical_detection_message(dashboard, cot_message)
    elif kind == "soi":
        handle_tactical_soi_message(dashboard, cot_message)
    elif kind == "artifact":
        handle_tactical_artifact_message(dashboard, cot_message)
    elif _cot_has_fissure_event(cot_message, "plugin_list"):
        handle_tactical_plugin_list_message(dashboard, cot_message)
    elif _cot_has_fissure_event(cot_message, "plugin_actions"):
        handle_tactical_plugin_actions_message(dashboard, cot_message)     
    elif _cot_has_fissure_event(cot_message, "plugin_action_schema"):
        handle_tactical_action_customize_message(dashboard, cot_message)     
    elif _cot_has_fissure_event(cot_message, "ecosystem_plugin_list"):
        handle_tactical_ecosystem_plugin_list_message(dashboard, cot_message)
    elif _cot_has_fissure_event(cot_message, "ecosystem_plugin_actions"):
        handle_tactical_ecosystem_plugin_actions_message(dashboard, cot_message)
    elif _cot_has_fissure_event(cot_message, "ecosystem_plugin_action_schema"):
        handle_tactical_ecosystem_customize_message(dashboard, cot_message)
    else:
        dashboard.logger.debug(
            f"Unhandled tactical CoT message type: {cot_message.get('cot_type')}"
        )


def _cot_has_fissure_event(cot_message, event_type):
    raw_xml = cot_message.get("raw_xml")
    if not raw_xml:
        return False

    try:
        root = ET.fromstring(raw_xml)
        return root.find(f".//fissure/{event_type}") is not None
    except Exception:
        return False
    

def handle_tactical_node_message(dashboard, cot_message):
    frontend = dashboard.frontend

    node_record = cot_to_tactical_node_record(cot_message)
    if not node_record:
        return

    if not hasattr(frontend, "tactical_nodes"):
        frontend.tactical_nodes = {}

    uid = node_record["uid"]
    frontend.tactical_nodes[uid] = node_record

    lat = node_record.get("lat")
    lon = node_record.get("lon")
    label = node_record.get("callsign") or uid

    if lat is not None and lon is not None:
        frontend.tactical_map.add_node(
            node_id=uid,
            lat=lat,
            lon=lon,
            label=label,
            active=is_tactical_node_active(node_record),
            status=node_record.get("status", ""),
        )

    TacticalTabSlots.update_tactical_node_roster_row(
        frontend,
        node_record,
    )

    try:
        TSITabSlots.update_tsi_sweep_detector_status_from_selected_node(
            frontend,
            node_uid=uid,
            status=node_record.get("status", ""),
        )
    except Exception as e:
        frontend.logger.debug(
            f"Could not update TSI Sweep detector status from CoT node message: {e}"
        )


def handle_tactical_target_message(dashboard, cot_message):
    frontend = dashboard.frontend

    target_record = cot_to_tactical_target_record(cot_message)
    if not target_record:
        return

    if not hasattr(frontend, "tactical_targets"):
        frontend.tactical_targets = {}

    if not hasattr(frontend, "selected_tactical_target_id"):
        frontend.selected_tactical_target_id = None

    target_id = target_record["target_id"]

    is_new_target = target_id not in frontend.tactical_targets

    frontend.tactical_targets[target_id] = target_record

    TacticalTabSlots.update_tactical_target_row(
        frontend,
        target_record,
    )

    if (
        is_new_target
        and frontend.ui.checkBox_tactical_targets_show_new_targets.isChecked()
    ):
        TacticalTabSlots.plot_tactical_target(
            frontend,
            target_record,
            zoom=False,
        )

    if frontend.selected_tactical_target_id == target_id:
        TacticalTabSlots._slotTacticalTargetsRowSelectionChanged(frontend)


def cot_to_tactical_target_record(
    cot_message,
):
    target_id = cot_message.get(
        "target_id"
    )

    if not target_id:
        return None

    identity = cot_message.get(
        "target_identity",
        {},
    )

    if not isinstance(
        identity,
        dict,
    ):
        identity = {}

    artifact_ids = cot_message.get(
        "target_artifact_ids",
        [],
    )

    if not isinstance(
        artifact_ids,
        list,
    ):
        artifact_ids = []

    artifact_links = cot_message.get(
        "target_artifact_links",
        [],
    )

    if not isinstance(
        artifact_links,
        list,
    ):
        artifact_links = []

    history = cot_message.get(
        "target_history",
        [],
    )

    if not isinstance(
        history,
        list,
    ):
        history = []

    latest_artifact_id = str(
        cot_message.get(
            "artifact_id",
            "",
        )
        or ""
    ).strip()

    if (
        latest_artifact_id
        and latest_artifact_id
        not in artifact_ids
    ):
        artifact_ids.append(
            latest_artifact_id
        )

    return {
        "uid":
            cot_message.get("uid"),
        "target_id":
            target_id,

        "type": (
            cot_message.get(
                "target_label"
            )
            or cot_message.get(
                "display_label"
            )
            or cot_message.get(
                "target_frequency_mhz"
            )
            or "Unknown"
        ),
        "display_label": (
            cot_message.get(
                "target_label"
            )
            or cot_message.get(
                "display_label"
            )
            or ""
        ),
        "state":
            cot_message.get(
                "target_state",
                "",
            ),
        "updated":
            cot_message.get(
                "time",
                "",
            ),

        "lat":
            cot_message.get("lat"),
        "lon":
            cot_message.get("lon"),
        "ce_m":
            cot_message.get("ce"),
        "hae_m":
            cot_message.get("hae"),

        "node_uid":
            cot_message.get(
                "node_uid",
                "",
            ),
        "ssid":
            cot_message.get(
                "ssid",
                "",
            ),
        "bssid":
            cot_message.get(
                "bssid",
                "",
            ),
        "rssi_dbm":
            cot_message.get(
                "rssi_dbm",
                "",
            ),
        "last_observation_time":
            cot_message.get(
                "last_observation_time",
                "",
            ),
        "geolocation_status": (
            cot_message.get(
                "target_geolocation_status"
            )
            or "idle"
        ),

        "target_frequency_mhz":
            cot_message.get(
                "target_frequency_mhz"
            ),
        "source_soi_id":
            cot_message.get(
                "source_soi_id",
                "",
            ),

        "identity":
            identity,
        "artifact_id":
            latest_artifact_id,
        "artifact_ids":
            artifact_ids,
        "artifact_links":
            artifact_links,
        "history":
            history,

        "raw_xml":
            cot_message.get(
                "raw_xml"
            ),
    }


def handle_tactical_alert_message(dashboard, cot_message):
    frontend = dashboard.frontend

    alert_record = cot_to_tactical_alert_record(cot_message)
    if not alert_record:
        return

    if not hasattr(frontend, "tactical_alerts"):
        frontend.tactical_alerts = {}

    uid = alert_record["uid"]
    frontend.tactical_alerts[uid] = alert_record

    lat = alert_record.get("lat")
    lon = alert_record.get("lon")
    label = alert_record.get("type") or alert_record.get("callsign") or uid

    cot_type = alert_record.get("cot_type") or ""
    auto_plot = str(cot_type).startswith("a-h-G-E-S")

    if auto_plot and lat is not None and lon is not None:
        frontend.tactical_map.add_alert(
            alert_id=uid,
            lat=lat,
            lon=lon,
            label=label,
        )

    TacticalTabSlots.update_tactical_alert_row(
        frontend,
        alert_record,
    )


def handle_tactical_plugin_list_message(dashboard, cot_message):
    raw_xml = cot_message.get("raw_xml")
    if not raw_xml:
        return

    try:
        root = ET.fromstring(raw_xml)

        plugin_list_node = root.find(".//fissure/plugin_list")
        if plugin_list_node is None:
            return

        plugin_names = [
            plugin_node.text
            for plugin_node in plugin_list_node.findall("plugin")
            if plugin_node.text
        ]

        event_type_node = root.find(".//fissure/event_type")

        event_type = (
            event_type_node.text.strip()
            if event_type_node is not None and event_type_node.text
            else "plugin_list"
        )

        node_uid = (
            dashboard.frontend.ui.label2_tactical_node_uuid.text().strip()
        )

        if node_uid:
            if not hasattr(dashboard.frontend, "tactical_nodes"):
                dashboard.frontend.tactical_nodes = {}

            node = dashboard.frontend.tactical_nodes.setdefault(
                node_uid,
                {"uid": node_uid},
            )

            node["plugins"] = plugin_names

        TacticalTabSlots.update_tactical_node_plugin_combo(
            dashboard.frontend,
            plugin_names,
        )

    except Exception as e:
        dashboard.logger.error(
            f"Failed to parse tactical plugin list: {e}"
        )


def handle_tactical_ecosystem_plugin_list_message(
    dashboard,
    cot_message,
):
    raw_xml = cot_message.get("raw_xml")
    if not raw_xml:
        return

    try:
        root = ET.fromstring(raw_xml)

        plugin_list_node = root.find(
            ".//fissure/ecosystem_plugin_list"
        )

        if plugin_list_node is None:
            return

        plugin_names = [
            plugin_node.text
            for plugin_node in plugin_list_node.findall("plugin")
            if plugin_node.text
        ]

        TacticalTabSlots.update_tactical_ecosystem_plugin_combo(
            dashboard.frontend,
            plugin_names,
        )

    except Exception as e:
        dashboard.logger.error(
            f"Failed to parse tactical ecosystem plugin list: {e}"
        )


def handle_tactical_ecosystem_plugin_actions_message(
    dashboard,
    cot_message,
):
    raw_xml = cot_message.get("raw_xml")
    if not raw_xml:
        return

    try:
        root = ET.fromstring(raw_xml)

        actions_node = root.find(
            ".//fissure/ecosystem_plugin_actions"
        )

        if actions_node is None:
            return

        plugin_name_node = actions_node.find("plugin_name")

        plugin_name = (
            plugin_name_node.text
            if plugin_name_node is not None
            else ""
        )

        action_names = [
            action_node.text
            for action_node in actions_node.findall("action")
            if action_node.text
        ]

        dashboard.frontend.tactical_ecosystem_plugin_actions = action_names

        TacticalTabSlots.update_tactical_ecosystem_action_combo(
            dashboard.frontend,
            action_names,
        )

        dashboard.logger.debug(
            f"Updated ecosystem plugin actions for '{plugin_name}': {action_names}"
        )

    except Exception as e:
        dashboard.logger.error(
            f"Failed to parse tactical ecosystem plugin actions: {e}"
        )


def handle_tactical_plugin_actions_message(dashboard, cot_message):
    raw_xml = cot_message.get("raw_xml")
    if not raw_xml:
        return

    try:
        root = ET.fromstring(raw_xml)

        actions_node = root.find(".//fissure/plugin_actions")
        if actions_node is None:
            return

        plugin_name_node = actions_node.find("plugin_name")

        plugin_name = (
            plugin_name_node.text
            if plugin_name_node is not None
            else ""
        )

        action_names = [
            action_node.text
            for action_node in actions_node.findall("action")
            if action_node.text
        ]

        node_uid = (
            dashboard.frontend.ui.label2_tactical_node_uuid.text().strip()
        )

        if node_uid:
            if not hasattr(dashboard.frontend, "tactical_nodes"):
                dashboard.frontend.tactical_nodes = {}

            node = dashboard.frontend.tactical_nodes.setdefault(
                node_uid,
                {"uid": node_uid},
            )

            actions = node.setdefault("actions", {})
            actions[plugin_name] = action_names

        dashboard.frontend.tactical_plugin_actions = action_names

        TacticalTabSlots.update_tactical_node_action_combo(
            dashboard.frontend,
            action_names,
        )

        dashboard.logger.debug(
            f"Updated plugin actions for '{plugin_name}': {action_names}"
        )

    except Exception as e:
        dashboard.logger.error(
            f"Failed to parse tactical plugin actions: {e}"
        )


def handle_tactical_action_customize_message(dashboard, cot_message):
    raw_xml = cot_message.get("raw_xml")
    if not raw_xml:
        return

    try:
        root = ET.fromstring(raw_xml)

        schema_node = root.find(".//fissure/plugin_action_schema")
        if schema_node is None:
            return

        plugin_name = schema_node.findtext("plugin_name", default="")
        action_name = schema_node.findtext("action_name", default="")
        node_uid = schema_node.findtext("node_uid", default="")

        parameters = []

        schema_root = schema_node.find("schema")
        if schema_root is not None:
            for param_node in schema_root.findall("param"):
                param = {
                    "name": param_node.findtext("name", default=""),
                    "label": param_node.findtext("label", default=""),
                    "type": param_node.findtext("type", default="string"),
                    "default": param_node.findtext("default", default=""),
                    "options": [
                        option_node.text
                        for option_node in param_node.findall("option")
                        if option_node.text
                    ],
                }

                if param["name"]:
                    parameters.append(param)

        TacticalTabSlots.update_tactical_node_action_parameters(
            dashboard.frontend,
            plugin_name,
            action_name,
            parameters,
        )

        dashboard.logger.debug(
            f"Updated action schema for plugin='{plugin_name}', "
            f"action='{action_name}', parameters={parameters}"
        )

    except Exception as e:
        dashboard.logger.error(
            f"Failed to parse tactical action customize schema: {e}"
        )


def handle_tactical_ecosystem_customize_message(
    dashboard,
    cot_message,
):
    raw_xml = cot_message.get("raw_xml")
    if not raw_xml:
        return

    try:
        root = ET.fromstring(raw_xml)

        schema_node = root.find(".//fissure/ecosystem_plugin_action_schema")
        if schema_node is None:
            return

        plugin_name = schema_node.findtext("plugin_name", default="")
        action_name = schema_node.findtext("action_name", default="")
        node_uid = schema_node.findtext("node_uid", default="")

        parameters = []

        schema_root = schema_node.find("schema")
        if schema_root is not None:
            for param_node in schema_root.findall("param"):
                param = {
                    "name": param_node.findtext("name", default=""),
                    "label": param_node.findtext("label", default=""),
                    "type": param_node.findtext("type", default="string"),
                    "default": param_node.findtext("default", default=""),
                    "options": [
                        option_node.text
                        for option_node in param_node.findall("option")
                        if option_node.text
                    ],
                }

                if param["name"]:
                    parameters.append(param)

        TacticalTabSlots.update_tactical_ecosystem_action_parameters(
            dashboard.frontend,
            plugin_name,
            action_name,
            parameters,
        )

        dashboard.logger.debug(
            f"Updated ecosystem action schema for plugin='{plugin_name}', "
            f"action='{action_name}', node_uid='{node_uid}', parameters={parameters}"
        )

    except Exception as e:
        dashboard.logger.error(
            f"Failed to parse tactical ecosystem action schema: {e}"
        )


def handle_tactical_detection_message(dashboard, cot_message):
    frontend = dashboard.frontend

    detection_record = cot_to_tactical_detection_record(cot_message)
    if not detection_record:
        return

    if not hasattr(frontend, "tactical_detections"):
        frontend.tactical_detections = {}

    uid = detection_record["uid"]
    frontend.tactical_detections[uid] = detection_record

    selected_node_uid = getattr(frontend, "selected_tactical_node_uid", None)
    detection_node_uid = detection_record.get("node_uid")

    if not selected_node_uid:
        return

    if detection_node_uid != selected_node_uid:
        return

    TacticalTabSlots.update_tactical_detection_row(
        frontend,
        detection_record,
    )


def handle_tactical_soi_message(dashboard, cot_message):
    frontend = dashboard.frontend

    soi_record = cot_to_tactical_soi_record(cot_message)
    if not soi_record:
        return

    if not hasattr(frontend, "tactical_sois"):
        frontend.tactical_sois = {}

    soi_key = soi_record["soi_key"]

    existing = frontend.tactical_sois.get(soi_key)
    if existing:
        new_stage_order = soi_record.get("stage_order")
        old_stage_order = existing.get("stage_order")

        if (
            new_stage_order is not None
            and old_stage_order is not None
            and new_stage_order < old_stage_order
        ):
            frontend.logger.info(
                f"Ignoring out-of-order SOI update: new={new_stage_order} < old={old_stage_order}"
            )
            return

    frontend.tactical_sois[soi_key] = soi_record

    selected_node_uid = getattr(frontend, "selected_tactical_node_uid", None)
    soi_node_uid = soi_record.get("node_uid")

    if not selected_node_uid:
        return

    if soi_node_uid != selected_node_uid:
        return

    TacticalTabSlots.update_tactical_node_soi_row(
        frontend,
        soi_record,
    )


def cot_to_tactical_soi_record(cot_message):
    node_uid = cot_message.get("soi_node_uid", "")
    soi_id = cot_message.get("soi_id", "")

    if not soi_id:
        return None

    soi_key = f"{node_uid}:{soi_id}"

    frequency_mhz = cot_message.get("soi_frequency_mhz")

    frequency_display = ""
    if frequency_mhz not in [None, "", "None"]:
        try:
            frequency_display = f"{float(frequency_mhz):.3f} MHz"
        except Exception:
            frequency_display = str(frequency_mhz)

    model_classification = cot_message.get("soi_model_classification", "")
    model_confidence = cot_message.get("soi_model_confidence", "")

    model_display = model_classification
    if model_classification and model_confidence not in [None, "", "None"]:
        model_display = f"{model_classification} ({model_confidence}%)"

    return {
        "soi_key": soi_key,
        "uid": cot_message.get("uid"),
        "event_id": cot_message.get("uid"),

        "node_uid": node_uid,
        "soi_id": soi_id,
        "operation_id": cot_message.get("soi_operation_id", ""),
        "artifact_id": cot_message.get("soi_artifact_id", ""),

        "frequency_mhz": frequency_mhz,
        "frequency_display": frequency_display,
        "status": cot_message.get("soi_status", ""),
        "time": cot_message.get("time", ""),

        "stage": cot_message.get("soi_stage", ""),
        "stage_order": cot_message.get("soi_stage_order"),

        "model_classification": model_classification,
        "model_confidence_pct": model_confidence,
        "model_classification_display": model_display,
        "database_classification": cot_message.get("soi_database_classification", ""),

        "lat": cot_message.get("lat"),
        "lon": cot_message.get("lon"),
        "hae_m": cot_message.get("hae"),

        "raw_xml": cot_message.get("raw_xml"),
    }


def handle_tactical_artifact_message(dashboard, cot_message):
    """
    Handle the lightweight artifact CoT notification without replacing the
    canonical manifest record delivered by sendArtifactsListTakReturn.

    CoT contains only summary fields. If a complete artifact record already
    exists, preserve its files, relations, file_count, total_size, metadata,
    and timestamps while applying only non-empty CoT summary values.
    """
    frontend = dashboard.frontend

    cot_record = cot_to_tactical_artifact_record(cot_message)
    if not cot_record:
        return

    if not hasattr(frontend, "tactical_artifacts"):
        frontend.tactical_artifacts = {}

    artifact_id = cot_record["artifact_id"]

    existing = frontend.tactical_artifacts.get(artifact_id)

    if isinstance(existing, dict):
        artifact_record = dict(existing)

        for key, value in cot_record.items():
            if value not in [None, "", "None"]:
                artifact_record[key] = value
    else:
        artifact_record = cot_record

    frontend.tactical_artifacts[artifact_id] = artifact_record

    selected_node_uid = getattr(
        frontend,
        "selected_tactical_node_uid",
        None,
    )
    artifact_node_uid = (
        artifact_record.get("source_id")
        or artifact_record.get("node_uid")
        or ""
    )

    if (
        selected_node_uid
        and artifact_node_uid == selected_node_uid
    ):
        TacticalTabSlots.update_tactical_node_artifact_row(
            frontend,
            artifact_record,
        )

        selected_artifact_id = getattr(
            frontend,
            "selected_tactical_node_artifact_id",
            None,
        )

        if selected_artifact_id == artifact_id:
            TacticalTabSlots.populate_tactical_node_artifact_details(
                frontend,
                artifact_record,
            )

    IQDataTabSlots.handle_iq_record_artifact_complete(
        frontend,
        artifact_record,
    )


def cot_to_tactical_artifact_record(cot_message):
    artifact_id = cot_message.get("artifact_id")
    name = cot_message.get("artifact_name")
    timestamp = cot_message.get("artifact_timestamp")

    if not artifact_id or not name or not timestamp:
        return None

    return {
        "artifact_id": artifact_id,
        "node_uid": cot_message.get("artifact_node_uid") or "",
        "operation_id": cot_message.get("artifact_operation_id", ""),
        "name": name,
        "time": timestamp,
    }


def is_tactical_node_active(node_record):
    status = (node_record.get("status") or "").strip().lower()

    return status not in [
        "",
        "idle",
        "stopped",
        "unknown",
        "disconnected",
    ]