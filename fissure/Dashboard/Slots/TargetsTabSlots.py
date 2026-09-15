import html
import json
import os

import qasync
from PyQt5 import QtCore, QtGui, QtWidgets

import fissure.utils

from fissure.Dashboard.TargetDataController import build_target_data_folder
from fissure.Dashboard.Slots import TacticalTabSlots, SingleActionTabSlots


def initialize_targets_tab(dashboard: QtCore.QObject):
    """Initialize the Targets workspace and shared Targets & Actions context."""
    dashboard.selected_targets_actions_target_id = None
    dashboard.pending_targets_actions_target_id = None
    dashboard.selected_target_recommendation_id = None
    dashboard.targets_geolocation_observations = {}

    table = dashboard.ui.tableWidget1_ta_targets
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    table.horizontalHeader().setStretchLastSection(True)

    refresh_icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", "refresh.png")
    if os.path.isfile(refresh_icon_path):
        refresh_button = dashboard.ui.pushButton_ta_targets_refresh
        refresh_button.setIcon(QtGui.QIcon(refresh_icon_path))
        refresh_button.setText("")
        refresh_button.setToolTip("Refresh targets")
        refresh_button.setIconSize(QtCore.QSize(18, 18))

    details_scroll = dashboard.ui.scrollArea_ta_targets_info
    details_label = dashboard.ui.label_ta_targets_info_details
    for widget in [details_scroll, details_scroll.viewport(), details_scroll.widget(), details_label]:
        if widget is None:
            continue
        widget.setProperty("uiRole", "detailsPanel")
        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    details_label.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
    details_label.setTextFormat(QtCore.Qt.RichText)
    details_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
    details_label.setWordWrap(True)

    recommendation_table = dashboard.ui.tableWidget_ta_targets_recommended_actions
    recommendation_table.setColumnCount(3)
    recommendation_table.setHorizontalHeaderLabels(["Plugin", "Action", "Reason"])
    recommendation_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    recommendation_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    recommendation_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    recommendation_table.setWordWrap(False)
    recommendation_table.setTextElideMode(QtCore.Qt.ElideRight)
    recommendation_table.verticalHeader().setVisible(False)

    recommendation_header = recommendation_table.horizontalHeader()
    recommendation_header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    recommendation_header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
    recommendation_header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)

    dashboard.ui.plainTextEdit_ta_targets_recommended_actions_parameters.setReadOnly(True)
    dashboard.ui.label2_ta_targets_recommended_actions_reason.setWordWrap(True)

    history_table = dashboard.ui.tableWidget_ta_targets_history
    history_table.setColumnCount(4)
    history_table.setHorizontalHeaderLabels(["Time", "Event", "Source", "Details"])
    history_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    history_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    history_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    history_table.setWordWrap(False)
    history_table.setTextElideMode(QtCore.Qt.ElideRight)
    history_table.verticalHeader().setVisible(False)

    history_header = history_table.horizontalHeader()
    history_header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    history_header.setSectionResizeMode(1, QtWidgets.QHeaderView.Interactive)
    history_header.setSectionResizeMode(2, QtWidgets.QHeaderView.Interactive)
    history_header.setSectionResizeMode(3, QtWidgets.QHeaderView.Stretch)
    history_header.resizeSection(1, 145)
    history_header.resizeSection(2, 185)

    dashboard.ui.plainTextEdit_ta_targets_history_details.setReadOnly(True)

    geolocation_table = dashboard.ui.tableWidget_ta_targets_geolocation_observations
    geolocation_table.setColumnCount(6)
    geolocation_table.setHorizontalHeaderLabels(
        ["Time", "Node", "Power", "Gain", "Position", "Status"]
    )
    geolocation_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    geolocation_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    geolocation_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    geolocation_table.setWordWrap(False)
    geolocation_table.setTextElideMode(QtCore.Qt.ElideRight)
    geolocation_table.verticalHeader().setVisible(False)

    geolocation_header = geolocation_table.horizontalHeader()
    for column in range(5):
        geolocation_header.setSectionResizeMode(column, QtWidgets.QHeaderView.ResizeToContents)
    geolocation_header.setSectionResizeMode(5, QtWidgets.QHeaderView.Stretch)
    geolocation_header.setStretchLastSection(True)

    geolocation_font = geolocation_table.font()
    if geolocation_font.pointSize() > 0:
        geolocation_font.setPointSize(max(8, geolocation_font.pointSize() - 1))
    else:
        geolocation_font.setPixelSize(11)
    geolocation_table.setFont(geolocation_font)
    geolocation_table.horizontalHeader().setFont(geolocation_font)

    dashboard.ui.label_ta_targets_geolocation_info.setWordWrap(True)
    dashboard.ui.label_ta_targets_geolocation_info.setVisible(False)
    _update_geolocation_button(dashboard, "idle", has_target=False)

    dashboard.ui.comboBox_ta_target.clear()
    dashboard.ui.comboBox_ta_target.addItem("No Target", None)
    dashboard.ui.tabWidget_ta_targets.setCurrentWidget(dashboard.ui.tab_targets_details)

    clear_target_details(dashboard)
    refresh_targets_view(dashboard)


def _target_id(target: dict):
    return str(target.get("target_id") or target.get("uid") or target.get("id") or "").strip()


def _target_display_label(target: dict):
    classification = target.get("classification") or {}
    if not isinstance(classification, dict):
        classification = {}

    target_id = _target_id(target)
    return str(
        target.get("display_label")
        or target.get("type")
        or target.get("target_label")
        or classification.get("display_label")
        or target.get("name")
        or TacticalTabSlots.shorten_target_id(target_id)
        or "Unknown Target"
    ).strip()


def _target_protocol(target: dict):
    identity = target.get("identity") or {}
    if not isinstance(identity, dict):
        identity = {}

    classification = target.get("classification") or {}
    if not isinstance(classification, dict):
        classification = {}

    return str(
        identity.get("protocol")
        or identity.get("protocol_name")
        or classification.get("protocol")
        or target.get("protocol")
        or ""
    ).strip()


def _target_state(target: dict):
    return str(target.get("state") or target.get("target_state") or target.get("status") or "").strip()


def _target_updated(target: dict):
    value = (
        target.get("updated")
        or target.get("last_update_time")
        or target.get("updated_at")
        or target.get("time")
        or target.get("timestamp")
        or ""
    )
    return TacticalTabSlots.format_tactical_time(value)


def _target_matches_search(target: dict, search_text: str):
    search_text = str(search_text or "").strip().lower()
    if not search_text:
        return True

    try:
        target_text = json.dumps(target, default=str).lower()
    except Exception:
        target_text = str(target).lower()

    return search_text in target_text


def _target_combo_text(target: dict):
    target_id = _target_id(target)
    display_label = _target_display_label(target)
    short_id = TacticalTabSlots.shorten_target_id(target_id, max_len=18)
    return f"{display_label} ({short_id})" if short_id and short_id != display_label else display_label


def refresh_targets_view(dashboard: QtCore.QObject):
    """Rebuild the Targets table and shared target selector from the Target cache."""
    targets = getattr(dashboard, "tactical_targets", {}) or {}
    selected_target_id = getattr(dashboard, "selected_targets_actions_target_id", None)

    if selected_target_id and selected_target_id not in targets:
        selected_target_id = None
        dashboard.selected_targets_actions_target_id = None

    sorted_targets = sorted(
        [target for target in targets.values() if isinstance(target, dict)],
        key=lambda target: (_target_display_label(target).lower(), _target_id(target)),
    )

    combo = dashboard.ui.comboBox_ta_target
    combo.blockSignals(True)
    combo.clear()
    combo.addItem("No Target", None)
    selected_combo_index = 0

    for target in sorted_targets:
        target_id = _target_id(target)
        if not target_id:
            continue
        combo.addItem(_target_combo_text(target), target_id)
        if target_id == selected_target_id:
            selected_combo_index = combo.count() - 1

    combo.setCurrentIndex(selected_combo_index)
    combo.blockSignals(False)

    search_text = dashboard.ui.textEdit_ta_targets_search.toPlainText()
    visible_targets = [target for target in sorted_targets if _target_matches_search(target, search_text)]

    table = dashboard.ui.tableWidget1_ta_targets
    table.blockSignals(True)
    table.setRowCount(0)
    selected_row = None

    for target in visible_targets:
        target_id = _target_id(target)
        if not target_id:
            continue

        row = table.rowCount()
        table.insertRow(row)
        values = [_target_display_label(target), _target_state(target), _target_protocol(target), _target_updated(target)]

        for column, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(str(value))
            item.setData(QtCore.Qt.UserRole, target_id)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
            if column == 0:
                item.setToolTip(target_id)
            table.setItem(row, column, item)

        if target_id == selected_target_id:
            selected_row = row

    if selected_row is not None:
        table.selectRow(selected_row)
        table.setCurrentCell(selected_row, 0)

    table.blockSignals(False)
    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setStretchLastSection(True)

    total_count = len(sorted_targets)
    visible_count = len(visible_targets)
    if visible_count == total_count:
        count_text = f"{total_count} target" if total_count == 1 else f"{total_count} targets"
    else:
        count_text = f"{visible_count} of {total_count} targets"
    dashboard.ui.label2_ta_targets_count.setText(count_text)

    if selected_target_id:
        populate_target_details(
            dashboard,
            targets.get(selected_target_id),
            preserve_notes=dashboard.ui.textEdit_ta_targets_notes.hasFocus(),
        )
    else:
        clear_target_details(dashboard)


def update_target_record(dashboard: QtCore.QObject, target_record: dict):
    """Refresh the Targets workspace after an authoritative Target update arrives."""
    if not isinstance(target_record, dict):
        return

    target_id = _target_id(target_record)
    pending_target_id = getattr(dashboard, "pending_targets_actions_target_id", None)
    if target_id and target_id == pending_target_id:
        dashboard.selected_targets_actions_target_id = target_id
        dashboard.pending_targets_actions_target_id = None

    refresh_targets_view(dashboard)


def _safe_float(value):
    try:
        if value in (None, "", "None"):
            return None
        return float(value)
    except Exception:
        return None


def _target_geolocate(target: dict):
    geo = target.get("geolocate") or {}
    return geo if isinstance(geo, dict) else {}


def _target_geolocate_status(target: dict):
    geo = _target_geolocate(target)
    return str(geo.get("status") or target.get("geolocation_status") or "idle").strip().lower()


def _target_geolocation_frequency(target: dict):
    value = target.get("target_frequency_mhz")
    if value in (None, "", "None"):
        value = target.get("frequency_mhz")
    value = _safe_float(value)
    return f"{value:.3f} MHz" if value is not None else "--"


def _normalize_geolocation_observation(detection: dict):
    if not isinstance(detection, dict):
        return None

    target_id = str(detection.get("target_id") or "").strip()
    if not target_id:
        return None

    lat = _safe_float(detection.get("latitude"))
    if lat is None:
        lat = _safe_float(detection.get("lat"))
    lon = _safe_float(detection.get("longitude"))
    if lon is None:
        lon = _safe_float(detection.get("lon"))

    power_value = _safe_float(detection.get("power_dbm"))
    units = "dBm" if power_value is not None else ""

    if power_value is None:
        power_value = _safe_float(detection.get("power_dbfs_peak"))
        if power_value is not None:
            units = "dBFS"

    if power_value is None:
        power_value = _safe_float(detection.get("metric"))
        units = str(detection.get("metric_units") or "").strip()

    gain_db = _safe_float(detection.get("receiver_gain_db"))
    if gain_db is None:
        gain_db = _safe_float(detection.get("gain_db"))

    valid_position = (
        lat is not None
        and lon is not None
        and -90.0 <= lat <= 90.0
        and -180.0 <= lon <= 180.0
    )

    if not valid_position:
        status = "No GPS"
    elif power_value is None:
        status = "No Metric"
    elif units.lower() == "dbfs" and power_value >= -1.0:
        status = "Near Full Scale"
    else:
        status = "Collected"

    return {
        "target_id": target_id,
        "node_uid": str(detection.get("node_uid") or detection.get("source_id") or "").strip(),
        "time": detection.get("observation_time") or detection.get("timestamp") or "",
        "lat": lat,
        "lon": lon,
        "power_value": power_value,
        "units": units,
        "gain_db": gain_db,
        "path_loss_p0_db": _safe_float(detection.get("path_loss_p0_db")),
        "detector": str(detection.get("detector") or detection.get("detection_kind") or "").strip(),
        "operation_id": str(detection.get("operation_id") or detection.get("opid") or "").strip(),
        "status": status,
    }


def _geolocation_observations(dashboard, target_id):
    cache = getattr(dashboard, "targets_geolocation_observations", {}) or {}
    values = cache.get(str(target_id or ""), [])
    return values if isinstance(values, list) else []


def _geolocation_geometry(observations):
    empty = {
        "sample_count": 0,
        "unique_node_count": 0,
        "unique_position_count": 0,
        "spread_m": 0.0,
        "shape_ratio": 0.0,
        "quality": "insufficient_positions",
        "usable": False,
    }

    try:
        from fissure.utils.geo import Sample, geometry_stats
    except Exception:
        return empty

    samples = []
    for observation in observations:
        lat = observation.get("lat")
        lon = observation.get("lon")
        metric = observation.get("power_value")
        if lat is None or lon is None or metric is None:
            continue
        samples.append(
            Sample(
                lat=float(lat),
                lon=float(lon),
                rssi_db=float(metric),
                t=0.0,
                node_uid=str(observation.get("node_uid") or ""),
            )
        )

    if not samples:
        return empty

    try:
        return geometry_stats(
            samples,
            min_position_separation_m=8.0,
            min_spread_m=20.0,
        )
    except Exception:
        return empty


def _geolocation_measurement_units(observations):
    for observation in reversed(observations):
        units = str(observation.get("units") or "").strip()
        if units:
            return units
    return ""


def _geolocation_range_calibrated(observations):
    units = _geolocation_measurement_units(observations).lower()
    if not units:
        return None
    if units == "dbm":
        return True
    return any(observation.get("path_loss_p0_db") is not None for observation in observations)


def _geolocation_method(target, observations):
    geo = _target_geolocate(target)
    action = str(geo.get("action") or "").strip().lower()
    detector = ""
    if observations:
        detector = str(observations[-1].get("detector") or "").strip().lower()

    name = action or detector
    if name in {
        "lfm_beacon_geolocate",
        "wifi_geolocate_target",
        "wifi_geolocate_all",
        "usrp_b2x0_geolocate",
    } or "geolocate" in name:
        return "RSSI Multilateration"

    return name.replace("_", " ").title() if name else "--"


def _geolocation_collection(target, geometry):
    node_count = int(geometry.get("unique_node_count", 0) or 0)
    position_count = int(geometry.get("unique_position_count", 0) or 0)
    geo = _target_geolocate(target)
    configured_nodes = geo.get("node_uids") or []

    if node_count >= 2 or (not node_count and isinstance(configured_nodes, list) and len(configured_nodes) >= 2):
        return "Distributed Locate"
    if position_count >= 2:
        return "Mobile Survey"
    if node_count == 1 or (isinstance(configured_nodes, list) and len(configured_nodes) == 1):
        return "Single Node"
    return "--"


def _geometry_display(quality):
    return {
        "insufficient_positions": "Need More Positions",
        "insufficient_spread": "Insufficient Spread",
        "collinear": "Collinear",
        "poor": "Poor",
        "fair": "Fair",
        "good": "Good",
    }.get(str(quality or "").lower(), "--")


def _set_semantic_state(widget, state=""):
    widget.setProperty("state", str(state or ""))
    widget.style().unpolish(widget)
    widget.style().polish(widget)
    widget.update()


def _set_geolocation_info(dashboard, text="", severity="info"):
    label = dashboard.ui.label_ta_targets_geolocation_info
    label.setText(str(text or ""))
    label.setProperty("severity", str(severity or "info"))
    label.setVisible(bool(text))
    label.style().unpolish(label)
    label.style().polish(label)
    label.update()


def _update_geolocation_button(dashboard, status, has_target=True):
    button = dashboard.ui.pushButton_ta_targets_geolocation_start_stop
    status = str(status or "idle").lower()
    running = status in ("starting", "running", "stopping")

    if status == "starting":
        button.setText("Starting...")
        button.setEnabled(False)
    elif status == "stopping":
        button.setText("Stopping...")
        button.setEnabled(False)
    elif status == "running":
        button.setText("Stop Geolocation")
        button.setEnabled(bool(has_target))
    else:
        button.setText("Start Geolocation")
        button.setEnabled(bool(has_target))

    button.setProperty("running", "true" if running else "false")
    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


def _populate_geolocation_observations_table(dashboard, observations):
    table = dashboard.ui.tableWidget_ta_targets_geolocation_observations
    table.blockSignals(True)
    table.setRowCount(0)

    tactical_nodes = getattr(dashboard, "tactical_nodes", {}) or {}

    for observation in reversed(observations[-100:]):
        row = table.rowCount()
        table.insertRow(row)

        power = "--"
        if observation.get("power_value") is not None:
            units = str(observation.get("units") or "").strip()
            power = f"{float(observation['power_value']):.1f} {units}".strip()

        gain = "--"
        if observation.get("gain_db") is not None:
            gain = f"{float(observation['gain_db']):.0f} dB"

        position = "--"
        if observation.get("lat") is not None and observation.get("lon") is not None:
            position = f"{float(observation['lat']):.6f}, {float(observation['lon']):.6f}"

        node_uid = str(observation.get("node_uid") or "").strip()
        node_record = tactical_nodes.get(node_uid) or {}
        node_label = node_record.get("callsign") or node_record.get("name") or node_uid or "--"

        values = [
            TacticalTabSlots.format_tactical_time(observation.get("time") or ""),
            node_label,
            power,
            gain,
            position,
            observation.get("status") or "Collected",
        ]

        for column, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(str(value))
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
            if column == 1 and node_uid:
                item.setToolTip(node_uid)
            table.setItem(row, column, item)

    table.resizeRowsToContents()
    table.blockSignals(False)


def populate_target_geolocation(dashboard: QtCore.QObject, target: dict):
    if not isinstance(target, dict) or not target:
        clear_target_geolocation(dashboard)
        return

    target_id = _target_id(target)
    observations = _geolocation_observations(dashboard, target_id)
    geometry = _geolocation_geometry(observations)
    status = _target_geolocate_status(target)
    units = _geolocation_measurement_units(observations)
    calibrated = _geolocation_range_calibrated(observations)
    quality = str(geometry.get("quality") or "")
    usable = bool(geometry.get("usable"))

    operation_text = {
        "idle": "Idle",
        "starting": "Starting",
        "running": "Running",
        "stopping": "Stopping",
        "unsupported": "Unsupported",
        "error": "Error",
    }.get(status, status.replace("_", " ").title() or "Idle")

    dashboard.ui.label_ta_targets_geolocation_operation.setText(operation_text)
    dashboard.ui.label_ta_targets_geolocation_method.setText(_geolocation_method(target, observations))
    dashboard.ui.label_ta_targets_geolocation_collection.setText(_geolocation_collection(target, geometry))
    dashboard.ui.label_ta_targets_geolocation_frequency.setText(_target_geolocation_frequency(target))

    dashboard.ui.label_ta_targets_geolocation_samples.setText(str(int(geometry.get("sample_count", 0) or 0)))
    dashboard.ui.label_ta_targets_geolocation_nodes.setText(str(int(geometry.get("unique_node_count", 0) or 0)))
    dashboard.ui.label_ta_targets_geolocation_positions.setText(str(int(geometry.get("unique_position_count", 0) or 0)))
    dashboard.ui.label_ta_targets_geolocation_spread.setText(f"{float(geometry.get('spread_m', 0.0) or 0.0):.1f} m")
    dashboard.ui.label_ta_targets_geolocation_geometry.setText(_geometry_display(quality))
    dashboard.ui.label_ta_targets_geolocation_measurement.setText(units or "--")
    dashboard.ui.label_ta_targets_geolocation_range_calibrated.setText(
        "Yes" if calibrated is True else "No" if calibrated is False else "--"
    )

    active = status in ("starting", "running", "stopping")
    location_source = str(target.get("location_source") or "").strip().lower()
    solution_available = location_source == "hiprfisr_multilateration"

    if status == "error":
        solution_text = "Error"
    elif status == "unsupported":
        solution_text = "Unsupported"
    elif solution_available:
        solution_text = "Available"
    elif active and not usable:
        solution_text = "Collecting"
    elif active and calibrated is False:
        solution_text = "Calibration Required"
    elif active and usable and calibrated is True:
        solution_text = "Solving"
    else:
        solution_text = "Not Available"

    dashboard.ui.label_ta_targets_geolocation_solution.setText(solution_text)

    if solution_text == "Available":
        lat = _safe_float(target.get("lat"))
        lon = _safe_float(target.get("lon"))
        ce_m = _safe_float(target.get("ce_m"))
        dashboard.ui.label_ta_targets_geolocation_latitude.setText(f"{lat:.6f}" if lat is not None else "--")
        dashboard.ui.label_ta_targets_geolocation_longitude.setText(f"{lon:.6f}" if lon is not None else "--")
        dashboard.ui.label_ta_targets_geolocation_ce.setText(f"{ce_m:.1f} m" if ce_m is not None else "--")
    else:
        dashboard.ui.label_ta_targets_geolocation_latitude.setText("--")
        dashboard.ui.label_ta_targets_geolocation_longitude.setText("--")
        dashboard.ui.label_ta_targets_geolocation_ce.setText("--")

    _set_semantic_state(
        dashboard.ui.label_ta_targets_geolocation_operation,
        "good" if status == "running" else "error" if status == "error" else "warning" if active else "",
    )
    _set_semantic_state(
        dashboard.ui.label_ta_targets_geolocation_geometry,
        "good" if quality == "good" else "warning" if quality in ("fair", "poor", "insufficient_positions", "insufficient_spread", "collinear") else "",
    )
    _set_semantic_state(
        dashboard.ui.label_ta_targets_geolocation_range_calibrated,
        "good" if calibrated is True else "warning" if calibrated is False else "",
    )
    _set_semantic_state(
        dashboard.ui.label_ta_targets_geolocation_solution,
        "good" if solution_text == "Available" else "error" if solution_text in ("Error", "Unsupported") else "warning" if solution_text in ("Calibration Required", "Collecting") else "",
    )

    geo = _target_geolocate(target)
    error = str(geo.get("error") or "").strip()
    if status == "error":
        _set_geolocation_info(dashboard, f"Geolocation error: {error or 'unknown error'}", "error")
    elif status == "unsupported":
        _set_geolocation_info(dashboard, "No supported geolocation action is available for this target.", "warning")
    elif active and not observations:
        _set_geolocation_info(dashboard, "Waiting for geolocation observations.", "info")
    elif active and int(geometry.get("unique_position_count", 0) or 0) < 3:
        _set_geolocation_info(dashboard, "Collect at least 3 distinct receiver positions.", "info")
    elif active and quality == "insufficient_spread":
        _set_geolocation_info(dashboard, "Need more spatial spread between receiver positions.", "info")
    elif active and quality == "collinear":
        _set_geolocation_info(dashboard, "Observation geometry is too linear. Collect positions around the target.", "warning")
    elif active and calibrated is False:
        _set_geolocation_info(dashboard, "Range calibration required before a solution can be produced.", "warning")
    elif active and usable and calibrated is True and not solution_available:
        _set_geolocation_info(dashboard, "Geometry is ready. Waiting for a location solution.", "info")
    else:
        _set_geolocation_info(dashboard)

    _populate_geolocation_observations_table(dashboard, observations)
    _update_geolocation_button(dashboard, status, has_target=bool(target_id))


def clear_target_geolocation(dashboard: QtCore.QObject):
    for name in (
        "label_ta_targets_geolocation_operation",
        "label_ta_targets_geolocation_method",
        "label_ta_targets_geolocation_collection",
        "label_ta_targets_geolocation_frequency",
        "label_ta_targets_geolocation_samples",
        "label_ta_targets_geolocation_nodes",
        "label_ta_targets_geolocation_positions",
        "label_ta_targets_geolocation_spread",
        "label_ta_targets_geolocation_geometry",
        "label_ta_targets_geolocation_measurement",
        "label_ta_targets_geolocation_range_calibrated",
        "label_ta_targets_geolocation_solution",
        "label_ta_targets_geolocation_latitude",
        "label_ta_targets_geolocation_longitude",
        "label_ta_targets_geolocation_ce",
    ):
        getattr(dashboard.ui, name).setText("--")

    dashboard.ui.tableWidget_ta_targets_geolocation_observations.setRowCount(0)
    _set_geolocation_info(dashboard)
    _update_geolocation_button(dashboard, "idle", has_target=False)


def handle_target_geolocation_detection(dashboard: QtCore.QObject, detection: dict):
    observation = _normalize_geolocation_observation(detection)
    if observation is None:
        return

    target_id = observation["target_id"]
    target = (getattr(dashboard, "tactical_targets", {}) or {}).get(target_id) or {}
    detector = str(observation.get("detector") or "").lower()
    if _target_geolocate_status(target) not in ("starting", "running", "stopping") and "geolocate" not in detector:
        return

    if not hasattr(dashboard, "targets_geolocation_observations"):
        dashboard.targets_geolocation_observations = {}

    observations = dashboard.targets_geolocation_observations.setdefault(target_id, [])
    operation_id = observation.get("operation_id") or ""
    if observations and operation_id:
        previous_operation_id = str(observations[-1].get("operation_id") or "")
        if previous_operation_id and previous_operation_id != operation_id:
            observations.clear()

    observations.append(observation)
    if len(observations) > 250:
        del observations[:-250]

    if getattr(dashboard, "selected_targets_actions_target_id", None) == target_id:
        populate_target_geolocation(dashboard, target)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTargetsGeolocationStartStopClicked(dashboard: QtCore.QObject):
    target_id = getattr(dashboard, "selected_targets_actions_target_id", None)
    if not target_id:
        return

    target = (getattr(dashboard, "tactical_targets", {}) or {}).get(target_id)
    if not target:
        return

    status = _target_geolocate_status(target)
    if status in ("starting", "running"):
        await dashboard.backend.tacticalTargetsGeolocateStop(target_id=target_id)
        return

    if status == "stopping":
        return

    dashboard.targets_geolocation_observations[target_id] = []
    populate_target_geolocation(dashboard, target)
    await dashboard.backend.tacticalTargetsGeolocateStart(
        target_id=target_id,
        search_similar_targets=False,
    )


def _target_details_html(target: dict):
    target_id = _target_id(target)
    identity = target.get("identity") or {}
    if not isinstance(identity, dict):
        identity = {}

    artifact_ids = target.get("artifact_ids") or []
    if not isinstance(artifact_ids, list):
        artifact_ids = []

    history = target.get("history") or []
    if not isinstance(history, list):
        history = []

    frequency = target.get("target_frequency_mhz")
    if frequency in [None, "", "None"]:
        frequency = target.get("frequency_mhz")
    if frequency not in [None, "", "None"]:
        try:
            frequency = f"{float(frequency):.3f} MHz"
        except Exception:
            frequency = str(frequency)

    lat = target.get("lat")
    lon = target.get("lon")
    location = ""
    if lat not in [None, "", "None"] and lon not in [None, "", "None"]:
        try:
            location = f"{float(lat):.6f}, {float(lon):.6f}"
        except Exception:
            location = f"{lat}, {lon}"

    fields = [
        ("Target ID", target_id),
        ("Source SOI", target.get("source_soi_id")),
        ("Protocol", _target_protocol(target)),
        ("Frequency", frequency),
        ("Node ID", target.get("node_uid") or target.get("sensor_node_id") or target.get("node_id")),
        ("Location", location),
        ("Updated", _target_updated(target)),
        ("Target Artifacts", len(artifact_ids)),
        ("History Entries", len(history)),
    ]

    lines = []
    for label, value in fields:
        if value in [None, "", "None"]:
            continue
        lines.append(
            "<span style='font-weight:500;'>"
            f"{html.escape(str(label))}:"
            "</span> "
            f"{html.escape(str(value))}"
        )

    useful_identity_keys = [
        "device_name",
        "device_id",
        "serial",
        "serial_number",
        "mac",
        "mac_address",
        "bssid",
        "ssid",
        "ip",
        "ip_address",
        "hostname",
        "callsign",
        "network",
        "network_id",
        "channel",
        "channel_name",
        "communicates_with",
    ]

    identity_lines = []
    for key in useful_identity_keys:
        value = identity.get(key)
        if value in [None, "", "None"]:
            continue
        label = key.replace("_", " ").title()
        identity_lines.append(
            "&nbsp;&nbsp;&nbsp;&nbsp;"
            "<span style='font-weight:500;'>"
            f"{html.escape(label)}:"
            "</span> "
            f"{html.escape(str(value))}"
        )

    if identity_lines:
        if lines:
            lines.append("<br>")
        lines.append("<span style='font-weight:700;'>Identity</span>")
        lines.extend(identity_lines)

    return "<br>".join(lines)


def _target_recommendations(target: dict):
    recommendations = target.get("recommendations") or []
    return [dict(value) for value in recommendations if isinstance(value, dict)]


def _history_source(entry: dict):
    plugin_name = str(entry.get("plugin") or "").strip()
    action_name = str(entry.get("action") or "").strip()
    if plugin_name and action_name:
        return f"{plugin_name}: {action_name}"
    if plugin_name:
        return plugin_name

    requester = str(
        entry.get("requester_callsign")
        or entry.get("requester")
        or entry.get("node_uid")
        or ""
    ).strip()
    return requester or "Dashboard"


def _history_summary(entry: dict):
    skip = {
        "timestamp", "event", "plugin", "action", "node_uid",
        "requester", "requester_uid", "requester_callsign",
    }
    parts = []
    for key, value in entry.items():
        if key in skip or value in [None, "", [], {}]:
            continue
        if isinstance(value, (dict, list)):
            value_text = json.dumps(value, default=str, separators=(",", ":"))
        else:
            value_text = str(value)
        if len(value_text) > 80:
            value_text = value_text[:77] + "..."
        parts.append(f"{key}={value_text}")
        if len(parts) >= 3:
            break
    return ", ".join(parts)


def _clear_recommendation_details(dashboard: QtCore.QObject):
    dashboard.selected_target_recommendation_id = None
    dashboard.ui.label2_ta_targets_recommended_actions_plugin.setText("—")
    dashboard.ui.label2_ta_targets_recommended_actions_action.setText("—")
    dashboard.ui.label2_ta_targets_recommended_actions_reason.setText("—")
    dashboard.ui.plainTextEdit_ta_targets_recommended_actions_parameters.clear()
    dashboard.ui.pushButton_ta_targets_recommended_actions_stage.setEnabled(False)
    dashboard.ui.pushButton_ta_targets_recommended_actions_remove.setEnabled(False)


def _populate_recommendation_details(dashboard: QtCore.QObject, recommendation: dict):
    if not isinstance(recommendation, dict):
        _clear_recommendation_details(dashboard)
        return

    recommendation_id = str(recommendation.get("recommendation_id") or "").strip()
    dashboard.selected_target_recommendation_id = recommendation_id or None
    dashboard.ui.label2_ta_targets_recommended_actions_plugin.setText(
        str(recommendation.get("plugin") or "—")
    )
    dashboard.ui.label2_ta_targets_recommended_actions_action.setText(
        str(recommendation.get("action") or "—")
    )
    dashboard.ui.label2_ta_targets_recommended_actions_reason.setText(
        str(recommendation.get("reason") or "—")
    )
    dashboard.ui.plainTextEdit_ta_targets_recommended_actions_parameters.setPlainText(
        json.dumps(recommendation.get("parameters") or {}, indent=2, sort_keys=True, default=str)
    )
    dashboard.ui.pushButton_ta_targets_recommended_actions_stage.setEnabled(
        bool(recommendation.get("plugin") and recommendation.get("action"))
    )
    dashboard.ui.pushButton_ta_targets_recommended_actions_remove.setEnabled(bool(recommendation_id))


def populate_target_recommendations(dashboard: QtCore.QObject, target: dict):
    table = dashboard.ui.tableWidget_ta_targets_recommended_actions
    previous_id = str(getattr(dashboard, "selected_target_recommendation_id", "") or "").strip()
    recommendations = _target_recommendations(target)

    table.blockSignals(True)
    table.setRowCount(0)
    selected_row = None

    for recommendation in reversed(recommendations):
        row = table.rowCount()
        table.insertRow(row)
        recommendation_id = str(recommendation.get("recommendation_id") or "").strip()
        values = [
            str(recommendation.get("plugin") or ""),
            str(recommendation.get("action") or ""),
            str(recommendation.get("reason") or ""),
        ]
        for column, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(value)
            item.setData(QtCore.Qt.UserRole, dict(recommendation))
            table.setItem(row, column, item)
        if recommendation_id and recommendation_id == previous_id:
            selected_row = row

    table.blockSignals(False)
    table.resizeRowsToContents()

    if selected_row is None and table.rowCount() > 0:
        selected_row = 0

    if selected_row is not None:
        table.selectRow(selected_row)
        table.setCurrentCell(selected_row, 0)
        item = table.item(selected_row, 0)
        _populate_recommendation_details(
            dashboard,
            item.data(QtCore.Qt.UserRole) if item is not None else {},
        )
    else:
        _clear_recommendation_details(dashboard)


def populate_target_history(dashboard: QtCore.QObject, target: dict):
    table = dashboard.ui.tableWidget_ta_targets_history
    history = target.get("history") or []
    history = [dict(value) for value in history if isinstance(value, dict)]

    table.blockSignals(True)
    table.setRowCount(0)

    for entry in reversed(history):
        row = table.rowCount()
        table.insertRow(row)
        values = [
            TacticalTabSlots.format_tactical_time(entry.get("timestamp") or ""),
            str(entry.get("event") or "history"),
            _history_source(entry),
            _history_summary(entry),
        ]
        for column, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(str(value))
            item.setData(QtCore.Qt.UserRole, dict(entry))
            table.setItem(row, column, item)

    table.blockSignals(False)
    table.resizeRowsToContents()

    if table.rowCount() > 0:
        table.selectRow(0)
        table.setCurrentCell(0, 0)
        item = table.item(0, 0)
        dashboard.ui.plainTextEdit_ta_targets_history_details.setPlainText(
            json.dumps(item.data(QtCore.Qt.UserRole) or {}, indent=2, sort_keys=True, default=str)
        )
    else:
        dashboard.ui.plainTextEdit_ta_targets_history_details.clear()


def populate_target_details(dashboard: QtCore.QObject, target: dict, preserve_notes=False):
    """Populate the Targets page for the current Targets & Actions context."""
    if not isinstance(target, dict) or not target:
        clear_target_details(dashboard)
        return

    target_id = _target_id(target)
    dashboard.selected_targets_actions_target_id = target_id

    dashboard.ui.label_ta_targets_info_title.setText(_target_display_label(target))
    dashboard.ui.label_ta_targets_info_status.setText(_target_state(target) or "unknown")
    dashboard.ui.label_ta_targets_info_details.setText(_target_details_html(target))
    populate_target_recommendations(dashboard, target)
    populate_target_history(dashboard, target)
    populate_target_geolocation(dashboard, target)

    if not preserve_notes:
        dashboard.ui.textEdit_ta_targets_notes.setPlainText(str(target.get("notes") or ""))

    source_soi_id = str(target.get("source_soi_id") or "").strip()
    dashboard.ui.textEdit_ta_targets_notes.setEnabled(True)
    dashboard.ui.pushButton_ta_targets_save_notes.setEnabled(True)
    dashboard.ui.pushButton_ta_targets_open_soi.setEnabled(bool(source_soi_id))
    dashboard.ui.pushButton_ta_targets_download_data.setEnabled(True)
    dashboard.ui.pushButton_ta_targets_copy_target_id.setEnabled(bool(target_id))
    dashboard.ui.pushButton_ta_open_in_tactical.setEnabled(bool(target_id))


def clear_target_details(dashboard: QtCore.QObject):
    dashboard.ui.label_ta_targets_info_title.setText("No Target Selected")
    dashboard.ui.label_ta_targets_info_status.setText("")
    dashboard.ui.label_ta_targets_info_details.setText("")
    dashboard.ui.textEdit_ta_targets_notes.clear()
    dashboard.ui.textEdit_ta_targets_notes.setEnabled(False)
    dashboard.ui.tableWidget_ta_targets_recommended_actions.setRowCount(0)
    dashboard.ui.tableWidget_ta_targets_history.setRowCount(0)
    dashboard.ui.plainTextEdit_ta_targets_history_details.clear()
    clear_target_geolocation(dashboard)
    _clear_recommendation_details(dashboard)
    dashboard.ui.pushButton_ta_targets_save_notes.setEnabled(False)
    dashboard.ui.pushButton_ta_targets_open_soi.setEnabled(False)
    dashboard.ui.pushButton_ta_targets_download_data.setEnabled(False)
    dashboard.ui.pushButton_ta_targets_copy_target_id.setEnabled(False)
    dashboard.ui.pushButton_ta_open_in_tactical.setEnabled(False)


def _set_target_context(dashboard: QtCore.QObject, target_id):
    target_id = str(target_id or "").strip() or None
    targets = getattr(dashboard, "tactical_targets", {}) or {}
    if target_id and target_id not in targets:
        target_id = None

    dashboard.selected_targets_actions_target_id = target_id

    combo = dashboard.ui.comboBox_ta_target
    combo.blockSignals(True)
    combo_index = combo.findData(target_id)
    combo.setCurrentIndex(combo_index if combo_index >= 0 else 0)
    combo.blockSignals(False)

    table = dashboard.ui.tableWidget1_ta_targets
    table.blockSignals(True)
    table.clearSelection()

    if target_id:
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            if item is None:
                continue
            if str(item.data(QtCore.Qt.UserRole) or "") == target_id:
                table.selectRow(row)
                table.setCurrentCell(row, 0)
                table.scrollToItem(item)
                break

    table.blockSignals(False)

    if target_id:
        populate_target_details(dashboard, targets.get(target_id))
    else:
        clear_target_details(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTargetContextChanged(dashboard: QtCore.QObject):
    _set_target_context(dashboard, dashboard.ui.comboBox_ta_target.currentData())


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTargetsRowSelectionChanged(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget1_ta_targets
    selected_items = table.selectedItems()
    if not selected_items:
        return

    item = table.item(selected_items[0].row(), 0)
    if item is not None:
        _set_target_context(dashboard, item.data(QtCore.Qt.UserRole))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTargetsSearchChanged(dashboard: QtCore.QObject):
    refresh_targets_view(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTargetsRefreshClicked(dashboard: QtCore.QObject):
    dashboard.pending_targets_actions_target_id = getattr(dashboard, "selected_targets_actions_target_id", None)
    dashboard.selected_targets_actions_target_id = None
    dashboard.tactical_targets = {}
    dashboard.ui.tableWidget_tactical_targets.setRowCount(0)
    dashboard.selected_tactical_target_id = None
    refresh_targets_view(dashboard)
    await dashboard.backend.tacticalTargetsRefreshTargets()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTargetsOpenInTacticalClicked(dashboard: QtCore.QObject):
    target_id = getattr(dashboard, "selected_targets_actions_target_id", None)
    if not target_id:
        return

    dashboard.ui.tabWidget.setCurrentWidget(dashboard.ui.tab_automation)
    TacticalTabSlots._slotTacticalTargetMapClicked(dashboard, target_id)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTargetsOpenSoiClicked(dashboard: QtCore.QObject):
    target_id = getattr(dashboard, "selected_targets_actions_target_id", None)
    target = dashboard.tactical_targets.get(target_id) if target_id else None
    if not isinstance(target, dict) or not target:
        return

    dashboard.ui.tabWidget.setCurrentWidget(dashboard.ui.tab_automation)
    TacticalTabSlots._openTacticalTargetSourceSoi(dashboard, target)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTargetsCopyTargetIdClicked(dashboard: QtCore.QObject):
    target_id = getattr(dashboard, "selected_targets_actions_target_id", None)
    if not target_id:
        return

    QtWidgets.QApplication.clipboard().setText(str(target_id))
    dashboard.statusBar().showMessage("Target ID copied.", 3000)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTargetsSaveNotesClicked(dashboard: QtCore.QObject):
    target_id = getattr(dashboard, "selected_targets_actions_target_id", None)
    target = dashboard.tactical_targets.get(target_id) if target_id else None
    if not isinstance(target, dict) or not target:
        dashboard.statusBar().showMessage("Select a Target first.", 5000)
        return

    notes = dashboard.ui.textEdit_ta_targets_notes.toPlainText().strip()
    button = dashboard.ui.pushButton_ta_targets_save_notes
    button.setEnabled(False)
    button.setText("Saving...")

    try:
        await dashboard.backend.tacticalTargetPatch(target_id=target_id, patch={"notes": notes})
        target["notes"] = notes
        dashboard.statusBar().showMessage("Target notes saved.", 3000)
    except Exception as exc:
        dashboard.logger.error(f"[Targets] Failed saving notes for {target_id}: {exc}")
        dashboard.statusBar().showMessage("Failed to save Target notes.", 5000)
    finally:
        button.setText("Save Notes")
        button.setEnabled(getattr(dashboard, "selected_targets_actions_target_id", None) == target_id)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTargetsDownloadDataClicked(dashboard: QtCore.QObject):
    target_id = getattr(dashboard, "selected_targets_actions_target_id", None)
    target = dashboard.tactical_targets.get(target_id) if target_id else None
    if not isinstance(target, dict) or not target:
        dashboard.statusBar().showMessage("Select a Target first.", 5000)
        return

    button = dashboard.ui.pushButton_ta_targets_download_data
    button.setEnabled(False)
    button.setText("Downloading...")

    try:
        await build_target_data_folder(dashboard, target)
        dashboard.statusBar().showMessage("Target data folder rebuilt.", 4000)
    except Exception as exc:
        dashboard.logger.error(f"[Targets] Failed downloading data for {target_id}: {exc}")
        dashboard.statusBar().showMessage("Failed to download Target data.", 5000)
    finally:
        button.setText("Download Data")
        button.setEnabled(getattr(dashboard, "selected_targets_actions_target_id", None) == target_id)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTargetsRecommendedActionSelectionChanged(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_targets_recommended_actions
    row = table.currentRow()
    if row < 0:
        _clear_recommendation_details(dashboard)
        return
    item = table.item(row, 0)
    recommendation = item.data(QtCore.Qt.UserRole) if item is not None else {}
    _populate_recommendation_details(dashboard, recommendation)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTargetsRecommendedActionStageClicked(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_targets_recommended_actions
    row = table.currentRow()
    if row < 0:
        return
    item = table.item(row, 0)
    recommendation = item.data(QtCore.Qt.UserRole) if item is not None else {}
    if not isinstance(recommendation, dict):
        return

    dashboard.ui.tabWidget_attack_attack.setCurrentWidget(dashboard.ui.tab_single_action)
    await SingleActionTabSlots.stage_single_action_recommendation(dashboard, recommendation)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTargetsRecommendedActionRemoveClicked(dashboard: QtCore.QObject):
    target_id = str(getattr(dashboard, "selected_targets_actions_target_id", "") or "").strip()
    recommendation_id = str(getattr(dashboard, "selected_target_recommendation_id", "") or "").strip()
    if not target_id or not recommendation_id:
        return

    dashboard.ui.pushButton_ta_targets_recommended_actions_remove.setEnabled(False)
    await dashboard.backend.tacticalTargetRecommendation(
        target_id=target_id,
        mode="remove",
        recommendation_id=recommendation_id,
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTargetsHistorySelectionChanged(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_targets_history
    row = table.currentRow()
    if row < 0:
        dashboard.ui.plainTextEdit_ta_targets_history_details.clear()
        return
    item = table.item(row, 0)
    entry = item.data(QtCore.Qt.UserRole) if item is not None else {}
    dashboard.ui.plainTextEdit_ta_targets_history_details.setPlainText(
        json.dumps(entry or {}, indent=2, sort_keys=True, default=str)
    )