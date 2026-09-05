from PyQt5 import QtCore, QtGui, QtWidgets

from datetime import datetime, timezone
import inspect
import os
import subprocess
import uuid

import qasync

import fissure.utils
from fissure.Dashboard.SoiEvidenceController import collect_soi_artifact_ids
from fissure.Dashboard.UI_Components import Qt5
from .sois import (
    _sa_sois_display_name,
    _sa_sois_format_bandwidth,
    _sa_sois_format_frequency,
    _sa_sois_stage,
    _sa_sois_value,
)


ACTION_QUERY_CONTEXT = "sa.capture.actions"
ACTION_SCHEMA_CONTEXT = "sa.capture.schema"


def _sa_capture_selected_node_available(dashboard: QtCore.QObject) -> bool:
    """Return True when an online Sensor Node is selected for Capture."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        return False

    node_state = (getattr(dashboard, "node_states", {}) or {}).get(node_uid)
    return not (isinstance(node_state, dict) and node_state.get("connected") is False)


def _sa_capture_hardware_matches(candidate: str, selected: str) -> bool:
    candidate = str(candidate or "").strip().lower()
    selected = str(selected or "").strip().lower()
    return bool(candidate and selected and (candidate in selected or selected in candidate))


def _sa_capture_selected_hardware(dashboard: QtCore.QObject) -> dict:
    record = dashboard.ui.comboBox_sa_capture_setup_hardware.currentData()
    return record if isinstance(record, dict) else {}


def _sa_capture_selected_soi(dashboard: QtCore.QObject):
    """Return the selected Capture SOI key and record, or (None, None)."""
    soi_key = dashboard.ui.comboBox_sa_capture_context_soi.currentData(QtCore.Qt.UserRole)
    soi_key = str(soi_key or "").strip()
    if not soi_key:
        return None, None

    soi = (getattr(dashboard, "tactical_sois", {}) or {}).get(soi_key)
    return (soi_key, soi) if isinstance(soi, dict) else (None, None)


def _sa_capture_soi_combo_text(soi: dict) -> str:
    name = _sa_sois_display_name(soi)
    frequency = _sa_sois_value(soi, "frequency_mhz", "center_frequency_mhz")
    try:
        frequency_text = f"{float(frequency):.3f} MHz"
    except Exception:
        frequency_text = str(frequency or "").strip()

    if frequency_text and frequency_text not in name:
        return f"{name} ({frequency_text})"
    return name


def _update_sa_capture_soi_details(dashboard: QtCore.QObject):
    """Render the selected SOI's compact Capture context."""
    _soi_key, soi = _sa_capture_selected_soi(dashboard)

    if not soi:
        values = {
            "name": "—",
            "frequency": "—",
            "bandwidth": "—",
            "stage": "—",
        }
    else:
        values = {
            "name": _sa_sois_display_name(soi),
            "frequency": _sa_sois_format_frequency(
                _sa_sois_value(soi, "frequency_mhz", "center_frequency_mhz")
            ),
            "bandwidth": _sa_sois_format_bandwidth(soi),
            "stage": _sa_sois_stage(soi) or "—",
        }

    dashboard.ui.label2_sa_capture_context_name.setText(values["name"])
    dashboard.ui.label2_sa_capture_context_frequency.setText(values["frequency"])
    dashboard.ui.label2_sa_capture_context_bandwidth.setText(values["bandwidth"])
    dashboard.ui.label2_sa_capture_context_stage.setText(values["stage"])


def refresh_sa_capture_soi_context(
    dashboard: QtCore.QObject,
    preferred_soi_key: str = "",
):
    """Rebuild the optional Capture SOI selector while preserving context."""
    combo = dashboard.ui.comboBox_sa_capture_context_soi
    current_key = str(combo.currentData(QtCore.Qt.UserRole) or "").strip()
    pending_key = str(getattr(dashboard, "signal_analysis_prefill_soi_key", "") or "").strip()
    preferred_key = str(preferred_soi_key or pending_key or current_key or "").strip()
    sois = getattr(dashboard, "tactical_sois", {}) or {}

    records = [
        (str(key), soi)
        for key, soi in sois.items()
        if isinstance(soi, dict)
    ]
    records.sort(
        key=lambda item: (
            str(_sa_sois_display_name(item[1]) or "").lower(),
            str(item[0]),
        )
    )

    combo.blockSignals(True)
    combo.clear()
    combo.addItem("Manual Capture / No SOI", "")
    for soi_key, soi in records:
        combo.addItem(_sa_capture_soi_combo_text(soi), soi_key)

    selected_index = 0
    if preferred_key:
        for index in range(combo.count()):
            if str(combo.itemData(index, QtCore.Qt.UserRole) or "").strip() == preferred_key:
                selected_index = index
                break
    combo.setCurrentIndex(selected_index)
    combo.blockSignals(False)

    matched_preferred = bool(
        preferred_key
        and str(combo.currentData(QtCore.Qt.UserRole) or "").strip() == preferred_key
    )
    if pending_key and preferred_key == pending_key and matched_preferred:
        dashboard.signal_analysis_prefill_soi_key = None

    _update_sa_capture_soi_details(dashboard)
    _update_sa_capture_link_button(dashboard)


def _clear_sa_capture_parameter_widgets(dashboard: QtCore.QObject):
    """Clear dynamically generated Capture parameter controls."""
    contents = dashboard.ui.scrollAreaWidgetContents_sa_capture_parameters
    layout = contents.layout()
    if layout is None:
        layout = QtWidgets.QFormLayout(contents)
        layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.AllNonFixedFieldsGrow)

    while layout.count():
        item = layout.takeAt(0)
        if item.widget() is not None:
            item.widget().deleteLater()
        elif item.layout() is not None:
            child_layout = item.layout()
            while child_layout.count():
                child_item = child_layout.takeAt(0)
                if child_item.widget() is not None:
                    child_item.widget().deleteLater()
            child_layout.deleteLater()

    layout.setContentsMargins(8, 8, 8, 8)
    layout.setHorizontalSpacing(10)
    layout.setVerticalSpacing(8)
    dashboard.sa_capture_parameter_widgets = {}
    dashboard.sa_capture_current_schema = {}
    dashboard.sa_capture_customized = False
    dashboard.ui.label_sa_capture_execution_info.setText(
        "Customize a capture action to preview the acquisition request."
    )
    dashboard.ui.pushButton_sa_capture_start_stop.setEnabled(False)


def _reset_sa_capture_action_selection(dashboard: QtCore.QObject):
    """Clear Capture Plugin/Action selection and customized parameters."""
    dashboard.sa_capture_filtered_actions = []
    dashboard.sa_capture_selected_plugin = ""
    dashboard.sa_capture_selected_action = ""

    for combo in (
        dashboard.ui.comboBox_sa_capture_setup_plugin,
        dashboard.ui.comboBox_sa_capture_setup_action,
    ):
        combo.blockSignals(True)
        combo.clear()
        combo.blockSignals(False)
        combo.setEnabled(False)

    dashboard.ui.pushButton_sa_capture_parameters_customize.setText("Customize")
    dashboard.ui.pushButton_sa_capture_parameters_customize.setEnabled(False)
    dashboard.ui.label_sa_capture_setup_info.setText("Query the selected Sensor Node for capture actions.")
    _clear_sa_capture_parameter_widgets(dashboard)


def _populate_sa_capture_actions_for_plugin(
    dashboard: QtCore.QObject,
    preferred_action: str = "",
):
    """Populate Capture actions for the selected Plugin."""
    plugin_name = str(dashboard.ui.comboBox_sa_capture_setup_plugin.currentText() or "").strip()
    action_combo = dashboard.ui.comboBox_sa_capture_setup_action
    matches = []

    action_combo.blockSignals(True)
    action_combo.clear()
    for record in getattr(dashboard, "sa_capture_filtered_actions", []) or []:
        if not isinstance(record, dict):
            continue
        if str(record.get("plugin") or "").strip() != plugin_name:
            continue
        action_name = str(record.get("action") or "").strip()
        if action_name:
            matches.append(record)
            action_combo.addItem(action_name, record)

    preferred_action = str(preferred_action or "").strip()
    if preferred_action:
        index = action_combo.findText(preferred_action, QtCore.Qt.MatchExactly)
        if index >= 0:
            action_combo.setCurrentIndex(index)
    if action_combo.currentIndex() < 0 and action_combo.count() > 0:
        action_combo.setCurrentIndex(0)
    action_combo.blockSignals(False)

    action_combo.setEnabled(
        bool(matches)
        and _sa_capture_selected_node_available(dashboard)
        and not bool(getattr(dashboard, "sa_capture_running", False))
    )

    if matches:
        _slotSA_CaptureActionChanged(dashboard)
    else:
        dashboard.sa_capture_selected_plugin = ""
        dashboard.sa_capture_selected_action = ""
        dashboard.ui.pushButton_sa_capture_parameters_customize.setEnabled(False)
        _clear_sa_capture_parameter_widgets(dashboard)


def _filter_sa_capture_action_catalog(
    dashboard: QtCore.QObject,
    preferred_plugin: str = "",
    preferred_action: str = "",
):
    """Filter the cached Capture catalog by selected hardware."""
    hardware_type = str(_sa_capture_selected_hardware(dashboard).get("hardware_type") or "").strip()
    filtered = []

    for record in getattr(dashboard, "sa_capture_action_catalog", []) or []:
        if not isinstance(record, dict):
            continue
        plugin_name = str(record.get("plugin") or "").strip()
        action_name = str(record.get("action") or "").strip()
        if not plugin_name or not action_name:
            continue

        compatible = record.get("hardware", []) or []
        if compatible and not any(
            _sa_capture_hardware_matches(value, hardware_type)
            for value in compatible
        ):
            continue
        filtered.append(record)

    dashboard.sa_capture_filtered_actions = filtered
    plugin_combo = dashboard.ui.comboBox_sa_capture_setup_plugin
    current_plugin = str(preferred_plugin or plugin_combo.currentText() or "").strip()
    plugins = sorted(
        {
            str(record.get("plugin") or "").strip()
            for record in filtered
            if str(record.get("plugin") or "").strip()
        },
        key=str.lower,
    )

    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.addItems(plugins)
    if current_plugin:
        index = plugin_combo.findText(current_plugin, QtCore.Qt.MatchExactly)
        if index >= 0:
            plugin_combo.setCurrentIndex(index)
    if plugin_combo.currentIndex() < 0 and plugin_combo.count() > 0:
        plugin_combo.setCurrentIndex(0)
    plugin_combo.blockSignals(False)
    plugin_combo.setEnabled(
        plugin_combo.count() > 0
        and _sa_capture_selected_node_available(dashboard)
        and not bool(getattr(dashboard, "sa_capture_running", False))
    )

    _clear_sa_capture_parameter_widgets(dashboard)
    _populate_sa_capture_actions_for_plugin(dashboard, preferred_action)


def _refresh_sa_capture_hardware(dashboard: QtCore.QObject):
    """Populate Capture Hardware with SDRs configured on the selected node."""
    combo = dashboard.ui.comboBox_sa_capture_setup_hardware
    records = []

    if _sa_capture_selected_node_available(dashboard):
        try:
            display_names = fissure.utils.hardware.selectedNodeHardwareDisplayNames(
                dashboard,
                "sdrs",
            )
        except Exception as error:
            dashboard.logger.debug(f"[Capture] Could not load hardware: {error}")
            display_names = []

        for display_name in display_names:
            try:
                hardware_type, *_ = fissure.utils.hardware.hardwareDisplayNameLookup(
                    dashboard,
                    display_name,
                    "iq",
                )
            except Exception:
                continue

            if str(display_name or "").strip() and str(hardware_type or "").strip():
                records.append(
                    {
                        "display_name": str(display_name),
                        "hardware_type": str(hardware_type),
                    }
                )

    signature = tuple((record["display_name"], record["hardware_type"]) for record in records)
    if getattr(dashboard, "sa_capture_hardware_signature", None) == signature:
        return

    dashboard.sa_capture_hardware_signature = signature
    current_text = str(combo.currentText() or "").strip()
    combo.blockSignals(True)
    combo.clear()
    for record in records:
        combo.addItem(record["display_name"], record)
    index = combo.findText(current_text, QtCore.Qt.MatchExactly)
    if index >= 0:
        combo.setCurrentIndex(index)
    elif combo.count() > 0:
        combo.setCurrentIndex(0)
    combo.blockSignals(False)

    combo.setEnabled(bool(records) and not bool(getattr(dashboard, "sa_capture_running", False)))
    _filter_sa_capture_action_catalog(dashboard)


def _create_sa_capture_parameter_widget(parent, parameter: dict):
    """Create one editor from a generic capture action-schema parameter."""
    parameter_type = str(parameter.get("type", "string") or "string").strip().lower()
    name = str(parameter.get("name") or "").strip()
    default = parameter.get("default", "")
    options = parameter.get("options", []) or []

    if isinstance(options, list) and options:
        widget = QtWidgets.QComboBox(parent)
        widget.addItems([str(option) for option in options])
        index = widget.findText(str(default), QtCore.Qt.MatchExactly)
        if index >= 0:
            widget.setCurrentIndex(index)
    elif parameter_type in {"int", "integer"}:
        widget = QtWidgets.QSpinBox(parent)
        widget.setRange(int(parameter.get("min", -2147483647)), int(parameter.get("max", 2147483647)))
        widget.setSingleStep(int(parameter.get("step", 1)))
        widget.setValue(int(default or 0))
    elif parameter_type in {"float", "double", "number"}:
        widget = QtWidgets.QDoubleSpinBox(parent)
        widget.setDecimals(int(parameter.get("decimals", 6)))
        widget.setRange(float(parameter.get("min", -1e12)), float(parameter.get("max", 1e12)))
        widget.setSingleStep(float(parameter.get("step", 1.0)))
        widget.setValue(float(default or 0.0))
    elif parameter_type in {"bool", "boolean"}:
        widget = QtWidgets.QCheckBox(parent)
        widget.setChecked(
            default.strip().lower() in {"true", "1", "yes", "on", "enabled"}
            if isinstance(default, str)
            else bool(default)
        )
    elif parameter_type == "label":
        widget = QtWidgets.QLabel(str(default or ""), parent)
        widget.setWordWrap(True)
        widget.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
    else:
        widget = QtWidgets.QLineEdit(str(default or ""), parent)

    widget.setObjectName(f"sa_capture_parameter_{name}")
    widget.setProperty(
        "uiRole",
        "captureParameterInfo" if parameter_type == "label" else "captureParameterEditor",
    )
    description = str(parameter.get("description") or "").strip()
    if description:
        widget.setToolTip(description)
    return widget


def _sa_capture_parameter_value(widget):
    if isinstance(widget, QtWidgets.QComboBox):
        return widget.currentText()
    if isinstance(widget, (QtWidgets.QDoubleSpinBox, QtWidgets.QSpinBox)):
        return widget.value()
    if isinstance(widget, QtWidgets.QCheckBox):
        return widget.isChecked()
    if isinstance(widget, QtWidgets.QLineEdit):
        return widget.text()
    if isinstance(widget, QtWidgets.QLabel):
        return widget.text()
    return None


def _sa_capture_set_parameter_value(record: dict, value) -> bool:
    widget = record.get("widget") if isinstance(record, dict) else None
    if widget is None:
        return False

    try:
        if isinstance(widget, QtWidgets.QComboBox):
            index = widget.findText(str(value), QtCore.Qt.MatchExactly)
            if index >= 0:
                widget.setCurrentIndex(index)
                return True
            return False
        if isinstance(widget, QtWidgets.QDoubleSpinBox):
            widget.setValue(float(value))
            return True
        if isinstance(widget, QtWidgets.QSpinBox):
            widget.setValue(int(round(float(value))))
            return True
        if isinstance(widget, QtWidgets.QCheckBox):
            if isinstance(value, str):
                value = value.strip().lower() in {"true", "1", "yes", "on", "enabled"}
            widget.setChecked(bool(value))
            return True
        if isinstance(widget, QtWidgets.QLineEdit):
            widget.setText(str(value))
            return True
    except Exception:
        return False
    return False


def _apply_sa_capture_soi_prefill(dashboard: QtCore.QObject):
    """Apply compatible values from the selected SOI to the loaded action schema."""
    _soi_key, soi = _sa_capture_selected_soi(dashboard)
    if not soi:
        return

    widgets = getattr(dashboard, "sa_capture_parameter_widgets", {}) or {}
    frequency = _sa_sois_value(soi, "frequency_mhz", "center_frequency_mhz")
    sample_rate_msps = _sa_sois_value(soi, "sample_rate_msps")
    display_name = _sa_sois_display_name(soi)

    if frequency not in (None, "", "None"):
        for name in ("frequency_mhz", "rx_frequency", "center_frequency_mhz"):
            if name in widgets:
                _sa_capture_set_parameter_value(widgets[name], frequency)

    if sample_rate_msps not in (None, "", "None") and "sample_rate_msps" in widgets:
        _sa_capture_set_parameter_value(widgets["sample_rate_msps"], sample_rate_msps)

    if "description" in widgets:
        current = str(_sa_capture_parameter_value(widgets["description"].get("widget")) or "").strip()
        schema_default = str(widgets["description"].get("schema", {}).get("default", "") or "").strip()
        if not current or current == schema_default:
            _sa_capture_set_parameter_value(widgets["description"], f"Capture from {display_name}")

    _update_sa_capture_estimate(dashboard)


def _connect_sa_capture_parameter_updates(dashboard: QtCore.QObject, widget):
    """Refresh the compact execution estimate when a capture parameter changes."""
    callback = lambda *_args: _update_sa_capture_estimate(dashboard)
    if isinstance(widget, QtWidgets.QComboBox):
        widget.currentIndexChanged.connect(callback)
    elif isinstance(widget, (QtWidgets.QDoubleSpinBox, QtWidgets.QSpinBox)):
        widget.valueChanged.connect(callback)
    elif isinstance(widget, QtWidgets.QCheckBox):
        widget.toggled.connect(callback)
    elif isinstance(widget, QtWidgets.QLineEdit):
        widget.textChanged.connect(callback)


def _sa_capture_parameter_by_names(dashboard: QtCore.QObject, *names):
    widgets = getattr(dashboard, "sa_capture_parameter_widgets", {}) or {}
    for name in names:
        record = widgets.get(name)
        if isinstance(record, dict) and record.get("widget") is not None:
            return _sa_capture_parameter_value(record["widget"])
    return None


def _format_sa_capture_size(byte_count: float) -> str:
    try:
        value = max(0.0, float(byte_count))
    except Exception:
        return ""

    units = ["B", "KB", "MB", "GB", "TB"]
    index = 0
    while value >= 1000.0 and index < len(units) - 1:
        value /= 1000.0
        index += 1
    return f"{value:.0f} {units[index]}" if index < 2 else f"{value:.1f} {units[index]}"


def _update_sa_capture_estimate(dashboard: QtCore.QObject):
    """Show a compact preflight estimate for conventional capture parameters."""
    if not bool(getattr(dashboard, "sa_capture_customized", False)):
        dashboard.ui.label_sa_capture_execution_info.setText(
            "Customize a capture action to preview the acquisition request."
        )
        return

    frequency = _sa_capture_parameter_by_names(
        dashboard,
        "frequency_mhz",
        "rx_frequency",
        "center_frequency_mhz",
    )
    sample_rate = _sa_capture_parameter_by_names(dashboard, "sample_rate_msps")
    duration = _sa_capture_parameter_by_names(dashboard, "duration_s", "duration_per_capture_s")
    count = _sa_capture_parameter_by_names(dashboard, "number_of_files", "number_of_captures")
    interval = _sa_capture_parameter_by_names(dashboard, "file_interval", "capture_interval_s")
    data_type = str(_sa_capture_parameter_by_names(dashboard, "data_type") or "").strip().lower()

    pieces = []
    try:
        pieces.append(f"{float(frequency):.3f} MHz")
    except Exception:
        pass
    try:
        pieces.append(f"{float(sample_rate):.3f} MS/s")
    except Exception:
        pass

    duration_value = None
    count_value = 1
    interval_value = 0.0
    try:
        duration_value = max(0.0, float(duration))
        count_value = max(1, int(round(float(count or 1))))
        pieces.append(
            f"{duration_value:g} s × {count_value}"
            if count_value > 1
            else f"{duration_value:g} s"
        )
    except Exception:
        duration_value = None

    try:
        interval_value = max(0.0, float(interval or 0.0))
    except Exception:
        interval_value = 0.0

    if (
        sample_rate not in (None, "", "None")
        and duration_value is not None
        and any(token in data_type for token in ("complex float 32", "complex float32", "cf32", "fc32", "gr_complex"))
    ):
        try:
            estimated_bytes = float(sample_rate) * 1e6 * duration_value * count_value * 8.0
            pieces.append(f"~{_format_sa_capture_size(estimated_bytes)}")
        except Exception:
            pass

    if not pieces:
        dashboard.ui.label_sa_capture_execution_info.setText(
            "Capture parameters are ready. Review them before starting."
        )
        return

    text = " | ".join(pieces)
    if duration_value is not None and count_value > 1:
        total_window = duration_value * count_value + interval_value * (count_value - 1)
        text += f"\nTotal acquisition window: {total_window:g} s"

    dashboard.ui.label_sa_capture_execution_info.setText(text)


def _collect_sa_capture_parameters(dashboard: QtCore.QObject) -> dict:
    """Collect Capture schema values plus selected hardware identity."""
    parameters = {}
    for name, record in (getattr(dashboard, "sa_capture_parameter_widgets", {}) or {}).items():
        if not isinstance(record, dict):
            continue
        widget = record.get("widget")
        schema = record.get("schema", {})
        if widget is None or str(schema.get("type") or "").strip().lower() == "label":
            continue
        parameters[name] = _sa_capture_parameter_value(widget)

    display_name = str(_sa_capture_selected_hardware(dashboard).get("display_name") or "").strip()
    if not display_name:
        raise ValueError("Select Capture hardware.")

    (
        hardware_type,
        hardware_uuid,
        hardware_radio_name,
        hardware_serial,
        hardware_interface,
        hardware_ip,
        hardware_daughterboard,
    ) = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, display_name, "iq")

    raw_serial = {"HackRF", "RTL2832U", "bladeRF", "bladeRF 2.0", "RSPduo", "RSPdx", "RSPdx R2"}
    zero_default = {"RTL2832U", "bladeRF", "bladeRF 2.0", "RSPduo", "RSPdx", "RSPdx R2"}
    if hardware_serial:
        serial_argument = hardware_serial if hardware_type in raw_serial else f"serial={hardware_serial}"
    elif hardware_type == "HackRF":
        serial_argument = ""
    elif hardware_type in zero_default:
        serial_argument = "0"
    else:
        serial_argument = "False"

    parameters.update(
        {
            "operation_id": str(uuid.uuid4()),
            "requester": "dashboard",
            "hardware_display_name": display_name,
            "hardware_type": hardware_type,
            "hardware_uuid": hardware_uuid,
            "hardware_radio_name": hardware_radio_name,
            "hardware_serial": hardware_serial,
            "hardware_serial_argument": serial_argument,
            "hardware_interface": hardware_interface,
            "hardware_ip": hardware_ip,
            "hardware_daughterboard": hardware_daughterboard,
        }
    )

    if "frequency_mhz" in parameters and "rx_frequency" not in parameters:
        parameters["rx_frequency"] = parameters["frequency_mhz"]
    return parameters


def _set_sa_capture_start_stop_button(dashboard: QtCore.QObject, running: bool):
    button = dashboard.ui.pushButton_sa_capture_start_stop
    button.setText("Stop" if running else "Start")
    button.setProperty("running", bool(running))
    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


def _set_sa_capture_controls_locked(dashboard: QtCore.QObject, locked: bool):
    available = _sa_capture_selected_node_available(dashboard)
    has_action = bool(
        getattr(dashboard, "sa_capture_selected_plugin", "")
        and getattr(dashboard, "sa_capture_selected_action", "")
    )

    dashboard.ui.comboBox_sa_capture_context_soi.setEnabled(not locked)
    dashboard.ui.comboBox_sa_capture_setup_hardware.setEnabled(
        available and dashboard.ui.comboBox_sa_capture_setup_hardware.count() > 0 and not locked
    )
    dashboard.ui.comboBox_sa_capture_setup_plugin.setEnabled(
        available and dashboard.ui.comboBox_sa_capture_setup_plugin.count() > 0 and not locked
    )
    dashboard.ui.comboBox_sa_capture_setup_action.setEnabled(
        available and dashboard.ui.comboBox_sa_capture_setup_action.count() > 0 and not locked
    )
    dashboard.ui.pushButton_sa_capture_setup_query.setEnabled(
        available
        and dashboard.ui.comboBox_sa_capture_setup_hardware.count() > 0
        and not getattr(dashboard, "sa_capture_query_pending", False)
        and not locked
    )
    dashboard.ui.pushButton_sa_capture_parameters_customize.setEnabled(
        available and has_action and not locked
    )

    for record in (getattr(dashboard, "sa_capture_parameter_widgets", {}) or {}).values():
        widget = record.get("widget") if isinstance(record, dict) else None
        if widget is not None:
            widget.setEnabled(not locked)


def _set_sa_capture_running(
    dashboard: QtCore.QObject,
    node_uid: str,
    operation_id: str,
):
    dashboard.sa_capture_running = True
    dashboard.sa_capture_node_uid = str(node_uid or "")
    dashboard.sa_capture_operation_id = str(operation_id or "")
    dashboard.sa_capture_last_requested_operation_id = dashboard.sa_capture_operation_id
    dashboard.ui.label_sa_capture_execution_status.setText("Capturing...")
    dashboard.ui.label_sa_capture_execution_operation_id.setText(dashboard.sa_capture_operation_id or "—")
    _set_sa_capture_start_stop_button(dashboard, True)
    _set_sa_capture_controls_locked(dashboard, True)
    dashboard.ui.pushButton_sa_capture_start_stop.setEnabled(True)


def _set_sa_capture_stopped(
    dashboard: QtCore.QObject,
    status_text: str = "Idle",
):
    """Return Capture to an idle state while preserving the last operation ID."""
    last_operation_id = str(
        getattr(dashboard, "sa_capture_operation_id", "")
        or getattr(dashboard, "sa_capture_last_requested_operation_id", "")
        or ""
    ).strip()

    dashboard.sa_capture_running = False
    dashboard.sa_capture_node_uid = ""
    dashboard.sa_capture_operation_id = ""

    dashboard.ui.label_sa_capture_execution_status.setText(
        str(status_text or "Idle")
    )
    dashboard.ui.label_sa_capture_execution_operation_id.setText(
        last_operation_id or "—"
    )

    _set_sa_capture_start_stop_button(dashboard, False)
    _set_sa_capture_controls_locked(dashboard, False)
    dashboard.ui.pushButton_sa_capture_start_stop.setEnabled(
        _sa_capture_selected_node_available(dashboard)
        and bool(getattr(dashboard, "sa_capture_customized", False))
    )


def _format_sa_capture_time(value) -> str:
    """Format Capture timestamps without fractional-second noise."""
    if value in (None, "", "None"):
        return "—"

    try:
        numeric = float(value)
        return datetime.fromtimestamp(
            numeric,
            tz=timezone.utc,
        ).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (TypeError, ValueError, OverflowError):
        pass

    text = str(value).strip()
    if not text:
        return "—"

    try:
        normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
        timestamp = datetime.fromisoformat(normalized)

        if timestamp.tzinfo is not None:
            if timestamp.utcoffset() == timezone.utc.utcoffset(timestamp):
                return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            return timestamp.strftime("%Y-%m-%d %H:%M:%S %z")

        return timestamp.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text.replace("T", " ").split(".")[0]


def _sa_capture_duration_from_metadata(metadata: dict):
    duration = metadata.get("duration_s")
    if duration not in (None, "", "None"):
        try:
            return float(duration)
        except Exception:
            pass

    try:
        file_length = float(metadata.get("file_length"))
        sample_rate = float(metadata.get("sample_rate_msps")) * 1e6
        if sample_rate > 0:
            return file_length / sample_rate
    except Exception:
        pass
    return None


def _update_sa_capture_link_button(dashboard: QtCore.QObject):
    button = dashboard.ui.pushButton_sa_capture_last_capture_link_to_soi
    artifact_id = str(getattr(dashboard, "sa_capture_artifact_id", "") or "").strip()
    _soi_key, soi = _sa_capture_selected_soi(dashboard)

    if not artifact_id or not soi:
        button.setText("Link to SOI")
        button.setEnabled(False)
        return

    linked = artifact_id in collect_soi_artifact_ids(soi)
    button.setText("Linked to SOI" if linked else "Link to SOI")
    button.setEnabled(not linked)


def _update_sa_capture_artifact_buttons(dashboard: QtCore.QObject):
    """Refresh Download/Open controls from the shared Dashboard artifact cache."""
    artifact_id = str(getattr(dashboard, "sa_capture_artifact_id", "") or "").strip()
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    local_path = controller.get_local_path(artifact_id) if controller is not None and artifact_id else None

    download_button = dashboard.ui.pushButton_sa_capture_last_capture_download
    open_button = dashboard.ui.pushButton_sa_capture_last_capture_open_folder

    download_button.setText("Downloaded" if local_path else "Download")
    download_button.setEnabled(bool(artifact_id) and not bool(local_path))
    download_button.setToolTip(
        str(local_path)
        if local_path
        else (f"Download capture Artifact {artifact_id}" if artifact_id else "No capture Artifact is available.")
    )
    open_button.setEnabled(bool(local_path))
    open_button.setToolTip(str(local_path or ""))

    dashboard.ui.pushButton_sa_capture_last_capture_inspect.setEnabled(bool(artifact_id))
    _update_sa_capture_link_button(dashboard)


def _populate_sa_capture_last_capture(dashboard: QtCore.QObject, artifact_record: dict):
    """Render the most recent completed Capture artifact."""
    metadata = artifact_record.get("metadata", {}) if isinstance(artifact_record, dict) else {}
    if not isinstance(metadata, dict):
        metadata = {}

    artifact_id = str(
        artifact_record.get("artifact_id", "")
        or artifact_record.get("id", "")
        or ""
    ).strip()
    dashboard.sa_capture_artifact_id = artifact_id
    dashboard.sa_capture_artifact_record = dict(artifact_record)

    recorded_files = metadata.get("recorded_files", [])
    if not isinstance(recorded_files, list):
        recorded_files = []
    file_name = os.path.basename(str(recorded_files[0])) if recorded_files else str(artifact_record.get("name") or "Capture")

    recorded_count = metadata.get("recorded_file_count", metadata.get("requested_number_of_files"))
    if recorded_count in (None, "", "None"):
        recorded_count = artifact_record.get("file_count", 0)

    duration = _sa_capture_duration_from_metadata(metadata)
    frequency = metadata.get("frequency_mhz", "")
    sample_rate = metadata.get("sample_rate_msps", "")
    total_size = artifact_record.get("total_size", 0)
    captured = artifact_record.get("created_at") or metadata.get("created_at") or artifact_record.get("time")

    dashboard.ui.label2_sa_capture_last_capture_file_name.setText(file_name or "—")
    dashboard.ui.label2_sa_capture_last_capture_artifact_id.setText(artifact_id or "—")
    dashboard.ui.label2_sa_capture_last_capture_artifact_id.setToolTip(artifact_id)
    dashboard.ui.label2_sa_capture_last_capture_files.setText(str(recorded_count or "—"))
    dashboard.ui.label2_sa_capture_last_capture_total_size.setText(
        _format_sa_capture_size(total_size) if total_size else "—"
    )
    dashboard.ui.label2_sa_capture_last_capture_frequency.setText(
        _sa_sois_format_frequency(frequency)
    )
    try:
        sample_rate_text = f"{float(sample_rate):.3f} MS/s"
    except Exception:
        sample_rate_text = str(sample_rate or "—")
    dashboard.ui.label2_sa_capture_last_capture_sample_rate.setText(sample_rate_text)
    dashboard.ui.label2_sa_capture_last_capture_duration.setText(
        f"{duration:g} s" if duration is not None else "—"
    )
    dashboard.ui.label2_sa_capture_last_capture_captured.setText(_format_sa_capture_time(captured))

    dashboard.ui.stackedWidget_sa_capture_last_capture.setCurrentWidget(
        dashboard.ui.page_sa_capture_last_capture_capture
    )
    _update_sa_capture_artifact_buttons(dashboard)




def _request_sa_capture_artifact_refresh(
    dashboard: QtCore.QObject,
    artifact_record: dict,
):
    """Request canonical metadata after a lightweight Artifact notification."""
    if not isinstance(artifact_record, dict):
        return
    if artifact_record.get("metadata") or artifact_record.get("files"):
        return

    node_uid = str(
        artifact_record.get("source_id", "")
        or artifact_record.get("node_uid", "")
        or getattr(dashboard, "sa_capture_node_uid", "")
        or getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()
    if not node_uid:
        return

    try:
        asyncio.ensure_future(
            dashboard.backend.tacticalNodeArtifactsRefresh(node_uid)
        )
    except Exception as error:
        dashboard.logger.debug(
            f"[Capture] Could not request canonical Artifact metadata: {error}"
        )


def handle_sa_capture_artifact_complete(
    dashboard: QtCore.QObject,
    artifact_record: dict,
):
    """Finish the active Capture run when its matching Artifact metadata arrives."""
    if not isinstance(artifact_record, dict):
        return

    operation_id = str(artifact_record.get("operation_id", "") or "").strip()
    active_operation_id = str(getattr(dashboard, "sa_capture_operation_id", "") or "").strip()
    last_requested_operation_id = str(
        getattr(dashboard, "sa_capture_last_requested_operation_id", "") or ""
    ).strip()
    if (
        not operation_id
        or operation_id not in {active_operation_id, last_requested_operation_id}
    ):
        return

    was_running = bool(getattr(dashboard, "sa_capture_running", False))
    _populate_sa_capture_last_capture(dashboard, artifact_record)
    _request_sa_capture_artifact_refresh(dashboard, artifact_record)
    if was_running:
        _set_sa_capture_stopped(dashboard, "Completed")


def refresh_sa_capture_artifact_state(dashboard: QtCore.QObject):
    """Refresh Last Capture buttons after an artifact transfer state change."""
    _update_sa_capture_artifact_buttons(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_CaptureSoiChanged(dashboard: QtCore.QObject):
    """Update Capture context and prefill the loaded schema when the SOI changes."""
    _update_sa_capture_soi_details(dashboard)
    if not bool(getattr(dashboard, "sa_capture_running", False)):
        _apply_sa_capture_soi_prefill(dashboard)
    _update_sa_capture_link_button(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_CaptureHardwareChanged(dashboard: QtCore.QObject):
    """Refilter Capture actions when Hardware changes."""
    if not bool(getattr(dashboard, "sa_capture_running", False)):
        _filter_sa_capture_action_catalog(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_CapturePluginChanged(dashboard: QtCore.QObject):
    """Populate Capture actions for the selected Plugin."""
    if not bool(getattr(dashboard, "sa_capture_running", False)):
        _populate_sa_capture_actions_for_plugin(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_CaptureActionChanged(dashboard: QtCore.QObject):
    """Track the selected Capture action and invalidate old parameters."""
    if bool(getattr(dashboard, "sa_capture_running", False)):
        return

    record = dashboard.ui.comboBox_sa_capture_setup_action.currentData()
    if not isinstance(record, dict):
        dashboard.sa_capture_selected_plugin = ""
        dashboard.sa_capture_selected_action = ""
        dashboard.ui.pushButton_sa_capture_parameters_customize.setEnabled(False)
        _clear_sa_capture_parameter_widgets(dashboard)
        return

    plugin_name = str(record.get("plugin") or "").strip()
    action_name = str(record.get("action") or "").strip()
    same_selection = (
        plugin_name == str(getattr(dashboard, "sa_capture_selected_plugin", "") or "").strip()
        and action_name == str(getattr(dashboard, "sa_capture_selected_action", "") or "").strip()
    )

    dashboard.sa_capture_selected_plugin = plugin_name
    dashboard.sa_capture_selected_action = action_name
    compatible = [str(value) for value in (record.get("hardware", []) or []) if str(value).strip()]
    dashboard.ui.label_sa_capture_setup_info.setText(
        f"{plugin_name}: {action_name}\n"
        f"Hardware: {', '.join(compatible) if compatible else 'No hardware restriction'}"
    )
    dashboard.ui.pushButton_sa_capture_parameters_customize.setText("Customize")
    dashboard.ui.pushButton_sa_capture_parameters_customize.setEnabled(
        bool(plugin_name and action_name) and _sa_capture_selected_node_available(dashboard)
    )

    if not same_selection:
        _clear_sa_capture_parameter_widgets(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_CaptureQueryClicked(dashboard: QtCore.QObject):
    """Query the selected Sensor Node for Capture-capable actions."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid or not _sa_capture_selected_node_available(dashboard):
        return
    if dashboard.ui.comboBox_sa_capture_setup_hardware.count() == 0:
        return

    dashboard.sa_capture_query_pending = True
    dashboard.ui.pushButton_sa_capture_setup_query.setEnabled(False)
    dashboard.ui.pushButton_sa_capture_setup_query.setText("Querying...")
    dashboard.ui.label_sa_capture_setup_info.setText("Querying available Capture actions...")
    await dashboard.backend.queryPluginActions(
        node_uid,
        context=ACTION_QUERY_CONTEXT,
        scope="all_plugins",
        include_tags=["sa.capture"],
    )


def handle_sa_capture_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    """Cache Capture actions and apply the selected-hardware filter."""
    if context != ACTION_QUERY_CONTEXT:
        return
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return

    dashboard.sa_capture_query_pending = False
    dashboard.sa_capture_action_catalog_node_uid = str(node_uid or "").strip()
    dashboard.sa_capture_action_catalog = actions if isinstance(actions, list) else []
    dashboard.ui.pushButton_sa_capture_setup_query.setText("Query Actions")
    dashboard.ui.pushButton_sa_capture_setup_query.setEnabled(
        _sa_capture_selected_node_available(dashboard)
        and dashboard.ui.comboBox_sa_capture_setup_hardware.count() > 0
    )
    _filter_sa_capture_action_catalog(dashboard)

    total = len(dashboard.sa_capture_action_catalog)
    visible = len(dashboard.sa_capture_filtered_actions)
    dashboard.ui.label_sa_capture_setup_info.setText(
        f"{visible} compatible Capture action(s) shown from {total} available."
        if total
        else "No Capture-capable plugin actions were returned by this Sensor Node."
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_CaptureCustomizeClicked(dashboard: QtCore.QObject):
    """Query the selected Capture action schema."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    record = dashboard.ui.comboBox_sa_capture_setup_action.currentData()
    if not node_uid or not _sa_capture_selected_node_available(dashboard) or not isinstance(record, dict):
        return

    plugin_name = str(record.get("plugin") or "").strip()
    action_name = str(record.get("action") or "").strip()
    if not plugin_name or not action_name:
        return

    _clear_sa_capture_parameter_widgets(dashboard)
    dashboard.ui.pushButton_sa_capture_parameters_customize.setText("Loading...")
    dashboard.ui.pushButton_sa_capture_parameters_customize.setEnabled(False)
    await dashboard.backend.queryPluginActionSchema(
        node_uid,
        plugin_name,
        action_name,
        context=ACTION_SCHEMA_CONTEXT,
    )


def handle_sa_capture_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
):
    """Render the selected Capture action schema in the Parameters card."""
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return
    if str(plugin_name or "").strip() != str(getattr(dashboard, "sa_capture_selected_plugin", "") or "").strip():
        return
    if str(action_name or "").strip() != str(getattr(dashboard, "sa_capture_selected_action", "") or "").strip():
        return

    parameters = parameters if isinstance(parameters, list) else []
    _clear_sa_capture_parameter_widgets(dashboard)
    dashboard.sa_capture_current_schema = {
        "plugin": str(plugin_name or "").strip(),
        "action": str(action_name or "").strip(),
        "params": [dict(parameter) for parameter in parameters if isinstance(parameter, dict)],
    }

    contents = dashboard.ui.scrollAreaWidgetContents_sa_capture_parameters
    layout = contents.layout()
    count = 0

    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name") or "").strip()
        if not name:
            continue

        label = QtWidgets.QLabel(f"{str(parameter.get('label') or name).strip()}:", contents)
        label.setObjectName(f"label2_sa_capture_parameter_{name}")
        label.setProperty("uiRole", "captureParameterLabel")
        description = str(parameter.get("description") or "").strip()
        if description:
            label.setToolTip(description)

        widget = _create_sa_capture_parameter_widget(contents, parameter)
        layout.addRow(label, widget)
        dashboard.sa_capture_parameter_widgets[name] = {
            "widget": widget,
            "schema": dict(parameter),
        }
        _connect_sa_capture_parameter_updates(dashboard, widget)
        count += 1

    if count == 0:
        label = QtWidgets.QLabel("No parameters required for this action.", contents)
        label.setObjectName("label2_sa_capture_no_parameters")
        label.setProperty("uiRole", "captureParameterInfo")
        layout.addRow(label)

    dashboard.sa_capture_customized = True
    _apply_sa_capture_soi_prefill(dashboard)
    _update_sa_capture_estimate(dashboard)
    dashboard.ui.pushButton_sa_capture_parameters_customize.setText("Customize")
    dashboard.ui.pushButton_sa_capture_parameters_customize.setEnabled(
        _sa_capture_selected_node_available(dashboard)
    )
    dashboard.ui.pushButton_sa_capture_start_stop.setEnabled(
        _sa_capture_selected_node_available(dashboard)
        and not bool(getattr(dashboard, "sa_capture_running", False))
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_CaptureStartStopClicked(dashboard: QtCore.QObject):
    """Start or stop the selected Capture action."""
    if bool(getattr(dashboard, "sa_capture_running", False)):
        node_uid = str(getattr(dashboard, "sa_capture_node_uid", "") or "").strip()
        operation_id = str(getattr(dashboard, "sa_capture_operation_id", "") or "").strip()
        if not node_uid or not operation_id:
            await Qt5.async_ok_dialog(dashboard, "Could not identify the active Capture operation to stop.")
            return

        dashboard.ui.label_sa_capture_execution_status.setText("Stopping...")
        try:
            await dashboard.backend.stopPluginOperation(node_uid, operation_id)
        except Exception as error:
            dashboard.logger.error(f"Failed to stop Capture operation: {error}")
            _set_sa_capture_stopped(dashboard, "Stop Failed")
            return

        _set_sa_capture_stopped(dashboard, "Stopped")
        return

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid or not _sa_capture_selected_node_available(dashboard):
        await Qt5.async_ok_dialog(dashboard, "Select an online Sensor Node before starting Capture.")
        return
    if not bool(getattr(dashboard, "sa_capture_customized", False)):
        await Qt5.async_ok_dialog(dashboard, "Customize the Capture parameters before starting.")
        return

    plugin_name = str(getattr(dashboard, "sa_capture_selected_plugin", "") or "").strip()
    action_name = str(getattr(dashboard, "sa_capture_selected_action", "") or "").strip()
    if not plugin_name or not action_name:
        await Qt5.async_ok_dialog(dashboard, "Select a Capture action before starting.")
        return

    try:
        parameters = _collect_sa_capture_parameters(dashboard)
    except Exception as error:
        dashboard.logger.error(f"Failed to collect Capture parameters: {error}")
        await Qt5.async_ok_dialog(dashboard, "One or more Capture parameters are invalid.")
        return

    operation_id = str(parameters.get("operation_id") or "").strip()
    _set_sa_capture_running(dashboard, node_uid, operation_id)

    try:
        await dashboard.backend.tacticalNodeExecute(
            [node_uid],
            plugin_name,
            action_name,
            parameters,
        )
    except Exception:
        _set_sa_capture_stopped(dashboard, "Start Failed")
        raise


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_CaptureDownloadClicked(dashboard: QtCore.QObject):
    """Download the most recent Capture artifact and open its cache folder."""
    artifact_id = str(getattr(dashboard, "sa_capture_artifact_id", "") or "").strip()
    if not artifact_id:
        return

    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    if controller is None:
        await Qt5.async_ok_dialog(dashboard, "Artifact transfer is unavailable.")
        return

    local_path = controller.get_local_path(artifact_id)
    if local_path:
        _slotSA_CaptureOpenFolderClicked(dashboard)
        return

    button = dashboard.ui.pushButton_sa_capture_last_capture_download
    button.setText("Downloading...")
    button.setEnabled(False)
    try:
        await dashboard.backend.requestDashboardArtifactDownload(
            artifact_id,
            open_when_complete=True,
        )
    except Exception as error:
        dashboard.logger.error(f"Capture Artifact download failed: {error}")
        _update_sa_capture_artifact_buttons(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_CaptureOpenFolderClicked(dashboard: QtCore.QObject):
    """Open the verified Dashboard cache folder for the most recent Capture."""
    artifact_id = str(getattr(dashboard, "sa_capture_artifact_id", "") or "").strip()
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    local_path = controller.get_local_path(artifact_id) if controller is not None and artifact_id else None
    if not local_path:
        return

    open_path = local_path if os.path.isdir(local_path) else os.path.dirname(local_path)
    if open_path and os.path.isdir(open_path):
        try:
            subprocess.Popen(["xdg-open", open_path])
        except Exception as error:
            dashboard.logger.error(f"Could not open Capture Artifact folder: {error}")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_CaptureInspectClicked(dashboard: QtCore.QObject):
    """Open Inspection with the most recent Capture artifact as context."""
    artifact_id = str(getattr(dashboard, "sa_capture_artifact_id", "") or "").strip()
    if not artifact_id:
        return

    dashboard.signal_analysis_prefill_artifact_id = artifact_id
    dashboard.ui.tabWidget_signal_analysis.setCurrentWidget(dashboard.ui.tab_inspection)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_CaptureLinkToSoiClicked(dashboard: QtCore.QObject):
    """Explicitly link the most recent Capture artifact to the selected SOI."""
    artifact_id = str(getattr(dashboard, "sa_capture_artifact_id", "") or "").strip()
    operation_id = str(
        (getattr(dashboard, "sa_capture_artifact_record", {}) or {}).get("operation_id", "")
        or ""
    ).strip()
    soi_key, soi = _sa_capture_selected_soi(dashboard)
    if not artifact_id or not soi_key or not soi:
        return
    if artifact_id in collect_soi_artifact_ids(soi):
        _update_sa_capture_link_button(dashboard)
        return

    node_uid = str(soi.get("node_uid", "") or "").strip()
    soi_id = str(soi.get("soi_id", "") or "").strip()
    if not soi_id:
        await Qt5.async_ok_dialog(dashboard, "The selected SOI does not have a valid SOI ID.")
        return

    await dashboard.backend.signalAnalysisSoiUpdate(
        node_uid=node_uid,
        soi_id=soi_id,
        operation_id=operation_id,
        artifact_id=artifact_id,
    )
    await dashboard.backend.signalAnalysisSoisRefresh()


def initialize_sa_capture_controls(dashboard: QtCore.QObject):
    """Initialize the Signal Analysis Capture workflow."""
    dashboard.sa_capture_action_catalog = []
    dashboard.sa_capture_filtered_actions = []
    dashboard.sa_capture_action_catalog_node_uid = ""
    dashboard.sa_capture_hardware_signature = None
    dashboard.sa_capture_selected_plugin = ""
    dashboard.sa_capture_selected_action = ""
    dashboard.sa_capture_parameter_widgets = {}
    dashboard.sa_capture_current_schema = {}
    dashboard.sa_capture_customized = False
    dashboard.sa_capture_query_pending = False
    dashboard.sa_capture_running = False
    dashboard.sa_capture_node_uid = ""
    dashboard.sa_capture_operation_id = ""
    dashboard.sa_capture_last_requested_operation_id = ""
    dashboard.sa_capture_artifact_id = ""
    dashboard.sa_capture_artifact_record = {}

    icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", "select_node.png")
    if os.path.isfile(icon_path):
        dashboard.ui.label_sa_capture_select_sensor_node_image.setPixmap(QtGui.QPixmap(icon_path))
        dashboard.ui.label_sa_capture_select_sensor_node_image.setScaledContents(False)
        dashboard.ui.label_sa_capture_select_sensor_node_image.setAlignment(QtCore.Qt.AlignCenter)

    dashboard.ui.scrollArea_sa_capture_parameters.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    dashboard.ui.scrollArea_sa_capture_parameters.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
    for widget in (
        dashboard.ui.scrollArea_sa_capture_parameters,
        dashboard.ui.scrollArea_sa_capture_parameters.viewport(),
        dashboard.ui.scrollArea_sa_capture_parameters.widget(),
    ):
        if widget is not None:
            widget.setProperty("uiRole", "captureParameterPanel")

    dashboard.ui.pushButton_sa_capture_setup_query.setText("Query Actions")
    dashboard.ui.pushButton_sa_capture_setup_query.setEnabled(False)
    dashboard.ui.pushButton_sa_capture_parameters_customize.setText("Customize")
    dashboard.ui.pushButton_sa_capture_parameters_customize.setEnabled(False)
    _set_sa_capture_start_stop_button(dashboard, False)
    dashboard.ui.pushButton_sa_capture_start_stop.setEnabled(False)
    dashboard.ui.label_sa_capture_execution_status.setText("Unavailable")
    dashboard.ui.label_sa_capture_execution_operation_id.setText("—")
    dashboard.ui.label_sa_capture_execution_info.setText(
        "Customize a capture action to preview the acquisition request."
    )
    dashboard.ui.stackedWidget_sa_capture_last_capture.setCurrentWidget(
        dashboard.ui.page_sa_capture_last_capture_no_capture
    )
    dashboard.ui.pushButton_sa_capture_last_capture_download.setEnabled(False)
    dashboard.ui.pushButton_sa_capture_last_capture_open_folder.setEnabled(False)
    dashboard.ui.pushButton_sa_capture_last_capture_inspect.setEnabled(False)
    dashboard.ui.pushButton_sa_capture_last_capture_link_to_soi.setEnabled(False)

    _reset_sa_capture_action_selection(dashboard)
    refresh_sa_capture_soi_context(dashboard)
    update_sa_capture_selected_node_gate(dashboard)


def update_sa_capture_selected_node_gate(dashboard: QtCore.QObject):
    """Show Capture controls only when an online Sensor Node is selected."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    available = _sa_capture_selected_node_available(dashboard)
    running = bool(getattr(dashboard, "sa_capture_running", False))
    previous_uid = str(getattr(dashboard, "sa_capture_action_catalog_node_uid", "") or "").strip()

    dashboard.ui.stackedWidget_sa_capture.setCurrentWidget(
        dashboard.ui.page_sa_capture_controls
        if available or running
        else dashboard.ui.page_sa_capture_no_node
    )

    if node_uid != previous_uid and not running:
        dashboard.sa_capture_action_catalog_node_uid = node_uid
        dashboard.sa_capture_action_catalog = []
        dashboard.sa_capture_hardware_signature = None
        dashboard.sa_capture_query_pending = False
        dashboard.ui.pushButton_sa_capture_setup_query.setText("Query Actions")
        _reset_sa_capture_action_selection(dashboard)

    if not running:
        _refresh_sa_capture_hardware(dashboard)

    if running:
        _set_sa_capture_controls_locked(dashboard, True)
        _set_sa_capture_start_stop_button(dashboard, True)
        dashboard.ui.pushButton_sa_capture_start_stop.setEnabled(True)
        return

    _set_sa_capture_controls_locked(dashboard, False)
    _set_sa_capture_start_stop_button(dashboard, False)
    dashboard.ui.pushButton_sa_capture_start_stop.setEnabled(
        available and bool(getattr(dashboard, "sa_capture_customized", False))
    )
    dashboard.ui.label_sa_capture_execution_status.setText("Idle" if available else "Unavailable")


__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value) and value.__module__ == __name__
]
