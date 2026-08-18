from PyQt5 import QtCore, QtWidgets, QtGui
import os
import fissure.utils
import yaml
import datetime
from ..UI_Components import DetectorSelectionDialog
import qasync
import time
import asyncio
import ast
from fissure.Dashboard.Slots import AttackTabSlots
import json
import csv
import re
from fissure.utils.selected_node_utils import (
    selected_node_is_local,
    selected_node_is_remote,
    selected_node_is_ip,
    selected_node_is_meshtastic,
)


def initialize_sensor_nodes_autorun_controls(dashboard: QtCore.QObject):
    """Initialize the plugin-backed Sensor Node Autorun editor."""
    dashboard.sensor_nodes_autorun_action_catalog = []
    dashboard.sensor_nodes_autorun_filtered_actions = []
    dashboard.sensor_nodes_autorun_parameter_widgets = {}
    dashboard.sensor_nodes_autorun_selected_plugin = ""
    dashboard.sensor_nodes_autorun_selected_action = ""
    dashboard.sensor_nodes_autorun_state = "Idle"
    dashboard.sensor_nodes_autorun_source = ""
    dashboard.sensor_nodes_autorun_last_node_uid = ""
    dashboard.sensor_nodes_autorun_hardware_signature = None

    dashboard.ui.textEdit_sensor_nodes_autorun_timing_delay.setPlainText("0")
    dashboard.ui.textEdit_sensor_nodes_autorun_timing_interval.setPlainText("60")
    dashboard.ui.checkBox_sensor_nodes_autorun_timing_repeat.setChecked(False)
    dashboard.ui.textEdit_sensor_nodes_autorun_timing_interval.setEnabled(False)

    dashboard.ui.pushButton_sensor_nodes_autorun_start_stop.setText("Start")
    dashboard.ui.pushButton_sensor_nodes_autorun_start_stop.setProperty("running", False)
    dashboard.ui.label2_sensor_nodes_autorun_status.setText("Idle")

    select_node_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "select_node.png",
    )
    if os.path.isfile(select_node_icon_path):
        select_node_pixmap = QtGui.QPixmap(select_node_icon_path)
        dashboard.ui.label_sensor_nodes_autorun_select_sensor_node_image.setPixmap(select_node_pixmap)
        dashboard.ui.label_sensor_nodes_autorun_select_sensor_node_image.setScaledContents(False)
        dashboard.ui.label_sensor_nodes_autorun_select_sensor_node_image.setAlignment(QtCore.Qt.AlignCenter)

    _clear_sensor_nodes_autorun_parameter_widgets(dashboard)
    _refresh_sensor_nodes_autorun_hardware_filter(dashboard)
    update_sensor_nodes_autorun_selected_node_gate(dashboard)


def update_sensor_nodes_autorun_selected_node_gate(dashboard: QtCore.QObject):
    """Show the Autorun editor for the selected node and synchronize its runtime state."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    has_selected_node = bool(node_uid)

    if has_selected_node:
        node_state = (getattr(dashboard, "node_states", {}) or {}).get(node_uid)
        if isinstance(node_state, dict) and node_state.get("connected") is False:
            has_selected_node = False

    dashboard.ui.stackedWidget_sensor_nodes_autorun.setCurrentWidget(
        dashboard.ui.page_sensor_nodes_autorun_controls
        if has_selected_node
        else dashboard.ui.page_sensor_nodes_autorun_no_node
    )

    if not has_selected_node:
        return

    node_changed = dashboard.sensor_nodes_autorun_last_node_uid != node_uid

    if node_changed:
        dashboard.sensor_nodes_autorun_last_node_uid = node_uid
        dashboard.sensor_nodes_autorun_action_catalog = []
        dashboard.sensor_nodes_autorun_hardware_signature = None
        dashboard.sensor_nodes_autorun_source = ""
        dashboard.ui.comboBox_sensor_nodes_autorun_playlists.clear()
        _reset_sensor_nodes_autorun_action_selection(dashboard)

    _refresh_sensor_nodes_autorun_hardware_filter(dashboard)

    node_state = (getattr(dashboard, "node_states", {}) or {}).get(node_uid, {}) or {}
    heartbeat_autorun_state = str(node_state.get("autorun_state") or "Idle").strip() or "Idle"

    if node_changed or heartbeat_autorun_state != dashboard.sensor_nodes_autorun_state:
        dashboard.sensor_nodes_autorun_state = heartbeat_autorun_state

        if heartbeat_autorun_state == "Idle":
            dashboard.sensor_nodes_autorun_source = ""

        status_text = heartbeat_autorun_state
        if (
            dashboard.sensor_nodes_autorun_source
            and heartbeat_autorun_state in {"Waiting", "Running"}
        ):
            status_text += f" — {dashboard.sensor_nodes_autorun_source}"

        dashboard.ui.label2_sensor_nodes_autorun_status.setText(status_text)

        running = heartbeat_autorun_state in {"Waiting", "Running", "Stopping"}
        _set_sensor_nodes_autorun_start_stop_button(dashboard, running)
        dashboard.ui.pushButton_sensor_nodes_autorun_start_stop.setEnabled(
            heartbeat_autorun_state != "Stopping"
        )


def _refresh_sensor_nodes_autorun_hardware_filter(dashboard: QtCore.QObject):
    """Populate the Autorun hardware filter only when configured node hardware changes."""
    combo = dashboard.ui.comboBox_sensor_nodes_autorun_hardware
    display_names = fissure.utils.hardware.selectedNodeHardwareDisplayNames(dashboard, "autorun")

    hardware_records = []
    for display_name in display_names:
        hardware_type, *_ = fissure.utils.hardware.hardwareDisplayNameLookup(
            dashboard, display_name, "autorun"
        )
        hardware_records.append(
            (
                str(display_name or "").strip(),
                str(hardware_type or "").strip(),
            )
        )

    signature = tuple(hardware_records)
    if getattr(dashboard, "sensor_nodes_autorun_hardware_signature", None) == signature and combo.count() > 0:
        return

    dashboard.sensor_nodes_autorun_hardware_signature = signature
    current_text = str(combo.currentText() or "").strip()

    combo.blockSignals(True)
    combo.clear()
    combo.addItem("All Compatible", {"mode": "all", "hardware_type": ""})
    combo.addItem("No Hardware", {"mode": "none", "hardware_type": ""})

    for display_name, hardware_type in hardware_records:
        combo.addItem(
            display_name,
            {
                "mode": "hardware",
                "hardware_type": hardware_type,
                "display_name": display_name,
            },
        )

    restore_index = combo.findText(current_text, QtCore.Qt.MatchExactly)
    combo.setCurrentIndex(restore_index if restore_index >= 0 else 0)
    combo.blockSignals(False)
    _filter_sensor_nodes_autorun_action_catalog(dashboard)


def _reset_sensor_nodes_autorun_action_selection(dashboard: QtCore.QObject):
    """Clear the current Autorun plugin/action selection and parameter controls."""
    dashboard.sensor_nodes_autorun_selected_plugin = ""
    dashboard.sensor_nodes_autorun_selected_action = ""
    dashboard.ui.comboBox_sensor_nodes_autorun_plugin.clear()
    dashboard.ui.comboBox_sensor_nodes_autorun_action.clear()
    dashboard.ui.pushButton_sensor_nodes_autorun_customize.setEnabled(False)
    dashboard.ui.pushButton_sensor_nodes_autorun_timing_add.setEnabled(False)
    _clear_sensor_nodes_autorun_parameter_widgets(dashboard)


def _filter_sensor_nodes_autorun_action_catalog(dashboard: QtCore.QObject):
    """Filter the cached Autorun action catalog locally by configured hardware."""
    record = dashboard.ui.comboBox_sensor_nodes_autorun_hardware.currentData()
    mode = "all"
    selected_type = ""

    if isinstance(record, dict):
        mode = str(record.get("mode", "all") or "all")
        selected_type = str(record.get("hardware_type", "") or "").strip().lower()

    filtered = []
    for action_record in getattr(dashboard, "sensor_nodes_autorun_action_catalog", []) or []:
        if not isinstance(action_record, dict):
            continue

        action_hardware = [
            str(value or "").strip()
            for value in (action_record.get("hardware", []) or [])
            if str(value or "").strip()
        ]

        if mode == "none" and action_hardware:
            continue

        if mode == "hardware" and action_hardware:
            normalized = [value.lower() for value in action_hardware]
            if not any(selected_type in value or value in selected_type for value in normalized):
                continue

        filtered.append(action_record)

    plugin_combo = dashboard.ui.comboBox_sensor_nodes_autorun_plugin
    current_plugin = str(plugin_combo.currentText() or "").strip()
    plugins = sorted(
        {
            str(record.get("plugin", "") or "").strip()
            for record in filtered
            if str(record.get("plugin", "") or "").strip()
        },
        key=str.lower,
    )

    dashboard.sensor_nodes_autorun_filtered_actions = filtered
    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.addItems(plugins)
    restore_index = plugin_combo.findText(current_plugin, QtCore.Qt.MatchExactly)
    plugin_combo.setCurrentIndex(restore_index if restore_index >= 0 else (0 if plugins else -1))
    plugin_combo.blockSignals(False)
    _populate_sensor_nodes_autorun_actions_for_plugin(dashboard)


def _populate_sensor_nodes_autorun_actions_for_plugin(dashboard: QtCore.QObject):
    """Populate actions for the selected Autorun plugin while preserving a valid selection."""
    plugin_name = str(dashboard.ui.comboBox_sensor_nodes_autorun_plugin.currentText() or "").strip()
    previous_plugin = str(getattr(dashboard, "sensor_nodes_autorun_selected_plugin", "") or "").strip()
    previous_action = str(getattr(dashboard, "sensor_nodes_autorun_selected_action", "") or "").strip()

    action_combo = dashboard.ui.comboBox_sensor_nodes_autorun_action
    action_combo.blockSignals(True)
    action_combo.clear()

    for action_record in getattr(dashboard, "sensor_nodes_autorun_filtered_actions", []) or []:
        if str(action_record.get("plugin", "") or "").strip() != plugin_name:
            continue

        action_name = str(action_record.get("action", "") or "").strip()
        if action_name:
            action_combo.addItem(action_name, action_record)

    restore_index = -1
    if plugin_name == previous_plugin and previous_action:
        restore_index = action_combo.findText(previous_action, QtCore.Qt.MatchExactly)

    action_combo.setCurrentIndex(restore_index if restore_index >= 0 else (0 if action_combo.count() else -1))
    action_combo.blockSignals(False)
    _slotSensorNodesAutorunActionChanged(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesAutorunQueryClicked(dashboard: QtCore.QObject):
    """Query the selected Sensor Node once for its Autorun-compatible action catalog."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        return

    dashboard.ui.pushButton_sensor_nodes_autorun_query.setEnabled(False)
    dashboard.ui.pushButton_sensor_nodes_autorun_query.setText("Querying...")
    await dashboard.backend.queryPluginActions(
        node_uid,
        context="sensor_nodes.autorun.actions",
        scope="all_plugins",
    )


def handle_sensor_nodes_autorun_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    """Cache one Autorun action query and apply the local hardware filter."""
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return
    if context != "sensor_nodes.autorun.actions":
        return

    dashboard.sensor_nodes_autorun_action_catalog = actions if isinstance(actions, list) else []
    dashboard.ui.pushButton_sensor_nodes_autorun_query.setText("Query Actions")
    dashboard.ui.pushButton_sensor_nodes_autorun_query.setEnabled(True)
    _filter_sensor_nodes_autorun_action_catalog(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunHardwareChanged(dashboard: QtCore.QObject):
    """Apply the optional hardware filter to the cached Autorun action catalog."""
    _filter_sensor_nodes_autorun_action_catalog(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunPluginChanged(dashboard: QtCore.QObject):
    """Populate actions for the selected Autorun plugin."""
    _populate_sensor_nodes_autorun_actions_for_plugin(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunActionChanged(dashboard: QtCore.QObject):
    """Update Autorun action selection and clear customization only when the action changes."""
    record = dashboard.ui.comboBox_sensor_nodes_autorun_action.currentData()

    if not isinstance(record, dict):
        dashboard.sensor_nodes_autorun_selected_plugin = ""
        dashboard.sensor_nodes_autorun_selected_action = ""
        dashboard.ui.pushButton_sensor_nodes_autorun_customize.setEnabled(False)
        dashboard.ui.pushButton_sensor_nodes_autorun_timing_add.setEnabled(False)
        _clear_sensor_nodes_autorun_parameter_widgets(dashboard)
        return

    plugin_name = str(record.get("plugin", "") or "").strip()
    action_name = str(record.get("action", "") or "").strip()
    same_selection = (
        plugin_name == str(getattr(dashboard, "sensor_nodes_autorun_selected_plugin", "") or "").strip()
        and action_name == str(getattr(dashboard, "sensor_nodes_autorun_selected_action", "") or "").strip()
    )

    dashboard.ui.pushButton_sensor_nodes_autorun_customize.setEnabled(bool(plugin_name and action_name))
    if same_selection:
        return

    dashboard.sensor_nodes_autorun_selected_plugin = plugin_name
    dashboard.sensor_nodes_autorun_selected_action = action_name
    dashboard.ui.pushButton_sensor_nodes_autorun_timing_add.setEnabled(False)
    _clear_sensor_nodes_autorun_parameter_widgets(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesAutorunCustomizeClicked(dashboard: QtCore.QObject):
    """Load the schema for the selected Autorun action."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    plugin_name = str(getattr(dashboard, "sensor_nodes_autorun_selected_plugin", "") or "").strip()
    action_name = str(getattr(dashboard, "sensor_nodes_autorun_selected_action", "") or "").strip()
    if not node_uid or not plugin_name or not action_name:
        return

    dashboard.ui.pushButton_sensor_nodes_autorun_customize.setEnabled(False)
    dashboard.ui.pushButton_sensor_nodes_autorun_customize.setText("Loading...")
    await dashboard.backend.queryPluginActionSchema(
        node_uid,
        plugin_name,
        action_name,
        context="sensor_nodes.autorun.schema",
    )


def _clear_sensor_nodes_autorun_parameter_widgets(dashboard: QtCore.QObject):
    """Clear dynamic Autorun action parameter controls."""
    contents = dashboard.ui.scrollAreaWidgetContents_sensor_nodes_autorun_parameters
    layout = contents.layout()
    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()

    layout.setContentsMargins(8, 8, 8, 8)
    layout.setHorizontalSpacing(8)
    layout.setVerticalSpacing(6)
    layout.setAlignment(QtCore.Qt.AlignTop)
    dashboard.sensor_nodes_autorun_parameter_widgets = {}


def _create_sensor_nodes_autorun_parameter_widget(parent, parameter: dict):
    """Create one styled editor for an Autorun action-schema parameter."""
    parameter_type = str(parameter.get("type", "string") or "string").strip().lower()
    parameter_name = str(parameter.get("name", "") or "").strip()
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
        widget.setMinimum(int(parameter.get("min", -2147483647)))
        widget.setMaximum(int(parameter.get("max", 2147483647)))
        widget.setSingleStep(int(parameter.get("step", 1)))
        widget.setValue(int(default or 0))

    elif parameter_type in {"float", "double", "number"}:
        widget = QtWidgets.QDoubleSpinBox(parent)
        widget.setDecimals(int(parameter.get("decimals", 6)))
        widget.setMinimum(float(parameter.get("min", -1000000000000.0)))
        widget.setMaximum(float(parameter.get("max", 1000000000000.0)))
        widget.setSingleStep(float(parameter.get("step", 1.0)))
        widget.setValue(float(default or 0.0))

    elif parameter_type in {"bool", "boolean"}:
        widget = QtWidgets.QCheckBox(parent)
        checked = default.strip().lower() in {"true", "1", "yes", "on", "enabled"} if isinstance(default, str) else bool(default)
        widget.setChecked(checked)

    elif parameter_type == "label":
        widget = QtWidgets.QLabel(str(default), parent)
        widget.setWordWrap(True)
        widget.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)

    else:
        widget = QtWidgets.QLineEdit(str(default), parent)

    widget.setObjectName(f"sensor_nodes_autorun_parameter_{parameter_name}")
    widget.setProperty(
        "uiRole",
        "autorunParameterInfo" if parameter_type == "label" else "autorunParameterEditor",
    )
    return widget


def handle_sensor_nodes_autorun_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
):
    """Render the selected Autorun action schema in the Parameters card."""
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return
    if plugin_name != getattr(dashboard, "sensor_nodes_autorun_selected_plugin", ""):
        return
    if action_name != getattr(dashboard, "sensor_nodes_autorun_selected_action", ""):
        return

    _clear_sensor_nodes_autorun_parameter_widgets(dashboard)
    contents = dashboard.ui.scrollAreaWidgetContents_sensor_nodes_autorun_parameters
    layout = contents.layout()
    layout.setColumnStretch(0, 2)
    layout.setColumnStretch(1, 3)

    visible_parameters = [
        parameter for parameter in (parameters or [])
        if str(parameter.get("name", "") or "").strip() != "description"
    ]

    for row, parameter in enumerate(visible_parameters):
        name = str(parameter.get("name", "") or "").strip()
        if not name:
            continue

        label = QtWidgets.QLabel(f"{str(parameter.get('label') or name).strip()}:", contents)
        label.setObjectName(f"label_sensor_nodes_autorun_parameter_{name}")
        label.setProperty("uiRole", "autorunParameterLabel")
        label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)

        widget = _create_sensor_nodes_autorun_parameter_widget(contents, parameter)

        layout.addWidget(label, row, 0)
        layout.addWidget(widget, row, 1)
        dashboard.sensor_nodes_autorun_parameter_widgets[name] = {
            "widget": widget,
            "schema": dict(parameter),
        }

    dashboard.ui.pushButton_sensor_nodes_autorun_customize.setText("Customize")
    dashboard.ui.pushButton_sensor_nodes_autorun_customize.setEnabled(True)
    dashboard.ui.pushButton_sensor_nodes_autorun_timing_add.setEnabled(True)


def _sensor_nodes_autorun_parameter_value(widget):
    """Return the current value from one Autorun parameter editor."""
    if isinstance(widget, QtWidgets.QComboBox):
        return widget.currentText()
    if isinstance(widget, QtWidgets.QDoubleSpinBox):
        return widget.value()
    if isinstance(widget, QtWidgets.QSpinBox):
        return widget.value()
    if isinstance(widget, QtWidgets.QCheckBox):
        return widget.isChecked()
    if isinstance(widget, QtWidgets.QLineEdit):
        return widget.text()
    if isinstance(widget, QtWidgets.QLabel):
        return widget.text()
    return None


def _collect_sensor_nodes_autorun_action_parameters(dashboard: QtCore.QObject):
    """Collect customized values for the selected Autorun action."""
    parameters = {}
    for name, record in (getattr(dashboard, "sensor_nodes_autorun_parameter_widgets", {}) or {}).items():
        widget = record.get("widget") if isinstance(record, dict) else None
        schema = record.get("schema", {}) if isinstance(record, dict) else {}
        if widget is None or str(schema.get("type", "") or "").lower() == "label":
            continue
        parameters[name] = _sensor_nodes_autorun_parameter_value(widget)
    return parameters


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunTimingRepeatChanged(dashboard: QtCore.QObject):
    """Enable Interval only when the action is configured to repeat forever."""
    dashboard.ui.textEdit_sensor_nodes_autorun_timing_interval.setEnabled(
        dashboard.ui.checkBox_sensor_nodes_autorun_timing_repeat.isChecked()
    )


def _sensor_nodes_autorun_timing_values(dashboard: QtCore.QObject):
    """Validate and return Delay, Repeat Forever, and Interval values."""
    try:
        delay_seconds = float(dashboard.ui.textEdit_sensor_nodes_autorun_timing_delay.toPlainText().strip() or "0")
        interval_seconds = float(dashboard.ui.textEdit_sensor_nodes_autorun_timing_interval.toPlainText().strip() or "0")
    except ValueError:
        raise ValueError("Delay and Interval must be numeric values.")

    if delay_seconds < 0 or interval_seconds < 0:
        raise ValueError("Delay and Interval cannot be negative.")

    repeat_forever = dashboard.ui.checkBox_sensor_nodes_autorun_timing_repeat.isChecked()
    if repeat_forever and interval_seconds <= 0:
        raise ValueError("Interval must be greater than zero when Repeat Forever is enabled.")

    return delay_seconds, repeat_forever, interval_seconds


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunTimingAddClicked(dashboard: QtCore.QObject):
    """Add one configured plugin action to the Autorun playlist."""
    plugin_name = str(getattr(dashboard, "sensor_nodes_autorun_selected_plugin", "") or "").strip()
    action_name = str(getattr(dashboard, "sensor_nodes_autorun_selected_action", "") or "").strip()
    if not plugin_name or not action_name:
        return

    try:
        delay_seconds, repeat_forever, interval_seconds = _sensor_nodes_autorun_timing_values(dashboard)
    except ValueError as error:
        QtWidgets.QMessageBox.warning(dashboard, "Autorun Timing", str(error))
        return

    record = {
        "plugin": plugin_name,
        "action": action_name,
        "parameters": _collect_sensor_nodes_autorun_action_parameters(dashboard),
        "delay_seconds": delay_seconds,
        "repeat": repeat_forever,
        "interval_seconds": interval_seconds,
    }
    _append_sensor_nodes_autorun_playlist_row(dashboard, record)


def _sensor_nodes_autorun_parameter_summary(parameters):
    """Build a compact table summary without hiding meaningful falsy values."""
    values = []
    for name, value in (parameters or {}).items():
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        values.append(f"{name}={value}")
    return ", ".join(values) if values else "—"


def _append_sensor_nodes_autorun_playlist_row(dashboard: QtCore.QObject, record: dict):
    """Append one normalized action record to the Autorun playlist table."""
    table = dashboard.ui.tableWidget_sensor_nodes_autorun_playlist
    row = table.rowCount()
    table.insertRow(row)

    parameter_summary = _sensor_nodes_autorun_parameter_summary(record.get("parameters", {}) or {})
    values = [
        str(record.get("plugin", "") or ""),
        str(record.get("action", "") or ""),
        str(record.get("delay_seconds", 0)),
        "Yes" if bool(record.get("repeat", False)) else "No",
        str(record.get("interval_seconds", 0)) if bool(record.get("repeat", False)) else "—",
        parameter_summary,
    ]

    for column, value in enumerate(values):
        item = QtWidgets.QTableWidgetItem(value)
        item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
        item.setTextAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter if column == 5 else QtCore.Qt.AlignCenter)
        table.setItem(row, column, item)

    table.item(row, 0).setData(QtCore.Qt.UserRole, dict(record))
    table.item(row, 5).setToolTip(parameter_summary)
    table.resizeRowsToContents()


def _slotSensorNodesAutorunPlaylistRemoveClicked(dashboard: QtCore.QObject):
    """Remove the selected action from the Autorun playlist."""
    table = dashboard.ui.tableWidget_sensor_nodes_autorun_playlist
    selection_model = table.selectionModel()
    selected_rows = selection_model.selectedRows() if selection_model is not None else []

    if selected_rows:
        table.removeRow(selected_rows[0].row())
        return

    selected_indexes = selection_model.selectedIndexes() if selection_model is not None else []
    if selected_indexes:
        table.removeRow(selected_indexes[0].row())


def _slotSensorNodesAutorunPlaylistClearClicked(dashboard: QtCore.QObject):
    """Clear the current Autorun playlist action table."""
    dashboard.ui.tableWidget_sensor_nodes_autorun_playlist.setRowCount(0)


def _slotSensorNodesAutorunDetectorAddClicked(dashboard: QtCore.QObject):
    """Add one reusable detector configuration to the Autorun playlist gate."""
    detector_config = dashboard.openPopUp("DetectorSelectionDialog", DetectorSelectionDialog)
    if not detector_config:
        return

    plugin_name = str(detector_config.get("plugin", "") or "").strip()
    action_name = str(detector_config.get("action", "") or "").strip()
    if not plugin_name or not action_name:
        return

    table = dashboard.ui.tableWidget_sensor_nodes_autorun_detectors
    row = table.rowCount()
    table.insertRow(row)

    parameters = detector_config.get("parameters", {}) or {}
    hardware = str(detector_config.get("hardware", "") or "").strip()
    values = [
        f"{plugin_name}: {action_name}",
        hardware or "No Hardware",
        ", ".join(f"{name}={value}" for name, value in parameters.items()),
    ]

    for column, value in enumerate(values):
        item = QtWidgets.QTableWidgetItem(value)
        item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
        item.setTextAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter if column == 2 else QtCore.Qt.AlignCenter)
        table.setItem(row, column, item)

    table.item(row, 0).setData(QtCore.Qt.UserRole, dict(detector_config))
    table.item(row, 2).setToolTip(values[2])
    table.resizeRowsToContents()


def _slotSensorNodesAutorunDetectorRemoveClicked(dashboard: QtCore.QObject):
    """Remove the selected detector from the Autorun gate."""
    table = dashboard.ui.tableWidget_sensor_nodes_autorun_detectors
    row = table.currentRow()
    if row >= 0:
        table.removeRow(row)


def _collect_sensor_nodes_autorun_detectors(dashboard: QtCore.QObject):
    """Collect detector configurations from the Autorun detector table."""
    detectors = []
    table = dashboard.ui.tableWidget_sensor_nodes_autorun_detectors
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        config = item.data(QtCore.Qt.UserRole) if item is not None else None
        if isinstance(config, dict):
            detectors.append(dict(config))
    return detectors


def _collect_sensor_nodes_autorun_actions(dashboard: QtCore.QObject):
    """Collect action records from the Autorun playlist table."""
    actions = []
    table = dashboard.ui.tableWidget_sensor_nodes_autorun_playlist
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        record = item.data(QtCore.Qt.UserRole) if item is not None else None
        if isinstance(record, dict):
            actions.append(dict(record))
    return actions


def _build_sensor_nodes_autorun_detector_runtime_parameters(dashboard: QtCore.QObject, detector_config: dict):
    """Build detector runtime parameters while keeping stored UI parameters clean."""
    parameters = dict(detector_config.get("parameters", {}) or {})
    hardware_display_name = str(detector_config.get("hardware", "") or "").strip()

    (
        hardware_type,
        hardware_uid,
        hardware_radio_name,
        hardware_serial,
        hardware_interface,
        hardware_ip,
        hardware_daughterboard,
    ) = fissure.utils.hardware.hardwareDisplayNameLookup(
        dashboard,
        hardware_display_name,
        "tsi",
    )

    if hardware_type in {"USRP B20xmini", "USRP B2x0"}:
        hardware_serial_argument = f"serial={hardware_serial}" if hardware_serial else "False"
    else:
        hardware_serial_argument = hardware_serial if hardware_serial else "False"

    parameters.update(
        {
            "requester": "autorun",
            "hardware_display_name": hardware_display_name,
            "hardware_type": hardware_type,
            "hardware_uid": hardware_uid,
            "hardware_uuid": hardware_uid,
            "hardware_radio_name": hardware_radio_name,
            "hardware_serial": hardware_serial,
            "hardware_serial_argument": hardware_serial_argument,
            "hardware_interface": hardware_interface,
            "hardware_ip": hardware_ip,
            "hardware_daughterboard": hardware_daughterboard,
            "serial": hardware_serial,
        }
    )
    return parameters


def build_sensor_nodes_autorun_playlist(dashboard: QtCore.QObject):
    """Build the versioned plugin-backed Autorun playlist document."""
    detectors = []
    for detector_config in _collect_sensor_nodes_autorun_detectors(dashboard):
        record = dict(detector_config)
        record["runtime_parameters"] = _build_sensor_nodes_autorun_detector_runtime_parameters(
            dashboard,
            detector_config,
        )
        detectors.append(record)

    return {
        "schema_version": 1,
        "detectors": detectors,
        "playlist": _collect_sensor_nodes_autorun_actions(dashboard),
    }


def _populate_sensor_nodes_autorun_workspace(dashboard: QtCore.QObject, playlist_dict: dict):
    """Replace the Autorun workspace from a versioned playlist document."""
    if not isinstance(playlist_dict, dict) or int(playlist_dict.get("schema_version", 0) or 0) != 1:
        raise ValueError("This is not a supported plugin-backed Autorun playlist.")

    detector_table = dashboard.ui.tableWidget_sensor_nodes_autorun_detectors
    playlist_table = dashboard.ui.tableWidget_sensor_nodes_autorun_playlist
    detector_table.setRowCount(0)
    playlist_table.setRowCount(0)

    for detector_config in playlist_dict.get("detectors", []) or []:
        if not isinstance(detector_config, dict):
            continue
        plugin_name = str(detector_config.get("plugin", "") or "").strip()
        action_name = str(detector_config.get("action", "") or "").strip()
        parameters = detector_config.get("parameters", {}) or {}
        row = detector_table.rowCount()
        detector_table.insertRow(row)
        hardware = str(detector_config.get("hardware", "") or "").strip()
        values = [
            f"{plugin_name}: {action_name}",
            hardware or "No Hardware",
            ", ".join(f"{name}={value}" for name, value in parameters.items()),
        ]
        for column, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(value)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
            item.setTextAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter if column == 2 else QtCore.Qt.AlignCenter)
            detector_table.setItem(row, column, item)
        detector_table.item(row, 0).setData(QtCore.Qt.UserRole, dict(detector_config))
        detector_table.item(row, 2).setToolTip(values[2])

    for action_record in playlist_dict.get("playlist", []) or []:
        if isinstance(action_record, dict):
            _append_sensor_nodes_autorun_playlist_row(dashboard, action_record)

    detector_table.resizeRowsToContents()
    playlist_table.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunPlaylistImportClicked(dashboard: QtCore.QObject):
    """Import a plugin-backed Autorun YAML file into the Dashboard workspace."""
    filepath, _ = QtWidgets.QFileDialog.getOpenFileName(
        dashboard,
        "Import Autorun Playlist",
        os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists"),
        "YAML (*.yaml *.yml)",
    )
    if not filepath:
        return

    try:
        with open(filepath, "r") as yaml_file:
            playlist_dict = yaml.safe_load(yaml_file) or {}
        _populate_sensor_nodes_autorun_workspace(dashboard, playlist_dict)
    except Exception as error:
        QtWidgets.QMessageBox.warning(dashboard, "Import Autorun Playlist", str(error))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunPlaylistExportClicked(dashboard: QtCore.QObject):
    """Export the current Dashboard Autorun workspace as YAML."""
    filepath, _ = QtWidgets.QFileDialog.getSaveFileName(
        dashboard,
        "Export Autorun Playlist",
        os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists", "playlist.yaml"),
        "YAML (*.yaml)",
    )
    if not filepath:
        return
    if not filepath.lower().endswith((".yaml", ".yml")):
        filepath += ".yaml"

    with open(filepath, "w") as yaml_file:
        yaml.safe_dump(build_sensor_nodes_autorun_playlist(dashboard), yaml_file, sort_keys=False)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesAutorunPlaylistQueryClicked(dashboard: QtCore.QObject):
    """Query YAML playlists currently stored on the selected Sensor Node."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if node_uid:
        await dashboard.backend.autorunPlaylistQuery(node_uid)


def handle_sensor_nodes_autorun_playlist_query_results(
    dashboard: QtCore.QObject, node_uid="", playlists=None, state="Idle", source="", message=""
):
    """Populate stored playlist names and synchronize authoritative Autorun state."""
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return

    combo = dashboard.ui.comboBox_sensor_nodes_autorun_playlists
    current_text = str(combo.currentText() or "").strip()
    combo.clear()
    combo.addItems(sorted([str(name) for name in (playlists or []) if str(name).strip()], key=str.lower))
    restore_index = combo.findText(current_text, QtCore.Qt.MatchExactly)
    if restore_index >= 0:
        combo.setCurrentIndex(restore_index)

    handle_sensor_nodes_autorun_status(
        dashboard, node_uid=node_uid, state=state, source=source, message=message
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesAutorunPlaylistLoadClicked(dashboard: QtCore.QObject):
    """Load the selected Sensor Node playlist into the Dashboard workspace."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    playlist_name = str(dashboard.ui.comboBox_sensor_nodes_autorun_playlists.currentText() or "").strip()
    if node_uid and playlist_name:
        await dashboard.backend.autorunPlaylistLoad(node_uid, playlist_name)


def handle_sensor_nodes_autorun_playlist_load_results(
    dashboard: QtCore.QObject,
    node_uid="",
    playlist_filename="",
    playlist_dict=None,
    success=False,
    message="",
):
    """Apply one loaded Sensor Node playlist to the Dashboard workspace."""
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return
    if not success:
        QtWidgets.QMessageBox.warning(dashboard, "Load Autorun Playlist", str(message or "Could not load playlist."))
        return

    try:
        _populate_sensor_nodes_autorun_workspace(dashboard, playlist_dict or {})
    except Exception as error:
        QtWidgets.QMessageBox.warning(dashboard, "Load Autorun Playlist", str(error))


async def _sensor_nodes_autorun_prompt_filename(dashboard: QtCore.QObject, current_name: str):
    """Prompt for a Sensor Node playlist filename without nesting the qasync event loop."""
    dialog = QtWidgets.QInputDialog(dashboard)
    dialog.setWindowTitle("Save Autorun Playlist to Sensor Node")
    dialog.setLabelText("Filename:")
    dialog.setInputMode(QtWidgets.QInputDialog.TextInput)
    dialog.setTextValue(current_name or "default.yaml")
    dialog.setWindowModality(QtCore.Qt.WindowModal)

    loop = asyncio.get_running_loop()
    result_future = loop.create_future()

    def accepted():
        if not result_future.done():
            result_future.set_result(str(dialog.textValue() or "").strip())

    def rejected():
        if not result_future.done():
            result_future.set_result(None)

    dialog.accepted.connect(accepted)
    dialog.rejected.connect(rejected)
    dialog.open()

    try:
        return await result_future
    finally:
        dialog.deleteLater()


async def _sensor_nodes_autorun_confirm_overwrite(dashboard: QtCore.QObject, filename: str):
    """Confirm overwriting a Sensor Node playlist without nesting the qasync event loop."""
    dialog = QtWidgets.QMessageBox(dashboard)
    dialog.setWindowTitle("Overwrite Autorun Playlist")
    dialog.setText(f"{filename} already exists on this Sensor Node. Overwrite it?")
    dialog.setIcon(QtWidgets.QMessageBox.Question)
    dialog.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
    dialog.setDefaultButton(QtWidgets.QMessageBox.No)
    dialog.setWindowModality(QtCore.Qt.WindowModal)

    loop = asyncio.get_running_loop()
    result_future = loop.create_future()

    def finished(result):
        if not result_future.done():
            result_future.set_result(result == QtWidgets.QMessageBox.Yes)

    dialog.finished.connect(finished)
    dialog.open()

    try:
        return await result_future
    finally:
        dialog.deleteLater()


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesAutorunPlaylistSaveToNodeClicked(dashboard: QtCore.QObject):
    """Save the current Dashboard Autorun workspace as a YAML file on the selected node."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        return

    current_name = str(
        dashboard.ui.comboBox_sensor_nodes_autorun_playlists.currentText() or "default.yaml"
    ).strip()

    filename = await _sensor_nodes_autorun_prompt_filename(dashboard, current_name)
    if filename is None:
        return

    filename = os.path.basename(filename)
    if not filename:
        return
    if not filename.lower().endswith((".yaml", ".yml")):
        filename += ".yaml"

    combo = dashboard.ui.comboBox_sensor_nodes_autorun_playlists
    if combo.findText(filename, QtCore.Qt.MatchExactly) >= 0:
        if not await _sensor_nodes_autorun_confirm_overwrite(dashboard, filename):
            return

    await dashboard.backend.autorunPlaylistSave(
        node_uid,
        filename,
        build_sensor_nodes_autorun_playlist(dashboard),
    )


def handle_sensor_nodes_autorun_playlist_save_results(
    dashboard: QtCore.QObject,
    node_uid="",
    playlist_filename="",
    success=False,
    message="",
):
    """Refresh the node-playlist selector after a save completes."""
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return
    if not success:
        QtWidgets.QMessageBox.warning(dashboard, "Save Autorun Playlist", str(message or "Could not save playlist."))
        return

    combo = dashboard.ui.comboBox_sensor_nodes_autorun_playlists
    if combo.findText(playlist_filename, QtCore.Qt.MatchExactly) < 0:
        combo.addItem(playlist_filename)
    combo.setCurrentText(playlist_filename)


def _set_sensor_nodes_autorun_start_stop_button(
    dashboard: QtCore.QObject,
    running: bool,
):
    """Update the Autorun Start/Stop button text and dynamic style state."""
    button = dashboard.ui.pushButton_sensor_nodes_autorun_start_stop
    button.setText("Stop" if running else "Start")
    button.setProperty("running", bool(running))
    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesAutorunStartStopClicked(dashboard: QtCore.QObject):
    """Start the current Dashboard workspace or stop the active node Autorun."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        return

    state = str(getattr(dashboard, "sensor_nodes_autorun_state", "Idle") or "Idle").strip() or "Idle"
    button = dashboard.ui.pushButton_sensor_nodes_autorun_start_stop

    if state in {"Waiting", "Running", "Stopping"}:
        if state == "Stopping":
            return

        dashboard.ui.label2_sensor_nodes_autorun_status.setText("Stopping...")
        _set_sensor_nodes_autorun_start_stop_button(dashboard, True)
        button.setEnabled(False)

        try:
            await dashboard.backend.autorunPlaylistStop(node_uid)
        except Exception as error:
            dashboard.logger.error(f"Failed to stop Autorun playlist: {error}")
            dashboard.ui.label2_sensor_nodes_autorun_status.setText("Stop Failed")
            _set_sensor_nodes_autorun_start_stop_button(dashboard, True)
            button.setEnabled(True)
        return

    playlist_dict = build_sensor_nodes_autorun_playlist(dashboard)
    if not playlist_dict.get("playlist"):
        QtWidgets.QMessageBox.warning(
            dashboard,
            "Start Autorun",
            "Add at least one action to the playlist.",
        )
        return

    dashboard.ui.label2_sensor_nodes_autorun_status.setText("Starting...")
    _set_sensor_nodes_autorun_start_stop_button(dashboard, False)
    button.setEnabled(False)

    try:
        await dashboard.backend.autorunPlaylistStart(node_uid, playlist_dict)
    except Exception as error:
        dashboard.logger.error(f"Failed to start Autorun playlist: {error}")
        dashboard.ui.label2_sensor_nodes_autorun_status.setText("Start Failed")
        _set_sensor_nodes_autorun_start_stop_button(dashboard, False)
        button.setEnabled(True)


def handle_sensor_nodes_autorun_status(
    dashboard: QtCore.QObject,
    node_uid="",
    state="Idle",
    source="",
    message="",
):
    """Update Autorun execution controls from authoritative Sensor Node state."""
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return

    normalized_state = str(state or "Idle").strip() or "Idle"
    dashboard.sensor_nodes_autorun_state = normalized_state
    dashboard.sensor_nodes_autorun_source = str(source or "").strip()

    status_text = normalized_state
    if dashboard.sensor_nodes_autorun_source and normalized_state in {"Waiting", "Running"}:
        status_text += f" — {dashboard.sensor_nodes_autorun_source}"
    if message and normalized_state == "Error":
        status_text += f": {message}"

    dashboard.ui.label2_sensor_nodes_autorun_status.setText(status_text)

    button = dashboard.ui.pushButton_sensor_nodes_autorun_start_stop
    running = normalized_state in {"Waiting", "Running", "Stopping"}
    _set_sensor_nodes_autorun_start_stop_button(dashboard, running)

    if normalized_state == "Stopping":
        button.setEnabled(False)
    else:
        button.setEnabled(True)


def _sensor_nodes_file_navigation_node_label(
    dashboard: QtCore.QObject,
) -> str:
    """
    Returns the display label for the selected Sensor Node.
    """
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if not node_uid:
        return "Sensor Node: —"

    settings = (
        getattr(
            dashboard,
            "selected_node_settings",
            {},
        )
        or {}
    )

    nickname = str(
        settings.get(
            "nickname"
        )
        or settings.get(
            "name"
        )
        or ""
    ).strip()

    if not nickname:
        node_state = (
            getattr(
                dashboard,
                "node_states",
                {},
            )
            or {}
        ).get(
            node_uid,
            {},
        )

        if isinstance(
            node_state,
            dict,
        ):
            nickname = str(
                node_state.get(
                    "nickname"
                )
                or node_state.get(
                    "name"
                )
                or node_state.get(
                    "callsign"
                )
                or ""
            ).strip()

    if nickname:
        return (
            f"Sensor Node: {nickname} "
            f"({node_uid})"
        )

    return f"Sensor Node: {node_uid}"


def initialize_sensor_nodes_file_navigation_controls(
    dashboard: QtCore.QObject,
):
    """
    Initializes the Sensor Nodes File Navigation node gate.
    """
    dashboard.ui.stackedWidget_sensor_nodes_fn_node_gate.setCurrentWidget(
        dashboard.ui.page_sensor_nodes_fn_no_node
    )

    select_node_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "select_node.png",
    )

    if os.path.isfile(
        select_node_icon_path
    ):
        select_node_pixmap = QtGui.QPixmap(
            select_node_icon_path
        )

        dashboard.ui.label_sensor_nodes_fn_select_sensor_node_image.setPixmap(
            select_node_pixmap
        )

        dashboard.ui.label_sensor_nodes_fn_select_sensor_node_image.setScaledContents(
            False
        )

        dashboard.ui.label_sensor_nodes_fn_select_sensor_node_image.setAlignment(
            QtCore.Qt.AlignCenter
        )

    update_sensor_nodes_file_navigation_selected_node_gate(
        dashboard
    )


def update_sensor_nodes_file_navigation_selected_node_gate(
    dashboard: QtCore.QObject,
):
    """
    Show File Navigation controls only when an online Sensor Node is selected.
    """
    selected_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    has_selected_node = bool(
        selected_uid
    )

    if has_selected_node:
        node_states = (
            getattr(
                dashboard,
                "node_states",
                {},
            )
            or {}
        )

        node_state = node_states.get(
            selected_uid
        )

        if (
            isinstance(
                node_state,
                dict,
            )
            and node_state.get(
                "connected"
            ) is False
        ):
            has_selected_node = False

    dashboard.ui.stackedWidget_sensor_nodes_fn_node_gate.setCurrentWidget(
        dashboard.ui.page_sensor_nodes_fn_controls
        if has_selected_node
        else dashboard.ui.page_sensor_nodes_fn_no_node
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalFolderChanged(dashboard: QtCore.QObject):
    """ 
    Changes the folder location in the tree view for viewing local files.
    """
    # Change the Root Location of the Tree
    get_path = str(dashboard.ui.comboBox_sensor_nodes_fn_local_folder.currentText())
    dashboard.ui.treeView_sensor_nodes_fn_local_files.setRootIndex(dashboard.ui.treeView_sensor_nodes_fn_local_files.model().index(get_path))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationFolderChanged(dashboard: QtCore.QObject):
    """ 
    Refreshes the files listed for the remote folder and disables the Transfer button. 
    """
    # Active Sensor Nodes Only
    if dashboard.selected_node_uid:
        # Disable/Enable the Transfer Button
        get_folder = str(dashboard.ui.comboBox_sensor_nodes_fn_folder.currentText())
        if (get_folder == '/IQ_Data_Playback') or (get_folder == '/Archive_Replay'):
            dashboard.ui.pushButton_sensor_nodes_fn_local_transfer.setEnabled(False)
        else:
            dashboard.ui.pushButton_sensor_nodes_fn_local_transfer.setEnabled(True)
            
        # Refresh the Folders
        _slotSensorNodesFileNavigationRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalDeleteClicked(dashboard: QtCore.QObject):
    """
    Deletes a selected local folder or file.
    """
    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()

    if not current_index.isValid():
        return

    get_item_path = str(tree_view.model().filePath(current_index) or "").strip()

    if not get_item_path or not os.path.exists(get_item_path):
        return

    qm = QtWidgets.QMessageBox
    ret = qm.question(dashboard, "", "Are you sure?", qm.Yes | qm.No)

    if ret != qm.Yes:
        return

    os.system('rm -Rf "' + get_item_path + '"')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalChooseClicked(dashboard: QtCore.QObject):
    """ 
    Opens a dialog to select a new folder for viewing local files.
    """
    # Choose Folder
    get_dir = str(QtWidgets.QFileDialog.getExistingDirectory(dashboard, "Select Directory"))

    # Add Directory to the Combobox
    if len(get_dir) > 0:
        dashboard.ui.comboBox_sensor_nodes_fn_local_folder.addItem(get_dir)
        dashboard.ui.comboBox_sensor_nodes_fn_local_folder.setCurrentIndex(dashboard.ui.comboBox_sensor_nodes_fn_local_folder.count()-1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalSelectClicked(dashboard: QtCore.QObject):
    """
    Uses the selected local folder as the File Navigation root.

    If a file is selected, its parent folder is used.
    """
    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()

    if not current_index.isValid():
        return

    selected_path = str(tree_view.model().filePath(current_index) or "").strip()

    if not selected_path:
        return

    if os.path.isfile(selected_path):
        selected_path = os.path.dirname(selected_path)

    if not os.path.isdir(selected_path):
        return

    folder_combo = dashboard.ui.comboBox_sensor_nodes_fn_local_folder
    existing_index = folder_combo.findText(selected_path, QtCore.Qt.MatchExactly)

    if existing_index >= 0:
        folder_combo.setCurrentIndex(existing_index)
    else:
        folder_combo.addItem(selected_path)
        folder_combo.setCurrentIndex(folder_combo.count() - 1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalShowInFolderClicked(dashboard: QtCore.QObject):
    """
    Opens the selected local item location in the system file manager.

    If nothing is selected, opens the current Local Folder.
    """
    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()
    selected_path = ""

    if current_index.isValid():
        selected_path = str(tree_view.model().filePath(current_index) or "").strip()

    if selected_path and os.path.isfile(selected_path):
        folder_path = os.path.dirname(selected_path)
    elif selected_path and os.path.isdir(selected_path):
        folder_path = selected_path
    else:
        folder_path = str(dashboard.ui.comboBox_sensor_nodes_fn_local_folder.currentText() or "").strip()

    if not os.path.isdir(folder_path):
        return

    QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(folder_path))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalUnzipClicked(dashboard: QtCore.QObject):
    """
    Unzips a selected local zip file.
    """
    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()

    if not current_index.isValid():
        return

    get_zip_file = str(tree_view.model().filePath(current_index) or "").strip()

    if not get_zip_file:
        return

    if not os.path.isfile(get_zip_file):
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select a zip file.")
        return

    if not get_zip_file.lower().endswith(".zip"):
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Cannot unzip file.")
        return

    os.system('unzip "' + get_zip_file + '" -d "' + get_zip_file[:-4] + '"')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalViewClicked(dashboard: QtCore.QObject):
    """
    Opens a selected local text file when it is small enough to view.
    """
    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()

    if not current_index.isValid():
        return

    get_file = str(tree_view.model().filePath(current_index) or "").strip()

    if not get_file or not os.path.isfile(get_file):
        return

    number_of_bytes = os.path.getsize(get_file)

    if number_of_bytes > 1000000:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("File is too large to view.")
        return

    if get_file.lower().endswith(".txt"):
        os.system('gedit "' + get_file + '" &')
    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Not a valid file extension.")


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Refreshes the tree widget of sensor node folders.
    """
    # Update the Tree Widget
    get_folder = str(dashboard.ui.comboBox_sensor_nodes_fn_folder.currentText())
    if (dashboard.selected_node_uid) and (len(get_folder) > 0):
        dashboard.ui.label1_sensor_nodes_fn_sensor_node.setText(
            _sensor_nodes_file_navigation_node_label(
                dashboard
            )
        )
        dashboard.ui.tableWidget_sensor_nodes_fn_files.setRowCount(0)
        
        # Local
        if selected_node_is_local(dashboard):
            folder_path = os.path.join(fissure.utils.SENSOR_NODE_DIR, get_folder.replace("/",""))
            
            for fname in os.listdir(folder_path):
                filepath = os.path.join(folder_path, fname)
                if os.path.isfile(filepath):
                    get_type = "File"
                else:
                    get_type = "Folder"
                path_item = QtWidgets.QTableWidgetItem(filepath)
                size_item = QtWidgets.QTableWidgetItem(str(os.path.getsize(filepath)))
                type_item = QtWidgets.QTableWidgetItem(get_type)
                modified_item = QtWidgets.QTableWidgetItem(str(time.strftime("%m/%d/%Y %-I:%M %p", time.gmtime(os.path.getmtime(filepath)))))
                dashboard.ui.tableWidget_sensor_nodes_fn_files.setRowCount(dashboard.ui.tableWidget_sensor_nodes_fn_files.rowCount() + 1)
                dashboard.ui.tableWidget_sensor_nodes_fn_files.setItem(dashboard.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,0,path_item)
                dashboard.ui.tableWidget_sensor_nodes_fn_files.setItem(dashboard.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,1,size_item)
                dashboard.ui.tableWidget_sensor_nodes_fn_files.setItem(dashboard.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,2,type_item)
                dashboard.ui.tableWidget_sensor_nodes_fn_files.setItem(dashboard.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,3,modified_item)    
                    
            # Resize Table            
            dashboard.ui.tableWidget_sensor_nodes_fn_files.resizeColumnsToContents()
            dashboard.ui.tableWidget_sensor_nodes_fn_files.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_sensor_nodes_fn_files.horizontalHeader().setStretchLastSection(True)
            dashboard.ui.tableWidget_sensor_nodes_fn_files.setColumnWidth(0,800)
            dashboard.ui.tableWidget_sensor_nodes_fn_files.resizeRowsToContents()

        # Remote
        else:
            # Send the Message
            await dashboard.backend.refreshSensorNodeFiles(dashboard.selected_node_uid, get_folder)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationDeleteClicked(dashboard: QtCore.QObject):
    """
    Deletes a selected folder or file on the Sensor Node.
    """
    if not dashboard.selected_node_uid:
        return

    table = dashboard.ui.tableWidget_sensor_nodes_fn_files
    current_row = table.currentRow()

    if current_row < 0:
        return

    path_item = table.item(current_row, 0)

    if path_item is None:
        return

    get_item_path = str(path_item.text() or "").strip()

    if not get_item_path:
        return

    ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(
        dashboard,
        "Are you sure?",
    )

    if ret != QtWidgets.QMessageBox.Yes:
        return

    if selected_node_is_local(dashboard):
        os.system('rm -Rf "' + get_item_path + '"')
    else:
        await dashboard.backend.deleteSensorNodeFile(
            dashboard.selected_node_uid,
            get_item_path,
        )

    table.removeRow(current_row)
    await _slotSensorNodesFileNavigationRefreshClicked(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationDownloadClicked(dashboard: QtCore.QObject):
    """
    Downloads a selected folder or file from the Sensor Node.
    """
    if not dashboard.selected_node_uid:
        return

    table = dashboard.ui.tableWidget_sensor_nodes_fn_files
    current_row = table.currentRow()

    if current_row < 0:
        return

    path_item = table.item(current_row, 0)

    if path_item is None:
        return

    get_item_path = str(path_item.text() or "").strip()

    if not get_item_path:
        return

    get_local_folder = str(
        dashboard.ui.comboBox_sensor_nodes_fn_local_folder.currentText() or ""
    ).strip()

    if not get_local_folder:
        return

    if selected_node_is_local(dashboard):
        get_new_path = os.path.join(
            get_local_folder,
            os.path.basename(get_item_path),
        )
        os.system('cp -r "' + get_item_path + '" "' + get_new_path + '"')
    else:
        await dashboard.backend.downloadSensorNodeFile(
            dashboard.selected_node_uid,
            get_item_path,
            get_local_folder,
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationLocalTransferClicked(dashboard: QtCore.QObject):
    """
    Transfers a selected local file to the selected Sensor Node folder.
    """
    if not dashboard.selected_node_uid:
        return

    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()

    if not current_index.isValid():
        return

    get_local_file = str(tree_view.model().filePath(current_index) or "").strip()

    if not get_local_file or not os.path.isfile(get_local_file):
        return

    get_remote_folder = str(dashboard.ui.comboBox_sensor_nodes_fn_folder.currentText() or "").strip()

    if not get_remote_folder:
        return

    await dashboard.backend.transferSensorNodeFile(
        dashboard.selected_node_uid,
        get_local_file,
        get_remote_folder,
        True,
    )


def update_sensor_node_title(dashboard: QtCore.QObject, change: int):
    # get current number
    current_text = dashboard.ui.tabWidget.tabBar().tabText(6)
    if "(" in current_text and ")" in current_text:
        base_text, count = current_text.rsplit("(", 1)
        count = count.rstrip(")")
        try:
            current_count = int(count)
        except ValueError:
            current_count = 0
    else:
        base_text = current_text
        current_count = 0

    new_count = max([0, current_count + change])
    if new_count == 0:
        new_text = base_text.strip()
    else:
        new_text = f"{base_text.strip()} ({new_count})"
    dashboard.ui.tabWidget.tabBar().setTabText(6, new_text)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAlertsClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Alerts text edit and resets the tab color.
    """
    # Clear
    dashboard.ui.textEdit2_sensor_nodes_alerts.clear()

    # get count from current title
    current_text = dashboard.ui.tabWidget_sensor_nodes.tabBar().tabText(3)
    if "(" in current_text and ")" in current_text:
        base_text, count = current_text.rsplit("(", 1)
        count = count.rstrip(")")
        try:
            current_count = int(count)
        except ValueError:
            current_count = 0
    else:
        base_text = current_text
        current_count = 0

    # Reset Alerts Tab Text
    dashboard.ui.tabWidget_sensor_nodes.tabBar().setTabText(3,"Alerts")

    # Update Sensor Nodes Tab Text
    update_sensor_node_title(dashboard, -current_count)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAlertsSaveClicked(dashboard: QtCore.QObject):
    """ 
    Saves the alerts to a text file.
    """
    # Define the default directory
    directory = os.path.join(fissure.utils.LOG_DIR, "Session Logs")

    # Open the Save File Dialog
    dialog = QtWidgets.QFileDialog()
    dialog.setDirectory(directory)
    dialog.setFilter(dialog.filter() | QtCore.QDir.Hidden)
    dialog.setDefaultSuffix('txt')
    dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
    dialog.setNameFilters(['Text Files (*.txt)'])
    
    if dialog.exec_() == QtWidgets.QDialog.Accepted:
        # Get the selected file path
        fname = dialog.selectedFiles()[0]

        # Ensure the file has the correct extension
        if not fname.lower().endswith(".txt"):
            fname += ".txt"

        try:
            # Write the text content to the file
            with open(fname, 'w', encoding='utf-8') as new_file:
                new_file.write(dashboard.ui.textEdit2_sensor_nodes_alerts.toPlainText())
            print(f"File saved successfully at: {fname}")
        except Exception as e:
            print(f"Error saving file: {e}")
    else:
        print("File save dialog was canceled.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesExploitsClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Listed Exploits text edit and resets the tab color.
    """
    tableWidget_exploits: QtWidgets.QTableWidget = dashboard.ui.tableWidget_exploits

    # Clear
    row_count = tableWidget_exploits.rowCount()
    tableWidget_exploits.setRowCount(0)

    tableWidget_exploits.horizontalHeader().setVisible(True) # set header visible in code; qt designer always sets to false

    # Reset Alerts Tab Text
    dashboard.ui.tabWidget_sensor_nodes.tabBar().setTabText(4,"Exploits")

    # Reset Sensor Nodes Tab Text
    update_sensor_node_title(dashboard, -row_count)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesExploitsRunClicked(dashboard: QtCore.QObject):
    """ 
    Saves the alerts to a text file.
    """
    if dashboard.ui.pushButton_attack_start_stop.text() == "Start Attack" and dashboard.ui.pushButton_attack_fuzzing_start.text() == "Start Attack":
        # get table
        table: QtWidgets.QTableWidget = dashboard.ui.tableWidget_exploits
        table.horizontalHeader().setVisible(True) # set header visible in code; qt designer always sets to false

        # get the fields from the table entry
        row = table.selectedItems()
        fields = {}
        for r in row:
            fields[int(r.column())] = r.text()

        # switch to single-stage attack tab
        toptab: QtWidgets.QTabWidget = dashboard.ui.tabWidget
        toptab.setCurrentIndex(3) # switch to attack tab
        subtab: QtWidgets.QTabWidget = dashboard.ui.tabWidget_attack_attack
        subtab.setCurrentIndex(0) # switch to Single-Stage

        # switch to protocol
        comboBox_attack_protocols: QtWidgets.QComboBox = dashboard.ui.comboBox_attack_protocols
        for i in range(comboBox_attack_protocols.count()):
            if comboBox_attack_protocols.itemText(i).lower() == fields.get(0).lower():
                comboBox_attack_protocols.setCurrentIndex(i)
                break
        AttackTabSlots._slotAttackProtocols(dashboard)

        # switch to modulation
        comboBox_attack_modulation: QtWidgets.QComboBox = dashboard.ui.comboBox_attack_modulation
        for i in range(comboBox_attack_modulation.count()):
            if comboBox_attack_modulation.itemText(i).lower() == fields.get(1).lower():
                comboBox_attack_modulation.setCurrentIndex(i)
                break
        AttackTabSlots._slotAttackModulationChanged(dashboard)

        # switch to hardware
        comboBox_attack_hardware: QtWidgets.QComboBox = dashboard.ui.comboBox_attack_hardware
        for i in range(comboBox_attack_hardware.count()):
            if str(fields.get(2)).lower() in str(comboBox_attack_hardware.itemText(i)).lower():
                comboBox_attack_hardware.setCurrentIndex(i)
                break
        AttackTabSlots._slotAttackHardwareChanged(dashboard)

        # select attack
        treeWidget_attack_attacks: QtWidgets.QTreeWidget = dashboard.ui.treeWidget_attack_attacks
        tree_item_string = comboBox_attack_protocols.currentText() + " - " + fields.get(4)  # protocol - attack_name
        treeWidget_attack_attacks.setCurrentItem(treeWidget_attack_attacks.findItems(tree_item_string, QtCore.Qt.MatchExactly|QtCore.Qt.MatchRecursive,0)[0])

        # load attack
        AttackTabSlots._slotAttackLoadTemplateClicked(dashboard)

        # set detected exploit variables
        variables = json.loads(str(fields.get(5)))
        table_vars:QtWidgets.QTableWidget = dashboard.ui.tableWidget1_attack_flow_graph_current_values
        for i in range(table_vars.rowCount()):
            variable = table_vars.verticalHeaderItem(i).text()
            if variable in variables.keys():
                table_vars.item(i, 0).setText(str(variables.get(variable)))

    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Stop the current attack to stage an exploit")

@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesReportsClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Listed Reports and resets the tab color.
    """
    tableWidget_reports: QtWidgets.QTableWidget = dashboard.ui.tableWidget_reports

    # Clear
    row_count = tableWidget_reports.rowCount()
    tableWidget_reports.setRowCount(0)

    # Reset Tab Text
    dashboard.ui.tabWidget_sensor_nodes.tabBar().setTabText(5,"Reports")

    # Reset Sensor Nodes Tab Text
    update_sensor_node_title(dashboard, -row_count)
    #dashboard.ui.tabWidget.tabBar().setTabText(6,"Sensor Nodes")


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesListenersMeshtasticInfoClicked(dashboard: QtCore.QObject):
    """ 
    Opens a dialog of potential serial ports.
    """
    # Issue the Command
    path = "/dev/serial/by-id/"
    if os.path.exists(path):
        output_text = os.popen(f"ls -l {path}").read()
    else:
        output_text = "No serial devices found"

    # Open a Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, output_text)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesListenersSaveClicked(dashboard: QtCore.QObject):
    """ 
    Transfers the listener information to the table.
    """
    # Save by Type
    status = "Disabled"
    get_type = str(dashboard.ui.comboBox_sensor_nodes_listeners_type.currentText())
    get_name = str(dashboard.ui.textEdit_sensor_nodes_listeners_name.toPlainText()).strip()
    get_parameters = {}

    if not get_name:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter listener name.")
        return

    if get_type == "Meshtastic":
        get_parameters["serial_port"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_meshtastic_serial_port.toPlainText())
        get_parameters["baud_rate"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_meshtastic_baud_rate.toPlainText())

        if not get_parameters["serial_port"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter serial port (e.g. /dev/ttyACM0).")
            return

        if not get_parameters["baud_rate"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter baud rate.")
            return
        
    elif get_type == "ZMQ SUB":
        get_parameters["ip_address"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_zmq_ip_address.toPlainText())
        get_parameters["port"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_zmq_port.toPlainText())
        get_parameters["topic_filter"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_zmq_topic.toPlainText())

        if not get_parameters["ip_address"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter IP address.")
            return

        if not get_parameters["port"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter port.")
            return
                
    elif get_type == "Website Poller":
        get_parameters["url"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_website_url.toPlainText())
        get_parameters["check_interval"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_website_interval.toPlainText())

        if not get_parameters["url"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter URL.")
            return

        if not get_parameters["check_interval"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter check interval.")
            return
        
    elif get_type == "Serial Port":
        get_parameters["serial_port"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_serial_serial_port.toPlainText())
        get_parameters["baud_rate"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_serial_baud_rate.toPlainText())

        if not get_parameters["serial_port"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter serial port (e.g. /dev/ttyACM0).")
            return

        if not get_parameters["baud_rate"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter baud rate.")
            return
        
    elif get_type == "TCP/UDP":
        get_parameters["protocol"] = str(dashboard.ui.comboBox_sensor_nodes_listeners_tcp_udp_protocol.currentText())
        get_parameters["ip_address"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_tcp_udp_ip_address.toPlainText())
        get_parameters["port"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_tcp_udp_port.toPlainText())

        if not get_parameters["ip_address"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter IP address.")
            return

        if not get_parameters["port"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter port.")
            return
        
    elif get_type == "Filesystem":
        get_filesystem_type = str(dashboard.ui.comboBox_sensor_nodes_listeners_filesystem_type.currentText())
        if get_filesystem_type == "New Files":
            get_parameters["folder"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_filesytem_folder.toPlainText()).strip()
            get_parameters["file_pattern"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_filesystem_pattern.toPlainText())

            if not get_parameters["folder"]:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter folder location.")
                return
            
        elif get_filesystem_type == "File Changes":
            get_parameters["filepath"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_filesystem_filepath.toPlainText()).strip()

            if not get_parameters["filepath"]:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter filepath location.")
                return

    elif get_type == "MQTT":
        get_parameters["broker_address"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_broker_address.toPlainText())
        get_parameters["port"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_port.toPlainText())
        get_parameters["topic"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_topic.toPlainText())
        get_parameters["username"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_username.toPlainText())
        get_parameters["password"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_password.toPlainText())

        if not get_parameters["broker_address"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter broker address.")
            return
        
        if not get_parameters["port"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter port.")
            return
        
        if not get_parameters["topic"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter topic.")
            return        

    # Reference to the table widget
    table = dashboard.ui.tableWidget_sensor_nodes_listeners

    # Check if the listener with the same name already exists
    existing_row = None
    for row in range(table.rowCount()):
        if table.item(row, 2) and table.item(row, 2).text() == get_name:  # Column 2 is "Name"
            existing_row = row
            break

    if existing_row is not None:
        # Check if the existing listener is disabled
        current_status = table.item(existing_row, 0).text()  # Status is in column 0
        if current_status.lower() != "disabled":
            # Show a popup informing the user to disable the listener first
            fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Listener '{get_name}' must be disabled before editing.")
            return
        row = existing_row
    else:
        # Add a new row to the table
        row = table.rowCount()
        table.insertRow(row)

    # Create table items with alignment
    status_item = QtWidgets.QTableWidgetItem(status)
    status_item.setTextAlignment(QtCore.Qt.AlignCenter)

    type_item = QtWidgets.QTableWidgetItem(get_type)
    type_item.setTextAlignment(QtCore.Qt.AlignCenter)

    name_item = QtWidgets.QTableWidgetItem(get_name)
    name_item.setTextAlignment(QtCore.Qt.AlignCenter)

    parameters_item = QtWidgets.QTableWidgetItem(str(get_parameters))
    parameters_item.setTextAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)

    # Populate the row with the listener data
    table.setItem(row, 0, status_item)      # Status Column (Centered)
    table.setItem(row, 1, type_item)        # Type Column (Centered)
    table.setItem(row, 2, name_item)        # Name Column (Centered)
    table.setItem(row, 3, parameters_item)  # Parameters Column (Left-Aligned)

    # Automatically scroll to the new/updated row
    table.scrollToItem(table.item(row, 0))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesListenersEditClicked(dashboard: QtCore.QObject):
    """ 
    Copies information from the table into the New Listener section.
    """
    table = dashboard.ui.tableWidget_sensor_nodes_listeners
    selected_items = table.selectedItems()

    if not selected_items:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Please select a listener to edit.")
        return

    # Get the selected row index
    selected_row = selected_items[0].row()

    # Extract data from the selected row
    # status = table.item(selected_row, 0).text()
    listener_type = table.item(selected_row, 1).text()
    listener_name = table.item(selected_row, 2).text()
    parameters_text = table.item(selected_row, 3).text()
    parameters = ast.literal_eval(parameters_text)

    # Update the UI elements with the extracted values
    dashboard.ui.comboBox_sensor_nodes_listeners_type.setCurrentText(listener_type)
    dashboard.ui.textEdit_sensor_nodes_listeners_name.setPlainText(listener_name)

    # Populate parameter fields based on the listener type
    if listener_type == "Meshtastic":
        dashboard.ui.textEdit_sensor_nodes_listeners_meshtastic_serial_port.setPlainText(parameters.get("serial_port", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_meshtastic_baud_rate.setPlainText(parameters.get("baud_rate", ""))
    elif listener_type == "ZMQ SUB":
        dashboard.ui.textEdit_sensor_nodes_listeners_zmq_ip_address.setPlainText(parameters.get("ip_address", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_zmq_port.setPlainText(parameters.get("port", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_zmq_topic.setPlainText(parameters.get("topic_filter", ""))
    elif listener_type == "Website Poller":
        dashboard.ui.textEdit_sensor_nodes_listeners_website_url.setPlainText(parameters.get("url", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_website_interval.setPlainText(parameters.get("check_interval", ""))
    elif listener_type == "Serial Port":
        dashboard.ui.textEdit_sensor_nodes_listeners_serial_serial_port.setPlainText(parameters.get("serial_port", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_serial_baud_rate.setPlainText(parameters.get("baud_rate", ""))
    elif listener_type == "TCP/UDP":
        dashboard.ui.comboBox_sensor_nodes_listeners_tcp_udp_protocol.setCurrentText(parameters.get("protocol", "TCP"))
        dashboard.ui.textEdit_sensor_nodes_listeners_tcp_udp_ip_address.setPlainText(parameters.get("ip_address", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_tcp_udp_port.setPlainText(parameters.get("port", ""))
    elif listener_type == "Filesystem":
        dashboard.ui.textEdit_sensor_nodes_listeners_filesytem_folder.setPlainText(parameters.get("folder", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_filesystem_pattern.setPlainText(parameters.get("file_pattern", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_filesystem_filepath.setPlainText(parameters.get("filepath", ""))

        filepath = parameters.get("filepath", "")
        if filepath:
            dashboard.ui.comboBox_sensor_nodes_listeners_filesystem_type.setCurrentText("File Changes")
        else:
            dashboard.ui.comboBox_sensor_nodes_listeners_filesystem_type.setCurrentText("New Files")
    elif listener_type == "MQTT":
        dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_broker_address.setPlainText(parameters.get("broker_address", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_port.setPlainText(parameters.get("port", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_topic.setPlainText(parameters.get("topic", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_username.setPlainText(parameters.get("username", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_password.setPlainText(parameters.get("password", ""))

    
@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesListenersDeleteClicked(dashboard: QtCore.QObject):
    """ 
    Deletes the selected row in the table and sends a message to the HIPRFISR to delete the listener.
    """
    table = dashboard.ui.tableWidget_sensor_nodes_listeners
    selected_items = table.selectedItems()

    if not selected_items:
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Please select a listener to delete.")
        return

    # Get the selected row index
    selected_row = selected_items[0].row()
    listener_name = table.item(selected_row, 2).text()  # Assuming 'Name' is in column 2

    # Confirmation dialog before deletion
    ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(dashboard, f"Are you sure you want to delete listener '{listener_name}'?")
    if ret == QtWidgets.QMessageBox.No:
        return

    # Send the Message
    await dashboard.backend.deleteListener(listener_name)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesListenersEnableDisableClicked(dashboard: QtCore.QObject):
    """ 
    Opens a dialog of potential serial ports.
    """
    table = dashboard.ui.tableWidget_sensor_nodes_listeners
    selected_items = table.selectedItems()

    if not selected_items:
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Please select a listener to enable/disable.")
        return

    # Get the selected row index
    selected_row = selected_items[0].row()

    # Extract data from the selected row
    # status = table.item(selected_row, 0).text()
    listener_type = table.item(selected_row, 1).text()
    listener_name = table.item(selected_row, 2).text()
    parameters_text = table.item(selected_row, 3).text()
    parameters = ast.literal_eval(parameters_text)

    # Send the Message
    await dashboard.backend.enableDisableListener(listener_type, listener_name, parameters) 


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesListenersFilesystemFolderBrowseClicked(dashboard: QtCore.QObject):
    """ 
    Chooses a folder to monitor.
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    dialog.setFileMode(QtWidgets.QFileDialog.Directory)
    dialog.setOption(QtWidgets.QFileDialog.ShowDirsOnly, True)

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_sensor_nodes_listeners_filesytem_folder.setText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesListenersFilesystemFilepathBrowseClicked(dashboard: QtCore.QObject):
    """ 
    Chooses a file to monitor.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.FISSURE_ROOT  # Default Directory
    dialog.setDirectory(directory)
    # dialog.setNameFilters(['IQ/Misc. (*.iq *.dat)','IQ Recordings (*.iq)','Misc. (*.dat)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_sensor_nodes_listeners_filesystem_filepath.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesReportsSaveClicked(dashboard: QtCore.QObject):
    """ 
    Saves the reports from `tableWidget_reports` to a .txt or .csv file.
    """
    # Define the default directory
    directory = os.path.join(fissure.utils.LOG_DIR, "Session Logs")

    # Open the Save File Dialog
    dialog = QtWidgets.QFileDialog()
    dialog.setDirectory(directory)
    dialog.setFilter(dialog.filter() | QtCore.QDir.Hidden)
    dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
    dialog.setNameFilters(["Text Files (*.txt)", "CSV Files (*.csv)"])

    if dialog.exec_() == QtWidgets.QDialog.Accepted:
        # Get the selected file path
        fname = dialog.selectedFiles()[0]

        # Get the selected filter (CSV or TXT)
        selected_filter = dialog.selectedNameFilter()

        # Ensure the correct file extension based on the selected filter
        if "CSV Files" in selected_filter:
            file_format = "csv"
            if not fname.lower().endswith(".csv"):
                fname += ".csv"
        else:
            file_format = "txt"
            if not fname.lower().endswith(".txt"):
                fname += ".txt"

        try:
            # Extract data from tableWidget_reports
            table = dashboard.ui.tableWidget_reports
            row_count = table.rowCount()
            col_count = table.columnCount()

            if file_format == "txt":
                with open(fname, "w", encoding="utf-8") as file:
                    for row in range(row_count):
                        row_data = []
                        for col in range(col_count):
                            item = table.item(row, col)
                            row_data.append(item.text() if item else "")
                        file.write(" | ".join(row_data) + "\n")  # Format for readability
            else:  # CSV format
                with open(fname, "w", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    # Write header row (if available)
                    headers = [table.horizontalHeaderItem(col).text() if table.horizontalHeaderItem(col) else f"Column {col+1}" for col in range(col_count)]
                    writer.writerow(headers)
                    # Write table rows
                    for row in range(row_count):
                        writer.writerow([table.item(row, col).text() if table.item(row, col) else "" for col in range(col_count)])

            dashboard.logger.info(f"File saved successfully at: {fname}")
        except Exception as e:
            dashboard.logger.error(f"Error saving file: {e}")
    else:
        dashboard.logger.debug("File save dialog was canceled.")

@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesPluginSelected(dashboard: QtCore.QObject):
    """ 
    Slot to handle the selection of a plugin from the dropdown.
    This will populate the operations list with the available operations for the selected plugin.
    """
    # Get selected plugin
    selected_plugin = str(dashboard.ui.comboBox_select_plugin.currentText())

    # Clear previous operations
    combobox_ops: QtWidgets.QComboBox = dashboard.ui.comboBox_select_plugin_op
    combobox_ops.clear()
    params_table: QtWidgets.QTableWidget = dashboard.ui.tableWidget_plugin_op_params
    params_table.setRowCount(0)  # Clear previous parameters
    res_table: QtWidgets.QTableWidget = dashboard.ui.tableWidget_plugin_op_resources
    res_table.setRowCount(0)  # Clear previous resources
    iface_table: QtWidgets.QTableWidget = dashboard.ui.tableWidget_plugin_op_interfaces
    iface_table.setRowCount(0)  # Clear previous interface

    # If no plugin is selected, return
    if not selected_plugin:
        return

    # Send request to get plugin parameters
    PARAMETERS = {
        "plugin": selected_plugin,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
        fissure.comms.MessageFields.MESSAGE_NAME: "plugin_get_operations",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await dashboard.backend.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesOperationRun(dashboard: QtCore.QObject):
    """ 
    Slot to run a plugin operation.
    """
    # Get parameters for the plugin operation
    parameters = {}
    params_table: QtWidgets.QTableWidget = dashboard.ui.tableWidget_plugin_op_params
    for row in range(params_table.rowCount()):
        value_item = params_table.item(row, 0)  # User entered value
        if value_item is None:
            required = bool(params_table.item(row, 2)) # get required state
            if required:
                value_item = params_table.item(row, 1)  # default value
                if value_item is None:
                    fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Parameter '{params_table.verticalHeaderItem(row).text()}' is required but not provided.")
                    return
                parameters[params_table.verticalHeaderItem(row).text()] = value_item.text()

        else:
            parameters[params_table.verticalHeaderItem(row).text()] = value_item.text()

    combobox_plugin: QtWidgets.QComboBox = dashboard.ui.comboBox_select_plugin
    combobox_op: QtWidgets.QComboBox = dashboard.ui.comboBox_select_plugin_op
    PARAMETERS = {
        "node_uid": dashboard.selected_node_uid,
        "plugin": combobox_plugin.currentText(),
        "operation": combobox_op.currentText(),
        "parameters": parameters
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
        fissure.comms.MessageFields.MESSAGE_NAME: "run_plugin_operation",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await dashboard.backend.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesOperationStop(dashboard: QtCore.QObject):
    """ 
    Slot to stop a plugin operation.
    """
    ops_table: QtWidgets.QListWidget = dashboard.ui.listWidget_operations
    selected_items = ops_table.selectedItems()
    if not selected_items:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Please select an operation to stop.")
        return
    selected_item = selected_items[0]
    selected_text = selected_item.text()
    match = re.search(r"\(ID:\s*([a-fA-F0-9\-]+)\)", selected_text)
    if match:
        operation_id = match.group(1)
    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Could not extract operation ID from selection.")
        return

    PARAMETERS = {
        "node_uid": dashboard.selected_node_uid,
        "operation_id": operation_id,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
        fissure.comms.MessageFields.MESSAGE_NAME: "stop_plugin_operation",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await dashboard.backend.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesPluginOperationOpen(dashboard: QtCore.QObject):
    """ 
    Slot to open a plugin operation.
    """
    combobox_plugin: QtWidgets.QComboBox = dashboard.ui.comboBox_select_plugin
    combobox_op: QtWidgets.QComboBox = dashboard.ui.comboBox_select_plugin_op
    PARAMETERS = {
        "plugin": combobox_plugin.currentText(),
        "operation": combobox_op.currentText(),
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
        fissure.comms.MessageFields.MESSAGE_NAME: "plugin_get_operation_parameters",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await dashboard.backend.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)