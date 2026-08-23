from PyQt5 import QtCore, QtGui, QtWidgets
import asyncio
import os
import qasync
import time
import uuid

import fissure.utils
from ..UI_Components import DetectorSelectionDialog


ACTION_QUERY_CONTEXT = "targets_actions.single_action.actions"
ACTION_SCHEMA_CONTEXT = "targets_actions.single_action.schema"


def initialize_single_action_tab(dashboard: QtCore.QObject):
    """Initialize the generic Targets & Actions Single Action workflow."""
    dashboard.single_action_action_catalog = []
    dashboard.single_action_filtered_actions = []
    dashboard.single_action_action_catalog_node_uid = ""
    dashboard.single_action_hardware_signature = None
    dashboard.single_action_selected_plugin = ""
    dashboard.single_action_selected_action = ""
    dashboard.single_action_parameter_widgets = {}
    dashboard.single_action_current_schema = {}
    dashboard.single_action_customized = False
    dashboard.single_action_query_pending = False

    dashboard.single_action_start_pending = False
    dashboard.single_action_running = False
    dashboard.single_action_node_uid = ""
    dashboard.single_action_operation_id = ""
    dashboard.single_action_target_id = ""
    dashboard.single_action_run_plugin = ""
    dashboard.single_action_run_action = ""
    dashboard.single_action_run_parameters = {}
    dashboard.single_action_started_at = 0.0
    dashboard.single_action_seen_running_status = False
    dashboard.single_action_stop_requested = False
    dashboard.single_action_waiting_for_detection = False
    dashboard.single_action_monitor_action_status = False
    dashboard.single_action_detector_operation_ids = set()
    dashboard.single_action_detection_event = None
    dashboard.single_action_detection = None
    dashboard.single_action_task = None

    dashboard.ui.stackedWidget_ta_single_action.setCurrentWidget(dashboard.ui.page_ta_single_action_no_node)

    select_node_icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", "select_node.png")
    if os.path.isfile(select_node_icon_path):
        select_node_pixmap = QtGui.QPixmap(select_node_icon_path)
        dashboard.ui.label_ta_single_action_select_sensor_node_image.setPixmap(select_node_pixmap)
        dashboard.ui.label_ta_single_action_select_sensor_node_image.setScaledContents(False)
        dashboard.ui.label_ta_single_action_select_sensor_node_image.setAlignment(QtCore.Qt.AlignCenter)

    dashboard.ui.pushButton_ta_single_action_query.setText("Query Actions")
    dashboard.ui.pushButton_ta_single_action_customize.setText("Customize")
    dashboard.ui.pushButton_ta_single_action_customize.setEnabled(False)
    _set_single_action_start_stop_button(dashboard, False)
    dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(False)
    dashboard.ui.label_ta_single_action_execution_status.setText("Idle")
    dashboard.ui.label_ta_single_action_execution_operation_id.setText("—")
    dashboard.ui.textEdit_ta_single_action_execution_result.clear()
    dashboard.ui.textEdit_ta_single_action_execution_result.setReadOnly(True)

    scroll_area = dashboard.ui.scrollArea_ta_single_action_parameters
    scroll_area.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    scroll_area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)

    table = dashboard.ui.tableWidget_ta_single_action_detectors
    header = table.horizontalHeader()
    header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
    header.setDefaultAlignment(QtCore.Qt.AlignCenter | QtCore.Qt.AlignVCenter)
    table.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    table.setTextElideMode(QtCore.Qt.ElideRight)
    table.setWordWrap(False)

    _clear_single_action_parameter_widgets(dashboard)
    update_single_action_selected_node_gate(dashboard)


def _single_action_selected_node_available(dashboard: QtCore.QObject):
    """Return True when the globally selected Sensor Node is currently available."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        return False

    node_state = (getattr(dashboard, "node_states", {}) or {}).get(node_uid)
    if isinstance(node_state, dict) and node_state.get("connected") is False:
        return False

    return True


def update_single_action_selected_node_gate(dashboard: QtCore.QObject):
    """Show Single Action controls only while a Sensor Node is selected or an action is active."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    has_selected_node = _single_action_selected_node_available(dashboard)
    previous_node_uid = str(getattr(dashboard, "single_action_action_catalog_node_uid", "") or "").strip()
    node_changed = node_uid != previous_node_uid
    active = _single_action_active(dashboard)

    dashboard.ui.stackedWidget_ta_single_action.setCurrentWidget(
        dashboard.ui.page_ta_single_action_controls
        if has_selected_node or active
        else dashboard.ui.page_ta_single_action_no_node
    )

    if node_changed and not active:
        dashboard.single_action_action_catalog_node_uid = node_uid
        dashboard.single_action_action_catalog = []
        dashboard.single_action_filtered_actions = []
        dashboard.single_action_hardware_signature = None
        dashboard.single_action_query_pending = False
        dashboard.ui.pushButton_ta_single_action_query.setText("Query Actions")
        _reset_single_action_action_selection(dashboard)

    if not active:
        _refresh_single_action_hardware_filter(dashboard)

    if active:
        _single_action_set_execution_locked(dashboard, True)
        _set_single_action_start_stop_button(dashboard, True)
        dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(
            not bool(getattr(dashboard, "single_action_stop_requested", False))
        )
        return

    dashboard.ui.comboBox_ta_single_action_hardware.setEnabled(has_selected_node)
    dashboard.ui.comboBox_ta_single_action_plugin.setEnabled(has_selected_node and bool(dashboard.single_action_filtered_actions))
    dashboard.ui.comboBox_ta_single_action_action.setEnabled(has_selected_node and bool(dashboard.single_action_filtered_actions))
    dashboard.ui.pushButton_ta_single_action_query.setEnabled(has_selected_node and not dashboard.single_action_query_pending)

    has_action = bool(dashboard.single_action_selected_plugin and dashboard.single_action_selected_action)
    dashboard.ui.pushButton_ta_single_action_customize.setEnabled(has_selected_node and has_action)
    dashboard.ui.pushButton_ta_single_action_detector_add.setEnabled(has_selected_node)
    dashboard.ui.pushButton_ta_single_action_detector_remove.setEnabled(
        has_selected_node and dashboard.ui.tableWidget_ta_single_action_detectors.rowCount() > 0
    )
    _set_single_action_start_stop_button(dashboard, False)
    dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(
        has_selected_node and has_action and bool(getattr(dashboard, "single_action_customized", False))
    )

    if not has_selected_node:
        dashboard.ui.label_ta_single_action_setup_info.setText("Select a Sensor Node to query available actions.")
        dashboard.ui.label_ta_single_action_execution_status.setText("Unavailable")
    elif not dashboard.single_action_action_catalog:
        dashboard.ui.label_ta_single_action_execution_status.setText("Idle")


def _refresh_single_action_hardware_filter(dashboard: QtCore.QObject):
    """Populate the optional hardware filter from the globally selected Sensor Node."""
    combo = dashboard.ui.comboBox_ta_single_action_hardware
    display_names = []

    if _single_action_selected_node_available(dashboard):
        display_names = fissure.utils.hardware.selectedNodeHardwareDisplayNames(dashboard, "attack")

    hardware_records = []
    for display_name in display_names:
        hardware_type, *_ = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, display_name, "attack")
        hardware_records.append((str(display_name or "").strip(), str(hardware_type or "").strip()))

    signature = tuple(hardware_records)
    if getattr(dashboard, "single_action_hardware_signature", None) == signature and combo.count() > 0:
        _filter_single_action_action_catalog(dashboard)
        return

    dashboard.single_action_hardware_signature = signature
    current_text = str(combo.currentText() or "").strip()

    combo.blockSignals(True)
    combo.clear()
    combo.addItem("All Compatible", {"mode": "all", "hardware_type": ""})
    combo.addItem("No Hardware Required", {"mode": "none", "hardware_type": ""})

    for display_name, hardware_type in hardware_records:
        combo.addItem(display_name, {"mode": "hardware", "hardware_type": hardware_type, "display_name": display_name})

    restore_index = combo.findText(current_text, QtCore.Qt.MatchExactly)
    combo.setCurrentIndex(restore_index if restore_index >= 0 else 0)
    combo.blockSignals(False)
    _filter_single_action_action_catalog(dashboard)


def _single_action_hardware_matches(candidate: str, selected: str):
    candidate_text = str(candidate or "").strip().lower()
    selected_text = str(selected or "").strip().lower()
    if not candidate_text or not selected_text:
        return False
    return candidate_text in selected_text or selected_text in candidate_text


def _single_action_configured_hardware_types(dashboard: QtCore.QObject):
    types = []
    combo = dashboard.ui.comboBox_ta_single_action_hardware
    for index in range(combo.count()):
        record = combo.itemData(index)
        if not isinstance(record, dict) or record.get("mode") != "hardware":
            continue
        hardware_type = str(record.get("hardware_type", "") or "").strip()
        if hardware_type:
            types.append(hardware_type)
    return types


def _filter_single_action_action_catalog(dashboard: QtCore.QObject):
    """Apply the hardware filter locally, then rebuild the optional Plugin filter."""
    hardware_record = dashboard.ui.comboBox_ta_single_action_hardware.currentData()
    mode = "all"
    selected_type = ""

    if isinstance(hardware_record, dict):
        mode = str(hardware_record.get("mode", "all") or "all")
        selected_type = str(hardware_record.get("hardware_type", "") or "").strip()

    configured_types = _single_action_configured_hardware_types(dashboard)
    filtered = []

    for action_record in getattr(dashboard, "single_action_action_catalog", []) or []:
        if not isinstance(action_record, dict):
            continue

        action_hardware = [
            str(value or "").strip()
            for value in (action_record.get("hardware", []) or [])
            if str(value or "").strip()
        ]

        if mode == "none":
            if action_hardware:
                continue
        elif mode == "hardware":
            if action_hardware and not any(_single_action_hardware_matches(value, selected_type) for value in action_hardware):
                continue
        elif action_hardware:
            compatible = any(
                _single_action_hardware_matches(action_type, configured_type)
                for action_type in action_hardware
                for configured_type in configured_types
            )
            if not compatible:
                continue

        filtered.append(action_record)

    dashboard.single_action_filtered_actions = filtered

    plugin_combo = dashboard.ui.comboBox_ta_single_action_plugin
    current_plugin = str(plugin_combo.currentText() or "").strip()
    plugins = sorted(
        {
            str(record.get("plugin", "") or "").strip()
            for record in filtered
            if str(record.get("plugin", "") or "").strip()
        },
        key=str.lower,
    )

    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.addItem("All Plugins", None)
    for plugin_name in plugins:
        plugin_combo.addItem(plugin_name, plugin_name)

    restore_index = plugin_combo.findText(current_plugin, QtCore.Qt.MatchExactly)
    plugin_combo.setCurrentIndex(restore_index if restore_index >= 0 else 0)
    plugin_combo.blockSignals(False)
    plugin_combo.setEnabled(_single_action_selected_node_available(dashboard) and bool(filtered))

    _populate_single_action_actions(dashboard)


def _populate_single_action_actions(dashboard: QtCore.QObject):
    """Populate actions for the optional Plugin filter while preserving a valid selection."""
    plugin_combo = dashboard.ui.comboBox_ta_single_action_plugin
    plugin_name = str(plugin_combo.currentData() or "").strip()
    previous_plugin = str(getattr(dashboard, "single_action_selected_plugin", "") or "").strip()
    previous_action = str(getattr(dashboard, "single_action_selected_action", "") or "").strip()

    records = []
    for action_record in getattr(dashboard, "single_action_filtered_actions", []) or []:
        record_plugin = str(action_record.get("plugin", "") or "").strip()
        action_name = str(action_record.get("action", "") or "").strip()
        if not record_plugin or not action_name:
            continue
        if plugin_name and record_plugin != plugin_name:
            continue
        records.append(action_record)

    records.sort(key=lambda record: (str(record.get("plugin", "")).lower(), str(record.get("action", "")).lower()))

    action_combo = dashboard.ui.comboBox_ta_single_action_action
    action_combo.blockSignals(True)
    action_combo.clear()

    restore_index = -1
    for action_record in records:
        record_plugin = str(action_record.get("plugin", "") or "").strip()
        action_name = str(action_record.get("action", "") or "").strip()
        display_text = action_name if plugin_name else f"{record_plugin}: {action_name}"
        action_combo.addItem(display_text, action_record)
        if record_plugin == previous_plugin and action_name == previous_action:
            restore_index = action_combo.count() - 1

    action_combo.setCurrentIndex(restore_index if restore_index >= 0 else (0 if action_combo.count() else -1))
    action_combo.blockSignals(False)
    action_combo.setEnabled(_single_action_selected_node_available(dashboard) and bool(records))
    _slotSingleActionActionChanged(dashboard)

    if not records:
        dashboard.ui.label_ta_single_action_setup_info.setText("No actions match the current filters.")


def _reset_single_action_action_selection(dashboard: QtCore.QObject):
    """Clear the selected action and any previously rendered schema."""
    dashboard.single_action_selected_plugin = ""
    dashboard.single_action_selected_action = ""
    dashboard.single_action_current_schema = {}
    dashboard.single_action_customized = False
    dashboard.ui.comboBox_ta_single_action_plugin.clear()
    dashboard.ui.comboBox_ta_single_action_action.clear()
    dashboard.ui.pushButton_ta_single_action_customize.setEnabled(False)
    dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(False)
    _clear_single_action_parameter_widgets(dashboard)


def _single_action_selection_summary(action_record: dict):
    plugin_name = str(action_record.get("plugin", "") or "").strip()
    action_name = str(action_record.get("action", "") or "").strip()
    hardware = [str(value or "").strip() for value in (action_record.get("hardware", []) or []) if str(value or "").strip()]
    tags = [str(value or "").strip() for value in (action_record.get("tags", []) or []) if str(value or "").strip() and str(value or "").strip() != "All"]

    lines = [f"{plugin_name}: {action_name}"]
    lines.append(f"Hardware: {', '.join(hardware) if hardware else 'No hardware required'}")
    if tags:
        lines.append(f"Tags: {', '.join(tags)}")
    return "\n".join(lines)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSingleActionQueryClicked(dashboard: QtCore.QObject):
    """Query the selected Sensor Node once for the complete Dashboard action catalog."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid or not _single_action_selected_node_available(dashboard):
        return

    dashboard.single_action_query_pending = True
    dashboard.ui.pushButton_ta_single_action_query.setEnabled(False)
    dashboard.ui.pushButton_ta_single_action_query.setText("Querying...")
    dashboard.ui.label_ta_single_action_setup_info.setText("Querying available actions...")

    await dashboard.backend.queryPluginActions(node_uid, context=ACTION_QUERY_CONTEXT, scope="all_plugins")


def handle_single_action_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    """Cache one node action catalog and apply the local Hardware/Plugin filters."""
    if context != ACTION_QUERY_CONTEXT:
        return
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return

    dashboard.single_action_query_pending = False
    dashboard.single_action_action_catalog_node_uid = str(node_uid or "").strip()
    dashboard.single_action_action_catalog = actions if isinstance(actions, list) else []
    dashboard.ui.pushButton_ta_single_action_query.setText("Query Actions")
    dashboard.ui.pushButton_ta_single_action_query.setEnabled(_single_action_selected_node_available(dashboard))

    _filter_single_action_action_catalog(dashboard)

    total = len(dashboard.single_action_action_catalog)
    visible = len(dashboard.single_action_filtered_actions)
    if total:
        dashboard.ui.label_ta_single_action_setup_info.setText(f"{visible} compatible action(s) shown from {total} available on this node.")
    else:
        dashboard.ui.label_ta_single_action_setup_info.setText("No Dashboard-compatible plugin actions were returned by this Sensor Node.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSingleActionHardwareChanged(dashboard: QtCore.QObject):
    """Apply the optional Hardware filter to the cached action catalog."""
    _filter_single_action_action_catalog(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSingleActionPluginChanged(dashboard: QtCore.QObject):
    """Apply the optional Plugin filter to the hardware-filtered action catalog."""
    _populate_single_action_actions(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSingleActionActionChanged(dashboard: QtCore.QObject):
    """Track the selected action and invalidate parameters only when it changes."""
    if _single_action_active(dashboard):
        return

    action_record = dashboard.ui.comboBox_ta_single_action_action.currentData()

    if not isinstance(action_record, dict):
        dashboard.single_action_selected_plugin = ""
        dashboard.single_action_selected_action = ""
        dashboard.single_action_current_schema = {}
        dashboard.single_action_customized = False
        dashboard.ui.pushButton_ta_single_action_customize.setEnabled(False)
        dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(False)
        _clear_single_action_parameter_widgets(dashboard)
        return

    plugin_name = str(action_record.get("plugin", "") or "").strip()
    action_name = str(action_record.get("action", "") or "").strip()
    same_selection = (
        plugin_name == str(getattr(dashboard, "single_action_selected_plugin", "") or "").strip()
        and action_name == str(getattr(dashboard, "single_action_selected_action", "") or "").strip()
    )

    dashboard.ui.label_ta_single_action_setup_info.setText(_single_action_selection_summary(action_record))
    dashboard.ui.pushButton_ta_single_action_customize.setText("Customize")
    dashboard.ui.pushButton_ta_single_action_customize.setEnabled(
        bool(plugin_name and action_name) and _single_action_selected_node_available(dashboard)
    )

    if same_selection:
        return

    dashboard.single_action_selected_plugin = plugin_name
    dashboard.single_action_selected_action = action_name
    dashboard.single_action_current_schema = {}
    dashboard.single_action_customized = False
    dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(False)
    _clear_single_action_parameter_widgets(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSingleActionCustomizeClicked(dashboard: QtCore.QObject):
    """Load the selected action schema from the globally selected Sensor Node."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    plugin_name = str(getattr(dashboard, "single_action_selected_plugin", "") or "").strip()
    action_name = str(getattr(dashboard, "single_action_selected_action", "") or "").strip()
    if not node_uid or not plugin_name or not action_name or not _single_action_selected_node_available(dashboard):
        return

    dashboard.ui.pushButton_ta_single_action_customize.setEnabled(False)
    dashboard.ui.pushButton_ta_single_action_customize.setText("Loading...")
    await dashboard.backend.queryPluginActionSchema(node_uid, plugin_name, action_name, context=ACTION_SCHEMA_CONTEXT)


def _clear_single_action_parameter_widgets(dashboard: QtCore.QObject):
    """Clear the dynamically generated Single Action parameter controls."""
    contents = dashboard.ui.scrollAreaWidgetContents_ta_single_action_parameters
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
    layout.setHorizontalSpacing(10)
    layout.setVerticalSpacing(8)
    layout.setAlignment(QtCore.Qt.AlignTop)
    layout.setColumnStretch(0, 1)
    layout.setColumnStretch(1, 3)
    dashboard.single_action_parameter_widgets = {}


def _create_single_action_parameter_widget(parent, parameter: dict):
    """Create one editor from a generic plugin action-schema parameter."""
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
        widget = QtWidgets.QLabel(str(default or ""), parent)
        widget.setWordWrap(True)
        widget.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
    else:
        widget = QtWidgets.QLineEdit(str(default or ""), parent)

    widget.setObjectName(f"single_action_parameter_{parameter_name}")
    widget.setProperty("uiRole", "singleActionParameterInfo" if parameter_type == "label" else "singleActionParameterEditor")

    description = str(parameter.get("description", "") or "").strip()
    if description:
        widget.setToolTip(description)

    return widget


def handle_single_action_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
):
    """Render the selected plugin action schema in the Single Action Parameters card."""
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return
    if plugin_name != getattr(dashboard, "single_action_selected_plugin", ""):
        return
    if action_name != getattr(dashboard, "single_action_selected_action", ""):
        return

    parameter_list = parameters if isinstance(parameters, list) else []
    dashboard.single_action_current_schema = {"params": [dict(parameter) for parameter in parameter_list if isinstance(parameter, dict)]}
    _clear_single_action_parameter_widgets(dashboard)

    contents = dashboard.ui.scrollAreaWidgetContents_ta_single_action_parameters
    layout = contents.layout()
    row = 0

    for parameter in parameter_list:
        if not isinstance(parameter, dict):
            continue

        name = str(parameter.get("name", "") or "").strip()
        if not name:
            continue

        label_text = str(parameter.get("label") or name).strip()
        label = QtWidgets.QLabel(f"{label_text}:", contents)
        label.setObjectName(f"label2_single_action_parameter_{name}")
        label.setProperty("uiRole", "singleActionParameterLabel")
        label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)

        description = str(parameter.get("description", "") or "").strip()
        if description:
            label.setToolTip(description)

        widget = _create_single_action_parameter_widget(contents, parameter)
        layout.addWidget(label, row, 0)
        layout.addWidget(widget, row, 1)
        dashboard.single_action_parameter_widgets[name] = {"widget": widget, "schema": dict(parameter)}
        row += 1

    if row == 0:
        empty_label = QtWidgets.QLabel("No parameters required for this action.", contents)
        empty_label.setObjectName("label_single_action_no_parameters")
        empty_label.setProperty("uiRole", "singleActionParameterInfo")
        layout.addWidget(empty_label, 0, 0, 1, 2)

    dashboard.single_action_customized = True
    dashboard.ui.pushButton_ta_single_action_customize.setText("Customize")
    dashboard.ui.pushButton_ta_single_action_customize.setEnabled(_single_action_selected_node_available(dashboard))
    dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(
        _single_action_selected_node_available(dashboard) and not _single_action_active(dashboard)
    )


def _single_action_parameter_value(widget):
    """Return the current Python value from one Single Action parameter editor."""
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


def collect_single_action_parameters(dashboard: QtCore.QObject):
    """Collect customized values for the currently selected Single Action."""
    parameters = {}
    for name, record in (getattr(dashboard, "single_action_parameter_widgets", {}) or {}).items():
        widget = record.get("widget") if isinstance(record, dict) else None
        schema = record.get("schema", {}) if isinstance(record, dict) else {}
        if widget is None or str(schema.get("type", "") or "").strip().lower() == "label":
            continue
        parameters[name] = _single_action_parameter_value(widget)
    return parameters


def _slotSingleActionDetectorAddClicked(dashboard: QtCore.QObject):
    """Add one reusable detector configuration to Single Action."""
    detector_config = dashboard.openPopUp("DetectorSelectionDialog", DetectorSelectionDialog)
    if not detector_config:
        return

    plugin_name = str(detector_config.get("plugin", "") or "").strip()
    action_name = str(detector_config.get("action", "") or "").strip()
    hardware = str(detector_config.get("hardware", "") or "").strip()
    parameters = detector_config.get("parameters", {}) or {}

    if not plugin_name or not action_name:
        dashboard.logger.warning("Single Action detector selection returned without a plugin/action.")
        return

    detector_name = f"{plugin_name}: {action_name}"
    parameter_summary = ", ".join(f"{name}={value}" for name, value in parameters.items())

    table = dashboard.ui.tableWidget_ta_single_action_detectors
    row = table.rowCount()
    table.insertRow(row)

    detector_item = QtWidgets.QTableWidgetItem(detector_name)
    detector_item.setTextAlignment(QtCore.Qt.AlignCenter)
    detector_item.setFlags(detector_item.flags() & ~QtCore.Qt.ItemIsEditable)
    detector_item.setData(QtCore.Qt.UserRole, detector_config)
    table.setItem(row, 0, detector_item)

    hardware_item = QtWidgets.QTableWidgetItem(hardware or "No Hardware")
    hardware_item.setTextAlignment(QtCore.Qt.AlignCenter)
    hardware_item.setFlags(hardware_item.flags() & ~QtCore.Qt.ItemIsEditable)
    table.setItem(row, 1, hardware_item)

    parameters_item = QtWidgets.QTableWidgetItem(f"  {parameter_summary}")
    parameters_item.setTextAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
    parameters_item.setFlags(parameters_item.flags() & ~QtCore.Qt.ItemIsEditable)
    parameters_item.setToolTip(parameter_summary)
    table.setItem(row, 2, parameters_item)

    table.resizeRowsToContents()
    dashboard.ui.pushButton_ta_single_action_detector_remove.setEnabled(True)
    dashboard.logger.info(f"Added Single Action detector: {detector_name}")


def _slotSingleActionDetectorRemoveClicked(dashboard: QtCore.QObject):
    """Remove the selected Single Action detector."""
    table = dashboard.ui.tableWidget_ta_single_action_detectors
    row = table.currentRow()
    if row < 0:
        return

    table.removeRow(row)
    dashboard.ui.pushButton_ta_single_action_detector_remove.setEnabled(table.rowCount() > 0)


def _collect_single_action_detector_configs(dashboard: QtCore.QObject):
    """Return detector configurations stored in the Single Action detector table."""
    table = dashboard.ui.tableWidget_ta_single_action_detectors
    detector_configs = []

    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is None:
            continue

        detector_config = item.data(QtCore.Qt.UserRole)
        if isinstance(detector_config, dict):
            detector_configs.append(dict(detector_config))

    return detector_configs


def _build_single_action_detector_parameters(
    dashboard: QtCore.QObject,
    detector_config: dict,
    operation_id: str,
):
    """Build detector parameters with the selected detector hardware."""
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
            "operation_id": operation_id,
            "requester": "dashboard",
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


async def _start_single_action_detectors(
    dashboard: QtCore.QObject,
    node_uid: str,
    detector_configs: list,
):
    """Launch all detector operations configured for the current Single Action."""
    launch_requests = []
    operation_ids = set()

    for detector_config in detector_configs:
        plugin_name = str(detector_config.get("plugin", "") or "").strip()
        action_name = str(detector_config.get("action", "") or "").strip()
        if not plugin_name or not action_name:
            raise ValueError("Single Action detector is missing plugin/action information.")

        operation_id = str(uuid.uuid4())
        parameters = _build_single_action_detector_parameters(dashboard, detector_config, operation_id)
        operation_ids.add(operation_id)
        launch_requests.append((plugin_name, action_name, parameters))

    dashboard.single_action_detector_operation_ids = operation_ids

    tasks = [
        dashboard.backend.tacticalNodeExecute([node_uid], plugin_name, action_name, parameters)
        for plugin_name, action_name, parameters in launch_requests
    ]
    if tasks:
        await asyncio.gather(*tasks)

    dashboard.logger.info(
        f"Single Action waiting on {len(operation_ids)} detector operation(s): {sorted(operation_ids)}"
    )


async def _stop_single_action_detectors(dashboard: QtCore.QObject, node_uid: str):
    """Stop detector operations launched for the current Single Action."""
    operation_ids = list(getattr(dashboard, "single_action_detector_operation_ids", set()) or set())
    dashboard.single_action_detector_operation_ids = set()

    for operation_id in operation_ids:
        try:
            await dashboard.backend.stopPluginOperation(node_uid, operation_id)
        except Exception as error:
            dashboard.logger.warning(
                f"Could not stop Single Action detector operation {operation_id}: {error}"
            )


async def _wait_for_single_action_detection(dashboard: QtCore.QObject):
    """Wait until one configured detector reports a matching Detection or Stop is requested."""
    detection_event = getattr(dashboard, "single_action_detection_event", None)
    if detection_event is None:
        return False

    while not detection_event.is_set():
        if bool(getattr(dashboard, "single_action_stop_requested", False)):
            return False
        await asyncio.sleep(0.05)

    return True


def handle_single_action_detection(dashboard: QtCore.QObject, detection: dict):
    """Release a waiting Single Action when one of its detector operation IDs reports a Detection."""
    if not isinstance(detection, dict):
        return
    if not bool(getattr(dashboard, "single_action_waiting_for_detection", False)):
        return

    detection_event = getattr(dashboard, "single_action_detection_event", None)
    if detection_event is None or detection_event.is_set():
        return

    node_uid = str(detection.get("node_uid", "") or "").strip()
    action_node_uid = str(getattr(dashboard, "single_action_node_uid", "") or "").strip()
    if action_node_uid and node_uid and not _single_action_node_uids_match(action_node_uid, node_uid):
        return

    operation_id = str(detection.get("opid") or detection.get("operation_id") or "").strip()
    operation_ids = getattr(dashboard, "single_action_detector_operation_ids", set()) or set()
    if not operation_id or operation_id not in operation_ids:
        return

    dashboard.single_action_detection = dict(detection)
    detection_event.set()
    dashboard.logger.info(
        "Single Action detector matched: "
        f"operation_id={operation_id}, detector={detection.get('detector', '')}"
    )


async def _run_single_action(
    dashboard: QtCore.QObject,
    node_uid: str,
    plugin_name: str,
    action_name: str,
    parameters: dict,
    detector_configs: list,
):
    """Run one plugin action immediately or after optional detector gating."""
    try:
        if detector_configs:
            dashboard.single_action_waiting_for_detection = True
            dashboard.single_action_detection_event = asyncio.Event()
            dashboard.single_action_detection = None
            dashboard.ui.label_ta_single_action_execution_status.setText("Starting Detectors...")

            await _start_single_action_detectors(dashboard, node_uid, detector_configs)

            if bool(getattr(dashboard, "single_action_stop_requested", False)):
                await _stop_single_action_detectors(dashboard, node_uid)
                await _finish_single_action(dashboard, "Stopped")
                return

            dashboard.ui.label_ta_single_action_execution_status.setText("Waiting for Detection...")
            detected = await _wait_for_single_action_detection(dashboard)
            await _stop_single_action_detectors(dashboard, node_uid)
            dashboard.single_action_waiting_for_detection = False

            if bool(getattr(dashboard, "single_action_stop_requested", False)):
                await _finish_single_action(dashboard, "Stopped")
                return
            if not detected:
                await _finish_single_action(dashboard, "Error")
                return

            detection = getattr(dashboard, "single_action_detection", {}) or {}
            dashboard.logger.info(
                "Single Action detector gate released: "
                f"detector={detection.get('detector', '')}, "
                f"operation_id={detection.get('opid') or detection.get('operation_id') or ''}"
            )

        dashboard.single_action_monitor_action_status = False
        dashboard.ui.label_ta_single_action_execution_status.setText("Starting...")

        await dashboard.backend.tacticalNodeExecute(
            [node_uid],
            plugin_name,
            action_name,
            parameters,
        )

        dashboard.single_action_monitor_action_status = True
        dashboard.single_action_start_pending = False
        dashboard.single_action_running = True

    except Exception as error:
        dashboard.logger.error(f"Could not start Single Action: {error}")

        try:
            await _stop_single_action_detectors(dashboard, node_uid)
        except Exception:
            pass

        await _finish_single_action(dashboard, "Start Failed")


def _single_action_active(dashboard: QtCore.QObject):
    return bool(
        getattr(dashboard, "single_action_start_pending", False)
        or getattr(dashboard, "single_action_running", False)
    )


def _single_action_node_uids_match(first: str, second: str):
    first = str(first or "").strip()
    second = str(second or "").strip()
    if not first or not second:
        return False
    return first == second or first.endswith(second) or second.endswith(first)


def _set_single_action_start_stop_button(dashboard: QtCore.QObject, running: bool):
    button = dashboard.ui.pushButton_ta_single_action_start_stop
    button.setText("Stop" if running else "Start")
    button.setProperty("running", bool(running))
    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


def _single_action_set_execution_locked(dashboard: QtCore.QObject, locked: bool):
    """Lock setup and parameter controls while the current Single Action is active."""
    has_selected_node = _single_action_selected_node_available(dashboard)
    has_filtered_actions = bool(getattr(dashboard, "single_action_filtered_actions", []))
    has_action = bool(
        getattr(dashboard, "single_action_selected_plugin", "")
        and getattr(dashboard, "single_action_selected_action", "")
    )

    dashboard.ui.comboBox_ta_single_action_hardware.setEnabled(has_selected_node and not locked)
    dashboard.ui.comboBox_ta_single_action_plugin.setEnabled(has_selected_node and has_filtered_actions and not locked)
    dashboard.ui.comboBox_ta_single_action_action.setEnabled(has_selected_node and has_filtered_actions and not locked)
    dashboard.ui.pushButton_ta_single_action_query.setEnabled(
        has_selected_node and not dashboard.single_action_query_pending and not locked
    )
    dashboard.ui.pushButton_ta_single_action_customize.setEnabled(has_selected_node and has_action and not locked)
    dashboard.ui.pushButton_ta_single_action_detector_add.setEnabled(has_selected_node and not locked)
    dashboard.ui.pushButton_ta_single_action_detector_remove.setEnabled(
        has_selected_node
        and dashboard.ui.tableWidget_ta_single_action_detectors.rowCount() > 0
        and not locked
    )

    for record in (getattr(dashboard, "single_action_parameter_widgets", {}) or {}).values():
        widget = record.get("widget") if isinstance(record, dict) else None
        if widget is not None:
            widget.setEnabled(not locked)


def _single_action_clear_run_state(dashboard: QtCore.QObject):
    dashboard.single_action_start_pending = False
    dashboard.single_action_running = False
    dashboard.single_action_node_uid = ""
    dashboard.single_action_operation_id = ""
    dashboard.single_action_target_id = ""
    dashboard.single_action_run_plugin = ""
    dashboard.single_action_run_action = ""
    dashboard.single_action_run_parameters = {}
    dashboard.single_action_started_at = 0.0
    dashboard.single_action_seen_running_status = False
    dashboard.single_action_stop_requested = False
    dashboard.single_action_waiting_for_detection = False
    dashboard.single_action_monitor_action_status = False
    dashboard.single_action_detector_operation_ids = set()
    dashboard.single_action_detection_event = None
    dashboard.single_action_detection = None
    dashboard.single_action_task = None


def _single_action_result_text(
    dashboard: QtCore.QObject,
    status_text: str,
    node_status: str = "",
):
    started_at = float(getattr(dashboard, "single_action_started_at", 0.0) or 0.0)
    duration = max(0.0, time.time() - started_at) if started_at else 0.0
    plugin_name = str(getattr(dashboard, "single_action_run_plugin", "") or "")
    action_name = str(getattr(dashboard, "single_action_run_action", "") or "")
    node_uid = str(getattr(dashboard, "single_action_node_uid", "") or "")
    operation_id = str(getattr(dashboard, "single_action_operation_id", "") or "")
    target_id = str(getattr(dashboard, "single_action_target_id", "") or "")

    lines = [
        f"Status: {status_text}",
        f"Action: {plugin_name}: {action_name}",
        f"Sensor Node: {node_uid}",
        f"Operation ID: {operation_id}",
        f"Duration: {duration:.2f} s",
        f"Target: {target_id or 'No Target'}",
    ]
    if node_status:
        lines.append(f"Node Status: {node_status}")
    return "\n".join(lines)


async def _record_single_action_target_history(
    dashboard: QtCore.QObject,
    status_text: str,
):
    target_id = str(getattr(dashboard, "single_action_target_id", "") or "").strip()
    if not target_id or target_id not in (getattr(dashboard, "tactical_targets", {}) or {}):
        return

    started_at = float(getattr(dashboard, "single_action_started_at", 0.0) or 0.0)
    history_entry = {
        "event": "single_action",
        "operation_id": str(getattr(dashboard, "single_action_operation_id", "") or ""),
        "plugin": str(getattr(dashboard, "single_action_run_plugin", "") or ""),
        "action": str(getattr(dashboard, "single_action_run_action", "") or ""),
        "node_uid": str(getattr(dashboard, "single_action_node_uid", "") or ""),
        "status": str(status_text or "").strip().lower(),
        "parameters": dict(getattr(dashboard, "single_action_run_parameters", {}) or {}),
        "duration_seconds": max(0.0, time.time() - started_at) if started_at else 0.0,
    }

    await dashboard.backend.tacticalTargetPatch(
        target_id=target_id,
        patch={},
        history_entry=history_entry,
        artifact_id="",
    )


async def _finish_single_action(
    dashboard: QtCore.QObject,
    status_text: str,
    node_status: str = "",
):
    """Restore the Single Action UI after Stop, natural completion, or error."""
    result_text = _single_action_result_text(dashboard, status_text, node_status)

    node_uid = str(getattr(dashboard, "single_action_node_uid", "") or "").strip()
    if node_uid and getattr(dashboard, "single_action_detector_operation_ids", set()):
        await _stop_single_action_detectors(dashboard, node_uid)

    try:
        await _record_single_action_target_history(dashboard, status_text)
    except Exception as error:
        dashboard.logger.error(f"Could not record Single Action Target history: {error}")

    _single_action_clear_run_state(dashboard)
    _single_action_set_execution_locked(dashboard, False)
    update_single_action_selected_node_gate(dashboard)

    dashboard.ui.label_ta_single_action_execution_status.setText(status_text)
    dashboard.ui.label_ta_single_action_execution_operation_id.setText("—")
    dashboard.ui.textEdit_ta_single_action_execution_result.setPlainText(result_text)


@qasync.asyncSlot(QtCore.QObject)


async def _slotSingleActionStartStopClicked(dashboard: QtCore.QObject):
    """Start the selected action immediately or after optional detector gating."""
    if _single_action_active(dashboard):
        node_uid = str(getattr(dashboard, "single_action_node_uid", "") or "").strip()
        if not node_uid:
            return

        dashboard.single_action_stop_requested = True
        dashboard.ui.label_ta_single_action_execution_status.setText("Stopping...")
        dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(False)

        if bool(getattr(dashboard, "single_action_waiting_for_detection", False)):
            await _stop_single_action_detectors(dashboard, node_uid)
            return

        operation_id = str(getattr(dashboard, "single_action_operation_id", "") or "").strip()
        if not operation_id:
            return

        try:
            await dashboard.backend.stopPluginOperation(node_uid, operation_id)
        except Exception as error:
            dashboard.logger.error(f"Could not stop Single Action operation {operation_id}: {error}")
            dashboard.single_action_stop_requested = False
            dashboard.ui.label_ta_single_action_execution_status.setText("Running")
            dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(True)
        return

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    plugin_name = str(getattr(dashboard, "single_action_selected_plugin", "") or "").strip()
    action_name = str(getattr(dashboard, "single_action_selected_action", "") or "").strip()

    if not node_uid or not _single_action_selected_node_available(dashboard):
        return
    if not plugin_name or not action_name or not bool(getattr(dashboard, "single_action_customized", False)):
        return

    parameters = collect_single_action_parameters(dashboard)
    operation_id = str(uuid.uuid4())
    parameters["operation_id"] = operation_id
    detector_configs = _collect_single_action_detector_configs(dashboard)

    dashboard.single_action_start_pending = True
    dashboard.single_action_running = False
    dashboard.single_action_node_uid = node_uid
    dashboard.single_action_operation_id = operation_id
    dashboard.single_action_target_id = str(
        getattr(dashboard, "selected_targets_actions_target_id", "") or ""
    ).strip()
    dashboard.single_action_run_plugin = plugin_name
    dashboard.single_action_run_action = action_name
    dashboard.single_action_run_parameters = dict(parameters)
    dashboard.single_action_started_at = time.time()
    dashboard.single_action_seen_running_status = False
    dashboard.single_action_stop_requested = False
    dashboard.single_action_waiting_for_detection = False
    dashboard.single_action_monitor_action_status = False
    dashboard.single_action_detector_operation_ids = set()
    dashboard.single_action_detection_event = None
    dashboard.single_action_detection = None

    _single_action_set_execution_locked(dashboard, True)
    _set_single_action_start_stop_button(dashboard, True)
    dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(True)
    dashboard.ui.label_ta_single_action_execution_status.setText(
        "Starting Detectors..." if detector_configs else "Starting..."
    )
    dashboard.ui.label_ta_single_action_execution_operation_id.setText(operation_id)
    dashboard.ui.textEdit_ta_single_action_execution_result.setPlainText(
        f"{'Waiting to start' if detector_configs else 'Starting'} {plugin_name}: {action_name}\n"
        f"Sensor Node: {node_uid}\n"
        f"Operation ID: {operation_id}\n"
        f"Target: {dashboard.single_action_target_id or 'No Target'}"
    )

    dashboard.single_action_task = asyncio.create_task(
        _run_single_action(
            dashboard,
            node_uid,
            plugin_name,
            action_name,
            parameters,
            detector_configs,
        )
    )


async def update_single_action_status_from_selected_node(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    status: str = "",
):
    """
    Track generic Single Action lifecycle from the same Sensor Node status path
    already used by IQ Playback and IQ Inspection.
    """
    if not _single_action_active(dashboard):
        return

    tracked_node_uid = str(getattr(dashboard, "single_action_node_uid", "") or "").strip()
    if not _single_action_node_uids_match(tracked_node_uid, node_uid):
        return

    if (
        bool(getattr(dashboard, "single_action_waiting_for_detection", False))
        or not bool(getattr(dashboard, "single_action_monitor_action_status", False))
    ):
        return

    status_text = str(status or "").strip()
    if not status_text:
        return

    if status_text.startswith("Running"):
        dashboard.single_action_seen_running_status = True
        dashboard.single_action_start_pending = False
        dashboard.single_action_running = True

        if not bool(getattr(dashboard, "single_action_stop_requested", False)):
            dashboard.ui.label_ta_single_action_execution_status.setText(status_text)
            dashboard.ui.pushButton_ta_single_action_start_stop.setEnabled(True)
        return

    if status_text == "Error":
        await _finish_single_action(dashboard, "Error", node_status=status_text)
        return

    if (
        status_text == "Idle"
        and bool(getattr(dashboard, "single_action_seen_running_status", False))
    ):
        final_status = (
            "Stopped"
            if bool(getattr(dashboard, "single_action_stop_requested", False))
            else "Completed"
        )
        await _finish_single_action(dashboard, final_status, node_status=status_text)