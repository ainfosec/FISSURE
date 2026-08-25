from PyQt5 import QtCore, QtGui, QtWidgets
import os
import re
import time
import uuid

import qasync

import fissure.utils
from ..UI_Components import Qt5


ACTION_QUERY_CONTEXT = "targets_actions.fuzzing.actions"
ACTION_SCHEMA_CONTEXT = "targets_actions.fuzzing.schema"
FUZZING_REQUIRED_TAGS = ["fuzzing.data", "ui.fuzzing"]


def initialize_fuzzing_tab(dashboard: QtCore.QObject):
    """Initialize the Targets & Actions Fuzzing workflow."""
    dashboard.fuzzing_action_catalog = []
    dashboard.fuzzing_filtered_actions = []
    dashboard.fuzzing_action_catalog_node_uid = ""
    dashboard.fuzzing_hardware_signature = None
    dashboard.fuzzing_selected_plugin = ""
    dashboard.fuzzing_selected_action = ""
    dashboard.fuzzing_parameter_widgets = {}
    dashboard.fuzzing_current_schema = {}
    dashboard.fuzzing_customized = False
    dashboard.fuzzing_query_pending = False

    dashboard.fuzzing_start_pending = False
    dashboard.fuzzing_running = False
    dashboard.fuzzing_node_uid = ""
    dashboard.fuzzing_operation_id = ""
    dashboard.fuzzing_started_at = 0.0
    dashboard.fuzzing_seen_running_status = False
    dashboard.fuzzing_stop_requested = False
    dashboard.fuzzing_monitor_action_status = False

    dashboard.ui.stackedWidget_ta_fuzzing.setCurrentWidget(dashboard.ui.page_ta_fuzzing_no_node)

    select_node_icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", "select_node.png")
    if os.path.isfile(select_node_icon_path):
        pixmap = QtGui.QPixmap(select_node_icon_path)
        dashboard.ui.label_ta_fuzzing_select_sensor_node_image.setPixmap(pixmap)
        dashboard.ui.label_ta_fuzzing_select_sensor_node_image.setScaledContents(False)
        dashboard.ui.label_ta_fuzzing_select_sensor_node_image.setAlignment(QtCore.Qt.AlignCenter)

    dashboard.ui.pushButton_ta_fuzzing_query.setText("Query Actions")
    dashboard.ui.pushButton_ta_fuzzing_customize.setText("Customize")
    dashboard.ui.pushButton_ta_fuzzing_customize.setEnabled(False)
    _set_fuzzing_start_stop_button(dashboard, False)
    dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(False)
    dashboard.ui.label_ta_fuzzing_execution_status.setText("Idle")
    dashboard.ui.label_ta_fuzzing_execution_operation_id.setText("—")
    dashboard.ui.textEdit_ta_fuzzing_seed.setPlainText("0")
    dashboard.ui.textEdit_ta_fuzzing_interval.setPlainText("5")

    scroll_area = dashboard.ui.scrollArea_ta_fuzzing_parameters
    scroll_area.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    scroll_area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)

    table = dashboard.ui.tableWidget_ta_fuzzing_fields
    table.clearContents()
    table.setRowCount(0)
    table.setEnabled(False)
    table.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    table.setWordWrap(False)
    header = table.horizontalHeader()
    header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(5, QtWidgets.QHeaderView.Stretch)
    header.setSectionResizeMode(6, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(7, QtWidgets.QHeaderView.ResizeToContents)

    _clear_fuzzing_parameter_widgets(dashboard)
    _populate_fuzzing_protocols(dashboard)
    update_fuzzing_selected_node_gate(dashboard)


def _fuzzing_selected_node_available(dashboard: QtCore.QObject):
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        return False

    node_state = (getattr(dashboard, "node_states", {}) or {}).get(node_uid)
    if isinstance(node_state, dict) and node_state.get("connected") is False:
        return False

    return True


def update_fuzzing_selected_node_gate(dashboard: QtCore.QObject):
    """Show Fuzzing controls only while a Sensor Node is selected or fuzzing is active."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    has_selected_node = _fuzzing_selected_node_available(dashboard)
    previous_node_uid = str(getattr(dashboard, "fuzzing_action_catalog_node_uid", "") or "").strip()
    node_changed = node_uid != previous_node_uid
    active = _fuzzing_active(dashboard)

    dashboard.ui.stackedWidget_ta_fuzzing.setCurrentWidget(
        dashboard.ui.page_ta_fuzzing_controls if has_selected_node or active else dashboard.ui.page_ta_fuzzing_no_node
    )

    if node_changed and not active:
        dashboard.fuzzing_action_catalog_node_uid = node_uid
        dashboard.fuzzing_action_catalog = []
        dashboard.fuzzing_filtered_actions = []
        dashboard.fuzzing_hardware_signature = None
        dashboard.fuzzing_query_pending = False
        dashboard.ui.pushButton_ta_fuzzing_query.setText("Query Actions")
        _reset_fuzzing_action_selection(dashboard)

    if not active:
        _refresh_fuzzing_hardware_filter(dashboard)

    if active:
        _fuzzing_set_execution_locked(dashboard, True)
        _set_fuzzing_start_stop_button(dashboard, True)
        dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(not dashboard.fuzzing_stop_requested)
        return

    dashboard.ui.comboBox_ta_fuzzing_protocol.setEnabled(has_selected_node)
    dashboard.ui.comboBox_ta_fuzzing_packet_type.setEnabled(has_selected_node and dashboard.ui.comboBox_ta_fuzzing_packet_type.count() > 0)
    dashboard.ui.comboBox_ta_fuzzing_hardware.setEnabled(has_selected_node)
    dashboard.ui.comboBox_ta_fuzzing_plugin.setEnabled(has_selected_node and bool(dashboard.fuzzing_filtered_actions))
    dashboard.ui.comboBox_ta_fuzzing_action.setEnabled(has_selected_node and bool(dashboard.fuzzing_filtered_actions))
    dashboard.ui.pushButton_ta_fuzzing_query.setEnabled(has_selected_node and not dashboard.fuzzing_query_pending)

    has_action = bool(dashboard.fuzzing_selected_plugin and dashboard.fuzzing_selected_action)
    dashboard.ui.pushButton_ta_fuzzing_customize.setEnabled(has_selected_node and has_action)
    dashboard.ui.tableWidget_ta_fuzzing_fields.setEnabled(has_selected_node and dashboard.ui.tableWidget_ta_fuzzing_fields.rowCount() > 0)
    dashboard.ui.pushButton_ta_fuzzing_restore_defaults.setEnabled(has_selected_node and dashboard.ui.tableWidget_ta_fuzzing_fields.rowCount() > 0)
    dashboard.ui.pushButton_ta_fuzzing_all_binary.setEnabled(has_selected_node and dashboard.ui.tableWidget_ta_fuzzing_fields.rowCount() > 0)
    dashboard.ui.pushButton_ta_fuzzing_all_hex.setEnabled(has_selected_node and dashboard.ui.tableWidget_ta_fuzzing_fields.rowCount() > 0)
    _set_fuzzing_start_stop_button(dashboard, False)
    dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(has_selected_node and has_action and dashboard.fuzzing_customized)

    if not has_selected_node:
        dashboard.ui.label_ta_fuzzing_execution_status.setText("Unavailable")
    elif not dashboard.fuzzing_action_catalog:
        dashboard.ui.label_ta_fuzzing_execution_status.setText("Idle")


def _populate_fuzzing_protocols(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_ta_fuzzing_protocol
    current = str(combo.currentText() or "").strip()
    protocols = []

    for protocol in fissure.utils.library.getProtocols(dashboard.backend.library):
        if fissure.utils.library.getPacketTypes(dashboard.backend.library, protocol):
            protocols.append(str(protocol))

    combo.blockSignals(True)
    combo.clear()
    combo.addItems(sorted(protocols, key=str.lower))
    restore_index = combo.findText(current, QtCore.Qt.MatchExactly)
    if restore_index < 0:
        restore_index = combo.findText("X10", QtCore.Qt.MatchExactly)
    combo.setCurrentIndex(restore_index if restore_index >= 0 else (0 if combo.count() else -1))
    combo.blockSignals(False)
    _populate_fuzzing_packet_types(dashboard)


def _populate_fuzzing_packet_types(dashboard: QtCore.QObject):
    protocol = str(dashboard.ui.comboBox_ta_fuzzing_protocol.currentText() or "").strip()
    combo = dashboard.ui.comboBox_ta_fuzzing_packet_type
    current = str(combo.currentText() or "").strip()
    packet_types = fissure.utils.library.getPacketTypes(dashboard.backend.library, protocol) if protocol else []

    combo.blockSignals(True)
    combo.clear()
    combo.addItems([str(packet_type) for packet_type in packet_types])
    restore_index = combo.findText(current, QtCore.Qt.MatchExactly)
    combo.setCurrentIndex(restore_index if restore_index >= 0 else (0 if combo.count() else -1))
    combo.blockSignals(False)
    _populate_fuzzing_fields(dashboard)


def _populate_fuzzing_fields(dashboard: QtCore.QObject):
    protocol = str(dashboard.ui.comboBox_ta_fuzzing_protocol.currentText() or "").strip()
    packet_type = str(dashboard.ui.comboBox_ta_fuzzing_packet_type.currentText() or "").strip()
    table = dashboard.ui.tableWidget_ta_fuzzing_fields

    table.blockSignals(True)
    table.clearContents()
    table.setRowCount(0)

    if protocol and packet_type:
        field_names = fissure.utils.library.getFields(dashboard.backend.library, protocol, packet_type)
        table.setRowCount(len(field_names))
        table.setVerticalHeaderLabels([str(field_name) for field_name in field_names])

    table.blockSignals(False)
    _restore_fuzzing_defaults(dashboard)
    table.resizeRowsToContents()
    update_fuzzing_selected_node_gate(dashboard)


def _restore_fuzzing_defaults(dashboard: QtCore.QObject):
    protocol = str(dashboard.ui.comboBox_ta_fuzzing_protocol.currentText() or "").strip()
    packet_type = str(dashboard.ui.comboBox_ta_fuzzing_packet_type.currentText() or "").strip()
    table = dashboard.ui.tableWidget_ta_fuzzing_fields

    if not protocol or not packet_type or table.rowCount() == 0:
        return

    field_names = fissure.utils.library.getFields(dashboard.backend.library, protocol, packet_type)
    table.blockSignals(True)

    for row, field_name in enumerate(field_names):
        field_data = fissure.utils.library.getFieldData(dashboard.backend.library, protocol, packet_type, field_name)
        field_length = int(field_data.get("Length", 0) or 0)
        default_value = str(field_data.get("Default Value", "") or "")

        select = QtWidgets.QCheckBox("", table)
        select.setStyleSheet("margin-left:17%")
        table.setCellWidget(row, 0, select)

        fuzz_type = QtWidgets.QComboBox(table)
        fuzz_type.addItems(["Random", "Sequential"])
        table.setCellWidget(row, 1, fuzz_type)

        min_item = QtWidgets.QTableWidgetItem("0")
        min_item.setTextAlignment(QtCore.Qt.AlignCenter)
        table.setItem(row, 2, min_item)

        max_item = QtWidgets.QTableWidgetItem(str((2 ** field_length) - 1 if field_length > 0 else 0))
        max_item.setTextAlignment(QtCore.Qt.AlignCenter)
        table.setItem(row, 3, max_item)

        representation = QtWidgets.QComboBox(table)
        representation.addItems(["Binary", "Hex"])
        representation.setProperty("row", row)
        representation.currentIndexChanged.connect(lambda _index, r=row: _convert_fuzzing_representation(dashboard, r))
        table.setCellWidget(row, 4, representation)

        data_item = QtWidgets.QTableWidgetItem(default_value)
        table.setItem(row, 5, data_item)

        length_item = QtWidgets.QTableWidgetItem(str(field_length))
        length_item.setTextAlignment(QtCore.Qt.AlignCenter)
        length_item.setFlags(length_item.flags() & ~QtCore.Qt.ItemIsEditable)
        table.setItem(row, 6, length_item)

        default_length_item = QtWidgets.QTableWidgetItem(str(field_length))
        default_length_item.setTextAlignment(QtCore.Qt.AlignCenter)
        default_length_item.setFlags(default_length_item.flags() & ~QtCore.Qt.ItemIsEditable)
        table.setItem(row, 7, default_length_item)

        if field_length % 4:
            representation.setEnabled(False)
        else:
            representation.setCurrentIndex(1)

    table.blockSignals(False)
    table.resizeRowsToContents()


def _convert_fuzzing_representation(dashboard: QtCore.QObject, row: int):
    table = dashboard.ui.tableWidget_ta_fuzzing_fields
    representation = table.cellWidget(row, 4)
    data_item = table.item(row, 5)
    if representation is None or data_item is None:
        return

    data = str(data_item.text() or "").strip()
    if not data:
        return

    try:
        table.blockSignals(True)
        if representation.currentText() == "Binary":
            hex_data = data.replace(" ", "")
            binary = bin(int(hex_data, 16))[2:].zfill(len(hex_data) * 4)
            data_item.setText(" ".join(binary[index:index + 4] for index in range(0, len(binary), 4)))
        else:
            binary = data.replace(" ", "")
            data_item.setText("%0*X" % ((len(binary) + 3) // 4, int(binary, 2)))
    except ValueError:
        Qt5.errorMessage("Message data was entered incorrectly.")
    finally:
        table.blockSignals(False)

    _update_fuzzing_field_length(dashboard, row)


def _update_fuzzing_field_length(dashboard: QtCore.QObject, row: int):
    table = dashboard.ui.tableWidget_ta_fuzzing_fields
    representation = table.cellWidget(row, 4)
    data_item = table.item(row, 5)
    if representation is None or data_item is None:
        return

    data = str(data_item.text() or "")
    length = len(data.replace(" ", "")) if representation.currentText() == "Binary" else 4 * len(data.strip())
    item = QtWidgets.QTableWidgetItem(str(length))
    item.setTextAlignment(QtCore.Qt.AlignCenter)
    item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
    table.blockSignals(True)
    table.setItem(row, 6, item)
    table.blockSignals(False)


def _protocol_tag(protocol: str):
    slug = re.sub(r"[^a-z0-9]+", "_", str(protocol or "").strip().lower()).strip("_")
    return f"protocol.{slug}" if slug else ""


def _refresh_fuzzing_hardware_filter(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_ta_fuzzing_hardware
    display_names = []
    if _fuzzing_selected_node_available(dashboard):
        display_names = fissure.utils.hardware.selectedNodeHardwareDisplayNames(dashboard, "attack")

    hardware_records = []
    for display_name in display_names:
        hardware_type, *_ = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, display_name, "attack")
        hardware_records.append((str(display_name or "").strip(), str(hardware_type or "").strip()))

    signature = tuple(hardware_records)
    if getattr(dashboard, "fuzzing_hardware_signature", None) == signature and combo.count() > 0:
        _filter_fuzzing_action_catalog(dashboard)
        return

    dashboard.fuzzing_hardware_signature = signature
    current_text = str(combo.currentText() or "").strip()
    combo.blockSignals(True)
    combo.clear()
    for display_name, hardware_type in hardware_records:
        combo.addItem(display_name, {"hardware_type": hardware_type, "display_name": display_name})
    restore_index = combo.findText(current_text, QtCore.Qt.MatchExactly)
    combo.setCurrentIndex(restore_index if restore_index >= 0 else (0 if combo.count() else -1))
    combo.blockSignals(False)
    _filter_fuzzing_action_catalog(dashboard)


def _fuzzing_hardware_matches(candidate: str, selected: str):
    candidate_text = str(candidate or "").strip().lower()
    selected_text = str(selected or "").strip().lower()
    return bool(candidate_text and selected_text and (candidate_text in selected_text or selected_text in candidate_text))


def _filter_fuzzing_action_catalog(dashboard: QtCore.QObject):
    record = dashboard.ui.comboBox_ta_fuzzing_hardware.currentData()
    selected_type = str(record.get("hardware_type", "") or "").strip() if isinstance(record, dict) else ""
    filtered = []

    for action_record in getattr(dashboard, "fuzzing_action_catalog", []) or []:
        if not isinstance(action_record, dict):
            continue
        hardware = [str(value or "").strip() for value in (action_record.get("hardware", []) or []) if str(value or "").strip()]
        if hardware and (not selected_type or not any(_fuzzing_hardware_matches(value, selected_type) for value in hardware)):
            continue
        filtered.append(action_record)

    dashboard.fuzzing_filtered_actions = filtered
    plugin_combo = dashboard.ui.comboBox_ta_fuzzing_plugin
    current_plugin = str(plugin_combo.currentText() or "").strip()
    plugins = sorted({str(item.get("plugin", "") or "").strip() for item in filtered if str(item.get("plugin", "") or "").strip()}, key=str.lower)

    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.addItem("All Plugins", None)
    for plugin_name in plugins:
        plugin_combo.addItem(plugin_name, plugin_name)
    restore_index = plugin_combo.findText(current_plugin, QtCore.Qt.MatchExactly)
    plugin_combo.setCurrentIndex(restore_index if restore_index >= 0 else 0)
    plugin_combo.blockSignals(False)
    plugin_combo.setEnabled(_fuzzing_selected_node_available(dashboard) and bool(filtered))
    _populate_fuzzing_actions(dashboard)


def _populate_fuzzing_actions(dashboard: QtCore.QObject):
    plugin_name = str(dashboard.ui.comboBox_ta_fuzzing_plugin.currentData() or "").strip()
    previous_plugin = str(getattr(dashboard, "fuzzing_selected_plugin", "") or "").strip()
    previous_action = str(getattr(dashboard, "fuzzing_selected_action", "") or "").strip()
    records = []

    for action_record in getattr(dashboard, "fuzzing_filtered_actions", []) or []:
        record_plugin = str(action_record.get("plugin", "") or "").strip()
        action_name = str(action_record.get("action", "") or "").strip()
        if not record_plugin or not action_name or (plugin_name and record_plugin != plugin_name):
            continue
        records.append(action_record)

    records.sort(key=lambda item: (str(item.get("plugin", "")).lower(), str(item.get("action", "")).lower()))
    combo = dashboard.ui.comboBox_ta_fuzzing_action
    combo.blockSignals(True)
    combo.clear()
    restore_index = -1
    for action_record in records:
        record_plugin = str(action_record.get("plugin", "") or "").strip()
        action_name = str(action_record.get("action", "") or "").strip()
        combo.addItem(action_name if plugin_name else f"{record_plugin}: {action_name}", action_record)
        if record_plugin == previous_plugin and action_name == previous_action:
            restore_index = combo.count() - 1
    combo.setCurrentIndex(restore_index if restore_index >= 0 else (0 if combo.count() else -1))
    combo.blockSignals(False)
    combo.setEnabled(_fuzzing_selected_node_available(dashboard) and bool(records))
    _slotFuzzingActionChanged(dashboard)


def _reset_fuzzing_action_selection(dashboard: QtCore.QObject):
    dashboard.fuzzing_selected_plugin = ""
    dashboard.fuzzing_selected_action = ""
    dashboard.fuzzing_current_schema = {}
    dashboard.fuzzing_customized = False
    dashboard.ui.comboBox_ta_fuzzing_plugin.clear()
    dashboard.ui.comboBox_ta_fuzzing_action.clear()
    dashboard.ui.pushButton_ta_fuzzing_customize.setEnabled(False)
    dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(False)
    _clear_fuzzing_parameter_widgets(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotFuzzingProtocolChanged(dashboard: QtCore.QObject):
    if _fuzzing_active(dashboard):
        return
    _populate_fuzzing_packet_types(dashboard)
    dashboard.fuzzing_action_catalog = []
    dashboard.fuzzing_filtered_actions = []
    _reset_fuzzing_action_selection(dashboard)
    _refresh_fuzzing_hardware_filter(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotFuzzingPacketTypeChanged(dashboard: QtCore.QObject):
    if not _fuzzing_active(dashboard):
        _populate_fuzzing_fields(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotFuzzingHardwareChanged(dashboard: QtCore.QObject):
    _filter_fuzzing_action_catalog(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotFuzzingPluginChanged(dashboard: QtCore.QObject):
    _populate_fuzzing_actions(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotFuzzingActionChanged(dashboard: QtCore.QObject):
    if _fuzzing_active(dashboard):
        return

    action_record = dashboard.ui.comboBox_ta_fuzzing_action.currentData()
    if not isinstance(action_record, dict):
        dashboard.fuzzing_selected_plugin = ""
        dashboard.fuzzing_selected_action = ""
        dashboard.fuzzing_current_schema = {}
        dashboard.fuzzing_customized = False
        dashboard.ui.pushButton_ta_fuzzing_customize.setEnabled(False)
        dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(False)
        _clear_fuzzing_parameter_widgets(dashboard)
        return

    plugin_name = str(action_record.get("plugin", "") or "").strip()
    action_name = str(action_record.get("action", "") or "").strip()
    same_selection = plugin_name == dashboard.fuzzing_selected_plugin and action_name == dashboard.fuzzing_selected_action
    dashboard.ui.pushButton_ta_fuzzing_customize.setText("Customize")
    dashboard.ui.pushButton_ta_fuzzing_customize.setEnabled(bool(plugin_name and action_name) and _fuzzing_selected_node_available(dashboard))
    if same_selection:
        return

    dashboard.fuzzing_selected_plugin = plugin_name
    dashboard.fuzzing_selected_action = action_name
    dashboard.fuzzing_current_schema = {}
    dashboard.fuzzing_customized = False
    dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(False)
    _clear_fuzzing_parameter_widgets(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotFuzzingQueryClicked(dashboard: QtCore.QObject):
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    protocol = str(dashboard.ui.comboBox_ta_fuzzing_protocol.currentText() or "").strip()
    protocol_tag = _protocol_tag(protocol)
    if not node_uid or not protocol_tag or not _fuzzing_selected_node_available(dashboard):
        return

    dashboard.fuzzing_query_pending = True
    dashboard.ui.pushButton_ta_fuzzing_query.setEnabled(False)
    dashboard.ui.pushButton_ta_fuzzing_query.setText("Querying...")
    await dashboard.backend.queryPluginActions(
        node_uid,
        context=ACTION_QUERY_CONTEXT,
        scope="all_plugins",
        include_tags=FUZZING_REQUIRED_TAGS + [protocol_tag],
    )


def handle_fuzzing_action_query_results(dashboard: QtCore.QObject, node_uid: str = "", context: str = "", actions: list = None):
    if context != ACTION_QUERY_CONTEXT:
        return
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return

    dashboard.fuzzing_query_pending = False
    dashboard.fuzzing_action_catalog_node_uid = str(node_uid or "").strip()
    dashboard.fuzzing_action_catalog = actions if isinstance(actions, list) else []
    dashboard.ui.pushButton_ta_fuzzing_query.setText("Query Actions")
    dashboard.ui.pushButton_ta_fuzzing_query.setEnabled(_fuzzing_selected_node_available(dashboard))
    _filter_fuzzing_action_catalog(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotFuzzingCustomizeClicked(dashboard: QtCore.QObject):
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    plugin_name = str(getattr(dashboard, "fuzzing_selected_plugin", "") or "").strip()
    action_name = str(getattr(dashboard, "fuzzing_selected_action", "") or "").strip()
    if not node_uid or not plugin_name or not action_name or not _fuzzing_selected_node_available(dashboard):
        return

    dashboard.ui.pushButton_ta_fuzzing_customize.setEnabled(False)
    dashboard.ui.pushButton_ta_fuzzing_customize.setText("Loading...")
    await dashboard.backend.queryPluginActionSchema(node_uid, plugin_name, action_name, context=ACTION_SCHEMA_CONTEXT)


def _clear_fuzzing_parameter_widgets(dashboard: QtCore.QObject):
    contents = dashboard.ui.scrollAreaWidgetContents_ta_fuzzing_parameters
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
    dashboard.fuzzing_parameter_widgets = {}


def _create_fuzzing_parameter_widget(parent, parameter: dict):
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

    widget.setObjectName(f"fuzzing_parameter_{parameter_name}")
    widget.setProperty("uiRole", "singleActionParameterInfo" if parameter_type == "label" else "singleActionParameterEditor")
    description = str(parameter.get("description", "") or "").strip()
    if description:
        widget.setToolTip(description)
    return widget


def handle_fuzzing_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
):
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return
    if plugin_name != getattr(dashboard, "fuzzing_selected_plugin", "") or action_name != getattr(dashboard, "fuzzing_selected_action", ""):
        return

    parameter_list = parameters if isinstance(parameters, list) else []
    dashboard.fuzzing_current_schema = {"params": [dict(parameter) for parameter in parameter_list if isinstance(parameter, dict)]}
    _clear_fuzzing_parameter_widgets(dashboard)
    contents = dashboard.ui.scrollAreaWidgetContents_ta_fuzzing_parameters
    layout = contents.layout()
    row = 0

    for parameter in parameter_list:
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name", "") or "").strip()
        if not name:
            continue
        label = QtWidgets.QLabel(f"{str(parameter.get('label') or name).strip()}:", contents)
        label.setObjectName(f"label2_fuzzing_parameter_{name}")
        label.setProperty("uiRole", "singleActionParameterLabel")
        label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        description = str(parameter.get("description", "") or "").strip()
        if description:
            label.setToolTip(description)
        widget = _create_fuzzing_parameter_widget(contents, parameter)
        layout.addWidget(label, row, 0)
        layout.addWidget(widget, row, 1)
        dashboard.fuzzing_parameter_widgets[name] = {"widget": widget, "schema": dict(parameter)}
        row += 1

    if row == 0:
        empty_label = QtWidgets.QLabel("No parameters required for this action.", contents)
        empty_label.setProperty("uiRole", "singleActionParameterInfo")
        layout.addWidget(empty_label, 0, 0, 1, 2)

    dashboard.fuzzing_customized = True
    dashboard.ui.pushButton_ta_fuzzing_customize.setText("Customize")
    dashboard.ui.pushButton_ta_fuzzing_customize.setEnabled(_fuzzing_selected_node_available(dashboard))
    dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(_fuzzing_selected_node_available(dashboard) and not _fuzzing_active(dashboard))


def _fuzzing_parameter_value(widget):
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


def collect_fuzzing_action_parameters(dashboard: QtCore.QObject):
    parameters = {}
    for name, record in (getattr(dashboard, "fuzzing_parameter_widgets", {}) or {}).items():
        widget = record.get("widget") if isinstance(record, dict) else None
        schema = record.get("schema", {}) if isinstance(record, dict) else {}
        if widget is None or str(schema.get("type", "") or "").strip().lower() == "label":
            continue
        parameters[name] = _fuzzing_parameter_value(widget)
    return parameters


def _fuzzing_hardware_parameters(dashboard: QtCore.QObject):
    record = dashboard.ui.comboBox_ta_fuzzing_hardware.currentData()
    display_name = str(record.get("display_name", "") or "").strip() if isinstance(record, dict) else ""
    if not display_name:
        return {}

    hardware_type, hardware_uuid, hardware_radio_name, hardware_serial, hardware_interface, hardware_ip, hardware_daughterboard = (
        fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, display_name, "attack")
    )
    hardware_serial_argument = f"serial={hardware_serial}" if hardware_serial else "False"
    return {
        "hardware_display_name": display_name,
        "hardware_type": hardware_type,
        "hardware_uuid": hardware_uuid,
        "hardware_radio_name": hardware_radio_name,
        "hardware_serial": hardware_serial,
        "hardware_serial_argument": hardware_serial_argument,
        "hardware_interface": hardware_interface,
        "hardware_ip": hardware_ip,
        "hardware_daughterboard": hardware_daughterboard,
    }


def collect_fuzzing_plan(dashboard: QtCore.QObject):
    protocol = str(dashboard.ui.comboBox_ta_fuzzing_protocol.currentText() or "").strip()
    packet_type = str(dashboard.ui.comboBox_ta_fuzzing_packet_type.currentText() or "").strip()
    table = dashboard.ui.tableWidget_ta_fuzzing_fields
    fuzzing_fields = []
    fuzzing_type = []
    fuzzing_min = []
    fuzzing_max = []
    packet_binary = ""

    for row in range(table.rowCount()):
        field_name = str(table.verticalHeaderItem(row).text() if table.verticalHeaderItem(row) else "").strip()
        representation = table.cellWidget(row, 4)
        data_item = table.item(row, 5)
        data = str(data_item.text() if data_item else "").strip()
        if not data or representation is None:
            raise ValueError(f"Field '{field_name}' is missing base data.")

        if representation.currentText() == "Binary":
            field_binary = data.replace(" ", "")
            int(field_binary, 2)
        else:
            hex_data = data.replace(" ", "")
            int(hex_data, 16)
            field_binary = bin(int(hex_data, 16))[2:].zfill(len(hex_data) * 4)
        packet_binary += field_binary

        select = table.cellWidget(row, 0)
        if select is None or not select.isChecked():
            continue

        min_item = table.item(row, 2)
        max_item = table.item(row, 3)
        min_text = str(min_item.text() if min_item else "").strip()
        max_text = str(max_item.text() if max_item else "").strip()
        if not min_text or not max_text:
            raise ValueError(f"Field '{field_name}' requires minimum and maximum values.")
        min_value = int(min_text)
        max_value = int(max_text)
        if min_value > max_value:
            raise ValueError(f"Field '{field_name}' has a minimum greater than its maximum.")

        fuzzing_fields.append(field_name)
        fuzzing_type.append(str(table.cellWidget(row, 1).currentText()))
        fuzzing_min.append(str(min_value))
        fuzzing_max.append(str(max_value))

    fuzzing_seed = str(dashboard.ui.textEdit_ta_fuzzing_seed.toPlainText() or "0").strip()
    fuzzing_interval = str(dashboard.ui.textEdit_ta_fuzzing_interval.toPlainText() or "5").strip()
    int(fuzzing_seed)
    if float(fuzzing_interval) <= 0:
        raise ValueError("Fuzzing interval must be greater than zero.")

    fuzzing_data = "%0*X" % ((len(packet_binary) + 3) // 4, int(packet_binary or "0", 2))
    packet_types_fields = fissure.utils.library.getFieldDataAll(dashboard.backend.library, protocol, packet_type)
    return {
        "fuzzing_protocol": protocol,
        "fuzzing_packet_type": packet_type,
        "fuzzing_fields": str(fuzzing_fields),
        "fuzzing_type": str(fuzzing_type),
        "fuzzing_min": str(fuzzing_min),
        "fuzzing_max": str(fuzzing_max),
        "fuzzing_data": fuzzing_data,
        "fuzzing_seed": fuzzing_seed,
        "fuzzing_interval": fuzzing_interval,
        "packet_types_fields": str(packet_types_fields),
    }


def _fuzzing_active(dashboard: QtCore.QObject):
    return bool(getattr(dashboard, "fuzzing_start_pending", False) or getattr(dashboard, "fuzzing_running", False))


def _fuzzing_node_uids_match(first: str, second: str):
    first = str(first or "").strip()
    second = str(second or "").strip()
    return bool(first and second and (first == second or first.endswith(second) or second.endswith(first)))


def _set_fuzzing_start_stop_button(dashboard: QtCore.QObject, running: bool):
    button = dashboard.ui.pushButton_ta_fuzzing_start_stop
    button.setText("Stop" if running else "Start")
    button.setProperty("running", bool(running))
    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


def _fuzzing_set_execution_locked(dashboard: QtCore.QObject, locked: bool):
    has_node = _fuzzing_selected_node_available(dashboard)
    has_actions = bool(getattr(dashboard, "fuzzing_filtered_actions", []))
    has_action = bool(dashboard.fuzzing_selected_plugin and dashboard.fuzzing_selected_action)
    dashboard.ui.comboBox_ta_fuzzing_protocol.setEnabled(has_node and not locked)
    dashboard.ui.comboBox_ta_fuzzing_packet_type.setEnabled(has_node and not locked)
    dashboard.ui.comboBox_ta_fuzzing_hardware.setEnabled(has_node and not locked)
    dashboard.ui.comboBox_ta_fuzzing_plugin.setEnabled(has_node and has_actions and not locked)
    dashboard.ui.comboBox_ta_fuzzing_action.setEnabled(has_node and has_actions and not locked)
    dashboard.ui.pushButton_ta_fuzzing_query.setEnabled(has_node and not dashboard.fuzzing_query_pending and not locked)
    dashboard.ui.pushButton_ta_fuzzing_customize.setEnabled(has_node and has_action and not locked)
    dashboard.ui.tableWidget_ta_fuzzing_fields.setEnabled(has_node and not locked)
    dashboard.ui.pushButton_ta_fuzzing_restore_defaults.setEnabled(has_node and not locked)
    dashboard.ui.pushButton_ta_fuzzing_all_binary.setEnabled(has_node and not locked)
    dashboard.ui.pushButton_ta_fuzzing_all_hex.setEnabled(has_node and not locked)
    dashboard.ui.textEdit_ta_fuzzing_seed.setEnabled(has_node and not locked)
    dashboard.ui.textEdit_ta_fuzzing_interval.setEnabled(has_node and not locked)
    for record in (getattr(dashboard, "fuzzing_parameter_widgets", {}) or {}).values():
        widget = record.get("widget") if isinstance(record, dict) else None
        if widget is not None:
            widget.setEnabled(not locked)


def _clear_fuzzing_run_state(dashboard: QtCore.QObject):
    dashboard.fuzzing_start_pending = False
    dashboard.fuzzing_running = False
    dashboard.fuzzing_node_uid = ""
    dashboard.fuzzing_operation_id = ""
    dashboard.fuzzing_started_at = 0.0
    dashboard.fuzzing_seen_running_status = False
    dashboard.fuzzing_stop_requested = False
    dashboard.fuzzing_monitor_action_status = False


async def _finish_fuzzing(dashboard: QtCore.QObject, status_text: str):
    _clear_fuzzing_run_state(dashboard)
    _fuzzing_set_execution_locked(dashboard, False)
    _set_fuzzing_start_stop_button(dashboard, False)
    dashboard.ui.label_ta_fuzzing_execution_status.setText(status_text)
    update_fuzzing_selected_node_gate(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotFuzzingStartStopClicked(dashboard: QtCore.QObject):
    if _fuzzing_active(dashboard):
        node_uid = str(getattr(dashboard, "fuzzing_node_uid", "") or "").strip()
        operation_id = str(getattr(dashboard, "fuzzing_operation_id", "") or "").strip()
        if not node_uid or not operation_id:
            return
        dashboard.fuzzing_stop_requested = True
        dashboard.ui.label_ta_fuzzing_execution_status.setText("Stopping...")
        dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(False)
        try:
            await dashboard.backend.stopPluginOperation(node_uid, operation_id)
        except Exception as error:
            dashboard.logger.error(f"Could not stop Fuzzing operation {operation_id}: {error}")
            dashboard.fuzzing_stop_requested = False
            dashboard.ui.label_ta_fuzzing_execution_status.setText("Running")
            dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(True)
        return

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    plugin_name = str(getattr(dashboard, "fuzzing_selected_plugin", "") or "").strip()
    action_name = str(getattr(dashboard, "fuzzing_selected_action", "") or "").strip()
    if not node_uid or not plugin_name or not action_name or not dashboard.fuzzing_customized:
        return

    try:
        parameters = collect_fuzzing_action_parameters(dashboard)
        parameters.update(_fuzzing_hardware_parameters(dashboard))
        parameters.update(collect_fuzzing_plan(dashboard))
    except (TypeError, ValueError) as error:
        Qt5.errorMessage(str(error))
        return

    operation_id = str(uuid.uuid4())
    parameters["operation_id"] = operation_id
    parameters["requester"] = "dashboard"
    dashboard.fuzzing_start_pending = True
    dashboard.fuzzing_running = False
    dashboard.fuzzing_node_uid = node_uid
    dashboard.fuzzing_operation_id = operation_id
    dashboard.fuzzing_started_at = time.time()
    dashboard.fuzzing_seen_running_status = False
    dashboard.fuzzing_stop_requested = False
    dashboard.fuzzing_monitor_action_status = False

    _fuzzing_set_execution_locked(dashboard, True)
    _set_fuzzing_start_stop_button(dashboard, True)
    dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(True)
    dashboard.ui.label_ta_fuzzing_execution_status.setText("Starting...")
    dashboard.ui.label_ta_fuzzing_execution_operation_id.setText(operation_id)

    try:
        await dashboard.backend.tacticalNodeExecute([node_uid], plugin_name, action_name, parameters)
        dashboard.fuzzing_monitor_action_status = True
        dashboard.fuzzing_start_pending = False
        dashboard.fuzzing_running = True
    except Exception as error:
        dashboard.logger.error(f"Could not start Fuzzing action: {error}")
        await _finish_fuzzing(dashboard, "Start Failed")


async def update_fuzzing_status_from_selected_node(dashboard: QtCore.QObject, node_uid: str = "", status: str = ""):
    if not _fuzzing_active(dashboard) or not dashboard.fuzzing_monitor_action_status:
        return
    if not _fuzzing_node_uids_match(dashboard.fuzzing_node_uid, node_uid):
        return

    status_text = str(status or "").strip()
    if not status_text:
        return
    if status_text.startswith("Running"):
        dashboard.fuzzing_seen_running_status = True
        dashboard.fuzzing_start_pending = False
        dashboard.fuzzing_running = True
        if not dashboard.fuzzing_stop_requested:
            dashboard.ui.label_ta_fuzzing_execution_status.setText(status_text)
            dashboard.ui.pushButton_ta_fuzzing_start_stop.setEnabled(True)
        return
    if status_text == "Error":
        await _finish_fuzzing(dashboard, "Error")
        return
    if status_text == "Idle" and dashboard.fuzzing_seen_running_status:
        await _finish_fuzzing(dashboard, "Stopped" if dashboard.fuzzing_stop_requested else "Completed")


@QtCore.pyqtSlot(QtCore.QObject, int, int)
def _slotFuzzingFieldItemChanged(dashboard: QtCore.QObject, row: int, column: int):
    if column == 5:
        _update_fuzzing_field_length(dashboard, row)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotFuzzingRestoreDefaultsClicked(dashboard: QtCore.QObject):
    _restore_fuzzing_defaults(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotFuzzingAllBinaryClicked(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_fuzzing_fields
    for row in range(table.rowCount()):
        representation = table.cellWidget(row, 4)
        if representation is not None:
            representation.setCurrentIndex(0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotFuzzingAllHexClicked(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_fuzzing_fields
    for row in range(table.rowCount()):
        representation = table.cellWidget(row, 4)
        if representation is not None and representation.isEnabled():
            representation.setCurrentIndex(1)