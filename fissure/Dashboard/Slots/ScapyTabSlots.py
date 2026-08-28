from PyQt5 import QtCore, QtGui, QtWidgets
import os
import asyncio
import uuid

import fissure.utils
import fissure.utils.scapy_compat as scapy_compat
import fissure.utils.scapy_presets as scapy_presets
from fissure.utils.selected_node_utils import (
    selected_node_is_ip,
    selected_node_is_local,
)


SCAPY_AVAILABLE = scapy_compat.is_available()
SCAPY_IMPORT_ERROR = scapy_compat.import_error()
Packet = scapy_compat.Packet
NoPayload = scapy_compat.NoPayload


SCAPY_METHOD_AUTO = "Auto"
SCAPY_METHOD_SENDP = "sendp (Layer 2)"
SCAPY_METHOD_SEND = "send (Layer 3)"


def initialize_scapy_tab(dashboard: QtCore.QObject):
    """Initialize the Targets & Actions Scapy packet builder."""
    dashboard.scapy_packet = None
    dashboard.scapy_layers = []
    dashboard.scapy_layer_defaults = []
    dashboard.scapy_selected_layer_index = -1
    dashboard.scapy_updating_fields = False
    dashboard.scapy_interfaces_node_uid = ""
    dashboard.scapy_start_pending = False
    dashboard.scapy_running = False
    dashboard.scapy_operation_id = ""
    dashboard.scapy_operation_node_uid = ""

    dashboard.ui.stackedWidget_ta_scapy.setCurrentWidget(
        dashboard.ui.page_ta_scapy_no_node
    )

    select_node_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "select_node.png",
    )
    if os.path.isfile(select_node_icon_path):
        pixmap = QtGui.QPixmap(select_node_icon_path)
        dashboard.ui.label_ta_scapy_select_sensor_node_image.setPixmap(pixmap)
        dashboard.ui.label_ta_scapy_select_sensor_node_image.setScaledContents(False)
        dashboard.ui.label_ta_scapy_select_sensor_node_image.setAlignment(
            QtCore.Qt.AlignCenter
        )

    refresh_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "refresh.png",
    )
    if os.path.isfile(refresh_icon_path):
        dashboard.ui.pushButton_ta_scapy_transmit_interface_refresh.setIcon(
            QtGui.QIcon(refresh_icon_path)
        )
    dashboard.ui.pushButton_ta_scapy_transmit_interface_refresh.setToolTip(
        "Refresh interfaces on the selected Sensor Node"
    )

    _configure_scapy_tables(dashboard)

    dashboard.ui.plainTextEdit_ta_scapy_output_hexdump.setReadOnly(True)
    dashboard.ui.plainTextEdit_ta_scapy_output_python.setReadOnly(True)
    dashboard.ui.tabWidget_ta_scapy_output.setTabText(0, "Hexdump")
    if dashboard.ui.tabWidget_ta_scapy_output.count() > 1:
        dashboard.ui.tabWidget_ta_scapy_output.setTabText(1, "Python")

    method_combo = dashboard.ui.comboBox_ta_scapy_transmit_method
    method_combo.clear()
    method_combo.addItems(
        [
            SCAPY_METHOD_AUTO,
            SCAPY_METHOD_SENDP,
            SCAPY_METHOD_SEND,
        ]
    )
    method_combo.setCurrentIndex(0)

    dashboard.ui.doubleSpinBox_ta_scapy_transmit_interval.setDecimals(3)
    dashboard.ui.doubleSpinBox_ta_scapy_transmit_interval.setMinimum(0.0)
    dashboard.ui.doubleSpinBox_ta_scapy_transmit_interval.setMaximum(3600.0)
    dashboard.ui.doubleSpinBox_ta_scapy_transmit_interval.setValue(0.1)
    dashboard.ui.spinBox_ta_scapy_transmit_count.setMinimum(1)
    dashboard.ui.spinBox_ta_scapy_transmit_count.setMaximum(1000000000)
    dashboard.ui.spinBox_ta_scapy_transmit_count.setValue(1)
    dashboard.ui.checkBox_ta_scapy_transmit_loop.setChecked(False)

    _set_scapy_start_stop_button(dashboard, False)
    dashboard.ui.pushButton_ta_scapy_transmit_start_stop.setEnabled(False)
    dashboard.ui.pushButton_ta_scapy_transmit_interface_refresh.setEnabled(False)
    dashboard.ui.label2_ta_scapy_transmit_status.setText("Idle")
    dashboard.ui.label2_ta_scapy_transmit_operation_id.setText("—")
    dashboard.ui.label2_ta_scapy_transmit_started.setText("—")
    dashboard.ui.label2_ta_scapy_transmit_packets_sent.setText("—")
    dashboard.ui.label2_ta_scapy_transmit_set_rate.setText("—")

    if SCAPY_AVAILABLE:
        _populate_scapy_presets(dashboard)
        _clear_scapy_packet(dashboard)
    else:
        dashboard.ui.lineEdit_ta_scapy_source_search.setEnabled(False)
        dashboard.ui.treeWidget_ta_scapy_source_presets.clear()
        dashboard.ui.pushButton_ta_scapy_stack_add_layer.setEnabled(False)
        dashboard.ui.label2_ta_scapy_transmit_status.setText("Scapy unavailable")
        dashboard.ui.plainTextEdit_ta_scapy_output_hexdump.setPlainText(
            "Scapy could not be imported:\n" + SCAPY_IMPORT_ERROR
        )

    update_scapy_selected_node_gate(dashboard)


def _configure_scapy_tables(dashboard: QtCore.QObject):
    presets = dashboard.ui.treeWidget_ta_scapy_source_presets
    presets.setHeaderHidden(True)
    presets.setColumnCount(1)
    presets.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

    stack = dashboard.ui.tableWidget_ta_scapy_stack_layers
    stack.clearContents()
    stack.setRowCount(0)
    stack.setColumnCount(2)
    stack.setHorizontalHeaderLabels(["Layer", "Summary"])
    stack.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    stack.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    stack.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    stack.verticalHeader().setVisible(False)
    stack.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    stack.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)

    fields = dashboard.ui.tableWidget_ta_scapy_layers_fields
    fields.clearContents()
    fields.setRowCount(0)
    fields.setColumnCount(4)
    fields.setHorizontalHeaderLabels(["Field", "Value", "Type", "Len"])
    fields.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    fields.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    fields.verticalHeader().setVisible(False)
    fields.verticalHeader().setDefaultSectionSize(22)
    fields.verticalHeader().setMinimumSectionSize(20)
    fields_font = fields.font()
    fields_font.setPointSize(8)
    fields.setFont(fields_font)
    fields.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignCenter)
    fields.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    fields.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)
    fields.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
    fields.horizontalHeader().setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)

    interfaces = dashboard.ui.tableWidget_ta_scapy_transmit_interfaces
    interfaces.clearContents()
    interfaces.setRowCount(0)
    interfaces.setColumnCount(3)
    interfaces.setHorizontalHeaderLabels(["Interface", "Type", "Description"])
    interfaces.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    interfaces.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    interfaces.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    interfaces.verticalHeader().setVisible(False)
    interfaces.verticalHeader().setDefaultSectionSize(22)
    interfaces.verticalHeader().setMinimumSectionSize(20)
    interfaces.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    interfaces.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
    interfaces.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)


def _scapy_selected_node_available(dashboard: QtCore.QObject):
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        return False

    node_state = (getattr(dashboard, "node_states", {}) or {}).get(node_uid)
    if isinstance(node_state, dict) and node_state.get("connected") is False:
        return False

    return True


def _selected_scapy_interface_name(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_scapy_transmit_interfaces
    rows = table.selectionModel().selectedRows()

    if not rows:
        return ""

    item = table.item(rows[0].row(), 0)
    if item is None:
        return ""

    return str(item.text() or "").strip()


def _set_scapy_start_stop_button(
    dashboard: QtCore.QObject,
    running: bool,
):
    """Update the Scapy Start/Stop button text and dynamic style state."""
    button = dashboard.ui.pushButton_ta_scapy_transmit_start_stop

    button.setProperty(
        "running",
        bool(running),
    )
    button.setText(
        "Stop"
        if running
        else "Start"
    )

    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


def _update_scapy_start_gate(dashboard: QtCore.QObject):
    """Enable Start/Stop only when the current Scapy state allows it."""
    button = dashboard.ui.pushButton_ta_scapy_transmit_start_stop

    if getattr(dashboard, "scapy_start_pending", False):
        button.setEnabled(False)
        return

    if getattr(dashboard, "scapy_stop_pending", False):
        button.setEnabled(False)
        return

    if getattr(dashboard, "scapy_running", False):
        current_uid = str(
            getattr(dashboard, "selected_node_uid", "")
            or ""
        ).strip()
        operation_uid = str(
            getattr(dashboard, "scapy_operation_node_uid", "")
            or ""
        ).strip()

        button.setEnabled(
            bool(current_uid)
            and current_uid == operation_uid
        )
        return

    ready = _scapy_selected_node_available(dashboard)

    try:
        ready = ready and selected_node_is_ip(dashboard)
    except Exception:
        ready = False

    ready = (
        ready
        and SCAPY_AVAILABLE
        and dashboard.scapy_packet is not None
        and bool(_selected_scapy_interface_name(dashboard))
    )

    button.setEnabled(bool(ready))


def _reset_scapy_operation_state(dashboard: QtCore.QObject):
    dashboard.scapy_start_pending = False
    dashboard.scapy_stop_pending = False
    dashboard.scapy_running = False
    dashboard.scapy_operation_id = ""
    dashboard.scapy_operation_node_uid = ""

    _set_scapy_start_stop_button(
        dashboard,
        False,
    )

    # Leave the last displayed Operation ID visible after completion/stop/error.
    _update_scapy_start_gate(dashboard)


def update_scapy_selected_node_gate(dashboard: QtCore.QObject):
    """Show Scapy controls and synchronize interfaces for the selected IP node."""
    available = _scapy_selected_node_available(dashboard)
    dashboard.ui.stackedWidget_ta_scapy.setCurrentWidget(
        dashboard.ui.page_ta_scapy_controls
        if available
        else dashboard.ui.page_ta_scapy_no_node
    )

    current_uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()
    previous_uid = str(
        getattr(dashboard, "scapy_interfaces_node_uid", "")
        or ""
    ).strip()
    node_changed = current_uid != previous_uid

    if node_changed and not getattr(dashboard, "scapy_running", False):
        dashboard.scapy_start_pending = False
        dashboard.scapy_operation_id = ""
        dashboard.scapy_operation_node_uid = ""

    if not available:
        dashboard.scapy_interfaces_node_uid = ""
        _clear_scapy_interfaces(dashboard)
        dashboard.ui.pushButton_ta_scapy_transmit_interface_refresh.setEnabled(False)
        _update_scapy_start_gate(dashboard)
        return

    try:
        ip_node = selected_node_is_ip(dashboard)
    except Exception:
        ip_node = False

    if not ip_node:
        dashboard.scapy_interfaces_node_uid = current_uid
        _clear_scapy_interfaces(dashboard)
        dashboard.ui.pushButton_ta_scapy_transmit_interface_refresh.setEnabled(False)
        _update_scapy_start_gate(dashboard)
        return

    dashboard.scapy_interfaces_node_uid = current_uid
    dashboard.ui.pushButton_ta_scapy_transmit_interface_refresh.setEnabled(True)

    try:
        local_node = selected_node_is_local(dashboard)
    except Exception:
        local_node = False

    if local_node:
        if (
            node_changed
            or dashboard.ui.tableWidget_ta_scapy_transmit_interfaces.rowCount() == 0
        ):
            _populate_local_scapy_interfaces(dashboard)
    elif (
        node_changed
        or dashboard.ui.tableWidget_ta_scapy_transmit_interfaces.rowCount() == 0
    ):
        _clear_scapy_interfaces(dashboard)
        _request_remote_scapy_interfaces(dashboard)

    _update_scapy_start_gate(dashboard)


def _clear_scapy_interfaces(dashboard: QtCore.QObject):
    dashboard.ui.tableWidget_ta_scapy_transmit_interfaces.setRowCount(0)
    _update_scapy_start_gate(dashboard)


def _slotScapyInterfaceRefreshClicked(dashboard: QtCore.QObject):
    """Refresh interfaces on the currently selected local or remote IP node."""
    if not _scapy_selected_node_available(dashboard):
        _clear_scapy_interfaces(dashboard)
        return

    try:
        ip_node = selected_node_is_ip(dashboard)
    except Exception:
        ip_node = False

    if not ip_node:
        _clear_scapy_interfaces(dashboard)
        return

    try:
        local_node = selected_node_is_local(dashboard)
    except Exception:
        local_node = False

    if local_node:
        _populate_local_scapy_interfaces(dashboard)
    else:
        _request_remote_scapy_interfaces(dashboard)


def _request_remote_scapy_interfaces(dashboard: QtCore.QObject):
    """Request interface rows from the selected remote Sensor Node."""
    node_uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    if not node_uid:
        return

    asyncio.create_task(
        dashboard.backend.refreshScapyInterfaces(node_uid)
    )


def _populate_local_scapy_interfaces(dashboard: QtCore.QObject):
    """Enumerate local interfaces and populate the shared interface table."""
    try:
        interface_rows = scapy_compat.get_interfaces()
    except Exception as exc:
        _clear_scapy_interfaces(dashboard)
        _show_scapy_error(
            dashboard,
            f"Could not enumerate local network interfaces:\n{exc}",
        )
        return

    _populate_scapy_interfaces(
        dashboard,
        interface_rows,
    )


def handle_scapy_interface_results(
    dashboard: QtCore.QObject,
    node_uid="",
    interfaces=None,
):
    """Accept remote interface rows only for the node that is still selected."""
    node_uid = str(node_uid or "").strip()
    selected_uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    if not node_uid or node_uid != selected_uid:
        return

    try:
        if selected_node_is_local(dashboard):
            return
    except Exception:
        pass

    _populate_scapy_interfaces(
        dashboard,
        interfaces or [],
    )


def _populate_scapy_interfaces(
    dashboard: QtCore.QObject,
    interface_rows,
):
    """Populate normalized local or remote Scapy interface rows."""
    table = dashboard.ui.tableWidget_ta_scapy_transmit_interfaces
    selected_name = ""

    selected_rows = table.selectionModel().selectedRows()
    if selected_rows:
        item = table.item(
            selected_rows[0].row(),
            0,
        )
        if item is not None:
            selected_name = str(
                item.text()
                or ""
            ).strip()

    rows = [
        interface
        for interface in (interface_rows or [])
        if isinstance(interface, dict)
    ]

    table.blockSignals(True)

    try:
        table.setRowCount(len(rows))
        restore_row = -1

        for row, interface in enumerate(rows):
            values = (
                str(interface.get("name", "") or ""),
                str(interface.get("type", "") or ""),
                str(interface.get("description", "") or ""),
            )

            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setFlags(
                    item.flags()
                    & ~QtCore.Qt.ItemIsEditable
                )
                table.setItem(
                    row,
                    column,
                    item,
                )

            if values[0] == selected_name:
                restore_row = row

        if restore_row >= 0:
            table.selectRow(restore_row)
        elif table.rowCount() > 0:
            table.selectRow(0)

    finally:
        table.blockSignals(False)

    _update_scapy_start_gate(dashboard)


def _scapy_preset_value_supported(value):
    """Return True when nested Scapy values use layers available at runtime."""
    if isinstance(value, dict):
        nested_layer_name = value.get("__scapy_layer__")
        if nested_layer_name:
            if scapy_compat.get_layer_class(nested_layer_name) is None:
                return False
            return _scapy_preset_value_supported(value.get("fields", {}))
        return all(_scapy_preset_value_supported(item) for item in value.values())

    if isinstance(value, (list, tuple)):
        return all(_scapy_preset_value_supported(item) for item in value)

    return True


def _scapy_preset_supported(layer_specs):
    """Return True when every layer used by a preset exists in this Scapy runtime."""
    for layer_name, fields in layer_specs:
        if scapy_compat.get_layer_class(layer_name) is None:
            return False
        if not _scapy_preset_value_supported(fields):
            return False
    return True


def _resolve_scapy_preset_value(value):
    """Resolve nested declarative values into the objects expected by Scapy."""
    if isinstance(value, dict):
        nested_layer_name = value.get("__scapy_layer__")
        if nested_layer_name:
            layer_class = scapy_compat.get_layer_class(nested_layer_name)
            if layer_class is None:
                raise RuntimeError(f"Scapy layer is unavailable: {nested_layer_name}")

            fields = {
                key: _resolve_scapy_preset_value(field_value)
                for key, field_value in dict(value.get("fields", {}) or {}).items()
            }
            return layer_class(**fields)

        return {
            key: _resolve_scapy_preset_value(field_value)
            for key, field_value in value.items()
        }

    if isinstance(value, list):
        return [_resolve_scapy_preset_value(item) for item in value]

    if isinstance(value, tuple):
        return tuple(_resolve_scapy_preset_value(item) for item in value)

    return value


def _build_scapy_preset(layer_specs):
    """Build a packet from a declarative Scapy preset."""
    packet = None

    for layer_name, fields in layer_specs:
        layer_class = scapy_compat.get_layer_class(layer_name)
        if layer_class is None:
            raise RuntimeError(f"Scapy layer is unavailable: {layer_name}")

        resolved_fields = {
            key: _resolve_scapy_preset_value(value)
            for key, value in dict(fields or {}).items()
        }
        layer = layer_class(**resolved_fields)
        packet = layer if packet is None else packet / layer

    return packet


def _preset_catalog():
    """Return only declarative presets supported by the installed Scapy runtime."""
    catalog = {}

    for category_name, presets in scapy_presets.SCAPY_PRESETS.items():
        supported_presets = {
            preset_name: layer_specs
            for preset_name, layer_specs in presets.items()
            if _scapy_preset_supported(layer_specs)
        }

        if supported_presets:
            catalog[category_name] = supported_presets

    return catalog


def _populate_scapy_presets(dashboard: QtCore.QObject):
    tree = dashboard.ui.treeWidget_ta_scapy_source_presets
    tree.clear()
    dashboard.scapy_presets = _preset_catalog()

    for category_name, presets in dashboard.scapy_presets.items():
        category_item = QtWidgets.QTreeWidgetItem([category_name])
        category_item.setData(0, QtCore.Qt.UserRole, None)
        tree.addTopLevelItem(category_item)

        for preset_name in presets:
            preset_item = QtWidgets.QTreeWidgetItem([preset_name])
            preset_item.setData(0, QtCore.Qt.UserRole, (category_name, preset_name))
            category_item.addChild(preset_item)

        category_item.setExpanded(True)


def _slotScapyPresetSearchChanged(dashboard: QtCore.QObject, text: str):
    query = str(text or "").strip().lower()
    tree = dashboard.ui.treeWidget_ta_scapy_source_presets

    for top_index in range(tree.topLevelItemCount()):
        category = tree.topLevelItem(top_index)
        category_match = query in category.text(0).lower()
        any_child_visible = False

        for child_index in range(category.childCount()):
            child = category.child(child_index)
            visible = not query or category_match or query in child.text(0).lower()
            child.setHidden(not visible)
            any_child_visible = any_child_visible or visible

        category.setHidden(bool(query) and not category_match and not any_child_visible)
        if query and any_child_visible:
            category.setExpanded(True)


def _slotScapyPresetClicked(dashboard: QtCore.QObject, item: QtWidgets.QTreeWidgetItem, column: int):
    key = item.data(0, QtCore.Qt.UserRole)
    if not key:
        return

    category_name, preset_name = key
    layer_specs = dashboard.scapy_presets.get(category_name, {}).get(preset_name)
    if not layer_specs:
        return

    try:
        packet = _build_scapy_preset(layer_specs)
        _load_scapy_packet(dashboard, packet)
    except Exception as exc:
        _show_scapy_error(dashboard, f"Could not load Scapy preset:\n{exc}")


def _load_scapy_packet(dashboard: QtCore.QObject, packet):
    layers = _packet_to_layers(packet)
    dashboard.scapy_layers = [layer.copy() for layer in layers]
    dashboard.scapy_layer_defaults = [layer.copy() for layer in layers]
    dashboard.scapy_selected_layer_index = 0 if layers else -1
    _refresh_scapy_stack(dashboard)
    _refresh_scapy_packet(dashboard)


def _clear_scapy_packet(dashboard: QtCore.QObject):
    dashboard.scapy_packet = None
    dashboard.scapy_layers = []
    dashboard.scapy_layer_defaults = []
    dashboard.scapy_selected_layer_index = -1
    dashboard.ui.tableWidget_ta_scapy_stack_layers.setRowCount(0)
    dashboard.ui.comboBox_ta_scapy_layers_editing.clear()
    dashboard.ui.tableWidget_ta_scapy_layers_fields.setRowCount(0)
    dashboard.ui.plainTextEdit_ta_scapy_output_hexdump.clear()
    dashboard.ui.plainTextEdit_ta_scapy_output_python.clear()
    dashboard.ui.label2_ta_scapy_output_hexdump_byte_count.setText("0")
    _update_scapy_start_gate(dashboard)


def _packet_to_layers(packet):
    return scapy_compat.packet_to_layers(packet)


def _build_scapy_packet(dashboard: QtCore.QObject):
    if not dashboard.scapy_layers:
        return None

    packet = dashboard.scapy_layers[0].copy()
    for layer in dashboard.scapy_layers[1:]:
        packet = packet / layer.copy()
    return packet


def _refresh_scapy_stack(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_scapy_stack_layers
    combo = dashboard.ui.comboBox_ta_scapy_layers_editing
    selected = dashboard.scapy_selected_layer_index

    table.blockSignals(True)
    combo.blockSignals(True)
    table.setRowCount(len(dashboard.scapy_layers))
    combo.clear()

    seen = {}
    for row, layer in enumerate(dashboard.scapy_layers):
        layer_name = layer.__class__.__name__
        seen[layer_name] = seen.get(layer_name, 0) + 1
        display_name = layer_name if seen[layer_name] == 1 else f"{layer_name} #{seen[layer_name]}"
        summary = _layer_summary(layer)

        table.setItem(row, 0, QtWidgets.QTableWidgetItem(display_name))
        table.setItem(row, 1, QtWidgets.QTableWidgetItem(summary))
        combo.addItem(display_name, row)

    if 0 <= selected < len(dashboard.scapy_layers):
        table.selectRow(selected)
        combo.setCurrentIndex(selected)
    elif dashboard.scapy_layers:
        dashboard.scapy_selected_layer_index = 0
        table.selectRow(0)
        combo.setCurrentIndex(0)

    table.blockSignals(False)
    combo.blockSignals(False)
    _refresh_scapy_fields(dashboard)


def _layer_summary(layer):
    values = []
    for key, value in list(getattr(layer, "fields", {}).items())[:4]:
        values.append(f"{key}={_display_value(value)}")
    return ", ".join(values) if values else "Defaults"


def _display_value(value):
    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
            if decoded.isprintable():
                return decoded
        except Exception:
            pass
        return "0x" + value.hex()
    return str(value)


def _slotScapyStackSelectionChanged(dashboard: QtCore.QObject):
    rows = dashboard.ui.tableWidget_ta_scapy_stack_layers.selectionModel().selectedRows()
    if not rows:
        return
    _set_selected_layer(dashboard, rows[0].row())


def _slotScapyEditingLayerChanged(dashboard: QtCore.QObject, index: int):
    if index < 0:
        return
    _set_selected_layer(dashboard, index)


def _set_selected_layer(dashboard: QtCore.QObject, index: int):
    if index < 0 or index >= len(dashboard.scapy_layers):
        return

    dashboard.scapy_selected_layer_index = index

    table = dashboard.ui.tableWidget_ta_scapy_stack_layers
    combo = dashboard.ui.comboBox_ta_scapy_layers_editing
    table.blockSignals(True)
    combo.blockSignals(True)
    table.selectRow(index)
    combo.setCurrentIndex(index)
    table.blockSignals(False)
    combo.blockSignals(False)
    _refresh_scapy_fields(dashboard)


def _slotScapyAddLayerClicked(dashboard: QtCore.QObject):
    if not SCAPY_AVAILABLE:
        return

    dialog = ScapyLayerDialog(dashboard)
    if dialog.exec_() != QtWidgets.QDialog.Accepted or dialog.selected_layer_class is None:
        return

    try:
        new_layer = dialog.selected_layer_class()
    except Exception as exc:
        _show_scapy_error(dashboard, f"Could not create {dialog.selected_layer_class.__name__}:\n{exc}")
        return

    insert_at = dashboard.scapy_selected_layer_index + 1
    if insert_at <= 0 or insert_at > len(dashboard.scapy_layers):
        insert_at = len(dashboard.scapy_layers)

    dashboard.scapy_layers.insert(insert_at, new_layer)
    dashboard.scapy_layer_defaults.insert(insert_at, new_layer.copy())
    dashboard.scapy_selected_layer_index = insert_at
    _refresh_scapy_stack(dashboard)
    _refresh_scapy_packet(dashboard)


def _slotScapyRemoveLayerClicked(dashboard: QtCore.QObject):
    index = dashboard.scapy_selected_layer_index
    if index < 0 or index >= len(dashboard.scapy_layers):
        return

    dashboard.scapy_layers.pop(index)
    dashboard.scapy_layer_defaults.pop(index)
    if dashboard.scapy_layers:
        dashboard.scapy_selected_layer_index = min(index, len(dashboard.scapy_layers) - 1)
    else:
        dashboard.scapy_selected_layer_index = -1
    _refresh_scapy_stack(dashboard)
    _refresh_scapy_packet(dashboard)


def _slotScapyMoveLayerUpClicked(dashboard: QtCore.QObject):
    index = dashboard.scapy_selected_layer_index
    if index <= 0 or index >= len(dashboard.scapy_layers):
        return

    dashboard.scapy_layers[index - 1], dashboard.scapy_layers[index] = dashboard.scapy_layers[index], dashboard.scapy_layers[index - 1]
    dashboard.scapy_layer_defaults[index - 1], dashboard.scapy_layer_defaults[index] = dashboard.scapy_layer_defaults[index], dashboard.scapy_layer_defaults[index - 1]
    dashboard.scapy_selected_layer_index = index - 1
    _refresh_scapy_stack(dashboard)
    _refresh_scapy_packet(dashboard)


def _slotScapyMoveLayerDownClicked(dashboard: QtCore.QObject):
    index = dashboard.scapy_selected_layer_index
    if index < 0 or index >= len(dashboard.scapy_layers) - 1:
        return

    dashboard.scapy_layers[index + 1], dashboard.scapy_layers[index] = dashboard.scapy_layers[index], dashboard.scapy_layers[index + 1]
    dashboard.scapy_layer_defaults[index + 1], dashboard.scapy_layer_defaults[index] = dashboard.scapy_layer_defaults[index], dashboard.scapy_layer_defaults[index + 1]
    dashboard.scapy_selected_layer_index = index + 1
    _refresh_scapy_stack(dashboard)
    _refresh_scapy_packet(dashboard)


def _slotScapyClearAllClicked(dashboard: QtCore.QObject):
    _clear_scapy_packet(dashboard)


def _slotScapyResetLayerClicked(dashboard: QtCore.QObject):
    index = dashboard.scapy_selected_layer_index
    if index < 0 or index >= len(dashboard.scapy_layer_defaults):
        return

    dashboard.scapy_layers[index] = dashboard.scapy_layer_defaults[index].copy()
    _refresh_scapy_stack(dashboard)
    _refresh_scapy_packet(dashboard)


def _refresh_scapy_fields(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_scapy_layers_fields
    table.setRowCount(0)

    index = dashboard.scapy_selected_layer_index
    if index < 0 or index >= len(dashboard.scapy_layers):
        return

    layer = dashboard.scapy_layers[index]
    field_descriptors = list(getattr(layer, "fields_desc", []) or [])
    dashboard.scapy_updating_fields = True
    table.setRowCount(len(field_descriptors))

    for row, field in enumerate(field_descriptors):
        base_field = getattr(field, "fld", field)
        field_name = getattr(field, "name", getattr(base_field, "name", ""))
        type_name = scapy_compat.field_type_name(field)
        field_len = scapy_compat.field_length(field)
        value = layer.getfieldval(field_name)

        name_item = QtWidgets.QTableWidgetItem(field_name)
        type_item = QtWidgets.QTableWidgetItem(type_name)
        len_item = QtWidgets.QTableWidgetItem(field_len)
        name_item.setFlags(name_item.flags() & ~QtCore.Qt.ItemIsEditable)
        type_item.setFlags(type_item.flags() & ~QtCore.Qt.ItemIsEditable)
        len_item.setFlags(len_item.flags() & ~QtCore.Qt.ItemIsEditable)
        table.setItem(row, 0, name_item)
        table.setItem(row, 2, type_item)
        table.setItem(row, 3, len_item)

        editor = _make_field_editor(dashboard, layer, field, value)
        table.setCellWidget(row, 1, editor)

    dashboard.scapy_updating_fields = False


def _make_field_editor(dashboard: QtCore.QObject, layer, field, value):
    flag_options = scapy_compat.field_flag_options(field)

    if flag_options:
        editor = ScapyFlagsEditor(flag_options, value)
        editor.valueChanged.connect(
            lambda d=dashboard, l=layer, f=field, w=editor: _apply_field_editor_value(d, l, f, w)
        )
        return editor

    enum_values = scapy_compat.field_enum_values(field)

    if isinstance(enum_values, dict) and enum_values:
        combo = QtWidgets.QComboBox()
        current_index = -1
        for enum_value, enum_name in sorted(enum_values.items(), key=lambda item: str(item[0])):
            combo.addItem(f"{enum_value}: {enum_name}", enum_value)
            if enum_value == value:
                current_index = combo.count() - 1
        if current_index >= 0:
            combo.setCurrentIndex(current_index)
        combo_font = combo.font()
        combo_font.setPointSize(8)
        combo.setFont(combo_font)
        combo.setFixedHeight(20)
        combo.currentIndexChanged.connect(
            lambda _index, d=dashboard, l=layer, f=field, w=combo: _apply_field_editor_value(d, l, f, w)
        )
        return combo

    editor = QtWidgets.QLineEdit()
    editor.setText(_field_display_text(field, layer, value))
    editor_font = editor.font()
    editor_font.setPointSize(8)
    editor.setFont(editor_font)
    editor.setFixedHeight(20)
    editor.setFrame(False)
    editor.setStyleSheet("QLineEdit { border: none; background: transparent; padding: 0 2px; }")
    editor.editingFinished.connect(
        lambda d=dashboard, l=layer, f=field, w=editor: _apply_field_editor_value(d, l, f, w)
    )
    return editor


def _field_display_text(field, layer, value):
    return scapy_compat.field_display_text(field, layer, value)


def _apply_field_editor_value(dashboard: QtCore.QObject, layer, field, editor):
    if dashboard.scapy_updating_fields:
        return

    field_name = getattr(field, "name", getattr(getattr(field, "fld", None), "name", ""))
    if not field_name:
        return

    try:
        if isinstance(editor, ScapyFlagsEditor):
            value = editor.flag_value()
        elif isinstance(editor, QtWidgets.QComboBox):
            value = editor.currentData()
        else:
            value = _parse_field_text(field, layer, editor.text())
        setattr(layer, field_name, value)
        _refresh_scapy_stack(dashboard)
        _refresh_scapy_packet(dashboard)
    except Exception as exc:
        _show_scapy_error(dashboard, f"Invalid value for {field_name}:\n{exc}")
        _refresh_scapy_fields(dashboard)


def _parse_field_text(field, layer, text):
    return scapy_compat.parse_field_text(field, layer, text)


def _refresh_scapy_packet(dashboard: QtCore.QObject):
    dashboard.scapy_packet = _build_scapy_packet(dashboard)
    packet = dashboard.scapy_packet

    if packet is None:
        dashboard.ui.plainTextEdit_ta_scapy_output_hexdump.clear()
        dashboard.ui.plainTextEdit_ta_scapy_output_python.clear()
        dashboard.ui.label2_ta_scapy_output_hexdump_byte_count.setText("0")
        _update_scapy_start_gate(dashboard)
        return

    try:
        packet_bytes = scapy_compat.packet_bytes(packet)
        hex_text = _fallback_hexdump(packet_bytes)
        dashboard.ui.plainTextEdit_ta_scapy_output_hexdump.setPlainText(hex_text)
        dashboard.ui.label2_ta_scapy_output_hexdump_byte_count.setText(
            str(len(packet_bytes))
        )
    except Exception as exc:
        dashboard.ui.plainTextEdit_ta_scapy_output_hexdump.setPlainText(
            f"Packet build error:\n{exc}"
        )
        dashboard.ui.label2_ta_scapy_output_hexdump_byte_count.setText("—")

    try:
        command = scapy_compat.packet_command(packet)
        python_text = "from scapy.all import *\n\npacket = " + command + "\n"
        dashboard.ui.plainTextEdit_ta_scapy_output_python.setPlainText(
            python_text
        )
    except Exception as exc:
        dashboard.ui.plainTextEdit_ta_scapy_output_python.setPlainText(
            f"Could not generate Scapy Python:\n{exc}"
        )

    _update_scapy_start_gate(dashboard)


def _fallback_hexdump(data: bytes):
    """Return a roomy Wireshark-style 16-byte hexdump."""
    lines = []
    for offset in range(0, len(data), 16):
        chunk = data[offset:offset + 16]
        left = " ".join(f"{byte:02X}" for byte in chunk[:8])
        right = " ".join(f"{byte:02X}" for byte in chunk[8:])
        hex_part = f"{left:<23}  {right:<23}"
        ascii_part = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
        lines.append(f"{offset:04X}   {hex_part}   |{ascii_part:<16}|")
    return "\n".join(lines)


def _slotScapyOutputCopyClicked(dashboard: QtCore.QObject):
    if dashboard.ui.tabWidget_ta_scapy_output.currentIndex() == 1:
        text = dashboard.ui.plainTextEdit_ta_scapy_output_python.toPlainText()
    else:
        text = dashboard.ui.plainTextEdit_ta_scapy_output_hexdump.toPlainText()
    QtWidgets.QApplication.clipboard().setText(text)


def _slotScapyOutputSaveAsClicked(dashboard: QtCore.QObject):
    python_output = dashboard.ui.tabWidget_ta_scapy_output.currentIndex() == 1
    default_name = "scapy_packet.py" if python_output else "scapy_packet.hex.txt"
    file_filter = "Python Files (*.py);;All Files (*)" if python_output else "Text Files (*.txt);;All Files (*)"
    path, _selected_filter = QtWidgets.QFileDialog.getSaveFileName(dashboard, "Save Scapy Output", default_name, file_filter)
    if not path:
        return

    if python_output:
        text = dashboard.ui.plainTextEdit_ta_scapy_output_python.toPlainText()
    else:
        text = dashboard.ui.plainTextEdit_ta_scapy_output_hexdump.toPlainText()

    try:
        with open(path, "w", encoding="utf-8") as output_file:
            output_file.write(text)
    except Exception as exc:
        _show_scapy_error(dashboard, f"Could not save Scapy output:\n{exc}")


def _slotScapyLoopToggled(dashboard: QtCore.QObject, checked: bool):
    dashboard.ui.spinBox_ta_scapy_transmit_count.setEnabled(not checked)


def _set_scapy_status(dashboard: QtCore.QObject, summary: str, detail: str = ""):
    """Show a short Scapy status while preserving the full message in a tooltip."""
    label = dashboard.ui.label2_ta_scapy_transmit_status
    summary = str(summary or "").strip()
    detail = str(detail or "").strip()

    label.setText(summary)
    label.setToolTip(detail if detail and detail != summary else "")


def _show_scapy_error(dashboard: QtCore.QObject, message: str):
    QtWidgets.QMessageBox.warning(dashboard, "Scapy", str(message))


class ScapyFlagsEditor(QtWidgets.QToolButton):
    """Compact multi-select editor backed by flag names exposed by Scapy."""

    valueChanged = QtCore.pyqtSignal()

    def __init__(self, flag_options, value, parent=None):
        super().__init__(parent)

        self._flag_options = [
            (int(mask), str(name))
            for mask, name in flag_options
            if int(mask) > 0 and str(name)
        ]
        self._checkboxes = {}

        known_mask = 0
        for mask, _name in self._flag_options:
            known_mask |= mask

        try:
            numeric_value = int(value or 0)
        except Exception:
            numeric_value = 0

        self._unknown_bits = numeric_value & ~known_mask

        self.setPopupMode(QtWidgets.QToolButton.InstantPopup)
        self.setFixedHeight(20)

        editor_font = self.font()
        editor_font.setPointSize(8)
        self.setFont(editor_font)

        self._menu = QtWidgets.QMenu(self)
        self.setMenu(self._menu)

        for mask, name in self._flag_options:
            checkbox = QtWidgets.QCheckBox(name, self._menu)
            checkbox.setChecked(bool(numeric_value & mask))

            action = QtWidgets.QWidgetAction(self._menu)
            action.setDefaultWidget(checkbox)
            self._menu.addAction(action)

            checkbox.toggled.connect(
                lambda _checked, m=mask: self._flag_toggled(m)
            )
            self._checkboxes[mask] = checkbox

        self._update_text()

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self._show_menu()
            event.accept()
            return

        super().mousePressEvent(event)

    def _show_menu(self):
        if self._menu.isVisible():
            self._menu.hide()
            return

        global_top_left = self.mapToGlobal(QtCore.QPoint(0, 0))
        popup_position = self.mapToGlobal(QtCore.QPoint(0, self.height()))
        screen = QtWidgets.QApplication.screenAt(
            self.mapToGlobal(self.rect().center())
        )

        if screen is not None:
            available = screen.availableGeometry()
            menu_size = self._menu.sizeHint()

            x = popup_position.x()
            y = popup_position.y()

            if x + menu_size.width() > available.right() + 1:
                x = available.right() - menu_size.width() + 1
            if x < available.left():
                x = available.left()

            if y + menu_size.height() > available.bottom() + 1:
                y = global_top_left.y() - menu_size.height()
            if y < available.top():
                y = available.top()

            popup_position = QtCore.QPoint(x, y)

        self._menu.popup(popup_position)

    def _flag_toggled(self, _mask):
        self._update_text()
        self.valueChanged.emit()

    def _update_text(self):
        selected_names = [
            name
            for mask, name in self._flag_options
            if self._checkboxes[mask].isChecked()
        ]

        if self._unknown_bits:
            selected_names.append(f"0x{self._unknown_bits:X}")

        self.setText(", ".join(selected_names) if selected_names else "none")
        self.setToolTip(self.text())

    def flag_value(self):
        value = self._unknown_bits

        for mask, _name in self._flag_options:
            if self._checkboxes[mask].isChecked():
                value |= mask

        return value
    

class ScapyLayerDialog(QtWidgets.QDialog):
    """Small searchable browser for packet layers registered with Scapy."""

    def __init__(self, dashboard):
        super().__init__(dashboard)
        self.selected_layer_class = None
        self.setWindowTitle("Add Layer")
        self.resize(430, 560)

        layout = QtWidgets.QVBoxLayout(self)
        self.search = QtWidgets.QLineEdit(self)
        self.search.setPlaceholderText("Search Scapy layers...")
        layout.addWidget(self.search)

        self.tree = QtWidgets.QTreeWidget(self)
        self.tree.setHeaderHidden(True)
        self.tree.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        layout.addWidget(self.tree, 1)

        button_layout = QtWidgets.QHBoxLayout()
        button_layout.addStretch(1)
        self.add_button = QtWidgets.QPushButton("Add Layer", self)
        self.cancel_button = QtWidgets.QPushButton("Cancel", self)
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        self._populate_layers()
        self.search.textChanged.connect(self._filter_layers)
        self.add_button.clicked.connect(self._accept_selected)
        self.cancel_button.clicked.connect(self.reject)
        self.tree.itemDoubleClicked.connect(lambda _item, _column: self._accept_selected())
        self.tree.itemSelectionChanged.connect(self._update_add_button)
        self._update_add_button()

    def _populate_layers(self):
        categories = {}
        seen = set()

        layer_classes = scapy_compat.get_layer_classes()

        for layer_class in layer_classes:
            if not isinstance(layer_class, type):
                continue
            try:
                if not issubclass(layer_class, Packet):
                    continue
            except Exception:
                continue

            name = str(getattr(layer_class, "__name__", "") or "").strip()
            if not name or name.startswith("_") or name in seen or name == "NoPayload":
                continue
            seen.add(name)
            category = self._category_for_layer(layer_class)
            categories.setdefault(category, []).append(layer_class)

        category_order = [
            "Recently Used",
            "802.11 Wireless",
            "Link Layer",
            "Network Layer",
            "Transport Layer",
            "Bluetooth",
            "802.15.4 / Zigbee",
            "Application / Services",
            "Other",
        ]

        for category in category_order:
            classes = categories.get(category, [])
            if not classes:
                continue
            parent = QtWidgets.QTreeWidgetItem([category])
            self.tree.addTopLevelItem(parent)
            for layer_class in sorted(classes, key=lambda cls: cls.__name__.lower()):
                child = QtWidgets.QTreeWidgetItem([layer_class.__name__])
                child.setData(0, QtCore.Qt.UserRole, layer_class)
                parent.addChild(child)
            if category in ("802.11 Wireless", "Link Layer", "Network Layer", "Transport Layer"):
                parent.setExpanded(True)

    @staticmethod
    def _category_for_layer(layer_class):
        module = str(getattr(layer_class, "__module__", "") or "").lower()
        name = str(getattr(layer_class, "__name__", "") or "").lower()

        if "dot11" in module or name.startswith("dot11") or name == "radiotap":
            return "802.11 Wireless"
        if "bluetooth" in module or name.startswith(("btle", "hci_", "l2cap")):
            return "Bluetooth"
        if "dot15d4" in module or "zigbee" in module or name.startswith(("dot15d4", "zigbee")):
            return "802.15.4 / Zigbee"
        if any(token in name for token in ("tcp", "udp", "sctp")) and ".inet" in module:
            return "Transport Layer"
        if ".inet" in module or ".inet6" in module or name in ("ip", "ipv6", "icmp", "icmpv6"):
            return "Network Layer"
        if module.endswith(".l2") or name in ("ether", "arp", "llc", "snap"):
            return "Link Layer"
        if any(token in module for token in ("dns", "dhcp", "http", "tls")):
            return "Application / Services"
        return "Other"

    def _filter_layers(self, text):
        query = str(text or "").strip().lower()
        for top_index in range(self.tree.topLevelItemCount()):
            category = self.tree.topLevelItem(top_index)
            category_match = query in category.text(0).lower()
            any_child_visible = False
            for child_index in range(category.childCount()):
                child = category.child(child_index)
                visible = not query or category_match or query in child.text(0).lower()
                child.setHidden(not visible)
                any_child_visible = any_child_visible or visible
            category.setHidden(bool(query) and not category_match and not any_child_visible)
            if query and any_child_visible:
                category.setExpanded(True)

    def _update_add_button(self):
        item = self.tree.currentItem()
        layer_class = item.data(0, QtCore.Qt.UserRole) if item is not None else None
        self.add_button.setEnabled(layer_class is not None)

    def _accept_selected(self):
        item = self.tree.currentItem()
        if item is None:
            return
        layer_class = item.data(0, QtCore.Qt.UserRole)
        if layer_class is None:
            return
        self.selected_layer_class = layer_class
        self.accept()


def _slotScapyInterfaceSelectionChanged(dashboard: QtCore.QObject):
    _update_scapy_start_gate(dashboard)


def _slotScapyTransmitStartStopClicked(dashboard: QtCore.QObject):
    """Start or stop the selected Sensor Node Scapy transmission."""
    if getattr(dashboard, "scapy_start_pending", False):
        return

    if getattr(dashboard, "scapy_stop_pending", False):
        return

    if getattr(dashboard, "scapy_running", False):
        node_uid = str(
            getattr(dashboard, "scapy_operation_node_uid", "")
            or ""
        ).strip()
        operation_id = str(
            getattr(dashboard, "scapy_operation_id", "")
            or ""
        ).strip()

        if not node_uid or not operation_id:
            _set_scapy_status(
                dashboard,
                "Error",
                "Stop failed — missing operation state.",
            )
            return

        dashboard.scapy_stop_pending = True
        _set_scapy_status(
            dashboard,
            "Stopping...",
        )
        _update_scapy_start_gate(dashboard)

        asyncio.create_task(
            dashboard.backend.stopPluginOperation(
                node_uid,
                operation_id,
            )
        )
        return

    _update_scapy_start_gate(dashboard)

    if not dashboard.ui.pushButton_ta_scapy_transmit_start_stop.isEnabled():
        return

    node_uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()
    interface = _selected_scapy_interface_name(dashboard)
    method = str(
        dashboard.ui.comboBox_ta_scapy_transmit_method.currentText()
        or ""
    ).strip()
    interval = float(
        dashboard.ui.doubleSpinBox_ta_scapy_transmit_interval.value()
    )
    count = int(
        dashboard.ui.spinBox_ta_scapy_transmit_count.value()
    )
    loop = bool(
        dashboard.ui.checkBox_ta_scapy_transmit_loop.isChecked()
    )

    try:
        packet_hex = scapy_compat.packet_bytes(
            dashboard.scapy_packet
        ).hex()
    except Exception as exc:
        _show_scapy_error(
            dashboard,
            f"Could not build packet:\n{exc}",
        )
        return

    operation_id = str(uuid.uuid4())

    dashboard.scapy_start_pending = True
    dashboard.scapy_stop_pending = False
    dashboard.scapy_operation_id = operation_id
    dashboard.scapy_operation_node_uid = node_uid

    _set_scapy_status(
        dashboard,
        "Starting...",
    )
    dashboard.ui.label2_ta_scapy_transmit_operation_id.setText(
        operation_id[:8]
    )
    dashboard.ui.label2_ta_scapy_transmit_operation_id.setToolTip(
        operation_id
    )
    dashboard.ui.label2_ta_scapy_transmit_started.setText("—")
    dashboard.ui.label2_ta_scapy_transmit_packets_sent.setText("0")
    dashboard.ui.label2_ta_scapy_transmit_set_rate.setText("—")
    _update_scapy_start_gate(dashboard)

    asyncio.create_task(
        dashboard.backend.startScapyTransmission(
            node_uid=node_uid,
            operation_id=operation_id,
            interface=interface,
            method=method,
            interval=interval,
            count=count,
            loop=loop,
            packet_hex=packet_hex,
        )
    )

    QtCore.QTimer.singleShot(
        5000,
        lambda d=dashboard, opid=operation_id: _scapy_start_timeout(
            d,
            opid,
        ),
    )


def _scapy_start_timeout(
    dashboard: QtCore.QObject,
    operation_id: str,
):
    if not getattr(dashboard, "scapy_start_pending", False):
        return

    if str(
        getattr(dashboard, "scapy_operation_id", "")
        or ""
    ) != str(operation_id or ""):
        return

    _set_scapy_status(
        dashboard,
        "Timed Out",
        "Scapy transmission start timed out.",
    )
    _reset_scapy_operation_state(dashboard)


def handle_scapy_transmission_status(
    dashboard: QtCore.QObject,
    node_uid="",
    operation_id="",
    state="",
    message="",
    packets_sent=0,
    set_rate="",
    started="",
):
    """Apply Sensor Node Scapy transmission state to the current operation."""
    node_uid = str(node_uid or "").strip()
    operation_id = str(operation_id or "").strip()
    state = str(state or "").strip().lower()
    message = str(message or "").strip()

    if operation_id != str(
        getattr(dashboard, "scapy_operation_id", "")
        or ""
    ).strip():
        return

    if node_uid != str(
        getattr(dashboard, "scapy_operation_node_uid", "")
        or ""
    ).strip():
        return

    if state == "validated":
        # TEMPORARY — REMOVE WHEN THE SCAPY TAB LAUNCHES Base.scapy_transmit.
        _set_scapy_status(
            dashboard,
            "Ready",
            message,
        )
        _reset_scapy_operation_state(dashboard)
        return

    if state == "started":
        dashboard.scapy_start_pending = False
        dashboard.scapy_running = True

        _set_scapy_start_stop_button(
            dashboard,
            True,
        )

        _set_scapy_status(
            dashboard,
            "Running",
            message,
        )
        dashboard.ui.label2_ta_scapy_transmit_started.setText(
            started or "—"
        )
        dashboard.ui.label2_ta_scapy_transmit_packets_sent.setText(
            str(int(packets_sent or 0))
        )
        dashboard.ui.label2_ta_scapy_transmit_set_rate.setText(
            set_rate or "—"
        )
        _update_scapy_start_gate(dashboard)
        return

    if state == "running":
        dashboard.scapy_start_pending = False
        dashboard.scapy_running = True

        dashboard.ui.label2_ta_scapy_transmit_packets_sent.setText(
            str(int(packets_sent or 0))
        )
        dashboard.ui.label2_ta_scapy_transmit_set_rate.setText(
            set_rate or "—"
        )

        if getattr(dashboard, "scapy_stop_pending", False):
            # A final progress update can arrive after Stop was clicked.
            # Keep the button disabled/gray and preserve "Stopping...".
            _update_scapy_start_gate(dashboard)
            return

        _set_scapy_start_stop_button(
            dashboard,
            True,
        )
        _set_scapy_status(
            dashboard,
            "Running",
            message,
        )
        _update_scapy_start_gate(dashboard)
        return

    if state in {
        "completed",
        "stopped",
        "error",
    }:
        if state == "completed":
            summary = "Completed"
        elif state == "stopped":
            summary = "Stopped"
        else:
            summary = "Error"

        _set_scapy_status(
            dashboard,
            summary,
            message,
        )
        dashboard.ui.label2_ta_scapy_transmit_packets_sent.setText(
            str(int(packets_sent or 0))
        )
        dashboard.ui.label2_ta_scapy_transmit_set_rate.setText(
            set_rate or "—"
        )

        _reset_scapy_operation_state(dashboard)