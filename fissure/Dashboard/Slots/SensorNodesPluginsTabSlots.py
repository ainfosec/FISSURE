#!/usr/bin/python3
import datetime
import os
import asyncio
from PyQt5 import QtCore, QtWidgets, QtGui
import qasync

import fissure
from fissure.utils.selected_node_utils import (
    selected_node_is_ip,
    selected_node_is_remote,
)


_PLUGIN_STATUS_COLORS = {
    "Ready": "#2EA043",
    "Up to Date": "#2EA043",

    "Setup Required": "#D98200",
    "Update Available": "#D98200",
    "Missing on Node": "#D98200",

    "Setup Failed": "#D9534F",

    "Not Deployed": "#808080",
    "Node Only": "#808080",

    "Running": "#2F80ED",
}


def initialize_sensor_nodes_plugins_controls(dashboard: QtCore.QObject):
    """Initialize the selected-node plugin inventory view."""
    dashboard.sensor_nodes_plugin_inventory = {}
    dashboard.sensor_nodes_plugins_last_node_uid = ""
    dashboard.sensor_nodes_plugin_management_busy = False

    table = dashboard.ui.tableWidget_sn_plugins_inventory
    table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    table.setSortingEnabled(False)
    table.verticalHeader().setVisible(False)

    header = table.horizontalHeader()
    header.setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
    header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(5, QtWidgets.QHeaderView.ResizeToContents)

    dashboard.ui.plainTextEdit_sn_plugins_operation_log.setReadOnly(True)
    dashboard.ui.progressBar_sn_plugins_operation_status.setRange(0, 100)
    dashboard.ui.progressBar_sn_plugins_operation_status.setValue(0)

    dashboard.ui.pushButton_sn_plugins_inventory_deploy.setEnabled(False)
    dashboard.ui.pushButton_sn_plugins_inventory_repair.setEnabled(False)
    dashboard.ui.pushButton_sn_plugins_inventory_remove.setEnabled(False)

    dashboard.ui.label2_sn_plugins_operation_status_current_operation.setText("—")
    dashboard.ui.label2_sn_plugins_operation_status_status.setText("Idle")
    dashboard.ui.label2_sn_plugins_operation_status_last_update.setText("—")

    select_node_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "select_node.png",
    )
    if os.path.isfile(select_node_icon_path):
        select_node_pixmap = QtGui.QPixmap(select_node_icon_path)
        dashboard.ui.label_sn_plugins_select_sensor_node_image.setPixmap(
            select_node_pixmap
        )
        dashboard.ui.label_sn_plugins_select_sensor_node_image.setScaledContents(False)
        dashboard.ui.label_sn_plugins_select_sensor_node_image.setAlignment(
            QtCore.Qt.AlignCenter
        )

    _clear_plugin_details(dashboard)
    update_sensor_nodes_plugins_selected_node_gate(dashboard)


def _plugin_uid_matches(first_uid: str, second_uid: str) -> bool:
    """Return True when full/short Sensor Node UIDs refer to the same node."""
    first_uid = str(first_uid or "").strip()
    second_uid = str(second_uid or "").strip()

    if not first_uid or not second_uid:
        return False

    return (
        first_uid == second_uid
        or first_uid.endswith(second_uid)
        or second_uid.endswith(first_uid)
    )


def _plugin_details_layout(dashboard: QtCore.QObject):
    """Return the reusable read-only Plugin Details layout."""
    contents = dashboard.ui.scrollAreaWidgetContents_sn_plugins_details
    layout = contents.layout()

    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    layout.setContentsMargins(10, 8, 10, 8)
    layout.setHorizontalSpacing(12)
    layout.setVerticalSpacing(5)
    layout.setColumnStretch(0, 0)
    layout.setColumnStretch(1, 1)
    layout.setAlignment(QtCore.Qt.AlignTop)

    return layout


def _clear_plugin_details(dashboard: QtCore.QObject):
    """Clear the selected plugin details pane."""
    layout = _plugin_details_layout(dashboard)

    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()

    empty_label = QtWidgets.QLabel("Select a plugin to view details.")
    empty_label.setAlignment(QtCore.Qt.AlignCenter)
    empty_label.setProperty("uiRole", "emptyState")
    layout.addWidget(empty_label, 0, 0, 1, 2)


def _update_plugin_management_buttons(dashboard: QtCore.QObject):
    """Enable plugin controls according to selected plugin/node lifecycle state."""
    table = dashboard.ui.tableWidget_sn_plugins_inventory
    row = table.currentRow()

    dashboard.ui.pushButton_sn_plugins_inventory_deploy.setEnabled(False)
    dashboard.ui.pushButton_sn_plugins_inventory_remove.setEnabled(False)
    dashboard.ui.pushButton_sn_plugins_inventory_repair.setEnabled(False)

    if getattr(
        dashboard,
        "sensor_nodes_plugin_management_busy",
        False,
    ):
        return

    if row < 0:
        return

    item = table.item(
        row,
        0,
    )

    plugin_name = str(
        item.text()
        if item is not None
        else ""
    ).strip()

    entry = (
        getattr(
            dashboard,
            "sensor_nodes_plugin_inventory",
            {},
        )
        or {}
    ).get(
        plugin_name
    )

    if not isinstance(
        entry,
        dict,
    ):
        return

    node_present = bool(
        entry.get(
            "node_present"
        )
    )

    if (
        node_present
        and plugin_name.casefold() != "base"
    ):
        dashboard.ui.pushButton_sn_plugins_inventory_remove.setEnabled(
            True
        )

    repair_available = bool(
        node_present
        and entry.get(
            "node_setup_present"
        )
    )

    dashboard.ui.pushButton_sn_plugins_inventory_repair.setEnabled(
        repair_available
    )

    if not selected_node_is_remote(
        dashboard
    ):
        return

    if not selected_node_is_ip(
        dashboard
    ):
        return

    hub_present = bool(
        entry.get(
            "hub_present"
        )
    )

    hub_version = str(
        entry.get(
            "hub_version",
            "—",
        )
        or "—"
    )

    node_version = str(
        entry.get(
            "node_version",
            "—",
        )
        or "—"
    )

    deploy_available = bool(
        hub_present
        and (
            not node_present
            or hub_version != node_version
        )
    )

    dashboard.ui.pushButton_sn_plugins_inventory_deploy.setEnabled(
        deploy_available
    )


def _add_plugin_detail_row(layout, row: int, label: str, value: str):
    """Add one label/value row to the Plugin Details grid."""
    name_label = QtWidgets.QLabel(label)
    value_label = QtWidgets.QLabel(value or "—")

    name_font = name_label.font()
    name_font.setBold(True)
    name_label.setFont(name_font)

    name_label.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
    value_label.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
    value_label.setWordWrap(True)
    value_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)

    layout.addWidget(name_label, row, 0)
    layout.addWidget(value_label, row, 1)


def _populate_plugin_details(dashboard: QtCore.QObject, plugin_name: str):
    """Populate details for the selected union-inventory plugin."""
    entry = (getattr(dashboard, "sensor_nodes_plugin_inventory", {}) or {}).get(
        plugin_name
    )
    if not isinstance(entry, dict):
        _clear_plugin_details(dashboard)
        return

    layout = _plugin_details_layout(dashboard)
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()

    title = QtWidgets.QLabel(plugin_name)
    title_font = title.font()
    title_font.setBold(True)
    title_font.setPointSize(max(title_font.pointSize(), 9))
    title.setFont(title_font)
    title.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
    layout.addWidget(title, 0, 0, 1, 2)

    _add_plugin_detail_row(layout, 1, "Location:", entry.get("location", "—"))
    _add_plugin_detail_row(layout, 2, "Hub Version:", entry.get("hub_version", "—"))
    _add_plugin_detail_row(layout, 3, "Node Version:", entry.get("node_version", "—"))
    _add_plugin_detail_row(layout, 4, "Setup Status:", entry.get("setup_status", "—"))
    _add_plugin_detail_row(layout, 5, "State:", entry.get("state", "—"))
    _add_plugin_detail_row(
        layout,
        6,
        "Hub Manifest:",
        "Present" if entry.get("hub_manifest_present") else "Legacy / None",
    )
    _add_plugin_detail_row(
        layout,
        7,
        "Node Manifest:",
        "Present" if entry.get("node_manifest_present") else (
            "Legacy / None" if entry.get("node_present") else "—"
        ),
    )
    _add_plugin_detail_row(
        layout,
        8,
        "Setup Hook:",
        "Present" if entry.get("node_setup_present") else (
            "Not Required" if entry.get("node_present") else "—"
        ),
    )
    _add_plugin_detail_row(
        layout,
        9,
        "Cleanup:",
        (
            "Declared"
            if entry.get("node_cleanup_supported")
            else (
                "Not Declared"
                if entry.get("node_present")
                else "—"
            )
        ),
    )

    setup_message = str(
        entry.get("setup_message")
        or ""
    ).strip()

    if setup_message:
        _add_plugin_detail_row(
            layout,
            10,
            "Setup Check:",
            setup_message,
        )
        next_row = 11
    else:
        next_row = 10

    manifest_error = (
        entry.get("hub_manifest_error")
        or entry.get("node_manifest_error")
        or ""
    )
    if manifest_error:
        _add_plugin_detail_row(
            layout,
            next_row,
            "Manifest Error:",
            manifest_error,
        )
        description_row = next_row + 1
    else:
        description_row = next_row

    required_plugins = [
        str(required_plugin).strip()
        for required_plugin in (
            entry.get(
                "required_plugins",
                [],
            )
            or []
        )
        if str(required_plugin).strip()
    ]

    _add_plugin_detail_row(
        layout,
        description_row,
        "Required Plugins:",
        (
            ", ".join(required_plugins)
            if required_plugins
            else "None"
        ),
    )

    _add_plugin_detail_row(
        layout,
        description_row + 1,
        "Description:",
        entry.get("description") or "—",
    )


def _combine_plugin_inventory(hub_inventory: dict, node_inventory: dict) -> dict:
    """Build the Dashboard union view from independent Hub/Node inventories."""
    hub_inventory = hub_inventory if isinstance(hub_inventory, dict) else {}
    node_inventory = node_inventory if isinstance(node_inventory, dict) else {}

    combined = {}

    for plugin_name in sorted(
        set(hub_inventory.keys()) | set(node_inventory.keys()),
        key=str.casefold,
    ):
        hub_entry = hub_inventory.get(plugin_name) or {}
        node_entry = node_inventory.get(plugin_name) or {}

        hub_present = plugin_name in hub_inventory
        node_present = plugin_name in node_inventory

        hub_version_raw = str(hub_entry.get("version") or "").strip()
        node_version_raw = str(node_entry.get("version") or "").strip()
        hub_version = hub_version_raw or "—"
        node_version = node_version_raw or "—"

        if hub_present and node_present:
            location = "Both (Hub & Node)"
        elif hub_present:
            location = "Hub Only"
        else:
            location = "Node Only"

        node_setup_present = bool(node_entry.get("setup_present"))

        if not node_present:
            setup_status = "Not Deployed"
            setup_message = ""
        elif node_setup_present:
            setup_status = str(
                node_entry.get("setup_status")
                or "Setup Failed"
            )
            setup_message = str(
                node_entry.get("setup_message")
                or ""
            )
        else:
            setup_status = "Ready"
            setup_message = str(
                node_entry.get("setup_message")
                or "No external setup required."
            )

        if hub_present and not node_present:
            state = "Missing on Node"
        elif node_present and not hub_present:
            state = "Node Only"
        elif hub_version_raw != node_version_raw:
            state = "Update Available"
        elif setup_status == "Setup Required":
            state = "Setup Required"
        elif setup_status == "Setup Failed":
            state = "Setup Failed"
        else:
            state = "Up to Date"

        combined[plugin_name] = {
            "plugin": plugin_name,
            "hub_present": hub_present,
            "node_present": node_present,
            "hub_version": hub_version,
            "node_version": node_version,
            "setup_status": setup_status,
            "setup_message": setup_message,
            "setup_output": str(node_entry.get("setup_output") or ""),
            "setup_returncode": node_entry.get("setup_returncode"),
            "state": state,
            "location": location,
            "hub_manifest_present": bool(hub_entry.get("manifest_present")),
            "node_manifest_present": bool(node_entry.get("manifest_present")),
            "hub_manifest_error": str(hub_entry.get("manifest_error") or ""),
            "node_manifest_error": str(node_entry.get("manifest_error") or ""),
            "hub_setup_present": bool(hub_entry.get("setup_present")),
            "node_setup_present": node_setup_present,
            "hub_cleanup_supported": bool(
                hub_entry.get(
                    "cleanup_supported",
                    False,
                )
            ),
            "node_cleanup_supported": bool(
                node_entry.get(
                    "cleanup_supported",
                    False,
                )
            ),
            "hub_required_plugins": list(
                hub_entry.get(
                    "required_plugins",
                    [],
                )
                or []
            ),
            "node_required_plugins": list(
                node_entry.get(
                    "required_plugins",
                    [],
                )
                or []
            ),
            "required_plugins": list(
                (
                    hub_entry
                    if hub_present
                    else node_entry
                ).get(
                    "required_plugins",
                    [],
                )
                or []
            ),          
            "description": str(
                hub_entry.get("description")
                or node_entry.get("description")
                or ""
            ),
        }

    return combined


def _append_plugin_operation_log(dashboard: QtCore.QObject, message: str):
    """Append one local Dashboard-side plugin-management status line."""
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    dashboard.ui.plainTextEdit_sn_plugins_operation_log.appendPlainText(
        f"{timestamp}  {message}"
    )


def _set_plugin_operation_status(
    dashboard: QtCore.QObject,
    operation="—",
    status="Idle",
    progress=0,
):
    """Update the reserved plugin-management operation-status panel."""
    dashboard.ui.label2_sn_plugins_operation_status_current_operation.setText(
        str(operation or "—")
    )
    dashboard.ui.label2_sn_plugins_operation_status_status.setText(
        str(status or "Idle")
    )
    dashboard.ui.progressBar_sn_plugins_operation_status.setValue(
        max(0, min(int(progress), 100))
    )
    dashboard.ui.label2_sn_plugins_operation_status_last_update.setText(
        datetime.datetime.now().strftime("%H:%M:%S")
    )


def _clear_plugin_inventory(dashboard: QtCore.QObject):
    """Clear inventory/details when the selected Sensor Node changes."""
    dashboard.sensor_nodes_plugin_inventory = {}
    dashboard.ui.tableWidget_sn_plugins_inventory.setRowCount(0)
    dashboard.ui.plainTextEdit_sn_plugins_operation_log.clear()
    _clear_plugin_details(dashboard)
    _set_plugin_operation_status(
        dashboard,
        operation="—",
        status="Idle",
        progress=0,
    )

    dashboard.sensor_nodes_plugin_management_busy = False

    dashboard.ui.pushButton_sn_plugins_inventory_deploy.setEnabled(False)
    dashboard.ui.pushButton_sn_plugins_inventory_repair.setEnabled(False)
    dashboard.ui.pushButton_sn_plugins_inventory_remove.setEnabled(False)


def update_sensor_nodes_plugins_selected_node_gate(dashboard: QtCore.QObject):
    """Show plugin controls only for an online selected IP Sensor Node."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    node_state = (getattr(dashboard, "node_states", {}) or {}).get(node_uid, {}) or {}

    available = bool(node_uid) and selected_node_is_ip(dashboard)
    if available and isinstance(node_state, dict) and node_state.get("connected") is False:
        available = False

    dashboard.ui.stackedWidget_sn_plugins.setCurrentWidget(
        dashboard.ui.page_sn_plugins_controls
        if available
        else dashboard.ui.page_sn_plugins_no_node
    )

    if not available:
        if node_uid and not selected_node_is_ip(dashboard):
            dashboard.ui.label2_sn_plugins_no_node_selected.setText(
                "Plugin Management Unavailable"
            )
            dashboard.ui.label2_sn_plugins_select_a_node.setText(
                "Plugin management is currently supported for IP Sensor Nodes."
            )
        else:
            dashboard.ui.label2_sn_plugins_no_node_selected.setText(
                "Sensor Node Unavailable"
            )
            dashboard.ui.label2_sn_plugins_select_a_node.setText(
                "Select an online sensor node to configure plugins."
            )

        dashboard.sensor_nodes_plugins_last_node_uid = ""
        return

    if dashboard.sensor_nodes_plugins_last_node_uid != node_uid:
        dashboard.sensor_nodes_plugins_last_node_uid = node_uid
        _clear_plugin_inventory(dashboard)


def populate_plugin_inventory(
    dashboard: QtCore.QObject,
    node_uid="",
    hub_inventory=None,
    node_inventory=None,
    error="",
    record_refresh=True,
):
    """Populate the Hub/selected-node plugin inventory from one result."""
    selected_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if not _plugin_uid_matches(
        selected_uid,
        node_uid,
    ):
        return

    hub_inventory = hub_inventory or {}
    node_inventory = node_inventory or {}

    combined = _combine_plugin_inventory(
        hub_inventory,
        node_inventory,
    )
    dashboard.sensor_nodes_plugin_inventory = combined

    table = dashboard.ui.tableWidget_sn_plugins_inventory
    selected_name = ""
    current_row = table.currentRow()

    if current_row >= 0:
        current_item = table.item(
            current_row,
            0,
        )
        if current_item is not None:
            selected_name = str(
                current_item.text()
                or ""
            )

    table.blockSignals(True)
    table.setRowCount(len(combined))

    selected_row = -1

    for row, (plugin_name, entry) in enumerate(combined.items()):
        values = [
            plugin_name,
            entry.get("hub_version", "—"),
            entry.get("node_version", "—"),
            entry.get("setup_status", "—"),
            entry.get("state", "—"),
            entry.get("location", "—"),
        ]

        for column, value in enumerate(values):
            value_text = str(value)

            item = QtWidgets.QTableWidgetItem(
                value_text
            )

            if column in (1, 2, 3, 4, 5):
                item.setTextAlignment(
                    QtCore.Qt.AlignCenter
                )

            if column in (3, 4):
                status_color = _PLUGIN_STATUS_COLORS.get(
                    value_text
                )

                if status_color:
                    item.setForeground(
                        QtGui.QBrush(
                            QtGui.QColor(
                                status_color
                            )
                        )
                    )

            table.setItem(
                row,
                column,
                item,
            )

        if plugin_name == selected_name:
            selected_row = row

    table.blockSignals(False)
    table.resizeRowsToContents()

    if selected_row >= 0:
        table.selectRow(selected_row)
        _populate_plugin_details(
            dashboard,
            selected_name,
        )
    else:
        table.clearSelection()
        _clear_plugin_details(dashboard)

    _update_plugin_management_buttons(dashboard)

    if not record_refresh:
        return

    if error:
        _append_plugin_operation_log(
            dashboard,
            f"Refresh failed: {error}",
        )
        _set_plugin_operation_status(
            dashboard,
            operation="—",
            status="Idle",
            progress=0,
        )
        return

    _append_plugin_operation_log(
        dashboard,
        (
            f"Inventory refreshed: {len(hub_inventory)} Hub plugin"
            f"{'s' if len(hub_inventory) != 1 else ''}, "
            f"{len(node_inventory)} Node plugin"
            f"{'s' if len(node_inventory) != 1 else ''}."
        ),
    )
    _set_plugin_operation_status(
        dashboard,
        operation="—",
        status="Idle",
        progress=0,
    )


def handle_plugin_setup_result(
    dashboard: QtCore.QObject,
    node_uid="",
    plugin_name="",
    success=False,
    status="",
    message="",
    output="",
    hub_inventory=None,
    node_inventory=None,
):
    """Apply one Repair Setup result to the inventory and operation feedback."""
    selected_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if not _plugin_uid_matches(
        selected_uid,
        node_uid,
    ):
        return

    dashboard.sensor_nodes_plugin_management_busy = False

    dashboard.ui.pushButton_sn_plugins_refresh.setEnabled(
        True
    )

    if isinstance(hub_inventory, dict) and isinstance(node_inventory, dict):
        populate_plugin_inventory(
            dashboard,
            node_uid=node_uid,
            hub_inventory=hub_inventory,
            node_inventory=node_inventory,
            record_refresh=False,
        )

    plugin_name = str(
        plugin_name
        or ""
    ).strip()
    status = str(
        status
        or ""
    ).strip()
    message = str(
        message
        or ""
    ).strip()
    output = str(
        output
        or ""
    ).strip()

    if message:
        _append_plugin_operation_log(
            dashboard,
            f"{plugin_name}: {message}",
        )

    if output:
        for line in output.splitlines():
            line = line.rstrip()

            if line:
                _append_plugin_operation_log(
                    dashboard,
                    f"{plugin_name}> {line}",
                )

    if success:
        _append_plugin_operation_log(
            dashboard,
            f"{plugin_name}: Repair Setup completed.",
        )
    else:
        _append_plugin_operation_log(
            dashboard,
            f"{plugin_name}: Repair Setup failed ({status or 'Failed'}).",
        )

    _set_plugin_operation_status(
        dashboard,
        operation="—",
        status="Idle",
        progress=0,
    )

    _update_plugin_management_buttons(
        dashboard
    )


def handle_plugin_deploy_result(
    dashboard: QtCore.QObject,
    node_uid="",
    plugin_name="",
    transfer_id="",
    success=False,
    status="",
    message="",
    output="",
    hub_inventory=None,
    node_inventory=None,
):
    """Apply one Deploy/Update completion and refreshed inventory."""
    selected_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if not _plugin_uid_matches(
        selected_uid,
        node_uid,
    ):
        return

    dashboard.sensor_nodes_plugin_management_busy = False
    dashboard.ui.pushButton_sn_plugins_refresh.setEnabled(
        True
    )

    if (
        isinstance(
            hub_inventory,
            dict,
        )
        and isinstance(
            node_inventory,
            dict,
        )
    ):
        populate_plugin_inventory(
            dashboard,
            node_uid=node_uid,
            hub_inventory=hub_inventory,
            node_inventory=node_inventory,
            record_refresh=False,
        )

    plugin_name = str(
        plugin_name
        or ""
    ).strip()
    status = str(
        status
        or ""
    ).strip()
    message = str(
        message
        or ""
    ).strip()
    output = str(
        output
        or ""
    ).strip()

    if message:
        _append_plugin_operation_log(
            dashboard,
            f"{plugin_name}: {message}",
        )

    if output:
        for line in output.splitlines():
            line = line.rstrip()

            if line:
                _append_plugin_operation_log(
                    dashboard,
                    f"{plugin_name}> {line}",
                )

    if success:
        _append_plugin_operation_log(
            dashboard,
            f"{plugin_name}: Deploy / Update completed.",
        )
    else:
        _append_plugin_operation_log(
            dashboard,
            (
                f"{plugin_name}: Deploy / Update failed "
                f"({status or 'Failed'})."
            ),
        )

    _set_plugin_operation_status(
        dashboard,
        operation="—",
        status="Idle",
        progress=0,
    )

    _update_plugin_management_buttons(
        dashboard
    )


def handle_plugin_remove_result(
    dashboard: QtCore.QObject,
    node_uid="",
    plugin_name="",
    success=False,
    status="",
    message="",
    output="",
    hub_inventory=None,
    node_inventory=None,
):
    """Apply one managed Remove result and refreshed inventory."""
    selected_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if not _plugin_uid_matches(
        selected_uid,
        node_uid,
    ):
        return

    dashboard.sensor_nodes_plugin_management_busy = False

    dashboard.ui.pushButton_sn_plugins_refresh.setEnabled(
        True
    )

    if (
        isinstance(
            hub_inventory,
            dict,
        )
        and isinstance(
            node_inventory,
            dict,
        )
    ):
        populate_plugin_inventory(
            dashboard,
            node_uid=node_uid,
            hub_inventory=hub_inventory,
            node_inventory=node_inventory,
            record_refresh=False,
        )

    plugin_name = str(
        plugin_name
        or ""
    ).strip()

    status = str(
        status
        or ""
    ).strip()

    message = str(
        message
        or ""
    ).strip()

    output = str(
        output
        or ""
    ).strip()

    if message:
        _append_plugin_operation_log(
            dashboard,
            f"{plugin_name}: {message}",
        )

    if output:
        for line in output.splitlines():
            line = line.rstrip()

            if line:
                _append_plugin_operation_log(
                    dashboard,
                    f"{plugin_name}> {line}",
                )

    if success:
        _append_plugin_operation_log(
            dashboard,
            f"{plugin_name}: Remove completed.",
        )
    else:
        _append_plugin_operation_log(
            dashboard,
            (
                f"{plugin_name}: Remove failed "
                f"({status or 'Failed'})."
            ),
        )

    _set_plugin_operation_status(
        dashboard,
        operation="—",
        status="Idle",
        progress=0,
    )

    _update_plugin_management_buttons(
        dashboard
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesPluginsRefreshClicked(dashboard: QtCore.QObject):
    """Request one Hub/selected-node plugin inventory snapshot."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid or not selected_node_is_ip(dashboard):
        update_sensor_nodes_plugins_selected_node_gate(dashboard)
        return

    _append_plugin_operation_log(dashboard, "Requesting plugin inventory...")
    _set_plugin_operation_status(
        dashboard,
        operation="Inventory Refresh",
        status="Refreshing...",
        progress=0,
    )
    await dashboard.backend.refreshPluginInventory(node_uid)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesPluginInventorySelectionChanged(dashboard: QtCore.QObject):
    """Update Plugin Details and management buttons for the selected row."""
    table = dashboard.ui.tableWidget_sn_plugins_inventory
    row = table.currentRow()

    if row < 0:
        _clear_plugin_details(dashboard)
        _update_plugin_management_buttons(dashboard)
        return

    item = table.item(row, 0)
    plugin_name = str(
        item.text()
        if item is not None
        else ""
    ).strip()

    if not plugin_name:
        _clear_plugin_details(dashboard)
        _update_plugin_management_buttons(dashboard)
        return

    _populate_plugin_details(
        dashboard,
        plugin_name,
    )
    _update_plugin_management_buttons(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesPluginDeployClicked(
    dashboard: QtCore.QObject,
):
    """Deploy/update the selected Hub plugin to one remote IP Sensor Node."""
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if (
        not node_uid
        or not selected_node_is_ip(
            dashboard
        )
        or not selected_node_is_remote(
            dashboard
        )
    ):
        update_sensor_nodes_plugins_selected_node_gate(
            dashboard
        )
        return

    table = (
        dashboard.ui
        .tableWidget_sn_plugins_inventory
    )
    row = table.currentRow()

    if row < 0:
        return

    item = table.item(
        row,
        0,
    )
    plugin_name = str(
        item.text()
        if item is not None
        else ""
    ).strip()

    entry = (
        getattr(
            dashboard,
            "sensor_nodes_plugin_inventory",
            {},
        )
        or {}
    ).get(
        plugin_name
    )

    if (
        not plugin_name
        or not isinstance(
            entry,
            dict,
        )
        or not entry.get(
            "hub_present"
        )
    ):
        return

    node_present = bool(
        entry.get(
            "node_present"
        )
    )
    hub_version = str(
        entry.get(
            "hub_version",
            "—",
        )
        or "—"
    )
    node_version = str(
        entry.get(
            "node_version",
            "—",
        )
        or "—"
    )

    if (
        node_present
        and hub_version == node_version
    ):
        return

    dashboard.sensor_nodes_plugin_management_busy = True

    dashboard.ui.pushButton_sn_plugins_refresh.setEnabled(
        False
    )

    _update_plugin_management_buttons(
        dashboard
    )

    if node_present:
        operation_label = (
            f"Update: {plugin_name}"
        )
        log_message = (
            f"Starting plugin update for "
            f"{plugin_name} "
            f"({node_version} -> {hub_version})..."
        )
    else:
        operation_label = (
            f"Deploy: {plugin_name}"
        )
        log_message = (
            f"Starting plugin deployment for "
            f"{plugin_name} ({hub_version})..."
        )

    _append_plugin_operation_log(
        dashboard,
        log_message,
    )

    _set_plugin_operation_status(
        dashboard,
        operation=operation_label,
        status="Running",
        progress=10,
    )

    try:
        await dashboard.backend.deployPlugin(
            node_uid,
            plugin_name,
        )

    except Exception as exc:
        dashboard.sensor_nodes_plugin_management_busy = False
        dashboard.ui.pushButton_sn_plugins_refresh.setEnabled(
            True
        )

        _append_plugin_operation_log(
            dashboard,
            (
                f"{plugin_name}: Could not request "
                f"Deploy / Update: {exc}"
            ),
        )

        _set_plugin_operation_status(
            dashboard,
            operation="—",
            status="Idle",
            progress=0,
        )

        _update_plugin_management_buttons(
            dashboard
        )


async def _confirm_plugin_remove(
    dashboard: QtCore.QObject,
    plugin_name: str,
) -> bool:
    """Ask the operator to confirm destructive plugin removal."""
    message_box = QtWidgets.QMessageBox(dashboard)
    message_box.setIcon(QtWidgets.QMessageBox.Warning)
    message_box.setWindowTitle("Remove Plugin")
    message_box.setText(
        f"Remove the plugin '{plugin_name}' from the selected Sensor Node?"
    )
    message_box.setInformativeText(
        "This will delete the deployed plugin files from the node."
    )
    message_box.setStandardButtons(
        QtWidgets.QMessageBox.Yes
        | QtWidgets.QMessageBox.No
    )
    message_box.setDefaultButton(
        QtWidgets.QMessageBox.No
    )

    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def _finished(_result):
        if not future.done():
            future.set_result(
                message_box.standardButton(
                    message_box.clickedButton()
                )
            )

    message_box.finished.connect(_finished)
    message_box.open()

    result = await future
    message_box.deleteLater()

    return result == QtWidgets.QMessageBox.Yes


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesPluginRemoveClicked(
    dashboard: QtCore.QObject,
):
    """Remove the selected deployed plugin from the selected Sensor Node."""
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if not node_uid:
        update_sensor_nodes_plugins_selected_node_gate(
            dashboard
        )
        return

    table = (
        dashboard.ui
        .tableWidget_sn_plugins_inventory
    )

    row = table.currentRow()

    if row < 0:
        return

    item = table.item(
        row,
        0,
    )

    plugin_name = str(
        item.text()
        if item is not None
        else ""
    ).strip()

    entry = (
        getattr(
            dashboard,
            "sensor_nodes_plugin_inventory",
            {},
        )
        or {}
    ).get(
        plugin_name
    )

    if (
        not plugin_name
        or not isinstance(
            entry,
            dict,
        )
        or not entry.get(
            "node_present"
        )
        or plugin_name.casefold() == "base"
    ):
        return
    
    confirmed = await _confirm_plugin_remove(
        dashboard,
        plugin_name,
    )

    if not confirmed:
        return

    dashboard.sensor_nodes_plugin_management_busy = True

    dashboard.ui.pushButton_sn_plugins_refresh.setEnabled(
        False
    )

    _update_plugin_management_buttons(
        dashboard
    )

    _append_plugin_operation_log(
        dashboard,
        f"Starting plugin removal for {plugin_name}...",
    )

    _set_plugin_operation_status(
        dashboard,
        operation=f"Remove: {plugin_name}",
        status="Running",
        progress=10,
    )

    try:
        await dashboard.backend.removeManagedPlugin(
            node_uid,
            plugin_name,
        )

    except Exception as exc:
        dashboard.sensor_nodes_plugin_management_busy = False

        dashboard.ui.pushButton_sn_plugins_refresh.setEnabled(
            True
        )

        _append_plugin_operation_log(
            dashboard,
            (
                f"{plugin_name}: Could not request "
                f"Remove: {exc}"
            ),
        )

        _set_plugin_operation_status(
            dashboard,
            operation="—",
            status="Idle",
            progress=0,
        )

        _update_plugin_management_buttons(
            dashboard
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesPluginRepairClicked(
    dashboard: QtCore.QObject,
):
    """Run the selected deployed plugin's setup install/check lifecycle."""
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if not node_uid or not selected_node_is_ip(dashboard):
        update_sensor_nodes_plugins_selected_node_gate(
            dashboard
        )
        return

    table = dashboard.ui.tableWidget_sn_plugins_inventory
    row = table.currentRow()

    if row < 0:
        return

    item = table.item(
        row,
        0,
    )

    plugin_name = str(
        item.text()
        if item is not None
        else ""
    ).strip()

    entry = (
        getattr(
            dashboard,
            "sensor_nodes_plugin_inventory",
            {},
        )
        or {}
    ).get(
        plugin_name
    )

    if not plugin_name or not isinstance(entry, dict):
        return

    if (
        not entry.get(
            "node_present"
        )
        or not entry.get(
            "node_setup_present"
        )
    ):
        return

    dashboard.sensor_nodes_plugin_management_busy = True

    dashboard.ui.pushButton_sn_plugins_refresh.setEnabled(
        False
    )

    _update_plugin_management_buttons(
        dashboard
    )

    _append_plugin_operation_log(
        dashboard,
        f"Starting Repair Setup for {plugin_name}...",
    )

    _set_plugin_operation_status(
        dashboard,
        operation=f"Repair Setup: {plugin_name}",
        status="Running",
        progress=10,
    )

    try:
        await dashboard.backend.repairPluginSetup(
            node_uid,
            plugin_name,
        )

    except Exception as exc:
        dashboard.sensor_nodes_plugin_management_busy = False

        dashboard.ui.pushButton_sn_plugins_refresh.setEnabled(
            True
        )

        _append_plugin_operation_log(
            dashboard,
            (
                f"{plugin_name}: Could not request "
                f"Repair Setup: {exc}"
            ),
        )

        _set_plugin_operation_status(
            dashboard,
            operation="—",
            status="Idle",
            progress=0,
        )

        _update_plugin_management_buttons(
            dashboard
        )