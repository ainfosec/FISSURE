from PyQt5 import QtCore, QtWidgets
import fissure.utils
from fissure.Dashboard.UI_Components.Qt5 import DownloadMapPackDialog
import shutil
import pathlib
import datetime
import qasync
import subprocess
import os
import asyncio
import html


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalRefreshMapPacks(dashboard: QtCore.QObject):
    """ 
    Refreshes the combobox of map pack names from the map data folder.
    """
    combo = dashboard.ui.comboBox_tactical_map_pack

    # Preserve current selection
    current_map = combo.currentText()

    combo.blockSignals(True)
    combo.clear()

    map_names = dashboard.tactical_map.refresh_available_maps()
    combo.addItems(map_names)

    # Restore selection if possible
    if current_map in map_names:
        combo.setCurrentText(current_map)
    elif map_names:
        combo.setCurrentIndex(0)

    combo.blockSignals(False)

    if combo.currentText():
        try:
            dashboard.tactical_map.load_map(str(combo.currentText()), preferred_zoom=None, fit=False)
        except Exception as e:
            dashboard.logger.error(f"[Tactical] Failed to load map pack '{combo.currentText()}': {e}")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalMapPackChanged(dashboard: QtCore.QObject):
    """
    Loads the selected map pack into the Tactical map.
    Clears the map view if no map pack is selected.
    """
    combo = dashboard.ui.comboBox_tactical_map_pack
    map_name = combo.currentText()

    if not map_name:
        dashboard.tactical_map.scene.clear()
        dashboard.tactical_map.scene.setSceneRect(0, 0, 0, 0)
        dashboard.logger.info("[Tactical] No map pack selected. Cleared tactical map.")
        return

    try:
        dashboard.tactical_map.load_map(map_name, preferred_zoom=None, fit=False)
        dashboard.logger.info(f"[Tactical] Loaded map pack: {map_name}")
    except Exception as e:
        dashboard.logger.error(f"[Tactical] Failed to load map pack '{map_name}': {e}")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalDownloadMapPack(dashboard: QtCore.QObject):
    """
    Opens the Download Map Pack dialog.
    """
    # Load the Dialog
    download_map_pack_dlg = DownloadMapPackDialog(parent=dashboard)
    download_map_pack_dlg.show()
    # download_map_pack_dlg.exec_()

    if download_map_pack_dlg.exec_() == QtWidgets.QDialog.Accepted:
        _slotTacticalRefreshMapPacks(dashboard)
        dashboard.ui.comboBox_tactical_map_pack.setCurrentText(download_map_pack_dlg.map_pack_name)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalDeleteMapPack(dashboard: QtCore.QObject):
    """
    Deletes the selected map pack folder from FISSURE/map_data.
    """
    combo = dashboard.ui.comboBox_tactical_map_pack
    map_name = combo.currentText()

    if not map_name:
        QtWidgets.QMessageBox.warning(
            dashboard,
            "No Map Pack Selected",
            "Select a map pack to delete."
        )
        return

    map_pack_dir = pathlib.Path(fissure.utils.FISSURE_ROOT) / "map_data" / map_name

    answer = QtWidgets.QMessageBox.question(
        dashboard,
        "Delete Map Pack",
        f"Delete map pack '{map_name}'?\n\nThis cannot be undone.",
        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        QtWidgets.QMessageBox.No,
    )

    if answer != QtWidgets.QMessageBox.Yes:
        return

    try:
        shutil.rmtree(map_pack_dir)
        dashboard.logger.info(f"[Tactical] Deleted map pack: {map_name}")
    except Exception as e:
        QtWidgets.QMessageBox.critical(
            dashboard,
            "Delete Failed",
            f"Failed to delete map pack:\n{e}"
        )
        return

    # Refresh (this will trigger load via combobox signal)
    _slotTacticalRefreshMapPacks(dashboard)

    # If nothing remains, manually clear
    if combo.count() == 0:
        dashboard.tactical_map.scene.clear()
        dashboard.tactical_map.scene.setSceneRect(0, 0, 0, 0)
        dashboard.logger.info("[Tactical] No map packs remain. Cleared tactical map.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeMapClicked(dashboard: QtCore.QObject, node_uid):
    populate_tactical_node_details(dashboard, node_uid)
    dashboard.ui.tabWidget_tactical.setCurrentIndex(0)
    

def populate_tactical_node_details(dashboard: QtCore.QObject, node_uid):
    node = dashboard.tactical_nodes.get(node_uid)
    if not node:
        dashboard.logger.warning(f"No tactical node record found for UID: {node_uid}")
        return

    previous_uid = getattr(dashboard, "selected_tactical_node_uid", None)
    same_node = previous_uid == node_uid

    dashboard.selected_tactical_node_uid = node_uid

    dashboard.ui.label2_tactical_node_callsign.setText(node.get("callsign", ""))
    dashboard.ui.label2_tactical_node_uuid.setText(node.get("uid", ""))
    dashboard.ui.label2_node_tactical_status.setText(node.get("status", ""))

    dashboard.ui.frame5_tactical2.setEnabled(True)

    if not same_node:
        clear_tactical_node_targets(dashboard)
        rebuild_tactical_node_detections(dashboard, node_uid)
        rebuild_tactical_node_sois(dashboard, node_uid)
        rebuild_tactical_node_artifacts(dashboard, node_uid)

    restore_tactical_node_capabilities(
        dashboard,
        node,
        preserve_current_selection=same_node,
    )

    update_tactical_node_stop_button_state(dashboard, node)

    _updateTacticalNodeInfoFrameState(dashboard)


def update_tactical_node_stop_button_state(dashboard: QtCore.QObject, node: dict):
    status = (node.get("status") or "").strip().lower()

    stop_enabled = status not in [
        "",
        "idle",
        "stopped",
        "unknown",
    ]

    dashboard.ui.pushButton_tactical_node_stop.setEnabled(stop_enabled)


def restore_tactical_node_capabilities(
    dashboard: QtCore.QObject,
    node: dict,
    preserve_current_selection=False,
):
        plugins = node.get("plugins", [])
        actions_by_plugin = node.get("actions", {})

        if plugins:
            update_tactical_node_plugin_combo(
                dashboard,
                plugins,
                preserve_current_selection=preserve_current_selection,
            )
            dashboard.ui.comboBox_tactical_node_plugins.setEnabled(True)
            dashboard.ui.pushButton_tactical_node_select.setEnabled(True)
        else:
            clear_tactical_node_plugin_controls(dashboard)
            return

        selected_plugin = dashboard.ui.comboBox_tactical_node_plugins.currentText().strip()
        action_names = actions_by_plugin.get(selected_plugin, [])

        if action_names:
            update_tactical_node_action_combo(
                dashboard,
                action_names,
                preserve_current_selection=preserve_current_selection,
            )
            dashboard.ui.comboBox_tactical_node_actions.setEnabled(True)
            dashboard.ui.pushButton_tactical_node_customize.setEnabled(True)
        else:
            clear_tactical_node_action_controls(dashboard)


def clear_tactical_node_plugin_controls(dashboard: QtCore.QObject):
    dashboard.ui.comboBox_tactical_node_plugins.blockSignals(True)
    dashboard.ui.comboBox_tactical_node_plugins.clear()
    dashboard.ui.comboBox_tactical_node_plugins.blockSignals(False)

    dashboard.ui.comboBox_tactical_node_plugins.setEnabled(False)
    dashboard.ui.pushButton_tactical_node_select.setEnabled(False)

    clear_tactical_node_action_controls(dashboard)


def clear_tactical_node_action_controls(dashboard: QtCore.QObject):
    dashboard.ui.comboBox_tactical_node_actions.blockSignals(True)
    dashboard.ui.comboBox_tactical_node_actions.clear()
    dashboard.ui.comboBox_tactical_node_actions.blockSignals(False)

    dashboard.ui.comboBox_tactical_node_actions.setEnabled(False)
    dashboard.ui.pushButton_tactical_node_customize.setEnabled(False)
    dashboard.ui.pushButton_tactical_node_execute.setEnabled(False)
    dashboard.ui.pushButton_tactical_node_stop.setEnabled(False)

    clear_tactical_node_action_parameters(dashboard)


def clear_tactical_node_action_parameters(dashboard: QtCore.QObject):
    scroll_area = dashboard.ui.scrollArea_tactical_node_action_parameters
    content_widget = scroll_area.widget()

    if content_widget is not None and content_widget.layout() is not None:
        layout = content_widget.layout()

        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()

            if widget:
                widget.deleteLater()

    dashboard.tactical_action_parameter_widgets = {}


def clear_tactical_ecosystem_plugin_controls(dashboard: QtCore.QObject):
    dashboard.ui.comboBox_tactical_ecosystem_plugins.blockSignals(True)
    dashboard.ui.comboBox_tactical_ecosystem_plugins.clear()
    dashboard.ui.comboBox_tactical_ecosystem_plugins.blockSignals(False)

    dashboard.ui.comboBox_tactical_ecosystem_plugins.setEnabled(False)
    dashboard.ui.pushButton_tactical_ecosystem_select.setEnabled(False)

    clear_tactical_ecosystem_action_controls(dashboard)


def clear_tactical_ecosystem_action_controls(dashboard: QtCore.QObject):
    dashboard.ui.comboBox_tactical_ecosystem_actions.blockSignals(True)
    dashboard.ui.comboBox_tactical_ecosystem_actions.clear()
    dashboard.ui.comboBox_tactical_ecosystem_actions.blockSignals(False)

    dashboard.ui.comboBox_tactical_ecosystem_actions.setEnabled(False)
    dashboard.ui.pushButton_tactical_ecosystem_customize.setEnabled(False)
    dashboard.ui.pushButton_tactical_ecosystem_execute.setEnabled(False)

    clear_tactical_ecosystem_action_parameters(dashboard)


def clear_tactical_ecosystem_action_parameters(dashboard: QtCore.QObject):
    scroll_area = dashboard.ui.scrollArea_tactical_ecosystem_action_parameters
    content_widget = scroll_area.widget()

    if content_widget is not None and content_widget.layout() is not None:
        layout = content_widget.layout()

        while layout.count():
            item = layout.takeAt(0)
            widget = item.widget()

            if widget:
                widget.deleteLater()

    dashboard.tactical_ecosystem_action_parameter_widgets = {}


def update_tactical_node_roster_row(dashboard: QtCore.QObject, node_record):
    table = dashboard.ui.tableWidget_tactical_ecosystem

    uid = node_record.get("uid")
    if not uid:
        return

    values = [
        node_record.get("callsign", ""),
        node_record.get("status", ""),
        node_record.get("version", ""),
        format_tactical_time(node_record.get("time", "")),      # Last Seen
    ]

    existing_row = None

    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item and item.data(QtCore.Qt.UserRole) == uid:
            existing_row = row
            break

    if existing_row is None:
        existing_row = table.rowCount()
        table.insertRow(existing_row)

    for col, value in enumerate(values):
        item = table.item(existing_row, col)

        if item is None:
            item = QtWidgets.QTableWidgetItem()
            table.setItem(existing_row, col, item)

        item.setText(str(value))

        # Store UID on every cell so clicking any column can recover it
        item.setData(QtCore.Qt.UserRole, uid)

    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setStretchLastSection(True)

    selected_uid = getattr(dashboard, "selected_tactical_node_uid", None)

    if selected_uid == uid:
        dashboard.ui.label2_node_tactical_status.setText(
            node_record.get("status", "")
        )

        update_tactical_node_stop_button_state(
            dashboard,
            node_record,
        )


def format_tactical_time(timestamp):
    if not timestamp:
        return ""

    try:
        # Example:
        # 2026-05-07T16:06:16.832397Z

        dt = datetime.datetime.fromisoformat(
            timestamp.replace("Z", "+00:00")
        )

        return dt.strftime("%H:%M:%S")

    except Exception:
        return str(timestamp)


def format_detection_time(timestamp):
    if not timestamp:
        return ""

    try:
        ts = float(timestamp)
        dt = datetime.datetime.fromtimestamp(ts)
        return dt.strftime("%H:%M:%S")
    except Exception:
        pass

    return format_tactical_time(timestamp)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemSelectAllNodesClicked(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_ecosystem

    table.selectAll()

    update_selected_tactical_nodes(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemClearSelectionClicked(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_ecosystem

    table.clearSelection()

    update_selected_tactical_nodes(dashboard)


def update_selected_tactical_nodes(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_ecosystem

    selected_uids = []

    for item in table.selectedItems():
        uid = item.data(QtCore.Qt.UserRole)

        if uid and uid not in selected_uids:
            selected_uids.append(uid)

    dashboard.selected_tactical_node_uids = selected_uids

    selected_count = len(selected_uids)

    ref_node = ""
    if selected_uids:
        first_uid = selected_uids[0]

        node = dashboard.tactical_nodes.get(first_uid, {})
        ref_node = node.get("callsign", first_uid)

    dashboard.ui.label2_tactical_ecosystem_selected_nodes.setText(str(selected_count))
    dashboard.ui.label2_tactical_ecosystem_reference_node.setText(str(ref_node))

    dashboard.ui.frame5_tactical_ecosystem2.setEnabled(True)
    dashboard.ui.label2_tactical_ecosystem_selected_nodes.setEnabled(True)
    dashboard.ui.label2_tactical_ecosystem_selected_nodes2.setEnabled(True)
    dashboard.ui.label2_tactical_ecosystem_reference_node.setEnabled(True)
    dashboard.ui.label2_tactical_ecosystem_reference_node2.setEnabled(True)
    dashboard.ui.label2_tactical_ecosystem_plugin.setEnabled(True)
    dashboard.ui.pushButton_tactical_ecosystem_query.setEnabled(True)
    dashboard.ui.pushButton_tactical_ecosystem_stop.setEnabled(True)

    
@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemNodeRosterDoubleClicked(dashboard, item):
    """
    Selects and zooms to the double-clicked node in the Ecosystem node roster table.
    """
    row = item.row()
    uid_item = dashboard.ui.tableWidget_tactical_ecosystem.item(row, 0)
    if uid_item is None:
        return

    uid = uid_item.data(QtCore.Qt.UserRole)
    if not uid:
        return

    dashboard.selected_tactical_node_uid = uid

    populate_tactical_node_details(dashboard, uid)

    dashboard.ui.tabWidget_tactical.setCurrentIndex(0)

    if hasattr(dashboard, "tactical_map"):
        dashboard.tactical_map.center_on_node(uid)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemPanToNodeClicked(
    dashboard: QtCore.QObject,
):
    """
    Opens the current Node Roster row in the Node tab and centers the map.
    """
    table = dashboard.ui.tableWidget_tactical_ecosystem

    row = table.currentRow()
    if row < 0:
        return

    item = table.item(row, 0)
    if item is None:
        return

    uid = item.data(QtCore.Qt.UserRole)
    if not uid:
        return

    dashboard.selected_tactical_node_uid = uid

    populate_tactical_node_details(
        dashboard,
        uid,
    )

    dashboard.ui.tabWidget_tactical.setCurrentIndex(0)

    if hasattr(dashboard, "tactical_map"):
        dashboard.tactical_map.center_on_node(uid)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeQueryClicked(dashboard):
    """
    Queries the node for its list of plugins.
    """
    uid = dashboard.ui.label2_tactical_node_uuid.text().strip()

    if not uid:
        dashboard.logger.warning(
            "[Tactical] No node UID selected for plugin query."
        )
        return

    clear_tactical_node_plugin_controls(dashboard)

    await dashboard.backend.tacticalNodeQuery(uid, tak_context="node",)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalEcosystemQueryClicked(dashboard):
    """
    Queries the selected reference node for its list of plugins.
    """
    table = dashboard.ui.tableWidget_tactical_ecosystem

    selected_rows = sorted(
        set(index.row() for index in table.selectedIndexes())
    )

    if not selected_rows:
        dashboard.logger.warning(
            "[Tactical] No ecosystem reference node selected for plugin query."
        )
        return

    ref_row = selected_rows[0]
    item = table.item(ref_row, 0)

    if item is None:
        dashboard.logger.warning(
            "[Tactical] Selected ecosystem row does not contain a node UID."
        )
        return

    uid = item.data(QtCore.Qt.UserRole)

    if not uid:
        dashboard.logger.warning(
            "[Tactical] Selected ecosystem row does not contain a valid node UID."
        )
        return

    clear_tactical_ecosystem_plugin_controls(dashboard)

    await dashboard.backend.tacticalNodeQuery(
        uid,
        tak_context="ecosystem",
    )


def update_tactical_ecosystem_action_combo(
    dashboard: QtCore.QObject,
    action_names,
):
    combo = dashboard.ui.comboBox_tactical_ecosystem_actions

    current_text = combo.currentText()

    combo.blockSignals(True)
    combo.clear()
    combo.addItems(action_names)

    if current_text in action_names:
        combo.setCurrentText(current_text)

    combo.blockSignals(False)

    has_actions = bool(action_names)

    combo.setEnabled(has_actions)
    dashboard.ui.pushButton_tactical_ecosystem_customize.setEnabled(has_actions)
    dashboard.ui.label2_tactical_ecosystem_action.setEnabled(has_actions)
    dashboard.ui.pushButton_tactical_ecosystem_execute.setEnabled(has_actions)

def update_tactical_node_plugin_combo(    
    dashboard: QtCore.QObject,
    plugin_names,
    preserve_current_selection=False,
):
    combo = dashboard.ui.comboBox_tactical_node_plugins

    current_text = combo.currentText().strip()

    combo.blockSignals(True)
    combo.clear()
    combo.addItems(plugin_names)

    if preserve_current_selection and current_text in plugin_names:
        combo.setCurrentText(current_text)

    combo.blockSignals(False)

    has_plugins = bool(plugin_names)

    combo.setEnabled(has_plugins)
    dashboard.ui.pushButton_tactical_node_select.setEnabled(has_plugins)


def update_tactical_ecosystem_plugin_combo(
    dashboard: QtCore.QObject,
    plugin_names,
):
    combo = dashboard.ui.comboBox_tactical_ecosystem_plugins

    current_text = combo.currentText()

    combo.blockSignals(True)
    combo.clear()
    combo.addItems(plugin_names)

    if current_text in plugin_names:
        combo.setCurrentText(current_text)

    combo.blockSignals(False)

    has_plugins = bool(plugin_names)

    combo.setEnabled(has_plugins)

    dashboard.ui.pushButton_tactical_ecosystem_select.setEnabled(
        has_plugins
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeSelectClicked(dashboard):
    """
    Queries the node for its list of plugin actions.
    """
    uid = dashboard.ui.label2_tactical_node_uuid.text().strip()

    plugin_name = str(
        dashboard.ui.comboBox_tactical_node_plugins.currentText()
    ).strip()

    if not uid:
        dashboard.logger.warning(
            "[Tactical] No node UID selected for plugin action query."
        )
        return

    if not plugin_name:
        dashboard.logger.warning(
            "[Tactical] No plugin selected for plugin action query."
        )
        return

    await dashboard.backend.tacticalNodeSelect(
        uid,
        plugin_name,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalEcosystemSelectClicked(dashboard):
    """
    Queries the selected ecosystem reference node for its list of plugin actions.
    """
    table = dashboard.ui.tableWidget_tactical_ecosystem

    selected_rows = sorted(
        set(index.row() for index in table.selectedIndexes())
    )

    if not selected_rows:
        dashboard.logger.warning(
            "[Tactical] No ecosystem reference node selected for plugin action query."
        )
        return

    ref_row = selected_rows[0]
    item = table.item(ref_row, 0)

    if item is None:
        dashboard.logger.warning(
            "[Tactical] Selected ecosystem row does not contain a node UID."
        )
        return

    uid = item.data(QtCore.Qt.UserRole)

    if not uid:
        dashboard.logger.warning(
            "[Tactical] Selected ecosystem row does not contain a valid node UID."
        )
        return

    plugin_name = str(
        dashboard.ui.comboBox_tactical_ecosystem_plugins.currentText()
    ).strip()

    if not plugin_name:
        dashboard.logger.warning(
            "[Tactical] No ecosystem plugin selected for plugin action query."
        )
        return

    clear_tactical_ecosystem_action_controls(dashboard)

    await dashboard.backend.tacticalNodeSelect(
        uid,
        plugin_name,
        tak_context="ecosystem",
    )


def update_tactical_node_action_combo(
    dashboard: QtCore.QObject,
    action_names,
    preserve_current_selection=False,
):
    combo = dashboard.ui.comboBox_tactical_node_actions

    current_text = combo.currentText().strip()

    combo.blockSignals(True)
    combo.clear()
    combo.addItems(action_names)

    if preserve_current_selection and current_text in action_names:
        combo.setCurrentText(current_text)

    combo.blockSignals(False)

    has_actions = bool(action_names)

    combo.setEnabled(has_actions)
    dashboard.ui.pushButton_tactical_node_customize.setEnabled(has_actions)
    dashboard.ui.pushButton_tactical_node_execute.setEnabled(has_actions)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeCustomizeClicked(dashboard):
    """
    Queries the node for its plugin action default input parameters.
    """
    uid = dashboard.ui.label2_tactical_node_uuid.text().strip()

    plugin_name = str(
        dashboard.ui.comboBox_tactical_node_plugins.currentText()
    ).strip()

    action_name = str(
        dashboard.ui.comboBox_tactical_node_actions.currentText()
    ).strip()

    if not uid:
        dashboard.logger.warning(
            "[Tactical] No node UID selected for customize request."
        )
        return

    if not plugin_name:
        dashboard.logger.warning(
            "[Tactical] No plugin selected for customize request."
        )
        return

    if not action_name:
        dashboard.logger.warning(
            "[Tactical] No action selected for customize request."
        )
        return

    await dashboard.backend.tacticalNodeCustomize(
        uid,
        plugin_name,
        action_name,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalEcosystemCustomizeClicked(dashboard):
    """
    Queries the selected ecosystem reference node for plugin action default input parameters.
    """
    table = dashboard.ui.tableWidget_tactical_ecosystem

    selected_rows = sorted(
        set(index.row() for index in table.selectedIndexes())
    )

    if not selected_rows:
        dashboard.logger.warning(
            "[Tactical] No ecosystem reference node selected for customize request."
        )
        return

    ref_row = selected_rows[0]
    item = table.item(ref_row, 0)

    if item is None:
        dashboard.logger.warning(
            "[Tactical] Selected ecosystem row does not contain a node UID."
        )
        return

    uid = item.data(QtCore.Qt.UserRole)

    if not uid:
        dashboard.logger.warning(
            "[Tactical] Selected ecosystem row does not contain a valid node UID."
        )
        return

    plugin_name = str(
        dashboard.ui.comboBox_tactical_ecosystem_plugins.currentText()
    ).strip()

    action_name = str(
        dashboard.ui.comboBox_tactical_ecosystem_actions.currentText()
    ).strip()

    if not plugin_name:
        dashboard.logger.warning(
            "[Tactical] No ecosystem plugin selected for customize request."
        )
        return

    if not action_name:
        dashboard.logger.warning(
            "[Tactical] No ecosystem action selected for customize request."
        )
        return

    clear_tactical_ecosystem_action_parameters(dashboard)

    await dashboard.backend.tacticalNodeCustomize(
        uid,
        plugin_name,
        action_name,
        tak_context="ecosystem",
    )


def make_tactical_parameter_widget_compact(widget):
    """
    Applies compact sizing to generated Tactical action parameter widgets.
    """
    font = widget.font()
    font.setPointSize(max(font.pointSize() - 1, 8))
    widget.setFont(font)

    widget.setMinimumHeight(20)
    widget.setMaximumHeight(24)

    size_policy = widget.sizePolicy()
    size_policy.setVerticalPolicy(QtWidgets.QSizePolicy.Fixed)
    widget.setSizePolicy(size_policy)

    if isinstance(widget, QtWidgets.QAbstractSpinBox):
        widget.setButtonSymbols(QtWidgets.QAbstractSpinBox.UpDownArrows)


def update_tactical_node_action_parameters(
    dashboard,
    plugin_name,
    action_name,
    parameters,
):
    scroll_area = dashboard.ui.scrollArea_tactical_node_action_parameters

    content_widget = scroll_area.widget()

    if content_widget is None:
        content_widget = QtWidgets.QWidget()
        scroll_area.setWidget(content_widget)
        scroll_area.setWidgetResizable(True)

    layout = content_widget.layout()

    if layout is None:
        layout = QtWidgets.QVBoxLayout(content_widget)

    layout.setContentsMargins(4, 2, 4, 2)
    layout.setSpacing(2)

    while layout.count():
        item = layout.takeAt(0)

        widget = item.widget()
        if widget:
            widget.deleteLater()

    dashboard.tactical_action_parameter_widgets = {}

    description_text = ""

    for param in parameters:
        param_name = param.get("name", "")

        if param_name == "description":
            description_text = str(param.get("default", ""))
            continue

    if description_text:
        description_label = QtWidgets.QLabel(description_text)
        description_label.setProperty(
            "uiRole",
            "parameterLabel",
        )
        description_label.setWordWrap(True)
        description_label.setMinimumHeight(18)
        description_label.setMaximumHeight(36)

        description_font = description_label.font()
        description_font.setPointSize(max(description_font.pointSize() - 1, 8))
        description_font.setItalic(True)
        description_label.setFont(description_font)

        layout.addWidget(description_label)

    for param in parameters:
        param_name = param.get("name", "")

        if not param_name:
            continue

        if param_name == "description":
            continue

        row_widget = QtWidgets.QWidget()
        row_widget.setMinimumHeight(20)
        row_widget.setMaximumHeight(26)

        row_layout = QtWidgets.QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 2, 0)
        row_layout.setSpacing(3)

        label_text = param.get("label") or param_name

        label = QtWidgets.QLabel(label_text)
        label.setProperty(
            "uiRole",
            "parameterLabel",
        )
        label.setFixedWidth(125)
        label.setMinimumHeight(20)
        label.setMaximumHeight(24)
        label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        label.setToolTip(label_text)

        label_font = label.font()
        label_font.setPointSize(max(label_font.pointSize() - 1, 8))
        label.setFont(label_font)

        row_layout.addWidget(label)
        row_layout.setStretch(0, 0)

        param_type = param.get("type", "string")
        default = str(param.get("default", ""))
        options = param.get("options", param.get("option", []))

        if options:
            widget = QtWidgets.QComboBox()

            option_strings = [str(option) for option in options]
            widget.addItems(option_strings)

            if default in option_strings:
                widget.setCurrentText(default)

        elif param_type == "number":
            widget = QtWidgets.QDoubleSpinBox()

            decimals = int(param.get("decimals", 3))
            minimum = float(param.get("min", -999999999.0))
            maximum = float(param.get("max", 999999999.0))
            step = float(param.get("step", 1.0))

            widget.setDecimals(decimals)
            widget.setRange(minimum, maximum)
            widget.setSingleStep(step)

            try:
                widget.setValue(float(default))
            except Exception:
                pass

        elif param_type == "integer":
            widget = QtWidgets.QSpinBox()

            minimum = int(param.get("min", -999999999))
            maximum = int(param.get("max", 999999999))
            step = int(param.get("step", 1))

            widget.setRange(minimum, maximum)
            widget.setSingleStep(step)

            try:
                widget.setValue(int(float(default)))
            except Exception:
                pass

        else:
            widget = QtWidgets.QLineEdit(default)

        widget.setObjectName(f"tactical_param_{param_name}")
        widget.setToolTip(param.get("description", ""))

        make_tactical_parameter_widget_compact(widget)

        row_layout.addWidget(widget, 1)

        layout.addWidget(row_widget)

        dashboard.tactical_action_parameter_widgets[param_name] = widget

    layout.addStretch()

    apply_pending_tactical_customize_defaults(dashboard)

    content_widget.adjustSize()
    scroll_area.update()


def apply_pending_tactical_customize_defaults(dashboard: QtCore.QObject):
    pending = getattr(
        dashboard,
        "pending_tactical_customize_defaults",
        None,
    )

    if not pending:
        return

    action_name = str(
        dashboard.ui.comboBox_tactical_node_actions.currentText()
    ).strip()

    if pending.get("action_name") != action_name:
        return

    values = pending.get("values", {})

    for param_name, value in values.items():
        widget = dashboard.tactical_action_parameter_widgets.get(param_name)

        if widget is None:
            continue

        if isinstance(widget, QtWidgets.QDoubleSpinBox):
            try:
                widget.setValue(float(value))
            except Exception:
                pass

        elif isinstance(widget, QtWidgets.QSpinBox):
            try:
                widget.setValue(int(float(value)))
            except Exception:
                pass

        elif isinstance(widget, QtWidgets.QComboBox):
            index = widget.findText(str(value))
            if index >= 0:
                widget.setCurrentIndex(index)

        elif isinstance(widget, QtWidgets.QLineEdit):
            widget.setText(str(value))

    dashboard.pending_tactical_customize_defaults = None


def update_tactical_ecosystem_action_parameters(
    dashboard,
    plugin_name,
    action_name,
    parameters,
):
    scroll_area = (
        dashboard.ui.scrollArea_tactical_ecosystem_action_parameters
    )

    scroll_area.setProperty(
        "uiRole",
        "parameterPanel",
    )

    content_widget = scroll_area.widget()

    if content_widget is None:
        content_widget = QtWidgets.QWidget()
        scroll_area.setWidget(content_widget)
        scroll_area.setWidgetResizable(True)

    content_widget.setProperty(
        "uiRole",
        "parameterPanel",
    )

    layout = content_widget.layout()

    if layout is None:
        layout = QtWidgets.QVBoxLayout(content_widget)

    layout.setContentsMargins(4, 2, 4, 2)
    layout.setSpacing(2)

    while layout.count():
        item = layout.takeAt(0)

        widget = item.widget()

        if widget:
            widget.deleteLater()

    dashboard.tactical_ecosystem_action_parameter_widgets = {}

    description_text = ""

    for param in parameters:
        param_name = param.get("name", "")

        if param_name == "description":
            description_text = str(
                param.get(
                    "default",
                    "",
                )
            )
            continue

    if description_text:
        description_label = QtWidgets.QLabel(
            description_text
        )

        description_label.setProperty(
            "uiRole",
            "parameterLabel",
        )

        description_label.setWordWrap(True)
        description_label.setMinimumHeight(18)
        description_label.setMaximumHeight(36)

        description_font = description_label.font()
        description_font.setPointSize(
            max(
                description_font.pointSize() - 1,
                8,
            )
        )
        description_font.setItalic(True)
        description_label.setFont(
            description_font
        )

        layout.addWidget(
            description_label
        )

    for param in parameters:
        param_name = param.get(
            "name",
            "",
        )

        if not param_name:
            continue

        if param_name == "description":
            continue

        row_widget = QtWidgets.QWidget()
        row_widget.setMinimumHeight(20)
        row_widget.setMaximumHeight(26)

        row_layout = QtWidgets.QHBoxLayout(
            row_widget
        )

        row_layout.setContentsMargins(
            0,
            0,
            2,
            0,
        )

        row_layout.setSpacing(3)

        label_text = (
            param.get("label")
            or param_name
        )

        label = QtWidgets.QLabel(
            label_text
        )

        label.setProperty(
            "uiRole",
            "parameterLabel",
        )

        label.setFixedWidth(125)
        label.setMinimumHeight(20)
        label.setMaximumHeight(24)

        label.setAlignment(
            QtCore.Qt.AlignRight
            | QtCore.Qt.AlignVCenter
        )

        label.setToolTip(
            label_text
        )

        label_font = label.font()

        label_font.setPointSize(
            max(
                label_font.pointSize() - 1,
                8,
            )
        )

        label.setFont(
            label_font
        )

        row_layout.addWidget(
            label
        )

        row_layout.setStretch(
            0,
            0,
        )

        param_type = param.get(
            "type",
            "string",
        )

        default = str(
            param.get(
                "default",
                "",
            )
        )

        options = param.get(
            "options",
            param.get(
                "option",
                [],
            ),
        )

        if options:
            widget = QtWidgets.QComboBox()

            option_strings = [
                str(option)
                for option in options
            ]

            widget.addItems(
                option_strings
            )

            if default in option_strings:
                widget.setCurrentText(
                    default
                )

        elif param_type == "number":
            widget = QtWidgets.QDoubleSpinBox()

            decimals = int(
                param.get(
                    "decimals",
                    3,
                )
            )

            minimum = float(
                param.get(
                    "min",
                    -999999999.0,
                )
            )

            maximum = float(
                param.get(
                    "max",
                    999999999.0,
                )
            )

            step = float(
                param.get(
                    "step",
                    1.0,
                )
            )

            widget.setDecimals(
                decimals
            )

            widget.setRange(
                minimum,
                maximum,
            )

            widget.setSingleStep(
                step
            )

            try:
                widget.setValue(
                    float(default)
                )
            except Exception:
                pass

        elif param_type == "integer":
            widget = QtWidgets.QSpinBox()

            minimum = int(
                param.get(
                    "min",
                    -999999999,
                )
            )

            maximum = int(
                param.get(
                    "max",
                    999999999,
                )
            )

            step = int(
                param.get(
                    "step",
                    1,
                )
            )

            widget.setRange(
                minimum,
                maximum,
            )

            widget.setSingleStep(
                step
            )

            try:
                widget.setValue(
                    int(
                        float(default)
                    )
                )
            except Exception:
                pass

        else:
            widget = QtWidgets.QLineEdit(
                default
            )

        widget.setObjectName(
            f"tactical_ecosystem_param_{param_name}"
        )

        widget.setToolTip(
            param.get(
                "description",
                "",
            )
        )

        make_tactical_parameter_widget_compact(
            widget
        )

        row_layout.addWidget(
            widget,
            1,
        )

        layout.addWidget(
            row_widget
        )

        dashboard.tactical_ecosystem_action_parameter_widgets[
            param_name
        ] = widget

    layout.addStretch()

    has_parameters = bool(
        dashboard.tactical_ecosystem_action_parameter_widgets
    )

    dashboard.ui.pushButton_tactical_ecosystem_execute.setEnabled(
        has_parameters
    )

    content_widget.adjustSize()

    dashboard.ui.scrollArea_tactical_ecosystem_action_parameters.setEnabled(
        True
    )

    for widget in [
        scroll_area,
        scroll_area.viewport(),
        content_widget,
    ]:
        widget.style().unpolish(
            widget
        )
        widget.style().polish(
            widget
        )
        widget.update()

    scroll_area.update()
    

@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeExecuteClicked(dashboard):
    """
    Executes the selected plugin action on the selected tactical node.
    """
    uid = dashboard.ui.label2_tactical_node_uuid.text().strip()

    plugin_name = str(
        dashboard.ui.comboBox_tactical_node_plugins.currentText()
    ).strip()

    action_name = str(
        dashboard.ui.comboBox_tactical_node_actions.currentText()
    ).strip()

    if not uid:
        dashboard.logger.warning(
            "[Tactical] No node UID selected for execute request."
        )
        return

    if not plugin_name:
        dashboard.logger.warning(
            "[Tactical] No plugin selected for execute request."
        )
        return

    if not action_name:
        dashboard.logger.warning(
            "[Tactical] No action selected for execute request."
        )
        return

    parameters = {}

    parameter_widgets = getattr(
        dashboard,
        "tactical_action_parameter_widgets",
        {},
    )

    for parameter_name, widget in parameter_widgets.items():
        if not parameter_name:
            continue

        if isinstance(widget, QtWidgets.QLineEdit):
            parameters[parameter_name] = widget.text()

        elif isinstance(widget, QtWidgets.QComboBox):
            parameters[parameter_name] = widget.currentText()

        elif isinstance(widget, QtWidgets.QDoubleSpinBox):
            parameters[parameter_name] = widget.value()

        elif isinstance(widget, QtWidgets.QSpinBox):
            parameters[parameter_name] = widget.value()

        elif isinstance(widget, QtWidgets.QCheckBox):
            parameters[parameter_name] = widget.isChecked()

        else:
            dashboard.logger.warning(
                f"[Tactical] Unsupported parameter widget for "
                f"{parameter_name}: {type(widget)}"
            )

    await dashboard.backend.tacticalNodeExecute(
        [uid],
        plugin_name,
        action_name,
        parameters,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalEcosystemExecuteClicked(dashboard):
    """
    Executes the selected plugin action on the selected ecosystem nodes.
    """
    table = dashboard.ui.tableWidget_tactical_ecosystem

    uids = []

    selected_rows = sorted(
        set(index.row() for index in table.selectedIndexes())
    )

    if not selected_rows:
        dashboard.logger.warning(
            "[Tactical] No ecosystem nodes selected for execute request."
        )
        return

    for row in selected_rows:
        item = table.item(row, 0)

        if item is None:
            continue

        uid = item.data(QtCore.Qt.UserRole)

        if uid and uid not in uids:
            uids.append(uid)

    if not uids:
        dashboard.logger.warning(
            "[Tactical] Selected ecosystem rows do not contain valid node UIDs."
        )
        return

    plugin_name = str(
        dashboard.ui.comboBox_tactical_ecosystem_plugins.currentText()
    ).strip()

    action_name = str(
        dashboard.ui.comboBox_tactical_ecosystem_actions.currentText()
    ).strip()

    if not plugin_name:
        dashboard.logger.warning(
            "[Tactical] No ecosystem plugin selected for execute request."
        )
        return

    if not action_name:
        dashboard.logger.warning(
            "[Tactical] No ecosystem action selected for execute request."
        )
        return

    parameters = {}

    parameter_widgets = getattr(
        dashboard,
        "tactical_ecosystem_action_parameter_widgets",
        {},
    )

    for parameter_name, widget in parameter_widgets.items():
        if not parameter_name:
            continue

        if isinstance(widget, QtWidgets.QLineEdit):
            parameters[parameter_name] = widget.text()

        elif isinstance(widget, QtWidgets.QComboBox):
            parameters[parameter_name] = widget.currentText()

        elif isinstance(widget, QtWidgets.QDoubleSpinBox):
            parameters[parameter_name] = widget.value()

        elif isinstance(widget, QtWidgets.QSpinBox):
            parameters[parameter_name] = widget.value()

        elif isinstance(widget, QtWidgets.QCheckBox):
            parameters[parameter_name] = widget.isChecked()

        else:
            dashboard.logger.warning(
                f"[Tactical] Unsupported ecosystem parameter widget for "
                f"{parameter_name}: {type(widget)}"
            )

    await dashboard.backend.tacticalNodeExecute(
        uids,
        plugin_name,
        action_name,
        parameters,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeStopClicked(dashboard):
    """
    Stops any running actions for a node.
    """
    uid = dashboard.ui.label2_tactical_node_uuid.text().strip()

    if not uid:
        dashboard.logger.warning(
            "[Tactical] No node UID selected for plugin query."
        )
        return

    await dashboard.backend.tacticalNodeStop([uid])


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalEcosystemStopClicked(dashboard):
    """
    Stops running actions on selected ecosystem nodes.
    """
    table = dashboard.ui.tableWidget_tactical_ecosystem

    uids = []

    selected_rows = sorted(
        set(index.row() for index in table.selectedIndexes())
    )

    if not selected_rows:
        dashboard.logger.warning(
            "[Tactical] No ecosystem nodes selected for stop request."
        )
        return

    for row in selected_rows:
        item = table.item(row, 0)

        if item is None:
            continue

        uid = item.data(QtCore.Qt.UserRole)

        if uid and uid not in uids:
            uids.append(uid)

    if not uids:
        dashboard.logger.warning(
            "[Tactical] Selected ecosystem rows do not contain valid node UIDs."
        )
        return

    await dashboard.backend.tacticalNodeStop(
        uids,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalEcosystemRefreshStatusClicked(dashboard):
    """
    Refreshes the status for selected ecosystem nodes.
    """
    table = dashboard.ui.tableWidget_tactical_ecosystem

    uids = []

    selected_rows = sorted(
        set(index.row() for index in table.selectedIndexes())
    )

    if not selected_rows:
        dashboard.logger.warning(
            "[Tactical] No ecosystem nodes selected for status refresh."
        )
        return

    for row in selected_rows:
        item = table.item(row, 0)

        if item is None:
            continue

        uid = item.data(QtCore.Qt.UserRole)

        if uid and uid not in uids:
            uids.append(uid)

    if not uids:
        dashboard.logger.warning(
            "[Tactical] Selected ecosystem rows do not contain valid node UIDs."
        )
        return

    await dashboard.backend.tacticalEcosystemRefreshStatus(uids)


def update_tactical_alert_row(dashboard: QtCore.QObject, alert_record):
    table = dashboard.ui.tableWidget_tactical_ecosystem_alerts

    uid = alert_record.get("uid")
    if not uid:
        return

    values = [
        alert_record.get("type", ""),
        format_tactical_time(alert_record.get("time", "")),
        alert_record.get("summary", ""),
    ]

    existing_row = None

    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item and item.data(QtCore.Qt.UserRole) == uid:
            existing_row = row
            break

    if existing_row is None:
        existing_row = 0
        table.insertRow(existing_row)

    for col, value in enumerate(values):
        item = table.item(existing_row, col)

        if item is None:
            item = QtWidgets.QTableWidgetItem()
            table.setItem(existing_row, col, item)

        item.setText(str(value))
        item.setData(QtCore.Qt.UserRole, uid)

    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject, str)
def _slotTacticalAlertMapClicked(dashboard: QtCore.QObject, alert_uid):
    dashboard.ui.tabWidget_tactical.setCurrentIndex(2)  # Ecosystem tab

    select_tactical_alert_row(dashboard, alert_uid)


def select_tactical_alert_row(dashboard: QtCore.QObject, alert_uid):
    table = dashboard.ui.tableWidget_tactical_ecosystem_alerts

    table.clearSelection()

    for row in range(table.rowCount()):
        item = table.item(row, 0)

        if item and item.data(QtCore.Qt.UserRole) == alert_uid:
            table.selectRow(row)
            table.scrollToItem(item, QtWidgets.QAbstractItemView.PositionAtCenter)
            table.setCurrentCell(row, 0)
            return


def clear_tactical_node_pins(dashboard):
    dashboard.tactical_map.clear_node_records()


def clear_tactical_target_pins(dashboard):
    dashboard.tactical_map.clear_target_records()


def clear_tactical_alert_pins(dashboard):
    dashboard.tactical_map.clear_alert_records()


def clear_tactical_detection_pins(dashboard):
    dashboard.tactical_map.clear_detection_records()


def clear_tactical_soi_pins(dashboard):
    dashboard.tactical_map.clear_soi_records()


def clear_tactical_map_pins(dashboard):
    dashboard.tactical_map.clear_overlay_records()


def update_tactical_detection_row(dashboard: QtCore.QObject, detection_record):
    selected_node_uid = getattr(dashboard, "selected_tactical_node_uid", None)
    detection_node_uid = detection_record.get("node_uid")

    if not selected_node_uid:
        return

    if detection_node_uid != selected_node_uid:
        return

    table = dashboard.ui.tableWidget_tactical_node_detections

    uid = detection_record.get("uid")
    if not uid:
        return

    was_empty = table.rowCount() == 0

    values = [
        detection_record.get("frequency", ""),
        detection_record.get("power", ""),
        format_detection_time(detection_record.get("time", "")),
    ]

    existing_row = None

    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item and item.data(QtCore.Qt.UserRole) == uid:
            existing_row = row
            break

    if existing_row is None:
        existing_row = 0
        table.insertRow(0)

    for col, value in enumerate(values):
        item = table.item(existing_row, col)

        if item is None:
            item = QtWidgets.QTableWidgetItem()
            table.setItem(existing_row, col, item)

        item.setText(str(value))
        item.setData(QtCore.Qt.UserRole, uid)

    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setStretchLastSection(True)

    if was_empty:
        table.selectRow(existing_row)
        table.setCurrentCell(existing_row, 0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeDetectionRowChanged(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_node_detections

    current_row = table.currentRow()
    if current_row < 0:
        clear_tactical_detection_details(dashboard)
        return

    item = table.item(current_row, 0)
    if item is None:
        clear_tactical_detection_details(dashboard)
        return

    detection_uid = item.data(QtCore.Qt.UserRole)
    if not detection_uid:
        clear_tactical_detection_details(dashboard)
        return

    detection = dashboard.tactical_detections.get(detection_uid)
    if not detection:
        clear_tactical_detection_details(dashboard)
        return

    populate_tactical_detection_details(dashboard, detection)
    enable_tactical_node_detection_details(dashboard, True)


def clear_tactical_detection_details(dashboard: QtCore.QObject):
    dashboard.ui.label2_tactical_node_detection_details.setText("")

    enable_tactical_node_detection_details(dashboard, False)


def populate_tactical_detection_details(
    dashboard: QtCore.QObject,
    detection: dict,
):
    """
    Displays every non-empty detection value except raw transport payloads
    that are better shown separately in a future raw-message viewer.
    """
    hidden_keys = {
        "raw_xml",
        "cot_xml",
        "xml",
        "raw_message",
        "raw_payload",
    }

    def is_empty(value):
        if value is None:
            return True

        if isinstance(value, str):
            return value.strip() in ["", "None"]

        if isinstance(value, (dict, list, tuple, set)):
            return len(value) == 0

        return False

    def make_label(key):
        return str(key).replace("_", " ").strip().title()

    def format_scalar(key, value):
        if key == "time":
            formatted_time = format_detection_time(value)
            if formatted_time:
                return formatted_time

        return str(value)

    def field_label_html(label):
        return (
            "<span style='font-weight:500;'>"
            f"{html.escape(str(label))}:"
            "</span>"
        )

    def append_value(lines, key, value, depth=0):
        normalized_key = str(key).strip().lower()

        if normalized_key in hidden_keys:
            return

        if is_empty(value):
            return

        label = make_label(key)
        indent = "&nbsp;" * (depth * 4)

        if isinstance(value, dict):
            lines.append(
                f"{indent}{field_label_html(label)}"
            )

            for nested_key, nested_value in value.items():
                append_value(
                    lines,
                    nested_key,
                    nested_value,
                    depth + 1,
                )

            return

        if isinstance(value, (list, tuple, set)):
            values = list(value)

            if not values:
                return

            lines.append(
                f"{indent}{field_label_html(label)}"
            )

            for index, item in enumerate(values):
                if is_empty(item):
                    continue

                if isinstance(item, dict):
                    item_label = (
                        item.get("label")
                        or item.get("name")
                        or f"Item {index + 1}"
                    )

                    item_value = item.get("value")

                    if "value" in item and not is_empty(item_value):
                        unit = str(
                            item.get("unit", "")
                            or ""
                        ).strip()

                        display_value = str(item_value)

                        if unit:
                            display_value = (
                                f"{display_value} {unit}"
                            )

                        lines.append(
                            f"{'&nbsp;' * ((depth + 1) * 4)}"
                            f"{field_label_html(item_label)} "
                            f"{html.escape(display_value)}"
                        )

                        remaining = {
                            nested_key: nested_value
                            for nested_key, nested_value in item.items()
                            if nested_key not in {
                                "label",
                                "name",
                                "value",
                                "unit",
                            }
                        }

                        for nested_key, nested_value in remaining.items():
                            append_value(
                                lines,
                                nested_key,
                                nested_value,
                                depth + 2,
                            )

                    else:
                        lines.append(
                            f"{'&nbsp;' * ((depth + 1) * 4)}"
                            f"<span style='font-weight:600;'>"
                            f"{html.escape(str(item_label))}"
                            f"</span>"
                        )

                        for nested_key, nested_value in item.items():
                            append_value(
                                lines,
                                nested_key,
                                nested_value,
                                depth + 2,
                            )

                else:
                    lines.append(
                        f"{'&nbsp;' * ((depth + 1) * 4)}"
                        f"{html.escape(str(item))}"
                    )

            return

        display_value = format_scalar(
            normalized_key,
            value,
        )

        lines.append(
            f"{indent}{field_label_html(label)} "
            f"{html.escape(display_value)}"
        )

    lines = []

    for key, value in detection.items():
        append_value(
            lines,
            key,
            value,
        )

    dashboard.ui.label2_tactical_node_detection_details.setText(
        "<br>".join(lines)
    )

    dashboard.ui.label2_tactical_node_detection_details.setAlignment(
        QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeDetectionsPlotClicked(dashboard: QtCore.QObject):
    detection = get_selected_tactical_node_detection(dashboard)
    if not detection:
        return

    plot_tactical_node_detection(dashboard, detection, zoom=False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeDetectionsPlotZoomClicked(dashboard: QtCore.QObject):
    detection = get_selected_tactical_node_detection(dashboard)
    if not detection:
        return

    plot_tactical_node_detection(dashboard, detection, zoom=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeDetectionsRemoveClicked(dashboard: QtCore.QObject):
    detection = get_selected_tactical_node_detection(dashboard)
    if not detection:
        return

    uid = detection.get("uid")
    if uid:
        dashboard.tactical_map.remove_detection_pin(uid)


def get_selected_tactical_node_detection(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_node_detections

    row = table.currentRow()
    if row < 0:
        return None

    item = table.item(row, 0)
    if item is None:
        return None

    uid = item.data(QtCore.Qt.UserRole)
    if not uid:
        return None

    return dashboard.tactical_detections.get(uid)


def plot_tactical_node_detection(
    dashboard: QtCore.QObject,
    detection: dict,
    zoom=False,
):
    uid = detection.get("uid")
    lat = detection.get("lat")
    lon = detection.get("lon")

    if not uid or lat is None or lon is None:
        return

    label = detection.get("frequency") or uid

    dashboard.tactical_map.add_detection(
        detection_id=uid,
        lat=lat,
        lon=lon,
        label=label,
    )

    if zoom:
        dashboard.tactical_map.center_on_latlon(lat, lon)


@QtCore.pyqtSlot(QtCore.QObject, str)
def _slotTacticalNodeDetectionMapClicked(dashboard: QtCore.QObject, detection_uid):
    dashboard.ui.tabWidget_tactical.setCurrentIndex(0)
    dashboard.ui.tabWidget_tactical_node.setCurrentIndex(0)

    select_tactical_node_detection_row(dashboard, detection_uid)


def select_tactical_node_detection_row(dashboard: QtCore.QObject, detection_uid):
    table = dashboard.ui.tableWidget_tactical_node_detections

    table.clearSelection()

    for row in range(table.rowCount()):
        item = table.item(row, 0)

        if item and item.data(QtCore.Qt.UserRole) == detection_uid:
            table.selectRow(row)
            table.scrollToItem(item, QtWidgets.QAbstractItemView.PositionAtCenter)
            table.setCurrentCell(row, 0)
            return


@QtCore.pyqtSlot(QtCore.QObject, QtWidgets.QTableWidgetItem)
def _slotTacticalNodeDetectionDoubleClicked(dashboard, item):
    if item is None:
        return

    row = item.row()
    uid_item = dashboard.ui.tableWidget_tactical_node_detections.item(row, 0)
    if uid_item is None:
        return

    detection_uid = uid_item.data(QtCore.Qt.UserRole)
    if not detection_uid:
        return

    detection = dashboard.tactical_detections.get(detection_uid)
    if not detection:
        return

    plot_tactical_node_detection(
        dashboard,
        detection,
        zoom=True,
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeDetectionsDeleteRowClicked(
    dashboard: QtCore.QObject,
):
    table = dashboard.ui.tableWidget_tactical_node_detections

    row = table.currentRow()
    if row < 0:
        return

    item = table.item(row, 0)
    if item is None:
        return

    uid = item.data(QtCore.Qt.UserRole)

    if uid:
        dashboard.tactical_detections.pop(uid, None)

        # Remove plotted pin only if present
        dashboard.tactical_map.remove_detection_pin(uid)

    table.removeRow(row)

    if table.rowCount() == 0:
        clear_tactical_detection_details(dashboard)
    else:
        next_row = min(row, table.rowCount() - 1)

        table.selectRow(next_row)
        table.setCurrentCell(next_row, 0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeDetectionsClearRowsClicked(
    dashboard: QtCore.QObject,
):
    node_uid = getattr(dashboard, "selected_tactical_node_uid", None)

    if not node_uid:
        dashboard.ui.tableWidget_tactical_node_detections.setRowCount(0)
        clear_tactical_detection_details(dashboard)
        return

    detections_to_remove = [
        uid
        for uid, detection in dashboard.tactical_detections.items()
        if detection.get("node_uid") == node_uid
    ]

    for uid in detections_to_remove:
        dashboard.tactical_detections.pop(uid, None)
        dashboard.tactical_map.remove_detection(uid)

    dashboard.ui.tableWidget_tactical_node_detections.setRowCount(0)

    clear_tactical_detection_details(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemDeleteNodeRowClicked(
    dashboard: QtCore.QObject,
):
    table = dashboard.ui.tableWidget_tactical_ecosystem

    row = table.currentRow()
    if row < 0:
        return

    item = table.item(row, 0)
    if item is None:
        return

    uid = item.data(QtCore.Qt.UserRole)
    if not uid:
        return

    # Remove node record and plotted pin
    dashboard.tactical_nodes.pop(uid, None)
    dashboard.tactical_map.remove_node(uid)

    # Remove table row
    table.removeRow(row)

    # Clear selected node state if needed
    if dashboard.selected_tactical_node_uid == uid:
        dashboard.selected_tactical_node_uid = None

    dashboard.selected_tactical_node_uids = [
        x for x in dashboard.selected_tactical_node_uids
        if x != uid
    ]

    # Update selection labels/buttons
    update_selected_tactical_nodes(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemClearNodeRowsClicked(
    dashboard: QtCore.QObject,
):
    # Clear records and plotted pins
    dashboard.tactical_nodes.clear()
    dashboard.tactical_map.clear_node_records()

    # Clear table
    dashboard.ui.tableWidget_tactical_ecosystem.setRowCount(0)

    # Clear selected node state
    dashboard.selected_tactical_node_uid = None
    dashboard.selected_tactical_node_uids = []

    # Reset selection UI
    update_selected_tactical_nodes(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalTargetsRefreshTargetsClicked(dashboard):
    """
    Requests the current target list from the hub.
    """
    try:
        dashboard.tactical_targets = {}

        dashboard.ui.tableWidget_tactical_targets.setRowCount(0)

        await dashboard.backend.tacticalTargetsRefreshTargets()

    except Exception as e:
        dashboard.logger.error(
            f"[Tactical] Failed requesting target list: {e}"
        )


def update_tactical_target_row(
    dashboard: QtCore.QObject,
    target_record,
):
    table = dashboard.ui.tableWidget_tactical_targets

    target_id = target_record.get("target_id")
    if not target_id:
        return

    display_target_id = shorten_target_id(target_id)

    values = [
        display_target_id,
        target_record.get("type", ""),
        format_tactical_time(target_record.get("updated", "")),
    ]

    existing_row = None

    for row in range(table.rowCount()):
        item = table.item(row, 0)

        if item and item.data(QtCore.Qt.UserRole) == target_id:
            existing_row = row
            break

    if existing_row is None:
        existing_row = 0
        table.insertRow(0)

    for col, value in enumerate(values):
        item = table.item(existing_row, col)

        if item is None:
            item = QtWidgets.QTableWidgetItem()
            table.setItem(existing_row, col, item)

        item.setText(str(value))

        item.setData(QtCore.Qt.UserRole, target_id)

        if col == 0:
            item.setToolTip(target_id)

    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setStretchLastSection(True)


def shorten_target_id(target_id, max_len=24):
    if not target_id:
        return ""

    if len(target_id) <= max_len:
        return target_id

    prefix_len = 12
    suffix_len = 6

    return (
        target_id[:prefix_len]
        + "..."
        + target_id[-suffix_len:]
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalTargetsRowSelectionChanged(
    dashboard: QtCore.QObject,
):
    table = dashboard.ui.tableWidget_tactical_targets

    selected_items = table.selectedItems()

    if not selected_items:
        clear_tactical_targets_details(dashboard)
        return

    row = selected_items[0].row()
    id_item = table.item(row, 0)

    if id_item is None:
        clear_tactical_targets_details(dashboard)
        return

    target_id = (
        id_item.data(QtCore.Qt.UserRole)
        or id_item.text()
    )

    target = dashboard.tactical_targets.get(
        target_id,
        {},
    )

    if not isinstance(target, dict) or not target:
        clear_tactical_targets_details(dashboard)
        return

    dashboard.selected_tactical_target_id = target_id

    populate_tactical_targets_details(
        dashboard,
        target,
    )

    enable_tactical_targets_details(
        dashboard,
        True,
    )

    update_tactical_targets_geolocate_button_state(
        dashboard,
        target,
    )


def clear_tactical_targets_details(
    dashboard: QtCore.QObject,
):
    dashboard.selected_tactical_target_id = None

    dashboard.ui.label2_tactical_targets_details.setText("")

    enable_tactical_targets_details(
        dashboard,
        False,
    )

    update_tactical_targets_geolocate_button_state(
        dashboard,
        None,
    )


def enable_tactical_targets_details(
    dashboard: QtCore.QObject,
    enabled=True,
):
    dashboard.ui.scrollArea_tactical_targets_details.setEnabled(
        enabled
    )

    dashboard.ui.label2_tactical_targets_details.setEnabled(
        enabled
    )

    dashboard.ui.checkBox_tactical_targets_search_similar_targets.setEnabled(
        enabled
    )

    dashboard.ui.pushButton_tactical_targets_query_actions.setEnabled(
        enabled
    )

    if not enabled:
        dashboard.ui.pushButton_tactical_targets_geolocate.setEnabled(
            False
        )


def clear_tactical_node_artifact_details(
    dashboard: QtCore.QObject,
):
    dashboard.selected_tactical_node_artifact_id = None

    dashboard.ui.label2_tactical_node_artifact_details.setText("")

    enable_tactical_artifacts_details(
        dashboard,
        False,
    )


def enable_tactical_artifacts_details(
    dashboard: QtCore.QObject,
    enabled=True,
):
    dashboard.ui.scrollArea_tactical_node_artifact_details.setEnabled(
        enabled
    )
    dashboard.ui.label2_tactical_node_artifact_details.setEnabled(
        enabled
    )
    dashboard.ui.pushButton_tactical_node_artifacts_open_folder.setEnabled(
        enabled
    )
    dashboard.ui.pushButton_tactical_node_artifacts_download.setEnabled(
        enabled
    )

    dashboard.ui.pushButton_tactical_node_artifacts_refresh.setEnabled(
        bool(
            getattr(
                dashboard,
                "selected_tactical_node_uid",
                None,
            )
        )
    )


def initialize_tactical_node_artifact_details_context_menu(
    dashboard: QtCore.QObject,
):
    """
    Applies the shared details-panel stylesheet role and adds Full Details,
    Copy, and Select All to the artifact details label.
    """
    scroll_area = (
        dashboard.ui.scrollArea_tactical_node_artifact_details
    )
    content_widget = scroll_area.widget()
    label = dashboard.ui.label2_tactical_node_artifact_details

    scroll_area.setHorizontalScrollBarPolicy(
        QtCore.Qt.ScrollBarAlwaysOff
    )
    scroll_area.setVerticalScrollBarPolicy(
        QtCore.Qt.ScrollBarAsNeeded
    )

    label.setWordWrap(True)
    label.setMinimumWidth(0)

    # Match the programmatic styling used by the other read-only details
    # panels. The shared custom/dark/light stylesheets already target this
    # dynamic property.
    scroll_area.setProperty(
        "uiRole",
        "detailsPanel",
    )

    if content_widget is not None:
        content_widget.setProperty(
            "uiRole",
            "detailsPanel",
        )

    label.setProperty(
        "uiRole",
        "detailsPanel",
    )

    # Re-polish because the dynamic property is assigned after the .ui file
    # and application stylesheet have already been loaded.
    widgets = [
        scroll_area,
        scroll_area.viewport(),
        content_widget,
        label,
    ]

    for widget in widgets:
        if widget is None:
            continue

        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    label.setContextMenuPolicy(
        QtCore.Qt.CustomContextMenu
    )

    label.customContextMenuRequested.connect(
        lambda position: _showTacticalNodeArtifactDetailsContextMenu(
            dashboard,
            position,
        )
    )


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QPoint)
def _showTacticalNodeArtifactDetailsContextMenu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    label = dashboard.ui.label2_tactical_node_artifact_details

    menu = QtWidgets.QMenu(label)

    action_full_details = menu.addAction(
        "Full Details"
    )
    action_full_details.setCheckable(True)
    action_full_details.setChecked(
        bool(
            getattr(
                dashboard,
                "tactical_node_artifact_full_details",
                False,
            )
        )
    )

    menu.addSeparator()

    action_copy = menu.addAction("Copy")
    action_select_all = menu.addAction("Select All")

    has_text = bool(label.text().strip())
    has_selection = bool(label.hasSelectedText())

    action_copy.setEnabled(has_selection)
    action_select_all.setEnabled(has_text)

    selected_action = menu.exec_(
        label.mapToGlobal(position)
    )

    if selected_action == action_full_details:
        dashboard.tactical_node_artifact_full_details = (
            action_full_details.isChecked()
        )

        artifact_id = getattr(
            dashboard,
            "selected_tactical_node_artifact_id",
            None,
        )

        artifact = (
            dashboard.tactical_artifacts.get(artifact_id)
            if artifact_id
            else None
        )

        if isinstance(artifact, dict) and artifact:
            populate_tactical_node_artifact_details(
                dashboard,
                artifact,
            )

    elif selected_action == action_copy:
        selected_text = label.selectedText()

        if selected_text:
            QtWidgets.QApplication.clipboard().setText(
                selected_text
            )

    elif selected_action == action_select_all:
        label.setSelection(
            0,
            len(label.text()),
        )


def _format_tactical_artifact_file_size(value):
    try:
        size = int(value)
    except (TypeError, ValueError):
        return str(value or "")

    units = [
        "B",
        "KB",
        "MB",
        "GB",
        "TB",
    ]

    display_size = float(size)
    unit = units[0]

    for candidate_unit in units:
        unit = candidate_unit

        if display_size < 1024.0 or candidate_unit == units[-1]:
            break

        display_size /= 1024.0

    if unit == "B":
        return f"{size:,} B"

    return f"{display_size:.2f} {unit} ({size:,} bytes)"


def populate_tactical_node_artifact_details(
    dashboard: QtCore.QObject,
    artifact: dict,
):
    """
    Displays either a curated artifact summary or the complete dynamic record.

    Compact mode prioritizes common review fields.

    Full Details preserves complete lookup identifiers, arbitrary nested
    metadata, and every remaining non-empty artifact field, but presents the
    most useful human-readable values before IDs and implementation details.
    """
    hidden_keys = {
        "raw_xml",
        "cot_xml",
        "xml",
        "raw_message",
        "raw_payload",
        "data",
        "file_data",
        "contents",
    }

    detail_field_groups = [
        (
            "Name",
            [
                "name",
                "filename",
            ],
        ),
        (
            "Artifact Type",
            [
                "artifact_type",
                "type",
            ],
        ),
        (
            "File Size",
            [
                "file_size",
                "size",
            ],
        ),
        (
            "Created",
            [
                "created_at",
                "created",
            ],
        ),
        (
            "Modified",
            [
                "modified_at",
                "time",
            ],
        ),
        (
            "Source Node",
            [
                "source_id",
                "node_uid",
            ],
        ),
        (
            "Operation ID",
            [
                "operation_id",
            ],
        ),
        (
            "Artifact ID",
            [
                "artifact_id",
                "id",
            ],
        ),
        (
            "Checksum",
            [
                "checksum",
                "sha256",
            ],
        ),
        (
            "File Path",
            [
                "file_path",
                "path",
            ],
        ),
        (
            "Metadata",
            [
                "metadata",
            ],
        ),
    ]

    def is_empty(value):
        if value is None:
            return True

        if isinstance(value, str):
            return not value.strip()

        if isinstance(value, (list, tuple, set, dict)):
            return len(value) == 0

        return False

    def display_label(key):
        return str(key).replace("_", " ").strip().title()

    def field_label_html(label):
        return (
            "<span style=\"font-weight: 600;\">"
            f"{html.escape(str(label))}:"
            "</span>"
        )

    def first_non_empty_value(candidate_keys):
        for key in candidate_keys:
            value = artifact.get(key)

            if not is_empty(value):
                return key, value, False

        metadata = artifact.get("metadata")

        if isinstance(metadata, dict):
            for key in candidate_keys:
                value = metadata.get(key)

                if not is_empty(value):
                    return key, value, True

        return None, None, False

    def scalar_text(key, value):
        if key in {"file_size", "size"}:
            return _format_tactical_artifact_file_size(value)

        if isinstance(value, bool):
            return "Yes" if value else "No"

        return str(value)

    def append_value(
        lines,
        key,
        value,
        display_name=None,
        indent="",
    ):
        normalized_key = str(key).strip().lower()

        if normalized_key in hidden_keys or is_empty(value):
            return

        label = display_name or display_label(key)

        if isinstance(value, dict):
            lines.append(
                f"{indent}{field_label_html(label)}"
            )

            for child_key, child_value in value.items():
                append_value(
                    lines,
                    child_key,
                    child_value,
                    indent=indent + "&nbsp;&nbsp;&nbsp;&nbsp;",
                )

            return

        if isinstance(value, (list, tuple, set)):
            lines.append(
                f"{indent}{field_label_html(label)}"
            )

            for index, child_value in enumerate(value):
                append_value(
                    lines,
                    str(index + 1),
                    child_value,
                    display_name=str(index + 1),
                    indent=indent + "&nbsp;&nbsp;&nbsp;&nbsp;",
                )

            return

        value_text = scalar_text(
            normalized_key,
            value,
        )

        lines.append(
            f"{indent}{field_label_html(label)} "
            f"{html.escape(value_text)}"
        )

    full_details = bool(
        getattr(
            dashboard,
            "tactical_node_artifact_full_details",
            False,
        )
    )

    lines = []
    used_top_level_keys = set()
    used_metadata_keys = set()

    groups_to_render = (
        detail_field_groups
        if full_details
        else detail_field_groups[:-1]
    )

    for display_name, candidate_keys in groups_to_render:
        actual_key, value, from_metadata = first_non_empty_value(
            candidate_keys
        )

        if actual_key is None:
            continue

        if from_metadata:
            used_metadata_keys.add(actual_key)
        else:
            used_top_level_keys.add(actual_key)

        # Treat aliases as one logical field so Full Details does not repeat
        # source_id/node_uid, artifact_id/id, checksum/sha256, and similar
        # values immediately afterward.
        used_top_level_keys.update(candidate_keys)

        append_value(
            lines,
            actual_key,
            value,
            display_name=display_name,
        )

    if full_details:
        metadata = artifact.get("metadata")

        # Metadata was already rendered in its preferred position above.
        used_top_level_keys.add("metadata")

        # Append every remaining top-level field so Full Details remains
        # field-agnostic and no future ArtifactTracker values are hidden.
        for key, value in artifact.items():
            if key in used_top_level_keys:
                continue

            append_value(
                lines,
                key,
                value,
            )

        # When selected summary values came from metadata, preserve all other
        # metadata entries while avoiding duplicate display of those aliases.
        if isinstance(metadata, dict):
            remaining_metadata = {
                key: value
                for key, value in metadata.items()
                if key not in used_metadata_keys
                and not is_empty(value)
            }

            if remaining_metadata and "metadata" not in artifact:
                append_value(
                    lines,
                    "metadata",
                    remaining_metadata,
                    display_name="Metadata",
                )

    dashboard.ui.label2_tactical_node_artifact_details.setText(
        "<br>".join(lines)
    )

    dashboard.ui.label2_tactical_node_artifact_details.setAlignment(
        QtCore.Qt.AlignLeft
        | QtCore.Qt.AlignTop
    )


@QtCore.pyqtSlot(QtCore.QObject, str)
def _slotTacticalTargetMapClicked(dashboard: QtCore.QObject, target_id):
    dashboard.ui.tabWidget_tactical.setCurrentIndex(1)  # Targets tab

    table = dashboard.ui.tableWidget_tactical_targets

    for row in range(table.rowCount()):
        id_item = table.item(row, 0)

        if id_item is None:
            continue

        row_target_id = (
            id_item.data(QtCore.Qt.UserRole)
            or id_item.text()
        )

        if row_target_id == target_id:
            table.blockSignals(True)
            table.selectRow(row)
            table.blockSignals(False)

            dashboard.selected_tactical_target_id = target_id

            _slotTacticalTargetsRowSelectionChanged(
                dashboard
            )

            table.scrollToItem(id_item)

            return


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalTargetsPlotClicked(dashboard: QtCore.QObject):
    target_id = dashboard.selected_tactical_target_id

    if not target_id:
        return

    target = dashboard.tactical_targets.get(target_id)
    if not target:
        return

    plot_tactical_target(dashboard, target, zoom=False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalTargetsPlotZoomClicked(dashboard: QtCore.QObject):
    target_id = dashboard.selected_tactical_target_id

    if not target_id:
        return

    target = dashboard.tactical_targets.get(target_id)
    if not target:
        return

    plot_tactical_target(dashboard, target, zoom=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalTargetsRemovePinClicked(dashboard: QtCore.QObject):
    target_id = dashboard.selected_tactical_target_id

    if not target_id:
        return

    dashboard.tactical_map.remove_target_pin(target_id)


@QtCore.pyqtSlot(QtCore.QObject, str)
def _slotTacticalTargetsTableDoubleClicked(dashboard: QtCore.QObject, item):
    if item is None:
        return

    row = item.row()
    table = dashboard.ui.tableWidget_tactical_targets

    id_item = table.item(row, 0)
    if id_item is None:
        return

    target_id = id_item.data(QtCore.Qt.UserRole) or id_item.text()
    target = dashboard.tactical_targets.get(target_id)

    if not target:
        return

    dashboard.selected_tactical_target_id = target_id

    plot_tactical_target(dashboard, target, zoom=True)


def plot_tactical_target(dashboard: QtCore.QObject, target: dict, zoom=False):
    target_id = target.get("target_id")
    if not target_id:
        return

    lat = target.get("lat")
    lon = target.get("lon")

    if lat in [None, "", "None"] or lon in [None, "", "None"]:
        return

    try:
        lat = float(lat)
        lon = float(lon)
    except Exception:
        return

    ce_m = target.get("ce_m")

    dashboard.tactical_map.add_target(
        target_id=target_id,
        lat=lat,
        lon=lon,
        label=target_id,
        ce_m=ce_m,
    )

    if zoom:
        dashboard.tactical_map.center_on_latlon(lat, lon)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalTargetsPlotAllClicked(dashboard: QtCore.QObject):
    for target_id, target in dashboard.tactical_targets.items():
        plot_tactical_target(
            dashboard,
            target,
            zoom=False,
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalTargetsDeleteRowClicked(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_targets

    selected_items = table.selectedItems()
    if not selected_items:
        return

    row = selected_items[0].row()

    id_item = table.item(row, 0)
    if id_item is None:
        return

    target_id = id_item.data(QtCore.Qt.UserRole) or id_item.text()

    # Remove plotted marker + persistent map overlay record
    dashboard.tactical_map.remove_target(target_id)

    # Remove dashboard target record
    dashboard.tactical_targets.pop(target_id, None)

    # Remove row
    table.removeRow(row)

    # Clear details if deleting selected target
    if dashboard.selected_tactical_target_id == target_id:
        clear_tactical_targets_details(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalTargetsClearRowsClicked(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_targets

    # Clear plotted markers + persistent map overlay records
    dashboard.tactical_map.clear_target_records()

    # Clear dashboard target records
    dashboard.tactical_targets.clear()

    # Clear table
    table.setRowCount(0)

    # Clear details panel
    clear_tactical_targets_details(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalTargetsShowCeRingsToggled(dashboard: QtCore.QObject):
    checked = dashboard.ui.checkBox_tactical_targets_show_ce_rings.isChecked()

    dashboard.tactical_map.set_show_ce_rings(checked)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeTargetsRefreshTargetsClicked(dashboard: QtCore.QObject):
    """
    Refreshes the Node > Targets table.

    If the table currently has rows, only refresh those displayed target IDs.
    If the table is empty, repopulate from all current dashboard.tactical_targets.

    Selection behavior:
      - Preserve the previously selected target row if it still exists.
      - If repopulating a full list from empty, select the first row.
    """
    table = dashboard.ui.tableWidget_tactical_node_targets

    previous_selected_target_id = getattr(
        dashboard,
        "selected_tactical_node_target_id",
        None,
    )

    if not previous_selected_target_id:
        current_row = table.currentRow()
        if current_row >= 0:
            item = table.item(current_row, 0)
            if item is not None:
                previous_selected_target_id = (
                    item.data(QtCore.Qt.UserRole)
                    or item.text()
                )

    if previous_selected_target_id:
        previous_selected_target_id = str(previous_selected_target_id)

    visible_target_ids = []

    for row in range(table.rowCount()):
        item = table.item(row, 0)

        if item is None:
            continue

        target_id = item.data(QtCore.Qt.UserRole) or item.text()

        if target_id:
            visible_target_ids.append(str(target_id))

    full_reload = not bool(visible_target_ids)

    update_tactical_node_targets_table(
        dashboard,
        target_ids=visible_target_ids if visible_target_ids else None,
        selected_target_id=previous_selected_target_id,
        select_first_if_no_match=full_reload,
    )


def update_tactical_node_targets_table(
    dashboard: QtCore.QObject,
    target_ids=None,
    selected_target_id=None,
    select_first_if_no_match=False,
):
    table = dashboard.ui.tableWidget_tactical_node_targets

    table.blockSignals(True)
    table.setRowCount(0)

    dashboard.selected_tactical_node_target_id = None
    clear_tactical_node_target_details(dashboard)

    if target_ids is not None:
        target_ids = {str(target_id) for target_id in target_ids if target_id}

    if selected_target_id:
        selected_target_id = str(selected_target_id)

    node_uid = dashboard.selected_tactical_node_uid
    if not node_uid:
        table.blockSignals(False)
        return

    node = dashboard.tactical_nodes.get(node_uid)
    if not node:
        table.blockSignals(False)
        return

    node_lat = node.get("lat")
    node_lon = node.get("lon")

    if not fissure.utils.common.is_valid_lat_lon(node_lat, node_lon):
        table.blockSignals(False)
        return

    rows = []

    for target_id, target in dashboard.tactical_targets.items():
        target_id = str(target_id)

        # Filtered refresh: only rebuild rows already visible in Node > Targets.
        if target_ids is not None and target_id not in target_ids:
            continue

        target_lat = target.get("lat")
        target_lon = target.get("lon")

        if not fissure.utils.common.is_valid_lat_lon(target_lat, target_lon):
            continue

        try:
            distance_m = fissure.utils.common.haversine_m(
                node_lat,
                node_lon,
                target_lat,
                target_lon,
            )
        except Exception:
            continue

        rows.append((distance_m, target_id, target))

    rows.sort(key=lambda x: x[0])

    selected_row = -1

    for distance_m, target_id, target in rows:
        row = table.rowCount()
        table.insertRow(row)

        distance_item = QtWidgets.QTableWidgetItem(
            format_tactical_distance(distance_m)
        )
        type_item = QtWidgets.QTableWidgetItem(
            str(target.get("type", ""))
        )
        state_item = QtWidgets.QTableWidgetItem(
            str(target.get("state", ""))
        )

        for item in [distance_item, type_item, state_item]:
            item.setData(QtCore.Qt.UserRole, target_id)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
            item.setToolTip(target_id)

        table.setItem(row, 0, distance_item)
        table.setItem(row, 1, type_item)
        table.setItem(row, 2, state_item)

        if selected_target_id and target_id == selected_target_id:
            selected_row = row

    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setStretchLastSection(True)

    table.blockSignals(False)

    if selected_row < 0 and select_first_if_no_match and table.rowCount() > 0:
        selected_row = 0

    if selected_row >= 0:
        table.selectRow(selected_row)
        table.setCurrentCell(selected_row, 0)
        _slotTacticalNodeTargetsRowSelectionChanged(dashboard)
    else:
        clear_tactical_node_target_details(dashboard)


def format_tactical_distance(distance_m):
    try:
        distance_m = float(distance_m)
    except Exception:
        return ""

    if distance_m < 1000:
        return f"{distance_m:.0f} m"

    return f"{distance_m / 1000.0:.2f} km"


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeTargetsRowSelectionChanged(
    dashboard: QtCore.QObject,
):
    table = dashboard.ui.tableWidget_tactical_node_targets

    selected_items = table.selectedItems()

    if not selected_items:
        clear_tactical_node_target_details(dashboard)
        return

    row = selected_items[0].row()

    id_item = table.item(row, 0)

    if id_item is None:
        clear_tactical_node_target_details(dashboard)
        return

    target_id = (
        id_item.data(QtCore.Qt.UserRole)
        or id_item.text()
    )

    target = dashboard.tactical_targets.get(
        target_id,
        {},
    )

    dashboard.selected_tactical_node_target_id = target_id

    distance_item = table.item(row, 0)

    distance_text = (
        distance_item.text()
        if distance_item
        else ""
    )

    lat = target.get("lat")
    lon = target.get("lon")
    ce_m = target.get("ce_m")

    location_text = ""

    if (
        lat not in [None, "", "None"]
        and lon not in [None, "", "None"]
    ):
        try:
            location_text = (
                f"{float(lat):.6f}, "
                f"{float(lon):.6f}"
            )
        except Exception:
            location_text = f"{lat}, {lon}"

        if ce_m not in [None, "", "None"]:
            location_text += f"  CE {ce_m} m"

    frequency = target.get(
        "target_frequency_mhz",
        "",
    )

    if frequency not in [None, "", "None"]:
        try:
            frequency = f"{float(frequency):.3f}"
        except Exception:
            pass
    else:
        frequency = ""

    full_target_id = str(
        target.get(
            "target_id",
            target_id,
        )
        or ""
    )

    dashboard.ui.label2_tactical_node_targets_target_id.setText(
        shorten_target_id(
            full_target_id,
            max_len=32,
        )
    )

    dashboard.ui.label2_tactical_node_targets_target_id.setToolTip(
        full_target_id
    )

    dashboard.ui.label2_tactical_node_targets_display_label.setText(
        str(
            target.get(
                "type",
                "",
            )
        )
    )

    dashboard.ui.label2_tactical_node_targets_distance.setText(
        str(distance_text)
    )

    dashboard.ui.label2_tactical_node_targets_state.setText(
        str(
            target.get(
                "state",
                "",
            )
        )
    )

    dashboard.ui.label2_tactical_node_targets_location.setText(
        location_text
    )

    dashboard.ui.label2_tactical_node_targets_frequency.setText(
        str(frequency)
    )

    enable_tactical_node_target_details(
        dashboard,
        True,
    )


def clear_tactical_node_target_details(
    dashboard: QtCore.QObject,
):
    dashboard.selected_tactical_node_target_id = None

    labels = [
        dashboard.ui.label2_tactical_node_targets_target_id,
        dashboard.ui.label2_tactical_node_targets_display_label,
        dashboard.ui.label2_tactical_node_targets_distance,
        dashboard.ui.label2_tactical_node_targets_state,
        dashboard.ui.label2_tactical_node_targets_location,
        dashboard.ui.label2_tactical_node_targets_frequency,
    ]

    for label in labels:
        label.setText("")

    dashboard.ui.label2_tactical_node_targets_target_id.setToolTip("")

    enable_tactical_node_target_details(
        dashboard,
        False,
    )

    update_tactical_targets_geolocate_button_state(
        dashboard,
        None,
    )


def enable_tactical_node_target_details(
    dashboard: QtCore.QObject,
    enabled=True,
):
    widgets = [
        dashboard.ui.frame5_tactical_node_targets_details,
        dashboard.ui.label2_tactical_node_targets_target_id2,
        dashboard.ui.label2_tactical_node_targets_display_label2,
        dashboard.ui.label2_tactical_node_targets_distance2,
        dashboard.ui.label2_tactical_node_targets_state2,
        dashboard.ui.label2_tactical_node_targets_location2,
        dashboard.ui.label2_tactical_node_targets_frequency2,
        dashboard.ui.label2_tactical_node_targets_target_id,
        dashboard.ui.label2_tactical_node_targets_display_label,
        dashboard.ui.label2_tactical_node_targets_distance,
        dashboard.ui.label2_tactical_node_targets_state,
        dashboard.ui.label2_tactical_node_targets_location,
        dashboard.ui.label2_tactical_node_targets_frequency,
        dashboard.ui.pushButton_tactical_node_targets_query_actions,
    ]

    for widget in widgets:
        widget.setEnabled(enabled)

    dashboard.ui.pushButton_tactical_node_targets_refresh_targets.setEnabled(
        bool(
            getattr(
                dashboard,
                "selected_tactical_node_uid",
                None,
            )
        )
    )


def clear_tactical_node_targets(dashboard: QtCore.QObject):
    dashboard.selected_tactical_node_target_id = None

    dashboard.ui.tableWidget_tactical_node_targets.setRowCount(0)

    clear_tactical_node_target_details(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeTargetsPlotClicked(dashboard: QtCore.QObject):
    target_id = getattr(dashboard, "selected_tactical_node_target_id", None)
    if not target_id:
        return

    target = dashboard.tactical_targets.get(target_id)
    if not target:
        return

    plot_tactical_target(dashboard, target, zoom=False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeTargetsPlotZoomClicked(dashboard: QtCore.QObject):
    target_id = getattr(dashboard, "selected_tactical_node_target_id", None)
    if not target_id:
        return

    target = dashboard.tactical_targets.get(target_id)
    if not target:
        return

    plot_tactical_target(dashboard, target, zoom=True) 


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeTargetsRemoveClicked(dashboard: QtCore.QObject):
    target_id = getattr(dashboard, "selected_tactical_node_target_id", None)
    if not target_id:
        return

    dashboard.tactical_map.remove_target(target_id)       


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeTargetsQueryActionsClicked(dashboard: QtCore.QObject):
    """
    Queries the hub for plugin actions for a selected target.
    """
    uid = dashboard.ui.label2_tactical_node_uuid.text().strip()

    plugin_name = str(
        dashboard.ui.comboBox_tactical_node_plugins.currentText()
    ).strip()

    target_id = getattr(dashboard, "selected_tactical_node_target_id", None)

    if not uid:
        dashboard.logger.warning(
            "[Tactical] No node UID selected for plugin action query."
        )
        return

    if not plugin_name:
        dashboard.logger.warning(
            "[Tactical] No plugin selected for plugin action query."
        )
        return
    
    if not target_id:
        dashboard.logger.warning(
            "[Tactical] No target selected for target action query."
        )
        return
    
    await dashboard.backend.tacticalNodeTargetsQueryActions(
        uid, 
        plugin_name,
        target_id,
    )


@QtCore.pyqtSlot(QtCore.QObject, str)
def _slotTacticalNodeTargetsDoubleClicked(dashboard: QtCore.QObject, item):
    """
    Plots the target on the map from the Node>Targets table.
    """
    _slotTacticalNodeTargetsPlotZoomClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeTargetsMoreDetailsClicked(dashboard: QtCore.QObject):
    """
    Selects the matching target row in the Targets tab table from the selected item in the Node>Targets table.
    """
    target_id = getattr(dashboard, "selected_tactical_node_target_id", None)
    if not target_id:
        return

    # Switch to Targets tab
    dashboard.ui.tabWidget_tactical.setCurrentIndex(1)

    table = dashboard.ui.tableWidget_tactical_targets

    for row in range(table.rowCount()):
        id_item = table.item(row, 0)

        if id_item is None:
            continue

        row_target_id = (
            id_item.data(QtCore.Qt.UserRole)
            or id_item.text()
        )

        if row_target_id == target_id:
            table.blockSignals(True)
            table.selectRow(row)
            table.blockSignals(False)

            dashboard.selected_tactical_target_id = target_id

            _slotTacticalTargetsRowSelectionChanged(
                dashboard
            )

            table.scrollToItem(id_item)

            return


def update_tactical_node_soi_row(dashboard: QtCore.QObject, soi_record: dict):
    selected_node_uid = getattr(dashboard, "selected_tactical_node_uid", None)
    soi_node_uid = soi_record.get("node_uid")

    if not selected_node_uid:
        return

    if soi_node_uid != selected_node_uid:
        return

    table = dashboard.ui.tableWidget_tactical_node_sois

    soi_key = soi_record.get("soi_key")
    if not soi_key:
        return

    was_empty = table.rowCount() == 0

    row = None

    for r in range(table.rowCount()):
        item = table.item(r, 0)
        if item and item.data(QtCore.Qt.UserRole) == soi_key:
            row = r
            break

    if row is None:
        row = 0
        table.insertRow(row)

    frequency_text = ""

    frequency_mhz = soi_record.get("frequency_mhz")

    if frequency_mhz not in [None, "", "None"]:
        try:
            frequency_text = f"{float(frequency_mhz):.3f}"
        except Exception:
            frequency_text = str(frequency_mhz)

    frequency_item = QtWidgets.QTableWidgetItem(
        frequency_text
    )

    status_item = QtWidgets.QTableWidgetItem(
        str(soi_record.get("status", ""))
    )

    time_item = QtWidgets.QTableWidgetItem(
        format_detection_time(soi_record.get("time", ""))
    )

    tooltip = (
        f"SOI ID: {soi_record.get('soi_id', '')}\n"
        f"Node ID: {soi_record.get('node_uid', '')}"
    )

    for item in [frequency_item, status_item, time_item]:
        item.setData(QtCore.Qt.UserRole, soi_key)
        item.setToolTip(tooltip)
        item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)

    table.setItem(row, 0, frequency_item)
    table.setItem(row, 1, status_item)
    table.setItem(row, 2, time_item)

    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setStretchLastSection(True)

    if was_empty:
        table.selectRow(row)
        table.setCurrentCell(row, 0)
    
    if dashboard.selected_tactical_node_soi_id == soi_key:
        _slotTacticalNodeSoisRowSelectionChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeSoisRowSelectionChanged(
    dashboard: QtCore.QObject,
):
    table = dashboard.ui.tableWidget_tactical_node_sois
    selected_items = table.selectedItems()

    if not selected_items:
        clear_tactical_node_soi_details(dashboard)
        return

    row = selected_items[0].row()
    item = table.item(row, 0)

    if item is None:
        clear_tactical_node_soi_details(dashboard)
        return

    soi_key = item.data(QtCore.Qt.UserRole)

    if not soi_key:
        clear_tactical_node_soi_details(dashboard)
        return

    soi = dashboard.tactical_sois.get(soi_key)

    if not isinstance(soi, dict) or not soi:
        clear_tactical_node_soi_details(dashboard)
        return

    dashboard.selected_tactical_node_soi_id = soi_key

    populate_tactical_node_soi_details(
        dashboard,
        soi,
    )

    enable_tactical_node_soi_details(
        dashboard,
        True,
    )


def clear_tactical_node_soi_details(
    dashboard: QtCore.QObject,
):
    dashboard.selected_tactical_node_soi_id = None

    dashboard.ui.label2_tactical_node_soi_details.setText("")

    enable_tactical_node_soi_details(
        dashboard,
        False,
    )


def initialize_tactical_node_soi_details_context_menu(
    dashboard: QtCore.QObject,
):
    """
    Adds a Full Details toggle to the SOI details label context menu.

    QLabel does not expose QTextEdit.createStandardContextMenu(), so Copy and
    Select All are recreated here with the same expected behavior.
    """
    label = dashboard.ui.label2_tactical_node_soi_details

    label.setContextMenuPolicy(
        QtCore.Qt.CustomContextMenu
    )

    label.customContextMenuRequested.connect(
        lambda position: _showTacticalNodeSoiDetailsContextMenu(
            dashboard,
            position,
        )
    )


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QPoint)
def _showTacticalNodeSoiDetailsContextMenu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    label = dashboard.ui.label2_tactical_node_soi_details

    menu = QtWidgets.QMenu(label)

    action_full_details = menu.addAction(
        "Full Details"
    )
    action_full_details.setCheckable(True)
    action_full_details.setChecked(
        bool(
            getattr(
                dashboard,
                "tactical_node_soi_full_details",
                False,
            )
        )
    )

    menu.addSeparator()

    action_copy = menu.addAction("Copy")
    action_select_all = menu.addAction("Select All")

    has_text = bool(
        label.text().strip()
    )
    has_selection = bool(
        label.hasSelectedText()
    )

    action_copy.setEnabled(
        has_selection
    )
    action_select_all.setEnabled(
        has_text
    )

    selected_action = menu.exec_(
        label.mapToGlobal(position)
    )

    if selected_action == action_full_details:
        dashboard.tactical_node_soi_full_details = (
            action_full_details.isChecked()
        )

        soi_key = getattr(
            dashboard,
            "selected_tactical_node_soi_id",
            None,
        )

        soi = (
            dashboard.tactical_sois.get(soi_key)
            if soi_key
            else None
        )

        if isinstance(soi, dict) and soi:
            populate_tactical_node_soi_details(
                dashboard,
                soi,
            )

    elif selected_action == action_copy:
        selected_text = label.selectedText()

        if selected_text:
            QtWidgets.QApplication.clipboard().setText(
                selected_text
            )

    elif selected_action == action_select_all:
        label.setSelection(
            0,
            len(label.text()),
        )


def populate_tactical_node_soi_details(
    dashboard: QtCore.QObject,
    soi: dict,
):
    """
    Displays either a curated SOI summary or the complete dynamic record.

    Summary mode prioritizes the fields normally needed during Tactical review.
    Full Details mode preserves the field-agnostic renderer for every non-empty
    field except raw transport payloads.
    """
    hidden_keys = {
        "raw_xml",
        "cot_xml",
        "xml",
        "raw_message",
        "raw_payload",
    }

    summary_field_groups = [
        (
            "SOI ID",
            [
                "soi_id",
                "uid",
                "id",
            ],
        ),
        (
            "Model Classification",
            [
                "model_classification_display",
                "model_classification",
                "classification",
            ],
        ),
        (
            "Database Classification",
            [
                "database_classification",
                "database_match",
                "database",
            ],
        ),
        (
            "Latitude",
            [
                "lat",
                "latitude",
            ],
        ),
        (
            "Longitude",
            [
                "lon",
                "longitude",
            ],
        ),
    ]

    def is_empty(value):
        if value is None:
            return True

        if isinstance(value, str):
            return value.strip() in [
                "",
                "None",
            ]

        if isinstance(
            value,
            (
                dict,
                list,
                tuple,
                set,
            ),
        ):
            return len(value) == 0

        return False

    def make_label(key):
        return str(
            key
        ).strip().replace(
            "_",
            " ",
        ).strip().title()

    def field_label_html(label):
        return (
            "<span style='font-weight:500;'>"
            f"{html.escape(str(label))}:"
            "</span>"
        )

    def format_scalar(key, value):
        normalized_key = str(
            key
        ).strip().lower()

        if normalized_key in {
            "time",
            "timestamp",
            "created_at",
            "updated_at",
        }:
            formatted_time = format_detection_time(
                value
            )

            if formatted_time:
                return formatted_time

        if normalized_key in {
            "frequency_mhz",
            "center_frequency_mhz",
            "start_frequency_mhz",
            "end_frequency_mhz",
        }:
            try:
                return f"{float(value):.6f} MHz"
            except Exception:
                pass

        if normalized_key in {
            "frequency_hz",
            "center_frequency_hz",
            "start_frequency_hz",
            "end_frequency_hz",
        }:
            try:
                return f"{float(value) / 1e6:.6f} MHz"
            except Exception:
                pass

        if normalized_key in {
            "frequency",
            "center_frequency",
        }:
            try:
                numeric_value = float(value)

                if abs(numeric_value) >= 1e5:
                    return f"{numeric_value / 1e6:.6f} MHz"

                return f"{numeric_value:.6f} MHz"
            except Exception:
                pass

        if normalized_key == "bandwidth_hz":
            try:
                return f"{float(value) / 1e3:.3f} kHz"
            except Exception:
                pass

        if normalized_key == "bandwidth_mhz":
            try:
                return f"{float(value):.6f} MHz"
            except Exception:
                pass

        if normalized_key == "bandwidth":
            try:
                numeric_value = float(value)

                if abs(numeric_value) >= 1e5:
                    return f"{numeric_value / 1e6:.6f} MHz"

                if abs(numeric_value) >= 1e3:
                    return f"{numeric_value / 1e3:.3f} kHz"

                return str(value)
            except Exception:
                pass

        if normalized_key in {
            "power",
            "power_dbm",
            "signal_power_dbm",
        }:
            try:
                return f"{float(value):.1f} dBm"
            except Exception:
                pass

        if normalized_key in {
            "confidence",
            "model_confidence",
            "classification_confidence",
            "database_confidence",
        }:
            try:
                confidence = float(value)

                if 0.0 <= confidence <= 1.0:
                    confidence *= 100.0

                return f"{confidence:.1f}%"
            except Exception:
                pass

        return str(value)

    def first_non_empty_value(candidate_keys):
        for candidate_key in candidate_keys:
            if candidate_key not in soi:
                continue

            value = soi.get(candidate_key)

            if not is_empty(value):
                return candidate_key, value

        return None, None

    def append_value(
        lines,
        key,
        value,
        depth=0,
        display_label=None,
    ):
        normalized_key = str(
            key
        ).strip().lower()

        if normalized_key in hidden_keys:
            return

        if is_empty(value):
            return

        label = (
            str(display_label)
            if display_label is not None
            else make_label(key)
        )

        indent = "&nbsp;" * (
            depth * 4
        )

        if isinstance(value, dict):
            lines.append(
                f"{indent}{field_label_html(label)}"
            )

            for nested_key, nested_value in value.items():
                append_value(
                    lines,
                    nested_key,
                    nested_value,
                    depth + 1,
                )

            return

        if isinstance(
            value,
            (
                list,
                tuple,
                set,
            ),
        ):
            values = list(value)

            if not values:
                return

            lines.append(
                f"{indent}{field_label_html(label)}"
            )

            for index, item in enumerate(values):
                if is_empty(item):
                    continue

                if isinstance(item, dict):
                    item_label = (
                        item.get("label")
                        or item.get("name")
                        or f"Item {index + 1}"
                    )

                    item_value = item.get("value")

                    if (
                        "value" in item
                        and not is_empty(item_value)
                    ):
                        unit = str(
                            item.get("unit", "")
                            or ""
                        ).strip()

                        display_value = str(
                            item_value
                        )

                        if unit:
                            display_value = (
                                f"{display_value} {unit}"
                            )

                        lines.append(
                            f"{'&nbsp;' * ((depth + 1) * 4)}"
                            f"{field_label_html(item_label)} "
                            f"{html.escape(display_value)}"
                        )

                        remaining = {
                            nested_key: nested_value
                            for nested_key, nested_value in item.items()
                            if nested_key not in {
                                "label",
                                "name",
                                "value",
                                "unit",
                            }
                        }

                        for nested_key, nested_value in remaining.items():
                            append_value(
                                lines,
                                nested_key,
                                nested_value,
                                depth + 2,
                            )

                    else:
                        lines.append(
                            f"{'&nbsp;' * ((depth + 1) * 4)}"
                            f"<span style='font-weight:600;'>"
                            f"{html.escape(str(item_label))}"
                            f"</span>"
                        )

                        for nested_key, nested_value in item.items():
                            append_value(
                                lines,
                                nested_key,
                                nested_value,
                                depth + 2,
                            )

                else:
                    lines.append(
                        f"{'&nbsp;' * ((depth + 1) * 4)}"
                        f"{html.escape(str(item))}"
                    )

            return

        display_value = format_scalar(
            normalized_key,
            value,
        )

        lines.append(
            f"{indent}{field_label_html(label)} "
            f"{html.escape(display_value)}"
        )

    full_details = bool(
        getattr(
            dashboard,
            "tactical_node_soi_full_details",
            False,
        )
    )

    lines = []

    if full_details:
        for key, value in soi.items():
            append_value(
                lines,
                key,
                value,
            )

    else:
        used_keys = set()

        for display_label, candidate_keys in summary_field_groups:
            actual_key, value = first_non_empty_value(
                candidate_keys
            )

            if actual_key is None:
                continue

            used_keys.add(actual_key)

            append_value(
                lines,
                actual_key,
                value,
                display_label=display_label,
            )

    dashboard.ui.label2_tactical_node_soi_details.setText(
        "<br>".join(lines)
    )

    dashboard.ui.label2_tactical_node_soi_details.setAlignment(
        QtCore.Qt.AlignLeft
        | QtCore.Qt.AlignTop
    )


def enable_tactical_node_soi_details(
    dashboard: QtCore.QObject,
    enabled=True,
):
    widgets = [
        dashboard.ui.scrollArea_tactical_node_soi_details,
        dashboard.ui.label2_tactical_node_soi_details,
        dashboard.ui.pushButton_tactical_node_soi_download_evidence,
        dashboard.ui.pushButton_tactical_node_soi_promote_to_target,
    ]

    for widget in widgets:
        widget.setEnabled(enabled)


def enable_tactical_node_detection_details(
    dashboard: QtCore.QObject,
    enabled=True,
):
    widgets = [
        dashboard.ui.scrollArea_tactical_node_detection_details,
        dashboard.ui.label2_tactical_node_detection_details,
        dashboard.ui.pushButton_tactical_node_detections_promote_to_soi,
        dashboard.ui.pushButton_tactical_node_detections_promote_to_target,
    ]

    for widget in widgets:
        widget.setEnabled(enabled)


def plot_tactical_node_soi(dashboard: QtCore.QObject, soi: dict, zoom=False):
    soi_key = soi.get("soi_key")
    if not soi_key:
        return

    lat = soi.get("lat")
    lon = soi.get("lon")

    if lat in [None, "", "None"] or lon in [None, "", "None"]:
        return

    try:
        lat = float(lat)
        lon = float(lon)
    except Exception:
        return

    label = soi.get("soi_id") or soi_key

    dashboard.tactical_map.add_soi(
        soi_id=soi_key,
        lat=lat,
        lon=lon,
        label=label,
    )

    if zoom:
        dashboard.tactical_map.center_on_latlon(lat, lon)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeSoisPlotClicked(dashboard: QtCore.QObject):
    soi_key = getattr(dashboard, "selected_tactical_node_soi_id", None)
    if not soi_key:
        return

    soi = dashboard.tactical_sois.get(soi_key)
    if not soi:
        return

    plot_tactical_node_soi(dashboard, soi, zoom=False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeSoisPlotZoomClicked(dashboard: QtCore.QObject):
    soi_key = getattr(dashboard, "selected_tactical_node_soi_id", None)
    if not soi_key:
        return

    soi = dashboard.tactical_sois.get(soi_key)
    if not soi:
        return

    plot_tactical_node_soi(dashboard, soi, zoom=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeSoisRemoveClicked(dashboard: QtCore.QObject):
    soi_key = getattr(dashboard, "selected_tactical_node_soi_id", None)
    if not soi_key:
        return

    dashboard.tactical_map.remove_soi(soi_key)


@QtCore.pyqtSlot(QtCore.QObject, QtWidgets.QTableWidgetItem)
def _slotTacticalNodeSoisDoubleClicked(dashboard: QtCore.QObject, item):
    _slotTacticalNodeSoisPlotZoomClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject, str)
def _slotTacticalNodeSoiMapClicked(dashboard: QtCore.QObject, soi_key):
    dashboard.ui.tabWidget_tactical.setCurrentIndex(0)  # Node tab

    table = dashboard.ui.tableWidget_tactical_node_sois

    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is None:
            continue

        row_soi_key = item.data(QtCore.Qt.UserRole)

        if row_soi_key == soi_key:
            table.blockSignals(True)
            table.selectRow(row)
            table.blockSignals(False)

            dashboard.selected_tactical_node_soi_id = soi_key

            _slotTacticalNodeSoisRowSelectionChanged(dashboard)

            table.scrollToItem(item)
            return


def update_tactical_node_artifact_row(dashboard: QtCore.QObject, artifact_record: dict):
    table = dashboard.ui.tableWidget_tactical_node_artifacts

    artifact_id = artifact_record.get("artifact_id")
    if not artifact_id:
        return

    was_empty = table.rowCount() == 0

    row = None

    for r in range(table.rowCount()):
        item = table.item(r, 0)
        if item and item.data(QtCore.Qt.UserRole) == artifact_id:
            row = r
            break

    if row is None:
        row = 0
        table.insertRow(row)

    name_item = QtWidgets.QTableWidgetItem(
        str(artifact_record.get("name", ""))
    )

    time_item = QtWidgets.QTableWidgetItem(
        format_detection_time(artifact_record.get("time", ""))
    )

    for item in [name_item, time_item]:
        item.setData(QtCore.Qt.UserRole, artifact_id)
        item.setToolTip(f"Artifact ID: {artifact_id}")
        item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)

    table.setItem(row, 0, name_item)
    table.setItem(row, 1, time_item)

    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setStretchLastSection(True)

    table.selectRow(row)
    table.setCurrentCell(row, 0)
    _slotTacticalNodeArtifactsRowSelectionChanged(dashboard)

    enable_tactical_artifacts_details(dashboard, True)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeSoisDownloadEvidenceClicked(
    dashboard: QtCore.QObject
):
    soi_key = getattr(
        dashboard,
        "selected_tactical_node_soi_id",
        None,
    )
    if not soi_key:
        return

    soi = dashboard.tactical_sois.get(soi_key)
    if not soi:
        return

    artifact_id = soi.get("artifact_id")
    if not artifact_id:
        dashboard.logger.warning(
            "[Tactical] Selected SOI has no artifact ID."
        )
        return

    table = dashboard.ui.tableWidget_tactical_node_artifacts
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is None:
            continue
        if item.data(QtCore.Qt.UserRole) == artifact_id:
            dashboard.ui.tabWidget_tactical_node.setCurrentIndex(3)
            table.selectRow(row)
            table.setCurrentCell(row, 0)
            table.scrollToItem(item)
            break

    local_path = dashboard.backend.artifact_transfer_controller.get_local_path(
        artifact_id
    )
    if local_path:
        subprocess.Popen(["xdg-open", os.path.dirname(local_path)])
        return

    try:
        await dashboard.backend.requestDashboardArtifactDownload(
            artifact_id,
            open_when_complete=True,
        )
    except Exception as exc:
        dashboard.logger.error(
            f"[Tactical] SOI evidence download request failed: {exc}"
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeArtifactsOpenFolderClicked(
    dashboard: QtCore.QObject
):
    artifact_id = getattr(
        dashboard,
        "selected_tactical_node_artifact_id",
        None,
    )
    if not artifact_id:
        return

    local_path = dashboard.backend.artifact_transfer_controller.get_local_path(
        artifact_id
    )
    if local_path:
        subprocess.Popen(["xdg-open", os.path.dirname(local_path)])
        return

    dashboard.logger.warning(
        f"[Tactical] Artifact has not been downloaded: {artifact_id}"
    )
    dashboard.statusBar().showMessage(
        "Artifact has not been downloaded",
        5000,
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeArtifactsRowSelectionChanged(
    dashboard: QtCore.QObject,
):
    table = dashboard.ui.tableWidget_tactical_node_artifacts

    selected_items = table.selectedItems()

    if not selected_items:
        clear_tactical_node_artifact_details(
            dashboard
        )
        return

    row = selected_items[0].row()

    item = table.item(row, 0)
    if item is None:
        clear_tactical_node_artifact_details(
            dashboard
        )
        return

    artifact_id = item.data(QtCore.Qt.UserRole)
    if not artifact_id:
        clear_tactical_node_artifact_details(
            dashboard
        )
        return

    artifact = dashboard.tactical_artifacts.get(
        artifact_id,
        {},
    )

    if not isinstance(artifact, dict) or not artifact:
        clear_tactical_node_artifact_details(
            dashboard
        )
        return

    dashboard.selected_tactical_node_artifact_id = artifact_id

    populate_tactical_node_artifact_details(
        dashboard,
        artifact,
    )

    enable_tactical_artifacts_details(
        dashboard,
        True,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalTargetsQueryActionsClicked(dashboard: QtCore.QObject):
    """
    Queries the hub for plugin actions for the selected target from the Targets tab.
    Uses the currently selected tactical node and currently selected node plugin.
    """
    target_id = getattr(
        dashboard,
        "selected_tactical_target_id",
        None,
    )

    if not target_id:
        dashboard.logger.warning(
            "[Tactical] No target selected for target action query."
        )
        return

    target = dashboard.tactical_targets.get(target_id)
    if not target:
        dashboard.logger.warning(
            f"[Tactical] Target record not found for target_id={target_id}"
        )
        return

    uid = dashboard.ui.label2_tactical_node_uuid.text().strip()

    plugin_name = str(
        dashboard.ui.comboBox_tactical_node_plugins.currentText()
    ).strip()

    if not uid:
        dashboard.logger.warning(
            "[Tactical] No node UID selected for target action query."
        )
        dashboard.ui.tabWidget_tactical.setCurrentIndex(0)
        return

    if not plugin_name:
        dashboard.logger.warning(
            "[Tactical] No plugin selected for target action query."
        )
        dashboard.ui.tabWidget_tactical.setCurrentIndex(0)
        return

    dashboard.ui.tabWidget_tactical.setCurrentIndex(0)

    await dashboard.backend.tacticalNodeTargetsQueryActions(
        uid,
        plugin_name,
        target_id,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeDetectionsPromoteToSoiClicked(
    dashboard: QtCore.QObject,
):
    """
    Promote the complete selected Tactical detection directly to an
    authoritative SOI at HIPRFISR.
    """
    detection = get_selected_tactical_node_detection(
        dashboard
    )

    if not detection:
        dashboard.logger.warning(
            "[Tactical] Select a detection before promoting it to an SOI."
        )
        return

    await dashboard.backend.promoteDetection(
        detection=dict(detection),
        destination="soi",
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeDetectionsPromoteToTargetClicked(
    dashboard: QtCore.QObject,
):
    """
    Promote the complete selected Tactical detection directly to an
    authoritative Target at HIPRFISR.
    """
    detection = get_selected_tactical_node_detection(
        dashboard
    )

    if not detection:
        dashboard.logger.warning(
            "[Tactical] Select a detection before promoting it to a Target."
        )
        return

    await dashboard.backend.promoteDetection(
        detection=dict(detection),
        destination="target",
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeSoiPromoteToTargetClicked(
    dashboard: QtCore.QObject
):
    soi_key = getattr(dashboard, "selected_tactical_node_soi_id", None)
    if not soi_key:
        return

    soi = dashboard.tactical_sois.get(soi_key)
    if not soi:
        return

    soi_id = soi.get("soi_id", "")
    frequency_mhz = soi.get("frequency_mhz")
    node_uid = soi.get("node_uid", "")
    artifact_id = soi.get("artifact_id", "")

    display_label = (
        soi.get("database_classification")
        or soi.get("model_classification")
        or "SOI"
    )

    target_id = f"soi-{soi_id}"

    patch = {
        "target_id": target_id,
        "node_uid": node_uid,
        "source_soi_id": soi_id,
        "frequency_mhz": frequency_mhz,
        "classification": {
            "display_label": display_label,
            "candidates": [
                {
                    "source": "database",
                    "label": soi.get("database_classification", ""),
                },
                {
                    "source": "model",
                    "label": soi.get("model_classification", ""),
                    "confidence": soi.get("model_confidence_pct", ""),
                },
            ],
        },
        "location": {
            "lat": soi.get("lat"),
            "lon": soi.get("lon"),
            "hae_m": soi.get("hae_m"),
            "ce_m": 100,
            "source": "soi",
        },
        "state": "imported",
        "artifact_id": artifact_id,
    }

    history_entry = {
        "event": "soi_promoted_to_target",
        "soi_id": soi_id,
        "artifact_id": artifact_id,
        "operation_id": soi.get("operation_id", ""),
    }

    await dashboard.backend.tacticalPromoteSoiToTarget(
        target_id=target_id,
        patch=patch,
        history_entry=history_entry,
        artifact_id=artifact_id,
    )


def get_target_geolocate_status(target: dict):
    geolocate = target.get("geolocate") or {}
    return geolocate.get("status", "") or target.get("geolocation_status", "")


def update_tactical_targets_geolocate_button_state(
    dashboard,
    target=None,
):
    button = dashboard.ui.pushButton_tactical_targets_geolocate

    if not target:
        button.setText("Geolocate")
        button.setEnabled(False)
        return

    status = str(
        target.get("geolocation_status", "idle")
    ).lower()

    if status in ["starting", "running"]:
        button.setText("Stop Geolocate")
        button.setEnabled(True)
    elif status == "stopping":
        button.setText("Stopping...")
        button.setEnabled(False)
    else:
        button.setText("Geolocate")
        button.setEnabled(True)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalTargetsGeolocateClicked(dashboard: QtCore.QObject):
    target_id = getattr(dashboard, "selected_tactical_target_id", None)
    if not target_id:
        return

    target = dashboard.tactical_targets.get(target_id)
    if not target:
        return

    status = get_target_geolocate_status(target)

    search_similar_targets = (
        dashboard.ui.checkBox_tactical_targets_search_similar_targets.isChecked()
    )

    if status in ["starting", "running"]:
        await dashboard.backend.tacticalTargetsGeolocateStop(
            target_id=target_id,
        )
    else:
        await dashboard.backend.tacticalTargetsGeolocateStart(
            target_id=target_id,
            search_similar_targets=search_similar_targets,
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeActionChanged(dashboard: QtCore.QObject):
    """
    Clears currently displayed parameter widgets whenever the
    selected action changes so stale parameters are not reused.
    """
    clear_tactical_node_action_parameters(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodePluginChanged(dashboard: QtCore.QObject):
    """
    Clears the list of actions and action parameters upon changing the plugin.
    
    :param dashboard: Description
    :type dashboard: QtCore.QObject
    """
    clear_tactical_node_action_controls(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemActionChanged(dashboard: QtCore.QObject):
    """
    Clears currently displayed parameter widgets whenever the
    selected action changes so stale parameters are not reused.
    """
    clear_tactical_ecosystem_action_parameters(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemPluginChanged(dashboard: QtCore.QObject):
    """
    Clears the list of actions and action parameters in the Ecosystem tab upon changing the plugin.
    
    :param dashboard: Description
    :type dashboard: QtCore.QObject
    """
    clear_tactical_ecosystem_action_controls(dashboard)


def _refresh_frame_style(frame):
    frame.style().unpolish(frame)
    frame.style().polish(frame)
    frame.update()


def _clickableFramePressed(frame: QtWidgets.QFrame, event: QtCore.QEvent):
    if event.button() != QtCore.Qt.LeftButton:
        return

    if frame.property("clickable") != "true":
        return

    frame.setProperty("pressed", "true")
    _refresh_frame_style(frame)


def _clickableFrameReleased(dashboard, frame: QtWidgets.QFrame, event: QtCore.QEvent, callback):
    if event.button() != QtCore.Qt.LeftButton:
        return

    frame.setProperty("pressed", "false")
    _refresh_frame_style(frame)

    if not frame.rect().contains(event.pos()):
        return

    if frame.property("clickable") != "true":
        return

    result = callback(dashboard)

    if asyncio.iscoroutine(result):
        asyncio.create_task(result)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSetTacticalNodeActiveClicked(dashboard: QtCore.QObject):
    """
    Promote the currently selected Tactical node to the dashboard-selected sensor node.
    """
    node_uid = getattr(dashboard, "selected_tactical_node_uid", None)

    if not node_uid:
        dashboard.logger.warning("No Tactical node is selected.")
        return

    # Already active
    if getattr(dashboard, "selected_node_uid", None) == node_uid:
        dashboard.logger.debug("Tactical node is already the dashboard-selected node.")
        return

    dashboard.logger.info(f"Setting Tactical node as active selected node: {node_uid}")

    try:
        await dashboard.backend.nodeSelectIP(node_uid=node_uid)
    except TypeError:
        # Use this fallback if your backend wrapper expects the UUID positionally.
        await dashboard.backend.nodeSelectIP(node_uid)
    except Exception as e:
        dashboard.logger.error(f"Failed to select Tactical node through HIPRFISR: {e}")
        return


def _updateTacticalNodeInfoFrameState(dashboard):
    """
    Updates the Tactical selected-node info frame state.

    The frame contains node information whenever a Tactical node is selected,
    but it is only clickable when:
    - a Tactical node is selected
    - that Tactical node is not already the dashboard-selected node
    """
    frame = dashboard.ui.frame5_tactical1

    tactical_node_uid = getattr(dashboard, "selected_tactical_node_uid", None)
    active_node_uid = getattr(dashboard, "selected_node_uid", None)

    has_tactical_node = bool(tactical_node_uid)
    is_active = has_tactical_node and tactical_node_uid == active_node_uid
    is_clickable = has_tactical_node and not is_active

    node_state = getattr(dashboard, "node_states", {}).get(tactical_node_uid, {})
    is_connected = bool(node_state.get("connected", True))

    # Keep the frame enabled when it has node information so tooltip/hover can work.
    frame.setEnabled(has_tactical_node)

    # Use string values for Qt stylesheet dynamic properties.
    frame.setProperty("active", "true" if is_active else "false")
    frame.setProperty("clickable", "true" if is_clickable else "false")
    frame.setProperty("connected", "true" if is_connected else "false")
    frame.setProperty("pressed", "false")

    if is_clickable:
        frame.setCursor(QtCore.Qt.PointingHandCursor)
        frame.setToolTip("Set this Tactical node as the dashboard-selected sensor node.")
    elif is_active:
        frame.unsetCursor()
        frame.setToolTip("This is the dashboard-selected sensor node.")
    else:
        frame.unsetCursor()
        frame.setToolTip("Select a Tactical node pin or ecosystem row first.")

    _refresh_frame_style(frame)



















def get_selected_tactical_ecosystem_alert(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_ecosystem_alerts

    row = table.currentRow()
    if row < 0:
        return None

    item = table.item(row, 0)
    if item is None:
        return None

    alert_uid = item.data(QtCore.Qt.UserRole) or item.text()
    if not alert_uid:
        return None

    return dashboard.tactical_alerts.get(alert_uid)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemAlertsPlotClicked(dashboard: QtCore.QObject):
    alert = get_selected_tactical_ecosystem_alert(dashboard)
    if not alert:
        return

    plot_tactical_ecosystem_alert(dashboard, alert, zoom=False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemAlertsPlotZoomClicked(dashboard: QtCore.QObject):
    alert = get_selected_tactical_ecosystem_alert(dashboard)
    if not alert:
        return

    plot_tactical_ecosystem_alert(dashboard, alert, zoom=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemAlertsRemoveClicked(dashboard: QtCore.QObject):
    alert = get_selected_tactical_ecosystem_alert(dashboard)
    if not alert:
        return

    uid = alert.get("uid") or alert.get("alert_id")
    if uid:
        dashboard.tactical_map.remove_alert_pin(uid)


def plot_tactical_ecosystem_alert(
    dashboard: QtCore.QObject,
    alert: dict,
    zoom=False,
):
    uid = alert.get("uid") or alert.get("alert_id")
    lat = alert.get("lat")
    lon = alert.get("lon")

    if not uid or lat is None or lon is None:
        return

    label = (
        alert.get("alert_text")
        or alert.get("message")
        or alert.get("summary")
        or alert.get("type")
        or uid
    )

    dashboard.tactical_map.add_alert(
        alert_id=uid,
        lat=lat,
        lon=lon,
        label=label,
    )

    if zoom:
        dashboard.tactical_map.center_on_latlon(lat, lon)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemAlertsDeleteRowClicked(
    dashboard: QtCore.QObject,
):
    table = dashboard.ui.tableWidget_tactical_ecosystem_alerts

    row = table.currentRow()
    if row < 0:
        return

    item = table.item(row, 0)
    if item is None:
        return

    uid = item.data(QtCore.Qt.UserRole) or item.text()

    if uid:
        dashboard.tactical_alerts.pop(uid, None)

        # Remove plotted pin only if present
        dashboard.tactical_map.remove_alert_pin(uid)

    table.removeRow(row)

    if table.rowCount() == 0:
        clear_tactical_ecosystem_alert_details(dashboard)
    else:
        next_row = min(row, table.rowCount() - 1)

        table.selectRow(next_row)
        table.setCurrentCell(next_row, 0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemAlertsClearRowsClicked(
    dashboard: QtCore.QObject,
):
    dashboard.tactical_alerts.clear()

    dashboard.tactical_map.clear_alert_records()

    dashboard.ui.tableWidget_tactical_ecosystem_alerts.setRowCount(0)

    clear_tactical_ecosystem_alert_details(dashboard)


@QtCore.pyqtSlot(QtCore.QObject, QtWidgets.QTableWidgetItem)
def _slotTacticalEcosystemAlertsDoubleClicked(dashboard, item):
    if item is None:
        return

    row = item.row()
    uid_item = dashboard.ui.tableWidget_tactical_ecosystem_alerts.item(row, 0)
    if uid_item is None:
        return

    alert_uid = uid_item.data(QtCore.Qt.UserRole) or uid_item.text()
    if not alert_uid:
        return

    alert = dashboard.tactical_alerts.get(alert_uid)
    if not alert:
        return

    plot_tactical_ecosystem_alert(
        dashboard,
        alert,
        zoom=True,
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemAlertsRowSelectionChanged(
    dashboard: QtCore.QObject,
):
    alert = get_selected_tactical_ecosystem_alert(
        dashboard
    )

    if not alert:
        clear_tactical_ecosystem_alert_details(
            dashboard
        )
        return

    uid = (
        alert.get("uid")
        or alert.get("alert_id")
    )

    dashboard.selected_tactical_alert_id = uid


def clear_tactical_ecosystem_alert_details(
    dashboard: QtCore.QObject,
):
    dashboard.selected_tactical_alert_id = None


def clear_tactical_node_detections(dashboard: QtCore.QObject):
    dashboard.ui.tableWidget_tactical_node_detections.setRowCount(0)
    clear_tactical_detection_details(dashboard)


def rebuild_tactical_node_detections(dashboard: QtCore.QObject, node_uid):
    clear_tactical_node_detections(dashboard)

    if not node_uid:
        return

    detections = getattr(dashboard, "tactical_detections", {}) or {}

    matching_detections = [
        detection
        for detection in detections.values()
        if detection.get("node_uid") == node_uid
    ]

    matching_detections.sort(
        key=lambda detection: str(detection.get("time", "")),
        reverse=True,
    )

    for detection in reversed(matching_detections):
        update_tactical_detection_row(dashboard, detection)


def clear_tactical_node_sois(dashboard: QtCore.QObject):
    dashboard.ui.tableWidget_tactical_node_sois.setRowCount(0)
    clear_tactical_node_soi_details(dashboard)


def rebuild_tactical_node_sois(dashboard: QtCore.QObject, node_uid):
    clear_tactical_node_sois(dashboard)

    if not node_uid:
        return

    sois = getattr(dashboard, "tactical_sois", {}) or {}

    matching_sois = [
        soi
        for soi in sois.values()
        if soi.get("node_uid") == node_uid
    ]

    matching_sois.sort(
        key=lambda soi: str(soi.get("time", "")),
        reverse=True,
    )

    for soi in reversed(matching_sois):
        update_tactical_node_soi_row(dashboard, soi)


def clear_tactical_node_artifacts(dashboard: QtCore.QObject):
    dashboard.ui.tableWidget_tactical_node_artifacts.setRowCount(0)
    clear_tactical_node_artifact_details(dashboard)


def rebuild_tactical_node_artifacts(dashboard: QtCore.QObject, node_uid):
    clear_tactical_node_artifacts(dashboard)

    if not node_uid:
        return

    artifacts = getattr(dashboard, "tactical_artifacts", {}) or {}

    matching_artifacts = [
        artifact
        for artifact in artifacts.values()
        if artifact.get("node_uid") == node_uid
    ]

    matching_artifacts.sort(
        key=lambda artifact: str(artifact.get("time", "")),
        reverse=True,
    )

    for artifact in reversed(matching_artifacts):
        update_tactical_node_artifact_row(dashboard, artifact)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeSoisDeleteRowClicked(
    dashboard: QtCore.QObject,
):
    table = dashboard.ui.tableWidget_tactical_node_sois

    row = table.currentRow()
    if row < 0:
        return

    item = table.item(row, 0)
    if item is None:
        return

    soi_key = item.data(QtCore.Qt.UserRole)

    if soi_key:
        dashboard.tactical_sois.pop(soi_key, None)

        # Remove plotted pin and persistent map overlay record.
        dashboard.tactical_map.remove_soi(soi_key)

        if getattr(dashboard, "selected_tactical_node_soi_id", None) == soi_key:
            dashboard.selected_tactical_node_soi_id = None

    table.removeRow(row)

    if table.rowCount() == 0:
        clear_tactical_node_soi_details(dashboard)
    else:
        next_row = min(row, table.rowCount() - 1)
        table.selectRow(next_row)
        table.setCurrentCell(next_row, 0)
        _slotTacticalNodeSoisRowSelectionChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeSoisClearRowsClicked(
    dashboard: QtCore.QObject,
):
    node_uid = getattr(dashboard, "selected_tactical_node_uid", None)

    if not node_uid:
        dashboard.ui.tableWidget_tactical_node_sois.setRowCount(0)
        clear_tactical_node_soi_details(dashboard)
        return

    sois_to_remove = [
        soi_key
        for soi_key, soi in dashboard.tactical_sois.items()
        if soi.get("node_uid") == node_uid
    ]

    for soi_key in sois_to_remove:
        dashboard.tactical_sois.pop(soi_key, None)
        dashboard.tactical_map.remove_soi(soi_key)

    dashboard.ui.tableWidget_tactical_node_sois.setRowCount(0)
    clear_tactical_node_soi_details(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeTargetsDeleteRowClicked(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_node_targets

    selected_items = table.selectedItems()
    if not selected_items:
        return

    row = selected_items[0].row()

    id_item = table.item(row, 0)
    if id_item is None:
        return

    target_id = id_item.data(QtCore.Qt.UserRole) or id_item.text()

    # Remove plotted marker + persistent map overlay record.
    # Do not remove dashboard.tactical_targets; this is only the node shortlist.
    if target_id:
        dashboard.tactical_map.remove_target(target_id)

    table.removeRow(row)

    if getattr(dashboard, "selected_tactical_node_target_id", None) == target_id:
        dashboard.selected_tactical_node_target_id = None

    if table.rowCount() == 0:
        clear_tactical_node_target_details(dashboard)
        return

    next_row = min(row, table.rowCount() - 1)
    table.selectRow(next_row)
    table.setCurrentCell(next_row, 0)
    _slotTacticalNodeTargetsRowSelectionChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeTargetsClearRowsClicked(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_node_targets

    target_ids = []

    for row in range(table.rowCount()):
        id_item = table.item(row, 0)

        if id_item is None:
            continue

        target_id = id_item.data(QtCore.Qt.UserRole) or id_item.text()

        if target_id:
            target_ids.append(target_id)

    for target_id in target_ids:
        dashboard.tactical_map.remove_target(target_id)

    table.setRowCount(0)
    dashboard.selected_tactical_node_target_id = None
    clear_tactical_node_target_details(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeTargetsKeepSelectedClicked(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_node_targets

    selected_items = table.selectedItems()
    if not selected_items:
        return

    selected_row = selected_items[0].row()

    selected_item = table.item(selected_row, 0)
    if selected_item is None:
        return

    selected_target_id = (
        selected_item.data(QtCore.Qt.UserRole)
        or selected_item.text()
    )

    if not selected_target_id:
        return

    # Remove all non-selected target pins/records from the map overlay.
    for row in range(table.rowCount()):
        if row == selected_row:
            continue

        id_item = table.item(row, 0)

        if id_item is None:
            continue

        target_id = id_item.data(QtCore.Qt.UserRole) or id_item.text()

        if target_id:
            dashboard.tactical_map.remove_target(target_id)

    # Remove all non-selected rows from bottom to top so row indexes stay valid.
    for row in range(table.rowCount() - 1, -1, -1):
        if row != selected_row:
            table.removeRow(row)

    dashboard.selected_tactical_node_target_id = selected_target_id

    table.selectRow(0)
    table.setCurrentCell(0, 0)
    _slotTacticalNodeTargetsRowSelectionChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeArtifactsDeleteRowClicked(
    dashboard: QtCore.QObject,
):
    """
    Removes the selected artifact row from the Dashboard local cache/view.

    This does not delete artifact files and does not remove the artifact
    from HIPRFISR's artifact tracker.
    """
    table = dashboard.ui.tableWidget_tactical_node_artifacts

    selected_items = table.selectedItems()
    if not selected_items:
        return

    row = selected_items[0].row()

    item = table.item(row, 0)
    if item is None:
        return

    artifact_id = item.data(QtCore.Qt.UserRole)

    if artifact_id:
        dashboard.tactical_artifacts.pop(artifact_id, None)

    table.removeRow(row)

    if getattr(dashboard, "selected_tactical_node_artifact_id", None) == artifact_id:
        dashboard.selected_tactical_node_artifact_id = None

    if table.rowCount() == 0:
        clear_tactical_node_artifact_details(dashboard)
        return

    next_row = min(row, table.rowCount() - 1)
    table.selectRow(next_row)
    table.setCurrentCell(next_row, 0)
    _slotTacticalNodeArtifactsRowSelectionChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeArtifactsClearRowsClicked(
    dashboard: QtCore.QObject,
):
    """
    Clears visible selected-node artifact rows from the Dashboard local cache/view.

    This does not delete artifact files and does not clear HIPRFISR's artifact
    tracker. Refresh will reload known artifacts from the hub registry.
    """
    table = dashboard.ui.tableWidget_tactical_node_artifacts

    artifact_ids = []

    for row in range(table.rowCount()):
        item = table.item(row, 0)

        if item is None:
            continue

        artifact_id = item.data(QtCore.Qt.UserRole)

        if artifact_id:
            artifact_ids.append(artifact_id)

    for artifact_id in artifact_ids:
        dashboard.tactical_artifacts.pop(artifact_id, None)

    table.setRowCount(0)
    clear_tactical_node_artifact_details(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeSoisRefreshClicked(
    dashboard: QtCore.QObject,
):
    """
    Requests the authoritative SOI set for the selected Tactical node.
    """
    node_uid = str(
        getattr(dashboard, "selected_tactical_node_uid", "")
        or ""
    ).strip()

    if not node_uid:
        dashboard.logger.warning(
            "[Tactical] No node selected for SOI refresh."
        )
        return

    refresh_button = getattr(
        dashboard.ui,
        "pushButton_tactical_node_sois_refresh",
        None,
    )

    if refresh_button is not None:
        refresh_button.setEnabled(False)

    try:
        await dashboard.backend.tacticalNodeSoisRefresh(
            node_uid
        )
    except Exception as error:
        dashboard.logger.error(
            f"[Tactical] Failed requesting SOI refresh: {error}"
        )
    finally:
        if refresh_button is not None:
            refresh_button.setEnabled(True)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeArtifactsRefreshClicked(
    dashboard: QtCore.QObject,
):
    """
    Requests artifact metadata for the selected Tactical node from HIPRFISR.
    """
    node_uid = getattr(
        dashboard,
        "selected_tactical_node_uid",
        None,
    )

    if not node_uid:
        dashboard.logger.warning(
            "[Tactical] No node selected for artifact refresh."
        )
        return

    try:
        await dashboard.backend.tacticalNodeArtifactsRefresh(node_uid)
    except Exception as e:
        dashboard.logger.error(
            f"[Tactical] Failed requesting artifact refresh: {e}"
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTacticalNodeArtifactsDownloadClicked(
    dashboard: QtCore.QObject,
):
    artifact_id = getattr(
        dashboard,
        "selected_tactical_node_artifact_id",
        None,
    )
    if not artifact_id:
        return

    local_path = dashboard.backend.artifact_transfer_controller.get_local_path(
        artifact_id
    )
    if local_path:
        subprocess.Popen(["xdg-open", os.path.dirname(local_path)])
        return

    try:
        await dashboard.backend.requestDashboardArtifactDownload(
            artifact_id,
            open_when_complete=True,
        )
    except Exception as exc:
        dashboard.logger.error(
            f"[Tactical] Artifact download request failed: {exc}"
        )


def initialize_tactical_node_artifact_context_menu(
    dashboard: QtCore.QObject,
):
    """
    Adds local table-management actions to the artifact table.

    Delete Row and Clear Rows only remove metadata from the current Dashboard
    view/cache. They do not delete files from the Sensor Node or HIPRFISR.
    """
    table = dashboard.ui.tableWidget_tactical_node_artifacts

    table.setContextMenuPolicy(
        QtCore.Qt.CustomContextMenu
    )

    table.customContextMenuRequested.connect(
        lambda position: _showTacticalNodeArtifactsContextMenu(
            dashboard,
            position,
        )
    )


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QPoint)
def _showTacticalNodeArtifactsContextMenu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    """
    Selects the right-clicked artifact row and shows local table-management
    actions.

    Delete Row and Clear Rows only remove records from the current Dashboard
    view/cache. They do not delete files from the Sensor Node or HIPRFISR.
    """
    table = dashboard.ui.tableWidget_tactical_node_artifacts
    clicked_item = table.itemAt(position)

    if clicked_item is not None:
        table.selectRow(clicked_item.row())
        table.setCurrentCell(
            clicked_item.row(),
            clicked_item.column(),
        )

        _slotTacticalNodeArtifactsRowSelectionChanged(
            dashboard
        )

    artifact_id = getattr(
        dashboard,
        "selected_tactical_node_artifact_id",
        None,
    )

    has_artifact = bool(artifact_id)
    has_rows = table.rowCount() > 0

    menu = QtWidgets.QMenu(table)

    action_delete = menu.addAction("Delete Row")
    action_clear = menu.addAction("Clear Rows")

    action_delete.setEnabled(has_artifact)
    action_clear.setEnabled(has_rows)

    selected_action = menu.exec_(
        table.viewport().mapToGlobal(position)
    )

    if selected_action == action_delete:
        _slotTacticalNodeArtifactsDeleteRowClicked(
            dashboard
        )
    elif selected_action == action_clear:
        _slotTacticalNodeArtifactsClearRowsClicked(
            dashboard
        )


def initialize_tactical_node_target_context_menu(
    dashboard: QtCore.QObject,
):
    """
    Moves secondary Node Targets actions into the table context menu.

    Refresh Targets and Query Actions remain visible below the details panel.
    """
    table = dashboard.ui.tableWidget_tactical_node_targets

    table.setContextMenuPolicy(
        QtCore.Qt.CustomContextMenu
    )

    table.customContextMenuRequested.connect(
        lambda position: _showTacticalNodeTargetsContextMenu(
            dashboard,
            position,
        )
    )


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QPoint)
def _showTacticalNodeTargetsContextMenu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    """
    Selects the right-clicked row and shows Node Targets row actions.
    """
    table = dashboard.ui.tableWidget_tactical_node_targets
    clicked_item = table.itemAt(position)

    if clicked_item is not None:
        table.selectRow(clicked_item.row())
        table.setCurrentCell(
            clicked_item.row(),
            clicked_item.column(),
        )

        _slotTacticalNodeTargetsRowSelectionChanged(
            dashboard
        )

    target_id = getattr(
        dashboard,
        "selected_tactical_node_target_id",
        None,
    )

    target = (
        dashboard.tactical_targets.get(target_id)
        if target_id
        else None
    )

    has_target = (
        isinstance(target, dict)
        and bool(target)
    )

    has_rows = table.rowCount() > 0

    menu = QtWidgets.QMenu(table)

    action_more_details = menu.addAction(
        "More Details"
    )

    action_keep_selected = menu.addAction(
        "Keep Selected"
    )

    menu.addSeparator()

    action_plot = menu.addAction(
        "Plot"
    )

    action_plot_zoom = menu.addAction(
        "Plot + Zoom"
    )

    action_remove = menu.addAction(
        "Remove from Map"
    )

    menu.addSeparator()

    action_delete = menu.addAction(
        "Delete Row"
    )

    action_clear = menu.addAction(
        "Clear Rows"
    )

    action_more_details.setEnabled(has_target)
    action_keep_selected.setEnabled(has_target)
    action_plot.setEnabled(has_target)
    action_plot_zoom.setEnabled(has_target)
    action_remove.setEnabled(has_target)
    action_delete.setEnabled(has_target)
    action_clear.setEnabled(has_rows)

    selected_action = menu.exec_(
        table.viewport().mapToGlobal(position)
    )

    if selected_action == action_more_details:
        _slotTacticalNodeTargetsMoreDetailsClicked(
            dashboard
        )

    elif selected_action == action_keep_selected:
        _slotTacticalNodeTargetsKeepSelectedClicked(
            dashboard
        )

    elif selected_action == action_plot:
        _slotTacticalNodeTargetsPlotClicked(
            dashboard
        )

    elif selected_action == action_plot_zoom:
        _slotTacticalNodeTargetsPlotZoomClicked(
            dashboard
        )

    elif selected_action == action_remove:
        _slotTacticalNodeTargetsRemoveClicked(
            dashboard
        )

    elif selected_action == action_delete:
        _slotTacticalNodeTargetsDeleteRowClicked(
            dashboard
        )

    elif selected_action == action_clear:
        _slotTacticalNodeTargetsClearRowsClicked(
            dashboard
        )


def initialize_tactical_node_soi_context_menu(
    dashboard: QtCore.QObject,
):
    """
    Moves secondary selected-node SOI actions into the SOI table context
    menu while leaving Download Evidence and Promote to Target visible.
    """
    table = dashboard.ui.tableWidget_tactical_node_sois

    table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
    table.customContextMenuRequested.connect(
        lambda position: _showTacticalNodeSoisContextMenu(
            dashboard,
            position,
        )
    )


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QPoint)
def _showTacticalNodeSoisContextMenu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    """
    Shows SOI map, refresh, and table-management actions. Right-clicking a
    row selects it before the menu opens.
    """
    table = dashboard.ui.tableWidget_tactical_node_sois
    clicked_item = table.itemAt(position)

    if clicked_item is not None:
        table.selectRow(clicked_item.row())
        table.setCurrentCell(
            clicked_item.row(),
            clicked_item.column(),
        )

    soi_key = getattr(
        dashboard,
        "selected_tactical_node_soi_id",
        None,
    )
    soi = (
        dashboard.tactical_sois.get(soi_key)
        if soi_key
        else None
    )

    has_soi = isinstance(soi, dict) and bool(soi)
    has_rows = table.rowCount() > 0
    has_node = bool(
        str(
            getattr(
                dashboard,
                "selected_tactical_node_uid",
                "",
            )
            or ""
        ).strip()
    )

    menu = QtWidgets.QMenu(table)

    action_refresh = menu.addAction("Refresh")

    menu.addSeparator()

    action_plot = menu.addAction("Plot")
    action_plot_zoom = menu.addAction("Plot + Zoom")
    action_remove = menu.addAction("Remove from Map")

    menu.addSeparator()

    action_delete = menu.addAction("Delete Row")
    action_clear = menu.addAction("Clear Rows")

    action_refresh.setEnabled(has_node)
    action_plot.setEnabled(has_soi)
    action_plot_zoom.setEnabled(has_soi)
    action_remove.setEnabled(has_soi)
    action_delete.setEnabled(has_soi)
    action_clear.setEnabled(has_rows)

    chosen_action = menu.exec_(
        table.viewport().mapToGlobal(position)
    )

    if chosen_action == action_refresh:
        _slotTacticalNodeSoisRefreshClicked(dashboard)
    elif chosen_action == action_plot:
        _slotTacticalNodeSoisPlotClicked(dashboard)
    elif chosen_action == action_plot_zoom:
        _slotTacticalNodeSoisPlotZoomClicked(dashboard)
    elif chosen_action == action_remove:
        _slotTacticalNodeSoisRemoveClicked(dashboard)
    elif chosen_action == action_delete:
        _slotTacticalNodeSoisDeleteRowClicked(dashboard)
    elif chosen_action == action_clear:
        _slotTacticalNodeSoisClearRowsClicked(dashboard)


def initialize_tactical_node_detection_context_menu(
    dashboard: QtCore.QObject,
):
    """
    Adds secondary selected-node detection actions to the detections table
    context menu while leaving promotion actions visible in the details panel.
    """
    table = dashboard.ui.tableWidget_tactical_node_detections

    table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
    table.customContextMenuRequested.connect(
        lambda position: _showTacticalNodeDetectionsContextMenu(
            dashboard,
            position,
        )
    )


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QPoint)
def _showTacticalNodeDetectionsContextMenu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    """
    Shows row and table management actions for the selected-node detections
    table. Right-clicking a row selects that row before opening the menu.
    """
    table = dashboard.ui.tableWidget_tactical_node_detections
    clicked_item = table.itemAt(position)

    if clicked_item is not None:
        table.selectRow(clicked_item.row())
        table.setCurrentCell(clicked_item.row(), clicked_item.column())

    detection = get_selected_tactical_node_detection(dashboard)
    has_detection = detection is not None
    has_rows = table.rowCount() > 0

    menu = QtWidgets.QMenu(table)

    action_plot = menu.addAction("Plot")
    action_plot_zoom = menu.addAction("Plot + Zoom")
    action_remove = menu.addAction("Remove from Map")

    menu.addSeparator()

    action_delete = menu.addAction("Delete Row")
    action_clear = menu.addAction("Clear Rows")

    action_plot.setEnabled(has_detection)
    action_plot_zoom.setEnabled(has_detection)
    action_remove.setEnabled(has_detection)
    action_delete.setEnabled(has_detection)
    action_clear.setEnabled(has_rows)

    chosen_action = menu.exec_(table.viewport().mapToGlobal(position))

    if chosen_action == action_plot:
        _slotTacticalNodeDetectionsPlotClicked(dashboard)
    elif chosen_action == action_plot_zoom:
        _slotTacticalNodeDetectionsPlotZoomClicked(dashboard)
    elif chosen_action == action_remove:
        _slotTacticalNodeDetectionsRemoveClicked(dashboard)
    elif chosen_action == action_delete:
        _slotTacticalNodeDetectionsDeleteRowClicked(dashboard)
    elif chosen_action == action_clear:
        _slotTacticalNodeDetectionsClearRowsClicked(dashboard)


def initialize_tactical_targets_context_menu(
    dashboard: QtCore.QObject,
):
    """
    Moves secondary global Target actions into the Target List context menu.

    Refresh Targets, geolocation controls, and Query Actions remain visible.
    """
    table = dashboard.ui.tableWidget_tactical_targets

    table.setContextMenuPolicy(
        QtCore.Qt.CustomContextMenu
    )

    table.customContextMenuRequested.connect(
        lambda position: _showTacticalTargetsContextMenu(
            dashboard,
            position,
        )
    )


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QPoint)
def _showTacticalTargetsContextMenu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    """
    Selects the right-clicked Target row before showing row and map actions.
    """
    table = dashboard.ui.tableWidget_tactical_targets
    clicked_item = table.itemAt(position)

    if clicked_item is not None:
        table.selectRow(clicked_item.row())
        table.setCurrentCell(
            clicked_item.row(),
            clicked_item.column(),
        )

    target_id = getattr(
        dashboard,
        "selected_tactical_target_id",
        None,
    )

    target = (
        dashboard.tactical_targets.get(target_id)
        if target_id
        else None
    )

    has_selection = bool(target)
    has_rows = table.rowCount() > 0

    has_location = False

    if target:
        lat = target.get("lat")
        lon = target.get("lon")

        if (
            lat not in [None, "", "None"]
            and lon not in [None, "", "None"]
        ):
            try:
                float(lat)
                float(lon)
                has_location = True
            except Exception:
                has_location = False

    menu = QtWidgets.QMenu(table)

    action_plot = menu.addAction("Plot")
    action_plot_zoom = menu.addAction("Plot + Zoom")
    action_remove_pin = menu.addAction("Remove Pin")

    action_plot.setEnabled(
        has_selection and has_location
    )
    action_plot_zoom.setEnabled(
        has_selection and has_location
    )
    action_remove_pin.setEnabled(
        has_selection
    )

    menu.addSeparator()

    action_plot_all = menu.addAction("Plot All")
    action_plot_all.setEnabled(has_rows)

    menu.addSeparator()

    action_delete_row = menu.addAction("Delete Row")
    action_clear_rows = menu.addAction("Clear Rows")

    action_delete_row.setEnabled(has_selection)
    action_clear_rows.setEnabled(has_rows)

    selected_action = menu.exec_(
        table.viewport().mapToGlobal(position)
    )

    if selected_action == action_plot:
        _slotTacticalTargetsPlotClicked(dashboard)

    elif selected_action == action_plot_zoom:
        _slotTacticalTargetsPlotZoomClicked(dashboard)

    elif selected_action == action_remove_pin:
        _slotTacticalTargetsRemovePinClicked(dashboard)

    elif selected_action == action_plot_all:
        _slotTacticalTargetsPlotAllClicked(dashboard)

    elif selected_action == action_delete_row:
        _slotTacticalTargetsDeleteRowClicked(dashboard)

    elif selected_action == action_clear_rows:
        _slotTacticalTargetsClearRowsClicked(dashboard)


def initialize_tactical_targets_details_context_menu(
    dashboard: QtCore.QObject,
):
    """
    Adds Full Details, Copy, and Select All to the dynamic Target details label.
    """
    label = dashboard.ui.label2_tactical_targets_details

    label.setContextMenuPolicy(
        QtCore.Qt.CustomContextMenu
    )

    label.customContextMenuRequested.connect(
        lambda position: _showTacticalTargetsDetailsContextMenu(
            dashboard,
            position,
        )
    )


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QPoint)
def _showTacticalTargetsDetailsContextMenu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    label = dashboard.ui.label2_tactical_targets_details

    menu = QtWidgets.QMenu(label)

    action_full_details = menu.addAction(
        "Full Details"
    )
    action_full_details.setCheckable(True)
    action_full_details.setChecked(
        bool(
            getattr(
                dashboard,
                "tactical_targets_full_details",
                False,
            )
        )
    )

    menu.addSeparator()

    action_copy = menu.addAction("Copy")
    action_select_all = menu.addAction("Select All")

    has_text = bool(label.text().strip())
    has_selection = bool(label.hasSelectedText())

    action_copy.setEnabled(has_selection)
    action_select_all.setEnabled(has_text)

    selected_action = menu.exec_(
        label.mapToGlobal(position)
    )

    if selected_action == action_full_details:
        dashboard.tactical_targets_full_details = (
            action_full_details.isChecked()
        )

        target_id = getattr(
            dashboard,
            "selected_tactical_target_id",
            None,
        )

        target = (
            dashboard.tactical_targets.get(target_id)
            if target_id
            else None
        )

        if isinstance(target, dict) and target:
            populate_tactical_targets_details(
                dashboard,
                target,
            )

    elif selected_action == action_copy:
        selected_text = label.selectedText()

        if selected_text:
            QtWidgets.QApplication.clipboard().setText(
                selected_text
            )

    elif selected_action == action_select_all:
        label.setSelection(
            0,
            len(label.text()),
        )


def populate_tactical_targets_details(
    dashboard: QtCore.QObject,
    target: dict,
):
    """
    Displays either a curated Target summary or every non-empty structured
    field except raw transport payloads.
    """
    hidden_keys = {
        "raw_xml",
        "cot_xml",
        "xml",
        "raw_message",
        "raw_payload",
    }

    summary_field_groups = [
        (
            "Target ID",
            [
                "target_id",
                "uid",
                "id",
            ],
        ),
        (
            "Display Label",
            [
                "type",
                "display_label",
                "target_label",
                "name",
            ],
        ),
        (
            "State",
            [
                "state",
                "target_state",
                "status",
            ],
        ),
        (
            "Geolocation",
            [
                "geolocation_status",
                "geolocate_status",
            ],
        ),
        (
            "Location",
            [
                "location",
            ],
        ),
        (
            "Frequency",
            [
                "target_frequency_mhz",
                "frequency_mhz",
                "frequency_hz",
                "frequency",
            ],
        ),
        (
            "Updated",
            [
                "updated",
                "updated_at",
                "time",
                "timestamp",
            ],
        ),
        (
            "Node ID",
            [
                "node_uid",
                "sensor_node_id",
                "node_id",
            ],
        ),
    ]

    def is_empty(value):
        if value is None:
            return True

        if isinstance(value, str):
            return value.strip() in [
                "",
                "None",
            ]

        if isinstance(
            value,
            (
                dict,
                list,
                tuple,
                set,
            ),
        ):
            return len(value) == 0

        return False

    def make_label(key):
        return str(key).replace(
            "_",
            " ",
        ).strip().title()

    def field_label_html(label):
        return (
            "<span style='font-weight:500;'>"
            f"{html.escape(str(label))}:"
            "</span>"
        )

    def format_scalar(key, value):
        normalized_key = str(
            key
        ).strip().lower()

        if normalized_key in {
            "updated",
            "updated_at",
            "time",
            "timestamp",
            "last_observation_time",
        }:
            formatted_time = format_detection_time(
                value
            )

            if formatted_time:
                return formatted_time

        if normalized_key in {
            "target_frequency_mhz",
            "frequency_mhz",
        }:
            try:
                return f"{float(value):.3f} MHz"
            except Exception:
                pass

        if normalized_key == "frequency_hz":
            try:
                return f"{float(value) / 1e6:.3f} MHz"
            except Exception:
                pass

        if normalized_key in {
            "rssi",
            "rssi_dbm",
            "power",
            "power_dbm",
        }:
            try:
                return f"{float(value):.1f} dBm"
            except Exception:
                pass

        if normalized_key in {
            "ce",
            "ce_m",
            "hae",
            "hae_m",
        }:
            try:
                return f"{float(value):.1f} m"
            except Exception:
                pass

        return str(value)

    def build_location_value(record):
        lat = (
            record.get("lat")
            if record.get("lat") not in [None, "", "None"]
            else record.get("latitude")
        )

        lon = (
            record.get("lon")
            if record.get("lon") not in [None, "", "None"]
            else record.get("longitude")
        )

        if (
            lat in [None, "", "None"]
            or lon in [None, "", "None"]
        ):
            return ""

        try:
            location = (
                f"{float(lat):.6f}, "
                f"{float(lon):.6f}"
            )
        except Exception:
            location = f"{lat}, {lon}"

        ce_m = (
            record.get("ce_m")
            if record.get("ce_m") not in [None, "", "None"]
            else record.get("ce")
        )

        if ce_m not in [None, "", "None"]:
            location += f"  CE {ce_m} m"

        return location

    def first_value(record, keys):
        for key in keys:
            if key == "location":
                value = build_location_value(record)
            else:
                value = record.get(key)

            if not is_empty(value):
                return key, value

        return None, None

    def append_value(lines, key, value, depth=0):
        normalized_key = str(key).strip().lower()

        if normalized_key in hidden_keys or is_empty(value):
            return

        label = make_label(key)
        indent = "&nbsp;" * (depth * 4)

        if isinstance(value, dict):
            lines.append(
                f"{indent}{field_label_html(label)}"
            )

            for nested_key, nested_value in value.items():
                append_value(
                    lines,
                    nested_key,
                    nested_value,
                    depth + 1,
                )

            return

        if isinstance(value, (list, tuple, set)):
            values = list(value)

            if not values:
                return

            lines.append(
                f"{indent}{field_label_html(label)}"
            )

            for item in values:
                if is_empty(item):
                    continue

                if isinstance(item, dict):
                    for nested_key, nested_value in item.items():
                        append_value(
                            lines,
                            nested_key,
                            nested_value,
                            depth + 1,
                        )
                else:
                    lines.append(
                        f"{'&nbsp;' * ((depth + 1) * 4)}"
                        f"{html.escape(str(item))}"
                    )

            return

        display_value = format_scalar(
            normalized_key,
            value,
        )

        lines.append(
            f"{indent}{field_label_html(label)} "
            f"{html.escape(display_value)}"
        )

    lines = []

    full_details = bool(
        getattr(
            dashboard,
            "tactical_targets_full_details",
            False,
        )
    )

    if full_details:
        for key, value in target.items():
            append_value(
                lines,
                key,
                value,
            )
    else:
        for label, keys in summary_field_groups:
            key, value = first_value(
                target,
                keys,
            )

            if is_empty(value):
                continue

            if key == "location":
                display_value = str(value)
            else:
                display_value = format_scalar(
                    key,
                    value,
                )

            lines.append(
                f"{field_label_html(label)} "
                f"{html.escape(display_value)}"
            )

    dashboard.ui.label2_tactical_targets_details.setText(
        "<br>".join(lines)
    )

    dashboard.ui.label2_tactical_targets_details.setAlignment(
        QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop
    )


def initialize_tactical_ecosystem_node_context_menu(
    dashboard: QtCore.QObject,
):
    """
    Adds map and row-management actions to the Ecosystem Node Roster.

    Select All, Unselect, and Refresh Status remain visible because they are
    primary controls for the multi-node workflow.
    """
    table = dashboard.ui.tableWidget_tactical_ecosystem

    table.setContextMenuPolicy(
        QtCore.Qt.CustomContextMenu
    )

    table.customContextMenuRequested.connect(
        lambda position: _showTacticalEcosystemNodeContextMenu(
            dashboard,
            position,
        )
    )


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QPoint)
def _showTacticalEcosystemNodeContextMenu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    table = dashboard.ui.tableWidget_tactical_ecosystem
    clicked_item = table.itemAt(position)

    if clicked_item is not None:
        row = clicked_item.row()

        # Preserve Ctrl/Shift multi-selection behavior. A normal right-click
        # on an unselected row makes that row the active selection.
        if not table.item(row, 0).isSelected():
            table.clearSelection()
            table.selectRow(row)

        table.setCurrentCell(
            row,
            clicked_item.column(),
        )

        update_selected_tactical_nodes(dashboard)

    current_row = table.currentRow()
    has_selection = current_row >= 0
    has_rows = table.rowCount() > 0

    menu = QtWidgets.QMenu(table)

    action_pan = menu.addAction("Pan to Node")
    action_pan.setEnabled(has_selection)

    menu.addSeparator()

    action_delete_row = menu.addAction("Delete Row")
    action_clear_rows = menu.addAction("Clear Rows")

    action_delete_row.setEnabled(has_selection)
    action_clear_rows.setEnabled(has_rows)

    selected_action = menu.exec_(
        table.viewport().mapToGlobal(position)
    )

    if selected_action == action_pan:
        _slotTacticalEcosystemPanToNodeClicked(
            dashboard
        )

    elif selected_action == action_delete_row:
        _slotTacticalEcosystemDeleteNodeRowClicked(
            dashboard
        )

    elif selected_action == action_clear_rows:
        _slotTacticalEcosystemClearNodeRowsClicked(
            dashboard
        )


def initialize_tactical_ecosystem_alert_context_menu(
    dashboard: QtCore.QObject,
):
    """
    Moves all secondary Alert actions into the Alerts table context menu.
    """
    table = dashboard.ui.tableWidget_tactical_ecosystem_alerts

    table.setContextMenuPolicy(
        QtCore.Qt.CustomContextMenu
    )

    table.customContextMenuRequested.connect(
        lambda position: _showTacticalEcosystemAlertContextMenu(
            dashboard,
            position,
        )
    )


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QPoint)
def _showTacticalEcosystemAlertContextMenu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    table = dashboard.ui.tableWidget_tactical_ecosystem_alerts
    clicked_item = table.itemAt(position)

    if clicked_item is not None:
        table.selectRow(clicked_item.row())
        table.setCurrentCell(
            clicked_item.row(),
            clicked_item.column(),
        )

    alert = get_selected_tactical_ecosystem_alert(
        dashboard
    )

    has_rows = table.rowCount() > 0
    has_selection = alert is not None

    has_location = False

    if alert:
        lat = alert.get("lat")
        lon = alert.get("lon")

        if (
            lat not in [None, "", "None"]
            and lon not in [None, "", "None"]
        ):
            try:
                float(lat)
                float(lon)
                has_location = True
            except Exception:
                has_location = False

    menu = QtWidgets.QMenu(table)

    action_plot = menu.addAction("Plot")
    action_plot_zoom = menu.addAction("Plot + Zoom")
    action_remove = menu.addAction("Remove From Map")

    action_plot.setEnabled(has_location)
    action_plot_zoom.setEnabled(has_location)
    action_remove.setEnabled(
        has_selection
    )

    menu.addSeparator()

    action_delete_row = menu.addAction("Delete Row")
    action_clear_rows = menu.addAction("Clear Rows")

    action_delete_row.setEnabled(has_selection)
    action_clear_rows.setEnabled(has_rows)

    selected_action = menu.exec_(
        table.viewport().mapToGlobal(position)
    )

    if selected_action == action_plot:
        _slotTacticalEcosystemAlertsPlotClicked(
            dashboard
        )

    elif selected_action == action_plot_zoom:
        _slotTacticalEcosystemAlertsPlotZoomClicked(
            dashboard
        )

    elif selected_action == action_remove:
        _slotTacticalEcosystemAlertsRemoveClicked(
            dashboard
        )

    elif selected_action == action_delete_row:
        _slotTacticalEcosystemAlertsDeleteRowClicked(
            dashboard
        )

    elif selected_action == action_clear_rows:
        _slotTacticalEcosystemAlertsClearRowsClicked(
            dashboard
        )


def _apply_tactical_details_panel_role(*widgets):
    """
    Applies the shared detailsPanel stylesheet role to widgets created
    programmatically and forces Qt to re-evaluate the active stylesheet.
    """
    for widget in widgets:
        if widget is None:
            continue

        widget.setProperty("uiRole", "detailsPanel")

        style = widget.style()
        if style is not None:
            style.unpolish(widget)
            style.polish(widget)

        widget.update()