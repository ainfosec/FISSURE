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
    scroll_area = dashboard.ui.scrollArea_tactical_ecosystem_action_parameters

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

    dashboard.tactical_ecosystem_action_parameter_widgets = {}

    description_text = ""

    for param in parameters:
        param_name = param.get("name", "")

        if param_name == "description":
            description_text = str(param.get("default", ""))
            continue

    if description_text:
        description_label = QtWidgets.QLabel(description_text)
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

        widget.setObjectName(f"tactical_ecosystem_param_{param_name}")
        widget.setToolTip(param.get("description", ""))

        make_tactical_parameter_widget_compact(widget)

        row_layout.addWidget(widget, 1)

        layout.addWidget(row_widget)

        dashboard.tactical_ecosystem_action_parameter_widgets[param_name] = widget

    layout.addStretch()

    has_parameters = bool(dashboard.tactical_ecosystem_action_parameter_widgets)

    dashboard.ui.pushButton_tactical_ecosystem_execute.setEnabled(has_parameters)

    content_widget.adjustSize()
    scroll_area.update()

    dashboard.ui.scrollArea_tactical_ecosystem_action_parameters.setEnabled(True)


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
    dashboard.ui.label2_node_detections_frequency.setText("")
    dashboard.ui.label2_node_detections_time.setText("")
    dashboard.ui.label2_node_detections_detector.setText("")
    dashboard.ui.label2_node_detections_op_id.setText("")
    dashboard.ui.label2_node_detections_event_id.setText("")

    enable_tactical_node_detection_details(dashboard, False)


def populate_tactical_detection_details(dashboard: QtCore.QObject, detection: dict):
    frequency = detection.get("frequency", "")

    if frequency and "mhz" not in frequency.lower():
        frequency = f"{frequency} MHz"

    dashboard.ui.label2_node_detections_frequency.setText(frequency)

    dashboard.ui.label2_node_detections_time.setText(
        format_detection_time(detection.get("time", ""))
    )

    dashboard.ui.label2_node_detections_detector.setText(
        detection.get("detector", "")
    )

    dashboard.ui.label2_node_detections_op_id.setText(
        detection.get("operation_id", "")
    )

    dashboard.ui.label2_node_detections_event_id.setText(
        detection.get("event_uid", "")
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
def _slotTacticalTargetsRowSelectionChanged(dashboard: QtCore.QObject):
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

    target_id = id_item.data(QtCore.Qt.UserRole) or id_item.text()
    target = dashboard.tactical_targets.get(target_id, {})

    dashboard.selected_tactical_target_id = target_id

    dashboard.ui.label2_tactical_targets_target_id.setText(
        str(target.get("target_id", target_id))
    )

    dashboard.ui.label2_tactical_targets_display_label.setText(
        str(target.get("type", ""))
    )

    dashboard.ui.label2_tactical_targets_state.setText(
        str(target.get("state", ""))
    )

    dashboard.ui.label2_tactical_targets_geolocation.setText(
        str(target.get("geolocation_status", "idle"))
    )

    frequency = target.get("target_frequency_mhz", "")
    if frequency not in [None, "", "None"]:
        try:
            frequency = f"{float(frequency):.3f}"
        except Exception:
            pass
    else:
        frequency = ""

    dashboard.ui.label2_tactical_targets_frequency.setText(str(frequency))

    dashboard.ui.label2_tactical_targets_updated.setText(
        str(target.get("updated", ""))
    )

    dashboard.ui.label2_tactical_targets_node_id.setText(
        str(target.get("node_uid", ""))
    )

    dashboard.ui.label2_tactical_targets_ssid.setText(
        str(target.get("ssid", ""))
    )

    dashboard.ui.label2_tactical_targets_bssid.setText(
        str(target.get("bssid", ""))
    )

    dashboard.ui.label2_tactical_targets_source_soi_id.setText(
        str(target.get("source_soi_id", ""))
    )

    lat = target.get("lat")
    lon = target.get("lon")
    ce_m = target.get("ce_m")

    location_text = ""
    if lat not in [None, "", "None"] and lon not in [None, "", "None"]:
        try:
            location_text = f"{float(lat):.6f}, {float(lon):.6f}"
        except Exception:
            location_text = f"{lat}, {lon}"

        if ce_m not in [None, "", "None"]:
            location_text += f"  CE {ce_m} m"

    dashboard.ui.label2_tactical_targets_location.setText(location_text)

    dashboard.ui.label2_tactical_targets_artifact_id.setText(
        str(target.get("artifact_id", ""))
    )

    enable_tactical_targets_details(dashboard, True)

    update_tactical_targets_geolocate_button_state(dashboard, target,)


def clear_tactical_targets_details(dashboard: QtCore.QObject):

    dashboard.selected_tactical_target_id = None

    labels = [
        dashboard.ui.label2_tactical_targets_display_label,
        dashboard.ui.label2_tactical_targets_state,
        dashboard.ui.label2_tactical_targets_geolocation,
        dashboard.ui.label2_tactical_targets_frequency,
        dashboard.ui.label2_tactical_targets_updated,
        dashboard.ui.label2_tactical_targets_node_id,
        dashboard.ui.label2_tactical_targets_target_id,
        dashboard.ui.label2_tactical_targets_ssid,
        dashboard.ui.label2_tactical_targets_bssid,
        dashboard.ui.label2_tactical_targets_source_soi_id,
        dashboard.ui.label2_tactical_targets_location,
        dashboard.ui.label2_tactical_targets_artifact_id,
    ]

    for label in labels:
        label.setText("")

    enable_tactical_targets_details(dashboard, False)


def enable_tactical_targets_details(dashboard: QtCore.QObject, enabled=True):

    widgets = [
        dashboard.ui.label2_tactical_targets_target_id2,
        dashboard.ui.label2_tactical_targets_display_label2,
        dashboard.ui.label2_tactical_targets_state2,
        dashboard.ui.label2_tactical_targets_geolocation2,
        dashboard.ui.label2_tactical_targets_frequency2,
        dashboard.ui.label2_tactical_targets_updated2,
        dashboard.ui.label2_tactical_targets_node_id2,
        dashboard.ui.label2_tactical_targets_target_id,
        dashboard.ui.label2_tactical_targets_display_label,
        dashboard.ui.label2_tactical_targets_state,
        dashboard.ui.label2_tactical_targets_geolocation,
        dashboard.ui.label2_tactical_targets_frequency,
        dashboard.ui.label2_tactical_targets_updated,
        dashboard.ui.label2_tactical_targets_node_id,
        dashboard.ui.label2_tactical_targets_ssid2,
        dashboard.ui.label2_tactical_targets_bssid2,
        dashboard.ui.label2_tactical_targets_source_soi_id2,
        dashboard.ui.label2_tactical_targets_location2,
        dashboard.ui.label2_tactical_targets_artifact_id2,
        dashboard.ui.label2_tactical_targets_ssid,
        dashboard.ui.label2_tactical_targets_bssid,
        dashboard.ui.label2_tactical_targets_source_soi_id,
        dashboard.ui.label2_tactical_targets_location,
        dashboard.ui.label2_tactical_targets_artifact_id,
        dashboard.ui.pushButton_tactical_targets_plot,
        dashboard.ui.pushButton_tactical_targets_plot_and_zoom,
        dashboard.ui.pushButton_tactical_targets_remove_pin,
        dashboard.ui.checkBox_tactical_targets_search_similar_targets,
        dashboard.ui.pushButton_tactical_targets_geolocate,
        dashboard.ui.pushButton_tactical_targets_query_actions,
    ]

    for widget in widgets:
        widget.setEnabled(enabled)


def clear_tactical_node_artifact_details(dashboard: QtCore.QObject):
    dashboard.selected_tactical_node_artifact_id = None

    # labels = [
    #     dashboard.ui.label2_tactical_node_targets_target_id,
    # ]

    # for label in labels:
    #     label.setText("")
    
    enable_tactical_artifacts_details(dashboard, False)


def enable_tactical_artifacts_details(dashboard: QtCore.QObject, enabled=True):
    widgets = [
        dashboard.ui.pushButton_tactical_node_artifacts_open_folder,
        dashboard.ui.pushButton_tactical_node_artifacts_download,
        dashboard.ui.pushButton_tactical_node_artifacts_delete_row,
    ]

    for widget in widgets:
        widget.setEnabled(enabled)

    dashboard.ui.pushButton_tactical_node_artifacts_clear_rows.setEnabled(
        dashboard.ui.tableWidget_tactical_node_artifacts.rowCount() > 0
    )

    dashboard.ui.pushButton_tactical_node_artifacts_refresh.setEnabled(
        bool(getattr(dashboard, "selected_tactical_node_uid", None))
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
def _slotTacticalNodeTargetsRowSelectionChanged(dashboard: QtCore.QObject):
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

    target_id = id_item.data(QtCore.Qt.UserRole) or id_item.text()
    target = dashboard.tactical_targets.get(target_id, {})

    dashboard.selected_tactical_node_target_id = target_id

    distance_item = table.item(row, 0)
    distance_text = distance_item.text() if distance_item else ""

    lat = target.get("lat")
    lon = target.get("lon")
    ce_m = target.get("ce_m")

    location_text = ""
    if lat not in [None, "", "None"] and lon not in [None, "", "None"]:
        try:
            location_text = f"{float(lat):.6f}, {float(lon):.6f}"
        except Exception:
            location_text = f"{lat}, {lon}"

        if ce_m not in [None, "", "None"]:
            location_text += f"  CE {ce_m} m"

    frequency = target.get("target_frequency_mhz", "")
    if frequency not in [None, "", "None"]:
        try:
            frequency = f"{float(frequency):.3f}"
        except Exception:
            pass
    else:
        frequency = ""

    dashboard.ui.label2_tactical_node_targets_target_id.setText(
        str(target.get("target_id", target_id))
    )
    dashboard.ui.label2_tactical_node_targets_display_label.setText(
        str(target.get("type", ""))
    )
    dashboard.ui.label2_tactical_node_targets_distance.setText(
        str(distance_text)
    )
    dashboard.ui.label2_tactical_node_targets_state.setText(
        str(target.get("state", ""))
    )
    dashboard.ui.label2_tactical_node_targets_location.setText(
        location_text
    )
    dashboard.ui.label2_tactical_node_targets_frequency.setText(
        str(frequency)
    )

    enable_tactical_node_target_details(dashboard, True)


def clear_tactical_node_target_details(dashboard: QtCore.QObject):
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
    
    enable_tactical_node_target_details(dashboard, False)

    update_tactical_targets_geolocate_button_state(dashboard, None,)


def enable_tactical_node_target_details(dashboard: QtCore.QObject, enabled=True):
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
        dashboard.ui.pushButton_tactical_node_targets_more_details,
        dashboard.ui.pushButton_tactical_node_targets_plot,
        dashboard.ui.pushButton_tactical_node_targets_plot_and_zoom,
        dashboard.ui.pushButton_tactical_node_targets_remove_from_map,

        dashboard.ui.pushButton_tactical_node_targets_delete_row,
        dashboard.ui.pushButton_tactical_node_targets_clear_rows,
        dashboard.ui.pushButton_tactical_node_targets_keep_selected,
    ]

    for widget in widgets:
        widget.setEnabled(enabled)


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
def _slotTacticalNodeSoisRowSelectionChanged(dashboard: QtCore.QObject):
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
        return

    soi = dashboard.tactical_sois.get(soi_key, {})
    dashboard.selected_tactical_node_soi_id = soi_key

    dashboard.ui.label2_tactical_node_soi_frequency.setText(
        str(soi.get("frequency_display", ""))
    )
    dashboard.ui.label2_tactical_node_soi_status.setText(
        str(soi.get("status", ""))
    )
    dashboard.ui.label2_tactical_node_soi_node_id.setText(
        str(soi.get("node_uid", ""))
    )
    dashboard.ui.label2_tactical_node_soi_soi_id.setText(
        str(soi.get("soi_id", ""))
    )
    dashboard.ui.label2_tactical_node_soi_artifact_id.setText(
        str(soi.get("artifact_id", ""))
    )
    dashboard.ui.label2_tactical_node_soi_event_id.setText(
        str(soi.get("event_id", ""))
    )
    dashboard.ui.label2_tactical_node_soi_model.setText(
        str(soi.get("model_classification_display", ""))
    )
    dashboard.ui.label2_tactical_node_soi_database.setText(
        str(soi.get("database_classification", ""))
    )

    enable_tactical_node_soi_details(dashboard, True)


def clear_tactical_node_soi_details(dashboard: QtCore.QObject):
    dashboard.selected_tactical_node_soi_id = None

    labels = [
        dashboard.ui.label2_tactical_node_soi_frequency,
        dashboard.ui.label2_tactical_node_soi_status,
        dashboard.ui.label2_tactical_node_soi_node_id,
        dashboard.ui.label2_tactical_node_soi_soi_id,
        dashboard.ui.label2_tactical_node_soi_artifact_id,
        dashboard.ui.label2_tactical_node_soi_event_id,
        dashboard.ui.label2_tactical_node_soi_model,
        dashboard.ui.label2_tactical_node_soi_database,
    ]

    for label in labels:
        label.setText("")
    
    enable_tactical_node_soi_details(dashboard, False)


def enable_tactical_node_soi_details(dashboard: QtCore.QObject, enabled=True):
    widgets = [
        dashboard.ui.label2_tactical_node_soi_frequency2,
        dashboard.ui.label2_tactical_node_soi_status2,
        dashboard.ui.label2_tactical_node_soi_node_id2,
        dashboard.ui.label2_tactical_node_soi_soi_id2,
        dashboard.ui.label2_tactical_node_soi_artifact_id2,
        dashboard.ui.label2_tactical_node_soi_event_id2,
        dashboard.ui.label2_tactical_node_soi_model2,
        dashboard.ui.label2_tactical_node_soi_database2,

        dashboard.ui.label2_tactical_node_soi_frequency,
        dashboard.ui.label2_tactical_node_soi_status,
        dashboard.ui.label2_tactical_node_soi_node_id,
        dashboard.ui.label2_tactical_node_soi_soi_id,
        dashboard.ui.label2_tactical_node_soi_artifact_id,
        dashboard.ui.label2_tactical_node_soi_event_id,
        dashboard.ui.label2_tactical_node_soi_model,
        dashboard.ui.label2_tactical_node_soi_database,

        dashboard.ui.label2_tactical_node_soi_classification,

        dashboard.ui.pushButton_tactical_node_soi_download_evidence,
        dashboard.ui.pushButton_tactical_node_soi_promote_to_target,
        dashboard.ui.pushButton_tactical_node_soi_plot,
        dashboard.ui.pushButton_tactical_node_soi_plot_zoom,
        dashboard.ui.pushButton_tactical_node_soi_remove_from_map,
        dashboard.ui.pushButton_tactical_node_soi_delete_row,
    ]

    for widget in widgets:
        widget.setEnabled(enabled)

    dashboard.ui.pushButton_tactical_node_soi_clear_rows.setEnabled(
        dashboard.ui.tableWidget_tactical_node_sois.rowCount() > 0
    )


def enable_tactical_node_detection_details(dashboard: QtCore.QObject, enabled=True):
    widgets = [
        dashboard.ui.label2_node_detections_frequency,
        dashboard.ui.label2_node_detections_frequency2,
        dashboard.ui.label2_node_detections_time,
        dashboard.ui.label2_node_detections_time2,
        dashboard.ui.label2_node_detections_detector,
        dashboard.ui.label2_node_detections_detector2,
        dashboard.ui.label2_node_detections_op_id,
        dashboard.ui.label2_node_detections_op_id2,
        dashboard.ui.label2_node_detections_event_id,
        dashboard.ui.label2_node_detections_event_id2,

        dashboard.ui.pushButton_tactical_node_detections_promote_to_soi,
        dashboard.ui.pushButton_tactical_node_detections_delete_row,
        dashboard.ui.pushButton_tactical_node_detections_clear_rows,
        dashboard.ui.pushButton_tactical_node_detections_plot,
        dashboard.ui.pushButton_tactical_node_detections_plot_zoom,
        dashboard.ui.pushButton_tactical_node_detection_remove_from_map,
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


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeSoisDownloadEvidenceClicked(
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

        row_artifact_id = item.data(QtCore.Qt.UserRole)

        if row_artifact_id == artifact_id:

            # Switch to Artifacts tab
            dashboard.ui.tabWidget_tactical_node.setCurrentIndex(3)

            # Select matching artifact row
            table.selectRow(row)
            table.setCurrentCell(row, 0)

            # Optional: scroll into view
            table.scrollToItem(item)

            return

    dashboard.logger.warning(
        f"[Tactical] Artifact not found in table: {artifact_id}"
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeArtifactsOpenFolderClicked(
    dashboard: QtCore.QObject
):
    """
    Opens the artifact operation folder when available,
    otherwise opens the base hub artifacts folder.
    """
    artifact_folder = fissure.utils.HUB_ARTIFACTS_DIR

    artifact_id = getattr(
        dashboard,
        "selected_tactical_node_artifact_id",
        None,
    )

    if artifact_id:
        artifact = dashboard.tactical_artifacts.get(artifact_id)

        if artifact:
            operation_id = artifact.get("operation_id")

            candidate_folders = []

            if operation_id:
                candidate_folders.append(
                    os.path.join(
                        fissure.utils.HUB_ARTIFACTS_DIR,
                        operation_id,
                    )
                )

            candidate_folders.append(
                os.path.join(
                    fissure.utils.HUB_ARTIFACTS_DIR,
                    artifact_id,
                )
            )

            for candidate_folder in candidate_folders:
                if os.path.exists(candidate_folder):
                    artifact_folder = candidate_folder
                    break
            else:
                dashboard.logger.warning(
                    f"[Tactical] Artifact folder not found for "
                    f"artifact_id={artifact_id}, "
                    f"operation_id={operation_id}"
                )
        else:
            dashboard.logger.warning(
                f"[Tactical] No artifact record found for artifact_id={artifact_id}"
            )

    subprocess.Popen([
        "xdg-open",
        artifact_folder,
    ])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeArtifactsRowSelectionChanged(
    dashboard: QtCore.QObject
):
    table = dashboard.ui.tableWidget_tactical_node_artifacts

    selected_items = table.selectedItems()

    if not selected_items:
        dashboard.selected_tactical_node_artifact_id = None

        dashboard.ui.label2_tactical_node_artifacts_artifact_id.setText("")
        dashboard.ui.label2_tactical_node_artifacts_operation_id.setText("")

        dashboard.ui.frame5_tactical_node_artifacts_details.setEnabled(False)
        dashboard.ui.label2_tactical_node_artifacts_artifact_id.setEnabled(False)
        dashboard.ui.label2_tactical_node_artifacts_operation_id.setEnabled(False)
        dashboard.ui.label2_tactical_node_artifacts_artifact_id2.setEnabled(False)
        dashboard.ui.label2_tactical_node_artifacts_operation_id2.setEnabled(False)

        return

    row = selected_items[0].row()

    item = table.item(row, 0)
    if item is None:
        dashboard.selected_tactical_node_artifact_id = None
        return

    artifact_id = item.data(QtCore.Qt.UserRole)
    if not artifact_id:
        dashboard.selected_tactical_node_artifact_id = None
        return

    dashboard.selected_tactical_node_artifact_id = artifact_id

    artifact = dashboard.tactical_artifacts.get(artifact_id, {})

    operation_id = artifact.get("operation_id", "")

    dashboard.ui.label2_tactical_node_artifacts_artifact_id.setText(
        str(artifact_id)
    )
    dashboard.ui.label2_tactical_node_artifacts_operation_id.setText(
        str(operation_id)
    )

    dashboard.ui.frame5_tactical_node_artifacts_details.setEnabled(True)
    dashboard.ui.label2_tactical_node_artifacts_artifact_id.setEnabled(True)
    dashboard.ui.label2_tactical_node_artifacts_operation_id.setEnabled(True)
    dashboard.ui.label2_tactical_node_artifacts_artifact_id2.setEnabled(True)
    dashboard.ui.label2_tactical_node_artifacts_operation_id2.setEnabled(True)


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
    dashboard: QtCore.QObject
):
    detection = get_selected_tactical_node_detection(dashboard)
    if not detection:
        return

    frequency_mhz = detection.get("frequency")

    if frequency_mhz in [None, "", "None"]:
        dashboard.logger.warning(
            "[Tactical] Selected detection has no frequency for Promote to SOI."
        )
        return

    try:
        frequency_mhz = float(str(frequency_mhz).replace("MHz", "").strip())
    except Exception:
        dashboard.logger.warning(
            f"[Tactical] Invalid detection frequency for Promote to SOI: {frequency_mhz}"
        )
        return

    action_name = "promote_to_soi"

    combo = dashboard.ui.comboBox_tactical_node_actions
    index = combo.findText(action_name)

    if index < 0:
        dashboard.logger.warning(
            f"[Tactical] Action not available: {action_name}"
        )
        return

    dashboard.pending_tactical_customize_defaults = {
        "action_name": action_name,
        "values": {
            "frequency_mhz": frequency_mhz,
            "description": "Promote to SOI",
        },
    }

    combo.setCurrentIndex(index)

    await _slotTacticalNodeCustomizeClicked(dashboard)


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

    update_tactical_ecosystem_alert_buttons(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalEcosystemAlertsClearRowsClicked(
    dashboard: QtCore.QObject,
):
    dashboard.tactical_alerts.clear()

    dashboard.tactical_map.clear_alert_records()

    dashboard.ui.tableWidget_tactical_ecosystem_alerts.setRowCount(0)

    clear_tactical_ecosystem_alert_details(dashboard)

    update_tactical_ecosystem_alert_buttons(dashboard)


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
def _slotTacticalEcosystemAlertsRowSelectionChanged(dashboard: QtCore.QObject):
    alert = get_selected_tactical_ecosystem_alert(dashboard)

    if not alert:
        clear_tactical_ecosystem_alert_details(dashboard)
        update_tactical_ecosystem_alert_buttons(dashboard)
        return

    uid = alert.get("uid") or alert.get("alert_id")
    dashboard.selected_tactical_alert_id = uid

    # If you later add alert detail labels, populate them here.

    update_tactical_ecosystem_alert_buttons(dashboard)


def clear_tactical_ecosystem_alert_details(dashboard: QtCore.QObject):
    dashboard.selected_tactical_alert_id = None

    # Add label clearing here if you later create alert detail labels.
    # Example:
    # dashboard.ui.label2_tactical_ecosystem_alerts_uid.setText("")

    update_tactical_ecosystem_alert_buttons(dashboard)


def update_tactical_ecosystem_alert_buttons(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_tactical_ecosystem_alerts
    alert = get_selected_tactical_ecosystem_alert(dashboard)

    has_rows = table.rowCount() > 0
    has_selection = alert is not None

    has_location = False
    if alert:
        lat = alert.get("lat")
        lon = alert.get("lon")

        if lat not in [None, "", "None"] and lon not in [None, "", "None"]:
            try:
                float(lat)
                float(lon)
                has_location = True
            except Exception:
                has_location = False

    dashboard.ui.pushButton_tactical_ecosystem_alerts_plot.setEnabled(has_location)
    dashboard.ui.pushButton_tactical_ecosystem_alerts_plot_zoom.setEnabled(has_location)
    dashboard.ui.pushButton_tactical_ecosystem_alerts_remove_from_map.setEnabled(has_location)

    dashboard.ui.pushButton_tactical_ecosystem_alerts_delete_row.setEnabled(has_selection)
    dashboard.ui.pushButton_tactical_ecosystem_alerts_clear_rows.setEnabled(has_rows)


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


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTacticalNodeArtifactsDownloadClicked(
    dashboard: QtCore.QObject,
):
    """
    First-pass behavior: open the selected artifact folder.
    Later this can request/retrieve missing artifact files from the node.
    """
    _slotTacticalNodeArtifactsOpenFolderClicked(dashboard)


