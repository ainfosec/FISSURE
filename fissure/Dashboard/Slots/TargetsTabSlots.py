import html
import json
import os

import qasync
from PyQt5 import QtCore, QtGui, QtWidgets

import fissure.utils

from fissure.Dashboard.TargetDataController import build_target_data_folder
from fissure.Dashboard.Slots import TacticalTabSlots


def initialize_targets_tab(dashboard: QtCore.QObject):
    """Initialize the Targets workspace and shared Targets & Actions context."""
    dashboard.selected_targets_actions_target_id = None
    dashboard.pending_targets_actions_target_id = None

    table = dashboard.ui.tableWidget1_ta_targets
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)

    table.resizeColumnsToContents()
    table.resizeRowsToContents()
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setStretchLastSection(True)

    refresh_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "refresh.png",
    )

    if os.path.isfile(refresh_icon_path):
        refresh_button = dashboard.ui.pushButton_ta_targets_refresh
        refresh_button.setIcon(QtGui.QIcon(refresh_icon_path))
        refresh_button.setText("")
        refresh_button.setToolTip("Refresh targets")
        refresh_button.setIconSize(QtCore.QSize(18, 18))

    details_scroll = dashboard.ui.scrollArea_ta_targets_info

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

    dashboard.ui.comboBox_ta_target.clear()
    dashboard.ui.comboBox_ta_target.addItem("No Target", None)

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


