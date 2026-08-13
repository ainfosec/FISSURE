from PyQt5 import QtCore, QtGui, QtWidgets
import random
import os
import fissure.utils
import csv
import datetime
import time
import subprocess
import qasync
from ..UI_Components import DetectorSelectionDialog
from fissure.Dashboard.UI_Components.Qt5 import MyMessageBox
import struct
import matplotlib.pyplot as plt
import asyncio
import uuid

from fissure.utils.selected_node_utils import (
    selected_node_is_local,
    selected_node_is_remote,
    selected_node_is_ip,
    selected_node_is_meshtastic,
)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadPreviewClicked(dashboard: QtCore.QObject):
    """ 
    Plots a zoomed out version of the downloaded file.
    """
    # Ignore Folders
    get_index = dashboard.ui.listView_archive.currentIndex()
    if dashboard.ui.listView_archive.model().isDir(get_index) == True:
        return

    # Get the Folder and File
    get_file = str(dashboard.ui.listView_archive.currentIndex().data())
    get_folder = str(dashboard.ui.listView_archive.model().filePath(dashboard.ui.listView_archive.currentIndex())).rsplit('/',1)[0]
    get_filepath = os.path.join(get_folder, get_file)

    # Ignore No Selection
    if (len(get_folder) == 0) or (len(get_file) == 0):
        return

    # Get the Data Type and File Size
    get_type = str(dashboard.ui.comboBox_archive_downloaded_data_type.currentText())
        
    # Plot
    fissure.Dashboard.UI_Components.Qt5.previewIQ_File(get_type, get_filepath)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadRenameClicked(dashboard: QtCore.QObject):
    """ 
    Renames the selected file or folder in the Archive Downloaded listview.
    """
    # Get the Folder and File or Folder and Folder
    get_file = str(dashboard.ui.listView_archive.currentIndex().data())
    get_folder = str(dashboard.ui.listView_archive.model().filePath(dashboard.ui.listView_archive.currentIndex())).rsplit('/',1)[0]
    get_filepath = os.path.join(get_folder, get_file)

    # Ignore No Selection
    if (len(get_folder) == 0) or (len(get_file) == 0):
        return

    # Open the GUI
    text, ok = QtWidgets.QInputDialog.getText(dashboard, 'Rename', 'Enter new name:', QtWidgets.QLineEdit.Normal,get_file)

    # Ok Clicked
    if ok:
        os.rename(get_filepath, os.path.join(get_folder, text))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Reloads the files in the current Archive folder
    """
    # Get the Folder Location
    get_folder = dashboard.ui.listView_archive.model().rootPath()

    # Get the Extension Filter
    get_extension = str(dashboard.ui.comboBox_archive_extension.currentText())
    if get_extension == "All":
        filters = ['*']
    elif get_extension == "Custom":
        get_custom_extension = str(dashboard.ui.textEdit_archive_extension.toPlainText())
        filters = ['*' + get_custom_extension]
    else:
        filters = ['*' + get_extension]

    # Reset ListView
    #path = QtCore.QDir.rootPath()  #get_folder
    model = QtWidgets.QFileSystemModel(nameFilterDisables=False)
    model.setRootPath(get_folder)
    model.setFilter(QtCore.QDir.NoDot|QtCore.QDir.AllDirs|QtCore.QDir.Files)
    model.setNameFilters(filters)
    dashboard.ui.listView_archive.setModel(model)
    dashboard.ui.listView_archive.setRootIndex(model.index(get_folder))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadFolderChanged(dashboard: QtCore.QObject):
    """ 
    Changes the folder displayed in the ListView.
    """
    # Get the Folder Location
    get_folder = str(dashboard.ui.comboBox3_archive_download_folder.currentText())

    # Get the Extension Filter
    get_extension = str(dashboard.ui.comboBox_archive_extension.currentText())
    if get_extension == "All":
        filters = ['*']
    elif get_extension == "Custom":
        get_custom_extension = str(dashboard.ui.textEdit_archive_extension.toPlainText())
        filters = ['*' + get_custom_extension]
    else:
        filters = ['*' + get_extension]

    # Reset ListView
    #path = QtCore.QDir.rootPath()  #get_folder
    model = QtWidgets.QFileSystemModel(nameFilterDisables=False)
    model.setRootPath(get_folder)
    model.setFilter(QtCore.QDir.NoDot|QtCore.QDir.AllDirs|QtCore.QDir.Files)
    model.setNameFilters(filters)
    dashboard.ui.listView_archive.setModel(model)
    dashboard.ui.listView_archive.setRootIndex(model.index(get_folder))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveExtensionChanged(dashboard: QtCore.QObject):
    """ 
    Enables/disables the custom extension field in the Archive tab.
    """
    # Refresh
    if str(dashboard.ui.comboBox_archive_extension.currentText()) == "Custom":
        dashboard.ui.textEdit_archive_extension.setEnabled(True)
    else:
        dashboard.ui.textEdit_archive_extension.setEnabled(False)
        _slotArchiveDownloadRefreshClicked(dashboard)


def _clear_archive_replay_parameter_widgets(
    dashboard: QtCore.QObject,
):
    """
    Clear the Archive Replay parameter panel and widget registry.
    """
    content = (
        dashboard.ui
        .scrollAreaWidgetContents_archive_replay_parameters
    )
    layout = content.layout()

    if layout is None:
        layout = QtWidgets.QFormLayout(
            content
        )
        layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )
        layout.setHorizontalSpacing(
            10
        )
        layout.setVerticalSpacing(
            6
        )
        layout.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.AllNonFixedFieldsGrow
        )

    else:
        while layout.count():
            item = layout.takeAt(0)

            if item.widget() is not None:
                item.widget().deleteLater()

            if item.layout() is not None:
                child_layout = item.layout()

                while child_layout.count():
                    child_item = child_layout.takeAt(0)

                    if child_item.widget() is not None:
                        child_item.widget().deleteLater()

                child_layout.deleteLater()

    dashboard.archive_replay_parameter_widgets = {}
    dashboard.archive_replay_current_schema = {}
    dashboard.archive_replay_customized = False

    dashboard.ui.pushButton_archive_replay_start_stop.setEnabled(
        False
    )


def _reset_archive_replay_action_selection(
    dashboard: QtCore.QObject,
):
    """
    Clear queried Archive Replay actions and customized parameters.
    """
    dashboard.archive_replay_method_actions = []
    dashboard.archive_replay_selected_plugin = ""
    dashboard.archive_replay_selected_action = ""
    dashboard.archive_replay_action_query_pending = False
    dashboard.archive_replay_action_query_context = ""
    dashboard.archive_replay_action_query_node_uid = ""

    combo = dashboard.ui.comboBox_archive_replay_method

    combo.blockSignals(
        True
    )
    combo.clear()
    combo.blockSignals(
        False
    )
    combo.setEnabled(
        False
    )

    dashboard.ui.pushButton_archive_replay_customize.setEnabled(
        False
    )

    _clear_archive_replay_parameter_widgets(
        dashboard
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayActionHardwareChanged(
    dashboard: QtCore.QObject,
):
    """
    Reset the selected playback action and update playlist hardware defaults
    when the new Archive Replay hardware selector changes.
    """
    _reset_archive_replay_action_selection(
        dashboard
    )

    # The new hardware selector is now authoritative for Archive Replay.
    _slotArchiveReplayHardwareChanged(
        dashboard
    )

    has_node = bool(
        str(
            getattr(
                dashboard,
                "selected_node_uid",
                "",
            )
            or ""
        ).strip()
    )

    has_hardware = bool(
        str(
            dashboard.ui
            .comboBox_archive_replay_hardware
            .currentText()
            or ""
        ).strip()
    )

    dashboard.ui.pushButton_archive_replay_query.setEnabled(
        has_node and has_hardware
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotArchiveReplayQueryClicked(
    dashboard: QtCore.QObject,
):
    """
    Query the selected Sensor Node for compatible IQ Playback actions.
    """
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    hardware_display_name = str(
        dashboard.ui
        .comboBox_archive_replay_hardware
        .currentText()
        or ""
    ).strip()

    if not node_uid:
        dashboard.logger.warning(
            "Select a Sensor Node before querying Archive Replay actions."
        )
        return

    if not hardware_display_name:
        dashboard.logger.warning(
            "Select hardware before querying Archive Replay actions."
        )
        return

    (
        hardware_type,
        _hardware_uuid,
        _hardware_radio_name,
        _hardware_serial,
        _hardware_interface,
        _hardware_ip,
        _hardware_daughterboard,
    ) = fissure.utils.hardware.hardwareDisplayNameLookup(
        dashboard,
        hardware_display_name,
        "archive",
    )

    _reset_archive_replay_action_selection(
        dashboard
    )

    context = "archive.replay.actions"

    dashboard.archive_replay_action_query_pending = True
    dashboard.archive_replay_action_query_context = context
    dashboard.archive_replay_action_query_node_uid = node_uid

    dashboard.ui.pushButton_archive_replay_query.setText(
        "Querying..."
    )
    dashboard.ui.pushButton_archive_replay_query.setEnabled(
        False
    )

    await dashboard.backend.queryPluginActions(
        node_uid,
        context=context,
        scope="all_plugins",
        include_tags=[
            "iq.playback",
        ],
        hardware=hardware_type,
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayMethodChanged(
    dashboard: QtCore.QObject,
):
    """
    Update Archive Replay action state after action selection changes.
    """
    record = (
        dashboard.ui
        .comboBox_archive_replay_method
        .currentData()
    )

    if not isinstance(
        record,
        dict,
    ):
        dashboard.archive_replay_selected_plugin = ""
        dashboard.archive_replay_selected_action = ""

        dashboard.ui.pushButton_archive_replay_customize.setEnabled(
            False
        )

        _clear_archive_replay_parameter_widgets(
            dashboard
        )
        return

    plugin_name = str(
        record.get(
            "plugin",
            "",
        )
        or ""
    ).strip()

    action_name = str(
        record.get(
            "action",
            "",
        )
        or ""
    ).strip()

    dashboard.archive_replay_selected_plugin = plugin_name
    dashboard.archive_replay_selected_action = action_name

    _clear_archive_replay_parameter_widgets(
        dashboard
    )

    dashboard.ui.pushButton_archive_replay_customize.setEnabled(
        bool(
            plugin_name
            and action_name
        )
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotArchiveReplayCustomizeClicked(
    dashboard: QtCore.QObject,
):
    """
    Query the selected Archive Replay playback action schema.
    """
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    record = (
        dashboard.ui
        .comboBox_archive_replay_method
        .currentData()
    )

    if not node_uid:
        dashboard.logger.warning(
            "Select a Sensor Node before loading Archive Replay parameters."
        )
        return

    if not isinstance(
        record,
        dict,
    ):
        dashboard.logger.warning(
            "Select an Archive Replay action before loading parameters."
        )
        return

    plugin_name = str(
        record.get(
            "plugin",
            "",
        )
        or ""
    ).strip()

    action_name = str(
        record.get(
            "action",
            "",
        )
        or ""
    ).strip()

    if not plugin_name or not action_name:
        dashboard.logger.warning(
            "The selected Archive Replay action is missing plugin "
            "or action information."
        )
        return

    _clear_archive_replay_parameter_widgets(
        dashboard
    )

    dashboard.ui.pushButton_archive_replay_customize.setText(
        "Loading..."
    )
    dashboard.ui.pushButton_archive_replay_customize.setEnabled(
        False
    )

    await dashboard.backend.queryPluginActionSchema(
        node_uid,
        plugin_name,
        action_name,
        context="archive.replay.schema",
    )


def handle_archive_replay_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    """
    Populate the Archive Replay action selector from a filtered action query.
    """
    result_node_uid = str(
        node_uid
        or ""
    ).strip()

    result_context = str(
        context
        or ""
    ).strip()

    expected_node_uid = str(
        getattr(
            dashboard,
            "archive_replay_action_query_node_uid",
            "",
        )
        or ""
    ).strip()

    expected_context = str(
        getattr(
            dashboard,
            "archive_replay_action_query_context",
            "",
        )
        or ""
    ).strip()

    query_pending = bool(
        getattr(
            dashboard,
            "archive_replay_action_query_pending",
            False,
        )
    )

    if (
        not query_pending
        or result_node_uid != expected_node_uid
        or result_context != expected_context
    ):
        dashboard.logger.debug(
            "Ignoring stale Archive Replay action query results: "
            f"node_uid={result_node_uid!r}, "
            f"context={result_context!r}"
        )
        return

    dashboard.archive_replay_action_query_pending = False
    dashboard.archive_replay_action_query_context = ""
    dashboard.archive_replay_action_query_node_uid = ""

    combo = dashboard.ui.comboBox_archive_replay_method

    dashboard.archive_replay_method_actions = (
        actions
        if isinstance(
            actions,
            list,
        )
        else []
    )

    combo.blockSignals(
        True
    )
    combo.clear()

    for action_record in dashboard.archive_replay_method_actions:
        if not isinstance(
            action_record,
            dict,
        ):
            continue

        plugin_name = str(
            action_record.get(
                "plugin",
                "",
            )
            or ""
        ).strip()

        action_name = str(
            action_record.get(
                "action",
                "",
            )
            or ""
        ).strip()

        if not plugin_name or not action_name:
            continue

        combo.addItem(
            f"{plugin_name}: {action_name}",
            {
                "plugin": plugin_name,
                "action": action_name,
            },
        )

    combo.blockSignals(
        False
    )

    has_actions = combo.count() > 0

    combo.setEnabled(
        has_actions
    )

    dashboard.ui.pushButton_archive_replay_query.setText(
        "Query Actions"
    )
    dashboard.ui.pushButton_archive_replay_query.setEnabled(
        True
    )

    dashboard.ui.pushButton_archive_replay_customize.setEnabled(
        has_actions
    )

    if has_actions:
        combo.setCurrentIndex(
            0
        )

        _slotArchiveReplayMethodChanged(
            dashboard
        )

    else:
        dashboard.archive_replay_selected_plugin = ""
        dashboard.archive_replay_selected_action = ""


def _create_archive_replay_parameter_widget(
    dashboard: QtCore.QObject,
    parameter: dict,
):
    """
    Create one editor for an Archive Replay action-schema parameter.
    """
    parameter_type = str(
        parameter.get(
            "type",
            "string",
        )
        or "string"
    ).strip().lower()

    default = parameter.get(
        "default",
        "",
    )

    options = parameter.get(
        "options",
        [],
    )

    parent = (
        dashboard.ui
        .scrollAreaWidgetContents_archive_replay_parameters
    )

    if isinstance(
        options,
        list,
    ) and options:
        widget = QtWidgets.QComboBox(
            parent
        )

        for option in options:
            widget.addItem(
                str(option)
            )

        default_index = widget.findText(
            str(default),
            QtCore.Qt.MatchExactly,
        )

        if default_index >= 0:
            widget.setCurrentIndex(
                default_index
            )

        return widget

    if parameter_type in {
        "int",
        "integer",
    }:
        widget = QtWidgets.QSpinBox(
            parent
        )
        widget.setMinimum(
            int(
                parameter.get(
                    "min",
                    -2147483647,
                )
            )
        )
        widget.setMaximum(
            int(
                parameter.get(
                    "max",
                    2147483647,
                )
            )
        )
        widget.setSingleStep(
            int(
                parameter.get(
                    "step",
                    1,
                )
            )
        )
        widget.setValue(
            int(
                default
                or 0
            )
        )
        return widget

    if parameter_type in {
        "float",
        "double",
        "number",
    }:
        widget = QtWidgets.QDoubleSpinBox(
            parent
        )
        widget.setDecimals(
            int(
                parameter.get(
                    "decimals",
                    6,
                )
            )
        )
        widget.setMinimum(
            float(
                parameter.get(
                    "min",
                    -1000000000000.0,
                )
            )
        )
        widget.setMaximum(
            float(
                parameter.get(
                    "max",
                    1000000000000.0,
                )
            )
        )
        widget.setSingleStep(
            float(
                parameter.get(
                    "step",
                    1.0,
                )
            )
        )
        widget.setValue(
            float(
                default
                or 0.0
            )
        )
        return widget

    if parameter_type in {
        "bool",
        "boolean",
    }:
        widget = QtWidgets.QCheckBox(
            parent
        )

        if isinstance(
            default,
            str,
        ):
            checked = default.strip().lower() in {
                "true",
                "1",
                "yes",
                "on",
                "enabled",
            }

        else:
            checked = bool(
                default
            )

        widget.setChecked(
            checked
        )
        return widget

    if parameter_type == "label":
        widget = QtWidgets.QLabel(
            str(default),
            parent,
        )
        widget.setWordWrap(
            True
        )
        widget.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse
        )
        return widget

    return QtWidgets.QLineEdit(
        str(default),
        parent,
    )


def _archive_replay_parameter_widget_value(
    widget: QtWidgets.QWidget,
):
    """Return the current value from one Archive Replay parameter editor."""
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


def _collect_archive_replay_action_parameters(
    dashboard: QtCore.QObject,
    row: int,
):
    """
    Collect customized playback defaults, hardware identity, and one playlist
    row's playback overrides.
    """
    table = dashboard.ui.tableWidget_archive_replay

    if row < 0 or row >= table.rowCount():
        raise ValueError("Archive Replay playlist row is out of range.")

    parameters = {}

    for parameter_name, record in (
        getattr(
            dashboard,
            "archive_replay_parameter_widgets",
            {},
        )
        or {}
    ).items():
        if not isinstance(record, dict):
            continue

        widget = record.get("widget")
        schema = record.get("schema", {})

        if widget is None:
            continue

        parameter_type = str(
            schema.get("type", "string")
            or "string"
        ).strip().lower()

        if parameter_type == "label":
            continue

        parameters[parameter_name] = (
            _archive_replay_parameter_widget_value(widget)
        )

    hardware_display_name = str(
        dashboard.ui.comboBox_archive_replay_hardware.currentText()
        or ""
    ).strip()

    (
        hardware_type,
        hardware_uuid,
        hardware_radio_name,
        hardware_serial,
        hardware_interface,
        hardware_ip,
        hardware_daughterboard,
    ) = fissure.utils.hardware.hardwareDisplayNameLookup(
        dashboard,
        hardware_display_name,
        "archive",
    )

    raw_serial_hardware = {
        "HackRF",
        "RTL2832U",
        "bladeRF",
        "bladeRF 2.0",
        "RSPduo",
        "RSPdx",
        "RSPdx R2",
    }

    zero_default_serial_hardware = {
        "RTL2832U",
        "bladeRF",
        "bladeRF 2.0",
        "RSPduo",
        "RSPdx",
        "RSPdx R2",
    }

    if hardware_serial:
        if hardware_type in raw_serial_hardware:
            hardware_serial_argument = hardware_serial
        else:
            hardware_serial_argument = f"serial={hardware_serial}"
    else:
        if hardware_type == "HackRF":
            hardware_serial_argument = ""
        elif hardware_type in zero_default_serial_hardware:
            hardware_serial_argument = "0"
        else:
            hardware_serial_argument = "False"

    def _item_text(column: int) -> str:
        item = table.item(row, column)

        if item is None:
            raise ValueError(
                f"Archive Replay row {row + 1} is missing column {column}."
            )

        return str(item.text() or "").strip()

    filename = _item_text(0)
    folder = _item_text(9)
    filepath = os.path.join(folder, filename)

    # Archive stores these in Hz. iq_playback exposes MHz / MS/s.
    tx_frequency_mhz = float(_item_text(3)) / 1e6
    sample_rate_msps = float(_item_text(4)) / 1e6

    data_type = _item_text(5)
    tx_gain = float(_item_text(7))
    duration = float(_item_text(8))

    channel_widget = table.cellWidget(row, 6)

    if not isinstance(channel_widget, QtWidgets.QComboBox):
        raise ValueError(
            f"Archive Replay row {row + 1} is missing its TX Channel selector."
        )

    tx_channel = str(
        channel_widget.currentText()
        or ""
    ).strip()

    if not filename:
        raise ValueError("Archive Replay filename is empty.")

    if duration <= 0:
        raise ValueError(
            "Archive Replay Duration must be greater than zero."
        )

    parameters.update(
        {
            "operation_id": str(uuid.uuid4()),
            "requester": "dashboard",
            "filepath": filepath,
            "hardware_display_name": hardware_display_name,
            "hardware_type": hardware_type,
            "hardware_uuid": hardware_uuid,
            "hardware_radio_name": hardware_radio_name,
            "hardware_serial": hardware_serial,
            "hardware_serial_argument": hardware_serial_argument,
            "hardware_interface": hardware_interface,
            "hardware_ip": hardware_ip,
            "hardware_daughterboard": hardware_daughterboard,

            # Playlist row overrides.
            "tx_frequency": tx_frequency_mhz,
            "sample_rate_msps": sample_rate_msps,
            "data_type": data_type,
            "tx_channel": tx_channel,
            "tx_gain": tx_gain,
        }
    )

    return parameters, duration


def _set_archive_replay_start_stop_button(
    dashboard: QtCore.QObject,
    running: bool,
):
    """Update the plugin-backed Archive Replay Start/Stop button."""
    button = dashboard.ui.pushButton_archive_replay_start_stop

    button.setText(
        "Stop Replay"
        if running
        else "Start Replay"
    )

    button.setProperty(
        "running",
        bool(running),
    )

    button.style().unpolish(
        button
    )
    button.style().polish(
        button
    )
    button.update()


def _update_archive_replay_start_button(
    dashboard: QtCore.QObject,
):
    """Enable Start only when the playback action and playlist are ready."""
    running = bool(
        getattr(
            dashboard,
            "archive_replay_running",
            False,
        )
    )

    _set_archive_replay_start_stop_button(
        dashboard,
        running,
    )

    if running:
        stop_event = getattr(
            dashboard,
            "archive_replay_stop_event",
            None,
        )

        stopping = bool(
            stop_event is not None
            and stop_event.is_set()
        )

        dashboard.ui.pushButton_archive_replay_start_stop.setEnabled(
            not stopping
        )
        return

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
        node_state = (
            getattr(
                dashboard,
                "node_states",
                {},
            )
            or {}
        ).get(
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

    ready = bool(
        has_selected_node
        and getattr(
            dashboard,
            "archive_replay_customized",
            False,
        )
        and str(
            getattr(
                dashboard,
                "archive_replay_selected_plugin",
                "",
            )
            or ""
        ).strip()
        and str(
            getattr(
                dashboard,
                "archive_replay_selected_action",
                "",
            )
            or ""
        ).strip()
        and dashboard.ui.tableWidget_archive_replay.rowCount() > 0
    )

    dashboard.ui.pushButton_archive_replay_start_stop.setEnabled(
        ready
    )


def _set_archive_replay_execution_controls_enabled(
    dashboard: QtCore.QObject,
    enabled: bool,
):
    """Freeze mutable Archive Replay controls while playback is active."""
    for widget in (
        dashboard.ui.comboBox_archive_replay_hardware,
        dashboard.ui.comboBox_archive_replay_method,
        dashboard.ui.pushButton_archive_replay_query,
        dashboard.ui.pushButton_archive_replay_customize,
        dashboard.ui.tableWidget_archive_replay_detectors,
        dashboard.ui.pushButton_archive_replay_detector_add,
        dashboard.ui.pushButton_archive_replay_detector_remove,
        dashboard.ui.tableWidget_archive_replay,
        dashboard.ui.pushButton_archive_replay_add,
        dashboard.ui.pushButton_archive_replay_remove,
        dashboard.ui.pushButton_archive_replay_remove_all,
        dashboard.ui.pushButton_archive_replay_up,
        dashboard.ui.pushButton_archive_replay_down,
        dashboard.ui.pushButton_archive_replay_import_csv,
        dashboard.ui.checkBox_archive_replay_repeat,
    ):
        widget.setEnabled(enabled)

    for record in (getattr(dashboard, "archive_replay_parameter_widgets", {}) or {}).values():
        if not isinstance(record, dict):
            continue

        widget = record.get("widget")
        if widget is not None:
            widget.setEnabled(enabled)


async def _wait_for_archive_replay_playback_started(
    dashboard: QtCore.QObject,
    node_uid: str,
    stop_event,
    timeout: float = 15.0,
):
    """
    Wait for IQ Playback to report that its flow graph has actually started.

    The Sensor Node publishes "Running: IQ Playback" only after tb.start(),
    so Archive Replay can begin its Duration clock at the real playback edge
    instead of including SDR initialization time.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + float(timeout)

    while loop.time() < deadline:
        if (
            stop_event is not None
            and stop_event.is_set()
        ):
            return False

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

        status = str(
            node_state.get(
                "status",
                "",
            )
            or ""
        ).strip()

        if status == "Running: IQ Playback":
            return True

        await asyncio.sleep(
            0.05
        )

    return False


async def _wait_for_archive_replay_playback_stopped(
    dashboard: QtCore.QObject,
    node_uid: str,
    timeout: float = 10.0,
):
    """Wait for the current IQ Playback operation to release the node."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + float(timeout)

    while loop.time() < deadline:
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

        status = str(
            node_state.get(
                "status",
                "",
            )
            or ""
        ).strip()

        if status not in {
            "Running: iq_playback.py",
            "Running: IQ Playback",
        }:
            return True

        await asyncio.sleep(
            0.05
        )

    return False


async def _stage_archive_replay_remote_files(
    dashboard: QtCore.QObject,
    node_uid: str,
    playlist_rows: list,
    stop_event,
):
    """
    Stage Dashboard-local Archive Replay source files on a remote Sensor Node.

    Each unique source is uploaded once to Sensor_Node/Archive_Replay. The
    returned row plans point iq_playback at the staged Sensor Node path.
    """
    staged_rows = []
    sources_by_name = {}
    unique_sources = []

    for row_index, row_plan in enumerate(
        playlist_rows
    ):
        parameter_template, duration = row_plan

        local_filepath = str(
            parameter_template.get(
                "filepath",
                "",
            )
            or ""
        ).strip()

        if not local_filepath:
            raise ValueError(
                f"Archive Replay row {row_index + 1} has no filepath."
            )

        if not os.path.isfile(
            local_filepath
        ):
            raise FileNotFoundError(
                f"Archive Replay source file not found: {local_filepath}"
            )

        basename = os.path.basename(
            local_filepath
        )

        previous_source = sources_by_name.get(
            basename
        )

        if (
            previous_source
            and os.path.abspath(
                previous_source
            ) != os.path.abspath(
                local_filepath
            )
        ):
            raise ValueError(
                "Archive Replay remote staging cannot use two different "
                f"files with the same filename: {basename}"
            )

        if previous_source is None:
            sources_by_name[
                basename
            ] = local_filepath
            unique_sources.append(
                local_filepath
            )

        staged_parameters = dict(
            parameter_template
        )
        staged_parameters[
            "playback_file_mode"
        ] = "transfer"
        staged_parameters[
            "filepath"
        ] = f"/Archive_Replay/{basename}"

        staged_rows.append(
            (
                staged_parameters,
                duration,
            )
        )

    total_files = len(
        unique_sources
    )

    dashboard.logger.info(
        "Preparing Archive Replay files on remote Sensor Node: "
        f"node_uid={node_uid}, files={total_files}"
    )

    for file_index, local_filepath in enumerate(
        unique_sources,
        start=1,
    ):
        if (
            stop_event is not None
            and stop_event.is_set()
        ):
            return staged_rows

        dashboard.ui.label2_archive_replay_status.setText(
            f"Staging File {file_index}/{total_files}..."
        )

        dashboard.logger.info(
            "Staging Archive Replay file on remote Sensor Node: "
            f"node_uid={node_uid}, "
            f"file={local_filepath}"
        )

        transferred = await dashboard.backend.transferSensorNodeFile(
            node_uid,
            local_filepath,
            "/Archive_Replay",
            False,
        )

        if not transferred:
            raise RuntimeError(
                "Failed to stage Archive Replay file on Sensor Node: "
                f"{local_filepath}"
            )

    return staged_rows


async def _run_archive_replay_playlist(
    dashboard: QtCore.QObject,
    node_uid: str,
    plugin_name: str,
    action_name: str,
    playlist_rows: list,
    detector_configs: list,
    repeat_enabled: bool,
    remote_node: bool,
):
    """Run Archive Replay after optional detector gating."""
    stop_event = getattr(dashboard, "archive_replay_stop_event", None)
    final_status = "Completed"
    pass_number = 1

    try:
        if remote_node:
            playlist_rows = await _stage_archive_replay_remote_files(
                dashboard,
                node_uid,
                playlist_rows,
                stop_event,
            )

            if stop_event is not None and stop_event.is_set():
                final_status = "Stopped"

        if final_status == "Completed" and detector_configs:
            dashboard.archive_replay_detection_event = asyncio.Event()
            dashboard.archive_replay_detection = None

            dashboard.ui.label2_archive_replay_status.setText("Starting Detectors...")
            await _start_archive_replay_detectors(dashboard, node_uid, detector_configs)

            if stop_event is not None and stop_event.is_set():
                final_status = "Stopped"
            else:
                dashboard.ui.label2_archive_replay_status.setText("Waiting for Detection...")
                detected = await _wait_for_archive_replay_detection(dashboard, stop_event)

                if stop_event is not None and stop_event.is_set():
                    final_status = "Stopped"
                elif not detected:
                    final_status = "Error"

            await _stop_archive_replay_detectors(dashboard, node_uid)

            if final_status == "Completed":
                detection = getattr(dashboard, "archive_replay_detection", {}) or {}
                dashboard.logger.info(
                    "Archive Replay detector gate released: "
                    f"detector={detection.get('detector', '')}, "
                    f"operation_id={detection.get('opid') or detection.get('operation_id') or ''}"
                )

        total_rows = len(playlist_rows)

        while final_status == "Completed":
            for row_index, row_plan in enumerate(playlist_rows):
                if stop_event is not None and stop_event.is_set():
                    final_status = "Stopped"
                    break

                parameter_template, duration = row_plan
                parameters = dict(parameter_template)

                operation_id = str(uuid.uuid4())
                parameters["operation_id"] = operation_id

                row_number = row_index + 1
                dashboard.archive_replay_operation_id = operation_id
                dashboard.ui.tableWidget_archive_replay.selectRow(row_index)
                dashboard.ui.label2_archive_replay_status.setText(
                    f"Starting Row {row_number}/{total_rows}..."
                )

                dashboard.logger.info(
                    f"Starting Archive Replay row {row_number}/{total_rows}: "
                    f"pass={pass_number}, "
                    f"plugin={plugin_name}, "
                    f"action={action_name}, "
                    f"node_uid={node_uid}, "
                    f"operation_id={operation_id}, "
                    f"filepath={parameters.get('filepath', '')}, "
                    f"duration={duration}"
                )

                await dashboard.backend.tacticalNodeExecute(
                    [node_uid],
                    plugin_name,
                    action_name,
                    parameters,
                )

                playback_started = await _wait_for_archive_replay_playback_started(
                    dashboard,
                    node_uid,
                    stop_event,
                )

                if stop_event is not None and stop_event.is_set():
                    final_status = "Stopped"

                elif not playback_started:
                    final_status = "Error"
                    dashboard.logger.error(
                        f"Archive Replay row {row_number}/{total_rows} "
                        "did not report playback-ready status before the startup timeout."
                    )

                else:
                    dashboard.logger.info(
                        f"Archive Replay row {row_number}/{total_rows} "
                        f"playback started; beginning {duration}-second Duration."
                    )

                    dashboard.ui.label2_archive_replay_status.setText(
                        f"Playing Row {row_number}/{total_rows}..."
                    )

                    if stop_event is not None:
                        try:
                            await asyncio.wait_for(stop_event.wait(), timeout=duration)
                            final_status = "Stopped"
                        except asyncio.TimeoutError:
                            pass
                    else:
                        await asyncio.sleep(duration)

                if operation_id:
                    dashboard.ui.label2_archive_replay_status.setText(
                        f"Stopping Row {row_number}/{total_rows}..."
                    )

                    await dashboard.backend.stopPluginOperation(node_uid, operation_id)

                    playback_stopped = await _wait_for_archive_replay_playback_stopped(
                        dashboard,
                        node_uid,
                    )

                    if not playback_stopped:
                        final_status = "Error"
                        dashboard.logger.error(
                            f"Archive Replay row {row_number}/{total_rows} "
                            "did not stop before the shutdown timeout."
                        )

                dashboard.archive_replay_operation_id = ""

                if final_status != "Completed":
                    break

            if final_status != "Completed":
                break

            if not repeat_enabled:
                break

            if stop_event is not None and stop_event.is_set():
                final_status = "Stopped"
                break

            pass_number += 1
            dashboard.logger.info(f"Repeating Archive Replay playlist: pass={pass_number}")

    except Exception as error:
        final_status = "Error"
        dashboard.logger.error(f"Archive Replay playlist failed: {error}")

        try:
            await _stop_archive_replay_detectors(dashboard, node_uid)
        except Exception:
            pass

    finally:
        dashboard.archive_replay_running = False
        dashboard.archive_replay_node_uid = ""
        dashboard.archive_replay_operation_id = ""
        dashboard.archive_replay_detector_operation_ids = set()
        dashboard.archive_replay_detection_event = None
        dashboard.archive_replay_detection = None
        dashboard.archive_replay_stop_event = None
        dashboard.archive_replay_task = None

        _set_archive_replay_execution_controls_enabled(dashboard, True)
        update_archive_replay_selected_node_gate(dashboard)
        dashboard.ui.label2_archive_replay_status.setText(final_status)


@qasync.asyncSlot(QtCore.QObject)
async def _slotArchiveReplayStartStopClicked(dashboard: QtCore.QObject):
    """Start or stop the plugin-backed Archive Replay playlist."""
    if bool(getattr(dashboard, "archive_replay_running", False)):
        stop_event = getattr(dashboard, "archive_replay_stop_event", None)
        dashboard.ui.label2_archive_replay_status.setText("Stopping...")

        if stop_event is not None:
            stop_event.set()

        _update_archive_replay_start_button(dashboard)
        return

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()

    if not node_uid:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Select a Sensor Node.",
        )
        return

    if not bool(getattr(dashboard, "archive_replay_customized", False)):
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Load the Archive Replay parameters before starting.",
        )
        return

    plugin_name = str(getattr(dashboard, "archive_replay_selected_plugin", "") or "").strip()
    action_name = str(getattr(dashboard, "archive_replay_selected_action", "") or "").strip()

    if not plugin_name or not action_name:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Select an Archive Replay action.",
        )
        return

    row_count = dashboard.ui.tableWidget_archive_replay.rowCount()

    if row_count < 1:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Add at least one file to the Archive Replay playlist.",
        )
        return

    playlist_rows = []

    for row in range(row_count):
        try:
            playlist_rows.append(_collect_archive_replay_action_parameters(dashboard, row))
        except Exception as error:
            dashboard.logger.error(
                f"Failed to build Archive Replay row {row + 1} parameters: {error}"
            )

            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                f"Archive Replay row {row + 1} has invalid values.",
            )
            return

    detector_configs = _collect_archive_replay_detector_configs(dashboard)
    repeat_enabled = dashboard.ui.checkBox_archive_replay_repeat.isChecked()

    dashboard.archive_replay_running = True
    dashboard.archive_replay_node_uid = node_uid
    dashboard.archive_replay_operation_id = ""
    dashboard.archive_replay_detector_operation_ids = set()
    dashboard.archive_replay_detection_event = None
    dashboard.archive_replay_detection = None
    dashboard.archive_replay_stop_event = asyncio.Event()

    _set_archive_replay_execution_controls_enabled(dashboard, False)
    _update_archive_replay_start_button(dashboard)

    dashboard.archive_replay_task = asyncio.create_task(
        _run_archive_replay_playlist(
            dashboard,
            node_uid,
            plugin_name,
            action_name,
            playlist_rows,
            detector_configs,
            repeat_enabled,
            selected_node_is_remote(dashboard),
        )
    )


def handle_archive_replay_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
):
    """
    Build the Archive Replay parameter panel from an action schema.
    """
    selected_node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if str(
        node_uid
        or ""
    ).strip() != selected_node_uid:
        dashboard.logger.debug(
            "Ignoring Archive Replay action schema for a different Sensor Node."
        )
        return

    selected_record = (
        dashboard.ui
        .comboBox_archive_replay_method
        .currentData()
    )

    if not isinstance(
        selected_record,
        dict,
    ):
        return

    selected_plugin = str(
        selected_record.get(
            "plugin",
            "",
        )
        or ""
    ).strip()

    selected_action = str(
        selected_record.get(
            "action",
            "",
        )
        or ""
    ).strip()

    if (
        selected_plugin != str(
            plugin_name
            or ""
        ).strip()
        or selected_action != str(
            action_name
            or ""
        ).strip()
    ):
        dashboard.logger.debug(
            "Ignoring Archive Replay action schema for a different action."
        )
        return

    _clear_archive_replay_parameter_widgets(
        dashboard
    )

    content = (
        dashboard.ui
        .scrollAreaWidgetContents_archive_replay_parameters
    )
    layout = content.layout()

    if layout is None:
        layout = QtWidgets.QFormLayout(
            content
        )
        layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )
        layout.setHorizontalSpacing(
            10
        )
        layout.setVerticalSpacing(
            6
        )
        layout.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.AllNonFixedFieldsGrow
        )

    normalized_parameters = (
        parameters
        if isinstance(
            parameters,
            list,
        )
        else []
    )

    dashboard.archive_replay_current_schema = {
        "plugin":
            selected_plugin,
        "action":
            selected_action,
        "params":
            normalized_parameters,
    }

    for parameter in normalized_parameters:
        if not isinstance(
            parameter,
            dict,
        ):
            continue

        name = str(
            parameter.get(
                "name",
                "",
            )
            or ""
        ).strip()

        if not name:
            continue

        label_text = str(
            parameter.get(
                "label",
                name,
            )
            or name
        )

        widget = _create_archive_replay_parameter_widget(
            dashboard,
            parameter,
        )

        if isinstance(
            widget,
            QtWidgets.QDoubleSpinBox,
        ):
            widget.setObjectName(
                "doubleSpinBox_archive_replay_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QSpinBox,
        ):
            widget.setObjectName(
                "spinBox_archive_replay_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QComboBox,
        ):
            widget.setObjectName(
                "comboBox_archive_replay_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QCheckBox,
        ):
            widget.setObjectName(
                "checkBox_archive_replay_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QLineEdit,
        ):
            widget.setObjectName(
                "lineEdit_archive_replay_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QLabel,
        ):
            widget.setObjectName(
                "label_archive_replay_parameter_info"
            )

        dashboard.archive_replay_parameter_widgets[
            name
        ] = {
            "widget":
                widget,
            "schema":
                dict(
                    parameter
                ),
        }

        label = QtWidgets.QLabel(
            label_text,
            content,
        )
        label.setObjectName(
            "label_archive_replay_parameter"
        )
        label.setWordWrap(
            True
        )

        layout.addRow(
            label,
            widget,
        )

    dashboard.archive_replay_selected_plugin = selected_plugin
    dashboard.archive_replay_selected_action = selected_action
    dashboard.archive_replay_customized = True

    dashboard.ui.pushButton_archive_replay_customize.setText(
        "Customize"
    )
    dashboard.ui.pushButton_archive_replay_customize.setEnabled(
        True
    )

    _update_archive_replay_start_button(
        dashboard
    )

    dashboard.ui.label2_archive_replay_status.setText(
        "Ready"
    )


def initialize_archive_replay_controls(
    dashboard: QtCore.QObject,
):
    """
    Initialize the plugin-backed Archive Replay control strip.
    """
    dashboard.archive_replay_method_actions = []
    dashboard.archive_replay_selected_plugin = ""
    dashboard.archive_replay_selected_action = ""
    dashboard.archive_replay_parameter_widgets = {}
    dashboard.archive_replay_current_schema = {}
    dashboard.archive_replay_customized = False

    dashboard.archive_replay_running = False
    dashboard.archive_replay_node_uid = ""
    dashboard.archive_replay_operation_id = ""
    dashboard.archive_replay_task = None
    dashboard.archive_replay_stop_event = None
    dashboard.archive_replay_detector_operation_ids = set()
    dashboard.archive_replay_detection_event = None
    dashboard.archive_replay_detection = None

    dashboard.archive_replay_action_query_pending = False
    dashboard.archive_replay_action_query_context = ""
    dashboard.archive_replay_action_query_node_uid = ""

    dashboard.ui.stackedWidget_archive_replay.setCurrentWidget(
        dashboard.ui.page_archive_replay_no_node
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

        dashboard.ui.label_archive_replay_select_sensor_node_image.setPixmap(
            select_node_pixmap
        )
        dashboard.ui.label_archive_replay_select_sensor_node_image.setScaledContents(
            False
        )
        dashboard.ui.label_archive_replay_select_sensor_node_image.setAlignment(
            QtCore.Qt.AlignCenter
        )

    step_badges = (
        (
            dashboard.ui.label_archive_replay_setup_badge,
            "1",
        ),
        (
            dashboard.ui.label_archive_replay_parameters_badge,
            "2",
        ),
        (
            dashboard.ui.label_archive_replay_run_badge,
            "5",
        ),
    )

    for badge, badge_text in step_badges:
        badge.setText(
            badge_text
        )
        badge.setAlignment(
            QtCore.Qt.AlignCenter
        )

    dashboard.ui.comboBox_archive_replay_method.clear()
    dashboard.ui.comboBox_archive_replay_method.setEnabled(
        False
    )

    dashboard.ui.pushButton_archive_replay_query.setText(
        "Query Actions"
    )
    dashboard.ui.pushButton_archive_replay_query.setEnabled(
        False
    )

    dashboard.ui.pushButton_archive_replay_customize.setText(
        "Customize"
    )
    dashboard.ui.pushButton_archive_replay_customize.setEnabled(
        False
    )

    dashboard.ui.pushButton_archive_replay_start_stop.setText(
        "Start Replay"
    )
    dashboard.ui.pushButton_archive_replay_start_stop.setEnabled(
        False
    )
    dashboard.ui.pushButton_archive_replay_start_stop.setProperty(
        "running",
        False,
    )

    dashboard.ui.label2_archive_replay_status.setText(
        "Unavailable"
    )

    scroll_area = getattr(
        dashboard.ui,
        "scrollArea_archive_replay_parameters",
        None,
    )

    if scroll_area is not None:
        scroll_area.setHorizontalScrollBarPolicy(
            QtCore.Qt.ScrollBarAlwaysOff
        )
        scroll_area.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarAsNeeded
        )

        parameter_widgets = [
            scroll_area,
            scroll_area.viewport(),
            scroll_area.widget(),
        ]

        for widget in parameter_widgets:
            if widget is None:
                continue

            widget.setProperty(
                "uiRole",
                "parameterPanel",
            )
            widget.style().unpolish(
                widget
            )
            widget.style().polish(
                widget
            )
            widget.update()

    _clear_archive_replay_parameter_widgets(
        dashboard
    )

    update_archive_replay_selected_node_gate(
        dashboard
    )

    # Replay Detector Table
    table = dashboard.ui.tableWidget_archive_replay_detectors
    header = table.horizontalHeader()

    header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
    header.setDefaultAlignment(QtCore.Qt.AlignCenter | QtCore.Qt.AlignVCenter)

    table.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    table.setTextElideMode(QtCore.Qt.ElideRight)
    table.setWordWrap(False)


def update_archive_replay_selected_node_gate(
    dashboard: QtCore.QObject,
):
    """
    Show Archive Replay controls only when an online Sensor Node is selected.
    Preserve execution state across heartbeat refreshes.
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

    dashboard.ui.stackedWidget_archive_replay.setCurrentWidget(
        dashboard.ui.page_archive_replay_controls
        if has_selected_node
        else dashboard.ui.page_archive_replay_no_node
    )

    running = bool(
        getattr(
            dashboard,
            "archive_replay_running",
            False,
        )
    )

    hardware_combo = (
        dashboard.ui.comboBox_archive_replay_hardware
    )
    method_combo = (
        dashboard.ui.comboBox_archive_replay_method
    )
    query_button = (
        dashboard.ui.pushButton_archive_replay_query
    )
    customize_button = (
        dashboard.ui.pushButton_archive_replay_customize
    )

    mutable_controls_enabled = (
        has_selected_node
        and not running
    )

    hardware_combo.setEnabled(
        mutable_controls_enabled
        and hardware_combo.count() > 0
    )

    method_combo.setEnabled(
        mutable_controls_enabled
        and method_combo.count() > 0
    )

    query_button.setEnabled(
        mutable_controls_enabled
        and hardware_combo.count() > 0
    )

    customize_button.setEnabled(
        mutable_controls_enabled
        and isinstance(
            method_combo.currentData(),
            dict,
        )
    )

    _update_archive_replay_start_button(
        dashboard
    )

    # Do not let heartbeat/state refresh overwrite Playing/Stopping text.
    if running:
        return

    if not has_selected_node:
        dashboard.ui.label2_archive_replay_status.setText(
            "Unavailable"
        )

    elif bool(
        getattr(
            dashboard,
            "archive_replay_customized",
            False,
        )
    ):
        dashboard.ui.label2_archive_replay_status.setText(
            "Ready"
        )

    else:
        dashboard.ui.label2_archive_replay_status.setText(
            "Idle"
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Changes the Archive replay settings based on hardware.
    """
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_archive_replay_hardware.currentText())
    get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'archive')
    
    # Hardware Utility Functions
    get_gain = fissure.utils.hardware.getHardwareGain(get_hardware_type, "TX")
    get_channels = fissure.utils.hardware.getHardwareChannels(get_hardware_type, "TX")
    get_antennas = fissure.utils.hardware.getHardwareAntennas(get_hardware_type, "TX")

    # Adjust Existing Channel ComboBoxes and Gain in Replay Tab
    for n in range(0, dashboard.ui.tableWidget_archive_replay.rowCount()):
        get_combobox = dashboard.ui.tableWidget_archive_replay.cellWidget(n,6)
        get_combobox.clear()
        if get_hardware_type == "Computer":
            get_combobox.addItem("")
        elif get_hardware_type == "USRP X3x0":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "USRP B2x0":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "HackRF":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "RTL2832U":
            get_combobox.addItem("")
        elif get_hardware_type == "802.11x Adapter":
            get_combobox.addItem("")
        elif get_hardware_type == "USRP B20xmini":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "LimeSDR":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "bladeRF":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "Open Sniffer":
            get_combobox.addItem("")
        elif get_hardware_type == "PlutoSDR":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "USRP2":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "USRP N2xx":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "bladeRF 2.0":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "USRP X410":
            get_combobox.addItems(get_channels)
            gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        else:
            get_combobox.addItem("")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveListViewDoubleClicked(dashboard: QtCore.QObject, mouse_event):
    """ 
    Adds the IQ file to the replay table when double clicked in the list widget.
    """
    # Index and Filepath
    get_index = dashboard.ui.listView_archive.currentIndex()
    get_filepath = dashboard.ui.listView_archive.model().filePath(get_index)

    # Navigate Folder
    if dashboard.ui.listView_archive.model().isDir(get_index) == True:
        # DotDot
        if get_filepath[-2:] == '..':
            parent_index = get_index.parent().parent()
            parent_filepath = dashboard.ui.listView_archive.model().filePath(parent_index)
            dashboard.ui.listView_archive.setRootIndex(parent_index)
            dashboard.ui.listView_archive.model().setRootPath(parent_filepath)  # Need to set this to keep sorting order

        # Folder
        else:
            dashboard.ui.listView_archive.setRootIndex(get_index)
            dashboard.ui.listView_archive.model().setRootPath(get_filepath)

    # Do Action on File
    else:
        # Add Only on Replay
        if dashboard.ui.tabWidget_archive.currentIndex() == 1:
            _slotArchiveReplayAddClicked(dashboard)

        # Add on Datasets
        elif dashboard.ui.tabWidget_archive.currentIndex() == 2:
            _slotArchiveDatasetsAddClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayAddClicked(dashboard: QtCore.QObject):
    """ 
    Adds a selected archive file to the playlist table.
    """
    # Get File
    get_archive_file = str(dashboard.ui.listView_archive.currentIndex().data())
    get_archive_folder = str(dashboard.ui.listView_archive.model().filePath(dashboard.ui.listView_archive.currentIndex())).rsplit('/',1)[0] + '/'

    get_archives = fissure.utils.library.getArchiveFavorites(dashboard.backend.library)
    
    get_hardware_type = str(dashboard.ui.comboBox_archive_replay_hardware.currentText()).split(' - ')[0]

    # Hardware Utility Functions
    get_gain = fissure.utils.hardware.getHardwareGain(get_hardware_type, "TX")
    get_channels = fissure.utils.hardware.getHardwareChannels(get_hardware_type, "TX")

    # Check Archive Favorites in Database
    for n in range(0,len(get_archives)):
        # Get File Info
        get_file = str(get_archives[n][1])
        if get_archive_file == get_file:
            # Archive Lookup
            get_protocol = str(get_archives[n][6])
            #get_date = str(get_archives[n][2])
            get_format = str(get_archives[n][3])
            get_sample_rate = str(get_archives[n][7])
            get_tuned_frequency = str(get_archives[n][10])
            #get_samples = str(get_archives[n][8])
            #get_size = str(get_archives[n][9])
            get_modulation = str(get_archives[n][4])
            #get_notes = str(get_archives[n][5])

            # Set the Value in the Table
            dashboard.ui.tableWidget_archive_replay.setRowCount(dashboard.ui.tableWidget_archive_replay.rowCount()+1)
            file_item = QtWidgets.QTableWidgetItem(get_file)
            file_item.setTextAlignment(QtCore.Qt.AlignCenter)
            file_item.setFlags(file_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,0,file_item)
            protocol_item = QtWidgets.QTableWidgetItem(get_protocol)
            protocol_item.setTextAlignment(QtCore.Qt.AlignCenter)
            protocol_item.setFlags(protocol_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,1,protocol_item)
            modulation_item = QtWidgets.QTableWidgetItem(get_modulation)
            modulation_item.setTextAlignment(QtCore.Qt.AlignCenter)
            modulation_item.setFlags(modulation_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,2,modulation_item)
            tuned_frequency_item = QtWidgets.QTableWidgetItem(get_tuned_frequency)
            tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
            #tuned_frequency_item.setFlags(tuned_frequency_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,3,tuned_frequency_item)
            sample_rate_item = QtWidgets.QTableWidgetItem(get_sample_rate)
            sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
            #sample_rate_item.setFlags(sample_rate_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,4,sample_rate_item)
            format_item = QtWidgets.QTableWidgetItem(get_format)
            format_item.setTextAlignment(QtCore.Qt.AlignCenter)
            #format_item.setFlags(format_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,5,format_item)

            # Channel
            new_combobox1 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
            dashboard.ui.tableWidget_archive_replay.setCellWidget(dashboard.ui.tableWidget_archive_replay.rowCount()-1,6,new_combobox1)
            if get_channels:
                new_combobox1.addItems(get_channels)
            else:
                new_combobox1.addItem("")
            new_combobox1.setFixedSize(67,24)
            new_combobox1.setCurrentIndex(0)

            # Gain
            if get_gain:
                gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
            else:
                gain_item = QtWidgets.QTableWidgetItem("")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,7,gain_item)

            # Duration
            duration_item = QtWidgets.QTableWidgetItem('5')
            duration_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,8,duration_item)

            # Folder
            folder_item = QtWidgets.QTableWidgetItem(get_archive_folder)
            folder_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,9,folder_item)

            # Resize the Table
            dashboard.ui.tableWidget_archive_replay.resizeColumnsToContents()
            dashboard.ui.tableWidget_archive_replay.resizeRowsToContents()
            dashboard.ui.tableWidget_archive_replay.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_archive_replay.horizontalHeader().setStretchLastSection(True)

            _update_archive_replay_start_button(dashboard)

            return

    # Add File not Found in Archive
    dashboard.ui.tableWidget_archive_replay.setRowCount(dashboard.ui.tableWidget_archive_replay.rowCount()+1)
    file_item = QtWidgets.QTableWidgetItem(get_archive_file)
    file_item.setTextAlignment(QtCore.Qt.AlignCenter)
    file_item.setFlags(file_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,0,file_item)
    protocol_item = QtWidgets.QTableWidgetItem("?")
    protocol_item.setTextAlignment(QtCore.Qt.AlignCenter)
    protocol_item.setFlags(protocol_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,1,protocol_item)
    modulation_item = QtWidgets.QTableWidgetItem("?")
    modulation_item.setTextAlignment(QtCore.Qt.AlignCenter)
    modulation_item.setFlags(modulation_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,2,modulation_item)
    tuned_frequency_item = QtWidgets.QTableWidgetItem("2400e6")
    tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
    #tuned_frequency_item.setFlags(tuned_frequency_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,3,tuned_frequency_item)
    sample_rate_item = QtWidgets.QTableWidgetItem("1e6")
    sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
    #sample_rate_item.setFlags(sample_rate_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,4,sample_rate_item)
    format_item = QtWidgets.QTableWidgetItem("Complex Float 32")
    format_item.setTextAlignment(QtCore.Qt.AlignCenter)
    #format_item.setFlags(format_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,5,format_item)

    # Channel
    new_combobox1 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
    dashboard.ui.tableWidget_archive_replay.setCellWidget(dashboard.ui.tableWidget_archive_replay.rowCount()-1,6,new_combobox1)
    if get_channels:
        new_combobox1.addItems(get_channels)
    else:
        new_combobox1.addItem("")
    new_combobox1.setFixedSize(67,24)
    new_combobox1.setCurrentIndex(0)

    # Gain
    if get_gain:
        gain_item = QtWidgets.QTableWidgetItem(str(get_gain[2]))
    else:
        gain_item = QtWidgets.QTableWidgetItem("")
    gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
    gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,7,gain_item)

    # Duration
    duration_item = QtWidgets.QTableWidgetItem('5')
    duration_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,8,duration_item)

    # Folder
    folder_item = QtWidgets.QTableWidgetItem(get_archive_folder)
    folder_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,9,folder_item)

    # Resize the Table
    dashboard.ui.tableWidget_archive_replay.resizeColumnsToContents()
    dashboard.ui.tableWidget_archive_replay.resizeRowsToContents()
    dashboard.ui.tableWidget_archive_replay.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_archive_replay.horizontalHeader().setStretchLastSection(True)

    _update_archive_replay_start_button(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsAddClicked(dashboard: QtCore.QObject, filepath=None):
    """ 
    Adds a selected archive file to the Datasets table.
    """
    # Get File
    if (filepath == None) or (filepath == False) :
        get_archive_file = str(dashboard.ui.listView_archive.currentIndex().data())
        get_archive_folder = str(dashboard.ui.listView_archive.model().filePath(dashboard.ui.listView_archive.currentIndex())).rsplit('/',1)[0] + '/'
    else:
        get_archive_file = str(filepath).rsplit("/",1)[1]
        get_archive_folder = str(filepath).rsplit("/",1)[0] + '/'

    get_archives = fissure.utils.library.getArchiveFavorites(dashboard.backend.library)

    for n in range(0,len(get_archives)):
        # Get File Info
        get_file = str(get_archives[n][1])
        if get_archive_file == get_file:
            # Archive Lookup
            get_truth = str(get_archives[n][6])
            get_sample_rate = str(get_archives[n][7])
            get_tuned_frequency = str(get_archives[n][10])

            # Set the Value in the Table
            dashboard.ui.tableWidget_archive_datasets.setRowCount(dashboard.ui.tableWidget_archive_datasets.rowCount()+1)
            folder_item = QtWidgets.QTableWidgetItem(get_archive_folder + get_archive_file)
            folder_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,0,folder_item)
            truth_item = QtWidgets.QTableWidgetItem(get_truth)
            truth_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,1,truth_item)
            sample_rate_item = QtWidgets.QTableWidgetItem(get_sample_rate)
            sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,2,sample_rate_item)
            tuned_frequency_item = QtWidgets.QTableWidgetItem(get_tuned_frequency)
            tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,3,tuned_frequency_item)

            # Generate Values in the Tables
            noise_value = random.uniform(float(dashboard.backend.settings['dataset_noise_min']),float(dashboard.backend.settings['dataset_noise_max']))
            noise_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(noise_value))
            noise_item.setTextAlignment(QtCore.Qt.AlignCenter)
            noise_item.setCheckState(QtCore.Qt.Unchecked)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,4,noise_item)
            phase_value = random.uniform(float(dashboard.backend.settings['dataset_phase_rot_min']),float(dashboard.backend.settings['dataset_phase_rot_max']))
            phase_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(phase_value))
            phase_item.setTextAlignment(QtCore.Qt.AlignCenter)
            phase_item.setCheckState(QtCore.Qt.Unchecked)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,5,phase_item)
            scale_value = random.uniform(float(dashboard.backend.settings['dataset_scale_min']),float(dashboard.backend.settings['dataset_scale_max']))
            scale_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(scale_value))
            scale_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scale_item.setCheckState(QtCore.Qt.Unchecked)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,6,scale_item)
            freq_shift_value = random.uniform(float(dashboard.backend.settings['dataset_freq_shift_min']),float(dashboard.backend.settings['dataset_freq_shift_max']))
            freq_shift_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(freq_shift_value))
            freq_shift_item.setTextAlignment(QtCore.Qt.AlignCenter)
            freq_shift_item.setFlags(freq_shift_item.flags() & ~QtCore.Qt.ItemIsEnabled)
            freq_shift_item.setCheckState(QtCore.Qt.Unchecked)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,7,freq_shift_item)
            sigmf_item = QtWidgets.QTableWidgetItem("")
            sigmf_item.setTextAlignment(QtCore.Qt.AlignCenter)
            sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEditable)
            sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEnabled)
            sigmf_item.setCheckState(QtCore.Qt.Unchecked)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,8,sigmf_item)

            # Resize the Table
            dashboard.ui.tableWidget_archive_datasets.resizeColumnsToContents()
            dashboard.ui.tableWidget_archive_datasets.resizeRowsToContents()
            dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(True)

            # Enable PushButton
            dashboard.ui.pushButton_archive_datasets_start.setEnabled(True)

            return

    # Add File not Found in Archive
    dashboard.ui.tableWidget_archive_datasets.setRowCount(dashboard.ui.tableWidget_archive_datasets.rowCount()+1)
    folder_item = QtWidgets.QTableWidgetItem(get_archive_folder + get_archive_file)
    folder_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,0,folder_item)
    truth_item = QtWidgets.QTableWidgetItem("")
    truth_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,1,truth_item)
    sample_rate_item = QtWidgets.QTableWidgetItem("")
    sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,2,sample_rate_item)
    tuned_frequency_item = QtWidgets.QTableWidgetItem("")
    tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,3,tuned_frequency_item)

    # Generate Values in the Tables
    noise_value = random.uniform(float(dashboard.backend.settings['dataset_noise_min']),float(dashboard.backend.settings['dataset_noise_max']))
    noise_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(noise_value))
    noise_item.setTextAlignment(QtCore.Qt.AlignCenter)
    noise_item.setCheckState(QtCore.Qt.Unchecked)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,4,noise_item)
    phase_value = random.uniform(float(dashboard.backend.settings['dataset_phase_rot_min']),float(dashboard.backend.settings['dataset_phase_rot_max']))
    phase_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(phase_value))
    phase_item.setTextAlignment(QtCore.Qt.AlignCenter)
    phase_item.setCheckState(QtCore.Qt.Unchecked)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,5,phase_item)
    scale_value = random.uniform(float(dashboard.backend.settings['dataset_scale_min']),float(dashboard.backend.settings['dataset_scale_max']))
    scale_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(scale_value))
    scale_item.setTextAlignment(QtCore.Qt.AlignCenter)
    scale_item.setCheckState(QtCore.Qt.Unchecked)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,6,scale_item)
    freq_shift_value = random.uniform(float(dashboard.backend.settings['dataset_freq_shift_min']),float(dashboard.backend.settings['dataset_freq_shift_max']))
    freq_shift_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(freq_shift_value))
    freq_shift_item.setTextAlignment(QtCore.Qt.AlignCenter)
    freq_shift_item.setFlags(freq_shift_item.flags() & ~QtCore.Qt.ItemIsEnabled)
    freq_shift_item.setCheckState(QtCore.Qt.Unchecked)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,7,freq_shift_item)
    sigmf_item = QtWidgets.QTableWidgetItem("")
    sigmf_item.setTextAlignment(QtCore.Qt.AlignCenter)
    sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEditable)
    sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEnabled)
    sigmf_item.setCheckState(QtCore.Qt.Unchecked)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,8,sigmf_item)

    # Resize the Table
    dashboard.ui.tableWidget_archive_datasets.resizeColumnsToContents()
    dashboard.ui.tableWidget_archive_datasets.resizeRowsToContents()
    dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(True)

    # Enable PushButton
    dashboard.ui.pushButton_archive_datasets_start.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsColumnClicked(dashboard: QtCore.QObject, col):
    """ 
    Checks/unchecks all items in a column for the Dataset Builder table.
    """
    # Toggle the State
    if (col > 3) and (bool(dashboard.ui.tableWidget_archive_datasets.item(0,col).flags() & QtCore.Qt.ItemIsEnabled) == True):
        get_check_state = dashboard.ui.tableWidget_archive_datasets.item(0,col).checkState()
        for row in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
            if get_check_state == 0:
                dashboard.ui.tableWidget_archive_datasets.item(row,col).setCheckState(2)
            else:
                dashboard.ui.tableWidget_archive_datasets.item(row,col).setCheckState(0)

    # Apply the Same Sample Rate
    if col == 2:
        get_sample_rate = str(dashboard.ui.tableWidget_archive_datasets.item(0,col).text())
        for row in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
            sample_rate_item = QtWidgets.QTableWidgetItem(get_sample_rate)
            sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(row,2,sample_rate_item)

    # Apply the Same Frequency
    if col == 3:
        get_frequency = str(dashboard.ui.tableWidget_archive_datasets.item(0,col).text())
        for row in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
            frequency_item = QtWidgets.QTableWidgetItem(get_frequency)
            frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(row,3,frequency_item)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadFolderClicked(dashboard: QtCore.QObject):
    """ 
    Selects a folder for viewing and downloading archive files.
    """
    # Choose Folder
    get_dir = str(QtWidgets.QFileDialog.getExistingDirectory(dashboard, "Select Directory"))

    # Add Directory to the Combobox
    if len(get_dir) > 0:
        dashboard.ui.comboBox3_archive_download_folder.addItem(get_dir)
        dashboard.ui.comboBox3_archive_download_folder.setCurrentIndex(dashboard.ui.comboBox3_archive_download_folder.count()-1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadDeleteClicked(dashboard: QtCore.QObject):
    """
    Deletes a file or folder from the Archive list and reselects the next or previous item.
    """
    # Get the currently selected index and the parent directory
    get_index = dashboard.ui.listView_archive.currentIndex()
    delete_filepath = str(dashboard.ui.listView_archive.model().filePath(get_index))
    if not delete_filepath:
        return

    model = dashboard.ui.listView_archive.model()
    parent_index = get_index.parent()
    row_count = model.rowCount(parent_index)

    # Determine next or previous item to select after deletion
    if get_index.row() < row_count - 1:
        next_index = model.index(get_index.row() + 1, 0, parent_index)
    elif get_index.row() > 0:
        next_index = model.index(get_index.row() - 1, 0, parent_index)
    else:
        next_index = parent_index  # No siblings, fall back to parent directory

    # Confirm deletion for files and folders
    qm = QtWidgets.QMessageBox
    item_type = "folder" if model.isDir(get_index) else "file"
    ret = qm.question(dashboard, '', f"Delete this {item_type}?", qm.Yes | qm.No)

    if ret == qm.Yes:
        # Delete the folder or file
        if model.isDir(get_index) and not delete_filepath.endswith('..'):
            os.system(f'rm -Rf "{delete_filepath}"')  # Folder
        elif not model.isDir(get_index):
            os.system(f'rm "{delete_filepath}"')  # File

        # Directly set selection to the next item without refreshing
        if next_index.isValid():
            dashboard.ui.listView_archive.setCurrentIndex(next_index)


@qasync.asyncSlot(QtCore.QObject)
async def _slotArchiveDownloadClicked(dashboard: QtCore.QObject):
    """ 
    Asynchronously downloads the selected file from the internet with error handling.
    Prevents GUI freezing.
    """
    # Find Selected Row
    get_row = dashboard.ui.tableWidget_archive_download.currentRow()
    if get_row < 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("No file selected for download.")
        return

    # Get File
    get_file = str(dashboard.ui.tableWidget_archive_download.verticalHeaderItem(get_row).text())

    # Get Folder
    get_folder = str(dashboard.ui.listView_archive.model().rootPath())

    # Build the URL
    url = f"https://fissure.ainfosec.com/{get_file}"
    download_path = f"{get_folder}/"

    # Wget command with timeout (10s) and retries (2)
    command = ["wget", "-P", download_path, "--timeout=5", "--tries=1", "--no-check-certificate", url]

    try:
        process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = f"Download failed: {stderr.decode().strip()}"
            dashboard.logger.error(error_message)
            ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, error_message)
        else:
            success_message = f"Download completed: {url}"
            dashboard.logger.info(success_message)
    
    except asyncio.TimeoutError:
        error_message = f"Download timed out: {url}"
        dashboard.logger.error(error_message)
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, error_message)


@qasync.asyncSlot(QtCore.QObject)
async def _slotArchiveDownloadCollectionClicked(dashboard: QtCore.QObject):
    """ 
    Asynchronously downloads a single IQ file or a collection of IQ files and unzips them.
    Prevents multiple error popups if the first download fails.
    """
    # Find Selected Row Text and Parent Text
    try:
        item_index = dashboard.ui.treeView_archive_download_collection.selectedIndexes()[0]
    except IndexError:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select a collection")
        return
    
    parent1_index = dashboard.ui.treeView_archive_download_collection.model().parent(item_index)
    parent2_index = dashboard.ui.treeView_archive_download_collection.model().parent(parent1_index)

    item_data = dashboard.ui.treeView_archive_download_collection.model().data(item_index)
    parent1_data = dashboard.ui.treeView_archive_download_collection.model().data(parent1_index)
    parent2_data = dashboard.ui.treeView_archive_download_collection.model().data(parent2_index)

    # Use None instead of Notes
    parent1_data = None if parent1_data == "Notes" else parent1_data
    parent2_data = None if parent2_data == "Notes" else parent2_data

    # Assemble Filepath
    get_filepath = fissure.utils.library.getArchiveCollectionFilepath(dashboard.backend.library, item_data, parent1_data, parent2_data)

    # Check if the filepath is valid
    if get_filepath is None:
        dashboard.logger.error("Invalid filepath format. File not downloaded.")
        return

    get_folder = str(dashboard.ui.listView_archive.model().rootPath())

    # Define base URL
    base_url = "https://fissure.ainfosec.com"

    # Function to execute `wget` asynchronously with a return status
    async def download_file(url, output_folder):
        command = ["wget", "--timeout=5", "--tries=1", "--no-check-certificate", "-P", output_folder, url]
        process = await asyncio.create_subprocess_exec(*command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        stdout, stderr = await process.communicate()

        if process.returncode != 0:
            error_message = f"Failed to download {url}: {stderr.decode().strip()}"
            dashboard.logger.error(error_message)
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, error_message)
            return False  # Return failure status
        return True  # Return success status

    # Handle different file types
    file_url = f"{base_url}{get_filepath}"

    if get_filepath.endswith('.tar'):
        # Download and extract .tar file in one step asynchronously
        command = f"wget --no-check-certificate {file_url} -O - | tar -x -C {get_folder}"
        process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            error_message = f"Failed to download and extract {file_url}: {stderr.decode().strip()}"
            dashboard.logger.error(error_message)
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, error_message)

    elif get_filepath.endswith('.sigmf-data'):
        # Download .sigmf-data first
        success = await download_file(file_url, get_folder)

        # Only try .sigmf-meta if .sigmf-data was successful
        if success:
            meta_url = file_url.replace('.sigmf-data', '.sigmf-meta')
            await download_file(meta_url, get_folder)

    else:
        # General file download
        await download_file(file_url, get_folder)
        
    # """ 
    # Downloads a single IQ file or a collection of IQ files and unzips them.
    # """
    # # Find Selected Row Text and Parent Text
    # try:
        # item_index = dashboard.ui.treeView_archive_download_collection.selectedIndexes()[0]
    # except:
        # fissure.Dashboard.UI_Components.Qt5.errorMessage("Select a collection")
        # return
    # parent1_index = dashboard.ui.treeView_archive_download_collection.model().parent(item_index)
    # parent2_index = dashboard.ui.treeView_archive_download_collection.model().parent(parent1_index)

    # item_data = dashboard.ui.treeView_archive_download_collection.model().data(item_index)
    # parent1_data = dashboard.ui.treeView_archive_download_collection.model().data(parent1_index)
    # parent2_data = dashboard.ui.treeView_archive_download_collection.model().data(parent2_index)

    # # Use None instead of Notes
    # if parent1_data == "Notes":
        # parent1_data = None
    # if parent2_data == "Notes":
        # parent2_data = None

    # # Assemble Filepath
    # get_filepath = fissure.utils.library.getArchiveCollectionFilepath(dashboard.backend.library, item_data, parent1_data, parent2_data)

    # # Download and Unzip
    # if get_filepath == None:
        # dashboard.logger.error("Invalid filepath format. File not downloaded.")
    # else:
        # get_folder = str(dashboard.ui.listView_archive.model().rootPath())
        # if get_filepath[-4:] == '.tar':
            # os.system('wget https://fissure.ainfosec.com' + get_filepath + ' -O - | tar -x -C "' + get_folder + '/"')
        # elif get_filepath[-11:] == '.sigmf-data':
            # os.system('wget https://fissure.ainfosec.com' + get_filepath + ' -P "' + get_folder + '/"')
            # os.system('wget https://fissure.ainfosec.com' + get_filepath.replace('.sigmf-data','.sigmf-meta') + ' -P "' + get_folder + '/"')
        # else:
            # os.system('wget https://fissure.ainfosec.com' + get_filepath + ' -P "' + get_folder + '/"')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayRemoveClicked(
    dashboard: QtCore.QObject,
):
    """
    Removes a row from the Archive playlist table.
    """
    get_current_row = (
        dashboard.ui.tableWidget_archive_replay.currentRow()
    )

    dashboard.ui.tableWidget_archive_replay.removeRow(
        get_current_row
    )

    if get_current_row == 0:
        dashboard.ui.tableWidget_archive_replay.setCurrentCell(
            0,
            0,
        )
    else:
        dashboard.ui.tableWidget_archive_replay.setCurrentCell(
            get_current_row - 1,
            0,
        )

    _update_archive_replay_start_button(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayUpClicked(dashboard: QtCore.QObject):
    """ 
    Moves the selected row up in the Archive playlist table.
    """
    if dashboard.ui.tableWidget_archive_replay.currentRow() != 0:  # Ignore top row
        # Take the Row Above
        above_item0 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,0)
        above_item1 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,1)
        above_item2 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,2)
        above_item3 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,3)
        above_item4 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,4)
        above_item5 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,5)
        above_item6 = dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow()-1,6).currentIndex()
        above_item7 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,7)
        above_item8 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,8)

        # Take the Current Row
        current_item0 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),0)
        current_item1 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),1)
        current_item2 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),2)
        current_item3 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),3)
        current_item4 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),4)
        current_item5 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),5)
        current_item6 = dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow(),6).currentIndex()
        current_item7 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),7)
        current_item8 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),8)

        # Set the Current Row
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),0,above_item0)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),1,above_item1)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),2,above_item2)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),3,above_item3)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),4,above_item4)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),5,above_item5)
        dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow(),6).setCurrentIndex(above_item6)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),7,above_item7)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),8,above_item8)

        # Set the Row Above
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,0,current_item0)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,1,current_item1)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,2,current_item2)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,3,current_item3)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,4,current_item4)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,5,current_item5)
        dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow()-1,6).setCurrentIndex(current_item6)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,7,current_item7)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,8,current_item8)

        # Change the Selected Row
        dashboard.ui.tableWidget_archive_replay.setCurrentCell(dashboard.ui.tableWidget_archive_replay.currentRow()-1,0)

        # Resize
        dashboard.ui.tableWidget_archive_replay.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayDownClicked(dashboard: QtCore.QObject):
    """ 
    Moves the selected row down in the Archive playlist table.
    """
    # Get Bottom Row
    bottom_row = dashboard.ui.tableWidget_archive_replay.rowCount()

    # Move it Down
    if dashboard.ui.tableWidget_archive_replay.currentRow() != bottom_row-1:  # Ignore bottom row
        # Take the Row Below
        below_item0 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,0)
        below_item1 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,1)
        below_item2 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,2)
        below_item3 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,3)
        below_item4 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,4)
        below_item5 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,5)
        below_item6 = dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow()+1,6).currentIndex()
        below_item7 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,7)
        below_item8 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,8)

        # Take the Current Row
        current_item0 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),0)
        current_item1 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),1)
        current_item2 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),2)
        current_item3 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),3)
        current_item4 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),4)
        current_item5 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),5)
        current_item6 = dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow(),6).currentIndex()
        current_item7 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),7)
        current_item8 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),8)

        # Set the Current Row
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),0,below_item0)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),1,below_item1)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),2,below_item2)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),3,below_item3)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),4,below_item4)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),5,below_item5)
        dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow(),6).setCurrentIndex(below_item6)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),7,below_item7)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),8,below_item8)

        # Set the Row Above
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,0,current_item0)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,1,current_item1)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,2,current_item2)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,3,current_item3)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,4,current_item4)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,5,current_item5)
        dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow()+1,6).setCurrentIndex(current_item6)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,7,current_item7)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,8,current_item8)

        # Change the Selected Row
        dashboard.ui.tableWidget_archive_replay.setCurrentCell(dashboard.ui.tableWidget_archive_replay.currentRow()+1,0)

        # Resize
        dashboard.ui.tableWidget_archive_replay.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayRemoveAllClicked(
    dashboard: QtCore.QObject,
):
    """
    Clears the Archive playlist table.
    """
    for row in reversed(
        range(
            dashboard.ui.tableWidget_archive_replay.rowCount()
        )
    ):
        dashboard.ui.tableWidget_archive_replay.removeRow(
            row
        )

    _update_archive_replay_start_button(
        dashboard
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayImportCSV_Clicked(dashboard: QtCore.QObject):
    """ 
    Imports a CSV file to populate the playlist table.
    """
    # Choose File
    get_archive_folder = os.path.join(fissure.utils.ARCHIVE_DIR, "Playlists")
    fname = QtWidgets.QFileDialog.getOpenFileNames(None,"Select CSV File...", get_archive_folder, filter="CSV (*.csv)")
    if fname != "":
        r = dashboard.ui.tableWidget_archive_replay.rowCount()
        for n in fname[0]:
            csv_row = 0
            with open(n, "r") as fileInput:
                for row in csv.reader(fileInput):
                    if csv_row == 0:
                        _slotArchiveReplayHardwareChanged(dashboard)
                    else:
                        _slotArchiveReplayAddClicked(dashboard)
                        for c in range(0,len(row)):
                            get_text = row[c]
                            # Channel
                            if c == 6:
                                dashboard.ui.tableWidget_archive_replay.cellWidget(r,c).setCurrentIndex(int(get_text))
                            else:
                                dashboard.ui.tableWidget_archive_replay.item(r,c).setText(str(get_text))
                        r = r + 1
                    csv_row = csv_row + 1

        _update_archive_replay_start_button(
            dashboard
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayExportCSV_Clicked(dashboard: QtCore.QObject):
    """
    Exports a CSV file from the playlist table.
    """
    # Choose File Location
    get_archive_folder = os.path.join(
        fissure.utils.ARCHIVE_DIR,
        "Playlists",
    )

    path, _ = QtWidgets.QFileDialog.getSaveFileName(
        dashboard,
        "Save CSV",
        get_archive_folder,
        filter="CSV (*.csv)",
    )

    if not path:
        return

    if not path.lower().endswith(
        ".csv"
    ):
        path += ".csv"

    columns = range(
        dashboard.ui.tableWidget_archive_replay.columnCount()
    )

    get_hardware_type = str(
        dashboard.ui.comboBox_archive_replay_hardware.currentText()
    ).split(
        " - "
    )[0]

    with open(
        path,
        "w",
    ) as csvfile:
        writer = csv.writer(
            csvfile,
            dialect="excel",
            lineterminator="\n",
        )

        writer.writerow(
            [get_hardware_type]
        )

        for row in range(
            dashboard.ui.tableWidget_archive_replay.rowCount()
        ):
            row_text = []

            for column in columns:
                try:
                    # Channel
                    if column == 6:
                        get_text = str(
                            dashboard.ui.tableWidget_archive_replay.cellWidget(
                                row,
                                column,
                            ).currentIndex()
                        )
                    else:
                        get_text = str(
                            dashboard.ui.tableWidget_archive_replay.item(
                                row,
                                column,
                            ).text()
                        )

                except Exception:
                    get_text = ""

                row_text.append(
                    get_text
                )

            writer.writerow(
                row_text
            )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsImportClicked(dashboard: QtCore.QObject):
    """ 
    Opens a file dialog to select IQ files for the Datasets table.
    """
    # Choose File
    get_archive_folder = str(dashboard.ui.listView_archive.model().rootPath()) + '/'
    fname = QtWidgets.QFileDialog.getOpenFileNames(None,"Select IQ File...", get_archive_folder, filter="All Files (*)")
    if fname != "":
        for n in fname[0]:
            _slotArchiveDatasetsAddClicked(dashboard, filepath=n)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row from the Archive Datasets table.
    """
    # Remove Rows
    if dashboard.ui.tableWidget_archive_datasets.rowCount() > 0:
        # Find Selected Rows Manually (selectedRanges() not working for programmatic selection?)
        first = -1
        last = -1
        for n in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
            item = dashboard.ui.tableWidget_archive_datasets.item(n,0)
            if item:
                if item.isSelected():
                    if first == -1:
                        first = n
                    last = n

        for n in reversed(range(first,last+1)):
            dashboard.ui.tableWidget_archive_datasets.removeRow(n)

        # Highlight New Row
        if dashboard.ui.tableWidget_archive_datasets.rowCount() > first:
            dashboard.ui.tableWidget_archive_datasets.selectRow(first)
        else:
            dashboard.ui.tableWidget_archive_datasets.selectRow(dashboard.ui.tableWidget_archive_datasets.rowCount()-1)

    # Disable PushButtons
    if dashboard.ui.tableWidget_archive_datasets.rowCount() < 1:
        dashboard.ui.pushButton_archive_datasets_start.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsRemoveAllClicked(dashboard: QtCore.QObject):
    """ 
    Removes all the rows in the Dataset Builder table.
    """
    # Remove all Rows
    for row in reversed(range(0,dashboard.ui.tableWidget_archive_datasets.rowCount())):
        dashboard.ui.tableWidget_archive_datasets.removeRow(row)

    # Disable PushButtons
    dashboard.ui.pushButton_archive_datasets_start.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsExportClicked(dashboard: QtCore.QObject):
    """ 
    Exports the contents of the Datasets table to a CSV.
    """
    # Choose File Location
    get_archive_folder = os.path.join(fissure.utils.ARCHIVE_DIR, "Datasets")
    path = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save CSV', get_archive_folder, filter='CSV (*.csv)')
    if len(path[0]) > 0:
        columns = range(dashboard.ui.tableWidget_archive_datasets.columnCount())
        with open(path[0], 'w') as csvfile:
            writer = csv.writer(csvfile, dialect='excel', lineterminator='\n')
            for row in range(dashboard.ui.tableWidget_archive_datasets.rowCount()):
                row_text = []
                for column in columns:
                    try:
                        get_text = str(dashboard.ui.tableWidget_archive_datasets.item(row, column).text())
                        if column > 3:
                            get_checked_state = str(dashboard.ui.tableWidget_archive_datasets.item(row, column).checkState())
                            get_text = get_checked_state + ':' + get_text
                    except:
                        get_text = ""
                    row_text.append(get_text)
                writer.writerow(row_text)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsOptionsClicked(dashboard: QtCore.QObject):
    """ 
    Opens the Options dialog to change the settings for the Dataset Builder.
    """
    fissure.Dashboard.Slots.MenuBarSlots._slotMenuOptionsClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsImportCSV_Clicked(dashboard: QtCore.QObject):
    """ 
    Loads a .csv file into the Dataset Builder table.
    """
    # Choose File
    get_archive_folder = os.path.join(fissure.utils.ARCHIVE_DIR, "Datasets")
    fname = QtWidgets.QFileDialog.getOpenFileNames(None,"Select CSV File...", get_archive_folder, filter="CSV (*.csv)")
    if fname != "":
        r = dashboard.ui.tableWidget_archive_datasets.rowCount()
        for n in fname[0]:
            with open(n, "r") as fileInput:
                for row in csv.reader(fileInput):
                    dashboard.ui.tableWidget_archive_datasets.setRowCount(dashboard.ui.tableWidget_archive_datasets.rowCount() + 1)
                    for c in range(0,len(row)):
                        if c > 3:
                            get_text = row[c].split(':',1)[1]
                            get_checked_state = int(row[c].split(':',1)[0])
                            new_item = QtWidgets.QTableWidgetItem(get_text)
                            new_item.setCheckState(get_checked_state)
                            if c > 6:
                                new_item.setFlags(new_item.flags() & ~QtCore.Qt.ItemIsEnabled)
                        else:
                            get_text = row[c]
                            new_item = QtWidgets.QTableWidgetItem(get_text)
                        new_item.setTextAlignment(QtCore.Qt.AlignCenter)
                        dashboard.ui.tableWidget_archive_datasets.setItem(r,c,new_item)
                    r = r+1

        # Resize the Table
        dashboard.ui.tableWidget_archive_datasets.resizeColumnsToContents()
        dashboard.ui.tableWidget_archive_datasets.resizeRowsToContents()
        dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(True)

        # Enable PushButton
        dashboard.ui.pushButton_archive_datasets_start.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsViewClicked(dashboard: QtCore.QObject):
    """ 
    Opens the flow graph used to apply changes to the IQ files listed the Dataset Builder table.
    """
    # Open the Flow Graph in GNU Radio Companion
    flow_graph_filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Archive Flow Graphs", "dataset_builder.grc")
    osCommandString = 'gnuradio-companion "' + flow_graph_filepath + '"'
    os.system(osCommandString + " &")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsCopyClicked(dashboard: QtCore.QObject):
    """ 
    Copies selected rows in the Dataset Builder table and generates new checkbox values.
    """
    if dashboard.ui.tableWidget_archive_datasets.rowCount() > 0:
        # Find Selected Rows Manually (selectedRanges() not working for programmatic selection?)
        first = -1
        last = -1
        for n in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
            item = dashboard.ui.tableWidget_archive_datasets.item(n,0)
            if item:
                if item.isSelected():
                    if first == -1:
                        first = n
                    last = n

        # Insert Rows
        for n in reversed(range(first,last+1)):
            dashboard.ui.tableWidget_archive_datasets.insertRow(last+1)

            # Set the Value in the Table
            folder_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_archive_datasets.item(n,0).text()))
            folder_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,0,folder_item)
            truth_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_archive_datasets.item(n,1).text()))
            truth_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,1,truth_item)
            sample_rate_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_archive_datasets.item(n,2).text()))
            sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,2,sample_rate_item)
            tuned_frequency_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_archive_datasets.item(n,3).text()))
            tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,3,tuned_frequency_item)

            # Generate Values in the Tables
            noise_value = random.uniform(float(dashboard.backend.settings['dataset_noise_min']),float(dashboard.backend.settings['dataset_noise_max']))
            noise_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(noise_value))
            noise_item.setTextAlignment(QtCore.Qt.AlignCenter)
            if dashboard.ui.tableWidget_archive_datasets.item(n,4).checkState() == 0:
                noise_item.setCheckState(0)
            else:
                noise_item.setCheckState(2)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,4,noise_item)
            phase_value = random.uniform(float(dashboard.backend.settings['dataset_phase_rot_min']),float(dashboard.backend.settings['dataset_phase_rot_max']))
            phase_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(phase_value))
            phase_item.setTextAlignment(QtCore.Qt.AlignCenter)
            if dashboard.ui.tableWidget_archive_datasets.item(n,5).checkState() == 0:
                phase_item.setCheckState(0)
            else:
                phase_item.setCheckState(2)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,5,phase_item)
            scale_value = random.uniform(float(dashboard.backend.settings['dataset_scale_min']),float(dashboard.backend.settings['dataset_scale_max']))
            scale_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(scale_value))
            scale_item.setTextAlignment(QtCore.Qt.AlignCenter)
            if dashboard.ui.tableWidget_archive_datasets.item(n,6).checkState() == 0:
                scale_item.setCheckState(0)
            else:
                scale_item.setCheckState(2)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,6,scale_item)
            freq_shift_value = random.uniform(float(dashboard.backend.settings['dataset_freq_shift_min']),float(dashboard.backend.settings['dataset_freq_shift_max']))
            freq_shift_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(freq_shift_value))
            freq_shift_item.setTextAlignment(QtCore.Qt.AlignCenter)
            freq_shift_item.setFlags(freq_shift_item.flags() & ~QtCore.Qt.ItemIsEnabled)
            if dashboard.ui.tableWidget_archive_datasets.item(n,7).checkState() == 0:
                freq_shift_item.setCheckState(0)
            else:
                freq_shift_item.setCheckState(2)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,7,freq_shift_item)
            sigmf_item = QtWidgets.QTableWidgetItem("")
            sigmf_item.setTextAlignment(QtCore.Qt.AlignCenter)
            sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEditable)
            sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEnabled)
            if dashboard.ui.tableWidget_archive_datasets.item(n,8).checkState() == 0:
                sigmf_item.setCheckState(0)
            else:
                sigmf_item.setCheckState(2)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,8,sigmf_item)

        # Keep the Selection
        dashboard.ui.tableWidget_archive_datasets.clearSelection()
        for n in range(first,last+1):
            for m in range(0,dashboard.ui.tableWidget_archive_datasets.columnCount()):
                item = dashboard.ui.tableWidget_archive_datasets.item(n,m)
                if item:
                    item.setSelected(True)

        # Resize the Table
        dashboard.ui.tableWidget_archive_datasets.resizeColumnsToContents()
        dashboard.ui.tableWidget_archive_datasets.resizeRowsToContents()
        dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsOpenFolderClicked(dashboard: QtCore.QObject):
    """ 
    Opens the folder where datasets gets stored by default.
    """
    # Open the Folder
    folder_filepath = os.path.join(fissure.utils.FISSURE_ROOT, "Archive", "Datasets")
    os.system("nautilus '" + folder_filepath + "' &")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadCollectionCollapseAllClicked(dashboard: QtCore.QObject):
    """ 
    Collapses the Collection TreeView.
    """
    # Collapse
    dashboard.ui.treeView_archive_download_collection.collapseAll()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveNewFolderClicked(dashboard: QtCore.QObject):
    """ 
    Creates a new folder in the current directory of the Archive ListView.
    """
    text, ok = QtWidgets.QInputDialog.getText(dashboard, 'New Folder', 'Enter new folder name:',QtWidgets.QLineEdit.Normal)
    if ok:
        if len(str(text)) > 0:
            folder_filepath = str(dashboard.ui.listView_archive.model().rootPath())
            os.system('mkdir "' + folder_filepath + '/' + str(text) + '"')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveFolderClicked(dashboard: QtCore.QObject):
    """ 
    Opens a window to current directory of the Archive ListView.
    """
    # Open the Folder
    folder_filepath = str(dashboard.ui.listView_archive.model().rootPath())
    os.system('nautilus "' + folder_filepath + '" &')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayDetectorAddClicked(dashboard: QtCore.QObject):
    """
    Opens the reusable detector selection dialog and adds the selected
    detector configuration to the Archive Replay detector table.
    """
    detector_config = dashboard.openPopUp("DetectorSelectionDialog", DetectorSelectionDialog)

    if not detector_config:
        return

    plugin_name = str(detector_config.get("plugin", "") or "").strip()
    action_name = str(detector_config.get("action", "") or "").strip()
    hardware = str(detector_config.get("hardware", "") or "").strip()
    parameters = detector_config.get("parameters", {}) or {}

    if not plugin_name or not action_name:
        dashboard.logger.warning("Archive Replay detector selection returned without a plugin/action.")
        return

    detector_name = f"{plugin_name}: {action_name}"
    parameter_summary = ", ".join(f"{name}={value}" for name, value in parameters.items())

    table = dashboard.ui.tableWidget_archive_replay_detectors
    row = table.rowCount()
    table.insertRow(row)

    detector_item = QtWidgets.QTableWidgetItem(detector_name)
    detector_item.setTextAlignment(QtCore.Qt.AlignCenter)
    detector_item.setFlags(detector_item.flags() & ~QtCore.Qt.ItemIsEditable)
    detector_item.setData(QtCore.Qt.UserRole, detector_config)
    table.setItem(row, 0, detector_item)

    hardware_item = QtWidgets.QTableWidgetItem(hardware)
    hardware_item.setTextAlignment(QtCore.Qt.AlignCenter)
    hardware_item.setFlags(hardware_item.flags() & ~QtCore.Qt.ItemIsEditable)
    table.setItem(row, 1, hardware_item)

    parameters_item = QtWidgets.QTableWidgetItem(f"  {parameter_summary}")
    parameters_item.setTextAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
    parameters_item.setFlags(parameters_item.flags() & ~QtCore.Qt.ItemIsEditable)
    parameters_item.setToolTip(parameter_summary)
    table.setItem(row, 2, parameters_item)

    table.resizeRowsToContents()

    dashboard.logger.info(f"Added Archive Replay detector: {detector_name}")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayDetectorRemoveClicked(dashboard: QtCore.QObject):
    """
    Removes the selected Archive Replay detector.
    """
    table = dashboard.ui.tableWidget_archive_replay_detectors
    row = table.currentRow()

    if row < 0:
        return

    table.removeRow(row)


def _collect_archive_replay_detector_configs(dashboard: QtCore.QObject):
    """Return the saved detector configurations from the Archive Replay table."""
    table = dashboard.ui.tableWidget_archive_replay_detectors
    detector_configs = []

    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is None:
            continue

        detector_config = item.data(QtCore.Qt.UserRole)
        if isinstance(detector_config, dict):
            detector_configs.append(dict(detector_config))

    return detector_configs


def _build_archive_replay_detector_parameters(
    dashboard: QtCore.QObject,
    detector_config: dict,
    operation_id: str,
):
    """Build detector parameters, including the detector's selected hardware."""
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


async def _start_archive_replay_detectors(
    dashboard: QtCore.QObject,
    node_uid: str,
    detector_configs: list,
):
    """Launch all configured Archive Replay detector operations."""
    launch_requests = []
    operation_ids = set()

    for detector_config in detector_configs:
        plugin_name = str(detector_config.get("plugin", "") or "").strip()
        action_name = str(detector_config.get("action", "") or "").strip()

        if not plugin_name or not action_name:
            raise ValueError("Archive Replay detector is missing plugin/action information.")

        operation_id = str(uuid.uuid4())
        parameters = _build_archive_replay_detector_parameters(dashboard, detector_config, operation_id)

        operation_ids.add(operation_id)
        launch_requests.append((plugin_name, action_name, parameters))

    dashboard.archive_replay_detector_operation_ids = operation_ids

    tasks = [
        dashboard.backend.tacticalNodeExecute([node_uid], plugin_name, action_name, parameters)
        for plugin_name, action_name, parameters in launch_requests
    ]

    if tasks:
        await asyncio.gather(*tasks)

    dashboard.logger.info(
        f"Archive Replay waiting on {len(operation_ids)} detector operation(s): "
        f"{sorted(operation_ids)}"
    )


async def _stop_archive_replay_detectors(
    dashboard: QtCore.QObject,
    node_uid: str,
):
    """Stop all detector operations launched for the current Archive Replay run."""
    operation_ids = list(getattr(dashboard, "archive_replay_detector_operation_ids", set()) or set())
    dashboard.archive_replay_detector_operation_ids = set()

    for operation_id in operation_ids:
        try:
            await dashboard.backend.stopPluginOperation(node_uid, operation_id)
        except Exception as error:
            dashboard.logger.warning(
                f"Could not stop Archive Replay detector operation {operation_id}: {error}"
            )


async def _wait_for_archive_replay_detection(
    dashboard: QtCore.QObject,
    stop_event,
):
    """Wait until one configured detector reports a matching Detection."""
    detection_event = getattr(dashboard, "archive_replay_detection_event", None)

    if detection_event is None:
        return False

    while not detection_event.is_set():
        if stop_event is not None and stop_event.is_set():
            return False

        await asyncio.sleep(0.05)

    return True


def handle_archive_replay_detection(
    dashboard: QtCore.QObject,
    detection: dict,
):
    """Release Archive Replay when a Detection matches one of its active detector opids."""
    if not isinstance(detection, dict):
        return

    if not bool(getattr(dashboard, "archive_replay_running", False)):
        return

    detection_event = getattr(dashboard, "archive_replay_detection_event", None)
    if detection_event is None or detection_event.is_set():
        return

    node_uid = str(detection.get("node_uid", "") or "").strip()
    replay_node_uid = str(getattr(dashboard, "archive_replay_node_uid", "") or "").strip()

    if replay_node_uid and node_uid and node_uid != replay_node_uid:
        return

    operation_id = str(
        detection.get("opid")
        or detection.get("operation_id")
        or ""
    ).strip()

    operation_ids = getattr(dashboard, "archive_replay_detector_operation_ids", set()) or set()

    if not operation_id or operation_id not in operation_ids:
        return

    dashboard.archive_replay_detection = dict(detection)
    detection_event.set()

    dashboard.logger.info(
        "Archive Replay detector matched: "
        f"operation_id={operation_id}, "
        f"detector={detection.get('detector', '')}"
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsRegenerateClicked(dashboard: QtCore.QObject):
    """ 
    Regenerates the checkbox values in the Dataset Builder table.
    """
    # Generate Values in the Tables
    for row in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
        noise_value = random.uniform(float(dashboard.backend.settings['dataset_noise_min']),float(dashboard.backend.settings['dataset_noise_max']))
        dashboard.ui.tableWidget_archive_datasets.item(row,4).setText("{:0.2f}".format(noise_value))
        phase_value = random.uniform(float(dashboard.backend.settings['dataset_phase_rot_min']),float(dashboard.backend.settings['dataset_phase_rot_max']))
        dashboard.ui.tableWidget_archive_datasets.item(row,5).setText("{:0.2f}".format(phase_value))
        scale_value = random.uniform(float(dashboard.backend.settings['dataset_scale_min']),float(dashboard.backend.settings['dataset_scale_max']))
        dashboard.ui.tableWidget_archive_datasets.item(row,6).setText("{:0.2f}".format(scale_value))
        freq_shift_value = random.uniform(float(dashboard.backend.settings['dataset_freq_shift_min']),float(dashboard.backend.settings['dataset_freq_shift_max']))
        dashboard.ui.tableWidget_archive_datasets.item(row,7).setText("{:0.2f}".format(freq_shift_value))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadPlotClicked(dashboard: QtCore.QObject):
    """ 
    Plots the Archive file in the IQ Viewer.
    """
    # Ignore Folders
    get_index = dashboard.ui.listView_archive.currentIndex()
    if dashboard.ui.listView_archive.model().isDir(get_index) == True:
        return

    # Get the Folder and File
    get_file = str(dashboard.ui.listView_archive.currentIndex().data())
    get_folder = str(dashboard.ui.listView_archive.model().filePath(dashboard.ui.listView_archive.currentIndex())).rsplit('/',1)[0]

    # Ignore No Selection
    if len(get_folder) == 0:
        return

    # Set the Files and Directories in the IQ Tab
    if get_folder == fissure.utils.ARCHIVE_DIR:
        dashboard.ui.comboBox3_iq_folders.setCurrentIndex(1)
    else:
        # Determine if the Directory is Present Already
        match_found = False
        for n in range(0,dashboard.ui.comboBox3_iq_folders.count()):
            if get_folder == dashboard.ui.comboBox3_iq_folders.itemText(n):
                dashboard.ui.comboBox3_iq_folders.setCurrentIndex(n)
                match_found = True
                break
        if match_found == False:
            dashboard.ui.comboBox3_iq_folders.addItem(get_folder)
            dashboard.ui.comboBox3_iq_folders.setCurrentIndex(dashboard.ui.comboBox3_iq_folders.count()-1)

    for n in range(0,dashboard.ui.listWidget_iq_files.count()):
        if get_file == dashboard.ui.listWidget_iq_files.item(n).text():
            dashboard.ui.listWidget_iq_files.setCurrentRow(n)
            break
    
    # Sync Data Type Comboboxes
    current_tab_data_type = str(dashboard.ui.comboBox_archive_downloaded_data_type.currentText())
    index = dashboard.ui.comboBox_iq_data_type.findText(current_tab_data_type)
    if index != -1:
        dashboard.ui.comboBox_iq_data_type.setCurrentIndex(index)

    # Load the File
    fissure.Dashboard.Slots.IQDataTabSlots._slotIQ_LoadIQ_Data(dashboard)

    # Plot the File
    fissure.Dashboard.Slots.IQDataTabSlots._slotIQ_PlotAllClicked(dashboard)

    # Change to IQ Tab
    dashboard.ui.tabWidget.setCurrentIndex(4)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsStartClicked(dashboard: QtCore.QObject):
    """ 
    Inputs the checked values in the table into the Dataset Builder flow graph.
    """
    # Stop Generating Datasets
    if dashboard.ui.pushButton_archive_datasets_start.text() == "Stop":
        dashboard.stop_archive_operations = True
        dashboard.ui.pushButton_archive_datasets_start.setText("Start")
        dashboard.ui.progressBar_archive_datasets.setVisible(False)

    # Start Generating Datasets
    elif dashboard.ui.pushButton_archive_datasets_start.text() == "Start":
        dashboard.ui.pushButton_archive_datasets_start.setText("Stop")
        dashboard.ui.progressBar_archive_datasets.setValue(1)
        dashboard.ui.progressBar_archive_datasets.setVisible(True)

        # Run the Flow Graph
        archive_flow_graph = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Archive Flow Graphs", "dataset_builder.py")
        now = datetime.datetime.now()
        now = now.strftime("%Y-%m-%d %H:%M:%S").replace(' ','_')
        get_new_filepath = os.path.join(fissure.utils.FISSURE_ROOT, "Archive", "Datasets", now)
        os.system("mkdir " + get_new_filepath)
        dashboard.stop_archive_operations = False
        for row in range(dashboard.ui.tableWidget_archive_datasets.rowCount()):
            # Get Values
            get_filepath = str(dashboard.ui.tableWidget_archive_datasets.item(row,0).text())
            get_sample_rate = str(dashboard.ui.tableWidget_archive_datasets.item(row,2).text())
            if len(get_sample_rate) == 0:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Error: Missing sample rate value in table.")
                dashboard.ui.pushButton_archive_datasets_start.setText("Start")
                dashboard.ui.progressBar_archive_datasets.setValue(0)
                dashboard.ui.progressBar_archive_datasets.setVisible(False)
                return
            get_frequency = str(dashboard.ui.tableWidget_archive_datasets.item(row,3).text())
            if len(get_frequency) == 0:
                get_frequency = "1000000000"
            if int(dashboard.ui.tableWidget_archive_datasets.item(row,4).checkState()) == 2:
                get_noise = str(dashboard.ui.tableWidget_archive_datasets.item(row,4).text())
            else:
                get_noise = "0"
            if int(dashboard.ui.tableWidget_archive_datasets.item(row,5).checkState()) == 2:
                get_phase_rot = str(dashboard.ui.tableWidget_archive_datasets.item(row,5).text())
            else:
                get_phase_rot = "0"
            if int(dashboard.ui.tableWidget_archive_datasets.item(row,6).checkState()) == 2:
                get_scale = str(dashboard.ui.tableWidget_archive_datasets.item(row,6).text())
            else:
                get_scale = "1"
            if int(dashboard.ui.tableWidget_archive_datasets.item(row,7).checkState()) == 2:
                get_freq_shift = str(dashboard.ui.tableWidget_archive_datasets.item(row,7).text())
            else:
                get_freq_shift = "0"
            if int(dashboard.ui.tableWidget_archive_datasets.item(row,8).checkState()) == 2:
                get_sigmf = True
            else:
                get_sigmf = False

            dashboard.archive_database_loop = True
            loadthread = OperationsThread('python3 "' + archive_flow_graph + '" --filepath "' + get_filepath \
                + '" --sample-rate ' + get_sample_rate + " --frequency " + get_frequency + " --noise " + get_noise \
                + " --phase-rot " + get_phase_rot + " --scale " + get_scale + " --freq-shift " + get_freq_shift \
                + " --new-filepath " + get_new_filepath + "/" + now + "_" + str(row), get_new_filepath, dashboard)
            loadthread.finished.connect(lambda: on_finished(dashboard))
            loadthread.start()
            while dashboard.archive_database_loop == True:
                QtWidgets.QApplication.processEvents()
                time.sleep(0.1)
                if dashboard.stop_archive_operations == True:
                    break
            dashboard.ui.progressBar_archive_datasets.setValue(1+int(float(row+1)/float(dashboard.ui.tableWidget_archive_datasets.rowCount())*99))

        dashboard.ui.progressBar_archive_datasets.setValue(100)
        dashboard.ui.pushButton_archive_datasets_start.setText("Start")
        time.sleep(1)
        dashboard.ui.progressBar_archive_datasets.setVisible(False)


@QtCore.pyqtSlot()
def on_finished(dashboard: QtCore.QObject):
    """ 
    Proceed to the operation.
    """
    dashboard.archive_database_loop = False

    
class OperationsThread(QtCore.QThread):
    """
    Used for Archive database generation.
    """
    def __init__(self, cmd, get_cwd, parent=None):
        QtCore.QThread.__init__(self, parent)
        self.cmd = cmd
        self.get_cwd = get_cwd

    def run(self):
        try:
            p1 = subprocess.Popen(self.cmd, shell=True, cwd=self.get_cwd)
            (output, err) = p1.communicate()
            p1.wait()
        except:
            print("FAILURE")
