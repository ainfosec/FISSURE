from PyQt5 import QtCore, QtGui, QtWidgets

import inspect
import os
import qasync
import json
import time
import subprocess
import csv
import math
import matplotlib.pyplot as plt
import uuid
import asyncio
import zipfile

import fissure.utils
from fissure.utils.selected_node_utils import selected_node_is_local


def _tsi_fe_selected_node_available(dashboard: QtCore.QObject) -> bool:
    """
    Returns True when a Sensor Node is selected and is not explicitly
    disconnected in the Dashboard node-state cache.
    """
    selected_uid = str(
        getattr(dashboard, "selected_node_uid", "") or ""
    ).strip()

    if not selected_uid:
        return False

    node_states = getattr(dashboard, "node_states", {}) or {}
    node_state = node_states.get(selected_uid)

    if isinstance(node_state, dict) and node_state.get("connected") is False:
        return False

    return True


def update_tsi_fe_selected_node_gate(dashboard: QtCore.QObject):
    """
    Switches the Feature Extractor selected-node gate.

    Designer page order:
        0 = normal Feature Extractor workflow
        1 = select-node / unavailable-node page
    """
    selected_uid = str(
        getattr(dashboard, "selected_node_uid", "") or ""
    ).strip()
    node_ready = _tsi_fe_selected_node_available(dashboard)

    gate_stack = getattr(
        dashboard.ui,
        "stackedWidget_tsi_fe_node_gate",
        None,
    )

    if gate_stack is None:
        dashboard.logger.debug(
            "[Feature Extractor] stackedWidget_tsi_fe_node_gate not found."
        )
        return

    target_index = 0 if node_ready else 1
    gate_stack.setCurrentIndex(target_index)

    dashboard.logger.debug(
        "[Feature Extractor] node gate updated: "
        f"selected_uid={selected_uid!r}, "
        f"node_ready={node_ready}, "
        f"target_index={target_index}, "
        f"actual_index={gate_stack.currentIndex()}, "
        f"page_count={gate_stack.count()}"
    )


def initialize_tsi_feature_extractor_controls(dashboard: QtCore.QObject):
    """Initialize the Feature Extractor around Artifact-first SOI context."""
    select_node_icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", "select_node.png")
    select_node_label = getattr(dashboard.ui, "label_tsi_fe_select_sensor_node_image", None)
    if select_node_label is not None and os.path.isfile(select_node_icon_path):
        select_node_label.setPixmap(QtGui.QPixmap(select_node_icon_path))

    workflow_icons = {
        "label_tsi_fe_workflow_source_icon": "conditioner_source.svg",
        "label_tsi_fe_workflow_node_icon": "conditioner_node.svg",
        "label_tsi_fe_workflow_action_icon": "conditioner_action.svg",
        "label_tsi_fe_workflow_inputs_icon": "conditioner_count.svg",
        "label_tsi_fe_workflow_profile_icon": "conditioner_method.svg",
        "label_tsi_fe_workflow_output_type_icon": "conditioner_artifact.svg",
    }
    for label_name, icon_name in workflow_icons.items():
        label = getattr(dashboard.ui, label_name, None)
        icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", icon_name)
        if label is not None and os.path.isfile(icon_path):
            label.setPixmap(QtGui.QPixmap(icon_path))

    browse_icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", "folder_black.svg")
    if os.path.isfile(browse_icon_path):
        button = dashboard.ui.pushButton_tsi_fe_input_folder
        button.setIcon(QtGui.QIcon(browse_icon_path))
        button.setText("")
        button.setToolTip("Select input folder")
        button.setIconSize(QtCore.QSize(18, 18))

    refresh_icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", "refresh.png")
    if os.path.isfile(refresh_icon_path):
        for button_name, tooltip in (
            ("pushButton_tsi_fe_input_refresh", "Refresh file list"),
            ("pushButton_tsi_fe_input_artifact_refresh", "Refresh available artifacts"),
        ):
            button = getattr(dashboard.ui, button_name, None)
            if button is None:
                continue
            button.setIcon(QtGui.QIcon(refresh_icon_path))
            button.setText("")
            button.setToolTip(tooltip)
            button.setIconSize(QtCore.QSize(18, 18))

    dashboard.tsi_fe_input_folder = getattr(dashboard, "tsi_fe_input_folder", "")
    dashboard.tsi_fe_input_artifacts = []
    dashboard.tsi_fe_input_sois = []
    dashboard.tsi_fe_selected_input_artifact = {}
    dashboard.tsi_fe_selected_input_artifact_files = []
    dashboard.tsi_fe_selected_input_soi = {}
    dashboard.tsi_fe_result_saved_to_soi = False
    dashboard.tsi_fe_last_selected_node_uid = str(
        getattr(dashboard, "selected_node_uid", "") or ""
    ).strip()

    source_combo = dashboard.ui.comboBox_tsi_fe_input_source
    source_combo.blockSignals(True)
    source_combo.clear()
    source_combo.addItems(["Files", "Folder", "Artifact"])
    source_combo.setCurrentText("Files")
    source_combo.blockSignals(False)

    artifact_combo = dashboard.ui.comboBox_tsi_fe_input_artifact
    artifact_combo.blockSignals(True)
    artifact_combo.clear()
    artifact_combo.addItem("Select Artifact...", None)
    artifact_combo.setCurrentIndex(0)
    artifact_combo.blockSignals(False)

    soi_combo = dashboard.ui.comboBox_tsi_fe_input_soi
    soi_combo.blockSignals(True)
    soi_combo.clear()
    soi_combo.addItem("Manual / No SOI", None)
    soi_combo.setCurrentIndex(0)
    soi_combo.blockSignals(False)

    profile_combo = dashboard.ui.comboBox_tsi_fe_method_profile
    profile_combo.blockSignals(True)
    profile_combo.clear()
    profile_combo.addItems(["Time Domain", "Frequency Domain", "Time + Frequency", "All Available", "Custom"])
    profile_combo.setCurrentText("Time Domain")
    profile_combo.blockSignals(False)

    action_combo = dashboard.ui.comboBox_tsi_fe_method_action
    action_combo.blockSignals(True)
    action_combo.clear()
    action_combo.blockSignals(False)
    action_combo.setEnabled(False)

    dashboard.tsi_fe_method_actions = []
    dashboard.tsi_fe_selected_plugin = ""
    dashboard.tsi_fe_selected_action = ""
    dashboard.tsi_fe_action_query_pending = False
    dashboard.tsi_fe_action_query_context = ""
    dashboard.tsi_fe_action_query_node_uid = ""
    clear_tsi_fe_method_parameter_controls(dashboard)

    dashboard.ui.label_tsi_fe_workflow_profile.setText(profile_combo.currentText())
    dashboard.ui.label_tsi_fe_workflow_action.setText("—")

    _tsi_fe_set_input_folder(dashboard, os.path.join(fissure.utils.FISSURE_ROOT, "Conditioner Data", "Output"))
    if not dashboard.ui.textEdit_tsi_fe_file_sample_rate.toPlainText().strip():
        dashboard.ui.textEdit_tsi_fe_file_sample_rate.setPlainText("1")

    dashboard.ui.radioButton_tsi_fe_input_extensions_all.setChecked(True)
    dashboard.ui.textEdit_tsi_fe_input_extensions.setEnabled(False)
    dashboard.ui.listWidget_tsi_fe_input_files.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
    dashboard.ui.stackedWidget_tsi_fe_input.setCurrentIndex(0)

    refresh_tsi_fe_input_sois(dashboard)
    _slotTSI_FE_InputSourceChanged(dashboard)
    _tsi_fe_refresh_file_list_from_path(dashboard)
    _tsi_fe_update_preview_gate(dashboard)
    initialize_tsi_fe_run_controls(dashboard)
    update_tsi_fe_selected_node_gate(dashboard)
    update_tsi_fe_locality_controls(dashboard)
    initialize_tsi_fe_results_controls(dashboard)


def _tsi_fe_current_source(dashboard: QtCore.QObject) -> str:
    """
    Returns the selected Feature Extractor input source.
    """
    return str(
        dashboard.ui.comboBox_tsi_fe_input_source.currentText()
        or ""
    ).strip()


def _tsi_fe_shorten_path(path: str, max_chars: int = 38) -> str:
    """
    Shortens a folder path for the cramped folder text edit.

    The real path is stored separately on dashboard.tsi_fe_input_folder.
    """
    path = str(path or "").strip()

    if len(path) <= max_chars:
        return path

    base = os.path.basename(path.rstrip(os.sep))
    parent = os.path.basename(os.path.dirname(path.rstrip(os.sep)))

    if parent:
        shortened = f".../{parent}/{base}"
    else:
        shortened = f".../{base}"

    if len(shortened) > max_chars:
        shortened = "..." + shortened[-(max_chars - 3):]

    return shortened


def _tsi_fe_set_input_folder(
    dashboard: QtCore.QObject,
    folder_path: str,
):
    """
    Sets the Feature Extractor input folder.

    The QTextEdit displays a shortened path while the full path is stored in:
        dashboard.tsi_fe_input_folder
    """
    folder_path = os.path.abspath(str(folder_path or "").strip())

    dashboard.tsi_fe_input_folder = folder_path

    text_edit = dashboard.ui.textEdit_tsi_fe_file_path
    old_state = text_edit.blockSignals(True)
    text_edit.setPlainText(_tsi_fe_shorten_path(folder_path))
    text_edit.setToolTip(folder_path)
    text_edit.blockSignals(old_state)


def _tsi_fe_get_input_folder(dashboard: QtCore.QObject) -> str:
    """
    Gets the real Feature Extractor input folder.

    Falls back to the visible text only when no stored folder is available.
    """
    folder_path = getattr(dashboard, "tsi_fe_input_folder", "")

    if folder_path and os.path.isdir(folder_path):
        return folder_path

    visible_text = (
        dashboard.ui.textEdit_tsi_fe_file_path
        .toPlainText()
        .strip()
    )

    if visible_text and os.path.isdir(visible_text):
        dashboard.tsi_fe_input_folder = os.path.abspath(visible_text)
        return dashboard.tsi_fe_input_folder

    return ""


def _tsi_fe_refresh_file_list_from_path(
    dashboard: QtCore.QObject,
):
    """
    Refreshes the Feature Extractor file list from the selected input folder.

    Filtering matches the Conditioner:
        - All includes every regular file.
        - Custom includes files ending with the entered extension.

    Files mode preserves the explicit multi-selection when possible.
    Folder mode treats every visible filtered file as input; the current row is
    retained only for Preview IQ.
    """
    list_widget = dashboard.ui.listWidget_tsi_fe_input_files

    previous_selected = {
        item.text()
        for item in list_widget.selectedItems()
    }

    previous_current = ""
    current_item = list_widget.currentItem()

    if current_item is not None:
        previous_current = current_item.text()

    list_widget.clear()

    folder_path = _tsi_fe_get_input_folder(dashboard)

    if not folder_path or not os.path.isdir(folder_path):
        _tsi_fe_update_input_ribbon(dashboard)
        _tsi_fe_update_preview_gate(dashboard)
        update_tsi_fe_run_start_state(dashboard)
        return

    use_all = (
        dashboard.ui.radioButton_tsi_fe_input_extensions_all.isChecked()
    )
    extension = (
        dashboard.ui.textEdit_tsi_fe_input_extensions
        .toPlainText()
        .strip()
    )

    filenames = []

    for fname in os.listdir(folder_path):
        full_path = os.path.join(folder_path, fname)

        if not os.path.isfile(full_path):
            continue

        if use_all:
            filenames.append(fname)
        elif extension and fname.lower().endswith(extension.lower()):
            filenames.append(fname)

    filenames = sorted(filenames, key=str.lower)

    for fname in filenames:
        list_widget.addItem(fname)

    source = _tsi_fe_current_source(dashboard)

    if source == "Files":
        restored_any = False

        for row in range(list_widget.count()):
            item = list_widget.item(row)

            if item.text() in previous_selected:
                item.setSelected(True)
                restored_any = True

        if list_widget.count() > 0:
            if previous_current:
                matches = list_widget.findItems(
                    previous_current,
                    QtCore.Qt.MatchExactly,
                )
                if matches:
                    list_widget.setCurrentItem(
                        matches[0],
                        QtCore.QItemSelectionModel.NoUpdate,
                    )
                elif not restored_any:
                    list_widget.setCurrentRow(0)
            elif not restored_any:
                list_widget.setCurrentRow(0)

    elif source == "Folder":
        if list_widget.count() > 0:
            if previous_current:
                matches = list_widget.findItems(
                    previous_current,
                    QtCore.Qt.MatchExactly,
                )
                if matches:
                    list_widget.setCurrentItem(matches[0])
                else:
                    list_widget.setCurrentRow(0)
            else:
                list_widget.setCurrentRow(0)

    elif list_widget.count() > 0:
        list_widget.setCurrentRow(0)

    _tsi_fe_update_input_ribbon(dashboard)
    _tsi_fe_update_preview_gate(dashboard)
    update_tsi_fe_run_start_state(dashboard)


def _tsi_fe_update_input_ribbon(
    dashboard: QtCore.QObject,
):
    """
    Updates the Source and Inputs values in the Feature Extractor ribbon.

    Files:
        selected files / visible files

    Folder:
        all visible filtered files / visible files
    """
    source = _tsi_fe_current_source(dashboard)
    list_widget = dashboard.ui.listWidget_tsi_fe_input_files

    dashboard.ui.label_tsi_fe_workflow_source.setText(
        source if source else "—"
    )

    total_count = list_widget.count()

    if source == "Files":
        selected_count = len(list_widget.selectedItems())
    elif source == "Folder":
        selected_count = total_count
    else:
        selected_count = len(list_widget.selectedItems())

    dashboard.ui.label_tsi_fe_workflow_inputs.setText(
        f"{selected_count} / {total_count}"
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputSourceChanged(dashboard: QtCore.QObject):
    """Apply source-page, selection, locality, and input-list refresh state."""
    source_combo = dashboard.ui.comboBox_tsi_fe_input_source
    source = _tsi_fe_current_source(dashboard)

    if _tsi_fe_selected_node_is_remote(dashboard) and source in {"Files", "Folder"}:
        artifact_index = source_combo.findText("Artifact")
        if artifact_index >= 0:
            source_combo.blockSignals(True)
            source_combo.setCurrentIndex(artifact_index)
            source_combo.blockSignals(False)
        source = "Artifact"

    dashboard.ui.stackedWidget_tsi_fe_input.setCurrentIndex({"Files": 0, "Folder": 0, "Artifact": 1}.get(source, 0))
    list_widget = dashboard.ui.listWidget_tsi_fe_input_files

    if source == "Files":
        list_widget.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        list_widget.clear()
        _tsi_fe_refresh_file_list_from_path(dashboard)
    elif source == "Folder":
        list_widget.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        list_widget.clear()
        _tsi_fe_refresh_file_list_from_path(dashboard)
    elif source == "Artifact":
        list_widget.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        list_widget.clear()
        refresh_tsi_fe_input_artifacts(dashboard)
    else:
        list_widget.clear()

    local_enabled = bool(source in {"Files", "Folder"} and not _tsi_fe_selected_node_is_remote(dashboard))
    for widget_name in ("pushButton_tsi_fe_input_folder", "pushButton_tsi_fe_input_refresh", "textEdit_tsi_fe_file_path"):
        widget = getattr(dashboard.ui, widget_name, None)
        if widget is not None:
            widget.setEnabled(local_enabled)

    clear_tsi_fe_method_actions(dashboard)
    _tsi_fe_update_input_ribbon(dashboard)
    _tsi_fe_update_preview_gate(dashboard)
    update_tsi_fe_run_start_state(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputFolderClicked(dashboard: QtCore.QObject):
    """
    Selects the Feature Extractor input folder.

    Files and Folder both browse for a folder. The active Files input comes from
    the file-list selection.
    """
    current_folder = _tsi_fe_get_input_folder(dashboard)

    if not current_folder:
        current_folder = os.path.join(
            fissure.utils.FISSURE_ROOT,
            "Conditioner Data",
            "Output",
        )

    selected_dir = QtWidgets.QFileDialog.getExistingDirectory(
        dashboard,
        "Select IQ Input Folder",
        current_folder,
    )

    if not selected_dir:
        return

    _tsi_fe_set_input_folder(dashboard, selected_dir)
    _tsi_fe_refresh_file_list_from_path(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputRefreshClicked(dashboard: QtCore.QObject):
    """
    Refreshes the Feature Extractor input file list.
    """
    _tsi_fe_refresh_file_list_from_path(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputPathEdited(dashboard: QtCore.QObject):
    """
    Accepts a manually typed or pasted input folder path.

    Shortened display paths such as .../folder are ignored.
    """
    text = (
        dashboard.ui.textEdit_tsi_fe_file_path
        .toPlainText()
        .strip()
    )

    if text and os.path.isdir(text):
        dashboard.tsi_fe_input_folder = os.path.abspath(text)
        dashboard.ui.textEdit_tsi_fe_file_path.setToolTip(
            dashboard.tsi_fe_input_folder
        )
        _tsi_fe_refresh_file_list_from_path(dashboard)
        return

    _tsi_fe_update_input_ribbon(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputExtensionsAllClicked(dashboard: QtCore.QObject):
    """Show all resolved files for the current local or Artifact input."""
    dashboard.ui.textEdit_tsi_fe_input_extensions.setEnabled(False)
    source = _tsi_fe_current_source(dashboard)
    if source in {"Files", "Folder"}:
        _tsi_fe_refresh_file_list_from_path(dashboard)
    elif source == "Artifact":
        _tsi_fe_render_managed_file_list(dashboard, getattr(dashboard, "tsi_fe_selected_input_artifact_files", []))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputExtensionsCustomClicked(
    dashboard: QtCore.QObject,
):
    """
    Enables custom extension filtering for local and managed inputs.
    """
    dashboard.ui.textEdit_tsi_fe_input_extensions.setEnabled(
        True
    )

    _slotTSI_FE_InputExtensionsEdited(
        dashboard
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputExtensionsEdited(dashboard: QtCore.QObject):
    """Reapply the active custom extension filter."""
    if not dashboard.ui.radioButton_tsi_fe_input_extensions_custom.isChecked():
        return
    source = _tsi_fe_current_source(dashboard)
    if source in {"Files", "Folder"}:
        _tsi_fe_refresh_file_list_from_path(dashboard)
    elif source == "Artifact":
        _tsi_fe_render_managed_file_list(dashboard, getattr(dashboard, "tsi_fe_selected_input_artifact_files", []))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputSelectionChanged(
    dashboard: QtCore.QObject,
):
    """
    Keeps the ribbon input count and Preview IQ state synchronized.
    """
    _tsi_fe_update_input_ribbon(dashboard)
    _tsi_fe_update_preview_gate(dashboard)
    update_tsi_fe_run_start_state(dashboard)


def _tsi_fe_selected_input_file(dashboard: QtCore.QObject) -> str:
    """Return the highlighted local path when the Dashboard has one."""
    source = _tsi_fe_current_source(dashboard)
    current_item = dashboard.ui.listWidget_tsi_fe_input_files.currentItem()
    if current_item is None:
        return ""

    if source == "Artifact":
        item_data = current_item.data(QtCore.Qt.UserRole)
        if isinstance(item_data, dict):
            return str(item_data.get("path", "") or "").strip()
        return ""

    folder_path = _tsi_fe_get_input_folder(dashboard)
    if not folder_path:
        return ""
    return os.path.join(folder_path, str(current_item.text() or "").strip())


def _tsi_fe_update_preview_gate(
    dashboard: QtCore.QObject,
):
    """
    Enables Preview IQ only when the highlighted local file exists.
    """
    filepath = _tsi_fe_selected_input_file(dashboard)

    dashboard.ui.pushButton_tsi_fe_input_preview.setEnabled(
        bool(filepath and os.path.isfile(filepath))
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputPreviewClicked(
    dashboard: QtCore.QObject,
):
    """
    Opens the existing IQ preview dialog for the highlighted input file.
    """
    filepath = _tsi_fe_selected_input_file(dashboard)

    if not filepath or not os.path.isfile(filepath):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Select a valid input file first."
        )
        _tsi_fe_update_preview_gate(dashboard)
        return

    data_type = str(
        dashboard.ui.comboBox_tsi_fe_input_data_type.currentText()
        or ""
    ).strip()

    try:
        fissure.Dashboard.UI_Components.Qt5.previewIQ_File(
            data_type,
            filepath,
        )
    except Exception as e:
        dashboard.logger.error(
            f"[Feature Extractor] Failed to preview IQ file: {e}"
        )
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to preview IQ file:\n{e}"
        )

    _tsi_fe_update_preview_gate(dashboard)


def _tsi_fe_profile_tag(dashboard: QtCore.QObject) -> str:
    """
    Returns the plugin action tag for the selected Feature Extractor profile.

    All Available intentionally returns an empty tag so the query returns every
    Feature Extractor action compatible with the selected source.
    """
    profile = str(
        dashboard.ui.comboBox_tsi_fe_method_profile.currentText()
        or ""
    ).strip()

    tags = {
        "Time Domain": "tsi.feature_extractor.profile.time_domain",
        "Frequency Domain": "tsi.feature_extractor.profile.frequency_domain",
        "Time + Frequency": "tsi.feature_extractor.profile.time_frequency",
        "Custom": "tsi.feature_extractor.profile.custom",
    }

    return tags.get(profile, "")


def _tsi_fe_source_tag(dashboard: QtCore.QObject) -> str:
    """Return the plugin-action source compatibility tag."""
    return {
        "Files": "tsi.feature_extractor.source.file",
        "Folder": "tsi.feature_extractor.source.folder",
        "Artifact": "tsi.feature_extractor.source.artifact",
    }.get(_tsi_fe_current_source(dashboard), "")


def _tsi_fe_update_method_ribbon(dashboard: QtCore.QObject):
    profile = str(
        dashboard.ui.comboBox_tsi_fe_method_profile.currentText()
        or ""
    ).strip()

    action_text = str(
        dashboard.ui.comboBox_tsi_fe_method_action.currentText()
        or ""
    ).strip()

    dashboard.ui.label_tsi_fe_workflow_profile.setText(
        profile if profile else "—"
    )
    dashboard.ui.label_tsi_fe_workflow_action.setText(
        action_text if action_text else "—"
    )


def _tsi_fe_clear_layout_widgets(layout: QtWidgets.QLayout):
    if layout is None:
        return

    while layout.count():
        item = layout.takeAt(0)

        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
            continue

        child_layout = item.layout()
        if child_layout is not None:
            _tsi_fe_clear_layout_widgets(child_layout)


def clear_tsi_fe_method_parameter_controls(dashboard: QtCore.QObject):
    """
    Clears Feature Extractor action-parameter controls.
    """
    scroll_area = dashboard.ui.scrollArea_tsi_fe_method
    contents = dashboard.ui.scrollAreaWidgetContents_tsi_fe_parameters

    contents.setAutoFillBackground(False)

    layout = contents.layout()

    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    _tsi_fe_clear_layout_widgets(layout)

    layout.setContentsMargins(12, 10, 12, 10)
    layout.setHorizontalSpacing(8)
    layout.setVerticalSpacing(7)
    layout.setAlignment(QtCore.Qt.AlignTop)

    contents.setMaximumWidth(430)

    scroll_area.setWidget(contents)
    scroll_area.setWidgetResizable(True)
    scroll_area.setAlignment(
        QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop
    )
    scroll_area.setHorizontalScrollBarPolicy(
        QtCore.Qt.ScrollBarAlwaysOff
    )
    scroll_area.setVerticalScrollBarPolicy(
        QtCore.Qt.ScrollBarAsNeeded
    )

    dashboard.tsi_fe_method_parameter_widgets = {}
    dashboard.tsi_fe_method_current_schema = {}
    dashboard.tsi_fe_method_customized = False


def clear_tsi_fe_method_actions(dashboard: QtCore.QObject):
    """
    Clears queried Feature Extractor actions and parameters.
    """
    combo = dashboard.ui.comboBox_tsi_fe_method_action

    combo.blockSignals(True)
    combo.clear()
    combo.blockSignals(False)
    combo.setEnabled(False)

    dashboard.ui.pushButton_tsi_fe_method_query_actions.setEnabled(True)
    dashboard.ui.pushButton_tsi_fe_method_query_parameters.setEnabled(False)

    dashboard.tsi_fe_method_actions = []
    dashboard.tsi_fe_selected_plugin = ""
    dashboard.tsi_fe_selected_action = ""

    dashboard.tsi_fe_action_query_pending = False
    dashboard.tsi_fe_action_query_context = ""
    dashboard.tsi_fe_action_query_node_uid = ""

    clear_tsi_fe_method_parameter_controls(dashboard)
    _tsi_fe_update_method_ribbon(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_MethodProfileChanged(dashboard: QtCore.QObject):
    clear_tsi_fe_method_actions(dashboard)
    _tsi_fe_update_method_ribbon(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_MethodActionChanged(dashboard: QtCore.QObject):
    record = dashboard.ui.comboBox_tsi_fe_method_action.currentData()

    clear_tsi_fe_method_parameter_controls(dashboard)

    if not isinstance(record, dict):
        dashboard.tsi_fe_selected_plugin = ""
        dashboard.tsi_fe_selected_action = ""
        dashboard.ui.pushButton_tsi_fe_method_query_parameters.setEnabled(False)
        _tsi_fe_update_method_ribbon(dashboard)
        return

    plugin_name = str(record.get("plugin", "") or "").strip()
    action_name = str(record.get("action", "") or "").strip()

    dashboard.tsi_fe_selected_plugin = plugin_name
    dashboard.tsi_fe_selected_action = action_name

    dashboard.ui.pushButton_tsi_fe_method_query_parameters.setEnabled(
        bool(plugin_name and action_name)
    )

    _tsi_fe_update_method_ribbon(dashboard)
    update_tsi_fe_run_start_state(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_FE_MethodQueryActionsClicked(
    dashboard: QtCore.QObject,
):
    """
    Queries Feature Extractor actions matching the selected profile and source.
    """
    uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    if not uid:
        dashboard.logger.warning(
            "[Feature Extractor] Select a sensor node before querying actions."
        )
        return

    profile = str(
        dashboard.ui.comboBox_tsi_fe_method_profile.currentText()
        or ""
    ).strip()

    source = _tsi_fe_current_source(dashboard)
    profile_tag = _tsi_fe_profile_tag(dashboard)
    source_tag = _tsi_fe_source_tag(dashboard)

    include_tags = ["tsi.feature_extractor"]

    if profile_tag:
        include_tags.append(profile_tag)

    if source_tag:
        include_tags.append(source_tag)

    context_profile = (
        profile.lower()
        .replace("+", "plus")
        .replace(" ", "_")
    )
    context_source = source.lower().replace(" ", "_")
    context = (
        f"tsi.feature_extractor."
        f"{context_profile}.{context_source}"
    )

    clear_tsi_fe_method_actions(dashboard)

    dashboard.tsi_fe_action_query_pending = True
    dashboard.tsi_fe_action_query_context = context
    dashboard.tsi_fe_action_query_node_uid = uid

    dashboard.ui.comboBox_tsi_fe_method_action.setEnabled(False)
    dashboard.ui.pushButton_tsi_fe_method_query_actions.setEnabled(False)
    dashboard.ui.pushButton_tsi_fe_method_query_parameters.setEnabled(False)

    dashboard.logger.debug(
        "[Feature Extractor] Querying actions: "
        f"uid={uid!r}, context={context!r}, "
        f"include_tags={include_tags!r}"
    )

    await dashboard.backend.queryPluginActions(
        uid=uid,
        context=context,
        scope="all_plugins",
        plugin_name="",
        include_tags=include_tags,
        exclude_tags=[],
        hardware="",
    )


def handle_tsi_fe_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str,
    context: str,
    actions: list,
):
    """
    Populates the Feature Extractor action combo from an async query result.
    """
    expected_context = str(
        getattr(dashboard, "tsi_fe_action_query_context", "")
        or ""
    )
    expected_node_uid = str(
        getattr(dashboard, "tsi_fe_action_query_node_uid", "")
        or ""
    )

    result_context = str(context or "")
    result_node_uid = str(node_uid or "")

    query_pending = bool(
        getattr(dashboard, "tsi_fe_action_query_pending", False)
    )

    if (
        not query_pending
        or result_context != expected_context
        or result_node_uid != expected_node_uid
    ):
        dashboard.logger.debug(
            "[Feature Extractor] Ignoring stale action query results: "
            f"node_uid={result_node_uid!r}, "
            f"context={result_context!r}, "
            f"expected_node_uid={expected_node_uid!r}, "
            f"expected_context={expected_context!r}, "
            f"query_pending={query_pending}"
        )
        return

    dashboard.tsi_fe_action_query_pending = False
    dashboard.tsi_fe_action_query_context = ""
    dashboard.tsi_fe_action_query_node_uid = ""

    combo = dashboard.ui.comboBox_tsi_fe_method_action

    dashboard.tsi_fe_method_actions = actions or []

    combo.blockSignals(True)
    combo.clear()

    for action_record in dashboard.tsi_fe_method_actions:
        plugin_name = str(
            action_record.get("plugin", "")
            or ""
        ).strip()
        action_name = str(
            action_record.get("action", "")
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

    combo.blockSignals(False)

    has_actions = combo.count() > 0

    combo.setEnabled(has_actions)
    dashboard.ui.pushButton_tsi_fe_method_query_actions.setEnabled(True)
    dashboard.ui.pushButton_tsi_fe_method_query_parameters.setEnabled(
        has_actions
    )

    if has_actions:
        combo.setCurrentIndex(0)
        _slotTSI_FE_MethodActionChanged(dashboard)
    else:
        dashboard.tsi_fe_selected_plugin = ""
        dashboard.tsi_fe_selected_action = ""
        clear_tsi_fe_method_parameter_controls(dashboard)

    _tsi_fe_update_method_ribbon(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_FE_MethodQueryParametersClicked(
    dashboard: QtCore.QObject,
):
    uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    record = dashboard.ui.comboBox_tsi_fe_method_action.currentData()

    if not uid:
        dashboard.logger.warning(
            "[Feature Extractor] Select a sensor node before querying parameters."
        )
        return

    if not isinstance(record, dict):
        dashboard.logger.warning(
            "[Feature Extractor] Select an action before querying parameters."
        )
        return

    plugin_name = str(record.get("plugin", "") or "").strip()
    action_name = str(record.get("action", "") or "").strip()

    if not plugin_name or not action_name:
        dashboard.logger.warning(
            "[Feature Extractor] Selected action is missing plugin/action information."
        )
        return

    dashboard.tsi_fe_method_customized = False
    dashboard.tsi_fe_selected_plugin = plugin_name
    dashboard.tsi_fe_selected_action = action_name

    clear_tsi_fe_method_parameter_controls(dashboard)

    dashboard.ui.pushButton_tsi_fe_method_query_parameters.setEnabled(False)

    await dashboard.backend.queryPluginActionSchema(
        uid=uid,
        plugin_name=plugin_name,
        action_name=action_name,
        context="tsi.feature_extractor",
    )


def handle_tsi_fe_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str,
    action_name: str,
    node_uid: str,
    parameters: list,
):
    parameters = parameters or []

    selected_uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    selected_record = (
        dashboard.ui.comboBox_tsi_fe_method_action.currentData()
    )

    selected_plugin = ""
    selected_action = ""

    if isinstance(selected_record, dict):
        selected_plugin = str(
            selected_record.get("plugin", "")
            or ""
        ).strip()
        selected_action = str(
            selected_record.get("action", "")
            or ""
        ).strip()

    plugin_name = str(plugin_name or "").strip()
    action_name = str(action_name or "").strip()
    node_uid = str(node_uid or "").strip()

    if (
        selected_plugin != plugin_name
        or selected_action != action_name
        or selected_uid != node_uid
    ):
        dashboard.logger.debug(
            "[Feature Extractor] Ignoring stale schema for "
            f"{plugin_name}.{action_name}; "
            f"selected={selected_plugin}.{selected_action}, "
            f"node_uid={node_uid!r}, selected_uid={selected_uid!r}"
        )

        dashboard.tsi_fe_method_customized = False
        dashboard.ui.pushButton_tsi_fe_method_query_parameters.setEnabled(
            bool(selected_plugin and selected_action)
        )
        return

    clear_tsi_fe_method_parameter_controls(dashboard)

    dashboard.tsi_fe_selected_plugin = plugin_name
    dashboard.tsi_fe_selected_action = action_name

    dashboard.tsi_fe_method_current_schema = {
        "plugin": plugin_name,
        "action": action_name,
        "node_uid": node_uid,
        "params": parameters,
    }

    _render_tsi_fe_method_parameter_widgets(
        dashboard,
        parameters,
    )

    dashboard.tsi_fe_method_customized = True

    dashboard.ui.pushButton_tsi_fe_method_query_parameters.setEnabled(True)

    _tsi_fe_update_method_ribbon(dashboard)
    update_tsi_fe_run_start_state(dashboard)
    

def _render_tsi_fe_method_parameter_widgets(
    dashboard: QtCore.QObject,
    parameters: list,
):
    clear_tsi_fe_method_parameter_controls(dashboard)

    contents = dashboard.ui.scrollAreaWidgetContents_tsi_fe_parameters
    layout = contents.layout()

    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    visible_params = [
        param
        for param in parameters
        if str(param.get("name", "") or "").strip() != "description"
    ]

    for row, param in enumerate(visible_params):
        name = str(param.get("name", "") or "").strip()

        if not name:
            continue

        label_text = str(
            param.get("label")
            or name
        ).strip()

        widget = _create_tsi_fe_method_parameter_widget(param)

        label = QtWidgets.QLabel(
            label_text + ":",
            contents,
        )
        label.setObjectName("label2_tsi_fe_method_parameter")
        label.setAlignment(
            QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter
        )
        label.setFixedWidth(160)

        layout.addWidget(label, row, 0)
        layout.addWidget(widget, row, 1)

        dashboard.tsi_fe_method_parameter_widgets[name] = widget

    layout.setColumnMinimumWidth(0, 160)
    layout.setColumnMinimumWidth(1, 180)
    layout.setColumnStretch(0, 0)
    layout.setColumnStretch(1, 0)


def _create_tsi_fe_method_parameter_widget(param: dict):
    param_type = str(
        param.get("type", "string")
        or "string"
    ).lower()

    default = param.get("default", "")
    options = param.get("options", []) or []
    compact_width = 170

    if param_type == "label":
        widget = QtWidgets.QLabel(str(default))
        widget.setObjectName(
            "label2_tsi_fe_method_parameter_value"
        )
        widget.setWordWrap(True)
        widget.setAlignment(
            QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop
        )
        widget.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse
        )

        font = widget.font()
        font.setPointSize(8)
        widget.setFont(font)

        widget.setMinimumWidth(0)
        widget.setMaximumWidth(16777215)

        widget.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Minimum,
        )

        return widget

    if param_type in {
        "int",
        "integer",
        "number",
        "float",
        "double",
    }:
        widget = QtWidgets.QDoubleSpinBox()
        widget.setObjectName(
            "doubleSpinBox_tsi_fe_method_parameter"
        )

        try:
            decimals = int(param.get("decimals", 3))
        except Exception:
            decimals = 3

        try:
            minimum = float(param.get("min", -999999999.0))
        except Exception:
            minimum = -999999999.0

        try:
            maximum = float(param.get("max", 999999999.0))
        except Exception:
            maximum = 999999999.0

        try:
            step = float(param.get("step", 1.0))
        except Exception:
            step = 1.0

        try:
            value = float(default)
        except Exception:
            value = 0.0

        widget.setDecimals(decimals)
        widget.setMinimum(minimum)
        widget.setMaximum(maximum)
        widget.setSingleStep(step)
        widget.setValue(value)

        if param_type in {"int", "integer"}:
            widget.setDecimals(0)

        widget.setFixedWidth(compact_width)
        widget.setButtonSymbols(
            QtWidgets.QAbstractSpinBox.UpDownArrows
        )
        widget.setAlignment(QtCore.Qt.AlignRight)
        return widget

    if param_type in {"bool", "boolean"}:
        widget = QtWidgets.QCheckBox()
        widget.setObjectName(
            "checkBox_tsi_fe_method_parameter"
        )
        widget.setChecked(
            str(default).strip().lower()
            in {"1", "true", "yes", "on"}
        )
        widget.setFixedWidth(compact_width)
        return widget

    if options:
        widget = QtWidgets.QComboBox()
        widget.setObjectName(
            "comboBox_tsi_fe_method_parameter"
        )
        widget.addItems([str(option) for option in options])

        index = widget.findText(str(default))

        if index >= 0:
            widget.setCurrentIndex(index)

        widget.setFixedWidth(compact_width)
        return widget

    widget = QtWidgets.QLineEdit()
    widget.setObjectName(
        "lineEdit_tsi_fe_method_parameter"
    )
    widget.setText(str(default))
    widget.setFixedWidth(compact_width)
    return widget


def _tsi_fe_selected_node_display_name(
    dashboard: QtCore.QObject,
) -> str:
    """
    Returns the best available display name for the selected Sensor Node.
    """
    node_uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    if not node_uid:
        return "—"

    settings = (
        getattr(dashboard, "selected_node_settings", {})
        or {}
    )

    nickname = str(
        settings.get("nickname")
        or settings.get("name")
        or ""
    ).strip()

    if nickname:
        return nickname

    node_state = (
        getattr(dashboard, "node_states", {})
        or {}
    ).get(node_uid, {})

    if isinstance(node_state, dict):
        nickname = str(
            node_state.get("nickname")
            or node_state.get("name")
            or node_state.get("callsign")
            or ""
        ).strip()

        if nickname:
            return nickname

    return node_uid


def reset_tsi_fe_for_selected_node_change(dashboard: QtCore.QObject):
    """Reset node-bound Feature Extractor state after the selected node changes."""
    if bool(getattr(dashboard, "tsi_fe_running", False)):
        dashboard.logger.warning(
            "[Feature Extractor] Selected Sensor Node changed while a Feature run was active; "
            "the Dashboard is detaching from the previous run without stopping that node operation."
        )

    _tsi_fe_stop_result_timer(dashboard)
    clear_tsi_fe_method_actions(dashboard)

    soi_combo = dashboard.ui.comboBox_tsi_fe_input_soi
    soi_combo.blockSignals(True)
    if soi_combo.count() > 0:
        soi_combo.setCurrentIndex(0)
    soi_combo.blockSignals(False)
    dashboard.tsi_fe_selected_input_soi = {}

    artifact_combo = dashboard.ui.comboBox_tsi_fe_input_artifact
    artifact_combo.blockSignals(True)
    artifact_combo.clear()
    artifact_combo.addItem("Select Artifact...", None)
    artifact_combo.setCurrentIndex(0)
    artifact_combo.blockSignals(False)
    dashboard.tsi_fe_input_artifacts = []
    dashboard.tsi_fe_selected_input_artifact = {}
    dashboard.tsi_fe_selected_input_artifact_files = []
    dashboard.ui.listWidget_tsi_fe_input_files.clear()

    dashboard.tsi_fe_running = False
    dashboard.tsi_fe_started_at = None
    dashboard.tsi_fe_completed_at = None
    dashboard.tsi_fe_operation_id = ""
    dashboard.tsi_fe_source_operation_id = ""
    dashboard.tsi_fe_artifact_id = ""
    dashboard.tsi_fe_expected_feature_path = ""
    dashboard.tsi_fe_expected_report_path = ""
    dashboard.tsi_fe_result_feature_path = ""
    dashboard.tsi_fe_result_report_path = ""
    dashboard.tsi_fe_auto_download_artifact_id = ""
    dashboard.tsi_fe_result_saved_to_soi = False
    dashboard.tsi_fe_result_rows = []
    dashboard.tsi_fe_result_feature_names = []
    dashboard.tsi_fe_result_report = {}

    table = dashboard.ui.tableWidget_tsi_fe_results
    table.clear()
    table.setRowCount(0)
    table.setColumnCount(0)

    dashboard.ui.label2_tsi_fe_run_artifact_id.setText("—")
    dashboard.ui.label2_tsi_fe_run_status.setText("Idle")
    dashboard.ui.progressBar_tsi_fe_run_progress.setRange(0, 100)
    dashboard.ui.progressBar_tsi_fe_run_progress.setValue(0)
    dashboard.ui.label2_tsi_fe_run_started.setText("—")
    dashboard.ui.label2_tsi_fe_run_completed.setText("—")
    dashboard.ui.label2_tsi_fe_run_duration.setText("—")
    _tsi_fe_set_run_button_state(dashboard, running=False)
    _tsi_fe_update_artifact_download_button(dashboard)

    refresh_tsi_fe_input_sois(dashboard)
    if _tsi_fe_current_source(dashboard) == "Artifact":
        refresh_tsi_fe_input_artifacts(dashboard)

    _tsi_fe_update_input_ribbon(dashboard)
    _tsi_fe_update_method_ribbon(dashboard)
    _tsi_fe_update_result_button_state(dashboard)
    _tsi_fe_update_preview_gate(dashboard)
    _tsi_fe_update_destination_state(dashboard)
    update_tsi_fe_run_start_state(dashboard)


def update_tsi_fe_run_node(dashboard: QtCore.QObject):
    """Mirror the selected Sensor Node and reset node-bound state on real node changes."""
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    previous_uid = str(getattr(dashboard, "tsi_fe_last_selected_node_uid", "") or "").strip()

    if previous_uid and selected_uid and previous_uid != selected_uid:
        reset_tsi_fe_for_selected_node_change(dashboard)

    if selected_uid:
        dashboard.tsi_fe_last_selected_node_uid = selected_uid

    dashboard.ui.label_tsi_fe_workflow_node.setText(_tsi_fe_selected_node_display_name(dashboard))

    if not (previous_uid and selected_uid and previous_uid != selected_uid):
        refresh_tsi_fe_input_sois(dashboard)
        if _tsi_fe_current_source(dashboard) == "Artifact":
            refresh_tsi_fe_input_artifacts(dashboard)

    update_tsi_fe_run_start_state(dashboard)


def _tsi_fe_destination_is_available(dashboard: QtCore.QObject, destination: str) -> tuple:
    """Return destination availability and a user-facing reason."""
    destination = str(destination or "").strip()
    if destination not in {"Local Results", "Artifact"}:
        return False, "Select Local Results or Artifact."
    if destination == "Local Results" and _tsi_fe_selected_node_is_remote(dashboard):
        return False, "Local Results are available only when the local Sensor Node is selected."
    return True, ""


def _tsi_fe_update_destination_state(dashboard: QtCore.QObject):
    """Update the output ribbon and destination readiness."""
    destination = str(dashboard.ui.comboBox_tsi_fe_run_destination.currentText() or "").strip()
    dashboard.ui.label_tsi_fe_workflow_output_type.setText(destination if destination else "—")
    available, reason = _tsi_fe_destination_is_available(dashboard, destination)
    dashboard.ui.comboBox_tsi_fe_run_destination.setToolTip(reason if reason else destination)
    dashboard.tsi_fe_destination_available = available
    dashboard.tsi_fe_destination_unavailable_reason = reason


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_RunDestinationChanged(dashboard: QtCore.QObject):
    """Apply destination state and refresh Start/SOI-result gating."""
    _tsi_fe_update_destination_state(dashboard)
    _tsi_fe_update_result_button_state(dashboard)
    update_tsi_fe_run_start_state(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_RunDescriptionChanged(
    dashboard: QtCore.QObject,
):
    """
    Stores the current description for later operation construction.
    """
    dashboard.tsi_fe_run_description = (
        dashboard.ui.textEdit_tsi_fe_run_description
        .toPlainText()
        .strip()
    )


def _tsi_fe_update_artifact_download_button(
    dashboard: QtCore.QObject,
):
    """
    Updates the stateful Feature Extractor analysis Artifact button.

    No completed Artifact:
        disabled, Download Artifact

    Completed and uncached:
        enabled, Download Artifact

    Completed and cached:
        enabled, Open Artifact
    """
    button = getattr(
        dashboard.ui,
        "pushButton_tsi_fe_run_download_artifact",
        None,
    )

    if button is None:
        return

    artifact_id = str(
        getattr(
            dashboard,
            "tsi_fe_artifact_id",
            "",
        )
        or ""
    ).strip()

    if not artifact_id:
        button.setText(
            "Download Artifact"
        )
        button.setEnabled(False)
        button.setToolTip(
            "Run Feature Extractor with a managed Artifact destination first."
        )
        return

    controller = getattr(
        dashboard.backend,
        "artifact_transfer_controller",
        None,
    )

    local_path = (
        controller.get_local_path(
            artifact_id
        )
        if controller is not None
        else None
    )

    if local_path:
        button.setText(
            "Open Artifact"
        )
        button.setEnabled(True)
        button.setToolTip(
            str(local_path)
        )
    else:
        button.setText(
            "Download Artifact"
        )
        button.setEnabled(True)
        button.setToolTip(
            f"Download analysis Artifact {artifact_id}"
        )


def initialize_tsi_fe_run_controls(dashboard: QtCore.QObject):
    """Initialize Feature Extractor execution state."""
    dashboard.tsi_fe_running = False
    dashboard.tsi_fe_started_at = None
    dashboard.tsi_fe_completed_at = None
    dashboard.tsi_fe_operation_id = ""
    dashboard.tsi_fe_source_operation_id = ""
    dashboard.tsi_fe_artifact_id = ""
    dashboard.tsi_fe_expected_feature_path = ""
    dashboard.tsi_fe_expected_report_path = ""
    dashboard.tsi_fe_result_feature_path = ""
    dashboard.tsi_fe_result_report_path = ""
    dashboard.tsi_fe_auto_download_artifact_id = ""
    dashboard.tsi_fe_result_saved_to_soi = False

    description = dashboard.ui.textEdit_tsi_fe_run_description.toPlainText().strip()
    if not description:
        description = "Feature extraction results"
        dashboard.ui.textEdit_tsi_fe_run_description.setPlainText(description)
    dashboard.tsi_fe_run_description = description

    destination_combo = dashboard.ui.comboBox_tsi_fe_run_destination
    destination_combo.blockSignals(True)
    destination_combo.clear()
    destination_combo.addItems(["Local Results", "Artifact"])
    destination_combo.setCurrentText("Artifact")
    destination_combo.blockSignals(False)

    dashboard.ui.label2_tsi_fe_run_artifact_id.setText("—")
    dashboard.ui.label2_tsi_fe_run_status.setText("Idle")
    dashboard.ui.progressBar_tsi_fe_run_progress.setRange(0, 100)
    dashboard.ui.progressBar_tsi_fe_run_progress.setValue(0)
    dashboard.ui.label2_tsi_fe_run_started.setText("—")
    dashboard.ui.label2_tsi_fe_run_completed.setText("—")
    dashboard.ui.label2_tsi_fe_run_duration.setText("—")
    _tsi_fe_set_run_button_state(dashboard, running=False)
    _tsi_fe_update_artifact_download_button(dashboard)
    update_tsi_fe_run_node(dashboard)
    _tsi_fe_update_destination_state(dashboard)
    update_tsi_fe_run_start_state(dashboard)


def _tsi_fe_local_input_ready(
    dashboard: QtCore.QObject,
) -> bool:
    """
    Returns True when the current Files/Folder source has usable local input.
    """
    source = _tsi_fe_current_source(dashboard)
    folder_path = _tsi_fe_get_input_folder(dashboard)
    list_widget = dashboard.ui.listWidget_tsi_fe_input_files

    if source == "Files":
        if not folder_path or not os.path.isdir(folder_path):
            return False

        return any(
            os.path.isfile(
                os.path.join(folder_path, item.text())
            )
            for item in list_widget.selectedItems()
        )

    if source == "Folder":
        if not folder_path or not os.path.isdir(folder_path):
            return False

        return any(
            os.path.isfile(
                os.path.join(
                    folder_path,
                    list_widget.item(row).text(),
                )
            )
            for row in range(list_widget.count())
        )

    return False


def _tsi_fe_managed_input_ready(dashboard: QtCore.QObject) -> bool:
    """Return True when an Artifact and at least one manifest member are selected."""
    if _tsi_fe_current_source(dashboard) != "Artifact":
        return False
    context = getattr(dashboard, "tsi_fe_selected_input_artifact", {})
    if not isinstance(context, dict):
        return False
    artifact_id = str(context.get("artifact_id", "") or "").strip()
    return bool(artifact_id and dashboard.ui.listWidget_tsi_fe_input_files.selectedItems())


def _tsi_fe_run_readiness(dashboard: QtCore.QObject) -> tuple:
    """Return Feature Extractor readiness and a user-facing reason."""
    if bool(getattr(dashboard, "tsi_fe_running", False)):
        return True, ""
    if not _tsi_fe_selected_node_available(dashboard):
        return False, "Select an available Sensor Node."

    source = _tsi_fe_current_source(dashboard)
    if source in {"Files", "Folder"}:
        if not selected_node_is_local(dashboard):
            return False, "Files and Folder inputs require the local Sensor Node."
        if not _tsi_fe_local_input_ready(dashboard):
            return False, "Select valid local input data."
    elif source == "Artifact":
        if not _tsi_fe_managed_input_ready(dashboard):
            return False, "Select an Artifact and at least one IQ member."
    else:
        return False, "Select a supported input source."

    record = dashboard.ui.comboBox_tsi_fe_method_action.currentData()
    if not isinstance(record, dict):
        return False, "Query and select a Feature Extractor action."
    if not str(record.get("plugin", "") or "").strip() or not str(record.get("action", "") or "").strip():
        return False, "Query and select a Feature Extractor action."
    if not bool(getattr(dashboard, "tsi_fe_method_customized", False)):
        return False, "Customize the selected action parameters."

    return _tsi_fe_destination_is_available(dashboard, dashboard.ui.comboBox_tsi_fe_run_destination.currentText())


def update_tsi_fe_run_start_state(
    dashboard: QtCore.QObject,
):
    """
    Enables Start when the current source/node/action/destination combination
    is executable.

    While running, the same button remains enabled as Stop.
    """
    button = dashboard.ui.pushButton_tsi_fe_run_start_stop
    running = bool(
        getattr(dashboard, "tsi_fe_running", False)
    )

    if running:
        button.setText("Stop")
        button.setEnabled(True)
        button.setToolTip("Stop the active feature extraction operation.")
        return

    ready, reason = _tsi_fe_run_readiness(dashboard)

    button.setText("Start")
    button.setEnabled(ready)
    button.setToolTip(
        "Start feature extraction."
        if ready
        else reason
    )


def _tsi_fe_collect_method_parameters(
    dashboard: QtCore.QObject,
) -> dict:
    """
    Collects editable schema-generated parameters.

    Informational QLabel parameters are intentionally skipped.
    """
    parameters = {}

    for name, widget in (
        getattr(
            dashboard,
            "tsi_fe_method_parameter_widgets",
            {},
        )
        or {}
    ).items():
        if isinstance(widget, QtWidgets.QLabel):
            continue

        if isinstance(widget, QtWidgets.QComboBox):
            value = widget.currentData()

            if value is None:
                value = widget.currentText()

        elif isinstance(widget, QtWidgets.QCheckBox):
            value = widget.isChecked()

        elif isinstance(widget, QtWidgets.QSpinBox):
            value = widget.value()

        elif isinstance(widget, QtWidgets.QDoubleSpinBox):
            value = widget.value()

        elif isinstance(widget, QtWidgets.QLineEdit):
            value = widget.text().strip()

        elif isinstance(widget, QtWidgets.QTextEdit):
            value = widget.toPlainText().strip()

        else:
            continue

        parameters[str(name)] = value

    return parameters


def _tsi_fe_local_result_paths(dashboard: QtCore.QObject, destination: str = "", operation_id: str = "") -> tuple:
    """Return Dashboard-visible result paths for local execution."""
    destination = str(destination or dashboard.ui.comboBox_tsi_fe_run_destination.currentText() or "Local Results").strip()
    source = _tsi_fe_current_source(dashboard)

    if destination == "Artifact":
        operation_id = str(operation_id or getattr(dashboard, "tsi_fe_operation_id", "") or "").strip()
        if not operation_id:
            return "", ""
        folder = os.path.join(fissure.utils.FISSURE_ROOT, "artifacts", operation_id, "files")
    elif source == "Artifact":
        operation_id = str(operation_id or getattr(dashboard, "tsi_fe_operation_id", "") or "").strip()
        if not operation_id:
            return "", ""
        folder = os.path.join(fissure.utils.ARTIFACT_NODE_DIR, operation_id, "files")
    elif source in {"Files", "Folder"}:
        folder = _tsi_fe_get_input_folder(dashboard)
    else:
        return "", ""

    if not folder:
        return "", ""
    return os.path.join(folder, "tsi_features.json"), os.path.join(folder, "feature_extraction_report.json")


def _tsi_fe_collect_local_input_parameters(
    dashboard: QtCore.QObject,
) -> dict:
    """
    Builds Files/Folder operation inputs.

    Files:
        Only explicitly selected rows are submitted.

    Folder:
        Every visible row after extension filtering is submitted. Row
        highlighting is used only by Preview IQ and does not affect the run set.
    """
    source = _tsi_fe_current_source(dashboard)
    folder = _tsi_fe_get_input_folder(dashboard)
    list_widget = dashboard.ui.listWidget_tsi_fe_input_files
    files = []

    if source == "Files":
        items = list_widget.selectedItems()

    elif source == "Folder":
        items = [
            list_widget.item(row)
            for row in range(list_widget.count())
        ]

    else:
        items = []

    for item in items:
        filepath = os.path.join(folder, item.text())

        if os.path.isfile(filepath):
            files.append(filepath)

    return {
        "folder": folder,
        "files": files,
        "data_type": str(
            dashboard.ui.comboBox_tsi_fe_input_data_type.currentText()
            or ""
        ).strip(),
    }


def _tsi_fe_format_timestamp(epoch_value) -> str:
    if not epoch_value:
        return "—"

    return time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.localtime(float(epoch_value)),
    )


def _tsi_fe_update_duration(
    dashboard: QtCore.QObject,
    completed_at=None,
):
    started_at = getattr(
        dashboard,
        "tsi_fe_started_at",
        None,
    )

    if not started_at:
        dashboard.ui.label2_tsi_fe_run_duration.setText("—")
        return

    end_time = (
        float(completed_at)
        if completed_at is not None
        else time.time()
    )

    duration_s = max(0.0, end_time - float(started_at))

    if duration_s < 60.0:
        text = f"{duration_s:.1f} s"
    else:
        minutes = int(duration_s // 60)
        seconds = duration_s - (minutes * 60)
        text = f"{minutes}m {seconds:.1f}s"

    dashboard.ui.label2_tsi_fe_run_duration.setText(text)


def _tsi_fe_stop_result_timer(
    dashboard: QtCore.QObject,
):
    timer = getattr(
        dashboard,
        "tsi_fe_result_timer",
        None,
    )

    if timer is not None:
        timer.stop()


def _tsi_fe_finish_local_run(
    dashboard: QtCore.QObject,
    status: str = "Completed",
    progress: int = 100,
):
    """
    Finishes a local Feature Extractor run and restores the Start state.
    """
    completed_at = time.time()

    dashboard.tsi_fe_running = False
    dashboard.tsi_fe_completed_at = completed_at

    try:
        progress = int(progress)
    except Exception:
        progress = 100

    progress = max(0, min(100, progress))

    dashboard.ui.label2_tsi_fe_run_status.setText(
        str(status or "Completed")
    )

    dashboard.ui.progressBar_tsi_fe_run_progress.setRange(0, 100,)

    dashboard.ui.progressBar_tsi_fe_run_progress.setValue(progress)

    dashboard.ui.label2_tsi_fe_run_completed.setText(
        time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(completed_at),
        )
    )

    started_at = getattr(
        dashboard,
        "tsi_fe_started_at",
        None,
    )

    if started_at:
        duration_s = max(
            0.0,
            completed_at - float(started_at),
        )

        dashboard.ui.label2_tsi_fe_run_duration.setText(
            f"{duration_s:.1f} s"
        )
    else:
        dashboard.ui.label2_tsi_fe_run_duration.setText("—")

    _tsi_fe_set_run_button_state(
        dashboard,
        running=False,
    )

    _tsi_fe_stop_result_timer(dashboard)

    update_tsi_fe_run_start_state(dashboard)
    _tsi_fe_update_result_button_state(dashboard)


def _tsi_fe_poll_local_results(
    dashboard: QtCore.QObject,
):
    """
    Detects local completion, loads the detailed feature matrix, and updates
    Card 3 and the Feature Results table.

    Both canonical files must exist and have mtimes newer than the Start click.
    """
    if not bool(
        getattr(dashboard, "tsi_fe_running", False)
    ):
        _tsi_fe_stop_result_timer(dashboard)
        return

    _tsi_fe_update_duration(dashboard)

    feature_path = str(
        getattr(
            dashboard,
            "tsi_fe_expected_feature_path",
            "",
        )
        or ""
    )
    report_path = str(
        getattr(
            dashboard,
            "tsi_fe_expected_report_path",
            "",
        )
        or ""
    )
    started_at = float(
        getattr(
            dashboard,
            "tsi_fe_started_at",
            0.0,
        )
        or 0.0
    )

    if not (
        os.path.isfile(feature_path)
        and os.path.isfile(report_path)
    ):
        return

    try:
        feature_mtime = os.path.getmtime(feature_path)
        report_mtime = os.path.getmtime(report_path)
    except OSError:
        return

    if (
        feature_mtime < started_at
        or report_mtime < started_at
    ):
        return

    try:
        with open(
            feature_path,
            "r",
            encoding="utf-8",
        ) as feature_file:
            results = json.load(feature_file)

        with open(
            report_path,
            "r",
            encoding="utf-8",
        ) as report_file:
            report = json.load(report_file)

        if not isinstance(results, list):
            raise ValueError(
                "tsi_features.json must contain a list of result rows."
            )

        if not isinstance(report, dict):
            raise ValueError(
                "feature_extraction_report.json must contain an object."
            )

        operation_id = str(
            report.get("operation_id", "")
            or ""
        ).strip()

        artifact_id = str(
            report.get("artifact_id", "")
            or ""
        ).strip()

        errors = report.get("errors", []) or []

        dashboard.tsi_fe_operation_id = operation_id
        dashboard.tsi_fe_artifact_id = artifact_id
        dashboard.tsi_fe_result_report = report
        dashboard.tsi_fe_result_feature_path = feature_path
        dashboard.tsi_fe_result_report_path = report_path

        dashboard.ui.label2_tsi_fe_run_artifact_id.setText(
            artifact_id if artifact_id else "—"
        )

        _tsi_fe_populate_results_table(
            dashboard,
            results,
        )

        if errors:
            status = (
                f"Completed with {len(errors)} error"
                if len(errors) == 1
                else f"Completed with {len(errors)} errors"
            )
        else:
            status = "Completed"

        _tsi_fe_finish_local_run(
            dashboard,
            status=status,
            progress=100,
        )

        dashboard.logger.info(
            "[Feature Extractor] Results loaded: "
            f"destination={report.get('destination', '')!r}, "
            f"rows={len(results)}, "
            f"features={len(dashboard.tsi_fe_result_feature_names)}, "
            f"feature_path={feature_path!r}, "
            f"report_path={report_path!r}, "
            f"operation_id={operation_id!r}, "
            f"artifact_id={artifact_id!r}"
        )

    except Exception as e:
        dashboard.logger.error(
            "[Feature Extractor] Failed reading completed Local Results: "
            f"{e!r}"
        )

        _tsi_fe_finish_local_run(
            dashboard,
            status="Result Read Failed",
            progress=100,
        )


def _tsi_fe_start_local_result_timer(
    dashboard: QtCore.QObject,
):
    timer = getattr(
        dashboard,
        "tsi_fe_result_timer",
        None,
    )

    if timer is None:
        timer = QtCore.QTimer(dashboard)
        timer.setInterval(250)
        timer.timeout.connect(
            lambda: _tsi_fe_poll_local_results(dashboard)
        )
        dashboard.tsi_fe_result_timer = timer

    timer.start()


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_FE_RunStartStopClicked(dashboard: QtCore.QObject):
    """Start or stop Feature extraction with Artifact-first managed input/output."""
    uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not uid:
        update_tsi_fe_run_start_state(dashboard)
        return

    if bool(getattr(dashboard, "tsi_fe_running", False)):
        try:
            await dashboard.backend.tacticalNodeStop([uid])
        except Exception as error:
            dashboard.logger.error(f"[Feature Extractor] Stop request failed: {error!r}")
        _tsi_fe_finish_local_run(dashboard, status="Stopped", progress=0)
        return

    ready, reason = _tsi_fe_run_readiness(dashboard)
    if not ready:
        dashboard.ui.label2_tsi_fe_run_status.setText(reason or "Not Ready")
        update_tsi_fe_run_start_state(dashboard)
        return

    destination = str(dashboard.ui.comboBox_tsi_fe_run_destination.currentText() or "").strip()
    source = _tsi_fe_current_source(dashboard)
    record = dashboard.ui.comboBox_tsi_fe_method_action.currentData()
    if not isinstance(record, dict):
        return
    plugin_name = str(record.get("plugin", "") or "").strip()
    action_name = str(record.get("action", "") or "").strip()
    parameters = _tsi_fe_collect_method_parameters(dashboard)

    if source in {"Files", "Folder"}:
        parameters.update(_tsi_fe_collect_local_input_parameters(dashboard))
    elif source == "Artifact":
        parameters.update(_tsi_fe_collect_artifact_input_parameters(dashboard))
    else:
        dashboard.ui.label2_tsi_fe_run_status.setText("Input Source Not Implemented")
        return

    soi_context = _tsi_fe_selected_soi_context(dashboard)
    parameters["input_soi_id"] = str(soi_context.get("soi_id", "") or "").strip() if soi_context else ""
    parameters["input_soi_key"] = str(soi_context.get("soi_key", "") or "").strip() if soi_context else ""
    parameters["input_soi_frequency_mhz"] = soi_context.get("frequency_mhz") if soi_context else None
    parameters["description"] = dashboard.ui.textEdit_tsi_fe_run_description.toPlainText().strip()
    parameters["destination"] = destination
    parameters["source_id"] = uid
    parameters["node_uid"] = uid

    remote_selected = _tsi_fe_selected_node_is_remote(dashboard)
    operation_id = ""
    source_operation_id = ""
    if destination == "Artifact" or source == "Artifact":
        operation_id = str(uuid.uuid4())
        parameters["operation_id"] = operation_id
    if destination == "Artifact" and source in {"Files", "Folder"}:
        source_operation_id = str(uuid.uuid4())
        parameters["source_operation_id"] = source_operation_id

    feature_path = report_path = ""
    if not remote_selected and destination == "Local Results":
        feature_path, report_path = _tsi_fe_local_result_paths(dashboard, destination=destination, operation_id=operation_id)
        if not feature_path or not report_path:
            dashboard.ui.label2_tsi_fe_run_status.setText("Invalid Result Path")
            return

    started_at = time.time()
    dashboard.tsi_fe_result_rows = []
    dashboard.tsi_fe_result_feature_names = []
    dashboard.tsi_fe_result_report = {}
    dashboard.tsi_fe_result_feature_path = ""
    dashboard.tsi_fe_result_report_path = ""
    dashboard.tsi_fe_result_saved_to_soi = False
    dashboard.tsi_fe_auto_download_artifact_id = ""
    table = dashboard.ui.tableWidget_tsi_fe_results
    table.clear(); table.setRowCount(0); table.setColumnCount(0)
    _tsi_fe_update_result_button_state(dashboard)

    dashboard.tsi_fe_running = True
    dashboard.tsi_fe_started_at = started_at
    dashboard.tsi_fe_completed_at = None
    dashboard.tsi_fe_operation_id = operation_id
    dashboard.tsi_fe_source_operation_id = source_operation_id
    dashboard.tsi_fe_artifact_id = ""
    dashboard.tsi_fe_expected_feature_path = feature_path
    dashboard.tsi_fe_expected_report_path = report_path
    dashboard.ui.label2_tsi_fe_run_artifact_id.setText("—")
    dashboard.ui.label2_tsi_fe_run_status.setText("Starting...")
    dashboard.ui.progressBar_tsi_fe_run_progress.setRange(0, 0)
    dashboard.ui.label2_tsi_fe_run_started.setText(_tsi_fe_format_timestamp(started_at))
    dashboard.ui.label2_tsi_fe_run_completed.setText("—")
    dashboard.ui.label2_tsi_fe_run_duration.setText("0.0 s")
    _tsi_fe_set_run_button_state(dashboard, running=True)
    _tsi_fe_update_artifact_download_button(dashboard)
    update_tsi_fe_run_start_state(dashboard)

    if not remote_selected and destination == "Local Results":
        _tsi_fe_start_local_result_timer(dashboard)

    dashboard.logger.info(
        "[Feature Extractor] Starting run: uid=%r destination=%r operation_id=%r plugin=%r action=%r "
        "source=%r input_soi_id=%r managed_input=%r",
        uid, destination, operation_id, plugin_name, action_name, source,
        parameters.get("input_soi_id", ""), parameters.get("managed_input", {}),
    )

    try:
        await dashboard.backend.tacticalNodeExecute([uid], plugin_name, action_name, parameters)
        dashboard.ui.label2_tsi_fe_run_status.setText("Running")
    except Exception as error:
        dashboard.logger.error(f"[Feature Extractor] Start request failed: {error!r}")
        _tsi_fe_finish_local_run(dashboard, status="Start Failed", progress=0)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_FE_RunDownloadArtifactClicked(
    dashboard: QtCore.QObject,
):
    """
    Downloads the completed Feature Extractor analysis Artifact or opens the
    shared Dashboard cache when it has already been downloaded.
    """
    artifact_id = str(
        getattr(
            dashboard,
            "tsi_fe_artifact_id",
            "",
        )
        or ""
    ).strip()

    if not artifact_id:
        dashboard.logger.warning(
            "[Feature Extractor] No completed analysis Artifact is available."
        )
        _tsi_fe_update_artifact_download_button(
            dashboard
        )
        return

    controller = getattr(
        dashboard.backend,
        "artifact_transfer_controller",
        None,
    )

    if controller is None:
        dashboard.logger.error(
            "[Feature Extractor] Artifact transfer controller is unavailable."
        )
        return

    local_path = controller.get_local_path(
        artifact_id
    )

    if local_path:
        open_path = (
            local_path
            if os.path.isdir(local_path)
            else os.path.dirname(local_path)
        )

        try:
            subprocess.Popen([
                "xdg-open",
                open_path,
            ])
        except Exception as error:
            dashboard.logger.error(
                "[Feature Extractor] Failed opening analysis Artifact: "
                f"{error}"
            )
        return

    button = dashboard.ui.pushButton_tsi_fe_run_download_artifact
    button.setText(
        "Downloading..."
    )
    button.setEnabled(False)

    try:
        await dashboard.backend.requestDashboardArtifactDownload(
            artifact_id,
            open_when_complete=True,
        )

    except Exception as error:
        dashboard.logger.error(
            "[Feature Extractor] Failed requesting analysis Artifact: "
            f"{error}"
        )

        _tsi_fe_update_artifact_download_button(
            dashboard
        )

        
def _tsi_fe_result_text(value) -> str:
    """
    Returns a compact display string for a result-table value.
    """
    if value is None:
        return "—"

    if isinstance(value, float):
        return f"{value:.10g}"

    return str(value)


def _tsi_fe_result_feature_names(results: list) -> list:
    """
    Returns feature names in stable first-seen order across all result rows.
    """
    feature_names = []

    for result in results or []:
        if not isinstance(result, dict):
            continue

        features = result.get("features", {}) or {}

        if not isinstance(features, dict):
            continue

        for feature_name in features:
            feature_name = str(feature_name)

            if feature_name not in feature_names:
                feature_names.append(feature_name)

    return feature_names


def _tsi_fe_populate_results_table(
    dashboard: QtCore.QObject,
    results: list,
):
    """
    Populates one row per input file and one column per returned feature.

    Alignment:
      - File is left-aligned.
      - Data Type, Size, and feature values are centered.
    """
    table = dashboard.ui.tableWidget_tsi_fe_results

    results = [
        result
        for result in (results or [])
        if isinstance(result, dict)
    ]

    feature_names = _tsi_fe_result_feature_names(
        results
    )

    headers = [
        "Files",
        "Data Type",
        "Size (Bytes)",
    ] + feature_names

    sorting_enabled = table.isSortingEnabled()

    table.setSortingEnabled(False)
    table.blockSignals(True)

    try:
        table.clear()
        table.setRowCount(len(results))
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)

        for row, result in enumerate(results):
            file_item = QtWidgets.QTableWidgetItem(
                str(
                    result.get("file", "")
                    or result.get("name", "")
                    or ""
                )
            )

            file_item.setTextAlignment(
                QtCore.Qt.AlignLeft
                | QtCore.Qt.AlignVCenter
            )

            file_item.setData(
                QtCore.Qt.UserRole,
                {
                    "path": str(
                        result.get("path", "")
                        or ""
                    ),
                    "result": result,
                },
            )

            error_text = str(
                result.get("error", "")
                or ""
            ).strip()

            if error_text:
                file_item.setToolTip(error_text)

            data_type_item = QtWidgets.QTableWidgetItem(
                str(
                    result.get("data_type", "")
                    or result.get("format", "")
                    or ""
                )
            )

            data_type_item.setTextAlignment(
                QtCore.Qt.AlignCenter
            )

            size_value = result.get(
                "size_bytes",
                result.get("size"),
            )

            size_item = QtWidgets.QTableWidgetItem(
                _tsi_fe_result_text(size_value)
            )

            if (
                isinstance(size_value, (int, float))
                and not isinstance(size_value, bool)
            ):
                size_item.setData(
                    QtCore.Qt.EditRole,
                    float(size_value),
                )

            size_item.setTextAlignment(
                QtCore.Qt.AlignCenter
            )

            table.setItem(row, 0, file_item)
            table.setItem(row, 1, data_type_item)
            table.setItem(row, 2, size_item)

            features = result.get(
                "features",
                {},
            ) or {}

            if not isinstance(features, dict):
                features = {}

            for offset, feature_name in enumerate(
                feature_names
            ):
                raw_value = features.get(feature_name)

                value_item = QtWidgets.QTableWidgetItem(
                    _tsi_fe_result_text(raw_value)
                )

                if (
                    isinstance(raw_value, (int, float))
                    and not isinstance(raw_value, bool)
                ):
                    value_item.setData(
                        QtCore.Qt.EditRole,
                        float(raw_value),
                    )

                value_item.setTextAlignment(
                    QtCore.Qt.AlignCenter
                )

                table.setItem(
                    row,
                    3 + offset,
                    value_item,
                )

    finally:
        table.blockSignals(False)
        table.setSortingEnabled(sorting_enabled)

    table.resizeColumnsToContents()
    table.resizeRowsToContents()

    horizontal_header = table.horizontalHeader()
    horizontal_header.setStretchLastSection(
        table.columnCount() > 0
    )

    dashboard.tsi_fe_result_rows = results
    dashboard.tsi_fe_result_feature_names = (
        feature_names
    )

    if table.rowCount() > 0:
        table.selectRow(0)
        table.setCurrentCell(0, 0)

    _tsi_fe_update_result_button_state(dashboard)


def _tsi_fe_selected_result(
    dashboard: QtCore.QObject,
):
    """
    Returns the complete result dictionary for the selected table row.
    """
    table = dashboard.ui.tableWidget_tsi_fe_results
    row = table.currentRow()

    if row < 0:
        return None

    item = table.item(row, 0)

    if item is None:
        return None

    data = item.data(QtCore.Qt.UserRole)

    if not isinstance(data, dict):
        return None

    result = data.get("result")

    if not isinstance(result, dict):
        return None

    return result


def _tsi_fe_update_result_button_state(dashboard: QtCore.QObject):
    """Enable result actions supported by the loaded feature result set."""
    table = dashboard.ui.tableWidget_tsi_fe_results
    has_rows = table.rowCount() > 0
    selected_result = _tsi_fe_selected_result(dashboard)
    selected_path = str(selected_result.get("path", "") or "").strip() if selected_result else ""
    has_local_file = bool(selected_path and os.path.isfile(selected_path))
    has_features = bool(getattr(dashboard, "tsi_fe_result_feature_names", []))
    result_path = str(getattr(dashboard, "tsi_fe_result_report_path", "") or getattr(dashboard, "tsi_fe_result_feature_path", "") or "").strip()
    has_result_folder = bool(result_path and os.path.isdir(os.path.dirname(result_path)))
    artifact_id = str(getattr(dashboard, "tsi_fe_artifact_id", "") or "").strip()
    saved = bool(getattr(dashboard, "tsi_fe_result_saved_to_soi", False))
    soi_context = _tsi_fe_selected_soi_context(dashboard)

    dashboard.ui.pushButton_tsi_fe_results_preview.setEnabled(has_local_file)
    dashboard.ui.pushButton_tsi_fe_results_open_folder.setEnabled(has_result_folder)
    dashboard.ui.pushButton_tsi_fe_results_export_csv.setEnabled(has_rows)
    dashboard.ui.pushButton_tsi_fe_results_export_json.setEnabled(has_rows)
    dashboard.ui.pushButton_tsi_fe_results_plot_feature.setEnabled(has_rows and has_features)
    dashboard.ui.pushButton_tsi_fe_results_plot_distribution.setEnabled(has_rows and has_features)

    button = dashboard.ui.pushButton_tsi_fe_results_promote_to_soi
    if saved:
        button.setText("Saved to SOI")
        button.setEnabled(False)
        button.setToolTip("This Feature Analysis Artifact has already been saved to an SOI.")
    else:
        button.setText("Save to SOI" if soi_context else "Create SOI")
        button.setEnabled(bool(has_rows and artifact_id))
        button.setToolTip(
            "Save the Feature Analysis Artifact to the selected SOI."
            if soi_context else
            "Create an SOI and link the Feature Analysis Artifact and its source Artifact provenance."
        )
        if has_rows and not artifact_id:
            button.setToolTip("Run with Artifact output before saving Feature results to an SOI.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultSelectionChanged(
    dashboard: QtCore.QObject,
):
    _tsi_fe_update_result_button_state(dashboard)


def initialize_tsi_fe_results_controls(
    dashboard: QtCore.QObject,
):
    """
    Initializes the Feature Results table and action-button state.
    """
    dashboard.tsi_fe_result_rows = []
    dashboard.tsi_fe_result_feature_names = []
    dashboard.tsi_fe_result_report = {}

    table = dashboard.ui.tableWidget_tsi_fe_results

    table.clear()
    table.setRowCount(0)
    table.setColumnCount(0)
    table.setSortingEnabled(True)
    table.setSelectionBehavior(
        QtWidgets.QAbstractItemView.SelectRows
    )
    table.setSelectionMode(
        QtWidgets.QAbstractItemView.SingleSelection
    )
    table.setEditTriggers(
        QtWidgets.QAbstractItemView.NoEditTriggers
    )

    _tsi_fe_update_result_button_state(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsOpenFolderClicked(
    dashboard: QtCore.QObject,
):
    result_path = str(
        getattr(
            dashboard,
            "tsi_fe_result_report_path",
            "",
        )
        or getattr(
            dashboard,
            "tsi_fe_result_feature_path",
            "",
        )
        or ""
    ).strip()

    if not result_path:
        dashboard.logger.warning(
            "[Feature Extractor] No Local Results path is available."
        )
        return

    folder = os.path.dirname(result_path)

    if not os.path.isdir(folder):
        dashboard.logger.warning(
            "[Feature Extractor] Local Results folder does not exist: "
            f"{folder}"
        )
        return

    try:
        subprocess.Popen([
            "xdg-open",
            folder,
        ])
    except Exception as e:
        dashboard.logger.error(
            "[Feature Extractor] Failed to open Local Results folder: "
            f"{e}"
        )


def _tsi_fe_set_run_button_state(
    dashboard: QtCore.QObject,
    running: bool,
):
    """
    Updates the Feature Extractor Start/Stop button text and style state.
    """
    button = dashboard.ui.pushButton_tsi_fe_run_start_stop

    button.setText("Stop" if running else "Start")
    button.setProperty(
        "running",
        "true" if running else "false",
    )

    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsPreviewClicked(
    dashboard: QtCore.QObject,
):
    """
    Opens the existing IQ preview dialog for the selected Feature Results row.

    Uses the file path and data type recorded by the completed operation rather
    than the current Input card controls.
    """
    result = _tsi_fe_selected_result(
        dashboard
    )

    if not isinstance(result, dict):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Select a Feature Results row first."
        )
        _tsi_fe_update_result_button_state(
            dashboard
        )
        return

    filepath = str(
        result.get("path", "")
        or ""
    ).strip()

    if not filepath or not os.path.isfile(filepath):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "The selected result file is not available locally."
        )
        _tsi_fe_update_result_button_state(
            dashboard
        )
        return

    data_type = str(
        result.get("data_type", "")
        or ""
    ).strip()

    if not data_type:
        # Defensive fallback for older result files that did not record it.
        data_type = str(
            dashboard.ui.comboBox_tsi_fe_input_data_type.currentText()
            or ""
        ).strip()

    try:
        fissure.Dashboard.UI_Components.Qt5.previewIQ_File(
            data_type,
            filepath,
        )

    except Exception as e:
        dashboard.logger.error(
            "[Feature Extractor] Failed to preview selected result IQ file: "
            f"path={filepath!r}, data_type={data_type!r}, error={e!r}"
        )

        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to preview IQ file:\n{e}"
        )

    _tsi_fe_update_result_button_state(
        dashboard
    )


def _tsi_fe_export_default_directory(
    dashboard: QtCore.QObject,
) -> str:
    """
    Returns the completed Local Results folder when available.
    """
    result_path = str(
        getattr(
            dashboard,
            "tsi_fe_result_report_path",
            "",
        )
        or getattr(
            dashboard,
            "tsi_fe_result_feature_path",
            "",
        )
        or ""
    ).strip()

    if result_path:
        folder = os.path.dirname(result_path)

        if os.path.isdir(folder):
            return folder

    return os.path.expanduser("~")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsExportCSVClicked(
    dashboard: QtCore.QObject,
):
    """
    Exports the currently loaded detailed Feature Results to CSV.

    The export contains one row per input file and one column per feature.
    """
    results = list(
        getattr(
            dashboard,
            "tsi_fe_result_rows",
            [],
        )
        or []
    )

    feature_names = list(
        getattr(
            dashboard,
            "tsi_fe_result_feature_names",
            [],
        )
        or []
    )

    if not results:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "There are no Feature Results to export."
        )
        return

    default_path = os.path.join(
        _tsi_fe_export_default_directory(
            dashboard
        ),
        "tsi_features.csv",
    )

    filepath, selected_filter = QtWidgets.QFileDialog.getSaveFileName(
        dashboard,
        "Export Feature Results CSV",
        default_path,
        "CSV Files (*.csv)",
    )

    if not filepath:
        return

    if not filepath.lower().endswith(".csv"):
        filepath += ".csv"

    fieldnames = [
        "file",
        "path",
        "data_type",
        "size_bytes",
    ] + feature_names

    try:
        with open(
            filepath,
            "w",
            encoding="utf-8",
            newline="",
        ) as csv_file:
            writer = csv.DictWriter(
                csv_file,
                fieldnames=fieldnames,
                extrasaction="ignore",
            )

            writer.writeheader()

            for result in results:
                if not isinstance(result, dict):
                    continue

                features = result.get(
                    "features",
                    {},
                ) or {}

                if not isinstance(features, dict):
                    features = {}

                row = {
                    "file": str(
                        result.get("file", "")
                        or result.get("name", "")
                        or ""
                    ),
                    "path": str(
                        result.get("path", "")
                        or ""
                    ),
                    "data_type": str(
                        result.get("data_type", "")
                        or result.get("format", "")
                        or ""
                    ),
                    "size_bytes": result.get(
                        "size_bytes",
                        result.get("size"),
                    ),
                }

                for feature_name in feature_names:
                    row[feature_name] = features.get(
                        feature_name
                    )

                writer.writerow(row)

        dashboard.logger.info(
            "[Feature Extractor] Exported Feature Results CSV: "
            f"{filepath!r}"
        )

    except Exception as e:
        dashboard.logger.error(
            "[Feature Extractor] Failed exporting Feature Results CSV: "
            f"{e!r}"
        )

        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to export Feature Results CSV:\n{e}"
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsExportJSONClicked(
    dashboard: QtCore.QObject,
):
    """
    Exports the currently loaded report and detailed Feature Results as JSON.
    """
    results = list(
        getattr(
            dashboard,
            "tsi_fe_result_rows",
            [],
        )
        or []
    )

    report = dict(
        getattr(
            dashboard,
            "tsi_fe_result_report",
            {},
        )
        or {}
    )

    if not results:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "There are no Feature Results to export."
        )
        return

    default_path = os.path.join(
        _tsi_fe_export_default_directory(
            dashboard
        ),
        "tsi_features_export.json",
    )

    filepath, selected_filter = QtWidgets.QFileDialog.getSaveFileName(
        dashboard,
        "Export Feature Results JSON",
        default_path,
        "JSON Files (*.json)",
    )

    if not filepath:
        return

    if not filepath.lower().endswith(".json"):
        filepath += ".json"

    payload = {
        "report": report,
        "results": results,
    }

    try:
        with open(
            filepath,
            "w",
            encoding="utf-8",
        ) as json_file:
            json.dump(
                payload,
                json_file,
                indent=2,
                ensure_ascii=False,
            )

        dashboard.logger.info(
            "[Feature Extractor] Exported Feature Results JSON: "
            f"{filepath!r}"
        )

    except Exception as e:
        dashboard.logger.error(
            "[Feature Extractor] Failed exporting Feature Results JSON: "
            f"{e!r}"
        )

        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to export Feature Results JSON:\n{e}"
        )


def _tsi_fe_select_result_feature(
    dashboard: QtCore.QObject,
    title: str,
):
    """
    Prompts the user to select one extracted feature.
    """
    feature_names = list(
        getattr(
            dashboard,
            "tsi_fe_result_feature_names",
            [],
        )
        or []
    )

    if not feature_names:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "There are no extracted features available to plot."
        )
        return None

    selected_feature, ok = QtWidgets.QInputDialog.getItem(
        dashboard,
        title,
        "Feature:",
        feature_names,
        0,
        False,
    )

    if not ok:
        return None

    selected_feature = str(
        selected_feature
        or ""
    ).strip()

    return selected_feature or None


def _tsi_fe_numeric_feature_values(
    dashboard: QtCore.QObject,
    feature_name: str,
):
    """
    Returns valid numeric values and corresponding file labels for one feature.

    Missing, nonnumeric, NaN, and infinite values are skipped.
    """
    results = list(
        getattr(
            dashboard,
            "tsi_fe_result_rows",
            [],
        )
        or []
    )

    labels = []
    values = []

    for index, result in enumerate(results):
        if not isinstance(result, dict):
            continue

        features = result.get(
            "features",
            {},
        ) or {}

        if not isinstance(features, dict):
            continue

        raw_value = features.get(feature_name)

        if isinstance(raw_value, bool):
            continue

        try:
            numeric_value = float(raw_value)
        except (TypeError, ValueError):
            continue

        if not math.isfinite(numeric_value):
            continue

        label = str(
            result.get("file", "")
            or result.get("name", "")
            or f"Result {index + 1}"
        )

        labels.append(label)
        values.append(numeric_value)

    return labels, values


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsPlotFeatureClicked(
    dashboard: QtCore.QObject,
):
    """
    Plots one selected feature value across all extracted input files.
    """
    feature_name = _tsi_fe_select_result_feature(
        dashboard,
        "Plot Feature",
    )

    if not feature_name:
        return

    labels, values = _tsi_fe_numeric_feature_values(
        dashboard,
        feature_name,
    )

    if not values:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f'No numeric values are available for "{feature_name}".'
        )
        return

    try:
        figure = plt.figure(
            num=f"Feature: {feature_name}",
            clear=True,
        )

        axes = figure.add_subplot(111)

        x_values = list(range(len(values)))

        axes.plot(
            x_values,
            values,
            marker="o",
        )

        axes.set_title(
            f"{feature_name} Across Input Files"
        )
        axes.set_xlabel("Input File")
        axes.set_ylabel(feature_name)
        axes.grid(
            True,
            alpha=0.3,
        )

        axes.set_xticks(x_values)
        axes.set_xticklabels(
            labels,
            rotation=45,
            ha="right",
        )

        figure.tight_layout()
        figure.show()

    except Exception as e:
        dashboard.logger.error(
            "[Feature Extractor] Failed plotting feature: "
            f"feature={feature_name!r}, error={e!r}"
        )

        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to plot feature:\n{e}"
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsPlotDistributionClicked(
    dashboard: QtCore.QObject,
):
    """
    Plots a histogram showing the distribution of one selected feature.
    """
    feature_name = _tsi_fe_select_result_feature(
        dashboard,
        "Plot Feature Distribution",
    )

    if not feature_name:
        return

    labels, values = _tsi_fe_numeric_feature_values(
        dashboard,
        feature_name,
    )

    if not values:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f'No numeric values are available for "{feature_name}".'
        )
        return

    # Use a bounded automatic bin count that remains useful for small folders.
    bin_count = max(
        1,
        min(
            30,
            int(math.ceil(math.sqrt(len(values)))),
        ),
    )

    try:
        figure = plt.figure(
            num=f"Distribution: {feature_name}",
            clear=True,
        )

        axes = figure.add_subplot(111)

        axes.hist(
            values,
            bins=bin_count,
            edgecolor="black",
        )

        axes.set_title(
            f"{feature_name} Distribution"
        )
        axes.set_xlabel(feature_name)
        axes.set_ylabel("File Count")
        axes.grid(
            True,
            axis="y",
            alpha=0.3,
        )

        figure.tight_layout()
        figure.show()

    except Exception as e:
        dashboard.logger.error(
            "[Feature Extractor] Failed plotting feature distribution: "
            f"feature={feature_name!r}, error={e!r}"
        )

        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to plot feature distribution:\n{e}"
        )


def _tsi_fe_soi_display_text(
    soi_key: str,
    record: dict,
) -> str:
    """
    Builds a readable SOI combo-box label while keeping the full SOI record
    in combo userData.
    """
    soi_id = str(
        record.get("soi_id", "")
        or ""
    ).strip()

    frequency = record.get("frequency_mhz")

    try:
        frequency_text = (
            f"{float(frequency):.6f} MHz"
            if frequency not in [None, "", "None"]
            else ""
        )
    except Exception:
        frequency_text = str(
            frequency
            or ""
        ).strip()

    modulation = str(
        record.get("modulation", "")
        or record.get("modulation_type", "")
        or ""
    ).strip()

    classification = str(
        record.get("model_classification", "")
        or record.get("database_classification", "")
        or ""
    ).strip()

    status = str(
        record.get("status", "")
        or ""
    ).strip()

    parts = [
        value
        for value in (
            frequency_text,
            modulation,
            classification,
            status,
        )
        if value
    ]

    label = " | ".join(parts)

    if not label:
        label = soi_id or soi_key

    if soi_id and soi_id not in label:
        label = f"{label} | {soi_id}"

    return label


def _tsi_fe_selected_soi_context(dashboard: QtCore.QObject) -> dict:
    """Return the optional SOI context selected beside Input Source."""
    context = dashboard.ui.comboBox_tsi_fe_input_soi.currentData()
    if not isinstance(context, dict):
        return {}
    soi_id = str(context.get("soi_id", "") or "").strip()
    soi_key = str(context.get("soi_key", "") or "").strip()
    node_uid = str(context.get("node_uid", "") or "").strip()
    selected_node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not soi_id or not soi_key:
        return {}
    if selected_node_uid and node_uid and node_uid != selected_node_uid:
        return {}
    return context


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputArtifactChanged(
    dashboard: QtCore.QObject,
):
    """
    Stores the selected Artifact context and resolves its local files.
    """
    context = (
        dashboard.ui.comboBox_tsi_fe_input_artifact
        .currentData()
    )

    if not isinstance(context, dict):
        context = {}

    dashboard.tsi_fe_selected_input_artifact = (
        dict(context)
    )

    if context:
        _tsi_fe_populate_artifact_file_list(
            dashboard,
            context,
        )

    else:
        dashboard.tsi_fe_selected_input_artifact_files = []

        dashboard.ui.listWidget_tsi_fe_input_files.clear()

        _tsi_fe_update_input_ribbon(
            dashboard
        )
        _tsi_fe_update_preview_gate(
            dashboard
        )
        update_tsi_fe_run_start_state(
            dashboard
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputSOIChanged(dashboard: QtCore.QObject):
    """Apply optional SOI context and refilter Artifact input when active."""
    context = _tsi_fe_selected_soi_context(dashboard)
    dashboard.tsi_fe_selected_input_soi = dict(context) if context else {}
    if _tsi_fe_current_source(dashboard) == "Artifact":
        refresh_tsi_fe_input_artifacts(dashboard)
    _tsi_fe_update_result_button_state(dashboard)
    update_tsi_fe_run_start_state(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_FE_InputArtifactRefreshClicked(
    dashboard: QtCore.QObject,
):
    """Request current Artifact metadata from HIPRFISR for the selected node."""
    node_uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    if not node_uid:
        dashboard.logger.warning(
            "[Feature Extractor] Select a Sensor Node before refreshing Artifacts."
        )
        return

    refresh_button = getattr(
        dashboard.ui,
        "pushButton_tsi_fe_input_artifact_refresh",
        None,
    )

    if refresh_button is not None:
        refresh_button.setEnabled(False)

    try:
        await dashboard.backend.tacticalNodeArtifactsRefresh(
            node_uid
        )
    except Exception as error:
        dashboard.logger.error(
            "[Feature Extractor] Failed requesting Artifact refresh: "
            f"{error}"
        )
    finally:
        if refresh_button is not None:
            refresh_button.setEnabled(True)


def _tsi_fe_artifact_id(
    artifact_key,
    record: dict,
) -> str:
    """
    Returns the best available artifact ID from a Tactical artifact record.
    """
    if not isinstance(record, dict):
        return str(artifact_key or "").strip()

    return str(
        record.get("artifact_id")
        or record.get("id")
        or artifact_key
        or ""
    ).strip()


def _tsi_fe_artifact_node_uid(
    record: dict,
) -> str:
    """
    Returns the owning Sensor Node UID from an artifact record.
    """
    if not isinstance(record, dict):
        return ""

    return str(
        record.get("node_uid")
        or record.get("source_id")
        or ""
    ).strip()


def _tsi_fe_artifact_file_is_iq(file_record: dict) -> bool:
    """Return True for directly registered IQ Artifact members."""
    if not isinstance(file_record, dict):
        return False
    metadata = file_record.get("metadata", {})
    metadata = metadata if isinstance(metadata, dict) else {}
    role = str(file_record.get("role") or metadata.get("role") or "").strip().lower()
    if role in {"iq_data", "sigmf_data", "iq_burst", "source_iq", "source_iq_v1"}:
        return True
    if role in {"bundle", "sigmf_metadata", "operation_metadata", "feature_results", "feature_report", "classification"}:
        return False
    name = str(file_record.get("name") or file_record.get("relative_path") or "").strip().lower()
    return name.endswith((".iq", ".dat", ".bin", ".raw", ".sigmf-data"))

def _tsi_fe_artifact_display_text(
    artifact_id: str,
    record: dict,
) -> str:
    """
    Builds a readable Artifact combo label.
    """
    name = str(
        record.get("name")
        or record.get("description")
        or record.get("artifact_name")
        or "Artifact"
    ).strip()

    operation_id = str(
        record.get("operation_id")
        or ""
    ).strip()

    time_value = str(
        record.get("time")
        or ""
    ).strip()

    parts = [
        name,
        artifact_id,
    ]

    if operation_id:
        parts.append(
            f"op {operation_id}"
        )

    if time_value:
        parts.append(
            time_value
        )

    return " | ".join(parts)


def _tsi_fe_artifact_file_records(dashboard: QtCore.QObject, artifact_id: str, record: dict) -> list:
    """Build selectable Artifact members from the canonical manifest, adding cache paths when available."""
    if not isinstance(record, dict):
        return []
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    local_files = controller.get_local_files(artifact_id) if controller is not None else {}
    operation_id = str(record.get("operation_id", "") or "").strip()
    output = []

    for file_record in record.get("files", []) or []:
        if not _tsi_fe_artifact_file_is_iq(file_record):
            continue
        file_id = str(file_record.get("id", "") or "").strip()
        name = str(file_record.get("name") or file_record.get("relative_path") or "").strip()
        if not file_id or not name:
            continue
        metadata = file_record.get("metadata", {}) if isinstance(file_record.get("metadata"), dict) else {}
        output.append({
            "name": name,
            "path": str(local_files.get(file_id, "") or "").strip(),
            "file_id": file_id,
            "artifact_id": artifact_id,
            "operation_id": operation_id,
            "role": str(file_record.get("role") or metadata.get("role") or "").strip(),
            "sha256": str(file_record.get("sha256", "") or "").strip(),
            "size_bytes": file_record.get("size", file_record.get("size_bytes", 0)),
            "source_type": "Artifact",
            "record": dict(file_record),
        })

    output.sort(key=lambda item: (item["name"].lower(), item["file_id"]))
    return output


def _tsi_fe_filter_managed_file_records(
    dashboard: QtCore.QObject,
    file_records: list,
) -> list:
    """
    Applies the existing All / Custom extension controls to Artifact or SOI
    file records.
    """
    use_all = (
        dashboard.ui.radioButton_tsi_fe_input_extensions_all
        .isChecked()
    )

    extension = (
        dashboard.ui.textEdit_tsi_fe_input_extensions
        .toPlainText()
        .strip()
    )

    if use_all:
        return list(
            file_records
            or []
        )

    if not extension:
        return []

    extension_lower = extension.lower()

    return [
        record
        for record in (
            file_records
            or []
        )
        if str(
            record.get("name", "")
            or ""
        ).lower().endswith(
            extension_lower
        )
    ]


def _tsi_fe_populate_artifact_file_list(
    dashboard: QtCore.QObject,
    artifact_context: dict,
):
    """
    Resolve all locally cached files for the selected Artifact and render them
    using the current extension filter.
    """
    artifact_id = str(
        artifact_context.get(
            "artifact_id",
            "",
        )
        or ""
    ).strip()

    record = artifact_context.get(
        "record",
        {},
    )

    all_files = _tsi_fe_artifact_file_records(
        dashboard,
        artifact_id,
        record,
    )

    dashboard.tsi_fe_selected_input_artifact_files = all_files

    _tsi_fe_render_managed_file_list(
        dashboard,
        all_files,
    )


def _tsi_fe_render_managed_file_list(dashboard: QtCore.QObject, file_records: list):
    """Render filtered Artifact members and select all without collapsing ExtendedSelection."""
    list_widget = dashboard.ui.listWidget_tsi_fe_input_files
    filtered_files = _tsi_fe_filter_managed_file_records(dashboard, file_records)
    list_widget.blockSignals(True)
    list_widget.clear()
    list_widget.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)

    for file_record in filtered_files:
        item = QtWidgets.QListWidgetItem(str(file_record.get("name", "") or ""))
        item.setData(QtCore.Qt.UserRole, file_record)
        tooltip = str(file_record.get("path", "") or "").strip()
        if not tooltip:
            tooltip = f"Artifact {file_record.get('artifact_id', '')} | {file_record.get('role', '')}"
        item.setToolTip(tooltip)
        list_widget.addItem(item)
        item.setSelected(True)

    if list_widget.count() > 0:
        list_widget.setCurrentItem(list_widget.item(0), QtCore.QItemSelectionModel.NoUpdate)

    list_widget.blockSignals(False)
    _tsi_fe_update_input_ribbon(dashboard)
    _tsi_fe_update_preview_gate(dashboard)
    update_tsi_fe_run_start_state(dashboard)


def refresh_tsi_fe_input_artifacts(dashboard: QtCore.QObject):
    """Populate Artifacts for the selected node, optionally filtered by SOI context."""
    combo = dashboard.ui.comboBox_tsi_fe_input_artifact
    previous = combo.currentData()
    previous_id = str(previous.get("artifact_id", "") or "").strip() if isinstance(previous, dict) else ""
    selected_node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    soi_context = _tsi_fe_selected_soi_context(dashboard)
    allowed_ids = None
    if soi_context:
        allowed_ids = set(_tsi_fe_soi_source_artifact_ids(soi_context.get("record", {})))

    tactical_artifacts = getattr(dashboard, "tactical_artifacts", {}) or {}
    iterable = tactical_artifacts.items() if isinstance(tactical_artifacts, dict) else enumerate(tactical_artifacts) if isinstance(tactical_artifacts, list) else []
    rows = []
    for artifact_key, record in iterable:
        if not isinstance(record, dict):
            continue
        artifact_id = _tsi_fe_artifact_id(artifact_key, record)
        if not artifact_id or (allowed_ids is not None and artifact_id not in allowed_ids):
            continue
        record_node_uid = _tsi_fe_artifact_node_uid(record)
        if selected_node_uid and record_node_uid and record_node_uid != selected_node_uid:
            continue
        context = {"artifact_id": artifact_id, "node_uid": record_node_uid, "record": dict(record)}
        rows.append((_tsi_fe_artifact_display_text(artifact_id, record), context))

    rows.sort(key=lambda row: row[0].lower())
    combo.blockSignals(True)
    combo.clear()
    combo.addItem("Select Artifact...", None)
    restored_index = -1
    for display_text, context in rows:
        combo.addItem(display_text, context)
        if previous_id and context["artifact_id"] == previous_id:
            restored_index = combo.count() - 1
    if restored_index >= 0:
        combo.setCurrentIndex(restored_index)
    elif len(rows) == 1:
        combo.setCurrentIndex(1)
    else:
        combo.setCurrentIndex(0)
    combo.blockSignals(False)

    dashboard.tsi_fe_input_artifacts = [context for _display_text, context in rows]
    dashboard.ui.pushButton_tsi_fe_input_artifact_refresh.setToolTip(
        f"Refresh artifacts for {selected_node_uid}" if selected_node_uid else "Select a Sensor Node before refreshing artifacts"
    )
    _slotTSI_FE_InputArtifactChanged(dashboard)


def _tsi_fe_collect_artifact_input_parameters(dashboard: QtCore.QObject) -> dict:
    """Build one identifier-only managed Artifact request for local or remote execution."""
    context = getattr(dashboard, "tsi_fe_selected_input_artifact", {})
    context = context if isinstance(context, dict) else {}
    artifact_id = str(context.get("artifact_id", "") or "").strip()
    record = context.get("record", {}) if isinstance(context.get("record"), dict) else {}
    operation_id = str(record.get("operation_id") or (record.get("metadata", {}) if isinstance(record.get("metadata"), dict) else {}).get("operation_id") or "").strip()
    selected_files = _tsi_fe_selected_managed_file_records(dashboard)
    soi_context = _tsi_fe_selected_soi_context(dashboard)
    soi_id = str(soi_context.get("soi_id", "") or "").strip() if soi_context else ""
    soi_key = str(soi_context.get("soi_key", "") or "").strip() if soi_context else ""

    return {
        "input_source": "Artifact",
        "managed_input": {
            "source": "Artifact",
            "artifact_ids": [artifact_id] if artifact_id else [],
            "input_soi_id": soi_id,
            "input_soi_key": soi_key,
            "artifacts": [{
                "artifact_id": artifact_id,
                "operation_id": operation_id,
                "selected_files": [row for row in selected_files if not row.get("artifact_id") or row.get("artifact_id") == artifact_id],
            }],
        },
        "artifact_id": artifact_id,
        "source_artifact_id": artifact_id,
        "source_artifact_ids": [artifact_id] if artifact_id else [],
        "input_soi_id": soi_id,
        "input_soi_key": soi_key,
        "input_soi_frequency_mhz": soi_context.get("frequency_mhz") if soi_context else None,
        "folder": "",
        "files": [],
        "data_type": str(dashboard.ui.comboBox_tsi_fe_input_data_type.currentText() or "").strip(),
    }


def _tsi_fe_soi_source_artifact_ids(
    record: dict,
) -> list:
    """
    Returns Artifact IDs that may contain source material for one SOI.

    SOIs may contain:
        - explicitly typed source_iq links
        - evidence/capture bundles containing IQ plus metadata
        - legacy links with no role
        - analysis-result links that must not become FE inputs

    The authoritative relationship is artifact_links. Legacy scalar fields are
    used only when no usable Artifact links are available.
    """
    if not isinstance(record, dict):
        return []

    artifact_ids = []

    def _append(value):
        artifact_id = str(
            value
            or ""
        ).strip()

        if (
            artifact_id
            and artifact_id not in artifact_ids
        ):
            artifact_ids.append(
                artifact_id
            )

    def _is_analysis_role(role: str) -> bool:
        role = str(
            role
            or ""
        ).strip().lower()

        if not role:
            return False

        if "analysis" in role:
            return True

        return role in {
            "feature_report",
            "feature_results",
            "classification",
            "classification_report",
            "model_report",
            "tsi_features",
        }

    summary = record.get(
        "summary"
    )

    candidate_containers = [
        record,
        summary if isinstance(summary, dict) else {},
    ]

    found_source_link = False

    for container in candidate_containers:
        links = container.get(
            "artifact_links",
            [],
        )

        if not isinstance(links, list):
            continue

        for link in links:
            if not isinstance(link, dict):
                continue

            role = str(
                link.get("role")
                or ""
            ).strip().lower()

            if _is_analysis_role(role):
                continue

            artifact_id = str(
                link.get("artifact_id")
                or ""
            ).strip()

            if not artifact_id:
                continue

            _append(
                artifact_id
            )
            found_source_link = True

    if found_source_link:
        return artifact_ids

    for container in candidate_containers:
        _append(
            container.get(
                "source_artifact_id"
            )
        )

    if artifact_ids:
        return artifact_ids

    for container in candidate_containers:
        values = container.get(
            "artifact_ids",
            [],
        )

        if isinstance(values, list):
            for value in values:
                _append(
                    value
                )

    if artifact_ids:
        return artifact_ids

    for container in candidate_containers:
        _append(
            container.get(
                "artifact_id"
            )
        )

    return artifact_ids


def _tsi_fe_find_tactical_artifact(
    dashboard: QtCore.QObject,
    artifact_id: str,
) -> dict:
    """
    Finds one artifact record in dashboard.tactical_artifacts.
    """
    artifact_id = str(
        artifact_id
        or ""
    ).strip()

    if not artifact_id:
        return {}

    tactical_artifacts = (
        getattr(
            dashboard,
            "tactical_artifacts",
            {},
        )
        or {}
    )

    if isinstance(
        tactical_artifacts,
        dict,
    ):
        direct_record = tactical_artifacts.get(
            artifact_id
        )

        if isinstance(direct_record, dict):
            return dict(direct_record)

        iterable = tactical_artifacts.items()

    elif isinstance(
        tactical_artifacts,
        list,
    ):
        iterable = enumerate(
            tactical_artifacts
        )

    else:
        iterable = []

    for artifact_key, record in iterable:
        if not isinstance(record, dict):
            continue

        candidate_id = _tsi_fe_artifact_id(
            artifact_key,
            record,
        )

        if candidate_id == artifact_id:
            return dict(record)

    return {}


def refresh_tsi_fe_input_sois(dashboard: QtCore.QObject):
    """Populate optional SOI context for the selected Sensor Node."""
    combo = dashboard.ui.comboBox_tsi_fe_input_soi
    previous = combo.currentData()
    previous_key = str(previous.get("soi_key", "") or "").strip() if isinstance(previous, dict) else ""
    selected_node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    tactical_sois = getattr(dashboard, "tactical_sois", {}) or {}
    iterable = tactical_sois.items() if isinstance(tactical_sois, dict) else enumerate(tactical_sois) if isinstance(tactical_sois, list) else []
    rows = []

    for soi_key, record in iterable:
        if not isinstance(record, dict):
            continue
        record_node_uid = str(record.get("node_uid") or "").strip()
        if selected_node_uid and record_node_uid and record_node_uid != selected_node_uid:
            continue
        soi_id = str(record.get("soi_id") or "").strip()
        if not soi_id:
            continue
        context = {
            "soi_key": str(record.get("soi_key") or soi_key or "").strip(),
            "soi_id": soi_id,
            "node_uid": record_node_uid,
            "frequency_mhz": record.get("frequency_mhz"),
            "record": dict(record),
        }
        rows.append((_tsi_fe_soi_display_text(context["soi_key"], record), context))

    rows.sort(key=lambda row: row[0].lower())
    combo.blockSignals(True)
    combo.clear()
    combo.addItem("Manual / No SOI", None)
    restored_index = 0
    for display_text, context in rows:
        combo.addItem(display_text, context)
        if previous_key and context["soi_key"] == previous_key:
            restored_index = combo.count() - 1
    combo.setCurrentIndex(restored_index)
    combo.blockSignals(False)
    dashboard.tsi_fe_input_sois = [context for _display_text, context in rows]
    dashboard.tsi_fe_selected_input_soi = _tsi_fe_selected_soi_context(dashboard)


def _tsi_fe_set_combo_item_enabled(
    combo: QtWidgets.QComboBox,
    item_text: str,
    enabled: bool,
    tooltip: str = "",
):
    """Enable or disable one visible QComboBox item by text."""
    index = combo.findText(item_text)
    if index < 0:
        return

    model = combo.model()
    item = model.item(index) if hasattr(model, "item") else None
    if item is None:
        return

    item.setEnabled(bool(enabled))
    item.setToolTip(tooltip or "")


def _tsi_fe_selected_node_is_remote(
    dashboard: QtCore.QObject,
) -> bool:
    """Return True when an available non-local Sensor Node is selected."""
    return bool(
        _tsi_fe_selected_node_available(dashboard)
        and not selected_node_is_local(dashboard)
    )


def update_tsi_fe_locality_controls(dashboard: QtCore.QObject):
    """Apply local/remote source and destination gating."""
    remote_selected = _tsi_fe_selected_node_is_remote(dashboard)
    source_combo = dashboard.ui.comboBox_tsi_fe_input_source
    tooltip = "Files and Folder inputs are available only when the local Sensor Node is selected."
    for source_name in ("Files", "Folder"):
        _tsi_fe_set_combo_item_enabled(source_combo, source_name, not remote_selected, tooltip if remote_selected else "")
    _tsi_fe_set_combo_item_enabled(source_combo, "Artifact", True)

    source_changed = False
    if remote_selected and source_combo.currentText() in {"Files", "Folder"}:
        index = source_combo.findText("Artifact")
        if index >= 0:
            source_combo.blockSignals(True)
            source_combo.setCurrentIndex(index)
            source_combo.blockSignals(False)
            source_changed = True

    destination_combo = dashboard.ui.comboBox_tsi_fe_run_destination
    _tsi_fe_set_combo_item_enabled(
        destination_combo, "Local Results", not remote_selected,
        "Local Results are available only when the local Sensor Node is selected." if remote_selected else ""
    )
    _tsi_fe_set_combo_item_enabled(destination_combo, "Artifact", True)

    destination_changed = False
    if remote_selected and destination_combo.currentText() == "Local Results":
        index = destination_combo.findText("Artifact")
        if index >= 0:
            destination_combo.blockSignals(True)
            destination_combo.setCurrentIndex(index)
            destination_combo.blockSignals(False)
            destination_changed = True

    for widget_name in ("pushButton_tsi_fe_input_folder", "pushButton_tsi_fe_input_refresh", "textEdit_tsi_fe_file_path"):
        widget = getattr(dashboard.ui, widget_name, None)
        if widget is not None:
            widget.setEnabled(not remote_selected)

    if source_changed:
        _slotTSI_FE_InputSourceChanged(dashboard)
    if destination_changed:
        _slotTSI_FE_RunDestinationChanged(dashboard)
    _tsi_fe_update_preview_gate(dashboard)
    _tsi_fe_update_destination_state(dashboard)
    update_tsi_fe_run_start_state(dashboard)


def _tsi_fe_selected_managed_file_records(
    dashboard: QtCore.QObject,
) -> list:
    """
    Returns normalized metadata for the selected Artifact/SOI file-list rows.

    Local cache paths are deliberately excluded. The returned dictionaries are
    safe to send as a small remote control message.
    """
    output = []

    for item in (
        dashboard.ui.listWidget_tsi_fe_input_files
        .selectedItems()
    ):
        item_data = item.data(
            QtCore.Qt.UserRole
        )

        if not isinstance(item_data, dict):
            item_data = {}

        file_record = item_data.get(
            "record",
            {},
        )

        if not isinstance(file_record, dict):
            file_record = {}

        name = str(
            item_data.get("name")
            or file_record.get("name")
            or file_record.get("filename")
            or file_record.get("file_name")
            or item.text()
            or ""
        ).strip()

        artifact_id = str(
            item_data.get("artifact_id")
            or file_record.get("artifact_id")
            or ""
        ).strip()

        operation_id = str(
            item_data.get("operation_id")
            or file_record.get("operation_id")
            or ""
        ).strip()

        role = str(
            item_data.get("role")
            or file_record.get("role")
            or ""
        ).strip()

        sha256 = str(
            item_data.get("sha256")
            or file_record.get("sha256")
            or ""
        ).strip()

        size_bytes = (
            item_data.get("size_bytes")
            if item_data.get("size_bytes") is not None
            else file_record.get("size_bytes")
        )

        if not name:
            continue

        output.append(
            {
                "name": name,
                "artifact_id": artifact_id,
                "operation_id": operation_id,
                "role": role,
                "sha256": sha256,
                "size_bytes": size_bytes,
            }
        )

    return output


def _tsi_fe_optional_new_soi_frequency(dashboard: QtCore.QObject):
    """Prompt for optional MHz when creating an SOI from Feature results."""
    report = getattr(dashboard, "tsi_fe_result_report", {}) or {}
    value = report.get("input_soi_frequency_mhz")
    if value not in [None, "", "None"]:
        try:
            return float(value)
        except Exception:
            pass
    text, ok = QtWidgets.QInputDialog.getText(
        dashboard,
        "Create SOI",
        "Frequency (MHz), or leave blank if unknown:",
        QtWidgets.QLineEdit.Normal,
        "",
    )
    if not ok:
        return "cancelled"
    text = str(text or "").strip()
    if not text:
        return None
    try:
        return float(text)
    except Exception:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Invalid frequency value:\n{text}")
        return "cancelled"


def _slotTSI_FE_ResultsPromoteToSoiClicked(dashboard: QtCore.QObject):
    """Save the current Feature Analysis Artifact to an existing or new SOI."""
    artifact_id = str(getattr(dashboard, "tsi_fe_artifact_id", "") or "").strip()
    report = getattr(dashboard, "tsi_fe_result_report", {}) or {}
    if not artifact_id or dashboard.ui.tableWidget_tsi_fe_results.rowCount() <= 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Run Feature extraction with Artifact output first.")
        return

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select a Sensor Node first.")
        return

    context = _tsi_fe_selected_soi_context(dashboard)
    existing = bool(context)
    soi_id = str(context.get("soi_id", "") or "").strip() if existing else str(uuid.uuid4())
    frequency_mhz = None if existing else _tsi_fe_optional_new_soi_frequency(dashboard)
    if frequency_mhz == "cancelled":
        return

    operation_id = str(report.get("operation_id", "") or getattr(dashboard, "tsi_fe_operation_id", "") or "").strip()
    source_artifact_ids = report.get("source_artifact_ids", [])
    if not isinstance(source_artifact_ids, list):
        source_artifact_ids = [source_artifact_ids]
    source_artifact_ids = [
        str(value or "").strip()
        for value in source_artifact_ids
        if str(value or "").strip()
    ]

    existing_artifact_ids = set()
    if existing:
        record = context.get("record", {}) if isinstance(context.get("record"), dict) else {}
        containers = [record]
        summary_record = record.get("summary")
        if isinstance(summary_record, dict):
            containers.append(summary_record)
        for container in containers:
            links = container.get("artifact_links", [])
            if not isinstance(links, list):
                continue
            for link in links:
                if not isinstance(link, dict):
                    continue
                linked_id = str(link.get("artifact_id", "") or "").strip()
                if linked_id:
                    existing_artifact_ids.add(linked_id)

    artifact_links = [
        {"artifact_id": source_id, "role": "source_iq", "source": "tsi_feature_extractor"}
        for source_id in source_artifact_ids
        if source_id not in existing_artifact_ids and source_id != artifact_id
    ]
    artifact_links.append({
        "artifact_id": artifact_id,
        "operation_id": operation_id,
        "role": "feature_analysis",
        "source": "tsi_feature_extractor",
        "source_artifact_ids": source_artifact_ids,
    })

    history_entry = {
        "analysis_id": f"feature_extractor:{operation_id}" if operation_id else f"feature_extractor:{uuid.uuid4()}",
        "stage": "feature_extractor",
        "source": "tsi_feature_extractor",
        "operation_id": operation_id,
        "artifact_id": artifact_id,
        "source_artifact_ids": source_artifact_ids,
        "profile": report.get("profile", ""),
        "preset": report.get("preset", ""),
        "feature_count": report.get("feature_count", 0),
        "result_count": report.get("result_count", 0),
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    summary = {"artifact_links": artifact_links, "analysis_history": [history_entry]}
    if not existing:
        summary.update({
            "stage": "feature_extractor_promoted",
            "stage_order": 60,
            "source": "tsi_feature_extractor",
            "operation_id": operation_id,
            "artifact_id": artifact_id,
            "source_artifact_ids": source_artifact_ids,
            "description": "Feature extraction results promoted to SOI",
            "features": {},
            "classification": {},
            "protocol": {},
            "model_classification": "",
            "model_confidence": None,
        })

    button = dashboard.ui.pushButton_tsi_fe_results_promote_to_soi
    button.setEnabled(False)
    dashboard.ui.label2_tsi_fe_run_status.setText("Saving to SOI..." if existing else "Creating SOI...")
    task = asyncio.ensure_future(
        dashboard.backend.tacticalConditionerPromoteToSoi(
            node_uid=node_uid,
            soi_id=soi_id,
            frequency_mhz=frequency_mhz,
            status="" if existing else "EVIDENCE_READY",
            operation_id=operation_id,
            artifact_id=artifact_id,
            summary=summary,
        )
    )

    def _done(future):
        try:
            future.result()
            dashboard.tsi_fe_result_saved_to_soi = True
            dashboard.ui.label2_tsi_fe_run_status.setText(
                f"Saved Feature results to SOI: {soi_id}" if existing else f"Created SOI from Feature results: {soi_id}"
            )
        except Exception as error:
            dashboard.logger.error(f"[Feature Extractor] Failed saving results to SOI: {error}")
            fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Failed to save Feature results to SOI:\n{error}")
        finally:
            _tsi_fe_update_result_button_state(dashboard)

    task.add_done_callback(_done)

def _tsi_fe_cached_artifact_result_paths(dashboard: QtCore.QObject, artifact_id: str) -> tuple:
    """Return cached Feature JSON/report paths for one completed analysis Artifact."""
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    if controller is None:
        return "", ""
    local_files = controller.get_local_files(artifact_id) or {}
    feature_path = report_path = ""
    for path in local_files.values():
        name = os.path.basename(str(path or ""))
        if name == "tsi_features.json" and os.path.isfile(path):
            feature_path = path
        elif name == "feature_extraction_report.json" and os.path.isfile(path):
            report_path = path
    return feature_path, report_path

def _tsi_fe_load_cached_artifact_results(dashboard: QtCore.QObject, artifact_id: str) -> bool:
    """Load verified cached Feature Artifact files into the result table."""
    feature_path, report_path = _tsi_fe_cached_artifact_result_paths(dashboard, artifact_id)
    if not feature_path or not report_path:
        return False
    try:
        with open(feature_path, "r", encoding="utf-8") as handle:
            results = json.load(handle)
        with open(report_path, "r", encoding="utf-8") as handle:
            report = json.load(handle)
        if not isinstance(results, list) or not isinstance(report, dict):
            raise ValueError("Feature Artifact result files have an unexpected format.")
        dashboard.tsi_fe_artifact_id = artifact_id
        dashboard.tsi_fe_result_report = report
        dashboard.tsi_fe_result_feature_path = feature_path
        dashboard.tsi_fe_result_report_path = report_path
        dashboard.tsi_fe_result_saved_to_soi = False
        dashboard.ui.label2_tsi_fe_run_artifact_id.setText(artifact_id or "—")
        _tsi_fe_populate_results_table(dashboard, results)
        errors = report.get("errors", []) or []
        status = f"Completed with {len(errors)} error" if len(errors) == 1 else f"Completed with {len(errors)} errors" if errors else "Completed — Analysis Artifact"
        dashboard.ui.label2_tsi_fe_run_status.setText(status)
        _tsi_fe_update_artifact_download_button(dashboard)
        _tsi_fe_update_result_button_state(dashboard)
        return True
    except Exception as error:
        dashboard.logger.error(f"[Feature Extractor] Failed loading cached analysis Artifact: {error!r}")
        dashboard.ui.label2_tsi_fe_run_status.setText("Artifact Result Read Failed")
        return False


def handle_tsi_fe_artifact_download_complete(dashboard: QtCore.QObject, artifact_id: str):
    """Load a Feature Analysis Artifact after the verified Dashboard cache commit."""
    expected = str(getattr(dashboard, "tsi_fe_auto_download_artifact_id", "") or "").strip()
    artifact_id = str(artifact_id or "").strip()
    if not expected or expected != artifact_id:
        return
    dashboard.tsi_fe_auto_download_artifact_id = ""
    if not _tsi_fe_load_cached_artifact_results(dashboard, artifact_id):
        dashboard.ui.label2_tsi_fe_run_status.setText("Completed — Artifact Download Failed")
    _tsi_fe_update_artifact_download_button(dashboard)


def handle_tsi_fe_artifact_metadata(dashboard: QtCore.QObject, node_uid: str = "", artifacts=None):
    """Complete Artifact output, auto-cache its small JSON payload, and refresh Artifact input."""
    artifacts = artifacts or []
    if isinstance(artifacts, dict):
        artifacts = list(artifacts.values())
    if not isinstance(artifacts, list):
        artifacts = []

    if _tsi_fe_current_source(dashboard) == "Artifact":
        refresh_tsi_fe_input_artifacts(dashboard)
    if not bool(getattr(dashboard, "tsi_fe_running", False)):
        return

    expected_operation_id = str(getattr(dashboard, "tsi_fe_operation_id", "") or "").strip()
    if not expected_operation_id:
        return
    selected_node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    callback_node_uid = str(node_uid or "").strip()
    if selected_node_uid and callback_node_uid and callback_node_uid != selected_node_uid:
        return
    if str(dashboard.ui.comboBox_tsi_fe_run_destination.currentText() or "").strip() != "Artifact":
        return

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue
        metadata = artifact.get("metadata", {}) if isinstance(artifact.get("metadata"), dict) else {}
        workflow = str(metadata.get("workflow", "") or "").strip().lower()
        operation_id = str(artifact.get("operation_id") or metadata.get("operation_id") or "").strip()
        if workflow != "feature_extractor" or operation_id != expected_operation_id:
            continue

        artifact_id = str(artifact.get("artifact_id") or artifact.get("id") or "").strip()
        if not artifact_id:
            continue
        dashboard.tsi_fe_artifact_id = artifact_id
        dashboard.tsi_fe_result_report = dict(metadata)
        dashboard.tsi_fe_result_feature_path = ""
        dashboard.tsi_fe_result_report_path = ""
        dashboard.tsi_fe_auto_download_artifact_id = artifact_id
        dashboard.ui.label2_tsi_fe_run_artifact_id.setText(artifact_id)
        _tsi_fe_finish_local_run(dashboard, status="Downloading Feature Results...", progress=100)
        _tsi_fe_update_artifact_download_button(dashboard)

        if _tsi_fe_load_cached_artifact_results(dashboard, artifact_id):
            dashboard.tsi_fe_auto_download_artifact_id = ""
            return

        async def _request():
            try:
                await dashboard.backend.requestDashboardArtifactDownload(artifact_id, open_when_complete=False)
            except Exception as error:
                dashboard.logger.error(f"[Feature Extractor] Automatic Artifact download failed: {error!r}")
                dashboard.tsi_fe_auto_download_artifact_id = ""
                dashboard.ui.label2_tsi_fe_run_status.setText("Completed — Artifact Download Failed")
                _tsi_fe_update_artifact_download_button(dashboard)

        asyncio.ensure_future(_request())
        dashboard.logger.info(
            "[Feature Extractor] Analysis Artifact registered; downloading small result payload: "
            f"artifact_id={artifact_id!r}, operation_id={operation_id!r}, node_uid={callback_node_uid!r}"
        )
        return





__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value)
    and value.__module__ == __name__
]