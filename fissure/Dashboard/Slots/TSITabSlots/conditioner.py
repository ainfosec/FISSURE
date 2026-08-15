from PyQt5 import QtCore, QtWidgets, QtGui

import asyncio
import csv
import datetime
import inspect
import json
import os
import subprocess
import time
import uuid

import numpy as np
import qasync

from fissure.Dashboard.UI_Components.MPL import MPL_IQCanvas
import fissure.utils
from fissure.utils.selected_node_utils import (
    selected_node_is_local,
    selected_node_is_remote,
)
from .legacy import _safe_float, _safe_int


TSI_CONDITIONER_METHOD_CATEGORIES = [
    ("energy", "Energy"),
    ("eigenvalue", "Eigenvalue"),
    ("matched_filter", "Matched Filter"),
    ("cyclostationary", "Cyclostationary"),
    ("imagery", "Imagery"),
]

TSI_CONDITIONER_METHODS_BY_CATEGORY = {
    "energy": [
        ("burst_tagger", "Burst Tagger"),
        ("normal", "Normal"),
        ("normal_decay", "Normal Decay"),
        ("power_squelch", "Power Squelch"),
        ("lowpass", "Lowpass"),
        ("power_squelch_lowpass", "Power Squelch then Lowpass"),
        ("bandpass", "Bandpass"),
        ("strongest_frequency_bandpass", "Strongest Frequency then Bandpass"),
    ],
    "eigenvalue": [
        ("placeholder", "Placeholder"),
    ],
    "matched_filter": [
        ("placeholder", "Placeholder"),
    ],
    "cyclostationary": [
        ("placeholder", "Placeholder"),
    ],
    "imagery": [
        ("placeholder", "Placeholder"),
    ],
}

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputSourceChanged(dashboard: QtCore.QObject):
    """
    Handles Conditioner input source switching.

    Changing source changes the valid action-query context, so existing
    actions/parameters are cleared. Actions are not queried automatically.
    """
    source = _tsi_conditioner_current_source(dashboard)

    if source in ["File", "Folder"]:
        dashboard.ui.stackedWidget_tsi_conditioner_input.setCurrentIndex(0)

    elif source == "Frequencies":
        dashboard.ui.stackedWidget_tsi_conditioner_input.setCurrentIndex(1)

    update_tsi_conditioner_method_hardware_combo(dashboard)
    clear_tsi_conditioner_method_actions(dashboard)
    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputSelectionChanged(dashboard: QtCore.QObject):
    """
    Updates the active Conditioner input file when the file-list selection changes.
    """
    filepath = _tsi_conditioner_selected_input_file(dashboard)

    if filepath:
        dashboard.tsi_conditioner_selected_file_path = filepath

    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputPathEdited(dashboard: QtCore.QObject):
    """
    Manual folder entry.

    If the user types/pastes a real folder path, store it and refresh the file list.
    Ignore shortened display paths like .../folder.
    """
    text = dashboard.ui.textEdit_tsi_conditioner_file_path.toPlainText().strip()

    if text and os.path.isdir(text):
        dashboard.tsi_conditioner_input_folder = os.path.abspath(text)
        dashboard.ui.textEdit_tsi_conditioner_file_path.setToolTip(
            dashboard.tsi_conditioner_input_folder
        )
        _tsi_conditioner_refresh_file_list_from_path(dashboard)
        return

    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputDataTypeChanged(dashboard: QtCore.QObject):
    """
    Recalculate file metadata and keep preview gate current.
    """
    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputExtensionsAllClicked(dashboard: QtCore.QObject):
    """
    Shows all files and refreshes immediately.
    """
    dashboard.ui.textEdit_tsi_conditioner_input_extensions.setEnabled(False)
    _tsi_conditioner_refresh_file_list_from_path(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputExtensionsCustomClicked(dashboard: QtCore.QObject):
    """
    Enables custom extension filtering and refreshes immediately.
    """
    dashboard.ui.textEdit_tsi_conditioner_input_extensions.setEnabled(True)
    _tsi_conditioner_refresh_file_list_from_path(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFolderClicked(dashboard: QtCore.QObject):
    """
    Selects the Conditioner input folder.

    This intentionally selects a folder for File and Folder source types.
    The active input file comes from listWidget_tsi_conditioner_input_files.
    """
    current_folder = _tsi_conditioner_get_input_folder(dashboard)

    if not current_folder:
        current_folder = os.path.join(
            fissure.utils.FISSURE_ROOT,
            "Conditioner Data",
            "Input",
        )

    selected_dir = QtWidgets.QFileDialog.getExistingDirectory(
        dashboard,
        "Select IQ Input Folder",
        current_folder,
    )

    if not selected_dir:
        return

    _tsi_conditioner_set_input_folder(dashboard, selected_dir)
    _tsi_conditioner_refresh_file_list_from_path(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputRefreshClicked(dashboard: QtCore.QObject):
    """
    Refreshes the Conditioner input file list from the selected folder.
    """
    _tsi_conditioner_refresh_file_list_from_path(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputPreviewClicked(dashboard: QtCore.QObject):
    """
    Plots the selected input file inside the Conditioner preview frame.
    """
    filepath = _tsi_conditioner_selected_input_file(dashboard)

    if not filepath or not os.path.isfile(filepath):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Select a valid input file first."
        )
        update_tsi_conditioner_file_gate(dashboard)
        return

    try:
        _tsi_conditioner_plot_preview(dashboard, filepath)
    except Exception as e:
        dashboard.logger.error(f"[Conditioner] Failed to preview IQ file: {e}")
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to preview IQ file:\n{e}"
        )

    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsFolderClicked(dashboard: QtCore.QObject):
    """
    Opens the Conditioner output folder for Local Folder mode only.

    Artifact mode uses managed artifact storage, so the normal output folder
    button is disabled and the artifact button should be used instead.
    """
    if _tsi_conditioner_current_results_are_artifact(dashboard):
        _tsi_conditioner_set_run_status(
            dashboard,
            "Artifact results are managed. Use Open Artifact.",
        )
        return

    output_dir = _tsi_conditioner_get_run_output_folder(dashboard)

    if output_dir and os.path.isdir(output_dir):
        subprocess.Popen(["xdg-open", output_dir])
        return

    fissure.Dashboard.UI_Components.Qt5.errorMessage(
        "The Conditioner output folder does not exist."
    )

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsDeleteClicked(dashboard: QtCore.QObject):
    """
    Deletes the selected Conditioner output file and its SigMF sidecar metadata.
    """
    if _tsi_conditioner_current_results_are_artifact(dashboard):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Artifact-managed Conditioner results are read-only."
        )
        return

    table = dashboard.ui.tableWidget_tsi_conditioner_results
    row = table.currentRow()

    if row < 0:
        return

    file_item = table.item(row, 0)

    if file_item is None:
        return

    filepath = file_item.data(QtCore.Qt.UserRole)

    if not filepath:
        output_dir = _tsi_conditioner_get_run_output_folder(dashboard)
        filepath = os.path.join(output_dir, file_item.text())

    payload_row = {}

    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    for candidate in payload.get("files", []) or []:
        candidate_path = str(candidate.get("path", "") or "")
        candidate_name = str(candidate.get("name", "") or "")

        if (
            candidate_path
            and filepath
            and os.path.abspath(candidate_path) == os.path.abspath(filepath)
        ):
            payload_row = candidate
            break

        if candidate_name and candidate_name == file_item.text():
            payload_row = candidate
            break

    _tsi_conditioner_delete_output_file_and_sidecars(
        dashboard,
        filepath,
        payload_row,
    )

    table.removeRow(row)

    _tsi_conditioner_mark_results_unpromoted(dashboard)

    count_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_results_file_count",
        None,
    )
    if count_label is not None:
        count_label.setText(f"File Count: {table.rowCount()}")

    # The zip/artifact is now stale because one file was manually deleted.
    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    bundle_path = str(payload.get("bundle_path", "") or "")
    if bundle_path and os.path.isfile(bundle_path):
        try:
            os.remove(bundle_path)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Could not delete stale bundle: {bundle_path}. Error: {e}"
            )

    dashboard.tsi_conditioner_last_artifact_id = ""
    dashboard.tsi_conditioner_last_artifact_payload = {}

    artifact_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_run_artifact_id",
        None,
    )
    if artifact_label is not None:
        artifact_label.setText("—")
        artifact_label.setToolTip("")

    download_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_run_download_artifact",
        None,
    )
    if download_button is not None:
        download_button.setEnabled(False)
    
    _tsi_conditioner_update_workflow_ribbon(dashboard)
    _tsi_conditioner_update_results_action_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsDeleteAllClicked(dashboard: QtCore.QObject):
    """
    Deletes all Conditioner result files currently listed in the table,
    including SigMF sidecars, current operation metadata, current bundle,
    and the latest-run metadata pointer.
    """
    if _tsi_conditioner_current_results_are_artifact(dashboard):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Artifact-managed Conditioner results are read-only."
        )
        return

    table = dashboard.ui.tableWidget_tsi_conditioner_results

    if table.rowCount() <= 0:
        return

    output_dir = _tsi_conditioner_get_run_output_folder(dashboard)

    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    latest_metadata_path = os.path.join(
        output_dir,
        "signal_conditioning_file_artifact.json",
    )

    # If Dashboard state was already cleared/stale, recover payload from disk.
    if not payload and os.path.isfile(latest_metadata_path):
        try:
            with open(latest_metadata_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Could not read latest Conditioner metadata: {e}"
            )
            payload = {}

    payload_files = payload.get("files", []) or []

    payload_by_name = {}
    payload_by_path = {}

    for payload_row in payload_files:
        name = str(payload_row.get("name", "") or "")
        path = str(payload_row.get("path", "") or "")

        if name:
            payload_by_name[name] = payload_row

        if path:
            payload_by_path[os.path.abspath(path)] = payload_row

    operation_id = str(payload.get("operation_id", "") or "").strip()

    deleted_paths = []

    for row in reversed(range(table.rowCount())):
        file_item = table.item(row, 0)

        if file_item is None:
            table.removeRow(row)
            continue

        filepath = file_item.data(QtCore.Qt.UserRole)

        if not filepath:
            filepath = os.path.join(output_dir, file_item.text())

        payload_row = {}

        if filepath:
            payload_row = payload_by_path.get(
                os.path.abspath(filepath),
                {},
            )

        if not payload_row:
            payload_row = payload_by_name.get(
                file_item.text(),
                {},
            )

        if filepath:
            deleted_paths.append(os.path.abspath(filepath))

        sigmf_meta_path = str(
            payload_row.get("sigmf_meta_path", "") or ""
        ).strip()

        if sigmf_meta_path:
            deleted_paths.append(os.path.abspath(sigmf_meta_path))

        _tsi_conditioner_delete_output_file_and_sidecars(
            dashboard,
            filepath,
            payload_row,
        )

        table.removeRow(row)

    # Delete bundle from payload.
    bundle_path = str(payload.get("bundle_path", "") or "").strip()
    if bundle_path and os.path.isfile(bundle_path):
        try:
            os.remove(bundle_path)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Could not delete Conditioner bundle: {bundle_path}. Error: {e}"
            )

    # Delete operation metadata from payload.
    metadata_path = str(payload.get("metadata_path", "") or "").strip()
    if metadata_path and os.path.isfile(metadata_path):
        try:
            os.remove(metadata_path)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Could not delete Conditioner metadata: {metadata_path}. Error: {e}"
            )

    # Fallback cleanup for current operation files in the output folder.
    # This catches conditioner_<operation_id>.json / .zip even when payload paths
    # are missing or stale.
    if output_dir and os.path.isdir(output_dir):
        try:
            for fname in os.listdir(output_dir):
                fpath = os.path.join(output_dir, fname)

                if not os.path.isfile(fpath):
                    continue

                delete_file = False

                if operation_id:
                    if fname == f"conditioner_{operation_id}.json":
                        delete_file = True
                    elif fname == f"conditioner_{operation_id}.zip":
                        delete_file = True
                    elif operation_id in fname and fname.endswith(".json"):
                        delete_file = True
                    elif operation_id in fname and fname.endswith(".zip"):
                        delete_file = True

                # If there is no operation_id, only delete the known latest pointer.
                if fname == "signal_conditioning_file_artifact.json":
                    delete_file = True

                if delete_file:
                    try:
                        os.remove(fpath)
                    except Exception as e:
                        dashboard.logger.warning(
                            f"[Conditioner] Could not delete Conditioner operation file: {fpath}. Error: {e}"
                        )

        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Could not scan output folder for metadata cleanup: {e}"
            )

    # Extra latest-pointer cleanup. If it survived the scan, remove it.
    if os.path.isfile(latest_metadata_path):
        try:
            os.remove(latest_metadata_path)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Could not delete latest metadata pointer: {latest_metadata_path}. Error: {e}"
            )

    count_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_results_file_count",
        None,
    )
    if count_label is not None:
        count_label.setText("File Count: 0")

    dashboard.tsi_conditioner_last_artifact_id = ""
    dashboard.tsi_conditioner_last_artifact_payload = {}

    artifact_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_run_artifact_id",
        None,
    )
    if artifact_label is not None:
        artifact_label.setText("—")
        artifact_label.setToolTip("")

    download_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_run_download_artifact",
        None,
    )
    if download_button is not None:
        download_button.setEnabled(False)

    _tsi_conditioner_update_workflow_ribbon(dashboard)
    _tsi_conditioner_update_results_action_gate(dashboard)

def _tsi_conditioner_widget(dashboard: QtCore.QObject, name: str):
    return getattr(dashboard.ui, name, None)

def _tsi_conditioner_get_text_edit(dashboard: QtCore.QObject, name: str) -> str:
    widget = _tsi_conditioner_widget(dashboard, name)
    if widget is None:
        return ""
    return widget.toPlainText().strip()

def _tsi_conditioner_set_text_edit(dashboard: QtCore.QObject, name: str, value: str):
    widget = _tsi_conditioner_widget(dashboard, name)
    if widget is None:
        return

    old_state = widget.blockSignals(True)
    widget.setPlainText(str(value))
    widget.blockSignals(old_state)

def _tsi_conditioner_set_label(dashboard: QtCore.QObject, name: str, value: str):
    widget = _tsi_conditioner_widget(dashboard, name)
    if widget is not None:
        widget.setText(str(value))

def _tsi_conditioner_set_combo_items(
    combo: QtWidgets.QComboBox,
    items,
    preferred_text: str = "",
):
    if combo is None:
        return

    current_text = preferred_text or combo.currentText()

    old_state = combo.blockSignals(True)
    combo.clear()
    combo.addItems([str(x) for x in items if str(x).strip()])

    if current_text:
        idx = combo.findText(current_text)
        if idx >= 0:
            combo.setCurrentIndex(idx)
        elif combo.count() > 0:
            combo.setCurrentIndex(0)
    elif combo.count() > 0:
        combo.setCurrentIndex(0)

    combo.blockSignals(old_state)

def _tsi_conditioner_file_bytes_per_iq_sample(data_type: str):
    """
    Returns bytes per IQ sample for known file formats.

    Scalar-only entries are treated as one sample per scalar item. Interleaved
    I/Q and Complex entries are treated as one IQ sample per I/Q pair.
    """
    data_type = str(data_type or "").strip()

    bytes_per_sample = {
        "Complex Float 32": 8,
        "Float/Float 32": 8,
        "Short/Int 16": 2,
        "Unsigned Int 16": 2,
        "Int/Int 32": 4,
        "Unsigned Int 32": 4,
        "Byte/Int 8": 1,
        "Unsigned Int 8": 1,
        "Complex Float 64": 16,
        "Complex Int 64": 16,
        "Complex Unsigned Int 64": 16,
        "Complex Int 16": 4,
        "Complex Unsigned Int 16": 4,
        "Complex Int 8": 2,
        "Complex Unsigned Int 8": 2,
    }

    return bytes_per_sample.get(data_type)

def _tsi_conditioner_format_file_size(num_bytes: int) -> str:
    if num_bytes < 1024:
        return f"{num_bytes} B"
    if num_bytes < 1024 * 1024:
        return f"{num_bytes / 1024:.2f} KB"
    if num_bytes < 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.2f} MB"
    return f"{num_bytes / (1024 * 1024 * 1024):.2f} GB"

def _tsi_conditioner_current_source(dashboard: QtCore.QObject) -> str:
    combo = _tsi_conditioner_widget(dashboard, "comboBox_tsi_conditioner_input_source")
    if combo is None:
        return ""
    return combo.currentText().strip()

def _tsi_conditioner_preview_sample_rate_sps(dashboard: QtCore.QObject) -> float:
    """
    Reads the Conditioner file preview sample rate.

    UI units:
        textEdit_tsi_conditioner_file_sample_rate = MS/s

    Return:
        sample rate in samples/second
    """
    text = _tsi_conditioner_get_text_edit(
        dashboard,
        "textEdit_tsi_conditioner_file_sample_rate",
    )

    try:
        return float(text) * 1_000_000.0
    except Exception:
        return 0.0

def _tsi_conditioner_update_workflow_ribbon(dashboard: QtCore.QObject):
    """
    Updates the Conditioner workflow summary ribbon.

    Count is the number of data files in the latest completed Conditioner run,
    not a scan of the output folder.
    """
    def _short_ribbon_text(text: str, max_chars: int = 28) -> str:
        text = str(text or "").strip()

        if len(text) <= max_chars:
            return text

        return text[: max_chars - 1].rstrip() + "…"

    def _set_ribbon_label(name: str, full_text: str, max_chars: int = 18):
        label = _tsi_conditioner_widget(dashboard, name)
        if label is None:
            return

        full_text = str(full_text or "").strip()
        if not full_text:
            full_text = "—"

        label.setText(_short_ribbon_text(full_text, max_chars))
        label.setToolTip(full_text)

    node_ready = _tsi_conditioner_selected_node_available(dashboard)

    if not node_ready:
        source_label = "—"
        node_label = "—"
        method_label = "—"
        action_label = "—"

    else:
        source = _tsi_conditioner_current_source(dashboard)

        source_labels = {
            "File": "Local IQ File",
            "Folder": "Local IQ Folder",
            "Frequencies": "Frequencies",
            "Select Node": "—",
        }

        source_label = source_labels.get(source, source or "—")
        node_label = _tsi_conditioner_selected_node_label(dashboard)

        method_combo = _tsi_conditioner_widget(
            dashboard,
            "comboBox_tsi_conditioner_method_method",
        )
        method_label = (
            method_combo.currentText().strip()
            if method_combo is not None
            else ""
        )
        if not method_label:
            method_label = "—"

        action_combo = _tsi_conditioner_widget(
            dashboard,
            "comboBox_tsi_conditioner_method_action",
        )
        action_label = (
            action_combo.currentText().strip()
            if action_combo is not None
            else ""
        )
        if not action_label:
            action_label = "—"

    format_combo = _tsi_conditioner_widget(
        dashboard,
        "comboBox_tsi_conditioner_run_output_format",
    )
    output_format = (
        format_combo.currentText().strip()
        if format_combo is not None
        else ""
    )
    if not output_format:
        output_format = "Raw IQ"

    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    files = payload.get("files", []) or []
    if not isinstance(files, list):
        files = []

    data_file_count = len(files)

    # If payload is unavailable but the table is currently populated, use the
    # table count as the UI fallback. This keeps the ribbon aligned after manual
    # refreshes and during local-only testing.
    if data_file_count == 0:
        table = getattr(
            dashboard.ui,
            "tableWidget_tsi_conditioner_results",
            None,
        )
        if table is not None:
            data_file_count = table.rowCount()

    artifact_id = str(
        getattr(dashboard, "tsi_conditioner_last_artifact_id", "")
        or payload.get("artifact_id", "")
        or ""
    ).strip()

    output_mode = str(payload.get("output_mode", "") or "").strip()
    bundle_path = str(payload.get("bundle_path", "") or "").strip()

    artifact_active = (
        output_mode in ["Artifact", "Local Folder + Artifact"]
        and bool(artifact_id)
        and (
            not bundle_path
            or os.path.isfile(bundle_path)
        )
    )

    artifact_label = artifact_id if artifact_active else "—"

    promoted = str(payload.get("promoted", "") or "").strip()
    if not promoted:
        promoted = str(payload.get("promoted_to_soi", "") or "").strip()

    promoted_label = "Yes" if promoted.lower() in {"true", "1", "yes"} else "No"

    _set_ribbon_label(
        "label_tsi_conditioner_workflow_source",
        source_label,
        18,
    )
    _set_ribbon_label(
        "label_tsi_conditioner_workflow_node",
        node_label,
        18,
    )
    _set_ribbon_label(
        "label_tsi_conditioner_workflow_method",
        method_label,
        18,
    )
    _set_ribbon_label(
        "label_tsi_conditioner_workflow_action",
        action_label,
        30,
    )
    _set_ribbon_label(
        "label_tsi_conditioner_workflow_format",
        output_format,
        18,
    )

    _tsi_conditioner_set_label(
        dashboard,
        "label_tsi_conditioner_workflow_count",
        str(data_file_count),
    )
    _tsi_conditioner_set_label(
        dashboard,
        "label_tsi_conditioner_workflow_artifact",
        artifact_label,
    )
    _tsi_conditioner_set_label(
        dashboard,
        "label_tsi_conditioner_workflow_promoted",
        promoted_label,
    )

def _tsi_conditioner_update_file_tooltip(dashboard: QtCore.QObject):
    filepath = _tsi_conditioner_selected_input_file(dashboard)
    list_widget = dashboard.ui.listWidget_tsi_conditioner_input_files

    if not filepath or not os.path.isfile(filepath):
        list_widget.setToolTip("No valid local IQ file selected.")
        return

    data_type = dashboard.ui.comboBox_tsi_conditioner_input_data_type.currentText()
    byte_count = os.path.getsize(filepath)
    bytes_per_sample = _tsi_conditioner_file_bytes_per_iq_sample(data_type)

    if bytes_per_sample:
        sample_count = byte_count // bytes_per_sample
        sample_text = f"{sample_count:,}"
    else:
        sample_count = 0
        sample_text = "Unknown"

    sample_rate = _tsi_conditioner_preview_sample_rate_sps(dashboard)

    if sample_rate > 0 and sample_count > 0:
        duration_s = sample_count / sample_rate
        duration_text = f"{duration_s:.6f} s"
    else:
        duration_text = "Unknown"

    tooltip = (
        f"File: {filepath}\n"
        f"Type: {data_type}\n"
        f"Size: {_tsi_conditioner_format_file_size(byte_count)}\n"
        f"IQ Samples: {sample_text}\n"
        f"Preview Sample Rate: {sample_rate / 1_000_000.0:.6f} MS/s\n"
        f"Estimated Duration: {duration_text}"
    )

    list_widget.setToolTip(tooltip)

def update_tsi_conditioner_file_gate(dashboard: QtCore.QObject):
    """
    Updates current first-pass Conditioner gates.

    File / Folder source:
      - Preview enabled only for local selected node.
      - Preview enabled only when selected list row resolves to a real file.

    Frequencies source:
      - Input table editing is allowed when a node is selected.
      - Hardware/start gating happens in Section 2/3.
    """
    source = _tsi_conditioner_current_source(dashboard)
    filepath = _tsi_conditioner_selected_input_file(dashboard)

    node_ready = _tsi_conditioner_selected_node_available(dashboard)
    local_node = _tsi_conditioner_selected_node_is_local(dashboard)

    valid_file = (
        node_ready
        and local_node
        and source in ["File", "Folder"]
        and os.path.isfile(filepath)
    )

    dashboard.ui.pushButton_tsi_conditioner_input_preview.setEnabled(valid_file)

    _tsi_conditioner_update_file_tooltip(dashboard)
    _tsi_conditioner_update_workflow_ribbon(dashboard)

def _tsi_conditioner_refresh_file_list_from_path(dashboard: QtCore.QObject):
    """
    Refreshes the input list from the selected input folder.

    The folder path is stored separately from the shortened display text.
    """
    list_widget = dashboard.ui.listWidget_tsi_conditioner_input_files
    previous_file = ""

    current_item = list_widget.currentItem()
    if current_item is not None:
        previous_file = current_item.text()

    list_widget.clear()

    folder_path = _tsi_conditioner_get_input_folder(dashboard)

    if not folder_path or not os.path.isdir(folder_path):
        update_tsi_conditioner_file_gate(dashboard)
        return

    use_all = dashboard.ui.radioButton_tsi_conditioner_input_extensions_all.isChecked()
    extension = dashboard.ui.textEdit_tsi_conditioner_input_extensions.toPlainText().strip()

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

    if list_widget.count() > 0:
        if previous_file:
            matches = list_widget.findItems(previous_file, QtCore.Qt.MatchExactly)
            if matches:
                list_widget.setCurrentItem(matches[0])
            else:
                list_widget.setCurrentRow(0)
        else:
            list_widget.setCurrentRow(0)

    update_tsi_conditioner_file_gate(dashboard)


def _initialize_tsi_conditioner_preview_canvas(
    dashboard: QtCore.QObject,
):
    """
    Creates the embedded Conditioner IQ preview canvas.

    Safe to call more than once.
    """
    canvas = getattr(
        dashboard,
        "tsi_conditioner_preview_widget",
        None,
    )

    if canvas is None:
        canvas = MPL_IQCanvas(
            dashboard.ui.frame_tsi_conditioner_preview_plot,
            dpi=100,
            title="",
            ylim=400,
            bg_color=dashboard.backend.settings["color2"],
            face_color=dashboard.backend.settings["color5"],
            text_color=dashboard.backend.settings["color4"],
        )

        dashboard.tsi_conditioner_preview_widget = canvas

    canvas.setGeometry(
        0,
        0,
        dashboard.ui.frame_tsi_conditioner_preview_plot.width(),
        dashboard.ui.frame_tsi_conditioner_preview_plot.height(),
    )

    canvas.setContentsMargins(
        0,
        0,
        0,
        0,
    )


def initialize_tsi_conditioner_controls(
    dashboard: QtCore.QObject,
):
    """
    Initializes the TSI Conditioner controls.
    Safe to call more than once.
    """
    select_node_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "select_node.png",
    )

    select_node_label = getattr(
        dashboard.ui,
        "label_tsi_conditioner_select_sensor_node_image",
        None,
    )

    if (
        select_node_label is not None
        and os.path.isfile(select_node_icon_path)
    ):
        select_node_label.setPixmap(
            QtGui.QPixmap(select_node_icon_path)
        )

    _initialize_tsi_conditioner_preview_canvas(
        dashboard
    )

    dashboard.tsi_conditioner_method_actions = []
    dashboard.tsi_conditioner_selected_plugin = ""
    dashboard.tsi_conditioner_selected_action = ""
    dashboard.tsi_conditioner_method_parameter_widgets = {}
    dashboard.tsi_conditioner_method_current_schema = {}
    dashboard.tsi_conditioner_method_customized = False

    dashboard.tsi_conditioner_last_input_source = ""
    dashboard.tsi_conditioner_action_query_pending = False
    dashboard.tsi_conditioner_action_query_context = ""
    dashboard.tsi_conditioner_action_query_node_uid = ""

    dashboard.tsi_conditioner_run_output_folder = getattr(
        dashboard,
        "tsi_conditioner_run_output_folder",
        "",
    )

    workflow_icons = {
        "label_tsi_conditioner_workflow_source_icon":
            "conditioner_source.svg",
        "label_tsi_conditioner_workflow_node_icon":
            "conditioner_node.svg",
        "label_tsi_conditioner_workflow_method_icon":
            "conditioner_method.svg",
        "label_tsi_conditioner_workflow_action_icon":
            "conditioner_action.svg",
        "label_tsi_conditioner_workflow_format_icon":
            "conditioner_format.svg",
        "label_tsi_conditioner_workflow_count_icon":
            "conditioner_count.svg",
        "label_tsi_conditioner_workflow_artifact_icon":
            "conditioner_artifact.svg",
        "label_tsi_conditioner_workflow_promoted_icon":
            "conditioner_promoted.svg",
    }

    for label_name, icon_name in workflow_icons.items():
        label = getattr(
            dashboard.ui,
            label_name,
            None,
        )

        icon_path = os.path.join(
            fissure.utils.UI_DIR,
            "Icons",
            icon_name,
        )

        if (
            label is not None
            and os.path.isfile(icon_path)
        ):
            label.setPixmap(
                QtGui.QPixmap(icon_path)
            )

    browse_icon = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "folder_black.svg",
    )

    if os.path.isfile(browse_icon):
        input_browse_button = getattr(
            dashboard.ui,
            "pushButton_tsi_conditioner_input_folder",
            None,
        )

        if input_browse_button is not None:
            input_browse_button.setIcon(
                QtGui.QIcon(browse_icon)
            )
            input_browse_button.setText("")
            input_browse_button.setToolTip(
                "Select input folder"
            )
            input_browse_button.setIconSize(
                QtCore.QSize(18, 18)
            )

        run_browse_button = getattr(
            dashboard.ui,
            "pushButton_tsi_conditioner_run_browse",
            None,
        )

        if run_browse_button is not None:
            run_browse_button.setIcon(
                QtGui.QIcon(browse_icon)
            )
            run_browse_button.setText("")
            run_browse_button.setToolTip(
                "Select output folder"
            )
            run_browse_button.setIconSize(
                QtCore.QSize(18, 18)
            )

    refresh_icon = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "refresh.png",
    )

    if os.path.isfile(refresh_icon):
        refresh_button = getattr(
            dashboard.ui,
            "pushButton_tsi_conditioner_input_refresh",
            None,
        )

        if refresh_button is not None:
            refresh_button.setIcon(
                QtGui.QIcon(refresh_icon)
            )
            refresh_button.setText("")
            refresh_button.setToolTip(
                "Refresh file list"
            )
            refresh_button.setIconSize(
                QtCore.QSize(18, 18)
            )

    if not _tsi_conditioner_get_text_edit(
        dashboard,
        "textEdit_tsi_conditioner_file_sample_rate",
    ):
        _tsi_conditioner_set_text_edit(
            dashboard,
            "textEdit_tsi_conditioner_file_sample_rate",
            "1.0",
        )

    if not _tsi_conditioner_get_text_edit(
        dashboard,
        "textEdit_tsi_conditioner_input_extensions",
    ):
        _tsi_conditioner_set_text_edit(
            dashboard,
            "textEdit_tsi_conditioner_input_extensions",
            ".iq",
        )

    dashboard.ui.radioButton_tsi_conditioner_input_extensions_all.setChecked(
        True
    )
    dashboard.ui.textEdit_tsi_conditioner_input_extensions.setEnabled(
        False
    )

    default_input_dir = os.path.join(
        fissure.utils.FISSURE_ROOT,
        "Conditioner Data",
        "Input",
    )

    if os.path.isdir(default_input_dir):
        _tsi_conditioner_set_input_folder(
            dashboard,
            default_input_dir,
        )
    else:
        _tsi_conditioner_set_input_folder(
            dashboard,
            fissure.utils.FISSURE_ROOT,
        )

    default_output_dir = os.path.join(
        fissure.utils.FISSURE_ROOT,
        "Conditioner Data",
        "Output",
    )

    if os.path.isdir(default_output_dir):
        _tsi_conditioner_set_run_output_folder(
            dashboard,
            default_output_dir,
        )
    else:
        _tsi_conditioner_set_run_output_folder(
            dashboard,
            fissure.utils.FISSURE_ROOT,
        )

    if not _tsi_conditioner_get_text_edit(
        dashboard,
        "textEdit_tsi_conditioner_run_file_prefix",
    ):
        _tsi_conditioner_set_text_edit(
            dashboard,
            "textEdit_tsi_conditioner_run_file_prefix",
            "output_",
        )

    output_mode_combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_run_output_mode",
        None,
    )

    if output_mode_combo is not None:
        current_output_mode = (
            output_mode_combo.currentText().strip()
        )

        if current_output_mode == "Local Folder + Artifact":
            current_output_mode = "Artifact"

        output_mode_combo.blockSignals(True)
        output_mode_combo.clear()
        output_mode_combo.addItems([
            "Local Folder",
            "Artifact",
        ])

        if current_output_mode in {
            "Local Folder",
            "Artifact",
        }:
            output_mode_combo.setCurrentText(
                current_output_mode
            )
        else:
            output_mode_combo.setCurrentText(
                "Local Folder"
            )

        output_mode_combo.blockSignals(False)

    output_format_combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_run_output_format",
        None,
    )

    if output_format_combo is not None:
        current_output_format = (
            output_format_combo.currentText().strip()
        )

        legacy_format_map = {
            "Raw IQ": "Raw IQ Files",
            "SigMF": "SigMF Files",
            "Zip Bundle": "Raw IQ Zip Bundle",
        }

        current_output_format = legacy_format_map.get(
            current_output_format,
            current_output_format,
        )

        output_format_combo.blockSignals(True)
        output_format_combo.clear()
        output_format_combo.addItems([
            "Raw IQ Files",
            "SigMF Files",
            "Raw IQ Zip Bundle",
            "SigMF Zip Bundle",
        ])

        if current_output_format:
            index = output_format_combo.findText(
                current_output_format
            )

            if index >= 0:
                output_format_combo.setCurrentIndex(
                    index
                )
            else:
                output_format_combo.setCurrentText(
                    "Raw IQ Files"
                )
        else:
            output_format_combo.setCurrentText(
                "Raw IQ Files"
            )

        output_format_combo.blockSignals(False)

    saturation_combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_run_saturation_check",
        None,
    )

    if saturation_combo is not None:
        saturation_combo.blockSignals(True)

        if saturation_combo.findText("No") < 0:
            saturation_combo.clear()
            saturation_combo.addItems([
                "No",
                "Yes",
            ])

        saturation_combo.setCurrentText("No")
        saturation_combo.blockSignals(False)

    run_status_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_run_status",
        None,
    )

    if run_status_label is not None:
        run_status_label.setText("Idle")

    run_progress_bar = getattr(
        dashboard.ui,
        "progressBar_tsi_conditioner_run_progress",
        None,
    )

    if run_progress_bar is not None:
        run_progress_bar.setRange(
            0,
            100,
        )
        run_progress_bar.setValue(0)

    run_start_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_run_start_stop",
        None,
    )

    if run_start_button is not None:
        run_start_button.setText("Start")
        run_start_button.setProperty(
            "running",
            "false",
        )
        run_start_button.style().unpolish(
            run_start_button
        )
        run_start_button.style().polish(
            run_start_button
        )

    artifact_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_run_artifact_id",
        None,
    )

    if artifact_label is not None:
        artifact_label.setText("—")

    download_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_run_download_artifact",
        None,
    )

    if download_button is not None:
        download_button.setEnabled(False)

    reset_tsi_conditioner_preview_plot(
        dashboard
    )

    source_combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_input_source",
        None,
    )

    if source_combo is not None:
        current_source = (
            source_combo.currentText().strip()
        )

        source_combo.blockSignals(True)
        source_combo.clear()
        source_combo.addItems([
            "File",
            "Folder",
            "Frequencies",
        ])

        if current_source in {
            "File",
            "Folder",
            "Frequencies",
        }:
            source_combo.setCurrentText(
                current_source
            )
        else:
            source_combo.setCurrentText(
                "File"
            )

        source_combo.blockSignals(False)

    _populate_tsi_conditioner_method_category_combo(
        dashboard
    )
    _populate_tsi_conditioner_method_method_combo(
        dashboard
    )
    update_tsi_conditioner_method_hardware_combo(
        dashboard
    )
    clear_tsi_conditioner_method_actions(
        dashboard
    )

    dashboard.ui.pushButton_tsi_conditioner_method_query_actions.setText(
        "Query Actions"
    )
    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setText(
        "Query Parameters"
    )
    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setEnabled(
        False
    )

    dashboard.ui.scrollArea_tsi_conditioner_method.setHorizontalScrollBarPolicy(
        QtCore.Qt.ScrollBarAlwaysOff
    )
    dashboard.ui.scrollArea_tsi_conditioner_method.setVerticalScrollBarPolicy(
        QtCore.Qt.ScrollBarAsNeeded
    )

    _tsi_conditioner_update_run_output_mode_gate(
        dashboard
    )
    _tsi_conditioner_refresh_file_list_from_path(
        dashboard
    )
    update_tsi_conditioner_selected_node_gate(
        dashboard
    )
    update_tsi_conditioner_run_node_label(
        dashboard
    )

    if not getattr(
        dashboard,
        "tsi_conditioner_selected_file_path",
        "",
    ):
        _tsi_conditioner_set_preview_file_label(
            dashboard,
            "",
        )


def _tsi_conditioner_shorten_path(path: str, max_chars: int = 38) -> str:
    """
    Shortens a folder path for the cramped folder text edit.
    Stores the real path separately on dashboard.tsi_conditioner_input_folder.
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

def _tsi_conditioner_set_input_folder(dashboard: QtCore.QObject, folder_path: str):
    """
    Sets the Conditioner input folder.

    The QTextEdit only displays a shortened path. The real folder is stored in:
        dashboard.tsi_conditioner_input_folder
    """
    folder_path = os.path.abspath(str(folder_path or "").strip())

    dashboard.tsi_conditioner_input_folder = folder_path

    text_edit = dashboard.ui.textEdit_tsi_conditioner_file_path
    old_state = text_edit.blockSignals(True)
    text_edit.setPlainText(_tsi_conditioner_shorten_path(folder_path))
    text_edit.setToolTip(folder_path)
    text_edit.blockSignals(old_state)

def _tsi_conditioner_get_input_folder(dashboard: QtCore.QObject) -> str:
    """
    Gets the real Conditioner input folder.

    Falls back to the visible text only if no stored folder exists.
    """
    folder_path = getattr(dashboard, "tsi_conditioner_input_folder", "")

    if folder_path and os.path.isdir(folder_path):
        return folder_path

    visible_text = dashboard.ui.textEdit_tsi_conditioner_file_path.toPlainText().strip()

    if visible_text and os.path.isdir(visible_text):
        dashboard.tsi_conditioner_input_folder = os.path.abspath(visible_text)
        return dashboard.tsi_conditioner_input_folder

    return ""

def _tsi_conditioner_selected_input_file(dashboard: QtCore.QObject) -> str:
    """
    Returns the full path for the currently selected Conditioner input file.
    """
    folder_path = _tsi_conditioner_get_input_folder(dashboard)

    if not folder_path:
        return ""

    item = dashboard.ui.listWidget_tsi_conditioner_input_files.currentItem()

    if item is None:
        return ""

    filepath = os.path.join(folder_path, item.text())

    if os.path.isfile(filepath):
        return filepath

    return ""

def _tsi_conditioner_set_preview_file_label(dashboard: QtCore.QObject, filepath: str):
    """
    Updates the Conditioner preview file labels.

    Expected Designer objects:
        label2_tsi_conditioner_preview_file_label
        label2_tsi_conditioner_preview_file

    Behavior:
        - Shows both labels when a file is selected.
        - Hides both labels when no file is selected.
        - Displays basename only.
        - Stores full path in tooltip.
    """
    title_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_preview_file_label",
        None,
    )
    file_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_preview_file",
        None,
    )

    if title_label is not None:
        title_label.setVisible(bool(filepath))
        title_label.setToolTip(filepath if filepath else "")

    if file_label is not None:
        file_label.setVisible(bool(filepath))

        if filepath:
            file_label.setText(os.path.basename(filepath))
            file_label.setToolTip(filepath)
        else:
            file_label.setText("")
            file_label.setToolTip("")

def _tsi_conditioner_file_dtype(data_type: str):
    """
    Returns numpy dtype and whether the file should be interpreted as I/Q pairs.
    """
    data_type = str(data_type or "").strip()

    dtype_map = {
        "Complex Float 32": (np.float32, True),
        "Float/Float 32": (np.float32, True),
        "Short/Int 16": (np.int16, False),
        "Unsigned Int 16": (np.uint16, False),
        "Int/Int 32": (np.int32, False),
        "Unsigned Int 32": (np.uint32, False),
        "Byte/Int 8": (np.int8, False),
        "Unsigned Int 8": (np.uint8, False),
        "Complex Float 64": (np.float64, True),
        "Complex Int 64": (np.int64, True),
        "Complex Unsigned Int 64": (np.uint64, True),
        "Complex Int 16": (np.int16, True),
        "Complex Unsigned Int 16": (np.uint16, True),
        "Complex Int 8": (np.int8, True),
        "Complex Unsigned Int 8": (np.uint8, True),
    }

    return dtype_map.get(data_type, (None, False))

def _tsi_conditioner_read_preview_samples(filepath: str, data_type: str, max_points: int = 5000):
    """
    Reads a downsampled preview from an IQ file without loading the entire file.
    """
    dtype, is_iq = _tsi_conditioner_file_dtype(data_type)

    if dtype is None:
        raise ValueError(f"Unsupported data type: {data_type}")

    item_size = np.dtype(dtype).itemsize
    byte_count = os.path.getsize(filepath)

    if byte_count <= 0:
        raise ValueError("Input file is empty.")

    scalar_count = byte_count // item_size

    if is_iq:
        scalar_count -= scalar_count % 2
        iq_count = scalar_count // 2

        if iq_count <= 0:
            raise ValueError("Input file does not contain enough I/Q samples.")

        skip = max(1, iq_count // max_points)

        data = np.memmap(filepath, dtype=dtype, mode="r", shape=(scalar_count,))
        i_data = np.asarray(data[0::2][::skip], dtype=np.float64)
        q_data = np.asarray(data[1::2][::skip], dtype=np.float64)

        del data

        return i_data, q_data, skip

    sample_count = scalar_count

    if sample_count <= 0:
        raise ValueError("Input file does not contain enough samples.")

    skip = max(1, sample_count // max_points)

    data = np.memmap(filepath, dtype=dtype, mode="r", shape=(scalar_count,))
    y_data = np.asarray(data[::skip], dtype=np.float64)

    del data

    return y_data, None, skip

def _tsi_conditioner_plot_preview(dashboard: QtCore.QObject, filepath: str):
    """
    Plots the selected input file inside the Conditioner preview frame.
    """
    canvas = getattr(dashboard, "tsi_conditioner_preview_widget", None)

    if canvas is None:
        dashboard.logger.error("[Conditioner] Preview canvas was not initialized.")
        return

    data_type = dashboard.ui.comboBox_tsi_conditioner_input_data_type.currentText().strip()
    sample_rate = _tsi_conditioner_preview_sample_rate_sps(dashboard)
    colors = _tsi_conditioner_plot_color_settings(dashboard)

    i_data, q_data, skip = _tsi_conditioner_read_preview_samples(
        filepath,
        data_type,
        max_points=5000,
    )

    resize_tsi_conditioner_preview_canvas(dashboard)

    canvas.axes.cla()
    canvas.axes.set_axis_on()

    if sample_rate > 0:
        x_data = np.arange(len(i_data), dtype=np.float64) * skip / sample_rate
        x_label = "Time (s)"
    else:
        x_data = np.arange(len(i_data), dtype=np.float64) * skip
        x_label = f"Samples/{skip}" if skip > 1 else "Samples"

    if q_data is not None:
        canvas.axes.plot(
            x_data,
            i_data,
            linewidth=0.8,
            alpha=0.90,
            color=colors["i_color"],
            label="I",
            zorder=3,
        )
        canvas.axes.plot(
            x_data,
            q_data,
            linewidth=0.8,
            alpha=colors["q_alpha"],
            color=colors["q_color"],
            label="Q",
            zorder=2,
        )
        legend = canvas.axes.legend(
            loc="upper right",
            fontsize=8,
            frameon=False,
            borderpad=0.2,
            handlelength=1.5,
        )

        for text in legend.get_texts():
            text.set_color(colors["text_color"])
    else:
        canvas.axes.plot(
            x_data,
            i_data,
            linewidth=0.8,
            alpha=0.90,
            color=colors["i_color"],
        )

    canvas.axes.set_title("")

    canvas.axes.set_xlabel(
        x_label,
        color=colors["text_color"],
        fontsize=9,
        labelpad=1,
    )
    canvas.axes.set_ylabel(
        "Amplitude",
        color=colors["text_color"],
        fontsize=9,
        labelpad=2,
    )

    canvas.axes.tick_params(
        axis="x",
        colors=colors["text_color"],
        labelsize=8,
        pad=1,
    )
    canvas.axes.tick_params(
        axis="y",
        colors=colors["text_color"],
        labelsize=8,
        pad=1,
    )

    canvas.axes.grid(
        True,
        linewidth=0.6,
        alpha=0.45,
        color=colors["grid_color"],
    )

    canvas.fig.set_facecolor(colors["fig_face"])
    canvas.axes.set_facecolor(colors["plot_face"])

    canvas.fig.subplots_adjust(
        left=0.115,
        right=0.988,
        bottom=0.12,
        top=0.97,
    )

    canvas.setToolTip(filepath)

    dashboard.tsi_conditioner_selected_file_path = filepath
    _tsi_conditioner_set_preview_file_label(dashboard, filepath)

    canvas.draw()

def resize_tsi_conditioner_preview_canvas(dashboard: QtCore.QObject):
    """
    Resizes the embedded Conditioner preview canvas to fill the preview plot frame.
    """
    canvas = getattr(dashboard, "tsi_conditioner_preview_widget", None)

    if canvas is None:
        return

    canvas.setGeometry(
        0,
        0,
        dashboard.ui.frame_tsi_conditioner_preview_plot.width(),
        dashboard.ui.frame_tsi_conditioner_preview_plot.height(),
    )

def reset_tsi_conditioner_preview_plot(dashboard: QtCore.QObject):
    """
    Clears the Conditioner preview plot to a blank themed canvas and hides file labels.
    """
    _tsi_conditioner_set_preview_file_label(dashboard, "")

    canvas = getattr(dashboard, "tsi_conditioner_preview_widget", None)

    if canvas is None:
        return

    colors = _tsi_conditioner_plot_color_settings(dashboard)

    resize_tsi_conditioner_preview_canvas(dashboard)

    canvas.axes.cla()
    canvas.axes.set_axis_off()

    canvas.fig.set_facecolor(colors["fig_face"])
    canvas.axes.set_facecolor(colors["plot_face"])

    canvas.fig.subplots_adjust(
        left=0.01,
        right=0.99,
        bottom=0.01,
        top=0.99,
    )

    canvas.setToolTip("")
    canvas.draw()

def _tsi_conditioner_plot_color_settings(dashboard: QtCore.QObject):
    """
    Returns theme-aware colors for the Conditioner preview plot.
    """
    settings = getattr(dashboard.backend, "settings", {}) or {}

    text_color = settings.get("color4", "#000000")
    fig_face = settings.get("color5", "#ffffff")
    plot_face = settings.get("color5", "#ffffff")

    color_mode = str(settings.get("color_mode", "") or "")

    if "Dark" in color_mode:
        grid_color = "#56616f"
        i_color = "#2f8fe8"
        q_color = "#7aa35a"
        q_alpha = 0.55
    elif "Custom" in color_mode:
        grid_color = settings.get("color3", "#31577d")
        i_color = "#1f77b4"
        q_color = "#6f8f4e"
        q_alpha = 0.50
    else:
        grid_color = "#b8c0ca"
        i_color = "#1f77b4"
        q_color = "#7aa35a"
        q_alpha = 0.55

    return {
        "text_color": text_color,
        "fig_face": fig_face,
        "plot_face": plot_face,
        "grid_color": grid_color,
        "i_color": i_color,
        "q_color": q_color,
        "q_alpha": q_alpha,
    }

def restyle_tsi_conditioner_preview_canvas(dashboard: QtCore.QObject):
    """
    Reapplies the current Dashboard theme to the Conditioner preview canvas
    without loading or plotting any file.

    Style changes should not trigger a preview. The Preview button is the only
    path that should read IQ data and plot a selected file.
    """
    canvas = getattr(dashboard, "tsi_conditioner_preview_widget", None)

    if canvas is None:
        return

    frame = getattr(dashboard.ui, "frame_tsi_conditioner_preview_plot", None)
    if frame is not None:
        frame.style().unpolish(frame)
        frame.style().polish(frame)
        frame.update()

    colors = _tsi_conditioner_plot_color_settings(dashboard)

    canvas.fig.set_facecolor(colors["fig_face"])
    canvas.axes.set_facecolor(colors["plot_face"])

    # If a preview is currently visible, only recolor existing plot elements.
    if canvas.axes.axison:
        for line in canvas.axes.lines:
            label = str(line.get_label() or "")

            if label == "I":
                line.set_color(colors["i_color"])
                line.set_alpha(0.90)
            elif label == "Q":
                line.set_color(colors["q_color"])
                line.set_alpha(colors["q_alpha"])

        for text in (
            [canvas.axes.xaxis.label, canvas.axes.yaxis.label]
            + list(canvas.axes.get_xticklabels())
            + list(canvas.axes.get_yticklabels())
        ):
            text.set_color(colors["text_color"])

        legend = canvas.axes.get_legend()
        if legend is not None:
            for text in legend.get_texts():
                text.set_color(colors["text_color"])

        canvas.axes.grid(
            True,
            linewidth=0.6,
            alpha=0.45,
            color=colors["grid_color"],
        )

    # Blank state stays blank.
    else:
        canvas.axes.set_axis_off()
        canvas.fig.subplots_adjust(
            left=0.01,
            right=0.99,
            bottom=0.01,
            top=0.99,
        )

    canvas.draw()

def _tsi_conditioner_frequency_table(dashboard: QtCore.QObject):
    return getattr(dashboard.ui, "tableWidget_tsi_conditioner_input_frequencies", None)

def _tsi_conditioner_frequency_dwell_widget(dashboard: QtCore.QObject):
    return getattr(dashboard.ui, "label2_conditioner_input_frequencies_dwell", None)

def _tsi_conditioner_frequency_default_dwell(dashboard: QtCore.QObject) -> str:
    """
    Reads the default dwell field.

    The widget name is label2_conditioner_input_frequencies_dwell, but this
    helper supports QLabel, QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox,
    and QDoubleSpinBox in case the Designer type changes.
    """
    widget = _tsi_conditioner_frequency_dwell_widget(dashboard)

    if widget is None:
        return "10"

    try:
        if isinstance(widget, QtWidgets.QDoubleSpinBox):
            return f"{widget.value():g}"

        if isinstance(widget, QtWidgets.QSpinBox):
            return str(widget.value())

        if isinstance(widget, QtWidgets.QLineEdit):
            text = widget.text().strip()
            return text if text else "10"

        if isinstance(widget, QtWidgets.QTextEdit):
            text = widget.toPlainText().strip()
            return text if text else "10"

        if isinstance(widget, QtWidgets.QPlainTextEdit):
            text = widget.toPlainText().strip()
            return text if text else "10"

        if isinstance(widget, QtWidgets.QLabel):
            text = widget.text().strip()
            return text if text else "10"
    except Exception:
        pass

    return "10"

def _tsi_conditioner_parse_frequency_mhz(value) -> str:
    """
    Converts common frequency strings into MHz display text.

    Examples:
        915               -> 915
        "915 MHz"         -> 915
        "915.000"         -> 915
        "915000000"       -> 915
        "915000000 Hz"    -> 915
    """
    text = str(value or "").strip()

    if not text:
        return ""

    text = (
        text.replace("MHz", "")
        .replace("mhz", "")
        .replace("MHZ", "")
        .replace("Hz", "")
        .replace("hz", "")
        .replace("HZ", "")
        .replace(",", "")
        .strip()
    )

    try:
        freq = float(text)
    except Exception:
        return ""

    # Treat large values as Hz.
    if abs(freq) > 100000.0:
        freq = freq / 1_000_000.0

    return f"{freq:g}"

def _tsi_conditioner_add_frequency_row(
    dashboard: QtCore.QObject,
    frequency_mhz="",
    dwell_s=None,
    power_db="",
    time_text="",
    select_row: bool = True,
):
    """
    Adds one row to the Conditioner frequency plan table.

    Columns:
        0 Freq. (MHz)
        1 Dwell (s)
        2 Power (dB)
        3 Time
    """
    table = _tsi_conditioner_frequency_table(dashboard)

    if table is None:
        return

    if dwell_s is None:
        dwell_s = _tsi_conditioner_frequency_default_dwell(dashboard)

    frequency_text = _tsi_conditioner_parse_frequency_mhz(frequency_mhz)
    dwell_text = str(dwell_s or "").strip() or "10"
    power_text = str(power_db or "").strip()
    time_text = str(time_text or "").strip()

    current_row = table.currentRow()

    if current_row < 0:
        insert_row = table.rowCount()
    else:
        insert_row = current_row + 1

    table.insertRow(insert_row)

    values = [
        frequency_text,
        dwell_text,
        power_text,
        time_text,
    ]

    for col, value in enumerate(values):
        item = QtWidgets.QTableWidgetItem(str(value))
        item.setTextAlignment(QtCore.Qt.AlignCenter)
        table.setItem(insert_row, col, item)

    _tsi_conditioner_resize_frequency_table(dashboard)

    if select_row:
        table.selectRow(insert_row)
        table.setCurrentCell(insert_row, 0)

    update_tsi_conditioner_file_gate(dashboard)

def _tsi_conditioner_resize_frequency_table(dashboard: QtCore.QObject):
    table = _tsi_conditioner_frequency_table(dashboard)

    if table is None:
        return

    table.resizeRowsToContents()
    table.resizeColumnsToContents()

    try:
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setSectionResizeMode(0, QtWidgets.QHeaderView.Stretch)
        table.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        table.horizontalHeader().setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
    except Exception:
        table.horizontalHeader().setStretchLastSection(True)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesApplyToAllClicked(dashboard: QtCore.QObject):
    """
    Applies the default dwell value to all frequency-plan rows.
    """
    table = _tsi_conditioner_frequency_table(dashboard)

    if table is None:
        return

    dwell_text = _tsi_conditioner_frequency_default_dwell(dashboard)

    for row in range(table.rowCount()):
        item = table.item(row, 1)

        if item is None:
            item = QtWidgets.QTableWidgetItem()
            item.setTextAlignment(QtCore.Qt.AlignCenter)
            table.setItem(row, 1, item)

        item.setText(dwell_text)

    _tsi_conditioner_resize_frequency_table(dashboard)
    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesAddClicked(dashboard: QtCore.QObject):
    """
    Adds a manual frequency-plan row.
    """
    _tsi_conditioner_add_frequency_row(
        dashboard,
        frequency_mhz="",
        dwell_s=_tsi_conditioner_frequency_default_dwell(dashboard),
        power_db="",
        time_text="",
        select_row=True,
    )

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesImportTsiClicked(dashboard: QtCore.QObject):
    """
    Imports rows from the TSI Detector results table into the Conditioner
    frequency plan.

    Source table:
        tableWidget1_tsi_wideband

    Expected source columns:
        0 Freq. (MHz)
        1 Power (dB)
        2 Time
    """
    source_table = getattr(dashboard.ui, "tableWidget1_tsi_wideband", None)

    if source_table is None:
        return

    added = 0
    dwell_text = _tsi_conditioner_frequency_default_dwell(dashboard)

    for row in range(source_table.rowCount()):
        freq_item = source_table.item(row, 0)

        if freq_item is None:
            continue

        frequency_mhz = _tsi_conditioner_parse_frequency_mhz(freq_item.text())

        if not frequency_mhz:
            continue

        power_text = ""
        time_text = ""

        if source_table.columnCount() > 1 and source_table.item(row, 1) is not None:
            power_text = source_table.item(row, 1).text()

        if source_table.columnCount() > 2 and source_table.item(row, 2) is not None:
            time_text = source_table.item(row, 2).text()

        _tsi_conditioner_add_frequency_row(
            dashboard,
            frequency_mhz=frequency_mhz,
            dwell_s=dwell_text,
            power_db=power_text,
            time_text=time_text,
            select_row=False,
        )
        added += 1

    if added > 0:
        table = _tsi_conditioner_frequency_table(dashboard)
        if table is not None:
            table.selectRow(table.rowCount() - 1)
            table.setCurrentCell(table.rowCount() - 1, 0)

    _tsi_conditioner_resize_frequency_table(dashboard)
    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesImportTacticalClicked(dashboard: QtCore.QObject):
    """
    Imports rows from the Tactical selected-node detections table into the
    Conditioner frequency plan.

    Source table:
        tableWidget_tactical_node_detections

    Expected source columns:
        0 Frequency
        1 Power
        2 Time
    """
    source_table = getattr(dashboard.ui, "tableWidget_tactical_node_detections", None)

    if source_table is None:
        return

    added = 0
    dwell_text = _tsi_conditioner_frequency_default_dwell(dashboard)

    for row in range(source_table.rowCount()):
        freq_item = source_table.item(row, 0)

        if freq_item is None:
            continue

        frequency_mhz = _tsi_conditioner_parse_frequency_mhz(freq_item.text())

        if not frequency_mhz:
            continue

        power_text = ""
        time_text = ""

        if source_table.columnCount() > 1 and source_table.item(row, 1) is not None:
            power_text = source_table.item(row, 1).text()

        if source_table.columnCount() > 2 and source_table.item(row, 2) is not None:
            time_text = source_table.item(row, 2).text()

        _tsi_conditioner_add_frequency_row(
            dashboard,
            frequency_mhz=frequency_mhz,
            dwell_s=dwell_text,
            power_db=power_text,
            time_text=time_text,
            select_row=False,
        )
        added += 1

    if added > 0:
        table = _tsi_conditioner_frequency_table(dashboard)
        if table is not None:
            table.selectRow(table.rowCount() - 1)
            table.setCurrentCell(table.rowCount() - 1, 0)

    _tsi_conditioner_resize_frequency_table(dashboard)
    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesUpClicked(dashboard: QtCore.QObject):
    """
    Moves the selected frequency-plan row up.
    """
    table = _tsi_conditioner_frequency_table(dashboard)

    if table is None:
        return

    current_row = table.currentRow()

    if current_row <= 0:
        return

    for column in range(table.columnCount()):
        current_item = table.takeItem(current_row, column)
        above_item = table.takeItem(current_row - 1, column)

        table.setItem(current_row, column, above_item)
        table.setItem(current_row - 1, column, current_item)

    table.selectRow(current_row - 1)
    table.setCurrentCell(current_row - 1, max(table.currentColumn(), 0))

    _tsi_conditioner_resize_frequency_table(dashboard)
    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesDownClicked(dashboard: QtCore.QObject):
    """
    Moves the selected frequency-plan row down.
    """
    table = _tsi_conditioner_frequency_table(dashboard)

    if table is None:
        return

    current_row = table.currentRow()

    if current_row < 0 or current_row >= table.rowCount() - 1:
        return

    for column in range(table.columnCount()):
        current_item = table.takeItem(current_row, column)
        below_item = table.takeItem(current_row + 1, column)

        table.setItem(current_row, column, below_item)
        table.setItem(current_row + 1, column, current_item)

    table.selectRow(current_row + 1)
    table.setCurrentCell(current_row + 1, max(table.currentColumn(), 0))

    _tsi_conditioner_resize_frequency_table(dashboard)
    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesRemoveClicked(dashboard: QtCore.QObject):
    """
    Removes the selected frequency-plan row.
    """
    table = _tsi_conditioner_frequency_table(dashboard)

    if table is None:
        return

    current_row = table.currentRow()

    if current_row < 0:
        return

    table.removeRow(current_row)

    if table.rowCount() > 0:
        next_row = min(current_row, table.rowCount() - 1)
        table.selectRow(next_row)
        table.setCurrentCell(next_row, 0)

    _tsi_conditioner_resize_frequency_table(dashboard)
    update_tsi_conditioner_file_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesClearClicked(dashboard: QtCore.QObject):
    """
    Clears the Conditioner frequency plan.
    """
    table = _tsi_conditioner_frequency_table(dashboard)

    if table is None:
        return

    table.setRowCount(0)
    _tsi_conditioner_resize_frequency_table(dashboard)
    update_tsi_conditioner_file_gate(dashboard)

def _tsi_conditioner_node_uid_matches(left: str, right: str) -> bool:
    """
    Returns True when two node UID strings appear to refer to the same node.

    This handles exact UUIDs and the occasional shortened/embedded UUID form
    seen during local-node removal.
    """
    left = str(left or "").strip()
    right = str(right or "").strip()

    if not left or not right:
        return False

    return (
        left == right
        or left.endswith(right)
        or right.endswith(left)
        or left in right
        or right in left
    )

def _tsi_conditioner_selected_node_state(dashboard: QtCore.QObject):
    """
    Returns the cached node_state dict for the selected Dashboard node.

    Supports exact and fuzzy UID matching so local-node remove/update paths do
    not leave stale selected-node state looking valid.
    """
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()

    if not selected_uid:
        return None

    node_states = getattr(dashboard, "node_states", {}) or {}

    if selected_uid in node_states:
        return node_states.get(selected_uid)

    for node_uid, node_state in node_states.items():
        if _tsi_conditioner_node_uid_matches(selected_uid, node_uid):
            return node_state

    return None

def _tsi_conditioner_selected_node_available(dashboard: QtCore.QObject) -> bool:
    """
    Returns True only when the Dashboard has a selected Sensor Node and that
    selected node is still present and not known to be disconnected.
    """
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()

    if not selected_uid:
        return False

    node_states = getattr(dashboard, "node_states", {}) or {}
    node_state = _tsi_conditioner_selected_node_state(dashboard)

    # If node state tracking has started and the selected UID is not present,
    # treat the selected node as stale/unavailable.
    if node_states and node_state is None:
        return False

    if isinstance(node_state, dict) and node_state.get("connected") is False:
        return False

    return True

def _tsi_conditioner_selected_node_is_local(dashboard: QtCore.QObject) -> bool:
    """
    Returns True when the selected Sensor Node is local.
    """
    if not _tsi_conditioner_selected_node_available(dashboard):
        return False

    try:
        return bool(selected_node_is_local(dashboard))
    except Exception:
        selected_ip = str(getattr(dashboard, "selected_node_ip", "") or "").strip().lower()
        return selected_ip == "ipc"

def _tsi_conditioner_allowed_sources_for_selected_node(dashboard: QtCore.QObject):
    """
    Returns the Source Type options allowed by the selected node.

    Local node:
        File, Folder, Frequencies

    Remote node:
        Frequencies only
    """
    if not _tsi_conditioner_selected_node_available(dashboard):
        return []

    if _tsi_conditioner_selected_node_is_local(dashboard):
        return ["File", "Folder", "Frequencies"]

    return ["Frequencies"]

def _tsi_conditioner_selected_node_label(dashboard: QtCore.QObject) -> str:
    """
    Returns a workflow-ribbon label for the selected node.
    """
    if not _tsi_conditioner_selected_node_available(dashboard):
        return "Select Node"

    if _tsi_conditioner_selected_node_is_local(dashboard):
        return "Local"

    settings = getattr(dashboard, "selected_node_settings", {}) or {}
    sensor_settings = settings.get("Sensor Node", {}) or {}

    nickname = str(sensor_settings.get("nickname", "") or "").strip()
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()

    if nickname:
        return nickname

    if selected_uid:
        return selected_uid.split("-")[0]

    return "Remote Node"

def _tsi_conditioner_set_source_combo_items(
    dashboard: QtCore.QObject,
    allowed_sources,
):
    """
    Rebuilds the Conditioner Source Type combo without firing source-change
    logic mid-update.
    """
    combo = dashboard.ui.comboBox_tsi_conditioner_input_source
    current_source = combo.currentText().strip()

    combo.blockSignals(True)
    combo.clear()

    if allowed_sources:
        combo.addItems(allowed_sources)

        if current_source in allowed_sources:
            combo.setCurrentText(current_source)
        else:
            combo.setCurrentText(allowed_sources[0])
    else:
        combo.addItem("Select Node")
        combo.setCurrentText("Select Node")

    combo.blockSignals(False)

def _tsi_conditioner_set_source_page_enabled(
    dashboard: QtCore.QObject,
    enabled: bool,
):
    """
    Enables/disables the Conditioner input-source page controls.
    """
    widget_names = [
        "comboBox_tsi_conditioner_input_source",

        # File / Folder page
        "textEdit_tsi_conditioner_file_path",
        "pushButton_tsi_conditioner_input_folder",
        "pushButton_tsi_conditioner_input_refresh",
        "listWidget_tsi_conditioner_input_files",
        "radioButton_tsi_conditioner_input_extensions_all",
        "radioButton_tsi_conditioner_input_extensions_custom",
        "textEdit_tsi_conditioner_input_extensions",
        "comboBox_tsi_conditioner_input_data_type",
        "textEdit_tsi_conditioner_file_sample_rate",
        "pushButton_tsi_conditioner_input_preview",

        # Frequencies page
        "label2_conditioner_input_frequencies_dwell",
        "pushButton_tsi_conditioner_input_frequencies_apply_to_all",
        "tableWidget_tsi_conditioner_input_frequencies",
        "pushButton_tsi_conditioner_input_frequencies_add",
        "pushButton_tsi_conditioner_input_frequencies_import_tsi",
        "pushButton_tsi_conditioner_input_frequencies_import_tactical",
        "pushButton_tsi_conditioner_input_frequencies_up",
        "pushButton_tsi_conditioner_input_frequencies_down",
        "pushButton_tsi_conditioner_input_frequencies_remove",
        "pushButton_tsi_conditioner_input_frequencies_clear",
    ]

    for widget_name in widget_names:
        widget = getattr(dashboard.ui, widget_name, None)

        if widget is not None:
            widget.setEnabled(enabled)

def update_tsi_conditioner_selected_node_gate(dashboard: QtCore.QObject):
    """
    Gates the Conditioner workflow based on selected Sensor Node state.

    Expected Designer object:
        stackedWidget_tsi_conditioner_node_gate

    Expected pages:
        0 = normal Conditioner workflow
        1 = select-node / no-node page

    Important:
        This function must not clear Conditioner actions or parameters.
        It can be called from heartbeat/status/node refresh paths.

        Selected-node changes should reset Conditioner Section 2 from
        recallSettingsReturn().

        Source Type changes should reset Conditioner Section 2 from
        _slotTSI_ConditionerInputSourceChanged().
    """
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    node_ready = _tsi_conditioner_selected_node_available(dashboard)

    update_tsi_conditioner_run_node_label(dashboard)

    gate_stack = getattr(
        dashboard.ui,
        "stackedWidget_tsi_conditioner_node_gate",
        None,
    )

    # ------------------------------------------------------------
    # Outer workflow gate.
    # ------------------------------------------------------------
    if gate_stack is None:
        dashboard.logger.debug(
            "[Conditioner] stackedWidget_tsi_conditioner_node_gate not found."
        )
    else:
        target_index = 0 if node_ready else 1
        gate_stack.setCurrentIndex(target_index)

        dashboard.logger.debug(
            "[Conditioner] node gate updated: "
            f"selected_uid={selected_uid!r}, "
            f"node_ready={node_ready}, "
            f"target_index={target_index}, "
            f"actual_index={gate_stack.currentIndex()}, "
            f"page_count={gate_stack.count()}"
        )

    # ------------------------------------------------------------
    # No selected/available node.
    #
    # Do not clear actions/parameters here. A transient node refresh or
    # unrelated local-node lifecycle event should not destroy Section 2 state.
    # ------------------------------------------------------------
    if not node_ready:
        _tsi_conditioner_set_source_combo_items(dashboard, [])

        preview_button = getattr(
            dashboard.ui,
            "pushButton_tsi_conditioner_input_preview",
            None,
        )
        if preview_button is not None:
            preview_button.setEnabled(False)

        update_tsi_conditioner_method_hardware_combo(dashboard)
        _tsi_conditioner_update_run_output_mode_gate(dashboard)
        _tsi_conditioner_update_workflow_ribbon(dashboard)
        return

    # ------------------------------------------------------------
    # Selected/available node.
    # Local nodes allow file/folder/frequency sources.
    # Remote nodes allow frequency sources only.
    #
    # This only updates allowed source choices and visible pages. It does not
    # clear actions/parameters.
    # ------------------------------------------------------------
    allowed_sources = _tsi_conditioner_allowed_sources_for_selected_node(dashboard)

    source_combo = dashboard.ui.comboBox_tsi_conditioner_input_source
    current_source = source_combo.currentText().strip()

    source_combo.blockSignals(True)

    _tsi_conditioner_set_source_combo_items(dashboard, allowed_sources)

    current_source = source_combo.currentText().strip()

    if current_source not in allowed_sources and allowed_sources:
        current_source = allowed_sources[0]
        source_combo.setCurrentText(current_source)

    source_combo.blockSignals(False)

    _tsi_conditioner_apply_input_source_page(dashboard)
    _tsi_conditioner_update_run_output_mode_gate(dashboard)
    _tsi_conditioner_update_workflow_ribbon(dashboard)

def _tsi_conditioner_current_combo_data(combo, fallback=""):
    data = combo.currentData()

    if data is not None and str(data).strip():
        return str(data).strip()

    text = combo.currentText().strip().lower()
    return text or fallback

def _tsi_conditioner_selected_method_category(dashboard: QtCore.QObject) -> str:
    return _tsi_conditioner_current_combo_data(
        dashboard.ui.comboBox_tsi_conditioner_method_category,
        "iq",
    )

def _tsi_conditioner_selected_method(dashboard: QtCore.QObject) -> str:
    return _tsi_conditioner_current_combo_data(
        dashboard.ui.comboBox_tsi_conditioner_method_method,
        "signal_conditioning",
    )

def _populate_tsi_conditioner_method_category_combo(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_tsi_conditioner_method_category
    current_data = combo.currentData()

    combo.blockSignals(True)
    combo.clear()

    for data, text in TSI_CONDITIONER_METHOD_CATEGORIES:
        combo.addItem(text, data)

    if current_data:
        index = combo.findData(current_data)
        if index >= 0:
            combo.setCurrentIndex(index)

    combo.blockSignals(False)

def _populate_tsi_conditioner_method_method_combo(dashboard: QtCore.QObject):
    category = _tsi_conditioner_selected_method_category(dashboard)
    methods = TSI_CONDITIONER_METHODS_BY_CATEGORY.get(category, [])

    combo = dashboard.ui.comboBox_tsi_conditioner_method_method
    current_data = combo.currentData()

    combo.blockSignals(True)
    combo.clear()

    for data, text in methods:
        combo.addItem(text, data)

    if current_data:
        index = combo.findData(current_data)
        if index >= 0:
            combo.setCurrentIndex(index)

    combo.blockSignals(False)

def update_tsi_conditioner_method_hardware_combo(dashboard: QtCore.QObject):
    """
    Updates the Conditioner Method hardware combo.

    File / Folder:
      show disabled 'No Hardware Required'

    Frequencies:
      show selected-node TSI hardware
    """
    combo = dashboard.ui.comboBox_tsi_conditioner_method_hardware
    current_hardware = combo.currentText().strip()

    node_ready = _tsi_conditioner_selected_node_available(dashboard)
    requires_hardware = _tsi_conditioner_method_requires_hardware(dashboard)

    combo.blockSignals(True)
    combo.clear()

    if not node_ready:
        combo.addItem("")
        combo.setEnabled(False)
        combo.blockSignals(False)
        return

    if not requires_hardware:
        combo.addItem("No Hardware Required")
        combo.setEnabled(False)
        combo.blockSignals(False)
        return

    hardware_names = []

    try:
        hardware_names = fissure.utils.hardware.selectedNodeHardwareDisplayNames(
            dashboard,
            "tsi",
        )
    except Exception as e:
        dashboard.logger.debug(
            f"[Conditioner] Could not load selected-node hardware: {e}"
        )
        hardware_names = []

    if hardware_names:
        combo.addItems(hardware_names)

        if current_hardware and combo.findText(current_hardware) >= 0:
            combo.setCurrentText(current_hardware)
    else:
        combo.addItem("")

    combo.setEnabled(bool(hardware_names))
    combo.blockSignals(False)

def clear_tsi_conditioner_method_actions(dashboard: QtCore.QObject):
    """
    Clears Conditioner action and parameter state.

    This does not query actions. Querying is button-only.
    """
    combo = dashboard.ui.comboBox_tsi_conditioner_method_action

    combo.blockSignals(True)
    combo.clear()
    combo.blockSignals(False)

    combo.setEnabled(False)

    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setEnabled(False)
    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setText(
        "Query Parameters"
    )

    dashboard.ui.pushButton_tsi_conditioner_method_query_actions.setEnabled(True)
    dashboard.ui.pushButton_tsi_conditioner_method_query_actions.setText(
        "Query Actions"
    )

    dashboard.tsi_conditioner_method_actions = []
    dashboard.tsi_conditioner_selected_plugin = ""
    dashboard.tsi_conditioner_selected_action = ""

    dashboard.tsi_conditioner_action_query_pending = False
    dashboard.tsi_conditioner_action_query_context = ""
    dashboard.tsi_conditioner_action_query_node_uid = ""

    clear_tsi_conditioner_method_parameter_controls(dashboard)

def clear_tsi_conditioner_method_parameter_controls(dashboard: QtCore.QObject):
    """
    Clears Conditioner method parameter widgets.
    """
    scroll_area = dashboard.ui.scrollArea_tsi_conditioner_method
    contents = scroll_area.widget()

    if contents is None:
        dashboard.logger.debug(
            "[Conditioner] scrollArea_tsi_conditioner_method has no contents widget."
        )
        dashboard.tsi_conditioner_method_parameter_widgets = {}
        dashboard.tsi_conditioner_method_current_schema = {}
        dashboard.tsi_conditioner_method_customized = False
        return

    contents.setObjectName("scrollAreaWidgetContents_tsi_conditioner_parameters")
    contents.setAutoFillBackground(False)

    layout = contents.layout()

    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    _clear_layout_widgets(layout)

    layout.setContentsMargins(12, 10, 12, 10)
    layout.setHorizontalSpacing(8)
    layout.setVerticalSpacing(7)
    layout.setAlignment(QtCore.Qt.AlignTop)

    contents.setMaximumWidth(430)

    scroll_area.setWidgetResizable(True)
    scroll_area.setAlignment(QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop)
    scroll_area.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    scroll_area.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)

    dashboard.tsi_conditioner_method_parameter_widgets = {}
    dashboard.tsi_conditioner_method_current_schema = {}
    dashboard.tsi_conditioner_method_customized = False

def _slotTSI_ConditionerMethodCategoryChanged(dashboard: QtCore.QObject):
    _populate_tsi_conditioner_method_method_combo(dashboard)
    clear_tsi_conditioner_method_actions(dashboard)
    _tsi_conditioner_update_workflow_ribbon(dashboard)

def _slotTSI_ConditionerMethodMethodChanged(dashboard: QtCore.QObject):
    clear_tsi_conditioner_method_actions(dashboard)
    _tsi_conditioner_update_workflow_ribbon(dashboard)

def _slotTSI_ConditionerMethodHardwareChanged(dashboard: QtCore.QObject):
    clear_tsi_conditioner_method_actions(dashboard)
    _tsi_conditioner_update_workflow_ribbon(dashboard)

def _slotTSI_ConditionerMethodActionChanged(dashboard: QtCore.QObject):
    record = dashboard.ui.comboBox_tsi_conditioner_method_action.currentData()

    clear_tsi_conditioner_method_parameter_controls(dashboard)

    if not isinstance(record, dict):
        dashboard.tsi_conditioner_selected_plugin = ""
        dashboard.tsi_conditioner_selected_action = ""
        dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setEnabled(False)
        _tsi_conditioner_update_workflow_ribbon(dashboard)
        return

    plugin_name = str(record.get("plugin", "")).strip()
    action_name = str(record.get("action", "")).strip()

    dashboard.tsi_conditioner_selected_plugin = plugin_name
    dashboard.tsi_conditioner_selected_action = action_name

    has_action = bool(plugin_name and action_name)
    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setEnabled(has_action)

    _tsi_conditioner_update_workflow_ribbon(dashboard)

@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_ConditionerMethodQueryActionsClicked(dashboard: QtCore.QObject):
    """
    Queries Conditioner actions.

    This function should only be connected to the Query Actions button.
    Source changes, node changes, hardware refreshes, and heartbeat updates
    must not call this function.
    """
    uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()

    if not uid:
        dashboard.logger.warning(
            "[Conditioner] Select a sensor node before querying Conditioner actions."
        )
        return

    category = _tsi_conditioner_selected_method_category(dashboard)
    method = _tsi_conditioner_selected_method(dashboard)
    source = _tsi_conditioner_current_source(dashboard)
    source_tag = _tsi_conditioner_selected_source_tag(dashboard)
    hardware = _tsi_conditioner_selected_method_hardware(dashboard)

    include_tags = [
        "tsi.conditioner",
        f"tsi.conditioner.category.{category}",
        f"tsi.conditioner.method.{method}",
    ]

    if source_tag:
        include_tags.append(source_tag)

    context_source = source.lower().replace(" ", "_")
    context = f"tsi.conditioner.{category}.{method}.{context_source}"

    clear_tsi_conditioner_method_actions(dashboard)

    dashboard.tsi_conditioner_action_query_pending = True
    dashboard.tsi_conditioner_action_query_context = context
    dashboard.tsi_conditioner_action_query_node_uid = uid

    dashboard.ui.comboBox_tsi_conditioner_method_action.setEnabled(False)
    dashboard.ui.pushButton_tsi_conditioner_method_query_actions.setEnabled(False)
    dashboard.ui.pushButton_tsi_conditioner_method_query_actions.setText("Querying...")

    dashboard.logger.debug(
        "[Conditioner] Querying actions: "
        f"uid={uid!r}, "
        f"context={context!r}, "
        f"include_tags={include_tags!r}, "
        f"hardware={hardware!r}"
    )

    await dashboard.backend.queryPluginActions(
        uid=uid,
        context=context,
        scope="all_plugins",
        plugin_name="",
        include_tags=include_tags,
        exclude_tags=[],
        hardware=hardware,
    )

def handle_tsi_conditioner_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str,
    context: str,
    actions: list,
):
    """
    Handles Conditioner action-query results.

    The Query Actions button sends the request. This function receives the
    async result and populates the action combo only if the result still matches
    the latest pending Conditioner query.
    """
    expected_context = str(
        getattr(dashboard, "tsi_conditioner_action_query_context", "") or ""
    )
    expected_node_uid = str(
        getattr(dashboard, "tsi_conditioner_action_query_node_uid", "") or ""
    )
    result_context = str(context or "")
    result_node_uid = str(node_uid or "")

    query_pending = bool(
        getattr(dashboard, "tsi_conditioner_action_query_pending", False)
    )

    if (
        not query_pending
        or result_context != expected_context
        or result_node_uid != expected_node_uid
    ):
        dashboard.logger.debug(
            "[Conditioner] Ignoring stale action query results: "
            f"node_uid={result_node_uid!r}, "
            f"context={result_context!r}, "
            f"expected_node_uid={expected_node_uid!r}, "
            f"expected_context={expected_context!r}, "
            f"query_pending={query_pending}"
        )
        return

    dashboard.tsi_conditioner_action_query_pending = False
    dashboard.tsi_conditioner_action_query_context = ""
    dashboard.tsi_conditioner_action_query_node_uid = ""

    combo = dashboard.ui.comboBox_tsi_conditioner_method_action

    dashboard.tsi_conditioner_method_actions = actions or []

    combo.blockSignals(True)
    combo.clear()

    for action_record in dashboard.tsi_conditioner_method_actions:
        plugin_name = str(action_record.get("plugin", "")).strip()
        action_name = str(action_record.get("action", "")).strip()

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
    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setEnabled(
        has_actions
    )
    dashboard.ui.pushButton_tsi_conditioner_method_query_actions.setText(
        "Query Actions"
    )
    dashboard.ui.pushButton_tsi_conditioner_method_query_actions.setEnabled(True)

    if has_actions:
        combo.setCurrentIndex(0)
        _slotTSI_ConditionerMethodActionChanged(dashboard)
    else:
        dashboard.tsi_conditioner_selected_plugin = ""
        dashboard.tsi_conditioner_selected_action = ""

    _tsi_conditioner_update_workflow_ribbon(dashboard)

@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_ConditionerMethodQueryParametersClicked(dashboard: QtCore.QObject):
    uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    record = dashboard.ui.comboBox_tsi_conditioner_method_action.currentData()

    if not uid:
        dashboard.logger.warning(
            "[Conditioner] Select a sensor node before querying Conditioner parameters."
        )
        return

    if not isinstance(record, dict):
        dashboard.logger.warning(
            "[Conditioner] Select a Conditioner action before querying parameters."
        )
        return

    plugin_name = str(record.get("plugin", "")).strip()
    action_name = str(record.get("action", "")).strip()

    if not plugin_name or not action_name:
        dashboard.logger.warning(
            "[Conditioner] Selected Conditioner action is missing plugin/action information."
        )
        return

    dashboard.tsi_conditioner_method_customized = False
    dashboard.tsi_conditioner_selected_plugin = plugin_name
    dashboard.tsi_conditioner_selected_action = action_name

    clear_tsi_conditioner_method_parameter_controls(dashboard)

    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setEnabled(False)
    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setText("Loading...")

    await dashboard.backend.queryPluginActionSchema(
        uid=uid,
        plugin_name=plugin_name,
        action_name=action_name,
        context="tsi.conditioner",
    )

def handle_tsi_conditioner_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str,
    action_name: str,
    node_uid: str,
    parameters: list,
):
    parameters = parameters or []

    selected_record = dashboard.ui.comboBox_tsi_conditioner_method_action.currentData()

    selected_plugin = ""
    selected_action = ""

    if isinstance(selected_record, dict):
        selected_plugin = str(selected_record.get("plugin", "")).strip()
        selected_action = str(selected_record.get("action", "")).strip()

    plugin_name = str(plugin_name or "").strip()
    action_name = str(action_name or "").strip()

    if selected_plugin != plugin_name or selected_action != action_name:
        dashboard.logger.debug(
            f"[Conditioner] Ignoring stale schema for "
            f"{plugin_name}.{action_name}; "
            f"selected={selected_plugin}.{selected_action}"
        )

        dashboard.tsi_conditioner_method_customized = False
        dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setText(
            "Query Parameters"
        )
        dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setEnabled(
            bool(selected_plugin and selected_action)
        )
        return

    clear_tsi_conditioner_method_parameter_controls(dashboard)

    dashboard.tsi_conditioner_selected_plugin = plugin_name
    dashboard.tsi_conditioner_selected_action = action_name

    dashboard.tsi_conditioner_method_current_schema = {
        "plugin": plugin_name,
        "action": action_name,
        "node_uid": node_uid,
        "params": parameters,
    }

    dashboard.tsi_conditioner_method_parameter_widgets = {}

    _render_tsi_conditioner_method_parameter_widgets(
        dashboard,
        parameters,
    )

    dashboard.tsi_conditioner_method_customized = True

    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setText(
        "Query Parameters"
    )
    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setEnabled(True)

    _tsi_conditioner_update_workflow_ribbon(dashboard)

def _render_tsi_conditioner_method_parameter_widgets(
    dashboard: QtCore.QObject,
    parameters: list,
):
    """
    Renders Conditioner method parameters in the existing scroll area contents.
    """
    clear_tsi_conditioner_method_parameter_controls(dashboard)

    scroll_area = dashboard.ui.scrollArea_tsi_conditioner_method
    contents = scroll_area.widget()

    if contents is None:
        dashboard.logger.debug(
            "[Conditioner] Cannot render parameters because scroll area has no contents widget."
        )
        return

    layout = contents.layout()

    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    visible_params = [
        p for p in parameters
        if str(p.get("name", "")).strip() != "description"
    ]

    for row, param in enumerate(visible_params):
        name = str(param.get("name", "")).strip()

        if not name:
            continue

        label_text = str(param.get("label") or name).strip()
        widget = _create_tsi_conditioner_method_parameter_widget(
            dashboard,
            param,
        )

        label = QtWidgets.QLabel(label_text + ":", contents)
        label.setObjectName("label2_tsi_conditioner_method_parameter")
        label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        label.setFixedWidth(160)

        layout.addWidget(label, row, 0)
        layout.addWidget(widget, row, 1)

        dashboard.tsi_conditioner_method_parameter_widgets[name] = widget

    layout.setColumnMinimumWidth(0, 160)
    layout.setColumnMinimumWidth(1, 180)
    layout.setColumnStretch(0, 0)
    layout.setColumnStretch(1, 0)

def _create_tsi_conditioner_method_parameter_widget(
    dashboard: QtCore.QObject,
    param: dict,
):
    param_name = str(param.get("name", "")).strip()
    param_type = str(param.get("type", "string") or "string").lower()
    default = param.get("default", "")
    options = param.get("options", []) or []

    compact_width = 170

    if param_type == "label":
        widget = QtWidgets.QLabel(str(default))
        widget.setObjectName(
            "label2_tsi_conditioner_method_parameter_value"
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

    if param_type in {"int", "integer", "number", "float", "double"}:
        widget = QtWidgets.QDoubleSpinBox()
        widget.setObjectName("doubleSpinBox_tsi_conditioner_method_parameter")

        widget.setDecimals(_safe_int(param.get("decimals"), 3))
        widget.setMinimum(_safe_float(param.get("min"), -999999999.0))
        widget.setMaximum(_safe_float(param.get("max"), 999999999.0))
        widget.setSingleStep(_safe_float(param.get("step"), 1.0))
        widget.setValue(_safe_float(default, 0.0))

        if param_type in {"int", "integer"}:
            widget.setDecimals(0)

        widget.setFixedWidth(compact_width)
        widget.setButtonSymbols(QtWidgets.QAbstractSpinBox.UpDownArrows)
        widget.setAlignment(QtCore.Qt.AlignRight)
        return widget

    if param_type in {"bool", "boolean"}:
        widget = QtWidgets.QCheckBox()
        widget.setObjectName("checkBox_tsi_conditioner_method_parameter")
        widget.setChecked(
            str(default).strip().lower() in {"1", "true", "yes", "on"}
        )
        widget.setFixedWidth(compact_width)
        return widget

    if options:
        widget = QtWidgets.QComboBox()
        widget.setObjectName("comboBox_tsi_conditioner_method_parameter")
        widget.addItems([str(option) for option in options])

        default_text = str(default)
        index = widget.findText(default_text)

        if index >= 0:
            widget.setCurrentIndex(index)

        widget.setFixedWidth(compact_width)
        return widget

    widget = QtWidgets.QLineEdit()
    widget.setObjectName("lineEdit_tsi_conditioner_method_parameter")
    widget.setText(str(default))
    widget.setFixedWidth(compact_width)
    return widget

def _tsi_conditioner_method_requires_hardware(dashboard: QtCore.QObject) -> bool:
    """
    Returns True when the selected Conditioner source requires selected-node
    SDR hardware.

    File / Folder:
      no SDR hardware required

    Frequencies:
      selected-node SDR hardware required
    """
    return _tsi_conditioner_current_source(dashboard) == "Frequencies"

def _tsi_conditioner_selected_source_tag(dashboard: QtCore.QObject) -> str:
    """
    Returns the source-specific plugin-action tag for the selected Conditioner
    input source.
    """
    source = _tsi_conditioner_current_source(dashboard)

    source_tags = {
        "File": "tsi.conditioner.source.file",
        "Folder": "tsi.conditioner.source.folder",
        "Frequencies": "tsi.conditioner.source.frequencies",
    }

    return source_tags.get(source, "")

def _tsi_conditioner_selected_method_hardware(dashboard: QtCore.QObject) -> str:
    """
    Returns the Conditioner hardware filter.

    Empty string means no hardware filter.
    """
    if not _tsi_conditioner_method_requires_hardware(dashboard):
        return ""

    combo = dashboard.ui.comboBox_tsi_conditioner_method_hardware
    hardware = combo.currentText().strip()

    if hardware in ["", "No Hardware Required", "—"]:
        return ""

    return hardware

def _tsi_conditioner_apply_input_source_page(dashboard: QtCore.QObject):
    """
    Applies the current Conditioner input source to the input stacked widget
    without clearing queried actions or rendered parameters.
    """
    source = _tsi_conditioner_current_source(dashboard)

    if source in ["File", "Folder"]:
        dashboard.ui.stackedWidget_tsi_conditioner_input.setCurrentIndex(0)

    elif source == "Frequencies":
        dashboard.ui.stackedWidget_tsi_conditioner_input.setCurrentIndex(1)

    update_tsi_conditioner_method_hardware_combo(dashboard)
    update_tsi_conditioner_file_gate(dashboard)

def _clear_layout_widgets(layout: QtWidgets.QLayout):
    """
    Removes all widgets and child layouts from a layout.
    """
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
            _clear_layout_widgets(child_layout)

def reset_tsi_conditioner_method_for_selected_node_change(
    dashboard: QtCore.QObject,
):
    """
    Resets Conditioner Section 2 after the selected Sensor Node changes.

    This is intentionally explicit. Selected-node changes invalidate queried
    actions and rendered parameters, even if the new node has the same hardware
    display text.
    """
    clear_tsi_conditioner_method_actions(dashboard)

    dashboard.ui.pushButton_tsi_conditioner_method_query_actions.setText(
        "Query Actions"
    )
    dashboard.ui.pushButton_tsi_conditioner_method_query_actions.setEnabled(True)

    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setText(
        "Query Parameters"
    )
    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.setEnabled(False)

    _tsi_conditioner_update_workflow_ribbon(dashboard)

def _tsi_conditioner_get_run_output_folder(dashboard: QtCore.QObject) -> str:
    """
    Returns the full Conditioner run output folder.

    The visible text edit may contain a shortened display path, so prefer the
    stored full path when available.
    """
    folder = str(
        getattr(dashboard, "tsi_conditioner_run_output_folder", "") or ""
    ).strip()

    if folder:
        return folder

    text_edit = getattr(
        dashboard.ui,
        "textEdit_tsi_conditioner_run_output_folder",
        None,
    )

    if text_edit is None:
        return ""

    return text_edit.toPlainText().strip()

def _tsi_conditioner_set_run_output_folder(
    dashboard: QtCore.QObject,
    folder: str,
):
    """
    Stores the full Conditioner run output folder and displays a shortened
    version in the Section 3 text edit.
    """
    folder = os.path.abspath(str(folder or "").strip())

    dashboard.tsi_conditioner_run_output_folder = folder

    text_edit = getattr(
        dashboard.ui,
        "textEdit_tsi_conditioner_run_output_folder",
        None,
    )

    if text_edit is None:
        return

    text_edit.blockSignals(True)
    text_edit.setPlainText(_tsi_conditioner_shorten_path(folder))
    text_edit.setToolTip(folder)
    text_edit.blockSignals(False)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerRunBrowseClicked(dashboard: QtCore.QObject):
    """
    Selects the Conditioner run output folder.

    Disabled for Artifact mode because artifacts are FISSURE-managed and must
    go under FISSURE_ROOT/artifacts/<operation_id>/files.
    """
    if _tsi_conditioner_output_mode_is_artifact(dashboard):
        _tsi_conditioner_set_run_status(
            dashboard,
            "Artifact output uses managed FISSURE artifact storage.",
        )
        _tsi_conditioner_update_run_output_mode_gate(dashboard)
        return

    current_folder = _tsi_conditioner_get_run_output_folder(dashboard)

    if not current_folder or not os.path.isdir(current_folder):
        current_folder = os.path.join(
            fissure.utils.FISSURE_ROOT,
            "Conditioner Data",
            "Output",
        )

    if not os.path.isdir(current_folder):
        current_folder = fissure.utils.FISSURE_ROOT

    selected_dir = QtWidgets.QFileDialog.getExistingDirectory(
        dashboard,
        "Select IQ Output Folder",
        current_folder,
    )

    if not selected_dir:
        return

    _tsi_conditioner_set_run_output_folder(dashboard, selected_dir)
    _tsi_conditioner_update_workflow_ribbon(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerRunNowClicked(dashboard: QtCore.QObject):
    """
    Generates a timestamped Conditioner run file prefix.
    """
    now = datetime.datetime.now()
    prefix = now.strftime("%Y-%m-%d_%H:%M:%S") + "_"

    text_edit = getattr(
        dashboard.ui,
        "textEdit_tsi_conditioner_run_file_prefix",
        None,
    )

    if text_edit is not None:
        text_edit.setPlainText(prefix)

def update_tsi_conditioner_run_node_label(dashboard: QtCore.QObject):
    """
    Updates Section 3 run node label from the selected Sensor Node.
    """
    label = getattr(dashboard.ui, "label2_tsi_conditioner_run_node", None)
    if label is None:
        return

    node_label = _tsi_conditioner_selected_node_label(dashboard)
    label.setText(node_label)
    label.setToolTip(node_label)

def _tsi_conditioner_set_run_button_state(
    dashboard: QtCore.QObject,
    running: bool,
):
    """
    Updates the Conditioner Section 3 Start/Stop button.
    """
    button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_run_start_stop",
        None,
    )

    if button is None:
        return

    button.setText("Stop" if running else "Start")
    button.setProperty("running", "true" if running else "false")
    button.style().unpolish(button)
    button.style().polish(button)

def _tsi_conditioner_set_run_status(
    dashboard: QtCore.QObject,
    status: str,
):
    """
    Updates the Conditioner Section 3 status label.
    """
    status = str(status or "").strip()

    label = getattr(dashboard.ui, "label2_tsi_conditioner_run_status", None)

    if label is not None:
        label.setText(status)
        label.setToolTip(status)
        return

def _tsi_conditioner_get_method_parameter_values(
    dashboard: QtCore.QObject,
) -> dict:
    """
    Collects current Section 2 generated action parameter values.
    """
    values = {}

    widgets = getattr(
        dashboard,
        "tsi_conditioner_method_parameter_widgets",
        {},
    ) or {}

    for name, widget in widgets.items():
        if isinstance(widget, QtWidgets.QDoubleSpinBox):
            if widget.decimals() == 0:
                values[name] = int(widget.value())
            else:
                values[name] = float(widget.value())

        elif isinstance(widget, QtWidgets.QSpinBox):
            values[name] = int(widget.value())

        elif isinstance(widget, QtWidgets.QComboBox):
            values[name] = widget.currentText().strip()

        elif isinstance(widget, QtWidgets.QLineEdit):
            values[name] = widget.text().strip()

        elif isinstance(widget, QtWidgets.QTextEdit):
            values[name] = widget.toPlainText().strip()

        elif isinstance(widget, QtWidgets.QCheckBox):
            values[name] = widget.isChecked()

    return values

def _tsi_conditioner_get_input_filepaths_for_run(
    dashboard: QtCore.QObject,
) -> list:
    """
    Returns Conditioner input paths for the current source type.

    First implementation:
      File   -> selected file only
      Folder -> every visible file in the input list
    """
    source = _tsi_conditioner_current_source(dashboard)
    filepaths = []

    if source == "File":
        filepath = _tsi_conditioner_selected_input_file(dashboard)
        if filepath and os.path.isfile(filepath):
            filepaths.append(filepath)

    elif source == "Folder":
        folder = _tsi_conditioner_get_input_folder(dashboard)
        list_widget = dashboard.ui.listWidget_tsi_conditioner_input_files

        for row in range(list_widget.count()):
            item = list_widget.item(row)
            if item is None:
                continue

            filepath = os.path.join(folder, item.text())
            if os.path.isfile(filepath):
                filepaths.append(filepath)

    return filepaths

def _tsi_conditioner_samples_from_size(
    size_bytes: int,
    data_type: str,
) -> int:
    """
    Converts file size to sample count for display.
    """
    bytes_per_sample = {
        "Complex Float 32": 8,
        "Float/Float 32": 4,
        "Short/Int 16": 2,
        "Int/Int 32": 4,
        "Byte/Int 8": 1,
        "Complex Int 16": 4,
        "Complex Int 8": 2,
        "Complex Float 64": 16,
        "Complex Int 64": 16,
    }.get(str(data_type or "").strip(), 1)

    return int(size_bytes / bytes_per_sample)

@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_ConditionerRunStartStopClicked(
    dashboard: QtCore.QObject,
):
    """
    Starts/stops the selected Conditioner action on the selected Sensor Node.

    Output policy:
        Local Folder:
            use Dashboard-selected output_directory.

        Artifact:
            do not send output_directory. The Sensor Node operation must write
            to FISSURE_ROOT/artifacts/<operation_id>/files.

    The Dashboard assigns operation_id before execution and passes it to the
    action. Artifact metadata returns are only allowed to finish this run when
    their operation_id matches dashboard.tsi_conditioner_opid.
    """
    uid = str(
        getattr(dashboard, "selected_node_uid", "") or ""
    ).strip()

    if not uid:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Select a Sensor Node before starting the Conditioner.",
        )
        return

    if bool(getattr(dashboard, "tsi_conditioner_running", False)):
        try:
            _tsi_conditioner_set_run_status(
                dashboard,
                "Stopping Conditioner action...",
            )

            await dashboard.backend.tacticalNodeStop([uid])

        finally:
            dashboard.tsi_conditioner_running = False
            dashboard.tsi_conditioner_node_uid = ""
            dashboard.tsi_conditioner_opid = ""
            dashboard.tsi_conditioner_waiting_for_opid = False

            _tsi_conditioner_set_run_button_state(
                dashboard,
                False,
            )

            progress_bar = getattr(
                dashboard.ui,
                "progressBar_tsi_conditioner_run_progress",
                None,
            )
            if progress_bar is not None:
                progress_bar.setRange(0, 100)
                progress_bar.setValue(0)

            _tsi_conditioner_set_run_status(
                dashboard,
                "Stopped",
            )

            if hasattr(dashboard, "refreshStatusBarText"):
                dashboard.refreshStatusBarText()

        return

    _tsi_conditioner_update_run_output_mode_gate(dashboard)

    plugin_name = str(
        getattr(dashboard, "tsi_conditioner_selected_plugin", "") or ""
    ).strip()

    action_name = str(
        getattr(dashboard, "tsi_conditioner_selected_action", "") or ""
    ).strip()

    if not plugin_name or not action_name:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Query and select a Conditioner action before starting.",
        )
        return

    if not bool(getattr(dashboard, "tsi_conditioner_method_customized", False)):
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Query Conditioner parameters before starting.",
        )
        return

    method = str(
        _tsi_conditioner_selected_method(dashboard) or ""
    ).strip()

    method_id = (
        method
        .lower()
        .replace(" ", "_")
        .replace("-", "_")
    )

    if method_id != "normal_decay":
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "This first-pass Conditioner runner currently supports Normal Decay only.",
        )
        return

    source_type = _tsi_conditioner_selected_source_type(dashboard)
    input_files = []
    frequency_plan = []

    if source_type in ["file", "folder"]:
        input_files = _tsi_conditioner_get_input_filepaths_for_run(
            dashboard,
        )

        if not input_files:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                "Select at least one Conditioner input file.",
            )
            return

    elif source_type == "frequencies":
        frequency_plan = _tsi_conditioner_get_frequency_plan_for_run(
            dashboard,
        )

        if not frequency_plan:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                "Add at least one Conditioner frequency row.",
            )
            return

    output_mode = _tsi_conditioner_get_run_output_mode(dashboard)
    output_dir = ""

    if output_mode == "Local Folder":
        output_dir = _tsi_conditioner_get_run_output_folder(dashboard)

        if not output_dir:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                "Select a Conditioner output folder.",
            )
            return

        try:
            os.makedirs(
                output_dir,
                exist_ok=True,
            )
        except Exception as e:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                f"Could not create Conditioner output folder:\n{e}",
            )
            return

    operation_id = str(uuid.uuid4())

    try:
        output_format = str(
            dashboard.ui.comboBox_tsi_conditioner_run_output_format.currentText()
        ).strip()

        prefix = str(
            dashboard.ui.textEdit_tsi_conditioner_run_file_prefix.toPlainText()
        ).strip()

        parameters = _tsi_conditioner_get_method_parameter_values(
            dashboard,
        )

        # Section 3 is the only authority for saturation checking.
        # Remove anything that came from queried action defaults, legacy
        # Conditioner settings, previous UI state, or old metadata workflows.
        for stale_key in (
            "check_saturation",
            "saturation_check",
            "detect_saturation",
            "saturation_min",
            "saturation_max",
        ):
            parameters.pop(stale_key, None)

        parameters["operation_id"] = operation_id
        parameters["source_type"] = source_type
        parameters["category"] = _tsi_conditioner_selected_method_category(
            dashboard,
        )
        parameters["method"] = method_id
        parameters["output_mode"] = output_mode
        parameters["output_format"] = output_format or "Raw IQ Files"
        parameters["prefix"] = prefix

        if output_mode == "Local Folder":
            parameters["output_directory"] = output_dir
        else:
            parameters["output_directory"] = ""

        if source_type in ["file", "folder"]:
            parameters["all_filepaths"] = input_files

        elif source_type == "frequencies":
            parameters["frequency_plan"] = frequency_plan

            if frequency_plan:
                parameters["frequency_mhz"] = frequency_plan[0]["frequency_mhz"]
                parameters["dwell_s"] = frequency_plan[0]["dwell_s"]

        parameters.setdefault("data_type", "Complex Float 32")
        parameters.setdefault("sample_rate", 1000000.0)
        parameters.setdefault("min_samples", 1)
        parameters.setdefault("max_files", 15)

        check_saturation = _tsi_conditioner_get_run_saturation_check_enabled(
            dashboard,
        )

        parameters["check_saturation"] = bool(check_saturation)
        parameters["saturation_check"] = (
            "full"
            if check_saturation
            else "none"
        )

        saturation_combo = getattr(
            dashboard.ui,
            "comboBox_tsi_conditioner_run_saturation_check",
            None,
        )

        dashboard.logger.info(
            "[Conditioner] Final saturation params: combo_text=%r "
            "check_saturation=%s saturation_check=%s",
            saturation_combo.currentText() if saturation_combo is not None else "",
            parameters.get("check_saturation"),
            parameters.get("saturation_check"),
        )

    except Exception as e:
        dashboard.logger.error(
            f"[Conditioner] Could not collect Conditioner parameters: {e}"
        )

        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Could not collect Conditioner parameters.",
        )
        return

    latest_metadata_path = _tsi_conditioner_latest_metadata_path(
        dashboard,
    )

    if latest_metadata_path and os.path.isfile(latest_metadata_path):
        try:
            os.remove(latest_metadata_path)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Could not remove stale run metadata "
                f"{latest_metadata_path}: {e}"
            )

    dashboard.tsi_conditioner_run_started_at = time.time()
    dashboard.tsi_conditioner_running = True
    dashboard.tsi_conditioner_node_uid = uid
    dashboard.tsi_conditioner_opid = operation_id
    dashboard.tsi_conditioner_waiting_for_opid = False
    dashboard.tsi_conditioner_last_artifact_id = ""
    dashboard.tsi_conditioner_last_artifact_payload = {}
    dashboard.tsi_conditioner_last_artifact_metadata_request_at = 0.0

    table = getattr(
        dashboard.ui,
        "tableWidget_tsi_conditioner_results",
        None,
    )
    if table is not None:
        table.setRowCount(0)

    count_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_results_file_count",
        None,
    )
    if count_label is not None:
        count_label.setText("File Count: 0")

    _tsi_conditioner_mark_results_unpromoted(dashboard)

    _tsi_conditioner_set_run_button_state(
        dashboard,
        True,
    )

    progress_bar = getattr(
        dashboard.ui,
        "progressBar_tsi_conditioner_run_progress",
        None,
    )
    if progress_bar is not None:
        progress_bar.setRange(0, 100)
        progress_bar.setValue(1)

    _tsi_conditioner_set_run_status(
        dashboard,
        "Starting Conditioner action...",
    )

    artifact_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_run_artifact_id",
        None,
    )
    if artifact_label is not None:
        artifact_label.setText("—")
        artifact_label.setToolTip("")

    download_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_run_download_artifact",
        None,
    )
    if download_button is not None:
        download_button.setEnabled(False)

    dashboard.logger.info(
        "[Conditioner] Starting operation_id=%s node_uid=%s plugin=%s "
        "action=%s output_mode=%s check_saturation=%s saturation_check=%s",
        operation_id,
        uid,
        plugin_name,
        action_name,
        output_mode,
        parameters.get("check_saturation"),
        parameters.get("saturation_check"),
    )

    try:
        await dashboard.backend.tacticalNodeExecute(
            [uid],
            plugin_name,
            action_name,
            parameters,
        )

    except Exception as e:
        dashboard.logger.error(
            f"[Conditioner] Failed starting Conditioner action: {e}"
        )

        dashboard.tsi_conditioner_running = False
        dashboard.tsi_conditioner_node_uid = ""
        dashboard.tsi_conditioner_opid = ""
        dashboard.tsi_conditioner_waiting_for_opid = False

        _tsi_conditioner_set_run_button_state(
            dashboard,
            False,
        )

        progress_bar = getattr(
            dashboard.ui,
            "progressBar_tsi_conditioner_run_progress",
            None,
        )
        if progress_bar is not None:
            progress_bar.setRange(0, 100)
            progress_bar.setValue(0)

        _tsi_conditioner_set_run_status(
            dashboard,
            "Failed to start Conditioner action",
        )

        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            f"Failed starting Conditioner action:\n{e}",
        )
        return

    if hasattr(dashboard, "refreshStatusBarText"):
        dashboard.refreshStatusBarText()

    if (
        output_mode == "Artifact"
        and _tsi_conditioner_selected_node_is_remote(dashboard)
    ):
        dashboard.tsi_conditioner_last_artifact_metadata_request_at = 0.0

    QtCore.QTimer.singleShot(
        1000,
        lambda: _tsi_conditioner_poll_run_completion(dashboard),
    )

def _tsi_conditioner_latest_metadata_path(
    dashboard: QtCore.QObject,
) -> str:
    """
    Returns the expected Conditioner run metadata file path.

    Local Folder:
        <selected output folder>/signal_conditioning_file_artifact.json

    Artifact:
        FISSURE_ROOT/artifacts/<operation_id>/files/
        signal_conditioning_file_artifact.json

    Important:
        Do not fall back to newest local artifact metadata when an operation_id
        exists. The Dashboard assigns operation_id before starting the action,
        so only that operation's metadata is valid for this run.
    """
    output_mode = _tsi_conditioner_get_run_output_mode(dashboard)

    if output_mode == "Artifact":
        operation_id = str(
            getattr(dashboard, "tsi_conditioner_opid", "") or ""
        ).strip()

        if not operation_id:
            return ""

        metadata_path = os.path.join(
            fissure.utils.FISSURE_ROOT,
            "artifacts",
            operation_id,
            "files",
            "signal_conditioning_file_artifact.json",
        )

        if os.path.isfile(metadata_path):
            return metadata_path

        return ""

    output_dir = _tsi_conditioner_get_run_output_folder(dashboard)

    if not output_dir:
        return ""

    return os.path.join(
        output_dir,
        "signal_conditioning_file_artifact.json",
    )

def _tsi_conditioner_read_run_metadata(
    dashboard: QtCore.QObject,
) -> dict:
    """
    Reads the current Conditioner run metadata JSON.

    If dashboard.tsi_conditioner_opid is set, only metadata with that exact
    operation_id is accepted. This prevents stale local/shared artifact metadata
    from completing or overwriting the current run.
    """
    metadata_path = _tsi_conditioner_latest_metadata_path(dashboard)

    if not metadata_path or not os.path.isfile(metadata_path):
        return {}

    active_operation_id = str(
        getattr(dashboard, "tsi_conditioner_opid", "") or ""
    ).strip()

    try:
        with open(metadata_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)

        if not isinstance(payload, dict):
            return {}

        operation_id = str(payload.get("operation_id", "") or "").strip()
        artifact_id = str(payload.get("artifact_id", "") or "").strip()

        if active_operation_id:
            if operation_id != active_operation_id:
                dashboard.logger.info(
                    "[Conditioner] Ignoring metadata with non-matching operation_id: "
                    "payload_opid=%s active_opid=%s path=%s",
                    operation_id,
                    active_operation_id,
                    metadata_path,
                )
                return {}

        elif operation_id:
            dashboard.tsi_conditioner_opid = operation_id
            dashboard.tsi_conditioner_waiting_for_opid = False

        if artifact_id:
            dashboard.tsi_conditioner_last_artifact_id = artifact_id

        dashboard.tsi_conditioner_last_artifact_payload = payload

        return payload

    except Exception as e:
        dashboard.logger.error(
            f"[Conditioner] Failed reading run metadata {metadata_path}: {e}"
        )

    return {}

def _tsi_conditioner_set_results_table_from_payload(
    dashboard: QtCore.QObject,
    payload: dict,
):
    """
    Populates the Conditioner results table from operation metadata.

    Saturated column behavior:
        - missing "saturated" key -> blank
        - bool True/False -> Yes/No
        - existing string -> displayed as-is

    Column 3 is the IQ data type. It must not show SigMF/package format.
    """
    table = getattr(
        dashboard.ui,
        "tableWidget_tsi_conditioner_results",
        None,
    )

    if table is None:
        return

    if not isinstance(payload, dict):
        payload = {}

    files = payload.get("files", []) or []

    if not isinstance(files, list):
        files = []

    headers = [
        "File",
        "Size (MB)",
        "Samples",
        "Format",
        "Sample Rate",
        "Saturated",
        "Frequency",
        "Source",
        "Notes",
    ]

    table.setColumnCount(len(headers))

    for col, header in enumerate(headers):
        table.setHorizontalHeaderItem(
            col,
            QtWidgets.QTableWidgetItem(header),
        )

    table.setRowCount(0)

    payload_data_type = str(
        payload.get("data_type", "") or "Complex Float 32"
    ).strip()

    valid_data_types = {
        "Complex Float 64",
        "Complex Float 32",
        "Float/Float 32",
        "Complex Int 16",
        "Short/Int 16",
        "Complex Int 64",
        "Int/Int 32",
        "Complex Int 8",
        "Byte/Int 8",
        "Unsigned Int 8",
        "Unsigned Int 16",
        "Unsigned Int 32",
        "Complex Unsigned Int 64",
        "Complex Unsigned Int 16",
        "Complex Unsigned Int 8",
    }

    displayed_count = 0

    for file_record in files:
        if not isinstance(file_record, dict):
            continue

        name = str(file_record.get("name", "") or "")
        path = str(file_record.get("path", "") or "")

        try:
            size_bytes = int(file_record.get("size", 0) or 0)
        except Exception:
            size_bytes = 0

        size_mb = ""
        if size_bytes > 0:
            size_mb = str(round(size_bytes / 1048576, 2))

        data_type = str(
            file_record.get("format", "")
            or file_record.get("data_type", "")
            or payload_data_type
            or ""
        ).strip()

        if data_type not in valid_data_types:
            data_type = payload_data_type

        sample_rate = str(
            file_record.get("sample_rate", "")
            or payload.get("sample_rate", "")
            or ""
        )

        saturated_value = ""

        if "saturated" in file_record:
            saturated_raw = file_record.get("saturated")

            if isinstance(saturated_raw, bool):
                saturated_value = "Yes" if saturated_raw else "No"
            else:
                saturated_text = str(saturated_raw or "").strip()
                if saturated_text:
                    saturated_value = saturated_text

        frequency_value = str(
            file_record.get("frequency_mhz", "")
            or payload.get("frequency_mhz", "")
            or ""
        )

        source = str(file_record.get("source", "") or "")
        source_name = str(file_record.get("source_name", "") or "")

        if not source_name and source:
            if os.path.isfile(source) or os.path.sep in source:
                source_name = os.path.basename(source)
            else:
                source_name = source

        notes = str(
            file_record.get("notes", "")
            or file_record.get("note", "")
            or ""
        )

        row_values = [
            name,
            size_mb,
            str(file_record.get("samples", "") or ""),
            data_type,
            sample_rate,
            saturated_value,
            frequency_value,
            source_name,
            notes,
        ]

        row = table.rowCount()
        table.insertRow(row)

        for col, value in enumerate(row_values):
            item = QtWidgets.QTableWidgetItem(str(value))
            item.setTextAlignment(QtCore.Qt.AlignCenter)

            if col == 0:
                item.setData(QtCore.Qt.UserRole, path)
                item.setToolTip(path)

            elif col == 7:
                item.setToolTip(source)

            table.setItem(row, col, item)

        displayed_count += 1

    table.resizeRowsToContents()
    table.resizeColumnsToContents()
    table.horizontalHeader().setStretchLastSection(False)
    table.horizontalHeader().setStretchLastSection(True)

    count_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_results_file_count",
        None,
    )
    if count_label is not None:
        count_label.setText(f"File Count: {displayed_count}")

def _tsi_conditioner_set_run_artifact_state_from_payload(
    dashboard: QtCore.QObject,
    payload: dict,
):
    """
    Update Section 3 artifact controls from operation metadata.

    Download/Open state is based only on the shared Dashboard artifact cache.
    A Sensor Node source directory does not count as a completed download.
    """
    if not isinstance(payload, dict):
        payload = {}

    output_mode = str(
        payload.get("output_mode", "")
        or ""
    ).strip()

    if output_mode == "Local Folder + Artifact":
        output_mode = "Artifact"
        payload["output_mode"] = "Artifact"

    artifact_id = str(
        payload.get("artifact_id", "")
        or ""
    ).strip()

    artifact_enabled = (
        output_mode == "Artifact"
        and bool(artifact_id)
    )

    cached_path = None

    if artifact_enabled:
        try:
            cached_path = (
                dashboard.backend
                .artifact_transfer_controller
                .get_local_path(
                    artifact_id
                )
            )
        except Exception:
            cached_path = None

    dashboard.tsi_conditioner_last_artifact_id = (
        artifact_id
    )
    dashboard.tsi_conditioner_last_artifact_payload = (
        payload
    )

    artifact_title_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_run_artifact_id_label",
        None,
    )
    artifact_value_label = getattr(
        dashboard.ui,
        "label2_tsi_conditioner_run_artifact_id",
        None,
    )

    for label in (
        artifact_title_label,
        artifact_value_label,
    ):
        if label is not None:
            label.setEnabled(
                artifact_enabled
            )

    if artifact_value_label is not None:
        artifact_value_label.setText(
            artifact_id
            if artifact_id
            else "—"
        )
        artifact_value_label.setToolTip(
            str(
                cached_path
                or artifact_id
                or ""
            )
        )

    download_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_run_download_artifact",
        None,
    )

    if download_button is not None:
        download_button.setEnabled(
            artifact_enabled
        )
        download_button.setText(
            "Open Artifact"
            if cached_path
            else "Download Artifact"
        )
        download_button.setToolTip(
            str(
                cached_path
                or (
                    "Download artifact to the Dashboard cache"
                    if artifact_enabled
                    else ""
                )
            )
        )

    _tsi_conditioner_update_results_action_gate(
        dashboard
    )

def _tsi_conditioner_set_run_finished_from_payload(
    dashboard: QtCore.QObject,
    payload: dict,
):
    """
    Finishes the Section 3 run UI from operation metadata.

    Artifact mode additionally requests a Tactical artifact metadata refresh
    through the existing HIPRFISR ArtifactTracker path. This matters for
    same-filesystem remote tests where the Conditioner table can finish from
    local metadata before the remote-artifact polling branch runs.
    """
    if not isinstance(payload, dict):
        payload = {}

    file_count = int(payload.get("file_count", 0) or 0)

    _tsi_conditioner_set_results_table_from_payload(dashboard, payload)
    _tsi_conditioner_set_run_artifact_state_from_payload(dashboard, payload)
    _tsi_conditioner_update_results_action_gate(dashboard)

    _tsi_conditioner_request_artifact_refresh_for_payload(
        dashboard,
        payload,
    )

    progress_bar = getattr(
        dashboard.ui,
        "progressBar_tsi_conditioner_run_progress",
        None,
    )
    if progress_bar is not None:
        progress_bar.setRange(0, 100)
        progress_bar.setValue(100)

    _tsi_conditioner_set_run_status(
        dashboard,
        f"Complete: {file_count} files",
    )

    dashboard.tsi_conditioner_running = False
    dashboard.tsi_conditioner_node_uid = ""
    dashboard.tsi_conditioner_waiting_for_opid = False

    _tsi_conditioner_set_run_button_state(dashboard, False)
    _tsi_conditioner_update_workflow_ribbon(dashboard)


def _tsi_conditioner_poll_run_completion(
    dashboard: QtCore.QObject,
    attempts_remaining: int = 120,
):
    """
    Polls for Conditioner metadata and finishes the UI when it appears.

    The operation does not currently report a true percentage. Until metadata
    arrives, show bounded activity progress and mirror the selected node status.

    A previously scheduled timer may still fire after artifact metadata has
    already completed the run. Exit immediately in that case so stale polling
    cannot overwrite the completed status with a false metadata timeout.
    """
    if not bool(
        getattr(dashboard, "tsi_conditioner_running", False)
    ):
        return

    uid = str(
        getattr(dashboard, "tsi_conditioner_node_uid", "")
        or getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    update_tsi_conditioner_status_from_selected_node(
        dashboard,
        node_uid=uid,
    )

    payload = _tsi_conditioner_read_run_metadata(dashboard)

    if payload:
        _tsi_conditioner_set_run_finished_from_payload(
            dashboard,
            payload,
        )
        return

    if attempts_remaining <= 0:
        dashboard.tsi_conditioner_running = False
        dashboard.tsi_conditioner_node_uid = ""
        dashboard.tsi_conditioner_waiting_for_opid = False

        _tsi_conditioner_set_run_button_state(
            dashboard,
            False,
        )

        progress_bar = getattr(
            dashboard.ui,
            "progressBar_tsi_conditioner_run_progress",
            None,
        )
        if progress_bar is not None:
            progress_bar.setRange(0, 100)
            progress_bar.setValue(0)

        _tsi_conditioner_set_run_status(
            dashboard,
            "Finished, but Conditioner metadata was not found",
        )

        return

    progress_bar = getattr(
        dashboard.ui,
        "progressBar_tsi_conditioner_run_progress",
        None,
    )

    if progress_bar is not None:
        progress_bar.setRange(0, 100)

        current_value = int(progress_bar.value() or 0)

        # Bounded pseudo-progress. Completion metadata owns 100%.
        if current_value < 90:
            progress_bar.setValue(max(2, current_value + 1))
        else:
            progress_bar.setValue(90)

    QtCore.QTimer.singleShot(
        1000,
        lambda: _tsi_conditioner_poll_run_completion(
            dashboard,
            attempts_remaining - 1,
        ),
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsPreviewClicked(dashboard: QtCore.QObject):
    """
    Previews the selected Conditioner output file.

    Remote artifact rows are metadata-only until a download/cache workflow
    exists, so preview is disabled for those rows.
    """
    if _tsi_conditioner_payload_is_remote_artifact(dashboard):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Remote artifact files must be downloaded before preview."
        )
        return

    table = getattr(
        dashboard.ui,
        "tableWidget_tsi_conditioner_results",
        None,
    )

    if table is None:
        return

    row = table.currentRow()

    if row < 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Select a Conditioner result first."
        )
        return

    file_item = table.item(row, 0)

    if file_item is None:
        return

    filepath = file_item.data(QtCore.Qt.UserRole)

    if not filepath:
        output_dir = _tsi_conditioner_get_run_output_folder(dashboard)
        filepath = os.path.join(output_dir, file_item.text())

    if not filepath or not os.path.isfile(filepath):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "The selected Conditioner output file is not available locally."
        )
        return

    data_type_item = table.item(row, 3)
    sample_rate_item = table.item(row, 4)

    previous_data_type = ""
    previous_sample_rate = ""

    data_type_combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_input_data_type",
        None,
    )
    sample_rate_text = getattr(
        dashboard.ui,
        "textEdit_tsi_conditioner_file_sample_rate",
        None,
    )

    try:
        if data_type_combo is not None and data_type_item is not None:
            previous_data_type = data_type_combo.currentText().strip()

            data_type = data_type_item.text().strip()
            index = data_type_combo.findText(data_type)

            if index >= 0:
                data_type_combo.blockSignals(True)
                data_type_combo.setCurrentIndex(index)
                data_type_combo.blockSignals(False)

        if sample_rate_text is not None and sample_rate_item is not None:
            previous_sample_rate = sample_rate_text.toPlainText().strip()

            sample_rate = sample_rate_item.text().strip()

            try:
                sample_rate_msps = float(sample_rate) / 1e6
            except Exception:
                sample_rate_msps = 1.0

            sample_rate_text.blockSignals(True)
            sample_rate_text.setPlainText(str(sample_rate_msps))
            sample_rate_text.blockSignals(False)

        _tsi_conditioner_plot_preview(dashboard, filepath)

    except Exception as e:
        dashboard.logger.error(
            f"[Conditioner] Failed to preview output IQ file: {e}"
        )
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to preview output IQ file:\n{e}"
        )

    finally:
        if data_type_combo is not None and previous_data_type:
            index = data_type_combo.findText(previous_data_type)
            if index >= 0:
                data_type_combo.blockSignals(True)
                data_type_combo.setCurrentIndex(index)
                data_type_combo.blockSignals(False)

        if sample_rate_text is not None and previous_sample_rate:
            sample_rate_text.blockSignals(True)
            sample_rate_text.setPlainText(previous_sample_rate)
            sample_rate_text.blockSignals(False)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_ConditionerRunDownloadArtifactClicked(
    dashboard: QtCore.QObject,
):
    """
    Open a completed Dashboard-cached Conditioner artifact, or download it
    through the same verified transfer service used by Tactical.

    The Sensor Node's managed source directory is intentionally not treated as
    a Dashboard download, even when the node is local.
    """
    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    artifact_id = str(
        payload.get("artifact_id", "")
        or getattr(
            dashboard,
            "tsi_conditioner_last_artifact_id",
            "",
        )
        or ""
    ).strip()

    if not artifact_id:
        dashboard.logger.warning(
            "[Conditioner] No artifact ID was found for the current result."
        )
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "No artifact ID was found for this Conditioner result."
        )
        return

    controller = (
        dashboard.backend
        .artifact_transfer_controller
    )

    local_path = controller.get_local_path(
        artifact_id
    )

    if local_path:
        local_folder = (
            local_path
            if os.path.isdir(local_path)
            else os.path.dirname(local_path)
        )

        if local_folder and os.path.isdir(local_folder):
            subprocess.Popen(
                [
                    "xdg-open",
                    local_folder,
                ]
            )
            return

    try:
        await (
            dashboard.backend
            .requestDashboardArtifactDownload(
                artifact_id,
                open_when_complete=True,
            )
        )

    except Exception as exc:
        dashboard.logger.error(
            "[Conditioner] Artifact download request failed for %s: %s",
            artifact_id,
            exc,
        )

def _tsi_conditioner_numpy_dtype_for_data_type(data_type: str):
    """
    Returns numpy dtype and whether the IQ file is interleaved complex samples.
    """
    data_type = str(data_type or "").strip()

    if data_type == "Complex Float 64":
        return np.float64, True

    if data_type in ["Complex Float 32"]:
        return np.float32, True

    if data_type in ["Float/Float 32"]:
        return np.float32, False

    if data_type in ["Complex Int 16"]:
        return np.int16, True

    if data_type in ["Short/Int 16"]:
        return np.int16, False

    if data_type == "Complex Int 64":
        return np.int64, True

    if data_type == "Int/Int 32":
        return np.int32, False

    if data_type == "Complex Int 8":
        return np.int8, True

    if data_type == "Byte/Int 8":
        return np.int8, False

    return None, False

def _tsi_conditioner_sha256_file(
    filepath: str,
    chunk_size: int = 1024 * 1024,
) -> str:
    """
    Returns SHA256 for a file.
    """
    import hashlib

    digest = hashlib.sha256()

    with open(filepath, "rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)

    return digest.hexdigest()

def _tsi_conditioner_strip_iq_file(
    filepath: str,
    data_type: str,
    threshold: float,
) -> tuple:
    """
    Strips low-amplitude samples from the beginning and end of an IQ file.

    Returns:
        (old_size_bytes, new_size_bytes, old_samples, new_samples)
    """
    dtype, is_complex = _tsi_conditioner_numpy_dtype_for_data_type(data_type)

    if dtype is None:
        raise ValueError(f"Unknown Data Type: {data_type}")

    if not os.path.isfile(filepath):
        raise FileNotFoundError(filepath)

    raw = np.fromfile(filepath, dtype=dtype)

    old_size = os.path.getsize(filepath)

    if raw.size == 0:
        return old_size, old_size, 0, 0

    if is_complex:
        # Keep full I/Q pairs. Ignore trailing partial sample if present.
        pair_count = raw.size // 2

        if pair_count <= 0:
            return old_size, old_size, 0, 0

        paired = raw[:pair_count * 2].reshape((-1, 2)).astype(np.float64)
        magnitude = np.sqrt((paired[:, 0] * paired[:, 0]) + (paired[:, 1] * paired[:, 1]))

        active = np.where(magnitude > threshold)[0]

        if active.size == 0:
            stripped = raw[:0]
        else:
            left_pair = int(active[0])
            right_pair = int(active[-1]) + 1
            stripped = raw[left_pair * 2:right_pair * 2]

        old_samples = pair_count
        new_samples = int(stripped.size // 2)

    else:
        magnitude = np.abs(raw.astype(np.float64))
        active = np.where(magnitude > threshold)[0]

        if active.size == 0:
            stripped = raw[:0]
        else:
            left = int(active[0])
            right = int(active[-1]) + 1
            stripped = raw[left:right]

        old_samples = int(raw.size)
        new_samples = int(stripped.size)

    stripped.astype(dtype, copy=False).tofile(filepath)

    new_size = os.path.getsize(filepath)

    return old_size, new_size, old_samples, new_samples

def _tsi_conditioner_results_file_path_for_row(
    dashboard: QtCore.QObject,
    row: int,
) -> str:
    """
    Gets the absolute file path for a Conditioner results table row.
    """
    table = dashboard.ui.tableWidget_tsi_conditioner_results
    file_item = table.item(row, 0)

    if file_item is None:
        return ""

    filepath = file_item.data(QtCore.Qt.UserRole)

    if filepath:
        return str(filepath)

    output_dir = _tsi_conditioner_get_run_output_folder(dashboard)
    return os.path.join(output_dir, file_item.text())

def _tsi_conditioner_update_result_row_after_file_change(
    dashboard: QtCore.QObject,
    row: int,
    filepath: str,
    data_type: str,
):
    """
    Refreshes size and sample count for a single results table row.
    """
    table = dashboard.ui.tableWidget_tsi_conditioner_results

    if row < 0 or row >= table.rowCount():
        return

    if not os.path.isfile(filepath):
        return

    size_bytes = os.path.getsize(filepath)
    samples = _tsi_conditioner_samples_from_size(size_bytes, data_type)

    size_item = QtWidgets.QTableWidgetItem(str(round(size_bytes / 1048576, 2)))
    size_item.setTextAlignment(QtCore.Qt.AlignCenter)
    table.setItem(row, 1, size_item)

    sample_item = QtWidgets.QTableWidgetItem(str(samples))
    sample_item.setTextAlignment(QtCore.Qt.AlignCenter)
    table.setItem(row, 2, sample_item)

def _tsi_conditioner_mark_payload_modified_after_strip(
    dashboard: QtCore.QObject,
):
    """
    Updates current payload metadata after Strip/Strip All.

    The old zip bundle is deleted because it no longer matches the modified IQ
    files. The artifact is cleared until a future export/rebundle action exists.
    """
    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    if not payload:
        return

    table = getattr(
        dashboard.ui,
        "tableWidget_tsi_conditioner_results",
        None,
    )

    if table is None:
        return

    files_by_name = {}

    for file_record in payload.get("files", []) or []:
        if isinstance(file_record, dict):
            files_by_name[str(file_record.get("name", "") or "")] = file_record

    for row in range(table.rowCount()):
        file_item = table.item(row, 0)
        type_item = table.item(row, 3)

        if file_item is None or type_item is None:
            continue

        filename = file_item.text()
        filepath = file_item.data(QtCore.Qt.UserRole)

        if not filepath:
            filepath = _tsi_conditioner_results_file_path_for_row(dashboard, row)

        if not filepath or not os.path.isfile(filepath):
            continue

        file_record = files_by_name.get(filename)

        if not file_record:
            continue

        size_bytes = os.path.getsize(filepath)
        data_type = type_item.text()

        file_record["size"] = size_bytes
        file_record["samples"] = _tsi_conditioner_samples_from_size(size_bytes, data_type)
        file_record["mtime"] = os.path.getmtime(filepath)

        try:
            file_record["sha256"] = _tsi_conditioner_sha256_file(filepath)
        except Exception:
            pass

    # Existing zip no longer matches after file mutation.
    bundle_path = str(payload.get("bundle_path", "") or "").strip()

    if bundle_path and os.path.isfile(bundle_path):
        try:
            os.remove(bundle_path)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Failed removing stale bundle {bundle_path}: {e}"
            )

    payload["artifact_id"] = ""
    payload["artifact_format"] = "local_iq_files_modified"
    payload["bundle_path"] = ""
    payload["bundle_name"] = ""
    payload["bundle_size"] = 0
    payload["modified"] = True
    payload["modification"] = "strip"

    dashboard.tsi_conditioner_last_artifact_id = ""
    dashboard.tsi_conditioner_last_artifact_payload = payload

    # Rewrite operation-specific metadata if present.
    metadata_paths = []

    metadata_path = str(payload.get("metadata_path", "") or "").strip()
    if metadata_path:
        metadata_paths.append(metadata_path)

    latest_metadata_path = _tsi_conditioner_latest_metadata_path(dashboard)
    if latest_metadata_path:
        metadata_paths.append(latest_metadata_path)

    for path in metadata_paths:
        try:
            if path:
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, sort_keys=True)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Failed updating metadata after strip {path}: {e}"
            )

    _tsi_conditioner_set_run_artifact_state_from_payload(
        dashboard,
        {
            "output_mode": _tsi_conditioner_get_run_output_mode(dashboard),
            "artifact_id": "",
            "bundle_path": "",
            "metadata_path": metadata_path,
        },
    )

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsStripClicked(dashboard: QtCore.QObject):
    """
    Removes silence before and after the selected Conditioner output IQ file.
    Updates matching SigMF sidecar metadata when the file is .sigmf-data.
    """
    if _tsi_conditioner_current_results_are_artifact(dashboard):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Artifact-managed Conditioner results are read-only."
        )
        return

    table = getattr(
        dashboard.ui,
        "tableWidget_tsi_conditioner_results",
        None,
    )

    if table is None:
        return

    row = table.currentRow()

    if row < 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Select an output file first."
        )
        return

    text, ok = QtWidgets.QInputDialog.getText(
        dashboard,
        "Strip",
        "Enter amplitude threshold:",
        QtWidgets.QLineEdit.Normal,
        "0.001",
    )

    if not ok:
        return

    try:
        threshold = float(text)
    except Exception:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Enter a valid numeric threshold."
        )
        return

    type_item = table.item(row, 3)

    if type_item is None:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Selected output file is missing a data type."
        )
        return

    filepath = _tsi_conditioner_results_file_path_for_row(dashboard, row)
    data_type = type_item.text()

    try:
        old_size, new_size, old_samples, new_samples = _tsi_conditioner_strip_iq_file(
            filepath=filepath,
            data_type=data_type,
            threshold=threshold,
        )

        _tsi_conditioner_update_sigmf_meta_after_file_change(
            dashboard,
            filepath,
            data_type,
        )

        _tsi_conditioner_update_result_row_after_file_change(
            dashboard,
            row,
            filepath,
            data_type,
        )

        _tsi_conditioner_mark_payload_modified_after_strip(dashboard)

        _tsi_conditioner_set_run_status(
            dashboard,
            f"Stripped 1 file: {old_samples} → {new_samples} samples",
        )

        _tsi_conditioner_mark_results_unpromoted(dashboard)

    except Exception as e:
        dashboard.logger.error(
            f"[Conditioner] Failed stripping output file {filepath}: {e}"
        )
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to strip output file:\n{e}"
        )

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsStripAllClicked(dashboard: QtCore.QObject):
    """
    Removes silence before and after all IQ files in the Conditioner results table.
    Updates matching SigMF sidecar metadata for .sigmf-data files.
    """
    if _tsi_conditioner_current_results_are_artifact(dashboard):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Artifact-managed Conditioner results are read-only."
        )
        return

    table = getattr(
        dashboard.ui,
        "tableWidget_tsi_conditioner_results",
        None,
    )

    if table is None:
        return

    row_count = table.rowCount()

    if row_count <= 0:
        return

    text, ok = QtWidgets.QInputDialog.getText(
        dashboard,
        "Strip All",
        "Enter amplitude threshold:",
        QtWidgets.QLineEdit.Normal,
        "0.001",
    )

    if not ok:
        return

    try:
        threshold = float(text)
    except Exception:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Enter a valid numeric threshold."
        )
        return

    reply = QtWidgets.QMessageBox.question(
        dashboard,
        "Strip All Conditioner Results",
        (
            f"Strip leading/trailing silence from all {row_count} listed "
            "Conditioner output files?\n\n"
            "This modifies the files in place."
        ),
        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        QtWidgets.QMessageBox.No,
    )

    if reply != QtWidgets.QMessageBox.Yes:
        return

    stripped_count = 0
    failed_paths = []
    old_total_samples = 0
    new_total_samples = 0

    for row in range(row_count):
        type_item = table.item(row, 3)

        if type_item is None:
            continue

        filepath = _tsi_conditioner_results_file_path_for_row(dashboard, row)
        data_type = type_item.text()

        try:
            old_size, new_size, old_samples, new_samples = _tsi_conditioner_strip_iq_file(
                filepath=filepath,
                data_type=data_type,
                threshold=threshold,
            )

            _tsi_conditioner_update_sigmf_meta_after_file_change(
                dashboard,
                filepath,
                data_type,
            )

            _tsi_conditioner_update_result_row_after_file_change(
                dashboard,
                row,
                filepath,
                data_type,
            )

            stripped_count += 1
            old_total_samples += old_samples
            new_total_samples += new_samples

        except Exception as e:
            failed_paths.append(f"{filepath}: {e}")

    _tsi_conditioner_mark_payload_modified_after_strip(dashboard)

    _tsi_conditioner_set_run_status(
        dashboard,
        (
            f"Stripped {stripped_count} files: "
            f"{old_total_samples} → {new_total_samples} samples"
        ),
    )

    _tsi_conditioner_mark_results_unpromoted(dashboard)

    _tsi_conditioner_update_workflow_ribbon(dashboard)

    if failed_paths:
        dashboard.logger.warning(
            "[Conditioner] Failed stripping some output files:\n"
            + "\n".join(failed_paths)
        )

        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Some Conditioner files could not be stripped. "
            "Check the Dashboard log."
        )

def _tsi_conditioner_update_sigmf_meta_after_file_change(
    dashboard: QtCore.QObject,
    data_path: str,
    data_type: str,
):
    """
    Updates a SigMF metadata sidecar after a .sigmf-data file is modified.

    Keeps the existing metadata content, but refreshes:
        global/core:dataset
        global/core:sha512
        global/core:datatype
    """
    data_path = str(data_path or "").strip()

    if not data_path:
        return

    if data_path.endswith(".sigmf-data"):
        meta_path = data_path.replace(".sigmf-data", ".sigmf-meta")
    else:
        meta_path = data_path + ".sigmf-meta"

    if not os.path.isfile(meta_path):
        return

    try:
        with open(meta_path, "r", encoding="utf-8") as handle:
            meta = json.load(handle)

    except Exception:
        meta = {}

    if not isinstance(meta, dict):
        meta = {}

    meta.setdefault("global", {})
    meta.setdefault("captures", [])
    meta.setdefault("annotations", [])

    meta["global"]["core:dataset"] = os.path.basename(data_path)

    try:
        import hashlib

        digest = hashlib.sha512()

        with open(data_path, "rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)

                if not chunk:
                    break

                digest.update(chunk)

        meta["global"]["core:sha512"] = digest.hexdigest()

    except Exception as e:
        dashboard.logger.warning(
            f"[Conditioner] Could not update SigMF sha512 for {data_path}: {e}"
        )

    sigmf_datatype_map = {
        "Complex Float 32": "cf32_le",
        "Complex Float 64": "cf64_le",
        "Float/Float 32": "rf32_le",
        "Short/Int 16": "ri16_le",
        "Int/Int 32": "ri32_le",
        "Byte/Int 8": "ri8",
        "Complex Int 16": "ci16_le",
        "Complex Int 8": "ci8",
        "Complex Int 64": "ci64_le",
        "Unsigned Int 8": "ru8",
        "Unsigned Int 16": "ru16_le",
        "Unsigned Int 32": "ru32_le",
        "Complex Unsigned Int 64": "cu64_le",
        "Complex Unsigned Int 16": "cu16_le",
        "Complex Unsigned Int 8": "cu8",
    }

    sigmf_datatype = sigmf_datatype_map.get(
        str(data_type or "").strip(),
        "",
    )

    if sigmf_datatype:
        meta["global"]["core:datatype"] = sigmf_datatype

    meta.setdefault("fissure", {})
    meta["fissure"]["modified"] = True
    meta["fissure"]["modification"] = "strip"
    meta["fissure"]["modified_at"] = datetime.datetime.utcnow().isoformat("T") + "Z"

    try:
        with open(meta_path, "w", encoding="utf-8") as handle:
            json.dump(meta, handle, indent=2, sort_keys=True)

    except Exception as e:
        dashboard.logger.warning(
            f"[Conditioner] Could not update SigMF metadata {meta_path}: {e}"
        )

def _tsi_conditioner_get_run_output_mode(
    dashboard: QtCore.QObject,
) -> str:
    """
    Returns the selected Conditioner run output mode.

    Legacy 'Local Folder + Artifact' is normalized to 'Artifact'.
    Remote nodes are always artifact-only.
    """
    try:
        if selected_node_is_remote(dashboard):
            return "Artifact"
    except Exception:
        pass

    combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_run_output_mode",
        None,
    )

    if combo is None:
        return "Local Folder"

    text = combo.currentText().strip()

    if text == "Local Folder + Artifact":
        return "Artifact"

    if text in ["Local Folder", "Artifact"]:
        return text

    return "Local Folder"

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerRunOutputModeChanged(dashboard: QtCore.QObject):
    """
    Handles Conditioner output mode changes.
    """
    _tsi_conditioner_update_run_output_mode_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsRefreshClicked(dashboard: QtCore.QObject):
    """
    Refreshes the Conditioner results table from the current operation metadata.

    Local Folder mode:
        - reloads/validates the current payload
        - keeps only files that still exist on disk
        - rewrites metadata only if the refreshed file list is valid

    Artifact mode:
        - read-only; refresh is disabled because artifact metadata should not
          be mutated from the Results table.

    Important:
        Do not clear the table until a valid payload has been found. Otherwise
        a stale/missing metadata lookup can erase visible local-folder results.
    """
    if _tsi_conditioner_current_results_are_artifact(dashboard):
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Artifact-managed Conditioner results are read-only."
        )
        return

    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    if not payload:
        payload = _tsi_conditioner_read_run_metadata(dashboard)

    if not payload:
        _tsi_conditioner_set_run_status(
            dashboard,
            "No Conditioner metadata to refresh",
        )
        _tsi_conditioner_update_results_action_gate(dashboard)
        return

    files = payload.get("files", []) or []

    if not isinstance(files, list):
        files = []

    if not files:
        _tsi_conditioner_set_run_status(
            dashboard,
            "No Conditioner file records to refresh",
        )
        _tsi_conditioner_update_results_action_gate(dashboard)
        return

    refreshed_files = []
    missing_count = 0
    changed = False

    for file_record in files:
        if not isinstance(file_record, dict):
            continue

        original_record = dict(file_record)

        filepath = str(file_record.get("path", "") or "").strip()

        if not filepath:
            missing_count += 1
            changed = True
            continue

        filepath = os.path.abspath(os.path.expanduser(filepath))

        if not os.path.isfile(filepath):
            missing_count += 1
            changed = True
            continue

        data_type = str(
            file_record.get("format", "")
            or file_record.get("data_type", "")
            or payload.get("data_type", "")
            or ""
        ).strip()

        size_bytes = os.path.getsize(filepath)

        file_record = dict(file_record)
        file_record["path"] = filepath
        file_record["size"] = size_bytes
        file_record["samples"] = _tsi_conditioner_samples_from_size(
            size_bytes,
            data_type,
        )
        file_record["mtime"] = os.path.getmtime(filepath)

        try:
            file_record["sha256"] = _tsi_conditioner_sha256_file(filepath)
        except Exception:
            pass

        if file_record != original_record:
            changed = True

        refreshed_files.append(file_record)

    if not refreshed_files:
        dashboard.tsi_conditioner_last_artifact_payload = {}
        dashboard.tsi_conditioner_last_artifact_id = ""

        table = getattr(
            dashboard.ui,
            "tableWidget_tsi_conditioner_results",
            None,
        )
        if table is not None:
            table.setRowCount(0)

        count_label = getattr(
            dashboard.ui,
            "label2_tsi_conditioner_results_file_count",
            None,
        )
        if count_label is not None:
            count_label.setText("File Count: 0")

        _tsi_conditioner_set_run_status(
            dashboard,
            f"Refreshed: 0 files, {missing_count} missing",
        )

        _tsi_conditioner_update_workflow_ribbon(dashboard)
        _tsi_conditioner_update_results_action_gate(dashboard)
        return

    payload = dict(payload)
    payload["files"] = refreshed_files
    payload["file_count"] = len(refreshed_files)

    dashboard.tsi_conditioner_last_artifact_payload = payload
    dashboard.tsi_conditioner_last_artifact_id = str(
        payload.get("artifact_id", "") or ""
    )

    _tsi_conditioner_set_results_table_from_payload(dashboard, payload)
    _tsi_conditioner_set_run_artifact_state_from_payload(dashboard, payload)

    # Rewrite metadata only for editable Local Folder results.
    metadata_paths = []

    metadata_path = str(payload.get("metadata_path", "") or "").strip()
    if metadata_path:
        metadata_paths.append(metadata_path)

    latest_metadata_path = _tsi_conditioner_latest_metadata_path(dashboard)
    if latest_metadata_path:
        metadata_paths.append(latest_metadata_path)

    for path in sorted(set(metadata_paths)):
        try:
            if path:
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, sort_keys=True)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Failed updating refreshed metadata {path}: {e}"
            )

    if changed:
        _tsi_conditioner_mark_results_unpromoted(dashboard)

    if missing_count > 0:
        _tsi_conditioner_set_run_status(
            dashboard,
            f"Refreshed: {len(refreshed_files)} files, {missing_count} missing",
        )
    else:
        _tsi_conditioner_set_run_status(
            dashboard,
            f"Refreshed: {len(refreshed_files)} files",
        )

    _tsi_conditioner_update_workflow_ribbon(dashboard)
    _tsi_conditioner_update_results_action_gate(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsExportClicked(dashboard: QtCore.QObject):
    """
    Exports the Conditioner results table to a CSV file.
    """
    table = getattr(
        dashboard.ui,
        "tableWidget_tsi_conditioner_results",
        None,
    )

    if table is None:
        return

    if table.rowCount() <= 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "There are no Conditioner results to export."
        )
        return

    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    operation_id = str(payload.get("operation_id", "") or "").strip()
    default_name = "conditioner_results.csv"

    if operation_id:
        default_name = f"conditioner_{operation_id}_results.csv"

    output_dir = str(
        payload.get("output_dir", "")
        or payload.get("files_dir", "")
        or _tsi_conditioner_get_run_output_folder(dashboard)
        or ""
    ).strip()

    if output_dir and os.path.isdir(output_dir):
        default_path = os.path.join(output_dir, default_name)
    else:
        default_path = default_name

    path, selected_filter = QtWidgets.QFileDialog.getSaveFileName(
        dashboard,
        "Save Conditioner Results CSV",
        default_path,
        "CSV Files (*.csv);;All Files (*)",
    )

    if not path:
        return

    if not path.lower().endswith(".csv"):
        path += ".csv"

    try:
        columns = range(table.columnCount())

        header = []

        for column in columns:
            header_item = table.horizontalHeaderItem(column)
            header.append(header_item.text() if header_item is not None else "")

        with open(path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile, dialect="excel", lineterminator="\n")
            writer.writerow(header)

            for row in range(table.rowCount()):
                row_values = []

                for column in columns:
                    item = table.item(row, column)
                    row_values.append(item.text() if item is not None else "")

                writer.writerow(row_values)

        _tsi_conditioner_set_run_status(
            dashboard,
            f"Exported results CSV: {os.path.basename(path)}",
        )

    except Exception as e:
        dashboard.logger.error(
            f"[Conditioner] Failed exporting results CSV {path}: {e}"
        )

        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to export Conditioner results CSV:\n{e}"
        )

def update_tsi_conditioner_status_from_selected_node(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    status: str = "",
):
    """
    Mirrors selected Sensor Node status into the Conditioner Run status.

    Also parses operation progress strings formatted as:

        25% | Conditioning 1/3: input.iq

    This follows dashboard.selected_node_uid from the top node selector.
    """
    selected_uid = str(
        getattr(dashboard, "selected_node_uid", "") or ""
    ).strip()

    if not selected_uid:
        _tsi_conditioner_set_run_status(
            dashboard,
            "Sensor Node Unavailable",
        )
        return

    if node_uid and str(node_uid).strip() != selected_uid:
        return

    if not bool(getattr(dashboard, "tsi_conditioner_running", False)):
        return

    node_states = getattr(dashboard, "node_states", {}) or {}
    node_state = node_states.get(selected_uid, {}) or {}

    if isinstance(node_state, dict):
        if node_state.get("connected") is False:
            _tsi_conditioner_set_run_status(
                dashboard,
                "Sensor Node Unavailable",
            )
            return

        status_text = str(
            status
            or node_state.get("status", "")
            or node_state.get("state", "")
            or node_state.get("operation_status", "")
            or node_state.get("last_status", "")
            or ""
        ).strip()

    else:
        status_text = str(status or "").strip()

    if not status_text:
        status_text = "Running Conditioner action..."

    display_status = status_text
    progress_percent = None

    if "%" in status_text:
        first_part, remaining = status_text.split("%", 1)
        first_part = first_part.strip()

        try:
            parsed_percent = int(float(first_part))

            if 0 <= parsed_percent <= 100:
                progress_percent = parsed_percent

                remaining = remaining.strip()

                if remaining.startswith("|"):
                    remaining = remaining[1:].strip()

                display_status = remaining or status_text

        except Exception:
            progress_percent = None

    if progress_percent is not None:
        progress_bar = getattr(
            dashboard.ui,
            "progressBar_tsi_conditioner_run_progress",
            None,
        )

        if progress_bar is not None:
            progress_bar.setRange(0, 100)
            progress_bar.setValue(progress_percent)

    _tsi_conditioner_set_run_status(
        dashboard,
        display_status,
    )

def _tsi_conditioner_selected_source_type(dashboard: QtCore.QObject) -> str:
    """
    Returns the Conditioner input source type for action parameters.

    UI text:
        File        -> file
        Folder      -> folder
        Frequencies -> frequencies
    """
    source = _tsi_conditioner_current_source(dashboard)

    source_types = {
        "File": "file",
        "Folder": "folder",
        "Frequencies": "frequencies",
    }

    return source_types.get(source, source.lower().replace(" ", "_"))

def _tsi_conditioner_delete_output_file_and_sidecars(
    dashboard: QtCore.QObject,
    filepath: str,
    payload_row: dict = None,
):
    """
    Deletes a Conditioner output file and any SigMF sidecar metadata file.

    Handles:
        output.sigmf-data -> output.sigmf-meta
        output.iq         -> output.iq.sigmf-meta, if present
        payload row       -> sigmf_meta_path, if present
    """
    payload_row = payload_row or {}

    paths_to_delete = []

    filepath = str(filepath or "").strip()

    if filepath:
        paths_to_delete.append(filepath)

        if filepath.endswith(".sigmf-data"):
            paths_to_delete.append(
                filepath.replace(".sigmf-data", ".sigmf-meta")
            )
        else:
            paths_to_delete.append(filepath + ".sigmf-meta")

    sigmf_meta_path = str(
        payload_row.get("sigmf_meta_path", "") or ""
    ).strip()

    if sigmf_meta_path:
        paths_to_delete.append(sigmf_meta_path)

    # De-duplicate while preserving order.
    seen = set()
    clean_paths = []

    for path in paths_to_delete:
        path = str(path or "").strip()

        if not path:
            continue

        path_key = os.path.abspath(path)

        if path_key in seen:
            continue

        seen.add(path_key)
        clean_paths.append(path)

    for path in clean_paths:
        try:
            if os.path.isfile(path):
                os.remove(path)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Could not delete output file: {path}. Error: {e}"
            )

def _tsi_conditioner_get_frequency_plan_for_run(
    dashboard: QtCore.QObject,
) -> list:
    """
    Returns Conditioner frequency-plan rows for Frequencies source.

    Columns:
        0 Freq. (MHz)
        1 Dwell (s)
        2 Power (dB)
        3 Time
    """
    table = _tsi_conditioner_frequency_table(dashboard)
    plan = []

    if table is None:
        return plan

    for row in range(table.rowCount()):
        freq_item = table.item(row, 0)

        if freq_item is None:
            continue

        frequency_text = _tsi_conditioner_parse_frequency_mhz(freq_item.text())

        if not frequency_text:
            continue

        try:
            frequency_mhz = float(frequency_text)
        except Exception:
            continue

        dwell_s = 10.0
        dwell_item = table.item(row, 1)

        if dwell_item is not None:
            try:
                dwell_s = float(str(dwell_item.text()).strip())
            except Exception:
                dwell_s = 10.0

        dwell_s = max(0.1, dwell_s)

        power_db = ""
        time_text = ""

        if table.columnCount() > 2 and table.item(row, 2) is not None:
            power_db = str(table.item(row, 2).text()).strip()

        if table.columnCount() > 3 and table.item(row, 3) is not None:
            time_text = str(table.item(row, 3).text()).strip()

        plan.append(
            {
                "frequency_mhz": frequency_mhz,
                "dwell_s": dwell_s,
                "power_db": power_db,
                "time": time_text,
                "row": row,
            }
        )

    return plan

def _tsi_conditioner_dtype_for_saturation(data_type: str):
    """
    Returns numpy dtype and saturation limits for a Conditioner result format.

    This is a full-file check. It returns:
        dtype, min_value, max_value
    """
    data_type = str(data_type or "").strip()

    dtype_map = {
        "Complex Float 32": (np.float32, -1.0, 1.0),
        "Float/Float 32": (np.float32, -1.0, 1.0),
        "Complex Float 64": (np.float64, -1.0, 1.0),

        "Byte/Int 8": (np.int8, -128, 127),
        "Complex Int 8": (np.int8, -128, 127),

        "Unsigned Int 8": (np.uint8, 0, 255),
        "Complex Unsigned Int 8": (np.uint8, 0, 255),

        "Short/Int 16": (np.int16, -32768, 32767),
        "Complex Int 16": (np.int16, -32768, 32767),

        "Unsigned Int 16": (np.uint16, 0, 65535),
        "Complex Unsigned Int 16": (np.uint16, 0, 65535),

        "Int/Int 32": (np.int32, -2147483648, 2147483647),
        "Complex Int 32": (np.int32, -2147483648, 2147483647),

        "Unsigned Int 32": (np.uint32, 0, 4294967295),
        "Complex Unsigned Int 32": (np.uint32, 0, 4294967295),

        "Complex Int 64": (
            np.int64,
            -9223372036854775808,
            9223372036854775807,
        ),
        "Complex Unsigned Int 64": (
            np.uint64,
            0,
            18446744073709551615,
        ),
    }

    return dtype_map.get(data_type, (None, None, None))

def _tsi_conditioner_rewrite_result_metadata(
    dashboard: QtCore.QObject,
    payload: dict,
):
    """
    Rewrites Conditioner metadata after Dashboard-side result updates.
    """
    metadata_paths = []

    metadata_path = str(payload.get("metadata_path", "") or "").strip()
    if metadata_path:
        metadata_paths.append(metadata_path)

    latest_metadata_path = _tsi_conditioner_latest_metadata_path(dashboard)
    if latest_metadata_path:
        metadata_paths.append(latest_metadata_path)

    for path in metadata_paths:
        try:
            if path:
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, sort_keys=True)
        except Exception as e:
            dashboard.logger.warning(
                f"[Conditioner] Failed rewriting metadata {path}: {e}"
            )

def _tsi_conditioner_get_run_saturation_check_enabled(
    dashboard: QtCore.QObject,
) -> bool:
    """
    Returns True only when Section 3 explicitly says Yes.

    There is intentionally no fallback to old Conditioner settings controls.
    The old settings saturation checkbox/combobox belonged to the legacy
    file-conditioning workflow and must not affect the new Section 3 runner.
    """
    combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_run_saturation_check",
        None,
    )

    if combo is None:
        dashboard.logger.warning(
            "[Conditioner] Saturation combo is missing; defaulting to No."
        )
        return False

    text = combo.currentText().strip()

    enabled = text.lower() == "yes"

    dashboard.logger.info(
        "[Conditioner] Saturation combo text=%r enabled=%s",
        text,
        enabled,
    )

    return enabled

def _tsi_conditioner_file_record_from_results_row(
    dashboard: QtCore.QObject,
    row: int,
    payload_files_by_path: dict,
    payload_files_by_name: dict,
) -> dict:
    """
    Builds a Conditioner SOI evidence file record from one visible results row.
    """
    table = dashboard.ui.tableWidget_tsi_conditioner_results

    file_item = table.item(row, 0)
    if file_item is None:
        return {}

    name = str(file_item.text() or "").strip()
    filepath = file_item.data(QtCore.Qt.UserRole)

    if not filepath:
        output_dir = _tsi_conditioner_get_run_output_folder(dashboard)
        filepath = os.path.join(output_dir, name)

    filepath = os.path.abspath(os.path.expanduser(str(filepath or "")))

    payload_record = payload_files_by_path.get(filepath)
    if payload_record is None:
        payload_record = payload_files_by_name.get(name, {})

    if payload_record is None:
        payload_record = {}

    def _cell_text(column: int) -> str:
        item = table.item(row, column)
        if item is None:
            return ""
        return str(item.text() or "").strip()

    try:
        size_bytes = os.path.getsize(filepath) if os.path.isfile(filepath) else 0
    except Exception:
        size_bytes = 0

    record = dict(payload_record)

    record.update(
        {
            "name": record.get("name") or name,
            "path": record.get("path") or filepath,
            "size_bytes": record.get("size_bytes") or size_bytes,
            "size_mb": _cell_text(1),
            "samples": record.get("samples") or _cell_text(2),
            "format": record.get("format") or _cell_text(3),
            "data_type": record.get("data_type") or _cell_text(3),
            "sample_rate": record.get("sample_rate") or _cell_text(4),
            "saturated": record.get("saturated") or _cell_text(5),
            "source": record.get("source") or _cell_text(6),
            "notes": record.get("notes") or _cell_text(7),
        }
    )

    return record

def _tsi_conditioner_payload_file_indexes(payload: dict) -> tuple:
    """
    Returns payload file lookup dictionaries by absolute path and file name.
    """
    files = payload.get("files", []) or []
    if not isinstance(files, list):
        files = []

    by_path = {}
    by_name = {}

    for file_record in files:
        if not isinstance(file_record, dict):
            continue

        path = str(file_record.get("path", "") or "").strip()
        name = str(file_record.get("name", "") or "").strip()

        if path:
            by_path[os.path.abspath(os.path.expanduser(path))] = file_record

        if name:
            by_name[name] = file_record

    return by_path, by_name

def _tsi_conditioner_prompt_for_optional_soi_frequency(
    dashboard: QtCore.QObject,
):
    """
    Prompts once for optional tuned frequency when Conditioner metadata does not
    already provide one.
    """
    text, ok = QtWidgets.QInputDialog.getText(
        dashboard,
        "Promote to SOI",
        (
            "No tuned frequency was found for these Conditioner results.\n\n"
            "Enter tuned frequency in MHz, or leave blank to promote without it:"
        ),
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
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Invalid frequency value:\n{text}"
        )
        return "cancelled"

def _tsi_conditioner_resolve_soi_frequency(
    dashboard: QtCore.QObject,
    payload: dict,
    files: list,
):
    """
    Resolves the best top-level SOI frequency.

    For first pass:
      - Use payload/file frequency if all known file frequencies agree.
      - If none found, prompt once.
      - If multiple frequencies are present, leave top-level frequency unknown
        and keep per-file values in summary.
    """
    candidates = []

    payload_frequency = payload.get("frequency_mhz")
    if payload_frequency not in [None, "", "None"]:
        candidates.append(payload_frequency)

    for file_record in files:
        if not isinstance(file_record, dict):
            continue

        value = file_record.get("frequency_mhz")
        if value in [None, "", "None"]:
            continue

        candidates.append(value)

    normalized = []

    for value in candidates:
        try:
            normalized.append(round(float(value), 6))
        except Exception:
            continue

    unique_values = sorted(set(normalized))

    if len(unique_values) == 1:
        return unique_values[0]

    if len(unique_values) > 1:
        return None

    return _tsi_conditioner_prompt_for_optional_soi_frequency(dashboard)

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsPromoteToSoiClicked(
    dashboard: QtCore.QObject,
):
    """
    Promotes all visible Conditioner result rows into one metadata-only SOI.

    The SOI is stored at HIPRFISR and associated with the currently selected
    sensor node. Feature extraction, classification, and protocol discovery can
    attach details later.
    """
    table = getattr(
        dashboard.ui,
        "tableWidget_tsi_conditioner_results",
        None,
    )

    if table is None or table.rowCount() <= 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "There are no Conditioner results to promote."
        )
        return

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()

    if not node_uid:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "Select a sensor node before promoting Conditioner results to an SOI."
        )
        return

    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    if not payload:
        metadata_path = _tsi_conditioner_latest_metadata_path(dashboard)
        if metadata_path and os.path.isfile(metadata_path):
            try:
                with open(metadata_path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
            except Exception as e:
                dashboard.logger.warning(
                    f"[Conditioner] Could not read Conditioner metadata for SOI promotion: {e}"
                )
                payload = {}

    payload_files_by_path, payload_files_by_name = (
        _tsi_conditioner_payload_file_indexes(payload)
    )

    files = []

    for row in range(table.rowCount()):
        record = _tsi_conditioner_file_record_from_results_row(
            dashboard=dashboard,
            row=row,
            payload_files_by_path=payload_files_by_path,
            payload_files_by_name=payload_files_by_name,
        )

        if not record:
            continue

        files.append(record)

    if not files:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            "No valid Conditioner result files were found to promote."
        )
        return

    frequency_mhz = _tsi_conditioner_resolve_soi_frequency(
        dashboard=dashboard,
        payload=payload,
        files=files,
    )

    if frequency_mhz == "cancelled":
        return

    soi_id = str(uuid.uuid4())

    operation_id = str(
        payload.get("operation_id", "")
        or getattr(dashboard, "tsi_conditioner_opid", "")
        or ""
    ).strip()

    artifact_id = str(
        payload.get("artifact_id", "")
        or getattr(dashboard, "tsi_conditioner_last_artifact_id", "")
        or ""
    ).strip()

    source_type = str(
        payload.get("source_type", "")
        or _tsi_conditioner_current_source(dashboard)
        or ""
    ).strip()

    method_combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_method_method",
        None,
    )
    method = method_combo.currentText().strip() if method_combo is not None else ""

    action_combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_method_action",
        None,
    )
    action = action_combo.currentText().strip() if action_combo is not None else ""

    output_format_combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_run_output_format",
        None,
    )
    output_format = (
        output_format_combo.currentText().strip()
        if output_format_combo is not None
        else ""
    )

    sample_rate = (
        payload.get("sample_rate")
        or files[0].get("sample_rate", "")
        or ""
    )

    data_type = (
        payload.get("data_type")
        or files[0].get("data_type", "")
        or files[0].get("format", "")
        or ""
    )

    summary = {
        "stage": "conditioner_promoted",
        "stage_order": 50,
        "folder": _tsi_conditioner_get_run_output_folder(dashboard),
        "files_present": True,
        "file_count": len(files),

        "source": "tsi_conditioner",
        "source_type": source_type,
        "method": method,
        "action": action,
        "output_format": output_format,

        "sample_rate": sample_rate,
        "data_type": data_type,
        "operation_id": operation_id,
        "artifact_id": artifact_id,

        "description": "Conditioner results promoted to SOI",
        "files": files,

        # Reserved for next workflow steps.
        "features": {},
        "classification": {},
        "protocol": {},
        "model_classification": "",
        "model_confidence": None,
    }

    button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_results_promote_to_soi",
        None,
    )

    if button is not None:
        button.setEnabled(False)

    _tsi_conditioner_set_run_status(
        dashboard,
        f"Promoting {len(files)} Conditioner results to SOI...",
    )

    task = asyncio.ensure_future(
        _tsi_conditioner_send_promote_to_soi(
            dashboard=dashboard,
            node_uid=node_uid,
            soi_id=soi_id,
            frequency_mhz=frequency_mhz,
            operation_id=operation_id,
            artifact_id=artifact_id,
            summary=summary,
        )
    )

    task.add_done_callback(
        lambda future: _tsi_conditioner_promote_to_soi_done(
            dashboard=dashboard,
            future=future,
            button=button,
            soi_id=soi_id,
        )
    )

async def _tsi_conditioner_send_promote_to_soi(
    dashboard: QtCore.QObject,
    node_uid: str,
    soi_id: str,
    frequency_mhz,
    operation_id: str,
    artifact_id: str,
    summary: dict,
):
    """
    Sends the Conditioner SOI promotion request to HIPRFISR.

    This runs as a scheduled backend task so the Qt slot can return immediately.
    """
    await dashboard.backend.tacticalConditionerPromoteToSoi(
        node_uid=node_uid,
        soi_id=soi_id,
        frequency_mhz=frequency_mhz,
        status="EVIDENCE_READY",
        operation_id=operation_id,
        artifact_id=artifact_id,
        summary=summary,
    )


def _tsi_conditioner_promote_to_soi_done(
    dashboard: QtCore.QObject,
    future,
    button,
    soi_id: str,
):
    """
    Handles completion of the scheduled Promote to SOI backend send.

    Artifact-managed metadata files are immutable after registration. Promotion
    state is kept in Dashboard/SOI relationship state and must not rewrite a
    registered artifact member.
    """
    try:
        future.result()

        payload = getattr(
            dashboard,
            "tsi_conditioner_last_artifact_payload",
            {},
        ) or {}

        payload["promoted"] = True
        payload["promoted_to_soi"] = True
        payload["last_soi_id"] = soi_id
        payload["last_promoted_at"] = (
            datetime.datetime.utcnow().isoformat("T") + "Z"
        )

        dashboard.tsi_conditioner_last_artifact_payload = payload

        _tsi_conditioner_update_workflow_ribbon(dashboard)

        _tsi_conditioner_set_run_status(
            dashboard,
            f"Promoted Conditioner results to SOI: {soi_id}",
        )

    except Exception as e:
        dashboard.logger.error(
            f"[Conditioner] Failed to promote results to SOI: {e}"
        )
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Failed to promote Conditioner results to SOI:\n{e}"
        )

    finally:
        if button is not None:
            button.setEnabled(True)


def _tsi_conditioner_mark_results_unpromoted(
    dashboard: QtCore.QObject,
    rewrite_metadata: bool = True,
):
    """
    Marks the current Conditioner result set as not promoted.

    Registered artifact members are immutable. Metadata rewriting is allowed
    only for editable Local Folder results.
    """
    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    if not isinstance(payload, dict):
        payload = {}

    has_real_payload = bool(
        payload.get("files")
        or payload.get("operation_id")
        or payload.get("metadata_path")
        or payload.get("artifact_id")
    )

    if not has_real_payload:
        dashboard.tsi_conditioner_last_artifact_payload = {}
        _tsi_conditioner_update_workflow_ribbon(dashboard)
        return

    payload["promoted"] = False
    payload["promoted_to_soi"] = False
    payload.pop("last_soi_id", None)
    payload.pop("last_promoted_at", None)

    dashboard.tsi_conditioner_last_artifact_payload = payload

    output_mode = str(
        payload.get("output_mode", "")
        or ""
    ).strip()

    if rewrite_metadata and output_mode != "Artifact":
        try:
            _tsi_conditioner_rewrite_result_metadata(
                dashboard,
                payload,
            )
        except Exception as e:
            dashboard.logger.debug(
                f"[Conditioner] Could not rewrite unpromoted metadata: {e}"
            )

    _tsi_conditioner_update_workflow_ribbon(dashboard)

    
def _tsi_conditioner_output_mode_is_artifact(dashboard: QtCore.QObject) -> bool:
    """
    Returns True when the Conditioner output mode is FISSURE-managed artifact
    storage instead of a user-selected output folder.
    """
    return _tsi_conditioner_get_run_output_mode(dashboard) == "Artifact"

def _tsi_conditioner_update_run_output_mode_gate(
    dashboard: QtCore.QObject,
):
    """
    Gates Conditioner output controls.

    Policy:
        Local Folder:
            user-selected Dashboard/local output folder is enabled.

        Artifact:
            output folder is disabled and ignored. The operation writes to
            FISSURE_ROOT/artifacts/<operation_id>/files.

        Remote node:
            force Artifact. Dashboard-local output folders are not valid for
            remote sensor-node operations.
    """
    combo = getattr(
        dashboard.ui,
        "comboBox_tsi_conditioner_run_output_mode",
        None,
    )

    output_folder_text = getattr(
        dashboard.ui,
        "textEdit_tsi_conditioner_run_output_folder",
        None,
    )

    browse_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_run_browse",
        None,
    )

    is_remote = False

    try:
        is_remote = selected_node_is_remote(dashboard)
    except Exception:
        is_remote = False

    current_mode = "Local Folder"

    if combo is not None:
        current_mode = combo.currentText().strip() or "Local Folder"

        if current_mode == "Local Folder + Artifact":
            current_mode = "Artifact"

        combo.blockSignals(True)
        combo.clear()

        if is_remote:
            combo.addItem("Artifact")
            combo.setCurrentText("Artifact")
            current_mode = "Artifact"
        else:
            combo.addItems([
                "Local Folder",
                "Artifact",
            ])

            if current_mode in ["Local Folder", "Artifact"]:
                combo.setCurrentText(current_mode)
            else:
                combo.setCurrentText("Local Folder")
                current_mode = "Local Folder"

        combo.blockSignals(False)

    artifact_mode = current_mode == "Artifact"

    if output_folder_text is not None:
        output_folder_text.setEnabled(not artifact_mode)

        if artifact_mode:
            output_folder_text.setToolTip(
                "Artifact output is stored under "
                "FISSURE_ROOT/artifacts/<operation_id>/files."
            )
        else:
            output_folder_text.setToolTip(
                str(getattr(dashboard, "tsi_conditioner_run_output_folder", "") or "")
            )

    if browse_button is not None:
        browse_button.setEnabled(not artifact_mode)

        if artifact_mode:
            browse_button.setToolTip(
                "Artifact output uses the managed FISSURE artifacts folder."
            )
        else:
            browse_button.setToolTip("Select output folder")

    _tsi_conditioner_update_workflow_ribbon(dashboard)

def _tsi_conditioner_find_latest_artifact_metadata_path(
    dashboard: QtCore.QObject,
) -> str:
    """
    Finds the newest local Conditioner artifact metadata file for the current run.

    This is needed because Sensor Node plugin operations currently do not send
    pluginOperationStarted/pluginOperationStopped messages, so the Dashboard may
    not know the operation_id while polling.

    Local artifact layout:
        FISSURE_ROOT/artifacts/<operation_id>/files/
        signal_conditioning_file_artifact.json
    """
    artifacts_root = os.path.join(
        fissure.utils.FISSURE_ROOT,
        "artifacts",
    )

    if not os.path.isdir(artifacts_root):
        return ""

    run_started_at = float(
        getattr(dashboard, "tsi_conditioner_run_started_at", 0.0) or 0.0
    )

    selected_node_uid = str(
        getattr(dashboard, "tsi_conditioner_node_uid", "")
        or getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    candidates = []

    try:
        operation_dirs = os.listdir(artifacts_root)
    except Exception as e:
        dashboard.logger.debug(
            f"[Conditioner] Could not list artifacts folder: {e}"
        )
        return ""

    for operation_id in operation_dirs:
        metadata_path = os.path.join(
            artifacts_root,
            operation_id,
            "files",
            "signal_conditioning_file_artifact.json",
        )

        if not os.path.isfile(metadata_path):
            continue

        try:
            metadata_mtime = os.path.getmtime(metadata_path)
        except Exception:
            continue

        # Avoid picking up old Conditioner artifact metadata from a previous run.
        if run_started_at and metadata_mtime < (run_started_at - 5.0):
            continue

        try:
            with open(metadata_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except Exception:
            continue

        if not isinstance(payload, dict):
            continue

        event_type = str(payload.get("event_type", "") or "").strip()
        artifact_type = str(payload.get("artifact_type", "") or "").strip()
        payload_node_uid = str(payload.get("node_uid", "") or "").strip()
        source_id = str(payload.get("source_id", "") or "").strip()

        is_conditioner_payload = (
            event_type == "signal_conditioning_artifact"
            or artifact_type == "iq_file_conditioning"
            or bool(payload.get("files"))
        )

        if not is_conditioner_payload:
            continue

        if selected_node_uid:
            if payload_node_uid and payload_node_uid != selected_node_uid:
                continue

            if source_id and source_id != selected_node_uid:
                continue

        candidates.append((metadata_mtime, metadata_path))

    if not candidates:
        return ""

    candidates.sort(key=lambda item: item[0], reverse=True)

    return candidates[0][1]

def _tsi_conditioner_payload_is_artifact_mode(payload: dict) -> bool:
    """
    Returns True when the current Conditioner result set is managed as an
    artifact.

    Artifact-mode results are treated as read-only from the Results table.
    """
    if not isinstance(payload, dict):
        payload = {}

    output_mode = str(payload.get("output_mode", "") or "").strip()

    if output_mode == "Local Folder + Artifact":
        output_mode = "Artifact"

    return output_mode == "Artifact"

def _tsi_conditioner_get_managed_artifact_folder_from_payload(
    payload: dict,
) -> str:
    """
    Returns the local managed artifact folder for a Conditioner payload.

    Prefer files_dir/output_dir. If those are absent, fall back to the parent
    folder of bundle_path or metadata_path.
    """
    if not isinstance(payload, dict):
        payload = {}

    candidates = [
        str(payload.get("files_dir", "") or "").strip(),
        str(payload.get("output_dir", "") or "").strip(),
    ]

    bundle_path = str(payload.get("bundle_path", "") or "").strip()
    if bundle_path:
        candidates.append(os.path.dirname(bundle_path))

    metadata_path = str(payload.get("metadata_path", "") or "").strip()
    if metadata_path:
        candidates.append(os.path.dirname(metadata_path))

    for candidate in candidates:
        if candidate and os.path.isdir(candidate):
            return candidate

    return ""

def _tsi_conditioner_current_results_are_artifact(
    dashboard: QtCore.QObject,
) -> bool:
    """
    Returns True when the currently loaded Conditioner results are artifact
    managed.
    """
    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    return _tsi_conditioner_payload_is_artifact_mode(payload)


def _tsi_conditioner_update_results_action_gate(
    dashboard: QtCore.QObject,
):
    """
    Gates Conditioner Results buttons.

    Local Folder:
        editable local files.

    Local Artifact:
        read-only managed local artifact. Preview/export/promote allowed.

    Remote Artifact:
        metadata-only until download/cache exists. Export/promote and artifact
        download are allowed. Preview remains disabled until the artifact is
        available locally.
    """
    table = getattr(
        dashboard.ui,
        "tableWidget_tsi_conditioner_results",
        None,
    )

    has_rows = bool(table is not None and table.rowCount() > 0)

    payload = getattr(
        dashboard,
        "tsi_conditioner_last_artifact_payload",
        {},
    ) or {}

    artifact_mode = _tsi_conditioner_payload_is_artifact_mode(payload)
    remote_artifact = _tsi_conditioner_payload_is_remote_artifact(
        dashboard,
        payload,
    )

    artifact_id = str(
        payload.get("artifact_id", "")
        or getattr(dashboard, "tsi_conditioner_last_artifact_id", "")
        or ""
    ).strip()

    artifact_folder = _tsi_conditioner_get_managed_artifact_folder_from_payload(
        payload
    )

    cached_path = ""
    if artifact_id:
        try:
            cached_path = (
                dashboard.backend.artifact_transfer_controller.get_local_path(
                    artifact_id
                )
                or ""
            )
        except Exception:
            cached_path = ""

    artifact_available_locally = bool(
        artifact_folder
        or cached_path
    )

    preview_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_results_preview",
        None,
    )
    if preview_button is not None:
        preview_button.setEnabled(
            has_rows
            and (
                not remote_artifact
                or artifact_available_locally
            )
        )
        preview_button.setToolTip(
            "Remote artifact files must be downloaded before preview."
            if remote_artifact and not artifact_available_locally
            else ""
        )

    export_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_results_export",
        None,
    )
    if export_button is not None:
        export_button.setEnabled(has_rows)

    promote_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_results_promote_to_soi",
        None,
    )
    if promote_button is not None:
        promote_button.setEnabled(has_rows)

    mutable_buttons = {
        "pushButton_tsi_conditioner_results_delete": (
            has_rows and not artifact_mode
        ),
        "pushButton_tsi_conditioner_results_delete_all": (
            has_rows and not artifact_mode
        ),
        "pushButton_tsi_conditioner_results_strip": (
            has_rows and not artifact_mode
        ),
        "pushButton_tsi_conditioner_results_strip_all": (
            has_rows and not artifact_mode
        ),
        "pushButton_tsi_conditioner_results_refresh": (
            has_rows and not artifact_mode
        ),
    }

    for button_name, enabled in mutable_buttons.items():
        button = getattr(dashboard.ui, button_name, None)
        if button is not None:
            button.setEnabled(bool(enabled))
            if artifact_mode:
                button.setToolTip(
                    "Disabled for artifact-managed results."
                )
            else:
                button.setToolTip("")

    folder_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_results_folder",
        None,
    )
    if folder_button is not None:
        folder_button.setEnabled(has_rows and not artifact_mode)
        if artifact_mode:
            folder_button.setToolTip(
                "Artifact results are managed. Use artifact controls."
            )
        else:
            folder_button.setToolTip("Open output folder")

    artifact_button = getattr(
        dashboard.ui,
        "pushButton_tsi_conditioner_run_download_artifact",
        None,
    )
    if artifact_button is not None:
        artifact_button.setEnabled(
            bool(artifact_mode and artifact_id)
        )

        if remote_artifact and cached_path:
            artifact_button.setToolTip(
                cached_path
            )
        elif remote_artifact:
            artifact_button.setToolTip(
                "Download remote Conditioner artifact"
            )
        elif artifact_mode:
            artifact_button.setToolTip(
                artifact_folder
                or cached_path
                or "Open managed Conditioner artifact folder"
            )
        else:
            artifact_button.setToolTip(
                "No Conditioner artifact for Local Folder output"
            )


def _tsi_conditioner_selected_node_is_remote(
    dashboard: QtCore.QObject,
) -> bool:
    """
    Returns True when the selected Dashboard node is remote.

    Treat errors as local so local workflows do not get unnecessarily blocked.
    """
    try:
        return selected_node_is_remote(dashboard)
    except Exception:
        return False


def _tsi_conditioner_payload_is_remote_artifact(
    dashboard: QtCore.QObject,
    payload: dict = None,
) -> bool:
    """
    Returns True when the current Conditioner results are artifact-managed
    and belong to a remote selected node.
    """
    if payload is None:
        payload = getattr(
            dashboard,
            "tsi_conditioner_last_artifact_payload",
            {},
        ) or {}

    if not isinstance(payload, dict):
        payload = {}

    output_mode = str(payload.get("output_mode", "") or "").strip()

    if output_mode == "Local Folder + Artifact":
        output_mode = "Artifact"

    return (
        output_mode == "Artifact"
        and _tsi_conditioner_selected_node_is_remote(dashboard)
    )

def _tsi_conditioner_is_conditioner_artifact_metadata(
    metadata: dict,
) -> bool:
    """
    Returns True when artifact metadata looks like a Conditioner artifact payload.
    """
    if not isinstance(metadata, dict):
        return False

    event_type = str(metadata.get("event_type", "") or "").strip()
    artifact_type = str(metadata.get("artifact_type", "") or "").strip()

    return (
        event_type == "signal_conditioning_artifact"
        or artifact_type == "iq_file_conditioning"
        or bool(metadata.get("files"))
    )

def _tsi_conditioner_payload_from_artifact_record(
    dashboard: QtCore.QObject,
    artifact_record: dict,
) -> dict:
    """
    Builds a Conditioner payload from a HIPRFISR artifact metadata record.

    This does not require local file access. For true remote artifacts, file
    paths remain sensor-node-local evidence references.
    """
    if not isinstance(artifact_record, dict):
        return {}

    metadata = artifact_record.get("metadata") or {}

    if not isinstance(metadata, dict):
        metadata = {}

    if not _tsi_conditioner_is_conditioner_artifact_metadata(metadata):
        return {}

    payload = dict(metadata)

    artifact_id = str(
        artifact_record.get("artifact_id", "")
        or artifact_record.get("id", "")
        or payload.get("artifact_id", "")
        or ""
    ).strip()

    operation_id = str(
        artifact_record.get("operation_id", "")
        or payload.get("operation_id", "")
        or ""
    ).strip()

    node_uid = str(
        artifact_record.get("node_uid", "")
        or artifact_record.get("source_id", "")
        or payload.get("node_uid", "")
        or payload.get("source_id", "")
        or getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    if artifact_id:
        payload["artifact_id"] = artifact_id

    if operation_id:
        payload["operation_id"] = operation_id

    if node_uid:
        payload["node_uid"] = node_uid
        payload.setdefault("source_id", node_uid)

    payload["output_mode"] = "Artifact"
    payload["remote_artifact"] = _tsi_conditioner_selected_node_is_remote(dashboard)
    payload["artifact_file_path"] = artifact_record.get("file_path", "")

    files = payload.get("files", []) or []

    if isinstance(files, list):
        normalized_files = []

        for file_record in files:
            if not isinstance(file_record, dict):
                continue

            row = dict(file_record)

            if payload["remote_artifact"]:
                row["path_scope"] = "sensor_node"
                row["remote_path"] = str(row.get("path", "") or "")
                row.setdefault("local_cache_path", "")
                row.setdefault("downloaded", False)
            else:
                row.setdefault("path_scope", "dashboard")

            row.setdefault("artifact_id", artifact_id)
            row.setdefault("node_uid", node_uid)

            normalized_files.append(row)

        payload["files"] = normalized_files
        payload["file_count"] = len(normalized_files)

    return payload

def _tsi_conditioner_apply_artifact_metadata_payload(
    dashboard: QtCore.QObject,
    payload: dict,
    status_text: str = "",
    finish_run: bool = False,
):
    """
    Applies Conditioner artifact metadata to the Results table.

    If dashboard.tsi_conditioner_opid is set, only that operation_id may update
    the Conditioner Results table. This prevents old artifact-list refreshes
    from overwriting the current run's results after the run has completed.
    """
    if not isinstance(payload, dict):
        return

    artifact_id = str(payload.get("artifact_id", "") or "").strip()
    operation_id = str(payload.get("operation_id", "") or "").strip()

    active_operation_id = str(
        getattr(dashboard, "tsi_conditioner_opid", "") or ""
    ).strip()

    running = bool(
        getattr(dashboard, "tsi_conditioner_running", False)
    )

    matches_active_operation = bool(
        operation_id
        and active_operation_id
        and operation_id == active_operation_id
    )

    if active_operation_id and not matches_active_operation:
        dashboard.logger.info(
            "[Conditioner] Rejecting non-matching artifact payload: "
            "payload_opid=%s active_opid=%s artifact_id=%s running=%s",
            operation_id,
            active_operation_id,
            artifact_id,
            running,
        )
        return

    if running and not active_operation_id:
        dashboard.logger.debug(
            "[Conditioner] Rejecting artifact payload while running because "
            "active operation_id is blank: payload_opid=%s artifact_id=%s",
            operation_id,
            artifact_id,
        )
        return

    if operation_id:
        dashboard.tsi_conditioner_opid = operation_id
        dashboard.tsi_conditioner_waiting_for_opid = False

    dashboard.tsi_conditioner_last_artifact_id = artifact_id
    dashboard.tsi_conditioner_last_artifact_payload = payload

    _tsi_conditioner_set_results_table_from_payload(
        dashboard,
        payload,
    )

    _tsi_conditioner_set_run_artifact_state_from_payload(
        dashboard,
        payload,
    )

    if status_text:
        _tsi_conditioner_set_run_status(
            dashboard,
            status_text,
        )
    else:
        _tsi_conditioner_set_run_status(
            dashboard,
            f"Artifact metadata loaded: {int(payload.get('file_count', 0) or 0)} files",
        )

    # Display-only refresh. Do not change the run state.
    if not running and not finish_run:
        _tsi_conditioner_update_workflow_ribbon(dashboard)
        _tsi_conditioner_update_results_action_gate(dashboard)
        return

    # Active run completion. Only allowed when the payload matches.
    if running and active_operation_id and not matches_active_operation:
        return

    progress_bar = getattr(
        dashboard.ui,
        "progressBar_tsi_conditioner_run_progress",
        None,
    )
    if progress_bar is not None:
        progress_bar.setRange(0, 100)
        progress_bar.setValue(100)

    dashboard.tsi_conditioner_running = False
    dashboard.tsi_conditioner_node_uid = ""
    dashboard.tsi_conditioner_waiting_for_opid = False

    _tsi_conditioner_set_run_button_state(
        dashboard,
        False,
    )

    _tsi_conditioner_update_workflow_ribbon(dashboard)
    _tsi_conditioner_update_results_action_gate(dashboard)


def handle_tsi_conditioner_artifact_metadata(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    artifacts: list = None,
):
    """
    Consumes artifact-list metadata for the Conditioner Results table.

    Rule:
        If dashboard.tsi_conditioner_opid is set, only metadata with that exact
        operation_id can populate the Results table.

    This must remain true even after the run finishes, because artifact-list
    refreshes can arrive later and include older Conditioner artifacts.

    A remote run may clear tsi_conditioner_running before its artifact-list
    metadata arrives. Treat a matching payload as completion when the progress
    bar is still in its pending 1-99% state.
    """
    artifacts = artifacts or []

    selected_node_uid = str(
        getattr(dashboard, "selected_node_uid", "") or ""
    ).strip()

    run_node_uid = str(
        getattr(dashboard, "tsi_conditioner_node_uid", "") or ""
    ).strip()

    expected_node_uid = (
        run_node_uid
        or selected_node_uid
        or str(node_uid or "").strip()
    )

    if (
        expected_node_uid
        and node_uid
        and expected_node_uid != str(node_uid).strip()
    ):
        return

    active_operation_id = str(
        getattr(dashboard, "tsi_conditioner_opid", "") or ""
    ).strip()

    running = bool(
        getattr(dashboard, "tsi_conditioner_running", False)
    )

    progress_bar = getattr(
        dashboard.ui,
        "progressBar_tsi_conditioner_run_progress",
        None,
    )
    progress_value = (
        int(progress_bar.value() or 0)
        if progress_bar is not None
        else 0
    )

    pending_completion = bool(
        active_operation_id
        and 0 < progress_value < 100
    )

    matching_payloads = []
    candidate_payloads = []
    ignored_count = 0

    for artifact in artifacts:
        payload = _tsi_conditioner_payload_from_artifact_record(
            dashboard,
            artifact,
        )

        if not payload:
            continue

        payload_node_uid = str(
            payload.get("node_uid", "")
            or payload.get("source_id", "")
            or ""
        ).strip()

        if (
            expected_node_uid
            and payload_node_uid
            and payload_node_uid != expected_node_uid
        ):
            continue

        payload_operation_id = str(
            payload.get("operation_id", "") or ""
        ).strip()

        if active_operation_id:
            if payload_operation_id == active_operation_id:
                matching_payloads.append(payload)
            else:
                ignored_count += 1
                dashboard.logger.debug(
                    "[Conditioner] Ignoring Conditioner artifact payload with "
                    "non-matching operation_id: payload_opid=%s active_opid=%s "
                    "artifact_id=%s running=%s",
                    payload_operation_id,
                    active_operation_id,
                    payload.get("artifact_id", ""),
                    running,
                )
            continue

        if running:
            dashboard.logger.debug(
                "[Conditioner] Ignoring artifact metadata while running "
                "because active operation_id is blank. payload_opid=%s "
                "artifact_id=%s",
                payload_operation_id,
                payload.get("artifact_id", ""),
            )
            continue

        candidate_payloads.append(payload)

    if active_operation_id:
        conditioner_payloads = matching_payloads

        if not conditioner_payloads:
            if ignored_count:
                dashboard.logger.info(
                    "[Conditioner] Ignored %s Conditioner artifact payload(s); "
                    "none matched active_opid=%s",
                    ignored_count,
                    active_operation_id,
                )
            return
    else:
        conditioner_payloads = candidate_payloads

    if not conditioner_payloads:
        return

    def _sort_key(payload):
        return str(
            payload.get("modified_at", "")
            or payload.get("created_at", "")
            or payload.get("time", "")
            or payload.get("operation_id", "")
            or ""
        )

    conditioner_payloads.sort(
        key=_sort_key,
        reverse=True,
    )

    payload = conditioner_payloads[0]

    payload_operation_id = str(
        payload.get("operation_id", "") or ""
    ).strip()

    matches_active_operation = bool(
        active_operation_id
        and payload_operation_id
        and payload_operation_id == active_operation_id
    )

    finish_run = bool(
        matches_active_operation
        and (
            running
            or pending_completion
        )
    )

    try:
        saturated_count = sum(
            1
            for row in payload.get("files", []) or []
            if isinstance(row, dict) and "saturated" in row
        )

        dashboard.logger.info(
            "[Conditioner] Applying artifact payload operation_id=%s "
            "artifact_id=%s files=%s saturated_fields=%s created_at=%s "
            "finish_run=%s active_opid=%s running=%s progress=%s",
            payload.get("operation_id", ""),
            payload.get("artifact_id", ""),
            len(payload.get("files", []) or []),
            saturated_count,
            payload.get("created_at", ""),
            finish_run,
            active_operation_id,
            running,
            progress_value,
        )
    except Exception:
        pass

    _tsi_conditioner_apply_artifact_metadata_payload(
        dashboard,
        payload,
        status_text=(
            f"Remote artifact metadata loaded: "
            f"{int(payload.get('file_count', 0) or 0)} files"
            if _tsi_conditioner_payload_is_remote_artifact(
                dashboard,
                payload,
            )
            else ""
        ),
        finish_run=finish_run,
    )
    

def _tsi_conditioner_request_artifact_refresh_for_payload(
    dashboard: QtCore.QObject,
    payload: dict = None,
):
    """
    Requests a hub-side Tactical artifact metadata refresh for the Conditioner
    artifact's node.

    This uses the existing artifact system:
        Backend.tacticalNodeArtifactsRefresh
        HIPRFISR sendArtifactsListTak
        DashboardCallbacks.sendArtifactsListTakReturn
        TacticalTabSlots.rebuild_tactical_node_artifacts

    It does not download artifact files.
    """
    if not isinstance(payload, dict):
        payload = getattr(
            dashboard,
            "tsi_conditioner_last_artifact_payload",
            {},
        ) or {}

    output_mode = str(payload.get("output_mode", "") or "").strip()

    if output_mode == "Local Folder + Artifact":
        output_mode = "Artifact"

    if output_mode != "Artifact":
        return

    node_uid = str(
        payload.get("node_uid", "")
        or payload.get("source_id", "")
        or getattr(dashboard, "tsi_conditioner_node_uid", "")
        or getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()

    if not node_uid:
        return

    try:
        asyncio.ensure_future(
            dashboard.backend.tacticalNodeArtifactsRefresh(node_uid)
        )
    except Exception as e:
        dashboard.logger.debug(
            f"[Conditioner] Could not request Tactical artifact refresh: {e}"
        )

__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value)
    and value.__module__ == __name__
]