from PyQt5 import QtCore, QtGui, QtWidgets

import asyncio
import inspect
import json
import os
import qasync
import subprocess
import time
import uuid

import fissure.utils
from fissure.Dashboard.SoiEvidenceController import collect_soi_artifact_ids
from fissure.Dashboard.UI_Components import Qt5
from fissure.utils.selected_node_utils import selected_node_is_local


ACTION_QUERY_CONTEXT = "sa.classifier.model"
ACTION_SCHEMA_CONTEXT = "sa.classifier.model"


def _sa_classifier_selected_node_available(dashboard: QtCore.QObject) -> bool:
    uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not uid:
        return False
    state = (getattr(dashboard, "node_states", {}) or {}).get(uid)
    return not (isinstance(state, dict) and state.get("connected") is False)


def _sa_classifier_source(dashboard: QtCore.QObject) -> str:
    return str(dashboard.ui.comboBox_sa_classifier_classify_input_source.currentText() or "None").strip()


def _sa_classifier_requested_input_mode(dashboard: QtCore.QObject) -> str:
    value = str(
        dashboard.ui.comboBox_sa_classifier_classify_input_mode.currentText()
        or "Combine Results"
    ).strip()

    if value not in {"Combine Results", "Per Input"}:
        return "Combine Results"

    return value


def _sa_classifier_input_count(dashboard: QtCore.QObject) -> int:
    report = getattr(dashboard, "sa_classifier_model_report", {}) or {}
    per_file = report.get("per_file", []) if isinstance(report, dict) else []

    if isinstance(per_file, list) and per_file:
        return len(per_file)

    evidence = getattr(dashboard, "sa_classifier_evidence", {}) or {}

    try:
        return max(0, int(evidence.get("file_count", 0) or 0))
    except Exception:
        return 0


def _sa_classifier_resolved_input_mode(dashboard: QtCore.QObject) -> str:
    return _sa_classifier_requested_input_mode(dashboard)


def _sa_classifier_shared_library_evidence_allowed(
    dashboard: QtCore.QObject,
) -> bool:
    return not (
        _sa_classifier_resolved_input_mode(dashboard) == "Per Input"
        and _sa_classifier_input_count(dashboard) > 1
    )


def _sa_classifier_sync_library_mode_availability(
    dashboard: QtCore.QObject,
) -> bool:
    """
    Keep the Library Match master control aligned with the active input mode.
    """
    available = _sa_classifier_shared_library_evidence_allowed(
        dashboard
    )
    checkbox = dashboard.ui.checkBox_sa_classifier_classify_library_enable

    if not available:
        checkbox.blockSignals(True)
        checkbox.setChecked(False)
        checkbox.blockSignals(False)
        checkbox.setEnabled(False)
        checkbox.setToolTip(
            "Library Match requires per-input RF metadata when multiple "
            "inputs are classified independently."
        )
    else:
        checkbox.setEnabled(True)
        checkbox.setToolTip("")

    return available


def _sa_classifier_library_ready(dashboard: QtCore.QObject) -> bool:
    if not dashboard.ui.checkBox_sa_classifier_classify_library_enable.isChecked():
        return False

    if not _sa_classifier_shared_library_evidence_allowed(dashboard):
        return False

    evidence = getattr(dashboard, "sa_classifier_evidence", {}) or {}
    frequency_ready = evidence.get("frequency_mhz") not in (None, "", "None")

    return (
        frequency_ready
        and dashboard.ui.checkBox_sa_classifier_classify_library_frequency.isChecked()
    )


def _sa_classifier_update_results_mode_state(
    dashboard: QtCore.QObject,
) -> None:
    mode = _sa_classifier_resolved_input_mode(dashboard)
    per_input = mode == "Per Input"

    table = dashboard.ui.tableWidget_sa_classifier_classify_results
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    table.setSelectionMode(
        QtWidgets.QAbstractItemView.ExtendedSelection
        if per_input
        else QtWidgets.QAbstractItemView.SingleSelection
    )

    dashboard.ui.label2_sa_classifier_classify_results_primary.setVisible(
        not per_input
    )
    dashboard.ui.comboBox_sa_classifier_classify_results_primary.setVisible(
        not per_input
    )

    if per_input:
        tooltip = (
            "Classify each input separately and keep independent results."
        )
    else:
        tooltip = (
            "Classify each input individually, then combine the per-input "
            "results into one overall assessment."
        )

    dashboard.ui.comboBox_sa_classifier_classify_input_mode.setToolTip(
        tooltip
    )
    dashboard.ui.label2_sa_classifier_classify_input_mode.setToolTip(
        tooltip
    )


def _sa_classifier_soi_context(dashboard: QtCore.QObject) -> dict:
    value = dashboard.ui.comboBox_sa_classifier_classify_input_soi.currentData()
    return dict(value) if isinstance(value, dict) else {}


def _sa_classifier_artifact_context(dashboard: QtCore.QObject) -> dict:
    value = dashboard.ui.comboBox_sa_classifier_classify_input_artifact.currentData()
    return dict(value) if isinstance(value, dict) else {}


def _sa_classifier_artifact_id(key, record: dict) -> str:
    return str((record or {}).get("artifact_id") or (record or {}).get("id") or key or "").strip()


def _sa_classifier_artifact_node_uid(record: dict) -> str:
    metadata = record.get("metadata", {}) if isinstance(record.get("metadata"), dict) else {}
    return str(
        record.get("node_uid")
        or record.get("source_id")
        or metadata.get("node_uid")
        or metadata.get("source_id")
        or ""
    ).strip()


def _sa_classifier_artifact_is_feature_analysis(record: dict) -> bool:
    metadata = record.get("metadata", {}) if isinstance(record.get("metadata"), dict) else {}
    artifact_type = str(record.get("artifact_type") or "").strip().lower()
    kind = str(metadata.get("kind") or "").strip().lower()
    role = str(metadata.get("role") or "").strip().lower()
    return (
        artifact_type == "feature_analysis"
        or kind == "feature_analysis"
        or role.startswith("feature_analysis")
    )

def _sa_classifier_feature_file_record(record: dict) -> dict:
    for file_record in record.get("files", []) or []:
        if not isinstance(file_record, dict):
            continue
        name = str(file_record.get("name") or file_record.get("relative_path") or "").strip()
        role = str(file_record.get("role") or "").strip().lower()
        if name == "tsi_features.json" or role == "feature_results":
            return dict(file_record)
    return {}


def _sa_classifier_evidence(dashboard: QtCore.QObject) -> dict:
    evidence = {
        "frequency_mhz": None,
        "bandwidth": "",
        "duration": "",
        "modulation": "",
        "feature_count": 0,
        "feature_sets": "",
        "file_count": 0,
    }
    soi = _sa_classifier_soi_context(dashboard)
    record = soi.get("record", {}) if isinstance(soi.get("record"), dict) else {}
    summary = record.get("summary", {}) if isinstance(record.get("summary"), dict) else {}

    for source in (record, summary):
        if evidence["frequency_mhz"] in (None, "", "None"):
            evidence["frequency_mhz"] = source.get("frequency_mhz", source.get("center_frequency_mhz"))
        if not evidence["bandwidth"]:
            evidence["bandwidth"] = source.get("bandwidth", source.get("bandwidth_hz", ""))
        if not evidence["duration"]:
            evidence["duration"] = source.get("duration", source.get("duration_s", ""))
        if not evidence["modulation"]:
            evidence["modulation"] = source.get("modulation", source.get("modulation_type", ""))

    source = _sa_classifier_source(dashboard)
    if source == "Artifact":
        context = _sa_classifier_artifact_context(dashboard)
        artifact = context.get("record", {}) if isinstance(context.get("record"), dict) else {}
        metadata = artifact.get("metadata", {}) if isinstance(artifact.get("metadata"), dict) else {}
        if evidence["frequency_mhz"] in (None, "", "None"):
            evidence["frequency_mhz"] = metadata.get("input_soi_frequency_mhz")
        evidence["feature_count"] = int(metadata.get("feature_count", 0) or 0)
        evidence["file_count"] = int(metadata.get("result_count", metadata.get("input_count", 0)) or 0)
        profile = str(metadata.get("profile", "") or "").replace("_", " ").strip().title()
        evidence["feature_sets"] = profile
    elif source == "Local File":
        path = str(dashboard.ui.textEdit_sa_classifier_classify_file.toPlainText() or "").strip()
        rows = _sa_classifier_read_feature_rows(path)
        names = []
        for row in rows:
            features = row.get("features", {}) if isinstance(row, dict) else {}
            if isinstance(features, dict):
                for name in features:
                    if name not in names:
                        names.append(name)
        evidence["feature_count"] = len(names)
        evidence["file_count"] = len(rows)
        report_path = os.path.join(os.path.dirname(path), "feature_extraction_report.json") if path else ""
        if report_path and os.path.isfile(report_path):
            try:
                with open(report_path, "r", encoding="utf-8") as handle:
                    report = json.load(handle)
                if evidence["frequency_mhz"] in (None, "", "None"):
                    evidence["frequency_mhz"] = report.get("input_soi_frequency_mhz")
                evidence["feature_sets"] = str(report.get("profile", "") or "").replace("_", " ").strip().title()
            except Exception:
                pass
    return evidence


def _sa_classifier_read_feature_rows(path: str) -> list:
    if not path or not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = json.load(handle)
        return value if isinstance(value, list) else []
    except Exception:
        return []


def _sa_classifier_format_number(value, suffix="") -> str:
    if value in (None, "", "None"):
        return "—"
    try:
        text = f"{float(value):.6f}".rstrip("0").rstrip(".")
    except Exception:
        text = str(value)
    return f"{text}{suffix}"


def _sa_classifier_set_combo_item_enabled(combo: QtWidgets.QComboBox, text: str, enabled: bool, tooltip: str = ""):
    index = combo.findText(text)
    if index < 0:
        return
    model = combo.model()
    item = model.item(index) if hasattr(model, "item") else None
    if item is not None:
        item.setEnabled(bool(enabled))
        item.setToolTip(tooltip or "")


def _sa_classifier_set_assessment(dashboard: QtCore.QObject, state: str, detail: str, symbol: str = "?"):
    dashboard.ui.label2_sa_classifier_classify_results_assessment1.setText(state or "—")
    dashboard.ui.label2_sa_classifier_classify_results_assessment2.setText(detail or "")
    dashboard.ui.label_sa_classifier_classify_results_image.setText(symbol)


def _sa_classifier_clear_results(dashboard: QtCore.QObject):
    dashboard.sa_classifier_library_results = []
    dashboard.sa_classifier_model_report = {}
    dashboard.sa_classifier_candidates = []
    dashboard.sa_classifier_per_input_results = []

    table = dashboard.ui.tableWidget_sa_classifier_classify_results
    table.setRowCount(0)

    combo = dashboard.ui.comboBox_sa_classifier_classify_results_primary
    combo.blockSignals(True)
    combo.clear()
    combo.setEditText("")
    combo.blockSignals(False)

    _sa_classifier_update_results_mode_state(dashboard)
    _sa_classifier_set_assessment(
        dashboard,
        "—",
        "No classification has been run yet.",
        "?",
    )
    _sa_classifier_update_save_button(dashboard)


def _sa_classifier_update_input_summary(dashboard: QtCore.QObject):
    evidence = _sa_classifier_evidence(dashboard)
    dashboard.sa_classifier_evidence = evidence

    text = (
        f"Frequency:       {_sa_classifier_format_number(evidence.get('frequency_mhz'), ' MHz')}\n"
        f"Bandwidth:       {_sa_classifier_format_number(evidence.get('bandwidth'))}\n"
        f"Duration:        {_sa_classifier_format_number(evidence.get('duration'))}\n"
        f"Feature Sets:    {evidence.get('feature_sets') or '—'}\n"
        f"Total Features:  {evidence.get('feature_count', 0) or '—'}\n"
        f"Files in Input:  {evidence.get('file_count', 0) or '—'}"
    )
    dashboard.ui.label_sa_classifier_classify_input_evidence.setText(text)

    frequency_ready = evidence.get("frequency_mhz") not in (None, "", "None")
    dashboard.ui.checkBox_sa_classifier_classify_library_frequency.setChecked(
        frequency_ready
    )
    dashboard.ui.label2_sa_classifier_classify_library_frequency.setText(
        _sa_classifier_format_number(
            evidence.get("frequency_mhz"),
            " MHz",
        )
        if frequency_ready
        else "Not available"
    )

    for checkbox_name, label_name in (
        (
            "checkBox_sa_classifier_classify_library_bandwidth",
            "label2_sa_classifier_classify_library_bandwidth",
        ),
        (
            "checkBox_sa_classifier_classify_library_duration",
            "label2_sa_classifier_classify_library_duration",
        ),
        (
            "checkBox_sa_classifier_classify_library_modulation",
            "label2_sa_classifier_classify_library_modulation",
        ),
    ):
        checkbox = getattr(dashboard.ui, checkbox_name)
        checkbox.setChecked(False)
        checkbox.setEnabled(False)

        label = getattr(dashboard.ui, label_name)
        label.setText("Not supported")
        label.setEnabled(False)

    dashboard.ui.checkBox_sa_classifier_classify_library_partial_matches.setChecked(
        False
    )

    _sa_classifier_update_results_mode_state(dashboard)
    _sa_classifier_update_library_info(dashboard)
    _sa_classifier_update_model_info(dashboard)
    _sa_classifier_update_run_state(dashboard)


def _sa_classifier_update_library_controls(
    dashboard: QtCore.QObject,
):
    ui = dashboard.ui
    mode_available = _sa_classifier_sync_library_mode_availability(
        dashboard
    )
    enabled = (
        mode_available
        and ui.checkBox_sa_classifier_classify_library_enable.isChecked()
    )

    evidence = getattr(
        dashboard,
        "sa_classifier_evidence",
        {},
    ) or {}
    frequency_ready = (
        evidence.get("frequency_mhz")
        not in (None, "", "None")
    )

    ui.checkBox_sa_classifier_classify_library_frequency.setEnabled(
        enabled and frequency_ready
    )
    ui.label2_sa_classifier_classify_library_frequency.setEnabled(
        enabled and frequency_ready
    )
    ui.label2_sa_classifier_classify_library_evidence.setEnabled(
        enabled
    )
    ui.label2_sa_classifier_classify_library_matching_options.setEnabled(
        enabled
    )
    ui.checkBox_sa_classifier_classify_library_multiple_candidates.setEnabled(
        enabled
    )

    multiple = (
        enabled
        and ui.checkBox_sa_classifier_classify_library_multiple_candidates.isChecked()
    )
    ui.spinBox_sa_classifier_classify_library_max_results.setEnabled(
        multiple
    )
    ui.label2_sa_classifier_classify_library_max_results.setEnabled(
        multiple
    )

    ui.checkBox_sa_classifier_classify_library_partial_matches.setEnabled(
        False
    )

    for name in (
        "checkBox_sa_classifier_classify_library_bandwidth",
        "checkBox_sa_classifier_classify_library_duration",
        "checkBox_sa_classifier_classify_library_modulation",
        "label2_sa_classifier_classify_library_bandwidth",
        "label2_sa_classifier_classify_library_duration",
        "label2_sa_classifier_classify_library_modulation",
    ):
        getattr(
            ui,
            name,
        ).setEnabled(False)

    ui.label_sa_classifier_classify_library_info.setEnabled(True)


def _sa_classifier_update_model_controls(dashboard: QtCore.QObject):
    ui = dashboard.ui
    enabled = (
        ui.checkBox_sa_classifier_classify_model_enable.isChecked()
        and _sa_classifier_selected_node_available(dashboard)
    )

    for name in (
        "label2_sa_classifier_classify_model_plugin",
        "label2_sa_classifier_classify_model_action",
        "label2_sa_classifier_classify_model_compatible_models_label",
        "label2_sa_classifier_classify_model_compatible_models",
        "label2_sa_classifier_classify_model_models_selected_label",
        "label2_sa_classifier_classify_model_models_selected",
        "label_sa_classifier_classify_model_info",
    ):
        getattr(ui, name).setEnabled(enabled)

    query_pending = bool(
        getattr(
            dashboard,
            "sa_classifier_action_query_pending",
            False,
        )
    )
    ui.pushButton_sa_classifier_classify_model_query.setEnabled(
        enabled and not query_pending
    )
    ui.comboBox_sa_classifier_classify_model_plugin.setEnabled(
        enabled
        and ui.comboBox_sa_classifier_classify_model_plugin.count() > 0
    )
    ui.comboBox_sa_classifier_classify_model_action.setEnabled(
        enabled
        and ui.comboBox_sa_classifier_classify_model_action.count() > 0
    )

    action_ready = (
        enabled
        and isinstance(
            ui.comboBox_sa_classifier_classify_model_action.currentData(),
            dict,
        )
    )
    ui.pushButton_sa_classifier_classify_model_customize.setEnabled(
        action_ready
    )


def _sa_classifier_update_library_info(
    dashboard: QtCore.QObject,
):
    mode_available = _sa_classifier_sync_library_mode_availability(
        dashboard
    )
    enabled = (
        mode_available
        and dashboard.ui.checkBox_sa_classifier_classify_library_enable.isChecked()
    )

    evidence = getattr(
        dashboard,
        "sa_classifier_evidence",
        {},
    ) or {}
    frequency_ready = (
        evidence.get("frequency_mhz")
        not in (None, "", "None")
    )

    if not mode_available:
        text = (
            "Unavailable for multi-input Per Input mode without "
            "per-input RF metadata."
        )
    elif not enabled:
        text = "Library Match disabled."
    elif frequency_ready:
        text = (
            "Ready. Current library matching uses frequency ranges "
            "from HIPRFISR."
        )
    else:
        text = (
            "Frequency evidence is required by the current "
            "library matcher."
        )

    dashboard.ui.label_sa_classifier_classify_library_info.setText(
        text
    )
    _sa_classifier_update_library_controls(
        dashboard
    )


def _sa_classifier_model_input_ready(dashboard: QtCore.QObject) -> tuple:
    if not _sa_classifier_selected_node_available(dashboard):
        return False, "Select an online Sensor Node."

    source = _sa_classifier_source(dashboard)
    if source == "Artifact":
        context = _sa_classifier_artifact_context(dashboard)
        if not context:
            return False, "Select a Feature Analysis Artifact."

        record = context.get("record", {}) if isinstance(context.get("record"), dict) else {}
        if not _sa_classifier_artifact_is_feature_analysis(record):
            return False, "Select a Feature Analysis Artifact."

        owner = str(context.get("node_uid") or "").strip()
        selected = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
        if owner and selected and owner != selected:
            return False, "The selected Feature Artifact belongs to another Sensor Node."

        return True, ""

    if source == "Local File":
        if not selected_node_is_local(dashboard):
            return False, "Local File classification requires the local Sensor Node."

        path = str(dashboard.ui.textEdit_sa_classifier_classify_file.toPlainText() or "").strip()
        if not path or not os.path.isfile(path):
            return False, "Select a local tsi_features.json file."
        if not _sa_classifier_read_feature_rows(path):
            return False, "The selected feature file is empty or invalid."

        return True, ""

    return False, "Select a Feature Artifact or Local File to use model classification."


def _sa_classifier_action_key(plugin_name: str, action_name: str) -> str:
    plugin_name = str(plugin_name or "").strip()
    action_name = str(action_name or "").strip()
    return f"{plugin_name}::{action_name}" if plugin_name and action_name else ""


def _sa_classifier_current_action_key(dashboard: QtCore.QObject) -> str:
    return _sa_classifier_action_key(
        getattr(dashboard, "sa_classifier_selected_plugin", ""),
        getattr(dashboard, "sa_classifier_selected_action", ""),
    )


def _sa_classifier_current_parameter_overrides(dashboard: QtCore.QObject) -> dict:
    key = _sa_classifier_current_action_key(dashboard)
    saved = getattr(dashboard, "sa_classifier_model_parameter_overrides", {}) or {}
    values = saved.get(key, {}) if key else {}
    return dict(values) if isinstance(values, dict) else {}


def _sa_classifier_model_selection_ready(dashboard: QtCore.QObject) -> bool:
    """Return False only when an explicit model selection disables every model."""
    overrides = _sa_classifier_current_parameter_overrides(dashboard)
    values = [
        value
        for name, value in overrides.items()
        if str(name).startswith("model_")
    ]

    if not values:
        return True

    for value in values:
        if isinstance(value, str):
            if value.strip().lower() in {
                "true",
                "1",
                "yes",
                "y",
                "on",
                "enabled",
            }:
                return True
        elif bool(value):
            return True

    return False


def _sa_classifier_update_model_info(dashboard: QtCore.QObject):
    enabled = dashboard.ui.checkBox_sa_classifier_classify_model_enable.isChecked()
    ready, reason = _sa_classifier_model_input_ready(dashboard)
    record = dashboard.ui.comboBox_sa_classifier_classify_model_action.currentData()
    overrides = _sa_classifier_current_parameter_overrides(dashboard)

    model_overrides = {
        name: value
        for name, value in overrides.items()
        if str(name).startswith("model_")
    }
    if model_overrides:
        dashboard.sa_classifier_models_selected = sum(
            1
            for value in model_overrides.values()
            if bool(value)
        )

    if not enabled:
        text = "Model Classification disabled."
    elif not ready:
        text = reason
    elif not isinstance(record, dict):
        text = "Query and select a classifier action."
    else:
        compatible = str(
            getattr(
                dashboard,
                "sa_classifier_compatible_models",
                "",
            )
            or "—"
        )
        selected = str(
            getattr(
                dashboard,
                "sa_classifier_models_selected",
                "",
            )
            or "All Compatible"
        )

        custom_parameters = [
            name
            for name in overrides
            if not str(name).startswith("model_")
        ]

        if compatible != "—":
            text = (
                f"Ready. {compatible} compatible model(s); "
                f"{selected} selected."
            )
        else:
            text = (
                "Ready. Customize to review classifier parameters "
                "and model selection."
            )

        if custom_parameters:
            count = len(custom_parameters)
            suffix = "parameter" if count == 1 else "parameters"
            text += f" {count} custom {suffix} applied."

    dashboard.ui.label_sa_classifier_classify_model_info.setText(text)
    dashboard.ui.label2_sa_classifier_classify_model_compatible_models.setText(
        str(
            getattr(
                dashboard,
                "sa_classifier_compatible_models",
                "",
            )
            or "—"
        )
    )
    dashboard.ui.label2_sa_classifier_classify_model_models_selected.setText(
        str(
            getattr(
                dashboard,
                "sa_classifier_models_selected",
                "Automatic",
            )
            or "Automatic"
        )
    )


def update_sa_classifier_selected_node_gate(dashboard: QtCore.QObject):
    uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    available = _sa_classifier_selected_node_available(dashboard)
    local = available and selected_node_is_local(dashboard)
    dashboard.ui.stackedWidget_sa_classifier_classify_model.setCurrentIndex(0 if available else 1)
    local_file_tooltip = (
        "Local File classification is available only with the local Sensor Node selected."
        if not local
        else ""
    )
    _sa_classifier_set_combo_item_enabled(
        dashboard.ui.comboBox_sa_classifier_classify_input_source,
        "Local File",
        local,
        local_file_tooltip,
    )
    destination = dashboard.ui.comboBox_sa_classifier_classify_run_destination
    local_results_tooltip = (
        "Local Results are available only with the local Sensor Node selected."
        if not local
        else ""
    )
    _sa_classifier_set_combo_item_enabled(destination, "Local Results", local, local_results_tooltip)
    if not local and destination.currentText() == "Local Results":
        destination.setCurrentText("Artifact")
    previous_uid = str(getattr(dashboard, "sa_classifier_action_node_uid", "") or "").strip()
    if previous_uid != uid:
        dashboard.sa_classifier_action_node_uid = uid
        _sa_classifier_clear_action_catalog(dashboard)
    _sa_classifier_update_model_controls(dashboard)
    _sa_classifier_update_model_info(dashboard)
    _sa_classifier_update_run_state(dashboard)


def _sa_classifier_refresh_sois(dashboard: QtCore.QObject, preferred_soi_key: str = ""):
    combo = dashboard.ui.comboBox_sa_classifier_classify_input_soi
    previous = combo.currentData()
    previous_key = str(previous.get("soi_key", "") or "").strip() if isinstance(previous, dict) else ""
    preferred_soi_key = str(preferred_soi_key or previous_key or "").strip()
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    rows = []
    tactical_sois = getattr(dashboard, "tactical_sois", {}) or {}
    if isinstance(tactical_sois, dict):
        iterable = tactical_sois.items()
    elif isinstance(tactical_sois, list):
        iterable = enumerate(tactical_sois)
    else:
        iterable = []
    for key, record in iterable:
        if not isinstance(record, dict):
            continue
        node_uid = str(record.get("node_uid") or "").strip()
        if selected_uid and node_uid and node_uid != selected_uid:
            continue
        soi_id = str(record.get("soi_id") or "").strip()
        if not soi_id:
            continue
        freq = record.get("frequency_mhz")
        summary = record.get("summary", {}) if isinstance(record.get("summary"), dict) else {}
        name = str(record.get("name") or summary.get("name") or "").strip()
        if not name:
            try:
                name = f"{float(freq):.3f} MHz SOI" if freq not in (None, "", "None") else soi_id
            except Exception:
                name = soi_id
        context = {
            "soi_key": str(record.get("soi_key") or key or "").strip(),
            "soi_id": soi_id,
            "node_uid": node_uid,
            "frequency_mhz": freq,
            "record": dict(record),
        }
        rows.append((name, context))
    rows.sort(key=lambda item: item[0].lower())
    combo.blockSignals(True)
    combo.clear()
    combo.addItem("Manual / No SOI", None)
    restored = 0
    for text, context in rows:
        combo.addItem(text, context)
        if preferred_soi_key and context["soi_key"] == preferred_soi_key:
            restored = combo.count() - 1
    combo.setCurrentIndex(restored)
    combo.blockSignals(False)


def refresh_sa_classifier_input_artifacts(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_sa_classifier_classify_input_artifact
    previous = combo.currentData()
    previous_id = str(previous.get("artifact_id", "") or "").strip() if isinstance(previous, dict) else ""
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    soi = _sa_classifier_soi_context(dashboard)
    allowed = None
    if soi:
        record = soi.get("record", {}) if isinstance(soi.get("record"), dict) else {}
        allowed = set()
        summary = record.get("summary", {}) if isinstance(record.get("summary"), dict) else {}
        for container in (record, summary):
            artifact_ids = collect_soi_artifact_ids(container)
            allowed.update(str(value or "").strip() for value in artifact_ids if str(value or "").strip())
    rows = []
    artifacts = getattr(dashboard, "tactical_artifacts", {}) or {}
    if isinstance(artifacts, dict):
        iterable = artifacts.items()
    elif isinstance(artifacts, list):
        iterable = enumerate(artifacts)
    else:
        iterable = []
    for key, record in iterable:
        if not isinstance(record, dict) or not _sa_classifier_artifact_is_feature_analysis(record):
            continue
        artifact_id = _sa_classifier_artifact_id(key, record)
        if not artifact_id or (allowed is not None and artifact_id not in allowed):
            continue
        node_uid = _sa_classifier_artifact_node_uid(record)
        if selected_uid and node_uid and node_uid != selected_uid:
            continue
        name = str(record.get("name") or "Feature Analysis").strip()
        context = {
            "artifact_id": artifact_id,
            "node_uid": node_uid,
            "record": dict(record),
        }
        rows.append((f"{name} | {artifact_id}", context))
    rows.sort(key=lambda item: item[0].lower())
    combo.blockSignals(True)
    combo.clear()
    combo.addItem("Select Artifact...", None)
    restored = 0
    for text, context in rows:
        combo.addItem(text, context)
        if previous_id and context["artifact_id"] == previous_id:
            restored = combo.count() - 1
    if restored == 0 and len(rows) == 1:
        restored = 1
    combo.setCurrentIndex(restored)
    combo.blockSignals(False)
    _sa_classifier_update_input_summary(dashboard)


def refresh_sa_classifier_context(dashboard: QtCore.QObject, preferred_soi_key: str = ""):
    """Refresh Classifier SOI/Artifact context while preserving or prefilling selections."""
    soi_combo = dashboard.ui.comboBox_sa_classifier_classify_input_soi
    artifact_combo = dashboard.ui.comboBox_sa_classifier_classify_input_artifact
    current = _sa_classifier_soi_context(dashboard)
    current_key = str(current.get("soi_key") or "") if current else ""
    artifact_id = str((_sa_classifier_artifact_context(dashboard) or {}).get("artifact_id") or "")
    _sa_classifier_refresh_sois(dashboard, preferred_soi_key=preferred_soi_key or current_key)
    refresh_sa_classifier_input_artifacts(dashboard)
    if artifact_id:
        for index in range(artifact_combo.count()):
            data = artifact_combo.itemData(index)
            if isinstance(data, dict) and str(data.get("artifact_id") or "") == artifact_id:
                artifact_combo.setCurrentIndex(index)
                break
    _sa_classifier_update_input_summary(dashboard)


def _sa_classifier_update_source_page(dashboard: QtCore.QObject):
    source = _sa_classifier_source(dashboard)
    page_index = {"None": 0, "Local File": 1, "Artifact": 2}.get(source, 0)
    dashboard.ui.stackedWidget_sa_classifier_classify_input.setCurrentIndex(page_index)
    if source == "Artifact":
        refresh_sa_classifier_input_artifacts(dashboard)
    else:
        _sa_classifier_update_input_summary(dashboard)


def _sa_classifier_clear_action_catalog(dashboard: QtCore.QObject):
    dashboard.sa_classifier_action_catalog = []
    dashboard.sa_classifier_selected_plugin = ""
    dashboard.sa_classifier_selected_action = ""
    dashboard.sa_classifier_model_parameters = {}
    for combo in (
        dashboard.ui.comboBox_sa_classifier_classify_model_plugin,
        dashboard.ui.comboBox_sa_classifier_classify_model_action,
    ):
        combo.blockSignals(True)
        combo.clear()
        combo.blockSignals(False)
    _sa_classifier_update_model_controls(dashboard)


def _sa_classifier_populate_actions_for_plugin(dashboard: QtCore.QObject):
    plugin = str(dashboard.ui.comboBox_sa_classifier_classify_model_plugin.currentText() or "").strip()
    combo = dashboard.ui.comboBox_sa_classifier_classify_model_action
    combo.blockSignals(True)
    combo.clear()
    for record in getattr(dashboard, "sa_classifier_action_catalog", []) or []:
        if str(record.get("plugin") or "").strip() != plugin:
            continue
        action = str(record.get("action") or "").strip()
        if action:
            combo.addItem(action, dict(record))
    combo.blockSignals(False)
    if combo.count() > 0:
        combo.setCurrentIndex(0)
    _slotSA_ClassifierModelActionChanged(dashboard)
    _sa_classifier_update_model_controls(dashboard)


def _slotSA_ClassifierTabChanged(dashboard: QtCore.QObject):
    if dashboard.ui.tabWidget_signal_analysis.currentWidget() is not dashboard.ui.tab_tsi_classifier:
        return
    if dashboard.ui.tabWidget_tsi_classifier.currentWidget() is not dashboard.ui.tab_classifier_classify:
        return
    preferred = str(getattr(dashboard, "signal_analysis_prefill_soi_key", "") or "").strip()
    refresh_sa_classifier_context(dashboard, preferred_soi_key=preferred)
    if preferred:
        dashboard.signal_analysis_prefill_soi_key = None
    update_sa_classifier_selected_node_gate(dashboard)
    _sa_classifier_update_input_summary(dashboard)
    

def initialize_sa_classifier_controls(dashboard: QtCore.QObject):
    """Initialize the new Signal Analysis Classify workflow."""
    dashboard.sa_classifier_running = False
    dashboard.sa_classifier_run_id = ""
    dashboard.sa_classifier_operation_id = ""
    dashboard.sa_classifier_model_node_uid = ""
    dashboard.sa_classifier_model_launched = False
    dashboard.sa_classifier_model_operation_complete = False
    dashboard.sa_classifier_run_local_results = False
    dashboard.sa_classifier_stop_requested = False
    dashboard.sa_classifier_artifact_id = ""
    dashboard.sa_classifier_library_pending = False
    dashboard.sa_classifier_model_pending = False
    dashboard.sa_classifier_library_results = []
    dashboard.sa_classifier_library_evidence_used = []
    dashboard.sa_classifier_model_report = {}
    dashboard.sa_classifier_candidates = []
    dashboard.sa_classifier_action_catalog = []
    dashboard.sa_classifier_action_query_pending = False
    dashboard.sa_classifier_model_parameters = {}
    dashboard.sa_classifier_model_parameter_overrides = {}
    dashboard.sa_classifier_schema_request_key = ""
    dashboard.sa_classifier_compatible_models = ""
    dashboard.sa_classifier_models_selected = "All Compatible"
    dashboard.sa_classifier_auto_download_artifact_id = ""

    mode_combo = dashboard.ui.comboBox_sa_classifier_classify_input_mode
    mode_combo.blockSignals(True)
    mode_combo.clear()
    mode_combo.addItems(
        [
            "Combine Results",
            "Per Input",
        ]
    )
    mode_combo.setCurrentText("Combine Results")
    mode_combo.blockSignals(False)

    if not bool(
        getattr(
            dashboard,
            "sa_classifier_mode_signals_connected",
            False,
        )
    ):
        mode_combo.currentIndexChanged.connect(
            lambda _index: _slotSA_ClassifierInputModeChanged(
                dashboard
            )
        )
        dashboard.ui.tableWidget_sa_classifier_classify_results.itemSelectionChanged.connect(
            lambda: _slotSA_ClassifierResultsSelectionChanged(
                dashboard
            )
        )
        dashboard.sa_classifier_mode_signals_connected = True

    source = dashboard.ui.comboBox_sa_classifier_classify_input_source
    source.blockSignals(True)
    source.clear()
    source.addItems(["None", "Artifact", "Local File"])
    source.setCurrentText("Artifact")
    source.blockSignals(False)

    destination = dashboard.ui.comboBox_sa_classifier_classify_run_destination
    destination.blockSignals(True)
    destination.clear()
    destination.addItems(["Artifact", "Local Results"])
    destination.setCurrentText("Artifact")
    destination.blockSignals(False)

    dashboard.ui.comboBox_sa_classifier_classify_results_primary.setEditable(True)
    dashboard.ui.checkBox_sa_classifier_classify_library_enable.setChecked(True)
    dashboard.ui.checkBox_sa_classifier_classify_library_multiple_candidates.setChecked(True)
    dashboard.ui.spinBox_sa_classifier_classify_library_max_results.setRange(1, 100)
    if dashboard.ui.spinBox_sa_classifier_classify_library_max_results.value() <= 0:
        dashboard.ui.spinBox_sa_classifier_classify_library_max_results.setValue(10)

    dashboard.ui.checkBox_sa_classifier_classify_model_enable.setChecked(True)
    dashboard.ui.progressBar_sa_classifier_classify_run_progress.setRange(0, 100)
    dashboard.ui.progressBar_sa_classifier_classify_run_progress.setValue(0)
    dashboard.ui.label2_sa_classifier_classify_run_status.setText("Idle")
    dashboard.ui.label2_sa_classifier_classify_run_operation_id.setText("—")
    dashboard.ui.label2_sa_classifier_classify_run_artifact_id.setText("—")
    dashboard.ui.pushButton_sa_classifier_classify_run_artifact.setText("Download Artifact")
    dashboard.ui.pushButton_sa_classifier_classify_run_artifact.setEnabled(False)

    browse_icon = os.path.join(fissure.utils.UI_DIR, "Icons", "folder_black.svg")
    if os.path.isfile(browse_icon):
        button = dashboard.ui.pushButton_sa_classifier_classify_input_file
        button.setIcon(QtGui.QIcon(browse_icon))
        button.setText("")
        button.setToolTip("Select local tsi_features.json")
        button.setIconSize(QtCore.QSize(18, 18))

    refresh_icon = os.path.join(fissure.utils.UI_DIR, "Icons", "refresh.png")
    if os.path.isfile(refresh_icon):
        button = dashboard.ui.pushButton_sa_classifier_classify_input_artifact_refresh
        button.setIcon(QtGui.QIcon(refresh_icon))
        button.setText("")
        button.setToolTip("Refresh available Feature Analysis Artifacts")
        button.setIconSize(QtCore.QSize(18, 18))

    select_node_icon = os.path.join(fissure.utils.UI_DIR, "Icons", "select_node.png")
    if os.path.isfile(select_node_icon):
        dashboard.ui.label_sa_classifier_classify_model_select_sensor_node_image.setPixmap(
            QtGui.QPixmap(select_node_icon)
        )

    _sa_classifier_refresh_sois(dashboard)
    refresh_sa_classifier_input_artifacts(dashboard)
    _sa_classifier_clear_action_catalog(dashboard)
    _sa_classifier_clear_results(dashboard)
    _sa_classifier_update_source_page(dashboard)
    update_sa_classifier_selected_node_gate(dashboard)
    _sa_classifier_update_library_controls(dashboard)
    _sa_classifier_update_model_controls(dashboard)
    _sa_classifier_update_artifact_button(dashboard)


def _sa_classifier_update_run_state(dashboard: QtCore.QObject):
    button = dashboard.ui.pushButton_sa_classifier_classify_run_start_stop

    if bool(getattr(dashboard, "sa_classifier_running", False)):
        button.setText("Stop")
        uid = str(getattr(dashboard, "sa_classifier_model_node_uid", "") or "").strip()
        node = (getattr(dashboard, "node_states", {}) or {}).get(uid, {}) or {}
        pending = (getattr(dashboard, "_manual_action_recovery_pending", {}) or {}).get("classifier")
        blocked = (
            bool(getattr(dashboard, "sa_classifier_stop_requested", False))
            or (bool(getattr(dashboard, "sa_classifier_model_launched", False)) and (
                (isinstance(node, dict) and node.get("connected") is False)
                or pending == (uid, str(getattr(dashboard, "sa_classifier_operation_id", "") or ""))
            ))
        )
        button.setEnabled(not blocked)
        return

    library_enabled = (
        dashboard.ui.checkBox_sa_classifier_classify_library_enable.isChecked()
    )
    library_ready = (
        _sa_classifier_library_ready(dashboard)
        if library_enabled
        else False
    )

    model_enabled = (
        dashboard.ui.checkBox_sa_classifier_classify_model_enable.isChecked()
    )
    model_input_ready, model_reason = _sa_classifier_model_input_ready(
        dashboard
    )
    model_selection_ready = _sa_classifier_model_selection_ready(
        dashboard
    )

    action_record = (
        dashboard.ui.comboBox_sa_classifier_classify_model_action.currentData()
    )
    action_ready = (
        isinstance(action_record, dict)
        and bool(str(action_record.get("plugin") or "").strip())
        and bool(str(action_record.get("action") or "").strip())
    )

    model_ready = (
        model_enabled
        and model_input_ready
        and action_ready
        and model_selection_ready
    )

    any_enabled = library_enabled or model_enabled
    all_enabled_methods_ready = (
        any_enabled
        and (not library_enabled or library_ready)
        and (not model_enabled or model_ready)
    )

    button.setText("Start Classification")
    button.setEnabled(all_enabled_methods_ready)

    if not any_enabled:
        status = "Enable a classification method"
    elif model_enabled and not action_ready:
        status = "Select a classifier action"
    elif model_enabled and not model_input_ready:
        status = model_reason or "Model input not ready"
    elif model_enabled and not model_selection_ready:
        status = "Select at least one model"
    elif library_enabled and not library_ready:
        status = "Library Match not ready"
    else:
        status = "Ready"

    current_status = str(
        dashboard.ui.label2_sa_classifier_classify_run_status.text()
        or ""
    ).strip()

    if (
        status != "Ready"
        or current_status
        in {
            "",
            "Idle",
            "Ready",
            "Not Ready",
            "Enable a classification method",
            "Select a classifier action",
            "Model input not ready",
            "Select at least one model",
            "Library Match not ready",
        }
    ):
        dashboard.ui.label2_sa_classifier_classify_run_status.setText(
            status
        )


def _sa_classifier_update_artifact_button(dashboard: QtCore.QObject):
    button = dashboard.ui.pushButton_sa_classifier_classify_run_artifact
    artifact_id = str(getattr(dashboard, "sa_classifier_artifact_id", "") or "").strip()
    if not artifact_id:
        button.setText("Download Artifact")
        button.setEnabled(False)
        return
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    local_path = controller.get_local_path(artifact_id) if controller is not None else None
    if local_path:
        button.setText("Open Artifact")
        button.setEnabled(True)
        button.setToolTip(str(local_path))
    else:
        button.setText("Download Artifact")
        button.setEnabled(True)
        button.setToolTip(f"Download Classification Analysis Artifact {artifact_id}")


def _sa_classifier_set_running(dashboard: QtCore.QObject, running: bool, status: str = ""):
    dashboard.sa_classifier_running = bool(running)

    button = dashboard.ui.pushButton_sa_classifier_classify_run_start_stop
    button.setText("Stop" if running else "Start Classification")
    button.setProperty("running", bool(running))
    button.style().unpolish(button)
    button.style().polish(button)
    button.update()

    progress = dashboard.ui.progressBar_sa_classifier_classify_run_progress
    progress.setRange(0, 0 if running else 100)
    if not running and progress.maximum() == 100:
        progress_value = 100 if status.lower().startswith("completed") else progress.value()
        progress.setValue(progress_value)

    if status:
        dashboard.ui.label2_sa_classifier_classify_run_status.setText(status)

    _sa_classifier_update_run_state(dashboard)


def _sa_classifier_finish_if_complete(dashboard: QtCore.QObject):
    if not bool(getattr(dashboard, "sa_classifier_running", False)):
        return
    if bool(getattr(dashboard, "sa_classifier_stop_requested", False)):
        return
    # Model results and the remote operation terminal event can arrive in
    # either order. Both must finish before releasing this run's widgets.
    if (bool(getattr(dashboard, "sa_classifier_model_launched", False))
            and not bool(getattr(dashboard, "sa_classifier_model_operation_complete", False))):
        return
    library_pending = bool(getattr(dashboard, "sa_classifier_library_pending", False))
    model_pending = bool(getattr(dashboard, "sa_classifier_model_pending", False))
    if library_pending or model_pending:
        return
    _sa_classifier_render_results(dashboard)
    _sa_classifier_set_running(dashboard, False, "Completed")


def _sa_classifier_normalize_label(value: str) -> str:
    return " ".join(str(value or "").replace("_", " ").replace("-", " ").lower().split())


def _sa_classifier_labels_correlate(a: str, b: str) -> bool:
    na = _sa_classifier_normalize_label(a)
    nb = _sa_classifier_normalize_label(b)
    return bool(na and nb and (na == nb or na in nb or nb in na))


def _sa_classifier_library_evidence_labels(
    dashboard: QtCore.QObject,
) -> list:
    """Return the Card 2 evidence labels selected for the library lookup."""
    ui = dashboard.ui
    labels = []

    for checkbox_name, fallback in (
        ("checkBox_sa_classifier_classify_library_frequency", "Frequency"),
        ("checkBox_sa_classifier_classify_library_bandwidth", "Bandwidth"),
        ("checkBox_sa_classifier_classify_library_duration", "Duration"),
        ("checkBox_sa_classifier_classify_library_modulation", "Modulation"),
    ):
        checkbox = getattr(ui, checkbox_name, None)
        if checkbox is None or not checkbox.isChecked():
            continue

        text = str(checkbox.text() or "").strip()
        labels.append(text or fallback)

    return labels


def _sa_classifier_input_feature_names(
    dashboard: QtCore.QObject,
) -> set:
    """Return locally readable feature names for pre-run model compatibility."""
    source = _sa_classifier_source(dashboard)
    rows = []

    if source == "Local File":
        path = str(
            dashboard.ui.textEdit_sa_classifier_classify_file.toPlainText()
            or ""
        ).strip()
        rows = _sa_classifier_read_feature_rows(path)

    elif source == "Artifact":
        context = _sa_classifier_artifact_context(dashboard)
        artifact_id = str(context.get("artifact_id") or "").strip()
        controller = getattr(
            dashboard.backend,
            "artifact_transfer_controller",
            None,
        )

        candidate_paths = []

        if controller is not None and artifact_id:
            local_files = controller.get_local_files(artifact_id) or {}

            for path in local_files.values():
                path = str(path or "")
                if os.path.basename(path) == "tsi_features.json":
                    candidate_paths.append(path)

            local_path = controller.get_local_path(artifact_id)
            if local_path:
                local_path = str(local_path)

                if os.path.isdir(local_path):
                    candidate_paths.append(
                        os.path.join(local_path, "tsi_features.json")
                    )
                elif os.path.basename(local_path) == "tsi_features.json":
                    candidate_paths.append(local_path)

        for path in candidate_paths:
            if os.path.isfile(path):
                rows = _sa_classifier_read_feature_rows(path)
                if rows:
                    break

    names = set()

    for row in rows:
        if not isinstance(row, dict):
            continue

        features = row.get("features", {})
        if isinstance(features, dict):
            names.update(str(name) for name in features.keys())

    return names


def _sa_classifier_model_candidates(report: dict) -> list:
    """Build aggregate candidates from per-input consensus plus model evidence."""
    consensus_counts = {}
    model_support = {}
    total_inputs = 0

    for row in report.get("per_file", []) or []:
        if not isinstance(row, dict):
            continue

        consensus = (
            row.get("consensus", {})
            if isinstance(row.get("consensus"), dict)
            else {}
        )
        consensus_label = str(consensus.get("label") or "").strip()

        if consensus_label:
            consensus_counts[consensus_label] = (
                consensus_counts.get(consensus_label, 0) + 1
            )
            total_inputs += 1

        votes = row.get("votes", {})
        if not isinstance(votes, dict):
            continue

        for model_name, label in votes.items():
            model_name = str(model_name or "").strip()
            label = str(label or "").strip()

            if not model_name or not label:
                continue

            by_model = model_support.setdefault(label, {})
            by_model[model_name] = by_model.get(model_name, 0) + 1

    if not consensus_counts:
        batch = report.get("batch", {}) if isinstance(report, dict) else {}
        batch_counts = (
            batch.get("vote_counts", {})
            if isinstance(batch, dict)
            else {}
        )

        if isinstance(batch_counts, dict):
            for label, count in batch_counts.items():
                label = str(label or "").strip()
                if not label:
                    continue

                try:
                    consensus_counts[label] = int(count)
                except Exception:
                    continue

        try:
            total_inputs = int(batch.get("files_used", 0) or 0)
        except Exception:
            total_inputs = 0

    if total_inputs <= 0:
        total_inputs = sum(consensus_counts.values())

    output = []

    for label, count in sorted(
        consensus_counts.items(),
        key=lambda item: (-item[1], item[0].lower()),
    ):
        contributions = model_support.get(label, {})
        contribution_text = ", ".join(
            f"{model}: {votes}"
            for model, votes in sorted(
                contributions.items(),
                key=lambda item: (-item[1], item[0].lower()),
            )
        )

        output.append(
            {
                "source": "Model",
                "label": label,
                "basis": contribution_text or "Model consensus",
                "agreement": (
                    f"{count} / {total_inputs} inputs"
                    if total_inputs
                    else "—"
                ),
                "agreement_value": (
                    count / total_inputs
                    if total_inputs
                    else None
                ),
                "support_count": count,
                "support_total": total_inputs,
                "model_support": dict(contributions),
            }
        )

    return output


def _sa_classifier_per_input_results(report: dict) -> list:
    output = []

    for row in report.get("per_file", []) or []:
        if not isinstance(row, dict):
            continue

        file_name = str(row.get("file") or "").strip()
        votes = (
            row.get("votes", {})
            if isinstance(row.get("votes"), dict)
            else {}
        )
        vote_counts = (
            row.get("vote_counts", {})
            if isinstance(row.get("vote_counts"), dict)
            else {}
        )
        consensus = (
            row.get("consensus", {})
            if isinstance(row.get("consensus"), dict)
            else {}
        )

        label = str(consensus.get("label") or "").strip()

        try:
            models_used = int(row.get("models_used", 0) or 0)
        except Exception:
            models_used = 0

        try:
            winner_count = int(vote_counts.get(label, 0) or 0)
        except Exception:
            winner_count = 0

        agreement_value = (
            winner_count / models_used
            if models_used > 0 and winner_count > 0
            else None
        )

        model_votes = " | ".join(
            f"{model}: {prediction}"
            for model, prediction in sorted(
                votes.items(),
                key=lambda item: str(item[0]).lower(),
            )
        )

        candidates = []

        for candidate_label, count in sorted(
            vote_counts.items(),
            key=lambda item: (-int(item[1]), str(item[0]).lower()),
        ):
            candidate_label = str(candidate_label or "").strip()
            if not candidate_label:
                continue

            try:
                count_value = int(count)
            except Exception:
                count_value = 0

            candidate = {
                "source": "model",
                "label": candidate_label,
                "votes": count_value,
            }

            if models_used > 0:
                candidate["agreement"] = count_value / models_used

            candidates.append(candidate)

        output.append(
            {
                "input": file_name or "Unnamed input",
                "label": label or "—",
                "basis": model_votes or "No model votes",
                "agreement": (
                    f"{winner_count} / {models_used} models"
                    if models_used > 0 and winner_count > 0
                    else "—"
                ),
                "agreement_value": agreement_value,
                "models_used": models_used,
                "votes": dict(votes),
                "vote_counts": dict(vote_counts),
                "candidates": candidates,
                "raw": dict(row),
            }
        )

    return output


def _sa_classifier_selected_per_input_results(
    dashboard: QtCore.QObject,
) -> list:
    table = dashboard.ui.tableWidget_sa_classifier_classify_results
    selection_model = table.selectionModel()

    if selection_model is None:
        return []

    rows = sorted(
        {index.row() for index in selection_model.selectedRows()}
    )
    selected = []

    for row in rows:
        item = table.item(row, 0)

        if item is None:
            continue

        value = item.data(QtCore.Qt.UserRole)

        if isinstance(value, dict):
            selected.append(dict(value))

    return selected


def _sa_classifier_configure_results_table(
    dashboard: QtCore.QObject,
    mode: str,
) -> None:
    table = dashboard.ui.tableWidget_sa_classifier_classify_results
    header = table.horizontalHeader()
    vertical_header = table.verticalHeader()

    vertical_header.setVisible(False)
    table.setWordWrap(False)
    table.setTextElideMode(QtCore.Qt.ElideRight)
    table.setHorizontalScrollMode(
        QtWidgets.QAbstractItemView.ScrollPerPixel
    )
    vertical_header.setSectionResizeMode(
        QtWidgets.QHeaderView.ResizeToContents
    )
    header.setStretchLastSection(False)

    if mode == "Per Input":
        header.setSectionResizeMode(
            QtWidgets.QHeaderView.Interactive
        )
        table.setColumnWidth(0, 290)
        table.setColumnWidth(1, 160)
        table.setColumnWidth(2, 105)
        table.setColumnWidth(3, 330)
    else:
        header.setSectionResizeMode(
            0,
            QtWidgets.QHeaderView.ResizeToContents,
        )
        header.setSectionResizeMode(
            1,
            QtWidgets.QHeaderView.ResizeToContents,
        )
        header.setSectionResizeMode(
            2,
            QtWidgets.QHeaderView.ResizeToContents,
        )
        header.setSectionResizeMode(
            3,
            QtWidgets.QHeaderView.Stretch,
        )

    table.resizeRowsToContents()


def _sa_classifier_render_results(dashboard: QtCore.QObject):
    mode = _sa_classifier_resolved_input_mode(dashboard)
    table = dashboard.ui.tableWidget_sa_classifier_classify_results
    primary_combo = dashboard.ui.comboBox_sa_classifier_classify_results_primary

    _sa_classifier_update_results_mode_state(dashboard)

    if mode == "Per Input":
        results = _sa_classifier_per_input_results(
            getattr(dashboard, "sa_classifier_model_report", {}) or {}
        )
        dashboard.sa_classifier_per_input_results = results
        dashboard.sa_classifier_candidates = []

        table.setRowCount(0)
        table.setColumnCount(4)
        table.setHorizontalHeaderLabels(
            [
                "Input",
                "Classification",
                "Support",
                "Model Votes",
            ]
        )

        for row_index, result in enumerate(results):
            table.insertRow(row_index)

            values = (
                result.get("input", ""),
                result.get("label", ""),
                result.get("agreement", ""),
                result.get("basis", ""),
            )

            for column, value in enumerate(values):
                text = str(value or "—")
                item = QtWidgets.QTableWidgetItem(text)
                item.setFlags(
                    item.flags()
                    & ~QtCore.Qt.ItemIsEditable
                )

                if column == 0:
                    item.setData(
                        QtCore.Qt.UserRole,
                        dict(result),
                    )
                    item.setToolTip(text)
                elif column == 3:
                    item.setToolTip(text)

                table.setItem(
                    row_index,
                    column,
                    item,
                )

        _sa_classifier_configure_results_table(
            dashboard,
            "Per Input",
        )

        primary_combo.blockSignals(True)
        primary_combo.clear()
        primary_combo.setEditText("")
        primary_combo.blockSignals(False)

        if results:
            _sa_classifier_set_assessment(
                dashboard,
                "Per Input",
                (
                    f"{len(results)} inputs classified separately. "
                    "Select rows to create SOIs."
                ),
                "i",
            )
        else:
            _sa_classifier_set_assessment(
                dashboard,
                "Inconclusive",
                "No per-input model results were produced.",
                "?",
            )

        _sa_classifier_update_save_button(dashboard)
        return

    dashboard.sa_classifier_per_input_results = []
    candidates = []

    library_labels = list(
        getattr(
            dashboard,
            "sa_classifier_library_evidence_used",
            [],
        )
        or _sa_classifier_library_evidence_labels(dashboard)
    )
    library_basis = " + ".join(library_labels) or "Library match"
    library_support = (
        f"{len(library_labels)} / {len(library_labels)}"
        if library_labels
        else "—"
    )

    for row in getattr(
        dashboard,
        "sa_classifier_library_results",
        [],
    ) or []:
        if not isinstance(row, dict):
            continue

        label = str(
            row.get("protocol_name")
            or row.get("label")
            or ""
        ).strip()

        if not label:
            continue

        candidates.append(
            {
                "source": "Library",
                "label": label,
                "basis": library_basis,
                "agreement": library_support,
                "agreement_value": 1.0 if library_labels else None,
                "library_record": dict(row),
            }
        )

    model_report = getattr(
        dashboard,
        "sa_classifier_model_report",
        {},
    ) or {}
    model_candidates = _sa_classifier_model_candidates(
        model_report
    )
    candidates.extend(model_candidates)
    dashboard.sa_classifier_candidates = candidates

    table.setRowCount(0)
    table.setColumnCount(4)
    table.setHorizontalHeaderLabels(
        [
            "Source",
            "Candidate",
            "Support",
            "Evidence",
        ]
    )

    for row_index, candidate in enumerate(candidates):
        table.insertRow(row_index)

        for column, key in enumerate(
            (
                "source",
                "label",
                "agreement",
                "basis",
            )
        ):
            text = str(candidate.get(key, "") or "—")
            item = QtWidgets.QTableWidgetItem(text)
            item.setFlags(
                item.flags()
                & ~QtCore.Qt.ItemIsEditable
            )

            if column == 3:
                item.setToolTip(text)

            table.setItem(
                row_index,
                column,
                item,
            )

    _sa_classifier_configure_results_table(
        dashboard,
        "Combine Results",
    )

    library_top = next(
        (
            row
            for row in candidates
            if row.get("source") == "Library"
        ),
        None,
    )
    model_top = next(
        (
            row
            for row in candidates
            if row.get("source") == "Model"
        ),
        None,
    )

    if library_top and model_top:
        if _sa_classifier_labels_correlate(
            library_top["label"],
            model_top["label"],
        ):
            _sa_classifier_set_assessment(
                dashboard,
                "Corroborated",
                "Library and model results are consistent.",
                "✓",
            )
        else:
            _sa_classifier_set_assessment(
                dashboard,
                "Conflicting",
                (
                    "Library and model results suggest different "
                    "classifications."
                ),
                "!",
            )
    elif library_top or model_top:
        _sa_classifier_set_assessment(
            dashboard,
            "Single Source",
            "Only one classification method produced candidates.",
            "i",
        )
    else:
        _sa_classifier_set_assessment(
            dashboard,
            "Inconclusive",
            "No usable classification candidates were produced.",
            "?",
        )

    primary_combo.blockSignals(True)
    primary_combo.clear()

    seen = set()

    for candidate in candidates:
        label = str(candidate.get("label") or "").strip()

        if label and label not in seen:
            primary_combo.addItem(label)
            seen.add(label)

    if model_top:
        preferred = str(model_top.get("label") or "")
    elif library_top:
        preferred = str(library_top.get("label") or "")
    else:
        preferred = ""

    primary_combo.setEditText(preferred)
    primary_combo.blockSignals(False)

    _sa_classifier_update_save_button(dashboard)


def _sa_classifier_update_save_button(dashboard: QtCore.QObject):
    button = dashboard.ui.pushButton_sa_classifier_classify_results_save_soi
    mode = _sa_classifier_resolved_input_mode(dashboard)

    if mode == "Per Input":
        button.setText("Create SOIs")

        selected = _sa_classifier_selected_per_input_results(
            dashboard
        )
        valid_selected = [
            row
            for row in selected
            if str(row.get("label") or "").strip() not in {"", "—"}
        ]

        button.setEnabled(
            bool(
                getattr(
                    dashboard,
                    "sa_classifier_per_input_results",
                    [],
                )
                and valid_selected
            )
        )
        return

    existing = bool(_sa_classifier_soi_context(dashboard))
    button.setText(
        "Save to SOI"
        if existing
        else "Create SOI"
    )
    button.setEnabled(
        bool(
            str(
                dashboard.ui.comboBox_sa_classifier_classify_results_primary.currentText()
                or ""
            ).strip()
            and getattr(
                dashboard,
                "sa_classifier_candidates",
                [],
            )
        )
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_ClassifierInputModeChanged(dashboard: QtCore.QObject):
    _sa_classifier_update_input_summary(dashboard)

    if (
        getattr(dashboard, "sa_classifier_model_report", {})
        or getattr(dashboard, "sa_classifier_library_results", [])
    ):
        _sa_classifier_render_results(dashboard)
    else:
        _sa_classifier_update_results_mode_state(dashboard)
        _sa_classifier_update_save_button(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_ClassifierResultsSelectionChanged(
    dashboard: QtCore.QObject,
):
    _sa_classifier_update_save_button(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_ClassifierInputSourceChanged(dashboard: QtCore.QObject):
    dashboard.sa_classifier_compatible_models = ""
    _sa_classifier_update_source_page(dashboard)
    _sa_classifier_update_model_info(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_ClassifierInputSoiChanged(dashboard: QtCore.QObject):
    if _sa_classifier_source(dashboard) == "Artifact":
        refresh_sa_classifier_input_artifacts(dashboard)

    dashboard.sa_classifier_compatible_models = ""
    _sa_classifier_update_input_summary(dashboard)
    _sa_classifier_update_model_info(dashboard)
    _sa_classifier_update_save_button(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_ClassifierInputArtifactChanged(dashboard: QtCore.QObject):
    dashboard.sa_classifier_compatible_models = ""
    _sa_classifier_update_input_summary(dashboard)
    _sa_classifier_update_model_info(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_ClassifierInputArtifactRefreshClicked(dashboard: QtCore.QObject):
    uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not uid:
        refresh_sa_classifier_input_artifacts(dashboard)
        return
    button = dashboard.ui.pushButton_sa_classifier_classify_input_artifact_refresh
    button.setEnabled(False)
    try:
        await dashboard.backend.tacticalNodeArtifactsRefresh(uid)
    finally:
        button.setEnabled(True)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_ClassifierInputFileClicked(dashboard: QtCore.QObject):
    path = await Qt5.async_open_file_dialog(
        dashboard,
        os.path.expanduser("~"),
        "Feature Results (tsi_features.json);;JSON Files (*.json);;All Files (*)",
    )
    if path:
        dashboard.ui.textEdit_sa_classifier_classify_file.setPlainText(path)
        _sa_classifier_update_input_summary(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_ClassifierInputFileChanged(dashboard: QtCore.QObject):
    dashboard.sa_classifier_compatible_models = ""
    _sa_classifier_update_input_summary(dashboard)
    _sa_classifier_update_model_info(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_ClassifierViewInputsClicked(dashboard: QtCore.QObject):
    payload = {
        "soi": _sa_classifier_soi_context(dashboard),
        "source": _sa_classifier_source(dashboard),
        "artifact": _sa_classifier_artifact_context(dashboard),
        "local_file": str(dashboard.ui.textEdit_sa_classifier_classify_file.toPlainText() or "").strip(),
        "evidence": _sa_classifier_evidence(dashboard),
    }
    await Qt5.async_ok_dialog(dashboard, json.dumps(payload, indent=2, default=str), width=800, height=600)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_ClassifierLibraryChanged(dashboard: QtCore.QObject):
    _sa_classifier_update_library_info(dashboard)
    _sa_classifier_update_run_state(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_ClassifierModelEnableChanged(dashboard: QtCore.QObject):
    _sa_classifier_update_model_controls(dashboard)
    _sa_classifier_update_model_info(dashboard)
    _sa_classifier_update_run_state(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_ClassifierModelQueryClicked(dashboard: QtCore.QObject):
    uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not uid or not _sa_classifier_selected_node_available(dashboard):
        return
    dashboard.sa_classifier_action_query_pending = True
    dashboard.ui.pushButton_sa_classifier_classify_model_query.setEnabled(False)
    dashboard.ui.pushButton_sa_classifier_classify_model_query.setText("Querying...")
    await dashboard.backend.queryPluginActions(
        uid=uid,
        context=ACTION_QUERY_CONTEXT,
        scope="all_plugins",
        plugin_name="",
        include_tags=["tsi.classifier", "tsi.classifier.method.model"],
        exclude_tags=[],
        hardware="",
    )


def handle_sa_classifier_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if context != ACTION_QUERY_CONTEXT or str(node_uid or "").strip() != selected_uid:
        return
    dashboard.sa_classifier_action_query_pending = False
    dashboard.sa_classifier_action_catalog = actions if isinstance(actions, list) else []
    plugins = sorted({
        str(row.get("plugin") or "").strip()
        for row in dashboard.sa_classifier_action_catalog
        if isinstance(row, dict) and str(row.get("plugin") or "").strip()
    })
    combo = dashboard.ui.comboBox_sa_classifier_classify_model_plugin
    combo.blockSignals(True)
    combo.clear()
    combo.addItems(plugins)
    combo.blockSignals(False)
    dashboard.ui.pushButton_sa_classifier_classify_model_query.setText("Query Actions")
    if plugins:
        combo.setCurrentIndex(0)
        _sa_classifier_populate_actions_for_plugin(dashboard)
    else:
        dashboard.ui.comboBox_sa_classifier_classify_model_action.clear()
    _sa_classifier_update_model_controls(dashboard)
    _sa_classifier_update_model_info(dashboard)
    _sa_classifier_update_run_state(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_ClassifierModelPluginChanged(dashboard: QtCore.QObject):
    _sa_classifier_populate_actions_for_plugin(dashboard)


def _slotSA_ClassifierModelActionChanged(dashboard: QtCore.QObject):
    record = dashboard.ui.comboBox_sa_classifier_classify_model_action.currentData()

    if isinstance(record, dict):
        dashboard.sa_classifier_selected_plugin = str(
            record.get("plugin") or ""
        ).strip()
        dashboard.sa_classifier_selected_action = str(
            record.get("action") or ""
        ).strip()
    else:
        dashboard.sa_classifier_selected_plugin = ""
        dashboard.sa_classifier_selected_action = ""

    dashboard.sa_classifier_model_parameters = (
        _sa_classifier_current_parameter_overrides(dashboard)
    )
    dashboard.sa_classifier_compatible_models = ""
    dashboard.sa_classifier_models_selected = "All Compatible"

    _sa_classifier_update_model_controls(dashboard)
    _sa_classifier_update_model_info(dashboard)
    _sa_classifier_update_run_state(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_ClassifierModelCustomizeClicked(
    dashboard: QtCore.QObject,
):
    uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()
    record = dashboard.ui.comboBox_sa_classifier_classify_model_action.currentData()

    if not uid or not isinstance(record, dict):
        return

    plugin_name = str(record.get("plugin") or "").strip()
    action_name = str(record.get("action") or "").strip()
    dashboard.sa_classifier_schema_request_key = _sa_classifier_action_key(
        plugin_name,
        action_name,
    )

    button = dashboard.ui.pushButton_sa_classifier_classify_model_customize
    button.setEnabled(False)
    button.setText("Loading...")

    await dashboard.backend.queryPluginActionSchema(
        uid=uid,
        plugin_name=plugin_name,
        action_name=action_name,
        context=ACTION_SCHEMA_CONTEXT,
    )


def _sa_classifier_parameter_widget(parent, parameter: dict, current_value=None, use_current_value: bool = False):
    ptype = str(parameter.get("type") or "string").lower()
    value = current_value if use_current_value else parameter.get("default")
    options = parameter.get("options")

    if isinstance(options, list) and options:
        widget = QtWidgets.QComboBox(parent)
        widget.addItems([str(option) for option in options])
        index = widget.findText(str(value))
        if index >= 0:
            widget.setCurrentIndex(index)
        return widget

    if ptype in {"int", "integer"}:
        widget = QtWidgets.QSpinBox(parent)
        widget.setRange(
            int(parameter.get("min", -1000000000)),
            int(parameter.get("max", 1000000000)),
        )
        widget.setValue(int(value or 0))
        return widget

    if ptype in {"number", "float", "double"}:
        widget = QtWidgets.QDoubleSpinBox(parent)
        widget.setRange(
            float(parameter.get("min", -1e12)),
            float(parameter.get("max", 1e12)),
        )
        widget.setDecimals(int(parameter.get("decimals", 6)))
        widget.setValue(float(value or 0))
        return widget

    if ptype in {"bool", "boolean"}:
        widget = QtWidgets.QCheckBox(parent)
        if isinstance(value, str):
            checked = value.strip().lower() in {"true", "1", "yes", "y", "on", "enabled"}
        else:
            checked = bool(value)
        widget.setChecked(checked)
        return widget

    widget = QtWidgets.QLineEdit(parent)
    widget.setText("" if value is None else str(value))
    return widget


def _sa_classifier_parameter_value(widget):
    if isinstance(widget, QtWidgets.QComboBox):
        return widget.currentText()
    if isinstance(widget, QtWidgets.QSpinBox):
        return widget.value()
    if isinstance(widget, QtWidgets.QDoubleSpinBox):
        return widget.value()
    if isinstance(widget, QtWidgets.QCheckBox):
        return widget.isChecked()
    if isinstance(widget, QtWidgets.QLineEdit):
        return widget.text()
    return None


def handle_sa_classifier_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
    schema: dict = None,
):
    customize_button = dashboard.ui.pushButton_sa_classifier_classify_model_customize
    customize_button.setText("Customize")
    _sa_classifier_update_model_controls(dashboard)

    selected_uid = str(
        getattr(dashboard, "selected_node_uid", "")
        or ""
    ).strip()
    if str(node_uid or "").strip() != selected_uid:
        return

    expected_key = str(
        getattr(dashboard, "sa_classifier_schema_request_key", "")
        or ""
    ).strip()
    response_key = _sa_classifier_action_key(
        plugin_name,
        action_name,
    )

    if not response_key or response_key != expected_key:
        return
    if response_key != _sa_classifier_current_action_key(dashboard):
        return

    schema_payload = dict(schema) if isinstance(schema, dict) else {}
    if not schema_payload:
        schema_payload = {
            "params": parameters or [],
        }

    parameters = (
        schema_payload.get("params", [])
        if isinstance(schema_payload.get("params"), list)
        else parameters or []
    )

    hidden_parameters = {
        "description",
        "destination",
        "managed_input",
        "input_soi_id",
        "input_soi_key",
        "input_soi_frequency_mhz",
        "operation_id",
        "source_id",
    }
    normal_parameters = []
    model_parameters = []

    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue

        name = str(parameter.get("name") or "").strip()
        if not name or name in hidden_parameters:
            continue

        if str(parameter.get("group") or "").strip().lower() == "models":
            model_parameters.append(parameter)
        else:
            normal_parameters.append(parameter)

    dialog = QtWidgets.QDialog(dashboard)
    dialog.setWindowTitle(
        f"Customize {plugin_name}: {action_name}"
    )
    dialog.setAttribute(
        QtCore.Qt.WA_DeleteOnClose,
        True,
    )

    layout = QtWidgets.QVBoxLayout(dialog)
    widgets = {}
    overrides = _sa_classifier_current_parameter_overrides(dashboard)

    if normal_parameters:
        parameter_group = QtWidgets.QGroupBox(
            "Parameters",
            dialog,
        )
        parameter_form = QtWidgets.QFormLayout(parameter_group)

        for parameter in normal_parameters:
            name = str(parameter.get("name") or "").strip()
            widget = _sa_classifier_parameter_widget(
                dialog,
                parameter,
                current_value=overrides.get(name),
                use_current_value=name in overrides,
            )
            widgets[name] = widget
            parameter_form.addRow(
                f"{str(parameter.get('label') or name)}:",
                widget,
            )

        layout.addWidget(parameter_group)

    compatible_count = 0
    compatibility_known = False
    model_widgets = {}

    if model_parameters:
        model_group = QtWidgets.QGroupBox(
            "Models",
            dialog,
        )
        model_layout = QtWidgets.QGridLayout(model_group)
        model_layout.setColumnStretch(0, 1)

        input_features = _sa_classifier_input_feature_names(dashboard)
        compatibility_known = bool(input_features)

        for row_index, parameter in enumerate(model_parameters):
            name = str(parameter.get("name") or "").strip()
            label = str(parameter.get("label") or name).strip()
            widget = _sa_classifier_parameter_widget(
                dialog,
                parameter,
                current_value=overrides.get(name),
                use_current_value=name in overrides,
            )

            if not isinstance(widget, QtWidgets.QCheckBox):
                continue

            widget.setText(label)
            widgets[name] = widget
            model_widgets[name] = widget

            required_features = {
                str(feature)
                for feature in parameter.get("required_features", []) or []
                if str(feature or "").strip()
            }
            missing = sorted(
                required_features - input_features,
                key=str.lower,
            )

            if input_features and missing:
                widget.setChecked(False)
                widget.setEnabled(False)
                compatibility = f"Missing {len(missing)} feature(s)"
                tooltip = "Missing required features: " + ", ".join(missing)
                widget.setToolTip(tooltip)
            elif input_features:
                compatible_count += 1
                compatibility = "Compatible"
                if required_features:
                    widget.setToolTip(
                        "Required features: "
                        + ", ".join(sorted(required_features, key=str.lower))
                    )
            else:
                compatibility = "Compatibility unknown"
                if required_features:
                    widget.setToolTip(
                        "Required features: "
                        + ", ".join(sorted(required_features, key=str.lower))
                    )

            status_label = QtWidgets.QLabel(
                compatibility,
                model_group,
            )
            status_label.setToolTip(widget.toolTip())

            model_layout.addWidget(
                widget,
                row_index,
                0,
            )
            model_layout.addWidget(
                status_label,
                row_index,
                1,
            )

        layout.addWidget(model_group)

    if not widgets:
        layout.addWidget(
            QtWidgets.QLabel(
                "No user-adjustable parameters are exposed by this classifier action.",
                dialog,
            )
        )

    if model_widgets:
        dashboard.sa_classifier_compatible_models = (
            compatible_count
            if compatibility_known
            else "—"
        )
        dashboard.sa_classifier_models_selected = sum(
            1
            for widget in model_widgets.values()
            if widget.isChecked() and widget.isEnabled()
        )
        _sa_classifier_update_model_info(dashboard)

    status = QtWidgets.QLabel("", dialog)
    status.setWordWrap(True)
    layout.addWidget(status)

    buttons = QtWidgets.QDialogButtonBox(
        QtWidgets.QDialogButtonBox.Apply
        | QtWidgets.QDialogButtonBox.Close,
        dialog,
    )
    layout.addWidget(buttons)

    apply_button = buttons.button(
        QtWidgets.QDialogButtonBox.Apply
    )
    apply_button.setEnabled(bool(widgets))

    def apply_values():
        values = {
            name: _sa_classifier_parameter_value(widget)
            for name, widget in widgets.items()
        }
        store = getattr(
            dashboard,
            "sa_classifier_model_parameter_overrides",
            None,
        )
        if not isinstance(store, dict):
            store = {}
            dashboard.sa_classifier_model_parameter_overrides = store

        store[response_key] = dict(values)
        dashboard.sa_classifier_model_parameters = dict(values)

        if model_widgets:
            dashboard.sa_classifier_models_selected = sum(
                1
                for widget in model_widgets.values()
                if widget.isChecked() and widget.isEnabled()
            )

        status.setText(
            "Applied. These values will be used for the next classification run."
        )
        _sa_classifier_update_model_info(dashboard)
        dialog.close()

    apply_button.clicked.connect(apply_values)
    buttons.rejected.connect(dialog.close)
    buttons.accepted.connect(dialog.close)

    dashboard._sa_classifier_customize_dialog = dialog
    row_count = len(normal_parameters) + len(model_parameters)
    dialog.resize(
        560,
        max(260, 160 + 38 * row_count),
    )
    dialog.show()


def _sa_classifier_model_parameters(dashboard: QtCore.QObject, operation_id: str) -> dict:
    source = _sa_classifier_source(dashboard)
    params = _sa_classifier_current_parameter_overrides(dashboard)

    params.update({
        "operation_id": operation_id,
        "destination": str(
            dashboard.ui.comboBox_sa_classifier_classify_run_destination.currentText() or "Artifact"
        ).strip(),
        "description": "Classification analysis results",
        "source_id": str(getattr(dashboard, "selected_node_uid", "") or "").strip(),
        "input_soi_id": str(_sa_classifier_soi_context(dashboard).get("soi_id", "") or ""),
        "input_soi_key": str(_sa_classifier_soi_context(dashboard).get("soi_key", "") or ""),
        "input_soi_frequency_mhz": _sa_classifier_evidence(dashboard).get("frequency_mhz"),
        "library_candidates": list(getattr(dashboard, "sa_classifier_library_results", []) or []),
    })

    if source == "Artifact":
        context = _sa_classifier_artifact_context(dashboard)
        artifact_id = str(context.get("artifact_id") or "").strip()
        record = context.get("record", {}) if isinstance(context.get("record"), dict) else {}
        file_record = _sa_classifier_feature_file_record(record)

        artifact_request = {"artifact_id": artifact_id}
        if file_record:
            artifact_request["selected_files"] = [{
                "file_id": str(file_record.get("id") or "").strip(),
                "name": str(file_record.get("name") or file_record.get("relative_path") or "").strip(),
                "role": str(file_record.get("role") or "").strip(),
            }]

        params.update({
            "input_source": "Artifact",
            "source_artifact_id": artifact_id,
            "source_artifact_ids": [artifact_id] if artifact_id else [],
            "managed_input": {
                "source": "Artifact",
                "artifact_ids": [artifact_id] if artifact_id else [],
                "artifacts": [artifact_request] if artifact_id else [],
            },
        })

    elif source == "Local File":
        params.update({
            "input_source": "Local File",
            "features_path": str(
                dashboard.ui.textEdit_sa_classifier_classify_file.toPlainText() or ""
            ).strip(),
            "source_artifact_id": "",
            "source_artifact_ids": [],
        })

    return params


async def _sa_classifier_start_model(dashboard: QtCore.QObject):
    if (not bool(getattr(dashboard, "sa_classifier_running", False))
            or bool(getattr(dashboard, "sa_classifier_stop_requested", False))):
        return
    if not dashboard.ui.checkBox_sa_classifier_classify_model_enable.isChecked():
        dashboard.sa_classifier_model_pending = False
        _sa_classifier_finish_if_complete(dashboard)
        return
    ready, reason = _sa_classifier_model_input_ready(dashboard)
    record = dashboard.ui.comboBox_sa_classifier_classify_model_action.currentData()
    if not ready or not isinstance(record, dict):
        dashboard.sa_classifier_model_pending = False
        dashboard.ui.label2_sa_classifier_classify_run_status.setText(reason or "Model classification unavailable")
        _sa_classifier_finish_if_complete(dashboard)
        return
    uid = str(getattr(dashboard, "sa_classifier_model_node_uid", "") or "").strip()
    operation_id = str(getattr(dashboard, "sa_classifier_operation_id", "") or "").strip()
    if not uid or not operation_id:
        dashboard.sa_classifier_model_pending = False
        _sa_classifier_set_running(dashboard, False, "Model Node Unavailable")
        return
    params = _sa_classifier_model_parameters(dashboard, operation_id)
    dashboard.sa_classifier_model_pending = True
    dashboard.sa_classifier_model_launched = True
    dashboard.sa_classifier_model_operation_complete = False
    try:
        await dashboard.backend.tacticalNodeExecute(
            [uid],
            str(record.get("plugin") or ""),
            str(record.get("action") or ""),
            params,
        )
        destination = str(
            dashboard.ui.comboBox_sa_classifier_classify_run_destination.currentText() or ""
        ).strip()
        if (not bool(getattr(dashboard, "sa_classifier_stop_requested", False))
                and bool(getattr(dashboard, "sa_classifier_running", False))
                and str(getattr(dashboard, "sa_classifier_operation_id", "") or "") == operation_id
                and bool(getattr(dashboard, "sa_classifier_run_local_results", False))):
            _sa_classifier_start_local_result_timer(dashboard)
    except Exception as error:
        dashboard.logger.error(f"[Classifier] Model start failed: {error!r}")
        if str(getattr(dashboard, "sa_classifier_operation_id", "") or "") == operation_id:
            dashboard.sa_classifier_model_pending = False
            dashboard.sa_classifier_model_operation_complete = True
            _sa_classifier_set_running(dashboard, False, "Model Start Failed")


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_ClassifierRunStartStopClicked(
    dashboard: QtCore.QObject,
):
    if bool(getattr(dashboard, "sa_classifier_running", False)):
        if bool(getattr(dashboard, "sa_classifier_stop_requested", False)):
            return
        operation_id = str(getattr(dashboard, "sa_classifier_operation_id", "") or "").strip()
        uid = str(getattr(dashboard, "sa_classifier_model_node_uid", "") or "").strip()
        dashboard.sa_classifier_stop_requested = True
        dashboard.sa_classifier_library_pending = False
        timer = getattr(dashboard, "sa_classifier_result_timer", None)
        if timer is not None:
            timer.stop()

        if bool(getattr(dashboard, "sa_classifier_model_launched", False)) and not bool(
            getattr(dashboard, "sa_classifier_model_operation_complete", False)
        ) and operation_id and uid:
            dashboard.ui.label2_sa_classifier_classify_run_status.setText("Stopping...")
            dashboard.ui.pushButton_sa_classifier_classify_run_start_stop.setEnabled(False)
            try:
                await dashboard.backend.stopPluginOperation(uid, operation_id)
            except Exception as error:
                dashboard.logger.error("[Classifier] Stop failed: %r", error)
                if (bool(getattr(dashboard, "sa_classifier_running", False))
                        and str(getattr(dashboard, "sa_classifier_operation_id", "") or "") == operation_id):
                    dashboard.sa_classifier_stop_requested = False
                    dashboard.ui.label2_sa_classifier_classify_run_status.setText("Stop Failed — Retry")
                    dashboard.ui.pushButton_sa_classifier_classify_run_start_stop.setEnabled(True)
            # Do not reset until a terminal lifecycle event arrives.
            return

        # Library-only run or remote model already completed; cancel locally.
        dashboard.sa_classifier_model_pending = False
        _sa_classifier_set_running(dashboard, False, "Stopped")
        return

    library_selected = (
        dashboard.ui.checkBox_sa_classifier_classify_library_enable.isChecked()
    )
    library_ready = (
        _sa_classifier_library_ready(dashboard)
        if library_selected
        else False
    )

    model_selected = (
        dashboard.ui.checkBox_sa_classifier_classify_model_enable.isChecked()
    )
    model_input_ready, _model_reason = _sa_classifier_model_input_ready(
        dashboard
    )
    model_selection_ready = _sa_classifier_model_selection_ready(
        dashboard
    )

    action_record = (
        dashboard.ui.comboBox_sa_classifier_classify_model_action.currentData()
    )
    action_ready = (
        isinstance(action_record, dict)
        and bool(str(action_record.get("plugin") or "").strip())
        and bool(str(action_record.get("action") or "").strip())
    )

    model_ready = (
        model_selected
        and model_input_ready
        and action_ready
        and model_selection_ready
    )

    any_selected = library_selected or model_selected
    all_selected_methods_ready = (
        any_selected
        and (not library_selected or library_ready)
        and (not model_selected or model_ready)
    )

    if not all_selected_methods_ready:
        _sa_classifier_update_run_state(dashboard)
        return

    run_library = library_selected and library_ready
    run_model = model_selected and model_ready

    dashboard.sa_classifier_library_evidence_used = (
        _sa_classifier_library_evidence_labels(dashboard)
        if run_library
        else []
    )

    _sa_classifier_clear_results(dashboard)

    run_id = str(uuid.uuid4())
    dashboard.sa_classifier_run_id = run_id
    dashboard.sa_classifier_operation_id = run_id
    dashboard.sa_classifier_artifact_id = ""
    dashboard.sa_classifier_model_node_uid = (
        str(getattr(dashboard, "selected_node_uid", "") or "").strip()
        if run_model else ""
    )
    dashboard.sa_classifier_run_local_results = bool(
        run_model
        and dashboard.ui.comboBox_sa_classifier_classify_run_destination.currentText() == "Local Results"
        and selected_node_is_local(dashboard)
    )
    dashboard.sa_classifier_model_launched = False
    dashboard.sa_classifier_model_operation_complete = False
    dashboard.sa_classifier_stop_requested = False

    dashboard.ui.label2_sa_classifier_classify_run_operation_id.setText(
        run_id
    )
    dashboard.ui.label2_sa_classifier_classify_run_artifact_id.setText(
        "—"
    )
    dashboard.ui.progressBar_sa_classifier_classify_run_progress.setValue(
        0
    )

    _sa_classifier_update_artifact_button(dashboard)

    dashboard.sa_classifier_library_pending = bool(run_library)
    dashboard.sa_classifier_model_pending = False

    _sa_classifier_set_running(
        dashboard,
        True,
        "Running",
    )

    if run_library:
        evidence = _sa_classifier_evidence(dashboard)
        max_results = (
            dashboard.ui.spinBox_sa_classifier_classify_library_max_results.value()
            if dashboard.ui.checkBox_sa_classifier_classify_library_multiple_candidates.isChecked()
            else 1
        )

        await dashboard.backend.classifierLibraryMatch(
            request_id=run_id,
            frequency_mhz=evidence.get("frequency_mhz"),
            max_results=max_results,
        )
    elif run_model:
        await _sa_classifier_start_model(dashboard)


def handle_sa_classifier_library_match_results(
    dashboard: QtCore.QObject,
    request_id: str = "",
    frequency_mhz=None,
    matches: list = None,
    error: str = "",
):
    if str(request_id or "").strip() != str(getattr(dashboard, "sa_classifier_run_id", "") or "").strip():
        return
    if (not bool(getattr(dashboard, "sa_classifier_running", False))
            or bool(getattr(dashboard, "sa_classifier_stop_requested", False))):
        return
    dashboard.sa_classifier_library_pending = False
    dashboard.sa_classifier_library_results = matches if isinstance(matches, list) else []
    if error:
        dashboard.logger.warning(f"[Classifier] Library Match: {error}")
    if dashboard.ui.checkBox_sa_classifier_classify_model_enable.isChecked():
        asyncio.ensure_future(_sa_classifier_start_model(dashboard))
    else:
        _sa_classifier_finish_if_complete(dashboard)


def handle_sa_classifier_operation_state(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    operation_id: str = "",
    state: str = "",
    error: str = "",
):
    """Handle model plugin lifecycle independently of local Library Match."""
    if not bool(getattr(dashboard, "sa_classifier_running", False)):
        return
    if not bool(getattr(dashboard, "sa_classifier_model_launched", False)):
        return
    if str(getattr(dashboard, "sa_classifier_model_node_uid", "") or "").strip() != str(node_uid or "").strip():
        return
    if str(getattr(dashboard, "sa_classifier_operation_id", "") or "").strip() != str(operation_id or "").strip():
        return
    state = str(state or "").strip()
    if state in {"Starting", "Running"}:
        if not bool(getattr(dashboard, "sa_classifier_stop_requested", False)):
            dashboard.ui.label2_sa_classifier_classify_run_status.setText(state)
            dashboard.ui.pushButton_sa_classifier_classify_run_start_stop.setEnabled(True)
        return
    if state not in {"Completed", "Stopped", "Failed"}:
        return

    dashboard.sa_classifier_model_operation_complete = True
    if state in {"Stopped", "Failed"}:
        timer = getattr(dashboard, "sa_classifier_result_timer", None)
        if timer is not None:
            timer.stop()
        dashboard.sa_classifier_library_pending = False
        dashboard.sa_classifier_model_pending = False
        if state == "Failed" and error:
            dashboard.logger.warning("[Classifier] Model failed: %s", error)
        _sa_classifier_set_running(dashboard, False, "Model Failed" if state == "Failed" else "Stopped")
        return

    if bool(getattr(dashboard, "sa_classifier_stop_requested", False)):
        dashboard.sa_classifier_model_pending = False
        _sa_classifier_set_running(dashboard, False, "Completed Before Stop")
    elif bool(getattr(dashboard, "sa_classifier_model_pending", False)):
        dashboard.ui.label2_sa_classifier_classify_run_status.setText("Awaiting Model Results...")
    else:
        _sa_classifier_finish_if_complete(dashboard)


def update_sa_classifier_status_from_selected_node(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    status: str = "",
):
    """Aggregate node Error is not evidence that this Classifier Action failed."""
    return


def _sa_classifier_local_result_path(dashboard: QtCore.QObject) -> str:
    opid = str(getattr(dashboard, "sa_classifier_operation_id", "") or "").strip()
    return os.path.join(fissure.utils.ARTIFACT_NODE_DIR, opid, "files", "classification_report.json") if opid else ""


def _sa_classifier_start_local_result_timer(dashboard: QtCore.QObject):
    timer = getattr(dashboard, "sa_classifier_result_timer", None)
    if timer is None:
        timer = QtCore.QTimer(dashboard)
        timer.setInterval(250)
        timer.timeout.connect(lambda: _sa_classifier_poll_local_result(dashboard))
        dashboard.sa_classifier_result_timer = timer
    timer.start()


def _sa_classifier_poll_local_result(dashboard: QtCore.QObject):
    path = _sa_classifier_local_result_path(dashboard)
    if not path or not os.path.isfile(path):
        return

    timer = getattr(dashboard, "sa_classifier_result_timer", None)
    if timer is not None:
        timer.stop()

    try:
        with open(path, "r", encoding="utf-8") as handle:
            dashboard.sa_classifier_model_report = json.load(handle)

        report = dashboard.sa_classifier_model_report
        dashboard.sa_classifier_compatible_models = report.get(
            "models_eligible_any",
            "",
        )
        dashboard.sa_classifier_models_selected = report.get(
            "models_selected_count",
            report.get("models_eligible_any", "All Compatible"),
        )
    except Exception as error:
        dashboard.logger.error(
            f"[Classifier] Failed reading Local Results: {error!r}"
        )
        dashboard.sa_classifier_model_report = {}

    dashboard.sa_classifier_model_pending = False
    _sa_classifier_update_model_info(dashboard)
    _sa_classifier_finish_if_complete(dashboard)


def handle_sa_classifier_artifact_metadata(dashboard: QtCore.QObject, node_uid: str = "", artifacts=None):
    if _sa_classifier_source(dashboard) == "Artifact":
        refresh_sa_classifier_input_artifacts(dashboard)
    if not bool(getattr(dashboard, "sa_classifier_model_pending", False)):
        return
    expected = str(getattr(dashboard, "sa_classifier_operation_id", "") or "").strip()
    for artifact in artifacts or []:
        if not isinstance(artifact, dict):
            continue
        metadata = artifact.get("metadata", {}) if isinstance(artifact.get("metadata"), dict) else {}
        if str(metadata.get("workflow") or "").strip().lower() != "classifier":
            continue
        opid = str(artifact.get("operation_id") or metadata.get("operation_id") or "").strip()
        if opid != expected:
            continue
        artifact_id = str(artifact.get("artifact_id") or artifact.get("id") or "").strip()
        if not artifact_id:
            continue
        dashboard.sa_classifier_artifact_id = artifact_id
        dashboard.sa_classifier_auto_download_artifact_id = artifact_id
        dashboard.ui.label2_sa_classifier_classify_run_artifact_id.setText(artifact_id)
        dashboard.ui.label2_sa_classifier_classify_run_status.setText("Downloading Results...")
        _sa_classifier_update_artifact_button(dashboard)
        if _sa_classifier_load_cached_artifact(dashboard, artifact_id):
            dashboard.sa_classifier_auto_download_artifact_id = ""
            return
        async def request_download():
            try:
                await dashboard.backend.requestDashboardArtifactDownload(artifact_id, open_when_complete=False)
            except Exception as error:
                dashboard.logger.error(f"[Classifier] Automatic Artifact download failed: {error!r}")
        asyncio.ensure_future(request_download())
        return


def _sa_classifier_cached_report_path(dashboard: QtCore.QObject, artifact_id: str) -> str:
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    if controller is None:
        return ""
    files = controller.get_local_files(artifact_id) or {}
    for path in files.values():
        if os.path.basename(str(path)) == "classification_report.json":
            return str(path)
    local_path = controller.get_local_path(artifact_id)
    if local_path and os.path.isdir(local_path):
        candidate = os.path.join(local_path, "classification_report.json")
        if os.path.isfile(candidate):
            return candidate
    return ""


def _sa_classifier_load_cached_artifact(
    dashboard: QtCore.QObject,
    artifact_id: str,
) -> bool:
    path = _sa_classifier_cached_report_path(
        dashboard,
        artifact_id,
    )
    if not path or not os.path.isfile(path):
        return False

    try:
        with open(path, "r", encoding="utf-8") as handle:
            dashboard.sa_classifier_model_report = json.load(handle)

        report = dashboard.sa_classifier_model_report
        if isinstance(report.get("library_candidates"), list):
            dashboard.sa_classifier_library_results = report.get(
                "library_candidates",
                [],
            )

        dashboard.sa_classifier_compatible_models = report.get(
            "models_eligible_any",
            "",
        )
        dashboard.sa_classifier_models_selected = report.get(
            "models_selected_count",
            report.get("models_eligible_any", "All Compatible"),
        )
        dashboard.sa_classifier_model_pending = False

        _sa_classifier_update_model_info(dashboard)
        _sa_classifier_update_artifact_button(dashboard)
        _sa_classifier_finish_if_complete(dashboard)
        return True
    except Exception as error:
        dashboard.logger.error(
            "[Classifier] Failed reading cached Classification Artifact: "
            f"{error!r}"
        )
        return False


def handle_sa_classifier_artifact_download_complete(dashboard: QtCore.QObject, artifact_id: str):
    expected = str(getattr(dashboard, "sa_classifier_auto_download_artifact_id", "") or "").strip()
    artifact_id = str(artifact_id or "").strip()
    if not expected or expected != artifact_id:
        return
    dashboard.sa_classifier_auto_download_artifact_id = ""
    if not _sa_classifier_load_cached_artifact(dashboard, artifact_id):
        dashboard.sa_classifier_model_pending = False
        dashboard.ui.label2_sa_classifier_classify_run_status.setText("Artifact Result Read Failed")
        _sa_classifier_finish_if_complete(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_ClassifierRunArtifactClicked(dashboard: QtCore.QObject):
    artifact_id = str(getattr(dashboard, "sa_classifier_artifact_id", "") or "").strip()
    if not artifact_id:
        return
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    if controller is None:
        return
    local_path = controller.get_local_path(artifact_id)
    if local_path:
        open_path = local_path if os.path.isdir(local_path) else os.path.dirname(local_path)
        try:
            subprocess.Popen(["xdg-open", open_path])
        except Exception as error:
            dashboard.logger.error(f"[Classifier] Failed opening Artifact: {error!r}")
        return
    button = dashboard.ui.pushButton_sa_classifier_classify_run_artifact
    button.setText("Downloading...")
    button.setEnabled(False)
    try:
        await dashboard.backend.requestDashboardArtifactDownload(artifact_id, open_when_complete=True)
    finally:
        _sa_classifier_update_artifact_button(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_ClassifierResultsDetailsClicked(
    dashboard: QtCore.QObject,
):
    mode = _sa_classifier_resolved_input_mode(dashboard)
    assessment = str(
        dashboard.ui.label2_sa_classifier_classify_results_assessment1.text()
        or "—"
    )
    primary = str(
        dashboard.ui.comboBox_sa_classifier_classify_results_primary.currentText()
        or ""
    ).strip()

    lines = [
        f"Mode: {mode}",
        f"Assessment: {assessment}",
    ]

    if mode == "Combine Results":
        lines.append(f"Primary Classification: {primary or '—'}")

    library_results = getattr(
        dashboard,
        "sa_classifier_library_results",
        [],
    ) or []

    if library_results:
        evidence_labels = list(
            getattr(
                dashboard,
                "sa_classifier_library_evidence_used",
                [],
            )
            or _sa_classifier_library_evidence_labels(dashboard)
        )
        evidence_text = " + ".join(evidence_labels) or "Library match"

        lines.extend(["", "Library Results"])

        for row in library_results:
            if not isinstance(row, dict):
                continue

            label = str(
                row.get("protocol_name")
                or row.get("label")
                or "—"
            )
            lines.append(f"  {label}")
            lines.append(f"    Evidence: {evidence_text}")

            freq_low = row.get("freq_low")
            freq_high = row.get("freq_high")
            if freq_low not in (None, "", "None") or freq_high not in (
                None,
                "",
                "None",
            ):
                try:
                    freq_low_text = (
                        _sa_classifier_format_number(
                            float(freq_low) / 1e6
                        )
                        if freq_low not in (None, "", "None")
                        else "—"
                    )
                except Exception:
                    freq_low_text = str(freq_low or "—")

                try:
                    freq_high_text = (
                        _sa_classifier_format_number(
                            float(freq_high) / 1e6
                        )
                        if freq_high not in (None, "", "None")
                        else "—"
                    )
                except Exception:
                    freq_high_text = str(freq_high or "—")

                lines.append(
                    "    Frequency Range: "
                    f"{freq_low_text} to {freq_high_text} MHz"
                )

            region = str(row.get("region") or "").strip()
            if region:
                lines.append(f"    Region: {region}")

            priority = row.get("priority")
            if priority not in (None, "", "None"):
                lines.append(f"    Priority: {priority}")

            notes = str(row.get("notes") or "").strip()
            if notes:
                lines.append(f"    Notes: {notes}")

    report = getattr(dashboard, "sa_classifier_model_report", {}) or {}
    per_file = report.get("per_file", []) if isinstance(report, dict) else []

    if per_file:
        lines.extend(["", "Model Results"])

        for row in per_file:
            if not isinstance(row, dict):
                continue

            file_name = str(row.get("file") or "Unnamed input")
            lines.append(f"  {file_name}")

            votes = row.get("votes", {})
            if isinstance(votes, dict) and votes:
                for model, prediction in sorted(
                    votes.items(),
                    key=lambda item: str(item[0]).lower(),
                ):
                    lines.append(f"    {model}: {prediction}")
            else:
                lines.append("    No model votes")

            consensus = (
                row.get("consensus", {})
                if isinstance(row.get("consensus"), dict)
                else {}
            )
            label = str(consensus.get("label") or "—")
            vote_counts = (
                row.get("vote_counts", {})
                if isinstance(row.get("vote_counts"), dict)
                else {}
            )

            try:
                models_used = int(row.get("models_used", 0) or 0)
            except Exception:
                models_used = 0

            try:
                winner_count = int(vote_counts.get(label, 0) or 0)
            except Exception:
                winner_count = 0

            support = (
                f"{winner_count} / {models_used} models"
                if models_used and winner_count
                else "—"
            )
            lines.append(f"    Consensus: {label} ({support})")

    await Qt5.async_ok_dialog(
        dashboard,
        "\n".join(lines),
        width=900,
        height=650,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_ClassifierResultsExportJsonClicked(
    dashboard: QtCore.QObject,
):
    has_combined = bool(
        getattr(
            dashboard,
            "sa_classifier_candidates",
            [],
        )
    )
    has_per_input = bool(
        getattr(
            dashboard,
            "sa_classifier_per_input_results",
            [],
        )
    )

    if not (has_combined or has_per_input):
        return

    path = await Qt5.async_save_file_dialog(
        dashboard,
        os.path.expanduser(
            "~/classification_results.json"
        ),
        ".json",
        "JSON Files (*.json)",
    )

    if not path:
        return

    resolved_mode = _sa_classifier_resolved_input_mode(
        dashboard
    )

    payload = {
        "input_mode": {
            "requested": _sa_classifier_requested_input_mode(
                dashboard
            ),
            "resolved": resolved_mode,
        },
        "primary_classification": (
            str(
                dashboard.ui.comboBox_sa_classifier_classify_results_primary.currentText()
                or ""
            ).strip()
            if resolved_mode == "Combine Results"
            else ""
        ),
        "assessment": (
            dashboard.ui.label2_sa_classifier_classify_results_assessment1.text()
        ),
        "candidates": getattr(
            dashboard,
            "sa_classifier_candidates",
            [],
        ),
        "per_input_results": getattr(
            dashboard,
            "sa_classifier_per_input_results",
            [],
        ),
        "library": getattr(
            dashboard,
            "sa_classifier_library_results",
            [],
        ),
        "model_report": getattr(
            dashboard,
            "sa_classifier_model_report",
            {},
        ),
    }

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as handle:
        json.dump(
            payload,
            handle,
            indent=2,
            default=str,
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_ClassifierPrimaryChanged(dashboard: QtCore.QObject):
    _sa_classifier_update_save_button(dashboard)


async def _sa_classifier_create_selected_input_sois(
    dashboard: QtCore.QObject,
) -> None:
    selected = _sa_classifier_selected_per_input_results(
        dashboard
    )

    if not selected:
        return

    count = len(selected)
    result = await Qt5.async_yes_no_dialog(
        dashboard,
        (
            f"Create {count} SOI"
            f"{'s' if count != 1 else ''} from the selected "
            "classifier results?"
        ),
    )

    if result != QtWidgets.QMessageBox.Yes:
        return

    button = dashboard.ui.pushButton_sa_classifier_classify_results_save_soi
    button.setEnabled(False)

    operation_id = str(
        getattr(
            dashboard,
            "sa_classifier_operation_id",
            "",
        )
        or ""
    ).strip()
    classification_artifact_id = str(
        getattr(
            dashboard,
            "sa_classifier_artifact_id",
            "",
        )
        or ""
    ).strip()

    feature_artifact_id = ""
    if _sa_classifier_source(dashboard) == "Artifact":
        feature_context = _sa_classifier_artifact_context(
            dashboard
        )
        feature_artifact_id = str(
            feature_context.get("artifact_id")
            or ""
        ).strip()

    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    created = 0

    try:
        for row in selected:
            file_name = str(
                row.get("input")
                or "Classifier Input"
            ).strip()
            primary = str(
                row.get("label")
                or ""
            ).strip()

            if not primary or primary == "—":
                continue

            candidates = []

            for candidate in row.get("candidates", []) or []:
                if not isinstance(candidate, dict):
                    continue

                entry = {
                    "source": "model",
                    "label": str(
                        candidate.get("label")
                        or ""
                    ),
                }

                if candidate.get("agreement") is not None:
                    entry["agreement"] = candidate.get(
                        "agreement"
                    )

                candidates.append(entry)

            agreement_value = row.get("agreement_value")
            model_confidence = None

            if agreement_value is not None:
                try:
                    model_confidence = round(
                        float(agreement_value) * 100
                    )
                except Exception:
                    model_confidence = None

            soi_id = str(uuid.uuid4())
            created_at = time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(),
            )

            artifact_links = []

            if feature_artifact_id:
                artifact_links.append(
                    {
                        "artifact_id": feature_artifact_id,
                        "role": "feature_analysis",
                        "source": "signal_analysis_classifier",
                    }
                )

            if classification_artifact_id:
                artifact_links.append(
                    {
                        "artifact_id": classification_artifact_id,
                        "operation_id": operation_id,
                        "role": "classification_analysis",
                        "source": "signal_analysis_classifier",
                    }
                )

            summary = {
                "name": os.path.basename(file_name),
                "stage": "classified",
                "stage_order": 70,
                "source": "signal_analysis_classifier",
                "description": (
                    f"Classifier result for {file_name}"
                ),
                "input_mode": "per_input",
                "input_file": file_name,
                "source_feature_artifact_id": feature_artifact_id,
                "classification": {
                    "display_label": primary,
                    "candidates": candidates,
                },
                "model_classification": primary,
                "model_confidence": model_confidence,
                "analysis_history": [
                    {
                        "analysis_id": (
                            f"classifier:{operation_id}:"
                            f"{uuid.uuid4()}"
                        ),
                        "stage": "classifier",
                        "source": "signal_analysis_classifier",
                        "operation_id": operation_id,
                        "artifact_id": classification_artifact_id,
                        "input_mode": "per_input",
                        "input_file": file_name,
                        "primary_classification": primary,
                        "candidate_count": len(candidates),
                        "created_at": created_at,
                    }
                ],
            }

            if artifact_links:
                summary["artifact_links"] = artifact_links

            await dashboard.backend.signalAnalysisSoiUpdate(
                node_uid=node_uid,
                soi_id=soi_id,
                frequency_mhz=None,
                status="EVIDENCE_READY",
                operation_id=operation_id,
                artifact_id=classification_artifact_id,
                summary=summary,
            )

            created += 1

        dashboard.ui.label2_sa_classifier_classify_run_status.setText(
            (
                f"Created {created} SOI"
                f"{'s' if created != 1 else ''}"
            )
        )

    except Exception as error:
        dashboard.logger.error(
            "[Classifier] Failed creating per-input SOIs: "
            f"{error!r}"
        )
        await Qt5.async_ok_dialog(
            dashboard,
            (
                "Failed to create one or more classifier SOIs."
                f"\n\n{error}"
            ),
        )

    finally:
        _sa_classifier_update_save_button(
            dashboard
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_ClassifierSaveSoiClicked(
    dashboard: QtCore.QObject,
):
    if _sa_classifier_resolved_input_mode(dashboard) == "Per Input":
        await _sa_classifier_create_selected_input_sois(
            dashboard
        )
        return

    primary = str(
        dashboard.ui.comboBox_sa_classifier_classify_results_primary.currentText()
        or ""
    ).strip()

    if not primary or not getattr(
        dashboard,
        "sa_classifier_candidates",
        [],
    ):
        return

    context = _sa_classifier_soi_context(dashboard)
    existing = bool(context)

    soi_id = (
        str(context.get("soi_id") or "").strip()
        if existing
        else str(uuid.uuid4())
    )
    node_uid = (
        str(context.get("node_uid") or "").strip()
        if existing
        else str(
            getattr(
                dashboard,
                "selected_node_uid",
                "",
            )
            or ""
        ).strip()
    )
    frequency = (
        None
        if existing
        else _sa_classifier_evidence(
            dashboard
        ).get("frequency_mhz")
    )

    library_top = next(
        (
            row
            for row in dashboard.sa_classifier_candidates
            if row.get("source") == "Library"
        ),
        None,
    )
    model_top = next(
        (
            row
            for row in dashboard.sa_classifier_candidates
            if row.get("source") == "Model"
        ),
        None,
    )

    candidates = []

    for row in dashboard.sa_classifier_candidates:
        entry = {
            "source": str(
                row.get("source")
                or ""
            ).lower(),
            "label": str(
                row.get("label")
                or ""
            ),
        }

        if row.get("agreement_value") is not None:
            entry["agreement"] = row.get(
                "agreement_value"
            )

        candidates.append(entry)

    candidates.append(
        {
            "source": "analyst",
            "label": primary,
        }
    )

    classification_artifact_id = str(
        getattr(
            dashboard,
            "sa_classifier_artifact_id",
            "",
        )
        or ""
    ).strip()
    operation_id = str(
        getattr(
            dashboard,
            "sa_classifier_operation_id",
            "",
        )
        or ""
    ).strip()

    feature_artifact_id = ""
    if _sa_classifier_source(dashboard) == "Artifact":
        feature_artifact_id = str(
            _sa_classifier_artifact_context(dashboard).get(
                "artifact_id"
            )
            or ""
        ).strip()

    artifact_links = []

    if feature_artifact_id:
        artifact_links.append(
            {
                "artifact_id": feature_artifact_id,
                "role": "feature_analysis",
                "source": "signal_analysis_classifier",
            }
        )

    if classification_artifact_id:
        artifact_links.append(
            {
                "artifact_id": classification_artifact_id,
                "operation_id": operation_id,
                "role": "classification_analysis",
                "source": "signal_analysis_classifier",
            }
        )

    summary = {
        "analyst_classification": primary,
        "input_mode": "combine_results",
        "source_feature_artifact_id": feature_artifact_id,
        "classification": {
            "display_label": primary,
            "candidates": candidates,
        },
        "database_classification": (
            str(library_top.get("label") or "")
            if library_top
            else ""
        ),
        "model_classification": (
            str(model_top.get("label") or "")
            if model_top
            else ""
        ),
        "model_confidence": (
            round(
                float(
                    model_top.get(
                        "agreement_value"
                    )
                )
                * 100
            )
            if model_top
            and model_top.get("agreement_value") is not None
            else None
        ),
        "analysis_history": [
            {
                "analysis_id": (
                    f"classifier:"
                    f"{operation_id or uuid.uuid4()}"
                ),
                "stage": "classifier",
                "source": "signal_analysis_classifier",
                "operation_id": operation_id,
                "artifact_id": classification_artifact_id,
                "input_mode": "combine_results",
                "primary_classification": primary,
                "candidate_count": len(candidates),
                "created_at": time.strftime(
                    "%Y-%m-%dT%H:%M:%SZ",
                    time.gmtime(),
                ),
            }
        ],
    }

    if artifact_links:
        summary["artifact_links"] = artifact_links

    if not existing:
        summary.update(
            {
                "stage": "classified",
                "stage_order": 70,
                "source": "signal_analysis_classifier",
                "description": (
                    "Classification results promoted to SOI"
                ),
            }
        )

    button = dashboard.ui.pushButton_sa_classifier_classify_results_save_soi
    button.setEnabled(False)

    dashboard.ui.label2_sa_classifier_classify_run_status.setText(
        "Saving to SOI..."
        if existing
        else "Creating SOI..."
    )

    try:
        await dashboard.backend.signalAnalysisSoiUpdate(
            node_uid=node_uid,
            soi_id=soi_id,
            frequency_mhz=frequency,
            status=(
                ""
                if existing
                else "EVIDENCE_READY"
            ),
            operation_id=operation_id,
            artifact_id=classification_artifact_id,
            summary=summary,
        )

        dashboard.ui.label2_sa_classifier_classify_run_status.setText(
            (
                f"Saved classification to SOI: {soi_id}"
                if existing
                else f"Created SOI: {soi_id}"
            )
        )

    except Exception as error:
        dashboard.logger.error(
            "[Classifier] Failed saving SOI classification: "
            f"{error!r}"
        )
        await Qt5.async_ok_dialog(
            dashboard,
            (
                "Failed to save classification to SOI."
                f"\n\n{error}"
            ),
        )

    finally:
        _sa_classifier_update_save_button(
            dashboard
        )



__all__ = [name for name, value in globals().items() if inspect.isfunction(value) and value.__module__ == __name__]
