"""Dashboard handlers for Signal Analysis / Protocol Discovery / Demodulation.

Input and Artifact handling mirror Inspection, but use independent Dashboard state.
Numerical signal recovery lives in fissure.utils.protocol_demodulation so it can
be called from Sensor Node Operations and plugins without importing PyQt5.
"""

import inspect
from PyQt5 import QtCore, QtGui, QtWidgets
import asyncio
import json
import math
import os
import re
import shutil
import zipfile
import numpy as np
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg, NavigationToolbar2QT
from matplotlib.figure import Figure
from matplotlib.ticker import MaxNLocator
import qasync

import fissure.utils
from fissure.Dashboard.SoiEvidenceController import collect_soi_artifact_ids
from fissure.Dashboard.UI_Components import Qt5
from .sois import _sa_sois_display_name, _sa_sois_format_frequency, _sa_sois_value
from fissure.utils.protocol_demodulation import estimate_parameters, recover_candidate, retime_cached_candidate

OVERVIEW_POINTS = 4000
VIEW_POINTS = 60000
MAX_ANALYSIS_SAMPLES = 2_000_000

_SIGMF_TYPE_MAP = {
    "cf32_le": ("Complex Float 32", np.dtype("<c8"), True, False),
    "cf32_be": ("Complex Float 32", np.dtype(">c8"), True, False),
    "cf64_le": ("Complex Float 64", np.dtype("<c16"), True, False),
    "cf64_be": ("Complex Float 64", np.dtype(">c16"), True, False),
    "ci16_le": ("Complex Int 16", np.dtype("<i2"), True, True),
    "ci16_be": ("Complex Int 16", np.dtype(">i2"), True, True),
    "cu16_le": ("Complex Unsigned Int 16", np.dtype("<u2"), True, True),
    "cu16_be": ("Complex Unsigned Int 16", np.dtype(">u2"), True, True),
    "ci32_le": ("Complex Int 32", np.dtype("<i4"), True, True),
    "ci32_be": ("Complex Int 32", np.dtype(">i4"), True, True),
    "cu32_le": ("Complex Unsigned Int 32", np.dtype("<u4"), True, True),
    "cu32_be": ("Complex Unsigned Int 32", np.dtype(">u4"), True, True),
    "ci8": ("Complex Int 8", np.dtype("i1"), True, True),
    "cu8": ("Complex Unsigned Int 8", np.dtype("u1"), True, True),
    "rf32_le": ("Float/Float 32", np.dtype("<f4"), False, False),
    "rf32_be": ("Float/Float 32", np.dtype(">f4"), False, False),
    "rf64_le": ("Float/Float 64", np.dtype("<f8"), False, False),
    "rf64_be": ("Float/Float 64", np.dtype(">f8"), False, False),
    "ri16_le": ("Short/Int 16", np.dtype("<i2"), False, False),
    "ri16_be": ("Short/Int 16", np.dtype(">i2"), False, False),
    "ru16_le": ("Unsigned Int 16", np.dtype("<u2"), False, False),
    "ru16_be": ("Unsigned Int 16", np.dtype(">u2"), False, False),
    "ri32_le": ("Int/Int 32", np.dtype("<i4"), False, False),
    "ri32_be": ("Int/Int 32", np.dtype(">i4"), False, False),
    "ru32_le": ("Unsigned Int 32", np.dtype("<u4"), False, False),
    "ru32_be": ("Unsigned Int 32", np.dtype(">u4"), False, False),
    "ri8": ("Byte/Int 8", np.dtype("i1"), False, False),
    "ru8": ("Unsigned Int 8", np.dtype("u1"), False, False),
}

_FISSURE_TYPE_MAP = {
    "Complex Float 32": (np.dtype("<c8"), True, False),
    "Complex Float 64": (np.dtype("<c16"), True, False),
    "Complex Int 16": (np.dtype("<i2"), True, True),
    "Complex Unsigned Int 16": (np.dtype("<u2"), True, True),
    "Complex Int 32": (np.dtype("<i4"), True, True),
    "Complex Unsigned Int 32": (np.dtype("<u4"), True, True),
    "Complex Int 64": (np.dtype("<i8"), True, True),
    "Complex Unsigned Int 64": (np.dtype("<u8"), True, True),
    "Complex Int 8": (np.dtype("i1"), True, True),
    "Complex Unsigned Int 8": (np.dtype("u1"), True, True),
    "Float/Float 32": (np.dtype("<f4"), False, False),
    "Float/Float 64": (np.dtype("<f8"), False, False),
    "Short/Int 16": (np.dtype("<i2"), False, False),
    "Unsigned Int 16": (np.dtype("<u2"), False, False),
    "Int/Int 32": (np.dtype("<i4"), False, False),
    "Unsigned Int 32": (np.dtype("<u4"), False, False),
    "Byte/Int 8": (np.dtype("i1"), False, False),
    "Unsigned Int 8": (np.dtype("u1"), False, False),
}

_PD_DEMODULATION_FILE_TYPE_BY_EXTENSION = {
    # Complex floating-point I/Q.
    ".cf32": "Complex Float 32",
    ".fc32": "Complex Float 32",
    ".cfile": "Complex Float 32",
    ".cf64": "Complex Float 64",
    ".fc64": "Complex Float 64",

    # Complex signed integer I/Q.
    ".ci8": "Complex Int 8",
    ".cs8": "Complex Int 8",
    ".sc8": "Complex Int 8",
    ".ci16": "Complex Int 16",
    ".cs16": "Complex Int 16",
    ".sc16": "Complex Int 16",
    ".ci32": "Complex Int 32",
    ".cs32": "Complex Int 32",
    ".sc32": "Complex Int 32",
    ".ci64": "Complex Int 64",
    ".cs64": "Complex Int 64",
    ".sc64": "Complex Int 64",

    # Complex unsigned integer I/Q.
    ".cu8": "Complex Unsigned Int 8",
    ".cu16": "Complex Unsigned Int 16",
    ".cu32": "Complex Unsigned Int 32",
    ".cu64": "Complex Unsigned Int 64",

    # Real/scalar floating-point data.
    ".f32": "Float/Float 32",
    ".rf32": "Float/Float 32",
    ".f64": "Float/Float 64",
    ".rf64": "Float/Float 64",

    # Real/scalar signed integer data.
    ".i8": "Byte/Int 8",
    ".s8": "Byte/Int 8",
    ".ri8": "Byte/Int 8",
    ".i16": "Short/Int 16",
    ".s16": "Short/Int 16",
    ".ri16": "Short/Int 16",
    ".i32": "Int/Int 32",
    ".s32": "Int/Int 32",
    ".ri32": "Int/Int 32",

    # Real/scalar unsigned integer data.
    ".u8": "Unsigned Int 8",
    ".ru8": "Unsigned Int 8",
    ".u16": "Unsigned Int 16",
    ".ru16": "Unsigned Int 16",
    ".u32": "Unsigned Int 32",
    ".ru32": "Unsigned Int 32",
}

_PD_DEMODULATION_DATA_EXTENSIONS = (
    ".sigmf-data",
    ".iq",
    ".dat",
    ".bin",
    ".raw",
    *_PD_DEMODULATION_FILE_TYPE_BY_EXTENSION.keys(),
)





def _sa_pd_demodulation_find_soi(dashboard: QtCore.QObject, soi_key: str) -> dict:
    soi = (getattr(dashboard, "tactical_sois", {}) or {}).get(str(soi_key or "").strip())
    return dict(soi) if isinstance(soi, dict) else {}


def _sa_pd_demodulation_soi_text(soi: dict) -> str:
    name = _sa_sois_display_name(soi)
    frequency = _sa_sois_value(soi, "frequency_mhz", "center_frequency_mhz")
    frequency_text = _sa_sois_format_frequency(frequency)
    if frequency_text not in ("", "—") and frequency_text not in name:
        return f"{name} ({frequency_text})"
    return name


def refresh_sa_pd_demodulation_soi_context(dashboard: QtCore.QObject, preferred_soi_key: str = ""):
    """Refresh the optional SOI context selector without changing the active source."""
    combo = dashboard.ui.comboBox_sa_pd_demodulation_selection_soi
    current_key = str(combo.currentData(QtCore.Qt.UserRole) or "").strip()
    pending_key = str(getattr(dashboard, "signal_analysis_prefill_soi_key", "") or "").strip()
    preferred_key = str(preferred_soi_key or pending_key or current_key or "").strip()

    rows = [
        (str(key), record)
        for key, record in (getattr(dashboard, "tactical_sois", {}) or {}).items()
        if isinstance(record, dict)
    ]
    rows.sort(key=lambda item: (_sa_pd_demodulation_soi_text(item[1]).lower(), item[0]))

    combo.blockSignals(True)
    combo.clear()
    combo.addItem("Manual / No SOI", "")
    for soi_key, record in rows:
        combo.addItem(_sa_pd_demodulation_soi_text(record), soi_key)

    selected_index = 0
    if preferred_key:
        for index in range(combo.count()):
            if str(combo.itemData(index, QtCore.Qt.UserRole) or "").strip() == preferred_key:
                selected_index = index
                break
    combo.setCurrentIndex(selected_index)
    combo.blockSignals(False)

    if pending_key and preferred_key == pending_key and selected_index > 0:
        pass  # Leave shared SOI prefill available to other Signal Analysis tabs

    if getattr(dashboard, "sa_pd_demodulation_source", "artifact") == "artifact":
        _refresh_sa_pd_demodulation_artifacts(dashboard)
    


def _sa_pd_demodulation_artifact_id(key, record: dict) -> str:
    return str(record.get("artifact_id") or record.get("id") or key or "").strip()


def _sa_pd_demodulation_artifact_timestamp(record: dict) -> str:
    return str(record.get("modified_at") or record.get("created_at") or record.get("time") or "").strip()


def _sa_pd_demodulation_artifact_text(artifact_id: str, record: dict) -> str:
    name = str(record.get("name") or record.get("description") or "Artifact").strip()
    timestamp = _sa_pd_demodulation_artifact_timestamp(record).replace("T", " ").split(".")[0]
    parts = [name]
    if timestamp:
        parts.append(timestamp)
    if artifact_id:
        parts.append(artifact_id)
    return " | ".join(parts)


def _sa_pd_demodulation_artifact_rows(dashboard: QtCore.QObject) -> list:
    artifacts = getattr(dashboard, "tactical_artifacts", {}) or {}
    if isinstance(artifacts, dict):
        iterable = artifacts.items()
    elif isinstance(artifacts, list):
        iterable = enumerate(artifacts)
    else:
        iterable = []

    soi_key = str(dashboard.ui.comboBox_sa_pd_demodulation_selection_soi.currentData(QtCore.Qt.UserRole) or "").strip()
    soi = _sa_pd_demodulation_find_soi(dashboard, soi_key)
    linked_ids = collect_soi_artifact_ids(soi) if soi else []
    linked_set = set(linked_ids)

    rows = []
    for key, record in iterable:
        if not isinstance(record, dict):
            continue
        artifact_id = _sa_pd_demodulation_artifact_id(key, record)
        if not artifact_id:
            continue
        if soi and artifact_id not in linked_set:
            continue
        rows.append((artifact_id, dict(record)))

    rows.sort(key=lambda item: _sa_pd_demodulation_artifact_timestamp(item[1]), reverse=True)
    return rows


def _refresh_sa_pd_demodulation_artifacts(dashboard: QtCore.QObject, preferred_artifact_id: str = ""):
    combo = dashboard.ui.comboBox_sa_pd_demodulation_selection_artifact
    current = combo.currentData(QtCore.Qt.UserRole)
    current_id = str(current.get("artifact_id") or "").strip() if isinstance(current, dict) else ""
    pending_id = str(getattr(dashboard, "signal_analysis_prefill_artifact_id", "") or "").strip()
    preferred_id = str(preferred_artifact_id or pending_id or current_id or "").strip()

    rows = _sa_pd_demodulation_artifact_rows(dashboard)
    combo.blockSignals(True)
    combo.clear()
    for artifact_id, record in rows:
        combo.addItem(
            _sa_pd_demodulation_artifact_text(artifact_id, record),
            {"artifact_id": artifact_id, "record": record},
        )

    selected_index = 0 if combo.count() else -1
    if preferred_id:
        for index in range(combo.count()):
            context = combo.itemData(index, QtCore.Qt.UserRole)
            if isinstance(context, dict) and str(context.get("artifact_id") or "").strip() == preferred_id:
                selected_index = index
                break
    combo.setCurrentIndex(selected_index)
    combo.blockSignals(False)

    matched_pending = False
    context = combo.currentData(QtCore.Qt.UserRole)
    if isinstance(context, dict):
        matched_pending = str(context.get("artifact_id") or "").strip() == pending_id
    if pending_id and matched_pending:
        pass  # Leave shared Artifact prefill available to other Signal Analysis tabs

    _slotSA_PDDemodulationArtifactChanged(dashboard)


def _sa_pd_demodulation_selected_artifact(dashboard: QtCore.QObject) -> tuple:
    context = dashboard.ui.comboBox_sa_pd_demodulation_selection_artifact.currentData(QtCore.Qt.UserRole)
    if not isinstance(context, dict):
        return "", {}
    return str(context.get("artifact_id") or "").strip(), dict(context.get("record") or {})


def _sa_pd_demodulation_file_role(file_record: dict) -> str:
    return str(file_record.get("role") or file_record.get("metadata", {}).get("role") or "").strip().lower()


def _sa_pd_demodulation_file_name(file_record: dict) -> str:
    return str(
        file_record.get("name")
        or file_record.get("relative_path")
        or file_record.get("path")
        or file_record.get("id")
        or "File"
    ).strip()


def _sa_pd_demodulation_manifest_files(record: dict) -> list:
    files = record.get("files", []) if isinstance(record, dict) else []

    if not isinstance(files, list):
        return []

    inspectable = []
    fallback = []

    for item in files:
        if not isinstance(item, dict):
            continue

        role = _sa_pd_demodulation_file_role(item)
        name = _sa_pd_demodulation_file_name(item).lower()

        if (
            role in {"sigmf_data", "iq_data"}
            or name.endswith(_PD_DEMODULATION_DATA_EXTENSIONS)
        ):
            inspectable.append(dict(item))

        elif role == "bundle" or name.endswith(".zip"):
            fallback.append(dict(item))

    return inspectable or fallback


def _sa_pd_demodulation_cached_file_map(dashboard: QtCore.QObject, artifact_id: str) -> dict:
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    return controller.get_local_files(artifact_id) if controller is not None and artifact_id else {}


def _sa_pd_demodulation_extracted_root(dashboard: QtCore.QObject, artifact_id: str) -> str:
    return os.path.join(
        fissure.utils.HUB_ARTIFACTS_DIR,
        "pd_demodulation",
        str(artifact_id or "unknown"),
    )


def _sa_pd_demodulation_safe_extract(zip_path: str, destination: str):
    os.makedirs(destination, exist_ok=True)
    destination_real = os.path.realpath(destination)
    with zipfile.ZipFile(zip_path, "r") as handle:
        for member in handle.infolist():
            target = os.path.realpath(os.path.join(destination_real, member.filename))
            if target != destination_real and not target.startswith(destination_real + os.sep):
                raise RuntimeError(f"Unsafe ZIP member path: {member.filename}")
        handle.extractall(destination_real)


def _sa_pd_demodulation_extracted_files(
    dashboard: QtCore.QObject,
    artifact_id: str,
) -> list:
    root = _sa_pd_demodulation_extracted_root(
        dashboard,
        artifact_id,
    )

    if not os.path.isdir(root):
        return []

    rows = []

    for current_root, _dirs, names in os.walk(root):
        for name in sorted(names):
            path = os.path.join(current_root, name)
            lower = name.lower()

            if not lower.endswith(_PD_DEMODULATION_DATA_EXTENSIONS):
                continue

            rows.append(
                {
                    "id": f"extracted:{os.path.relpath(path, root)}",
                    "name": name,
                    "role": (
                        "sigmf_data"
                        if lower.endswith(".sigmf-data")
                        else "iq_data"
                    ),
                    "local_path": path,
                }
            )

    return rows


def _sa_pd_demodulation_file_rows(dashboard: QtCore.QObject, artifact_id: str, record: dict) -> list:
    extracted = _sa_pd_demodulation_extracted_files(dashboard, artifact_id)
    if extracted:
        return extracted

    local_map = _sa_pd_demodulation_cached_file_map(dashboard, artifact_id)
    rows = []
    for item in _sa_pd_demodulation_manifest_files(record):
        file_id = str(item.get("id") or item.get("file_id") or "").strip()
        row = dict(item)
        row["file_id"] = file_id
        row["artifact_id"] = artifact_id
        local_path = str(local_map.get(file_id) or "").strip()
        if local_path:
            row["local_path"] = local_path
        rows.append(row)
    return rows


def _populate_sa_pd_demodulation_files(dashboard: QtCore.QObject, preferred_file_id: str = ""):
    combo = dashboard.ui.comboBox_sa_pd_demodulation_selection_file
    artifact_id, record = _sa_pd_demodulation_selected_artifact(dashboard)
    current = combo.currentData(QtCore.Qt.UserRole)
    current_id = str(current.get("file_id") or current.get("id") or "").strip() if isinstance(current, dict) else ""
    preferred_id = str(preferred_file_id or current_id or "").strip()

    rows = _sa_pd_demodulation_file_rows(dashboard, artifact_id, record) if artifact_id else []
    combo.blockSignals(True)
    combo.clear()
    for row in rows:
        combo.addItem(_sa_pd_demodulation_file_name(row), row)

    selected_index = 0 if combo.count() else -1
    if preferred_id:
        for index in range(combo.count()):
            context = combo.itemData(index, QtCore.Qt.UserRole)
            candidate = str(context.get("file_id") or context.get("id") or "").strip() if isinstance(context, dict) else ""
            if candidate == preferred_id:
                selected_index = index
                break
    combo.setCurrentIndex(selected_index)
    combo.blockSignals(False)

    _update_sa_pd_demodulation_prepare_button(dashboard)
    _slotSA_PDDemodulationFileChanged(dashboard)


def _update_sa_pd_demodulation_prepare_button(dashboard: QtCore.QObject):
    button = dashboard.ui.pushButton_sa_pd_demodulation_selection_prepare
    artifact_id, record = _sa_pd_demodulation_selected_artifact(dashboard)
    if not artifact_id:
        button.setText("Prepare")
        button.setEnabled(False)
        return

    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    local_path = controller.get_local_path(artifact_id) if controller is not None else None
    rows = _sa_pd_demodulation_file_rows(dashboard, artifact_id, record)
    has_local_iq = any(
        _sa_pd_demodulation_file_role(row) != "bundle"
        and not _sa_pd_demodulation_file_name(row).lower().endswith(".zip")
        and os.path.isfile(str(row.get("local_path") or ""))
        for row in rows
    )

    if has_local_iq:
        button.setText("Prepared")
        button.setEnabled(False)
    elif local_path and os.path.isfile(local_path) and local_path.lower().endswith(".zip"):
        button.setText("Prepare")
        button.setEnabled(True)
    elif local_path:
        button.setText("No IQ Data")
        button.setEnabled(False)
    else:
        button.setText("Download")
        button.setEnabled(True)


def _sa_pd_demodulation_sigmf_meta_path(filepath: str) -> str:
    lower = filepath.lower()
    if lower.endswith(".sigmf-data"):
        return filepath[:-11] + ".sigmf-meta"
    if lower.endswith(".sigmf-meta"):
        return filepath
    sidecar = filepath + ".sigmf-meta"
    return sidecar if os.path.isfile(sidecar) else ""


def _sa_pd_demodulation_load_sigmf(filepath: str) -> dict:
    meta_path = _sa_pd_demodulation_sigmf_meta_path(filepath)
    if not meta_path or not os.path.isfile(meta_path):
        return {}
    try:
        with open(meta_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _sa_pd_demodulation_metadata_value(file_record: dict, artifact_record: dict, *keys):
    sources = [
        file_record,
        file_record.get("metadata", {}) if isinstance(file_record.get("metadata"), dict) else {},
        artifact_record.get("metadata", {}) if isinstance(artifact_record.get("metadata"), dict) else {},
        artifact_record,
    ]
    for source in sources:
        if not isinstance(source, dict):
            continue
        for key in keys:
            value = source.get(key)
            if value not in (None, "", "None"):
                return value
    return None


def _sa_pd_demodulation_float(value, default=None):
    try:
        return float(value)
    except Exception:
        return default


def _sa_pd_demodulation_resolve_type(data_type: str, sigmf_type: str = "") -> tuple:
    if sigmf_type in _SIGMF_TYPE_MAP:
        label, dtype, is_complex, interleaved = _SIGMF_TYPE_MAP[sigmf_type]
        return label, dtype, is_complex, interleaved
    if data_type in _FISSURE_TYPE_MAP:
        dtype, is_complex, interleaved = _FISSURE_TYPE_MAP[data_type]
        return data_type, dtype, is_complex, interleaved
    return "Complex Float 32", np.dtype("<c8"), True, False


def _sa_pd_demodulation_build_file_metadata(
    dashboard: QtCore.QObject,
    filepath: str,
    file_record: dict = None,
    artifact_record: dict = None,
) -> dict:
    file_record = dict(file_record or {})
    artifact_record = dict(artifact_record or {})
    filepath = os.path.abspath(str(filepath or "").strip())

    sigmf = _sa_pd_demodulation_load_sigmf(filepath)
    sigmf_global = (
        sigmf.get("global", {})
        if isinstance(sigmf.get("global"), dict)
        else {}
    )
    captures = (
        sigmf.get("captures", [])
        if isinstance(sigmf.get("captures"), list)
        else []
    )
    first_capture = (
        captures[0]
        if captures and isinstance(captures[0], dict)
        else {}
    )

    sigmf_type = str(
        sigmf_global.get("core:datatype")
        or ""
    ).strip()

    declared_data_type = str(
        _sa_pd_demodulation_metadata_value(
            file_record,
            artifact_record,
            "data_type",
        )
        or ""
    ).strip()

    extension = os.path.splitext(filepath)[1].lower()
    extension_data_type = _PD_DEMODULATION_FILE_TYPE_BY_EXTENSION.get(
        extension,
        "",
    )

    # Prefer explicit SigMF / Artifact metadata. If none exists, use a
    # conventional typed extension such as .cf32 or .sc16. Generic extensions
    # such as .iq/.dat/.bin/.raw remain assumptions and therefore still receive
    # the UI's assumed-data-type marker.
    data_type = declared_data_type or extension_data_type
    data_type_assumed = not bool(
        sigmf_type
        or declared_data_type
        or extension_data_type
    )

    data_type, dtype, is_complex, interleaved = (
        _sa_pd_demodulation_resolve_type(
            data_type,
            sigmf_type,
        )
    )

    sample_rate_hz = _sa_pd_demodulation_float(
        sigmf_global.get("core:sample_rate")
    )

    if sample_rate_hz is None:
        sample_rate_msps = _sa_pd_demodulation_float(
            _sa_pd_demodulation_metadata_value(
                file_record,
                artifact_record,
                "sample_rate_msps",
            )
        )
        sample_rate_hz = (
            sample_rate_msps * 1e6
            if sample_rate_msps is not None
            else None
        )

    if sample_rate_hz is None:
        sample_rate_hz = _sa_pd_demodulation_float(
            _sa_pd_demodulation_metadata_value(
                file_record,
                artifact_record,
                "sample_rate",
                "sample_rate_hz",
            )
        )

    sample_rate_source = "metadata" if sample_rate_hz else "unknown"
    if not sample_rate_hz:
        sample_rate_hz = _pd_sample_rate_from_filename(filepath)
        if sample_rate_hz:
            sample_rate_source = "filename"

    center_frequency_hz = _sa_pd_demodulation_float(
        first_capture.get("core:frequency")
    )

    if center_frequency_hz is None:
        frequency_mhz = _sa_pd_demodulation_float(
            _sa_pd_demodulation_metadata_value(
                file_record,
                artifact_record,
                "frequency_mhz",
                "center_frequency_mhz",
            )
        )
        center_frequency_hz = (
            frequency_mhz * 1e6
            if frequency_mhz is not None
            else None
        )

    if center_frequency_hz is None:
        soi_key = str(
            dashboard.ui.comboBox_sa_pd_demodulation_selection_soi.currentData(
                QtCore.Qt.UserRole
            )
            or ""
        ).strip()

        soi = _sa_pd_demodulation_find_soi(
            dashboard,
            soi_key,
        )

        frequency_mhz = (
            _sa_pd_demodulation_float(
                _sa_sois_value(
                    soi,
                    "frequency_mhz",
                    "center_frequency_mhz",
                )
            )
            if soi
            else None
        )

        center_frequency_hz = (
            frequency_mhz * 1e6
            if frequency_mhz is not None
            else None
        )

    size_bytes = (
        os.path.getsize(filepath)
        if os.path.isfile(filepath)
        else int(file_record.get("size") or 0)
    )

    scalar_size = int(dtype.itemsize)
    bytes_per_sample = (
        scalar_size * 2
        if interleaved
        else scalar_size
    )

    sample_count = (
        int(size_bytes // bytes_per_sample)
        if bytes_per_sample > 0
        else 0
    )

    duration_s = (
        sample_count / sample_rate_hz
        if sample_rate_hz and sample_rate_hz > 0
        else None
    )

    return {
        "path": filepath,
        "name": os.path.basename(filepath),
        "data_type": data_type,
        "data_type_assumed": data_type_assumed,
        "dtype": dtype,
        "is_complex": bool(is_complex),
        "interleaved": bool(interleaved),
        "bytes_per_sample": bytes_per_sample,
        "sample_rate_hz": sample_rate_hz,
        "sample_rate_source": sample_rate_source,
        "center_frequency_hz": center_frequency_hz,
        "sample_count": sample_count,
        "duration_s": duration_s,
        "size_bytes": size_bytes,
        "sigmf": sigmf,
        "file_record": file_record,
        "artifact_record": artifact_record,
    }


def _sa_pd_demodulation_read_samples(metadata: dict, start_sample: int, end_sample: int) -> np.ndarray:
    path = str(metadata.get("path") or "")
    if not path or not os.path.isfile(path):
        return np.asarray([], dtype=np.complex64)

    total = int(metadata.get("sample_count") or 0)
    start = max(0, min(int(start_sample), total))
    end = max(start, min(int(end_sample), total))
    count = end - start
    if count <= 0:
        return np.asarray([], dtype=np.complex64)

    dtype = metadata["dtype"]
    if metadata.get("interleaved"):
        raw = np.memmap(path, dtype=dtype, mode="r", offset=start * dtype.itemsize * 2, shape=(count * 2,))
        real = np.asarray(raw[0::2], dtype=np.float32)
        imag = np.asarray(raw[1::2], dtype=np.float32)
        return real + 1j * imag

    raw = np.memmap(path, dtype=dtype, mode="r", offset=start * dtype.itemsize, shape=(count,))
    return np.asarray(raw)


def _sa_pd_demodulation_read_indices(metadata: dict, indices: np.ndarray) -> np.ndarray:
    """Read only requested sample indices and ignore any trailing partial sample bytes."""
    path = str(metadata.get("path") or "")
    indices = np.asarray(indices, dtype=np.int64)
    total = int(metadata.get("sample_count") or 0)
    if not path or not os.path.isfile(path) or indices.size == 0 or total <= 0:
        return np.asarray([], dtype=np.complex64)

    indices = indices[(indices >= 0) & (indices < total)]
    if indices.size == 0:
        return np.asarray([], dtype=np.complex64)

    dtype = metadata["dtype"]
    if metadata.get("interleaved"):
        raw = np.memmap(path, dtype=dtype, mode="r", shape=(total * 2,))
        real = np.asarray(raw[indices * 2], dtype=np.float32)
        imag = np.asarray(raw[indices * 2 + 1], dtype=np.float32)
        return real + 1j * imag

    raw = np.memmap(path, dtype=dtype, mode="r", shape=(total,))
    return np.asarray(raw[indices])


def _sa_pd_demodulation_read_display_samples(metadata: dict, start_sample: int, end_sample: int, limit: int) -> tuple:
    count = max(0, int(end_sample) - int(start_sample))
    if count <= limit:
        data = _sa_pd_demodulation_read_samples(metadata, start_sample, end_sample)
        indices = np.arange(start_sample, start_sample + len(data), dtype=np.int64)
        return data, indices

    step = max(1, int(math.ceil(count / float(limit))))
    indices = np.arange(start_sample, end_sample, step, dtype=np.int64)[:limit]
    return _sa_pd_demodulation_read_indices(metadata, indices), indices


def _sa_pd_demodulation_read_centered_samples(metadata: dict, start_sample: int, end_sample: int, limit: int) -> tuple:
    count = max(0, int(end_sample) - int(start_sample))
    if count <= limit:
        return _sa_pd_demodulation_read_samples(metadata, start_sample, end_sample), start_sample
    center = start_sample + count // 2
    half = limit // 2
    read_start = max(start_sample, center - half)
    read_end = min(end_sample, read_start + limit)
    read_start = max(start_sample, read_end - limit)
    return _sa_pd_demodulation_read_samples(metadata, read_start, read_end), read_start


def _sa_pd_demodulation_format_size(size_bytes: int) -> str:
    value = float(size_bytes or 0)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{int(size_bytes)} B"


def _sa_pd_demodulation_format_duration(value) -> str:
    value = _sa_pd_demodulation_float(value)
    if value is None:
        return "—"
    if value < 1e-3:
        return f"{value * 1e6:.3f} µs"
    if value < 1.0:
        return f"{value * 1e3:.3f} ms"
    return f"{value:.6g} s"


def _sa_pd_demodulation_format_sample_rate(value) -> str:
    value = _sa_pd_demodulation_float(value)
    if value is None:
        return "—"
    if value >= 1e6:
        return f"{value / 1e6:.6g} MS/s"
    if value >= 1e3:
        return f"{value / 1e3:.6g} kS/s"
    return f"{value:.6g} S/s"


def _sa_pd_demodulation_format_frequency(value) -> str:
    value = _sa_pd_demodulation_float(value)
    if value is None:
        return "—"
    if abs(value) >= 1e6:
        return f"{value / 1e6:.6f} MHz"
    if abs(value) >= 1e3:
        return f"{value / 1e3:.3f} kHz"
    return f"{value:.3f} Hz"


def _sa_pd_demodulation_set_file_metadata(dashboard: QtCore.QObject, metadata: dict = None):
    """Populate editable metadata without emitting recursive change events."""
    metadata = metadata or {}
    ui = dashboard.ui
    sample_rate = ui.doubleSpinBox_sa_pd_demodulation_selection_sample_rate
    frequency = ui.doubleSpinBox_sa_pd_demodulation_selection_center_frequency
    for spin, value in (
        (sample_rate, float(metadata.get("sample_rate_hz") or 0.0) / 1e6),
        (frequency, float(metadata.get("center_frequency_hz") or 0.0) / 1e6),
    ):
        blocked = spin.blockSignals(True)
        try:
            spin.setValue(value)
            spin.setEnabled(bool(metadata))
        finally:
            spin.blockSignals(blocked)
    rate_source = metadata.get("sample_rate_source", "unknown")
    sample_rate.setToolTip(
        "Rate parsed from filename; verify before use." if rate_source == "filename"
        else "Rate from SigMF/Artifact metadata." if rate_source == "metadata"
        else "Enter the source recording's sample rate (MS/s)."
    )
    combo = ui.comboBox_sa_pd_demodulation_selection_data_type
    chosen = str(metadata.get("data_type") or "Complex Float 32")
    blocked = combo.blockSignals(True)
    try:
        position = combo.findText(chosen)
        combo.setCurrentIndex(position if position >= 0 else combo.findText("Complex Float 32"))
        combo.setEnabled(bool(metadata))
    finally:
        combo.blockSignals(blocked)
    combo.setToolTip(
        "Assumed datatype; verify against original sample format."
        if metadata and metadata.get("data_type_assumed")
        else "Interpretation of the original file's stored samples."
    )
    ui.label2_sa_pd_demodulation_selection_duration.setText(
        _sa_pd_demodulation_format_duration(metadata.get("duration_s"))
    )
    ui.label2_sa_pd_demodulation_selection_size.setText(
        _sa_pd_demodulation_format_size(int(metadata.get("size_bytes") or 0)) if metadata else "—"
    )
    ui.label2_sa_pd_demodulation_selection_samples.setText(
        f"{int(metadata.get('sample_count') or 0):,}" if metadata else "—"
    )


def _pd_metadata_controls_changed(dashboard: QtCore.QObject):
    """Apply manually corrected sample metadata to the active file and plots.

    Editing datatype changes how many samples exist. Editing sample rate changes
    the time axis and all symbol estimates. In either case the existing candidate
    and region selection must be invalidated.
    """
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    if not _sa_pd_demodulation_file_is_ready(metadata):
        return
    ui = dashboard.ui
    sample_rate_msps = float(ui.doubleSpinBox_sa_pd_demodulation_selection_sample_rate.value())
    frequency_mhz = float(ui.doubleSpinBox_sa_pd_demodulation_selection_center_frequency.value())
    data_type = str(ui.comboBox_sa_pd_demodulation_selection_data_type.currentText() or "")
    if data_type not in _FISSURE_TYPE_MAP:
        return
    sample_rate_hz = sample_rate_msps * 1e6 if sample_rate_msps > 0.0 else None
    center_frequency_hz = frequency_mhz * 1e6 if frequency_mhz > 0.0 else None
    dtype, is_complex, interleaved = _FISSURE_TYPE_MAP[data_type]
    bytes_per_sample = dtype.itemsize * (2 if interleaved else 1)
    size_bytes = int(metadata.get("size_bytes") or 0)
    sample_count = size_bytes // bytes_per_sample
    if (
        sample_rate_hz == metadata.get("sample_rate_hz")
        and center_frequency_hz == metadata.get("center_frequency_hz")
        and data_type == metadata.get("data_type")
    ):
        return
    metadata = dict(metadata)
    metadata.update(
        data_type=data_type,
        data_type_assumed=False,
        dtype=dtype,
        is_complex=bool(is_complex),
        interleaved=bool(interleaved),
        bytes_per_sample=bytes_per_sample,
        sample_rate_hz=sample_rate_hz,
        center_frequency_hz=center_frequency_hz,
        sample_count=sample_count,
        duration_s=(sample_count / sample_rate_hz if sample_rate_hz else None),
    )
    dashboard.sa_pd_demodulation_file_metadata = metadata
    dashboard.sa_pd_demodulation_metadata_revision = (
        getattr(dashboard, "sa_pd_demodulation_metadata_revision", 0) + 1
    )
    _sa_pd_demodulation_set_file_metadata(dashboard, metadata)
    _pd_full_file(dashboard)
    ui.label2_sa_pd_demodulation_results_status.setText(
        "Ready" if sample_rate_hz else "Enter sample rate to demodulate"
    )


def _sa_pd_demodulation_file_is_ready(metadata: dict) -> bool:
    """Return True only when the selected evidence resolves to a local IQ data file."""
    path = str((metadata or {}).get("path") or "").strip()
    return bool(path and os.path.isfile(path) and not path.lower().endswith(".zip"))


def _update_sa_pd_demodulation_navigation_controls(dashboard: QtCore.QObject):
    """Disable empty/boundary Artifact navigation controls and respect action locking."""
    locked = bool(getattr(dashboard, "sa_pd_demodulation_action_running", False))
    artifact_mode = getattr(dashboard, "sa_pd_demodulation_source", "artifact") == "artifact"

    artifact_combo = dashboard.ui.comboBox_sa_pd_demodulation_selection_artifact
    artifact_count = artifact_combo.count()
    artifact_index = artifact_combo.currentIndex()
    artifact_available = artifact_mode and not locked and artifact_count > 0
    artifact_combo.setEnabled(artifact_available)
    dashboard.ui.pushButton_sa_pd_demodulation_selection_artifact_left.setEnabled(
        artifact_available and artifact_index > 0
    )
    dashboard.ui.pushButton_sa_pd_demodulation_selection_artifact_right.setEnabled(
        artifact_available and 0 <= artifact_index < artifact_count - 1
    )

    file_combo = dashboard.ui.comboBox_sa_pd_demodulation_selection_file
    file_count = file_combo.count()
    file_index = file_combo.currentIndex()
    file_available = artifact_available and file_count > 0
    file_combo.setEnabled(file_available)
    dashboard.ui.pushButton_sa_pd_demodulation_selection_file_left.setEnabled(
        file_available and file_index > 0
    )
    dashboard.ui.pushButton_sa_pd_demodulation_selection_file_right.setEnabled(
        file_available and 0 <= file_index < file_count - 1
    )


def _sa_pd_demodulation_selection_is_seconds(dashboard: QtCore.QObject) -> bool:
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    return bool(_sa_pd_demodulation_float(metadata.get("sample_rate_hz")))


def _sa_pd_demodulation_selection_to_samples(dashboard: QtCore.QObject, selection: tuple) -> tuple:
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    total = int(metadata.get("sample_count") or 0)
    sample_rate = _sa_pd_demodulation_float(metadata.get("sample_rate_hz"))
    start, end = selection
    if sample_rate:
        start_sample = int(round(float(start) * sample_rate))
        end_sample = int(round(float(end) * sample_rate))
    else:
        start_sample = int(round(float(start)))
        end_sample = int(round(float(end)))
    start_sample = max(0, min(start_sample, total))
    end_sample = max(start_sample + 1, min(end_sample, total)) if total > 0 else 0
    return start_sample, end_sample


def _sa_pd_demodulation_set_local_file_path(dashboard: QtCore.QObject, filepath: str):
    """Retain a local file path while displaying only its filename."""
    path = os.path.abspath(str(filepath or "").strip()) if filepath else ""
    dashboard.sa_pd_demodulation_local_file_path = path

    editor = dashboard.ui.textEdit_sa_pd_demodulation_selection_file_name
    editor.setPlainText(os.path.basename(path) if path else "")
    editor.setToolTip(path)


def _update_sa_pd_demodulation_source_buttons(dashboard: QtCore.QObject):
    """Keep the active evidence source selected but non-clickable."""
    artifact_selected = (
        getattr(dashboard, "sa_pd_demodulation_source", "artifact") == "artifact"
    )

    artifact_button = dashboard.ui.pushButton_sa_pd_demodulation_selection_source_artifact
    local_button = dashboard.ui.pushButton_sa_pd_demodulation_selection_source_local_file

    artifact_button.setChecked(artifact_selected)
    local_button.setChecked(not artifact_selected)

    artifact_button.setEnabled(not artifact_selected)
    local_button.setEnabled(artifact_selected)
    _update_sa_pd_demodulation_navigation_controls(dashboard)


def _slotSA_PDDemodulationSourceArtifactClicked(dashboard: QtCore.QObject):
    """Switch to Artifact evidence."""
    if getattr(dashboard, "sa_pd_demodulation_source", "") == "artifact":
        _update_sa_pd_demodulation_source_buttons(dashboard)
        dashboard.ui.stackedWidget_sa_pd_demodulation_selection_source.setCurrentIndex(0)
        return

    dashboard.sa_pd_demodulation_source = "artifact"
    dashboard.ui.stackedWidget_sa_pd_demodulation_selection_source.setCurrentIndex(0)
    _update_sa_pd_demodulation_source_buttons(dashboard)
    _refresh_sa_pd_demodulation_artifacts(dashboard)


def _slotSA_PDDemodulationSourceLocalFileClicked(dashboard: QtCore.QObject):
    """Switch to Local File evidence."""
    if getattr(dashboard, "sa_pd_demodulation_source", "") == "local":
        _update_sa_pd_demodulation_source_buttons(dashboard)
        dashboard.ui.stackedWidget_sa_pd_demodulation_selection_source.setCurrentIndex(1)
        return

    dashboard.sa_pd_demodulation_source = "local"
    dashboard.ui.stackedWidget_sa_pd_demodulation_selection_source.setCurrentIndex(1)
    _update_sa_pd_demodulation_source_buttons(dashboard)

    dashboard.sa_pd_demodulation_artifact_id = ""
    dashboard.sa_pd_demodulation_file_id = ""

    path = str(
        getattr(dashboard, "sa_pd_demodulation_local_file_path", "") or ""
    ).strip()

    if path and os.path.isfile(path):
        _sa_pd_demodulation_load_file(dashboard, path)
    else:
        _sa_pd_demodulation_clear_file(dashboard)


def _slotSA_PDDemodulationSoiChanged(dashboard: QtCore.QObject):
    if getattr(dashboard, "sa_pd_demodulation_source", "artifact") == "artifact":
        _refresh_sa_pd_demodulation_artifacts(dashboard)
    else:
        metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
        path = str(metadata.get("path") or "")
        if path and os.path.isfile(path):
            _sa_pd_demodulation_load_file(dashboard, path)
    


def _slotSA_PDDemodulationArtifactChanged(dashboard: QtCore.QObject):
    artifact_id, _record = _sa_pd_demodulation_selected_artifact(dashboard)
    dashboard.sa_pd_demodulation_artifact_id = artifact_id
    _populate_sa_pd_demodulation_files(dashboard)
    _update_sa_pd_demodulation_navigation_controls(dashboard)


def _slotSA_PDDemodulationPreviousArtifactClicked(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_sa_pd_demodulation_selection_artifact
    if combo.count() > 0:
        combo.setCurrentIndex(max(0, combo.currentIndex() - 1))


def _slotSA_PDDemodulationNextArtifactClicked(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_sa_pd_demodulation_selection_artifact
    if combo.count() > 0:
        combo.setCurrentIndex(min(combo.count() - 1, combo.currentIndex() + 1))


def _slotSA_PDDemodulationPreviousFileClicked(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_sa_pd_demodulation_selection_file
    if combo.count() > 0:
        combo.setCurrentIndex(max(0, combo.currentIndex() - 1))


def _slotSA_PDDemodulationNextFileClicked(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_sa_pd_demodulation_selection_file
    if combo.count() > 0:
        combo.setCurrentIndex(min(combo.count() - 1, combo.currentIndex() + 1))


def _slotSA_PDDemodulationLocalFileSelectClicked(
    dashboard: QtCore.QObject,
):
    """Choose a local PDDemodulation data file and display only its basename."""
    current = str(
        getattr(
            dashboard,
            "sa_pd_demodulation_local_file_path",
            "",
        )
        or ""
    ).strip()

    directory = (
        os.path.dirname(current)
        if current
        else fissure.utils.IQ_RECORDINGS_DIR
    )

    known_extensions = (
        ".sigmf-meta",
        *_PD_DEMODULATION_DATA_EXTENSIONS,
    )
    known_patterns = " ".join(
        f"*{extension}"
        for extension in known_extensions
    )

    filepath, _selected_filter = QtWidgets.QFileDialog.getOpenFileName(
        dashboard,
        "Select Demodulation File",
        directory,
        (
            "All Files (*);;"
            f"Known Signal Data ({known_patterns})"
        ),
    )

    if not filepath:
        return

    if filepath.lower().endswith(".sigmf-meta"):
        candidate = filepath[:-11] + ".sigmf-data"

        if os.path.isfile(candidate):
            filepath = candidate

    _sa_pd_demodulation_set_local_file_path(
        dashboard,
        filepath,
    )
    dashboard.sa_pd_demodulation_artifact_id = ""
    dashboard.sa_pd_demodulation_file_id = ""
    _sa_pd_demodulation_load_file(
        dashboard,
        filepath,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_PDDemodulationPrepareClicked(dashboard: QtCore.QObject):
    artifact_id, record = _sa_pd_demodulation_selected_artifact(dashboard)
    if not artifact_id:
        return
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    local_path = controller.get_local_path(artifact_id) if controller is not None else None

    if not local_path:
        dashboard.sa_pd_demodulation_prepare_artifact_id = artifact_id
        dashboard.ui.pushButton_sa_pd_demodulation_selection_prepare.setEnabled(False)
        dashboard.ui.pushButton_sa_pd_demodulation_selection_prepare.setText("Downloading...")
        try:
            await dashboard.backend.requestDashboardArtifactDownload(artifact_id)
        except Exception as error:
            dashboard.sa_pd_demodulation_prepare_artifact_id = ""
            _update_sa_pd_demodulation_prepare_button(dashboard)
            await Qt5.async_ok_dialog(dashboard, f"Unable to download artifact.\n\n{error}")
        return

    if os.path.isfile(local_path) and local_path.lower().endswith(".zip"):
        destination = _sa_pd_demodulation_extracted_root(dashboard, artifact_id)
        dashboard.ui.pushButton_sa_pd_demodulation_selection_prepare.setEnabled(False)
        dashboard.ui.pushButton_sa_pd_demodulation_selection_prepare.setText("Preparing...")
        loop = asyncio.get_event_loop()
        try:
            if os.path.isdir(destination):
                shutil.rmtree(destination)
            await loop.run_in_executor(None, _sa_pd_demodulation_safe_extract, local_path, destination)
        except Exception as error:
            await Qt5.async_ok_dialog(dashboard, f"Unable to prepare artifact.\n\n{error}")
        finally:
            _populate_sa_pd_demodulation_files(dashboard)
        return

    _populate_sa_pd_demodulation_files(dashboard)


def refresh_sa_pd_demodulation_artifact_state(dashboard: QtCore.QObject, artifact_id: str = ""):
    """Refresh PDDemodulation after Artifact metadata or transfer state changes."""
    current_id, _record = _sa_pd_demodulation_selected_artifact(dashboard)
    preferred = str(artifact_id or current_id or "").strip()
    if getattr(dashboard, "sa_pd_demodulation_source", "artifact") == "artifact":
        _refresh_sa_pd_demodulation_artifacts(dashboard, preferred_artifact_id=preferred)


def handle_sa_pd_demodulation_artifact_metadata(dashboard: QtCore.QObject, node_uid: str = "", artifacts: list = None):
    """Refresh the PDDemodulation Artifact selector after canonical metadata arrives."""
    if getattr(dashboard, "sa_pd_demodulation_source", "artifact") != "artifact":
        return
    _refresh_sa_pd_demodulation_artifacts(dashboard)


def handle_sa_pd_demodulation_artifact_download_complete(dashboard: QtCore.QObject, artifact_id: str):
    """Refresh PDDemodulation only for the Artifact download it explicitly requested."""
    pending = str(
        getattr(dashboard, "sa_pd_demodulation_prepare_artifact_id", "")
        or ""
    ).strip()
    completed = str(artifact_id or "").strip()

    if not pending or pending != completed:
        return

    dashboard.sa_pd_demodulation_prepare_artifact_id = ""
    refresh_sa_pd_demodulation_artifact_state(dashboard, completed)


class _PDDemodulationCanvas(FigureCanvasQTAgg):
    """Matplotlib plot embedded into a fixed Designer plot frame."""

    def __init__(self, parent):
        self.fig = Figure(dpi=100)
        self.axes = self.fig.add_subplot(111)
        self.fig.subplots_adjust(left=0.08, right=0.98, bottom=0.19, top=0.94)
        super().__init__(self.fig)
        self.setParent(parent)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)


def _pd_mount_plot(frame, navigation_toolbar=False, dashboard=None, toolbar_role="signal"):
    """Mount the plot and its navigation toolbar in separate, nonoverlapping Qt rows."""
    canvas = _PDDemodulationCanvas(frame)
    layout = frame.layout()
    if layout is None:
        layout = QtWidgets.QVBoxLayout(frame)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)

    if navigation_toolbar:
        # These are figure margins, not toolbar placement. Leave the currently
        # working plot axes and tick-label geometry alone.
        bottom = 0.20 if toolbar_role == "signal" else 0.15
        canvas.fig.subplots_adjust(left=0.105, right=0.985, bottom=bottom, top=0.925)

        toolbar = NavigationToolbar2QT(canvas, frame)
        toolbar.setObjectName(f"toolbar_sa_pd_demodulation_{toolbar_role}")
        toolbar.setIconSize(QtCore.QSize(16, 16))
        toolbar.setMovable(False)
        toolbar.setFloatable(False)

        names = {
            "Home": "home.png", "Back": "back.png", "Forward": "forward.png",
            "Pan": "move.png", "Zoom": "zoom_to_rect.png", "Save": "filesave.png",
        }
        for action in toolbar.actions():
            title = str(action.text() or "")
            if title in {"Subplots", "Customize"}:
                action.setVisible(False)
            elif title in names:
                path = os.path.join(fissure.utils.UI_DIR, "Icons", names[title])
                if os.path.isfile(path):
                    action.setIcon(QtGui.QIcon(path))

        toolbar.setFixedHeight(30)
        toolbar.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed
        )
        layout.addWidget(toolbar, 0)
        layout.addSpacing(5)
        if dashboard is not None:
            setattr(dashboard, f"sa_pd_demodulation_{toolbar_role}_toolbar", toolbar)
    else:
        canvas.fig.subplots_adjust(left=0.018, right=0.982, bottom=0.255, top=0.96)

    layout.addWidget(canvas, 1)
    if navigation_toolbar:
        # Keep the interactive toolbar above the canvas in Qt's sibling stack.
        toolbar.raise_()
    return canvas


def _pd_style_axes(dashboard, canvas):
    """Use Inspection's theme-aware Matplotlib treatment for every PD plot."""
    _background, face, text, grid, _i_color, _q_color, _if_color = _pd_theme(dashboard)
    canvas.fig.set_facecolor(face)
    canvas.axes.set_facecolor(face)
    canvas.axes.set_axisbelow(True)
    canvas.axes.tick_params(axis="both", colors=text, labelsize=8, length=3, pad=1)
    canvas.axes.xaxis.label.set_color(text)
    canvas.axes.yaxis.label.set_color(text)
    canvas.axes.title.set_color(text)
    for spine in canvas.axes.spines.values():
        spine.set_color(grid)
        spine.set_linewidth(0.8)
    canvas.axes.grid(True, color=grid, alpha=0.45, linewidth=0.6)


def _pd_theme(dashboard):
    """Inspection-compatible palette: background, axes face, text, grid, I, Q, IF."""
    settings = getattr(dashboard.backend, "settings", {}) or {}
    background = str(settings.get("color2") or "#FBFBFB")
    face = str(settings.get("color5") or "#FFFFFF")
    text = str(settings.get("color4") or "#000000")
    mode = str(settings.get("color_mode", "") or "")
    if "Dark" in mode:
        grid = "#56616f"
        i_color, q_color, if_color = "#2f8fe8", "#7aa35a", "#c58cf5"
    elif "Custom" in mode:
        grid = str(settings.get("color3") or "#31577d")
        i_color, q_color, if_color = "#1f77b4", "#6f8f4e", "#a46cc5"
    else:
        grid = "#b8c0ca"
        i_color, q_color, if_color = "#1f77b4", "#7aa35a", "#8c4ab1"
    return background, face, text, grid, i_color, q_color, if_color


def restyle_sa_pd_demodulation_canvases(dashboard):
    """Refresh all three plots after a FISSURE theme change without rerunning DSP."""
    if getattr(dashboard, "sa_pd_demodulation_overview_canvas", None) is None:
        return
    signal_canvas = getattr(dashboard, "sa_pd_demodulation_signal_canvas", None)
    preserve_signal = bool(signal_canvas is not None and signal_canvas.axes.has_data())
    signal_xlim = signal_canvas.axes.get_xlim() if preserve_signal else None
    signal_ylim = signal_canvas.axes.get_ylim() if preserve_signal else None
    _pd_draw_overview(dashboard)
    _pd_draw_signal(dashboard)
    if preserve_signal and signal_canvas.axes.has_data():
        signal_canvas.axes.set_xlim(signal_xlim)
        signal_canvas.axes.set_ylim(signal_ylim)
        signal_canvas.draw_idle()
    _pd_draw_output(dashboard, preserve_view=True)


def _pd_clear_plot(dashboard, canvas):
    """Keep the empty plot the same color as Inspection's empty plot."""
    for extra_axes in list(canvas.fig.axes[1:]):
        canvas.fig.delaxes(extra_axes)
    canvas.axes.clear()
    _pd_style_axes(dashboard, canvas)
    canvas.axes.set_xticks([])
    canvas.axes.set_yticks([])
    canvas.axes.set_xlabel("")
    canvas.axes.set_ylabel("")
    canvas.axes.grid(False)
    canvas.draw_idle()


def _pd_selection_units(dashboard):
    return 'seconds' if _sa_pd_demodulation_selection_is_seconds(dashboard) else 'samples'


def _pd_draw_overview(dashboard):
    """Render a compact overview with visible time ticks and little wasted height."""
    canvas = dashboard.sa_pd_demodulation_overview_canvas
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    if not _sa_pd_demodulation_file_is_ready(metadata):
        _pd_clear_plot(dashboard, canvas)
        return
    total = int(metadata.get("sample_count") or 0)
    if total <= 0:
        _pd_clear_plot(dashboard, canvas)
        return
    step = max(1, int(math.ceil(total / OVERVIEW_POINTS)))
    indices = np.arange(0, total, step, dtype=np.int64)[:OVERVIEW_POINTS]
    data = _sa_pd_demodulation_read_indices(metadata, indices)
    if not data.size:
        _pd_clear_plot(dashboard, canvas)
        return
    indices = indices[:data.size]
    rate = _sa_pd_demodulation_float(metadata.get("sample_rate_hz"))
    x = indices / rate if rate else indices
    y = np.abs(data)

    _background, _face, text, grid, i_color, _q_color, _if_color = _pd_theme(dashboard)
    canvas.axes.clear()
    canvas.fig.subplots_adjust(left=0.018, right=0.982, bottom=0.255, top=0.96)
    _pd_style_axes(dashboard, canvas)
    canvas.axes.plot(x, y, linewidth=0.9, color=i_color)
    canvas.axes.fill_between(x, 0.0, y, color=i_color, alpha=0.08)
    start, end = getattr(dashboard, "sa_pd_demodulation_pending_selection", (0, 0))
    if end > start:
        canvas.axes.axvspan(start, end, color=i_color, alpha=0.18)
        canvas.axes.axvline(start, color=i_color, linewidth=0.8)
        canvas.axes.axvline(end, color=i_color, linewidth=0.8)
    canvas.axes.set_yticks([])
    canvas.axes.set_ylabel("")
    canvas.axes.set_xlabel("")
    canvas.axes.xaxis.set_major_locator(MaxNLocator(nbins=6))
    canvas.axes.tick_params(axis="x", colors=text, labelsize=7, length=2, pad=1)
    canvas.axes.grid(False)
    canvas.axes.grid(True, axis="x", color=grid, alpha=0.40, linewidth=0.5)
    if len(x) > 1:
        canvas.axes.set_xlim(x[0], x[-1])
    canvas.draw_idle()


def _pd_draw_signal(dashboard):
    """Render the selected signal trace using the current FISSURE theme."""
    canvas = dashboard.sa_pd_demodulation_signal_canvas
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    if not _sa_pd_demodulation_file_is_ready(metadata):
        _pd_clear_plot(dashboard, canvas)
        return
    start, end = _sa_pd_demodulation_selection_to_samples(
        dashboard, dashboard.sa_pd_demodulation_active_selection
    )
    data, indices = _sa_pd_demodulation_read_display_samples(metadata, start, end, VIEW_POINTS)
    if not data.size:
        _pd_clear_plot(dashboard, canvas)
        return
    rate = _sa_pd_demodulation_float(metadata.get("sample_rate_hz"))
    x = indices / rate if rate else indices
    _background, face, text, grid, i_color, q_color, if_color = _pd_theme(dashboard)
    canvas.axes.clear()
    _pd_style_axes(dashboard, canvas)
    ui = dashboard.ui
    if ui.radioButton_sa_pd_demodulation_signal_iq.isChecked():
        canvas.axes.plot(x, data.real, label="I", color=i_color, linewidth=0.8)
        if np.iscomplexobj(data):
            canvas.axes.plot(x, data.imag, label="Q", color=q_color, linewidth=0.8)
        canvas.axes.set_ylabel("Amplitude")
        legend = canvas.axes.legend(fontsize=7, loc="upper right", facecolor=face, edgecolor=grid)
        if legend is not None:
            for legend_text in legend.get_texts():
                legend_text.set_color(text)
    elif ui.radioButton_sa_pd_demodulation_signal_if.isChecked():
        if not np.iscomplexobj(data):
            canvas.axes.text(0.5, 0.5, "IF requires complex IQ samples",
                             color=text, ha="center", va="center",
                             transform=canvas.axes.transAxes)
        elif not rate:
            canvas.axes.text(0.5, 0.5, "Enter sample rate for instantaneous frequency",
                             color=text, ha="center", va="center",
                             transform=canvas.axes.transAxes)
        elif len(data) > 1:
            preceding = _sa_pd_demodulation_read_indices(metadata, indices[1:] - 1)
            instantaneous_hz = np.angle(data[1:] * np.conj(preceding)) * rate / (2 * np.pi)
            canvas.axes.plot(x[1:], instantaneous_hz, color=if_color, linewidth=0.8)
        canvas.axes.set_ylabel("Frequency (Hz)")
    else:
        canvas.axes.plot(x, np.abs(data), color=i_color, linewidth=0.85)
        canvas.axes.set_ylabel("Magnitude")
    # The time/sample ticks already convey the horizontal position.
    # Suppress the axis title so it cannot be clipped by the compact frame.
    canvas.axes.set_xlabel("")
    if len(x) > 1:
        canvas.axes.set_xlim(x[0], x[-1])
    ui.label2_sa_pd_demodulation_signal_samples.setText(f"{end - start:,} samples")
    canvas.draw_idle()


def _pd_overview_press(dashboard, event):
    if event.inaxes != dashboard.sa_pd_demodulation_overview_canvas.axes or event.xdata is None:
        return
    dashboard.sa_pd_demodulation_drag_start = float(event.xdata)


def _pd_overview_release(dashboard, event):
    first = getattr(dashboard, "sa_pd_demodulation_drag_start", None)
    dashboard.sa_pd_demodulation_drag_start = None
    if first is None or event.xdata is None:
        return
    start, end = sorted((first, float(event.xdata)))
    if end <= start:
        return
    dashboard.sa_pd_demodulation_pending_selection = (start, end)
    _pd_update_selection_label(dashboard)
    _pd_draw_overview(dashboard)
    _pd_update_available_controls(dashboard)


def _pd_update_selection_label(dashboard):
    start, end = getattr(dashboard, "sa_pd_demodulation_pending_selection", (0, 0))
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    if not metadata or end <= start:
        label = "—"
    elif _sa_pd_demodulation_selection_is_seconds(dashboard):
        label = f"{start:.6g}–{end:.6g} s"
    else:
        label = f"{int(start):,}–{int(end):,} samples"
    dashboard.ui.label2_sa_pd_demodulation_signal_selection.setText(label)


def _pd_zoom_selection(dashboard):
    if not getattr(dashboard, "sa_pd_demodulation_file_metadata", None):
        return
    start, end = dashboard.sa_pd_demodulation_pending_selection
    if end <= start:
        return
    dashboard.sa_pd_demodulation_active_selection = (start, end)
    _pd_update_selection_label(dashboard)
    _pd_draw_signal(dashboard)
    _pd_clear_result(dashboard)


def _pd_full_file(dashboard):
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    if not metadata:
        return
    rate = _sa_pd_demodulation_float(metadata.get("sample_rate_hz"))
    count = int(metadata.get("sample_count") or 0)
    end = count / rate if rate else float(count)
    dashboard.sa_pd_demodulation_pending_selection = (0.0, end)
    dashboard.sa_pd_demodulation_active_selection = (0.0, end)
    _pd_update_selection_label(dashboard)
    _pd_draw_overview(dashboard)
    _pd_draw_signal(dashboard)
    _pd_clear_result(dashboard)


def _pd_reset_selection(dashboard):
    dashboard.sa_pd_demodulation_pending_selection = dashboard.sa_pd_demodulation_active_selection
    _pd_draw_overview(dashboard)


def _sa_pd_demodulation_clear_file(dashboard):
    dashboard.sa_pd_demodulation_file_metadata = {}
    dashboard.sa_pd_demodulation_file_id = ""
    dashboard.sa_pd_demodulation_active_selection = (0, 0)
    dashboard.sa_pd_demodulation_pending_selection = (0, 0)
    dashboard.sa_pd_demodulation_metadata_revision = (
        getattr(dashboard, "sa_pd_demodulation_metadata_revision", 0) + 1
    )
    _sa_pd_demodulation_set_file_metadata(dashboard)
    dashboard.ui.label2_sa_pd_demodulation_signal_samples.setText("—")
    _pd_update_selection_label(dashboard)
    _pd_update_inspection_button(dashboard)
    _pd_draw_overview(dashboard)
    _pd_draw_signal(dashboard)
    _pd_clear_result(dashboard)


def _sa_pd_demodulation_load_file(dashboard, filepath, file_record=None, artifact_record=None):
    filepath = os.path.abspath(str(filepath or "").strip())
    if filepath.lower().endswith(".sigmf-meta"):
        paired = filepath[:-11] + ".sigmf-data"
        if os.path.isfile(paired):
            filepath = paired
    if not filepath or not os.path.isfile(filepath):
        _sa_pd_demodulation_clear_file(dashboard)
        return
    metadata = _sa_pd_demodulation_build_file_metadata(
        dashboard, filepath, file_record, artifact_record
    )
    dashboard.sa_pd_demodulation_file_metadata = metadata
    dashboard.sa_pd_demodulation_file_id = str(
        (file_record or {}).get("file_id") or (file_record or {}).get("id") or ""
    )
    dashboard.sa_pd_demodulation_metadata_revision = (
        getattr(dashboard, "sa_pd_demodulation_metadata_revision", 0) + 1
    )
    rate = _sa_pd_demodulation_float(metadata.get("sample_rate_hz"))
    count = int(metadata.get("sample_count") or 0)
    end = count / rate if rate else float(count)
    dashboard.sa_pd_demodulation_pending_selection = (0.0, end)
    dashboard.sa_pd_demodulation_active_selection = (0.0, end)
    _sa_pd_demodulation_set_file_metadata(dashboard, metadata)
    _pd_update_inspection_button(dashboard)
    _pd_update_selection_label(dashboard)
    _pd_draw_overview(dashboard)
    _pd_draw_signal(dashboard)
    _pd_clear_result(dashboard)
    # Reveal live tuning for each newly loaded file. A manual collapse remains
    # in effect until another file is selected; the no-file state stays closed.
    dashboard.ui.toolButton_sa_pd_demodulation_settings.setChecked(True)
    dashboard.ui.label2_sa_pd_demodulation_results_status.setText(
        "Ready" if rate else "Enter sample rate to demodulate"
    )


def _slotSA_PDDemodulationFileChanged(dashboard):
    _update_sa_pd_demodulation_navigation_controls(dashboard)
    context = dashboard.ui.comboBox_sa_pd_demodulation_selection_file.currentData(QtCore.Qt.UserRole)
    if not isinstance(context, dict):
        _sa_pd_demodulation_clear_file(dashboard)
        return
    artifact_id, artifact_record = _sa_pd_demodulation_selected_artifact(dashboard)
    dashboard.sa_pd_demodulation_artifact_id = artifact_id
    dashboard.sa_pd_demodulation_file_id = str(context.get('file_id') or context.get('id') or '')
    role = _sa_pd_demodulation_file_role(context)
    name = _sa_pd_demodulation_file_name(context)
    local_path = str(context.get('local_path') or '').strip()
    if role != 'bundle' and not name.lower().endswith('.zip') and local_path and os.path.isfile(local_path):
        _sa_pd_demodulation_load_file(dashboard, local_path, context, artifact_record)
        return
    _sa_pd_demodulation_clear_file(dashboard)
    # Show metadata for a remote/unprepared artifact without treating it as a local file.
    placeholder = _sa_pd_demodulation_build_file_metadata(
        dashboard, str(context.get('path') or context.get('relative_path') or name),
        context, artifact_record
    )
    placeholder['path'] = ''
    _sa_pd_demodulation_set_file_metadata(dashboard, placeholder)


def _pd_clear_result(dashboard):
    dashboard.sa_pd_demodulation_result = None
    dashboard.sa_pd_demodulation_estimate = None
    _pd_sync_live_sliders(dashboard)
    ui = dashboard.ui
    ui.plainTextEdit_sa_pd_demodulation_bits.setPlainText('')
    ui.label2_sa_pd_demodulation_results_status.setText('Select input')
    ui.label2_sa_pd_demodulation_results_bits.setText('—')
    ui.label2_sa_pd_demodulation_results_processing_time.setText('—')
    for name in ('modulation', 'symbol_rate', 'deviation', 'frequency_offset', 'confidence'):
        widget = getattr(ui, 'label2_sa_pd_demodulation_output_parameters_' + name, None)
        if widget is not None:
            widget.setText('—')
    _pd_draw_output(dashboard)


def _pd_method_settings(dashboard):
    """Configure the three method-specific rows without erasing the previous plot."""
    ui = dashboard.ui
    method = str(ui.comboBox_sa_pd_demodulation_settings_method.currentData() or "auto")
    configuration = {
        "auto": [("Symbol Rate", "sym/s", 0.01, 1e7, 9600.0),
                 ("Frequency Offset", "Hz", -1e9, 1e9, 0.0),
                 ("Threshold", "linear", 0.0, 1e9, 0.0)],
        "ook": [("Symbol Rate", "sym/s", 0.01, 1e7, 9600.0),
                ("Threshold", "linear", 0.0, 1e9, 0.0),
                ("Timing Offset", "symbols", -0.49, 0.49, 0.0)],
        "fsk": [("Symbol Rate", "sym/s", 0.01, 1e7, 9600.0),
                ("Frequency Offset", "Hz", -1e9, 1e9, 0.0),
                ("Timing Offset", "symbols", -0.49, 0.49, 0.0)],
    }
    result = getattr(dashboard, "sa_pd_demodulation_result", None)
    for i, (label, unit, minimum, maximum, default) in enumerate(configuration[method], 1):
        getattr(ui, f"label2_sa_pd_demodulation_settings_item{i}").setText(f"{label}:")
        spinner = getattr(ui, f"doubleSpinBox_sa_pd_demodulation_settings_item{i}")
        check = getattr(ui, f"checkBox_sa_pd_demodulation_settings_item{i}")
        combo = getattr(ui, f"comboBox_sa_pd_demodulation_settings_item{i}")
        for widget in (spinner, check, combo):
            widget.blockSignals(True)
        spinner.setRange(minimum, maximum)
        spinner.setDecimals(4 if label == 'Timing Offset' else 3)
        if result and (method == result.get("method")):
            if i == 1:
                default = result.get("symbol_rate", default)
            elif i == 2:
                default = result.get("threshold", default)
            elif i == 3:
                default = result.get("timing_offset", default)
        spinner.setValue(float(default))
        check.setChecked(True)
        spinner.setEnabled(False)
        combo.clear()
        combo.addItem(unit, unit)
        for widget in (spinner, check, combo):
            widget.blockSignals(False)
    if result is not None:
        ui.label2_sa_pd_demodulation_results_status.setText(
            "Method changed; last result retained"
        )
        ui.label2_sa_pd_demodulation_results_status.setToolTip(
            "Press Demodulate to calculate the newly selected modulation."
        )


def _pd_current_parameters(dashboard):
    ui = dashboard.ui
    checks = [getattr(ui, f'checkBox_sa_pd_demodulation_settings_item{i}') for i in (1, 2, 3)]
    spins = [getattr(ui, f'doubleSpinBox_sa_pd_demodulation_settings_item{i}') for i in (1, 2, 3)]
    method = str(ui.comboBox_sa_pd_demodulation_settings_method.currentData() or 'auto')
    return dict(
        method=method,
        symbol_rate=None if checks[0].isChecked() else float(spins[0].value()),
        parameter_2=None if checks[1].isChecked() else float(spins[1].value()),
        timing_offset=None if method == 'auto' or checks[2].isChecked() else float(spins[2].value()),
        parameter_3=None if method != 'auto' or checks[2].isChecked() else float(spins[2].value()),
        # Internal auto behavior; no longer exposed as obscure controls.
        smoothing=5, min_samples_per_symbol=4, ignore_quiet=True,
    )



class _PDRecoveryThread(QtCore.QThread):
    completed = QtCore.pyqtSignal(object)

    def __init__(self, metadata, start, end, parameters, revision, mode, parent=None):
        super().__init__(parent)
        self.metadata = metadata
        self.start_sample = start
        self.end_sample = end
        self.parameters = parameters
        self.revision = revision
        self.mode = mode

    def run(self):
        try:
            data = _sa_pd_demodulation_read_samples(
                self.metadata, self.start_sample, self.end_sample
            )
            rate = float(self.metadata["sample_rate_hz"])
            if self.mode == "estimate":
                result = estimate_parameters(data, rate, self.parameters)
            else:
                result = recover_candidate(data, rate, self.parameters)
            result["start_sample"] = self.start_sample
            self.completed.emit((result, None))
        except Exception as error:
            self.completed.emit((None, str(error)))


def _pd_estimate(dashboard):
    """Estimate possible modulation and parameters, without recovering bits."""
    _pd_launch_worker(dashboard, "estimate")


def _pd_start(dashboard):
    """Recover candidate bits; estimator is used internally when needed."""
    _pd_launch_worker(dashboard, "demodulate")


def _pd_finish(dashboard, payload):
    """Apply either a fresh estimate or a recovered candidate to the UI.

    Estimate restores the automatic tuning position. If a matching result is
    already cached, resample its discriminator without rerunning demodulation.
    """
    worker = getattr(dashboard, "sa_pd_demodulation_worker", None)
    dashboard.sa_pd_demodulation_worker = None
    ui = dashboard.ui
    ui.pushButton_sa_pd_demodulation_settings_demodulate.setEnabled(True)
    ui.pushButton_sa_pd_demodulation_settings_estimate.setEnabled(True)
    result, error = payload

    if worker is not None and (
        worker.revision != getattr(dashboard, "sa_pd_demodulation_metadata_revision", 0)
        or worker.metadata.get("path") != (
            getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
        ).get("path")
        or (worker.start_sample, worker.end_sample) != _sa_pd_demodulation_selection_to_samples(
            dashboard, dashboard.sa_pd_demodulation_active_selection
        )
        or worker.parameters != _pd_current_parameters(dashboard)
    ):
        ui.label2_sa_pd_demodulation_results_status.setText("Input changed; result discarded")
        return
    if error:
        ui.label2_sa_pd_demodulation_results_status.setText("Inconclusive (hover for reason)")
        ui.label2_sa_pd_demodulation_results_status.setToolTip(str(error))
        return

    estimating = worker is not None and worker.mode == "estimate"
    rate = result.get("symbol_rate")
    deviation = result.get("frequency_deviation")
    offset = result.get("frequency_offset")

    if estimating:
        dashboard.sa_pd_demodulation_estimate = result
        timer = getattr(dashboard, "sa_pd_demodulation_live_timer", None)
        if timer is not None:
            timer.stop()

        # The original discriminator/threshold data remains available even
        # after live adjustments; only the sampling grid and bit decisions
        # need to be restored to the new estimates.
        existing = getattr(dashboard, "sa_pd_demodulation_result", None)
        restored = None
        level = result.get("threshold")
        phase = result.get("timing_offset")
        phase = float(phase) if phase is not None else 0.0
        if (
            existing is not None
            and existing.get("method") == result.get("method")
            and rate is not None and level is not None
            and np.isfinite(rate) and float(rate) > 0
            and np.isfinite(level) and np.isfinite(phase)
        ):
            try:
                restored = retime_cached_candidate(
                    existing, float(rate), float(level), phase
                )
            except (ValueError, KeyError, TypeError):
                restored = None

        if restored is not None:
            dashboard.sa_pd_demodulation_result = restored
            _pd_sync_live_sliders(dashboard, restored)
            _pd_format_bits(dashboard)
            ui.label2_sa_pd_demodulation_results_bits.setText(
                f"{restored['bit_count']:,}"
            )
            _pd_draw_output(dashboard, preserve_view=True)
            ui.label2_sa_pd_demodulation_results_status.setText(
                "Estimate restored (unverified)"
            )
        else:
            # If the modulation changed, old decisions are no longer valid.
            dashboard.sa_pd_demodulation_result = None
            _pd_sync_live_sliders(dashboard)
            ui.plainTextEdit_sa_pd_demodulation_bits.clear()
            ui.label2_sa_pd_demodulation_results_bits.setText("—")
            _pd_draw_output(dashboard)
            ui.label2_sa_pd_demodulation_results_status.setText(
                f"Estimated {result['method'].upper()} (unverified)"
            )
            # No bitstream has been recovered yet. Display the estimated
            # settings, but leave the live sliders inactive until Demodulate.
            live_labels = getattr(dashboard, "sa_pd_demodulation_live_values", {})
            if live_labels:
                live_labels["rate"].setText(
                    f"{float(rate):,.2f} sym/s" if rate is not None else "—"
                )
                live_labels["threshold"].setText(
                    (f"{float(level):,.1f} Hz" if result['method'] == 'fsk'
                     else f"{float(level):.4f}") if level is not None else "—"
                )
                live_labels["phase"].setText(
                    f"{phase:+.3f} sym" if result.get('timing_offset') is not None else "—"
                )

        # Reset manual overrides to Auto and update the displayed estimates.
        # Block signals so the buttons/sliders cannot invalidate this result.
        method = str(ui.comboBox_sa_pd_demodulation_settings_method.currentData() or "auto")
        parameter_values = (
            (rate, offset, level) if method == "auto"
            else (rate, level, phase)
        )
        for index, value in enumerate(parameter_values, start=1):
            check = getattr(ui, f"checkBox_sa_pd_demodulation_settings_item{index}")
            spin = getattr(ui, f"doubleSpinBox_sa_pd_demodulation_settings_item{index}")
            old_check = check.blockSignals(True)
            old_spin = spin.blockSignals(True)
            try:
                check.setChecked(True)
                spin.setEnabled(False)
                if value is not None and np.isfinite(value):
                    spin.setValue(float(value))
            finally:
                check.blockSignals(old_check)
                spin.blockSignals(old_spin)
    else:
        dashboard.sa_pd_demodulation_result = result
        _pd_sync_live_sliders(dashboard, result)
        if result.get("timing_uncertain"):
            message = f"{result['method'].upper()} preview: timing uncertain"
        elif result.get("auto_selection"):
            message = f"Auto selected {result['method'].upper()} (unverified)"
        else:
            message = "Candidate recovered (unverified)"
        ui.label2_sa_pd_demodulation_results_status.setText(message)
        ui.label2_sa_pd_demodulation_results_bits.setText(f"{result['bit_count']:,}")
        _pd_format_bits(dashboard)
        _pd_draw_output(dashboard)

        # Display the latest demodulation parameters even when Auto remains checked.
        for index, value in ((1, rate), (2, result.get("threshold"))):
            if value is not None and np.isfinite(value):
                spin = getattr(ui, f"doubleSpinBox_sa_pd_demodulation_settings_item{index}")
                old = spin.blockSignals(True)
                spin.setValue(float(value))
                spin.blockSignals(old)

    ui.label2_sa_pd_demodulation_results_processing_time.setText(
        f"{result['elapsed']:.3f} s"
    )
    ui.label2_sa_pd_demodulation_results_status.setToolTip(result.get("note", ""))
    labels = {
        "modulation": result["method"].upper(),
        "symbol_rate": f"{rate:.4g} sym/s" if rate is not None else "Unknown",
        "deviation": f"{deviation:.4g} Hz" if deviation is not None else "—",
        "frequency_offset": f"{offset:.4g} Hz" if offset is not None else "—",
        "confidence": "Timing uncertain" if result.get("timing_uncertain") else "Unverified",
    }
    for name, value in labels.items():
        widget = getattr(ui, "label2_sa_pd_demodulation_output_parameters_" + name, None)
        if widget is not None:
            widget.setText(value)


def _pd_format_bits(dashboard):
    result=getattr(dashboard,'sa_pd_demodulation_result',None)
    if result is None:return
    bits=result['bits'][:4096]
    ui=dashboard.ui
    mode=str(ui.comboBox_sa_pd_demodulation_bits_format.currentData() or 'bits')
    group=int(ui.comboBox_sa_pd_demodulation_bits_group.currentData() or 8)
    packed=''.join(map(str,bits.tolist()))
    if mode=='hex':
        packed=''.join(f'{int(packed[i:i+8],2):02X}' for i in range(0,len(packed)//8*8,8))
        group=max(1,group//4)
    elif mode=='ascii':
        packed=''.join(chr(int(packed[i:i+8],2)) if 32<=int(packed[i:i+8],2)<=126 else '.' for i in range(0,len(packed)//8*8,8))
        group=0
    if group:
        packed=' '.join(packed[i:i+group] for i in range(0,len(packed),group))
    ui.plainTextEdit_sa_pd_demodulation_bits.setPlainText(packed)
    ui.plainTextEdit_sa_pd_demodulation_bits.setToolTip('Preview limited to first 4,096 bits; complete candidate retained in memory')


def _pd_update_content_visibility(dashboard, has_file, has_result):
    """Keep fixed Designer panels blank until there is content to display.

    Frames use fixed Designer geometry, so hiding them does not resize or
    reposition the rest of the page. Hiding a plot frame also hides its
    Matplotlib toolbar, avoiding inert toolbar buttons in the empty state.
    An Estimate can display Detected Parameters without creating a bitstream.
    """
    ui = dashboard.ui
    has_parameters = bool(
        has_result or getattr(dashboard, "sa_pd_demodulation_estimate", None) is not None
    )

    for name in (
        "frame_sa_pd_demodulation_signal_small_plot",
        "frame_sa_pd_demodulation_signal_plot",
    ):
        getattr(ui, name).setVisible(bool(has_file))

    ui.frame_sa_pd_demodulation_output_plot.setVisible(bool(has_result))
    ui.tabWidget_sa_pd_demodulation_output.setVisible(bool(has_result))
    ui.frame_sa_pd_demodulation_output_parameters.setVisible(has_parameters)

    # Keep section 5's heading and badge, but suppress the empty editor and
    # formatting row until actual recovered bits are present.
    for name in (
        "plainTextEdit_sa_pd_demodulation_bits",
        "label2_16",  # Format:
        "label2_35",  # Group:
        "comboBox_sa_pd_demodulation_bits_format",
        "comboBox_sa_pd_demodulation_bits_group",
    ):
        getattr(ui, name).setVisible(bool(has_result))


def _pd_update_available_controls(dashboard):
    """Enable analysis and navigation only when their inputs/results exist.

    A local IQ file may be viewable without a sample rate. Demodulation needs
    both a file and its sample rate. Output controls need recovered samples.
    Preserve file selection and metadata entry in every state.
    """
    ui = dashboard.ui
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    has_file = _sa_pd_demodulation_file_is_ready(metadata)
    sample_count = int(metadata.get("sample_count") or 0)
    sample_rate = float(metadata.get("sample_rate_hz") or 0.0)
    worker_running = getattr(dashboard, "sa_pd_demodulation_worker", None) is not None
    has_result = getattr(dashboard, "sa_pd_demodulation_result", None) is not None

    selected_start, selected_end = getattr(
        dashboard, "sa_pd_demodulation_active_selection", (0, 0)
    )
    pending_start, pending_end = getattr(
        dashboard, "sa_pd_demodulation_pending_selection", (0, 0)
    )
    has_selection = has_file and pending_end > pending_start
    selection_changed = has_selection and (
        abs(float(pending_start) - float(selected_start)) > 1e-9
        or abs(float(pending_end) - float(selected_end)) > 1e-9
    )
    if has_file:
        start_sample, end_sample = _sa_pd_demodulation_selection_to_samples(
            dashboard, (selected_start, selected_end)
        )
        analysis_samples = end_sample - start_sample
    else:
        analysis_samples = 0
    can_analyze = (
        has_file and sample_rate > 0.0 and sample_count > 0
        and 0 < analysis_samples <= MAX_ANALYSIS_SAMPLES and not worker_running
    )

    # Source selection and local metadata editors remain available. Offline IQ
    # plots can use sample indices even before the sample rate is entered.
    ui.pushButton_sa_pd_demodulation_signal_full.setEnabled(has_file and not worker_running)
    ui.pushButton_sa_pd_demodulation_signal_zoom.setEnabled(
        bool(selection_changed and not worker_running)
    )
    for name in ("iq", "magnitude", "if"):
        getattr(ui, f"radioButton_sa_pd_demodulation_signal_{name}").setEnabled(has_file)

    signal_toolbar = getattr(dashboard, "sa_pd_demodulation_signal_toolbar", None)
    if signal_toolbar is not None:
        signal_toolbar.setEnabled(has_file)
    output_toolbar = getattr(dashboard, "sa_pd_demodulation_output_toolbar", None)
    if output_toolbar is not None:
        output_toolbar.setEnabled(has_result)

    ui.pushButton_sa_pd_demodulation_settings_estimate.setEnabled(bool(can_analyze))
    ui.pushButton_sa_pd_demodulation_settings_demodulate.setEnabled(bool(can_analyze))
    for index in (1, 2, 3):
        check = getattr(ui, f"checkBox_sa_pd_demodulation_settings_item{index}")
        spin = getattr(ui, f"doubleSpinBox_sa_pd_demodulation_settings_item{index}")
        unit = getattr(ui, f"comboBox_sa_pd_demodulation_settings_item{index}")
        check.setEnabled(has_file and sample_rate > 0.0)
        spin.setEnabled(has_file and sample_rate > 0.0 and not check.isChecked())
        unit.setEnabled(has_file and sample_rate > 0.0)

    advanced = ui.toolButton_sa_pd_demodulation_settings
    if not has_file and advanced.isChecked():
        advanced.setChecked(False)
    advanced.setEnabled(has_file and sample_rate > 0.0)
    sliders = getattr(dashboard, "sa_pd_demodulation_live_sliders", {})
    for slider in sliders.values():
        slider.setEnabled(has_result and not worker_running)

    ui.tabWidget_sa_pd_demodulation_output.tabBar().setEnabled(has_result)
    ui.comboBox_sa_pd_demodulation_bits_format.setEnabled(has_result)
    ui.comboBox_sa_pd_demodulation_bits_group.setEnabled(has_result)

    # Pass complete recovered bits directly to the adjacent framing workspace.
    bf_ready = bool(getattr(dashboard, "sa_pd_bf_initialized", False))
    ui.pushButton_sa_pd_demodulation_results_bitstream_and_framing.setEnabled(
        has_result and bf_ready
    )
    ui.pushButton_sa_pd_demodulation_results_bitstream_and_framing.setToolTip(
        "Open recovered bits in Bitstream & Framing" if bf_ready
        else "Bitstream & Framing has not finished initializing"
    )
    ui.pushButton_sa_pd_demodulation_results_save_as_artifact.setEnabled(False)
    ui.pushButton_sa_pd_demodulation_results_save_as_artifact.setToolTip(
        "Saving demodulation results as an Artifact has not been implemented"
    )

    if has_file and sample_rate <= 0:
        message = "Enter the sample rate to enable Estimate and Demodulate"
    elif has_file and analysis_samples > MAX_ANALYSIS_SAMPLES:
        message = "Zoom to a region of 2,000,000 samples or fewer"
    elif not has_file:
        message = "Select or prepare a local IQ file to enable analysis"
    else:
        message = "Estimate signal parameters"
    for name in ("estimate", "demodulate"):
        button = getattr(ui, f"pushButton_sa_pd_demodulation_settings_{name}")
        button.setToolTip(message)

    # Hide blank Matplotlib canvases, inactive toolbars, and results-only widgets.
    _pd_update_content_visibility(dashboard, has_file, has_result)


def _pd_detected_x_limits_changed(dashboard):
    """Refresh Detected after toolbar pan, zoom, or Home (debounced)."""
    if getattr(dashboard, "sa_pd_demodulation_detected_busy", False):
        return
    if getattr(dashboard, "sa_pd_demodulation_result", None) is None:
        return
    if dashboard.ui.tabWidget_sa_pd_demodulation_output.currentIndex() != 0:
        return
    timer = getattr(dashboard, "sa_pd_demodulation_detected_timer", None)
    if timer is None:
        timer = QtCore.QTimer(dashboard.sa_pd_demodulation_output_canvas)
        timer.setSingleShot(True)
        timer.timeout.connect(lambda: _pd_draw_output(dashboard, preserve_view=True))
        dashboard.sa_pd_demodulation_detected_timer = timer
    # Restarting defers the expensive re-render until the user stops dragging.
    timer.start(130)


def _pd_plot_detected_region(dashboard, canvas, result, bounds):
    """Draw the *entire visible region* of the discriminator at appropriate detail.

    Dense views use per-bin minimum/maximum rather than sampling every Nth
    point, so narrow OOK bursts and FSK transitions are not silently dropped.
    """
    data = np.asarray(result["base"])
    count = len(data)
    if count == 0:
        return
    left = max(0, min(count - 1, int(np.floor(min(bounds)))))
    right = min(count, max(left + 1, int(np.ceil(max(bounds)))))
    _background, _face, _text, _grid, i_color, _q_color, _if_color = _pd_theme(dashboard)
    dark = "Dark" in str((getattr(dashboard.backend, "settings", {}) or {}).get("color_mode", ""))
    above_color = "#60c783" if dark else "#148a3b"
    below_color = "#ee8585" if dark else "#ba4444"
    threshold_color = "#eda765" if dark else "#bf7333"
    axes = canvas.axes

    if right - left <= 12000:
        # Display every discriminator sample when zoomed into a manageable range.
        positions = np.arange(left, right)
        axes.plot(positions, data[left:right], linewidth=0.85, color=i_color)
    else:
        # Each display column includes its minimum and maximum. Decimation by
        # stride would obscure the sparse OOK pulses we're trying to inspect.
        bin_count = min(1600, right - left)
        edges = np.linspace(0, right - left, bin_count + 1, dtype=np.int64)
        starts = edges[:-1]
        values = data[left:right]
        lows = np.minimum.reduceat(values, starts)
        highs = np.maximum.reduceat(values, starts)
        x_positions = left + (edges[:-1] + edges[1:] - 1) * 0.5
        axes.vlines(x_positions, lows, highs, colors=i_color, linewidth=0.8)

    threshold = float(result["threshold"])
    axes.axhline(threshold, color=threshold_color, linestyle="--", linewidth=0.9)
    centers = np.asarray(result["centers"])
    visible = centers[(centers >= left) & (centers < right)]
    # Limit marker clutter in the full-recording view but never lose markers
    # when the user zooms in for precise timing adjustment.
    if len(visible) > 750:
        visible = visible[::int(np.ceil(len(visible) / 750))]
    if len(visible):
        indices = np.clip(visible.astype(np.int64), 0, count - 1)
        fractions = visible - indices
        sampled = data[indices] + (data[np.minimum(indices + 1, count - 1)] - data[indices]) * fractions
        colors = np.where(sampled >= threshold, above_color, below_color)
        axes.scatter(visible, sampled, s=13 if right - left <= 12000 else 9,
                     c=colors, zorder=5, linewidths=0)
    axes.set_ylabel("Magnitude" if result["method"] == "ook" else "Frequency (Hz)")


def _pd_draw_output(dashboard, preserve_view=False):
    """Draw output; Detected supports full-range and pan/zoom adaptive rendering."""
    _pd_update_available_controls(dashboard)
    canvas = dashboard.sa_pd_demodulation_output_canvas
    result = getattr(dashboard, "sa_pd_demodulation_result", None)
    if result is None:
        timer = getattr(dashboard, "sa_pd_demodulation_detected_timer", None)
        if timer is not None:
            timer.stop()
        _pd_clear_plot(dashboard, canvas)
        return
    tab = dashboard.ui.tabWidget_sa_pd_demodulation_output.currentIndex()
    same_tab = getattr(dashboard, "sa_pd_demodulation_last_output_tab", None) == tab
    keep = bool(preserve_view and same_tab and canvas.axes.has_data())
    xlim = canvas.axes.get_xlim() if keep else None
    ylim = canvas.axes.get_ylim() if keep else None
    timer = getattr(dashboard, "sa_pd_demodulation_detected_timer", None)
    if timer is not None:
        timer.stop()
    dashboard.sa_pd_demodulation_detected_busy = True
    try:
        canvas.axes.clear()
        _pd_style_axes(dashboard, canvas)
        _background, _face, text, grid, i_color, q_color, if_color = _pd_theme(dashboard)
        base = np.asarray(result["base"])
        n = min(8000, len(base))
        if tab == 0:
            if len(base):
                # The initial view is the FULL selected capture; subsequent
                # toolbar navigation requests only the newly visible portion.
                bounds = xlim if keep else (0, len(base))
                _pd_plot_detected_region(dashboard, canvas, result, bounds)
                if keep:
                    canvas.axes.set_xlim(xlim)
                    canvas.axes.set_ylim(ylim)
                else:
                    canvas.axes.set_xlim(0, len(base))
                # Axes.clear() discards its callbacks. Reinstall after every
                # draw so future Home/Zoom/Pan operations stay interactive.
                canvas.axes.callbacks.connect(
                    "xlim_changed", lambda _axes: _pd_detected_x_limits_changed(dashboard)
                )
        elif tab == 1:
            canvas.axes.step(np.arange(n), result["levels"][:n].astype(int),
                             where="post", linewidth=0.8, color=i_color)
            canvas.axes.set_ylabel("Symbol decision")
        elif tab == 2:
            bits = result["bits"][:4096]
            canvas.axes.step(np.arange(len(bits)), bits, where="post", linewidth=0.8,
                             color=i_color)
            canvas.axes.set_ylabel("Recovered bit")
        elif tab in (3, 4):
            trace = base[:min(32768, len(base))]
            if tab == 3:
                power = np.abs(np.fft.rfft(trace - np.mean(trace))) ** 2
                canvas.axes.plot(np.fft.rfftfreq(len(trace), 1 / result["sample_rate"]),
                                 10 * np.log10(np.maximum(power, 1e-12)), color=i_color)
            else:
                canvas.axes.specgram(trace, Fs=result["sample_rate"], NFFT=256,
                                     noverlap=192)
        else:
            canvas.axes.text(0.5, 0.5, "Constellation requires carrier/symbol recovery",
                             color=text, ha="center", va="center", transform=canvas.axes.transAxes)
        # Preserve existing output-tab label layout, including the unclipped X ticks.
        canvas.axes.set_xlabel("")
        if keep and tab != 0:
            canvas.axes.set_xlim(xlim)
            canvas.axes.set_ylim(ylim)
        dashboard.sa_pd_demodulation_last_output_tab = tab
        canvas.draw_idle()
    finally:
        dashboard.sa_pd_demodulation_detected_busy = False




def _pd_toggle_advanced(dashboard, checked):
    dashboard.ui.widget_sa_pd_demodulation_settings.setVisible(bool(checked))
    dashboard.ui.toolButton_sa_pd_demodulation_settings.setArrowType(QtCore.Qt.DownArrow if checked else QtCore.Qt.RightArrow)


def _slotSA_PDDemodulationOpenInInspectionClicked(dashboard):
    """Open the same source in the existing Inspection workspace.

    This handoff calls Inspection's existing public-ish slot helpers, but no
    Inspection file-handling code or state is shared with Demodulation itself.
    """
    from . import inspection as inspection_slots

    ui = dashboard.ui
    source = getattr(dashboard, "sa_pd_demodulation_source", "artifact")
    soi_key = str(ui.comboBox_sa_pd_demodulation_selection_soi.currentData(QtCore.Qt.UserRole) or "")
    path = str((getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}).get("path") or "")
    artifact_id = str(getattr(dashboard, "sa_pd_demodulation_artifact_id", "") or "")
    file_id = str(getattr(dashboard, "sa_pd_demodulation_file_id", "") or "")
    if source == "local" and not os.path.isfile(path):
        ui.label2_sa_pd_demodulation_results_status.setText("Select a local file first")
        return
    if source == "artifact" and not artifact_id:
        ui.label2_sa_pd_demodulation_results_status.setText("Select an Artifact first")
        return

    # Switch first: Inspection's tab-change handler may otherwise overwrite the
    # source we have just selected when the new tab becomes active.
    ui.tabWidget_signal_analysis.setCurrentWidget(ui.tab_inspection)
    if source == "local":
        inspection_slots._slotSA_InspectionSourceLocalFileClicked(dashboard)
        inspection_slots._sa_inspection_set_local_file_path(dashboard, path)
        inspection_slots._sa_inspection_load_file(dashboard, path)
        inspection_slots.refresh_sa_inspection_soi_context(dashboard, preferred_soi_key=soi_key)
    else:
        inspection_slots._slotSA_InspectionSourceArtifactClicked(dashboard)
        inspection_slots.refresh_sa_inspection_soi_context(dashboard, preferred_soi_key=soi_key)
        inspection_slots._refresh_sa_inspection_artifacts(
            dashboard, preferred_artifact_id=artifact_id
        )
        combo = ui.comboBox_sa_inspection_selection_file
        for index in range(combo.count()):
            row = combo.itemData(index, QtCore.Qt.UserRole)
            if isinstance(row, dict) and str(row.get("file_id") or row.get("id") or "") == file_id:
                combo.setCurrentIndex(index)
                break


def initialize_sa_pd_demodulation_controls(dashboard):
    """Initialize independent Demodulation sources, metadata, plots and UI controls."""
    dashboard.sa_pd_demodulation_source = "artifact"
    dashboard.sa_pd_demodulation_local_file_path = ""
    dashboard.sa_pd_demodulation_artifact_id = ""
    dashboard.sa_pd_demodulation_file_id = ""
    dashboard.sa_pd_demodulation_file_metadata = {}
    dashboard.sa_pd_demodulation_metadata_revision = 0
    dashboard.sa_pd_demodulation_prepare_artifact_id = ""
    dashboard.sa_pd_demodulation_pending_selection = (0, 0)
    dashboard.sa_pd_demodulation_active_selection = (0, 0)
    dashboard.sa_pd_demodulation_drag_start = None
    dashboard.sa_pd_demodulation_result = None
    dashboard.sa_pd_demodulation_worker = None
    dashboard.sa_pd_demodulation_signal_toolbar = None
    ui = dashboard.ui
    ui.textEdit_sa_pd_demodulation_selection_file_name.setReadOnly(True)
    ui.plainTextEdit_sa_pd_demodulation_bits.setReadOnly(True)
    ui.plainTextEdit_sa_pd_demodulation_bits.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
    ui.plainTextEdit_sa_pd_demodulation_bits.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    ui.stackedWidget_sa_pd_demodulation_selection_source.setCurrentIndex(0)
    for name, labels in (
        ("comboBox_sa_pd_demodulation_settings_method", [
            ("Auto (basic OOK/2-FSK trial)", "auto"),
            ("OOK / ASK", "ook"), ("2-FSK", "fsk")]),
        ("comboBox_sa_pd_demodulation_bits_format", [
            ("Bits", "bits"), ("Hex", "hex"), ("ASCII", "ascii")]),
        ("comboBox_sa_pd_demodulation_bits_group", [
            ("8", "8"), ("4", "4"), ("16", "16"), ("None", "0")]),
    ):
        combo = getattr(ui, name)
        blocked = combo.blockSignals(True)
        combo.clear()
        for label, data in labels:
            combo.addItem(label, data)
        combo.blockSignals(blocked)

    rate = ui.doubleSpinBox_sa_pd_demodulation_selection_sample_rate
    rate.setDecimals(3)
    rate.setRange(0.0, 100000.0)
    rate.setSingleStep(0.1)
    rate.setSuffix(" MS/s")
    rate.setSpecialValueText("—")
    frequency = ui.doubleSpinBox_sa_pd_demodulation_selection_center_frequency
    frequency.setDecimals(3)
    frequency.setRange(0.0, 1000000.0)
    frequency.setSingleStep(0.1)
    frequency.setSuffix(" MHz")
    frequency.setSpecialValueText("—")
    data_type = ui.comboBox_sa_pd_demodulation_selection_data_type
    blocked = data_type.blockSignals(True)
    data_type.clear()
    data_type.addItems(list(_FISSURE_TYPE_MAP))
    data_type.blockSignals(blocked)

    dashboard.sa_pd_demodulation_trace_group = QtWidgets.QButtonGroup(dashboard)
    dashboard.sa_pd_demodulation_trace_group.setExclusive(True)
    for radio in (
        ui.radioButton_sa_pd_demodulation_signal_iq,
        ui.radioButton_sa_pd_demodulation_signal_magnitude,
        ui.radioButton_sa_pd_demodulation_signal_if,
    ):
        dashboard.sa_pd_demodulation_trace_group.addButton(radio)
    # Frontend connects the radio signals before this initializer runs.
    # Block all three so switching the default does not draw an unmounted canvas.
    trace_radios = (
        ui.radioButton_sa_pd_demodulation_signal_iq,
        ui.radioButton_sa_pd_demodulation_signal_magnitude,
        ui.radioButton_sa_pd_demodulation_signal_if,
    )
    previous_signal_states = [radio.blockSignals(True) for radio in trace_radios]
    try:
        ui.radioButton_sa_pd_demodulation_signal_iq.setChecked(True)
    finally:
        for radio, previous_state in zip(trace_radios, previous_signal_states):
            radio.blockSignals(previous_state)

    for name, icon in (
        ("artifact_left", "back.png"), ("artifact_right", "forward.png"),
        ("file_left", "back.png"), ("file_right", "forward.png"),
        ("file_select", "folder_black.svg"),
    ):
        widget = getattr(ui, "pushButton_sa_pd_demodulation_selection_" + name)
        path = os.path.join(fissure.utils.UI_DIR, "Icons", icon)
        if os.path.isfile(path):
            widget.setIcon(QtGui.QIcon(path))
            widget.setText("")
    dashboard.sa_pd_demodulation_overview_canvas = _pd_mount_plot(
        ui.frame_sa_pd_demodulation_signal_small_plot
    )
    dashboard.sa_pd_demodulation_signal_canvas = _pd_mount_plot(
        ui.frame_sa_pd_demodulation_signal_plot,
        navigation_toolbar=True, dashboard=dashboard,
    )
    dashboard.sa_pd_demodulation_output_canvas = _pd_mount_plot(
        ui.frame_sa_pd_demodulation_output_plot,
        navigation_toolbar=True, dashboard=dashboard, toolbar_role="output",
    )
    dashboard.sa_pd_demodulation_overview_canvas.mpl_connect(
        "button_press_event", lambda ev: _pd_overview_press(dashboard, ev)
    )
    dashboard.sa_pd_demodulation_overview_canvas.mpl_connect(
        "button_release_event", lambda ev: _pd_overview_release(dashboard, ev)
    )
    _pd_advanced_settings_initialize(dashboard)
    _pd_method_settings(dashboard)
    ui.widget_sa_pd_demodulation_settings.setVisible(False)
    ui.toolButton_sa_pd_demodulation_settings.setChecked(False)
    ui.toolButton_sa_pd_demodulation_settings.setArrowType(QtCore.Qt.RightArrow)
    ui.tabWidget_sa_pd_demodulation_output.setCurrentIndex(0)
    _sa_pd_demodulation_set_local_file_path(dashboard, "")
    _update_sa_pd_demodulation_source_buttons(dashboard)
    _sa_pd_demodulation_clear_file(dashboard)
    refresh_sa_pd_demodulation_soi_context(dashboard)
    _pd_compact_sections(dashboard)
    _pd_update_inspection_button(dashboard)


def _pd_sample_rate_from_filename(filepath: str):
    """Return explicitly encoded Sps/kSps/MSps/GSps rate, or None.

    Example: capture_1MSps.iq -> 1e6. A filename is a hint, not metadata.
    """
    name = os.path.basename(str(filepath or ""))
    match = re.search(
        r"(?<![A-Za-z0-9.])(?P<value>\d+(?:[.]\d+)?)[_ -]*(?P<prefix>[kKmMgG]?)[_ -]*sps(?![a-z])",
        name, flags=re.IGNORECASE,
    )
    if not match:
        return None
    factor = {'': 1.0, 'k': 1e3, 'm': 1e6, 'g': 1e9}[match.group('prefix').lower()]
    value = float(match.group('value')) * factor
    return value if 0 < value <= 1e12 else None


def _pd_metadata_controls_changed(dashboard: QtCore.QObject):
    """Apply manually corrected sample metadata to the active file and plots.

    Editing datatype changes how many samples exist. Editing sample rate changes
    the time axis and all symbol estimates. In either case the existing candidate
    and region selection must be invalidated.
    """
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    if not _sa_pd_demodulation_file_is_ready(metadata):
        return
    ui = dashboard.ui
    sample_rate_msps = float(ui.doubleSpinBox_sa_pd_demodulation_selection_sample_rate.value())
    frequency_mhz = float(ui.doubleSpinBox_sa_pd_demodulation_selection_center_frequency.value())
    data_type = str(ui.comboBox_sa_pd_demodulation_selection_data_type.currentText() or "")
    if data_type not in _FISSURE_TYPE_MAP:
        return
    sample_rate_hz = sample_rate_msps * 1e6 if sample_rate_msps > 0.0 else None
    center_frequency_hz = frequency_mhz * 1e6 if frequency_mhz > 0.0 else None
    dtype, is_complex, interleaved = _FISSURE_TYPE_MAP[data_type]
    bytes_per_sample = dtype.itemsize * (2 if interleaved else 1)
    size_bytes = int(metadata.get("size_bytes") or 0)
    sample_count = size_bytes // bytes_per_sample
    if (
        sample_rate_hz == metadata.get("sample_rate_hz")
        and center_frequency_hz == metadata.get("center_frequency_hz")
        and data_type == metadata.get("data_type")
    ):
        return
    metadata = dict(metadata)
    metadata.update(
        data_type=data_type,
        data_type_assumed=False,
        dtype=dtype,
        is_complex=bool(is_complex),
        interleaved=bool(interleaved),
        bytes_per_sample=bytes_per_sample,
        sample_rate_hz=sample_rate_hz,
        sample_rate_source="manual",
        center_frequency_hz=center_frequency_hz,
        sample_count=sample_count,
        duration_s=(sample_count / sample_rate_hz if sample_rate_hz else None),
    )
    dashboard.sa_pd_demodulation_file_metadata = metadata
    dashboard.sa_pd_demodulation_metadata_revision = (
        getattr(dashboard, "sa_pd_demodulation_metadata_revision", 0) + 1
    )
    _sa_pd_demodulation_set_file_metadata(dashboard, metadata)
    _pd_full_file(dashboard)
    ui.label2_sa_pd_demodulation_results_status.setText(
        "Ready" if sample_rate_hz else "Enter sample rate to demodulate"
    )


def _pd_update_selection_label(dashboard):
    start, end = getattr(dashboard, "sa_pd_demodulation_pending_selection", (0, 0))
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    if not metadata or end <= start:
        label = "—"
    elif _sa_pd_demodulation_selection_is_seconds(dashboard):
        label = f"{start:.6g}–{end:.6g} s"
    else:
        label = f"{int(start):,}–{int(end):,} samples"
    dashboard.ui.label2_sa_pd_demodulation_signal_selection.setText(label)


def _pd_advanced_settings_initialize(dashboard):
    """Three compact always-visible live tuning sliders (advanced area only)."""
    parent = dashboard.ui.widget_sa_pd_demodulation_settings
    form_host = parent.findChild(QtWidgets.QWidget, 'formLayoutWidget')
    if form_host is not None:
        form_host.hide()
    layout = parent.layout()
    if layout is None:
        layout = QtWidgets.QVBoxLayout(parent)
    layout.setContentsMargins(2, 0, 2, 0)
    layout.setSpacing(0)
    dashboard.sa_pd_demodulation_live_sliders = {}
    dashboard.sa_pd_demodulation_live_values = {}
    dashboard.sa_pd_demodulation_live_anchor = None
    dashboard.sa_pd_demodulation_live_busy = False
    dashboard.sa_pd_demodulation_live_timer = QtCore.QTimer(dashboard)
    dashboard.sa_pd_demodulation_live_timer.setSingleShot(True)
    dashboard.sa_pd_demodulation_live_timer.setInterval(35)
    dashboard.sa_pd_demodulation_live_timer.timeout.connect(
        lambda: _pd_live_settings_changed(dashboard)
    )
    for name, title, maximum in (
        ('rate', 'Rate', 2000), ('threshold', 'Level', 2000), ('phase', 'Phase', 490)
    ):
        row = QtWidgets.QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(4)
        caption = QtWidgets.QLabel(title, parent)
        caption.setFixedWidth(43)
        slider = QtWidgets.QSlider(QtCore.Qt.Horizontal, parent)
        slider.setObjectName(f'horizontalSlider_sa_pd_demodulation_live_{name}')
        slider.setRange(-maximum, maximum)
        slider.setSingleStep(1)
        slider.setPageStep(10)
        slider.setFixedHeight(22)
        slider.setToolTip('Drag for fast tuning; use arrow keys for fine adjustments')
        value_label = QtWidgets.QLabel('—', parent)
        value_label.setObjectName(f'label2_sa_pd_demodulation_live_{name}')
        value_label.setMinimumWidth(104)
        value_label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        row.addWidget(caption)
        row.addWidget(slider, 1)
        row.addWidget(value_label)
        layout.addLayout(row)
        dashboard.sa_pd_demodulation_live_sliders[name] = slider
        dashboard.sa_pd_demodulation_live_values[name] = value_label
        slider.valueChanged.connect(lambda _value: _pd_live_slider_changed(dashboard))
    for widget in parent.findChildren(QtWidgets.QWidget):
        if isinstance(widget, QtWidgets.QLabel):
            font = widget.font()
            font.setPointSize(10)
            widget.setFont(font)
    _pd_sync_live_sliders(dashboard)


def _slotSA_PDDemodulationOpenInInspectionClicked(dashboard):
    """Open the same source in the existing Inspection workspace.

    This handoff calls Inspection's existing public-ish slot helpers, but no
    Inspection file-handling code or state is shared with Demodulation itself.
    """
    from . import inspection as inspection_slots

    ui = dashboard.ui
    source = getattr(dashboard, "sa_pd_demodulation_source", "artifact")
    soi_key = str(ui.comboBox_sa_pd_demodulation_selection_soi.currentData(QtCore.Qt.UserRole) or "")
    path = str((getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}).get("path") or "")
    artifact_id = str(getattr(dashboard, "sa_pd_demodulation_artifact_id", "") or "")
    file_id = str(getattr(dashboard, "sa_pd_demodulation_file_id", "") or "")
    if source == "local" and not os.path.isfile(path):
        ui.label2_sa_pd_demodulation_results_status.setText("Select a local file first")
        return
    if source == "artifact" and not artifact_id:
        ui.label2_sa_pd_demodulation_results_status.setText("Select an Artifact first")
        return

    # Switch first: Inspection's tab-change handler may otherwise overwrite the
    # source we have just selected when the new tab becomes active.
    ui.tabWidget_signal_analysis.setCurrentWidget(ui.tab_inspection)
    if source == "local":
        inspection_slots._slotSA_InspectionSourceLocalFileClicked(dashboard)
        inspection_slots._sa_inspection_set_local_file_path(dashboard, path)
        inspection_slots._sa_inspection_load_file(dashboard, path)
        inspection_slots.refresh_sa_inspection_soi_context(dashboard, preferred_soi_key=soi_key)
    else:
        inspection_slots._slotSA_InspectionSourceArtifactClicked(dashboard)
        inspection_slots.refresh_sa_inspection_soi_context(dashboard, preferred_soi_key=soi_key)
        inspection_slots._refresh_sa_inspection_artifacts(
            dashboard, preferred_artifact_id=artifact_id
        )
        combo = ui.comboBox_sa_inspection_selection_file
        for index in range(combo.count()):
            row = combo.itemData(index, QtCore.Qt.UserRole)
            if isinstance(row, dict) and str(row.get("file_id") or row.get("id") or "") == file_id:
                combo.setCurrentIndex(index)
                break


def _pd_compact_sections(dashboard):
    """Fit six metadata rows and output tabs inside the existing Designer cards.

    The metadata grid is 160 px tall in the .ui, but its parent frame is only
    120 px tall. Resize the embedded grid, not the entire Dashboard page.
    """
    ui = dashboard.ui
    ui.frame_sa_pd_demodulation_signal_small_plot.setToolTip(
        "Full-recording magnitude overview. Horizontal positions are in "
        "seconds when a sample rate is known, otherwise sample indices. "
        "Drag to select a region and click Zoom to Selection."
    )
    details = ui.frame_sa_pd_demodulation_selection_details
    grid_host = details.findChild(QtWidgets.QWidget, "gridLayoutWidget_5")
    grid = getattr(ui, "gridLayout_sa_pd_demodulation_selection_details", None)
    if grid is not None:
        grid.setContentsMargins(2, 0, 2, 0)
        grid.setVerticalSpacing(0)
        grid.setHorizontalSpacing(3)
    if grid_host is not None:
        grid_host.setGeometry(0, 0, details.width(), details.height())
    for name in (
        "doubleSpinBox_sa_pd_demodulation_selection_sample_rate",
        "doubleSpinBox_sa_pd_demodulation_selection_center_frequency",
        "comboBox_sa_pd_demodulation_selection_data_type",
    ):
        widget = getattr(ui, name)
        widget.setMinimumHeight(0)
        widget.setMaximumHeight(19)
    for name in ("samples", "duration", "size"):
        getattr(ui, f"label2_sa_pd_demodulation_selection_{name}").setMinimumHeight(0)

    tabs = ui.tabWidget_sa_pd_demodulation_output
    tabs.setTabText(0, "Detected")
    tabs.setTabText(5, "Constellation")
    tabs.setTabToolTip(0, "Detected signal and symbol sampling positions")
    tabs.tabBar().setExpanding(False)
    tabs.tabBar().setUsesScrollButtons(True)
    ui.label_sa_pd_demodulation_output_parameters_title.setToolTip(
        "Estimated parameters are provisional until validated against known data"
    )


def _pd_update_inspection_button(dashboard):
    """Inspection handoff only makes sense for a locally accessible data file."""
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    ready = _sa_pd_demodulation_file_is_ready(metadata)
    button = dashboard.ui.pushButton_sa_pd_demodulation_selection_open_in_inspection
    button.setEnabled(ready)
    button.setToolTip(
        "Open the selected IQ file in Inspection" if ready
        else "Load or prepare an IQ file before opening it in Inspection"
    )


def _pd_launch_worker(dashboard, mode):
    """Run the full DSP only on an explicit button click, not on value changes."""
    if getattr(dashboard, "sa_pd_demodulation_worker", None) is not None:
        return
    metadata = getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}
    ui = dashboard.ui
    if not _sa_pd_demodulation_file_is_ready(metadata):
        ui.label2_sa_pd_demodulation_results_status.setText("Select a prepared IQ file")
        return
    if not metadata.get("sample_rate_hz"):
        ui.label2_sa_pd_demodulation_results_status.setText("Input sample rate required")
        return
    start, end = _sa_pd_demodulation_selection_to_samples(
        dashboard, dashboard.sa_pd_demodulation_active_selection
    )
    if end <= start:
        ui.label2_sa_pd_demodulation_results_status.setText("Select samples to analyze")
        return
    if end - start > MAX_ANALYSIS_SAMPLES:
        ui.label2_sa_pd_demodulation_results_status.setText("Zoom to ≤2,000,000 samples")
        return
    worker = _PDRecoveryThread(
        dict(metadata), start, end, _pd_current_parameters(dashboard),
        getattr(dashboard, "sa_pd_demodulation_metadata_revision", 0), mode, dashboard,
    )
    dashboard.sa_pd_demodulation_worker = worker
    ui.pushButton_sa_pd_demodulation_settings_demodulate.setEnabled(False)
    ui.pushButton_sa_pd_demodulation_settings_estimate.setEnabled(False)
    ui.label2_sa_pd_demodulation_results_status.setText(
        "Estimating parameters..." if mode == "estimate" else "Demodulating..."
    )
    worker.completed.connect(lambda payload: _pd_finish(dashboard, payload))
    worker.finished.connect(worker.deleteLater)
    worker.start()


def _pd_sync_live_sliders(dashboard, result=None):
    """Reset all three sliders around the most recent full demodulation result."""
    sliders = getattr(dashboard, 'sa_pd_demodulation_live_sliders', {})
    labels = getattr(dashboard, 'sa_pd_demodulation_live_values', {})
    if not sliders:
        return
    result = result if result is not None else getattr(dashboard, 'sa_pd_demodulation_result', None)
    dashboard.sa_pd_demodulation_live_anchor = dict(result) if result else None
    for name, slider in sliders.items():
        prev = slider.blockSignals(True)
        slider.setValue(int(round(float(result.get('timing_offset', 0.)) * 1000)) if result and name == 'phase' else 0)
        slider.setEnabled(bool(result))
        slider.blockSignals(prev)
        if not result:
            labels[name].setText('—')
    if result:
        _pd_update_live_labels(dashboard, float(result['symbol_rate']),
                               float(result['threshold']), float(result.get('timing_offset', 0.)))

def _pd_update_live_labels(dashboard, rate, threshold, phase):
    labels = getattr(dashboard, 'sa_pd_demodulation_live_values', {})
    if not labels:
        return
    labels['rate'].setText(f'{rate:,.2f} sym/s')
    method = (getattr(dashboard, 'sa_pd_demodulation_live_anchor', None) or {}).get('method')
    labels['threshold'].setText(f'{threshold:,.1f} Hz' if method == 'fsk' else f'{threshold:.4f}')
    labels['phase'].setText(f'{phase:+.3f} sym')


def _pd_live_slider_changed(dashboard):
    """Update rate/level/phase controls together using a stable tuning anchor."""
    anchor = getattr(dashboard, 'sa_pd_demodulation_live_anchor', None)
    if not anchor or getattr(dashboard, 'sa_pd_demodulation_worker', None) is not None:
        return
    sliders = getattr(dashboard, 'sa_pd_demodulation_live_sliders', {})
    if len(sliders) != 3:
        return
    ui = dashboard.ui
    method_combo = ui.comboBox_sa_pd_demodulation_settings_method
    if method_combo.currentData() == 'auto':
        old = method_combo.blockSignals(True)
        index = method_combo.findData(anchor['method'])
        if index >= 0:
            method_combo.setCurrentIndex(index)
        method_combo.blockSignals(old)
        _pd_method_settings(dashboard)
    if method_combo.currentData() != anchor['method']:
        ui.label2_sa_pd_demodulation_results_status.setText('Select matching modulation')
        return
    rate_scale = max(float(anchor['symbol_rate']) * .02 / 2000., .0005)
    rate = float(anchor['symbol_rate']) + sliders['rate'].value() * rate_scale
    if anchor['method'] == 'fsk':
        level_scale = max(abs(float(anchor.get('frequency_deviation') or 0)) * .6 / 2000., .001)
    else:
        base = np.asarray(anchor['base'])
        span = float(np.percentile(base, 85) - np.percentile(base, 15))
        level_scale = max(span * .6 / 2000., 1e-7)
    level = float(anchor['threshold']) + sliders['threshold'].value() * level_scale
    phase = float(sliders['phase'].value() * .001)
    # QSlider cannot represent >0.49 phase; keep its physical position and
    # report the clipped value when the original fitted phase was not centered.
    for row, value in ((1, rate), (2, level), (3, phase)):
        spinner = getattr(ui, f'doubleSpinBox_sa_pd_demodulation_settings_item{row}')
        check = getattr(ui, f'checkBox_sa_pd_demodulation_settings_item{row}')
        old_check = check.blockSignals(True)
        check.setChecked(False)
        check.blockSignals(old_check)
        spinner.setEnabled(True)
        old_spin = spinner.blockSignals(True)
        spinner.setValue(value)
        spinner.blockSignals(old_spin)
    _pd_update_live_labels(dashboard, rate, level, phase)
    dashboard.sa_pd_demodulation_live_timer.start()


def _pd_live_settings_changed(dashboard):
    """Update only cached bit sampling and marker positions; keep plot zoom."""
    result = getattr(dashboard, 'sa_pd_demodulation_result', None)
    if result is None or getattr(dashboard, 'sa_pd_demodulation_worker', None) is not None:
        return
    if getattr(dashboard, 'sa_pd_demodulation_live_busy', False):
        return
    ui = dashboard.ui
    chosen = ui.comboBox_sa_pd_demodulation_settings_method.currentData()
    if chosen not in (result['method'], 'auto'):
        ui.label2_sa_pd_demodulation_results_status.setText('Method changed; press Demodulate')
        return
    checks = [getattr(ui, f'checkBox_sa_pd_demodulation_settings_item{i}') for i in (1, 2, 3)]
    spins = [getattr(ui, f'doubleSpinBox_sa_pd_demodulation_settings_item{i}') for i in (1, 2, 3)]
    rate = result['symbol_rate'] if checks[0].isChecked() else float(spins[0].value())
    level = result['threshold'] if checks[1].isChecked() else float(spins[1].value())
    phase = (result.get('timing_offset', 0.) if chosen == 'auto' or checks[2].isChecked()
             else float(spins[2].value()))
    try:
        dashboard.sa_pd_demodulation_live_busy = True
        updated = retime_cached_candidate(result, rate, level, phase)
        dashboard.sa_pd_demodulation_result = updated
        _pd_format_bits(dashboard)
        ui.label2_sa_pd_demodulation_results_bits.setText(f"{updated['bit_count']:,}")
        ui.label2_sa_pd_demodulation_output_parameters_symbol_rate.setText(f'{rate:,.2f} sym/s')
        if updated['method'] == 'fsk':
            ui.label2_sa_pd_demodulation_output_parameters_frequency_offset.setText(
                f'{level:,.1f} Hz')
        ui.label2_sa_pd_demodulation_results_status.setText('Live preview (unverified)')
        ui.label2_sa_pd_demodulation_results_status.setToolTip(
            'Only bit decisions were recomputed from the cached discriminator. '
            'No frame or CRC validation has occurred.')
        _pd_update_live_labels(dashboard, rate, level, phase)
        _pd_draw_output(dashboard, preserve_view=True)
    except (ValueError, KeyError) as exc:
        ui.label2_sa_pd_demodulation_results_status.setText('Invalid tuning range')
        ui.label2_sa_pd_demodulation_results_status.setToolTip(str(exc))
    finally:
        dashboard.sa_pd_demodulation_live_busy = False


__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value) and value.__module__ == __name__
]