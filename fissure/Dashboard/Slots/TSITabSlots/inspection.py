from PyQt5 import QtCore, QtGui, QtWidgets

import asyncio
from datetime import datetime, timezone
import inspect
import json
import math
import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile

import numpy as np
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg, NavigationToolbar2QT
from matplotlib.figure import Figure
from matplotlib.ticker import FuncFormatter, MaxNLocator

import qasync

import fissure.utils
from fissure.Dashboard.SoiEvidenceController import collect_soi_artifact_ids
from fissure.Dashboard.UI_Components import Qt5
from fissure.utils.selected_node_utils import selected_node_is_remote
from .sois import _sa_sois_display_name, _sa_sois_format_frequency, _sa_sois_value


OVERVIEW_POINTS = 4000
MAX_TIME_POINTS = 120000
MAX_SPECTRUM_SAMPLES = 262144
MAX_SPECTROGRAM_SAMPLES = 262144
MAX_CONSTELLATION_POINTS = 50000

ACTION_QUERY_CONTEXT = "sa.inspection.actions"
ACTION_SCHEMA_CONTEXT = "sa.inspection.schema"


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

_INSPECTION_FILE_TYPE_BY_EXTENSION = {
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

_INSPECTION_DATA_EXTENSIONS = (
    ".sigmf-data",
    ".iq",
    ".dat",
    ".bin",
    ".raw",
    *_INSPECTION_FILE_TYPE_BY_EXTENSION.keys(),
)


class _InspectionCanvas(FigureCanvasQTAgg):
    """Small reusable matplotlib canvas for Inspection."""

    def __init__(self, parent=None):
        self.fig = Figure(dpi=100)
        self.axes = self.fig.add_subplot(111)
        self.fig.subplots_adjust(left=0.09, right=0.98, bottom=0.16, top=0.96)
        super().__init__(self.fig)
        self.setParent(parent)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding)
        self.updateGeometry()


def _sa_inspection_theme(dashboard: QtCore.QObject) -> tuple:
    """Return theme-aware plot colors consistent with Conditioner preview."""
    settings = getattr(dashboard.backend, "settings", {}) or {}
    background = str(settings.get("color2") or "#FBFBFB")
    face = str(settings.get("color5") or "#FFFFFF")
    text = str(settings.get("color4") or "#000000")
    color_mode = str(settings.get("color_mode", "") or "")

    if "Dark" in color_mode:
        grid = "#56616f"
        i_color = "#2f8fe8"
        q_color = "#7aa35a"
    elif "Custom" in color_mode:
        grid = str(settings.get("color3") or "#31577d")
        i_color = "#1f77b4"
        q_color = "#6f8f4e"
    else:
        grid = "#b8c0ca"
        i_color = "#1f77b4"
        q_color = "#7aa35a"

    return background, face, text, grid, i_color, q_color


def _sa_inspection_style_axes(dashboard: QtCore.QObject, canvas: _InspectionCanvas):
    """Apply compact FISSURE plot styling."""
    _background, face, text, grid, _i_color, _q_color = _sa_inspection_theme(dashboard)

    canvas.fig.set_facecolor(face)
    canvas.axes.set_facecolor(face)
    canvas.axes.set_axisbelow(True)

    canvas.axes.tick_params(
        axis="x",
        colors=text,
        labelsize=8,
        length=3,
        pad=1,
    )
    canvas.axes.tick_params(
        axis="y",
        colors=text,
        labelsize=8,
        length=3,
        pad=1,
    )

    canvas.axes.xaxis.label.set_color(text)
    canvas.axes.yaxis.label.set_color(text)
    canvas.axes.title.set_color(text)

    for spine in canvas.axes.spines.values():
        spine.set_color(grid)
        spine.set_linewidth(0.8)

    canvas.axes.grid(
        True,
        color=grid,
        alpha=0.45,
        linewidth=0.6,
    )


def _sa_inspection_mount_canvas(
    dashboard: QtCore.QObject,
    frame,
    attribute_name: str,
    navigation_toolbar: bool = False,
):
    """Mount an Inspection Matplotlib canvas and optional navigation toolbar."""
    canvas = _InspectionCanvas(frame)

    layout = frame.layout()
    if layout is None:
        layout = QtWidgets.QVBoxLayout(frame)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

    if navigation_toolbar:
        toolbar = NavigationToolbar2QT(canvas, frame)
        toolbar.setObjectName("toolbar_sa_inspection_view")
        toolbar.setIconSize(QtCore.QSize(16, 16))
        toolbar.setFixedHeight(28)

        toolbar_icons = {
            "Home": "home.png",
            "Back": "back.png",
            "Forward": "forward.png",
            "Pan": "move.png",
            "Zoom": "zoom_to_rect.png",
            "Save": "filesave.png",
        }

        for action in toolbar.actions():
            action_text = str(action.text() or "")
            if action_text in {"Subplots", "Customize"}:
                action.setVisible(False)
                continue

            icon_name = toolbar_icons.get(action_text)
            if icon_name:
                icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", icon_name)
                if os.path.isfile(icon_path):
                    action.setIcon(QtGui.QIcon(icon_path))

        layout.addWidget(toolbar)
        dashboard.sa_inspection_view_toolbar = toolbar

    layout.addWidget(canvas, 1)
    setattr(dashboard, attribute_name, canvas)
    return canvas


def _sa_inspection_set_button_icon(
    dashboard: QtCore.QObject,
    widget_name: str,
    icon_name: str,
    tooltip: str = "",
    clear_text: bool = False,
    size: int = 16,
):
    """Apply a common FISSURE icon to an Inspection button."""
    button = getattr(dashboard.ui, widget_name, None)
    if button is None:
        return

    icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", icon_name)
    if not os.path.isfile(icon_path):
        return

    button.setIcon(QtGui.QIcon(icon_path))
    button.setIconSize(QtCore.QSize(size, size))
    if clear_text:
        button.setText("")
    if tooltip:
        button.setToolTip(tooltip)


def _initialize_sa_inspection_visuals(dashboard: QtCore.QObject):
    """Initialize Inspection presentation helpers."""
    select_node_icon = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "select_node.png",
    )

    if os.path.isfile(select_node_icon):
        dashboard.ui.label_sa_inspection_actions_select_sensor_node_image.setPixmap(
            QtGui.QPixmap(select_node_icon)
        )
        dashboard.ui.label_sa_inspection_actions_select_sensor_node_image.setScaledContents(False)
        dashboard.ui.label_sa_inspection_actions_select_sensor_node_image.setAlignment(
            QtCore.Qt.AlignCenter
        )

    # Keep icons only for compact icon-only navigation and file browsing.
    icon_specs = [
        (
            "pushButton_sa_inspection_selection_artifact_left",
            "back.png",
            "Previous artifact",
            True,
            16,
        ),
        (
            "pushButton_sa_inspection_selection_artifact_right",
            "forward.png",
            "Next artifact",
            True,
            16,
        ),
        (
            "pushButton_sa_inspection_selection_file_left",
            "back.png",
            "Previous file",
            True,
            16,
        ),
        (
            "pushButton_sa_inspection_selection_file_right",
            "forward.png",
            "Next file",
            True,
            16,
        ),
        (
            "pushButton_sa_inspection_selection_file_select",
            "folder_black.svg",
            "Select local IQ file",
            True,
            18,
        ),
    ]

    for widget_name, icon_name, tooltip, clear_text, size in icon_specs:
        _sa_inspection_set_button_icon(
            dashboard,
            widget_name,
            icon_name,
            tooltip=tooltip,
            clear_text=clear_text,
            size=size,
        )

    # Ordinary text buttons should remain text-only.
    text_buttons = (
        dashboard.ui.pushButton_sa_inspection_selection_prepare,
        dashboard.ui.pushButton_sa_inspection_overview_zoom,
        dashboard.ui.pushButton_sa_inspection_overview_reset,
        dashboard.ui.pushButton_sa_inspection_overview_full_file,
        dashboard.ui.pushButton_sa_inspection_measurements_set_from_selection,
        dashboard.ui.pushButton_sa_inspection_actions_query,
        dashboard.ui.pushButton_sa_inspection_actions_customize,
        dashboard.ui.pushButton_sa_inspection_findings_save_changes,
    )

    for button in text_buttons:
        button.setIcon(QtGui.QIcon())


def restyle_sa_inspection_canvases(dashboard: QtCore.QObject):
    """Redraw Inspection plots after a FISSURE theme change."""
    _draw_sa_inspection_overview(dashboard)
    _draw_sa_inspection_main(dashboard)


def _sa_inspection_find_soi(dashboard: QtCore.QObject, soi_key: str) -> dict:
    soi = (getattr(dashboard, "tactical_sois", {}) or {}).get(str(soi_key or "").strip())
    return dict(soi) if isinstance(soi, dict) else {}


def _sa_inspection_soi_text(soi: dict) -> str:
    name = _sa_sois_display_name(soi)
    frequency = _sa_sois_value(soi, "frequency_mhz", "center_frequency_mhz")
    frequency_text = _sa_sois_format_frequency(frequency)
    if frequency_text not in ("", "—") and frequency_text not in name:
        return f"{name} ({frequency_text})"
    return name


def refresh_sa_inspection_soi_context(dashboard: QtCore.QObject, preferred_soi_key: str = ""):
    """Refresh the optional SOI context selector without changing the active source."""
    combo = dashboard.ui.comboBox_sa_inspection_selection_soi
    current_key = str(combo.currentData(QtCore.Qt.UserRole) or "").strip()
    pending_key = str(getattr(dashboard, "signal_analysis_prefill_soi_key", "") or "").strip()
    preferred_key = str(preferred_soi_key or pending_key or current_key or "").strip()

    rows = [
        (str(key), record)
        for key, record in (getattr(dashboard, "tactical_sois", {}) or {}).items()
        if isinstance(record, dict)
    ]
    rows.sort(key=lambda item: (_sa_inspection_soi_text(item[1]).lower(), item[0]))

    combo.blockSignals(True)
    combo.clear()
    combo.addItem("Manual / No SOI", "")
    for soi_key, record in rows:
        combo.addItem(_sa_inspection_soi_text(record), soi_key)

    selected_index = 0
    if preferred_key:
        for index in range(combo.count()):
            if str(combo.itemData(index, QtCore.Qt.UserRole) or "").strip() == preferred_key:
                selected_index = index
                break
    combo.setCurrentIndex(selected_index)
    combo.blockSignals(False)

    if pending_key and preferred_key == pending_key and selected_index > 0:
        dashboard.signal_analysis_prefill_soi_key = None

    if getattr(dashboard, "sa_inspection_source", "artifact") == "artifact":
        _refresh_sa_inspection_artifacts(dashboard)
    _update_sa_inspection_findings_controls(dashboard)

def _sa_inspection_artifact_id(key, record: dict) -> str:
    return str(record.get("artifact_id") or record.get("id") or key or "").strip()


def _sa_inspection_artifact_timestamp(record: dict) -> str:
    return str(record.get("modified_at") or record.get("created_at") or record.get("time") or "").strip()


def _sa_inspection_artifact_text(artifact_id: str, record: dict) -> str:
    name = str(record.get("name") or record.get("description") or "Artifact").strip()
    timestamp = _sa_inspection_artifact_timestamp(record).replace("T", " ").split(".")[0]
    parts = [name]
    if timestamp:
        parts.append(timestamp)
    if artifact_id:
        parts.append(artifact_id)
    return " | ".join(parts)


def _sa_inspection_artifact_rows(dashboard: QtCore.QObject) -> list:
    artifacts = getattr(dashboard, "tactical_artifacts", {}) or {}
    if isinstance(artifacts, dict):
        iterable = artifacts.items()
    elif isinstance(artifacts, list):
        iterable = enumerate(artifacts)
    else:
        iterable = []

    soi_key = str(dashboard.ui.comboBox_sa_inspection_selection_soi.currentData(QtCore.Qt.UserRole) or "").strip()
    soi = _sa_inspection_find_soi(dashboard, soi_key)
    linked_ids = collect_soi_artifact_ids(soi) if soi else []
    linked_set = set(linked_ids)

    rows = []
    for key, record in iterable:
        if not isinstance(record, dict):
            continue
        artifact_id = _sa_inspection_artifact_id(key, record)
        if not artifact_id:
            continue
        if soi and artifact_id not in linked_set:
            continue
        rows.append((artifact_id, dict(record)))

    rows.sort(key=lambda item: _sa_inspection_artifact_timestamp(item[1]), reverse=True)
    return rows


def _refresh_sa_inspection_artifacts(dashboard: QtCore.QObject, preferred_artifact_id: str = ""):
    combo = dashboard.ui.comboBox_sa_inspection_selection_artifact
    current = combo.currentData(QtCore.Qt.UserRole)
    current_id = str(current.get("artifact_id") or "").strip() if isinstance(current, dict) else ""
    pending_id = str(getattr(dashboard, "signal_analysis_prefill_artifact_id", "") or "").strip()
    preferred_id = str(preferred_artifact_id or pending_id or current_id or "").strip()

    rows = _sa_inspection_artifact_rows(dashboard)
    combo.blockSignals(True)
    combo.clear()
    for artifact_id, record in rows:
        combo.addItem(
            _sa_inspection_artifact_text(artifact_id, record),
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
        dashboard.signal_analysis_prefill_artifact_id = None

    _slotSA_InspectionArtifactChanged(dashboard)


def _sa_inspection_selected_artifact(dashboard: QtCore.QObject) -> tuple:
    context = dashboard.ui.comboBox_sa_inspection_selection_artifact.currentData(QtCore.Qt.UserRole)
    if not isinstance(context, dict):
        return "", {}
    return str(context.get("artifact_id") or "").strip(), dict(context.get("record") or {})


def _sa_inspection_file_role(file_record: dict) -> str:
    return str(file_record.get("role") or file_record.get("metadata", {}).get("role") or "").strip().lower()


def _sa_inspection_file_name(file_record: dict) -> str:
    return str(
        file_record.get("name")
        or file_record.get("relative_path")
        or file_record.get("path")
        or file_record.get("id")
        or "File"
    ).strip()


def _sa_inspection_manifest_files(record: dict) -> list:
    files = record.get("files", []) if isinstance(record, dict) else []

    if not isinstance(files, list):
        return []

    inspectable = []
    fallback = []

    for item in files:
        if not isinstance(item, dict):
            continue

        role = _sa_inspection_file_role(item)
        name = _sa_inspection_file_name(item).lower()

        if (
            role in {"sigmf_data", "iq_data"}
            or name.endswith(_INSPECTION_DATA_EXTENSIONS)
        ):
            inspectable.append(dict(item))

        elif role == "bundle" or name.endswith(".zip"):
            fallback.append(dict(item))

    return inspectable or fallback


def _sa_inspection_cached_file_map(dashboard: QtCore.QObject, artifact_id: str) -> dict:
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    return controller.get_local_files(artifact_id) if controller is not None and artifact_id else {}


def _sa_inspection_extracted_root(dashboard: QtCore.QObject, artifact_id: str) -> str:
    return os.path.join(
        fissure.utils.HUB_ARTIFACTS_DIR,
        "inspection",
        str(artifact_id or "unknown"),
    )


def _sa_inspection_safe_extract(zip_path: str, destination: str):
    os.makedirs(destination, exist_ok=True)
    destination_real = os.path.realpath(destination)
    with zipfile.ZipFile(zip_path, "r") as handle:
        for member in handle.infolist():
            target = os.path.realpath(os.path.join(destination_real, member.filename))
            if target != destination_real and not target.startswith(destination_real + os.sep):
                raise RuntimeError(f"Unsafe ZIP member path: {member.filename}")
        handle.extractall(destination_real)


def _sa_inspection_extracted_files(
    dashboard: QtCore.QObject,
    artifact_id: str,
) -> list:
    root = _sa_inspection_extracted_root(
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

            if not lower.endswith(_INSPECTION_DATA_EXTENSIONS):
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


def _sa_inspection_file_rows(dashboard: QtCore.QObject, artifact_id: str, record: dict) -> list:
    extracted = _sa_inspection_extracted_files(dashboard, artifact_id)
    if extracted:
        return extracted

    local_map = _sa_inspection_cached_file_map(dashboard, artifact_id)
    rows = []
    for item in _sa_inspection_manifest_files(record):
        file_id = str(item.get("id") or item.get("file_id") or "").strip()
        row = dict(item)
        row["file_id"] = file_id
        row["artifact_id"] = artifact_id
        local_path = str(local_map.get(file_id) or "").strip()
        if local_path:
            row["local_path"] = local_path
        rows.append(row)
    return rows


def _populate_sa_inspection_files(dashboard: QtCore.QObject, preferred_file_id: str = ""):
    combo = dashboard.ui.comboBox_sa_inspection_selection_file
    artifact_id, record = _sa_inspection_selected_artifact(dashboard)
    current = combo.currentData(QtCore.Qt.UserRole)
    current_id = str(current.get("file_id") or current.get("id") or "").strip() if isinstance(current, dict) else ""
    preferred_id = str(preferred_file_id or current_id or "").strip()

    rows = _sa_inspection_file_rows(dashboard, artifact_id, record) if artifact_id else []
    combo.blockSignals(True)
    combo.clear()
    for row in rows:
        combo.addItem(_sa_inspection_file_name(row), row)

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

    _update_sa_inspection_prepare_button(dashboard)
    _slotSA_InspectionFileChanged(dashboard)


def _update_sa_inspection_prepare_button(dashboard: QtCore.QObject):
    button = dashboard.ui.pushButton_sa_inspection_selection_prepare
    artifact_id, record = _sa_inspection_selected_artifact(dashboard)
    if not artifact_id:
        button.setText("Prepare")
        button.setEnabled(False)
        return

    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    local_path = controller.get_local_path(artifact_id) if controller is not None else None
    rows = _sa_inspection_file_rows(dashboard, artifact_id, record)
    has_local_iq = any(
        _sa_inspection_file_role(row) != "bundle"
        and not _sa_inspection_file_name(row).lower().endswith(".zip")
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

def _sa_inspection_sigmf_meta_path(filepath: str) -> str:
    lower = filepath.lower()
    if lower.endswith(".sigmf-data"):
        return filepath[:-11] + ".sigmf-meta"
    if lower.endswith(".sigmf-meta"):
        return filepath
    sidecar = filepath + ".sigmf-meta"
    return sidecar if os.path.isfile(sidecar) else ""


def _sa_inspection_load_sigmf(filepath: str) -> dict:
    meta_path = _sa_inspection_sigmf_meta_path(filepath)
    if not meta_path or not os.path.isfile(meta_path):
        return {}
    try:
        with open(meta_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _sa_inspection_metadata_value(file_record: dict, artifact_record: dict, *keys):
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


def _sa_inspection_float(value, default=None):
    try:
        return float(value)
    except Exception:
        return default


def _sa_inspection_resolve_type(data_type: str, sigmf_type: str = "") -> tuple:
    if sigmf_type in _SIGMF_TYPE_MAP:
        label, dtype, is_complex, interleaved = _SIGMF_TYPE_MAP[sigmf_type]
        return label, dtype, is_complex, interleaved
    if data_type in _FISSURE_TYPE_MAP:
        dtype, is_complex, interleaved = _FISSURE_TYPE_MAP[data_type]
        return data_type, dtype, is_complex, interleaved
    return "Complex Float 32", np.dtype("<c8"), True, False


def _sa_inspection_build_file_metadata(
    dashboard: QtCore.QObject,
    filepath: str,
    file_record: dict = None,
    artifact_record: dict = None,
) -> dict:
    file_record = dict(file_record or {})
    artifact_record = dict(artifact_record or {})
    filepath = os.path.abspath(str(filepath or "").strip())

    sigmf = _sa_inspection_load_sigmf(filepath)
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
        _sa_inspection_metadata_value(
            file_record,
            artifact_record,
            "data_type",
        )
        or ""
    ).strip()

    extension = os.path.splitext(filepath)[1].lower()
    extension_data_type = _INSPECTION_FILE_TYPE_BY_EXTENSION.get(
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
        _sa_inspection_resolve_type(
            data_type,
            sigmf_type,
        )
    )

    sample_rate_hz = _sa_inspection_float(
        sigmf_global.get("core:sample_rate")
    )

    if sample_rate_hz is None:
        sample_rate_msps = _sa_inspection_float(
            _sa_inspection_metadata_value(
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
        sample_rate_hz = _sa_inspection_float(
            _sa_inspection_metadata_value(
                file_record,
                artifact_record,
                "sample_rate",
                "sample_rate_hz",
            )
        )

    center_frequency_hz = _sa_inspection_float(
        first_capture.get("core:frequency")
    )

    if center_frequency_hz is None:
        frequency_mhz = _sa_inspection_float(
            _sa_inspection_metadata_value(
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
            dashboard.ui.comboBox_sa_inspection_selection_soi.currentData(
                QtCore.Qt.UserRole
            )
            or ""
        ).strip()

        soi = _sa_inspection_find_soi(
            dashboard,
            soi_key,
        )

        frequency_mhz = (
            _sa_inspection_float(
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
        "center_frequency_hz": center_frequency_hz,
        "sample_count": sample_count,
        "duration_s": duration_s,
        "size_bytes": size_bytes,
        "sigmf": sigmf,
        "file_record": file_record,
        "artifact_record": artifact_record,
    }


def _sa_inspection_read_samples(metadata: dict, start_sample: int, end_sample: int) -> np.ndarray:
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


def _sa_inspection_read_indices(metadata: dict, indices: np.ndarray) -> np.ndarray:
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

def _sa_inspection_read_display_samples(metadata: dict, start_sample: int, end_sample: int, limit: int) -> tuple:
    count = max(0, int(end_sample) - int(start_sample))
    if count <= limit:
        data = _sa_inspection_read_samples(metadata, start_sample, end_sample)
        indices = np.arange(start_sample, start_sample + len(data), dtype=np.int64)
        return data, indices

    step = max(1, int(math.ceil(count / float(limit))))
    indices = np.arange(start_sample, end_sample, step, dtype=np.int64)[:limit]
    return _sa_inspection_read_indices(metadata, indices), indices


def _sa_inspection_read_centered_samples(metadata: dict, start_sample: int, end_sample: int, limit: int) -> tuple:
    count = max(0, int(end_sample) - int(start_sample))
    if count <= limit:
        return _sa_inspection_read_samples(metadata, start_sample, end_sample), start_sample
    center = start_sample + count // 2
    half = limit // 2
    read_start = max(start_sample, center - half)
    read_end = min(end_sample, read_start + limit)
    read_start = max(start_sample, read_end - limit)
    return _sa_inspection_read_samples(metadata, read_start, read_end), read_start


def _sa_inspection_format_size(size_bytes: int) -> str:
    value = float(size_bytes or 0)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if value < 1024.0 or unit == units[-1]:
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{int(size_bytes)} B"


def _sa_inspection_format_duration(value) -> str:
    value = _sa_inspection_float(value)
    if value is None:
        return "—"
    if value < 1e-3:
        return f"{value * 1e6:.3f} µs"
    if value < 1.0:
        return f"{value * 1e3:.3f} ms"
    return f"{value:.6g} s"


def _sa_inspection_format_sample_rate(value) -> str:
    value = _sa_inspection_float(value)
    if value is None:
        return "—"
    if value >= 1e6:
        return f"{value / 1e6:.6g} MS/s"
    if value >= 1e3:
        return f"{value / 1e3:.6g} kS/s"
    return f"{value:.6g} S/s"


def _sa_inspection_format_frequency(value) -> str:
    value = _sa_inspection_float(value)
    if value is None:
        return "—"
    if abs(value) >= 1e6:
        return f"{value / 1e6:.6f} MHz"
    if abs(value) >= 1e3:
        return f"{value / 1e3:.3f} kHz"
    return f"{value:.3f} Hz"


def _sa_inspection_set_file_metadata(dashboard: QtCore.QObject, metadata: dict = None):
    """Update Card 1 metadata, keeping assumed datatype text compact."""
    metadata = metadata or {}
    dashboard.ui.label2_sa_inspection_selection_sample_rate.setText(
        _sa_inspection_format_sample_rate(metadata.get("sample_rate_hz"))
    )
    dashboard.ui.label2_sa_inspection_selection_center_frequency.setText(
        _sa_inspection_format_frequency(metadata.get("center_frequency_hz"))
    )
    dashboard.ui.label2_sa_inspection_selection_duration.setText(
        _sa_inspection_format_duration(metadata.get("duration_s"))
    )

    data_type = str(metadata.get("data_type") or "—")
    assumed = bool(metadata.get("data_type_assumed") and data_type != "—")
    data_type_widget = dashboard.ui.label2_sa_inspection_selection_data_type
    data_type_widget.setText(f"{data_type}*" if assumed else data_type)
    data_type_tooltip = (
        "Assumed data type. No SigMF or artifact datatype metadata was available for this file."
        if assumed
        else ""
    )
    data_type_widget.setToolTip(data_type_tooltip)
    dashboard.ui.label2_sa_inspection_selection_data_type_label.setToolTip(data_type_tooltip)

    dashboard.ui.label2_sa_inspection_selection_size.setText(
        _sa_inspection_format_size(int(metadata.get("size_bytes") or 0)) if metadata else "—"
    )
    dashboard.ui.label2_sa_inspection_selection_samples.setText(
        f"{int(metadata.get('sample_count') or 0):,}" if metadata else "—"
    )


def _sa_inspection_external_tool_file(dashboard: QtCore.QObject) -> str:
    """Return the prepared local Inspection evidence path."""
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    path = str(metadata.get("path") or "").strip()
    if path and os.path.isfile(path) and not path.lower().endswith(".zip"):
        return path
    return ""


def _launch_sa_inspection_inspectrum(dashboard: QtCore.QObject):
    """Launch Inspectrum, using selected Inspection evidence when available."""
    path = _sa_inspection_external_tool_file(dashboard)
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    sample_rate = _sa_inspection_float(metadata.get("sample_rate_hz"))

    try:
        command = ["inspectrum"]
        if path:
            if sample_rate and sample_rate > 0:
                command.extend(["-r", str(int(round(sample_rate)))])
            command.append(path)
        subprocess.Popen(command)
    except Exception as error:
        dashboard.logger.error(f"Could not launch Inspectrum: {error}")


def _launch_sa_inspection_gqrx(dashboard: QtCore.QObject):
    """Launch Gqrx, preconfigured from Inspection evidence when possible."""
    path = _sa_inspection_external_tool_file(dashboard)
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    sample_rate = _sa_inspection_float(metadata.get("sample_rate_hz"))
    center_frequency = _sa_inspection_float(metadata.get("center_frequency_hz"))

    try:
        if not path or not sample_rate or not center_frequency:
            subprocess.Popen(["gqrx"])
            return

        template_path = os.path.join(fissure.utils.TOOLS_DIR, "Gqrx", "template.conf")
        if not os.path.isfile(template_path):
            dashboard.logger.warning(
                f"Gqrx template not found, launching normally: {template_path}"
            )
            subprocess.Popen(["gqrx"])
            return

        with open(template_path, "rt", encoding="utf-8") as source:
            config_text = source.read()

        config_text = config_text.replace("<file>", path)
        config_text = config_text.replace("<rate>", str(int(round(sample_rate))))
        config_text = config_text.replace("<freq>", str(int(round(center_frequency))))

        with tempfile.NamedTemporaryFile(
            mode="wt",
            encoding="utf-8",
            prefix="fissure_inspection_gqrx_",
            suffix=".conf",
            delete=False,
        ) as config_file:
            config_file.write(config_text)
            config_path = config_file.name

        subprocess.Popen(["gqrx", "-c", config_path])
    except Exception as error:
        dashboard.logger.error(f"Could not launch Gqrx: {error}")


def _launch_sa_inspection_iqengine(dashboard: QtCore.QObject):
    """Launch the existing local IQEngine workflow."""
    try:
        from .. import MenuBarSlots

        MenuBarSlots._slotMenuIQEngineLocalClicked(dashboard)
    except Exception as error:
        dashboard.logger.error(f"Could not launch IQEngine: {error}")


def _launch_sa_inspection_urh(dashboard: QtCore.QObject):
    """Launch Universal Radio Hacker."""
    try:
        from .. import MenuBarSlots

        MenuBarSlots._slotMenuURH_Clicked(dashboard)
    except Exception as error:
        dashboard.logger.error(f"Could not launch Universal Radio Hacker: {error}")


def _initialize_sa_inspection_external_tools(dashboard: QtCore.QObject):
    """Build the compact expandable External Tools launcher list."""
    contents = dashboard.ui.scrollAreaWidgetContents_sa_inspection_external_tools

    existing_layout = contents.layout()
    if existing_layout is None:
        layout = QtWidgets.QVBoxLayout(contents)
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)
    else:
        layout = existing_layout
        layout.setContentsMargins(3, 3, 3, 3)
        layout.setSpacing(3)

    dashboard.sa_inspection_external_tools_layout = layout
    dashboard.sa_inspection_external_tool_buttons = {}

    tools = [
        (
            "Inspectrum",
            "Launch Inspectrum. Uses the selected IQ file and sample rate when available.",
            lambda: _launch_sa_inspection_inspectrum(dashboard),
        ),
        (
            "Gqrx",
            "Launch Gqrx. Uses the selected IQ file, sample rate, and center frequency when available.",
            lambda: _launch_sa_inspection_gqrx(dashboard),
        ),
        (
            "IQEngine",
            "Launch local IQEngine.",
            lambda: _launch_sa_inspection_iqengine(dashboard),
        ),
        (
            "Universal Radio Hacker",
            "Launch Universal Radio Hacker.",
            lambda: _launch_sa_inspection_urh(dashboard),
        ),
    ]

    for name, tooltip, callback in tools:
        button = QtWidgets.QPushButton(name, contents)
        button.setProperty("uiRole", "inspectionToolButton")
        button.setMinimumHeight(25)
        button.setMaximumHeight(25)
        button.setToolTip(tooltip)
        button.clicked.connect(callback)

        layout.addWidget(button)
        dashboard.sa_inspection_external_tool_buttons[name] = button

    layout.addStretch(1)


def _sa_inspection_current_evidence_key(dashboard: QtCore.QObject) -> str:
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    path = str(metadata.get("path") or "").strip()
    artifact_id = str(getattr(dashboard, "sa_inspection_artifact_id", "") or "").strip()
    file_id = str(getattr(dashboard, "sa_inspection_file_id", "") or "").strip()
    if artifact_id or file_id:
        return f"artifact:{artifact_id}:{file_id or path}"
    return f"local:{path}" if path else ""


def _sa_inspection_file_is_ready(metadata: dict) -> bool:
    """Return True only when the selected evidence resolves to a local IQ data file."""
    path = str((metadata or {}).get("path") or "").strip()
    return bool(path and os.path.isfile(path) and not path.lower().endswith(".zip"))


def _activate_sa_inspection_plot_surfaces(dashboard: QtCore.QObject):
    """Reveal plot surfaces once and keep them visible for the rest of the session."""
    if getattr(dashboard, "sa_inspection_plots_activated", False):
        return

    dashboard.sa_inspection_plots_activated = True
    dashboard.ui.frame_sa_inspection_overview_plot.setVisible(True)
    dashboard.ui.frame_sa_inspection_view_plot.setVisible(True)
    for index in range(dashboard.ui.tabWidget_sa_inspection_view.count()):
        dashboard.ui.tabWidget_sa_inspection_view.setTabEnabled(index, True)


def _update_sa_inspection_overview_controls(dashboard: QtCore.QObject):
    """Enable overview controls only while locally plottable evidence is available."""
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    ready = _sa_inspection_file_is_ready(metadata)
    for widget in (
        dashboard.ui.pushButton_sa_inspection_overview_full_file,
        dashboard.ui.pushButton_sa_inspection_overview_reset,
        dashboard.ui.pushButton_sa_inspection_overview_zoom,
        dashboard.ui.textEdit_sa_inspection_overview_start,
        dashboard.ui.textEdit_sa_inspection_overview_end,
    ):
        widget.setEnabled(ready)


def _update_sa_inspection_navigation_controls(dashboard: QtCore.QObject):
    """Disable empty/boundary Artifact navigation controls and respect action locking."""
    locked = bool(getattr(dashboard, "sa_inspection_action_running", False))
    artifact_mode = getattr(dashboard, "sa_inspection_source", "artifact") == "artifact"

    artifact_combo = dashboard.ui.comboBox_sa_inspection_selection_artifact
    artifact_count = artifact_combo.count()
    artifact_index = artifact_combo.currentIndex()
    artifact_available = artifact_mode and not locked and artifact_count > 0
    artifact_combo.setEnabled(artifact_available)
    dashboard.ui.pushButton_sa_inspection_selection_artifact_left.setEnabled(
        artifact_available and artifact_index > 0
    )
    dashboard.ui.pushButton_sa_inspection_selection_artifact_right.setEnabled(
        artifact_available and 0 <= artifact_index < artifact_count - 1
    )

    file_combo = dashboard.ui.comboBox_sa_inspection_selection_file
    file_count = file_combo.count()
    file_index = file_combo.currentIndex()
    file_available = artifact_available and file_count > 0
    file_combo.setEnabled(file_available)
    dashboard.ui.pushButton_sa_inspection_selection_file_left.setEnabled(
        file_available and file_index > 0
    )
    dashboard.ui.pushButton_sa_inspection_selection_file_right.setEnabled(
        file_available and 0 <= file_index < file_count - 1
    )


def _sa_inspection_clear_file(dashboard: QtCore.QObject):
    dashboard.sa_inspection_file_metadata = {}
    dashboard.sa_inspection_file_id = ""
    dashboard.sa_inspection_active_selection = (0.0, 0.0)
    dashboard.sa_inspection_pending_selection = (0.0, 0.0)
    _sa_inspection_set_file_metadata(dashboard)
    dashboard.ui.textEdit_sa_inspection_overview_start.setPlainText("")
    dashboard.ui.textEdit_sa_inspection_overview_end.setPlainText("")
    dashboard.ui.label2_sa_inspection_overview_duration.setText("—")
    _update_sa_inspection_overview_controls(dashboard)
    _clear_sa_inspection_measurement(dashboard)
    _draw_sa_inspection_overview(dashboard)
    _draw_sa_inspection_main(dashboard)
    _refresh_sa_inspection_findings_table(dashboard)
    if hasattr(dashboard, "sa_inspection_action_last_result"):
        _clear_sa_inspection_action_result(dashboard, "Select evidence")
        _update_sa_inspection_action_controls(dashboard)


def _sa_inspection_load_file(
    dashboard: QtCore.QObject,
    filepath: str,
    file_record: dict = None,
    artifact_record: dict = None,
):
    filepath = os.path.abspath(str(filepath or "").strip())
    if filepath.lower().endswith(".sigmf-meta"):
        candidate = filepath[:-11] + ".sigmf-data"
        if os.path.isfile(candidate):
            filepath = candidate
    if not filepath or not os.path.isfile(filepath):
        _sa_inspection_clear_file(dashboard)
        return

    metadata = _sa_inspection_build_file_metadata(dashboard, filepath, file_record, artifact_record)
    dashboard.sa_inspection_file_metadata = metadata
    dashboard.sa_inspection_file_id = str(
        (file_record or {}).get("file_id")
        or (file_record or {}).get("id")
        or ""
    ).strip()

    sample_count = int(metadata.get("sample_count") or 0)
    sample_rate = metadata.get("sample_rate_hz")
    full_end = sample_count / sample_rate if sample_rate else float(sample_count)
    dashboard.sa_inspection_active_selection = (0.0, full_end)
    dashboard.sa_inspection_pending_selection = (0.0, full_end)
    _sa_inspection_set_file_metadata(dashboard, metadata)
    _update_sa_inspection_selection_text(dashboard)
    _update_sa_inspection_overview_controls(dashboard)
    _clear_sa_inspection_measurement(dashboard)

    if _sa_inspection_file_is_ready(metadata):
        _activate_sa_inspection_plot_surfaces(dashboard)

    _draw_sa_inspection_overview(dashboard)
    _draw_sa_inspection_main(dashboard)
    _refresh_sa_inspection_findings_table(dashboard)
    if hasattr(dashboard, "sa_inspection_action_last_result"):
        _clear_sa_inspection_action_result(dashboard, "Ready")
        _update_sa_inspection_action_controls(dashboard)


def _sa_inspection_selection_is_seconds(dashboard: QtCore.QObject) -> bool:
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    return bool(_sa_inspection_float(metadata.get("sample_rate_hz")))


def _sa_inspection_selection_to_samples(dashboard: QtCore.QObject, selection: tuple) -> tuple:
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    total = int(metadata.get("sample_count") or 0)
    sample_rate = _sa_inspection_float(metadata.get("sample_rate_hz"))
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


def _update_sa_inspection_selection_text(dashboard: QtCore.QObject):
    start, end = getattr(dashboard, "sa_inspection_pending_selection", (0.0, 0.0))
    if _sa_inspection_selection_is_seconds(dashboard):
        start_text = f"{float(start):.6f}"
        end_text = f"{float(end):.6f}"
        duration = max(0.0, float(end) - float(start))
        dashboard.ui.label2_sa_inspection_overview_duration.setText(_sa_inspection_format_duration(duration))
    else:
        start_text = str(int(round(start)))
        end_text = str(int(round(end)))
        duration = max(0, int(round(end - start)))
        dashboard.ui.label2_sa_inspection_overview_duration.setText(f"{duration:,} samples")
    dashboard.ui.textEdit_sa_inspection_overview_start.setPlainText(start_text)
    dashboard.ui.textEdit_sa_inspection_overview_end.setPlainText(end_text)


def _sa_inspection_parse_selection_edits(dashboard: QtCore.QObject) -> tuple:
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    if not metadata:
        return (0.0, 0.0)
    try:
        start = float(dashboard.ui.textEdit_sa_inspection_overview_start.toPlainText().strip())
        end = float(dashboard.ui.textEdit_sa_inspection_overview_end.toPlainText().strip())
    except Exception:
        return getattr(dashboard, "sa_inspection_pending_selection", (0.0, 0.0))

    full_end = metadata.get("duration_s") if metadata.get("sample_rate_hz") else float(metadata.get("sample_count") or 0)
    full_end = float(full_end or 0.0)
    start = max(0.0, min(start, full_end))
    end = max(0.0, min(end, full_end))
    if end <= start:
        return getattr(dashboard, "sa_inspection_pending_selection", (0.0, full_end))
    return start, end


def _draw_sa_inspection_overview(dashboard: QtCore.QObject):
    """Draw a compact whole-file navigator with readable x-axis ticks."""
    canvas = getattr(dashboard, "sa_inspection_overview_canvas", None)
    if canvas is None:
        return

    canvas.axes.clear()
    canvas.axes.set_aspect("auto")
    canvas.fig.subplots_adjust(
        left=0.018,
        right=0.982,
        bottom=0.30,
        top=0.95,
    )
    _sa_inspection_style_axes(dashboard, canvas)

    _background, _face, text, grid, i_color, _q_color = _sa_inspection_theme(dashboard)

    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    if not metadata or not _sa_inspection_file_is_ready(metadata):
        canvas.axes.set_xticks([])
        canvas.axes.set_yticks([])
        canvas.draw_idle()
        return

    sample_count = int(metadata.get("sample_count") or 0)
    if sample_count <= 0:
        canvas.axes.set_xticks([])
        canvas.axes.set_yticks([])
        canvas.draw_idle()
        return

    step = max(1, int(math.ceil(sample_count / float(OVERVIEW_POINTS))))
    indices = np.arange(0, sample_count, step, dtype=np.int64)[:OVERVIEW_POINTS]
    preview = _sa_inspection_read_indices(metadata, indices)
    if preview.size == 0:
        canvas.axes.set_xticks([])
        canvas.axes.set_yticks([])
        canvas.draw_idle()
        return

    indices = indices[:preview.size]
    values = (
        np.abs(preview)
        if np.iscomplexobj(preview)
        else np.abs(np.asarray(preview, dtype=np.float64))
    )

    sample_rate = _sa_inspection_float(metadata.get("sample_rate_hz"))
    x = indices / sample_rate if sample_rate else indices

    canvas.axes.plot(x, values, color=i_color, linewidth=0.9)
    canvas.axes.fill_between(x, 0.0, values, color=i_color, alpha=0.08)

    canvas.axes.set_yticks([])
    canvas.axes.set_ylabel("")
    canvas.axes.set_xlabel("")
    canvas.axes.xaxis.set_major_locator(MaxNLocator(nbins=6))
    canvas.axes.tick_params(
        axis="x",
        colors=text,
        labelsize=7,
        length=2,
        pad=1,
    )
    canvas.axes.grid(False)
    canvas.axes.grid(
        True,
        axis="x",
        color=grid,
        alpha=0.40,
        linewidth=0.5,
    )
    canvas.axes.margins(x=0.010, y=0.08)

    start, end = getattr(
        dashboard,
        "sa_inspection_pending_selection",
        (0.0, 0.0),
    )
    if end > start:
        canvas.axes.axvspan(start, end, color=i_color, alpha=0.14)
        canvas.axes.axvline(start, color=i_color, alpha=0.80, linewidth=0.9)
        canvas.axes.axvline(end, color=i_color, alpha=0.80, linewidth=0.9)

    canvas.draw_idle()

    
def _sa_inspection_time_axis(metadata: dict, indices: np.ndarray) -> tuple:
    sample_rate = _sa_inspection_float(metadata.get("sample_rate_hz"))
    if sample_rate:
        return indices / sample_rate, "Time (s)"
    return indices, "Samples"


def _sa_inspection_current_view(dashboard: QtCore.QObject) -> str:
    return str(dashboard.ui.tabWidget_sa_inspection_view.tabText(
        dashboard.ui.tabWidget_sa_inspection_view.currentIndex()
    ) or "Time / I-Q").strip()


def _draw_sa_inspection_main(dashboard: QtCore.QObject):
    """Draw the selected Inspection analysis view."""
    canvas = getattr(dashboard, "sa_inspection_view_canvas", None)
    if canvas is None:
        return

    canvas.axes.clear()
    canvas.axes.set_aspect("auto")
    canvas.fig.subplots_adjust(left=0.105, right=0.985, bottom=0.22, top=0.96)
    _sa_inspection_style_axes(dashboard, canvas)

    _background, face, text, grid, i_color, q_color = _sa_inspection_theme(dashboard)

    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    if not metadata or not _sa_inspection_file_is_ready(metadata):
        canvas.axes.set_xticks([])
        canvas.axes.set_yticks([])
        canvas.draw_idle()
        return

    selection = getattr(dashboard, "sa_inspection_active_selection", (0.0, 0.0))
    start_sample, end_sample = _sa_inspection_selection_to_samples(dashboard, selection)
    if end_sample <= start_sample:
        canvas.draw_idle()
        return

    view = _sa_inspection_current_view(dashboard)
    sample_rate = _sa_inspection_float(metadata.get("sample_rate_hz"))
    center_frequency = _sa_inspection_float(metadata.get("center_frequency_hz"))

    if view in {"Time / I-Q", "Magnitude", "Phase"}:
        data, indices = _sa_inspection_read_display_samples(
            metadata,
            start_sample,
            end_sample,
            MAX_TIME_POINTS,
        )
        x, xlabel = _sa_inspection_time_axis(metadata, indices)

        if view == "Time / I-Q":
            if np.iscomplexobj(data):
                canvas.axes.plot(
                    x,
                    np.real(data),
                    color=i_color,
                    linewidth=0.8,
                    alpha=0.95,
                    label="I",
                )
                canvas.axes.plot(
                    x,
                    np.imag(data),
                    color=q_color,
                    linewidth=0.8,
                    alpha=0.60,
                    label="Q",
                )

                legend = canvas.axes.legend(
                    loc="upper right",
                    fontsize=8,
                    frameon=False,
                    borderpad=0.2,
                    handlelength=1.5,
                )
                for label in legend.get_texts():
                    label.set_color(text)
            else:
                canvas.axes.plot(x, data, color=i_color, linewidth=0.8)

            canvas.axes.set_ylabel("Amplitude", fontsize=9, labelpad=2)

        elif view == "Magnitude":
            canvas.axes.plot(x, np.abs(data), color=i_color, linewidth=0.85)
            canvas.axes.set_ylabel("Magnitude", fontsize=9, labelpad=2)

        else:
            canvas.axes.plot(x, np.angle(data), color=i_color, linewidth=0.85)
            canvas.axes.set_ylabel("Phase (rad)", fontsize=9, labelpad=2)

        canvas.axes.set_xlabel(xlabel, fontsize=9, labelpad=2)
        canvas.axes.margins(x=0.01)

    elif view == "Spectrum":
        data, _read_start = _sa_inspection_read_centered_samples(
            metadata,
            start_sample,
            end_sample,
            MAX_SPECTRUM_SAMPLES,
        )

        if len(data) > 1:
            signal = np.asarray(
                data,
                dtype=np.complex64 if np.iscomplexobj(data) else np.float32,
            )
            signal = signal - np.mean(signal)
            window = np.hanning(len(signal))
            spectrum = np.fft.fftshift(np.fft.fft(signal * window))
            power = 20.0 * np.log10(np.maximum(np.abs(spectrum), 1e-12))
            power -= np.max(power)

            if sample_rate:
                freq = np.fft.fftshift(
                    np.fft.fftfreq(len(signal), d=1.0 / sample_rate)
                )
                if center_frequency is not None:
                    x = (freq + center_frequency) / 1e6
                    canvas.axes.set_xlabel("Frequency (MHz)", fontsize=9, labelpad=2)
                else:
                    x = freq / 1e3
                    canvas.axes.set_xlabel(
                        "Frequency Offset (kHz)",
                        fontsize=9,
                        labelpad=2,
                    )
            else:
                x = np.fft.fftshift(np.fft.fftfreq(len(signal), d=1.0))
                canvas.axes.set_xlabel(
                    "Normalized Frequency",
                    fontsize=9,
                    labelpad=2,
                )

            canvas.axes.plot(x, power, color=i_color, linewidth=0.85)
            canvas.axes.set_ylabel(
                "Relative Power (dB)",
                fontsize=9,
                labelpad=2,
            )
            canvas.axes.margins(x=0.01)

    elif view == "Spectrogram":
        data, read_start = _sa_inspection_read_centered_samples(
            metadata,
            start_sample,
            end_sample,
            MAX_SPECTROGRAM_SAMPLES,
        )

        if len(data) > 16:
            nfft = min(
                1024,
                2 ** int(math.floor(math.log2(max(16, len(data) // 8)))),
            )
            noverlap = nfft // 2
            canvas.axes.grid(False)

            if sample_rate:
                fc = center_frequency or 0.0
                x_start = read_start / sample_rate
                x_end = (read_start + len(data)) / sample_rate

                canvas.axes.specgram(
                    data,
                    NFFT=nfft,
                    Fs=sample_rate,
                    noverlap=noverlap,
                    Fc=fc,
                    xextent=(x_start, x_end),
                    cmap="viridis",
                )

                if center_frequency is not None:
                    canvas.axes.yaxis.set_major_formatter(
                        FuncFormatter(
                            lambda value, _pos: f"{value / 1e6:.3f}"
                        )
                    )
                    canvas.axes.set_ylabel(
                        "Frequency (MHz)",
                        fontsize=9,
                        labelpad=2,
                    )
                else:
                    canvas.axes.yaxis.set_major_formatter(
                        FuncFormatter(
                            lambda value, _pos: f"{value / 1e3:.1f}"
                        )
                    )
                    canvas.axes.set_ylabel(
                        "Frequency Offset (kHz)",
                        fontsize=9,
                        labelpad=2,
                    )

                canvas.axes.set_xlabel("Time (s)", fontsize=9, labelpad=2)
            else:
                canvas.axes.specgram(
                    data,
                    NFFT=nfft,
                    Fs=1.0,
                    noverlap=noverlap,
                    xextent=(read_start, read_start + len(data)),
                    cmap="viridis",
                )
                canvas.axes.set_ylabel(
                    "Normalized Frequency",
                    fontsize=9,
                    labelpad=2,
                )
                canvas.axes.set_xlabel("Samples", fontsize=9, labelpad=2)

    elif view == "IF":
        data, read_start = _sa_inspection_read_centered_samples(
            metadata,
            start_sample,
            end_sample,
            MAX_TIME_POINTS,
        )

        if len(data) > 2 and np.iscomplexobj(data):
            phase = np.unwrap(np.angle(data))

            if sample_rate:
                values = np.diff(phase) * sample_rate / (2.0 * np.pi)
                indices = np.arange(
                    read_start + 1,
                    read_start + 1 + len(values),
                )
                x = indices / sample_rate
                canvas.axes.plot(
                    x,
                    values / 1e3,
                    color=i_color,
                    linewidth=0.8,
                )
                canvas.axes.set_xlabel("Time (s)", fontsize=9, labelpad=2)
                canvas.axes.set_ylabel(
                    "Frequency Offset (kHz)",
                    fontsize=9,
                    labelpad=2,
                )
            else:
                values = np.diff(phase) / (2.0 * np.pi)
                x = np.arange(
                    read_start + 1,
                    read_start + 1 + len(values),
                )
                canvas.axes.plot(x, values, color=i_color, linewidth=0.8)
                canvas.axes.set_xlabel("Samples", fontsize=9, labelpad=2)
                canvas.axes.set_ylabel(
                    "Cycles / Sample",
                    fontsize=9,
                    labelpad=2,
                )

            canvas.axes.margins(x=0.01)

    elif view == "Constellation":
        data, _read_start = _sa_inspection_read_centered_samples(
            metadata,
            start_sample,
            end_sample,
            MAX_CONSTELLATION_POINTS,
        )

        if len(data) and np.iscomplexobj(data):
            canvas.axes.scatter(
                np.real(data),
                np.imag(data),
                s=5,
                color=i_color,
                alpha=0.38,
                edgecolors="none",
            )
            canvas.axes.axhline(
                0.0,
                color=grid,
                alpha=0.55,
                linewidth=0.7,
            )
            canvas.axes.axvline(
                0.0,
                color=grid,
                alpha=0.55,
                linewidth=0.7,
            )
            canvas.axes.set_xlabel("I", fontsize=9, labelpad=2)
            canvas.axes.set_ylabel("Q", fontsize=9, labelpad=2)
            canvas.axes.set_aspect("equal", adjustable="datalim")

    _draw_sa_inspection_measurement_overlay(dashboard)
    canvas.draw_idle()


def _redraw_sa_inspection_main_preserve_view(dashboard: QtCore.QObject):
    """Redraw measurement overlays without discarding toolbar zoom/pan."""
    canvas = getattr(dashboard, "sa_inspection_view_canvas", None)
    if canvas is None:
        return

    xlim = canvas.axes.get_xlim()
    ylim = canvas.axes.get_ylim()

    _draw_sa_inspection_main(dashboard)

    try:
        canvas.axes.set_xlim(xlim)
        canvas.axes.set_ylim(ylim)
        canvas.draw_idle()
    except Exception:
        pass


def _sa_inspection_measurement_mode(dashboard: QtCore.QObject) -> str:
    return "frequency" if dashboard.ui.pushButton_sa_inspection_measurements_frequency.isChecked() else "time"


def _clear_sa_inspection_measurement(dashboard: QtCore.QObject):
    dashboard.sa_inspection_measurement_values = []
    dashboard.ui.textEdit_sa_inspection_measurements_cursor_a.setPlainText("—")
    dashboard.ui.textEdit_sa_inspection_measurements_cursor_b.setPlainText("—")
    dashboard.ui.textEdit_sa_inspection_measurements_delta.setPlainText("—")
    dashboard.ui.textEdit_sa_inspection_measurements_samples.setPlainText("—")
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    dashboard.ui.textEdit_sa_inspection_measurements_sample_rate.setPlainText(
        _sa_inspection_format_sample_rate(metadata.get("sample_rate_hz"))
    )
    dashboard.ui.pushButton_sa_inspection_measurements_save_as_finding.setEnabled(False)
    _update_sa_inspection_measurement_mode_ui(dashboard)


def _update_sa_inspection_measurement_mode_ui(dashboard: QtCore.QObject):
    """Make manual measurement controls match the active analysis view."""
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    ready = _sa_inspection_file_is_ready(metadata)
    sample_rate = (
        _sa_inspection_float(metadata.get("sample_rate_hz"))
        if ready
        else None
    )
    view = _sa_inspection_current_view(dashboard)

    time_views = {
        "Time / I-Q",
        "Magnitude",
        "IF",
        "Phase",
        "Spectrogram",
    }
    frequency_views = {
        "Spectrum",
        "Spectrogram",
    }

    time_supported = ready and view in time_views
    frequency_supported = (
        ready
        and bool(sample_rate)
        and view in frequency_views
    )

    time_button = dashboard.ui.pushButton_sa_inspection_measurements_time
    frequency_button = (
        dashboard.ui.pushButton_sa_inspection_measurements_frequency
    )

    if view == "Constellation":
        time_button.setChecked(False)
        frequency_button.setChecked(False)

    elif view == "Spectrum":
        time_button.setChecked(False)
        frequency_button.setChecked(frequency_supported)

    elif view in {"Time / I-Q", "Magnitude", "IF", "Phase"}:
        time_button.setChecked(time_supported)
        frequency_button.setChecked(False)

    elif view == "Spectrogram":
        if frequency_button.isChecked() and frequency_supported:
            time_button.setChecked(False)
        else:
            time_button.setChecked(time_supported)
            frequency_button.setChecked(False)

    time_selected = bool(
        time_button.isChecked()
        and time_supported
    )
    frequency_selected = bool(
        frequency_button.isChecked()
        and frequency_supported
    )

    # The active mode stays visibly selected, but clicking it again serves no
    # purpose. On Spectrogram, the alternate supported mode remains clickable.
    time_button.setEnabled(
        bool(time_supported and not time_selected)
    )
    frequency_button.setEnabled(
        bool(frequency_supported and not frequency_selected)
    )

    if frequency_selected:
        dashboard.ui.label2_sa_inspection_measurements_delta_label.setText("Δf:")
    elif time_selected:
        dashboard.ui.label2_sa_inspection_measurements_delta_label.setText(
            "Δt:" if sample_rate else "Δn:"
        )
    else:
        dashboard.ui.label2_sa_inspection_measurements_delta_label.setText("Δ:")

    dashboard.ui.pushButton_sa_inspection_measurements_set_from_selection.setEnabled(
        time_selected
    )


def _sa_inspection_format_measurement_value(dashboard: QtCore.QObject, mode: str, value: float) -> str:
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    sample_rate = _sa_inspection_float(metadata.get("sample_rate_hz"))
    center_frequency = _sa_inspection_float(metadata.get("center_frequency_hz"))
    if mode == "time":
        return _sa_inspection_format_duration(value) if sample_rate else f"{int(round(value)):,} samples"
    if center_frequency is not None:
        return _sa_inspection_format_frequency(value)
    return _sa_inspection_format_frequency(value)


def _update_sa_inspection_measurement_values(dashboard: QtCore.QObject):
    values = list(getattr(dashboard, "sa_inspection_measurement_values", []) or [])
    mode = _sa_inspection_measurement_mode(dashboard)
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    sample_rate = _sa_inspection_float(metadata.get("sample_rate_hz"))

    a = values[0] if len(values) > 0 else None
    b = values[1] if len(values) > 1 else None
    dashboard.ui.textEdit_sa_inspection_measurements_cursor_a.setPlainText(
        _sa_inspection_format_measurement_value(dashboard, mode, a) if a is not None else "—"
    )
    dashboard.ui.textEdit_sa_inspection_measurements_cursor_b.setPlainText(
        _sa_inspection_format_measurement_value(dashboard, mode, b) if b is not None else "—"
    )

    if a is not None and b is not None:
        delta = abs(float(b) - float(a))
        dashboard.ui.textEdit_sa_inspection_measurements_delta.setPlainText(
            _sa_inspection_format_duration(delta) if mode == "time" and sample_rate
            else (f"{int(round(delta)):,} samples" if mode == "time" else _sa_inspection_format_frequency(delta))
        )
        if mode == "time":
            sample_delta = int(round(delta * sample_rate)) if sample_rate else int(round(delta))
            dashboard.ui.textEdit_sa_inspection_measurements_samples.setPlainText(f"{sample_delta:,}")
        else:
            dashboard.ui.textEdit_sa_inspection_measurements_samples.setPlainText("—")
        dashboard.ui.pushButton_sa_inspection_measurements_save_as_finding.setEnabled(True)
    else:
        dashboard.ui.textEdit_sa_inspection_measurements_delta.setPlainText("—")
        dashboard.ui.textEdit_sa_inspection_measurements_samples.setPlainText("—")
        dashboard.ui.pushButton_sa_inspection_measurements_save_as_finding.setEnabled(False)

    dashboard.ui.textEdit_sa_inspection_measurements_sample_rate.setPlainText(
        _sa_inspection_format_sample_rate(sample_rate)
    )
    _update_sa_inspection_measurement_mode_ui(dashboard)


def _draw_sa_inspection_measurement_overlay(dashboard: QtCore.QObject):
    """Draw the two active manual-measurement cursors."""
    canvas = getattr(dashboard, "sa_inspection_view_canvas", None)
    if canvas is None:
        return

    values = list(getattr(dashboard, "sa_inspection_measurement_values", []) or [])
    if not values:
        return

    mode = _sa_inspection_measurement_mode(dashboard)
    view = _sa_inspection_current_view(dashboard)
    if mode == "time" and view == "Spectrum":
        return
    if mode == "frequency" and view not in {"Spectrum", "Spectrogram"}:
        return

    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    center_frequency = _sa_inspection_float(metadata.get("center_frequency_hz"))
    cursor_colors = ("#F5A623", "#E74C3C")

    for index, value in enumerate(values[:2]):
        color = cursor_colors[index]
        if mode == "frequency" and view == "Spectrogram":
            canvas.axes.axhline(value, color=color, linestyle="--", linewidth=1.15, alpha=0.95)
        elif mode == "frequency" and view == "Spectrum":
            axis_value = value / (1e6 if center_frequency is not None else 1e3)
            canvas.axes.axvline(axis_value, color=color, linestyle="--", linewidth=1.15, alpha=0.95)
        else:
            canvas.axes.axvline(value, color=color, linestyle="--", linewidth=1.15, alpha=0.95)


def _slotSA_InspectionOverviewPress(dashboard: QtCore.QObject, event):
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    if not _sa_inspection_file_is_ready(metadata):
        return
    if event.inaxes != getattr(dashboard, "sa_inspection_overview_canvas", None).axes or event.xdata is None:
        return
    dashboard.sa_inspection_overview_drag_start = float(event.xdata)


def _slotSA_InspectionOverviewRelease(dashboard: QtCore.QObject, event):
    start = getattr(dashboard, "sa_inspection_overview_drag_start", None)
    if start is None or event.xdata is None:
        dashboard.sa_inspection_overview_drag_start = None
        return
    end = float(event.xdata)
    dashboard.sa_inspection_overview_drag_start = None
    if end == start:
        return
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    full_end = metadata.get("duration_s") if metadata.get("sample_rate_hz") else float(metadata.get("sample_count") or 0)
    full_end = float(full_end or 0.0)
    pending = (max(0.0, min(start, end)), min(full_end, max(start, end)))
    if pending[1] <= pending[0]:
        return
    dashboard.sa_inspection_pending_selection = pending
    _update_sa_inspection_selection_text(dashboard)
    _draw_sa_inspection_overview(dashboard)


def _slotSA_InspectionMainClicked(dashboard: QtCore.QObject, event):
    """Capture a manual measurement point when navigation tools are inactive."""
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    if not _sa_inspection_file_is_ready(metadata):
        return

    canvas = getattr(dashboard, "sa_inspection_view_canvas", None)
    if canvas is None or event.inaxes != canvas.axes or event.button != 1:
        return

    toolbar = getattr(dashboard, "sa_inspection_view_toolbar", None)
    if toolbar is not None and getattr(toolbar, "mode", ""):
        return

    mode = _sa_inspection_measurement_mode(dashboard)
    view = _sa_inspection_current_view(dashboard)

    if view == "Constellation":
        return

    value = None

    if mode == "time":
        if view not in {"Spectrum", "Constellation"} and event.xdata is not None:
            value = float(event.xdata)

    elif mode == "frequency":
        if view == "Spectrum" and event.xdata is not None:
            center = _sa_inspection_float(metadata.get("center_frequency_hz"))
            value = float(event.xdata) * (
                1e6 if center is not None else 1e3
            )

        elif view == "Spectrogram" and event.ydata is not None:
            value = float(event.ydata)

    if value is None:
        return

    values = list(
        getattr(dashboard, "sa_inspection_measurement_values", []) or []
    )
    values = [value] if len(values) >= 2 else values + [value]

    dashboard.sa_inspection_measurement_values = values
    _update_sa_inspection_measurement_values(dashboard)
    _redraw_sa_inspection_main_preserve_view(dashboard)


def _sa_inspection_finding_store(dashboard: QtCore.QObject) -> dict:
    store = getattr(dashboard, "sa_inspection_findings", None)
    if not isinstance(store, dict):
        store = {}
        dashboard.sa_inspection_findings = store
    return store


def _sa_inspection_visible_findings(dashboard: QtCore.QObject) -> list:
    evidence_key = _sa_inspection_current_evidence_key(dashboard)
    rows = [finding for finding in _sa_inspection_finding_store(dashboard).values() if finding.get("evidence_key") == evidence_key]
    rows.sort(key=lambda finding: str(finding.get("created_at") or ""))
    return rows


def _refresh_sa_inspection_findings_table(dashboard: QtCore.QObject, preferred_id: str = ""):
    table = dashboard.ui.tableWidget_sa_inspection_findings
    current_row = table.currentRow()
    current_id = ""
    if current_row >= 0:
        item = table.item(current_row, 0)
        current_id = str(item.data(QtCore.Qt.UserRole) or "").strip() if item is not None else ""
    preferred_id = str(preferred_id or current_id or "").strip()

    table.blockSignals(True)
    table.setRowCount(0)
    selected_row = -1
    for finding in _sa_inspection_visible_findings(dashboard):
        row = table.rowCount()
        table.insertRow(row)
        title_item = QtWidgets.QTableWidgetItem(str(finding.get("title") or "Finding"))
        title_item.setData(QtCore.Qt.UserRole, str(finding.get("finding_id") or ""))
        source_item = QtWidgets.QTableWidgetItem(str(finding.get("source") or "Manual"))
        for item in (title_item, source_item):
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
        table.setItem(row, 0, title_item)
        table.setItem(row, 1, source_item)
        if str(finding.get("finding_id") or "") == preferred_id:
            selected_row = row

    if selected_row < 0 and table.rowCount() > 0:
        selected_row = 0
    if selected_row >= 0:
        table.setCurrentCell(selected_row, 0)
    table.blockSignals(False)
    _slotSA_InspectionFindingSelectionChanged(dashboard)


def _sa_inspection_selected_finding(dashboard: QtCore.QObject) -> dict:
    row = dashboard.ui.tableWidget_sa_inspection_findings.currentRow()
    if row < 0:
        return {}
    item = dashboard.ui.tableWidget_sa_inspection_findings.item(row, 0)
    finding_id = str(item.data(QtCore.Qt.UserRole) or "").strip() if item is not None else ""
    finding = _sa_inspection_finding_store(dashboard).get(finding_id)
    return finding if isinstance(finding, dict) else {}


def _update_sa_inspection_findings_controls(dashboard: QtCore.QObject):
    finding = _sa_inspection_selected_finding(dashboard)
    soi_key = str(dashboard.ui.comboBox_sa_inspection_selection_soi.currentData(QtCore.Qt.UserRole) or "").strip()
    has_finding = bool(finding)
    dashboard.ui.pushButton_sa_inspection_findings_delete.setEnabled(has_finding)
    dashboard.ui.pushButton_sa_inspection_findings_save_changes.setEnabled(has_finding)
    save_to_soi = dashboard.ui.pushButton_sa_inspection_findings_save_to_soi
    saved = bool(finding.get("saved_to_soi")) if finding else False
    save_to_soi.setText("Saved to SOI" if saved else "Save to SOI")
    save_to_soi.setEnabled(has_finding and bool(soi_key) and not saved)


def _sa_inspection_new_finding(dashboard: QtCore.QObject, title: str, source: str, details_text: str, values=None) -> str:
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    finding_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    finding = {
        "finding_id": finding_id,
        "evidence_key": _sa_inspection_current_evidence_key(dashboard),
        "title": str(title or "Finding"),
        "source": str(source or "Manual"),
        "details": str(details_text or ""),
        "values": dict(values or {}),
        "created_at": now,
        "updated_at": now,
        "artifact_id": str(getattr(dashboard, "sa_inspection_artifact_id", "") or ""),
        "file_id": str(getattr(dashboard, "sa_inspection_file_id", "") or ""),
        "file_name": str(metadata.get("name") or ""),
        "file_path": str(metadata.get("path") or ""),
        "selection": list(getattr(dashboard, "sa_inspection_active_selection", (0.0, 0.0))),
        "saved_to_soi": False,
    }
    _sa_inspection_finding_store(dashboard)[finding_id] = finding
    _refresh_sa_inspection_findings_table(dashboard, preferred_id=finding_id)
    return finding_id


def _sa_inspection_measurement_finding(dashboard: QtCore.QObject):
    values = list(getattr(dashboard, "sa_inspection_measurement_values", []) or [])
    if len(values) < 2:
        return
    mode = _sa_inspection_measurement_mode(dashboard)
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    sample_rate = _sa_inspection_float(metadata.get("sample_rate_hz"))
    a, b = values[:2]
    delta = abs(b - a)

    if mode == "time":
        result = {
            "cursor_a": _sa_inspection_format_measurement_value(dashboard, mode, a),
            "cursor_b": _sa_inspection_format_measurement_value(dashboard, mode, b),
            "delta": _sa_inspection_format_duration(delta) if sample_rate else f"{int(round(delta)):,} samples",
            "samples": int(round(delta * sample_rate)) if sample_rate else int(round(delta)),
        }
        title = "Time Measurement"
    else:
        result = {
            "cursor_a": _sa_inspection_format_measurement_value(dashboard, mode, a),
            "cursor_b": _sa_inspection_format_measurement_value(dashboard, mode, b),
            "delta": _sa_inspection_format_frequency(delta),
        }
        title = "Frequency Measurement"

    details = "\n".join(f"{key.replace('_', ' ').title()}: {value}" for key, value in result.items())
    _sa_inspection_new_finding(dashboard, title, "Manual Measurement", details, result)


def _slotSA_InspectionFindingSelectionChanged(dashboard: QtCore.QObject):
    finding = _sa_inspection_selected_finding(dashboard)
    dashboard.ui.textEdit_sa_inspection_findings_title.setPlainText(str(finding.get("title") or ""))
    dashboard.ui.textEdit_sa_inspection_findings_details.setPlainText(str(finding.get("details") or ""))
    _update_sa_inspection_findings_controls(dashboard)


def _slotSA_InspectionAddFindingClicked(dashboard: QtCore.QObject):
    if not _sa_inspection_current_evidence_key(dashboard):
        return
    _sa_inspection_new_finding(dashboard, "New Finding", "Manual", "")


def _slotSA_InspectionDeleteFindingClicked(dashboard: QtCore.QObject):
    finding = _sa_inspection_selected_finding(dashboard)
    finding_id = str(finding.get("finding_id") or "")
    if not finding_id:
        return
    _sa_inspection_finding_store(dashboard).pop(finding_id, None)
    _refresh_sa_inspection_findings_table(dashboard)


def _slotSA_InspectionSaveFindingChangesClicked(dashboard: QtCore.QObject):
    finding = _sa_inspection_selected_finding(dashboard)
    if not finding:
        return
    finding["title"] = dashboard.ui.textEdit_sa_inspection_findings_title.toPlainText().strip() or "Finding"
    finding["details"] = dashboard.ui.textEdit_sa_inspection_findings_details.toPlainText()
    finding["updated_at"] = datetime.now(timezone.utc).isoformat()
    finding["saved_to_soi"] = False
    _refresh_sa_inspection_findings_table(dashboard, preferred_id=str(finding.get("finding_id") or ""))


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_InspectionSaveFindingToSoiClicked(dashboard: QtCore.QObject):
    finding = _sa_inspection_selected_finding(dashboard)
    soi_key = str(dashboard.ui.comboBox_sa_inspection_selection_soi.currentData(QtCore.Qt.UserRole) or "").strip()
    soi = _sa_inspection_find_soi(dashboard, soi_key)
    if not finding or not soi:
        return

    soi_id = str(soi.get("soi_id") or "").strip()
    node_uid = str(soi.get("node_uid") or "").strip()
    if not soi_id:
        await Qt5.async_ok_dialog(dashboard, "The selected SOI does not have a valid SOI ID.")
        return

    snapshot = {
        "name": str(finding.get("title") or "Inspection Finding"),
        "event": "Inspection Finding",
        "source": str(finding.get("source") or "Inspection"),
        "details": str(finding.get("details") or ""),
        "values": dict(finding.get("values") or {}),
        "artifact_id": str(finding.get("artifact_id") or ""),
        "file_id": str(finding.get("file_id") or ""),
        "file_name": str(finding.get("file_name") or ""),
        "selection": list(finding.get("selection") or []),
        "finding_id": str(finding.get("finding_id") or ""),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    await dashboard.backend.signalAnalysisSoiUpdate(
        node_uid=node_uid,
        soi_id=soi_id,
        summary={"analysis_history": [snapshot]},
    )
    finding["saved_to_soi"] = True
    finding["saved_soi_key"] = soi_key
    _update_sa_inspection_findings_controls(dashboard)
    await dashboard.backend.signalAnalysisSoisRefresh()


def _sa_inspection_set_local_file_path(dashboard: QtCore.QObject, filepath: str):
    """Retain a local file path while displaying only its filename."""
    path = os.path.abspath(str(filepath or "").strip()) if filepath else ""
    dashboard.sa_inspection_local_file_path = path

    editor = dashboard.ui.textEdit_sa_inspection_selection_file_name
    editor.setPlainText(os.path.basename(path) if path else "")
    editor.setToolTip(path)


def _update_sa_inspection_source_buttons(dashboard: QtCore.QObject):
    """Keep the active evidence source selected but non-clickable."""
    artifact_selected = (
        getattr(dashboard, "sa_inspection_source", "artifact") == "artifact"
    )

    artifact_button = dashboard.ui.pushButton_sa_inspection_selection_source_artifact
    local_button = dashboard.ui.pushButton_sa_inspection_selection_source_local_file

    artifact_button.setChecked(artifact_selected)
    local_button.setChecked(not artifact_selected)

    artifact_button.setEnabled(not artifact_selected)
    local_button.setEnabled(artifact_selected)
    _update_sa_inspection_navigation_controls(dashboard)


def _slotSA_InspectionSourceArtifactClicked(dashboard: QtCore.QObject):
    """Switch to Artifact evidence."""
    if getattr(dashboard, "sa_inspection_source", "") == "artifact":
        _update_sa_inspection_source_buttons(dashboard)
        dashboard.ui.stackedWidget_sa_inspection_selection_source.setCurrentIndex(0)
        return

    dashboard.sa_inspection_source = "artifact"
    dashboard.ui.stackedWidget_sa_inspection_selection_source.setCurrentIndex(0)
    _update_sa_inspection_source_buttons(dashboard)
    _refresh_sa_inspection_artifacts(dashboard)


def _slotSA_InspectionSourceLocalFileClicked(dashboard: QtCore.QObject):
    """Switch to Local File evidence."""
    if getattr(dashboard, "sa_inspection_source", "") == "local":
        _update_sa_inspection_source_buttons(dashboard)
        dashboard.ui.stackedWidget_sa_inspection_selection_source.setCurrentIndex(1)
        return

    dashboard.sa_inspection_source = "local"
    dashboard.ui.stackedWidget_sa_inspection_selection_source.setCurrentIndex(1)
    _update_sa_inspection_source_buttons(dashboard)

    dashboard.sa_inspection_artifact_id = ""
    dashboard.sa_inspection_file_id = ""

    path = str(
        getattr(dashboard, "sa_inspection_local_file_path", "") or ""
    ).strip()

    if path and os.path.isfile(path):
        _sa_inspection_load_file(dashboard, path)
    else:
        _sa_inspection_clear_file(dashboard)


def _slotSA_InspectionSoiChanged(dashboard: QtCore.QObject):
    if getattr(dashboard, "sa_inspection_source", "artifact") == "artifact":
        _refresh_sa_inspection_artifacts(dashboard)
    else:
        metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
        path = str(metadata.get("path") or "")
        if path and os.path.isfile(path):
            _sa_inspection_load_file(dashboard, path)
    _update_sa_inspection_findings_controls(dashboard)


def _slotSA_InspectionArtifactChanged(dashboard: QtCore.QObject):
    artifact_id, _record = _sa_inspection_selected_artifact(dashboard)
    dashboard.sa_inspection_artifact_id = artifact_id
    _populate_sa_inspection_files(dashboard)
    _update_sa_inspection_navigation_controls(dashboard)


def _slotSA_InspectionFileChanged(dashboard: QtCore.QObject):
    _update_sa_inspection_navigation_controls(dashboard)
    context = dashboard.ui.comboBox_sa_inspection_selection_file.currentData(QtCore.Qt.UserRole)
    if not isinstance(context, dict):
        _sa_inspection_clear_file(dashboard)
        return

    artifact_id, artifact_record = _sa_inspection_selected_artifact(dashboard)
    dashboard.sa_inspection_artifact_id = artifact_id
    dashboard.sa_inspection_file_id = str(
        context.get("file_id") or context.get("id") or ""
    ).strip()
    role = _sa_inspection_file_role(context)
    name = _sa_inspection_file_name(context)
    local_path = str(context.get("local_path") or "").strip()

    if (
        role != "bundle"
        and not name.lower().endswith(".zip")
        and local_path
        and os.path.isfile(local_path)
    ):
        _sa_inspection_load_file(dashboard, local_path, context, artifact_record)
        return

    artifact_meta = (
        artifact_record.get("metadata", {})
        if isinstance(artifact_record.get("metadata"), dict)
        else {}
    )
    placeholder_path = str(
        context.get("path")
        or context.get("relative_path")
        or context.get("name")
        or ""
    )
    metadata = _sa_inspection_build_file_metadata(
        dashboard,
        placeholder_path,
        context,
        artifact_record,
    )
    metadata["path"] = ""

    if role == "bundle" or name.lower().endswith(".zip"):
        sample_rate_msps = _sa_inspection_float(artifact_meta.get("sample_rate_msps"))
        frequency_mhz = _sa_inspection_float(artifact_meta.get("frequency_mhz"))
        if metadata.get("sample_rate_hz") is None and sample_rate_msps is not None:
            metadata["sample_rate_hz"] = sample_rate_msps * 1e6
        if metadata.get("center_frequency_hz") is None and frequency_mhz is not None:
            metadata["center_frequency_hz"] = frequency_mhz * 1e6
        metadata["data_type"] = str(
            artifact_meta.get("data_type")
            or metadata.get("data_type")
            or "—"
        )
        metadata["data_type_assumed"] = False
        metadata["sample_count"] = int(
            artifact_meta.get("file_length")
            or metadata.get("sample_count")
            or 0
        )
        metadata["duration_s"] = _sa_inspection_float(
            artifact_meta.get("duration_s"),
            metadata.get("duration_s"),
        )

    dashboard.sa_inspection_file_metadata = metadata
    dashboard.sa_inspection_active_selection = (0.0, 0.0)
    dashboard.sa_inspection_pending_selection = (0.0, 0.0)
    _sa_inspection_set_file_metadata(dashboard, metadata)
    dashboard.ui.textEdit_sa_inspection_overview_start.setPlainText("")
    dashboard.ui.textEdit_sa_inspection_overview_end.setPlainText("")
    dashboard.ui.label2_sa_inspection_overview_duration.setText("—")
    _update_sa_inspection_overview_controls(dashboard)
    _clear_sa_inspection_measurement(dashboard)
    _draw_sa_inspection_overview(dashboard)
    _draw_sa_inspection_main(dashboard)
    _refresh_sa_inspection_findings_table(dashboard)


def _slotSA_InspectionPreviousArtifactClicked(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_sa_inspection_selection_artifact
    if combo.count() > 0:
        combo.setCurrentIndex(max(0, combo.currentIndex() - 1))


def _slotSA_InspectionNextArtifactClicked(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_sa_inspection_selection_artifact
    if combo.count() > 0:
        combo.setCurrentIndex(min(combo.count() - 1, combo.currentIndex() + 1))


def _slotSA_InspectionPreviousFileClicked(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_sa_inspection_selection_file
    if combo.count() > 0:
        combo.setCurrentIndex(max(0, combo.currentIndex() - 1))


def _slotSA_InspectionNextFileClicked(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_sa_inspection_selection_file
    if combo.count() > 0:
        combo.setCurrentIndex(min(combo.count() - 1, combo.currentIndex() + 1))


def _slotSA_InspectionLocalFileSelectClicked(
    dashboard: QtCore.QObject,
):
    """Choose a local Inspection data file and display only its basename."""
    current = str(
        getattr(
            dashboard,
            "sa_inspection_local_file_path",
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
        *_INSPECTION_DATA_EXTENSIONS,
    )
    known_patterns = " ".join(
        f"*{extension}"
        for extension in known_extensions
    )

    filepath, _selected_filter = QtWidgets.QFileDialog.getOpenFileName(
        dashboard,
        "Select Inspection File",
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

    _sa_inspection_set_local_file_path(
        dashboard,
        filepath,
    )
    dashboard.sa_inspection_artifact_id = ""
    dashboard.sa_inspection_file_id = ""
    _sa_inspection_load_file(
        dashboard,
        filepath,
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_InspectionPrepareClicked(dashboard: QtCore.QObject):
    artifact_id, record = _sa_inspection_selected_artifact(dashboard)
    if not artifact_id:
        return
    controller = getattr(dashboard.backend, "artifact_transfer_controller", None)
    local_path = controller.get_local_path(artifact_id) if controller is not None else None

    if not local_path:
        dashboard.sa_inspection_prepare_artifact_id = artifact_id
        dashboard.ui.pushButton_sa_inspection_selection_prepare.setEnabled(False)
        dashboard.ui.pushButton_sa_inspection_selection_prepare.setText("Downloading...")
        try:
            await dashboard.backend.requestDashboardArtifactDownload(artifact_id)
        except Exception as error:
            dashboard.sa_inspection_prepare_artifact_id = ""
            _update_sa_inspection_prepare_button(dashboard)
            await Qt5.async_ok_dialog(dashboard, f"Unable to download artifact.\n\n{error}")
        return

    if os.path.isfile(local_path) and local_path.lower().endswith(".zip"):
        destination = _sa_inspection_extracted_root(dashboard, artifact_id)
        dashboard.ui.pushButton_sa_inspection_selection_prepare.setEnabled(False)
        dashboard.ui.pushButton_sa_inspection_selection_prepare.setText("Preparing...")
        loop = asyncio.get_event_loop()
        try:
            if os.path.isdir(destination):
                shutil.rmtree(destination)
            await loop.run_in_executor(None, _sa_inspection_safe_extract, local_path, destination)
        except Exception as error:
            await Qt5.async_ok_dialog(dashboard, f"Unable to prepare artifact.\n\n{error}")
        finally:
            _populate_sa_inspection_files(dashboard)
        return

    _populate_sa_inspection_files(dashboard)


def refresh_sa_inspection_artifact_state(dashboard: QtCore.QObject, artifact_id: str = ""):
    """Refresh Inspection after Artifact metadata or transfer state changes."""
    current_id, _record = _sa_inspection_selected_artifact(dashboard)
    preferred = str(artifact_id or current_id or "").strip()
    if getattr(dashboard, "sa_inspection_source", "artifact") == "artifact":
        _refresh_sa_inspection_artifacts(dashboard, preferred_artifact_id=preferred)


def handle_sa_inspection_artifact_metadata(dashboard: QtCore.QObject, node_uid: str = "", artifacts: list = None):
    """Refresh the Inspection Artifact selector after canonical metadata arrives."""
    if getattr(dashboard, "sa_inspection_source", "artifact") != "artifact":
        return
    _refresh_sa_inspection_artifacts(dashboard)


def handle_sa_inspection_artifact_download_complete(dashboard: QtCore.QObject, artifact_id: str):
    """Refresh Inspection only for the Artifact download it explicitly requested."""
    pending = str(
        getattr(dashboard, "sa_inspection_prepare_artifact_id", "")
        or ""
    ).strip()
    completed = str(artifact_id or "").strip()

    if not pending or pending != completed:
        return

    dashboard.sa_inspection_prepare_artifact_id = ""
    refresh_sa_inspection_artifact_state(dashboard, completed)


def _slotSA_InspectionOverviewZoomClicked(dashboard: QtCore.QObject):
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    if not _sa_inspection_file_is_ready(metadata):
        return
    selection = _sa_inspection_parse_selection_edits(dashboard)
    dashboard.sa_inspection_pending_selection = selection
    dashboard.sa_inspection_active_selection = selection
    _update_sa_inspection_selection_text(dashboard)
    _clear_sa_inspection_measurement(dashboard)
    if hasattr(dashboard, "sa_inspection_action_last_result"):
        _clear_sa_inspection_action_result(dashboard, "Ready")
    _draw_sa_inspection_overview(dashboard)
    _draw_sa_inspection_main(dashboard)


def _slotSA_InspectionOverviewResetClicked(dashboard: QtCore.QObject):
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    if not _sa_inspection_file_is_ready(metadata):
        return
    dashboard.sa_inspection_pending_selection = tuple(getattr(dashboard, "sa_inspection_active_selection", (0.0, 0.0)))
    _update_sa_inspection_selection_text(dashboard)
    _draw_sa_inspection_overview(dashboard)


def _slotSA_InspectionOverviewFullFileClicked(dashboard: QtCore.QObject):
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    if not _sa_inspection_file_is_ready(metadata):
        return
    full_end = metadata.get("duration_s") if metadata.get("sample_rate_hz") else float(metadata.get("sample_count") or 0)
    selection = (0.0, float(full_end or 0.0))
    dashboard.sa_inspection_pending_selection = selection
    dashboard.sa_inspection_active_selection = selection
    _update_sa_inspection_selection_text(dashboard)
    _clear_sa_inspection_measurement(dashboard)
    if hasattr(dashboard, "sa_inspection_action_last_result"):
        _clear_sa_inspection_action_result(dashboard, "Ready")
    _draw_sa_inspection_overview(dashboard)
    _draw_sa_inspection_main(dashboard)


def _slotSA_InspectionViewChanged(dashboard: QtCore.QObject):
    """Redraw the selected analysis lens and reset manual measurements."""
    _clear_sa_inspection_measurement(dashboard)
    _draw_sa_inspection_main(dashboard)

    toolbar = getattr(dashboard, "sa_inspection_view_toolbar", None)
    if toolbar is not None:
        try:
            toolbar.update()
        except Exception:
            pass


def _slotSA_InspectionMeasurementTimeClicked(dashboard: QtCore.QObject):
    if not dashboard.ui.pushButton_sa_inspection_measurements_time.isEnabled():
        return

    dashboard.ui.pushButton_sa_inspection_measurements_time.setChecked(True)
    dashboard.ui.pushButton_sa_inspection_measurements_frequency.setChecked(False)
    _clear_sa_inspection_measurement(dashboard)
    _redraw_sa_inspection_main_preserve_view(dashboard)


def _slotSA_InspectionMeasurementFrequencyClicked(dashboard: QtCore.QObject):
    if not dashboard.ui.pushButton_sa_inspection_measurements_frequency.isEnabled():
        return

    dashboard.ui.pushButton_sa_inspection_measurements_time.setChecked(False)
    dashboard.ui.pushButton_sa_inspection_measurements_frequency.setChecked(True)
    _clear_sa_inspection_measurement(dashboard)
    _redraw_sa_inspection_main_preserve_view(dashboard)


def _slotSA_InspectionMeasurementFromSelectionClicked(dashboard: QtCore.QObject):
    if (
        not dashboard.ui.pushButton_sa_inspection_measurements_set_from_selection.isEnabled()
        or _sa_inspection_measurement_mode(dashboard) != "time"
    ):
        return

    dashboard.sa_inspection_measurement_values = list(
        getattr(
            dashboard,
            "sa_inspection_pending_selection",
            (0.0, 0.0),
        )
    )
    _update_sa_inspection_measurement_values(dashboard)
    _redraw_sa_inspection_main_preserve_view(dashboard)


def _slotSA_InspectionMeasurementSaveFindingClicked(dashboard: QtCore.QObject):
    _sa_inspection_measurement_finding(dashboard)


def _sa_inspection_selected_node_available(dashboard: QtCore.QObject) -> bool:
    """Return True when an online Sensor Node is selected."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        return False
    node_state = (getattr(dashboard, "node_states", {}) or {}).get(node_uid)
    return not (isinstance(node_state, dict) and node_state.get("connected") is False)


def _sa_inspection_action_local_ready(dashboard: QtCore.QObject) -> bool:
    """Return True when prepared evidence and a local Sensor Node are available."""
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    return bool(
        _sa_inspection_file_is_ready(metadata)
        and _sa_inspection_selected_node_available(dashboard)
        and not selected_node_is_remote(dashboard)
    )


def update_sa_inspection_selected_node_gate(dashboard: QtCore.QObject):
    """Show Analysis Actions only for the selected Local Sensor Node."""
    running = bool(getattr(dashboard, "sa_inspection_action_running", False))
    node_available = _sa_inspection_selected_node_available(dashboard)
    local_node = node_available and not selected_node_is_remote(dashboard)

    if local_node or running:
        dashboard.ui.stackedWidget_sa_inspection_actions.setCurrentWidget(
            dashboard.ui.page_sa_inspection_actions_controls
        )
    else:
        dashboard.ui.stackedWidget_sa_inspection_actions.setCurrentWidget(
            dashboard.ui.page_sa_inspection_actions_no_node
        )


def _clear_sa_inspection_parameter_widgets(dashboard: QtCore.QObject):
    """Clear dynamically generated Inspection action parameters."""
    contents = dashboard.ui.scrollAreaWidgetContents_sa_inspection_actions_parameters
    layout = contents.layout()

    if layout is None:
        layout = QtWidgets.QVBoxLayout(contents)

    while layout.count():
        item = layout.takeAt(0)

        widget = item.widget()
        if widget is not None:
            widget.deleteLater()
            continue

        child_layout = item.layout()
        if child_layout is not None:
            while child_layout.count():
                child_item = child_layout.takeAt(0)
                child_widget = child_item.widget()
                if child_widget is not None:
                    child_widget.deleteLater()
            child_layout.deleteLater()

    layout.setContentsMargins(0, 2, 2, 2)
    layout.setSpacing(4)

    contents.setMinimumWidth(0)

    dashboard.sa_inspection_action_parameter_widgets = {}
    dashboard.sa_inspection_action_schema = {}
    dashboard.sa_inspection_action_customized = False


def _reset_sa_inspection_action_selection(dashboard: QtCore.QObject):
    """Clear Inspection plugin/action selection and parameters."""
    dashboard.sa_inspection_action_catalog = []
    dashboard.sa_inspection_selected_plugin = ""
    dashboard.sa_inspection_selected_action = ""

    for combo in (
        dashboard.ui.comboBox_sa_inspection_actions_plugin,
        dashboard.ui.comboBox_sa_inspection_actions_action,
    ):
        combo.blockSignals(True)
        combo.clear()
        combo.blockSignals(False)
        combo.setEnabled(False)

    _clear_sa_inspection_parameter_widgets(dashboard)
    dashboard.ui.pushButton_sa_inspection_actions_customize.setText("Customize")
    dashboard.ui.pushButton_sa_inspection_actions_customize.setEnabled(False)


def _clear_sa_inspection_action_result(
    dashboard: QtCore.QObject,
    status_text: str = "Ready",
):
    """Clear the transient plugin result for the current evidence."""
    dashboard.sa_inspection_action_last_result = None
    dashboard.sa_inspection_action_last_result_plugin = ""
    dashboard.sa_inspection_action_last_result_action = ""

    dialog = getattr(dashboard, "sa_inspection_result_dialog", None)
    if dialog is not None:
        try:
            dialog.close()
        except Exception:
            pass
        dashboard.sa_inspection_result_dialog = None

    dashboard.ui.pushButton_sa_inspection_actions_view_result.setEnabled(False)
    dashboard.ui.pushButton_sa_inspection_actions_save_as_finding.setEnabled(False)

    if not bool(
        getattr(
            dashboard,
            "sa_inspection_action_running",
            False,
        )
    ):
        dashboard.ui.label_sa_inspection_actions_status.setText(status_text)


def _update_sa_inspection_action_controls(dashboard: QtCore.QObject):
    """Refresh Analysis Actions controls from evidence/node/action state."""
    ready = _sa_inspection_file_is_ready(getattr(dashboard, "sa_inspection_file_metadata", {}) or {})
    node_available = _sa_inspection_selected_node_available(dashboard)
    local_node = node_available and not selected_node_is_remote(dashboard)
    running = bool(getattr(dashboard, "sa_inspection_action_running", False))
    has_action = bool(
        getattr(dashboard, "sa_inspection_selected_plugin", "")
        and getattr(dashboard, "sa_inspection_selected_action", "")
    )
    has_result = getattr(
        dashboard,
        "sa_inspection_action_last_result",
        None,
    ) is not None

    update_sa_inspection_selected_node_gate(dashboard)

    dashboard.ui.pushButton_sa_inspection_actions_view_result.setEnabled(has_result)

    dashboard.ui.pushButton_sa_inspection_actions_query.setEnabled(ready and local_node and not running)
    dashboard.ui.comboBox_sa_inspection_actions_plugin.setEnabled(
        local_node and dashboard.ui.comboBox_sa_inspection_actions_plugin.count() > 0 and not running
    )
    dashboard.ui.comboBox_sa_inspection_actions_action.setEnabled(
        local_node and dashboard.ui.comboBox_sa_inspection_actions_action.count() > 0 and not running
    )
    dashboard.ui.pushButton_sa_inspection_actions_customize.setEnabled(local_node and has_action and not running)

    for record in (getattr(dashboard, "sa_inspection_action_parameter_widgets", {}) or {}).values():
        widget = record.get("widget") if isinstance(record, dict) else None
        if widget is not None:
            widget.setEnabled(not running)

    dashboard.ui.pushButton_sa_inspection_actions_start_stop.setEnabled(
        bool(
            running
            or (
                ready
                and local_node
                and has_action
                and getattr(dashboard, "sa_inspection_action_customized", False)
            )
        )
    )

    if running:
        return
    if not ready:
        dashboard.ui.label_sa_inspection_actions_status.setText("Select evidence")
    elif not node_available:
        dashboard.ui.label_sa_inspection_actions_status.setText("Select Local Sensor Node")
    elif not local_node:
        dashboard.ui.label_sa_inspection_actions_status.setText("Local Sensor Node required")
    elif not has_action and dashboard.sa_inspection_action_last_result is None:
        dashboard.ui.label_sa_inspection_actions_status.setText("Ready")


def refresh_sa_inspection_action_state(dashboard: QtCore.QObject):
    """Refresh the Analysis Actions node gate and control availability."""
    _update_sa_inspection_action_controls(dashboard)


def _populate_sa_inspection_actions_for_plugin(dashboard: QtCore.QObject, preferred_action: str = ""):
    """Populate actions belonging to the selected Inspection plugin."""
    plugin_name = str(dashboard.ui.comboBox_sa_inspection_actions_plugin.currentText() or "").strip()
    action_combo = dashboard.ui.comboBox_sa_inspection_actions_action
    matches = []

    action_combo.blockSignals(True)
    action_combo.clear()
    for record in getattr(dashboard, "sa_inspection_action_catalog", []) or []:
        if not isinstance(record, dict):
            continue
        if str(record.get("plugin") or "").strip() != plugin_name:
            continue
        action_name = str(record.get("action") or "").strip()
        if action_name:
            matches.append(record)
            action_combo.addItem(action_name, record)

    if preferred_action:
        index = action_combo.findText(preferred_action, QtCore.Qt.MatchExactly)
        if index >= 0:
            action_combo.setCurrentIndex(index)
    if action_combo.currentIndex() < 0 and action_combo.count() > 0:
        action_combo.setCurrentIndex(0)
    action_combo.blockSignals(False)

    dashboard.sa_inspection_selected_plugin = plugin_name if matches else ""
    dashboard.sa_inspection_selected_action = str(action_combo.currentText() or "").strip() if matches else ""
    _clear_sa_inspection_parameter_widgets(dashboard)
    _update_sa_inspection_action_controls(dashboard)


def _populate_sa_inspection_action_catalog(dashboard: QtCore.QObject):
    """Populate plugin/action selectors from the cached Inspection catalog."""
    plugin_combo = dashboard.ui.comboBox_sa_inspection_actions_plugin
    current_plugin = str(plugin_combo.currentText() or "").strip()
    plugins = sorted(
        {
            str(record.get("plugin") or "").strip()
            for record in (getattr(dashboard, "sa_inspection_action_catalog", []) or [])
            if isinstance(record, dict) and str(record.get("plugin") or "").strip()
        },
        key=str.lower,
    )

    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.addItems(plugins)
    if current_plugin:
        index = plugin_combo.findText(current_plugin, QtCore.Qt.MatchExactly)
        if index >= 0:
            plugin_combo.setCurrentIndex(index)
    if plugin_combo.currentIndex() < 0 and plugin_combo.count() > 0:
        plugin_combo.setCurrentIndex(0)
    plugin_combo.blockSignals(False)

    _populate_sa_inspection_actions_for_plugin(dashboard)


def _create_sa_inspection_parameter_widget(parent, parameter: dict):
    """Create one editor from a generic Inspection action-schema parameter."""
    parameter_type = str(parameter.get("type", "string") or "string").strip().lower()
    name = str(parameter.get("name") or "").strip()
    default = parameter.get("default", "")
    options = parameter.get("options", []) or []

    if isinstance(options, list) and options:
        widget = QtWidgets.QComboBox(parent)
        widget.addItems([str(option) for option in options])
        index = widget.findText(str(default), QtCore.Qt.MatchExactly)
        if index >= 0:
            widget.setCurrentIndex(index)
    elif parameter_type in {"int", "integer"}:
        widget = QtWidgets.QSpinBox(parent)
        widget.setRange(int(parameter.get("min", -2147483647)), int(parameter.get("max", 2147483647)))
        widget.setSingleStep(int(parameter.get("step", 1)))
        widget.setValue(int(default or 0))
    elif parameter_type in {"float", "double", "number"}:
        widget = QtWidgets.QDoubleSpinBox(parent)
        widget.setDecimals(int(parameter.get("decimals", 6)))
        widget.setRange(float(parameter.get("min", -1e12)), float(parameter.get("max", 1e12)))
        widget.setSingleStep(float(parameter.get("step", 1.0)))
        widget.setValue(float(default or 0.0))
    elif parameter_type in {"bool", "boolean"}:
        widget = QtWidgets.QCheckBox(parent)
        widget.setChecked(
            default.strip().lower() in {"true", "1", "yes", "on", "enabled"}
            if isinstance(default, str)
            else bool(default)
        )
    elif parameter_type == "label":
        widget = QtWidgets.QLabel(str(default or ""), parent)
        widget.setWordWrap(True)
        widget.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
    else:
        widget = QtWidgets.QLineEdit(str(default or ""), parent)

    widget.setObjectName(f"sa_inspection_action_parameter_{name}")
    description = str(parameter.get("description") or "").strip()
    if description:
        widget.setToolTip(description)
    return widget


def _sa_inspection_parameter_value(widget):
    if isinstance(widget, QtWidgets.QComboBox):
        return widget.currentText()
    if isinstance(widget, (QtWidgets.QDoubleSpinBox, QtWidgets.QSpinBox)):
        return widget.value()
    if isinstance(widget, QtWidgets.QCheckBox):
        return widget.isChecked()
    if isinstance(widget, QtWidgets.QLineEdit):
        return widget.text()
    if isinstance(widget, QtWidgets.QLabel):
        return widget.text()
    return None


def _sa_inspection_collect_action_parameters(dashboard: QtCore.QObject) -> dict:
    """Collect schema values and attach the active evidence/range context."""
    metadata = getattr(dashboard, "sa_inspection_file_metadata", {}) or {}
    if not _sa_inspection_file_is_ready(metadata):
        raise ValueError("Select prepared Inspection evidence before running analysis.")

    parameters = {}
    for name, record in (getattr(dashboard, "sa_inspection_action_parameter_widgets", {}) or {}).items():
        if not isinstance(record, dict):
            continue
        widget = record.get("widget")
        schema = record.get("schema", {})
        if widget is None or str(schema.get("type") or "").strip().lower() == "label":
            continue
        parameters[name] = _sa_inspection_parameter_value(widget)

    start_sample, end_sample = _sa_inspection_selection_to_samples(
        dashboard,
        tuple(getattr(dashboard, "sa_inspection_active_selection", (0.0, 0.0))),
    )
    sigmf = metadata.get("sigmf", {}) if isinstance(metadata.get("sigmf"), dict) else {}
    sigmf_global = sigmf.get("global", {}) if isinstance(sigmf.get("global"), dict) else {}
    soi_key = str(dashboard.ui.comboBox_sa_inspection_selection_soi.currentData(QtCore.Qt.UserRole) or "").strip()
    operation_id = str(uuid.uuid4())

    parameters["operation_id"] = operation_id
    parameters["requester"] = "dashboard"
    parameters["_fissure_inspection_context"] = {
        "filepath": str(metadata.get("path") or ""),
        "file_name": str(metadata.get("name") or ""),
        "artifact_id": str(getattr(dashboard, "sa_inspection_artifact_id", "") or ""),
        "file_id": str(getattr(dashboard, "sa_inspection_file_id", "") or ""),
        "soi_key": soi_key,
        "data_type": str(metadata.get("data_type") or ""),
        "sigmf_datatype": str(sigmf_global.get("core:datatype") or ""),
        "sample_rate_hz": _sa_inspection_float(metadata.get("sample_rate_hz")),
        "center_frequency_hz": _sa_inspection_float(metadata.get("center_frequency_hz")),
        "sample_count": int(metadata.get("sample_count") or 0),
        "selection_start": float(getattr(dashboard, "sa_inspection_active_selection", (0.0, 0.0))[0]),
        "selection_end": float(getattr(dashboard, "sa_inspection_active_selection", (0.0, 0.0))[1]),
        "selection_units": "seconds" if _sa_inspection_selection_is_seconds(dashboard) else "samples",
        "start_sample": int(start_sample),
        "end_sample": int(end_sample),
    }
    return parameters


def _set_sa_inspection_action_start_stop_button(dashboard: QtCore.QObject, running: bool):
    button = dashboard.ui.pushButton_sa_inspection_actions_start_stop
    button.setText("Stop" if running else "Start")
    button.setProperty("running", bool(running))
    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


def _set_sa_inspection_action_evidence_locked(dashboard: QtCore.QObject, locked: bool):
    """Prevent the active evidence from changing while an analysis operation runs."""
    for widget in (
        dashboard.ui.pushButton_sa_inspection_selection_source_artifact,
        dashboard.ui.pushButton_sa_inspection_selection_source_local_file,
        dashboard.ui.comboBox_sa_inspection_selection_soi,
        dashboard.ui.comboBox_sa_inspection_selection_artifact,
        dashboard.ui.comboBox_sa_inspection_selection_file,
        dashboard.ui.pushButton_sa_inspection_selection_artifact_left,
        dashboard.ui.pushButton_sa_inspection_selection_artifact_right,
        dashboard.ui.pushButton_sa_inspection_selection_file_left,
        dashboard.ui.pushButton_sa_inspection_selection_file_right,
        dashboard.ui.pushButton_sa_inspection_selection_prepare,
        dashboard.ui.pushButton_sa_inspection_selection_file_select,
    ):
        widget.setEnabled(not locked)

    if not locked:
        _update_sa_inspection_source_buttons(dashboard)
        if getattr(dashboard, "sa_inspection_source", "artifact") == "artifact":
            _update_sa_inspection_prepare_button(dashboard)


def _set_sa_inspection_action_running(dashboard: QtCore.QObject, node_uid: str, operation_id: str):
    dashboard.sa_inspection_action_running = True
    dashboard.sa_inspection_action_node_uid = str(node_uid or "")
    dashboard.sa_inspection_action_operation_id = str(operation_id or "")
    dashboard.ui.label_sa_inspection_actions_status.setText("Running")
    dashboard.ui.label_sa_inspection_actions_operation_id.setText(dashboard.sa_inspection_action_operation_id or "—")
    _set_sa_inspection_action_start_stop_button(dashboard, True)
    _set_sa_inspection_action_evidence_locked(dashboard, True)
    dashboard.ui.pushButton_sa_inspection_actions_save_as_finding.setEnabled(False)
    _update_sa_inspection_action_controls(dashboard)
    dashboard.ui.pushButton_sa_inspection_actions_start_stop.setEnabled(True)


def _set_sa_inspection_action_stopped(dashboard: QtCore.QObject, status_text: str = "Idle"):
    dashboard.sa_inspection_action_running = False
    dashboard.sa_inspection_action_node_uid = ""
    dashboard.ui.label_sa_inspection_actions_status.setText(status_text)
    _set_sa_inspection_action_start_stop_button(dashboard, False)
    _set_sa_inspection_action_evidence_locked(dashboard, False)
    _update_sa_inspection_action_controls(dashboard)


def _sa_inspection_format_plugin_result(value, indent: int = 0) -> str:
    """Render arbitrary JSON-like plugin output as readable text."""
    prefix = "  " * max(0, int(indent))
    if isinstance(value, dict):
        lines = []
        for key, item in value.items():
            label = str(key)
            if isinstance(item, (dict, list, tuple)):
                lines.append(f"{prefix}{label}:")
                lines.append(_sa_inspection_format_plugin_result(item, indent + 1))
            else:
                lines.append(f"{prefix}{label}: {item}")
        return "\n".join(line for line in lines if line != "")
    if isinstance(value, (list, tuple)):
        lines = []
        for index, item in enumerate(value, start=1):
            if isinstance(item, (dict, list, tuple)):
                lines.append(f"{prefix}[{index}]")
                lines.append(_sa_inspection_format_plugin_result(item, indent + 1))
            else:
                lines.append(f"{prefix}{item}")
        return "\n".join(lines)
    return f"{prefix}{value}"


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_InspectionActionsQueryClicked(dashboard: QtCore.QObject):
    """Query the selected Local Sensor Node for sa.inspection actions."""
    if not _sa_inspection_file_is_ready(getattr(dashboard, "sa_inspection_file_metadata", {}) or {}):
        await Qt5.async_ok_dialog(dashboard, "Select prepared evidence before querying Inspection actions.")
        return
    if not _sa_inspection_selected_node_available(dashboard):
        await Qt5.async_ok_dialog(dashboard, "Select an online Local Sensor Node before querying Inspection actions.")
        return
    if selected_node_is_remote(dashboard):
        await Qt5.async_ok_dialog(
            dashboard,
            "Inspection analysis currently runs against Dashboard-local evidence and requires the Local Sensor Node.",
        )
        return

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    dashboard.sa_inspection_action_query_pending = True
    dashboard.ui.pushButton_sa_inspection_actions_query.setText("Querying...")
    dashboard.ui.pushButton_sa_inspection_actions_query.setEnabled(False)
    _reset_sa_inspection_action_selection(dashboard)
    dashboard.ui.label_sa_inspection_actions_status.setText("Querying")
    await dashboard.backend.queryPluginActions(
        node_uid,
        context=ACTION_QUERY_CONTEXT,
        scope="all_plugins",
        include_tags=["sa.inspection"],
    )


def handle_sa_inspection_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    """Populate Analysis Actions from a generic plugin-action query."""
    if context != ACTION_QUERY_CONTEXT:
        return
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return

    dashboard.sa_inspection_action_query_pending = False
    dashboard.sa_inspection_action_catalog = actions if isinstance(actions, list) else []
    dashboard.ui.pushButton_sa_inspection_actions_query.setText("Query Actions")
    _populate_sa_inspection_action_catalog(dashboard)
    dashboard.ui.label_sa_inspection_actions_status.setText(
        "Ready" if dashboard.sa_inspection_action_catalog else "No Inspection actions"
    )
    _update_sa_inspection_action_controls(dashboard)


def _slotSA_InspectionActionsPluginChanged(dashboard: QtCore.QObject):
    """Refresh the action selector after the plugin changes."""
    _populate_sa_inspection_actions_for_plugin(dashboard)


def _slotSA_InspectionActionsActionChanged(dashboard: QtCore.QObject):
    """Track the selected Inspection action and invalidate its schema."""
    record = dashboard.ui.comboBox_sa_inspection_actions_action.currentData()
    dashboard.sa_inspection_selected_plugin = str(dashboard.ui.comboBox_sa_inspection_actions_plugin.currentText() or "").strip()
    dashboard.sa_inspection_selected_action = (
        str(record.get("action") or "").strip()
        if isinstance(record, dict)
        else str(dashboard.ui.comboBox_sa_inspection_actions_action.currentText() or "").strip()
    )
    _clear_sa_inspection_parameter_widgets(dashboard)
    _update_sa_inspection_action_controls(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_InspectionActionsCustomizeClicked(dashboard: QtCore.QObject):
    """Query the schema for the selected Inspection action."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    record = dashboard.ui.comboBox_sa_inspection_actions_action.currentData()
    if not node_uid or not _sa_inspection_action_local_ready(dashboard) or not isinstance(record, dict):
        return

    plugin_name = str(record.get("plugin") or "").strip()
    action_name = str(record.get("action") or "").strip()
    if not plugin_name or not action_name:
        return

    dashboard.sa_inspection_selected_plugin = plugin_name
    dashboard.sa_inspection_selected_action = action_name
    _clear_sa_inspection_parameter_widgets(dashboard)
    dashboard.ui.pushButton_sa_inspection_actions_customize.setText("Loading...")
    dashboard.ui.pushButton_sa_inspection_actions_customize.setEnabled(False)
    await dashboard.backend.queryPluginActionSchema(
        node_uid,
        plugin_name,
        action_name,
        context=ACTION_SCHEMA_CONTEXT,
    )


def handle_sa_inspection_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
):
    """Render a plugin Inspection action schema in the Parameters area."""
    if str(node_uid or "").strip() != str(
        getattr(dashboard, "selected_node_uid", "") or ""
    ).strip():
        return

    if str(plugin_name or "").strip() != str(
        getattr(dashboard, "sa_inspection_selected_plugin", "") or ""
    ).strip():
        return

    if str(action_name or "").strip() != str(
        getattr(dashboard, "sa_inspection_selected_action", "") or ""
    ).strip():
        return

    parameters = parameters if isinstance(parameters, list) else []

    _clear_sa_inspection_parameter_widgets(dashboard)

    dashboard.sa_inspection_action_schema = {
        "plugin": str(plugin_name or "").strip(),
        "action": str(action_name or "").strip(),
        "params": [
            dict(parameter)
            for parameter in parameters
            if isinstance(parameter, dict)
        ],
    }

    scroll_area = dashboard.ui.scrollArea_sa_inspection_actions_parameters
    contents = dashboard.ui.scrollAreaWidgetContents_sa_inspection_actions_parameters
    layout = contents.layout()

    parameter_label_texts = []

    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue

        name = str(parameter.get("name") or "").strip()
        if not name:
            continue

        parameter_label_texts.append(
            str(parameter.get("label") or name).strip()
        )

    label_probe = QtWidgets.QLabel()
    parameter_label_font = label_probe.font()
    parameter_label_font.setPointSize(
        max(parameter_label_font.pointSize() - 1, 8)
    )
    label_probe.setFont(parameter_label_font)
    label_metrics = label_probe.fontMetrics()

    parameter_label_width = 125

    if parameter_label_texts:
        parameter_label_width = max(
            125,
            max(
                label_metrics.horizontalAdvance(label_text)
                for label_text in parameter_label_texts
            ),
        )

    parameter_widget_minimum_width = 105

    parameter_row_minimum_width = (
        parameter_label_width
        + 3
        + parameter_widget_minimum_width
        + 2
    )

    count = 0

    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue

        name = str(parameter.get("name") or "").strip()
        if not name:
            continue

        row_widget = QtWidgets.QWidget(contents)
        row_widget.setMinimumWidth(parameter_row_minimum_width)
        row_widget.setMinimumHeight(20)
        row_widget.setMaximumHeight(26)

        row_layout = QtWidgets.QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 2, 0)
        row_layout.setSpacing(3)

        label_text = str(parameter.get("label") or name).strip()

        label = QtWidgets.QLabel(f"{label_text}:", row_widget)
        label.setObjectName(
            f"label2_sa_inspection_action_parameter_{name}"
        )
        label.setProperty("uiRole", "inspectionParameterLabel")
        label.setFixedWidth(parameter_label_width)
        label.setMinimumHeight(20)
        label.setMaximumHeight(24)
        label.setAlignment(
            QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter
        )
        label.setFont(parameter_label_font)

        description = str(parameter.get("description") or "").strip()
        label.setToolTip(description or label_text)

        row_layout.addWidget(label)
        row_layout.setStretch(0, 0)

        widget = _create_sa_inspection_parameter_widget(
            row_widget,
            parameter,
        )
        widget.setProperty("uiRole", "inspectionParameterEditor")
        widget.setMinimumWidth(parameter_widget_minimum_width)
        widget.setMinimumHeight(20)
        widget.setMaximumHeight(24)

        widget_font = widget.font()
        widget_font.setPointSize(max(widget_font.pointSize() - 1, 8))
        widget.setFont(widget_font)

        size_policy = widget.sizePolicy()
        size_policy.setHorizontalPolicy(QtWidgets.QSizePolicy.Expanding)
        size_policy.setVerticalPolicy(QtWidgets.QSizePolicy.Fixed)
        widget.setSizePolicy(size_policy)

        if isinstance(widget, QtWidgets.QAbstractSpinBox):
            widget.setButtonSymbols(QtWidgets.QAbstractSpinBox.UpDownArrows)

        row_layout.addWidget(widget, 1)
        layout.addWidget(row_widget)

        dashboard.sa_inspection_action_parameter_widgets[name] = {
            "widget": widget,
            "schema": dict(parameter),
        }

        count += 1

    if count == 0:
        label = QtWidgets.QLabel(
            "No configurable parameters.",
            contents,
        )
        label.setObjectName(
            "label2_sa_inspection_action_no_parameters"
        )
        layout.addWidget(label)

    layout.addStretch()

    contents.setMinimumWidth(parameter_row_minimum_width + 8)
    contents.adjustSize()

    scroll_area.horizontalScrollBar().setValue(0)
    scroll_area.verticalScrollBar().setValue(0)
    scroll_area.update()

    dashboard.sa_inspection_action_customized = True
    dashboard.ui.pushButton_sa_inspection_actions_customize.setText(
        "Customize"
    )
    _update_sa_inspection_action_controls(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_InspectionActionsStartStopClicked(dashboard: QtCore.QObject):
    """Start or stop the selected Inspection analysis operation."""
    if bool(getattr(dashboard, "sa_inspection_action_running", False)):
        node_uid = str(getattr(dashboard, "sa_inspection_action_node_uid", "") or "").strip()
        operation_id = str(getattr(dashboard, "sa_inspection_action_operation_id", "") or "").strip()
        if not node_uid or not operation_id:
            await Qt5.async_ok_dialog(dashboard, "Could not identify the active Inspection operation to stop.")
            return
        dashboard.ui.label_sa_inspection_actions_status.setText("Stopping...")
        try:
            await dashboard.backend.stopPluginOperation(node_uid, operation_id)
        except Exception as error:
            dashboard.logger.error(f"Failed to stop Inspection analysis: {error}")
            _set_sa_inspection_action_stopped(dashboard, "Stop Failed")
            return
        _set_sa_inspection_action_stopped(dashboard, "Stopped")
        return

    if not _sa_inspection_action_local_ready(dashboard):
        await Qt5.async_ok_dialog(dashboard, "Select prepared evidence and the Local Sensor Node before running analysis.")
        return
    if not bool(getattr(dashboard, "sa_inspection_action_customized", False)):
        await Qt5.async_ok_dialog(dashboard, "Customize the Inspection action before starting it.")
        return

    plugin_name = str(getattr(dashboard, "sa_inspection_selected_plugin", "") or "").strip()
    action_name = str(getattr(dashboard, "sa_inspection_selected_action", "") or "").strip()
    if not plugin_name or not action_name:
        return

    try:
        parameters = _sa_inspection_collect_action_parameters(dashboard)
    except Exception as error:
        await Qt5.async_ok_dialog(dashboard, str(error))
        return

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    operation_id = str(parameters.get("operation_id") or "").strip()
    _clear_sa_inspection_action_result(dashboard, "Running")
    _set_sa_inspection_action_running(dashboard, node_uid, operation_id)
    try:
        await dashboard.backend.tacticalNodeExecute(
            [node_uid],
            plugin_name,
            action_name,
            parameters,
        )
    except Exception:
        _set_sa_inspection_action_stopped(dashboard, "Start Failed")
        raise


def handle_sa_inspection_return(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    operation_id: str = "",
    inspection=None,
    final: bool = True,
    timestamp: str = "",
):
    """Apply one structured Inspection callback payload to Analysis Actions."""
    if not isinstance(inspection, dict):
        return

    tracked = str(
        getattr(
            dashboard,
            "sa_inspection_action_operation_id",
            "",
        )
        or ""
    ).strip()

    returned_operation_id = str(operation_id or "").strip()

    if not tracked or returned_operation_id != tracked:
        return

    dashboard.sa_inspection_action_last_result = dict(inspection)
    dashboard.sa_inspection_action_last_result_plugin = str(
        getattr(
            dashboard,
            "sa_inspection_selected_plugin",
            "",
        )
        or ""
    ).strip()

    dashboard.sa_inspection_action_last_result_action = str(
        getattr(
            dashboard,
            "sa_inspection_selected_action",
            "",
        )
        or ""
    ).strip()

    dashboard.ui.pushButton_sa_inspection_actions_view_result.setEnabled(True)

    if final:
        status = (
            "Error"
            if str(inspection.get("error") or "").strip()
            else "Completed"
        )
        _set_sa_inspection_action_stopped(
            dashboard,
            status,
        )

    dashboard.ui.pushButton_sa_inspection_actions_save_as_finding.setEnabled(
        dashboard.sa_inspection_action_last_result is not None
        and not bool(
            getattr(
                dashboard,
                "sa_inspection_action_running",
                False,
            )
        )
    )


def _slotSA_InspectionActionsViewResultClicked(dashboard: QtCore.QObject):
    """Show the current Inspection callback result in a large non-modal window."""
    result = getattr(dashboard, "sa_inspection_action_last_result", None)
    if result is None:
        return

    existing = getattr(dashboard, "sa_inspection_result_dialog", None)
    if existing is not None:
        try:
            existing.close()
        except Exception:
            pass

    plugin_name = str(
        getattr(
            dashboard,
            "sa_inspection_action_last_result_plugin",
            "",
        )
        or "Plugin"
    ).strip()

    action_name = str(
        getattr(
            dashboard,
            "sa_inspection_action_last_result_action",
            "",
        )
        or "Analysis"
    ).strip()

    dialog = QtWidgets.QDialog(dashboard)
    dialog.setObjectName("dialog_sa_inspection_result")
    dialog.setWindowTitle("Inspection Analysis Result")
    dialog.setAttribute(QtCore.Qt.WA_DeleteOnClose, True)
    dialog.resize(600, 460)

    layout = QtWidgets.QVBoxLayout(dialog)
    layout.setContentsMargins(10, 10, 10, 10)
    layout.setSpacing(8)

    source_label = QtWidgets.QLabel(
        f"{plugin_name} / {action_name}",
        dialog,
    )
    source_label.setObjectName("label_sa_inspection_result_source")
    layout.addWidget(source_label)

    result_text = QtWidgets.QPlainTextEdit(dialog)
    result_text.setObjectName("plainTextEdit_sa_inspection_result")
    result_text.setReadOnly(True)
    result_text.setPlainText(
        _sa_inspection_format_plugin_result(result)
    )
    layout.addWidget(result_text, 1)

    close_button = QtWidgets.QPushButton("Close", dialog)
    close_button.setObjectName(
        "pushButton_sa_inspection_result_close"
    )
    close_button.setFixedSize(140, 30)
    close_button.clicked.connect(dialog.close)

    button_row = QtWidgets.QHBoxLayout()
    button_row.addStretch(1)
    button_row.addWidget(close_button)
    layout.addLayout(button_row)

    dashboard.sa_inspection_result_dialog = dialog

    def _clear_result_dialog_reference():
        if getattr(dashboard, "sa_inspection_result_dialog", None) is dialog:
            dashboard.sa_inspection_result_dialog = None

    dialog.destroyed.connect(_clear_result_dialog_reference)
    dialog.show()
    dialog.raise_()
    dialog.activateWindow()


def _slotSA_InspectionActionsSaveFindingClicked(dashboard: QtCore.QObject):
    """Save the current plugin result as one editable Inspection Finding."""
    result = getattr(dashboard, "sa_inspection_action_last_result", None)
    if result is None:
        return
    plugin_name = str(getattr(dashboard, "sa_inspection_action_last_result_plugin", "") or "Plugin").strip()
    action_name = str(getattr(dashboard, "sa_inspection_action_last_result_action", "") or "Analysis").strip()
    title = action_name.replace("_", " ").strip().title() or "Plugin Analysis"
    if isinstance(result, dict):
        candidate_title = result.get("title")
        if isinstance(candidate_title, str) and candidate_title.strip():
            title = candidate_title.strip()
        values = dict(result)
    else:
        values = {"result": result}
    _sa_inspection_new_finding(
        dashboard,
        title,
        f"{plugin_name} / {action_name}",
        _sa_inspection_format_plugin_result(result),
        values,
    )


def _slotSA_InspectionTabChanged(dashboard: QtCore.QObject):
    if dashboard.ui.tabWidget_signal_analysis.currentWidget() is not dashboard.ui.tab_inspection:
        return
    pending_soi = str(getattr(dashboard, "signal_analysis_prefill_soi_key", "") or "").strip()
    pending_artifact = str(getattr(dashboard, "signal_analysis_prefill_artifact_id", "") or "").strip()
    if pending_artifact or pending_soi:
        dashboard.sa_inspection_source = "artifact"
        dashboard.ui.stackedWidget_sa_inspection_selection_source.setCurrentIndex(0)
        _update_sa_inspection_source_buttons(dashboard)
        if pending_artifact and not pending_soi:
            dashboard.ui.comboBox_sa_inspection_selection_soi.blockSignals(True)
            dashboard.ui.comboBox_sa_inspection_selection_soi.setCurrentIndex(0)
            dashboard.ui.comboBox_sa_inspection_selection_soi.blockSignals(False)
    refresh_sa_inspection_soi_context(dashboard, preferred_soi_key=pending_soi)
    if pending_artifact:
        _refresh_sa_inspection_artifacts(dashboard, preferred_artifact_id=pending_artifact)
    _update_sa_inspection_action_controls(dashboard)


def initialize_sa_inspection_controls(dashboard: QtCore.QObject):
    """Initialize the permanent Signal Analysis Inspection workspace."""
    dashboard.sa_inspection_source = "artifact"
    dashboard.sa_inspection_local_file_path = ""
    dashboard.sa_inspection_artifact_id = ""
    dashboard.sa_inspection_file_id = ""
    dashboard.sa_inspection_file_metadata = {}
    dashboard.sa_inspection_active_selection = (0.0, 0.0)
    dashboard.sa_inspection_pending_selection = (0.0, 0.0)
    dashboard.sa_inspection_overview_drag_start = None
    dashboard.sa_inspection_measurement_values = []
    dashboard.sa_inspection_findings = {}
    dashboard.sa_inspection_prepare_artifact_id = ""
    dashboard.sa_inspection_action_catalog = []
    dashboard.sa_inspection_action_query_pending = False
    dashboard.sa_inspection_selected_plugin = ""
    dashboard.sa_inspection_selected_action = ""
    dashboard.sa_inspection_action_parameter_widgets = {}
    dashboard.sa_inspection_action_schema = {}
    dashboard.sa_inspection_action_customized = False
    dashboard.sa_inspection_action_running = False
    dashboard.sa_inspection_action_node_uid = ""
    dashboard.sa_inspection_action_operation_id = ""
    dashboard.sa_inspection_action_last_result = None
    dashboard.sa_inspection_action_last_result_plugin = ""
    dashboard.sa_inspection_action_last_result_action = ""
    dashboard.sa_inspection_result_dialog = None
    dashboard.sa_inspection_plots_activated = False
    _initialize_sa_inspection_visuals(dashboard)
    dashboard.sa_inspection_external_tools_layout = None
    dashboard.sa_inspection_external_tool_buttons = {}

    # Hide only the actual plot surfaces on first boot. Card geometry stays fixed.
    dashboard.ui.frame_sa_inspection_overview_plot.setVisible(False)
    dashboard.ui.frame_sa_inspection_view_plot.setVisible(False)
    for index in range(dashboard.ui.tabWidget_sa_inspection_view.count()):
        dashboard.ui.tabWidget_sa_inspection_view.setTabEnabled(index, False)

    _sa_inspection_mount_canvas(
        dashboard,
        dashboard.ui.frame_sa_inspection_overview_plot,
        "sa_inspection_overview_canvas",
    )
    _sa_inspection_mount_canvas(
        dashboard,
        dashboard.ui.frame_sa_inspection_view_plot,
        "sa_inspection_view_canvas",
        navigation_toolbar=True,
    )
    dashboard.sa_inspection_overview_canvas.mpl_connect(
        "button_press_event",
        lambda event: _slotSA_InspectionOverviewPress(dashboard, event),
    )
    dashboard.sa_inspection_overview_canvas.mpl_connect(
        "button_release_event",
        lambda event: _slotSA_InspectionOverviewRelease(dashboard, event),
    )
    dashboard.sa_inspection_view_canvas.mpl_connect(
        "button_press_event",
        lambda event: _slotSA_InspectionMainClicked(dashboard, event),
    )

    dashboard.ui.tableWidget_sa_inspection_findings.setSelectionBehavior(
        QtWidgets.QAbstractItemView.SelectRows
    )
    dashboard.ui.tableWidget_sa_inspection_findings.setSelectionMode(
        QtWidgets.QAbstractItemView.SingleSelection
    )
    dashboard.ui.tableWidget_sa_inspection_findings.horizontalHeader().setStretchLastSection(True)
    dashboard.ui.tableWidget_sa_inspection_findings.verticalHeader().setVisible(False)
    dashboard.ui.textEdit_sa_inspection_selection_file_name.setReadOnly(True)
    _sa_inspection_set_local_file_path(dashboard, "")

    dashboard.ui.stackedWidget_sa_inspection_selection_source.setCurrentIndex(0)
    _update_sa_inspection_source_buttons(dashboard)
    dashboard.ui.pushButton_sa_inspection_measurements_time.setChecked(True)
    dashboard.ui.pushButton_sa_inspection_measurements_frequency.setChecked(False)

    _initialize_sa_inspection_external_tools(dashboard)
    _reset_sa_inspection_action_selection(dashboard)
    dashboard.ui.pushButton_sa_inspection_actions_query.setText("Query Actions")
    dashboard.ui.pushButton_sa_inspection_actions_start_stop.setText("Start")
    dashboard.ui.pushButton_sa_inspection_actions_view_result.setEnabled(False)
    dashboard.ui.pushButton_sa_inspection_actions_save_as_finding.setEnabled(False)
    dashboard.ui.label_sa_inspection_actions_status.setText("Select evidence")
    dashboard.ui.label_sa_inspection_actions_operation_id.setText("—")

    _sa_inspection_clear_file(dashboard)
    refresh_sa_inspection_soi_context(dashboard)
    _update_sa_inspection_navigation_controls(dashboard)
    _update_sa_inspection_findings_controls(dashboard)
    _update_sa_inspection_action_controls(dashboard)
    

__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value) and value.__module__ == __name__
]