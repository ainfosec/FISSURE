from PyQt5 import QtCore, QtWidgets, QtGui

from collections import deque
import inspect
import os
import time
import html

import matplotlib
matplotlib.use("Qt5Agg")
from matplotlib.collections import LineCollection
import matplotlib.pyplot

import numpy as np
import qasync

import fissure.utils
from .legacy import _safe_float, _safe_int


TSI_DETECTOR_TYPES = [
    ("rf", "RF"),
    ("wifi", "Wi-Fi"),
    ("bluetooth", "Bluetooth"),
    ("protocol", "Protocol"),
    ("ml", "ML"),
]


TSI_DETECTOR_MODES = [
    ("fixed", "Fixed"),
    ("sweep", "Sweep"),
    ("channel_hop", "Channel Hop"),
    ("lock", "Lock"),
    ("passive", "Passive"),
    ("file", "File"),
    ("simulation", "Simulation"),
]


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorSearchClicked(dashboard: QtCore.QObject):
    """ 
    Switches to the Search tab and copies the selected frequency.
    """
    # Copy the Value
    get_row = dashboard.ui.tableWidget1_tsi_wideband.currentRow()
    if get_row >= 0:
        get_freq = dashboard.ui.tableWidget1_tsi_wideband.item(get_row,0).text()
        dashboard.ui.textEdit_library_search_frequency.setPlainText(get_freq)

        # Format the Search
        dashboard.ui.checkBox_library_search_frequency.setChecked(True)
        dashboard.ui.textEdit_library_search_frequency_margin.setPlainText("5")
        dashboard.ui.checkBox_library_search_start_frequency.setChecked(False)
        dashboard.ui.checkBox_library_search_end_frequency.setChecked(False)
        dashboard.ui.checkBox_library_search_bandwidth.setChecked(False)
        dashboard.ui.checkBox_library_search_modulation.setChecked(False)
        dashboard.ui.checkBox_library_search_continuous.setChecked(False)

        # Change Tabs
        dashboard.ui.tabWidget_library.setCurrentIndex(2)  # Search
        dashboard.ui.tabWidget.setCurrentIndex(7)  # Library


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_ClearWidebandListClicked(dashboard: QtCore.QObject):
    """
    Clears the unified TSI detector results list, selected details, and plot.
    """
    for table in _tsi_detector_results_tables(dashboard):
        table.blockSignals(True)
        table.clearContents()
        table.setRowCount(0)
        table.blockSignals(False)

    _clear_tsi_detector_detection_details(
        dashboard
    )

    if hasattr(dashboard, "tsi_detector_plot_events"):
        _tsi_detector_plot_clear_points(dashboard)


def _show_tsi_detector_results_context_menu(
    dashboard: QtCore.QObject,
    position: QtCore.QPoint,
):
    """
    Shows TSI detector result actions. Right-clicking a row selects it first.
    """
    table = dashboard.ui.tableWidget1_tsi_wideband
    clicked_item = table.itemAt(position)

    if clicked_item is not None:
        table.selectRow(clicked_item.row())
        table.setCurrentCell(
            clicked_item.row(),
            clicked_item.column(),
        )

    menu = QtWidgets.QMenu(table)

    action_clear = menu.addAction("Clear Results")
    action_clear.setEnabled(
        table.rowCount() > 0
    )

    chosen_action = menu.exec_(
        table.viewport().mapToGlobal(position)
    )

    if chosen_action == action_clear:
        _slotTSI_ClearWidebandListClicked(
            dashboard
        )


def _get_selected_tsi_detector_detection(
    dashboard: QtCore.QObject,
):
    """
    Returns the full CoT detection dictionary stored on the selected row.
    """
    table = dashboard.ui.tableWidget1_tsi_wideband
    row = table.currentRow()

    if row < 0:
        return None

    # The current detector code stores the full CoT message on column 0
    # under Qt.UserRole.
    item = table.item(row, 0)

    if item is None:
        return None

    detection = item.data(
        QtCore.Qt.UserRole
    )

    if isinstance(detection, dict):
        return detection

    # Fallback for the time-column storage used by the current implementation.
    time_item = table.item(row, 2)

    if time_item is not None:
        detection = time_item.data(
            QtCore.Qt.UserRole + 2
        )

        if isinstance(detection, dict):
            return detection

    return None


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorResultSelectionChanged(
    dashboard: QtCore.QObject,
):
    detection = _get_selected_tsi_detector_detection(
        dashboard
    )

    if not detection:
        _clear_tsi_detector_detection_details(
            dashboard
        )
        return

    _populate_tsi_detector_detection_details(
        dashboard,
        detection,
    )

    _enable_tsi_detector_detection_details(
        dashboard,
        True,
    )


def _clear_tsi_detector_detection_details(
    dashboard: QtCore.QObject,
):
    dashboard.ui.label2_tsi_detector_detection_details.setText(
        ""
    )

    _enable_tsi_detector_detection_details(
        dashboard,
        False,
    )


def _enable_tsi_detector_detection_details(
    dashboard: QtCore.QObject,
    enabled=True,
):
    widgets = [
        dashboard.ui.scrollArea_tsi_detector_detection_details,
        dashboard.ui.label2_tsi_detector_detection_details,
        dashboard.ui.pushButton_tsi_detector_promote_to_soi,
        dashboard.ui.pushButton_tsi_detector_promote_to_target,
    ]

    for widget in widgets:
        widget.setEnabled(enabled)


def _populate_tsi_detector_detection_details(
    dashboard: QtCore.QObject,
    detection: dict,
):
    """
    Displays every non-empty detection value except raw transport payloads.
    Nested dictionaries and lists are expanded.
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
        key_text = str(key).strip()

        # Parsed CoT detection records currently use detection_* names.
        if key_text.startswith("detection_"):
            key_text = key_text[len("detection_"):]

        return key_text.replace(
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
        key = str(key).strip().lower()

        if key in {
            "time",
            "timestamp",
            "detection_timestamp",
        }:
            try:
                timestamp = float(value)
                return time.strftime(
                    "%H:%M:%S",
                    time.localtime(timestamp),
                )
            except Exception:
                pass

        if key in {
            "frequency_hz",
            "detection_frequency_hz",
        }:
            try:
                return f"{float(value) / 1e6:.6f} MHz"
            except Exception:
                pass

        if key in {
            "power_dbm",
            "detection_power_dbm",
        }:
            try:
                return f"{float(value):.1f} dBm"
            except Exception:
                pass

        return str(value)

    def append_value(
        lines,
        key,
        value,
        depth=0,
    ):
        normalized_key = str(
            key
        ).strip().lower()

        if normalized_key in hidden_keys:
            return

        if is_empty(value):
            return

        label = make_label(key)
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

                    item_value = item.get(
                        "value"
                    )

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
                            "<span style='font-weight:500;'>"
                            f"{html.escape(str(item_label))}"
                            "</span>"
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

    dashboard.ui.label2_tsi_detector_detection_details.setText(
        "<br>".join(lines)
    )


def _tsi_frequency_is_blacklisted(
    dashboard: QtCore.QObject,
    frequency_mhz: float,
) -> bool:
    try:
        frequency_mhz = float(frequency_mhz)
    except Exception:
        return False

    for start_mhz, end_mhz in _tsi_blacklist_ranges_mhz(dashboard):
        if start_mhz <= frequency_mhz <= end_mhz:
            return True

    return False


def _tsi_blacklist_ranges_mhz(
    dashboard: QtCore.QObject,
):
    """
    Returns blacklist ranges stored independently of the popup widgets.
    """
    ranges = getattr(
        dashboard,
        "tsi_detector_blacklist_ranges",
        [],
    )

    clean_ranges = []

    for entry in ranges:
        try:
            start_mhz, end_mhz = entry
            start_mhz = float(start_mhz)
            end_mhz = float(end_mhz)
        except Exception:
            continue

        clean_ranges.append(
            (
                min(start_mhz, end_mhz),
                max(start_mhz, end_mhz),
            )
        )

    return clean_ranges


def _refresh_tsi_detector_blacklist_dialog(
    dashboard: QtCore.QObject,
):
    list_widget = getattr(
        dashboard,
        "_tsi_detector_blacklist_list",
        None,
    )

    remove_button = getattr(
        dashboard,
        "_tsi_detector_blacklist_remove_button",
        None,
    )

    if list_widget is None:
        return

    list_widget.clear()

    for start_mhz, end_mhz in _tsi_blacklist_ranges_mhz(
        dashboard
    ):
        list_widget.addItem(
            f"{start_mhz:g}-{end_mhz:g}"
        )

    if remove_button is not None:
        remove_button.setEnabled(
            list_widget.count() > 0
            and list_widget.currentRow() >= 0
        )


def _slotTSI_DetectorBlacklistAddClicked(
    dashboard: QtCore.QObject,
):
    start_edit = getattr(
        dashboard,
        "_tsi_detector_blacklist_start",
        None,
    )

    end_edit = getattr(
        dashboard,
        "_tsi_detector_blacklist_end",
        None,
    )

    if start_edit is None or end_edit is None:
        return

    try:
        start_mhz = float(
            start_edit.text().strip()
        )

        end_mhz = float(
            end_edit.text().strip()
        )
    except Exception:
        QtWidgets.QMessageBox.warning(
            dashboard,
            "Invalid Blacklist Range",
            "Enter valid start and end frequencies in MHz.",
        )
        return

    if start_mhz == end_mhz:
        QtWidgets.QMessageBox.warning(
            dashboard,
            "Invalid Blacklist Range",
            "Start and end frequencies cannot be the same.",
        )
        return

    normalized_range = (
        min(start_mhz, end_mhz),
        max(start_mhz, end_mhz),
    )

    ranges = getattr(
        dashboard,
        "tsi_detector_blacklist_ranges",
        [],
    )

    if normalized_range not in ranges:
        ranges.append(
            normalized_range
        )

        ranges.sort(
            key=lambda item: (
                item[0],
                item[1],
            )
        )

    dashboard.tsi_detector_blacklist_ranges = ranges

    start_edit.clear()
    end_edit.clear()

    _refresh_tsi_detector_blacklist_dialog(
        dashboard
    )


def _slotTSI_DetectorBlacklistRemoveClicked(
    dashboard: QtCore.QObject,
):
    list_widget = getattr(
        dashboard,
        "_tsi_detector_blacklist_list",
        None,
    )

    if list_widget is None:
        return

    row = list_widget.currentRow()

    if row < 0:
        return

    ranges = _tsi_blacklist_ranges_mhz(
        dashboard
    )

    if row < len(ranges):
        ranges.pop(row)

    dashboard.tsi_detector_blacklist_ranges = ranges

    _refresh_tsi_detector_blacklist_dialog(
        dashboard
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorBlacklistClicked(
    dashboard: QtCore.QObject,
):
    """
    Opens blacklist management without resetting saved ranges.
    """
    dialog = QtWidgets.QDialog(
        dashboard
    )

    dialog.setWindowTitle(
        "TSI Detector Blacklist"
    )

    dialog.setModal(True)
    dialog.resize(
        390,
        340,
    )

    main_layout = QtWidgets.QVBoxLayout(
        dialog
    )

    form_layout = QtWidgets.QFormLayout()

    start_edit = QtWidgets.QLineEdit(
        dialog
    )

    end_edit = QtWidgets.QLineEdit(
        dialog
    )

    start_edit.setPlaceholderText(
        "e.g. 433.90"
    )

    end_edit.setPlaceholderText(
        "e.g. 433.95"
    )

    form_layout.addRow(
        "Start Frequency (MHz):",
        start_edit,
    )

    form_layout.addRow(
        "End Frequency (MHz):",
        end_edit,
    )

    main_layout.addLayout(
        form_layout
    )

    button_layout = QtWidgets.QHBoxLayout()

    add_button = QtWidgets.QPushButton(
        "Add",
        dialog,
    )

    remove_button = QtWidgets.QPushButton(
        "Remove Selected",
        dialog,
    )

    button_layout.addWidget(
        add_button
    )

    button_layout.addWidget(
        remove_button
    )

    main_layout.addLayout(
        button_layout
    )

    list_widget = QtWidgets.QListWidget(
        dialog
    )

    list_widget.setSelectionMode(
        QtWidgets.QAbstractItemView.SingleSelection
    )

    main_layout.addWidget(
        list_widget,
        1,
    )

    close_buttons = QtWidgets.QDialogButtonBox(
        QtWidgets.QDialogButtonBox.Close,
        parent=dialog,
    )

    main_layout.addWidget(
        close_buttons
    )

    dashboard._tsi_detector_blacklist_start = start_edit
    dashboard._tsi_detector_blacklist_end = end_edit
    dashboard._tsi_detector_blacklist_list = list_widget
    dashboard._tsi_detector_blacklist_remove_button = remove_button

    add_button.clicked.connect(
        lambda: _slotTSI_DetectorBlacklistAddClicked(
            dashboard
        )
    )

    remove_button.clicked.connect(
        lambda: _slotTSI_DetectorBlacklistRemoveClicked(
            dashboard
        )
    )

    list_widget.itemSelectionChanged.connect(
        lambda: remove_button.setEnabled(
            list_widget.currentRow() >= 0
        )
    )

    close_buttons.rejected.connect(
        dialog.reject
    )

    _refresh_tsi_detector_blacklist_dialog(
        dashboard
    )

    dialog.exec_()

    dashboard._tsi_detector_blacklist_start = None
    dashboard._tsi_detector_blacklist_end = None
    dashboard._tsi_detector_blacklist_list = None
    dashboard._tsi_detector_blacklist_remove_button = None


def _set_spinbox_value_blocked(widget, value):
    widget.blockSignals(True)
    widget.setValue(float(value))
    widget.blockSignals(False)


def append_tsi_active_detector_detection_from_cot(
    dashboard: QtCore.QObject,
    cot_message: dict,
):
    """
    Routes CoT detections into the shared TSI detector workbench.

    Unified, Sweep, and Fixed share:
        - detector results table
        - conditioner detector input table
        - detector plot/raster area
        - blacklist filtering

    Unified detector mode is plugin/action generic. It does not maintain a
    Dashboard-side detector allowlist.
    """
    if not cot_message:
        return

    if cot_message.get("kind") != "detection":
        return

    unified_running = bool(
        getattr(dashboard, "tsi_detector_running", False)
    )

    if not unified_running:
        return

    _append_tsi_detector_detection_from_cot(
        dashboard,
        cot_message,
        allowed_detectors=None,
        active_node_uid=getattr(dashboard, "tsi_detector_node_uid", ""),
        active_opid_attr="tsi_detector_opid",
        waiting_opid_attr="tsi_detector_waiting_for_opid",
    )


def _append_tsi_detector_detection_from_cot(
    dashboard: QtCore.QObject,
    cot_message: dict,
    allowed_detectors: set = None,
    active_node_uid: str = "",
    active_opid_attr: str = "",
    waiting_opid_attr: str = "",
):
    """
    Append one parsed CoT detection into the shared TSI detector table/plot.

    If allowed_detectors is None or empty, detector-name filtering is skipped.
    That is required for the unified detector workflow.
    """
    allowed_detectors = allowed_detectors or set()

    detector_name = str(
        cot_message.get("detection_detector") or ""
    ).strip()

    if allowed_detectors and detector_name not in allowed_detectors:
        return

    detection_node_uid = str(
        cot_message.get("detection_node_uid") or ""
    ).strip()

    active_node_uid = str(active_node_uid or "").strip()

    if active_node_uid and detection_node_uid and detection_node_uid != active_node_uid:
        return

    detection_opid = str(
        cot_message.get("detection_opid") or ""
    ).strip()

    if not detection_opid:
        return

    active_opid = str(
        getattr(dashboard, active_opid_attr, "") or ""
    ).strip()

    if active_opid:
        if detection_opid != active_opid:
            return
    else:
        setattr(dashboard, active_opid_attr, detection_opid)
        setattr(dashboard, waiting_opid_attr, False)

    try:
        frequency_hz = float(cot_message.get("detection_frequency_hz"))
        frequency_mhz = frequency_hz / 1e6
    except Exception:
        dashboard.logger.debug(
            f"[TSI Detector] Ignoring detection with invalid frequency: {cot_message}"
        )
        return

    if _tsi_frequency_is_blacklisted(dashboard, frequency_mhz):
        dashboard.logger.debug(
            f"Ignoring blacklisted TSI detection: {frequency_mhz} MHz"
        )
        return

    try:
        power_value = float(cot_message.get("detection_power_dbm"))
    except Exception:
        power_value = 0.0

    try:
        time_value = float(cot_message.get("detection_timestamp"))
    except Exception:
        time_value = time.time()

    try:
        _tsi_detector_plot_add_detection(
            dashboard,
            frequency_mhz=frequency_mhz,
            power_dbm=power_value,
            timestamp_s=time_value,
        )
    except Exception as e:
        dashboard.logger.debug(
            f"Could not add TSI detection to shared plot: {e}"
        )

    get_time = time.strftime("%H:%M:%S", time.localtime(time_value))
    time_obj = QtCore.QTime.fromString(get_time, "HH:mm:ss")

    for table in _tsi_detector_results_tables(dashboard):
        was_empty = table.rowCount() == 0

        row = table.rowCount()
        table.setRowCount(row + 1)

        frequency_item = QtWidgets.QTableWidgetItem(f"{frequency_mhz:.6f}")
        frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
        frequency_item.setData(QtCore.Qt.UserRole, cot_message)
        frequency_item.setData(QtCore.Qt.UserRole + 1, detection_opid)
        table.setItem(row, 0, frequency_item)

        power_item = QtWidgets.QTableWidgetItem(f"{power_value:.1f}")
        power_item.setTextAlignment(QtCore.Qt.AlignCenter)
        power_item.setData(QtCore.Qt.UserRole, cot_message)
        power_item.setData(QtCore.Qt.UserRole + 1, detection_opid)
        table.setItem(row, 1, power_item)

        time_item = QtWidgets.QTableWidgetItem(get_time)
        time_item.setTextAlignment(QtCore.Qt.AlignCenter)
        time_item.setData(QtCore.Qt.UserRole, time_obj.msecsSinceStartOfDay())
        time_item.setData(QtCore.Qt.UserRole + 1, detection_opid)
        time_item.setData(QtCore.Qt.UserRole + 2, cot_message)
        table.setItem(row, 2, time_item)

        table.sortItems(2, order=QtCore.Qt.DescendingOrder)
        table.resizeColumnsToContents()
        table.resizeRowsToContents()
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setStretchLastSection(True)

        if was_empty:
            table.selectRow(row)
            table.setCurrentCell(row, 0)


def _tsi_detector_plot_initial_xlim(dashboard: QtCore.QObject):
    """
    Returns initial x-axis limits for the unified TSI detector plot.

    Primary method:
      - infer configured plot range from detector parameter names/values.

    Fallback:
      - return 0-1 MHz if no useful frequency/range parameters are found.
        _tsi_detector_plot_data_xlim() will later replace this fallback with
        data-centered limits once real detections arrive.
    """
    params = collect_tsi_detector_parameters(dashboard)

    center_mhz = None
    sample_rate_hz = None
    start_mhz = None
    stop_mhz = None

    center_frequency_keys = {
        "frequency",
        "freq",
        "freq_mhz",
        "frequency_mhz",
        "center_frequency",
        "center_frequency_mhz",
        "center_freq",
        "center_freq_mhz",
        "rx_freq",
        "rx_frequency",
        "rx_frequency_mhz",
        "tuned_freq",
        "tuned_frequency",
        "tuned_frequency_mhz",
    }

    sample_rate_keys = {
        "sample_rate",
        "samp_rate",
        "sample_rate_hz",
        "rx_sample_rate",
        "rx_sample_rate_hz",
    }

    start_frequency_keys = {
        "start_frequency",
        "start_frequency_mhz",
        "start_freq",
        "start_freq_mhz",
        "start_mhz",
        "custom_start_mhz",
        "frequency_min",
        "frequency_min_mhz",
        "min_frequency",
        "min_frequency_mhz",
        "low_frequency",
        "low_frequency_mhz",
        "low_mhz",
    }

    stop_frequency_keys = {
        "stop_frequency",
        "stop_frequency_mhz",
        "stop_freq",
        "stop_freq_mhz",
        "stop_mhz",
        "end_frequency",
        "end_frequency_mhz",
        "end_freq",
        "end_freq_mhz",
        "end_mhz",
        "custom_end_mhz",
        "frequency_max",
        "frequency_max_mhz",
        "max_frequency",
        "max_frequency_mhz",
        "high_frequency",
        "high_frequency_mhz",
        "high_mhz",
    }

    range_keys = {
        "band_range_mhz",
        "segment_range_mhz",
        "range_mhz",
        "frequency_range_mhz",
        "scan_range_mhz",
    }

    for key, value in params.items():
        key_l = str(key).strip().lower()

        try:
            numeric_value = float(value)
        except Exception:
            numeric_value = None

        if key_l in center_frequency_keys and numeric_value is not None:
            center_mhz = numeric_value

        elif key_l in sample_rate_keys and numeric_value is not None:
            sample_rate_hz = numeric_value

        elif key_l in start_frequency_keys and numeric_value is not None:
            start_mhz = numeric_value

        elif key_l in stop_frequency_keys and numeric_value is not None:
            stop_mhz = numeric_value

        elif key_l in range_keys:
            try:
                text = str(value).strip()
                text = text.replace("MHz", "").replace("mhz", "")
                text = text.replace("–", "-").replace("—", "-")

                low_text, high_text = text.split("-", 1)
                start_mhz = float(low_text.strip())
                stop_mhz = float(high_text.strip())
            except Exception:
                pass

    # Sweep/range-style detector.
    if start_mhz is not None and stop_mhz is not None:
        x_low = min(start_mhz, stop_mhz)
        x_high = max(start_mhz, stop_mhz)

        if abs(x_high - x_low) < 1e-9:
            return x_low - 0.5, x_high + 0.5

        x_pad = max(0.05, (x_high - x_low) * 0.05)
        return x_low - x_pad, x_high + x_pad

    # Fixed/center-frequency detector.
    if center_mhz is not None:
        if sample_rate_hz is not None:
            half_bw_mhz = max(0.5, (sample_rate_hz / 1e6) / 2.0)
        else:
            half_bw_mhz = 0.5

        return center_mhz - half_bw_mhz, center_mhz + half_bw_mhz

    # Meaningless fallback. Data autoscale will replace this once detections arrive.
    return 0.0, 1.0


def _tsi_detector_plot_data_xlim(
    dashboard: QtCore.QObject,
    freqs=None,
):
    """
    Returns x-axis limits for the unified detector plot.

    Data-first behavior:
      - If detections exist, scale to observed detector data.
      - If no detections exist, use configured detector parameters.
      - If no configured detector range is available, use 0-1 MHz fallback.

    This lets the plot follow live retunes, e.g. starting at 915 MHz and later
    moving to 310 MHz without keeping 915 MHz in view forever.
    """
    if freqs is None:
        freqs = []

    clean_freqs = []
    for freq in freqs:
        try:
            clean_freqs.append(float(freq))
        except Exception:
            pass

    if clean_freqs:
        data_low = min(clean_freqs)
        data_high = max(clean_freqs)

        if abs(data_high - data_low) < 1e-9:
            data_pad = 0.5
        else:
            data_pad = max(0.05, (data_high - data_low) * 0.08)

        return data_low - data_pad, data_high + data_pad

    initial_low = getattr(
        dashboard,
        "tsi_detector_plot_initial_xlim_low",
        None,
    )
    initial_high = getattr(
        dashboard,
        "tsi_detector_plot_initial_xlim_high",
        None,
    )

    if initial_low is None or initial_high is None:
        initial_low, initial_high = _tsi_detector_plot_initial_xlim(dashboard)
        dashboard.tsi_detector_plot_initial_xlim_low = initial_low
        dashboard.tsi_detector_plot_initial_xlim_high = initial_high

    try:
        return float(initial_low), float(initial_high)
    except Exception:
        return 0.0, 1.0


def handle_tsi_detector_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str,
    context: str,
    actions: list,
):
    """
    Populate the unified TSI Detector Method combobox from generic
    filtered plugin-action query results.
    """
    combo = dashboard.ui.comboBox_tsi_detector_method

    dashboard.tsi_detector_method_actions = actions or []

    combo.blockSignals(True)
    combo.clear()

    for action_record in dashboard.tsi_detector_method_actions:
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
    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(has_actions)
    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)

    if has_actions:
        combo.setCurrentIndex(0)
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Customize this method to load its parameters and details."
        )
    else:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "No matching detector actions are available for the selected node, type, mode, and hardware."
        )


def _tsi_detector_current_combo_data(combo, fallback=""):
    data = combo.currentData()

    if data is not None and str(data).strip():
        return str(data).strip()

    text = combo.currentText().strip().lower()
    return text or fallback


def _tsi_detector_selected_type(dashboard: QtCore.QObject) -> str:
    return _tsi_detector_current_combo_data(
        dashboard.ui.comboBox_tsi_detector_type,
        "rf",
    )


def _tsi_detector_selected_mode(dashboard: QtCore.QObject) -> str:
    return _tsi_detector_current_combo_data(
        dashboard.ui.comboBox_tsi_detector_mode,
        "sweep",
    )


def _tsi_detector_selected_hardware(dashboard: QtCore.QObject) -> str:
    return dashboard.ui.comboBox_tsi_detector_hardware.currentText().strip()


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_DetectorQueryClicked(dashboard: QtCore.QObject):
    uid = getattr(dashboard, "selected_node_uid", "").strip()

    if not uid:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a sensor node before querying detector methods."
        )
        return

    detector_type = _tsi_detector_selected_type(dashboard)
    detector_mode = _tsi_detector_selected_mode(dashboard)
    hardware = _tsi_detector_selected_hardware(dashboard)

    include_tags = [
        "tsi.detector",
        f"tsi.detector.type.{detector_type}",
        f"tsi.detector.mode.{detector_mode}",
    ]

    context = f"tsi.detector.{detector_type}.{detector_mode}"

    dashboard.ui.comboBox_tsi_detector_method.clear()
    dashboard.ui.comboBox_tsi_detector_method.setEnabled(False)
    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)
    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)
    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Querying selected node for matching detector actions..."
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


def initialize_tsi_detector_controls(dashboard: QtCore.QObject):
    """
    Initialize the unified TSI Detector controls.
    Safe to call more than once.

    The Detector Matplotlib canvas is created earlier by
    Frontend.load_MPL_components() to preserve the original Qt widget stacking.
    """
    select_node_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "select_node.png",
    )

    select_node_label = getattr(
        dashboard.ui,
        "label_tsi_detector_select_sensor_node_image",
        None,
    )

    if (
        select_node_label is not None
        and os.path.isfile(select_node_icon_path)
    ):
        select_node_label.setPixmap(
            QtGui.QPixmap(select_node_icon_path)
        )

    dashboard.tsi_detector_method_actions = []
    dashboard.tsi_detector_selected_plugin = ""
    dashboard.tsi_detector_selected_action = ""

    dashboard.tsi_detector_action_schema_cache = getattr(
        dashboard,
        "tsi_detector_action_schema_cache",
        {},
    )

    dashboard.tsi_detector_parameter_widgets = {}
    dashboard.tsi_detector_current_schema = {}
    dashboard.tsi_detector_customized = False

    dashboard.tsi_detector_running = False
    dashboard.tsi_detector_node_uid = ""
    dashboard.tsi_detector_opid = ""
    dashboard.tsi_detector_waiting_for_opid = False

    # Persist for the lifetime of the Dashboard, including popup close/reopen.
    dashboard.tsi_detector_blacklist_ranges = getattr(
        dashboard,
        "tsi_detector_blacklist_ranges",
        [],
    )

    _populate_tsi_detector_type_combo(dashboard)
    _populate_tsi_detector_mode_combo(dashboard)

    dashboard.ui.comboBox_tsi_detector_type.setEnabled(True)
    dashboard.ui.comboBox_tsi_detector_mode.setEnabled(True)

    clear_tsi_detector_methods(dashboard)
    clear_tsi_detector_parameter_controls(dashboard)

    dashboard.ui.pushButton_tsi_detector_query.setText("Query")
    dashboard.ui.pushButton_tsi_detector_query.setToolTip(
        "Query the selected node for detector methods matching the "
        "selected type, mode, and hardware."
    )

    dashboard.ui.pushButton_tsi_detector_customize.setText("Customize")
    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)
    dashboard.ui.pushButton_tsi_detector_customize.setToolTip(
        "Load and customize parameters for the selected detector method."
    )

    _tsi_detector_set_start_stop_button(
        dashboard,
        False,
    )

    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)

    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Select a detector method to view details."
    )
    dashboard.ui.label2_tsi_detector_status.setText("Idle")

    dashboard.ui.scrollArea_tsi_detector_parameters.setHorizontalScrollBarPolicy(
        QtCore.Qt.ScrollBarAlwaysOff
    )
    dashboard.ui.scrollArea_tsi_detector_parameters.setVerticalScrollBarPolicy(
        QtCore.Qt.ScrollBarAsNeeded
    )

    table = dashboard.ui.tableWidget1_tsi_wideband
    table.resizeColumnsToContents()
    table.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)

    details_label = (
        dashboard.ui.label2_tsi_detector_detection_details
    )
    details_label.setAlignment(
        QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop
    )
    details_label.setWordWrap(True)
    details_label.setTextInteractionFlags(
        QtCore.Qt.TextSelectableByMouse
    )

    details_scroll = (
        dashboard.ui.scrollArea_tsi_detector_detection_details
    )

    details_widgets = [
        details_scroll,
        details_scroll.viewport(),
        details_scroll.widget(),
        dashboard.ui.label2_tsi_detector_detection_details,
    ]

    for widget in details_widgets:
        if widget is None:
            continue

        widget.setProperty(
            "uiRole",
            "detailsPanel",
        )

        widget.style().unpolish(widget)
        widget.style().polish(widget)
        widget.update()

    dashboard.ui.scrollArea_tsi_detector_detection_details.setHorizontalScrollBarPolicy(
        QtCore.Qt.ScrollBarAlwaysOff
    )

    _clear_tsi_detector_detection_details(
        dashboard
    )

    update_tsi_detector_selected_node_gate(dashboard)


def _populate_tsi_detector_type_combo(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_tsi_detector_type
    current_data = combo.currentData()

    combo.blockSignals(True)
    combo.clear()

    for value, label in TSI_DETECTOR_TYPES:
        combo.addItem(label, value)

    restore_index = combo.findData(current_data)
    if restore_index >= 0:
        combo.setCurrentIndex(restore_index)
    else:
        combo.setCurrentIndex(combo.findData("rf"))

    combo.blockSignals(False)


def _populate_tsi_detector_mode_combo(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_tsi_detector_mode
    current_data = combo.currentData()

    combo.blockSignals(True)
    combo.clear()

    for value, label in TSI_DETECTOR_MODES:
        combo.addItem(label, value)

    restore_index = combo.findData(current_data)
    if restore_index >= 0:
        combo.setCurrentIndex(restore_index)
    else:
        combo.setCurrentIndex(combo.findData("sweep"))

    combo.blockSignals(False)


def update_tsi_detector_hardware_combo(dashboard: QtCore.QObject):
    """
    Populate unified Detector hardware from selected-node TSI hardware.
    """
    combo = dashboard.ui.comboBox_tsi_detector_hardware
    current_hardware = combo.currentText().strip()

    combo.blockSignals(True)
    combo.clear()

    if getattr(dashboard, "selected_node_uid", ""):
        try:
            hardware_names = fissure.utils.hardware.selectedNodeHardwareDisplayNames(
                dashboard,
                "tsi",
            )
        except Exception as e:
            dashboard.logger.debug(
                f"[TSI Detector] Could not get selected-node hardware: {e}"
            )
            hardware_names = []

        combo.addItems(hardware_names)

        if current_hardware and combo.findText(current_hardware) >= 0:
            combo.setCurrentText(current_hardware)
        elif combo.count() > 0:
            combo.setCurrentIndex(0)

    combo.blockSignals(False)

    has_node = bool(getattr(dashboard, "selected_node_uid", ""))
    has_hardware = combo.count() > 0

    combo.setEnabled(has_node and has_hardware)
    dashboard.ui.comboBox_tsi_detector_type.setEnabled(True)
    dashboard.ui.comboBox_tsi_detector_mode.setEnabled(True)
    dashboard.ui.pushButton_tsi_detector_query.setEnabled(has_node and has_hardware)


def clear_tsi_detector_methods(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_tsi_detector_method

    combo.blockSignals(True)
    combo.clear()
    combo.blockSignals(False)

    combo.setEnabled(False)
    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)

    dashboard.tsi_detector_method_actions = []
    dashboard.tsi_detector_selected_plugin = ""
    dashboard.tsi_detector_selected_action = ""

    clear_tsi_detector_parameter_controls(dashboard)


def _slotTSI_DetectorTypeChanged(dashboard: QtCore.QObject):
    clear_tsi_detector_methods(dashboard)
    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Query matching detector methods for the selected type, mode, and hardware."
    )


def _slotTSI_DetectorModeChanged(dashboard: QtCore.QObject):
    clear_tsi_detector_methods(dashboard)
    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Query matching detector methods for the selected type, mode, and hardware."
    )


def _slotTSI_DetectorHardwareChanged(dashboard: QtCore.QObject):
    clear_tsi_detector_methods(dashboard)
    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Query matching detector methods for the selected type, mode, and hardware."
    )


def reset_tsi_detector_customization(dashboard: QtCore.QObject):
    """
    Reset Card 2 after method/type/mode/hardware changes.
    """
    clear_tsi_detector_parameter_controls(dashboard)

    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)

    if dashboard.ui.comboBox_tsi_detector_method.count() > 0:
        dashboard.ui.pushButton_tsi_detector_customize.setEnabled(True)
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Customize this method to load its parameters and details."
        )
    else:
        dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)


def _slotTSI_DetectorMethodChanged(dashboard: QtCore.QObject):
    record = dashboard.ui.comboBox_tsi_detector_method.currentData()

    clear_tsi_detector_parameter_controls(dashboard)

    if not isinstance(record, dict):
        dashboard.tsi_detector_selected_plugin = ""
        dashboard.tsi_detector_selected_action = ""
        dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)
        dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a detector method to view details."
        )
        return

    plugin_name = str(record.get("plugin", "")).strip()
    action_name = str(record.get("action", "")).strip()

    dashboard.tsi_detector_selected_plugin = plugin_name
    dashboard.tsi_detector_selected_action = action_name

    has_method = bool(plugin_name and action_name)

    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(has_method)
    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)

    if has_method:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Customize this method to load its parameters and details."
        )
    else:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a detector method to view details."
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_DetectorCustomizeClicked(dashboard: QtCore.QObject):
    """
    Query the selected node for the selected detector action schema and render
    Card 2 when the result returns.
    """
    uid = getattr(dashboard, "selected_node_uid", "").strip()
    record = dashboard.ui.comboBox_tsi_detector_method.currentData()

    if not uid:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a sensor node before customizing detector parameters."
        )
        return

    if not isinstance(record, dict):
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a detector method before customizing parameters."
        )
        return

    plugin_name = str(record.get("plugin", "")).strip()
    action_name = str(record.get("action", "")).strip()

    if not plugin_name or not action_name:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Selected detector method is missing plugin/action information."
        )
        return

    dashboard.tsi_detector_customized = False
    dashboard.tsi_detector_selected_plugin = plugin_name
    dashboard.tsi_detector_selected_action = action_name

    clear_tsi_detector_parameter_controls(dashboard)

    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)
    dashboard.ui.pushButton_tsi_detector_customize.setText("Loading...")
    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)
    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Loading detector parameters..."
    )

    await dashboard.backend.queryPluginActionSchema(
        uid=uid,
        plugin_name=plugin_name,
        action_name=action_name,
        context="tsi.detector",
    )


def handle_tsi_detector_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str,
    action_name: str,
    node_uid: str,
    parameters: list,
):
    """
    Render Card 2 dynamic detector parameters from a Dashboard-only action
    schema result.
    """
    parameters = parameters or []

    selected_record = dashboard.ui.comboBox_tsi_detector_method.currentData()

    selected_plugin = ""
    selected_action = ""

    if isinstance(selected_record, dict):
        selected_plugin = str(selected_record.get("plugin", "")).strip()
        selected_action = str(selected_record.get("action", "")).strip()

    plugin_name = str(plugin_name or "").strip()
    action_name = str(action_name or "").strip()

    # Ignore stale schema responses after a method change.
    if selected_plugin != plugin_name or selected_action != action_name:
        dashboard.logger.debug(
            f"[TSI Detector] Ignoring stale schema for "
            f"{plugin_name}.{action_name}; "
            f"selected={selected_plugin}.{selected_action}"
        )

        dashboard.tsi_detector_customized = False

        dashboard.ui.pushButton_tsi_detector_customize.setText("Customize")
        dashboard.ui.pushButton_tsi_detector_customize.setEnabled(
            bool(selected_plugin and selected_action)
        )

        _tsi_detector_set_start_stop_button(dashboard, False)
        dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)
        return

    clear_tsi_detector_parameter_controls(dashboard)

    # These are what the Start slot needs.
    dashboard.tsi_detector_selected_plugin = plugin_name
    dashboard.tsi_detector_selected_action = action_name

    dashboard.tsi_detector_current_schema = {
        "plugin": plugin_name,
        "action": action_name,
        "node_uid": node_uid,
        "params": parameters,
    }

    dashboard.tsi_detector_parameter_widgets = {}

    _render_tsi_detector_parameter_widgets(
        dashboard,
        parameters,
    )

    dashboard.tsi_detector_customized = True

    description = _tsi_detector_schema_description(parameters)

    if description:
        dashboard.ui.label_tsi_detector_setup_info.setText(description)
    else:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Detector parameters loaded. Review settings before starting."
        )

    dashboard.ui.pushButton_tsi_detector_customize.setText("Customize")
    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(True)

    _tsi_detector_set_start_stop_button(dashboard, False)
    _tsi_detector_set_card3_enabled(dashboard, True)

    if getattr(dashboard, "selected_node_uid", ""):
        _tsi_detector_set_status_text(dashboard, "Idle")
    else:
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")


def clear_tsi_detector_parameter_controls(dashboard: QtCore.QObject):
    """
    Clear Card 2 dynamic parameter widgets.
    """
    contents = dashboard.ui.scrollAreaWidgetContents_tsi_detector_parameters

    layout = contents.layout()
    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    while layout.count():
        item = layout.takeAt(0)

        widget = item.widget()
        if widget is not None:
            widget.deleteLater()

        child_layout = item.layout()
        if child_layout is not None:
            while child_layout.count():
                child_item = child_layout.takeAt(0)
                child_widget = child_item.widget()
                if child_widget is not None:
                    child_widget.deleteLater()

    layout.setContentsMargins(12, 10, 12, 10)
    layout.setHorizontalSpacing(8)
    layout.setVerticalSpacing(7)

    for col in range(0, 8):
        layout.setColumnStretch(col, 0)
        layout.setColumnMinimumWidth(col, 0)

    contents.setMinimumWidth(0)
    contents.setMaximumWidth(390)

    dashboard.ui.scrollArea_tsi_detector_parameters.setWidgetResizable(True)
    dashboard.ui.scrollArea_tsi_detector_parameters.setAlignment(
        QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop
    )
    dashboard.ui.scrollArea_tsi_detector_parameters.setHorizontalScrollBarPolicy(
        QtCore.Qt.ScrollBarAlwaysOff
    )
    dashboard.ui.scrollArea_tsi_detector_parameters.setVerticalScrollBarPolicy(
        QtCore.Qt.ScrollBarAsNeeded
    )

    dashboard.tsi_detector_parameter_widgets = {}
    dashboard.tsi_detector_current_schema = {}
    dashboard.tsi_detector_customized = False

    _tsi_detector_set_card3_enabled(dashboard, False)


def _render_tsi_detector_parameter_widgets(
    dashboard: QtCore.QObject,
    parameters: list,
):
    contents = dashboard.ui.scrollAreaWidgetContents_tsi_detector_parameters

    layout = contents.layout()
    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    layout.setContentsMargins(12, 10, 12, 10)
    layout.setHorizontalSpacing(8)
    layout.setVerticalSpacing(7)
    layout.setAlignment(QtCore.Qt.AlignTop)

    # Kill leftovers from old layout columns.
    for col in range(0, 8):
        layout.setColumnStretch(col, 0)
        layout.setColumnMinimumWidth(col, 0)

    contents.setAutoFillBackground(False)
    contents.setMaximumWidth(430)

    dashboard.ui.scrollArea_tsi_detector_parameters.setWidgetResizable(True)
    dashboard.ui.scrollArea_tsi_detector_parameters.setAlignment(
        QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop
    )
    dashboard.ui.scrollArea_tsi_detector_parameters.setHorizontalScrollBarPolicy(
        QtCore.Qt.ScrollBarAlwaysOff
    )
    dashboard.ui.scrollArea_tsi_detector_parameters.setVerticalScrollBarPolicy(
        QtCore.Qt.ScrollBarAsNeeded
    )

    visible_params = [
        p for p in parameters
        if str(p.get("name", "")).strip() != "description"
    ]

    for row, param in enumerate(visible_params):
        name = str(param.get("name", "")).strip()
        if not name:
            continue

        label_text = str(param.get("label") or name).strip()
        widget = _create_tsi_detector_parameter_widget(dashboard, param)

        label = QtWidgets.QLabel(label_text + ":", contents)
        label.setObjectName("label2_tsi_detector_parameter")
        label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        label.setFixedWidth(160)

        layout.addWidget(label, row, 0)
        layout.addWidget(widget, row, 1)

        dashboard.tsi_detector_parameter_widgets[name] = widget

    layout.setColumnMinimumWidth(0, 160)
    layout.setColumnMinimumWidth(1, 180)
    layout.setColumnStretch(0, 0)
    layout.setColumnStretch(1, 0)


def _create_tsi_detector_parameter_widget(
    dashboard: QtCore.QObject,
    param: dict,
):
    param_name = str(param.get("name", "")).strip()
    param_type = str(param.get("type", "string") or "string").lower()
    default = param.get("default", "")
    options = param.get("options", []) or []

    compact_width = 180

    if param_type == "label":
        widget = QtWidgets.QLabel(str(default))
        widget.setObjectName(
            "label_tsi_dynamic_parameter_value"
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
        widget.setObjectName("doubleSpinBox_tsi_detector_parameter")

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
        widget.setObjectName("checkBox_tsi_detector_parameter")
        widget.setChecked(
            str(default).strip().lower() in {"1", "true", "yes", "on"}
        )
        widget.setFixedWidth(compact_width)
        return widget

    if options:
        widget = QtWidgets.QComboBox()
        widget.setObjectName("comboBox_tsi_detector_parameter")
        widget.addItems([str(option) for option in options])

        default_text = str(default)
        index = widget.findText(default_text)
        if index >= 0:
            widget.setCurrentIndex(index)

        widget.setFixedWidth(compact_width)

        if param_name == "run_mode":
            widget.setToolTip(
                "GUI mode is intended for local nodes. Remote nodes should run headless."
            )

        return widget

    widget = QtWidgets.QLineEdit()
    widget.setObjectName("lineEdit_tsi_detector_parameter")
    widget.setText(str(default))
    widget.setFixedWidth(compact_width)
    return widget


def _tsi_detector_schema_description(parameters: list) -> str:
    for param in parameters:
        if str(param.get("name", "")).strip() == "description":
            description = str(param.get("default", "") or "").strip()
            if description:
                return description
    return ""


def update_tsi_detector_selected_node_gate(dashboard: QtCore.QObject):
    """
    Shows the unified detector controls only when a selected Sensor Node exists
    and is currently connected.

    stackedWidget_tsi_detector:
        page 0 = normal Detector controls
        page 1 = no Sensor Node selected / unavailable empty-state page
    """
    selected_uid = getattr(dashboard, "selected_node_uid", "") or ""
    has_selected_node = bool(selected_uid)

    if has_selected_node:
        node_states = getattr(dashboard, "node_states", {}) or {}
        node_state = node_states.get(selected_uid)

        if isinstance(node_state, dict) and node_state.get("connected") is False:
            has_selected_node = False

    stack = getattr(dashboard.ui, "stackedWidget_tsi_detector", None)
    if stack is not None:
        stack.setCurrentIndex(0 if has_selected_node else 1)

    # If running, do not re-enable anything. A node status/hardware refresh may
    # call this gate while the action is active.
    if getattr(dashboard, "tsi_detector_running", False):
        _tsi_detector_set_controls_enabled(dashboard, False)
        _tsi_detector_set_card3_enabled(dashboard, True)
        update_tsi_detector_status_from_node(
            dashboard,
            node_uid=selected_uid,
        )
        return

    # Static filters should be enabled only when not running.
    dashboard.ui.comboBox_tsi_detector_type.setEnabled(True)
    dashboard.ui.comboBox_tsi_detector_mode.setEnabled(True)

    _tsi_detector_set_start_stop_button(dashboard, False)

    hardware_combo = dashboard.ui.comboBox_tsi_detector_hardware
    method_combo = dashboard.ui.comboBox_tsi_detector_method
    query_button = dashboard.ui.pushButton_tsi_detector_query
    customize_button = dashboard.ui.pushButton_tsi_detector_customize

    if not has_selected_node:
        clear_tsi_detector_methods(dashboard)

        hardware_combo.blockSignals(True)
        hardware_combo.clear()
        hardware_combo.blockSignals(False)
        hardware_combo.setEnabled(False)

        method_combo.setEnabled(False)
        query_button.setEnabled(False)
        customize_button.setEnabled(False)

        _tsi_detector_set_card3_enabled(dashboard, False)
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")

        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a sensor node before querying detector methods."
        )
        return

    update_tsi_detector_hardware_combo(dashboard)

    has_hardware = hardware_combo.count() > 0
    has_method = method_combo.count() > 0
    is_customized = bool(getattr(dashboard, "tsi_detector_customized", False))

    hardware_combo.setEnabled(has_hardware)
    method_combo.setEnabled(has_hardware and has_method)
    query_button.setEnabled(has_hardware)
    customize_button.setEnabled(has_hardware and has_method)

    _tsi_detector_set_card3_enabled(
        dashboard,
        has_selected_node and has_hardware and is_customized,
    )

    for widget in getattr(dashboard, "tsi_detector_parameter_widgets", {}).values():
        widget.setEnabled(True)

    _tsi_detector_set_status_text(dashboard, "Idle")

    if has_hardware:
        if not has_method:
            dashboard.ui.label_tsi_detector_setup_info.setText(
                "Query matching detector methods for the selected type, mode, and hardware."
            )
    else:
        clear_tsi_detector_methods(dashboard)
        _tsi_detector_set_card3_enabled(dashboard, False)
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "No detector-compatible hardware is configured for the selected node."
        )


def _tsi_detector_set_start_stop_button(
    dashboard: QtCore.QObject,
    running: bool,
):
    """
    Updates the unified detector start/stop button text and dynamic stylesheet state.
    """
    button = dashboard.ui.pushButton_tsi_detector_start_stop

    button.setProperty("running", bool(running))

    if running:
        button.setText("▮▮  Stop Detector")
    else:
        button.setText("▶  Start Detector")

    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


def _tsi_detector_set_status_text(
    dashboard: QtCore.QObject,
    text: str,
):
    """
    Sets the unified detector Card 3 status label.
    """
    label = getattr(dashboard.ui, "label2_tsi_detector_status", None)

    if label is not None:
        label.setText(str(text or "").strip())


def _tsi_detector_set_controls_enabled(
    dashboard: QtCore.QObject,
    enabled: bool,
):
    """
    Enables/disables unified detector setup and parameter controls while running.

    Do not use this for selected-node gating. Type/Mode are static filters and
    should stay populated.
    """
    for widget_name in (
        "comboBox_tsi_detector_type",
        "comboBox_tsi_detector_mode",
        "comboBox_tsi_detector_hardware",
        "comboBox_tsi_detector_method",
        "pushButton_tsi_detector_query",
        "pushButton_tsi_detector_customize",
    ):
        widget = getattr(dashboard.ui, widget_name, None)

        if widget is not None:
            widget.setEnabled(enabled)

    for widget in getattr(dashboard, "tsi_detector_parameter_widgets", {}).values():
        widget.setEnabled(enabled)


def _tsi_detector_set_running(
    dashboard: QtCore.QObject,
    node_uid: str,
):
    """
    Marks the unified detector action as running and updates Card 3/UI state.

    Status label follows the selected node action status, same as Fixed/Sweep.
    """
    dashboard.tsi_detector_running = True
    dashboard.tsi_detector_node_uid = node_uid or ""
    dashboard.tsi_detector_opid = ""
    dashboard.tsi_detector_waiting_for_opid = True

    stack = getattr(dashboard.ui, "stackedWidget_tsi_detector", None)
    if stack is not None:
        stack.setCurrentIndex(0)

    for table in _tsi_detector_results_tables(dashboard):
        table.clearContents()
        table.setRowCount(0)

    _tsi_detector_plot_start(dashboard)

    _tsi_detector_set_start_stop_button(dashboard, True)
    _tsi_detector_set_status_text(dashboard, "Starting...")
    update_tsi_detector_status_from_node(dashboard, node_uid=node_uid)

    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(True)
    _tsi_detector_set_controls_enabled(dashboard, False)


def _tsi_detector_set_stopped(dashboard: QtCore.QObject):
    """
    Marks the unified detector action as stopped and restores Card 3/UI state.
    """
    _tsi_detector_plot_stop(dashboard)

    dashboard.tsi_detector_running = False
    dashboard.tsi_detector_node_uid = ""
    dashboard.tsi_detector_opid = ""
    dashboard.tsi_detector_waiting_for_opid = False

    _tsi_detector_set_start_stop_button(dashboard, False)

    if getattr(dashboard, "selected_node_uid", ""):
        _tsi_detector_set_status_text(dashboard, "Idle")
    else:
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")

    update_tsi_detector_selected_node_gate(dashboard)


def update_tsi_detector_status_from_node(
    dashboard: QtCore.QObject,
    node_uid: str = "",
):
    """
    Mirrors the selected node's operation/status text into the unified detector
    status label.
    """
    selected_uid = getattr(dashboard, "selected_node_uid", "") or ""

    if node_uid and selected_uid and node_uid != selected_uid:
        return

    if not selected_uid:
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")
        return

    if not getattr(dashboard, "tsi_detector_running", False):
        _tsi_detector_set_status_text(dashboard, "Idle")
        return

    node_states = getattr(dashboard, "node_states", {}) or {}
    node_state = node_states.get(selected_uid, {}) or {}

    status_text = (
        node_state.get("status")
        or node_state.get("state")
        or node_state.get("operation_status")
        or node_state.get("last_status")
        or ""
    )

    status_text = str(status_text).strip()

    if not status_text:
        status_text = "Running"

    _tsi_detector_set_status_text(dashboard, status_text)


def update_tsi_detector_status_from_selected_node(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    status: str = "",
):
    """
    Mirrors the top-panel selected node's operation/status text into the
    unified detector status label.

    This uses dashboard.selected_node_uid, not selected_tactical_node_uid.
    """
    selected_uid = getattr(dashboard, "selected_node_uid", "") or ""

    if not selected_uid:
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")
        return

    if node_uid and node_uid != selected_uid:
        return

    node_states = getattr(dashboard, "node_states", {}) or {}
    node_state = node_states.get(selected_uid, {}) or {}

    if isinstance(node_state, dict) and node_state.get("connected") is False:
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")
        return

    status_text = str(
        status
        or node_state.get("status", "")
        or ""
    ).strip()

    detector_running = bool(
        getattr(dashboard, "tsi_detector_running", False)
    )

    if not detector_running:
        _tsi_detector_set_status_text(dashboard, "Idle")
        return

    if not status_text:
        status_text = "Starting..."

    _tsi_detector_set_status_text(dashboard, status_text)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_DetectorStartStopClicked(dashboard: QtCore.QObject):
    """
    Starts/stops the unified TSI Detector action through the plugin action path.
    """
    uid = getattr(dashboard, "selected_node_uid", "") or ""

    if not uid:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Select a Sensor Node before starting the detector.",
        )
        return

    if getattr(dashboard, "tsi_detector_running", False):
        try:
            await dashboard.backend.tacticalNodeStop([uid])
        finally:
            _tsi_detector_set_stopped(dashboard)
            dashboard.refreshStatusBarText()
        return

    plugin_name = getattr(dashboard, "tsi_detector_selected_plugin", "") or ""
    action_name = getattr(dashboard, "tsi_detector_selected_action", "") or ""

    if not plugin_name or not action_name:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Query and customize a detector method before starting.",
        )
        return

    if not getattr(dashboard, "tsi_detector_customized", False):
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Customize detector parameters before starting.",
        )
        return

    try:
        parameters = collect_tsi_detector_parameters(dashboard)
    except Exception as e:
        dashboard.logger.error(f"Could not collect TSI Detector parameters: {e}")
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Could not collect detector parameters.",
        )
        return

    _tsi_detector_set_running(
        dashboard,
        node_uid=uid,
    )

    try:
        await dashboard.backend.tacticalNodeExecute(
            [uid],
            plugin_name,
            action_name,
            parameters,
        )
    except Exception:
        _tsi_detector_set_stopped(dashboard)
        raise

    dashboard.refreshStatusBarText()


def collect_tsi_detector_parameters(dashboard: QtCore.QObject) -> dict:
    """
    Collect Card 2 dynamic detector parameter widget values into the plugin
    action parameters dictionary.
    """
    parameters = {}

    parameter_widgets = getattr(
        dashboard,
        "tsi_detector_parameter_widgets",
        {},
    )

    for parameter_name, widget in parameter_widgets.items():
        parameter_name = str(parameter_name or "").strip()

        if not parameter_name:
            continue

        if isinstance(widget, QtWidgets.QLineEdit):
            parameters[parameter_name] = widget.text()

        elif isinstance(widget, QtWidgets.QComboBox):
            parameters[parameter_name] = widget.currentText()

        elif isinstance(widget, QtWidgets.QDoubleSpinBox):
            value = widget.value()

            if widget.decimals() == 0:
                parameters[parameter_name] = int(value)
            else:
                parameters[parameter_name] = value

        elif isinstance(widget, QtWidgets.QSpinBox):
            parameters[parameter_name] = widget.value()

        elif isinstance(widget, QtWidgets.QCheckBox):
            parameters[parameter_name] = widget.isChecked()

        else:
            dashboard.logger.warning(
                f"[TSI Detector] Unsupported parameter widget for "
                f"{parameter_name}: {type(widget)}"
            )

    return parameters


def _tsi_detector_set_card3_enabled(
    dashboard: QtCore.QObject,
    enabled: bool,
):
    """
    Enables/disables Card 3 labels along with the Start/Stop button.
    """
    for widget_name in (
        # "label_tsi_detector_run_title",
        # "label_tsi_detector_run_subtitle",
        "label2_detector_status_status",
        "label2_tsi_detector_status",
    ):
        widget = getattr(dashboard.ui, widget_name, None)

        if widget is not None:
            widget.setEnabled(enabled)

    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(enabled)


def _tsi_detector_results_tables(dashboard: QtCore.QObject):
    """
    Returns all tables that should receive/clear TSI detector result rows.

    Conditioner frequency-plan import is now explicit through:
        pushButton_tsi_conditioner_input_frequencies_import_tsi

    Do not auto-populate Conditioner input tables from detector returns.
    """
    tables = []

    for name in (
        "tableWidget1_tsi_wideband",
    ):
        table = getattr(dashboard.ui, name, None)
        if table is not None:
            tables.append(table)

    return tables


def _tsi_detector_plot_color_settings(dashboard: QtCore.QObject):
    """
    Returns plot colors tuned for the current Dashboard color mode.
    """
    settings = getattr(dashboard.backend, "settings", {}) or {}
    color_mode = str(settings.get("color_mode", "") or "")

    text_color = settings.get("color4", "#000000")
    fig_face = settings.get("color1", "#f4f4f4")

    if "Dark" in color_mode:
        plot_face = "#1f2933"
        grid_color = "#56616f"
    else:
        plot_face = "#e9ecef"
        grid_color = "#b8c0ca"

    return fig_face, plot_face, grid_color, text_color


def _tsi_detector_plot_ensure_state(dashboard: QtCore.QObject):
    """
    Lazily initializes the unified TSI detector raster state.
    """
    if not hasattr(dashboard, "tsi_detector_plot_events"):
        dashboard.tsi_detector_plot_events = deque(maxlen=2000)

    if not hasattr(dashboard, "tsi_detector_plot_start_time"):
        dashboard.tsi_detector_plot_start_time = None

    if not hasattr(dashboard, "tsi_detector_plot_dirty"):
        dashboard.tsi_detector_plot_dirty = False

    if not hasattr(dashboard, "tsi_detector_plot_timer"):
        dashboard.tsi_detector_plot_timer = None

    if not hasattr(dashboard, "tsi_detector_plot_window_s"):
        dashboard.tsi_detector_plot_window_s = 60.0

    if not hasattr(dashboard, "tsi_detector_plot_initial_xlim_low"):
        dashboard.tsi_detector_plot_initial_xlim_low = None

    if not hasattr(dashboard, "tsi_detector_plot_initial_xlim_high"):
        dashboard.tsi_detector_plot_initial_xlim_high = None


def _tsi_detector_plot_reset(dashboard: QtCore.QObject):
    """
    Clears current unified detector plot state and draws an empty raster.
    """
    _tsi_detector_plot_ensure_state(dashboard)

    dashboard.tsi_detector_plot_events.clear()
    dashboard.tsi_detector_plot_start_time = None
    dashboard.tsi_detector_plot_dirty = True

    x_low, x_high = _tsi_detector_plot_initial_xlim(dashboard)
    dashboard.tsi_detector_plot_initial_xlim_low = x_low
    dashboard.tsi_detector_plot_initial_xlim_high = x_high

    _tsi_detector_plot_refresh(dashboard, force=True)


def _tsi_detector_plot_clear_points(dashboard: QtCore.QObject):
    """
    Clears plotted detector points while preserving the active run state.
    """
    _tsi_detector_plot_ensure_state(dashboard)

    dashboard.tsi_detector_plot_events.clear()
    dashboard.tsi_detector_plot_start_time = None
    dashboard.tsi_detector_plot_dirty = True

    _tsi_detector_plot_refresh(
        dashboard,
        force=True,
        running=getattr(dashboard, "tsi_detector_running", False),
    )


def _tsi_detector_plot_start(dashboard: QtCore.QObject):
    """
    Starts/resets the unified detector plot for a new detector operation.

    Elapsed time is anchored to the Dashboard Start click, not the first
    detection timestamp.
    """
    _tsi_detector_plot_ensure_state(dashboard)

    dashboard.tsi_detector_plot_events.clear()
    dashboard.tsi_detector_plot_start_time = time.time()
    dashboard.tsi_detector_plot_dirty = True

    x_low, x_high = _tsi_detector_plot_initial_xlim(dashboard)
    dashboard.tsi_detector_plot_initial_xlim_low = x_low
    dashboard.tsi_detector_plot_initial_xlim_high = x_high

    _tsi_detector_plot_refresh(dashboard, force=True, running=True)

    old_timer = getattr(dashboard, "tsi_detector_plot_timer", None)
    if old_timer is not None:
        try:
            old_timer.stop()
            old_timer.timeout.disconnect()
        except Exception:
            pass

    timer = QtCore.QTimer(dashboard)
    timer.setInterval(250)
    timer.timeout.connect(lambda: _tsi_detector_plot_refresh(dashboard))
    dashboard.tsi_detector_plot_timer = timer
    timer.start()


def _tsi_detector_plot_stop(dashboard: QtCore.QObject):
    """
    Stops the detector plot timer/refresh behavior but leaves visible points.
    """
    timer = getattr(dashboard, "tsi_detector_plot_timer", None)
    if timer is not None:
        try:
            timer.stop()
        except Exception:
            pass

    _tsi_detector_plot_refresh(dashboard, force=True, running=False)


def _tsi_detector_plot_add_detection(
    dashboard: QtCore.QObject,
    frequency_mhz: float,
    power_dbm: float,
    timestamp_s: float = None,
):
    """
    Appends one detector event to the unified detector raster.
    """
    _tsi_detector_plot_ensure_state(dashboard)

    if timestamp_s is None:
        timestamp_s = time.time()

    if dashboard.tsi_detector_plot_start_time is None:
        dashboard.tsi_detector_plot_start_time = timestamp_s

    elapsed_s = max(
        0.0,
        float(timestamp_s) - float(dashboard.tsi_detector_plot_start_time),
    )

    dashboard.tsi_detector_plot_events.append(
        {
            "frequency_mhz": float(frequency_mhz),
            "power_dbm": float(power_dbm),
            "timestamp_s": float(timestamp_s),
            "elapsed_s": elapsed_s,
        }
    )

    dashboard.tsi_detector_plot_dirty = True


def _tsi_detector_plot_refresh(
    dashboard: QtCore.QObject,
    force: bool = False,
    running: bool = None,
):
    """
    Redraws the unified TSI detector raster when there are new events.

    Rebuilds the Matplotlib figure contents because the shared TSI canvas may
    previously have been used as an image/waterfall canvas. Rebuilding prevents
    old imshow/colorbar state from forcing an equal-aspect, vertically squished
    plot.
    """
    _tsi_detector_plot_ensure_state(dashboard)

    if not force and not getattr(dashboard, "tsi_detector_plot_dirty", False):
        return

    canvas = getattr(dashboard, "matplotlib_widget", None)
    if canvas is None:
        return

    try:
        fig = canvas.fig

        fig_face, plot_face, grid_color, text_color = (
            _tsi_detector_plot_color_settings(dashboard)
        )

        events_all = list(getattr(dashboard, "tsi_detector_plot_events", []))
        window_s = float(
            getattr(dashboard, "tsi_detector_plot_window_s", 60.0) or 60.0
        )

        if events_all:
            latest_elapsed = max(float(e["elapsed_s"]) for e in events_all)
        else:
            latest_elapsed = 0.0

        y_min = max(0.0, latest_elapsed - window_s)
        y_max = max(window_s, latest_elapsed + 1.0)

        events = [
            e for e in events_all
            if float(e["elapsed_s"]) >= y_min
        ]

        freqs = [
            float(e["frequency_mhz"])
            for e in events_all
        ]

        x_min, x_max = _tsi_detector_plot_data_xlim(
            dashboard,
            freqs=freqs,
        )

        #
        # Rebuild the figure for detector-raster mode.
        #
        fig.clear()
        fig.set_facecolor(fig_face)

        ax = fig.add_subplot(111)
        canvas.axes = ax

        # Critical: do not let old imshow/equal-aspect behavior squeeze this.
        ax.set_aspect("auto", adjustable="box")

        fig.subplots_adjust(
            left=0.085,
            right=0.895,
            bottom=0.125,
            top=0.94,
            wspace=0.0,
            hspace=0.0,
        )

        ax.set_facecolor(plot_face)

        if running is None:
            running = bool(getattr(dashboard, "tsi_detector_running", False))

        if running:
            title_state = "Running"
        else:
            title_state = "Stopped"

        detector_type = ""
        detector_mode = ""

        try:
            detector_type = str(
                dashboard.ui.comboBox_tsi_detector_type.currentText()
            ).strip()
        except Exception:
            detector_type = ""

        try:
            detector_mode = str(
                dashboard.ui.comboBox_tsi_detector_mode.currentText()
            ).strip()
        except Exception:
            detector_mode = ""

        title_prefix = "Detector Activity"

        if detector_type or detector_mode:
            title_parts = [
                part for part in (detector_type, detector_mode)
                if part
            ]
            title_prefix = " ".join(title_parts) + " Detector Activity"

        ax.set_title(
            f"{title_prefix} - {title_state}",
            color=text_color,
            fontsize=10,
            pad=8,
        )

        ax.set_xlabel(
            "Frequency (MHz)",
            color=text_color,
            fontsize=9,
            labelpad=7,
        )
        ax.set_ylabel(
            "Time Elapsed (s)",
            color=text_color,
            fontsize=9,
            labelpad=7,
        )

        ax.set_xlim(x_min, x_max)
        ax.set_ylim(y_min, y_max)

        try:
            ax.xaxis.set_major_locator(matplotlib.ticker.MaxNLocator(nbins=6))
            ax.xaxis.set_major_formatter(
                matplotlib.ticker.FormatStrFormatter("%.3f")
            )
        except Exception:
            pass

        ax.grid(
            True,
            color=grid_color,
            linestyle="--",
            linewidth=0.6,
            alpha=0.75,
        )
        ax.set_axisbelow(True)

        ax.tick_params(axis="x", colors=text_color, labelsize=8)
        ax.tick_params(axis="y", colors=text_color, labelsize=8)

        for spine in ax.spines.values():
            spine.set_color(grid_color)

        try:
            cmap = matplotlib.cm.get_cmap("turbo")
        except Exception:
            cmap = matplotlib.cm.get_cmap("rainbow")

        norm = matplotlib.colors.Normalize(vmin=-60.0, vmax=40.0)

        if events:
            tick_height = max(0.35, (y_max - y_min) * 0.012)

            segments = []
            powers = []

            for event in events:
                x = float(event["frequency_mhz"])
                y = float(event["elapsed_s"])

                segments.append(
                    [
                        (x, max(y_min, y - tick_height)),
                        (x, min(y_max, y + tick_height)),
                    ]
                )
                powers.append(float(event["power_dbm"]))

            line_collection = LineCollection(
                segments,
                cmap=cmap,
                norm=norm,
                linewidths=2.8,
                alpha=0.95,
            )
            line_collection.set_array(np.array(powers))
            ax.add_collection(line_collection)

        else:
            if running:
                message = "Waiting for detector reports..."
            else:
                message = "No detector data"

            ax.text(
                0.5,
                0.5,
                message,
                transform=ax.transAxes,
                ha="center",
                va="center",
                color=text_color,
                alpha=0.75,
                fontsize=10,
            )

        sm = matplotlib.cm.ScalarMappable(norm=norm, cmap=cmap)
        sm.set_array([])

        cbar = fig.colorbar(
            sm,
            ax=ax,
            fraction=0.035,
            pad=0.025,
        )
        canvas.cbar = cbar

        cbar.set_label(
            label="Power (dB)",
            color=text_color,
            fontsize=9,
        )
        cbar.ax.tick_params(labelsize=8, color=text_color)

        matplotlib.pyplot.setp(
            matplotlib.pyplot.getp(cbar.ax.axes, "yticklabels"),
            color=text_color,
        )

        canvas.draw_idle()
        dashboard.tsi_detector_plot_dirty = False

    except Exception as e:
        dashboard.logger.debug(
            f"Failed to refresh unified TSI detector raster: {e}"
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_DetectorPromoteToSoiClicked(
    dashboard: QtCore.QObject,
):
    """
    Promote the complete selected TSI detection directly to an
    authoritative SOI at HIPRFISR.
    """
    detection = _get_selected_tsi_detector_detection(
        dashboard
    )

    if not detection:
        dashboard.logger.warning(
            "[TSI Detector] Select a detection before promoting it to an SOI."
        )
        return

    await dashboard.backend.promoteDetection(
        detection=dict(detection),
        destination="soi",
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_DetectorPromoteToTargetClicked(
    dashboard: QtCore.QObject,
):
    """
    Promote the complete selected TSI detection directly to an
    authoritative Target at HIPRFISR.
    """
    detection = _get_selected_tsi_detector_detection(
        dashboard
    )

    if not detection:
        dashboard.logger.warning(
            "[TSI Detector] Select a detection before promoting it to a Target."
        )
        return

    await dashboard.backend.promoteDetection(
        detection=dict(detection),
        destination="target",
    )





__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value)
    and value.__module__ == __name__
]
