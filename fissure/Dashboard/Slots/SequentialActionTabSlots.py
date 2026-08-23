from PyQt5 import QtCore, QtGui, QtWidgets
import asyncio
import copy
import os
import time
import uuid
import qasync

import fissure.utils
from ..UI_Components import DetectorSelectionDialog, SequentialActionSelectionDialog


SEQUENCE_DATA_ROLE = QtCore.Qt.UserRole


def initialize_sequential_actions_tab(dashboard: QtCore.QObject):
    """Initialize the Targets & Actions Sequential Actions builder."""
    dashboard.sequential_actions_sequence = []
    dashboard.sequential_actions_task = None
    dashboard.sequential_actions_running = False
    dashboard.sequential_actions_stop_requested = False
    dashboard.sequential_actions_node_uid = ""
    dashboard.sequential_actions_target_id = ""
    dashboard.sequential_actions_run_id = ""
    dashboard.sequential_actions_operation_history = []
    dashboard.sequential_actions_timeline_cards = []
    dashboard.sequential_actions_run_sequence = []
    dashboard.sequential_actions_started_at = 0.0
    dashboard.sequential_actions_cycle = 0
    dashboard.sequential_actions_completed_iterations = 0
    dashboard.sequential_actions_total_iterations = 0
    dashboard.sequential_actions_current_index = -1
    dashboard.sequential_actions_current_repeat = 0
    dashboard.sequential_actions_current_operation_id = ""
    dashboard.sequential_actions_current_event = None
    dashboard.sequential_actions_current_result = ""
    dashboard.sequential_actions_current_seen_running = False
    dashboard.sequential_actions_current_monitor_status = False
    dashboard.sequential_actions_current_stop_reason = ""
    dashboard.sequential_actions_detector_configs = []
    dashboard.sequential_actions_detector_operation_ids = set()
    dashboard.sequential_actions_waiting_for_detection = False
    dashboard.sequential_actions_detection_event = None
    dashboard.sequential_actions_detection = None

    dashboard.ui.stackedWidget_ta_sequential_actions.setCurrentWidget(
        dashboard.ui.page_ta_sequential_actions_no_node
    )

    select_node_icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", "select_node.png")
    if os.path.isfile(select_node_icon_path):
        select_node_pixmap = QtGui.QPixmap(select_node_icon_path)
        dashboard.ui.label_ta_sequential_actions_select_sensor_node_image.setPixmap(select_node_pixmap)
        dashboard.ui.label_ta_sequential_actions_select_sensor_node_image.setScaledContents(False)
        dashboard.ui.label_ta_sequential_actions_select_sensor_node_image.setAlignment(QtCore.Qt.AlignCenter)

    table = dashboard.ui.tableWidget_ta_sequential_actions_sequence
    table.verticalHeader().setVisible(False)
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    table.setWordWrap(False)
    table.setTextElideMode(QtCore.Qt.ElideRight)

    header = table.horizontalHeader()
    header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
    header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(5, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(6, QtWidgets.QHeaderView.ResizeToContents)
    header.setDefaultAlignment(QtCore.Qt.AlignCenter | QtCore.Qt.AlignVCenter)

    detector_table = dashboard.ui.tableWidget_ta_sequential_actions_detectors
    detector_table.verticalHeader().setVisible(False)
    detector_table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    detector_table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    detector_table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    detector_table.setWordWrap(False)
    detector_table.setTextElideMode(QtCore.Qt.ElideRight)

    detector_header = detector_table.horizontalHeader()
    detector_header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    detector_header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
    detector_header.setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)
    detector_header.setDefaultAlignment(QtCore.Qt.AlignCenter | QtCore.Qt.AlignVCenter)

    dashboard.ui.label_ta_sequential_actions_total_duration.setText("0.0 s")
    dashboard.ui.label_ta_sequential_actions_execution_status.setText("Idle")
    dashboard.ui.label_ta_sequential_actions_execution_current_action.setText("—")
    dashboard.ui.label_ta_sequential_actions_execution_elapsed_time.setText("00:00:00")
    dashboard.ui.label_ta_sequential_actions_execution_operation_id.setText("—")
    dashboard.ui.progressBar_ta_sequential_actions.setRange(0, 100)
    dashboard.ui.progressBar_ta_sequential_actions.setValue(0)
    dashboard.ui.plainTextEdit_ta_sequential_actions_sequence_log.clear()
    dashboard.ui.plainTextEdit_ta_sequential_actions_action_log.clear()
    dashboard.ui.plainTextEdit_ta_sequential_actions_sequence_log.setReadOnly(True)
    dashboard.ui.plainTextEdit_ta_sequential_actions_action_log.setReadOnly(True)
    dashboard.ui.label_ta_sequential_actions_action_log.setText("Action Log")

    timeline_scroll = dashboard.ui.scrollArea_ta_sequential_actions_timeline
    timeline_scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
    timeline_scroll.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    timeline_scroll.setWidgetResizable(True)

    dashboard.ui.pushButton_ta_sequential_actions_start_stop.setText("Start Sequence")
    dashboard.ui.pushButton_ta_sequential_actions_start_stop.setEnabled(False)
    dashboard.ui.pushButton_ta_sequential_actions_detector_add.setEnabled(False)
    dashboard.ui.pushButton_ta_sequential_actions_detector_remove.setEnabled(False)

    _ensure_sequential_actions_timeline_layout(dashboard)
    _update_sequential_actions_table(dashboard)
    update_sequential_actions_selected_node_gate(dashboard)


def _sequential_actions_selected_node_available(dashboard: QtCore.QObject):
    """Return True when the globally selected Sensor Node is currently available."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        return False

    node_state = (getattr(dashboard, "node_states", {}) or {}).get(node_uid)
    if isinstance(node_state, dict) and node_state.get("connected") is False:
        return False

    return True


def update_sequential_actions_selected_node_gate(dashboard: QtCore.QObject):
    """Show Sequential Actions controls only while the selected Sensor Node is available."""
    active = _sequential_actions_active(dashboard)
    has_selected_node = _sequential_actions_selected_node_available(dashboard)
    dashboard.ui.stackedWidget_ta_sequential_actions.setCurrentWidget(
        dashboard.ui.page_ta_sequential_actions_controls
        if active or has_selected_node
        else dashboard.ui.page_ta_sequential_actions_no_node
    )
    _update_sequence_button_states(dashboard)
    _update_sequential_actions_detector_button_states(dashboard)

def _selected_sequence_row(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_sequential_actions_sequence
    rows = sorted({index.row() for index in table.selectedIndexes()})
    return rows[0] if rows else -1


def _update_sequence_button_states(dashboard: QtCore.QObject):
    row = _selected_sequence_row(dashboard)
    count = len(getattr(dashboard, "sequential_actions_sequence", []) or [])
    has_selection = 0 <= row < count
    has_node = _sequential_actions_selected_node_available(dashboard)
    active = _sequential_actions_active(dashboard)

    dashboard.ui.pushButton_ta_sequential_actions_add.setEnabled(has_node and not active)
    dashboard.ui.pushButton_ta_sequential_actions_duplicate.setEnabled(has_selection and not active)
    dashboard.ui.pushButton_ta_sequential_actions_remove.setEnabled(has_selection and not active)
    dashboard.ui.pushButton_ta_sequential_actions_up.setEnabled(has_selection and row > 0 and not active)
    dashboard.ui.pushButton_ta_sequential_actions_down.setEnabled(has_selection and row < count - 1 and not active)
    dashboard.ui.tableWidget_ta_sequential_actions_sequence.setEnabled(not active)
    dashboard.ui.comboBox_ta_sequential_actions_on_error.setEnabled(not active)
    dashboard.ui.comboBox_ta_sequential_actions_on_complete.setEnabled(not active)

    if active:
        dashboard.ui.pushButton_ta_sequential_actions_start_stop.setEnabled(True)
    else:
        dashboard.ui.pushButton_ta_sequential_actions_start_stop.setEnabled(
            has_node and count > 0
        )

def _sequence_item(text, alignment=None):
    item = QtWidgets.QTableWidgetItem(str(text))
    item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
    if alignment is not None:
        item.setTextAlignment(alignment)
    return item


def _format_seconds(seconds):
    seconds = max(0.0, float(seconds or 0.0))
    if seconds < 60.0:
        return f"{seconds:.1f} s"
    if seconds < 3600.0:
        minutes = int(seconds // 60)
        remaining = seconds - minutes * 60
        return f"{minutes}m {remaining:.0f}s"
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    return f"{hours}h {minutes}m"


def _sequence_action_estimated_duration(action_config):
    duration = max(0.0, float(action_config.get("duration", 0.0) or 0.0))
    repeat = max(1, int(action_config.get("repeat", 1) or 1))
    interval = max(0.0, float(action_config.get("interval", 0.0) or 0.0))
    return duration * repeat + interval * max(0, repeat - 1)


def _update_sequential_actions_table(dashboard: QtCore.QObject, select_row=None):
    """Render the in-memory sequence into the table and update its estimate."""
    table = dashboard.ui.tableWidget_ta_sequential_actions_sequence
    sequence = getattr(dashboard, "sequential_actions_sequence", []) or []

    table.blockSignals(True)
    table.setRowCount(len(sequence))
    for row, action_config in enumerate(sequence):
        values = [
            str(action_config.get("plugin", "") or ""),
            str(action_config.get("action", "") or ""),
            str(action_config.get("description", "") or ""),
            _format_seconds(action_config.get("duration", 0.0)),
            str(max(1, int(action_config.get("repeat", 1) or 1))),
            _format_seconds(action_config.get("interval", 0.0)),
            "Yes" if bool(action_config.get("advance_early", False)) else "No",
        ]

        for column, value in enumerate(values):
            alignment = None if column == 2 else QtCore.Qt.AlignCenter
            item = _sequence_item(value, alignment)
            if column == 0:
                item.setData(SEQUENCE_DATA_ROLE, copy.deepcopy(action_config))
            table.setItem(row, column, item)

    table.blockSignals(False)

    total_duration = sum(_sequence_action_estimated_duration(config) for config in sequence)
    dashboard.ui.label_ta_sequential_actions_total_duration.setText(_format_seconds(total_duration))

    if sequence:
        if select_row is None:
            select_row = min(max(_selected_sequence_row(dashboard), 0), len(sequence) - 1)
        if 0 <= select_row < len(sequence):
            table.selectRow(select_row)
    else:
        table.clearSelection()

    if not _sequential_actions_active(dashboard):
        _build_sequential_actions_timeline(dashboard, sequence)

    _update_sequence_button_states(dashboard)


def _open_sequence_action_dialog(dashboard: QtCore.QObject, action_config=None):
    """Open the generic action chooser used for adding/editing one sequence row."""
    return dashboard.openPopUp(
        "SequentialActionSelectionDialog",
        SequentialActionSelectionDialog,
        copy.deepcopy(action_config or {}),
    )


def _slotSequentialActionsAddClicked(dashboard: QtCore.QObject):
    if not _sequential_actions_selected_node_available(dashboard):
        return

    action_config = _open_sequence_action_dialog(dashboard)
    if not isinstance(action_config, dict):
        return

    dashboard.sequential_actions_sequence.append(action_config)
    _update_sequential_actions_table(dashboard, len(dashboard.sequential_actions_sequence) - 1)


def _slotSequentialActionsTableDoubleClicked(dashboard: QtCore.QObject, row, column=0):
    """Double-click a row to reopen that action in the configuration dialog."""
    sequence = getattr(dashboard, "sequential_actions_sequence", []) or []
    if not _sequential_actions_selected_node_available(dashboard) or not (0 <= row < len(sequence)):
        return

    updated_config = _open_sequence_action_dialog(dashboard, sequence[row])
    if not isinstance(updated_config, dict):
        return

    sequence[row] = updated_config
    _update_sequential_actions_table(dashboard, row)


def _slotSequentialActionsDuplicateClicked(dashboard: QtCore.QObject):
    row = _selected_sequence_row(dashboard)
    sequence = getattr(dashboard, "sequential_actions_sequence", []) or []
    if not (0 <= row < len(sequence)):
        return

    insert_row = row + 1
    sequence.insert(insert_row, copy.deepcopy(sequence[row]))
    _update_sequential_actions_table(dashboard, insert_row)


def _slotSequentialActionsRemoveClicked(dashboard: QtCore.QObject):
    row = _selected_sequence_row(dashboard)
    sequence = getattr(dashboard, "sequential_actions_sequence", []) or []
    if not (0 <= row < len(sequence)):
        return

    sequence.pop(row)
    next_row = min(row, len(sequence) - 1)
    _update_sequential_actions_table(dashboard, next_row if next_row >= 0 else None)


def _slotSequentialActionsUpClicked(dashboard: QtCore.QObject):
    row = _selected_sequence_row(dashboard)
    sequence = getattr(dashboard, "sequential_actions_sequence", []) or []
    if not (0 < row < len(sequence)):
        return

    sequence[row - 1], sequence[row] = sequence[row], sequence[row - 1]
    _update_sequential_actions_table(dashboard, row - 1)


def _slotSequentialActionsDownClicked(dashboard: QtCore.QObject):
    row = _selected_sequence_row(dashboard)
    sequence = getattr(dashboard, "sequential_actions_sequence", []) or []
    if not (0 <= row < len(sequence) - 1):
        return

    sequence[row + 1], sequence[row] = sequence[row], sequence[row + 1]
    _update_sequential_actions_table(dashboard, row + 1)


def _update_sequential_actions_detector_button_states(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_sequential_actions_detectors
    has_node = _sequential_actions_selected_node_available(dashboard)
    active = _sequential_actions_active(dashboard)
    dashboard.ui.pushButton_ta_sequential_actions_detector_add.setEnabled(has_node and not active)
    dashboard.ui.pushButton_ta_sequential_actions_detector_remove.setEnabled(
        has_node and table.currentRow() >= 0 and not active
    )
    table.setEnabled(not active)

def _slotSequentialActionsDetectorAddClicked(dashboard: QtCore.QObject):
    """Add one reusable detector configuration to the sequence gate."""
    if not _sequential_actions_selected_node_available(dashboard):
        return

    detector_config = dashboard.openPopUp("DetectorSelectionDialog", DetectorSelectionDialog)
    if not detector_config:
        return

    plugin_name = str(detector_config.get("plugin", "") or "").strip()
    action_name = str(detector_config.get("action", "") or "").strip()
    hardware = str(detector_config.get("hardware", "") or "").strip()
    parameters = detector_config.get("parameters", {}) or {}

    if not plugin_name or not action_name:
        dashboard.logger.warning("Sequential Actions detector selection returned without a plugin/action.")
        return

    detector_name = f"{plugin_name}: {action_name}"
    parameter_summary = ", ".join(f"{name}={value}" for name, value in parameters.items())
    table = dashboard.ui.tableWidget_ta_sequential_actions_detectors
    row = table.rowCount()
    table.insertRow(row)

    detector_item = QtWidgets.QTableWidgetItem(detector_name)
    detector_item.setTextAlignment(QtCore.Qt.AlignCenter)
    detector_item.setFlags(detector_item.flags() & ~QtCore.Qt.ItemIsEditable)
    detector_item.setData(QtCore.Qt.UserRole, detector_config)
    table.setItem(row, 0, detector_item)

    hardware_item = QtWidgets.QTableWidgetItem(hardware or "No Hardware")
    hardware_item.setTextAlignment(QtCore.Qt.AlignCenter)
    hardware_item.setFlags(hardware_item.flags() & ~QtCore.Qt.ItemIsEditable)
    table.setItem(row, 1, hardware_item)

    parameters_item = QtWidgets.QTableWidgetItem(f"  {parameter_summary}")
    parameters_item.setTextAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
    parameters_item.setFlags(parameters_item.flags() & ~QtCore.Qt.ItemIsEditable)
    parameters_item.setToolTip(parameter_summary)
    table.setItem(row, 2, parameters_item)

    table.resizeRowsToContents()
    table.selectRow(row)
    _update_sequential_actions_detector_button_states(dashboard)
    _update_sequence_button_states(dashboard)
    dashboard.logger.info(f"Added Sequential Actions detector: {detector_name}")


def _slotSequentialActionsDetectorRemoveClicked(dashboard: QtCore.QObject):
    """Remove the selected detector configuration from the sequence gate."""
    table = dashboard.ui.tableWidget_ta_sequential_actions_detectors
    row = table.currentRow()
    if row < 0:
        return

    table.removeRow(row)
    if table.rowCount() > 0:
        table.selectRow(min(row, table.rowCount() - 1))
    _update_sequential_actions_detector_button_states(dashboard)
    _update_sequence_button_states(dashboard)


def _slotSequentialActionsDetectorSelectionChanged(dashboard: QtCore.QObject):
    _update_sequential_actions_detector_button_states(dashboard)


def collect_sequential_actions_detector_configs(dashboard: QtCore.QObject):
    """Return detector configurations stored in the Sequential Actions detector table."""
    table = dashboard.ui.tableWidget_ta_sequential_actions_detectors
    detector_configs = []
    for row in range(table.rowCount()):
        item = table.item(row, 0)
        if item is None:
            continue
        detector_config = item.data(QtCore.Qt.UserRole)
        if isinstance(detector_config, dict):
            detector_configs.append(dict(detector_config))
    return detector_configs


def _sequential_actions_active(dashboard: QtCore.QObject):
    return bool(getattr(dashboard, "sequential_actions_running", False))


def _sequential_actions_node_uids_match(first: str, second: str):
    first = str(first or "").strip()
    second = str(second or "").strip()
    if not first or not second:
        return False
    return first == second or first.endswith(second) or second.endswith(first)


def _set_sequential_actions_start_stop_button(dashboard: QtCore.QObject, running: bool):
    button = dashboard.ui.pushButton_ta_sequential_actions_start_stop
    button.setText("Stop Sequence" if running else "Start Sequence")
    button.setProperty("running", bool(running))
    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


def _ensure_sequential_actions_timeline_layout(dashboard: QtCore.QObject):
    """Ensure the timeline scroll-area contents own one horizontal card layout."""
    contents = dashboard.ui.scrollAreaWidgetContents_ta_sequential_actions_timeline
    layout = contents.layout()
    if layout is None:
        layout = QtWidgets.QHBoxLayout(contents)
        contents.setLayout(layout)

    layout.setContentsMargins(6, 6, 6, 6)
    layout.setSpacing(8)
    layout.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
    return layout


def _clear_sequential_actions_timeline(dashboard: QtCore.QObject):
    """Remove all generated timeline cards."""
    layout = _ensure_sequential_actions_timeline_layout(dashboard)
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()

    dashboard.sequential_actions_timeline_cards = []


def _build_sequential_actions_timeline(dashboard: QtCore.QObject, sequence=None):
    """Build equal-width timeline cards from the configured or running sequence."""
    sequence = sequence if sequence is not None else (getattr(dashboard, "sequential_actions_sequence", []) or [])
    _clear_sequential_actions_timeline(dashboard)
    layout = _ensure_sequential_actions_timeline_layout(dashboard)

    cards = []
    for index, action_config in enumerate(sequence):
        plugin_name = str(action_config.get("plugin", "") or "")
        action_name = str(action_config.get("action", "") or "")
        duration = _format_seconds(action_config.get("duration", 0.0))
        repeat = max(1, int(action_config.get("repeat", 1) or 1))

        card = QtWidgets.QFrame(dashboard.ui.scrollAreaWidgetContents_ta_sequential_actions_timeline)
        card.setObjectName("frame_ta_sequential_actions_timeline_action")
        card.setProperty("timelineState", "pending")
        card.setFrameShape(QtWidgets.QFrame.StyledPanel)
        card.setMinimumWidth(180)
        card.setMaximumWidth(220)
        card.setMinimumHeight(105)

        card_layout = QtWidgets.QVBoxLayout(card)
        card_layout.setContentsMargins(10, 8, 10, 8)
        card_layout.setSpacing(3)

        title = QtWidgets.QLabel(f"{index + 1}. {plugin_name}: {action_name}", card)
        title.setObjectName("label2_ta_sequential_actions_timeline_action")
        title.setAlignment(QtCore.Qt.AlignCenter)
        title.setWordWrap(True)

        detail_text = duration
        if repeat > 1:
            detail_text += f"  •  Repeat {repeat}"

        detail = QtWidgets.QLabel(detail_text, card)
        detail.setObjectName("label2_ta_sequential_actions_timeline_detail")
        detail.setAlignment(QtCore.Qt.AlignCenter)
        detail.setWordWrap(True)

        state = QtWidgets.QLabel("Pending", card)
        state.setObjectName("label2_ta_sequential_actions_timeline_state")
        state.setProperty("timelineState", "pending")
        state.setAlignment(QtCore.Qt.AlignCenter)

        card_layout.addWidget(title)
        card_layout.addStretch(1)
        card_layout.addWidget(detail)
        card_layout.addWidget(state)

        layout.addWidget(card)
        cards.append({"frame": card, "state": state})

    layout.addStretch(1)
    dashboard.sequential_actions_timeline_cards = cards


def _set_sequential_actions_timeline_state(
    dashboard: QtCore.QObject,
    action_index: int,
    state: str,
    repeat_index: int = 0,
    repeat_total: int = 0,
):
    """Update one generated timeline card without rebuilding the strip."""
    cards = getattr(dashboard, "sequential_actions_timeline_cards", []) or []
    if not (0 <= action_index < len(cards)):
        return

    state = str(state or "pending").strip().lower()
    state_text = {
        "pending": "Pending",
        "running": "Running",
        "completed": "Completed",
        "error": "Error",
        "stopped": "Stopped",
    }.get(state, state.title())

    if state == "running" and repeat_total > 1:
        state_text = f"Running ({repeat_index}/{repeat_total})"

    card = cards[action_index]
    frame = card.get("frame")
    state_label = card.get("state")

    if frame is not None:
        frame.setProperty("timelineState", state)
        frame.style().unpolish(frame)
        frame.style().polish(frame)
        frame.update()

    if state_label is not None:
        state_label.setText(state_text)
        state_label.setProperty("timelineState", state)
        state_label.style().unpolish(state_label)
        state_label.style().polish(state_label)
        state_label.update()


def _reset_sequential_actions_timeline(dashboard: QtCore.QObject):
    """Return all generated timeline cards to Pending."""
    cards = getattr(dashboard, "sequential_actions_timeline_cards", []) or []
    for index in range(len(cards)):
        _set_sequential_actions_timeline_state(dashboard, index, "pending")


def _append_sequence_log(dashboard: QtCore.QObject, text: str):
    dashboard.ui.plainTextEdit_ta_sequential_actions_sequence_log.appendPlainText(str(text))


def _append_action_log(dashboard: QtCore.QObject, text: str):
    dashboard.ui.plainTextEdit_ta_sequential_actions_action_log.appendPlainText(str(text))


def _format_elapsed_clock(seconds):
    seconds = max(0, int(seconds or 0))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _update_sequential_actions_elapsed(dashboard: QtCore.QObject):
    started_at = float(getattr(dashboard, "sequential_actions_started_at", 0.0) or 0.0)
    elapsed = max(0.0, time.time() - started_at) if started_at else 0.0
    dashboard.ui.label_ta_sequential_actions_execution_elapsed_time.setText(_format_elapsed_clock(elapsed))


def _update_sequential_actions_progress(dashboard: QtCore.QObject, partial=0.0):
    total = max(1, int(getattr(dashboard, "sequential_actions_total_iterations", 0) or 0))
    completed = max(0, int(getattr(dashboard, "sequential_actions_completed_iterations", 0) or 0))
    partial = min(1.0, max(0.0, float(partial or 0.0)))
    percent = int(round(100.0 * min(1.0, (completed + partial) / total)))
    dashboard.ui.progressBar_ta_sequential_actions.setValue(percent)


def _clear_sequential_actions_current_state(dashboard: QtCore.QObject):
    dashboard.sequential_actions_current_index = -1
    dashboard.sequential_actions_current_repeat = 0
    dashboard.sequential_actions_current_operation_id = ""
    dashboard.sequential_actions_current_event = None
    dashboard.sequential_actions_current_result = ""
    dashboard.sequential_actions_current_seen_running = False
    dashboard.sequential_actions_current_monitor_status = False
    dashboard.sequential_actions_current_stop_reason = ""


def _clear_sequential_actions_run_state(dashboard: QtCore.QObject):
    dashboard.sequential_actions_task = None
    dashboard.sequential_actions_running = False
    dashboard.sequential_actions_stop_requested = False
    dashboard.sequential_actions_node_uid = ""
    dashboard.sequential_actions_target_id = ""
    dashboard.sequential_actions_run_id = ""
    dashboard.sequential_actions_operation_history = []
    dashboard.sequential_actions_run_sequence = []
    dashboard.sequential_actions_started_at = 0.0
    dashboard.sequential_actions_cycle = 0
    dashboard.sequential_actions_completed_iterations = 0
    dashboard.sequential_actions_total_iterations = 0
    dashboard.sequential_actions_detector_configs = []
    dashboard.sequential_actions_detector_operation_ids = set()
    dashboard.sequential_actions_waiting_for_detection = False
    dashboard.sequential_actions_detection_event = None
    dashboard.sequential_actions_detection = None
    _clear_sequential_actions_current_state(dashboard)


async def _wait_for_sequence_interval(dashboard: QtCore.QObject, seconds: float):
    deadline = time.monotonic() + max(0.0, float(seconds or 0.0))
    while time.monotonic() < deadline:
        if bool(getattr(dashboard, "sequential_actions_stop_requested", False)):
            return False
        _update_sequential_actions_elapsed(dashboard)
        await asyncio.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    return True


async def _wait_for_current_sequence_action(
    dashboard: QtCore.QObject,
    node_uid: str,
    duration: float,
    advance_early: bool,
):
    """Wait for one action repeat using configured duration and completion behavior."""
    event = getattr(dashboard, "sequential_actions_current_event", None)
    if event is None:
        return "error"

    duration = max(0.0, float(duration or 0.0))
    started = time.monotonic()

    while True:
        if bool(getattr(dashboard, "sequential_actions_stop_requested", False)):
            operation_id = str(getattr(dashboard, "sequential_actions_current_operation_id", "") or "").strip()
            if operation_id and not event.is_set():
                dashboard.sequential_actions_current_stop_reason = "sequence"
                await dashboard.backend.stopPluginOperation(node_uid, operation_id)
            return "stopped"

        elapsed = time.monotonic() - started
        partial = min(1.0, elapsed / duration) if duration > 0.0 else 0.0
        _update_sequential_actions_elapsed(dashboard)
        _update_sequential_actions_progress(dashboard, partial)

        if event.is_set():
            result = str(getattr(dashboard, "sequential_actions_current_result", "") or "").strip().lower()
            if result == "error":
                return "error"
            if result == "stopped" and dashboard.sequential_actions_current_stop_reason != "duration":
                return "stopped"
            if advance_early or duration <= 0.0:
                return "completed"

        if duration > 0.0 and elapsed >= duration:
            if not event.is_set():
                operation_id = str(getattr(dashboard, "sequential_actions_current_operation_id", "") or "").strip()
                if operation_id:
                    dashboard.sequential_actions_current_stop_reason = "duration"
                    _append_action_log(dashboard, f"Duration reached; stopping operation {operation_id}.")
                    await dashboard.backend.stopPluginOperation(node_uid, operation_id)

                try:
                    await asyncio.wait_for(event.wait(), timeout=5.0)
                except asyncio.TimeoutError:
                    _append_action_log(dashboard, "Timed out waiting for operation stop confirmation.")

            result = str(getattr(dashboard, "sequential_actions_current_result", "") or "").strip().lower()
            return "error" if result == "error" else "completed"

        await asyncio.sleep(0.1)


async def _run_sequence_action_repeat(
    dashboard: QtCore.QObject,
    node_uid: str,
    action_config: dict,
    action_index: int,
    repeat_index: int,
):
    plugin_name = str(action_config.get("plugin", "") or "").strip()
    action_name = str(action_config.get("action", "") or "").strip()
    parameters = copy.deepcopy(action_config.get("parameters", {}) or {})
    duration = max(0.0, float(action_config.get("duration", 0.0) or 0.0))
    repeat_total = max(1, int(action_config.get("repeat", 1) or 1))
    advance_early = bool(action_config.get("advance_early", False))
    operation_id = str(uuid.uuid4())
    operation_started_at = time.time()
    parameters["operation_id"] = operation_id

    dashboard.sequential_actions_current_index = action_index
    dashboard.sequential_actions_current_repeat = repeat_index
    dashboard.sequential_actions_current_operation_id = operation_id
    dashboard.sequential_actions_current_event = asyncio.Event()
    dashboard.sequential_actions_current_result = ""
    dashboard.sequential_actions_current_seen_running = False
    dashboard.sequential_actions_current_monitor_status = False
    dashboard.sequential_actions_current_stop_reason = ""

    action_text = f"{plugin_name}: {action_name}"
    dashboard.ui.label_ta_sequential_actions_execution_current_action.setText(
        f"{action_text}  ({repeat_index}/{repeat_total})"
    )
    dashboard.ui.label_ta_sequential_actions_execution_operation_id.setText(operation_id)
    dashboard.ui.label_ta_sequential_actions_action_log.setText(f"Action Log ({action_text})")
    _set_sequential_actions_timeline_state(
        dashboard,
        action_index,
        "running",
        repeat_index=repeat_index,
        repeat_total=repeat_total,
    )
    dashboard.ui.label_ta_sequential_actions_execution_status.setText("Starting...")
    dashboard.ui.plainTextEdit_ta_sequential_actions_action_log.clear()
    _append_action_log(dashboard, f"Starting {action_text}")
    _append_action_log(dashboard, f"Repeat: {repeat_index}/{repeat_total}")
    _append_action_log(dashboard, f"Operation ID: {operation_id}")
    _append_sequence_log(
        dashboard,
        f"Action {action_index + 1}: starting {action_text} ({repeat_index}/{repeat_total})",
    )

    try:
        await dashboard.backend.tacticalNodeExecute([node_uid], plugin_name, action_name, parameters)
    except Exception as error:
        _append_action_log(dashboard, f"Start failed: {error}")
        _append_sequence_log(dashboard, f"Action {action_index + 1}: start failed: {error}")
        dashboard.sequential_actions_operation_history.append(
            {
                "action_index": action_index,
                "repeat_index": repeat_index,
                "plugin": plugin_name,
                "action": action_name,
                "operation_id": operation_id,
                "status": "error",
                "duration_seconds": max(0.0, time.time() - operation_started_at),
            }
        )
        return "error"

    dashboard.sequential_actions_current_monitor_status = True
    result = await _wait_for_current_sequence_action(dashboard, node_uid, duration, advance_early)

    if result == "completed":
        _append_action_log(dashboard, "Action repeat complete.")
        _append_sequence_log(dashboard, f"Action {action_index + 1}: repeat {repeat_index} complete")
    elif result == "error":
        _append_action_log(dashboard, "Action repeat ended with an error.")
        _append_sequence_log(dashboard, f"Action {action_index + 1}: repeat {repeat_index} error")
    else:
        _append_action_log(dashboard, "Action repeat stopped.")
        _append_sequence_log(dashboard, f"Action {action_index + 1}: repeat {repeat_index} stopped")

    dashboard.sequential_actions_operation_history.append(
        {
            "action_index": action_index,
            "repeat_index": repeat_index,
            "plugin": plugin_name,
            "action": action_name,
            "operation_id": operation_id,
            "status": result,
            "duration_seconds": max(0.0, time.time() - operation_started_at),
        }
    )

    return result


def _build_sequential_actions_detector_parameters(
    dashboard: QtCore.QObject,
    detector_config: dict,
    operation_id: str,
):
    """Build detector parameters with the selected detector hardware."""
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


async def _start_sequential_actions_detectors(
    dashboard: QtCore.QObject,
    node_uid: str,
    detector_configs: list,
):
    """Launch all detector operations configured for the current sequence gate."""
    launch_requests = []
    operation_ids = set()

    for detector_config in detector_configs:
        plugin_name = str(detector_config.get("plugin", "") or "").strip()
        action_name = str(detector_config.get("action", "") or "").strip()
        if not plugin_name or not action_name:
            raise ValueError("Sequential Actions detector is missing plugin/action information.")

        operation_id = str(uuid.uuid4())
        parameters = _build_sequential_actions_detector_parameters(dashboard, detector_config, operation_id)
        operation_ids.add(operation_id)
        launch_requests.append((plugin_name, action_name, parameters))

    dashboard.sequential_actions_detector_operation_ids = operation_ids

    tasks = [
        dashboard.backend.tacticalNodeExecute([node_uid], plugin_name, action_name, parameters)
        for plugin_name, action_name, parameters in launch_requests
    ]
    if tasks:
        await asyncio.gather(*tasks)

    _append_sequence_log(
        dashboard,
        f"Waiting on {len(operation_ids)} detector operation(s).",
    )


async def _stop_sequential_actions_detectors(dashboard: QtCore.QObject, node_uid: str):
    """Stop detector operations launched for the current sequence gate."""
    operation_ids = list(getattr(dashboard, "sequential_actions_detector_operation_ids", set()) or set())
    dashboard.sequential_actions_detector_operation_ids = set()

    for operation_id in operation_ids:
        try:
            await dashboard.backend.stopPluginOperation(node_uid, operation_id)
        except Exception as error:
            dashboard.logger.warning(
                f"Could not stop Sequential Actions detector operation {operation_id}: {error}"
            )


async def _wait_for_sequential_actions_detection(dashboard: QtCore.QObject):
    """Wait until one configured detector reports a matching Detection or Stop is requested."""
    detection_event = getattr(dashboard, "sequential_actions_detection_event", None)
    if detection_event is None:
        return False

    while not detection_event.is_set():
        if bool(getattr(dashboard, "sequential_actions_stop_requested", False)):
            return False
        _update_sequential_actions_elapsed(dashboard)
        await asyncio.sleep(0.05)

    return not bool(getattr(dashboard, "sequential_actions_stop_requested", False))


def handle_sequential_actions_detection(dashboard: QtCore.QObject, detection: dict):
    """Release a waiting sequence when one of its detector operation IDs reports a Detection."""
    if not isinstance(detection, dict):
        return
    if not bool(getattr(dashboard, "sequential_actions_waiting_for_detection", False)):
        return

    detection_event = getattr(dashboard, "sequential_actions_detection_event", None)
    if detection_event is None or detection_event.is_set():
        return

    node_uid = str(detection.get("node_uid", "") or "").strip()
    sequence_node_uid = str(getattr(dashboard, "sequential_actions_node_uid", "") or "").strip()
    if sequence_node_uid and node_uid and not _sequential_actions_node_uids_match(sequence_node_uid, node_uid):
        return

    operation_id = str(detection.get("opid") or detection.get("operation_id") or "").strip()
    operation_ids = getattr(dashboard, "sequential_actions_detector_operation_ids", set()) or set()
    if not operation_id or operation_id not in operation_ids:
        return

    dashboard.sequential_actions_detection = dict(detection)
    detection_event.set()
    dashboard.logger.info(
        "Sequential Actions detector matched: "
        f"operation_id={operation_id}, detector={detection.get('detector', '')}"
    )


async def _run_sequential_actions_with_optional_detectors(dashboard: QtCore.QObject):
    """Release the optional detector gate, then run the already-proven sequence runner."""
    node_uid = str(getattr(dashboard, "sequential_actions_node_uid", "") or "").strip()
    detector_configs = copy.deepcopy(
        getattr(dashboard, "sequential_actions_detector_configs", []) or []
    )

    try:
        if detector_configs:
            dashboard.sequential_actions_waiting_for_detection = True
            dashboard.sequential_actions_detection_event = asyncio.Event()
            dashboard.sequential_actions_detection = None
            dashboard.ui.label_ta_sequential_actions_execution_status.setText("Starting Detectors...")
            _append_sequence_log(dashboard, "Starting sequence detectors.")

            await _start_sequential_actions_detectors(dashboard, node_uid, detector_configs)

            if bool(getattr(dashboard, "sequential_actions_stop_requested", False)):
                await _stop_sequential_actions_detectors(dashboard, node_uid)
                await _finish_sequential_actions(dashboard, "Stopped")
                return

            dashboard.ui.label_ta_sequential_actions_execution_status.setText("Waiting for Detection...")
            _append_sequence_log(dashboard, "Waiting for detection to start sequence.")

            detected = await _wait_for_sequential_actions_detection(dashboard)
            await _stop_sequential_actions_detectors(dashboard, node_uid)
            dashboard.sequential_actions_waiting_for_detection = False

            if bool(getattr(dashboard, "sequential_actions_stop_requested", False)):
                await _finish_sequential_actions(dashboard, "Stopped")
                return
            if not detected:
                await _finish_sequential_actions(dashboard, "Error")
                return

            detection = getattr(dashboard, "sequential_actions_detection", {}) or {}
            detector_name = str(detection.get("detector", "") or "").strip()
            detector_operation_id = str(
                detection.get("opid") or detection.get("operation_id") or ""
            ).strip()
            _append_sequence_log(
                dashboard,
                "Detection received"
                + (f": {detector_name}" if detector_name else "")
                + (f" ({detector_operation_id})" if detector_operation_id else "")
                + ".",
            )

        await _run_sequential_actions(dashboard)

    except Exception as error:
        dashboard.logger.error(f"Could not start Sequential Actions: {error}")
        _append_sequence_log(dashboard, f"Sequence start failed: {error}")

        try:
            await _stop_sequential_actions_detectors(dashboard, node_uid)
        except Exception:
            pass

        await _finish_sequential_actions(dashboard, "Start Failed")


async def _run_sequential_actions(dashboard: QtCore.QObject):
    """Run the snapshotted sequence using the existing generic plugin action path."""
    node_uid = str(getattr(dashboard, "sequential_actions_node_uid", "") or "").strip()
    sequence = copy.deepcopy(getattr(dashboard, "sequential_actions_run_sequence", []) or [])
    on_error = str(getattr(dashboard, "sequential_actions_on_error", "Stop Sequence") or "Stop Sequence")
    on_complete = str(getattr(dashboard, "sequential_actions_on_complete", "Stop") or "Stop")

    final_status = "Completed"

    try:
        while not bool(getattr(dashboard, "sequential_actions_stop_requested", False)):
            dashboard.sequential_actions_cycle += 1
            dashboard.sequential_actions_completed_iterations = 0
            dashboard.ui.progressBar_ta_sequential_actions.setValue(0)
            _reset_sequential_actions_timeline(dashboard)
            _append_sequence_log(dashboard, f"Sequence cycle {dashboard.sequential_actions_cycle} started.")

            sequence_error = False
            for action_index, action_config in enumerate(sequence):
                repeat_total = max(1, int(action_config.get("repeat", 1) or 1))
                interval = max(0.0, float(action_config.get("interval", 0.0) or 0.0))

                for repeat_index in range(1, repeat_total + 1):
                    if bool(getattr(dashboard, "sequential_actions_stop_requested", False)):
                        final_status = "Stopped"
                        break

                    result = await _run_sequence_action_repeat(
                        dashboard,
                        node_uid,
                        action_config,
                        action_index,
                        repeat_index,
                    )

                    if result == "stopped":
                        _set_sequential_actions_timeline_state(dashboard, action_index, "stopped")
                        final_status = "Stopped"
                        break

                    if result == "error":
                        _set_sequential_actions_timeline_state(dashboard, action_index, "error")
                        sequence_error = True
                        if on_error == "Stop Sequence":
                            final_status = "Error"
                            break
                        _append_sequence_log(
                            dashboard,
                            f"Action {action_index + 1}: continuing to next action after error.",
                        )
                        break

                    dashboard.sequential_actions_completed_iterations += 1
                    _update_sequential_actions_progress(dashboard)
                    if repeat_index == repeat_total:
                        _set_sequential_actions_timeline_state(dashboard, action_index, "completed")

                    if repeat_index < repeat_total and interval > 0.0:
                        dashboard.ui.label_ta_sequential_actions_execution_status.setText("Interval...")
                        _append_sequence_log(
                            dashboard,
                            f"Action {action_index + 1}: waiting {_format_seconds(interval)} before repeat {repeat_index + 1}.",
                        )
                        if not await _wait_for_sequence_interval(dashboard, interval):
                            _set_sequential_actions_timeline_state(dashboard, action_index, "stopped")
                            final_status = "Stopped"
                            break

                if final_status in {"Stopped", "Error"}:
                    break
                if sequence_error and on_error == "Continue":
                    sequence_error = False
                    continue

            if final_status in {"Stopped", "Error"}:
                break

            _update_sequential_actions_progress(dashboard, 1.0)
            _append_sequence_log(dashboard, f"Sequence cycle {dashboard.sequential_actions_cycle} completed.")

            if on_complete != "Repeat Sequence":
                final_status = "Completed"
                break

            _append_sequence_log(dashboard, "Repeating sequence.")

    except Exception as error:
        current_index = int(getattr(dashboard, "sequential_actions_current_index", -1) or -1)
        if current_index >= 0:
            _set_sequential_actions_timeline_state(dashboard, current_index, "error")
        dashboard.logger.error(f"Sequential Actions execution failed: {error}")
        _append_sequence_log(dashboard, f"Sequence error: {error}")
        final_status = "Error"

    await _finish_sequential_actions(dashboard, final_status)


async def _record_sequential_actions_target_history(
    dashboard: QtCore.QObject,
    status_text: str,
):
    """Record one Target history entry for the completed/stopped sequence run."""
    target_id = str(getattr(dashboard, "sequential_actions_target_id", "") or "").strip()
    if not target_id or target_id not in (getattr(dashboard, "tactical_targets", {}) or {}):
        return

    started_at = float(getattr(dashboard, "sequential_actions_started_at", 0.0) or 0.0)
    sequence = copy.deepcopy(getattr(dashboard, "sequential_actions_run_sequence", []) or [])
    detectors = copy.deepcopy(getattr(dashboard, "sequential_actions_detector_configs", []) or [])
    detection = copy.deepcopy(getattr(dashboard, "sequential_actions_detection", {}) or {})
    operations = copy.deepcopy(getattr(dashboard, "sequential_actions_operation_history", []) or [])

    history_entry = {
        "event": "sequential_actions",
        "operation_id": str(getattr(dashboard, "sequential_actions_run_id", "") or ""),
        "node_uid": str(getattr(dashboard, "sequential_actions_node_uid", "") or ""),
        "status": str(status_text or "").strip().lower(),
        "duration_seconds": max(0.0, time.time() - started_at) if started_at else 0.0,
        "cycles": max(0, int(getattr(dashboard, "sequential_actions_cycle", 0) or 0)),
        "on_error": str(getattr(dashboard, "sequential_actions_on_error", "") or ""),
        "on_complete": str(getattr(dashboard, "sequential_actions_on_complete", "") or ""),
        "sequence": sequence,
        "detectors": detectors,
        "detection": detection,
        "operations": operations,
    }

    await dashboard.backend.tacticalTargetPatch(
        target_id=target_id,
        patch={},
        history_entry=history_entry,
        artifact_id="",
    )


async def _finish_sequential_actions(dashboard: QtCore.QObject, status_text: str):
    """Restore Sequential Actions controls after completion, Stop, or error."""
    _update_sequential_actions_elapsed(dashboard)
    _append_sequence_log(dashboard, f"Sequence {status_text.lower()}.")

    try:
        await _record_sequential_actions_target_history(dashboard, status_text)
    except Exception as error:
        dashboard.logger.error(f"Could not record Sequential Actions Target history: {error}")

    _clear_sequential_actions_run_state(dashboard)

    _set_sequential_actions_start_stop_button(dashboard, False)
    dashboard.ui.label_ta_sequential_actions_execution_status.setText(status_text)
    dashboard.ui.label_ta_sequential_actions_execution_current_action.setText("—")
    dashboard.ui.label_ta_sequential_actions_execution_operation_id.setText("—")
    dashboard.ui.label_ta_sequential_actions_action_log.setText("Action Log")
    if status_text == "Completed":
        dashboard.ui.progressBar_ta_sequential_actions.setValue(100)

    update_sequential_actions_selected_node_gate(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSequentialActionsStartStopClicked(dashboard: QtCore.QObject):
    """Start or stop the current Sequential Actions run."""
    if _sequential_actions_active(dashboard):
        dashboard.sequential_actions_stop_requested = True
        dashboard.ui.label_ta_sequential_actions_execution_status.setText("Stopping...")
        dashboard.ui.pushButton_ta_sequential_actions_start_stop.setEnabled(False)

        node_uid = str(getattr(dashboard, "sequential_actions_node_uid", "") or "").strip()

        if bool(getattr(dashboard, "sequential_actions_waiting_for_detection", False)):
            try:
                await _stop_sequential_actions_detectors(dashboard, node_uid)
            except Exception as error:
                dashboard.logger.error(f"Could not stop Sequential Actions detectors: {error}")

            detection_event = getattr(dashboard, "sequential_actions_detection_event", None)
            if detection_event is not None and not detection_event.is_set():
                detection_event.set()
            return

        operation_id = str(getattr(dashboard, "sequential_actions_current_operation_id", "") or "").strip()
        event = getattr(dashboard, "sequential_actions_current_event", None)
        if operation_id and node_uid and event is not None and not event.is_set():
            dashboard.sequential_actions_current_stop_reason = "sequence"
            try:
                await dashboard.backend.stopPluginOperation(node_uid, operation_id)
            except Exception as error:
                dashboard.logger.error(f"Could not stop Sequential Actions operation {operation_id}: {error}")
                dashboard.ui.pushButton_ta_sequential_actions_start_stop.setEnabled(True)
        return

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    sequence = copy.deepcopy(getattr(dashboard, "sequential_actions_sequence", []) or [])
    detector_configs = collect_sequential_actions_detector_configs(dashboard)

    if not node_uid or not _sequential_actions_selected_node_available(dashboard) or not sequence:
        return

    dashboard.sequential_actions_running = True
    dashboard.sequential_actions_stop_requested = False
    dashboard.sequential_actions_node_uid = node_uid
    dashboard.sequential_actions_target_id = str(
        getattr(dashboard, "selected_targets_actions_target_id", "") or ""
    ).strip()
    dashboard.sequential_actions_run_id = str(uuid.uuid4())
    dashboard.sequential_actions_operation_history = []
    dashboard.sequential_actions_run_sequence = sequence
    dashboard.sequential_actions_detector_configs = copy.deepcopy(detector_configs)
    dashboard.sequential_actions_detector_operation_ids = set()
    dashboard.sequential_actions_waiting_for_detection = False
    dashboard.sequential_actions_detection_event = None
    dashboard.sequential_actions_detection = None
    dashboard.sequential_actions_started_at = time.time()
    dashboard.sequential_actions_cycle = 0
    dashboard.sequential_actions_completed_iterations = 0
    dashboard.sequential_actions_total_iterations = sum(
        max(1, int(action_config.get("repeat", 1) or 1)) for action_config in sequence
    )
    dashboard.sequential_actions_on_error = dashboard.ui.comboBox_ta_sequential_actions_on_error.currentText()
    dashboard.sequential_actions_on_complete = dashboard.ui.comboBox_ta_sequential_actions_on_complete.currentText()
    _clear_sequential_actions_current_state(dashboard)

    dashboard.ui.plainTextEdit_ta_sequential_actions_sequence_log.clear()
    dashboard.ui.plainTextEdit_ta_sequential_actions_action_log.clear()
    dashboard.ui.label_ta_sequential_actions_action_log.setText("Action Log")
    _build_sequential_actions_timeline(dashboard, sequence)
    _reset_sequential_actions_timeline(dashboard)
    dashboard.ui.label_ta_sequential_actions_execution_status.setText("Starting...")
    dashboard.ui.label_ta_sequential_actions_execution_current_action.setText("—")
    dashboard.ui.label_ta_sequential_actions_execution_elapsed_time.setText("00:00:00")
    dashboard.ui.label_ta_sequential_actions_execution_operation_id.setText("—")
    dashboard.ui.progressBar_ta_sequential_actions.setValue(0)
    _append_sequence_log(dashboard, f"Sequence started on Sensor Node {node_uid}.")
    _append_sequence_log(dashboard, f"Sequence Run ID: {dashboard.sequential_actions_run_id}")
    if dashboard.sequential_actions_target_id:
        _append_sequence_log(dashboard, f"Target: {dashboard.sequential_actions_target_id}")

    _set_sequential_actions_start_stop_button(dashboard, True)
    _update_sequence_button_states(dashboard)
    _update_sequential_actions_detector_button_states(dashboard)
    dashboard.sequential_actions_task = asyncio.create_task(
        _run_sequential_actions_with_optional_detectors(dashboard)
    )


async def update_sequential_actions_status_from_selected_node(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    status: str = "",
):
    """Track the current sequence action using the existing Sensor Node status path."""
    if not _sequential_actions_active(dashboard):
        return

    tracked_node_uid = str(getattr(dashboard, "sequential_actions_node_uid", "") or "").strip()
    if not _sequential_actions_node_uids_match(tracked_node_uid, node_uid):
        return
    if not bool(getattr(dashboard, "sequential_actions_current_monitor_status", False)):
        return

    event = getattr(dashboard, "sequential_actions_current_event", None)
    if event is None or event.is_set():
        return

    status_text = str(status or "").strip()
    if not status_text:
        return

    if status_text.startswith("Running"):
        if not bool(getattr(dashboard, "sequential_actions_current_seen_running", False)):
            _append_action_log(dashboard, status_text)
        dashboard.sequential_actions_current_seen_running = True
        if not bool(getattr(dashboard, "sequential_actions_stop_requested", False)):
            dashboard.ui.label_ta_sequential_actions_execution_status.setText(status_text)
        return

    if status_text == "Error":
        dashboard.sequential_actions_current_result = "error"
        _append_action_log(dashboard, "Sensor Node status: Error")
        event.set()
        return

    if status_text == "Idle" and bool(getattr(dashboard, "sequential_actions_current_seen_running", False)):
        stop_reason = str(getattr(dashboard, "sequential_actions_current_stop_reason", "") or "")
        dashboard.sequential_actions_current_result = "stopped" if stop_reason else "completed"
        _append_action_log(dashboard, "Sensor Node status: Idle")
        event.set()


def _slotSequentialActionsSelectionChanged(dashboard: QtCore.QObject):
    _update_sequence_button_states(dashboard)