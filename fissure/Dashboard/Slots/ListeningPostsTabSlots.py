#!/usr/bin/python3
import asyncio
import os
from datetime import datetime
from PyQt5 import QtCore, QtWidgets, QtGui
import qasync

import fissure
from fissure.ListeningPosts.common import (
    LISTENING_POST_TYPES,
    listening_post_fields,
    normalize_listening_post_definition,
)


class ListeningPostDialog(QtWidgets.QDialog):
    """Dynamic Add/Edit dialog driven by the common Listening Post field schema."""

    def __init__(self, parent=None, definition=None):
        super().__init__(parent)
        self.existing = dict(definition or {})
        self.result_definition = None
        self.parameter_widgets = {}
        self.parameter_rows = {}

        self.setWindowTitle(
            "Edit Listening Post"
            if self.existing
            else "Add Listening Post"
        )
        self.setModal(True)
        self.resize(520, 390)

        root = QtWidgets.QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(10)

        form = QtWidgets.QFormLayout()
        form.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.AllNonFixedFieldsGrow
        )

        self.name_edit = QtWidgets.QLineEdit()
        self.name_edit.setText(str(self.existing.get("name", "") or ""))
        form.addRow("Name:", self.name_edit)

        self.type_combo = QtWidgets.QComboBox()
        self.type_combo.addItems(list(LISTENING_POST_TYPES))
        existing_type = str(self.existing.get("type", "") or "")
        if existing_type in LISTENING_POST_TYPES:
            self.type_combo.setCurrentText(existing_type)
        form.addRow("Type:", self.type_combo)

        self.autostart_check = QtWidgets.QCheckBox("Start automatically with HIPRFISR")
        self.autostart_check.setChecked(bool(self.existing.get("autostart", False)))
        form.addRow("Auto Start:", self.autostart_check)

        root.addLayout(form)

        self.parameters_group = QtWidgets.QGroupBox("Parameters")
        self.parameters_layout = QtWidgets.QFormLayout(self.parameters_group)
        self.parameters_layout.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.AllNonFixedFieldsGrow
        )
        root.addWidget(self.parameters_group, 1)

        self.error_label = QtWidgets.QLabel("")
        self.error_label.setWordWrap(True)
        self.error_label.setProperty("uiRole", "error")
        root.addWidget(self.error_label)

        buttons = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.Save
            | QtWidgets.QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self._save_clicked)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

        self.type_combo.currentTextChanged.connect(
            self._rebuild_parameter_widgets
        )
        self._rebuild_parameter_widgets(self.type_combo.currentText())

    def _clear_parameter_layout(self):
        while self.parameters_layout.rowCount() > 0:
            self.parameters_layout.removeRow(0)
        self.parameter_widgets = {}
        self.parameter_rows = {}

    def _make_text_widget(self, kind, value):
        edit = QtWidgets.QLineEdit()
        edit.setText(str(value or ""))
        if kind == "password":
            edit.setEchoMode(QtWidgets.QLineEdit.Password)
        return edit

    def _make_path_widget(self, kind, value):
        container = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        edit = QtWidgets.QLineEdit()
        edit.setText(str(value or ""))
        browse = QtWidgets.QPushButton("Browse")
        layout.addWidget(edit, 1)
        layout.addWidget(browse)

        if kind == "folder":
            browse.clicked.connect(
                lambda: self._browse_folder(edit)
            )
        else:
            browse.clicked.connect(
                lambda: self._browse_file(edit)
            )

        return container, edit

    def _rebuild_parameter_widgets(self, post_type):
        current_parameters = {}
        if self.parameter_widgets:
            current_parameters = self._collect_parameters()
        elif str(self.existing.get("type", "") or "") == post_type:
            current_parameters = dict(self.existing.get("parameters", {}) or {})

        self._clear_parameter_layout()

        for field in listening_post_fields(post_type):
            key = field["name"]
            kind = field.get("kind", "text")
            value = current_parameters.get(key, field.get("default", ""))

            label = QtWidgets.QLabel(field.get("label", key))

            if kind == "choice":
                widget = QtWidgets.QComboBox()
                widget.addItems([str(value) for value in field.get("choices", [])])
                if str(value) in field.get("choices", []):
                    widget.setCurrentText(str(value))
                value_widget = widget

            elif kind in {"folder", "file"}:
                widget, value_widget = self._make_path_widget(kind, value)

            else:
                widget = self._make_text_widget(kind, value)
                value_widget = widget

            self.parameters_layout.addRow(label, widget)
            self.parameter_widgets[key] = value_widget
            self.parameter_rows[key] = (label, widget, field)

            if key == "mode" and isinstance(value_widget, QtWidgets.QComboBox):
                value_widget.currentTextChanged.connect(
                    lambda _text: self._update_conditional_rows()
                )

        self._update_conditional_rows()

    def _update_conditional_rows(self):
        values = self._collect_parameters()

        for _key, (label, widget, field) in self.parameter_rows.items():
            condition = field.get("show_when")
            visible = True
            if condition:
                dependent_key, required_value = condition
                visible = values.get(dependent_key) == required_value
            label.setVisible(visible)
            widget.setVisible(visible)

    def _collect_parameters(self):
        parameters = {}
        for key, widget in self.parameter_widgets.items():
            if isinstance(widget, QtWidgets.QComboBox):
                parameters[key] = widget.currentText()
            elif isinstance(widget, QtWidgets.QLineEdit):
                parameters[key] = widget.text()
        return parameters

    def _browse_folder(self, edit):
        folder = QtWidgets.QFileDialog.getExistingDirectory(
            self,
            "Select Folder",
            edit.text() or fissure.utils.FISSURE_ROOT,
        )
        if folder:
            edit.setText(folder)

    def _browse_file(self, edit):
        filepath, _selected_filter = QtWidgets.QFileDialog.getOpenFileName(
            self,
            "Select File",
            edit.text() or fissure.utils.FISSURE_ROOT,
        )
        if filepath:
            edit.setText(filepath)

    def _save_clicked(self):
        definition = {
            "id": str(self.existing.get("id", "") or ""),
            "name": self.name_edit.text().strip(),
            "type": self.type_combo.currentText(),
            "host": "hiprfisr",
            "autostart": self.autostart_check.isChecked(),
            "parameters": self._collect_parameters(),
        }

        try:
            self.result_definition = normalize_listening_post_definition(definition)
        except Exception as exc:
            self.error_label.setText(str(exc))
            return

        self.accept()


async def _run_listening_post_dialog(dashboard, definition=None):
    """Open Add/Edit without starting a nested Qt event loop."""
    dialog = ListeningPostDialog(
        dashboard,
        definition=definition,
    )

    loop = asyncio.get_running_loop()
    future = loop.create_future()

    def _finished(result):
        if future.done():
            return
        if result == QtWidgets.QDialog.Accepted:
            future.set_result(dialog.result_definition)
        else:
            future.set_result(None)

    dialog.finished.connect(_finished)
    dialog.open()

    result = await future
    dialog.deleteLater()
    return result


def initialize_listening_posts_tab(dashboard: QtCore.QObject):
    """Initialize the Targets & Actions Listening Posts workspace."""
    dashboard.listening_posts = {}
    dashboard.selected_listening_post_id = ""
    dashboard.pending_listening_post_id = ""
    dashboard.listening_posts_management_busy = False

    table = dashboard.ui.tableWidget_ta_lp_setup
    table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    table.setSortingEnabled(False)
    table.verticalHeader().setVisible(False)

    header = table.horizontalHeader()
    header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeToContents)
    header.setSectionResizeMode(4, QtWidgets.QHeaderView.Stretch)

    dashboard.ui.plainTextEdit_ta_lp_activity.setReadOnly(True)
    _clear_listening_post_details(dashboard)
    _update_listening_post_buttons(dashboard)


def _details_layout(dashboard: QtCore.QObject):
    contents = dashboard.ui.scrollAreaWidgetContents_ta_lp_details
    layout = contents.layout()

    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    layout.setContentsMargins(10, 8, 10, 8)
    layout.setHorizontalSpacing(12)
    layout.setVerticalSpacing(5)
    layout.setColumnStretch(0, 0)
    layout.setColumnStretch(1, 1)
    layout.setAlignment(QtCore.Qt.AlignTop)
    return layout


def _clear_layout(layout):
    while layout.count():
        item = layout.takeAt(0)
        widget = item.widget()
        if widget is not None:
            widget.deleteLater()


def _clear_listening_post_details(dashboard: QtCore.QObject):
    layout = _details_layout(dashboard)
    _clear_layout(layout)

    label = QtWidgets.QLabel("Select a Listening Post to view details.")
    label.setAlignment(QtCore.Qt.AlignCenter)
    label.setProperty("uiRole", "emptyState")
    layout.addWidget(label, 0, 0, 1, 2)
    dashboard.ui.plainTextEdit_ta_lp_activity.clear()


def _add_detail_row(layout, row, label, value):
    name_label = QtWidgets.QLabel(str(label))
    value_label = QtWidgets.QLabel(str(value if value not in [None, ""] else "—"))

    font = name_label.font()
    font.setBold(True)
    name_label.setFont(font)

    name_label.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
    value_label.setAlignment(QtCore.Qt.AlignTop | QtCore.Qt.AlignLeft)
    value_label.setWordWrap(True)
    value_label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)

    layout.addWidget(name_label, row, 0)
    layout.addWidget(value_label, row, 1)


def _format_parameter_label(key):
    special = {
        "ip_address": "IP Address",
        "url": "URL",
        "mqtt": "MQTT",
        "zmq": "ZMQ",
    }
    if key in special:
        return special[key]
    return str(key).replace("_", " ").title()


def _format_activity_timestamp(timestamp):
    text = str(timestamp or "")
    if len(text) >= 19 and "T" in text:
        return text[11:19]
    return text


def _populate_activity(dashboard: QtCore.QObject, post):
    activity = post.get("activity", []) or []
    lines = []

    for entry in activity:
        if not isinstance(entry, dict):
            continue
        timestamp = _format_activity_timestamp(entry.get("timestamp"))
        level = str(entry.get("level", "INFO") or "INFO").upper()
        message = str(entry.get("message", "") or "")
        lines.append(f"{timestamp}  [{level}]  {message}".rstrip())

    dashboard.ui.plainTextEdit_ta_lp_activity.setPlainText("\n".join(lines))
    scrollbar = dashboard.ui.plainTextEdit_ta_lp_activity.verticalScrollBar()
    scrollbar.setValue(scrollbar.maximum())


def _populate_listening_post_details(dashboard: QtCore.QObject, post_id):
    post = (getattr(dashboard, "listening_posts", {}) or {}).get(post_id)
    if not isinstance(post, dict):
        _clear_listening_post_details(dashboard)
        return

    layout = _details_layout(dashboard)
    _clear_layout(layout)

    row = 0
    _add_detail_row(layout, row, "Name:", post.get("name", "—")); row += 1
    _add_detail_row(layout, row, "Type:", post.get("type", "—")); row += 1
    _add_detail_row(layout, row, "Host:", "HIPRFISR"); row += 1
    _add_detail_row(layout, row, "Status:", post.get("status", "Stopped")); row += 1
    _add_detail_row(
        layout,
        row,
        "Auto Start:",
        "Yes" if post.get("autostart") else "No",
    ); row += 1
    _add_detail_row(layout, row, "Endpoint:", post.get("endpoint", "—")); row += 1

    parameters = post.get("parameters", {}) or {}
    ordered_keys = [
        field["name"]
        for field in listening_post_fields(str(post.get("type", "") or ""))
    ]

    for key in ordered_keys:
        value = parameters.get(key)
        if key == "password":
            value = "••••••" if str(value or "") else "—"
        if value in [None, ""]:
            continue
        _add_detail_row(
            layout,
            row,
            f"{_format_parameter_label(key)}:",
            value,
        )
        row += 1

    last_error = str(post.get("last_error", "") or "").strip()
    if last_error:
        _add_detail_row(layout, row, "Last Error:", last_error)

    _populate_activity(dashboard, post)


def _selected_post_id(dashboard: QtCore.QObject):
    table = dashboard.ui.tableWidget_ta_lp_setup
    row = table.currentRow()
    if row < 0:
        return ""
    item = table.item(row, 0)
    if item is None:
        return ""
    return str(item.data(QtCore.Qt.UserRole) or "").strip()


def _update_listening_post_buttons(dashboard: QtCore.QObject):
    busy = bool(getattr(dashboard, "listening_posts_management_busy", False))
    post_id = _selected_post_id(dashboard)
    post = (getattr(dashboard, "listening_posts", {}) or {}).get(post_id, {}) or {}
    status = str(post.get("status", "") or "")
    running = status == "Running"

    dashboard.ui.pushButton_ta_lp_add.setEnabled(not busy)
    dashboard.ui.pushButton_ta_lp_refresh.setEnabled(not busy)
    dashboard.ui.pushButton_ta_lp_edit.setEnabled(bool(post_id) and not running and not busy)
    dashboard.ui.pushButton_ta_lp_remove.setEnabled(bool(post_id) and not running and not busy)
    dashboard.ui.pushButton_ta_lp_activity_clear.setEnabled(bool(post_id) and not busy)

    start_stop = dashboard.ui.pushButton_ta_lp_start_stop
    start_stop.setEnabled(bool(post_id) and not busy)
    start_stop.setText("Stop" if running else "Start")
    start_stop.setProperty("running", running)
    start_stop.style().unpolish(start_stop)
    start_stop.style().polish(start_stop)


def _set_management_busy(dashboard: QtCore.QObject, busy):
    dashboard.listening_posts_management_busy = bool(busy)
    _update_listening_post_buttons(dashboard)


def populate_listening_posts(
    dashboard: QtCore.QObject,
    posts=None,
    error="",
    select_id="",
    clear_busy=True,
):
    """Populate the authoritative HIPRFISR Listening Post snapshot."""
    posts = posts if isinstance(posts, list) else []
    previous_id = select_id or _selected_post_id(dashboard)

    dashboard.listening_posts = {
        str(post.get("id", "") or ""): dict(post)
        for post in posts
        if isinstance(post, dict) and str(post.get("id", "") or "").strip()
    }

    table = dashboard.ui.tableWidget_ta_lp_setup
    table.blockSignals(True)
    table.setRowCount(0)

    selected_row = -1

    for post in posts:
        if not isinstance(post, dict):
            continue
        post_id = str(post.get("id", "") or "").strip()
        if not post_id:
            continue

        row = table.rowCount()
        table.insertRow(row)
        values = [
            str(post.get("name", "") or ""),
            str(post.get("type", "") or ""),
            str(post.get("status", "Stopped") or "Stopped"),
            "Yes" if post.get("autostart") else "No",
            str(post.get("endpoint", "") or ""),
        ]

        for column, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(value)
            item.setData(QtCore.Qt.UserRole, post_id)
            if column in (1, 2, 3):
                item.setTextAlignment(QtCore.Qt.AlignCenter)
            table.setItem(row, column, item)

        if post_id == previous_id:
            selected_row = row

    table.blockSignals(False)
    table.resizeRowsToContents()

    if selected_row < 0 and table.rowCount() > 0:
        selected_row = 0

    if selected_row >= 0:
        table.selectRow(selected_row)
        table.setCurrentCell(selected_row, 0)
        dashboard.selected_listening_post_id = _selected_post_id(dashboard)
        _populate_listening_post_details(
            dashboard,
            dashboard.selected_listening_post_id,
        )
    else:
        dashboard.selected_listening_post_id = ""
        table.clearSelection()
        _clear_listening_post_details(dashboard)

    if error:
        dashboard.ui.plainTextEdit_ta_lp_activity.appendPlainText(
            f"[ERROR] {error}"
        )

    if clear_busy:
        _set_management_busy(dashboard, False)
    else:
        _update_listening_post_buttons(dashboard)


def handle_listening_post_operation_result(
    dashboard: QtCore.QObject,
    action="",
    post_id="",
    success=False,
    message="",
    posts=None,
):
    """Apply one create/update/start/stop/delete result."""
    post_id = str(post_id or "").strip()
    select_id = post_id

    if action == "delete" and success:
        select_id = ""

    populate_listening_posts(
        dashboard,
        posts=posts or [],
        select_id=select_id,
    )

    if not success and message:
        dashboard.ui.plainTextEdit_ta_lp_activity.appendPlainText(
            f"[ERROR] {message}"
        )


def handle_listening_post_update(dashboard: QtCore.QObject, post=None):
    """Apply a live HIPRFISR status/activity update without polling."""
    if not isinstance(post, dict):
        return

    post_id = str(post.get("id", "") or "").strip()
    if not post_id:
        return

    posts_by_id = dict(getattr(dashboard, "listening_posts", {}) or {})
    posts_by_id[post_id] = dict(post)

    posts = sorted(
        posts_by_id.values(),
        key=lambda value: str(value.get("name", "") or "").casefold(),
    )

    populate_listening_posts(
        dashboard,
        posts=posts,
        select_id=_selected_post_id(dashboard) or post_id,
        clear_busy=False,
    )


def _selected_post(dashboard: QtCore.QObject):
    post_id = _selected_post_id(dashboard)
    if not post_id:
        return "", None
    post = (getattr(dashboard, "listening_posts", {}) or {}).get(post_id)
    return post_id, post if isinstance(post, dict) else None


async def _request_listening_posts_refresh(dashboard: QtCore.QObject):
    if getattr(dashboard, "listening_posts_management_busy", False):
        return

    _set_management_busy(dashboard, True)
    try:
        await dashboard.backend.queryListeningPosts()
    except Exception as exc:
        _set_management_busy(dashboard, False)
        dashboard.ui.plainTextEdit_ta_lp_activity.appendPlainText(
            f"[ERROR] Could not query Listening Posts: {exc}"
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotListeningPostsRefreshClicked(dashboard: QtCore.QObject):
    await _request_listening_posts_refresh(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotListeningPostsTabChanged(dashboard: QtCore.QObject):
    if dashboard.ui.tabWidget_attack_attack.currentWidget() is not dashboard.ui.tab_listening_posts:
        return
    await _request_listening_posts_refresh(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotListeningPostsAddClicked(dashboard: QtCore.QObject):
    if getattr(dashboard, "listening_posts_management_busy", False):
        return

    definition = await _run_listening_post_dialog(dashboard)
    if not definition:
        return

    _set_management_busy(dashboard, True)
    try:
        await dashboard.backend.saveListeningPost(definition)
    except Exception as exc:
        _set_management_busy(dashboard, False)
        dashboard.ui.plainTextEdit_ta_lp_activity.appendPlainText(
            f"[ERROR] Could not save Listening Post: {exc}"
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotListeningPostsEditClicked(dashboard: QtCore.QObject):
    if getattr(dashboard, "listening_posts_management_busy", False):
        return

    post_id, post = _selected_post(dashboard)
    if not post_id or not post:
        return
    if str(post.get("status", "") or "") == "Running":
        return

    definition = await _run_listening_post_dialog(dashboard, definition=post)
    if not definition:
        return

    _set_management_busy(dashboard, True)
    try:
        await dashboard.backend.saveListeningPost(definition)
    except Exception as exc:
        _set_management_busy(dashboard, False)
        dashboard.ui.plainTextEdit_ta_lp_activity.appendPlainText(
            f"[ERROR] Could not update Listening Post: {exc}"
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotListeningPostsRemoveClicked(dashboard: QtCore.QObject):
    if getattr(dashboard, "listening_posts_management_busy", False):
        return

    post_id, post = _selected_post(dashboard)
    if not post_id or not post:
        return
    if str(post.get("status", "") or "") == "Running":
        return

    name = str(post.get("name", "Listening Post") or "Listening Post")
    answer = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(
        dashboard,
        f"Remove Listening Post '{name}'?",
    )
    if answer != QtWidgets.QMessageBox.Yes:
        return

    _set_management_busy(dashboard, True)
    try:
        await dashboard.backend.deleteListeningPost(post_id)
    except Exception as exc:
        _set_management_busy(dashboard, False)
        dashboard.ui.plainTextEdit_ta_lp_activity.appendPlainText(
            f"[ERROR] Could not remove Listening Post: {exc}"
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotListeningPostsStartStopClicked(dashboard: QtCore.QObject):
    if getattr(dashboard, "listening_posts_management_busy", False):
        return

    post_id, post = _selected_post(dashboard)
    if not post_id or not post:
        return

    running = str(post.get("status", "") or "") == "Running"
    _set_management_busy(dashboard, True)

    try:
        if running:
            await dashboard.backend.stopListeningPost(post_id)
        else:
            await dashboard.backend.startListeningPost(post_id)
    except Exception as exc:
        _set_management_busy(dashboard, False)
        dashboard.ui.plainTextEdit_ta_lp_activity.appendPlainText(
            f"[ERROR] Could not {'stop' if running else 'start'} Listening Post: {exc}"
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotListeningPostsSelectionChanged(dashboard: QtCore.QObject):
    post_id = _selected_post_id(dashboard)
    dashboard.selected_listening_post_id = post_id

    if post_id:
        _populate_listening_post_details(dashboard, post_id)
    else:
        _clear_listening_post_details(dashboard)

    _update_listening_post_buttons(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotListeningPostsActivityClearClicked(dashboard: QtCore.QObject):
    """Clear the selected Listening Post's bounded Recent Activity buffer."""
    if getattr(dashboard, "listening_posts_management_busy", False):
        return

    post_id, post = _selected_post(dashboard)
    if not post_id or not post:
        return

    _set_management_busy(dashboard, True)

    try:
        await dashboard.backend.clearListeningPostActivity(post_id)
    except Exception as exc:
        _set_management_busy(dashboard, False)
        dashboard.ui.plainTextEdit_ta_lp_activity.appendPlainText(
            f"[ERROR] Could not clear Listening Post activity: {exc}"
        )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotListeningPostsTestScriptsClicked(dashboard: QtCore.QObject):
    """Open the Listening Post test scripts folder."""
    test_scripts_path = os.path.join(
        fissure.utils.TOOLS_DIR,
        "Listening_Post_Test_Scripts",
    )

    if not os.path.isdir(test_scripts_path):
        QtWidgets.QMessageBox.warning(
            dashboard,
            "Test Scripts Not Found",
            f"Listening Post test scripts were not found:\n\n{test_scripts_path}",
        )
        return

    QtGui.QDesktopServices.openUrl(
        QtCore.QUrl.fromLocalFile(test_scripts_path)
    )