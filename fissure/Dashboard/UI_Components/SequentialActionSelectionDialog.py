from PyQt5 import QtCore, QtWidgets
import asyncio
import qasync

import fissure.utils
from .DetectorSelectionDialog import DetectorSelectionDialog, _safe_float, _safe_int


ACTION_QUERY_CONTEXT = "targets_actions.sequential_action.selection.actions"
ACTION_SCHEMA_CONTEXT = "targets_actions.sequential_action.selection.schema"


class SequentialActionSelectionDialog(DetectorSelectionDialog):
    """Configure one generic plugin action for the Sequential Actions table."""

    def __init__(self, parent: QtWidgets.QWidget, dashboard: QtCore.QObject, action_config=None):
        self.action_config = dict(action_config or {})
        self.pending_parameters = dict(self.action_config.get("parameters", {}) or {})
        self.pending_sequence_settings = {
            "duration": _safe_float(self.action_config.get("duration"), 60.0),
            "repeat": max(1, _safe_int(self.action_config.get("repeat"), 1)),
            "interval": max(0.0, _safe_float(self.action_config.get("interval"), 0.0)),
            "advance_early": bool(self.action_config.get("advance_early", False)),
        }
        self.sequence_setting_widgets = {}
        self.restore_existing = bool(self.action_config)
        super().__init__(parent, dashboard, self.action_config)

        self.setWindowTitle("Configure Sequence Action")
        self.label_detector_selection_setup_title.setText("Action Setup")
        self.label_detector_selection_setup_subtitle.setText("Choose hardware, plugin, and action.")
        self.label_detector_selection_parameters_title.setText("Action Parameters")
        self.label_detector_selection_parameters_subtitle.setText("Configure action and sequence behavior.")
        self.pushButton_detector_selection_save.setText("Save Action" if self.action_config else "Add Action")
        self.query_button_text = "Query Actions"
        self.pushButton_detector_selection_query.setText(self.query_button_text)
        self.label_detector_selection_setup_info.setText(
            "Query available actions, then choose and customize one for the sequence."
        )

        if self.restore_existing:
            QtCore.QTimer.singleShot(0, lambda: asyncio.ensure_future(self._query_clicked()))


    def _populate_hardware(self):
        """Populate the generic action hardware filter from the selected Sensor Node."""
        combo = self.comboBox_detector_selection_hardware
        current_text = str(combo.currentText() or "").strip()
        hardware_records = []

        if getattr(self.dashboard, "selected_node_uid", ""):
            try:
                for display_name in fissure.utils.hardware.selectedNodeHardwareDisplayNames(self.dashboard, "attack"):
                    hardware_type, *_ = fissure.utils.hardware.hardwareDisplayNameLookup(
                        self.dashboard, display_name, "attack"
                    )
                    hardware_records.append((str(display_name or "").strip(), str(hardware_type or "").strip()))
            except Exception as error:
                self.dashboard.logger.debug(f"Could not populate sequence action hardware: {error}")

        combo.blockSignals(True)
        combo.clear()
        combo.addItem("All Compatible", {"mode": "all", "hardware_type": ""})
        combo.addItem("No Hardware Required", {"mode": "none", "hardware_type": ""})
        for display_name, hardware_type in hardware_records:
            combo.addItem(
                display_name,
                {"mode": "hardware", "hardware_type": hardware_type, "display_name": display_name},
            )

        restore_index = combo.findText(current_text, QtCore.Qt.MatchExactly)
        combo.setCurrentIndex(restore_index if restore_index >= 0 else 0)
        combo.blockSignals(False)

        has_node = bool(str(getattr(self.dashboard, "selected_node_uid", "") or "").strip())
        combo.setEnabled(has_node)
        self.pushButton_detector_selection_query.setEnabled(has_node)


    def _hardware_changed(self):
        self.customized = False
        self._clear_parameter_controls()
        self.pushButton_detector_selection_save.setEnabled(False)
        self._filter_action_catalog()
        self.label_detector_selection_setup_info.setText(
            "Actions filtered by the selected hardware."
            if self.action_catalog
            else "Query available actions for the selected Sensor Node."
        )


    def _action_changed(self):
        record = self.comboBox_detector_selection_action.currentData()
        self._clear_parameter_controls()
        self.customized = False
        self.pushButton_detector_selection_save.setEnabled(False)

        if not isinstance(record, dict):
            self.selected_plugin = ""
            self.selected_action = ""
            self.pushButton_detector_selection_customize.setEnabled(False)
            return

        self.selected_plugin = str(record.get("plugin", "") or "").strip()
        self.selected_action = str(record.get("action", "") or "").strip()
        has_action = bool(self.selected_plugin and self.selected_action)
        self.pushButton_detector_selection_customize.setEnabled(has_action)
        if has_action:
            self.label_detector_selection_setup_info.setText(
                "Customize the selected action to load its parameters."
            )


    def _update_save_enabled(self):
        has_selection = bool(self.selected_plugin and self.selected_action)
        hardware_ready = (
            not self._selected_action_requires_hardware()
            or bool(self._selected_runtime_hardware())
        )
        self.pushButton_detector_selection_save.setEnabled(
            bool(self.customized and has_selection and hardware_ready)
        )
        if self.customized and has_selection and not hardware_ready:
            self.label_detector_selection_setup_info.setText(
                "Select a specific compatible hardware device before saving this action."
            )


    @staticmethod
    def _hardware_matches(candidate, selected):
        candidate_text = str(candidate or "").strip().lower()
        selected_text = str(selected or "").strip().lower()
        return bool(candidate_text and selected_text and (candidate_text in selected_text or selected_text in candidate_text))


    def _configured_hardware_types(self):
        hardware_types = []
        combo = self.comboBox_detector_selection_hardware
        for index in range(combo.count()):
            record = combo.itemData(index)
            if not isinstance(record, dict) or record.get("mode") != "hardware":
                continue
            hardware_type = str(record.get("hardware_type", "") or "").strip()
            if hardware_type:
                hardware_types.append(hardware_type)
        return hardware_types


    def _filter_action_catalog(self, preferred_plugin="", preferred_action=""):
        """Filter generic actions by compatible hardware and rebuild Plugin/Action."""
        hardware_record = self.comboBox_detector_selection_hardware.currentData()
        mode = "all"
        selected_type = ""
        if isinstance(hardware_record, dict):
            mode = str(hardware_record.get("mode", "all") or "all").strip().lower()
            selected_type = str(hardware_record.get("hardware_type", "") or "").strip()

        configured_types = self._configured_hardware_types()
        filtered = []
        for action_record in self.action_catalog:
            if not isinstance(action_record, dict):
                continue

            plugin_name = str(action_record.get("plugin", "") or "").strip()
            action_name = str(action_record.get("action", "") or "").strip()
            if not plugin_name or not action_name:
                continue

            action_hardware = [
                str(value or "").strip()
                for value in (action_record.get("hardware", []) or [])
                if str(value or "").strip()
            ]

            if mode == "none":
                if action_hardware:
                    continue
            elif mode == "hardware":
                if action_hardware and not any(
                    self._hardware_matches(required, selected_type) for required in action_hardware
                ):
                    continue
            elif action_hardware:
                if not any(
                    self._hardware_matches(required, configured)
                    for required in action_hardware
                    for configured in configured_types
                ):
                    continue

            filtered.append(action_record)

        self.filtered_actions = filtered
        plugin_combo = self.comboBox_detector_selection_plugin
        current_plugin = str(preferred_plugin or plugin_combo.currentText() or "").strip()
        plugins = sorted(
            {
                str(record.get("plugin", "") or "").strip()
                for record in filtered
                if str(record.get("plugin", "") or "").strip()
            },
            key=str.lower,
        )

        plugin_combo.blockSignals(True)
        plugin_combo.clear()
        plugin_combo.addItems(plugins)
        restore_index = plugin_combo.findText(current_plugin, QtCore.Qt.MatchExactly)
        plugin_combo.setCurrentIndex(restore_index if restore_index >= 0 else (0 if plugins else -1))
        plugin_combo.blockSignals(False)
        plugin_combo.setEnabled(bool(plugins))
        self._populate_actions_for_plugin(preferred_action=preferred_action)


    @qasync.asyncSlot()
    async def _query_clicked(self):
        uid = str(getattr(self.dashboard, "selected_node_uid", "") or "").strip()
        if not uid:
            self.label_detector_selection_setup_info.setText("Select a Sensor Node before querying actions.")
            return

        self.action_catalog = []
        self._clear_action_selection()
        self.query_pending = True
        self.query_node_uid = uid
        self.pushButton_detector_selection_query.setEnabled(False)
        self.pushButton_detector_selection_query.setText("Querying...")
        self.label_detector_selection_setup_info.setText("Querying selected node for available actions...")

        try:
            await self.dashboard.backend.queryPluginActions(
                uid=uid,
                context=ACTION_QUERY_CONTEXT,
                scope="all_plugins",
                plugin_name="",
                include_tags=[],
                exclude_tags=[],
            )
        except Exception:
            self.query_pending = False
            self.query_node_uid = ""
            self.pushButton_detector_selection_query.setText(self.query_button_text)
            self.pushButton_detector_selection_query.setEnabled(True)
            raise


    def handle_action_query_results(self, node_uid="", context="", actions=None):
        result_node_uid = str(node_uid or "").strip()
        selected_node_uid = str(getattr(self.dashboard, "selected_node_uid", "") or "").strip()
        if (
            not self.query_pending
            or result_node_uid != self.query_node_uid
            or result_node_uid != selected_node_uid
            or str(context or "").strip() != ACTION_QUERY_CONTEXT
        ):
            self.dashboard.logger.debug(
                "Ignoring stale sequence action query results: "
                f"node_uid={result_node_uid!r}, context={context!r}"
            )
            return

        self.query_pending = False
        self.query_node_uid = ""
        self.action_catalog = [record for record in (actions if isinstance(actions, list) else []) if isinstance(record, dict)]
        self.pushButton_detector_selection_query.setText(self.query_button_text)
        self.pushButton_detector_selection_query.setEnabled(bool(selected_node_uid))

        preferred_plugin = self.pending_plugin
        preferred_action = self.pending_action
        self.pending_plugin = ""
        self.pending_action = ""
        self._filter_action_catalog(preferred_plugin=preferred_plugin, preferred_action=preferred_action)

        if self.comboBox_detector_selection_action.count() > 0:
            self.label_detector_selection_setup_info.setText("Customize the selected action to load its parameters.")
        else:
            self.label_detector_selection_setup_info.setText("No actions match the selected hardware filter.")

        if self.restore_existing and self.selected_plugin and self.selected_action:
            self.restore_existing = False
            QtCore.QTimer.singleShot(0, lambda: asyncio.ensure_future(self._customize_clicked()))


    @qasync.asyncSlot()
    async def _customize_clicked(self):
        uid = str(getattr(self.dashboard, "selected_node_uid", "") or "").strip()
        record = self.comboBox_detector_selection_action.currentData()
        if not uid or not isinstance(record, dict):
            return

        plugin_name = str(record.get("plugin", "") or "").strip()
        action_name = str(record.get("action", "") or "").strip()
        if not plugin_name or not action_name:
            return

        self.selected_plugin = plugin_name
        self.selected_action = action_name
        self.customized = False
        self._clear_parameter_controls()
        self.pushButton_detector_selection_customize.setEnabled(False)
        self.pushButton_detector_selection_customize.setText("Loading...")
        self.pushButton_detector_selection_save.setEnabled(False)
        self.label_detector_selection_setup_info.setText("Loading action parameters...")

        await self.dashboard.backend.queryPluginActionSchema(
            uid=uid,
            plugin_name=plugin_name,
            action_name=action_name,
            context=ACTION_SCHEMA_CONTEXT,
        )


    def handle_action_schema(self, plugin_name="", action_name="", node_uid="", parameters=None):
        parameters = parameters or []
        record = self.comboBox_detector_selection_action.currentData()
        if not isinstance(record, dict):
            return

        selected_plugin = str(record.get("plugin", "") or "").strip()
        selected_action = str(record.get("action", "") or "").strip()
        plugin_name = str(plugin_name or "").strip()
        action_name = str(action_name or "").strip()
        if selected_plugin != plugin_name or selected_action != action_name:
            self.dashboard.logger.debug(
                f"Ignoring stale sequence action schema for {plugin_name}.{action_name}; "
                f"selected={selected_plugin}.{selected_action}"
            )
            self.pushButton_detector_selection_customize.setText("Customize")
            self.pushButton_detector_selection_customize.setEnabled(bool(selected_plugin and selected_action))
            return

        self._clear_parameter_controls()
        self.selected_plugin = plugin_name
        self.selected_action = action_name
        self.current_schema = {
            "plugin": plugin_name,
            "action": action_name,
            "node_uid": node_uid,
            "params": parameters,
        }
        self._render_parameter_widgets(parameters)
        self._render_sequence_settings()
        self._apply_pending_values()
        self.customized = True

        self.label_detector_selection_setup_info.setText("Action parameters loaded. Review settings before saving.")
        self.pushButton_detector_selection_customize.setText("Customize")
        self.pushButton_detector_selection_customize.setEnabled(True)
        self._update_save_enabled()


    def _clear_parameter_controls(self):
        super()._clear_parameter_controls()
        self.sequence_setting_widgets = {}


    def _render_parameter_widgets(self, parameters):
        """Render all generic action parameters, including a literal description parameter."""
        contents = self.scrollAreaWidgetContents_detector_selection_parameters
        layout = contents.layout()
        if layout is None:
            layout = QtWidgets.QGridLayout(contents)
            contents.setLayout(layout)
        layout.setAlignment(QtCore.Qt.AlignTop)

        for row, parameter in enumerate(parameters):
            name = str(parameter.get("name", "") or "").strip()
            if not name:
                continue

            label_text = str(parameter.get("label") or name).strip()
            widget = self._create_parameter_widget(parameter)
            label = QtWidgets.QLabel(label_text + ":", contents)
            label.setObjectName("label2_tsi_detector_parameter")
            label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
            label.setFixedWidth(160)
            layout.addWidget(label, row, 0)
            layout.addWidget(widget, row, 1)
            self.parameter_widgets[name] = widget

        layout.setColumnMinimumWidth(0, 160)
        layout.setColumnMinimumWidth(1, 180)


    def _render_sequence_settings(self):
        contents = self.scrollAreaWidgetContents_detector_selection_parameters
        layout = contents.layout()
        row = layout.rowCount()

        separator = QtWidgets.QFrame(contents)
        separator.setFrameShape(QtWidgets.QFrame.HLine)
        separator.setFrameShadow(QtWidgets.QFrame.Sunken)
        layout.addWidget(separator, row, 0, 1, 2)
        row += 1

        duration = QtWidgets.QDoubleSpinBox(contents)
        duration.setObjectName("doubleSpinBox_tsi_detector_parameter")
        duration.setDecimals(1)
        duration.setRange(0.0, 86400.0)
        duration.setSingleStep(1.0)
        duration.setSuffix(" s")
        duration.setFixedWidth(180)

        repeat = QtWidgets.QSpinBox(contents)
        repeat.setObjectName("spinBox_ta_sequential_actions_repeat")
        repeat.setRange(1, 9999)
        repeat.setFixedWidth(180)

        interval = QtWidgets.QDoubleSpinBox(contents)
        interval.setObjectName("doubleSpinBox_tsi_detector_parameter")
        interval.setDecimals(1)
        interval.setRange(0.0, 86400.0)
        interval.setSingleStep(1.0)
        interval.setSuffix(" s")
        interval.setFixedWidth(180)

        advance_early = QtWidgets.QComboBox(contents)
        advance_early.setObjectName("comboBox_tsi_detector_parameter")
        advance_early.addItems(["No", "Yes"])
        advance_early.setFixedWidth(180)

        settings = [
            ("Duration:", duration),
            ("Repeat:", repeat),
            ("Interval:", interval),
            ("Advance Early:", advance_early),
        ]
        for label_text, widget in settings:
            label = QtWidgets.QLabel(label_text, contents)
            label.setObjectName("label2_tsi_detector_parameter")
            label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
            label.setFixedWidth(160)
            layout.addWidget(label, row, 0)
            layout.addWidget(widget, row, 1)
            row += 1

        self.sequence_setting_widgets = {
            "duration": duration,
            "repeat": repeat,
            "interval": interval,
            "advance_early": advance_early,
        }


    def _apply_pending_values(self):
        for name, value in self.pending_parameters.items():
            widget = self.parameter_widgets.get(name)
            if widget is not None:
                self._set_widget_value(widget, value)

        duration = self.sequence_setting_widgets.get("duration")
        repeat = self.sequence_setting_widgets.get("repeat")
        interval = self.sequence_setting_widgets.get("interval")
        advance_early = self.sequence_setting_widgets.get("advance_early")
        if duration is not None:
            duration.setValue(self.pending_sequence_settings["duration"])
        if repeat is not None:
            repeat.setValue(self.pending_sequence_settings["repeat"])
        if interval is not None:
            interval.setValue(self.pending_sequence_settings["interval"])
        if advance_early is not None:
            advance_early.setCurrentText("Yes" if self.pending_sequence_settings["advance_early"] else "No")

        self.pending_parameters = {}


    @staticmethod
    def _set_widget_value(widget, value):
        if isinstance(widget, QtWidgets.QLineEdit):
            widget.setText(str(value))
        elif isinstance(widget, QtWidgets.QComboBox):
            index = widget.findText(str(value), QtCore.Qt.MatchExactly)
            if index >= 0:
                widget.setCurrentIndex(index)
        elif isinstance(widget, QtWidgets.QDoubleSpinBox):
            widget.setValue(_safe_float(value, widget.value()))
        elif isinstance(widget, QtWidgets.QSpinBox):
            widget.setValue(_safe_int(value, widget.value()))
        elif isinstance(widget, QtWidgets.QCheckBox):
            widget.setChecked(str(value).strip().lower() in {"1", "true", "yes", "on"})


    def _save_clicked(self):
        if not self.customized or not self.selected_plugin or not self.selected_action:
            return

        runtime_hardware = self._selected_runtime_hardware()
        if self._selected_action_requires_hardware() and not runtime_hardware:
            self._update_save_enabled()
            return

        parameters = self._collect_parameters()
        description = str(parameters.get("description", "") or "").strip()
        if not description:
            description = self._schema_description(self.current_schema.get("params", []))
        if not description:
            description = f"{self.selected_plugin}: {self.selected_action}"

        self.return_value = {
            "hardware": runtime_hardware,
            "plugin": self.selected_plugin,
            "action": self.selected_action,
            "description": description,
            "parameters": parameters,
            "duration": self.sequence_setting_widgets["duration"].value(),
            "repeat": self.sequence_setting_widgets["repeat"].value(),
            "interval": self.sequence_setting_widgets["interval"].value(),
            "advance_early": self.sequence_setting_widgets["advance_early"].currentText() == "Yes",
        }
        self.accept()


    def _load_existing_config(self, action_config):
        hardware = str(action_config.get("hardware", "") or "").strip()
        plugin_name = str(action_config.get("plugin", "") or "").strip()
        action_name = str(action_config.get("action", "") or "").strip()

        hardware_text = hardware or "No Hardware Required"
        hardware_index = self.comboBox_detector_selection_hardware.findText(
            hardware_text, QtCore.Qt.MatchExactly
        )
        if hardware_index >= 0:
            self.comboBox_detector_selection_hardware.setCurrentIndex(hardware_index)

        self.pending_plugin = plugin_name
        self.pending_action = action_name
        self.label_detector_selection_setup_info.setText("Restoring saved action configuration...")