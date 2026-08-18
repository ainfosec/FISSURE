from PyQt5 import QtCore, QtWidgets
import qasync

import fissure.utils
from .UI_Types import UI_Types


DETECTOR_QUERY_CONTEXT = "detector.selection.actions"


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class DetectorSelectionDialog(QtWidgets.QDialog, UI_Types.DetectorSelection):

    def __init__(
        self,
        parent: QtWidgets.QWidget,
        dashboard: QtCore.QObject,
        detector_config=None,
    ):
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.dashboard = dashboard
        self.setupUi(self)

        self.return_value = None
        self.detector_config = detector_config or {}

        self.action_catalog = []
        self.filtered_actions = []
        self.parameter_widgets = {}
        self.current_schema = {}
        self.selected_plugin = ""
        self.selected_action = ""
        self.customized = False
        self.query_pending = False
        self.query_node_uid = ""
        self.pending_plugin = ""
        self.pending_action = ""
        self.query_button_text = str(self.pushButton_detector_selection_query.text() or "Query").strip()

        self.__connect_slots__()
        self._initialize_controls()
        self._populate_hardware()

        if self.detector_config:
            self._load_existing_config(self.detector_config)


    def __connect_slots__(self):
        self.comboBox_detector_selection_hardware.currentIndexChanged.connect(self._hardware_changed)
        self.comboBox_detector_selection_plugin.currentIndexChanged.connect(self._plugin_changed)
        self.comboBox_detector_selection_action.currentIndexChanged.connect(self._action_changed)
        self.pushButton_detector_selection_query.clicked.connect(self._query_clicked)
        self.pushButton_detector_selection_customize.clicked.connect(self._customize_clicked)
        self.pushButton_detector_selection_save.clicked.connect(self._save_clicked)


    def _initialize_controls(self):
        self.comboBox_detector_selection_plugin.clear()
        self.comboBox_detector_selection_plugin.setEnabled(False)
        self.comboBox_detector_selection_action.clear()
        self.comboBox_detector_selection_action.setEnabled(False)
        self.pushButton_detector_selection_customize.setEnabled(False)
        self.pushButton_detector_selection_save.setEnabled(False)

        self.scrollArea_detector_selection_parameters.setWidgetResizable(True)
        self.scrollArea_detector_selection_parameters.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.scrollArea_detector_selection_parameters.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)

        self._clear_parameter_controls()
        self.label_detector_selection_setup_info.setText(
            "Query available detector actions, then choose a plugin and action."
        )


    def _populate_hardware(self):
        """Populate detector hardware filters using the same model as Autorun."""
        combo = self.comboBox_detector_selection_hardware
        current_text = str(combo.currentText() or "").strip()
        hardware_records = []

        if getattr(self.dashboard, "selected_node_uid", ""):
            try:
                for display_name in fissure.utils.hardware.selectedNodeHardwareDisplayNames(self.dashboard, "tsi"):
                    hardware_type, *_ = fissure.utils.hardware.hardwareDisplayNameLookup(
                        self.dashboard, display_name, "tsi"
                    )
                    hardware_records.append(
                        (str(display_name or "").strip(), str(hardware_type or "").strip())
                    )
            except Exception as error:
                self.dashboard.logger.debug(
                    f"Could not populate detector selection hardware: {error}"
                )

        combo.blockSignals(True)
        combo.clear()
        combo.addItem("All Compatible", {"mode": "all", "hardware_type": ""})
        combo.addItem("No Hardware", {"mode": "none", "hardware_type": ""})

        for display_name, hardware_type in hardware_records:
            combo.addItem(
                display_name,
                {
                    "mode": "hardware",
                    "hardware_type": hardware_type,
                    "display_name": display_name,
                },
            )

        restore_index = combo.findText(current_text, QtCore.Qt.MatchExactly)
        combo.setCurrentIndex(restore_index if restore_index >= 0 else 0)
        combo.blockSignals(False)

        has_node = bool(str(getattr(self.dashboard, "selected_node_uid", "") or "").strip())
        combo.setEnabled(has_node)
        self.pushButton_detector_selection_query.setEnabled(has_node)


    def _hardware_changed(self):
        """Refilter the cached detector catalog when the hardware filter changes."""
        self.customized = False
        self._clear_parameter_controls()
        self.pushButton_detector_selection_save.setEnabled(False)
        self._filter_action_catalog()

        if self.action_catalog:
            self.label_detector_selection_setup_info.setText(
                "Detector actions filtered by the selected hardware."
            )
        else:
            self.label_detector_selection_setup_info.setText(
                "Query available detector actions for the selected Sensor Node."
            )


    def _plugin_changed(self):
        """Populate detector actions for the selected plugin."""
        self.customized = False
        self._clear_parameter_controls()
        self.pushButton_detector_selection_save.setEnabled(False)
        self._populate_actions_for_plugin()


    def _clear_action_selection(self):
        """Clear Plugin/Action selection without discarding the cached catalog."""
        self.filtered_actions = []
        self.selected_plugin = ""
        self.selected_action = ""
        self.customized = False

        self.comboBox_detector_selection_plugin.blockSignals(True)
        self.comboBox_detector_selection_plugin.clear()
        self.comboBox_detector_selection_plugin.blockSignals(False)
        self.comboBox_detector_selection_plugin.setEnabled(False)

        self.comboBox_detector_selection_action.blockSignals(True)
        self.comboBox_detector_selection_action.clear()
        self.comboBox_detector_selection_action.blockSignals(False)
        self.comboBox_detector_selection_action.setEnabled(False)

        self.pushButton_detector_selection_customize.setEnabled(False)
        self.pushButton_detector_selection_save.setEnabled(False)
        self._clear_parameter_controls()


    def _filter_action_catalog(self, preferred_plugin="", preferred_action=""):
        """Filter cached detector actions by hardware and rebuild Plugin/Action."""
        hardware_record = self.comboBox_detector_selection_hardware.currentData()
        mode = "all"
        selected_type = ""

        if isinstance(hardware_record, dict):
            mode = str(hardware_record.get("mode", "all") or "all").strip().lower()
            selected_type = str(hardware_record.get("hardware_type", "") or "").strip().lower()

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

            if mode == "none" and action_hardware:
                continue

            if mode == "hardware" and action_hardware:
                normalized = [value.lower() for value in action_hardware]
                if not any(selected_type in value or value in selected_type for value in normalized):
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


    def _populate_actions_for_plugin(self, preferred_action=""):
        """Populate detector actions for the selected plugin."""
        plugin_name = str(self.comboBox_detector_selection_plugin.currentText() or "").strip()
        action_combo = self.comboBox_detector_selection_action
        current_action = str(preferred_action or action_combo.currentText() or "").strip()

        action_combo.blockSignals(True)
        action_combo.clear()

        for action_record in self.filtered_actions:
            if str(action_record.get("plugin", "") or "").strip() != plugin_name:
                continue

            action_name = str(action_record.get("action", "") or "").strip()
            if action_name:
                action_combo.addItem(action_name, action_record)

        restore_index = action_combo.findText(current_action, QtCore.Qt.MatchExactly)
        action_combo.setCurrentIndex(
            restore_index if restore_index >= 0 else (0 if action_combo.count() else -1)
        )
        action_combo.blockSignals(False)
        action_combo.setEnabled(action_combo.count() > 0)
        self._action_changed()


    def _selected_action_requires_hardware(self):
        record = self.comboBox_detector_selection_action.currentData()
        if not isinstance(record, dict):
            return False

        return any(
            str(value or "").strip()
            for value in (record.get("hardware", []) or [])
        )


    def _selected_runtime_hardware(self):
        """Return the concrete hardware used by the selected action, if required."""
        if not self._selected_action_requires_hardware():
            return ""

        hardware_record = self.comboBox_detector_selection_hardware.currentData()
        if not isinstance(hardware_record, dict):
            return ""

        if str(hardware_record.get("mode", "") or "").strip().lower() != "hardware":
            return ""

        return str(
            hardware_record.get("display_name")
            or self.comboBox_detector_selection_hardware.currentText()
            or ""
        ).strip()


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
                "Select a specific compatible hardware device before saving this detector."
            )


    @qasync.asyncSlot()
    async def _query_clicked(self):
        """Query once for all detector actions; hardware/plugin filtering is local."""
        uid = str(getattr(self.dashboard, "selected_node_uid", "") or "").strip()

        if not uid:
            self.label_detector_selection_setup_info.setText(
                "Select a Sensor Node before querying detector actions."
            )
            return

        self.action_catalog = []
        self._clear_action_selection()
        self.query_pending = True
        self.query_node_uid = uid

        self.pushButton_detector_selection_query.setEnabled(False)
        self.pushButton_detector_selection_query.setText("Querying...")
        self.label_detector_selection_setup_info.setText(
            "Querying selected node for detector actions..."
        )

        try:
            await self.dashboard.backend.queryPluginActions(
                uid=uid,
                context=DETECTOR_QUERY_CONTEXT,
                scope="all_plugins",
                plugin_name="",
                include_tags=["tsi.detector"],
                exclude_tags=[],
            )
        except Exception:
            self.query_pending = False
            self.query_node_uid = ""
            self.pushButton_detector_selection_query.setText(self.query_button_text)
            self.pushButton_detector_selection_query.setEnabled(True)
            raise


    def handle_action_query_results(self, node_uid="", context="", actions=None):
        """Cache detector actions and apply the current Hardware -> Plugin filter."""
        result_node_uid = str(node_uid or "").strip()
        selected_node_uid = str(getattr(self.dashboard, "selected_node_uid", "") or "").strip()

        if (
            not self.query_pending
            or result_node_uid != self.query_node_uid
            or result_node_uid != selected_node_uid
            or str(context or "").strip() != DETECTOR_QUERY_CONTEXT
        ):
            self.dashboard.logger.debug(
                "Ignoring stale detector selection action query results: "
                f"node_uid={result_node_uid!r}, context={context!r}"
            )
            return

        self.query_pending = False
        self.query_node_uid = ""
        self.action_catalog = [
            record
            for record in (actions if isinstance(actions, list) else [])
            if isinstance(record, dict)
        ]

        self.pushButton_detector_selection_query.setText(self.query_button_text)
        self.pushButton_detector_selection_query.setEnabled(bool(selected_node_uid))

        preferred_plugin = self.pending_plugin
        preferred_action = self.pending_action
        self.pending_plugin = ""
        self.pending_action = ""
        self._filter_action_catalog(
            preferred_plugin=preferred_plugin,
            preferred_action=preferred_action,
        )

        if self.comboBox_detector_selection_action.count() > 0:
            self.label_detector_selection_setup_info.setText(
                "Customize the selected detector to load its parameters."
            )
        else:
            self.label_detector_selection_setup_info.setText(
                "No detector actions match the selected hardware filter."
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
                "Customize the selected detector to load its parameters."
            )


    @qasync.asyncSlot()
    async def _customize_clicked(self):
        uid = str(getattr(self.dashboard, "selected_node_uid", "") or "").strip()
        record = self.comboBox_detector_selection_action.currentData()

        if not uid or not isinstance(record, dict):
            return

        plugin_name = str(record.get("plugin", "")).strip()
        action_name = str(record.get("action", "")).strip()

        if not plugin_name or not action_name:
            return

        self.selected_plugin = plugin_name
        self.selected_action = action_name
        self.customized = False

        self._clear_parameter_controls()
        self.pushButton_detector_selection_customize.setEnabled(False)
        self.pushButton_detector_selection_customize.setText("Loading...")
        self.pushButton_detector_selection_save.setEnabled(False)
        self.label_detector_selection_setup_info.setText(
            "Loading detector parameters..."
        )

        await self.dashboard.backend.queryPluginActionSchema(
            uid=uid,
            plugin_name=plugin_name,
            action_name=action_name,
            context="detector.selection",
        )


    def handle_action_schema(
        self,
        plugin_name="",
        action_name="",
        node_uid="",
        parameters=None,
    ):
        parameters = parameters or []

        record = self.comboBox_detector_selection_action.currentData()
        if not isinstance(record, dict):
            return

        selected_plugin = str(record.get("plugin", "")).strip()
        selected_action = str(record.get("action", "")).strip()

        plugin_name = str(plugin_name or "").strip()
        action_name = str(action_name or "").strip()

        if selected_plugin != plugin_name or selected_action != action_name:
            self.dashboard.logger.debug(
                f"Ignoring stale detector selection schema for "
                f"{plugin_name}.{action_name}; "
                f"selected={selected_plugin}.{selected_action}"
            )
            self.pushButton_detector_selection_customize.setText("Customize")
            self.pushButton_detector_selection_customize.setEnabled(
                bool(selected_plugin and selected_action)
            )
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
        self.customized = True

        description = self._schema_description(parameters)
        self.label_detector_selection_setup_info.setText(
            description or "Detector parameters loaded. Review settings before saving."
        )

        self.pushButton_detector_selection_customize.setText("Customize")
        self.pushButton_detector_selection_customize.setEnabled(True)
        self._update_save_enabled()


    def _clear_parameter_controls(self):
        contents = self.scrollAreaWidgetContents_detector_selection_parameters
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

        for column in range(8):
            layout.setColumnStretch(column, 0)
            layout.setColumnMinimumWidth(column, 0)

        self.parameter_widgets = {}
        self.current_schema = {}


    def _render_parameter_widgets(self, parameters):
        contents = self.scrollAreaWidgetContents_detector_selection_parameters
        layout = contents.layout()

        if layout is None:
            layout = QtWidgets.QGridLayout(contents)
            contents.setLayout(layout)

        layout.setAlignment(QtCore.Qt.AlignTop)

        visible_params = [
            parameter
            for parameter in parameters
            if str(parameter.get("name", "")).strip() != "description"
        ]

        for row, parameter in enumerate(visible_params):
            name = str(parameter.get("name", "")).strip()
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


    def _create_parameter_widget(self, parameter):
        parameter_name = str(parameter.get("name", "")).strip()
        parameter_type = str(
            parameter.get("type", "string") or "string"
        ).lower()
        default = parameter.get("default", "")
        options = parameter.get("options", []) or []
        compact_width = 180

        if parameter_type == "label":
            widget = QtWidgets.QLabel(str(default))
            widget.setObjectName("label_tsi_dynamic_parameter_value")
            widget.setWordWrap(True)
            widget.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
            widget.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
            widget.setMinimumWidth(0)
            widget.setMaximumWidth(16777215)
            return widget

        if parameter_type in {"int", "integer", "number", "float", "double"}:
            widget = QtWidgets.QDoubleSpinBox()
            widget.setObjectName("doubleSpinBox_tsi_detector_parameter")
            widget.setDecimals(_safe_int(parameter.get("decimals"), 3))
            widget.setMinimum(_safe_float(parameter.get("min"), -999999999.0))
            widget.setMaximum(_safe_float(parameter.get("max"), 999999999.0))
            widget.setSingleStep(_safe_float(parameter.get("step"), 1.0))
            widget.setValue(_safe_float(default, 0.0))

            if parameter_type in {"int", "integer"}:
                widget.setDecimals(0)

            widget.setFixedWidth(compact_width)
            widget.setAlignment(QtCore.Qt.AlignRight)
            return widget

        if parameter_type in {"bool", "boolean"}:
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

            index = widget.findText(str(default))
            if index >= 0:
                widget.setCurrentIndex(index)

            widget.setFixedWidth(compact_width)

            if parameter_name == "run_mode":
                widget.setToolTip(
                    "GUI mode is intended for local nodes. Remote nodes should run headless."
                )

            return widget

        widget = QtWidgets.QLineEdit()
        widget.setObjectName("lineEdit_tsi_detector_parameter")
        widget.setText(str(default))
        widget.setFixedWidth(compact_width)
        return widget


    def _collect_parameters(self):
        parameters = {}

        for parameter_name, widget in self.parameter_widgets.items():
            if isinstance(widget, QtWidgets.QLineEdit):
                parameters[parameter_name] = widget.text()
            elif isinstance(widget, QtWidgets.QComboBox):
                parameters[parameter_name] = widget.currentText()
            elif isinstance(widget, QtWidgets.QDoubleSpinBox):
                value = widget.value()
                parameters[parameter_name] = (
                    int(value) if widget.decimals() == 0 else value
                )
            elif isinstance(widget, QtWidgets.QSpinBox):
                parameters[parameter_name] = widget.value()
            elif isinstance(widget, QtWidgets.QCheckBox):
                parameters[parameter_name] = widget.isChecked()

        return parameters


    def _schema_description(self, parameters):
        for parameter in parameters:
            if str(parameter.get("name", "")).strip() == "description":
                return str(parameter.get("default", "") or "").strip()

        return ""


    def _save_clicked(self):
        if not self.customized or not self.selected_plugin or not self.selected_action:
            return

        runtime_hardware = self._selected_runtime_hardware()
        if self._selected_action_requires_hardware() and not runtime_hardware:
            self._update_save_enabled()
            return

        self.return_value = {
            "hardware": runtime_hardware,
            "plugin": self.selected_plugin,
            "action": self.selected_action,
            "parameters": self._collect_parameters(),
        }

        self.accept()


    def _load_existing_config(self, detector_config):
        """Restore the saved hardware filter and action preference before Query."""
        hardware = str(detector_config.get("hardware", "") or "").strip()
        plugin_name = str(detector_config.get("plugin", "") or "").strip()
        action_name = str(detector_config.get("action", "") or "").strip()

        if hardware:
            hardware_index = self.comboBox_detector_selection_hardware.findText(
                hardware, QtCore.Qt.MatchExactly
            )
        else:
            hardware_index = self.comboBox_detector_selection_hardware.findText(
                "No Hardware", QtCore.Qt.MatchExactly
            )

        if hardware_index >= 0:
            self.comboBox_detector_selection_hardware.setCurrentIndex(hardware_index)

        self.pending_plugin = plugin_name
        self.pending_action = action_name

        self.label_detector_selection_setup_info.setText(
            "Query detector actions to restore the saved plugin and action."
        )