from PyQt5 import QtCore, QtWidgets
import qasync

import fissure.utils
from .UI_Types import UI_Types


TSI_DETECTOR_TYPES = [
    ("rf", "RF"),
    ("wifi", "Wi-Fi"),
    ("bluetooth", "Bluetooth"),
    ("protocol", "Protocol"),
    ("ml", "ML"),
    ("time", "Time"),
    ("system", "System"),
    ("sensor", "Sensor"),
    ("environmental", "Environmental"),
    ("location", "Location"),
    ("network", "Network"),
]


TSI_DETECTOR_MODES = [
    ("fixed", "Fixed"),
    ("sweep", "Sweep"),
    ("channel_hop", "Channel Hop"),
    ("lock", "Lock"),
    ("passive", "Passive"),
    ("file", "File"),
    ("simulation", "Simulation"),
    ("scheduled", "Scheduled"),
    ("threshold", "Threshold"),
    ("change", "Change"),
    ("condition", "Condition"),
    ("presence", "Presence"),
    ("proximity", "Proximity"),
    ("boundary", "Boundary"),
    ("match", "Match"),
    ("request", "Request"),
]


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

        self.action_records = []
        self.parameter_widgets = {}
        self.current_schema = {}
        self.selected_plugin = ""
        self.selected_action = ""
        self.customized = False

        self.__connect_slots__()
        self._initialize_controls()
        self._populate_hardware()

        if self.detector_config:
            self._load_existing_config(self.detector_config)


    def __connect_slots__(self):
        self.comboBox_detector_selection_type.currentIndexChanged.connect(
            self._selection_filter_changed
        )
        self.comboBox_detector_selection_mode.currentIndexChanged.connect(
            self._selection_filter_changed
        )
        self.comboBox_detector_selection_hardware.currentIndexChanged.connect(
            self._selection_filter_changed
        )
        self.comboBox_detector_selection_action.currentIndexChanged.connect(
            self._action_changed
        )
        self.pushButton_detector_selection_query.clicked.connect(
            self._query_clicked
        )
        self.pushButton_detector_selection_customize.clicked.connect(
            self._customize_clicked
        )
        self.pushButton_detector_selection_save.clicked.connect(
            self._save_clicked
        )


    def _initialize_controls(self):
        self.comboBox_detector_selection_type.clear()
        for value, label in TSI_DETECTOR_TYPES:
            self.comboBox_detector_selection_type.addItem(label, value)

        self.comboBox_detector_selection_mode.clear()
        for value, label in TSI_DETECTOR_MODES:
            self.comboBox_detector_selection_mode.addItem(label, value)

        rf_index = self.comboBox_detector_selection_type.findData("rf")
        if rf_index >= 0:
            self.comboBox_detector_selection_type.setCurrentIndex(rf_index)

        sweep_index = self.comboBox_detector_selection_mode.findData("sweep")
        if sweep_index >= 0:
            self.comboBox_detector_selection_mode.setCurrentIndex(sweep_index)

        self.comboBox_detector_selection_action.clear()
        self.comboBox_detector_selection_action.setEnabled(False)
        self.pushButton_detector_selection_customize.setEnabled(False)
        self.pushButton_detector_selection_save.setEnabled(False)

        self.scrollArea_detector_selection_parameters.setWidgetResizable(True)
        self.scrollArea_detector_selection_parameters.setHorizontalScrollBarPolicy(
            QtCore.Qt.ScrollBarAlwaysOff
        )
        self.scrollArea_detector_selection_parameters.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarAsNeeded
        )

        self._clear_parameter_controls()
        self.label_detector_selection_setup_info.setText(
            "Select detector settings, then query available actions."
        )


    def _populate_hardware(self):
        combo = self.comboBox_detector_selection_hardware
        current = combo.currentText().strip()

        combo.blockSignals(True)
        combo.clear()

        if getattr(self.dashboard, "selected_node_uid", ""):
            try:
                hardware_names = fissure.utils.hardware.selectedNodeHardwareDisplayNames(
                    self.dashboard,
                    "tsi",
                )
            except Exception as e:
                self.dashboard.logger.debug(
                    f"Could not populate detector selection hardware: {e}"
                )
                hardware_names = []

            combo.addItems(hardware_names)

        if current and combo.findText(current) >= 0:
            combo.setCurrentText(current)
        elif combo.count() > 0:
            combo.setCurrentIndex(0)

        combo.blockSignals(False)

        has_hardware = combo.count() > 0
        combo.setEnabled(has_hardware)
        self.pushButton_detector_selection_query.setEnabled(has_hardware)


    def _selection_filter_changed(self):
        self._clear_actions()
        self.label_detector_selection_setup_info.setText(
            "Query matching detector actions for the selected type, mode, and hardware."
        )


    def _clear_actions(self):
        self.action_records = []
        self.selected_plugin = ""
        self.selected_action = ""
        self.customized = False

        self.comboBox_detector_selection_action.blockSignals(True)
        self.comboBox_detector_selection_action.clear()
        self.comboBox_detector_selection_action.blockSignals(False)

        self.comboBox_detector_selection_action.setEnabled(False)
        self.pushButton_detector_selection_customize.setEnabled(False)
        self.pushButton_detector_selection_save.setEnabled(False)
        self._clear_parameter_controls()


    @qasync.asyncSlot()
    async def _query_clicked(self):
        uid = str(getattr(self.dashboard, "selected_node_uid", "") or "").strip()

        if not uid:
            self.label_detector_selection_setup_info.setText(
                "Select a Sensor Node before querying detector actions."
            )
            return

        detector_type = str(
            self.comboBox_detector_selection_type.currentData() or ""
        ).strip()
        detector_mode = str(
            self.comboBox_detector_selection_mode.currentData() or ""
        ).strip()
        hardware = self.comboBox_detector_selection_hardware.currentText().strip()

        include_tags = [
            "tsi.detector",
            f"tsi.detector.type.{detector_type}",
            f"tsi.detector.mode.{detector_mode}",
        ]

        context = f"detector.selection.{detector_type}.{detector_mode}"

        self._clear_actions()
        self.pushButton_detector_selection_query.setEnabled(False)
        self.label_detector_selection_setup_info.setText(
            "Querying selected node for matching detector actions..."
        )

        try:
            await self.dashboard.backend.queryPluginActions(
                uid=uid,
                context=context,
                scope="all_plugins",
                plugin_name="",
                include_tags=include_tags,
                exclude_tags=[],
                hardware=hardware,
            )
        except Exception:
            self.pushButton_detector_selection_query.setEnabled(True)
            raise


    def handle_action_query_results(self, node_uid="", context="", actions=None):
        self.action_records = actions or []

        combo = self.comboBox_detector_selection_action
        combo.blockSignals(True)
        combo.clear()

        for action_record in self.action_records:
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

        self.pushButton_detector_selection_query.setEnabled(
            self.comboBox_detector_selection_hardware.count() > 0
        )

        if combo.count() > 0:
            combo.setEnabled(True)
            combo.setCurrentIndex(0)
            self.pushButton_detector_selection_customize.setEnabled(True)
            self.label_detector_selection_setup_info.setText(
                "Customize the selected detector to load its parameters."
            )
            self._action_changed()
        else:
            combo.setEnabled(False)
            self.pushButton_detector_selection_customize.setEnabled(False)
            self.pushButton_detector_selection_save.setEnabled(False)
            self.label_detector_selection_setup_info.setText(
                "No matching detector actions are available."
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

        self.selected_plugin = str(record.get("plugin", "")).strip()
        self.selected_action = str(record.get("action", "")).strip()

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
        self.pushButton_detector_selection_save.setEnabled(True)


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

        self.return_value = {
            "detector_type": str(
                self.comboBox_detector_selection_type.currentData() or ""
            ).strip(),
            "detector_mode": str(
                self.comboBox_detector_selection_mode.currentData() or ""
            ).strip(),
            "hardware": self.comboBox_detector_selection_hardware.currentText().strip(),
            "plugin": self.selected_plugin,
            "action": self.selected_action,
            "parameters": self._collect_parameters(),
        }

        self.accept()


    def _load_existing_config(self, detector_config):
        detector_type = str(detector_config.get("detector_type", "")).strip()
        detector_mode = str(detector_config.get("detector_mode", "")).strip()
        hardware = str(detector_config.get("hardware", "")).strip()

        type_index = self.comboBox_detector_selection_type.findData(detector_type)
        if type_index >= 0:
            self.comboBox_detector_selection_type.setCurrentIndex(type_index)

        mode_index = self.comboBox_detector_selection_mode.findData(detector_mode)
        if mode_index >= 0:
            self.comboBox_detector_selection_mode.setCurrentIndex(mode_index)

        if hardware and self.comboBox_detector_selection_hardware.findText(hardware) >= 0:
            self.comboBox_detector_selection_hardware.setCurrentText(hardware)

        self.label_detector_selection_setup_info.setText(
            "Query the saved detector filters, then select and customize the action."
        )
