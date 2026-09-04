from PyQt5 import QtCore, QtGui, QtWidgets

import asyncio
import getpass
import inspect
import os
import shutil
import time
import uuid
import tempfile
import shlex

import qasync

import fissure.utils
from fissure.utils.selected_node_utils import (
    selected_node_is_ip,
    selected_node_is_local,
    selected_node_is_remote,
)


ACTION_QUERY_CONTEXT = "sa.survey.actions"
ACTION_SCHEMA_CONTEXT = "sa.survey.schema"
SA_SURVEY_XPRA_DISPLAY = ":100"
SA_SURVEY_REMOTE_XPRA = "/usr/local/bin/xpra"

SA_SURVEY_TOOLS = [
    {
        "name": "Spektrum",
        "hardware": ["RTL2832U"],
        "callback": "_slotMenuSpektrumClicked",
        "remote": True,
        "remote_command": [
            "{home}/Installed_by_FISSURE/spektrum/spektrum",
        ],
        "description": "Live RTL-SDR spectrum viewer.",
    },
    {
        "name": "QSpectrumAnalyzer",
        "hardware": [
            "RTL2832U",
            "HackRF",
            "USRP B20xmini",
            "USRP B2x0",
        ],
        "callback": "_slotMenuQSpectrumAnalyzerClicked",
        "remote": True,
        "remote_command": [
            "/usr/bin/env",
            "QT_PREFERRED_BINDING=PyQt5",
            "qspectrumanalyzer",
        ],
        "description": "Wideband spectrum viewer for supported SDR backends.",
    },
    {
        "name": "Gqrx",
        "hardware": [
            "RTL2832U",
            "HackRF",
            "USRP B20xmini",
            "USRP B2x0",
            "LimeSDR",
            "bladeRF",
            "bladeRF 2.0",
            "PlutoSDR",
        ],
        "callback": "_slotMenuGQRX_Clicked",
        "remote": True,
        "remote_command": ["gqrx"],
        "description": "General-purpose SDR receiver. Hardware support depends on the installed backend.",
    },
    {
        "name": "Universal Radio Hacker",
        "hardware": [
            "RTL2832U", "HackRF", "USRP B20xmini", "USRP B2x0",
            "LimeSDR", "bladeRF", "bladeRF 2.0", "PlutoSDR",
        ],
        "callback": "_slotMenuURH_Clicked",
        "remote": True,
        "remote_command": ["urh"],
        "description": "Interactive signal capture, analysis, and protocol exploration.",
    },
]


def _sa_survey_active(dashboard: QtCore.QObject) -> bool:
    return bool(
        getattr(dashboard, "sa_survey_running", False)
        or getattr(dashboard, "sa_survey_start_pending", False)
    )


def _sa_survey_selected_node_available(dashboard: QtCore.QObject) -> bool:
    """Return True when the selected node can support graphical Survey."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid:
        return False

    supported_location = (
        selected_node_is_local(dashboard)
        or (
            selected_node_is_remote(dashboard)
            and selected_node_is_ip(dashboard)
        )
    )
    if not supported_location:
        return False

    node_state = (getattr(dashboard, "node_states", {}) or {}).get(node_uid)
    return not (isinstance(node_state, dict) and node_state.get("connected") is False)


def _sa_survey_remote_xpra_enabled(dashboard: QtCore.QObject) -> bool:
    """Return True when the selected Survey node needs Xpra presentation."""
    return (
        selected_node_is_remote(dashboard)
        and selected_node_is_ip(dashboard)
    )


def _sa_survey_remote_tool_active(dashboard: QtCore.QObject) -> bool:
    """Return True while a remote third-party Survey tool owns Xpra."""
    process = getattr(dashboard, "sa_survey_xpra_process", None)
    return bool(
        str(getattr(dashboard, "sa_survey_remote_tool_name", "") or "").strip()
        and process is not None
        and process.returncode is None
    )


def _sa_survey_xpra_username(dashboard: QtCore.QObject) -> str:
    """Resolve the SSH username for remote graphical Survey."""
    settings = getattr(dashboard, "selected_node_settings", {}) or {}
    sensor_settings = settings.get("Sensor Node", {}) if isinstance(settings, dict) else {}
    if not isinstance(sensor_settings, dict):
        sensor_settings = {}

    return str(
        sensor_settings.get("ssh_username")
        or getpass.getuser()
        or ""
    ).strip()


def _sa_survey_local_xpra_executable() -> str:
    """Resolve the Xpra client installed on the Dashboard computer."""
    return shutil.which("xpra") or SA_SURVEY_REMOTE_XPRA


async def _sa_survey_prompt_ssh_password(
    dashboard: QtCore.QObject,
    target: str,
):
    """Prompt for an SSH password without nesting the qasync event loop."""
    dialog = QtWidgets.QInputDialog(dashboard)
    dialog.setWindowTitle("Remote Sensor Node Authentication")
    dialog.setLabelText(f"SSH password for {target}:")
    dialog.setInputMode(QtWidgets.QInputDialog.TextInput)
    dialog.setTextEchoMode(QtWidgets.QLineEdit.Password)
    dialog.setWindowModality(QtCore.Qt.WindowModal)

    loop = asyncio.get_running_loop()
    result_future = loop.create_future()

    def _accepted():
        if not result_future.done():
            result_future.set_result(str(dialog.textValue() or ""))

    def _rejected():
        if not result_future.done():
            result_future.set_result(None)

    dialog.accepted.connect(_accepted)
    dialog.rejected.connect(_rejected)
    dialog.open()

    try:
        return await result_future
    finally:
        dialog.deleteLater()


async def _sa_survey_ssh_key_available(target: str) -> bool:
    """Return True when system OpenSSH can authenticate without interaction."""
    ssh_executable = shutil.which("ssh")
    if not ssh_executable:
        return False

    process = await asyncio.create_subprocess_exec(
        ssh_executable,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "StrictHostKeyChecking=accept-new",
        target,
        "true",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    return await process.wait() == 0


def _sa_survey_create_ssh_askpass(password: str):
    """Create a short-lived OpenSSH askpass helper for one Xpra session."""
    auth_dir = tempfile.mkdtemp(prefix="fissure-xpra-ssh-")
    os.chmod(auth_dir, 0o700)

    password_path = os.path.join(auth_dir, "password")
    askpass_path = os.path.join(auth_dir, "askpass.sh")

    with open(password_path, "w", encoding="utf-8") as password_file:
        password_file.write(password)
        password_file.write("\n")
    os.chmod(password_path, 0o600)

    with open(askpass_path, "w", encoding="utf-8") as askpass_file:
        askpass_file.write(
            "#!/bin/sh\n"
            'cat "$FISSURE_SSH_PASSWORD_FILE"\n'
        )
    os.chmod(askpass_path, 0o700)

    return auth_dir, askpass_path, password_path


async def _sa_survey_start_remote_xpra(
    dashboard: QtCore.QObject,
    start_child: str = "",
    exit_with_children: bool = False,
) -> str:
    """Start and attach one remote Xpra Survey session."""
    node_ip = str(getattr(dashboard, "selected_node_ip", "") or "").strip()
    username = _sa_survey_xpra_username(dashboard)
    display = SA_SURVEY_XPRA_DISPLAY
    xpra_executable = _sa_survey_local_xpra_executable()
    existing_process = getattr(dashboard, "sa_survey_xpra_process", None)

    if existing_process is not None and existing_process.returncode is None:
        raise RuntimeError("A remote Survey display is already active.")
    if not node_ip or node_ip == "ipc":
        raise RuntimeError(
            "Selected remote Sensor Node does not have an IP address."
        )
    if not username:
        raise RuntimeError(
            "Could not determine the Sensor Node SSH username."
        )
    if not os.path.isfile(xpra_executable):
        raise RuntimeError(
            f"Xpra client was not found: {xpra_executable}"
        )

    target = f"{username}@{node_ip}"
    remote_uri = f"ssh://{target}/{display.lstrip(':')}"

    dashboard.logger.info(
        f"Starting and attaching Survey Xpra display {display} on {target}"
    )

    key_available = await _sa_survey_ssh_key_available(target)
    auth_dir = ""
    process_env = os.environ.copy()

    if key_available:
        ssh_command = "ssh"
    else:
        password = await _sa_survey_prompt_ssh_password(
            dashboard,
            target,
        )
        if password is None:
            raise RuntimeError("SSH authentication was cancelled.")

        setsid_executable = shutil.which("setsid")
        if not setsid_executable:
            raise RuntimeError(
                "The system 'setsid' command was not found."
            )

        auth_dir, askpass_path, password_path = (
            _sa_survey_create_ssh_askpass(password)
        )

        process_env["SSH_ASKPASS"] = askpass_path
        process_env["FISSURE_SSH_PASSWORD_FILE"] = password_path
        process_env.pop("SSH_ASKPASS_REQUIRE", None)

        if not str(process_env.get("DISPLAY") or "").strip():
            process_env["DISPLAY"] = ":0"

        ssh_command = (
            f"{setsid_executable} -w "
            "ssh "
            "-o PubkeyAuthentication=no "
            "-o PasswordAuthentication=yes "
            "-o PreferredAuthentications=password "
            "-o NumberOfPasswordPrompts=1 "
            "-o StrictHostKeyChecking=accept-new"
        )

    xpra_arguments = [
        xpra_executable,
        "start",
        f"--ssh={ssh_command}",
        remote_uri,
        "--attach=yes",
        "--compressors=none",
        "--speaker=disabled",
        "--microphone=disabled",
        "--tray=no",
        "--system-tray=no",
        "--exit-with-client=yes",
    ]
    if start_child:
        xpra_arguments.append(f"--start-child={start_child}")
    if exit_with_children:
        xpra_arguments.append("--exit-with-children")

    try:
        client_process = await asyncio.create_subprocess_exec(
            *xpra_arguments,
            stdin=asyncio.subprocess.DEVNULL,
            env=process_env,
        )

        await asyncio.sleep(0.1)

        if client_process.returncode is not None:
            raise RuntimeError(
                "Xpra client exited during startup with return code "
                f"{client_process.returncode}."
            )

    except Exception:
        if auth_dir:
            shutil.rmtree(auth_dir, ignore_errors=True)
        raise

    dashboard.sa_survey_xpra_process = client_process
    dashboard.sa_survey_xpra_target = target
    dashboard.sa_survey_xpra_display = display
    dashboard.sa_survey_xpra_auth_dir = auth_dir

    return display


async def _sa_survey_cleanup_remote_xpra(
    logger,
    client_process,
    target: str,
    display: str,
    auth_dir: str = "",
):
    """Detach the Dashboard Xpra client and remove temporary SSH credentials."""
    try:
        if client_process is not None and client_process.returncode is None:
            try:
                client_process.terminate()
                await asyncio.wait_for(
                    client_process.wait(),
                    timeout=3.0,
                )
            except asyncio.TimeoutError:
                client_process.kill()
                await client_process.wait()
            except ProcessLookupError:
                pass
    finally:
        if auth_dir:
            shutil.rmtree(auth_dir, ignore_errors=True)


def _schedule_sa_survey_xpra_cleanup(dashboard: QtCore.QObject):
    """Snapshot and asynchronously clean up the active Survey Xpra session."""
    client_process = getattr(
        dashboard,
        "sa_survey_xpra_process",
        None,
    )
    target = str(
        getattr(dashboard, "sa_survey_xpra_target", "")
        or ""
    ).strip()
    display = str(
        getattr(dashboard, "sa_survey_xpra_display", "")
        or ""
    ).strip()
    auth_dir = str(
        getattr(dashboard, "sa_survey_xpra_auth_dir", "")
        or ""
    ).strip()

    dashboard.sa_survey_xpra_process = None
    dashboard.sa_survey_xpra_target = ""
    dashboard.sa_survey_xpra_display = ""
    dashboard.sa_survey_xpra_auth_dir = ""

    if client_process is None and not auth_dir:
        return

    asyncio.create_task(
        _sa_survey_cleanup_remote_xpra(
            dashboard.logger,
            client_process,
            target,
            display,
            auth_dir,
        )
    )


def _sa_survey_hardware_matches(candidate: str, selected: str) -> bool:
    candidate = str(candidate or "").strip().lower()
    selected = str(selected or "").strip().lower()
    return bool(candidate and selected and (candidate in selected or selected in candidate))


def _sa_survey_selected_hardware(dashboard: QtCore.QObject) -> dict:
    record = dashboard.ui.comboBox_sa_survey_settings_hardware.currentData()
    return record if isinstance(record, dict) else {}


def _clear_sa_survey_parameter_widgets(dashboard: QtCore.QObject):
    """Clear dynamically generated Survey parameter controls."""
    contents = dashboard.ui.scrollAreaWidgetContents_sa_survey_parameters
    layout = contents.layout()
    if layout is None:
        layout = QtWidgets.QFormLayout(contents)
        layout.setFieldGrowthPolicy(QtWidgets.QFormLayout.AllNonFixedFieldsGrow)

    while layout.count():
        item = layout.takeAt(0)
        if item.widget() is not None:
            item.widget().deleteLater()

    layout.setContentsMargins(8, 8, 8, 8)
    layout.setHorizontalSpacing(10)
    layout.setVerticalSpacing(8)
    dashboard.sa_survey_parameter_widgets = {}
    dashboard.sa_survey_current_schema = {}
    dashboard.sa_survey_customized = False
    dashboard.ui.pushButton_sa_survey_execution_start_stop.setEnabled(False)


def _reset_sa_survey_action_selection(dashboard: QtCore.QObject):
    """Clear Survey Plugin/Action selection and customized parameters."""
    dashboard.sa_survey_filtered_actions = []
    dashboard.sa_survey_selected_plugin = ""
    dashboard.sa_survey_selected_action = ""

    for combo in (
        dashboard.ui.comboBox_sa_survey_settings_plugin,
        dashboard.ui.comboBox_sa_survey_settings_action,
    ):
        combo.blockSignals(True)
        combo.clear()
        combo.blockSignals(False)
        combo.setEnabled(False)

    dashboard.ui.pushButton_sa_survey_parameters_customize.setText("Customize")
    dashboard.ui.pushButton_sa_survey_parameters_customize.setEnabled(False)
    _clear_sa_survey_parameter_widgets(dashboard)


def _populate_sa_survey_actions_for_plugin(
    dashboard: QtCore.QObject,
    preferred_action: str = "",
):
    """Populate Survey actions for the selected Plugin."""
    plugin_name = dashboard.ui.comboBox_sa_survey_settings_plugin.currentText().strip()
    action_combo = dashboard.ui.comboBox_sa_survey_settings_action
    matches = []

    action_combo.blockSignals(True)
    action_combo.clear()
    for record in getattr(dashboard, "sa_survey_filtered_actions", []) or []:
        if not isinstance(record, dict) or str(record.get("plugin") or "").strip() != plugin_name:
            continue
        action_name = str(record.get("action") or "").strip()
        if action_name:
            matches.append(record)
            action_combo.addItem(action_name, record)

    if preferred_action:
        index = action_combo.findText(str(preferred_action), QtCore.Qt.MatchExactly)
        if index >= 0:
            action_combo.setCurrentIndex(index)
    if action_combo.currentIndex() < 0 and action_combo.count() > 0:
        action_combo.setCurrentIndex(0)
    action_combo.blockSignals(False)

    action_combo.setEnabled(
        bool(matches) and _sa_survey_selected_node_available(dashboard) and not _sa_survey_active(dashboard)
    )
    if matches:
        _slotSA_SurveyActionChanged(dashboard)
    else:
        dashboard.sa_survey_selected_plugin = ""
        dashboard.sa_survey_selected_action = ""
        dashboard.ui.pushButton_sa_survey_parameters_customize.setEnabled(False)
        _clear_sa_survey_parameter_widgets(dashboard)


def _filter_sa_survey_action_catalog(
    dashboard: QtCore.QObject,
    preferred_plugin: str = "",
    preferred_action: str = "",
):
    """Filter the cached Survey catalog by selected hardware."""
    hardware_type = str(_sa_survey_selected_hardware(dashboard).get("hardware_type") or "").strip()
    filtered = []

    for record in getattr(dashboard, "sa_survey_action_catalog", []) or []:
        if not isinstance(record, dict):
            continue
        plugin_name = str(record.get("plugin") or "").strip()
        action_name = str(record.get("action") or "").strip()
        if not plugin_name or not action_name:
            continue

        compatible = record.get("hardware", []) or []
        if compatible and not any(_sa_survey_hardware_matches(value, hardware_type) for value in compatible):
            continue
        filtered.append(record)

    dashboard.sa_survey_filtered_actions = filtered
    plugin_combo = dashboard.ui.comboBox_sa_survey_settings_plugin
    current_plugin = str(preferred_plugin or plugin_combo.currentText() or "").strip()
    plugins = sorted(
        {str(record.get("plugin") or "").strip() for record in filtered if str(record.get("plugin") or "").strip()},
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
    plugin_combo.setEnabled(
        plugin_combo.count() > 0
        and _sa_survey_selected_node_available(dashboard)
        and not _sa_survey_active(dashboard)
    )

    _clear_sa_survey_parameter_widgets(dashboard)
    _populate_sa_survey_actions_for_plugin(dashboard, preferred_action)


def _clear_sa_survey_tools(dashboard: QtCore.QObject):
    """Clear generated Third-Party Tool widgets."""
    contents = dashboard.ui.scrollAreaWidgetContents_sa_survey_tools
    layout = contents.layout()
    if layout is None:
        layout = QtWidgets.QVBoxLayout(contents)

    while layout.count():
        item = layout.takeAt(0)
        if item.widget() is not None:
            item.widget().deleteLater()

    layout.setContentsMargins(8, 8, 8, 8)
    layout.setSpacing(10)
    layout.setAlignment(QtCore.Qt.AlignTop)
    dashboard.sa_survey_tools_layout = layout


async def _watch_sa_survey_remote_tool(
    dashboard: QtCore.QObject,
    client_process,
    tool_name: str,
):
    """Clear remote-tool state after its Xpra client exits."""
    return_code = await client_process.wait()

    if getattr(dashboard, "sa_survey_xpra_process", None) is not client_process:
        return

    auth_dir = str(
        getattr(dashboard, "sa_survey_xpra_auth_dir", "")
        or ""
    ).strip()

    dashboard.sa_survey_xpra_process = None
    dashboard.sa_survey_xpra_target = ""
    dashboard.sa_survey_xpra_display = ""
    dashboard.sa_survey_xpra_auth_dir = ""
    dashboard.sa_survey_remote_tool_name = ""
    dashboard.sa_survey_remote_tool_pending = False

    if auth_dir:
        shutil.rmtree(auth_dir, ignore_errors=True)

    dashboard.logger.info(
        f"Remote Survey tool {tool_name} closed with return code {return_code}."
    )
    dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
        f"Remote third-party tool closed: {tool_name}"
    )
    update_sa_survey_selected_node_gate(dashboard)
    _rebuild_sa_survey_tools(dashboard)


async def _launch_sa_survey_remote_tool(
    dashboard: QtCore.QObject,
    tool: dict,
):
    """Launch one curated tool on a remote IP Sensor Node through Xpra."""
    name = str(tool.get("name") or "Tool").strip()
    command = tool.get("remote_command") or tool.get("command") or []

    if _sa_survey_active(dashboard):
        dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
            "Stop the active Survey action before launching a remote third-party tool."
        )
        return
    if _sa_survey_remote_tool_active(dashboard) or bool(
        getattr(dashboard, "sa_survey_remote_tool_pending", False)
    ):
        dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
            "Close the active remote third-party tool before launching another."
        )
        return
    if isinstance(command, str):
        command = [command]
    if not isinstance(command, (list, tuple)) or not command:
        dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
            f"No remote command is configured for third-party tool: {name}"
        )
        return

    command_parts = [
        str(value)
        for value in command
        if str(value).strip()
    ]
    if not command_parts:
        return

    username = _sa_survey_xpra_username(dashboard)
    remote_home = (
        "/root"
        if username == "root"
        else f"/home/{username}"
    )
    command_parts = [
        value.replace("{home}", remote_home)
        for value in command_parts
    ]
    remote_path = ":".join(
        [
            f"{remote_home}/.local/bin",
            "/usr/local/sbin",
            "/usr/local/bin",
            "/usr/sbin",
            "/usr/bin",
            "/sbin",
            "/bin",
        ]
    )

    start_child = shlex.join(
        [
            "/usr/bin/env",
            f"PATH={remote_path}",
            *command_parts,
        ]
    )

    dashboard.sa_survey_remote_tool_pending = True
    dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
        f"Starting remote third-party tool: {name}"
    )
    _rebuild_sa_survey_tools(dashboard)

    try:
        await _sa_survey_start_remote_xpra(
            dashboard,
            start_child=start_child,
            exit_with_children=True,
        )

        dashboard.sa_survey_remote_tool_name = name
        client_process = dashboard.sa_survey_xpra_process
        dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
            f"Launched remote third-party tool: {name}"
        )

        asyncio.create_task(
            _watch_sa_survey_remote_tool(
                dashboard,
                client_process,
                name,
            )
        )

    except Exception as error:
        dashboard.logger.error(
            f"Could not launch remote Survey tool {name}: {error}"
        )
        dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
            f"Failed to launch remote third-party tool: {name}\n{error}"
        )
    finally:
        dashboard.sa_survey_remote_tool_pending = False
        _rebuild_sa_survey_tools(dashboard)


def _launch_sa_survey_tool(dashboard: QtCore.QObject, tool: dict):
    """Launch one curated Survey tool locally or on a remote IP node."""
    name = str(tool.get("name") or "Tool").strip()

    if selected_node_is_local(dashboard):
        callback_name = str(tool.get("callback") or "").strip()
        try:
            from .. import MenuBarSlots

            getattr(MenuBarSlots, callback_name)(dashboard)
            dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
                f"Launched third-party tool: {name}"
            )
        except Exception as error:
            dashboard.logger.error(
                f"Could not launch Survey tool {name}: {error}"
            )
            dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
                f"Failed to launch third-party tool: {name}\n{error}"
            )
        return

    if _sa_survey_remote_xpra_enabled(dashboard):
        asyncio.create_task(
            _launch_sa_survey_remote_tool(
                dashboard,
                tool,
            )
        )


def _rebuild_sa_survey_tools(dashboard: QtCore.QObject):
    """Show curated tools compatible with the selected hardware and node."""
    _clear_sa_survey_tools(dashboard)
    hardware_type = str(
        _sa_survey_selected_hardware(dashboard).get("hardware_type")
        or ""
    ).strip()
    tools = []
    local_node = selected_node_is_local(dashboard)
    remote_ip_node = _sa_survey_remote_xpra_enabled(dashboard)

    if _sa_survey_selected_node_available(dashboard):
        for tool in SA_SURVEY_TOOLS:
            supported = tool.get("hardware", []) or []
            if supported and not any(
                _sa_survey_hardware_matches(value, hardware_type)
                for value in supported
            ):
                continue

            if local_node:
                tools.append(tool)
            elif remote_ip_node and bool(tool.get("remote", False)):
                if tool.get("remote_command") or tool.get("command"):
                    tools.append(tool)

    if not tools:
        if remote_ip_node:
            empty_text = (
                "No compatible remote third-party tools for the selected hardware."
            )
        else:
            empty_text = (
                "No compatible third-party tools for the selected hardware."
            )

        label = QtWidgets.QLabel(
            empty_text,
            dashboard.ui.scrollAreaWidgetContents_sa_survey_tools,
        )
        label.setWordWrap(True)
        label.setProperty("uiRole", "surveyToolEmpty")
        dashboard.sa_survey_tools_layout.addWidget(label)
        return

    remote_tool_busy = (
        bool(getattr(dashboard, "sa_survey_remote_tool_pending", False))
        or _sa_survey_remote_tool_active(dashboard)
    )

    for index, tool in enumerate(tools):
        name = str(tool.get("name") or "Tool")

        tool_widget = QtWidgets.QWidget(
            dashboard.ui.scrollAreaWidgetContents_sa_survey_tools
        )
        tool_layout = QtWidgets.QVBoxLayout(tool_widget)
        tool_layout.setContentsMargins(0, 0, 0, 0)
        tool_layout.setSpacing(5)

        button = QtWidgets.QPushButton(name, tool_widget)
        button.setProperty("uiRole", "surveyToolButton")
        button.setEnabled(
            not (
                remote_ip_node
                and (_sa_survey_active(dashboard) or remote_tool_busy)
            )
        )
        button.clicked.connect(
            lambda _checked=False, tool=tool: _launch_sa_survey_tool(
                dashboard,
                tool,
            )
        )
        tool_layout.addWidget(button)

        description = str(tool.get("description") or "").strip()
        if description:
            label = QtWidgets.QLabel(description, tool_widget)
            label.setWordWrap(True)
            label.setProperty("uiRole", "surveyToolDescription")
            label.setContentsMargins(4, 0, 4, 0)
            tool_layout.addWidget(label)

        dashboard.sa_survey_tools_layout.addWidget(tool_widget)

        if index < len(tools) - 1:
            dashboard.sa_survey_tools_layout.addSpacing(10)


def _refresh_sa_survey_hardware(dashboard: QtCore.QObject):
    """Populate Survey Hardware from SDRs configured on the selected local node."""
    combo = dashboard.ui.comboBox_sa_survey_settings_hardware
    records = []

    if _sa_survey_selected_node_available(dashboard):
        try:
            display_names = fissure.utils.hardware.selectedNodeHardwareDisplayNames(dashboard, "archive")
        except Exception as error:
            dashboard.logger.debug(f"[Survey] Could not load hardware: {error}")
            display_names = []

        for display_name in display_names:
            try:
                hardware_type, *_ = fissure.utils.hardware.hardwareDisplayNameLookup(
                    dashboard, display_name, "iq"
                )
            except Exception:
                continue
            if str(display_name or "").strip() and str(hardware_type or "").strip():
                records.append({"display_name": str(display_name), "hardware_type": str(hardware_type)})

    signature = tuple((record["display_name"], record["hardware_type"]) for record in records)
    if getattr(dashboard, "sa_survey_hardware_signature", None) == signature:
        return

    dashboard.sa_survey_hardware_signature = signature
    current_text = combo.currentText().strip()
    combo.blockSignals(True)
    combo.clear()
    for record in records:
        combo.addItem(record["display_name"], record)
    index = combo.findText(current_text, QtCore.Qt.MatchExactly)
    if index >= 0:
        combo.setCurrentIndex(index)
    elif combo.count() > 0:
        combo.setCurrentIndex(0)
    combo.blockSignals(False)

    combo.setEnabled(bool(records) and not _sa_survey_active(dashboard))
    _filter_sa_survey_action_catalog(dashboard)
    _rebuild_sa_survey_tools(dashboard)


def _set_sa_survey_start_stop_button(dashboard: QtCore.QObject, running: bool):
    button = dashboard.ui.pushButton_sa_survey_execution_start_stop
    button.setText("Stop" if running else "Start")
    button.setProperty("running", bool(running))
    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


def _set_sa_survey_execution_locked(dashboard: QtCore.QObject, locked: bool):
    available = _sa_survey_selected_node_available(dashboard)
    has_actions = bool(getattr(dashboard, "sa_survey_filtered_actions", []))
    has_action = bool(
        getattr(dashboard, "sa_survey_selected_plugin", "")
        and getattr(dashboard, "sa_survey_selected_action", "")
    )

    dashboard.ui.comboBox_sa_survey_settings_hardware.setEnabled(available and not locked)
    dashboard.ui.comboBox_sa_survey_settings_plugin.setEnabled(available and has_actions and not locked)
    dashboard.ui.comboBox_sa_survey_settings_action.setEnabled(available and has_actions and not locked)
    dashboard.ui.pushButton_sa_survey_settings_query.setEnabled(
        available
        and dashboard.ui.comboBox_sa_survey_settings_hardware.count() > 0
        and not getattr(dashboard, "sa_survey_query_pending", False)
        and not locked
    )
    dashboard.ui.pushButton_sa_survey_parameters_customize.setEnabled(available and has_action and not locked)

    for record in (getattr(dashboard, "sa_survey_parameter_widgets", {}) or {}).values():
        widget = record.get("widget") if isinstance(record, dict) else None
        if widget is not None:
            widget.setEnabled(not locked)


def initialize_sa_survey_controls(dashboard: QtCore.QObject):
    """Initialize the graphical Signal Analysis Survey workflow."""
    dashboard.sa_survey_action_catalog = []
    dashboard.sa_survey_filtered_actions = []
    dashboard.sa_survey_action_catalog_node_uid = ""
    dashboard.sa_survey_hardware_signature = None
    dashboard.sa_survey_selected_plugin = ""
    dashboard.sa_survey_selected_action = ""
    dashboard.sa_survey_parameter_widgets = {}
    dashboard.sa_survey_current_schema = {}
    dashboard.sa_survey_customized = False
    dashboard.sa_survey_query_pending = False
    dashboard.sa_survey_start_pending = False
    dashboard.sa_survey_running = False
    dashboard.sa_survey_node_uid = ""
    dashboard.sa_survey_operation_id = ""
    dashboard.sa_survey_run_plugin = ""
    dashboard.sa_survey_run_action = ""
    dashboard.sa_survey_run_parameters = {}
    dashboard.sa_survey_started_at = 0.0
    dashboard.sa_survey_stop_requested = False
    dashboard.sa_survey_seen_running_status = False
    dashboard.sa_survey_monitor_action_status = False
    dashboard.sa_survey_xpra_process = None
    dashboard.sa_survey_xpra_target = ""
    dashboard.sa_survey_xpra_display = ""
    dashboard.sa_survey_xpra_auth_dir = ""
    dashboard.sa_survey_remote_tool_name = ""
    dashboard.sa_survey_remote_tool_pending = False

    icon_path = os.path.join(fissure.utils.UI_DIR, "Icons", "select_node.png")
    if os.path.isfile(icon_path):
        dashboard.ui.label_sa_survey_select_sensor_node_image.setPixmap(QtGui.QPixmap(icon_path))
        dashboard.ui.label_sa_survey_select_sensor_node_image.setScaledContents(False)
        dashboard.ui.label_sa_survey_select_sensor_node_image.setAlignment(QtCore.Qt.AlignCenter)

    dashboard.ui.scrollArea_sa_survey_parameters.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    dashboard.ui.scrollArea_sa_survey_parameters.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
    dashboard.ui.scrollArea_sa_survey_tools.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    dashboard.ui.scrollArea_sa_survey_tools.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
    dashboard.ui.pushButton_sa_survey_settings_query.setText("Query Actions")
    dashboard.ui.pushButton_sa_survey_parameters_customize.setText("Customize")
    dashboard.ui.pushButton_sa_survey_parameters_customize.setEnabled(False)
    dashboard.ui.pushButton_sa_survey_execution_add_soi.setEnabled(False)
    dashboard.ui.label_sa_survey_execution_status.setText("Unavailable")
    dashboard.ui.label_sa_survey_execution_operation_id.setText("-")
    dashboard.ui.textEdit_sa_survey_execution_result.clear()
    dashboard.ui.textEdit_sa_survey_execution_result.setReadOnly(True)
    _set_sa_survey_start_stop_button(dashboard, False)
    dashboard.ui.pushButton_sa_survey_execution_start_stop.setEnabled(False)
    _clear_sa_survey_parameter_widgets(dashboard)
    _clear_sa_survey_tools(dashboard)
    update_sa_survey_selected_node_gate(dashboard)


def update_sa_survey_selected_node_gate(dashboard: QtCore.QObject):
    """Show Survey controls for local nodes and remote IP nodes."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    available = _sa_survey_selected_node_available(dashboard)
    active = _sa_survey_active(dashboard)
    previous_uid = str(getattr(dashboard, "sa_survey_action_catalog_node_uid", "") or "").strip()

    dashboard.ui.stackedWidget_sa_survey.setCurrentWidget(
        dashboard.ui.page_sa_survey_controls if available or active else dashboard.ui.page_sa_survey_no_node
    )

    if node_uid != previous_uid and not active:
        dashboard.sa_survey_action_catalog_node_uid = node_uid
        dashboard.sa_survey_action_catalog = []
        dashboard.sa_survey_hardware_signature = None
        dashboard.sa_survey_query_pending = False
        dashboard.ui.pushButton_sa_survey_settings_query.setText("Query Actions")
        _reset_sa_survey_action_selection(dashboard)

    if not active:
        _refresh_sa_survey_hardware(dashboard)

    if active:
        _set_sa_survey_execution_locked(dashboard, True)
        _set_sa_survey_start_stop_button(dashboard, True)
        dashboard.ui.pushButton_sa_survey_execution_start_stop.setEnabled(
            not bool(getattr(dashboard, "sa_survey_stop_requested", False))
        )
        dashboard.ui.pushButton_sa_survey_execution_add_soi.setEnabled(True)
        return

    has_hardware = dashboard.ui.comboBox_sa_survey_settings_hardware.count() > 0
    has_action = bool(dashboard.sa_survey_selected_plugin and dashboard.sa_survey_selected_action)
    dashboard.ui.comboBox_sa_survey_settings_hardware.setEnabled(available and has_hardware)
    dashboard.ui.pushButton_sa_survey_settings_query.setEnabled(
        available and has_hardware and not dashboard.sa_survey_query_pending
    )
    dashboard.ui.pushButton_sa_survey_parameters_customize.setEnabled(available and has_action)
    dashboard.ui.pushButton_sa_survey_execution_add_soi.setEnabled(available)
    _set_sa_survey_start_stop_button(dashboard, False)
    remote_tool_busy = (
        _sa_survey_remote_xpra_enabled(dashboard)
        and (
            bool(getattr(dashboard, "sa_survey_remote_tool_pending", False))
            or _sa_survey_remote_tool_active(dashboard)
        )
    )
    dashboard.ui.pushButton_sa_survey_execution_start_stop.setEnabled(
        available
        and has_action
        and dashboard.sa_survey_customized
        and not remote_tool_busy
    )

    if available:
        dashboard.ui.label_sa_survey_execution_status.setText("Idle")
    else:
        dashboard.ui.label_sa_survey_execution_status.setText("Unavailable")
        dashboard.ui.label2_sa_survey_select_a_node.setText(
            "Remote graphical Survey requires an IP Sensor Node."
            if node_uid and selected_node_is_remote(dashboard)
            else "Select an online sensor node to perform RF survey."
        )


def _survey_selection_summary(record: dict) -> str:
    plugin_name = str(record.get("plugin") or "").strip()
    action_name = str(record.get("action") or "").strip()
    hardware = [str(value) for value in (record.get("hardware", []) or []) if str(value).strip()]
    return (
        f"{plugin_name}: {action_name}\n"
        f"Hardware: {', '.join(hardware) if hardware else 'No hardware restriction'}"
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_SurveyHardwareChanged(dashboard: QtCore.QObject):
    """Refilter Survey actions and tools when Hardware changes."""
    if not _sa_survey_active(dashboard):
        _filter_sa_survey_action_catalog(dashboard)
        _rebuild_sa_survey_tools(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_SurveyPluginChanged(dashboard: QtCore.QObject):
    """Populate Survey actions for the selected Plugin."""
    if not _sa_survey_active(dashboard):
        _populate_sa_survey_actions_for_plugin(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSA_SurveyActionChanged(dashboard: QtCore.QObject):
    """Track the selected Survey action and invalidate old parameters."""
    if _sa_survey_active(dashboard):
        return

    record = dashboard.ui.comboBox_sa_survey_settings_action.currentData()
    if not isinstance(record, dict):
        dashboard.sa_survey_selected_plugin = ""
        dashboard.sa_survey_selected_action = ""
        dashboard.ui.pushButton_sa_survey_parameters_customize.setEnabled(False)
        _clear_sa_survey_parameter_widgets(dashboard)
        return

    plugin_name = str(record.get("plugin") or "").strip()
    action_name = str(record.get("action") or "").strip()
    same_selection = (
        plugin_name == str(dashboard.sa_survey_selected_plugin or "").strip()
        and action_name == str(dashboard.sa_survey_selected_action or "").strip()
    )
    dashboard.ui.label_sa_survey_setup_info.setText(_survey_selection_summary(record))
    dashboard.ui.pushButton_sa_survey_parameters_customize.setText("Customize")
    dashboard.ui.pushButton_sa_survey_parameters_customize.setEnabled(
        bool(plugin_name and action_name) and _sa_survey_selected_node_available(dashboard)
    )
    if same_selection:
        return

    dashboard.sa_survey_selected_plugin = plugin_name
    dashboard.sa_survey_selected_action = action_name
    _clear_sa_survey_parameter_widgets(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_SurveyQueryClicked(dashboard: QtCore.QObject):
    """Query the selected Sensor Node for Survey-capable actions."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    if not node_uid or not _sa_survey_selected_node_available(dashboard):
        return
    if dashboard.ui.comboBox_sa_survey_settings_hardware.count() == 0:
        return

    dashboard.sa_survey_query_pending = True
    dashboard.ui.pushButton_sa_survey_settings_query.setEnabled(False)
    dashboard.ui.pushButton_sa_survey_settings_query.setText("Querying...")
    dashboard.ui.label_sa_survey_setup_info.setText("Querying available Survey actions...")
    await dashboard.backend.queryPluginActions(
        node_uid,
        context=ACTION_QUERY_CONTEXT,
        scope="all_plugins",
        include_tags=["sa.survey"],
    )


def handle_sa_survey_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    """Cache Survey actions and apply the selected-hardware filter."""
    if context != ACTION_QUERY_CONTEXT:
        return
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return

    dashboard.sa_survey_query_pending = False
    dashboard.sa_survey_action_catalog_node_uid = str(node_uid or "").strip()
    dashboard.sa_survey_action_catalog = actions if isinstance(actions, list) else []
    dashboard.ui.pushButton_sa_survey_settings_query.setText("Query Actions")
    dashboard.ui.pushButton_sa_survey_settings_query.setEnabled(
        _sa_survey_selected_node_available(dashboard)
        and dashboard.ui.comboBox_sa_survey_settings_hardware.count() > 0
    )
    _filter_sa_survey_action_catalog(dashboard)

    total = len(dashboard.sa_survey_action_catalog)
    visible = len(dashboard.sa_survey_filtered_actions)
    dashboard.ui.label_sa_survey_setup_info.setText(
        f"{visible} compatible Survey action(s) shown from {total} available."
        if total
        else "No Survey-capable plugin actions were returned by this Sensor Node."
    )


def _create_sa_survey_parameter_widget(parent, parameter: dict):
    """Create one editor from a generic plugin action-schema parameter."""
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

    widget.setObjectName(f"sa_survey_parameter_{name}")
    widget.setProperty(
        "uiRole",
        "surveyParameterInfo" if parameter_type == "label" else "surveyParameterEditor",
    )
    description = str(parameter.get("description") or "").strip()
    if description:
        widget.setToolTip(description)
    return widget


@qasync.asyncSlot(QtCore.QObject)
async def _slotSA_SurveyCustomizeClicked(dashboard: QtCore.QObject):
    """Query the selected Survey action schema."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    record = dashboard.ui.comboBox_sa_survey_settings_action.currentData()
    if not node_uid or not _sa_survey_selected_node_available(dashboard) or not isinstance(record, dict):
        return

    plugin_name = str(record.get("plugin") or "").strip()
    action_name = str(record.get("action") or "").strip()
    if not plugin_name or not action_name:
        return

    _clear_sa_survey_parameter_widgets(dashboard)
    dashboard.ui.pushButton_sa_survey_parameters_customize.setText("Loading...")
    dashboard.ui.pushButton_sa_survey_parameters_customize.setEnabled(False)
    await dashboard.backend.queryPluginActionSchema(
        node_uid,
        plugin_name,
        action_name,
        context=ACTION_SCHEMA_CONTEXT,
    )


def handle_sa_survey_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
):
    """Render the selected Survey action schema in the Parameters card."""
    if str(node_uid or "").strip() != str(getattr(dashboard, "selected_node_uid", "") or "").strip():
        return
    if str(plugin_name or "").strip() != str(dashboard.sa_survey_selected_plugin or "").strip():
        return
    if str(action_name or "").strip() != str(dashboard.sa_survey_selected_action or "").strip():
        return

    parameters = parameters if isinstance(parameters, list) else []
    dashboard.sa_survey_current_schema = {
        "params": [dict(parameter) for parameter in parameters if isinstance(parameter, dict)]
    }
    _clear_sa_survey_parameter_widgets(dashboard)
    contents = dashboard.ui.scrollAreaWidgetContents_sa_survey_parameters
    layout = contents.layout()
    count = 0

    for parameter in parameters:
        if not isinstance(parameter, dict):
            continue
        name = str(parameter.get("name") or "").strip()
        if not name:
            continue

        label = QtWidgets.QLabel(f"{str(parameter.get('label') or name).strip()}:", contents)
        label.setObjectName(f"label2_sa_survey_parameter_{name}")
        label.setProperty("uiRole", "surveyParameterLabel")
        description = str(parameter.get("description") or "").strip()
        if description:
            label.setToolTip(description)

        widget = _create_sa_survey_parameter_widget(contents, parameter)
        layout.addRow(label, widget)
        dashboard.sa_survey_parameter_widgets[name] = {"widget": widget, "schema": dict(parameter)}
        count += 1

    if count == 0:
        label = QtWidgets.QLabel("No parameters required for this action.", contents)
        label.setObjectName("label2_sa_survey_no_parameters")
        label.setProperty("uiRole", "surveyParameterInfo")
        layout.addRow(label)

    dashboard.sa_survey_customized = True
    dashboard.ui.pushButton_sa_survey_parameters_customize.setText("Customize")
    dashboard.ui.pushButton_sa_survey_parameters_customize.setEnabled(
        _sa_survey_selected_node_available(dashboard)
    )
    dashboard.ui.pushButton_sa_survey_execution_start_stop.setEnabled(
        _sa_survey_selected_node_available(dashboard) and not _sa_survey_active(dashboard)
    )


def _sa_survey_parameter_value(widget):
    if isinstance(widget, QtWidgets.QComboBox):
        return widget.currentText()
    if isinstance(widget, (QtWidgets.QDoubleSpinBox, QtWidgets.QSpinBox)):
        return widget.value()
    if isinstance(widget, QtWidgets.QCheckBox):
        return widget.isChecked()
    if isinstance(widget, QtWidgets.QLineEdit):
        return widget.text()
    return None


def _collect_sa_survey_parameters(dashboard: QtCore.QObject) -> dict:
    """Collect Survey schema values plus selected hardware identity."""
    parameters = {}
    for name, record in (dashboard.sa_survey_parameter_widgets or {}).items():
        if not isinstance(record, dict):
            continue
        widget = record.get("widget")
        schema = record.get("schema", {})
        if widget is None or str(schema.get("type") or "").strip().lower() == "label":
            continue
        parameters[name] = _sa_survey_parameter_value(widget)

    display_name = str(_sa_survey_selected_hardware(dashboard).get("display_name") or "").strip()
    if not display_name:
        raise ValueError("Select Survey hardware.")

    (
        hardware_type,
        hardware_uuid,
        hardware_radio_name,
        hardware_serial,
        hardware_interface,
        hardware_ip,
        hardware_daughterboard,
    ) = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, display_name, "iq")

    raw_serial = {"HackRF", "RTL2832U", "bladeRF", "bladeRF 2.0", "RSPduo", "RSPdx", "RSPdx R2"}
    zero_default = {"RTL2832U", "bladeRF", "bladeRF 2.0", "RSPduo", "RSPdx", "RSPdx R2"}
    if hardware_serial:
        serial_argument = hardware_serial if hardware_type in raw_serial else f"serial={hardware_serial}"
    elif hardware_type == "HackRF":
        serial_argument = ""
    elif hardware_type in zero_default:
        serial_argument = "0"
    else:
        serial_argument = "False"

    parameters.update(
        {
            "operation_id": str(uuid.uuid4()),
            "requester": "dashboard",
            "hardware_display_name": display_name,
            "hardware_type": hardware_type,
            "hardware_uuid": hardware_uuid,
            "hardware_radio_name": hardware_radio_name,
            "hardware_serial": hardware_serial,
            "hardware_serial_argument": serial_argument,
            "hardware_interface": hardware_interface,
            "hardware_ip": hardware_ip,
            "hardware_daughterboard": hardware_daughterboard,
        }
    )
    return parameters


def _clear_sa_survey_run_state(dashboard: QtCore.QObject):
    dashboard.sa_survey_start_pending = False
    dashboard.sa_survey_running = False
    dashboard.sa_survey_node_uid = ""
    dashboard.sa_survey_operation_id = ""
    dashboard.sa_survey_run_plugin = ""
    dashboard.sa_survey_run_action = ""
    dashboard.sa_survey_run_parameters = {}
    dashboard.sa_survey_started_at = 0.0
    dashboard.sa_survey_stop_requested = False
    dashboard.sa_survey_seen_running_status = False
    dashboard.sa_survey_monitor_action_status = False


def _finish_sa_survey(dashboard: QtCore.QObject, status_text: str):
    started_at = float(getattr(dashboard, "sa_survey_started_at", 0.0) or 0.0)
    result = "\n".join(
        [
            f"Status: {status_text}",
            f"Action: {dashboard.sa_survey_run_plugin}: {dashboard.sa_survey_run_action}",
            f"Sensor Node: {dashboard.sa_survey_node_uid}",
            f"Operation ID: {dashboard.sa_survey_operation_id}",
            f"Duration: {max(0.0, time.time() - started_at) if started_at else 0.0:.2f} s",
        ]
    )
    _schedule_sa_survey_xpra_cleanup(dashboard)
    _clear_sa_survey_run_state(dashboard)
    _set_sa_survey_execution_locked(dashboard, False)
    update_sa_survey_selected_node_gate(dashboard)
    dashboard.ui.label_sa_survey_execution_status.setText(status_text)
    dashboard.ui.label_sa_survey_execution_operation_id.setText("-")
    dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(result)


async def _slotSA_SurveyStartStopClicked(dashboard: QtCore.QObject):
    """Start the selected Survey action or stop its active operation."""
    if _sa_survey_active(dashboard):
        node_uid = str(dashboard.sa_survey_node_uid or "").strip()
        operation_id = str(dashboard.sa_survey_operation_id or "").strip()
        if not node_uid or not operation_id:
            return

        dashboard.sa_survey_stop_requested = True
        dashboard.ui.label_sa_survey_execution_status.setText("Stopping...")
        dashboard.ui.pushButton_sa_survey_execution_start_stop.setEnabled(False)
        try:
            await dashboard.backend.stopPluginOperation(node_uid, operation_id)
        except Exception as error:
            dashboard.logger.error(f"Could not stop Survey operation {operation_id}: {error}")
            dashboard.sa_survey_stop_requested = False
            dashboard.ui.label_sa_survey_execution_status.setText("Running")
            dashboard.ui.pushButton_sa_survey_execution_start_stop.setEnabled(True)
        return

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    plugin_name = str(dashboard.sa_survey_selected_plugin or "").strip()
    action_name = str(dashboard.sa_survey_selected_action or "").strip()
    if not node_uid or not _sa_survey_selected_node_available(dashboard):
        return
    if not plugin_name or not action_name or not dashboard.sa_survey_customized:
        return
    if (
        _sa_survey_remote_xpra_enabled(dashboard)
        and (
            bool(getattr(dashboard, "sa_survey_remote_tool_pending", False))
            or _sa_survey_remote_tool_active(dashboard)
        )
    ):
        dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
            "Close the active remote third-party tool before starting a Survey action."
        )
        return

    try:
        parameters = _collect_sa_survey_parameters(dashboard)
    except Exception as error:
        dashboard.logger.error(f"Could not collect Survey parameters: {error}")
        dashboard.ui.label_sa_survey_execution_status.setText("Invalid Parameters")
        return

    dashboard.sa_survey_start_pending = True
    dashboard.sa_survey_running = False
    dashboard.sa_survey_node_uid = node_uid
    dashboard.sa_survey_operation_id = str(parameters.get("operation_id") or "")
    dashboard.sa_survey_run_plugin = plugin_name
    dashboard.sa_survey_run_action = action_name
    dashboard.sa_survey_started_at = time.time()
    dashboard.sa_survey_stop_requested = False

    if _sa_survey_remote_xpra_enabled(dashboard):
        dashboard.ui.label_sa_survey_execution_status.setText(
            "Starting Remote Display..."
        )
        try:
            xpra_display = await _sa_survey_start_remote_xpra(dashboard)
        except Exception as error:
            dashboard.logger.error(
                f"Could not start remote Survey display: {error}"
            )
            dashboard.sa_survey_run_parameters = dict(parameters)
            _finish_sa_survey(dashboard, "Display Failed")
            return

        parameters["_fissure_execution_context"] = {
            "presentation": "xpra",
            "display": xpra_display,
        }

    dashboard.sa_survey_run_parameters = dict(parameters)

    _set_sa_survey_execution_locked(dashboard, True)
    _set_sa_survey_start_stop_button(dashboard, True)
    dashboard.ui.pushButton_sa_survey_execution_start_stop.setEnabled(True)
    dashboard.ui.label_sa_survey_execution_status.setText("Starting...")
    dashboard.ui.label_sa_survey_execution_operation_id.setText(dashboard.sa_survey_operation_id)
    dashboard.ui.textEdit_sa_survey_execution_result.setPlainText(
        f"Starting {plugin_name}: {action_name}\n"
        f"Sensor Node: {node_uid}\n"
        f"Operation ID: {dashboard.sa_survey_operation_id}"
    )

    try:
        dashboard.sa_survey_monitor_action_status = False

        await dashboard.backend.tacticalNodeExecute(
            [node_uid],
            plugin_name,
            action_name,
            parameters,
        )

        dashboard.sa_survey_monitor_action_status = True
        dashboard.sa_survey_start_pending = False
        dashboard.sa_survey_running = True
        dashboard.ui.label_sa_survey_execution_status.setText("Running")

    except Exception as error:
        dashboard.logger.error(f"Could not start Survey action: {error}")
        _finish_sa_survey(dashboard, "Start Failed")


def update_sa_survey_status_from_selected_node(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    status: str = "",
):
    """Track Survey lifecycle from the selected Sensor Node status."""
    if not _sa_survey_active(dashboard):
        return

    tracked_node_uid = str(
        getattr(dashboard, "sa_survey_node_uid", "") or ""
    ).strip()
    if tracked_node_uid != str(node_uid or "").strip():
        return

    if not bool(
        getattr(dashboard, "sa_survey_monitor_action_status", False)
    ):
        return

    status_text = str(status or "").strip()
    if not status_text:
        return

    if status_text.startswith("Running"):
        dashboard.sa_survey_seen_running_status = True
        dashboard.sa_survey_start_pending = False
        dashboard.sa_survey_running = True

        if not bool(
            getattr(dashboard, "sa_survey_stop_requested", False)
        ):
            dashboard.ui.label_sa_survey_execution_status.setText("Running")
            dashboard.ui.pushButton_sa_survey_execution_start_stop.setEnabled(True)
        return

    if status_text == "Error":
        _finish_sa_survey(dashboard, "Error")
        return

    if status_text == "Idle" and (
        bool(getattr(dashboard, "sa_survey_seen_running_status", False))
        or bool(getattr(dashboard, "sa_survey_stop_requested", False))
    ):
        final_status = (
            "Stopped"
            if bool(getattr(dashboard, "sa_survey_stop_requested", False))
            else "Completed"
        )
        _finish_sa_survey(dashboard, final_status)


__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value)
    and value.__module__ == __name__
]