from PyQt5 import QtCore, QtWidgets

# import fissure.comms
import fissure.utils
import qasync
import time
import os
import yaml
import asyncio
import tempfile
import subprocess
import serial.tools.list_ports
import re
import getpass
import shutil


@qasync.asyncSlot(QtCore.QObject)
async def guess(NodeConfigure: QtCore.QObject):
    """
    Cycles through possible values for the selected row in the scan results table.
    """
    get_uid = NodeConfigure.uid
    scan_results_table = NodeConfigure.tableWidget_scan_results
    get_row = scan_results_table.currentRow()
    get_row_text = []
    for n in range(0, scan_results_table.columnCount()):
        get_row_text.append(str(scan_results_table.item(get_row, n).text()))

    # Send Message for HIPRFISR to Sensor Node Connections
    get_network_type = "IP"
    if get_network_type == "IP":
        await NodeConfigure.dashboard.backend.guessHardware(get_uid, get_row, get_row_text, NodeConfigure.guess_index)
    elif get_network_type == "Meshtastic":
        await NodeConfigure.dashboard.backend.guessHardwareLT(get_uid, get_row, get_row_text, NodeConfigure.guess_index)


@qasync.asyncSlot(QtCore.QObject)
async def probe(NodeConfigure: QtCore.QObject):
    """
    Probes the selected radio in the scan results table.
    """
    # Row Number and Text
    get_uid = NodeConfigure.uid
    scan_results_table = NodeConfigure.tableWidget_scan_results
    get_row = scan_results_table.currentRow()
    get_row_text = []
    for n in range(0, scan_results_table.columnCount()):
        get_row_text.append(str(scan_results_table.item(get_row, n).text()))

    # Show Label
    scan_results_label =  NodeConfigure.label2_scan_results_probe
    scan_results_label.setVisible(True)

    # Disable Probe Button
    probe_button = NodeConfigure.pushButton_scan_results_probe

    # Send Message for HIPRFISR to Sensor Node Connections
    get_network_type = "IP"
    if get_network_type == "IP":
        probe_button.setEnabled(False)
        await NodeConfigure.dashboard.backend.probeHardware(get_uid, get_row_text)
    elif get_network_type == "Meshtastic":
        await NodeConfigure.dashboard.backend.probeHardwareLT(get_uid, get_row_text)


@qasync.asyncSlot(QtCore.QObject)
async def scan(NodeConfigure: QtCore.QObject):
    """
    Performs a mass hardware scan on the local/remote sensor node and returns the results.
    """
    # Save Checked Items in Current Tab
    get_node_uid = NodeConfigure.uid
    list_widget = NodeConfigure.listWidget_scan
    hardware_list = []
    for n in range(0, list_widget.count()):
        if list_widget.item(n).checkState() == QtCore.Qt.Checked:
            hardware_list.append(str(list_widget.item(n).text()))

    # Send Message for HIPRFISR to Sensor Node Connections
    get_network_type = "IP"
    if get_network_type == "IP":
        await NodeConfigure.dashboard.backend.scanHardware(get_node_uid, hardware_list)
    elif get_network_type == "Meshtastic":
        await NodeConfigure.dashboard.backend.scanHardwareLT(get_node_uid, hardware_list)


@QtCore.pyqtSlot(QtCore.QObject)
def add_to_hardware(NodeConfigure: QtCore.QObject, suppress_warning=False):
    scan_table = NodeConfigure.tableWidget_scan_results
    hw_table = NodeConfigure.tableWidget_hardware
    src_row = scan_table.currentRow()

    if src_row < 0:
        if not suppress_warning:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Select a scan result first.")
        return

    def get_scan(col):
        item = scan_table.item(src_row, col)
        return item.text().strip() if item else ""

    scan_type          = get_scan(0)
    scan_uid           = get_scan(1)
    scan_radio_name    = get_scan(2)
    scan_serial        = get_scan(3)
    scan_interface     = get_scan(4)
    scan_ip_address    = get_scan(5)
    scan_daughterboard = get_scan(6)

    category = "wifi_adapter" if "802.11x" in scan_type.lower() else "sdr"

    if scan_uid == "":
        scan_uid = get_next_hardware_uid(hw_table, category)

    dst_row = hw_table.rowCount()
    hw_table.insertRow(dst_row)

    values = [
        "No",
        category,
        scan_uid,
        scan_type,
        scan_radio_name,
        scan_serial,
        scan_interface,
        scan_ip_address,
        scan_daughterboard,
        "",
    ]

    for col, value in enumerate(values):
        item = QtWidgets.QTableWidgetItem(str(value))
        item.setTextAlignment(QtCore.Qt.AlignCenter)
        hw_table.setItem(dst_row, col, item)

    hw_table.resizeColumnsToContents()
    hw_table.resizeRowsToContents()
    hw_table.horizontalHeader().setStretchLastSection(False)
    hw_table.horizontalHeader().setStretchLastSection(True)
    hw_table.selectRow(dst_row)


def get_next_hardware_uid(hw_table, category):
    existing = []

    for row in range(hw_table.rowCount()):
        cat_item = hw_table.item(row, 1)
        uid_item = hw_table.item(row, 2)

        if not cat_item or not uid_item:
            continue

        if cat_item.text().strip() != category:
            continue

        try:
            existing.append(int(uid_item.text().strip()))
        except ValueError:
            pass

    return str(max(existing) + 1) if existing else "0"


@QtCore.pyqtSlot(QtCore.QObject)
def remove_hardware(NodeConfigure: QtCore.QObject):
    """
    Removes a row from the hardware table.
    """
    # Remove Row
    hardware_table = NodeConfigure.tableWidget_hardware
    get_row = hardware_table.currentRow()
    hardware_table.removeRow(get_row)
    if get_row == hardware_table.rowCount():
        hardware_table.setCurrentCell(hardware_table.rowCount() - 1, 0)
    elif get_row >= 0:
        hardware_table.setCurrentCell(get_row, 0)


@QtCore.pyqtSlot(QtCore.QObject)
def add_selected(NodeConfigure: QtCore.QObject):
    """
    Adds the selected row in the scan results table to the hardware table.
    """
    add_to_hardware(NodeConfigure, True)


@QtCore.pyqtSlot(QtCore.QObject)
def add_all(NodeConfigure: QtCore.QObject):
    """
    Adds the all the rows in the scan results table to all the tables.
    """
    scan_results_table = NodeConfigure.tableWidget_scan_results
    total_rows = scan_results_table.rowCount()

    for row in range(total_rows):
        scan_results_table.setCurrentCell(row,0)  # Set the current row to simulate selection
        add_to_hardware(NodeConfigure, True)


@QtCore.pyqtSlot(QtCore.QObject)
def scan_results_remove(NodeConfigure: QtCore.QObject):
    """
    Removes a row from the scan results table.
    """
    # Retrieve widgets
    get_tableWidget = NodeConfigure.tableWidget_scan_results

    # Remove the selected row
    get_row = get_tableWidget.currentRow()
    get_tableWidget.removeRow(get_row)

    # Select a new row after deletion
    if get_tableWidget.rowCount() > 0:
        new_row = min(get_row, get_tableWidget.rowCount() - 1)  # Ensure valid row index
        get_tableWidget.setCurrentCell(new_row, 0)

    # Disable buttons if table is empty
    if get_tableWidget.rowCount() == 0:
        # Get all relevant push buttons
        get_pushButtons = [
            NodeConfigure.pushButton_add_all,
            NodeConfigure.pushButton_add_selected,
            NodeConfigure.pushButton_scan_results_remove,
            NodeConfigure.pushButton_scan_results_remove_all,
            NodeConfigure.pushButton_scan_results_probe,
            NodeConfigure.pushButton_scan_results_guess,
        ]

        for btn in get_pushButtons:
            btn.setEnabled(False)
        get_tableWidget.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def scan_results_remove_all(NodeConfigure: QtCore.QObject):
    """
    Removes all rows from the scan results table.
    """
    # Retrieve widgets
    get_tableWidget = NodeConfigure.tableWidget_scan_results

    # Get all relevant push buttons
    get_pushButtons = [
        NodeConfigure.pushButton_add_all,
        NodeConfigure.pushButton_add_selected,
        NodeConfigure.pushButton_scan_results_remove,
        NodeConfigure.pushButton_scan_results_remove_all,
        NodeConfigure.pushButton_scan_results_probe,
        NodeConfigure.pushButton_scan_results_guess,
    ]

    # Remove all rows
    get_tableWidget.setRowCount(0)

    # Disable buttons when table is empty
    for btn in get_pushButtons:
        btn.setEnabled(False)
    
    get_tableWidget.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def manual(NodeConfigure: QtCore.QObject):
    """
    Manually adds the checked hardware to the scan results table.
    """
    # Dynamically retrieve widgets based on tab index
    get_listWidget = NodeConfigure.listWidget_scan
    get_tableWidget = NodeConfigure.tableWidget_scan_results

    # Get all relevant push buttons
    get_pushButtons = [
        NodeConfigure.pushButton_add_all,
        NodeConfigure.pushButton_add_selected,
        NodeConfigure.pushButton_scan_results_remove,
        NodeConfigure.pushButton_scan_results_remove_all,
        NodeConfigure.pushButton_scan_results_probe,
        NodeConfigure.pushButton_scan_results_guess,
    ]

    # Fill Scan Results Table with Checked Items
    for n in range(get_listWidget.count()):
        if get_listWidget.item(n).checkState() == QtCore.Qt.Checked:
            rows = get_tableWidget.rowCount()
            get_tableWidget.setRowCount(rows + 1)
            table_item = QtWidgets.QTableWidgetItem(str(get_listWidget.item(n).text()))
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            get_tableWidget.setItem(rows, 0, table_item)
            
            for m in range(1, get_tableWidget.columnCount()):
                empty_table_item = QtWidgets.QTableWidgetItem("")
                empty_table_item.setTextAlignment(QtCore.Qt.AlignCenter)
                get_tableWidget.setItem(rows, m, empty_table_item)

            NodeConfigure.highlight_hardware_id(get_tableWidget, rows)

    # Update UI
    get_tableWidget.setCurrentCell(get_tableWidget.rowCount() - 1, 0)
    get_tableWidget.resizeColumnsToContents()
    get_tableWidget.resizeRowsToContents()
    get_tableWidget.horizontalHeader().setStretchLastSection(False)
    get_tableWidget.horizontalHeader().setStretchLastSection(True)

    # Enable relevant buttons if there are rows in the table
    if get_tableWidget.rowCount() > 0:
        for btn in get_pushButtons:
            btn.setEnabled(True)
        get_tableWidget.setEnabled(True)


@qasync.asyncSlot(QtCore.QObject)
async def ping(NodeConfigure: QtCore.QObject):
    """
    Send ping command to the Sensor Node IP.
    """
    # Ping IP Address
    get_ip = NodeConfigure.ip_address

    response = os.system("ping -c 1 " + get_ip)
    if response == 0:
        NodeConfigure.dashboard.logger.info(get_ip + " is up!")
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(NodeConfigure, get_ip + " is up!")
    else:
        NodeConfigure.dashboard.logger.info(get_ip + " is down!")
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(NodeConfigure, get_ip + " is down!")


@qasync.asyncSlot(QtCore.QObject)
async def apply(NodeConfigure: QtCore.QObject):
    """
    Save selected sensor node changes locally and send them to the node.
    """
    dashboard = NodeConfigure.dashboard
    node_uid = dashboard.selected_node_uid
    settings = NodeConfigure.settings
    sensor_node_settings = NodeConfigure.sensor_node_settings

    if not node_uid or settings is None:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("No sensor node selected.")
        return

    nickname = str(NodeConfigure.textEdit_nickname.toPlainText()).strip()
    location_description = str(NodeConfigure.textEdit_location.toPlainText()).strip()
    notes = str(NodeConfigure.textEdit_notes.toPlainText()).strip()

    if not nickname:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a nickname for the sensor node.")
        return

    sensor_node_settings["nickname"] = nickname
    sensor_node_settings["location_description"] = location_description
    sensor_node_settings["notes"] = notes
    sensor_node_settings["hardware"] = build_hardware_settings_from_table(NodeConfigure)

    dashboard.selected_node_settings = settings

    # Update selected node button text
    dashboard.ui.label_top_configure_node_title.setText(nickname)

    # Send updated settings to node
    await dashboard.backend.updateNodeSettings(
        node_uid=node_uid,
        settings_dict=settings,
    )

    # Update Dashboard Tabs
    dashboard.configureSelectedNodeHardware()

    NodeConfigure.accept()


def build_hardware_settings_from_table(NodeConfigure: QtCore.QObject):
    table = NodeConfigure.tableWidget_hardware

    hardware = {
        "defaults": {
            "sdr": "",
            "wifi_adapter": "",
        },
        "sdrs": {},
        "wifi_adapters": {},
    }

    def get(row, col):
        item = table.item(row, col)
        return item.text().strip() if item else ""

    for row in range(table.rowCount()):
        default = get(row, 0)
        category = get(row, 1)
        uid = get(row, 2)
        hw_type = get(row, 3)
        radio_name = get(row, 4)
        serial = get(row, 5)
        interface = get(row, 6)
        ip_address = get(row, 7)
        daughterboard = get(row, 8)
        notes = get(row, 9)

        if not uid:
            continue

        if category == "sdr":
            hardware["sdrs"][uid] = {
                "radio_name": radio_name,
                "type": hw_type,
                "serial": serial,
                "daughterboard": daughterboard,
                "ip_address": ip_address,
                "network_interface": interface,
                "notes": notes,
            }

            if default.lower() == "yes":
                hardware["defaults"]["sdr"] = uid

        elif category == "wifi_adapter":
            hardware["wifi_adapters"][uid] = {
                "radio_name": radio_name,
                "interface": interface,
                "notes": notes,
            }

            if default.lower() == "yes":
                hardware["defaults"]["wifi_adapter"] = uid

    return hardware


@qasync.asyncSlot(QtCore.QObject)
async def find(NodeConfigure: QtCore.QObject):
    """ 
    Finds the GPS location for the provided method.
    """
    # GPS Data Format
    get_format = str(NodeConfigure.comboBox_format.currentText())
    get_gps_source = str(NodeConfigure.comboBox_gps_source.currentText())
    get_network_type = "IP"
    get_uid = NodeConfigure.uid
    find_widget = NodeConfigure.pushButton_find

    # Send the Message

    # Local, Connected: IP
    if get_network_type == "IP":
        if get_gps_source == "gpsd":
            await NodeConfigure.dashboard.backend.findGPS_Coordinates(get_uid, get_gps_source, get_format)
        elif get_gps_source == "Meshtastic":
            await NodeConfigure.dashboard.backend.findGPS_Coordinates(get_uid, get_gps_source, get_format)
        elif get_gps_source == "Saved":
            await NodeConfigure.dashboard.backend.findGPS_Coordinates(get_uid, get_gps_source, get_format)
        elif get_gps_source == "Internet":
            await NodeConfigure.dashboard.backend.findGPS_Coordinates(get_uid, get_gps_source, get_format)
        else:
            return

        # Disable the Find Button
        find_widget.setEnabled(False)

    # Remote, Connected: Meshtastic
    elif get_network_type == "Meshtastic":
        # Send the Message
        if get_gps_source == "gpsd":
            await NodeConfigure.dashboard.backend.findGPS_CoordinatesLT(get_uid, get_gps_source, get_format)
        elif get_gps_source == "Meshtastic":
            await NodeConfigure.dashboard.backend.findGPS_CoordinatesLT(get_uid, get_gps_source, get_format)
        elif get_gps_source == "Saved":
            await NodeConfigure.dashboard.backend.findGPS_CoordinatesLT(get_uid, get_gps_source, get_format)
        elif get_gps_source == "Internet":
            await NodeConfigure.dashboard.backend.findGPS_CoordinatesLT(get_uid, get_gps_source, get_format)
        else:
            return

        # Disable the Find Button
        # find_widget.setEnabled(False)
    else:
        NodeConfigure.dashboard.logger.error("Sensor node not connected. Unable to retrieve GPS location.")


@QtCore.pyqtSlot(QtCore.QObject)
def map(NodeConfigure: QtCore.QObject):
    """ 
    Maps the GPS location in default KML viewer (likely Google Earth Pro).
    """
    # Gather Location
    get_location = NodeConfigure.label2_lat_lon_alt.text()
    get_format = str(NodeConfigure.comboBox_format.currentText())

    # Convert to DD if needed
    try:
        if get_format == "MGRS":
            lat, lon = fissure.utils.mgrs_to_dd(get_location)
        elif get_format == "DMS":
            lat, lon = fissure.utils.dms_to_dd(get_location)
        else:  # Already in Decimal Degrees
            parts = get_location.split(',')
            if len(parts) != 2:
                raise ValueError(f"Invalid Decimal Degrees format: {get_location}")
            
            lat = parts[0].strip()
            lon = parts[1].strip()

        NodeConfigure.dashboard.logger.debug(f"✅ Converted Coordinates: {lat}, {lon}")  # Debugging output

    except ValueError as e:
        NodeConfigure.dashboard.logger.error(f"❌ Error in coordinate conversion: {e}")
        return

    except Exception as e:
        NodeConfigure.dashboard.logger.error(f"❌ Unexpected error: {e}")
        return

    # Construct KML
    kml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
    <kml xmlns="http://www.opengis.net/kml/2.2">
      <Placemark>
        <name>GPS Location</name>
        <Point>
          <coordinates>{lon},{lat},0</coordinates>
        </Point>
      </Placemark>
    </kml>
    """

    # Create a temporary KML file in /tmp/
    with tempfile.NamedTemporaryFile(delete=False, suffix=".kml", dir="/tmp/") as temp_kml:
        temp_kml.write(kml_content.encode('utf-8'))
        temp_kml_path = temp_kml.name

    NodeConfigure.dashboard.logger.info(f"KML written to: {temp_kml_path}")

    # Open the file using xdg-open (respects user's default KML viewer)
    subprocess.run(["xdg-open", temp_kml_path], check=False)


async def _passwordless_ssh_test(target: str) -> bool:
    """Return True when the selected host accepts noninteractive SSH."""
    ssh_executable = shutil.which("ssh")
    if not ssh_executable:
        return False

    process = await asyncio.create_subprocess_exec(
        ssh_executable,
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=accept-new",
        target,
        "true",
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    return await process.wait() == 0


async def _ensure_passwordless_ssh_key(NodeConfigure: QtCore.QObject):
    """Return the local Ed25519 public key path, creating it when approved."""
    ssh_dir = os.path.expanduser("~/.ssh")
    private_key = os.path.join(ssh_dir, "id_ed25519")
    public_key = private_key + ".pub"
    ssh_keygen = shutil.which("ssh-keygen")

    if not ssh_keygen:
        raise RuntimeError("ssh-keygen was not found on the Dashboard.")

    if not os.path.exists(private_key):
        answer = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(
            NodeConfigure,
            (
                "No ~/.ssh/id_ed25519 SSH key exists on this Dashboard.\n\n"
                "Create one for passwordless Sensor Node access?\n\n"
                "The new key will not have a passphrase so FISSURE can use "
                "it noninteractively."
            ),
        )

        if answer != QtWidgets.QMessageBox.Yes:
            return None

        os.makedirs(ssh_dir, mode=0o700, exist_ok=True)
        os.chmod(ssh_dir, 0o700)

        process = await asyncio.create_subprocess_exec(
            ssh_keygen,
            "-q",
            "-t", "ed25519",
            "-N", "",
            "-f", private_key,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        _, stderr = await process.communicate()

        if process.returncode != 0:
            raise RuntimeError(
                "Could not create the SSH key:\n"
                + stderr.decode(errors="replace").strip()
            )

    if not os.path.exists(public_key):
        process = await asyncio.create_subprocess_exec(
            ssh_keygen,
            "-y",
            "-P", "",
            "-f", private_key,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        stdout, stderr = await process.communicate()

        if process.returncode != 0 or not stdout.strip():
            raise RuntimeError(
                "The SSH private key exists, but its public key is missing "
                "and could not be regenerated automatically. If the private "
                "key is passphrase-protected, restore the matching "
                "~/.ssh/id_ed25519.pub file or load/configure the key manually."
            )

        with open(public_key, "wb") as public_key_file:
            public_key_file.write(stdout.rstrip() + b"\n")

        os.chmod(public_key, 0o644)

    return public_key


async def _install_passwordless_ssh_key(
    target: str,
    public_key_path: str,
    password: str,
):
    """Install one Dashboard public key on a remote Sensor Node."""
    ssh_executable = shutil.which("ssh")
    setsid_executable = shutil.which("setsid")

    if not ssh_executable:
        raise RuntimeError("ssh was not found on the Dashboard.")
    if not setsid_executable:
        raise RuntimeError("setsid was not found on the Dashboard.")

    with open(public_key_path, "r", encoding="utf-8") as public_key_file:
        public_key = public_key_file.read().strip()

    if not public_key:
        raise RuntimeError("The local SSH public key is empty.")

    with tempfile.TemporaryDirectory(
        prefix="fissure-ssh-setup-"
    ) as auth_dir:
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

        process_env = os.environ.copy()
        process_env["SSH_ASKPASS"] = askpass_path
        process_env["FISSURE_SSH_PASSWORD_FILE"] = password_path
        process_env.pop("SSH_ASKPASS_REQUIRE", None)

        if not str(process_env.get("DISPLAY") or "").strip():
            process_env["DISPLAY"] = ":0"

        remote_command = (
            "umask 077; "
            "mkdir -p ~/.ssh; "
            "chmod 700 ~/.ssh; "
            "touch ~/.ssh/authorized_keys; "
            "chmod 600 ~/.ssh/authorized_keys; "
            'IFS= read -r fissure_key; '
            'grep -qxF "$fissure_key" ~/.ssh/authorized_keys '
            '|| printf "%s\\n" "$fissure_key" >> ~/.ssh/authorized_keys'
        )

        process = await asyncio.create_subprocess_exec(
            setsid_executable,
            "-w",
            ssh_executable,
            "-o", "PubkeyAuthentication=no",
            "-o", "PasswordAuthentication=yes",
            "-o", "PreferredAuthentications=password",
            "-o", "NumberOfPasswordPrompts=1",
            "-o", "StrictHostKeyChecking=accept-new",
            target,
            remote_command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=process_env,
        )

        stdout, stderr = await process.communicate(
            (public_key + "\n").encode("utf-8")
        )

        if process.returncode != 0:
            error_text = stderr.decode(errors="replace").strip()
            raise RuntimeError(
                "Could not install the SSH public key on the Sensor Node."
                + (f"\n\n{error_text}" if error_text else "")
            )


@qasync.asyncSlot(QtCore.QObject)
async def passwordless_ssh(NodeConfigure: QtCore.QObject):
    """Configure passwordless SSH access for the selected Sensor Node."""
    dashboard = NodeConfigure.dashboard
    button = NodeConfigure.pushButton_remote_actions_passwordless_ssh
    node_ip = str(getattr(NodeConfigure, "ip_address", "") or "").strip()
    sensor_node_settings = getattr(
        NodeConfigure,
        "sensor_node_settings",
        {},
    ) or {}

    ssh_username = str(
        sensor_node_settings.get("ssh_username", "")
        or getpass.getuser()
    ).strip()

    if not node_ip or node_ip == "ipc":
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            NodeConfigure,
            "Passwordless SSH setup is only available for remote IP Sensor Nodes.",
            width=450,
            height=160,
        )
        return

    if not ssh_username:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            NodeConfigure,
            "Could not determine the SSH username for this Sensor Node.",
            width=450,
            height=160,
        )
        return

    target = f"{ssh_username}@{node_ip}"
    button.setEnabled(False)

    try:
        dashboard.logger.info(
            f"Checking passwordless SSH access to {target}."
        )

        if await _passwordless_ssh_test(target):
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                NodeConfigure,
                f"Passwordless SSH is already configured for:\n\n{target}",
                width=450,
                height=180,
            )
            return

        public_key_path = await _ensure_passwordless_ssh_key(NodeConfigure)
        if not public_key_path:
            return

        password = await fissure.Dashboard.UI_Components.Qt5.async_input_dialog(
            NodeConfigure,
            "Sensor Node Authentication",
            f"SSH password for {target}:",
        )

        if not password:
            return

        dashboard.logger.info(
            f"Installing Dashboard SSH public key on {target}."
        )

        await _install_passwordless_ssh_key(
            target,
            public_key_path,
            password,
        )

        if await _passwordless_ssh_test(target):
            dashboard.logger.info(
                f"Passwordless SSH configured successfully for {target}."
            )

            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                NodeConfigure,
                (
                    "Passwordless SSH configured successfully.\n\n"
                    f"{target}\n\n"
                    "Remote Survey/Xpra sessions can now connect without "
                    "showing the SSH password prompt."
                ),
                width=500,
                height=220,
            )
            return

        dashboard.logger.warning(
            f"SSH public key was installed on {target}, but "
            "noninteractive authentication still failed."
        )

        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            NodeConfigure,
            (
                "The public key was installed on the Sensor Node, but "
                "passwordless SSH still failed.\n\n"
                "If ~/.ssh/id_ed25519 already existed and is protected by "
                "a passphrase, load it into ssh-agent with:\n\n"
                "ssh-add ~/.ssh/id_ed25519"
            ),
            width=520,
            height=260,
        )

    except Exception as exc:
        dashboard.logger.error(
            f"Passwordless SSH setup failed for {target}: {exc}"
        )

        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            NodeConfigure,
            f"Passwordless SSH setup failed:\n\n{exc}",
            width=520,
            height=260,
        )

    finally:
        button.setEnabled(True)
        

@qasync.asyncSlot(QtCore.QObject)
async def ip_gps_beacon_enable_disable(NodeConfigure: QtCore.QObject):
    """
    Sends a message to the HIPRFISR to enable/disable the GPS TAK beacon.
    """
    # Send Message to Backend
    await NodeConfigure.dashboard.backend.gpsBeaconEnableDisableIP(NodeConfigure.uid)


@qasync.asyncSlot(QtCore.QObject)
async def ip_reboot(NodeConfigure: QtCore.QObject):
    """
    Sends a message to the HIPRFISR to reboot the sensor node.
    """
    # Send Message to Backend
    await NodeConfigure.dashboard.backend.rebootIP(NodeConfigure.uid)


@qasync.asyncSlot(QtCore.QObject)
async def ip_uptime(NodeConfigure: QtCore.QObject):
    """
    Sends a message to the HIPRFISR to retrieve the uptime of the sensor node.
    """
    # Send Message to Backend
    await NodeConfigure.dashboard.backend.uptimeIP(NodeConfigure.uid)


@qasync.asyncSlot(QtCore.QObject)
async def ip_memory(NodeConfigure: QtCore.QObject):
    """
    Sends a message to the HIPRFISR to retrieve the memory usage of the sensor node.
    """
    # Send Message to Backend
    await NodeConfigure.dashboard.backend.memoryIP(NodeConfigure.uid)


@qasync.asyncSlot(QtCore.QObject)
async def ip_disk(NodeConfigure: QtCore.QObject):
    """
    Sends a message to the HIPRFISR to retrieve the disk usage of the sensor node.
    """
    # Send Message to Backend
    await NodeConfigure.dashboard.backend.diskIP(NodeConfigure.uid)


@qasync.asyncSlot(QtCore.QObject)
async def ip_cpu(NodeConfigure: QtCore.QObject):
    """
    Sends a message to the HIPRFISR to retrieve the CPU percentage of the sensor node.
    """
    # Send Message to Backend
    await NodeConfigure.dashboard.backend.cpuIP(NodeConfigure.uid)


@qasync.asyncSlot(QtCore.QObject)
async def ip_processes(NodeConfigure: QtCore.QObject):
    """
    Sends a message to the HIPRFISR to retrieve the processes on the sensor node.
    """
    # Send Message to Backend
    await NodeConfigure.dashboard.backend.processesIP(NodeConfigure.uid)


@qasync.asyncSlot(QtCore.QObject)
async def ip_ifconfig(NodeConfigure: QtCore.QObject):
    """
    Sends a message to the HIPRFISR to retrieve the ifconfig output on the sensor node.
    """
    # Send Message to Backend
    await NodeConfigure.dashboard.backend.ifconfigIP(NodeConfigure.uid)  


@qasync.asyncSlot(QtCore.QObject)
async def ip_iwconfig(NodeConfigure: QtCore.QObject):
    """
    Sends a message to the HIPRFISR to retrieve the iwconfig output on the sensor node.
    """
    # Send Message to Backend
    await NodeConfigure.dashboard.backend.iwconfigIP(NodeConfigure.uid)  


@qasync.asyncSlot(QtCore.QObject)
async def ip_ping(NodeConfigure: QtCore.QObject):
    """
    Send command to HiprFisr to ping the host running the Sensor Node and await response.
    """
    # Send Message to Backend
    await NodeConfigure.dashboard.backend.pingIP(NodeConfigure.uid)


# @QtCore.pyqtSlot(QtCore.QObject)
# def meshtastic_refresh(NodeConfigure: QtCore.QObject):
#     """ 
#     Refreshes the list of potential serial ports in the combobox.
#     """
#     # Move Page to the Right
#     tab_index = NodeConfigure.tabWidget_nodes.currentIndex()
#     serial_port_widget = getattr(NodeConfigure, f"comboBox_meshtastic_port_{tab_index+1}")

#     # ports = [port.device for port in serial.tools.list_ports.comports()]

#     # Only include /dev/ttyACM* and /dev/ttyUSB*
#     ports = [
#         port.device 
#         for port in serial.tools.list_ports.comports() 
#         if '/dev/ttyACM' in port.device or '/dev/ttyUSB' in port.device
#     ]
#     ports.sort(key=lambda s: [int(t) if t.isdigit() else t.lower() for t in re.split(r'(\d+)', s)])

#     serial_port_widget.clear()
#     serial_port_widget.addItems(ports if ports else ["No ports found"])


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_info(NodeConfigure: QtCore.QObject):
#     """ 
#     Opens a pop up with serial port and device information.
#     """
#     # Issue the Command
#     path = "/dev/serial/by-id/"
#     if os.path.exists(path):
#         output_text = os.popen(f"ls -l {path}").read()
#     else:
#         output_text = "No serial devices found"

#     # Open a Dialog
#     ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(NodeConfigure, output_text)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_recall_info(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to retrieve sensor node information from its config file.
#     """
#     # Send Message to Backend
#     tab_index = NodeConfigure.tabWidget_nodes.currentIndex()
#     await NodeConfigure.dashboard.backend.recallInfoMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_recall_hardware(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to retrieve sensor node information from its config file.
#     """
#     # Send Message to Backend
#     tab_index = NodeConfigure.tabWidget_nodes.currentIndex()
#     await NodeConfigure.dashboard.backend.recallHardwareMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_recall_status(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to retrieve sensor node status.
#     """
#     # Send Message to Backend
#     tab_index = NodeConfigure.tabWidget_nodes.currentIndex()
#     await NodeConfigure.dashboard.backend.recallStatusMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_gps_beacon_enable(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to enable the GPS TAK beacon.
#     """
#     # Send Message to Backend
#     tab_index = NodeConfigure.tabWidget_nodes.currentIndex()
#     await NodeConfigure.dashboard.backend.gpsBeaconEnableMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_gps_beacon_disable(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to disable the GPS TAK beacon.
#     """
#     # Send Message to Backend
#     tab_index = NodeConfigure.tabWidget_nodes.currentIndex()
#     await NodeConfigure.dashboard.backend.gpsBeaconDisableMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_reboot(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to reboot the sensor node.
#     """
#     # Send Message to Backend
#     await NodeConfigure.dashboard.backend.rebootMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_uptime(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to retrieve the uptime of the sensor node.
#     """
#     # Send Message to Backend
#     await NodeConfigure.dashboard.backend.uptimeMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_memory(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to retrieve the memory usage of the sensor node.
#     """
#     # Send Message to Backend
#     await NodeConfigure.dashboard.backend.memoryMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_disk(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to retrieve the disk usage of the sensor node.
#     """
#     # Send Message to Backend
#     await NodeConfigure.dashboard.backend.diskMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_cpu(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to retrieve the CPU percentage of the sensor node.
#     """
#     # Send Message to Backend
#     await NodeConfigure.dashboard.backend.cpuMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_processes(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to retrieve the processes on the sensor node.
#     """
#     # Send Message to Backend
#     await NodeConfigure.dashboard.backend.processesMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_ifconfig(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to retrieve the ifconfig output on the sensor node.
#     """
#     # Send Message to Backend
#     await NodeConfigure.dashboard.backend.ifconfigMeshtasticLT(NodeConfigure.uid)


# @qasync.asyncSlot(QtCore.QObject)
# async def meshtastic_iwconfig(NodeConfigure: QtCore.QObject):
#     """
#     Sends a message to the HIPRFISR to retrieve the iwconfig output on the sensor node.
#     """
#     # Send Message to Backend
#     await NodeConfigure.dashboard.backend.iwconfigMeshtasticLT(NodeConfigure.uid)