from ..Slots import NodeConfigureSlots
from .UI_Types import UI_Types
from PyQt5 import QtCore, QtWidgets, QtGui

import fissure.comms
import os
import time
import yaml


class NodeConfigureDialog(QtWidgets.QDialog, UI_Types.Node_Configure):
    tabWidget: QtWidgets.QTabWidget
    guess_index: int

    def __init__(self, parent: QtWidgets.QWidget, dashboard: QtCore.QObject):
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.dashboard = dashboard
        self.setupUi(self)
        self.guess_index = 0
        #dashboard.logger.critical(f"HWSelect clicked (node_idx = {node_idx})")

        # Prevent Resizing/Maximizing
        self.parent.setFixedSize(QtCore.QSize(1100, 850))

        # Connect Signals to Slots
        self.__connect_slots__()

        # Node UUID
        self.uid = getattr(self.dashboard, "selected_node_uid", "")
        self.label2_uuid.setText(self.uid)

        # Node IP Address
        self.ip_address = getattr(self.dashboard, "selected_node_ip", "")
        self.label2_ip_address.setText(self.ip_address)


        # ------------------------------------------------------------------
        # Populate widgets from selected sensor node settings
        # ------------------------------------------------------------------
        settings_dict = getattr(self.dashboard, "selected_node_settings", {}) or {}

        self.settings = settings_dict
        self.sensor_node_settings = settings_dict.get("Sensor Node", settings_dict)

        # Hide Temporary Text
        self.label2_scan_results_probe.setVisible(False)

        # Basic node settings
        self.textEdit_nickname.setPlainText(str(self.sensor_node_settings.get("nickname", "")))
        self.textEdit_location.setPlainText(str(self.sensor_node_settings.get("location_description", "")))
        self.textEdit_notes.setPlainText(str(self.sensor_node_settings.get("notes", "")))
        # self.textEdit_msg_port.setPlainText(str(self.sensor_node_settings.get("msg_port", "")))
        # self.textEdit_hb_port.setPlainText(str(self.sensor_node_settings.get("hb_port", "")))

        # Read-only/display values
        self.label2_autorun_value.setText(str(self.sensor_node_settings.get("autorun", "")))
        self.label2_autorun_delay_value.setText(str(self.sensor_node_settings.get("autorun_delay_seconds", "")))
        self.label2_console_logging_level_value.setText(str(self.sensor_node_settings.get("console_logging_level", "")))
        self.label2_file_logging_level_value.setText(str(self.sensor_node_settings.get("file_logging_level", "")))

        # GPS TAK Beacon Button
        get_gps_tak_beacon = self.sensor_node_settings.get("gps", {}).get("gps_tak_beacon", False)
        if get_gps_tak_beacon:
            self.pushButton_remote_actions_ip_gps_beacon_enable_disable.setText("Disable")
        else:
            self.pushButton_remote_actions_ip_gps_beacon_enable_disable.setText("Enable")

        # ------------------------------------------------------------------
        # Populate hardware table from selected sensor node settings
        # ------------------------------------------------------------------
        hardware_settings = self.sensor_node_settings.get("hardware", {}) or {}
        hardware_defaults = hardware_settings.get("defaults", {}) or {}
        sdrs = hardware_settings.get("sdrs", {}) or {}
        wifi_adapters = hardware_settings.get("wifi_adapters", {}) or {}

        self.tableWidget_hardware.setColumnCount(10)
        self.tableWidget_hardware.setHorizontalHeaderLabels([
            "Default",
            "Category",
            "UID",
            "Type",
            "Radio Name",
            "Serial",
            "Net. Interface",
            "IP Address",
            "Daughterboard",
            "Notes",
        ])

        self.tableWidget_hardware.setRowCount(0)

        def set_hardware_item(row, col, value, tooltip=None):
            item = QtWidgets.QTableWidgetItem(str(value))
            item.setTextAlignment(QtCore.Qt.AlignCenter)

            if tooltip:
                item.setToolTip(tooltip)

            self.tableWidget_hardware.setItem(row, col, item)

        # SDR rows
        for uid, sdr in sdrs.items():
            row = self.tableWidget_hardware.rowCount()
            self.tableWidget_hardware.insertRow(row)

            is_default = str(hardware_defaults.get("sdr", "")) == str(uid)

            values = [
                "Yes" if is_default else "No",
                "sdr",
                str(uid),
                str(sdr.get("type", "")),
                str(sdr.get("radio_name", "")),
                str(sdr.get("serial", "")),
                str(sdr.get("network_interface", "")),
                str(sdr.get("ip_address", "")),
                str(sdr.get("daughterboard", "")),
                str(sdr.get("notes", "")),
            ]

            tooltip = "Default SDR" if is_default else None

            for col, value in enumerate(values):
                set_hardware_item(row, col, value, tooltip)

        # Wi-Fi adapter rows
        for uid, wifi_adapter in wifi_adapters.items():
            row = self.tableWidget_hardware.rowCount()
            self.tableWidget_hardware.insertRow(row)

            is_default = str(hardware_defaults.get("wifi_adapter", "")) == str(uid)

            values = [
                "Yes" if is_default else "No",
                "wifi_adapter",
                str(uid),
                "802.11x Adapter",
                str(wifi_adapter.get("radio_name", "")),
                "",
                str(wifi_adapter.get("interface", "")),
                "",
                "",
                str(wifi_adapter.get("notes", "")),
            ]

            tooltip = "Default Wi-Fi Adapter" if is_default else None

            for col, value in enumerate(values):
                set_hardware_item(row, col, value, tooltip)

        self.tableWidget_hardware.resizeColumnsToContents()
        self.tableWidget_hardware.resizeRowsToContents()
        self.tableWidget_hardware.horizontalHeader().setStretchLastSection(False)
        self.tableWidget_hardware.horizontalHeader().setStretchLastSection(True)


    def __connect_slots__(self):
        """
        Contains the connect functions for all the signals and slots
        """
        self.pushButton_find.clicked.connect(lambda: NodeConfigureSlots.find(self))      
        self.pushButton_map.clicked.connect(lambda: NodeConfigureSlots.map(self))      
        self.pushButton_scan.clicked.connect(lambda: NodeConfigureSlots.scan(self))      
        self.pushButton_manual.clicked.connect(lambda: NodeConfigureSlots.manual(self))      
        self.pushButton_scan_results_remove.clicked.connect(lambda: NodeConfigureSlots.scan_results_remove(self))      
        self.pushButton_scan_results_remove_all.clicked.connect(lambda: NodeConfigureSlots.scan_results_remove_all(self))      
        self.pushButton_scan_results_guess.clicked.connect(lambda: NodeConfigureSlots.guess(self))      
        self.pushButton_scan_results_probe.clicked.connect(lambda: NodeConfigureSlots.probe(self))      
        self.pushButton_add_selected.clicked.connect(lambda: NodeConfigureSlots.add_selected(self))      
        self.pushButton_add_all.clicked.connect(lambda: NodeConfigureSlots.add_all(self))      
        self.pushButton_hardware_remove.clicked.connect(lambda: NodeConfigureSlots.remove_hardware(self))      
        self.pushButton_remote_actions_ip_ping.clicked.connect(lambda: NodeConfigureSlots.ping(self))
        self.pushButton_remote_actions_passwordless_ssh.clicked.connect(lambda: NodeConfigureSlots.passwordless_ssh(self))
        self.pushButton_remote_actions_ip_gps_beacon_enable_disable.clicked.connect(lambda: NodeConfigureSlots.ip_gps_beacon_enable_disable(self))
        self.pushButton_remote_actions_ip_reboot.clicked.connect(lambda: NodeConfigureSlots.ip_reboot(self))
        self.pushButton_remote_actions_ip_uptime.clicked.connect(lambda: NodeConfigureSlots.ip_uptime(self))
        self.pushButton_remote_actions_ip_memory.clicked.connect(lambda: NodeConfigureSlots.ip_memory(self))
        self.pushButton_remote_actions_ip_disk.clicked.connect(lambda: NodeConfigureSlots.ip_disk(self))
        self.pushButton_remote_actions_ip_cpu.clicked.connect(lambda: NodeConfigureSlots.ip_cpu(self))
        self.pushButton_remote_actions_ip_processes.clicked.connect(lambda: NodeConfigureSlots.ip_processes(self))
        self.pushButton_remote_actions_ip_ifconfig.clicked.connect(lambda: NodeConfigureSlots.ip_ifconfig(self))
        self.pushButton_remote_actions_ip_iwconfig.clicked.connect(lambda: NodeConfigureSlots.ip_iwconfig(self))

        self.pushButton_apply.clicked.connect(lambda: NodeConfigureSlots.apply(self))
        self.pushButton_cancel.clicked.connect(self.close)


    def scanReturn(self, all_scan_results):
        """
        Populates the scan results table with the results of the hardware scan.
        """

        # Dynamically retrieve widgets based on tab index
        get_tableWidget = self.tableWidget_scan_results
        get_tableWidget_scan_results = get_tableWidget  # Alias for clarity

        # Get all relevant push buttons
        get_pushButtons = [
            self.pushButton_add_all,
            self.pushButton_add_selected,
            self.pushButton_scan_results_remove,
            self.pushButton_scan_results_remove_all,
            self.pushButton_scan_results_probe,
            self.pushButton_scan_results_guess,
        ]

        # Add to Scan Results Table
        for row_data in all_scan_results:
            rows = get_tableWidget.rowCount()
            get_tableWidget.setRowCount(rows + 1)
            for col, cell_value in enumerate(row_data):
                table_item = QtWidgets.QTableWidgetItem(cell_value)
                table_item.setTextAlignment(QtCore.Qt.AlignCenter)
                get_tableWidget.setItem(rows, col, table_item)
            self.highlight_hardware_id(get_tableWidget, rows)

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
            get_tableWidget_scan_results.setEnabled(True)


    def guessReturn(self, get_row, get_hardware, get_row_text, get_guess_index):
        """
        Populates the scan results table with the results of the hardware scan.
        """
        # Update Guess Index
        self.guess_index = get_guess_index

        # Fill Cells by Hardware
        scan_results_table = self.tableWidget_scan_results

        if get_hardware == "USRP X3x0":
            pass

        elif get_hardware == "USRP B2x0":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item)

        elif get_hardware == "USRP B20xmini":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item)

        elif get_hardware == "bladeRF":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item)

        elif get_hardware == "LimeSDR":
            pass

        elif get_hardware == "HackRF":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item)

        elif get_hardware == "PlutoSDR":
            pass

        elif get_hardware == "USRP2":
            # Update Serial, IP Address, Daughterboard
            new_serial = str(get_row_text[3])
            table_item1 = QtWidgets.QTableWidgetItem(new_serial)
            table_item1.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item1)

            new_ip = str(get_row_text[5])
            table_item2 = QtWidgets.QTableWidgetItem(new_ip)
            table_item2.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 5, table_item2)

            new_daughterboard = str(get_row_text[6])
            table_item3 = QtWidgets.QTableWidgetItem(new_daughterboard)
            table_item3.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 6, table_item3)

        elif get_hardware == "USRP N2xx":
            # Update Serial, IP Address, Daughterboard
            new_serial = str(get_row_text[3])
            table_item1 = QtWidgets.QTableWidgetItem(new_serial)
            table_item1.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item1)

            new_ip = str(get_row_text[5])
            table_item2 = QtWidgets.QTableWidgetItem(new_ip)
            table_item2.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 5, table_item2)

            new_daughterboard = str(get_row_text[6])
            table_item3 = QtWidgets.QTableWidgetItem(new_daughterboard)
            table_item3.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 6, table_item3)

        elif get_hardware == "bladeRF 2.0":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item)

        elif get_hardware == "USRP X410":
            # Update Serial, IP Address, Daughterboard
            new_serial = str(get_row_text[3])
            table_item1 = QtWidgets.QTableWidgetItem(new_serial)
            table_item1.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item1)

            new_ip = str(get_row_text[5])
            table_item2 = QtWidgets.QTableWidgetItem(new_ip)
            table_item2.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 5, table_item2)

            new_daughterboard = str(get_row_text[6])
            table_item3 = QtWidgets.QTableWidgetItem(new_daughterboard)
            table_item3.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 6, table_item3)

        elif get_hardware == "802.11x Adapter":
            new_network_interface = str(get_row_text[4])
            table_item = QtWidgets.QTableWidgetItem(new_network_interface)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 4, table_item)

        elif get_hardware == "RTL2832U":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item)

        elif get_hardware == "RSPduo":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item)

        elif get_hardware == "RSPdx":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item)
            
        elif get_hardware == "RSPdx R2":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 3, table_item)

        elif get_hardware == "CaribouLite":
            new_uuid = str(get_row_text[1])
            table_item = QtWidgets.QTableWidgetItem(new_uuid)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_table.setItem(get_row, 1, table_item)            

        # Highlight
        self.highlight_hardware_id(scan_results_table, get_row)
            
        # Resize the Scan Results Table
        scan_results_table.resizeColumnsToContents()
        scan_results_table.resizeRowsToContents()
        scan_results_table.horizontalHeader().setStretchLastSection(False)
        scan_results_table.horizontalHeader().setStretchLastSection(True)


    def highlight_hardware_id(self, table_widget, row):
        """
        Highlights the hardware ID cell used when selecting hardware throughout FISSURE.
        """
        # Get Hardware
        get_hardware = str(table_widget.item(row, 0).text())

        # Retrieve Hardware ID Field
        get_column = fissure.utils.hardware.hardwareID_Column(get_hardware)

        # Highlight the Cell
        if get_column:
            cell_item = table_widget.item(row, get_column)
            cell_item.setBackground(QtGui.QColor("yellow"))





