from ..Slots import HardwareSelectSlots
from .UI_Types import UI_Types
from PyQt5 import QtCore, QtWidgets

import fissure.comms
import os
import time
import yaml


class HardwareSelectDialog(QtWidgets.QDialog, UI_Types.HW_Select):
    tabWidget: QtWidgets.QTabWidget
    guess_index: int

    def __init__(self, parent: QtWidgets.QWidget, dashboard: QtCore.QObject, node_idx: int = None):
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

        # Disable Unused Tabs
        self.tabWidget_nodes.setTabEnabled(0, False)
        self.tabWidget_nodes.setTabEnabled(1, False)  # No function to hide tab visibility in PyQt4
        self.tabWidget_nodes.setTabEnabled(2, False)
        self.tabWidget_nodes.setTabEnabled(3, False)
        self.tabWidget_nodes.setTabEnabled(4, False)

        # Enable Tabs for Configured Nodes
        get_sensor_node = ["sensor_node1", "sensor_node2", "sensor_node3", "sensor_node4", "sensor_node5"]
        for n in range(0, len(get_sensor_node)):
            if self.dashboard.backend.settings[get_sensor_node[n]]["nickname"] != "":
                self.tabWidget_nodes.setTabEnabled(n, True)
            if n == node_idx:
                self.tabWidget_nodes.setTabEnabled(n, True)

        # Change Tab
        self.tabWidget_nodes.setCurrentIndex(node_idx)
        self.tabWidget_nodes.setTabEnabled((node_idx), True)

        # Support Only One Local Sensor Node
        local_assigned = False
        for n in range(0, 5):
            if str(self.dashboard.backend.settings[get_sensor_node[n]]["local_remote"]) == "local":
                local_assigned = True

        # Hide Temporary Text
        self.label2_scan_results_probe_1.setVisible(False)
        self.label2_scan_results_probe_2.setVisible(False)
        self.label2_scan_results_probe_3.setVisible(False)
        self.label2_scan_results_probe_4.setVisible(False)
        self.label2_scan_results_probe_5.setVisible(False)

        # Recall Saved Settings
        nickname_widgets = [
            self.textEdit_nickname_1,
            self.textEdit_nickname_2,
            self.textEdit_nickname_3,
            self.textEdit_nickname_4,
            self.textEdit_nickname_5,
        ]
        location_widgets = [
            self.textEdit_location_1,
            self.textEdit_location_2,
            self.textEdit_location_3,
            self.textEdit_location_4,
            self.textEdit_location_5,
        ]
        notes_widgets = [
            self.textEdit_notes_1,
            self.textEdit_notes_2,
            self.textEdit_notes_3,
            self.textEdit_notes_4,
            self.textEdit_notes_5,
        ]
        ip_widgets = [
            self.textEdit_ip_addr_1, 
            self.textEdit_ip_addr_2, 
            self.textEdit_ip_addr_3, 
            self.textEdit_ip_addr_4, 
            self.textEdit_ip_addr_5
        ]
        msg_port_widgets = [
            self.textEdit_msg_port_1,
            self.textEdit_msg_port_2,
            self.textEdit_msg_port_3,
            self.textEdit_msg_port_4,
            self.textEdit_msg_port_5,
        ]
        hb_port_widgets = [
            self.textEdit_hb_port_1,
            self.textEdit_hb_port_2,
            self.textEdit_hb_port_3,
            self.textEdit_hb_port_4,
            self.textEdit_hb_port_5,
        ]
        local_widgets = [
            self.radioButton_local_1,
            self.radioButton_local_2,
            self.radioButton_local_3,
            self.radioButton_local_4,
            self.radioButton_local_5,
        ]
        remote_widgets = [
            self.radioButton_remote_1,
            self.radioButton_remote_2,
            self.radioButton_remote_3,
            self.radioButton_remote_4,
            self.radioButton_remote_5,
        ]
        hardware_tsi_widgets = [
            self.tableWidget_tsi_1,
            self.tableWidget_tsi_2,
            self.tableWidget_tsi_3,
            self.tableWidget_tsi_4,
            self.tableWidget_tsi_5,
        ]
        hardware_pd_widgets = [
            self.tableWidget_pd_1,
            self.tableWidget_pd_2,
            self.tableWidget_pd_3,
            self.tableWidget_pd_4,
            self.tableWidget_pd_5,
        ]
        hardware_attack_widgets = [
            self.tableWidget_attack_1,
            self.tableWidget_attack_2,
            self.tableWidget_attack_3,
            self.tableWidget_attack_4,
            self.tableWidget_attack_5,
        ]
        hardware_iq_widgets = [
            self.tableWidget_iq_1,
            self.tableWidget_iq_2,
            self.tableWidget_iq_3,
            self.tableWidget_iq_4,
            self.tableWidget_iq_5,
        ]
        hardware_archive_widgets = [
            self.tableWidget_archive_1,
            self.tableWidget_archive_2,
            self.tableWidget_archive_3,
            self.tableWidget_archive_4,
            self.tableWidget_archive_5,
        ]
        autorun_widgets = [
            self.label2_autorun_value_1,
            self.label2_autorun_value_2,
            self.label2_autorun_value_3,
            self.label2_autorun_value_4,
            self.label2_autorun_value_5,
        ]
        autorun_delay_widgets = [
            self.label2_autorun_delay_value_1,
            self.label2_autorun_delay_value_2,
            self.label2_autorun_delay_value_3,
            self.label2_autorun_delay_value_4,
            self.label2_autorun_delay_value_5,
        ]
        console_logging_level_widgets = [
            self.label2_console_logging_level_value_1,
            self.label2_console_logging_level_value_2,
            self.label2_console_logging_level_value_3,
            self.label2_console_logging_level_value_4,
            self.label2_console_logging_level_value_5
        ]
        file_logging_level_widgets = [
            self.label2_file_logging_level_value_1,
            self.label2_file_logging_level_value_2,
            self.label2_file_logging_level_value_3,
            self.label2_file_logging_level_value_4,
            self.label2_file_logging_level_value_5
        ]

        for n in range(0, len(get_sensor_node)):
            if self.dashboard.backend.settings[get_sensor_node[n]]["nickname"] != "":
                self.tabWidget_nodes.setTabText(n, str(self.dashboard.backend.settings[get_sensor_node[n]]["nickname"]))
                if str(self.dashboard.backend.settings[get_sensor_node[n]]["local_remote"]).lower() == "local":
                    HardwareSelectSlots.local(self, tab_index=n)
                else:
                    if local_assigned:
                        local_widgets[n].setEnabled(False)
                    remote_widgets[n].setChecked(True)
                    HardwareSelectSlots.remote(self, tab_index=n)
                nickname_widgets[n].setPlainText(str(self.dashboard.backend.settings[get_sensor_node[n]]["nickname"]))
                location_widgets[n].setPlainText(str(self.dashboard.backend.settings[get_sensor_node[n]]["location"]))
                notes_widgets[n].setPlainText(str(self.dashboard.backend.settings[get_sensor_node[n]]["notes"]))
                ip_widgets[n].setPlainText(str(self.dashboard.backend.settings[get_sensor_node[n]]["ip_address"]))
                msg_port_widgets[n].setPlainText(str(self.dashboard.backend.settings[get_sensor_node[n]]["msg_port"]))
                hb_port_widgets[n].setPlainText(str(self.dashboard.backend.settings[get_sensor_node[n]]["hb_port"]))
                autorun_widgets[n].setText(str(self.dashboard.backend.settings[get_sensor_node[n]]["autorun"]))
                autorun_delay_widgets[n].setText(str(self.dashboard.backend.settings[get_sensor_node[n]]["autorun_delay_seconds"]))
                console_logging_level_widgets[n].setText(str(self.dashboard.backend.settings[get_sensor_node[n]]['console_logging_level']))
                file_logging_level_widgets[n].setText(str(self.dashboard.backend.settings[get_sensor_node[n]]['file_logging_level']))

                # TSI Table
                tsi_hardware = self.dashboard.backend.settings[get_sensor_node[n]]["tsi"]
                for row in range(0, len(tsi_hardware)):
                    get_row = tsi_hardware[row]
                    hardware_tsi_widgets[n].setRowCount(hardware_tsi_widgets[n].rowCount() + 1)
                    for c in range(0, len(get_row)):
                        get_text = get_row[c]
                        new_item = QtWidgets.QTableWidgetItem(get_text)
                        new_item.setTextAlignment(QtCore.Qt.AlignCenter)
                        hardware_tsi_widgets[n].setItem(hardware_tsi_widgets[n].rowCount() - 1, c, new_item)

                # PD Table
                pd_hardware = self.dashboard.backend.settings[get_sensor_node[n]]["pd"]
                for row in range(0, len(pd_hardware)):
                    get_row = pd_hardware[row]
                    hardware_pd_widgets[n].setRowCount(hardware_pd_widgets[n].rowCount() + 1)
                    for c in range(0, len(get_row)):
                        get_text = get_row[c]
                        new_item = QtWidgets.QTableWidgetItem(get_text)
                        new_item.setTextAlignment(QtCore.Qt.AlignCenter)
                        hardware_pd_widgets[n].setItem(hardware_pd_widgets[n].rowCount() - 1, c, new_item)

                # Attack Table
                attack_hardware = self.dashboard.backend.settings[get_sensor_node[n]]["attack"]
                for row in range(0, len(attack_hardware)):
                    get_row = attack_hardware[row]
                    hardware_attack_widgets[n].setRowCount(hardware_attack_widgets[n].rowCount() + 1)
                    for c in range(0, len(get_row)):
                        get_text = get_row[c]
                        new_item = QtWidgets.QTableWidgetItem(get_text)
                        new_item.setTextAlignment(QtCore.Qt.AlignCenter)
                        hardware_attack_widgets[n].setItem(hardware_attack_widgets[n].rowCount() - 1, c, new_item)

                # IQ Table
                iq_hardware = self.dashboard.backend.settings[get_sensor_node[n]]["iq"]
                for row in range(0, len(iq_hardware)):
                    get_row = iq_hardware[row]
                    hardware_iq_widgets[n].setRowCount(hardware_iq_widgets[n].rowCount() + 1)
                    for c in range(0, len(get_row)):
                        get_text = get_row[c]
                        new_item = QtWidgets.QTableWidgetItem(get_text)
                        new_item.setTextAlignment(QtCore.Qt.AlignCenter)
                        hardware_iq_widgets[n].setItem(hardware_iq_widgets[n].rowCount() - 1, c, new_item)

                # Archive Table
                archive_hardware = self.dashboard.backend.settings[get_sensor_node[n]]["archive"]
                for row in range(0, len(archive_hardware)):
                    get_row = archive_hardware[row]
                    hardware_archive_widgets[n].setRowCount(hardware_archive_widgets[n].rowCount() + 1)
                    for c in range(0, len(get_row)):
                        get_text = get_row[c]
                        new_item = QtWidgets.QTableWidgetItem(get_text)
                        new_item.setTextAlignment(QtCore.Qt.AlignCenter)
                        hardware_archive_widgets[n].setItem(hardware_archive_widgets[n].rowCount() - 1, c, new_item)

                # Resize the Tables
                hardware_tsi_widgets[n].resizeColumnsToContents()
                hardware_tsi_widgets[n].resizeRowsToContents()
                hardware_tsi_widgets[n].horizontalHeader().setStretchLastSection(False)
                hardware_tsi_widgets[n].horizontalHeader().setStretchLastSection(True)
                hardware_pd_widgets[n].resizeColumnsToContents()
                hardware_pd_widgets[n].resizeRowsToContents()
                hardware_pd_widgets[n].horizontalHeader().setStretchLastSection(False)
                hardware_pd_widgets[n].horizontalHeader().setStretchLastSection(True)
                hardware_attack_widgets[n].resizeColumnsToContents()
                hardware_attack_widgets[n].resizeRowsToContents()
                hardware_attack_widgets[n].horizontalHeader().setStretchLastSection(False)
                hardware_attack_widgets[n].horizontalHeader().setStretchLastSection(True)
                hardware_iq_widgets[n].resizeColumnsToContents()
                hardware_iq_widgets[n].resizeRowsToContents()
                hardware_iq_widgets[n].horizontalHeader().setStretchLastSection(False)
                hardware_iq_widgets[n].horizontalHeader().setStretchLastSection(True)
                hardware_archive_widgets[n].resizeColumnsToContents()
                hardware_archive_widgets[n].resizeRowsToContents()
                hardware_archive_widgets[n].horizontalHeader().setStretchLastSection(False)
                hardware_archive_widgets[n].horizontalHeader().setStretchLastSection(True)

            # Nothing Saved, First Time
            else:
                # Update Tab Text
                if n == self.tabWidget_nodes.currentIndex():
                    self.tabWidget_nodes.setTabText(n, "Node " + str(n + 1))
                
                # Check Local or Remote
                if (
                    (str(self.dashboard.backend.settings[get_sensor_node[n]]["local_remote"]).lower() == "local"
                    or str(self.dashboard.backend.settings[get_sensor_node[n]]["local_remote"]).lower() == "")
                    and (local_assigned == False)
                ):
                    local_widgets[n].setChecked(True)
                    # HardwareSelectSlots.local(self, tab_index=n)
                else:
                    remote_widgets[n].setChecked(True)
                    # HardwareSelectSlots.remote(self, tab_index=n)

        # Update if Connected
        if "OK" in self.dashboard.statusBar().sensor_nodes[0].text():
            self.sensorNodeConnected(0)
        else:
            self.sensorNodeDisconnected(0)
        if "OK" in self.dashboard.statusBar().sensor_nodes[1].text():
            self.sensorNodeConnected(1)
        else:
            self.sensorNodeDisconnected(1)
        if "OK" in self.dashboard.statusBar().sensor_nodes[2].text():
            self.sensorNodeConnected(2)
        else:
            self.sensorNodeDisconnected(2)
        if "OK" in self.dashboard.statusBar().sensor_nodes[3].text():
            self.sensorNodeConnected(3)
        else:
            self.sensorNodeDisconnected(3)
        if "OK" in self.dashboard.statusBar().sensor_nodes[4].text():
            self.sensorNodeConnected(4)
        else:
            self.sensorNodeDisconnected(4)

    def __connect_slots__(self):
        """
        Contains the connect functions for all the signals and slots
        """
        # Node Slots
        for node_idx in range(1, 6):
            # Connect slots for each node
            local_button: QtWidgets.QPushButton = getattr(self, f"radioButton_local_{node_idx}")
            remote_button: QtWidgets.QPushButton = getattr(self, f"radioButton_remote_{node_idx}")
            launch_button: QtWidgets.QPushButton = getattr(self, f'pushButton_launch_{node_idx}')
            ping_button: QtWidgets.QPushButton = getattr(self, f"pushButton_ping_{node_idx}")
            connect_button: QtWidgets.QPushButton = getattr(self, f"pushButton_connect_{node_idx}")
            disconnect_button: QtWidgets.QPushButton = getattr(self, f"pushButton_disconnect_{node_idx}")
            more_a_button: QtWidgets.QPushButton = getattr(self, f"pushButton_more_a_{node_idx}")
            more_b_button: QtWidgets.QPushButton = getattr(self, f"pushButton_more_b_{node_idx}")
            manual_button: QtWidgets.QPushButton = getattr(self, f"pushButton_manual_{node_idx}")
            scan_results_remove_button: QtWidgets.QPushButton = getattr(self, f"pushButton_scan_results_remove_{node_idx}")
            add_to_all_button: QtWidgets.QPushButton = getattr(self, f"pushButton_add_to_all_{node_idx}")
            tsi_button: QtWidgets.QPushButton = getattr(self, f"pushButton_tsi_{node_idx}")
            pd_button: QtWidgets.QPushButton = getattr(self, f"pushButton_pd_{node_idx}")
            attack_button: QtWidgets.QPushButton = getattr(self, f"pushButton_attack_{node_idx}")
            iq_button: QtWidgets.QPushButton = getattr(self, f"pushButton_iq_{node_idx}")
            archive_button: QtWidgets.QPushButton = getattr(self, f"pushButton_archive_{node_idx}")
            remove_tsi_button: QtWidgets.QPushButton = getattr(self, f"pushButton_remove_tsi_{node_idx}")
            remove_pd_button: QtWidgets.QPushButton = getattr(self, f"pushButton_remove_pd_{node_idx}")
            remove_attack_button: QtWidgets.QPushButton = getattr(self, f"pushButton_remove_attack_{node_idx}")
            remove_iq_button: QtWidgets.QPushButton = getattr(self, f"pushButton_remove_iq_{node_idx}")
            remove_archive_button: QtWidgets.QPushButton = getattr(self, f"pushButton_remove_archive_{node_idx}")
            remove_all_button: QtWidgets.QPushButton = getattr(self, f"pushButton_remove_all_{node_idx}")
            scan_button: QtWidgets.QPushButton = getattr(self, f"pushButton_scan_{node_idx}")
            probe_button: QtWidgets.QPushButton = getattr(self, f"pushButton_scan_results_probe_{node_idx}")
            guess_button: QtWidgets.QPushButton = getattr(self, f"pushButton_scan_results_guess_{node_idx}")

            local_button.clicked.connect(lambda _, idx=node_idx: HardwareSelectSlots.local(self, tab_index=idx - 1))
            remote_button.clicked.connect(lambda _, idx=node_idx: HardwareSelectSlots.remote(self, tab_index=idx - 1))
            launch_button.clicked.connect(lambda: HardwareSelectSlots.launch(self))
            ping_button.clicked.connect(lambda: HardwareSelectSlots.ping(self))
            connect_button.clicked.connect(lambda: HardwareSelectSlots.connect(self))
            disconnect_button.clicked.connect(lambda: HardwareSelectSlots.disconnect(self))
            more_a_button.clicked.connect(lambda: HardwareSelectSlots.more(self))
            more_b_button.clicked.connect(lambda: HardwareSelectSlots.more(self))
            manual_button.clicked.connect(lambda: HardwareSelectSlots.manual(self))
            scan_results_remove_button.clicked.connect(lambda: HardwareSelectSlots.scan_results_remove(self))
            add_to_all_button.clicked.connect(lambda: HardwareSelectSlots.add_to_all(self))
            tsi_button.clicked.connect(lambda: HardwareSelectSlots.tsi(self))
            pd_button.clicked.connect(lambda: HardwareSelectSlots.pd(self))
            attack_button.clicked.connect(lambda: HardwareSelectSlots.attack(self))
            iq_button.clicked.connect(lambda: HardwareSelectSlots.iq(self))
            archive_button.clicked.connect(lambda: HardwareSelectSlots.archive(self))
            remove_tsi_button.clicked.connect(lambda: HardwareSelectSlots.remove_tsi(self))
            remove_pd_button.clicked.connect(lambda: HardwareSelectSlots.remove_pd(self))
            remove_attack_button.clicked.connect(lambda: HardwareSelectSlots.remove_attack(self))
            remove_iq_button.clicked.connect(lambda: HardwareSelectSlots.remove_iq(self))
            remove_archive_button.clicked.connect(lambda: HardwareSelectSlots.remove_archive(self))
            remove_all_button.clicked.connect(lambda: HardwareSelectSlots.remove_all(self))
            scan_button.clicked.connect(lambda: HardwareSelectSlots.scan(self))
            probe_button.clicked.connect(lambda: HardwareSelectSlots.probe(self))
            guess_button.clicked.connect(lambda: HardwareSelectSlots.guess(self))

        # Connect general slots
        self.pushButton_import.clicked.connect(lambda: HardwareSelectSlots.importClicked(self, settings_dict=""))
        self.pushButton_export.clicked.connect(lambda: HardwareSelectSlots.export(self))
        self.pushButton_apply.clicked.connect(lambda: HardwareSelectSlots.apply(self))
        self.pushButton_cancel.clicked.connect(lambda: HardwareSelectSlots.cancel(self))
        self.pushButton_delete.clicked.connect(lambda: HardwareSelectSlots.delete(self))

    def scanReturn(self, tab_index, all_scan_results):
        """Populates the scan results table with the results of the hardware scan."""
        # Retrieve Widgets in Current Tab
        tab_index = int(tab_index)
        if tab_index == 0:
            # get_listWidget = self.listWidget_scan_1
            get_tableWidget = self.tableWidget_scan_results_1
            get_pushButton_add_to_all = self.pushButton_add_to_all_1
            get_pushButton_tsi = self.pushButton_tsi_1
            get_pushButton_pd = self.pushButton_pd_1
            get_pushButton_attack = self.pushButton_attack_1
            get_pushButton_iq = self.pushButton_iq_1
            get_pushButton_archive = self.pushButton_archive_1
            get_pushButton_scan_results_remove = self.pushButton_scan_results_remove_1
            get_pushButton_scan_results_probe = self.pushButton_scan_results_probe_1
            get_pushButton_scan_results_guess = self.pushButton_scan_results_guess_1
            get_tableWidget_scan_results = self.tableWidget_scan_results_1
            get_line3_scan_results = self.line3_scan_results_1
        elif tab_index == 1:
            # get_listWidget = self.listWidget_scan_2
            get_tableWidget = self.tableWidget_scan_results_2
            get_pushButton_add_to_all = self.pushButton_add_to_all_2
            get_pushButton_tsi = self.pushButton_tsi_2
            get_pushButton_pd = self.pushButton_pd_2
            get_pushButton_attack = self.pushButton_attack_2
            get_pushButton_iq = self.pushButton_iq_2
            get_pushButton_archive = self.pushButton_archive_2
            get_pushButton_scan_results_remove = self.pushButton_scan_results_remove_2
            get_pushButton_scan_results_probe = self.pushButton_scan_results_probe_2
            get_pushButton_scan_results_guess = self.pushButton_scan_results_guess_2
            get_tableWidget_scan_results = self.tableWidget_scan_results_2
            get_line3_scan_results = self.line3_scan_results_2
        elif tab_index == 2:
            # get_listWidget = self.listWidget_scan_3
            get_tableWidget = self.tableWidget_scan_results_3
            get_pushButton_add_to_all = self.pushButton_add_to_all_3
            get_pushButton_tsi = self.pushButton_tsi_3
            get_pushButton_pd = self.pushButton_pd_3
            get_pushButton_attack = self.pushButton_attack_3
            get_pushButton_iq = self.pushButton_iq_3
            get_pushButton_archive = self.pushButton_archive_3
            get_pushButton_scan_results_remove = self.pushButton_scan_results_remove_3
            get_pushButton_scan_results_probe = self.pushButton_scan_results_probe_3
            get_pushButton_scan_results_guess = self.pushButton_scan_results_guess_3
            get_tableWidget_scan_results = self.tableWidget_scan_results_3
            get_line3_scan_results = self.line3_scan_results_3
        elif tab_index == 3:
            # get_listWidget = self.listWidget_scan_4
            get_tableWidget = self.tableWidget_scan_results_4
            get_pushButton_add_to_all = self.pushButton_add_to_all_4
            get_pushButton_tsi = self.pushButton_tsi_4
            get_pushButton_pd = self.pushButton_pd_4
            get_pushButton_attack = self.pushButton_attack_4
            get_pushButton_iq = self.pushButton_iq_4
            get_pushButton_archive = self.pushButton_archive_4
            get_pushButton_scan_results_remove = self.pushButton_scan_results_remove_4
            get_pushButton_scan_results_probe = self.pushButton_scan_results_probe_4
            get_pushButton_scan_results_guess = self.pushButton_scan_results_guess_4
            get_tableWidget_scan_results = self.tableWidget_scan_results_4
            get_line3_scan_results = self.line3_scan_results_4
        elif tab_index == 4:
            # get_listWidget = self.listWidget_scan_5
            get_tableWidget = self.tableWidget_scan_results_5
            get_pushButton_add_to_all = self.pushButton_add_to_all_5
            get_pushButton_tsi = self.pushButton_tsi_5
            get_pushButton_pd = self.pushButton_pd_5
            get_pushButton_attack = self.pushButton_attack_5
            get_pushButton_iq = self.pushButton_iq_5
            get_pushButton_archive = self.pushButton_archive_5
            get_pushButton_scan_results_remove = self.pushButton_scan_results_remove_5
            get_pushButton_scan_results_probe = self.pushButton_scan_results_probe_5
            get_pushButton_scan_results_guess = self.pushButton_scan_results_guess_5
            get_tableWidget_scan_results = self.tableWidget_scan_results_5
            get_line3_scan_results = self.line3_scan_results_5

        # Add to Scan Results Table
        for n in range(0, len(all_scan_results)):
            rows = get_tableWidget.rowCount()
            get_tableWidget.setRowCount(rows + 1)
            for m in range(0, len(all_scan_results[n])):
                table_item = QtWidgets.QTableWidgetItem(all_scan_results[n][m])
                table_item.setTextAlignment(QtCore.Qt.AlignCenter)
                get_tableWidget.setItem(rows, m, table_item)

        get_tableWidget.selectRow(get_tableWidget.rowCount() - 1)

        get_tableWidget.resizeColumnsToContents()
        get_tableWidget.resizeRowsToContents()
        get_tableWidget.horizontalHeader().setStretchLastSection(False)
        get_tableWidget.horizontalHeader().setStretchLastSection(True)

        # Enable Push Buttons
        if get_tableWidget.rowCount() > 0:
            get_pushButton_add_to_all.setEnabled(True)
            get_pushButton_tsi.setEnabled(True)
            get_pushButton_pd.setEnabled(True)
            get_pushButton_attack.setEnabled(True)
            get_pushButton_iq.setEnabled(True)
            get_pushButton_archive.setEnabled(True)
            get_pushButton_scan_results_remove.setEnabled(True)
            get_pushButton_scan_results_probe.setEnabled(True)
            get_pushButton_scan_results_guess.setEnabled(True)
            get_tableWidget_scan_results.setEnabled(True)
            get_line3_scan_results.setEnabled(True)

    def guessReturn(self, tab_index, get_row, get_hardware, get_row_text, get_guess_index):
        """Populates the scan results table with the results of the hardware scan."""
        tab_index = int(tab_index)

        # Update Guess Index
        self.guess_index = get_guess_index

        # Fill Cells by Hardware
        scan_results_tables = [
            self.tableWidget_scan_results_1,
            self.tableWidget_scan_results_2,
            self.tableWidget_scan_results_3,
            self.tableWidget_scan_results_4,
            self.tableWidget_scan_results_5,
        ]

        if get_hardware == "USRP X3x0":
            pass

        elif get_hardware == "USRP B2x0":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item)

        elif get_hardware == "USRP B20xmini":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item)

        elif get_hardware == "bladeRF":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item)

        elif get_hardware == "LimeSDR":
            pass

        elif get_hardware == "HackRF":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item)

        elif get_hardware == "PlutoSDR":
            pass

        elif get_hardware == "USRP2":
            # Update Serial, IP Address, Daughterboard
            new_serial = str(get_row_text[3])
            table_item1 = QtWidgets.QTableWidgetItem(new_serial)
            table_item1.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item1)

            new_ip = str(get_row_text[5])
            table_item2 = QtWidgets.QTableWidgetItem(new_ip)
            table_item2.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 5, table_item2)

            new_daughterboard = str(get_row_text[6])
            table_item3 = QtWidgets.QTableWidgetItem(new_daughterboard)
            table_item3.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 6, table_item3)

        elif get_hardware == "USRP N2xx":
            # Update Serial, IP Address, Daughterboard
            new_serial = str(get_row_text[3])
            table_item1 = QtWidgets.QTableWidgetItem(new_serial)
            table_item1.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item1)

            new_ip = str(get_row_text[5])
            table_item2 = QtWidgets.QTableWidgetItem(new_ip)
            table_item2.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 5, table_item2)

            new_daughterboard = str(get_row_text[6])
            table_item3 = QtWidgets.QTableWidgetItem(new_daughterboard)
            table_item3.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 6, table_item3)

        elif get_hardware == "bladeRF 2.0":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item)

        elif get_hardware == "USRP X410":
            # Update Serial, IP Address, Daughterboard
            new_serial = str(get_row_text[3])
            table_item1 = QtWidgets.QTableWidgetItem(new_serial)
            table_item1.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item1)

            new_ip = str(get_row_text[5])
            table_item2 = QtWidgets.QTableWidgetItem(new_ip)
            table_item2.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 5, table_item2)

            new_daughterboard = str(get_row_text[6])
            table_item3 = QtWidgets.QTableWidgetItem(new_daughterboard)
            table_item3.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 6, table_item3)

        elif get_hardware == "802.11x Adapter":
            new_network_interface = str(get_row_text[4])
            table_item = QtWidgets.QTableWidgetItem(new_network_interface)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 4, table_item)

        elif get_hardware == "RTL2832U":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item)

        elif get_hardware == "RSPduo":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item)

        elif get_hardware == "RSPdx":
            new_serial = str(get_row_text[3])
            table_item = QtWidgets.QTableWidgetItem(new_serial)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scan_results_tables[tab_index].setItem(get_row, 3, table_item)
            
        # Resize the Scan Results Table
        scan_results_tables[tab_index].resizeColumnsToContents()
        scan_results_tables[tab_index].resizeRowsToContents()
        scan_results_tables[tab_index].horizontalHeader().setStretchLastSection(False)
        scan_results_tables[tab_index].horizontalHeader().setStretchLastSection(True)

    def sensorNodeConnected(self, tab_index=0):
        """Updates widgets for a sensor node once it is connected to the rest of FISSURE."""
        # Adjust the Widgets
        stacked_widgets = [
            self.stackedWidget_local_remote_1,
            self.stackedWidget_local_remote_2,
            self.stackedWidget_local_remote_3,
            self.stackedWidget_local_remote_4,
            self.stackedWidget_local_remote_5,
        ]
        bottom_stacked_widgets = [
            self.stackedWidget_bottom_1,
            self.stackedWidget_bottom_2,
            self.stackedWidget_bottom_3,
            self.stackedWidget_bottom_4,
            self.stackedWidget_bottom_5,
        ]
        scan_pushbuttons = [
            self.pushButton_scan_1,
            self.pushButton_scan_2,
            self.pushButton_scan_3,
            self.pushButton_scan_4,
            self.pushButton_scan_5,
        ]
        local_buttons = [
            self.radioButton_local_1,
            self.radioButton_local_2,
            self.radioButton_local_3,
            self.radioButton_local_4,
            self.radioButton_local_5,
        ]
        remote_buttons = [
            self.radioButton_remote_1,
            self.radioButton_remote_2,
            self.radioButton_remote_3,
            self.radioButton_remote_4,
            self.radioButton_remote_5,
        ]
        recall_settings_local_widgets = [
            self.checkBox_recall_settings_local_1,
            self.checkBox_recall_settings_local_2,
            self.checkBox_recall_settings_local_3,
            self.checkBox_recall_settings_local_4,
            self.checkBox_recall_settings_local_5,
        ]
        recall_settings_widgets = [
            self.checkBox_recall_settings_remote_1,
            self.checkBox_recall_settings_remote_2,
            self.checkBox_recall_settings_remote_3,
            self.checkBox_recall_settings_remote_4,
            self.checkBox_recall_settings_remote_5,
        ]
        launch_widgets = [
            self.pushButton_launch_1,
            self.pushButton_launch_2,
            self.pushButton_launch_3,
            self.pushButton_launch_4,
            self.pushButton_launch_5,
        ]
        connect_widgets = [
            self.pushButton_connect_1,
            self.pushButton_connect_2,
            self.pushButton_connect_3,
            self.pushButton_connect_4,
            self.pushButton_connect_5,
        ]
        ip_widgets = [
            self.textEdit_ip_addr_1, 
            self.textEdit_ip_addr_2, 
            self.textEdit_ip_addr_3, 
            self.textEdit_ip_addr_4, 
            self.textEdit_ip_addr_5
        ]
        msg_port_widgets = [
            self.textEdit_msg_port_1,
            self.textEdit_msg_port_2,
            self.textEdit_msg_port_3,
            self.textEdit_msg_port_4,
            self.textEdit_msg_port_5,
        ]
        hb_port_widgets = [
            self.textEdit_hb_port_1,
            self.textEdit_hb_port_2,
            self.textEdit_hb_port_3,
            self.textEdit_hb_port_4,
            self.textEdit_hb_port_5,
        ]
        stacked_widgets[tab_index].setCurrentIndex(2)
        bottom_stacked_widgets[tab_index].setCurrentIndex(0)
        scan_pushbuttons[tab_index].setEnabled(True)
        local_buttons[tab_index].setEnabled(False)
        remote_buttons[tab_index].setEnabled(False)
        launch_widgets[tab_index].setEnabled(True)
        recall_settings_local_widgets[tab_index].setEnabled(True)
        recall_settings_widgets[tab_index].setEnabled(True)
        connect_widgets[tab_index].setEnabled(True)
        ip_widgets[tab_index].setEnabled(True)
        msg_port_widgets[tab_index].setEnabled(True)
        hb_port_widgets[tab_index].setEnabled(True)

    def importResults(self, settings_dict=""):
        """
        Reuses the importClicked function on recall settings return from sensor node.
        """
        # Function in Slots
        HardwareSelectSlots.importClicked(self, settings_dict)

    def sensorNodeDisconnected(self, tab_index=0):
        """Updates widgets for a sensor node once it is disconnected from the rest of FISSURE."""
        # Adjust the Widgets
        stacked_widgets = [
            self.stackedWidget_local_remote_1,
            self.stackedWidget_local_remote_2,
            self.stackedWidget_local_remote_3,
            self.stackedWidget_local_remote_4,
            self.stackedWidget_local_remote_5,
        ]
        bottom_stacked_widgets = [
            self.stackedWidget_bottom_1,
            self.stackedWidget_bottom_2,
            self.stackedWidget_bottom_3,
            self.stackedWidget_bottom_4,
            self.stackedWidget_bottom_5,
        ]
        scan_pushbuttons = [
            self.pushButton_scan_1,
            self.pushButton_scan_2,
            self.pushButton_scan_3,
            self.pushButton_scan_4,
            self.pushButton_scan_5,
        ]
        local_buttons = [
            self.radioButton_local_1,
            self.radioButton_local_2,
            self.radioButton_local_3,
            self.radioButton_local_4,
            self.radioButton_local_5,
        ]
        remote_buttons = [
            self.radioButton_remote_1,
            self.radioButton_remote_2,
            self.radioButton_remote_3,
            self.radioButton_remote_4,
            self.radioButton_remote_5,
        ]
        details_stacked_widgets = [
            self.stackedWidget_details_1,
            self.stackedWidget_details_2,
            self.stackedWidget_details_3,
            self.stackedWidget_details_4,
            self.stackedWidget_details_5,
        ]

        if local_buttons[tab_index].isChecked():
            stacked_widgets[tab_index].setCurrentIndex(0)
        else:
            stacked_widgets[tab_index].setCurrentIndex(1)
        bottom_stacked_widgets[tab_index].setCurrentIndex(1)
        scan_pushbuttons[tab_index].setEnabled(True)
        local_buttons[tab_index].setEnabled(True)
        remote_buttons[tab_index].setEnabled(True)
        details_stacked_widgets[tab_index].setCurrentIndex(0)

        # Support Only One Local Sensor Node
        get_sensor_node = ["sensor_node1", "sensor_node2", "sensor_node3", "sensor_node4", "sensor_node5"]
        for n in range(0, 5):
            if str(self.dashboard.backend.settings[get_sensor_node[n]]["local_remote"]) == "local":
                if n != tab_index:
                    local_buttons[tab_index].setEnabled(False)

