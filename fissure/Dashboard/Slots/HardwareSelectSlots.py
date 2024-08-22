from PyQt5 import QtCore, QtWidgets

# import fissure.comms
import fissure.utils
import qasync
import time
import os
import yaml
import asyncio


@QtCore.pyqtSlot(QtCore.QObject)
def importClicked(HWSelect, settings_dict=""):
    """Import all sensor node information from a .csv file."""
    # Choose File
    if len(settings_dict) == 0:
        import_button_pressed = False
        get_archive_folder = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Import_Export_Files")
        fname = QtWidgets.QFileDialog.getOpenFileNames(
            None, "Select YAML File...", get_archive_folder, filter="YAML (*.yaml)"
        )
        if len(fname[0]) == 0:
            return
        sensor_index_start = 0
        sensor_index_end = 5
    else:
        import_button_pressed = True
        sensor_index_start = int(HWSelect.tabWidget_nodes.currentIndex())
        sensor_index_end = int(HWSelect.tabWidget_nodes.currentIndex()) + 1

    # Gather Widgets
    nickname_widgets = [
        HWSelect.textEdit_nickname_1,
        HWSelect.textEdit_nickname_2,
        HWSelect.textEdit_nickname_3,
        HWSelect.textEdit_nickname_4,
        HWSelect.textEdit_nickname_5,
    ]
    location_widgets = [
        HWSelect.textEdit_location_1,
        HWSelect.textEdit_location_2,
        HWSelect.textEdit_location_3,
        HWSelect.textEdit_location_4,
        HWSelect.textEdit_location_5,
    ]
    notes_widgets = [
        HWSelect.textEdit_notes_1,
        HWSelect.textEdit_notes_2,
        HWSelect.textEdit_notes_3,
        HWSelect.textEdit_notes_4,
        HWSelect.textEdit_notes_5,
    ]
    ip_widgets = [
        HWSelect.textEdit_ip_addr_1,
        HWSelect.textEdit_ip_addr_2, 
        HWSelect.textEdit_ip_addr_3, 
        HWSelect.textEdit_ip_addr_4, 
        HWSelect.textEdit_ip_addr_5
    ]
    
    msg_port_widgets = [
        HWSelect.textEdit_msg_port_1,
        HWSelect.textEdit_msg_port_2,
        HWSelect.textEdit_msg_port_3,
        HWSelect.textEdit_msg_port_4,
        HWSelect.textEdit_msg_port_5,
    ]
    hb_port_widgets = [
        HWSelect.textEdit_hb_port_1,
        HWSelect.textEdit_hb_port_2,
        HWSelect.textEdit_hb_port_3,
        HWSelect.textEdit_hb_port_4,
        HWSelect.textEdit_hb_port_5,
    ]
    local_widgets = [
        HWSelect.radioButton_local_1,
        HWSelect.radioButton_local_2,
        HWSelect.radioButton_local_3,
        HWSelect.radioButton_local_4,
        HWSelect.radioButton_local_5,
    ]
    remote_widgets = [
        HWSelect.radioButton_remote_1,
        HWSelect.radioButton_remote_2,
        HWSelect.radioButton_remote_3,
        HWSelect.radioButton_remote_4,
        HWSelect.radioButton_remote_5,
    ]
    hardware_tsi_widgets = [
        HWSelect.tableWidget_tsi_1,
        HWSelect.tableWidget_tsi_2,
        HWSelect.tableWidget_tsi_3,
        HWSelect.tableWidget_tsi_4,
        HWSelect.tableWidget_tsi_5,
    ]
    hardware_pd_widgets = [
        HWSelect.tableWidget_pd_1,
        HWSelect.tableWidget_pd_2,
        HWSelect.tableWidget_pd_3,
        HWSelect.tableWidget_pd_4,
        HWSelect.tableWidget_pd_5,
    ]
    hardware_attack_widgets = [
        HWSelect.tableWidget_attack_1,
        HWSelect.tableWidget_attack_2,
        HWSelect.tableWidget_attack_3,
        HWSelect.tableWidget_attack_4,
        HWSelect.tableWidget_attack_5,
    ]
    hardware_iq_widgets = [
        HWSelect.tableWidget_iq_1,
        HWSelect.tableWidget_iq_2,
        HWSelect.tableWidget_iq_3,
        HWSelect.tableWidget_iq_4,
        HWSelect.tableWidget_iq_5,
    ]
    hardware_archive_widgets = [
        HWSelect.tableWidget_archive_1,
        HWSelect.tableWidget_archive_2,
        HWSelect.tableWidget_archive_3,
        HWSelect.tableWidget_archive_4,
        HWSelect.tableWidget_archive_5,
    ]
    autorun_widgets = [
        HWSelect.label2_autorun_value_1,
        HWSelect.label2_autorun_value_2,
        HWSelect.label2_autorun_value_3,
        HWSelect.label2_autorun_value_4,
        HWSelect.label2_autorun_value_5,
    ]
    autorun_delay_widgets = [
        HWSelect.label2_autorun_delay_value_1,
        HWSelect.label2_autorun_delay_value_2,
        HWSelect.label2_autorun_delay_value_3,
        HWSelect.label2_autorun_delay_value_4,
        HWSelect.label2_autorun_delay_value_5,
    ]
    console_logging_level_widgets = [
        HWSelect.label2_console_logging_level_value_1,
        HWSelect.label2_console_logging_level_value_2,
        HWSelect.label2_console_logging_level_value_3,
        HWSelect.label2_console_logging_level_value_4,
        HWSelect.label2_console_logging_level_value_5
    ]
    file_logging_level_widgets = [
        HWSelect.label2_file_logging_level_value_1,
        HWSelect.label2_file_logging_level_value_2,
        HWSelect.label2_file_logging_level_value_3,
        HWSelect.label2_file_logging_level_value_4,
        HWSelect.label2_file_logging_level_value_5
    ]

    # Load the YAML File
    if len(settings_dict) == 0:
        with open(fname[0][0]) as yaml_library_file:
            settings_dict = yaml.load(yaml_library_file, yaml.FullLoader)
    else:
        # # Load the YAML String into a Dictionary
        # settings_dict = yaml.load(settings_dict, yaml.FullLoader)

        # Update Sensor Node Dictionary Key
        settings_dict["Sensor Node " + str(int(HWSelect.tabWidget_nodes.currentIndex()) + 1)] = settings_dict["Sensor Node"]
        del settings_dict["Sensor Node"]

    # Each Tab/Sensor Node
    for n in range(sensor_index_start, sensor_index_end):
        local_assigned = False
        ignore_nickname = False

        # Tab Enabled/Disabled
        if settings_dict["Sensor Node " + str(n + 1)]["enabled_disabled"] == "enabled":
            HWSelect.tabWidget_nodes.setTabEnabled(n, True)
            ignore_nickname = False
        else:
            HWSelect.tabWidget_nodes.setTabEnabled(n, False)
            HWSelect.tabWidget_nodes.setTabText(n, "")
            ignore_nickname = True

        # Local/Remote
        if settings_dict["Sensor Node " + str(n + 1)]["local_remote"] == "local":
            local_widgets[n].setChecked(True)
            local_assigned = True
            local(HWSelect, tab_index=n)
            HWSelect.tabWidget_nodes.setTabText(n, "Local Sensor Node")
        else:
            remote_widgets[n].setChecked(True)
            remote(HWSelect, tab_index=n)

        # Nickname
        nickname_widgets[n].setPlainText(settings_dict["Sensor Node " + str(n + 1)]["nickname"])
        HWSelect.tabWidget_nodes.setTabText(n, settings_dict["Sensor Node " + str(n + 1)]["nickname"])
        if ignore_nickname is True:
            HWSelect.tabWidget_nodes.setTabText(n, "")

        # Location
        location_widgets[n].setPlainText(settings_dict["Sensor Node " + str(n + 1)]["location"])

        # Notes
        notes_widgets[n].setPlainText(settings_dict["Sensor Node " + str(n + 1)]["notes"])

        # Autorun Details
        autorun_widgets[n].setText(str(settings_dict["Sensor Node " + str(n + 1)]["autorun"]))
        autorun_delay_widgets[n].setText(str(settings_dict["Sensor Node " + str(n + 1)]["autorun_delay_seconds"]))

        # Logging Details
        console_logging_level_widgets[n].setText(str(settings_dict['Sensor Node ' + str(n+1)]['console_logging_level']))
        file_logging_level_widgets[n].setText(str(settings_dict['Sensor Node ' + str(n+1)]['file_logging_level']))

        # IP Address
        ip_widgets[n].setPlainText(settings_dict["Sensor Node " + str(n + 1)]["ip_address"])

        # Ports
        msg_port_widgets[n].setPlainText(settings_dict["Sensor Node " + str(n + 1)]["msg_port"])
        hb_port_widgets[n].setPlainText(settings_dict["Sensor Node " + str(n + 1)]["hb_port"])

        # Clear the Tables
        hardware_tsi_widgets[n].setRowCount(0)
        hardware_pd_widgets[n].setRowCount(0)
        hardware_attack_widgets[n].setRowCount(0)
        hardware_iq_widgets[n].setRowCount(0)
        hardware_archive_widgets[n].setRowCount(0)

        # TSI
        for row_key in settings_dict["Sensor Node " + str(n + 1)]["tsi"]:
            hardware_tsi_widgets[n].setRowCount(hardware_tsi_widgets[n].rowCount() + 1)
            type_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["tsi"][row_key]["type"]
            )
            type_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_tsi_widgets[n].setItem(hardware_tsi_widgets[n].rowCount() - 1, 0, type_item)
            uid_item = QtWidgets.QTableWidgetItem(settings_dict["Sensor Node " + str(n + 1)]["tsi"][row_key]["uid"])
            uid_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_tsi_widgets[n].setItem(hardware_tsi_widgets[n].rowCount() - 1, 1, uid_item)
            radio_name_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["tsi"][row_key]["radio_name"]
            )
            radio_name_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_tsi_widgets[n].setItem(hardware_tsi_widgets[n].rowCount() - 1, 2, radio_name_item)
            serial_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["tsi"][row_key]["serial"]
            )
            serial_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_tsi_widgets[n].setItem(hardware_tsi_widgets[n].rowCount() - 1, 3, serial_item)
            network_interface_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["tsi"][row_key]["network_interface"]
            )
            network_interface_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_tsi_widgets[n].setItem(hardware_tsi_widgets[n].rowCount() - 1, 4, network_interface_item)
            ip_address_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["tsi"][row_key]["ip_address"]
            )
            ip_address_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_tsi_widgets[n].setItem(hardware_tsi_widgets[n].rowCount() - 1, 5, ip_address_item)
            daughterboard_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["tsi"][row_key]["daughterboard"]
            )
            daughterboard_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_tsi_widgets[n].setItem(hardware_tsi_widgets[n].rowCount() - 1, 6, daughterboard_item)

        # PD
        for row_key in settings_dict["Sensor Node " + str(n + 1)]["pd"]:
            hardware_pd_widgets[n].setRowCount(hardware_pd_widgets[n].rowCount() + 1)
            type_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["pd"][row_key]["type"]
            )
            type_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_pd_widgets[n].setItem(hardware_pd_widgets[n].rowCount() - 1, 0, type_item)
            uid_item = QtWidgets.QTableWidgetItem(settings_dict["Sensor Node " + str(n + 1)]["pd"][row_key]["uid"])
            uid_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_pd_widgets[n].setItem(hardware_pd_widgets[n].rowCount() - 1, 1, uid_item)
            radio_name_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["pd"][row_key]["radio_name"]
            )
            radio_name_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_pd_widgets[n].setItem(hardware_pd_widgets[n].rowCount() - 1, 2, radio_name_item)
            serial_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["pd"][row_key]["serial"]
            )
            serial_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_pd_widgets[n].setItem(hardware_pd_widgets[n].rowCount() - 1, 3, serial_item)
            network_interface_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["pd"][row_key]["network_interface"]
            )
            network_interface_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_pd_widgets[n].setItem(hardware_pd_widgets[n].rowCount() - 1, 4, network_interface_item)
            ip_address_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["pd"][row_key]["ip_address"]
            )
            ip_address_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_pd_widgets[n].setItem(hardware_pd_widgets[n].rowCount() - 1, 5, ip_address_item)
            daughterboard_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["pd"][row_key]["daughterboard"]
            )
            daughterboard_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_pd_widgets[n].setItem(hardware_pd_widgets[n].rowCount() - 1, 6, daughterboard_item)

        # Attack
        for row_key in settings_dict["Sensor Node " + str(n + 1)]["attack"]:
            hardware_attack_widgets[n].setRowCount(hardware_attack_widgets[n].rowCount() + 1)
            type_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["attack"][row_key]["type"]
            )
            type_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_attack_widgets[n].setItem(hardware_attack_widgets[n].rowCount() - 1, 0, type_item)
            uid_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["attack"][row_key]["uid"]
            )
            uid_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_attack_widgets[n].setItem(hardware_attack_widgets[n].rowCount() - 1, 1, uid_item)
            radio_name_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["attack"][row_key]["radio_name"]
            )
            radio_name_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_attack_widgets[n].setItem(hardware_attack_widgets[n].rowCount() - 1, 2, radio_name_item)
            serial_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["attack"][row_key]["serial"]
            )
            serial_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_attack_widgets[n].setItem(hardware_attack_widgets[n].rowCount() - 1, 3, serial_item)
            network_interface_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["attack"][row_key]["network_interface"]
            )
            network_interface_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_attack_widgets[n].setItem(hardware_attack_widgets[n].rowCount() - 1, 4, network_interface_item)
            ip_address_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["attack"][row_key]["ip_address"]
            )
            ip_address_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_attack_widgets[n].setItem(hardware_attack_widgets[n].rowCount() - 1, 5, ip_address_item)
            daughterboard_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["attack"][row_key]["daughterboard"]
            )
            daughterboard_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_attack_widgets[n].setItem(hardware_attack_widgets[n].rowCount() - 1, 6, daughterboard_item)

        # IQ
        for row_key in settings_dict["Sensor Node " + str(n + 1)]["iq"]:
            hardware_iq_widgets[n].setRowCount(hardware_iq_widgets[n].rowCount() + 1)
            type_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["iq"][row_key]["type"]
            )
            type_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_iq_widgets[n].setItem(hardware_iq_widgets[n].rowCount() - 1, 0, type_item)
            uid_item = QtWidgets.QTableWidgetItem(settings_dict["Sensor Node " + str(n + 1)]["iq"][row_key]["uid"])
            uid_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_iq_widgets[n].setItem(hardware_iq_widgets[n].rowCount() - 1, 1, uid_item)
            radio_name_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["iq"][row_key]["radio_name"]
            )
            radio_name_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_iq_widgets[n].setItem(hardware_iq_widgets[n].rowCount() - 1, 2, radio_name_item)
            serial_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["iq"][row_key]["serial"]
            )
            serial_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_iq_widgets[n].setItem(hardware_iq_widgets[n].rowCount() - 1, 3, serial_item)
            network_interface_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["iq"][row_key]["network_interface"]
            )
            network_interface_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_iq_widgets[n].setItem(hardware_iq_widgets[n].rowCount() - 1, 4, network_interface_item)
            ip_address_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["iq"][row_key]["ip_address"]
            )
            ip_address_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_iq_widgets[n].setItem(hardware_iq_widgets[n].rowCount() - 1, 5, ip_address_item)
            daughterboard_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["iq"][row_key]["daughterboard"]
            )
            daughterboard_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_iq_widgets[n].setItem(hardware_iq_widgets[n].rowCount() - 1, 6, daughterboard_item)

        # Archive
        for row_key in settings_dict["Sensor Node " + str(n + 1)]["archive"]:
            hardware_archive_widgets[n].setRowCount(hardware_archive_widgets[n].rowCount() + 1)
            type_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["archive"][row_key]["type"]
            )
            type_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_archive_widgets[n].setItem(hardware_archive_widgets[n].rowCount() - 1, 0, type_item)
            uid_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["archive"][row_key]["uid"]
            )
            uid_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_archive_widgets[n].setItem(hardware_archive_widgets[n].rowCount() - 1, 1, uid_item)
            radio_name_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["archive"][row_key]["radio_name"]
            )
            radio_name_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_archive_widgets[n].setItem(hardware_archive_widgets[n].rowCount() - 1, 2, radio_name_item)
            serial_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["archive"][row_key]["serial"]
            )
            serial_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_archive_widgets[n].setItem(hardware_archive_widgets[n].rowCount() - 1, 3, serial_item)
            network_interface_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["archive"][row_key]["network_interface"]
            )
            network_interface_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_archive_widgets[n].setItem(
                hardware_archive_widgets[n].rowCount() - 1, 4, network_interface_item
            )
            ip_address_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["archive"][row_key]["ip_address"]
            )
            ip_address_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_archive_widgets[n].setItem(hardware_archive_widgets[n].rowCount() - 1, 5, ip_address_item)
            daughterboard_item = QtWidgets.QTableWidgetItem(
                settings_dict["Sensor Node " + str(n + 1)]["archive"][row_key]["daughterboard"]
            )
            daughterboard_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_archive_widgets[n].setItem(hardware_archive_widgets[n].rowCount() - 1, 6, daughterboard_item)

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

    # Enable/Disable Local and Remote Radio Buttons
    for k in range(sensor_index_start, sensor_index_end):
        if (local_assigned is True) and (remote_widgets[k].isChecked() is True):
            local_widgets[k].setEnabled(False)

@QtCore.pyqtSlot(QtCore.QObject)
def export(HWSelect: QtCore.QObject):
    """
    Exports all the sensor node information to a csv file.
    """
    # Choose File Location
    get_archive_folder = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Import_Export_Files")
    path = QtWidgets.QFileDialog.getSaveFileName(HWSelect, "Save YAML", get_archive_folder, filter="YAML (*.yaml)")
    get_path = path[0]

    # Add Extension
    if get_path.endswith(".yaml") is False:
        get_path = get_path + ".yaml"

    # Save Values
    if len(path[0]) > 0:
        nickname_widgets = [
            HWSelect.textEdit_nickname_1,
            HWSelect.textEdit_nickname_2,
            HWSelect.textEdit_nickname_3,
            HWSelect.textEdit_nickname_4,
            HWSelect.textEdit_nickname_5,
        ]
        location_widgets = [
            HWSelect.textEdit_location_1,
            HWSelect.textEdit_location_2,
            HWSelect.textEdit_location_3,
            HWSelect.textEdit_location_4,
            HWSelect.textEdit_location_5,
        ]
        notes_widgets = [
            HWSelect.textEdit_notes_1,
            HWSelect.textEdit_notes_2,
            HWSelect.textEdit_notes_3,
            HWSelect.textEdit_notes_4,
            HWSelect.textEdit_notes_5,
        ]
        ip_widgets = [
            HWSelect.textEdit_ip_addr_1, 
            HWSelect.textEdit_ip_addr_2, 
            HWSelect.textEdit_ip_addr_3, 
            HWSelect.textEdit_ip_addr_4, 
            HWSelect.textEdit_ip_addr_5
        ]
        msg_port_widgets = [
            HWSelect.textEdit_msg_port_1,
            HWSelect.textEdit_msg_port_2,
            HWSelect.textEdit_msg_port_3,
            HWSelect.textEdit_msg_port_4,
            HWSelect.textEdit_msg_port_5,
        ]
        hb_port_widgets = [
            HWSelect.textEdit_hb_port_1,
            HWSelect.textEdit_hb_port_2,
            HWSelect.textEdit_hb_port_3,
            HWSelect.textEdit_hb_port_4,
            HWSelect.textEdit_hb_port_5,
        ]
        local_widgets = [
            HWSelect.radioButton_local_1,
            HWSelect.radioButton_local_2,
            HWSelect.radioButton_local_3,
            HWSelect.radioButton_local_4,
            HWSelect.radioButton_local_5,
        ]
        # remote_widgets = [
        #     HWSelect.radioButton_remote_1,
        #     HWSelect.radioButton_remote_2,
        #     HWSelect.radioButton_remote_3,
        #     HWSelect.radioButton_remote_4,
        #     HWSelect.radioButton_remote_5,
        # ]
        hardware_tsi_widgets = [
            HWSelect.tableWidget_tsi_1,
            HWSelect.tableWidget_tsi_2,
            HWSelect.tableWidget_tsi_3,
            HWSelect.tableWidget_tsi_4,
            HWSelect.tableWidget_tsi_5,
        ]
        hardware_pd_widgets = [
            HWSelect.tableWidget_pd_1,
            HWSelect.tableWidget_pd_2,
            HWSelect.tableWidget_pd_3,
            HWSelect.tableWidget_pd_4,
            HWSelect.tableWidget_pd_5,
        ]
        hardware_attack_widgets = [
            HWSelect.tableWidget_attack_1,
            HWSelect.tableWidget_attack_2,
            HWSelect.tableWidget_attack_3,
            HWSelect.tableWidget_attack_4,
            HWSelect.tableWidget_attack_5,
        ]
        hardware_iq_widgets = [
            HWSelect.tableWidget_iq_1,
            HWSelect.tableWidget_iq_2,
            HWSelect.tableWidget_iq_3,
            HWSelect.tableWidget_iq_4,
            HWSelect.tableWidget_iq_5,
        ]
        hardware_archive_widgets = [
            HWSelect.tableWidget_archive_1,
            HWSelect.tableWidget_archive_2,
            HWSelect.tableWidget_archive_3,
            HWSelect.tableWidget_archive_4,
            HWSelect.tableWidget_archive_5,
        ]
        autorun_widgets = [
            HWSelect.label2_autorun_value_1,
            HWSelect.label2_autorun_value_2,
            HWSelect.label2_autorun_value_3,
            HWSelect.label2_autorun_value_4,
            HWSelect.label2_autorun_value_5,
        ]
        autorun_delay_widgets = [
            HWSelect.label2_autorun_delay_value_1,
            HWSelect.label2_autorun_delay_value_2,
            HWSelect.label2_autorun_delay_value_3,
            HWSelect.label2_autorun_delay_value_4,
            HWSelect.label2_autorun_delay_value_5,
        ]
        console_logging_level_widgets = [
            HWSelect.label2_console_logging_level_value_1,
            HWSelect.label2_console_logging_level_value_2,
            HWSelect.label2_console_logging_level_value_3,
            HWSelect.label2_console_logging_level_value_4,
            HWSelect.label2_console_logging_level_value_5
        ]
        file_logging_level_widgets = [
            HWSelect.label2_file_logging_level_value_1,
            HWSelect.label2_file_logging_level_value_2,
            HWSelect.label2_file_logging_level_value_3,
            HWSelect.label2_file_logging_level_value_4,
            HWSelect.label2_file_logging_level_value_5
        ]

        settings_dict = {}
        for n in range(0, len(nickname_widgets)):
            sensor_dict = {}

            if len(HWSelect.tabWidget_nodes.tabText(n)) == 0:
                sensor_dict["enabled_disabled"] = "disabled"
            else:
                sensor_dict["enabled_disabled"] = "enabled"

            if local_widgets[n].isChecked() is True:
                sensor_dict["local_remote"] = "local"
            else:
                sensor_dict["local_remote"] = "remote"

            sensor_dict["nickname"] = str(nickname_widgets[n].toPlainText())
            sensor_dict["location"] = str(location_widgets[n].toPlainText())
            sensor_dict["notes"] = str(notes_widgets[n].toPlainText())
            sensor_dict["ip_address"] = str(ip_widgets[n].toPlainText())
            sensor_dict["msg_port"] = str(msg_port_widgets[n].toPlainText())
            sensor_dict["hb_port"] = str(hb_port_widgets[n].toPlainText())
            sensor_dict["autorun"] = bool(autorun_widgets[n].text())
            try:
                sensor_dict["autorun_delay_seconds"] = float(autorun_delay_widgets[n].text())
            except:
                sensor_dict["autorun_delay_seconds"] = ""
            sensor_dict['console_logging_level'] = console_logging_level_widgets[n].text()
            sensor_dict['file_logging_level'] = file_logging_level_widgets[n].text()

            # TSI
            tsi_dict = {}
            for row in range(hardware_tsi_widgets[n].rowCount()):
                row_dict = {}
                try:
                    row_dict["type"] = str(hardware_tsi_widgets[n].item(row, 0).text())
                except:
                    row_dict["type"] = ""
                try:
                    row_dict["uid"] = str(hardware_tsi_widgets[n].item(row, 1).text())
                except:
                    row_dict["uid"] = ""
                try:
                    row_dict["radio_name"] = str(hardware_tsi_widgets[n].item(row, 2).text())
                except:
                    row_dict["radio_name"] = ""
                try:
                    row_dict["serial"] = str(hardware_tsi_widgets[n].item(row, 3).text())
                except:
                    row_dict["serial"] = ""
                try:
                    row_dict["network_interface"] = str(hardware_tsi_widgets[n].item(row, 4).text())
                except:
                    row_dict["network_interface"] = ""
                try:
                    row_dict["ip_address"] = str(hardware_tsi_widgets[n].item(row, 5).text())
                except:
                    row_dict["ip_address"] = ""
                try:
                    row_dict["daughterboard"] = str(hardware_tsi_widgets[n].item(row, 6).text())
                except:
                    row_dict["daughterboard"] = ""
                tsi_dict[row] = row_dict
            sensor_dict["tsi"] = tsi_dict

            # PD
            pd_dict = {}
            for row in range(hardware_pd_widgets[n].rowCount()):
                row_dict = {}
                try:
                    row_dict["type"] = str(hardware_pd_widgets[n].item(row, 0).text())
                except:
                    row_dict["type"] = ""
                try:
                    row_dict["uid"] = str(hardware_pd_widgets[n].item(row, 1).text())
                except:
                    row_dict["uid"] = ""
                try:
                    row_dict["radio_name"] = str(hardware_pd_widgets[n].item(row, 2).text())
                except:
                    row_dict["radio_name"] = ""
                try:
                    row_dict["serial"] = str(hardware_pd_widgets[n].item(row, 3).text())
                except:
                    row_dict["serial"] = ""
                try:
                    row_dict["network_interface"] = str(hardware_pd_widgets[n].item(row, 4).text())
                except:
                    row_dict["network_interface"] = ""
                try:
                    row_dict["ip_address"] = str(hardware_pd_widgets[n].item(row, 5).text())
                except:
                    row_dict["ip_address"] = ""
                try:
                    row_dict["daughterboard"] = str(hardware_pd_widgets[n].item(row, 6).text())
                except:
                    row_dict["daughterboard"] = ""
                pd_dict[row] = row_dict
            sensor_dict["pd"] = pd_dict

            # Attack
            attack_dict = {}
            for row in range(hardware_attack_widgets[n].rowCount()):
                row_dict = {}
                try:
                    row_dict["type"] = str(hardware_attack_widgets[n].item(row, 0).text())
                except:
                    row_dict["type"] = ""
                try:
                    row_dict["uid"] = str(hardware_attack_widgets[n].item(row, 1).text())
                except:
                    row_dict["uid"] = ""
                try:
                    row_dict["radio_name"] = str(hardware_attack_widgets[n].item(row, 2).text())
                except:
                    row_dict["radio_name"] = ""
                try:
                    row_dict["serial"] = str(hardware_attack_widgets[n].item(row, 3).text())
                except:
                    row_dict["serial"] = ""
                try:
                    row_dict["network_interface"] = str(hardware_attack_widgets[n].item(row, 4).text())
                except:
                    row_dict["network_interface"] = ""
                try:
                    row_dict["ip_address"] = str(hardware_attack_widgets[n].item(row, 5).text())
                except:
                    row_dict["ip_address"] = ""
                try:
                    row_dict["daughterboard"] = str(hardware_attack_widgets[n].item(row, 6).text())
                except:
                    row_dict["daughterboard"] = ""
                attack_dict[row] = row_dict
            sensor_dict["attack"] = attack_dict

            # IQ
            iq_dict = {}
            for row in range(hardware_iq_widgets[n].rowCount()):
                row_dict = {}
                try:
                    row_dict["type"] = str(hardware_iq_widgets[n].item(row, 0).text())
                except:
                    row_dict["type"] = ""
                try:
                    row_dict["uid"] = str(hardware_iq_widgets[n].item(row, 1).text())
                except:
                    row_dict["uid"] = ""
                try:
                    row_dict["radio_name"] = str(hardware_iq_widgets[n].item(row, 2).text())
                except:
                    row_dict["radio_name"] = ""
                try:
                    row_dict["serial"] = str(hardware_iq_widgets[n].item(row, 3).text())
                except:
                    row_dict["serial"] = ""
                try:
                    row_dict["network_interface"] = str(hardware_iq_widgets[n].item(row, 4).text())
                except:
                    row_dict["network_interface"] = ""
                try:
                    row_dict["ip_address"] = str(hardware_iq_widgets[n].item(row, 5).text())
                except:
                    row_dict["ip_address"] = ""
                try:
                    row_dict["daughterboard"] = str(hardware_iq_widgets[n].item(row, 6).text())
                except:
                    row_dict["daughterboard"] = ""
                iq_dict[row] = row_dict
            sensor_dict["iq"] = iq_dict

            # Archive
            archive_dict = {}
            for row in range(hardware_archive_widgets[n].rowCount()):
                row_dict = {}
                try:
                    row_dict["type"] = str(hardware_archive_widgets[n].item(row, 0).text())
                except:
                    row_dict["type"] = ""
                try:
                    row_dict["uid"] = str(hardware_archive_widgets[n].item(row, 1).text())
                except:
                    row_dict["uid"] = ""
                try:
                    row_dict["radio_name"] = str(hardware_archive_widgets[n].item(row, 2).text())
                except:
                    row_dict["radio_name"] = ""
                try:
                    row_dict["serial"] = str(hardware_archive_widgets[n].item(row, 3).text())
                except:
                    row_dict["serial"] = ""
                try:
                    row_dict["network_interface"] = str(hardware_archive_widgets[n].item(row, 4).text())
                except:
                    row_dict["network_interface"] = ""
                try:
                    row_dict["ip_address"] = str(hardware_archive_widgets[n].item(row, 5).text())
                except:
                    row_dict["ip_address"] = ""
                try:
                    row_dict["daughterboard"] = str(hardware_archive_widgets[n].item(row, 6).text())
                except:
                    row_dict["daughterboard"] = ""
                archive_dict[row] = row_dict
            sensor_dict["archive"] = archive_dict

            # Save Sensor Node
            settings_dict["Sensor Node " + str(n + 1)] = sensor_dict

        # Dump Dictionary to File
        stream = open(get_path, "w")
        yaml.dump(settings_dict, stream, default_flow_style=False, indent=5)

@qasync.asyncSlot(QtCore.QObject)
async def guess(HWSelect: QtCore.QObject):
    """
    Cycles through possible values for the selected row in the scan results table.
    """
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    scan_results_tables = [
        HWSelect.tableWidget_scan_results_1,
        HWSelect.tableWidget_scan_results_2,
        HWSelect.tableWidget_scan_results_3,
        HWSelect.tableWidget_scan_results_4,
        HWSelect.tableWidget_scan_results_5,
    ]
    get_row = scan_results_tables[tab_index].currentRow()
    get_row_text = []
    for n in range(0, scan_results_tables[tab_index].columnCount()):
        get_row_text.append(str(scan_results_tables[tab_index].item(get_row, n).text()))

    # Send Message for HIPRFISR to Sensor Node Connections
    await HWSelect.dashboard.backend.guess_sensor_node(str(tab_index), get_row, get_row_text, HWSelect.guess_index)

@qasync.asyncSlot(QtCore.QObject)
async def probe(HWSelect: QtCore.QObject):
    """
    Probes the selected radio in the scan results table.
    """
    # Row Number and Text
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    scan_results_tables = [
        HWSelect.tableWidget_scan_results_1,
        HWSelect.tableWidget_scan_results_2,
        HWSelect.tableWidget_scan_results_3,
        HWSelect.tableWidget_scan_results_4,
        HWSelect.tableWidget_scan_results_5,
    ]
    get_row = scan_results_tables[tab_index].currentRow()
    get_row_text = []
    for n in range(0, scan_results_tables[tab_index].columnCount()):
        get_row_text.append(str(scan_results_tables[tab_index].item(get_row, n).text()))

    # Show Label
    scan_results_labels = [
        HWSelect.label2_scan_results_probe_1,
        HWSelect.label2_scan_results_probe_2,
        HWSelect.label2_scan_results_probe_3,
        HWSelect.label2_scan_results_probe_4,
        HWSelect.label2_scan_results_probe_5,
    ]
    scan_results_labels[tab_index].setVisible(True)

    # Disable Probe Button
    probe_buttons = [
        HWSelect.pushButton_scan_results_probe_1,
        HWSelect.pushButton_scan_results_probe_2,
        HWSelect.pushButton_scan_results_probe_3,
        HWSelect.pushButton_scan_results_probe_4,
        HWSelect.pushButton_scan_results_probe_5
    ]
    probe_buttons[tab_index].setEnabled(False)

    # Send Message for HIPRFISR to Sensor Node Connections
    await HWSelect.dashboard.backend.probe_sensor_node(str(tab_index), get_row_text)

@qasync.asyncSlot(QtCore.QObject)
async def scan(HWSelect: QtCore.QObject):
    """
    Performs a mass hardware scan on the local/remote sensor node and returns the results.
    """
    # Save Checked Items in Current Tab
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    list_widgets = [
        HWSelect.listWidget_scan_1,
        HWSelect.listWidget_scan_2,
        HWSelect.listWidget_scan_3,
        HWSelect.listWidget_scan_4,
        HWSelect.listWidget_scan_5,
    ]
    get_list_widget = list_widgets[tab_index]
    hardware_list = []
    for n in range(0, get_list_widget.count()):
        if get_list_widget.item(n).checkState() == QtCore.Qt.Checked:
            hardware_list.append(str(get_list_widget.item(n).text()))

    # Send Message for HIPRFISR to Sensor Node Connections
    await HWSelect.dashboard.backend.scan_sensor_node(str(tab_index), hardware_list)

@QtCore.pyqtSlot(QtCore.QObject)
def tsi(HWSelect: QtCore.QObject):
    """
    Adds the selected row in the scan results table to the TSI table.
    """
    # Copy Scan Result to TSI Table
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    scan_results_widgets = [
        HWSelect.tableWidget_scan_results_1,
        HWSelect.tableWidget_scan_results_2,
        HWSelect.tableWidget_scan_results_3,
        HWSelect.tableWidget_scan_results_4,
        HWSelect.tableWidget_scan_results_5,
    ]
    hardware_tsi_widgets = [
        HWSelect.tableWidget_tsi_1,
        HWSelect.tableWidget_tsi_2,
        HWSelect.tableWidget_tsi_3,
        HWSelect.tableWidget_tsi_4,
        HWSelect.tableWidget_tsi_5,
    ]
    hardware_tabs_widgets = [
        HWSelect.tabWidget_hardware_1,
        HWSelect.tabWidget_hardware_2,
        HWSelect.tabWidget_hardware_3,
        HWSelect.tabWidget_hardware_4,
        HWSelect.tabWidget_hardware_5,
    ]
    hardware_tsi_widgets[tab_index].setRowCount(hardware_tsi_widgets[tab_index].rowCount() + 1)
    get_row = scan_results_widgets[tab_index].currentRow()
    for col in range(0, scan_results_widgets[tab_index].columnCount()):
        if scan_results_widgets[tab_index].item(get_row, col) is not None:
            table_item = QtWidgets.QTableWidgetItem(str(scan_results_widgets[tab_index].item(get_row, col).text()))
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_tsi_widgets[tab_index].setItem(hardware_tsi_widgets[tab_index].rowCount() - 1, col, table_item)
    hardware_tsi_widgets[tab_index].resizeColumnsToContents()
    hardware_tsi_widgets[tab_index].resizeRowsToContents()
    hardware_tsi_widgets[tab_index].horizontalHeader().setStretchLastSection(False)
    hardware_tsi_widgets[tab_index].horizontalHeader().setStretchLastSection(True)
    hardware_tabs_widgets[tab_index].setCurrentIndex(0)

@QtCore.pyqtSlot(QtCore.QObject)
def pd(HWSelect: QtCore.QObject):
    """
    Adds the selected row in the scan results table to the PD table.
    """
    # Copy Scan Result to PD Table
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    scan_results_widgets = [
        HWSelect.tableWidget_scan_results_1,
        HWSelect.tableWidget_scan_results_2,
        HWSelect.tableWidget_scan_results_3,
        HWSelect.tableWidget_scan_results_4,
        HWSelect.tableWidget_scan_results_5,
    ]
    hardware_pd_widgets = [
        HWSelect.tableWidget_pd_1,
        HWSelect.tableWidget_pd_2,
        HWSelect.tableWidget_pd_3,
        HWSelect.tableWidget_pd_4,
        HWSelect.tableWidget_pd_5,
    ]
    hardware_tabs_widgets = [
        HWSelect.tabWidget_hardware_1,
        HWSelect.tabWidget_hardware_2,
        HWSelect.tabWidget_hardware_3,
        HWSelect.tabWidget_hardware_4,
        HWSelect.tabWidget_hardware_5,
    ]
    hardware_pd_widgets[tab_index].setRowCount(hardware_pd_widgets[tab_index].rowCount() + 1)
    get_row = scan_results_widgets[tab_index].currentRow()
    for col in range(0, scan_results_widgets[tab_index].columnCount()):
        if scan_results_widgets[tab_index].item(get_row, col) is not None:
            table_item = QtWidgets.QTableWidgetItem(str(scan_results_widgets[tab_index].item(get_row, col).text()))
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_pd_widgets[tab_index].setItem(hardware_pd_widgets[tab_index].rowCount() - 1, col, table_item)
    hardware_pd_widgets[tab_index].resizeColumnsToContents()
    hardware_pd_widgets[tab_index].resizeRowsToContents()
    hardware_pd_widgets[tab_index].horizontalHeader().setStretchLastSection(False)
    hardware_pd_widgets[tab_index].horizontalHeader().setStretchLastSection(True)
    hardware_tabs_widgets[tab_index].setCurrentIndex(1)

@QtCore.pyqtSlot(QtCore.QObject)
def attack(HWSelect: QtCore.QObject):
    """
    Adds the selected row in the scan results table to the Attack table.
    """
    # Copy Scan Result to Attack Table
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    scan_results_widgets = [
        HWSelect.tableWidget_scan_results_1,
        HWSelect.tableWidget_scan_results_2,
        HWSelect.tableWidget_scan_results_3,
        HWSelect.tableWidget_scan_results_4,
        HWSelect.tableWidget_scan_results_5,
    ]
    hardware_attack_widgets = [
        HWSelect.tableWidget_attack_1,
        HWSelect.tableWidget_attack_2,
        HWSelect.tableWidget_attack_3,
        HWSelect.tableWidget_attack_4,
        HWSelect.tableWidget_attack_5,
    ]
    hardware_tabs_widgets = [
        HWSelect.tabWidget_hardware_1,
        HWSelect.tabWidget_hardware_2,
        HWSelect.tabWidget_hardware_3,
        HWSelect.tabWidget_hardware_4,
        HWSelect.tabWidget_hardware_5,
    ]
    hardware_attack_widgets[tab_index].setRowCount(hardware_attack_widgets[tab_index].rowCount() + 1)
    get_row = scan_results_widgets[tab_index].currentRow()
    for col in range(0, scan_results_widgets[tab_index].columnCount()):
        if scan_results_widgets[tab_index].item(get_row, col) is not None:
            table_item = QtWidgets.QTableWidgetItem(str(scan_results_widgets[tab_index].item(get_row, col).text()))
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_attack_widgets[tab_index].setItem(
                hardware_attack_widgets[tab_index].rowCount() - 1, col, table_item
            )
    hardware_attack_widgets[tab_index].resizeColumnsToContents()
    hardware_attack_widgets[tab_index].resizeRowsToContents()
    hardware_attack_widgets[tab_index].horizontalHeader().setStretchLastSection(False)
    hardware_attack_widgets[tab_index].horizontalHeader().setStretchLastSection(True)
    hardware_tabs_widgets[tab_index].setCurrentIndex(2)

@QtCore.pyqtSlot(QtCore.QObject)
def iq(HWSelect: QtCore.QObject):
    """
    Adds the selected row in the scan results table to the IQ table.
    """
    # Copy Scan Result to IQ Table
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    scan_results_widgets = [
        HWSelect.tableWidget_scan_results_1,
        HWSelect.tableWidget_scan_results_2,
        HWSelect.tableWidget_scan_results_3,
        HWSelect.tableWidget_scan_results_4,
        HWSelect.tableWidget_scan_results_5,
    ]
    hardware_iq_widgets = [
        HWSelect.tableWidget_iq_1,
        HWSelect.tableWidget_iq_2,
        HWSelect.tableWidget_iq_3,
        HWSelect.tableWidget_iq_4,
        HWSelect.tableWidget_iq_5,
    ]
    hardware_tabs_widgets = [
        HWSelect.tabWidget_hardware_1,
        HWSelect.tabWidget_hardware_2,
        HWSelect.tabWidget_hardware_3,
        HWSelect.tabWidget_hardware_4,
        HWSelect.tabWidget_hardware_5,
    ]
    hardware_iq_widgets[tab_index].setRowCount(hardware_iq_widgets[tab_index].rowCount() + 1)
    get_row = scan_results_widgets[tab_index].currentRow()
    for col in range(0, scan_results_widgets[tab_index].columnCount()):
        if scan_results_widgets[tab_index].item(get_row, col) is not None:
            table_item = QtWidgets.QTableWidgetItem(str(scan_results_widgets[tab_index].item(get_row, col).text()))
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_iq_widgets[tab_index].setItem(hardware_iq_widgets[tab_index].rowCount() - 1, col, table_item)
    hardware_iq_widgets[tab_index].resizeColumnsToContents()
    hardware_iq_widgets[tab_index].resizeRowsToContents()
    hardware_iq_widgets[tab_index].horizontalHeader().setStretchLastSection(False)
    hardware_iq_widgets[tab_index].horizontalHeader().setStretchLastSection(True)
    hardware_tabs_widgets[tab_index].setCurrentIndex(3)

@QtCore.pyqtSlot(QtCore.QObject)
def archive(HWSelect: QtCore.QObject):
    """
    Adds the selected row in the scan results table to the Archive table.
    """
    # Copy Scan Result to Archive Table
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    scan_results_widgets = [
        HWSelect.tableWidget_scan_results_1,
        HWSelect.tableWidget_scan_results_2,
        HWSelect.tableWidget_scan_results_3,
        HWSelect.tableWidget_scan_results_4,
        HWSelect.tableWidget_scan_results_5,
    ]
    hardware_archive_widgets = [
        HWSelect.tableWidget_archive_1,
        HWSelect.tableWidget_archive_2,
        HWSelect.tableWidget_archive_3,
        HWSelect.tableWidget_archive_4,
        HWSelect.tableWidget_archive_5,
    ]
    hardware_tabs_widgets = [
        HWSelect.tabWidget_hardware_1,
        HWSelect.tabWidget_hardware_2,
        HWSelect.tabWidget_hardware_3,
        HWSelect.tabWidget_hardware_4,
        HWSelect.tabWidget_hardware_5,
    ]
    hardware_archive_widgets[tab_index].setRowCount(hardware_archive_widgets[tab_index].rowCount() + 1)
    get_row = scan_results_widgets[tab_index].currentRow()
    for col in range(0, scan_results_widgets[tab_index].columnCount()):
        if scan_results_widgets[tab_index].item(get_row, col) is not None:
            table_item = QtWidgets.QTableWidgetItem(str(scan_results_widgets[tab_index].item(get_row, col).text()))
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            hardware_archive_widgets[tab_index].setItem(
                hardware_archive_widgets[tab_index].rowCount() - 1, col, table_item
            )
    hardware_archive_widgets[tab_index].resizeColumnsToContents()
    hardware_archive_widgets[tab_index].resizeRowsToContents()
    hardware_archive_widgets[tab_index].horizontalHeader().setStretchLastSection(False)
    hardware_archive_widgets[tab_index].horizontalHeader().setStretchLastSection(True)
    hardware_tabs_widgets[tab_index].setCurrentIndex(4)

@QtCore.pyqtSlot(QtCore.QObject)
def remove_tsi(HWSelect: QtCore.QObject):
    """
    Removes a row from the TSI table.
    """
    # Remove Row
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    tsi_tables = [
        HWSelect.tableWidget_tsi_1,
        HWSelect.tableWidget_tsi_2,
        HWSelect.tableWidget_tsi_3,
        HWSelect.tableWidget_tsi_4,
        HWSelect.tableWidget_tsi_5,
    ]
    get_row = tsi_tables[tab_index].currentRow()
    tsi_tables[tab_index].removeRow(get_row)
    if get_row == tsi_tables[tab_index].rowCount():
        tsi_tables[tab_index].setCurrentCell(tsi_tables[tab_index].rowCount() - 1, 0)
    elif get_row >= 0:
        tsi_tables[tab_index].setCurrentCell(get_row, 0)

@QtCore.pyqtSlot(QtCore.QObject)
def remove_pd(HWSelect: QtCore.QObject):
    """
    Removes a row from the PD table.
    """
    # Remove Row
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    pd_tables = [
        HWSelect.tableWidget_pd_1,
        HWSelect.tableWidget_pd_2,
        HWSelect.tableWidget_pd_3,
        HWSelect.tableWidget_pd_4,
        HWSelect.tableWidget_pd_5,
    ]
    get_row = pd_tables[tab_index].currentRow()
    pd_tables[tab_index].removeRow(get_row)
    if get_row == pd_tables[tab_index].rowCount():
        pd_tables[tab_index].setCurrentCell(pd_tables[tab_index].rowCount() - 1, 0)
    elif get_row >= 0:
        pd_tables[tab_index].setCurrentCell(get_row, 0)

@QtCore.pyqtSlot(QtCore.QObject)
def remove_attack(HWSelect: QtCore.QObject):
    """
    Removes a row from the Attack table.
    """
    # Remove Row
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    attack_tables = [
        HWSelect.tableWidget_attack_1,
        HWSelect.tableWidget_attack_2,
        HWSelect.tableWidget_attack_3,
        HWSelect.tableWidget_attack_4,
        HWSelect.tableWidget_attack_5,
    ]
    get_row = attack_tables[tab_index].currentRow()
    attack_tables[tab_index].removeRow(get_row)
    if get_row == attack_tables[tab_index].rowCount():
        attack_tables[tab_index].setCurrentCell(attack_tables[tab_index].rowCount() - 1, 0)
    elif get_row >= 0:
        attack_tables[tab_index].setCurrentCell(get_row, 0)

@QtCore.pyqtSlot(QtCore.QObject)
def remove_iq(HWSelect: QtCore.QObject):
    """
    Removes a row from the IQ table.
    """
    # Remove Row
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    iq_tables = [
        HWSelect.tableWidget_iq_1,
        HWSelect.tableWidget_iq_2,
        HWSelect.tableWidget_iq_3,
        HWSelect.tableWidget_iq_4,
        HWSelect.tableWidget_iq_5,
    ]
    get_row = iq_tables[tab_index].currentRow()
    iq_tables[tab_index].removeRow(get_row)
    if get_row == iq_tables[tab_index].rowCount():
        iq_tables[tab_index].setCurrentCell(iq_tables[tab_index].rowCount() - 1, 0)
    elif get_row >= 0:
        iq_tables[tab_index].setCurrentCell(get_row, 0)

@QtCore.pyqtSlot(QtCore.QObject)
def remove_archive(HWSelect: QtCore.QObject):
    """
    Removes a row from the Archive table.
    """
    # Remove Row
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    archive_tables = [
        HWSelect.tableWidget_archive_1,
        HWSelect.tableWidget_archive_2,
        HWSelect.tableWidget_archive_3,
        HWSelect.tableWidget_archive_4,
        HWSelect.tableWidget_archive_5,
    ]
    get_row = archive_tables[tab_index].currentRow()
    archive_tables[tab_index].removeRow(get_row)
    if get_row == archive_tables[tab_index].rowCount():
        archive_tables[tab_index].setCurrentCell(archive_tables[tab_index].rowCount() - 1, 0)
    elif get_row >= 0:
        archive_tables[tab_index].setCurrentCell(get_row, 0)

@QtCore.pyqtSlot(QtCore.QObject)
def add_to_all(HWSelect: QtCore.QObject):
    """
    Adds the selected row in the scan results table to all the tables.
    """
    tsi(HWSelect)
    pd(HWSelect)
    attack(HWSelect)
    iq(HWSelect)
    archive(HWSelect)

@QtCore.pyqtSlot(QtCore.QObject)
def scan_results_remove(HWSelect: QtCore.QObject):
    """
    Removes a row from the scan results table.
    """
    # Remove Row
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    add_to_all_buttons = [
        HWSelect.pushButton_add_to_all_1,
        HWSelect.pushButton_add_to_all_2,
        HWSelect.pushButton_add_to_all_3,
        HWSelect.pushButton_add_to_all_4,
        HWSelect.pushButton_add_to_all_5,
    ]
    tsi_buttons = [
        HWSelect.pushButton_tsi_1,
        HWSelect.pushButton_tsi_2,
        HWSelect.pushButton_tsi_3,
        HWSelect.pushButton_tsi_4,
        HWSelect.pushButton_tsi_5,
    ]
    pd_buttons = [
        HWSelect.pushButton_pd_1,
        HWSelect.pushButton_pd_2,
        HWSelect.pushButton_pd_3,
        HWSelect.pushButton_pd_4,
        HWSelect.pushButton_pd_5,
    ]
    attack_buttons = [
        HWSelect.pushButton_attack_1,
        HWSelect.pushButton_attack_2,
        HWSelect.pushButton_attack_3,
        HWSelect.pushButton_attack_4,
        HWSelect.pushButton_attack_5,
    ]
    iq_buttons = [
        HWSelect.pushButton_iq_1,
        HWSelect.pushButton_iq_2,
        HWSelect.pushButton_iq_3,
        HWSelect.pushButton_iq_4,
        HWSelect.pushButton_iq_5,
    ]
    archive_buttons = [
        HWSelect.pushButton_archive_1,
        HWSelect.pushButton_archive_2,
        HWSelect.pushButton_archive_3,
        HWSelect.pushButton_archive_4,
        HWSelect.pushButton_archive_5,
    ]
    scan_results_remove_buttons = [
        HWSelect.pushButton_scan_results_remove_1,
        HWSelect.pushButton_scan_results_remove_2,
        HWSelect.pushButton_scan_results_remove_3,
        HWSelect.pushButton_scan_results_remove_4,
        HWSelect.pushButton_scan_results_remove_5,
    ]
    scan_results_probe_buttons = [
        HWSelect.pushButton_scan_results_probe_1,
        HWSelect.pushButton_scan_results_probe_2,
        HWSelect.pushButton_scan_results_probe_3,
        HWSelect.pushButton_scan_results_probe_4,
        HWSelect.pushButton_scan_results_probe_5,
    ]
    scan_results_guess_buttons = [
        HWSelect.pushButton_scan_results_guess_1,
        HWSelect.pushButton_scan_results_guess_2,
        HWSelect.pushButton_scan_results_guess_3,
        HWSelect.pushButton_scan_results_guess_4,
        HWSelect.pushButton_scan_results_guess_5,
    ]
    scan_results_tables = [
        HWSelect.tableWidget_scan_results_1,
        HWSelect.tableWidget_scan_results_2,
        HWSelect.tableWidget_scan_results_3,
        HWSelect.tableWidget_scan_results_4,
        HWSelect.tableWidget_scan_results_5,
    ]
    scan_results_lines = [
        HWSelect.line3_scan_results_1,
        HWSelect.line3_scan_results_2,
        HWSelect.line3_scan_results_3,
        HWSelect.line3_scan_results_4,
        HWSelect.line3_scan_results_5,
    ]

    get_row = scan_results_tables[tab_index].currentRow()
    scan_results_tables[tab_index].removeRow(get_row)
    if get_row == scan_results_tables[tab_index].rowCount():
        scan_results_tables[tab_index].setCurrentCell(scan_results_tables[tab_index].rowCount() - 1, 0)
    elif get_row >= 0:
        scan_results_tables[tab_index].setCurrentCell(get_row, 0)

    # Disable Push Buttons
    if scan_results_tables[tab_index].rowCount() == 0:
        add_to_all_buttons[tab_index].setEnabled(False)
        tsi_buttons[tab_index].setEnabled(False)
        pd_buttons[tab_index].setEnabled(False)
        attack_buttons[tab_index].setEnabled(False)
        iq_buttons[tab_index].setEnabled(False)
        archive_buttons[tab_index].setEnabled(False)
        scan_results_remove_buttons[tab_index].setEnabled(False)
        scan_results_probe_buttons[tab_index].setEnabled(False)
        scan_results_guess_buttons[tab_index].setEnabled(False)
        scan_results_tables[tab_index].setEnabled(False)
        scan_results_lines[tab_index].setEnabled(False)

@QtCore.pyqtSlot(QtCore.QObject)
def manual(HWSelect: QtCore.QObject):
    """
    Manually adds the checked hardware to the scan results table.
    """
    # Retrieve Widgets in Current Tab
    if HWSelect.tabWidget_nodes.currentIndex() == 0:
        get_listWidget = HWSelect.listWidget_scan_1
        get_tableWidget = HWSelect.tableWidget_scan_results_1
        get_pushButton_add_to_all = HWSelect.pushButton_add_to_all_1
        get_pushButton_tsi = HWSelect.pushButton_tsi_1
        get_pushButton_pd = HWSelect.pushButton_pd_1
        get_pushButton_attack = HWSelect.pushButton_attack_1
        get_pushButton_iq = HWSelect.pushButton_iq_1
        get_pushButton_archive = HWSelect.pushButton_archive_1
        get_pushButton_scan_results_remove = HWSelect.pushButton_scan_results_remove_1
        get_pushButton_scan_results_probe = HWSelect.pushButton_scan_results_probe_1
        get_pushButton_scan_results_guess = HWSelect.pushButton_scan_results_guess_1
        get_tableWidget_scan_results = HWSelect.tableWidget_scan_results_1
        get_line3_scan_results = HWSelect.line3_scan_results_1
    elif HWSelect.tabWidget_nodes.currentIndex() == 1:
        get_listWidget = HWSelect.listWidget_scan_2
        get_tableWidget = HWSelect.tableWidget_scan_results_2
        get_pushButton_add_to_all = HWSelect.pushButton_add_to_all_2
        get_pushButton_tsi = HWSelect.pushButton_tsi_2
        get_pushButton_pd = HWSelect.pushButton_pd_2
        get_pushButton_attack = HWSelect.pushButton_attack_2
        get_pushButton_iq = HWSelect.pushButton_iq_2
        get_pushButton_archive = HWSelect.pushButton_archive_2
        get_pushButton_scan_results_remove = HWSelect.pushButton_scan_results_remove_2
        get_pushButton_scan_results_probe = HWSelect.pushButton_scan_results_probe_2
        get_pushButton_scan_results_guess = HWSelect.pushButton_scan_results_guess_2
        get_tableWidget_scan_results = HWSelect.tableWidget_scan_results_2
        get_line3_scan_results = HWSelect.line3_scan_results_2
    elif HWSelect.tabWidget_nodes.currentIndex() == 2:
        get_listWidget = HWSelect.listWidget_scan_3
        get_tableWidget = HWSelect.tableWidget_scan_results_3
        get_pushButton_add_to_all = HWSelect.pushButton_add_to_all_3
        get_pushButton_tsi = HWSelect.pushButton_tsi_3
        get_pushButton_pd = HWSelect.pushButton_pd_3
        get_pushButton_attack = HWSelect.pushButton_attack_3
        get_pushButton_iq = HWSelect.pushButton_iq_3
        get_pushButton_archive = HWSelect.pushButton_archive_3
        get_pushButton_scan_results_remove = HWSelect.pushButton_scan_results_remove_3
        get_pushButton_scan_results_probe = HWSelect.pushButton_scan_results_probe_3
        get_pushButton_scan_results_guess = HWSelect.pushButton_scan_results_guess_3
        get_tableWidget_scan_results = HWSelect.tableWidget_scan_results_3
        get_line3_scan_results = HWSelect.line3_scan_results_3
    elif HWSelect.tabWidget_nodes.currentIndex() == 3:
        get_listWidget = HWSelect.listWidget_scan_4
        get_tableWidget = HWSelect.tableWidget_scan_results_4
        get_pushButton_add_to_all = HWSelect.pushButton_add_to_all_4
        get_pushButton_tsi = HWSelect.pushButton_tsi_4
        get_pushButton_pd = HWSelect.pushButton_pd_4
        get_pushButton_attack = HWSelect.pushButton_attack_4
        get_pushButton_iq = HWSelect.pushButton_iq_4
        get_pushButton_archive = HWSelect.pushButton_archive_4
        get_pushButton_scan_results_remove = HWSelect.pushButton_scan_results_remove_4
        get_pushButton_scan_results_probe = HWSelect.pushButton_scan_results_probe_4
        get_pushButton_scan_results_guess = HWSelect.pushButton_scan_results_guess_4
        get_tableWidget_scan_results = HWSelect.tableWidget_scan_results_4
        get_line3_scan_results = HWSelect.line3_scan_results_4
    elif HWSelect.tabWidget_nodes.currentIndex() == 4:
        get_listWidget = HWSelect.listWidget_scan_5
        get_tableWidget = HWSelect.tableWidget_scan_results_5
        get_pushButton_add_to_all = HWSelect.pushButton_add_to_all_5
        get_pushButton_tsi = HWSelect.pushButton_tsi_5
        get_pushButton_pd = HWSelect.pushButton_pd_5
        get_pushButton_attack = HWSelect.pushButton_attack_5
        get_pushButton_iq = HWSelect.pushButton_iq_5
        get_pushButton_archive = HWSelect.pushButton_archive_5
        get_pushButton_scan_results_remove = HWSelect.pushButton_scan_results_remove_5
        get_pushButton_scan_results_probe = HWSelect.pushButton_scan_results_probe_5
        get_pushButton_scan_results_guess = HWSelect.pushButton_scan_results_guess_5
        get_tableWidget_scan_results = HWSelect.tableWidget_scan_results_5
        get_line3_scan_results = HWSelect.line3_scan_results_5

    # Fill Scan Results Table with Checked Items
    for n in range(0, get_listWidget.count()):
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

@QtCore.pyqtSlot(QtCore.QObject)
def more(HWSelect: QtCore.QObject):
    """ 
    Moves the sensor node details stacked widget to the next page.
    """
    # Move Page to the Right
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    stacked_widgets = [HWSelect.stackedWidget_details_1, HWSelect.stackedWidget_details_2, HWSelect.stackedWidget_details_3, HWSelect.stackedWidget_details_4, HWSelect.stackedWidget_details_5]
    new_index = stacked_widgets[tab_index].currentIndex() + 1
    get_count = stacked_widgets[tab_index].count()

    if new_index >= get_count:
        stacked_widgets[tab_index].setCurrentIndex(0)
    else:
        stacked_widgets[tab_index].setCurrentIndex(new_index)


@QtCore.pyqtSlot(QtCore.QObject)
def local(HWSelect: QtCore.QObject, tab_index=0):
    """
    Switch to Local Sensor Node configuration page

    TODO: Fix this
    """
    # node_idx = HWSelect.tabWidget_nodes.currentIndex() + 1
    # page_widget: QtWidgets.QStackedWidget = getattr(HWSelect, f"stackedWidget_local_remote_{node_idx}")
    # target_widget: QtWidgets.QWidget = getattr(HWSelect, f"page_local_{node_idx}")
    # page_widget.setCurrentWidget(target_widget)

    # Local
    if tab_index == 0:
        HWSelect.textEdit_ip_addr_1.setEnabled(False)
        HWSelect.textEdit_msg_port_1.setEnabled(False)
        HWSelect.textEdit_hb_port_1.setEnabled(False)
        HWSelect.pushButton_ping_1.setEnabled(False)
        HWSelect.pushButton_connect_1.setEnabled(False)
        HWSelect.label2_ip_addr_1.setEnabled(False)
        HWSelect.label2_msg_port_1.setEnabled(False)
        HWSelect.label2_hb_port_1.setEnabled(False)
        HWSelect.checkBox_recall_settings_remote_1.setEnabled(False)
        HWSelect.label2_nickname_1.setEnabled(False)
        HWSelect.textEdit_nickname_1.setEnabled(False)
        HWSelect.textEdit_nickname_1.setPlainText("Local Sensor Node")
        # HWSelect.label2_location_1.setEnabled(False)
        # HWSelect.textEdit_location_1.setEnabled(False)
        # HWSelect.label2_notes_1.setEnabled(False)
        # HWSelect.textEdit_notes_1.setEnabled(False)
        # HWSelect.line1_remote_details.setEnabled(False)
        if HWSelect.stackedWidget_local_remote_1.currentIndex() == 1:
            HWSelect.stackedWidget_local_remote_1.setCurrentIndex(0)
    elif tab_index == 1:
        HWSelect.textEdit_ip_addr_2.setEnabled(False)
        HWSelect.textEdit_msg_port_2.setEnabled(False)
        HWSelect.textEdit_hb_port_2.setEnabled(False)
        HWSelect.pushButton_ping_2.setEnabled(False)
        HWSelect.pushButton_connect_2.setEnabled(False)
        HWSelect.label2_ip_addr_2.setEnabled(False)
        HWSelect.label2_msg_port_2.setEnabled(False)
        HWSelect.label2_hb_port_2.setEnabled(False)
        HWSelect.checkBox_recall_settings_remote_2.setEnabled(False)
        HWSelect.label2_nickname_2.setEnabled(False)
        HWSelect.textEdit_nickname_2.setEnabled(False)
        HWSelect.textEdit_nickname_2.setPlainText("Local Sensor Node")
        # HWSelect.label2_location_2.setEnabled(False)
        # HWSelect.textEdit_location_2.setEnabled(False)
        # HWSelect.label2_notes_2.setEnabled(False)
        # HWSelect.textEdit_notes_2.setEnabled(False)
        # HWSelect.line1_remote_details1.setEnabled(False)
        if HWSelect.stackedWidget_local_remote_2.currentIndex() == 1:
            HWSelect.stackedWidget_local_remote_2.setCurrentIndex(0)
    elif tab_index == 2:
        HWSelect.textEdit_ip_addr_3.setEnabled(False)
        HWSelect.textEdit_msg_port_3.setEnabled(False)
        HWSelect.textEdit_hb_port_3.setEnabled(False)
        HWSelect.pushButton_ping_3.setEnabled(False)
        HWSelect.pushButton_connect_3.setEnabled(False)
        HWSelect.label2_ip_addr_3.setEnabled(False)
        HWSelect.label2_msg_port_3.setEnabled(False)
        HWSelect.label2_hb_port_3.setEnabled(False)
        HWSelect.checkBox_recall_settings_remote_3.setEnabled(False)
        HWSelect.label2_nickname_3.setEnabled(False)
        HWSelect.textEdit_nickname_3.setEnabled(False)
        HWSelect.textEdit_nickname_3.setPlainText("Local Sensor Node")
        # HWSelect.label2_location_3.setEnabled(False)
        # HWSelect.textEdit_location_3.setEnabled(False)
        # HWSelect.label2_notes_3.setEnabled(False)
        # HWSelect.textEdit_notes_3.setEnabled(False)
        # HWSelect.line1_remote_details2.setEnabled(False)
        if HWSelect.stackedWidget_local_remote_3.currentIndex() == 1:
            HWSelect.stackedWidget_local_remote_3.setCurrentIndex(0)
    elif tab_index == 3:
        HWSelect.textEdit_ip_addr_4.setEnabled(False)
        HWSelect.textEdit_msg_port_4.setEnabled(False)
        HWSelect.textEdit_hb_port_4.setEnabled(False)
        HWSelect.pushButton_ping_4.setEnabled(False)
        HWSelect.pushButton_connect_4.setEnabled(False)
        HWSelect.label2_ip_addr_4.setEnabled(False)
        HWSelect.label2_msg_port_4.setEnabled(False)
        HWSelect.label2_hb_port_4.setEnabled(False)
        HWSelect.checkBox_recall_settings_remote_4.setEnabled(False)
        HWSelect.label2_nickname_4.setEnabled(False)
        HWSelect.textEdit_nickname_4.setEnabled(False)
        HWSelect.textEdit_nickname_4.setPlainText("Local Sensor Node")
        # HWSelect.label2_location_4.setEnabled(False)
        # HWSelect.textEdit_location_4.setEnabled(False)
        # HWSelect.label2_notes_4.setEnabled(False)
        # HWSelect.textEdit_notes_4.setEnabled(False)
        # HWSelect.line1_remote_details3.setEnabled(False)
        if HWSelect.stackedWidget_local_remote_4.currentIndex() == 1:
            HWSelect.stackedWidget_local_remote_4.setCurrentIndex(0)
    elif tab_index == 4:
        HWSelect.textEdit_ip_addr_5.setEnabled(False)
        HWSelect.textEdit_msg_port_5.setEnabled(False)
        HWSelect.textEdit_hb_port_5.setEnabled(False)
        HWSelect.pushButton_ping_5.setEnabled(False)
        HWSelect.pushButton_connect_5.setEnabled(False)
        HWSelect.label2_ip_addr_5.setEnabled(False)
        HWSelect.label2_msg_port_5.setEnabled(False)
        HWSelect.label2_hb_port_5.setEnabled(False)
        HWSelect.checkBox_recall_settings_remote_5.setEnabled(False)
        HWSelect.label2_nickname_5.setEnabled(False)
        HWSelect.textEdit_nickname_5.setEnabled(False)
        HWSelect.textEdit_nickname_5.setPlainText("Local Sensor Node")
        # HWSelect.label2_location_5.setEnabled(False)
        # HWSelect.textEdit_location_5.setEnabled(False)
        # HWSelect.label2_notes_5.setEnabled(False)
        # HWSelect.textEdit_notes_5.setEnabled(False)
        # HWSelect.line1_remote_details4.setEnabled(False)
        if HWSelect.stackedWidget_local_remote_5.currentIndex() == 1:
            HWSelect.stackedWidget_local_remote_5.setCurrentIndex(0)


@QtCore.pyqtSlot(QtCore.QObject)
def remote(HWSelect: QtCore.QObject, tab_index=0):
    """
    Switch to Local Sensor Node configuration page

    TODO: Fix this
    """
    # node_idx = HWSelect.tabWidget_nodes.currentIndex() + 1
    # page_widget: QtWidgets.QStackedWidget = getattr(HWSelect, f"stackedWidget_local_remote_{node_idx}")
    # target_widget: QtWidgets.QWidget = getattr(HWSelect, f"page_remote_{node_idx}")
    # HWSelect.dashboard.logger.info(f"page = {page_widget}, target = {target_widget}")
    # page_widget.setCurrentWidget(target_widget)
    # remote_widget = page_widget.widget(1)
    # remote_widget.show()
    # HWSelect.dashboard.logger.info(f"remote = {remote_widget}")

    # Remote
    if tab_index == 0:
        HWSelect.textEdit_ip_addr_1.setEnabled(True)
        HWSelect.textEdit_msg_port_1.setEnabled(True)
        HWSelect.textEdit_hb_port_1.setEnabled(True)
        HWSelect.pushButton_ping_1.setEnabled(True)
        HWSelect.pushButton_connect_1.setEnabled(True)
        HWSelect.label2_ip_addr_1.setEnabled(True)
        HWSelect.label2_msg_port_1.setEnabled(True)
        HWSelect.label2_hb_port_1.setEnabled(True)
        HWSelect.checkBox_recall_settings_remote_1.setEnabled(True)
        HWSelect.label2_nickname_1.setEnabled(True)
        HWSelect.textEdit_nickname_1.setEnabled(True)
        HWSelect.textEdit_nickname_1.setPlainText("")
        HWSelect.label2_location_1.setEnabled(True)
        HWSelect.textEdit_location_1.setEnabled(True)
        HWSelect.label2_notes_1.setEnabled(True)
        HWSelect.textEdit_notes_1.setEnabled(True)
        # HWSelect.line1_remote_details.setEnabled(True)
        if HWSelect.stackedWidget_local_remote_1.currentIndex() == 0:  # Change on local clicked, not on import/recall/disconnect
            HWSelect.stackedWidget_local_remote_1.setCurrentIndex(1)
    elif tab_index == 1:
        HWSelect.textEdit_ip_addr_2.setEnabled(True)
        HWSelect.textEdit_msg_port_2.setEnabled(True)
        HWSelect.textEdit_hb_port_2.setEnabled(True)
        HWSelect.pushButton_ping_2.setEnabled(True)
        HWSelect.pushButton_connect_2.setEnabled(True)
        HWSelect.label2_ip_addr_2.setEnabled(True)
        HWSelect.label2_msg_port_2.setEnabled(True)
        HWSelect.label2_hb_port_2.setEnabled(True)
        HWSelect.checkBox_recall_settings_remote_2.setEnabled(True)
        HWSelect.label2_nickname_2.setEnabled(True)
        HWSelect.textEdit_nickname_2.setEnabled(True)
        HWSelect.textEdit_nickname_2.setPlainText("")
        HWSelect.label2_location_2.setEnabled(True)
        HWSelect.textEdit_location_2.setEnabled(True)
        HWSelect.label2_notes_2.setEnabled(True)
        HWSelect.textEdit_notes_2.setEnabled(True)
        # HWSelect.line1_remote_details1.setEnabled(True)
        if HWSelect.stackedWidget_local_remote_2.currentIndex() == 0:
            HWSelect.stackedWidget_local_remote_2.setCurrentIndex(1)
    elif tab_index == 2:
        HWSelect.textEdit_ip_addr_3.setEnabled(True)
        HWSelect.textEdit_msg_port_3.setEnabled(True)
        HWSelect.textEdit_hb_port_3.setEnabled(True)
        HWSelect.pushButton_ping_3.setEnabled(True)
        HWSelect.pushButton_connect_3.setEnabled(True)
        HWSelect.label2_ip_addr_3.setEnabled(True)
        HWSelect.label2_msg_port_3.setEnabled(True)
        HWSelect.label2_hb_port_3.setEnabled(True)
        HWSelect.checkBox_recall_settings_remote_3.setEnabled(True)
        HWSelect.label2_nickname_3.setEnabled(True)
        HWSelect.textEdit_nickname_3.setEnabled(True)
        HWSelect.textEdit_nickname_3.setPlainText("")
        HWSelect.label2_location_3.setEnabled(True)
        HWSelect.textEdit_location_3.setEnabled(True)
        HWSelect.label2_notes_3.setEnabled(True)
        HWSelect.textEdit_notes_3.setEnabled(True)
        # HWSelect.line1_remote_details2.setEnabled(True)
        if HWSelect.stackedWidget_local_remote_3.currentIndex() == 0:
            HWSelect.stackedWidget_local_remote_3.setCurrentIndex(1)
    elif tab_index == 3:
        HWSelect.textEdit_ip_addr_4.setEnabled(True)
        HWSelect.textEdit_msg_port_4.setEnabled(True)
        HWSelect.textEdit_hb_port_4.setEnabled(True)
        HWSelect.pushButton_ping_4.setEnabled(True)
        HWSelect.pushButton_connect_4.setEnabled(True)
        HWSelect.label2_ip_addr_4.setEnabled(True)
        HWSelect.label2_msg_port_4.setEnabled(True)
        HWSelect.label2_hb_port_4.setEnabled(True)
        HWSelect.checkBox_recall_settings_remote_4.setEnabled(True)
        HWSelect.label2_nickname_4.setEnabled(True)
        HWSelect.textEdit_nickname_4.setEnabled(True)
        HWSelect.textEdit_nickname_4.setPlainText("")
        HWSelect.label2_location_4.setEnabled(True)
        HWSelect.textEdit_location_4.setEnabled(True)
        HWSelect.label2_notes_4.setEnabled(True)
        HWSelect.textEdit_notes_4.setEnabled(True)
        # HWSelect.line1_remote_details3.setEnabled(True)
        if HWSelect.stackedWidget_local_remote_4.currentIndex() == 0:
            HWSelect.stackedWidget_local_remote_4.setCurrentIndex(1)
    elif tab_index == 4:
        HWSelect.textEdit_ip_addr_5.setEnabled(True)
        HWSelect.textEdit_msg_port_5.setEnabled(True)
        HWSelect.textEdit_hb_port_5.setEnabled(True)
        HWSelect.pushButton_ping_5.setEnabled(True)
        HWSelect.pushButton_connect_5.setEnabled(True)
        HWSelect.label2_ip_addr_5.setEnabled(True)
        HWSelect.label2_msg_port_5.setEnabled(True)
        HWSelect.label2_hb_port_5.setEnabled(True)
        HWSelect.checkBox_recall_settings_remote_5.setEnabled(True)
        HWSelect.label2_nickname_5.setEnabled(True)
        HWSelect.textEdit_nickname_5.setEnabled(True)
        HWSelect.textEdit_nickname_5.setPlainText("")
        HWSelect.label2_location_5.setEnabled(True)
        HWSelect.textEdit_location_5.setEnabled(True)
        HWSelect.label2_notes_5.setEnabled(True)
        HWSelect.textEdit_notes_5.setEnabled(True)
        # HWSelect.line1_remote_details4.setEnabled(True)
        if HWSelect.stackedWidget_local_remote_5.currentIndex() == 0:
            HWSelect.stackedWidget_local_remote_5.setCurrentIndex(1)


@qasync.asyncSlot(QtCore.QObject)
async def launch(HWSelect: QtCore.QObject):
    """ 
    Launches and then connects to a local sensor node.
    """
    # Get Widgets and Values
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    recall_settings_widgets = [HWSelect.checkBox_recall_settings_local_1,HWSelect.checkBox_recall_settings_local_2,HWSelect.checkBox_recall_settings_local_3,HWSelect.checkBox_recall_settings_local_4,HWSelect.checkBox_recall_settings_local_5]
    launch_widgets = [HWSelect.pushButton_launch_1,HWSelect.pushButton_launch_2,HWSelect.pushButton_launch_3,HWSelect.pushButton_launch_4,HWSelect.pushButton_launch_5]
    get_ip = 'ipc'
    get_msg_port = "ipc:///tmp/zmq_ipc_message"
    get_hb_port = "ipc:///tmp/zmq_ipc_heartbeat"
    get_recall_settings = str(recall_settings_widgets[tab_index].isChecked())
    
    # Disable Buttons
    launch_widgets[tab_index].setEnabled(False)
    recall_settings_widgets[tab_index].setEnabled(False)
    QtWidgets.QApplication.processEvents()
    
    # Connect
    os.system('python3 "' + os.path.join(fissure.utils.SENSOR_NODE_DIR, "SensorNode.py") + '" --local &')
    HWSelect.dashboard.logger.info("Launching local sensor node, please wait...")
    await asyncio.sleep(9)
    # time.sleep(1)
 
    # Send Message for HIPRFISR to Sensor Node Connections
    await HWSelect.dashboard.backend.launch_local_sensor_node(str(tab_index), get_ip, get_msg_port, get_hb_port, get_recall_settings)


@qasync.asyncSlot(QtCore.QObject)
async def ping(HWSelect: QtCore.QObject):
    """
    Send command to HiprFisr to ping the host running the Sensor Node and await response
    """
    # Ping IP Address
    if HWSelect.tabWidget_nodes.currentIndex() == 0:
        get_ip = str(HWSelect.textEdit_ip_addr_1.toPlainText())
    elif HWSelect.tabWidget_nodes.currentIndex() == 1:
        get_ip = str(HWSelect.textEdit_ip_addr_2.toPlainText())
    elif HWSelect.tabWidget_nodes.currentIndex() == 2:
        get_ip = str(HWSelect.textEdit_ip_addr_3.toPlainText())
    elif HWSelect.tabWidget_nodes.currentIndex() == 3:
        get_ip = str(HWSelect.textEdit_ip_addr_4.toPlainText())
    elif HWSelect.tabWidget_nodes.currentIndex() == 4:
        get_ip = str(HWSelect.textEdit_ip_addr_5.toPlainText())
    response = os.system("ping -c 1 " + get_ip)
    if response == 0:
        HWSelect.dashboard.logger.info(get_ip + " is up!")
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(HWSelect.dashboard, get_ip + " is up!")
    else:
        HWSelect.dashboard.logger.info(get_ip + " is down!")
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(HWSelect.dashboard, get_ip + " is down!")


@qasync.asyncSlot(QtCore.QObject)
async def connect(HWSelect: QtCore.QObject):
    """
    Connects to the remote sensor node using the IP address and ports.
    """
    # Connect
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    ip_widgets = [
        HWSelect.textEdit_ip_addr_1, 
        HWSelect.textEdit_ip_addr_2, 
        HWSelect.textEdit_ip_addr_3, 
        HWSelect.textEdit_ip_addr_4, 
        HWSelect.textEdit_ip_addr_5
    ]
    msg_port_widgets = [
        HWSelect.textEdit_msg_port_1,
        HWSelect.textEdit_msg_port_2,
        HWSelect.textEdit_msg_port_3,
        HWSelect.textEdit_msg_port_4,
        HWSelect.textEdit_msg_port_5,
    ]
    hb_port_widgets = [
        HWSelect.textEdit_hb_port_1,
        HWSelect.textEdit_hb_port_2,
        HWSelect.textEdit_hb_port_3,
        HWSelect.textEdit_hb_port_4,
        HWSelect.textEdit_hb_port_5,
    ]
    recall_settings_widgets = [
        HWSelect.checkBox_recall_settings_remote_1,
        HWSelect.checkBox_recall_settings_remote_2,
        HWSelect.checkBox_recall_settings_remote_3,
        HWSelect.checkBox_recall_settings_remote_4,
        HWSelect.checkBox_recall_settings_remote_5,
    ]
    connect_widgets = [
        HWSelect.pushButton_connect_1,
        HWSelect.pushButton_connect_2,
        HWSelect.pushButton_connect_3,
        HWSelect.pushButton_connect_4,
        HWSelect.pushButton_connect_5,
    ]

    get_ip = str(ip_widgets[tab_index].toPlainText())
    get_msg_port = str(msg_port_widgets[tab_index].toPlainText())
    get_hb_port = str(hb_port_widgets[tab_index].toPlainText())
    get_recall_settings = str(recall_settings_widgets[tab_index].isChecked())

    # Check Existing IPs
    get_sensor_node = ["sensor_node1", "sensor_node2", "sensor_node3", "sensor_node4", "sensor_node5"]
    for n in range(0, len(get_sensor_node)):
        if (get_ip == HWSelect.dashboard.backend.settings[get_sensor_node[n]]["ip_address"]) and (n != tab_index):
            ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(HWSelect.dashboard, "IP address already in use.")
            return

    # Disable Buttons
    connect_widgets[tab_index].setEnabled(False)
    recall_settings_widgets[tab_index].setEnabled(False)
    ip_widgets[tab_index].setEnabled(False)
    msg_port_widgets[tab_index].setEnabled(False)
    hb_port_widgets[tab_index].setEnabled(False)
    QtWidgets.QApplication.processEvents()

    # # Dashboard SUB to Sensor Node TSI Detector Flow Graph PUB
    # try:
    # HWSelect.parent.dashboard_sub_listener.initialize_port(get_ip,int(HWSelect.dashboard.backend.settings['tsi_hb_port_id']))
    # except:
    # print("Unable to subscribe Dashboard SUB to TSI Detector Flow Graph PUB")

    # # Dashboard SUB to Sensor Node PUB
    # try:
    # HWSelect.parent.dashboard_sub_listener.initialize_port(get_ip,get_hb_port)
    # except:
    # print("Unable to subscribe Dashboard SUB to Sensor Node PUB")

    # Send Message for HIPRFISR to Sensor Node Connections
    await HWSelect.dashboard.backend.connect_remote_sensor_node(str(tab_index), get_ip, get_msg_port, get_hb_port, get_recall_settings)

    # # Check for Connection
    # click_time = time.time()
    # while time.time() - click_time < 10:
    #     if tab_index == 0:
    #         if HWSelect.dashboard.statusBar().sensor_nodes[0].text() == "SN1: OK":
    #             return
    #     elif tab_index == 1:
    #         if HWSelect.dashboard.statusBar().sensor_nodes[1].text() == "SN2: OK":
    #             return
    #     elif tab_index == 2:
    #         if HWSelect.dashboard.statusBar().sensor_nodes[2].text() == "SN3: OK":
    #             return
    #     elif tab_index == 3:
    #         if HWSelect.dashboard.statusBar().sensor_nodes[3].text() == "SN4: OK":
    #             return
    #     elif tab_index == 4:
    #         if HWSelect.dashboard.statusBar().sensor_nodes[4].text() == "SN5: OK":
    #             return
    #     time.sleep(0.1)
    #     QtWidgets.QApplication.processEvents()

    # # Enable Buttons after Timeout
    # print("TIMEOUT")
    # connect_widgets[tab_index].setEnabled(True)
    # recall_settings_widgets[tab_index].setEnabled(True)
    # ip_widgets[tab_index].setEnabled(True)
    # msg_port_widgets[tab_index].setEnabled(True)
    # hb_port_widgets[tab_index].setEnabled(True)


@qasync.asyncSlot(QtCore.QObject)
async def disconnect(HWSelect: QtCore.QObject, delete_node=False):
    """
    Send command to HiprFisr to disconnect from remote Sensor Node
    OR
    Disconnect/Shutdown local Sensor Node
    """
    # Disconnect
    tab_index = HWSelect.tabWidget_nodes.currentIndex()
    stacked_widgets = [
        HWSelect.stackedWidget_local_remote_1,
        HWSelect.stackedWidget_local_remote_2,
        HWSelect.stackedWidget_local_remote_3,
        HWSelect.stackedWidget_local_remote_4,
        HWSelect.stackedWidget_local_remote_5,
    ]
    local_buttons = [
        HWSelect.radioButton_local_1,
        HWSelect.radioButton_local_2,
        HWSelect.radioButton_local_3,
        HWSelect.radioButton_local_4,
        HWSelect.radioButton_local_5,
    ]

    # Local
    if local_buttons[tab_index].isChecked():
        stacked_widgets[tab_index].setCurrentIndex(0)
        await HWSelect.dashboard.backend.disconnect_local_sensor_node(str(tab_index))

    # Remote
    else:
        ip_widgets = [
            HWSelect.textEdit_ip_addr_1,
            HWSelect.textEdit_ip_addr_2,
            HWSelect.textEdit_ip_addr_3,
            HWSelect.textEdit_ip_addr_4,
            HWSelect.textEdit_ip_addr_5
        ]
        msg_port_widgets = [
            HWSelect.textEdit_msg_port_1,
            HWSelect.textEdit_msg_port_2,
            HWSelect.textEdit_msg_port_3,
            HWSelect.textEdit_msg_port_4,
            HWSelect.textEdit_msg_port_5,
        ]
        hb_port_widgets = [
            HWSelect.textEdit_hb_port_1,
            HWSelect.textEdit_hb_port_2,
            HWSelect.textEdit_hb_port_3,
            HWSelect.textEdit_hb_port_4,
            HWSelect.textEdit_hb_port_5,
        ]

        get_ip = str(ip_widgets[tab_index].toPlainText())
        get_msg_port = str(msg_port_widgets[tab_index].toPlainText())
        get_hb_port = str(hb_port_widgets[tab_index].toPlainText())

        stacked_widgets[tab_index].setCurrentIndex(1)

        # # Disconnect Dashboard SUB from Sensor Node PUB
        # try:
        # HWSelect.parent.dashboard_sub_listener.disconnect_port(get_ip,get_hb_port)
        # except:
        # pass

        # # Disconnect Dashboard SUB from Sensor Node TSI Flow Graph PUB
        # try:
        # HWSelect.parent.dashboard_sub_listener.disconnect_port(get_ip,HWSelect.dashboard.backend.settings['tsi_hb_port_id'])
        # except:
        # pass

        # # Send Message to HIPRFISR
        # PARAMETERS = {
        #     "sensor_node_id": str(tab_index),
        #     "ip_address": get_ip,
        #     "hb_port": get_hb_port,
        #     "delete_node": delete_node,
        # }
        # msg = {
        #     fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
        #     fissure.comms.MessageFields.MESSAGE_NAME: "Disconnect from Sensor Node",
        #     fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        # }
        # HWSelect.parent.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

        # Send Message for HIPRFISR to Sensor Node Connections
        await HWSelect.dashboard.backend.disconnect_remote_sensor_node(str(tab_index), get_ip, get_msg_port, get_hb_port, delete_node)

@QtCore.pyqtSlot(QtCore.QObject)
def remove_all(HWSelect: QtCore.QObject):
    """
    Removes all rows from the Default Hardware Assignments tables.
    """
    node_idx = HWSelect.tabWidget_nodes.currentIndex() + 1
    HWSelect.dashboard.logger.debug(f"removing all table rows from 'Sensor Node {node_idx}")
    for table in ["tsi", "pd", "attack", "iq", "archive"]:
        table_widget = getattr(HWSelect, f"tableWidget_{table}_{node_idx}")
        table_widget.setRowCount(0)

@QtCore.pyqtSlot(QtCore.QObject)
def apply(HWSelect: QtCore.QObject):
    """
    Save Sensor Node chages and close the window
    """
    button: QtWidgets.QPushButton = HWSelect.pushButton_apply
    button.setCheckable(True)

    button.setChecked(True)
    HWSelect.dashboard.logger.debug("[Apply] Clicked")
    time.sleep(0.5)
    button.setChecked(False)

    top_button_widgets = [
        HWSelect.dashboard.ui.pushButton_top_node1,
        HWSelect.dashboard.ui.pushButton_top_node2,
        HWSelect.dashboard.ui.pushButton_top_node3,
        HWSelect.dashboard.ui.pushButton_top_node4,
        HWSelect.dashboard.ui.pushButton_top_node5
        ]

    for node_idx in range(1, 6):
        if len(HWSelect.tabWidget_nodes.tabText(node_idx-1)) > 0:
            nickname_widget: QtWidgets.QTextEdit = getattr(HWSelect, f"textEdit_nickname_{node_idx}")
            location_widget: QtWidgets.QTextEdit = getattr(HWSelect, f"textEdit_location_{node_idx}")
            notes_widget: QtWidgets.QTextEdit = getattr(HWSelect, f"textEdit_notes_{node_idx}")
            ip_addr_widget: QtWidgets.QTextEdit = getattr(HWSelect, f"textEdit_ip_addr_{node_idx}")
            hb_port_widget: QtWidgets.QTextEdit = getattr(HWSelect, f"textEdit_hb_port_{node_idx}")
            msg_port_widget: QtWidgets.QTextEdit = getattr(HWSelect, f"textEdit_msg_port_{node_idx}")
            local_button: QtWidgets.QRadioButton = getattr(HWSelect, f"radioButton_local_{node_idx}")
            tsi_widget: QtWidgets.QTableWidget = getattr(HWSelect, f"tableWidget_tsi_{node_idx}")
            pd_widget: QtWidgets.QTableWidget = getattr(HWSelect, f"tableWidget_pd_{node_idx}")
            attack_widget: QtWidgets.QTableWidget = getattr(HWSelect, f"tableWidget_attack_{node_idx}")
            iq_widget: QtWidgets.QTableWidget = getattr(HWSelect, f"tableWidget_iq_{node_idx}")
            archive_widget: QtWidgets.QTableWidget = getattr(HWSelect, f"tableWidget_archive_{node_idx}")
            autorun_widget: QtWidgets.QLabel = getattr(HWSelect, f"label2_autorun_value_{node_idx}")
            autorun_delay_widget: QtWidgets.QLabel = getattr(HWSelect, f"label2_autorun_delay_value_{node_idx}")
            console_logging_level_widget: QtWidgets.QLabel = getattr(HWSelect, f"label2_console_logging_level_value_{node_idx}")
            file_logging_level_widget: QtWidgets.QLabel = getattr(HWSelect, f"label2_file_logging_level_value_{node_idx}")
            
            # Check for Valid Values Before Saving
            if local_button.isChecked() is False:
                if len(nickname_widget.toPlainText()) == 0:
                    fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a nickname for the remote sensor node.")
                    return
                if len(ip_addr_widget.toPlainText()) == 0:
                    fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter an IP Address for the remote sensor node.")
                    return
                if len(msg_port_widget.toPlainText()) == 0:
                    fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a message port for the remote sensor node.")
                    return
                if len(hb_port_widget.toPlainText()) == 0:
                    fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a heartbeat port for the remote sensor node.")
                    return
                get_msg_port = msg_port_widget.toPlainText()
                if not (get_msg_port.isdigit() and 1 <= int(get_msg_port) <= 65535):
                    fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a valid message port (1-65535).")
                    return
                get_hb_port = hb_port_widget.toPlainText()
                if not (get_hb_port.isdigit() and 1 <= int(get_hb_port) <= 65535):
                    fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a valid heartbeat port (1-65535).")
                    return

            # TSI Default Hardware Assignments
            columns = range(tsi_widget.columnCount())
            tsi_info = []
            for row in range(tsi_widget.rowCount()):
                row_text = []
                for column in columns:
                    try:
                        get_text = str(tsi_widget.item(row, column).text())
                    except:
                        get_text = ""
                    row_text.append(get_text)
                tsi_info.append(row_text)

            # PD Default Hardware Assignments
            columns = range(pd_widget.columnCount())
            pd_info = []
            for row in range(pd_widget.rowCount()):
                row_text = []
                for column in columns:
                    try:
                        get_text = str(pd_widget.item(row, column).text())
                    except:
                        get_text = ""
                    row_text.append(get_text)
                pd_info.append(row_text)

            # Attack Default Hardware Assignments
            columns = range(attack_widget.columnCount())
            attack_info = []
            for row in range(attack_widget.rowCount()):
                row_text = []
                for column in columns:
                    try:
                        get_text = str(attack_widget.item(row, column).text())
                    except:
                        get_text = ""
                    row_text.append(get_text)
                attack_info.append(row_text)

            # IQ Default Hardware Assignments
            columns = range(iq_widget.columnCount())
            iq_info = []
            for row in range(iq_widget.rowCount()):
                row_text = []
                for column in columns:
                    try:
                        get_text = str(iq_widget.item(row, column).text())
                    except:
                        get_text = ""
                    row_text.append(get_text)
                iq_info.append(row_text)

            # Archive Default Hardware Assignments
            columns = range(archive_widget.columnCount())
            archive_info = []
            for row in range(archive_widget.rowCount()):
                row_text = []
                for column in columns:
                    try:
                        get_text = str(archive_widget.item(row, column).text())
                    except:
                        get_text = ""
                    row_text.append(get_text)
                archive_info.append(row_text)

            node_config = {
                "nickname": nickname_widget.toPlainText(),
                "location": location_widget.toPlainText(),
                "notes": notes_widget.toPlainText(),
                "ip_address": ip_addr_widget.toPlainText(),
                "hb_port": hb_port_widget.toPlainText(),
                "msg_port": msg_port_widget.toPlainText(),
                "local_remote": "local" if local_button.isChecked() else "remote",
                "autorun": autorun_widget.text(),
                "autorun_delay_seconds": autorun_delay_widget.text(),
                "console_logging_level": console_logging_level_widget.text(),
                "file_logging_level": file_logging_level_widget.text(),
                "tsi": tsi_info,
                "pd": pd_info,
                "attack": attack_info,
                "iq": iq_info,
                "archive": archive_info,
            }

            HWSelect.dashboard.backend.settings.update({f"sensor_node{node_idx}": node_config})

            # Update Top Bar
            if local_button.isChecked() == True:
                top_button_widgets[node_idx-1].setText("Local Sensor Node")
            else:
                top_button_widgets[node_idx-1].setText(nickname_widget.toPlainText())
            top_button_widgets[node_idx-1].setVisible(True)

    # Enable the Next Top Button
    if len(HWSelect.dashboard.backend.settings['sensor_node2']['nickname']) == 0:
        HWSelect.dashboard.ui.pushButton_top_node2.setVisible(True)
        HWSelect.dashboard.ui.pushButton_top_node2.setText("New Sensor Node")
        HWSelect.dashboard.ui.pushButton_top_node3.setVisible(False)
        HWSelect.dashboard.ui.pushButton_top_node4.setVisible(False)
        HWSelect.dashboard.ui.pushButton_top_node5.setVisible(False)        
        fissure.Dashboard.Slots.TopBarSlots.sensor_node_rightClick(HWSelect.dashboard, node_idx=0)
    elif len(HWSelect.dashboard.backend.settings['sensor_node3']['nickname']) == 0:
        HWSelect.dashboard.ui.pushButton_top_node3.setVisible(True)
        HWSelect.dashboard.ui.pushButton_top_node3.setText("New Sensor Node")
        HWSelect.dashboard.ui.pushButton_top_node4.setVisible(False)
        HWSelect.dashboard.ui.pushButton_top_node5.setVisible(False)
    elif len(HWSelect.dashboard.backend.settings['sensor_node4']['nickname']) == 0:
        HWSelect.dashboard.ui.pushButton_top_node4.setVisible(True)
        HWSelect.dashboard.ui.pushButton_top_node4.setText("New Sensor Node")
        HWSelect.dashboard.ui.pushButton_top_node5.setVisible(False)          
    elif len(HWSelect.dashboard.backend.settings['sensor_node5']['nickname']) == 0:
        HWSelect.dashboard.ui.pushButton_top_node5.setVisible(True)
        HWSelect.dashboard.ui.pushButton_top_node5.setText("New Sensor Node")

    # Close Window
    HWSelect.accept()

@QtCore.pyqtSlot(QtCore.QObject)
def cancel(HWSelect: QtCore.QObject):
    """
    Close the HW Select window without saving changes
    """
    HWSelect.accept()


@QtCore.pyqtSlot(QtCore.QObject)
def delete(HWSelect: QtCore.QObject):
    """
    Deletes all saved Sensor Node info for the current tab
    """
    # button: QtWidgets.QPushButton = HWSelect.pushButton_delete
    # button.setCheckable(True)

    # button.setChecked(True)
    # HWSelect.dashboard.logger.info("[Delete] Clicked")
    # time.sleep(0.5)
    # button.setChecked(False)

    # node_idx = HWSelect.tabWidget_nodes.currentIndex() + 1
    # stacked_widget: QtWidgets.QStackedWidget = getattr(HWSelect, f"stackedWidget_local_remote_{node_idx}")
    # sensor_node_settings: dict = HWSelect.dashboard.backend.settings.get("sensor_nodes")

    # # Disconnect first if currently connected
    # if stacked_widget.currentIndex() == 2:
    #     # disconnect_node()
    #     pass

    # # Shift Sensor Node entries
    # for idx in range(node_idx, 5):
    #     sensor_node_settings[f"sensor_node{idx}"] = sensor_node_settings.get(f"sensor_node{idx+1}")

    # sensor_node_settings["sensor_node5"] = {}

    # # Store updated settings
    # HWSelect.dashboard.backend.settings.update({"sensor_nodes": sensor_node_settings})

    # Yes/No Dialog
    qm = QtWidgets.QMessageBox
    ret = qm.question(
        HWSelect,
        "",
        "Delete all saved information for this sensor node?"
        "Any outstanding changes to other sensor nodes will not be saved.",
        qm.Yes | qm.No,
    )
    if ret == qm.Yes:
        # Shift Nodes to the Left
        deleted_node = HWSelect.tabWidget_nodes.currentIndex()

        # Disconnect
        stacked_widgets = [
            HWSelect.stackedWidget_local_remote_1,
            HWSelect.stackedWidget_local_remote_2,
            HWSelect.stackedWidget_local_remote_3,
            HWSelect.stackedWidget_local_remote_4,
            HWSelect.stackedWidget_local_remote_5,
        ]
        if stacked_widgets[deleted_node].currentIndex() == 2:
            disconnect(HWSelect, True)

        if deleted_node == 0:
            HWSelect.dashboard.backend.settings["sensor_node1"]["local_remote"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["local_remote"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["nickname"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["nickname"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["location"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["location"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["notes"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["notes"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["ip_address"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["ip_address"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["msg_port"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["msg_port"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["hb_port"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["hb_port"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["tsi"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["tsi"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["pd"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["pd"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["attack"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["attack"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["iq"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["iq"]
            )
            HWSelect.dashboard.backend.settings["sensor_node1"]["archive"] = (
                HWSelect.dashboard.backend.settings["sensor_node2"]["archive"]
            )

        if deleted_node <= 1:
            HWSelect.dashboard.backend.settings["sensor_node2"]["local_remote"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["local_remote"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["nickname"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["nickname"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["location"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["location"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["notes"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["notes"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["ip_address"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["ip_address"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["msg_port"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["msg_port"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["hb_port"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["hb_port"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["tsi"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["tsi"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["pd"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["pd"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["attack"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["attack"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["iq"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["iq"]
            )
            HWSelect.dashboard.backend.settings["sensor_node2"]["archive"] = (
                HWSelect.dashboard.backend.settings["sensor_node3"]["archive"]
            )

        if deleted_node <= 2:
            HWSelect.dashboard.backend.settings["sensor_node3"]["local_remote"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["local_remote"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["nickname"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["nickname"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["location"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["location"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["notes"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["notes"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["ip_address"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["ip_address"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["msg_port"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["msg_port"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["hb_port"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["hb_port"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["tsi"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["tsi"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["pd"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["pd"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["attack"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["attack"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["iq"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["iq"]
            )
            HWSelect.dashboard.backend.settings["sensor_node3"]["archive"] = (
                HWSelect.dashboard.backend.settings["sensor_node4"]["archive"]
            )

        if deleted_node <= 3:
            HWSelect.dashboard.backend.settings["sensor_node4"]["local_remote"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["local_remote"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["nickname"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["nickname"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["location"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["location"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["notes"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["notes"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["ip_address"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["ip_address"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["msg_port"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["msg_port"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["hb_port"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["hb_port"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["tsi"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["tsi"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["pd"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["pd"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["attack"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["attack"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["iq"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["iq"]
            )
            HWSelect.dashboard.backend.settings["sensor_node4"]["archive"] = (
                HWSelect.dashboard.backend.settings["sensor_node5"]["archive"]
            )

        HWSelect.dashboard.backend.settings["sensor_node5"]["local_remote"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["nickname"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["location"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["notes"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["ip_address"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["msg_port"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["hb_port"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["tsi"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["pd"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["attack"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["iq"] = ""
        HWSelect.dashboard.backend.settings["sensor_node5"]["archive"] = ""

        # Update Top Buttons
        HWSelect.dashboard.ui.pushButton_top_node2.setVisible(False)
        HWSelect.dashboard.ui.pushButton_top_node3.setVisible(False)
        HWSelect.dashboard.ui.pushButton_top_node4.setVisible(False)
        HWSelect.dashboard.ui.pushButton_top_node5.setVisible(False)
        HWSelect.dashboard.ui.pushButton_top_node1.setText(
            HWSelect.dashboard.backend.settings["sensor_node1"]["nickname"]
        )
        HWSelect.dashboard.ui.pushButton_top_node2.setText(
            HWSelect.dashboard.backend.settings["sensor_node2"]["nickname"]
        )
        HWSelect.dashboard.ui.pushButton_top_node3.setText(
            HWSelect.dashboard.backend.settings["sensor_node3"]["nickname"]
        )
        HWSelect.dashboard.ui.pushButton_top_node4.setText(
            HWSelect.dashboard.backend.settings["sensor_node4"]["nickname"]
        )
        if HWSelect.dashboard.backend.settings["sensor_node1"]["nickname"] == "":
            HWSelect.dashboard.ui.pushButton_top_node1.setText("New Sensor Node")
            HWSelect.dashboard.statusBar().sensor_nodes[0].setText("SN1: --")
            fissure.Dashboard.Slots.TopBarSlots.sensor_node_rightClick(HWSelect.dashboard, node_idx=-1)
        elif HWSelect.dashboard.backend.settings["sensor_node2"]["nickname"] == "":
            HWSelect.dashboard.ui.pushButton_top_node1.setText(
                HWSelect.dashboard.backend.settings["sensor_node1"]["nickname"]
            )
            HWSelect.dashboard.ui.pushButton_top_node2.setText("New Sensor Node")
            HWSelect.dashboard.ui.pushButton_top_node2.setVisible(True)
            HWSelect.dashboard.statusBar().sensor_nodes[1].setText("SN2: --")
            if HWSelect.dashboard.active_sensor_node <= 1:
                fissure.Dashboard.Slots.TopBarSlots.sensor_node_rightClick(HWSelect.dashboard, node_idx=0)
        elif HWSelect.dashboard.backend.settings["sensor_node3"]["nickname"] == "":
            HWSelect.dashboard.ui.pushButton_top_node2.setText(
                HWSelect.dashboard.backend.settings["sensor_node2"]["nickname"]
            )
            HWSelect.dashboard.ui.pushButton_top_node3.setText("New Sensor Node")
            HWSelect.dashboard.ui.pushButton_top_node2.setVisible(True)
            HWSelect.dashboard.ui.pushButton_top_node3.setVisible(True)
            HWSelect.dashboard.statusBar().sensor_nodes[3].setText("SN3: --")
            if HWSelect.dashboard.active_sensor_node == 2:
                fissure.Dashboard.Slots.TopBarSlots.sensor_node_rightClick(HWSelect.dashboard, node_idx=1)
            elif HWSelect.dashboard.active_sensor_node == 0:
                fissure.Dashboard.Slots.TopBarSlots.sensor_node_rightClick(HWSelect.dashboard, node_idx=0)
        elif HWSelect.dashboard.backend.settings["sensor_node4"]["nickname"] == "":
            HWSelect.dashboard.ui.pushButton_top_node3.setText(
                HWSelect.dashboard.backend.settings["sensor_node3"]["nickname"]
            )
            HWSelect.dashboard.ui.pushButton_top_node4.setText("New Sensor Node")
            HWSelect.dashboard.ui.pushButton_top_node2.setVisible(True)
            HWSelect.dashboard.ui.pushButton_top_node3.setVisible(True)
            HWSelect.dashboard.ui.pushButton_top_node4.setVisible(True)
            HWSelect.dashboard.statusBar().sensor_nodes[3].setText("SN4: --")
            if HWSelect.dashboard.active_sensor_node == 3:
                fissure.Dashboard.Slots.TopBarSlots.sensor_node_rightClick(HWSelect.dashboard, node_idx=2)
            elif HWSelect.dashboard.active_sensor_node == 0:
                fissure.Dashboard.Slots.TopBarSlots.sensor_node_rightClick(HWSelect.dashboard, node_idx=0)
        elif HWSelect.dashboard.backend.settings["sensor_node5"]["nickname"] == "":
            HWSelect.dashboard.ui.pushButton_top_node4.setText(
                HWSelect.dashboard.backend.settings["sensor_node4"]["nickname"]
            )
            HWSelect.dashboard.ui.pushButton_top_node5.setText("New Sensor Node")
            HWSelect.dashboard.ui.pushButton_top_node2.setVisible(True)
            HWSelect.dashboard.ui.pushButton_top_node3.setVisible(True)
            HWSelect.dashboard.ui.pushButton_top_node4.setVisible(True)
            HWSelect.dashboard.ui.pushButton_top_node5.setVisible(True)
            HWSelect.dashboard.statusBar().sensor_nodes[4].setText("SN5: --")
            if HWSelect.dashboard.active_sensor_node == 4:
                fissure.Dashboard.Slots.TopBarSlots.sensor_node_rightClick(HWSelect.dashboard, node_idx=3)
            elif HWSelect.dashboard.active_sensor_node == 0:
                fissure.Dashboard.Slots.TopBarSlots.sensor_node_rightClick(HWSelect.dashboard, node_idx=0)

        HWSelect.accept()
