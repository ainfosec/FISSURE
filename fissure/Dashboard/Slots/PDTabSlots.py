from PyQt5 import QtCore, QtWidgets, QtGui
import os
import fissure.utils
from fissure.Dashboard.UI_Components.Qt5 import MyMessageBox, NewSOI
import subprocess
import qasync
import time


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DemodHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Updates the list of demodulation flow graphs.
    """
    # Get Hardware
    get_hardware = str(dashboard.ui.comboBox_pd_demod_hardware.currentText()).split(' - ')[0]

    # Clear the List
    dashboard.ui.listWidget_pd_flow_graphs_all_fgs.clear()

    # Get All Demodulation Flow Graphs
    all_demod_fgs = fissure.utils.library.getDemodulationFlowGraphs(dashboard.backend.library,protocol=None,modulation=None,hardware=get_hardware)

    # Update the List Widget
    for fg in sorted(all_demod_fgs,key=str.lower):
        dashboard.ui.listWidget_pd_flow_graphs_all_fgs.addItem(fg)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DissectorsProtocolChanged(dashboard: QtCore.QObject):
    """ 
    Changes the combobox of packet types to reflect the selected protocol.
    """
    # Clear Tab if Blank Selected
    get_protocol = str(dashboard.ui.comboBox_pd_dissectors_protocol.currentText())
    if get_protocol == "":
        dashboard.ui.comboBox_pd_dissectors_packet_type.clear()
        dashboard.ui.comboBox_pd_dissectors_existing_dissectors.clear()
        dashboard.ui.frame_pd_dissectors_editor.setVisible(False)
    else:
        # Get the Packet Types
        get_packet_types = fissure.utils.library.getPacketTypes(dashboard.backend.library, get_protocol)

        # Clear the ComboBox
        dashboard.ui.comboBox_pd_dissectors_packet_type.clear()

        # Fill the ComboBox
        dashboard.ui.comboBox_pd_dissectors_packet_type.addItems(get_packet_types)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DissectorsPacketTypeChanged(dashboard: QtCore.QObject):
    """ 
    Auto-populates the Dissectors tab with packet information from "library.yaml."
    """
    # Get Protocol
    protocol = str(dashboard.ui.comboBox_pd_dissectors_protocol.currentText())

    # Get Packet Type
    packet_type = str(dashboard.ui.comboBox_pd_dissectors_packet_type.currentText())

    # Make the Groupbox Invisible
    dashboard.ui.frame_pd_dissectors_editor.setVisible(False)

    # Clear Existing Dissectors
    dashboard.ui.comboBox_pd_dissectors_existing_dissectors.clear()

    # Filter Name
    if len(protocol) == 0:
        filter_name = "protocol.packet_type"
    else:
        filter_name = (protocol + "." + packet_type).lower().replace(' ','_')
    dashboard.ui.textEdit_pd_dissectors_filter_name.setPlainText(filter_name)

    # Tree Name
    if len(protocol) == 0:
        dashboard.ui.textEdit_pd_dissectors_tree_name.setPlainText("Protocol: Packet Type")
    else:
        dashboard.ui.textEdit_pd_dissectors_tree_name.setPlainText(protocol + ": " + packet_type)

    # UDP Port
    if len(protocol) == 0:
        # Get Next Unassigned UDP Port
        next_port = fissure.utils.library.getNextDissectorPort(dashboard.backend.library)
        dashboard.ui.textEdit_pd_dissectors_udp_port.setPlainText(str(next_port))
    else:
        # No Packet Type
        if len(packet_type) == 0:
            # Get Next Unassigned UDP Port
            next_port = fissure.utils.library.getNextDissectorPort(dashboard.backend.library)
            dashboard.ui.textEdit_pd_dissectors_udp_port.setPlainText(str(next_port))
        # Valid Packet Type
        else:
            get_port = fissure.utils.library.getDissector(dashboard.backend.library, protocol, packet_type)['Port']
            # No Assigned Dissector Port
            if (get_port == "None") or (get_port == None):
                # Get Next Unassigned UDP Port
                next_port = fissure.utils.library.getNextDissectorPort(dashboard.backend.library)
                dashboard.ui.textEdit_pd_dissectors_udp_port.setPlainText(str(next_port))
            # Valid Dissector Port
            else:
                dashboard.ui.textEdit_pd_dissectors_udp_port.setPlainText(str(get_port))

    # Clear the Tables
    for row in reversed(range(0,dashboard.ui.tableWidget_pd_dissectors.rowCount())):
        dashboard.ui.tableWidget_pd_dissectors.removeRow(row)

    # Add Field Names, Lengths, and Display Text to the Table
    if protocol != "" and packet_type != "":
        # Load Dissectors for all Packets Types in the ComboBox
        get_packet_types = fissure.utils.library.getPacketTypes(dashboard.backend.library, protocol)
        dashboard.ui.comboBox_pd_dissectors_existing_dissectors.addItem('None')
        get_dissectors = []
        for n in get_packet_types:
            get_dissectors.append(fissure.utils.library.getDissector(dashboard.backend.library, protocol, n)['Filename'])
        get_dissectors = sorted(list(set(get_dissectors)))
        if 'None' in get_dissectors:
            get_dissectors.remove('None')
        dashboard.ui.comboBox_pd_dissectors_existing_dissectors.addItems(get_dissectors)

        # Populate Existing Dissectors
        get_dissector = fissure.utils.library.getDissector(dashboard.backend.library, protocol, packet_type)['Filename']
        if get_dissector != None:
            dissector_index = dashboard.ui.comboBox_pd_dissectors_existing_dissectors.findText(get_dissector)
            if dissector_index > 0:
                dashboard.ui.comboBox_pd_dissectors_existing_dissectors.setCurrentIndex(dissector_index)

        get_fields = fissure.utils.library.getFields(dashboard.backend.library, protocol, packet_type)
        for n in range(0,len(get_fields)):
            # Add Row
            _slotPD_DissectorsAddFieldClicked(dashboard)

            # Display Name
            table_item = QtWidgets.QTableWidgetItem(get_fields[n])
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_pd_dissectors.setItem(n,0,table_item)

            # Filter Name
            table_item = QtWidgets.QTableWidgetItem(get_fields[n].replace(" ","_").lower())
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_pd_dissectors.setItem(n,1,table_item)  # No Spaces, Lower-Case

            # # Bitmask
            # get_length = str(int(math.floor(dashboard.backend.library["Protocols"][protocol]['Packet Types'][packet_type]['Fields'][get_fields[n]]['Length']/8)))
            # table_item = QtWidgets.QTableWidgetItem(get_length)
            # table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            # dashboard.ui.tableWidget_pd_dissectors.setItem(n,2,table_item)

    # Resize
    dashboard.ui.tableWidget_pd_dissectors.resizeColumnsToContents()
    dashboard.ui.tableWidget_pd_dissectors.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_pd_dissectors.horizontalHeader().setStretchLastSection(True)
    dashboard.ui.tableWidget_pd_dissectors.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_CRC_AlgorithmChanged(dashboard: QtCore.QObject):
    """ 
    Updates the CRC widgets to the corresponding algorithm.
    """
    # Disable from a Custom Selection
    dashboard.ui.textEdit_pd_crc_polynomial_common.setEnabled(False)
    dashboard.ui.textEdit_pd_crc_seed_common.setEnabled(False)
    dashboard.ui.textEdit_pd_crc_final_xor_common.setEnabled(False)
    dashboard.ui.checkBox_pd_crc_reverse_input_common.setEnabled(False)
    dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setEnabled(False)

    # Switch on Algorithm
    if dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC8":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("07")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC8_CDMA2000":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("9B")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC8_DARC":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("39")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC8_DVB-S2":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("D5")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC8_EBU":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1D")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC8_I-CODE":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1D")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FD")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC8_ITU":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("07")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("55")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC8_MAXIM":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("31")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC8_ROHC":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("07")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC8_WCDMA":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("9B")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_CCIT_ZERO":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_ARC":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_AUG_CCITT (Z-Wave)":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("1D0F")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_BUYPASS":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_CCITT_FALSE":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_CDMA2000":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("C867")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_DDS_110":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("800D")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_DECT_R":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("0589")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0001")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_DECT_X":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("0589")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_DNP":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("3D65")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_EN_13757":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("3D65")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_GENIBUS":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_MAXIM":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_MCRF4XX":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_RIELLO":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("B2AA")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_T10_DIF":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("8BB7")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_TELEDISK":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("A097")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_TMS37157":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("89EC")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_USB":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_A":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("C6C6")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_KERMIT":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_MODBUS":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_X_25":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC16_XMODEM":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC32":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC32_BZIP2":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC32_C":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("1EDC6F41")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC32_D":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("A833982B")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC32_MPEG-2":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC32_POSIX":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("00000000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC32-32Q":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("814141AB")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("00000000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC32_JAMCRC":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "CRC32_XFER":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setText("000000AF")
        dashboard.ui.textEdit_pd_crc_seed_common.setText("00000000")
        dashboard.ui.textEdit_pd_crc_final_xor_common.setText("00000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setChecked(False)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")
    elif dashboard.ui.comboBox_pd_crc_algorithm.currentText() == "Custom":
        dashboard.ui.textEdit_pd_crc_polynomial_common.setEnabled(True)
        dashboard.ui.textEdit_pd_crc_seed_common.setEnabled(True)
        dashboard.ui.textEdit_pd_crc_final_xor_common.setEnabled(True)
        dashboard.ui.checkBox_pd_crc_reverse_input_common.setEnabled(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.setEnabled(True)
        dashboard.ui.textEdit_pd_crc_crc_common.setText("")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_CRC_CommonWidthChanged(dashboard: QtCore.QObject):
    """ 
    Changes the list of common CRC algorithms based on width.
    """
    # Get the CRC Width
    get_width = str(dashboard.ui.comboBox_pd_crc_common_width.currentText())

    # Switch the Algorithms
    dashboard.ui.comboBox_pd_crc_algorithm.clear()
    if get_width == "8":
        dashboard.ui.comboBox_pd_crc_algorithm.addItems(dashboard.crc_algorithms8)
    elif get_width == "16":
        dashboard.ui.comboBox_pd_crc_algorithm.addItems(dashboard.crc_algorithms16)
    elif get_width == "32":
        dashboard.ui.comboBox_pd_crc_algorithm.addItems(dashboard.crc_algorithms32)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_CRC_RevEngWidthChanged(dashboard: QtCore.QObject):
    """ 
    Changes the list of CRC RevEng CRC algorithms based on width.
    """
    # Get the CRC Width
    new_algorithms = []
    get_width = str(dashboard.ui.comboBox_pd_crc_reveng_width.currentText())

    # Switch the Algorithms
    dashboard.ui.comboBox_pd_crc_reveng_algorithm.clear()
    if get_width == "3":
        new_algorithms = ['CRC-3/GSM','CRC-3/ROHC']
    elif get_width == "4":
        new_algorithms = ['CRC-4/G-704','CRC-4/INTERLAKEN']
    elif get_width == "5":
        new_algorithms = ['CRC-5/EPC-C1G2','CRC-5/G-704','CRC-5/USB']
    elif get_width == "6":
        new_algorithms = ['CRC-6/CDMA2000-A','CRC-6/CDMA2000-B','CRC-6/DARC','CRC-6/G-704','CRC-6/GSM']
    elif get_width == "7":
        new_algorithms = ['CRC-7/MMC','CRC-7/ROHC','CRC-7/UMTS']
    elif get_width == "8":
        new_algorithms = ['CRC-8/AUTOSAR','CRC-8/BLUETOOTH','CRC-8/CDMA2000','CRC-8/DARC','CRC-8/DVB-S2','CRC-8/GSM-A','CRC-8/GSM-B',
            'CRC-8/HITAG','CRC-8/I-432-1','CRC-8/I-CODE','CRC-8/LTE','CRC-8/MAXIM-DOW','CRC-8/MIFARE-MAD','CRC-8/NRSC-5','CRC-8/OPENSAFETY',
            'CRC-8/ROHC','CRC-8/SAE-J1850','CRC-8/SMBUS','CRC-8/TECH-3250','CRC-8/WCDMA']
    elif get_width == "10":
        new_algorithms = ['CRC-10/ATM','CRC-10/CDMA2000','CRC-10/GSM']
    elif get_width == "11":
        new_algorithms = ['CRC-11/FLEXRAY','CRC-11/UMTS']
    elif get_width == "12":
        new_algorithms = ['CRC-12/CDMA2000','CRC-12/DECT','CRC-12/GSM','CRC-12/UMTS']
    elif get_width == "13":
        new_algorithms = ['CRC-13/BBC']
    elif get_width == "14":
        new_algorithms = ['CRC-14/DARC','CRC-14/GSM']
    elif get_width == "15":
        new_algorithms = ['CRC-15/CAN','CRC-15/MPT1327']
    elif get_width == "16":
        new_algorithms = ['CRC-16/ARC','CRC-16/CDMA2000','CRC-16/CMS','CRC-16/DDS-110','CRC-16/DECT-R','CRC-16/DECT-X','CRC-16/DNP','CRC-16/EN-13757',
            'CRC-16/GENIBUS','CRC-16/GSM','CRC-16/IBM-3740','CRC-16/IBM-SDLC','CRC-16/ISO-IEC-14443-3-A','CRC-16/KERMIT','CRC-16/LJ1200','CRC-16/M17',
            'CRC-16/MAXIM-DOW','CRC-16/MCRF4XX','CRC-16/MODBUS','CRC-16/NRSC-5','CRC-16/OPENSAFETY-A','CRC-16/OPENSAFETY-B','CRC-16/PROFIBUS','CRC-16/RIELLO',
            'CRC-16/SPI-FUJITSU','CRC-16/T10-DIF','CRC-16/TELEDISK','CRC-16/TMS37157','CRC-16/UMTS','CRC-16/USB','CRC-16/XMODEM']
    elif get_width == "17":
        new_algorithms = ['CRC-17/CAN-FD']
    elif get_width == "21":
        new_algorithms = ['CRC-21/CAN-FD']
    elif get_width == "24":
        new_algorithms = ['CRC-24/BLE','CRC-24/FLEXRAY-A','CRC-24/FLEXRAY-B','CRC-24/INTERLAKEN','CRC-24/LTE-A','CRC-24/LTE-B','CRC-24/OPENPGP','CRC-24/OS-9']
    elif get_width == "30":
        new_algorithms = ['CRC-30/CDMA']
    elif get_width == "31":
        new_algorithms = ['CRC-31/PHILIPS']
    elif get_width == "32":
        new_algorithms = ['CRC-32/AIXM','CRC-32/AUTOSAR','CRC-32/BASE91-D','CRC-32/BZIP2','CRC-32/CD-ROM-EDC','CRC-32/CKSUM','CRC-32/ISCSI','CRC-32/ISO-HDLC',
            'CRC-32/JAMCRC','CRC-32/MEF','CRC-32/MPEG-2','CRC-32/XFER']
    elif get_width == "40":
        new_algorithms = ['CRC-40/GSM']
    elif get_width == "64":
        new_algorithms = ['CRC-64/ECMA-182','CRC-64/GO-ISO','CRC-64/MS','CRC-64/REDIS','CRC-64/WE','CRC-64/XZ']
    elif get_width == "82":
        new_algorithms = ['CRC-82/DARC']
    else:
        return
    dashboard.ui.comboBox_pd_crc_reveng_algorithm.addItems(new_algorithms)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_CRC_RevEngAlgorithmChanged(dashboard: QtCore.QObject):
    """ 
    Updates the CRC RevEng widgets to the corresponding algorithm.
    """
    # Disable from a Custom Selection
    dashboard.ui.textEdit_pd_crc_polynomial_reveng.setEnabled(False)
    dashboard.ui.textEdit_pd_crc_seed_reveng.setEnabled(False)
    dashboard.ui.textEdit_pd_crc_final_xor_reveng.setEnabled(False)
    dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setEnabled(False)
    dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setEnabled(False)
    dashboard.ui.textEdit_pd_crc_crc_reveng.setText("")

    # Switch on Algorithm
    if dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-3/GSM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("3")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("7")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-3/ROHC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("3")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("7")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-4/G-704":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("6")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-4/INTERLAKEN":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("3")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("F")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("F")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-5/EPC-C1G2":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("09")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("09")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-5/G-704":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("15")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-5/USB":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("05")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("1F")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("1F")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-6/CDMA2000-A":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("27")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("3F")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-6/CDMA2000-B":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("07")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("3F")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-6/DARC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("19")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-6/G-704":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("03")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-6/GSM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("2F")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("3F")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-7/MMC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("09")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-7/ROHC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("4F")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("7F")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-7/UMTS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("45")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/AUTOSAR":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("2F")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/BLUETOOTH":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("A7")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/CDMA2000":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("9B")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/DARC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("39")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/DVB-S2":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("D5")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/GSM-A":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1D")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/GSM-B":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("49")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/HITAG":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1D")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/I-432-1":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("07")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("55")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/I-CODE":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1D")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FD")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/LTE":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("9B")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/MAXIM-DOW":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("31")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/MIFARE-MAD":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1D")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("C7")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/NRSC-5":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("31")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/OPENSAFETY":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("2F")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/ROHC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("07")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/SAE-J1850":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1D")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/SMBUS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("07")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/TECH-3250":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1D")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-8/WCDMA":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("9B")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-10/ATM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("233")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-10/CDMA2000":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("3D9")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("3FF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-10/GSM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("175")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("3FF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-11/FLEXRAY":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("385")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("01A")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-11/UMTS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("307")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-12/CDMA2000":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("F13")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-12/DECT":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("80F")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-12/GSM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("D31")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-12/UMTS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("80F")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-13/BBC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1CF5")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-14/DARC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("0805")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-14/GSM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("202D")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("3FFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-15/CAN":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("4599")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-15/MPT1327":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("6815")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0001")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/ARC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/CDMA2000":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("C867")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/CMS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/DDS-110":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("800D")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/DECT-R":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("0589")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0001")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/DECT-X":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("0589")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/DNP":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("3D65")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/EN-13757":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("3D65")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/GENIBUS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/GSM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/IBM-3740":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/IBM-SDLC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/ISO-IEC-14443-3-A":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("C6C6")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/KERMIT":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/LJ1200":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("6F63")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/M17":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("5935")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/MAXIM-DOW":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/MCRF4XX":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/MODBUS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/NRSC-5":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("080B")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/OPENSAFETY-A":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("5935")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/OPENSAFETY-B":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("755B")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/PROFIBUS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1DCF")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/RIELLO":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("B2AA")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/SPI-FUJITSU":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("1D0F")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/T10-DIF":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("8BB7")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/TELEDISK":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("A097")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/TMS37157":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("89EC")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/UMTS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/USB":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("8005")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-16/XMODEM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1021")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-17/CAN-FD":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1685B")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-21/CAN-FD":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("102899")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-24/BLE":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("00065B")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("555555")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-24/FLEXRAY-A":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("5D6DCB")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FEDCBA")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-24/FLEXRAY-B":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("5D6DCB")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("ABCDEF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-24/INTERLAKEN":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("328B63")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-24/LTE-A":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("864CFB")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-24/LTE-B":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("800063")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-24/OPENPGP":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("864CFB")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("B704CE")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-24/OS-9":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("800063")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-30/CDMA":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("2030B9C7")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("3FFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("3FFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-31/PHILIPS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("7FFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("7FFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/AIXM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("814141AB")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/AUTOSAR":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("F4ACFB13")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/BASE91-D":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("A833982B")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/BZIP2":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/CD-ROM-EDC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("8001801B")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/CKSUM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/ISCSI":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("1EDC6F41")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/ISO-HDLC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/JAMCRC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/MEF":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("741B8CD7")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/MPEG-2":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("04C11DB7")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-32/XFER":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("000000AF")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("00000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("00000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-40/GSM":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("0004820009")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-64/ECMA-182":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("42F0E1EBA9EA3693")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000000000000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000000000000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-64/GO-ISO":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("000000000000001B")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFFFFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFFFFFFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-64/MS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("259C84CBA6426349")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFFFFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000000000000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-64/REDIS":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("AD93D23594C935A9")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("0000000000000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("0000000000000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-64/WE":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("42F0E1EBA9EA3693")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFFFFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFFFFFFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(False)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(False)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-64/XZ":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("42F0E1EBA9EA3693")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("FFFFFFFFFFFFFFFF")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("FFFFFFFFFFFFFFFF")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)
    elif dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText() == "CRC-82/DARC":
        dashboard.ui.textEdit_pd_crc_polynomial_reveng.setText("0308C0111011401440411")
        dashboard.ui.textEdit_pd_crc_seed_reveng.setText("000000000000000000000")
        dashboard.ui.textEdit_pd_crc_final_xor_reveng.setText("000000000000000000000")
        dashboard.ui.checkBox_pd_crc_reverse_input_reveng.setChecked(True)
        dashboard.ui.checkBox_pd_crc_reverse_final_xor_reveng.setChecked(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerProtocolsChanged(dashboard: QtCore.QObject):
    """ 
    Updates the list of protocol message types in subcategories combo box.
    """
    # Get the Protocol
    current_protocol_key = str(dashboard.ui.comboBox_pd_bit_viewer_protocols.currentText())
    if current_protocol_key:  #will be false if no current protocol selected
        try:
            if current_protocol_key == "Raw":
                dashboard.ui.comboBox_pd_bit_viewer_subcategory.clear()
            else:
                #return sorted list based on sort order subkey
                packet_types = fissure.utils.library.getPacketTypes(dashboard.backend.library, current_protocol_key)
                dashboard.ui.comboBox_pd_bit_viewer_subcategory.clear()
                dashboard.ui.comboBox_pd_bit_viewer_subcategory.addItems(packet_types)

        except KeyError:
            #No packet types!
            packet_types = []
            dashboard.ui.comboBox_pd_bit_viewer_subcategory.clear()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerSubcategoryChanged(dashboard: QtCore.QObject):
    """ 
    Doesn't do anything yet. Delete?
    """
    pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_SnifferProtocolsChanged(dashboard: QtCore.QObject):
    """ 
    Updates the packet type combobox in the Sniffer tab.
    """
    # Get Protocol
    get_protocol = str(dashboard.ui.comboBox_pd_sniffer_protocols.currentText())

    # Get the Packet Type
    get_packet_type = fissure.utils.library.getPacketTypes(dashboard.backend.library, get_protocol)

    # Clear the ComboBox
    dashboard.ui.comboBox_pd_sniffer_packet_type.clear()

    # Fill the ComboBox
    dashboard.ui.comboBox_pd_sniffer_packet_type.addItems(get_packet_type)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_SnifferPacketTypeChanged(dashboard: QtCore.QObject):
    """ 
    Updates the SUB & UDP Port to match the dissector in the library.
    """
    # Get Protocol and Packet Type
    get_protocol = str(dashboard.ui.comboBox_pd_sniffer_protocols.currentText())
    get_packet_type = str(dashboard.ui.comboBox_pd_sniffer_packet_type.currentText())

    # Find Dissector Port
    if len(get_packet_type) > 0:
        get_dissectors = fissure.utils.library.getDissector(dashboard.backend.library, get_protocol, get_packet_type)['Filename']

        # No Dissector
        if get_dissectors == None:
            dashboard.ui.textEdit_pd_sniffer_sub_udp_port.setPlainText("55555")
            dashboard.ui.textEdit_pd_sniffer_test_port.setPlainText("55555")

        # Dissector Found
        else:
            get_port = fissure.utils.library.getDissector(dashboard.backend.library, get_protocol, get_packet_type)['Port']
            if get_port == "None":
                dashboard.ui.textEdit_pd_sniffer_sub_udp_port.setPlainText("55555")
                dashboard.ui.textEdit_pd_sniffer_test_port.setPlainText("55555")
            else:
                dashboard.ui.textEdit_pd_sniffer_sub_udp_port.setPlainText(str(get_port))
                dashboard.ui.textEdit_pd_sniffer_test_port.setPlainText(str(get_port))    


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_SnifferTestFoldersChanged(dashboard: QtCore.QObject):
    """ 
    Updates the list of crafted packet files in the sniffer test listbox.
    """
    # Load the Files in the Listbox
    get_dir = str(dashboard.ui.comboBox_pd_sniffer_test_folders.currentText())
    if get_dir != "":
        dashboard.ui.listWidget_pd_sniffer_test_files.clear()
        file_names = []
        for fname in os.listdir(get_dir):
            if os.path.isfile(get_dir+"/"+fname):
                file_names.append(fname)
        file_names = sorted(file_names)
        for n in file_names:
            dashboard.ui.listWidget_pd_sniffer_test_files.addItem(n)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingSpinboxWindowChanged(dashboard: QtCore.QObject):
    """ 
    This adjusts the preamble stats to display the results for the selected window size.
    """
    # Adjust the Slider to Match
    dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats.setSliderPosition(int(dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size.value()))

    # Change the Preamble Stats that are Displayed in the Table
    pdBitSlicingSortPreambleStatsTable(dashboard, int(dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size.value()))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingSpinboxWindowCandidatesChanged(dashboard: QtCore.QObject):
    """ 
    This adjusts the preamble stats to display the results for the selected window size.
    """
    # Adjust the Slider to Match
    dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats_candidates.setSliderPosition(int(dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size_candidates.value()))

    # Change the Preamble Stats that are Displayed in the Table
    pdBitSlicingSortCandidatePreambleTable(dashboard, int(dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size_candidates.value()))


def pdBitSlicingSortPreambleStatsTable(dashboard: QtCore.QObject, packet_length):
    """ 
    This function adds the values to the Preamble Stats and sorts the values by occurrence. Not a slot.
    """
    # Initialize the Table
    for row in reversed(range(0, dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.rowCount())):
        dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.removeRow(row)

    # Add the Values to the Table
    packet_size = packet_length
    for key,value in dashboard.median_slicing_results.items():
        # Matching Packet Size
        if value[0] == packet_size:
            # Add First Preamble
            if dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.rowCount() == 0:
                # Insert New Row
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.insertRow(0)

                # Preamble
                preamble_item = QtWidgets.QTableWidgetItem(key)
                preamble_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setItem(0,0,preamble_item)

                # Occurrences
                occurrences_item = QtWidgets.QTableWidgetItem(str(value[4]))
                occurrences_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setItem(0,1,occurrences_item)

                # Packet Median
                packet_median_item = QtWidgets.QTableWidgetItem(str("%.1f" % round(value[1],1)))
                packet_median_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setItem(0,2,packet_median_item)

                # Packet Mean
                packet_mean_item = QtWidgets.QTableWidgetItem(str("%.1f" % round(value[2],1)))
                packet_mean_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setItem(0,3,packet_mean_item)

                # Packet Std. Dev.
                packet_std_dev_item = QtWidgets.QTableWidgetItem(str("%.1f" % round(value[3],1)))
                packet_std_dev_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setItem(0,4,packet_std_dev_item)

            # Sort by Occurrence
            else:
                for row in range(0,dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.rowCount()):
                    insert_row = -1
                    # Insert New Row
                    if int(value[4]) > int(dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.item(row,1).text()):
                        insert_row = row
                        dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.insertRow(row)
                        break

                # Insert Row at End
                if insert_row == -1:
                    insert_row = dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.rowCount()
                    dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.insertRow(dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.rowCount())

                # Preamble
                preamble_item = QtWidgets.QTableWidgetItem(key)
                preamble_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setItem(insert_row,0,preamble_item)

                # Occurrences
                occurrences_item = QtWidgets.QTableWidgetItem(str(value[4]))
                occurrences_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setItem(insert_row,1,occurrences_item)

                # Packet Median
                packet_median_item = QtWidgets.QTableWidgetItem(str("%.1f" % round(value[1],1)))
                packet_median_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setItem(insert_row,2,packet_median_item)

                # Packet Mean
                packet_mean_item = QtWidgets.QTableWidgetItem(str("%.1f" % round(value[2],1)))
                packet_mean_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setItem(insert_row,3,packet_mean_item)

                # Packet Std. Dev.
                packet_std_dev_item = QtWidgets.QTableWidgetItem(str("%.1f" % round(value[3],1)))
                packet_std_dev_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setItem(insert_row,4,packet_std_dev_item)

    # Resize the Table
    dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setColumnWidth(1,97)
    dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setColumnWidth(2,111)
    dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setColumnWidth(3,111)
    dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setColumnWidth(4,121)
    dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.horizontalHeader().setSectionResizeMode(0,QtWidgets.QHeaderView.Stretch)
    dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.resizeRowsToContents()

    # Select First Row
    dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.setCurrentCell(0,0)    


def pdBitSlicingSortCandidatePreambleTable(dashboard: QtCore.QObject, preamble_length):
    """ 
    This function adds the values to the Preamble Stats and sorts the values by occurrence. Not a slot.
    """
    # Initialize the Table
    for row in reversed(range(0,dashboard.ui.tableWidget_pd_bit_slicing_candidate_preambles.rowCount())):
        dashboard.ui.tableWidget_pd_bit_slicing_candidate_preambles.removeRow(row)

    # Add the Values to the Table
    for key,value in dashboard.candidate_preamble_data.items():
        if len(key) == preamble_length:
            # Insert New Row
            dashboard.ui.tableWidget_pd_bit_slicing_candidate_preambles.insertRow(0)

            # Preamble
            preamble_item = QtWidgets.QTableWidgetItem(key)
            preamble_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_pd_bit_slicing_candidate_preambles.setItem(0,0,preamble_item)

    # Resize the Table
    dashboard.ui.tableWidget_pd_bit_slicing_candidate_preambles.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingSliderWindowChanged(dashboard: QtCore.QObject):
    """ 
    This adjusts the preamble stats to display the results.
    """
    # Adjust the Spinbox to Match
    dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size.setValue(dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats.value())    


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingSliderWindowCandidatesChanged(dashboard: QtCore.QObject):
    """ 
    This adjusts the preamble stats to display the results.
    """
    # Adjust the Spinbox to Match
    dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size_candidates.setValue(dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats_candidates.value())


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DemodulationCurrentValuesEdited(dashboard: QtCore.QObject):
    """ 
    Enables the pushbuttons after the "Current Values" table has been edited and the flow graph is stopped
    """
    # Don't Show "Apply All" Button When Flow Graph is Stopped and Changes are Made
    if dashboard.ui.pushButton_pd_flow_graphs_start_stop.text() == "Stop":
        dashboard.ui.pushButton_pd_flow_graphs_apply_changes.setEnabled(True)

    dashboard.ui.pushButton_pd_flow_graphs_restore_defaults.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingLengthsChanged(dashboard: QtCore.QObject):
    """ 
    This updates the packet listings when an item is clicked in the packet length table.
    """
    # Get the Current Row
    get_row = dashboard.ui.tableWidget_pd_bit_slicing_lengths.currentRow()

    # Valid Case
    if get_row >= 0:
        # Clear the Packet Table
        for row in reversed(range(0,dashboard.ui.tableWidget_pd_bit_slicing_packets.rowCount())):
            dashboard.ui.tableWidget_pd_bit_slicing_packets.removeRow(row)
        for col in reversed(range(0,dashboard.ui.tableWidget_pd_bit_slicing_packets.columnCount())):
            dashboard.ui.tableWidget_pd_bit_slicing_packets.removeColumn(col)

        # Get Length Value
        length_item_value = int(dashboard.ui.tableWidget_pd_bit_slicing_lengths.item(get_row,0).text())

        # Add Column
        dashboard.ui.tableWidget_pd_bit_slicing_packets.setColumnCount(1)
        header_item = QtWidgets.QTableWidgetItem("Packets of Length " + str(length_item_value))
        header_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_pd_bit_slicing_packets.setHorizontalHeaderItem(0,header_item)

        # Clear Field Delineations Table
        dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.setRowCount(0)

        # Add First Packet Length to the Packets Table
        for n in range(0,len(dashboard.first_n_packets[length_item_value])):
            new_row = dashboard.ui.tableWidget_pd_bit_slicing_packets.rowCount()
            dashboard.ui.tableWidget_pd_bit_slicing_packets.insertRow(new_row)
            packet_item = QtWidgets.QTableWidgetItem(dashboard.first_n_packets[length_item_value][n])
            dashboard.ui.tableWidget_pd_bit_slicing_packets.setItem(new_row,0,packet_item)

        #~ # Resize the Table
        #~ dashboard.ui.tableWidget_pd_bit_slicing_packets.resizeColumnsToContents()
        #~ dashboard.ui.tableWidget_pd_bit_slicing_packets.resizeRowsToContents()

        # Reset the Packet Type
        dashboard.bit_slicing_column_type = ["Binary"]

        # Slice the Data
        _slotPD_BitSlicingSliceClicked(dashboard, length_item_value)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingCandidateDoubleClicked(dashboard: QtCore.QObject, row, col):
    """ 
    This will update the preamble text edit box for bit slicing with the item that was double clicked in the "Candidate Preambles" table.
    """
    # Update the Edit Box
    dashboard.ui.textEdit_pd_bit_slicing_recommended_preamble.setPlainText(str(dashboard.ui.tableWidget_pd_bit_slicing_candidate_preambles.item(row,col).text()))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingAllPreamblesDoubleClicked(dashboard: QtCore.QObject, row, col):
    """ 
    This will update the preamble text edit box for bit slicing with the item that was double clicked in the "All Preambles" table.
    """
    # Update the Edit Box
    dashboard.ui.textEdit_pd_bit_slicing_recommended_preamble.setPlainText(str(dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.item(row,0).text()))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingColumnClicked(dashboard: QtCore.QObject, col):
    """ 
    Toggles the contents of the bit slicing table between binary and hex.
    """
    # Toggle the Text
    stay_binary = False
    for row in range(0,dashboard.ui.tableWidget_pd_bit_slicing_packets.rowCount()):
        # Get the Data
        get_data = str(dashboard.ui.tableWidget_pd_bit_slicing_packets.item(row,col).text())

        # Hex to Binary
        if dashboard.bit_slicing_column_type[col] == "Hex":
            bin_str = bin(int(get_data, 16))[2:].zfill(int(len(get_data)*4))
            #~ bin_str_spaces = ' '.join([bin_str[i:i+4] for i in range(0, len(bin_str), 4)])
            dashboard.ui.tableWidget_pd_bit_slicing_packets.item(row,col).setText(bin_str)

        # Binary to Hex
        elif dashboard.bit_slicing_column_type[col] == "Binary":
            get_data = get_data.replace(' ', '')
            if len(get_data) % 4 == 0:
                hex_str = '%0*X' % ((len(get_data) + 3) // 4, int(get_data, 2))
                dashboard.ui.tableWidget_pd_bit_slicing_packets.item(row,col).setText(hex_str)
            else:
                stay_binary = True

    # Save the Field Type
    if dashboard.bit_slicing_column_type[col] == "Hex":
        dashboard.bit_slicing_column_type[col] = "Binary"

        # Change the Header Font Color to Red
        header_item = QtWidgets.QTableWidgetItem(dashboard.colnum_string(col+1))
        header_item.setTextAlignment(QtCore.Qt.AlignCenter)
        header_item.setForeground(QtGui.QColor(255,0,0))
        dashboard.ui.tableWidget_pd_bit_slicing_packets.setHorizontalHeaderItem(col,header_item)

    else:
        if stay_binary == False:
            dashboard.bit_slicing_column_type[col] = "Hex"

            # Change the Header Font Color to Black
            header_item = QtWidgets.QTableWidgetItem(dashboard.colnum_string(col+1))
            header_item.setTextAlignment(QtCore.Qt.AlignCenter)
            header_item.setForeground(QtGui.QColor(dashboard.backend.settings['color4']))
            dashboard.ui.tableWidget_pd_bit_slicing_packets.setHorizontalHeaderItem(col,header_item)

    # Resize the Table
    dashboard.ui.tableWidget_pd_bit_slicing_packets.resizeColumnsToContents()
    dashboard.ui.tableWidget_pd_bit_slicing_packets.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_pd_bit_slicing_packets.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerColumnClicked(dashboard: QtCore.QObject, col):
    """ 
    Toggles the contents of the bit viewer table between binary and hex.
    """
    # Ignore Raw Type
    get_protocol = str(dashboard.ui.comboBox_pd_bit_viewer_protocols.currentText())
    if get_protocol != "Raw":  
        
        # Toggle the Text
        stay_binary = False
        for row in range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()):
            # Get the Data
            try:
                get_data = str(dashboard.ui.tableWidget_pd_bit_viewer_hex.item(row,col).text())
            except:
                get_data = ''

            # Hex to Binary
            if dashboard.bit_viewer_column_type[col] == "Hex":
                if len(get_data) > 0:
                    bin_str = bin(int(get_data, 16))[2:].zfill(int(len(get_data)*4))
                    #~ bin_str_spaces = ' '.join([bin_str[i:i+4] for i in range(0, len(bin_str), 4)])
                    dashboard.ui.tableWidget_pd_bit_viewer_hex.item(row,col).setText(bin_str)

            # Binary to Hex
            elif dashboard.bit_viewer_column_type[col] == "Binary":
                get_data = get_data.replace(' ', '')
                if len(get_data) > 0:                        
                    if len(get_data) % 4 == 0:
                        hex_str = '%0*X' % ((len(get_data) + 3) // 4, int(get_data, 2))
                        dashboard.ui.tableWidget_pd_bit_viewer_hex.item(row,col).setText(hex_str)
                    else:
                        stay_binary = True

        # Save the Field Type
        if dashboard.bit_viewer_column_type[col] == "Hex":
            dashboard.bit_viewer_column_type[col] = "Binary"

            # Change the Header Font Color to Red
            get_header_text = str(dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeaderItem(col).text())
            header_item = QtWidgets.QTableWidgetItem(get_header_text)
            header_item.setTextAlignment(QtCore.Qt.AlignCenter)
            header_item.setForeground(QtGui.QColor(255,0,0))
            dashboard.ui.tableWidget_pd_bit_viewer_hex.setHorizontalHeaderItem(col,header_item)

        else:
            if stay_binary == False:
                dashboard.bit_viewer_column_type[col] = "Hex"

                # Change the Header Font Color to Black
                get_header_text = str(dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeaderItem(col).text())
                header_item = QtWidgets.QTableWidgetItem(get_header_text)
                header_item.setTextAlignment(QtCore.Qt.AlignCenter)
                header_item.setForeground(QtGui.QColor(dashboard.backend.settings['color4']))
                dashboard.ui.tableWidget_pd_bit_viewer_hex.setHorizontalHeaderItem(col,header_item)

        # Resize the Table
        dashboard.ui.tableWidget_pd_bit_viewer_hex.resizeColumnsToContents()
        dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DemodulationLoadSelectedClicked(dashboard: QtCore.QObject):
    """ 
    Loads the currently selected flow graph from the "Recommended Flow Graphs" list.
    """
    if dashboard.ui.listWidget_pd_flow_graphs_recommended_fgs.count() > 0:
        # Get the File Name
        fname = dashboard.ui.listWidget_pd_flow_graphs_recommended_fgs.currentItem().text()

        # Stop the Current Flow Graph
        if dashboard.ui.pushButton_pd_flow_graphs_start_stop.text() == "Stop":
            _slotPD_DemodulationStartStopClicked(dashboard)

        # Load the File
        _slotPD_DemodulationLoadFlowGraphClicked(dashboard, fname)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DemodulationLoadSelectedAllClicked(dashboard: QtCore.QObject):
    """ 
    Loads the currently selected flow graph from the "All Flow Graphs" list.
    """
    if dashboard.ui.listWidget_pd_flow_graphs_all_fgs.count() > 0:
        # Get the File Name
        fname = dashboard.ui.listWidget_pd_flow_graphs_all_fgs.currentItem().text()

        # Stop the Current Flow Graph
        if dashboard.ui.pushButton_pd_flow_graphs_start_stop.text() == "Stop":
            _slotPD_DemodulationStartStopClicked(dashboard)

        # Load the File
        _slotPD_DemodulationLoadFlowGraphClicked(dashboard, fname)            


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerHexChanged(dashboard: QtCore.QObject):
    """ 
    Updates the ASCII values when the hex changes.
    """      
    # Display the ASCII
    get_hex_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_hex.toPlainText()).replace(" ","")

    # Update Counter
    dashboard.ui.label2_pd_bit_viewer_nibbles.setText(str(len(get_hex_str.replace('\t','').replace('\n',''))))

    # Split by Line
    get_hex = get_hex_str.splitlines()
    new_ascii = ""
    for n in range(0, len(get_hex)):
        if (len(get_hex[n])%2 == 0):
            new_ascii = new_ascii + str(bytes.fromhex(get_hex[n]))[2:-1] + "\n"

    dashboard.ui.plainTextEdit_pd_bit_viewer_ascii.setPlainText(new_ascii)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerBitsChanged(dashboard: QtCore.QObject):
    """ 
    Updates the bit counter in the Data Viewer.
    """
    # Obtain the Count
    get_bit_count = len(str(dashboard.ui.plainTextEdit_pd_bit_viewer_bits.toPlainText()).replace(' ','').replace('\t','').replace('\n',''))
    
    # Update the Bits
    dashboard.ui.label2_pd_bit_viewer_bits.setText(str(get_bit_count))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_StatusSOI_NewClicked(dashboard: QtCore.QObject):
    """ 
    Manually creates a new signal of interest.
    """
    # Open the NewSOI Dialog
    new_soi_dlg = NewSOI(parent=dashboard)
    new_soi_dlg.show()
    new_soi_dlg.exec_()

    # Apply Clicked
    get_value = new_soi_dlg.return_value
    if len(get_value) > 0:

        # Update the Text
        #target_soi = [get_frequency, get_modulation, get_bandwidth, get_continuous, get_start_frequency, get_end_frequency]
        dashboard.ui.textEdit_pd_status_target.setPlainText("Center Frequency (MHz): " + dashboard.target_soi[0])
        dashboard.ui.textEdit_pd_status_target.append("Start Frequency (MHz): " + dashboard.target_soi[4])
        dashboard.ui.textEdit_pd_status_target.append("End Frequency (MHz): " + dashboard.target_soi[5])
        dashboard.ui.textEdit_pd_status_target.append("Bandwidth (MHz): " + dashboard.target_soi[2])
        dashboard.ui.textEdit_pd_status_target.append("Modulation: " + dashboard.target_soi[1])
        dashboard.ui.textEdit_pd_status_target.append("Continuous: " + dashboard.target_soi[3])
        dashboard.ui.textEdit_pd_status_target.append("Notes: " + dashboard.target_soi[6])

        dashboard.ui.pushButton_pd_status_untarget.setEnabled(True)
        #dashboard.ui.pushButton_pd_status_blacklist_soi.setEnabled(True)
        dashboard.ui.pushButton_pd_status_search_library.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_StatusSearchLibraryClicked(dashboard: QtCore.QObject):
    """ 
    Populates the Search Library Fields with the current SOI.
    """
    # Set the Fields
    fissure.Dashboard.Slots.LibraryTabSlots._slotLibrarySearchCurrentSOI_Clicked(dashboard)

    # Change the Tab
    dashboard.ui.tabWidget_library.setCurrentIndex(2)
    dashboard.ui.tabWidget.setCurrentIndex(7)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DemodulationCurrentSOI_Clicked(dashboard: QtCore.QObject):
    """ 
    Updates the edit boxes in the Flow Graph Lookup section of the "Flow Graphs" tab with the current SOI information.
    """
    # Display the Current Signal of Interest
    if len(dashboard.target_soi) > 0:
        dashboard.ui.textEdit_pd_flow_graphs_frequency.setPlainText(dashboard.target_soi[0])
        dashboard.ui.textEdit_pd_flow_graphs_modulation.setPlainText(dashboard.target_soi[1])
        dashboard.ui.textEdit_pd_flow_graphs_bandwidth.setPlainText(dashboard.target_soi[2])

        if dashboard.target_soi[3] == "True":
            dashboard.ui.comboBox_pd_flow_graphs_continuous.setCurrentIndex(0)
        else:
            dashboard.ui.comboBox_pd_flow_graphs_continuous.setCurrentIndex(1)

        dashboard.ui.textEdit_pd_flow_graphs_start_frequency.setPlainText(dashboard.target_soi[4])
        dashboard.ui.textEdit_pd_flow_graphs_end_frequency.setPlainText(dashboard.target_soi[5])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DemodulationViewFlowGraphClicked(dashboard: QtCore.QObject):
    """ 
    Views the currently loaded flow graph in GNU Radio Companion
    """
    try:
        # Get the Flow Graph Name
        loaded_flow_graph = str(dashboard.ui.textEdit_pd_flow_graphs_filepath.toPlainText())
        loaded_flow_graph = loaded_flow_graph.replace(' ','\ ')
        loaded_flow_graph = loaded_flow_graph.rpartition('.')[0] + '.grc'

        # Open the Flow Graph in GNU Radio Companion
        osCommandString = 'gnuradio-companion ' + loaded_flow_graph
        os.system(osCommandString + ' &')

    except:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Error loading flow graph in GNU Radio Companion")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DemodulationLoadFlowGraphClicked(dashboard: QtCore.QObject, fname=''):
    """ 
    Loads a new flow graph from the library and sends it to Sensor Node to run
    """
    if fname == '':
        # Look for the Flow Graph
        directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "PD Flow Graphs")  # Default Directory
        fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select Flow Graph...", directory, filter='Flow Graphs (*.py)')[0]

    else:
        # Flow Graph Filename was Provided
        flow_graph_directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "PD Flow Graphs")

        # Enable/Disable the Sniffer Buttons
        get_sniffer_type = fissure.utils.library.getDemodulationFlowGraphsSnifferType(dashboard.backend.library, fname)
        dashboard.ui.pushButton_pd_sniffer_stream.setEnabled(False)
        dashboard.ui.pushButton_pd_sniffer_tagged_stream.setEnabled(False)
        dashboard.ui.pushButton_pd_sniffer_msg_pdu.setEnabled(False)
        if get_sniffer_type == 'Stream':
            dashboard.ui.pushButton_pd_sniffer_stream.setEnabled(True)
        elif get_sniffer_type == 'Tagged Stream':
            dashboard.ui.pushButton_pd_sniffer_tagged_stream.setEnabled(True)
        elif get_sniffer_type == 'Message/PDU':
            dashboard.ui.pushButton_pd_sniffer_msg_pdu.setEnabled(True)

        fname = os.path.join(flow_graph_directory, fname)

    # If a Valid File
    if fname != '':
        # Attempt to Open the File
        error_found = False
        try:
            f = open(str(fname),'r')
        except:
            error_found = True
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Flow Graph was not Found in PD Flow Graph Library!")

        if error_found == False:
            # Sensor Node Hardware Information
            get_current_hardware = str(dashboard.ui.comboBox_pd_demod_hardware.currentText())
            get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'attack')
            
            # Update the Edit Box
            dashboard.ui.textEdit_pd_flow_graphs_filepath.setPlainText(fname)

            # Update the Status Dialog
            if dashboard.active_sensor_node > -1:
                dashboard.statusbar_text[dashboard.active_sensor_node][2] = "Loaded: " + str(fname.split('/')[-1]) 
                dashboard.refreshStatusBarText()

            # Update the Protocol Tab Labels
            dashboard.ui.label2_pd_status_loaded_flow_graph.setText(str(fname.split('/')[-1]))
            dashboard.ui.label2_pd_status_flow_graph_status.setText("Stopped")

            # Update the Description and Variable Listings in "Flow Graph" tab
            temp_flow_graph_variables = {}
            dashboard.ui.label3_pd_flow_graphs_description.setText("")
            dashboard.ui.label3_pd_flow_graphs_default_variables.setText("")
            dashboard.ui.tableWidget_pd_flow_graphs_current_values.clearContents()
            dashboard.ui.tableWidget_pd_flow_graphs_current_values.setRowCount(0)
            parsing = False
            description_parsing = False
            for line in f:
                # Description
                if line.startswith("# Description: "):
                    description_parsing = True
                elif line.startswith("# GNU Radio version: "):
                    description_parsing = False
                if description_parsing:
                    # Get Text
                    get_line = line
                    get_line = get_line.replace("# Description: ","")

                    # Break it up by Keywords
                    if "OSI Levels: " in get_line:
                        get_line = get_line.partition("OSI Levels:")[0] + "\n" + "\n" + get_line.partition("OSI Levels:")[1] + get_line.partition("OSI Levels:")[2]
                    if "Description: " in get_line:
                        get_line = get_line.partition("Description:")[0] + "\n" + "\n" + get_line.partition("Description:")[1] + get_line.partition("Description:")[2]

                    # Fill in the "Loaded Flow Graph" Label
                    if get_line != "":
                        dashboard.ui.label3_pd_flow_graphs_description.setText(dashboard.ui.label3_pd_flow_graphs_description.text() + get_line)

                # Variables
                if line.startswith("        # Variables"):
                    parsing = True
                elif line.startswith("        # Blocks"):
                    parsing = False
                if parsing:
                    # Strip Extra Text
                    get_line = line.split('=',1)[-1]
                    get_line = get_line.split('#',1)[0]
                    get_line = get_line.lstrip()

                    if get_line != "":
                        # Fill in the "Default Variables" Label
                        dashboard.ui.label3_pd_flow_graphs_default_variables.setText(dashboard.ui.label3_pd_flow_graphs_default_variables.text() + get_line)

                        # Fill in the "Current Values" Table
                        variable_name = get_line.split(' = ')[0]
                        variable_name_item = QtWidgets.QTableWidgetItem(variable_name)
                        value_text = get_line.split(' = ')[1].rstrip('\n')
                        value_text = value_text.replace('"','')

                        # Replace with Global Constants
                        if variable_name == 'ip_address':
                            value_text = get_hardware_ip
                        elif variable_name == 'serial':
                            if len(get_hardware_serial) > 0:
                                if get_hardware_type == 'HackRF':
                                    value_text = get_hardware_serial
                                elif get_hardware_type == 'bladeRF':
                                    value_text = get_hardware_serial
                                elif get_hardware_type == 'bladeRF 2.0':
                                    value_text = get_hardware_serial
                                elif get_hardware_type == 'RTL2832U':
                                    value_text = get_hardware_serial
                                else:
                                    value_text = 'serial=' + get_hardware_serial
                            else:
                                if get_hardware_type == 'HackRF':
                                    value_text = ''
                                elif get_hardware_type == 'bladeRF':
                                    value_text = '0'
                                elif get_hardware_type == 'bladeRF 2.0':
                                    value_text = '0'
                                elif get_hardware_type == 'RTL2832U':
                                    value_text = '0'
                                else:
                                    value_text = 'False'

                        # Fill in the "Current Values" Table
                        value = QtWidgets.QTableWidgetItem(value_text)
                        dashboard.ui.tableWidget_pd_flow_graphs_current_values.setRowCount(dashboard.ui.tableWidget_pd_flow_graphs_current_values.rowCount()+1)
                        dashboard.ui.tableWidget_pd_flow_graphs_current_values.setVerticalHeaderItem(dashboard.ui.tableWidget_pd_flow_graphs_current_values.rowCount()-1,variable_name_item)
                        dashboard.ui.tableWidget_pd_flow_graphs_current_values.setItem(dashboard.ui.tableWidget_pd_flow_graphs_current_values.rowCount()-1,0,value)

                        # Store Variables and Values to a Dictionary
                        temp_flow_graph_variables[str(variable_name_item.text())] = str(value.text())

                        # Create Apply Pushbutton
                        #new_pushbutton = QtWidgets.QPushButton(dashboard.ui.tableWidget_pd_flow_graphs_current_values)
                        #new_pushbutton.setText("Apply")
                        #dashboard.ui.tableWidget_pd_flow_graphs_current_values.setCellWidget(dashboard.ui.tableWidget_pd_flow_graphs_current_values.rowCount()-1,1,new_pushbutton)
                        #new_pushbutton.clicked.connect(_slotPD_DemodulationApplyChangesClicked)

            # Close the File
            f.close()

            # Adjust Table
            dashboard.ui.tableWidget_pd_flow_graphs_current_values.resizeRowsToContents()

            # Copy the Flow Graph Dictionary
            dashboard.flow_graph_variables = temp_flow_graph_variables

            # Enable/Disable the Push Buttons
            dashboard.ui.pushButton_pd_flow_graphs_view.setEnabled(True)
            dashboard.ui.pushButton_pd_flow_graphs_start_stop.setEnabled(True)
            dashboard.ui.pushButton_pd_flow_graphs_apply_changes.setEnabled(False)
            dashboard.ui.pushButton_pd_flow_graphs_restore_defaults.setEnabled(False)

            # Update Flow Graph Status Label
            dashboard.ui.label2_pd_flow_graphs_status.setText("Not Running")

            # Enable Protocol Discovery
            dashboard.ui.pushButton_pd_status_start.setEnabled(True)

            # Start Protocol Discovery if "Auto-Start Protocol Discovery" is Activated
            if dashboard.ui.checkBox_automation_auto_start_pd.isChecked():
                _slotPD_StatusStartClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DemodulationLookupClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the values of the edit boxes in the "Flow Graph" Tab
    """
    dashboard.ui.textEdit_pd_flow_graphs_frequency.setPlainText("")
    dashboard.ui.textEdit_pd_flow_graphs_modulation.setPlainText("")
    dashboard.ui.textEdit_pd_flow_graphs_bandwidth.setPlainText("")
    dashboard.ui.comboBox_pd_flow_graphs_continuous.setCurrentIndex(1)
    dashboard.ui.textEdit_pd_flow_graphs_start_frequency.setPlainText("")
    dashboard.ui.textEdit_pd_flow_graphs_end_frequency.setPlainText("")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DemodulationRestoreDefaultsClicked(dashboard: QtCore.QObject):
    """ Updates the "Current Values" table with the default variables in the flow graph python file
    """
    # Get Flow Graph Filepath
    fname = dashboard.ui.textEdit_pd_flow_graphs_filepath.toPlainText()

    # If a Valid File
    if fname != "":
        # Update the Variable Listings in "Flow Graph" tab
        f = open(fname,'r')
        dashboard.ui.tableWidget_pd_flow_graphs_current_values.clearContents()
        dashboard.ui.tableWidget_pd_flow_graphs_current_values.setRowCount(0)
        parsing = False
        for line in f:
            if line.startswith("        # Variables"):
                parsing = True
            elif line.startswith("        # Blocks"):
                parsing = False
            if parsing:
                # Strip Extra Text
                get_line = line.split('=',1)[-1]
                get_line = get_line.split('#',1)[0]
                get_line = get_line.lstrip()

                if get_line != "":
                    # Fill in the "Current Values" Table
                    variable_name = QtWidgets.QTableWidgetItem(get_line.split(' = ')[0])
                    value_text = get_line.split(' = ')[1].rstrip('\n')
                    value_text = value_text.replace('"','')
                    value = QtWidgets.QTableWidgetItem(value_text)
                    dashboard.ui.tableWidget_pd_flow_graphs_current_values.setRowCount(dashboard.ui.tableWidget_pd_flow_graphs_current_values.rowCount()+1)
                    dashboard.ui.tableWidget_pd_flow_graphs_current_values.setVerticalHeaderItem(dashboard.ui.tableWidget_pd_flow_graphs_current_values.rowCount()-1,variable_name)
                    dashboard.ui.tableWidget_pd_flow_graphs_current_values.setItem(dashboard.ui.tableWidget_pd_flow_graphs_current_values.rowCount()-1,0,value)

        # Close the File
        f.close()

        # Adjust Table
        dashboard.ui.tableWidget_pd_flow_graphs_current_values.resizeRowsToContents()

        # Disable the Pushbutton
        dashboard.ui.pushButton_pd_flow_graphs_restore_defaults.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingDetectFieldsClicked(dashboard: QtCore.QObject, field_locations = False, packet_data = None):
    """ 
    Begins slicing the packets in the packet table by potential fields. The table then highlights the different detected fields.
    """
    # Reset the Field Types
    dashboard.bit_slicing_column_type = []

    # Get the Selected Packets of Length N
    get_row = dashboard.ui.tableWidget_pd_bit_slicing_lengths.currentRow()

    # Get the Table Data
    length_item_value = int(dashboard.ui.tableWidget_pd_bit_slicing_lengths.item(get_row,0).text())
    if packet_data == None:
        packet_data = dashboard.first_n_packets[length_item_value]

    # Get the Field Delineations
    if type(field_locations) is bool:
        # Get the Field Locations
        field_locations = []
        for row in range(0,dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.rowCount()):
            field_locations.append(int(dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.item(row,0).text()))

    # Append the Data End
    field_locations.append(int(dashboard.ui.tableWidget_pd_bit_slicing_lengths.item(dashboard.ui.tableWidget_pd_bit_slicing_lengths.currentRow(),0).text()))

    # Clear the Packet Table
    for row in reversed(range(0,dashboard.ui.tableWidget_pd_bit_slicing_packets.rowCount())):
        dashboard.ui.tableWidget_pd_bit_slicing_packets.removeRow(row)
    for col in reversed(range(0,dashboard.ui.tableWidget_pd_bit_slicing_packets.columnCount())):
        dashboard.ui.tableWidget_pd_bit_slicing_packets.removeColumn(col)

    # Break up Packets By Field Lengths
    dashboard.ui.tableWidget_pd_bit_slicing_packets.setRowCount(len(packet_data))
    for n in range(0,len(field_locations)-1):
        # Add Column
        new_color = dashboard.suitable_colors[n%len(dashboard.suitable_colors)]
        dashboard.ui.tableWidget_pd_bit_slicing_packets.setColumnCount(dashboard.ui.tableWidget_pd_bit_slicing_packets.columnCount() + 1)
        header_item = QtWidgets.QTableWidgetItem(dashboard.colnum_string(n+1))
        header_item.setTextAlignment(QtCore.Qt.AlignCenter)
        header_item.setForeground(QtGui.QColor(255,0,0))
        dashboard.ui.tableWidget_pd_bit_slicing_packets.setHorizontalHeaderItem(dashboard.ui.tableWidget_pd_bit_slicing_packets.columnCount()-1,header_item)

        # Add Field Values to the Packet Table for Each Packet
        for m in range(0,len(packet_data)):
            packet_item = QtWidgets.QTableWidgetItem(packet_data[m][field_locations[n]:field_locations[n+1]])
            packet_item.setTextAlignment(QtCore.Qt.AlignCenter)
            if dashboard.ui.checkBox_pd_bit_slicing_colors.isChecked():
                packet_item.setBackground(QtGui.QColor(new_color[0],new_color[1],new_color[2]))
            dashboard.ui.tableWidget_pd_bit_slicing_packets.setItem(m,n,packet_item)

        # Default to Hex
        dashboard.bit_slicing_column_type.append("Binary")
        if len(str(packet_item.text()))%4 == 0:
            _slotPD_BitSlicingColumnClicked(dashboard, n)

    # Resize the Table
    dashboard.ui.tableWidget_pd_bit_slicing_packets.resizeColumnsToContents()
    dashboard.ui.tableWidget_pd_bit_slicing_packets.resizeRowsToContents()
    dashboard.ui.tableWidget_pd_bit_slicing_packets.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_pd_bit_slicing_packets.horizontalHeader().setStretchLastSection(True)

    # Enable the Controls
    dashboard.ui.label2_pd_bit_slicing_field_delineations.setEnabled(True)
    dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.setEnabled(True)
    dashboard.ui.pushButton_pd_bit_slicing_add_to_library.setEnabled(True)
    dashboard.ui.pushButton_pd_bit_slicing_refresh.setEnabled(True)
    dashboard.ui.pushButton_pd_bit_slicing_insert_field.setEnabled(True)
    dashboard.ui.pushButton_pd_bit_slicing_remove_field.setEnabled(True)
    dashboard.ui.pushButton_pd_bit_slicing_search_library.setEnabled(True)
    dashboard.ui.pushButton_pd_bit_slicing_reset.setEnabled(True)

    # Populate Field Delineation Table
    dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.setRowCount(dashboard.ui.tableWidget_pd_bit_slicing_packets.columnCount())
    for n in range(0,dashboard.ui.tableWidget_pd_bit_slicing_packets.columnCount()):
        # Header Item
        header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_pd_bit_slicing_packets.horizontalHeaderItem(n).text()))
        header_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.setVerticalHeaderItem(n,header_item)

        # Table Item
        table_item = QtWidgets.QTableWidgetItem(str(field_locations[n]))
        table_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.setItem(n,0,table_item)

    # Resize the Table
    dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.resizeRowsToContents()

    # Reset the Current Selection
    dashboard.ui.tableWidget_pd_bit_slicing_packets.setCurrentCell(0,0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Updates the packet table with the fields entered in the field delineation table
    """
    # Get the Field Locations
    field_locations = []
    for row in range(0,dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.rowCount()):
        field_locations.append(int(dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.item(row,0).text()))

    # Update the Packet Table
    _slotPD_BitSlicingDetectFieldsClicked(dashboard, field_locations)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingRemoveFieldClicked(dashboard: QtCore.QObject):
    """ 
    Removes a field/row from the field delineation table.
    """
    # Remove the Current Row
    dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.removeRow(dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.currentRow())

    # Reset the Current Selection
    dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.setCurrentCell(dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.currentRow(),0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingSliceClicked(dashboard: QtCore.QObject, slicing_interval=0):
    """ 
    Divides the remaining bits in the bit slicing table by byte.
    """
    # Get the Slicing Interval
    if slicing_interval == 0:
        slicing_interval = int(dashboard.ui.spinBox_pd_bit_slicing_interval.value())

    # Divide the Bits
    column_text = ""
    for col in range(0,dashboard.ui.tableWidget_pd_bit_slicing_packets.columnCount()):
        # Get the Data as Binary
        get_data = str(dashboard.ui.tableWidget_pd_bit_slicing_packets.item(0,col).text())
        if dashboard.bit_slicing_column_type[col] == "Binary":
            column_text += get_data
        else:
            bin_str = bin(int(get_data, 16))[2:].zfill(int(len(get_data)*4))
            column_text += bin_str
    byte_list = [column_text[i:i+slicing_interval] for i in range(0, len(column_text), slicing_interval)]

    # Add Field Delineations
    field_delineations = [0]
    for n in range(0,len(byte_list)):
        field_delineations.append((n+1)*slicing_interval)

    # Update the Tables
    _slotPD_BitSlicingDetectFieldsClicked(dashboard, field_delineations[:-1])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingMergeFieldsClicked(dashboard: QtCore.QObject):
    """ 
    Assigns a field to the highlighted text in the bit slicing table.
    """
    # Get Selected Items
    selection_range = dashboard.ui.tableWidget_pd_bit_slicing_packets.selectedRanges()[0]

    # Get the Unique Columns
    first_column = selection_range.leftColumn()
    last_column = selection_range.rightColumn()

    # Insert the Text/Bits to the First Column
    if first_column < last_column:
        for row in range(0,dashboard.ui.tableWidget_pd_bit_slicing_packets.rowCount()):
            new_text = ""
            for col in range(first_column,last_column+1):
                # Get the Data as Binary
                get_data = str(dashboard.ui.tableWidget_pd_bit_slicing_packets.item(row,col).text())
                if dashboard.bit_slicing_column_type[col] == "Binary":
                    new_text += get_data
                else:
                    bin_str = bin(int(get_data, 16))[2:].zfill(int(len(get_data)*4))
                    new_text += bin_str

            # Set the Text
            table_item = QtWidgets.QTableWidgetItem(new_text)
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_pd_bit_slicing_packets.setItem(row,first_column,table_item)

        # Delete the Columns and Field Delineations
        for col in reversed(range(first_column+1,last_column+1)):
            dashboard.ui.tableWidget_pd_bit_slicing_packets.removeColumn(col)
            dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.removeRow(col)

            # Move the Colors to the End
            dashboard.suitable_colors.insert(-1, dashboard.suitable_colors.pop(col))  # Keeps the same color order for the other columns

    # Refresh the Table
    _slotPD_BitSlicingRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingSplitFieldsClicked(dashboard: QtCore.QObject):
    """ 
    Unassigns a field in the bit slicing table.
    """
    # Get Selected Items
    selection_range = dashboard.ui.tableWidget_pd_bit_slicing_packets.selectedRanges()[0]

    # Get the Unique Columns
    first_column = selection_range.leftColumn()
    last_column = selection_range.rightColumn()

    # Get the Split Interval
    split_interval = int(dashboard.ui.spinBox_pd_bit_slicining_split_interval.value())

    # Get the Combined Text
    new_text = ""
    for col in range(first_column,last_column+1):
        # Get the Data as Binary
        get_data = str(dashboard.ui.tableWidget_pd_bit_slicing_packets.item(0,col).text())
        if dashboard.bit_slicing_column_type[col] == "Binary":
            new_text += get_data
        else:
            bin_str = bin(int(get_data, 16))[2:].zfill(int(len(get_data)*4))
            new_text += bin_str

    # Divide the Bits
    bit_list = [new_text[i:i+split_interval] for i in range(0, len(new_text), split_interval)]

    # Remove Split Field Delineations
    first_location = int(dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.item(first_column,0).text())
    for row in reversed(range(first_column,last_column+1)):
        dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.removeRow(row)

    # Move the First Color to the End
    dashboard.suitable_colors.insert(-1, dashboard.suitable_colors.pop(first_column))

    # Add Field Delineations
    for col in range(first_column,first_column+len(bit_list)):
        # Insert a Row
        dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.insertRow(col)

        # Set the Text
        table_item = QtWidgets.QTableWidgetItem(str((col-first_column)*split_interval+first_location))
        table_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.setItem(col,0,table_item)

        # Move the Colors from the End
        dashboard.suitable_colors.insert(col, dashboard.suitable_colors.pop(-1))  # Keeps the same color order for the other columns

    # Refresh the Table
    _slotPD_BitSlicingRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingShiftLeftClicked(dashboard: QtCore.QObject):
    """ 
    Shifts the data in the bit slicing table to the left one bit (circular shift).
    """
    # Update the Shift Counter
    dashboard.bit_shift_counter -= 1
    shifted_data = []

    # Get Length Value
    get_row = dashboard.ui.tableWidget_pd_bit_slicing_lengths.currentRow()
    length_item_value = int(dashboard.ui.tableWidget_pd_bit_slicing_lengths.item(get_row,0).text())

    # Shift the Data to the Left
    if dashboard.bit_shift_counter < 0:
        for n in range(0,len(dashboard.first_n_packets[length_item_value])):
            shifted_data.append(dashboard.first_n_packets[length_item_value][n][-dashboard.bit_shift_counter:] + dashboard.first_n_packets[length_item_value][n][0:-dashboard.bit_shift_counter])

    # Shift the Data to the Right
    elif dashboard.bit_shift_counter > 0:
        for n in range(0,len(dashboard.first_n_packets[length_item_value])):
            shifted_data.append(dashboard.first_n_packets[length_item_value][n][-dashboard.bit_shift_counter] + dashboard.first_n_packets[length_item_value][n][0:-dashboard.bit_shift_counter+1])

    # Original Data
    else:
        shifted_data = dashboard.first_n_packets[length_item_value]

    # Redraw the Table
    _slotPD_BitSlicingDetectFieldsClicked(dashboard, False, shifted_data)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingShiftRightClicked(dashboard: QtCore.QObject):
    """ 
    Shifts the data in the bit slicing table to the right one bit (circular shift).
    """
    # Update the Shift Counter
    dashboard.bit_shift_counter += 1
    shifted_data = []

    # Get Length Value
    get_row = dashboard.ui.tableWidget_pd_bit_slicing_lengths.currentRow()
    length_item_value = int(dashboard.ui.tableWidget_pd_bit_slicing_lengths.item(get_row,0).text())

    # Shift the Data to the Left
    if dashboard.bit_shift_counter < 0:
        for n in range(0,len(dashboard.first_n_packets[length_item_value])):
            shifted_data.append(dashboard.first_n_packets[length_item_value][n][-dashboard.bit_shift_counter:] + dashboard.first_n_packets[length_item_value][n][0:-dashboard.bit_shift_counter])

    # Shift the Data to the Right
    elif dashboard.bit_shift_counter > 0:
        for n in range(0,len(dashboard.first_n_packets[length_item_value])):
            shifted_data.append(dashboard.first_n_packets[length_item_value][n][-dashboard.bit_shift_counter] + dashboard.first_n_packets[length_item_value][n][0:-dashboard.bit_shift_counter+1])

    # Original Data
    else:
        shifted_data = dashboard.first_n_packets[length_item_value]

    # Redraw the Table
    _slotPD_BitSlicingDetectFieldsClicked(dashboard, False, shifted_data)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerHexClicked(dashboard: QtCore.QObject):
    """ 
    Converts list of bits into hex.
    """
    # Get List of Bits
    get_bits_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_bits.toPlainText())
    if len(get_bits_str) > 0:
        # Remove Spaces
        get_bits_str = get_bits_str.replace(" ","")

        # Split by Line
        get_bits = get_bits_str.splitlines()

        # Convert Each to Hex
        get_hex = []
        for b in get_bits:

            # Get Rid of Bits on End
            bit_modulo = len(b) % 4
            if bit_modulo != 0:
                b = b[:-bit_modulo]

            get_hex.append( str(('%0*X' % (2,int(b,2))).zfill(int(len(b)/4))) )

        # Clear the Hex Edit Box
        if dashboard.ui.checkBox_pd_bit_viewer_replace.isChecked():
            dashboard.ui.plainTextEdit_pd_bit_viewer_hex.setPlainText("")

        # Put Hex Strings in Table
        for i in get_hex:
            dashboard.ui.plainTextEdit_pd_bit_viewer_hex.appendPlainText(i)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerSortClicked(dashboard: QtCore.QObject):
    """ 
    Sorts the Hex Output Alphabetically
    """
    # Sort Hex Text Edit Box
    get_hex_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_hex.toPlainText())
    if len(get_hex_str) > 0:
        get_hex = sorted(get_hex_str.splitlines())
        dashboard.ui.plainTextEdit_pd_bit_viewer_hex.setPlainText("")
        for i in get_hex:
            dashboard.ui.plainTextEdit_pd_bit_viewer_hex.appendPlainText(i)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerSendToBufferClicked(dashboard: QtCore.QObject):
    """ 
    Sends Hex Edit Box Data to Circular Buffer
    """
    # Get Hex Data from Edit Box
    get_hex_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_hex.toPlainText())
    get_hex_str = get_hex_str.replace("\n","")

    if len(get_hex_str) > 0:

        # Even Number of Nibbles
        nibble_modulo = len(get_hex_str) % 2
        if nibble_modulo != 0:
            get_hex_str = get_hex_str[:-nibble_modulo]

        # Convert Strings to Bytes
        hex_bytes = bytearray.fromhex(get_hex_str)

        # # Make a PUB Socket  # Update this network connection
        # pd_bits_port = self.fissure_settings['pd_bits_port']
        # ctx = zmq.Context()
        # sock = ctx.socket(zmq.PUB)
        # sock.bind("tcp://127.0.0.1:" + str(pd_bits_port))
        # #sock.bind("tcp://127.0.0.1:5066")
        # time.sleep(1)
        # sock.send(hex_bytes)
        # print("Sent string: %s ..." % get_hex_str)
        # time.sleep(1)
        # sock.close()
        # ctx.term()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerTableSortClicked(dashboard: QtCore.QObject):
    """ 
    Sorts the Hex Output Alphabetically
    """
    # Sort Hex Text Edit Box and Table Widget
    get_hex_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_hex.toPlainText())
    if len(get_hex_str) > 0:
        get_hex = sorted(get_hex_str.splitlines())
        dashboard.ui.tableWidget_pd_bit_viewer_hex.setRowCount(0)
        for i in get_hex:
            # Insert a Row
            dashboard.ui.tableWidget_pd_bit_viewer_hex.setRowCount(dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()+1)

            # Set the Text
            table_item = QtWidgets.QTableWidgetItem(str(i))
            dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()-1,0,table_item)

        # Resize Table
        dashboard.ui.tableWidget_pd_bit_viewer_hex.resizeColumnsToContents()
        dashboard.ui.tableWidget_pd_bit_viewer_hex.resizeRowsToContents()
        dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerFillTableClicked(dashboard: QtCore.QObject):
    """ 
    Fills the protocol matching table with hex data.
    """
    # Get Hex
    get_hex = str(dashboard.ui.plainTextEdit_pd_bit_viewer_hex.toPlainText())

    if len(get_hex) > 0:

        # Remove Spaces
        get_hex = get_hex.replace(" ","")

        # Clear the Hex Table
        if dashboard.ui.checkBox_pd_bit_viewer_table_replace.isChecked():
            dashboard.ui.tableWidget_pd_bit_viewer_hex.setRowCount(0)
            dashboard.ui.tableWidget_pd_bit_viewer_hex.setColumnCount(1)
            header_item = QtWidgets.QTableWidgetItem("Data")
            header_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_pd_bit_viewer_hex.setHorizontalHeaderItem(0,header_item)

        # Put Hex Strings in Table
        for i in get_hex.split():
            # Insert a Row
            dashboard.ui.tableWidget_pd_bit_viewer_hex.setRowCount(dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()+1)

            # Set the Text
            table_item = QtWidgets.QTableWidgetItem(str(i))
            dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()-1,0,table_item)

        # Resize Table
        dashboard.ui.tableWidget_pd_bit_viewer_hex.resizeColumnsToContents()
        dashboard.ui.tableWidget_pd_bit_viewer_hex.resizeRowsToContents()
        dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeader().setStretchLastSection(True)

        # Enable Buttons
        dashboard.ui.pushButton_pd_bit_viewer_table_sort.setEnabled(True)
        dashboard.ui.pushButton_pd_bit_viewer_apply.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerApplyClicked(dashboard: QtCore.QObject):
    """ 
    Applies message fields to the data in the protocol matching table.
    """
    if dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount() > 0:
        # Disable Button to Force "Fill Table" Button Press
        dashboard.ui.pushButton_pd_bit_viewer_apply.setEnabled(False)
        
        # Get Protocol and Subcategory
        get_protocol = str(dashboard.ui.comboBox_pd_bit_viewer_protocols.currentText())
        get_subcategory = str(dashboard.ui.comboBox_pd_bit_viewer_subcategory.currentText())
        
        # Get Alignment
        if dashboard.ui.radioButton_pd_bit_viewer_left_align.isChecked():
            get_alignment = 'left'
        else:
            get_alignment = 'right'

        # Raw Diffs the Bits
        if get_protocol == "Raw":
            # Find Max Number of Bits
            max_bit_len = 0
            for row in range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()):
                get_data = str(dashboard.ui.tableWidget_pd_bit_viewer_hex.item(row,0).text())
                bit_len = len(get_data)*4
                if bit_len > max_bit_len:
                    max_bit_len = bit_len
            
            # Make Columns
            dashboard.ui.tableWidget_pd_bit_viewer_hex.setColumnCount(max_bit_len)
            if get_alignment == 'left':
                for col in range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.columnCount()):
                    header_item = QtWidgets.QTableWidgetItem(str(7-(col%8)))
                    header_item.setTextAlignment(QtCore.Qt.AlignCenter)
                    header_item.setForeground(QtGui.QColor(0,0,0))
                    dashboard.ui.tableWidget_pd_bit_viewer_hex.setHorizontalHeaderItem(col,header_item)
            else:
                counter = 0
                for col in reversed(range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.columnCount())):
                    header_item = QtWidgets.QTableWidgetItem(str(counter))
                    header_item.setTextAlignment(QtCore.Qt.AlignCenter)
                    header_item.setForeground(QtGui.QColor(0,0,0))
                    dashboard.ui.tableWidget_pd_bit_viewer_hex.setHorizontalHeaderItem(col,header_item)
                    counter = counter + 1
                    if counter == 8:
                        counter = 0
            
            # Fill the Rows with Bits
            for row in range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()):
                # Get the Table Data
                get_data = str(dashboard.ui.tableWidget_pd_bit_viewer_hex.item(row,0).text())
                hex_len = len(get_data)
                bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))
                dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(row,0,QtWidgets.QTableWidgetItem(''))
                
                # Left-Align
                if get_alignment == 'left':
                    for col in range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.columnCount()):
                        if col < len(bin_str):
                            bit_item = QtWidgets.QTableWidgetItem(bin_str[col])
                            bit_item.setTextAlignment(QtCore.Qt.AlignCenter)
                            dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(row,col,bit_item)
                
                # Right-Align
                else:
                    for col in range(0,len(bin_str)):
                        bit_item = QtWidgets.QTableWidgetItem(bin_str[col])
                        bit_item.setTextAlignment(QtCore.Qt.AlignCenter)
                        dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(row,col+(dashboard.ui.tableWidget_pd_bit_viewer_hex.columnCount()-len(bin_str)),bit_item)
                        
            # Colorize the Bits that are Different
            for col in reversed(range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.columnCount())):
                # Find First Bit Value
                first_bit_value = ''
                color_column = False
                for row in range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()):
                    try:
                        get_data = str(dashboard.ui.tableWidget_pd_bit_viewer_hex.item(row,col).text())
                    except:
                        get_data = ''
                    if len(get_data) > 0:
                        first_bit_value = get_data
                        break
                        
                # Find a Difference
                for row in range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()):
                    try:
                        get_data = str(dashboard.ui.tableWidget_pd_bit_viewer_hex.item(row,col).text())
                    except:
                        get_data = ''
                    if len(get_data) > 0:
                        if get_data != first_bit_value:
                            color_column = True
                            break
                        
                # Color Columns
                if color_column == True:
                    for row in range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()):
                        try:
                            get_data = str(dashboard.ui.tableWidget_pd_bit_viewer_hex.item(row,col).text())
                        except:
                            get_data = ''
                        bit_item = QtWidgets.QTableWidgetItem(get_data)
                        bit_item.setTextAlignment(QtCore.Qt.AlignCenter)
                        bit_item.setForeground(QtGui.QColor(255,0,0))
                        dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(row,col,bit_item)

        # Compare Against Library
        else:
            try:
                # Fields
                fields = fissure.utils.library.getFields(dashboard.backend.library, get_protocol, get_subcategory)
                dashboard.ui.tableWidget_pd_bit_viewer_hex.setColumnCount(len(fields)+1)

                # Lengths
                get_lengths = []
                for n in range(0,len(fields)):
                    get_lengths.append(dashboard.backend.library["Protocols"][get_protocol]['Packet Types'][get_subcategory]['Fields'][fields[n]]['Length'])

            except KeyError:
                #No Fields Defined!
                fissure.Dashboard.UI_Components.Qt5.errorMessage("No Fields Defined!")

            if len(get_lengths) > 0:

                # Break up Packets By Field Lengths
                dashboard.bit_viewer_column_type = []
                if get_alignment == 'left':
                    col_offset = 0
                else:
                    col_offset = 1
                for col in range(0,len(fields)):
                    # Add Column
                    new_color = dashboard.suitable_colors[0]
                    header_item = QtWidgets.QTableWidgetItem(fields[col])
                    header_item.setTextAlignment(QtCore.Qt.AlignCenter)
                    header_item.setForeground(QtGui.QColor(255,0,0))
                    dashboard.ui.tableWidget_pd_bit_viewer_hex.setHorizontalHeaderItem(col+col_offset,header_item)
                    dashboard.bit_viewer_column_type.append("Binary")
                dashboard.bit_viewer_column_type.append("Binary")  # "Extra"

                # Create "Extra" Column
                new_color = dashboard.suitable_colors[0]
                header_item = QtWidgets.QTableWidgetItem("Extra")
                header_item.setTextAlignment(QtCore.Qt.AlignCenter)
                header_item.setForeground(QtGui.QColor(255,0,0))
                if get_alignment == 'left':
                    dashboard.ui.tableWidget_pd_bit_viewer_hex.setHorizontalHeaderItem(len(fields),header_item)
                else:
                    dashboard.ui.tableWidget_pd_bit_viewer_hex.setHorizontalHeaderItem(0,header_item)
                    
                for row in range(0,dashboard.ui.tableWidget_pd_bit_viewer_hex.rowCount()):

                    # Get the Table Data
                    get_data = str(dashboard.ui.tableWidget_pd_bit_viewer_hex.item(row,0).text())
                    hex_len = len(get_data)
                    bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))
                    bit_index = 0

                    # Populate the Row
                    if get_alignment == 'left':
                        for col in range(0,len(fields)+1):
                            if col == len(fields):
                                data_item = QtWidgets.QTableWidgetItem(bin_str[bit_index::])
                            else:
                                data_item = QtWidgets.QTableWidgetItem(bin_str[bit_index:bit_index+get_lengths[col]])
                                bit_index = bit_index + get_lengths[col]
                            data_item.setTextAlignment(QtCore.Qt.AlignCenter)
                            dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(row,col,data_item)
                    else:
                        data_item = QtWidgets.QTableWidgetItem('')
                        data_item.setTextAlignment(QtCore.Qt.AlignCenter)
                        dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(row,0,data_item)   
                        for col in reversed(range(0,len(fields)+1)):
                            if col == 0:
                                if len(bin_str)-bit_index > 0:
                                    data_item = QtWidgets.QTableWidgetItem(bin_str[0:bit_index])
                                    data_item.setTextAlignment(QtCore.Qt.AlignCenter)
                                    dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(row,0,data_item)
                            else:
                                if (len(bin_str)-get_lengths[col-1]-bit_index) < 0:
                                    data_item = QtWidgets.QTableWidgetItem(bin_str[0:len(bin_str)-bit_index])
                                    data_item.setTextAlignment(QtCore.Qt.AlignCenter)
                                    dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(row,col,data_item)
                                    break
                                else:
                                    data_item = QtWidgets.QTableWidgetItem(bin_str[len(bin_str)-get_lengths[col-1]-bit_index:len(bin_str)-bit_index])
                                    data_item.setTextAlignment(QtCore.Qt.AlignCenter)
                                    dashboard.ui.tableWidget_pd_bit_viewer_hex.setItem(row,col,data_item)   
                                    bit_index = bit_index + get_lengths[col-1]

        # Resize the Table
        dashboard.ui.tableWidget_pd_bit_viewer_hex.resizeColumnsToContents()
        dashboard.ui.tableWidget_pd_bit_viewer_hex.resizeRowsToContents()
        dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerInvertClicked(dashboard: QtCore.QObject):
    """ 
    Inverts the bits in the Data Viewer tab.
    """
    # Get List of Bits
    get_bits_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_bits.toPlainText())

    # Invert the Bits
    inverted_bits = []
    if len(get_bits_str) > 0:
        get_bits = get_bits_str.splitlines()
        for x in get_bits:
            inverted_bits.append(x.replace("1", "2").replace("0", "1").replace("2", "0"))

        # Clear the Bits Edit Box
        dashboard.ui.plainTextEdit_pd_bit_viewer_bits.setPlainText("")

        # Put Bit Strings in Table
        for i in inverted_bits:
            dashboard.ui.plainTextEdit_pd_bit_viewer_bits.appendPlainText(i)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerDifferentialClicked(dashboard: QtCore.QObject):
    """ 
    Applies differential encoding to the bits in the Data Viewer tab.
    """
    # Get List of Bits
    get_bits_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_bits.toPlainText())

    # Differentiate the Bits
    diff_bits = []
    if len(get_bits_str) > 0:
        get_bits = get_bits_str.splitlines()

        # Each Row
        for x in get_bits:
            get_diff = ''
            if len(x) > 1:
                # Differentiate
                for b in range(1,len(x)):
                    if x[b-1] == x[b]:
                        get_diff = get_diff + '0'
                    else:
                        get_diff = get_diff + '1'
                diff_bits.append(get_diff)
            elif len(x) == 1:
                diff_bits.append(x[0])

        # Clear the Bits Edit Box
        dashboard.ui.plainTextEdit_pd_bit_viewer_bits.setPlainText("")

        # Put Bit Strings in Table
        for i in diff_bits:
            dashboard.ui.plainTextEdit_pd_bit_viewer_bits.appendPlainText(i)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerManEncClicked(dashboard: QtCore.QObject):
    """ 
    Applies Manchester encoding to the bits in the Data Viewer tab.
    """
    # Get List of Bits
    get_bits_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_bits.toPlainText())

    # Manchester Encode the Bits
    man_bits = []
    if len(get_bits_str) > 0:
        get_bits = get_bits_str.splitlines()

        # Each Row
        for x in get_bits:
            get_man = ''

            # Manchester Encode
            for m in x:
                if m == '0':
                    get_man = get_man + '01'
                else:
                    get_man = get_man + '10'
            man_bits.append(get_man)

        # Clear the Bits Edit Box
        dashboard.ui.plainTextEdit_pd_bit_viewer_bits.setPlainText("")

        # Put Bit Strings in Table
        for i in man_bits:
            dashboard.ui.plainTextEdit_pd_bit_viewer_bits.appendPlainText(i)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerManDecClicked(dashboard: QtCore.QObject):
    """ 
    Applies Manchester decoding to the bits in the Data Viewer tab.
    """
    # Get List of Bits
    get_bits_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_bits.toPlainText())

    # Manchester Decode the Bits
    dec_man_bits = []
    if len(get_bits_str) > 0:
        get_bits = get_bits_str.splitlines()

        # Each Row
        for x in get_bits:
            get_dec_man = ''

            # Manchester Decode
            for m in range(0,len(x),2):
                if x[m:m+2] == '01':
                    get_dec_man = get_dec_man + '0'
                elif x[m:m+2] == '10':
                    get_dec_man = get_dec_man + '1'
                else:
                    get_dec_man = get_dec_man + '?'
            dec_man_bits.append(get_dec_man)

        # Clear the Bits Edit Box
        dashboard.ui.plainTextEdit_pd_bit_viewer_bits.setPlainText("")

        # Put Bit Strings in Table
        for i in dec_man_bits:
            dashboard.ui.plainTextEdit_pd_bit_viewer_bits.appendPlainText(i)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerUnDiff0Clicked(dashboard: QtCore.QObject):
    """ 
    Undoes a bit diff operation starting with a 0.
    """
    # Get List of Bits
    get_bits_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_bits.toPlainText())

    # UnDiff the Bits
    undiff_bits = []
    if len(get_bits_str) > 0:
        get_bits = get_bits_str.splitlines()

        # Each Row
        for x in get_bits:
            get_undiff = '0'
            if len(x) > 1:
                # UnDiff
                for b in range(0,len(x)):
                    # Change
                    if x[b] == '1':
                        if get_undiff[-1] == '0':
                            get_undiff = get_undiff + '1'
                        else:
                            get_undiff = get_undiff + '0'
                    # Same
                    else:
                        if get_undiff[-1] == '0':
                            get_undiff = get_undiff + '0'
                        else:
                            get_undiff = get_undiff + '1'
                undiff_bits.append(get_undiff)

        # Clear the Bits Edit Box
        dashboard.ui.plainTextEdit_pd_bit_viewer_bits.setPlainText("")

        # Put Bit Strings in Table
        for i in undiff_bits:
            dashboard.ui.plainTextEdit_pd_bit_viewer_bits.appendPlainText(i)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerUnDiff1Clicked(dashboard: QtCore.QObject):
    """ 
    Undoes a bit diff operation starting with a 1.
    """
    # Get List of Bits
    get_bits_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_bits.toPlainText())

    # UnDiff the Bits
    undiff_bits = []
    if len(get_bits_str) > 0:
        get_bits = get_bits_str.splitlines()

        # Each Row
        for x in get_bits:
            get_undiff = '1'
            if len(x) > 1:
                # UnDiff
                for b in range(0,len(x)):
                    # Change
                    if x[b] == '1':
                        if get_undiff[-1] == '0':
                            get_undiff = get_undiff + '1'
                        else:
                            get_undiff = get_undiff + '0'
                    # Same
                    else:
                        if get_undiff[-1] == '0':
                            get_undiff = get_undiff + '0'
                        else:
                            get_undiff = get_undiff + '1'
                undiff_bits.append(get_undiff)

        # Clear the Bits Edit Box
        dashboard.ui.plainTextEdit_pd_bit_viewer_bits.setPlainText("")

        # Put Bit Strings in Table
        for i in undiff_bits:
            dashboard.ui.plainTextEdit_pd_bit_viewer_bits.appendPlainText(i)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitViewerBinClicked(dashboard: QtCore.QObject):
    """ 
    Converts list of hex into bits.
    """
    # Get List of Hex
    get_hex_str = str(dashboard.ui.plainTextEdit_pd_bit_viewer_hex.toPlainText())
    if len(get_hex_str) > 0:
        # Remove Spaces
        get_hex_str = get_hex_str.replace(" ","")

        # Split by Line
        get_hex = get_hex_str.splitlines()

        # Convert Each to Binary
        get_bin = []
        for b in get_hex:
            get_bin.append(bin(int(b, 16))[2:].zfill(int(len(b)*4)))

        # Clear the Binary Edit Box
        if dashboard.ui.checkBox_pd_bit_viewer_replace.isChecked():
            dashboard.ui.plainTextEdit_pd_bit_viewer_bits.setPlainText("")

        # Put Binary Strings in Table
        for i in get_bin:
            dashboard.ui.plainTextEdit_pd_bit_viewer_bits.appendPlainText(i)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DissectorsNewClicked(dashboard: QtCore.QObject):
    """ 
    Loads the dissector editor with default values.
    """
    # Repopulate the Contents
    _slotPD_DissectorsPacketTypeChanged(dashboard)

    # Make the Groupbox Visible
    dashboard.ui.frame_pd_dissectors_editor.setVisible(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DissectorsEditClicked(dashboard: QtCore.QObject):
    """ 
    Loads the currently selected dissector for manual editing.
    """
    # Browse for a Lua Dissector
    directory = os.path.join(fissure.utils.FISSURE_ROOT, "Dissectors")  # Default Directory
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select Dissector...", directory, filter="Lua Dissector (*.lua);;All Files (*.*)")[0]

    # Open the Dissector in Gedit
    if fname != "":
        osCommandString = "gedit " + str(fname)
        os.system(osCommandString+ " &")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DissectorsAddFieldClicked(dashboard: QtCore.QObject):
    """ 
    Adds a new row to the Dissectors table in the Dissectors tab.
    """
    # Add Row
    dashboard.ui.tableWidget_pd_dissectors.setRowCount(dashboard.ui.tableWidget_pd_dissectors.rowCount()+1)
    header_item = QtWidgets.QTableWidgetItem("Field" + str(dashboard.ui.tableWidget_pd_dissectors.rowCount()))
    new_font = QtGui.QFont("Ubuntu",10)
    header_item.setFont(new_font)
    header_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_pd_dissectors.setVerticalHeaderItem(dashboard.ui.tableWidget_pd_dissectors.rowCount()-1,header_item)

    # Display Name
    table_item = QtWidgets.QTableWidgetItem("New Field")
    table_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.rowCount()-1,0,table_item)

    # Filter Name
    table_item = QtWidgets.QTableWidgetItem("new_field")
    table_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.rowCount()-1,1,table_item)

    # Type ComboBox
    new_combobox = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
    new_combobox.addItem("ftypes.NONE")
    new_combobox.addItem("ftypes.BOOLEAN")
    new_combobox.addItem("ftypes.CHAR")
    new_combobox.addItem("ftypes.UINT8")
    new_combobox.addItem("ftypes.UINT16")
    new_combobox.addItem("ftypes.UINT24")
    new_combobox.addItem("ftypes.UINT32")
    new_combobox.addItem("ftypes.UINT64")
    new_combobox.addItem("ftypes.INT8")
    new_combobox.addItem("ftypes.INT16")
    new_combobox.addItem("ftypes.INT24")
    new_combobox.addItem("ftypes.INT32")
    new_combobox.addItem("ftypes.INT64")
    new_combobox.addItem("ftypes.FLOAT")
    new_combobox.addItem("ftypes.DOUBLE")
    new_combobox.addItem("ftypes.ABSOLUTE_TIME")
    new_combobox.addItem("ftypes.RELATIVE_TIME")
    new_combobox.addItem("ftypes.STRING")
    new_combobox.addItem("ftypes.STRINGZ")
    new_combobox.addItem("ftypes.UINT_STRING")
    new_combobox.addItem("ftypes.ETHER")
    new_combobox.addItem("ftypes.BYTES")
    new_combobox.addItem("ftypes.UINT_BYTES")
    new_combobox.addItem("ftypes.IPv4")
    new_combobox.addItem("ftypes.IPv6")
    new_combobox.addItem("ftypes.IPXNET")
    new_combobox.addItem("ftypes.FRAMENUM")
    new_combobox.addItem("ftypes.PCRE")
    new_combobox.addItem("ftypes.GUID")
    new_combobox.addItem("ftypes.OID")
    new_combobox.addItem("ftypes.PROTOCOL")
    new_combobox.addItem("ftypes.REL_OID")
    new_combobox.addItem("ftypes.SYSTEM_ID")
    new_combobox.addItem("ftypes.EUI64")
    new_combobox.setCurrentIndex(0)
    new_combobox.currentIndexChanged.connect(lambda: _slotPD_DissectorsTypeChanged(dashboard))
    dashboard.ui.tableWidget_pd_dissectors.setCellWidget(dashboard.ui.tableWidget_pd_dissectors.rowCount()-1,2,new_combobox)

    # Display ComboBox
    new_combobox2 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
    new_combobox2.addItem("base.NONE")
    new_combobox2.addItem("base.DEC")
    new_combobox2.addItem("base.HEX")
    new_combobox2.addItem("base.OCT")
    new_combobox2.addItem("base.DEC_HEX")
    new_combobox2.addItem("base.HEX_DEC")
    new_combobox2.addItem("base.UINT_STRING")
    new_combobox2.addItem("base.RANGE_STRING")
    #new_combobox2.addItem("BASE_CUSTOM")  # Not listed for Lua ProtoField
    #new_combobox2.addItem("STR_ASCII")  # Same as BASE_NONE
    #new_combobox2.addItem("STR_UNICODE")
    #new_combobox2.addItem("BASE_EXT_STRING")
    #new_combobox2.addItem("BASE_VAL64_STRING")
    new_combobox2.setCurrentIndex(0)
    dashboard.ui.tableWidget_pd_dissectors.setCellWidget(dashboard.ui.tableWidget_pd_dissectors.rowCount()-1,3,new_combobox2)

    # Bitmask
    table_item = QtWidgets.QTableWidgetItem("")
    table_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.rowCount()-1,4,table_item)

    # Buffer
    table_item = QtWidgets.QTableWidgetItem("(,)")
    table_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.rowCount()-1,5,table_item)

    # Resize
    dashboard.ui.tableWidget_pd_dissectors.resizeColumnsToContents()
    dashboard.ui.tableWidget_pd_dissectors.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_pd_dissectors.horizontalHeader().setStretchLastSection(True)
    dashboard.ui.tableWidget_pd_dissectors.resizeRowsToContents()

    # Disable ftypes.NONE for ftypes.BYTES
    _slotPD_DissectorsTypeChanged(dashboard)


def _slotPD_DissectorsTypeChanged(dashboard: QtCore.QObject):
    """ 
    This is called when the type is changed. Its purpose is to assign ftypes.BYTES with ftypes.NONE so no errors are produced. Not a slot.
    """
    for row in range(0,dashboard.ui.tableWidget_pd_dissectors.rowCount()):
        if dashboard.ui.tableWidget_pd_dissectors.cellWidget(row,2).currentText() == "ftypes.BYTES":
            dashboard.ui.tableWidget_pd_dissectors.cellWidget(row,3).setEnabled(False)
            dashboard.ui.tableWidget_pd_dissectors.cellWidget(row,3).setCurrentIndex(0)
        else:
            dashboard.ui.tableWidget_pd_dissectors.cellWidget(row,3).setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DissectorsRemoveFieldClicked(dashboard: QtCore.QObject):
    """ 
    Removes the current row in the dissector table in the Dissectors tab.
    """
    # Remove Row
    dashboard.ui.tableWidget_pd_dissectors.removeRow(dashboard.ui.tableWidget_pd_dissectors.currentRow())

    # Relabel the Rows
    new_font = QtGui.QFont("Ubuntu",10)
    for rows in range(0,dashboard.ui.tableWidget_pd_dissectors.rowCount()):
        header_item = QtWidgets.QTableWidgetItem("Field" + str(rows+1))
        header_item.setFont(new_font)
        header_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_pd_dissectors.setVerticalHeaderItem(rows,header_item)

    # Resize
    dashboard.ui.tableWidget_pd_dissectors.resizeColumnsToContents()
    dashboard.ui.tableWidget_pd_dissectors.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_pd_dissectors.horizontalHeader().setStretchLastSection(True)
    dashboard.ui.tableWidget_pd_dissectors.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DissectorsUpClicked(dashboard: QtCore.QObject):
    """ 
    Moves the current field up one position in the field table.
    """
    if dashboard.ui.tableWidget_pd_dissectors.currentRow() != 0:  # Ignore top row
        # Take the Row Above
        above_item0 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,0)
        above_item1 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,1)
        above_item2 = dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,2).currentIndex()
        above_item3 = dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,3).currentIndex()
        above_item4 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,4)
        above_item5 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,5)

        # Take the Current Row
        current_item0 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),0)
        current_item1 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),1)
        current_item2 = dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow(),2).currentIndex()
        current_item3 = dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow(),3).currentIndex()
        current_item4 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),4)
        current_item5 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),5)

        # Set the Current Row
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),0,above_item0)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),1,above_item1)
        dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow(),2).setCurrentIndex(above_item2)
        dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow(),3).setCurrentIndex(above_item3)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),4,above_item4)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),5,above_item5)

        # Set the Row Above
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,0,current_item0)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,1,current_item1)
        dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,2).setCurrentIndex(current_item2)
        dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,3).setCurrentIndex(current_item3)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,4,current_item4)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,5,current_item5)

        # Change the Selected Row
        dashboard.ui.tableWidget_pd_dissectors.setCurrentCell(dashboard.ui.tableWidget_pd_dissectors.currentRow()-1,0)

        # Resize
        dashboard.ui.tableWidget_pd_dissectors.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DissectorsDownClicked(dashboard: QtCore.QObject):
    """ 
    Moves the current field down one position in the field table.
    """
    # Get Bottom Row
    bottom_row = dashboard.ui.tableWidget_pd_dissectors.rowCount()

    # Move it Down
    if dashboard.ui.tableWidget_pd_dissectors.currentRow() != bottom_row-1:  # Ignore bottom row
        # Take the Row Below
        below_item0 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,0)
        below_item1 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,1)
        below_item2 = dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,2).currentIndex()
        below_item3 = dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,3).currentIndex()
        below_item4 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,4)
        below_item5 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,5)

        # Take the Current Row
        current_item0 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),0)
        current_item1 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),1)
        current_item2 = dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow(),2).currentIndex()
        current_item3 = dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow(),3).currentIndex()
        current_item4 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),4)
        current_item5 = dashboard.ui.tableWidget_pd_dissectors.takeItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),5)

        # Set the Current Row
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),0,below_item0)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),1,below_item1)
        dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow(),2).setCurrentIndex(below_item2)
        dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow(),3).setCurrentIndex(below_item3)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),4,below_item4)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow(),5,below_item5)

        # Set the Row Above
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,0,current_item0)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,1,current_item1)
        dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,2).setCurrentIndex(current_item2)
        dashboard.ui.tableWidget_pd_dissectors.cellWidget(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,3).setCurrentIndex(current_item3)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,4,current_item4)
        dashboard.ui.tableWidget_pd_dissectors.setItem(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,5,current_item5)

        # Change the Selected Row
        dashboard.ui.tableWidget_pd_dissectors.setCurrentCell(dashboard.ui.tableWidget_pd_dissectors.currentRow()+1,0)

        # Resize
        dashboard.ui.tableWidget_pd_dissectors.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DissectorsPreviewClicked(dashboard: QtCore.QObject):
    """ 
    Opens a message box with the code for the dissector and for the known-protocols.py cases.
    """
    _slotPD_DissectorsConstructClicked(dashboard, preview=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_DissectorsUpdateAllClicked(dashboard: QtCore.QObject):
    """ 
    Copies the contents of the /FISSURE/Dissectors folder to the ~/.config/wireshark/plugins folder.
    """
    # Directories
    dissector_source = os.path.join(fissure.utils.FISSURE_ROOT, "Dissectors")
    dissector_dest = os.path.expanduser("~/.config/wireshark/plugins")

    # Issue the Command
    os.system('cp -R "' + dissector_source + '" "' + dissector_dest + '"')
    fissure.Dashboard.UI_Components.Qt5.errorMessage("Dissectors copied from \"/FISSURE/Dissectors\" to \"~/.config/wireshark/plugins\"")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_SnifferWireshark80211Clicked(dashboard: QtCore.QObject):
    """ 
    Opens Wireshark to an 802.11x interface.
    """
    # Start Wireshark
    get_interface = str(dashboard.ui.textEdit_pd_sniffer_interface.toPlainText())

    # Find Wireshark
    out = subprocess.Popen(['which', 'wireshark'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)

    try:
        stdout, _ = out.communicate(timeout=15)
    except TimeoutError as err:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Error communicating with Wireshark: {}".format(err))

    wireshark_cmd = stdout.decode('UTF-8').strip()
    if not wireshark_cmd:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Wireshark not found!")
        return

    if len(get_interface) == 0 and len(wireshark_cmd) > 0:
        subprocess.Popen([wireshark_cmd])
    else:
        subprocess.Popen([wireshark_cmd, '-k', '-i', get_interface])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_SnifferGuessClicked(dashboard: QtCore.QObject):
    """ 
    Guesses the wireless interface to use for Wireshark.
    """
    # Guess and Store
    get_network_interface = str(dashboard.ui.textEdit_pd_sniffer_interface.toPlainText())
    scan_results, dashboard.guess_index = fissure.utils.hardware.find80211x(get_network_interface, dashboard.guess_index)
    dashboard.ui.textEdit_pd_sniffer_interface.setPlainText(scan_results[4])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_SnifferNetcatClicked(dashboard: QtCore.QObject):
    """ 
    Start a netcat listener in a new terminal.
    """
    # Get the Values
    get_tcp_udp = str(dashboard.ui.comboBox_pd_sniffer_netcat.currentText())
    get_ip = str(dashboard.ui.textEdit_pd_sniffer_netcat_ip.toPlainText())
    get_port = str(dashboard.ui.textEdit_pd_sniffer_netcat_port.toPlainText())

    # Check the Values
    if not (get_port.isdigit() and 1 <= int(get_port) <= 65535):
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a valid port (1-65535).")
        return

    # Issue the Command
    if get_tcp_udp == "TCP":
        if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
            command_text = 'gnome-terminal -- nc -l ' + get_ip + ' ' + get_port + ' &'
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
            command_text = 'qterminal -e nc -l ' + get_ip + ' ' + get_port + ' &'
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
            command_text = 'lxterminal -e nc -l ' + get_ip + ' ' + get_port + ' &'
            
    else:
        if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
            command_text = 'gnome-terminal -- nc -lu ' + get_ip + ' ' + get_port + ' &'
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
            command_text = 'qterminal -e nc -lu ' + get_ip + ' ' + get_port + ' &'
        elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
            command_text = 'lxterminal -e nc -lu ' + get_ip + ' ' + get_port + ' &'

    proc = subprocess.Popen(command_text, shell=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_SnifferTestFolderClicked(dashboard: QtCore.QObject):
    """ 
    Selects a folder for listing more crafted packets in the sniffer test listbox.
    """
    # Choose Folder
    get_dir = str(QtWidgets.QFileDialog.getExistingDirectory(dashboard, "Select Directory"))

    # Add Directory to the Combobox
    if len(get_dir) > 0:
        dashboard.ui.comboBox_pd_sniffer_test_folders.addItem(get_dir)
        dashboard.ui.comboBox_pd_sniffer_test_folders.setCurrentIndex(dashboard.ui.comboBox_pd_sniffer_test_folders.count()-1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_SnifferTestSendClicked(dashboard: QtCore.QObject):
    """ 
    Sends the file data to the Sniffer UDP port using Netcat.
    """
    # Get the Values
    get_file_path = str(dashboard.ui.comboBox_pd_sniffer_test_folders.currentText()) + "/" + str(dashboard.ui.listWidget_pd_sniffer_test_files.currentItem().text())
    get_port = str(dashboard.ui.textEdit_pd_sniffer_test_port.toPlainText())

    # Check the Values
    if not (get_port.isdigit() and 1 <= int(get_port) <= 65535):
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a valid port (1-65535).")
        return

    # Issue the Command
    command_text = 'cat "' + get_file_path + '" | nc -u 127.0.0.1 ' + get_port
    proc = subprocess.Popen(command_text, shell=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_CRC_StartClicked(dashboard: QtCore.QObject):
    """ 
    Calculates the CRC Polynomial based on two inputs and the expected CRCs for each input. 32 is too much memory.
    """
    # Conversions
    #get_input1 = bin(int(get_input1, 16))[2:].zfill(int(len(get_input1)*4))  # Convert to binary strings
    ##get_input1 = int(get_input1,16)  # Convert entire string to int
    #hex_str = '%0*X' % ((len(get_data) + 3) // 4, int(get_data, 2))  #binary to hex
    # "0x%0.2X" % 255  # int to hex
    # int('{:08b}'.format(int(new_byte,16))[::-1], 2)  # reverse byte

    # Reset the Progress Bar
    dashboard.ui.progressBar_pd_crc_progress.setValue(0)

    # Get the Values
    get_width = str(dashboard.ui.comboBox_pd_crc_find_poly.currentText())
    get_seed = str(dashboard.ui.textEdit_pd_crc_seed.toPlainText()).upper()
    get_final_xor = str(dashboard.ui.textEdit_pd_crc_final_xor.toPlainText()).upper()
    get_input1 = str(dashboard.ui.textEdit_pd_crc_input1.toPlainText()).upper()
    get_input2 = str(dashboard.ui.textEdit_pd_crc_input2.toPlainText()).upper()
    get_crc1 = str(dashboard.ui.textEdit_pd_crc_crc1.toPlainText()).upper()
    get_crc2 = str(dashboard.ui.textEdit_pd_crc_crc2.toPlainText()).upper()
    get_reverse_input = dashboard.ui.checkBox_pd_crc_reverse_input.isChecked()
    get_reverse_output = dashboard.ui.checkBox_pd_crc_reverse_final_xor.isChecked()

    # # Special Cases for 32
    # if get_width == "32":
        # # Flip the Poly
        # #get_poly = int('{:08b}'.format(get_poly).zfill(32)[::-1],2)

        # # Make the Seed an int
        # get_seed = int(get_seed,16)

        # # Invert the Reverse Logic
        # get_reverse_input = not get_reverse_input
        # get_reverse_output = not get_reverse_output

    # Calculate Polynomial from Two Known Inputs and CRCs
    match = "No Match"
    if get_width == "8":
        max_poly = 256
    elif get_width == "16":
        max_poly = 65536
    # elif get_width == "32":
        # max_poly = 4294967295

    for p1 in range(0,max_poly):
        # Update the Progress Bar
        dashboard.ui.progressBar_pd_crc_progress.setValue(int(100*p1/max_poly))

        # Known Seed
        acc = get_seed
        for n in range(0,int(len(get_input1)/2)):
            # Reverse Input
            if get_reverse_input == True:
                new_byte = get_input1[2*n:2*n+2]
                new_byte = int('{:08b}'.format(int(new_byte,16))[::-1], 2)
                new_byte = "%0.2X" % new_byte
            else:
                new_byte = get_input1[2*n:2*n+2]

            acc = updateCRC(p1, acc, new_byte, int(get_width))

        # Reverse Output
        if get_reverse_output == True:
            if get_width == "8":
                acc = int('{:08b}'.format(int(acc,16))[::-1], 2)
                acc = "%0.2X" % acc
            elif get_width == "16":
                new_byte1 = acc[0:2]
                new_byte1 = int('{:08b}'.format(int(new_byte1,16))[::-1], 2)
                new_byte1 = "%0.2X" % new_byte1
                new_byte2 = acc[2:4]
                new_byte2 = int('{:08b}'.format(int(new_byte2,16))[::-1], 2)
                new_byte2 = "%0.2X" % new_byte2
                acc = new_byte2 + new_byte1
            # elif get_width == "32":
                # acc = int('{:08b}'.format(acc).zfill(32)[::-1],2)

        # Final XOR
        # if get_width == "32":
            # acc = (acc^int(get_final_xor,16)) & 0xFFFFFFFF
        # else:
        acc = int(acc,16)^int(get_final_xor,16)

        # Format the Data
        if get_width == "8":
            acc = "%0.2X" % acc
        elif get_width == "16":
            acc = "%0.4X" % acc
        # elif get_width == "32":
            # acc = "%0.8X" % acc

        # Input 1 Match
        if acc == get_crc1:
            #print("MATCH1")
            acc = get_seed
            for n in range(0,int(len(get_input2)/2)):
                # Reverse Input
                if get_reverse_input == True:
                    new_byte = get_input2[2*n:2*n+2]
                    new_byte = int('{:08b}'.format(int(new_byte,16))[::-1], 2)
                    new_byte = "%0.2X" % new_byte
                else:
                    new_byte = get_input2[2*n:2*n+2]

                acc = updateCRC(p1, acc, new_byte, int(get_width))

            # Reverse Output
            if get_reverse_output == True:
                if get_width == "8":
                    acc = int('{:08b}'.format(int(acc,16))[::-1], 2)
                    acc = "%0.2X" % acc
                elif get_width == "16":
                    new_byte1 = acc[0:2]
                    new_byte1 = int('{:08b}'.format(int(new_byte1,16))[::-1], 2)
                    new_byte1 = "%0.2X" % new_byte1
                    new_byte2 = acc[2:4]
                    new_byte2 = int('{:08b}'.format(int(new_byte2,16))[::-1], 2)
                    new_byte2 = "%0.2X" % new_byte2
                    acc = new_byte2 + new_byte1
                # elif get_width == "32":
                    # acc = int('{:08b}'.format(acc).zfill(32)[::-1],2)

            # Final XOR
            # if get_width == "32":
                # acc = (acc^int(get_final_xor,16)) & 0xFFFFFFFF
            # else:
            acc = int(acc,16)^int(get_final_xor,16)

            # Format the Data
            if get_width == "8":
                acc = "%0.2X" % acc
            elif get_width == "16":
                acc = "%0.4X" % acc
            # elif get_width == "32":
                # acc = "%0.8X" % acc

            # Input 1 and Input 2 Match
            if acc == get_crc2:
                if get_width == "8":
                    match = "%0.2X" % p1
                elif get_width == "16":
                    match = "%0.4X" % p1
                # elif get_width == "32":
                    # match = "%0.8X" % p1

    # Update the Polynomial Edit Box
    dashboard.ui.textEdit_pd_crc_polynomial.setText(match)
    dashboard.ui.textEdit_pd_crc_polynomial.setAlignment(QtCore.Qt.AlignCenter)

    # Set the Progress Bar
    dashboard.ui.progressBar_pd_crc_progress.setValue(100)


def updateCRC(crc_poly, crc_acc, crc_input, crc_length):
    """ Calculates CRC for bytes. Not a slot.
    """
    # 8-bit CRC
    if crc_length == 8:
        # Convert Hex Byte String to int
        crc_input_int = int(crc_input,16)
        crc_acc_int = int(crc_acc,16)
        crc_acc_int = crc_acc_int ^ crc_input_int
        for _ in range(8):
            crc_acc_int <<= 1
            if crc_acc_int & 0x0100:
                crc_acc_int ^= crc_poly
            #crc &= 0xFF

        # Convert to Hex String
        crc_acc = ("%0.2X" % crc_acc_int)[-2:]

    # 16-bit CRC
    elif crc_length == 16:
        # Convert Hex Byte String to int
        crc_input_int = int(crc_input,16)
        crc_acc_int = int(crc_acc,16)
        crc_acc_int = crc_acc_int ^ (crc_input_int << 8)
        for i in range(0,8):
            if (crc_acc_int & 32768) == 32768:
                crc_acc_int = crc_acc_int << 1
                crc_acc_int = crc_acc_int^crc_poly
            else:
                crc_acc_int = crc_acc_int << 1

        # Convert to Hex String
        crc_acc = "%0.4X" % crc_acc_int

        # Keep Only the Last 2 Bytes
        crc_acc = crc_acc[-4:]

    # 32-bit CRC
    elif crc_length == 32:
        crc_input_int = int(crc_input,16)
        crc_acc = crc_acc ^ crc_input_int
        for _ in range(0,8):
            mask = -(crc_acc & 1)
            crc_acc = (crc_acc >> 1) ^ (crc_poly & mask)

    return crc_acc
    

@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_CRC_CalculateClicked(dashboard: QtCore.QObject):
    """ 
    Calculates the CRC using the selected algorithm.
    """
    # Get Width
    get_width = str(dashboard.ui.comboBox_pd_crc_common_width.currentText())

    # Get the Values
    get_input = str(dashboard.ui.textEdit_pd_crc_input_common.toPlainText())
    get_poly = int(str(dashboard.ui.textEdit_pd_crc_polynomial_common.toPlainText()),16)
    get_seed = str(dashboard.ui.textEdit_pd_crc_seed_common.toPlainText())
    get_final_xor = str(dashboard.ui.textEdit_pd_crc_final_xor_common.toPlainText())
    get_reverse_input = dashboard.ui.checkBox_pd_crc_reverse_input_common.isChecked()
    get_reverse_output = dashboard.ui.checkBox_pd_crc_reverse_final_xor_common.isChecked()

    # Special Cases for 32
    if get_width == "32":
        # Flip the Poly
        get_poly = int('{:08b}'.format(get_poly).zfill(32)[::-1],2)

        # Make the Seed an int
        get_seed = int(get_seed,16)

        # Invert the Reverse Logic
        get_reverse_input = not get_reverse_input
        get_reverse_output = not get_reverse_output

    # Known Seed
    acc = get_seed
    for n in range(0,int(len(get_input)/2)):
        # Reverse Input
        if get_reverse_input == True:
            new_byte = get_input[2*n:2*n+2]
            new_byte = int('{:08b}'.format(int(new_byte,16))[::-1], 2)
            new_byte = "%0.2X" % new_byte
        else:
            new_byte = get_input[2*n:2*n+2]

        # Do CRC
        acc = updateCRC(get_poly, acc, new_byte, int(get_width))

    # This sort of works, but only if get_rev_input and get_rev_output are the same (which is typical). Also, half of the CRC32 defaults are wrong.
    #crc8class = crcmod.Crc(get_poly, initCrc=get_seed, rev=get_rev_input,xorOut=get_final_xor)
    #crc8class = crcmod.Crc(get_poly, initCrc=get_seed, rev=False,xorOut=get_final_xor)
    #crc8class.update(binascii.unhexlify(get_input))
    #crc = crc8class.hexdigest()[-2:]

    # Reverse Output
    if get_reverse_output == True:
        if get_width == "8":
            acc = int('{:08b}'.format(int(acc,16))[::-1], 2)
            acc = "%0.2X" % acc
        elif get_width == "16":
            new_byte1 = acc[0:2]
            new_byte1 = int('{:08b}'.format(int(new_byte1,16))[::-1], 2)
            new_byte1 = "%0.2X" % new_byte1
            new_byte2 = acc[2:4]
            new_byte2 = int('{:08b}'.format(int(new_byte2,16))[::-1], 2)
            new_byte2 = "%0.2X" % new_byte2
            acc = new_byte2 + new_byte1
        elif get_width == "32":
            acc = int('{:08b}'.format(acc).zfill(32)[::-1],2)

    # Final XOR
    if get_width == "32":
        acc = (acc^int(get_final_xor,16)) & 0xFFFFFFFF
    else:
        acc = int(acc,16)^int(get_final_xor,16)

    # Format the Data
    if get_width == "8":
        acc = "%0.2X" % acc
    elif get_width == "16":
        acc = "%0.4X" % acc
    elif get_width == "32":
        acc = "%0.8X" % acc
    dashboard.ui.textEdit_pd_crc_crc_common.setText(acc)
    dashboard.ui.textEdit_pd_crc_crc_common.setAlignment(QtCore.Qt.AlignCenter)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_CRC_RevEngCalculateClicked(dashboard: QtCore.QObject):
    """ 
    Uses CRC RevEng to calculate the CRC for the selected algorithm.
    """
    # Get Input Parameters
    get_algorithm = str(dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentText())
    get_input = str(dashboard.ui.textEdit_pd_crc_input_reveng.toPlainText())

    # Issue the Command
    reveng_directory = os.path.expanduser("~/Installed_by_FISSURE/reveng-3.0.5/bin/i386-linux/")
    proc = subprocess.Popen("./reveng -m " + get_algorithm + " -c " + get_input + " &", cwd=reveng_directory, shell=True, stdout=subprocess.PIPE, )
    output = str(proc.communicate()[0].decode()).strip().upper()

    # Set the Output
    dashboard.ui.textEdit_pd_crc_crc_reveng.setPlainText(output)
    dashboard.ui.textEdit_pd_crc_crc_reveng.setAlignment(QtCore.Qt.AlignCenter)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_AddStatus(dashboard: QtCore.QObject, statusmessage):
    """ 
    Adds a new status message to the Protocol Discovery log after receiving information from the PD component. Not a slot.
    """
    # Add Status Message to PD Log
    get_text = dashboard.ui.textEdit2_pd_status.toPlainText()
    get_text = get_text + statusmessage
    dashboard.ui.textEdit2_pd_status.setText(get_text)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_BitSlicingPlotEntropyClicked(dashboard: QtCore.QObject):
    """ 
    Sends a message to the HIPRFISR/PD to calculate the entropy for the bit positions of fixed-length messages in the buffer when sliced by the preamble.
    """
    # Get the Preamble
    get_preamble = str(dashboard.ui.textEdit_pd_bit_slicing_recommended_preamble.toPlainText())

    # Get the Message Length
    get_row = dashboard.ui.tableWidget_pd_bit_slicing_lengths.currentRow()
    get_message_length = int(dashboard.ui.tableWidget_pd_bit_slicing_lengths.item(get_row,0).text())

    # Send the Message
    await dashboard.backend.findEntropy(get_message_length, get_preamble)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_DissectorsConstructClicked(dashboard: QtCore.QObject, preview = False):
    """ 
    Adds a new packet dissector to the library and the Dissectors folder and Wireshark Lua Default folder.
    """
    try:
        my_error = "Input error."

        # Get Values
        get_filter_name = str(dashboard.ui.textEdit_pd_dissectors_filter_name.toPlainText())
        get_tree_name = str(dashboard.ui.textEdit_pd_dissectors_tree_name.toPlainText())
        get_udp_port = str(dashboard.ui.textEdit_pd_dissectors_udp_port.toPlainText())

        # Check Filter Name Format
        good_chars = []
        good_chars.extend(range(48,58))  # Numbers
        good_chars.extend(range(97,123))  # Lower-Case Letters
        good_chars.append(45)  # '-'
        good_chars.append(95)  # '_'
        good_chars.append(46)  # '.'
        if any(ord(x) not in good_chars for x in get_filter_name):
            my_error = "Filter Name must not contain upper-case letters, numbers, spaces, or symbols other than '-', '_', and '.'."
            raise NameError
    except:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(my_error)

    # Get the Table Values
    get_display_names = []
    get_filter_names = []
    get_types = []
    get_bases = []
    get_bitmasks = []
    get_buffer_locations = []
    for row in range(0,dashboard.ui.tableWidget_pd_dissectors.rowCount()):
        get_display_names.append(str(dashboard.ui.tableWidget_pd_dissectors.item(row,0).text()))
        get_filter_names.append(str(dashboard.ui.tableWidget_pd_dissectors.item(row,1).text()).replace('-','_'))  # Variable names cannot have '-'
        get_types.append(str(dashboard.ui.tableWidget_pd_dissectors.cellWidget(row,2).currentText()))
        get_bases.append(str(dashboard.ui.tableWidget_pd_dissectors.cellWidget(row,3).currentText()))
        if len(str(dashboard.ui.tableWidget_pd_dissectors.item(row,4).text())) == 0:
            get_bitmasks.append('nil')
        else:
            get_bitmasks.append(str(dashboard.ui.tableWidget_pd_dissectors.item(row,4).text()))
        get_buffer_locations.append(str(dashboard.ui.tableWidget_pd_dissectors.item(row,5).text()))

    # Assemble the Text
    dissector_text = 'custom_protocol = Proto("' + get_filter_name + '", "' + get_filter_name + '")\n\n'
    field_list = ''
    for n in range(0,len(get_filter_names)):
        dissector_text = dissector_text + get_filter_names[n] + ' = ProtoField.new("' + get_display_names[n] + '", "' + get_filter_name + '.' + get_filter_names[n] + '", ' + get_types[n] + ', nil, ' + get_bases[n] + ', ' + get_bitmasks[n] + ')\n'
        field_list = field_list + get_filter_names[n] + ', '

    dissector_text = dissector_text + '\ncustom_protocol.fields = {' + field_list[:-2] + '}\n\n'
    dissector_text = dissector_text + 'function custom_protocol.dissector(buffer, pinfo, tree)\n'
    dissector_text = dissector_text + '  length = buffer:len()\n'
    dissector_text = dissector_text + '  if length == 0 then return end\n\n'
    dissector_text = dissector_text + '  pinfo.cols.protocol = custom_protocol.name\n\n'
    dissector_text = dissector_text + '  local subtree = tree:add(custom_protocol, buffer(), "' + get_tree_name + '")\n'
    for n in range(0,len(get_filter_names)):
        dissector_text = dissector_text + '\n  subtree:add_le(' + get_filter_names[n] + ', buffer' + get_buffer_locations[n] + ')'
    dissector_text = dissector_text + '\nend\n\n'
    dissector_text = dissector_text + 'local udp_port = DissectorTable.get("udp.port")\n'
    dissector_text = dissector_text + 'udp_port:add(' + get_udp_port + ', custom_protocol)'

    # Preview Dissector (Clicked)
    if preview == True:
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, dissector_text, width=1950)

    # Save the File
    else:
        # Select a Filepath
        directory = os.path.join(fissure.utils.FISSURE_ROOT, "Dissectors")  # Default Directory

        # This Method Allows ".lua" to be Added to the End of the Name
        dialog = QtWidgets.QFileDialog()
        dialog.setDirectory(directory)
        dialog.setFilter(dialog.filter() | QtCore.QDir.Hidden)
        dialog.setDefaultSuffix('lua')
        dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
        dialog.setNameFilters(['Lua Dissectors (*.lua)'])
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            fileName = str(dialog.selectedFiles()[0])
        else:
            fileName = ""

        # Valid file
        if fileName:
            # Write to File
            file = open(fileName,"wb")
            file.write(dissector_text)
            file.close()

            # Update Library
            get_protocol = str(dashboard.ui.comboBox_pd_dissectors_protocol.currentText())
            get_packet_type = str(dashboard.ui.comboBox_pd_dissectors_packet_type.currentText())
            if len(get_protocol) > 0 and len(get_packet_type) > 0:
                dissector_file = fileName.rsplit('/')[-1]
                dissector_port = int(get_udp_port)
                new_dissector = [dissector_file, dissector_port]
                await dashboard.backend.addToLibrary(get_protocol, get_packet_type, [], [], [], [], [], [], new_dissector)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_StatusBufferApplyClicked(dashboard: QtCore.QObject):
    """ 
    Updates Protocol Discovery with the new buffer size limits.
    """
    # Get the Min/Max Sizes
    min_buffer = str(dashboard.ui.textEdit_pd_status_min_buffer_size.toPlainText())
    max_buffer = str(dashboard.ui.textEdit_pd_status_buffer_size.toPlainText())

    # Send the Message
    await dashboard.backend.setBufferSize(min_buffer, max_buffer)

    # Insert Message into the Status Window
    get_text = time.strftime('%H:%M:%S', time.localtime()) + ": Applying Changes to Buffer Limits...\n"
    _slotPD_AddStatus(dashboard, get_text)

    # Adjust Protocol Discovery Progress Bars
    dashboard.ui.progressBar_pd_status_buffer.setMaximum(int(max_buffer))
    dashboard.ui.progressBar_bit_slicing_buffer.setMaximum(int(max_buffer))


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_StatusBufferClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Protocol Discovery buffer.
    """
    # Send the Message
    await dashboard.backend.clearPD_Buffer()

    # Insert Message into the Status Window
    get_text = time.strftime('%H:%M:%S', time.localtime()) + ": Clearing Buffer...\n"
    _slotPD_AddStatus(dashboard, get_text)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_StatusStartClicked(dashboard: QtCore.QObject):
    """ 
    Protocol "Start" button was clicked. Begins protocol discovery.
    """
    # Turn Protocol Discovery On
    if dashboard.ui.pushButton_pd_status_start.text() == "Start":
        dashboard.ui.pushButton_pd_status_start.setText("Stop")

        # Send Message to Turn on PD
        await dashboard.backend.startPD(dashboard.active_sensor_node)

        # Update the Labels
        if dashboard.active_sensor_node > -1:
            dashboard.statusbar_text[dashboard.active_sensor_node][2] = "Running"
            dashboard.refreshStatusBarText()
        dashboard.ui.label2_pd_status_pd.setText("Running")

        # Enable the Tabs
        dashboard.ui.tabWidget_protocol.setTabEnabled(1,True)
        dashboard.ui.tabWidget_protocol.setTabEnabled(2,True)
        #dashboard.ui.tabWidget_protocol.setTabEnabled(3,True)
        #dashboard.ui.tabWidget_protocol.setTabEnabled(4,True)
        #dashboard.ui.tabWidget_protocol.setTabEnabled(5,True)
        #dashboard.ui.tabWidget_protocol.setTabEnabled(6,True)
        #dashboard.ui.tabWidget_protocol.setTabEnabled(7,True)

        # Enable the Status Labels/Controls
        dashboard.ui.frame_pd_status_current_soi.setEnabled(True)
        dashboard.ui.frame_pd_status_bitstream_buffer.setEnabled(True)
        dashboard.ui.frame_pd_status_zmq_pub.setEnabled(True)
        dashboard.ui.pushButton_pd_status_soi_new.setEnabled(True)

        # Insert Message into the Status Window
        get_text = time.strftime('%H:%M:%S', time.localtime()) + ": Starting Protocol Discovery...\n"
        _slotPD_AddStatus(dashboard, get_text)

    # Turn Protocol Discovery Off
    else:
        dashboard.ui.pushButton_pd_status_start.setText("Start")

        # Send Message to Turn off PD
        await dashboard.backend.stopPD(dashboard.active_sensor_node)

        # Disable the Protocol Discovery Trigger
        await dashboard.backend.setAutoStartPD(False)

        # Update the Labels
        if dashboard.active_sensor_node > -1:
            dashboard.statusbar_text[dashboard.active_sensor_node][2] = "Not Running"
            dashboard.refreshStatusBarText()
        dashboard.ui.label2_pd_status_pd.setText("Not Running")

        # Disable the Tabs
        dashboard.ui.tabWidget_protocol.setTabEnabled(1,False)
        dashboard.ui.tabWidget_protocol.setTabEnabled(2,False)
        #dashboard.ui.tabWidget_protocol.setTabEnabled(3,False)
        #dashboard.ui.tabWidget_protocol.setTabEnabled(4,False)
        #dashboard.ui.tabWidget_protocol.setTabEnabled(5,False)
        #dashboard.ui.tabWidget_protocol.setTabEnabled(6,False)
        #dashboard.ui.tabWidget_protocol.setTabEnabled(7,False)

        # Disable the Status Labels/Controls
        dashboard.ui.frame_pd_status_current_soi.setEnabled(False)
        dashboard.ui.frame_pd_status_bitstream_buffer.setEnabled(False)
        dashboard.ui.frame_pd_status_zmq_pub.setEnabled(False)

        # Insert Message into the Status Window
        get_text = time.strftime('%H:%M:%S', time.localtime()) + ": Stopping Protocol Discovery...\n"
        _slotPD_AddStatus(dashboard, get_text)

        # TEST ONLY: Stopping Flow Graph at PD Stop (will be removed)
        if dashboard.ui.pushButton_pd_flow_graphs_start_stop.text() == "Stop":
            _slotPD_DemodulationStartStopClicked(dashboard)  # TEST ONLY: PD program will handle stopping flow graphs


@qasync.asyncSlot(QtCore.QObject)  # async?
async def _slotPD_StatusBlacklistSOI_Clicked(dashboard: QtCore.QObject):
    """ 
    This will stop protocol discovery of the current SOI. If the auto-select SOIs is checked it will procede to the next unique SOI.
    Otherwise the user can manually select a new SOI.
    """
    #~ # Stop Protocol Discovery
    #~ if dashboard.ui.pushButton_pd_status_start.text() == "Stop":
        #~ _slotPD_StatusStartClicked(dashboard)

    # Stop Any Running Flow Graphs
    if dashboard.ui.pushButton_pd_flow_graphs_start_stop.text() == "Stop":
        _slotPD_DemodulationStartStopClicked(dashboard)

    # Unload the Flow Graph
    unloadFlowGraph(dashboard)

    # Disable the Pushbuttons
    dashboard.ui.pushButton_pd_status_blacklist_soi.setEnabled(False)
    dashboard.ui.pushButton_pd_status_untarget.setEnabled(False)
    dashboard.ui.pushButton_pd_status_search_library.setEnabled(False)


def unloadFlowGraph(dashboard: QtCore.QObject):
    """ 
    This will undo the effects of "_slotPD_DemodulationLoadFlowGraphClicked" by erasing the tables, labels, and text boxes. Not a slot.
    """
    # Update the Edit Box
    dashboard.ui.textEdit_pd_flow_graphs_filepath.setPlainText("")

    # Update the Status Dialog
    if dashboard.active_sensor_node > -1:
        dashboard.statusbar_text[dashboard.active_sensor_node][2] = "Flow Graph Not Loaded"
        dashboard.refreshStatusBarText()

    # Update the Protocol Tab Labels
    dashboard.ui.label2_pd_status_loaded_flow_graph.setText('')
    dashboard.ui.label2_pd_status_flow_graph_status.setText('')

    # Update the Variable Listings in "Flow Graph" tab
    dashboard.ui.label3_pd_flow_graphs_default_variables.setText("")
    dashboard.ui.tableWidget_pd_flow_graphs_current_values.clearContents()
    dashboard.ui.tableWidget_pd_flow_graphs_current_values.setRowCount(0)

    # Adjust Table
    dashboard.ui.tableWidget_pd_flow_graphs_current_values.resizeRowsToContents()

    # Copy the Flow Graph Dictionary
    dashboard.ui.flow_graph_variables = []

    # Enable/Disable the Push Buttons
    dashboard.ui.pushButton_pd_flow_graphs_view.setEnabled(False)
    dashboard.ui.pushButton_pd_flow_graphs_start_stop.setEnabled(False)
    dashboard.ui.pushButton_pd_flow_graphs_apply_changes.setEnabled(False)
    dashboard.ui.pushButton_pd_flow_graphs_restore_defaults.setEnabled(False)

    # Update Flow Graph Status Label
    dashboard.ui.label2_pd_flow_graphs_status.setText("Not Loaded")


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_StatusAddPubClicked(dashboard: QtCore.QObject):
    """ 
    Connects the PD SUB socket to another PUB socket.
    """
    # Check IP and Port
    ip_address = str(dashboard.ui.textEdit_pd_status_ip_address.toPlainText())
    port = str(dashboard.ui.textEdit_pd_status_port.toPlainText())
    full_address = ip_address + ":" + port

    address_exists = False
    if dashboard.ui.listWidget_pd_status_current_pubs.count() > 0:
        for n in range(0,dashboard.ui.listWidget_pd_status_current_pubs.count()):
            if full_address == str(dashboard.ui.listWidget_pd_status_current_pubs.item(n).text()):
                address_exists = True

    if address_exists == False:
        # Send Message to HIPRFISR/Protocol Discovery
        await dashboard.backend.addPubSocket(ip_address, port)

        # Add it to the List Widget
        dashboard.ui.listWidget_pd_status_current_pubs.addItem(full_address)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_StatusRemovePubClicked(dashboard: QtCore.QObject):
    """ 
    Disconnects the selected PUB from the Protocol Discovery SUB.
    """
    if dashboard.ui.listWidget_pd_status_current_pubs.count() > 0:
        # Send Message to HIPRFISR/Protocol Discovery
        get_pub_address = str(dashboard.ui.listWidget_pd_status_current_pubs.currentItem().text())
        await dashboard.backend.removePubSocket(get_pub_address)

        # Remove the Item
        dashboard.ui.listWidget_pd_status_current_pubs.takeItem(dashboard.ui.listWidget_pd_status_current_pubs.currentRow())


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_DemodulationLookupClicked(dashboard: QtCore.QObject):
    """ 
    Sends a SOI to the HIPRFISR to look up in the signal library. Same effect as clicking the target radio button.
    """
    # Get SOI Data
    soi_data = ['','','','','','','','','','']
    if dashboard.ui.checkBox_pd_flow_graphs_frequency.isChecked():
        soi_data[0] = str(dashboard.ui.textEdit_pd_flow_graphs_frequency.toPlainText())
        soi_data[6] = str(dashboard.ui.textEdit_pd_flow_graphs_frequency_margin.toPlainText())
    if dashboard.ui.checkBox_pd_flow_graphs_modulation.isChecked():
        soi_data[1] = str(dashboard.ui.textEdit_pd_flow_graphs_modulation.toPlainText()).upper()
    if dashboard.ui.checkBox_pd_flow_graphs_bandwidth.isChecked():
        soi_data[2] = str(dashboard.ui.textEdit_pd_flow_graphs_bandwidth.toPlainText())
        soi_data[7] = str(dashboard.ui.textEdit_pd_flow_graphs_bandwidth_margin.toPlainText())
    if dashboard.ui.checkBox_pd_flow_graphs_continuous.isChecked():
        soi_data[3] = str(dashboard.ui.comboBox_pd_flow_graphs_continuous.currentText())
    if dashboard.ui.checkBox_pd_flow_graphs_start_frequency.isChecked():
        soi_data[4] = str(dashboard.ui.textEdit_pd_flow_graphs_start_frequency.toPlainText())
        soi_data[8] = str(dashboard.ui.textEdit_pd_flow_graphs_start_frequency_margin.toPlainText())
    if dashboard.ui.checkBox_pd_flow_graphs_end_frequency.isChecked():
        soi_data[5] = str(dashboard.ui.textEdit_pd_flow_graphs_end_frequency.toPlainText())
        soi_data[9] = str(dashboard.ui.textEdit_pd_flow_graphs_end_frequency_margin.toPlainText())

    # Get Hardware
    get_hardware = str(dashboard.ui.comboBox_pd_demod_hardware.currentText()).split(' - ')[0]

    # Clear Results Table
    dashboard.ui.tableWidget1_library_search_results.setRowCount(0)

    # Send Message
    await dashboard.backend.searchLibraryForFlowGraphs(soi_data, get_hardware)

    # Change the Label
    dashboard.ui.label2_pd_flow_graphs_lookup_not_found.setText("Searching...")


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_DemodulationStartStopClicked(dashboard: QtCore.QObject):
    """ 
    Signals to the HIPRFISR to stop/resume the currently running flow graph and toggles the push button text
    """
    # Send Stop Message to the HIPRFISR
    if dashboard.ui.pushButton_pd_flow_graphs_start_stop.text() == "Stop":
        await dashboard.backend.protocolDiscoveryFG_Stop(dashboard.active_sensor_node)

        # Toggle the Text
        dashboard.ui.pushButton_pd_flow_graphs_start_stop.setText("Start")

        # Enable/Disable the Pushbuttons
        dashboard.ui.pushButton_pd_flow_graphs_apply_changes.setEnabled(False)
        dashboard.ui.pushButton_pd_flow_graphs_restore_defaults.setEnabled(False)

        # Update Flow Graph Status Labels
        dashboard.ui.label2_pd_flow_graphs_status.setText("Stopped")
        dashboard.ui.label2_pd_status_flow_graph_status.setText("Stopped")

        # Update the Status Dialog
        if dashboard.active_sensor_node > -1:
            dashboard.statusbar_text[dashboard.active_sensor_node][2] = "Flow Graph Stopped"
            dashboard.refreshStatusBarText()

    # Reset to Last Known Flow Graph Configuration
    elif dashboard.ui.pushButton_pd_flow_graphs_start_stop.text() == "Start":
        # Toggle the Text
        dashboard.ui.pushButton_pd_flow_graphs_start_stop.setText("Stop")

        # Enable/Disable the Pushbuttons
        dashboard.ui.pushButton_pd_flow_graphs_restore_defaults.setEnabled(True)

        # Send Message(s) to the HIPRFISR for each Variable Name and Value
        variable_names = []
        variable_values = []
        for get_row in range(dashboard.ui.tableWidget_pd_flow_graphs_current_values.rowCount()):
            # Save the Variable Name and Value in the Row to a Dictionary
            variable_names.append(str(dashboard.ui.tableWidget_pd_flow_graphs_current_values.verticalHeaderItem(get_row).text()))
            variable_values.append(str(dashboard.ui.tableWidget_pd_flow_graphs_current_values.item(get_row,0).text()))

        # Update Flow Graph Status Labels
        dashboard.ui.label2_pd_flow_graphs_status.setText("Starting...")
        dashboard.ui.pushButton_pd_flow_graphs_start_stop.setEnabled(False)  # Causes errors when stopped while loading
        dashboard.ui.label2_pd_status_flow_graph_status.setText("Starting...")

        # Send "Run PD Flow Graph" Message to the HIPRFISR
        fname = dashboard.ui.textEdit_pd_flow_graphs_filepath.toPlainText()
        await dashboard.backend.protocolDiscoveryFG_Start(dashboard.active_sensor_node, str(fname.split('/')[-1]), variable_names, variable_values)

        # Update the Status Dialog
        if dashboard.active_sensor_node > -1:
            dashboard.statusbar_text[dashboard.active_sensor_node][2] = 'Starting... ' + fname.split('/')[-1]
            dashboard.refreshStatusBarText()


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_DemodulationApplyChangesClicked(dashboard: QtCore.QObject):
    """ 
    Applies any changes made in the "Flow Graph Current Values" table by calling the 'set' functions in the flow graph modules.
    """
    # Send Message(s) to the HIPRFISR for each Variable Name and Value
    for get_row in range(dashboard.ui.tableWidget_pd_flow_graphs_current_values.rowCount()):

        # Determine the Variable Name and Value in the Row
        variable_name = dashboard.ui.tableWidget_pd_flow_graphs_current_values.verticalHeaderItem(get_row).text()
        value = dashboard.ui.tableWidget_pd_flow_graphs_current_values.item(get_row,0).text()

        # Check and Send the "Set" Message if Value Changed
        if dashboard.flow_graph_variables[str(variable_name)] != str(value):
            dashboard.flow_graph_variables[str(variable_name)] = str(value)
            await dashboard.backend.setVariable(dashboard.active_sensor_node, 'Protocol Discovery', str(variable_name), str(value))

    # Disable the Pushbutton
    dashboard.ui.pushButton_pd_flow_graphs_apply_changes.setEnabled(False)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_BitSlicingFindPreamblesClicked(dashboard: QtCore.QObject):
    """ 
    Sends a message to the HIPRFISR/PD to begin searching for candidate preambles from within the buffer.
    """
    # Get the Window Parameters
    win_min = str(dashboard.ui.spinBox_pd_bit_slicing_min_window.value())
    win_max = str(dashboard.ui.spinBox_pd_bit_slicing_max_window.value())
    topx = str(dashboard.ui.spinBox_pd_bit_slicing_ranking.value())
    num_std_dev = str(dashboard.ui.spinBox_pd_bit_slicing_std_deviations.value())

    # Adjust the SpinBox and Slider
    dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size.setMinimum(int(win_min))
    dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size.setMaximum(int(win_max))
    dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size.setValue(int(win_min))
    dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats.setMinimum(int(win_min))
    dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats.setMaximum(int(win_max))
    dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats.setValue(int(win_min))
    dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size_candidates.setMinimum(int(win_min))
    dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size_candidates.setMaximum(int(win_max))
    dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size_candidates.setValue(int(win_min))
    dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats_candidates.setMinimum(int(win_min))
    dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats_candidates.setMaximum(int(win_max))
    dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats_candidates.setValue(int(win_min))

    # Clear the Table
    dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.clearContents()

    # Send Message
    await dashboard.backend.findPreambles(win_min, win_max, topx, num_std_dev)

    # Show the Calculating Label
    dashboard.ui.label2_pd_bit_slicing_calculating.setVisible(True)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_BitSlicingSliceByPreambleClicked(dashboard: QtCore.QObject):
    """ 
    Signals to PD to slices the buffer by a select preamble and return the lengths, length count, and first N packets.
    """
    # Get the Preamble
    get_preamble = str(dashboard.ui.textEdit_pd_bit_slicing_recommended_preamble.toPlainText())

    # Get the First N Value
    get_first_n = str(dashboard.ui.spinBox_pd_bit_slicing_return_limit.value())

    # Estimated Length
    get_estimated_length = str(dashboard.ui.spinBox_pd_bit_slicing_estimated_length.value())

    # Send the Message
    await dashboard.backend.sliceByPreamble(get_preamble, get_first_n, get_estimated_length)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingInsertFieldClicked(dashboard: QtCore.QObject):
    """ 
    Inserts a new field/row to the field delineation table.
    """
    # Insert after the Current Row
    dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.insertRow(dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.currentRow()+1)

    # Reset the Current Selection
    dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.setCurrentCell(dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.currentRow()+1,0)

    # Center the Text
    table_item = QtWidgets.QTableWidgetItem("")
    table_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.setItem(dashboard.ui.tableWidget_pd_bit_slicing_field_delineations.currentRow(),0,table_item)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingAddToLibraryClicked(dashboard: QtCore.QObject):
    """ 
    Populates the Add to Library Tab with the contents from the the bit slicing tab.
    """
    # Clear the "Add to Library" Table
    for row in reversed(range(0,dashboard.ui.tableWidget_library_pd_packet.rowCount())):
        dashboard.ui.tableWidget_library_pd_packet.removeRow(row)

    # Insert Each Field
    for col in range(0,dashboard.ui.tableWidget_pd_bit_slicing_packets.columnCount()):
        # Insert Row
        dashboard.ui.tableWidget_library_pd_packet.setRowCount(dashboard.ui.tableWidget_library_pd_packet.rowCount() + 1)

        # Row Header
        header_item = QtWidgets.QTableWidgetItem("Field " + str(dashboard.ui.tableWidget_library_pd_packet.rowCount()))
        header_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_library_pd_packet.setVerticalHeaderItem(dashboard.ui.tableWidget_library_pd_packet.rowCount()-1,header_item)

        # Field Name
        table_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_pd_bit_slicing_packets.horizontalHeaderItem(col).text()))
        table_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_library_pd_packet.setItem(col,0,table_item)

        # Length
        if dashboard.bit_slicing_column_type[col] == "Binary":
            length_item = QtWidgets.QTableWidgetItem(str(len(dashboard.ui.tableWidget_pd_bit_slicing_packets.item(dashboard.ui.tableWidget_pd_bit_slicing_packets.currentRow(),col).text())))
        else:
            length_item = QtWidgets.QTableWidgetItem(str(4*len(dashboard.ui.tableWidget_pd_bit_slicing_packets.item(dashboard.ui.tableWidget_pd_bit_slicing_packets.currentRow(),col).text())))
        length_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_library_pd_packet.setItem(col,1,length_item)

        # Default Value
        # Get the Data as Binary
        get_data = str(dashboard.ui.tableWidget_pd_bit_slicing_packets.item(dashboard.ui.tableWidget_pd_bit_slicing_packets.currentRow(),col).text())
        if dashboard.bit_slicing_column_type[col] == "Binary":
            default_item_text = get_data
        else:
            bin_str = bin(int(get_data, 16))[2:].zfill(int(len(get_data)*4))
            default_item_text = bin_str
        default_item = QtWidgets.QTableWidgetItem(default_item_text)
        default_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_library_pd_packet.setItem(col,2,default_item)

        # CRC Range
        crc_range_item = QtWidgets.QTableWidgetItem("")
        crc_range_item.setTextAlignment(QtCore.Qt.AlignCenter)
        crc_range_item.setFlags(crc_range_item.flags() ^ QtCore.Qt.ItemIsEnabled)
        crc_range_item.setFlags(crc_range_item.flags() ^ QtCore.Qt.ItemIsEditable)
        dashboard.ui.tableWidget_library_pd_packet.setItem(col,4,crc_range_item)

        # Is CRC
        new_combobox = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        new_combobox.addItem("True")
        new_combobox.addItem("False")
        new_combobox.setCurrentIndex(1)
        dashboard.ui.tableWidget_library_pd_packet.setCellWidget(col,3,new_combobox)
        new_combobox.currentIndexChanged.connect(lambda: _slotPD_AddToLibraryIsCRC_Changed(dashboard))
        new_combobox.setProperty("row", col)

        # Resize the Table
        dashboard.ui.tableWidget_library_pd_packet.resizeRowsToContents()
        dashboard.ui.tableWidget_library_pd_packet.setColumnWidth(0,125)
        dashboard.ui.tableWidget_library_pd_packet.setColumnWidth(1,75)
        dashboard.ui.tableWidget_library_pd_packet.setColumnWidth(3,75)
        dashboard.ui.tableWidget_library_pd_packet.setColumnWidth(4,130)
        dashboard.ui.tableWidget_library_pd_packet.horizontalHeader().setSectionResizeMode(2,QtWidgets.QHeaderView.Stretch)

        # Change the Tab
        dashboard.ui.tabWidget_library.setCurrentIndex(4)
        dashboard.ui.tabWidget.setCurrentIndex(7)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_AddToLibraryIsCRC_Changed(dashboard: QtCore.QObject):
    """ 
    Enable/Disable the "CRC Range" item in the protocol discovery add to library packet type table based on "Is CRC" value.
    """
    # Get Row, Value
    row = dashboard.sender().property("row")  # FIX
    current_selection = dashboard.ui.tableWidget_library_pd_packet.cellWidget(row,3).currentText()

    # Enable
    if current_selection == "True":
        dashboard.ui.tableWidget_library_pd_packet.item(row,4).setFlags(dashboard.ui.tableWidget_library_pd_packet.item(row,4).flags() ^ QtCore.Qt.ItemIsEnabled)
        dashboard.ui.tableWidget_library_pd_packet.item(row,4).setFlags(dashboard.ui.tableWidget_library_pd_packet.item(row,4).flags() ^ QtCore.Qt.ItemIsEditable)

    # Disable
    else:
        dashboard.ui.tableWidget_library_pd_packet.item(row,4).setText("")  # Clear existing text
        dashboard.ui.tableWidget_library_pd_packet.item(row,4).setFlags(dashboard.ui.tableWidget_library_pd_packet.item(row,4).flags() ^ QtCore.Qt.ItemIsEnabled)
        dashboard.ui.tableWidget_library_pd_packet.item(row,4).setFlags(dashboard.ui.tableWidget_library_pd_packet.item(row,4).flags() ^ QtCore.Qt.ItemIsEditable)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_BitSlicingSearchLibraryClicked(dashboard: QtCore.QObject):
    """ 
    Takes the currently select field in the bit slicing table and puts it in the field data search box in the search tab.
    """
    # Get the Selected Items
    get_items = dashboard.ui.tableWidget_pd_bit_slicing_packets.selectedItems()

    # Get Selected Item Ranges
    selection_range = dashboard.ui.tableWidget_pd_bit_slicing_packets.selectedRanges()[0]

    # Get the First Column
    first_column = selection_range.leftColumn()

    if len(get_items) > 0:
        # Append Each Item
        new_text = ""
        for n in range(0,len(get_items)):
            # Get the Data as Binary
            get_data = str(get_items[n].text())
            if dashboard.bit_slicing_column_type[first_column + n] == "Binary":
                new_text += get_data
            else:
                bin_str = bin(int(get_data, 16))[2:].zfill(int(len(get_data)*4))
                new_text += bin_str

        # Change the EditBox and Radio Button
        dashboard.ui.textEdit_library_search_field_value.setPlainText("")
        dashboard.ui.radioButton_library_search_binary.setChecked(True)
        dashboard.ui.textEdit_library_search_field_value.setPlainText(new_text)

        # Change the Tab
        dashboard.ui.tabWidget_library.setCurrentIndex(2)
        dashboard.ui.tabWidget.setCurrentIndex(7)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_DissectorRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes the dissector lua file and entry from the library for the packet type.
    """
    # Get Values
    get_protocol = str(dashboard.ui.comboBox_pd_dissectors_protocol.currentText())
    get_packet_type = str(dashboard.ui.comboBox_pd_dissectors_packet_type.currentText())
    get_dissector = str(dashboard.ui.comboBox_pd_dissectors_existing_dissectors.currentText())

    # Remove
    if len(get_protocol) > 0 and len(get_packet_type) > 0 and len(get_dissector) > 0:
        if get_dissector != "None":
            dissector_source = os.path.join(fissure.utils.FISSURE_ROOT, "Dissectors", get_dissector)
            os.system('rm ' + dissector_source)
        new_dissector = [None, None]
        await dashboard.backend.addToLibrary(get_protocol, get_packet_type, [], [], [], [], [], [], new_dissector)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_DissectorApplyClicked(dashboard: QtCore.QObject):
    """ 
    Assigns the selected dissector to the selected packet type.
    """
    # Update Library
    get_protocol = str(dashboard.ui.comboBox_pd_dissectors_protocol.currentText())
    get_packet_type = str(dashboard.ui.comboBox_pd_dissectors_packet_type.currentText())
    get_dissector_file = str(dashboard.ui.comboBox_pd_dissectors_existing_dissectors.currentText())
    if len(get_protocol) > 0 and len(get_packet_type) > 0:
        # Find Port for Existing Dissector
        get_packet_types = fissure.utils.library.getPacketTypes(dashboard.backend.library, get_protocol)
        for n in get_packet_types:
            dissector = fissure.utils.library.getDissector(dashboard.backend.library, get_protocol, n)
            if get_dissector_file == dissector['Filename']:
                get_dissector_port = dissector['Port']
                break

        new_dissector = [get_dissector_file, get_dissector_port]
        await dashboard.backend.addToLibrary(get_protocol, get_packet_type, [], [], [], [], [], [], new_dissector)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_SnifferStreamClicked(dashboard: QtCore.QObject):
    """ 
    Launches the Sniffer_stream flow graph which sniffs a ZMQ PUB port, passes the data to a UDP port, and opens Wireshark.
    """
    # Start Sniffer
    if dashboard.ui.pushButton_pd_sniffer_stream.text() == "Sniffer - Stream":
        try:
            flow_graph_filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Sniffer Flow Graphs", "Sniffer_stream.py")

            variable_names = ['address','port']
            get_pd_bits_port = str(dashboard.ui.label2_pd_sniffer_zmq_port.text())

            get_address = '127.0.0.1:' + get_pd_bits_port
            get_port = str(dashboard.ui.textEdit_pd_sniffer_sub_udp_port.toPlainText())
            variable_values = [get_address, get_port]

            # Check the Values
            if not (get_port.isdigit() and 1 <= int(get_port) <= 65535):
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a valid port (1-65535).")
                return

            # Send the Message
            await dashboard.backend.snifferFlowGraphStart(dashboard.active_sensor_node, flow_graph_filepath, variable_names, variable_values)

            # Disable the Buttons
            dashboard.ui.pushButton_pd_sniffer_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_tagged_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_msg_pdu.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_stream.setText("Stop")

        except:
            pass

    # Stop Sniffer
    else:
        try:
            # Send the Message
            await dashboard.backend.snifferFlowGraphStop(dashboard.active_sensor_node, 'Stream')

            # Disable the Buttons
            dashboard.ui.pushButton_pd_sniffer_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_tagged_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_msg_pdu.setEnabled(False)

        except:
            pass


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_SnifferTaggedStreamClicked(dashboard: QtCore.QObject):
    """ 
    Launches the Sniffer_tagged_stream flow graph which sniffs a ZMQ PUB port, passes the data to a UDP port, and opens Wireshark.
    """
    # Start Sniffer
    get_port = str(dashboard.ui.textEdit_pd_sniffer_sub_udp_port.toPlainText())
    if dashboard.ui.pushButton_pd_sniffer_tagged_stream.text() == "Sniffer - Tagged Str.":
        try:
            flow_graph_filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Sniffer Flow Graphs", "Sniffer_tagged_stream.py")

            variable_names = ['address','port']
            get_pd_bits_port = str(dashboard.ui.label2_pd_sniffer_zmq_port.text())
            get_address = '127.0.0.1:' + get_pd_bits_port
            get_port = str(dashboard.ui.textEdit_pd_sniffer_sub_udp_port.toPlainText())
            variable_values = [get_address, get_port]

            # Check the Values
            if not (get_port.isdigit() and 1 <= int(get_port) <= 65535):
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a valid port (1-65535).")
                return

            # Send the Message
            await dashboard.backend.snifferFlowGraphStart(dashboard.active_sensor_node, flow_graph_filepath, variable_names, variable_values)

            # Disable the Buttons
            dashboard.ui.pushButton_pd_sniffer_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_tagged_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_msg_pdu.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_tagged_stream.setText("Stop")

        except:
            pass

    # Stop Sniffer
    else:
        try:
            # Send the Message
            await dashboard.backend.snifferFlowGraphStop(dashboard.active_sensor_node, 'TaggedStream')

            # Disable the Buttons
            dashboard.ui.pushButton_pd_sniffer_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_tagged_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_msg_pdu.setEnabled(False)

        except:
            pass


@qasync.asyncSlot(QtCore.QObject)
async def _slotPD_SnifferMsgPduClicked(dashboard: QtCore.QObject):
    """ 
    Launches the Sniffer_msg_pdu flow graph which sniffs a ZMQ PUB port, passes the data to a UDP port, and opens Wireshark.
    """
    # Start Sniffer
    if dashboard.ui.pushButton_pd_sniffer_msg_pdu.text() == "Sniffer - Msg/PDU":
        try:
            flow_graph_filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Sniffer Flow Graphs", "Sniffer_async.py")

            variable_names = ['address','port']
            get_pd_bits_port = str(dashboard.ui.label2_pd_sniffer_zmq_port.text())
            get_address = '127.0.0.1:' + get_pd_bits_port
            get_port = str(dashboard.ui.textEdit_pd_sniffer_sub_udp_port.toPlainText())
            variable_values = [get_address, get_port]

            # Check the Values
            if not (get_port.isdigit() and 1 <= int(get_port) <= 65535):
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a valid port (1-65535).")
                return

            # Send the Message
            await dashboard.backend.snifferFlowGraphStart(dashboard.active_sensor_node, flow_graph_filepath, variable_names, variable_values)

            # Disable the Buttons
            dashboard.ui.pushButton_pd_sniffer_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_tagged_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_msg_pdu.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_msg_pdu.setText("Stop")

        except:
            pass

    # Stop Sniffer
    else:
        try:
            # Send the Message
            await dashboard.backend.snifferFlowGraphStop(dashboard.active_sensor_node, 'Message/PDU')

            # Disable the Buttons
            dashboard.ui.pushButton_pd_sniffer_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_tagged_stream.setEnabled(False)
            dashboard.ui.pushButton_pd_sniffer_msg_pdu.setEnabled(False)
        except:
            pass