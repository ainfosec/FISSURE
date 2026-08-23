from PyQt5 import QtCore, QtWidgets, QtGui
import os
import fissure.utils
import qasync
import yaml
import binascii
import sys
import crcmod
from scipy import signal as signal2
from io import StringIO
from scapy.all import Dot11, RadioTap, sendp, ls, wrpcap, Dot11Deauth, Dot11ProbeReq, IP, UDP, LLC, SNAP, ARP, Ether, ICMP
from fissure.Dashboard.UI_Components.Qt5 import MyMessageBox
import subprocess
import ast
import time


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketProtocols(dashboard: QtCore.QObject):
    """ 
    Changes the Packet editor fields and subcategory combobox whenever the protocol combobox is changed
    """
    # Get the Protocol
    current_protocol_key = str(dashboard.ui.comboBox_packet_protocols.currentText())
    if current_protocol_key:  #will be false if no current protocol selected
        try:
            #return sorted list based on sort order subkey
            packet_types = fissure.utils.library.getPacketTypes(dashboard.backend.library, current_protocol_key)
            dashboard.ui.comboBox_packet_subcategory.clear()
            dashboard.ui.comboBox_packet_subcategory.addItems(packet_types)
            dashboard.ui.comboBox_packet_subcategory.setEnabled(True)
            dashboard.ui.tableWidget1_attack_packet_editor.clearContents()

            _slotPacketRestoreDefaultsClicked(dashboard)

        except KeyError:
            #No packet types!
            packet_types = []
            dashboard.ui.comboBox_packet_subcategory.clear()

    # Change the Stacked Widget for Scapy Controls
    if "802.11x" in current_protocol_key:
        dashboard.ui.pushButton_packet_calculate_crcs.setVisible(False)
        dashboard.ui.pushButton_packet_assemble.setVisible(False)
        dashboard.ui.stackedWidget_packet.setCurrentIndex(1)
    else:
        dashboard.ui.pushButton_packet_calculate_crcs.setVisible(True)
        dashboard.ui.pushButton_packet_assemble.setVisible(True)
        dashboard.ui.stackedWidget_packet.setCurrentIndex(0)



@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketSubcategory(dashboard: QtCore.QObject):
    """ 
    Changes the Packet Editor fields whenever the subcategory combobox is changed
    """
    # Get the Subcategory
    current_protocol_key = str(dashboard.ui.comboBox_packet_protocols.currentText())
    current_subcategory = str(dashboard.ui.comboBox_packet_subcategory.currentText())

    try:
        # Fields
        dashboard.ui.tableWidget1_attack_packet_editor.clearContents()
        field_names = fissure.utils.library.getFields(dashboard.backend.library, current_protocol_key, current_subcategory)
        dashboard.ui.tableWidget1_attack_packet_editor.setRowCount(len(field_names))
        dashboard.ui.tableWidget1_attack_packet_editor.setVerticalHeaderLabels(field_names)

        # Lengths
        for n in range(0,len(field_names)):
            get_length = fissure.utils.library.getFieldData(dashboard.backend.library, current_protocol_key, current_subcategory, field_names[n])["Length"]
            length_item = QtWidgets.QTableWidgetItem(str(get_length))
            length_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget1_attack_packet_editor.setItem(n,3,length_item)

    except KeyError:
        #No Fields Defined!
        #~ print("No Fields Defined!")
        fields = []
        dashboard.ui.tableWidget1_attack_packet_editor.setRowCount(1)
        dashboard.ui.tableWidget1_attack_packet_editor.setVerticalHeaderLabels(['Custom'])
        get_length = 0
        length_item = QtWidgets.QTableWidgetItem("")
        length_item.setTextAlignment(QtCore.Qt.AlignCenter)
        default_length_item = QtWidgets.QTableWidgetItem(str(get_length))
        default_length_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget1_attack_packet_editor.setItem(0,2,length_item)
        dashboard.ui.tableWidget1_attack_packet_editor.setItem(0,3,default_length_item)

    # Binary/Hex ComboBoxes
    for n in range(0,dashboard.ui.tableWidget1_attack_packet_editor.rowCount()):
        new_combobox1 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        new_combobox1.addItem("Binary")
        new_combobox1.addItem("Hex")
        new_combobox1.setFixedSize(75,24)
        new_combobox1.setCurrentIndex(1)
        new_combobox1.currentIndexChanged.connect(lambda: _slotPacketBinaryHex(dashboard, dashboard.ui.tableWidget1_attack_packet_editor))
        new_combobox1.setProperty("row", n)
        dashboard.ui.tableWidget1_attack_packet_editor.setCellWidget(n,0,new_combobox1)

    # Calculate the Lengths
    default_length = 0
    for n in range(0,dashboard.ui.tableWidget1_attack_packet_editor.rowCount()):
        default_length += int(dashboard.ui.tableWidget1_attack_packet_editor.item(n,3).text())

    # Set the Length Labels
    dashboard.ui.label2_packet_current_length_total.setText(str(""))
    dashboard.ui.label2_packet_default_length_total.setText(str(default_length))

    # Resize the Table
    dashboard.ui.tableWidget1_attack_packet_editor.setColumnWidth(0,75)
    dashboard.ui.tableWidget1_attack_packet_editor.setColumnWidth(2,75)
    dashboard.ui.tableWidget1_attack_packet_editor.setColumnWidth(3,75)
    dashboard.ui.tableWidget1_attack_packet_editor.horizontalHeader().setSectionResizeMode(1,QtWidgets.QHeaderView.Stretch)

    # Restore Defaults
    if dashboard.ui.comboBox_packet_subcategory.count() > 0:
        _slotPacketRestoreDefaultsClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketRestoreDefaultsClicked(dashboard: QtCore.QObject):
    """ 
    Restores the values in the Packet Editor to the default values for the selected protocol.
    """
    # Get the Protocol
    current_protocol = dashboard.ui.comboBox_packet_protocols.currentText()
    current_protocol_key = str(current_protocol)

    # Get the Subcategory
    current_subcategory = dashboard.ui.comboBox_packet_subcategory.currentText()
    current_subcategory_key = str(current_subcategory)

    # Clear the Table
    dashboard.ui.tableWidget1_attack_packet_editor.clearContents()

    # Load the Default Fields and Data
    field_names = fissure.utils.library.getFields(dashboard.backend.library,current_protocol_key,current_subcategory_key)

    for n in range(0,len(field_names)):
        # Length Items
        get_length = fissure.utils.library.getFieldData(dashboard.backend.library, current_protocol_key, current_subcategory, field_names[n])["Length"]
        length_item = QtWidgets.QTableWidgetItem(str(get_length))
        length_item.setTextAlignment(QtCore.Qt.AlignCenter)
        length_item.setFlags(length_item.flags() & ~QtCore.Qt.ItemIsEditable)
        default_length_item = QtWidgets.QTableWidgetItem(str(get_length))
        default_length_item.setTextAlignment(QtCore.Qt.AlignCenter)
        default_length_item.setFlags(default_length_item.flags() & ~QtCore.Qt.ItemIsEditable)
        dashboard.ui.tableWidget1_attack_packet_editor.setItem(n,2,length_item)
        dashboard.ui.tableWidget1_attack_packet_editor.setItem(n,3,default_length_item)

        # Create Table Comboboxes
        new_combobox1 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        dashboard.ui.tableWidget1_attack_packet_editor.setCellWidget(n,0,new_combobox1)

        # String
        if get_length == 0:
            new_combobox1.addItem("String")
            new_combobox1.setEnabled(False)
        else:
            new_combobox1.addItem("Binary")
            new_combobox1.addItem("Hex")

            # Binary
            if get_length % 4 != 0:
                new_combobox1.setEnabled(False)
            # Hex
            else:
                new_combobox1.setCurrentIndex(1)

        # Format
        default_field_data = fissure.utils.library.getFieldData(dashboard.backend.library, current_protocol_key, current_subcategory, field_names[n])["Default Value"]
        new_combobox1.setFixedSize(75,24)
        new_combobox1.setCurrentIndex(0)
        new_combobox1.currentIndexChanged.connect(lambda: _slotPacketBinaryHex(dashboard, dashboard.ui.tableWidget1_attack_packet_editor))
        new_combobox1.setProperty("row", n)
        dashboard.ui.tableWidget1_attack_packet_editor.setItem(n,1,QtWidgets.QTableWidgetItem(str(default_field_data)))

    # Calculate the Lengths
    current_length = 0
    default_length = 0
    for n in range(0,dashboard.ui.tableWidget1_attack_packet_editor.rowCount()):
        current_length += int(dashboard.ui.tableWidget1_attack_packet_editor.item(n,2).text())
        default_length += int(dashboard.ui.tableWidget1_attack_packet_editor.item(n,3).text())

    # Set the Length Labels
    dashboard.ui.label2_packet_current_length_total.setText(str(current_length))
    dashboard.ui.label2_packet_default_length_total.setText(str(default_length))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketBinaryHex(dashboard: QtCore.QObject, table_widget):
    """ 
    This will convert the data in the Packet Editor to binary and hexadecimal via the combobox.
    """
    row = dashboard.sender().property("row")  # FIX
    if table_widget.horizontalHeaderItem(0).text() == "Select":
        column = 4
    else:
        column = 0

    # Binary or Hex
    current_selection = table_widget.cellWidget(row,column).currentText()

    # Contains Data
    if table_widget.item(row,column+1) != None:
        if str(table_widget.item(row,column+1).text()) != "":

            # Get the Data
            get_data = str(table_widget.item(row,column+1).text())

            try:
                # Hex to Binary
                if current_selection == "Binary":
                    hex_len = len(get_data)
                    bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))
                    bin_str_spaces = ' '.join([bin_str[i:i+4] for i in range(0, len(bin_str), 4)])
                    table_widget.item(row,column+1).setText(bin_str_spaces)

                # Binary to Hex
                elif current_selection == "Hex":
                    get_data = get_data.replace(' ', '')
                    hex_str = '%0*X' % ((len(get_data) + 3) // 4, int(get_data, 2))
                    table_widget.item(row,column+1).setText(hex_str)

                # String/Length 0
                elif current_selection == "String":
                    pass
                    #table_widget.item(row,column+1).setText(get_data)

            # Message Data Entered Incorrectly
            except ValueError as inst:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Message data was entered incorrectly.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketAssembleClicked(dashboard: QtCore.QObject):
    """ 
    This will piece together the fields in the Packet Editor to produce a correctly ordered message in the text edit box.
    """
    try:
        # Convert Every Field to Binary, Assemble
        get_bin = ""
        for n in range(0,dashboard.ui.tableWidget1_attack_packet_editor.rowCount()):
            # Binary or Hex
            current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(n,0).currentText()

            # Contains Item
            if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1) != None:
                # Not Empty
                if str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text()) != "":
                    # Get the Data
                    get_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text())

                    if current_selection == "Binary":
                        bin_str = get_data.replace(' ', '')

                    # Hex to Binary
                    elif current_selection == "Hex":
                        hex_len = len(get_data)
                        bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                    get_bin = get_bin + bin_str

        # Convert to Hex, Print
        hex_str = '%0*X' % ((len(get_bin) + 3) // 4, int(get_bin, 2))
        dashboard.ui.textEdit1_packet_assembled.setPlainText(hex_str)

    # Message Data Entered Incorrectly
    except ValueError as inst:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Message data was entered incorrectly.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketSaveAs(dashboard: QtCore.QObject):
    """ 
    Saves the Assembled Packet to a .bin file (and text file?)
    """
    # Select a Filepath
    directory = os.path.join(fissure.utils.FISSURE_ROOT, "Crafted Packets")  # Default Directory

    # Open the Save Dialog
    dialog = QtWidgets.QFileDialog()
    dialog.setDirectory(directory)
    dialog.setFilter(dialog.filter() | QtCore.QDir.Hidden)
    dialog.setDefaultSuffix('bin')
    dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
    dialog.setNameFilters(['Binary Data Files (*.bin)'])
    if dialog.exec_() == QtWidgets.QDialog.Accepted:
        fileName = str(dialog.selectedFiles()[0])
    else:
        fileName = ""

    # Valid File
    if fileName:
        # Get the File
        file = open(fileName,"wb")

        # Get the Data
        get_data = str(dashboard.ui.textEdit1_packet_constructed.toPlainText())

        # Check if the Length is Even
        if len(get_data)%2 == 1:
            get_data = get_data + "0"  # Append something to the end to complete the byte

        # Format it
        hb=binascii.a2b_hex(get_data)

        # Write to File
        file.write(hb)
        file.close()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketCalculateCRCsClicked(dashboard: QtCore.QObject):  # Somehow use the library for this? CRC Polynomial? How to get it to work for SimpliciTI?
    """ 
    This will calculate the CRCs for the selected protocol and update the Packet Editor.
    """
    # Get the Protocol
    current_protocol = dashboard.ui.comboBox_packet_protocols.currentText()

    # Get the Subcategory
    current_subcategory = dashboard.ui.comboBox_packet_subcategory.currentText()

    #try:
    if True:
        # FM
        if current_protocol == "FM":
            pass

        # DECT
        elif current_protocol == "DECT":
            # A-Field
            get_bin = ""
            for n in range(2,7):
                # Binary or Hex
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(n,0).currentText()

                # Contains Data
                if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1) != None:  # No Item Exists
                    if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text() != "":  # No Text for the Item Exists

                        # Get the Data
                        get_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text())

                        if current_selection == "Binary":
                            bin_str = get_data.replace(' ', '')

                        # Hex to Binary
                        elif current_selection == "Hex":
                            hex_len = len(get_data)
                            bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                        get_bin = get_bin + bin_str

                    # Nothing Found in a Field
                    else:
                        get_bin = "MISSING DECT FIELD"
                        dashboard.ui.tableWidget1_attack_packet_editor.item(7,1).setText(get_bin)
                        break
                else:
                    get_bin = "MISSING DECT FIELD"
                    new_item = QtWidgets.QTableWidgetItem("MISSING DECT FIELD")
                    dashboard.ui.tableWidget1_attack_packet_editor.setItem(7,1,new_item)
                    break

            if get_bin != "MISSING DECT FIELD":

                # A-Field CRC Algorithm
                poly = [1,0,0,0,0,0,1,0,1,1,0,0,0,1,0,0,1]  # From DECT Standard
                padding = "0"*(len(poly)-1)
                mseg = list(get_bin + padding)
                mseg = [int(i) for i in mseg]

                q, r = signal2.deconvolve(mseg, poly)
                r = abs(r)

                for i in range(0,len(r)):
                    a = r[i]
                    if (a % 2) == 0:
                        r[i] = 0
                    else:
                        r[i] = 1

                crc = r[len(get_bin):len(r)]
                crc[-1] = (crc[-1]+1) % 2  # Invert the last bit  (EN 300 175-3 at 6.2.5.2)

                # Format it for the Table ("#### #### #### ####")
                bin_str = str(crc.tolist()).strip('[]')
                bin_str = ''.join([bin_str[i] for i in range(0, len(bin_str), 5)])  # removes decimals
                bin_str_spaces = ' '.join([bin_str[i:i+4] for i in range(0, len(bin_str), 4)])  # groups bits into 4

                # Is Hex or Binary Selected for the CRC?
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(7,0).currentText()
                if current_selection == "Binary":
                    dashboard.ui.tableWidget1_attack_packet_editor.item(7,1).setText(bin_str_spaces)

                # Binary to Hex
                elif current_selection == "Hex":
                    bin_str = bin_str_spaces.replace(' ', '')
                    hex_str = '%0*X' % ((len(bin_str) + 3) // 4, int(bin_str, 2))
                    dashboard.ui.tableWidget1_attack_packet_editor.item(7,1).setText(hex_str)

                # B-Field CRC
                if current_subcategory == "Basic Packet":
                    # Get B-Field Data
                    # Binary or Hex
                    get_bin = ""
                    current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(8,0).currentText()

                    # Contains Data
                    if dashboard.ui.tableWidget1_attack_packet_editor.item(8,1) != None:  # No Item Exists
                        if dashboard.ui.tableWidget1_attack_packet_editor.item(8,1).text() != "":  # No Text for the Item Exists

                            # Get the Data
                            get_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(8,1).text())

                            if current_selection == "Binary":
                                bin_str = get_data.replace(' ', '')

                            # Hex to Binary
                            elif current_selection == "Hex":
                                hex_len = len(get_data)
                                bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                            get_bin = get_bin + bin_str

                        # Nothing Found in a Field
                        else:
                            get_bin = "MISSING DECT B-FIELD"
                            dashboard.ui.tableWidget1_attack_packet_editor.item(9,1).setText(get_bin)
                    else:
                        get_bin = "MISSING DECT B-FIELD"
                        new_item = QtWidgets.QTableWidgetItem("MISSING DECT B-FIELD")
                        dashboard.ui.tableWidget1_attack_packet_editor.setItem(9,1,new_item)

                    # Do the Algorithm
                    b_dec = []
                    for x in range(0,len(get_bin),8):
                            b_dec.append(int(get_bin[x:x+8],2))  # Convert every 8 bits to decimal (40 bytes)

                    rbyte = 0
                    rbit_cnt = 0
                    rbyte_cnt = 0
                    rbits = []
                    for i in range(0,(83-4)+1):
                        bi = i + 48 * (1 + (i >> 4))
                        nb = bi >> 3
                        bw = b_dec[nb]
                        rbyte = int((rbyte << 1) & 255)
                        rbyte |= (bw >> (7 - (bi - (nb << 3)))) & 1

                        rbit_cnt = rbit_cnt + 1
                        if rbit_cnt == 8:
                            rbits.append(int(rbyte&255))
                            rbyte_cnt = rbyte_cnt + 1
                            rbit_cnt = 0

                    # Calculate CRC from rbits
                    get_bin = ''
                    for n in range(0,len(rbits)):
                        get_bin = get_bin + bin(rbits[n])[2:].zfill(8)  # Convert decimal to binary string
                    poly = [1,0,0,0,1]  # From DECT Standard (x^4+1)
                    padding = "0"*(len(poly)-1)
                    mseg = list(get_bin + padding)
                    mseg = [int(i) for i in mseg]
                    q, r = signal2.deconvolve(mseg, poly)
                    r = abs(r)
                    for i in range(0,len(r)):
                        a = r[i]
                        if (a % 2) == 0:
                            r[i] = 0
                        else:
                            r[i] = 1
                    crc = r[len(get_bin):len(r)]

                    # Format it for the Table ("####")
                    bin_str = str(crc.tolist()).strip('[]')
                    bin_str = ''.join([bin_str[i] for i in range(0, len(bin_str), 5)])  # removes decimals
                    bin_str_spaces = ' '.join([bin_str[i:i+4] for i in range(0, len(bin_str), 4)])  # groups bits into 4

                    # Is Hex or Binary Selected for the CRC?
                    current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(9,0).currentText()
                    if current_selection == "Binary":
                        dashboard.ui.tableWidget1_attack_packet_editor.item(9,1).setText(bin_str_spaces)

                    # Binary to Hex
                    elif current_selection == "Hex":
                        bin_str = bin_str_spaces.replace(' ', '')
                        hex_str = '%0*X' % ((len(bin_str) + 3) // 4, int(bin_str, 2))
                        dashboard.ui.tableWidget1_attack_packet_editor.item(9,1).setText(hex_str)

        # Mode S
        elif current_protocol == "Mode S":

            # All Fields before the CRC Field (88 bits)
            get_bin = ""
            last_row = dashboard.ui.tableWidget1_attack_packet_editor.rowCount()-1

            for n in range(0,last_row):
                # Binary or Hex
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(n,0).currentText()

                # Contains Data
                if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1) != None:  # No Item Exists
                    if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text() != "":  # No Text for the Item Exists

                        # Get the Data
                        get_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text())

                        if current_selection == "Binary":
                            bin_str = get_data.replace(' ', '')

                        # Hex to Binary
                        elif current_selection == "Hex":
                            hex_len = len(get_data)
                            bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                        get_bin = get_bin + bin_str

                    # Nothing Found in a Field
                    else:
                        #if n != 3:  # Ignore Empty MISC Field
                        get_bin = "MISSING MODE S FIELD"
                        dashboard.ui.tableWidget1_attack_packet_editor.item(10,1).setText(get_bin)
                        break
                else:
                    #if n != 3:  # Ignore Empty MISC Field
                    get_bin = "MISSING MODE S FIELD"
                    new_item = QtWidgets.QTableWidgetItem("MISSING MODE S FIELD")
                    dashboard.ui.tableWidget1_attack_packet_editor.setItem(10,1,new_item)
                    break

            if get_bin != "MISSING MODE S FIELD":
                # Binary String to Hex
                bin_str = get_bin.replace(' ', '')
                hex_str = '%0*X' % ((len(bin_str) + 3) // 4, int(bin_str, 2))

                # From ADS-B Out: "adsb_encode.py"
                # CRC Polynomial (25)
                GENERATOR = "1111111111111010000001001"
                df17_str = hex_str +"000000"

                # Calculate CRC
                hex_len = len(df17_str)
                bin_str = bin(int(df17_str, 16))[2:].zfill(int(hex_len*4))
                msgbin = list(bin_str)
                encode = True
                if encode:
                    msgbin[-24:] = ['0'] * 24

                # loop all bits, except last 24 parity bits
                for i in range(len(msgbin)-24):
                    # if 1, perform modulo 2 multiplication,
                    if msgbin[i] == '1':
                        for j in range(len(GENERATOR)):
                            # modulo 2 multiplication = XOR
                            msgbin[i+j] = str((int(msgbin[i+j]) ^ int(GENERATOR[j])))

                # last 24 bits
                crc = ''.join(msgbin[-24:])

                # Format it for the Table ("#### #### #### ####")
                bin_str = str(crc).strip('[]')
                bin_str = bin_str.replace(', ','')

                bin_str_spaces = ' '.join([bin_str[i:i+4] for i in range(0, len(bin_str), 4)])  # groups bits into 4

                # Is Hex or Binary Selected for the CRC?
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(last_row,0).currentText()
                if current_selection == "Binary":
                    dashboard.ui.tableWidget1_attack_packet_editor.item(last_row,1).setText(bin_str_spaces)

                # Binary to Hex
                elif current_selection == "Hex":
                    bin_str = bin_str_spaces.replace(' ', '')
                    hex_str = '%0*X' % ((len(bin_str) + 3) // 4, int(bin_str, 2))
                    dashboard.ui.tableWidget1_attack_packet_editor.item(last_row,1).setText(hex_str)

        # SimpliciTI
        elif current_protocol == "SimpliciTI":
            # Length Field to End of Payload
            get_bin = ""
            last_row = dashboard.ui.tableWidget1_attack_packet_editor.rowCount()-1

            for n in range(2,last_row):
                # Binary or Hex
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(n,0).currentText()

                # Contains Data
                if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1) != None:  # No Item Exists
                    if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text() != "":  # No Text for the Item Exists

                        # Get the Data
                        get_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text())

                        if current_selection == "Binary":
                            bin_str = get_data.replace(' ', '')

                        # Hex to Binary
                        elif current_selection == "Hex":
                            hex_len = len(get_data)
                            bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                        get_bin = get_bin + bin_str

                    # Nothing Found in a Field
                    else:
                        if n != 3:  # Ignore Empty MISC Field
                            get_bin = "MISSING SIMPLICITI FIELD"
                            dashboard.ui.tableWidget1_attack_packet_editor.item(10,1).setText(get_bin)
                            break
                else:
                    if n != 3:  # Ignore Empty MISC Field
                        get_bin = "MISSING SIMPLICITI FIELD"
                        new_item = QtWidgets.QTableWidgetItem("MISSING SIMPLICITI FIELD")
                        dashboard.ui.tableWidget1_attack_packet_editor.setItem(10,1,new_item)
                        break

            if get_bin != "MISSING SIMPLICITI FIELD":
                # CRC Algorithm
                crc_registers = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]  # From Design Note 502 Figure 1

                mseg = [int(i) for i in list(get_bin)]

                for i in range(0,len(mseg)):
                    bit0 = mseg[i] ^ crc_registers[15]
                    bit2 = bit0 ^ crc_registers[1]
                    bit15 = bit0 ^ crc_registers[14]

                    crc_registers = crc_registers[-1:] + crc_registers[:-1]  # rotate list

                    crc_registers[0] = bit0
                    crc_registers[2] = bit2
                    crc_registers[15] = bit15

                crc = list(reversed(crc_registers))

                # Format it for the Table ("#### #### #### ####")
                bin_str = str(crc).strip('[]')
                bin_str = bin_str.replace(', ','')

                bin_str_spaces = ' '.join([bin_str[i:i+4] for i in range(0, len(bin_str), 4)])  # groups bits into 4

                # Is Hex or Binary Selected for the CRC?
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(last_row,0).currentText()
                if current_selection == "Binary":
                    dashboard.ui.tableWidget1_attack_packet_editor.item(last_row,1).setText(bin_str_spaces)

                # Binary to Hex
                elif current_selection == "Hex":
                    bin_str = bin_str_spaces.replace(' ', '')
                    hex_str = '%0*X' % ((len(bin_str) + 3) // 4, int(bin_str, 2))
                    dashboard.ui.tableWidget1_attack_packet_editor.item(last_row,1).setText(hex_str)

        # RDS
        elif current_protocol == "RDS":

            # Rows to Examine in Packet Crafter
            if current_subcategory == "Message Version A":
                first_row = [0,4,10,12]
                last_row = [3,9,11,13]
            elif current_subcategory == "Message Version B":
                first_row = [0,4,10,14]
                last_row = [3,9,13,15]

            # CRC A,B,C,D
            for m in range(0,len(first_row)):
                get_bin = ""
                for n in range(first_row[m],last_row[m]):
                    # Binary or Hex
                    current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(n,0).currentText()

                    # Contains Data
                    if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1) != None:  # No Item Exists
                        if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text() != "":  # No Text for the Item Exists

                            # Get the Data
                            get_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text())

                            if current_selection == "Binary":
                                bin_str = get_data.replace(' ', '')

                            # Hex to Binary
                            elif current_selection == "Hex":
                                hex_len = len(get_data)
                                bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                            get_bin = get_bin + bin_str

                        # Nothing Found in a Field
                        else:
                            get_bin = "MISSING RDS FIELD"
                            dashboard.ui.tableWidget1_attack_packet_editor.item(last_row[m],1).setText(get_bin)
                            break
                    else:
                        get_bin = "MISSING RDS FIELD"
                        new_item = QtWidgets.QTableWidgetItem("MISSING RDS FIELD")
                        dashboard.ui.tableWidget1_attack_packet_editor.setItem(last_row[m],1,new_item)
                        break

                if get_bin != "MISSING RDS FIELD":
                    # Binary String to Hex
                    bin_str = get_bin.replace(' ', '')
                    hex_str = '%0*X' % ((len(bin_str) + 3) // 4, int(bin_str, 2))

                    # CRC Algorithm
                    _GENERATOR_MATRIX = [
                        (0, 0, 0, 1, 1, 1, 0, 1, 1, 1),  # infoword msb
                        (1, 0, 1, 1, 1, 0, 0, 1, 1, 1),  # infoword msb - 1
                        (1, 1, 1, 0, 1, 0, 1, 1, 1, 1),  # infoword msb - 2, ...etc
                        (1, 1, 0, 0, 0, 0, 1, 0, 1, 1),
                        (1, 1, 0, 1, 0, 1, 1, 0, 0, 1),
                        (1, 1, 0, 1, 1, 1, 0, 0, 0, 0),
                        (0, 1, 1, 0, 1, 1, 1, 0, 0, 0),
                        (0, 0, 1, 1, 0, 1, 1, 1, 0, 0),
                        (0, 0, 0, 1, 1, 0, 1, 1, 1, 0),
                        (0, 0, 0, 0, 1, 1, 0, 1, 1, 1),
                        (1, 0, 1, 1, 0, 0, 0, 1, 1, 1),
                        (1, 1, 1, 0, 1, 1, 1, 1, 1, 1),
                        (1, 1, 0, 0, 0, 0, 0, 0, 1, 1),
                        (1, 1, 0, 1, 0, 1, 1, 1, 0, 1),
                        (1, 1, 0, 1, 1, 1, 0, 0, 1, 0),
                        (0, 1, 1, 0, 1, 1, 1, 0, 0, 1)   # infoword lsb
                    ]

                    _OFFSET_WORD = [
                        (0, 0, 1, 1, 1, 1, 1, 1, 0, 0),  # 'A'
                        (0, 1, 1, 0, 0, 1, 1, 0, 0, 0),  # 'B'
                        (0, 1, 0, 1, 1, 0, 1, 0, 0, 0),  # 'C'
                        (0, 1, 1, 0, 1, 1, 0, 1, 0, 0),  # 'D'
                        (1, 1, 0, 1, 0, 1, 0, 0, 0, 0),  # 'C prime' (used in block 3 if version is type B)
                        #(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)   # 'E'
                    ]

                    mseg = [int(i) for i in list(get_bin)]  # [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]

                    gen_polys = []
                    for index, bit in enumerate(mseg):
                        if bit:
                            gen_polys.append(_GENERATOR_MATRIX[index])

                    # Add Each Generator mod 2 (XOR)
                    crc_registers = [0,0,0,0,0,0,0,0,0,0]
                    for poly in gen_polys:
                        for n in range(0,len(crc_registers)):
                            crc_registers[n] = crc_registers[n] ^ poly[n]

                    # Add CRC and Offset Word
                    for n in range(0,len(crc_registers)):
                        if current_subcategory == "Message Version B" and m == 2:
                            crc_registers[n] = crc_registers[n] ^ _OFFSET_WORD[4][n]  # C'
                        else:
                            crc_registers[n] = crc_registers[n] ^ _OFFSET_WORD[m][n]

                    # Format it for the Table ("##########")
                    bin_str = str(crc_registers).strip('[]')
                    bin_str = bin_str.replace(', ','')
                    dashboard.ui.tableWidget1_attack_packet_editor.item(last_row[m],1).setText(bin_str)

        # X10
        elif current_protocol == "X10":

            # Invert Address Code and Data Code Fields
            for n in (0,2):
                bin_str = ""
                inv_bin_str = ""
                # Binary or Hex
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(n,0).currentText()

                # Contains Data
                if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1) != None:  # No Item Exists
                    if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text() != "":  # No Text for the Item Exists

                        # Get the Data
                        get_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text())

                        if current_selection == "Binary":
                            bin_str = get_data.replace(' ', '')

                        # Hex to Binary
                        elif current_selection == "Hex":
                            hex_len = len(get_data)
                            bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                        # Address Code
                        if n == 0:
                            if len(bin_str) != 8:
                                bin_str = "MISSING ADDRESS CODE"
                                dashboard.ui.tableWidget1_attack_packet_editor.item(1,1).setText(bin_str)
                        elif n == 2:
                            if len(bin_str) != 8:
                                bin_str = "MISSING DATA CODE"
                                dashboard.ui.tableWidget1_attack_packet_editor.item(3,1).setText(bin_str)

                    # Nothing Found in a Field
                    else:
                        if n == 0:
                            bin_str = "MISSING ADDRESS CODE"
                            dashboard.ui.tableWidget1_attack_packet_editor.item(1,1).setText(bin_str)
                        elif n == 2:
                            bin_str = "MISSING DATA CODE"
                            dashboard.ui.tableWidget1_attack_packet_editor.item(3,1).setText(bin_str)
                        break
                # Nothing Found in a Field
                else:
                    if n == 0:
                        bin_str = "MISSING ADDRESS CODE"
                        dashboard.ui.tableWidget1_attack_packet_editor.item(1,1).setText(bin_str)
                    elif n == 2:
                        bin_str = "MISSING DATA CODE"
                        dashboard.ui.tableWidget1_attack_packet_editor.item(3,1).setText(bin_str)
                    break

                # Calculate Inverse
                if bin_str != "MISSING ADDRESS CODE" and bin_str != "MISSING DATA CODE":
                    for m in range(0,8):
                        # Address Code
                        if bin_str[m] == "0":
                            inv_bin_str = inv_bin_str + "1"
                        else:
                            inv_bin_str = inv_bin_str + "0"

                    # Binary String to Hex
                    inv_bin_str = inv_bin_str.replace(' ', '')
                    inv_hex_str = '%0*X' % ((len(inv_bin_str) + 3) // 4, int(inv_bin_str, 2))

                    # Format it for the Table ("#### #### #### ####")
                    inv_bin_str_spaces = ' '.join([inv_bin_str[i:i+4] for i in range(0, len(inv_bin_str), 4)])  # groups bits into 4

                    # Is Hex or Binary Selected for the CRC?
                    inv_current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(n+1,0).currentText()
                    if inv_current_selection == "Binary":
                        dashboard.ui.tableWidget1_attack_packet_editor.item(n+1,1).setText(inv_bin_str_spaces)
                    else:
                        dashboard.ui.tableWidget1_attack_packet_editor.item(n+1,1).setText(inv_hex_str)

        # TPMS
        elif current_protocol == "TPMS":
            # All Fields before the CRC Field (58 bits)
            get_bin = ""
            last_row = dashboard.ui.tableWidget1_attack_packet_editor.rowCount()-1

            for n in range(0,last_row):
                # Binary or Hex
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(n,0).currentText()

                # Contains Data
                if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1) != None:  # No Item Exists
                    if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text() != "":  # No Text for the Item Exists

                        # Get the Data
                        get_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text())

                        if current_selection == "Binary":
                            bin_str = get_data.replace(' ', '')

                        # Hex to Binary
                        elif current_selection == "Hex":
                            hex_len = len(get_data)
                            bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                        get_bin = get_bin + bin_str

                    # Nothing Found in a Field
                    else:
                        get_bin = "MISSING TPMS FIELD"
                        dashboard.ui.tableWidget1_attack_packet_editor.item(10,1).setText(get_bin)
                        break
                else:
                    get_bin = "MISSING TPMS FIELD"
                    new_item = QtWidgets.QTableWidgetItem("MISSING TPMS FIELD")
                    dashboard.ui.tableWidget1_attack_packet_editor.setItem(10,1,new_item)
                    break

            if get_bin != "MISSING TPMS FIELD":
                # Binary String to Hex
                bin_str = get_bin.replace(' ', '')
                crc_data =  '000000' + bin_str
                crc_data_bytes = []
                for n in range(0,int(len(crc_data)/8)):
                    crc_data_bytes.append(int(crc_data[n*8:n*8+8],2))
                crc_data_bytes = bytes(crc_data_bytes)
                check_fn = crcmod.mkCrcFun(0x100 | 0x13, initCrc=0x0, rev=False)
                crc = '{0:08b}'.format(check_fn(crc_data_bytes))

                ####################################################
                # # From ADS-B Out: "adsb_encode.py"
                # # CRC Polynomial (25)
                # GENERATOR = "1111111111111010000001001"
                # df17_str = hex_str +"000000"

                # # Calculate CRC
                # hex_len = len(df17_str)
                # bin_str = bin(int(df17_str, 16))[2:].zfill(int(hex_len*4))
                # msgbin = list(bin_str)
                # encode = True
                # if encode:
                    # msgbin[-24:] = ['0'] * 24

                # # loop all bits, except last 24 parity bits
                # for i in range(len(msgbin)-24):
                    # # if 1, perform modulo 2 multiplication,
                    # if msgbin[i] == '1':
                        # for j in range(len(GENERATOR)):
                            # # modulo 2 multiplication = XOR
                            # msgbin[i+j] = str((int(msgbin[i+j]) ^ int(GENERATOR[j])))

                # # last 24 bits
                # crc = ''.join(msgbin[-24:])
                ####################################################

                # Format it for the Table ("#### #### #### ####")
                bin_str = str(crc).strip('[]')
                bin_str = bin_str.replace(', ','')

                bin_str_spaces = ' '.join([bin_str[i:i+4] for i in range(0, len(bin_str), 4)])  # groups bits into 4

                # Is Hex or Binary Selected for the CRC?
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(last_row,0).currentText()
                if current_selection == "Binary":
                    dashboard.ui.tableWidget1_attack_packet_editor.item(last_row,1).setText(bin_str_spaces)

                # Binary to Hex
                elif current_selection == "Hex":
                    bin_str = bin_str_spaces.replace(' ', '')
                    hex_str = '%0*X' % ((len(bin_str) + 3) // 4, int(bin_str, 2))
                    dashboard.ui.tableWidget1_attack_packet_editor.item(last_row,1).setText(hex_str)

        # Z-Wave
        elif current_protocol == "ZWAVE":
            # All Fields before the CRC Field
            get_bin = ""
            last_row = dashboard.ui.tableWidget1_attack_packet_editor.rowCount()-1

            for n in range(0,last_row):
                # Binary or Hex
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(n,0).currentText()

                # Contains Data
                if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1) != None:  # No Item Exists
                    if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text() != "":  # No Text for the Item Exists

                        # Get the Data
                        get_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text())

                        if current_selection == "Binary":
                            bin_str = get_data.replace(' ', '')

                        # Hex to Binary
                        elif current_selection == "Hex":
                            hex_len = len(get_data)
                            bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                        get_bin = get_bin + bin_str

                    # Nothing Found in a Field
                    else:
                        get_bin = "MISSING ZWAVE FIELD"
                        dashboard.ui.tableWidget1_attack_packet_editor.item(last_row,1).setText(get_bin)
                        break
                else:
                    get_bin = "MISSING ZWAVE FIELD"
                    new_item = QtWidgets.QTableWidgetItem("MISSING ZWAVE FIELD")
                    dashboard.ui.tableWidget1_attack_packet_editor.setItem(last_row,1,new_item)
                    break

            if get_bin != "MISSING ZWAVE FIELD":

                # Binary String to Hex
                bin_str = get_bin.replace(' ', '')
                crc_data =  bin_str
                crc_data_bytes = ''
                for n in range(0,int(len(crc_data)/8)):
                    crc_data_bytes = crc_data_bytes + hex(int(crc_data[n*8:n*8+8],2))[2:].zfill(2)

                # Calculate the CRC
                get_seed = "1D0F"
                get_poly = int("1021",16)

                # Known Seed
                acc = get_seed
                for n in range(0,int(len(crc_data_bytes)/2)):
                    new_byte = crc_data_bytes[2*n:2*n+2]
                    acc = fissure.utils.updateCRC(get_poly, acc, new_byte, 16)  # Poly: 0x1021, Seed: 0x1DOF

                hex_len = len(acc)
                bin_str = bin(int(acc, 16))[2:].zfill(int(hex_len*4))

                # Format it for the Table ("#### #### #### ####")
                bin_str_spaces = ' '.join([bin_str[i:i+4] for i in range(0, len(bin_str), 4)])  # groups bits into 4

                # Is Hex or Binary Selected for the CRC?
                current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(last_row,0).currentText()
                if current_selection == "Binary":
                    dashboard.ui.tableWidget1_attack_packet_editor.item(last_row,1).setText(bin_str_spaces)

                # Binary to Hex
                elif current_selection == "Hex":
                    bin_str = bin_str_spaces.replace(' ', '')
                    hex_str = '%0*X' % ((len(bin_str) + 3) // 4, int(bin_str, 2))
                    dashboard.ui.tableWidget1_attack_packet_editor.item(last_row,1).setText(hex_str)

    # Message Data Entered Incorrectly
    #except ValueError as inst:
    #    fissure.Dashboard.UI_Components.Qt5.errorMessage("Message data was entered incorrectly.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketAllHexClicked(dashboard: QtCore.QObject):
    """ 
    Converts all values to hex from binary in the packet editor.
    """
    try:
        # Change the Binary/Hex ComboBox
        for row in range(dashboard.ui.tableWidget1_attack_packet_editor.rowCount()):
            if dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(row,0).isEnabled() is True:
                dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(row,0).setCurrentIndex(1)

    # Message Data Entered Incorrectly
    except ValueError as inst:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Message data was entered incorrectly.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketAllBinaryClicked(dashboard: QtCore.QObject):
    """ 
    Converts all values to binary from hex in the packet editor.
    """
    try:
        # Change the Binary ComboBox
        for row in range(dashboard.ui.tableWidget1_attack_packet_editor.rowCount()):
            get_length = int(dashboard.ui.tableWidget1_attack_packet_editor.item(row,3).text())
            if get_length > 0:
                dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(row,0).setCurrentIndex(0)

    # Message Data Entered Incorrectly
    except ValueError as inst:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Message data was entered incorrectly.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketOpenClicked(dashboard: QtCore.QObject):
    """ 
    Loads a binary file into the packet editor.
    """
    # Look for the Binary File
    directory = os.path.join(fissure.utils.FISSURE_ROOT, "Crafted Packets")  # Default Directory
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select Binary File...", directory, filter="Binary Files (*.bin);;All Files (*.*)")[0]

    # If a Valid File
    if fname != "":
        # Read the File
        f = open(fname, "rb")
        get_bytes = f.read()
        f.close()
        hex_str = binascii.hexlify(get_bytes)
        hex_str = hex_str.decode("utf-8").upper()

        # Set the Assembled Text Box
        dashboard.ui.textEdit1_packet_constructed.setPlainText(hex_str)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketAppendClicked(dashboard: QtCore.QObject):
    """ 
    Appends the contents of the packet scratchpad (with the multiplier) to the assembled text edit box.
    """
    # Get the Assembled Packet Text
    scratch_pad_text = str(dashboard.ui.textEdit1_packet_assembled.toPlainText())

    # Get the Text Multiplier
    try:
        text_multiplier = int(str(dashboard.ui.textEdit_packet_number_of_messages.toPlainText()))
        if text_multiplier < 1:
            text_multipler = 1
            dashboard.ui.textEdit_packet_number_of_messages.setText("1")

        # Create a Repeated Message
        repeated_message = ""
        for n in range(0,text_multiplier):
            repeated_message += scratch_pad_text

        # Append to the Constructed Sequence
        get_assembled_text = str(dashboard.ui.textEdit1_packet_constructed.toPlainText())
        get_assembled_text += repeated_message

        # Update the Constructed Sequence
        dashboard.ui.textEdit1_packet_constructed.setText(get_assembled_text)
    except:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a Valid Multiplier (Counting Number)")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketScapyShowClicked(dashboard: QtCore.QObject):
    """ 
    Calls the Scapy function '.show()' on a loaded packet.
    """
    # Show Loaded Data
    if dashboard.scapy_data != None:
        capture = StringIO()
        save_stdout = sys.stdout
        sys.stdout = capture
        dashboard.scapy_data[0].show()
        sys.stdout = save_stdout

        msgBox = MyMessageBox(my_text = capture.getvalue())
        msgBox.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketScapyRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Refreshes the list of wireless interfaces available for Scapy injection.
    """
    # Update Interface Comboboxes
    get_interfaces = os.listdir("/sys/class/net/")
    dashboard.ui.comboBox_packet_scapy_interface.clear()
    for n in get_interfaces:
        dashboard.ui.comboBox_packet_scapy_interface.addItem(n)

    # Select the Last Interface by Default
    dashboard.ui.comboBox_packet_scapy_interface.setCurrentIndex(dashboard.ui.comboBox_packet_scapy_interface.count()-1)


@qasync.asyncSlot(QtCore.QObject)
async def _slotPacketScapyStartClicked(dashboard: QtCore.QObject):
    """ 
    Runs the Scapy .sendp() command.
    """
    # Get Parameters
    get_iface = str(dashboard.ui.comboBox_packet_scapy_interface.currentText())
    get_interval = str(dashboard.ui.textEdit_packet_scapy_interval.toPlainText())
    if dashboard.ui.checkBox_packet_scapy_loop.isChecked():
        get_loop = "1"
    else:
        get_loop = "0"

    # Start Transmitting
    if len(get_iface) > 0:
        # Send the Message
        await dashboard.backend.startScapy(dashboard.selected_node_uid, get_iface, get_interval, get_loop, dashboard.backend.os_info)
    else:
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Specify wireless interface.", width=100, height=20)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketScapyLoadClicked(dashboard: QtCore.QObject):
    """ 
    Loads the information from the top half of the packet crafter and assembles a Scapy packet.
    """
    # Get Frame Type
    get_type = str(dashboard.ui.comboBox_packet_subcategory.currentText())

    # Convert Rows to Binary
    get_bin = []
    for n in range(0,dashboard.ui.tableWidget1_attack_packet_editor.rowCount()):
        # Binary or Hex
        bin_str = ""
        current_selection = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(n,0).currentText()

        # Contains Item
        if dashboard.ui.tableWidget1_attack_packet_editor.item(n,1) != None:
            # Not Empty
            if str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text()) != "":
                # Get the Data
                get_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(n,1).text())

                if current_selection == "Binary":
                    bin_str = get_data.replace(' ', '')

                # Hex to Binary
                elif current_selection == "Hex":
                    hex_len = len(get_data)
                    bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                # Store Rows in List, Ignores Strings
                if len(bin_str) > 0:
                    get_bin.append(bin_str)

    # Assemble
    if "Action" == get_type:
        get_dest_mac = '%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))
        get_dest_mac = get_dest_mac[0:2] + ":" + get_dest_mac[2:4] + ":" + get_dest_mac[4:6] + ":" + get_dest_mac[6:8] + ":" + get_dest_mac[8:10] + ":" + get_dest_mac[10:12]
        get_source_mac = '%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))
        get_source_mac = get_source_mac[0:2] + ":" + get_source_mac[2:4] + ":" + get_source_mac[4:6] + ":" + get_source_mac[6:8] + ":" + get_source_mac[8:10] + ":" + get_source_mac[10:12]
        get_bssid_mac = '%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))
        get_bssid_mac = get_bssid_mac[0:2] + ":" + get_bssid_mac[2:4] + ":" + get_bssid_mac[4:6] + ":" + get_bssid_mac[6:8] + ":" + get_bssid_mac[8:10] + ":" + get_bssid_mac[10:12]
        get_category = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[3]) + 3) // 4, int(get_bin[3], 2))))
        get_action = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[4]) + 3) // 4, int(get_bin[4], 2))))
        get_element = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[5]) + 3) // 4, int(get_bin[5], 2))))
        dashboard.scapy_data = RadioTap()/Dot11(type=0, subtype=13, addr1=get_dest_mac, addr2=get_source_mac, addr3=get_bssid_mac)/get_category/get_action/get_element

    elif "CTS" == get_type:
        get_recv_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_type_subtype = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        get_duration = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        dashboard.scapy_data = RadioTap()/get_type_subtype/get_duration/get_recv_mac

    elif "Deauthentication" == get_type:
        get_target_mac = '%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))
        get_target_mac = get_target_mac[0:2] + ":" + get_target_mac[2:4] + ":" + get_target_mac[4:6] + ":" + get_target_mac[6:8] + ":" + get_target_mac[8:10] + ":" + get_target_mac[10:12]
        get_ap_mac = '%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))
        get_ap_mac = get_ap_mac[0:2] + ":" + get_ap_mac[2:4] + ":" + get_ap_mac[4:6] + ":" + get_ap_mac[6:8] + ":" + get_ap_mac[8:10] + ":" + get_ap_mac[10:12]
        dashboard.scapy_data = RadioTap()/Dot11(type=0, subtype=12, addr1=get_target_mac, addr2=get_ap_mac, addr3=get_ap_mac)/Dot11Deauth(reason=7)

    elif "Null" == get_type:
        get_dest_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_source_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        get_bssid_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        get_type_subtype = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[3]) + 3) // 4, int(get_bin[3], 2))))
        get_flags = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[4]) + 3) // 4, int(get_bin[4], 2))))
        get_duration = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[5]) + 3) // 4, int(get_bin[5], 2))))
        get_fragment_sequence = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[6]) + 3) // 4, int(get_bin[6], 2))))
        dashboard.scapy_data = RadioTap()/get_type_subtype/get_flags/get_duration/get_dest_mac/get_source_mac/get_bssid_mac/get_fragment_sequence

    elif "Probe Request" == get_type:
        get_source_mac = '%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))
        get_source_mac = get_source_mac[0:2] + ":" + get_source_mac[2:4] + ":" + get_source_mac[4:6] + ":" + get_source_mac[6:8] + ":" + get_source_mac[8:10] + ":" + get_source_mac[10:12]
        get_target_mac = '%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))
        get_target_mac = get_target_mac[0:2] + ":" + get_target_mac[2:4] + ":" + get_target_mac[4:6] + ":" + get_target_mac[6:8] + ":" + get_target_mac[8:10] + ":" + get_target_mac[10:12]
        dashboard.scapy_data = RadioTap()/Dot11(type=0, subtype=4, addr1=get_target_mac, addr2=get_source_mac)/Dot11ProbeReq("00" * 1)
        #dashboard.scapy_data = RadioTap()/Dot11(type=0, subtype=0100, addr2=get_target_mac)/Dot11ProbeReq("00" * 1)  # "subtype" doesn't register in this format

    elif "RTS" == get_type:
        get_recv_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_tx_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        get_type_subtype = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        get_duration = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[3]) + 3) // 4, int(get_bin[3], 2))))
        dashboard.scapy_data = RadioTap()/get_type_subtype/get_duration/get_recv_mac/get_tx_mac

    elif "UDP from AP" == get_type:
        get_addr1_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_addr2_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        #get_addr3_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        get_type_subtype = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        get_flags = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[3]) + 3) // 4, int(get_bin[3], 2))))
        get_duration = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[4]) + 3) // 4, int(get_bin[4], 2))))
        get_fragment_sequence = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[5]) + 3) // 4, int(get_bin[5], 2))))
        get_udp_source_ip = str(dashboard.ui.tableWidget1_attack_packet_editor.item(6,1).text())
        get_udp_dest_ip = str(dashboard.ui.tableWidget1_attack_packet_editor.item(7,1).text())
        get_udp_source_port = str(dashboard.ui.tableWidget1_attack_packet_editor.item(8,1).text())
        get_udp_dest_port = str(dashboard.ui.tableWidget1_attack_packet_editor.item(9,1).text())
        get_udp_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(10,1).text())

        # Convert Hex to Hexstring Format ('00FF' --> '\x00\xFF')
        # get_udp_data = bytes(get_udp_data, encoding='utf-8')  # Treats \xAA as string
        get_udp_data = bytes.fromhex(get_udp_data.replace("\\x", ""))

        llc_bytes = LLC()/SNAP()

        udp_bytes = IP()/UDP()
        udp_bytes[IP].src = get_udp_source_ip
        udp_bytes[IP].dst = get_udp_dest_ip
        udp_bytes[UDP].sport = int(get_udp_source_port)
        udp_bytes[UDP].dport = int(get_udp_dest_port)

        # Flag DS bits: 01 (From Ap), Addr1=Destination STA, Addr2=BSSID, Addr3=Source STA
        dashboard.scapy_data = RadioTap()/get_type_subtype/get_flags/get_duration/get_addr2_mac/get_addr1_mac/get_addr1_mac/get_fragment_sequence/llc_bytes/udp_bytes/get_udp_data

    elif "UDP to AP" == get_type:
        get_addr1_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_addr2_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        get_addr3_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        get_type_subtype = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[3]) + 3) // 4, int(get_bin[3], 2))))
        get_flags = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[4]) + 3) // 4, int(get_bin[4], 2))))
        get_duration = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[5]) + 3) // 4, int(get_bin[5], 2))))
        get_fragment_sequence = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[6]) + 3) // 4, int(get_bin[6], 2))))
        get_udp_source_ip = str(dashboard.ui.tableWidget1_attack_packet_editor.item(7,1).text())
        get_udp_dest_ip = str(dashboard.ui.tableWidget1_attack_packet_editor.item(8,1).text())
        get_udp_source_port = str(dashboard.ui.tableWidget1_attack_packet_editor.item(9,1).text())
        get_udp_dest_port = str(dashboard.ui.tableWidget1_attack_packet_editor.item(10,1).text())
        get_udp_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(11,1).text())

        # Convert Hex to Hexstring Format ('00FF' --> '\x00\xFF')
        # get_udp_data = bytes(get_udp_data, encoding='utf-8')  # Treats \xAA as string
        get_udp_data = bytes.fromhex(get_udp_data.replace("\\x", ""))

        llc_bytes = LLC()/SNAP()

        udp_bytes = IP()/UDP()
        udp_bytes[IP].src = get_udp_source_ip
        udp_bytes[IP].dst = get_udp_dest_ip
        udp_bytes[UDP].sport = int(get_udp_source_port)
        udp_bytes[UDP].dport = int(get_udp_dest_port)

        # Flag DS bits: 01 (From Ap), Addr1=Destination STA, Addr2=BSSID, Addr3=Source STA
        dashboard.scapy_data = RadioTap()/get_type_subtype/get_flags/get_duration/get_addr1_mac/get_addr2_mac/get_addr3_mac/get_fragment_sequence/llc_bytes/udp_bytes/get_udp_data
        #print(dashboard.scapy_data[0].show())

    elif "ARP Response - Wifi" == get_type:
        get_addr1_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_addr2_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        get_addr3_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        get_type_subtype = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[3]) + 3) // 4, int(get_bin[3], 2))))
        get_flags = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[4]) + 3) // 4, int(get_bin[4], 2))))
        get_duration = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[5]) + 3) // 4, int(get_bin[5], 2))))
        get_fragment_sequence = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[6]) + 3) // 4, int(get_bin[6], 2))))

        get_hwtype = str(dashboard.ui.tableWidget1_attack_packet_editor.item(7,1).text())
        get_ptype = str(dashboard.ui.tableWidget1_attack_packet_editor.item(8,1).text())
        get_hwlen = str(dashboard.ui.tableWidget1_attack_packet_editor.item(9,1).text())
        get_plen = str(dashboard.ui.tableWidget1_attack_packet_editor.item(10,1).text())
        get_op = str(dashboard.ui.tableWidget1_attack_packet_editor.item(11,1).text())
        get_hwsrc = str(dashboard.ui.tableWidget1_attack_packet_editor.item(12,1).text())
        get_psrc = str(dashboard.ui.tableWidget1_attack_packet_editor.item(13,1).text())
        get_hwdst = str(dashboard.ui.tableWidget1_attack_packet_editor.item(14,1).text())
        get_pdst = str(dashboard.ui.tableWidget1_attack_packet_editor.item(15,1).text())

        arp_bytes = ARP()
        arp_bytes[ARP].hwtype = int(get_hwtype) & 0xFF
        arp_bytes[ARP].ptype = int(get_ptype) & 0xFFF
        arp_bytes[ARP].hwlen = int(get_hwlen)
        arp_bytes[ARP].plen = int(get_plen)
        arp_bytes[ARP].op = int(get_op)
        arp_bytes[ARP].hwsrc = get_hwsrc
        arp_bytes[ARP].psrc = get_psrc
        arp_bytes[ARP].hwdst = get_hwdst
        arp_bytes[ARP].pdst = get_pdst

        dashboard.scapy_data = RadioTap()/get_type_subtype/get_flags/get_duration/get_addr3_mac/get_addr1_mac/get_addr2_mac/get_fragment_sequence/LLC()/SNAP()/arp_bytes

    elif "ARP Response - Ethernet" == get_type:
        get_hwtype = str(dashboard.ui.tableWidget1_attack_packet_editor.item(0,1).text())
        get_ptype = str(dashboard.ui.tableWidget1_attack_packet_editor.item(1,1).text())
        get_hwlen = str(dashboard.ui.tableWidget1_attack_packet_editor.item(2,1).text())
        get_plen = str(dashboard.ui.tableWidget1_attack_packet_editor.item(3,1).text())
        get_op = str(dashboard.ui.tableWidget1_attack_packet_editor.item(4,1).text())
        get_hwsrc = str(dashboard.ui.tableWidget1_attack_packet_editor.item(5,1).text())
        get_psrc = str(dashboard.ui.tableWidget1_attack_packet_editor.item(6,1).text())
        get_hwdst = str(dashboard.ui.tableWidget1_attack_packet_editor.item(7,1).text())
        get_pdst = str(dashboard.ui.tableWidget1_attack_packet_editor.item(8,1).text())

        arp_bytes = ARP()
        arp_bytes[ARP].hwtype = int(get_hwtype) & 0xFF
        arp_bytes[ARP].ptype = int(get_ptype) & 0xFFF
        arp_bytes[ARP].hwlen = int(get_hwlen)
        arp_bytes[ARP].plen = int(get_plen)
        arp_bytes[ARP].op = int(get_op)
        arp_bytes[ARP].hwsrc = get_hwsrc
        arp_bytes[ARP].psrc = get_psrc
        arp_bytes[ARP].hwdst = get_hwdst
        arp_bytes[ARP].pdst = get_pdst

        dashboard.scapy_data = Ether()/arp_bytes

    elif "ICMP" == get_type:
        get_source_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_dest_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        get_bssid_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        get_source_ip = str(dashboard.ui.tableWidget1_attack_packet_editor.item(3,1).text())
        get_dest_ip = str(dashboard.ui.tableWidget1_attack_packet_editor.item(4,1).text())
        get_icmp_type = int(get_bin[3], 2)
        get_icmp_code = int(get_bin[4], 2)
        get_icmp_id = int(get_bin[5], 2)
        get_icmp_seq = int(get_bin[6], 2)

        scapy_bytes = RadioTap()/Dot11()/LLC()/SNAP()/IP()/ICMP()
        scapy_bytes[Dot11].addr1 = get_dest_mac
        scapy_bytes[Dot11].addr2 = get_source_mac
        scapy_bytes[Dot11].addr3 = get_bssid_mac
        scapy_bytes[Dot11].type = 2
        scapy_bytes[Dot11].subtype = 0
        scapy_bytes[IP].src = get_source_ip
        scapy_bytes[IP].dst = get_dest_ip
        scapy_bytes[ICMP].type = get_icmp_type
        scapy_bytes[ICMP].code = get_icmp_code
        scapy_bytes[ICMP].id = get_icmp_id
        scapy_bytes[ICMP].seq = get_icmp_seq

        dashboard.scapy_data = scapy_bytes

    elif "UDP to AP QoS" == get_type:
        get_addr1_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_addr2_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        get_addr3_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        get_type_subtype = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[3]) + 3) // 4, int(get_bin[3], 2))))
        get_flags = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[4]) + 3) // 4, int(get_bin[4], 2))))
        get_duration = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[5]) + 3) // 4, int(get_bin[5], 2))))
        get_fragment_sequence = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[6]) + 3) // 4, int(get_bin[6], 2))))
        get_qos_control = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[7]) + 3) // 4, int(get_bin[7], 2))))
        get_udp_source_ip = str(dashboard.ui.tableWidget1_attack_packet_editor.item(8,1).text())
        get_udp_dest_ip = str(dashboard.ui.tableWidget1_attack_packet_editor.item(9,1).text())
        get_udp_source_port = str(dashboard.ui.tableWidget1_attack_packet_editor.item(10,1).text())
        get_udp_dest_port = str(dashboard.ui.tableWidget1_attack_packet_editor.item(11,1).text())
        get_udp_data = str(dashboard.ui.tableWidget1_attack_packet_editor.item(12,1).text())

        # Convert Hex to Hexstring Format ('00FF' --> '\x00\xFF')
        # get_udp_data = bytes(get_udp_data, encoding='utf-8')  # Treats \xAA as string
        get_udp_data = bytes.fromhex(get_udp_data.replace("\\x", ""))

        llc_bytes = LLC()/SNAP()

        udp_bytes = IP()/UDP()
        udp_bytes[IP].src = get_udp_source_ip
        udp_bytes[IP].dst = get_udp_dest_ip
        udp_bytes[UDP].sport = int(get_udp_source_port)
        udp_bytes[UDP].dport = int(get_udp_dest_port)

        # Flag DS bits: 01 (From Ap), Addr1=Destination STA, Addr2=BSSID, Addr3=Source STA
        dashboard.scapy_data = RadioTap()/get_type_subtype/get_flags/get_duration/get_addr1_mac/get_addr2_mac/get_addr3_mac/get_fragment_sequence/get_qos_control/llc_bytes/udp_bytes/get_udp_data
        #print(dashboard.scapy_data[0].show())


    # Set Loaded Text
    dashboard.ui.label2_packet_scapy_loaded.setText(get_type)

    # Enable Controls
    dashboard.ui.label2_packet_scapy_view.setEnabled(True)
    dashboard.ui.pushButton_packet_scapy_show.setEnabled(True)
    dashboard.ui.pushButton_packet_scapy_ls.setEnabled(True)
    dashboard.ui.label2_packet_scapy_interval.setEnabled(True)
    dashboard.ui.textEdit_packet_scapy_interval.setEnabled(True)
    dashboard.ui.label2_packet_scapy_interface.setEnabled(True)
    dashboard.ui.comboBox_packet_scapy_interface.setEnabled(True)
    dashboard.ui.pushButton_packet_scapy_refresh.setEnabled(True)
    dashboard.ui.checkBox_packet_scapy_loop.setEnabled(True)
    dashboard.ui.pushButton_packet_scapy_start.setEnabled(True)
    dashboard.ui.pushButton_packet_scapy_stop.setEnabled(True)

    # Write to PCAP
    wrpcap(os.path.join(fissure.utils.FISSURE_ROOT, "Crafted Packets", "Scapy", "temp.cap"), dashboard.scapy_data)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketScapyLsClicked(dashboard: QtCore.QObject):
    """ 
    Calls the Scapy function 'ls' on a loaded packet.
    """
    # Show Loaded Data
    if dashboard.scapy_data != None:
        capture = StringIO()
        save_stdout = sys.stdout
        sys.stdout = capture
        ls(dashboard.scapy_data[0])
        sys.stdout = save_stdout

        msgBox = MyMessageBox(my_text = capture.getvalue(), width=800, height=600)
        msgBox.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketCommaSeparatedClicked(dashboard: QtCore.QObject):
    """ 
    Converts hex data (0000) to \x00,\x00 in assembled text edit box.
    """
    # Get the Hex String
    get_hex = str(dashboard.ui.textEdit1_packet_assembled.toPlainText())

    # Add the '\x,'
    if len(get_hex) > 0:
        output_string = '\\x'
        for n in range(0,len(get_hex),2):
            output_string = output_string + get_hex[n:n+2] + ',\\x'

        dashboard.ui.textEdit1_packet_assembled.setPlainText(output_string[:-3])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketCommaSeparatedClicked2(dashboard: QtCore.QObject):
    """ 
    Converts hex data (0000) to 0x00,0x00 in assembled text edit box.
    """
    # Get the Hex String
    get_hex = str(dashboard.ui.textEdit1_packet_assembled.toPlainText())

    # Add the '0x,'
    if len(get_hex) > 0:
        output_string = '0x'
        for n in range(0,len(get_hex),2):
            output_string = output_string + get_hex[n:n+2] + ',0x'

        dashboard.ui.textEdit1_packet_assembled.setPlainText(output_string[:-3])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketPattern1Clicked(dashboard: QtCore.QObject):
    """ 
    Converts hex data (0000) to \x00\x00 in assembled text edit box.
    """
    # Get the Hex String
    get_hex = str(dashboard.ui.textEdit1_packet_assembled.toPlainText())

    # Add the '\x'
    if len(get_hex) > 0:
        output_string = '\\x'
        for n in range(0,len(get_hex),2):
            output_string = output_string + get_hex[n:n+2] + '\\x'

        dashboard.ui.textEdit1_packet_assembled.setPlainText(output_string[:-2])


@qasync.asyncSlot(QtCore.QObject)
async def _slotPacketScapyStopClicked(dashboard: QtCore.QObject):
    """ 
    Kills all running Scapy processes.
    """
    # Send the Message
    await dashboard.backend.stopScapy(dashboard.selected_node_uid)


@QtCore.pyqtSlot(QtCore.QObject, int, int)
def _slotPacketItemChanged(dashboard: QtCore.QObject, row: int, col: int):
    """ 
    Updates the current lengths of fields when an item in the packet editor table changes.
    """
    # Only Look at the Data Column
    if col == 1:
        # Ignore Item Changes by the System
        if dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(row, 0) is not None:
            # Get the type from the combobox
            field_type = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(row, 0).currentText()

            # If it's a String, set length to 0
            if field_type == "String":
                get_length = 0
            else:
                # Get the Current Item
                current_item = dashboard.ui.tableWidget1_attack_packet_editor.item(row, 1)

                if current_item is not None:
                    # Binary or Hex
                    if field_type == "Binary":
                        get_length_str = str(current_item.text()).replace(" ", "")
                        get_length = len(get_length_str)
                    else:  # Hex
                        get_length = 4 * len(str(current_item.text()))

            # Always create a new `QTableWidgetItem`
            new_length_item = QtWidgets.QTableWidgetItem(str(get_length))
            new_length_item.setTextAlignment(QtCore.Qt.AlignCenter)
            new_length_item.setFlags(new_length_item.flags() & ~QtCore.Qt.ItemIsEditable)

            dashboard.ui.tableWidget1_attack_packet_editor.setItem(row, 2, new_length_item)

            # Calculate the Total Lengths
            current_length_total = sum(
                int(dashboard.ui.tableWidget1_attack_packet_editor.item(n, 2).text())
                for n in range(dashboard.ui.tableWidget1_attack_packet_editor.rowCount())
                if dashboard.ui.tableWidget1_attack_packet_editor.item(n, 2) is not None
            )
            dashboard.ui.label2_packet_current_length_total.setText(str(current_length_total))

    # Ensure the function is properly connected
    dashboard.ui.tableWidget1_attack_packet_editor.cellChanged.disconnect()
    dashboard.ui.tableWidget1_attack_packet_editor.cellChanged.connect(
        lambda row, col: _slotPacketItemChanged(dashboard, row, col)
    )


@QtCore.pyqtSlot(QtCore.QObject, int, int)
def _slotAttackFuzzingItemChanged(dashboard: QtCore.QObject, row: int, col: int):
    """ 
    This is called whenever an item in the fuzzing fields table is changed. It is used to update the current lengths of the fields.
    """
    # Only Look at the Data Column
    if col == 5:

        # Ignore Item Changes by the System
        if dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(dashboard.ui.tableWidget_attack_fuzzing_data_field.currentRow(),4) != None:

            # Get the Current Item
            current_item = dashboard.ui.tableWidget_attack_fuzzing_data_field.item(dashboard.ui.tableWidget_attack_fuzzing_data_field.currentRow(),5)

            # Binary or Hex
            if dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(dashboard.ui.tableWidget_attack_fuzzing_data_field.currentRow(),4).currentText() == "Binary":
                get_length_str = str(current_item.text()).replace(" ","")
                get_length = len(get_length_str)
            else:
                get_length = 4*len(str(current_item.text()))

            # Update the Length Label
            new_length_item = QtWidgets.QTableWidgetItem(str(get_length))
            new_length_item.setTextAlignment(QtCore.Qt.AlignCenter)
            new_length_item.setFlags(new_length_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setItem(dashboard.ui.tableWidget_attack_fuzzing_data_field.currentRow(),6,new_length_item)

            # Calculate the Lengths
            current_length_total = 0
            for n in range(0,dashboard.ui.tableWidget_attack_fuzzing_data_field.rowCount()):
                current_length_total += int(dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,6).text())
            dashboard.ui.label2_attack_fuzzing_current_length_total.setText(str(current_length_total))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackProtocols(dashboard: QtCore.QObject):
    """ 
    Changes the list of potential attacks based on the protocol information from the library.
    """
    try:
        # Clear Any Existing Attack Configurations
        dashboard.ui.label2_attack_fuzzing_selected_flow_graph.setText("")
        dashboard.ui.textEdit_fuzzing_from_file.setPlainText("")
        for row in reversed(range(0,dashboard.ui.tableWidget_fuzzing_variables.rowCount())):
            dashboard.ui.tableWidget_fuzzing_variables.removeRow(row)
        for row in reversed(range(0,dashboard.ui.tableWidget_attack_fuzzing_data_field.rowCount())):
            dashboard.ui.tableWidget_attack_fuzzing_data_field.removeRow(row)
        for row in reversed(range(0,dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount())):
            dashboard.ui.tableWidget1_attack_flow_graph_current_values.removeRow(row)
        dashboard.ui.label2_selected_flow_graph.setText("")
        dashboard.ui.label1_selected_attack.setText("")
        dashboard.ui.label2_selected_modulation.setText("")
        dashboard.ui.label2_selected_hardware.setText("")
        dashboard.ui.label2_selected_notes.setText("")
        dashboard.ui.label2_attack_single_stage_file_type.setText("")
        dashboard.ui.label2_selected_protocol.setText("")

        # Disable Buttons
        dashboard.ui.pushButton_attack_view_flow_graph.setEnabled(False)

        # Get the Protocol
        current_protocol = str(dashboard.ui.comboBox_attack_protocols.currentText())
        dashboard.ui.label2_attack_fuzzing_selected_protocol.setText(current_protocol)
        enabled_categories = []
        disabled_categories = []

        # Hide/Unhide All Attacks, Disable All Attacks
        iterator = QtWidgets.QTreeWidgetItemIterator(dashboard.ui.treeWidget_attack_attacks)
        while iterator.value():
            item = iterator.value()
            if dashboard.ui.checkBox_attack_show_all.isChecked():
                item.setHidden(False)
            else:
                item.setHidden(True)
            item.setDisabled(True)

            # Update Iterator
            iterator+=1

        # Fuzzing Subcategories ComboBox
        dashboard.ui.comboBox_attack_fuzzing_subcategory.clear()
        packet_types = fissure.utils.library.getPacketTypes(dashboard.backend.library,current_protocol)
        for packet_type in packet_types:
            dashboard.ui.comboBox_attack_fuzzing_subcategory.addItem(packet_type)

        # Data Field Table
        current_packet = str(dashboard.ui.comboBox_attack_fuzzing_subcategory.currentText())
        if current_packet != "None":
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setRowCount(len(fissure.utils.library.getFields(dashboard.backend.library,current_protocol,current_packet)))
            dashboard.ui.tableWidget_attack_fuzzing_data_field.clear()
            field_names =  fissure.utils.library.getFields(dashboard.backend.library,current_protocol,current_packet)
            for n in range(0,len(field_names)):
                new_item = QtWidgets.QTableWidgetItem(field_names[n])
                dashboard.ui.tableWidget_attack_fuzzing_data_field.setVerticalHeaderItem(n,new_item)

        # Update the Packet Editor Table Headers  # Update for Different Packet Types
        select_header_item = QtWidgets.QTableWidgetItem("Select")
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setHorizontalHeaderItem(0,select_header_item)
        type_header_item = QtWidgets.QTableWidgetItem("Type")
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setHorizontalHeaderItem(1,type_header_item)
        min_header_item = QtWidgets.QTableWidgetItem("Min.")
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setHorizontalHeaderItem(2,min_header_item)
        max_header_item = QtWidgets.QTableWidgetItem("Max.")
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setHorizontalHeaderItem(3,max_header_item)
        binary_hex_item = QtWidgets.QTableWidgetItem("Bin/Hex")
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setHorizontalHeaderItem(4,binary_hex_item)
        data_header_item = QtWidgets.QTableWidgetItem("Data")
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setHorizontalHeaderItem(5,data_header_item)
        length_header_item = QtWidgets.QTableWidgetItem("Length")
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setHorizontalHeaderItem(6,length_header_item)
        default_header_item = QtWidgets.QTableWidgetItem("Default")
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setHorizontalHeaderItem(7,default_header_item)

        # Binary/Hex ComboBoxes, Select CheckBoxes, Type ComboBoxes
        for n in range(0,dashboard.ui.tableWidget_attack_fuzzing_data_field.rowCount()):
            new_combobox1 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setCellWidget(n,4,new_combobox1)
            new_combobox1.addItem("Binary")
            new_combobox1.addItem("Hex")
            new_combobox1.currentIndexChanged.connect(lambda: _slotPacketBinaryHex(dashboard, dashboard.ui.tableWidget_attack_fuzzing_data_field))
            new_combobox1.setCurrentIndex(0)
            new_combobox1.setProperty("row", n)

            # CheckBoxes
            new_checkbox = QtWidgets.QCheckBox("",dashboard,objectName='checkBox_')
            new_checkbox.setStyleSheet("margin-left:17%")  # doesn't center, could create a layout and put the radio button in the layout
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setCellWidget(n,0,new_checkbox)
            #new_checkbox.stateChanged.connect(self._slotAttackFuzzingDataSelectCheckboxClicked)

            # ComboBoxes
            new_combobox2 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setCellWidget(n,1,new_combobox2)
            new_combobox2.addItem("Random")
            new_combobox2.addItem("Sequential")
            new_combobox2.setCurrentIndex(0)

        # Resize the Table
        dashboard.ui.tableWidget_attack_fuzzing_data_field.resizeRowsToContents()

        # Populate the ComboBox with the Associated Modulation Types
        dashboard.ui.comboBox_attack_modulation.blockSignals(True)
        dashboard.ui.comboBox_attack_modulation.clear()
        modulation_types = fissure.utils.library.getModulations(dashboard.backend.library, current_protocol)
        for n in modulation_types:
            dashboard.ui.comboBox_attack_modulation.addItem(n)
        current_modulation = str(dashboard.ui.comboBox_attack_modulation.currentText())
        dashboard.ui.comboBox_attack_modulation.blockSignals(False)
        _slotAttackModulationChanged(dashboard)

    except:
        #No packet types!
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackFuzzingSubcategory(dashboard: QtCore.QObject):
    """ 
    Updates the Data Fields table with fields and values for the selected messsage type.
    """
    # Get the Subcategory
    current_protocol_key = str(dashboard.ui.label2_attack_fuzzing_selected_protocol.text())
    current_subcategory = str(dashboard.ui.comboBox_attack_fuzzing_subcategory.currentText())
    if current_subcategory != "None":
        try:
            # Fields
            dashboard.ui.tableWidget_attack_fuzzing_data_field.clearContents()
            field_names = fissure.utils.library.getFields(dashboard.backend.library, current_protocol_key, current_subcategory)
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setRowCount(len(field_names))
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setVerticalHeaderLabels(field_names)

            # Lengths
            for n in range(0, len(field_names)):
                get_length = fissure.utils.library.getFieldData(dashboard.backend.library, current_protocol_key, current_subcategory, field_names[n])["Length"]
                length_item = QtWidgets.QTableWidgetItem(str(get_length))
                length_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_attack_fuzzing_data_field.setItem(n,7,length_item)

        except KeyError:
            #No Fields Defined!
            #~ print("No Fields Defined!")
            fields = []
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setRowCount(1)
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setVerticalHeaderLabels(['Custom'])
            get_length = 0
            length_item = QtWidgets.QTableWidgetItem("")
            length_item.setTextAlignment(QtCore.Qt.AlignCenter)
            default_length_item = QtWidgets.QTableWidgetItem(str(get_length))
            default_length_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setItem(0,6,length_item)
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setItem(0,7,default_length_item)

        # Restore ComboBoxes and CheckBoxes
        for n in range(0,dashboard.ui.tableWidget_attack_fuzzing_data_field.rowCount()):
            new_combobox1 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setCellWidget(n,4,new_combobox1)
            new_combobox1.addItem("Binary")
            new_combobox1.addItem("Hex")
            new_combobox1.setFixedSize(113,24)
            new_combobox1.setCurrentIndex(1)
            new_combobox1.currentIndexChanged.connect(lambda: _slotPacketBinaryHex(dashboard, dashboard.ui.tableWidget_attack_fuzzing_data_field))
            new_combobox1.setProperty("row", n)

            # CheckBoxes
            new_checkbox = QtWidgets.QCheckBox("",dashboard,objectName='checkBox_')
            new_checkbox.setStyleSheet("margin-left:17%")  # doesn't center, could create a layout and put the radio button in the layout
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setCellWidget(n,0,new_checkbox)
            #new_checkbox.stateChanged.connect(self._slotAttackFuzzingDataSelectCheckboxClicked)

            # ComboBoxes
            new_combobox2 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
            dashboard.ui.tableWidget_attack_fuzzing_data_field.setCellWidget(n,1,new_combobox2)
            new_combobox2.addItem("Random")
            new_combobox2.addItem("Sequential")
            new_combobox2.setFixedSize(90,24)
            new_combobox2.setCurrentIndex(0)
            new_combobox2.setProperty("row", n)

        # Calculate the Lengths
        default_length = 0
        for n in range(0,dashboard.ui.tableWidget_attack_fuzzing_data_field.rowCount()):
            default_length += int(dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,7).text())

        # Set the Length Labels
        dashboard.ui.label2_attack_fuzzing_current_length_total.setText(str(""))
        dashboard.ui.label2_attack_fuzzing_default_length_total.setText(str(default_length))

        # Resize the Table
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(0,54)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(1,113)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(2,87)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(3,87)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(4,87)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(6,75)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(7,75)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.horizontalHeader().setSectionResizeMode(5,QtWidgets.QHeaderView.Stretch)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)

        # Restore Defaults
        if dashboard.ui.comboBox_attack_fuzzing_subcategory.count() > 0:
            _slotAttackFuzzingRestoreDefaultsClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackModulationChanged(dashboard: QtCore.QObject):
    """ 
    This is called whenever the attack modulation combobox is changed. It is used to adjust label text.
    """
    try:
        # Get the Protocol and Modulation
        current_protocol = str(dashboard.ui.comboBox_attack_protocols.currentText())
        current_modulation = str(dashboard.ui.comboBox_attack_modulation.currentText())

        # Set Label Text
        dashboard.ui.label2_attack_fuzzing_selected_modulation.setText(current_modulation)

        # Modulation is Chosen
        if current_modulation != "":

            # Hide/Unhide All Attacks, Disable All Attacks
            iterator = QtWidgets.QTreeWidgetItemIterator(dashboard.ui.treeWidget_attack_attacks)
            while iterator.value():
                item = iterator.value()
                if dashboard.ui.checkBox_attack_show_all.isChecked():
                    item.setHidden(False)
                else:
                    item.setHidden(True)
                item.setDisabled(True)

                # Update Iterator
                iterator+=1

            # Enable the Selections
            get_attack_rows = fissure.utils.library.getAttacks(
                dashboard.backend.library, 
                current_protocol, 
                fissure.utils.get_library_version()
            )
            get_hardware = str(dashboard.ui.comboBox_attack_hardware.currentText())
            if ' - ' in get_hardware:
                get_hardware = str(dashboard.ui.comboBox_attack_hardware.currentText()).split(' - ')[0]

            for n in range(0, len(get_attack_rows)):
                if current_modulation == get_attack_rows[n][3]:
                    if get_hardware == get_attack_rows[n][4]:
                        tree_item_string = get_attack_rows[n][1] + " - " + get_attack_rows[n][2]
                        dashboard.logger.debug(f"Looking for tree item string: {tree_item_string}")
                        items = dashboard.ui.treeWidget_attack_attacks.findItems(
                            tree_item_string,
                            QtCore.Qt.MatchExactly | QtCore.Qt.MatchRecursive,
                            0
                        )
                        if items:
                            items[0].setDisabled(False)
                            items[0].setHidden(False)
                            enableAttackTreeParents(dashboard, tree_item_string)
                        else:
                            dashboard.logger.warning(f"Could not find tree item for: {tree_item_string}")
                        # tree_item_string = get_attack_rows[n][1] + " - " + get_attack_rows[n][2]  # protocol - attack_name
                        # dashboard.ui.treeWidget_attack_attacks.findItems(tree_item_string, QtCore.Qt.MatchExactly|QtCore.Qt.MatchRecursive,0)[0].setDisabled(False)
                        # dashboard.ui.treeWidget_attack_attacks.findItems(tree_item_string, QtCore.Qt.MatchExactly|QtCore.Qt.MatchRecursive,0)[0].setHidden(False)
                        # enableAttackTreeParents(dashboard, tree_item_string)

            # Always Enabled
            for n in ['Single-Stage', 'Multi-Stage', 'New Multi-Stage', 'Fuzzing', 'Variables']:
                try:
                    items = dashboard.ui.treeWidget_attack_attacks.findItems(
                        n,
                        QtCore.Qt.MatchExactly | QtCore.Qt.MatchRecursive,
                        0
                    )
                    if items:
                        items[0].setDisabled(False)
                        items[0].setHidden(False)
                except Exception as e:
                    dashboard.logger.warning(f"Failed to unhide/enable category '{n}': {e}")
                # try:
                #     dashboard.ui.treeWidget_attack_attacks.findItems(n,QtCore.Qt.MatchExactly|QtCore.Qt.MatchRecursive,0)[0].setDisabled(False)
                #     dashboard.ui.treeWidget_attack_attacks.findItems(n,QtCore.Qt.MatchExactly|QtCore.Qt.MatchRecursive,0)[0].setHidden(False)
                # except:
                #     pass

            # Expand the Tree Widget
            dashboard.ui.treeWidget_attack_attacks.expandAll()

            # Select the Top Item
            dashboard.ui.treeWidget_attack_attacks.setCurrentItem(dashboard.ui.treeWidget_attack_attacks.topLevelItem(0))

    except Exception as e:
        # No Attack Listed in Library
        dashboard.logger.error(f"Exception: {e}")
        dashboard.logger.error("Error parsing attacks in library. Some attacks may not be listed until fixed.")


@QtCore.pyqtSlot(QtCore.QObject)
def enableAttackTreeParents(dashboard: QtCore.QObject, attack):
    """ 
    Finds and enables the parents of an attack in the attack tree widget. Not a slot.
    """
    # Get All "attacks" Table Rows
    get_single_stage_attacks = fissure.utils.library.getSingleStageAttacks(dashboard.backend.library, None)  # add a version

    # Get Parent/Category Names
    get_parents = []
    category_names = fissure.utils.library.getAttackCategoryNames(dashboard.backend.library)
    tree_root_reached = False
    max_iterations = 10
    counter = 0
    while (tree_root_reached == False) and (counter < max_iterations):
        for n in range(0, len(get_single_stage_attacks)):
            attack_protocol = attack.split('-',1)[0].strip()
            attack_name = attack.split('-',1)[-1].strip()
            if (get_single_stage_attacks[n][1] == attack_protocol) and (get_single_stage_attacks[n][2] == attack_name):
                category = get_single_stage_attacks[n][7]  # category_name
                if category in category_names:
                    get_parents.append(category)
                    tree_root_reached = True 
                    break
                else:
                    get_parents.append(category)
                    break
        counter = counter + 1
    get_parents_unique = list(set(get_parents))

    # Enable the Parents
    for p in get_parents_unique:
        dashboard.ui.treeWidget_attack_attacks.findItems(p,QtCore.Qt.MatchExactly|QtCore.Qt.MatchRecursive,0)[0].setDisabled(False)
        dashboard.ui.treeWidget_attack_attacks.findItems(p,QtCore.Qt.MatchExactly|QtCore.Qt.MatchRecursive,0)[0].setHidden(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Updates the attack tree widget and is used to run attacks.
    """
    _slotAttackModulationChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackFuzzingRestoreDefaultsClicked(dashboard: QtCore.QObject):
    """ 
    Reloads the default values for the selected message type into the Data Fields table.
    """
    # Get the Protocol
    current_protocol = dashboard.ui.comboBox_attack_protocols.currentText()
    current_protocol_key = str(current_protocol)

    # Get the Subcategory
    current_subcategory = dashboard.ui.comboBox_attack_fuzzing_subcategory.currentText()
    current_subcategory_key = str(current_subcategory)

    # Clear the Tables
    dashboard.ui.tableWidget_attack_fuzzing_data_field.clearContents()

    # Load the Default Fields and Data
    field_names = fissure.utils.library.getFields(dashboard.backend.library,current_protocol_key,current_subcategory_key)

    for n in range(0,len(field_names)):
        # Length Items
        get_length = fissure.utils.library.getFieldData(dashboard.backend.library, current_protocol_key, current_subcategory, field_names[n])["Length"]
        length_item = QtWidgets.QTableWidgetItem(str(get_length))
        length_item.setTextAlignment(QtCore.Qt.AlignCenter)
        length_item.setFlags(QtCore.Qt.ItemIsEnabled)
        default_length_item = QtWidgets.QTableWidgetItem(str(get_length))
        default_length_item.setTextAlignment(QtCore.Qt.AlignCenter)
        default_length_item.setFlags(QtCore.Qt.ItemIsEnabled)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setItem(n,6,length_item)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setItem(n,7,default_length_item)

        # Set Binary/Hex comboboxes
        default_field_data = fissure.utils.library.getFieldData(dashboard.backend.library, current_protocol_key, current_subcategory, field_names[n])["Default Value"]
        new_combobox1 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setCellWidget(n,4,new_combobox1)
        new_combobox1.addItem("Binary")
        new_combobox1.addItem("Hex")
        new_combobox1.setFixedSize(113,24)
        new_combobox1.setCurrentIndex(0)
        new_combobox1.currentIndexChanged.connect(lambda: _slotPacketBinaryHex(dashboard, dashboard.ui.tableWidget_attack_fuzzing_data_field))
        new_combobox1.setProperty("row", n)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setItem(n,5,QtWidgets.QTableWidgetItem(str(default_field_data)))
        if get_length % 4 != 0:
            new_combobox1.setEnabled(False)
        else:
            new_combobox1.setCurrentIndex(1)

        # CheckBoxes
        new_checkbox = QtWidgets.QCheckBox("",dashboard,objectName='checkBox_')
        new_checkbox.setStyleSheet("margin-left:17%")  # doesn't center, could create a layout and put the radio button in the layout
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setCellWidget(n,0,new_checkbox)
        #new_checkbox.stateChanged.connect(self._slotAttackFuzzingDataSelectCheckboxClicked)

        # ComboBoxes
        new_combobox2 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setCellWidget(n,1,new_combobox2)
        new_combobox2.addItem("Random")
        new_combobox2.addItem("Sequential")
        new_combobox2.setFixedSize(90,24)
        new_combobox2.setCurrentIndex(0)

        # Set Min Values
        min_item = QtWidgets.QTableWidgetItem(str(0))
        min_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setItem(n,2,min_item)

        # Set Max Values
        get_max = (2**get_length)-1
        max_item = QtWidgets.QTableWidgetItem(str(get_max))
        max_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_attack_fuzzing_data_field.setItem(n,3,max_item)

    # Calculate the Lengths
    current_length = 0
    default_length = 0
    for n in range(0,dashboard.ui.tableWidget_attack_fuzzing_data_field.rowCount()):
        current_length += int(dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,6).text())
        default_length += int(dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,7).text())

    # Set the Length Labels
    dashboard.ui.label2_attack_fuzzing_current_length_total.setText(str(current_length))
    dashboard.ui.label2_attack_fuzzing_default_length_total.setText(str(default_length))

    # Resize the Table
    dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(0,54)
    dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(1,113)
    dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(2,87)
    dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(3,87)
    dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(4,87)
    dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(6,75)
    dashboard.ui.tableWidget_attack_fuzzing_data_field.setColumnWidth(7,75)
    dashboard.ui.tableWidget_attack_fuzzing_data_field.horizontalHeader().setSectionResizeMode(5,QtWidgets.QHeaderView.Stretch)
    dashboard.ui.tableWidget_attack_fuzzing_data_field.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
    dashboard.ui.tableWidget_attack_fuzzing_data_field.horizontalHeader().setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeToContents)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackFuzzingAllHexClicked(dashboard: QtCore.QObject):
    """ 
    Converts all values to hex from binary in the fuzzing controls tab.
    """
    # Change the Binary/Hex ComboBox
    for row in range(dashboard.ui.tableWidget_attack_fuzzing_data_field.rowCount()):
        if dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(row,4).isEnabled() is True:
            dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(row,4).setCurrentIndex(1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackFuzzingAllBinaryClicked(dashboard: QtCore.QObject):
    """ 
    Converts all values to binary from hex in the fuzzing controls tab.
    """
    # Change the Binary ComboBox
    for row in range(dashboard.ui.tableWidget_attack_fuzzing_data_field.rowCount()):
        dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(row,4).setCurrentIndex(0)


@QtCore.pyqtSlot(QtCore.QObject, int, int, str)
def _slotSelectFilepath(dashboard: QtCore.QObject, table_index, get_row=-1, default_directory=""):
    """ 
    Allows the user to browse for a file for any flow graph variables named "filepath."
    """
    # Default Directory
    if len(default_directory) == 0:
        default_directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs", "Attack Files")

    # Single-Stage or Multi-Stage Table
    if table_index > -1:
        get_table = dashboard.table_list[table_index]
    else:
        get_table = dashboard.ui.tableWidget1_attack_flow_graph_current_values

    # Look for a File
    fname = QtWidgets.QFileDialog.getSaveFileName(None,"Select File...", default_directory, filter="All Files (*)")[0]

    # Valid File
    if fname != "":

        # Put it Back in the Table
        if get_row >= 0:
            new_text_item = QtWidgets.QTableWidgetItem(str(fname))
            get_table.setItem(get_row,0,new_text_item)


@QtCore.pyqtSlot(QtCore.QObject, int)
def _slotGuessInterfaceTableClicked(dashboard: QtCore.QObject, table_index):
    """
    Automatically inserts a configured wireless interface name into the attack table.

    Uses the currently selected node's hardware settings instead of probing the
    Dashboard machine with iwconfig.
    """
    # Single-Stage or Multi-Stage Table
    if table_index > -1:
        get_table = dashboard.table_list[table_index]
    else:
        get_table = dashboard.ui.tableWidget1_attack_flow_graph_current_values

    # Find row with "iface"
    get_row = -1
    for row in range(get_table.rowCount()):
        header_item = get_table.verticalHeaderItem(row)

        if header_item is None:
            continue

        if header_item.text() == "iface":
            get_row = row
            break

    if get_row == -1:
        return

    interfaces = fissure.utils.selected_node_utils.get_selected_node_wifi_interfaces(
        dashboard,
    )

    if not interfaces:
        return

    current_item = get_table.item(get_row, 0)
    current_text = ""

    if current_item is not None:
        current_text = str(current_item.text()).strip()

    # Match old behavior: empty field starts at first interface.
    if not current_text:
        dashboard.guess_index_table = 0
    else:
        dashboard.guess_index_table += 1

    if dashboard.guess_index_table >= len(interfaces):
        dashboard.guess_index_table = 0

    get_interface = interfaces[dashboard.guess_index_table]

    new_text_item = QtWidgets.QTableWidgetItem(get_interface)
    get_table.setItem(get_row, 0, new_text_item)


def _slotAttackLoadFromLibraryClicked(dashboard: QtCore.QObject, checked, fname="", ftype="Flow Graph"):
    """ 
    Loads an attack flow graph from a file. Not a slot.
    """
    file_dialog_used = False
    
    if fname == "":
        # Look for the Flow Graph
        directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs")  # Default Directory
        fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select Attack Flow Graph...", directory, filter="Flow Graphs (*.py)")[0]
        dashboard.ui.label2_selected_protocol.setText("")
        dashboard.ui.label2_attack_fuzzing_selected_protocol.setText("")
        dashboard.ui.label2_selected_modulation.setText("")
        dashboard.ui.label2_selected_hardware.setText("")
        dashboard.ui.label2_attack_fuzzing_selected_modulation.setText("")
        dashboard.ui.label1_selected_attack.setText("")
        dashboard.ui.label2_attack_fuzzing_selected_attack.setText("")
        dashboard.ui.label2_selected_notes.setText("")
        dashboard.ui.label2_attack_single_stage_file_type.setText("")
        dashboard.ui.tabWidget_attack_attack.setCurrentIndex(0)
        file_dialog_used = True

        # Update the Status Dialog
        if dashboard.selected_node_uid:
            # dashboard.statusbar_text[dashboard.selected_node_uid][3] = "Loaded: " + fname.split('/')[-1]  # TODO
            dashboard.refreshStatusBarText()

    else:
        # Update the Status Dialog
        if dashboard.selected_node_uid:
            # dashboard.statusbar_text[dashboard.selected_node_uid][3] = "Loaded: " + fname  # TODO
            dashboard.refreshStatusBarText()

    # If a Valid File
    if fname != "":
        # Sensor Node Hardware Information
        get_current_hardware = str(dashboard.ui.comboBox_attack_hardware.currentText())
        get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'attack')
        
        #~ try:
        # Fuzzing (Variables)
        if dashboard.ui.treeWidget_attack_attacks.currentItem().text(0) == "Variables":

            # Look for Flow Graphs in this Directory
            if file_dialog_used == False:
                get_filename = fname
                fname = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs", fname)

            # Set Labels
            dashboard.ui.label2_attack_fuzzing_selected_flow_graph.setText(fname)

            # Read Flow Graph Variables
            temp_flow_graph_variables = {}
            f = open(fname,'r')
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setColumnCount(1)
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setRowCount(0)
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.clearContents()
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.resizeColumnsToContents()
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.horizontalHeader().setStretchLastSection(True)
            adjust_table_columns = False
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
                        variable_name = get_line.split(' = ')[0]
                        variable_name_item = QtWidgets.QTableWidgetItem(variable_name)

                        # Replace with Global Constants
                        if variable_name == "ip_address":
                            value_text = get_hardware_ip
                        elif variable_name == "serial":
                            if len(get_hardware_serial) > 0:
                                if get_hardware_type == "HackRF":
                                    value_text = get_hardware_serial
                                elif get_hardware_type == "bladeRF":
                                    value_text = get_hardware_serial
                                elif get_hardware_type == "bladeRF 2.0":
                                    value_text = get_hardware_serial
                                elif get_hardware_type == "RTL2832U":
                                    value_text = get_hardware_serial
                                else:
                                    value_text = 'serial=' + get_hardware_serial
                            else:
                                if get_hardware_type == "HackRF":
                                    value_text = ""
                                elif get_hardware_type == "bladeRF":
                                    value_text = "0"
                                elif get_hardware_type == "bladeRF 2.0":
                                    value_text = "0"
                                elif get_hardware_type == "RTL2832U":
                                    value_text = "0"
                                else:
                                    value_text = "False"
                        else:
                            value_text = get_line.split(' = ')[1].rstrip('\n')
                            value_text = value_text.replace('"','')

                        value = QtWidgets.QTableWidgetItem(value_text)

                        dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setRowCount(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()+1)
                        dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setVerticalHeaderItem(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()-1,variable_name_item)
                        dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setItem(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()-1,0,value)

                        # Store Variables and Values to a Dictionary
                        temp_flow_graph_variables[variable_name] = str(value.text())

                        # Add a Filepath Button
                        if 'filepath' in variable_name:

                            # Add a New Column
                            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.horizontalHeader().setStretchLastSection(False)
                            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setColumnCount(2)
                            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setHorizontalHeaderItem(1,QtWidgets.QTableWidgetItem(""))

                            # Create the PushButton
                            new_pushbutton = QtWidgets.QPushButton(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values,objectName='pushButton_')
                            new_pushbutton.setText("...")
                            new_pushbutton.setFixedSize(34,23)
                            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setCellWidget(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()-1,1,new_pushbutton)
                            get_row_number = dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()-1
                            get_default_directory = defaultAttackFilepathDirectory(dashboard, str(get_filename), variable_name)
                            new_pushbutton.clicked.connect((lambda get_row_number,get_default_directory: lambda: _slotAttackFuzzingSelectFilepath(dashboard, get_row = get_row_number, default_directory = get_default_directory))(get_row_number,get_default_directory))  # Pass constant value, not variable value

                            # Adjust Table
                            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setColumnWidth(0,col0_width)
                            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setColumnWidth(1,col1_width)
                            adjust_table_columns = True

            # Close the File
            f.close()

            # Adjust Table
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.resizeRowsToContents()
            if adjust_table_columns == True:
                col1_width = 35
                header_width = dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.verticalHeader().sizeHint().width()
                col0_width = dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.width() - header_width - col1_width  # .viewport.width() changes size between clicks
                dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setColumnWidth(0,col0_width)
                dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setColumnWidth(1,col1_width)

            # Copy the Flow Graph Dictionary
            dashboard.attack_flow_graph_variables = temp_flow_graph_variables

        # Fuzzing (Fields)
        elif dashboard.ui.treeWidget_attack_attacks.currentItem().text(0).split(" - ")[1] == "Fields":

            # Look for Flow Graphs in this Directory
            if file_dialog_used == False:
                get_filename = fname
                fname = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Fuzzing Flow Graphs", fname)

            # Set Labels
            dashboard.ui.label2_attack_fuzzing_selected_flow_graph.setText(fname)

            # Read Flow Graph Variables
            temp_flow_graph_variables = {}
            f = open(fname,'r')

            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setColumnCount(1)
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setRowCount(0)
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.clearContents()
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.resizeColumnsToContents()
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.horizontalHeader().setStretchLastSection(True)
            adjust_table_columns = False

            blocked_variables = ["fuzzing_type","fuzzing_seed","fuzzing_protocol","fuzzing_packet_type","fuzzing_min","fuzzing_max","fuzzing_interval","fuzzing_fields","fuzzing_data"]

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
                        variable_name = get_line.split(' = ')[0]
                        variable_name_item = QtWidgets.QTableWidgetItem(variable_name)

                        # Hide Fuzzing Variables
                        if variable_name not in blocked_variables:

                            # Replace with Global Constants
                            if variable_name == "ip_address":
                                value_text = get_hardware_ip
                            elif variable_name == "serial":
                                if len(get_hardware_serial) > 0:
                                    if get_hardware_type == "HackRF":
                                        value_text = get_hardware_serial
                                    elif get_hardware_type == "bladeRF":
                                        value_text = get_hardware_serial
                                    elif get_hardware_type == "bladeRF 2.0":
                                        value_text = get_hardware_serial
                                    elif get_hardware_type == "RTL2832U":
                                        value_text = get_hardware_serial
                                    else:
                                        value_text = 'serial=' + get_hardware_serial
                                else:
                                    if get_hardware_type == "HackRF":
                                        value_text = ""
                                    elif get_hardware_type == "bladeRF":
                                        value_text = "0"
                                    elif get_hardware_type == "bladeRF 2.0":
                                        value_text = "0"
                                    elif get_hardware_type == "RTL2832U":
                                        value_text = "0"
                                    else:
                                        value_text = "False"
                            else:
                                value_text = get_line.split(' = ')[1].rstrip('\n')
                                value_text = value_text.replace('"','')

                            value = QtWidgets.QTableWidgetItem(value_text)

                            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setRowCount(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()+1)
                            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setVerticalHeaderItem(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()-1,variable_name_item)
                            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setItem(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()-1,0,value)

                            # Store Variables and Values to a Dictionary
                            temp_flow_graph_variables[variable_name] = str(value.text())

                            # Add a Filepath Button
                            if 'filepath' in variable_name:
                                # Add a New Column
                                dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.horizontalHeader().setStretchLastSection(False)
                                dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setColumnCount(2)
                                dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setHorizontalHeaderItem(1,QtWidgets.QTableWidgetItem(""))

                                # Create the PushButton
                                new_pushbutton = QtWidgets.QPushButton(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values,objectName='pushButton_')
                                new_pushbutton.setText("...")
                                new_pushbutton.setFixedSize(34,23)
                                dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setCellWidget(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()-1,1,new_pushbutton)
                                get_row_number = dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()-1
                                get_default_directory = defaultAttackFilepathDirectory(dashboard, str(get_filename), variable_name)
                                new_pushbutton.clicked.connect((lambda get_row_number,get_default_directory: lambda: _slotAttackFuzzingSelectFilepath(dashboard, get_row = get_row_number, default_directory = get_default_directory))(get_row_number,get_default_directory))  # Pass constant value, not variable value

                                # Adjust Table Flag for Filepaths
                                adjust_table_columns = True

            # Close the File
            f.close()

            # Adjust Table
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.resizeRowsToContents()
            if adjust_table_columns == True:
                col1_width = 35
                header_width = dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.verticalHeader().sizeHint().width()
                col0_width = dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.width() - header_width - col1_width  # .viewport.width() changes size between clicks
                dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setColumnWidth(0,col0_width)
                dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setColumnWidth(1,col1_width)

            # Copy the Flow Graph Dictionary
            dashboard.attack_flow_graph_variables = temp_flow_graph_variables

            # Enable the PushButton
            dashboard.ui.pushButton_attack_fuzzing_start.setEnabled(True)

        # Single-Stage
        else:
            # Look for Flow Graphs in this Directory
            if file_dialog_used == False:
                flow_graph_directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs")
                get_file = fname
                fname = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs", fname)

            # Set Labels
            dashboard.ui.label2_selected_flow_graph.setText(fname)
            dashboard.ui.label2_selected_notes.setText("")

            # Clear Table
            f = open(fname,'r')
            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setColumnCount(1)
            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setRowCount(0)
            dashboard.ui.tableWidget1_attack_flow_graph_current_values.clearContents()
            dashboard.ui.tableWidget1_attack_flow_graph_current_values.resizeColumnsToContents()
            dashboard.ui.tableWidget1_attack_flow_graph_current_values.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget1_attack_flow_graph_current_values.horizontalHeader().setStretchLastSection(True)

            # Enable the Table
            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setEnabled(True)

            # Flow Graph
            if ftype == "Flow Graph":                    
                # Run with sudo Checkbox
                dashboard.ui.checkBox_attack_single_stage_sudo.setChecked(False)
                dashboard.ui.checkBox_attack_single_stage_sudo.setEnabled(False)
                
                # Read Flow Graph Variables
                temp_flow_graph_variables = {}
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
                            # Get Default Variable Name and Value
                            variable_name = get_line.split(' = ')[0]
                            variable_name_item = QtWidgets.QTableWidgetItem(variable_name)
                            value_text = get_line.split(' = ')[1].rstrip('\n')
                            value_text = value_text.replace('"','')

                            # Ignore Notes in the Table
                            if str(variable_name_item.text()).lower() == 'notes':
                                dashboard.ui.label2_selected_notes.setText(value_text)
                                
                            # Replace with Global Constants
                            else:
                                if variable_name == "ip_address":
                                    value_text = get_hardware_ip
                                elif variable_name == "serial":
                                    if len(get_hardware_serial) > 0:
                                        if get_hardware_type == "HackRF":
                                            value_text = get_hardware_serial
                                        elif get_hardware_type == "bladeRF":
                                            value_text = get_hardware_serial
                                        elif get_hardware_type == "bladeRF 2.0":
                                            value_text = get_hardware_serial
                                        elif get_hardware_type == "RTL2832U":
                                            value_text = get_hardware_serial
                                        else:
                                            value_text = 'serial=' + get_hardware_serial
                                    else:
                                        if get_hardware_type == "HackRF":
                                            value_text = ""
                                        elif get_hardware_type == "bladeRF":
                                            value_text = "0"
                                        elif get_hardware_type == "bladeRF 2.0":
                                            value_text = "0"
                                        elif get_hardware_type == "RTL2832U":
                                            value_text = "0"
                                        else:
                                            value_text = "False"

                                # Fill in the "Current Values" Table
                                value = QtWidgets.QTableWidgetItem(value_text)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setRowCount(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()+1)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setVerticalHeaderItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,variable_name_item)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,0,value)

                                # Store Variables and Values to a Dictionary
                                temp_flow_graph_variables[str(variable_name_item.text())] = str(value.text())

                                # Add a Filepath Button
                                if 'filepath' in variable_name:
                                    # Add a New Column
                                    dashboard.ui.tableWidget1_attack_flow_graph_current_values.horizontalHeader().setStretchLastSection(False)
                                    dashboard.ui.tableWidget1_attack_flow_graph_current_values.setColumnCount(2)
                                    dashboard.ui.tableWidget1_attack_flow_graph_current_values.setHorizontalHeaderItem(1,QtWidgets.QTableWidgetItem(""))

                                    # Create the PushButton
                                    new_pushbutton = QtWidgets.QPushButton(dashboard.ui.tableWidget1_attack_flow_graph_current_values,objectName='pushButton_')
                                    new_pushbutton.setText("...")
                                    new_pushbutton.setFixedSize(34,23)
                                    dashboard.ui.tableWidget1_attack_flow_graph_current_values.setCellWidget(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,1,new_pushbutton)
                                    get_row_number = dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1
                                    get_default_directory = defaultAttackFilepathDirectory(dashboard, str(dashboard.ui.label2_selected_flow_graph.text()).rsplit('/')[-1],variable_name)
                                    new_pushbutton.clicked.connect((lambda get_row_number,get_default_directory: lambda: _slotSelectFilepath(dashboard, -1, get_row = get_row_number, default_directory = get_default_directory))(get_row_number,get_default_directory))  # Pass constant value, not variable value

                                    # Adjust Table
                                    dashboard.ui.tableWidget1_attack_flow_graph_current_values.setColumnWidth(1,35)
                                    dashboard.ui.tableWidget1_attack_flow_graph_current_values.horizontalHeader().setSectionResizeMode(0,QtWidgets.QHeaderView.Stretch)
                                    
                                    # Modify Filepath for FISSURE Location
                                    filepath_value = value_text
                                    if "/FISSURE/" in value_text:
                                        new_filepath = os.path.join(fissure.utils.FISSURE_ROOT, filepath_value.split('/FISSURE/',1)[-1])
                                        filepath_value = new_filepath
                                        dashboard.ui.tableWidget1_attack_flow_graph_current_values.setItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,0,QtWidgets.QTableWidgetItem(new_filepath))

                                    # Modify Filepath for Flow Graph Library Location
                                    if "/Flow Graph Library/" in filepath_value:
                                        if ("/Flow Graph Library/maint-3.8/" not in filepath_value) and ("/Flow Graph Library/maint-3.10/" not in filepath_value):
                                            new_filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), filepath_value.split('/Flow Graph Library/',1)[-1])
                                            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,0,QtWidgets.QTableWidgetItem(new_filepath))

            # Flow Graph - GUI
            elif ftype == "Flow Graph - GUI": 
                    
                # Run with sudo Checkbox
                dashboard.ui.checkBox_attack_single_stage_sudo.setChecked(False)
                dashboard.ui.checkBox_attack_single_stage_sudo.setEnabled(False)
                
                # Return Parameter Block Text
                f = open(fname,'r')
                
                # Read Notes
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
                            # Get Default Variable Name and Value
                            variable_name = get_line.split(' = ')[0]
                            variable_name_item = QtWidgets.QTableWidgetItem(variable_name)
                            value_text = get_line.split(' = ')[1].rstrip('\n')
                            value_text = value_text.replace('"','')

                            # Ignore Notes in the Table
                            if str(variable_name_item.text()).lower() == 'notes':
                                dashboard.ui.label2_selected_notes.setText(value_text)
                
                # Return Parameter Block Text
                temp_flow_graph_variables = {}
                parsing = False
                f.seek(0)
                for line in f:
                    if line.startswith("    def __init__(self,"):
                        parsing = True
                    elif line.startswith("        gr.top_block."):
                        parsing = False
                    if parsing:
                        # Strip Extra Text
                        fg_parameters = line[:-3].split(',')
                        parameter_names = []
                        parameter_values = []
                        for p in range(1,len(fg_parameters)):
                            # Get Default Variable Name and Value
                            parameter_name = fg_parameters[p].lstrip(' ').split('=')[0].replace('_','-')
                            parameter_name_item = QtWidgets.QTableWidgetItem(parameter_name)

                            # Replace with Global Constants
                            if parameter_name == "ip-address":
                                parameter_value = get_hardware_ip
                            elif parameter_name == "serial":
                                if len(get_hardware_serial) > 0:
                                    if get_hardware_type == "HackRF":
                                        parameter_value = get_hardware_serial
                                    elif get_hardware_type == "bladeRF":
                                        parameter_value = get_hardware_serial
                                    elif get_hardware_type == "bladeRF 2.0":
                                        parameter_value = get_hardware_serial
                                    elif get_hardware_type == "RTL2832U":
                                        parameter_value = get_hardware_serial
                                    else:
                                        parameter_value = 'serial=' + get_hardware_serial
                                else:
                                    if get_hardware_type == "HackRF":
                                        parameter_value = ""
                                    elif get_hardware_type == "bladeRF":
                                        parameter_value = "0"
                                    elif get_hardware_type == "bladeRF 2.0":
                                        parameter_value = "0"
                                    elif get_hardware_type == "RTL2832U":
                                        parameter_value = "0"
                                    else:
                                        parameter_value = "False"
                            else:
                                parameter_value = fg_parameters[p].lstrip(' ').split('=')[1].replace('"','')

                            # Fill in the "Current Values" Table
                            value = QtWidgets.QTableWidgetItem(parameter_value)
                            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setRowCount(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()+1)
                            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setVerticalHeaderItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,parameter_name_item)
                            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,0,value)

                            # Store Variables and Values to a Dictionary
                            temp_flow_graph_variables[str(parameter_name_item.text())] = str(value.text())

                            # Add a Filepath Button
                            if 'filepath' in parameter_name:
                                # Add a New Column
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.horizontalHeader().setStretchLastSection(False)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setColumnCount(2)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setHorizontalHeaderItem(1,QtWidgets.QTableWidgetItem(""))

                                # Create the PushButton
                                new_pushbutton = QtWidgets.QPushButton(dashboard.ui.tableWidget1_attack_flow_graph_current_values,objectName='pushButton_')
                                new_pushbutton.setText("...")
                                new_pushbutton.setFixedSize(34,23)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setCellWidget(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,1,new_pushbutton)
                                get_row_number = dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1
                                get_default_directory = defaultAttackFilepathDirectory(dashboard, str(dashboard.ui.label2_selected_flow_graph.text()).rsplit('/')[-1],parameter_name)
                                new_pushbutton.clicked.connect((lambda get_row_number,get_default_directory: lambda: _slotSelectFilepath(dashboard, -1, get_row = get_row_number, default_directory = get_default_directory))(get_row_number,get_default_directory))  # Pass constant value, not variable value

                                # Adjust Table
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setColumnWidth(1,35)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.horizontalHeader().setSectionResizeMode(0,QtWidgets.QHeaderView.Stretch)
                                
                                # Modify Filepath for FISSURE Location
                                filepath_value = parameter_value
                                if "/FISSURE/" in filepath_value:
                                    new_filepath = os.path.join(fissure.utils.FISSURE_ROOT, filepath_value.split('/FISSURE/',1)[-1])
                                    filepath_value = new_filepath
                                    dashboard.ui.tableWidget1_attack_flow_graph_current_values.setItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,0,QtWidgets.QTableWidgetItem(new_filepath))
                                
                                # Modify Filepath for Flow Graph Library Location
                                if "/Flow Graph Library/" in filepath_value:
                                    if ("/Flow Graph Library/maint-3.8/" not in filepath_value) and ("/Flow Graph Library/maint-3.10/" not in filepath_value):
                                        new_filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), filepath_value.split('/Flow Graph Library/',1)[-1])
                                        dashboard.ui.tableWidget1_attack_flow_graph_current_values.setItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,0,QtWidgets.QTableWidgetItem(new_filepath))

                # Close the File
                f.close()

            # Python Script
            else:
                # Run with sudo Checkbox
                dashboard.ui.checkBox_attack_single_stage_sudo.setChecked(False)
                dashboard.ui.checkBox_attack_single_stage_sudo.setEnabled(True)                    
                
                # Get Python2/Python3 Variables
                if ftype == "Python3 Script":
                    proc=subprocess.Popen("python3 python_importer.py " + get_file.replace('.py',''), shell=True, stdout=subprocess.PIPE, cwd=flow_graph_directory)
                else:
                    proc=subprocess.Popen("python2 python_importer.py " + get_file.replace('.py',''), shell=True, stdout=subprocess.PIPE, cwd=flow_graph_directory)
                output=ast.literal_eval(proc.communicate()[0].decode())
                get_vars = output[0]
                get_vals = output[1]

                # get_module = __import__(get_file.replace('.py',''))  # Faster, but only works for the same Python version as Dashboard.py
                # get_args = get_module.getArguments()
                # get_vars = get_args[0]
                # get_vals = get_args[1]

                temp_flow_graph_variables = {}
                for n in range(0,len(get_vars)):
                    # Ignore Notes in the Table
                    if str(get_vars[n]).lower() == 'notes':
                        dashboard.ui.label2_selected_notes.setText(str(get_vals[n]))
                        
                    # Check if sudo is Required
                    elif str(get_vars[n]).lower() == 'run_with_sudo':
                        if str(get_vals[n]).lower() == 'true':
                            dashboard.ui.checkBox_attack_single_stage_sudo.setChecked(True)
                        else:
                            dashboard.ui.checkBox_attack_single_stage_sudo.setChecked(False)                                

                    # Replace with Global Constants
                    else:
                        if get_vars[n] == "iface":
                            get_vals[n] = get_hardware_interface
                        elif get_vars[n] == "serial":
                            if len(get_hardware_serial) > 0:
                                if get_hardware_type == "HackRF":
                                    get_vals[n] = get_hardware_serial
                                elif get_hardware_type == "bladeRF":
                                    get_vals[n] = get_hardware_serial
                                elif get_hardware_type == "bladeRF 2.0":
                                    get_vals[n] = get_hardware_serial
                                elif get_hardware_type == "RTL2832U":
                                    get_vals[n] = get_hardware_serial
                                else:
                                    get_vals[n] = 'serial=' + get_hardware_serial
                            else:
                                if get_hardware_type == "HackRF":
                                    get_vals[n] = ""
                                elif get_hardware_type == "bladeRF":
                                    get_vals[n] = "0"
                                elif get_hardware_type == "bladeRF 2.0":
                                    get_vals[n] = "0"
                                elif get_hardware_type == "RTL2832U":
                                    get_vals[n] = "0"
                                else:
                                    get_vals[n] = "False" 

                        # Fill in the "Current Values" Table
                        variable_name = QtWidgets.QTableWidgetItem(get_vars[n])
                        value = QtWidgets.QTableWidgetItem(str(get_vals[n]))
                        dashboard.ui.tableWidget1_attack_flow_graph_current_values.setRowCount(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()+1)
                        dashboard.ui.tableWidget1_attack_flow_graph_current_values.setVerticalHeaderItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,variable_name)
                        dashboard.ui.tableWidget1_attack_flow_graph_current_values.setItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,0,value)

                        # Store Variables and Values to a Dictionary
                        temp_flow_graph_variables[str(variable_name.text())] = str(value.text())

                        # Add a Filepath Button
                        if 'filepath' in str(variable_name.text()):
                            # Add a New Column
                            if dashboard.ui.tableWidget1_attack_flow_graph_current_values.columnCount() == 1:
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.horizontalHeader().setStretchLastSection(False)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setColumnCount(2)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setHorizontalHeaderItem(1,QtWidgets.QTableWidgetItem(""))

                            # Create the PushButton
                            new_pushbutton = QtWidgets.QPushButton(dashboard.ui.tableWidget1_attack_flow_graph_current_values,objectName='pushButton_')
                            new_pushbutton.setText("...")
                            if 'iface' in get_vars:
                                new_pushbutton.setFixedSize(64,23)
                            else:
                                new_pushbutton.setFixedSize(34,23)
                            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setCellWidget(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,1,new_pushbutton)
                            get_row_number = dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1
                            get_default_directory = defaultAttackFilepathDirectory(dashboard, str(dashboard.ui.label2_selected_flow_graph.text()).rsplit('/')[-1],str(variable_name.text()))
                            new_pushbutton.clicked.connect((lambda get_row_number,get_default_directory: lambda: _slotSelectFilepath(dashboard, -1, get_row = get_row_number, default_directory = get_default_directory))(get_row_number,get_default_directory))  # Pass constant value, not variable value

                            # Adjust Table
                            if dashboard.ui.tableWidget1_attack_flow_graph_current_values.columnWidth(1) > 65:  # check for iface/guess column width
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setColumnWidth(1,35)
                            dashboard.ui.tableWidget1_attack_flow_graph_current_values.horizontalHeader().setSectionResizeMode(0,QtWidgets.QHeaderView.Stretch)
                            
                            # Modify Filepath for FISSURE Location
                            filepath_value = str(value.text())
                            if "/FISSURE/" in filepath_value:
                                new_filepath = os.path.join(fissure.utils.FISSURE_ROOT, filepath_value.split('/FISSURE/',1)[-1])
                                filepath_value = new_filepath
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,0,QtWidgets.QTableWidgetItem(new_filepath))

                            # Modify Filepath for Flow Graph Library Location
                            if "/Flow Graph Library/" in filepath_value:
                                if ("/Flow Graph Library/maint-3.8/" not in filepath_value) and ("/Flow Graph Library/maint-3.10/" not in filepath_value):
                                    new_filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), filepath_value.split('/Flow Graph Library/',1)[-1])
                                    dashboard.ui.tableWidget1_attack_flow_graph_current_values.setItem(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,0,QtWidgets.QTableWidgetItem(new_filepath))

                        # Add a Guess Interface Button
                        if str(variable_name.text()) == 'iface':
                            # Add a New Column
                            if dashboard.ui.tableWidget1_attack_flow_graph_current_values.columnCount() == 1:
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.horizontalHeader().setStretchLastSection(False)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setColumnCount(2)
                                dashboard.ui.tableWidget1_attack_flow_graph_current_values.setHorizontalHeaderItem(1,QtWidgets.QTableWidgetItem(""))

                            # Create the PushButton
                            new_pushbutton = QtWidgets.QPushButton(dashboard.ui.tableWidget1_attack_flow_graph_current_values,objectName='pushButton_')
                            new_pushbutton.setText("Guess")
                            new_pushbutton.setFixedSize(64,23)
                            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setCellWidget(dashboard.ui.tableWidget1_attack_flow_graph_current_values.rowCount()-1,1,new_pushbutton)
                            new_pushbutton.clicked.connect(lambda: _slotGuessInterfaceTableClicked(dashboard, -1))

                            # Adjust Table
                            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setColumnWidth(1,65)
                            dashboard.ui.tableWidget1_attack_flow_graph_current_values.horizontalHeader().setSectionResizeMode(0,QtWidgets.QHeaderView.Stretch)

            # Close the File
            f.close()

            # Adjust Table
            dashboard.ui.tableWidget1_attack_flow_graph_current_values.resizeRowsToContents()

            # Copy the Flow Graph Dictionary
            dashboard.attack_flow_graph_variables = temp_flow_graph_variables

            # Enable/Disable the Push Buttons
            dashboard.ui.pushButton_attack_start_stop.setEnabled(True)
            dashboard.ui.pushButton_attack_view_flow_graph.setEnabled(True)
            dashboard.ui.pushButton_attack_apply_changes.setEnabled(False)
            dashboard.ui.pushButton_attack_restore_defaults.setEnabled(False)

            # Update Flow Graph Status Label
            dashboard.ui.label2_attack_flow_graph_status.setText("Stopped")

        #~ except:
            #~ pass
            #~ fissure.Dashboard.UI_Components.Qt5.errorMessage()


def defaultAttackFilepathDirectory(dashboard: QtCore.QObject, attack_name="", variable_name=""):
    """ Returns the default directory for when the filepath button is pressed for an attack. Not a slot
    """
    # Get the Desired Filepath
    get_directory = ""
    if attack_name == "DSRC_wifi_tx_generator.py":
        if variable_name == "coordinate_filepath":
            get_directory = os.path.join(fissure.utils.TOOLS_DIR, "v2verifier-master", "coords")
        elif variable_name == "key_filepath":
            get_directory = os.path.join(fissure.utils.TOOLS_DIR, "v2verifier-master", "keys")
    elif attack_name == "DSRC_Default_From_File.py":
        get_directory = os.path.join(fissure.utils.FISSURE_ROOT, "Crafted Packets")
    elif attack_name == "FM_Radio_FM_From_File.py":
        get_directory = os.path.join(fissure.utils.FISSURE_ROOT, "Crafted Packets", "Attack Recordings")
    elif attack_name == "hd_string_injection.py":
        if variable_name == "json_filepath":
            get_directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs", "Attack Files", "Naughty Strings")
        elif (variable_name == "wav1_filepath") or (variable_name == "wav2_filepath"):
            get_directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs", "Attack Files")
    return get_directory


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackFuzzingSelectFilepath(dashboard: QtCore.QObject, get_row=-1, default_directory=""):
    """ 
    Allows the user to browse for a file for any flow graph variables named "filepath." This is directed towards the Fuzzing-Variables Current Values table.
    """
    # Default Directory
    if len(default_directory) == 0:
        default_directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs", "Attack Files")

    # Look for a File
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select File...", default_directory, filter="All Files (*)")[0]

    # Valid File
    if fname != "":
        # Put it Back in the Table
        if get_row >= 0:
            new_text_item = QtWidgets.QTableWidgetItem(str(fname))
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setItem(get_row,0,new_text_item)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackFuzzingSelectFileClicked(dashboard: QtCore.QObject):
    """ 
    Loads a flow graph for fuzzing its variables.
    """
    # Get the Current Protocol and Modulation
    get_protocol = dashboard.ui.comboBox_attack_protocols.currentText()
    get_modulation = dashboard.ui.comboBox_attack_modulation.currentText()

    # Look for a Flow Graph
    directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs")  # Default Directory
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select Flow Graph...", directory, filter="Flow Graphs (" + get_protocol.replace(" ","_") + "_" + get_modulation.replace(" ","_")  + "*.py);;All Files (*.*)")[0]

    # If a Valid File
    if fname != "":
        # Set the File Edit Box
        dashboard.ui.textEdit_fuzzing_from_file.setText(fname)

        # Enable the Pushbutton
        dashboard.ui.pushButton_attack_fuzzing_start.setEnabled(True)

        # Load the File
        _slotAttackLoadFromLibraryClicked(dashboard, None, fname.split('/')[-1])

        # Update the Variables Table
        if dashboard.ui.stackedWidget_fuzzing.currentIndex() == 1:
            # Clear the Table
            for rows in reversed(range(0,dashboard.ui.tableWidget_fuzzing_variables.rowCount())):
                dashboard.ui.tableWidget_fuzzing_variables.removeRow(rows)

            # Insert the Data
            # Read Flow Graph Variables
            radio_button_group=QtWidgets.QButtonGroup(dashboard)
            temp_flow_graph_variables = {}
            f = open(fname,'r')
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

                    # Default Values in the Variables Table
                    if get_line != "":
                        variable_name = QtWidgets.QTableWidgetItem(get_line.split(' = ')[0])
                        value_text = get_line.split(' = ')[1].rstrip('\n')
                        value_text = value_text.replace('"','')
                        value = QtWidgets.QTableWidgetItem(value_text)
                        value.setFlags(value.flags() & ~QtCore.Qt.ItemIsEditable)
                        value.setTextAlignment(QtCore.Qt.AlignCenter)
                        dashboard.ui.tableWidget_fuzzing_variables.setRowCount(dashboard.ui.tableWidget_fuzzing_variables.rowCount()+1)

                        # Add Buttons/ComboBoxes if Value is a Float
                        if fissure.utils.isFloat(value_text):

                            # Select Radiobuttons
                            new_button = QtWidgets.QRadioButton("", dashboard)
                            new_button.setStyleSheet("margin-left:15%")  # doesn't center, could create a layout and put the radio button in the layout
                            dashboard.ui.tableWidget_fuzzing_variables.setCellWidget(dashboard.ui.tableWidget_fuzzing_variables.rowCount()-1,0,new_button)
                            radio_button_group.addButton(new_button)

                            # Type Comboboxes
                            new_fuzzing_combobox = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
                            dashboard.ui.tableWidget_fuzzing_variables.setCellWidget(dashboard.ui.tableWidget_fuzzing_variables.rowCount()-1,1,new_fuzzing_combobox)
                            new_fuzzing_combobox.addItem("Random")
                            new_fuzzing_combobox.addItem("Sequential")
                            new_fuzzing_combobox.setCurrentIndex(0)

                        # Disable the Row
                        else:
                            # Disable Editing
                            for col in range(0,dashboard.ui.tableWidget_fuzzing_variables.columnCount()):
                                blank_item = QtWidgets.QTableWidgetItem("")
                                blank_item.setFlags(blank_item.flags() & ~QtCore.Qt.ItemIsEnabled)
                                dashboard.ui.tableWidget_fuzzing_variables.setItem(dashboard.ui.tableWidget_fuzzing_variables.rowCount()-1,col,blank_item)

                            #~ value.setFlags(value.flags() & ~QtCore.Qt.ItemIsEnabled)
                            #~ variable_name.setFlags(variable_name.flags() & ~QtCore.Qt.ItemIsEditable)

                        # Add the Items
                        dashboard.ui.tableWidget_fuzzing_variables.setItem(dashboard.ui.tableWidget_fuzzing_variables.rowCount()-1,5,value)
                        dashboard.ui.tableWidget_fuzzing_variables.setVerticalHeaderItem(dashboard.ui.tableWidget_fuzzing_variables.rowCount()-1,variable_name)

            # Close the File
            f.close()

            # Adjust Table
            dashboard.ui.tableWidget_fuzzing_variables.resizeRowsToContents()
            dashboard.ui.tableWidget_fuzzing_variables.resizeColumnsToContents()
            dashboard.ui.tableWidget_fuzzing_variables.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_fuzzing_variables.horizontalHeader().setStretchLastSection(True)


@qasync.asyncSlot(QtCore.QObject)
async def _slotAttackFuzzingStartClicked(dashboard: QtCore.QObject):
    """ 
    Signals to HIPRFISR/Sensor Node to load fuzzer flow graph
    """
    # Check for Active Sensor Node
    if not dashboard.selected_node_uid:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Launch and select a sensor node prior to running attacks.")
        return

    #~ try:
    # Data Field Table
    if dashboard.ui.stackedWidget_fuzzing.currentIndex() == 0:
        # Convert Every Field to Binary, Assemble
        get_bin = ""
        fuzzing_fields = []
        fuzzing_type = []
        fuzzing_min = []
        fuzzing_max = []
        hex_str = ""
        for n in range(0,dashboard.ui.tableWidget_attack_fuzzing_data_field.rowCount()):
            # Binary or Hex
            current_selection = dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(n,4).currentText()

            # Contains Data
            if dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,5).text() != "":
                # Get the Data
                get_data = str(dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,5).text())

                if current_selection == "Binary":
                    bin_str = get_data.replace(' ', '')

                # Hex to Binary
                elif current_selection == "Hex":
                    hex_len = len(get_data)
                    bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))

                get_bin = get_bin + bin_str

            # Get Checked Fields
            if dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(n,0).isChecked() == True:
                fuzzing_fields.append(str(dashboard.ui.tableWidget_attack_fuzzing_data_field.verticalHeaderItem(n).text()))

                # Get Fuzzing Type
                fuzzing_type.append(str(dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(n,1).currentText()))

                # Get Fuzzing Min
                if dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,2) == None:
                    fuzzing_min.append("")
                else:
                    fuzzing_min.append(str(dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,2).text()))

                # Get Fuzzing Max
                if dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,3) == None:
                    fuzzing_max.append("")
                else:
                    fuzzing_max.append(str(dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,3).text()))

        # Convert to Hex
        if get_bin != "":
            hex_str = '%0*X' % ((len(get_bin) + 3) // 4, int(get_bin, 2))

    # Send Stop Message to the HIPRFISR (Flow Graph Currently Running: Stopping)
    if dashboard.ui.pushButton_attack_fuzzing_start.text() == "Stop Attack":

        # Stop Physical/Variable Fuzzing
        if dashboard.ui.stackedWidget_fuzzing.currentIndex() == 1:
            await dashboard.backend.physicalFuzzingStop(dashboard.selected_node_uid)  # Causes normal fuzzing to not stop if ran before attackFlowGraphStop

        # Stop Attack Flow Graph
        await dashboard.backend.attackFlowGraphStop(dashboard.selected_node_uid, '')

        # Toggle the Text
        dashboard.ui.pushButton_attack_fuzzing_start.setText("Start Attack")

        # Disable Apply Button
        dashboard.ui.pushButton_attack_fuzzing_apply_changes.setEnabled(False)

        # Update Flow Graph Status Label
        dashboard.ui.label2_attack_fuzzing_flow_graph_status.setText("Not Running")

        # Enabled All Values for Editing
        for get_row in range(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()):
            get_value_item = dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.takeItem(get_row,0)
            get_value_item.setFlags(get_value_item.flags() | QtCore.Qt.ItemIsEditable)
            get_value_item.setFlags(get_value_item.flags() | QtCore.Qt.ItemIsEnabled)
            dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setItem(get_row,0,get_value_item)

    # Start Flow Graph/Fuzzing
    elif dashboard.ui.pushButton_attack_fuzzing_start.text() == "Start Attack":

        # Initialize
        physical_fuzzing_enabled = False

        # Get each Variable Name and Value
        variable_names = []
        variable_values = []
        for get_row in range(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()):
            # Save the Variable Name and Value in the Row to a Dictionary
            get_name = str(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.verticalHeaderItem(get_row).text())
            fuzzing_blocks = [
                "fuzzing_fields",
                "fuzzing_type",
                "fuzzing_min",
                "fuzzing_max",
                "fuzzing_data",
                "fuzzing_seed",
                "fuzzing_interval",
                "fuzzing_protocol",
                "fuzzing_packet_type",
                "packet_types_fields"
            ]
            if not any(get_name in x for x in fuzzing_blocks):
                variable_names.append(get_name)
                variable_values.append(str(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.item(get_row,0).text()))

        # Disable Values with Names Matching those Listed in "fissure_config.yaml"
        for get_row in range(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()):
            get_name = str(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.verticalHeaderItem(get_row).text())
            if get_name in dashboard.backend.settings['disabled_running_flow_graph_variables']:
                get_value_item = dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.takeItem(get_row,0)
                get_value_item.setFlags(get_value_item.flags() & ~QtCore.Qt.ItemIsEnabled)
                dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setItem(get_row,0,get_value_item)

        # Fields - Insert Fuzzing Information
        if dashboard.ui.stackedWidget_fuzzing.currentIndex() == 0:
            variable_names.append("fuzzing_fields")
            variable_names.append("fuzzing_type")
            variable_names.append("fuzzing_min")
            variable_names.append("fuzzing_max")
            variable_names.append("fuzzing_data")
            variable_names.append("fuzzing_seed")
            variable_names.append("fuzzing_interval")
            variable_names.append("fuzzing_protocol")
            variable_names.append("fuzzing_packet_type")
            variable_names.append("packet_types_fields")
            variable_values.append(str(fuzzing_fields))
            variable_values.append(str(fuzzing_type))
            variable_values.append(str(fuzzing_min))
            variable_values.append(str(fuzzing_max))
            variable_values.append(hex_str)
            variable_values.append(str(dashboard.ui.textEdit_attack_fuzzing_seed.toPlainText()))
            variable_values.append(str(dashboard.ui.textEdit_attack_fuzzing_interval.toPlainText()))
            variable_values.append(str(dashboard.ui.label2_attack_fuzzing_selected_protocol.text()))
            variable_values.append(str(dashboard.ui.comboBox_attack_fuzzing_subcategory.currentText()))

            get_protocol = str(dashboard.ui.comboBox_attack_protocols.currentText())
            get_subcategory = str(dashboard.ui.comboBox_attack_fuzzing_subcategory.currentText())
            get_fields = fissure.utils.library.getFieldDataAll(dashboard.backend.library, get_protocol, get_subcategory)
            variable_values.append(str(get_fields))

        # Variables
        elif dashboard.ui.stackedWidget_fuzzing.currentIndex() == 1:

            # Look for Variable Fuzzing Radiobuttons
            for rows in range(0,dashboard.ui.tableWidget_fuzzing_variables.rowCount()):
                if dashboard.ui.tableWidget_fuzzing_variables.cellWidget(rows,0):  # Has a Cell Widget
                    if dashboard.ui.tableWidget_fuzzing_variables.cellWidget(rows,0).isChecked():
                        physical_fuzzing_enabled = True
                        break

            # Start Variable Fuzzing
            if physical_fuzzing_enabled == True:

                # Get Physical Layer Fuzzing Parameters
                fuzzing_variables = []
                fuzzing_type = []
                fuzzing_min = []
                fuzzing_max = []
                fuzzing_seed_step = []
                for rows in range(0,dashboard.ui.tableWidget_fuzzing_variables.rowCount()):
                    if dashboard.ui.tableWidget_fuzzing_variables.cellWidget(rows,0):  # Has a Cell Widget
                        if dashboard.ui.tableWidget_fuzzing_variables.cellWidget(rows,0).isChecked():
                            # Get Fuzzing Variable Name
                            fuzzing_variables.append(str(dashboard.ui.tableWidget_fuzzing_variables.verticalHeaderItem(rows).text()))

                            # Get Fuzzing Type
                            fuzzing_type.append(str(dashboard.ui.tableWidget_fuzzing_variables.cellWidget(rows,1).currentText()))

                            # Get Fuzzing Min
                            if dashboard.ui.tableWidget_fuzzing_variables.item(rows,3) == None:
                                fuzzing_min.append("")
                            else:
                                fuzzing_min.append(str(dashboard.ui.tableWidget_fuzzing_variables.item(rows,3).text()))

                            # Get Fuzzing Max
                            if dashboard.ui.tableWidget_fuzzing_variables.item(rows,4) == None:
                                fuzzing_max.append("")
                            else:
                                fuzzing_max.append(str(dashboard.ui.tableWidget_fuzzing_variables.item(rows,4).text()))

                            # Get Fuzzing Seed/Step
                            if dashboard.ui.tableWidget_fuzzing_variables.item(rows,2) == None:
                                fuzzing_seed_step.append("0")
                            else:
                                fuzzing_seed_step.append(str(dashboard.ui.tableWidget_fuzzing_variables.item(rows,2).text()))

                # Add Update Period
                fuzzing_update_period = str(dashboard.ui.textEdit_fuzzing_update_period.toPlainText())

                # Min/Max Error Checking
                for n in range(0,len(fuzzing_min)):
                    if (fuzzing_min[n] == "" or fuzzing_max[n] == ""):
                        fissure.Dashboard.UI_Components.Qt5.errorMessage("Error in Physical Layer Fuzzing: Min./Max. Value Missing.")
                        raise ValueError

                    else:
                        if float(fuzzing_min[n]) > float(fuzzing_max[n]):
                            fissure.Dashboard.UI_Components.Qt5.errorMessage("Error in Physical Layer Fuzzing: Minimum is Greater than Maximum.")
                            raise ValueError

        # Toggle the Text
        dashboard.ui.pushButton_attack_fuzzing_start.setText("Stop Attack")
        dashboard.ui.pushButton_attack_fuzzing_start.setEnabled(False)

        # Enable Apply Button
        dashboard.ui.pushButton_attack_fuzzing_apply_changes.setEnabled(False)

        # Update Flow Graph Status Label
        dashboard.ui.label2_attack_fuzzing_flow_graph_status.setText("Starting...")

        # Send "Run Attack Flow Graph" Message to the HIPRFISR
        fname = dashboard.ui.label2_attack_fuzzing_selected_flow_graph.text()
        get_file_type = "Flow Graph"
        await dashboard.backend.attackFlowGraphStart(
            dashboard.selected_node_uid,
            str(fname),
            variable_names,
            variable_values,
            get_file_type,
            False,
        )
        
        # Update the Status Dialog
        if dashboard.selected_node_uid:
            # dashboard.statusbar_text[dashboard.selected_node_uid][3] = 'Starting... "' + fname.split('/')[-1] + '"'  # TODO
            dashboard.refreshStatusBarText()

        # Send "Start Physical Fuzzing" Message
        if physical_fuzzing_enabled == True:
            await dashboard.backend.physicalFuzzingStart(dashboard.selected_node_uid, fuzzing_variables, fuzzing_type, fuzzing_min, fuzzing_max, fuzzing_update_period, fuzzing_seed_step)

        # Update the Attack History Table
        attack_name = str(dashboard.ui.label2_attack_fuzzing_selected_attack.text())
        protocol = str(dashboard.ui.label2_attack_fuzzing_selected_protocol.text())

    #~ # Message Data Entered Incorrectly
    #~ except ValueError as inst:
        #~ fissure.Dashboard.UI_Components.Qt5.errorMessage("Message data was entered incorrectly.")

    
@qasync.asyncSlot(QtCore.QObject)
async def _slotAttackFuzzingApplyChangesClicked(dashboard: QtCore.QObject):
    """ 
    Updates the fuzzing flow graph with new fuzzer/flow graph variable changes.
    """
    # Flow Graph Controls
    # Send Message(s) to the HIPRFISR for each Variable Name and Value
    for get_row in range(dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()):

        # Determine the Variable Name and Value in the Row
        variable_name = dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.verticalHeaderItem(get_row).text()
        value = dashboard.ui.tableWidget_attack_fuzzing_flow_graph_current_values.item(get_row,0).text()

        # Check and Send the "Set" Message if Value Changed
        if dashboard.attack_flow_graph_variables[str(variable_name)] != str(value):
            dashboard.attack_flow_graph_variables[str(variable_name)] = str(value)
            await dashboard.backend.setVariable(dashboard.selected_node_uid, "Attack", str(variable_name), str(value))

    #~ # Data Field Controls
    #~ if dashboard.ui.stackedWidget_fuzzing.currentIndex() == 0:
        #~ # Convert Every Field to Binary, Assemble
        #~ get_bin = ""
        #~ fuzzing_fields = []
        #~ fuzzing_type = []
        #~ fuzzing_min = []
        #~ fuzzing_max = []
        #~ hex_str = ""
        #~ for n in range(0,dashboard.ui.tableWidget_attack_fuzzing_data_field.rowCount()):
            #~ # Binary or Hex
            #~ current_selection = dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(n,4).currentText()
        #~
            #~ # Contains Data
            #~ if dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,5).text() != "":
                #~ # Get the Data
                #~ get_data = str(dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,5).text())
                #~ print(get_data)
                #~
                #~ if current_selection == "Binary":
                    #~ bin_str = get_data.replace(' ', '')
                    #~
                #~ # Hex to Binary
                #~ elif current_selection == "Hex":
                    #~ print(n)
                    #~ hex_len = len(get_data)
                    #~ bin_str = bin(int(get_data, 16))[2:].zfill(int(hex_len*4))
                    #~
                #~ get_bin = get_bin + bin_str
                #~
            #~ # Get Checked Fields
            #~ if dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(n,0).isChecked() == True:
                #~ fuzzing_fields.append(str(dashboard.ui.tableWidget_attack_fuzzing_data_field.verticalHeaderItem(n).text()))
                #~
                #~ # Get Fuzzing Type
                #~ fuzzing_type.append(str(dashboard.ui.tableWidget_attack_fuzzing_data_field.cellWidget(n,1).currentText()))
                #~
                #~ # Get Fuzzing Min
                #~ if dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,2) == None:
                    #~ fuzzing_min.append("")
                #~ else:
                    #~ fuzzing_min.append(str(dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,2).text()))
                #~
                #~ # Get Fuzzing Max
                #~ if dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,3) == None:
                    #~ fuzzing_max.append("")
                #~ else:
                    #~ fuzzing_max.append(str(dashboard.ui.tableWidget_attack_fuzzing_data_field.item(n,3).text()))
        #~
        #~ # Convert Data to Hex
        #~ if get_bin != "":
            #~ hex_str = '%0*X' % ((len(get_bin) + 3) // 4, int(get_bin, 2))
                    #~
        #~ # Check and Send the "Set" Message if Value Changed
        #~ if dashboard.attack_flow_graph_variables["fuzzing_fields"] != str(fuzzing_fields):
            #~ dashboard.attack_flow_graph_variables["fuzzing_fields"] = str(fuzzing_fields)
            #~ dashboard.dashboard_hiprfisr_server.sendmsg('Commands', Identifier = 'Dashboard', MessageName = 'Set Variable', Parameters = ["Attack", "fuzzing_fields", str(fuzzing_fields)] )
        #~ if dashboard.attack_flow_graph_variables["fuzzing_type"] != str(fuzzing_type):
            #~ dashboard.attack_flow_graph_variables["fuzzing_type"] = str(fuzzing_type)
            #~ dashboard.dashboard_hiprfisr_server.sendmsg('Commands', Identifier = 'Dashboard', MessageName = 'Set Variable', Parameters = ["Attack", "fuzzing_type", str(fuzzing_type)] )
        #~ if dashboard.attack_flow_graph_variables["fuzzing_min"] != str(fuzzing_min):
            #~ dashboard.attack_flow_graph_variables["fuzzing_min"] = str(fuzzing_min)
            #~ dashboard.dashboard_hiprfisr_server.sendmsg('Commands', Identifier = 'Dashboard', MessageName = 'Set Variable', Parameters = ["Attack", "fuzzing_min", str(fuzzing_min)] )
        #~ if dashboard.attack_flow_graph_variables["fuzzing_max"] != str(fuzzing_max):
            #~ dashboard.attack_flow_graph_variables["fuzzing_max"] = str(fuzzing_max)
            #~ dashboard.dashboard_hiprfisr_server.sendmsg('Commands', Identifier = 'Dashboard', MessageName = 'Set Variable', Parameters = ["Attack", "fuzzing_max", str(fuzzing_max)] )
        #~ if dashboard.attack_flow_graph_variables["fuzzing_data"] != hex_str:
            #~ dashboard.attack_flow_graph_variables["fuzzing_data"] = hex_str
            #~ dashboard.dashboard_hiprfisr_server.sendmsg('Commands', Identifier = 'Dashboard', MessageName = 'Set Variable', Parameters = ["Attack", "fuzzing_data", hex_str] )
            #~
    # Disable the Pushbutton
    dashboard.ui.pushButton_attack_fuzzing_apply_changes.setEnabled(False)

    # Update the "Attack History" Table
    attack_name = str(dashboard.ui.label2_attack_fuzzing_selected_attack.text())
    protocol = str(dashboard.ui.label2_attack_fuzzing_selected_protocol.text())


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketImportClicked(dashboard: QtCore.QObject):
    """ 
    Imports default values for a packet type.
    """
    try:
        # Select file to open
        open_path, _ = QtWidgets.QFileDialog.getOpenFileName(
            None, "Open Packet Defaults", "", "YAML Files (*.yaml);;All Files (*)"
        )

        if not open_path:
            return  # User canceled file selection

        # Load YAML file
        with open(open_path, "r") as file:
            import_data = yaml.safe_load(file)

        # Set protocol and packet type
        dashboard.ui.comboBox_packet_protocols.setCurrentText(import_data["protocol"])
        dashboard.ui.comboBox_packet_subcategory.setCurrentText(import_data["packet_type"])

        # Clear table contents and set row count
        dashboard.ui.tableWidget1_attack_packet_editor.clearContents()
        dashboard.ui.tableWidget1_attack_packet_editor.setRowCount(len(import_data["fields"]))

        # Retrieve default field lengths
        current_protocol_key = import_data["protocol"]
        current_subcategory = import_data["packet_type"]

        # Populate table with imported values
        for row, field in enumerate(import_data["fields"]):
            field_name = field["field_name"]
            dashboard.ui.tableWidget1_attack_packet_editor.setVerticalHeaderItem(
                row, QtWidgets.QTableWidgetItem(field_name)
            )

            # Create combobox with correct object name and options
            type_combobox = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')

            if field["type"] in ["Binary", "Hex"]:
                type_combobox.addItems(["Binary", "Hex"])
            elif field["type"] == "String":
                type_combobox.addItem("String")

            type_combobox.setCurrentText(field["type"])
            type_combobox.setFixedSize(75, 24)
            type_combobox.setProperty("row", row)

            # Connect to slot function
            type_combobox.currentIndexChanged.connect(
                lambda: _slotPacketBinaryHex(dashboard, dashboard.ui.tableWidget1_attack_packet_editor)
            )

            # Disable combobox if it's a String type
            if field["type"] == "String":
                type_combobox.setEnabled(False)

            dashboard.ui.tableWidget1_attack_packet_editor.setCellWidget(row, 0, type_combobox)

            # Set Data column
            data_item = QtWidgets.QTableWidgetItem(field["data"])
            dashboard.ui.tableWidget1_attack_packet_editor.setItem(row, 1, data_item)

            # Get length values from the library (like `_slotPacketSubcategory`)
            try:
                length_value = fissure.utils.library.getFieldData(
                    dashboard.backend.library, current_protocol_key, current_subcategory, field_name
                )["Length"]
            except KeyError:
                length_value = 0  # Default to 0 if not found

            # Set Default Length (Column 3)
            default_length_item = QtWidgets.QTableWidgetItem(str(length_value))
            default_length_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget1_attack_packet_editor.setItem(row, 3, default_length_item)

            # **Trigger `_slotPacketItemChanged` to ensure Column 2 updates**
            _slotPacketItemChanged(dashboard, row, 1)

        # Calculate total lengths
        current_length = sum(
            int(dashboard.ui.tableWidget1_attack_packet_editor.item(row, 2).text())
            for row in range(dashboard.ui.tableWidget1_attack_packet_editor.rowCount())
            if dashboard.ui.tableWidget1_attack_packet_editor.item(row, 2) is not None
        )

        default_length = sum(
            int(dashboard.ui.tableWidget1_attack_packet_editor.item(row, 3).text())
            for row in range(dashboard.ui.tableWidget1_attack_packet_editor.rowCount())
            if dashboard.ui.tableWidget1_attack_packet_editor.item(row, 3) is not None
        )

        dashboard.ui.label2_packet_current_length_total.setText(str(current_length))
        dashboard.ui.label2_packet_default_length_total.setText(str(default_length))

        # Resize columns
        dashboard.ui.tableWidget1_attack_packet_editor.setColumnWidth(0, 75)
        dashboard.ui.tableWidget1_attack_packet_editor.setColumnWidth(2, 75)
        dashboard.ui.tableWidget1_attack_packet_editor.setColumnWidth(3, 75)
        dashboard.ui.tableWidget1_attack_packet_editor.horizontalHeader().setSectionResizeMode(1, QtWidgets.QHeaderView.Stretch)

    except Exception as e:
        dashboard.logger.error(f"Import Error: {e}")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketExportClicked(dashboard: QtCore.QObject):
    """ 
    Exports default values for a packet type.
    """
    try:
        # Get current protocol and packet type
        protocol = dashboard.ui.comboBox_packet_protocols.currentText()
        packet_type = dashboard.ui.comboBox_packet_subcategory.currentText()

        # Prepare data to export
        export_data = {
            "protocol": protocol,
            "packet_type": packet_type,
            "fields": []
        }

        # Iterate through table rows
        for row in range(dashboard.ui.tableWidget1_attack_packet_editor.rowCount()):
            field_name = dashboard.ui.tableWidget1_attack_packet_editor.verticalHeaderItem(row).text()
            type_value = dashboard.ui.tableWidget1_attack_packet_editor.cellWidget(row, 0).currentText()

            # Get the data column (Column 1)
            data_item = dashboard.ui.tableWidget1_attack_packet_editor.item(row, 1)
            data_value = data_item.text() if data_item is not None else ""

            # Append field details
            export_data["fields"].append({
                "field_name": field_name,
                "type": type_value,
                "data": data_value
            })

        # Select file location
        save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
            None, "Save Packet Defaults", "", "YAML Files (*.yaml);;All Files (*)"
        )

        if save_path:
            # Write to YAML file
            with open(save_path, "w") as file:
                yaml.dump(export_data, file, default_flow_style=False)

    except Exception as e:
        dashboard.logger.error(f"Export Error: {e}")
