from PyQt5 import QtCore, QtWidgets
import os
import fissure.utils
import qasync
import yaml
import binascii
import crcmod
from scipy import signal as signal2
from scapy.all import Dot11, RadioTap, Dot11Deauth, Dot11ProbeReq, IP, UDP, LLC, SNAP, ARP, Ether, ICMP


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


def _buildPacketCrafterScapyPacket(dashboard: QtCore.QObject):
    """Build and return the current Packet Crafter Scapy packet without touching legacy Scapy UI."""
    packet = None
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
        packet = RadioTap()/Dot11(type=0, subtype=13, addr1=get_dest_mac, addr2=get_source_mac, addr3=get_bssid_mac)/get_category/get_action/get_element

    elif "CTS" == get_type:
        get_recv_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_type_subtype = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        get_duration = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        packet = RadioTap()/get_type_subtype/get_duration/get_recv_mac

    elif "Deauthentication" == get_type:
        get_target_mac = '%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))
        get_target_mac = get_target_mac[0:2] + ":" + get_target_mac[2:4] + ":" + get_target_mac[4:6] + ":" + get_target_mac[6:8] + ":" + get_target_mac[8:10] + ":" + get_target_mac[10:12]
        get_ap_mac = '%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))
        get_ap_mac = get_ap_mac[0:2] + ":" + get_ap_mac[2:4] + ":" + get_ap_mac[4:6] + ":" + get_ap_mac[6:8] + ":" + get_ap_mac[8:10] + ":" + get_ap_mac[10:12]
        packet = RadioTap()/Dot11(type=0, subtype=12, addr1=get_target_mac, addr2=get_ap_mac, addr3=get_ap_mac)/Dot11Deauth(reason=7)

    elif "Null" == get_type:
        get_dest_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_source_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        get_bssid_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        get_type_subtype = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[3]) + 3) // 4, int(get_bin[3], 2))))
        get_flags = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[4]) + 3) // 4, int(get_bin[4], 2))))
        get_duration = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[5]) + 3) // 4, int(get_bin[5], 2))))
        get_fragment_sequence = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[6]) + 3) // 4, int(get_bin[6], 2))))
        packet = RadioTap()/get_type_subtype/get_flags/get_duration/get_dest_mac/get_source_mac/get_bssid_mac/get_fragment_sequence

    elif "Probe Request" == get_type:
        get_source_mac = '%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))
        get_source_mac = get_source_mac[0:2] + ":" + get_source_mac[2:4] + ":" + get_source_mac[4:6] + ":" + get_source_mac[6:8] + ":" + get_source_mac[8:10] + ":" + get_source_mac[10:12]
        get_target_mac = '%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))
        get_target_mac = get_target_mac[0:2] + ":" + get_target_mac[2:4] + ":" + get_target_mac[4:6] + ":" + get_target_mac[6:8] + ":" + get_target_mac[8:10] + ":" + get_target_mac[10:12]
        packet = RadioTap()/Dot11(type=0, subtype=4, addr1=get_target_mac, addr2=get_source_mac)/Dot11ProbeReq("00" * 1)
        #packet = RadioTap()/Dot11(type=0, subtype=0100, addr2=get_target_mac)/Dot11ProbeReq("00" * 1)  # "subtype" doesn't register in this format

    elif "RTS" == get_type:
        get_recv_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[0]) + 3) // 4, int(get_bin[0], 2))))
        get_tx_mac = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[1]) + 3) // 4, int(get_bin[1], 2))))
        get_type_subtype = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[2]) + 3) // 4, int(get_bin[2], 2))))
        get_duration = binascii.unhexlify(''.join('%0*X' % ((len(get_bin[3]) + 3) // 4, int(get_bin[3], 2))))
        packet = RadioTap()/get_type_subtype/get_duration/get_recv_mac/get_tx_mac

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
        packet = RadioTap()/get_type_subtype/get_flags/get_duration/get_addr2_mac/get_addr1_mac/get_addr1_mac/get_fragment_sequence/llc_bytes/udp_bytes/get_udp_data

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
        packet = RadioTap()/get_type_subtype/get_flags/get_duration/get_addr1_mac/get_addr2_mac/get_addr3_mac/get_fragment_sequence/llc_bytes/udp_bytes/get_udp_data
        #print(packet[0].show())

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

        packet = RadioTap()/get_type_subtype/get_flags/get_duration/get_addr3_mac/get_addr1_mac/get_addr2_mac/get_fragment_sequence/LLC()/SNAP()/arp_bytes

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

        packet = Ether()/arp_bytes

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

        packet = scapy_bytes

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
        packet = RadioTap()/get_type_subtype/get_flags/get_duration/get_addr1_mac/get_addr2_mac/get_addr3_mac/get_fragment_sequence/get_qos_control/llc_bytes/udp_bytes/get_udp_data
        #print(packet[0].show())

    return packet


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


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPacketOpenInScapyClicked(dashboard: QtCore.QObject):
    """Build the current Packet Crafter packet and open it in the Scapy tab."""
    from fissure.Dashboard.Slots import ScapyTabSlots

    try:
        packet = _buildPacketCrafterScapyPacket(dashboard)

        if packet is None:
            fissure.Dashboard.UI_Components.Qt5.errorMessage(
                "Could not build a Scapy packet from the current Packet Crafter fields."
            )
            return

        ScapyTabSlots._load_scapy_packet(dashboard, packet)

        dashboard.ui.tabWidget.setCurrentWidget(dashboard.ui.tab_attack)
        dashboard.ui.tabWidget_attack_attack.setCurrentWidget(dashboard.ui.tab_ta_scapy)

    except Exception as exc:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(
            f"Could not open packet in Scapy:\n{exc}"
        )