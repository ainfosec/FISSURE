from PyQt5 import QtCore, QtWidgets, QtGui
import os
import fissure.utils
import qasync
import yaml
import shutil
import csv
import zipfile
import shutil
import pyzipper
import json
import asyncio
from PyQt5.QtWidgets import QApplication
import subprocess


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryGalleryNextClicked(dashboard: QtCore.QObject):
    """
    Selects the next picture in the gallery listbox.
    """
    # Increment the Row
    get_index = dashboard.ui.listWidget_library_gallery.currentRow() + 1
    if get_index >= dashboard.ui.listWidget_library_gallery.count():
        dashboard.ui.listWidget_library_gallery.setCurrentRow(0)
    else:
        dashboard.ui.listWidget_library_gallery.setCurrentRow(get_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryGalleryPreviousClicked(dashboard: QtCore.QObject):
    """
    Selects the previous picture in the gallery listbox.
    """
    # Decrement the Row
    get_index = dashboard.ui.listWidget_library_gallery.currentRow() - 1
    if get_index < 0:
        dashboard.ui.listWidget_library_gallery.setCurrentRow(dashboard.ui.listWidget_library_gallery.count()-1)
    else:
        dashboard.ui.listWidget_library_gallery.setCurrentRow(get_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryGalleryOpenClicked(dashboard: QtCore.QObject):
    """
    Opens the selected gallery image in an image viewer.
    """
    # Get the File
    get_image_name = str(dashboard.ui.listWidget_library_gallery.currentItem().text())
    image_filepath = os.path.join(fissure.utils.GALLERY_DIR, get_image_name)

    # Opens the File with EOG
    osCommandString = "eog " + image_filepath
    os.system(osCommandString+ " &")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryGalleryProtocolChanged(dashboard: QtCore.QObject):
    """ 
    Updates the gallery listbox with images files for the selected protocol.
    """
    # Update the Listbox
    dashboard.ui.listWidget_library_gallery.clear()
    get_protocol = str(dashboard.ui.comboBox_library_gallery_protocol.currentText())
    get_protocol = get_protocol.replace(" ","_")
    protocol_len = len(get_protocol)
    for fname in sorted(os.listdir(fissure.utils.GALLERY_DIR)):
        if get_protocol in fname[0:protocol_len]:
            dashboard.ui.listWidget_library_gallery.addItem(fname)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryGalleryImageChanged(dashboard: QtCore.QObject):
    """ 
    Displays the selected image in the gallery.
    """
    try:
        # Display Image
        get_image_name = str(dashboard.ui.listWidget_library_gallery.currentItem().text())
        get_image = QtGui.QPixmap(os.path.join(fissure.utils.GALLERY_DIR, get_image_name))
        get_width = get_image.width()
        get_height = get_image.height()
        label_width = 860
        label_height = 630

        # Resize Image, Keep Aspect Ratio
        w_ratio = float(get_width)/float(label_width)
        h_ratio = float(get_height)/float(label_height)
        if w_ratio > h_ratio:
            get_image = get_image.scaled(int(get_width/w_ratio),int(get_height/w_ratio))
        else:
            get_image = get_image.scaled(int(get_width/h_ratio),int(get_height/h_ratio))

        dashboard.ui.label_library_gallery.setFixedSize(get_image.width(),get_image.height())
        dashboard.ui.label_library_gallery.setPixmap(get_image)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibrarySearchBinaryClicked(dashboard: QtCore.QObject):
    """ 
    Converts the PD Search Field Values edit box to binary.
    """
    try:
        # Convert to Binary
        get_data = str(dashboard.ui.textEdit_library_search_field_value.toPlainText())
        get_data = get_data.replace(' ','')
        bin_str = bin(int(get_data, 16))[2:].zfill(int(len(get_data)*4))
        dashboard.ui.textEdit_library_search_field_value.setPlainText(bin_str)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibrarySearchHexClicked(dashboard: QtCore.QObject):
    """ 
    Converts the PD Search Field Values edit box to hex.
    """
    try:
        # Convert to Hex
        get_data = str(dashboard.ui.textEdit_library_search_field_value.toPlainText())
        get_data = get_data.replace(' ','')
        hex_str = '%0*X' % ((len(get_data) + 3) // 4, int(get_data, 2))
        dashboard.ui.textEdit_library_search_field_value.setPlainText(hex_str)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotPD_AddToLibraryProtocolChanged(dashboard: QtCore.QObject):
    """ 
    Selects a protocol for the new packet type to be assigned to in the library.
    """
    # Clear Demodulation Flow Graph Modulation Combo Box
    dashboard.ui.comboBox_library_pd_modulation_types.clear()

    # Enable/Disable New Protocol Name
    get_protocol = str(dashboard.ui.comboBox_library_pd_protocol.currentText())
    if get_protocol != "":
        if get_protocol == "-- New Protocol --":
            dashboard.ui.label1_library_add.setText("Add New Protocol to Library")
            dashboard.ui.stackedWidget2_library_pd.setCurrentIndex(0)
            dashboard.ui.label2_library_pd_data_type.setVisible(False)
            dashboard.ui.comboBox_library_pd_data_type.setVisible(False)
        else:
            dashboard.ui.label2_library_pd_data_type.setVisible(True)
            dashboard.ui.comboBox_library_pd_data_type.setVisible(True)
            _slotLibraryAddDataTypeChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackImportAttackTypeChanged(dashboard: QtCore.QObject):
    """ 
    This changes the items in the attack tree parent combobox to reflect single-stage or multi-stage categories.
    """
    # Add New Items
    dashboard.ui.comboBox_library_attacks_subcategory.clear()
    if dashboard.ui.comboBox_library_attacks_attack_type.currentText() == "Single-Stage":
        dashboard.ui.comboBox_library_attacks_subcategory.addItems(["Denial of Service", "Jamming", "Spoofing", "Sniffing/Snooping", "Probe Attacks", "Installation of Malware", "Misuse of Resources", "Other"])
        dashboard.ui.label2_library_attacks_new_name.setHidden(False)
        dashboard.ui.label2_library_attacks_new_name2.setHidden(False)
        dashboard.ui.textEdit_library_attacks_new_name.setHidden(False)
        dashboard.ui.label2_library_attacks_file_select.setText(".py File:")
        dashboard.ui.label2_library_attacks_modulation.setHidden(False)
        dashboard.ui.comboBox_library_attacks_modulation.setHidden(False)

    # Reset State
    dashboard.ui.label_library_attacks_filepath.setText("")
    dashboard.ui.textEdit_library_attacks_name.setPlainText("")
    dashboard.ui.textEdit_library_attacks_new_name.setPlainText("")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackImportFileTypeChanged(dashboard: QtCore.QObject):
    """ 
    Toggles the "include .grc" check box.
    """
    # Enable Check Box
    if str(dashboard.ui.comboBox_library_attacks_file_type.currentText()) == "Flow Graph":
        dashboard.ui.checkBox_library_attacks_grc_file.setEnabled(True)
        dashboard.ui.checkBox_library_attacks_grc_file.setChecked(True)
    elif str(dashboard.ui.comboBox_library_attacks_file_type.currentText()) == "Flow Graph - GUI":
        dashboard.ui.checkBox_library_attacks_grc_file.setEnabled(True)
        dashboard.ui.checkBox_library_attacks_grc_file.setChecked(True)
    else:
        dashboard.ui.checkBox_library_attacks_grc_file.setEnabled(False)
        dashboard.ui.checkBox_library_attacks_grc_file.setChecked(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryAddDataTypeChanged(dashboard: QtCore.QObject):
    """ 
    Changes the stacked widget for adding different types of protocol data to the library.
    """
    # Change Index
    get_type = str(dashboard.ui.comboBox_library_pd_data_type.currentText())
    if get_type == "Modulation Type":
        dashboard.ui.label1_library_add.setText("Add New Modulation Type to Library")
        dashboard.ui.stackedWidget2_library_pd.setCurrentIndex(1)
    elif get_type == "Packet Type":
        dashboard.ui.label1_library_add.setText("Add New Packet Type to Library")
        dashboard.ui.stackedWidget2_library_pd.setCurrentIndex(2)
    elif get_type == "Signal of Interest":
        dashboard.ui.label1_library_add.setText("Add New Signal of Interest to Library")
        dashboard.ui.stackedWidget2_library_pd.setCurrentIndex(3)
    elif get_type == "Demodulation Flow Graph":
        dashboard.ui.label1_library_add.setText("Add New Demodulation Flow Graph to Library")
        dashboard.ui.stackedWidget2_library_pd.setCurrentIndex(4)

        # Populate Demodulation Flow Graph Modulation Types
        get_protocol = str(dashboard.ui.comboBox_library_pd_protocol.currentText())
        if len(get_protocol) > 0:
            get_modulation_types = fissure.utils.library.getModulations(dashboard.backend.library, get_protocol)
            if len(get_modulation_types) > 0:
                dashboard.ui.comboBox_library_pd_modulation_types.addItems(get_modulation_types)

    elif get_type == "Attack":
        _slotAttackImportProtocolChanged(dashboard)
        dashboard.ui.label1_library_add.setText("Add New Attack to Library")
        dashboard.ui.stackedWidget2_library_pd.setCurrentIndex(5)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAttackImportProtocolChanged(dashboard: QtCore.QObject):
    """ 
    This changes the items in the modulation combobox to reflect the currently selected protocol. FIX - Is this a real slot?
    """
    # Update Comboboxes
    dashboard.ui.comboBox_library_attacks_modulation.clear()
    get_protocol = str(dashboard.ui.comboBox_library_pd_protocol.currentText())
    if get_protocol != "":
        try:
            modulation_types = fissure.utils.library.getModulations(dashboard.backend.library, get_protocol)
            dashboard.ui.comboBox_library_attacks_modulation.addItems(modulation_types)
        # No Modulation Types Available
        except KeyError:
            pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibrarySearchCurrentSOI_Clicked(dashboard: QtCore.QObject):
    """ 
    Populates the Search Library Fields with the current SOI.
    """
    # Set the Fields
    if len(dashboard.target_soi) > 0:
        dashboard.ui.textEdit_library_search_frequency.setPlainText(dashboard.target_soi[0])
        dashboard.ui.textEdit_library_search_modulation.setPlainText(dashboard.target_soi[1])
        dashboard.ui.textEdit_library_search_bandwidth.setPlainText(dashboard.target_soi[2])

        if dashboard.target_soi[3] == "True":
            dashboard.ui.comboBox_library_search_continuous.setCurrentIndex(0)
        else:
            dashboard.ui.comboBox_library_search_continuous.setCurrentIndex(1)

        dashboard.ui.textEdit_library_search_start_frequency.setPlainText(dashboard.target_soi[4])
        dashboard.ui.textEdit_library_search_end_frequency.setPlainText(dashboard.target_soi[5])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryAddBrowseClicked(dashboard: QtCore.QObject):
    """ 
    Opens a file dialog to choose an existing python file for demodulating the protocol.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "PD Flow Graphs")
    dialog.setDirectory(directory)
    dialog.setNameFilters(['Flow Graphs (*.py)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_library_pd_demodulation_fg.setPlainText(str(folder))
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryAddCurrentSOI_Clicked(dashboard: QtCore.QObject):
    """ 
    Updates the edit boxes in the SOI Data section of the "Add to Library" tab with the current SOI information.
    """
    # Insert the Information
    if str(dashboard.ui.textEdit_pd_status_target.toPlainText()) != "":
        if len(dashboard.target_soi) > 0:
            dashboard.ui.textEdit_library_pd_soi_frequency.setPlainText(dashboard.target_soi[0])
            dashboard.ui.textEdit_library_pd_soi_modulation.setPlainText(dashboard.target_soi[1])
            dashboard.ui.textEdit_library_pd_soi_bandwidth.setPlainText(dashboard.target_soi[2])

            if dashboard.target_soi[3] == "True":
                dashboard.ui.comboBox_library_pd_soi_continuous.setCurrentIndex(0)
            else:
                dashboard.ui.comboBox_library_pd_soi_continuous.setCurrentIndex(1)

            dashboard.ui.textEdit_library_pd_soi_start_frequency.setPlainText(dashboard.target_soi[4])
            dashboard.ui.textEdit_library_pd_soi_end_frequency.setPlainText(dashboard.target_soi[5])
            dashboard.ui.textEdit_library_pd_soi_notes.setPlainText(dashboard.target_soi[6])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryAddAddFieldClicked(dashboard: QtCore.QObject):
    """ 
    Adds a new row to the library packet table in the protocol discovery\add to library packet tab.
    """
    # Add Row
    dashboard.ui.tableWidget_library_pd_packet.setRowCount(dashboard.ui.tableWidget_library_pd_packet.rowCount()+1)
    header_item = QtWidgets.QTableWidgetItem("Field " + str(dashboard.ui.tableWidget_library_pd_packet.rowCount()))
    header_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_library_pd_packet.setVerticalHeaderItem(dashboard.ui.tableWidget_library_pd_packet.rowCount()-1,header_item)

    # CRC Range
    crc_range_item = QtWidgets.QTableWidgetItem("")
    crc_range_item.setTextAlignment(QtCore.Qt.AlignCenter)
    crc_range_item.setFlags(crc_range_item.flags() ^ QtCore.Qt.ItemIsEnabled)
    crc_range_item.setFlags(crc_range_item.flags() ^ QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.rowCount()-1,4,crc_range_item)

    # Is CRC Combobox
    new_combobox = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
    new_combobox.addItem("True")
    new_combobox.addItem("False")
    new_combobox.setCurrentIndex(1)
    dashboard.ui.tableWidget_library_pd_packet.setCellWidget(dashboard.ui.tableWidget_library_pd_packet.rowCount()-1,3,new_combobox)
    new_combobox.currentIndexChanged.connect(lambda: _slotPD_AddToLibraryIsCRC_Changed(dashboard))
    new_combobox.setProperty("row", dashboard.ui.tableWidget_library_pd_packet.rowCount()-1)

    # Resize the Table
    dashboard.ui.tableWidget_library_pd_packet.resizeRowsToContents()
    dashboard.ui.tableWidget_library_pd_packet.setColumnWidth(0,125)
    dashboard.ui.tableWidget_library_pd_packet.setColumnWidth(1,100)
    dashboard.ui.tableWidget_library_pd_packet.setColumnWidth(3,75)
    dashboard.ui.tableWidget_library_pd_packet.setColumnWidth(4,130)
    dashboard.ui.tableWidget_library_pd_packet.horizontalHeader().setSectionResizeMode(2,QtWidgets.QHeaderView.Stretch)


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
def _slotLibraryAddRemoveFieldClicked(dashboard: QtCore.QObject):
    """ 
    Removes the current row from the library packet table in the protocol discovery\construct packet tab.
    """
    # Remove Row
    dashboard.ui.tableWidget_library_pd_packet.removeRow(dashboard.ui.tableWidget_library_pd_packet.currentRow())

    # Relabel the Rows
    for rows in range(0,dashboard.ui.tableWidget_library_pd_packet.rowCount()):
        header_item = QtWidgets.QTableWidgetItem("Field " + str(rows+1))
        header_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_library_pd_packet.setVerticalHeaderItem(rows,header_item)

    # Resize
    dashboard.ui.tableWidget_library_pd_packet.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryAddUpClicked(dashboard: QtCore.QObject):
    """ 
    Moves the current field up one position in the field table.
    """
    if dashboard.ui.tableWidget_library_pd_packet.currentRow() != 0:  # Ignore top row
        # Take the Row Above
        above_item0 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()-1,0)
        above_item1 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()-1,1)
        above_item2 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()-1,2)

        # Take the Current Row
        current_item0 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),0)
        current_item1 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),1)
        current_item2 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),2)

        # Set the Current Row
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),0,above_item0)
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),1,above_item1)
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),2,above_item2)

        # Set the Row Above
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()-1,0,current_item0)
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()-1,1,current_item1)
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()-1,2,current_item2)

        # Change the Selected Row
        dashboard.ui.tableWidget_library_pd_packet.setCurrentCell(dashboard.ui.tableWidget_library_pd_packet.currentRow()-1,0)

        # Resize
        dashboard.ui.tableWidget_library_pd_packet.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryAddDownClicked(dashboard: QtCore.QObject):
    """ 
    Moves the current field down one position in the field table.
    """
    # Get Bottom Row
    bottom_row = dashboard.ui.tableWidget_library_pd_packet.rowCount()

    # Move it Down
    if dashboard.ui.tableWidget_library_pd_packet.currentRow() != bottom_row-1:  # Ignore bottom row
        # Take the Row Below
        below_item0 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()+1,0)
        below_item1 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()+1,1)
        below_item2 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()+1,2)

        # Take the Current Row
        current_item0 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),0)
        current_item1 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),1)
        current_item2 = dashboard.ui.tableWidget_library_pd_packet.takeItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),2)

        # Set the Current Row
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),0,below_item0)
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),1,below_item1)
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow(),2,below_item2)

        # Set the Row Above
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()+1,0,current_item0)
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()+1,1,current_item1)
        dashboard.ui.tableWidget_library_pd_packet.setItem(dashboard.ui.tableWidget_library_pd_packet.currentRow()+1,2,current_item2)

        # Change the Selected Row
        dashboard.ui.tableWidget_library_pd_packet.setCurrentCell(dashboard.ui.tableWidget_library_pd_packet.currentRow()+1,0)

        # Resize
        dashboard.ui.tableWidget_library_pd_packet.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryAddAttacksSelectClicked(dashboard: QtCore.QObject):
    """ 
    This opens a file dialog to select a .py or .msa file as the source of the new attack template.
    """
    # Look for the Flow Graph Files or Multi-Stage Attack File
    directory = ""
    dialog_text = ""
    dialog_filter = ""

    directory = fissure.utils.FISSURE_ROOT
    dialog_text = "Select Python File..."
    dialog_filter = "Python Files (*.py)"

    fpath = str(QtWidgets.QFileDialog.getOpenFileName(None,dialog_text, directory, filter=dialog_filter)[0])

    # If a Valid File
    if fpath != "":
        fname = fpath.rsplit("/",1)[1]
        fname = fname.rsplit(".py",1)[0]
        fname = fname.rsplit(".msa",1)[0]
        dashboard.ui.label_library_attacks_filepath.setText(fpath)
        dashboard.ui.textEdit_library_attacks_new_name.setPlainText(fname)

        dashboard.ui.textEdit_library_attacks_name.setPlainText(fname)
        dashboard.ui.textEdit_library_attacks_new_name.setPlainText(fpath.rsplit("/",1)[1])
    else:
        if dashboard.ui.textEdit_library_attacks_name.toPlainText() != "":
            pass


@qasync.asyncSlot(QtCore.QObject)
async def _slotLibrarySearchSearchLibraryClicked(dashboard: QtCore.QObject):
    """ 
    Sends a message to the HIPRFISR/PD to check the library for occurences of the selected preamble.
    """
    # Get SOI Data
    soi_data = ["","","","","","","","","",""]
    if dashboard.ui.checkBox_library_search_frequency.isChecked():
        soi_data[0] = str(dashboard.ui.textEdit_library_search_frequency.toPlainText())
        soi_data[6] = str(dashboard.ui.textEdit_library_search_frequency_margin.toPlainText())
    if dashboard.ui.checkBox_library_search_modulation.isChecked():
        soi_data[1] = str(dashboard.ui.textEdit_library_search_modulation.toPlainText())
    if dashboard.ui.checkBox_library_search_bandwidth.isChecked():
        soi_data[2] = str(dashboard.ui.textEdit_library_search_bandwidth.toPlainText())
        soi_data[7] = str(dashboard.ui.textEdit_library_search_bandwidth_margin.toPlainText())
    if dashboard.ui.checkBox_library_search_continuous.isChecked():
        soi_data[3] = str(dashboard.ui.comboBox_library_search_continuous.currentText())
    if dashboard.ui.checkBox_library_search_start_frequency.isChecked():
        soi_data[4] = str(dashboard.ui.textEdit_library_search_start_frequency.toPlainText())
        soi_data[8] = str(dashboard.ui.textEdit_library_search_start_frequency_margin.toPlainText())
    if dashboard.ui.checkBox_library_search_end_frequency.isChecked():
        soi_data[5] = str(dashboard.ui.textEdit_library_search_end_frequency.toPlainText())
        soi_data[9] = str(dashboard.ui.textEdit_library_search_end_frequency_margin.toPlainText())

    # Get Field Value
    field_data = ""
    if dashboard.ui.checkBox_library_search_field_value.isChecked():
        # Convert to Binary
        if dashboard.ui.radioButton_library_search_hex.isChecked():
            get_data = str(dashboard.ui.textEdit_library_search_field_value.toPlainText())
            get_data = get_data.replace(' ','')
            field_data = bin(int(get_data, 16))[2:].zfill(int(len(get_data)*4))
        else:
            field_data = str(dashboard.ui.textEdit_library_search_field_value.toPlainText())
            field_data.replace(' ','')

    # Clear Results Table
    dashboard.ui.tableWidget1_library_search_results.setRowCount(0)

    # Send Message
    await dashboard.backend.searchLibrary(soi_data, field_data)

    # Show the Label
    dashboard.ui.label2_library_search_searching.setVisible(True)


@qasync.asyncSlot(QtCore.QObject)
async def _slotLibraryAddAddToLibrary_Clicked(dashboard: QtCore.QObject):
    """ 
    Collects the data to be added to the library and sends it to the HIPRFISR.
    """
    protocol_name = ""
    get_modulation = ""
    new_packet_name = ""
    get_packet_data = []
    get_soi_data = {}
    demodulation_fg_data = {}
    attack_data = {}

    # Protocol Name
    if dashboard.ui.stackedWidget2_library_pd.currentIndex() == 0:
        protocol_name = str(dashboard.ui.textEdit_library_pd_new_protocol.toPlainText())
        protocols = fissure.utils.library.getProtocols(dashboard.backend.library)

        # Empty or Duplicate
        if len(protocol_name) == 0:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Enter valid protocol name.")
            return
        if protocol_name in protocols:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Protocol already exists.")
            return        
    else:
        protocol_name = str(dashboard.ui.comboBox_library_pd_protocol.currentText())

    # Modulation Type
    if dashboard.ui.stackedWidget2_library_pd.currentIndex() == 1:
        get_modulation = str(dashboard.ui.textEdit_library_pd_modulation_type.toPlainText())
        modulation_types = fissure.utils.library.getModulations(dashboard.backend.library, protocol_name)

        # Empty or Duplicate
        if len(get_modulation) == 0:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Enter valid modulation type.")
            return
        if get_modulation in modulation_types:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Modulation type already exists.")
            return

    # Packet Type
    elif dashboard.ui.stackedWidget2_library_pd.currentIndex() == 2:
        # Valid Packet Name
        new_packet_name = str(dashboard.ui.textEdit_library_pd_packet_name.toPlainText())
        packet_types = fissure.utils.library.getPacketTypes(dashboard.backend.library, protocol_name)

        # Empty or Duplicate
        if len(new_packet_name) == 0:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Enter valid packet name.")
            return
        if new_packet_name in packet_types:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Packet type already exists.")
            return

        # Check for Content
        if dashboard.ui.tableWidget_library_pd_packet.rowCount() == 0:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "The number of fields cannot be zero.")
            return

        # Get Packet Data
        for row in range(0,dashboard.ui.tableWidget_library_pd_packet.rowCount()):
            get_packet_data.append([])
            get_packet_data[row].append(str(dashboard.ui.tableWidget_library_pd_packet.item(row,0).text()))
            get_packet_data[row].append(str(dashboard.ui.tableWidget_library_pd_packet.item(row,1).text()))

            # Check Default Values for Binary Characters
            check_default_values = str(dashboard.ui.tableWidget_library_pd_packet.item(row,2).text())
            if set(check_default_values).issubset({'0','1',' '}) and bool(check_default_values):
                get_packet_data[row].append(check_default_values)
            else:
                await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Default values must be binary: 1010 0010 1111...")
                return

            get_packet_data[row].append(str(dashboard.ui.tableWidget_library_pd_packet.cellWidget(row,3).currentText()))
            get_packet_data[row].append(str(dashboard.ui.tableWidget_library_pd_packet.item(row,4).text()))

    # Signal of Interest
    elif dashboard.ui.stackedWidget2_library_pd.currentIndex() == 3:
        # Must Have Subtype/Label
        if len(str(dashboard.ui.textEdit_library_pd_soi_subtype.toPlainText()).replace(" ","")) == 0:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Requires Subtype/Label")
            return

        get_soi_data["soi_name"] = str(dashboard.ui.textEdit_library_pd_soi_subtype.toPlainText())
        get_soi_data["center_frequency"] = str(dashboard.ui.textEdit_library_pd_soi_frequency.toPlainText())
        get_soi_data["start_frequency"] = str(dashboard.ui.textEdit_library_pd_soi_start_frequency.toPlainText())
        get_soi_data["end_frequency"] = str(dashboard.ui.textEdit_library_pd_soi_end_frequency.toPlainText())
        get_soi_data["bandwidth"] = str(dashboard.ui.textEdit_library_pd_soi_bandwidth.toPlainText())
        get_soi_data["continuous"] = str(dashboard.ui.comboBox_library_pd_soi_continuous.currentText())
        get_soi_data["modulation"] = str(dashboard.ui.textEdit_library_pd_soi_modulation.toPlainText())
        get_soi_data["notes"] = str(dashboard.ui.textEdit_library_pd_soi_notes.toPlainText())

    # Demodulation Flow Graph
    elif dashboard.ui.stackedWidget2_library_pd.currentIndex() == 4:
        get_demodulation_fg = str(dashboard.ui.textEdit_library_pd_demodulation_fg.toPlainText())
        get_demodulation_type = str(dashboard.ui.comboBox_library_pd_modulation_types.currentText())
        get_demodulation_hardware = str(dashboard.ui.comboBox_library_pd_hardware.currentText())
        if dashboard.ui.radioButton_library_add_demodulation_fg_stream.isChecked():
            get_sniffer_type = "Stream"
        elif dashboard.ui.radioButton_library_add_demodulation_fg_tagged_stream.isChecked():
            get_sniffer_type = "Tagged Stream"
        elif dashboard.ui.radioButton_library_add_demodulation_fg_msg_pdu.isChecked():
            get_sniffer_type = "Message/PDU"

        # Invalid Demodulation Flow Graph
        if get_demodulation_fg == "":
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Enter valid demodulation flow graph filepath.")
            return
        if get_demodulation_type == "":
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Add modulation type for demodulation flow graph.")
            return

        # Add .py and .grc to "PD Flow Graphs"
        try:
            demod_py_filepath = get_demodulation_fg
            get_demodulation_fg = get_demodulation_fg.rsplit("/",1)[1]

            # Check for Duplicate
            demod_fg_exists = os.path.exists(os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "PD Flow Graphs", get_demodulation_fg))
            if demod_fg_exists:
                await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Duplicate demodulation flow graph name")
                return

            shutil.copy(demod_py_filepath, os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "PD Flow Graphs", get_demodulation_fg))
            demodulation_fg_data["output_type"] = get_sniffer_type
            demodulation_fg_data["filename"] = get_demodulation_fg
            demodulation_fg_data["hardware"] = get_demodulation_hardware
            demodulation_fg_data["modulation_type"] = get_demodulation_type

            demod_grc_file = get_demodulation_fg.replace('.py','.grc')
            demod_grc_filepath = demod_py_filepath.replace('.py','.grc')
            shutil.copy(demod_grc_filepath, os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "PD Flow Graphs", demod_grc_file))
        except:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "New demodulation flow graph requires a valid .py and .grc file with the same name.")
            return

    # Attack
    elif dashboard.ui.stackedWidget2_library_pd.currentIndex() == 5:
        # Get Tree Parent, Attack Name, Hardware
        get_tree_parent = str(dashboard.ui.comboBox_library_attacks_subcategory.currentText())
        get_attack_name = str(dashboard.ui.textEdit_library_attacks_name.toPlainText())
        get_hardware = str(dashboard.ui.comboBox_library_attacks_hardware.currentText())
        get_file_type = str(dashboard.ui.comboBox_library_attacks_file_type.currentText())
        get_new_filename = str(dashboard.ui.textEdit_library_attacks_new_name.toPlainText())
        get_attack_type = str(dashboard.ui.comboBox_library_attacks_attack_type.currentText())

        # Assemble New Attack Filepath, Determine Single-Stage or Multi-Stage
        get_filepath = str(dashboard.ui.label_library_attacks_filepath.text())

        # Invalid Filepath
        if len(get_filepath) == 0:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, 'Select attack file.')
            return

        # Invalid Attack Template Name
        if len(get_attack_name) == 0:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, 'Enter new attack template name.')
            return

        # Invalid Attack Name
        if len(get_new_filename) == 0:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, 'Enter new attack name.')
            return

        # Format Filepath
        if get_filepath.rsplit(".",1)[-1] == "py":
            # Force it to End with ".py"
            if get_new_filename.rsplit(".",1)[-1] != "py":
                get_new_filename = get_new_filename + ".py"
                dashboard.ui.textEdit_library_attacks_new_name.setPlainText(get_new_filename)
            else:
                get_new_filename = str(dashboard.ui.textEdit_library_attacks_new_name.toPlainText())
        elif get_filepath.rsplit(".",1)[1] == "msa":
            get_new_filename = get_filepath.rsplit("/",1)[-1]
        else:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, 'Attack needs to end with ".py" or ".msa"')
            return
        
        # Get Modulation Type
        if get_attack_type == "Single-Stage":
            get_modulation = str(dashboard.ui.comboBox_library_attacks_modulation.currentText())

            # No Modulation Type
            if len(get_modulation) == 0:
                await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, 'Requires modulation type.')
                return

        # Check if File Already Exists
        if os.path.isfile(os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs", get_new_filename)):
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, 'File already exists in "Single-Stage Flow Graphs" folder.')
            return

        # Check if Attack Already Exists for the Protocol, Modulation, and Hardware Combination
        if fissure.utils.library.getAttackFilename(
            dashboard.backend.library, 
            protocol_name, 
            get_new_filename, 
            get_modulation, 
            get_hardware,
            fissure.utils.get_library_version()
        ) != None:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Attack name already exists for this protocol/modulation/hardware combination.")
            return

        # Assemble Message
        attack_data["protocol"] = protocol_name
        attack_data["attack_name"] = get_attack_name
        attack_data["modulation_type"] = get_modulation
        attack_data["hardware"] = get_hardware
        attack_data["attack_type"] = get_file_type
        attack_data["filename"] = get_new_filename
        attack_data["category_name"] = get_tree_parent

        # Add to "Flow Graph Library/Single-Stage Flow Graphs"
        shutil.copy(get_filepath, os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs", get_new_filename))

        # Add .grc File to "Flow Graph Library/Single-Stage Flow Graphs"
        if dashboard.ui.checkBox_library_attacks_grc_file.isChecked():
            shutil.copy(get_filepath.replace(".py",".grc"), os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Single-Stage Flow Graphs", get_new_filename.replace(".py",".grc")))

    # Valid Protocol Name
    if protocol_name != "":
        # Send Message to HIPRFISR/Protocol Discovery
        await dashboard.backend.addToLibrary(protocol_name, new_packet_name, get_packet_data, get_soi_data, get_modulation, demodulation_fg_data, attack_data, [])


def _slotPD_DemodHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Updates the list of demodulation flow graphs. Not a slot.
    """
    # Get Hardware
    get_hardware = str(dashboard.ui.comboBox_pd_demod_hardware.currentText()).split(' - ')[0]

    # Clear the List
    dashboard.ui.listWidget_pd_flow_graphs_all_fgs.clear()

    # Get All Demodulation Flow Graphs
    all_demod_fgs = fissure.utils.library.getDemodulationFlowGraphFilenames(
        dashboard.backend.library, 
        protocol = None, 
        modulation = None, 
        hardware = get_hardware,
        version = fissure.utils.get_library_version()
    )

    # Update the List Widget
    for fg in sorted(all_demod_fgs,key=str.lower):
        dashboard.ui.listWidget_pd_flow_graphs_all_fgs.addItem(fg)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryBrowseChanged(dashboard: QtCore.QObject):
    """ 
    Loads a table from the Dashboard's cached version of the FISSURE PostgreSQL database.
    """
    # Clear the Table
    dashboard.ui.tableWidget1_library_browse.setRowCount(0)
    dashboard.ui.tableWidget1_library_browse.setColumnCount(0)

    # Populate the Table
    get_table_name = str(dashboard.ui.comboBox_library_browse.currentText())

    if get_table_name == "archive_collection":
        get_rows = fissure.utils.library.getArchiveCollection(dashboard.backend.library)
    elif get_table_name == "archive_favorites":
        get_rows = fissure.utils.library.getArchiveFavorites(dashboard.backend.library)
    elif get_table_name == "attack_categories":
        get_rows = fissure.utils.library.getAttackCategories(dashboard.backend.library)
    elif get_table_name == "attacks":
        get_rows = fissure.utils.library.getAttacks(dashboard.backend.library, None, None)
    elif get_table_name == "conditioner_flow_graphs":
        get_rows = fissure.utils.library.getConditionerFlowGraphsTable(dashboard.backend.library)
    elif get_table_name == "demodulation_flow_graphs":
        get_rows = fissure.utils.library.getDemodulationFlowGraphs(dashboard.backend.library)
    elif get_table_name == "detector_flow_graphs":
        get_rows = fissure.utils.library.getDetectorFlowGraphsTable(dashboard.backend.library)
    elif get_table_name == "inspection_flow_graphs":
        get_rows = fissure.utils.library.getInspectionFlowGraphs(dashboard.backend.library)
    elif get_table_name == "modulation_types":
        get_rows = fissure.utils.library.getModulationTypes(dashboard.backend.library)
    elif get_table_name == "packet_types":
        get_rows = fissure.utils.library.getPacketTypesTable(dashboard.backend.library)
    elif get_table_name == "protocols":
        get_rows = fissure.utils.library.getProtocolsTable(dashboard.backend.library)
    elif get_table_name == "soi_data":
        get_rows = fissure.utils.library.getSOIs(dashboard.backend.library, None)
    elif get_table_name == "triggers":
        get_rows = fissure.utils.library.getTriggersTable(dashboard.backend.library)
    else:
        return
    headers = fissure.utils.DATABASE_TABLE_HEADERS[get_table_name]

    # Create Rows and Columns
    dashboard.ui.tableWidget1_library_browse.setRowCount(len(get_rows))
    dashboard.ui.tableWidget1_library_browse.setColumnCount(len(get_rows[0]))
    
    # Add Headers
    for index, header in enumerate(headers):
        header_item = QtWidgets.QTableWidgetItem(header)
        header_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget1_library_browse.setHorizontalHeaderItem(index, header_item)

    # Add Items
    for r in range(0,len(get_rows)):
        for c in range(0,len(get_rows[0])):
            new_item = QtWidgets.QTableWidgetItem(str(get_rows[r][c]))
            new_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget1_library_browse.setItem(r,c, QtWidgets.QTableWidgetItem(new_item))

    # Resize the Table
    dashboard.ui.tableWidget1_library_browse.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryBrowsePgAdmin4_Clicked(dashboard: QtCore.QObject):
    """ 
    Opens a browser to pgAdmin 4 for viewing the FISSURE PostgreSQL database tables.
    """
    # Open a Browser
    os.system("xdg-open http://localhost:3000/browser/")


@qasync.asyncSlot(QtCore.QObject)
async def _slotLibraryBrowseDeleteRowClicked(dashboard: QtCore.QObject):
    """ 
    Sends a message to the HIPRFISR to delete a row in the database.
    """
    # Get Table and Row ID
    get_table_name = str(dashboard.ui.comboBox_library_browse.currentText())
    try:
        current_row = dashboard.ui.tableWidget1_library_browse.currentRow()
        get_row_id = str(dashboard.ui.tableWidget1_library_browse.item(current_row, 0).text())
    except:
        dashboard.logger.info("Select a table row to delete.")

    # Ask to Delete Row and then Files for Certain Tables
    delete_files = False
    ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(dashboard, "Delete row with id: " + get_row_id + "?")
    if ret == QtWidgets.QMessageBox.Yes:
        if get_table_name == "demodulation_flow_graphs":
            get_filename = str(dashboard.ui.tableWidget1_library_browse.item(current_row, 4).text())
            ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(dashboard, "Also delete filename: " + get_filename + "?")
            if ret == QtWidgets.QMessageBox.Yes:
                delete_files = True
        elif get_table_name == "inspection_flow_graphs":
            get_filename = str(dashboard.ui.tableWidget1_library_browse.item(current_row, 2).text())
            ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(dashboard, "Also delete files (.py & .grc) for: " + get_filename + "?")
            if ret == QtWidgets.QMessageBox.Yes:
                delete_files = True
        elif get_table_name == "soi_data":
            pass  # Delete IQ files
        elif get_table_name == "triggers":
            get_filename = str(dashboard.ui.tableWidget1_library_browse.item(current_row, 4).text())
            ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(dashboard, "Also delete filename: " + get_filename + "?")
            if ret == QtWidgets.QMessageBox.Yes:
                delete_files = True
        elif get_table_name == "attacks":
            get_filename = str(dashboard.ui.tableWidget1_library_browse.item(current_row, 6).text())
            ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(dashboard, "Also delete filename: " + get_filename + "?")
            if ret == QtWidgets.QMessageBox.Yes:
                delete_files = True

        # Send Message to HIPRFISR/Protocol Discovery
        if get_row_id is not None:
            await dashboard.backend.removeFromLibrary(get_table_name, get_row_id, delete_files)




########################################################################################

@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryPluginEditChanged(dashboard: QtCore.QObject):
    """
    Changes the table and stackedwidget page for viewing/editing plugins.
    """
    # Change Stacked Widget Pages
    get_table_name = str(dashboard.ui.comboBox_library_plugin_edit.currentText())

    if get_table_name == "archive_collection":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(0)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(0)
    elif get_table_name == "archive_favorites":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(1)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(1)
    elif get_table_name == "attack_categories":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(2)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(2)
    elif get_table_name == "attacks":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(3)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(3)
    elif get_table_name == "conditioner_flow_graphs":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(4)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(4)
    elif get_table_name == "demodulation_flow_graphs":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(5)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(5)
    elif get_table_name == "detector_flow_graphs":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(6)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(6)
    elif get_table_name == "inspection_flow_graphs":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(7)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(7)
    elif get_table_name == "modulation_types":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(8)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(8)
    elif get_table_name == "packet_types":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(9)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(9)
    elif get_table_name == "protocols":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(10)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(10)
    elif get_table_name == "soi_data":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(11)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(11)
    elif get_table_name == "triggers":
        dashboard.ui.stackedWidget_library_plugin_support.setCurrentIndex(12)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(12)
    else:
        return
    

@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryPluginAddRowClicked(dashboard: QtCore.QObject):
    """
    Adds a row to the current Edit Plugin table.
    """
    # Get the Current Page
    current_page = dashboard.ui.stackedWidget_library_plugin_tables.currentWidget()

    # Find the QTableWidget on the Current Page
    get_table = current_page.findChild(QtWidgets.QTableWidget)
    if get_table:
        # Add a New Empty Row
        row_count = get_table.rowCount()
        get_table.insertRow(row_count)

        # Resize the Table
        get_table.resizeRowsToContents()
    else:
        dashboard.logger.info("No QTableWidget found on the current page.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryPluginDeleteRowClicked(dashboard: QtCore.QObject):
    """
    Deletes a row from the current Edit Plugin table.
    """
    # Get the Current Page and Table Widget
    current_page = dashboard.ui.stackedWidget_library_plugin_tables.currentWidget()
    get_table = current_page.findChild(QtWidgets.QTableWidget)
    if get_table:
        # Get the Currently Selected Row
        selected_row = get_table.currentRow()

        # Check if a Valid Row is Selected
        if selected_row >= 0:
            # Remove the Row
            get_table.removeRow(selected_row)

            # Resize the Table
            get_table.resizeRowsToContents()

            # Select the Next Logical Row, if Any
            new_row = max(0, selected_row - 1)
            if get_table.rowCount() > 0:
                get_table.setCurrentCell(new_row, 0)
        else:
            dashboard.logger.info("No row selected!")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryPluginClearTableClicked(dashboard: QtCore.QObject):
    """
    Clears the current Edit Plugin table.
    """
    # Remove All Rows
    current_page = dashboard.ui.stackedWidget_library_plugin_tables.currentWidget()
    get_table = current_page.findChild(QtWidgets.QTableWidget)
    if get_table:
        get_table.setRowCount(0)
    else:
        dashboard.logger.info("No QTableWidget found on the current page.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryPluginClearAllTablesClicked(dashboard: QtCore.QObject):
    """
    Clears all the Edit Plugin tables.
    """
    # Iterate through all Pages in the Stacked Widget
    for index in range(dashboard.ui.stackedWidget_library_plugin_tables.count()):
        page = dashboard.ui.stackedWidget_library_plugin_tables.widget(index)
        
        # Find all QTableWidget Instances on the Current Page
        tables = page.findChildren(QtWidgets.QTableWidget)
        for table in tables:
            # Clear all Rows in the Table
            table.setRowCount(0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryBrowseCopyClicked(dashboard: QtCore.QObject):
    """
    Copies the selected row from a table in the Browse tab to an Edit Plugin table.
    """  
    # Check If a Row Is Selected in the Source Table
    selected_items = dashboard.ui.tableWidget1_library_browse.selectedItems()
    if not selected_items:
        dashboard.logger.info("No row selected in the Browse table.")
        return

    # Get the Selected Row Index
    selected_row = selected_items[0].row()

    # Copy the Row Data from the Source Table
    row_data = [
        dashboard.ui.tableWidget1_library_browse.item(selected_row, col).text() if dashboard.ui.tableWidget1_library_browse.item(selected_row, col) else ""
        for col in range(dashboard.ui.tableWidget1_library_browse.columnCount())
    ]
    
    # Get the Target Table via the Combobox and Stacked Widget
    target_page_index = dashboard.ui.comboBox_library_browse.currentIndex()
    target_page = dashboard.ui.stackedWidget_library_plugin_tables.widget(target_page_index)
    target_table = target_page.findChild(QtWidgets.QTableWidget)

    if not target_table:
        dashboard.logger.error("Target table not found.")
        return

    # Append the Copied Row Data to the Target Table
    target_table.insertRow(target_table.rowCount())
    for col, data in enumerate(row_data):
        item = QtWidgets.QTableWidgetItem(data)
        item.setTextAlignment(QtCore.Qt.AlignCenter)
        target_table.setItem(target_table.rowCount() - 1, col, item)
    
    # Resize Rows to Fit Content
    target_table.resizeRowsToContents()


# @qasync.asyncSlot(QtCore.QObject)
# async def _slotLibraryPluginImportClicked(dashboard: QtCore.QObject):
#     """
#     Imports a plugin from a ZIP file into the FISSURE system.

#     Steps:
#     1. Opens a file dialog for the user to select a ZIP file.
#     2. Checks if the selected ZIP file requires a password.
#        - If a password is required, prompts the user via a GUI input dialog.
#     3. Creates the plugin directory if it does not already exist.
#     4. Extracts the ZIP contents, handling password-protected archives.
#     5. Moves extracted files to the correct plugin directory.
#     6. Opens the plugin in the FISSURE system.
#     7. Prompts the user to apply changes to save the imported plugin.
#     """

#     # Select a .zip
#     file_path = await fissure.Dashboard.UI_Components.Qt5.async_open_file_dialog(dashboard, ".", "ZIP Files (*.zip)")
#     if not file_path:
#         return  # User canceled file selection

#     plugin_name = os.path.basename(file_path).replace(".zip", "")
#     plugins_root = os.path.join(fissure.utils.FISSURE_ROOT, "Plugins")
#     new_folder = os.path.join(plugins_root, plugin_name)

#     if os.path.exists(new_folder):
#         return  # Plugin folder already exists, do not proceed

#     # Step 1: Check if ZIP requires a password
#     password = None
#     test_cmd = ["7z", "t", file_path, "-p"]
    
#     try:
#         proc = await asyncio.create_subprocess_exec(
#             *test_cmd,
#             stdout=asyncio.subprocess.DEVNULL,  # Suppress normal output
#             stderr=asyncio.subprocess.PIPE  # Capture errors only
#         )
#         _, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)

#     except asyncio.TimeoutError:
#         return  # Exit if 7z test command hangs

#     # Check if the ZIP is password-protected
#     stderr_output = stderr.decode().strip()
#     if "Wrong password" in stderr_output or "Can not open encrypted archive" in stderr_output or "Data Error" in stderr_output:
#         password = await fissure.Dashboard.UI_Components.Qt5.async_input_dialog(dashboard, "Enter ZIP password:", "Password Required")
#         if not password:
#             return  # User canceled password input

#     # Step 2: Create the plugin directory in the system
#     dashboard.ui.comboBox_library_plugin_new_existing.setCurrentIndex(1)
#     dashboard.ui.textEdit_library_plugin_plugin_name.setPlainText(plugin_name)
#     await _slotLibraryPluginCreate(dashboard, open_after_create=False)

#     # Step 3: Extract ZIP after plugin creation
#     temp_extract_path = os.path.join(plugins_root, f"{plugin_name}_temp")
#     os.makedirs(temp_extract_path, exist_ok=True)

#     try:
#         extract_cmd = ["7z", "x", file_path, f"-o{temp_extract_path}", "-y"]
#         if password:
#             extract_cmd.append(f"-p{password}")

#         proc = await asyncio.create_subprocess_exec(
#             *extract_cmd,
#             stdout=asyncio.subprocess.DEVNULL,  # Suppress normal output
#             stderr=asyncio.subprocess.PIPE
#         )

#         _, stderr = await proc.communicate()
#         stderr_output = stderr.decode().strip()

#         if "Wrong password" in stderr_output or "Can not open encrypted archive" in stderr_output:
#             return  # Exit if incorrect password

#         # Step 4: Move extracted files to the plugin directory
#         extracted_folder = None
#         for root, dirs, _ in os.walk(temp_extract_path):
#             if "install_files" in dirs and "tables" in dirs:
#                 extracted_folder = root
#                 break

#         if extracted_folder:
#             for item in os.listdir(extracted_folder):
#                 src_path = os.path.join(extracted_folder, item)
#                 dest_path = os.path.join(new_folder, item)
#                 if os.path.isdir(src_path):
#                     shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
#                 else:
#                     shutil.copy2(src_path, dest_path)
#         else:
#             return  # Exit if required folders are missing

#         shutil.rmtree(temp_extract_path)  # Remove temporary extraction folder

#     except asyncio.TimeoutError:
#         return  # Exit if 7z extraction times out
#     except Exception:
#         return  # Exit on unexpected extraction failure

#     # Step 5: Open the Plugin
#     await _slotLibraryPluginOpenClose(dashboard)

#     # Step 6: Prompt user to save changes
#     await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, 'Click "Apply Changes" to save to database.')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryPluginExportTablesClicked(dashboard: QtCore.QObject):
    """
    Exports the tables and files to a tables directory.
    """
    # Prompt the user to select a directory for saving the CSV files
    folder_path = QtWidgets.QFileDialog.getExistingDirectory(
        None, "Select Directory to Save Tables"
    )
    if not folder_path:
        # QtWidgets.QMessageBox.warning(None, "Export Canceled", "No folder selected. Operation aborted.")
        return

    # Ensure the "tables" subdirectory exists
    tables_dir = os.path.join(folder_path, "tables")
    os.makedirs(tables_dir, exist_ok=True)

    # Iterate over the ComboBox items
    for index in range(dashboard.ui.comboBox_library_plugin_edit.count()):
        table_name = dashboard.ui.comboBox_library_plugin_edit.itemText(index)
        dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(index)
        current_page = dashboard.ui.stackedWidget_library_plugin_tables.currentWidget()

        # Find the table widget on the current page
        target_table = current_page.findChild(QtWidgets.QTableWidget)
        if not target_table:
            continue  # Skip if no table is found

        # Check if the table is populated
        if target_table.rowCount() == 0 or target_table.columnCount() == 0:
            continue

        populated = any(
            target_table.item(row, col) is not None and target_table.item(row, col).text().strip() != ""
            for row in range(target_table.rowCount())
            for col in range(target_table.columnCount())
        )
        if not populated:
            continue  # Skip empty tables

        # Define the CSV file path
        csv_filename = f"{table_name}.csv"
        csv_filepath = os.path.join(tables_dir, csv_filename)

        # Export the table data to a CSV file
        try:
            with open(csv_filepath, mode="w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)

                # Write the table headers as the first row
                headers = [
                    target_table.horizontalHeaderItem(col).text() if target_table.horizontalHeaderItem(col) else ""
                    for col in range(target_table.columnCount())
                ]
                writer.writerow(headers)

                # Write each row of the table
                for row in range(target_table.rowCount()):
                    row_data = [
                        target_table.item(row, col).text() if target_table.item(row, col) else ""
                        for col in range(target_table.columnCount())
                    ]
                    writer.writerow(row_data)

        except Exception as e:
            QtWidgets.QMessageBox.critical(
                None,
                "Error",
                f"Failed to export table '{csv_filename}': {str(e)}",
            )
            continue

    QtWidgets.QMessageBox.information(None, "Export Complete", "Tables successfully exported!")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryPluginExportZipClicked(dashboard: QtCore.QObject):
    """
    Exports the plugin to zip file with optional password.
    """
    # Get the selected plugin name from the combobox
    selected_plugin = dashboard.ui.comboBox_library_plugin_selection.currentText()
    if not selected_plugin:
        # QtWidgets.QMessageBox.warning(None, "Error", "No plugin selected.")
        return

    # Construct the full path to the plugins folder
    plugins_root = os.path.join(fissure.utils.FISSURE_ROOT, "Plugins")
    plugin_folder = os.path.join(plugins_root, selected_plugin)
    if not os.path.exists(plugin_folder):
        QtWidgets.QMessageBox.critical(None, "Error", f"Plugin folder '{plugin_folder}' does not exist.")
        return

    # Prompt the user to save the ZIP file
    save_path, _ = QtWidgets.QFileDialog.getSaveFileName(
        None, "Save ZIP File", f"{selected_plugin}.zip", "ZIP Files (*.zip)"
    )
    if not save_path:
        QtWidgets.QMessageBox.warning(None, "Operation Canceled", "No save location selected.")
        return
    
    # Derive the internal folder name from the saved filename
    zip_root_name = os.path.splitext(os.path.basename(save_path))[0]

    # Ensure the save path ends with .zip
    if not save_path.lower().endswith(".zip"):
        save_path += ".zip"

    # Ask if the user wants to set a password
    password, ok = QtWidgets.QInputDialog.getText(
        None, "Set Password (Optional)", "Enter password for ZIP file (leave empty for no password):",
        QtWidgets.QLineEdit.Password
    )
    if not ok:
        QtWidgets.QMessageBox.warning(None, "Operation Canceled", "Password prompt canceled.")
        return

    try:
        # Create the ZIP file
        with pyzipper.AESZipFile(save_path, 'w', compression=pyzipper.ZIP_DEFLATED) as zipf:
            if password:
                zipf.setpassword(password.encode())
                zipf.setencryption(pyzipper.WZ_AES)

            # Walk through the selected plugin folder and add files to the zip
            for root, _, files in os.walk(plugin_folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, plugin_folder)
                    arcname = os.path.join(zip_root_name, rel_path)
                    zipf.write(file_path, arcname)

        QtWidgets.QMessageBox.information(None, "Success", f"Plugin '{selected_plugin}' successfully zipped to {save_path}")

    except Exception as e:
        QtWidgets.QMessageBox.critical(None, "Error", f"Failed to create ZIP file: {e}")


# @qasync.asyncSlot(QtCore.QObject)
# async def _slotLibraryPluginApplyChangesClicked(dashboard: QtCore.QObject):
#     """
#     Applies changes to existing plugins by copying all the table data and overwriting the csv files at the HIPRFISR.
#     """
#     # Gather Table Data
#     table_data = {}

#     # Iterate through each page of the stacked widget
#     for page_index in range(dashboard.ui.stackedWidget_library_plugin_tables.count()):
#         page = dashboard.ui.stackedWidget_library_plugin_tables.widget(page_index)  # Get the page at index
#         target_table = page.findChild(QtWidgets.QTableWidget)  # Find the QTableWidget in the page
        
#         if target_table:
#             database_table_name = str(dashboard.ui.comboBox_library_plugin_edit.itemText(page_index))
            
#             # Extract column headers
#             headers = [target_table.horizontalHeaderItem(col).text() for col in range(target_table.columnCount())]
            
#             # Extract table rows
#             rows = []
#             rows.append(headers)
#             for row in range(target_table.rowCount()):
#                 row_data = [target_table.item(row, col).text() if target_table.item(row, col) else "" for col in range(target_table.columnCount())]
#                 rows.append(row_data)
            
#             # Store data in a dictionary with table_name as key
#             # table_data[table_name] = {"headers": headers, "rows": rows}
#             table_data[database_table_name] = {"rows": rows}
    
#     # Convert the dictionary to JSON format for easy transfer (if needed)
#     table_data_json = json.dumps(table_data)

#     # Gather Supporting Files
#     supporting_files_data = {}

#     # Iterate through each page of the stacked widget
#     for page_index in range(dashboard.ui.stackedWidget_library_plugin_support.count()):
#         page = dashboard.ui.stackedWidget_library_plugin_support.widget(page_index)  # Get the page at index
#         target_table = page.findChild(QtWidgets.QTableWidget)  # Find the QTableWidget in the page
        
#         if target_table:
#             database_table_name = str(dashboard.ui.comboBox_library_plugin_edit.itemText(page_index))
            
#             rows = []
#             for row in range(target_table.rowCount()):
#                 # First column: Filepath string
#                 filepath = target_table.item(row, 0).text() if target_table.item(row, 0) else ""

#                 # Second column: Combobox value
#                 combobox = target_table.cellWidget(row, 1)
#                 combobox_value = str(combobox.currentText()) if isinstance(combobox, QtWidgets.QComboBox) else ""

#                 # Third column: New filepath string
#                 new_filepath = target_table.item(row, 2).text() if target_table.item(row, 2) else ""

#                 # Append the row data to the list
#                 rows.append({"filepath": filepath, "action": combobox_value, "new_filepath": new_filepath})
            
#             # Store rows data under the page name
#             supporting_files_data[database_table_name] = rows

#     # Convert the dictionary to JSON format for easy transfer (if needed)
#     supporting_files_data_json = json.dumps(supporting_files_data, indent=4)

#     await dashboard.backend.pluginApplyChanges(table_data_json, supporting_files_data_json)
    

@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryPluginNewExistingChanged(dashboard: QtCore.QObject):
    """Change Plugin Selector or Creator

    Parameters
    ----------
    dashboard : QtCore.QObject
        FISSURE Dashboard
    """
    comboBox_library_plugin_new_existing: QtWidgets.QComboBox = dashboard.ui.comboBox_library_plugin_new_existing
    stackedWidget_library_plugin_selection: QtWidgets.QStackedWidget = dashboard.ui.stackedWidget_library_plugin_selection
    if comboBox_library_plugin_new_existing.currentText() == "Existing":
        stackedWidget_library_plugin_selection.setCurrentIndex(0)
        if dashboard.ui.pushButton_library_plugin_selection_open_close.text() == "Close Plugin":
            dashboard.ui.frame1_library_plugin_edit_plugin.setEnabled(True)
            dashboard.ui.label1_library_plugin_edit_plugin.setEnabled(True)
        else:
            dashboard.ui.frame1_library_plugin_edit_plugin.setEnabled(False)
            dashboard.ui.label1_library_plugin_edit_plugin.setEnabled(False)    
    elif comboBox_library_plugin_new_existing.currentText() == "New":
        stackedWidget_library_plugin_selection.setCurrentIndex(1)
        dashboard.ui.frame1_library_plugin_edit_plugin.setEnabled(False)
        dashboard.ui.label1_library_plugin_edit_plugin.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLibraryPluginAppendClicked(dashboard: QtCore.QObject):
    """
    Imports a plugin and appends it to an existing plugin but does not create a new plugin.
    """
    # Open File Dialog to Select a ZIP File
    file_path, _ = QtWidgets.QFileDialog.getOpenFileName(
        None,
        "Select Plugin ZIP File",
        "",
        "ZIP Files (*.zip)",
        options=QtWidgets.QFileDialog.Options(),
    )

    if not file_path:
        return  # User canceled

    extracted_path = None
    password = None  # For password-protected ZIP files

    # Check if the Selected File is a ZIP File
    try:
        with pyzipper.AESZipFile(file_path, 'r') as zf:
            # If password is required, prompt user
            if zf.pwd is None:
                # No password required
                password = ""
            else:
                # Prompt for password
                password, ok = QtWidgets.QInputDialog.getText(
                    None,
                    "Password Required",
                    "Enter password for ZIP archive:",
                    QtWidgets.QLineEdit.Password
                )
                if not ok:  # User canceled
                    QtWidgets.QMessageBox.warning(
                        None, "Import Canceled", "Password not provided. Operation aborted."
                    )
                    return

                if password:
                    zf.setpassword(password.encode())
                else:
                    # If no password provided, but a password is required, return
                    QtWidgets.QMessageBox.warning(
                        None, "Password Error", "No password provided for a password-protected ZIP file."
                    )
                    return

            # Define the extraction path
            extracted_path = os.path.join(os.path.dirname(file_path), "temp_extracted")
            os.makedirs(extracted_path, exist_ok=True)

            # Extract all files and directories
            for file_info in zf.infolist():
                try:
                    # Construct full file path
                    file_path = os.path.join(extracted_path, file_info.filename)
                    if file_info.is_dir():
                        os.makedirs(file_path, exist_ok=True)  # Create directory
                    else:
                        os.makedirs(os.path.dirname(file_path), exist_ok=True)  # Create parent directories
                        with open(file_path, "wb") as f:
                            f.write(zf.read(file_info.filename))  # Write file content
                except RuntimeError as e:
                    QtWidgets.QMessageBox.critical(
                        None, "Error", f"Failed to extract {file_info.filename}: {e}"
                    )
                    continue
    except (pyzipper.BadZipFile, RuntimeError) as e:
        QtWidgets.QMessageBox.critical(None, "Error", f"Failed to process ZIP file: {e}")
        return

    # Look for 'tables' folder anywhere under extracted_path
    tables_path = None
    for root, dirs, _ in os.walk(extracted_path):
        if "tables" in dirs:
            tables_path = os.path.join(root, "tables")
            print(f"'tables' folder found at: {tables_path}")
            break  # Stop after finding the first occurrence of 'tables'

    # Handle case where no 'tables' folder is found
    if not tables_path:
        print("No 'tables' folder found.")
        QtWidgets.QMessageBox.critical(None, "Error", "The selected plugin does not contain a 'tables' folder.")
        return
    else:
        print(f"Proceeding with 'tables' folder at: {tables_path}")

    # Iterate Over CSV Files in the 'tables' Folder
    for file_name in os.listdir(tables_path):
        if file_name.endswith(".csv"):
            table_name = os.path.splitext(file_name)[0]

            # Match Table to ComboBox Item
            current_combobox_index = dashboard.ui.comboBox_library_plugin_edit.findText(table_name)
            if current_combobox_index == -1:
                QtWidgets.QMessageBox.warning(None, "Warning", f"No matching table found for: {table_name}")
                continue

            # Get Corresponding Table Widget
            dashboard.ui.stackedWidget_library_plugin_tables.setCurrentIndex(current_combobox_index)
            current_page = dashboard.ui.stackedWidget_library_plugin_tables.currentWidget()
            target_table = current_page.findChild(QtWidgets.QTableWidget)

            if target_table:
                # Append Data from CSV File to the Table
                csv_file_path = os.path.join(tables_path, file_name)
                with open(csv_file_path, "r", newline="") as csv_file:
                    reader = csv.reader(csv_file)

                    # Skip the first row (header)
                    next(reader, None)  # This skips the first row

                    # Iterate over the rest of the rows and append data to the table
                    for row in reader:
                        target_row = target_table.rowCount()
                        target_table.insertRow(target_row)
                        for col_index, value in enumerate(row):
                            item = QtWidgets.QTableWidgetItem(value)
                            item.setTextAlignment(QtCore.Qt.AlignCenter)
                            target_table.setItem(target_row, col_index, item)

    # Cleanup: Remove temporary extracted files
    if os.path.isdir(extracted_path) and "temp_extracted" in extracted_path:
        shutil.rmtree(extracted_path, ignore_errors=True)

    # Notify User of Success
    QtWidgets.QMessageBox.information(None, "Success", "Data successfully appended to tables!")


# @qasync.asyncSlot(QtCore.QObject)
# async def _slotLibraryPluginCreate(dashboard: QtCore.QObject, open_after_create=True):
#     """
#     Creates a new empty plugin at the HIPRFISR and prepares the Plugin Editor for editing.
#     """
#     # Get plugin name
#     plugin_name = dashboard.ui.textEdit_library_plugin_plugin_name.toPlainText()

#     if len(plugin_name) > 0:
#         # Open editor on hiprfisr to create plugin
#         await dashboard.backend.openPluginHiprfisr(plugin_name)

#         # Refresh the List
#         await _slotLibraryPluginPluginRefresh(dashboard)

#         # Wait up to 5 seconds for the plugin to appear
#         comboBox = dashboard.ui.comboBox_library_plugin_selection
#         timeout = 5  # seconds
#         elapsed = 0
#         check_interval = 0.2  # seconds
#         timeout_triggered = False

#         while elapsed < timeout:
#             QApplication.processEvents()  # Process UI updates
#             plugin_names = [comboBox.itemText(i) for i in range(comboBox.count())]

#             if plugin_name in plugin_names:
#                 comboBox.setCurrentText(plugin_name)
#                 break  # Exit loop once the plugin is found

#             await asyncio.sleep(check_interval)  # Wait before retrying
#             elapsed += check_interval

#         if elapsed >= timeout:
#             dashboard.logger.debug(f"Timeout: Plugin '{plugin_name}' not found after {timeout} seconds.")
#             timeout_triggered = True

#         # Switch UI to show existing plugin
#         dashboard.ui.textEdit_library_plugin_plugin_name.setPlainText("")
#         dashboard.ui.comboBox_library_plugin_new_existing.setCurrentText("Existing")
#         dashboard.ui.stackedWidget_library_plugin_selection.setCurrentIndex(0)

#         # Open Plugin
#         if timeout_triggered == False:
#             if open_after_create == True:
#                 await _slotLibraryPluginOpenClose(dashboard)


# @qasync.asyncSlot(QtCore.QObject)
# async def _slotLibraryPluginOpenClose(dashboard: QtCore.QObject):
#     """
#     Opens and closes a plugin at the HIPRFISR to retrieve and edit plugin data.
#     """
#     # UI objects
#     pushButton_library_plugin_selection_open_close: QtWidgets.QPushButton = dashboard.ui.pushButton_library_plugin_selection_open_close
#     comboBox_library_plugin_new_existing: QtWidgets.QComboBox = dashboard.ui.comboBox_library_plugin_new_existing

#     if pushButton_library_plugin_selection_open_close.text() == "Open Plugin":
#         # Open editor on hiprfisr
#         await dashboard.backend.openPluginHiprfisr(dashboard.ui.comboBox_library_plugin_selection.currentText())

#         # Disable plugin selection boxes
#         comboBox_library_plugin_new_existing.setEnabled(False)
#         dashboard.ui.comboBox_library_plugin_selection.setEnabled(False)
#         dashboard.ui.pushButton_library_plugin_refresh.setEnabled(False)
#         dashboard.ui.pushButton_library_plugin_delete.setEnabled(False)

#         # Change button text
#         pushButton_library_plugin_selection_open_close.setText("Close Plugin")

#         # Enable Edit Plugin Widgets
#         dashboard.ui.frame1_library_plugin_edit_plugin.setEnabled(True)
#         dashboard.ui.label1_library_plugin_edit_plugin.setEnabled(True)        

#     else:
#         # Close editor on hiprfisr
#         await dashboard.backend.closePluginHiprfisr()

#         # Enable plugin selection boxes
#         comboBox_library_plugin_new_existing.setEnabled(True)
#         dashboard.ui.comboBox_library_plugin_selection.setEnabled(True)
#         dashboard.ui.pushButton_library_plugin_refresh.setEnabled(True)
#         dashboard.ui.pushButton_library_plugin_delete.setEnabled(True)

#         # Change button text
#         pushButton_library_plugin_selection_open_close.setText("Open Plugin")

#         # Disable Edit Plugin Widgets
#         dashboard.ui.frame1_library_plugin_edit_plugin.setEnabled(False)
#         dashboard.ui.label1_library_plugin_edit_plugin.setEnabled(False)

#         # Clear the Tables
#         for page_index in range(dashboard.ui.stackedWidget_library_plugin_tables.count()):
#             page = dashboard.ui.stackedWidget_library_plugin_tables.widget(page_index)  # Get the page at index
#             target_table = page.findChild(QtWidgets.QTableWidget)  # Find the QTableWidget in the page
            
#             if target_table:
#                 # Set the row count to zero to clear the table
#                 target_table.setRowCount(0)

#         # Clear the Supporting Files
#         for page_index in range(dashboard.ui.stackedWidget_library_plugin_support.count()):
#             page = dashboard.ui.stackedWidget_library_plugin_support.widget(page_index)  # Get the page at index
#             target_table = page.findChild(QtWidgets.QTableWidget)  # Find the QTableWidget in the page
            
#             if target_table:
#                 # Set the row count to zero to clear the table
#                 target_table.setRowCount(0)


# @qasync.asyncSlot(QtCore.QObject)
# async def _slotLibraryPluginPluginRefresh(dashboard: QtCore.QObject):
#     """
#     Queries the HIPRFISR and refreshes the combobox of plugins.
#     """
#     # Send the Message
#     await dashboard.backend.requestPluginNamesHiprfisr()


# @qasync.asyncSlot(QtCore.QObject)
# async def _slotLibraryPluginPluginDelete(dashboard: QtCore.QObject):
#     """
#     Deletes a plugin from the Plugin directory.
#     """
#     # Ask the user for confirmation
#     plugin_name = dashboard.ui.comboBox_library_plugin_selection.currentText()
#     if plugin_name:
#         ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(
#             dashboard,
#             f"Are you sure you want to delete the plugin '{plugin_name}'?"
#         )
#         if ret == QtWidgets.QMessageBox.Yes:
#             pass
#         else:
#             return

#         # Ask the user to delete files from library
#         ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(
#             dashboard,
#             "The plugin folder will be removed. Do you also want to remove all associated plugin data from the library and database?"
#         )
#         if ret == QtWidgets.QMessageBox.Yes:
#             delete_from_library = True
#         else:
#             delete_from_library = False
            
#         # Send the Message
#         await dashboard.backend.pluginDelete(plugin_name, delete_from_library)

    
# @QtCore.pyqtSlot(QtCore.QObject)
# def _slotLibraryPluginSupportAddClicked(dashboard: QtCore.QObject):
#     """
#     Adds a new empty row to the Supporting Files table.
#     """
#     # Get the Current Page
#     current_page = dashboard.ui.stackedWidget_library_plugin_support.currentWidget()

#     # Find the QTableWidget on the Current Page
#     get_table = current_page.findChild(QtWidgets.QTableWidget)
#     if get_table:
#         # Add a new row to the table
#         row_position = get_table.rowCount()
#         get_table.insertRow(row_position)
        
#         # Add the filepath as a new item
#         filepath_item = QtWidgets.QTableWidgetItem("")
#         filepath_item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
#         filepath_item.setFlags(filepath_item.flags() & ~QtCore.Qt.ItemIsEditable)
#         get_table.setItem(row_position, 0, filepath_item)

#         # Action Comboboxes
#         new_action_combobox = QtWidgets.QComboBox(get_table, objectName='comboBox2_')
#         new_action_combobox.setFixedSize(73, 23)
#         get_table.setCellWidget(row_position, 1, new_action_combobox)
#         new_action_combobox.addItem("Keep")
#         new_action_combobox.addItem("Replace")
#         new_action_combobox.addItem("Delete")
#         new_action_combobox.setCurrentIndex(0)
#         new_action_combobox.setEnabled(False)

#         new_pushbutton = QtWidgets.QPushButton(get_table, objectName='pushButton_')
#         new_pushbutton.setText("...")
#         new_pushbutton.setFixedSize(36, 23)
#         get_table.setCellWidget(row_position, 3, new_pushbutton)
#         new_pushbutton.clicked.connect(lambda checked, table=get_table, row=row_position: _slotLibraryPluginSupportFileSelectionClicked(dashboard, table, row))
#         get_table.resizeRowsToContents()
#     else:
#         dashboard.logger.info("No QTableWidget found on the current page.")


# @QtCore.pyqtSlot(QtCore.QObject)
# def _slotLibraryPluginSupportFileSelectionClicked(dashboard: QtCore.QObject, target_table, row_position):
#     file_dialog = QtWidgets.QFileDialog()
#     file_dialog.setFileMode(QtWidgets.QFileDialog.ExistingFile)
#     file_dialog.setDirectory(fissure.utils.FISSURE_ROOT)
#     selected_file, _ = file_dialog.getOpenFileName()
#     if selected_file:
#         # Place the selected file in the correct row and column (assume column 2)
#         new_file_item = QtWidgets.QTableWidgetItem(selected_file)
#         new_file_item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
#         target_table.setItem(row_position, 2, new_file_item)


# @QtCore.pyqtSlot(QtCore.QObject)
# def _slotLibraryPluginSupportDeleteClicked(dashboard: QtCore.QObject):
#     """
#     Deletes a newly added row in the Supporting Files table or clears the New Column if Existing is populated.
#     """
#     # Get the Current Page and Table Widget
#     current_page = dashboard.ui.stackedWidget_library_plugin_support.currentWidget()
#     get_table = current_page.findChild(QtWidgets.QTableWidget)
#     if get_table:
#         # Get the Currently Selected Row
#         selected_row = get_table.currentRow()

#         # Check if a Valid Row is Selected
#         if selected_row >= 0:
#             get_item = get_table.item(selected_row, 0)
#             if get_item and get_item.text() != "":
#                 # Clear New
#                 new_file_item = QtWidgets.QTableWidgetItem("")
#                 new_file_item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
#                 get_table.setItem(selected_row, 2, new_file_item)
#             else:
#                 # Remove the Row
#                 get_table.removeRow(selected_row)

#             # Select the Next Logical Row, if Any
#             new_row = max(0, selected_row - 1)
#             if get_table.rowCount() > 0:
#                 get_table.setCurrentCell(new_row, 0)
#         else:
#             dashboard.logger.info("No row selected!")


# @QtCore.pyqtSlot(QtCore.QObject)
# def _slotLibraryPluginSupportResetClicked(dashboard: QtCore.QObject):
#     """
#     Resets all new rows and new column items in the current Supporting Files table.
#     """
#     # Get the Current Page and Table Widget
#     current_page = dashboard.ui.stackedWidget_library_plugin_support.currentWidget()
#     get_table = current_page.findChild(QtWidgets.QTableWidget)
#     if get_table:
#         for row in reversed(range(0, get_table.rowCount())):
#             if row >= 0:
#                 get_item = get_table.item(row, 0)
#                 if get_item and get_item.text() != "":
#                     # Clear New
#                     new_file_item = QtWidgets.QTableWidgetItem("")
#                     new_file_item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
#                     get_table.setItem(row, 2, new_file_item)

#                     # Reset Combobox
#                     combo_box = get_table.cellWidget(row, 1)  # Get the combobox from the table
#                     if combo_box:
#                         combo_box.setCurrentIndex(0) 
#                 else:
#                     # Remove the Row
#                     get_table.removeRow(row)


# @QtCore.pyqtSlot(QtCore.QObject)
# def _slotLibraryPluginSupportResetAllClicked(dashboard: QtCore.QObject):
#     """
#     Resets all new rows and new column items in all Supporting Files tables.
#     """
#     # Iterate through all Pages in the Stacked Widget
#     for index in range(dashboard.ui.stackedWidget_library_plugin_support.count()):
#         page = dashboard.ui.stackedWidget_library_plugin_support.widget(index)
        
#         # Find all QTableWidget Instances on the Current Page
#         tables = page.findChildren(QtWidgets.QTableWidget)
#         for table in tables:
#             for row in reversed(range(0, table.rowCount())):
#                 if row >= 0:
#                     get_item = table.item(row, 0)
#                     if get_item and get_item.text() != "":
#                         # Clear New
#                         new_file_item = QtWidgets.QTableWidgetItem("")
#                         new_file_item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
#                         table.setItem(row, 2, new_file_item)

#                         # Reset Combobox
#                         combo_box = table.cellWidget(row, 1)  # Get the combobox from the table
#                         if combo_box:
#                             combo_box.setCurrentIndex(0) 
#                     else:
#                         # Remove the Row
#                         table.removeRow(row)


@qasync.asyncSlot(QtCore.QObject)
async def _slotLibraryBrowseRefreshClicked(dashboard: QtCore.QObject):
    """
    Refreshes the Dashboard database cache.
    """
    # Send the Message
    await dashboard.backend.retrieveDatabaseCache(refresh_frontend_widgets=True)
    