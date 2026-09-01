from PyQt5 import QtCore, QtWidgets, QtGui
import os
import fissure.utils
import qasync
import yaml
import shutil


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


@qasync.asyncSlot(QtCore.QObject)
async def _slotLibraryBrowseRefreshClicked(dashboard: QtCore.QObject):
    """
    Refreshes the Dashboard database cache.
    """
    # Send the Message
    await dashboard.backend.retrieveDatabaseCache(refresh_frontend_widgets=True)
    