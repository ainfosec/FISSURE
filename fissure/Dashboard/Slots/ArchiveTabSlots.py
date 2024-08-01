from PyQt5 import QtCore, QtWidgets
import random
import os
import fissure.utils
import csv
import datetime
import time
import subprocess
import qasync
from ..UI_Components import TriggersDialog
from fissure.Dashboard.UI_Components.Qt5 import MyMessageBox

@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Reloads the files in the current Archive folder
    """
    # Get the Folder Location
    get_folder = dashboard.ui.listView_archive.model().rootPath()

    # Get the Extension Filter
    get_extension = str(dashboard.ui.comboBox_archive_extension.currentText())
    if get_extension == "All":
        filters = ['*']
    elif get_extension == "Custom":
        get_custom_extension = str(dashboard.ui.textEdit_archive_extension.toPlainText())
        filters = ['*' + get_custom_extension]
    else:
        filters = ['*' + get_extension]

    # Reset ListView
    #path = QtCore.QDir.rootPath()  #get_folder
    model = QtWidgets.QFileSystemModel(nameFilterDisables=False)
    model.setRootPath(get_folder)
    model.setFilter(QtCore.QDir.NoDot|QtCore.QDir.AllDirs|QtCore.QDir.Files)
    model.setNameFilters(filters)
    dashboard.ui.listView_archive.setModel(model)
    dashboard.ui.listView_archive.setRootIndex(model.index(get_folder))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadFolderChanged(dashboard: QtCore.QObject):
    """ 
    Changes the folder displayed in the ListView.
    """
    # Get the Folder Location
    get_folder = str(dashboard.ui.comboBox3_archive_download_folder.currentText())

    # Get the Extension Filter
    get_extension = str(dashboard.ui.comboBox_archive_extension.currentText())
    if get_extension == "All":
        filters = ['*']
    elif get_extension == "Custom":
        get_custom_extension = str(dashboard.ui.textEdit_archive_extension.toPlainText())
        filters = ['*' + get_custom_extension]
    else:
        filters = ['*' + get_extension]

    # Reset ListView
    #path = QtCore.QDir.rootPath()  #get_folder
    model = QtWidgets.QFileSystemModel(nameFilterDisables=False)
    model.setRootPath(get_folder)
    model.setFilter(QtCore.QDir.NoDot|QtCore.QDir.AllDirs|QtCore.QDir.Files)
    model.setNameFilters(filters)
    dashboard.ui.listView_archive.setModel(model)
    dashboard.ui.listView_archive.setRootIndex(model.index(get_folder))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveExtensionChanged(dashboard: QtCore.QObject):
    """ 
    Enables/disables the custom extension field in the Archive tab.
    """
    # Refresh
    if str(dashboard.ui.comboBox_archive_extension.currentText()) == "Custom":
        dashboard.ui.textEdit_archive_extension.setEnabled(True)
    else:
        dashboard.ui.textEdit_archive_extension.setEnabled(False)
        _slotArchiveDownloadRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Changes the Archive replay settings based on hardware.
    """
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_archive_replay_hardware.currentText())
    get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = dashboard.hardwareDisplayNameLookup(get_current_hardware,'archive')
    
    # Adjust Existing Channel ComboBoxes and Gain in Replay Tab
    for n in range(0, dashboard.ui.tableWidget_archive_replay.rowCount()):
        get_combobox = dashboard.ui.tableWidget_archive_replay.cellWidget(n,6)
        get_combobox.clear()
        if get_hardware_type == "Computer":
            get_combobox.addItem("")
        elif get_hardware_type == "USRP X3x0":
            get_combobox.addItem("A:0")
            get_combobox.addItem("B:0")
            gain_item = QtWidgets.QTableWidgetItem("30")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "USRP B2x0":
            get_combobox.addItem("A:A")
            get_combobox.addItem("A:B")
            gain_item = QtWidgets.QTableWidgetItem("60")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "HackRF":
            get_combobox.addItem("")
            gain_item = QtWidgets.QTableWidgetItem("20")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "RTL2832U":
            get_combobox.addItem("")
        elif get_hardware_type == "802.11x Adapter":
            get_combobox.addItem("")
        elif get_hardware_type == "USRP B20xmini":
            get_combobox.addItem("A:A")
            get_combobox.addItem("A:B")
            gain_item = QtWidgets.QTableWidgetItem("60")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "LimeSDR":
            get_combobox.addItem("A")
            get_combobox.addItem("B")
            gain_item = QtWidgets.QTableWidgetItem("55")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "bladeRF":
            get_combobox.addItem("")
            gain_item = QtWidgets.QTableWidgetItem("20")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "Open Sniffer":
            get_combobox.addItem("")
        elif get_hardware_type == "PlutoSDR":
            get_combobox.addItem("")
            gain_item = QtWidgets.QTableWidgetItem("64")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "USRP2":
            get_combobox.addItem("A:0")
            get_combobox.addItem("B:0")
            get_combobox.addItem("A:AB")
            get_combobox.addItem("A:BA")
            get_combobox.addItem("A:A")
            get_combobox.addItem("A:B")
            get_combobox.addItem("B:AB")
            get_combobox.addItem("B:BA")
            get_combobox.addItem("B:A")
            get_combobox.addItem("B:B")
            gain_item = QtWidgets.QTableWidgetItem("30")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "USRP N2xx":
            get_combobox.addItem("A:0")
            get_combobox.addItem("B:0")
            get_combobox.addItem("A:AB")
            get_combobox.addItem("A:BA")
            get_combobox.addItem("A:A")
            get_combobox.addItem("A:B")
            get_combobox.addItem("B:AB")
            get_combobox.addItem("B:BA")
            get_combobox.addItem("B:A")
            get_combobox.addItem("B:B")
            gain_item = QtWidgets.QTableWidgetItem("30")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "bladeRF 2.0":
            get_combobox.addItem("")
            gain_item = QtWidgets.QTableWidgetItem("20")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        elif get_hardware_type == "USRP X410":
            get_combobox.addItem("A:0")
            get_combobox.addItem("B:0")
            gain_item = QtWidgets.QTableWidgetItem("50")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(n,7,gain_item)
        else:
            get_combobox.addItem("")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveListViewDoubleClicked(dashboard: QtCore.QObject, mouse_event):
    """ 
    Adds the IQ file to the replay table when double clicked in the list widget.
    """
    # Index and Filepath
    get_index = dashboard.ui.listView_archive.currentIndex()
    get_filepath = dashboard.ui.listView_archive.model().filePath(get_index)

    # Navigate Folder
    if dashboard.ui.listView_archive.model().isDir(get_index) == True:
        # DotDot
        if get_filepath[-2:] == '..':
            parent_index = get_index.parent().parent()
            parent_filepath = dashboard.ui.listView_archive.model().filePath(parent_index)
            dashboard.ui.listView_archive.setRootIndex(parent_index)
            dashboard.ui.listView_archive.model().setRootPath(parent_filepath)  # Need to set this to keep sorting order

        # Folder
        else:
            dashboard.ui.listView_archive.setRootIndex(get_index)
            dashboard.ui.listView_archive.model().setRootPath(get_filepath)

    # Do Action on File
    else:
        # Add Only on Replay
        if dashboard.ui.tabWidget_archive.currentIndex() == 1:
            _slotArchiveReplayAddClicked(dashboard)

        # Add on Datasets
        elif dashboard.ui.tabWidget_archive.currentIndex() == 2:
            _slotArchiveDatasetsAddClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayAddClicked(dashboard: QtCore.QObject):
    """ 
    Adds a selected archive file to the playlist table.
    """
    # Get File
    get_archive_file = str(dashboard.ui.listView_archive.currentIndex().data())
    get_archive_folder = str(dashboard.ui.listView_archive.model().filePath(dashboard.ui.listView_archive.currentIndex())).rsplit('/',1)[0] + '/'

    get_archives = [archive for archive in dashboard.backend.library['Archive']['File']]
    
    get_hardware_type = str(dashboard.ui.comboBox_archive_replay_hardware.currentText()).split(' - ')[0]

    for n in range(0,len(get_archives)):
        # Get File Info
        get_file = str(get_archives[n])
        if get_archive_file == get_file:
            # Archive Lookup
            get_protocol = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Protocol'])
            #get_date = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Date'])
            get_format = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Format'])
            get_sample_rate = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Sample Rate'])
            get_tuned_frequency = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Tuned Frequency'])
            #get_samples = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Samples'])
            #get_size = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Size'])
            get_modulation = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Modulation'])
            #get_notes = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Notes'])

            # Set the Value in the Table
            dashboard.ui.tableWidget_archive_replay.setRowCount(dashboard.ui.tableWidget_archive_replay.rowCount()+1)
            file_item = QtWidgets.QTableWidgetItem(get_file)
            file_item.setTextAlignment(QtCore.Qt.AlignCenter)
            file_item.setFlags(file_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,0,file_item)
            protocol_item = QtWidgets.QTableWidgetItem(get_protocol)
            protocol_item.setTextAlignment(QtCore.Qt.AlignCenter)
            protocol_item.setFlags(protocol_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,1,protocol_item)
            modulation_item = QtWidgets.QTableWidgetItem(get_modulation)
            modulation_item.setTextAlignment(QtCore.Qt.AlignCenter)
            modulation_item.setFlags(modulation_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,2,modulation_item)
            tuned_frequency_item = QtWidgets.QTableWidgetItem(get_tuned_frequency)
            tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
            #tuned_frequency_item.setFlags(tuned_frequency_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,3,tuned_frequency_item)
            sample_rate_item = QtWidgets.QTableWidgetItem(get_sample_rate)
            sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
            #sample_rate_item.setFlags(sample_rate_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,4,sample_rate_item)
            format_item = QtWidgets.QTableWidgetItem(get_format)
            format_item.setTextAlignment(QtCore.Qt.AlignCenter)
            #format_item.setFlags(format_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,5,format_item)

            # Channel
            new_combobox1 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
            dashboard.ui.tableWidget_archive_replay.setCellWidget(dashboard.ui.tableWidget_archive_replay.rowCount()-1,6,new_combobox1)
            if get_hardware_type == "Computer":
                new_combobox1.addItem("")
            elif get_hardware_type == "USRP X3x0":
                new_combobox1.addItem("A:0")
                new_combobox1.addItem("B:0")
            elif get_hardware_type == "USRP B2x0":
                new_combobox1.addItem("A:A")
                new_combobox1.addItem("A:B")
            elif get_hardware_type == "HackRF":
                new_combobox1.addItem("")
            elif get_hardware_type == "RTL2832U":
                new_combobox1.addItem("")
            elif get_hardware_type == "802.11x Adapter":
                new_combobox1.addItem("")
            elif get_hardware_type == "USRP B20xmini":
                new_combobox1.addItem("A:A")
                new_combobox1.addItem("A:B")
            elif get_hardware_type == "LimeSDR":
                new_combobox1.addItem("A")
                new_combobox1.addItem("B")
            elif get_hardware_type == "bladeRF":
                new_combobox1.addItem("")
            elif get_hardware_type == "Open Sniffer":
                new_combobox1.addItem("")
            elif get_hardware_type == "PlutoSDR":
                new_combobox1.addItem("")
            elif get_hardware_type == "USRP2":
                new_combobox1.addItem("A:0")
                new_combobox1.addItem("B:0")
                new_combobox1.addItem("A:AB")
                new_combobox1.addItem("A:BA")
                new_combobox1.addItem("A:A")
                new_combobox1.addItem("A:B")
                new_combobox1.addItem("B:AB")
                new_combobox1.addItem("B:BA")
                new_combobox1.addItem("B:A")
                new_combobox1.addItem("B:B")
            elif get_hardware_type == "USRP N2xx":
                new_combobox1.addItem("A:0")
                new_combobox1.addItem("B:0")
                new_combobox1.addItem("A:AB")
                new_combobox1.addItem("A:BA")
                new_combobox1.addItem("A:A")
                new_combobox1.addItem("A:B")
                new_combobox1.addItem("B:AB")
                new_combobox1.addItem("B:BA")
                new_combobox1.addItem("B:A")
                new_combobox1.addItem("B:B")
            elif get_hardware_type == "bladeRF 2.0":
                new_combobox1.addItem("")
            elif get_hardware_type == "USRP X410":
                new_combobox1.addItem("A:0")
                new_combobox1.addItem("B:0")
            else:
                new_combobox1.addItem("")
            new_combobox1.setFixedSize(67,24)
            new_combobox1.setCurrentIndex(0)

            # Gain
            if get_hardware_type == "Computer":
                gain_item = QtWidgets.QTableWidgetItem("")
            elif get_hardware_type == "USRP X3x0":
                gain_item = QtWidgets.QTableWidgetItem("30")
            elif get_hardware_type == "USRP B2x0":
                gain_item = QtWidgets.QTableWidgetItem("60")
            elif get_hardware_type == "HackRF":
                gain_item = QtWidgets.QTableWidgetItem("20")
            elif get_hardware_type == "RTL2832U":
                gain_item = QtWidgets.QTableWidgetItem("")
            elif get_hardware_type == "802.11x Adapter":
                gain_item = QtWidgets.QTableWidgetItem("")
            elif get_hardware_type == "USRP B20xmini":
                gain_item = QtWidgets.QTableWidgetItem("60")
            elif get_hardware_type == "LimeSDR":
                gain_item = QtWidgets.QTableWidgetItem("55")
            elif get_hardware_type == "bladeRF":
                gain_item = QtWidgets.QTableWidgetItem("20")
            elif get_hardware_type == "Open Sniffer":
                gain_item = QtWidgets.QTableWidgetItem("")
            elif get_hardware_type == "PlutoSDR":
                gain_item = QtWidgets.QTableWidgetItem("64")
            elif get_hardware_type == "USRP2":
                gain_item = QtWidgets.QTableWidgetItem("30")
            elif get_hardware_type == "USRP N2xx":
                gain_item = QtWidgets.QTableWidgetItem("30")
            elif get_hardware_type == "bladeRF 2.0":
                gain_item = QtWidgets.QTableWidgetItem("20")
            elif get_hardware_type == "USRP X410":
                gain_item = QtWidgets.QTableWidgetItem("50")
            else:
                gain_item = QtWidgets.QTableWidgetItem("")
            gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,7,gain_item)

            # Duration
            duration_item = QtWidgets.QTableWidgetItem('5')
            duration_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,8,duration_item)

            # Folder
            folder_item = QtWidgets.QTableWidgetItem(get_archive_folder)
            folder_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,9,folder_item)

            # Resize the Table
            dashboard.ui.tableWidget_archive_replay.resizeColumnsToContents()
            dashboard.ui.tableWidget_archive_replay.resizeRowsToContents()
            dashboard.ui.tableWidget_archive_replay.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_archive_replay.horizontalHeader().setStretchLastSection(True)

            # Enable PushButton
            dashboard.ui.pushButton_archive_replay_start.setEnabled(True)

            return

    # Add File not Found in Archive
    dashboard.ui.tableWidget_archive_replay.setRowCount(dashboard.ui.tableWidget_archive_replay.rowCount()+1)
    file_item = QtWidgets.QTableWidgetItem(get_archive_file)
    file_item.setTextAlignment(QtCore.Qt.AlignCenter)
    file_item.setFlags(file_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,0,file_item)
    protocol_item = QtWidgets.QTableWidgetItem("?")
    protocol_item.setTextAlignment(QtCore.Qt.AlignCenter)
    protocol_item.setFlags(protocol_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,1,protocol_item)
    modulation_item = QtWidgets.QTableWidgetItem("?")
    modulation_item.setTextAlignment(QtCore.Qt.AlignCenter)
    modulation_item.setFlags(modulation_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,2,modulation_item)
    tuned_frequency_item = QtWidgets.QTableWidgetItem("2400e6")
    tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
    #tuned_frequency_item.setFlags(tuned_frequency_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,3,tuned_frequency_item)
    sample_rate_item = QtWidgets.QTableWidgetItem("1e6")
    sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
    #sample_rate_item.setFlags(sample_rate_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,4,sample_rate_item)
    format_item = QtWidgets.QTableWidgetItem("Complex Float 32")
    format_item.setTextAlignment(QtCore.Qt.AlignCenter)
    #format_item.setFlags(format_item.flags() & ~QtCore.Qt.ItemIsEditable)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,5,format_item)

    # Channel
    new_combobox1 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
    dashboard.ui.tableWidget_archive_replay.setCellWidget(dashboard.ui.tableWidget_archive_replay.rowCount()-1,6,new_combobox1)
    if get_hardware_type == "Computer":
        new_combobox1.addItem("")
    elif get_hardware_type == "USRP X3x0":
        new_combobox1.addItem("A:0")
        new_combobox1.addItem("B:0")
    elif get_hardware_type == "USRP B2x0":
        new_combobox1.addItem("A:A")
        new_combobox1.addItem("A:B")
    elif get_hardware_type == "HackRF":
        new_combobox1.addItem("")
    elif get_hardware_type == "RTL2832U":
        new_combobox1.addItem("")
    elif get_hardware_type == "802.11x Adapter":
        new_combobox1.addItem("")
    elif get_hardware_type == "USRP B20xmini":
        new_combobox1.addItem("A:A")
        new_combobox1.addItem("A:B")
    elif get_hardware_type == "LimeSDR":
        new_combobox1.addItem("A")
        new_combobox1.addItem("B")
    elif get_hardware_type == "bladeRF":
        new_combobox1.addItem("")
    elif get_hardware_type == "Open Sniffer":
        new_combobox1.addItem("")
    elif get_hardware_type == "PlutoSDR":
        new_combobox1.addItem("")
    elif get_hardware_type == "USRP2":
        new_combobox1.addItem("A:0")
        new_combobox1.addItem("B:0")
        new_combobox1.addItem("A:AB")
        new_combobox1.addItem("A:BA")
        new_combobox1.addItem("A:A")
        new_combobox1.addItem("A:B")
        new_combobox1.addItem("B:AB")
        new_combobox1.addItem("B:BA")
        new_combobox1.addItem("B:A")
        new_combobox1.addItem("B:B")
    elif get_hardware_type == "USRP N2xx":
        new_combobox1.addItem("A:0")
        new_combobox1.addItem("B:0")
        new_combobox1.addItem("A:AB")
        new_combobox1.addItem("A:BA")
        new_combobox1.addItem("A:A")
        new_combobox1.addItem("A:B")
        new_combobox1.addItem("B:AB")
        new_combobox1.addItem("B:BA")
        new_combobox1.addItem("B:A")
        new_combobox1.addItem("B:B")
    elif get_hardware_type == "bladeRF 2.0":
        new_combobox1.addItem("")
    elif get_hardware_type == "USRP X410":
        new_combobox1.addItem("A:0")
        new_combobox1.addItem("B:0")
    else:
        new_combobox1.addItem("")
    new_combobox1.setFixedSize(67,24)
    new_combobox1.setCurrentIndex(0)

    # Gain
    if get_hardware_type == "Computer":
        gain_item = QtWidgets.QTableWidgetItem("")
    elif get_hardware_type == "USRP X3x0":
        gain_item = QtWidgets.QTableWidgetItem("30")
    elif get_hardware_type == "USRP B2x0":
        gain_item = QtWidgets.QTableWidgetItem("60")
    elif get_hardware_type == "HackRF":
        gain_item = QtWidgets.QTableWidgetItem("20")
    elif get_hardware_type == "RTL2832U":
        gain_item = QtWidgets.QTableWidgetItem("")
    elif get_hardware_type == "802.11x Adapter":
        gain_item = QtWidgets.QTableWidgetItem("")
    elif get_hardware_type == "USRP B20xmini":
        gain_item = QtWidgets.QTableWidgetItem("60")
    elif get_hardware_type == "LimeSDR":
        gain_item = QtWidgets.QTableWidgetItem("55")
    elif get_hardware_type == "bladeRF":
        gain_item = QtWidgets.QTableWidgetItem("20")
    elif get_hardware_type == "Open Sniffer":
        gain_item = QtWidgets.QTableWidgetItem("")
    elif get_hardware_type == "PlutoSDR":
        gain_item = QtWidgets.QTableWidgetItem("")
    elif get_hardware_type == "USRP2":
        gain_item = QtWidgets.QTableWidgetItem("30")
    elif get_hardware_type == "USRP N2xx":
        gain_item = QtWidgets.QTableWidgetItem("30")
    elif get_hardware_type == "bladeRF 2.0":
        gain_item = QtWidgets.QTableWidgetItem("20")
    elif get_hardware_type == "USRP X410":
        gain_item = QtWidgets.QTableWidgetItem("50")
    else:
        gain_item = QtWidgets.QTableWidgetItem("")
    gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
    gain_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,7,gain_item)

    # Duration
    duration_item = QtWidgets.QTableWidgetItem('5')
    duration_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,8,duration_item)

    # Folder
    folder_item = QtWidgets.QTableWidgetItem(get_archive_folder)
    folder_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.rowCount()-1,9,folder_item)

    # Resize the Table
    dashboard.ui.tableWidget_archive_replay.resizeColumnsToContents()
    dashboard.ui.tableWidget_archive_replay.resizeRowsToContents()
    dashboard.ui.tableWidget_archive_replay.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_archive_replay.horizontalHeader().setStretchLastSection(True)

    # Enable PushButton
    dashboard.ui.pushButton_archive_replay_start.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsAddClicked(dashboard: QtCore.QObject, filepath=None):
    """ 
    Adds a selected archive file to the Datasets table.
    """
    # Get File
    if (filepath == None) or (filepath == False) :
        get_archive_file = str(dashboard.ui.listView_archive.currentIndex().data())
        get_archive_folder = str(dashboard.ui.listView_archive.model().filePath(dashboard.ui.listView_archive.currentIndex())).rsplit('/',1)[0] + '/'
    else:
        get_archive_file = str(filepath).rsplit("/",1)[1]
        get_archive_folder = str(filepath).rsplit("/",1)[0] + '/'

    get_archives = [archive for archive in dashboard.backend.library['Archive']['File']]

    for n in range(0,len(get_archives)):
        # Get File Info
        get_file = str(get_archives[n])
        if get_archive_file == get_file:
            # Archive Lookup
            get_truth = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Protocol'])
            get_sample_rate = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Sample Rate'])
            get_tuned_frequency = str(dashboard.backend.library['Archive']['File'][get_archives[n]]['Tuned Frequency'])

            # Set the Value in the Table
            dashboard.ui.tableWidget_archive_datasets.setRowCount(dashboard.ui.tableWidget_archive_datasets.rowCount()+1)
            folder_item = QtWidgets.QTableWidgetItem(get_archive_folder + get_archive_file)
            folder_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,0,folder_item)
            truth_item = QtWidgets.QTableWidgetItem(get_truth)
            truth_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,1,truth_item)
            sample_rate_item = QtWidgets.QTableWidgetItem(get_sample_rate)
            sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,2,sample_rate_item)
            tuned_frequency_item = QtWidgets.QTableWidgetItem(get_tuned_frequency)
            tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,3,tuned_frequency_item)

            # Generate Values in the Tables
            noise_value = random.uniform(float(dashboard.backend.settings['dataset_noise_min']),float(dashboard.backend.settings['dataset_noise_max']))
            noise_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(noise_value))
            noise_item.setTextAlignment(QtCore.Qt.AlignCenter)
            noise_item.setCheckState(QtCore.Qt.Unchecked)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,4,noise_item)
            phase_value = random.uniform(float(dashboard.backend.settings['dataset_phase_rot_min']),float(dashboard.backend.settings['dataset_phase_rot_max']))
            phase_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(phase_value))
            phase_item.setTextAlignment(QtCore.Qt.AlignCenter)
            phase_item.setCheckState(QtCore.Qt.Unchecked)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,5,phase_item)
            scale_value = random.uniform(float(dashboard.backend.settings['dataset_scale_min']),float(dashboard.backend.settings['dataset_scale_max']))
            scale_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(scale_value))
            scale_item.setTextAlignment(QtCore.Qt.AlignCenter)
            scale_item.setCheckState(QtCore.Qt.Unchecked)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,6,scale_item)
            freq_shift_value = random.uniform(float(dashboard.backend.settings['dataset_freq_shift_min']),float(dashboard.backend.settings['dataset_freq_shift_max']))
            freq_shift_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(freq_shift_value))
            freq_shift_item.setTextAlignment(QtCore.Qt.AlignCenter)
            freq_shift_item.setFlags(freq_shift_item.flags() & ~QtCore.Qt.ItemIsEnabled)
            freq_shift_item.setCheckState(QtCore.Qt.Unchecked)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,7,freq_shift_item)
            sigmf_item = QtWidgets.QTableWidgetItem("")
            sigmf_item.setTextAlignment(QtCore.Qt.AlignCenter)
            sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEditable)
            sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEnabled)
            sigmf_item.setCheckState(QtCore.Qt.Unchecked)
            dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,8,sigmf_item)

            # Resize the Table
            dashboard.ui.tableWidget_archive_datasets.resizeColumnsToContents()
            dashboard.ui.tableWidget_archive_datasets.resizeRowsToContents()
            dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(True)

            # Enable PushButton
            dashboard.ui.pushButton_archive_datasets_start.setEnabled(True)

            return

    # Add File not Found in Archive
    dashboard.ui.tableWidget_archive_datasets.setRowCount(dashboard.ui.tableWidget_archive_datasets.rowCount()+1)
    folder_item = QtWidgets.QTableWidgetItem(get_archive_folder + get_archive_file)
    folder_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,0,folder_item)
    truth_item = QtWidgets.QTableWidgetItem("")
    truth_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,1,truth_item)
    sample_rate_item = QtWidgets.QTableWidgetItem("")
    sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,2,sample_rate_item)
    tuned_frequency_item = QtWidgets.QTableWidgetItem("")
    tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,3,tuned_frequency_item)

    # Generate Values in the Tables
    noise_value = random.uniform(float(dashboard.backend.settings['dataset_noise_min']),float(dashboard.backend.settings['dataset_noise_max']))
    noise_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(noise_value))
    noise_item.setTextAlignment(QtCore.Qt.AlignCenter)
    noise_item.setCheckState(QtCore.Qt.Unchecked)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,4,noise_item)
    phase_value = random.uniform(float(dashboard.backend.settings['dataset_phase_rot_min']),float(dashboard.backend.settings['dataset_phase_rot_max']))
    phase_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(phase_value))
    phase_item.setTextAlignment(QtCore.Qt.AlignCenter)
    phase_item.setCheckState(QtCore.Qt.Unchecked)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,5,phase_item)
    scale_value = random.uniform(float(dashboard.backend.settings['dataset_scale_min']),float(dashboard.backend.settings['dataset_scale_max']))
    scale_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(scale_value))
    scale_item.setTextAlignment(QtCore.Qt.AlignCenter)
    scale_item.setCheckState(QtCore.Qt.Unchecked)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,6,scale_item)
    freq_shift_value = random.uniform(float(dashboard.backend.settings['dataset_freq_shift_min']),float(dashboard.backend.settings['dataset_freq_shift_max']))
    freq_shift_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(freq_shift_value))
    freq_shift_item.setTextAlignment(QtCore.Qt.AlignCenter)
    freq_shift_item.setFlags(freq_shift_item.flags() & ~QtCore.Qt.ItemIsEnabled)
    freq_shift_item.setCheckState(QtCore.Qt.Unchecked)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,7,freq_shift_item)
    sigmf_item = QtWidgets.QTableWidgetItem("")
    sigmf_item.setTextAlignment(QtCore.Qt.AlignCenter)
    sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEditable)
    sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEnabled)
    sigmf_item.setCheckState(QtCore.Qt.Unchecked)
    dashboard.ui.tableWidget_archive_datasets.setItem(dashboard.ui.tableWidget_archive_datasets.rowCount()-1,8,sigmf_item)

    # Resize the Table
    dashboard.ui.tableWidget_archive_datasets.resizeColumnsToContents()
    dashboard.ui.tableWidget_archive_datasets.resizeRowsToContents()
    dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(True)

    # Enable PushButton
    dashboard.ui.pushButton_archive_datasets_start.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsColumnClicked(dashboard: QtCore.QObject, col):
    """ 
    Checks/unchecks all items in a column for the Dataset Builder table.
    """
    # Toggle the State
    if (col > 3) and (bool(dashboard.ui.tableWidget_archive_datasets.item(0,col).flags() & QtCore.Qt.ItemIsEnabled) == True):
        get_check_state = dashboard.ui.tableWidget_archive_datasets.item(0,col).checkState()
        for row in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
            if get_check_state == 0:
                dashboard.ui.tableWidget_archive_datasets.item(row,col).setCheckState(2)
            else:
                dashboard.ui.tableWidget_archive_datasets.item(row,col).setCheckState(0)

    # Apply the Same Sample Rate
    if col == 2:
        get_sample_rate = str(dashboard.ui.tableWidget_archive_datasets.item(0,col).text())
        for row in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
            sample_rate_item = QtWidgets.QTableWidgetItem(get_sample_rate)
            sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(row,2,sample_rate_item)

    # Apply the Same Frequency
    if col == 3:
        get_frequency = str(dashboard.ui.tableWidget_archive_datasets.item(0,col).text())
        for row in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
            frequency_item = QtWidgets.QTableWidgetItem(get_frequency)
            frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(row,3,frequency_item)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadFolderClicked(dashboard: QtCore.QObject):
    """ 
    Selects a folder for viewing and downloading archive files.
    """
    # Choose Folder
    get_dir = str(QtWidgets.QFileDialog.getExistingDirectory(dashboard, "Select Directory"))

    # Add Directory to the Combobox
    if len(get_dir) > 0:
        dashboard.ui.comboBox3_archive_download_folder.addItem(get_dir)
        dashboard.ui.comboBox3_archive_download_folder.setCurrentIndex(dashboard.ui.comboBox3_archive_download_folder.count()-1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadDeleteClicked(dashboard: QtCore.QObject):
    """ 
    Deletes an IQ file from the Archive downloaded list.
    """
    # Get Highlighted File from Listbox
    get_index = dashboard.ui.listView_archive.currentIndex()
    delete_filepath = str(dashboard.ui.listView_archive.model().filePath(get_index))
    if len(delete_filepath) == 0:
        return

    # Delete Folder
    if dashboard.ui.listView_archive.model().isDir(get_index) == True:
        # DotDot
        if delete_filepath[-2:] == '..':
            return

        # Folder
        else:
            # Yes/No Dialog
            qm = QtWidgets.QMessageBox
            ret = qm.question(dashboard,'', "Delete this folder?", qm.Yes | qm.No)
            if ret == qm.Yes:
                os.system('rm -Rf "' + delete_filepath + '"')
            else:
                return

    # Delete File
    else:
        os.system('rm "' + delete_filepath + '"')

    # Refresh
    _slotArchiveDownloadRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadClicked(dashboard: QtCore.QObject):
    """ 
    Downloads the selected file from the internet.
    """
    # Find Selected Row
    get_row = dashboard.ui.tableWidget_archive_download.currentRow()
    if get_row >= 0:
        # Get File
        get_file = str(dashboard.ui.tableWidget_archive_download.verticalHeaderItem(get_row).text())

        # Get Folder
        get_folder = str(dashboard.ui.listView_archive.model().rootPath())

        # Download
        os.system('wget -P "' + get_folder + '/"' + ' https://fissure.ainfosec.com/' + get_file)
        _slotArchiveDownloadRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadCollectionClicked(dashboard: QtCore.QObject):
    """ 
    Downloads a single IQ file or a collection of IQ files and unzips them.
    """
    # Find Selected Row Text and Parent Text
    try:
        item_index = dashboard.ui.treeView_archive_download_collection.selectedIndexes()[0]
    except:
        dashboard.errorMessage("Select a collection")
        return
    parent1_index = dashboard.ui.treeView_archive_download_collection.model().parent(item_index)
    parent2_index = dashboard.ui.treeView_archive_download_collection.model().parent(parent1_index)

    item_data = dashboard.ui.treeView_archive_download_collection.model().data(item_index)
    parent1_data = dashboard.ui.treeView_archive_download_collection.model().data(parent1_index)
    parent2_data = dashboard.ui.treeView_archive_download_collection.model().data(parent2_index)

    # Assemble Filepath
    if parent1_data == "Notes":
        get_filepath = dashboard.backend.library['Archive']['Collection'][item_data]['Filepath']
    elif parent2_data == "Notes":
        if '.sigmf-data' in item_data:
            get_filepath = dashboard.backend.library['Archive']['Collection'][parent1_data]['Filepath'].replace('.tar','') + '/' + item_data
        else:
            get_filepath = dashboard.backend.library['Archive']['Collection'][parent1_data]['Filepath'].replace('.tar','') + '/' + item_data + '.tar'
    else:
        get_filepath = dashboard.backend.library['Archive']['Collection'][parent2_data]['Filepath'].replace('.tar','') + '/' + parent1_data + '/' + item_data

    # Download and Unzip
    get_folder = str(dashboard.ui.listView_archive.model().rootPath())
    if get_filepath[-4:] == '.tar':
        os.system('wget https://fissure.ainfosec.com' + get_filepath + ' -O - | tar -x -C "' + get_folder + '/"')
    elif get_filepath[-11:] == '.sigmf-data':
        os.system('wget https://fissure.ainfosec.com' + get_filepath + ' -P "' + get_folder + '/"')
        os.system('wget https://fissure.ainfosec.com' + get_filepath.replace('.sigmf-data','.sigmf-meta') + ' -P "' + get_folder + '/"')
    else:
        os.system('wget https://fissure.ainfosec.com' + get_filepath + ' -P "' + get_folder + '/"')
    _slotArchiveDownloadRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row from the Archive playlist table.
    """
    # Remove from the TableWidget
    get_current_row = dashboard.ui.tableWidget_archive_replay.currentRow()
    dashboard.ui.tableWidget_archive_replay.removeRow(get_current_row)
    if get_current_row == 0:
        dashboard.ui.tableWidget_archive_replay.setCurrentCell(0,0)
    else:
        dashboard.ui.tableWidget_archive_replay.setCurrentCell(get_current_row-1,0)

    # Disable PushButtons
    if dashboard.ui.tableWidget_archive_replay.rowCount() < 1:
        dashboard.ui.pushButton_archive_replay_start.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayUpClicked(dashboard: QtCore.QObject):
    """ 
    Moves the selected row up in the Archive playlist table.
    """
    if dashboard.ui.tableWidget_archive_replay.currentRow() != 0:  # Ignore top row
        # Take the Row Above
        above_item0 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,0)
        above_item1 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,1)
        above_item2 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,2)
        above_item3 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,3)
        above_item4 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,4)
        above_item5 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,5)
        above_item6 = dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow()-1,6).currentIndex()
        above_item7 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,7)
        above_item8 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,8)

        # Take the Current Row
        current_item0 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),0)
        current_item1 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),1)
        current_item2 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),2)
        current_item3 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),3)
        current_item4 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),4)
        current_item5 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),5)
        current_item6 = dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow(),6).currentIndex()
        current_item7 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),7)
        current_item8 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),8)

        # Set the Current Row
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),0,above_item0)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),1,above_item1)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),2,above_item2)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),3,above_item3)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),4,above_item4)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),5,above_item5)
        dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow(),6).setCurrentIndex(above_item6)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),7,above_item7)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),8,above_item8)

        # Set the Row Above
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,0,current_item0)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,1,current_item1)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,2,current_item2)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,3,current_item3)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,4,current_item4)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,5,current_item5)
        dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow()-1,6).setCurrentIndex(current_item6)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,7,current_item7)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()-1,8,current_item8)

        # Change the Selected Row
        dashboard.ui.tableWidget_archive_replay.setCurrentCell(dashboard.ui.tableWidget_archive_replay.currentRow()-1,0)

        # Resize
        dashboard.ui.tableWidget_archive_replay.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayDownClicked(dashboard: QtCore.QObject):
    """ 
    Moves the selected row down in the Archive playlist table.
    """
    # Get Bottom Row
    bottom_row = dashboard.ui.tableWidget_archive_replay.rowCount()

    # Move it Down
    if dashboard.ui.tableWidget_archive_replay.currentRow() != bottom_row-1:  # Ignore bottom row
        # Take the Row Below
        below_item0 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,0)
        below_item1 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,1)
        below_item2 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,2)
        below_item3 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,3)
        below_item4 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,4)
        below_item5 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,5)
        below_item6 = dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow()+1,6).currentIndex()
        below_item7 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,7)
        below_item8 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,8)

        # Take the Current Row
        current_item0 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),0)
        current_item1 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),1)
        current_item2 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),2)
        current_item3 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),3)
        current_item4 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),4)
        current_item5 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),5)
        current_item6 = dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow(),6).currentIndex()
        current_item7 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),7)
        current_item8 = dashboard.ui.tableWidget_archive_replay.takeItem(dashboard.ui.tableWidget_archive_replay.currentRow(),8)

        # Set the Current Row
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),0,below_item0)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),1,below_item1)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),2,below_item2)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),3,below_item3)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),4,below_item4)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),5,below_item5)
        dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow(),6).setCurrentIndex(below_item6)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),7,below_item7)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow(),8,below_item8)

        # Set the Row Above
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,0,current_item0)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,1,current_item1)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,2,current_item2)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,3,current_item3)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,4,current_item4)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,5,current_item5)
        dashboard.ui.tableWidget_archive_replay.cellWidget(dashboard.ui.tableWidget_archive_replay.currentRow()+1,6).setCurrentIndex(current_item6)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,7,current_item7)
        dashboard.ui.tableWidget_archive_replay.setItem(dashboard.ui.tableWidget_archive_replay.currentRow()+1,8,current_item8)

        # Change the Selected Row
        dashboard.ui.tableWidget_archive_replay.setCurrentCell(dashboard.ui.tableWidget_archive_replay.currentRow()+1,0)

        # Resize
        dashboard.ui.tableWidget_archive_replay.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayRemoveAllClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Archive playlist table.
    """
    # Remove all Rows
    for row in reversed(range(0,dashboard.ui.tableWidget_archive_replay.rowCount())):
        dashboard.ui.tableWidget_archive_replay.removeRow(row)

    # Disable PushButtons
    dashboard.ui.pushButton_archive_replay_start.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayImportCSV_Clicked(dashboard: QtCore.QObject):
    """ 
    Imports a CSV file to populate the playlist table.
    """
    # Choose File
    get_archive_folder = os.path.join(fissure.utils.ARCHIVE_DIR, "Playlists")
    fname = QtWidgets.QFileDialog.getOpenFileNames(None,"Select CSV File...", get_archive_folder, filter="CSV (*.csv)")
    if fname != "":
        r = dashboard.ui.tableWidget_archive_replay.rowCount()
        for n in fname[0]:
            csv_row = 0
            with open(n, "r") as fileInput:
                for row in csv.reader(fileInput):
                    if csv_row == 0:
                        _slotArchiveReplayHardwareChanged(dashboard)
                    else:
                        _slotArchiveReplayAddClicked(dashboard)
                        for c in range(0,len(row)):
                            get_text = row[c]
                            # Channel
                            if c == 6:
                                dashboard.ui.tableWidget_archive_replay.cellWidget(r,c).setCurrentIndex(int(get_text))
                            else:
                                dashboard.ui.tableWidget_archive_replay.item(r,c).setText(str(get_text))
                        r = r + 1
                    csv_row = csv_row + 1

        # Enable PushButton
        dashboard.ui.pushButton_archive_replay_start.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayExportCSV_Clicked(dashboard: QtCore.QObject):
    """ 
    Exports a CSV file from the playlist table.
    """
    # Choose File Location
    get_archive_folder = os.path.join(fissure.utils.ARCHIVE_DIR, "Playlists")
    path = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save CSV', get_archive_folder, filter='CSV (*.csv)')
    if len(path[0]) > 0:
        columns = range(dashboard.ui.tableWidget_archive_replay.columnCount())
        get_hardware_type = str(dashboard.ui.comboBox_archive_replay_hardware.currentText()).split(' - ')[0]
        with open(path[0], 'w') as csvfile:
            writer = csv.writer(csvfile, dialect='excel', lineterminator='\n')                
            writer.writerow([get_hardware_type])
            for row in range(dashboard.ui.tableWidget_archive_replay.rowCount()):
                row_text = []
                for column in columns:
                    try:
                        # Channel
                        if column == 6:
                            get_text = str(dashboard.ui.tableWidget_archive_replay.cellWidget(row,column).currentIndex())
                        else:
                            get_text = str(dashboard.ui.tableWidget_archive_replay.item(row,column).text())
                    except:
                        get_text = ""
                    row_text.append(get_text)
                writer.writerow(row_text)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsImportClicked(dashboard: QtCore.QObject):
    """ 
    Opens a file dialog to select IQ files for the Datasets table.
    """
    # Choose File
    get_archive_folder = str(dashboard.ui.listView_archive.model().rootPath()) + '/'
    fname = QtWidgets.QFileDialog.getOpenFileNames(None,"Select IQ File...", get_archive_folder, filter="All Files (*)")
    if fname != "":
        for n in fname[0]:
            _slotArchiveDatasetsAddClicked(dashboard, filepath=n)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row from the Archive Datasets table.
    """
    # Remove Rows
    if dashboard.ui.tableWidget_archive_datasets.rowCount() > 0:
        # Find Selected Rows Manually (selectedRanges() not working for programmatic selection?)
        first = -1
        last = -1
        for n in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
            item = dashboard.ui.tableWidget_archive_datasets.item(n,0)
            if item:
                if item.isSelected():
                    if first == -1:
                        first = n
                    last = n

        for n in reversed(range(first,last+1)):
            dashboard.ui.tableWidget_archive_datasets.removeRow(n)

        # Highlight New Row
        if dashboard.ui.tableWidget_archive_datasets.rowCount() > first:
            dashboard.ui.tableWidget_archive_datasets.selectRow(first)
        else:
            dashboard.ui.tableWidget_archive_datasets.selectRow(dashboard.ui.tableWidget_archive_datasets.rowCount()-1)

    # Disable PushButtons
    if dashboard.ui.tableWidget_archive_datasets.rowCount() < 1:
        dashboard.ui.pushButton_archive_datasets_start.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsRemoveAllClicked(dashboard: QtCore.QObject):
    """ 
    Removes all the rows in the Dataset Builder table.
    """
    # Remove all Rows
    for row in reversed(range(0,dashboard.ui.tableWidget_archive_datasets.rowCount())):
        dashboard.ui.tableWidget_archive_datasets.removeRow(row)

    # Disable PushButtons
    dashboard.ui.pushButton_archive_datasets_start.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsExportClicked(dashboard: QtCore.QObject):
    """ 
    Exports the contents of the Datasets table to a CSV.
    """
    # Choose File Location
    get_archive_folder = os.path.join(fissure.utils.ARCHIVE_DIR, "Datasets")
    path = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save CSV', get_archive_folder, filter='CSV (*.csv)')
    if len(path[0]) > 0:
        columns = range(dashboard.ui.tableWidget_archive_datasets.columnCount())
        with open(path[0], 'w') as csvfile:
            writer = csv.writer(csvfile, dialect='excel', lineterminator='\n')
            for row in range(dashboard.ui.tableWidget_archive_datasets.rowCount()):
                row_text = []
                for column in columns:
                    try:
                        get_text = str(dashboard.ui.tableWidget_archive_datasets.item(row, column).text())
                        if column > 3:
                            get_checked_state = str(dashboard.ui.tableWidget_archive_datasets.item(row, column).checkState())
                            get_text = get_checked_state + ':' + get_text
                    except:
                        get_text = ""
                    row_text.append(get_text)
                writer.writerow(row_text)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsOptionsClicked(dashboard: QtCore.QObject):
    """ 
    Opens the Options dialog to change the settings for the Dataset Builder.
    """
    fissure.Dashboard.Slots.MenuBarSlots._slotMenuOptionsClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsImportCSV_Clicked(dashboard: QtCore.QObject):
    """ 
    Loads a .csv file into the Dataset Builder table.
    """
    # Choose File
    get_archive_folder = os.path.join(fissure.utils.ARCHIVE_DIR, "Datasets")
    fname = QtWidgets.QFileDialog.getOpenFileNames(None,"Select CSV File...", get_archive_folder, filter="CSV (*.csv)")
    if fname != "":
        r = dashboard.ui.tableWidget_archive_datasets.rowCount()
        for n in fname[0]:
            with open(n, "r") as fileInput:
                for row in csv.reader(fileInput):
                    dashboard.ui.tableWidget_archive_datasets.setRowCount(dashboard.ui.tableWidget_archive_datasets.rowCount() + 1)
                    for c in range(0,len(row)):
                        if c > 3:
                            get_text = row[c].split(':',1)[1]
                            get_checked_state = int(row[c].split(':',1)[0])
                            new_item = QtWidgets.QTableWidgetItem(get_text)
                            new_item.setCheckState(get_checked_state)
                            if c > 6:
                                new_item.setFlags(new_item.flags() & ~QtCore.Qt.ItemIsEnabled)
                        else:
                            get_text = row[c]
                            new_item = QtWidgets.QTableWidgetItem(get_text)
                        new_item.setTextAlignment(QtCore.Qt.AlignCenter)
                        dashboard.ui.tableWidget_archive_datasets.setItem(r,c,new_item)
                    r = r+1

        # Resize the Table
        dashboard.ui.tableWidget_archive_datasets.resizeColumnsToContents()
        dashboard.ui.tableWidget_archive_datasets.resizeRowsToContents()
        dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(True)

        # Enable PushButton
        dashboard.ui.pushButton_archive_datasets_start.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsViewClicked(dashboard: QtCore.QObject):
    """ 
    Opens the flow graph used to apply changes to the IQ files listed the Dataset Builder table.
    """
    # Open the Flow Graph in GNU Radio Companion
    flow_graph_filepath = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Archive Flow Graphs", "dataset_builder.grc")
    osCommandString = 'gnuradio-companion "' + flow_graph_filepath + '"'
    os.system(osCommandString + " &")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsCopyClicked(dashboard: QtCore.QObject):
    """ 
    Copies selected rows in the Dataset Builder table and generates new checkbox values.
    """
    if dashboard.ui.tableWidget_archive_datasets.rowCount() > 0:
        # Find Selected Rows Manually (selectedRanges() not working for programmatic selection?)
        first = -1
        last = -1
        for n in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
            item = dashboard.ui.tableWidget_archive_datasets.item(n,0)
            if item:
                if item.isSelected():
                    if first == -1:
                        first = n
                    last = n

        # Insert Rows
        for n in reversed(range(first,last+1)):
            dashboard.ui.tableWidget_archive_datasets.insertRow(last+1)

            # Set the Value in the Table
            folder_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_archive_datasets.item(n,0).text()))
            folder_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,0,folder_item)
            truth_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_archive_datasets.item(n,1).text()))
            truth_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,1,truth_item)
            sample_rate_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_archive_datasets.item(n,2).text()))
            sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,2,sample_rate_item)
            tuned_frequency_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_archive_datasets.item(n,3).text()))
            tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,3,tuned_frequency_item)

            # Generate Values in the Tables
            noise_value = random.uniform(float(dashboard.backend.settings['dataset_noise_min']),float(dashboard.backend.settings['dataset_noise_max']))
            noise_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(noise_value))
            noise_item.setTextAlignment(QtCore.Qt.AlignCenter)
            if dashboard.ui.tableWidget_archive_datasets.item(n,4).checkState() == 0:
                noise_item.setCheckState(0)
            else:
                noise_item.setCheckState(2)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,4,noise_item)
            phase_value = random.uniform(float(dashboard.backend.settings['dataset_phase_rot_min']),float(dashboard.backend.settings['dataset_phase_rot_max']))
            phase_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(phase_value))
            phase_item.setTextAlignment(QtCore.Qt.AlignCenter)
            if dashboard.ui.tableWidget_archive_datasets.item(n,5).checkState() == 0:
                phase_item.setCheckState(0)
            else:
                phase_item.setCheckState(2)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,5,phase_item)
            scale_value = random.uniform(float(dashboard.backend.settings['dataset_scale_min']),float(dashboard.backend.settings['dataset_scale_max']))
            scale_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(scale_value))
            scale_item.setTextAlignment(QtCore.Qt.AlignCenter)
            if dashboard.ui.tableWidget_archive_datasets.item(n,6).checkState() == 0:
                scale_item.setCheckState(0)
            else:
                scale_item.setCheckState(2)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,6,scale_item)
            freq_shift_value = random.uniform(float(dashboard.backend.settings['dataset_freq_shift_min']),float(dashboard.backend.settings['dataset_freq_shift_max']))
            freq_shift_item = QtWidgets.QTableWidgetItem("{:0.2f}".format(freq_shift_value))
            freq_shift_item.setTextAlignment(QtCore.Qt.AlignCenter)
            freq_shift_item.setFlags(freq_shift_item.flags() & ~QtCore.Qt.ItemIsEnabled)
            if dashboard.ui.tableWidget_archive_datasets.item(n,7).checkState() == 0:
                freq_shift_item.setCheckState(0)
            else:
                freq_shift_item.setCheckState(2)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,7,freq_shift_item)
            sigmf_item = QtWidgets.QTableWidgetItem("")
            sigmf_item.setTextAlignment(QtCore.Qt.AlignCenter)
            sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEditable)
            sigmf_item.setFlags(sigmf_item.flags() & ~QtCore.Qt.ItemIsEnabled)
            if dashboard.ui.tableWidget_archive_datasets.item(n,8).checkState() == 0:
                sigmf_item.setCheckState(0)
            else:
                sigmf_item.setCheckState(2)
            dashboard.ui.tableWidget_archive_datasets.setItem(last+1,8,sigmf_item)

        # Keep the Selection
        dashboard.ui.tableWidget_archive_datasets.clearSelection()
        for n in range(first,last+1):
            for m in range(0,dashboard.ui.tableWidget_archive_datasets.columnCount()):
                item = dashboard.ui.tableWidget_archive_datasets.item(n,m)
                if item:
                    item.setSelected(True)

        # Resize the Table
        dashboard.ui.tableWidget_archive_datasets.resizeColumnsToContents()
        dashboard.ui.tableWidget_archive_datasets.resizeRowsToContents()
        dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_archive_datasets.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsOpenFolderClicked(dashboard: QtCore.QObject):
    """ 
    Opens the folder where datasets gets stored by default.
    """
    # Open the Folder
    folder_filepath = os.path.join(fissure.utils.FISSURE_ROOT, "Archive", "Datasets")
    os.system("nautilus '" + folder_filepath + "' &")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadCollectionCollapseAllClicked(dashboard: QtCore.QObject):
    """ 
    Collapses the Collection TreeView.
    """
    # Collapse
    dashboard.ui.treeView_archive_download_collection.collapseAll()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveNewFolderClicked(dashboard: QtCore.QObject):
    """ 
    Creates a new folder in the current directory of the Archive ListView.
    """
    text, ok = QtWidgets.QInputDialog.getText(dashboard, 'New Folder', 'Enter new folder name:',QtWidgets.QLineEdit.Normal)
    if ok:
        if len(str(text)) > 0:
            folder_filepath = str(dashboard.ui.listView_archive.model().rootPath())
            os.system('mkdir "' + folder_filepath + '/' + str(text) + '"')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveFolderClicked(dashboard: QtCore.QObject):
    """ 
    Opens a window to current directory of the Archive ListView.
    """
    # Open the Folder
    folder_filepath = str(dashboard.ui.listView_archive.model().rootPath())
    os.system('nautilus "' + folder_filepath + '" &')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveReplayTriggersEditClicked(dashboard: QtCore.QObject):
    """ 
    Opens the triggers dialog window to edit the list of Archive replay triggers.
    """
    # Obtain Table Information
    table_values = []
    for row in range(0, dashboard.ui.tableWidget1_archive_replay_triggers.rowCount()):
        table_values.append([str(dashboard.ui.tableWidget1_archive_replay_triggers.item(row,0).text()), str(dashboard.ui.tableWidget1_archive_replay_triggers.item(row,1).text()), str(dashboard.ui.tableWidget1_archive_replay_triggers.item(row,2).text()), str(dashboard.ui.tableWidget1_archive_replay_triggers.item(row,3).text())])
    
    # Open the Dialog
    get_value = dashboard.openPopUp("TriggersDialog", TriggersDialog, "Archive Replay", table_values)

    # Cancel Clicked
    if get_value == None:
        pass
        
    # OK Clicked
    elif len(get_value) > 0:
        dashboard.ui.tableWidget1_archive_replay_triggers.setRowCount(len(get_value))
        for row in range(0,len(get_value)):
            # Filename
            filename_item = QtWidgets.QTableWidgetItem(get_value[row][0])
            filename_item.setTextAlignment(QtCore.Qt.AlignCenter)
            filename_item.setFlags(filename_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget1_archive_replay_triggers.setItem(row,0,filename_item)
            
            # Type
            type_item = QtWidgets.QTableWidgetItem(get_value[row][1])
            type_item.setTextAlignment(QtCore.Qt.AlignCenter)
            type_item.setFlags(type_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget1_archive_replay_triggers.setItem(row,1,type_item)

            # Variable Names
            variable_names_item = QtWidgets.QTableWidgetItem(get_value[row][2])
            variable_names_item.setTextAlignment(QtCore.Qt.AlignCenter)
            variable_names_item.setFlags(variable_names_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget1_archive_replay_triggers.setItem(row,2,variable_names_item)

            # Variable Values
            variable_values_item = QtWidgets.QTableWidgetItem(get_value[row][3])
            variable_values_item.setTextAlignment(QtCore.Qt.AlignCenter)
            variable_values_item.setFlags(variable_values_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget1_archive_replay_triggers.setItem(row,3,variable_values_item)
        
        # Resize the Table
        dashboard.ui.tableWidget1_archive_replay_triggers.resizeColumnsToContents()
        #dashboard.ui.tableWidget1_archive_replay_triggers.setColumnWidth(5,300)
        #dashboard.ui.tableWidget1_archive_replay_triggers.setColumnWidth(6,300)
        dashboard.ui.tableWidget1_archive_replay_triggers.resizeRowsToContents()
        dashboard.ui.tableWidget1_archive_replay_triggers.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget1_archive_replay_triggers.horizontalHeader().setStretchLastSection(True)
        
    # All Rows Removed
    else:
        dashboard.ui.tableWidget1_archive_replay_triggers.setRowCount(0)

@qasync.asyncSlot(QtCore.QObject)
async def _slotArchiveReplayStartClicked(dashboard: QtCore.QObject):
    """ 
    Sends message to HIPRFISR to start replaying the archive playlist.
    """
    # Send Stop Message to the HIPRFISR (Flow Graph Currently Running: Stopping)
    if dashboard.ui.pushButton_archive_replay_start.text() == "Stop":

        # Send Message to the Backend
        await dashboard.backend.archivePlaylistStop(dashboard.active_sensor_node)

        # Toggle the Text
        dashboard.ui.pushButton_archive_replay_start.setText("Start")

        # Update the Status Label
        dashboard.ui.label2_archive_replay_status.setVisible(False)

    # Reset to Last Known Flow Graph Configuration (Flow Graph Currently Stopped: Starting)
    elif dashboard.ui.pushButton_archive_replay_start.text() == "Start":
        # Return if no Sensor Node Selected
        if dashboard.active_sensor_node < 0:
            ret = await dashboard.ask_confirmation_ok("Select a sensor node.")
            return

        # Cycle Through Each Tab and Collect the Values
        all_file_list = []
        all_frequency_list = []
        all_sample_rate_list = []
        all_format_list = []
        all_channel_list = []
        all_gain_list = []
        all_duration_list = []
        for n in range(0,dashboard.ui.tableWidget_archive_replay.rowCount()):
            # Get File Details
            get_folder = str(dashboard.ui.tableWidget_archive_replay.item(n,9).text()) + '/'
            all_file_list.append(get_folder + str(dashboard.ui.tableWidget_archive_replay.item(n,0).text()))
            all_frequency_list.append(str(dashboard.ui.tableWidget_archive_replay.item(n,3).text()))
            all_sample_rate_list.append(str(dashboard.ui.tableWidget_archive_replay.item(n,4).text()))
            all_format_list.append(str(dashboard.ui.tableWidget_archive_replay.item(n,5).text()))
            all_channel_list.append(str(dashboard.ui.tableWidget_archive_replay.cellWidget(n,6).currentText()))
            all_gain_list.append(str(dashboard.ui.tableWidget_archive_replay.item(n,7).text()))
            all_duration_list.append(str(dashboard.ui.tableWidget_archive_replay.item(n,8).text()))

        # Only Replay Complex Float 32 Files
        for n in all_format_list:
            if n != "Complex Float 32":
                ret = await dashboard.ask_confirmation_ok("Error: Only Complex Float 32 files are supported.")
                dashboard.errorMessage("")
                return

        # Get Repeat Checkbox Value
        get_repeat = dashboard.ui.checkBox_archive_replay_repeat.isChecked()

        # Sensor Node Hardware Information
        get_current_hardware = str(dashboard.ui.comboBox_archive_replay_hardware.currentText())
        get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = dashboard.hardwareDisplayNameLookup(get_current_hardware,'archive')
    
        # Choose Replay Flow Graph from Hardware Type
        flow_graph = ""
        if get_hardware_type == "Computer":
            flow_graph = ""  # Error
        elif get_hardware_type == "USRP X3x0":
            flow_graph = "archive_replay_x3x0"
        elif get_hardware_type == "USRP B2x0":
            flow_graph = "archive_replay_b2x0"
        elif get_hardware_type == "HackRF":
            flow_graph = "archive_replay_hackrf"
        elif get_hardware_type == "RTL2832U":
            flow_graph = ""  # Error
        elif get_hardware_type == "802.11x Adapter":
            flow_graph = ""  # Error
        elif get_hardware_type == "USRP B20xmini":
            flow_graph = "archive_replay_b2x0"
        elif get_hardware_type == "LimeSDR":
            flow_graph = "archive_replay_limesdr"
        elif get_hardware_type == "bladeRF":
            flow_graph = "archive_replay_bladerf"
        elif get_hardware_type == "Open Sniffer":
            flow_graph = ""  # Error
        elif get_hardware_type == "PlutoSDR":
            flow_graph = "archive_replay_plutosdr"
        elif get_hardware_type == "USRP2":
            flow_graph = "archive_replay_usrp2"
        elif get_hardware_type == "USRP N2xx":
            flow_graph = "archive_replay_usrp_n2xx"
        elif get_hardware_type == "bladeRF 2.0":
            flow_graph = "archive_replay_bladerf2"
        elif get_hardware_type == "USRP X410":
            flow_graph = "archive_replay_usrp_x410"

        # Send "Start Archive Playlist" Message to the HIPRFISR
        if len(flow_graph) > 0:

            # Hardware IP Address
            get_ip_address = get_hardware_ip

            # Hardware Serial
            if len(get_hardware_serial) > 0:
                if get_hardware_type == "HackRF":
                    get_serial = get_hardware_serial
                elif get_hardware_type == "bladeRF":
                    get_serial = get_hardware_serial
                elif get_hardware_type == "bladeRF 2.0":
                    get_serial = get_hardware_serial
                else:
                    get_serial = 'serial=' + get_hardware_serial
            else:
                if get_hardware_type == "HackRF":
                    get_serial = ""
                elif get_hardware_type == "bladeRF":
                    get_serial = "0"
                elif get_hardware_type == "bladeRF 2.0":
                    get_serial = "0"
                else:
                    get_serial = "False"
                    
            # Trigger Parameters
            trigger_values = []
            for row in range(0, dashboard.ui.tableWidget1_archive_replay_triggers.rowCount()):
                trigger_values.append([str(dashboard.ui.tableWidget1_archive_replay_triggers.item(row,0).text()), str(dashboard.ui.tableWidget1_archive_replay_triggers.item(row,1).text()), str(dashboard.ui.tableWidget1_archive_replay_triggers.item(row,2).text()), str(dashboard.ui.tableWidget1_archive_replay_triggers.item(row,3).text())])

            # Sensor Node Name
            sensor_nodes = ['sensor_node1','sensor_node2','sensor_node3','sensor_node4','sensor_node5']
            get_sensor_node = sensor_nodes[dashboard.active_sensor_node]

            # Transfer All IQ Files to Remote Sensor Node (Sensor Node Messages are Blocking)
            if str(dashboard.backend.settings[get_sensor_node]['local_remote']) == 'remote':
                # Clear Folder
                await dashboard.backend.deleteArchiveReplayFiles(dashboard.active_sensor_node)

                # Transfer
                for n in all_file_list:
                    await dashboard.backend.transferSensorNodeFile(dashboard.active_sensor_node, n, '/Archive_Replay', False)

            # Send Message to Backend
            await dashboard.backend.archivePlaylistStart(dashboard.active_sensor_node, flow_graph, all_file_list, all_frequency_list, all_sample_rate_list, all_format_list, all_channel_list, all_gain_list, all_duration_list, get_repeat, get_ip_address, get_serial, trigger_values)

            # Toggle the Text
            dashboard.ui.pushButton_archive_replay_start.setText("Stop")

            # Update the Status Label
            dashboard.ui.label2_archive_replay_status.setVisible(True)

        # Error
        else:
            ret = await dashboard.ask_confirmation_ok("Choose a valid hardware type.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsRegenerateClicked(dashboard: QtCore.QObject):
    """ 
    Regenerates the checkbox values in the Dataset Builder table.
    """
    # Generate Values in the Tables
    for row in range(0,dashboard.ui.tableWidget_archive_datasets.rowCount()):
        noise_value = random.uniform(float(dashboard.backend.settings['dataset_noise_min']),float(dashboard.backend.settings['dataset_noise_max']))
        dashboard.ui.tableWidget_archive_datasets.item(row,4).setText("{:0.2f}".format(noise_value))
        phase_value = random.uniform(float(dashboard.backend.settings['dataset_phase_rot_min']),float(dashboard.backend.settings['dataset_phase_rot_max']))
        dashboard.ui.tableWidget_archive_datasets.item(row,5).setText("{:0.2f}".format(phase_value))
        scale_value = random.uniform(float(dashboard.backend.settings['dataset_scale_min']),float(dashboard.backend.settings['dataset_scale_max']))
        dashboard.ui.tableWidget_archive_datasets.item(row,6).setText("{:0.2f}".format(scale_value))
        freq_shift_value = random.uniform(float(dashboard.backend.settings['dataset_freq_shift_min']),float(dashboard.backend.settings['dataset_freq_shift_max']))
        dashboard.ui.tableWidget_archive_datasets.item(row,7).setText("{:0.2f}".format(freq_shift_value))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDownloadPlotClicked(dashboard: QtCore.QObject):
    """ 
    Plots the Archive file in the IQ Viewer.
    """
    # Ignore Folders
    get_index = dashboard.ui.listView_archive.currentIndex()
    if dashboard.ui.listView_archive.model().isDir(get_index) == True:
        return

    # Get the Folder and File
    get_file = str(dashboard.ui.listView_archive.currentIndex().data())
    get_folder = str(dashboard.ui.listView_archive.model().filePath(dashboard.ui.listView_archive.currentIndex())).rsplit('/',1)[0]

    # Ignore No Selection
    if len(get_folder) == 0:
        return

    # Set the Files and Directories in the IQ Tab
    if get_folder == fissure.utils.ARCHIVE_DIR:
        dashboard.ui.comboBox3_iq_folders.setCurrentIndex(1)
    else:
        # Determine if the Directory is Present Already
        match_found = False
        for n in range(0,dashboard.ui.comboBox3_iq_folders.count()):
            if get_folder == dashboard.ui.comboBox3_iq_folders.itemText(n):
                dashboard.ui.comboBox3_iq_folders.setCurrentIndex(n)
                match_found = True
                break
        if match_found == False:
            dashboard.ui.comboBox3_iq_folders.addItem(get_folder)
            dashboard.ui.comboBox3_iq_folders.setCurrentIndex(dashboard.ui.comboBox3_iq_folders.count()-1)

    for n in range(0,dashboard.ui.listWidget_iq_files.count()):
        if get_file == dashboard.ui.listWidget_iq_files.item(n).text():
            dashboard.ui.listWidget_iq_files.setCurrentRow(n)
            break

    # Load the File
    # self._slotIQ_LoadIQ_Data()  # FIX - Once this function exists

    # Plot the File
    # self._slotIQ_PlotAllClicked()  # FIX - Once this function exists

    # Change to IQ Tab
    dashboard.ui.tabWidget.setCurrentIndex(4)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotArchiveDatasetsStartClicked(dashboard: QtCore.QObject):
    """ 
    Inputs the checked values in the table into the Dataset Builder flow graph.
    """
    # Stop Generating Datasets
    if dashboard.ui.pushButton_archive_datasets_start.text() == "Stop":
        dashboard.stop_archive_operations = True
        dashboard.ui.pushButton_archive_datasets_start.setText("Start")
        dashboard.ui.progressBar_archive_datasets.setVisible(False)

    # Start Generating Datasets
    elif dashboard.ui.pushButton_archive_datasets_start.text() == "Start":
        dashboard.ui.pushButton_archive_datasets_start.setText("Stop")
        dashboard.ui.progressBar_archive_datasets.setValue(1)
        dashboard.ui.progressBar_archive_datasets.setVisible(True)

        # Run the Flow Graph
        archive_flow_graph = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Archive Flow Graphs", "dataset_builder.py")
        now = datetime.datetime.now()
        now = now.strftime("%Y-%m-%d %H:%M:%S").replace(' ','_')
        get_new_filepath = os.path.join(fissure.utils.FISSURE_ROOT, "Archive", "Datasets", now)
        os.system("mkdir " + get_new_filepath)
        dashboard.stop_archive_operations = False
        for row in range(dashboard.ui.tableWidget_archive_datasets.rowCount()):
            # Get Values
            get_filepath = str(dashboard.ui.tableWidget_archive_datasets.item(row,0).text())
            get_sample_rate = str(dashboard.ui.tableWidget_archive_datasets.item(row,2).text())
            if len(get_sample_rate) == 0:
                dashboard.errorMessage("Error: Missing sample rate value in table.")
                dashboard.ui.pushButton_archive_datasets_start.setText("Start")
                dashboard.ui.progressBar_archive_datasets.setValue(0)
                dashboard.ui.progressBar_archive_datasets.setVisible(False)
                return
            get_frequency = str(dashboard.ui.tableWidget_archive_datasets.item(row,3).text())
            if len(get_frequency) == 0:
                get_frequency = "1000000000"
            if int(dashboard.ui.tableWidget_archive_datasets.item(row,4).checkState()) == 2:
                get_noise = str(dashboard.ui.tableWidget_archive_datasets.item(row,4).text())
            else:
                get_noise = "0"
            if int(dashboard.ui.tableWidget_archive_datasets.item(row,5).checkState()) == 2:
                get_phase_rot = str(dashboard.ui.tableWidget_archive_datasets.item(row,5).text())
            else:
                get_phase_rot = "0"
            if int(dashboard.ui.tableWidget_archive_datasets.item(row,6).checkState()) == 2:
                get_scale = str(dashboard.ui.tableWidget_archive_datasets.item(row,6).text())
            else:
                get_scale = "1"
            if int(dashboard.ui.tableWidget_archive_datasets.item(row,7).checkState()) == 2:
                get_freq_shift = str(dashboard.ui.tableWidget_archive_datasets.item(row,7).text())
            else:
                get_freq_shift = "0"
            if int(dashboard.ui.tableWidget_archive_datasets.item(row,8).checkState()) == 2:
                get_sigmf = True
            else:
                get_sigmf = False

            dashboard.archive_database_loop = True
            loadthread = OperationsThread('python3 "' + archive_flow_graph + '" --filepath "' + get_filepath \
                + '" --sample-rate ' + get_sample_rate + " --frequency " + get_frequency + " --noise " + get_noise \
                + " --phase-rot " + get_phase_rot + " --scale " + get_scale + " --freq-shift " + get_freq_shift \
                + " --new-filepath " + get_new_filepath + "/" + now + "_" + str(row), get_new_filepath, dashboard)
            loadthread.finished.connect(lambda: on_finished(dashboard))
            loadthread.start()
            while dashboard.archive_database_loop == True:
                QtWidgets.QApplication.processEvents()
                time.sleep(0.1)
                if dashboard.stop_archive_operations == True:
                    break
            dashboard.ui.progressBar_archive_datasets.setValue(1+int(float(row+1)/float(dashboard.ui.tableWidget_archive_datasets.rowCount())*99))

        dashboard.ui.progressBar_archive_datasets.setValue(100)
        dashboard.ui.pushButton_archive_datasets_start.setText("Start")
        time.sleep(1)
        dashboard.ui.progressBar_archive_datasets.setVisible(False)


@QtCore.pyqtSlot()
def on_finished(dashboard: QtCore.QObject):
    """ 
    Proceed to the operation.
    """
    dashboard.archive_database_loop = False

    
class OperationsThread(QtCore.QThread):
    """
    Used for Archive database generation.
    """
    def __init__(self, cmd, get_cwd, parent=None):
        QtCore.QThread.__init__(self, parent)
        self.cmd = cmd
        self.get_cwd = get_cwd

    def run(self):
        try:
            p1 = subprocess.Popen(self.cmd, shell=True, cwd=self.get_cwd)
            (output, err) = p1.communicate()
            p1.wait()
        except:
            print("FAILURE")