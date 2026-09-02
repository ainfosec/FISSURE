from PyQt5 import QtCore, QtWidgets, QtGui
import os
import fissure.utils
import json
import shutil
import numpy as np
import math
from fissure.Dashboard.UI_Components.Qt5 import MyMessageBox
import subprocess
from scipy import signal as signal2
import struct
import warnings
import matplotlib.pyplot as plt
import time
from scipy.signal import hilbert, lfilter, butter, filtfilt, sosfilt
import datetime
import qasync
from ..UI_Components import DemodDialog
from typing import List
from fissure.utils.selected_node_utils import (
    selected_node_is_local,
    selected_node_is_remote,
    selected_node_is_ip,
    selected_node_is_meshtastic,
)
import uuid


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_StripOverwriteClicked(dashboard: QtCore.QObject):
    """ 
    Disables/enables output directory widgets.
    """
    # Disable
    if dashboard.ui.checkBox_iq_strip_overwrite.isChecked():
        dashboard.ui.label2_iq_strip_output.setEnabled(False)
        dashboard.ui.textEdit_iq_strip_output.setEnabled(False)
        dashboard.ui.pushButton_iq_strip_choose.setEnabled(False)

    # Enable
    else:
        dashboard.ui.label2_iq_strip_output.setEnabled(True)
        dashboard.ui.textEdit_iq_strip_output.setEnabled(True)
        dashboard.ui.pushButton_iq_strip_choose.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_FoldersChanged(dashboard: QtCore.QObject):
    """ 
    Changes the IQ Files in the listbox.
    """
    # Load the Files in the Listbox
    get_dir = str(dashboard.ui.comboBox3_iq_folders.currentText())
    if get_dir != "":
        # if get_dir == "./IQ Recordings":
            # get_dir = os.path.dirname(os.path.realpath(__file__)) + get_dir[1:]
        dashboard.ui.label_iq_folder.setText(get_dir)
        dashboard.ui.listWidget_iq_files.clear()
        file_names = []
        for fname in os.listdir(get_dir):
            if os.path.isfile(get_dir+"/"+fname):
                if ".sigmf-meta" not in fname:
                    file_names.append(fname)
        file_names = sorted(file_names)
        for n in file_names:
            dashboard.ui.listWidget_iq_files.addItem(n)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_NormalizeMinMaxChanged(dashboard: QtCore.QObject):
    """ 
    Enables/Disables the min and max labels and comboboxes.
    """
    # Enable Widgets
    if dashboard.ui.comboBox_iq_normalize_min_max.currentIndex() == 5:
        dashboard.ui.label2_iq_normalize_min.setEnabled(True)
        dashboard.ui.textEdit_iq_normalize_min.setEnabled(True)
        dashboard.ui.label2_iq_normalize_max.setEnabled(True)
        dashboard.ui.textEdit_iq_normalize_max.setEnabled(True)

    # Disable Widgets
    else:
        dashboard.ui.label2_iq_normalize_min.setEnabled(False)
        dashboard.ui.textEdit_iq_normalize_min.setEnabled(False)
        dashboard.ui.label2_iq_normalize_max.setEnabled(False)
        dashboard.ui.textEdit_iq_normalize_max.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_FilterTypeChanged(dashboard: QtCore.QObject):
    """ 
    Enables/disables the filter start frequency edit box.
    """
    # Toggle the Edit Box
    if str(dashboard.ui.comboBox_iq_filter_type.currentText()) == "lowpass":
        dashboard.ui.textEdit_iq_filter_start.setEnabled(False)
    elif str(dashboard.ui.comboBox_iq_filter_type.currentText()) == "bandpass":
        dashboard.ui.textEdit_iq_filter_start.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject, int)
def _slotIQ_AppendColumnClicked(dashboard: QtCore.QObject, col):
    """ 
    Copies the first row padding amounts to the remaining rows.
    """
    # Padding Before/After
    if (col == 0) or (col == 2):
        get_padding = str(dashboard.ui.tableWidget_iq_append.item(0,col).text())
        for row in range(0,dashboard.ui.tableWidget_iq_append.rowCount()):
            padding_item = QtWidgets.QTableWidgetItem(get_padding)
            padding_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_iq_append.setItem(row,col,padding_item)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TabClicked(
    dashboard: QtCore.QObject,
    button_name,
):
    """
    Simulate the IQ tab strip and select the corresponding IQ page.
    """
    page_by_button = {
        "pushButton1_iq_tab_record": dashboard.ui.page_iq_record,
        "pushButton1_iq_tab_playback": dashboard.ui.page_iq_playback,
        "pushButton1_iq_tab_inspection": dashboard.ui.page_iq_inspection,
        "pushButton1_iq_tab_crop": dashboard.ui.page_iq_crop,
        "pushButton1_iq_tab_convert": dashboard.ui.page_iq_convert,
        "pushButton1_iq_tab_append": dashboard.ui.page_iq_append,
        "pushButton1_iq_tab_transfer": dashboard.ui.page_iq_transfer,
        "pushButton1_iq_tab_timeslot": dashboard.ui.page_iq_timeslot,
        "pushButton1_iq_tab_overlap": dashboard.ui.page_iq_overlap,
        "pushButton1_iq_tab_resample": dashboard.ui.page_iq_resample,
        "pushButton1_iq_tab_ofdm": dashboard.ui.page_iq_ofdm,
        "pushButton1_iq_tab_normalize": dashboard.ui.page_iq_normalize,
        "pushButton1_iq_tab_strip": dashboard.ui.page_iq_strip,
        "pushButton1_iq_tab_split": dashboard.ui.page_iq_split,
        "pushButton1_iq_tab_ook": dashboard.ui.page_iq_ook,
        "pushButton1_iq_tab_endianness": dashboard.ui.page_iq_endianness,
    }

    page = page_by_button.get(
        button_name
    )

    if page is not None:
        dashboard.ui.stackedWidget3_iq_pages.setCurrentWidget(
            page
        )

    button_list = [
        "pushButton1_iq_tab_record",
        "pushButton1_iq_tab_playback",
        "pushButton1_iq_tab_inspection",
        "pushButton1_iq_tab_crop",
        "pushButton1_iq_tab_convert",
        "pushButton1_iq_tab_append",
        "pushButton1_iq_tab_transfer",
        "pushButton1_iq_tab_timeslot",
        "pushButton1_iq_tab_overlap",
        "pushButton1_iq_tab_resample",
        "pushButton1_iq_tab_ofdm",
        "pushButton1_iq_tab_normalize",
        "pushButton1_iq_tab_strip",
        "pushButton1_iq_tab_split",
        "pushButton1_iq_tab_ook",
        "pushButton1_iq_tab_endianness",
    ]

    for name in button_list:
        button = getattr(
            dashboard.ui,
            name,
        )

        button.setStyleSheet(
            f"QPushButton#{name} {{}}"
        )

    color3 = dashboard.backend.settings[
        "color3"
    ]

    if (
        dashboard.backend.settings[
            "color_mode"
        ]
        == "Light Mode"
    ):
        selected_style = (
            "background-color: qlineargradient("
            "spread:pad, "
            "x1:0, y1:0, "
            "x2:0, y2:1, "
            "stop:0 #e7eaee, "
            "stop:0.12 #455e7d, "
            "stop:0.3 #2e4a6d, "
            f"stop:0.85 {color3}, "
            f"stop:1 {color3}"
            ");"
        )

    else:
        selected_style = (
            "background-color: qlineargradient("
            "spread:pad, "
            "x1:0, y1:0, "
            "x2:0, y2:1, "
            f"stop:0 {color3}, "
            "stop:0.05 #888888, "
            f"stop:0.15 {color3}, "
            f"stop:0.85 {color3}, "
            f"stop:1 {color3}"
            ");"
        )

    selected_button = getattr(
        dashboard.ui,
        button_name,
    )

    selected_button.setStyleSheet(
        f"QPushButton#{button_name} {{"
        f"{selected_style}"
        "color: rgb(0, 220, 0);"
        f"border: 1px solid {color3};"
        "border-top-left-radius: 15px;"
        "border-top-right-radius: 15px;"
        "height: 27px;"
        "margin-top: 3px;"
        "}"
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_LoadIQ_Data(dashboard: QtCore.QObject):
    """ 
    Loads the IQ data file information
    """
    # Update the File Information
    try:
        dashboard.ui.label2_iq_file_name.setText("File: " + dashboard.ui.listWidget_iq_files.currentItem().text())  # File name
    except:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("No file selected.")
        return
    get_file_path = str(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    dashboard.ui.label2_iq_file_size.setText("Size: " + str(round(float((os.path.getsize(get_file_path)))/1048576,2)) + " MB")  # File Size
    dashboard.ui.textEdit_iq_crop_original.setPlainText(get_file_path)
    dashboard.ui.textEdit_iq_crop_new.setPlainText(get_file_path.rpartition('.')[0] + '_cropped.' + get_file_path.rpartition('.')[2])
    dashboard.ui.comboBox_iq_crop_data_type.setCurrentIndex(dashboard.ui.comboBox_iq_data_type.currentIndex())
    dashboard.ui.comboBox_iq_resample_data_type.setCurrentIndex(dashboard.ui.comboBox_iq_data_type.currentIndex())

    # Number of Samples
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    if number_of_bytes > 0:
        dashboard.ui.textEdit_iq_start.setPlainText("1")  # Start
        dashboard.ui.textEdit_iq_crop_start.setPlainText("1")

        if get_type == "Complex Float 32":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/8)))  # End
        elif get_type == "Float/Float 32":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/4)))
        elif get_type == "Short/Int 16":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/2)))
        elif get_type == "Int/Int 32":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/4)))
        elif get_type == "Byte/Int 8":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/1)))
        elif get_type == "Complex Int 16":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/4)))
        elif get_type == "Complex Int 8":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/2)))
        elif get_type == "Complex Float 64":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/16)))
        elif get_type == "Complex Int 64":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/16)))
        elif get_type == "Unsigned Int 8":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/1)))
        elif get_type == "Unsigned Int 16":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/2)))
        elif get_type == "Unsigned Int 32":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/4)))
        elif get_type == "Complex Unsigned Int 64":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/16)))
        elif get_type == "Complex Unsigned Int 16":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/4)))
        elif get_type == "Complex Unsigned Int 8":
            dashboard.ui.textEdit_iq_end.setPlainText(str(int(number_of_bytes/2)))
    else:
        dashboard.ui.textEdit_iq_start.setPlainText("n/a")
        dashboard.ui.textEdit_iq_end.setPlainText("n/a")

    # Sample Label
    dashboard.ui.label2_iq_samples.setText("Samples: " + str(dashboard.ui.textEdit_iq_end.toPlainText()))

    # Playback
    dashboard.ui.textEdit_iq_playback_filepath.setPlainText(
        get_file_path
    )

    # Inspection
    dashboard.ui.textEdit_iq_inspection_filepath.setPlainText(
        get_file_path
    )

    # Range Buttons
    if int(dashboard.ui.textEdit_iq_end.toPlainText()) > 1000000:
        dashboard.ui.pushButton_iq_plot_prev.setVisible(True)
        dashboard.ui.pushButton_iq_plot_next.setVisible(True)
        #dashboard.ui.pushButton_iq_plot_all.setEnabled(False)
        dashboard.ui.textEdit_iq_end.setPlainText("1000000")
    else:
        dashboard.ui.pushButton_iq_plot_prev.setVisible(False)
        dashboard.ui.pushButton_iq_plot_next.setVisible(False)
        #dashboard.ui.pushButton_iq_plot_all.setEnabled(True)

    # Reset Range Cursor Memory
    dashboard.iq_plot_range_start = 0
    dashboard.iq_plot_range_end = 0

    # SigMF Information
    if ".sigmf-data" in get_file_path:
        if os.path.isfile(get_file_path.replace('.sigmf-data','.sigmf-meta').replace('"','')):
            f = open(get_file_path.replace('.sigmf-data','.sigmf-meta'))
            metadata_file = json.load(f)
            f.close()
            if 'core:sample_rate' in metadata_file['global']:
                dashboard.ui.textEdit_iq_sample_rate.setPlainText(str(float(str(metadata_file['global']['core:sample_rate']))/1000000))
            if 'core:frequency' in metadata_file['captures'][0]:
                dashboard.ui.textEdit_iq_frequency.setPlainText(str(float(str(metadata_file['captures'][0]['core:frequency']))/1000000))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_StartChanged(dashboard: QtCore.QObject):
    """ 
    Updates the Crop start sample.
    """
    get_start = str(dashboard.ui.textEdit_iq_start.toPlainText())
    dashboard.ui.textEdit_iq_crop_start.setText(get_start)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_EndChanged(dashboard: QtCore.QObject):
    """ 
    Updates the Crop end sample.
    """
    get_end = str(dashboard.ui.textEdit_iq_end.toPlainText())
    dashboard.ui.textEdit_iq_crop_end.setText(get_end)


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QEvent)
def _slotIQ_EndLabelClicked(dashboard: QtCore.QObject, event: QtCore.QEvent):
    """ 
    Puts the maximum number of samples in the plot range end text edit.
    """
    # Copy Other Label Value
    get_samples = str(dashboard.ui.label2_iq_samples.text()).replace('Samples:','').replace(' ','')
    dashboard.ui.textEdit_iq_end.setPlainText(get_samples)


@QtCore.pyqtSlot(QtCore.QObject, QtCore.QEvent)
def _slotIQ_StartLabelClicked(dashboard: QtCore.QObject, event: QtCore.QEvent):
    """ 
    Sets the value to 1 in the plot range start text edit.
    """
    # Reset to 1
    dashboard.ui.textEdit_iq_start.setPlainText("1")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_Dir1_Clicked(dashboard: QtCore.QObject):
    """ 
    Selects a source folder for transferring files
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    dialog.setFileMode(QtWidgets.QFileDialog.Directory)
    dialog.setOption(QtWidgets.QFileDialog.ShowDirsOnly, True)

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_dir1.setText(folder)
    except:
        pass

    # Hide Success Label
    dashboard.ui.label2_iq_transfer_folder_success.setVisible(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_Dir2_Clicked(dashboard: QtCore.QObject):
    """ 
    Selects a destination folder for transferring files
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    dialog.setFileMode(QtWidgets.QFileDialog.Directory)
    dialog.setOption(QtWidgets.QFileDialog.ShowDirsOnly, True)

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_dir2.setText(folder)
    except:
        pass

    # Hide Success Label
    dashboard.ui.label2_iq_transfer_folder_success.setVisible(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TransferClicked(dashboard: QtCore.QObject):
    """ 
    Transfers files from the source folder to the destination folder
    """
    try:
        copytree(str(dashboard.ui.textEdit_iq_dir1.toPlainText()), str(dashboard.ui.textEdit_iq_dir2.toPlainText()))

        # Show Success Label
        dashboard.ui.label2_iq_transfer_folder_success.setVisible(True)

    except OSError as e:
        pass


def copytree(src, dst, symlinks=False, ignore=None):
    """ 
    Copies files from one folder to another. Creates the output directory if it does not exist. Only replaces if the file is modified. Not a slot.
    """
    if not os.path.exists(dst):
        os.makedirs(dst)
    for item in os.listdir(src):
        s = os.path.join(src, item)
        d = os.path.join(dst, item)
        if os.path.isdir(s):
            copytree(s, d, symlinks, ignore)
        else:
            if not os.path.exists(d) or os.stat(s).st_mtime - os.stat(d).st_mtime > 1:
                shutil.copy2(s, d)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_RefreshClicked(dashboard: QtCore.QObject):
    """ 
    Reloads the files in the current folder of IQ Recordings
    """
    try:
        # Get the Folder Location
        get_folder = str(dashboard.ui.label_iq_folder.text())

        # Get the Files for the Listbox
        dashboard.ui.listWidget_iq_files.clear()
        temp_names = []
        for fname in os.listdir(get_folder):
            if os.path.isfile(get_folder+"/"+fname):
                if ".sigmf-meta" not in fname:
                    temp_names.append(fname)

        # Sort and Add to the Listbox
        temp_names = sorted(temp_names)
        for n in temp_names:
            dashboard.ui.listWidget_iq_files.addItem(n)

        # Set the Listbox Selection
        dashboard.ui.listWidget_iq_files.setCurrentRow(0)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_CropClicked(dashboard: QtCore.QObject):
    """ 
    Crops a data file to a smaller size.
    """
    # Get Crop Settings
    get_file_path_original = str(dashboard.ui.textEdit_iq_crop_original.toPlainText())
    get_file_path = str(dashboard.ui.textEdit_iq_crop_new.toPlainText())
    get_start = str(int(str(dashboard.ui.textEdit_iq_crop_start.toPlainText()))-1)
    get_end = str(dashboard.ui.textEdit_iq_crop_end.toPlainText())
    get_data_type = str(dashboard.ui.comboBox_iq_crop_data_type.currentText())

    # Sample Size in Bytes
    if get_data_type == "Complex Float 32":
        bs = "8"
    elif get_data_type == "Float/Float 32":
        bs = "4"
    elif get_data_type == "Short/Int 16":
        bs = "2"
    elif get_data_type == "Int/Int 32":
        bs = "4"
    elif get_data_type == "Byte/Int 8":
        bs = "1"
    elif get_data_type == "Complex Float 64":
        bs = "16"
    elif get_data_type == "Complex Int 64":
        bs = "16"
    elif get_data_type == "Complex Int 16":
        bs = "4"
    elif get_data_type == "Complex Int 8":
        bs = "2"
    elif get_data_type == "Unsigned Int 8":
        bs = "1"
    elif get_data_type == "Unsigned Int 16":
        bs = "2"
    elif get_data_type == "Unsigned Int 32":
        bs = "4"
    elif get_data_type == "Complex Unsigned Int 64":
        bs = "16"
    elif get_data_type == "Complex Unsigned Int 16":
        bs = "4"
    elif get_data_type == "Complex Unsigned Int 8":
        bs = "2"
    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Cannot crop " + get_data_type + ".")
        return

    # Calculate Number of Samples
    num_samples = str(int(get_end)-int(get_start))

    # Exclude Samples in Range
    if dashboard.ui.checkBox_iq_crop_exclude.isChecked() == True:
        # Copy Before and After
        os.system('dd if="'+ get_file_path_original + '" of="' + get_file_path + '.tmp1" bs=' + bs + ' count=' + get_start)
        os.system('dd if="'+ get_file_path_original + '" of="' + get_file_path + '.tmp2" bs=' + bs + ' skip=' + get_end)

        # Join Temporary Files
        os.system('cat "' + get_file_path + '.tmp1" "' + get_file_path + '.tmp2" > "' + get_file_path + '"')

        # Remove Temporary Files
        os.system('rm "' + get_file_path + '.tmp1" "' + get_file_path + '.tmp2"')

    # Copy Samples in Range
    else:
        # Save File
        os.system('dd if="'+ get_file_path_original + '" of="' + get_file_path + '" bs=' + bs + ' skip=' + get_start + ' count=' + num_samples)

    # Refresh Listbox
    _slotIQ_RefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AppendSelect1Clicked(dashboard: QtCore.QObject):
    """ 
    Copies the filepath of the selected IQ file for appending.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        table_item1 = QtWidgets.QTableWidgetItem("0")
        table_item1.setTextAlignment(QtCore.Qt.AlignCenter)
        table_item2 = QtWidgets.QTableWidgetItem(get_folder + '/' + get_file)
        table_item3 = QtWidgets.QTableWidgetItem("0")
        table_item3.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_append.setRowCount(dashboard.ui.tableWidget_iq_append.rowCount()+1)
        dashboard.ui.tableWidget_iq_append.setItem(dashboard.ui.tableWidget_iq_append.rowCount()-1,0,table_item1)
        dashboard.ui.tableWidget_iq_append.setItem(dashboard.ui.tableWidget_iq_append.rowCount()-1,1,table_item2)
        dashboard.ui.tableWidget_iq_append.setItem(dashboard.ui.tableWidget_iq_append.rowCount()-1,2,table_item3)

        # Resize the Table
        dashboard.ui.tableWidget_iq_append.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_append.resizeRowsToContents()
        dashboard.ui.tableWidget_iq_append.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_append.horizontalHeader().setStretchLastSection(True)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AppendSelect2Clicked(dashboard: QtCore.QObject):
    """ 
    Copies the filepath of the selected IQ file for appending.
    """
    # Get Highlighted File from Listbox
    get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
    get_folder = str(dashboard.ui.label_iq_folder.text())
    dashboard.ui.textEdit_iq_append_output.setPlainText(get_folder + '/' + get_file)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AppendLoad1Clicked(dashboard: QtCore.QObject):
    """ 
    Opens a dialog to select an IQ file for appending.
    """
    # Choose Files
    get_iq_folder = str(dashboard.ui.comboBox3_iq_folders.currentText()) + '/'
    fname = QtWidgets.QFileDialog.getOpenFileNames(None,"Select IQ Files...", get_iq_folder, filter="All Files (*)")
    if fname != "":
        for n in fname[0]:
            table_item1 = QtWidgets.QTableWidgetItem("0")
            table_item1.setTextAlignment(QtCore.Qt.AlignCenter)
            table_item2 = QtWidgets.QTableWidgetItem(n)
            table_item3 = QtWidgets.QTableWidgetItem("0")
            table_item3.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_iq_append.setRowCount(dashboard.ui.tableWidget_iq_append.rowCount()+1)
            dashboard.ui.tableWidget_iq_append.setItem(dashboard.ui.tableWidget_iq_append.rowCount()-1,0,table_item1)
            dashboard.ui.tableWidget_iq_append.setItem(dashboard.ui.tableWidget_iq_append.rowCount()-1,1,table_item2)
            dashboard.ui.tableWidget_iq_append.setItem(dashboard.ui.tableWidget_iq_append.rowCount()-1,2,table_item3)

        # Resize the Table
        dashboard.ui.tableWidget_iq_append.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_append.resizeRowsToContents()
        dashboard.ui.tableWidget_iq_append.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_append.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AppendLoad2Clicked(dashboard: QtCore.QObject):
    """ 
    Opens a dialog to select an IQ file for appending.
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['IQ/Misc. (*.iq *.dat)','IQ Recordings (*.iq)','Misc. (*.dat)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_append_output.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AppendAppendClicked(dashboard: QtCore.QObject):
    """ 
    Concatenates two files together with cat. Prepends/Appends with 0's if samples are entered.
    """
    if dashboard.ui.tableWidget_iq_append.rowCount() > 0:
        get_output_file = str(dashboard.ui.textEdit_iq_append_output.toPlainText())
        get_type = dashboard.ui.comboBox_iq_append_data_type.currentText()
        if len(get_output_file) > 0:
            for n in range(0, dashboard.ui.tableWidget_iq_append.rowCount()):
                get_prepend = str(dashboard.ui.tableWidget_iq_append.item(n,0).text())
                get_file = str(dashboard.ui.tableWidget_iq_append.item(n,1).text())
                get_append = str(dashboard.ui.tableWidget_iq_append.item(n,2).text())

                if get_type == "Complex Float 32":
                    num_bytes1 = str(8 * int(get_prepend))
                    num_bytes2 = str(8 * int(get_append))
                elif get_type == "Float/Float 32":
                    num_bytes1 = str(4 * int(get_prepend))
                    num_bytes2 = str(4 * int(get_append))
                elif get_type == "Short/Int 16":
                    num_bytes1 = str(2* int(get_prepend))
                    num_bytes2 = str(2* int(get_append))
                elif get_type == "Int/Int 32":
                    num_bytes1 = str(4 * int(get_prepend))
                    num_bytes2 = str(4 * int(get_append))
                elif get_type == "Byte/Int 8":
                    num_bytes1 = str(1 * int(get_prepend))
                    num_bytes2 = str(1 * int(get_append))
                elif get_type == "Complex Int 16":
                    num_bytes1 = str(4 * int(get_prepend))
                    num_bytes2 = str(4 * int(get_append))
                elif get_type == "Complex Int 8":
                    num_bytes1 = str(2 * int(get_prepend))
                    num_bytes2 = str(2 * int(get_append))
                elif get_type == "Complex Float 64":
                    num_bytes1 = str(16 * int(get_prepend))
                    num_bytes2 = str(16 * int(get_append))
                elif get_type == "Complex Int 64":
                    num_bytes1 = str(16 * int(get_prepend))
                    num_bytes2 = str(16 * int(get_append))
                elif get_type == "Unsigned Int 8":
                    num_bytes1 = str(1 * int(get_prepend))
                    num_bytes2 = str(1 * int(get_append))
                elif get_type == "Unsigned Int 16":
                    num_bytes1 = str(2 * int(get_prepend))
                    num_bytes2 = str(2 * int(get_append))
                elif get_type == "Unsigned Int 32":
                    num_bytes1 = str(4 * int(get_prepend))
                    num_bytes2 = str(4 * int(get_append))
                elif get_type == "Complex Unsigned Int 64":
                    num_bytes1 = str(16 * int(get_prepend))
                    num_bytes2 = str(16 * int(get_append))
                elif get_type == "Complex Unsigned Int 16":
                    num_bytes1 = str(4 * int(get_prepend))
                    num_bytes2 = str(4 * int(get_append))
                elif get_type == "Complex Unsigned Int 8":
                    num_bytes1 = str(2 * int(get_prepend))
                    num_bytes2 = str(2 * int(get_append))

                # Copy File
                os.system('touch "' + get_output_file + '"')
                os.system('touch "' + get_output_file + '.new1"')
                os.system('touch "' + get_output_file + '.new3"')
                os.system('cp "' + get_file + '" "' + get_output_file + '.new2"')

                # Create Zeros
                os.system('dd if=/dev/zero of="' + get_output_file + '.new1" bs=1 count=' + num_bytes1)
                os.system('dd if=/dev/zero of="' + get_output_file + '.new3" bs=1 count=' + num_bytes2)

                # Combine Files
                if n == 0:
                    os.system('cat "' + get_output_file + '.new1" "' + get_output_file + '.new2" "' + get_output_file + '.new3"' + ' > "' + get_output_file + '"')
                else:
                    os.system('cat "' + get_output_file + '.new1" "' + get_output_file + '.new2" "' + get_output_file + '.new3"' + ' >> "' + get_output_file + '"')

                # Remove Temporary Files
                os.system('rm "' + get_output_file + '.new1" "' + get_output_file + '.new2" "' + get_output_file + '.new3"')

            # Refresh
            _slotIQ_RefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_DeleteClicked(dashboard: QtCore.QObject):
    """ 
    Deletes an IQ file from the list.
    """
    # Get Highlighted File from Listbox
    if dashboard.ui.listWidget_iq_files.count() > 0:
        get_index = int(dashboard.ui.listWidget_iq_files.currentRow())
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        delete_filepath = os.path.join(get_folder, get_file)

        # Confirm deletion for files and folders
        qm = QtWidgets.QMessageBox
        ret = qm.question(dashboard, '', "Delete this file?", qm.Yes | qm.No)
        if ret == qm.Yes:
            # Delete
            os.system('rm "' + delete_filepath + '"')
            if ".sigmf-data" in delete_filepath:
                if os.path.isfile(delete_filepath.replace(".sigmf-data",".sigmf-meta")):
                    os.system('rm "' + delete_filepath.replace(".sigmf-data",".sigmf-meta") + '"')

            # Refresh
            _slotIQ_RefreshClicked(dashboard)
            if get_index == dashboard.ui.listWidget_iq_files.count():
                get_index = get_index -1
            dashboard.ui.listWidget_iq_files.setCurrentRow(get_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_Cursor1Clicked(dashboard: QtCore.QObject):
    """ 
    Add/Removes a cursor on the plot.
    """
    if dashboard.ui.pushButton_iq_cursor1.isChecked():
        dashboard.iq_matplotlib_widget.cursor_enable = True
        dashboard.ui.pushButton_iq_get_range.setEnabled(True)
    else:
        dashboard.ui.pushButton_iq_get_range.setEnabled(False)
        if dashboard.iq_matplotlib_widget.cursor1 != None:
            dashboard.iq_matplotlib_widget.cursor1.remove()
            dashboard.iq_matplotlib_widget.cursor1 = None
        if dashboard.iq_matplotlib_widget.cursor2 != None:
            dashboard.iq_matplotlib_widget.cursor2.remove()
            dashboard.iq_matplotlib_widget.cursor2 = None
        if dashboard.iq_matplotlib_widget.fill_rect != None:
            dashboard.iq_matplotlib_widget.fill_rect.remove()
            dashboard.iq_matplotlib_widget.fill_rect = None
        if dashboard.iq_matplotlib_widget.txt != None:
            dashboard.iq_matplotlib_widget.txt.remove()
            dashboard.iq_matplotlib_widget.txt = None
        dashboard.iq_matplotlib_widget.click = 1
        dashboard.iq_matplotlib_widget.axes.figure.canvas.draw()
        dashboard.iq_matplotlib_widget.cursor_enable = False


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_GetRangeClicked(dashboard: QtCore.QObject):
    """ 
    Copies the cursor locations to the start and end edit boxes.
    """
    # Cursors Exist
    if dashboard.iq_matplotlib_widget.cursor1 != None and dashboard.iq_matplotlib_widget.cursor2 != None:

        # Get Scale
        get_xlabel = str(dashboard.iq_matplotlib_widget.axes.xaxis.get_label())
        if "Samples/1000" in get_xlabel:
            get_scale = 1000
        elif "Samples/100" in get_xlabel:
            get_scale = 100
        elif "Samples/10" in get_xlabel:
            get_scale = 10
        else:
            get_scale = 1

        # Get Cursor Locations
        try:
            get_start = str(get_scale * int(math.floor(dashboard.iq_matplotlib_widget.cursor1.get_xdata())))
            get_end = str(get_scale * int(math.floor(dashboard.iq_matplotlib_widget.cursor2.get_xdata())))
        except:
            get_start = str(get_scale * int(math.floor(dashboard.iq_matplotlib_widget.cursor1.get_xdata()[0])))
            get_end = str(get_scale * int(math.floor(dashboard.iq_matplotlib_widget.cursor2.get_xdata()[0])))

        # Update Text Edit Boxes
        dashboard.ui.textEdit_iq_start.setPlainText(str(int(get_start) + dashboard.iq_plot_range_start))
        dashboard.ui.textEdit_iq_end.setPlainText(str(int(get_end) + dashboard.iq_plot_range_start))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OverlapStore1Clicked(dashboard: QtCore.QObject):
    """ 
    Saves the current plot data for overlapping.
    """
    # Save Plot Data into a Variable
    if len(dashboard.iq_matplotlib_widget.axes.lines) > 0:
        dashboard.overlap_data1 = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        dashboard.ui.label2_iq_overlap_store1.setText("Stored")
        get_samples = str(len(dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()))
        dashboard.ui.label2_iq_overlap_samples1.setText(get_samples)

    # Enable Plot if Two Sources are Stored
    if str(dashboard.ui.label2_iq_overlap_samples1.text()) == "Stored" and str(dashboard.ui.label2_iq_overlap_samples2.text()) == "Stored":
        dashboard.ui.pushButton_iq_overlap_plot.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OverlapStore2Clicked(dashboard: QtCore.QObject):
    """ 
    Saves the current plot data for overlapping.
    """
    # Save Plot Data into a Variable
    if len(dashboard.iq_matplotlib_widget.axes.lines) > 0:
        dashboard.overlap_data2 = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        dashboard.ui.label2_iq_overlap_store2.setText("Stored")
        get_samples = str(len(dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()))
        dashboard.ui.label2_iq_overlap_samples2.setText(get_samples)

    # Enable Plot if Two Sources are Stored
    if str(dashboard.ui.label2_iq_overlap_store1.text()) == "Stored" and str(dashboard.ui.label2_iq_overlap_store2.text()) == "Stored":
        dashboard.ui.pushButton_iq_overlap_plot.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_SubcarrierAddClicked(dashboard: QtCore.QObject):
    """ 
    Adds a new row to enter subcarrier ranges.
    """
    # Add an Empty, Editable Row
    item = QtWidgets.QListWidgetItem()
    item.setFlags(item.flags() | QtCore.Qt.ItemIsEditable)
    dashboard.ui.listWidget_iq_ofdm_subcarriers.addItem(item)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_SubcarrierRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row of subcarrier ranges.
    """
    # Remove Items
    for item in dashboard.ui.listWidget_iq_ofdm_subcarriers.selectedItems():
        dashboard.ui.listWidget_iq_ofdm_subcarriers.takeItem(dashboard.ui.listWidget_iq_ofdm_subcarriers.row(item))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_SubcarrierClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the list of data subcarriers.
    """
    dashboard.ui.listWidget_iq_ofdm_subcarriers.clear()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_SubcarrierAddRangeClicked(dashboard: QtCore.QObject):
    """ 
    Adds a range of subcarriers to the list.
    """
    # Get Range
    get_start = int(str(dashboard.ui.textEdit_iq_ofdm_subcarrier_start.toPlainText()))
    get_skip = int(str(dashboard.ui.textEdit_iq_ofdm_subcarrier_skip.toPlainText()))
    get_end = int(str(dashboard.ui.textEdit_iq_ofdm_subcarrier_end.toPlainText()))

    # Make List
    sub_list = range(get_start,get_end,get_skip)

    # Add to the List
    for i in sub_list:
        item = QtWidgets.QListWidgetItem(str(i))
        item.setFlags(item.flags() | QtCore.Qt.ItemIsEditable)
        dashboard.ui.listWidget_iq_ofdm_subcarriers.addItem(item)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ResampleClicked(dashboard: QtCore.QObject):
    """ 
    Resamples a data file to a new rate.
    """
    # Get Values
    get_original_file = str(dashboard.ui.textEdit_iq_resample_original_file.toPlainText())
    get_new_file = str(dashboard.ui.textEdit_iq_resample_new_file.toPlainText())
    get_original_rate = float(dashboard.ui.textEdit_iq_resample_original_rate.toPlainText())
    get_new_rate = float(dashboard.ui.textEdit_iq_resample_new_rate.toPlainText())
    get_data_type = str(dashboard.ui.comboBox_iq_crop_data_type.currentText())

    # Define data type mappings
    data_type_map = {
        "Complex Float 32": ("f", 4, np.float32),
        "Float/Float 32": ("f", 4, np.float32),
        "Short/Int 16": ("h", 2, np.int16),
        "Int/Int 32": ("i", 4, np.int32),
        "Byte/Int 8": ("b", 1, np.int8),
        "Complex Int 16": ("h", 4, np.int16),
        "Complex Int 8": ("b", 2, np.int8),
        "Complex Float 64": ("d", 8, np.float64),
        "Complex Int 64": ("q", 8, np.int64),
        "Unsigned Int 8": ("B", 1, np.uint8),
        "Unsigned Int 16": ("H", 2, np.uint16),
        "Unsigned Int 32": ("I", 4, np.uint32),
        "Complex Unsigned Int 64": ("Q", 16, np.uint64),
        "Complex Unsigned Int 16": ("H", 4, np.uint16),
        "Complex Unsigned Int 8": ("B", 2, np.uint8),
    }

    # Validate input
    if not (get_original_file and get_new_file and get_original_rate > 0 and get_new_rate > 0):
        dashboard.logger.error("Invalid input parameters.")
        return

    if get_data_type not in data_type_map:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Cannot resample {get_data_type}.")
        return

    format_char, sample_size, np_dtype = data_type_map[get_data_type]

    try:
        # Read the data
        with open(get_original_file, "rb") as file:
            plot_data = file.read()

        number_of_bytes = os.path.getsize(get_original_file)
        num_samples = number_of_bytes // sample_size
        plot_data_formatted = struct.unpack(f"{num_samples}{format_char}", plot_data)

        if "Complex" in get_data_type:
            # Resample complex data
            num_resampled_samples = int(math.floor((get_new_rate / get_original_rate) * num_samples / 2))
            i_resampled = np.array(signal2.resample(plot_data_formatted[::2], num_resampled_samples), dtype=np_dtype)
            q_resampled = np.array(signal2.resample(plot_data_formatted[1::2], num_resampled_samples), dtype=np_dtype)
            new_data = np.empty((i_resampled.size + q_resampled.size,), dtype=np_dtype)
            new_data[0::2] = i_resampled
            new_data[1::2] = q_resampled
        else:
            # Resample real data
            num_resampled_samples = int(math.floor((get_new_rate / get_original_rate) * num_samples))
            new_data = np.array(signal2.resample(plot_data_formatted, num_resampled_samples), dtype=np_dtype)

        # Write resampled data to the new file
        new_data.tofile(get_new_file)
        dashboard.logger.info("Resampling completed successfully.")

    except Exception as e:
        dashboard.logger.error(f"Error during resampling: {e}")
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Resampling failed. See logs for details.")
        return

    # Refresh Listbox
    _slotIQ_RefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_FolderClicked(dashboard: QtCore.QObject):
    """ 
    Chooses a new folder containing IQ recordings to view in the listbox.
    """
    # Choose Folder
    get_pwd = str(dashboard.ui.comboBox3_iq_folders.currentText())
    get_dir = str(QtWidgets.QFileDialog.getExistingDirectory(dashboard, "Select Directory",get_pwd))

    # Add Directory to the Combobox
    if len(get_dir) > 0:

        # Load Directory and File
        folder_index = dashboard.ui.comboBox3_iq_folders.findText(get_dir)
        if folder_index < 0:
            # New Directory
            dashboard.ui.comboBox3_iq_folders.addItem(get_dir)
            dashboard.ui.comboBox3_iq_folders.setCurrentIndex(dashboard.ui.comboBox3_iq_folders.count()-1)
        else:
            # Directory Exists
            dashboard.ui.comboBox3_iq_folders.setCurrentIndex(folder_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TransferFileSelectClicked(dashboard: QtCore.QObject):
    """ 
    Returns the filepath of a source IQ file.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['IQ/Misc. (*.iq *.dat)','IQ Recordings (*.iq)','Misc. (*.dat)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_transfer_file.setPlainText(folder)
    except:
        pass

    # Hide Success Label
    dashboard.ui.label2_iq_transfer_file_success.setVisible(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TransferFileSaveAsClicked(dashboard: QtCore.QObject):
    """ 
    Returns the destination filepath for an IQ file.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['IQ/Misc. (*.iq *.dat)','IQ Recordings (*.iq)','Misc. (*.dat)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_transfer_save_as.setPlainText(folder)
    except:
        pass

    # Hide Success Label
    dashboard.ui.label2_iq_transfer_file_success.setVisible(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TranferFileClicked(dashboard: QtCore.QObject):
    """ 
    Copies the file from the source location to the destination location
    """
    # Get Files
    get_file1 = str(dashboard.ui.textEdit_iq_transfer_file.toPlainText())
    get_file2 = str(dashboard.ui.textEdit_iq_transfer_save_as.toPlainText())

    # Copy Files
    if len(get_file1) > 0 and len(get_file2) > 0:
        shutil.copy(get_file1, get_file2)

        # Show Success Label
        dashboard.ui.label2_iq_transfer_file_success.setVisible(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_CropSaveAsClicked(dashboard: QtCore.QObject):
    """ 
    Returns the destination filepath for the new IQ file.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['IQ/Misc. (*.iq *.dat)','IQ Recordings (*.iq)','Misc. (*.dat)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_crop_new.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlotNextClicked(dashboard: QtCore.QObject):
    """ 
    Increments the number of samples in the plot range.
    """
    # Get the Range
    get_start = int(dashboard.ui.textEdit_iq_start.toPlainText())
    get_end = int(dashboard.ui.textEdit_iq_end.toPlainText())
    get_max = int(dashboard.ui.label2_iq_samples.text().split(" ")[1])

    # Increment the Range
    if get_end < get_max:
        get_start = get_start + 1000000
        get_end = get_end + 1000000

        # Do Not Surpass Max
        if get_end > get_max:
            get_end = get_max
            get_start = get_max - 1000000 + 1

        # Set the Range
        dashboard.ui.textEdit_iq_start.setPlainText(str(get_start))
        dashboard.ui.textEdit_iq_end.setPlainText(str(get_end))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlotPrevClicked(dashboard: QtCore.QObject):
    """ 
    Decrements the number of samples in the plot range.
    """
    # Get the Range
    get_start = int(dashboard.ui.textEdit_iq_start.toPlainText())
    get_end = int(dashboard.ui.textEdit_iq_end.toPlainText())
    get_max = int(dashboard.ui.label2_iq_samples.text().split(" ")[1])

    # Decrement the Range
    if get_end > 1000000:
        get_start = get_start - 1000000
        get_end = get_end - 1000000

        # Do Not Surpass Min
        if get_start < 1:
            get_start = 1
            get_end = 1000000

        # Set the Range
        dashboard.ui.textEdit_iq_start.setPlainText(str(get_start))
        dashboard.ui.textEdit_iq_end.setPlainText(str(get_end))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TimeslotSelect1Clicked(dashboard: QtCore.QObject):
    """ 
    Loads the current file selected in the list widget as the input file.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.textEdit_iq_timeslot_input.setPlainText(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TimeslotSelect2Clicked(dashboard: QtCore.QObject):
    """ 
    Loads the current file selected in the list widget as the output file.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.textEdit_iq_timeslot_output.setPlainText(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TimeslotLoad1Clicked(dashboard: QtCore.QObject):
    """ 
    Opens a file dialog to select input file for padding data.
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['IQ/Misc. (*.iq *.dat)','IQ Recordings (*.iq)','Misc. (*.dat)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_timeslot_input.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TimeslotLoad2Clicked(dashboard: QtCore.QObject):
    """ 
    Opens a file dialog to select output file.
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['IQ/Misc. (*.iq *.dat)','IQ Recordings (*.iq)','Misc. (*.dat)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_timeslot_output.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TimeslotPadClicked(dashboard: QtCore.QObject):
    """ 
    Pads the input file with zeros to make evenly spaced timeslots.
    """
    if len(str(dashboard.ui.textEdit_iq_timeslot_input.toPlainText())) > 0 and len(str(dashboard.ui.textEdit_iq_timeslot_output.toPlainText())) > 0:
        dashboard.logger.info("Padding to make timeslots...")
        dashboard.logger.info("Identifying burst locations...")
        new_filepath = str(dashboard.ui.textEdit_iq_timeslot_output.toPlainText())
        filepath = str(dashboard.ui.textEdit_iq_timeslot_input.toPlainText())
        fs = int(float(str(dashboard.ui.textEdit_iq_timeslot_sample_rate.toPlainText()))*1e6)
        timeslot = float(str(dashboard.ui.textEdit_iq_timeslot_period.toPlainText()))
        sample_size = 8
        num_copies = int(str(dashboard.ui.textEdit_iq_timeslot_copies.toPlainText()))

        start_loc = [0]
        end_loc = []
        find_start = False
        find_end = True

        old_file = np.fromfile(open(filepath), dtype=np.complex64)

        # Find Start and End of Each Message
        for n in range(2,len(old_file)):

            # Find End
            if find_end is True:
                if old_file[n] == 0j and old_file[n-1] == 0j and old_file[n-2]== 0j:
                    end_loc.append(n-3)
                    find_end = False
                    find_start = True

            # Find Start
            if find_start is True:
                if old_file[n] != 0j and old_file[n-1] and old_file[n-2]== 0j:
                    start_loc.append(n-1)
                    find_end = True
                    find_start = False

        #print(start_loc)
        #print(end_loc)

        dashboard.logger.info("Burst rising edges detected: " + str(len(start_loc)))
        dashboard.logger.info("Burst falling edges detected: " + str(len(end_loc)))

        old_file = open(filepath,"rb")
        new_file = open(new_filepath,"a")

        #print("Writing to file...")
        for n in range(0,len(end_loc)):
        #for n in range(0,500):
            old_file.seek(start_loc[n]*sample_size)
            packet_len = end_loc[n]-start_loc[n]
            get_packet = old_file.read(packet_len*sample_size)
            for m in range(0,num_copies):
                    pad_bytes = (fs*timeslot-packet_len) * sample_size
                    new_file.write(get_packet)
                    new_file.write(b'\x00' * int(pad_bytes))
        old_file.close()
        new_file.close()
        dashboard.logger.info("Done")

    else:
        msgBox = MyMessageBox(my_text = "Provide input and output IQ file.", width=300, height=100)
        msgBox.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_RenameClicked(dashboard: QtCore.QObject):
    """ 
    Renames the selected IQ file.
    """
    # Get the Selected File
    try:
        get_file = dashboard.ui.listWidget_iq_files.currentItem().text()
    except:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("No File Selected.")
        return
    get_file_path = os.path.join(str(dashboard.ui.label_iq_folder.text()), get_file)

    # Open the GUI
    text, ok = QtWidgets.QInputDialog.getText(dashboard, 'Rename', 'Enter new name:', QtWidgets.QLineEdit.Normal, get_file)

    # Ok Clicked
    if ok:
        os.rename(get_file_path, os.path.join(str(dashboard.ui.label_iq_folder.text()), text))
        _slotIQ_RefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_FunctionsSettingsClicked(dashboard: QtCore.QObject):
    """ 
    Opens the Options dialog to change the settings for the IQ functions.
    """
    fissure.Dashboard.Slots.MenuBarSlots._slotMenuOptionsClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_FunctionsLeftClicked(dashboard: QtCore.QObject):
    """ 
    Decreases the index for the stackedwidget of IQ functions.
    """
    # Move Page to the Left
    new_index = dashboard.ui.stackedWidget_IQ_Functions.currentIndex() - 1
    get_count = dashboard.ui.stackedWidget_IQ_Functions.count()

    if new_index < 0:
        dashboard.ui.stackedWidget_IQ_Functions.setCurrentIndex(get_count-1)
    else:
        dashboard.ui.stackedWidget_IQ_Functions.setCurrentIndex(new_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_FunctionsRightClicked(dashboard: QtCore.QObject):
    """ 
    Increases the index for the stackedwidget of IQ functions.
    """
    # Move Page to the Right
    new_index = dashboard.ui.stackedWidget_IQ_Functions.currentIndex() + 1
    get_count = dashboard.ui.stackedWidget_IQ_Functions.count()

    if new_index >= get_count:
        dashboard.ui.stackedWidget_IQ_Functions.setCurrentIndex(0)
    else:
        dashboard.ui.stackedWidget_IQ_Functions.setCurrentIndex(new_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_TerminalClicked(dashboard: QtCore.QObject):
    """ 
    Opens a terminal to the current IQ folder.
    """
    # Open the Terminal
    get_dir = str(dashboard.ui.comboBox3_iq_folders.currentText())
    if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
        proc=subprocess.Popen('gnome-terminal', cwd=get_dir, shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
        proc=subprocess.Popen('qterminal', cwd=get_dir, shell=True)
    elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
        proc=subprocess.Popen('lxterminal', cwd=get_dir, shell=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_NormalizeOriginalLoadClicked(dashboard: QtCore.QObject):
    """ 
    Selects a file to convert to a new data type.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['Data File (*.*)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_normalize_original.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_NormalizeNewLoadClicked(dashboard: QtCore.QObject):
    """ 
    Selects the location for the new data file.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['Data File (*.*)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_normalize_new.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_NormalizeCopyClicked(dashboard: QtCore.QObject):
    """ 
    Copies the contents from the "Original File" text edit box to the "New File" text edit box.
    """
    # Copy the Contents
    get_original_file = str(dashboard.ui.textEdit_iq_normalize_original.toPlainText())
    filename_split = get_original_file.rsplit('.',1)
    if len(filename_split) == 2:
        dashboard.ui.textEdit_iq_normalize_new.setPlainText(filename_split[0] + "_norm." + filename_split[1])
    else:
        dashboard.ui.textEdit_iq_normalize_new.setPlainText(filename_split[0] + "_norm")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_NormalizeClicked(dashboard: QtCore.QObject):
    """ 
    Normalizes data from a file and saves it to a new file.
    """
    # Get Min/Max
    if dashboard.ui.comboBox_iq_normalize_min_max.currentIndex() == 0:
        get_min = -1
        get_max = 1
    elif dashboard.ui.comboBox_iq_normalize_min_max.currentIndex() == 1:
        get_min = -128
        get_max = 127
    elif dashboard.ui.comboBox_iq_normalize_min_max.currentIndex() == 2:
        get_min = -32768
        get_max = 32767
    elif dashboard.ui.comboBox_iq_normalize_min_max.currentIndex() == 3:
        get_min = -2147483648
        get_max = 2147483647
    elif dashboard.ui.comboBox_iq_normalize_min_max.currentIndex() == 4:
        get_min = -9223372036854775808
        get_max = 9223372036854775807
    else:
        try:
            get_min = float(dashboard.ui.textEdit_iq_normalize_min.toPlainText())
            get_max = float(dashboard.ui.textEdit_iq_normalize_max.toPlainText())
        except ValueError:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Not a valid float.")
            return

    # Load the Data
    get_data_type = str(dashboard.ui.comboBox_iq_normalize_data_type.currentText())
    get_original_file = str(dashboard.ui.textEdit_iq_normalize_original.toPlainText())
    get_new_file = str(dashboard.ui.textEdit_iq_normalize_new.toPlainText())

    if not get_original_file or not get_new_file:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Please specify both input and output files.")
        return

    try:
        with open(get_original_file, "rb") as file:
            plot_data = file.read()
    except IOError:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Error reading the original file.")
        return

    number_of_bytes = os.path.getsize(get_original_file)

    try:
        if get_data_type == "Complex Float 64":
            plot_data_formatted = struct.unpack(f"{number_of_bytes // 8}d", plot_data)
            np_data = np.asarray(plot_data_formatted, dtype=np.float64)

        elif get_data_type in ["Complex Float 32", "Float/Float 32"]:
            plot_data_formatted = struct.unpack(f"{number_of_bytes // 4}f", plot_data)
            np_data = np.asarray(plot_data_formatted, dtype=np.float32)

        elif get_data_type in ["Complex Int 16", "Short/Int 16"]:
            plot_data_formatted = struct.unpack(f"{number_of_bytes // 2}h", plot_data)
            np_data = np.asarray(plot_data_formatted, dtype=np.int16)

        elif get_data_type == "Complex Int 64":
            plot_data_formatted = struct.unpack(f"{number_of_bytes // 8}q", plot_data)
            np_data = np.asarray(plot_data_formatted, dtype=np.int64)

        elif get_data_type == "Int/Int 32":
            plot_data_formatted = struct.unpack(f"{number_of_bytes // 4}i", plot_data)
            np_data = np.asarray(plot_data_formatted, dtype=np.int32)

        elif get_data_type in ["Complex Int 8", "Byte/Int 8"]:
            plot_data_formatted = struct.unpack(f"{number_of_bytes}b", plot_data)
            np_data = np.asarray(plot_data_formatted, dtype=np.int8)

        elif get_data_type == "Unsigned Int 8":
            plot_data_formatted = struct.unpack(f"{number_of_bytes}B", plot_data)
            np_data = np.asarray(plot_data_formatted, dtype=np.uint8)

        elif get_data_type == "Unsigned Int 16":
            plot_data_formatted = struct.unpack(f"{number_of_bytes // 2}H", plot_data)
            np_data = np.asarray(plot_data_formatted, dtype=np.uint16)

        elif get_data_type == "Unsigned Int 32":
            plot_data_formatted = struct.unpack(f"{number_of_bytes // 4}I", plot_data)
            np_data = np.asarray(plot_data_formatted, dtype=np.uint32)

        elif get_data_type == "Unsigned Int 64":
            plot_data_formatted = struct.unpack(f"{number_of_bytes // 8}Q", plot_data)
            np_data = np.asarray(plot_data_formatted, dtype=np.uint64)

        else:
            fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Cannot normalize {get_data_type}.")
            return

        array_min = float(np.min(np_data))
        array_max = float(np.max(np_data))

        if array_min == array_max:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Data range is zero; cannot normalize.")
            return

        np_data = (np_data - array_min) * (get_max - get_min) / (array_max - array_min) + get_min
        np_data.tofile(get_new_file)
        dashboard.logger.info("Normalization complete and file saved.")

    except (struct.error, ValueError) as e:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Error processing data: {e}")
        return

    # Refresh
    _slotIQ_RefreshClicked(dashboard)
    dashboard.logger.info("Convert Complete")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ResampleOriginalLoadClicked(dashboard: QtCore.QObject):
    """ 
    Selects a file to convert to a new data type.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['Data File (*.*)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_resample_original_file.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ResampleNewLoadClicked(dashboard: QtCore.QObject):
    """ 
    Selects the location for the new data file.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['Data File (*.*)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_resample_new_file.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ResampleOriginalSelectClicked(dashboard: QtCore.QObject):
    """ 
    Loads the current file selected in the list widget as the input file.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.textEdit_iq_resample_original_file.setPlainText(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ResampleNewSelectClicked(dashboard: QtCore.QObject):
    """ 
    Loads the current file selected in the list widget as the output file.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.textEdit_iq_resample_new_file.setPlainText(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ResampleCopyClicked(dashboard: QtCore.QObject):
    """ 
    Copies the contents from the "Original File" text edit box to the "New File" text edit box.
    """
    # Copy the Contents
    get_original_file = str(dashboard.ui.textEdit_iq_resample_original_file.toPlainText())
    filename_split = get_original_file.rsplit('.',1)
    if len(filename_split) == 2:
        dashboard.ui.textEdit_iq_resample_new_file.setPlainText(filename_split[0] + "_resampled." + filename_split[1])
    else:
        dashboard.ui.textEdit_iq_resample_new_file.setPlainText(filename_split[0] + "_resampled")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_NormalizeOriginalSelectClicked(dashboard: QtCore.QObject):
    """ 
    Loads the current file selected in the list widget as the input file.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.textEdit_iq_normalize_original.setPlainText(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_NormalizeNewSelectClicked(dashboard: QtCore.QObject):
    """ 
    Loads the current file selected in the list widget as the output file.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.textEdit_iq_normalize_new.setPlainText(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_GqrxClicked(dashboard: QtCore.QObject):
    """ 
    Opens an IQ file in Gqrx.
    """
    # Get IQ File
    get_iq_file = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File:","").lstrip()

    # Get Sample Rate and Frequency
    get_sample_rate = str(dashboard.ui.textEdit_iq_sample_rate.toPlainText())
    get_frequency = str(dashboard.ui.textEdit_iq_frequency.toPlainText())
    try:
        fissure.utils.isFloat(float(get_sample_rate))
        fissure.utils.isFloat(float(get_frequency))
        get_sample_rate = str(int(float(get_sample_rate)*1000000))
        get_frequency = str(int(float(get_frequency)*1000000))
    except:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter a valid sample rate and frequency.")
        return

    # Modify Local Gqrx Config File
    if (len(dashboard.ui.label2_iq_file_name.text().replace("File:","").lstrip()) > 0) and (len(get_sample_rate) > 0) and (len(get_frequency) > 0):
        fin = open(os.path.join(fissure.utils.TOOLS_DIR, "Gqrx", "template.conf"), "rt")
        fout = open(os.path.join(fissure.utils.TOOLS_DIR, "Gqrx", "default.conf"), "wt")
        file_text = fin.read()
        file_text = file_text.replace('<file>', get_iq_file)
        file_text = file_text.replace('<rate>', get_sample_rate)
        file_text = file_text.replace('<freq>', get_frequency)
        fin.close()
        fout.write(file_text)
        fout.close()

        # Open Gqrx
        proc = subprocess.Popen('gqrx -c "' + os.path.join(fissure.utils.TOOLS_DIR, "Gqrx", "default.conf") + '"', shell=True)

    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select a valid file, sample rate, and frequency.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_InspectrumClicked(dashboard: QtCore.QObject):
    """ 
    Opens an IQ file in Inspectrum.
    """
    # Get IQ File
    get_iq_file = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File:","").lstrip()

    if len(dashboard.ui.label2_iq_file_name.text().replace("File:","").lstrip()) > 0:

        # Get Sample Rate
        get_sample_rate = str(dashboard.ui.textEdit_iq_sample_rate.toPlainText())
        try:
            fissure.utils.isFloat(float(get_sample_rate))
            get_sample_rate = str(int(float(get_sample_rate)*1000000))
            proc = subprocess.Popen('inspectrum -r ' + get_sample_rate + ' "' + get_iq_file + '"', shell=True)
        except:
            proc = subprocess.Popen('inspectrum "' + get_iq_file + '"', shell=True)

    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Load an IQ file and try again.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_SigMF_Clicked(dashboard: QtCore.QObject):
    """ 
    Opens the SigMF metadata file in a text editor.
    """
    # Open the File
    get_iq_file = os.path.join(str(dashboard.ui.comboBox3_iq_folders.currentText()), str(dashboard.ui.listWidget_iq_files.currentItem().text()))
    if ".sigmf-data" in get_iq_file:
        get_meta_file = get_iq_file.replace('.sigmf-data','.sigmf-meta')
        if os.path.isfile(get_meta_file.replace('"','')):
            os.system('gedit "' + get_meta_file + '" &')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_StripClicked(dashboard: QtCore.QObject):
    """ 
    Removes samples before and after a signal in IQ files.
    """
    # Get Inputs
    get_overwrite = dashboard.ui.checkBox_iq_strip_overwrite.isChecked()
    get_before = dashboard.ui.checkBox_iq_strip_before.isChecked()
    get_after = dashboard.ui.checkBox_iq_strip_after.isChecked()
    get_data_type = str(dashboard.ui.comboBox_iq_strip_data_type.currentText())
    get_threshold = dashboard.ui.textEdit_iq_strip_amplitude.toPlainText()
    get_output_directory = str(dashboard.ui.textEdit_iq_strip_output.toPlainText())

    # Validate Inputs
    if not get_overwrite and not get_output_directory:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select output directory")
        return

    if not get_threshold:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter amplitude threshold")
        return

    if dashboard.ui.listWidget_iq_strip_input.count() == 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select IQ files to be stripped")
        return

    # Process IQ Files
    for n in range(dashboard.ui.listWidget_iq_strip_input.count()):
        fname = str(dashboard.ui.listWidget_iq_strip_input.item(n).text())
        new_file = fname if get_overwrite else f"{get_output_directory}/{os.path.splitext(os.path.basename(fname))[0]}_stripped.{os.path.splitext(fname)[1]}"

        if not os.path.isfile(fname):
            continue

        dashboard.logger.info(f"Stripping: {fname}")

        with open(fname, "rb") as file:
            plot_data = file.read()

        number_of_bytes = os.path.getsize(fname)
        try:
            # Determine Data Type and Load Data
            data_types = {
                "Complex Float 32": ("f", np.complex64),
                "Float/Float 32": ("f", np.float32),
                "Short/Int 16": ("h", np.int16),
                "Unsigned Int 16": ("H", np.uint16),
                "Int/Int 32": ("i", np.int32),
                "Unsigned Int 32": ("I", np.uint32),
                "Byte/Int 8": ("b", np.int8),
                "Unsigned Int 8": ("B", np.uint8),
                "Complex Float 64": ("d", np.complex128),
                "Complex Int 64": ("q", np.int64),
                "Complex Unsigned Int 64": ("Q", np.uint64),
                "Complex Int 16": ("h", np.int16),
                "Complex Unsigned Int 16": ("H", np.uint16),
                "Complex Int 8": ("b", np.int8),
                "Complex Unsigned Int 8": ("B", np.uint8),
            }

            struct_format, numpy_dtype = data_types.get(get_data_type, (None, None))
            if not struct_format:
                raise ValueError("Unknown Data Type")

            plot_data_formatted = struct.unpack(int(number_of_bytes / struct.calcsize(struct_format)) * struct_format, plot_data)
            np_data = np.array(plot_data_formatted, dtype=numpy_dtype)

            # Strip Data
            strip_left, strip_right = 0, len(np_data)
            if get_before:
                for i, sample in enumerate(np_data):
                    if abs(sample) > float(get_threshold):
                        strip_left = i
                        break
            if get_after:
                for i in reversed(range(len(np_data))):
                    if abs(np_data[i]) > float(get_threshold):
                        strip_right = i + 1
                        break
            np_data = np_data[strip_left:strip_right]

            # Save Data
            np_data.tofile(new_file)
        except ValueError as e:
            fissure.Dashboard.UI_Components.Qt5.errorMessage(str(e))
            return

    _slotIQ_RefreshClicked(dashboard)
    dashboard.logger.info("Complete")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_StripSelectClicked(dashboard: QtCore.QObject):
    """ 
    Selects an IQ file from the Data Viewer and adds it to the listwidget.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.listWidget_iq_strip_input.addItem(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_StripLoadClicked(dashboard: QtCore.QObject):
    """ 
    Load multiple IQ files into the listwidget.
    """
    # Choose Files
    get_iq_folder = str(dashboard.ui.comboBox3_iq_folders.currentText()) + '/'
    fname = QtWidgets.QFileDialog.getOpenFileNames(None,"Select IQ Files...", get_iq_folder, filter="All Files (*)")
    if fname != "":
        for n in fname[0]:
            dashboard.ui.listWidget_iq_strip_input.addItem(n)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_StripRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a file from the list widget.
    """
    # Remove
    if dashboard.ui.listWidget_iq_strip_input.count() > 0:
        get_index = int(dashboard.ui.listWidget_iq_strip_input.currentRow())
        for item in dashboard.ui.listWidget_iq_strip_input.selectedItems():
            dashboard.ui.listWidget_iq_strip_input.takeItem(dashboard.ui.listWidget_iq_strip_input.row(item))

        # Refresh
        if get_index == dashboard.ui.listWidget_iq_strip_input.count():
            get_index = get_index -1
        dashboard.ui.listWidget_iq_strip_input.setCurrentRow(get_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_StripChooseClicked(dashboard: QtCore.QObject):
    """ 
    Choose an output directory to store new stripped IQ files.
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    dialog.setFileMode(QtWidgets.QFileDialog.Directory)
    dialog.setOption(QtWidgets.QFileDialog.ShowDirsOnly, True)

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_strip_output.setText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_StripClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Strip tab list widget.
    """
    # Clear the List Widget
    dashboard.ui.listWidget_iq_strip_input.clear()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AppendClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Append tab table.
    """
    # Remove Rows
    dashboard.ui.tableWidget_iq_append.setRowCount(0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AppendRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes the selected rows from the Append tab table.
    """
    # Remove Rows
    if dashboard.ui.tableWidget_iq_append.rowCount() > 0:
        # Find Selected Rows Manually (selectedRanges() not working for programmatic selection?)
        first = -1
        last = -1
        for n in range(0,dashboard.ui.tableWidget_iq_append.rowCount()):
            for m in range(0,3):
                item = dashboard.ui.tableWidget_iq_append.item(n,m)
                if item:
                    if item.isSelected():
                        if first == -1:
                            first = n
                            last = n
                            break
                        last = n
                        break

        for n in reversed(range(first,last+1)):
            dashboard.ui.tableWidget_iq_append.removeRow(n)

        # Highlight New Row
        if dashboard.ui.tableWidget_iq_append.rowCount() > first:
            dashboard.ui.tableWidget_iq_append.selectRow(first)
        else:
            dashboard.ui.tableWidget_iq_append.selectRow(dashboard.ui.tableWidget_iq_append.rowCount()-1)

        # Resize the Table
        dashboard.ui.tableWidget_iq_append.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_append.resizeRowsToContents()
        dashboard.ui.tableWidget_iq_append.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_append.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AppendUpClicked(dashboard: QtCore.QObject):
    """ 
    Moves a row up in the Append tab table.
    """
    if dashboard.ui.tableWidget_iq_append.rowCount() > 1:
        # Find Selected Rows Manually (selectedRanges() not working for programmatic selection?)
        first = -1
        last = -1
        for n in range(0,dashboard.ui.tableWidget_iq_append.rowCount()):
            for m in range(0,3):
                item = dashboard.ui.tableWidget_iq_append.item(n,m)
                if item:
                    if item.isSelected():
                        if first == -1:
                            first = n
                            last = n
                            break
                        last = n
                        break

        if first > 0:
            # Take the Row Above
            above_item0 = dashboard.ui.tableWidget_iq_append.takeItem(first-1,0)
            above_item1 = dashboard.ui.tableWidget_iq_append.takeItem(first-1,1)
            above_item2 = dashboard.ui.tableWidget_iq_append.takeItem(first-1,2)

            for n in range(first,last+1):
                # Take the Selected Row
                current_item0 = dashboard.ui.tableWidget_iq_append.takeItem(n,0)
                current_item1 = dashboard.ui.tableWidget_iq_append.takeItem(n,1)
                current_item2 = dashboard.ui.tableWidget_iq_append.takeItem(n,2)

                # Move it Up
                dashboard.ui.tableWidget_iq_append.setItem(n-1,0,current_item0)
                dashboard.ui.tableWidget_iq_append.setItem(n-1,1,current_item1)
                dashboard.ui.tableWidget_iq_append.setItem(n-1,2,current_item2)

            # Move the Row above Selection Down
            dashboard.ui.tableWidget_iq_append.setItem(last,0,above_item0)
            dashboard.ui.tableWidget_iq_append.setItem(last,1,above_item1)
            dashboard.ui.tableWidget_iq_append.setItem(last,2,above_item2)

            # Keep the Selection
            dashboard.ui.tableWidget_iq_append.clearSelection()
            for n in range(first-1,last):
                for m in range(0,3):
                    item = dashboard.ui.tableWidget_iq_append.item(n,m)
                    if item:
                        item.setSelected(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AppendDownClicked(dashboard: QtCore.QObject):
    """ 
    Moves a row down in the Append tab table.
    """
    if dashboard.ui.tableWidget_iq_append.rowCount() > 1:
        # Find Selected Rows Manually (selectedRanges() not working for programmatic selection?)
        first = -1
        last = -1
        for n in range(0,dashboard.ui.tableWidget_iq_append.rowCount()):
            for m in range(0,3):
                item = dashboard.ui.tableWidget_iq_append.item(n,m)
                if item:
                    if item.isSelected():
                        if first == -1:
                            first = n
                            last = n
                            break
                        last = n
                        break

        if last < dashboard.ui.tableWidget_iq_append.rowCount()-1:
            # Take the Row Below
            above_item0 = dashboard.ui.tableWidget_iq_append.takeItem(last+1,0)
            above_item1 = dashboard.ui.tableWidget_iq_append.takeItem(last+1,1)
            above_item2 = dashboard.ui.tableWidget_iq_append.takeItem(last+1,2)

            for n in reversed(range(first,last+1)):
                # Take the Selected Row
                current_item0 = dashboard.ui.tableWidget_iq_append.takeItem(n,0)
                current_item1 = dashboard.ui.tableWidget_iq_append.takeItem(n,1)
                current_item2 = dashboard.ui.tableWidget_iq_append.takeItem(n,2)

                # Move it Down
                dashboard.ui.tableWidget_iq_append.setItem(n+1,0,current_item0)
                dashboard.ui.tableWidget_iq_append.setItem(n+1,1,current_item1)
                dashboard.ui.tableWidget_iq_append.setItem(n+1,2,current_item2)

            # Move the Row below Selection Up
            dashboard.ui.tableWidget_iq_append.setItem(first,0,above_item0)
            dashboard.ui.tableWidget_iq_append.setItem(first,1,above_item1)
            dashboard.ui.tableWidget_iq_append.setItem(first,2,above_item2)

            # Keep the Selection
            dashboard.ui.tableWidget_iq_append.clearSelection()
            for n in range(first+1,last+2):
                for m in range(0,3):
                    item = dashboard.ui.tableWidget_iq_append.item(n,m)
                    if item:
                        item.setSelected(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AppendCopyClicked(dashboard: QtCore.QObject):
    """ 
    Duplicates rows in the Append table.
    """
    if dashboard.ui.tableWidget_iq_append.rowCount() > 0:
        # Find Selected Rows Manually (selectedRanges() not working for programmatic selection?)
        first = -1
        last = -1
        for n in range(0,dashboard.ui.tableWidget_iq_append.rowCount()):
            for m in range(0,3):
                item = dashboard.ui.tableWidget_iq_append.item(n,m)
                if item:
                    if item.isSelected():
                        if first == -1:
                            first = n
                            last = n
                            break
                        last = n
                        break

        # Insert Rows
        for n in reversed(range(first,last+1)):
            dashboard.ui.tableWidget_iq_append.insertRow(last+1)
            for m in range(0,3):
                new_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_iq_append.item(n,m).text()))
                if (m == 0) or (m == 2):
                    new_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_iq_append.setItem(last+1,m,new_item)

        # Keep the Selection
        dashboard.ui.tableWidget_iq_append.clearSelection()
        for n in range(first,last+1):
            for m in range(0,3):
                item = dashboard.ui.tableWidget_iq_append.item(n,m)
                if item:
                    item.setSelected(True)

        # Resize the Table
        dashboard.ui.tableWidget_iq_append.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_append.resizeRowsToContents()
        dashboard.ui.tableWidget_iq_append.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_append.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_SplitInputSelectClicked(dashboard: QtCore.QObject):
    """ 
    Loads the current file selected in the list widget as the input file.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.textEdit_iq_split_input.setPlainText(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_SplitInputLoadClicked(dashboard: QtCore.QObject):
    """ 
    Selects a file to split.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['Data File (*.*)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_split_input.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_SplitOutputSelectClicked(dashboard: QtCore.QObject):
    """ 
    Loads the current file selected in the list widget as the output file template.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.textEdit_iq_split_output.setPlainText(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_SplitOutputLoadClicked(dashboard: QtCore.QObject):
    """ 
    Selects a file for split output template.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.IQ_RECORDINGS_DIR  # Default Directory
    dialog.setDirectory(directory)
    dialog.setNameFilters(['Data File (*.*)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_split_output.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_SplitClicked(dashboard: QtCore.QObject):
    """ 
    Splits a large file into many smaller files.
    """
    # Get Values
    get_data_type = str(dashboard.ui.comboBox_iq_split_data_type.currentText())
    get_input_file = str(dashboard.ui.textEdit_iq_split_input.toPlainText())
    get_output_file = str(dashboard.ui.textEdit_iq_split_output.toPlainText())
    get_num_files = int(dashboard.ui.spinBox_iq_split.value())
    if not get_input_file or not get_output_file:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter filepaths")
        return

    # Number of Samples
    number_of_bytes = os.path.getsize(get_input_file)
    num_samples = 0
    type_to_bytes = {
        "Complex Float 32": 8,
        "Float/Float 32": 4,
        "Short/Int 16": 2,
        "Unsigned Int 16": 2,
        "Int/Int 32": 4,
        "Unsigned Int 32": 4,
        "Byte/Int 8": 1,
        "Unsigned Int 8": 1,
        "Complex Float 64": 16,
        "Complex Int 64": 16,
        "Complex Unsigned Int 64": 16,
        "Complex Int 16": 4,
        "Complex Unsigned Int 16": 4,
        "Complex Int 8": 2,
        "Complex Unsigned Int 8": 2,
    }

    if number_of_bytes > 0:
        if get_data_type in type_to_bytes:
            num_samples = number_of_bytes // type_to_bytes[get_data_type]
        else:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid data type selected.")
            return
    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Error. File is empty.")
        return

    # Split
    block_size = num_samples // get_num_files
    remainder = num_samples % get_num_files

    # Sample Size in Bytes
    bs = str(type_to_bytes.get(get_data_type, 1))  # Default to 1 if type is invalid

    # Save Files
    start_location = 0
    for n in range(get_num_files):
        if '.' in get_output_file:
            new_output_file = f"{get_output_file.rpartition('.')[0]}_{n+1}.{get_output_file.rpartition('.')[2]}"
        else:
            new_output_file = f"{get_output_file}_{n+1}"
        
        # Last File Gets Remainder
        count = block_size + remainder if n == get_num_files - 1 else block_size
        os.system(f'dd if="{get_input_file}" of="{new_output_file}" bs={bs} skip={start_location} count={count}')
        start_location += block_size

    # Refresh the List
    _slotIQ_RefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OOK_SaveClicked(dashboard: QtCore.QObject):
    """ 
    Generates and saves the OOK signal to file.
    """  
    # Retrieve Parameters
    get_chip0_pattern = str(dashboard.ui.textEdit_iq_ook_chip0_pattern.toPlainText())
    get_chip1_pattern = str(dashboard.ui.textEdit_iq_ook_chip1_pattern.toPlainText())
    get_burst_interval = str(dashboard.ui.textEdit_iq_ook_burst_interval.toPlainText())
    get_sample_rate = str(dashboard.ui.textEdit_iq_ook_sample_rate.toPlainText())
    get_chip0_duration = str(dashboard.ui.textEdit_iq_ook_chip0_duration.toPlainText())
    get_chip1_duration = str(dashboard.ui.textEdit_iq_ook_chip1_duration.toPlainText())
    get_number_of_bursts = int(dashboard.ui.spinBox_iq_ook_bursts.value())
    get_data_type = str(dashboard.ui.comboBox_iq_ook_data_type.currentText())
    get_sequence = str(dashboard.ui.textEdit_iq_ook_sequence.toPlainText())
    
    # Save
    path = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save IQ File', fissure.utils.IQ_RECORDINGS_DIR)
    if len(path[0]) > 0:
        # Generate Signal
        signal_data = generateOOK_Signal(dashboard, get_chip0_pattern, get_chip1_pattern, get_burst_interval, get_sample_rate, get_chip0_duration, get_chip1_duration, get_number_of_bursts, get_data_type, get_sequence)
        signal_data.tofile(path[0])


def generateOOK_Signal(dashboard: QtCore.QObject, chip0_pattern, chip1_pattern, burst_interval, sample_rate, chip0_duration, chip1_duration, number_of_bursts, data_type, sequence):
    """ 
    Creates an OOK signal from input parameters. Not a slot.
    """
    # Determine Samples
    chip0_samples = int(float(chip0_duration) * 1e-6 * float(sample_rate) * 1e6)  # in us and MS/s
    chip1_samples = int(float(chip1_duration) * 1e-6 * float(sample_rate) * 1e6)
    
    # Convert Bits to Chips
    sequence = sequence.replace(' ', '')
    chip_stream = ''
    for n in range(len(sequence)):
        if sequence[n] == "0":
            chip_stream += chip0_pattern
        elif sequence[n] == "1":
            chip_stream += chip1_pattern
        else:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid chip/bit sequence. Enter as a series of 0's and 1's.")
            return -1       
            
    # Convert Chips to Samples
    chip_samples = ''
    for n in range(len(chip_stream)):
        if chip_stream[n] == "0":
            chip_samples += chip_stream[n] * chip0_samples
        elif chip_stream[n] == "1":
            chip_samples += chip_stream[n] * chip1_samples
            
    # Add in Bursts
    burst_samples = ''
    for n in range(int(number_of_bursts)):
        burst_samples += chip_samples + "0" * int(float(burst_interval) * 1e-6 * float(sample_rate) * 1e6)

    # Format Samples
    sample_array = np.array([int(sample) for sample in burst_samples])
    
    if data_type == "Complex Float 32":
        signal_array = np.zeros(len(sample_array), dtype=np.complex64)
        signal_array.real = sample_array.astype(np.float32)
    elif data_type == "Float/Float 32":
        signal_array = sample_array.astype(np.float32)
    elif data_type == "Short/Int 16":
        signal_array = sample_array.astype(np.int16)
    elif data_type == "Unsigned Int 16":
        signal_array = sample_array.astype(np.uint16)
    elif data_type == "Int/Int 32":
        signal_array = sample_array.astype(np.int32)
    elif data_type == "Unsigned Int 32":
        signal_array = sample_array.astype(np.uint32)
    elif data_type == "Byte/Int 8":
        signal_array = sample_array.astype(np.int8)
    elif data_type == "Unsigned Int 8":
        signal_array = sample_array.astype(np.uint8)
    elif data_type == "Complex Float 64":
        signal_array = np.zeros(len(sample_array), dtype=np.complex128)
        signal_array.real = sample_array.astype(np.float64)
    elif data_type == "Complex Int 64":
        signal_array = np.zeros(len(sample_array), dtype=np.complex128)
        signal_array.real = sample_array.astype(np.int64)
    elif data_type == "Complex Unsigned Int 64":
        signal_array = np.zeros(len(sample_array), dtype=np.complex128)
        signal_array.real = sample_array.astype(np.uint64)
    elif data_type == "Complex Int 16":
        signal_array = np.zeros(len(sample_array), dtype=np.complex64)
        signal_array.real = sample_array.astype(np.int16)
    elif data_type == "Complex Unsigned Int 16":
        signal_array = np.zeros(len(sample_array), dtype=np.complex64)
        signal_array.real = sample_array.astype(np.uint16)
    elif data_type == "Complex Int 8":
        signal_array = np.zeros(len(sample_array), dtype=np.complex64)
        signal_array.real = sample_array.astype(np.int8)
    elif data_type == "Complex Unsigned Int 8":
        signal_array = np.zeros(len(sample_array), dtype=np.complex64)
        signal_array.real = sample_array.astype(np.uint8)
    else:
        signal_array = -1
        dashboard.logger.error("Invalid data type for OOK signal generation.")

    return signal_array


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlotRangeClicked(dashboard: QtCore.QObject):
    """ 
    Plots the selected IQ file within the specified range.
    """
    # Get the Filepath
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/"+dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    if number_of_bytes > 0:

        # Get the Number of Samples
        try:
            start_sample = int(dashboard.ui.textEdit_iq_start.toPlainText())
            end_sample = int(dashboard.ui.textEdit_iq_end.toPlainText())
            num_samples = end_sample - start_sample + 1
        except:
            return

        # Do Nothing if Bad Range
        if num_samples < 0:
            return

        # Do Not Load Large Amounts of Data
        if num_samples < 5000000:

            # Get the Size of Each Sample in Bytes
            complex_multiple = 1
            if get_type == "Complex Float 32":
                complex_multiple = 2
                sample_size = 4
                num_samples = complex_multiple * num_samples
            elif get_type == "Float/Float 32":
                sample_size = 4
            elif get_type == "Short/Int 16":
                sample_size = 2
            elif get_type == "Int/Int 32":
                sample_size = 4
            elif get_type == "Byte/Int 8":
                sample_size = 1
            elif get_type == "Complex Int 16":
                complex_multiple = 2
                sample_size = 2
                num_samples = complex_multiple * num_samples
            elif get_type == "Complex Int 8":
                complex_multiple = 2
                sample_size = 1
                num_samples = complex_multiple * num_samples
            elif get_type == "Complex Float 64":
                complex_multiple = 2
                sample_size = 8
                num_samples = complex_multiple * num_samples
            elif get_type == "Complex Int 64":
                complex_multiple = 2
                sample_size = 8
                num_samples = complex_multiple * num_samples
            elif get_type == "Unsigned Int 8":
                sample_size = 1
            elif get_type == "Unsigned Int 16":
                sample_size = 2
            elif get_type == "Unsigned Int 32":
                sample_size = 4
            elif get_type == "Complex Unsigned Int 64":
                sample_size = 8
                complex_multiple = 2
                num_samples = complex_multiple * num_samples
            elif get_type == "Complex Unsigned Int 16":
                sample_size = 2
                complex_multiple = 2
                num_samples = complex_multiple * num_samples
            elif get_type == "Complex Unsigned Int 8":
                sample_size = 1
                complex_multiple = 2
                num_samples = complex_multiple * num_samples

            # Check the Range
            if (num_samples*sample_size > number_of_bytes) or (complex_multiple*end_sample*sample_size > number_of_bytes) or (start_sample < 1):
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Samples out of range")
                return

            # Read the Data
            filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
            file = open(filepath,"rb")                          # Open the file
            if "Complex" in get_type:
                file.seek(2*(start_sample-1) * sample_size)     # Point to the starting sample
            else:
                file.seek((start_sample-1) * sample_size)       # Point to the starting sample
            plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes
            file.close()

            # Format the Data
            if get_type == "Complex Float 32":
                plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
            elif get_type == "Float/Float 32":
                plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
            elif get_type == "Short/Int 16":
                plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
            elif get_type == "Int/Int 32":
                plot_data_formatted = struct.unpack(num_samples*'i', plot_data)
            elif get_type == "Byte/Int 8":
                plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
            elif get_type == "Complex Int 16":
                plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
            elif get_type == "Complex Int 8":
                plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
            elif get_type == "Complex Float 64":
                plot_data_formatted = struct.unpack(num_samples*'d', plot_data)
            elif get_type == "Complex Int 64":
                plot_data_formatted = struct.unpack(num_samples*'l', plot_data)
            elif get_type == "Unsigned Int 8":
                plot_data_formatted = struct.unpack(int(len(plot_data)/1)*'B', plot_data)
            elif get_type == "Unsigned Int 16":
                plot_data_formatted = struct.unpack(int(len(plot_data)/2)*'H', plot_data)
            elif get_type == "Unsigned Int 32":
                plot_data_formatted = struct.unpack(int(len(plot_data)/4)*'I', plot_data)
            elif get_type == "Complex Unsigned Int 64":
                plot_data_formatted = struct.unpack(int(len(plot_data)/8)*'Q', plot_data)
            elif get_type == "Complex Unsigned Int 16":
                plot_data_formatted = struct.unpack(int(len(plot_data)/2)*'H', plot_data)
            elif get_type == "Complex Unsigned Int 8":
                plot_data_formatted = struct.unpack(int(len(plot_data)/1)*'B', plot_data)

            # Plot
            dashboard.iq_matplotlib_widget.clearPlot()
            dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
            if "Complex" in get_type:
                # Ignore hold() Deprecation Warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    warnings.filterwarnings("ignore", module="matplotlib")

                    # Plot
                    dashboard.iq_matplotlib_widget.axes.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[::2],'b',linewidth=1)
                    #dashboard.iq_matplotlib_widget.axes.hold(True)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()
                    dashboard.iq_matplotlib_widget.axes.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[1::2],'r',linewidth=1)
                    #dashboard.iq_matplotlib_widget.axes.hold(False)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()
            else:
                dashboard.iq_matplotlib_widget.axes.plot(range(1,len(plot_data_formatted)+1),plot_data_formatted,'b',linewidth=1)

            dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
            dashboard.ui.pushButton_iq_cursor1.setChecked(False)
            _slotIQ_Cursor1Clicked(dashboard)
            #dashboard.iq_matplotlib_widget.draw()

            # Set Range Cursor Memory
            dashboard.iq_plot_range_start = start_sample
            dashboard.iq_plot_range_end = end_sample

        else:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Too many samples for plotting.")

    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("File is empty or invalid")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlotAllClicked(dashboard: QtCore.QObject):
    """ 
    Plots all samples of an IQ file.
    """
    # File Loaded
    if len(dashboard.ui.label2_iq_file_name.text().split('File:')[-1]) == 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Load an IQ file before plotting by double-clicking the filename or clicking the Load File button.")
        return

    # Get the Filepath
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    # File with Zero Bytes
    if number_of_bytes <= 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("File is empty. Load a valid IQ file before plotting.")
        return

    # Skip Bytes if File is Too Large
    # Get the Number of Samples
    start_sample = 1
    num_samples = int(dashboard.ui.label2_iq_samples.text().split(" ")[1])

    # Get the Size of Each Sample in Bytes
    complex_multiple = 1
    if get_type == "Complex Float 32":
        sample_size = 4
        complex_multiple = 2
        num_samples = complex_multiple * num_samples
    elif get_type == "Float/Float 32":
        sample_size = 4
    elif get_type == "Short/Int 16":
        sample_size = 2
    elif get_type == "Int/Int 32":
        sample_size = 4
    elif get_type == "Byte/Int 8":
        sample_size = 1
    elif get_type == "Complex Int 16":
        sample_size = 2
        complex_multiple = 2
        num_samples = complex_multiple * num_samples
    elif get_type == "Complex Int 8":
        sample_size = 1
        complex_multiple = 2
        num_samples = complex_multiple * num_samples
    elif get_type == "Complex Float 64":
        sample_size = 8
        complex_multiple = 2
        num_samples = complex_multiple * num_samples
    elif get_type == "Complex Int 64":
        sample_size = 8
        complex_multiple = 2
        num_samples = complex_multiple * num_samples
    elif get_type == "Unsigned Int 8":
        sample_size = 1
    elif get_type == "Unsigned Int 16":
        sample_size = 2
    elif get_type == "Unsigned Int 32":
        sample_size = 4
    elif get_type == "Complex Unsigned Int 64":
        sample_size = 8
        complex_multiple = 2
        num_samples = complex_multiple * num_samples
    elif get_type == "Complex Unsigned Int 16":
        sample_size = 2
        complex_multiple = 2
        num_samples = complex_multiple * num_samples
    elif get_type == "Complex Unsigned Int 8":
        sample_size = 1
        complex_multiple = 2
        num_samples = complex_multiple * num_samples

    # Read the Data
    plot_data = b''
    filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
    file = open(filepath,"rb")
    # Open the file
    try:
        if "Complex" in get_type:
            starting_byte = 2*(start_sample-1) * sample_size
        else:
            starting_byte = (start_sample-1) * sample_size

        # No Skip
        if number_of_bytes <= 400000:
            skip = 1
            file.seek(starting_byte)
            plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes

        # Skip
        else:
            # Every 10th Sample
            if number_of_bytes > 400000 and number_of_bytes <= 4000000:
                skip = 10

            # Every 100th Sample
            elif number_of_bytes > 4000000 and number_of_bytes <= 40000000:
                skip = 100

            # Every 1000th Sample
            elif number_of_bytes > 40000000 and number_of_bytes <= 400000000:
                skip = 1000

            # Every 10000th Sample
            elif number_of_bytes > 400000000 and number_of_bytes <= 4000000000:
                skip = 10000

            # Skip 100000 Samples
            else:
                skip = 100000

            # Read
            for n in range(starting_byte,number_of_bytes,(sample_size*skip*complex_multiple)):
                file.seek(n)
                plot_data = plot_data + file.read(sample_size)
                if "Complex" in get_type:
                    plot_data = plot_data + file.read(sample_size)

    except:
        # Close the File
        file.close()

    # Close the File
    file.close()

    # Format the Data
    if get_type == "Complex Float 32":
        #plot_data_formatted = struct.unpack(num_samples/skip*'f', plot_data)
        plot_data_formatted = struct.unpack(int(len(plot_data)/4)*'f', plot_data)
    elif get_type == "Float/Float 32":
        plot_data_formatted = struct.unpack(int(len(plot_data)/4)*'f', plot_data)
    elif get_type == "Short/Int 16":
        plot_data_formatted = struct.unpack(int(len(plot_data)/2)*'h', plot_data)
    elif get_type == "Int/Int 32":
        plot_data_formatted = struct.unpack(int(len(plot_data)/4)*'i', plot_data)
    elif get_type == "Byte/Int 8":
        plot_data_formatted = struct.unpack(int(len(plot_data)/1)*'b', plot_data)
    elif get_type == "Complex Int 16":
        plot_data_formatted = struct.unpack(int(len(plot_data)/2)*'h', plot_data)
    elif get_type == "Complex Int 8":
        plot_data_formatted = struct.unpack(int(len(plot_data)/1)*'b', plot_data)
    elif get_type == "Complex Float 64":
        plot_data_formatted = struct.unpack(int(len(plot_data)/8)*'d', plot_data)
    elif get_type == "Complex Int 64":
        plot_data_formatted = struct.unpack(int(len(plot_data)/8)*'l', plot_data)
    elif get_type == "Unsigned Int 8":
        plot_data_formatted = struct.unpack(int(len(plot_data)/1)*'B', plot_data)
    elif get_type == "Unsigned Int 16":
        plot_data_formatted = struct.unpack(int(len(plot_data)/2)*'H', plot_data)
    elif get_type == "Unsigned Int 32":
        plot_data_formatted = struct.unpack(int(len(plot_data)/4)*'I', plot_data)
    elif get_type == "Complex Unsigned Int 64":
        plot_data_formatted = struct.unpack(int(len(plot_data)/8)*'Q', plot_data)
    elif get_type == "Complex Unsigned Int 16":
        plot_data_formatted = struct.unpack(int(len(plot_data)/2)*'H', plot_data)
    elif get_type == "Complex Unsigned Int 8":
        plot_data_formatted = struct.unpack(int(len(plot_data)/1)*'B', plot_data)

    # Plot
    dashboard.iq_matplotlib_widget.clearPlot()
    dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
    if "Complex" in get_type:
        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            # Plot
            dashboard.iq_matplotlib_widget.axes.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[::2],'b',linewidth=1,zorder=2)
            #dashboard.iq_matplotlib_widget.axes.hold(True)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()
            dashboard.iq_matplotlib_widget.axes.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[1::2],'r',linewidth=1,zorder=2)
            # dashboard.iq_matplotlib_widget.axes.hold(False)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()
    else:
        dashboard.iq_matplotlib_widget.axes.plot(range(1,len(plot_data_formatted)+1),plot_data_formatted,'b',linewidth=1,zorder=2)

    # Axes Label
    if skip == 1:
        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
    elif skip == 10:
        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples/10','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
    elif skip == 100:
        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples/100','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
    elif skip == 1000:
        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples/1000','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
    elif skip == 10000:
        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples/10000','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
    else:
        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples/100000','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

    dashboard.ui.pushButton_iq_cursor1.setChecked(False)
    _slotIQ_Cursor1Clicked(dashboard)
    #dashboard.iq_matplotlib_widget.draw()

    # Reset Range Cursor Memory
    dashboard.iq_plot_range_start = 0
    dashboard.iq_plot_range_end = 0


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlotMagnitudeClicked(dashboard: QtCore.QObject):
    """ 
    Plots magnitude of what is displayed in the plot window.
    """
    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Calculate AM
        AM = [math.sqrt(float(i)**2) for i in y_data]

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(AM,'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("Magnitude",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()

        I_squared = [float(i)**2 for i in I]
        Q_squared = [float(q)**2 for q in Q]

        # Calculate AM
        AM = [math.sqrt(I_squared[x] + Q_squared[x]) for x in range(len(I_squared))]

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(AM,'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("Magnitude",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Reset the Cursor and Draw
    dashboard.ui.pushButton_iq_cursor1.setChecked(False)
    _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()
    #dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlotIF_Clicked(dashboard: QtCore.QObject):
    """ 
    Plots the instantaneous frequency of what is displayed in the plot window.
    """
    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.angle(y_data),'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

        # Acquire Sample Rate and Frequency
        try:
            get_sample_rate = float(str(dashboard.ui.textEdit_iq_sample_rate.toPlainText()))
        except:
            get_sample_rate = ""
        try:
            get_frequency = float(str(dashboard.ui.textEdit_iq_frequency.toPlainText()))
        except:
            get_frequency = ""

        # Calculate IF
        if fissure.utils.isFloat(get_sample_rate):
            if fissure.utils.isFloat(get_frequency):
                instantaneous_frequency = np.diff(np.unwrap(np.angle(complex_data)))/(2.0*np.pi)*get_sample_rate + get_frequency
            else:
                instantaneous_frequency = np.diff(np.unwrap(np.angle(complex_data)))/(2.0*np.pi)*get_sample_rate
        else:
            instantaneous_frequency = np.diff(np.unwrap(np.angle(complex_data)))

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(instantaneous_frequency,'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("Instantaneous Frequency",'Samples','Frequency (Hz)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OverlapPlotClicked(dashboard: QtCore.QObject):
    """ 
    Plots the stored data for data1 and data2 on the same figure.
    """
    # Work with Temp. Values
    overlap_data1_plot = dashboard.overlap_data1
    overlap_data2_plot = dashboard.overlap_data2

    # Make Same Length
    if len(dashboard.overlap_data1) > len(dashboard.overlap_data2):
        sample_diff = len(dashboard.overlap_data1) - len(dashboard.overlap_data2)
        overlap_data2_plot = np.pad(dashboard.overlap_data2,(0,sample_diff),'constant')
    elif len(dashboard.overlap_data2) > len(dashboard.overlap_data1):
        sample_diff = len(dashboard.overlap_data2) - len(dashboard.overlap_data1)
        overlap_data1_plot = np.pad(dashboard.overlap_data1,(0,sample_diff),'constant')

    # Circular Shift - Data 1
    get_shift1 = dashboard.ui.spinBox_iq_overlap_offset1.value()
    overlap_data1_plot = np.roll(overlap_data1_plot, get_shift1)

    # Circular Shift - Data 2
    get_shift2 = dashboard.ui.spinBox_iq_overlap_offset2.value()
    overlap_data2_plot = np.roll(overlap_data2_plot, get_shift2)

    # Plot
    dashboard.iq_matplotlib_widget.clearPlot()
    dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

    # Ignore hold() Deprecation Warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        warnings.filterwarnings("ignore", module="matplotlib")

        # Plot
        dashboard.iq_matplotlib_widget.axes.plot(overlap_data1_plot,'b',linewidth=1,zorder=2)
        #dashboard.iq_matplotlib_widget.axes.hold(True)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()
        dashboard.iq_matplotlib_widget.axes.plot(overlap_data2_plot,'r',linewidth=1,zorder=2)
        #dashboard.iq_matplotlib_widget.axes.hold(False)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()
        dashboard.iq_matplotlib_widget.applyLabels("Data Overlap",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

        # Reset the Cursor and Draw
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_PlotSymbolCP_Clicked(dashboard: QtCore.QObject):
    """ 
    Plots highlighted cyclic prefixes for all symbols.
    """
    # Get Data
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    if number_of_bytes > 0 and ("Complex" in get_type):

        # Get the Number of Samples
        start_sample = 1
        num_samples = int(dashboard.ui.label2_iq_samples.text().split(" ")[1])

        # Get the Size of Each Sample in Bytes
        if get_type == "Complex Float 32":
            sample_size = 4
        elif get_type == "Complex Int 16":
            sample_size = 2
        elif get_type == "Complex Int 8":
            sample_size = 1
        elif get_type == "Complex Float 64":
            sample_size = 8
        elif get_type == "Complex Int 64":
            sample_size = 8
        num_samples = 2 * num_samples

        # Read the Data
        filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
        file = open(filepath,"rb")                          # Open the file
        #if get_type == "Complex Float 32":
        file.seek(2*(start_sample-1) * sample_size)     # Point to the starting sample
        #else:
        #    file.seek((start_sample-1) * sample_size)       # Point to the starting sample
        plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes
        file.close()

        # Format the Data
        if get_type == "Complex Float 32":
            plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
        elif get_type == "Complex Int 16":
            plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
        elif get_type == "Complex Int 8":
            plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
        elif get_type == "Complex Float 64":
            plot_data_formatted = struct.unpack(num_samples*'d', plot_data)
        elif get_type == "Complex Int 64":
            plot_data_formatted = struct.unpack(num_samples*'l', plot_data)

        # Resample
        get_sample_rate = float(dashboard.ui.textEdit_iq_ofdm_sample_rate.toPlainText())
        get_resample_rate = float(dashboard.ui.textEdit_iq_ofdm_resample_rate.toPlainText())
        num_resampled_samples = int(math.floor((get_resample_rate/get_sample_rate)*len(plot_data_formatted)/2))
        i_resampled = signal2.resample(plot_data_formatted[::2],num_resampled_samples)
        q_resampled = signal2.resample(plot_data_formatted[1::2],num_resampled_samples)

        # Get Message
        get_trigger_level = float(dashboard.ui.textEdit_iq_ofdm_trigger_level.toPlainText())
        I_squared = [float(i)**2 for i in i_resampled]
        Q_squared = [float(q)**2 for q in q_resampled]
        AM = [math.sqrt(I_squared[x] + Q_squared[x]) for x in range(len(I_squared))]
        first_point = 1
        for idx in range(0, len(AM)) :
            if AM[idx] > get_trigger_level:
                first_point = idx
                break

        # Get Symbol Size
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        get_cp_length = int(dashboard.ui.textEdit_iq_ofdm_cp_length.toPlainText())
        interval = (get_fft_size+get_cp_length)

        # Detect Number of Symbols
        num_sym = 0
        for n in range(first_point,len(AM)-interval,interval):
            if all(x < get_trigger_level for x in AM[n+int(math.floor(interval/10)):n+interval]):
                break

            # No End Found
            num_sym = num_sym + 1

        # Plot
        symbols_remaining = num_sym
        subs_per_page = 10
        for x in range(0,int(num_sym/subs_per_page) + 1):
            if symbols_remaining/subs_per_page > 0:
                fig, axs = plt.subplots(subs_per_page)
            else:
                fig, axs = plt.subplots(symbols_remaining)
            fig.suptitle('OFDM Cyclic Prefix: ' + str(x))
            for n in range(0,subs_per_page):
                axs[n].plot(AM[first_point+n*interval:first_point+(n+1)*interval],'b',linewidth=1)
                axs[n].fill_between(range(0,get_cp_length),AM[first_point+n*interval:first_point+n*interval+get_cp_length])
                axs[n].fill_between(range(interval-get_cp_length,interval),AM[first_point+n*interval+get_fft_size:first_point+(n+1)*interval])

                # Reached End
                symbols_remaining = symbols_remaining - 1
                if symbols_remaining == 0:
                    break
            plt.show()

    # Create a Dialog Error Window
    else:
        msgBox = MyMessageBox(my_text = "File must be loaded and have complex data type.")
        msgBox.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_MagnitudeClicked(dashboard: QtCore.QObject):
    """ 
    Plots the magnitude and phase for a symbol in a message without subcarrier removal.
    """
    # Get Data
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    if number_of_bytes > 0 and ("Complex" in get_type):

        # Get the Number of Samples
        start_sample = 1
        num_samples = int(dashboard.ui.label2_iq_samples.text().split(" ")[1])

        # Get the Size of Each Sample in Bytes
        if get_type == "Complex Float 32":
            sample_size = 4
        elif get_type == "Complex Int 16":
            sample_size = 2
        elif get_type == "Complex Int 8":
            sample_size = 1
        elif get_type == "Complex Float 64":
            sample_size = 8
        elif get_type == "Complex Int 64":
            sample_size = 8
        num_samples = 2 * num_samples

        # Read the Data
        filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
        file = open(filepath,"rb")                          # Open the file
        #if get_type == "Complex Float 32":
        file.seek(2*(start_sample-1) * sample_size)     # Point to the starting sample
        #else:
        #    file.seek((start_sample-1) * sample_size)       # Point to the starting sample
        plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes
        file.close()

        # Format the Data
        if get_type == "Complex Float 32":
            plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
        elif get_type == "Complex Int 16":
            plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
        elif get_type == "Complex Int 8":
            plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
        elif get_type == "Complex Float 64":
            plot_data_formatted = struct.unpack(num_samples*'d', plot_data)
        elif get_type == "Complex Int 64":
            plot_data_formatted = struct.unpack(num_samples*'l', plot_data)

        # Resample
        get_sample_rate = float(dashboard.ui.textEdit_iq_ofdm_sample_rate.toPlainText())
        get_resample_rate = float(dashboard.ui.textEdit_iq_ofdm_resample_rate.toPlainText())
        num_resampled_samples = int(math.floor((get_resample_rate/get_sample_rate)*len(plot_data_formatted)/2))
        i_resampled = signal2.resample(plot_data_formatted[::2],num_resampled_samples)
        q_resampled = signal2.resample(plot_data_formatted[1::2],num_resampled_samples)

        # Get Message
        get_trigger_level = float(dashboard.ui.textEdit_iq_ofdm_trigger_level.toPlainText())
        I_squared = [float(i)**2 for i in i_resampled]
        Q_squared = [float(q)**2 for q in q_resampled]
        AM = [math.sqrt(I_squared[x] + Q_squared[x]) for x in range(len(I_squared))]
        first_point = 1
        for idx in range(0, len(AM)) :
            if AM[idx] > get_trigger_level:
                first_point = idx
                break

        # Get Symbol Size
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        get_cp_length = int(dashboard.ui.textEdit_iq_ofdm_cp_length.toPlainText())
        interval = (get_fft_size+get_cp_length)

        # Detect Number of Symbols
        num_sym = 0
        for n in range(first_point,len(AM)-interval,interval):
            if all(x < get_trigger_level for x in AM[n+int(math.floor(interval/10)):n+interval]):
                break

            # No End Found
            num_sym = num_sym + 1

        # Symbol Out of Range
        get_symbol = int(dashboard.ui.spinBox_iq_ofdm_symbol.value())
        if get_symbol > num_sym:
            msgBox = MyMessageBox(my_text = "Symbol exceeds the number of symbols in the message.")
            msgBox.exec_()
            return

        # Remove Cyclic Prefix
        i_symbol = np.array(i_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])
        q_symbol = np.array(q_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])

        # Combine the Data
        time_data = i_symbol + 1j*q_symbol

        # Do FFT
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        fft_data = np.fft.fftshift(np.fft.fft(time_data,get_fft_size,norm='ortho'))
        dashboard.fft_data = fft_data

        # Phase
        get_adj = int(str(dashboard.ui.textEdit_iq_ofdm_phase_adjustment1.toPlainText()))
        fft_data_adj = []
        for x in range(0,len(fft_data)):
            fft_data_adj.append(np.exp(-1j*2*math.pi*(float(get_adj)/100000*x))*fft_data[x])
        #phase_data = np.angle(fft_data_adj)

        # Magnitude
        mag_data = abs(np.array(fft_data_adj))/max(abs(np.array(fft_data_adj)))

        # Enable Buttons
        dashboard.ui.pushButton_iq_ofdm_cycle_adjustment.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_start.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_end.setEnabled(True)

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
        dashboard.iq_matplotlib_widget.axes.plot(mag_data,'b',linewidth=1,zorder=2)
        dashboard.iq_matplotlib_widget.applyLabels("OFDM Subcarriers",'Subcarriers','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()

    # Create a Dialog Error Window
    else:
        msgBox = MyMessageBox(my_text = "File must be loaded and have complex data type.")
        msgBox.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_CycleAdjustmentClicked(dashboard: QtCore.QObject):
    """ 
    Cycles through phase adjustment values and plots updated phase.
    """
    # Do Phase Adjustments
    if not isinstance(dashboard.fft_data,type(None)):

        # Get FFT Data
        fft_data = dashboard.fft_data

        # Make Plot
        plt.ion()
        fig = plt.figure()
        ax = fig.add_subplot(111)
        line1, = ax.plot(np.angle(fft_data),'b',linewidth=1)
        plt.show()

        # Get FFT Data
        fft_data = dashboard.fft_data

        # Update Adjustment
        get_start = int(str(dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_start.toPlainText()))
        get_end = int(str(dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_end.toPlainText()))
        for adj in range(get_start,get_end,2):
            dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle.setPlainText(str(adj))
            phase_data = []
            for x in range(0,len(fft_data)):
                phase_data.append(np.exp(-1j*2*math.pi*(float(adj)/100000*x))*fft_data[x])
            phase_data = np.angle(phase_data)

            # Plot
            #ax.clear()
            #ax.plot(phase_data,'b',linewidth=1)
            line1.set_ydata(phase_data)
            fig.canvas.draw()
            fig.canvas.flush_events()
            fig.show()
            time.sleep(.1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_PhaseClicked(dashboard: QtCore.QObject):
    """ 
    Plots the phase for all the subcarriers.
    """
    # Get Data
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    if number_of_bytes > 0 and ("Complex" in get_type):

        # Get the Number of Samples
        start_sample = 1
        num_samples = int(dashboard.ui.label2_iq_samples.text().split(" ")[1])

        # Get the Size of Each Sample in Bytes
        if get_type == "Complex Float 32":
            sample_size = 4
        elif get_type == "Complex Int 16":
            sample_size = 2
        elif get_type == "Complex Int 8":
            sample_size = 1
        elif get_type == "Complex Float 64":
            sample_size = 8
        elif get_type == "Complex Int 64":
            sample_size = 8
        num_samples = 2 * num_samples

        # Read the Data
        filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
        file = open(filepath,"rb")                          # Open the file
        #if get_type == "Complex Float 32":
        file.seek(2*(start_sample-1) * sample_size)     # Point to the starting sample
        #else:
        #    file.seek((start_sample-1) * sample_size)       # Point to the starting sample
        plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes
        file.close()

        # Format the Data
        if get_type == "Complex Float 32":
            plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
        elif get_type == "Complex Int 16":
            plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
        elif get_type == "Complex Int 8":
            plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
        elif get_type == "Complex Float 64":
            plot_data_formatted = struct.unpack(num_samples*'d', plot_data)
        elif get_type == "Complex Int 64":
            plot_data_formatted = struct.unpack(num_samples*'l', plot_data)

        # Resample
        get_sample_rate = float(dashboard.ui.textEdit_iq_ofdm_sample_rate.toPlainText())
        get_resample_rate = float(dashboard.ui.textEdit_iq_ofdm_resample_rate.toPlainText())
        num_resampled_samples = int(math.floor((get_resample_rate/get_sample_rate)*len(plot_data_formatted)/2))
        i_resampled = signal2.resample(plot_data_formatted[::2],num_resampled_samples)
        q_resampled = signal2.resample(plot_data_formatted[1::2],num_resampled_samples)

        # Get Message
        get_trigger_level = float(dashboard.ui.textEdit_iq_ofdm_trigger_level.toPlainText())
        I_squared = [float(i)**2 for i in i_resampled]
        Q_squared = [float(q)**2 for q in q_resampled]
        AM = [math.sqrt(I_squared[x] + Q_squared[x]) for x in range(len(I_squared))]
        first_point = 1
        for idx in range(0, len(AM)) :
            if AM[idx] > get_trigger_level:
                first_point = idx
                break

        # Get Symbol Size
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        get_cp_length = int(dashboard.ui.textEdit_iq_ofdm_cp_length.toPlainText())
        interval = (get_fft_size+get_cp_length)

        # Detect Number of Symbols
        num_sym = 0
        for n in range(first_point,len(AM)-interval,interval):
            if all(x < get_trigger_level for x in AM[n+int(math.floor(interval/10)):n+interval]):
                break

            # No End Found
            num_sym = num_sym + 1

        # Symbol Out of Range
        get_symbol = int(dashboard.ui.spinBox_iq_ofdm_symbol.value())
        if get_symbol > num_sym:
            msgBox = MyMessageBox(my_text = "Symbol exceeds the number of symbols in the message.")
            msgBox.exec_()
            return

        # Remove Cyclic Prefix
        i_symbol = np.array(i_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])
        q_symbol = np.array(q_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])

        # Combine the Data
        time_data = i_symbol + 1j*q_symbol

        # Do FFT
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        fft_data = np.fft.fftshift(np.fft.fft(time_data,get_fft_size,norm='ortho'))
        dashboard.fft_data = fft_data

        ## Magnitude
        #mag_data = abs(fft_data)/max(abs(fft_data))

        # Phase
        get_adj = int(str(dashboard.ui.textEdit_iq_ofdm_phase_adjustment1.toPlainText()))
        phase_data = []
        for x in range(0,len(fft_data)):
            phase_data.append(np.exp(-1j*2*math.pi*(float(get_adj)/100000*x))*fft_data[x])
        phase_data = np.angle(phase_data)

        # Enable Buttons
        dashboard.ui.pushButton_iq_ofdm_cycle_adjustment.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_start.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_end.setEnabled(True)

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
        dashboard.iq_matplotlib_widget.axes.plot(phase_data,'b',linewidth=1,zorder=2)
        dashboard.iq_matplotlib_widget.applyLabels("OFDM Subcarriers",'Subcarriers','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

        # Reset the Cursor and Draw
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()

    # Create a Dialog Error Window
    else:
        msgBox = MyMessageBox(my_text = "File must be loaded and have complex data type.")
        msgBox.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_PolarClicked(dashboard: QtCore.QObject):
    """ 
    Polar plot (magnitude and phase) for all of the subcarriers.
    """
    # Get Data
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    if number_of_bytes > 0 and ("Complex" in get_type):

        # Get the Number of Samples
        start_sample = 1
        num_samples = int(dashboard.ui.label2_iq_samples.text().split(" ")[1])

        # Get the Size of Each Sample in Bytes
        if get_type == "Complex Float 32":
            sample_size = 4
        elif get_type == "Complex Int 16":
            sample_size = 2
        elif get_type == "Complex Int 8":
            sample_size = 1
        elif get_type == "Complex Float 64":
            sample_size = 8
        elif get_type == "Complex Int 64":
            sample_size = 8
        num_samples = 2 * num_samples

        # Read the Data
        filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
        file = open(filepath,"rb")                          # Open the file
        #if get_type == "Complex Float 32":
        file.seek(2*(start_sample-1) * sample_size)     # Point to the starting sample
        #else:
        #    file.seek((start_sample-1) * sample_size)       # Point to the starting sample
        plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes
        file.close()

        # Format the Data
        if get_type == "Complex Float 32":
            plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
        elif get_type == "Complex Int 16":
            plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
        elif get_type == "Complex Int 8":
            plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
        elif get_type == "Complex Float 64":
            plot_data_formatted = struct.unpack(num_samples*'d', plot_data)
        elif get_type == "Complex Int 64":
            plot_data_formatted = struct.unpack(num_samples*'l', plot_data)

        # Resample
        get_sample_rate = float(dashboard.ui.textEdit_iq_ofdm_sample_rate.toPlainText())
        get_resample_rate = float(dashboard.ui.textEdit_iq_ofdm_resample_rate.toPlainText())
        num_resampled_samples = int(math.floor((get_resample_rate/get_sample_rate)*len(plot_data_formatted)/2))
        i_resampled = signal2.resample(plot_data_formatted[::2],num_resampled_samples)
        q_resampled = signal2.resample(plot_data_formatted[1::2],num_resampled_samples)

        # Get Message
        get_trigger_level = float(dashboard.ui.textEdit_iq_ofdm_trigger_level.toPlainText())
        I_squared = [float(i)**2 for i in i_resampled]
        Q_squared = [float(q)**2 for q in q_resampled]
        AM = [math.sqrt(I_squared[x] + Q_squared[x]) for x in range(len(I_squared))]
        first_point = 1
        for idx in range(0, len(AM)) :
            if AM[idx] > get_trigger_level:
                first_point = idx
                break

        # Get Symbol Size
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        get_cp_length = int(dashboard.ui.textEdit_iq_ofdm_cp_length.toPlainText())
        interval = (get_fft_size+get_cp_length)

        # Detect Number of Symbols
        num_sym = 0
        for n in range(first_point,len(AM)-interval,interval):
            if all(x < get_trigger_level for x in AM[n+int(math.floor(interval/10)):n+interval]):
                break

            # No End Found
            num_sym = num_sym + 1

        # Symbol Out of Range
        get_symbol = int(dashboard.ui.spinBox_iq_ofdm_symbol.value())
        if get_symbol > num_sym:
            msgBox = MyMessageBox(my_text = "Symbol exceeds the number of symbols in the message.")
            msgBox.exec_()
            return

        # Remove Cyclic Prefix
        i_symbol = np.array(i_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])
        q_symbol = np.array(q_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])

        # Combine the Data
        time_data = i_symbol + 1j*q_symbol

        # Do FFT
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        fft_data = np.fft.fftshift(np.fft.fft(time_data,get_fft_size,norm='ortho'))
        dashboard.fft_data = fft_data

        # Phase
        get_adj = int(str(dashboard.ui.textEdit_iq_ofdm_phase_adjustment1.toPlainText()))
        fft_adj = []
        for x in range(0,len(fft_data)):
            fft_adj.append(np.exp(-1j*2*math.pi*(float(get_adj)/100000*x))*fft_data[x])
        phase_data = np.angle(fft_adj)

        # Magnitude
        mag_data = abs(np.array(fft_adj))/max(abs(np.array(fft_adj)))

        # Enable Buttons
        dashboard.ui.pushButton_iq_ofdm_cycle_adjustment.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_start.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_end.setEnabled(True)

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=True,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
        dashboard.iq_matplotlib_widget.axes.plot(phase_data,mag_data,'bo',markersize=4)
        dashboard.iq_matplotlib_widget.applyLabels("OFDM Subcarriers",'Subcarriers','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

        # Reset the Cursor and Draw
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()

    # Create a Dialog Error Window
    else:
        msgBox = MyMessageBox(my_text = "File must be loaded and have complex data type.")
        msgBox.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_Magnitude2Clicked(dashboard: QtCore.QObject):
    """ 
    Plots the magnitude of the data subcarriers.
    """
    # Get Data
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    if number_of_bytes > 0 and ("Complex" in get_type):

        # Get the Number of Samples
        start_sample = 1
        num_samples = int(dashboard.ui.label2_iq_samples.text().split(" ")[1])

        # Get the Size of Each Sample in Bytes
        if get_type == "Complex Float 32":
            sample_size = 4
        elif get_type == "Complex Int 16":
            sample_size = 2
        elif get_type == "Complex Int 8":
            sample_size = 1
        elif get_type == "Complex Float 64":
            sample_size = 8
        elif get_type == "Complex Int 64":
            sample_size = 8
        num_samples = 2 * num_samples

        # Read the Data
        filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
        file = open(filepath,"rb")                          # Open the file
        #if get_type == "Complex Float 32":
        file.seek(2*(start_sample-1) * sample_size)     # Point to the starting sample
        #else:
        #    file.seek((start_sample-1) * sample_size)       # Point to the starting sample
        plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes
        file.close()

        # Format the Data
        if get_type == "Complex Float 32":
            plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
        elif get_type == "Complex Int 16":
            plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
        elif get_type == "Complex Int 8":
            plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
        elif get_type == "Complex Float 64":
            plot_data_formatted = struct.unpack(num_samples*'d', plot_data)
        elif get_type == "Complex Int 64":
            plot_data_formatted = struct.unpack(num_samples*'l', plot_data)

        # Resample
        get_sample_rate = float(dashboard.ui.textEdit_iq_ofdm_sample_rate.toPlainText())
        get_resample_rate = float(dashboard.ui.textEdit_iq_ofdm_resample_rate.toPlainText())
        num_resampled_samples = int(math.floor((get_resample_rate/get_sample_rate)*len(plot_data_formatted)/2))
        i_resampled = signal2.resample(plot_data_formatted[::2],num_resampled_samples)
        q_resampled = signal2.resample(plot_data_formatted[1::2],num_resampled_samples)

        # Get Message
        get_trigger_level = float(dashboard.ui.textEdit_iq_ofdm_trigger_level.toPlainText())
        I_squared = [float(i)**2 for i in i_resampled]
        Q_squared = [float(q)**2 for q in q_resampled]
        AM = [math.sqrt(I_squared[x] + Q_squared[x]) for x in range(len(I_squared))]
        first_point = 1
        for idx in range(0, len(AM)) :
            if AM[idx] > get_trigger_level:
                first_point = idx
                break

        # Get Symbol Size
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        get_cp_length = int(dashboard.ui.textEdit_iq_ofdm_cp_length.toPlainText())
        interval = (get_fft_size+get_cp_length)

        # Detect Number of Symbols
        num_sym = 0
        for n in range(first_point,len(AM)-interval,interval):
            if all(x < get_trigger_level for x in AM[n+int(math.floor(interval/10)):n+interval]):
                break

            # No End Found
            num_sym = num_sym + 1

        # Symbol Out of Range
        get_symbol = int(dashboard.ui.spinBox_iq_ofdm_symbol.value())
        if get_symbol > num_sym:
            msgBox = MyMessageBox(my_text = "Symbol exceeds the number of symbols in the message.")
            msgBox.exec_()
            return

        # Remove Cyclic Prefix
        i_symbol = np.array(i_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])
        q_symbol = np.array(q_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])

        # Combine the Data
        time_data = i_symbol + 1j*q_symbol

        # Do FFT
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        fft_data_pre = np.fft.fftshift(np.fft.fft(time_data,get_fft_size,norm='ortho'))

        # Keep Data Subcarriers
        get_data_subs = [] #range(75,511,3)  # [75:3:511,516:3:951];
        for row in range(0,dashboard.ui.listWidget_iq_ofdm_subcarriers.count()):
            get_data_subs.append(int(str(dashboard.ui.listWidget_iq_ofdm_subcarriers.item(row).text())))

        fft_data = np.array([fft_data_pre[i] for i in get_data_subs])
        dashboard.fft_data = fft_data

        # Phase
        get_adj = int(str(dashboard.ui.textEdit_iq_ofdm_phase_adjustment2.toPlainText()))
        fft_data_adj = []
        for x in range(0,len(fft_data)):
            fft_data_adj.append(np.exp(-1j*2*math.pi*(float(get_adj)/100000*x))*fft_data[x])
        #phase_data = np.angle(fft_data_adj)

        # Magnitude
        mag_data = abs(np.array(fft_data_adj))/max(abs(np.array(fft_data_adj)))

        # Enable Buttons
        dashboard.ui.pushButton_iq_ofdm_cycle_adjustment2.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_start2.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_end2.setEnabled(True)

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
        dashboard.iq_matplotlib_widget.axes.plot(mag_data,'b',linewidth=1,zorder=2)
        dashboard.iq_matplotlib_widget.applyLabels("OFDM Subcarriers",'Subcarriers','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

        # Reset the Cursor and Draw
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()

    # Create a Dialog Error Window
    else:
        msgBox = MyMessageBox(my_text = "File must be loaded and have complex data type.")
        msgBox.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_Phase2Clicked(dashboard: QtCore.QObject):
    """ 
    Plots the phase of the data subcarriers.
    """
    # Get Data
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    if number_of_bytes > 0 and ("Complex" in get_type):

        # Get the Number of Samples
        start_sample = 1
        num_samples = int(dashboard.ui.label2_iq_samples.text().split(" ")[1])

        # Get the Size of Each Sample in Bytes
        if get_type == "Complex Float 32":
            sample_size = 4
        elif get_type == "Complex Int 16":
            sample_size = 2
        elif get_type == "Complex Int 8":
            sample_size = 1
        elif get_type == "Complex Float 64":
            sample_size = 8
        elif get_type == "Complex Int 64":
            sample_size = 8
        num_samples = 2 * num_samples

        # Read the Data
        filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
        file = open(filepath,"rb")                          # Open the file
        #if get_type == "Complex Float 32":
        file.seek(2*(start_sample-1) * sample_size)     # Point to the starting sample
        #else:
        #    file.seek((start_sample-1) * sample_size)       # Point to the starting sample
        plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes
        file.close()

        # Format the Data
        if get_type == "Complex Float 32":
            plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
        elif get_type == "Complex Int 16":
            plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
        elif get_type == "Complex Int 8":
            plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
        elif get_type == "Complex Float 64":
            plot_data_formatted = struct.unpack(num_samples*'d', plot_data)
        elif get_type == "Complex Int 64":
            plot_data_formatted = struct.unpack(num_samples*'l', plot_data)

        # Resample
        get_sample_rate = float(dashboard.ui.textEdit_iq_ofdm_sample_rate.toPlainText())
        get_resample_rate = float(dashboard.ui.textEdit_iq_ofdm_resample_rate.toPlainText())
        num_resampled_samples = int(math.floor((get_resample_rate/get_sample_rate)*len(plot_data_formatted)/2))
        i_resampled = signal2.resample(plot_data_formatted[::2],num_resampled_samples)
        q_resampled = signal2.resample(plot_data_formatted[1::2],num_resampled_samples)

        # Get Message
        get_trigger_level = float(dashboard.ui.textEdit_iq_ofdm_trigger_level.toPlainText())
        I_squared = [float(i)**2 for i in i_resampled]
        Q_squared = [float(q)**2 for q in q_resampled]
        AM = [math.sqrt(I_squared[x] + Q_squared[x]) for x in range(len(I_squared))]
        first_point = 1
        for idx in range(0, len(AM)) :
            if AM[idx] > get_trigger_level:
                first_point = idx
                break

        # Get Symbol Size
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        get_cp_length = int(dashboard.ui.textEdit_iq_ofdm_cp_length.toPlainText())
        interval = (get_fft_size+get_cp_length)

        # Detect Number of Symbols
        num_sym = 0
        for n in range(first_point,len(AM)-interval,interval):
            if all(x < get_trigger_level for x in AM[n+int(math.floor(interval/10)):n+interval]):
                break

            # No End Found
            num_sym = num_sym + 1

        # Symbol Out of Range
        get_symbol = int(dashboard.ui.spinBox_iq_ofdm_symbol.value())
        if get_symbol > num_sym:
            msgBox = MyMessageBox(my_text = "Symbol exceeds the number of symbols in the message.")
            msgBox.exec_()
            return

        # Remove Cyclic Prefix
        i_symbol = np.array(i_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])
        q_symbol = np.array(q_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])

        # Combine the Data
        time_data = i_symbol + 1j*q_symbol

        # Do FFT
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        fft_data_pre = np.fft.fftshift(np.fft.fft(time_data,get_fft_size,norm='ortho'))

        # Keep Data Subcarriers
        get_data_subs = [] #range(75,511,3)  # [75:3:511,516:3:951];
        for row in range(0,dashboard.ui.listWidget_iq_ofdm_subcarriers.count()):
            get_data_subs.append(int(str(dashboard.ui.listWidget_iq_ofdm_subcarriers.item(row).text())))

        fft_data = np.array([fft_data_pre[i] for i in get_data_subs])
        dashboard.fft_data = fft_data

        # Phase
        get_adj = int(str(dashboard.ui.textEdit_iq_ofdm_phase_adjustment2.toPlainText()))
        fft_data_adj = []
        for x in range(0,len(fft_data)):
            fft_data_adj.append(np.exp(-1j*2*math.pi*(float(get_adj)/100000*x))*fft_data[x])
        phase_data = np.angle(fft_data_adj)

        ## Magnitude
        #mag_data = abs(np.array(fft_data_adj))/max(abs(np.array(fft_data_adj)))

        # Enable Buttons
        dashboard.ui.pushButton_iq_ofdm_cycle_adjustment2.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_start2.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_end2.setEnabled(True)

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
        dashboard.iq_matplotlib_widget.axes.plot(phase_data,'b',linewidth=1,zorder=2)
        dashboard.iq_matplotlib_widget.applyLabels("OFDM Subcarriers",'Subcarriers','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

        # Reset the Cursor and Draw
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()

    # Create a Dialog Error Window
    else:
        msgBox = MyMessageBox(my_text = "File must be loaded and have complex data type.")
        msgBox.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_Polar2Clicked(dashboard: QtCore.QObject):
    """ 
    Polar plots the data subcarriers.
    """
    # Get Data
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    if number_of_bytes > 0 and ("Complex" in get_type):

        # Get the Number of Samples
        start_sample = 1
        num_samples = int(dashboard.ui.label2_iq_samples.text().split(" ")[1])

        # Get the Size of Each Sample in Bytes
        if get_type == "Complex Float 32":
            sample_size = 4
        elif get_type == "Complex Int 16":
            sample_size = 2
        elif get_type == "Complex Int 8":
            sample_size = 1
        elif get_type == "Complex Float 64":
            sample_size = 8
        elif get_type == "Complex Int 64":
            sample_size = 8
        num_samples = 2 * num_samples

        # Read the Data
        filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
        file = open(filepath,"rb")                          # Open the file
        #if get_type == "Complex Float 32":
        file.seek(2*(start_sample-1) * sample_size)     # Point to the starting sample
        #else:
        #    file.seek((start_sample-1) * sample_size)       # Point to the starting sample
        plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes
        file.close()

        # Format the Data
        if get_type == "Complex Float 32":
            plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
        elif get_type == "Complex Int 16":
            plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
        elif get_type == "Complex Int 8":
            plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
        elif get_type == "Complex Float 64":
            plot_data_formatted = struct.unpack(num_samples*'d', plot_data)
        elif get_type == "Complex Int 64":
            plot_data_formatted = struct.unpack(num_samples*'l', plot_data)

        # Resample
        get_sample_rate = float(dashboard.ui.textEdit_iq_ofdm_sample_rate.toPlainText())
        get_resample_rate = float(dashboard.ui.textEdit_iq_ofdm_resample_rate.toPlainText())
        num_resampled_samples = int(math.floor((get_resample_rate/get_sample_rate)*len(plot_data_formatted)/2))
        i_resampled = signal2.resample(plot_data_formatted[::2],num_resampled_samples)
        q_resampled = signal2.resample(plot_data_formatted[1::2],num_resampled_samples)

        # Get Message
        get_trigger_level = float(dashboard.ui.textEdit_iq_ofdm_trigger_level.toPlainText())
        I_squared = [float(i)**2 for i in i_resampled]
        Q_squared = [float(q)**2 for q in q_resampled]
        AM = [math.sqrt(I_squared[x] + Q_squared[x]) for x in range(len(I_squared))]
        first_point = 1
        for idx in range(0, len(AM)) :
            if AM[idx] > get_trigger_level:
                first_point = idx
                break

        # Get Symbol Size
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        get_cp_length = int(dashboard.ui.textEdit_iq_ofdm_cp_length.toPlainText())
        interval = (get_fft_size+get_cp_length)

        # Detect Number of Symbols
        num_sym = 0
        for n in range(first_point,len(AM)-interval,interval):
            if all(x < get_trigger_level for x in AM[n+int(math.floor(interval/10)):n+interval]):
                break

            # No End Found
            num_sym = num_sym + 1

        # Symbol Out of Range
        get_symbol = int(dashboard.ui.spinBox_iq_ofdm_symbol.value())
        if get_symbol > num_sym:
            msgBox = MyMessageBox(my_text = "Symbol exceeds the number of symbols in the message.")
            msgBox.exec_()
            return

        # Remove Cyclic Prefix
        i_symbol = np.array(i_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])
        q_symbol = np.array(q_resampled[first_point+(get_symbol-1)*interval+get_cp_length:first_point+(get_symbol)*interval])

        # Combine the Data
        time_data = i_symbol + 1j*q_symbol

        # Do FFT
        get_fft_size = int(dashboard.ui.textEdit_iq_ofdm_fft_size.toPlainText())
        fft_data_pre = np.fft.fftshift(np.fft.fft(time_data,get_fft_size,norm='ortho'))

        # Keep Data Subcarriers
        get_data_subs = [] #range(75,511,3)  # [75:3:511,516:3:951];
        for row in range(0,dashboard.ui.listWidget_iq_ofdm_subcarriers.count()):
            get_data_subs.append(int(str(dashboard.ui.listWidget_iq_ofdm_subcarriers.item(row).text())))

        fft_data = np.array([fft_data_pre[i] for i in get_data_subs])
        dashboard.fft_data = fft_data

        # Phase
        get_adj = int(str(dashboard.ui.textEdit_iq_ofdm_phase_adjustment2.toPlainText()))
        fft_data_adj = []
        for x in range(0,len(fft_data)):
            fft_data_adj.append(np.exp(-1j*2*math.pi*(float(get_adj)/100000*x))*fft_data[x])
        phase_data = np.angle(fft_data_adj)

        # Magnitude
        mag_data = abs(np.array(fft_data_adj))/max(abs(np.array(fft_data_adj)))

        # Enable Buttons
        dashboard.ui.pushButton_iq_ofdm_cycle_adjustment2.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_start2.setEnabled(True)
        dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_end2.setEnabled(True)

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=True,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
        dashboard.iq_matplotlib_widget.axes.plot(phase_data,mag_data,'bo',markersize=4)
        dashboard.iq_matplotlib_widget.applyLabels("OFDM Subcarriers",'Subcarriers','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

        # Reset the Cursor and Draw
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()

    # Create a Dialog Error Window
    else:
        msgBox = MyMessageBox(my_text = "File must be loaded and have complex data type.")
        msgBox.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OFDM_CycleAdjustment2Clicked(dashboard: QtCore.QObject):
    """ 
    Cycles through phase adjustment values and plots updated phase for data subcarriers.
    """
    # Do Phase Adjustments
    if not isinstance(dashboard.fft_data,type(None)):

        # Get FFT Data
        fft_data = dashboard.fft_data

        # Make Plot
        plt.ion()
        fig = plt.figure()
        ax = fig.add_subplot(111)
        line1, = ax.plot(np.angle(fft_data),'b',linewidth=1)
        plt.show()

        # Get FFT Data
        fft_data = dashboard.fft_data

        # Update Adjustment
        get_start = int(str(dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_start2.toPlainText()))
        get_end = int(str(dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle_end2.toPlainText()))
        for adj in range(get_start,get_end,2):
            dashboard.ui.textEdit_iq_ofdm_phase_adjustment_cycle2.setPlainText(str(adj))
            phase_data = []
            for x in range(0,len(fft_data)):
                phase_data.append(np.exp(-1j*2*math.pi*(float(adj)/100000*x))*fft_data[x])
            phase_data = np.angle(phase_data)

            # Plot
            #ax.clear()
            #ax.plot(phase_data,'b',linewidth=1)
            line1.set_ydata(phase_data)
            fig.canvas.draw()
            fig.canvas.flush_events()
            fig.show()
            time.sleep(.1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_SpectrogramClicked(dashboard: QtCore.QObject):
    """ 
    Plots a spectrogram of the data in the plot window.
    """
    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            NFFT = 2048
            dashboard.iq_matplotlib_widget.axes.specgram(y_data, NFFT=NFFT, Fs=1, noverlap=900,zorder=2, cmap='viridis')

        dashboard.iq_matplotlib_widget.applyLabels("Spectrogram",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            NFFT = 2048
            dashboard.iq_matplotlib_widget.axes.specgram(complex_data, NFFT=NFFT, Fs=1, noverlap=900, zorder=2, cmap='viridis')

        dashboard.iq_matplotlib_widget.applyLabels("Spectrogram",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_FFT_Clicked(dashboard: QtCore.QObject):
    """ 
    Plots an FFT of what is displayed in the plot window.
    """
    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Do FFT
        try:
            get_sample_rate = float(str(dashboard.ui.textEdit_iq_sample_rate.toPlainText()))*1000000
        except:
            get_sample_rate = 1000000.0
        get_fft_size = int(dashboard.backend.settings['fft_size'])
        fft_data = np.log10(np.abs(np.fft.fftshift(np.fft.fft(y_data,get_fft_size,norm='ortho'))))
        #fft_data = fft_data/max(fft_data)
        freq = np.fft.fftshift(np.fft.fftfreq(len(fft_data),1/get_sample_rate))
        #freq = np.fft.fftfreq(len(fft_data),1/get_sample_rate)

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(freq,fft_data,'b',linewidth=1,zorder=2)

        dashboard.iq_matplotlib_widget.applyLabels("4096-point FFT",'Frequency (Hz)','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

        # Do FFT
        try:
            get_sample_rate = float(str(dashboard.ui.textEdit_iq_sample_rate.toPlainText()))*1000000
        except:
            get_sample_rate = 1000000.0
        get_fft_size = int(dashboard.backend.settings['fft_size'])
        fft_data = np.log10(np.abs(np.fft.fftshift(np.fft.fft(complex_data,get_fft_size,norm='ortho'))))
        #fft_data = fft_data/max(fft_data)
        freq = np.fft.fftshift(np.fft.fftfreq(len(fft_data),1/get_sample_rate))
        #freq = np.fft.fftfreq(len(fft_data),1/get_sample_rate)

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(freq,fft_data,'b',linewidth=1,zorder=2)

        dashboard.iq_matplotlib_widget.applyLabels("FFT",'Frequency (Hz)','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_CustomClicked(dashboard: QtCore.QObject):
    """ 
    Whatever you want. Experiment and see if it is worth it.
    """
    # Get the Filepath
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    if number_of_bytes > 0:

        # Get the Number of Samples
        try:
            start_sample = int(dashboard.ui.textEdit_iq_start.toPlainText())
            end_sample = int(dashboard.ui.textEdit_iq_end.toPlainText())
            num_samples = end_sample - start_sample + 1
        except:
            return

        # Do Nothing if Bad Range
        if num_samples < 0:
            return

        # Get the Size of Each Sample in Bytes
        complex_multiple = 1
        if get_type == "Complex Float 32":
            complex_multiple = 2
            sample_size = 4
            num_samples = complex_multiple * num_samples
        elif get_type == "Float/Float 32":
            sample_size = 4
        elif get_type == "Short/Int 16":
            sample_size = 2
        elif get_type == "Int/Int 32":
            sample_size = 4
        elif get_type == "Byte/Int 8":
            sample_size = 1
        elif get_type == "Complex Int 16":
            complex_multiple = 2
            sample_size = 2
            num_samples = complex_multiple * num_samples
        elif get_type == "Complex Int 8":
            sample_size = 1
            complex_multiple = 2
            num_samples = complex_multiple * num_samples
        elif get_type == "Complex Float 64":
            sample_size = 8
            complex_multiple = 2
            num_samples = complex_multiple * num_samples
        elif get_type == "Complex Int 64":
            sample_size = 8
            complex_multiple = 2
            num_samples = complex_multiple * num_samples

        # Check the Range
        if (num_samples*sample_size > number_of_bytes) or (complex_multiple*end_sample*sample_size > number_of_bytes) or (start_sample < 1):
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Out of range.")
            return

        # Read the Data
        filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
        file = open(filepath,"rb")                          # Open the file
        if "Complex" in get_type:
            file.seek(2*(start_sample-1) * sample_size)     # Point to the starting sample
        else:
            file.seek((start_sample-1) * sample_size)       # Point to the starting sample
        plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes
        file.close()

        # Format the Data
        if get_type == "Complex Float 32":
            plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
        elif get_type == "Float/Float 32":
            plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
        elif get_type == "Short/Int 16":
            plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
        elif get_type == "Int/Int 32":
            plot_data_formatted = struct.unpack(num_samples*'i', plot_data)
        elif get_type == "Byte/Int 8":
            plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
        elif get_type == "Complex Int 16":
            plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
        elif get_type == "Complex Int 8":
            plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
        elif get_type == "Complex Float 64":
            plot_data_formatted = struct.unpack(num_samples*'d', plot_data)
        elif get_type == "Complex Int 64":
            plot_data_formatted = struct.unpack(num_samples*'l', plot_data)

        # Get I/Q Data
        if "Complex" in get_type:

            I = [float(i) for i in plot_data_formatted[::2]]
            Q = [float(q) for q in plot_data_formatted[1::2]]
            complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

            # # Butterworth Filter
            # nyq = 0.5 * 5000000
            # order = 10
            # cutoff = 100000
            # normal_cutoff = cutoff/nyq
            # b, a = butter(order, normal_cutoff, btype='low', analog=False)
            # y1 = filtfilt(b, a, complex_data)

            # Calculate I.F. Method 1
            y = np.diff(np.angle(complex_data))
            #instantaneous_frequency = [((math.atan2(Q[x]*(180/math.pi), I[x]*(180/math.pi)))+2*math.pi)%(2*math.pi) for x in range(len(I))]

            for n in range(1,len(y)-1):
                if abs(y[n]-y[n-1]) > 0.1:
                    if y[n-1] > y[n+1]:
                        y[n] = y[n-1] - (y[n-1] - y[n+1])/2
                    else:
                        y[n] = y[n-1] + (y[n+1] - y[n-1])/2
        else:
            y = None

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
        dashboard.iq_matplotlib_widget.axes.plot(range(1,len(y)+1),y,'b',linewidth=1)
        dashboard.iq_matplotlib_widget.applyLabels("Filtered Signal",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

        # Reset the Cursor and Draw
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()
        #dashboard.iq_matplotlib_widget.draw()


        # # Plot
        # dashboard.iq_matplotlib_widget.clearPlot()
        # dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
        # if "Complex" in get_type:
            # # Ignore hold() Deprecation Warnings
            # with warnings.catch_warnings():
                # warnings.simplefilter("ignore")
                # warnings.filterwarnings("ignore", module="matplotlib")

                # # Plot
                # dashboard.iq_matplotlib_widget.axes.plot(y[::2],'b',linewidth=1)
                # dashboard.iq_matplotlib_widget.axes.hold(True)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()
                # dashboard.iq_matplotlib_widget.axes.plot(y[1::2],'r',linewidth=1)
                # dashboard.iq_matplotlib_widget.axes.hold(False)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()
        # else:
            # dashboard.iq_matplotlib_widget.axes.plot(plot_data_formatted,'b',linewidth=1)

        # dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        # dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        # _slotIQ_Cursor1Clicked(dashboard)
        # #dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_MorseCodeClicked(dashboard: QtCore.QObject):
    """ 
    Auto-detects Morse Code from the magnitude of an IQ file and returns the text.
    """
    # File Loaded
    if len(dashboard.ui.label2_iq_file_name.text().split('File:')[-1]) == 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Load an IQ file by double-clicking the filename or clicking the Load File button, then plot the signal.")
        return

    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        #print(len(y_data))

        # Calculate AM
        AM = [math.sqrt(float(i)**2) for i in y_data]

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(AM,'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("Magnitude",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()

        I_squared = [float(i)**2 for i in I]
        Q_squared = [float(q)**2 for q in Q]

        # Calculate AM
        AM = [math.sqrt(I_squared[x] + Q_squared[x]) for x in range(len(I_squared))]

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(AM,'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("Magnitude",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Invalid Signal
    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Plot a valid Morse Code signal.")
        return

    # Reset the Cursor and Draw
    dashboard.ui.pushButton_iq_cursor1.setChecked(False)
    _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()
    #dashboard.iq_matplotlib_widget.draw()

    # Get the Magnitude Rising and Falling Edges
    threshold = float(dashboard.backend.settings['morse_code_amplitude_threshold']) #0.5  # Adjust magnitude threshold accordingly
    state = 0
    edges = []
    for n in range(0,len(AM)):
        if (AM[n] > threshold) and (state == 0):
            edges.append(n)
            state = 1
        elif (AM[n] < threshold) and (state == 1):
            edges.append(n)
            state = 0

    # Find Dit/Dah Width
    error_tolerance = float(dashboard.backend.settings['morse_code_error_tolerance'])  # 0.05
    dashboard.logger.info("Edge Locations: " + str(edges))
    if len(edges) > 5:  # Any number demonstrating consistency
        edge_diff = []
        for n in range(1,len(edges)):
            edge_diff.append(edges[n] - edges[n-1])

        unique_widths = sorted(set(edge_diff))
        dashboard.logger.info("Edge Widths: " + str(edge_diff))
        dashboard.logger.info("Unique Widths: " + str(unique_widths))

        if len(unique_widths) > 1:
            dit = None
            for n in range(0,len(unique_widths)):
                temp_dit = unique_widths[n]
                for m in range(1,len(unique_widths)):
                    if (temp_dit*3 > unique_widths[m]*(1-error_tolerance)) and (temp_dit*3 < unique_widths[m]*(1+error_tolerance)):  # +/- 5%
                        dit = temp_dit
                if dit:
                    break

            # Spell Message
            morse_code = ""
            for n in range(1,len(edges)-1,2):
                # Note: People have a tendency to implement the space for the same letter, between letters, and words differently than the International Morse Code method. Adjust accordingly.
                same_letter_spacing = float(dashboard.backend.settings['morse_code_same_letter_spacing'])     #1 # 1 - I.M.C.
                between_letter_spacing = float(dashboard.backend.settings['morse_code_between_letter_spacing'])  #2 # 3 - I.M.C.
                between_word_spacing = float(dashboard.backend.settings['morse_code_between_word_spacing'])    #6 # 7 - I.M.C.

                # '10'
                if (edges[n]-edges[n-1] > dit*(1-error_tolerance)) and (edges[n]-edges[n-1] < dit*(1+error_tolerance)) and (edges[n+1]-edges[n] > same_letter_spacing* dit*(1-error_tolerance)) and (edges[n+1]-edges[n] < same_letter_spacing*dit*(1+error_tolerance)):
                    morse_code = morse_code + '.'

                # '1 [next letter]'
                elif (edges[n]-edges[n-1] > dit*(1-error_tolerance)) and (edges[n]-edges[n-1] < dit*(1+error_tolerance)) and (edges[n+1]-edges[n] > between_letter_spacing*dit*(1-error_tolerance)) and (edges[n+1]-edges[n] < between_letter_spacing*dit*(1+error_tolerance)):
                    morse_code = morse_code + '. '

                # '1110'
                elif (edges[n]-edges[n-1] > 3*dit*(1-error_tolerance)) and (edges[n]-edges[n-1] < 3*dit*(1+error_tolerance)) and (edges[n+1]-edges[n] > same_letter_spacing*dit*(1-error_tolerance)) and (edges[n+1]-edges[n] < same_letter_spacing*dit*(1+error_tolerance)):
                    morse_code = morse_code + '-'

                # '111 [next letter]'
                elif (edges[n]-edges[n-1] > 3*dit*(1-error_tolerance)) and (edges[n]-edges[n-1] < 3*dit*(1+error_tolerance)) and (edges[n+1]-edges[n] > between_letter_spacing*dit*(1-error_tolerance)) and (edges[n+1]-edges[n] < between_letter_spacing*dit*(1+error_tolerance)):
                    morse_code = morse_code + '- '

                # '1 [next word]'
                elif (edges[n]-edges[n-1] > dit*(1-error_tolerance)) and (edges[n]-edges[n-1] < dit*(1+error_tolerance)) and (edges[n+1]-edges[n] > between_word_spacing*dit*(1-error_tolerance)) and (edges[n+1]-edges[n] < between_word_spacing*dit*(1+error_tolerance)):
                    morse_code = morse_code + '.|'

                # '111 [next word]'
                elif (edges[n]-edges[n-1] > 3*dit*(1-error_tolerance)) and (edges[n]-edges[n-1] < 3*dit*(1+error_tolerance)) and (edges[n+1]-edges[n] > between_word_spacing*dit*(1-error_tolerance)) and (edges[n+1]-edges[n] < between_word_spacing*dit*(1+error_tolerance)):
                    morse_code = morse_code + '-|'

            # Last Dit/Dah
            if (edges[-1] - edges[-2] > dit*(1-error_tolerance)) and (edges[-1] - edges[-2] < dit*(1+error_tolerance)):
                morse_code = morse_code + '.'
            else:
                morse_code = morse_code + '-'

            dashboard.logger.info("\n" + morse_code)

            # Convert to English
            get_text = morseToEnglish(morse_code)
            dashboard.logger.info(get_text + '\n')

            # Open a MessageBox
            fissure.Dashboard.UI_Components.Qt5.errorMessage(get_text)


def morseToEnglish(message):
    """ Converts dits and dahs to English. Not a slot.
    """
    # Dictionary representing the morse code chart
    MORSE_CODE_DICT = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
        'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
        'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
        'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
        'Y': '-.--', 'Z': '--..',
        '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....',
        '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----',
        ', ': '--..--', '.': '.-.-.-', '?': '..--..', '/': '-..-.', '-': '-....-',
        '(': '-.--.', ')': '-.--.-', '!': '-.-.--', '&': '.-...', ':': '---...',
        ';': '-.-.-.', '=': '-...-', '+': '.-.-.', '_': '..--.-', '"': '.-..-.',
        '$': '...-..-', '@': '.--.-.'
    }

    # Replace '|' with Double Space
    message = message.replace('|','  ')

    # Extra Space Added at the End to Access the Last Morse Code
    message += ' '

    decipher = ''
    citext = ''
    for letter in message:
        # Checks for Space
        if (letter != ' '):
            # Counter to Keep Track of Space
            i = 0

            # Storing Morse Code of a Single Character
            citext += letter

        # In Case of Space
        else:
            # If i = 1 that Indicates a New Character
            i += 1

            # If i = 2 that Indicates a New Word
            if (i == 2):
                # Adding Space to Separate Words
                decipher += ' '
            else:
                # Accessing the Keys using their Values (Reverse of Encryption)
                if citext in MORSE_CODE_DICT.values():
                    # Accessing the Keys using their Values (Reverse of Encryption)
                    decipher += list(MORSE_CODE_DICT.keys())[list(MORSE_CODE_DICT.values()).index(citext)]
                else:
                    # If the character is not recognized, add a question mark
                    decipher += '?'
                citext = ''

    return decipher


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_MovingAverageClicked(dashboard: QtCore.QObject):
    """ 
    Applies a moving average filter to the data in the plot window.
    """
    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Taps
    num_points = int(dashboard.backend.settings['moving_avg_points'])
    taps = (np.ones(num_points))/num_points

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Ignore lfilter Warning
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")
            avg_data = lfilter(taps, 1.0, y_data)

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(avg_data,'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

        # Ignore lfilter Warning
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")
            avg_data = lfilter(taps, 1.0, complex_data)

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.real(avg_data),'b',linewidth=1)
            #dashboard.iq_matplotlib_widget.axes.hold(True)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()
            dashboard.iq_matplotlib_widget.axes.plot(np.imag(avg_data),'r',linewidth=1)
            #dashboard.iq_matplotlib_widget.axes.hold(False)  # FIX: To clear an axes you can manually use cla(), or to clear an entire figure use clf()

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PolarClicked(dashboard: QtCore.QObject):
    """ 
    Plots file data as a polar plot.
    """
    # Get the Filepath
    get_type = dashboard.ui.comboBox_iq_data_type.currentText()
    try:
        number_of_bytes = os.path.getsize(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
    except:
        number_of_bytes = -1

    if number_of_bytes > 0:

        # Get the Number of Samples
        try:
            start_sample = int(dashboard.ui.textEdit_iq_start.toPlainText())
            end_sample = int(dashboard.ui.textEdit_iq_end.toPlainText())
            num_samples = end_sample - start_sample + 1
        except:
            return

        # Do Nothing if Bad Range
        if num_samples < 0:
            return

        # Do Not Load Large Amounts of Data
        if num_samples < 5000000:

            # Get the Size of Each Sample in Bytes
            complex_multiple = 1
            if get_type == "Complex Float 32":
                complex_multiple = 2
                sample_size = 4
                num_samples = complex_multiple * num_samples
            elif get_type == "Float/Float 32":
                sample_size = 4
            elif get_type == "Short/Int 16":
                sample_size = 2
            elif get_type == "Int/Int 32":
                sample_size = 4
            elif get_type == "Byte/Int 8":
                sample_size = 1
            elif get_type == "Complex Int 16":
                complex_multiple = 2
                sample_size = 2
                num_samples = complex_multiple * num_samples
            elif get_type == "Complex Int 8":
                complex_multiple = 2
                sample_size = 1
                num_samples = complex_multiple * num_samples
            elif get_type == "Complex Float 64":
                complex_multiple = 2
                sample_size = 8
                num_samples = complex_multiple * num_samples
            elif get_type == "Complex Int 64":
                complex_multiple = 2
                sample_size = 8
                num_samples = complex_multiple * num_samples

            # Check the Range
            if (num_samples*sample_size > number_of_bytes) or (complex_multiple*end_sample*sample_size > number_of_bytes) or (start_sample < 1):
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Out of range.")
                return

            # Read the Data
            filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
            file = open(filepath,"rb")                          # Open the file
            if "Complex" in get_type:
                file.seek(2*(start_sample-1) * sample_size)     # Point to the starting sample
            else:
                file.seek((start_sample-1) * sample_size)       # Point to the starting sample
            plot_data = file.read(num_samples * sample_size)    # Read the right number of bytes
            file.close()

            # Format the Data
            if get_type == "Complex Float 32":
                plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
            elif get_type == "Float/Float 32":
                plot_data_formatted = struct.unpack(num_samples*'f', plot_data)
            elif get_type == "Short/Int 16":
                plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
            elif get_type == "Int/Int 32":
                plot_data_formatted = struct.unpack(num_samples*'i', plot_data)
            elif get_type == "Byte/Int 8":
                plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
            elif get_type == "Complex Int 16":
                plot_data_formatted = struct.unpack(num_samples*'h', plot_data)
            elif get_type == "Complex Int 8":
                plot_data_formatted = struct.unpack(num_samples*'b', plot_data)
            elif get_type == "Complex Float 64":
                plot_data_formatted = struct.unpack(num_samples*'d', plot_data)
            elif get_type == "Complex Int 64":
                plot_data_formatted = struct.unpack(num_samples*'l', plot_data)

        # Too Many Samples
        else:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Samples must be less than 5,000,000.")
            return

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=True,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
        dashboard.iq_matplotlib_widget.axes.plot(2*np.pi*np.arange(0,complex_multiple,complex_multiple/float(len(plot_data_formatted))),plot_data_formatted,'bo',markersize=1)
        dashboard.iq_matplotlib_widget.applyLabels("Polar Plot",'','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

        # Reset the Cursor and Draw
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)  # Does the draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_AbsoluteValueClicked(dashboard: QtCore.QObject):
    """ 
    Plots the absolute value of what is already displayed in the IQ Data plot window.
    """
    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.abs(y_data),'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.abs(np.real(complex_data)),'b',linewidth=1)
            dashboard.iq_matplotlib_widget.axes.plot(np.abs(np.imag(complex_data)),'r',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_DifferentialClicked(dashboard: QtCore.QObject):
    """ 
    Plots the differential of what is already displayed in the IQ Data plot window.
    """
    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.diff(y_data),'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.diff(np.real(complex_data)),'b',linewidth=1)
            dashboard.iq_matplotlib_widget.axes.plot(np.diff(np.imag(complex_data)),'r',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_Keep1in2_Clicked(dashboard: QtCore.QObject):
    """ 
    Plots 1 in 2 samples of what is already displayed in the IQ Data plot window.
    """
    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(y_data[::2],'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.real(complex_data[::2]),'b',linewidth=1)
            dashboard.iq_matplotlib_widget.axes.plot(np.imag(complex_data[::2]),'r',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PhaseClicked(dashboard: QtCore.QObject):
    """ 
    Plots phase of loaded IQ data.
    """
    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.angle(y_data),'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.angle(complex_data),'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_UnwrapClicked(dashboard: QtCore.QObject):
    """ 
    Plots the unwrapped version of what is already displayed in the IQ Data plot window.
    """
    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.unwrap(y_data),'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.unwrap(np.real(complex_data)),'b',linewidth=1)
            dashboard.iq_matplotlib_widget.axes.plot(np.unwrap(np.imag(complex_data)),'r',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_FilterClicked(dashboard: QtCore.QObject):
    """ 
    Applies a bandpass filter to the data in the plot window.
    """
    # Get the Filter Values
    try:
        end_freq = float(str(dashboard.ui.textEdit_iq_filter_end.toPlainText()))
        if str(dashboard.ui.comboBox_iq_filter_type.currentText()) == "bandpass":
            start_freq = float(str(dashboard.ui.textEdit_iq_filter_start.toPlainText()))
            if start_freq > end_freq:
                temp_freq = end_freq
                end_freq = start_freq
                start_freq = temp_freq
        sample_rate = float(str(dashboard.ui.textEdit_iq_sample_rate.toPlainText()))*1000000
    except:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid start frequency, end frequency, or sample rate.")
        return

    # Get the Data from the Window
    num_lines = dashboard.iq_matplotlib_widget.axes.lines

    # Single Line: Not IQ
    if len(num_lines) == 1:
        y_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.abs(y_data),'b',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()

    # Two Lines: IQ
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        complex_data = [complex(I[x],Q[x]) for x in range(len(I))]

        # Butterworth Lowpass Filter
        if str(dashboard.ui.comboBox_iq_filter_type.currentText()) == "lowpass":
            b, a = butter(5, end_freq/(sample_rate/2), 'lowpass')
            y = filtfilt(b, a, complex_data)

        # Butterworth Bandpass Filter
        elif str(dashboard.ui.comboBox_iq_filter_type.currentText()) == "bandpass":
            #print(str(start_freq/(sample_rate/2)))
            #print(str(end_freq/(sample_rate/2)))
            #b, a = butter(5, [start_freq/(sample_rate/2), end_freq/(sample_rate/2)], 'bandpass', False, 'ba')
            sos = butter(5, [start_freq, end_freq], 'bandpass', False, 'sos', sample_rate)
            #y = lfilter(b, a, complex_data)
            #y = filtfilt(b, a, complex_data)
            y = sosfilt(sos, complex_data)

        else:
            return

        # Plot
        dashboard.iq_matplotlib_widget.clearPlot()
        dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])

        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            dashboard.iq_matplotlib_widget.axes.plot(np.real(y),'b',linewidth=1)
            dashboard.iq_matplotlib_widget.axes.plot(np.imag(y),'r',linewidth=1)

        dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])
        dashboard.ui.pushButton_iq_cursor1.setChecked(False)
        _slotIQ_Cursor1Clicked(dashboard)
        dashboard.iq_matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_OOK_PlotClicked(dashboard: QtCore.QObject):
    """ 
    Generates and plots the OOK signal.
    """
    # Retrieve Parameters
    get_chip0_pattern = str(dashboard.ui.textEdit_iq_ook_chip0_pattern.toPlainText())
    get_chip1_pattern = str(dashboard.ui.textEdit_iq_ook_chip1_pattern.toPlainText())
    get_burst_interval = str(dashboard.ui.textEdit_iq_ook_burst_interval.toPlainText())
    get_sample_rate = str(dashboard.ui.textEdit_iq_ook_sample_rate.toPlainText())
    get_chip0_duration = str(dashboard.ui.textEdit_iq_ook_chip0_duration.toPlainText())
    get_chip1_duration = str(dashboard.ui.textEdit_iq_ook_chip1_duration.toPlainText())
    get_number_of_bursts = int(dashboard.ui.spinBox_iq_ook_bursts.value())
    get_data_type = str(dashboard.ui.comboBox_iq_ook_data_type.currentText())
    get_sequence = str(dashboard.ui.textEdit_iq_ook_sequence.toPlainText())
    
    # Generate Signal
    signal_data = generateOOK_Signal(dashboard, get_chip0_pattern, get_chip1_pattern, get_burst_interval, get_sample_rate, get_chip0_duration, get_chip1_duration, get_number_of_bursts, get_data_type, get_sequence)
    
    # Plot
    dashboard.iq_matplotlib_widget.clearPlot()
    dashboard.iq_matplotlib_widget.configureAxes(polar=False,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
    if "Complex" in get_data_type:
        # Ignore hold() Deprecation Warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            warnings.filterwarnings("ignore", module="matplotlib")

            # Plot
            dashboard.iq_matplotlib_widget.axes.plot(range(1,len(signal_data)+1),signal_data.real,'b',linewidth=1,zorder=2)
            dashboard.iq_matplotlib_widget.axes.plot(range(1,len(signal_data)+1),signal_data.imag,'r',linewidth=1,zorder=2)
    else:
        dashboard.iq_matplotlib_widget.axes.plot(range(1,len(signal_data)+1),signal_data,'b',linewidth=1,zorder=2)

    # Axes Label
    dashboard.iq_matplotlib_widget.applyLabels("IQ Data",'Samples','Amplitude (LSB)',None,None,text_color=dashboard.backend.settings['color4'])

    dashboard.ui.pushButton_iq_cursor1.setChecked(False)
    _slotIQ_Cursor1Clicked(dashboard)

    # Reset Range Cursor Memory
    dashboard.iq_plot_range_start = 0
    dashboard.iq_plot_range_end = 0


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_IQEngineClicked(dashboard: QtCore.QObject):
    """ 
    Opens the selected IQ file in IQEngine or opens the IQEngine browser page if not found.
    """
    # Check if Docker Container is Running
    try:
        # Detect IQ Engine Docker Container
        image_name = "ghcr.io/iqengine/iqengine:pre"
        result = subprocess.run(
            ['docker', 'ps', '--filter', f'ancestor={image_name}', '--format', '{{.Image}}'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Container Running
        if image_name in result.stdout.strip():
            dashboard.logger.info("IQEngine docker container found!")
            dashboard.logger.info("Click Refresh in the top right of the browser to view new files in the IQ Recordings folder.")

        # Container Not Running
        else:
            dashboard.logger.info("IQEngine docker container not found!")

            # Start the Container
            expect_script_filepath = os.path.join(fissure.utils.TOOLS_DIR, "expect_script")
            start_command = """docker run --env-file .env -v \\\"""" + os.path.join(fissure.utils.FISSURE_ROOT, 'IQ Recordings') + """\\\":/tmp/myrecordings -p 3001:3000 --pull=always -d ghcr.io/iqengine/iqengine:pre"""
            iq_engine_directory = os.path.expanduser("~/Installed_by_FISSURE/IQEngine/")
            if fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "gnome-terminal":
                proc = subprocess.Popen("gnome-terminal -- " + expect_script_filepath + ' "' + start_command + '"', shell=True, cwd=iq_engine_directory)
            elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "qterminal":
                proc = subprocess.Popen("qterminal -e " + expect_script_filepath + ' "' + start_command + '"', shell=True, cwd=iq_engine_directory)
            elif fissure.utils.get_default_expect_terminal(dashboard.backend.os_info) == "lxterminal":
                proc = subprocess.Popen('lxterminal -e ' + expect_script_filepath + ' "' + start_command + '"', shell=True, cwd=iq_engine_directory)

        # Read Loaded File
        get_iq_filename = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_iq_directory = str(dashboard.ui.comboBox3_iq_folders.currentText())
        if ("IQ Recordings" in get_iq_directory.split("/")[-1]) and (".sigmf-data" in get_iq_filename):
            # Open a Browser to the File
            os.system("xdg-open http://localhost:3001/view/api/local/local/" + get_iq_filename.split(".sigmf-data")[0])

        else:
            # Open a Browser to the IQ Recordings Folder
            os.system("xdg-open http://localhost:3001/browser")
            dashboard.logger.info("SigMF file not found in IQ Recordings folder. Click Refresh in the top right of the page to see new IQ files in the IQ Recordings folder.")

    except Exception as e:
        dashboard.logger.error(f"Error: {e}")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_EndiannessClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Endianness tab list widget.
    """
    # Clear the List Widget
    dashboard.ui.listWidget_iq_endianness_input.clear()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_EndiannessSelectClicked(dashboard: QtCore.QObject):
    """ 
    Selects an IQ file from the Data Viewer and adds it to the listwidget.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.listWidget_iq_endianness_input.addItem(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_EndiannessLoadClicked(dashboard: QtCore.QObject):
    """ 
    Load multiple IQ files into the listwidget.
    """
    # Choose Files
    get_iq_folder = str(dashboard.ui.comboBox3_iq_folders.currentText()) + '/'
    fname = QtWidgets.QFileDialog.getOpenFileNames(None,"Select IQ Files...", get_iq_folder, filter="All Files (*)")
    if fname != "":
        for n in fname[0]:
            dashboard.ui.listWidget_iq_endianness_input.addItem(n)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_EndiannessRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a file from the list widget.
    """
    # Remove
    if dashboard.ui.listWidget_iq_endianness_input.count() > 0:
        get_index = int(dashboard.ui.listWidget_iq_endianness_input.currentRow())
        for item in dashboard.ui.listWidget_iq_endianness_input.selectedItems():
            dashboard.ui.listWidget_iq_endianness_input.takeItem(dashboard.ui.listWidget_iq_endianness_input.row(item))

        # Refresh
        if get_index == dashboard.ui.listWidget_iq_endianness_input.count():
            get_index = get_index -1
        dashboard.ui.listWidget_iq_endianness_input.setCurrentRow(get_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_EndiannessChooseClicked(dashboard: QtCore.QObject):
    """ 
    Choose an output directory to store new stripped IQ files.
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    dialog.setFileMode(QtWidgets.QFileDialog.Directory)
    dialog.setOption(QtWidgets.QFileDialog.ShowDirsOnly, True)

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_endianness_output.setText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_EndiannessClicked(dashboard: QtCore.QObject):
    """ 
    Swaps the endianness for input IQ files.
    """
    # Get Inputs
    get_overwrite = dashboard.ui.checkBox_iq_endianness_overwrite.isChecked()
    get_data_type = str(dashboard.ui.comboBox_iq_endianness_data_type.currentText())
    get_output_directory = str(dashboard.ui.textEdit_iq_endianness_output.toPlainText())

    if not get_output_directory:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select output directory")
        return

    if dashboard.ui.listWidget_iq_endianness_input.count() == 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select IQ files to swap endianness")
        return

    # Define a mapping for data type sizes
    data_type_map = {
        "Complex Float 32": (">f", 4),
        "Float/Float 32": (">f", 4),
        "Short/Int 16": (">h", 2),
        "Unsigned Int 16": (">H", 2),
        "Int/Int 32": (">i", 4),
        "Unsigned Int 32": (">I", 4),
        "Byte/Int 8": (">b", 1),
        "Unsigned Int 8": (">B", 1),
        "Complex Float 64": (">d", 8),
        "Complex Int 64": (">q", 8),
        "Complex Unsigned Int 64": (">Q", 8),
        "Complex Int 16": (">h", 2),
        "Complex Unsigned Int 16": (">H", 2),
        "Complex Int 8": (">b", 1),
        "Complex Unsigned Int 8": (">B", 1),
    }

    # Process files
    for n in range(dashboard.ui.listWidget_iq_endianness_input.count()):
        fname = str(dashboard.ui.listWidget_iq_endianness_input.item(n).text())

        if get_overwrite:
            new_file = fname
        else:
            base_name = os.path.basename(fname)
            new_file = os.path.join(get_output_directory, f"{os.path.splitext(base_name)[0]}_swapped{os.path.splitext(base_name)[1]}")

        if not os.path.isfile(fname):
            fissure.Dashboard.UI_Components.Qt5.errorMessage(f"File not found: {fname}")
            continue

        # Check data type
        if get_data_type not in data_type_map:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Unknown Data Type")
            return

        # Read, swap, and write data
        dashboard.logger.info(f"Swapping Endianness for: {fname}")
        with open(fname, "rb") as file:
            file_data = file.read()

        struct_format, byte_size = data_type_map[get_data_type]
        try:
            # Unpack data, swap endianness, and repack
            unpacked_data = struct.iter_unpack(struct_format, file_data)
            swapped_data = [struct.pack(struct_format.replace(">", "<"), *item) for item in unpacked_data]
            
            # Save swapped data
            with open(new_file, "wb") as out_file:
                out_file.writelines(swapped_data)
        except Exception as e:
            dashboard.logger.error(f"Error processing {fname}: {e}")
            fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Error processing {fname}: {e}")
            continue

    # Refresh
    _slotIQ_RefreshClicked(dashboard)
    dashboard.logger.info("Swap Endianness Complete")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ConvertClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Convert tab list widget.
    """
    # Clear the List Widget
    dashboard.ui.listWidget_iq_convert_input.clear()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ConvertSelectClicked(dashboard: QtCore.QObject):
    """ 
    Selects an IQ file from the Data Viewer and adds it to the listwidget.
    """
    try:
        # Get Highlighted File from Listbox
        get_file = str(dashboard.ui.listWidget_iq_files.currentItem().text())
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.listWidget_iq_convert_input.addItem(get_folder + '/' + get_file)

    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ConvertLoadClicked(dashboard: QtCore.QObject):
    """ 
    Load multiple IQ files into the listwidget.
    """
    # Choose Files
    get_iq_folder = str(dashboard.ui.comboBox3_iq_folders.currentText()) + '/'
    fname = QtWidgets.QFileDialog.getOpenFileNames(None,"Select IQ Files...", get_iq_folder, filter="All Files (*)")
    if fname != "":
        for n in fname[0]:
            dashboard.ui.listWidget_iq_convert_input.addItem(n)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ConvertRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a file from the list widget.
    """
    # Remove
    if dashboard.ui.listWidget_iq_convert_input.count() > 0:
        get_index = int(dashboard.ui.listWidget_iq_convert_input.currentRow())
        for item in dashboard.ui.listWidget_iq_convert_input.selectedItems():
            dashboard.ui.listWidget_iq_convert_input.takeItem(dashboard.ui.listWidget_iq_convert_input.row(item))

        # Refresh
        if get_index == dashboard.ui.listWidget_iq_convert_input.count():
            get_index = get_index -1
        dashboard.ui.listWidget_iq_convert_input.setCurrentRow(get_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ConvertChooseClicked(dashboard: QtCore.QObject):
    """ 
    Choose an output directory to store new converted IQ files.
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    dialog.setFileMode(QtWidgets.QFileDialog.Directory)
    dialog.setOption(QtWidgets.QFileDialog.ShowDirsOnly, True)

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_iq_convert_output.setText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ConvertOutputSelectClicked(dashboard: QtCore.QObject):
    """ 
    Selects the current IQ Viewer directory for the Convert output directory.
    """
    try:
        # Get Highlighted File from Listbox
        get_folder = str(dashboard.ui.label_iq_folder.text())
        dashboard.ui.textEdit_iq_convert_output.setPlainText(get_folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ConvertClicked(dashboard: QtCore.QObject):
    """
    Convert between scalar and complex IQ formats.

    Assumptions:
    - Complex integer types are stored on disk as interleaved IQ:
        I0, Q0, I1, Q1, ...
    - Complex unsigned integer types are treated as centered/offset-binary IQ.
    - Complex float types are stored as native NumPy complex dtypes.
    - Scalar targets receiving complex input will keep only the real part.
    """
    # Get Inputs
    get_overwrite = dashboard.ui.checkBox_iq_convert_overwrite.isChecked()
    get_normalize = dashboard.ui.checkBox_iq_convert_normalize.isChecked()
    get_original_data_type = str(dashboard.ui.comboBox_iq_convert_original_data_type.currentText())
    get_new_data_type = str(dashboard.ui.comboBox_iq_convert_new_data_type.currentText())
    get_output_directory = str(dashboard.ui.textEdit_iq_convert_output.toPlainText())

    if not get_output_directory:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select output directory")
        return

    if dashboard.ui.listWidget_iq_convert_input.count() == 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select IQ files to convert")
        return

    type_specs = {
        "Complex Float 64": {
            "is_complex": True,
            "storage": "native_complex",
            "disk_dtype": np.complex128,
        },
        "Complex Float 32": {
            "is_complex": True,
            "storage": "native_complex",
            "disk_dtype": np.complex64,
        },
        "Float/Float 32": {
            "is_complex": False,
            "storage": "scalar",
            "disk_dtype": np.float32,
        },
        "Complex Int 64": {
            "is_complex": True,
            "storage": "interleaved_signed",
            "disk_dtype": np.int64,
            "bits": 64,
        },
        "Complex Int 16": {
            "is_complex": True,
            "storage": "interleaved_signed",
            "disk_dtype": np.int16,
            "bits": 16,
        },
        "Complex Int 8": {
            "is_complex": True,
            "storage": "interleaved_signed",
            "disk_dtype": np.int8,
            "bits": 8,
        },
        "Int/Int 32": {
            "is_complex": False,
            "storage": "scalar",
            "disk_dtype": np.int32,
        },
        "Short/Int 16": {
            "is_complex": False,
            "storage": "scalar",
            "disk_dtype": np.int16,
        },
        "Byte/Int 8": {
            "is_complex": False,
            "storage": "scalar",
            "disk_dtype": np.int8,
        },
        "Unsigned Int 8": {
            "is_complex": False,
            "storage": "scalar",
            "disk_dtype": np.uint8,
        },
        "Unsigned Int 16": {
            "is_complex": False,
            "storage": "scalar",
            "disk_dtype": np.uint16,
        },
        "Unsigned Int 32": {
            "is_complex": False,
            "storage": "scalar",
            "disk_dtype": np.uint32,
        },
        "Complex Unsigned Int 64": {
            "is_complex": True,
            "storage": "interleaved_unsigned_centered",
            "disk_dtype": np.uint64,
            "bits": 64,
        },
        "Complex Unsigned Int 16": {
            "is_complex": True,
            "storage": "interleaved_unsigned_centered",
            "disk_dtype": np.uint16,
            "bits": 16,
        },
        "Complex Unsigned Int 8": {
            "is_complex": True,
            "storage": "interleaved_unsigned_centered",
            "disk_dtype": np.uint8,
            "bits": 8,
        },
    }

    if get_original_data_type not in type_specs or get_new_data_type not in type_specs:
        dashboard.logger.error("Unknown Data Type")
        return

    original_spec = type_specs[get_original_data_type]
    new_spec = type_specs[get_new_data_type]

    for n in range(dashboard.ui.listWidget_iq_convert_input.count()):
        fname = str(dashboard.ui.listWidget_iq_convert_input.item(n).text())

        if get_overwrite:
            new_file = fname
        else:
            base_name = os.path.basename(fname)
            stem, ext = os.path.splitext(base_name)
            new_file = os.path.join(get_output_directory, f"{stem}_converted{ext}")

        if not os.path.isfile(fname):
            dashboard.logger.error(f"File not found: {fname}")
            continue

        try:
            # Read file into internal representation:
            #   complex -> np.complex128
            #   scalar  -> np.float64
            raw = np.fromfile(fname, dtype=original_spec["disk_dtype"])

            if original_spec["storage"] == "native_complex":
                data = raw.astype(np.complex128, copy=False)

            elif original_spec["storage"] == "scalar":
                data = raw.astype(np.float64, copy=False)

            elif original_spec["storage"] in ("interleaved_signed", "interleaved_unsigned_centered"):
                if raw.size < 2:
                    data = np.array([], dtype=np.complex128)
                else:
                    if raw.size % 2 != 0:
                        dashboard.logger.warning(
                            f"{fname}: odd number of scalar values for complex IQ; dropping last value"
                        )
                        raw = raw[:-1]

                    iq = raw.reshape(-1, 2)

                    if original_spec["storage"] == "interleaved_signed":
                        i = iq[:, 0].astype(np.float64)
                        q = iq[:, 1].astype(np.float64)
                        data = i + 1j * q
                    else:
                        center = 1 << (original_spec["bits"] - 1)
                        i = iq[:, 0].astype(np.float64) - center
                        q = iq[:, 1].astype(np.float64) - center
                        data = i + 1j * q
            else:
                raise ValueError(f"Unsupported source storage type: {original_spec['storage']}")

            # Optional normalization to target range
            if get_normalize and data.size > 0:
                if new_spec["is_complex"]:
                    cdata = np.asarray(data, dtype=np.complex128)
                    peak = max(
                        np.max(np.abs(cdata.real)) if cdata.size else 0.0,
                        np.max(np.abs(cdata.imag)) if cdata.size else 0.0,
                    )
                    if peak > 0:
                        if new_spec["storage"] == "native_complex":
                            target_peak = 1.0
                        else:
                            target_peak = (1 << (new_spec["bits"] - 1)) - 1
                        data = (cdata / peak) * target_peak
                else:
                    sdata = np.real(data) if np.iscomplexobj(data) else np.asarray(data, dtype=np.float64)

                    if np.issubdtype(new_spec["disk_dtype"], np.floating):
                        peak = np.max(np.abs(sdata)) if sdata.size else 0.0
                        if peak > 0:
                            data = sdata / peak
                        else:
                            data = sdata

                    elif np.issubdtype(new_spec["disk_dtype"], np.signedinteger):
                        peak = np.max(np.abs(sdata)) if sdata.size else 0.0
                        if peak > 0:
                            data = (sdata / peak) * np.iinfo(new_spec["disk_dtype"]).max
                        else:
                            data = sdata

                    elif np.issubdtype(new_spec["disk_dtype"], np.unsignedinteger):
                        dmin = np.min(sdata) if sdata.size else 0.0
                        dmax = np.max(sdata) if sdata.size else 0.0
                        if dmax != dmin:
                            data = ((sdata - dmin) / (dmax - dmin)) * np.iinfo(new_spec["disk_dtype"]).max
                        else:
                            data = np.zeros_like(sdata, dtype=np.float64)

            # Write output in requested target format
            if new_spec["is_complex"]:
                cdata = np.asarray(data, dtype=np.complex128)

                if new_spec["storage"] == "native_complex":
                    out = cdata.astype(new_spec["disk_dtype"])
                    out.tofile(new_file)

                elif new_spec["storage"] == "interleaved_signed":
                    scalar_dtype = new_spec["disk_dtype"]
                    info = np.iinfo(scalar_dtype)

                    i = np.clip(np.rint(cdata.real), info.min, info.max).astype(scalar_dtype)
                    q = np.clip(np.rint(cdata.imag), info.min, info.max).astype(scalar_dtype)

                    out = np.empty(i.size * 2, dtype=scalar_dtype)
                    out[0::2] = i
                    out[1::2] = q
                    out.tofile(new_file)

                elif new_spec["storage"] == "interleaved_unsigned_centered":
                    scalar_dtype = new_spec["disk_dtype"]
                    info = np.iinfo(scalar_dtype)
                    center = 1 << (new_spec["bits"] - 1)

                    i = np.clip(np.rint(cdata.real + center), info.min, info.max).astype(scalar_dtype)
                    q = np.clip(np.rint(cdata.imag + center), info.min, info.max).astype(scalar_dtype)

                    out = np.empty(i.size * 2, dtype=scalar_dtype)
                    out[0::2] = i
                    out[1::2] = q
                    out.tofile(new_file)

                else:
                    raise ValueError(f"Unsupported target storage type: {new_spec['storage']}")

            else:
                if np.iscomplexobj(data):
                    if np.any(np.abs(np.asarray(data).imag) > 0):
                        dashboard.logger.warning(
                            f"{new_file}: converting complex to scalar; imaginary component discarded"
                        )
                    sdata = np.asarray(data.real, dtype=np.float64)
                else:
                    sdata = np.asarray(data, dtype=np.float64)

                scalar_dtype = new_spec["disk_dtype"]

                if np.issubdtype(scalar_dtype, np.floating):
                    out = sdata.astype(scalar_dtype)
                else:
                    info = np.iinfo(scalar_dtype)
                    out = np.clip(np.rint(sdata), info.min, info.max).astype(scalar_dtype)

                out.tofile(new_file)

            dashboard.logger.info(f"File converted successfully: {new_file}")

        except Exception as e:
            dashboard.logger.error(f"Error processing file {fname}: {str(e)}")

    _slotIQ_RefreshClicked(dashboard)
    dashboard.logger.info("Convert Complete")

    # """ 
    # Convert from one data type to another with the option to normalize to target data range.
    # """
    # # Get Inputs
    # get_overwrite = dashboard.ui.checkBox_iq_convert_overwrite.isChecked()
    # get_normalize = dashboard.ui.checkBox_iq_convert_normalize.isChecked()
    # get_original_data_type = str(dashboard.ui.comboBox_iq_convert_original_data_type.currentText())
    # get_new_data_type = str(dashboard.ui.comboBox_iq_convert_new_data_type.currentText())
    # get_output_directory = str(dashboard.ui.textEdit_iq_convert_output.toPlainText())

    # if not get_output_directory:
    #     fissure.Dashboard.UI_Components.Qt5.errorMessage("Select output directory")
    #     return

    # if dashboard.ui.listWidget_iq_convert_input.count() == 0:
    #     fissure.Dashboard.UI_Components.Qt5.errorMessage("Select IQ files to convert")
    #     return

    # # Define a mapping for data type sizes
    # data_type_map = {
    #     "Complex Float 64": (">d", 8),
    #     "Complex Float 32": (">f", 4),
    #     "Float/Float 32": (">f", 4),
    #     "Complex Int 16": (">h", 2),
    #     "Short/Int 16": (">h", 2),
    #     "Complex Int 64": (">q", 8),
    #     "Int/Int 32": (">i", 4),
    #     "Complex Int 8": (">b", 1),
    #     "Byte/Int 8": (">b", 1),
    #     "Unsigned Int 8": (">B", 1),
    #     "Unsigned Int 16": (">H", 2),
    #     "Unsigned Int 32": (">I", 4),
    #     "Complex Unsigned Int 64": (">Q", 8),
    #     "Complex Unsigned Int 16": (">H", 2),
    #     "Complex Unsigned Int 8": (">B", 1),
    # }

    # dtype_mappings = {
    #     "Complex Float 64": np.complex128,
    #     "Complex Float 32": np.complex64,
    #     "Float/Float 32": np.float32,
    #     "Complex Int 64": np.complex128,
    #     "Int/Int 32": np.int32,
    #     "Complex Int 16": np.int16,
    #     "Short/Int 16": np.int16,
    #     "Complex Int 8": np.complex64,
    #     "Byte/Int 8": np.int8,
    #     "Unsigned Int 8": np.uint8,
    #     "Unsigned Int 16": np.uint16,
    #     "Unsigned Int 32": np.uint32,
    #     "Complex Unsigned Int 64": np.complex128,
    #     "Complex Unsigned Int 16": np.complex64,
    #     "Complex Unsigned Int 8": np.complex64,
    # }

    # for n in range(dashboard.ui.listWidget_iq_convert_input.count()):
    #     fname = str(dashboard.ui.listWidget_iq_convert_input.item(n).text())

    #     if get_overwrite:
    #         new_file = fname
    #     else:
    #         base_name = os.path.basename(fname)
    #         new_file = os.path.join(get_output_directory, f"{os.path.splitext(base_name)[0]}_converted{os.path.splitext(base_name)[1]}")

    #     if not os.path.isfile(fname):
    #         dashboard.logger.error(f"File not found: {fname}")
    #         continue

    #     if (get_original_data_type not in data_type_map) or (get_new_data_type not in data_type_map):
    #         dashboard.logger.error("Unknown Data Type")
    #         return

    #     # Convert Logic
    #     original_dtype = dtype_mappings[get_original_data_type]
    #     new_dtype = dtype_mappings[get_new_data_type]

    #     try:
    #         # Read input data
    #         data = np.fromfile(fname, dtype=original_dtype)

    #         if get_normalize:
    #             # Normalize data to fit new data type range
    #             if np.issubdtype(original_dtype, np.complexfloating):
    #                 real_max = max(np.abs(data.real))
    #                 imag_max = max(np.abs(data.imag))
    #                 scale = max(real_max, imag_max)
    #                 if scale > 0:
    #                     data = data / scale
    #             else:
    #                 data_max = max(np.abs(data))
    #                 if data_max > 0:
    #                     data = data / data_max

    #             # Scale to target type range
    #             if np.issubdtype(new_dtype, np.integer):
    #                 new_dtype_max = np.iinfo(new_dtype).max
    #             elif np.issubdtype(new_dtype, np.floating):
    #                 new_dtype_max = 1.0
    #             else:
    #                 new_dtype_max = 1.0  # Default fallback for unsupported cases
                
    #             data = data * new_dtype_max

    #         # Convert to new data type
    #         converted_data = data.astype(new_dtype)

    #         # Write output data
    #         converted_data.tofile(new_file)
    #         dashboard.logger.info(f"File converted successfully: {new_file}")

    #     except Exception as e:
    #         dashboard.logger.error(f"Error processing file {fname}: {str(e)}")

    # # Refresh
    # _slotIQ_RefreshClicked(dashboard)
    # dashboard.logger.info("Convert Complete")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_DemodClicked(dashboard: QtCore.QObject):
    """ 
    Opens a window with the currently loaded signal for applying simple demodulation techniques for viewing bits.
    """
    # File Loaded
    if len(dashboard.ui.label2_iq_file_name.text().split('File:')[-1]) == 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Load an IQ file before plotting by double-clicking the filename or clicking the Load File button.")
        return
    
    # Obtain Signal Information
    get_filepath = dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.label2_iq_file_name.text().replace("File: ","")
    try:
        get_sample_rate = float(dashboard.ui.textEdit_iq_sample_rate.toPlainText())
    except:
        dashboard.logger.error("Invalid sample rate. Provide float value under File Information.")
        get_sample_rate = 1
    
    num_lines = dashboard.iq_matplotlib_widget.axes.lines
    signal_data = []
    if len(num_lines) == 1:
        signal_data = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
    elif len(num_lines) == 2:
        I = dashboard.iq_matplotlib_widget.axes.lines[0].get_ydata()
        Q = dashboard.iq_matplotlib_widget.axes.lines[1].get_ydata()
        signal_data = [complex(I[x],Q[x]) for x in range(len(I))]

    # Open the Dialog
    get_value = dashboard.openPopUp("DemodDialog", DemodDialog, get_filepath, get_sample_rate, signal_data)

    # Cancel Clicked
    if get_value == None:
        pass
        
    # OK Clicked
    elif len(get_value) > 0:
        dashboard.ui.plainTextEdit_pd_bit_viewer_bits.setPlainText(get_value)
        dashboard.ui.tabWidget.setCurrentWidget(dashboard.ui.tab_tsi)
        dashboard.ui.tabWidget_signal_analysis.setCurrentWidget(dashboard.ui.tabWidget_protocol.parentWidget())
        dashboard.ui.tabWidget_protocol.setCurrentWidget(dashboard.ui.tab_pd_bit_viewer)
    else:
        pass


def _iq_get_artifact_files_dir(artifact_dir: str) -> str:
    """
    Returns the artifact files folder. Most plugin artifacts use:

        <artifact_dir>/files

    Falls back to artifact_dir for easier testing.
    """
    files_dir = os.path.join(artifact_dir, "files")
    if os.path.isdir(files_dir):
        return files_dir
    return artifact_dir


def _iq_format_artifact_combo_name(artifact_name: str, files_dir: str) -> str:
    """
    Compact display name for the artifact combo box.
    The full path is stored in UserRole/tooltip.
    """
    try:
        mtime = os.path.getmtime(files_dir)
        timestamp = datetime.datetime.fromtimestamp(mtime).strftime("%m/%d %H:%M")
        return f"{artifact_name}  {timestamp}"
    except Exception:
        return artifact_name


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ArtifactsRefreshClicked(
    dashboard: QtCore.QObject,
):
    """
    Refresh the temporary IQ Artifact browser from the shared Dashboard cache.

    ArtifactTransferController.local_cache is the primary discovery source, so
    downloaded Artifacts are available immediately during IQ tab
    initialization without first opening Tactical.

    dashboard.tactical_artifacts is used only to enrich cached entries with
    canonical names, timestamps, and manifest metadata when that information is
    already available.
    """
    combo = dashboard.ui.comboBox_iq_artifacts
    file_list = dashboard.ui.listWidget_iq_artifacts_files

    previous_artifact_id = ""

    current_data = combo.currentData(
        QtCore.Qt.UserRole
    )

    if isinstance(current_data, dict):
        previous_artifact_id = str(
            current_data.get(
                "artifact_id",
                "",
            )
            or ""
        ).strip()

    controller = getattr(
        dashboard.backend,
        "artifact_transfer_controller",
        None,
    )

    combo.blockSignals(True)
    combo.clear()
    file_list.clear()

    if controller is None:
        combo.blockSignals(False)

        dashboard.logger.warning(
            "[IQ] Artifact transfer controller is unavailable."
        )
        return

    local_cache = getattr(
        controller,
        "local_cache",
        {},
    )

    if not isinstance(local_cache, dict):
        local_cache = {}

    tactical_artifacts = (
        getattr(
            dashboard,
            "tactical_artifacts",
            {},
        )
        or {}
    )

    canonical_by_id = {}

    if isinstance(tactical_artifacts, dict):
        tactical_iterable = tactical_artifacts.items()

    elif isinstance(tactical_artifacts, list):
        tactical_iterable = enumerate(
            tactical_artifacts
        )

    else:
        tactical_iterable = []

    for artifact_key, artifact_record in tactical_iterable:
        if not isinstance(artifact_record, dict):
            continue

        artifact_id = str(
            artifact_record.get("artifact_id")
            or artifact_record.get("id")
            or artifact_key
            or ""
        ).strip()

        if artifact_id:
            canonical_by_id[artifact_id] = dict(
                artifact_record
            )

    rows = []

    for cache_key, cache_record in local_cache.items():
        if not isinstance(cache_record, dict):
            continue

        artifact_id = str(
            cache_record.get("artifact_id")
            or cache_key
            or ""
        ).strip()

        if not artifact_id:
            continue

        local_files = controller.get_local_files(
            artifact_id
        )

        if not isinstance(local_files, dict):
            continue

        local_files = {
            str(file_id): str(local_path)
            for file_id, local_path in local_files.items()
            if (
                str(local_path).strip()
                and os.path.isfile(
                    str(local_path)
                )
            )
        }

        if not local_files:
            continue

        canonical_record = canonical_by_id.get(
            artifact_id,
            {},
        )

        if not isinstance(canonical_record, dict):
            canonical_record = {}

        display_record = dict(
            cache_record
        )

        display_record.update(
            canonical_record
        )

        name = str(
            canonical_record.get("name")
            or canonical_record.get("description")
            or cache_record.get("artifact_name")
            or cache_record.get("name")
            or "Artifact"
        ).strip()

        timestamp_value = (
            canonical_record.get("modified_at")
            or canonical_record.get("created_at")
            or canonical_record.get("time")
            or cache_record.get("completed_at")
            or ""
        )

        timestamp_text = ""

        if timestamp_value not in (
            None,
            "",
        ):
            try:
                if isinstance(
                    timestamp_value,
                    (int, float),
                ):
                    timestamp_text = time.strftime(
                        "%m/%d %H:%M",
                        time.localtime(
                            float(timestamp_value)
                        ),
                    )

                else:
                    normalized_timestamp = str(
                        timestamp_value
                    ).replace(
                        "Z",
                        "+00:00",
                    )

                    parsed_timestamp = (
                        datetime.datetime.fromisoformat(
                            normalized_timestamp
                        )
                    )

                    timestamp_text = (
                        parsed_timestamp
                        .astimezone()
                        .strftime(
                            "%m/%d %H:%M"
                        )
                    )

            except Exception:
                timestamp_text = str(
                    timestamp_value
                )[:16]

        display_name = (
            f"{name}  {timestamp_text}"
            if timestamp_text
            else name
        )

        newest_mtime = 0.0

        for local_path in local_files.values():
            try:
                newest_mtime = max(
                    newest_mtime,
                    os.path.getmtime(
                        local_path
                    ),
                )

            except OSError:
                pass

        rows.append(
            (
                newest_mtime,
                display_name,
                {
                    "artifact_id": artifact_id,
                    "record": display_record,
                    "local_files": local_files,
                    "cache_record": dict(
                        cache_record
                    ),
                },
            )
        )

    rows.sort(
        key=lambda row: (
            row[0],
            row[1].lower(),
        ),
        reverse=True,
    )

    restore_index = -1

    for (
        _sort_time,
        display_name,
        artifact_data,
    ) in rows:
        combo.addItem(
            display_name,
            artifact_data,
        )

        index = combo.count() - 1

        combo.setItemData(
            index,
            artifact_data["artifact_id"],
            QtCore.Qt.ToolTipRole,
        )

        if (
            previous_artifact_id
            and artifact_data["artifact_id"]
            == previous_artifact_id
        ):
            restore_index = index

    if combo.count() > 0:
        combo.setCurrentIndex(
            restore_index
            if restore_index >= 0
            else 0
        )

    combo.blockSignals(False)

    _slotIQ_ArtifactsChanged(
        dashboard
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ArtifactsChanged(
    dashboard: QtCore.QObject,
):
    """
    Populate the temporary IQ Artifact file list from shared cached paths.
    """
    combo = dashboard.ui.comboBox_iq_artifacts
    file_list = dashboard.ui.listWidget_iq_artifacts_files

    file_list.clear()

    artifact_data = combo.currentData(
        QtCore.Qt.UserRole
    )

    if not isinstance(artifact_data, dict):
        return

    local_files = artifact_data.get(
        "local_files",
        {},
    )

    if not isinstance(local_files, dict):
        return

    artifact_record = artifact_data.get(
        "record",
        {},
    )

    if not isinstance(artifact_record, dict):
        artifact_record = {}

    manifest = artifact_record.get(
        "files",
        [],
    )

    if not isinstance(manifest, list):
        manifest = []

    manifest_by_id = {
        str(file_record.get("id", "") or ""): file_record
        for file_record in manifest
        if (
            isinstance(file_record, dict)
            and str(
                file_record.get("id", "")
                or ""
            ).strip()
        )
    }

    rows = []

    for file_id, local_path in local_files.items():
        local_path = str(
            local_path
            or ""
        ).strip()

        if not local_path or not os.path.isfile(local_path):
            continue

        file_record = manifest_by_id.get(
            str(file_id),
            {},
        )

        if not isinstance(file_record, dict):
            file_record = {}

        filename = str(
            file_record.get("name")
            or file_record.get("filename")
            or os.path.basename(local_path)
        ).strip()

        rows.append(
            (
                filename.lower(),
                filename,
                local_path,
                str(file_id),
                dict(file_record),
            )
        )

    rows.sort(
        key=lambda row: row[0]
    )

    for (
        _sort_name,
        filename,
        local_path,
        file_id,
        file_record,
    ) in rows:
        item = QtWidgets.QListWidgetItem(
            filename
        )

        item.setData(
            QtCore.Qt.UserRole,
            local_path,
        )

        item.setData(
            QtCore.Qt.UserRole + 1,
            {
                "artifact_id": str(
                    artifact_data.get(
                        "artifact_id",
                        "",
                    )
                    or ""
                ),
                "file_id": file_id,
                "record": file_record,
            },
        )

        item.setToolTip(
            local_path
        )

        file_list.addItem(
            item
        )

    if file_list.count() > 0:
        file_list.setCurrentRow(0)
        

@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ArtifactFileDoubleClicked(dashboard: QtCore.QObject, item=None):
    """
    Loads a local artifact file into the existing IQ viewer path.

    This intentionally reuses the existing Files-tab state:
      - comboBox3_iq_folders
      - label_iq_folder
      - listWidget_iq_files
      - comboBox_iq_data_type

    That keeps existing plot/filter/demod functions working because most of them
    still read label_iq_folder + listWidget_iq_files.currentItem().
    """
    if item is None:
        item = dashboard.ui.listWidget_iq_artifacts_files.currentItem()

    if item is None:
        QtWidgets.QMessageBox.warning(
            dashboard,
            "No Artifact File Selected",
            "Select an artifact file to load.",
        )
        return

    file_path = item.data(QtCore.Qt.UserRole)

    if not file_path:
        # Fallback from current artifact folder + visible item text.
        artifact_data = dashboard.ui.comboBox_iq_artifacts.currentData(QtCore.Qt.UserRole)
        if isinstance(artifact_data, dict):
            files_dir = artifact_data.get("files_dir", "")
            file_path = os.path.join(files_dir, item.text())

    if not file_path or not os.path.isfile(file_path):
        QtWidgets.QMessageBox.warning(
            dashboard,
            "Artifact File Not Found",
            f"Could not find artifact file:\n{file_path}",
        )
        return

    artifact_data_type = dashboard.ui.comboBox_iq_artifacts_data_type.currentText().strip()

    # Sync artifact data type into the existing IQ viewer data type combo.
    if artifact_data_type:
        data_type_index = dashboard.ui.comboBox_iq_data_type.findText(artifact_data_type)

        if data_type_index >= 0:
            dashboard.ui.comboBox_iq_data_type.setCurrentIndex(data_type_index)

    folder = os.path.dirname(file_path)
    filename = os.path.basename(file_path)

    # Add/select the artifact folder in the existing Files folder combo.
    # This lets existing IQ plotting functions continue using the old state path.
    folder_combo = dashboard.ui.comboBox3_iq_folders
    folder_index = folder_combo.findText(folder)

    if folder_index < 0:
        folder_combo.addItem(folder)
        folder_index = folder_combo.count() - 1

    folder_combo.setCurrentIndex(folder_index)

    # Ensure the old file list reflects the artifact folder, then select the file.
    dashboard.ui.label_iq_folder.setText(folder)
    _slotIQ_FoldersChanged(dashboard)

    matches = dashboard.ui.listWidget_iq_files.findItems(
        filename,
        QtCore.Qt.MatchExactly,
    )

    if matches:
        dashboard.ui.listWidget_iq_files.setCurrentItem(matches[0])
    else:
        # Should not usually happen, but keeps LoadIQ_Data safe if the refresh filter changes.
        dashboard.ui.listWidget_iq_files.addItem(filename)
        dashboard.ui.listWidget_iq_files.setCurrentRow(
            dashboard.ui.listWidget_iq_files.count() - 1
        )

    _slotIQ_LoadIQ_Data(dashboard)


def handle_iq_record_artifact_complete(
    dashboard: QtCore.QObject,
    artifact_record: dict,
):
    """
    Finish the active IQ Record run when its matching Artifact arrives and
    expose that Artifact through Card 3.
    """
    if not isinstance(
        artifact_record,
        dict,
    ):
        return

    if not bool(
        getattr(
            dashboard,
            "iq_record_running",
            False,
        )
    ):
        return

    operation_id = str(
        artifact_record.get(
            "operation_id",
            "",
        )
        or ""
    ).strip()

    expected_operation_id = str(
        getattr(
            dashboard,
            "iq_record_operation_id",
            "",
        )
        or ""
    ).strip()

    if (
        not operation_id
        or not expected_operation_id
        or operation_id
        != expected_operation_id
    ):
        return

    artifact_id = str(
        artifact_record.get(
            "artifact_id",
            "",
        )
        or artifact_record.get(
            "id",
            "",
        )
        or ""
    ).strip()

    dashboard.iq_record_artifact_id = artifact_id

    _set_iq_record_stopped(
        dashboard,
        status_text="Completed",
    )

    _update_iq_record_artifact_button(
        dashboard
    )

    try:
        _slotIQ_ArtifactsRefreshClicked(
            dashboard
        )

    except Exception as error:
        dashboard.logger.warning(
            "[IQ Record] Failed refreshing cached Artifacts "
            "after recording: "
            f"{error}"
        )
        return

    if not artifact_id:
        return

    combo = (
        dashboard.ui.comboBox_iq_artifacts
    )

    for index in range(
        combo.count()
    ):
        item_data = combo.itemData(
            index,
            QtCore.Qt.UserRole,
        )

        if not isinstance(
            item_data,
            dict,
        ):
            continue

        candidate_artifact_id = str(
            item_data.get(
                "artifact_id",
                "",
            )
            or ""
        ).strip()

        if (
            candidate_artifact_id
            != artifact_id
        ):
            continue

        combo.setCurrentIndex(
            index
        )
        break


def _clear_iq_record_parameter_widgets(
    dashboard: QtCore.QObject,
):
    """
    Clear the IQ Record parameter panel and its widget registry.
    """
    content = dashboard.ui.scrollAreaWidgetContents_iq_record_parameters
    layout = content.layout()

    if layout is None:
        layout = QtWidgets.QFormLayout(content)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setHorizontalSpacing(10)
        layout.setVerticalSpacing(6)
        layout.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.AllNonFixedFieldsGrow
        )
    else:
        while layout.count():
            item = layout.takeAt(0)

            if item.widget() is not None:
                item.widget().deleteLater()

            if item.layout() is not None:
                child_layout = item.layout()

                while child_layout.count():
                    child_item = child_layout.takeAt(0)

                    if child_item.widget() is not None:
                        child_item.widget().deleteLater()

                child_layout.deleteLater()

    dashboard.iq_record_parameter_widgets = {}
    dashboard.iq_record_current_schema = {}
    dashboard.iq_record_customized = False
    dashboard.ui.pushButton_iq_record_start_stop.setEnabled(False)


def _reset_iq_record_action_selection(dashboard: QtCore.QObject):
    """Reset IQ Record Plugin/Action selection and customized parameters."""
    dashboard.iq_record_filtered_actions = []
    dashboard.iq_record_method_actions = []
    dashboard.iq_record_selected_plugin = ""
    dashboard.iq_record_selected_action = ""
    dashboard.iq_record_customized = False

    plugin_combo = dashboard.ui.comboBox_iq_record_plugin
    action_combo = dashboard.ui.comboBox_iq_record_method

    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.blockSignals(False)
    plugin_combo.setEnabled(False)

    action_combo.blockSignals(True)
    action_combo.clear()
    action_combo.blockSignals(False)
    action_combo.setEnabled(False)

    dashboard.ui.pushButton_iq_record_customize.setEnabled(False)
    _clear_iq_record_parameter_widgets(dashboard)


def _iq_record_action_matches_hardware(hardware_type: str, compatible_hardware) -> bool:
    """Return True when an IQ Record action supports the selected hardware."""
    compatible_hardware = list(compatible_hardware or [])

    if not compatible_hardware:
        return True

    selected = str(hardware_type or "").strip().lower()

    if not selected:
        return False

    for hardware_name in compatible_hardware:
        candidate = str(hardware_name or "").strip().lower()

        if candidate and (candidate in selected or selected in candidate):
            return True

    return False


def _populate_iq_record_actions_for_plugin(
    dashboard: QtCore.QObject,
    preferred_action: str = "",
):
    """Populate IQ Record Action from the selected Plugin."""
    plugin_name = str(dashboard.ui.comboBox_iq_record_plugin.currentText() or "").strip()
    action_combo = dashboard.ui.comboBox_iq_record_method

    action_combo.blockSignals(True)
    action_combo.clear()

    matching_actions = []

    for action_record in getattr(dashboard, "iq_record_filtered_actions", []) or []:
        if not isinstance(action_record, dict):
            continue

        if str(action_record.get("plugin", "") or "").strip() != plugin_name:
            continue

        action_name = str(action_record.get("action", "") or "").strip()

        if not action_name:
            continue

        matching_actions.append(action_record)
        action_combo.addItem(action_name, action_record)

    action_combo.blockSignals(False)

    dashboard.iq_record_method_actions = matching_actions

    has_actions = action_combo.count() > 0
    action_combo.setEnabled(
        has_actions and not bool(getattr(dashboard, "iq_record_running", False))
    )

    if not has_actions:
        dashboard.iq_record_selected_plugin = ""
        dashboard.iq_record_selected_action = ""
        dashboard.iq_record_customized = False
        dashboard.ui.pushButton_iq_record_customize.setEnabled(False)
        _clear_iq_record_parameter_widgets(dashboard)
        return

    preferred_action = str(preferred_action or "").strip()

    if preferred_action:
        preferred_index = action_combo.findText(preferred_action, QtCore.Qt.MatchExactly)

        if preferred_index >= 0:
            action_combo.setCurrentIndex(preferred_index)

    if action_combo.currentIndex() < 0:
        action_combo.setCurrentIndex(0)

    _slotIQ_RecordMethodChanged(dashboard)


def _filter_iq_record_action_catalog(
    dashboard: QtCore.QObject,
    preferred_plugin: str = "",
    preferred_action: str = "",
):
    """Filter cached IQ Record actions by Hardware, then rebuild Plugin/Action."""
    hardware_display_name = str(
        dashboard.ui.comboBox_iq_record_hardware.currentText() or ""
    ).strip()

    dashboard.iq_record_filter_hardware_display = hardware_display_name
    hardware_type = ""

    if hardware_display_name:
        (
            hardware_type,
            _hardware_uuid,
            _hardware_radio_name,
            _hardware_serial,
            _hardware_interface,
            _hardware_ip,
            _hardware_daughterboard,
        ) = fissure.utils.hardware.hardwareDisplayNameLookup(
            dashboard,
            hardware_display_name,
            "iq",
        )

    filtered_actions = []

    if hardware_type:
        for action_record in getattr(dashboard, "iq_record_action_catalog", []) or []:
            if not isinstance(action_record, dict):
                continue

            plugin_name = str(action_record.get("plugin", "") or "").strip()
            action_name = str(action_record.get("action", "") or "").strip()

            if not plugin_name or not action_name:
                continue

            if not _iq_record_action_matches_hardware(
                hardware_type,
                action_record.get("hardware", []),
            ):
                continue

            filtered_actions.append(action_record)

    dashboard.iq_record_filtered_actions = filtered_actions

    plugin_combo = dashboard.ui.comboBox_iq_record_plugin
    current_plugin = str(
        preferred_plugin or plugin_combo.currentText() or ""
    ).strip()

    plugins = sorted(
        {
            str(action_record.get("plugin", "") or "").strip()
            for action_record in filtered_actions
            if isinstance(action_record, dict)
            and str(action_record.get("plugin", "") or "").strip()
        },
        key=str.lower,
    )

    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.addItems(plugins)

    if current_plugin:
        plugin_index = plugin_combo.findText(current_plugin, QtCore.Qt.MatchExactly)

        if plugin_index >= 0:
            plugin_combo.setCurrentIndex(plugin_index)

    if plugin_combo.currentIndex() < 0 and plugin_combo.count() > 0:
        plugin_combo.setCurrentIndex(0)

    plugin_combo.blockSignals(False)

    has_plugins = plugin_combo.count() > 0
    plugin_combo.setEnabled(
        has_plugins and not bool(getattr(dashboard, "iq_record_running", False))
    )

    dashboard.iq_record_customized = False
    _clear_iq_record_parameter_widgets(dashboard)

    _populate_iq_record_actions_for_plugin(
        dashboard,
        preferred_action=preferred_action,
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_RecordActionHardwareChanged(dashboard: QtCore.QObject):
    """Refilter the cached IQ Record catalog when capture hardware changes."""
    dashboard.iq_record_customized = False
    _clear_iq_record_parameter_widgets(dashboard)
    _filter_iq_record_action_catalog(dashboard)

    has_node = bool(str(getattr(dashboard, "selected_node_uid", "") or "").strip())
    has_hardware = bool(
        str(dashboard.ui.comboBox_iq_record_hardware.currentText() or "").strip()
    )

    dashboard.ui.pushButton_iq_record_query.setEnabled(
        has_node
        and has_hardware
        and not bool(getattr(dashboard, "iq_record_running", False))
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_RecordPluginChanged(dashboard: QtCore.QObject):
    """Populate IQ Record actions for the selected Plugin."""
    dashboard.iq_record_customized = False
    _clear_iq_record_parameter_widgets(dashboard)
    _populate_iq_record_actions_for_plugin(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_RecordQueryClicked(dashboard: QtCore.QObject):
    """Query the selected Sensor Node for the complete IQ Record action catalog."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    hardware_display_name = str(
        dashboard.ui.comboBox_iq_record_hardware.currentText() or ""
    ).strip()

    if not node_uid:
        dashboard.logger.warning(
            "Select a Sensor Node before querying IQ Record actions."
        )
        return

    if not hardware_display_name:
        dashboard.logger.warning(
            "Select hardware before querying IQ Record actions."
        )
        return

    dashboard.iq_record_action_catalog = []
    _reset_iq_record_action_selection(dashboard)

    context = "iq.record.actions"

    dashboard.iq_record_action_query_pending = True
    dashboard.iq_record_action_query_context = context
    dashboard.iq_record_action_query_node_uid = node_uid

    dashboard.ui.pushButton_iq_record_query.setText("Querying...")
    dashboard.ui.pushButton_iq_record_query.setEnabled(False)

    await dashboard.backend.queryPluginActions(
        node_uid,
        context=context,
        scope="all_plugins",
        include_tags=["iq.record"],
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_RecordMethodChanged(
    dashboard: QtCore.QObject,
):
    """
    Update IQ Record action state after the action selection changes.
    """
    record = dashboard.ui.comboBox_iq_record_method.currentData()

    if not isinstance(record, dict):
        dashboard.iq_record_selected_plugin = ""
        dashboard.iq_record_selected_action = ""
        dashboard.ui.pushButton_iq_record_customize.setEnabled(False)
        _clear_iq_record_parameter_widgets(dashboard)
        return

    plugin_name = str(
        record.get("plugin", "")
        or ""
    ).strip()
    action_name = str(
        record.get("action", "")
        or ""
    ).strip()

    dashboard.iq_record_selected_plugin = plugin_name
    dashboard.iq_record_selected_action = action_name

    _clear_iq_record_parameter_widgets(dashboard)

    has_action = bool(
        plugin_name and action_name
    )

    dashboard.ui.pushButton_iq_record_customize.setEnabled(
        has_action
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_RecordCustomizeClicked(
    dashboard: QtCore.QObject,
):
    """
    Query the selected IQ Record action schema.
    """
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    record = dashboard.ui.comboBox_iq_record_method.currentData()

    if not node_uid:
        dashboard.logger.warning(
            "Select a Sensor Node before loading IQ Record parameters."
        )
        return

    if not isinstance(record, dict):
        dashboard.logger.warning(
            "Select an IQ Record action before loading parameters."
        )
        return

    plugin_name = str(
        record.get("plugin", "")
        or ""
    ).strip()
    action_name = str(
        record.get("action", "")
        or ""
    ).strip()

    if not plugin_name or not action_name:
        dashboard.logger.warning(
            "The selected IQ Record action is missing plugin or action information."
        )
        return

    _clear_iq_record_parameter_widgets(dashboard)

    dashboard.ui.pushButton_iq_record_customize.setText(
        "Loading..."
    )
    dashboard.ui.pushButton_iq_record_customize.setEnabled(
        False
    )

    await dashboard.backend.queryPluginActionSchema(
        node_uid,
        plugin_name,
        action_name,
        context="iq.record.schema",
    )


def handle_iq_record_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    """Cache the complete IQ Record catalog and filter it locally."""
    result_node_uid = str(node_uid or "").strip()
    result_context = str(context or "").strip()
    expected_node_uid = str(
        getattr(dashboard, "iq_record_action_query_node_uid", "") or ""
    ).strip()
    expected_context = str(
        getattr(dashboard, "iq_record_action_query_context", "") or ""
    ).strip()
    selected_node_uid = str(
        getattr(dashboard, "selected_node_uid", "") or ""
    ).strip()

    if (
        not bool(getattr(dashboard, "iq_record_action_query_pending", False))
        or result_node_uid != expected_node_uid
        or result_context != expected_context
        or result_node_uid != selected_node_uid
    ):
        dashboard.logger.debug(
            "Ignoring stale IQ Record action query results: "
            f"node_uid={result_node_uid!r}, context={result_context!r}"
        )
        return

    dashboard.iq_record_action_query_pending = False
    dashboard.iq_record_action_query_context = ""
    dashboard.iq_record_action_query_node_uid = ""

    dashboard.iq_record_action_catalog = [
        action_record
        for action_record in (actions if isinstance(actions, list) else [])
        if isinstance(action_record, dict)
    ]

    dashboard.ui.pushButton_iq_record_query.setText("Query Actions")
    _filter_iq_record_action_catalog(dashboard)

    has_hardware = bool(
        str(dashboard.ui.comboBox_iq_record_hardware.currentText() or "").strip()
    )

    dashboard.ui.pushButton_iq_record_query.setEnabled(
        bool(selected_node_uid)
        and has_hardware
        and not bool(getattr(dashboard, "iq_record_running", False))
    )


def _create_iq_record_parameter_widget(
    dashboard: QtCore.QObject,
    parameter: dict,
):
    """
    Create one editor for an IQ Record action-schema parameter.
    """
    parameter_type = str(
        parameter.get("type", "string")
        or "string"
    ).strip().lower()

    default = parameter.get("default", "")

    options = parameter.get("options", [])

    if isinstance(options, list) and options:
        widget = QtWidgets.QComboBox(
            dashboard.ui.scrollAreaWidgetContents_iq_record_parameters
        )
        widget.addItems(
            [
                str(option)
                for option in options
            ]
        )

        default_index = widget.findText(
            str(default)
        )

        if default_index >= 0:
            widget.setCurrentIndex(default_index)

        return widget

    if parameter_type == "int":
        widget = QtWidgets.QSpinBox(
            dashboard.ui.scrollAreaWidgetContents_iq_record_parameters
        )
        widget.setMinimum(
            int(parameter.get("min", -2147483647))
        )
        widget.setMaximum(
            int(parameter.get("max", 2147483647))
        )
        widget.setSingleStep(
            int(parameter.get("step", 1))
        )
        widget.setValue(
            int(default or 0)
        )
        return widget

    if parameter_type == "number":
        widget = QtWidgets.QDoubleSpinBox(
            dashboard.ui.scrollAreaWidgetContents_iq_record_parameters
        )
        widget.setDecimals(
            int(parameter.get("decimals", 6))
        )
        widget.setMinimum(
            float(parameter.get("min", -1000000000000.0))
        )
        widget.setMaximum(
            float(parameter.get("max", 1000000000000.0))
        )
        widget.setSingleStep(
            float(parameter.get("step", 1.0))
        )
        widget.setValue(
            float(default or 0.0)
        )
        return widget

    if parameter_type in {
        "bool",
        "boolean",
    }:
        widget = QtWidgets.QCheckBox(
            dashboard.ui.scrollAreaWidgetContents_iq_record_parameters
        )

        if isinstance(default, str):
            checked = default.strip().lower() in {
                "true",
                "1",
                "yes",
                "on",
                "enabled",
            }
        else:
            checked = bool(default)

        widget.setChecked(checked)
        return widget

    if parameter_type == "label":
        widget = QtWidgets.QLabel(
            str(default),
            dashboard.ui.scrollAreaWidgetContents_iq_record_parameters,
        )
        widget.setWordWrap(True)
        widget.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse
        )
        return widget

    widget = QtWidgets.QLineEdit(
        str(default),
        dashboard.ui.scrollAreaWidgetContents_iq_record_parameters,
    )
    return widget


def _iq_record_parameter_widget_value(
    widget: QtWidgets.QWidget,
):
    """
    Return the current value from one IQ Record parameter editor.
    """
    if isinstance(
        widget,
        QtWidgets.QComboBox,
    ):
        return widget.currentText()

    if isinstance(
        widget,
        QtWidgets.QDoubleSpinBox,
    ):
        return widget.value()

    if isinstance(
        widget,
        QtWidgets.QSpinBox,
    ):
        return widget.value()

    if isinstance(
        widget,
        QtWidgets.QCheckBox,
    ):
        return widget.isChecked()

    if isinstance(
        widget,
        QtWidgets.QLineEdit,
    ):
        return widget.text()

    if isinstance(
        widget,
        QtWidgets.QLabel,
    ):
        return widget.text()

    return None


def _collect_iq_record_action_parameters(
    dashboard: QtCore.QObject,
):
    """
    Collect customized IQ Record parameters and selected hardware identity.
    """
    parameters = {}

    for parameter_name, record in (
        getattr(
            dashboard,
            "iq_record_parameter_widgets",
            {},
        )
        or {}
    ).items():
        if not isinstance(record, dict):
            continue

        widget = record.get("widget")
        schema = record.get("schema", {})

        if widget is None:
            continue

        parameter_type = str(
            schema.get("type", "string")
            or "string"
        ).strip().lower()

        if parameter_type == "label":
            continue

        parameters[parameter_name] = (
            _iq_record_parameter_widget_value(
                widget
            )
        )

    hardware_display_name = str(
        dashboard.ui.comboBox_iq_record_hardware.currentText()
        or ""
    ).strip()

    (
        hardware_type,
        hardware_uuid,
        hardware_radio_name,
        hardware_serial,
        hardware_interface,
        hardware_ip,
        hardware_daughterboard,
    ) = fissure.utils.hardware.hardwareDisplayNameLookup(
        dashboard,
        hardware_display_name,
        "iq",
    )

    raw_serial_hardware = {
        "HackRF",
        "RTL2832U",
        "bladeRF",
        "bladeRF 2.0",
        "RSPduo",
        "RSPdx",
        "RSPdx R2",
    }

    zero_default_serial_hardware = {
        "RTL2832U",
        "bladeRF",
        "bladeRF 2.0",
        "RSPduo",
        "RSPdx",
        "RSPdx R2",
    }

    if hardware_serial:
        if hardware_type in raw_serial_hardware:
            hardware_serial_argument = hardware_serial
        else:
            hardware_serial_argument = (
                f"serial={hardware_serial}"
            )
    else:
        if hardware_type == "HackRF":
            hardware_serial_argument = ""
        elif hardware_type in zero_default_serial_hardware:
            hardware_serial_argument = "0"
        else:
            hardware_serial_argument = "False"

    parameters.update(
        {
            "operation_id": str(uuid.uuid4()),
            "requester": "dashboard",
            "hardware_display_name":
                hardware_display_name,
            "hardware_type":
                hardware_type,
            "hardware_uuid":
                hardware_uuid,
            "hardware_radio_name":
                hardware_radio_name,
            "hardware_serial":
                hardware_serial,
            "hardware_serial_argument":
                hardware_serial_argument,
            "hardware_interface":
                hardware_interface,
            "hardware_ip":
                hardware_ip,
            "hardware_daughterboard":
                hardware_daughterboard,
        }
    )

    if "frequency_mhz" in parameters:
        parameters["rx_frequency"] = (
            parameters["frequency_mhz"]
        )

    return parameters


def handle_iq_record_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
):
    """
    Build the IQ Record parameter panel from an action schema.
    """
    selected_node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if str(node_uid or "").strip() != selected_node_uid:
        dashboard.logger.debug(
            "Ignoring IQ Record action schema for a different Sensor Node."
        )
        return

    selected_record = dashboard.ui.comboBox_iq_record_method.currentData()

    if not isinstance(selected_record, dict):
        return

    selected_plugin = str(
        selected_record.get("plugin", "")
        or ""
    ).strip()
    selected_action = str(
        selected_record.get("action", "")
        or ""
    ).strip()

    if (
        selected_plugin != str(plugin_name or "").strip()
        or selected_action != str(action_name or "").strip()
    ):
        dashboard.logger.debug(
            "Ignoring IQ Record action schema for a different action."
        )
        return

    _clear_iq_record_parameter_widgets(dashboard)

    content = dashboard.ui.scrollAreaWidgetContents_iq_record_parameters
    layout = content.layout()

    if layout is None:
        layout = QtWidgets.QFormLayout(content)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setHorizontalSpacing(10)
        layout.setVerticalSpacing(6)
        layout.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.AllNonFixedFieldsGrow
        )

    normalized_parameters = (
        parameters
        if isinstance(parameters, list)
        else []
    )

    dashboard.iq_record_current_schema = {
        "plugin": selected_plugin,
        "action": selected_action,
        "params": normalized_parameters,
    }

    for parameter in normalized_parameters:
        if not isinstance(parameter, dict):
            continue

        name = str(
            parameter.get("name", "")
            or ""
        ).strip()

        if not name:
            continue

        label_text = str(
            parameter.get("label", name)
            or name
        )

        widget = _create_iq_record_parameter_widget(
            dashboard,
            parameter,
        )

        parameter_type = str(
            parameter.get("type", "string")
            or "string"
        ).strip().lower()

        if isinstance(
            widget,
            QtWidgets.QDoubleSpinBox,
        ):
            widget.setObjectName(
                "doubleSpinBox_iq_record_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QSpinBox,
        ):
            widget.setObjectName(
                "spinBox_iq_record_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QComboBox,
        ):
            widget.setObjectName(
                "comboBox_iq_record_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QCheckBox,
        ):
            widget.setObjectName(
                "checkBox_iq_record_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QLineEdit,
        ):
            widget.setObjectName(
                "lineEdit_iq_record_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QLabel,
        ):
            widget.setObjectName(
                "label2_iq_record_parameter_info"
            )

        dashboard.iq_record_parameter_widgets[
            name
        ] = {
            "widget": widget,
            "schema": dict(parameter),
        }

        label = QtWidgets.QLabel(
            label_text,
            content,
        )
        label.setObjectName(
            "label2_iq_record_parameter"
        )
        label.setWordWrap(True)

        layout.addRow(
            label,
            widget,
        )


    dashboard.iq_record_selected_plugin = selected_plugin
    dashboard.iq_record_selected_action = selected_action
    dashboard.iq_record_customized = True

    dashboard.ui.pushButton_iq_record_customize.setText(
        "Customize"
    )
    dashboard.ui.pushButton_iq_record_customize.setEnabled(
        True
    )
    dashboard.ui.pushButton_iq_record_start_stop.setEnabled(
        True
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_RecordDownloadArtifactClicked(
    dashboard: QtCore.QObject,
):
    """
    Download the completed IQ recording Artifact or open its verified shared
    Dashboard cache location.
    """
    artifact_id = str(
        getattr(
            dashboard,
            "iq_record_artifact_id",
            "",
        )
        or ""
    ).strip()

    if not artifact_id:
        _update_iq_record_artifact_button(
            dashboard
        )
        return

    controller = getattr(
        dashboard.backend,
        "artifact_transfer_controller",
        None,
    )

    if controller is None:
        dashboard.logger.error(
            "[IQ Record] Artifact transfer controller is unavailable."
        )
        return

    local_path = controller.get_local_path(
        artifact_id
    )

    if local_path:
        open_path = (
            local_path
            if os.path.isdir(
                local_path
            )
            else os.path.dirname(
                local_path
            )
        )

        if (
            open_path
            and os.path.isdir(
                open_path
            )
        ):
            try:
                subprocess.Popen(
                    [
                        "xdg-open",
                        open_path,
                    ]
                )

            except Exception as error:
                dashboard.logger.error(
                    "[IQ Record] Failed opening Artifact: "
                    f"{error}"
                )

        return

    button = (
        dashboard.ui.pushButton_iq_record_download_artifact
    )
    button.setText(
        "Downloading..."
    )
    button.setEnabled(
        False
    )

    try:
        dashboard.iq_record_select_after_download_id = (
            artifact_id
        )

        await (
            dashboard.backend
            .requestDashboardArtifactDownload(
                artifact_id,
                open_when_complete=False,
            )
        )

    except Exception as error:
        dashboard.logger.error(
            "[IQ Record] Artifact download request failed: "
            f"{error}"
        )

        dashboard.iq_record_select_after_download_id = ""

        _update_iq_record_artifact_button(
            dashboard
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_RecordStartStopClicked(
    dashboard: QtCore.QObject,
):
    """
    Start or stop the selected IQ Record action.
    """
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if bool(
        getattr(
            dashboard,
            "iq_record_running",
            False,
        )
    ):
        dashboard.ui.label2_iq_record_status.setText(
            "Stopping..."
        )

        try:
            await dashboard.backend.tacticalNodeStop(
                [node_uid]
            )

        except Exception as error:
            dashboard.logger.error(
                "Failed to stop IQ Record operation: "
                f"{error}"
            )

            _set_iq_record_stopped(
                dashboard,
                status_text="Stop Failed",
            )
            return

        _set_iq_record_stopped(
            dashboard,
            status_text="Stopped",
        )

        try:
            _slotIQ_ArtifactsRefreshClicked(
                dashboard
            )

        except Exception as error:
            dashboard.logger.debug(
                "Could not refresh IQ artifacts after Stop: "
                f"{error}"
            )

        return

    if not node_uid:
        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "Select a Sensor Node.",
            )
        )
        return

    if not bool(
        getattr(
            dashboard,
            "iq_record_customized",
            False,
        )
    ):
        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "Load the IQ Record parameters before recording.",
            )
        )
        return

    plugin_name = str(
        getattr(
            dashboard,
            "iq_record_selected_plugin",
            "",
        )
        or ""
    ).strip()

    action_name = str(
        getattr(
            dashboard,
            "iq_record_selected_action",
            "",
        )
        or ""
    ).strip()

    if not plugin_name or not action_name:
        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "Select an IQ Record action.",
            )
        )
        return

    try:
        parameters = (
            _collect_iq_record_action_parameters(
                dashboard
            )
        )

    except Exception as error:
        dashboard.logger.error(
            "Failed to collect IQ Record parameters: "
            f"{error}"
        )

        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "One or more IQ Record parameters are invalid.",
            )
        )
        return

    operation_id = str(
        parameters.get(
            "operation_id",
            "",
        )
        or ""
    ).strip()

    _set_iq_record_running(
        dashboard,
        node_uid=node_uid,
        operation_id=operation_id,
    )

    try:
        await dashboard.backend.tacticalNodeExecute(
            [node_uid],
            plugin_name,
            action_name,
            parameters,
        )

    except Exception:
        _set_iq_record_stopped(
            dashboard,
            status_text="Start Failed",
        )
        raise


def _update_iq_record_artifact_button(
    dashboard: QtCore.QObject,
):
    """
    Update the IQ Record Artifact ID and Download/Open button from the shared
    Dashboard Artifact cache.
    """
    artifact_id = str(
        getattr(
            dashboard,
            "iq_record_artifact_id",
            "",
        )
        or ""
    ).strip()

    artifact_label = (
        dashboard.ui.label2_iq_record_status_artifact_id
    )
    download_button = (
        dashboard.ui.pushButton_iq_record_download_artifact
    )

    artifact_label.setText(
        artifact_id
        if artifact_id
        else "—"
    )
    artifact_label.setToolTip(
        artifact_id
    )

    controller = getattr(
        dashboard.backend,
        "artifact_transfer_controller",
        None,
    )

    cached_path = (
        controller.get_local_path(
            artifact_id
        )
        if controller is not None
        and artifact_id
        else None
    )

    if cached_path:
        download_button.setText(
            "Open Artifact"
        )
        download_button.setToolTip(
            str(
                cached_path
            )
        )

    else:
        download_button.setText(
            "Download Artifact"
        )
        download_button.setToolTip(
            (
                f"Download Artifact {artifact_id}"
                if artifact_id
                else "No recording Artifact is available."
            )
        )

    download_button.setEnabled(
        bool(
            artifact_id
        )
    )

    download_button.style().unpolish(
        download_button
    )
    download_button.style().polish(
        download_button
    )
    download_button.update()


def _set_iq_record_start_stop_button(
    dashboard: QtCore.QObject,
    running: bool,
):
    """
    Update the IQ Record Card 3 button.
    """
    button = (
        dashboard.ui.pushButton_iq_record_start_stop
    )

    button.setProperty(
        "running",
        bool(running),
    )

    button.setText(
        "Stop"
        if running
        else "Record"
    )

    button.style().unpolish(
        button
    )
    button.style().polish(
        button
    )
    button.update()


def _set_iq_record_running(
    dashboard: QtCore.QObject,
    node_uid: str,
    operation_id: str,
):
    """
    Mark IQ Record active before submitting the action.
    """
    dashboard.iq_record_running = True
    dashboard.iq_record_node_uid = str(
        node_uid or ""
    )
    dashboard.iq_record_operation_id = str(
        operation_id or ""
    )

    # The new run has not produced an Artifact yet.
    dashboard.iq_record_artifact_id = ""
    _update_iq_record_artifact_button(
        dashboard
    )

    _set_iq_record_start_stop_button(
        dashboard,
        True,
    )

    dashboard.ui.label2_iq_record_status.setText(
        "Recording..."
    )

    dashboard.ui.pushButton_iq_record_start_stop.setEnabled(
        True
    )

    for widget_name in (
        "comboBox_iq_record_hardware",
        "comboBox_iq_record_plugin",
        "comboBox_iq_record_method",
        "pushButton_iq_record_query",
        "pushButton_iq_record_customize",
    ):
        widget = getattr(
            dashboard.ui,
            widget_name,
            None,
        )

        if widget is not None:
            widget.setEnabled(
                False
            )

    for parameter_record in (
        getattr(
            dashboard,
            "iq_record_parameter_widgets",
            {},
        )
        or {}
    ).values():
        if not isinstance(
            parameter_record,
            dict,
        ):
            continue

        widget = parameter_record.get(
            "widget"
        )

        if widget is not None:
            widget.setEnabled(
                False
            )


def _set_iq_record_stopped(
    dashboard: QtCore.QObject,
    status_text: str = "Idle",
):
    """
    Restore IQ Record controls after completion or Stop.
    """
    dashboard.iq_record_running = False
    dashboard.iq_record_node_uid = ""
    dashboard.iq_record_operation_id = ""

    _set_iq_record_start_stop_button(
        dashboard,
        False,
    )

    dashboard.ui.label2_iq_record_status.setText(
        str(
            status_text or "Idle"
        )
    )

    hardware_combo = dashboard.ui.comboBox_iq_record_hardware
    plugin_combo = dashboard.ui.comboBox_iq_record_plugin
    method_combo = dashboard.ui.comboBox_iq_record_method

    hardware_combo.setEnabled(
        hardware_combo.count() > 0
    )
    plugin_combo.setEnabled(
        plugin_combo.count() > 0
    )
    method_combo.setEnabled(
        method_combo.count() > 0
    )

    dashboard.ui.pushButton_iq_record_query.setEnabled(
        hardware_combo.count() > 0
    )
    dashboard.ui.pushButton_iq_record_customize.setEnabled(
        method_combo.count() > 0
    )
    dashboard.ui.pushButton_iq_record_start_stop.setEnabled(
        bool(
            getattr(
                dashboard,
                "iq_record_customized",
                False,
            )
        )
    )

    for parameter_record in (
        getattr(
            dashboard,
            "iq_record_parameter_widgets",
            {},
        )
        or {}
    ).values():
        if not isinstance(
            parameter_record,
            dict,
        ):
            continue

        widget = parameter_record.get(
            "widget"
        )

        if widget is not None:
            widget.setEnabled(
                True
            )


def _clear_iq_playback_parameter_widgets(
    dashboard: QtCore.QObject,
):
    """
    Clear the IQ Playback parameter panel and widget registry.
    """
    content = (
        dashboard.ui
        .scrollAreaWidgetContents_iq_playback_parameters
    )
    layout = content.layout()

    if layout is None:
        layout = QtWidgets.QFormLayout(
            content
        )
        layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )
        layout.setHorizontalSpacing(
            10
        )
        layout.setVerticalSpacing(
            6
        )
        layout.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.AllNonFixedFieldsGrow
        )

    else:
        while layout.count():
            item = layout.takeAt(0)

            if item.widget() is not None:
                item.widget().deleteLater()

            if item.layout() is not None:
                child_layout = item.layout()

                while child_layout.count():
                    child_item = child_layout.takeAt(0)

                    if child_item.widget() is not None:
                        child_item.widget().deleteLater()

                child_layout.deleteLater()

    dashboard.iq_playback_parameter_widgets = {}
    dashboard.iq_playback_current_schema = {}
    dashboard.iq_playback_customized = False

    dashboard.ui.pushButton_iq_playback_start_stop.setEnabled(
        False
    )


def _reset_iq_playback_action_selection(dashboard: QtCore.QObject):
    """Reset IQ Playback Plugin/Action selection and customized parameters."""
    dashboard.iq_playback_filtered_actions = []
    dashboard.iq_playback_method_actions = []
    dashboard.iq_playback_selected_plugin = ""
    dashboard.iq_playback_selected_action = ""
    dashboard.iq_playback_customized = False

    plugin_combo = dashboard.ui.comboBox_iq_playback_plugin
    action_combo = dashboard.ui.comboBox_iq_playback_method

    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.blockSignals(False)
    plugin_combo.setEnabled(False)

    action_combo.blockSignals(True)
    action_combo.clear()
    action_combo.blockSignals(False)
    action_combo.setEnabled(False)

    dashboard.ui.pushButton_iq_playback_customize.setEnabled(False)
    _clear_iq_playback_parameter_widgets(dashboard)


def _iq_playback_action_matches_hardware(hardware_type: str, compatible_hardware) -> bool:
    """Return True when an IQ Playback action supports the selected hardware."""
    compatible_hardware = list(compatible_hardware or [])

    if not compatible_hardware:
        return True

    selected = str(hardware_type or "").strip().lower()

    if not selected:
        return False

    for hardware_name in compatible_hardware:
        candidate = str(hardware_name or "").strip().lower()

        if candidate and (candidate in selected or selected in candidate):
            return True

    return False


def _populate_iq_playback_actions_for_plugin(
    dashboard: QtCore.QObject,
    preferred_action: str = "",
):
    """Populate IQ Playback Action from the selected Plugin."""
    plugin_name = str(dashboard.ui.comboBox_iq_playback_plugin.currentText() or "").strip()
    action_combo = dashboard.ui.comboBox_iq_playback_method

    action_combo.blockSignals(True)
    action_combo.clear()

    matching_actions = []

    for action_record in getattr(dashboard, "iq_playback_filtered_actions", []) or []:
        if not isinstance(action_record, dict):
            continue

        if str(action_record.get("plugin", "") or "").strip() != plugin_name:
            continue

        action_name = str(action_record.get("action", "") or "").strip()

        if not action_name:
            continue

        matching_actions.append(action_record)
        action_combo.addItem(action_name, action_record)

    action_combo.blockSignals(False)
    dashboard.iq_playback_method_actions = matching_actions

    active = bool(
        getattr(dashboard, "iq_playback_running", False)
        or getattr(dashboard, "iq_playback_start_pending", False)
    )
    has_actions = action_combo.count() > 0
    action_combo.setEnabled(has_actions and not active)

    if not has_actions:
        dashboard.iq_playback_selected_plugin = ""
        dashboard.iq_playback_selected_action = ""
        dashboard.iq_playback_customized = False
        dashboard.ui.pushButton_iq_playback_customize.setEnabled(False)
        _clear_iq_playback_parameter_widgets(dashboard)
        return

    preferred_action = str(preferred_action or "").strip()

    if preferred_action:
        preferred_index = action_combo.findText(preferred_action, QtCore.Qt.MatchExactly)

        if preferred_index >= 0:
            action_combo.setCurrentIndex(preferred_index)

    if action_combo.currentIndex() < 0:
        action_combo.setCurrentIndex(0)

    _slotIQ_PlaybackMethodChanged(dashboard)


def _filter_iq_playback_action_catalog(
    dashboard: QtCore.QObject,
    preferred_plugin: str = "",
    preferred_action: str = "",
):
    """Filter cached IQ Playback actions by Hardware, then rebuild Plugin/Action."""
    hardware_display_name = str(
        dashboard.ui.comboBox_iq_playback_hardware.currentText() or ""
    ).strip()

    dashboard.iq_playback_filter_hardware_display = hardware_display_name
    hardware_type = ""

    if hardware_display_name:
        (
            hardware_type,
            _hardware_uuid,
            _hardware_radio_name,
            _hardware_serial,
            _hardware_interface,
            _hardware_ip,
            _hardware_daughterboard,
        ) = fissure.utils.hardware.hardwareDisplayNameLookup(
            dashboard,
            hardware_display_name,
            "iq",
        )

    filtered_actions = []

    if hardware_type:
        for action_record in getattr(dashboard, "iq_playback_action_catalog", []) or []:
            if not isinstance(action_record, dict):
                continue

            plugin_name = str(action_record.get("plugin", "") or "").strip()
            action_name = str(action_record.get("action", "") or "").strip()

            if not plugin_name or not action_name:
                continue

            if not _iq_playback_action_matches_hardware(
                hardware_type,
                action_record.get("hardware", []),
            ):
                continue

            filtered_actions.append(action_record)

    dashboard.iq_playback_filtered_actions = filtered_actions

    plugin_combo = dashboard.ui.comboBox_iq_playback_plugin
    current_plugin = str(preferred_plugin or plugin_combo.currentText() or "").strip()

    plugins = sorted(
        {
            str(action_record.get("plugin", "") or "").strip()
            for action_record in filtered_actions
            if isinstance(action_record, dict)
            and str(action_record.get("plugin", "") or "").strip()
        },
        key=str.lower,
    )

    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.addItems(plugins)

    if current_plugin:
        plugin_index = plugin_combo.findText(current_plugin, QtCore.Qt.MatchExactly)

        if plugin_index >= 0:
            plugin_combo.setCurrentIndex(plugin_index)

    if plugin_combo.currentIndex() < 0 and plugin_combo.count() > 0:
        plugin_combo.setCurrentIndex(0)

    plugin_combo.blockSignals(False)

    active = bool(
        getattr(dashboard, "iq_playback_running", False)
        or getattr(dashboard, "iq_playback_start_pending", False)
    )
    plugin_combo.setEnabled(plugin_combo.count() > 0 and not active)

    dashboard.iq_playback_customized = False
    _clear_iq_playback_parameter_widgets(dashboard)
    _populate_iq_playback_actions_for_plugin(
        dashboard,
        preferred_action=preferred_action,
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlaybackActionHardwareChanged(dashboard: QtCore.QObject):
    """Refilter the cached IQ Playback catalog when TX hardware changes."""
    dashboard.iq_playback_customized = False
    _clear_iq_playback_parameter_widgets(dashboard)
    _filter_iq_playback_action_catalog(dashboard)

    has_node = bool(str(getattr(dashboard, "selected_node_uid", "") or "").strip())
    has_hardware = bool(
        str(dashboard.ui.comboBox_iq_playback_hardware.currentText() or "").strip()
    )
    active = bool(
        getattr(dashboard, "iq_playback_running", False)
        or getattr(dashboard, "iq_playback_start_pending", False)
    )

    dashboard.ui.pushButton_iq_playback_query.setEnabled(
        has_node and has_hardware and not active
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlaybackPluginChanged(dashboard: QtCore.QObject):
    """Populate IQ Playback actions for the selected Plugin."""
    dashboard.iq_playback_customized = False
    _clear_iq_playback_parameter_widgets(dashboard)
    _populate_iq_playback_actions_for_plugin(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_PlaybackQueryClicked(dashboard: QtCore.QObject):
    """Query the selected Sensor Node for the complete IQ Playback action catalog."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    hardware_display_name = str(
        dashboard.ui.comboBox_iq_playback_hardware.currentText() or ""
    ).strip()

    if not node_uid:
        dashboard.logger.warning(
            "Select a Sensor Node before querying IQ Playback actions."
        )
        return

    if not hardware_display_name:
        dashboard.logger.warning(
            "Select hardware before querying IQ Playback actions."
        )
        return

    dashboard.iq_playback_action_catalog = []
    _reset_iq_playback_action_selection(dashboard)

    context = "iq.playback.actions"

    dashboard.iq_playback_action_query_pending = True
    dashboard.iq_playback_action_query_context = context
    dashboard.iq_playback_action_query_node_uid = node_uid

    dashboard.ui.pushButton_iq_playback_query.setText("Querying...")
    dashboard.ui.pushButton_iq_playback_query.setEnabled(False)

    await dashboard.backend.queryPluginActions(
        node_uid,
        context=context,
        scope="all_plugins",
        include_tags=["iq.playback"],
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlaybackMethodChanged(
    dashboard: QtCore.QObject,
):
    """
    Update IQ Playback action state after action selection changes.
    """
    record = (
        dashboard.ui
        .comboBox_iq_playback_method
        .currentData()
    )

    if not isinstance(
        record,
        dict,
    ):
        dashboard.iq_playback_selected_plugin = ""
        dashboard.iq_playback_selected_action = ""

        dashboard.ui.pushButton_iq_playback_customize.setEnabled(
            False
        )

        _clear_iq_playback_parameter_widgets(
            dashboard
        )
        return

    plugin_name = str(
        record.get(
            "plugin",
            "",
        )
        or ""
    ).strip()

    action_name = str(
        record.get(
            "action",
            "",
        )
        or ""
    ).strip()

    dashboard.iq_playback_selected_plugin = plugin_name
    dashboard.iq_playback_selected_action = action_name

    _clear_iq_playback_parameter_widgets(
        dashboard
    )

    dashboard.ui.pushButton_iq_playback_customize.setEnabled(
        bool(
            plugin_name
            and action_name
        )
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_PlaybackCustomizeClicked(
    dashboard: QtCore.QObject,
):
    """
    Query the selected IQ Playback action schema.
    """
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    record = (
        dashboard.ui
        .comboBox_iq_playback_method
        .currentData()
    )

    if not node_uid:
        dashboard.logger.warning(
            "Select a Sensor Node before loading IQ Playback parameters."
        )
        return

    if not isinstance(
        record,
        dict,
    ):
        dashboard.logger.warning(
            "Select an IQ Playback action before loading parameters."
        )
        return

    plugin_name = str(
        record.get(
            "plugin",
            "",
        )
        or ""
    ).strip()

    action_name = str(
        record.get(
            "action",
            "",
        )
        or ""
    ).strip()

    if not plugin_name or not action_name:
        dashboard.logger.warning(
            "The selected IQ Playback action is missing plugin "
            "or action information."
        )
        return

    _clear_iq_playback_parameter_widgets(
        dashboard
    )

    dashboard.ui.pushButton_iq_playback_customize.setText(
        "Loading..."
    )
    dashboard.ui.pushButton_iq_playback_customize.setEnabled(
        False
    )

    await dashboard.backend.queryPluginActionSchema(
        node_uid,
        plugin_name,
        action_name,
        context="iq.playback.schema",
    )


def handle_iq_playback_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    """Cache the complete IQ Playback catalog and filter it locally."""
    result_node_uid = str(node_uid or "").strip()
    result_context = str(context or "").strip()
    expected_node_uid = str(
        getattr(dashboard, "iq_playback_action_query_node_uid", "") or ""
    ).strip()
    expected_context = str(
        getattr(dashboard, "iq_playback_action_query_context", "") or ""
    ).strip()
    selected_node_uid = str(
        getattr(dashboard, "selected_node_uid", "") or ""
    ).strip()

    if (
        not bool(getattr(dashboard, "iq_playback_action_query_pending", False))
        or result_node_uid != expected_node_uid
        or result_context != expected_context
        or result_node_uid != selected_node_uid
    ):
        dashboard.logger.debug(
            "Ignoring stale IQ Playback action query results: "
            f"node_uid={result_node_uid!r}, context={result_context!r}"
        )
        return

    dashboard.iq_playback_action_query_pending = False
    dashboard.iq_playback_action_query_context = ""
    dashboard.iq_playback_action_query_node_uid = ""

    dashboard.iq_playback_action_catalog = [
        action_record
        for action_record in (actions if isinstance(actions, list) else [])
        if isinstance(action_record, dict)
    ]

    dashboard.ui.pushButton_iq_playback_query.setText("Query Actions")
    _filter_iq_playback_action_catalog(dashboard)

    has_hardware = bool(
        str(dashboard.ui.comboBox_iq_playback_hardware.currentText() or "").strip()
    )
    active = bool(
        getattr(dashboard, "iq_playback_running", False)
        or getattr(dashboard, "iq_playback_start_pending", False)
    )

    dashboard.ui.pushButton_iq_playback_query.setEnabled(
        bool(selected_node_uid) and has_hardware and not active
    )


def _create_iq_playback_parameter_widget(
    dashboard: QtCore.QObject,
    parameter: dict,
):
    """
    Create one editor for an IQ Playback action-schema parameter.
    """
    parameter_type = str(
        parameter.get(
            "type",
            "string",
        )
        or "string"
    ).strip().lower()

    default = parameter.get(
        "default",
        "",
    )

    options = parameter.get(
        "options",
        [],
    )

    parent = (
        dashboard.ui
        .scrollAreaWidgetContents_iq_playback_parameters
    )

    if isinstance(
        options,
        list,
    ) and options:
        widget = QtWidgets.QComboBox(
            parent
        )

        for option in options:
            widget.addItem(
                str(option)
            )

        default_index = widget.findText(
            str(default),
            QtCore.Qt.MatchExactly,
        )

        if default_index >= 0:
            widget.setCurrentIndex(
                default_index
            )

        return widget

    if parameter_type in {
        "int",
        "integer",
    }:
        widget = QtWidgets.QSpinBox(
            parent
        )
        widget.setMinimum(
            int(
                parameter.get(
                    "min",
                    -2147483647,
                )
            )
        )
        widget.setMaximum(
            int(
                parameter.get(
                    "max",
                    2147483647,
                )
            )
        )
        widget.setSingleStep(
            int(
                parameter.get(
                    "step",
                    1,
                )
            )
        )
        widget.setValue(
            int(
                default
                or 0
            )
        )
        return widget

    if parameter_type in {
        "float",
        "double",
        "number",
    }:
        widget = QtWidgets.QDoubleSpinBox(
            parent
        )
        widget.setDecimals(
            int(
                parameter.get(
                    "decimals",
                    6,
                )
            )
        )
        widget.setMinimum(
            float(
                parameter.get(
                    "min",
                    -1000000000000.0,
                )
            )
        )
        widget.setMaximum(
            float(
                parameter.get(
                    "max",
                    1000000000000.0,
                )
            )
        )
        widget.setSingleStep(
            float(
                parameter.get(
                    "step",
                    1.0,
                )
            )
        )
        widget.setValue(
            float(
                default
                or 0.0
            )
        )
        return widget

    if parameter_type in {
        "bool",
        "boolean",
    }:
        widget = QtWidgets.QCheckBox(
            parent
        )

        if isinstance(
            default,
            str,
        ):
            checked = default.strip().lower() in {
                "true",
                "1",
                "yes",
                "on",
                "enabled",
            }

        else:
            checked = bool(
                default
            )

        widget.setChecked(
            checked
        )
        return widget

    if parameter_type == "label":
        widget = QtWidgets.QLabel(
            str(default),
            parent,
        )
        widget.setWordWrap(
            True
        )
        widget.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse
        )
        return widget

    return QtWidgets.QLineEdit(
        str(default),
        parent,
    )


def _iq_playback_parameter_widget_value(
    widget: QtWidgets.QWidget,
):
    """
    Return the current value from one IQ Playback parameter editor.
    """
    if isinstance(
        widget,
        QtWidgets.QComboBox,
    ):
        return widget.currentText()

    if isinstance(
        widget,
        QtWidgets.QDoubleSpinBox,
    ):
        return widget.value()

    if isinstance(
        widget,
        QtWidgets.QSpinBox,
    ):
        return widget.value()

    if isinstance(
        widget,
        QtWidgets.QCheckBox,
    ):
        return widget.isChecked()

    if isinstance(
        widget,
        QtWidgets.QLineEdit,
    ):
        return widget.text()

    if isinstance(
        widget,
        QtWidgets.QLabel,
    ):
        return widget.text()

    return None


def _collect_iq_playback_action_parameters(
    dashboard: QtCore.QObject,
):
    """
    Collect customized IQ Playback parameters, selected hardware identity,
    and the currently entered playback filepath.
    """
    parameters = {}

    for parameter_name, record in (
        getattr(
            dashboard,
            "iq_playback_parameter_widgets",
            {},
        )
        or {}
    ).items():
        if not isinstance(
            record,
            dict,
        ):
            continue

        widget = record.get(
            "widget"
        )
        schema = record.get(
            "schema",
            {},
        )

        if widget is None:
            continue

        parameter_type = str(
            schema.get(
                "type",
                "string",
            )
            or "string"
        ).strip().lower()

        if parameter_type == "label":
            continue

        parameters[
            parameter_name
        ] = _iq_playback_parameter_widget_value(
            widget
        )

    hardware_display_name = str(
        dashboard.ui
        .comboBox_iq_playback_hardware
        .currentText()
        or ""
    ).strip()

    (
        hardware_type,
        hardware_uuid,
        hardware_radio_name,
        hardware_serial,
        hardware_interface,
        hardware_ip,
        hardware_daughterboard,
    ) = fissure.utils.hardware.hardwareDisplayNameLookup(
        dashboard,
        hardware_display_name,
        "iq",
    )

    raw_serial_hardware = {
        "HackRF",
        "RTL2832U",
        "bladeRF",
        "bladeRF 2.0",
        "RSPduo",
        "RSPdx",
        "RSPdx R2",
    }

    zero_default_serial_hardware = {
        "RTL2832U",
        "bladeRF",
        "bladeRF 2.0",
        "RSPduo",
        "RSPdx",
        "RSPdx R2",
    }

    if hardware_serial:
        if hardware_type in raw_serial_hardware:
            hardware_serial_argument = hardware_serial

        else:
            hardware_serial_argument = (
                f"serial={hardware_serial}"
            )

    else:
        if hardware_type == "HackRF":
            hardware_serial_argument = ""

        elif hardware_type in zero_default_serial_hardware:
            hardware_serial_argument = "0"

        else:
            hardware_serial_argument = "False"

    filepath = str(
        dashboard.ui
        .textEdit_iq_playback_filepath
        .toPlainText()
        or ""
    ).strip()

    parameters.update(
        {
            "operation_id": str(
                uuid.uuid4()
            ),
            "requester": "dashboard",
            "filepath":
                filepath,
            "hardware_display_name":
                hardware_display_name,
            "hardware_type":
                hardware_type,
            "hardware_uuid":
                hardware_uuid,
            "hardware_radio_name":
                hardware_radio_name,
            "hardware_serial":
                hardware_serial,
            "hardware_serial_argument":
                hardware_serial_argument,
            "hardware_interface":
                hardware_interface,
            "hardware_ip":
                hardware_ip,
            "hardware_daughterboard":
                hardware_daughterboard,
        }
    )

    return parameters


def handle_iq_playback_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
):
    """
    Build the IQ Playback parameter panel from an action schema.
    """
    selected_node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if str(
        node_uid
        or ""
    ).strip() != selected_node_uid:
        dashboard.logger.debug(
            "Ignoring IQ Playback action schema for a different Sensor Node."
        )
        return

    selected_record = (
        dashboard.ui
        .comboBox_iq_playback_method
        .currentData()
    )

    if not isinstance(
        selected_record,
        dict,
    ):
        return

    selected_plugin = str(
        selected_record.get(
            "plugin",
            "",
        )
        or ""
    ).strip()

    selected_action = str(
        selected_record.get(
            "action",
            "",
        )
        or ""
    ).strip()

    if (
        selected_plugin != str(
            plugin_name
            or ""
        ).strip()
        or selected_action != str(
            action_name
            or ""
        ).strip()
    ):
        dashboard.logger.debug(
            "Ignoring IQ Playback action schema for a different action."
        )
        return

    _clear_iq_playback_parameter_widgets(
        dashboard
    )

    content = (
        dashboard.ui
        .scrollAreaWidgetContents_iq_playback_parameters
    )
    layout = content.layout()

    if layout is None:
        layout = QtWidgets.QFormLayout(
            content
        )
        layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )
        layout.setHorizontalSpacing(
            10
        )
        layout.setVerticalSpacing(
            6
        )
        layout.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.AllNonFixedFieldsGrow
        )

    normalized_parameters = (
        parameters
        if isinstance(
            parameters,
            list,
        )
        else []
    )

    dashboard.iq_playback_current_schema = {
        "plugin":
            selected_plugin,
        "action":
            selected_action,
        "params":
            normalized_parameters,
    }

    for parameter in normalized_parameters:
        if not isinstance(
            parameter,
            dict,
        ):
            continue

        name = str(
            parameter.get(
                "name",
                "",
            )
            or ""
        ).strip()

        if not name:
            continue

        label_text = str(
            parameter.get(
                "label",
                name,
            )
            or name
        )

        widget = _create_iq_playback_parameter_widget(
            dashboard,
            parameter,
        )

        parameter_type = str(
            parameter.get(
                "type",
                "string",
            )
            or "string"
        ).strip().lower()

        if isinstance(
            widget,
            QtWidgets.QDoubleSpinBox,
        ):
            widget.setObjectName(
                "doubleSpinBox_iq_playback_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QSpinBox,
        ):
            widget.setObjectName(
                "spinBox_iq_playback_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QComboBox,
        ):
            widget.setObjectName(
                "comboBox_iq_playback_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QCheckBox,
        ):
            widget.setObjectName(
                "checkBox_iq_playback_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QLineEdit,
        ):
            widget.setObjectName(
                "lineEdit_iq_playback_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QLabel,
        ):
            widget.setObjectName(
                "label2_iq_playback_parameter_info"
            )

        dashboard.iq_playback_parameter_widgets[
            name
        ] = {
            "widget":
                widget,
            "schema":
                dict(
                    parameter
                ),
        }

        label = QtWidgets.QLabel(
            label_text,
            content,
        )
        label.setObjectName(
            "label2_iq_playback_parameter"
        )
        label.setWordWrap(
            True
        )

        layout.addRow(
            label,
            widget,
        )

    dashboard.iq_playback_selected_plugin = selected_plugin
    dashboard.iq_playback_selected_action = selected_action
    dashboard.iq_playback_customized = True

    dashboard.ui.pushButton_iq_playback_customize.setText(
        "Customize"
    )
    dashboard.ui.pushButton_iq_playback_customize.setEnabled(
        True
    )

    dashboard.ui.pushButton_iq_playback_start_stop.setEnabled(
        True
    )

    dashboard.ui.label2_iq_playback_status.setText(
        "Idle"
    )


def _set_iq_playback_start_stop_button(
    dashboard: QtCore.QObject,
    running: bool,
):
    """
    Update the IQ Playback Card 3 Play/Stop button.
    """
    button = (
        dashboard.ui.pushButton_iq_playback_start_stop
    )

    button.setProperty(
        "running",
        bool(running),
    )

    button.setText(
        "Stop"
        if running
        else "Play"
    )

    button.style().unpolish(
        button
    )
    button.style().polish(
        button
    )
    button.update()


def _set_iq_playback_stopped(
    dashboard: QtCore.QObject,
    status_text: str = "Idle",
):
    """
    Restore IQ Playback controls after Stop or natural completion.
    """
    dashboard.iq_playback_running = False
    dashboard.iq_playback_start_pending = False
    dashboard.iq_playback_node_uid = ""
    dashboard.iq_playback_operation_id = ""

    _set_iq_playback_start_stop_button(
        dashboard,
        False,
    )

    # Let the existing selected-node gate restore enabled/disabled controls.
    update_iq_playback_selected_node_gate(
        dashboard
    )

    # The gate may establish Idle/Unavailable. Apply the actual completion
    # result after it so the user can see how the last run ended.
    selected_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if selected_uid:
        dashboard.ui.label2_iq_playback_status.setText(
            status_text
        )


def update_iq_playback_status_from_selected_node(
    dashboard: QtCore.QObject,
    node_uid: str,
    status: str,
):
    """
    Update IQ Playback Card 3 from the selected Sensor Node status.

    Natural completion matters for single-shot playback because there is no
    manual Stop request for the Dashboard to await.
    """
    if not bool(
        getattr(
            dashboard,
            "iq_playback_running",
            False,
        )
    ):
        return

    tracked_node_uid = str(
        getattr(
            dashboard,
            "iq_playback_node_uid",
            "",
        )
        or ""
    ).strip()

    node_uid_text = str(
        node_uid
        or ""
    ).strip()

    if (
        tracked_node_uid
        and node_uid_text
        and tracked_node_uid != node_uid_text
        and not tracked_node_uid.endswith(
            node_uid_text
        )
        and not node_uid_text.endswith(
            tracked_node_uid
        )
    ):
        return

    parameters = (
        getattr(
            dashboard,
            "iq_playback_pending_parameters",
            {},
        )
        or {}
    )

    playback_mode = str(
        parameters.get(
            "playback_mode",
            "",
        )
        or ""
    ).strip().lower()

    # Continuous playback is intentionally stopped by the operator.
    # Its UI is already restored locally after tacticalNodeStop() returns.
    if playback_mode != "single":
        return

    status_text = str(
        status
        or ""
    ).strip()

    if status_text == "Idle":
        _set_iq_playback_stopped(
            dashboard,
            status_text="Completed",
        )
        return

    if status_text == "Error":
        _set_iq_playback_stopped(
            dashboard,
            status_text="Error",
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_PlaybackStartStopClicked(
    dashboard: QtCore.QObject,
):
    """
    Start or stop the selected IQ Playback plugin action.
    """
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    running = bool(
        getattr(
            dashboard,
            "iq_playback_running",
            False,
        )
    )

    start_pending = bool(
        getattr(
            dashboard,
            "iq_playback_start_pending",
            False,
        )
    )

    # ------------------------------------------------------------------
    # Stop
    # ------------------------------------------------------------------
    if running or start_pending:
        tracked_node_uid = str(
            getattr(
                dashboard,
                "iq_playback_node_uid",
                "",
            )
            or node_uid
            or ""
        ).strip()

        if not tracked_node_uid:
            return

        dashboard.ui.label2_iq_playback_status.setText(
            "Stopping..."
        )
        dashboard.ui.pushButton_iq_playback_start_stop.setEnabled(
            False
        )

        try:
            await dashboard.backend.tacticalNodeStop(
                [tracked_node_uid]
            )

        except Exception as error:
            dashboard.logger.error(
                "Failed to stop IQ Playback operation: "
                f"{error}"
            )

            dashboard.ui.label2_iq_playback_status.setText(
                "Stop Failed"
            )
            dashboard.ui.pushButton_iq_playback_start_stop.setEnabled(
                True
            )
            return

        _set_iq_playback_stopped(
            dashboard,
            status_text="Stopped",
        )
        return

    # ------------------------------------------------------------------
    # Validate Start
    # ------------------------------------------------------------------
    if not node_uid:
        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "Select a Sensor Node.",
            )
        )
        return

    if not bool(
        getattr(
            dashboard,
            "iq_playback_customized",
            False,
        )
    ):
        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "Load the IQ Playback parameters before playing.",
            )
        )
        return

    plugin_name = str(
        getattr(
            dashboard,
            "iq_playback_selected_plugin",
            "",
        )
        or ""
    ).strip()

    action_name = str(
        getattr(
            dashboard,
            "iq_playback_selected_action",
            "",
        )
        or ""
    ).strip()

    if not plugin_name or not action_name:
        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "Select an IQ Playback action.",
            )
        )
        return

    filepath = str(
        dashboard.ui
        .textEdit_iq_playback_filepath
        .toPlainText()
        or ""
    ).strip()

    if not filepath:
        dashboard.ui.label2_iq_playback_status.setText(
            "File Required"
        )

        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "Select or enter an IQ playback filepath.",
            )
        )
        return

    try:
        parameters = (
            _collect_iq_playback_action_parameters(
                dashboard
            )
        )

    except Exception as error:
        dashboard.logger.error(
            "Failed to collect IQ Playback parameters: "
            f"{error}"
        )

        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "One or more IQ Playback parameters are invalid.",
            )
        )
        return

    dashboard.iq_playback_pending_parameters = dict(
        parameters
    )
    dashboard.iq_playback_start_pending = True
    dashboard.iq_playback_running = False
    dashboard.iq_playback_node_uid = node_uid

    # This is the request-side operation ID. The Sensor Node operation
    # framework has its own authoritative opid, which is captured from the
    # operation-started callback below.
    dashboard.iq_playback_operation_id = ""

    _set_iq_playback_start_stop_button(
        dashboard,
        True,
    )

    dashboard.ui.label2_iq_playback_status.setText(
        "Starting..."
    )

    # Disable Setup, Parameters, and filepath while starting/running.
    dashboard.ui.comboBox_iq_playback_hardware.setEnabled(False)
    dashboard.ui.comboBox_iq_playback_plugin.setEnabled(False)
    dashboard.ui.comboBox_iq_playback_method.setEnabled(False)
    dashboard.ui.pushButton_iq_playback_query.setEnabled(False)
    dashboard.ui.pushButton_iq_playback_customize.setEnabled(False)
    dashboard.ui.textEdit_iq_playback_filepath.setEnabled(False)

    for parameter_record in (
        getattr(
            dashboard,
            "iq_playback_parameter_widgets",
            {},
        )
        or {}
    ).values():
        if not isinstance(
            parameter_record,
            dict,
        ):
            continue

        widget = parameter_record.get(
            "widget"
        )

        if widget is not None:
            widget.setEnabled(
                False
            )

    # Stop should be available immediately, including during startup.
    dashboard.ui.pushButton_iq_playback_start_stop.setEnabled(
        True
    )

    dashboard.logger.info(
        "Starting IQ Playback: "
        f"plugin={plugin_name}, "
        f"action={action_name}, "
        f"node_uid={node_uid}, "
        f"filepath={filepath}"
    )

    try:
        await dashboard.backend.tacticalNodeExecute(
            [node_uid],
            plugin_name,
            action_name,
            parameters,
        )

    except Exception as error:
        dashboard.logger.error(
            "Failed to start IQ Playback operation: "
            f"{error}"
        )

        _set_iq_playback_stopped(
            dashboard,
            status_text="Start Failed",
        )
        return

    dashboard.iq_playback_start_pending = False
    dashboard.iq_playback_running = True

    dashboard.ui.label2_iq_playback_status.setText(
        "Playing..."
    )

    _set_iq_playback_start_stop_button(
        dashboard,
        True,
    )
    

def initialize_iq_playback_controls(
    dashboard: QtCore.QObject,
):
    """
    Initialize IQ Playback controls.
    """
    dashboard.iq_playback_running = False
    dashboard.iq_playback_start_pending = False
    dashboard.iq_playback_node_uid = ""
    dashboard.iq_playback_operation_id = ""
    dashboard.iq_playback_pending_parameters = {}

    dashboard.iq_playback_action_catalog = []
    dashboard.iq_playback_filtered_actions = []
    dashboard.iq_playback_action_catalog_node_uid = ""
    dashboard.iq_playback_filter_hardware_display = ""
    dashboard.iq_playback_method_actions = []
    dashboard.iq_playback_selected_plugin = ""
    dashboard.iq_playback_selected_action = ""
    dashboard.iq_playback_parameter_widgets = {}
    dashboard.iq_playback_current_schema = {}
    dashboard.iq_playback_customized = False

    dashboard.iq_playback_action_query_pending = False
    dashboard.iq_playback_action_query_context = ""
    dashboard.iq_playback_action_query_node_uid = ""

    dashboard.ui.stackedWidget_iq_playback.setCurrentWidget(
        dashboard.ui.page_iq_playback_no_node
    )

    select_node_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "select_node.png",
    )

    if os.path.isfile(
        select_node_icon_path
    ):
        select_node_pixmap = QtGui.QPixmap(
            select_node_icon_path
        )

        dashboard.ui.label_iq_playback_select_sensor_node_image.setPixmap(
            select_node_pixmap
        )
        dashboard.ui.label_iq_playback_select_sensor_node_image.setScaledContents(
            False
        )
        dashboard.ui.label_iq_playback_select_sensor_node_image.setAlignment(
            QtCore.Qt.AlignCenter
        )

    dashboard.ui.comboBox_iq_playback_plugin.clear()
    dashboard.ui.comboBox_iq_playback_plugin.setEnabled(False)

    dashboard.ui.comboBox_iq_playback_method.clear()
    dashboard.ui.comboBox_iq_playback_method.setEnabled(
        False
    )

    dashboard.ui.pushButton_iq_playback_query.setText(
        "Query Actions"
    )
    dashboard.ui.pushButton_iq_playback_query.setEnabled(
        False
    )

    dashboard.ui.pushButton_iq_playback_customize.setText(
        "Customize"
    )
    dashboard.ui.pushButton_iq_playback_customize.setEnabled(
        False
    )

    dashboard.ui.pushButton_iq_playback_start_stop.setText(
        "Play"
    )
    dashboard.ui.pushButton_iq_playback_start_stop.setEnabled(
        False
    )
    dashboard.ui.pushButton_iq_playback_start_stop.setProperty(
        "running",
        False,
    )

    dashboard.ui.label2_iq_playback_status.setText(
        "Unavailable"
    )

    dashboard.ui.textEdit_iq_playback_filepath.setReadOnly(
        False
    )

    scroll_area = getattr(
        dashboard.ui,
        "scrollArea_iq_playback_parameters",
        None,
    )

    if scroll_area is not None:
        scroll_area.setHorizontalScrollBarPolicy(
            QtCore.Qt.ScrollBarAlwaysOff
        )
        scroll_area.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarAsNeeded
        )

        parameter_widgets = [
            scroll_area,
            scroll_area.viewport(),
            scroll_area.widget(),
        ]

        for widget in parameter_widgets:
            if widget is None:
                continue

            widget.setProperty(
                "uiRole",
                "parameterPanel",
            )
            widget.style().unpolish(
                widget
            )
            widget.style().polish(
                widget
            )
            widget.update()

    _clear_iq_playback_parameter_widgets(
        dashboard
    )

    update_iq_playback_selected_node_gate(
        dashboard
    )


def update_iq_playback_selected_node_gate(dashboard: QtCore.QObject):
    """
    Show IQ Playback controls only for an online selected Sensor Node and keep
    the cached action catalog owned by the correct node/hardware selection.
    """
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    has_selected_node = bool(selected_uid)

    if has_selected_node:
        node_state = (getattr(dashboard, "node_states", {}) or {}).get(selected_uid)

        if isinstance(node_state, dict) and node_state.get("connected") is False:
            has_selected_node = False

    dashboard.ui.stackedWidget_iq_playback.setCurrentWidget(
        dashboard.ui.page_iq_playback_controls
        if has_selected_node
        else dashboard.ui.page_iq_playback_no_node
    )

    hardware_combo = dashboard.ui.comboBox_iq_playback_hardware
    plugin_combo = dashboard.ui.comboBox_iq_playback_plugin
    method_combo = dashboard.ui.comboBox_iq_playback_method
    query_button = dashboard.ui.pushButton_iq_playback_query
    customize_button = dashboard.ui.pushButton_iq_playback_customize
    start_button = dashboard.ui.pushButton_iq_playback_start_stop
    filepath_edit = dashboard.ui.textEdit_iq_playback_filepath

    catalog_node_uid = str(
        getattr(dashboard, "iq_playback_action_catalog_node_uid", "") or ""
    ).strip()
    node_changed = selected_uid != catalog_node_uid

    if node_changed:
        dashboard.iq_playback_action_catalog_node_uid = selected_uid
        dashboard.iq_playback_action_catalog = []
        dashboard.iq_playback_filter_hardware_display = ""
        dashboard.iq_playback_action_query_pending = False
        dashboard.iq_playback_action_query_context = ""
        dashboard.iq_playback_action_query_node_uid = ""
        query_button.setText("Query Actions")
        _reset_iq_playback_action_selection(dashboard)

        if not bool(
            getattr(dashboard, "iq_playback_running", False)
            or getattr(dashboard, "iq_playback_start_pending", False)
        ):
            dashboard.ui.label2_iq_playback_status.setText(
                "Idle" if has_selected_node else "Unavailable"
            )

    current_hardware = str(hardware_combo.currentText() or "").strip()
    filtered_hardware = str(
        getattr(dashboard, "iq_playback_filter_hardware_display", "") or ""
    ).strip()

    active = bool(
        getattr(dashboard, "iq_playback_running", False)
        or getattr(dashboard, "iq_playback_start_pending", False)
    )

    if current_hardware != filtered_hardware and not active:
        dashboard.iq_playback_customized = False
        _clear_iq_playback_parameter_widgets(dashboard)
        _filter_iq_playback_action_catalog(dashboard)

    if active:
        hardware_combo.setEnabled(False)
        plugin_combo.setEnabled(False)
        method_combo.setEnabled(False)
        query_button.setEnabled(False)
        customize_button.setEnabled(False)
        filepath_edit.setEnabled(False)
        start_button.setEnabled(True)

        for parameter_record in (
            getattr(dashboard, "iq_playback_parameter_widgets", {}) or {}
        ).values():
            if not isinstance(parameter_record, dict):
                continue

            widget = parameter_record.get("widget")

            if widget is not None:
                widget.setEnabled(False)

        return

    _set_iq_playback_start_stop_button(dashboard, False)

    hardware_combo.setEnabled(
        has_selected_node and hardware_combo.count() > 0
    )
    plugin_combo.setEnabled(
        has_selected_node and plugin_combo.count() > 0
    )
    method_combo.setEnabled(
        has_selected_node and method_combo.count() > 0
    )
    query_button.setEnabled(
        has_selected_node
        and hardware_combo.count() > 0
        and not bool(getattr(dashboard, "iq_playback_action_query_pending", False))
    )
    customize_button.setEnabled(
        has_selected_node and method_combo.count() > 0
    )
    filepath_edit.setEnabled(has_selected_node)
    filepath_edit.setReadOnly(False)
    start_button.setEnabled(
        has_selected_node
        and bool(getattr(dashboard, "iq_playback_customized", False))
    )

    current_status = str(
        dashboard.ui.label2_iq_playback_status.text() or ""
    ).strip()

    if not has_selected_node:
        dashboard.ui.label2_iq_playback_status.setText("Unavailable")
    elif current_status in {"", "Unavailable"}:
        dashboard.ui.label2_iq_playback_status.setText("Idle")

    for parameter_record in (
        getattr(dashboard, "iq_playback_parameter_widgets", {}) or {}
    ).values():
        if not isinstance(parameter_record, dict):
            continue

        widget = parameter_record.get("widget")

        if widget is not None:
            widget.setEnabled(has_selected_node)


def _clear_iq_inspection_parameter_widgets(
    dashboard,
):
    """Clear the IQ Inspection parameter panel and widget registry."""
    content = (
        dashboard.ui
        .scrollAreaWidgetContents_iq_inspection_parameters
    )
    layout = content.layout()

    if layout is None:
        layout = QtWidgets.QFormLayout(
            content
        )
        layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )
        layout.setHorizontalSpacing(
            10
        )
        layout.setVerticalSpacing(
            6
        )
        layout.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.AllNonFixedFieldsGrow
        )

    else:
        while layout.count():
            item = layout.takeAt(0)

            if item.widget() is not None:
                item.widget().deleteLater()

            if item.layout() is not None:
                child_layout = item.layout()

                while child_layout.count():
                    child_item = child_layout.takeAt(0)

                    if child_item.widget() is not None:
                        child_item.widget().deleteLater()

                child_layout.deleteLater()

    dashboard.iq_inspection_parameter_widgets = {}
    dashboard.iq_inspection_current_schema = {}
    dashboard.iq_inspection_customized = False

    dashboard.ui.pushButton_iq_inspection_start_stop.setEnabled(
        False
    )


def _reset_iq_inspection_action_selection(dashboard):
    """Reset IQ Inspection Plugin/Action selection and customized parameters."""
    dashboard.iq_inspection_filtered_actions = []
    dashboard.iq_inspection_method_actions = []
    dashboard.iq_inspection_selected_plugin = ""
    dashboard.iq_inspection_selected_action = ""
    dashboard.iq_inspection_customized = False

    plugin_combo = dashboard.ui.comboBox_iq_inspection_plugin
    action_combo = dashboard.ui.comboBox_iq_inspection_action

    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.blockSignals(False)
    plugin_combo.setEnabled(False)

    action_combo.blockSignals(True)
    action_combo.clear()
    action_combo.blockSignals(False)
    action_combo.setEnabled(False)

    dashboard.ui.pushButton_iq_inspection_customize.setEnabled(False)
    _clear_iq_inspection_parameter_widgets(dashboard)


def _iq_inspection_action_tags(action_record: dict) -> set:
    """Return normalized tags for one IQ Inspection action record."""
    tags = action_record.get("tags", []) if isinstance(action_record, dict) else []

    if not isinstance(tags, (list, tuple, set)):
        tags = [tags]

    return {
        str(tag or "").strip().lower()
        for tag in tags
        if str(tag or "").strip()
    }


def _iq_inspection_action_matches_hardware(hardware_type: str, compatible_hardware) -> bool:
    """Return True when a live IQ Inspection action supports selected hardware."""
    compatible_hardware = list(compatible_hardware or [])

    if not compatible_hardware:
        return True

    selected = str(hardware_type or "").strip().lower()

    if not selected:
        return False

    for hardware_name in compatible_hardware:
        candidate = str(hardware_name or "").strip().lower()

        if candidate and (candidate in selected or selected in candidate):
            return True

    return False


def _populate_iq_inspection_actions_for_plugin(
    dashboard,
    preferred_action: str = "",
):
    """Populate IQ Inspection Action from the selected Plugin."""
    plugin_name = str(
        dashboard.ui.comboBox_iq_inspection_plugin.currentText() or ""
    ).strip()
    action_combo = dashboard.ui.comboBox_iq_inspection_action

    action_combo.blockSignals(True)
    action_combo.clear()

    matching_actions = []

    for action_record in getattr(dashboard, "iq_inspection_filtered_actions", []) or []:
        if not isinstance(action_record, dict):
            continue

        if str(action_record.get("plugin", "") or "").strip() != plugin_name:
            continue

        action_name = str(action_record.get("action", "") or "").strip()

        if not action_name:
            continue

        matching_actions.append(action_record)
        action_combo.addItem(action_name, action_record)

    action_combo.blockSignals(False)
    dashboard.iq_inspection_method_actions = matching_actions

    active = bool(
        getattr(dashboard, "iq_inspection_running", False)
        or getattr(dashboard, "iq_inspection_start_pending", False)
    )
    local_available = selected_node_is_local(dashboard)
    has_actions = action_combo.count() > 0
    action_combo.setEnabled(has_actions and local_available and not active)

    if not has_actions:
        dashboard.iq_inspection_selected_plugin = ""
        dashboard.iq_inspection_selected_action = ""
        dashboard.iq_inspection_customized = False
        dashboard.ui.pushButton_iq_inspection_customize.setEnabled(False)
        _clear_iq_inspection_parameter_widgets(dashboard)
        return

    preferred_action = str(preferred_action or "").strip()

    if preferred_action:
        preferred_index = action_combo.findText(preferred_action, QtCore.Qt.MatchExactly)

        if preferred_index >= 0:
            action_combo.setCurrentIndex(preferred_index)

    if action_combo.currentIndex() < 0:
        action_combo.setCurrentIndex(0)

    _slotIQ_InspectionActionChanged(dashboard)


def _filter_iq_inspection_action_catalog(
    dashboard,
    preferred_plugin: str = "",
    preferred_action: str = "",
):
    """Filter cached IQ Inspection actions by Source, then rebuild Plugin/Action."""
    source_text = str(
        dashboard.ui.comboBox_iq_inspection_source.currentText() or ""
    ).strip()

    dashboard.iq_inspection_filter_source = source_text

    source_is_file = source_text.lower() == "file"
    hardware_type = ""

    if source_text and not source_is_file:
        (
            hardware_type,
            _hardware_uuid,
            _hardware_radio_name,
            _hardware_serial,
            _hardware_interface,
            _hardware_ip,
            _hardware_daughterboard,
        ) = fissure.utils.hardware.hardwareDisplayNameLookup(
            dashboard,
            source_text,
            "iq",
        )

    filtered_actions = []

    for action_record in getattr(dashboard, "iq_inspection_action_catalog", []) or []:
        if not isinstance(action_record, dict):
            continue

        plugin_name = str(action_record.get("plugin", "") or "").strip()
        action_name = str(action_record.get("action", "") or "").strip()

        if not plugin_name or not action_name:
            continue

        tags = _iq_inspection_action_tags(action_record)

        if source_is_file:
            if "iq.inspection.source.file" not in tags:
                continue

        else:
            if not hardware_type:
                continue

            if "iq.inspection.source.radio" not in tags:
                continue

            if not _iq_inspection_action_matches_hardware(
                hardware_type,
                action_record.get("hardware", []),
            ):
                continue

        filtered_actions.append(action_record)

    dashboard.iq_inspection_filtered_actions = filtered_actions

    plugin_combo = dashboard.ui.comboBox_iq_inspection_plugin
    current_plugin = str(preferred_plugin or plugin_combo.currentText() or "").strip()

    plugins = sorted(
        {
            str(action_record.get("plugin", "") or "").strip()
            for action_record in filtered_actions
            if isinstance(action_record, dict)
            and str(action_record.get("plugin", "") or "").strip()
        },
        key=str.lower,
    )

    plugin_combo.blockSignals(True)
    plugin_combo.clear()
    plugin_combo.addItems(plugins)

    if current_plugin:
        plugin_index = plugin_combo.findText(current_plugin, QtCore.Qt.MatchExactly)

        if plugin_index >= 0:
            plugin_combo.setCurrentIndex(plugin_index)

    if plugin_combo.currentIndex() < 0 and plugin_combo.count() > 0:
        plugin_combo.setCurrentIndex(0)

    plugin_combo.blockSignals(False)

    active = bool(
        getattr(dashboard, "iq_inspection_running", False)
        or getattr(dashboard, "iq_inspection_start_pending", False)
    )
    plugin_combo.setEnabled(
        plugin_combo.count() > 0
        and selected_node_is_local(dashboard)
        and not active
    )

    dashboard.iq_inspection_customized = False
    _clear_iq_inspection_parameter_widgets(dashboard)
    _populate_iq_inspection_actions_for_plugin(
        dashboard,
        preferred_action=preferred_action,
    )


def _iq_inspection_source_is_file(
    dashboard,
):
    """Return True when the Inspection Source selector is set to File."""
    return (
        str(
            dashboard.ui
            .comboBox_iq_inspection_source
            .currentText()
            or ""
        ).strip().lower()
        == "file"
    )


def _update_iq_inspection_source_ui(
    dashboard,
):
    """Show the Run-card filepath only for File inspection."""
    is_file = _iq_inspection_source_is_file(
        dashboard
    )

    dashboard.ui.label2_iq_inspection_filepath_label.setVisible(
        is_file
    )
    dashboard.ui.textEdit_iq_inspection_filepath.setVisible(
        is_file
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_InspectionSourceChanged(dashboard):
    """Refilter cached IQ Inspection actions when Source changes."""
    dashboard.iq_inspection_customized = False
    _clear_iq_inspection_parameter_widgets(dashboard)
    _update_iq_inspection_source_ui(dashboard)
    _filter_iq_inspection_action_catalog(dashboard)

    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    has_source = bool(
        str(dashboard.ui.comboBox_iq_inspection_source.currentText() or "").strip()
    )
    active = bool(
        getattr(dashboard, "iq_inspection_running", False)
        or getattr(dashboard, "iq_inspection_start_pending", False)
    )

    dashboard.ui.pushButton_iq_inspection_query.setEnabled(
        bool(
            node_uid
            and selected_node_is_local(dashboard)
            and has_source
            and not active
        )
    )

    if node_uid and selected_node_is_local(dashboard) and not active:
        dashboard.ui.label2_iq_inspection_status.setText("Idle")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_InspectionPluginChanged(dashboard):
    """Populate IQ Inspection actions for the selected Plugin."""
    dashboard.iq_inspection_customized = False
    _clear_iq_inspection_parameter_widgets(dashboard)
    _populate_iq_inspection_actions_for_plugin(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_InspectionQueryClicked(dashboard):
    """Query the local Sensor Node for the complete IQ Inspection action catalog."""
    node_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    source_text = str(
        dashboard.ui.comboBox_iq_inspection_source.currentText() or ""
    ).strip()

    if not node_uid:
        dashboard.logger.warning(
            "Select a Sensor Node before querying IQ Inspection actions."
        )
        return

    if not selected_node_is_local(dashboard):
        dashboard.logger.warning(
            "IQ Inspection GUI actions currently require a local Sensor Node."
        )
        return

    if not source_text:
        dashboard.logger.warning(
            "Select an IQ Inspection source before querying actions."
        )
        return

    dashboard.iq_inspection_action_catalog = []
    _reset_iq_inspection_action_selection(dashboard)

    context = "iq.inspection.actions"

    dashboard.iq_inspection_action_query_pending = True
    dashboard.iq_inspection_action_query_context = context
    dashboard.iq_inspection_action_query_node_uid = node_uid

    dashboard.ui.pushButton_iq_inspection_query.setText("Querying...")
    dashboard.ui.pushButton_iq_inspection_query.setEnabled(False)

    await dashboard.backend.queryPluginActions(
        node_uid,
        context=context,
        scope="all_plugins",
        include_tags=["iq.inspection"],
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_InspectionActionChanged(
    dashboard,
):
    """Update IQ Inspection action state after action selection changes."""
    record = (
        dashboard.ui
        .comboBox_iq_inspection_action
        .currentData()
    )

    if not isinstance(
        record,
        dict,
    ):
        dashboard.iq_inspection_selected_plugin = ""
        dashboard.iq_inspection_selected_action = ""

        dashboard.ui.pushButton_iq_inspection_customize.setEnabled(
            False
        )

        _clear_iq_inspection_parameter_widgets(
            dashboard
        )
        return

    plugin_name = str(
        record.get(
            "plugin",
            "",
        )
        or ""
    ).strip()

    action_name = str(
        record.get(
            "action",
            "",
        )
        or ""
    ).strip()

    dashboard.iq_inspection_selected_plugin = plugin_name
    dashboard.iq_inspection_selected_action = action_name

    _clear_iq_inspection_parameter_widgets(
        dashboard
    )

    dashboard.ui.pushButton_iq_inspection_customize.setEnabled(
        bool(
            plugin_name
            and action_name
            and selected_node_is_local(
                dashboard
            )
        )
    )


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_InspectionCustomizeClicked(
    dashboard,
):
    """Query the selected IQ Inspection action schema."""
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    record = (
        dashboard.ui
        .comboBox_iq_inspection_action
        .currentData()
    )

    if not node_uid:
        dashboard.logger.warning(
            "Select a Sensor Node before loading IQ Inspection parameters."
        )
        return

    if not selected_node_is_local(
        dashboard
    ):
        dashboard.logger.warning(
            "IQ Inspection GUI actions currently require a local Sensor Node."
        )
        return

    if not isinstance(
        record,
        dict,
    ):
        dashboard.logger.warning(
            "Select an IQ Inspection action before loading parameters."
        )
        return

    plugin_name = str(
        record.get(
            "plugin",
            "",
        )
        or ""
    ).strip()

    action_name = str(
        record.get(
            "action",
            "",
        )
        or ""
    ).strip()

    if not plugin_name or not action_name:
        dashboard.logger.warning(
            "The selected IQ Inspection action is missing plugin or action information."
        )
        return

    _clear_iq_inspection_parameter_widgets(
        dashboard
    )

    dashboard.ui.pushButton_iq_inspection_customize.setText(
        "Loading..."
    )
    dashboard.ui.pushButton_iq_inspection_customize.setEnabled(
        False
    )

    await dashboard.backend.queryPluginActionSchema(
        node_uid,
        plugin_name,
        action_name,
        context="iq.inspection.schema",
    )


def handle_iq_inspection_action_query_results(
    dashboard,
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    """Cache the complete IQ Inspection catalog and filter it by current Source."""
    result_node_uid = str(node_uid or "").strip()
    result_context = str(context or "").strip()
    expected_node_uid = str(
        getattr(dashboard, "iq_inspection_action_query_node_uid", "") or ""
    ).strip()
    expected_context = str(
        getattr(dashboard, "iq_inspection_action_query_context", "") or ""
    ).strip()
    selected_node_uid = str(
        getattr(dashboard, "selected_node_uid", "") or ""
    ).strip()

    if (
        not bool(getattr(dashboard, "iq_inspection_action_query_pending", False))
        or result_node_uid != expected_node_uid
        or result_context != expected_context
        or result_node_uid != selected_node_uid
    ):
        dashboard.logger.debug(
            "Ignoring stale IQ Inspection action query results: "
            f"node_uid={result_node_uid!r}, context={result_context!r}"
        )
        return

    dashboard.iq_inspection_action_query_pending = False
    dashboard.iq_inspection_action_query_context = ""
    dashboard.iq_inspection_action_query_node_uid = ""

    dashboard.iq_inspection_action_catalog = [
        action_record
        for action_record in (actions if isinstance(actions, list) else [])
        if isinstance(action_record, dict)
    ]

    dashboard.ui.pushButton_iq_inspection_query.setText("Query Actions")
    _filter_iq_inspection_action_catalog(dashboard)

    has_source = bool(
        str(dashboard.ui.comboBox_iq_inspection_source.currentText() or "").strip()
    )
    active = bool(
        getattr(dashboard, "iq_inspection_running", False)
        or getattr(dashboard, "iq_inspection_start_pending", False)
    )

    dashboard.ui.pushButton_iq_inspection_query.setEnabled(
        bool(
            selected_node_uid
            and selected_node_is_local(dashboard)
            and has_source
            and not active
        )
    )


def _create_iq_inspection_parameter_widget(
    dashboard,
    parameter: dict,
):
    """Create one editor for an IQ Inspection action-schema parameter."""
    parameter_type = str(
        parameter.get(
            "type",
            "string",
        )
        or "string"
    ).strip().lower()

    default = parameter.get(
        "default",
        "",
    )

    options = parameter.get(
        "options",
        [],
    )

    parent = (
        dashboard.ui
        .scrollAreaWidgetContents_iq_inspection_parameters
    )

    if isinstance(
        options,
        list,
    ) and options:
        widget = QtWidgets.QComboBox(
            parent
        )

        for option in options:
            widget.addItem(
                str(option)
            )

        default_index = widget.findText(
            str(default),
            QtCore.Qt.MatchExactly,
        )

        if default_index >= 0:
            widget.setCurrentIndex(
                default_index
            )

        return widget

    if parameter_type in {
        "int",
        "integer",
    }:
        widget = QtWidgets.QSpinBox(
            parent
        )
        widget.setMinimum(
            int(
                parameter.get(
                    "min",
                    -2147483648,
                )
            )
        )
        widget.setMaximum(
            int(
                parameter.get(
                    "max",
                    2147483647,
                )
            )
        )
        widget.setSingleStep(
            int(
                parameter.get(
                    "step",
                    1,
                )
            )
        )
        widget.setValue(
            int(
                default
                or 0
            )
        )
        return widget

    if parameter_type in {
        "float",
        "double",
        "number",
    }:
        widget = QtWidgets.QDoubleSpinBox(
            parent
        )
        widget.setDecimals(
            int(
                parameter.get(
                    "decimals",
                    6,
                )
            )
        )
        widget.setMinimum(
            float(
                parameter.get(
                    "min",
                    -1000000000000.0,
                )
            )
        )
        widget.setMaximum(
            float(
                parameter.get(
                    "max",
                    1000000000000.0,
                )
            )
        )
        widget.setSingleStep(
            float(
                parameter.get(
                    "step",
                    1.0,
                )
            )
        )
        widget.setValue(
            float(
                default
                or 0.0
            )
        )
        return widget

    if parameter_type in {
        "bool",
        "boolean",
    }:
        widget = QtWidgets.QCheckBox(
            parent
        )

        if isinstance(
            default,
            str,
        ):
            checked = default.strip().lower() in {
                "true",
                "1",
                "yes",
                "on",
                "enabled",
            }

        else:
            checked = bool(
                default
            )

        widget.setChecked(
            checked
        )
        return widget

    if parameter_type == "label":
        widget = QtWidgets.QLabel(
            str(default),
            parent,
        )
        widget.setWordWrap(
            True
        )
        widget.setTextInteractionFlags(
            QtCore.Qt.TextSelectableByMouse
        )
        return widget

    return QtWidgets.QLineEdit(
        str(default),
        parent,
    )


def _iq_inspection_parameter_widget_value(
    widget,
):
    """Return the current value from one IQ Inspection parameter editor."""
    if isinstance(
        widget,
        QtWidgets.QComboBox,
    ):
        return widget.currentText()

    if isinstance(
        widget,
        QtWidgets.QDoubleSpinBox,
    ):
        return widget.value()

    if isinstance(
        widget,
        QtWidgets.QSpinBox,
    ):
        return widget.value()

    if isinstance(
        widget,
        QtWidgets.QCheckBox,
    ):
        return widget.isChecked()

    if isinstance(
        widget,
        QtWidgets.QLineEdit,
    ):
        return widget.text()

    if isinstance(
        widget,
        QtWidgets.QLabel,
    ):
        return widget.text()

    return None


def _collect_iq_inspection_action_parameters(
    dashboard,
):
    """Collect customized Inspection parameters plus Source-specific values."""
    parameters = {}

    for parameter_name, record in (
        getattr(
            dashboard,
            "iq_inspection_parameter_widgets",
            {},
        )
        or {}
    ).items():
        if not isinstance(
            record,
            dict,
        ):
            continue

        widget = record.get(
            "widget"
        )
        schema = record.get(
            "schema",
            {},
        )

        if widget is None:
            continue

        parameter_type = str(
            schema.get(
                "type",
                "string",
            )
            or "string"
        ).strip().lower()

        if parameter_type == "label":
            continue

        parameters[
            parameter_name
        ] = _iq_inspection_parameter_widget_value(
            widget
        )

    source_text = str(
        dashboard.ui
        .comboBox_iq_inspection_source
        .currentText()
        or ""
    ).strip()

    parameters[
        "operation_id"
    ] = str(
        uuid.uuid4()
    )
    parameters[
        "requester"
    ] = "dashboard"

    if source_text.lower() == "file":
        parameters[
            "filepath"
        ] = str(
            dashboard.ui
            .textEdit_iq_inspection_filepath
            .toPlainText()
            or ""
        ).strip()

        return parameters

    (
        hardware_type,
        hardware_uuid,
        hardware_radio_name,
        hardware_serial,
        hardware_interface,
        hardware_ip,
        hardware_daughterboard,
    ) = fissure.utils.hardware.hardwareDisplayNameLookup(
        dashboard,
        source_text,
        "iq",
    )

    raw_serial_hardware = {
        "HackRF",
        "RTL2832U",
        "bladeRF",
        "bladeRF 2.0",
        "RSPduo",
        "RSPdx",
        "RSPdx R2",
    }

    zero_default_serial_hardware = {
        "RTL2832U",
        "bladeRF",
        "bladeRF 2.0",
        "RSPduo",
        "RSPdx",
        "RSPdx R2",
    }

    if hardware_serial:
        if hardware_type in raw_serial_hardware:
            hardware_serial_argument = hardware_serial

        else:
            hardware_serial_argument = (
                f"serial={hardware_serial}"
            )

    else:
        if hardware_type == "HackRF":
            hardware_serial_argument = ""

        elif hardware_type in zero_default_serial_hardware:
            hardware_serial_argument = "0"

        else:
            hardware_serial_argument = "False"

    parameters.update(
        {
            "hardware_display_name":
                source_text,
            "hardware_type":
                hardware_type,
            "hardware_uuid":
                hardware_uuid,
            "hardware_radio_name":
                hardware_radio_name,
            "hardware_serial":
                hardware_serial,
            "hardware_serial_argument":
                hardware_serial_argument,
            "hardware_interface":
                hardware_interface,
            "hardware_ip":
                hardware_ip,
            "hardware_daughterboard":
                hardware_daughterboard,
        }
    )

    return parameters


def handle_iq_inspection_action_schema(
    dashboard,
    plugin_name: str = "",
    action_name: str = "",
    node_uid: str = "",
    parameters: list = None,
):
    """Build the IQ Inspection parameter panel from an action schema."""
    selected_node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if str(
        node_uid
        or ""
    ).strip() != selected_node_uid:
        dashboard.logger.debug(
            "Ignoring IQ Inspection action schema for a different Sensor Node."
        )
        return

    selected_record = (
        dashboard.ui
        .comboBox_iq_inspection_action
        .currentData()
    )

    if not isinstance(
        selected_record,
        dict,
    ):
        return

    selected_plugin = str(
        selected_record.get(
            "plugin",
            "",
        )
        or ""
    ).strip()

    selected_action = str(
        selected_record.get(
            "action",
            "",
        )
        or ""
    ).strip()

    if (
        selected_plugin != str(
            plugin_name
            or ""
        ).strip()
        or selected_action != str(
            action_name
            or ""
        ).strip()
    ):
        dashboard.logger.debug(
            "Ignoring IQ Inspection action schema for a different action."
        )
        return

    _clear_iq_inspection_parameter_widgets(
        dashboard
    )

    content = (
        dashboard.ui
        .scrollAreaWidgetContents_iq_inspection_parameters
    )
    layout = content.layout()

    if layout is None:
        layout = QtWidgets.QFormLayout(
            content
        )
        layout.setContentsMargins(
            8,
            8,
            8,
            8,
        )
        layout.setHorizontalSpacing(
            10
        )
        layout.setVerticalSpacing(
            6
        )
        layout.setFieldGrowthPolicy(
            QtWidgets.QFormLayout.AllNonFixedFieldsGrow
        )

    normalized_parameters = (
        parameters
        if isinstance(
            parameters,
            list,
        )
        else []
    )

    dashboard.iq_inspection_current_schema = {
        "plugin":
            selected_plugin,
        "action":
            selected_action,
        "params":
            normalized_parameters,
    }

    source_is_file = _iq_inspection_source_is_file(
        dashboard
    )

    for parameter in normalized_parameters:
        if not isinstance(
            parameter,
            dict,
        ):
            continue

        name = str(
            parameter.get(
                "name",
                "",
            )
            or ""
        ).strip()

        if not name:
            continue

        # The file action keeps filepath in its public schema for generic
        # callers, but IQ Data owns filepath in the Run card.
        if source_is_file and name == "filepath":
            continue

        label_text = str(
            parameter.get(
                "label",
                name,
            )
            or name
        )

        widget = _create_iq_inspection_parameter_widget(
            dashboard,
            parameter,
        )

        if isinstance(
            widget,
            QtWidgets.QDoubleSpinBox,
        ):
            widget.setObjectName(
                "doubleSpinBox_iq_inspection_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QSpinBox,
        ):
            widget.setObjectName(
                "spinBox_iq_inspection_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QComboBox,
        ):
            widget.setObjectName(
                "comboBox_iq_inspection_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QCheckBox,
        ):
            widget.setObjectName(
                "checkBox_iq_inspection_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QLineEdit,
        ):
            widget.setObjectName(
                "lineEdit_iq_inspection_parameter"
            )

        elif isinstance(
            widget,
            QtWidgets.QLabel,
        ):
            widget.setObjectName(
                "label2_iq_inspection_parameter_info"
            )

        dashboard.iq_inspection_parameter_widgets[
            name
        ] = {
            "widget":
                widget,
            "schema":
                dict(
                    parameter
                ),
        }

        label = QtWidgets.QLabel(
            label_text,
            content,
        )
        label.setObjectName(
            "label2_iq_inspection_parameter"
        )
        label.setWordWrap(
            True
        )

        layout.addRow(
            label,
            widget,
        )

    dashboard.iq_inspection_selected_plugin = selected_plugin
    dashboard.iq_inspection_selected_action = selected_action
    dashboard.iq_inspection_customized = True

    dashboard.ui.pushButton_iq_inspection_customize.setText(
        "Customize"
    )
    dashboard.ui.pushButton_iq_inspection_customize.setEnabled(
        True
    )

    dashboard.ui.label2_iq_inspection_status.setText(
        "Idle"
    )

    update_iq_inspection_selected_node_gate(
        dashboard
    )


def _set_iq_inspection_start_stop_button(
    dashboard,
    running: bool,
):
    """Update the IQ Inspection Card 3 Start/Stop button."""
    button = (
        dashboard.ui.pushButton_iq_inspection_start_stop
    )

    button.setProperty(
        "running",
        bool(running),
    )

    button.setText(
        "Stop"
        if running
        else "Start"
    )

    button.style().unpolish(
        button
    )
    button.style().polish(
        button
    )
    button.update()


def _set_iq_inspection_stopped(
    dashboard,
    status_text: str = "Idle",
):
    """Restore IQ Inspection controls after Stop or GUI completion."""
    dashboard.iq_inspection_running = False
    dashboard.iq_inspection_start_pending = False
    dashboard.iq_inspection_seen_running_status = False
    dashboard.iq_inspection_node_uid = ""
    dashboard.iq_inspection_operation_id = ""

    _set_iq_inspection_start_stop_button(
        dashboard,
        False,
    )

    update_iq_inspection_selected_node_gate(
        dashboard
    )

    selected_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if (
        selected_uid
        and selected_node_is_local(
            dashboard
        )
    ):
        dashboard.ui.label2_iq_inspection_status.setText(
            status_text
        )


def update_iq_inspection_status_from_selected_node(
    dashboard,
    node_uid: str,
    status: str,
):
    """Track Inspection GUI completion from the selected Sensor Node state."""
    if not bool(
        getattr(
            dashboard,
            "iq_inspection_running",
            False,
        )
    ):
        return

    tracked_node_uid = str(
        getattr(
            dashboard,
            "iq_inspection_node_uid",
            "",
        )
        or ""
    ).strip()

    node_uid_text = str(
        node_uid
        or ""
    ).strip()

    if (
        tracked_node_uid
        and node_uid_text
        and tracked_node_uid != node_uid_text
        and not tracked_node_uid.endswith(
            node_uid_text
        )
        and not node_uid_text.endswith(
            tracked_node_uid
        )
    ):
        return

    status_text = str(
        status
        or ""
    ).strip()

    if status_text.startswith(
        "Running"
    ):
        dashboard.iq_inspection_seen_running_status = True
        dashboard.ui.label2_iq_inspection_status.setText(
            "Running..."
        )
        return

    if status_text == "Error":
        _set_iq_inspection_stopped(
            dashboard,
            status_text="Error",
        )
        return

    if (
        status_text == "Idle"
        and bool(
            getattr(
                dashboard,
                "iq_inspection_seen_running_status",
                False,
            )
        )
    ):
        _set_iq_inspection_stopped(
            dashboard,
            status_text="Completed",
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_InspectionStartStopClicked(
    dashboard,
):
    """Start or stop the selected local IQ Inspection plugin action."""
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    running = bool(
        getattr(
            dashboard,
            "iq_inspection_running",
            False,
        )
    )

    start_pending = bool(
        getattr(
            dashboard,
            "iq_inspection_start_pending",
            False,
        )
    )

    if running or start_pending:
        tracked_node_uid = str(
            getattr(
                dashboard,
                "iq_inspection_node_uid",
                "",
            )
            or node_uid
            or ""
        ).strip()

        if not tracked_node_uid:
            return

        dashboard.ui.label2_iq_inspection_status.setText(
            "Stopping..."
        )
        dashboard.ui.pushButton_iq_inspection_start_stop.setEnabled(
            False
        )

        try:
            await dashboard.backend.tacticalNodeStop(
                [tracked_node_uid]
            )

        except Exception as error:
            dashboard.logger.error(
                "Failed to stop IQ Inspection operation: "
                f"{error}"
            )

            dashboard.ui.label2_iq_inspection_status.setText(
                "Stop Failed"
            )
            dashboard.ui.pushButton_iq_inspection_start_stop.setEnabled(
                True
            )
            return

        _set_iq_inspection_stopped(
            dashboard,
            status_text="Stopped",
        )
        return

    if not node_uid:
        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "Select a Sensor Node.",
            )
        )
        return

    if not selected_node_is_local(
        dashboard
    ):
        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "IQ Inspection GUI actions currently require a local Sensor Node.",
            )
        )
        return

    if not bool(
        getattr(
            dashboard,
            "iq_inspection_customized",
            False,
        )
    ):
        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "Load the IQ Inspection parameters before starting.",
            )
        )
        return

    plugin_name = str(
        getattr(
            dashboard,
            "iq_inspection_selected_plugin",
            "",
        )
        or ""
    ).strip()

    action_name = str(
        getattr(
            dashboard,
            "iq_inspection_selected_action",
            "",
        )
        or ""
    ).strip()

    if not plugin_name or not action_name:
        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "Select an IQ Inspection action.",
            )
        )
        return

    if _iq_inspection_source_is_file(
        dashboard
    ):
        filepath = str(
            dashboard.ui
            .textEdit_iq_inspection_filepath
            .toPlainText()
            or ""
        ).strip()

        if not filepath:
            dashboard.ui.label2_iq_inspection_status.setText(
                "File Required"
            )

            await (
                fissure.Dashboard.UI_Components.Qt5
                .async_ok_dialog(
                    dashboard,
                    "Select or enter an IQ inspection filepath.",
                )
            )
            return

    try:
        parameters = (
            _collect_iq_inspection_action_parameters(
                dashboard
            )
        )

    except Exception as error:
        dashboard.logger.error(
            "Failed to collect IQ Inspection parameters: "
            f"{error}"
        )

        await (
            fissure.Dashboard.UI_Components.Qt5
            .async_ok_dialog(
                dashboard,
                "One or more IQ Inspection parameters are invalid.",
            )
        )
        return

    dashboard.iq_inspection_start_pending = True
    dashboard.iq_inspection_running = False
    dashboard.iq_inspection_seen_running_status = False
    dashboard.iq_inspection_node_uid = node_uid
    dashboard.iq_inspection_operation_id = str(
        parameters.get(
            "operation_id",
            "",
        )
        or ""
    ).strip()

    _set_iq_inspection_start_stop_button(
        dashboard,
        True,
    )

    dashboard.ui.label2_iq_inspection_status.setText(
        "Starting..."
    )

    update_iq_inspection_selected_node_gate(
        dashboard
    )

    dashboard.logger.info(
        "Starting IQ Inspection: "
        f"plugin={plugin_name}, "
        f"action={action_name}, "
        f"node_uid={node_uid}, "
        f"source={dashboard.ui.comboBox_iq_inspection_source.currentText()}"
    )

    try:
        await dashboard.backend.tacticalNodeExecute(
            [node_uid],
            plugin_name,
            action_name,
            parameters,
        )

    except Exception as error:
        dashboard.logger.error(
            "Failed to start IQ Inspection operation: "
            f"{error}"
        )

        _set_iq_inspection_stopped(
            dashboard,
            status_text="Start Failed",
        )
        return

    dashboard.iq_inspection_start_pending = False
    dashboard.iq_inspection_running = True

    dashboard.ui.label2_iq_inspection_status.setText(
        "Running..."
    )

    _set_iq_inspection_start_stop_button(
        dashboard,
        True,
    )


def initialize_iq_inspection_controls(
    dashboard,
):
    """Initialize the action-driven IQ Inspection workflow."""
    dashboard.iq_inspection_running = False
    dashboard.iq_inspection_start_pending = False
    dashboard.iq_inspection_seen_running_status = False
    dashboard.iq_inspection_node_uid = ""
    dashboard.iq_inspection_operation_id = ""

    dashboard.iq_inspection_action_catalog = []
    dashboard.iq_inspection_filtered_actions = []
    dashboard.iq_inspection_action_catalog_node_uid = ""
    dashboard.iq_inspection_filter_source = ""
    dashboard.iq_inspection_method_actions = []
    dashboard.iq_inspection_selected_plugin = ""
    dashboard.iq_inspection_selected_action = ""
    dashboard.iq_inspection_parameter_widgets = {}
    dashboard.iq_inspection_current_schema = {}
    dashboard.iq_inspection_customized = False

    dashboard.iq_inspection_action_query_pending = False
    dashboard.iq_inspection_action_query_context = ""
    dashboard.iq_inspection_action_query_node_uid = ""

    dashboard.ui.stackedWidget_iq_inspection.setCurrentWidget(
        dashboard.ui.page_iq_inspection_no_node
    )

    select_node_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "select_node.png",
    )

    if os.path.isfile(
        select_node_icon_path
    ):
        select_node_pixmap = QtGui.QPixmap(
            select_node_icon_path
        )

        dashboard.ui.label_iq_inspection_select_sensor_node_image.setPixmap(
            select_node_pixmap
        )
        dashboard.ui.label_iq_inspection_select_sensor_node_image.setScaledContents(
            False
        )
        dashboard.ui.label_iq_inspection_select_sensor_node_image.setAlignment(
            QtCore.Qt.AlignCenter
        )

    dashboard.ui.comboBox_iq_inspection_source.clear()
    dashboard.ui.comboBox_iq_inspection_source.setEnabled(False)

    dashboard.ui.comboBox_iq_inspection_plugin.clear()
    dashboard.ui.comboBox_iq_inspection_plugin.setEnabled(False)

    dashboard.ui.comboBox_iq_inspection_action.clear()
    dashboard.ui.comboBox_iq_inspection_action.setEnabled(False)

    dashboard.ui.pushButton_iq_inspection_query.setText(
        "Query Actions"
    )
    dashboard.ui.pushButton_iq_inspection_query.setEnabled(
        False
    )

    dashboard.ui.pushButton_iq_inspection_customize.setText(
        "Customize"
    )
    dashboard.ui.pushButton_iq_inspection_customize.setEnabled(
        False
    )

    _set_iq_inspection_start_stop_button(
        dashboard,
        False,
    )
    dashboard.ui.pushButton_iq_inspection_start_stop.setEnabled(
        False
    )

    dashboard.ui.textEdit_iq_inspection_filepath.setReadOnly(
        False
    )
    dashboard.ui.textEdit_iq_inspection_filepath.setEnabled(
        False
    )

    dashboard.ui.label2_iq_inspection_filepath_label.setVisible(
        False
    )
    dashboard.ui.textEdit_iq_inspection_filepath.setVisible(
        False
    )

    dashboard.ui.label2_iq_inspection_status.setText(
        "Unavailable"
    )

    scroll_area = getattr(
        dashboard.ui,
        "scrollArea_iq_inspection_parameters",
        None,
    )

    if scroll_area is not None:
        scroll_area.setHorizontalScrollBarPolicy(
            QtCore.Qt.ScrollBarAlwaysOff
        )
        scroll_area.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarAsNeeded
        )

        parameter_widgets = [
            scroll_area,
            scroll_area.viewport(),
            scroll_area.widget(),
        ]

        for widget in parameter_widgets:
            if widget is None:
                continue

            widget.setProperty(
                "uiRole",
                "parameterPanel",
            )
            widget.style().unpolish(
                widget
            )
            widget.style().polish(
                widget
            )
            widget.update()

    _clear_iq_inspection_parameter_widgets(
        dashboard
    )

    update_iq_inspection_selected_node_gate(
        dashboard
    )


def update_iq_inspection_selected_node_gate(dashboard):
    """
    Gate the local-only IQ Inspection workflow and keep the cached action
    catalog owned by the correct node/source selection.
    """
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    has_selected_node = bool(selected_uid)

    if has_selected_node:
        node_state = (getattr(dashboard, "node_states", {}) or {}).get(selected_uid)

        if isinstance(node_state, dict) and node_state.get("connected") is False:
            has_selected_node = False

    is_local = bool(
        has_selected_node and selected_node_is_local(dashboard)
    )
    is_remote = bool(
        has_selected_node and selected_node_is_remote(dashboard)
    )

    if not has_selected_node:
        dashboard.ui.stackedWidget_iq_inspection.setCurrentWidget(
            dashboard.ui.page_iq_inspection_no_node
        )
    elif is_local:
        dashboard.ui.stackedWidget_iq_inspection.setCurrentWidget(
            dashboard.ui.page_iq_inspection_controls
        )
    elif is_remote:
        dashboard.ui.stackedWidget_iq_inspection.setCurrentWidget(
            dashboard.ui.page_iq_inspection_remote_node
        )
    else:
        dashboard.ui.stackedWidget_iq_inspection.setCurrentWidget(
            dashboard.ui.page_iq_inspection_no_node
        )

    source_combo = dashboard.ui.comboBox_iq_inspection_source
    plugin_combo = dashboard.ui.comboBox_iq_inspection_plugin
    action_combo = dashboard.ui.comboBox_iq_inspection_action
    query_button = dashboard.ui.pushButton_iq_inspection_query
    customize_button = dashboard.ui.pushButton_iq_inspection_customize
    filepath_edit = dashboard.ui.textEdit_iq_inspection_filepath
    start_button = dashboard.ui.pushButton_iq_inspection_start_stop

    _update_iq_inspection_source_ui(dashboard)

    catalog_node_uid = str(
        getattr(dashboard, "iq_inspection_action_catalog_node_uid", "") or ""
    ).strip()
    node_changed = selected_uid != catalog_node_uid

    if node_changed:
        dashboard.iq_inspection_action_catalog_node_uid = selected_uid
        dashboard.iq_inspection_action_catalog = []
        dashboard.iq_inspection_filter_source = ""
        dashboard.iq_inspection_action_query_pending = False
        dashboard.iq_inspection_action_query_context = ""
        dashboard.iq_inspection_action_query_node_uid = ""
        query_button.setText("Query Actions")
        _reset_iq_inspection_action_selection(dashboard)

        if not bool(
            getattr(dashboard, "iq_inspection_running", False)
            or getattr(dashboard, "iq_inspection_start_pending", False)
        ):
            dashboard.ui.label2_iq_inspection_status.setText(
                "Idle" if is_local else "Unavailable"
            )

    current_source = str(source_combo.currentText() or "").strip()
    filtered_source = str(
        getattr(dashboard, "iq_inspection_filter_source", "") or ""
    ).strip()

    active = bool(
        getattr(dashboard, "iq_inspection_running", False)
        or getattr(dashboard, "iq_inspection_start_pending", False)
    )

    if current_source != filtered_source and is_local and not active:
        dashboard.iq_inspection_customized = False
        _clear_iq_inspection_parameter_widgets(dashboard)
        _filter_iq_inspection_action_catalog(dashboard)

    if not is_local:
        source_combo.setEnabled(False)
        plugin_combo.setEnabled(False)
        action_combo.setEnabled(False)
        query_button.setEnabled(False)
        customize_button.setEnabled(False)
        filepath_edit.setEnabled(False)
        start_button.setEnabled(False)
        dashboard.ui.label2_iq_inspection_status.setText("Unavailable")

        for parameter_record in (
            getattr(dashboard, "iq_inspection_parameter_widgets", {}) or {}
        ).values():
            if not isinstance(parameter_record, dict):
                continue

            widget = parameter_record.get("widget")

            if widget is not None:
                widget.setEnabled(False)

        return

    if active:
        source_combo.setEnabled(False)
        plugin_combo.setEnabled(False)
        action_combo.setEnabled(False)
        query_button.setEnabled(False)
        customize_button.setEnabled(False)
        filepath_edit.setEnabled(False)
        start_button.setEnabled(True)

        for parameter_record in (
            getattr(dashboard, "iq_inspection_parameter_widgets", {}) or {}
        ).values():
            if not isinstance(parameter_record, dict):
                continue

            widget = parameter_record.get("widget")

            if widget is not None:
                widget.setEnabled(False)

        return

    has_source = bool(current_source)
    source_is_file = _iq_inspection_source_is_file(dashboard)

    source_combo.setEnabled(source_combo.count() > 0)
    plugin_combo.setEnabled(plugin_combo.count() > 0)
    action_combo.setEnabled(action_combo.count() > 0)
    query_button.setEnabled(
        has_source
        and not bool(getattr(dashboard, "iq_inspection_action_query_pending", False))
    )
    customize_button.setEnabled(action_combo.count() > 0)
    filepath_edit.setEnabled(source_is_file)
    filepath_edit.setReadOnly(False)
    start_button.setEnabled(
        bool(getattr(dashboard, "iq_inspection_customized", False))
    )

    current_status = str(
        dashboard.ui.label2_iq_inspection_status.text() or ""
    ).strip()

    if current_status in {"", "Unavailable"}:
        dashboard.ui.label2_iq_inspection_status.setText("Idle")

    for parameter_record in (
        getattr(dashboard, "iq_inspection_parameter_widgets", {}) or {}
    ).values():
        if not isinstance(parameter_record, dict):
            continue

        widget = parameter_record.get("widget")

        if widget is not None:
            widget.setEnabled(True)


def initialize_iq_record_controls(
    dashboard: QtCore.QObject,
):
    """
    Initialize IQ Record controls.
    """
    dashboard.iq_record_running = False
    dashboard.iq_record_node_uid = ""
    dashboard.iq_record_operation_id = ""
    dashboard.iq_record_artifact_id = ""
    dashboard.iq_record_select_after_download_id = ""

    dashboard.iq_record_action_catalog = []
    dashboard.iq_record_filtered_actions = []
    dashboard.iq_record_action_catalog_node_uid = ""
    dashboard.iq_record_filter_hardware_display = ""
    dashboard.iq_record_method_actions = []
    dashboard.iq_record_selected_plugin = ""
    dashboard.iq_record_selected_action = ""
    dashboard.iq_record_parameter_widgets = {}
    dashboard.iq_record_current_schema = {}
    dashboard.iq_record_customized = False

    dashboard.iq_record_action_query_pending = False
    dashboard.iq_record_action_query_context = ""
    dashboard.iq_record_action_query_node_uid = ""

    dashboard.ui.stackedWidget3_iq_pages.setCurrentWidget(
        dashboard.ui.page_iq_record
    )


    dashboard.ui.stackedWidget_iq_record.setCurrentWidget(
        dashboard.ui.page_iq_record_no_node
    )

    select_node_icon_path = os.path.join(
        fissure.utils.UI_DIR,
        "Icons",
        "select_node.png",
    )

    if os.path.isfile(
        select_node_icon_path
    ):
        select_node_pixmap = QtGui.QPixmap(
            select_node_icon_path
        )

        dashboard.ui.label_iq_record_select_sensor_node_image.setPixmap(
            select_node_pixmap
        )
        dashboard.ui.label_iq_record_select_sensor_node_image.setScaledContents(
            False
        )
        dashboard.ui.label_iq_record_select_sensor_node_image.setAlignment(
            QtCore.Qt.AlignCenter
        )

    dashboard.ui.comboBox_iq_record_plugin.clear()
    dashboard.ui.comboBox_iq_record_plugin.setEnabled(False)

    dashboard.ui.comboBox_iq_record_method.clear()
    dashboard.ui.comboBox_iq_record_method.setEnabled(False)

    dashboard.ui.pushButton_iq_record_query.setText("Query Actions")
    dashboard.ui.pushButton_iq_record_query.setEnabled(False)

    dashboard.ui.pushButton_iq_record_customize.setText("Customize")
    dashboard.ui.pushButton_iq_record_customize.setEnabled(False)

    _set_iq_record_start_stop_button(dashboard, False,)

    dashboard.ui.pushButton_iq_record_start_stop.setEnabled(False)

    dashboard.ui.label2_iq_record_status.setText("Unavailable")

    dashboard.ui.label2_iq_record_status_artifact_id_label.setText("Artifact ID:")

    _update_iq_record_artifact_button(dashboard)

    scroll_area = getattr(
        dashboard.ui,
        "scrollArea_iq_record_parameters",
        None,
    )

    if scroll_area is not None:
        scroll_area.setHorizontalScrollBarPolicy(
            QtCore.Qt.ScrollBarAlwaysOff
        )
        scroll_area.setVerticalScrollBarPolicy(
            QtCore.Qt.ScrollBarAsNeeded
        )

        parameter_widgets = [
            scroll_area,
            scroll_area.viewport(),
            scroll_area.widget(),
        ]

        for widget in parameter_widgets:
            if widget is None:
                continue

            widget.setProperty(
                "uiRole",
                "parameterPanel",
            )
            widget.style().unpolish(widget)
            widget.style().polish(widget)
            widget.update()

    _clear_iq_record_parameter_widgets(dashboard)

    update_iq_record_selected_node_gate(dashboard)


def update_iq_record_selected_node_gate(dashboard: QtCore.QObject):
    """
    Show IQ Record controls only for an online selected Sensor Node and keep
    the cached action catalog owned by the correct node/hardware selection.
    """
    selected_uid = str(getattr(dashboard, "selected_node_uid", "") or "").strip()
    has_selected_node = bool(selected_uid)

    if has_selected_node:
        node_state = (getattr(dashboard, "node_states", {}) or {}).get(selected_uid)

        if isinstance(node_state, dict) and node_state.get("connected") is False:
            has_selected_node = False

    dashboard.ui.stackedWidget_iq_record.setCurrentWidget(
        dashboard.ui.page_iq_record_controls
        if has_selected_node
        else dashboard.ui.page_iq_record_no_node
    )

    hardware_combo = dashboard.ui.comboBox_iq_record_hardware
    plugin_combo = dashboard.ui.comboBox_iq_record_plugin
    method_combo = dashboard.ui.comboBox_iq_record_method
    query_button = dashboard.ui.pushButton_iq_record_query
    customize_button = dashboard.ui.pushButton_iq_record_customize
    start_button = dashboard.ui.pushButton_iq_record_start_stop

    catalog_node_uid = str(
        getattr(dashboard, "iq_record_action_catalog_node_uid", "") or ""
    ).strip()
    node_changed = selected_uid != catalog_node_uid

    if node_changed:
        dashboard.iq_record_action_catalog_node_uid = selected_uid
        dashboard.iq_record_action_catalog = []
        dashboard.iq_record_filter_hardware_display = ""
        dashboard.iq_record_action_query_pending = False
        dashboard.iq_record_action_query_context = ""
        dashboard.iq_record_action_query_node_uid = ""
        dashboard.ui.pushButton_iq_record_query.setText("Query Actions")
        _reset_iq_record_action_selection(dashboard)

        if not bool(getattr(dashboard, "iq_record_running", False)):
            dashboard.ui.label2_iq_record_status.setText(
                "Idle" if has_selected_node else "Unavailable"
            )

    current_hardware = str(hardware_combo.currentText() or "").strip()
    filtered_hardware = str(
        getattr(dashboard, "iq_record_filter_hardware_display", "") or ""
    ).strip()

    if (
        current_hardware != filtered_hardware
        and not bool(getattr(dashboard, "iq_record_running", False))
    ):
        dashboard.iq_record_customized = False
        _clear_iq_record_parameter_widgets(dashboard)
        _filter_iq_record_action_catalog(dashboard)

    if bool(getattr(dashboard, "iq_record_running", False)):
        hardware_combo.setEnabled(False)
        plugin_combo.setEnabled(False)
        method_combo.setEnabled(False)
        query_button.setEnabled(False)
        customize_button.setEnabled(False)
        start_button.setEnabled(True)
        return

    _set_iq_record_start_stop_button(dashboard, False)

    hardware_combo.setEnabled(
        has_selected_node and hardware_combo.count() > 0
    )
    plugin_combo.setEnabled(
        has_selected_node and plugin_combo.count() > 0
    )
    method_combo.setEnabled(
        has_selected_node and method_combo.count() > 0
    )
    query_button.setEnabled(
        has_selected_node
        and hardware_combo.count() > 0
        and not bool(getattr(dashboard, "iq_record_action_query_pending", False))
    )
    customize_button.setEnabled(
        has_selected_node and method_combo.count() > 0
    )
    start_button.setEnabled(
        has_selected_node
        and bool(getattr(dashboard, "iq_record_customized", False))
    )

    current_status = str(
        dashboard.ui.label2_iq_record_status.text() or ""
    ).strip()

    if not has_selected_node:
        dashboard.ui.label2_iq_record_status.setText("Unavailable")
    elif current_status in {"", "Unavailable"}:
        dashboard.ui.label2_iq_record_status.setText("Idle")