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
def _slotIQ_RecordSigMF_Clicked(dashboard: QtCore.QObject):
    """ 
    Follows SigMF standard for recording IQ data when enabled.
    """
    # Enabled
    get_filename = str(dashboard.ui.tableWidget_iq_record.item(0,0).text())

    if dashboard.ui.checkBox_iq_record_sigmf.isChecked() == True:
        dashboard.ui.pushButton_iq_record_sigmf.setEnabled(True)
        new_filename = get_filename.replace('.iq','.sigmf-data')
        filename_item = QtWidgets.QTableWidgetItem(new_filename)
        filename_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setItem(0,0,filename_item)

    # Disabled
    else:
        dashboard.ui.pushButton_iq_record_sigmf.setEnabled(False)
        new_filename = get_filename.replace('.sigmf-data','.iq',)
        filename_item = QtWidgets.QTableWidgetItem(new_filename)
        filename_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setItem(0,0,filename_item)


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


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_RecordHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Changes IQ recording settings based on hardware.
    """
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_iq_record_hardware.currentText())
    get_hardware_type, get_hardware_uuid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'iq')

    # Utility Functions   
    get_gain = fissure.utils.hardware.getHardwareGain(get_hardware_type, "RX")
    get_antennas = fissure.utils.hardware.getHardwareAntennas(get_hardware_type, "RX")
    get_channels = fissure.utils.hardware.getHardwareChannels(get_hardware_type, "RX")

    # Set the Values
    if get_hardware_type == "Computer":
        dashboard.ui.frame_iq_record.setEnabled(False)

    elif get_hardware_type == "USRP X3x0":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(6000)
        spinbox_frequency.setMinimum(50)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)

        # Select Antenna
        get_daughterboard = get_hardware_daughterboard
        if "CBX-120" in get_daughterboard:
            comboBox_antenna.setCurrentIndex(0)
        elif "SBX-120" in get_daughterboard:
            comboBox_antenna.setCurrentIndex(0)
        elif "UBX-160" in get_daughterboard:
            comboBox_antenna.setCurrentIndex(0)
        elif "WBX-120" in get_daughterboard:
            comboBox_antenna.setCurrentIndex(0)
        elif "TwinRX" in get_daughterboard:
            comboBox_antenna.setCurrentIndex(1)
        else:
            comboBox_antenna.setCurrentIndex(0)

        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)

        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "USRP B2x0":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(6000)
        spinbox_frequency.setMinimum(70)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "HackRF":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(6000)
        spinbox_frequency.setMinimum(1)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "RTL2832U":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(1700)
        spinbox_frequency.setMinimum(64)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        comboBox_sample_rate = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_sample_rate.addItem("0.25")
        comboBox_sample_rate.addItem("1.024")
        comboBox_sample_rate.addItem("1.536")
        comboBox_sample_rate.addItem("1.792")
        comboBox_sample_rate.addItem("1.92")
        comboBox_sample_rate.addItem("2.048")
        comboBox_sample_rate.addItem("2.16")
        comboBox_sample_rate.addItem("2.56")
        comboBox_sample_rate.addItem("2.88")
        comboBox_sample_rate.addItem("3.2")
        comboBox_sample_rate.setCurrentIndex(7)
        comboBox_sample_rate.setEditable(True)
        comboBox_sample_rate.lineEdit().setAlignment(QtCore.Qt.AlignCenter)
        comboBox_sample_rate.lineEdit().setReadOnly(True)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,7,comboBox_sample_rate)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "802.11x Adapter":
        dashboard.ui.frame_iq_record.setEnabled(False)

    elif get_hardware_type == "USRP B20xmini":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(6000)
        spinbox_frequency.setMinimum(70)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "LimeSDR":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(6000)
        spinbox_frequency.setMinimum(50)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "bladeRF":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(3800)
        spinbox_frequency.setMinimum(50)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "Open Sniffer":
        dashboard.ui.frame_iq_record.setEnabled(False)

    elif get_hardware_type == "PlutoSDR":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(3800)
        spinbox_frequency.setMinimum(325)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "USRP2":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(6000)
        spinbox_frequency.setMinimum(50)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "USRP N2xx":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(6000)
        spinbox_frequency.setMinimum(50)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "bladeRF 2.0":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(6000)
        spinbox_frequency.setMinimum(47)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "USRP X410":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(7200)
        spinbox_frequency.setMinimum(1)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)

        # Select Antenna
        get_daughterboard = get_hardware_daughterboard
        if "ZBX" in get_daughterboard:
            comboBox_antenna.setCurrentIndex(0)

        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)

        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "RSPduo":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(2000)
        spinbox_frequency.setMinimum(1)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        item1 = comboBox_antenna.model().item(1)
        item1.setFlags(item1.flags() & ~QtCore.Qt.ItemIsEnabled)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "RSPdx":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(2000)
        spinbox_frequency.setMinimum(1)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        itemB = comboBox_antenna.model().item(1)
        itemB.setFlags(itemB.flags() & ~QtCore.Qt.ItemIsEnabled)
        itemC = comboBox_antenna.model().item(2)
        itemC.setFlags(itemC.flags() & ~QtCore.Qt.ItemIsEnabled)  
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "RSPdx R2":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(2000)
        spinbox_frequency.setMinimum(1)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_antenna.addItems(get_antennas)
        itemB = comboBox_antenna.model().item(1)
        itemB.setFlags(itemB.flags() & ~QtCore.Qt.ItemIsEnabled)
        itemC = comboBox_antenna.model().item(2)
        itemC.setFlags(itemC.flags() & ~QtCore.Qt.ItemIsEnabled)  
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    elif get_hardware_type == "CaribouLite":
        spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_frequency.setMaximum(6000)
        spinbox_frequency.setMinimum(30)
        spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,1,spinbox_frequency)
        comboBox_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,2,comboBox_channel)
        comboBox_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        # comboBox_antenna.addItems(get_antennas) 
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,3,comboBox_antenna)
        spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        spinbox_gain.setMaximum(get_gain[1])
        spinbox_gain.setMinimum(get_gain[0])
        spinbox_gain.setValue(get_gain[2])
        spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_record.setCellWidget(0,4,spinbox_gain)
        dashboard.ui.tableWidget_iq_record.removeCellWidget(0,7)
        dashboard.ui.tableWidget_iq_record.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_record.setColumnWidth(0,300)
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(False)  # Needs to toggle in PyQt5
        dashboard.ui.tableWidget_iq_record.horizontalHeader().setStretchLastSection(True)

        dashboard.ui.frame_iq_record.setEnabled(True)

    # Enable Recording
    dashboard.ui.pushButton_iq_record.setEnabled(True)
    dashboard.ui.label2_iq_status_files.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlaybackHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Changes IQ playback settings based on hardware.
    """
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_iq_playback_hardware.currentText())
    get_hardware_type, get_hardware_uuid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'iq')
    
    # Utility Functions   
    get_gain = fissure.utils.hardware.getHardwareGain(get_hardware_type, "TX")
    get_antennas = fissure.utils.hardware.getHardwareAntennas(get_hardware_type, "TX")
    get_channels = fissure.utils.hardware.getHardwareChannels(get_hardware_type, "TX")
    
    # Set the Values
    if get_hardware_type == "Computer":
        pass

    elif get_hardware_type == "USRP X3x0":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(6000)
        playback_spinbox_frequency.setMinimum(50)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "USRP B2x0":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(6000)
        playback_spinbox_frequency.setMinimum(70)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "HackRF":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(6000)
        playback_spinbox_frequency.setMinimum(1)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "RTL2832U":
        pass

    elif get_hardware_type == "802.11x Adapter":
        pass

    elif get_hardware_type == "USRP B20xmini":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(6000)
        playback_spinbox_frequency.setMinimum(70)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "LimeSDR":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(6000)
        playback_spinbox_frequency.setMinimum(50)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "bladeRF":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(3800)
        playback_spinbox_frequency.setMinimum(50)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "Open Sniffer":
        pass

    elif get_hardware_type == "PlutoSDR":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(3800)
        playback_spinbox_frequency.setMinimum(325)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "USRP2":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(6000)
        playback_spinbox_frequency.setMinimum(50)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "USRP N2xx":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(6000)
        playback_spinbox_frequency.setMinimum(50)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "bladeRF 2.0":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(6000)
        playback_spinbox_frequency.setMinimum(47)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])           
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "USRP X410":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(1)
        playback_spinbox_frequency.setMinimum(7200)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)

    elif get_hardware_type == "RSPduo":
        pass

    elif get_hardware_type == "RSPdx":
        pass

    elif get_hardware_type == "RSPdx R2":
        pass

    elif get_hardware_type == "CaribouLite":
        playback_spinbox_frequency = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_frequency.setMaximum(6000)
        playback_spinbox_frequency.setMinimum(30)
        playback_spinbox_frequency.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,0,playback_spinbox_frequency)
        comboBox_playback_channel = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        comboBox_playback_channel.addItems(get_channels)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,1,comboBox_playback_channel)
        comboBox_playback_antenna = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        # comboBox_playback_antenna.addItems(get_antennas)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,2,comboBox_playback_antenna)
        playback_spinbox_gain = QtWidgets.QDoubleSpinBox(dashboard)
        playback_spinbox_gain.setMaximum(get_gain[1])
        playback_spinbox_gain.setMinimum(get_gain[0])
        playback_spinbox_gain.setValue(get_gain[2])
        playback_spinbox_gain.setAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_iq_playback.setCellWidget(0,3,playback_spinbox_gain)
        dashboard.ui.tableWidget_iq_playback.resizeColumnsToContents()
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_iq_playback.horizontalHeader().setStretchLastSection(True)    

    # Enable Playback and Recording
    dashboard.ui.pushButton_iq_playback.setEnabled(True)
    dashboard.ui.label2_iq_playback_status.setEnabled(True)
    dashboard.ui.pushButton_iq_playback_record_freq.setEnabled(True)
    dashboard.ui.pushButton_iq_playback_record_gain.setEnabled(True)
    dashboard.ui.pushButton_iq_playback_record_rate.setEnabled(True)

    # Re-Enable Controls
    if dashboard.ui.label2_iq_file_name.text() != "File:" and get_antennas:
        dashboard.ui.frame_iq_playback_controls.setEnabled(True)
    else:
        dashboard.ui.frame_iq_playback_controls.setEnabled(False)   


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_InspectionHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Changes IQ inspection settings based on hardware.
    """
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_iq_inspection_hardware.currentText())
    get_hardware_type, get_hardware_uuid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'iq')
    
    # Clear Widgets
    dashboard.ui.listWidget_iq_inspection_flow_graphs.clear()

    # Update Flow Graphs
    if len(get_hardware_type) > 0:
        get_fgs = fissure.utils.library.getInspectionFlowGraphFilename(
            dashboard.backend.library, 
            get_hardware_type, 
            fissure.utils.get_library_version()
        )
        for n in sorted(get_fgs,key=str.lower):
            if n != "None":
                dashboard.ui.listWidget_iq_inspection_flow_graphs.addItem(n)
        dashboard.ui.listWidget_iq_inspection_flow_graphs.setCurrentRow(0)

        # Enable Frame
        dashboard.ui.frame1_iq_inspection_fg.setEnabled(True)


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
def _slotIQ_TabClicked(dashboard: QtCore.QObject, button_name):
    """ 
    Simulates a QTabWidget and changes the IQ QStackedWidget index.
    """
    # Change the Index
    if button_name == "pushButton1_iq_tab_record":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(0)
    elif button_name == "pushButton1_iq_tab_playback":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(1)
    elif button_name == "pushButton1_iq_tab_inspection":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(2)
    elif button_name == "pushButton1_iq_tab_crop":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(3)
    elif button_name == "pushButton1_iq_tab_convert":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(4)
    elif button_name == "pushButton1_iq_tab_append":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(5)
    elif button_name == "pushButton1_iq_tab_transfer":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(6)
    elif button_name == "pushButton1_iq_tab_timeslot":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(7)
    elif button_name == "pushButton1_iq_tab_overlap":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(8)
    elif button_name == "pushButton1_iq_tab_resample":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(9)
    elif button_name == "pushButton1_iq_tab_ofdm":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(10)
    elif button_name == "pushButton1_iq_tab_normalize":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(11)
    elif button_name == "pushButton1_iq_tab_strip":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(12)
    elif button_name == "pushButton1_iq_tab_split":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(13)
    elif button_name == "pushButton1_iq_tab_ook":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(14)
    elif button_name == "pushButton1_iq_tab_endianness":
        dashboard.ui.stackedWidget3_iq.setCurrentIndex(15)

    # Reset All Stylesheets
    button_list = [
        'pushButton1_iq_tab_record',
        'pushButton1_iq_tab_playback',
        'pushButton1_iq_tab_inspection',
        'pushButton1_iq_tab_crop',
        'pushButton1_iq_tab_convert',
        'pushButton1_iq_tab_append',
        'pushButton1_iq_tab_transfer',
        'pushButton1_iq_tab_timeslot',
        'pushButton1_iq_tab_overlap',
        'pushButton1_iq_tab_resample',
        'pushButton1_iq_tab_ofdm',
        'pushButton1_iq_tab_normalize',
        'pushButton1_iq_tab_strip',
        'pushButton1_iq_tab_split',
        'pushButton1_iq_tab_ook',
        'pushButton1_iq_tab_endianness'
    ]
    for n in button_list:
        exec("dashboard.ui." + n + """.setStyleSheet("QPushButton#""" + n + """ {}")""")
        # ~ exec("dashboard.ui." + n + """.setStyleSheet("QPushButton#""" + n + """ {"
                                            # ~ "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:0, y2:1, stop:0 #e7eaee, stop:0.12 #455e7d, stop:0.3 #2e4a6d,   stop:0.85 #17365D, stop:1 #17365D);"
                                            # ~ "color: rgb(255, 255, 255);"
                                            # ~ "border: 1px solid #17365D;"
                                            # ~ "border-top-left-radius: 15px;"
                                            # ~ "border-top-right-radius: 15px;"
                                            # ~ "width:107px;"
                                            # ~ "margin-top: 6px;"
                                            # ~ "height: 21px;}"
                                            # ~ )""")

    # Change Selected Stylesheet
    if dashboard.backend.settings['color_mode'] == "Light Mode":
        exec("dashboard.ui." + button_name + """.setStyleSheet("QPushButton#""" + button_name + """ {"
                                                    "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:0, y2:1, stop:0 #e7eaee, stop:0.12 #455e7d, stop:0.3 #2e4a6d, stop:0.85 """ + dashboard.backend.settings['color3'] + """, stop:1 """ + dashboard.backend.settings['color3'] + """);"
                                                    "color:rgb(0, 220, 0);"
                                                    "border: 1px solid """ + dashboard.backend.settings['color3'] + """;"
                                                    "border-top-left-radius: 15px;"
                                                    "border-top-right-radius: 15px;"
                                                    "height:27px;"
                                                    "margin-top: 3px;}"
                                                    )""")
    elif dashboard.backend.settings['color_mode'] == "Dark Mode":
        exec("dashboard.ui." + button_name + """.setStyleSheet("QPushButton#""" + button_name + """ {"
                                                    "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:0, y2:1, stop:0 """ + dashboard.backend.settings['color3'] + """, stop:0.05 #888888, stop:0.15 """ + dashboard.backend.settings['color3'] + """, stop:0.85 """ + dashboard.backend.settings['color3'] + """, stop:1 """ + dashboard.backend.settings['color3'] + """);"
                                                    "color:rgb(0, 220, 0);"
                                                    "border: 1px solid """ + dashboard.backend.settings['color3'] + """;"
                                                    "border-top-left-radius: 15px;"
                                                    "border-top-right-radius: 15px;"
                                                    "height:27px;"
                                                    "margin-top: 3px;}"
                                                    )""")
    else:
        exec("dashboard.ui." + button_name + """.setStyleSheet("QPushButton#""" + button_name + """ {"
                                                    "background-color: qlineargradient(spread:pad, x1:0, y1:0, x2:0, y2:1, stop:0 """ + dashboard.backend.settings['color3'] + """, stop:0.05 #888888, stop:0.15 """ + dashboard.backend.settings['color3'] + """, stop:0.85 """ + dashboard.backend.settings['color3'] + """, stop:1 """ + dashboard.backend.settings['color3'] + """);"
                                                    "color:rgb(0, 220, 0);"
                                                    "border: 1px solid """ + dashboard.backend.settings['color3'] + """;"
                                                    "border-top-left-radius: 15px;"
                                                    "border-top-right-radius: 15px;"
                                                    "height:27px;"
                                                    "margin-top: 3px;}"
                                                    )""")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_InspectionFlowGraphClicked(dashboard: QtCore.QObject):
    """ 
    Loads the selected inspector flow graph's default variables.
    """
    new_font = QtGui.QFont("Times", 10)  #,QtGui.QFont.Bold)

    # Flow Graph - GUI (Inspection)
    dashboard.ui.tableWidget_iq_inspection_fg_values.setRowCount(0)

    # Get the Flow Graph Filepath
    try:
        fname = str(dashboard.ui.listWidget_iq_inspection_flow_graphs.item(dashboard.ui.listWidget_iq_inspection_flow_graphs.currentRow()).text())
        fname_path = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Inspection Flow Graphs", fname)
    except:
        return
        
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_iq_inspection_hardware.currentText())
    get_hardware_type, get_hardware_uuid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'iq')

    # Read Flow Graph Variables
    try:
        f = open(fname_path,'r')
        parsing = False
        for line in f:
            if line.startswith("    def __init__(self"):
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
                            elif get_hardware_type == "RSPduo":
                                parameter_value = get_hardware_serial
                            elif get_hardware_type == "RSPdx":
                                parameter_value = get_hardware_serial
                            elif get_hardware_type == "RSPdx R2":
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
                            elif get_hardware_type == "RSPduo":
                                parameter_value = "0"
                            elif get_hardware_type == "RSPdx":
                                parameter_value = "0"
                            elif get_hardware_type == "RSPdx R2":
                                parameter_value = "0"
                            else:
                                parameter_value = "False"
                    elif parameter_name == "uuid":
                        if get_hardware_type == "CaribouLite":
                            parameter_value = get_hardware_uuid
                    else:
                        parameter_value = fg_parameters[p].lstrip(' ').split('=')[1].replace('"','')

                    # Fill in the "Current Values" Table
                    parameter_value_item = QtWidgets.QTableWidgetItem(parameter_value)
                    parameter_value_item.setFont(new_font)
                    #parameter_value_item.setFlags(parameter_value_item.flags() & ~QtCore.Qt.ItemIsEditable)
                    dashboard.ui.tableWidget_iq_inspection_fg_values.setRowCount(dashboard.ui.tableWidget_iq_inspection_fg_values.rowCount()+1)
                    dashboard.ui.tableWidget_iq_inspection_fg_values.setVerticalHeaderItem(dashboard.ui.tableWidget_iq_inspection_fg_values.rowCount()-1,parameter_name_item)
                    dashboard.ui.tableWidget_iq_inspection_fg_values.setItem(dashboard.ui.tableWidget_iq_inspection_fg_values.rowCount()-1,0,parameter_value_item)

        # Close the File
        f.close()

        # Enable the Table
        dashboard.ui.tableWidget_iq_inspection_fg_values.setEnabled(True)

        # Rename the Column Header
        header_name_item = QtWidgets.QTableWidgetItem(fname)
        header_name_item.setFont(new_font)
        dashboard.ui.tableWidget_iq_inspection_fg_values.setHorizontalHeaderItem(0,header_name_item)

        # Adjust Table
        #dashboard.ui.tableWidget_iq_inspection_fg_values.verticalHeader().setFont(new_header_font)
        #dashboard.ui.tableWidget_iq_inspection_fg_values.horizontalHeader().setFont(new_header_font)
        dashboard.ui.tableWidget_iq_inspection_fg_values.resizeRowsToContents()

    except:
        dashboard.logger.error("Error reading inspection flow graph. Recompile flow graph and try again.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_InspectionFG_FileClicked(dashboard: QtCore.QObject):
    """ 
    Loads the selected Inspection File flow graph's default variables.
    """
    new_font = QtGui.QFont("Times",10)

    # Flow Graph - GUI (Inspection)
    dashboard.ui.tableWidget_iq_inspection_fg_file_values.setRowCount(0)

    # Get the Flow Graph Filepath
    try:
        fname = str(dashboard.ui.listWidget_iq_inspection_fg_file.item(dashboard.ui.listWidget_iq_inspection_fg_file.currentRow()).text())
        fname_path = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Inspection Flow Graphs", "File", fname)
    except:
        return

    # Read Flow Graph Variables
    f = open(fname_path,'r')
    parsing = False
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
                parameter_value = fg_parameters[p].lstrip(' ').split('=')[1].replace('"','')

                # Fill in Filepath from Loaded IQ File
                if parameter_name == "filepath":
                    try:
                        if len(str(dashboard.ui.listWidget_iq_files.currentItem().text())) > 0:
                            parameter_value = str(dashboard.ui.label_iq_folder.text() + "/" + dashboard.ui.listWidget_iq_files.currentItem().text())
                        else:
                            parameter_value = ""
                    except:
                        parameter_value = ""

                elif (parameter_name == "sample-rate") or (parameter_name == "samp-rate"):
                    if len(str(dashboard.ui.textEdit_iq_sample_rate.toPlainText())) > 0:
                        parameter_value = str(dashboard.ui.textEdit_iq_sample_rate.toPlainText()) + "e6"
                    else:
                        parameter_value = "1e6"

                # Fill in the "Current Values" Table
                parameter_value_item = QtWidgets.QTableWidgetItem(parameter_value)
                parameter_value_item.setFont(new_font)
                dashboard.ui.tableWidget_iq_inspection_fg_file_values.setRowCount(dashboard.ui.tableWidget_iq_inspection_fg_file_values.rowCount()+1)
                dashboard.ui.tableWidget_iq_inspection_fg_file_values.setVerticalHeaderItem(dashboard.ui.tableWidget_iq_inspection_fg_file_values.rowCount()-1,parameter_name_item)
                dashboard.ui.tableWidget_iq_inspection_fg_file_values.setItem(dashboard.ui.tableWidget_iq_inspection_fg_file_values.rowCount()-1,0,parameter_value_item)

    # Close the File
    f.close()

    # Enable the Table
    dashboard.ui.tableWidget_iq_inspection_fg_file_values.setEnabled(True)

    # Rename the Column Header
    header_name_item = QtWidgets.QTableWidgetItem(fname)
    header_name_item.setFont(new_font)
    dashboard.ui.tableWidget_iq_inspection_fg_file_values.setHorizontalHeaderItem(0,header_name_item)

    # Adjust Table
    dashboard.ui.tableWidget_iq_inspection_fg_file_values.resizeRowsToContents()


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

    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_iq_playback_hardware.currentText())
    get_hardware_type, get_hardware_uuid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'iq')
    
    # Playback
    dashboard.ui.textEdit_iq_playback_filepath.setPlainText(get_file_path)
    get_antennas = fissure.utils.hardware.getHardwareAntennas(get_hardware_type, "TX")
    if get_antennas:  # Transmit-Only
        dashboard.ui.frame_iq_playback_controls.setEnabled(True)

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
def _slotIQ_PlaybackRecordFreqClicked(dashboard: QtCore.QObject):
    """ 
    Copies the frequency value from the Record tab table to the Playback tab table.
    """
    # Get Record Table Value
    try:
        get_frequency = float(dashboard.ui.tableWidget_iq_record.cellWidget(0,1).value())
    except:
        get_frequency = float(dashboard.ui.tableWidget_iq_record.item(0,1).text())

    # Copy to Playback Table
    dashboard.ui.tableWidget_iq_playback.cellWidget(0,0).setValue(get_frequency)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlaybackRecordGainClicked(dashboard: QtCore.QObject):
    """ 
    Copies the gain value from the Record tab table to the Playback tab table.
    """
    # Get Record Table Value
    try:
        get_gain = float(dashboard.ui.tableWidget_iq_record.cellWidget(0,4).value())
    except:
        get_gain = float(dashboard.ui.tableWidget_iq_record.item(0,4).text())

    # Copy to Playback Table
    dashboard.ui.tableWidget_iq_playback.cellWidget(0,3).setValue(get_gain)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_PlaybackRecordRateClicked(dashboard: QtCore.QObject):
    """ 
    Copies the sampling rate value from the Record tab table to the Playback tab table.
    """
    # Get Record Table Value
    get_sample_rate = str(dashboard.ui.tableWidget_iq_record.item(0,7).text())

    # Make New Item
    sample_rate_item = QtWidgets.QTableWidgetItem(get_sample_rate)
    sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)

    # Copy to Playback Table
    dashboard.ui.tableWidget_iq_playback.setItem(0,4,sample_rate_item)


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
def _slotIQ_InspectionFG_LiveViewClicked(dashboard: QtCore.QObject):
    """ 
    Open the selected Inspection Live flow graph in GNU Radio Companion
    """
    # Get the Flow Graph Filepath
    try:
        fname = str(dashboard.ui.listWidget_iq_inspection_flow_graphs.item(dashboard.ui.listWidget_iq_inspection_flow_graphs.currentRow()).text())
        fname_path = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Inspection Flow Graphs", fname)
        fname_path = fname_path.replace('.py','.grc')
    except:
        return

    # Open the Flow Graph in GNU Radio Companion
    osCommandString = 'gnuradio-companion "' + fname_path + '"'
    os.system(osCommandString+ " &")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_InspectionFG_FileViewClicked(dashboard: QtCore.QObject):
    """ 
    Open the selected Inspection File flow graph in GNU Radio Companion
    """
    # Get the Flow Graph Filepath
    try:
        fname = str(dashboard.ui.listWidget_iq_inspection_fg_file.item(dashboard.ui.listWidget_iq_inspection_fg_file.currentRow()).text())
        fname_path = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Inspection Flow Graphs", "File", fname)
        fname_path = fname_path.replace('.py','.grc')
    except:
        return

    # Open the Flow Graph in GNU Radio Companion
    osCommandString = 'gnuradio-companion "' + fname_path + '"'
    os.system(osCommandString+ " &")


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
def _slotIQ_RecordSigMF_ConfigureClicked(dashboard: QtCore.QObject):
    """ 
    Opens a dialog for configuring SigMF metadata values.
    """
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_iq_record_hardware.currentText())
    get_hardware_type, get_hardware_uuid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'iq')
    
    # Copy Values from Table
    # Sample Rate
    try:
        get_widget = dashboard.ui.tableWidget_iq_record.cellWidget(0,7)
        if get_widget == None:
            get_sample_rate = str(float(str(dashboard.ui.tableWidget_iq_record.item(0,7).text()))*1000000)
        else:
            get_sample_rate = str(float(str(dashboard.ui.tableWidget_iq_record.cellWidget(0,7).currentText()))*1000000)
    except:
        get_sample_rate = None

    # Hardware
    try:
        get_hw = get_hardware_type
    except:
        get_hw = None

    # File
    try:
        get_dataset = str(dashboard.ui.tableWidget_iq_record.item(0,0).text())
    except:
        get_dataset = None

    # Frequency
    try:
        get_widget = dashboard.ui.tableWidget_iq_record.cellWidget(0,1)
        if get_widget == None:
            get_frequency = str(float(str(dashboard.ui.tableWidget_iq_record.item(0,1).text()))*1000000)
        else:
            get_frequency = str(float(str(dashboard.ui.tableWidget_iq_record.cellWidget(0,1).value()))*1000000)
    except:
        get_frequency = None

    # Create Default Dictionary
    dlg = fissure.Dashboard.UI_Components.Qt5.SigMF_Dialog(dashboard, sample_rate=get_sample_rate, hw=get_hw, dataset=get_dataset, frequency=get_frequency, settings_dictionary = dashboard.sigmf_dict)
    dlg.show()
    dlg.exec_()

    # OK Clicked
    get_value = dlg.return_value
    if len(get_value) > 0:
        dashboard.sigmf_dict = dlg.settings_dictionary


def reset_iq_record_controls(
    dashboard: QtCore.QObject,
    status_text: str = "Idle",
    clear_pending: bool = True,
):
    dashboard.iq_file_counter = 0

    if clear_pending:
        dashboard.iq_record_pending_operation_id = ""
        dashboard.iq_record_pending_node_uid = ""
        dashboard.iq_record_pending_started_at = 0
        dashboard.iq_record_pending_base_file_name = ""

    dashboard.ui.pushButton_iq_record.setText("Record")
    dashboard.ui.pushButton_iq_record.setEnabled(True)
    dashboard.ui.label2_iq_status_files.setText(status_text)


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_RecordClicked(dashboard: QtCore.QObject, called_from_thread=False):
    """
    Starts/stops IQ recording through the Base plugin action path.

    First-pass behavior:
      - Dashboard collects the existing IQ Record table values.
      - Sends Base.iq_record to the selected Sensor Node.
      - Plugin operation handles the actual flow graph launch and artifact creation.
      - Stop requests all plugin operations stop on the selected node for now.
    """

    # ------------------------------------------------------------
    # Stop Recording
    # ------------------------------------------------------------
    if dashboard.ui.pushButton_iq_record.text() == "Stop":
        dashboard.ui.label2_iq_status_files.setText("Stopping...")
        dashboard.ui.pushButton_iq_record.setEnabled(False)

        try:
            await dashboard.backend.tacticalNodeStop(
                [dashboard.selected_node_uid]
            )
        except Exception as e:
            dashboard.logger.error(f"[IQ] Failed stopping IQ record operation: {e}")

        reset_iq_record_controls(
            dashboard,
            status_text="Stopped",
            clear_pending=True,
        )

        try:
            _slotIQ_ArtifactsRefreshClicked(dashboard)
        except Exception as e:
            dashboard.logger.warning(
                f"[IQ] Failed refreshing artifacts after IQ record stop: {e}"
            )

        # dashboard.refreshStatusBarText()
        return

    # ------------------------------------------------------------
    # Start Recording
    # ------------------------------------------------------------
    if not dashboard.selected_node_uid:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "No sensor node selected.",
        )
        return

    if dashboard.ui.pushButton_iq_record.text() != "Record":
        return

    if dashboard.iq_file_counter == 0:
        dashboard.iq_file_counter = 1

    if dashboard.iq_file_counter <= 0:
        return

    # ------------------------------------------------------------
    # Sensor Node Hardware Information
    # ------------------------------------------------------------
    get_current_hardware = str(dashboard.ui.comboBox_iq_record_hardware.currentText())

    (
        get_hardware_type,
        get_hardware_uuid,
        get_hardware_radio_name,
        get_hardware_serial,
        get_hardware_interface,
        get_hardware_ip,
        get_hardware_daughterboard,
    ) = fissure.utils.hardware.hardwareDisplayNameLookup(
        dashboard,
        get_current_hardware,
        "iq",
    )

    # ------------------------------------------------------------
    # Read and Validate UI Values
    # ------------------------------------------------------------
    try:
        get_base_file_name = str(dashboard.ui.tableWidget_iq_record.item(0, 0).text()).strip()

        try:
            get_frequency = str(dashboard.ui.tableWidget_iq_record.cellWidget(0, 1).value())
        except Exception:
            get_frequency = str(dashboard.ui.tableWidget_iq_record.item(0, 1).text()).strip()

        get_channel = str(dashboard.ui.tableWidget_iq_record.cellWidget(0, 2).currentText()).strip()
        get_antenna = str(dashboard.ui.tableWidget_iq_record.cellWidget(0, 3).currentText()).strip()

        try:
            get_gain = str(dashboard.ui.tableWidget_iq_record.cellWidget(0, 4).value())
        except Exception:
            get_gain = str(dashboard.ui.tableWidget_iq_record.item(0, 4).text()).strip()

        try:
            get_number_of_files = str(dashboard.ui.tableWidget_iq_record.cellWidget(0, 5).value())
        except Exception:
            get_number_of_files = str(dashboard.ui.tableWidget_iq_record.item(0, 5).text()).strip()

        get_file_length = str(dashboard.ui.tableWidget_iq_record.item(0, 6).text()).strip()

        try:
            get_sample_rate = str(dashboard.ui.tableWidget_iq_record.cellWidget(0, 7).currentText()).strip()
        except Exception:
            get_sample_rate = str(dashboard.ui.tableWidget_iq_record.item(0, 7).text()).strip()

        get_data_type = str(dashboard.ui.tableWidget_iq_record.cellWidget(0, 8).currentText()).strip()
        get_file_interval = str(dashboard.ui.tableWidget_iq_record.item(0, 9).text()).strip()

        # Validate conversions.
        frequency_mhz = float(get_frequency)
        gain = float(get_gain)
        number_of_files = int(get_number_of_files)
        file_length = int(get_file_length)
        sample_rate_mhz = float(get_sample_rate)
        file_interval = float(get_file_interval)

        valid_freq = fissure.utils.hardware.checkFrequencyBounds(
            frequency_mhz,
            get_hardware_type,
            get_hardware_daughterboard,
        )

        if valid_freq is False:
            dashboard.iq_file_counter = 0
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                "Frequency outside of hardware bounds.",
            )
            return

        if number_of_files < 1:
            dashboard.iq_file_counter = 0
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                "Number of files must be >= 1.",
            )
            return

        if file_length < 1:
            dashboard.iq_file_counter = 0
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                "File length must be >= 1.",
            )
            return

        if file_interval < 0:
            dashboard.iq_file_counter = 0
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                "File interval must be positive.",
            )
            return

    except Exception:
        dashboard.iq_file_counter = 0
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Invalid input parameter.",
        )
        return

    # ------------------------------------------------------------
    # Flow Graph Name from Hardware
    # Keep this for the plugin operation so the Dashboard still chooses
    # the same recorder family as the legacy path.
    # ------------------------------------------------------------
    if get_hardware_type == "Computer":
        fname = "iq_recorder"
    elif get_hardware_type == "USRP X3x0":
        fname = "iq_recorder_x3x0"
    elif get_hardware_type == "USRP B2x0":
        fname = "iq_recorder_b2x0"
    elif get_hardware_type == "HackRF":
        fname = "iq_recorder_hackrf"
    elif get_hardware_type == "RTL2832U":
        fname = "iq_recorder_rtl2832u"
    elif get_hardware_type == "802.11x Adapter":
        fname = "iq_recorder"
    elif get_hardware_type == "USRP B20xmini":
        fname = "iq_recorder_b2x0"
    elif get_hardware_type == "LimeSDR":
        fname = "iq_recorder_limesdr"
    elif get_hardware_type == "bladeRF":
        fname = "iq_recorder_bladerf"
    elif get_hardware_type == "Open Sniffer":
        fname = "iq_recorder"
    elif get_hardware_type == "PlutoSDR":
        fname = "iq_recorder_plutosdr"
    elif get_hardware_type == "USRP2":
        fname = "iq_recorder_usrp2"
    elif get_hardware_type == "USRP N2xx":
        fname = "iq_recorder_usrp_n2xx"
    elif get_hardware_type == "bladeRF 2.0":
        fname = "iq_recorder_bladerf2"
    elif get_hardware_type == "USRP X410":
        fname = "iq_recorder_usrp_x410"
    elif get_hardware_type == "RSPduo":
        fname = "iq_recorder_rspduo"
    elif get_hardware_type == "RSPdx":
        fname = "iq_recorder_rspdx"
    elif get_hardware_type == "RSPdx R2":
        fname = "iq_recorder_rspdx_r2"
    elif get_hardware_type == "CaribouLite":
        fname = "iq_recorder_cariboulite"
    else:
        fname = "iq_recorder"

    # LimeSDR channel normalization.
    if get_hardware_type == "LimeSDR":
        if get_channel == "A":
            get_channel = "0"
        elif get_channel == "B":
            get_channel = "1"

    # ------------------------------------------------------------
    # Hardware Serial Formatting
    # Preserve the old serial argument behavior for flow graph support.
    # ------------------------------------------------------------
    if len(get_hardware_serial) > 0:
        if get_hardware_type in [
            "HackRF",
            "bladeRF",
            "bladeRF 2.0",
            "RSPduo",
            "RSPdx",
            "RSPdx R2",
        ]:
            get_serial = get_hardware_serial
        else:
            get_serial = "serial=" + get_hardware_serial
    else:
        if get_hardware_type == "HackRF":
            get_serial = ""
        elif get_hardware_type in [
            "bladeRF",
            "bladeRF 2.0",
            "RSPduo",
            "RSPdx",
            "RSPdx R2",
        ]:
            get_serial = "0"
        else:
            get_serial = "False"

    # ------------------------------------------------------------
    # Artifact Format
    # ------------------------------------------------------------
    artifact_format_text = dashboard.ui.comboBox_iq_record_artifact_format.currentText().strip()

    artifact_format = {
        "Raw IQ File": "raw",
        "Zip Bundle": "zip",
    }.get(artifact_format_text, "raw")

    # ------------------------------------------------------------
    # SigMF Timestamp Update
    # ------------------------------------------------------------
    try:
        if "core:datetime" in dashboard.sigmf_dict["captures"][0]:
            iq_record_timestamp = datetime.datetime.utcnow().isoformat("T") + "Z"
            dashboard.sigmf_dict["captures"][0]["core:datetime"] = str(iq_record_timestamp)
    except Exception:
        pass

    # Copy SigMF metadata so plugin-side changes do not mutate Dashboard state.
    try:
        sigmf_metadata = json.loads(json.dumps(dashboard.sigmf_dict))
    except Exception:
        sigmf_metadata = {}

    # Remember File Name for Multiple File Recordings on First Attempt.
    # The plugin should handle number_of_files now, but keeping this avoids
    # breaking status logic that still looks at this value.
    if dashboard.iq_file_counter == 1:
        dashboard.iq_first_file_name = get_base_file_name

    # ------------------------------------------------------------
    # Plugin Action Parameters
    # ------------------------------------------------------------
    operation_id = str(uuid.uuid4())

    # Track only the IQ recording started from this Dashboard's IQ Data tab.
    # This prevents IQ artifacts launched from Tactical, TAK, another Dashboard,
    # or automation from resetting this local IQ Record UI.
    dashboard.iq_record_pending_operation_id = operation_id
    dashboard.iq_record_pending_node_uid = dashboard.selected_node_uid
    dashboard.iq_record_pending_started_at = time.time()
    dashboard.iq_record_pending_base_file_name = get_base_file_name

    parameters = {
        # Request identity / completion correlation
        "operation_id": operation_id,
        "requester": "iq_data_tab",

        # Legacy-ish recorder selection
        "flow_graph_name": fname,

        # File/output
        "base_file_name": get_base_file_name,
        "artifact_format": artifact_format,

        # Hardware identity
        "hardware_display_name": get_current_hardware,
        "hardware_type": get_hardware_type,
        "hardware_uuid": get_hardware_uuid,
        "hardware_radio_name": get_hardware_radio_name,
        "hardware_serial": get_hardware_serial,
        "hardware_serial_argument": get_serial,
        "hardware_interface": get_hardware_interface,
        "hardware_ip": get_hardware_ip,
        "hardware_daughterboard": get_hardware_daughterboard,

        # RF / recorder parameters
        "frequency_mhz": frequency_mhz,
        "rx_frequency": get_frequency,
        "rx_channel": get_channel,
        "rx_antenna": get_antenna,
        "rx_gain": gain,
        "sample_rate_mhz": sample_rate_mhz,
        "sample_rate": get_sample_rate,
        "file_length": file_length,
        "number_of_files": number_of_files,
        "file_interval": file_interval,
        "data_type": get_data_type,

        # Metadata
        "sigmf_enabled": bool(dashboard.ui.checkBox_iq_record_sigmf.isChecked()),
        "sigmf_metadata": sigmf_metadata,
    }

    # ------------------------------------------------------------
    # Send Plugin Action
    # ------------------------------------------------------------
    await dashboard.backend.tacticalNodeExecute(
        [dashboard.selected_node_uid],
        "Base",
        "iq_record",
        parameters,
    )

    # ------------------------------------------------------------
    # UI State
    # ------------------------------------------------------------
    dashboard.ui.label2_iq_status_files.setText("Starting...")
    dashboard.ui.pushButton_iq_record.setText("Stop")
    dashboard.ui.pushButton_iq_record.setEnabled(True)

    # if dashboard.selected_node_uid:
    #     dashboard.refreshStatusBarText()


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_PlaybackClicked(dashboard: QtCore.QObject):
    """
    Starts/stops IQ playback through the Base plugin action path.

    First-pass behavior:
      - Dashboard collects existing IQ Playback table values.
      - Sends Base.iq_playback to the selected Sensor Node.
      - node_path mode uses the filepath as it exists on the executing node.
      - transfer mode stages the Dashboard-local file to the selected node first.
      - Stop requests plugin operation stop on the selected node.
    """

    # ------------------------------------------------------------
    # Stop Playback
    # ------------------------------------------------------------
    if dashboard.ui.pushButton_iq_playback.text() == "Stop":
        dashboard.ui.label2_iq_playback_status.setText("Stopping...")
        dashboard.ui.pushButton_iq_playback.setEnabled(False)
        QtWidgets.QApplication.processEvents()

        try:
            await dashboard.backend.tacticalNodeStop(
                [dashboard.selected_node_uid]
            )
        except Exception as e:
            dashboard.logger.error(f"[IQ] Failed stopping IQ playback operation: {e}")

        dashboard.ui.label2_iq_playback_status.setText("")
        dashboard.ui.pushButton_iq_playback.setText("Play")
        dashboard.ui.pushButton_iq_playback.setEnabled(True)

        # await dashboard.refreshStatusBarText()
        return

    # ------------------------------------------------------------
    # Start Playback
    # ------------------------------------------------------------
    if dashboard.ui.pushButton_iq_playback.text() != "Play":
        return

    if not dashboard.selected_node_uid:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Select a sensor node.",
        )
        return

    # ------------------------------------------------------------
    # Initial UI State
    # ------------------------------------------------------------
    dashboard.ui.label2_iq_playback_status.setText("Starting...")
    dashboard.ui.pushButton_iq_playback.setText("Stop")
    dashboard.ui.pushButton_iq_playback.setEnabled(False)
    # await dashboard.refreshStatusBarText()
    QtWidgets.QApplication.processEvents()

    # ------------------------------------------------------------
    # Sensor Node Hardware Information
    # ------------------------------------------------------------
    get_current_hardware = str(
        dashboard.ui.comboBox_iq_playback_hardware.currentText()
    ).strip()

    (
        get_hardware_type,
        get_hardware_uuid,
        get_hardware_radio_name,
        get_hardware_serial,
        get_hardware_interface,
        get_hardware_ip,
        get_hardware_daughterboard,
    ) = fissure.utils.hardware.hardwareDisplayNameLookup(
        dashboard,
        get_current_hardware,
        "iq",
    )

    # ------------------------------------------------------------
    # Read and Validate UI Values
    # ------------------------------------------------------------
    try:
        try:
            get_frequency = str(
                dashboard.ui.tableWidget_iq_playback.cellWidget(0, 0).value()
            ).strip()
        except Exception:
            get_frequency = str(
                dashboard.ui.tableWidget_iq_playback.item(0, 0).text()
            ).strip()

        get_channel = str(
            dashboard.ui.tableWidget_iq_playback.cellWidget(0, 1).currentText()
        ).strip()

        get_antenna = str(
            dashboard.ui.tableWidget_iq_playback.cellWidget(0, 2).currentText()
        ).strip()

        try:
            get_gain = str(
                dashboard.ui.tableWidget_iq_playback.cellWidget(0, 3).value()
            ).strip()
        except Exception:
            get_gain = str(
                dashboard.ui.tableWidget_iq_playback.item(0, 3).text()
            ).strip()

        try:
            get_sample_rate = str(
                dashboard.ui.tableWidget_iq_playback.cellWidget(0, 4).currentText()
            ).strip()
        except Exception:
            get_sample_rate = str(
                dashboard.ui.tableWidget_iq_playback.item(0, 4).text()
            ).strip()

        get_data_type = str(
            dashboard.ui.tableWidget_iq_playback.cellWidget(0, 5).currentText()
        ).strip()

        get_repeat = str(
            dashboard.ui.tableWidget_iq_playback.cellWidget(0, 6).currentText()
        ).strip()

        get_filepath = str(
            dashboard.ui.textEdit_iq_playback_filepath.toPlainText()
        ).strip()

        playback_file_mode_text = str(
            dashboard.ui.comboBox_iq_playback_file_mode.currentText()
        ).strip()

        playback_file_mode = {
            "Node Path": "node_path",
            "Transfer": "transfer",
        }.get(playback_file_mode_text, "node_path")

        dashboard.logger.info(
            f"[IQ] Playback file mode selected: "
            f"text={playback_file_mode_text!r}, mode={playback_file_mode!r}"
        )

        frequency_mhz = float(get_frequency)
        tx_gain = float(get_gain)
        sample_rate_msps = float(get_sample_rate)

        if not get_filepath:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                "Select an IQ playback file.",
            )
            raise ValueError("Missing IQ playback filepath.")

        valid_freq = fissure.utils.hardware.checkFrequencyBounds(
            frequency_mhz,
            get_hardware_type,
            get_hardware_daughterboard,
        )

        if valid_freq is False:
            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                "Frequency outside of hardware bounds.",
            )
            raise ValueError("Frequency outside of hardware bounds.")

    except Exception as e:
        dashboard.logger.error(f"[IQ] Invalid playback input parameter: {e}")

        dashboard.ui.label2_iq_playback_status.setText("")
        dashboard.ui.pushButton_iq_playback.setText("Play")
        dashboard.ui.pushButton_iq_playback.setEnabled(True)
        # await dashboard.refreshStatusBarText()
        return

    # ------------------------------------------------------------
    # First-pass Flow Graph Name from Hardware / Repeat
    # ------------------------------------------------------------
    if get_hardware_type in {"USRP B2x0", "USRP B20xmini"}:
        if get_repeat == "No":
            fname = "iq_playback_single_b2x0"
        else:
            fname = "iq_playback_b2x0"
    else:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            f"Unsupported IQ playback hardware for first pass: {get_hardware_type}",
        )

        dashboard.ui.label2_iq_playback_status.setText("")
        dashboard.ui.pushButton_iq_playback.setText("Play")
        dashboard.ui.pushButton_iq_playback.setEnabled(True)
        # await dashboard.refreshStatusBarText()
        return

    # ------------------------------------------------------------
    # Hardware Serial Formatting
    # Preserve old UHD serial behavior.
    # ------------------------------------------------------------
    if len(get_hardware_serial) > 0:
        get_serial = "serial=" + get_hardware_serial
    else:
        get_serial = "False"

    # ------------------------------------------------------------
    # Optional File Transfer
    # ------------------------------------------------------------
    action_filepath = get_filepath

    if playback_file_mode == "transfer":
        try:
            await dashboard.backend.transferSensorNodeFile(
                dashboard.selected_node_uid,
                get_filepath,
                "/IQ_Data_Playback",
                False,
            )

            # Must match SensorNodeCallbacks.transferSensorNodeFile(), which
            # saves /IQ_Data_Playback as Sensor_Node/IQ_Data_Playback/playback.iq.
            action_filepath = os.path.join(
                fissure.utils.SENSOR_NODE_DIR,
                "IQ_Data_Playback",
                "playback.iq",
            )

        except Exception as e:
            dashboard.logger.error(f"[IQ] Failed transferring IQ playback file: {e}")

            await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
                dashboard,
                "Failed to transfer IQ playback file to selected node.",
            )

            dashboard.ui.label2_iq_playback_status.setText("")
            dashboard.ui.pushButton_iq_playback.setText("Play")
            dashboard.ui.pushButton_iq_playback.setEnabled(True)
            # await dashboard.refreshStatusBarText()
            return

    # ------------------------------------------------------------
    # Plugin Action Parameters
    # ------------------------------------------------------------
    operation_id = str(uuid.uuid4())

    parameters = {
        # Request identity
        "operation_id": operation_id,
        "requester": "iq_data_tab",

        # Playback selection
        "flow_graph_name": fname,
        "playback_file_mode": playback_file_mode,
        "filepath": action_filepath,

        # Hardware identity
        "hardware_display_name": get_current_hardware,
        "hardware_type": get_hardware_type,
        "hardware_uuid": get_hardware_uuid,
        "hardware_radio_name": get_hardware_radio_name,
        "hardware_serial": get_hardware_serial,
        "hardware_serial_argument": get_serial,
        "hardware_interface": get_hardware_interface,
        "hardware_ip": get_hardware_ip,
        "hardware_daughterboard": get_hardware_daughterboard,

        # RF / playback parameters
        "frequency_mhz": frequency_mhz,
        "tx_frequency": frequency_mhz,
        "tx_channel": get_channel,
        "tx_antenna": get_antenna,
        "tx_gain": tx_gain,
        "sample_rate_msps": sample_rate_msps,
        "data_type": get_data_type,

        # Metadata / logging
        "description": "IQ playback",
    }

    # ------------------------------------------------------------
    # Send Plugin Action
    # ------------------------------------------------------------
    try:
        await dashboard.backend.tacticalNodeExecute(
            [dashboard.selected_node_uid],
            "Base",
            "iq_playback",
            parameters,
        )

    except Exception as e:
        dashboard.logger.error(f"[IQ] Failed launching IQ playback action: {e}")

        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Failed to launch IQ playback action.",
        )

        dashboard.ui.label2_iq_playback_status.setText("")
        dashboard.ui.pushButton_iq_playback.setText("Play")
        dashboard.ui.pushButton_iq_playback.setEnabled(True)
        # await dashboard.refreshStatusBarText()
        return

    # ------------------------------------------------------------
    # UI State
    # ------------------------------------------------------------
    dashboard.ui.label2_iq_playback_status.setText("Starting...")
    dashboard.ui.pushButton_iq_playback.setText("Stop")
    dashboard.ui.pushButton_iq_playback.setEnabled(True)

    # await dashboard.refreshStatusBarText()
    

@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_InspectionFG_StartClicked(dashboard: QtCore.QObject):
    """ 
    Starts the inspection flow graph.
    """
    # Stop Flow Graph
    if dashboard.ui.pushButton_iq_inspection_fg_start.text() == "Stop":
        # Send Message
        await dashboard.backend.inspectionFlowGraphStop(dashboard.selected_node_uid, 'Flow Graph - GUI')

        # Toggle the Text
        dashboard.ui.pushButton_iq_inspection_fg_start.setText("Start")

        # Enable Attack Switching
        dashboard.ui.listWidget_iq_inspection_flow_graphs.setEnabled(True)
        dashboard.ui.pushButton_iq_inspection_fg_load.setEnabled(True)

    # Start Flow Graph
    elif (dashboard.ui.pushButton_iq_inspection_fg_start.text() == "Start") and (dashboard.ui.pushButton_iq_inspection_fg_file_start.text() == "Start"):

        # Send Message(s) to the HIPRFISR for each Variable Name and Value
        variable_names = []
        variable_values = []
        for get_row in range(0,dashboard.ui.tableWidget_iq_inspection_fg_values.rowCount()):
            # Save the Variable Name in the Row to a Dictionary
            get_name = str(dashboard.ui.tableWidget_iq_inspection_fg_values.verticalHeaderItem(get_row).text())
            variable_names.append(get_name)
            variable_values.append(str(dashboard.ui.tableWidget_iq_inspection_fg_values.item(get_row,0).text()))

        try:
            # Get the Flow Graph Filepath
            fname = str(dashboard.ui.tableWidget_iq_inspection_fg_values.horizontalHeaderItem(0).text())
            fname = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Inspection Flow Graphs", fname)
        except:
            return

        # Send "Run Inspection Flow Graph" Message to the HIPRFISR
        get_file_type = "Flow Graph - GUI"
        await dashboard.backend.inspectionFlowGraphStart(dashboard.selected_node_uid, fname, variable_names, variable_values, get_file_type)

        # Toggle the Text
        dashboard.ui.pushButton_iq_inspection_fg_start.setText("Stop")

        # Disable Attack Switching
        dashboard.ui.listWidget_iq_inspection_flow_graphs.setEnabled(False)
        dashboard.ui.pushButton_iq_inspection_fg_load.setEnabled(False)


@qasync.asyncSlot(QtCore.QObject)
async def _slotIQ_InspectionFG_FileStartClicked(dashboard: QtCore.QObject):
    """ 
    Starts the Inspection File flow graph.
    """
    # Stop Flow Graph
    if dashboard.ui.pushButton_iq_inspection_fg_file_start.text() == "Stop":
        # Send Message
        await dashboard.backend.inspectionFlowGraphStop(dashboard.selected_node_uid, 'Flow Graph - GUI')

        # Toggle the Text
        dashboard.ui.pushButton_iq_inspection_fg_file_start.setText("Start")

        # Enable Attack Switching
        dashboard.ui.listWidget_iq_inspection_fg_file.setEnabled(True)
        dashboard.ui.pushButton_iq_inspection_fg_file_load.setEnabled(True)

    # Start Flow Graph
    elif (dashboard.ui.pushButton_iq_inspection_fg_file_start.text() == "Start") and (dashboard.ui.pushButton_iq_inspection_fg_start.text() == "Start") and \
        (len(str(dashboard.ui.tableWidget_iq_inspection_fg_file_values.horizontalHeaderItem(0).text())) > 0):

        # Send Message(s) to the HIPRFISR for each Variable Name and Value
        variable_names = []
        variable_values = []
        for get_row in range(0,dashboard.ui.tableWidget_iq_inspection_fg_file_values.rowCount()):
            # Save the Variable Name in the Row to a Dictionary
            get_name = str(dashboard.ui.tableWidget_iq_inspection_fg_file_values.verticalHeaderItem(get_row).text())
            variable_names.append(get_name)
            variable_values.append(str(dashboard.ui.tableWidget_iq_inspection_fg_file_values.item(get_row,0).text()))

        try:
            # Get the Flow Graph Filepath
            fname = str(dashboard.ui.tableWidget_iq_inspection_fg_file_values.horizontalHeaderItem(0).text())
            fname = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "Inspection Flow Graphs", "File", fname)
        except:
            return

        # Send "Run Inspection Flow Graph" Message to the HIPRFISR
        get_file_type = "Flow Graph - GUI"
        await dashboard.backend.inspectionFlowGraphStart(dashboard.selected_node_uid, fname, variable_names, variable_values, get_file_type)

        # Toggle the Text
        dashboard.ui.pushButton_iq_inspection_fg_file_start.setText("Stop")

        # Disable Attack Switching
        dashboard.ui.listWidget_iq_inspection_fg_file.setEnabled(False)
        dashboard.ui.pushButton_iq_inspection_fg_file_load.setEnabled(False)


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
        dashboard.ui.tabWidget.setCurrentIndex(2)
        dashboard.ui.tabWidget_protocol.setCurrentIndex(3)
        
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
def _slotIQ_ArtifactsRefreshClicked(dashboard: QtCore.QObject):
    """
    Refreshes the IQ Data Artifacts combo box from local unpacked artifacts.

    Expected local layout:
        FISSURE/artifacts/<artifact_id>/files/<artifact files>
    """
    combo = dashboard.ui.comboBox_iq_artifacts
    file_list = dashboard.ui.listWidget_iq_artifacts_files

    previous_artifact_dir = None
    try:
        current_data = combo.currentData(QtCore.Qt.UserRole)
        if isinstance(current_data, dict):
            previous_artifact_dir = current_data.get("artifact_dir")
    except Exception:
        previous_artifact_dir = None

    combo.blockSignals(True)
    combo.clear()
    file_list.clear()

    artifacts_root = fissure.utils.HUB_ARTIFACTS_DIR

    if not os.path.isdir(artifacts_root):
        combo.blockSignals(False)
        dashboard.logger.warning(f"[IQ] Artifacts folder not found: {artifacts_root}")
        return

    artifacts = []

    try:
        for artifact_name in os.listdir(artifacts_root):
            artifact_dir = os.path.join(artifacts_root, artifact_name)

            if not os.path.isdir(artifact_dir):
                continue

            files_dir = _iq_get_artifact_files_dir(artifact_dir)

            if not os.path.isdir(files_dir):
                continue

            # Only include artifact folders that have at least one regular file.
            has_files = any(
                os.path.isfile(os.path.join(files_dir, fname))
                for fname in os.listdir(files_dir)
            )
            if not has_files:
                continue

            try:
                sort_time = os.path.getmtime(files_dir)
            except Exception:
                sort_time = 0

            display_name = _iq_format_artifact_combo_name(artifact_name, files_dir)

            artifacts.append(
                (
                    sort_time,
                    display_name,
                    {
                        "artifact_name": artifact_name,
                        "artifact_dir": artifact_dir,
                        "files_dir": files_dir,
                    },
                )
            )

    except Exception as e:
        combo.blockSignals(False)
        dashboard.logger.error(f"[IQ] Failed refreshing artifacts: {e}")
        return

    # Newest first
    artifacts.sort(key=lambda item: item[0], reverse=True)

    restore_index = -1

    for _, display_name, artifact_data in artifacts:
        combo.addItem(display_name, artifact_data)
        index = combo.count() - 1

        combo.setItemData(
            index,
            artifact_data["artifact_dir"],
            QtCore.Qt.ToolTipRole,
        )

        if previous_artifact_dir and artifact_data["artifact_dir"] == previous_artifact_dir:
            restore_index = index

    if combo.count() > 0:
        if restore_index >= 0:
            combo.setCurrentIndex(restore_index)
        else:
            combo.setCurrentIndex(0)

    combo.blockSignals(False)

    _slotIQ_ArtifactsChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotIQ_ArtifactsChanged(dashboard: QtCore.QObject):
    """
    Populates the IQ Data artifact file list from the selected local artifact folder.
    """
    combo = dashboard.ui.comboBox_iq_artifacts
    file_list = dashboard.ui.listWidget_iq_artifacts_files

    file_list.clear()

    artifact_data = combo.currentData(QtCore.Qt.UserRole)

    if not isinstance(artifact_data, dict):
        return

    files_dir = artifact_data.get("files_dir", "")

    if not files_dir or not os.path.isdir(files_dir):
        return

    try:
        file_names = []

        for fname in os.listdir(files_dir):
            full_path = os.path.join(files_dir, fname)

            if os.path.isfile(full_path):
                file_names.append(fname)

        file_names = sorted(file_names, key=str.lower)

        for fname in file_names:
            full_path = os.path.join(files_dir, fname)

            item = QtWidgets.QListWidgetItem(fname)
            item.setData(QtCore.Qt.UserRole, full_path)
            item.setToolTip(full_path)

            file_list.addItem(item)

        if file_list.count() > 0:
            file_list.setCurrentRow(0)

    except Exception as e:
        dashboard.logger.error(f"[IQ] Failed loading artifact files from {files_dir}: {e}")


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


def handle_iq_record_artifact_complete(dashboard: QtCore.QObject, artifact_record: dict):
    """
    Resets the IQ Record controls and refreshes the local IQ artifact browser
    when an IQ recording artifact is received.

    First-pass completion signal:
      artifact CoT received -> IQ record operation produced an artifact.
    """
    if artifact_record.get("operation_id", "") != getattr(
        dashboard,
        "iq_record_pending_operation_id",
        "",
    ):
        return

    reset_iq_record_controls(
        dashboard,
        status_text="Finished",
        clear_pending=True,
    )

    try:
        _slotIQ_ArtifactsRefreshClicked(dashboard)
    except Exception as e:
        dashboard.logger.warning(
            f"[IQ] Failed refreshing artifacts after IQ record completion: {e}"
        )

    # Select the new artifact in the IQ Data -> Artifacts combo if possible.
    try:
        operation_id = artifact_record.get("operation_id", "")
        artifact_id = artifact_record.get("artifact_id", "")

        candidate_dirs = []

        if operation_id:
            candidate_dirs.append(
                os.path.join(fissure.utils.HUB_ARTIFACTS_DIR, operation_id)
            )

        if artifact_id:
            candidate_dirs.append(
                os.path.join(fissure.utils.HUB_ARTIFACTS_DIR, artifact_id)
            )

        combo = dashboard.ui.comboBox_iq_artifacts

        for i in range(combo.count()):
            data = combo.itemData(i, QtCore.Qt.UserRole)

            if not isinstance(data, dict):
                continue

            artifact_dir = data.get("artifact_dir", "")

            if artifact_dir in candidate_dirs:
                combo.setCurrentIndex(i)
                break

    except Exception as e:
        dashboard.logger.warning(
            f"[IQ] Failed selecting completed IQ artifact: {e}"
        )