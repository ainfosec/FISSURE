from PyQt5 import QtCore, QtWidgets, QtGui
import os
import fissure.utils
import ast
import matplotlib.patches as patches
import matplotlib.pyplot as plt
import subprocess
import seaborn as sns
import csv
import pandas as pd
import struct
import numpy as np
import datetime
from yellowbrick.features import JointPlotVisualizer
from fissure.Dashboard.UI_Components.Qt5 import JointPlotDialog, TrimSettings, FeaturesDialog
import qasync
import asyncio
import time
import matplotlib
matplotlib.use('Qt5Agg')

# Decision Tree
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn import metrics
from sklearn.tree import export_graphviz
from six import StringIO
from IPython.display import Image  
import pydotplus
import pickle
import ast

# DNN
from numpy import loadtxt
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # Suppress most TensorFlow warnings
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense

from PIL import Image as PIL_Image
from PIL import ImageDraw, ImageFont
from tensorflow.keras.models import load_model


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorChanged(dashboard: QtCore.QObject):
    """ 
    Adjusts default settings for the current detector.
    """
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_tsi_detector_sweep_hardware.currentText())
    get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'tsi')
    
    # Change Settings
    get_detector = str(dashboard.ui.comboBox_tsi_detector.currentText())
    if get_detector == 'wideband_x3x0.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("20e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(35)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(30)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:0")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:0")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("TX/RX")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("RX1")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("RX2")

        # Select Antenna
        get_daughterboard = get_hardware_daughterboard
        if "CBX-120" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        elif "SBX-120" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        elif "UBX-160" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        elif "WBX-120" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        elif "TwinRX" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(1)
        else:
            dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_b2x0.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("10e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(80)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(60)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:B")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("TX/RX")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("RX2")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_hackrf.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("20e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(40)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(20)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_b20xmini.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("10e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(80)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(60)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:B")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("TX/RX")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("RX2")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_rtl2832u.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("2.56e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(50)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(20)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_limesdr.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("20e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(70)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(60)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("RX1")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("RX2")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_bladerf.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("20e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(40)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(10)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_plutosdr.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("20e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(71)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(64)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_usrp2.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("20e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(35)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(30)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:0")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:0")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:AB")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:BA")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:B")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:AB")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:BA")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:B")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("J1")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("J2")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_usrp_n2xx.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("20e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(35)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(30)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:0")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:0")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:AB")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:BA")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:B")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:AB")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:BA")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:B")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("J1")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("J2")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_bladerf2.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("20e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(40)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(10)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'wideband_usrp_x410.py':
        dashboard.ui.textEdit_tsi_detector_fg_sample_rate.setPlainText("20e6")
        dashboard.ui.spinBox_tsi_detector_fg_threshold.setValue(-70)
        dashboard.ui.comboBox_tsi_detector_fg_fft_size.setCurrentIndex(1)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMaximum(60)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fg_gain.setValue(50)
        dashboard.ui.comboBox_tsi_detector_fg_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("A:0")
        dashboard.ui.comboBox_tsi_detector_fg_channel.addItem("B:0")
        dashboard.ui.comboBox_tsi_detector_fg_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fg_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("TX/RX")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("RX1")
        dashboard.ui.comboBox_tsi_detector_fg_antenna.addItem("RX2")

        # Select Antenna
        get_daughterboard = get_hardware_daughterboard
        if "ZBX" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fg_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)

    elif get_detector == 'Simulator':
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(2)

    elif get_detector == 'IQ File':
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(3)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsNormalizeChecked(dashboard: QtCore.QObject):
    """ 
    Enables/disables the normalize min/max combobox.
    """
    # Enable
    if dashboard.ui.checkBox_tsi_conditioner_settings_normalize_output.isChecked():
        dashboard.ui.comboBox_tsi_conditioner_settings_normalize.setEnabled(True)
    # Disable
    else:
        dashboard.ui.comboBox_tsi_conditioner_settings_normalize.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsSaturationChecked(dashboard: QtCore.QObject):
    """ 
    Toggles the saturation combobox.
    """
    # Enable
    if dashboard.ui.checkBox_tsi_conditioner_settings_saturation.isChecked():
        dashboard.ui.comboBox_tsi_conditioner_settings_saturation.setEnabled(True)
    # Disable
    else:
        dashboard.ui.comboBox_tsi_conditioner_settings_saturation.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorFixedChanged(dashboard: QtCore.QObject):
    """ 
    Adjusts default settings for the current detector.
    """
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_tsi_detector_fixed_hardware.currentText())
    get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'tsi')
    
    # Change Settings
    get_detector = str(dashboard.ui.comboBox_tsi_detector_fixed.currentText())
    if get_detector == 'fixed_threshold_x3x0.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(35)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(30)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:0")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:0")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("TX/RX")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("RX1")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("RX2")

        # Select Antenna
        get_daughterboard = get_hardware_daughterboard
        if "CBX-120" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        elif "SBX-120" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        elif "UBX-160" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        elif "WBX-120" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        elif "TwinRX" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(1)
        else:
            dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_b2x0.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(80)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(60)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:B")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("TX/RX")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("RX2")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_hackrf.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(40)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(20)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_b20xmini.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(80)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(60)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:B")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("TX/RX")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("RX2")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_rtl2832u.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("102.4")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("0.25e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1.024e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1.536e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1.792e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1.92e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2.048e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2.16e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2.56e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2.88e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("3.2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(7)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(50)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(20)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_limesdr.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(70)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(60)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("RX1")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("RX2")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_bladerf.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(40)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(10)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_plutosdr.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(71)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(64)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_usrp2.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(35)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(30)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:0")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:0")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:AB")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:BA")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:B")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:AB")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:BA")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:B")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("J1")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("J2")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_usrp_n2xx.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(35)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(30)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:0")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:0")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:AB")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:BA")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:B")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:AB")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:BA")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:B")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("J1")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("J2")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_bladerf2.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(40)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(10)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    if get_detector == 'fixed_threshold_usrp_x410.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("500e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("400e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("300e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("200e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("100e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("50e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(6)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(60)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(50)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("A:0")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("B:0")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("TX/RX")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("RX1")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("RX2")

        # Select Antenna
        get_daughterboard = get_hardware_daughterboard
        if "ZBX" in get_daughterboard:
            dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        else:
            dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)

    elif get_detector == 'fixed_threshold_simulator.py':
        dashboard.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("20e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("10e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("5e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("2e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.addItem("1e6")
        dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.setCurrentIndex(0)
        dashboard.ui.spinBox_tsi_detector_fixed_threshold.setValue(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMaximum(10)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setMinimum(0)
        dashboard.ui.spinBox_tsi_detector_fixed_gain.setValue(2)
        dashboard.ui.comboBox_tsi_detector_fixed_channel.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_channel.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_channel.setCurrentIndex(0)
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.clear()
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.addItem("N/A")
        dashboard.ui.comboBox_tsi_detector_fixed_antenna.setCurrentIndex(0)
        dashboard.ui.stackedWidget2_tsi_detector_fixed.setCurrentIndex(0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFolderChanged(dashboard: QtCore.QObject):
    """ 
    Changes the IQ files in the input listbox.
    """
    # Load the Files in the Listbox
    get_dir = str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText())
    if get_dir != "":
        dashboard.ui.listWidget_tsi_conditioner_input_files.clear()
        file_names = []
        for fname in os.listdir(get_dir):
            if os.path.isfile(os.path.join(get_dir, fname)):
                file_names.append(fname)
        file_names = sorted(file_names, key=str.lower)
        for n in file_names:
            dashboard.ui.listWidget_tsi_conditioner_input_files.addItem(n)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsIsolationMethodChanged(dashboard: QtCore.QObject):
    """ 
    Changes the settings to match the selected isolation method.
    """
    get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.currentText())
    if get_method == "Normal":
        dashboard.ui.stackedWidget_tsi_conditioner_settings.setCurrentIndex(0)
        dashboard.ui.pushButton_tsi_conditioner_settings_view.setEnabled(True)
    elif get_method == "Normal Decay":
        dashboard.ui.stackedWidget_tsi_conditioner_settings.setCurrentIndex(1)
        dashboard.ui.pushButton_tsi_conditioner_settings_view.setEnabled(True)
    elif get_method == "Power Squelch":
        dashboard.ui.stackedWidget_tsi_conditioner_settings.setCurrentIndex(2)
        dashboard.ui.pushButton_tsi_conditioner_settings_view.setEnabled(True)
    elif get_method == "None":
        dashboard.ui.stackedWidget_tsi_conditioner_settings.setCurrentIndex(3)
        dashboard.ui.pushButton_tsi_conditioner_settings_view.setEnabled(False)
    elif get_method == "Lowpass":
        dashboard.ui.stackedWidget_tsi_conditioner_settings.setCurrentIndex(4)
        dashboard.ui.pushButton_tsi_conditioner_settings_view.setEnabled(True)
    elif get_method == "Power Squelch then Lowpass":
        dashboard.ui.stackedWidget_tsi_conditioner_settings.setCurrentIndex(5)
        dashboard.ui.pushButton_tsi_conditioner_settings_view.setEnabled(True)
    elif get_method == "Bandpass":
        dashboard.ui.stackedWidget_tsi_conditioner_settings.setCurrentIndex(6)
        dashboard.ui.pushButton_tsi_conditioner_settings_view.setEnabled(True)
    elif get_method == "Strongest Frequency then Bandpass":
        dashboard.ui.stackedWidget_tsi_conditioner_settings.setCurrentIndex(7)
        dashboard.ui.pushButton_tsi_conditioner_settings_view.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsInputSourceChanged(dashboard: QtCore.QObject):
    """ 
    Enables/disables the Start button if folder or file is selected with no valid filepath.
    """
    # File
    if dashboard.ui.comboBox_tsi_conditioner_settings_input_source.currentText() == "File":
        if dashboard.ui.label2_tsi_conditioner_info_file_name.text() == "File:":
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(False)
        else:
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(True)

    # Folder
    elif dashboard.ui.comboBox_tsi_conditioner_settings_input_source.currentText() == "Folder":
        if dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText() == "":
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(False)
        elif dashboard.ui.listWidget_tsi_conditioner_input_files.count() == 0:
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(False)
        else:
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsIsolationCategoryChanged(dashboard: QtCore.QObject):
    """ 
    Changes the isolation method options.
    """
    # Energy - Burst Tagger
    if dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText() == "Energy - Burst Tagger":
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.clear()
        methods = ['Normal','Normal Decay','Power Squelch','Lowpass','Power Squelch then Lowpass','Bandpass','Strongest Frequency then Bandpass']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.addItems(methods)
    
    # Energy - Imagery
    elif dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText() == "Energy - Imagery":
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.clear()
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.addItems(methods)
    
    # Eigenvalue
    elif dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText() == "Eigenvalue":
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.clear()
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.addItems(methods)
    
    # Matched Filter
    elif dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText() == "Matched Filter":
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.clear()
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.addItems(methods)
    
    # Cyclostationary
    elif dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText() == "Cyclostationary":
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.clear()
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.addItems(methods)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputFolderChanged(dashboard: QtCore.QObject):
    """ 
    Changes the IQ files in the input listbox.
    """
    # Load the Files in the Listbox
    get_dir = str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText())
    if get_dir != "":
        dashboard.ui.listWidget_tsi_fe_input_files.clear()
        file_names = []
        for fname in os.listdir(get_dir):
            if os.path.isfile(os.path.join(get_dir, fname)):
                file_names.append(fname)
        file_names = sorted(file_names, key=str.lower)
        for n in file_names:
            dashboard.ui.listWidget_tsi_fe_input_files.addItem(n)  


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_SettingsClassificationChanged(dashboard: QtCore.QObject):
    """ 
    Changes the classification technique options.
    """
    # Switch the Models
    dashboard.ui.comboBox_tsi_fe_settings_technique.clear()
    decision_tree_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
    dnn_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
    get_models = []
    if str(dashboard.ui.comboBox_tsi_fe_settings_classification.currentText()) == "Decision Tree":
        for file in os.listdir(decision_tree_directory):
            if file.endswith('.h5'):
                get_models.append(str(file).strip('.h5'))
    elif str(dashboard.ui.comboBox_tsi_fe_settings_classification.currentText()) == "Deep Neural Network":
        for file in os.listdir(dnn_directory):
            if file.endswith('.h5'):
                get_models.append(str(file).strip('.h5'))
    dashboard.ui.comboBox_tsi_fe_settings_technique.addItems(sorted(get_models, key=str.lower))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_SettingsTechniqueChanged(dashboard: QtCore.QObject):
    """ 
    Changes the checked items to align with each technique.
    """
    # Uncheck Everything
    dashboard.ui.checkBox_tsi_fe_td_mean.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_max.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_peak.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_ptp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_rms.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_variance.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_std_dev.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_power.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_crest.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_pulse.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_margin.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_kurtosis.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_skewness.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_zero_crossings.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_samples.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_mean_bps.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_max_bps.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_sum_tbp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_peak_bp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_var_bp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_std_dev_bp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_skewness_bp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_kurtosis_bp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_rel_spectral_peak_band.setChecked(False)
            
    # Load the Model
    if str(dashboard.ui.comboBox_tsi_fe_settings_classification.currentText()) == "Decision Tree":
        model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
    elif str(dashboard.ui.comboBox_tsi_fe_settings_classification.currentText()) == "Deep Neural Network":
        model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
    else:
        return
    get_file = str(dashboard.ui.comboBox_tsi_fe_settings_technique.currentText()) + ".txt"
    
    # Features
    get_features = []                             
    get_model = str(dashboard.ui.comboBox_tsi_fe_settings_technique.currentText())
    if len(get_model) > 0:           
        # Load Details, Features, Image Path from File
        get_details = ""            
        with open(os.path.join(model_directory, get_model + ".txt")) as model_details:
            get_details = model_details.read()
            model_details.seek(0)
            for line in model_details:
                if "Features: " in line:
                    get_features = ast.literal_eval(line.split('Features: ')[1])
    
    # Check the Features
    if len(get_features) > 0:
        if "Mean" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_mean.setChecked(True)
        if "Max" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_max.setChecked(True)
        if "Peak" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_peak.setChecked(True)
        if "Peak to Peak" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_ptp.setChecked(True)
        if "RMS" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_rms.setChecked(True)
        if "Variance" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_variance.setChecked(True)
        if "Std. Dev." in get_features:
            dashboard.ui.checkBox_tsi_fe_td_std_dev.setChecked(True)
        if "Power" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_power.setChecked(True)
        if "Crest Factor" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_crest.setChecked(True)
        if "Pulse Indicator" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_pulse.setChecked(True)
        if "Margin" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_margin.setChecked(True)
        if "Kurtosis" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_kurtosis.setChecked(True)
        if "Skewness" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_skewness.setChecked(True)
        if "Zero Crossings" in get_features:
            dashboard.ui.checkBox_tsi_fe_td_zero_crossings.setChecked(True)
        if "Samples" in get_features:               
            dashboard.ui.checkBox_tsi_fe_td_samples.setChecked(True)
        if "Mean of BPS" in get_features:
            dashboard.ui.checkBox_tsi_fe_mean_bps.setChecked(True)
        if "Max of BPS" in get_features:
            dashboard.ui.checkBox_tsi_fe_max_bps.setChecked(True)
        if "Sum of TBP" in get_features:
            dashboard.ui.checkBox_tsi_fe_sum_tbp.setChecked(True)
        if "Peak of BP" in get_features:
            dashboard.ui.checkBox_tsi_fe_peak_bp.setChecked(True)
        if "Variance of BP" in get_features:
            dashboard.ui.checkBox_tsi_fe_var_bp.setChecked(True)
        if "Std. Dev. of BP" in get_features:
            dashboard.ui.checkBox_tsi_fe_std_dev_bp.setChecked(True)
        if "Skewness of BP" in get_features:
            dashboard.ui.checkBox_tsi_fe_skewness_bp.setChecked(True)
        if "Kurtosis of BP" in get_features:
            dashboard.ui.checkBox_tsi_fe_kurtosis_bp.setChecked(True)
        if "RSPpB" in get_features:
            dashboard.ui.checkBox_tsi_fe_rel_spectral_peak_band.setChecked(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_SettingsInputSourceChanged(dashboard: QtCore.QObject):
    """ 
    Enables/disables the Start button if folder or file is selected with no valid filepath.
    """
    # File
    if dashboard.ui.comboBox_tsi_fe_settings_input_source.currentText() == "File":
        if dashboard.ui.label2_tsi_fe_info_file_name.text() == "File:":
            dashboard.ui.pushButton_tsi_fe_operation_start.setEnabled(False)
        else:
            dashboard.ui.pushButton_tsi_fe_operation_start.setEnabled(True)

    # Folder
    elif dashboard.ui.comboBox_tsi_fe_settings_input_source.currentText() == "Folder":
        if dashboard.ui.comboBox_tsi_fe_input_folders.currentText() == "":
            dashboard.ui.pushButton_tsi_fe_operation_start.setEnabled(False)
        elif dashboard.ui.listWidget_tsi_fe_input_files.count() == 0:
            dashboard.ui.pushButton_tsi_fe_operation_start.setEnabled(False)
        else:
            dashboard.ui.pushButton_tsi_fe_operation_start.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_SettingsCategoryChanged(dashboard: QtCore.QObject):
    """ 
    Changes the contents of the classification combobox.
    """
    # Switch the Techniques
    dashboard.ui.comboBox_tsi_fe_settings_classification.clear()
    if dashboard.ui.comboBox_tsi_fe_settings_category.currentText() == "All":
        dashboard.ui.comboBox_tsi_fe_settings_classification.addItem("Decision Tree")
        dashboard.ui.comboBox_tsi_fe_settings_classification.addItem("Deep Neural Network")
    elif dashboard.ui.comboBox_tsi_fe_settings_category.currentText() == "Supervised Learning":
        dashboard.ui.comboBox_tsi_fe_settings_classification.addItem("Decision Tree")
    elif dashboard.ui.comboBox_tsi_fe_settings_category.currentText() == "Artificial Neural Network":
        dashboard.ui.comboBox_tsi_fe_settings_classification.addItem("Deep Neural Network")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorSweepHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Changes TSI sweep detector hardware settings.
    """
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_tsi_detector_sweep_hardware.currentText())
    get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'tsi')
    
    # Change Settings
    dashboard.ui.comboBox_tsi_detector.clear()
    if get_hardware_type == "Computer":
        dashboard.ui.comboBox_tsi_detector.addItems(['Simulator', 'IQ File'])

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 1
        dashboard.tuning_widget.freq_end_limit = 6000

    elif get_hardware_type == "USRP X3x0":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_x3x0.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        if get_hardware_daughterboard == "CBX-120":
            dashboard.tuning_widget.freq_start_limit = 1200
            dashboard.tuning_widget.freq_end_limit = 6000
        elif get_hardware_daughterboard == "SBX-120":
            dashboard.tuning_widget.freq_start_limit = 400
            dashboard.tuning_widget.freq_end_limit = 4400
        elif get_hardware_daughterboard == "UBX-160":
            dashboard.tuning_widget.freq_start_limit = 10
            dashboard.tuning_widget.freq_end_limit = 6000
        elif get_hardware_daughterboard == "WBX-120":
            dashboard.tuning_widget.freq_start_limit = 25
            dashboard.tuning_widget.freq_end_limit = 2200
        elif get_hardware_daughterboard == "TwinRX":
            dashboard.tuning_widget.freq_start_limit = 10
            dashboard.tuning_widget.freq_end_limit = 6000

    elif get_hardware_type == "USRP B2x0":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_b2x0.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 70
        dashboard.tuning_widget.freq_end_limit = 6000

    elif get_hardware_type == "HackRF":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_hackrf.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 1
        dashboard.tuning_widget.freq_end_limit = 6000

    elif get_hardware_type == "RTL2832U":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_rtl2832u.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 64
        dashboard.tuning_widget.freq_end_limit = 1700

    elif get_hardware_type == "802.11x Adapter":
        dashboard.ui.comboBox_tsi_detector.addItems(['Simulator', 'IQ File'])
        dashboard.ui.comboBox_tsi_detector.setCurrentIndex(0)

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 1
        dashboard.tuning_widget.freq_end_limit = 6000

    elif get_hardware_type == "USRP B20xmini":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_b20xmini.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 70
        dashboard.tuning_widget.freq_end_limit = 6000

    elif get_hardware_type == "LimeSDR":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_limesdr.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 1
        dashboard.tuning_widget.freq_end_limit = 3800

    elif get_hardware_type == "bladeRF":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_bladerf.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 280
        dashboard.tuning_widget.freq_end_limit = 3800

    elif get_hardware_type == "Open Sniffer":
        dashboard.ui.comboBox_tsi_detector.addItems(['Simulator', 'IQ File'])

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 1
        dashboard.tuning_widget.freq_end_limit = 6000

    elif get_hardware_type == "PlutoSDR":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_plutosdr.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 325
        dashboard.tuning_widget.freq_end_limit = 3800

    elif get_hardware_type == "USRP2":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_usrp2.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        if get_hardware_daughterboard == "XCVR2450":
            dashboard.tuning_widget.freq_start_limit = 2400
            dashboard.tuning_widget.freq_end_limit = 6000
        elif get_hardware_daughterboard == "DBSRX":
            dashboard.tuning_widget.freq_start_limit = 800
            dashboard.tuning_widget.freq_end_limit = 2300
        elif get_hardware_daughterboard == "SBX-40":
            dashboard.tuning_widget.freq_start_limit = 400
            dashboard.tuning_widget.freq_end_limit = 4400
        elif get_hardware_daughterboard == "UBX-40":
            dashboard.tuning_widget.freq_start_limit = 10
            dashboard.tuning_widget.freq_end_limit = 6000
        elif get_hardware_daughterboard == "WBX-40":
            dashboard.tuning_widget.freq_start_limit = 50
            dashboard.tuning_widget.freq_end_limit = 2200
        elif get_hardware_daughterboard == "CBX-40":
            dashboard.tuning_widget.freq_start_limit = 1200
            dashboard.tuning_widget.freq_end_limit = 6000
        elif get_hardware_daughterboard == "LFRX":
            dashboard.tuning_widget.freq_start_limit = 0
            dashboard.tuning_widget.freq_end_limit = 30
        elif get_hardware_daughterboard == "LFTX":
            dashboard.tuning_widget.freq_start_limit = 0
            dashboard.tuning_widget.freq_end_limit = 30
        elif get_hardware_daughterboard == "BasicRX":
            dashboard.tuning_widget.freq_start_limit = 1
            dashboard.tuning_widget.freq_end_limit = 250
        elif get_hardware_daughterboard == "BasicTX":
            dashboard.tuning_widget.freq_start_limit = 1
            dashboard.tuning_widget.freq_end_limit = 250
        elif get_hardware_daughterboard == "TVRX2":
            dashboard.tuning_widget.freq_start_limit = 50
            dashboard.tuning_widget.freq_end_limit = 860
        elif get_hardware_daughterboard == "RFX400":
            dashboard.tuning_widget.freq_start_limit = 400
            dashboard.tuning_widget.freq_end_limit = 500
        elif get_hardware_daughterboard == "RFX900":
            dashboard.tuning_widget.freq_start_limit = 750
            dashboard.tuning_widget.freq_end_limit = 1050
        elif get_hardware_daughterboard == "RFX1200":
            dashboard.tuning_widget.freq_start_limit = 1150
            dashboard.tuning_widget.freq_end_limit = 1450
        elif get_hardware_daughterboard == "RFX1800":
            dashboard.tuning_widget.freq_start_limit = 1500
            dashboard.tuning_widget.freq_end_limit = 2100
        elif get_hardware_daughterboard == "RFX2400":
            dashboard.tuning_widget.freq_start_limit = 2300
            dashboard.tuning_widget.freq_end_limit = 2900

    elif get_hardware_type == "USRP N2xx":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_usrp_n2xx.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        if get_hardware_daughterboard == "XCVR2450":
            dashboard.tuning_widget.freq_start_limit = 2400
            dashboard.tuning_widget.freq_end_limit = 6000
        elif get_hardware_daughterboard == "DBSRX":
            dashboard.tuning_widget.freq_start_limit = 800
            dashboard.tuning_widget.freq_end_limit = 2300
        elif get_hardware_daughterboard == "SBX-40":
            dashboard.tuning_widget.freq_start_limit = 400
            dashboard.tuning_widget.freq_end_limit = 4400
        elif get_hardware_daughterboard == "UBX-40":
            dashboard.tuning_widget.freq_start_limit = 10
            dashboard.tuning_widget.freq_end_limit = 6000
        elif get_hardware_daughterboard == "WBX-40":
            dashboard.tuning_widget.freq_start_limit = 50
            dashboard.tuning_widget.freq_end_limit = 2200
        elif get_hardware_daughterboard == "CBX-40":
            dashboard.tuning_widget.freq_start_limit = 1200
            dashboard.tuning_widget.freq_end_limit = 6000
        elif get_hardware_daughterboard == "LFRX":
            dashboard.tuning_widget.freq_start_limit = 0
            dashboard.tuning_widget.freq_end_limit = 30
        elif get_hardware_daughterboard == "LFTX":
            dashboard.tuning_widget.freq_start_limit = 0
            dashboard.tuning_widget.freq_end_limit = 30
        elif get_hardware_daughterboard == "BasicRX":
            dashboard.tuning_widget.freq_start_limit = 1
            dashboard.tuning_widget.freq_end_limit = 250
        elif get_hardware_daughterboard == "BasicTX":
            dashboard.tuning_widget.freq_start_limit = 1
            dashboard.tuning_widget.freq_end_limit = 250
        elif get_hardware_daughterboard == "TVRX2":
            dashboard.tuning_widget.freq_start_limit = 50
            dashboard.tuning_widget.freq_end_limit = 860
        elif get_hardware_daughterboard == "RFX400":
            dashboard.tuning_widget.freq_start_limit = 400
            dashboard.tuning_widget.freq_end_limit = 500
        elif get_hardware_daughterboard == "RFX900":
            dashboard.tuning_widget.freq_start_limit = 750
            dashboard.tuning_widget.freq_end_limit = 1050
        elif get_hardware_daughterboard == "RFX1200":
            dashboard.tuning_widget.freq_start_limit = 1150
            dashboard.tuning_widget.freq_end_limit = 1450
        elif get_hardware_daughterboard == "RFX1800":
            dashboard.tuning_widget.freq_start_limit = 1500
            dashboard.tuning_widget.freq_end_limit = 2100
        elif get_hardware_daughterboard == "RFX2400":
            dashboard.tuning_widget.freq_start_limit = 2300
            dashboard.tuning_widget.freq_end_limit = 2900

    elif get_hardware_type == "bladeRF 2.0":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_bladerf2.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        dashboard.tuning_widget.freq_start_limit = 47
        dashboard.tuning_widget.freq_end_limit = 6000

    elif get_hardware_type == "USRP X410":
        dashboard.ui.comboBox_tsi_detector.addItems(['wideband_usrp_x410.py', 'Simulator', 'IQ File'])

        # Tuning Widget Limits
        if get_hardware_daughterboard == "ZBX":
            dashboard.tuning_widget.freq_start_limit = 1
            dashboard.tuning_widget.freq_end_limit = 7200
    
    dashboard.ui.comboBox_tsi_detector.setCurrentIndex(0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorFixedHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Changes TSI fixed hardware settings.
    """
    # Sensor Node Hardware Information
    get_current_hardware = str(dashboard.ui.comboBox_tsi_detector_fixed_hardware.currentText())
    get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'tsi')
    
    # Change Settings
    dashboard.ui.comboBox_tsi_detector_fixed.clear()
    if get_hardware_type == "Computer":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_simulator.py'])
    elif get_hardware_type == "USRP X3x0":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_x3x0.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "USRP B2x0":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_b2x0.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "HackRF":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_hackrf.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "RTL2832U":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_rtl2832u.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "802.11x Adapter":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_simulator.py'])
    elif get_hardware_type == "USRP B20xmini":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_b20xmini.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "LimeSDR":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_limesdr.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "bladeRF":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_bladerf.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "Open Sniffer":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_simulator.py'])
    elif get_hardware_type == "PlutoSDR":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_plutosdr.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "USRP2":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_usrp2.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "USRP N2xx":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_usrp_n2xx.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "bladeRF 2.0":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_bladerf2.py', 'fixed_threshold_simulator.py'])
    elif get_hardware_type == "USRP X410":
        dashboard.ui.comboBox_tsi_detector_fixed.addItems(['fixed_threshold_usrp_x410.py', 'fixed_threshold_simulator.py'])
    
    dashboard.ui.comboBox_tsi_detector_fixed.setCurrentIndex(0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputExtensionsAllClicked(dashboard: QtCore.QObject):
    """ 
    Disables the Custom text edit box.
    """
    # Disable
    dashboard.ui.textEdit_tsi_conditioner_input_extensions.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputExtensionsCustomClicked(dashboard: QtCore.QObject):
    """ 
    Enables the Custom text edit box.
    """
    # Enable
    dashboard.ui.textEdit_tsi_conditioner_input_extensions.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ScanPresetItemChanged(dashboard: QtCore.QObject):
    """ 
    Changes the values in the scan options table whenever the preset item is changed
    """
    if dashboard.ui.listWidget_tsi_scan_presets.count() > 1:  # Don't delete last preset settings

        dashboard.tuning_widget.axes.cla()  # TEST

        # Clear the Table
        dashboard.ui.tableWidget_tsi_scan_options.clearContents()
        dashboard.ui.tableWidget_tsi_scan_options.setColumnCount(0)

        # Delete the Text Labels
        for txt in reversed(dashboard.tuning_widget.axes.texts):
            if txt.get_position()[1] < 500:
                txt.remove()

        # Delete the Bands
        for col in reversed(range(0,len(dashboard.tuning_widget.bands))):
            dashboard.tuning_widget.bands[col].remove()
            del dashboard.tuning_widget.bands[col]

        # Add the Values to the Table
        preset_name = str(dashboard.ui.listWidget_tsi_scan_presets.currentItem().text())
        values = dashboard.preset_dictionary[preset_name]
        for col in range(0,len(values[0])):
            if values[0][col] != 0:
                # Header
                dashboard.ui.tableWidget_tsi_scan_options.setColumnCount(dashboard.ui.tableWidget_tsi_scan_options.columnCount()+1)
                header_item = QtWidgets.QTableWidgetItem("Band " + str(dashboard.ui.tableWidget_tsi_scan_options.columnCount()))
                header_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_tsi_scan_options.setHorizontalHeaderItem(dashboard.ui.tableWidget_tsi_scan_options.columnCount()-1,header_item)

                for row in range(0,len(values)):
                    # Other Items
                    new_item = QtWidgets.QTableWidgetItem(values[row][col])
                    new_item.setTextAlignment(QtCore.Qt.AlignCenter)
                    dashboard.ui.tableWidget_tsi_scan_options.setItem(row,col,new_item)

                # Draw New Rectangle
                h = dashboard.tuning_widget.axes.add_patch(patches.Rectangle((float(values[0][col])/10,
                    (dashboard.tuning_widget.band_height*(len(dashboard.tuning_widget.bands)+1))),
                        float(values[1][col])/10-float(values[0][col])/10,dashboard.tuning_widget.band_height,facecolor='blue',edgecolor='Black'))
                dashboard.tuning_widget.bands.append(h)

                # Draw Text Label
                x_offset = 10
                band_number = str(dashboard.ui.tableWidget_tsi_scan_options.columnCount())
                if band_number == "10":
                    x_offset = 15
                dashboard.tuning_widget.axes.text(float(values[0][col])/10 - x_offset,(dashboard.tuning_widget.band_height*(len(dashboard.tuning_widget.bands)+1)) - 5,band_number,fontsize=10)

        # Redraw the Plot
        dashboard.tuning_widget.draw()

        # Resize Table Columns and Rows
        dashboard.ui.tableWidget_tsi_scan_options.resizeColumnsToContents()
        dashboard.ui.tableWidget_tsi_scan_options.resizeRowsToContents()
        dashboard.ui.tableWidget_tsi_scan_options.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_tsi_scan_options.horizontalHeader().setStretchLastSection(True)

        # Enable Remove Band Pushbutton
        dashboard.ui.pushButton_tsi_remove_band.setEnabled(True)    


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputLoadFileClicked(dashboard: QtCore.QObject):
    """ 
    Loads the currently selected IQ files.
    """
    # File Name
    get_file = str(dashboard.ui.listWidget_tsi_conditioner_input_files.currentItem().text())
    dashboard.ui.label2_tsi_conditioner_info_file_name.setText("File: " + get_file)
    
    # Number of Bytes & Samples
    get_type = str(dashboard.ui.comboBox_tsi_conditioner_input_data_type.currentText())
    get_bytes = os.path.getsize(os.path.join(str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText()), get_file))
    get_samples = "-1"
    if get_bytes > 0:            
        if get_type == "Complex Float 32":
            get_samples = str(int(get_bytes/8))
        elif get_type == "Float/Float 32":
            get_samples = str(int(get_bytes/4))
        elif get_type == "Short/Int 16":
            get_samples = str(int(get_bytes/2))
        elif get_type == "Int/Int 32":
            get_samples = str(int(get_bytes/4))
        elif get_type == "Byte/Int 8":
            get_samples = str(int(get_bytes/1))
        elif get_type == "Complex Int 16":
            get_samples = str(int(get_bytes/4))
        elif get_type == "Complex Int 8":
            get_samples = str(int(get_bytes/2))
        elif get_type == "Complex Float 64":
            get_samples = str(int(get_bytes/16))
        elif get_type == "Complex Int 64":
            get_samples = str(int(get_bytes/16))   
    dashboard.ui.label2_tsi_conditioner_info_file_size.setText("Size (MB): " + str(round(get_bytes/1048576,2)))
    dashboard.ui.label2_tsi_conditioner_info_samples.setText("Samples: " + get_samples)
    
    # Enable Start Button
    dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputLoadFileClicked(dashboard: QtCore.QObject):
    """ 
    Loads the currently selected IQ files.
    """
    try:
        # File Name
        get_file = str(dashboard.ui.listWidget_tsi_fe_input_files.currentItem().text())
        dashboard.ui.label2_tsi_fe_info_file_name.setText("File: " + get_file)
        
        # Number of Bytes & Samples
        get_type = str(dashboard.ui.comboBox_tsi_fe_input_data_type.currentText())
        get_bytes = os.path.getsize(os.path.join(str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText()), get_file))
        get_samples = "-1"
        if get_bytes > 0:            
            if get_type == "Complex Float 32":
                get_samples = str(int(get_bytes/8))
            elif get_type == "Float/Float 32":
                get_samples = str(int(get_bytes/4))
            elif get_type == "Short/Int 16":
                get_samples = str(int(get_bytes/2))
            elif get_type == "Int/Int 32":
                get_samples = str(int(get_bytes/4))
            elif get_type == "Byte/Int 8":
                get_samples = str(int(get_bytes/1))
            elif get_type == "Complex Int 16":
                get_samples = str(int(get_bytes/4))
            elif get_type == "Complex Int 8":
                get_samples = str(int(get_bytes/2))
            elif get_type == "Complex Float 64":
                get_samples = str(int(get_bytes/16))
            elif get_type == "Complex Int 64":
                get_samples = str(int(get_bytes/16))   
        dashboard.ui.label2_tsi_fe_info_file_size.setText("Size (MB): " + str(round(get_bytes/1048576,2)))
        dashboard.ui.label2_tsi_fe_info_samples.setText("Samples: " + get_samples)
        
        # Enable Start Button
        dashboard.ui.pushButton_tsi_fe_operation_start.setEnabled(True)
    except:
        dashboard.logger.error("Unable to load Feature Extractor input file.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_AddBandClicked(dashboard: QtCore.QObject):
    """ 
    Copies the data entered into the Wideband edit boxes to the configuration table and edits the plot
    """
    # No More than 10 Bands
    if dashboard.ui.tableWidget_tsi_scan_options.columnCount() < 10:
        # Add it to the Table
        # Header
        dashboard.ui.tableWidget_tsi_scan_options.setColumnCount(dashboard.ui.tableWidget_tsi_scan_options.columnCount()+1)
        header_item = QtWidgets.QTableWidgetItem("Band " + str(dashboard.ui.tableWidget_tsi_scan_options.columnCount()))
        header_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_tsi_scan_options.setHorizontalHeaderItem(dashboard.ui.tableWidget_tsi_scan_options.columnCount()-1,header_item)

        # Start
        start_value = dashboard.ui.spinBox_tsi_sdr_start.value()
        #if start_value < 1200:  # Temporary Fix
        #    start_value = 1200
        start_item = QtWidgets.QTableWidgetItem(str(start_value))
        start_item.setTextAlignment(QtCore.Qt.AlignCenter)

        # End
        end_value = dashboard.ui.spinBox_tsi_sdr_end.value()
        #if end_value < 1200:  # Temporary Fix
        #    end_value = 1200
        end_item = QtWidgets.QTableWidgetItem(str(end_value))
        end_item.setTextAlignment(QtCore.Qt.AlignCenter)

        # Compare Start and End Frequencies
        if start_value <= end_value:
            dashboard.ui.tableWidget_tsi_scan_options.setItem(0,dashboard.ui.tableWidget_tsi_scan_options.columnCount()-1,start_item)
            dashboard.ui.tableWidget_tsi_scan_options.setItem(1,dashboard.ui.tableWidget_tsi_scan_options.columnCount()-1,end_item)
        else:
            dashboard.ui.tableWidget_tsi_scan_options.setItem(0,dashboard.ui.tableWidget_tsi_scan_options.columnCount()-1,end_item)
            dashboard.ui.tableWidget_tsi_scan_options.setItem(1,dashboard.ui.tableWidget_tsi_scan_options.columnCount()-1,start_item)

        # Step Size
        step_size_value = dashboard.ui.spinBox_tsi_sdr_step.value()
        step_size_item = QtWidgets.QTableWidgetItem(str(step_size_value))
        step_size_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_tsi_scan_options.setItem(2,dashboard.ui.tableWidget_tsi_scan_options.columnCount()-1,step_size_item)

        # Dwell
        dwell_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.doubleSpinBox_tsi_sdr_dwell.value()))
        dwell_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_tsi_scan_options.setItem(3,dashboard.ui.tableWidget_tsi_scan_options.columnCount()-1,dwell_item)

        # Resize Table Columns and Rows
        dashboard.ui.tableWidget_tsi_scan_options.resizeColumnsToContents()
        dashboard.ui.tableWidget_tsi_scan_options.resizeRowsToContents()
        dashboard.ui.tableWidget_tsi_scan_options.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_tsi_scan_options.horizontalHeader().setStretchLastSection(True)

        # Set Selection to the Last Column
        dashboard.ui.tableWidget_tsi_scan_options.setCurrentItem(start_item)

        # Enable Remove Band Pushbutton
        dashboard.ui.pushButton_tsi_remove_band.setEnabled(True)

        # Refresh Bands
        _slotTSI_RefreshPlotClicked(dashboard)

        # Enable Zoom
        dashboard.ui.pushButton_tsi_zoom_in.setEnabled(True)

        # Enable Update TSI Configuration Pushbutton
        if dashboard.ui.pushButton_tsi_detector_start.text() == "Stop":
            dashboard.ui.pushButton_tsi_update.setEnabled(True)
            dashboard.ui.pushButton_tsi_update.setStyleSheet("border: 1px solid darkGray; border-radius: 6px; background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,stop: 0 #ffff00, stop: 1 #d8d800); min-width: 80px;")
            dashboard.ui.label2_tsi_update_configuration.setVisible(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_RemoveBandClicked(dashboard: QtCore.QObject):
    """ 
    Removes the selected column from the Wideband SDR Configuration table and edits the plot
    """
    # At Least One Band
    if dashboard.ui.tableWidget_tsi_scan_options.columnCount() > 0:
        # Delete Column from Table
        get_column = dashboard.ui.tableWidget_tsi_scan_options.currentColumn()
        dashboard.ui.tableWidget_tsi_scan_options.removeColumn(get_column)

        # Renumber the Bands in the Table
        for col in range(get_column,dashboard.ui.tableWidget_tsi_scan_options.columnCount()):
            header_item = QtWidgets.QTableWidgetItem("Band " + str(col+1))
            header_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_scan_options.setHorizontalHeaderItem(col,header_item)

        # Resize Table Columns and Rows
        dashboard.ui.tableWidget_tsi_scan_options.resizeColumnsToContents()
        dashboard.ui.tableWidget_tsi_scan_options.resizeRowsToContents()
        dashboard.ui.tableWidget_tsi_scan_options.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_tsi_scan_options.horizontalHeader().setStretchLastSection(True)

        # Refresh the Plot
        _slotTSI_RefreshPlotClicked(dashboard)

        # Disable the Pushbuttons
        if dashboard.ui.tableWidget_tsi_scan_options.columnCount() == 0:
            dashboard.ui.pushButton_tsi_remove_band.setEnabled(False)
            dashboard.ui.pushButton_tsi_update.setEnabled(False)
            dashboard.ui.pushButton_tsi_zoom_in.setEnabled(False)

        # Update TSI Configuration Pushbutton Color
        if dashboard.ui.pushButton_tsi_detector_start.text() == "Stop":
            dashboard.ui.pushButton_tsi_update.setStyleSheet("border: 1px solid darkGray; border-radius: 6px; background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,stop: 0 #ffff00, stop: 1 #d8d800); min-width: 80px;")
            dashboard.ui.label2_tsi_update_configuration.setVisible(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SavePresetClicked(dashboard: QtCore.QObject):
    """ 
    Creates a new preset from the table contents and adds it to the preset list
    """
    # Create an Empty 2D Array
    value_matrix = [[0 for x in range(10)] for x in range(dashboard.ui.tableWidget_tsi_scan_options.rowCount())]

    # Get the Values from the Table
    for col in range(0,dashboard.ui.tableWidget_tsi_scan_options.columnCount()):
        for row in range(0,dashboard.ui.tableWidget_tsi_scan_options.rowCount()):
            value_matrix[row][col] = dashboard.ui.tableWidget_tsi_scan_options.item(row,col).text()

    # Add the Values to the Dictionary and Table
    dashboard.preset_count = dashboard.preset_count + 1
    preset_name = "Preset " + str(dashboard.preset_count)
    dashboard.preset_dictionary[preset_name] = value_matrix  # Dictionary
    dashboard.ui.listWidget_tsi_scan_presets.addItem(preset_name)  # Table


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DeletePresetClicked(dashboard: QtCore.QObject):
    """ 
    Deletes the currently selected preset from the list
    """
    # Delete from the Table
    for item in dashboard.ui.listWidget_tsi_scan_presets.selectedItems():
        dashboard.ui.listWidget_tsi_scan_presets.takeItem(dashboard.ui.listWidget_tsi_scan_presets.row(item))

        # Delete from Memory
        del dashboard.preset_dictionary[str(item.text())]


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClearDetectorPlotClicked(dashboard: QtCore.QObject):
    """ 
    Clears the points on the detector plot.
    """
    # Clear the Narrowband Array
    rgb = tuple(int(dashboard.backend.settings['color2'].lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
    background_color = (float(rgb[0])/255, float(rgb[1])/255, float(rgb[2])/255)
    dashboard.wideband_data = np.ones((dashboard.wideband_height,dashboard.wideband_width,3))*(background_color)

    # Plot and Draw Incoming Wideband Signals
    dashboard.matplotlib_widget.axes.cla()
    dashboard.matplotlib_widget.axes.imshow(dashboard.wideband_data, cmap='rainbow', clim=(-100,30))
    dashboard.matplotlib_widget.configureAxes(title='Detector History',xlabel='Frequency (MHz)',ylabel='Time Elapsed (s)', xlabels=['0', '','1000', '', '2000', '', '3000', '', '4000', '', '5000', '', '6000'],ylabels=['0', '5', '10', '15', '20', '25', '30', '35', '40'],ylim=dashboard.wideband_height,background_color=dashboard.backend.settings['color1'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
    dashboard.matplotlib_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_RefreshPlotClicked(dashboard: QtCore.QObject):
    """ 
    Redraws the search band plot based on values from the table.
    """
    # Configure Detector Axes
    dashboard.wideband_zoom_start = 0
    dashboard.wideband_zoom_end = 6000e6
    _slotTSI_ClearDetectorPlotClicked(dashboard)
    dashboard.wideband_zoom = False
    dashboard.matplotlib_widget.configureAxes(title='Detector History',xlabel='Frequency (MHz)',ylabel='Time Elapsed (s)', xlabels=['0', '','1000', '', '2000', '', '3000', '', '4000', '', '5000', '', '6000'],ylabels=['0', '5', '10', '15', '20', '25', '30', '35', '40'],ylim=dashboard.wideband_height,background_color=dashboard.backend.settings['color1'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
    dashboard.matplotlib_widget.draw()

    # Delete the Bands
    for n in reversed(range(0,len(dashboard.tuning_widget.bands))):
        dashboard.tuning_widget.bands[n].remove()
        del dashboard.tuning_widget.bands[n]

    # Delete the Labels
    for n in reversed(range(0,len(dashboard.tuning_widget.axes.texts))):
        dashboard.tuning_widget.axes.texts[n].remove()

    # Redraw the Bands in the Table
    for col in range(0,dashboard.ui.tableWidget_tsi_scan_options.columnCount()):

        # Draw Band Rectangle
        start_value = float(str(dashboard.ui.tableWidget_tsi_scan_options.item(0,col).text()))
        end_value = float(str(dashboard.ui.tableWidget_tsi_scan_options.item(1,col).text()))

        h = dashboard.tuning_widget.axes.add_patch(patches.Rectangle((start_value/10,
            (dashboard.tuning_widget.band_height*(len(dashboard.tuning_widget.bands)+1))),
                end_value/10-start_value/10,dashboard.tuning_widget.band_height,facecolor="blue",edgecolor="Black"))
        dashboard.tuning_widget.bands.append(h)

        # Draw Text Label
        x_offset = 10
        band_number = str(col+1)
        if band_number == "10":
            x_offset = 15

        if start_value <= end_value:  # Makes it appear next to the left-most value
            x_pos = start_value
        else:
            x_pos = end_value

        dashboard.tuning_widget.axes.text(x_pos/10 - x_offset,(dashboard.tuning_widget.band_height*(len(dashboard.tuning_widget.bands)+1)) - 5,band_number,fontsize=10)
        #dashboard.tuning_widget.axes.text(-10,(dashboard.tuning_widget.band_height*(len(dashboard.tuning_widget.bands)+1)) - 5,band_number,fontsize=10)

    dashboard.tuning_widget.configureAxes(title='Tuning',xlabel='Frequency (MHz)',ylabel='',ylabels='',ylim=400,background_color=dashboard.backend.settings['color2'],face_color=dashboard.backend.settings['color5'],text_color=dashboard.backend.settings['color4'])
    dashboard.tuning_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ZoomInClicked(dashboard: QtCore.QObject):
    """ 
    Zooms in on the currently configured SDR bands.
    """
    # Get Min and Max Frequency
    start_frequency = []
    end_frequency = []

    for col in range(0,dashboard.ui.tableWidget_tsi_scan_options.columnCount()):
        start_frequency.append(int(int(dashboard.ui.tableWidget_tsi_scan_options.item(0,col).text())*1e6))
        end_frequency.append(int(int(dashboard.ui.tableWidget_tsi_scan_options.item(1,col).text())*1e6))

    min_freq = min(start_frequency)
    max_freq = float(max(end_frequency))

    # Round Frequencies by 100 MHz
    min_freq = min_freq - (min_freq%100e6)
    if (max_freq%100e6) != 0:
        max_freq = max_freq + 100e6 - (max_freq%100e6)

    # Resize the Plot Window
    dashboard.tuning_widget.configureAxesZoom(xmin=min_freq,xmax=max_freq)

    # Resize the Detector Window
    _slotTSI_ClearDetectorPlotClicked(dashboard)
    dashboard.wideband_zoom_start = min_freq
    dashboard.wideband_zoom_end = max_freq
    dashboard.wideband_zoom = True
    dashboard.matplotlib_widget.configureAxesZoom1(dashboard.wideband_zoom_start, dashboard.wideband_zoom_end, dashboard.wideband_height)

    #dashboard.matplotlib_widget.configureAxesZoom1(xmin=min_freq,xmax=max_freq)
    dashboard.matplotlib_widget.draw()

    # Delete the Band Labels
    for n in reversed(range(0,len(dashboard.tuning_widget.axes.texts))):
        dashboard.tuning_widget.axes.texts[n].remove()

    # Draw Text Label
    axis_scale = (dashboard.tuning_widget.axes.get_xlim()[1] - dashboard.tuning_widget.axes.get_xlim()[0])/600
    x_offset = 10 * (1*axis_scale)

    for col in range(0,dashboard.ui.tableWidget_tsi_scan_options.columnCount()):
        band_number = str(col+1)
        if band_number == "10":
            x_offset = 15
        if min_freq <= max_freq:  # Makes it appear next to the left-most value
            x_pos = start_frequency[col]/1e6
        else:
            x_pos = end_frequency[col]/1e6

        dashboard.tuning_widget.axes.text(x_pos/10 - x_offset,(dashboard.tuning_widget.band_height*(col+2)) - 5,band_number,fontsize=10)

    dashboard.tuning_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_AdvancedSettingsClicked(dashboard: QtCore.QObject):
    """ 
    Displays the advanced settings for the currently selected TSI detector.
    """
    # Switch to Advanced Settings
    fg_detectors = ['wideband_x3x0.py','wideband_b2x0.py','wideband_hackrf.py','wideband_b20xmini.py','wideband_rtl2832u.py','wideband_limesdr.py','wideband_bladerf.py','wideband_plutosdr.py','wideband_usrp2.py','wideband_usrp_n2xx.py','wideband_bladerf2.py','wideband_usrp_x410.py']

    # Flow Graph Detectors
    if str(dashboard.ui.comboBox_tsi_detector.currentText()) in fg_detectors:
        dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_Back1_Clicked(dashboard: QtCore.QObject):
    """ 
    Goes back to the TSI search band settings.
    """
    # Go Back
    dashboard.ui.stackedWidget1_tsi_detector.setCurrentIndex(0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorIQ_FileBrowseClicked(dashboard: QtCore.QObject):
    """ 
    Chooses an IQ file for detection.
    """
    # Look for a File
    default_directory = fissure.utils.IQ_RECORDINGS_DIR
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select IQ File...", default_directory, filter="All Files (*)")[0]

    # Valid File
    if fname != "":
        dashboard.ui.textEdit_tsi_detector_iq_file_file.setPlainText(fname)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorSearchClicked(dashboard: QtCore.QObject):
    """ 
    Switches to the Search tab and copies the selected frequency.
    """
    # Copy the Value
    get_row = dashboard.ui.tableWidget1_tsi_wideband.currentRow()
    if get_row >= 0:
        get_freq = dashboard.ui.tableWidget1_tsi_wideband.item(get_row,0).text()
        dashboard.ui.textEdit_library_search_frequency.setPlainText(get_freq)

        # Format the Search
        dashboard.ui.checkBox_library_search_frequency.setChecked(True)
        dashboard.ui.textEdit_library_search_frequency_margin.setPlainText("5")
        dashboard.ui.checkBox_library_search_start_frequency.setChecked(False)
        dashboard.ui.checkBox_library_search_end_frequency.setChecked(False)
        dashboard.ui.checkBox_library_search_bandwidth.setChecked(False)
        dashboard.ui.checkBox_library_search_modulation.setChecked(False)
        dashboard.ui.checkBox_library_search_continuous.setChecked(False)

        # Change Tabs
        dashboard.ui.tabWidget_library.setCurrentIndex(2)  # Search
        dashboard.ui.tabWidget.setCurrentIndex(7)  # Library


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorCSV_FileBrowseClicked(dashboard: QtCore.QObject):
    """ 
    Selects a CSV file for the TSI detector simulator.
    """
    # Look for a File
    default_directory = os.path.join(fissure.utils.TOOLS_DIR, "TSI_Detector_Sim_Data")
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select CSV File...", default_directory, filter="CSV Files (*.csv)")[0]

    # Valid File
    if fname != "":
        dashboard.ui.textEdit_tsi_detector_csv_file.setPlainText(fname)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_DetectorCSV_FileEditClicked(dashboard: QtCore.QObject):
    """ 
    Opens the CSV file selected for the TSI detector simulator.
    """
    # Issue the Command
    csv_filepath = str(dashboard.ui.textEdit_tsi_detector_csv_file.toPlainText())
    if len(csv_filepath) > 0:
        command_text = 'libreoffice ' + csv_filepath + ' &'
        proc = subprocess.Popen(command_text, shell=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFolderClicked(dashboard: QtCore.QObject):
    """ 
    Selects a source folder for input data.
    """
    # Choose Folder
    get_pwd = str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText())
    get_dir = str(QtWidgets.QFileDialog.getExistingDirectory(dashboard, "Select Directory",get_pwd))
    
    # Add Directory to the Combobox       
    if len(get_dir) > 0:   
            
        # Load Directory and File
        folder_index = dashboard.ui.comboBox_tsi_conditioner_input_folders.findText(get_dir)
        if folder_index < 0:
            # New Directory
            dashboard.ui.comboBox_tsi_conditioner_input_folders.addItem(get_dir)      
            dashboard.ui.comboBox_tsi_conditioner_input_folders.setCurrentIndex(dashboard.ui.comboBox_tsi_conditioner_input_folders.count()-1)
        else:
            # Directory Exists
            dashboard.ui.comboBox_tsi_conditioner_input_folders.setCurrentIndex(folder_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Refreshes the files displayed in the input listbox.
    """
    try:
        # Get the Folder Location
        get_folder = str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText())
            
        # Get the Files for the Listbox
        dashboard.ui.listWidget_tsi_conditioner_input_files.clear()
        temp_names = []
        for fname in os.listdir(get_folder):
            if os.path.isfile(os.path.join(get_folder, fname)):
                # All Files
                if dashboard.ui.radioButton_tsi_conditioner_input_extensions_all.isChecked():
                    temp_names.append(fname)
                # Only Files with Extension
                else:
                    get_extension = str(dashboard.ui.textEdit_tsi_conditioner_input_extensions.toPlainText())
                    if fname[-len(get_extension):] == get_extension:
                        temp_names.append(fname)
                
        # Sort and Add to the Listbox
        temp_names = sorted(temp_names, key=str.lower)
        for n in temp_names:
            dashboard.ui.listWidget_tsi_conditioner_input_files.addItem(n)
                
        # Set the Listbox Selection
        dashboard.ui.listWidget_tsi_conditioner_input_files.setCurrentRow(0)
    except:
        pass  


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes the selected file from the input listbox.
    """
    # Get Highlighted File from Listbox
    if dashboard.ui.listWidget_tsi_conditioner_input_files.count() > 0:
        get_index = int(dashboard.ui.listWidget_tsi_conditioner_input_files.currentRow())
        
        # Remove Item
        for item in dashboard.ui.listWidget_tsi_conditioner_input_files.selectedItems():
            dashboard.ui.listWidget_tsi_conditioner_input_files.takeItem(dashboard.ui.listWidget_tsi_conditioner_input_files.row(item))
        
        # Reset Selected Item 
        if get_index == dashboard.ui.listWidget_tsi_conditioner_input_files.count():
            get_index = get_index -1
        dashboard.ui.listWidget_tsi_conditioner_input_files.setCurrentRow(get_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputRenameClicked(dashboard: QtCore.QObject):
    """ 
    Renames the selected file from the input listbox.
    """
    # Get the Selected File
    try:
        get_file = str(dashboard.ui.listWidget_tsi_conditioner_input_files.currentItem().text())
    except:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("No File Selected.")
        return        
    get_file_path = os.path.join(str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText()), get_file)
    
    # Open the GUI
    text, ok = QtWidgets.QInputDialog.getText(dashboard, 'Rename', 'Enter new name:',QtWidgets.QLineEdit.Normal,get_file)
    
    # Ok Clicked
    if ok:
        os.rename(get_file_path, os.path.join(str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText()), text))
        _slotTSI_ConditionerInputRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputTerminalClicked(dashboard: QtCore.QObject):
    """ 
    Opens a terminal at the location of the input data folder.
    """
    # Open the Terminal
    get_dir = str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText())
    if len(get_dir) > 0:
        proc=subprocess.Popen('gnome-terminal', cwd=get_dir, shell=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputPreviewClicked(dashboard: QtCore.QObject):
    """ 
    Plots a zoomed out version of the input file.
    """       
    # Get the Filepath
    get_type = str(dashboard.ui.comboBox_tsi_conditioner_input_data_type.currentText())
    get_file = str(dashboard.ui.listWidget_tsi_conditioner_input_files.currentItem().text())
    get_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText()), get_file)
    try:
        number_of_bytes = os.path.getsize(get_filepath)
    except:
        number_of_bytes = -1
        
    # Number of Samples
    get_samples = "-1"
    if number_of_bytes > 0:            
        if get_type == "Complex Float 32":
            num_samples = int(number_of_bytes/8)
        elif get_type == "Float/Float 32":
            num_samples = int(number_of_bytes/4)
        elif get_type == "Short/Int 16":
            num_samples = int(number_of_bytes/2)
        elif get_type == "Int/Int 32":
            num_samples = int(number_of_bytes/4)
        elif get_type == "Byte/Int 8":
            num_samples = int(number_of_bytes/1)
        elif get_type == "Complex Int 16":
            num_samples = int(number_of_bytes/4)
        elif get_type == "Complex Int 8":
            num_samples = int(number_of_bytes/2)
        elif get_type == "Complex Float 64":
            num_samples = int(number_of_bytes/16)
        elif get_type == "Complex Int 64":
            num_samples = int(number_of_bytes/16)
    
    # File with Zero Bytes
    if number_of_bytes <= 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("File is empty")

    # Skip Bytes if File is Too Large        
    else:            
        # Get the Number of Samples
        start_sample = 1
    
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
                        
        # Read the Data 
        plot_data = b''
        file = open(get_filepath,"rb")                          # Open the file
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
                    
                # Every 100000th Sample
                elif number_of_bytes > 4000000000 and number_of_bytes <= 40000000000:
                    skip = 100000
                    
                # Skip 1000000
                else:
                    skip = 1000000
                
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
        
        # Plot
        plt.ion()
        plt.close(1) 
        if "Complex" in get_type:                    
            # Plot
            plt.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[::2],'b',linewidth=1,zorder=2)
            plt.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[1::2],'r',linewidth=1,zorder=2)
            plt.show()
        else:
            plt.plot(range(1,len(plot_data_formatted)+1),plot_data_formatted,'b',linewidth=1,zorder=2)
            plt.show()
            
        # Axes Labels
        if skip == 1:
            plt.xlabel('Samples') 
            plt.ylabel('Amplitude (LSB)') 
        else:
            plt.xlabel('Samples/' + str(skip)) 
            plt.ylabel('Amplitude (LSB)')

        plt.ioff()  # Needed for 22.04, causes warning in 20.04
        plt.show()  # Needed for 22.04, causes warning in 20.04


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsBrowseClicked(dashboard: QtCore.QObject):
    """ 
    Browses for a new folder location to output the isolated signal data.
    """
    # Choose Folder
    get_pwd = str(dashboard.ui.comboBox_tsi_conditioner_settings_folder.currentText())
    get_dir = str(QtWidgets.QFileDialog.getExistingDirectory(dashboard, "Select Directory",get_pwd))
    
    # Add Directory to the Combobox       
    if len(get_dir) > 0:   
            
        # Load Directory and File
        folder_index = dashboard.ui.comboBox_tsi_conditioner_settings_folder.findText(get_dir)
        if folder_index < 0:
            # New Directory
            dashboard.ui.comboBox_tsi_conditioner_settings_folder.addItem(get_dir)      
            dashboard.ui.comboBox_tsi_conditioner_settings_folder.setCurrentIndex(dashboard.ui.comboBox_tsi_conditioner_settings_folder.count()-1)
        else:
            # Directory Exists
            dashboard.ui.comboBox_tsi_conditioner_settings_folder.setCurrentIndex(folder_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsNowClicked(dashboard: QtCore.QObject):
    """ 
    Generates a new timestamp for the output file prefix.
    """
    # Set Prefix
    now = datetime.datetime.now()
    dashboard.ui.textEdit_tsi_conditioner_settings_prefix.setPlainText(now.strftime("%Y-%m-%d %H:%M:%S").replace(' ','_') + '_')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsPreviewClicked(dashboard: QtCore.QObject):
    """ 
    Plots a zoomed out version of the output file.
    """    
    # Get the Filepath
    get_row = dashboard.ui.tableWidget_tsi_conditioner_results.currentRow()
    if get_row >= 0:
        # Get File
        get_file = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(get_row,0).text())          
        get_type = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(get_row,3).text()) 
        get_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_conditioner_settings_folder.currentText()), get_file)
        try:
            number_of_bytes = os.path.getsize(get_filepath)
        except:
            number_of_bytes = -1
            
        # Number of Samples
        get_samples = "-1"
        if number_of_bytes > 0:            
            if get_type == "Complex Float 32":
                num_samples = int(number_of_bytes/8)
            elif get_type == "Float/Float 32":
                num_samples = int(number_of_bytes/4)
            elif get_type == "Short/Int 16":
                num_samples = int(number_of_bytes/2)
            elif get_type == "Int/Int 32":
                num_samples = int(number_of_bytes/4)
            elif get_type == "Byte/Int 8":
                num_samples = int(number_of_bytes/1)
            elif get_type == "Complex Int 16":
                num_samples = int(number_of_bytes/4)
            elif get_type == "Complex Int 8":
                num_samples = int(number_of_bytes/2)
            elif get_type == "Complex Float 64":
                num_samples = int(number_of_bytes/16)
            elif get_type == "Complex Int 64":
                num_samples = int(number_of_bytes/16)
        
        # File with Zero Bytes
        if number_of_bytes <= 0:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("File is empty")

        # Skip Bytes if File is Too Large        
        else:            
            # Get the Number of Samples
            start_sample = 1
        
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
                            
            # Read the Data 
            plot_data = b''
            file = open(get_filepath,"rb")                          # Open the file
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
                        
                    # Every 100000th Sample
                    elif number_of_bytes > 4000000000 and number_of_bytes <= 40000000000:
                        skip = 100000
                        
                    # Skip 1000000
                    else:
                        skip = 1000000
                    
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
            
            # Plot
            plt.ion()
            plt.close(1) 
            if "Complex" in get_type:                    
                # Plot
                plt.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[::2],'b',linewidth=1,zorder=2)
                plt.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[1::2],'r',linewidth=1,zorder=2)
                plt.show()
            else:
                plt.plot(range(1,len(plot_data_formatted)+1),plot_data_formatted,'b',linewidth=1,zorder=2)
                plt.show()
                
            # Axes Labels
            if skip == 1:
                plt.xlabel('Samples') 
                plt.ylabel('Amplitude (LSB)') 
            else:
                plt.xlabel('Samples/' + str(skip)) 
                plt.ylabel('Amplitude (LSB)')
            
            plt.ioff()  # Needed for 22.04, causes warning in 20.04
            plt.show()  # Needed for 22.04, causes warning in 20.04


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsFolderClicked(dashboard: QtCore.QObject):
    """ 
    Opens a window to the output directory.
    """
    # Open a Window
    get_folder = str(dashboard.ui.comboBox_tsi_conditioner_settings_folder.currentText())
    subprocess.Popen(['xdg-open', get_folder])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsExportClicked(dashboard: QtCore.QObject):
    """ 
    Exports the contents of the Results table to a CSV.
    """
    # Choose File Location
    path, ok = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save CSV', 'results.csv', 'CSV(*.csv)')
    if ok:
        columns = range(dashboard.ui.tableWidget_tsi_conditioner_results.columnCount())
        header = [dashboard.ui.tableWidget_tsi_conditioner_results.horizontalHeaderItem(column).text() for column in columns]
        with open(path, 'w') as csvfile:
            writer = csv.writer(csvfile, dialect='excel', lineterminator='\n')
            writer.writerow(header)
            for row in range(dashboard.ui.tableWidget_tsi_conditioner_results.rowCount()):
                writer.writerow(dashboard.ui.tableWidget_tsi_conditioner_results.item(row, column).text() for column in columns)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsDeleteClicked(dashboard: QtCore.QObject):
    """ 
    Deletes the selected file listed in the results.
    """
    # Get Highlighted File from Table
    if dashboard.ui.tableWidget_tsi_conditioner_results.rowCount() > 0:
        get_row = dashboard.ui.tableWidget_tsi_conditioner_results.currentRow()
        if get_row >= 0:
            get_file = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(get_row,0).text())          
            get_type = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(get_row,3).text()) 
            get_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_conditioner_settings_folder.currentText()), get_file)
            
            # Delete
            os.system('rm "' + get_filepath + '"')
            
            # Remove Row
            dashboard.ui.tableWidget_tsi_conditioner_results.removeRow(get_row)
            if get_row == dashboard.ui.tableWidget_tsi_conditioner_results.rowCount():
                dashboard.ui.tableWidget_tsi_conditioner_results.setCurrentCell(dashboard.ui.tableWidget_tsi_conditioner_results.rowCount()-1,0)                 
            elif get_row >= 0:
                dashboard.ui.tableWidget_tsi_conditioner_results.setCurrentCell(get_row,0)
                
            # Update File Count
            dashboard.ui.label2_tsi_conditioner_results_file_count.setText("File Count: " + str(dashboard.ui.tableWidget_tsi_conditioner_results.rowCount()))
        
        # Refresh FE Input Folder
        _slotTSI_FE_InputRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsViewClicked(dashboard: QtCore.QObject):
    """ 
    Opens visualization (GNU Radio Companion flow graph, image, code) for the isolation technique.
    """
    # View if Possible
    get_category = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText())
    get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.currentText())
    get_type = str(dashboard.ui.comboBox_tsi_conditioner_input_data_type.currentText())
    
    # Flow Graph Directory
    if get_type == "Complex Float 32":
        fg_directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "TSI Flow Graphs", "Conditioner", "Flow_Graphs", "ComplexFloat32")
    elif get_type == "Complex Int 16":
        fg_directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "TSI Flow Graphs", "Conditioner", "Flow_Graphs", "ComplexInt16")

    # Method1: burst_tagger
    if (get_category == "Energy - Burst Tagger") and (get_method == "Normal"):
        filepath = os.path.join(fg_directory, "burst_tagger", "normal.grc")
        osCommandString = 'gnuradio-companion "' + filepath
        os.system(osCommandString + '" &')
    
    # Method2: burst_tagger with Decay
    elif (get_category == "Energy - Burst Tagger") and (get_method == "Normal Decay"):
        filepath = os.path.join(fg_directory, "burst_tagger", "normal_decay.grc")
        osCommandString = 'gnuradio-companion "' + filepath
        os.system(osCommandString + '" &')
    
    # Method3: power_squelch_with_burst_tagger
    elif (get_category == "Energy - Burst Tagger") and (get_method == "Power Squelch"):
        filepath = os.path.join(fg_directory, "burst_tagger", "power_squelch.grc")
        osCommandString = 'gnuradio-companion "' + filepath
        os.system(osCommandString + '" &')
    
    # Method4: lowpass_filter
    elif (get_category == "Energy - Burst Tagger") and (get_method == "Lowpass"):
        filepath = os.path.join(fg_directory, "burst_tagger", "lowpass.grc")
        osCommandString = 'gnuradio-companion "' + filepath
        os.system(osCommandString + '" &')
    
    # Method5: power_squelch_lowpass
    elif (get_category == "Energy - Burst Tagger") and (get_method == "Power Squelch then Lowpass"):
        filepath = os.path.join(fg_directory, "burst_tagger", "power_squelch_lowpass.grc")
        osCommandString = 'gnuradio-companion "' + filepath
        os.system(osCommandString + '" &')
        
    # Method6: bandpass_filter
    elif (get_category == "Energy - Burst Tagger") and (get_method == "Bandpass"):
        filepath = os.path.join(fg_directory, "burst_tagger", "bandpass.grc")
        osCommandString = 'gnuradio-companion "' + filepath
        os.system(osCommandString + '" &')
        
    # Method7: strongest
    elif (get_category == "Energy - Burst Tagger") and (get_method == "Strongest Frequency then Bandpass"):
        filepath1 = os.path.join(fg_directory, "fft", "strongest.grc")
        filepath2 = os.path.join(fg_directory, "burst_tagger", "bandpass.grc")
        osCommandString = 'gnuradio-companion "' + filepath1 + '" "' + filepath2
        os.system(osCommandString + '" &')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsStripClicked(dashboard: QtCore.QObject):
    """ 
    Removes silence before and after a signal in an IQ file.
    """
    text, ok = QtWidgets.QInputDialog.getText(dashboard, 'Strip', 'Enter amplitude threshold:',QtWidgets.QLineEdit.Normal,"0.001")
    if ok:            
        # Load the Data
        get_row = dashboard.ui.tableWidget_tsi_conditioner_results.currentRow()
        if get_row >= 0:
            get_data_type = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(get_row,3).text())
            fname = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(get_row,0).text())
            get_output_directory = str(dashboard.ui.comboBox_tsi_conditioner_settings_folder.currentText())
            get_original_file = os.path.join(get_output_directory, fname)
            
            if os.path.isfile(get_original_file):
                # Read the Data 
                file = open(get_original_file,"rb")                    
                plot_data = file.read() 
                file.close()
                
                # Complex Float 64
                if (get_data_type == "Complex Float 64"):                
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/8)*'d', plot_data)                
                    np_data = np.asarray(plot_data_formatted, dtype=np.float64)
                        
                # Complex Float 32
                elif (get_data_type == "Complex Float 32") or (get_data_type == "Float/Float 32"):                
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/4)*'f', plot_data)                
                    np_data = np.asarray(plot_data_formatted, dtype=np.float32)         
                
                # Complex Int 16
                elif (get_data_type == "Complex Int 16") or (get_data_type == "Short/Int 16"):               
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/2)*'h', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int16)
                
                # Complex Int 64
                elif (get_data_type == "Complex Int 64"):               
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/8)*'l', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int64)
                    
                # Int/Int 32
                elif (get_data_type == "Int/Int 32"):               
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/4)*'h', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int32)
                    
                # Complex Int 8
                elif (get_data_type == "Complex Int 8") or (get_data_type == "Byte/Int 8"):               
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes)*'b', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int8)
                
                # Unknown
                else:
                    fissure.Dashboard.UI_Components.Qt5.errorMessage("Unknown Data Type")
                    return
                
                # Strip and Save
                strip_left = 0
                strip_right = len(np_data)
                for n in range(0, len(np_data)-1):
                    if abs(np_data[n]) > float(text):
                        if n%2 == 1:
                            strip_left = n+1
                        else:
                            strip_left = n
                        break
                for n in reversed(range(1, len(np_data))):
                    if abs(np_data[n]) > float(text):
                        if n%2 == 1:
                            strip_right = n-1
                        else:
                            strip_right = n
                        break                                
                np_data = np_data[strip_left:strip_right]
                np_data.tofile(get_original_file)
        
            # Refresh Samples
            _slotTSI_ConditionerResultsRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsStripAllClicked(dashboard: QtCore.QObject):
    """ 
    Removes silence before and after a signal for all IQ files in the Signal Conditioner Results table.
    """
    text, ok = QtWidgets.QInputDialog.getText(dashboard, 'Strip', 'Enter amplitude threshold:',QtWidgets.QLineEdit.Normal,"0.001")
    if ok:            
        # Load the Data
        for get_row in range(0,dashboard.ui.tableWidget_tsi_conditioner_results.rowCount()):
            get_data_type = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(get_row,3).text())
            fname = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(get_row,0).text())
            get_output_directory = str(dashboard.ui.comboBox_tsi_conditioner_settings_folder.currentText())
            get_original_file = os.path.join(get_output_directory, fname)
            
            if os.path.isfile(get_original_file):
                # Read the Data 
                file = open(get_original_file,"rb")                    
                plot_data = file.read() 
                file.close()
                
                # Complex Float 64
                if (get_data_type == "Complex Float 64"):                
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/8)*'d', plot_data)                
                    np_data = np.asarray(plot_data_formatted, dtype=np.float64)
                        
                # Complex Float 32
                elif (get_data_type == "Complex Float 32") or (get_data_type == "Float/Float 32"):                
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/4)*'f', plot_data)                
                    np_data = np.asarray(plot_data_formatted, dtype=np.float32)         
                
                # Complex Int 16
                elif (get_data_type == "Complex Int 16") or (get_data_type == "Short/Int 16"):               
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/2)*'h', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int16)
                
                # Complex Int 64
                elif (get_data_type == "Complex Int 64"):               
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/8)*'l', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int64)
                    
                # Int/Int 32
                elif (get_data_type == "Int/Int 32"):               
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes/4)*'h', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int32)
                    
                # Complex Int 8
                elif (get_data_type == "Complex Int 8") or (get_data_type == "Byte/Int 8"):               
                    # Strip and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes)*'b', plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int8)
                
                # Unknown
                else:
                    fissure.Dashboard.UI_Components.Qt5.errorMessage("Unknown Data Type")
                    return
                
                # Strip and Save
                strip_left = 0
                strip_right = len(np_data)
                for n in range(0, len(np_data)):
                    if abs(np_data[n]) > float(text): 
                        strip_left = n
                        break
                for n in reversed(range(0, len(np_data))):
                    if abs(np_data[n]) > float(text): 
                        strip_right = n
                        break                                
                np_data = np_data[strip_left:strip_right]
                np_data.tofile(get_original_file)
        
        # Refresh Samples
        _slotTSI_ConditionerResultsRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Updates the Signal Conditioner Results table with values obtained from files in the output folder location.
    """
    # Common GUI Parameters
    get_category = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText())
    get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.currentText())
    get_input_source = str(dashboard.ui.comboBox_tsi_conditioner_settings_input_source.currentText())
    get_output_directory = str(dashboard.ui.comboBox_tsi_conditioner_settings_folder.currentText())
    get_prefix = str(dashboard.ui.textEdit_tsi_conditioner_settings_prefix.toPlainText())
    get_sample_rate = str(dashboard.ui.textEdit_tsi_conditioner_info_sample_rate.toPlainText())
    get_tuned_freq = str(dashboard.ui.textEdit_tsi_conditioner_info_frequency.toPlainText())
    get_type = str(dashboard.ui.comboBox_tsi_conditioner_input_data_type.currentText())
    get_max_files = int(dashboard.ui.textEdit_tsi_conditioner_settings_max_files.toPlainText())
    get_min_samples = int(dashboard.ui.textEdit_tsi_conditioner_settings_min_samples.toPlainText())
        
    # Get Files in Output Folder
    file_names = []
    get_output_directory = str(dashboard.ui.comboBox_tsi_conditioner_settings_folder.currentText())
    for row in reversed(range(0,dashboard.ui.tableWidget_tsi_conditioner_results.rowCount())):
        fname = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(row,0).text())
        if os.path.isfile(os.path.join(get_output_directory, fname)):
            
            # File Size
            get_bytes = os.path.getsize(os.path.join(get_output_directory, fname))
            table_item = QtWidgets.QTableWidgetItem(str(round(get_bytes/1048576,2)))
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_conditioner_results.setItem(row,1,table_item)

            # Samples
            get_samples = "-1"
            if get_bytes > 0:            
                if get_type == "Complex Float 32":
                    get_samples = str(int(get_bytes/8))
                elif get_type == "Float/Float 32":
                    get_samples = str(int(get_bytes/4))
                elif get_type == "Short/Int 16":
                    get_samples = str(int(get_bytes/2))
                elif get_type == "Int/Int 32":
                    get_samples = str(int(get_bytes/4))
                elif get_type == "Byte/Int 8":
                    get_samples = str(int(get_bytes/1))
                elif get_type == "Complex Int 16":
                    get_samples = str(int(get_bytes/4))
                elif get_type == "Complex Int 8":
                    get_samples = str(int(get_bytes/2))
                elif get_type == "Complex Float 64":
                    get_samples = str(int(get_bytes/16))
                elif get_type == "Complex Int 64":
                    get_samples = str(int(get_bytes/16))   
            table_item = QtWidgets.QTableWidgetItem(str(get_samples))
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_conditioner_results.setItem(row,2,table_item)
            
    # Resize Table
    dashboard.ui.tableWidget_tsi_conditioner_results.resizeRowsToContents()
    dashboard.ui.tableWidget_tsi_conditioner_results.resizeColumnsToContents()
    dashboard.ui.tableWidget_tsi_conditioner_results.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_tsi_conditioner_results.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerResultsDeleteAllClicked(dashboard: QtCore.QObject):
    """ 
    Deletes all the IQ files in the Signal Conditioner output directory.
    """
    # Delete All Files
    if dashboard.ui.tableWidget_tsi_conditioner_results.rowCount() > 0:
        for get_row in reversed(range(0,dashboard.ui.tableWidget_tsi_conditioner_results.rowCount())):
            get_file = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(get_row,0).text())          
            get_type = str(dashboard.ui.tableWidget_tsi_conditioner_results.item(get_row,3).text()) 
            get_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_conditioner_settings_folder.currentText()), get_file)
            
            # Delete
            os.system('rm "' + get_filepath + '"')
            
            # Remove Row
            dashboard.ui.tableWidget_tsi_conditioner_results.removeRow(get_row)
                
            # Update File Count
            dashboard.ui.label2_tsi_conditioner_results_file_count.setText("File Count: " + str(dashboard.ui.tableWidget_tsi_conditioner_results.rowCount()))
        
        # Refresh FE Input Folder
        _slotTSI_FE_InputRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputFolderClicked(dashboard: QtCore.QObject):
    """ 
    Selects a source folder for input data.
    """
    # Choose Folder
    get_pwd = str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText())
    get_dir = str(QtWidgets.QFileDialog.getExistingDirectory(dashboard, "Select Directory",get_pwd))
    
    # Add Directory to the Combobox       
    if len(get_dir) > 0:   
            
        # Load Directory and File
        folder_index = dashboard.ui.comboBox_tsi_fe_input_folders.findText(get_dir)
        if folder_index < 0:
            # New Directory
            dashboard.ui.comboBox_tsi_fe_input_folders.addItem(get_dir)      
            dashboard.ui.comboBox_tsi_fe_input_folders.setCurrentIndex(dashboard.ui.comboBox_tsi_fe_input_folders.count()-1)
        else:
            # Directory Exists
            dashboard.ui.comboBox_tsi_fe_input_folders.setCurrentIndex(folder_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Refreshes the files displayed in the input listbox.
    """
    try:
        # Get the Folder Location
        get_folder = str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText())
            
        # Get the Files for the Listbox
        dashboard.ui.listWidget_tsi_fe_input_files.clear()
        temp_names = []
        for fname in os.listdir(get_folder):
            if os.path.isfile(os.path.join(get_folder, fname)):
                temp_names.append(fname)
                
        # Sort and Add to the Listbox
        temp_names = sorted(temp_names, key=str.lower)
        for n in temp_names:
            dashboard.ui.listWidget_tsi_fe_input_files.addItem(n)
                
        # Set the Listbox Selection
        dashboard.ui.listWidget_tsi_fe_input_files.setCurrentRow(0)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes the selected file from the input listbox.
    """
    # Get Highlighted File from Listbox
    if dashboard.ui.listWidget_tsi_fe_input_files.count() > 0:
        get_index = int(dashboard.ui.listWidget_tsi_fe_input_files.currentRow())
        
        # Remove Item
        for item in dashboard.ui.listWidget_tsi_fe_input_files.selectedItems():
            dashboard.ui.listWidget_tsi_fe_input_files.takeItem(dashboard.ui.listWidget_tsi_fe_input_files.row(item))
        
        # Reset Selected Item 
        if get_index == dashboard.ui.listWidget_tsi_fe_input_files.count():
            get_index = get_index -1
        dashboard.ui.listWidget_tsi_fe_input_files.setCurrentRow(get_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputRenameClicked(dashboard: QtCore.QObject):
    """ 
    Renames the selected file from the input listbox.
    """
    # Get the Selected File
    try:
        get_file = str(dashboard.ui.listWidget_tsi_fe_input_files.currentItem().text())
    except:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("No File Selected.")
        return        
    get_file_path = os.path.join(str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText()), get_file)
    
    # Open the GUI
    text, ok = QtWidgets.QInputDialog.getText(dashboard, 'Rename', 'Enter new name:',QtWidgets.QLineEdit.Normal,get_file)
    
    # Ok Clicked
    if ok:
        os.rename(get_file_path, os.path.join(str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText()), text))
        _slotTSI_FE_InputRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputTerminalClicked(dashboard: QtCore.QObject):
    """ 
    Opens a terminal at the location of the input data folder.
    """
    # Open the Terminal
    get_dir = str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText())
    if len(get_dir) > 0:
        proc=subprocess.Popen('gnome-terminal', cwd=get_dir, shell=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_InputPreviewClicked(dashboard: QtCore.QObject):
    """ 
    Plots a zoomed out version of the input file.
    """       
    # Get the Filepath
    get_type = str(dashboard.ui.comboBox_tsi_fe_input_data_type.currentText())
    get_file = str(dashboard.ui.listWidget_tsi_fe_input_files.currentItem().text())
    get_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText()), get_file)
    try:
        number_of_bytes = os.path.getsize(get_filepath)
    except:
        number_of_bytes = -1
        
    # Number of Samples
    get_samples = "-1"
    if number_of_bytes > 0:            
        if get_type == "Complex Float 32":
            num_samples = int(number_of_bytes/8)
        elif get_type == "Float/Float 32":
            num_samples = int(number_of_bytes/4)
        elif get_type == "Short/Int 16":
            num_samples = int(number_of_bytes/2)
        elif get_type == "Int/Int 32":
            num_samples = int(number_of_bytes/4)
        elif get_type == "Byte/Int 8":
            num_samples = int(number_of_bytes/1)
        elif get_type == "Complex Int 16":
            num_samples = int(number_of_bytes/4)
        elif get_type == "Complex Int 8":
            num_samples = int(number_of_bytes/2)
        elif get_type == "Complex Float 64":
            num_samples = int(number_of_bytes/16)
        elif get_type == "Complex Int 64":
            num_samples = int(number_of_bytes/16)
    
    # File with Zero Bytes
    if number_of_bytes <= 0:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("File is empty")

    # Skip Bytes if File is Too Large        
    else:            
        # Get the Number of Samples
        start_sample = 1
    
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
                        
        # Read the Data 
        plot_data = b''
        file = open(get_filepath,"rb")                          # Open the file
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
                    
                # Every 100000th Sample
                elif number_of_bytes > 4000000000 and number_of_bytes <= 40000000000:
                    skip = 100000
                    
                # Skip 1000000
                else:
                    skip = 1000000
                
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
        
        # Plot
        plt.ion()
        plt.close(1) 
        if "Complex" in get_type:                    
            # Plot
            plt.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[::2],'b',linewidth=1,zorder=2)
            plt.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[1::2],'r',linewidth=1,zorder=2)
            plt.show()
        else:
            plt.plot(range(1,len(plot_data_formatted)+1),plot_data_formatted,'b',linewidth=1,zorder=2)
            plt.show()
            
        # Axes Labels
        if skip == 1:
            plt.xlabel('Samples') 
            plt.ylabel('Amplitude (LSB)') 
        else:
            plt.xlabel('Samples/' + str(skip)) 
            plt.ylabel('Amplitude (LSB)')

        plt.ioff()  # Needed for 22.04, causes warning in 20.04
        plt.show()  # Needed for 22.04, causes warning in 20.04


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsPreviewClicked(dashboard: QtCore.QObject):
    """ 
    Plots a zoomed out version of the output file.
    """
    # Get the Filepath
    get_row = dashboard.ui.tableWidget_tsi_fe_results.currentRow()
    if get_row >= 0:
        # Get File
        get_file = str(dashboard.ui.tableWidget_tsi_fe_results.verticalHeaderItem(get_row).text())          
        get_type = str(dashboard.ui.comboBox_tsi_fe_input_data_type.currentText()) 
        get_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText()), get_file)
        try:
            number_of_bytes = os.path.getsize(get_filepath)
        except:
            number_of_bytes = -1
            
        # Number of Samples
        get_samples = "-1"
        if number_of_bytes > 0:            
            if get_type == "Complex Float 32":
                num_samples = int(number_of_bytes/8)
            elif get_type == "Float/Float 32":
                num_samples = int(number_of_bytes/4)
            elif get_type == "Short/Int 16":
                num_samples = int(number_of_bytes/2)
            elif get_type == "Int/Int 32":
                num_samples = int(number_of_bytes/4)
            elif get_type == "Byte/Int 8":
                num_samples = int(number_of_bytes/1)
            elif get_type == "Complex Int 16":
                num_samples = int(number_of_bytes/4)
            elif get_type == "Complex Int 8":
                num_samples = int(number_of_bytes/2)
            elif get_type == "Complex Float 64":
                num_samples = int(number_of_bytes/16)
            elif get_type == "Complex Int 64":
                num_samples = int(number_of_bytes/16)
        
        # File with Zero Bytes
        if number_of_bytes <= 0:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("File is empty")

        # Skip Bytes if File is Too Large        
        else:            
            # Get the Number of Samples
            start_sample = 1
        
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
                            
            # Read the Data 
            plot_data = b''
            file = open(get_filepath,"rb")                          # Open the file
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
                        
                    # Every 100000th Sample
                    elif number_of_bytes > 4000000000 and number_of_bytes <= 40000000000:
                        skip = 100000
                        
                    # Skip 1000000
                    else:
                        skip = 1000000
                    
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
            
            # Plot
            plt.ion()
            plt.close(1) 
            if "Complex" in get_type:                    
                # Plot
                plt.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[::2],'b',linewidth=1,zorder=2)
                plt.plot(range(1,len(plot_data_formatted[::2])+1),plot_data_formatted[1::2],'r',linewidth=1,zorder=2)
                plt.show()
            else:
                plt.plot(range(1,len(plot_data_formatted)+1),plot_data_formatted,'b',linewidth=1,zorder=2)
                plt.show()
                
            # Axes Labels
            if skip == 1:
                plt.xlabel('Samples') 
                plt.ylabel('Amplitude (LSB)') 
            else:
                plt.xlabel('Samples/' + str(skip)) 
                plt.ylabel('Amplitude (LSB)')

            plt.ioff()  # Needed for 22.04, causes warning in 20.04
            plt.show()  # Needed for 22.04, causes warning in 20.04


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsPlotColumnClicked(dashboard: QtCore.QObject):
    """ 
    Plots all column values in the results table.
    """
    if (dashboard.ui.tableWidget_tsi_fe_results.columnCount() > 0) and (dashboard.ui.tableWidget_tsi_fe_results.rowCount() > 0):
        # Get Column Values
        get_values = []
        get_col = dashboard.ui.tableWidget_tsi_fe_results.currentColumn()
        if get_col != -1:
            for get_row in range(dashboard.ui.tableWidget_tsi_fe_results.rowCount()):             
                get_value = float(str(dashboard.ui.tableWidget_tsi_fe_results.item(get_row, get_col).text()))
                get_values.append(get_value)  
            
            # Plot
            plt.ion()
            plt.close(1) 
            plt.plot(range(1,len(get_values)+1),get_values[:],'b',linewidth=1,zorder=2)
            plt.show()
                
            # Axes Labels
            plt.xlabel('Row') 
            plt.ylabel('Value')
        else:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Select a cell in the Results table.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_SettingsDeselectAllClicked(dashboard: QtCore.QObject):
    """ 
    Unchecks all the checkboxes in the Feature Extractor settings.
    """
    # Uncheck Everything
    dashboard.ui.checkBox_tsi_fe_td_mean.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_max.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_peak.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_ptp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_rms.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_variance.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_std_dev.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_power.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_crest.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_pulse.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_margin.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_kurtosis.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_skewness.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_zero_crossings.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_td_samples.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_mean_bps.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_max_bps.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_sum_tbp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_peak_bp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_var_bp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_std_dev_bp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_skewness_bp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_kurtosis_bp.setChecked(False)
    dashboard.ui.checkBox_tsi_fe_rel_spectral_peak_band.setChecked(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_SettingsSelectAllClicked(dashboard: QtCore.QObject):
    """ 
    Checks all the checkboxes in the Feature Extractor settings.
    """
    # Uncheck Everything
    dashboard.ui.checkBox_tsi_fe_td_mean.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_max.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_peak.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_ptp.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_rms.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_variance.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_std_dev.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_power.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_crest.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_pulse.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_margin.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_kurtosis.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_skewness.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_zero_crossings.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_td_samples.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_mean_bps.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_max_bps.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_sum_tbp.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_peak_bp.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_var_bp.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_std_dev_bp.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_skewness_bp.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_kurtosis_bp.setChecked(True)
    dashboard.ui.checkBox_tsi_fe_rel_spectral_peak_band.setChecked(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsExportClicked(dashboard: QtCore.QObject):
    """ 
    Exports the Feature Extractor Results table to .csv file.
    """
    if (dashboard.ui.tableWidget_tsi_fe_results.columnCount() > 0) and (dashboard.ui.tableWidget_tsi_fe_results.rowCount() > 0):
        # Choose File Location
        get_results_folder = os.path.expanduser("~/fe_results_no_truth.csv")
        path, ok = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save CSV', get_results_folder, 'CSV(*.csv)')
        if ok:
            columns = range(dashboard.ui.tableWidget_tsi_fe_results.columnCount())
            rows = range(dashboard.ui.tableWidget_tsi_fe_results.rowCount())
            header = ["File"] + [dashboard.ui.tableWidget_tsi_fe_results.horizontalHeaderItem(column).text() for column in columns]
            row_header = [dashboard.ui.tableWidget_tsi_fe_results.verticalHeaderItem(row).text() for row in rows]
            with open(path, 'w') as csvfile:
                writer = csv.writer(csvfile, dialect='excel', lineterminator='\n')
                writer.writerow(header)
                for row in rows:
                    get_row_items = []
                    get_row_items = [row_header[row]] + [str(dashboard.ui.tableWidget_tsi_fe_results.item(row, column).text()) for column in columns]
                    writer.writerow(get_row_items)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsPlotAvgClicked(dashboard: QtCore.QObject):
    """ 
    Creates a bar and strip plot with data from all the columns in the Feature Extractor Results table.
    """
    if (dashboard.ui.tableWidget_tsi_fe_results.columnCount() > 0) and (dashboard.ui.tableWidget_tsi_fe_results.rowCount() > 0):
        # Get Column Values
        all_values = []
        col = dashboard.ui.tableWidget_tsi_fe_results.currentColumn()
        get_label = str(dashboard.ui.tableWidget_tsi_fe_results.horizontalHeaderItem(col).text())
        for row in range(dashboard.ui.tableWidget_tsi_fe_results.rowCount()):       
            get_value = float(str(dashboard.ui.tableWidget_tsi_fe_results.item(row, col).text()))
            all_values.append(get_value)
        df = pd.DataFrame(all_values, columns=[get_label])

        # Bar Plot for Average
        plt.figure(figsize=(10,6))
        ax = sns.barplot(y=get_label, data=df, palette='nipy_spectral', alpha=0.5, errorbar=None)

        # Strip/Scatter Plot
        ax = sns.stripplot(y=get_label, data=df, palette='nipy_spectral', linewidth=0.5, alpha=0.6)
        #ax = sns.scatterplot(data=df, palette='nipy_spectral', linewidth=0.5, alpha=0.6)

        # Horizontal Line
        ax.axhline(y=round(df[get_label].mean(), 2), ls=':', c='k', linewidth=3, label=None)

        # Labels
        ax.set_xlabel(get_label, fontsize=14, weight='bold')
        ax.set_ylabel('Value', fontsize=14, weight='bold')
        ax.set_title('Strip Plot with Average', fontsize=20, weight='bold')
        #plt.legend(fontsize=14, loc='lower right')
        plt.show()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsTrimClicked(dashboard: QtCore.QObject):
    """ 
    Removes rows from the Feature Extractor Results table.
    """
    if (dashboard.ui.tableWidget_tsi_fe_results.columnCount() > 0) and (dashboard.ui.tableWidget_tsi_fe_results.rowCount() > 0):
        # Get the Average
        col = dashboard.ui.tableWidget_tsi_fe_results.currentColumn()
        final_sum = 0
        for row in range(dashboard.ui.tableWidget_tsi_fe_results.rowCount()):       
            final_sum = final_sum + float(str(dashboard.ui.tableWidget_tsi_fe_results.item(row, col).text()))
        col_average = round(final_sum/float(dashboard.ui.tableWidget_tsi_fe_results.rowCount()),2)
                
        # Open a GUI
        trim_settings_dlg = TrimSettings(parent=dashboard, default_value=str(col_average))
        trim_settings_dlg.show()
        trim_settings_dlg.exec_()  
        
        get_rule_value = trim_settings_dlg.return_value
        if len(get_rule_value) < 2:
            return
        
        # Remove the Rows
        for row in reversed(range(0,dashboard.ui.tableWidget_tsi_fe_results.rowCount())):
            get_value = float(str(dashboard.ui.tableWidget_tsi_fe_results.item(row, col).text()))
            if get_rule_value[0] == 1:
                if get_value < float(get_rule_value[1]):
                    dashboard.ui.tableWidget_tsi_fe_results.removeRow(row)
            else:
                if get_value > float(get_rule_value[1]):
                    dashboard.ui.tableWidget_tsi_fe_results.removeRow(row)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsImportClicked(dashboard: QtCore.QObject):
    """ 
    Imports a CSV into the Feature Extractor Results table.
    """
    # Choose File
    get_default_folder = os.path.expanduser("~/")
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select CSV File...", get_default_folder, filter="CSV (*.csv)")
    if fname != ('', ''):
        dashboard.ui.tableWidget_tsi_fe_results.setRowCount(0)
        dashboard.ui.tableWidget_tsi_fe_results.clear()
        with open(fname[0], "r") as fileInput:
            skip_first_row = 0
            for row in csv.reader(fileInput):
                if skip_first_row > 0:
                    dashboard.ui.tableWidget_tsi_fe_results.setRowCount(dashboard.ui.tableWidget_tsi_fe_results.rowCount() + 1)
                    for c in range(0,len(row)):
                        # File Name
                        if c == 0:
                            dashboard.ui.tableWidget_tsi_fe_results.setVerticalHeaderItem(dashboard.ui.tableWidget_tsi_fe_results.rowCount()-1,QtWidgets.QTableWidgetItem(str(row[0])))
                        else:
                            get_text = row[c]
                            table_item = QtWidgets.QTableWidgetItem(str(get_text))
                            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
                            dashboard.ui.tableWidget_tsi_fe_results.setItem(dashboard.ui.tableWidget_tsi_fe_results.rowCount()-1,c-1,table_item)
                else:
                    skip_first_row = 1
                    dashboard.ui.tableWidget_tsi_fe_results.setColumnCount(len(row)-1)
                    
                    # Column Name
                    for c in range(1,len(row)):                           
                        dashboard.ui.tableWidget_tsi_fe_results.setHorizontalHeaderItem(c-1,QtWidgets.QTableWidgetItem(str(row[c])))
                        
        # Resize Table
        dashboard.ui.tableWidget_tsi_fe_results.resizeRowsToContents()
        dashboard.ui.tableWidget_tsi_fe_results.resizeColumnsToContents()
        dashboard.ui.tableWidget_tsi_fe_results.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_tsi_fe_results.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsJointPlotClicked(dashboard: QtCore.QObject):
    """ 
    Compares the values for two features.
    """
    if (dashboard.ui.tableWidget_tsi_fe_results.columnCount() > 1) and (dashboard.ui.tableWidget_tsi_fe_results.rowCount() > 0):
        # Obtain Features from Results Table
        get_features = []
        for col in range(dashboard.ui.tableWidget_tsi_fe_results.columnCount()):
            get_features.append(str(dashboard.ui.tableWidget_tsi_fe_results.horizontalHeaderItem(col).text()))
            
        # Load the Dialog
        joint_plot_dlg = JointPlotDialog(parent=dashboard, feature_list=get_features)
        joint_plot_dlg.show()
        joint_plot_dlg.exec_()  
        
        get_selected_features = joint_plot_dlg.return_value
        if len(get_selected_features) != 2:
            if get_selected_features != "Cancel":
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Error retrieving two features")
            return
                        
        # Obtain the Features
        get_column_labels = []            
        for m in range(0,dashboard.ui.tableWidget_tsi_fe_results.columnCount()):
            get_column_labels.append(str(dashboard.ui.tableWidget_tsi_fe_results.horizontalHeaderItem(m).text()))
        df = pd.DataFrame(columns=get_column_labels)
        for row in range(0,dashboard.ui.tableWidget_tsi_fe_results.rowCount()):
            get_row = []
            for col in range(0,dashboard.ui.tableWidget_tsi_fe_results.columnCount()):
                get_row.append(str(dashboard.ui.tableWidget_tsi_fe_results.item(row,col).text()))
            df.loc[len(df)] = get_row            
        X = df[get_selected_features[0]].astype(float)
        y = df[get_selected_features[1]].astype(float)
        
        # Plot
        visualizer = JointPlotVisualizer(feature=get_selected_features[0], target=get_selected_features[1])
        visualizer.fit(X, y)
        visualizer.ax.set_xlabel(get_selected_features[0])
        visualizer.ax.set_ylabel(get_selected_features[1])
        visualizer.show()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsRemoveRowClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row from the Feature Extractor Results table.
    """
    # Remove Row
    if dashboard.ui.tableWidget_tsi_fe_results.rowCount() > 0:
        row = dashboard.ui.tableWidget_tsi_fe_results.currentRow()
        dashboard.ui.tableWidget_tsi_fe_results.removeRow(row)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_FE_ResultsRemoveColClicked(dashboard: QtCore.QObject):
    """ 
    Removes a column from the Feature Extractor Results table.
    """
    # Remove Column
    row = dashboard.ui.tableWidget_tsi_fe_results.currentRow()
    col = dashboard.ui.tableWidget_tsi_fe_results.currentColumn()
    dashboard.ui.tableWidget_tsi_fe_results.removeColumn(col)
    
    if dashboard.ui.tableWidget_tsi_fe_results.columnCount() > 0:
        if col == dashboard.ui.tableWidget_tsi_fe_results.columnCount():
            dashboard.ui.tableWidget_tsi_fe_results.setCurrentCell(row,col-1)
        elif col == 0:
            dashboard.ui.tableWidget_tsi_fe_results.setCurrentCell(row,0)
        else:
            dashboard.ui.tableWidget_tsi_fe_results.setCurrentCell(row,col)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_ClearWidebandListClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Wideband list on the Dashboard and in the HIPRFISR
    """
    dashboard.ui.tableWidget1_tsi_wideband.clearContents()
    dashboard.ui.tableWidget1_tsi_wideband.setRowCount(0)
    await dashboard.backend.clearWidebandList()


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_UpdateTSI_Clicked(dashboard: QtCore.QObject):
    """ 
    Signals to HIPRFISR to update the TSI settings
    """
    # Hide Update Configuration Label
    dashboard.ui.label2_tsi_update_configuration.setVisible(False)
    dashboard.ui.pushButton_tsi_update.setStyleSheet("")

    # Refresh the Plot
    _slotTSI_RefreshPlotClicked(dashboard)

    # Zoom In
    _slotTSI_ZoomInClicked(dashboard)

    # Gather the Information
    start_frequency = []
    end_frequency = []
    step_size = []
    dwell_time = []
    detector_port = dashboard.backend.settings["tsi_pub_port_id"]

    for col in range(0,dashboard.ui.tableWidget_tsi_scan_options.columnCount()):
        start_frequency.append(str(int(int(dashboard.ui.tableWidget_tsi_scan_options.item(0,col).text())*1e6)))
        end_frequency.append(str(int(int(dashboard.ui.tableWidget_tsi_scan_options.item(1,col).text())*1e6)))
        step_size.append(str(int(int(dashboard.ui.tableWidget_tsi_scan_options.item(2,col).text())*1e6)))
        dwell_time.append(str(dashboard.ui.tableWidget_tsi_scan_options.item(3,col).text()))

    # Send the Message
    await dashboard.backend.updateConfiguration(dashboard.active_sensor_node, start_frequency, end_frequency, step_size, dwell_time, detector_port)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_BlacklistAddClicked(dashboard: QtCore.QObject):
    """ 
    Adds frequency range for TSI to ignore to list widget and sends message to TSI.
    """
    # Get the Start and End Frequencies
    start_freq = dashboard.ui.textEdit_tsi_ignore_start.toPlainText()
    end_freq = dashboard.ui.textEdit_tsi_ignore_end.toPlainText()
    start_freq_hz = str(float(start_freq)*1e6)
    end_freq_hz = str(float(end_freq)*1e6)

    # Valid Selection
    # if a number, if end_freq > start_freq, if none are blank

    # Add it to the TSI Blacklist List Widget
    dashboard.ui.listWidget_tsi_blacklist.addItem(start_freq + "-" + end_freq)
    dashboard.ui.pushButton_tsi_blacklist_remove.setEnabled(True)

    # Inform the HIPRFISR
    await dashboard.backend.addBlacklist(start_freq_hz, end_freq_hz)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_BlacklistRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes frequency range item for TSI to ignore from the list widget and sends message to TSI.
    """
    # Get the Values in the Current Row
    start_freq = str(dashboard.ui.listWidget_tsi_blacklist.currentItem().text()).split("-")[0]
    end_freq = str(dashboard.ui.listWidget_tsi_blacklist.currentItem().text()).split("-")[1]
    start_freq_hz = str(float(start_freq)*1e6)
    end_freq_hz = str(float(end_freq)*1e6)

    # Remove it from the TSI Blacklist List Widget
    dashboard.ui.listWidget_tsi_blacklist.takeItem(dashboard.ui.listWidget_tsi_blacklist.currentRow())

    # Inform the HIPRFISR
    await dashboard.backend.removeBlacklist(start_freq_hz, end_freq_hz)

    # Disable the Pusbuttons
    if dashboard.ui.listWidget_tsi_blacklist.count() == 0:
        dashboard.ui.pushButton_tsi_blacklist_remove.setEnabled(False)
        dashboard.ui.pushButton_tsi_update.setEnabled(False)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_DetectorStartClicked(dashboard: QtCore.QObject):
    """ 
    Toggles the TSI sweep detector on and off.
    """
    # Turn off TSI Detector
    if dashboard.ui.pushButton_tsi_detector_start.text() == "Stop":
        # Send the Message
        await dashboard.backend.stopTSI_Detector(dashboard.active_sensor_node)
        if dashboard.active_sensor_node > -1:
            dashboard.statusbar_text[dashboard.active_sensor_node][1] = "Not Running"
            dashboard.refreshStatusBarText()
        dashboard.ui.label2_tsi_detector.setText("Detector - Not Running")
        dashboard.ui.label2_tsi_detector.raise_()

        # Change the Button Text
        dashboard.ui.pushButton_tsi_detector_start.setText("Start")

        # Update the Labels
        dashboard.ui.label2_tsi_current_band.setText("")
        dashboard.ui.label2_tsi_current_frequency.setText("")

        # Disable Update TSI Configuration Pushbutton
        dashboard.ui.pushButton_tsi_update.setEnabled(False)
        dashboard.ui.pushButton_tsi_update.setStyleSheet("")

        # Enable Comboboxes
        dashboard.ui.comboBox_tsi_detector_sweep_hardware.setEnabled(True)
        dashboard.ui.comboBox_tsi_detector.setEnabled(True)

        # Hide Update Configuration Label
        dashboard.ui.label2_tsi_update_configuration.setVisible(False)

        # Refresh Axes
        #_slotTSI_RefreshPlotClicked(dashboard)

        # Enable the Advanced Options
        dashboard.ui.frame_tsi_detector_settings1.setEnabled(True)

    # Turn on TSI Detector
    elif dashboard.ui.pushButton_tsi_detector_start.text() == "Start":
        # Get Sensor Node IP Address
        sensor_nodes = ['sensor_node1','sensor_node2','sensor_node3','sensor_node4','sensor_node5']
        get_sensor_node = sensor_nodes[dashboard.active_sensor_node]
        get_sensor_node_ip = str(dashboard.backend.settings[get_sensor_node]['ip_address'])
        
        # Sensor Node Hardware Information
        get_current_hardware = str(dashboard.ui.comboBox_tsi_detector_sweep_hardware.currentText())
        get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'tsi')
    
        # Get Detector
        get_detector = str(dashboard.ui.comboBox_tsi_detector.currentText())
        detector_port = dashboard.backend.settings["tsi_pub_port_id"]

        # IQ File is Different
        if get_detector == "IQ File":
            # Get Variable Names and Values
            variable_names = ['rx_freq','sample_rate', 'threshold', 'fft_size','filepath']
            get_sample_rate = str(dashboard.ui.textEdit_tsi_detector_iq_file_sample_rate.toPlainText())
            get_frequency = str(dashboard.ui.textEdit_tsi_detector_iq_file_frequency.toPlainText())
            get_threshold = str(dashboard.ui.spinBox_tsi_detector_iq_file_threshold.value())
            get_fft_size = str(dashboard.ui.comboBox_tsi_detector_iq_file_fft_size.currentText())
            get_filepath = str(dashboard.ui.textEdit_tsi_detector_iq_file_file.toPlainText())
            variable_values = [get_frequency, get_sample_rate, get_threshold, get_fft_size, get_filepath]
            
            # Sensor Node IP Address
            variable_names.append('sensor_node_ip_address')
            variable_values.append(get_sensor_node_ip)

            # Valid Filepath
            if get_filepath == "":
                # msgBox = MyMessageBox(my_text = " Choose an IQ file.", height = 75, width = 140)
                # msgBox.exec_()
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Choose an IQ file.")
                return

        elif get_detector == "Simulator":
            # Get Variable Names and Values
            variable_names = ['filepath']
            get_filepath = str(dashboard.ui.textEdit_tsi_detector_csv_file.toPlainText())
            variable_values = [get_filepath]
            
            # Sensor Node IP Address
            variable_names.append('sensor_node_ip_address')
            variable_values.append(get_sensor_node_ip)

            # Valid Filepath
            if get_filepath == "":
                # msgBox = MyMessageBox(my_text = " Choose a CSV file.", height = 75, width = 140)
                # msgBox.exec_()
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Choose a CSV file.")
                return

        else:
            # No Hardware Selected
            if len(get_hardware_ip) == 0 and len(get_hardware_serial) == 0 \
                and (('x3x0' in get_detector) or ('b2x0' in get_detector) or ('x410' in get_detector)):

                error_text = " Fill out the IP address or serial number by clicking the TSI hardware button."

                # Create a Dialog Window
                # msgBox = MyMessageBox(my_text = error_text, height = 100, width = 510)
                # msgBox.exec_()
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, error_text)
                return

            # Valid Hardware
            else:
                # Get Variable Names and Values
                variable_names = ['rx_freq','sample_rate', 'threshold', 'fft_size','gain','channel','antenna']
                get_sample_rate = str(dashboard.ui.textEdit_tsi_detector_fg_sample_rate.toPlainText())
                get_threshold = str(dashboard.ui.spinBox_tsi_detector_fg_threshold.value())
                get_fft_size = str(dashboard.ui.comboBox_tsi_detector_fg_fft_size.currentText())
                get_gain = str(dashboard.ui.spinBox_tsi_detector_fg_gain.value())
                get_channel = str(dashboard.ui.comboBox_tsi_detector_fg_channel.currentText())
                get_antenna = str(dashboard.ui.comboBox_tsi_detector_fg_antenna.currentText())
                variable_values = ['1.2e9',get_sample_rate, get_threshold, get_fft_size, get_gain, get_channel, get_antenna]

                # Hardware IP Address
                variable_names.append('ip_address')
                variable_values.append(get_hardware_ip)
                
                # Sensor Node IP Address
                variable_names.append('sensor_node_ip_address')
                variable_values.append(get_sensor_node_ip)

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
                variable_names.append('serial')
                variable_values.append(get_serial)

        # Disable Comboboxes
        dashboard.ui.comboBox_tsi_detector_sweep_hardware.setEnabled(False)
        dashboard.ui.comboBox_tsi_detector.setEnabled(False)

        # Send the Message
        await dashboard.backend.startTSI_Detector(dashboard.active_sensor_node, get_detector, variable_names, variable_values, detector_port)
        if dashboard.active_sensor_node > -1:
            dashboard.statusbar_text[dashboard.active_sensor_node][1] = "Running TSI"
            dashboard.refreshStatusBarText()
        dashboard.ui.label2_tsi_detector.setText("Detector - Running")
        dashboard.ui.label2_tsi_detector.raise_()

        # Change the Button Text
        dashboard.ui.pushButton_tsi_detector_start.setText("Stop")

        # Enable Update TSI Configuration Pushbutton
        if dashboard.ui.tableWidget_tsi_scan_options.columnCount() > 0:
            # Keep Update Button Disabled for Simulator and IQ File
            if not ((str(dashboard.ui.comboBox_tsi_detector.currentText()) == "Simulator") or (str(dashboard.ui.comboBox_tsi_detector.currentText()) == "IQ File")):
                dashboard.ui.pushButton_tsi_update.setEnabled(True)
                dashboard.ui.pushButton_tsi_update.setStyleSheet("border: 1px solid darkGray; border-radius: 6px; background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,stop: 0 #ffff00, stop: 1 #d8d800); min-width: 80px;")

        # Show Update Configuration Label
        if (str(dashboard.ui.comboBox_tsi_detector.currentText()) == "Simulator") or (str(dashboard.ui.comboBox_tsi_detector.currentText()) == "IQ File"):
            dashboard.ui.label2_tsi_update_configuration.setVisible(False)
        else:
            dashboard.ui.label2_tsi_update_configuration.setVisible(True)

        # Disable the Advanced Options
        dashboard.ui.frame_tsi_detector_settings1.setEnabled(False)

        # Start Plotting
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, detectorPlotLoop, dashboard)


def detectorPlotLoop(dashboard: QtCore.QObject):
    """
    Continously loops to plot the detector waterfall plot when the detector is active.
    """
    # Plot and Draw Incoming Wideband Signals When Running Detector
    total_time = 0
    loop_time_interval = 1  # in seconds
    wideband_time_interval = 1
    while ((dashboard.ui.pushButton_tsi_detector_start.text() == "Stop") or (dashboard.ui.pushButton_tsi_detector_fixed_start.text() == "Stop")) and (dashboard.all_closed_down == False):
        # Single Loop Start Time
        start_time = time.time()

        # Update Start/End Frequency Spin Boxes
        if dashboard.tuning_widget.needs_update == True:
            dashboard.ui.spinBox_tsi_sdr_start.setValue(int(dashboard.tuning_widget.first_click))
            dashboard.ui.spinBox_tsi_sdr_end.setValue(int(dashboard.tuning_widget.second_click))
            dashboard.tuning_widget.needs_update = False

        # Plot
        dashboard.matplotlib_widget.axes.cla()
        dashboard.matplotlib_widget.axes.imshow(dashboard.wideband_data, cmap='rainbow', clim=(-100,30), extent=[0,1201,801,0])
        if dashboard.wideband_zoom == True:
            dashboard.matplotlib_widget.configureAxesZoom1(dashboard.wideband_zoom_start, dashboard.wideband_zoom_end, dashboard.wideband_height)
        else:
            dashboard.matplotlib_widget.configureAxes(
                title='Detector History',
                xlabel='Frequency (MHz)',
                ylabel='Time Elapsed (s)', 
                xlabels=['0', '','1000', '', '2000', '', '3000', '', '4000', '', '5000', '', '6000'],
                ylabels=['0', '5', '10', '15', '20', '25', '30', '35', '40'],
                ylim=dashboard.wideband_height,
                background_color=dashboard.backend.settings['color1'],
                face_color=dashboard.backend.settings['color5'],
                text_color=dashboard.backend.settings['color4'])
        dashboard.matplotlib_widget.draw()

        # Shift Wideband Rows Down
        if (total_time % wideband_time_interval == 0) and (total_time != 0):
            # Wideband Detector Background Color
            rgb = tuple(int(dashboard.backend.settings['color2'].lstrip('#')[i:i+2], 16) for i in (0, 2, 4))
            background_color = (float(rgb[0])/255, float(rgb[1])/255, float(rgb[2])/255)

            shift = 20
            dashboard.wideband_data[shift:dashboard.wideband_height-1 , 0:dashboard.wideband_width-1] = dashboard.wideband_data[0:dashboard.wideband_height-1-shift, 0:dashboard.wideband_width-1]
            dashboard.wideband_data[0:shift, 0:dashboard.wideband_width-1] = background_color

        # Update the Total Time
        total_time = total_time + loop_time_interval

        # Sleep the Remainder of the Time Interval
        time_difference = loop_time_interval-(time.time()-start_time)
        if time_difference > 0:
            time.sleep(time_difference)

        time.sleep(1)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_DetectorFixedStartClicked(dashboard: QtCore.QObject):
    """ 
    Starts a TSI detector set to a tuned frequency.
    """
    # Turn off TSI Detector
    if dashboard.ui.pushButton_tsi_detector_fixed_start.text() == "Stop":
        # Send the Message
        await dashboard.backend.stopTSI_Detector(dashboard.active_sensor_node)
        if dashboard.active_sensor_node > -1:
            dashboard.statusbar_text[dashboard.active_sensor_node][1] = "Not Running"
            dashboard.refreshStatusBarText()
        dashboard.ui.label2_tsi_detector.setText("Detector - Not Running")
        dashboard.ui.label2_tsi_detector.raise_()

        # Change the Button Text
        dashboard.ui.pushButton_tsi_detector_fixed_start.setText("Start")

        # Enable the Advanced Options
        dashboard.ui.frame_tsi_detector_fixed_settings1.setEnabled(True)

        # Enable Combobox
        dashboard.ui.comboBox_tsi_detector_fixed_hardware.setEnabled(True)
        dashboard.ui.comboBox_tsi_detector_fixed.setEnabled(True)

    # Turn on TSI Detector
    elif dashboard.ui.pushButton_tsi_detector_fixed_start.text() == "Start":
        # Get Sensor Node IP Address
        sensor_nodes = ['sensor_node1','sensor_node2','sensor_node3','sensor_node4','sensor_node5']
        get_sensor_node = sensor_nodes[dashboard.active_sensor_node]
        get_sensor_node_ip = str(dashboard.backend.settings[get_sensor_node]['ip_address'])
        
        # Sensor Node Hardware Information
        get_current_hardware = str(dashboard.ui.comboBox_tsi_detector_fixed_hardware.currentText())
        get_hardware_type, get_hardware_uid, get_hardware_radio_name, get_hardware_serial, get_hardware_interface, get_hardware_ip, get_hardware_daughterboard = fissure.utils.hardware.hardwareDisplayNameLookup(dashboard, get_current_hardware, 'tsi')

        # Get Detector
        get_detector = str(dashboard.ui.comboBox_tsi_detector_fixed.currentText())

        # No Hardware Selected
        if len(get_hardware_ip) == 0 and len(get_hardware_serial) == 0 \
            and (('x3x0' in get_detector) or ('b2x0' in get_detector) or ('x410' in get_detector)):

            error_text = " Fill out the IP address or serial number by clicking the TSI hardware button."

            # Create a Dialog Window
            # msgBox = MyMessageBox(my_text = error_text, height = 100, width = 510)
            # msgBox.exec_()
            ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, error_text)
            return

        # Valid Hardware
        else:
            # Get Variable Names and Values
            variable_names = ['rx-freq-default','sample-rate-default', 'threshold-default', 'gain-default','channel-default','antenna-default']
            get_frequency = str(dashboard.ui.textEdit_tsi_detector_fixed_frequency.toPlainText())
            get_sample_rate = str(dashboard.ui.comboBox_tsi_detector_fixed_sample_rate.currentText())
            get_threshold = str(dashboard.ui.spinBox_tsi_detector_fixed_threshold.value())
            get_gain = str(dashboard.ui.spinBox_tsi_detector_fixed_gain.value())
            get_channel = str(dashboard.ui.comboBox_tsi_detector_fixed_channel.currentText())
            get_antenna = str(dashboard.ui.comboBox_tsi_detector_fixed_antenna.currentText())
            variable_values = [get_frequency, get_sample_rate, get_threshold, get_gain, get_channel, get_antenna]
            detector_port = dashboard.backend.settings["tsi_pub_port_id"]

            # Hardware IP Address
            variable_names.append('ip-address')
            variable_values.append(get_hardware_ip)
            
            # # Sensor Node IP Address
            # variable_names.append('sensor-node-ip-address')
            # variable_values.append(get_sensor_node_ip)

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
            variable_names.append('serial')
            variable_values.append(get_serial)

        # Disable Combobox
        dashboard.ui.comboBox_tsi_detector_fixed_hardware.setEnabled(False)
        dashboard.ui.comboBox_tsi_detector_fixed.setEnabled(False)

        # Send the Message
        await dashboard.backend.startTSI_Detector(dashboard.active_sensor_node, get_detector, variable_names, variable_values, detector_port)
        if dashboard.active_sensor_node > -1:
            dashboard.statusbar_text[dashboard.active_sensor_node][1] = "Running TSI"
            dashboard.refreshStatusBarText()
        dashboard.ui.label2_tsi_detector.setText("Detector - Running")
        dashboard.ui.label2_tsi_detector.raise_()

        # Change the Button Text
        dashboard.ui.pushButton_tsi_detector_fixed_start.setText("Stop")

        # Disable the Advanced Options
        dashboard.ui.frame_tsi_detector_fixed_settings1.setEnabled(False)

        # Start Plotting
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, detectorPlotLoop, dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_ConditionerOperationStartClicked(dashboard: QtCore.QObject):
    """ 
    Begins conditioning and isolating signals from a file or several files.
    """
    # Stop
    if dashboard.ui.pushButton_tsi_conditioner_operation_start.text() == "Stop":
        
        # Send the Message
        await dashboard.backend.stopTSI_Conditioner(dashboard.active_sensor_node)

        # Reset Progress Bar
        dashboard.ui.progressBar_tsi_conditioner_operation.setValue(0)
        
        # Toggle the Text
        dashboard.ui.pushButton_tsi_conditioner_operation_start.setText("Start")
                    
    # Start
    elif dashboard.ui.pushButton_tsi_conditioner_operation_start.text() == "Start": 
    
        # Toggle the Text
        dashboard.ui.pushButton_tsi_conditioner_operation_start.setText("Stop")  
        
        # Reset Progress Bar
        dashboard.ui.progressBar_tsi_conditioner_operation.setValue(0)
        
        # Common GUI Parameters
        get_input_source = str(dashboard.ui.comboBox_tsi_conditioner_settings_input_source.currentText())

        get_category = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText())
        get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.currentText())
        get_output_directory = str(dashboard.ui.comboBox_tsi_conditioner_settings_folder.currentText())
        get_prefix = str(dashboard.ui.textEdit_tsi_conditioner_settings_prefix.toPlainText())
        get_sample_rate = str(dashboard.ui.textEdit_tsi_conditioner_info_sample_rate.toPlainText())
        get_tuned_freq = str(dashboard.ui.textEdit_tsi_conditioner_info_frequency.toPlainText())
        get_type = str(dashboard.ui.comboBox_tsi_conditioner_input_data_type.currentText())
        get_max_files = int(dashboard.ui.textEdit_tsi_conditioner_settings_max_files.toPlainText())
        get_min_samples = int(dashboard.ui.textEdit_tsi_conditioner_settings_min_samples.toPlainText())
        get_detect_saturation = str(dashboard.ui.checkBox_tsi_conditioner_settings_saturation.isChecked())
        get_saturation_min = ''
        get_saturation_max = ''
        get_normalize_output = str(dashboard.ui.checkBox_tsi_conditioner_settings_normalize_output.isChecked())
        get_normalize_min = ''
        get_normalize_max = ''

        # Check for Saturation
        if dashboard.ui.checkBox_tsi_conditioner_settings_saturation.isChecked():
            # Get Min/Max
            if dashboard.ui.comboBox_tsi_conditioner_settings_saturation.currentIndex() == 0:
                get_saturation_min = '-1'
                get_saturation_max = '1'
            elif dashboard.ui.comboBox_tsi_conditioner_settings_saturation.currentIndex() == 1:
                get_saturation_min = '-128'
                get_saturation_max = '127'
            elif dashboard.ui.comboBox_tsi_conditioner_settings_saturation.currentIndex() == 2:
                get_saturation_min = '-32768'
                get_saturation_max = '32767'
            elif dashboard.ui.comboBox_tsi_conditioner_settings_saturation.currentIndex() == 3:
                get_saturation_min = '-2147483648'
                get_saturation_max = '2147483647'
            elif dashboard.ui.comboBox_tsi_conditioner_settings_saturation.currentIndex() == 4:
                get_saturation_min = '-9223372036854775808'
                get_saturation_max = '9223372036854775807'
                
        # Check for Normalize
        if dashboard.ui.checkBox_tsi_conditioner_settings_normalize_output.isChecked():
            # Get Min/Max
            if dashboard.ui.comboBox_tsi_conditioner_settings_normalize.currentIndex() == 0:
                get_normalize_min = '-1'
                get_normalize_max = '1'
            elif dashboard.ui.comboBox_tsi_conditioner_settings_normalize.currentIndex() == 1:
                get_normalize_min = '-128'
                get_normalize_max = '127'
            elif dashboard.ui.comboBox_tsi_conditioner_settings_normalize.currentIndex() == 2:
                get_normalize_min = '-32768'
                get_normalize_max = '32767'
            elif dashboard.ui.comboBox_tsi_conditioner_settings_normalize.currentIndex() == 3:
                get_normalize_min = '-2147483648'
                get_normalize_max = '2147483647'
            elif dashboard.ui.comboBox_tsi_conditioner_settings_normalize.currentIndex() == 4:
                get_normalize_min = '-9223372036854775808'
                get_normalize_max = '9223372036854775807'
            # else:
                # try:
                    # get_min = float(dashboard.ui.textEdit_iq_normalize_min.toPlainText())
                    # get_max = float(dashboard.ui.textEdit_iq_normalize_max.toPlainText())
                # except:
                    # print("Not a valid float.")
                    # return
                                
        # File
        get_all_filepaths = []
        if get_input_source == "File":
            get_filename = str(dashboard.ui.label2_tsi_conditioner_info_file_name.text().replace("File: ",""))
            get_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText()), get_filename)
            if os.path.isfile(get_filepath):
                get_all_filepaths.append(get_filepath)
            else:
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid input file. Click the Refresh button.")
                return
        
        # Folder
        else:
            if dashboard.ui.listWidget_tsi_conditioner_input_files.count() > 0:
                for n in range(0,dashboard.ui.listWidget_tsi_conditioner_input_files.count()):
                    # All Files
                    if dashboard.ui.radioButton_tsi_conditioner_input_extensions_all.isChecked():
                        complete_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText()), str(dashboard.ui.listWidget_tsi_conditioner_input_files.item(n).text()))
                        if os.path.isfile(complete_filepath):
                            get_all_filepaths.append(complete_filepath)
                        else:
                            ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid input file. Click the Refresh button.")
                            return
                        
                    # Only Files with Extension
                    else:
                        get_extension = str(dashboard.ui.textEdit_tsi_conditioner_input_extensions.toPlainText())
                        if str(dashboard.ui.listWidget_tsi_conditioner_input_files.item(n).text())[-len(get_extension):] == get_extension:
                            complete_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText()), str(dashboard.ui.listWidget_tsi_conditioner_input_files.item(n).text()))
                            if os.path.isfile(complete_filepath):
                                get_all_filepaths.append(complete_filepath)
                            else:
                                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid input file. Click the Refresh button.")
                                return

            else:
                # fissure.Dashboard.UI_Components.Qt5.errorMessage("No input files found.")
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "No input files found.")
                return
        
        # Method1: burst_tagger
        if (get_category == "Energy - Burst Tagger") and (get_method == "Normal"):
            get_threshold = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_threshold.toPlainText())
            method_parameter_names = ['threshold']
            method_parameter_values = [get_threshold]
            
        # Method2: burst_tagger with Decay    
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Normal Decay"):
            get_threshold = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_decay_threshold.toPlainText())
            get_decay = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_decay_decay.toPlainText())
            method_parameter_names = ['threshold','decay']
            method_parameter_values = [get_threshold,get_decay]
            
        # Method3: power_squelch_with_burst_tagger    
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Power Squelch"):
            get_squelch = str(dashboard.ui.textEdit_tsi_conditioner_settings_psbt_squelch.toPlainText())
            get_threshold = str(dashboard.ui.textEdit_tsi_conditioner_settings_psbt_threshold.toPlainText())
            method_parameter_names = ['squelch','threshold']
            method_parameter_values = [get_squelch,get_threshold]
            
        # Method4: lowpass_filter    
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Lowpass"):
            get_threshold = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_lowpass_threshold.toPlainText())
            get_cutoff = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_lowpass_cutoff.toPlainText())
            get_transition = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_lowpass_transition.toPlainText())
            get_beta = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_lowpass_beta.toPlainText())
            method_parameter_names = ['threshold','cutoff','transition','beta']
            method_parameter_values = [get_threshold,get_cutoff,get_transition,get_beta]
        
        # Method5: power_squelch_lowpass    
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Power Squelch then Lowpass"):
            get_squelch = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_psl_squelch.toPlainText())
            get_cutoff = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_psl_cutoff.toPlainText())
            get_transition = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_psl_transition.toPlainText())
            get_beta = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_psl_beta.toPlainText())
            get_threshold = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_psl_threshold.toPlainText())
            method_parameter_names = ['squelch','cutoff','transition','beta','threshold']
            method_parameter_values = [get_squelch,get_cutoff,get_transition,get_beta,get_threshold]
                
        # Method6: bandpass_filter    
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Bandpass"):
            get_bandpass_freq = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_bandpass_freq.toPlainText())
            get_bandpass_width = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_bandpass_width.toPlainText())
            get_transition = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_bandpass_transition.toPlainText())
            get_beta = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_bandpass_beta.toPlainText())
            get_threshold = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_bandpass_threshold.toPlainText())
            method_parameter_names = ['bandpass_frequency','bandpass_width','transition','beta','threshold']
            method_parameter_values = [get_bandpass_freq,get_bandpass_width,get_transition,get_beta,get_threshold]
        
        # Method7: strongest    
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Strongest Frequency then Bandpass"):
            get_fft_size = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_sfb_fft_size.toPlainText())
            get_fft_threshold = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_sfb_fft_threshold.toPlainText())
            get_bandpass_width = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_sfb_width.toPlainText())
            get_transition = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_sfb_transition.toPlainText())
            get_beta = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_sfb_beta.toPlainText())
            get_threshold = str(dashboard.ui.textEdit_tsi_conditioner_settings_bt_sfb_threshold.toPlainText())
            method_parameter_names = ['fft_size','fft_threshold','bandpass_width','transition','beta','threshold']
            method_parameter_values = [get_fft_size,get_fft_threshold,get_bandpass_width,get_transition,get_beta,get_threshold]
            
        # Uknown Method
        else:
            dashboard.ui.progressBar_tsi_conditioner_operation.setValue(0)
            #dashboard.stop_operations = True        
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setText("Start")
            return
            
        # Assemble
        common_parameter_names = ['category','method','output_directory','prefix','sample_rate','tuned_frequency','data_type','max_files','min_samples','all_filepaths','detect_saturation','saturation_min','saturation_max','normalize_output','normalize_min','normalize_max']
        common_parameter_values = [get_category,get_method,get_output_directory,get_prefix,get_sample_rate,get_tuned_freq,get_type,get_max_files,get_min_samples,get_all_filepaths,get_detect_saturation,get_saturation_min,get_saturation_max,get_normalize_output,get_normalize_min,get_normalize_max]

        # Start the Progress Bar
        dashboard.ui.progressBar_tsi_conditioner_operation.setValue(1)
        
        # Send the Message
        await dashboard.backend.startTSI_Conditioner(dashboard.active_sensor_node, common_parameter_names, common_parameter_values, method_parameter_names, method_parameter_values)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_FE_OperationStartClicked(dashboard: QtCore.QObject):
    """ 
    Begins extracting features from a file or several files.
    """
    # Stop
    if dashboard.ui.pushButton_tsi_fe_operation_start.text() == "Stop":
        
        # Send the Message
        await dashboard.backend.stopTSI_FE()
        
        # Reset Progress Bar
        dashboard.ui.progressBar_tsi_fe_operation.setValue(0)            
        
        # Toggle the Text
        dashboard.ui.pushButton_tsi_fe_operation_start.setText("Start")
                    
    # Start
    elif dashboard.ui.pushButton_tsi_fe_operation_start.text() == "Start": 
    
        # Toggle the Text
        dashboard.ui.pushButton_tsi_fe_operation_start.setText("Stop")  
        
        # Reset Progress Bar
        dashboard.ui.progressBar_tsi_fe_operation.setValue(0)
        
        # Clear Results in Table
        for row in reversed(range(0,dashboard.ui.tableWidget_tsi_fe_results.rowCount())):
            dashboard.ui.tableWidget_tsi_fe_results.removeRow(row)
        for col in reversed(range(0,dashboard.ui.tableWidget_tsi_fe_results.columnCount())):
            dashboard.ui.tableWidget_tsi_fe_results.removeColumn(col)

        # File
        get_input_source = str(dashboard.ui.comboBox_tsi_fe_settings_input_source.currentText())
        if get_input_source == "File":
            get_all_filepaths = []
            get_filename = str(dashboard.ui.label2_tsi_fe_info_file_name.text().replace("File: ",""))
            complete_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText()), get_filename)
            if os.path.isfile(complete_filepath):
                get_filepath = complete_filepath
                get_all_filepaths.append(get_filepath)
            else:
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid input file. Click the Refresh button.")
                return
    
        # Folder
        else:
            get_all_filepaths = []
            if dashboard.ui.listWidget_tsi_fe_input_files.count() > 0:
                for n in range(0,dashboard.ui.listWidget_tsi_fe_input_files.count()):
                    complete_filepath = os.path.join(str(dashboard.ui.comboBox_tsi_fe_input_folders.currentText()), str(dashboard.ui.listWidget_tsi_fe_input_files.item(n).text()))
                    if os.path.isfile(complete_filepath):
                        get_all_filepaths.append(complete_filepath)
                    else:
                        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid input file. Click the Refresh button.")
                        return
            else:
                # fissure.Dashboard.UI_Components.Qt5.errorMessage("No input files found.")
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "No input files found.")
                return
        
        # Checked Features
        get_checkboxes = []
        if dashboard.ui.checkBox_tsi_fe_td_mean.isChecked():
            get_checkboxes.append("Mean")
        if dashboard.ui.checkBox_tsi_fe_td_max.isChecked():
            get_checkboxes.append("Max")
        if dashboard.ui.checkBox_tsi_fe_td_peak.isChecked():
            get_checkboxes.append("Peak")
        if dashboard.ui.checkBox_tsi_fe_td_ptp.isChecked():
            get_checkboxes.append("Peak to Peak")
        if dashboard.ui.checkBox_tsi_fe_td_rms.isChecked():
            get_checkboxes.append("RMS")
        if dashboard.ui.checkBox_tsi_fe_td_variance.isChecked():
            get_checkboxes.append("Variance")
        if dashboard.ui.checkBox_tsi_fe_td_std_dev.isChecked():
            get_checkboxes.append("Standard Deviation")
        if dashboard.ui.checkBox_tsi_fe_td_power.isChecked():
            get_checkboxes.append("Power")
        if dashboard.ui.checkBox_tsi_fe_td_crest.isChecked():
            get_checkboxes.append("Crest Factor")
        if dashboard.ui.checkBox_tsi_fe_td_pulse.isChecked():
            get_checkboxes.append("Pulse Indicator")
        if dashboard.ui.checkBox_tsi_fe_td_margin.isChecked():
            get_checkboxes.append("Margin")
        if dashboard.ui.checkBox_tsi_fe_td_kurtosis.isChecked():
            get_checkboxes.append("Kurtosis")
        if dashboard.ui.checkBox_tsi_fe_td_skewness.isChecked():
            get_checkboxes.append("Skewness")
        if dashboard.ui.checkBox_tsi_fe_td_zero_crossings.isChecked():
            get_checkboxes.append("Zero Crossings")
        if dashboard.ui.checkBox_tsi_fe_td_samples.isChecked():
            get_checkboxes.append("Samples")
        if dashboard.ui.checkBox_tsi_fe_mean_bps.isChecked():
            get_checkboxes.append("Mean of Band Power Spectrum")
        if dashboard.ui.checkBox_tsi_fe_max_bps.isChecked():
            get_checkboxes.append("Max of Band Power Spectrum")
        if dashboard.ui.checkBox_tsi_fe_sum_tbp.isChecked():
            get_checkboxes.append("Sum of Total Band Power")
        if dashboard.ui.checkBox_tsi_fe_peak_bp.isChecked():
            get_checkboxes.append("Peak of Band Power")
        if dashboard.ui.checkBox_tsi_fe_var_bp.isChecked():
            get_checkboxes.append("Variance of Band Power")
        if dashboard.ui.checkBox_tsi_fe_std_dev_bp.isChecked():
            get_checkboxes.append("Standard Deviation of Band Power")
        if dashboard.ui.checkBox_tsi_fe_skewness_bp.isChecked():
            get_checkboxes.append("Skewness of Band Power")
        if dashboard.ui.checkBox_tsi_fe_kurtosis_bp.isChecked():
            get_checkboxes.append("Kurtosis of Band Power")
        if dashboard.ui.checkBox_tsi_fe_rel_spectral_peak_band.isChecked():
            get_checkboxes.append("Relative Spectral Peak per Band")
            
        # Data Type
        get_data_type = str(dashboard.ui.comboBox_tsi_fe_input_data_type.currentText())  
            
        # Assemble
        common_parameter_names = ['checkboxes','data_type','all_filepaths']
        common_parameter_values = [get_checkboxes, get_data_type, get_all_filepaths]

        if len(get_all_filepaths) > 0:
            # Start the Progress Bar
            dashboard.ui.progressBar_tsi_fe_operation.setValue(1)
            
            # Send the Message
            await dashboard.backend.startTSI_FE(common_parameter_names, common_parameter_values)
        else:
            dashboard.logger.warning("No valid input files selected.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingImportFE_Clicked(dashboard: QtCore.QObject):
    """ 
    Imports a CSV of training data for the Classifier.
    """
    # Choose File
    get_default_folder = os.path.expanduser("~/")
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select CSV File...", get_default_folder, filter="CSV (*.csv)")
    if len(fname[0]) > 0:
        dashboard.ui.tableWidget_tsi_classifier_training_training.setRowCount(0)
        dashboard.ui.tableWidget_tsi_classifier_training_training.clear()
        with open(fname[0], "r") as fileInput:
            skip_first_row = 0
            for row in csv.reader(fileInput):                    
                if skip_first_row > 0:
                    dashboard.ui.tableWidget_tsi_classifier_training_training.setRowCount(dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount() + 1)
                    for c in range(0,len(row)):
                        # File Name
                        if c == 0:
                            dashboard.ui.tableWidget_tsi_classifier_training_training.setVerticalHeaderItem(dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()-1,QtWidgets.QTableWidgetItem(str(row[0])))
                        else:
                            get_text = row[c]
                            table_item = QtWidgets.QTableWidgetItem(str(get_text))
                            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
                            dashboard.ui.tableWidget_tsi_classifier_training_training.setItem(dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()-1,c,table_item)
                else:
                    skip_first_row = 1
                    dashboard.ui.tableWidget_tsi_classifier_training_training.setColumnCount(len(row))
                    
                    # Column Name
                    dashboard.ui.tableWidget_tsi_classifier_training_training.setHorizontalHeaderItem(0,QtWidgets.QTableWidgetItem("Truth"))    
                    for c in range(1,len(row)):                           
                        dashboard.ui.tableWidget_tsi_classifier_training_training.setHorizontalHeaderItem(c,QtWidgets.QTableWidgetItem(str(row[c])))
                        
        # Refresh Features
        _slotTSI_ClassifierTrainingModelChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingImportClicked(dashboard: QtCore.QObject):
    """ 
    Imports a CSV of training data for the Classifier.
    """
    # Choose File
    get_default_folder = os.path.expanduser("~/")
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select CSV File...", get_default_folder, filter="CSV (*.csv)")
    if len(fname[0]) > 0:
        dashboard.ui.tableWidget_tsi_classifier_training_training.setRowCount(0)
        dashboard.ui.tableWidget_tsi_classifier_training_training.clear()
        with open(fname[0], "r") as fileInput:
            skip_first_row = 0
            for row in csv.reader(fileInput):                    
                if skip_first_row > 0:
                    dashboard.ui.tableWidget_tsi_classifier_training_training.setRowCount(dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount() + 1)
                    for c in range(0,len(row)):
                        # File Name
                        if c == 0:
                            dashboard.ui.tableWidget_tsi_classifier_training_training.setVerticalHeaderItem(dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()-1,QtWidgets.QTableWidgetItem(str(row[0])))
                        else:
                            get_text = row[c]
                            table_item = QtWidgets.QTableWidgetItem(str(get_text))
                            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
                            dashboard.ui.tableWidget_tsi_classifier_training_training.setItem(dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()-1,c-1,table_item)
                else:
                    skip_first_row = 1
                    dashboard.ui.tableWidget_tsi_classifier_training_training.setColumnCount(len(row)-1)
                    
                    # Column Name
                    for c in range(1,len(row)):                           
                        dashboard.ui.tableWidget_tsi_classifier_training_training.setHorizontalHeaderItem(c-1,QtWidgets.QTableWidgetItem(str(row[c])))
                        
        # Refresh Features
        _slotTSI_ClassifierTrainingModelChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingCopyFE_Clicked(dashboard: QtCore.QObject):
    """ 
    Copies the F.E. Results table to the training data table for the Classifier.
    """
    # Clear Table
    dashboard.ui.tableWidget_tsi_classifier_training_training.setRowCount(0)
    dashboard.ui.tableWidget_tsi_classifier_training_training.clear()
    
    # Resize Table
    dashboard.ui.tableWidget_tsi_classifier_training_training.setRowCount(dashboard.ui.tableWidget_tsi_fe_results.rowCount())
    dashboard.ui.tableWidget_tsi_classifier_training_training.setColumnCount(dashboard.ui.tableWidget_tsi_fe_results.columnCount()+1)
    
    # Copy Vertical Headers
    for r in range(dashboard.ui.tableWidget_tsi_fe_results.rowCount()):
        dashboard.ui.tableWidget_tsi_classifier_training_training.setVerticalHeaderItem(r,QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_fe_results.verticalHeaderItem(r).text())))
    
    # Copy Horizontal Headers
    for c in range(dashboard.ui.tableWidget_tsi_fe_results.columnCount()+1):
        if c == 0:
            dashboard.ui.tableWidget_tsi_classifier_training_training.setHorizontalHeaderItem(c,QtWidgets.QTableWidgetItem("Truth"))
        else:
            dashboard.ui.tableWidget_tsi_classifier_training_training.setHorizontalHeaderItem(c,QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_fe_results.horizontalHeaderItem(c-1).text())))
    
    # Copy Contents
    for r in range(dashboard.ui.tableWidget_tsi_fe_results.rowCount()):
        table_item = QtWidgets.QTableWidgetItem("")
        dashboard.ui.tableWidget_tsi_classifier_training_training.setItem(r,0,table_item)
        for c in range(dashboard.ui.tableWidget_tsi_fe_results.columnCount()):
            table_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_fe_results.item(r, c).text()))
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_classifier_training_training.setItem(r,c+1,table_item)
            
    # Refresh Features
    _slotTSI_ClassifierTrainingModelChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingRemoveRowClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row in the training data table for the Classifier.
    """
    # Remove Row
    if dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount() > 0:
        row = dashboard.ui.tableWidget_tsi_classifier_training_training.currentRow()
        dashboard.ui.tableWidget_tsi_classifier_training_training.removeRow(row)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingRemoveColClicked(dashboard: QtCore.QObject):
    """ 
    Removes a column in the training data table for the Classifier.
    """
    # Remove Column
    row = dashboard.ui.tableWidget_tsi_classifier_training_training.currentRow()
    col = dashboard.ui.tableWidget_tsi_classifier_training_training.currentColumn()
    if (dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount() > 0) and (col > 0):
        dashboard.ui.tableWidget_tsi_classifier_training_training.removeColumn(col) 
        if col == dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount():
            dashboard.ui.tableWidget_tsi_classifier_training_training.setCurrentCell(row,col-1)
        elif col == 0:
            dashboard.ui.tableWidget_tsi_classifier_training_training.setCurrentCell(row,0)
        else:
            dashboard.ui.tableWidget_tsi_classifier_training_training.setCurrentCell(row,col)
            
        # Refresh Features
        _slotTSI_ClassifierTrainingModelChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingTrimClicked(dashboard: QtCore.QObject):
    """ 
    Removes rows based on user input in the training data table for the Classifier.
    """
    # Get the Average
    col = dashboard.ui.tableWidget_tsi_classifier_training_training.currentColumn()
    final_sum = 0
    for row in range(dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()):       
        final_sum = final_sum + float(str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(row, col).text()))
    col_average = round(final_sum/float(dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()),2)
            
    # Open a GUI
    trim_settings_dlg = TrimSettings(parent=dashboard, default_value=str(col_average))
    trim_settings_dlg.show()
    trim_settings_dlg.exec_()  
    
    get_rule_value = trim_settings_dlg.return_value
    if len(get_rule_value) < 2:
        return
    
    # Remove the Rows
    for row in reversed(range(0, dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount())):
        get_value = float(str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(row, col).text()))
        if get_rule_value[0] == 1:
            if get_value < float(get_rule_value[1]):
                dashboard.ui.tableWidget_tsi_classifier_training_training.removeRow(row)
        else:
            if get_value > float(get_rule_value[1]):
                dashboard.ui.tableWidget_tsi_classifier_training_training.removeRow(row)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingExportClicked(dashboard: QtCore.QObject):
    """ 
    Exports the contents of the training data table for the Classifier to a .csv file.
    """
    # Choose File Location
    get_results_folder = os.path.expanduser("~/fe_results_truth.csv")
    path, ok = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save CSV', get_results_folder, 'CSV(*.csv)')
    if ok:
        columns = range(dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount())
        rows = range(dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount())
        header = ["File"] + [dashboard.ui.tableWidget_tsi_classifier_training_training.horizontalHeaderItem(column).text() for column in columns]
        row_header = [dashboard.ui.tableWidget_tsi_classifier_training_training.verticalHeaderItem(row).text() for row in rows]
        with open(path, 'w') as csvfile:
            writer = csv.writer(csvfile, dialect='excel', lineterminator='\n')
            writer.writerow(header)
            for row in rows:
                get_row_items = []
                get_row_items = [row_header[row]] + [str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(row, column).text()) for column in columns]
                writer.writerow(get_row_items)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingPlotColClicked(dashboard: QtCore.QObject):
    """ 
    Plots all column values in the training data table.
    """
    # Get Column Values
    get_values = []
    get_col = dashboard.ui.tableWidget_tsi_classifier_training_training.currentColumn()
    for get_row in range(dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()):             
        get_value = float(str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(get_row, get_col).text()))
        get_values.append(get_value)  
    
    # Plot
    plt.ion()
    plt.close(1) 
    plt.plot(range(1,len(get_values)+1),get_values[:],'b',linewidth=1,zorder=2)
    plt.show()
        
    # Axes Labels
    plt.xlabel('Row') 
    plt.ylabel('Value') 


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationImportClicked(dashboard: QtCore.QObject):
    """ 
    Imports a CSV of unknown data for the Classifier.
    """
    # Choose File
    get_default_folder = os.path.join(fissure.utils.FISSURE_ROOT)
    fname = QtWidgets.QFileDialog.getOpenFileName(None,"Select CSV File...", get_default_folder, filter="CSV (*.csv)")
    if fname != "":
        dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setRowCount(0)
        dashboard.ui.tableWidget_tsi_classifier_classification_unknown.clear()
        with open(fname[0], "r") as fileInput:
            skip_first_row = 0
            for row in csv.reader(fileInput):                    
                if skip_first_row > 0:
                    dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setRowCount(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount() + 1)
                    for c in range(0,len(row)):
                        # File Name
                        if c == 0:
                            dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setVerticalHeaderItem(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount()-1,QtWidgets.QTableWidgetItem(str(row[0])))
                        else:
                            get_text = row[c]
                            table_item = QtWidgets.QTableWidgetItem(str(get_text))
                            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
                            dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setItem(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount()-1,c-1,table_item)
                else:
                    skip_first_row = 1
                    dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setColumnCount(len(row)-1)
                    
                    # Column Name
                    for c in range(1,len(row)):                           
                        dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setHorizontalHeaderItem(c-1,QtWidgets.QTableWidgetItem(str(row[c])))
                        
        # Refresh Features
        _slotTSI_ClassifierClassificationModelChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationCopyFE_Clicked(dashboard: QtCore.QObject):
    """ 
    Copies the F.E. Results table to the Unknown Data table for the Classifier.
    """
    # Clear Table
    dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setRowCount(0)
    dashboard.ui.tableWidget_tsi_classifier_classification_unknown.clear()
    
    # Resize Table
    dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setRowCount(dashboard.ui.tableWidget_tsi_fe_results.rowCount())
    dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setColumnCount(dashboard.ui.tableWidget_tsi_fe_results.columnCount())
    
    # Copy Vertical Headers
    for r in range(dashboard.ui.tableWidget_tsi_fe_results.rowCount()):
        dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setVerticalHeaderItem(r,QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_fe_results.verticalHeaderItem(r).text())))
    
    # Copy Horizontal Headers
    for c in range(dashboard.ui.tableWidget_tsi_fe_results.columnCount()):
        dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setHorizontalHeaderItem(c,QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_fe_results.horizontalHeaderItem(c).text())))
    
    # Copy Contents
    for r in range(dashboard.ui.tableWidget_tsi_fe_results.rowCount()):
        for c in range(dashboard.ui.tableWidget_tsi_fe_results.columnCount()):
            table_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_fe_results.item(r, c).text()))
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setItem(r,c,table_item)
            
    # Refresh Features
    _slotTSI_ClassifierClassificationModelChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationRemoveRowClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row in the Unknown Data table for the Classifier.
    """
    # Remove Row
    row = dashboard.ui.tableWidget_tsi_classifier_classification_unknown.currentRow()
    dashboard.ui.tableWidget_tsi_classifier_classification_unknown.removeRow(row) 


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationRemoveColClicked(dashboard: QtCore.QObject):
    """ 
    Removes a column in the Unknown Data table for the Classifier.
    """
    # Remove Column
    row = dashboard.ui.tableWidget_tsi_classifier_classification_unknown.currentRow()
    col = dashboard.ui.tableWidget_tsi_classifier_classification_unknown.currentColumn()
    dashboard.ui.tableWidget_tsi_classifier_classification_unknown.removeColumn(col)
    
    if dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount() > 0:
        if col == dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount():
            dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setCurrentCell(row,col-1)
        elif col == 0:
            dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setCurrentCell(row,0)
        else:
            dashboard.ui.tableWidget_tsi_classifier_classification_unknown.setCurrentCell(row,col)
            
        # Refresh Features
        _slotTSI_ClassifierClassificationModelChanged(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationTrimClicked(dashboard: QtCore.QObject):
    """ 
    Removes rows based on user input in the Unknown Data table for the Classifier.
    """
    # Get the Average
    col = dashboard.ui.tableWidget_tsi_classifier_classification_unknown.currentColumn()
    final_sum = 0
    for row in range(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount()):       
        final_sum = final_sum + float(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.item(row, col).text()))
    col_average = round(final_sum/float(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount()),2)
            
    # Open a GUI
    trim_settings_dlg = TrimSettings(parent=dashboard, default_value=str(col_average))
    trim_settings_dlg.show()
    trim_settings_dlg.exec_()  
    
    get_rule_value = trim_settings_dlg.return_value
    if len(get_rule_value) < 2:
        return
    
    # Remove the Rows
    for row in reversed(range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount())):
        get_value = float(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.item(row, col).text()))
        if get_rule_value[0] == 1:
            if get_value < float(get_rule_value[1]):
                dashboard.ui.tableWidget_tsi_classifier_classification_unknown.removeRow(row)
        else:
            if get_value > float(get_rule_value[1]):
                dashboard.ui.tableWidget_tsi_classifier_classification_unknown.removeRow(row)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationPlotColClicked(dashboard: QtCore.QObject):
    """ 
    Plots all column values in the Unknown Data table.
    """
    # Get Column Values
    get_values = []
    get_col = dashboard.ui.tableWidget_tsi_classifier_classification_unknown.currentColumn()
    for get_row in range(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount()):             
        get_value = float(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.item(get_row, get_col).text()))
        get_values.append(get_value)  
    
    # Plot
    plt.ion()
    plt.close(1) 
    plt.plot(range(1,len(get_values)+1),get_values[:],'b',linewidth=1,zorder=2)
    plt.show()
        
    # Axes Labels
    plt.xlabel('Row') 
    plt.ylabel('Value')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationExportClicked(dashboard: QtCore.QObject):
    """ 
    Exports the contents of the Unknown Data table for the Classifier to a .csv file.
    """
    # Choose File Location
    get_default_folder = os.path.join(fissure.utils.FISSURE_ROOT, "classifier_input_no_truth.csv")
    path, ok = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save CSV', get_default_folder, 'CSV(*.csv)')
    if ok:
        columns = range(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount())
        rows = range(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount())
        header = ["File"] + [dashboard.ui.tableWidget_tsi_classifier_classification_unknown.horizontalHeaderItem(column).text() for column in columns]
        row_header = [dashboard.ui.tableWidget_tsi_classifier_classification_unknown.verticalHeaderItem(row).text() for row in rows]
        with open(path, 'w') as csvfile:
            writer = csv.writer(csvfile, dialect='excel', lineterminator='\n')
            writer.writerow(header)
            for row in rows:
                get_row_items = []
                get_row_items = [row_header[row]] + [str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.item(row, column).text()) for column in columns]
                writer.writerow(get_row_items)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingViewClicked(dashboard: QtCore.QObject):
    """ 
    Opens up an image that details the selected model.
    """
    # Load Images Path From File
    get_model = str(dashboard.ui.comboBox_tsi_classifier_training_model.currentText())
    if len(get_model) > 0:
        if str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Decision Tree":
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
        elif str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Deep Neural Network":
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
        else:
            return
        os.system('eog "' + os.path.join(model_directory, get_model + '.png') + '" &')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingRetrainClicked(dashboard: QtCore.QObject):
        """ 
        Processes the training data to generate a new model.
        """
        # Check Table for Data
        if dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount() == 0:
            return
            
        # Retrain
        get_features = []
        accuracy = ""
        settings = ""
        details = ""
        if dashboard.ui.comboBox_tsi_classifier_training_technique.currentText() == "Decision Tree":
            # Features
            for n in range(0, dashboard.ui.listWidget_tsi_classifier_training_features.count()):
                if dashboard.ui.listWidget_tsi_classifier_training_features.item(n).checkState() == 2:
                    get_features.append(str(dashboard.ui.listWidget_tsi_classifier_training_features.item(n).text()))
            
            # Retrain Frame
            get_percentage = int(dashboard.ui.spinBox_tsi_classifier_training_percentage.value())
            get_max_depth = int(dashboard.ui.spinBox_tsi_classifier_training_retrain1_max_depth.value())
            get_criterion = str(dashboard.ui.comboBox_tsi_classifier_training_retrain1_criterion.currentText())
            get_splitter = str(dashboard.ui.comboBox_tsi_classifier_training_retrain1_splitter.currentText())
            
            # Create Dataframe
            get_column_labels = []            
            for m in range(0, dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount()):
                get_column_labels.append(str(dashboard.ui.tableWidget_tsi_classifier_training_training.horizontalHeaderItem(m).text()))
            df=pd.DataFrame(columns=get_column_labels)
            for row in range(0, dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()):
                get_row = []
                for col in range(0, dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount()):
                    get_row.append(str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(row,col).text()))
                df.loc[len(df)] = get_row
            
            # Sort Columns Alphabetically
            df = df.reindex(sorted(df.columns, key=str.lower), axis=1)
                
            # Extract Relevant Columns
            X = df[get_features]
            y = df.Truth
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=1-float(get_percentage)/100, random_state=1)
            clf_orig = DecisionTreeClassifier(criterion=get_criterion,max_depth=get_max_depth)
            clf_orig = clf_orig.fit(X_train,y_train)
                                   
            # Feature Importance
            feature_importances = pd.DataFrame(clf_orig.feature_importances_, X_train.columns)#.sort_values(0, ascending=False)
            df1 = feature_importances[(feature_importances != 0).all(1)].round(2)
            used_features = df1.index.tolist()
            used_features_importance = df1.iloc[:,0].tolist()
            
            # Remove Unused Features
            importances = clf_orig.feature_importances_
            indices = [i for i in range(len(importances)) if importances[i] > 0.0]
            X_train_new = X_train.iloc[:, indices]
            X_test_new = X_test.iloc[:, indices]

            # Train the New Decision Tree Classifier
            clf = DecisionTreeClassifier(criterion=get_criterion,max_depth=get_max_depth)
            clf.fit(X_train_new, y_train)
            y_pred = clf.predict(X_test_new)
            
            # Calculate Accuracy
            accuracy = str(round(metrics.accuracy_score(y_test, y_pred),2))
            precision = str(round(metrics.precision_score(y_test, y_pred, average='weighted'),2))
            recall = str(round(metrics.recall_score(y_test, y_pred, average='weighted'),2))
            f1_score = str(round(metrics.f1_score(y_test, y_pred, average='weighted'),2))
            
            # Classification
            dashboard.ui.tableWidget_tsi_classifier_training_results.setRowCount(0)
            for n in range(0,len(X_test_new.index[:])):
                row = dashboard.ui.tableWidget_tsi_classifier_training_results.rowCount()
                dashboard.ui.tableWidget_tsi_classifier_training_results.setRowCount(row + 1)
                truth_text = str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(X_test_new.index[n],0).text())
                truth_item = QtWidgets.QTableWidgetItem(truth_text)
                truth_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_tsi_classifier_training_results.setItem(row,0,truth_item)
                classification_text = str(y_pred[n])
                classification_item = QtWidgets.QTableWidgetItem(classification_text)
                classification_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_tsi_classifier_training_results.setItem(row,1,classification_item)
                
                header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_classifier_training_training.verticalHeaderItem(X_test_new.index[n]).text()))
                header_item.setFont(QtGui.QFont("Ubuntu",10))
                if truth_text == classification_text:
                    pass
                else:
                    header_item.setForeground(QtGui.QColor(255,0,0))
                dashboard.ui.tableWidget_tsi_classifier_training_results.setVerticalHeaderItem(row,header_item)
            
            dashboard.ui.tableWidget_tsi_classifier_training_results.resizeRowsToContents()
            dashboard.ui.tableWidget_tsi_classifier_training_results.resizeColumnsToContents()
            dashboard.ui.tableWidget_tsi_classifier_training_results.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_tsi_classifier_training_results.horizontalHeader().setStretchLastSection(True)
            
            # Save Confusion Matrix
            confusion_matrix = metrics.confusion_matrix(y_test, y_pred, labels=df.Truth.unique())
            print(confusion_matrix)
            
            # Generate Tree Image
            image_path = ""
            if dashboard.ui.checkBox_tsi_classifier_training_generate_image.isChecked():
                dot_data = StringIO()
                export_graphviz(clf, out_file=dot_data,  
                                filled=True, rounded=True,
                                special_characters=True,feature_names = used_features,class_names=df.Truth.unique())
                image_path = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "tmp.png")
                graph = pydotplus.graph_from_dot_data(dot_data.getvalue())
                graph.write_png(image_path)
                Image(graph.create_png())
                
            # Details
            details = details + "Technique: " + str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) + "\n"
            details = details + "Accuracy: " + str(accuracy) + "\n"
            details = details + "Precision: " + str(precision) + "\n"
            details = details + "Recall: " + str(recall) + "\n"
            details = details + "F1 Score: " + str(f1_score) + "\n"
            details = details + "Max. Depth: " + str(get_max_depth) + "\n"
            details = details + "Criterion: " + str(get_criterion) + "\n"
            details = details + "Splitter: " + str(get_splitter) + "\n"
            details = details + "Node Count: " + str(clf.tree_.node_count) + "\n"
            details = details + "Training Count: " + str(len(X_train_new)) + "\n"
            details = details + "Testing Count: " + str(len(X_test_new)) + "\n"
            details = details + "Truth Categories: " + str(df.Truth.unique()) + "\n"
            details = details + "Possible Features: " + str(get_features) + "\n"
            details = details + "Features: " + str(used_features) + "\n"
            details = details + "Feature Importance: " + str(used_features_importance) + "\n"
            details = details + "Confusion Matrix: " + str(confusion_matrix) + "\n"
            dashboard.ui.textEdit_tsi_classifier_training_results_details.setPlainText(details)
            
            # Save Temporary Copy
            s = pickle.dumps(clf)
            file = open(os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "tmp.h5"),"wb")                
            file.write(s)
            file.close()
                        
        elif dashboard.ui.comboBox_tsi_classifier_training_technique.currentText() == "Deep Neural Network":
            # DNN Target
            get_target = str(dashboard.ui.comboBox_tsi_classifier_training_retrain2_target.currentText())
            if len(get_target) == 0:
                print("Select Target")
                return
                
            # Features
            for n in range(0,dashboard.ui.listWidget_tsi_classifier_training_features.count()):
                if dashboard.ui.listWidget_tsi_classifier_training_features.item(n).checkState() == 2:
                    get_features.append(str(dashboard.ui.listWidget_tsi_classifier_training_features.item(n).text()))
                    
            # Create Dataframe
            get_column_labels = []            
            for m in range(0,dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount()):
                get_column_labels.append(str(dashboard.ui.tableWidget_tsi_classifier_training_training.horizontalHeaderItem(m).text()))
            df=pd.DataFrame(columns=get_column_labels)
            for row in range(0,dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()):
                get_row = []
                for col in range(0,dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount()):
                    get_row.append(str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(row,col).text()))
                df.loc[len(df)] = get_row
                    
            # Sort Columns Alphabetically
            df = df.reindex(sorted(df.columns, key=str.lower), axis=1)
                
            # Extract Relevant Columns
            X = df[get_features]
            y = pd.get_dummies(df.Truth)[get_target]
            X = X.to_numpy().astype(np.float64)
            X =(X-X.min())/(X.max()-X.min())
            y = y.to_numpy()

            # Define the Keras Model
            model = Sequential()
            model.add(Dense(12, input_shape=(len(get_features),), activation='relu'))
            model.add(Dense(8, activation='relu'))
            model.add(Dense(1, activation='sigmoid'))
            model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
            model.fit(X, y, epochs=150, batch_size=10)
                        
            # Classification
            # ~ y_pred = model.predict(X)
            # ~ score = model.evaluate(X, y,verbose=1)            
            if dashboard.ui.checkBox_tsi_classifier_training_retrain2_manual.isChecked() == True:
                get_threshold = float(dashboard.ui.doubleSpinBox_tsi_classifier_training_retrain2_threshold.value())
                predictions = (model.predict(X) > get_threshold).astype(int)
                for i in range(len(X)):
                    print('=> %d (expected %d)' % (predictions[i], y[i]))
            else:
                print("start")
                thresholds = np.arange(0, 1, 0.005)
                scores = []
                for t in thresholds:
                    print(t)
                    to_labels = (model.predict(X) > t).astype(int)
                    scores.append(metrics.f1_score(y, to_labels[:, 0]))
                ix = np.argmax(scores)
                print('Threshold=%.3f, F-Score=%.5f' % (thresholds[ix], scores[ix]))
                get_threshold = thresholds[ix]
                predictions = (model.predict(X) > get_threshold).astype(int)
                for i in range(len(X)):
                    print('=> %d (expected %d)' % (predictions[i], y[i]))
                    # ~ print('%s => %d %d (expected %d)' % (X[i].tolist(), predictions1[i], predictions2[i], y[i]))

            #print(model.summary())
            #plot_model(model, to_file='model_plot.png', show_shapes=True, show_layer_names=True)  # plot_model does not work
            
            # Fill the Results Table
            dashboard.ui.tableWidget_tsi_classifier_training_results.setRowCount(0)
            correct = 0
            for n in range(0, len(X)):
                row = dashboard.ui.tableWidget_tsi_classifier_training_results.rowCount()
                dashboard.ui.tableWidget_tsi_classifier_training_results.setRowCount(row + 1)
                truth_text = str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(n,0).text())
                truth_item = QtWidgets.QTableWidgetItem(truth_text)
                truth_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_tsi_classifier_training_results.setItem(row,0,truth_item)
                if predictions[n] == 0:
                    classification_text = "Not " + get_target
                else:
                    classification_text = get_target
                classification_item = QtWidgets.QTableWidgetItem(classification_text)
                classification_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_tsi_classifier_training_results.setItem(row,1,classification_item)
                
                header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_classifier_training_training.verticalHeaderItem(n).text()))
                header_item.setFont(QtGui.QFont("Ubuntu",10))
                if (truth_text == classification_text) or ((truth_text != get_target) and (predictions[n] == 0)):
                    correct = correct + 1
                else:
                    header_item.setForeground(QtGui.QColor(255,0,0))
                dashboard.ui.tableWidget_tsi_classifier_training_results.setVerticalHeaderItem(row,header_item)
            
            dashboard.ui.tableWidget_tsi_classifier_training_results.resizeRowsToContents()
            dashboard.ui.tableWidget_tsi_classifier_training_results.resizeColumnsToContents()
            dashboard.ui.tableWidget_tsi_classifier_training_results.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_tsi_classifier_training_results.horizontalHeader().setStretchLastSection(True)
            
            # Calculate Accuracy
            # _, accuracy = model.evaluate(X, y)  # model accuracy
            # accuracy = '%.2f' % (accuracy)           
            accuracy = '%.2f' % (float(correct)/float(len(X))) # classification results accuracy
            
            # Get Labels and Matrix from Results Table
            get_truth = []
            get_classification = []            
            for row in range(0, dashboard.ui.tableWidget_tsi_classifier_training_results.rowCount()):
                get_truth.append(str(dashboard.ui.tableWidget_tsi_classifier_training_results.item(row,0).text()))
                get_classification.append(str(dashboard.ui.tableWidget_tsi_classifier_training_results.item(row,1).text()))

            labels = sorted(pd.Series(get_truth + get_classification).drop_duplicates().tolist(), key=str.lower)
            confusion_matrix = metrics.confusion_matrix(get_truth, get_classification, labels=labels)

            # Save the Summary to an Image
            stringlist = []
            model.summary(print_fn=lambda x: stringlist.append(x))
            short_model_summary = "\n".join(stringlist)
            image = PIL_Image.new('RGB', (800, len(short_model_summary.split('\n'))*23), color = (0, 0, 0))
            fontsize = 20
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", fontsize)
            text_color = (255, 255, 255)
            text_start_height = 0
            drawMultipleLineText(image, short_model_summary, font, text_color, text_start_height)
            image.save(os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "tmp.png"))
            
            # Details
            details = details + "Technique: " + str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) + "\n"
            details = details + "Target: " + get_target + "\n"
            details = details + "Layer1: 12, relu\nLayer2: 8, relu\nLayer3: 1, sigmoid" + "\n"
            details = details + "Threshold: " + str(get_threshold) + "\n"
            details = details + "Truth Categories: " + str(df.Truth.unique()) + "\n"
            details = details + "Possible Features: " + str(get_features) + "\n"
            details = details + "Features: " + str(get_features) + "\n"
            details = details + "Confusion Matrix: " + str(confusion_matrix) + "\n"
            dashboard.ui.textEdit_tsi_classifier_training_results_details.setPlainText(details)
            
            # Save Temporary Copy
            s = model.save(os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "tmp.h5"))
        else:
            return
            
        # Add to Table
        new_row = dashboard.ui.tableWidget_tsi_classifier_training_accuracy.rowCount()
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.setRowCount(new_row+1)
        header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.comboBox_tsi_classifier_training_model.currentText()))
        header_item.setFont(QtGui.QFont("Ubuntu",10))
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.setVerticalHeaderItem(new_row,header_item)
        table_item = QtWidgets.QTableWidgetItem(accuracy)
        table_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.setItem(new_row,0,table_item)
        table_item = QtWidgets.QTableWidgetItem(str(get_features))
        table_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.setItem(new_row,1,table_item)
        table_item = QtWidgets.QTableWidgetItem(details.replace('\n','; '))
        table_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.setItem(new_row,2,table_item)
        
        # Resize Table
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.resizeRowsToContents()
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.resizeColumnsToContents()
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.horizontalHeader().setStretchLastSection(True)
        
        # Enable Buttons
        dashboard.ui.pushButton_tsi_classifier_training_results_save_as.setEnabled(True)
        dashboard.ui.pushButton_tsi_classifier_training_model_images_view.setEnabled(True)
        dashboard.ui.pushButton_tsi_classifier_training_results_netron.setEnabled(True)
        dashboard.ui.pushButton_tsi_classifier_training_results_confusion.setEnabled(True)
        dashboard.ui.pushButton_tsi_classifier_training_results_new_model_confusion.setEnabled(True)


def drawMultipleLineText(image, text, font, text_color, text_start_height):
    """ 
    Draw multiline text for DNN model summary. Not a slot.
    """
    draw = ImageDraw.Draw(image)
    image_width, image_height = image.size
    y_text = text_start_height
    #lines = textwrap.wrap(text)  # Doesn't split right
    for line in text.split('\n'):
        line_width, line_height = font.getsize(line)
        #draw.text(((image_width - line_width) / 2, y_text),  # center
        draw.text(((0), y_text),  # left
                    line, font=font, fill=text_color)
        y_text += line_height


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingAccuracyClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the accuracy list.
    """
    # Clear
    for row in reversed(range(0,dashboard.ui.tableWidget_tsi_classifier_training_accuracy.rowCount())):
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.removeRow(row)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingAccuracyExportClicked(dashboard: QtCore.QObject):
    """ 
    Exports the contents of the accuracy table to a .csv file.
    """
    # Choose File Location
    path, ok = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save CSV', 'results.csv', 'CSV(*.csv)')
    if ok:
        columns = range(dashboard.ui.tableWidget_tsi_classifier_training_accuracy.columnCount())
        rows = range(dashboard.ui.tableWidget_tsi_classifier_training_accuracy.rowCount())
        header = ["File"] + [dashboard.ui.tableWidget_tsi_classifier_training_accuracy.horizontalHeaderItem(column).text() for column in columns]
        row_header = [dashboard.ui.tableWidget_tsi_classifier_training_accuracy.verticalHeaderItem(row).text() for row in rows]
        with open(path, 'w') as csvfile:
            writer = csv.writer(csvfile, dialect='excel', lineterminator='\n')
            writer.writerow(header)
            for row in rows:
                get_row_items = []
                get_row_items = [row_header[row]] + [str(dashboard.ui.tableWidget_tsi_classifier_training_accuracy.item(row, column).text()) for column in columns]
                writer.writerow(get_row_items)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingModelImagesViewClicked(dashboard: QtCore.QObject):
    """ 
    Opens the selected model image in the Classifier Training tab.
    """
    # Open
    get_tmp_file = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "tmp.png")
    os.system('eog "' + get_tmp_file + '" &')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingAccuracyRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row from the accuracy table in the Classifier Training tab.
    """
    # Remove Row
    if dashboard.ui.tableWidget_tsi_classifier_training_accuracy.rowCount() > 0:
        row = dashboard.ui.tableWidget_tsi_classifier_training_accuracy.currentRow()
        dashboard.ui.tableWidget_tsi_classifier_training_accuracy.removeRow(row)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingResultsSaveAsClicked(dashboard: QtCore.QObject):
    """ 
    Saves the generated model and its details to disk.
    """
    # Open the Save Dialog
    if str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Decision Tree":
        model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
        model_filename = "tmp.h5"
        model_extension = ".h5"
    elif str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Deep Neural Network":
        model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
        model_filename = "tmp.h5"
        model_extension = ".h5"
    else:
        return
        
    tmp_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models")
    dialog = QtWidgets.QFileDialog()
    dialog.setDirectory(model_directory)
    dialog.setFilter(dialog.filter() | QtCore.QDir.Hidden)
    dialog.setDefaultSuffix('txt')
    dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
    dialog.setNameFilters(['Model Details (*.txt)'])
    if dialog.exec_() == QtWidgets.QDialog.Accepted:
        fileName = str(dialog.selectedFiles()[0])
    else:
        fileName = ""   
        
    # Valid File
    if fileName:        
        # Save the Details
        file = open(fileName,"w")                
        get_details = dashboard.ui.textEdit_tsi_classifier_training_results_details.toPlainText()
        file.write(get_details)
        file.close()
        
        # Copy Temporary Model
        os.system('cp "' + os.path.join(tmp_directory, model_filename) + '" "' + fileName.replace('.txt','') + model_extension + '"')
        try:
            os.system('cp "' + os.path.join(tmp_directory, "tmp.png") + '" "' + fileName.replace('.txt','') + '.png' + '"')
        except:
            pass
            
        # Add to Model ComboBox
        if dashboard.ui.comboBox_tsi_classifier_training_model.findText(os.path.splitext(fileName.split('/')[-1])[0], QtCore.Qt.MatchFixedString) < 0:
            dashboard.ui.comboBox_tsi_classifier_training_model.addItem(os.path.splitext(fileName.split('/')[-1])[0])
            #dashboard.ui.comboBox_tsi_classifier_training_model.addItem(fileName.split('/')[-1].strip('.txt'))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingTestClicked(dashboard: QtCore.QObject):
    """ 
    Applies the current model to all the data.
    """
    # Load the Model
    if str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Decision Tree":
        get_file = str(dashboard.ui.comboBox_tsi_classifier_training_model.currentText()) + ".h5"
        model_filepath = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree", get_file)
        clf = pickle.load(open(model_filepath, "rb"))
        
        # Features
        get_features = []
        get_details = str(dashboard.ui.textEdit_tsi_classifier_training_details.toPlainText())
        for line in get_details.split('\n'):
            if "Features: " in line:
                get_features = ast.literal_eval(line.split('Features: ')[1])
                
        # Create Dataframe
        get_column_labels = []            
        for m in range(0,dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount()):
            get_column_labels.append(str(dashboard.ui.tableWidget_tsi_classifier_training_training.horizontalHeaderItem(m).text()))
        df = pd.DataFrame(columns=get_column_labels)
        for row in range(0, dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()):
            get_row = []
            for col in range(0, dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount()):
                get_row.append(str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(row,col).text()))
            df.loc[len(df)] = get_row
    
        # Extract Relevant Columns
        X_test = df[get_features]
        y_test = df.Truth
        #X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=1-float(get_percentage)/100, random_state=1)
        #clf = DecisionTreeClassifier(criterion=get_criterion,max_depth=get_max_depth)
        #clf = clf.fit(X_train,y_train)
        y_pred = clf.predict(X_test)

        # Calculate Accuracy
        accuracy = str(metrics.accuracy_score(y_test, y_pred))
        
        # Classification
        dashboard.ui.tableWidget_tsi_classifier_training_results.setRowCount(0)
        for n in range(0,len(X_test.index[:])):
            row = dashboard.ui.tableWidget_tsi_classifier_training_results.rowCount()
            dashboard.ui.tableWidget_tsi_classifier_training_results.setRowCount(row + 1)
            truth_text = str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(X_test.index[n],0).text())
            truth_item = QtWidgets.QTableWidgetItem(truth_text)
            truth_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_classifier_training_results.setItem(row,0,truth_item)
            classification_text = str(y_pred[n])
            classification_item = QtWidgets.QTableWidgetItem(classification_text)
            classification_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_classifier_training_results.setItem(row,1,classification_item)
            
            header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_classifier_training_training.verticalHeaderItem(n).text()))
            header_item.setFont(QtGui.QFont("Ubuntu",10))
            if truth_text == classification_text:
                pass
            else:
                header_item.setForeground(QtGui.QColor(255,0,0))
            dashboard.ui.tableWidget_tsi_classifier_training_results.setVerticalHeaderItem(row,header_item)
        
    elif str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Deep Neural Network":
        get_file = str(dashboard.ui.comboBox_tsi_classifier_training_model.currentText()) + ".h5"
        model_filepath = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN", get_file)
        
        # DNN Target
        get_details = dashboard.ui.textEdit_tsi_classifier_training_details.toPlainText()
        get_target = get_details.split('Target: ')[1].split("\nLayer1: ")[0]
            
        # Features
        get_features = []
        get_details = str(dashboard.ui.textEdit_tsi_classifier_training_details.toPlainText())
        for line in get_details.split('\n'):
            if "Features: " in line:
                get_features = ast.literal_eval(line.split('Features: ')[1])
            
        # Create Dataframe
        get_column_labels = []            
        for m in range(0,dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount()):
            get_column_labels.append(str(dashboard.ui.tableWidget_tsi_classifier_training_training.horizontalHeaderItem(m).text()))
        df=pd.DataFrame(columns=get_column_labels)
        for row in range(0,dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()):
            get_row = []
            for col in range(0,dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount()):
                get_row.append(str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(row,col).text()))
            df.loc[len(df)] = get_row
                
        # Sort Columns Alphabetically
        df = df.reindex(sorted(df.columns, key=str.lower), axis=1)
            
        # Extract Relevant Columns
        X = df[get_features]
        y = pd.get_dummies(df.Truth)[get_target]
        X = X.to_numpy().astype(np.float64)
        X =(X-X.min())/(X.max()-X.min())
        y = y.to_numpy()

        # Load the Keras Model
        model = load_model(model_filepath)
                    
        # Classification
        for line in get_details.split('\n'):
            if "Threshold: " in line:
                get_threshold = float(line.split('Threshold: ')[1].replace('\n',''))
        predictions = (model.predict(X) > get_threshold).astype(int)
        for i in range(len(X)):
            print('=> %d (expected %d)' % (predictions[i], y[i]))
        
        # Fill the Results Table
        dashboard.ui.tableWidget_tsi_classifier_training_results.setRowCount(0)
        correct = 0
        for n in range(0,len(X)):
            row = dashboard.ui.tableWidget_tsi_classifier_training_results.rowCount()
            dashboard.ui.tableWidget_tsi_classifier_training_results.setRowCount(row + 1)
            truth_text = str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(n,0).text())
            truth_item = QtWidgets.QTableWidgetItem(truth_text)
            truth_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_classifier_training_results.setItem(row,0,truth_item)
            if predictions[n] == 0:
                classification_text = "Not " + get_target
            else:
                classification_text = get_target
            classification_item = QtWidgets.QTableWidgetItem(classification_text)
            classification_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_classifier_training_results.setItem(row,1,classification_item)
            
            header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_classifier_training_training.verticalHeaderItem(n).text()))
            header_item.setFont(QtGui.QFont("Ubuntu",10))
            if (truth_text == classification_text) or ((truth_text != get_target) and (predictions[n] == 0)):
                correct = correct + 1
            else:
                header_item.setForeground(QtGui.QColor(255,0,0))
            dashboard.ui.tableWidget_tsi_classifier_training_results.setVerticalHeaderItem(row,header_item)
                    
        # # Calculate Accuracy
        # # _, accuracy = model.evaluate(X, y)  # model accuracy
        # # accuracy = '%.2f' % (accuracy)           
        # accuracy = '%.2f' % (float(correct)/float(len(X))) # classification results accuracy
        
        # # Get Labels and Matrix from Results Table
        # get_truth = []
        # get_classification = []            
        # for row in range(0,dashboard.ui.tableWidget_tsi_classifier_training_results.rowCount()):
            # get_truth.append(str(dashboard.ui.tableWidget_tsi_classifier_training_results.item(row,0).text()))
            # get_classification.append(str(dashboard.ui.tableWidget_tsi_classifier_training_results.item(row,1).text()))

        # labels = sorted(pd.Series(get_truth + get_classification).drop_duplicates().tolist(), key=str.lower)
        # confusion_matrix = metrics.confusion_matrix(get_truth, get_classification, labels=labels)

        # # Save the Summary to an Image
        # stringlist = []
        # model.summary(print_fn=lambda x: stringlist.append(x))
        # short_model_summary = "\n".join(stringlist)
        # image = PIL_Image.new('RGB', (800, len(short_model_summary.split('\n'))*23), color = (0, 0, 0))
        # fontsize = 20
        # font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", fontsize)
        # text_color = (255, 255, 255)
        # text_start_height = 0
        # drawMultipleLineText(image, short_model_summary, font, text_color, text_start_height)
        # image.save(os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "tmp.png"))
        
        # # Details
        # details = details + "Target: " + get_target + "\n"
        # details = details + "Layer1: 12, relu\nLayer2: 8, relu\nLayer3: 1, sigmoid" + "\n"
        # details = details + "Threshold: " + str(get_threshold) + "\n"
        # details = details + "Truth Categories: " + str(df.Truth.unique()) + "\n"
        # details = details + "Features: " + str(get_features) + "\n"
        # details = details + "Confusion Matrix: " + str(confusion_matrix) + "\n"
        # dashboard.ui.textEdit_tsi_classifier_training_results_details.setPlainText(details)
        
        # # Save Temporary Copy
        # s = model.save(os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "tmp.h5"))
        
    else:
        return
    
    dashboard.ui.label2_tsi_classifier_training_results_test_data.setText("Test Data for " +  str(dashboard.ui.comboBox_tsi_classifier_training_model.currentText()))

    dashboard.ui.tableWidget_tsi_classifier_training_results.resizeRowsToContents()
    dashboard.ui.tableWidget_tsi_classifier_training_results.resizeColumnsToContents()
    dashboard.ui.tableWidget_tsi_classifier_training_results.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_tsi_classifier_training_results.horizontalHeader().setStretchLastSection(True)
    
    dashboard.ui.pushButton_tsi_classifier_training_results_confusion.setEnabled(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingModelDeleteClicked(dashboard: QtCore.QObject):
    """ 
    Deletes the model, details, and tree files.
    """
    # Yes/No Dialog
    get_model = str(dashboard.ui.comboBox_tsi_classifier_training_model.currentText())
    if len(get_model) > 0:
        qm = QtWidgets.QMessageBox
        ret = qm.question(dashboard,'', "Delete model " + str(get_model) + " and all model files?", qm.Yes | qm.No)
        if ret == qm.Yes:

            # Delete Tree
            if str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Decision Tree":
                model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
            elif str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Deep Neural Network":
                model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
            else:
                return
        
            # Delete Model, Details, and Image
            os.system('rm "' + os.path.join(model_directory, get_model + ".txt") + '"')
            os.system('rm "' + os.path.join(model_directory, get_model + ".h5") + '"')
            try:
                os.system('rm "' + os.path.join(model_directory, get_model + ".png") + '"')
            except:
                pass
            
            # Refresh the ComboBox
            _slotTSI_ClassifierTrainingTechniqueChanged(dashboard)
            _slotTSI_ClassifierClassificationTechniqueChanged(dashboard)
        else:
            return
        

@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingResultsConfusionClicked(dashboard: QtCore.QObject):
    """ 
    Plots a confusion matrix from the results table.
    """
    # Get Labels and Matrix from Results Table
    get_truth = []
    get_classification = []
    
    for row in range(0, dashboard.ui.tableWidget_tsi_classifier_training_results.rowCount()):
        get_truth.append(str(dashboard.ui.tableWidget_tsi_classifier_training_results.item(row,0).text()))
        get_classification.append(str(dashboard.ui.tableWidget_tsi_classifier_training_results.item(row,1).text()))

    labels = sorted(pd.Series(get_truth + get_classification).drop_duplicates().tolist(), key=str.lower)
    confusion_matrix = metrics.confusion_matrix(get_truth, get_classification, labels=labels) 
    
    # Plot        
    with matplotlib.rc_context({'toolbar':'None'}):  # Global: matplotlib.rcParams['toolbar'] = 'None'  
        plt.ion()
        fig, ax = plt.subplots()
        im = ax.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.viridis)  #, cmap=plt.cm.Blues)
        ax.figure.colorbar(im, ax=ax)
        title = 'Confusion Matrix'
        ax.set(xticks=np.arange(len(labels)),
                yticks=np.arange(len(labels)),
                xticklabels=labels, yticklabels=labels,
                title=title,
                ylabel='Truth',
                xlabel='Predicted')        
        ax.set_xticks(np.arange(-.5, len(labels), 1), minor=True)
        ax.set_yticks(np.arange(-.5, len(labels), 1), minor=True)
        ax.grid(which='minor', color='k', linestyle='-', linewidth=1.5)
        ax.grid(which='major', visible=None)
        ax.tick_params(which='minor', bottom=False, left=False)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
        plt.tight_layout()
        plt.show()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingModelConfusionClicked(dashboard: QtCore.QObject):
    """ 
    Plots the confusion matrix created during model training.
    """
    # Get Labels and Matrix from Details
    get_details = dashboard.ui.textEdit_tsi_classifier_training_details.toPlainText()
    labels = ast.literal_eval(get_details.split('Truth Categories: ')[1].split("\nPossible Features")[0].replace(' ',','))  #df.Truth.unique()
    confusion_matrix = ast.literal_eval(' '.join(get_details.split('Confusion Matrix: ')[1].split()).replace(' ',',').replace('[,','['))  #metrics.confusion_matrix(y_test, y_pred, labels=labels)        
    
    #cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix=confusion_matrix, display_labels=labels)
    with matplotlib.rc_context({'toolbar':'None'}):
        plt.ion()
        fig, ax = plt.subplots()
        im = ax.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.viridis)
        ax.figure.colorbar(im, ax=ax)
        title = 'Confusion Matrix'
        ax.set(xticks=np.arange(len(labels)),
                yticks=np.arange(len(labels)),
                xticklabels=labels, yticklabels=labels,
                title=title,
                ylabel='Truth',
                xlabel='Predicted')        
        ax.set_xticks(np.arange(-.5, len(labels), 1), minor=True)
        ax.set_yticks(np.arange(-.5, len(labels), 1), minor=True)
        ax.grid(which='minor', color='k', linestyle='-', linewidth=1.5)
        ax.grid(which='major', visible=None)
        ax.tick_params(which='minor', bottom=False, left=False)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
        plt.tight_layout()
        plt.show()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingResultsNewModelConfusionClicked(dashboard: QtCore.QObject):
    """ 
    Plots a confusion matrix for the trained data.
    """
    # Get Labels and Matrix from Details
    get_details = dashboard.ui.textEdit_tsi_classifier_training_results_details.toPlainText()
    labels = ast.literal_eval(get_details.split('Truth Categories: ')[1].split("\nPossible Features")[0].replace(' ',','))  #df.Truth.unique()
    confusion_matrix = ast.literal_eval(' '.join(get_details.split('Confusion Matrix: ')[1].split()).replace(' ',',').replace('[,','['))  #metrics.confusion_matrix(y_test, y_pred, labels=labels)        
    
    #cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix=confusion_matrix, display_labels=labels)
    with matplotlib.rc_context({'toolbar':'None'}):
        plt.ion()
        fig, ax = plt.subplots()
        im = ax.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.viridis)  #, cmap=plt.cm.Blues)
        ax.figure.colorbar(im, ax=ax)
        title = 'Confusion Matrix'
        ax.set(xticks=np.arange(len(labels)),
                yticks=np.arange(len(labels)),
                xticklabels=labels, yticklabels=labels,
                title=title,
                ylabel='Truth',
                xlabel='Predicted')        
        ax.set_xticks(np.arange(-.5, len(labels), 1), minor=True)
        ax.set_yticks(np.arange(-.5, len(labels), 1), minor=True)
        ax.grid(which='minor', color='k', linestyle='-', linewidth=1.5)
        ax.grid(which='major', visible=None)
        ax.tick_params(which='minor', bottom=False, left=False)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
        plt.tight_layout()
        plt.show()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingRetrain2_RefreshClicked(dashboard: QtCore.QObject):
    """ 
    Updates the list of targets for DNN classification.
    """
    # Get the Truth Categories
    get_truth = []
    for row in range(0, dashboard.ui.tableWidget_tsi_classifier_training_training.rowCount()):
        get_truth.append(str(dashboard.ui.tableWidget_tsi_classifier_training_training.item(row,0).text()))
        
    # Add to ComboBox
    dashboard.ui.comboBox_tsi_classifier_training_retrain2_target.clear()
    dashboard.ui.comboBox_tsi_classifier_training_retrain2_target.addItems(sorted(list(set(get_truth)), key=str.lower))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingSelectAllClicked(dashboard: QtCore.QObject):
    """ 
    Selects all the features under Choose Model in the Classifier Training tab.
    """
    # Check All
    for n in range(0,dashboard.ui.listWidget_tsi_classifier_training_features.count()):
        dashboard.ui.listWidget_tsi_classifier_training_features.item(n).setCheckState(QtCore.Qt.Checked)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingDeselectAllClicked(dashboard: QtCore.QObject):
    """ 
    Deselects all the features under Choose Model in the Classifier Training tab.
    """
    # Uncheck All
    for n in range(0, dashboard.ui.listWidget_tsi_classifier_training_features.count()):
        dashboard.ui.listWidget_tsi_classifier_training_features.item(n).setCheckState(QtCore.Qt.Unchecked)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingNetronClicked(dashboard: QtCore.QObject):
    """ 
    Opens the selected model in Netron.
    """
    # Issue the Command
    get_model = str(dashboard.ui.comboBox_tsi_classifier_training_model.currentText())
    if len(get_model) > 0:
        if str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Decision Tree":
            get_model = get_model + ".h5"
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
        elif str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Deep Neural Network":
            get_model = get_model + ".h5"
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
        else:
            return
    proc=subprocess.Popen('netron "' + get_model + '"', cwd=model_directory, shell=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingResultsNetronClicked(dashboard: QtCore.QObject):
    """ 
    Opens the generated model in Netron.
    """
    # Issue the Command
    if str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Decision Tree":
        get_model = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "tmp.h5")
    elif str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Deep Neural Network":
        get_model = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "tmp.h5")
    else:
        return
    proc=subprocess.Popen('netron "' + get_model + '"', shell=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationViewClicked(dashboard: QtCore.QObject):
    """ 
    Opens up an image that details the selected model.
    """
    # Load Images Path From File
    get_model = str(dashboard.ui.comboBox_tsi_classifier_classification_model.currentText())
    if len(get_model) > 0:
        if str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) == "Decision Tree":
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
        elif str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) == "Deep Neural Network":
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
        else:
            return
        os.system('eog "' + os.path.join(model_directory, get_model + '.png') + '" &')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationModelConfusionClicked(dashboard: QtCore.QObject):
    """ 
    Plots the confusion matrix created during model training.
    """
    # Get Labels and Matrix from Details
    get_details = dashboard.ui.textEdit_tsi_classifier_classification_details.toPlainText()
    labels = ast.literal_eval(get_details.split('Truth Categories: ')[1].split("\nPossible Features")[0].replace(' ',','))  #df.Truth.unique()
    confusion_matrix = ast.literal_eval(' '.join(get_details.split('Confusion Matrix: ')[1].split()).replace(' ',',').replace('[,','['))  #metrics.confusion_matrix(y_test, y_pred, labels=labels)        
    
    #cm_display = metrics.ConfusionMatrixDisplay(confusion_matrix=confusion_matrix, display_labels=labels)
    with matplotlib.rc_context({'toolbar':'None'}):
        plt.ion()
        fig, ax = plt.subplots()
        im = ax.imshow(confusion_matrix, interpolation='nearest', cmap=plt.cm.viridis)  #, cmap=plt.cm.Blues) https://matplotlib.org/stable/tutorials/colors/colormaps.html
        ax.figure.colorbar(im, ax=ax)
        title = 'Confusion Matrix'
        ax.set(xticks=np.arange(len(labels)),
                yticks=np.arange(len(labels)),
                xticklabels=labels, yticklabels=labels,
                title=title,
                ylabel='Truth',
                xlabel='Predicted')        
        ax.set_xticks(np.arange(-.5, len(labels), 1), minor=True)
        ax.set_yticks(np.arange(-.5, len(labels), 1), minor=True)
        ax.grid(which='minor', color='k', linestyle='-', linewidth=1.5)
        ax.grid(which='major', visible=None)
        ax.tick_params(which='minor', bottom=False, left=False)
        plt.setp(ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
        plt.tight_layout()
        plt.show()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationPlaylistAddClicked(dashboard: QtCore.QObject):
    """ 
    Adds a model to the classification playlist.
    """
    # Add Unique Values to the Listbox
    get_model = str(dashboard.ui.comboBox_tsi_classifier_classification_model.currentText())
    get_technique = str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText())
    new_text = '[' + get_technique + '] ' + get_model 
    get_items = dashboard.ui.listWidget_tsi_classifier_classification_playlist.findItems(new_text,QtCore.Qt.MatchExactly)
    if len(get_items) == 0:
        dashboard.ui.listWidget_tsi_classifier_classification_playlist.addItem(new_text)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationPlaylistRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a model from the classification playlist.
    """
    # Remove Selected Playlist Item
    if dashboard.ui.listWidget_tsi_classifier_classification_playlist.count() > 0:
        get_index = int(dashboard.ui.listWidget_tsi_classifier_classification_playlist.currentRow())
        
        # Remove Item
        for item in dashboard.ui.listWidget_tsi_classifier_classification_playlist.selectedItems():
            dashboard.ui.listWidget_tsi_classifier_classification_playlist.takeItem(dashboard.ui.listWidget_tsi_classifier_classification_playlist.row(item))
        
        # Reset Selected Item 
        if get_index == dashboard.ui.listWidget_tsi_classifier_classification_playlist.count():
            get_index = get_index -1
        dashboard.ui.listWidget_tsi_classifier_classification_playlist.setCurrentRow(get_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationAutoFillClicked(dashboard: QtCore.QObject):
    """ 
    Selects all available models for the classification playlist.
    """
    # Clear the List
    dashboard.ui.listWidget_tsi_classifier_classification_playlist.clear()
    
    # Get Features from Table
    columns = range(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount())
    get_table_features = [dashboard.ui.tableWidget_tsi_classifier_classification_unknown.horizontalHeaderItem(column).text() for column in columns]
    
    # Read Features for Every Model
    model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models")
    for subdir, dirs, files in os.walk(model_directory):
        for f in files:
            if f[-4:] == ".txt":
                filepath = os.path.join(subdir, f)
                
                # Get Features in Saved in Model
                get_details = ""
                get_technique = "?"
                with open(filepath) as model_details:
                    get_details = model_details.read()
                    model_details.seek(0)
                    for line in model_details:
                        if "Technique: " in line:
                            get_technique = line.split('Technique: ')[1].replace('\n','')
                        if "Features: " in line:
                            get_features = ast.literal_eval(line.split('Features: ')[1])
                        
                # Detect if all Model Features are in Table
                if set(get_features).issubset(set(get_table_features)):
                    dashboard.ui.listWidget_tsi_classifier_classification_playlist.addItem('[' + get_technique + '] ' + filepath.split('/')[-1][:-4])


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationPlaylistStartClicked(dashboard: QtCore.QObject):
    """ 
    Runs the test data through each model to produce classification results.
    """
    # Clear the Table
    dashboard.ui.tableWidget_tsi_classifier_classification_results.setRowCount(0)
    dashboard.ui.tableWidget_tsi_classifier_classification_results.setColumnCount(0)

    # Load Each Model
    for m in range(0, dashboard.ui.listWidget_tsi_classifier_classification_playlist.count()):
        get_technique = ""
        get_model = str(dashboard.ui.listWidget_tsi_classifier_classification_playlist.item(m).text()).split('] ',1)[1]
        
        # Read Features for Every Model
        model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models")
        for subdir, dirs, files in os.walk(model_directory):
            for f in files:
                if (f[-4:] == ".txt") and (get_model == f[:-4]):
                    filepath = os.path.join(subdir, f)
                    
                    # Get Technique Saved in Model
                    get_details = ""
                    with open(filepath) as model_details:
                        get_details = model_details.read()
                        model_details.seek(0)
                        for line in model_details:
                            if "Technique: " in line:
                                get_technique = line.split('Technique: ')[1].replace('\n','')
                                break
        
        if get_technique == "Decision Tree":
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
            get_file = get_model + ".h5"
            clf = pickle.load(open(os.path.join(model_directory, get_file), "rb"))
            
            # Details                
            with open(filepath) as model_details:
                get_details = model_details.read()
                
            # Features
            get_features = []
            for line in get_details.split('\n'):
                if "Features: " in line:
                    get_features = ast.literal_eval(line.split('Features: ')[1])
                        
            # Create Dataframe
            get_column_labels = []            
            for col in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount()):
                get_column_labels.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.horizontalHeaderItem(col).text()))
            df = pd.DataFrame(columns=get_column_labels)
            for row in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount()):
                get_row = []
                for col in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount()):
                    get_row.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.item(row,col).text()))
                df.loc[len(df)] = get_row
        
            # Extract Relevant Columns
            X_test = df[get_features]
            y_pred = clf.predict(X_test)

            # Classification
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setColumnCount(dashboard.ui.tableWidget_tsi_classifier_classification_results.columnCount() + 1)
            for n in range(0,len(X_test.index[:])):
                if m == 0:
                    dashboard.ui.tableWidget_tsi_classifier_classification_results.setRowCount(dashboard.ui.tableWidget_tsi_classifier_classification_results.rowCount() + 1)
                    header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.verticalHeaderItem(n).text()))
                    header_item.setFont(QtGui.QFont("Ubuntu",10))
                    dashboard.ui.tableWidget_tsi_classifier_classification_results.setVerticalHeaderItem(n,header_item)
                    
                classification_text = str(y_pred[n])
                classification_item = QtWidgets.QTableWidgetItem(classification_text)
                classification_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_tsi_classifier_classification_results.setItem(n,m,classification_item)
            
        elif get_technique == "Deep Neural Network":
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
            get_file = get_model + ".h5"
            
            # DNN Target
            get_details = ""                    
            with open(filepath) as model_details:
                get_details = model_details.read()
            get_target = get_details.split('Target: ')[1].split("\nLayer1: ")[0]
                
            # Features
            get_features = []
            for line in get_details.split('\n'):
                if "Features: " in line:
                    get_features = ast.literal_eval(line.split('Features: ')[1])
                
            # Create Dataframe
            get_column_labels = []            
            for col in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount()):
                get_column_labels.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.horizontalHeaderItem(col).text()))
            df=pd.DataFrame(columns=get_column_labels)
            for row in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount()):
                get_row = []
                for col in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount()):
                    get_row.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.item(row,col).text()))
                df.loc[len(df)] = get_row
                    
            # Sort Columns Alphabetically
            df = df.reindex(sorted(df.columns, key=str.lower), axis=1)
                
            # Extract Relevant Columns
            X = df[get_features]
            X = X.to_numpy().astype(np.float64)
            X =(X-X.min())/(X.max()-X.min())

            # Load the Keras Model
            model = load_model(os.path.join(model_directory, get_file))
                        
            # Classification
            for line in get_details.split('\n'):
                if "Threshold: " in line:
                    get_threshold = float(line.split('Threshold: ')[1].replace('\n',''))
            predictions = (model.predict(X) > get_threshold).astype(int)
            
            # Fill the Results Table
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setColumnCount(dashboard.ui.tableWidget_tsi_classifier_classification_results.columnCount() + 1)
            correct = 0
            for n in range(0,len(X)):
                if m == 0:
                    dashboard.ui.tableWidget_tsi_classifier_classification_results.setRowCount(dashboard.ui.tableWidget_tsi_classifier_classification_results.rowCount() + 1)
                    header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.verticalHeaderItem(n).text()))
                    header_item.setFont(QtGui.QFont("Ubuntu",10))
                    dashboard.ui.tableWidget_tsi_classifier_classification_results.setVerticalHeaderItem(n,header_item)
                                            
                if predictions[n] == 0:
                    classification_text = "Not " + get_target
                else:
                    classification_text = get_target
                classification_item = QtWidgets.QTableWidgetItem(classification_text)
                classification_item.setTextAlignment(QtCore.Qt.AlignCenter)
                dashboard.ui.tableWidget_tsi_classifier_classification_results.setItem(n,m,classification_item)
                        
        else:
            return
        
        header_item = QtWidgets.QTableWidgetItem('[' + get_technique + '] ' + get_model)
        header_item.setFont(QtGui.QFont("Ubuntu",10))
        dashboard.ui.tableWidget_tsi_classifier_classification_results.setHorizontalHeaderItem(m,header_item)

    # Resize the Table
    dashboard.ui.tableWidget_tsi_classifier_classification_results.resizeRowsToContents()
    dashboard.ui.tableWidget_tsi_classifier_classification_results.resizeColumnsToContents()
    dashboard.ui.tableWidget_tsi_classifier_classification_results.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_tsi_classifier_classification_results.horizontalHeader().setStretchLastSection(True)
    
    # Confidence Table
    _slotTSI_ClassifierClassificationConfidenceRecalculateClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationTestClicked(dashboard: QtCore.QObject):
    """ 
    Applies the current model to all the data.
    """
    # Load the Model
    dashboard.ui.tableWidget_tsi_classifier_classification_results.setColumnCount(1)
    if str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) == "Decision Tree":
        model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
        get_file = str(dashboard.ui.comboBox_tsi_classifier_classification_model.currentText()) + ".h5"
        clf = pickle.load(open(os.path.join(model_directory, get_file), "rb"))
        
        # Features
        get_features = []
        get_details = str(dashboard.ui.textEdit_tsi_classifier_classification_details.toPlainText())
        for line in get_details.split('\n'):
            if "Features: " in line:
                get_features = ast.literal_eval(line.split('Features: ')[1])
                
        # Create Dataframe
        get_column_labels = []            
        for m in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount()):
            get_column_labels.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.horizontalHeaderItem(m).text()))
        df = pd.DataFrame(columns=get_column_labels)
        for row in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount()):
            get_row = []
            for col in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount()):
                get_row.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.item(row,col).text()))
            df.loc[len(df)] = get_row
    
        # Extract Relevant Columns
        X_test = df[get_features]
        y_pred = clf.predict(X_test)

        # Classification
        dashboard.ui.tableWidget_tsi_classifier_classification_results.setRowCount(0)
        for n in range(0,len(X_test.index[:])):
            row = dashboard.ui.tableWidget_tsi_classifier_classification_results.rowCount()
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setRowCount(row + 1)
            classification_text = str(y_pred[n])
            classification_item = QtWidgets.QTableWidgetItem(classification_text)
            classification_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setItem(row,0,classification_item)
            
            header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.verticalHeaderItem(n).text()))
            header_item.setFont(QtGui.QFont("Ubuntu",10))
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setVerticalHeaderItem(row,header_item)
        
    elif str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) == "Deep Neural Network":
        model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
        get_file = str(dashboard.ui.comboBox_tsi_classifier_classification_model.currentText()) + ".h5"
        
        # DNN Target
        get_details = dashboard.ui.textEdit_tsi_classifier_classification_details.toPlainText()
        get_target = get_details.split('Target: ')[1].split("\nLayer1: ")[0]
            
        # Features
        get_features = []
        get_details = str(dashboard.ui.textEdit_tsi_classifier_classification_details.toPlainText())
        for line in get_details.split('\n'):
            if "Features: " in line:
                get_features = ast.literal_eval(line.split('Features: ')[1])
            
        # Create Dataframe
        get_column_labels = []            
        for m in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount()):
            get_column_labels.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.horizontalHeaderItem(m).text()))
        df=pd.DataFrame(columns=get_column_labels)
        for row in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.rowCount()):
            get_row = []
            for col in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount()):
                get_row.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.item(row,col).text()))
            df.loc[len(df)] = get_row
                
        # Sort Columns Alphabetically
        df = df.reindex(sorted(df.columns, key=str.lower), axis=1)
            
        # Extract Relevant Columns
        X = df[get_features]
        X = X.to_numpy().astype(np.float64)
        X =(X-X.min())/(X.max()-X.min())

        # Load the Keras Model
        model = load_model(os.path.join(model_directory, get_file))
                    
        # Classification
        for line in get_details.split('\n'):
            if "Threshold: " in line:
                get_threshold = float(line.split('Threshold: ')[1].replace('\n',''))
        predictions = (model.predict(X) > get_threshold).astype(int)
        
        # Fill the Results Table
        dashboard.ui.tableWidget_tsi_classifier_classification_results.setRowCount(0)
        correct = 0
        for n in range(0,len(X)):
            row = dashboard.ui.tableWidget_tsi_classifier_classification_results.rowCount()
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setRowCount(row + 1)
            if predictions[n] == 0:
                classification_text = "Not " + get_target
            else:
                classification_text = get_target
            classification_item = QtWidgets.QTableWidgetItem(classification_text)
            classification_item.setTextAlignment(QtCore.Qt.AlignCenter)
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setItem(row,0,classification_item)
            
            header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.verticalHeaderItem(n).text()))
            header_item.setFont(QtGui.QFont("Ubuntu",10))
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setVerticalHeaderItem(row,header_item)
                    
    else:
        return
    
    header_item = QtWidgets.QTableWidgetItem('[' + str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) + '] ' + str(dashboard.ui.comboBox_tsi_classifier_classification_model.currentText()))
    header_item.setFont(QtGui.QFont("Ubuntu",10))
    dashboard.ui.tableWidget_tsi_classifier_classification_results.setHorizontalHeaderItem(0,header_item)

    dashboard.ui.tableWidget_tsi_classifier_classification_results.resizeRowsToContents()
    dashboard.ui.tableWidget_tsi_classifier_classification_results.resizeColumnsToContents()
    dashboard.ui.tableWidget_tsi_classifier_classification_results.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_tsi_classifier_classification_results.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationResultsClear(dashboard: QtCore.QObject):
    """ 
    Clears the Classification Results table.
    """
    # Clear the Table
    dashboard.ui.tableWidget_tsi_classifier_classification_results.setRowCount(0)
    dashboard.ui.tableWidget_tsi_classifier_classification_results.setColumnCount(1)
    header_item = QtWidgets.QTableWidgetItem("")
    header_item.setFont(QtGui.QFont("Ubuntu",10))
    dashboard.ui.tableWidget_tsi_classifier_classification_results.setHorizontalHeaderItem(0,header_item)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationResultsRemoveColClicked(dashboard: QtCore.QObject):
    """ 
    Removes a column in the Classification Results table.
    """
    # Remove Column
    row = dashboard.ui.tableWidget_tsi_classifier_classification_results.currentRow()
    col = dashboard.ui.tableWidget_tsi_classifier_classification_results.currentColumn()
    dashboard.ui.tableWidget_tsi_classifier_classification_results.removeColumn(col)
    
    if dashboard.ui.tableWidget_tsi_classifier_classification_results.columnCount() > 0:
        if col == dashboard.ui.tableWidget_tsi_classifier_classification_results.columnCount():
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setCurrentCell(row,col-1)
        elif col == 0:
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setCurrentCell(row,0)
        else:
            dashboard.ui.tableWidget_tsi_classifier_classification_results.setCurrentCell(row,col)
    else:
        _slotTSI_ClassifierClassificationResultsClear(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationResultsModelClicked(dashboard: QtCore.QObject):
    """ 
    Brings up a model selected in the Results table in the Choose Model frame. 
    """
    # Get Model and Technique
    get_col = dashboard.ui.tableWidget_tsi_classifier_classification_results.currentColumn()
    if get_col >= 0:
        get_header = str(dashboard.ui.tableWidget_tsi_classifier_classification_results.horizontalHeaderItem(get_col).text())
        get_technique = get_header.split('] ',1)[0][1:]
        get_model = get_header.split('] ',1)[1]
    
        # Set Technique and Model Comboboxes
        technique_index = dashboard.ui.comboBox_tsi_classifier_classification_technique.findText(get_technique, QtCore.Qt.MatchFixedString)
        if technique_index >= 0:
            dashboard.ui.comboBox_tsi_classifier_classification_technique.setCurrentIndex(technique_index)    
        model_index = dashboard.ui.comboBox_tsi_classifier_classification_model.findText(get_model, QtCore.Qt.MatchFixedString)
        if model_index >= 0:
            dashboard.ui.comboBox_tsi_classifier_classification_model.setCurrentIndex(model_index)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationRemoveFeaturesClicked(dashboard: QtCore.QObject):
    """ 
    Creates a dialog with the result, model, and features for a selected file.
    """
    # File
    get_row = dashboard.ui.tableWidget_tsi_classifier_classification_results.currentRow()
    if get_row >= 0:
        get_file = str(dashboard.ui.tableWidget_tsi_classifier_classification_results.verticalHeaderItem(get_row).text())
        model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models")

        # Model, Result, and Features
        get_results = []
        get_techniques_models = []
        get_features = []
        for col in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_results.columnCount()):
            get_results.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_results.item(get_row,col).text()))
            get_techniques_models.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_results.horizontalHeaderItem(col).text()))
            get_model = str(dashboard.ui.tableWidget_tsi_classifier_classification_results.horizontalHeaderItem(col).text()).split('] ',1)[1]
            
            # Features
            get_model_features = ""
            for subdir, dirs, files in os.walk(model_directory):
                for f in files:
                    if (f[-4:] == ".txt") and (get_model == f[:-4]):
                        filepath = os.path.join(subdir, f)
                        
                        # Get Features Saved in Model
                        get_details = ""
                        with open(filepath) as model_details:
                            get_details = model_details.read()
                            model_details.seek(0)
                            for line in get_details.split('\n'):
                                if "Features: " in line:
                                    get_model_features = ast.literal_eval(line.split('Features: ')[1])
                                    break
            get_features.append(get_model_features)
        
        # Open a GUI
        features_dlg = FeaturesDialog(parent=dashboard, filename=get_file, results=get_results, models=get_techniques_models, features=get_features)
        features_dlg.show()
        features_dlg.exec_()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationConfidenceRecalculateClicked(dashboard: QtCore.QObject):
    """ 
    Recalculates the confidence levels from the classification results table.
    """
    # Clear the Table
    dashboard.ui.tableWidget_tsi_classifier_classification_confidence.setRowCount(0)
    
    # Analyze Results Table
    for row in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_results.rowCount()):
        dashboard.ui.tableWidget_tsi_classifier_classification_confidence.setRowCount(dashboard.ui.tableWidget_tsi_classifier_classification_confidence.rowCount() + 1)
        header_item = QtWidgets.QTableWidgetItem(str(dashboard.ui.tableWidget_tsi_classifier_classification_results.verticalHeaderItem(row).text()))
        header_item.setFont(QtGui.QFont("Ubuntu",10))
        dashboard.ui.tableWidget_tsi_classifier_classification_confidence.setVerticalHeaderItem(row,header_item)
        
        # Create a List
        get_results = []
        for col in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_results.columnCount()):
            get_results.append(str(dashboard.ui.tableWidget_tsi_classifier_classification_results.item(row,col).text()))
            
        # Calculate Confidence from List
        results_count = [[x,get_results.count(x)] for x in set(get_results)]  # [['qwer', 1], ['not asdf', 1], ['asdf', 3]]
        results_count.sort(key = lambda x: x[1],reverse=True)
        total_sum = 0
        for n in range(0,len(results_count)):
            total_sum = total_sum + results_count[n][1]
            
        equal_weight_text = ""
        for n in range(0,len(results_count)):
            try:
                if results_count[n][0][0:4] == "Not ":
                    pass  # Skip "Not Something" but keep it in total and as part of "Something" count
                else:
                    if len(equal_weight_text) == 0:
                        equal_weight_text = results_count[n][0] + ": " + str(round(float(results_count[n][1])/float(total_sum),2)*100) + "%"
                    else:
                        equal_weight_text = equal_weight_text + " | " + results_count[n][0] + ": " + str(round(float(results_count[n][1])/float(total_sum),2)*100) + "%"
            except:
                equal_weight_text = "Error"
                
        equal_weight_item = QtWidgets.QTableWidgetItem(equal_weight_text)
        equal_weight_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_tsi_classifier_classification_confidence.setItem(row,0,equal_weight_item)
                    
    # Resize the Table
    dashboard.ui.tableWidget_tsi_classifier_classification_confidence.resizeRowsToContents()
    dashboard.ui.tableWidget_tsi_classifier_classification_confidence.resizeColumnsToContents()
    dashboard.ui.tableWidget_tsi_classifier_classification_confidence.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_tsi_classifier_classification_confidence.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationNetronClicked(dashboard: QtCore.QObject):
    """ 
    Opens the selected model in Netron.
    """
    # Issue the Command
    get_model = str(dashboard.ui.comboBox_tsi_classifier_classification_model.currentText())
    if len(get_model) > 0:
        if str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) == "Decision Tree":
            get_model = get_model + ".h5"
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
        elif str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) == "Deep Neural Network":
            get_model = get_model + ".h5"
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
        else:
            return
    proc=subprocess.Popen('netron "' + get_model + '"', cwd=model_directory, shell=True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationResultsExportClicked(dashboard: QtCore.QObject):
    """ 
    Exports the Classifier Classification Results table to .csv file.
    """
    if (dashboard.ui.tableWidget_tsi_classifier_classification_results.columnCount() > 0) and (dashboard.ui.tableWidget_tsi_classifier_classification_results.rowCount() > 0):
        # Choose File Location
        get_default_folder = os.path.join(fissure.utils.FISSURE_ROOT, "classifier_results.csv")
        path, ok = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save CSV', get_default_folder, 'CSV(*.csv)')
        if ok:
            columns = range(dashboard.ui.tableWidget_tsi_classifier_classification_results.columnCount())
            rows = range(dashboard.ui.tableWidget_tsi_classifier_classification_results.rowCount())
            header = ["File"] + [dashboard.ui.tableWidget_tsi_classifier_classification_results.horizontalHeaderItem(column).text() for column in columns]
            row_header = [dashboard.ui.tableWidget_tsi_classifier_classification_results.verticalHeaderItem(row).text() for row in rows]
            with open(path, 'w') as csvfile:
                writer = csv.writer(csvfile, dialect='excel', lineterminator='\n')
                writer.writerow(header)
                for row in rows:
                    get_row_items = []
                    get_row_items = [row_header[row]] + [str(dashboard.ui.tableWidget_tsi_classifier_classification_results.item(row, column).text()) for column in columns]
                    writer.writerow(get_row_items)  


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingRetrain2_ManualChecked(dashboard: QtCore.QObject):
    """ 
    Disables the classification threshold spinbox in DNN retrain settings.
    """
    # Enable/Disable
    if dashboard.ui.checkBox_tsi_classifier_training_retrain2_manual.isChecked() == True:
        dashboard.ui.doubleSpinBox_tsi_classifier_training_retrain2_threshold.setEnabled(True)
        dashboard.ui.label2_tsi_classifier_training_retrain2_threshold.setEnabled(True)
    elif dashboard.ui.checkBox_tsi_classifier_training_retrain2_manual.isChecked() == False:
        dashboard.ui.doubleSpinBox_tsi_classifier_training_retrain2_threshold.setEnabled(False)
        dashboard.ui.label2_tsi_classifier_training_retrain2_threshold.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingCategoryChanged(dashboard: QtCore.QObject):
    """ 
    Switches between known AI/ML techniques.
    """
    # Switch the Techniques
    dashboard.ui.comboBox_tsi_classifier_training_technique.clear()
    if dashboard.ui.comboBox_tsi_classifier_training_category.currentText() == "All":
        dashboard.ui.comboBox_tsi_classifier_training_technique.addItem("Decision Tree")
        dashboard.ui.comboBox_tsi_classifier_training_technique.addItem("Deep Neural Network")
    elif dashboard.ui.comboBox_tsi_classifier_training_category.currentText() == "Supervised Learning":
        dashboard.ui.comboBox_tsi_classifier_training_technique.addItem("Decision Tree")
    elif dashboard.ui.comboBox_tsi_classifier_training_category.currentText() == "Artificial Neural Network":
        dashboard.ui.comboBox_tsi_classifier_training_technique.addItem("Deep Neural Network")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingModelChanged(dashboard: QtCore.QObject):
    """ 
    Lists the features assigned to a model and additional features that could be integrated.
    """
    get_model = str(dashboard.ui.comboBox_tsi_classifier_training_model.currentText())
    if len(get_model) > 0:
        columns = range(dashboard.ui.tableWidget_tsi_classifier_training_training.columnCount())
        get_table_features = [dashboard.ui.tableWidget_tsi_classifier_training_training.horizontalHeaderItem(column).text() for column in columns]
        dashboard.ui.pushButton_tsi_classifier_training_test.setEnabled(True)
        dashboard.ui.pushButton_tsi_classifier_training_retrain.setEnabled(True)
        
        # Load Details, Features, Image Path from File
        get_details = ""
        model_directory = ""
        if str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Decision Tree":
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
        elif str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Deep Neural Network":
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
        else:
            return
        
        with open(os.path.join(model_directory, get_model + ".txt")) as model_details:
            get_details = model_details.read()
            model_details.seek(0)
            for line in model_details:
                if "Features: " in line:
                    get_features = ast.literal_eval(line.split('Features: ')[1])
        dashboard.ui.textEdit_tsi_classifier_training_details.setPlainText(get_details)
        if os.path.isfile(os.path.join(model_directory, get_model + ".png")):
            dashboard.ui.pushButton_tsi_classifier_training_view.setEnabled(True)
        else:
            dashboard.ui.pushButton_tsi_classifier_training_view.setEnabled(False)
                                
        # Put Checked Items at the Top
        dashboard.ui.listWidget_tsi_classifier_training_features.clear()
        for n in sorted(get_features, key=str.lower):
            item = QtWidgets.QListWidgetItem()
            item.setText(n)
            item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
            item.setCheckState(QtCore.Qt.Checked)
            if n not in get_table_features:
                item.setForeground(QtGui.QColor(255,0,0))
                dashboard.ui.pushButton_tsi_classifier_training_test.setEnabled(False)
                #dashboard.ui.pushButton_tsi_classifier_training_retrain.setEnabled(False)
            dashboard.ui.listWidget_tsi_classifier_training_features.addItem(item)
            
        # Put Unchecked Items at the Bottom
        uncommon_elements = sorted(list(set(dashboard.all_features) - set(get_features)), key=str.lower)
        for n in uncommon_elements:
            item = QtWidgets.QListWidgetItem()
            item.setText(n)
            item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
            item.setCheckState(QtCore.Qt.Unchecked)
            if n not in get_table_features:
                item.setForeground(QtGui.QColor(255,0,0))
            dashboard.ui.listWidget_tsi_classifier_training_features.addItem(item)   


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierTrainingTechniqueChanged(dashboard: QtCore.QObject):
    """ 
    Switches the models for a selected technique.
    """
    # Switch the Models
    dashboard.ui.comboBox_tsi_classifier_training_model.clear()
    decision_tree_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
    dnn_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
    get_models = []
    if str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Decision Tree":
        for file in os.listdir(decision_tree_directory):
            if file.endswith('.h5'):
                get_models.append(str(file).strip('.h5'))
        dashboard.ui.stackedWidget_tsi_classifier_training_retrain.setCurrentIndex(1)
    elif str(dashboard.ui.comboBox_tsi_classifier_training_technique.currentText()) == "Deep Neural Network":
        for file in os.listdir(dnn_directory):
            if file.endswith('.h5'):
                get_models.append(str(file).strip('.h5'))
        dashboard.ui.stackedWidget_tsi_classifier_training_retrain.setCurrentIndex(2)
    dashboard.ui.comboBox_tsi_classifier_training_model.addItems(sorted(get_models, key=str.lower))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationCategoryChanged(dashboard: QtCore.QObject):
    """ 
    Switches between known AI/ML techniques.
    """
    # Switch the Techniques
    dashboard.ui.comboBox_tsi_classifier_classification_technique.clear()
    if dashboard.ui.comboBox_tsi_classifier_classification_category.currentText() == "All":
        dashboard.ui.comboBox_tsi_classifier_classification_technique.addItem("Decision Tree")
        dashboard.ui.comboBox_tsi_classifier_classification_technique.addItem("Deep Neural Network")
    elif dashboard.ui.comboBox_tsi_classifier_classification_category.currentText() == "Supervised Learning":
        dashboard.ui.comboBox_tsi_classifier_classification_technique.addItem("Decision Tree")
    elif dashboard.ui.comboBox_tsi_classifier_classification_category.currentText() == "Artificial Neural Network":
        dashboard.ui.comboBox_tsi_classifier_classification_technique.addItem("Deep Neural Network")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationTechniqueChanged(dashboard: QtCore.QObject):
    """ 
    Switches the models for a selected technique.
    """
    # Switch the Models
    dashboard.ui.comboBox_tsi_classifier_classification_model.clear()
    decision_tree_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
    dnn_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
    get_models = []
    if str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) == "Decision Tree":
        for file in os.listdir(decision_tree_directory):
            if file.endswith('.h5'):
                get_models.append(str(file).strip('.h5'))
        #dashboard.ui.stackedWidget_tsi_classifier_training_retrain.setCurrentIndex(1)
    elif str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) == "Deep Neural Network":
        for file in os.listdir(dnn_directory):
            if file.endswith('.h5'):
                get_models.append(str(file).strip('.h5'))
        #dashboard.ui.stackedWidget_tsi_classifier_training_retrain.setCurrentIndex(2)
    dashboard.ui.comboBox_tsi_classifier_classification_model.addItems(sorted(get_models, key=str.lower))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ClassifierClassificationModelChanged(dashboard: QtCore.QObject):
    """ 
    Lists the features assigned to a model and additional features that could be integrated.
    """
    get_model = str(dashboard.ui.comboBox_tsi_classifier_classification_model.currentText())
    if len(get_model) > 0:
        columns = range(dashboard.ui.tableWidget_tsi_classifier_classification_unknown.columnCount())
        get_table_features = [dashboard.ui.tableWidget_tsi_classifier_classification_unknown.horizontalHeaderItem(column).text() for column in columns]
        dashboard.ui.pushButton_tsi_classifier_classification_test.setEnabled(True)
        dashboard.ui.pushButton_tsi_classifier_classification_playlist_add.setEnabled(True)
        
        # Load Details, Features, Image Path from File
        get_details = ""
        model_directory = ""
        if str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) == "Decision Tree":
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "Decision_Tree")
        elif str(dashboard.ui.comboBox_tsi_classifier_classification_technique.currentText()) == "Deep Neural Network":
            model_directory = os.path.join(fissure.utils.CLASSIFIER_DIR, "Models", "DNN")
        else:
            return
        
        with open(os.path.join(model_directory, get_model + ".txt")) as model_details:
            get_details = model_details.read()
            model_details.seek(0)
            for line in model_details:
                if "Features: " in line:
                    get_features = ast.literal_eval(line.split('Features: ')[1])
        dashboard.ui.textEdit_tsi_classifier_classification_details.setPlainText(get_details)
        if os.path.isfile(os.path.join(model_directory, get_model + ".png")):
            dashboard.ui.pushButton_tsi_classifier_classification_view.setEnabled(True)
        else:
            dashboard.ui.pushButton_tsi_classifier_classification_view.setEnabled(False)
                                
        # Put Checked Items at the Top
        dashboard.ui.listWidget_tsi_classifier_classification_features.clear()
        for n in sorted(get_features, key=str.lower):
            item = QtWidgets.QListWidgetItem()
            item.setText(n)
            item.setCheckState(1)
            if n not in get_table_features:
                item.setForeground(QtGui.QColor(255,0,0))
                dashboard.ui.pushButton_tsi_classifier_classification_test.setEnabled(False)
                dashboard.ui.pushButton_tsi_classifier_classification_playlist_add.setEnabled(False)
            dashboard.ui.listWidget_tsi_classifier_classification_features.addItem(item)
            
        # # Put Unchecked Items at the Bottom
        # uncommon_elements = sorted(list(set(dashboard.all_features) - set(get_features)), key=str.lower)
        # for n in uncommon_elements:
            # item = QtWidgets.QListWidgetItem()
            # item.setText(n)
            # item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
            # item.setCheckState(QtCore.Qt.Unchecked)
            # if n not in get_table_features:
                # item.setForeground(QtGui.QColor(255,0,0))
            # dashboard.ui.listWidget_tsi_classifier_classification_features.addItem(item)