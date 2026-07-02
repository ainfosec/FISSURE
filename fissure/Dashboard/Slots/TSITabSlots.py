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

from fissure.utils.selected_node_utils import (
    selected_node_is_local,
    selected_node_is_remote,
)

from collections import deque
from matplotlib.collections import LineCollection


TSI_DETECTOR_TYPES = [
    ("rf", "RF"),
    ("wifi", "Wi-Fi"),
    ("bluetooth", "Bluetooth"),
    ("protocol", "Protocol"),
    ("ml", "ML"),
]

TSI_DETECTOR_MODES = [
    ("fixed", "Fixed"),
    ("sweep", "Sweep"),
    ("channel_hop", "Channel Hop"),
    ("lock", "Lock"),
    ("passive", "Passive"),
    ("file", "File"),
]


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
    # Retrieve Table Values
    get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.currentText())

    get_row = fissure.utils.library.getConditionerRow(
        dashboard.backend.library, 
        get_method, 
        fissure.utils.get_library_version(), 
        "File"
    )

    if get_row == None:
        get_parameter_labels = []
        get_parameter_values = []
    else:
        get_parameter_labels = get_row[9]
        get_parameter_values = get_row[8]

    # Clear Table
    dashboard.ui.tableWidget_tsi_conditioner_settings_files.setColumnCount(1)
    dashboard.ui.tableWidget_tsi_conditioner_settings_files.setRowCount(0)
    dashboard.ui.tableWidget_tsi_conditioner_settings_files.clearContents()

    # Fill Table
    for n in range(0, len(get_parameter_labels)):
        label_item = QtWidgets.QTableWidgetItem(get_parameter_labels[n])
        value_item = QtWidgets.QTableWidgetItem(get_parameter_values[n])
        dashboard.ui.tableWidget_tsi_conditioner_settings_files.setRowCount(dashboard.ui.tableWidget_tsi_conditioner_settings_files.rowCount()+1)
        dashboard.ui.tableWidget_tsi_conditioner_settings_files.setVerticalHeaderItem(dashboard.ui.tableWidget_tsi_conditioner_settings_files.rowCount()-1, label_item)
        dashboard.ui.tableWidget_tsi_conditioner_settings_files.setItem(dashboard.ui.tableWidget_tsi_conditioner_settings_files.rowCount()-1, 0, value_item)

    # Resize Table
    dashboard.ui.tableWidget_tsi_conditioner_settings_files.resizeColumnsToContents()
    dashboard.ui.tableWidget_tsi_conditioner_settings_files.resizeRowsToContents()
    dashboard.ui.tableWidget_tsi_conditioner_settings_files.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_tsi_conditioner_settings_files.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputSourceChanged(dashboard: QtCore.QObject):
    """ 
    Enables/disables the Start button if folder or file is selected with no valid filepath.
    """
    # File
    if dashboard.ui.comboBox_tsi_conditioner_input_source.currentText() == "File":
        if dashboard.ui.label2_tsi_conditioner_info_file_name.text() == "File:":
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(False)
        else:
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(True)
        dashboard.ui.stackedWidget_tsi_conditioner_input.setCurrentIndex(0)
        dashboard.ui.stackedWidget_tsi_conditioner_settings_method.setCurrentIndex(0)

        # Update Categories
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.blockSignals(True)
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.blockSignals(True)
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.clear()
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.clear()
        get_categories = fissure.utils.library.getConditionerIsolationCategory(
            dashboard.backend.library, 
            "File", 
            fissure.utils.get_library_version()
        )
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.addItems(get_categories)
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.blockSignals(False)
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.blockSignals(False)
        _slotTSI_ConditionerSettingsIsolationCategoryChanged(dashboard)

    # Folder
    elif dashboard.ui.comboBox_tsi_conditioner_input_source.currentText() == "Folder":
        if dashboard.ui.comboBox_tsi_conditioner_input_folders.currentText() == "":
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(False)
        elif dashboard.ui.listWidget_tsi_conditioner_input_files.count() == 0:
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(False)
        else:
            dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(True)
        dashboard.ui.stackedWidget_tsi_conditioner_input.setCurrentIndex(0)
        dashboard.ui.stackedWidget_tsi_conditioner_settings_method.setCurrentIndex(0)

        # Update Categories
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.blockSignals(True)
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.blockSignals(True)
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.clear()
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.clear()
        get_categories = fissure.utils.library.getConditionerIsolationCategory(
            dashboard.backend.library, 
            "File", 
            fissure.utils.get_library_version()
        )
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.addItems(get_categories)
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.blockSignals(False)
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.blockSignals(False)
        _slotTSI_ConditionerSettingsIsolationCategoryChanged(dashboard)
    
    # Detector Results
    elif dashboard.ui.comboBox_tsi_conditioner_input_source.currentText() == "Detector Results":
        dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(True)
        dashboard.ui.stackedWidget_tsi_conditioner_input.setCurrentIndex(1)
        dashboard.ui.stackedWidget_tsi_conditioner_settings_method.setCurrentIndex(1)

        # Update Categories
        _slotTSI_ConditionerSettingsIsolationFrequenciesHardwareChanged(dashboard)

        dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(False)  # Temporarily disabled while under development

    # Frequency
    elif dashboard.ui.comboBox_tsi_conditioner_input_source.currentText() == "Frequencies":
        dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(True)
        dashboard.ui.stackedWidget_tsi_conditioner_input.setCurrentIndex(2)
        dashboard.ui.stackedWidget_tsi_conditioner_settings_method.setCurrentIndex(1)

        # Update Categories
        _slotTSI_ConditionerSettingsIsolationFrequenciesHardwareChanged(dashboard)

        dashboard.ui.pushButton_tsi_conditioner_operation_start.setEnabled(False)  # Temporarily disabled while under development


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsIsolationCategoryChanged(dashboard: QtCore.QObject):
    """ 
    Changes the isolation method options.
    """
    # Get Category
    get_category = dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText()
    
    # Get Methods
    get_methods = fissure.utils.library.getConditionerIsolationMethod(
        dashboard.backend.library, 
        get_category, 
        fissure.utils.get_library_version(),
        "File"
    )
    dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.clear()

    # Exclude Certain Items
    item_to_remove = "Strongest Frequency then Bandpass"  # Need to convert two-stage method to one
    if item_to_remove in get_methods:
        get_methods.remove(item_to_remove)

    # Energy - Burst Tagger
    if get_category == "Energy - Burst Tagger":
        #methods = ['Normal','Normal Decay','Power Squelch','Lowpass','Power Squelch then Lowpass','Bandpass','Strongest Frequency then Bandpass']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.addItems(get_methods)
    
    # Energy - Imagery
    elif get_category == "Energy - Imagery":
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.addItems(methods)
    
    # Eigenvalue
    elif get_category == "Eigenvalue":
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.addItems(methods)
    
    # Matched Filter
    elif get_category == "Matched Filter":
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.addItems(methods)
    
    # Cyclostationary
    elif get_category == "Cyclostationary":
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
    
    # Plot
    fissure.Dashboard.UI_Components.Qt5.previewIQ_File(get_type, get_filepath)


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

        # Plot
        fissure.Dashboard.UI_Components.Qt5.previewIQ_File(get_type, get_filepath)


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
    # Gather Details
    get_category = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText())
    get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.currentText())
    get_type = str(dashboard.ui.comboBox_tsi_conditioner_input_data_type.currentText())

    if get_method == "None":
        return

    # Retrieve Filepath and File Type
    get_filepath, get_file_type = fissure.utils.library.getConditionerFilepath(
        dashboard.backend.library, 
        get_category, 
        get_method,
        "File",
        get_type,
        fissure.utils.get_library_version()
    )

    # Open File
    if get_filepath:
        fg_directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "TSI Flow Graphs", "Conditioner", get_filepath)
        if get_file_type == "Flow Graph":
            fg_directory = fg_directory.replace(".py", ".grc")
            osCommandString = 'gnuradio-companion "' + fg_directory + '"'
            try:
                os.system(osCommandString + ' &')
            except Exception as e:
                dashboard.logger.error(f"Could not open Conditioner flow graph with command: {osCommandString}. Error: {e}")
        else:
            dashboard.logger.error("Unknown file type")


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
    get_input_source = str(dashboard.ui.comboBox_tsi_conditioner_input_source.currentText())
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

    # Plot
    fissure.Dashboard.UI_Components.Qt5.previewIQ_File(get_type, get_filepath)


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

        # Plot
        fissure.Dashboard.UI_Components.Qt5.previewIQ_File(get_type, get_filepath)


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
    Clears the unified TSI detector results list and detector plot points.
    """
    for table in _tsi_detector_results_tables(dashboard):
        table.clearContents()
        table.setRowCount(0)

    if hasattr(dashboard, "tsi_detector_plot_events"):
        _tsi_detector_plot_clear_points(dashboard)


def _tsi_blacklist_ranges_mhz(dashboard: QtCore.QObject):
    ranges = []

    list_widget = dashboard.ui.listWidget_tsi_blacklist

    for row in range(list_widget.count()):
        item = list_widget.item(row)
        if item is None:
            continue

        text = str(item.text()).strip()

        try:
            start_text, end_text = text.split("-", 1)
            start_mhz = float(start_text.strip())
            end_mhz = float(end_text.strip())
        except Exception:
            continue

        low_mhz = min(start_mhz, end_mhz)
        high_mhz = max(start_mhz, end_mhz)

        ranges.append((low_mhz, high_mhz))

    return ranges


def _tsi_frequency_is_blacklisted(
    dashboard: QtCore.QObject,
    frequency_mhz: float,
) -> bool:
    try:
        frequency_mhz = float(frequency_mhz)
    except Exception:
        return False

    for start_mhz, end_mhz in _tsi_blacklist_ranges_mhz(dashboard):
        if start_mhz <= frequency_mhz <= end_mhz:
            return True

    return False


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_BlacklistAddClicked(dashboard: QtCore.QObject):
    """ 
    Adds frequency range for TSI to ignore to list widget and sends message to TSI.
    """
    start_text = str(dashboard.ui.textEdit_tsi_ignore_start.toPlainText()).strip()
    end_text = str(dashboard.ui.textEdit_tsi_ignore_end.toPlainText()).strip()

    try:
        start_freq = float(start_text)
        end_freq = float(end_text)
    except Exception:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Enter valid blacklist start and end frequencies in MHz.",
        )
        return

    if start_freq == end_freq:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Blacklist start and end frequencies cannot be the same.",
        )
        return

    low_freq = min(start_freq, end_freq)
    high_freq = max(start_freq, end_freq)

    item_text = f"{low_freq:g}-{high_freq:g}"

    for row in range(dashboard.ui.listWidget_tsi_blacklist.count()):
        existing = dashboard.ui.listWidget_tsi_blacklist.item(row)
        if existing is not None and existing.text() == item_text:
            return

    dashboard.ui.listWidget_tsi_blacklist.addItem(item_text)
    dashboard.ui.pushButton_tsi_blacklist_remove.setEnabled(True)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_BlacklistRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes frequency range item for TSI to ignore from the list widget and sends message to TSI.
    """
    current_item = dashboard.ui.listWidget_tsi_blacklist.currentItem()

    if current_item is None:
        return

    try:
        start_text, end_text = str(current_item.text()).split("-", 1)
        start_freq = float(start_text.strip())
        end_freq = float(end_text.strip())
    except Exception:
        dashboard.ui.listWidget_tsi_blacklist.takeItem(
            dashboard.ui.listWidget_tsi_blacklist.currentRow()
        )

        if dashboard.ui.listWidget_tsi_blacklist.count() == 0:
            dashboard.ui.pushButton_tsi_blacklist_remove.setEnabled(False)

        return

    dashboard.ui.listWidget_tsi_blacklist.takeItem(
        dashboard.ui.listWidget_tsi_blacklist.currentRow()
    )

    if dashboard.ui.listWidget_tsi_blacklist.count() == 0:
        dashboard.ui.pushButton_tsi_blacklist_remove.setEnabled(False)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_ConditionerOperationStartClicked(dashboard: QtCore.QObject):
    """ 
    Begins conditioning and isolating signals from a file or several files.
    """
    # Stop
    if dashboard.ui.pushButton_tsi_conditioner_operation_start.text() == "Stop":
        
        # Send the Message
        await dashboard.backend.stopTSI_Conditioner(dashboard.selected_node_uid)

        # Reset Progress Bar
        dashboard.ui.progressBar_tsi_conditioner_operation.setValue(0)
        
        # Toggle the Text
        dashboard.ui.pushButton_tsi_conditioner_operation_start.setText("Start")
                    
    # Start
    elif dashboard.ui.pushButton_tsi_conditioner_operation_start.text() == "Start": 
            
        # Reset Progress Bar
        dashboard.ui.progressBar_tsi_conditioner_operation.setValue(0)
        
        # Common GUI Parameters
        get_input_source = str(dashboard.ui.comboBox_tsi_conditioner_input_source.currentText())

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
            
            method_table = dashboard.ui.tableWidget_tsi_conditioner_settings_files
            get_category = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText())
            get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.currentText())
            get_hardware = "File"
        
        # Folder
        elif get_input_source == "Folder":
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
                
                method_table = dashboard.ui.tableWidget_tsi_conditioner_settings_files
                get_category = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentText())
                get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.currentText())
                get_hardware = "File"

            else:
                # fissure.Dashboard.UI_Components.Qt5.errorMessage("No input files found.")
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "No input files found.")
                return
        
        # Detector Results
        elif get_input_source == "Detector Results":
            method_table = dashboard.ui.tableWidget_tsi_conditioner_settings_files
            get_category = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_category.currentText())
            get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.currentText())
            get_hardware = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_hardware.currentText()).split(" - ")[0].strip()

        # Frequencies
        else:
            method_table = dashboard.ui.tableWidget_tsi_conditioner_settings_files
            get_category = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_category.currentText())
            get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.currentText())
            get_hardware = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_hardware.currentText()).split(" - ")[0].strip()

        # Ignore Empty Method
        if get_method == "None":
            ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Please choose a valid isolation method.")
            return

        # Collect Parameters from Database and Table
        get_row = fissure.utils.library.getConditionerRow(
            dashboard.backend.library, 
            get_method, 
            fissure.utils.get_library_version(), 
            get_hardware
        )
        method_parameter_names = get_row[7]
        method_filepath = get_row[10]
        method_parameter_values = []
        for n in range(0, method_table.rowCount()):
            method_parameter_values.append(str(method_table.item(n,0).text()))
            
        # Assemble
        common_parameter_names = ['category','method','output_directory','prefix','sample_rate','tuned_frequency','data_type','max_files','min_samples','all_filepaths','detect_saturation','saturation_min','saturation_max','normalize_output','normalize_min','normalize_max']
        common_parameter_values = [get_category,get_method,get_output_directory,get_prefix,get_sample_rate,get_tuned_freq,get_type,get_max_files,get_min_samples,get_all_filepaths,get_detect_saturation,get_saturation_min,get_saturation_max,get_normalize_output,get_normalize_min,get_normalize_max]

        # Toggle the Text
        dashboard.ui.pushButton_tsi_conditioner_operation_start.setText("Stop")

        # Start the Progress Bar
        dashboard.ui.progressBar_tsi_conditioner_operation.setValue(1)
        
        # Send the Message
        await dashboard.backend.startTSI_Conditioner(dashboard.selected_node_uid, common_parameter_names, common_parameter_values, method_parameter_names, method_parameter_values, method_filepath)


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
    if dashboard.backend.os_info == "Raspberry Pi OS":
        proc=subprocess.Popen('npm start', cwd="~/Installed_by_FISSURE/netron/", shell=True)
    else:
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
    if dashboard.backend.os_info == "Raspberry Pi OS":
        proc=subprocess.Popen('npm start', cwd="~/Installed_by_FISSURE/netron/", shell=True)
    else:
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
    if dashboard.backend.os_info == "Raspberry Pi OS":
        proc=subprocess.Popen('npm start', cwd="~/Installed_by_FISSURE/netron/", shell=True)
    else:
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


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SOI_AggregateClicked(dashboard: QtCore.QObject):
    """ 
    Collects information from the TSI Conditioner, Feature Extractor, and Classifier tabs and puts the results in a table.
    """
    print("START AGGREGATING")
    # Get IQ File Directory
    get_iq_dir = str(dashboard.ui.textEdit_tsi_soi_browse.toPlainText())
    if len(get_iq_dir) == 0:
        dashboard.logger.error("Enter a valid IQ file directory. Use the browse button to select a folder.")
        return
    if os.path.isdir(get_iq_dir) == False:
        dashboard.logger.error("Directory not found. Enter a valid IQ file directory.")
        return
    
    # Read Radiobuttons
    get_radiobutton_option = 0
    if dashboard.ui.radioButton_tsi_soi_iq_directory.isChecked():
        get_radiobutton_option = 0
    elif dashboard.ui.radioButton_tsi_soi_iq_fe_results.isChecked():
        get_radiobutton_option = 1
    elif dashboard.ui.radioButton_tsi_soi_iq_classifier_results.isChecked():
        get_radiobutton_option = 2 

    # Check for Files
    file_count = len([f for f in os.listdir(get_iq_dir) if os.path.isfile(os.path.join(get_iq_dir, f))])
    if file_count <= 0:
        dashboard.logger.warning("No IQ files found.")
        return

    # All Files
    get_filenames = []
    get_filepaths = []
    if get_radiobutton_option == 0:
        if file_count > 0:
            for filename in os.listdir(get_iq_dir):
                if os.path.isfile(os.path.join(get_iq_dir, filename)):
                    get_filenames.append(filename)
                    get_filepaths.append(os.path.join(get_iq_dir, filename))

    # Only F.E. Results Files
    elif get_radiobutton_option == 1:
        if file_count > 0:
            for filename in os.listdir(get_iq_dir):
                if os.path.isfile(os.path.join(get_iq_dir, filename)):
                    for m in range(0, dashboard.ui.tableWidget_tsi_fe_results.rowCount()):
                        get_table_filename_value = str(dashboard.ui.tableWidget_tsi_fe_results.verticalHeaderItem(m).text())
                        if get_table_filename_value == filename:
                            get_filenames.append(filename)
                            get_filepaths.append(os.path.join(get_iq_dir, filename))
                            break

    # Only Classifier Results Files
    elif get_radiobutton_option == 2:
        if file_count > 0:
            for filename in os.listdir(get_iq_dir):
                if os.path.isfile(os.path.join(get_iq_dir, filename)):
                    for m in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_confidence.rowCount()):
                        get_table_filename_value = str(dashboard.ui.tableWidget_tsi_classifier_classification_confidence.verticalHeaderItem(m).text())
                        if get_table_filename_value == filename:
                            get_filenames.append(filename)
                            get_filepaths.append(os.path.join(get_iq_dir, filename))
                            break

    # Sort Based on Filepath
    sorted_indices = sorted(range(len(get_filepaths)), key=lambda i: get_filepaths[i].lower())
    get_filenames = [get_filenames[i] for i in sorted_indices]
    get_filepaths = sorted(get_filepaths, key=str.lower)

    # Feature Extractor Results
    get_statistics = [""] * len(get_filenames)
    if dashboard.ui.checkBox_tsi_soi_settings_statistics.isChecked():
        for n in range(0, len(get_filenames)):
            for m in range(0, dashboard.ui.tableWidget_tsi_fe_results.rowCount()):
                get_table_filename_value = str(dashboard.ui.tableWidget_tsi_fe_results.verticalHeaderItem(m).text())
                if get_table_filename_value == get_filenames[n]:
                    statistics_item = {}
                    for k in range(0, dashboard.ui.tableWidget_tsi_fe_results.columnCount()):
                        get_header_text = str(dashboard.ui.tableWidget_tsi_fe_results.horizontalHeaderItem(k).text())
                        get_item_text = str(dashboard.ui.tableWidget_tsi_fe_results.item(m,k).text())
                        statistics_item[get_header_text] = get_item_text
                    get_statistics[n] = str(statistics_item)
                    break

    # Classifier Results
    get_classifications = [""] * len(get_filenames)
    if dashboard.ui.checkBox_tsi_soi_settings_classification.isChecked():
        for n in range(0, len(get_filenames)):
            for m in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_confidence.rowCount()):
                get_table_filename_value = str(dashboard.ui.tableWidget_tsi_classifier_classification_confidence.verticalHeaderItem(m).text())
                if get_table_filename_value == get_filenames[n]:
                    classification_item = {}
                    for k in range(0, dashboard.ui.tableWidget_tsi_classifier_classification_confidence.columnCount()):
                        get_header_text = str(dashboard.ui.tableWidget_tsi_classifier_classification_confidence.horizontalHeaderItem(k).text())
                        get_item_text = str(dashboard.ui.tableWidget_tsi_classifier_classification_confidence.item(m,k).text())
                        classification_item[get_header_text] = get_item_text
                    get_classifications[n] = str(classification_item)
                    break

    # Populate the Table
    dashboard.ui.tableWidget_tsi_soi_sois.setRowCount(0)
    for n in range(0, len(get_filenames)):
        # Add Row
        dashboard.ui.tableWidget_tsi_soi_sois.setRowCount(dashboard.ui.tableWidget_tsi_soi_sois.rowCount() + 1)
        
        # SOI Name
        soi_name_item = QtWidgets.QTableWidgetItem(get_filenames[n])
        soi_name_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_tsi_soi_sois.setItem(n,0,soi_name_item)

        # IQ Filepath
        if dashboard.ui.checkBox_tsi_soi_settings_iq_files.isChecked():
            iq_filepath_item = QtWidgets.QTableWidgetItem(get_filepaths[n])
        else:
            iq_filepath_item = QtWidgets.QTableWidgetItem("")
        dashboard.ui.tableWidget_tsi_soi_sois.setItem(n,1,iq_filepath_item)

        # Classification
        classification_table_item = QtWidgets.QTableWidgetItem(get_classifications[n])
        dashboard.ui.tableWidget_tsi_soi_sois.setItem(n,2,classification_table_item)

        # Statistics
        statistics_table_item = QtWidgets.QTableWidgetItem(get_statistics[n])
        dashboard.ui.tableWidget_tsi_soi_sois.setItem(n,3,statistics_table_item)

    # Enable PushButtons
    if dashboard.ui.tableWidget_tsi_soi_sois.rowCount() > 0:
        dashboard.ui.pushButton_tsi_soi_remove.setEnabled(True)
        dashboard.ui.pushButton_tsi_soi_remove_all.setEnabled(True)
        dashboard.ui.pushButton_tsi_soi_edit_statistics.setEnabled(True)
        dashboard.ui.pushButton_tsi_soi_pd_list.setEnabled(True)
        dashboard.ui.pushButton_tsi_soi_pd_list_all.setEnabled(True)
        dashboard.ui.pushButton_tsi_soi_library.setEnabled(True)
        dashboard.ui.pushButton_tsi_soi_library_all.setEnabled(True)

        # Resize Table Columns and Rows
        dashboard.ui.tableWidget_tsi_soi_sois.resizeColumnsToContents()
        dashboard.ui.tableWidget_tsi_soi_sois.resizeRowsToContents()
        dashboard.ui.tableWidget_tsi_soi_sois.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_tsi_soi_sois.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SOI_RemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row from the SOI Editor table.
    """
    # Remove from the TableWidget
    get_current_row = dashboard.ui.tableWidget_tsi_soi_sois.currentRow()
    dashboard.ui.tableWidget_tsi_soi_sois.removeRow(get_current_row)
    if get_current_row == 0:
        dashboard.ui.tableWidget_tsi_soi_sois.setCurrentCell(0,0)
    else:
        dashboard.ui.tableWidget_tsi_soi_sois.setCurrentCell(get_current_row-1,0)

    # Disable PushButtons
    if dashboard.ui.tableWidget_tsi_soi_sois.rowCount() < 1:
        dashboard.ui.pushButton_tsi_soi_remove.setEnabled(False)
        dashboard.ui.pushButton_tsi_soi_remove_all.setEnabled(False)
        dashboard.ui.pushButton_tsi_soi_edit_statistics.setEnabled(False)
        dashboard.ui.pushButton_tsi_soi_pd_list.setEnabled(False)
        dashboard.ui.pushButton_tsi_soi_pd_list_all.setEnabled(False)
        dashboard.ui.pushButton_tsi_soi_library.setEnabled(False)
        dashboard.ui.pushButton_tsi_soi_library_all.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SOI_RemoveAllClicked(dashboard: QtCore.QObject):
    """ 
    Removes all rows from the SOI Editor table.
    """
    # Remove all Rows
    dashboard.ui.tableWidget_tsi_soi_sois.setRowCount(0)

    # Disable PushButtons
    dashboard.ui.pushButton_tsi_soi_remove.setEnabled(False)
    dashboard.ui.pushButton_tsi_soi_remove_all.setEnabled(False)
    dashboard.ui.pushButton_tsi_soi_edit_statistics.setEnabled(False)
    dashboard.ui.pushButton_tsi_soi_pd_list.setEnabled(False)
    dashboard.ui.pushButton_tsi_soi_pd_list_all.setEnabled(False)
    dashboard.ui.pushButton_tsi_soi_library.setEnabled(False)
    dashboard.ui.pushButton_tsi_soi_library_all.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SOI_EditStatistics(dashboard: QtCore.QObject):
    """ 
    Opens a window to edit each statistical item individually.
    """
    pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SOI_PD_ListClicked(dashboard: QtCore.QObject):
    """ 
    Adds a single SOI to the Protocol Discovery SOI list.
    """
    pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SOI_PD_ListAllClicked(dashboard: QtCore.QObject):
    """ 
    Adds all SOIs in the SOI Editor table to the Protocol Discovery SOI list.
    """
    pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SOI_LibraryClicked(dashboard: QtCore.QObject):
    """ 
    Saves a single SOI to the FISSURE library.
    """
    pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SOI_LibraryAllClicked(dashboard: QtCore.QObject):
    """ 
    Saves all SOIs in the SOI Editor table to the FISSURE library.
    """
    pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SOI_SettingsIncludeIQ_FilesChecked(dashboard: QtCore.QObject):
    """ 
    Disables/enables widgets relating to including IQ files in the SOI Aggregator settings.
    """
    # Enabled
    if dashboard.ui.checkBox_tsi_soi_settings_iq_files.isChecked():
        dashboard.ui.label2_tsi_soi_iq_directory.setEnabled(True)
        dashboard.ui.pushButton_tsi_soi_browse.setEnabled(True)
        dashboard.ui.textEdit_tsi_soi_browse.setEnabled(True)
        dashboard.ui.radioButton_tsi_soi_iq_directory.setEnabled(True)
        dashboard.ui.radioButton_tsi_soi_iq_fe_results.setEnabled(True)
        dashboard.ui.radioButton_tsi_soi_iq_classifier_results.setEnabled(True)
        
    # Disabled
    else:
        dashboard.ui.label2_tsi_soi_iq_directory.setEnabled(False)
        dashboard.ui.pushButton_tsi_soi_browse.setEnabled(False)
        dashboard.ui.textEdit_tsi_soi_browse.setEnabled(False)
        dashboard.ui.radioButton_tsi_soi_iq_directory.setEnabled(False)
        dashboard.ui.radioButton_tsi_soi_iq_fe_results.setEnabled(False)
        dashboard.ui.radioButton_tsi_soi_iq_classifier_results.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_SOI_BrowseClicked(dashboard: QtCore.QObject):
    """ 
    Opens a dialog to choose an IQ file directory.
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    dialog.setFileMode(QtWidgets.QFileDialog.Directory)
    dialog.setOption(QtWidgets.QFileDialog.ShowDirsOnly, True)

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_tsi_soi_browse.setText(folder)           
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputDetectorClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the list of input frequencies for the conditioner.
    """
    # Remove All Rows
    dashboard.ui.tableWidget_tsi_conditioner_input_detector.setRowCount(0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputDetectorUpClicked(dashboard: QtCore.QObject):
    """ 
    Moves an input frequency up in the listbox.
    """
    current_row = dashboard.ui.tableWidget_tsi_conditioner_input_detector.currentRow()
    if current_row > 0:  # Ensure it isn't the topmost row
        # Swap all items in the current row with the row above it
        for column in range(dashboard.ui.tableWidget_tsi_conditioner_input_detector.columnCount()):
            current_item = dashboard.ui.tableWidget_tsi_conditioner_input_detector.takeItem(current_row, column)
            above_item = dashboard.ui.tableWidget_tsi_conditioner_input_detector.takeItem(current_row - 1, column)

            # Swap items
            dashboard.ui.tableWidget_tsi_conditioner_input_detector.setItem(current_row, column, above_item)
            dashboard.ui.tableWidget_tsi_conditioner_input_detector.setItem(current_row - 1, column, current_item)

        # Update the selected row
        dashboard.ui.tableWidget_tsi_conditioner_input_detector.setCurrentCell(current_row - 1, dashboard.ui.tableWidget_tsi_conditioner_input_detector.currentColumn())


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputDetectorDownClicked(dashboard: QtCore.QObject):
    """ 
    Moves an input frequency down in the listbox.
    """
    current_row = dashboard.ui.tableWidget_tsi_conditioner_input_detector.currentRow()
    if current_row < dashboard.ui.tableWidget_tsi_conditioner_input_detector.rowCount() - 1:  # Ensure it isn't the bottommost row
        # Swap all items in the current row with the row below it
        for column in range(dashboard.ui.tableWidget_tsi_conditioner_input_detector.columnCount()):
            current_item = dashboard.ui.tableWidget_tsi_conditioner_input_detector.takeItem(current_row, column)
            below_item = dashboard.ui.tableWidget_tsi_conditioner_input_detector.takeItem(current_row + 1, column)

            # Swap items
            dashboard.ui.tableWidget_tsi_conditioner_input_detector.setItem(current_row, column, below_item)
            dashboard.ui.tableWidget_tsi_conditioner_input_detector.setItem(current_row + 1, column, current_item)

        # Update the selected row
        dashboard.ui.tableWidget_tsi_conditioner_input_detector.setCurrentCell(current_row + 1, dashboard.ui.tableWidget_tsi_conditioner_input_detector.currentColumn())    


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputDetectorRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes an input frequency for the conditioner.
    """    
    current_row = dashboard.ui.tableWidget_tsi_conditioner_input_detector.currentRow()

    if current_row == -1:  # No row is selected
        return

    # Remove the current row
    dashboard.ui.tableWidget_tsi_conditioner_input_detector.removeRow(current_row)

    # Determine the next row to select
    if dashboard.ui.tableWidget_tsi_conditioner_input_detector.rowCount() == 0:  # Table is empty
        return
    elif current_row < dashboard.ui.tableWidget_tsi_conditioner_input_detector.rowCount():  # Select the row at the same index
        dashboard.ui.tableWidget_tsi_conditioner_input_detector.selectRow(current_row)
    else:  # Select the last row if the current row was the last one
        dashboard.ui.tableWidget_tsi_conditioner_input_detector.selectRow(dashboard.ui.tableWidget_tsi_conditioner_input_detector.rowCount() - 1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsIsolationFrequenciesCategoryChanged(dashboard: QtCore.QObject):
    """ 
    Updates the isolation methods after changing the category.
    """   
    # Get Category
    get_category = dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_category.currentText()
    get_hardware = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_hardware.currentText()).split(" - ")[0].strip()

    # Get Methods
    get_methods = fissure.utils.library.getConditionerIsolationMethod(
        dashboard.backend.library, 
        get_category, 
        fissure.utils.get_library_version(),
        get_hardware
    )
    dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.clear()

    # Exclude Certain Items
    item_to_remove = "Strongest Frequency then Bandpass"  # Need to convert two-stage method to one
    if item_to_remove in get_methods:
        get_methods.remove(item_to_remove)

    # Energy - Burst Tagger
    if get_category == "Energy - Burst Tagger":
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.addItems(get_methods)

    # Energy - Imagery
    elif get_category == "Energy - Imagery":
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.addItems(methods)
    
    # Eigenvalue
    elif get_category == "Eigenvalue":
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.addItems(methods)
    
    # Matched Filter
    elif get_category == "Matched Filter":
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.addItems(methods)
    
    # Cyclostationary
    elif get_category == "Cyclostationary":
        methods = ['None']
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.addItems(methods)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsIsolationFrequenciesMethodChanged(dashboard: QtCore.QObject):
    """ 
    Updates the method input parameters after changing the method.
    """   
    # Retrieve Table Values
    get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.currentText())
    get_hardware = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_hardware.currentText()).split(" - ")[0].strip()

    if len(get_hardware) > 0:
        # Search Database Cache
        get_row = fissure.utils.library.getConditionerRow(
            dashboard.backend.library, 
            get_method, 
            fissure.utils.get_library_version(), 
            get_hardware
        )

        if get_row == None:
            get_parameter_labels = []
            get_parameter_values = []
        else:
            get_parameter_labels = get_row[9]
            get_parameter_values = get_row[8]

        # Clear Table
        dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.setColumnCount(1)
        dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.setRowCount(0)
        dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.clearContents()

        # Fill Table
        for n in range(0, len(get_parameter_labels)):
            label_item = QtWidgets.QTableWidgetItem(get_parameter_labels[n])
            value_item = QtWidgets.QTableWidgetItem(get_parameter_values[n])
            dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.setRowCount(dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.rowCount()+1)
            dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.setVerticalHeaderItem(dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.rowCount()-1, label_item)
            dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.setItem(dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.rowCount()-1, 0, value_item)

        # Resize Table
        dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.resizeColumnsToContents()
        dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.resizeRowsToContents()
        dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget_tsi_conditioner_settings_frequencies.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsFrequenciesViewClicked(dashboard: QtCore.QObject):
    """ 
    Opens visualization (GNU Radio Companion flow graph, image, code) for the isolation technique.
    """
    # Gather Details
    get_category = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_category.currentText())
    get_method = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.currentText())
    get_type = "Complex Float 32"  # Support other types eventually? Ignore checks for this?
    get_hardware = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_hardware.currentText()).split(" - ")[0].strip()

    if get_method == "None":
        return

    # Retrieve Filepath and File Type
    get_filepath, get_file_type = fissure.utils.library.getConditionerFilepath(
        dashboard.backend.library, 
        get_category, 
        get_method,
        get_hardware,
        get_type,
        fissure.utils.get_library_version()
    )

    # Open File
    if get_filepath:
        fg_directory = os.path.join(fissure.utils.get_fg_library_dir(dashboard.backend.os_info), "TSI Flow Graphs", "Conditioner", get_filepath)
        if get_file_type == "Flow Graph":
            fg_directory = fg_directory.replace(".py", ".grc")
            osCommandString = 'gnuradio-companion "' + fg_directory + '"'
            try:
                os.system(osCommandString + ' &')
            except Exception as e:
                dashboard.logger.error(f"Could not open Conditioner flow graph with command: {osCommandString}. Error: {e}")
        else:
            dashboard.logger.error("Unknown file type")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the list of input frequencies for the conditioner.
    """
    # Remove All Rows
    dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.setRowCount(0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesUpClicked(dashboard: QtCore.QObject):
    """ 
    Moves an input frequency up in the listbox.
    """
    current_row = dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.currentRow()
    if current_row > 0:  # Ensure it isn't the topmost row
        # Swap all items in the current row with the row above it
        for column in range(dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.columnCount()):
            current_item = dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.takeItem(current_row, column)
            above_item = dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.takeItem(current_row - 1, column)

            # Swap items
            dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.setItem(current_row, column, above_item)
            dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.setItem(current_row - 1, column, current_item)

        # Update the selected row
        dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.setCurrentCell(current_row - 1, dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.currentColumn())


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesDownClicked(dashboard: QtCore.QObject):
    """ 
    Moves an input frequency down in the listbox.
    """
    current_row = dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.currentRow()
    if current_row < dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.rowCount() - 1:  # Ensure it isn't the bottommost row
        # Swap all items in the current row with the row below it
        for column in range(dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.columnCount()):
            current_item = dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.takeItem(current_row, column)
            below_item = dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.takeItem(current_row + 1, column)

            # Swap items
            dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.setItem(current_row, column, below_item)
            dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.setItem(current_row + 1, column, current_item)

        # Update the selected row
        dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.setCurrentCell(current_row + 1, dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.currentColumn())    


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerInputFrequenciesRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes an input frequency for the conditioner.
    """    
    current_row = dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.currentRow()

    if current_row == -1:  # No row is selected
        return

    # Remove the current row
    dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.removeRow(current_row)

    # Determine the next row to select
    if dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.rowCount() == 0:  # Table is empty
        return
    elif current_row < dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.rowCount():  # Select the row at the same index
        dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.selectRow(current_row)
    else:  # Select the last row if the current row was the last one
        dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.selectRow(dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.rowCount() - 1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsFrequenciesAddClicked(dashboard: QtCore.QObject):
    """ 
    Adds a new row to the frequencies table.
    """    
    current_row = dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.currentRow()

    # Determine where to insert the new row
    if current_row == -1:  # No row is selected
        insert_position = dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.rowCount()  # Add to the end
    else:
        insert_position = current_row + 1  # Insert after the selected row

    # Insert the new row
    dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.insertRow(insert_position)

    # Initialize the new row with empty items
    freq_item = QtWidgets.QTableWidgetItem("")
    freq_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.setItem(insert_position, 0, freq_item)
    dwell_item = QtWidgets.QTableWidgetItem("10")
    dwell_item.setTextAlignment(QtCore.Qt.AlignCenter)
    dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.setItem(insert_position, 1, dwell_item)

    # Resize the Table
    dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.resizeRowsToContents()
    dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.resizeColumnsToContents()
    dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.horizontalHeader().setStretchLastSection(True)

    # Select the newly inserted row
    dashboard.ui.tableWidget_tsi_conditioner_input_frequencies.setCurrentCell(insert_position, 0)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotTSI_ConditionerSettingsIsolationFrequenciesHardwareChanged(dashboard: QtCore.QObject):
    """ 
    Updates available isolation categories and methods based on selected hardware.
    """
    # Clear the Isolation Categories and Methods
    dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_category.blockSignals(True)
    dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.blockSignals(True)
    dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_category.clear()
    dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.clear()

    # Update Categories
    get_hardware = str(dashboard.ui.comboBox_tsi_conditioner_settings_isolation_hardware.currentText()).split(" - ")[0].strip()
    if get_hardware:
        get_categories = fissure.utils.library.getConditionerIsolationCategory(
            dashboard.backend.library, 
            get_hardware, 
            fissure.utils.get_library_version()
        )
        dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_category.addItems(get_categories)

    # Unblock
    dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_category.blockSignals(False)
    dashboard.ui.comboBox_tsi_conditioner_settings_isolation_frequencies_method.blockSignals(False)

    # Update Methods
    _slotTSI_ConditionerSettingsIsolationFrequenciesCategoryChanged(dashboard)


def _set_spinbox_value_blocked(widget, value):
    widget.blockSignals(True)
    widget.setValue(float(value))
    widget.blockSignals(False)


def append_tsi_active_detector_detection_from_cot(
    dashboard: QtCore.QObject,
    cot_message: dict,
):
    """
    Routes CoT detections into the shared TSI detector workbench.

    Unified, Sweep, and Fixed share:
        - detector results table
        - conditioner detector input table
        - detector plot/raster area
        - blacklist filtering

    Unified detector mode is plugin/action generic. It does not maintain a
    Dashboard-side detector allowlist.
    """
    if not cot_message:
        return

    if cot_message.get("kind") != "detection":
        return

    unified_running = bool(
        getattr(dashboard, "tsi_detector_running", False)
    )

    if not unified_running:
        return

    _append_tsi_detector_detection_from_cot(
        dashboard,
        cot_message,
        allowed_detectors=None,
        active_node_uid=getattr(dashboard, "tsi_detector_node_uid", ""),
        active_opid_attr="tsi_detector_opid",
        waiting_opid_attr="tsi_detector_waiting_for_opid",
    )


def _append_tsi_detector_detection_from_cot(
    dashboard: QtCore.QObject,
    cot_message: dict,
    allowed_detectors: set = None,
    active_node_uid: str = "",
    active_opid_attr: str = "",
    waiting_opid_attr: str = "",
):
    """
    Append one parsed CoT detection into the shared TSI detector table/plot.

    If allowed_detectors is None or empty, detector-name filtering is skipped.
    That is required for the unified detector workflow.
    """
    allowed_detectors = allowed_detectors or set()

    detector_name = str(
        cot_message.get("detection_detector") or ""
    ).strip()

    if allowed_detectors and detector_name not in allowed_detectors:
        return

    detection_node_uid = str(
        cot_message.get("detection_node_uid") or ""
    ).strip()

    active_node_uid = str(active_node_uid or "").strip()

    if active_node_uid and detection_node_uid and detection_node_uid != active_node_uid:
        return

    detection_opid = str(
        cot_message.get("detection_opid") or ""
    ).strip()

    if not detection_opid:
        return

    active_opid = str(
        getattr(dashboard, active_opid_attr, "") or ""
    ).strip()

    if active_opid:
        if detection_opid != active_opid:
            return
    else:
        setattr(dashboard, active_opid_attr, detection_opid)
        setattr(dashboard, waiting_opid_attr, False)

    try:
        frequency_hz = float(cot_message.get("detection_frequency_hz"))
        frequency_mhz = frequency_hz / 1e6
    except Exception:
        dashboard.logger.debug(
            f"[TSI Detector] Ignoring detection with invalid frequency: {cot_message}"
        )
        return

    if _tsi_frequency_is_blacklisted(dashboard, frequency_mhz):
        dashboard.logger.debug(
            f"Ignoring blacklisted TSI detection: {frequency_mhz} MHz"
        )
        return

    try:
        power_value = float(cot_message.get("detection_power_dbm"))
    except Exception:
        power_value = 0.0

    try:
        time_value = float(cot_message.get("detection_timestamp"))
    except Exception:
        time_value = time.time()

    try:
        _tsi_detector_plot_add_detection(
            dashboard,
            frequency_mhz=frequency_mhz,
            power_dbm=power_value,
            timestamp_s=time_value,
        )
    except Exception as e:
        dashboard.logger.debug(
            f"Could not add TSI detection to shared plot: {e}"
        )

    get_time = time.strftime("%H:%M:%S", time.localtime(time_value))
    time_obj = QtCore.QTime.fromString(get_time, "HH:mm:ss")

    for table in _tsi_detector_results_tables(dashboard):
        row = table.rowCount()
        table.setRowCount(row + 1)

        frequency_item = QtWidgets.QTableWidgetItem(f"{frequency_mhz:.6f}")
        frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
        frequency_item.setData(QtCore.Qt.UserRole, cot_message)
        frequency_item.setData(QtCore.Qt.UserRole + 1, detection_opid)
        table.setItem(row, 0, frequency_item)

        power_item = QtWidgets.QTableWidgetItem(f"{power_value:.1f}")
        power_item.setTextAlignment(QtCore.Qt.AlignCenter)
        power_item.setData(QtCore.Qt.UserRole, cot_message)
        power_item.setData(QtCore.Qt.UserRole + 1, detection_opid)
        table.setItem(row, 1, power_item)

        time_item = QtWidgets.QTableWidgetItem(get_time)
        time_item.setTextAlignment(QtCore.Qt.AlignCenter)
        time_item.setData(QtCore.Qt.UserRole, time_obj.msecsSinceStartOfDay())
        time_item.setData(QtCore.Qt.UserRole + 1, detection_opid)
        time_item.setData(QtCore.Qt.UserRole + 2, cot_message)
        table.setItem(row, 2, time_item)

        table.sortItems(2, order=QtCore.Qt.DescendingOrder)
        table.resizeColumnsToContents()
        table.resizeRowsToContents()
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setStretchLastSection(True)


def _tsi_detector_plot_initial_xlim(dashboard: QtCore.QObject):
    """
    Returns initial x-axis limits for the unified TSI detector plot.

    Primary method:
      - infer configured plot range from detector parameter names/values.

    Fallback:
      - return 0-1 MHz if no useful frequency/range parameters are found.
        _tsi_detector_plot_data_xlim() will later replace this fallback with
        data-centered limits once real detections arrive.
    """
    params = collect_tsi_detector_parameters(dashboard)

    center_mhz = None
    sample_rate_hz = None
    start_mhz = None
    stop_mhz = None

    center_frequency_keys = {
        "frequency",
        "freq",
        "freq_mhz",
        "frequency_mhz",
        "center_frequency",
        "center_frequency_mhz",
        "center_freq",
        "center_freq_mhz",
        "rx_freq",
        "rx_frequency",
        "rx_frequency_mhz",
        "tuned_freq",
        "tuned_frequency",
        "tuned_frequency_mhz",
    }

    sample_rate_keys = {
        "sample_rate",
        "samp_rate",
        "sample_rate_hz",
        "rx_sample_rate",
        "rx_sample_rate_hz",
    }

    start_frequency_keys = {
        "start_frequency",
        "start_frequency_mhz",
        "start_freq",
        "start_freq_mhz",
        "start_mhz",
        "custom_start_mhz",
        "frequency_min",
        "frequency_min_mhz",
        "min_frequency",
        "min_frequency_mhz",
        "low_frequency",
        "low_frequency_mhz",
        "low_mhz",
    }

    stop_frequency_keys = {
        "stop_frequency",
        "stop_frequency_mhz",
        "stop_freq",
        "stop_freq_mhz",
        "stop_mhz",
        "end_frequency",
        "end_frequency_mhz",
        "end_freq",
        "end_freq_mhz",
        "end_mhz",
        "custom_end_mhz",
        "frequency_max",
        "frequency_max_mhz",
        "max_frequency",
        "max_frequency_mhz",
        "high_frequency",
        "high_frequency_mhz",
        "high_mhz",
    }

    range_keys = {
        "band_range_mhz",
        "segment_range_mhz",
        "range_mhz",
        "frequency_range_mhz",
        "scan_range_mhz",
    }

    for key, value in params.items():
        key_l = str(key).strip().lower()

        try:
            numeric_value = float(value)
        except Exception:
            numeric_value = None

        if key_l in center_frequency_keys and numeric_value is not None:
            center_mhz = numeric_value

        elif key_l in sample_rate_keys and numeric_value is not None:
            sample_rate_hz = numeric_value

        elif key_l in start_frequency_keys and numeric_value is not None:
            start_mhz = numeric_value

        elif key_l in stop_frequency_keys and numeric_value is not None:
            stop_mhz = numeric_value

        elif key_l in range_keys:
            try:
                text = str(value).strip()
                text = text.replace("MHz", "").replace("mhz", "")
                text = text.replace("–", "-").replace("—", "-")

                low_text, high_text = text.split("-", 1)
                start_mhz = float(low_text.strip())
                stop_mhz = float(high_text.strip())
            except Exception:
                pass

    # Sweep/range-style detector.
    if start_mhz is not None and stop_mhz is not None:
        x_low = min(start_mhz, stop_mhz)
        x_high = max(start_mhz, stop_mhz)

        if abs(x_high - x_low) < 1e-9:
            return x_low - 0.5, x_high + 0.5

        x_pad = max(0.05, (x_high - x_low) * 0.05)
        return x_low - x_pad, x_high + x_pad

    # Fixed/center-frequency detector.
    if center_mhz is not None:
        if sample_rate_hz is not None:
            half_bw_mhz = max(0.5, (sample_rate_hz / 1e6) / 2.0)
        else:
            half_bw_mhz = 0.5

        return center_mhz - half_bw_mhz, center_mhz + half_bw_mhz

    # Meaningless fallback. Data autoscale will replace this once detections arrive.
    return 0.0, 1.0


def _tsi_detector_plot_data_xlim(
    dashboard: QtCore.QObject,
    freqs=None,
):
    """
    Returns x-axis limits for the unified detector plot.

    Data-first behavior:
      - If detections exist, scale to observed detector data.
      - If no detections exist, use configured detector parameters.
      - If no configured detector range is available, use 0-1 MHz fallback.

    This lets the plot follow live retunes, e.g. starting at 915 MHz and later
    moving to 310 MHz without keeping 915 MHz in view forever.
    """
    if freqs is None:
        freqs = []

    clean_freqs = []
    for freq in freqs:
        try:
            clean_freqs.append(float(freq))
        except Exception:
            pass

    if clean_freqs:
        data_low = min(clean_freqs)
        data_high = max(clean_freqs)

        if abs(data_high - data_low) < 1e-9:
            data_pad = 0.5
        else:
            data_pad = max(0.05, (data_high - data_low) * 0.08)

        return data_low - data_pad, data_high + data_pad

    initial_low = getattr(
        dashboard,
        "tsi_detector_plot_initial_xlim_low",
        None,
    )
    initial_high = getattr(
        dashboard,
        "tsi_detector_plot_initial_xlim_high",
        None,
    )

    if initial_low is None or initial_high is None:
        initial_low, initial_high = _tsi_detector_plot_initial_xlim(dashboard)
        dashboard.tsi_detector_plot_initial_xlim_low = initial_low
        dashboard.tsi_detector_plot_initial_xlim_high = initial_high

    try:
        return float(initial_low), float(initial_high)
    except Exception:
        return 0.0, 1.0


def handle_tsi_detector_action_query_results(
    dashboard: QtCore.QObject,
    node_uid: str,
    context: str,
    actions: list,
):
    """
    Populate the unified TSI Detector Method combobox from generic
    filtered plugin-action query results.
    """
    combo = dashboard.ui.comboBox_tsi_detector_method

    dashboard.tsi_detector_method_actions = actions or []

    combo.blockSignals(True)
    combo.clear()

    for action_record in dashboard.tsi_detector_method_actions:
        plugin_name = str(action_record.get("plugin", "")).strip()
        action_name = str(action_record.get("action", "")).strip()

        if not plugin_name or not action_name:
            continue

        combo.addItem(
            f"{plugin_name}: {action_name}",
            {
                "plugin": plugin_name,
                "action": action_name,
            },
        )

    combo.blockSignals(False)

    has_actions = combo.count() > 0

    combo.setEnabled(has_actions)
    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(has_actions)
    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)

    if has_actions:
        combo.setCurrentIndex(0)
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Customize this method to load its parameters and details."
        )
    else:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "No matching detector actions are available for the selected node, type, mode, and hardware."
        )


def _tsi_detector_current_combo_data(combo, fallback=""):
    data = combo.currentData()

    if data is not None and str(data).strip():
        return str(data).strip()

    text = combo.currentText().strip().lower()
    return text or fallback


def _tsi_detector_selected_type(dashboard: QtCore.QObject) -> str:
    return _tsi_detector_current_combo_data(
        dashboard.ui.comboBox_tsi_detector_type,
        "rf",
    )


def _tsi_detector_selected_mode(dashboard: QtCore.QObject) -> str:
    return _tsi_detector_current_combo_data(
        dashboard.ui.comboBox_tsi_detector_mode,
        "sweep",
    )


def _tsi_detector_selected_hardware(dashboard: QtCore.QObject) -> str:
    return dashboard.ui.comboBox_tsi_detector_hardware.currentText().strip()


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_DetectorQueryClicked(dashboard: QtCore.QObject):
    uid = getattr(dashboard, "selected_node_uid", "").strip()

    if not uid:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a sensor node before querying detector methods."
        )
        return

    detector_type = _tsi_detector_selected_type(dashboard)
    detector_mode = _tsi_detector_selected_mode(dashboard)
    hardware = _tsi_detector_selected_hardware(dashboard)

    include_tags = [
        "tsi.detector",
        f"tsi.detector.type.{detector_type}",
        f"tsi.detector.mode.{detector_mode}",
    ]

    context = f"tsi.detector.{detector_type}.{detector_mode}"

    dashboard.ui.comboBox_tsi_detector_method.clear()
    dashboard.ui.comboBox_tsi_detector_method.setEnabled(False)
    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)
    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)
    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Querying selected node for matching detector actions..."
    )

    await dashboard.backend.queryPluginActions(
        uid=uid,
        context=context,
        scope="all_plugins",
        plugin_name="",
        include_tags=include_tags,
        exclude_tags=[],
        hardware=hardware,
    )


def initialize_tsi_detector_controls(dashboard: QtCore.QObject):
    """
    Initialize the unified TSI Detector controls.
    Safe to call more than once.
    """
    dashboard.tsi_detector_method_actions = []
    dashboard.tsi_detector_selected_plugin = ""
    dashboard.tsi_detector_selected_action = ""
    dashboard.tsi_detector_action_schema_cache = getattr(
        dashboard,
        "tsi_detector_action_schema_cache",
        {},
    )

    dashboard.tsi_detector_parameter_widgets = {}
    dashboard.tsi_detector_current_schema = {}
    dashboard.tsi_detector_customized = False

    dashboard.tsi_detector_running = False
    dashboard.tsi_detector_node_uid = ""
    dashboard.tsi_detector_opid = ""
    dashboard.tsi_detector_waiting_for_opid = False

    # These are static filters. Always populate them regardless of node state.
    _populate_tsi_detector_type_combo(dashboard)
    _populate_tsi_detector_mode_combo(dashboard)

    dashboard.ui.comboBox_tsi_detector_type.setEnabled(True)
    dashboard.ui.comboBox_tsi_detector_mode.setEnabled(True)

    clear_tsi_detector_methods(dashboard)
    clear_tsi_detector_parameter_controls(dashboard)

    dashboard.ui.pushButton_tsi_detector_query.setText("Query")
    dashboard.ui.pushButton_tsi_detector_query.setToolTip(
        "Query the selected node for detector methods matching the selected type, mode, and hardware."
    )

    dashboard.ui.pushButton_tsi_detector_customize.setText("Customize")
    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)
    dashboard.ui.pushButton_tsi_detector_customize.setToolTip(
        "Load and customize parameters for the selected detector method."
    )

    _tsi_detector_set_start_stop_button(dashboard, False)
    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)

    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Select a detector method to view details."
    )
    dashboard.ui.label2_tsi_detector_status.setText("Idle")

    dashboard.ui.scrollArea_tsi_detector_parameters.setHorizontalScrollBarPolicy(
        QtCore.Qt.ScrollBarAlwaysOff
    )
    dashboard.ui.scrollArea_tsi_detector_parameters.setVerticalScrollBarPolicy(
        QtCore.Qt.ScrollBarAsNeeded
    )

    update_tsi_detector_selected_node_gate(dashboard)


def _populate_tsi_detector_type_combo(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_tsi_detector_type
    current_data = combo.currentData()

    combo.blockSignals(True)
    combo.clear()

    for value, label in TSI_DETECTOR_TYPES:
        combo.addItem(label, value)

    restore_index = combo.findData(current_data)
    if restore_index >= 0:
        combo.setCurrentIndex(restore_index)
    else:
        combo.setCurrentIndex(combo.findData("rf"))

    combo.blockSignals(False)


def _populate_tsi_detector_mode_combo(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_tsi_detector_mode
    current_data = combo.currentData()

    combo.blockSignals(True)
    combo.clear()

    for value, label in TSI_DETECTOR_MODES:
        combo.addItem(label, value)

    restore_index = combo.findData(current_data)
    if restore_index >= 0:
        combo.setCurrentIndex(restore_index)
    else:
        combo.setCurrentIndex(combo.findData("sweep"))

    combo.blockSignals(False)


def update_tsi_detector_hardware_combo(dashboard: QtCore.QObject):
    """
    Populate unified Detector hardware from selected-node TSI hardware.
    """
    combo = dashboard.ui.comboBox_tsi_detector_hardware
    current_hardware = combo.currentText().strip()

    combo.blockSignals(True)
    combo.clear()

    if getattr(dashboard, "selected_node_uid", ""):
        try:
            hardware_names = fissure.utils.hardware.selectedNodeHardwareDisplayNames(
                dashboard,
                "tsi",
            )
        except Exception as e:
            dashboard.logger.debug(
                f"[TSI Detector] Could not get selected-node hardware: {e}"
            )
            hardware_names = []

        combo.addItems(hardware_names)

        if current_hardware and combo.findText(current_hardware) >= 0:
            combo.setCurrentText(current_hardware)
        elif combo.count() > 0:
            combo.setCurrentIndex(0)

    combo.blockSignals(False)

    has_node = bool(getattr(dashboard, "selected_node_uid", ""))
    has_hardware = combo.count() > 0

    combo.setEnabled(has_node and has_hardware)
    dashboard.ui.comboBox_tsi_detector_type.setEnabled(True)
    dashboard.ui.comboBox_tsi_detector_mode.setEnabled(True)
    dashboard.ui.pushButton_tsi_detector_query.setEnabled(has_node and has_hardware)


def clear_tsi_detector_methods(dashboard: QtCore.QObject):
    combo = dashboard.ui.comboBox_tsi_detector_method

    combo.blockSignals(True)
    combo.clear()
    combo.blockSignals(False)

    combo.setEnabled(False)
    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)

    dashboard.tsi_detector_method_actions = []
    dashboard.tsi_detector_selected_plugin = ""
    dashboard.tsi_detector_selected_action = ""

    clear_tsi_detector_parameter_controls(dashboard)


def _slotTSI_DetectorTypeChanged(dashboard: QtCore.QObject):
    clear_tsi_detector_methods(dashboard)
    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Query matching detector methods for the selected type, mode, and hardware."
    )


def _slotTSI_DetectorModeChanged(dashboard: QtCore.QObject):
    clear_tsi_detector_methods(dashboard)
    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Query matching detector methods for the selected type, mode, and hardware."
    )


def _slotTSI_DetectorHardwareChanged(dashboard: QtCore.QObject):
    clear_tsi_detector_methods(dashboard)
    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Query matching detector methods for the selected type, mode, and hardware."
    )


def reset_tsi_detector_customization(dashboard: QtCore.QObject):
    """
    Reset Card 2 after method/type/mode/hardware changes.
    """
    clear_tsi_detector_parameter_controls(dashboard)

    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)

    if dashboard.ui.comboBox_tsi_detector_method.count() > 0:
        dashboard.ui.pushButton_tsi_detector_customize.setEnabled(True)
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Customize this method to load its parameters and details."
        )
    else:
        dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)


def _slotTSI_DetectorMethodChanged(dashboard: QtCore.QObject):
    record = dashboard.ui.comboBox_tsi_detector_method.currentData()

    clear_tsi_detector_parameter_controls(dashboard)

    if not isinstance(record, dict):
        dashboard.tsi_detector_selected_plugin = ""
        dashboard.tsi_detector_selected_action = ""
        dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)
        dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a detector method to view details."
        )
        return

    plugin_name = str(record.get("plugin", "")).strip()
    action_name = str(record.get("action", "")).strip()

    dashboard.tsi_detector_selected_plugin = plugin_name
    dashboard.tsi_detector_selected_action = action_name

    has_method = bool(plugin_name and action_name)

    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(has_method)
    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)

    if has_method:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Customize this method to load its parameters and details."
        )
    else:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a detector method to view details."
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_DetectorCustomizeClicked(dashboard: QtCore.QObject):
    """
    Query the selected node for the selected detector action schema and render
    Card 2 when the result returns.
    """
    uid = getattr(dashboard, "selected_node_uid", "").strip()
    record = dashboard.ui.comboBox_tsi_detector_method.currentData()

    if not uid:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a sensor node before customizing detector parameters."
        )
        return

    if not isinstance(record, dict):
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a detector method before customizing parameters."
        )
        return

    plugin_name = str(record.get("plugin", "")).strip()
    action_name = str(record.get("action", "")).strip()

    if not plugin_name or not action_name:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Selected detector method is missing plugin/action information."
        )
        return

    dashboard.tsi_detector_customized = False
    dashboard.tsi_detector_selected_plugin = plugin_name
    dashboard.tsi_detector_selected_action = action_name

    clear_tsi_detector_parameter_controls(dashboard)

    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(False)
    dashboard.ui.pushButton_tsi_detector_customize.setText("Loading...")
    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)
    dashboard.ui.label_tsi_detector_setup_info.setText(
        "Loading detector parameters..."
    )

    await dashboard.backend.queryPluginActionSchema(
        uid=uid,
        plugin_name=plugin_name,
        action_name=action_name,
        context="tsi.detector",
    )


def handle_tsi_detector_action_schema(
    dashboard: QtCore.QObject,
    plugin_name: str,
    action_name: str,
    node_uid: str,
    parameters: list,
):
    """
    Render Card 2 dynamic detector parameters from a Dashboard-only action
    schema result.
    """
    parameters = parameters or []

    selected_record = dashboard.ui.comboBox_tsi_detector_method.currentData()

    selected_plugin = ""
    selected_action = ""

    if isinstance(selected_record, dict):
        selected_plugin = str(selected_record.get("plugin", "")).strip()
        selected_action = str(selected_record.get("action", "")).strip()

    plugin_name = str(plugin_name or "").strip()
    action_name = str(action_name or "").strip()

    # Ignore stale schema responses after a method change.
    if selected_plugin != plugin_name or selected_action != action_name:
        dashboard.logger.debug(
            f"[TSI Detector] Ignoring stale schema for "
            f"{plugin_name}.{action_name}; "
            f"selected={selected_plugin}.{selected_action}"
        )

        dashboard.tsi_detector_customized = False

        dashboard.ui.pushButton_tsi_detector_customize.setText("Customize")
        dashboard.ui.pushButton_tsi_detector_customize.setEnabled(
            bool(selected_plugin and selected_action)
        )

        _tsi_detector_set_start_stop_button(dashboard, False)
        dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(False)
        return

    clear_tsi_detector_parameter_controls(dashboard)

    # These are what the Start slot needs.
    dashboard.tsi_detector_selected_plugin = plugin_name
    dashboard.tsi_detector_selected_action = action_name

    dashboard.tsi_detector_current_schema = {
        "plugin": plugin_name,
        "action": action_name,
        "node_uid": node_uid,
        "params": parameters,
    }

    dashboard.tsi_detector_parameter_widgets = {}

    _render_tsi_detector_parameter_widgets(
        dashboard,
        parameters,
    )

    dashboard.tsi_detector_customized = True

    description = _tsi_detector_schema_description(parameters)

    if description:
        dashboard.ui.label_tsi_detector_setup_info.setText(description)
    else:
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Detector parameters loaded. Review settings before starting."
        )

    dashboard.ui.pushButton_tsi_detector_customize.setText("Customize")
    dashboard.ui.pushButton_tsi_detector_customize.setEnabled(True)

    _tsi_detector_set_start_stop_button(dashboard, False)
    _tsi_detector_set_card3_enabled(dashboard, True)

    if getattr(dashboard, "selected_node_uid", ""):
        _tsi_detector_set_status_text(dashboard, "Idle")
    else:
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")


def clear_tsi_detector_parameter_controls(dashboard: QtCore.QObject):
    """
    Clear Card 2 dynamic parameter widgets.
    """
    contents = dashboard.ui.scrollAreaWidgetContents_tsi_detector_parameters

    layout = contents.layout()
    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    while layout.count():
        item = layout.takeAt(0)

        widget = item.widget()
        if widget is not None:
            widget.deleteLater()

        child_layout = item.layout()
        if child_layout is not None:
            while child_layout.count():
                child_item = child_layout.takeAt(0)
                child_widget = child_item.widget()
                if child_widget is not None:
                    child_widget.deleteLater()

    layout.setContentsMargins(12, 10, 12, 10)
    layout.setHorizontalSpacing(8)
    layout.setVerticalSpacing(7)

    for col in range(0, 8):
        layout.setColumnStretch(col, 0)
        layout.setColumnMinimumWidth(col, 0)

    contents.setMinimumWidth(0)
    contents.setMaximumWidth(390)

    dashboard.ui.scrollArea_tsi_detector_parameters.setWidgetResizable(True)
    dashboard.ui.scrollArea_tsi_detector_parameters.setAlignment(
        QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop
    )
    dashboard.ui.scrollArea_tsi_detector_parameters.setHorizontalScrollBarPolicy(
        QtCore.Qt.ScrollBarAlwaysOff
    )
    dashboard.ui.scrollArea_tsi_detector_parameters.setVerticalScrollBarPolicy(
        QtCore.Qt.ScrollBarAsNeeded
    )

    dashboard.tsi_detector_parameter_widgets = {}
    dashboard.tsi_detector_current_schema = {}
    dashboard.tsi_detector_customized = False

    _tsi_detector_set_card3_enabled(dashboard, False)


def _render_tsi_detector_parameter_widgets(
    dashboard: QtCore.QObject,
    parameters: list,
):
    contents = dashboard.ui.scrollAreaWidgetContents_tsi_detector_parameters

    layout = contents.layout()
    if layout is None:
        layout = QtWidgets.QGridLayout(contents)
        contents.setLayout(layout)

    layout.setContentsMargins(12, 10, 12, 10)
    layout.setHorizontalSpacing(8)
    layout.setVerticalSpacing(7)
    layout.setAlignment(QtCore.Qt.AlignTop)

    # Kill leftovers from old layout columns.
    for col in range(0, 8):
        layout.setColumnStretch(col, 0)
        layout.setColumnMinimumWidth(col, 0)

    contents.setAutoFillBackground(False)
    contents.setMaximumWidth(430)

    dashboard.ui.scrollArea_tsi_detector_parameters.setWidgetResizable(True)
    dashboard.ui.scrollArea_tsi_detector_parameters.setAlignment(
        QtCore.Qt.AlignHCenter | QtCore.Qt.AlignTop
    )
    dashboard.ui.scrollArea_tsi_detector_parameters.setHorizontalScrollBarPolicy(
        QtCore.Qt.ScrollBarAlwaysOff
    )
    dashboard.ui.scrollArea_tsi_detector_parameters.setVerticalScrollBarPolicy(
        QtCore.Qt.ScrollBarAsNeeded
    )

    visible_params = [
        p for p in parameters
        if str(p.get("name", "")).strip() != "description"
    ]

    for row, param in enumerate(visible_params):
        name = str(param.get("name", "")).strip()
        if not name:
            continue

        label_text = str(param.get("label") or name).strip()
        widget = _create_tsi_detector_parameter_widget(dashboard, param)

        label = QtWidgets.QLabel(label_text + ":", contents)
        label.setObjectName("label2_tsi_detector_parameter")
        label.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        label.setFixedWidth(160)

        layout.addWidget(label, row, 0)
        layout.addWidget(widget, row, 1)

        dashboard.tsi_detector_parameter_widgets[name] = widget

    layout.setColumnMinimumWidth(0, 160)
    layout.setColumnMinimumWidth(1, 180)
    layout.setColumnStretch(0, 0)
    layout.setColumnStretch(1, 0)


def _create_tsi_detector_parameter_widget(
    dashboard: QtCore.QObject,
    param: dict,
):
    param_name = str(param.get("name", "")).strip()
    param_type = str(param.get("type", "string") or "string").lower()
    default = param.get("default", "")
    options = param.get("options", []) or []

    compact_width = 180

    if param_type in {"int", "integer", "number", "float", "double"}:
        widget = QtWidgets.QDoubleSpinBox()
        widget.setObjectName("doubleSpinBox_tsi_detector_parameter")

        widget.setDecimals(_safe_int(param.get("decimals"), 3))
        widget.setMinimum(_safe_float(param.get("min"), -999999999.0))
        widget.setMaximum(_safe_float(param.get("max"), 999999999.0))
        widget.setSingleStep(_safe_float(param.get("step"), 1.0))
        widget.setValue(_safe_float(default, 0.0))

        if param_type in {"int", "integer"}:
            widget.setDecimals(0)

        widget.setFixedWidth(compact_width)
        widget.setButtonSymbols(QtWidgets.QAbstractSpinBox.UpDownArrows)
        widget.setAlignment(QtCore.Qt.AlignRight)
        return widget

    if param_type in {"bool", "boolean"}:
        widget = QtWidgets.QCheckBox()
        widget.setObjectName("checkBox_tsi_detector_parameter")
        widget.setChecked(
            str(default).strip().lower() in {"1", "true", "yes", "on"}
        )
        widget.setFixedWidth(compact_width)
        return widget

    if options:
        widget = QtWidgets.QComboBox()
        widget.setObjectName("comboBox_tsi_detector_parameter")
        widget.addItems([str(option) for option in options])

        default_text = str(default)
        index = widget.findText(default_text)
        if index >= 0:
            widget.setCurrentIndex(index)

        widget.setFixedWidth(compact_width)

        if param_name == "run_mode":
            widget.setToolTip(
                "GUI mode is intended for local nodes. Remote nodes should run headless."
            )

        return widget

    widget = QtWidgets.QLineEdit()
    widget.setObjectName("lineEdit_tsi_detector_parameter")
    widget.setText(str(default))
    widget.setFixedWidth(compact_width)
    return widget


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return float(default)


def _safe_int(value, default=0):
    try:
        return int(float(value))
    except Exception:
        return int(default)


def _tsi_detector_schema_description(parameters: list) -> str:
    for param in parameters:
        if str(param.get("name", "")).strip() == "description":
            description = str(param.get("default", "") or "").strip()
            if description:
                return description
    return ""


def update_tsi_detector_selected_node_gate(dashboard: QtCore.QObject):
    """
    Shows the unified detector controls only when a selected Sensor Node exists
    and is currently connected.

    stackedWidget_tsi_detector:
        page 0 = normal Detector controls
        page 1 = no Sensor Node selected / unavailable empty-state page
    """
    selected_uid = getattr(dashboard, "selected_node_uid", "") or ""
    has_selected_node = bool(selected_uid)

    if has_selected_node:
        node_states = getattr(dashboard, "node_states", {}) or {}
        node_state = node_states.get(selected_uid)

        if isinstance(node_state, dict) and node_state.get("connected") is False:
            has_selected_node = False

    stack = getattr(dashboard.ui, "stackedWidget_tsi_detector", None)
    if stack is not None:
        stack.setCurrentIndex(0 if has_selected_node else 1)

    # If running, do not re-enable anything. A node status/hardware refresh may
    # call this gate while the action is active.
    if getattr(dashboard, "tsi_detector_running", False):
        _tsi_detector_set_controls_enabled(dashboard, False)
        _tsi_detector_set_card3_enabled(dashboard, True)
        update_tsi_detector_status_from_node(
            dashboard,
            node_uid=selected_uid,
        )
        return

    # Static filters should be enabled only when not running.
    dashboard.ui.comboBox_tsi_detector_type.setEnabled(True)
    dashboard.ui.comboBox_tsi_detector_mode.setEnabled(True)

    _tsi_detector_set_start_stop_button(dashboard, False)

    hardware_combo = dashboard.ui.comboBox_tsi_detector_hardware
    method_combo = dashboard.ui.comboBox_tsi_detector_method
    query_button = dashboard.ui.pushButton_tsi_detector_query
    customize_button = dashboard.ui.pushButton_tsi_detector_customize

    if not has_selected_node:
        clear_tsi_detector_methods(dashboard)

        hardware_combo.blockSignals(True)
        hardware_combo.clear()
        hardware_combo.blockSignals(False)
        hardware_combo.setEnabled(False)

        method_combo.setEnabled(False)
        query_button.setEnabled(False)
        customize_button.setEnabled(False)

        _tsi_detector_set_card3_enabled(dashboard, False)
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")

        dashboard.ui.label_tsi_detector_setup_info.setText(
            "Select a sensor node before querying detector methods."
        )
        return

    update_tsi_detector_hardware_combo(dashboard)

    has_hardware = hardware_combo.count() > 0
    has_method = method_combo.count() > 0
    is_customized = bool(getattr(dashboard, "tsi_detector_customized", False))

    hardware_combo.setEnabled(has_hardware)
    method_combo.setEnabled(has_hardware and has_method)
    query_button.setEnabled(has_hardware)
    customize_button.setEnabled(has_hardware and has_method)

    _tsi_detector_set_card3_enabled(
        dashboard,
        has_selected_node and has_hardware and is_customized,
    )

    for widget in getattr(dashboard, "tsi_detector_parameter_widgets", {}).values():
        widget.setEnabled(True)

    _tsi_detector_set_status_text(dashboard, "Idle")

    if has_hardware:
        if not has_method:
            dashboard.ui.label_tsi_detector_setup_info.setText(
                "Query matching detector methods for the selected type, mode, and hardware."
            )
    else:
        clear_tsi_detector_methods(dashboard)
        _tsi_detector_set_card3_enabled(dashboard, False)
        dashboard.ui.label_tsi_detector_setup_info.setText(
            "No detector-compatible hardware is configured for the selected node."
        )


def _tsi_detector_set_start_stop_button(
    dashboard: QtCore.QObject,
    running: bool,
):
    """
    Updates the unified detector start/stop button text and dynamic stylesheet state.
    """
    button = dashboard.ui.pushButton_tsi_detector_start_stop

    button.setProperty("running", bool(running))

    if running:
        button.setText("▮▮  Stop Detector")
    else:
        button.setText("▶  Start Detector")

    button.style().unpolish(button)
    button.style().polish(button)
    button.update()


def _tsi_detector_set_status_text(
    dashboard: QtCore.QObject,
    text: str,
):
    """
    Sets the unified detector Card 3 status label.
    """
    label = getattr(dashboard.ui, "label2_tsi_detector_status", None)

    if label is not None:
        label.setText(str(text or "").strip())


def _tsi_detector_set_controls_enabled(
    dashboard: QtCore.QObject,
    enabled: bool,
):
    """
    Enables/disables unified detector setup and parameter controls while running.

    Do not use this for selected-node gating. Type/Mode are static filters and
    should stay populated.
    """
    for widget_name in (
        "comboBox_tsi_detector_type",
        "comboBox_tsi_detector_mode",
        "comboBox_tsi_detector_hardware",
        "comboBox_tsi_detector_method",
        "pushButton_tsi_detector_query",
        "pushButton_tsi_detector_customize",
    ):
        widget = getattr(dashboard.ui, widget_name, None)

        if widget is not None:
            widget.setEnabled(enabled)

    for widget in getattr(dashboard, "tsi_detector_parameter_widgets", {}).values():
        widget.setEnabled(enabled)


def _tsi_detector_set_running(
    dashboard: QtCore.QObject,
    node_uid: str,
):
    """
    Marks the unified detector action as running and updates Card 3/UI state.

    Status label follows the selected node action status, same as Fixed/Sweep.
    """
    dashboard.tsi_detector_running = True
    dashboard.tsi_detector_node_uid = node_uid or ""
    dashboard.tsi_detector_opid = ""
    dashboard.tsi_detector_waiting_for_opid = True

    stack = getattr(dashboard.ui, "stackedWidget_tsi_detector", None)
    if stack is not None:
        stack.setCurrentIndex(0)

    for table in _tsi_detector_results_tables(dashboard):
        table.clearContents()
        table.setRowCount(0)

    _tsi_detector_plot_start(dashboard)

    _tsi_detector_set_start_stop_button(dashboard, True)
    _tsi_detector_set_status_text(dashboard, "Starting...")
    update_tsi_detector_status_from_node(dashboard, node_uid=node_uid)

    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(True)
    _tsi_detector_set_controls_enabled(dashboard, False)


def _tsi_detector_set_stopped(dashboard: QtCore.QObject):
    """
    Marks the unified detector action as stopped and restores Card 3/UI state.
    """
    _tsi_detector_plot_stop(dashboard)

    dashboard.tsi_detector_running = False
    dashboard.tsi_detector_node_uid = ""
    dashboard.tsi_detector_opid = ""
    dashboard.tsi_detector_waiting_for_opid = False

    _tsi_detector_set_start_stop_button(dashboard, False)

    if getattr(dashboard, "selected_node_uid", ""):
        _tsi_detector_set_status_text(dashboard, "Idle")
    else:
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")

    update_tsi_detector_selected_node_gate(dashboard)


def update_tsi_detector_status_from_node(
    dashboard: QtCore.QObject,
    node_uid: str = "",
):
    """
    Mirrors the selected node's operation/status text into the unified detector
    status label.
    """
    selected_uid = getattr(dashboard, "selected_node_uid", "") or ""

    if node_uid and selected_uid and node_uid != selected_uid:
        return

    if not selected_uid:
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")
        return

    if not getattr(dashboard, "tsi_detector_running", False):
        _tsi_detector_set_status_text(dashboard, "Idle")
        return

    node_states = getattr(dashboard, "node_states", {}) or {}
    node_state = node_states.get(selected_uid, {}) or {}

    status_text = (
        node_state.get("status")
        or node_state.get("state")
        or node_state.get("operation_status")
        or node_state.get("last_status")
        or ""
    )

    status_text = str(status_text).strip()

    if not status_text:
        status_text = "Running"

    _tsi_detector_set_status_text(dashboard, status_text)


def update_tsi_detector_status_from_selected_node(
    dashboard: QtCore.QObject,
    node_uid: str = "",
    status: str = "",
):
    """
    Mirrors the top-panel selected node's operation/status text into the
    unified detector status label.

    This uses dashboard.selected_node_uid, not selected_tactical_node_uid.
    """
    selected_uid = getattr(dashboard, "selected_node_uid", "") or ""

    if not selected_uid:
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")
        return

    if node_uid and node_uid != selected_uid:
        return

    node_states = getattr(dashboard, "node_states", {}) or {}
    node_state = node_states.get(selected_uid, {}) or {}

    if isinstance(node_state, dict) and node_state.get("connected") is False:
        _tsi_detector_set_status_text(dashboard, "Sensor Node Unavailable")
        return

    status_text = str(
        status
        or node_state.get("status", "")
        or ""
    ).strip()

    detector_running = bool(
        getattr(dashboard, "tsi_detector_running", False)
    )

    if not detector_running:
        _tsi_detector_set_status_text(dashboard, "Idle")
        return

    if not status_text:
        status_text = "Starting..."

    _tsi_detector_set_status_text(dashboard, status_text)


@qasync.asyncSlot(QtCore.QObject)
async def _slotTSI_DetectorStartStopClicked(dashboard: QtCore.QObject):
    """
    Starts/stops the unified TSI Detector action through the plugin action path.
    """
    uid = getattr(dashboard, "selected_node_uid", "") or ""

    if not uid:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Select a Sensor Node before starting the detector.",
        )
        return

    if getattr(dashboard, "tsi_detector_running", False):
        try:
            await dashboard.backend.tacticalNodeStop([uid])
        finally:
            _tsi_detector_set_stopped(dashboard)
            dashboard.refreshStatusBarText()
        return

    plugin_name = getattr(dashboard, "tsi_detector_selected_plugin", "") or ""
    action_name = getattr(dashboard, "tsi_detector_selected_action", "") or ""

    if not plugin_name or not action_name:
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Query and customize a detector method before starting.",
        )
        return

    if not getattr(dashboard, "tsi_detector_customized", False):
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Customize detector parameters before starting.",
        )
        return

    try:
        parameters = collect_tsi_detector_parameters(dashboard)
    except Exception as e:
        dashboard.logger.error(f"Could not collect TSI Detector parameters: {e}")
        await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
            dashboard,
            "Could not collect detector parameters.",
        )
        return

    _tsi_detector_set_running(
        dashboard,
        node_uid=uid,
    )

    try:
        await dashboard.backend.tacticalNodeExecute(
            [uid],
            plugin_name,
            action_name,
            parameters,
        )
    except Exception:
        _tsi_detector_set_stopped(dashboard)
        raise

    dashboard.refreshStatusBarText()


def collect_tsi_detector_parameters(dashboard: QtCore.QObject) -> dict:
    """
    Collect Card 2 dynamic detector parameter widget values into the plugin
    action parameters dictionary.
    """
    parameters = {}

    parameter_widgets = getattr(
        dashboard,
        "tsi_detector_parameter_widgets",
        {},
    )

    for parameter_name, widget in parameter_widgets.items():
        parameter_name = str(parameter_name or "").strip()

        if not parameter_name:
            continue

        if isinstance(widget, QtWidgets.QLineEdit):
            parameters[parameter_name] = widget.text()

        elif isinstance(widget, QtWidgets.QComboBox):
            parameters[parameter_name] = widget.currentText()

        elif isinstance(widget, QtWidgets.QDoubleSpinBox):
            value = widget.value()

            if widget.decimals() == 0:
                parameters[parameter_name] = int(value)
            else:
                parameters[parameter_name] = value

        elif isinstance(widget, QtWidgets.QSpinBox):
            parameters[parameter_name] = widget.value()

        elif isinstance(widget, QtWidgets.QCheckBox):
            parameters[parameter_name] = widget.isChecked()

        else:
            dashboard.logger.warning(
                f"[TSI Detector] Unsupported parameter widget for "
                f"{parameter_name}: {type(widget)}"
            )

    return parameters


def _tsi_detector_set_card3_enabled(
    dashboard: QtCore.QObject,
    enabled: bool,
):
    """
    Enables/disables Card 3 labels along with the Start/Stop button.
    """
    for widget_name in (
        # "label_tsi_detector_run_title",
        # "label_tsi_detector_run_subtitle",
        "label2_detector_status_status",
        "label2_tsi_detector_status",
    ):
        widget = getattr(dashboard.ui, widget_name, None)

        if widget is not None:
            widget.setEnabled(enabled)

    dashboard.ui.pushButton_tsi_detector_start_stop.setEnabled(enabled)


def _tsi_detector_results_tables(dashboard: QtCore.QObject):
    """
    Returns all tables that should receive/clear TSI detector result rows.
    """
    tables = []

    for name in (
        "tableWidget1_tsi_wideband",
        "tableWidget_tsi_conditioner_input_detector",
    ):
        table = getattr(dashboard.ui, name, None)
        if table is not None:
            tables.append(table)

    return tables


def _tsi_detector_plot_color_settings(dashboard: QtCore.QObject):
    """
    Returns plot colors tuned for the current Dashboard color mode.
    """
    settings = getattr(dashboard.backend, "settings", {}) or {}
    color_mode = str(settings.get("color_mode", "") or "")

    text_color = settings.get("color4", "#000000")
    fig_face = settings.get("color1", "#f4f4f4")

    if "Dark" in color_mode:
        plot_face = "#1f2933"
        grid_color = "#56616f"
    else:
        plot_face = "#e9ecef"
        grid_color = "#b8c0ca"

    return fig_face, plot_face, grid_color, text_color


def _tsi_detector_plot_ensure_state(dashboard: QtCore.QObject):
    """
    Lazily initializes the unified TSI detector raster state.
    """
    if not hasattr(dashboard, "tsi_detector_plot_events"):
        dashboard.tsi_detector_plot_events = deque(maxlen=2000)

    if not hasattr(dashboard, "tsi_detector_plot_start_time"):
        dashboard.tsi_detector_plot_start_time = None

    if not hasattr(dashboard, "tsi_detector_plot_dirty"):
        dashboard.tsi_detector_plot_dirty = False

    if not hasattr(dashboard, "tsi_detector_plot_timer"):
        dashboard.tsi_detector_plot_timer = None

    if not hasattr(dashboard, "tsi_detector_plot_window_s"):
        dashboard.tsi_detector_plot_window_s = 60.0

    if not hasattr(dashboard, "tsi_detector_plot_initial_xlim_low"):
        dashboard.tsi_detector_plot_initial_xlim_low = None

    if not hasattr(dashboard, "tsi_detector_plot_initial_xlim_high"):
        dashboard.tsi_detector_plot_initial_xlim_high = None


def _tsi_detector_plot_reset(dashboard: QtCore.QObject):
    """
    Clears current unified detector plot state and draws an empty raster.
    """
    _tsi_detector_plot_ensure_state(dashboard)

    dashboard.tsi_detector_plot_events.clear()
    dashboard.tsi_detector_plot_start_time = None
    dashboard.tsi_detector_plot_dirty = True

    x_low, x_high = _tsi_detector_plot_initial_xlim(dashboard)
    dashboard.tsi_detector_plot_initial_xlim_low = x_low
    dashboard.tsi_detector_plot_initial_xlim_high = x_high

    _tsi_detector_plot_refresh(dashboard, force=True)


def _tsi_detector_plot_clear_points(dashboard: QtCore.QObject):
    """
    Clears plotted detector points while preserving the active run state.
    """
    _tsi_detector_plot_ensure_state(dashboard)

    dashboard.tsi_detector_plot_events.clear()
    dashboard.tsi_detector_plot_start_time = None
    dashboard.tsi_detector_plot_dirty = True

    _tsi_detector_plot_refresh(
        dashboard,
        force=True,
        running=getattr(dashboard, "tsi_detector_running", False),
    )


def _tsi_detector_plot_start(dashboard: QtCore.QObject):
    """
    Starts/resets the unified detector plot for a new detector operation.

    Elapsed time is anchored to the Dashboard Start click, not the first
    detection timestamp.
    """
    _tsi_detector_plot_ensure_state(dashboard)

    dashboard.tsi_detector_plot_events.clear()
    dashboard.tsi_detector_plot_start_time = time.time()
    dashboard.tsi_detector_plot_dirty = True

    x_low, x_high = _tsi_detector_plot_initial_xlim(dashboard)
    dashboard.tsi_detector_plot_initial_xlim_low = x_low
    dashboard.tsi_detector_plot_initial_xlim_high = x_high

    _tsi_detector_plot_refresh(dashboard, force=True, running=True)

    old_timer = getattr(dashboard, "tsi_detector_plot_timer", None)
    if old_timer is not None:
        try:
            old_timer.stop()
            old_timer.timeout.disconnect()
        except Exception:
            pass

    timer = QtCore.QTimer(dashboard)
    timer.setInterval(250)
    timer.timeout.connect(lambda: _tsi_detector_plot_refresh(dashboard))
    dashboard.tsi_detector_plot_timer = timer
    timer.start()


def _tsi_detector_plot_stop(dashboard: QtCore.QObject):
    """
    Stops the detector plot timer/refresh behavior but leaves visible points.
    """
    timer = getattr(dashboard, "tsi_detector_plot_timer", None)
    if timer is not None:
        try:
            timer.stop()
        except Exception:
            pass

    _tsi_detector_plot_refresh(dashboard, force=True, running=False)


def _tsi_detector_plot_add_detection(
    dashboard: QtCore.QObject,
    frequency_mhz: float,
    power_dbm: float,
    timestamp_s: float = None,
):
    """
    Appends one detector event to the unified detector raster.
    """
    _tsi_detector_plot_ensure_state(dashboard)

    if timestamp_s is None:
        timestamp_s = time.time()

    if dashboard.tsi_detector_plot_start_time is None:
        dashboard.tsi_detector_plot_start_time = timestamp_s

    elapsed_s = max(
        0.0,
        float(timestamp_s) - float(dashboard.tsi_detector_plot_start_time),
    )

    dashboard.tsi_detector_plot_events.append(
        {
            "frequency_mhz": float(frequency_mhz),
            "power_dbm": float(power_dbm),
            "timestamp_s": float(timestamp_s),
            "elapsed_s": elapsed_s,
        }
    )

    dashboard.tsi_detector_plot_dirty = True


def _tsi_detector_plot_refresh(
    dashboard: QtCore.QObject,
    force: bool = False,
    running: bool = None,
):
    """
    Redraws the unified TSI detector raster when there are new events.

    Rebuilds the Matplotlib figure contents because the shared TSI canvas may
    previously have been used as an image/waterfall canvas. Rebuilding prevents
    old imshow/colorbar state from forcing an equal-aspect, vertically squished
    plot.
    """
    _tsi_detector_plot_ensure_state(dashboard)

    if not force and not getattr(dashboard, "tsi_detector_plot_dirty", False):
        return

    canvas = getattr(dashboard, "matplotlib_widget", None)
    if canvas is None:
        return

    try:
        fig = canvas.fig

        fig_face, plot_face, grid_color, text_color = (
            _tsi_detector_plot_color_settings(dashboard)
        )

        events_all = list(getattr(dashboard, "tsi_detector_plot_events", []))
        window_s = float(
            getattr(dashboard, "tsi_detector_plot_window_s", 60.0) or 60.0
        )

        if events_all:
            latest_elapsed = max(float(e["elapsed_s"]) for e in events_all)
        else:
            latest_elapsed = 0.0

        y_min = max(0.0, latest_elapsed - window_s)
        y_max = max(window_s, latest_elapsed + 1.0)

        events = [
            e for e in events_all
            if float(e["elapsed_s"]) >= y_min
        ]

        freqs = [
            float(e["frequency_mhz"])
            for e in events_all
        ]

        x_min, x_max = _tsi_detector_plot_data_xlim(
            dashboard,
            freqs=freqs,
        )

        #
        # Rebuild the figure for detector-raster mode.
        #
        fig.clear()
        fig.set_facecolor(fig_face)

        ax = fig.add_subplot(111)
        canvas.axes = ax

        # Critical: do not let old imshow/equal-aspect behavior squeeze this.
        ax.set_aspect("auto", adjustable="box")

        fig.subplots_adjust(
            left=0.085,
            right=0.895,
            bottom=0.125,
            top=0.94,
            wspace=0.0,
            hspace=0.0,
        )

        ax.set_facecolor(plot_face)

        if running is None:
            running = bool(getattr(dashboard, "tsi_detector_running", False))

        if running:
            title_state = "Running"
        else:
            title_state = "Stopped"

        detector_type = ""
        detector_mode = ""

        try:
            detector_type = str(
                dashboard.ui.comboBox_tsi_detector_type.currentText()
            ).strip()
        except Exception:
            detector_type = ""

        try:
            detector_mode = str(
                dashboard.ui.comboBox_tsi_detector_mode.currentText()
            ).strip()
        except Exception:
            detector_mode = ""

        title_prefix = "Detector Activity"

        if detector_type or detector_mode:
            title_parts = [
                part for part in (detector_type, detector_mode)
                if part
            ]
            title_prefix = " ".join(title_parts) + " Detector Activity"

        ax.set_title(
            f"{title_prefix} - {title_state}",
            color=text_color,
            fontsize=10,
            pad=8,
        )

        ax.set_xlabel(
            "Frequency (MHz)",
            color=text_color,
            fontsize=9,
            labelpad=7,
        )
        ax.set_ylabel(
            "Time Elapsed (s)",
            color=text_color,
            fontsize=9,
            labelpad=7,
        )

        ax.set_xlim(x_min, x_max)
        ax.set_ylim(y_min, y_max)

        try:
            ax.xaxis.set_major_locator(matplotlib.ticker.MaxNLocator(nbins=6))
            ax.xaxis.set_major_formatter(
                matplotlib.ticker.FormatStrFormatter("%.3f")
            )
        except Exception:
            pass

        ax.grid(
            True,
            color=grid_color,
            linestyle="--",
            linewidth=0.6,
            alpha=0.75,
        )
        ax.set_axisbelow(True)

        ax.tick_params(axis="x", colors=text_color, labelsize=8)
        ax.tick_params(axis="y", colors=text_color, labelsize=8)

        for spine in ax.spines.values():
            spine.set_color(grid_color)

        try:
            cmap = matplotlib.cm.get_cmap("turbo")
        except Exception:
            cmap = matplotlib.cm.get_cmap("rainbow")

        norm = matplotlib.colors.Normalize(vmin=-60.0, vmax=40.0)

        if events:
            tick_height = max(0.35, (y_max - y_min) * 0.012)

            segments = []
            powers = []

            for event in events:
                x = float(event["frequency_mhz"])
                y = float(event["elapsed_s"])

                segments.append(
                    [
                        (x, max(y_min, y - tick_height)),
                        (x, min(y_max, y + tick_height)),
                    ]
                )
                powers.append(float(event["power_dbm"]))

            line_collection = LineCollection(
                segments,
                cmap=cmap,
                norm=norm,
                linewidths=2.8,
                alpha=0.95,
            )
            line_collection.set_array(np.array(powers))
            ax.add_collection(line_collection)

        else:
            if running:
                message = "Waiting for detector reports..."
            else:
                message = "No detector data"

            ax.text(
                0.5,
                0.5,
                message,
                transform=ax.transAxes,
                ha="center",
                va="center",
                color=text_color,
                alpha=0.75,
                fontsize=10,
            )

        sm = matplotlib.cm.ScalarMappable(norm=norm, cmap=cmap)
        sm.set_array([])

        cbar = fig.colorbar(
            sm,
            ax=ax,
            fraction=0.035,
            pad=0.025,
        )
        canvas.cbar = cbar

        cbar.set_label(
            label="Power (dB)",
            color=text_color,
            fontsize=9,
        )
        cbar.ax.tick_params(labelsize=8, color=text_color)

        matplotlib.pyplot.setp(
            matplotlib.pyplot.getp(cbar.ax.axes, "yticklabels"),
            color=text_color,
        )

        canvas.draw_idle()
        dashboard.tsi_detector_plot_dirty = False

    except Exception as e:
        dashboard.logger.debug(
            f"Failed to refresh unified TSI detector raster: {e}"
        )