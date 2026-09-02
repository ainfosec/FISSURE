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

import json
import uuid

import inspect



    # try:
    #     _slotTSI_FE_InputRefreshClicked(dashboard)
    # except Exception:
    #     pass



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



    



__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value)
    and value.__module__ == __name__
]
