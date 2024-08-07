from PyQt5 import QtCore, QtWidgets, QtGui
import os
import fissure.utils
import yaml
import datetime
from ..UI_Components import TriggersDialog
import qasync
import time
import asyncio


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodeAutorunTableDelayChecked(state: int, dashboard: QtCore.QObject):
    """ 
    Enables/disables the timeEdit box in the table row.
    """
    # Get Table Checkbox
    get_checkbox = dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(dashboard.ui.tableWidget_sensor_nodes_autorun.currentRow(),3)
    
    # Checked
    if get_checkbox.isChecked():
        dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(dashboard.ui.tableWidget_sensor_nodes_autorun.currentRow(),4).setEnabled(True)
    
    # Unchecked
    else:
        dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(dashboard.ui.tableWidget_sensor_nodes_autorun.currentRow(),4).setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodeAutorunDelayChecked(dashboard: QtCore.QObject):
    """ 
    Enables/disables the dateTimeEdit box.
    """
    # Checked
    if dashboard.ui.checkBox_sensor_nodes_autorun_delay.isChecked():
        dashboard.ui.dateTimeEdit_sensor_nodes_autorun.setEnabled(True)
    
    # Unchecked
    else:
        dashboard.ui.dateTimeEdit_sensor_nodes_autorun.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunPlaylistsChanged(dashboard: QtCore.QObject):
    """ 
    Imports the selected autorun playlist into the table.
    """
    # Load File Information, Ignore Custom
    if dashboard.ui.comboBox_sensor_nodes_autorun.count() > 0:
        get_playlist = str(dashboard.ui.comboBox_sensor_nodes_autorun.currentText())
        dashboard.ui.tableWidget_sensor_nodes_autorun.setRowCount(0)
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setRowCount(0)
        if get_playlist != "Custom":
            _slotSensorNodesAutorunImportClicked(dashboard, filepath=os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists",get_playlist))
            

@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalFolderChanged(dashboard: QtCore.QObject):
    """ 
    Changes the folder location in the tree view for viewing local files.
    """
    # Change the Root Location of the Tree
    get_path = str(dashboard.ui.comboBox_sensor_nodes_fn_local_folder.currentText())
    dashboard.ui.treeView_sensor_nodes_fn_local_files.setRootIndex(dashboard.ui.treeView_sensor_nodes_fn_local_files.model().index(get_path))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationFolderChanged(dashboard: QtCore.QObject):
    """ 
    Refreshes the files listed for the remote folder and disables the Transfer button. 
    """
    # Active Sensor Nodes Only
    if dashboard.active_sensor_node > -1:
        # Disable/Enable the Transfer Button
        get_folder = str(dashboard.ui.comboBox_sensor_nodes_fn_folder.currentText())
        if (get_folder == '/IQ_Data_Playback') or (get_folder == '/Archive_Replay'):
            dashboard.ui.pushButton_sensor_nodes_fn_local_transfer.setEnabled(False)
        else:
            dashboard.ui.pushButton_sensor_nodes_fn_local_transfer.setEnabled(True)
            
        # Refresh the Folders
        _slotSensorNodesFileNavigationRefreshClicked(dashboard)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunRemoveClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row from the autorun playlist table.
    """
    # Remove from the TableWidget
    get_current_row = dashboard.ui.tableWidget_sensor_nodes_autorun.currentRow()
    dashboard.ui.tableWidget_sensor_nodes_autorun.removeRow(get_current_row)
    if get_current_row == 0:
        dashboard.ui.tableWidget_sensor_nodes_autorun.setCurrentCell(0,0)
    else:
        dashboard.ui.tableWidget_sensor_nodes_autorun.setCurrentCell(get_current_row-1,0)

    # # Disable PushButtons
    # if dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount() < 1:
        # dashboard.ui.pushButton_archive_replay_start.setEnabled(False)


@QtCore.pyqtSlot(QtCore.QObject, str)
def _slotSensorNodesAutorunImportClicked(dashboard: QtCore.QObject, filepath=""):
    """ 
    Removes a row from the autorun playlist table.
    """
    # Choose File
    if len(filepath) == 0:
        get_playlist_folder = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists")
        filepath = QtWidgets.QFileDialog.getOpenFileNames(None,"Select YAML File...", get_playlist_folder, filter="YAML (*.yaml)")
        if len(filepath[0]) == 0:
            return          
        
        # Load the YAML File
        with open(filepath[0][0]) as yaml_playlist_file:
            playlist_dict = yaml.load(yaml_playlist_file, yaml.FullLoader)
            
    else:
        # Load the YAML File
        with open(filepath) as yaml_playlist_file:
            playlist_dict = yaml.load(yaml_playlist_file, yaml.FullLoader)
    
    # Delay Start
    get_delay_start = playlist_dict.pop('delay_start')
    if get_delay_start == 'True':
        dashboard.ui.checkBox_sensor_nodes_autorun_delay.setChecked(True)
    else:
        dashboard.ui.checkBox_sensor_nodes_autorun_delay.setChecked(False)
    _slotSensorNodeAutorunDelayChecked(dashboard)
    
    # Delay Start Time
    get_delay_start_time = playlist_dict.pop('delay_start_time')
    dashboard.ui.dateTimeEdit_sensor_nodes_autorun.setDateTime(datetime.datetime.strptime(get_delay_start_time,'%Y-%m-%d %H:%M:%S'))
    
    # Repetition Interval
    get_repetition_interval = playlist_dict.pop('repetition_interval_seconds')
    dashboard.ui.textEdit_sensor_nodes_autorun_repetition_interval.setPlainText(str(get_repetition_interval))
    
    # Clear the Tables
    dashboard.ui.tableWidget_sensor_nodes_autorun.setRowCount(0)
    dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setRowCount(0)

    # Triggers Table
    get_value = playlist_dict.pop('trigger_values')
    dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setRowCount(len(get_value))
    for row in range(0,len(get_value)):
        # Filename
        filename_item = QtWidgets.QTableWidgetItem(get_value[row][0])
        filename_item.setTextAlignment(QtCore.Qt.AlignCenter)
        filename_item.setFlags(filename_item.flags() & ~QtCore.Qt.ItemIsEditable)
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setItem(row,0,filename_item)
        
        # Type
        type_item = QtWidgets.QTableWidgetItem(get_value[row][1])
        type_item.setTextAlignment(QtCore.Qt.AlignCenter)
        type_item.setFlags(type_item.flags() & ~QtCore.Qt.ItemIsEditable)
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setItem(row,1,type_item)

        # Variable Names
        variable_names_item = QtWidgets.QTableWidgetItem(get_value[row][2])
        variable_names_item.setTextAlignment(QtCore.Qt.AlignCenter)
        variable_names_item.setFlags(variable_names_item.flags() & ~QtCore.Qt.ItemIsEditable)
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setItem(row,2,variable_names_item)

        # Variable Values
        variable_values_item = QtWidgets.QTableWidgetItem(get_value[row][3])
        variable_values_item.setTextAlignment(QtCore.Qt.AlignCenter)
        variable_values_item.setFlags(variable_values_item.flags() & ~QtCore.Qt.ItemIsEditable)
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setItem(row,3,variable_values_item)
    
    # Resize the Table
    dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.resizeColumnsToContents()
    #dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setColumnWidth(5,300)
    #dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setColumnWidth(6,300)
    dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.resizeRowsToContents()
    dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.horizontalHeader().setStretchLastSection(True)
    
    # Fill the Table
    for k in playlist_dict:
        dashboard.ui.tableWidget_sensor_nodes_autorun.setRowCount(dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount() + 1)
        
        # Type
        type_item = QtWidgets.QTableWidgetItem(playlist_dict[k]['type'])
        type_item.setTextAlignment(QtCore.Qt.AlignCenter)
        type_item.setFlags(type_item.flags() & ~QtCore.Qt.ItemIsEditable)
        dashboard.ui.tableWidget_sensor_nodes_autorun.setItem(dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()-1,0,type_item)
        
        # Repeat
        new_combobox1 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
        dashboard.ui.tableWidget_sensor_nodes_autorun.setCellWidget(dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()-1,1,new_combobox1)
        new_combobox1.addItem("True")
        new_combobox1.addItem("False")
        new_combobox1.setFixedSize(67,24)
        if playlist_dict[k]['repeat'] == "True":
            new_combobox1.setCurrentIndex(0)
        else:
            new_combobox1.setCurrentIndex(1)
            
        # Timeout
        timeout_item = QtWidgets.QTableWidgetItem(playlist_dict[k]['timeout_seconds'])
        timeout_item.setTextAlignment(QtCore.Qt.AlignCenter)
        dashboard.ui.tableWidget_sensor_nodes_autorun.setItem(dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()-1,2,timeout_item)
        
        # Delay
        new_checkbox = QtWidgets.QCheckBox("", dashboard, objectName='checkBox_')
        new_checkbox.setStyleSheet("margin-left:17%")
        new_checkbox.setChecked(eval(playlist_dict[k]['delay']))
        new_checkbox.stateChanged.connect(lambda state, dashboard=dashboard: _slotSensorNodeAutorunTableDelayChecked(-1, dashboard))
        dashboard.ui.tableWidget_sensor_nodes_autorun.setCellWidget(dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()-1,3,new_checkbox)
    
        # Start Time 
        new_time_edit = QtWidgets.QTimeEdit(dashboard)
        new_time_edit.setDisplayFormat('h:mm:ss AP')
        new_time_edit.setTime(QtCore.QTime.fromString(playlist_dict[k]['start_time'],'HH:mm:ss'))
        dashboard.ui.tableWidget_sensor_nodes_autorun.setCellWidget(dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()-1,4,new_time_edit)
        dashboard.ui.tableWidget_sensor_nodes_autorun.selectRow(dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()-1)
        _slotSensorNodeAutorunTableDelayChecked(-1, dashboard)
        
        # Details
        details_item = QtWidgets.QTableWidgetItem(playlist_dict[k]['details'])
        details_item.setTextAlignment(QtCore.Qt.AlignCenter)
        details_item.setFlags(details_item.flags() & ~QtCore.Qt.ItemIsEditable)
        dashboard.ui.tableWidget_sensor_nodes_autorun.setItem(dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()-1,5,details_item)
        
        # Variable Names
        variable_names_item = QtWidgets.QTableWidgetItem(playlist_dict[k]['variable_names'])
        variable_names_item.setTextAlignment(QtCore.Qt.AlignCenter)
        variable_names_item.setFlags(variable_names_item.flags() & ~QtCore.Qt.ItemIsEditable)
        dashboard.ui.tableWidget_sensor_nodes_autorun.setItem(dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()-1,6,variable_names_item)
        
        # Variable Values
        variable_values_item = QtWidgets.QTableWidgetItem(playlist_dict[k]['variable_values'])
        variable_values_item.setTextAlignment(QtCore.Qt.AlignCenter)
        variable_values_item.setFlags(variable_values_item.flags() & ~QtCore.Qt.ItemIsEditable)
        dashboard.ui.tableWidget_sensor_nodes_autorun.setItem(dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()-1,7,variable_values_item)
            
    # Resize the Table
    dashboard.ui.tableWidget_sensor_nodes_autorun.resizeColumnsToContents()
    dashboard.ui.tableWidget_sensor_nodes_autorun.setColumnWidth(5,300)
    dashboard.ui.tableWidget_sensor_nodes_autorun.setColumnWidth(6,300)
    dashboard.ui.tableWidget_sensor_nodes_autorun.resizeRowsToContents()
    dashboard.ui.tableWidget_sensor_nodes_autorun.horizontalHeader().setStretchLastSection(False)
    dashboard.ui.tableWidget_sensor_nodes_autorun.horizontalHeader().setStretchLastSection(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunExportClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row from the autorun playlist table.
    """                
    # Choose File Location
    get_playlist_folder = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists")
    path = QtWidgets.QFileDialog.getSaveFileName(dashboard, 'Save YAML', get_playlist_folder, filter='YAML (*.yaml)')
    get_path = path[0]
    
    # Add Extension
    if get_path.endswith('.yaml') == False:
        get_path = get_path + '.yaml'
        
    # Save Values
    if len(path[0]) > 0:            
        playlist_dict = {}
        playlist_dict['delay_start'] = str(dashboard.ui.checkBox_sensor_nodes_autorun_delay.isChecked())
        playlist_dict['delay_start_time'] = str(dashboard.ui.dateTimeEdit_sensor_nodes_autorun.dateTime().toString('yyyy-MM-dd hh:mm:ss'))  #.toPyDateTime())  # '2024-01-24 14:08:47.182000'
        playlist_dict['repetition_interval_seconds'] = str(dashboard.ui.textEdit_sensor_nodes_autorun_repetition_interval.toPlainText())
        for n in range(0,dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()):
            row_dict = {}
            try:
                row_dict['type'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,0).text())
            except:
                dashboard.errorMessage("Invalid Type")
                return
            try:
                row_dict['repeat'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,1).currentText())
            except:
                dashboard.errorMessage("Invalid Repeat Value")
                return
            try:
                row_dict['timeout_seconds'] = str(int(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,2).text()))
            except:
                dashboard.errorMessage("Invalid Timeout Value")
                return
            try:
                row_dict['delay'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,3).isChecked())
            except:
                dashboard.errorMessage("Invalid Delay Value")
                return
            try:
                row_dict['start_time'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,4).time().toString('hh:mm:ss'))
            except:
                dashboard.errorMessage("Invalid Start Time Value")
                return                                        
            try:
                row_dict['details'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,5).text())
            except:
                dashboard.errorMessage("Invalid Details Value")
                return
            try:
                row_dict['variable_names'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,6).text())
            except:
                dashboard.errorMessage("Invalid Variable Names Value")
                return
            try:
                row_dict['variable_values'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,7).text())
            except:
                dashboard.errorMessage("Invalid Variable Values Value")
                return
            playlist_dict[n] = row_dict
        
        # Trigger Parameters
        trigger_values = []
        for row in range(0, dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.rowCount()):
            trigger_values.append([str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,0).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,1).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,2).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,3).text())])
        playlist_dict['trigger_values'] = trigger_values
                
        # Dump Dictionary to File
        stream = open(get_path, 'w')
        yaml.dump(playlist_dict, stream, default_flow_style=False, indent=5)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunViewClicked(dashboard: QtCore.QObject):
    """ 
    Opens the autorun playlist item in the attack tab.
    """
    # Current Item
    get_row = dashboard.ui.tableWidget_sensor_nodes_autorun.currentRow()
    if get_row < 0:
        return
        
    get_type = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(get_row,0).text())
    get_details = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(get_row,5).text())
    get_variables = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(get_row,6).text())
    get_values = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(get_row,7).text())
    
    # Load Attack
    if get_type == "Single-Stage":
        # Highlight Attack
        get_attack_name = eval(get_details)[0]  #details = [get_attack_name, get_protocol, get_modulation, get_hardware, str(fname), get_file_type, run_with_sudo]
        get_protocol = eval(get_details)[1]
        get_modulation = eval(get_details)[2]
        get_hardware = eval(get_details)[3]
        get_values = eval(get_values)
        get_sudo = eval(get_details)[6]
        
        dashboard.ui.comboBox_attack_protocols.setCurrentIndex(dashboard.ui.comboBox_attack_protocols.findText(get_protocol))
        dashboard.ui.comboBox_attack_modulation.setCurrentIndex(dashboard.ui.comboBox_attack_modulation.findText(get_modulation))
        dashboard.ui.comboBox_attack_hardware.setCurrentIndex(dashboard.ui.comboBox_attack_hardware.findText(get_hardware))
        dashboard.ui.treeWidget_attack_attacks.setCurrentItem(dashboard.ui.treeWidget_attack_attacks.findItems(get_attack_name,QtCore.Qt.MatchExactly|QtCore.Qt.MatchRecursive,0)[0])
        fissure.Dashboard.Slots.AttackTabSlots._slotAttackLoadTemplateClicked(dashboard)
        
        # Replace Default Values
        variable_list = eval(get_variables)
        for n in range(0,len(get_values)):
            # Remove Quotes from Filepaths
            if 'filepath' in variable_list[n]:
                variable_value_item = QtWidgets.QTableWidgetItem(get_values[n].replace('"',''))
            else:
                variable_value_item = QtWidgets.QTableWidgetItem(get_values[n])
            dashboard.ui.tableWidget1_attack_flow_graph_current_values.setItem(n,0,variable_value_item)
            
        # Check Sudo Checkbox
        if get_sudo == True:
            dashboard.ui.checkBox_attack_single_stage_sudo.setChecked(True)
        else:
            dashboard.ui.checkBox_attack_single_stage_sudo.setChecked(False)
            
        # Switch Tabs
        dashboard.ui.tabWidget_attack_attack.setCurrentIndex(0)
        dashboard.ui.tabWidget.setCurrentIndex(3)
    elif get_type == "Multi-Stage":
        # Import
        formatted_data = [get_details, get_variables, get_values]
        fissure.Dashboard.Slots.AttackTabSlots._slotAttackMultiStageLoadClicked(dashboard, fname="n/a", data_override=formatted_data)
        
        # Switch Tabs
        dashboard.ui.tabWidget_attack_attack.setCurrentIndex(1)
        dashboard.ui.tabWidget.setCurrentIndex(3)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Refreshes the Sensor Nodes Autorun Existing Playlists combobox.
    """
    try:
        # Get the Folder Location
        get_folder = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists")

        # Get the Files for the Combobox
        dashboard.ui.comboBox_sensor_nodes_autorun.clear()
        temp_names = []
        for fname in os.listdir(get_folder):
            if os.path.isfile(get_folder+"/"+fname):
                if ".yaml" in fname:
                    temp_names.append(fname)

        # Sort and Add to the Combobox
        temp_names = sorted(temp_names)
        dashboard.ui.comboBox_sensor_nodes_autorun.addItem("Custom")
        for n in temp_names:
            dashboard.ui.comboBox_sensor_nodes_autorun.addItem(n)

        # Set the Combobox Selection
        dashboard.ui.comboBox_sensor_nodes_autorun.setCurrentIndex(0)
    except:
        dashboard.errorMessage("Unable to refresh autorun playlists")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalDeleteClicked(dashboard: QtCore.QObject):
    """ 
    Deletes a local folder or file.
    """
    # Get Folder/File
    get_item_path = str(dashboard.ui.treeView_sensor_nodes_fn_local_files.model().filePath(dashboard.ui.treeView_sensor_nodes_fn_local_files.currentIndex()))
    
    # Delete the Folder/File
    qm = QtWidgets.QMessageBox
    ret = qm.question(dashboard,'', "Are you sure?", qm.Yes | qm.No)
    if ret == qm.Yes:
        os.system('rm -Rf "' + get_item_path + '"')
    else:
        return


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalChooseClicked(dashboard: QtCore.QObject):
    """ 
    Opens a dialog to select a new folder for viewing local files.
    """
    # Choose Folder
    get_dir = str(QtWidgets.QFileDialog.getExistingDirectory(dashboard, "Select Directory"))

    # Add Directory to the Combobox
    if len(get_dir) > 0:
        dashboard.ui.comboBox_sensor_nodes_fn_local_folder.addItem(get_dir)
        dashboard.ui.comboBox_sensor_nodes_fn_local_folder.setCurrentIndex(dashboard.ui.comboBox_sensor_nodes_fn_local_folder.count()-1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalUnzipClicked(dashboard: QtCore.QObject):
    """ 
    Unzips a local zip file.
    """
    # Unzip the File
    get_zip_file = str(dashboard.ui.treeView_sensor_nodes_fn_local_files.model().filePath(dashboard.ui.treeView_sensor_nodes_fn_local_files.currentIndex()))
    if get_zip_file[-4:] == '.zip':
        os.system('unzip ' + get_zip_file + ' -d ' + get_zip_file[:-4])
    else:
        dashboard.errorMessage("Cannot unzip file")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalViewClicked(dashboard: QtCore.QObject):
    """ 
    Opens a file in the Sensor Nodes File Navigation tab based on size and type.
    """
    # Get the File
    get_file = str(dashboard.ui.treeView_sensor_nodes_fn_local_files.model().filePath(dashboard.ui.treeView_sensor_nodes_fn_local_files.currentIndex()))
    number_of_bytes = os.path.getsize(get_file)
    
    # Check the Size
    if number_of_bytes > 1000000:  # Adjust limit for IQ data, relocate size check inside type check
        dashboard.errorMessage("File is too large to view")
        return
    
    # Check the Type
    if get_file[-4:] == '.txt':
        os.system("gedit " + get_file + " &")
    else:
        dashboard.errorMessage("Not a valid file extension.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunTriggersEditClicked(dashboard: QtCore.QObject):
    """ 
    Opens the triggers dialog window to edit the list of Autorun playlist triggers.
    """
    # Obtain Table Information
    table_values = []
    for row in range(0, dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.rowCount()):
        table_values.append([str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,0).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,1).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,2).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,3).text())])
    
    # Open the Dialog
    get_value = dashboard.openPopUp("TriggersDialog", TriggersDialog, "Autorun Playlist", table_values)

    # Cancel Clicked
    if get_value == None:
        pass
        
    # OK Clicked
    elif len(get_value) > 0:
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setRowCount(len(get_value))
        for row in range(0,len(get_value)):
            # Filename
            filename_item = QtWidgets.QTableWidgetItem(get_value[row][0])
            filename_item.setTextAlignment(QtCore.Qt.AlignCenter)
            filename_item.setFlags(filename_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setItem(row,0,filename_item)
            
            # Type
            type_item = QtWidgets.QTableWidgetItem(get_value[row][1])
            type_item.setTextAlignment(QtCore.Qt.AlignCenter)
            type_item.setFlags(type_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setItem(row,1,type_item)

            # Variable Names
            variable_names_item = QtWidgets.QTableWidgetItem(get_value[row][2])
            variable_names_item.setTextAlignment(QtCore.Qt.AlignCenter)
            variable_names_item.setFlags(variable_names_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setItem(row,2,variable_names_item)

            # Variable Values
            variable_values_item = QtWidgets.QTableWidgetItem(get_value[row][3])
            variable_values_item.setTextAlignment(QtCore.Qt.AlignCenter)
            variable_values_item.setFlags(variable_values_item.flags() & ~QtCore.Qt.ItemIsEditable)
            dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setItem(row,3,variable_values_item)
        
        # Resize the Table
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.resizeColumnsToContents()
        #dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setColumnWidth(5,300)
        #dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setColumnWidth(6,300)
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.resizeRowsToContents()
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.horizontalHeader().setStretchLastSection(False)
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.horizontalHeader().setStretchLastSection(True)
        
    # All Rows Removed
    else:
        dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setRowCount(0)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesAutorunStartStopClicked(dashboard: QtCore.QObject):
    """ 
    Sends a message to the sensor node to start/stop autorun playlist.
    """
    # Start Clicked
    if dashboard.ui.pushButton_sensor_nodes_autorun_start_stop.text() == "Start":
        # Error with no Sensor Node Selected
        if dashboard.active_sensor_node == -1:
            dashboard.errorMessage("Select an active sensor node.")
            return

        # Retrieve Playlist
        playlist_dict = {}
        playlist_dict['delay_start'] = str(dashboard.ui.checkBox_sensor_nodes_autorun_delay.isChecked())
        playlist_dict['delay_start_time'] = str(dashboard.ui.dateTimeEdit_sensor_nodes_autorun.dateTime().toString('yyyy-MM-dd hh:mm:ss'))  #.toPyDateTime())  # '2024-01-24 14:08:47.182000'
        playlist_dict['repetition_interval_seconds'] = str(dashboard.ui.textEdit_sensor_nodes_autorun_repetition_interval.toPlainText())
        for n in range(0,dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()):
            row_dict = {}      
            try:
                row_dict['type'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,0).text())
            except:
                dashboard.errorMessage("Invalid Type")
                return
            try:
                row_dict['repeat'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,1).currentText())
            except:
                dashboard.errorMessage("Invalid Repeat Value")
                return
            try:
                row_dict['timeout_seconds'] = str(int(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,2).text()))
            except:
                dashboard.errorMessage("Invalid Timeout Value")
                return
            try:
                row_dict['delay'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,3).isChecked())
            except:
                dashboard.errorMessage("Invalid Delay Value")
                return
            try:
                row_dict['start_time'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,4).time().toString('hh:mm:ss'))
            except:
                dashboard.errorMessage("Invalid Start Time Value")
                return                      
            try:
                row_dict['details'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,5).text())
            except:
                dashboard.errorMessage("Invalid Details Value")
                return
            try:
                row_dict['variable_names'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,6).text())
            except:
                dashboard.errorMessage("Invalid Variable Names Value")
                return
            try:
                row_dict['variable_values'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,7).text())
            except:
                dashboard.errorMessage("Invalid Variable Values Value")
                return
            playlist_dict[n] = row_dict
        
        # Trigger Parameters
        trigger_values = []
        for row in range(0, dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.rowCount()):
            trigger_values.append([str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,0).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,1).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,2).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,3).text())])
    
        # Send the Message
        await dashboard.backend.autorunPlaylistStart(dashboard.active_sensor_node, playlist_dict, trigger_values)

        # Toggle the Text
        dashboard.ui.pushButton_sensor_nodes_autorun_start_stop.setText("Stop")
        
    # Stop Clicked
    elif dashboard.ui.pushButton_sensor_nodes_autorun_start_stop.text() == "Stop":
        # Send the Message
        await dashboard.backend.autorunPlaylistStop(dashboard.active_sensor_node)

        # Toggle the Text
        dashboard.ui.pushButton_sensor_nodes_autorun_start_stop.setText("Start")


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesAutorunOverwriteClicked(dashboard: QtCore.QObject):
    """ 
    Sends a message to the sensor node to overwrite the default autorun playlist.
    """
    # Error with no Sensor Node Selected
    if dashboard.active_sensor_node == -1:
        dashboard.errorMessage("Select an active sensor node.")
        return

    # Retrieve Playlist
    playlist_dict = {}
    playlist_dict['delay_start'] = str(dashboard.ui.checkBox_sensor_nodes_autorun_delay.isChecked())
    playlist_dict['delay_start_time'] = str(dashboard.ui.dateTimeEdit_sensor_nodes_autorun.dateTime().toString('yyyy-MM-dd hh:mm:ss'))  #.toPyDateTime())  # '2024-01-24 14:08:47.182000'
    playlist_dict['repetition_interval_seconds'] = str(dashboard.ui.textEdit_sensor_nodes_autorun_repetition_interval.toPlainText())
    for n in range(0,dashboard.ui.tableWidget_sensor_nodes_autorun.rowCount()):
        row_dict = {}      
        try:
            row_dict['type'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,0).text())
        except:
            dashboard.errorMessage("Invalid Type")
            return
        try:
            row_dict['repeat'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,1).currentText())
        except:
            dashboard.errorMessage("Invalid Repeat Value")
            return
        try:
            row_dict['timeout_seconds'] = str(int(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,2).text()))
        except:
            dashboard.errorMessage("Invalid Timeout Value")
            return
        try:
            row_dict['delay'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,3).isChecked())
        except:
            dashboard.errorMessage("Invalid Delay Value")
            return
        try:
            row_dict['start_time'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,4).time().toString('hh:mm:ss'))
        except:
            dashboard.errorMessage("Invalid Start Time Value")
            return                  
        try:
            row_dict['details'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,5).text())
        except:
            dashboard.errorMessage("Invalid Details Value")
            return
        try:
            row_dict['variable_names'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,6).text())
        except:
            dashboard.errorMessage("Invalid Variable Names Value")
            return
        try:
            row_dict['variable_values'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,7).text())
        except:
            dashboard.errorMessage("Invalid Variable Values Value")
            return
        playlist_dict[n] = row_dict

    # Trigger Parameters
    trigger_values = []
    for row in range(0, dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.rowCount()):
        trigger_values.append([str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,0).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,1).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,2).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,3).text())])
    playlist_dict['trigger_values'] = trigger_values

    # Send the Message
    await dashboard.backend.overwriteDefaultAutorunPlaylist(dashboard.active_sensor_node, playlist_dict)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Refreshes the tree widget of sensor node folders.
    """
    # Update the Tree Widget
    get_folder = str(dashboard.ui.comboBox_sensor_nodes_fn_folder.currentText())
    if (dashboard.active_sensor_node > -1) and (len(get_folder) > 0):
        get_sensor_node = ['sensor_node1','sensor_node2','sensor_node3','sensor_node4','sensor_node5']
        dashboard.ui.label1_sensor_nodes_fn_sensor_node.setText("Sensor Node " + str(dashboard.active_sensor_node+1))
        dashboard.ui.tableWidget_sensor_nodes_fn_files.setRowCount(0)
        
        # Local
        if dashboard.backend.settings[get_sensor_node[dashboard.active_sensor_node]]['nickname'] == 'Local Sensor Node':
            folder_path = os.path.join(fissure.utils.SENSOR_NODE_DIR, get_folder.replace("/",""))
            
            for fname in os.listdir(folder_path):
                filepath = os.path.join(folder_path, fname)
                if os.path.isfile(filepath):
                    get_type = "File"
                else:
                    get_type = "Folder"
                path_item = QtWidgets.QTableWidgetItem(filepath)
                size_item = QtWidgets.QTableWidgetItem(str(os.path.getsize(filepath)))
                type_item = QtWidgets.QTableWidgetItem(get_type)
                modified_item = QtWidgets.QTableWidgetItem(str(time.strftime("%m/%d/%Y %-I:%M %p", time.gmtime(os.path.getmtime(filepath)))))
                dashboard.ui.tableWidget_sensor_nodes_fn_files.setRowCount(dashboard.ui.tableWidget_sensor_nodes_fn_files.rowCount() + 1)
                dashboard.ui.tableWidget_sensor_nodes_fn_files.setItem(dashboard.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,0,path_item)
                dashboard.ui.tableWidget_sensor_nodes_fn_files.setItem(dashboard.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,1,size_item)
                dashboard.ui.tableWidget_sensor_nodes_fn_files.setItem(dashboard.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,2,type_item)
                dashboard.ui.tableWidget_sensor_nodes_fn_files.setItem(dashboard.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,3,modified_item)    
                    
            # Resize Table            
            dashboard.ui.tableWidget_sensor_nodes_fn_files.resizeColumnsToContents()
            dashboard.ui.tableWidget_sensor_nodes_fn_files.horizontalHeader().setStretchLastSection(False)
            dashboard.ui.tableWidget_sensor_nodes_fn_files.horizontalHeader().setStretchLastSection(True)
            dashboard.ui.tableWidget_sensor_nodes_fn_files.setColumnWidth(0,800)
            dashboard.ui.tableWidget_sensor_nodes_fn_files.resizeRowsToContents()

        # Remote
        else:
            # Send the Message
            await dashboard.backend.refreshSensorNodeFiles(dashboard.active_sensor_node, get_folder)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationDeleteClicked(dashboard: QtCore.QObject):
    """ 
    Deletes a folder or file on the sensor node.
    """
    # Get Folder/File
    try:
        get_item_path = str(dashboard.ui.tableWidget_sensor_nodes_fn_files.item(dashboard.ui.tableWidget_sensor_nodes_fn_files.currentRow(),0).text())
    except:
        dashboard.errorMessage("Select a file to delete.")
        return
    
    # Delete the Folder/File
    if (dashboard.active_sensor_node > -1) and (len(get_item_path) > 0):            
        # qm = QtWidgets.QMessageBox
        # ret = qm.question(dashboard,'', "Are you sure?", qm.Yes | qm.No)
        ret = await dashboard.ask_confirmation("Are you sure?")
        if ret == QtWidgets.QMessageBox.Yes:
            # Local
            get_sensor_node = ['sensor_node1','sensor_node2','sensor_node3','sensor_node4','sensor_node5']
            if dashboard.backend.settings[get_sensor_node[dashboard.active_sensor_node]]['nickname'] == 'Local Sensor Node':
                os.system('rm -Rf "' + get_item_path + '"')
                
            # Remote
            else:
                # Send the Message
                await dashboard.backend.deleteSensorNodeFile(dashboard.active_sensor_node, get_item_path)

            dashboard.ui.tableWidget_sensor_nodes_fn_files.removeRow(dashboard.ui.tableWidget_sensor_nodes_fn_files.currentRow())
            await _slotSensorNodesFileNavigationRefreshClicked(dashboard)
        else:
            return


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationDownloadClicked(dashboard: QtCore.QObject):
    """ 
    Downloads a folder or file from the sensor node.
    """
    # Get Folder/File
    try:
        get_item_path = str(dashboard.ui.tableWidget_sensor_nodes_fn_files.item(dashboard.ui.tableWidget_sensor_nodes_fn_files.currentRow(),0).text())
    except:
        dashboard.errorMessage("Select a file to download.")
        return            
    
    # Download the Folder/File
    if (dashboard.active_sensor_node > -1) and (len(get_item_path) > 0):
        # Local
        get_sensor_node = ['sensor_node1','sensor_node2','sensor_node3','sensor_node4','sensor_node5']
        if dashboard.backend.settings[get_sensor_node[dashboard.active_sensor_node]]['nickname'] == 'Local Sensor Node':
            get_new_path = str(dashboard.ui.comboBox_sensor_nodes_fn_local_folder.currentText()) + '/' + get_item_path.split('/')[-1]
            os.system('cp -r "' + get_item_path + '" "' + get_new_path + '"')
            
        # Remote
        else:
            # Send the Message
            get_new_path = str(dashboard.ui.comboBox_sensor_nodes_fn_local_folder.currentText())
            await dashboard.backend.downloadSensorNodeFile(dashboard.active_sensor_node, get_item_path, get_new_path)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationLocalTransferClicked(dashboard: QtCore.QObject):
    """ 
    Transfers a local file to the selected sensor node folder.
    """
    if dashboard.active_sensor_node > -1:
        # Obtain File Information
        get_local_file = str(dashboard.ui.treeView_sensor_nodes_fn_local_files.model().filePath(dashboard.ui.treeView_sensor_nodes_fn_local_files.currentIndex()))
        if os.path.isfile(get_local_file):
            get_remote_folder = str(dashboard.ui.comboBox_sensor_nodes_fn_folder.currentText())
            refresh_file_list = True
            
            # Send the Message
            await dashboard.backend.transferSensorNodeFile(dashboard.active_sensor_node, get_local_file, get_remote_folder, refresh_file_list)
