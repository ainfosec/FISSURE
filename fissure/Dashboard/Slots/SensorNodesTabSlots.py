from PyQt5 import QtCore, QtWidgets, QtGui
import os
import fissure.utils
import yaml
import datetime
from ..UI_Components import TriggersDialog
import qasync
import time
import asyncio
import ast
from fissure.Dashboard.Slots import AttackTabSlots
import json
import csv
import re
from fissure.utils.selected_node_utils import (
    selected_node_is_local,
    selected_node_is_remote,
    selected_node_is_ip,
    selected_node_is_meshtastic,
)

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
            

def _sensor_nodes_file_navigation_node_label(
    dashboard: QtCore.QObject,
) -> str:
    """
    Returns the display label for the selected Sensor Node.
    """
    node_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    if not node_uid:
        return "Sensor Node: —"

    settings = (
        getattr(
            dashboard,
            "selected_node_settings",
            {},
        )
        or {}
    )

    nickname = str(
        settings.get(
            "nickname"
        )
        or settings.get(
            "name"
        )
        or ""
    ).strip()

    if not nickname:
        node_state = (
            getattr(
                dashboard,
                "node_states",
                {},
            )
            or {}
        ).get(
            node_uid,
            {},
        )

        if isinstance(
            node_state,
            dict,
        ):
            nickname = str(
                node_state.get(
                    "nickname"
                )
                or node_state.get(
                    "name"
                )
                or node_state.get(
                    "callsign"
                )
                or ""
            ).strip()

    if nickname:
        return (
            f"Sensor Node: {nickname} "
            f"({node_uid})"
        )

    return f"Sensor Node: {node_uid}"


def initialize_sensor_nodes_file_navigation_controls(
    dashboard: QtCore.QObject,
):
    """
    Initializes the Sensor Nodes File Navigation node gate.
    """
    dashboard.ui.stackedWidget_sensor_nodes_fn_node_gate.setCurrentWidget(
        dashboard.ui.page_sensor_nodes_fn_no_node
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

        dashboard.ui.label_sensor_nodes_fn_select_sensor_node_image.setPixmap(
            select_node_pixmap
        )

        dashboard.ui.label_sensor_nodes_fn_select_sensor_node_image.setScaledContents(
            False
        )

        dashboard.ui.label_sensor_nodes_fn_select_sensor_node_image.setAlignment(
            QtCore.Qt.AlignCenter
        )

    update_sensor_nodes_file_navigation_selected_node_gate(
        dashboard
    )


def update_sensor_nodes_file_navigation_selected_node_gate(
    dashboard: QtCore.QObject,
):
    """
    Show File Navigation controls only when an online Sensor Node is selected.
    """
    selected_uid = str(
        getattr(
            dashboard,
            "selected_node_uid",
            "",
        )
        or ""
    ).strip()

    has_selected_node = bool(
        selected_uid
    )

    if has_selected_node:
        node_states = (
            getattr(
                dashboard,
                "node_states",
                {},
            )
            or {}
        )

        node_state = node_states.get(
            selected_uid
        )

        if (
            isinstance(
                node_state,
                dict,
            )
            and node_state.get(
                "connected"
            ) is False
        ):
            has_selected_node = False

    dashboard.ui.stackedWidget_sensor_nodes_fn_node_gate.setCurrentWidget(
        dashboard.ui.page_sensor_nodes_fn_controls
        if has_selected_node
        else dashboard.ui.page_sensor_nodes_fn_no_node
    )


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
    if dashboard.selected_node_uid:
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
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Type")
                return
            try:
                row_dict['repeat'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,1).currentText())
            except:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Repeat Value")
                return
            try:
                row_dict['timeout_seconds'] = str(int(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,2).text()))
            except:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Timeout Value")
                return
            try:
                row_dict['delay'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,3).isChecked())
            except:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Delay Value")
                return
            try:
                row_dict['start_time'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,4).time().toString('hh:mm:ss'))
            except:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Start Time Value")
                return                                        
            try:
                row_dict['details'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,5).text())
            except:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Details Value")
                return
            try:
                row_dict['variable_names'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,6).text())
            except:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Variable Names Value")
                return
            try:
                row_dict['variable_values'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,7).text())
            except:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Variable Values Value")
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
        fissure.Dashboard.Slots.AttackTabSlots._slotAttackMultiStageImportClicked(dashboard, fname="n/a", data_override=formatted_data)
        
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
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Unable to refresh autorun playlists")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalDeleteClicked(dashboard: QtCore.QObject):
    """
    Deletes a selected local folder or file.
    """
    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()

    if not current_index.isValid():
        return

    get_item_path = str(tree_view.model().filePath(current_index) or "").strip()

    if not get_item_path or not os.path.exists(get_item_path):
        return

    qm = QtWidgets.QMessageBox
    ret = qm.question(dashboard, "", "Are you sure?", qm.Yes | qm.No)

    if ret != qm.Yes:
        return

    os.system('rm -Rf "' + get_item_path + '"')


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
def _slotSensorNodesFileNavigationLocalSelectClicked(dashboard: QtCore.QObject):
    """
    Uses the selected local folder as the File Navigation root.

    If a file is selected, its parent folder is used.
    """
    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()

    if not current_index.isValid():
        return

    selected_path = str(tree_view.model().filePath(current_index) or "").strip()

    if not selected_path:
        return

    if os.path.isfile(selected_path):
        selected_path = os.path.dirname(selected_path)

    if not os.path.isdir(selected_path):
        return

    folder_combo = dashboard.ui.comboBox_sensor_nodes_fn_local_folder
    existing_index = folder_combo.findText(selected_path, QtCore.Qt.MatchExactly)

    if existing_index >= 0:
        folder_combo.setCurrentIndex(existing_index)
    else:
        folder_combo.addItem(selected_path)
        folder_combo.setCurrentIndex(folder_combo.count() - 1)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalShowInFolderClicked(dashboard: QtCore.QObject):
    """
    Opens the selected local item location in the system file manager.

    If nothing is selected, opens the current Local Folder.
    """
    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()
    selected_path = ""

    if current_index.isValid():
        selected_path = str(tree_view.model().filePath(current_index) or "").strip()

    if selected_path and os.path.isfile(selected_path):
        folder_path = os.path.dirname(selected_path)
    elif selected_path and os.path.isdir(selected_path):
        folder_path = selected_path
    else:
        folder_path = str(dashboard.ui.comboBox_sensor_nodes_fn_local_folder.currentText() or "").strip()

    if not os.path.isdir(folder_path):
        return

    QtGui.QDesktopServices.openUrl(QtCore.QUrl.fromLocalFile(folder_path))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalUnzipClicked(dashboard: QtCore.QObject):
    """
    Unzips a selected local zip file.
    """
    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()

    if not current_index.isValid():
        return

    get_zip_file = str(tree_view.model().filePath(current_index) or "").strip()

    if not get_zip_file:
        return

    if not os.path.isfile(get_zip_file):
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select a zip file.")
        return

    if not get_zip_file.lower().endswith(".zip"):
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Cannot unzip file.")
        return

    os.system('unzip "' + get_zip_file + '" -d "' + get_zip_file[:-4] + '"')


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesFileNavigationLocalViewClicked(dashboard: QtCore.QObject):
    """
    Opens a selected local text file when it is small enough to view.
    """
    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()

    if not current_index.isValid():
        return

    get_file = str(tree_view.model().filePath(current_index) or "").strip()

    if not get_file or not os.path.isfile(get_file):
        return

    number_of_bytes = os.path.getsize(get_file)

    if number_of_bytes > 1000000:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("File is too large to view.")
        return

    if get_file.lower().endswith(".txt"):
        os.system('gedit "' + get_file + '" &')
    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Not a valid file extension.")


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
async def _slotSensorNodesAutorunStartClicked(dashboard: QtCore.QObject):
    """ 
    Sends a message to the sensor node to start/stop autorun playlist.
    """
    # Error with no Sensor Node Selected
    if not dashboard.selected_node_uid:
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Select an active sensor node.")
        return

    # Run As Stored
    if dashboard.ui.checkBox_sensor_nodes_autorun_run_as_stored.isChecked() == True:
        get_filename = str(dashboard.ui.textEdit_sensor_nodes_autorun_playlist_filename.toPlainText())
        if get_filename.strip() == "":
            ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Enter playlist filename.")
            return
        
        # Send the Message
        if selected_node_is_ip(dashboard):
            await dashboard.backend.autorunPlaylistExecute(dashboard.selected_node_uid, get_filename)
        if selected_node_is_meshtastic(dashboard):
            await dashboard.backend.autorunPlaylistExecuteLT(dashboard.selected_node_uid, get_filename) 

    # Transfer Playlist to Sensor Node
    else:
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
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid Type")
                return
            try:
                row_dict['repeat'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,1).currentText())
            except:
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid Repeat Value")
                return
            try:
                row_dict['timeout_seconds'] = str(int(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,2).text()))
            except:
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid Timeout Value")
                return
            try:
                row_dict['delay'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,3).isChecked())
            except:
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid Delay Value")
                return
            try:
                row_dict['start_time'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,4).time().toString('hh:mm:ss'))
            except:
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid Start Time Value")
                return                      
            try:
                row_dict['details'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,5).text())
            except:
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid Details Value")
                return
            try:
                row_dict['variable_names'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,6).text())
            except:
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid Variable Names Value")
                return
            try:
                row_dict['variable_values'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,7).text())
            except:
                ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Invalid Variable Values Value")
                return
            playlist_dict[n] = row_dict
        
        # Trigger Parameters
        trigger_values = []
        for row in range(0, dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.rowCount()):
            trigger_values.append([str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,0).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,1).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,2).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,3).text())])
    
        # Send the Message
        await dashboard.backend.autorunPlaylistStart(dashboard.selected_node_uid, playlist_dict, trigger_values)

    # Toggle the Text
    if selected_node_is_ip(dashboard):
        dashboard.ui.pushButton_sensor_nodes_autorun_start.setEnabled(False)
        dashboard.ui.pushButton_sensor_nodes_autorun_stop.setEnabled(True)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesAutorunStopClicked(dashboard: QtCore.QObject):
    """ 
    Sends a message to the sensor node to stop the autorun playlist.
    """
    if selected_node_is_ip(dashboard):
        # Send the Message
        await dashboard.backend.autorunPlaylistStop(dashboard.selected_node_uid)
        
        # Swap Buttons
        dashboard.ui.pushButton_sensor_nodes_autorun_start.setEnabled(True)
        dashboard.ui.pushButton_sensor_nodes_autorun_stop.setEnabled(False)

    elif selected_node_is_meshtastic(dashboard):
        # Send the Message
        await dashboard.backend.autorunPlaylistStopLT(dashboard.selected_node_uid)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesAutorunOverwriteClicked(dashboard: QtCore.QObject):
    """ 
    Sends a message to the sensor node to overwrite the default autorun playlist.
    """
    # Error with no Sensor Node Selected
    if not dashboard.selected_node_uid:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Select an active sensor node.")
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
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Type")
            return
        try:
            row_dict['repeat'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,1).currentText())
        except:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Repeat Value")
            return
        try:
            row_dict['timeout_seconds'] = str(int(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,2).text()))
        except:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Timeout Value")
            return
        try:
            row_dict['delay'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,3).isChecked())
        except:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Delay Value")
            return
        try:
            row_dict['start_time'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.cellWidget(n,4).time().toString('hh:mm:ss'))
        except:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Start Time Value")
            return                  
        try:
            row_dict['details'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,5).text())
        except:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Details Value")
            return
        try:
            row_dict['variable_names'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,6).text())
        except:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Variable Names Value")
            return
        try:
            row_dict['variable_values'] = str(dashboard.ui.tableWidget_sensor_nodes_autorun.item(n,7).text())
        except:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Invalid Variable Values Value")
            return
        playlist_dict[n] = row_dict

    # Trigger Parameters
    trigger_values = []
    for row in range(0, dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.rowCount()):
        trigger_values.append([str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,0).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,1).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,2).text()), str(dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.item(row,3).text())])
    playlist_dict['trigger_values'] = trigger_values

    # Send the Message
    await dashboard.backend.overwriteDefaultAutorunPlaylist(dashboard.selected_node_uid, playlist_dict)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Refreshes the tree widget of sensor node folders.
    """
    # Update the Tree Widget
    get_folder = str(dashboard.ui.comboBox_sensor_nodes_fn_folder.currentText())
    if (dashboard.selected_node_uid) and (len(get_folder) > 0):
        dashboard.ui.label1_sensor_nodes_fn_sensor_node.setText(
            _sensor_nodes_file_navigation_node_label(
                dashboard
            )
        )
        dashboard.ui.tableWidget_sensor_nodes_fn_files.setRowCount(0)
        
        # Local
        if selected_node_is_local(dashboard):
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
            await dashboard.backend.refreshSensorNodeFiles(dashboard.selected_node_uid, get_folder)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationDeleteClicked(dashboard: QtCore.QObject):
    """
    Deletes a selected folder or file on the Sensor Node.
    """
    if not dashboard.selected_node_uid:
        return

    table = dashboard.ui.tableWidget_sensor_nodes_fn_files
    current_row = table.currentRow()

    if current_row < 0:
        return

    path_item = table.item(current_row, 0)

    if path_item is None:
        return

    get_item_path = str(path_item.text() or "").strip()

    if not get_item_path:
        return

    ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(
        dashboard,
        "Are you sure?",
    )

    if ret != QtWidgets.QMessageBox.Yes:
        return

    if selected_node_is_local(dashboard):
        os.system('rm -Rf "' + get_item_path + '"')
    else:
        await dashboard.backend.deleteSensorNodeFile(
            dashboard.selected_node_uid,
            get_item_path,
        )

    table.removeRow(current_row)
    await _slotSensorNodesFileNavigationRefreshClicked(dashboard)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationDownloadClicked(dashboard: QtCore.QObject):
    """
    Downloads a selected folder or file from the Sensor Node.
    """
    if not dashboard.selected_node_uid:
        return

    table = dashboard.ui.tableWidget_sensor_nodes_fn_files
    current_row = table.currentRow()

    if current_row < 0:
        return

    path_item = table.item(current_row, 0)

    if path_item is None:
        return

    get_item_path = str(path_item.text() or "").strip()

    if not get_item_path:
        return

    get_local_folder = str(
        dashboard.ui.comboBox_sensor_nodes_fn_local_folder.currentText() or ""
    ).strip()

    if not get_local_folder:
        return

    if selected_node_is_local(dashboard):
        get_new_path = os.path.join(
            get_local_folder,
            os.path.basename(get_item_path),
        )
        os.system('cp -r "' + get_item_path + '" "' + get_new_path + '"')
    else:
        await dashboard.backend.downloadSensorNodeFile(
            dashboard.selected_node_uid,
            get_item_path,
            get_local_folder,
        )


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesFileNavigationLocalTransferClicked(dashboard: QtCore.QObject):
    """
    Transfers a selected local file to the selected Sensor Node folder.
    """
    if not dashboard.selected_node_uid:
        return

    tree_view = dashboard.ui.treeView_sensor_nodes_fn_local_files
    current_index = tree_view.currentIndex()

    if not current_index.isValid():
        return

    get_local_file = str(tree_view.model().filePath(current_index) or "").strip()

    if not get_local_file or not os.path.isfile(get_local_file):
        return

    get_remote_folder = str(dashboard.ui.comboBox_sensor_nodes_fn_folder.currentText() or "").strip()

    if not get_remote_folder:
        return

    await dashboard.backend.transferSensorNodeFile(
        dashboard.selected_node_uid,
        get_local_file,
        get_remote_folder,
        True,
    )


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAutorunTriggersClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the list of triggers.
    """
    # Remove Rows
    dashboard.ui.tableWidget1_sensor_nodes_autorun_triggers.setRowCount(0)


def update_sensor_node_title(dashboard: QtCore.QObject, change: int):
    # get current number
    current_text = dashboard.ui.tabWidget.tabBar().tabText(6)
    if "(" in current_text and ")" in current_text:
        base_text, count = current_text.rsplit("(", 1)
        count = count.rstrip(")")
        try:
            current_count = int(count)
        except ValueError:
            current_count = 0
    else:
        base_text = current_text
        current_count = 0

    new_count = max([0, current_count + change])
    if new_count == 0:
        new_text = base_text.strip()
    else:
        new_text = f"{base_text.strip()} ({new_count})"
    dashboard.ui.tabWidget.tabBar().setTabText(6, new_text)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAlertsClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Alerts text edit and resets the tab color.
    """
    # Clear
    dashboard.ui.textEdit2_sensor_nodes_alerts.clear()

    # get count from current title
    current_text = dashboard.ui.tabWidget_sensor_nodes.tabBar().tabText(3)
    if "(" in current_text and ")" in current_text:
        base_text, count = current_text.rsplit("(", 1)
        count = count.rstrip(")")
        try:
            current_count = int(count)
        except ValueError:
            current_count = 0
    else:
        base_text = current_text
        current_count = 0

    # Reset Alerts Tab Text
    dashboard.ui.tabWidget_sensor_nodes.tabBar().setTabText(3,"Alerts")

    # Update Sensor Nodes Tab Text
    update_sensor_node_title(dashboard, -current_count)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesAlertsSaveClicked(dashboard: QtCore.QObject):
    """ 
    Saves the alerts to a text file.
    """
    # Define the default directory
    directory = os.path.join(fissure.utils.LOG_DIR, "Session Logs")

    # Open the Save File Dialog
    dialog = QtWidgets.QFileDialog()
    dialog.setDirectory(directory)
    dialog.setFilter(dialog.filter() | QtCore.QDir.Hidden)
    dialog.setDefaultSuffix('txt')
    dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
    dialog.setNameFilters(['Text Files (*.txt)'])
    
    if dialog.exec_() == QtWidgets.QDialog.Accepted:
        # Get the selected file path
        fname = dialog.selectedFiles()[0]

        # Ensure the file has the correct extension
        if not fname.lower().endswith(".txt"):
            fname += ".txt"

        try:
            # Write the text content to the file
            with open(fname, 'w', encoding='utf-8') as new_file:
                new_file.write(dashboard.ui.textEdit2_sensor_nodes_alerts.toPlainText())
            print(f"File saved successfully at: {fname}")
        except Exception as e:
            print(f"Error saving file: {e}")
    else:
        print("File save dialog was canceled.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesExploitsClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Listed Exploits text edit and resets the tab color.
    """
    tableWidget_exploits: QtWidgets.QTableWidget = dashboard.ui.tableWidget_exploits

    # Clear
    row_count = tableWidget_exploits.rowCount()
    tableWidget_exploits.setRowCount(0)

    tableWidget_exploits.horizontalHeader().setVisible(True) # set header visible in code; qt designer always sets to false

    # Reset Alerts Tab Text
    dashboard.ui.tabWidget_sensor_nodes.tabBar().setTabText(4,"Exploits")

    # Reset Sensor Nodes Tab Text
    update_sensor_node_title(dashboard, -row_count)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesExploitsRunClicked(dashboard: QtCore.QObject):
    """ 
    Saves the alerts to a text file.
    """
    if dashboard.ui.pushButton_attack_start_stop.text() == "Start Attack" and dashboard.ui.pushButton_attack_fuzzing_start.text() == "Start Attack":
        # get table
        table: QtWidgets.QTableWidget = dashboard.ui.tableWidget_exploits
        table.horizontalHeader().setVisible(True) # set header visible in code; qt designer always sets to false

        # get the fields from the table entry
        row = table.selectedItems()
        fields = {}
        for r in row:
            fields[int(r.column())] = r.text()

        # switch to single-stage attack tab
        toptab: QtWidgets.QTabWidget = dashboard.ui.tabWidget
        toptab.setCurrentIndex(3) # switch to attack tab
        subtab: QtWidgets.QTabWidget = dashboard.ui.tabWidget_attack_attack
        subtab.setCurrentIndex(0) # switch to Single-Stage

        # switch to protocol
        comboBox_attack_protocols: QtWidgets.QComboBox = dashboard.ui.comboBox_attack_protocols
        for i in range(comboBox_attack_protocols.count()):
            if comboBox_attack_protocols.itemText(i).lower() == fields.get(0).lower():
                comboBox_attack_protocols.setCurrentIndex(i)
                break
        AttackTabSlots._slotAttackProtocols(dashboard)

        # switch to modulation
        comboBox_attack_modulation: QtWidgets.QComboBox = dashboard.ui.comboBox_attack_modulation
        for i in range(comboBox_attack_modulation.count()):
            if comboBox_attack_modulation.itemText(i).lower() == fields.get(1).lower():
                comboBox_attack_modulation.setCurrentIndex(i)
                break
        AttackTabSlots._slotAttackModulationChanged(dashboard)

        # switch to hardware
        comboBox_attack_hardware: QtWidgets.QComboBox = dashboard.ui.comboBox_attack_hardware
        for i in range(comboBox_attack_hardware.count()):
            if str(fields.get(2)).lower() in str(comboBox_attack_hardware.itemText(i)).lower():
                comboBox_attack_hardware.setCurrentIndex(i)
                break
        AttackTabSlots._slotAttackHardwareChanged(dashboard)

        # select attack
        treeWidget_attack_attacks: QtWidgets.QTreeWidget = dashboard.ui.treeWidget_attack_attacks
        tree_item_string = comboBox_attack_protocols.currentText() + " - " + fields.get(4)  # protocol - attack_name
        treeWidget_attack_attacks.setCurrentItem(treeWidget_attack_attacks.findItems(tree_item_string, QtCore.Qt.MatchExactly|QtCore.Qt.MatchRecursive,0)[0])

        # load attack
        AttackTabSlots._slotAttackLoadTemplateClicked(dashboard)

        # set detected exploit variables
        variables = json.loads(str(fields.get(5)))
        table_vars:QtWidgets.QTableWidget = dashboard.ui.tableWidget1_attack_flow_graph_current_values
        for i in range(table_vars.rowCount()):
            variable = table_vars.verticalHeaderItem(i).text()
            if variable in variables.keys():
                table_vars.item(i, 0).setText(str(variables.get(variable)))

    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Stop the current attack to stage an exploit")

@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesReportsClearClicked(dashboard: QtCore.QObject):
    """ 
    Clears the Listed Reports and resets the tab color.
    """
    tableWidget_reports: QtWidgets.QTableWidget = dashboard.ui.tableWidget_reports

    # Clear
    row_count = tableWidget_reports.rowCount()
    tableWidget_reports.setRowCount(0)

    # Reset Tab Text
    dashboard.ui.tabWidget_sensor_nodes.tabBar().setTabText(5,"Reports")

    # Reset Sensor Nodes Tab Text
    update_sensor_node_title(dashboard, -row_count)
    #dashboard.ui.tabWidget.tabBar().setTabText(6,"Sensor Nodes")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodeAutorunRunAsStoredChecked(dashboard: QtCore.QObject):
    """ 
    Enables/Disables the Autorun controls.
    """
    # Checked
    if dashboard.ui.checkBox_sensor_nodes_autorun_run_as_stored.isChecked():
        dashboard.ui.frame_sensor_nodes_autorun_controls.setEnabled(False)
        dashboard.ui.label2_sensor_nodes_autorun_playlist_filename.setEnabled(True)
        dashboard.ui.textEdit_sensor_nodes_autorun_playlist_filename.setEnabled(True)
    
    # Unchecked
    else:
        dashboard.ui.frame_sensor_nodes_autorun_controls.setEnabled(True)
        dashboard.ui.label2_sensor_nodes_autorun_playlist_filename.setEnabled(False)
        dashboard.ui.textEdit_sensor_nodes_autorun_playlist_filename.setEnabled(False)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesListenersMeshtasticInfoClicked(dashboard: QtCore.QObject):
    """ 
    Opens a dialog of potential serial ports.
    """
    # Issue the Command
    path = "/dev/serial/by-id/"
    if os.path.exists(path):
        output_text = os.popen(f"ls -l {path}").read()
    else:
        output_text = "No serial devices found"

    # Open a Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, output_text)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesListenersSaveClicked(dashboard: QtCore.QObject):
    """ 
    Transfers the listener information to the table.
    """
    # Save by Type
    status = "Disabled"
    get_type = str(dashboard.ui.comboBox_sensor_nodes_listeners_type.currentText())
    get_name = str(dashboard.ui.textEdit_sensor_nodes_listeners_name.toPlainText()).strip()
    get_parameters = {}

    if not get_name:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter listener name.")
        return

    if get_type == "Meshtastic":
        get_parameters["serial_port"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_meshtastic_serial_port.toPlainText())
        get_parameters["baud_rate"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_meshtastic_baud_rate.toPlainText())

        if not get_parameters["serial_port"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter serial port (e.g. /dev/ttyACM0).")
            return

        if not get_parameters["baud_rate"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter baud rate.")
            return
        
    elif get_type == "ZMQ SUB":
        get_parameters["ip_address"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_zmq_ip_address.toPlainText())
        get_parameters["port"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_zmq_port.toPlainText())
        get_parameters["topic_filter"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_zmq_topic.toPlainText())

        if not get_parameters["ip_address"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter IP address.")
            return

        if not get_parameters["port"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter port.")
            return
                
    elif get_type == "Website Poller":
        get_parameters["url"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_website_url.toPlainText())
        get_parameters["check_interval"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_website_interval.toPlainText())

        if not get_parameters["url"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter URL.")
            return

        if not get_parameters["check_interval"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter check interval.")
            return
        
    elif get_type == "Serial Port":
        get_parameters["serial_port"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_serial_serial_port.toPlainText())
        get_parameters["baud_rate"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_serial_baud_rate.toPlainText())

        if not get_parameters["serial_port"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter serial port (e.g. /dev/ttyACM0).")
            return

        if not get_parameters["baud_rate"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter baud rate.")
            return
        
    elif get_type == "TCP/UDP":
        get_parameters["protocol"] = str(dashboard.ui.comboBox_sensor_nodes_listeners_tcp_udp_protocol.currentText())
        get_parameters["ip_address"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_tcp_udp_ip_address.toPlainText())
        get_parameters["port"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_tcp_udp_port.toPlainText())

        if not get_parameters["ip_address"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter IP address.")
            return

        if not get_parameters["port"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter port.")
            return
        
    elif get_type == "Filesystem":
        get_filesystem_type = str(dashboard.ui.comboBox_sensor_nodes_listeners_filesystem_type.currentText())
        if get_filesystem_type == "New Files":
            get_parameters["folder"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_filesytem_folder.toPlainText()).strip()
            get_parameters["file_pattern"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_filesystem_pattern.toPlainText())

            if not get_parameters["folder"]:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter folder location.")
                return
            
        elif get_filesystem_type == "File Changes":
            get_parameters["filepath"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_filesystem_filepath.toPlainText()).strip()

            if not get_parameters["filepath"]:
                fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter filepath location.")
                return

    elif get_type == "MQTT":
        get_parameters["broker_address"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_broker_address.toPlainText())
        get_parameters["port"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_port.toPlainText())
        get_parameters["topic"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_topic.toPlainText())
        get_parameters["username"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_username.toPlainText())
        get_parameters["password"] = str(dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_password.toPlainText())

        if not get_parameters["broker_address"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter broker address.")
            return
        
        if not get_parameters["port"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter port.")
            return
        
        if not get_parameters["topic"]:
            fissure.Dashboard.UI_Components.Qt5.errorMessage("Enter topic.")
            return        

    # Reference to the table widget
    table = dashboard.ui.tableWidget_sensor_nodes_listeners

    # Check if the listener with the same name already exists
    existing_row = None
    for row in range(table.rowCount()):
        if table.item(row, 2) and table.item(row, 2).text() == get_name:  # Column 2 is "Name"
            existing_row = row
            break

    if existing_row is not None:
        # Check if the existing listener is disabled
        current_status = table.item(existing_row, 0).text()  # Status is in column 0
        if current_status.lower() != "disabled":
            # Show a popup informing the user to disable the listener first
            fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Listener '{get_name}' must be disabled before editing.")
            return
        row = existing_row
    else:
        # Add a new row to the table
        row = table.rowCount()
        table.insertRow(row)

    # Create table items with alignment
    status_item = QtWidgets.QTableWidgetItem(status)
    status_item.setTextAlignment(QtCore.Qt.AlignCenter)

    type_item = QtWidgets.QTableWidgetItem(get_type)
    type_item.setTextAlignment(QtCore.Qt.AlignCenter)

    name_item = QtWidgets.QTableWidgetItem(get_name)
    name_item.setTextAlignment(QtCore.Qt.AlignCenter)

    parameters_item = QtWidgets.QTableWidgetItem(str(get_parameters))
    parameters_item.setTextAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)

    # Populate the row with the listener data
    table.setItem(row, 0, status_item)      # Status Column (Centered)
    table.setItem(row, 1, type_item)        # Type Column (Centered)
    table.setItem(row, 2, name_item)        # Name Column (Centered)
    table.setItem(row, 3, parameters_item)  # Parameters Column (Left-Aligned)

    # Automatically scroll to the new/updated row
    table.scrollToItem(table.item(row, 0))


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesListenersEditClicked(dashboard: QtCore.QObject):
    """ 
    Copies information from the table into the New Listener section.
    """
    table = dashboard.ui.tableWidget_sensor_nodes_listeners
    selected_items = table.selectedItems()

    if not selected_items:
        fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Please select a listener to edit.")
        return

    # Get the selected row index
    selected_row = selected_items[0].row()

    # Extract data from the selected row
    # status = table.item(selected_row, 0).text()
    listener_type = table.item(selected_row, 1).text()
    listener_name = table.item(selected_row, 2).text()
    parameters_text = table.item(selected_row, 3).text()
    parameters = ast.literal_eval(parameters_text)

    # Update the UI elements with the extracted values
    dashboard.ui.comboBox_sensor_nodes_listeners_type.setCurrentText(listener_type)
    dashboard.ui.textEdit_sensor_nodes_listeners_name.setPlainText(listener_name)

    # Populate parameter fields based on the listener type
    if listener_type == "Meshtastic":
        dashboard.ui.textEdit_sensor_nodes_listeners_meshtastic_serial_port.setPlainText(parameters.get("serial_port", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_meshtastic_baud_rate.setPlainText(parameters.get("baud_rate", ""))
    elif listener_type == "ZMQ SUB":
        dashboard.ui.textEdit_sensor_nodes_listeners_zmq_ip_address.setPlainText(parameters.get("ip_address", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_zmq_port.setPlainText(parameters.get("port", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_zmq_topic.setPlainText(parameters.get("topic_filter", ""))
    elif listener_type == "Website Poller":
        dashboard.ui.textEdit_sensor_nodes_listeners_website_url.setPlainText(parameters.get("url", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_website_interval.setPlainText(parameters.get("check_interval", ""))
    elif listener_type == "Serial Port":
        dashboard.ui.textEdit_sensor_nodes_listeners_serial_serial_port.setPlainText(parameters.get("serial_port", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_serial_baud_rate.setPlainText(parameters.get("baud_rate", ""))
    elif listener_type == "TCP/UDP":
        dashboard.ui.comboBox_sensor_nodes_listeners_tcp_udp_protocol.setCurrentText(parameters.get("protocol", "TCP"))
        dashboard.ui.textEdit_sensor_nodes_listeners_tcp_udp_ip_address.setPlainText(parameters.get("ip_address", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_tcp_udp_port.setPlainText(parameters.get("port", ""))
    elif listener_type == "Filesystem":
        dashboard.ui.textEdit_sensor_nodes_listeners_filesytem_folder.setPlainText(parameters.get("folder", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_filesystem_pattern.setPlainText(parameters.get("file_pattern", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_filesystem_filepath.setPlainText(parameters.get("filepath", ""))

        filepath = parameters.get("filepath", "")
        if filepath:
            dashboard.ui.comboBox_sensor_nodes_listeners_filesystem_type.setCurrentText("File Changes")
        else:
            dashboard.ui.comboBox_sensor_nodes_listeners_filesystem_type.setCurrentText("New Files")
    elif listener_type == "MQTT":
        dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_broker_address.setPlainText(parameters.get("broker_address", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_port.setPlainText(parameters.get("port", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_topic.setPlainText(parameters.get("topic", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_username.setPlainText(parameters.get("username", ""))
        dashboard.ui.textEdit_sensor_nodes_listeners_mqtt_password.setPlainText(parameters.get("password", ""))

    
@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesListenersDeleteClicked(dashboard: QtCore.QObject):
    """ 
    Deletes the selected row in the table and sends a message to the HIPRFISR to delete the listener.
    """
    table = dashboard.ui.tableWidget_sensor_nodes_listeners
    selected_items = table.selectedItems()

    if not selected_items:
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Please select a listener to delete.")
        return

    # Get the selected row index
    selected_row = selected_items[0].row()
    listener_name = table.item(selected_row, 2).text()  # Assuming 'Name' is in column 2

    # Confirmation dialog before deletion
    ret = await fissure.Dashboard.UI_Components.Qt5.async_yes_no_dialog(dashboard, f"Are you sure you want to delete listener '{listener_name}'?")
    if ret == QtWidgets.QMessageBox.No:
        return

    # Send the Message
    await dashboard.backend.deleteListener(listener_name)


@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesListenersEnableDisableClicked(dashboard: QtCore.QObject):
    """ 
    Opens a dialog of potential serial ports.
    """
    table = dashboard.ui.tableWidget_sensor_nodes_listeners
    selected_items = table.selectedItems()

    if not selected_items:
        ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(dashboard, "Please select a listener to enable/disable.")
        return

    # Get the selected row index
    selected_row = selected_items[0].row()

    # Extract data from the selected row
    # status = table.item(selected_row, 0).text()
    listener_type = table.item(selected_row, 1).text()
    listener_name = table.item(selected_row, 2).text()
    parameters_text = table.item(selected_row, 3).text()
    parameters = ast.literal_eval(parameters_text)

    # Send the Message
    await dashboard.backend.enableDisableListener(listener_type, listener_name, parameters) 


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesListenersFilesystemFolderBrowseClicked(dashboard: QtCore.QObject):
    """ 
    Chooses a folder to monitor.
    """
    # Select a Directory
    dialog = QtWidgets.QFileDialog(dashboard)
    dialog.setFileMode(QtWidgets.QFileDialog.Directory)
    dialog.setOption(QtWidgets.QFileDialog.ShowDirsOnly, True)

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_sensor_nodes_listeners_filesytem_folder.setText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesListenersFilesystemFilepathBrowseClicked(dashboard: QtCore.QObject):
    """ 
    Chooses a file to monitor.
    """
    # Select a File
    dialog = QtWidgets.QFileDialog(dashboard)
    directory = fissure.utils.FISSURE_ROOT  # Default Directory
    dialog.setDirectory(directory)
    # dialog.setNameFilters(['IQ/Misc. (*.iq *.dat)','IQ Recordings (*.iq)','Misc. (*.dat)'])

    if dialog.exec_():
        for d in dialog.selectedFiles():
            folder = d
    try:
        dashboard.ui.textEdit_sensor_nodes_listeners_filesystem_filepath.setPlainText(folder)
    except:
        pass


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSensorNodesReportsSaveClicked(dashboard: QtCore.QObject):
    """ 
    Saves the reports from `tableWidget_reports` to a .txt or .csv file.
    """
    # Define the default directory
    directory = os.path.join(fissure.utils.LOG_DIR, "Session Logs")

    # Open the Save File Dialog
    dialog = QtWidgets.QFileDialog()
    dialog.setDirectory(directory)
    dialog.setFilter(dialog.filter() | QtCore.QDir.Hidden)
    dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
    dialog.setNameFilters(["Text Files (*.txt)", "CSV Files (*.csv)"])

    if dialog.exec_() == QtWidgets.QDialog.Accepted:
        # Get the selected file path
        fname = dialog.selectedFiles()[0]

        # Get the selected filter (CSV or TXT)
        selected_filter = dialog.selectedNameFilter()

        # Ensure the correct file extension based on the selected filter
        if "CSV Files" in selected_filter:
            file_format = "csv"
            if not fname.lower().endswith(".csv"):
                fname += ".csv"
        else:
            file_format = "txt"
            if not fname.lower().endswith(".txt"):
                fname += ".txt"

        try:
            # Extract data from tableWidget_reports
            table = dashboard.ui.tableWidget_reports
            row_count = table.rowCount()
            col_count = table.columnCount()

            if file_format == "txt":
                with open(fname, "w", encoding="utf-8") as file:
                    for row in range(row_count):
                        row_data = []
                        for col in range(col_count):
                            item = table.item(row, col)
                            row_data.append(item.text() if item else "")
                        file.write(" | ".join(row_data) + "\n")  # Format for readability
            else:  # CSV format
                with open(fname, "w", newline="", encoding="utf-8") as file:
                    writer = csv.writer(file)
                    # Write header row (if available)
                    headers = [table.horizontalHeaderItem(col).text() if table.horizontalHeaderItem(col) else f"Column {col+1}" for col in range(col_count)]
                    writer.writerow(headers)
                    # Write table rows
                    for row in range(row_count):
                        writer.writerow([table.item(row, col).text() if table.item(row, col) else "" for col in range(col_count)])

            dashboard.logger.info(f"File saved successfully at: {fname}")
        except Exception as e:
            dashboard.logger.error(f"Error saving file: {e}")
    else:
        dashboard.logger.debug("File save dialog was canceled.")

@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesPluginSelected(dashboard: QtCore.QObject):
    """ 
    Slot to handle the selection of a plugin from the dropdown.
    This will populate the operations list with the available operations for the selected plugin.
    """
    # Get selected plugin
    selected_plugin = str(dashboard.ui.comboBox_select_plugin.currentText())

    # Clear previous operations
    combobox_ops: QtWidgets.QComboBox = dashboard.ui.comboBox_select_plugin_op
    combobox_ops.clear()
    params_table: QtWidgets.QTableWidget = dashboard.ui.tableWidget_plugin_op_params
    params_table.setRowCount(0)  # Clear previous parameters
    res_table: QtWidgets.QTableWidget = dashboard.ui.tableWidget_plugin_op_resources
    res_table.setRowCount(0)  # Clear previous resources
    iface_table: QtWidgets.QTableWidget = dashboard.ui.tableWidget_plugin_op_interfaces
    iface_table.setRowCount(0)  # Clear previous interface

    # If no plugin is selected, return
    if not selected_plugin:
        return

    # Send request to get plugin parameters
    PARAMETERS = {
        "plugin": selected_plugin,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
        fissure.comms.MessageFields.MESSAGE_NAME: "plugin_get_operations",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await dashboard.backend.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesOperationRun(dashboard: QtCore.QObject):
    """ 
    Slot to run a plugin operation.
    """
    # Get parameters for the plugin operation
    parameters = {}
    params_table: QtWidgets.QTableWidget = dashboard.ui.tableWidget_plugin_op_params
    for row in range(params_table.rowCount()):
        value_item = params_table.item(row, 0)  # User entered value
        if value_item is None:
            required = bool(params_table.item(row, 2)) # get required state
            if required:
                value_item = params_table.item(row, 1)  # default value
                if value_item is None:
                    fissure.Dashboard.UI_Components.Qt5.errorMessage(f"Parameter '{params_table.verticalHeaderItem(row).text()}' is required but not provided.")
                    return
                parameters[params_table.verticalHeaderItem(row).text()] = value_item.text()

        else:
            parameters[params_table.verticalHeaderItem(row).text()] = value_item.text()

    combobox_plugin: QtWidgets.QComboBox = dashboard.ui.comboBox_select_plugin
    combobox_op: QtWidgets.QComboBox = dashboard.ui.comboBox_select_plugin_op
    PARAMETERS = {
        "node_uid": dashboard.selected_node_uid,
        "plugin": combobox_plugin.currentText(),
        "operation": combobox_op.currentText(),
        "parameters": parameters
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
        fissure.comms.MessageFields.MESSAGE_NAME: "run_plugin_operation",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await dashboard.backend.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesOperationStop(dashboard: QtCore.QObject):
    """ 
    Slot to stop a plugin operation.
    """
    ops_table: QtWidgets.QListWidget = dashboard.ui.listWidget_operations
    selected_items = ops_table.selectedItems()
    if not selected_items:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Please select an operation to stop.")
        return
    selected_item = selected_items[0]
    selected_text = selected_item.text()
    match = re.search(r"\(ID:\s*([a-fA-F0-9\-]+)\)", selected_text)
    if match:
        operation_id = match.group(1)
    else:
        fissure.Dashboard.UI_Components.Qt5.errorMessage("Could not extract operation ID from selection.")
        return

    PARAMETERS = {
        "node_uid": dashboard.selected_node_uid,
        "operation_id": operation_id,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
        fissure.comms.MessageFields.MESSAGE_NAME: "stop_plugin_operation",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await dashboard.backend.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

@qasync.asyncSlot(QtCore.QObject)
async def _slotSensorNodesPluginOperationOpen(dashboard: QtCore.QObject):
    """ 
    Slot to open a plugin operation.
    """
    combobox_plugin: QtWidgets.QComboBox = dashboard.ui.comboBox_select_plugin
    combobox_op: QtWidgets.QComboBox = dashboard.ui.comboBox_select_plugin_op
    PARAMETERS = {
        "plugin": combobox_plugin.currentText(),
        "operation": combobox_op.currentText(),
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
        fissure.comms.MessageFields.MESSAGE_NAME: "plugin_get_operation_parameters",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await dashboard.backend.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)