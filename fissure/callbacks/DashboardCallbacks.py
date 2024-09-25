import fissure.comms
import time
from PyQt5 import QtCore, QtWidgets
import yaml
import os
import subprocess
import threading
import ast
import asyncio

from fissure.Dashboard.UI_Components.Qt5 import MyMessageBox
# from ..Dashboard.Slots import StatusBarSlots  # how do you go from callbacks to slots?
from fissure.Dashboard.Slots import (
    ArchiveTabSlots,
    AttackTabSlots,
    DashboardSlots,
    IQDataTabSlots,
    LibraryTabSlots,
    LogTabSlots,
    MenuBarSlots,
    PDTabSlots,
    SensorNodesTabSlots,
    StatusBarSlots,
    TopBarSlots,
    TSITabSlots,
)

from fissure.Dashboard.UI_Components.Qt5 import (
    # CustomColor,
    # JointPlotDialog,
    # MiscChooser,
    # MyMessageBox,
    MyPlotWindow,
    # NewSOI,
    # OperationsThread,
    # OptionsDialog,
    # SigMF_Dialog,
    # TreeModel,
    # TreeNode,
    # TrimSettings,
)


async def flowGraphFinished(component: object, sensor_node_id=0, category=""):
    """
    Update the Dashboard in response to a flow graph finished message.
    """
    # Perform Action
    if category == "PD":
        if component.frontend.ui.pushButton_pd_flow_graphs_start_stop.text() == "Stop":
            # Toggle the Text
            component.frontend.ui.pushButton_pd_flow_graphs_start_stop.setText("Start")

            # Disable Apply Button
            component.frontend.ui.pushButton_pd_flow_graphs_apply_changes.setEnabled(False)

            # Update Flow Graph Status Labels
            component.frontend.ui.label2_pd_flow_graphs_status.setText("Stopped")
            component.frontend.ui.label2_pd_status_flow_graph_status.setText("Stopped")

            # Update the Status Dialog               
            component.frontend.statusbar_text[sensor_node_id][2] = "Not Running"
            component.frontend.refreshStatusBarText()

    elif category == "Attack":
        # Single-Stage
        if component.frontend.ui.pushButton_attack_start_stop.text() == "Stop Attack":
            # Toggle the Text
            component.frontend.ui.pushButton_attack_start_stop.setText("Start Attack")

            # Disable Apply Button
            component.frontend.ui.pushButton_attack_apply_changes.setEnabled(False)

            # Update Flow Graph Status Label
            component.frontend.ui.label2_attack_flow_graph_status.setText("Stopped")

            # Enable Attack Switching
            component.frontend.ui.comboBox_attack_protocols.setEnabled(True)
            component.frontend.ui.comboBox_attack_modulation.setEnabled(True)
            component.frontend.ui.comboBox_attack_hardware.setEnabled(True)

            # Enabled All Values for Editing
            for get_row in range(component.frontend.ui.tableWidget1_attack_flow_graph_current_values.rowCount()):
                get_value_item = component.frontend.ui.tableWidget1_attack_flow_graph_current_values.takeItem(get_row,0)
                get_value_item.setFlags(get_value_item.flags() | QtCore.Qt.ItemIsEditable)
                get_value_item.setFlags(get_value_item.flags() | QtCore.Qt.ItemIsEnabled)
                component.frontend.ui.tableWidget1_attack_flow_graph_current_values.setItem(get_row,0,get_value_item)

        # Fuzzing
        if component.frontend.ui.pushButton_attack_fuzzing_start.text() == "Stop Attack":
            # Toggle the Text
            component.frontend.ui.pushButton_attack_fuzzing_start.setText("Start Attack")  ######

            # Disable Apply Button
            component.frontend.ui.pushButton_attack_fuzzing_apply_changes.setEnabled(False) #######

            # Update Flow Graph Status Label
            component.frontend.ui.label2_attack_fuzzing_flow_graph_status.setText("Stopped") ######

            # Enabled All Values for Editing
            for get_row in range(component.frontend.ui.tableWidget_attack_fuzzing_flow_graph_current_values.rowCount()):
                get_value_item = component.frontend.ui.tableWidget_attack_fuzzing_flow_graph_current_values.takeItem(get_row,0)
                get_value_item.setFlags(get_value_item.flags() | QtCore.Qt.ItemIsEditable)
                get_value_item.setFlags(get_value_item.flags() | QtCore.Qt.ItemIsEnabled)
                component.frontend.ui.tableWidget_attack_fuzzing_flow_graph_current_values.setItem(get_row,0,get_value_item)

        # Update the Status Dialog
        component.frontend.statusbar_text[sensor_node_id][3] = "Not Running"
        component.frontend.refreshStatusBarText()


async def flowGraphStarted(component: object, sensor_node_id=0, category=""):
    """
    Enable the stop buttons and change the status messages to indicate the flow graph is running.
    """
    # Perform Action
    if category == "PD":
        # Update Flow Graph Status Labels
        component.frontend.ui.label2_pd_flow_graphs_status.setText("Running... ")
        component.frontend.ui.pushButton_pd_flow_graphs_start_stop.setEnabled(True)
        component.frontend.ui.label2_pd_status_flow_graph_status.setText("Running... ")

        # Update the Status Dialog
        if component.frontend.active_sensor_node > -1:
            component.frontend.statusbar_text[component.frontend.active_sensor_node][2] = 'Running Flow Graph... ' + str(component.frontend.ui.textEdit_pd_flow_graphs_filepath.toPlainText()).rsplit("/",1)[1]
            component.frontend.refreshStatusBarText()

    elif category == "Attack":
        # Single-Stage
        if component.frontend.ui.tabWidget_attack_attack.currentIndex() == 0:
            # Update Flow Graph Status Label
            component.frontend.ui.label2_attack_flow_graph_status.setText("Running...")
            component.frontend.ui.pushButton_attack_start_stop.setEnabled(True)

        # Fuzzing
        elif component.frontend.ui.tabWidget_attack_attack.currentIndex() == 2:
            # Update Flow Graph Status Label
            component.frontend.ui.label2_attack_fuzzing_flow_graph_status.setText("Running...")
            component.frontend.ui.pushButton_attack_fuzzing_start.setEnabled(True)

        # Update the Status Dialog
        if component.frontend.active_sensor_node > -1:
            component.frontend.statusbar_text[component.frontend.active_sensor_node][3] = 'Running Flow Graph...'
            component.frontend.refreshStatusBarText()


async def archivePlaylistPosition(component: object, sensor_node_id=0, position=0):
    """ 
    Highlights the active archive playlist flow graph in the table.
    """        
    # Select Table Row
    try:
        component.frontend.ui.tableWidget_archive_replay.selectRow(int(position))
    except:
        component.logger.error("Invalid row value")
        
    # Update the Status Dialog
    component.frontend.statusbar_text[sensor_node_id][5] = "Replaying file in row " + str(position)
    component.frontend.refreshStatusBarText()


async def archivePlaylistFinished(component: object, sensor_node_id=0):
    """ 
    Changes the pushbuttons and labels upon receiving a message from the sensor node.
    """        
    # Change the Pushbuttons and Labels
    component.frontend.ui.pushButton_archive_replay_start.setText("Start")
    component.frontend.ui.label2_archive_replay_status.setVisible(False)

    # Update the Status Dialog
    component.frontend.statusbar_text[sensor_node_id][5] = "Not Running"
    component.frontend.refreshStatusBarText()


async def hardwareGuessResults(component: object, tab_index=0, table_row=[], hardware_type="", scan_results="", new_guess_index=0):
    """
    Fills the scan results table row with hardware information in HardwareSelectDialog.
    """
    # Fill the Table
    component.frontend.popups["HardwareSelectDialog"].guessReturn(tab_index, table_row, hardware_type, scan_results, new_guess_index)


async def hardwareProbeResults(component: object, tab_index=0, output="", height_width=[]):
    """
    Returns the probe results to the HardwareSelectDialog.
    """
    # Parse Return String
    probe_text = output
    
    # Hide Label
    scan_results_labels = [
        component.frontend.popups["HardwareSelectDialog"].label2_scan_results_probe_1,
        component.frontend.popups["HardwareSelectDialog"].label2_scan_results_probe_2,
        component.frontend.popups["HardwareSelectDialog"].label2_scan_results_probe_3,
        component.frontend.popups["HardwareSelectDialog"].label2_scan_results_probe_4,
        component.frontend.popups["HardwareSelectDialog"].label2_scan_results_probe_5
    ]
    scan_results_labels[int(tab_index)].setVisible(False)

    # Enable Probe Button
    probe_buttons = [
        component.frontend.popups["HardwareSelectDialog"].pushButton_scan_results_probe_1,
        component.frontend.popups["HardwareSelectDialog"].pushButton_scan_results_probe_2,
        component.frontend.popups["HardwareSelectDialog"].pushButton_scan_results_probe_3,
        component.frontend.popups["HardwareSelectDialog"].pushButton_scan_results_probe_4,
        component.frontend.popups["HardwareSelectDialog"].pushButton_scan_results_probe_5
    ]
    probe_buttons[int(tab_index)].setEnabled(True)

    # Open a Text Dialog
    if height_width[0] == '':
        msgBox = MyMessageBox(my_text = probe_text)
    else:
        msgBox = MyMessageBox(my_text = probe_text, height=height_width[0], width=height_width[1])
    msgBox.exec_()
    

async def hardwareScanResults(component: object, tab_index=0, hardware_scan_results=[]):
    """
    Returns Auto Scan results to the HardwareSelectDialog.
    """
    component.frontend.popups["HardwareSelectDialog"].scanReturn(tab_index=tab_index, all_scan_results=hardware_scan_results)


async def recallSettingsReturn(component: object, settings_dict={}):
    """
    Populates the HardwareSelectDialog with the sensor node settings on connect.
    """
    # Pass Sensor Node Settings to HardwareSelectDialog
    component.frontend.popups["HardwareSelectDialog"].importResults(settings_dict=settings_dict)


async def componentDisconnected(component: object, component_name=""):
    """
    Update status bar and other widgets with new connection status.
    """
    if component_name == fissure.comms.Identifiers.DASHBOARD:
        pass
    elif component_name == fissure.comms.Identifiers.TSI:
        component.frontend.signals.ComponentStatus.emit(fissure.comms.Identifiers.TSI, False, component.frontend.statusBar())
    elif component_name == fissure.comms.Identifiers.PD:
        component.frontend.signals.ComponentStatus.emit(fissure.comms.Identifiers.PD, False, component.frontend.statusBar())
    else:
        try:
            sensor_node_id = int(component_name)
        except:
            return
        if sensor_node_id == 0:
            component.frontend.signals.ComponentStatus.emit("Sensor Node 0", False, component.frontend.statusBar())
            component.sensor_node_connected[0] = False
        elif sensor_node_id == 1:
            component.frontend.signals.ComponentStatus.emit("Sensor Node 1", False, component.frontend.statusBar())
            component.sensor_node_connected[1] = False
        elif sensor_node_id == 2:
            component.frontend.signals.ComponentStatus.emit("Sensor Node 2", False, component.frontend.statusBar())
            component.sensor_node_connected[2] = False
        elif sensor_node_id == 3:
            component.frontend.signals.ComponentStatus.emit("Sensor Node 3", False, component.frontend.statusBar())
            component.sensor_node_connected[3] = False
        elif sensor_node_id == 4:
            component.frontend.signals.ComponentStatus.emit("Sensor Node 4", False, component.frontend.statusBar())
            component.sensor_node_connected[4] = False
        component.frontend.popups["HardwareSelectDialog"].sensorNodeDisconnected(tab_index=sensor_node_id)


async def componentConnected(component: object, component_name=""):
    """
    Update status bar and other widgets with new connection status.
    """
    if component_name == fissure.comms.Identifiers.PD:
        component.frontend.signals.ComponentStatus.emit(fissure.comms.Identifiers.PD, True, component.frontend.statusBar())
    elif component_name == fissure.comms.Identifiers.TSI:
        component.frontend.signals.ComponentStatus.emit(fissure.comms.Identifiers.TSI, True, component.frontend.statusBar())
    elif component_name == fissure.comms.Identifiers.DASHBOARD:
        pass
    else:
        # Modify the Button
        try:
            sensor_node_id = int(component_name)
        except:
            return
        if sensor_node_id == 0:
            component.frontend.signals.ComponentStatus.emit("Sensor Node 0", True, component.frontend.statusBar())
            component.sensor_node_connected[0] = True
        elif sensor_node_id == 1:
            component.frontend.signals.ComponentStatus.emit("Sensor Node 1", True, component.frontend.statusBar())
            component.sensor_node_connected[1] = True
        elif sensor_node_id == 2:
            component.frontend.signals.ComponentStatus.emit("Sensor Node 2", True, component.frontend.statusBar())
            component.sensor_node_connected[2] = True
        elif sensor_node_id == 3:
            component.frontend.signals.ComponentStatus.emit("Sensor Node 3", True, component.frontend.statusBar())
            component.sensor_node_connected[3] = True
        elif sensor_node_id == 4:
            component.frontend.signals.ComponentStatus.emit("Sensor Node 4", True, component.frontend.statusBar())
            component.sensor_node_connected[4] = True
        component.frontend.popups["HardwareSelectDialog"].sensorNodeConnected(tab_index=sensor_node_id)


async def bandID_Return(component: object, sensor_node_id=0, band_id=0, frequency=0):
    """ 
    Updates the search bands plot with the current band and center frequency of the detector.
    """
    if component.frontend.ui.pushButton_tsi_detector_start.text() == "Stop":

        #component.frontend.ui.tuning_matplotlib_widget.axes.cla()  # TEST

        # Get the Band and Current Frequency
        center_freq = frequency
        center_freq = round(float(center_freq)/1e6,2)  # In MHz, two decimal places

        # Update the Labels
        component.frontend.ui.label2_tsi_current_band.setText(str(band_id))
        component.frontend.ui.label2_tsi_current_frequency.setText(str(center_freq) + " MHz")

        # Change the Band Text in the Plot
        for col in range(0,len(component.frontend.tuning_widget.bands)):
            ## Get Band Position
            #start_x,y = component.frontend.tuning_widget.bands[col].get_xy()

            # Change the Band Labels
            if band_id-1 < len(component.frontend.tuning_widget.axes.texts):
                if col == band_id-1:
                    component.frontend.tuning_widget.axes.texts[col].set_color('red')
                else:
                    component.frontend.tuning_widget.axes.texts[col].set_color('black')

        # Update Tuner
        get_bandwidth = int(float(str(component.frontend.ui.textEdit_tsi_detector_fg_sample_rate.toPlainText()))/1000000)
        if get_bandwidth < 1:
            get_bandwidth = 1
        component.frontend.tuning_widget.updateTuned(int(band_id),int(center_freq),get_bandwidth)  # Rectangle width = sample_rate in MS/s rounded down

        # Redraw the Plot
        component.frontend.tuning_widget.draw()


async def detectorReturn(component: object, frequency_value=0, power_value=0, time_value=0.0):
    """ 
    Adds a TSI Detector signal to the waterfall plot and the list.
    """
    # Plot a Point
    frequency_value = frequency_value/1e6
    if component.frontend.wideband_zoom == True:
        labels = component.frontend.matplotlib_widget.axes.get_xticklabels()
        try:
            start_freq = float(str(labels[0]).split("'")[1])
            end_freq = float(str(labels[-1]).split("'")[1])
        except:
            start_freq = 0
            end_freq = 6000e6
        plot_x = 600 * (frequency_value-start_freq)/(end_freq-start_freq)
    else:
        plot_x = frequency_value/10  # Frequencies: 0 - 6000, X-Values: 0-600

    component.frontend.matplotlib_widget.plotPoint(plot_x, 11, component.frontend.matplotlib_widget.computeColormapValue(power_value), 5, component.frontend.wideband_data)

    # Add it to the Table
    component.frontend.ui.tableWidget1_tsi_wideband.setRowCount(component.frontend.ui.tableWidget1_tsi_wideband.rowCount()+1)

    # Frequency
    frequency_item = QtWidgets.QTableWidgetItem(str(frequency_value))
    frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
    component.frontend.ui.tableWidget1_tsi_wideband.setItem(component.frontend.ui.tableWidget1_tsi_wideband.rowCount()-1,0,frequency_item)

    # Power
    power_item = QtWidgets.QTableWidgetItem(str(power_value))
    power_item.setTextAlignment(QtCore.Qt.AlignCenter)
    component.frontend.ui.tableWidget1_tsi_wideband.setItem(component.frontend.ui.tableWidget1_tsi_wideband.rowCount()-1,1,power_item)

    # Time
    get_time = time.strftime('%H:%M:%S', time.localtime(time_value))  # time format?
    time_item = QtWidgets.QTableWidgetItem(get_time)
    time_item.setTextAlignment(QtCore.Qt.AlignCenter)
    component.frontend.ui.tableWidget1_tsi_wideband.setItem(component.frontend.ui.tableWidget1_tsi_wideband.rowCount()-1,2,time_item)  # Will this cause sorting problems going from 12:59 to 1:00 or 23:59 to 0:00?

    # Sort by Time
    component.frontend.ui.tableWidget1_tsi_wideband.sortItems(2,order=QtCore.Qt.DescendingOrder)

    # Resize Table Columns and Rows
    component.frontend.ui.tableWidget1_tsi_wideband.resizeColumnsToContents()
    component.frontend.ui.tableWidget1_tsi_wideband.resizeRowsToContents()
    component.frontend.ui.tableWidget1_tsi_wideband.horizontalHeader().setStretchLastSection(False)
    component.frontend.ui.tableWidget1_tsi_wideband.horizontalHeader().setStretchLastSection(True)


async def conditionerProgressBarReturn(component: object, progress=0, file_index=0):
    """ 
    Updates the TSI Conditioner progress bar.
    """
    # Update the Progress Bar
    progress_value = progress
    if int(progress) < 100:
        component.frontend.ui.progressBar_tsi_conditioner_operation.setValue(int(progress))
        if component.frontend.ui.comboBox_tsi_conditioner_settings_input_source.currentText() == "Folder":
            component.frontend.ui.listWidget_tsi_conditioner_input_files.setCurrentRow(file_index)
            TSITabSlots._slotTSI_ConditionerInputLoadFileClicked(component.frontend)


async def tsiConditionerFinished(component: object, table_strings=[]):
    """ 
    Acting on a TSI Conditioner Finished message from the TSI Component.
    """                
    # File Count
    component.frontend.ui.label2_tsi_conditioner_results_file_count.setText("File Count: " + str(len(table_strings)))
                    
    # Clear Table
    for row in reversed(range(0,component.frontend.ui.tableWidget_tsi_conditioner_results.rowCount())):
        component.frontend.ui.tableWidget_tsi_conditioner_results.removeRow(row)
            
    # Row
    for n in range(0,len(table_strings)):
        component.frontend.ui.tableWidget_tsi_conditioner_results.setRowCount(component.frontend.ui.tableWidget_tsi_conditioner_results.rowCount()+1)
        
        # Column
        for m in range(0,len(table_strings[0])):            
            table_item = QtWidgets.QTableWidgetItem(table_strings[n][m])
            table_item.setTextAlignment(QtCore.Qt.AlignCenter)
            component.frontend.ui.tableWidget_tsi_conditioner_results.setItem(component.frontend.ui.tableWidget_tsi_conditioner_results.rowCount()-1,m,table_item)

    # Resize Table
    component.frontend.ui.tableWidget_tsi_conditioner_results.resizeRowsToContents()
    component.frontend.ui.tableWidget_tsi_conditioner_results.resizeColumnsToContents()
    component.frontend.ui.tableWidget_tsi_conditioner_results.horizontalHeader().setStretchLastSection(False)
    component.frontend.ui.tableWidget_tsi_conditioner_results.horizontalHeader().setStretchLastSection(True)
    
    # Set Progress Bar
    component.frontend.ui.progressBar_tsi_conditioner_operation.setValue(100)
    component.frontend.ui.pushButton_tsi_conditioner_operation_start.setText("Start")
    
    # Refresh FE Listbox
    TSITabSlots._slotTSI_FE_InputRefreshClicked(component.frontend)


async def feProgressBarReturn(component: object, progress=0, file_index=0):
    """ 
    Updates the TSI Conditioner progress bar.
    """
    # Update the Progress Bar
    if int(progress) < 100:
        component.frontend.ui.progressBar_tsi_fe_operation.setValue(int(progress))
        if component.frontend.ui.comboBox_tsi_fe_settings_input_source.currentText() == "Folder":
            component.frontend.ui.listWidget_tsi_fe_input_files.setCurrentRow(file_index)
            TSITabSlots._slotTSI_FE_InputLoadFileClicked(component.frontend)


async def tsiFE_Finished(component: object, table_strings=[]):
    """ 
    Acting on a TSI Conditioner Finished message from the TSI Component.
    """       
    # Set Selection to Last Item in Listbox
    component.frontend.ui.listWidget_tsi_fe_input_files.setCurrentRow(len(table_strings)-2)

    # Clear Table
    component.frontend.ui.tableWidget_tsi_fe_results.clear()
            
    # Row
    component.frontend.ui.tableWidget_tsi_fe_results.setColumnCount(len(table_strings[0])-1)
    for n in range(0,len(table_strings)):
        # Column Headers
        if n == 0:
            for m in range(1,len(table_strings[0])):
                component.frontend.ui.tableWidget_tsi_fe_results.setHorizontalHeaderItem(m-1,QtWidgets.QTableWidgetItem(table_strings[n][m]))  
        
        else:
            component.frontend.ui.tableWidget_tsi_fe_results.setRowCount(component.frontend.ui.tableWidget_tsi_fe_results.rowCount()+1)
            
            # Column
            for m in range(0,len(table_strings[0])):
                # File/Row Headers
                if m == 0:
                    table_item = QtWidgets.QTableWidgetItem(table_strings[n][m])
                    table_item.setTextAlignment(QtCore.Qt.AlignCenter)
                    component.frontend.ui.tableWidget_tsi_fe_results.setVerticalHeaderItem(n-1,table_item)
        
                # Table Cells                    
                else:
                    table_item = QtWidgets.QTableWidgetItem(table_strings[n][m])
                    table_item.setTextAlignment(QtCore.Qt.AlignCenter)
                    component.frontend.ui.tableWidget_tsi_fe_results.setItem(component.frontend.ui.tableWidget_tsi_fe_results.rowCount()-1,m-1,table_item)
            
    # Resize Table
    component.frontend.ui.tableWidget_tsi_fe_results.resizeRowsToContents()
    component.frontend.ui.tableWidget_tsi_fe_results.resizeColumnsToContents()
    component.frontend.ui.tableWidget_tsi_fe_results.horizontalHeader().setStretchLastSection(False)
    component.frontend.ui.tableWidget_tsi_fe_results.horizontalHeader().setStretchLastSection(True)
        
    # Set Progress Bar
    component.frontend.ui.progressBar_tsi_fe_operation.setValue(100)
    component.frontend.ui.pushButton_tsi_fe_operation_start.setText("Start")


async def flowGraphStartedIQ(component: object, sensor_node_id=0):
    """ 
    This will be called in response to "Flow Graph Started IQ" Messages from Sensor Node.
    The purpose is to check the enable the cancel buttons and change the status messages to indicate the IQ flow graph is running.
    """        
    # Update the Pushbutton and Label
    component.frontend.ui.pushButton_iq_record.setEnabled(True)
    try:
        get_number_of_files = str(component.frontend.ui.tableWidget_iq_record.cellWidget(0,5).value())  # Save value from operation start?
    except:
        get_number_of_files = str(component.frontend.ui.tableWidget_iq_record.item(0,5).text())
    component.frontend.ui.label2_iq_status_files.setText("Recording File " + str(component.frontend.iq_file_counter) + " of " + get_number_of_files)

    # Update the Status Dialog
    if component.frontend.active_sensor_node > -1:
        component.frontend.statusbar_text[component.frontend.active_sensor_node][4] = 'Running Flow Graph...'
        component.frontend.refreshStatusBarText()


async def flowGraphStartedIQ_Playback(component: object, sensor_node_id=0):
    """ 
    This will be called in response to "Flow Graph Started IQ" Messages from Sensor Node.
    The purpose is to check the enable the cancel buttons and change the status messages to indicate the IQ flow graph is running.
    """       
    # Update the Pushbutton and Label
    component.frontend.ui.pushButton_iq_playback.setEnabled(True)
    component.frontend.ui.label2_iq_playback_status.setText("Running...")

    # Update the Status Dialog
    if component.frontend.active_sensor_node > -1:
        component.frontend.statusbar_text[component.frontend.active_sensor_node][4] = 'Running Flow Graph...'
        component.frontend.refreshStatusBarText()


async def flowGraphStartedIQ_Inspection(component: object, sensor_node_id=0):
    """
    Inspection flow graph started at sensor node.
    """
    # Future Use
    pass


async def flowGraphStartedSniffer(component: object, sensor_node_id=0, category=""):
    """ 
    Flow graph started message returned from Sensor Node.
    """        
    # Enable the Buttons
    if category == "Stream":
        component.frontend.ui.pushButton_pd_sniffer_stream.setEnabled(True)
    elif category == "Tagged Stream":
        component.frontend.ui.pushButton_pd_sniffer_tagged_stream.setEnabled(True)
    elif category == "Message/PDU":
        component.frontend.ui.pushButton_pd_sniffer_msg_pdu.setEnabled(True)


async def flowGraphFinishedIQ(component: object, sensor_node_id=0):
    """ 
    Called upon cancelling IQ recording. Changes the status and button text.
    """       
    # Change Status Label and Record Button Text
    component.frontend.ui.label2_iq_status_files.setText("Not Recording")
    component.frontend.statusbar_text[sensor_node_id][4] = 'Not Recording'
    component.frontend.refreshStatusBarText()

    # Refresh File List
    IQDataTabSlots._slotIQ_RefreshClicked(component.frontend)

    # Get Folder and File of Recording
    get_dir = str(component.frontend.ui.textEdit_iq_record_dir.toPlainText())
    get_file = str(component.frontend.ui.tableWidget_iq_record.item(0,0).text())

    if len(get_dir) > 0 and len(get_file) > 0:

        # Load Directory and File
        folder_index = component.frontend.ui.comboBox3_iq_folders.findText(get_dir)
        if folder_index < 0:
            # New Directory
            component.frontend.ui.comboBox3_iq_folders.addItem(get_dir)
            component.frontend.ui.comboBox3_iq_folders.setCurrentIndex(component.frontend.ui.comboBox3_iq_folders.count()-1)
        else:
            # Directory Exists
            component.frontend.ui.comboBox3_iq_folders.setCurrentIndex(folder_index)

        # Load File
        file_item = component.frontend.ui.listWidget_iq_files.findItems(get_file,QtCore.Qt.MatchExactly|QtCore.Qt.MatchRecursive)
        file_index = component.frontend.ui.listWidget_iq_files.row(file_item[0])
        component.frontend.ui.listWidget_iq_files.setCurrentRow(file_index)
        IQDataTabSlots._slotIQ_LoadIQ_Data(component.frontend)
        IQDataTabSlots._slotIQ_PlotAllClicked(component.frontend)

    # More than One Number of Files
    try:
        get_number_of_files = str(component.frontend.ui.tableWidget_iq_record.cellWidget(0,5).value())  # Save value from operation start?
    except:
        get_number_of_files = str(component.frontend.ui.tableWidget_iq_record.item(0,5).text())
    if int(get_number_of_files) > 1:

        # Update the Counter
        if component.frontend.iq_file_counter != "abort":
            component.frontend.iq_file_counter = component.frontend.iq_file_counter + 1

            # Write SigMF Metadata for Multiple Recordings
            if component.frontend.ui.checkBox_iq_record_sigmf.isChecked() == True:
                if 'core:sha512' in component.frontend.sigmf_dict['global']:
                    proc = subprocess.Popen('sha512sum "' + str(component.frontend.ui.textEdit_iq_record_dir.toPlainText()) + '/' + get_file + '" &', shell=True, stdout=subprocess.PIPE, )
                    output = proc.communicate()[0].decode().split(" ")[0]
                    component.frontend.sigmf_dict['global']['core:sha512'] = str(output)
                if 'core:dataset' in component.frontend.sigmf_dict['global']:
                    component.frontend.sigmf_dict['global']['core:dataset'] = get_file
                if 'core:sample_rate' in component.frontend.sigmf_dict['global']:
                    component.frontend.sigmf_dict['global']['core:sample_rate'] = float(str(component.frontend.ui.tableWidget_iq_record.item(0,7).text()))*1000000
                metadata_filepath = str(component.frontend.ui.textEdit_iq_record_dir.toPlainText()) + '/' + get_file.replace(".sigmf-data",".sigmf-meta")
                component.frontend.writeSigMF(metadata_filepath,component.frontend.sigmf_dict)

            # Update New File Name
            get_file_name = component.frontend.iq_first_file_name
            if '.' in get_file_name:
                get_file_name = get_file_name.split('.')[0] + '_' + str(component.frontend.iq_file_counter) + '.' + get_file_name.split('.')[1]
            else:
                get_file_name = get_file_name + '_' + str(component.frontend.iq_file_counter)
            component.frontend.ui.tableWidget_iq_record.setItem(0,0, QtWidgets.QTableWidgetItem(get_file_name))

        # Do the Next Recording
        if component.frontend.iq_file_counter == "abort":
            component.frontend.iq_file_counter = int(get_number_of_files) + 1
        if component.frontend.iq_file_counter <= int(get_number_of_files):
            get_delay = float(str(component.frontend.ui.tableWidget_iq_record.item(0,9).text()))
            next_record_thread = threading.Timer(get_delay, call_async_function, [component.frontend])
            next_record_thread.start()
            #IQDataTabSlots._slotIQ_RecordClicked()

        # All Done
        else:
            component.frontend.iq_file_counter = 0
            component.frontend.ui.pushButton_iq_record.setText("Record")
    else:
        component.frontend.iq_file_counter = 0
        component.frontend.ui.pushButton_iq_record.setText("Record")

        # Write SigMF Metadata for Single File
        if component.frontend.ui.checkBox_iq_record_sigmf.isChecked() == True:
            if 'core:sha512' in component.frontend.sigmf_dict['global']:
                proc = subprocess.Popen('sha512sum "' + str(component.frontend.ui.textEdit_iq_record_dir.toPlainText()) + '/' + get_file + '" &', shell=True, stdout=subprocess.PIPE, )
                output = proc.communicate()[0].decode().split(" ")[0]
                component.frontend.sigmf_dict['global']['core:sha512'] = str(output)
            if 'core:dataset' in component.frontend.sigmf_dict['global']:
                component.frontend.sigmf_dict['global']['core:dataset'] = get_file
            if 'core:sample_rate' in component.frontend.sigmf_dict['global']:
                component.frontend.sigmf_dict['global']['core:sample_rate'] = float(str(component.frontend.ui.tableWidget_iq_record.item(0,7).text()))*1000000
            metadata_filepath = str(component.frontend.ui.textEdit_iq_record_dir.toPlainText()) + '/' + get_file.replace(".sigmf-data",".sigmf-meta")
            component.frontend.writeSigMF(metadata_filepath,component.frontend.sigmf_dict)


# Function to wrap the async function call
def call_async_function(component: object):
    # Create a new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(IQDataTabSlots._slotIQ_RecordClicked(component, True))
    loop.close()  # Close the loop when done
    

async def flowGraphFinishedIQ_Inspection(component: object, sensor_node_id=0):
    """
    Inspection flow graph finished at sensor node.
    """
    # Future Use
    pass


async def flowGraphFinishedIQ_Playback(component: object, sensor_node_id=0):
    """ 
    Called upon cancelling IQ playback. Changes the status and button text.
    """
    # Change Status Label and Record Button Text
    component.frontend.ui.label2_iq_playback_status.setText("Not Running")
    component.frontend.ui.pushButton_iq_playback.setText("Play")
    component.frontend.ui.pushButton_iq_playback.setEnabled(True)
    component.frontend.statusbar_text[sensor_node_id][4] = 'Not Recording'
    component.frontend.refreshStatusBarText()


async def flowGraphFinishedSniffer(component: object, sensor_node_id=0, category=""):
    """ 
    Flow graph finished message returned from Sensor Node.
    """
    # Enable the Buttons
    component.frontend.ui.pushButton_pd_sniffer_stream.setText("Sniffer - Stream")
    component.frontend.ui.pushButton_pd_sniffer_tagged_stream.setText("Sniffer - Tagged Str.")
    component.frontend.ui.pushButton_pd_sniffer_msg_pdu.setText("Sniffer - Msg/PDU")
    component.frontend.ui.pushButton_pd_sniffer_stream.setEnabled(True)
    component.frontend.ui.pushButton_pd_sniffer_tagged_stream.setEnabled(True)
    component.frontend.ui.pushButton_pd_sniffer_msg_pdu.setEnabled(True)


async def multiStageAttackFinished(component: object, sensor_node_id=0):
    """ 
    Changes the pushbuttons and labels upon receiving a message from the Sensor Node.
    """       
    # Change the Pushbuttons and Labels
    component.frontend.ui.pushButton_attack_multi_stage_start.setText("Start")
    component.frontend.ui.label2_attack_multi_stage_status.setText("Not Running")

    # Update the Status Dialog
    if component.frontend.active_sensor_node > -1:
        component.frontend.statusbar_text[component.frontend.active_sensor_node][3] = "Not Running"
        component.frontend.refreshStatusBarText()

    # Enable Load/Save
    component.frontend.ui.pushButton_attack_multi_stage_load.setEnabled(True)
    component.frontend.ui.pushButton_attack_multi_stage_save.setEnabled(True)


async def detectorFlowGraphError(component: object, sensor_node_id=0, error=""):
    """ 
    Creates a message box with an error message upon Detector flow graph error.
    """
    # Enable Items
    TSITabSlots._slotTSI_DetectorStartClicked(component.frontend)

    # Open Window
    fissure.Dashboard.UI_Components.Qt5.errorMessage("Flow Graph Error:\n" + error)


async def flowGraphError(component: object, sensor_node_id=0, error=""):
    """ 
    Creates a message box with an error message upon flow graph error.
    """
    # Enable Items
    component.frontend.ui.comboBox_attack_protocols.setEnabled(True)
    component.frontend.ui.comboBox_attack_modulation.setEnabled(True)
    component.frontend.ui.comboBox_attack_hardware.setEnabled(True)

    # Open Window
    fissure.Dashboard.UI_Components.Qt5.errorMessage("Flow Graph Error:\n" + error)


async def autorunPlaylistFinished(component: object, sensor_node_id=0):
    """ 
    Updates the statusbar dialog.
    """
    # Update the Status Dialog
    component.frontend.statusbar_text[sensor_node_id][6] = "Not Running"
    component.frontend.refreshStatusBarText()


async def autorunPlaylistStarted(component: object, sensor_node_id=0):
    """ 
    Updates the statusbar dialog.
    """
    # Update the Status Dialog
    component.frontend.statusbar_text[sensor_node_id][6] = "Running"
    component.frontend.refreshStatusBarText()


async def refreshSensorNodeFilesResults(
    component: object, sensor_node_id=0, filepaths=[], file_sizes=[], file_types=[], modified_dates=[]
):
    """ 
    Populates the table with the results of the remote sensor node folder scan.
    """        
    # Populate the Table
    component.frontend.ui.tableWidget_sensor_nodes_fn_files.setRowCount(0)
    for n in range(0,len(filepaths)):
        path_item = QtWidgets.QTableWidgetItem(str(filepaths[n]))
        size_item = QtWidgets.QTableWidgetItem(str(file_sizes[n]))
        type_item = QtWidgets.QTableWidgetItem(str(file_types[n]))
        modified_item = QtWidgets.QTableWidgetItem(str(modified_dates[n]))
        component.frontend.ui.tableWidget_sensor_nodes_fn_files.setRowCount(component.frontend.ui.tableWidget_sensor_nodes_fn_files.rowCount() + 1)
        component.frontend.ui.tableWidget_sensor_nodes_fn_files.setItem(component.frontend.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,0,path_item)
        component.frontend.ui.tableWidget_sensor_nodes_fn_files.setItem(component.frontend.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,1,size_item)
        component.frontend.ui.tableWidget_sensor_nodes_fn_files.setItem(component.frontend.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,2,type_item)
        component.frontend.ui.tableWidget_sensor_nodes_fn_files.setItem(component.frontend.ui.tableWidget_sensor_nodes_fn_files.rowCount()-1,3,modified_item)
    
    # Resize Table            
    component.frontend.ui.tableWidget_sensor_nodes_fn_files.resizeColumnsToContents()
    component.frontend.ui.tableWidget_sensor_nodes_fn_files.horizontalHeader().setStretchLastSection(False)
    component.frontend.ui.tableWidget_sensor_nodes_fn_files.horizontalHeader().setStretchLastSection(True)
    component.frontend.ui.tableWidget_sensor_nodes_fn_files.setColumnWidth(0,800)
    component.frontend.ui.tableWidget_sensor_nodes_fn_files.resizeRowsToContents()


async def fileDownloaded(component: object, sensor_node_id=0):
    """ 
    Refreshes the local file list after downloading a file.
    """
    # Refresh
    tree_model = QtWidgets.QFileSystemModel()
    tree_model.setRootPath(os.path.expanduser("~"))
    component.frontend.ui.treeView_sensor_nodes_fn_local_files.setModel(tree_model)
    component.frontend.ui.treeView_sensor_nodes_fn_local_files.setRootIndex(tree_model.index(os.path.expanduser("~")))
    SensorNodesTabSlots._slotSensorNodesFileNavigationLocalFolderChanged(component.frontend)


async def findPreamblesReturn(component: object, slice_medians, candidate_preambles, min_std_dev_max_length_preambles):
    """
    Updates the Dashboard with the preamble results.
    """
    status_text = time.strftime("%H:%M:%S", time.localtime()) + ": Found Preambles\n"

    PDTabSlots._slotPD_AddStatus(component.frontend, status_text)
    
    # Store to Memory
    component.frontend.median_slicing_results = slice_medians
    component.frontend.candidate_preamble_data = candidate_preambles

    # Add the Values to the Table, Set the Slider
    PDTabSlots.pdBitSlicingSortPreambleStatsTable(component.frontend, int(component.frontend.ui.doubleSpinBox_pd_bit_slicing_window_size.value()))
    PDTabSlots.pdBitSlicingSortCandidatePreambleTable(component.frontend, int(component.frontend.ui.doubleSpinBox_pd_bit_slicing_window_size_candidates.value()))
    recommended_preamble = str(list(min_std_dev_max_length_preambles.keys())[0])
    component.frontend.ui.doubleSpinBox_pd_bit_slicing_window_size_candidates.setValue(len(recommended_preamble))
    component.frontend.ui.textEdit_pd_bit_slicing_recommended_preamble.setPlainText(recommended_preamble)

    # Enable Controls
    component.frontend.ui.label2_pd_bit_slicing_window_size.setEnabled(True)
    component.frontend.ui.doubleSpinBox_pd_bit_slicing_window_size.setEnabled(True)
    component.frontend.ui.horizontalSlider_pd_bit_slicing_preamble_stats.setEnabled(True)
    component.frontend.ui.label2_pd_bit_slicing_window_size_candidates.setEnabled(True)
    component.frontend.ui.doubleSpinBox_pd_bit_slicing_window_size_candidates.setEnabled(True)
    component.frontend.ui.horizontalSlider_pd_bit_slicing_preamble_stats_candidates.setEnabled(True)
    component.frontend.ui.pushButton_pd_bit_slicing_slice_by_preamble.setEnabled(True)
    component.frontend.ui.label2_pd_bit_slicing_first_n.setEnabled(True)
    component.frontend.ui.label2_pd_bit_slicing_estimated_length.setEnabled(True)
    component.frontend.ui.spinBox_pd_bit_slicing_return_limit.setEnabled(True)
    component.frontend.ui.spinBox_pd_bit_slicing_estimated_length.setEnabled(True)
    component.frontend.ui.tableWidget_pd_bit_slicing_lengths.setEnabled(True)
    component.frontend.ui.tableWidget_pd_bit_slicing_packets.setEnabled(True)
    component.frontend.ui.label2_pd_bit_slicing_recommended_preamble.setEnabled(True)
    component.frontend.ui.textEdit_pd_bit_slicing_recommended_preamble.setEnabled(True)

    # Hide the Calculating Label
    component.frontend.ui.label2_pd_bit_slicing_calculating.setVisible(False)


async def foundPreamblesInLibrary(component: object, parameters={}):
    """
    Updates the Dashboard with preamble search results.
    """
    PDTabSlots._slotPD_AddStatus(
        component.frontend,
        time.strftime("%H:%M:%S", time.localtime()) + ": Found Preambles in Library: " + repr(parameters) + "\n"
    )
    component.signal_pdBitSlicingLibraryLookupReturned.emit(parameters)


async def sliceByPreambleReturn(component: object, packet_lengths=[], packet_dict={}):
    """ 
    Updates the tables with the return values from 'Slice By Preamble.'
    """
    # Convert Hex Data to Binary
    component.frontend.first_n_packets = {}
    for p_length, packet in packet_dict.items():
        packet_list = []
        for hex_data in packet:
            packet_list.append(bin(int(hex_data, 16))[2:].zfill(int(len(hex_data)*4)))  # Converts packet to binary
        component.frontend.first_n_packets[4*int(p_length)] = packet_list

    # Clear the Packet Length Table
    for row in reversed(range(0,component.frontend.ui.tableWidget_pd_bit_slicing_lengths.rowCount())):
        component.frontend.ui.tableWidget_pd_bit_slicing_lengths.removeRow(row)
    for col in reversed(range(0,component.frontend.ui.tableWidget_pd_bit_slicing_packets.columnCount())):
        component.frontend.ui.tableWidget_pd_bit_slicing_packets.removeColumn(col)

    # Insert into the Packet Length Table
    for n in reversed(range(0,len(packet_lengths))):
        component.frontend.ui.tableWidget_pd_bit_slicing_lengths.insertRow(0)

        # Packet Lengths
        packet_length_item = QtWidgets.QTableWidgetItem(str(4*packet_lengths[n][0]))  # In bits
        packet_length_item.setTextAlignment(QtCore.Qt.AlignCenter)
        component.frontend.ui.tableWidget_pd_bit_slicing_lengths.setItem(0,0,packet_length_item)

        # Packet Length Occurrences
        length_occurrences_item = QtWidgets.QTableWidgetItem(str(packet_lengths[n][1]))
        length_occurrences_item.setTextAlignment(QtCore.Qt.AlignCenter)
        component.frontend.ui.tableWidget_pd_bit_slicing_lengths.setItem(0,1,length_occurrences_item)

    # Select the First Row
    component.frontend.ui.tableWidget_pd_bit_slicing_lengths.setCurrentCell(0,0)

    # Enable the Controls
    component.frontend.ui.frame_pd_bit_slicing_manual_slicing.setEnabled(True)
    component.frontend.ui.frame_pd_bit_slicing_automated_slicing.setEnabled(True)
    component.frontend.ui.frame_pd_bit_slicing_library.setEnabled(True)
    component.frontend.ui.label2_pd_bit_slicing_interval.setEnabled(True)
    component.frontend.ui.spinBox_pd_bit_slicing_interval.setEnabled(True)
    component.frontend.ui.pushButton_pd_bit_slicing_slice.setEnabled(True)
    component.frontend.ui.pushButton_pd_bit_slicing_reset.setEnabled(True)
    component.frontend.ui.label2_pd_bit_slicing_split_interval.setEnabled(True)
    component.frontend.ui.spinBox_pd_bit_slicining_split_interval.setEnabled(True)
    component.frontend.ui.pushButton_pd_bit_slicing_split_fields.setEnabled(True)
    component.frontend.ui.pushButton_pd_bit_slicing_merge_fields.setEnabled(True)
    component.frontend.ui.pushButton_pd_bit_slicing_search_library.setEnabled(True)
    component.frontend.ui.pushButton_pd_bit_slicing_add_to_library.setEnabled(True)
    component.frontend.ui.checkBox_pd_bit_slicing_colors.setEnabled(True)
    component.frontend.ui.pushButton_pd_bit_slicing_plot_entropy.setEnabled(True)
    component.frontend.ui.pushButton_pd_bit_slicing_shift_left.setEnabled(True)
    component.frontend.ui.pushButton_pd_bit_slicing_shift_right.setEnabled(True)

    # Resize the Tables
    #~ component.frontend.ui.tableWidget_pd_bit_slicing_lengths.resizeColumnsToContents()
    component.frontend.ui.tableWidget_pd_bit_slicing_lengths.resizeRowsToContents()


async def bufferSizeReturn(component: object, buffer_size=0):
    """ 
    Updates the status labels of the Dashboard with the latest protocol discovery buffer size.
    """
    # Protocol Discovery Progress Bars
    component.frontend.ui.progressBar_pd_status_buffer.setValue(int(buffer_size))
    component.frontend.ui.progressBar_bit_slicing_buffer.setValue(int(buffer_size))


async def SOI_Chosen(component: object, returned_soi=[]):
    """ 
    The HIPRFISR returned a SOI to target. This checks the radio button of the chosen SOI. This does nothing.
    """
    target_SOI = target_SOI.replace("(","")
    target_SOI = target_SOI.replace(")","")
    target_SOI = target_SOI.replace("'","")
    target_SOI = target_SOI.replace(" ","")
    target_SOI_label = ""


async def demodFG_LibrarySearchReturn(component: object, flow_graphs=[]):
    """ 
    Updates the list of recommended flow graphs in the "Flow Graph" tab.
    """
    # Clear the List(s)
    component.frontend.ui.listWidget_pd_flow_graphs_recommended_fgs.clear()

    # Format the String
    modulation_list = yaml.load(str(flow_graphs), yaml.FullLoader)

    # Add the Filenames to the List
    component.frontend.ui.listWidget_pd_flow_graphs_recommended_fgs.addItems(modulation_list)

    # Select the First File
    component.frontend.ui.listWidget_pd_flow_graphs_recommended_fgs.setCurrentRow(0)

    # Auto-Load PD Flow Graphs is Selected
    if component.frontend.ui.checkBox_automation_auto_select_pd_flow_graphs.isChecked():
        # Target Protocol if Targeting
        target_protocol = str(component.frontend.ui.comboBox_automation_target_protocol.currentText())

        # Protocol Flow Graph
        match_found = False
        if target_protocol != "None":
            for n in range(0,len(modulation_list)):
                if target_protocol in modulation_list[n]:
                    # Select Flow Graph
                    component.frontend.ui.listWidget_pd_flow_graphs_recommended_fgs.setCurrentRow(n)
                    PDTabSlots._slotPD_DemodulationLoadSelectedClicked(component.frontend)
                    match_found = True

        # Generic Flow Graph
        if match_found == False:
            get_modulation = str(component.frontend.ui.textEdit_pd_flow_graphs_modulation.toPlainText()).upper()
            for n in range(0,len(modulation_list)):
                if get_modulation in modulation_list[n]:
                    # Select Flow Graph
                    component.frontend.ui.listWidget_pd_flow_graphs_recommended_fgs.setCurrentRow(n)
                    PDTabSlots._slotPD_DemodulationLoadSelectedClicked(component.fronted)

    # Insert Message into the Status Window
    get_text = time.strftime('%H:%M:%S', time.localtime()) + ": Recommended Flow Graphs: " + str(modulation_list) +  "\n"
    PDTabSlots._slotPD_AddStatus(component.frontend, get_text)

    # Show/Hide the PD Flow Graph Lookup Not Found Label
    if len(modulation_list) == 0:
        component.frontend.ui.label2_pd_flow_graphs_lookup_not_found.setText("Not Found!")
    else:
        component.frontend.ui.label2_pd_flow_graphs_lookup_not_found.setText("Found!")


async def searchLibraryReturn(component: object, message=[]):
    """ 
    Updates the listbox of library packet types and protocols that match a preamble.
    """
    # Remove Existing Items
    component.frontend.ui.tableWidget1_library_search_results.setRowCount(0)

    # Convert Message to List
    # message_list = ast.literal_eval(message)

    # Set the Values in the Results Table
    for n in message:
        for m in n:
            component.frontend.ui.tableWidget1_library_search_results.setRowCount(component.frontend.ui.tableWidget1_library_search_results.rowCount()+1)

            # Protocol
            protocol_item = QtWidgets.QTableWidgetItem(str(n[m]['Protocol']))
            protocol_item.setTextAlignment(QtCore.Qt.AlignCenter)
            protocol_item.setFlags(protocol_item.flags() & ~QtCore.Qt.ItemIsEditable)
            component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,0,protocol_item)

            # Subtype
            subtype_item = QtWidgets.QTableWidgetItem(str(m))
            subtype_item.setTextAlignment(QtCore.Qt.AlignCenter)
            subtype_item.setFlags(subtype_item.flags() & ~QtCore.Qt.ItemIsEditable)
            component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,1,subtype_item)

            # Center Frequency
            center_freq_item = QtWidgets.QTableWidgetItem(str(n[m]['Frequency']))
            center_freq_item.setTextAlignment(QtCore.Qt.AlignCenter)
            center_freq_item.setFlags(center_freq_item.flags() & ~QtCore.Qt.ItemIsEditable)
            component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,2,center_freq_item)

            # Start Frequency
            start_freq_item = QtWidgets.QTableWidgetItem(str(n[m]['Start Frequency']))
            start_freq_item.setTextAlignment(QtCore.Qt.AlignCenter)
            start_freq_item.setFlags(start_freq_item.flags() & ~QtCore.Qt.ItemIsEditable)
            component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,3,start_freq_item)

            # End Frequency
            end_freq_item = QtWidgets.QTableWidgetItem(str(n[m]['End Frequency']))
            end_freq_item.setTextAlignment(QtCore.Qt.AlignCenter)
            end_freq_item.setFlags(end_freq_item.flags() & ~QtCore.Qt.ItemIsEditable)
            component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,4,end_freq_item)

            # Bandwidth
            bandwidth_item = QtWidgets.QTableWidgetItem(str(n[m]['Bandwidth']))
            bandwidth_item.setTextAlignment(QtCore.Qt.AlignCenter)
            bandwidth_item.setFlags(bandwidth_item.flags() & ~QtCore.Qt.ItemIsEditable)
            component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,5,bandwidth_item)

            # Modulation
            modulation_item = QtWidgets.QTableWidgetItem(str(n[m]['Modulation']))
            modulation_item.setTextAlignment(QtCore.Qt.AlignCenter)
            modulation_item.setFlags(modulation_item.flags() & ~QtCore.Qt.ItemIsEditable)
            component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,6,modulation_item)

            # Continuous
            continuous_item = QtWidgets.QTableWidgetItem(str(n[m]['Continuous']))
            continuous_item.setTextAlignment(QtCore.Qt.AlignCenter)
            continuous_item.setFlags(continuous_item.flags() & ~QtCore.Qt.ItemIsEditable)
            component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,7,continuous_item)

            # Notes
            notes_item = QtWidgets.QTableWidgetItem(str(n[m]['Notes']))
            notes_item.setTextAlignment(QtCore.Qt.AlignLeft)
            notes_item.setFlags(notes_item.flags() & ~QtCore.Qt.ItemIsEditable)
            component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,8,notes_item)

    # Resize the Table
    component.frontend.ui.tableWidget1_library_search_results.resizeColumnsToContents()
    component.frontend.ui.tableWidget1_library_search_results.resizeRowsToContents()
    #component.frontend.ui.tableWidget1_library_search_results.horizontalHeader().setStretchLastSection(False)
    #component.frontend.ui.tableWidget1_library_search_results.horizontalHeader().setStretchLastSection(True)

    # Hide the Label
    component.frontend.ui.label2_library_search_searching.setVisible(False)


async def setFullLibrary(component: object, message=[]):
    """ 
    Updates the FISSURE library and widgets with the latest library information.
    """
    # Save the Library to the Library Backend
    component.library = fissure.utils.load_library(component.os_info)

    # Refresh Library-Dependent Features
    protocols = fissure.utils.library.getProtocols(component.library)

    # Packet Crafter Protocols
    component.frontend.ui.comboBox_packet_protocols.clear()
    protocols_with_packet_types = []
    for p in protocols:
        if len(fissure.utils.library.getPacketTypes(component.library,p)) > 0:
            protocols_with_packet_types.append(p)
    component.frontend.ui.comboBox_packet_protocols.addItems(sorted(protocols_with_packet_types))

    # Bit Viewer Protocols
    component.frontend.ui.comboBox_pd_bit_viewer_protocols.clear()
    component.frontend.ui.comboBox_pd_bit_viewer_protocols.addItem("Raw")
    component.frontend.ui.comboBox_pd_bit_viewer_protocols.addItems(sorted(protocols_with_packet_types))

    # Dissector Protocols
    component.frontend.ui.comboBox_pd_dissectors_protocol.clear()
    component.frontend.ui.comboBox_pd_dissectors_protocol.addItems(sorted(protocols_with_packet_types))

    # Attack Tab Protocols
    component.frontend.ui.comboBox_attack_protocols.clear()
    protocols_with_attacks = []
    for p in protocols:
        if len(fissure.utils.library.getAttacks(component.library,p)) > 0:
            protocols_with_attacks.append(p)
    component.frontend.ui.comboBox_attack_protocols.addItems(sorted(protocols_with_attacks))

    # Gallery Protocols
    component.frontend.ui.comboBox_library_gallery_protocol.clear()
    protocols_with_images = []
    for p in protocols:
        if len(component.frontend.findGalleryImages(p)) > 0:
            protocols_with_images.append(p)
    component.frontend.ui.comboBox_library_gallery_protocol.addItems(sorted(protocols_with_images))

    component.frontend.ui.treeWidget_attack_attacks.clear()
    component.frontend.populateAttackTreeWidget()
    component.frontend.ui.treeWidget_attack_attacks.expandAll()
    AttackTabSlots._slotAttackProtocols(component.frontend)

    # Library Remove Protocols
    component.frontend.ui.comboBox_library_browse_protocol.clear()
    component.frontend.ui.comboBox_library_browse_protocol.addItems(sorted(protocols))

    # Sniffer Protocols
    component.frontend.ui.comboBox_pd_sniffer_protocols.clear()
    protocols_with_demod_fgs = []
    for p in protocols:
        if len(fissure.utils.library.getDemodulationFlowGraphs(component.library, p, '', '')) > 0:
            protocols_with_demod_fgs.append(p)
    component.frontend.ui.comboBox_pd_sniffer_protocols.addItems(sorted(protocols_with_demod_fgs))

    # Automation Target Protocols
    get_targeted_protocol = str(component.frontend.ui.comboBox_automation_target_protocol.currentText())  # Might want to recheck that this is ok.
    component.frontend.ui.comboBox_automation_target_protocol.clear()
    component.frontend.ui.comboBox_automation_target_protocol.addItems(sorted(protocols))
    index = component.frontend.ui.comboBox_automation_target_protocol.findText(get_targeted_protocol, QtCore.Qt.MatchFixedString)
    if index >= 0:
        component.frontend.ui.comboBox_automation_target_protocol.setCurrentIndex(index)

    LibraryTabSlots._slotAttackImportFileTypeChanged(component.frontend)

    # PD: Add to Library: Reset to Last Protocol Used or Added
    get_last_protocol = component.frontend.ui.comboBox_library_pd_protocol.currentText()
    component.frontend.ui.comboBox_library_pd_protocol.clear()
    component.frontend.ui.comboBox_library_pd_protocol.addItem("-- New Protocol --")
    component.frontend.ui.comboBox_library_pd_protocol.addItems(sorted(protocols))
    if get_last_protocol == "-- New Protocol --":
        get_last_protocol = component.frontend.ui.textEdit_library_pd_new_protocol.toPlainText()
    for i in range(component.frontend.ui.comboBox_library_pd_protocol.count()):
        if get_last_protocol == component.frontend.ui.comboBox_library_pd_protocol.itemText(i):
            component.frontend.ui.comboBox_library_pd_protocol.setCurrentIndex(i)

    # Update All Flow Graphs in Demodulation Tab
    PDTabSlots._slotPD_DemodHardwareChanged(component.frontend)

    # Update Browse YAML Files
    LibraryTabSlots._slotLibraryBrowseYAML_Changed(component.frontend)

    # Create a Dialog Window
    fissure.Dashboard.UI_Components.Qt5.errorMessage("Library updated successfully.")


async def findEntropyReturn(component: object, ents):
    """ 
    Plots the entropy for the bit positions upon receiving the message from Protocol Discovery.
    """
    # Create a Modeless Dialog Window
    plotBox = MyPlotWindow(component.frontend, ents)
    plotBox.exec_()


async def sensorNodeConnectTimeout(component: object, sensor_node_id=0):
    """
    Restores the connect buttons in the hardware select dialog.
    """
    # Gather Widgets
    tab_index = int(sensor_node_id)
    ip_widget = getattr(component.frontend.popups["HardwareSelectDialog"], f"textEdit_ip_addr_{int(sensor_node_id) + 1}")
    hb_port_widget = getattr(component.frontend.popups["HardwareSelectDialog"], f"textEdit_hb_port_{int(sensor_node_id) + 1}")
    msg_port_widget = getattr(component.frontend.popups["HardwareSelectDialog"], f"textEdit_msg_port_{int(sensor_node_id) + 1}")
    recall_settings_widget = getattr(component.frontend.popups["HardwareSelectDialog"], f"checkBox_recall_settings_remote_{int(sensor_node_id) + 1}")
    connect_widget = getattr(component.frontend.popups["HardwareSelectDialog"], f"pushButton_connect_{int(sensor_node_id) + 1}")

    # Restore Widgets
    ip_widget.setEnabled(True)
    hb_port_widget.setEnabled(True)
    msg_port_widget.setEnabled(True)
    recall_settings_widget.setEnabled(True)
    connect_widget.setEnabled(True)

    # Warning
    component.logger.warning("Timeout occurred establishing connection to remote sensor node")
