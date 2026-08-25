import binascii
import fissure.comms
import time
from PyQt5 import QtCore, QtWidgets, QtGui
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem
import yaml
import os
import subprocess
import ast
import asyncio
from typing import List
import json
import qasync
import datetime
import zipfile
import numpy as np
from fissure.Dashboard.Slots import TacticalTabSlots

from fissure.utils.plugin import get_fissure_plugin_editor_plugins_path
from fissure.Dashboard.UI_Components.Qt5 import MyMessageBox
# from ..Dashboard.Slots import StatusBarSlots  # how do you go from callbacks to slots?
from fissure.Dashboard.Slots import (
    ArchiveTabSlots,
    AttackTabSlots,
    DashboardSlots,
    FuzzingTabSlots,
    IQDataTabSlots,
    LibraryTabSlots,
    LogTabSlots,
    MenuBarSlots,
    PDTabSlots,
    SensorNodesTabSlots,
    SensorNodesPluginsTabSlots,
    SequentialActionTabSlots,
    SingleActionTabSlots,
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
    # TreeModel,
    # TreeNode,
    # TrimSettings,
)

from fissure.utils import cot_utils
from fissure.utils.selected_node_utils import set_selected_node_connection_state


async def flowGraphFinished(component: object, category=""):
    """Update the Dashboard in response to a legacy flow graph finished message."""
    if category == "PD":
        if component.frontend.ui.pushButton_pd_flow_graphs_start_stop.text() == "Stop":
            component.frontend.ui.pushButton_pd_flow_graphs_start_stop.setText("Start")
            component.frontend.ui.pushButton_pd_flow_graphs_apply_changes.setEnabled(False)
            component.frontend.ui.label2_pd_flow_graphs_status.setText("Stopped")
            component.frontend.ui.label2_pd_status_flow_graph_status.setText("Stopped")
            component.frontend.refreshStatusBarText()


async def flowGraphStarted(component: object, category=""):
    """Update Dashboard controls when a legacy flow graph reports that it started."""
    if category == "PD":
        component.frontend.ui.label2_pd_flow_graphs_status.setText("Running... ")
        component.frontend.ui.pushButton_pd_flow_graphs_start_stop.setEnabled(True)
        component.frontend.ui.label2_pd_status_flow_graph_status.setText("Running... ")

        if component.frontend.active_sensor_node > -1:
            filepath = str(component.frontend.ui.textEdit_pd_flow_graphs_filepath.toPlainText())
            component.frontend.statusbar_text[component.frontend.active_sensor_node][2] = (
                "Running Flow Graph... " + filepath.rsplit("/", 1)[-1]
            )
            component.frontend.refreshStatusBarText()


async def hardwareGuessResults(component: object, table_row=0, hardware_type="", scan_results="", new_guess_index=0):
    """
    Fills the scan results table row with hardware information in the Node Configure Dialog.
    """
    # Fill the Table
    component.frontend.popups["NodeConfigureDialog"].guessReturn(table_row, hardware_type, scan_results, new_guess_index)


async def hardwareProbeResults(component: object, output="", height_width=[]):
    """
    Returns the probe results to the NodeConfigureDialog.
    """
    # Parse Return String
    probe_text = output
    
    # Hide Label
    scan_results_label = component.frontend.popups["NodeConfigureDialog"].label2_scan_results_probe
    scan_results_label.setVisible(False)

    # Enable Probe Button
    probe_button = component.frontend.popups["NodeConfigureDialog"].pushButton_scan_results_probe
    probe_button.setEnabled(True)

    # Open a Text Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["NodeConfigureDialog"], probe_text)
    

async def hardwareScanResults(component: object, hardware_scan_results=[]):
    """
    Returns Auto Scan results to the Node Configure Dialog.
    """
    component.frontend.popups["NodeConfigureDialog"].scanReturn(all_scan_results=hardware_scan_results)


async def recallSettingsReturn(component: object, node_uuid: str, node_ip_address: str, settings_dict={}):
    """
    Store selected sensor node settings and update the selected node display.
    """
    previous_selected_node_uid = str(
        getattr(component.frontend, "selected_node_uid", "") or ""
    ).strip()
    new_selected_node_uid = str(node_uuid or "").strip()

    selected_node_changed = (
        new_selected_node_uid != ""
        and new_selected_node_uid != previous_selected_node_uid
    )

    component.frontend.selected_node_uid = node_uuid
    component.frontend.selected_node_ip = node_ip_address
    component.frontend.selected_node_settings = settings_dict or {}

    nickname = (
        settings_dict
        .get("Sensor Node", {})
        .get("nickname", node_uuid)
    )

    display_ip_address = node_ip_address
    if display_ip_address == "ipc":
        display_ip_address = "Local Process"

    component.frontend.ui.label_top_configure_node_title.setText(
        f"{nickname}  (Online)"
    )
    component.frontend.ui.label_top_configure_node_subtitle.setText(
        f"{display_ip_address}"
    )
    component.frontend.ui.label_top_configure_node_subtitle2.setText(
        "Click to view and configure this node"
    )

    frame = component.frontend.ui.frame_top_configure_node

    frame.setProperty("selected", "true")
    frame.setProperty("connected", "true")
    frame.setProperty("pressed", "false")
    frame.style().unpolish(frame)
    frame.style().polish(frame)

    component.frontend.ui.stackedWidget_top_configure_node.setCurrentIndex(1)

    if hasattr(component.frontend, "selected_tactical_node_uid"):
        TacticalTabSlots._updateTacticalNodeInfoFrameState(component.frontend)

    if selected_node_changed:
        try:
            TSITabSlots.reset_tsi_conditioner_method_for_selected_node_change(
                component.frontend
            )
        except Exception as e:
            component.logger.debug(
                f"Could not reset TSI Conditioner after selected-node change: {e}"
            )

    component.frontend.configureSelectedNodeHardware()

    try:
        TSITabSlots.update_tsi_detector_selected_node_gate(component.frontend)
    except Exception as e:
        component.logger.debug(
            f"Could not update unified TSI Detector selected-node gate after recallSettingsReturn: {e}"
        )

    try:
        TSITabSlots.update_tsi_conditioner_selected_node_gate(component.frontend)
    except Exception as e:
        component.logger.debug(
            f"Could not update TSI Conditioner selected-node gate after recallSettingsReturn: {e}"
        )
    
    try:
        TSITabSlots.update_tsi_fe_selected_node_gate(component.frontend)
    except Exception as e:
        component.logger.debug(
            f"Could not update TSI Feature Extractor selected-node gate "
            f"after recallSettingsReturn: {e}"
        )
    
    try:
        IQDataTabSlots.update_iq_record_selected_node_gate(
            component.frontend
        )
    except Exception as e:
        component.logger.debug(
            "Could not update IQ Record selected-node gate "
            f"after recallSettingsReturn: {e}"
        )
    
    try:
        IQDataTabSlots.update_iq_playback_selected_node_gate(
            component.frontend
        )
    except Exception as e:
        component.logger.debug(
            "Could not update IQ Playback selected-node gate "
            f"after recallSettingsReturn: {e}"
        )
    
    try:
        ArchiveTabSlots.update_archive_replay_selected_node_gate(
            component.frontend
        )
    except Exception as e:
        component.logger.debug(
            "Could not update Archive Replay selected-node gate "
            f"after recallSettingsReturn: {e}"
        )

    try:
        SensorNodesTabSlots.update_sensor_nodes_file_navigation_selected_node_gate(
            component.frontend
        )
    except Exception as e:
        component.logger.debug(
            "Could not update Sensor Nodes File Navigation selected-node gate "
            f"after recallSettingsReturn: {e}"
        )


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
        pass
        # component.frontend.popups["NodeConfigureDialog"].sensorNodeDisconnected()


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
        pass
        # component.frontend.popups["NodeConfigureDialog"].sensorNodeConnected(serial=False)



async def hiprfisrDisconnectedSerial(component: object):
    """
    Keeps track if the Meshtastic serial port at the HIPRFISR is disconnected.
    """
    component.hiprfisr_serial_connected = False


async def hiprfisrConnectedSerial(component: object):
    """
    Keeps track if the Meshtastic serial port at the HIPRFISR is connected.
    """
    component.hiprfisr_serial_connected = True


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


async def flowGraphStartedSniffer(component: object, category=""):
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


async def flowGraphFinishedSniffer(component: object, category=""):
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


async def flowGraphError(component: object, error=""):
    """Display a legacy flow-graph error returned by a Sensor Node."""
    fissure.Dashboard.UI_Components.Qt5.errorMessage("Flow Graph Error:\n" + error)


def autorunPlaylistQueryResults(
    component: object, node_uid="", playlists=None, state="Idle", source="", message=""
):
    """Populate stored Sensor Node Autorun playlist names."""
    SensorNodesTabSlots.handle_sensor_nodes_autorun_playlist_query_results(
        component.frontend,
        node_uid=node_uid,
        playlists=playlists or [],
        state=state,
        source=source,
        message=message,
    )


def autorunPlaylistLoadResults(
    component: object,
    node_uid="",
    playlist_filename="",
    playlist_dict=None,
    success=False,
    message="",
):
    """Load a stored Sensor Node Autorun playlist into the Dashboard workspace."""
    SensorNodesTabSlots.handle_sensor_nodes_autorun_playlist_load_results(
        component.frontend,
        node_uid=node_uid,
        playlist_filename=playlist_filename,
        playlist_dict=playlist_dict or {},
        success=success,
        message=message,
    )


def autorunPlaylistSaveResults(
    component: object,
    node_uid="",
    playlist_filename="",
    success=False,
    message="",
):
    """Handle completion of a Sensor Node Autorun playlist save."""
    SensorNodesTabSlots.handle_sensor_nodes_autorun_playlist_save_results(
        component.frontend,
        node_uid=node_uid,
        playlist_filename=playlist_filename,
        success=success,
        message=message,
    )


def autorunPlaylistStatus(component: object, node_uid="", state="Idle", source="", message=""):
    """Update the Dashboard from authoritative Sensor Node Autorun state."""
    SensorNodesTabSlots.handle_sensor_nodes_autorun_status(
        component.frontend,
        node_uid=node_uid,
        state=state,
        source=source,
        message=message,
    )


async def sensorNodeFileTransferStatus(
    component: object,
    node_uid="",
    transfer_id="",
    success=False,
    message="",
    remote_filepath="",
    remote_folder="",
    bytes_received=0,
    elapsed_seconds=0.0,
    mib_per_second=0.0,
    refresh_file_list=False,
):
    """Resolve one awaited Dashboard-to-Sensor-Node binary file upload."""
    pending_uploads = getattr(
        component,
        "_sensor_node_file_uploads",
        {},
    )
    completion_future = pending_uploads.get(
        transfer_id
    )

    result = {
        "success": bool(success),
        "message": str(message),
        "transfer_id": transfer_id,
        "node_uid": node_uid,
        "remote_filepath": remote_filepath,
        "remote_folder": remote_folder,
        "bytes_received": int(bytes_received),
        "elapsed_seconds": float(elapsed_seconds),
        "mib_per_second": float(mib_per_second),
    }

    if completion_future is not None and not completion_future.done():
        completion_future.set_result(result)
    elif success:
        component.logger.info(
            "Completed Sensor Node file upload transfer_id=%s path=%s",
            transfer_id,
            remote_filepath,
        )
    else:
        component.logger.error(
            "Sensor Node file upload failed transfer_id=%s: %s",
            transfer_id,
            message,
        )

    if (
        success
        and refresh_file_list
        and node_uid
        and remote_folder
    ):
        await component.refreshSensorNodeFiles(
            node_uid,
            remote_folder,
        )


async def refreshSensorNodeFilesResults(
    component: object, filepaths=[], file_sizes=[], file_types=[], modified_dates=[]
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


async def fileDownloaded(component: object):
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

    # # Auto-Load PD Flow Graphs is Selected
    # if component.frontend.ui.checkBox_automation_auto_select_pd_flow_graphs.isChecked():  # Combobox deleted
    #     # Target Protocol if Targeting
    #     target_protocol = str(component.frontend.ui.comboBox_automation_target_protocol.currentText())

    #     # Protocol Flow Graph
    #     match_found = False
    #     if target_protocol != "None":
    #         for n in range(0,len(modulation_list)):
    #             if target_protocol in modulation_list[n]:
    #                 # Select Flow Graph
    #                 component.frontend.ui.listWidget_pd_flow_graphs_recommended_fgs.setCurrentRow(n)
    #                 PDTabSlots._slotPD_DemodulationLoadSelectedClicked(component.frontend)
    #                 match_found = True

    #     # Generic Flow Graph
    #     if match_found == False:
    #         get_modulation = str(component.frontend.ui.textEdit_pd_flow_graphs_modulation.toPlainText()).upper()
    #         for n in range(0,len(modulation_list)):
    #             if get_modulation in modulation_list[n]:
    #                 # Select Flow Graph
    #                 component.frontend.ui.listWidget_pd_flow_graphs_recommended_fgs.setCurrentRow(n)
    #                 PDTabSlots._slotPD_DemodulationLoadSelectedClicked(component.fronted)

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
    for row in message:
        component.frontend.ui.tableWidget1_library_search_results.setRowCount(component.frontend.ui.tableWidget1_library_search_results.rowCount()+1)

        # Protocol
        protocol_item = QtWidgets.QTableWidgetItem(str(row[1]))
        protocol_item.setTextAlignment(QtCore.Qt.AlignCenter)
        protocol_item.setFlags(protocol_item.flags() & ~QtCore.Qt.ItemIsEditable)
        component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,0,protocol_item)

        # Subtype
        subtype_item = QtWidgets.QTableWidgetItem(str(row[2]))
        subtype_item.setTextAlignment(QtCore.Qt.AlignCenter)
        subtype_item.setFlags(subtype_item.flags() & ~QtCore.Qt.ItemIsEditable)
        component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,1,subtype_item)

        # Center Frequency
        center_freq_item = QtWidgets.QTableWidgetItem(str(row[3]))
        center_freq_item.setTextAlignment(QtCore.Qt.AlignCenter)
        center_freq_item.setFlags(center_freq_item.flags() & ~QtCore.Qt.ItemIsEditable)
        component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,2,center_freq_item)

        # Start Frequency
        start_freq_item = QtWidgets.QTableWidgetItem(str(row[4]))
        start_freq_item.setTextAlignment(QtCore.Qt.AlignCenter)
        start_freq_item.setFlags(start_freq_item.flags() & ~QtCore.Qt.ItemIsEditable)
        component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,3,start_freq_item)

        # End Frequency
        end_freq_item = QtWidgets.QTableWidgetItem(str(row[5]))
        end_freq_item.setTextAlignment(QtCore.Qt.AlignCenter)
        end_freq_item.setFlags(end_freq_item.flags() & ~QtCore.Qt.ItemIsEditable)
        component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,4,end_freq_item)

        # Bandwidth
        bandwidth_item = QtWidgets.QTableWidgetItem(str(row[6]))
        bandwidth_item.setTextAlignment(QtCore.Qt.AlignCenter)
        bandwidth_item.setFlags(bandwidth_item.flags() & ~QtCore.Qt.ItemIsEditable)
        component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,5,bandwidth_item)

        # Modulation
        modulation_item = QtWidgets.QTableWidgetItem(str(row[8]))
        modulation_item.setTextAlignment(QtCore.Qt.AlignCenter)
        modulation_item.setFlags(modulation_item.flags() & ~QtCore.Qt.ItemIsEditable)
        component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,6,modulation_item)

        # Continuous
        continuous_item = QtWidgets.QTableWidgetItem(str(row[7]).capitalize())
        continuous_item.setTextAlignment(QtCore.Qt.AlignCenter)
        continuous_item.setFlags(continuous_item.flags() & ~QtCore.Qt.ItemIsEditable)
        component.frontend.ui.tableWidget1_library_search_results.setItem(component.frontend.ui.tableWidget1_library_search_results.rowCount()-1,7,continuous_item)

        # Notes
        notes_item = QtWidgets.QTableWidgetItem(str(row[9]))
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


async def libraryUpdateFinished(component: object):
    """ 
    Updates the FISSURE library and widgets with the latest library information.
    """
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

    # Gallery Protocols
    component.frontend.ui.comboBox_library_gallery_protocol.clear()
    protocols_with_images = []
    for p in protocols:
        if len(component.frontend.findGalleryImages(p)) > 0:
            protocols_with_images.append(p)
    component.frontend.ui.comboBox_library_gallery_protocol.addItems(sorted(protocols_with_images))

    # Refresh Browse Table
    LibraryTabSlots._slotLibraryBrowseChanged(component.frontend)

    # Sniffer Protocols
    component.frontend.ui.comboBox_pd_sniffer_protocols.clear()
    protocols_with_demod_fgs = []
    for p in protocols:
        if len(fissure.utils.library.getDemodulationFlowGraphFilenames(component.library, p, '', '', version = fissure.utils.get_library_version())) > 0:
            protocols_with_demod_fgs.append(p)
    component.frontend.ui.comboBox_pd_sniffer_protocols.addItems(sorted(protocols_with_demod_fgs))

    # # Automation Target Protocols
    # get_targeted_protocol = str(component.frontend.ui.comboBox_automation_target_protocol.currentText())  # Might want to recheck that this is ok.
    # component.frontend.ui.comboBox_automation_target_protocol.clear()
    # component.frontend.ui.comboBox_automation_target_protocol.addItems(sorted(protocols))
    # index = component.frontend.ui.comboBox_automation_target_protocol.findText(get_targeted_protocol, QtCore.Qt.MatchFixedString)
    # if index >= 0:
    #     component.frontend.ui.comboBox_automation_target_protocol.setCurrentIndex(index)

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
    component.frontend.ui.label_library_attacks_filepath.setText("")
    component.frontend.ui.textEdit_library_attacks_name.setText("")
    component.frontend.ui.textEdit_library_attacks_new_name.setText("")

    # Update All Flow Graphs in Demodulation Tab
    PDTabSlots._slotPD_DemodHardwareChanged(component.frontend)


async def findEntropyReturn(component: object, ents):
    """ 
    Plots the entropy for the bit positions upon receiving the message from Protocol Discovery.
    """
    # Create a Modeless Dialog Window
    plotBox = MyPlotWindow(component.frontend, ents)
    plotBox.exec_()


async def retrieveDatabaseCacheReturn(component: object, database_return={}, refresh_frontend_widgets=False):
    """
    Save the database cache return to the backend library variable.
    """
    # Save
    component.library = database_return
    component.logger.info("Updated backend database cache from HIPRFISR database")

    # Enable Tabs
    component.frontend.ui.tabWidget.setEnabled(True)

    # Refresh Library Dependent Widgets
    if refresh_frontend_widgets is True:
        await libraryUpdateFinished(component)


async def checkSensorNodePluginResults(component: object, plugin_status: dict):
    """Update Based on Results of Sensor Node Plugin Status Response

    Parameters
    ----------
    component : object
        Dashboard Backend
    plugin_status : dict
        Status (values) of plugins (keys)
    """
    # if sensor_node_id == component.frontend.active_sensor_node:  #TODO
    # Update Row Items
    table: QtWidgets.QTableWidget = component.frontend.ui.pluginsTable
    items = [table.item(i,0).text() for i in range(table.rowCount())]
    for plugin_name in plugin_status.keys():
        status = plugin_status.get(plugin_name)
        if plugin_name in items:
            # Plugin Already on Table; Update
            rowindex = items.index(plugin_name)
            table.item(rowindex,0).setBackground(QtGui.QBrush(QtGui.QColor('white')))
            table.item(rowindex,1).setText(str(status.get('deployed')))
            table.item(rowindex,1).setBackground(QtGui.QBrush(QtGui.QColor('white')))
            table.item(rowindex,2).setText(str(status.get('installed')))
            table.item(rowindex,2).setBackground(QtGui.QBrush(QtGui.QColor('white')))

        else:
            # New Plugin; add to table
            rowindex = table.rowCount()
            table.insertRow(rowindex)
            table.setItem(rowindex, 0, QtWidgets.QTableWidgetItem(plugin_name))
            table.setItem(rowindex, 1, QtWidgets.QTableWidgetItem(str(status.get('deployed'))))
            table.setItem(rowindex, 2, QtWidgets.QTableWidgetItem(str(status.get('installed'))))

    # Check for Stale Items
    for item in items:
        if not item in plugin_status.keys():
            # Item is no Longer in the Plugin List; Remove
            table.removeRow(items.index(item))


async def requestPluginsTransferInstall(component: object, node_uid: str, plugin_names: str):
    """Transfer Plugin to Sensor Node by Request of Sensor Node

    Parameters
    ----------
    component : object
        Dashboard Backend
    node_uid : str
        Sensor node UID
    plugin_names : str
        Plugin name with file extension or no extension if folder
    """
    await component.transferPlugin(node_uid, plugin_names, True)
    await SensorNodesPluginsTabSlots._slotSensorNodesPluginsPluginsListRefresh(component.frontend)


# async def responsePluginNamesHiprfisr(component: object, plugin_names: List[str]):
#     """Handle Request for Plugin Names

#     Parameters
#     ----------
#     component : object
#         Component
#     """
#     plugin_names.sort()
#     plugin_manager_table: QtWidgets.QTableWidget = component.frontend.ui.tableWidget_plugin_pkgs_hiprfisr
#     plugin_manager_table.clearContents()
#     plugin_manager_table.setColumnCount(1)
#     plugin_manager_table.setRowCount(0)
#     for plugin_name in plugin_names:
#         plugin_manager_table.insertRow(plugin_manager_table.rowCount())
#         plugin_manager_table.setItem(plugin_manager_table.rowCount() - 1, 0, QtWidgets.QTableWidgetItem(plugin_name))
#     plugin_manager_table.setHorizontalHeaderLabels(["Plugin Name"])
#     plugin_manager_table.resizeColumnsToContents()
#     plugin_manager_table.horizontalHeader().setVisible(True)
#     plugin_manager_table.verticalHeader().setVisible(False)

#     # Also update the combobox in the Plugin Operations tab
#     combobox: QtWidgets.QComboBox = component.frontend.ui.comboBox_select_plugin
#     combobox.clear()
#     combobox.addItems(plugin_names)


async def responsePluginOperations(component: object, plugin: str, operations: List[str]) -> None:
    """Handle Request for Plugin Operations

    Parameters
    ----------
    component : object
        Component
    plugin : str
        Plugin name
    operations : List[str]
        List of operations for the plugin
    """
    operations.sort()
    combobox: QtWidgets.QComboBox = component.frontend.ui.comboBox_select_plugin_op
    combobox.clear()
    combobox.addItems(operations)


async def responsePluginOperationParameters(component: object, plugin: str, operation: str, parameters: dict, resources: dict, interfaces: dict) -> None:
    """Handle Request for Plugin Operation Parameters

    Parameters
    ----------
    component : object
        Component
    plugin : str
        Plugin name
    operation : str
        Operation name
    parameters : dict
        Parameters for the operation
    """
    params_table: QtWidgets.QTableWidget = component.frontend.ui.tableWidget_plugin_op_params

    keys = []
    for key, value in parameters.items():
        keys = np.union1d(keys, [str(k) for k in value.keys()])

    if "required" in keys:
        # Move required to first position if present (second position later)
        keys = ["required"] + [k for k in keys if k != "required"]
    else:
        keys = ["required"] + list(keys)

    if "default" in keys:
        # Move default to first position if present
        keys = ["default"] + [k for k in keys if k != "default"]
    else:
        keys = ["default"] + list(keys)

    # Move "description" to the end of the keys list if present
    if "description" in keys:
        keys = [k for k in keys if k != "description"] + ["description"]

    # Record position for each key
    key_positions = {key: (i+1) for i, key in enumerate(keys)}

    # Make the first letter for each key uppercase
    keys = [key.capitalize() for key in keys]

    # Prepare the column names for the table
    columns = ["Value"] + keys

    # configure table
    params_table.clearContents()
    params_table.setColumnCount(len(columns))
    params_table.setHorizontalHeaderLabels(columns)
    params_table.horizontalHeader().setVisible(True)
    params_table.verticalHeader().setVisible(True)
    params_table.setSortingEnabled(True)

    # Populate the table with parameters
    params_table.setRowCount(0)  # Clear existing rows
    for row_index, (key, value) in enumerate(parameters.items()):
        row_index = params_table.rowCount()
        params_table.insertRow(row_index)
        params_table.setVerticalHeaderItem(row_index, QtWidgets.QTableWidgetItem(key))
        for subkey, subvalue in value.items():
            col_index = key_positions.get(subkey, 0)
            item = QtWidgets.QTableWidgetItem(str(subvalue))
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)  # Make item non-editable
            params_table.setItem(row_index, col_index, item)
   
    # Resize the table to fit contents
    params_table.resizeColumnsToContents()
    params_table.resizeRowsToContents()
    
    # Get keys for resources
    keys = []
    for key, value in resources.items():
        keys = np.union1d(keys, [str(k) for k in value.keys()])

    # Move "description" to the end of the keys list if present
    if "description" in keys:
        keys = [k for k in keys if k != "description"] + ["description"]

    # Record position for each key
    key_positions = {key: i for i, key in enumerate(keys)}

    # Make the first letter for each key uppercase
    keys = [key.capitalize() for key in keys]

    # Configure resources table
    res_table: QtWidgets.QTableWidget = component.frontend.ui.tableWidget_plugin_op_resources
    res_table.clearContents()
    res_table.setColumnCount(len(keys))
    res_table.setHorizontalHeaderLabels(keys)
    res_table.horizontalHeader().setVisible(True)
    res_table.verticalHeader().setVisible(True)
    res_table.setSortingEnabled(True)

    # Populate the resources table
    res_table.setRowCount(0)  # Clear existing rows
    for row_index, (key, value) in enumerate(resources.items()):
        row_index = res_table.rowCount()
        res_table.insertRow(row_index)
        res_table.setVerticalHeaderItem(row_index, QtWidgets.QTableWidgetItem(key))
        for subkey, subvalue in value.items():
            col_index = key_positions.get(subkey, 0)
            item = QtWidgets.QTableWidgetItem(str(subvalue))
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)  # Make item non-editable
            res_table.setItem(row_index, col_index, item)
    
    # Resize the resources table to fit contents
    res_table.resizeColumnsToContents()
    res_table.resizeRowsToContents()

    # Get keys for interfaces
    keys = []
    for key, value in interfaces.items():
        keys = np.union1d(keys, [str(k) for k in value.keys()])

    # Move "description" to the end of the keys list if present
    if "description" in keys:
        keys = [k for k in keys if k != "description"] + ["description"]

    # Record position for each key
    key_positions = {key: i for i, key in enumerate(keys)}

    # Make the first letter for each key uppercase
    keys = [key.capitalize() for key in keys]

    # Configure interfaces table
    iface_table: QtWidgets.QTableWidget = component.frontend.ui.tableWidget_plugin_op_interfaces
    iface_table.clearContents()
    iface_table.setColumnCount(len(keys))
    iface_table.setHorizontalHeaderLabels(keys)
    iface_table.horizontalHeader().setVisible(True)
    iface_table.verticalHeader().setVisible(True)
    iface_table.setSortingEnabled(True)

    # Populate the interfaces table
    iface_table.setRowCount(0)  # Clear existing rows
    for row_index, (key, value) in enumerate(interfaces.items()):
        row_index = iface_table.rowCount()
        iface_table.insertRow(row_index)
        iface_table.setVerticalHeaderItem(row_index, QtWidgets.QTableWidgetItem(key))
        for subkey, subvalue in value.items():
            col_index = key_positions.get(subkey, 0)
            item = QtWidgets.QTableWidgetItem(str(subvalue))
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)  # Make item non-editable
            iface_table.setItem(row_index, col_index, item)

    # Resize the resources table to fit contents
    res_table.resizeColumnsToContents()
    res_table.resizeRowsToContents()


async def responsePluginOperationStarted(
    component: object,
    node_uid: str,
    operation_id: str,
    plugin: str,
    operation: str,
    parameters: dict,
) -> None:
    """Handle Request for Plugin Operation Started."""
    operations_list: QtWidgets.QListWidget = (
        component.frontend.ui.listWidget_operations
    )

    operations_list.addItem(
        f"{plugin} - {operation} (ID: {operation_id})"
    )
    operations_list.setWrapping(
        True
    )
    operations_list.scrollToBottom()

    try:
        operation_name = str(
            operation or ""
        ).strip()

        if operation_name in [
            "signal_conditioning.py",
            "signal_conditioning_file.py",
            "signal_conditioning",
            "signal_conditioning_file",
        ]:
            if bool(
                getattr(
                    component.frontend,
                    "tsi_conditioner_running",
                    False,
                )
            ):
                component.frontend.tsi_conditioner_opid = str(
                    operation_id or ""
                )
                component.frontend.tsi_conditioner_waiting_for_opid = False

                component.logger.debug(
                    "[Conditioner] Tracked operation_id=%s for %s",
                    operation_id,
                    operation_name,
                )

    except Exception as error:
        component.logger.debug(
            "[Conditioner] Could not track Conditioner "
            f"operation id: {error}"
        )

    # IQ Playback lifecycle only.
    operation_name = str(
        operation or ""
    ).strip()

    if operation_name not in {
        "iq_playback",
        "iq_playback.py",
    }:
        return

    frontend = component.frontend

    if not bool(
        getattr(
            frontend,
            "iq_playback_start_pending",
            False,
        )
    ):
        return

    tracked_node_uid = str(
        getattr(
            frontend,
            "iq_playback_node_uid",
            "",
        )
        or ""
    ).strip()

    if (
        tracked_node_uid
        and str(
            node_uid or ""
        ).strip() != tracked_node_uid
    ):
        return

    frontend.iq_playback_operation_id = str(
        operation_id or ""
    )
    frontend.iq_playback_start_pending = False
    frontend.iq_playback_running = True

    frontend.ui.label2_iq_playback_status.setText(
        "Playing..."
    )

    button = (
        frontend.ui.pushButton_iq_playback_start_stop
    )
    button.setText(
        "Stop"
    )
    button.setEnabled(
        True
    )
    button.setProperty(
        "running",
        True,
    )
    button.style().unpolish(
        button
    )
    button.style().polish(
        button
    )
    button.update()


async def responsePluginOperationStopped(
    component: object,
    node_uid: str,
    operation_id: str,
    plugin: str,
    operation: str,
) -> None:
    """
    Handle Request for Plugin Operation Stopped.

    Parameters
    ----------
    component : object
        Component
    node_uid : str
        Sensor node UID
    operation_id : str
        Operation ID
    plugin : str
        Plugin name
    operation : str
        Operation name
    """
    operations_list: QtWidgets.QListWidget = (
        component.frontend.ui.listWidget_operations
    )

    items = operations_list.findItems(
        f"{plugin} - {operation} (ID: {operation_id})",
        QtCore.Qt.MatchExactly,
    )

    for item in items:
        operations_list.takeItem(
            operations_list.row(
                item
            )
        )

    # IQ Playback lifecycle only.
    operation_name = str(
        operation or ""
    ).strip()

    if operation_name not in {
        "iq_playback",
        "iq_playback.py",
    }:
        return

    frontend = component.frontend

    playback_active = bool(
        getattr(
            frontend,
            "iq_playback_running",
            False,
        )
        or getattr(
            frontend,
            "iq_playback_start_pending",
            False,
        )
    )

    if not playback_active:
        return

    tracked_operation_id = str(
        getattr(
            frontend,
            "iq_playback_operation_id",
            "",
        )
        or ""
    ).strip()

    tracked_node_uid = str(
        getattr(
            frontend,
            "iq_playback_node_uid",
            "",
        )
        or ""
    ).strip()

    if (
        tracked_operation_id
        and str(
            operation_id or ""
        ).strip() != tracked_operation_id
    ):
        return

    if (
        tracked_node_uid
        and str(
            node_uid or ""
        ).strip() != tracked_node_uid
    ):
        return

    was_stopping = (
        str(
            frontend.ui.label2_iq_playback_status.text()
            or ""
        ).strip() == "Stopping..."
    )

    IQDataTabSlots._set_iq_playback_stopped(
        frontend,
        status_text=(
            "Stopped"
            if was_stopping
            else "Completed"
        ),
    )


async def savePlugin(component: object, plugin_name: str, plugin_data: str) -> None:
    """Save Plugin Data to File

    Parameters
    ----------
    component : object
        Component
    plugin_name : str
        Name of the plugin
    plugin_data : str
        Plugin data to save
    """
    # get the local plugin path from the UI or default to Downloads
    local_plugin_path = await get_fissure_plugin_editor_plugins_path()
    if not local_plugin_path:
        local_plugin_path = os.path.join(os.path.expanduser("~"), "Downloads")

    # Decode hex data
    plugin_data = binascii.a2b_hex(plugin_data)

    # Save file
    pathname = os.path.join(local_plugin_path, plugin_name + '.zip')
    with open(pathname, "wb") as f:
        f.write(plugin_data)

    # Create a path for the plugin to be extracted to
    extract_path = os.path.join(local_plugin_path, plugin_name)
    if os.path.exists(extract_path):
        copy_num = 1
        base_name = plugin_name
        while os.path.exists(extract_path):
            extract_path = os.path.join(local_plugin_path, f"{base_name} (Copy {copy_num})")
            copy_num += 1
    os.makedirs(extract_path, exist_ok=True)

    # Extract the zip file to the plugin directory
    with zipfile.ZipFile(pathname, "r") as zip_ref:
        zip_ref.extractall(extract_path)

    # Remove the zip file
    os.remove(pathname)

    # Refresh the local plugin list in the UI
    component.frontend.ui.toolButton_plugin_pkg_path_refresh.clicked.emit()


# async def responsePluginTableData(component: object, plugin_name: str, table_data_json: dict, install_files: List[str]):
#     """Populates table data after opening a plugin.

#     Parameters
#     ----------
#     component : object
#         Component
#     """
#     # Populate CSV Tables
#     table_data = json.loads(table_data_json)  # Convert JSON back to dictionary

#     for table_name, rows in table_data.items():
#         # Match Table to ComboBox Item
#         current_combobox_index = component.frontend.ui.comboBox_library_plugin_edit.findText(table_name)
#         if current_combobox_index == -1:
#             continue

#         # Get Corresponding Table Widget
#         component.frontend.ui.stackedWidget_library_plugin_tables.setCurrentIndex(current_combobox_index)
#         current_page = component.frontend.ui.stackedWidget_library_plugin_tables.currentWidget()
#         target_table = current_page.findChild(QtWidgets.QTableWidget)

#         if target_table:
#             # Get the headers from the table (expected headers from the database)
#             expected_headers = [
#                 target_table.horizontalHeaderItem(col).text() if target_table.horizontalHeaderItem(col) else ""
#                 for col in range(target_table.columnCount())
#             ]

#             # Check if the first row matches the expected headers
#             if rows and len(rows) > 0:
#                 first_row = rows[0]  # First row of data

#                 if len(first_row) != len(expected_headers):
#                     # Handle the mismatch in column count
#                     asyncio.ensure_future(
#                         fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
#                             component.frontend,
#                             f"Column count mismatch in table '{table_name}' between data and table headers."
#                         )
#                     )
#                     continue

#                 # Check if the first row values match the headers
#                 for col_index in range(len(first_row)):
#                     if first_row[col_index] != expected_headers[col_index]:
#                         # Handle the header mismatch
#                         asyncio.ensure_future(
#                             fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(
#                                 component.frontend,
#                                 f"In table '{table_name}', the value '{first_row[col_index]}' in the first row does not match the expected header '{expected_headers[col_index]}'."
#                             )
#                         )
#                         continue

#             # Insert rows into the table if header matches
#             for row in rows[1:]:  # Skip the first row (header row)
#                 target_row = target_table.rowCount()
#                 target_table.insertRow(target_row)
#                 for col_index, value in enumerate(row):
#                     item = QtWidgets.QTableWidgetItem(value)
#                     item.setTextAlignment(QtCore.Qt.AlignCenter)
#                     target_table.setItem(target_row, col_index, item)

#     # Populate Support Files Tables
#     page_mapping = {
#         "Single-Stage Flow Graphs": component.frontend.ui.tableWidget_library_plugin_attacks_support,
#         "Fuzzing Flow Graphs": component.frontend.ui.tableWidget_library_plugin_attacks_support,
#         "PD Flow Graphs": component.frontend.ui.tableWidget_library_plugin_demodulation_flow_graphs_support,
#         "Inspection Flow Graphs": component.frontend.ui.tableWidget_library_plugin_inspection_flow_graphs_support,
#         "Triggers": component.frontend.ui.tableWidget_library_plugin_triggers_support,
#     }

#     for filepath in install_files:
#         # Determine the table widget based on the keywords in the filepath
#         target_table = None
#         for keyword, table_widget in page_mapping.items():
#             if keyword in filepath:
#                 target_table = table_widget
#                 break
        
#         if target_table:
#             # Add a new row to the table
#             row_position = target_table.rowCount()
#             target_table.insertRow(row_position)
            
#             # Add the filepath as a new item
#             filepath_item = QtWidgets.QTableWidgetItem(filepath)
#             filepath_item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
#             filepath_item.setFlags(filepath_item.flags() & ~QtCore.Qt.ItemIsEditable)
#             target_table.setItem(row_position, 0, filepath_item)

#             # Empty New Filepath Item
#             new_filepath_item = QtWidgets.QTableWidgetItem("")
#             new_filepath_item.setTextAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
#             # new_filepath_item.setFlags(new_filepath_item.flags() & ~QtCore.Qt.ItemIsEditable)
#             target_table.setItem(row_position, 2, new_filepath_item)

#             # Action Comboboxes
#             new_action_combobox = QtWidgets.QComboBox(target_table, objectName='comboBox2_')
#             new_action_combobox.setFixedSize(73, 23)
#             target_table.setCellWidget(row_position, 1, new_action_combobox)
#             new_action_combobox.addItem("Keep")
#             new_action_combobox.addItem("Replace")
#             new_action_combobox.addItem("Delete")

#             # Function to handle enabling/disabling columns
#             def handle_combobox_change(target_table, row_position, index):
#                 if index == 0 or index == 2:  # Keep or Delete
#                     for col in [2, 3]:
#                         cell_widget = target_table.cellWidget(row_position, col)
#                         if isinstance(cell_widget, QtWidgets.QPushButton):
#                             cell_widget.setEnabled(False)
#                         else:
#                             item = target_table.item(row_position, col)
#                             if item:
#                                 item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEnabled)
#                 elif index == 1:  # Replace
#                     for col in [2, 3]:
#                         cell_widget = target_table.cellWidget(row_position, col)
#                         if isinstance(cell_widget, QtWidgets.QPushButton):
#                             cell_widget.setEnabled(True)
#                         else:
#                             item = target_table.item(row_position, col)
#                             if item:
#                                 item.setFlags(item.flags() | QtCore.Qt.ItemIsEnabled)

#                 # Ensure the table updates visually
#                 target_table.viewport().update()

#             # Create Pushbutton
#             new_pushbutton = QtWidgets.QPushButton(target_table, objectName='pushButton_')
#             new_pushbutton.setText("...")
#             new_pushbutton.setFixedSize(36, 23)
#             target_table.setCellWidget(row_position, 3, new_pushbutton)
#             new_pushbutton.clicked.connect(lambda checked, table=target_table, row=row_position: LibraryTabSlots._slotLibraryPluginSupportFileSelectionClicked(component.frontend, table, row))

#             # Activate Combobox Slot
#             new_action_combobox.currentIndexChanged.connect(
#                 lambda index, table=target_table, row=row_position: handle_combobox_change(table, row, index)
#             )
#             new_action_combobox.setCurrentIndex(0)
#             handle_combobox_change(target_table, row_position, 0)
            
#             # Resize Rows
#             target_table.resizeRowsToContents()
#         else:
#             component.logger.error(f"Supporting Files: No matching table widget for filepath '{filepath}'")

#     # Reset Combobox/Pages
#     if component.frontend.ui.comboBox_library_plugin_edit.currentIndex() == 0:
#         LibraryTabSlots._slotLibraryPluginEditChanged(component.frontend)
#     else:
#         component.frontend.ui.comboBox_library_plugin_edit.setCurrentIndex(0)  # Function not called when already 0


async def responsePluginProtocolParameters(component: object, plugin_name: str, protocol_name: str, parameters: dict):
    """Handle Request for Plugin Names

    Parameters
    ----------
    component : object
        Component
    """
    # UI Widgets
    doubleSpinBox_protocol_data_rate: QtWidgets.QDoubleSpinBox = component.frontend.ui.doubleSpinBox_protocol_data_rate
    checkBox_protocol_data_rates: QtWidgets.QCheckBox = component.frontend.ui.checkBox_protocol_data_rates
    doubleSpinBox_protocol_median_packet_lengths: QtWidgets.QDoubleSpinBox = component.frontend.ui.doubleSpinBox_protocol_median_packet_lengths
    checkBox_protocol_median_packet_lengths: QtWidgets.QCheckBox = component.frontend.ui.checkBox_protocol_median_packet_lengths
    listWidget_plugin_protocol_mod_type_list: QtWidgets.QListWidget = component.frontend.ui.listWidget_plugin_protocol_mod_type_list
    tableWidget_protocol_packet_type: QtWidgets.QTableWidget = component.frontend.ui.tableWidget_protocol_packet_type

    # Update Values
    data_rates = parameters.get('data_rates')
    if data_rates is None:
        doubleSpinBox_protocol_data_rate.setEnabled(False)
        checkBox_protocol_data_rates.setChecked(True)
    else:
        doubleSpinBox_protocol_data_rate.setEnabled(True)
        doubleSpinBox_protocol_data_rate.setValue(data_rates)
        checkBox_protocol_data_rates.setChecked(False)

    median_packet_lengths = parameters.get('median_packet_lengths')
    if median_packet_lengths is None:
        doubleSpinBox_protocol_median_packet_lengths.setEnabled(False)
        checkBox_protocol_median_packet_lengths.setChecked(True)
    else:
        doubleSpinBox_protocol_median_packet_lengths.setEnabled(True)
        doubleSpinBox_protocol_median_packet_lengths.setValue(median_packet_lengths)
        checkBox_protocol_median_packet_lengths.setChecked(False)

    listWidget_plugin_protocol_mod_type_list.clear()
    listWidget_plugin_protocol_mod_type_list.addItems(parameters.get('mod_types'))

    pkt_types = parameters.get('pkt_types')
    tableWidget_protocol_packet_type.clearContents()
    tableWidget_protocol_packet_type.setWordWrap(True)
    if not pkt_types is None:
        tableWidget_protocol_packet_type.setRowCount(len(pkt_types))
        cols = range(len(pkt_types[0]))
        for (r, row) in enumerate(pkt_types):
            for c in cols:
                tableWidget_protocol_packet_type.setItem(r, c, QtWidgets.QTableWidgetItem(row[c]))
    else:
        tableWidget_protocol_packet_type.setRowCount(0)


async def update_sensor_node_title(component: object, change: int):
    # get current number
    current_text = component.frontend.ui.tabWidget.tabBar().tabText(6)
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
    new_text = f"{base_text.strip()} ({new_count})"
    component.frontend.ui.tabWidget.tabBar().setTabText(6, new_text)


async def alertReturn(component: object, node_uid="", node_nickname="", alert_text=""):
    """
    Updates the Sensor Nodes Alert tab with a new alert.
    """
    # Get Sensor Node Label
    short_uid = str(node_uid or "").split("-")[0]

    if node_nickname and short_uid:
        node_label = f"{node_nickname} {short_uid}"
    elif node_nickname:
        node_label = node_nickname
    elif short_uid:
        node_label = short_uid
    else:
        node_label = "Unknown Node"

    # Generate a timestamp
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    sensor_node_text = f"[{node_label}]"
    formatted_message = f"{timestamp} {sensor_node_text} {alert_text}"

    # Append the message
    current_content = component.frontend.ui.textEdit2_sensor_nodes_alerts.toPlainText()
    updated_content = current_content + "\n" + formatted_message if current_content else formatted_message

    component.frontend.ui.textEdit2_sensor_nodes_alerts.setPlainText(updated_content)
    component.frontend.ui.textEdit2_sensor_nodes_alerts.verticalScrollBar().setValue(
        component.frontend.ui.textEdit2_sensor_nodes_alerts.verticalScrollBar().maximum()
    )

    # Calculate Alert Total
    current_text = component.frontend.ui.tabWidget_sensor_nodes.tabBar().tabText(2)
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

    new_count = current_count + 1
    new_text = f"{base_text.strip()} ({new_count})"

    # Update Alert Tab with Count
    component.frontend.ui.tabWidget_sensor_nodes.tabBar().setTabText(2, new_text)

    # Update Sensor Nodes Tab with Count
    await update_sensor_node_title(component, 1)


async def exploitReturn(component: object, node_uid: str, protocol:str, modulation:str, hardware:str, type:str, attack:str, variables:str):
    """ 
    Updates the Sensor Nodes Exploit tab with a new alert.
    """
    # Append the message
    row_position = component.frontend.ui.tableWidget_exploits.rowCount()
    component.frontend.ui.tableWidget_exploits.insertRow(row_position)
    component.frontend.ui.tableWidget_exploits.setItem(row_position, 0, QTableWidgetItem(protocol))
    component.frontend.ui.tableWidget_exploits.setItem(row_position, 1, QTableWidgetItem(modulation))
    component.frontend.ui.tableWidget_exploits.setItem(row_position, 2, QTableWidgetItem(hardware))
    component.frontend.ui.tableWidget_exploits.setItem(row_position, 3, QTableWidgetItem(type))
    component.frontend.ui.tableWidget_exploits.setItem(row_position, 4, QTableWidgetItem(attack))
    component.frontend.ui.tableWidget_exploits.setItem(row_position, 5, QTableWidgetItem(str(variables)))
    component.frontend.ui.tableWidget_exploits.resizeColumnsToContents()

    # Calculate Alert Total
    current_text = component.frontend.ui.tabWidget_sensor_nodes.tabBar().tabText(3)
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

    new_count = current_count + 1
    new_text = f"{base_text.strip()} ({new_count})"

    # Update Alert Tab with Count
    #component.frontend.ui.tabWidget_sensor_nodes.tabBar().setTabText(2, new_text)
    
    # Update Epxloits Tab with Count
    component.frontend.ui.tabWidget_sensor_nodes.tabBar().setTabText(3, new_text)
    
    # Update Sensor Nodes Tab with Count
    await update_sensor_node_title(component, 1)


async def snreport(component: object, node_uid: str, text:str):
    """
    Updates the Sensor Nodes Report tab with a new report.
    """
    # Append the message
    tableWidget_reports: QtWidgets.QTableWidget = component.frontend.ui.tableWidget_reports
    row_position = component.frontend.ui.tableWidget_reports.rowCount()
    component.frontend.ui.tableWidget_reports.insertRow(row_position)
    component.frontend.ui.tableWidget_reports.setItem(row_position, 0, QTableWidgetItem('\n'.join(text)))
    component.frontend.ui.tableWidget_reports.resizeRowsToContents()

    # Calculate Reports Total
    current_text = component.frontend.ui.tabWidget_sensor_nodes.tabBar().tabText(4)
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

    new_count = current_count + 1
    new_text = f"{base_text.strip()} ({new_count})"

    # update tab title
    component.frontend.ui.tabWidget_sensor_nodes.tabBar().setTabText(4, new_text)

    await update_sensor_node_title(component, 1)


async def findGPS_CoordinatesResults(component: object, coordinates=""):
    """
    Returns the GPS coordinate results to the NodeConfigureDialog.
    """
    # Populate Location
    component.frontend.popups["NodeConfigureDialog"].label2_lat_lon_alt.setText(str(coordinates))

    # Enable the Find Button
    component.frontend.popups["NodeConfigureDialog"].pushButton_find.setEnabled(True)


async def enableDisableListenerReturn(component: object, listener_name="", status=""):
    """
    Sets the new status for the listener with a matching name in the table.
    """
    # Access the table widget
    table = component.frontend.ui.tableWidget_sensor_nodes_listeners
    name_column_index = 2  # Assuming "Name" is in column 2 (index 2)
    status_column_index = 0  # Assuming "Status" is in column 0 (index 0)

    # Find the row with the matching name
    for row in range(table.rowCount()):
        item = table.item(row, name_column_index)
        if item and item.text() == listener_name:
            status_item = QtWidgets.QTableWidgetItem(status)
            status_item.setTextAlignment(QtCore.Qt.AlignCenter)
            
            # Set the status in the "Status" column
            table.setItem(row, status_column_index, status_item)
            # print(f"Updated status for '{listener_name}' to '{status}' in row {row}.")
            break
    else:
        component.logger.error(f"No matching listener found for name '{listener_name}'.")


async def deleteListenerReturn(component: object, listener_name=""):
    """
    Sets the new status for the listener with a matching name in the table.
    """
    # Access the table widget
    table = component.frontend.ui.tableWidget_sensor_nodes_listeners
    name_column_index = 2  # Assuming "Name" is in column 2 (index 2)

    # Find and remove the row with the matching name
    for row in range(table.rowCount()):
        item = table.item(row, name_column_index)
        if item and item.text() == listener_name:
            # Remove row, select the next row, if available
            selected_items = table.selectedItems()
            selected_row = selected_items[0].row()

            table.removeRow(row)

            new_row_count = table.rowCount()
            if new_row_count > 0:
                # Select the next row, or the last row if at the end
                new_row = min(selected_row, new_row_count - 1)
                table.selectRow(new_row)
            break
    else:
        component.logger.error(f"No matching listener found in the table for name '{listener_name}'.")


async def gpsBeaconEnableDisableIP_Return(component: object, gps_tak_beacon_status: bool):
    """
    Sets the state of the GPS TAK beacon enable/disable button for IP network connections.
    """
    # Populate Location
    enable_disable_button = component.frontend.popups["NodeConfigureDialog"].pushButton_remote_actions_ip_gps_beacon_enable_disable

    if gps_tak_beacon_status == True:
        enable_disable_button.setText("Disable")
    else:
        enable_disable_button.setText("Enable")


async def uptimeIP_Return(component: object, uptime: str):
    """
    Returns the uptime results to the NodeConfigureDialog.
    """
    # Open a Text Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["NodeConfigureDialog"], uptime)


async def memoryIP_Return(component: object, memory: str):
    """
    Returns the memory results to the NodeConfigureDialog.
    """
    # Open a Text Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["NodeConfigureDialog"], memory)


async def diskIP_Return(component: object, disk: str):
    """
    Returns the disk results to the NodeConfigureDialog.
    """
    # Open a Text Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["NodeConfigureDialog"], disk)


async def cpuIP_Return(component: object, cpu: str):
    """
    Returns the CPU percentage results to the NodeConfigureDialog.
    """
    # Open a Text Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["NodeConfigureDialog"], cpu)


async def processesIP_Return(component: object, processes: str):
    """
    Returns the processes results to the NodeConfigureDialog.
    """
    # Open a Text Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["NodeConfigureDialog"], processes)


async def ifconfigIP_Return(component: object, ifconfig: str):
    """
    Returns the ifconfig results to the NodeConfigureDialog.
    """
    # Open a Text Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["NodeConfigureDialog"], ifconfig)


async def iwconfigIP_Return(component: object, iwconfig: str):
    """
    Returns the iwconfig results to the NodeConfigureDialog.
    """
    # Open a Text Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["NodeConfigureDialog"], iwconfig)


async def pingIP_Return(component: object, ping: str):
    """
    Returns the iwconfig results to the NodeConfigureDialog.
    """
    # Open a Text Dialog
    ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["NodeConfigureDialog"], ping)


async def nodeRefreshReturn(component: object, nodes):
    """
    Returns the node information to the Node select dialog.
    """
    component.frontend.popups["NodeSelectDialog"].refreshNodes(nodes=nodes)


async def detectionReturn(component: object, detection: dict):
    """
    Receive one native FISSURE Detection for Dashboard engineering workflows.

    Tactical continues to consume the CoT copy through dashboardCoT_Message().
    """
    if not isinstance(detection, dict):
        component.logger.error("Dashboard detectionReturn received invalid detection data.")
        return

    try:
        TSITabSlots.append_tsi_active_detector_detection(component.frontend, detection)
    except Exception as exc:
        component.logger.error(
            f"Failed to update TSI detector table from native Detection: {exc}"
        )

    try:
        ArchiveTabSlots.handle_archive_replay_detection(component.frontend, detection)
    except Exception as exc:
        component.logger.error(
            f"Failed to process Archive Replay detector Detection: {exc}"
        )

    try:
        SingleActionTabSlots.handle_single_action_detection(component.frontend, detection)
    except Exception as exc:
        component.logger.error(
            f"Failed to process Single Action detector Detection: {exc}"
        )

    try:
        SequentialActionTabSlots.handle_sequential_actions_detection(component.frontend, detection)
    except Exception as exc:
        component.logger.error(
            f"Failed to process Sequential Actions detector Detection: {exc}"
        )


async def dashboardCoT_Message(component: object, raw_xml: str):
    """
    Receives a copy of the CoT message sent to the TAK server and hands it off for parsing.
    """
    try:
        cot_message = fissure.utils.cot_utils.parse_cot_xml(raw_xml)
    except Exception as e:
        component.logger.error(f"Failed to parse Dashboard CoT message: {e}")
        return

    fissure.utils.cot_utils.handle_tactical_cot_message(component, cot_message)

    try:
        TSITabSlots.append_tsi_active_detector_detection_from_cot(
            component.frontend,
            cot_message,
        )
    except Exception as e:
        component.logger.error(
            f"Failed to update TSI detector table: {e}"
        )


async def nodeStateUpdate(component: object, node_uid="", node={}):
    """
    Store the latest normalized node state from HIPRFISR.

    Also updates the selected-node top card when the selected node times out
    or reconnects, and mirrors that connection state into an existing
    Tactical node record.

    Heartbeat/status updates do not rebuild selected-node hardware controls.
    Hardware-dependent controls and gates are refreshed only when the selected
    node's connection state actually changes.
    """
    if not node_uid:
        return

    if node is None:
        node = {}

    frontend = component.frontend

    if not hasattr(frontend, "node_states"):
        frontend.node_states = {}

    previous_node_state = frontend.node_states.get(node_uid, {}) or {}
    previous_connected = (
        previous_node_state.get("connected")
        if isinstance(previous_node_state, dict)
        else None
    )
    connected = bool(node.get("connected", False))
    connection_state_changed = (
        previous_connected is None
        or bool(previous_connected) != connected
    )

    frontend.node_states[node_uid] = node

    tactical_nodes = getattr(frontend, "tactical_nodes", None)
    tactical_node = (
        tactical_nodes.get(node_uid)
        if isinstance(tactical_nodes, dict)
        else None
    )

    if isinstance(tactical_node, dict):
        reported_status = str(node.get("status") or "").strip()

        tactical_node["connected"] = connected
        tactical_node["status"] = (
            reported_status or "Unknown"
            if connected
            else "Disconnected"
        )

        TacticalTabSlots.update_tactical_node_roster_row(
            frontend,
            tactical_node,
        )

        if getattr(frontend, "selected_tactical_node_uid", None) == node_uid:
            TacticalTabSlots._updateTacticalNodeInfoFrameState(frontend)

        if hasattr(frontend, "tactical_map"):
            lat = tactical_node.get("lat")
            lon = tactical_node.get("lon")

            if lat is not None and lon is not None:
                frontend.tactical_map.add_node(
                    node_id=node_uid,
                    lat=lat,
                    lon=lon,
                    label=tactical_node.get("callsign") or node_uid,
                    active=cot_utils.is_tactical_node_active(
                        tactical_node
                    ),
                    status=tactical_node.get("status", ""),
                )

    selected_uid = str(getattr(frontend, "selected_node_uid", "") or "").strip()
    node_uid_text = str(node_uid or "").strip()

    selected_node_changed = (
        selected_uid == node_uid_text
        or selected_uid.endswith(node_uid_text)
        or node_uid_text.endswith(selected_uid)
        or selected_uid in node_uid_text
        or node_uid_text in selected_uid
    ) if selected_uid and node_uid_text else False

    if selected_node_changed:
        frontend.selected_node_ip = (
            node.get("node_ip_address")
            or node.get("ip")
            or frontend.selected_node_ip
        )

        set_selected_node_connection_state(
            frontend,
            connected=connected,
            node=node,
        )

        if hasattr(frontend, "selected_tactical_node_uid"):
            TacticalTabSlots._updateTacticalNodeInfoFrameState(frontend)

        if connection_state_changed:
            try:
                frontend.configureSelectedNodeHardware()
            except Exception as e:
                component.logger.debug(
                    f"Could not refresh selected-node hardware after connection-state change: {e}"
                )

            try:
                TSITabSlots.update_tsi_detector_selected_node_gate(frontend)
            except Exception as e:
                component.logger.debug(
                    "Could not update unified TSI Detector selected-node gate "
                    f"after connection-state change: {e}"
                )

            try:
                TSITabSlots.update_tsi_conditioner_selected_node_gate(frontend)
            except Exception as e:
                component.logger.debug(
                    "Could not update TSI Conditioner selected-node gate "
                    f"after connection-state change: {e}"
                )

            try:
                TSITabSlots.update_tsi_fe_selected_node_gate(frontend)
            except Exception as e:
                component.logger.debug(
                    "Could not update TSI Feature Extractor selected-node gate "
                    f"after connection-state change: {e}"
                )

            try:
                IQDataTabSlots.update_iq_record_selected_node_gate(frontend)
            except Exception as e:
                component.logger.debug(
                    "Could not update IQ Record selected-node gate "
                    f"after connection-state change: {e}"
                )

            try:
                ArchiveTabSlots.update_archive_replay_selected_node_gate(frontend)
            except Exception as e:
                component.logger.debug(
                    "Could not update Archive Replay selected-node gate "
                    f"after connection-state change: {e}"
                )

            try:
                SensorNodesTabSlots.update_sensor_nodes_file_navigation_selected_node_gate(frontend)
            except Exception as e:
                component.logger.debug(
                    "Could not update Sensor Nodes File Navigation selected-node gate "
                    f"after connection-state change: {e}"
                )

    try:
        TSITabSlots.update_tsi_detector_status_from_selected_node(
            frontend,
            node_uid=node_uid,
            status=node.get("status", ""),
        )
    except Exception as e:
        component.logger.debug(
            f"Could not update unified TSI Detector status: {e}"
        )

    try:
        TSITabSlots.update_tsi_conditioner_status_from_selected_node(
            frontend,
            node_uid=node_uid,
            status=node.get("status", ""),
        )
    except Exception as e:
        component.logger.debug(
            f"Could not update TSI Conditioner status: {e}"
        )

    try:
        IQDataTabSlots.update_iq_playback_status_from_selected_node(
            frontend,
            node_uid=node_uid,
            status=node.get(
                "status",
                "",
            ),
        )
    except Exception as e:
        component.logger.debug(
            "Could not update IQ Playback status "
            f"from selected node: {e}"
        )

    try:
        IQDataTabSlots.update_iq_inspection_status_from_selected_node(
            frontend,
            node_uid=node_uid,
            status=node.get(
                "status",
                "",
            ),
        )
    except Exception as e:
        component.logger.debug(
            "Could not update IQ Inspection status "
            f"from selected node: {e}"
        )

    try:
        await SingleActionTabSlots.update_single_action_status_from_selected_node(
            frontend,
            node_uid=node_uid,
            status=node.get("status", ""),
        )
    except Exception as e:
        component.logger.debug(
            f"Could not update Single Action status from selected node: {e}"
        )

    try:
        await FuzzingTabSlots.update_fuzzing_status_from_selected_node(
            frontend,
            node_uid=node_uid,
            status=node.get("status", ""),
        )
    except Exception as e:
        component.logger.debug(
            f"Could not update Fuzzing status from selected node: {e}"
        )

    try:
        await SequentialActionTabSlots.update_sequential_actions_status_from_selected_node(
            frontend,
            node_uid=node_uid,
            status=node.get("status", ""),
        )
    except Exception as e:
        component.logger.debug(
            f"Could not update Sequential Actions status from selected node: {e}"
        )        

    component.logger.debug(
        f"nodeStateUpdate: {node_uid} "
        f"connected={node.get('connected')} "
        f"last_seen={node.get('last_seen')} "
        f"status={node.get('status')}"
    )


async def nodeStateRemove(component: object, node_uid=""):
    """
    Remove a node from Dashboard-side normalized node state and Tactical UI.

    This is Dashboard-only cleanup for explicit node removal. It does not
    publish anything to TAK/WinTAK.
    """
    if not node_uid:
        return

    frontend = component.frontend

    # ---------------------------------------------------------
    # Normalized node state cache
    # ---------------------------------------------------------
    if hasattr(frontend, "node_states"):
        frontend.node_states.pop(node_uid, None)

    # ---------------------------------------------------------
    # Tactical node record cache
    # ---------------------------------------------------------
    if hasattr(frontend, "tactical_nodes"):
        frontend.tactical_nodes.pop(node_uid, None)

    # ---------------------------------------------------------
    # Tactical map pin/record
    # ---------------------------------------------------------
    if hasattr(frontend, "tactical_map"):
        try:
            frontend.tactical_map.remove_node(node_uid)
        except Exception as e:
            component.logger.error(
                f"Failed to remove Tactical node from map for {node_uid}: {e}"
            )

    # ---------------------------------------------------------
    # Tactical ecosystem roster row
    # ---------------------------------------------------------
    table = getattr(frontend.ui, "tableWidget_tactical_ecosystem", None)

    if table is not None:
        for row in range(table.rowCount() - 1, -1, -1):
            found = False

            for col in range(table.columnCount()):
                item = table.item(row, col)

                if item and item.data(QtCore.Qt.UserRole) == node_uid:
                    found = True
                    break

            if found:
                table.removeRow(row)
                break

        table.resizeColumnsToContents()
        table.resizeRowsToContents()
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setStretchLastSection(True)

    # ---------------------------------------------------------
    # Tactical selections
    # ---------------------------------------------------------
    if getattr(frontend, "selected_tactical_node_uid", None) == node_uid:
        frontend.selected_tactical_node_uid = None

        frontend.ui.label2_tactical_node_callsign.setText("")
        frontend.ui.label2_tactical_node_uuid.setText("")
        frontend.ui.label2_node_tactical_status.setText("")

        TacticalTabSlots.clear_tactical_node_targets(frontend)
        TacticalTabSlots.clear_tactical_detection_details(frontend)
        TacticalTabSlots.clear_tactical_node_soi_details(frontend)
        TacticalTabSlots.clear_tactical_node_artifact_details(frontend)
        TacticalTabSlots.clear_tactical_node_plugin_controls(frontend)

    if hasattr(frontend, "selected_tactical_node_uids"):
        frontend.selected_tactical_node_uids = [
            uid for uid in frontend.selected_tactical_node_uids
            if uid != node_uid
        ]

    # ---------------------------------------------------------
    # Top-bar selected node cleanup
    # ---------------------------------------------------------
    selected_uid = str(getattr(frontend, "selected_node_uid", "") or "").strip()
    removed_uid = str(node_uid or "").strip()

    selected_node_removed = (
        selected_uid
        and removed_uid
        and (
            selected_uid == removed_uid
            or selected_uid.endswith(removed_uid)
            or removed_uid.endswith(selected_uid)
            or selected_uid in removed_uid
            or removed_uid in selected_uid
        )
    )

    if selected_node_removed:
        try:
            TopBarSlots.clearSelectedNode(frontend)
        except Exception as e:
            component.logger.debug(
                f"Could not clear selected node after node removal: {e}"
            )

        frontend.selected_node_uid = ""
        frontend.selected_node_ip = ""
        frontend.selected_node_settings = {}

        try:
            frontend.configureSelectedNodeHardware()
        except Exception as e:
            component.logger.debug(
                f"Could not refresh selected-node hardware after node removal: {e}"
            )

        try:
            TSITabSlots.update_tsi_detector_selected_node_gate(frontend)
        except Exception as e:
            component.logger.debug(
                f"Could not update unified TSI Detector selected-node gate after node removal: {e}"
            )

        try:
            TSITabSlots.update_tsi_conditioner_selected_node_gate(frontend)
        except Exception as e:
            component.logger.debug(
                f"Could not update TSI Conditioner gate after selected node removal: {e}"
            )
        
        try:
            TSITabSlots.update_tsi_fe_selected_node_gate(frontend)
        except Exception as e:
            component.logger.debug(
                f"Could not update TSI Feature Extractor gate "
                f"after selected node removal: {e}"
            )
        
    # Recompute ecosystem selected-node labels/buttons after row removal.
    try:
        TacticalTabSlots.update_selected_tactical_nodes(frontend)
    except Exception as e:
        component.logger.debug(
            f"Could not refresh Tactical selected-node state after removal: {e}"
        )

    # Refresh selected Tactical node info frame state.
    try:
        TacticalTabSlots._updateTacticalNodeInfoFrameState(frontend)
    except Exception as e:
        component.logger.debug(
            f"Could not refresh Tactical node info frame after removal: {e}"
        )
    
    try:
        SensorNodesTabSlots.update_sensor_nodes_file_navigation_selected_node_gate(frontend)
    except Exception as e:
        component.logger.debug(
            f"Could not update Sensor Nodes File Navigation gate after selected node removal: {e}"
        )

    component.logger.debug(f"nodeStateRemove: {node_uid}")


async def sendArtifactsListTakReturn(
    component: object,
    node_uid: str = "",
    artifacts=None,
):
    """
    Replace or upsert Dashboard Artifact records using the canonical
    manifest-only schema, then route the same complete records to Tactical,
    Conditioner, Feature Extractor, and IQ Record.
    """
    artifacts = artifacts or []
    dashboard = component.frontend

    if not hasattr(
        dashboard,
        "tactical_artifacts",
    ):
        dashboard.tactical_artifacts = {}

    normalized_records = []

    for artifact in artifacts:
        if not isinstance(
            artifact,
            dict,
        ):
            continue

        artifact_id = str(
            artifact.get("id", "")
            or artifact.get(
                "artifact_id",
                "",
            )
            or ""
        ).strip()

        if not artifact_id:
            continue

        files = artifact.get(
            "files"
        )
        relations = artifact.get(
            "relations"
        )
        metadata = artifact.get(
            "metadata"
        )

        if not isinstance(
            files,
            list,
        ):
            files = []

        if not isinstance(
            relations,
            list,
        ):
            relations = []

        if not isinstance(
            metadata,
            dict,
        ):
            metadata = {}

        source_id = str(
            artifact.get(
                "source_id",
                "",
            )
            or artifact.get(
                "node_uid",
                "",
            )
            or node_uid
            or ""
        ).strip()

        operation_id = str(
            artifact.get(
                "operation_id",
                "",
            )
            or metadata.get(
                "operation_id",
                "",
            )
            or ""
        ).strip()

        normalized = dict(
            artifact
        )

        normalized.update(
            {
                "id":
                    artifact_id,
                "artifact_id":
                    artifact_id,
                "node_uid":
                    source_id,
                "source_id":
                    source_id,
                "operation_id":
                    operation_id,
                "name":
                    str(
                        artifact.get(
                            "name",
                            "Artifact",
                        )
                        or "Artifact"
                    ),
                "artifact_type":
                    str(
                        artifact.get(
                            "artifact_type",
                            "",
                        )
                        or metadata.get(
                            "artifact_type",
                            "",
                        )
                        or ""
                    ),
                "created_at":
                    str(
                        artifact.get(
                            "created_at",
                            "",
                        )
                        or ""
                    ),
                "modified_at":
                    str(
                        artifact.get(
                            "modified_at",
                            "",
                        )
                        or ""
                    ),
                "time":
                    str(
                        artifact.get(
                            "modified_at",
                            "",
                        )
                        or artifact.get(
                            "created_at",
                            "",
                        )
                        or ""
                    ),
                "files":
                    files,
                "relations":
                    relations,
                "file_count":
                    int(
                        artifact.get(
                            "file_count",
                            len(files),
                        )
                        or len(files)
                    ),
                "total_size":
                    int(
                        artifact.get(
                            "total_size",
                            sum(
                                int(
                                    item.get(
                                        "size",
                                        0,
                                    )
                                    or 0
                                )
                                for item in files
                                if isinstance(
                                    item,
                                    dict,
                                )
                            ),
                        )
                        or 0
                    ),
                "metadata":
                    metadata,
            }
        )

        dashboard.tactical_artifacts[
            artifact_id
        ] = normalized

        normalized_records.append(
            normalized
        )

    selected_node_uid = str(
        getattr(
            dashboard,
            "selected_tactical_node_uid",
            "",
        )
        or ""
    ).strip()

    if selected_node_uid == str(
        node_uid or ""
    ).strip():
        try:
            TacticalTabSlots.rebuild_tactical_node_artifacts(
                dashboard,
                node_uid,
            )

        except Exception as error:
            component.logger.debug(
                "Could not rebuild Tactical artifacts: "
                f"{error}"
            )

    try:
        TSITabSlots.handle_tsi_conditioner_artifact_metadata(
            dashboard,
            node_uid=node_uid,
            artifacts=normalized_records,
        )

    except Exception as error:
        component.logger.debug(
            "Could not route Artifact metadata "
            "to Conditioner: "
            f"{error}"
        )

    try:
        TSITabSlots.handle_tsi_fe_artifact_metadata(
            dashboard,
            node_uid=node_uid,
            artifacts=normalized_records,
        )

    except Exception as error:
        component.logger.debug(
            "Could not route Artifact metadata "
            "to Feature Extractor: "
            f"{error}"
        )

    for artifact_record in normalized_records:
        try:
            IQDataTabSlots.handle_iq_record_artifact_complete(
                dashboard,
                artifact_record,
            )

        except Exception as error:
            component.logger.debug(
                "Could not route Artifact metadata "
                "to IQ Record: "
                f"{error}"
            )


async def sendSoisListTakReturn(
    component: object,
    node_uid: str = "",
    sois=None,
):
    """
    Replaces the Dashboard SOI cache for one node with HIPRFISR's
    authoritative merged SOI records, then refreshes every SOI consumer.

    Linked Artifact metadata is also requested because Feature Extractor SOI
    inputs resolve their files through the shared Artifact cache.
    """
    frontend = component.frontend
    sois = sois or []
    node_uid = str(node_uid or "").strip()

    if not hasattr(frontend, "tactical_sois"):
        frontend.tactical_sois = {}

    stale_keys = [
        soi_key
        for soi_key, record in frontend.tactical_sois.items()
        if isinstance(record, dict)
        and str(record.get("node_uid", "") or "").strip() == node_uid
    ]

    for soi_key in stale_keys:
        frontend.tactical_sois.pop(soi_key, None)

        try:
            frontend.tactical_map.remove_soi(soi_key)
        except Exception:
            pass

    for soi in sois:
        if not isinstance(soi, dict):
            continue

        await soiUpdate(
            component,
            soi=soi,
        )

    selected_node_uid = str(
        getattr(frontend, "selected_tactical_node_uid", "")
        or ""
    ).strip()

    if selected_node_uid == node_uid:
        try:
            TacticalTabSlots.rebuild_tactical_node_sois(
                frontend,
                node_uid,
            )
        except Exception as error:
            component.logger.debug(
                f"Could not rebuild Tactical SOIs after refresh: {error}"
            )

    try:
        TSITabSlots.refresh_tsi_fe_input_sois(
            frontend
        )
        TSITabSlots.refresh_tsi_fe_run_sois(
            frontend
        )
    except Exception as error:
        component.logger.debug(
            "Could not refresh Feature Extractor SOI selectors "
            f"after authoritative SOI refresh: {error}"
        )

    try:
        await component.tacticalNodeArtifactsRefresh(
            node_uid
        )
    except Exception as error:
        component.logger.debug(
            "Could not refresh linked Artifact metadata after SOI refresh: "
            f"{error}"
        )


def queryPluginActionsResults(
    component: object,
    requester_uid: str = "",
    requester_type: str = "",
    node_uid: str = "",
    context: str = "",
    actions: list = None,
):
    """
    Route generic filtered action discovery results to the Dashboard tab
    that requested them.
    """
    actions = actions or []

    frontend = component.frontend

    if context.startswith("sensor_nodes.autorun"):
        SensorNodesTabSlots.handle_sensor_nodes_autorun_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return

    if context.startswith("targets_actions.single_action"):
        SingleActionTabSlots.handle_single_action_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return

    if context.startswith("targets_actions.fuzzing"):
        FuzzingTabSlots.handle_fuzzing_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return

    if context.startswith("targets_actions.sequential_action.selection"):
        dialog = frontend.popups.get("SequentialActionSelectionDialog")
        if dialog is not None:
            dialog.handle_action_query_results(
                node_uid=node_uid,
                context=context,
                actions=actions,
            )
        return
    
    if context.startswith("detector.selection"):
        dialog = frontend.popups.get("DetectorSelectionDialog")
        if dialog is not None:
            dialog.handle_action_query_results(
                node_uid=node_uid,
                context=context,
                actions=actions,
            )
        return

    if context.startswith("tsi.detector"):
        TSITabSlots.handle_tsi_detector_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return

    if context.startswith("tsi.conditioner"):
        TSITabSlots.handle_tsi_conditioner_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return

    if context.startswith("tsi.feature_extractor"):
        TSITabSlots.handle_tsi_fe_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return    

    if context.startswith("iq.record"):
        IQDataTabSlots.handle_iq_record_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return

    if context.startswith("iq.playback"):
        IQDataTabSlots.handle_iq_playback_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return

    if context.startswith("iq.inspection"):
        IQDataTabSlots.handle_iq_inspection_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return

    if context.startswith("archive.replay"):
        ArchiveTabSlots.handle_archive_replay_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return

    if context.startswith("tactical."):
        component.logger.debug(
            f"Unhandled Tactical action query context={context}, actions={actions}"
        )
        return

    component.logger.debug(
        f"Unhandled plugin action query context={context}, actions={actions}"
    )


def queryPluginActionSchemaResults(
    component: object,
    requester_uid: str = "",
    requester_type: str = "",
    node_uid: str = "",
    plugin_name: str = "",
    action_name: str = "",
    schema: dict = None,
    context: str = "",
):
    """
    Route Dashboard-only plugin action schema results to the tab/workflow
    that requested them.
    """
    schema = schema or {}

    if not isinstance(schema, dict):
        schema = {"params": []}

    if "params" not in schema or not isinstance(schema.get("params"), list):
        schema["params"] = []

    frontend = component.frontend

    if context.startswith("sensor_nodes.autorun"):
        SensorNodesTabSlots.handle_sensor_nodes_autorun_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return
    
    if context.startswith("targets_actions.single_action"):
        SingleActionTabSlots.handle_single_action_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return

    if context.startswith("targets_actions.fuzzing"):
        FuzzingTabSlots.handle_fuzzing_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return

    if context.startswith("targets_actions.sequential_action.selection"):
        dialog = frontend.popups.get("SequentialActionSelectionDialog")
        if dialog is not None:
            dialog.handle_action_schema(
                plugin_name=plugin_name,
                action_name=action_name,
                node_uid=node_uid,
                parameters=schema.get("params", []),
            )
        return

    if context.startswith("detector.selection"):
        dialog = frontend.popups.get("DetectorSelectionDialog")
        if dialog is not None:
            dialog.handle_action_schema(
                plugin_name=plugin_name,
                action_name=action_name,
                node_uid=node_uid,
                parameters=schema.get("params", []),
            )
        return

    if context.startswith("tsi.detector"):
        TSITabSlots.handle_tsi_detector_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return
    
    if context.startswith("tsi.conditioner"):
        TSITabSlots.handle_tsi_conditioner_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return

    if context.startswith("tsi.feature_extractor"):
        TSITabSlots.handle_tsi_fe_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return    

    if context.startswith("iq.record"):
        IQDataTabSlots.handle_iq_record_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return

    if context.startswith("iq.playback"):
        IQDataTabSlots.handle_iq_playback_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return

    if context.startswith("iq.inspection"):
        IQDataTabSlots.handle_iq_inspection_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return

    if context.startswith("archive.replay"):
        ArchiveTabSlots.handle_archive_replay_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return

    if context.startswith("tactical."):
        component.logger.debug(
            f"Unhandled Tactical filtered action schema context={context}, "
            f"plugin={plugin_name}, action={action_name}"
        )
        return

    component.logger.debug(
        f"Unhandled plugin action schema context={context}, "
        f"plugin={plugin_name}, action={action_name}"
    )


async def soiUpdate(component: object, soi=None):
    """
    Receive a hub-backed SOI and preserve its complete cumulative record in the
    Dashboard Tactical model.
    """
    if soi is None or not isinstance(soi, dict):
        return

    frontend = component.frontend

    if not hasattr(frontend, "tactical_sois"):
        frontend.tactical_sois = {}

    node_uid = str(soi.get("node_uid", "") or "").strip()
    soi_id = str(soi.get("soi_id", "") or "").strip()

    if not soi_id:
        return

    soi_key = str(
        soi.get("soi_key", "")
        or f"{node_uid}:{soi_id}"
    )

    summary = soi.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}

    artifact_ids = soi.get(
        "artifact_ids",
        summary.get("artifact_ids", []),
    )
    if not isinstance(artifact_ids, list):
        artifact_ids = [artifact_ids]
    artifact_ids = [
        str(value or "").strip()
        for value in artifact_ids
        if str(value or "").strip()
    ]

    artifact_links = soi.get(
        "artifact_links",
        summary.get("artifact_links", []),
    )
    if not isinstance(artifact_links, list):
        artifact_links = []

    detection_snapshots = soi.get(
        "detection_snapshots",
        summary.get("detection_snapshots", []),
    )
    if not isinstance(detection_snapshots, list):
        detection_snapshots = [detection_snapshots]
    detection_snapshots = [
        dict(value)
        for value in detection_snapshots
        if isinstance(value, dict)
    ]

    detection_ids = soi.get(
        "detection_ids",
        summary.get("detection_ids", []),
    )
    if not isinstance(detection_ids, list):
        detection_ids = [detection_ids]
    detection_ids = [
        str(value or "").strip()
        for value in detection_ids
        if str(value or "").strip()
    ]

    analysis_history = soi.get(
        "analysis_history",
        summary.get("analysis_history", []),
    )
    if not isinstance(analysis_history, list):
        analysis_history = [analysis_history]
    analysis_history = [
        dict(value)
        for value in analysis_history
        if isinstance(value, dict)
    ]

    frequency_mhz = soi.get("frequency_mhz")

    frequency_display = ""
    if frequency_mhz not in [None, "", "None"]:
        try:
            frequency_display = f"{float(frequency_mhz):.3f} MHz"
        except Exception:
            frequency_display = str(frequency_mhz)

    model_classification = str(
        soi.get("model_classification", "")
        or ""
    )
    model_confidence = soi.get("model_confidence", "")

    model_display = model_classification
    if (
        model_classification
        and model_confidence not in [None, "", "None"]
    ):
        model_display = (
            f"{model_classification} ({model_confidence}%)"
        )

    record = dict(soi)
    record.update({
        "soi_key": soi_key,
        "uid": f"fissure-soi-{node_uid}-{soi_id}",
        "event_id": f"fissure-soi-{node_uid}-{soi_id}",
        "node_uid": node_uid,
        "soi_id": soi_id,
        "operation_id": soi.get("operation_id", ""),
        "artifact_id": soi.get("artifact_id", ""),
        "artifact_ids": artifact_ids,
        "artifact_links": artifact_links,
        "detection_ids": detection_ids,
        "detection_snapshots": detection_snapshots,
        "analysis_history": analysis_history,
        "frequency_mhz": frequency_mhz,
        "frequency_display": frequency_display,
        "status": soi.get("status", ""),
        "time": soi.get("observation_time", "") or "",
        "stage": soi.get("stage", ""),
        "stage_order": soi.get("stage_order"),
        "model_classification": model_classification,
        "model_confidence_pct": model_confidence,
        "model_classification_display": model_display,
        "database_classification": soi.get(
            "database_classification",
            "",
        ),
        "lat": soi.get("lat"),
        "lon": soi.get("lon"),
        "hae_m": soi.get("hae_m"),
        "summary": summary,
        "raw": soi,
        "raw_xml": "",
    })

    frontend.tactical_sois[soi_key] = record

    TacticalTabSlots.update_tactical_node_soi_row(
        frontend,
        record,
    )


async def dashboardArtifactTransferStatus(
        component: object,
        transfer_id: str,
        success: bool,
        message: str,
    ) -> None:
        """Handle setup failures reported before binary streaming begins."""
        if success:
            component.logger.info(
                "Artifact transfer %s: %s",
                transfer_id,
                message,
            )
            return

        component.artifact_transfer_controller.fail_request(
            transfer_id,
            message,
        )
