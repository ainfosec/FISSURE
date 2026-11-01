import fissure.comms
import time
from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import QTableWidget, QTableWidgetItem
import yaml
import os
import subprocess
import ast
import asyncio
from typing import List
import json
import qasync
from fissure.Dashboard.Slots import TacticalTabSlots

from fissure.Dashboard.UI_Components.Qt5 import MyMessageBox
from fissure.Dashboard.Slots import (
    ArchiveTabSlots,
    DashboardSlots,
    FuzzingTabSlots,
    IQDataTabSlots,
    LibraryTabSlots,
    ListeningPostsTabSlots,
    LogTabSlots,
    MenuBarSlots,
    ScapyTabSlots,
    SensorNodesTabSlots,
    SensorNodesPluginsTabSlots,
    SequentialActionTabSlots,
    SingleActionTabSlots,
    StatusBarSlots,
    TargetsTabSlots,    
    TopBarSlots,
    TSITabSlots,
)

from fissure.utils import cot_utils
from fissure.utils.selected_node_utils import set_selected_node_connection_state


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
        TSITabSlots.update_sa_classifier_selected_node_gate(component.frontend)
    except Exception as e:
        component.logger.debug(
            f"Could not update Classifier selected-node gate after recallSettingsReturn: {e}"
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
    else:
        pass
        # component.frontend.popups["NodeConfigureDialog"].sensorNodeDisconnected()


async def componentConnected(component: object, component_name=""):
    """
    Update status bar and other widgets with new connection status.
    """
    if component_name == fissure.comms.Identifiers.TSI:
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


async def refreshSensorNodeActivityResults(
    component: object,
    node_uid="",
    operations=None,
    log_entries=None,
):
    """Populate the read-only Sensor Nodes Activity snapshot."""
    SensorNodesTabSlots.populate_sensor_nodes_activity_snapshot(
        component.frontend,
        node_uid=node_uid,
        operations=operations or [],
        log_entries=log_entries or [],
    )


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

    # Gallery Protocols
    component.frontend.ui.comboBox_library_gallery_protocol.clear()
    protocols_with_images = []
    for p in protocols:
        if len(component.frontend.findGalleryImages(p)) > 0:
            protocols_with_images.append(p)
    component.frontend.ui.comboBox_library_gallery_protocol.addItems(sorted(protocols_with_images))

    # Refresh Browse Table
    LibraryTabSlots._slotLibraryBrowseChanged(component.frontend)

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


async def queryListeningPostsReturn(
    component: object,
    posts=None,
    error="",
):
    """Populate the Targets & Actions Listening Posts workspace."""
    ListeningPostsTabSlots.populate_listening_posts(
        component.frontend,
        posts=posts or [],
        error=error,
    )


async def listeningPostOperationReturn(
    component: object,
    action="",
    post_id="",
    success=False,
    message="",
    posts=None,
):
    """Apply one Listening Post create/update/start/stop/delete result."""
    ListeningPostsTabSlots.handle_listening_post_operation_result(
        component.frontend,
        action=action,
        post_id=post_id,
        success=success,
        message=message,
        posts=posts or [],
    )


async def listeningPostUpdate(
    component: object,
    post=None,
):
    """Apply one live HIPRFISR Listening Post status/activity update."""
    ListeningPostsTabSlots.handle_listening_post_update(
        component.frontend,
        post=post or {},
    )


async def refreshPluginInventoryResults(
    component: object,
    node_uid="",
    hub_inventory=None,
    node_inventory=None,
    error="",
):
    """Populate the Sensor Nodes Plugins inventory from one explicit refresh."""
    SensorNodesPluginsTabSlots.populate_plugin_inventory(
        component.frontend,
        node_uid=node_uid,
        hub_inventory=hub_inventory or {},
        node_inventory=node_inventory or {},
        error=error,
    )


async def repairPluginSetupResults(
    component: object,
    node_uid="",
    plugin_name="",
    success=False,
    status="",
    message="",
    output="",
    hub_inventory=None,
    node_inventory=None,
):
    """Apply a setup-repair result and refreshed inventory to the Plugins page."""
    SensorNodesPluginsTabSlots.handle_plugin_setup_result(
        component.frontend,
        node_uid=node_uid,
        plugin_name=plugin_name,
        success=success,
        status=status,
        message=message,
        output=output,
        hub_inventory=hub_inventory,
        node_inventory=node_inventory,
    )


async def deployPluginResults(
    component: object,
    node_uid="",
    plugin_name="",
    transfer_id="",
    success=False,
    status="",
    message="",
    output="",
    hub_inventory=None,
    node_inventory=None,
):
    """Apply one remote Deploy/Update result to the Plugins page."""
    SensorNodesPluginsTabSlots.handle_plugin_deploy_result(
        component.frontend,
        node_uid=node_uid,
        plugin_name=plugin_name,
        transfer_id=transfer_id,
        success=success,
        status=status,
        message=message,
        output=output,
        hub_inventory=hub_inventory,
        node_inventory=node_inventory,
    )


async def removeManagedPluginResults(
    component: object,
    node_uid="",
    plugin_name="",
    success=False,
    status="",
    message="",
    output="",
    hub_inventory=None,
    node_inventory=None,
):
    """Apply one managed plugin-removal result to the Plugins page."""
    SensorNodesPluginsTabSlots.handle_plugin_remove_result(
        component.frontend,
        node_uid=node_uid,
        plugin_name=plugin_name,
        success=success,
        status=status,
        message=message,
        output=output,
        hub_inventory=hub_inventory,
        node_inventory=node_inventory,
    )


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


async def responsePluginOperationStarted(
    component: object,
    node_uid: str,
    operation_id: str,
    plugin: str,
    operation: str,
    parameters: dict,
) -> None:
    """Handle Request for Plugin Operation Started."""

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


async def newCoTLogSessionReturn(component: object, success=False, session_dir="", error=""):
    """Report the result of starting a new CoT logging session."""
    if success:
        session_name = os.path.basename(str(session_dir).rstrip(os.sep))
        message = f"New CoT log session started: {session_name}"
        component.logger.info(message)
        component.frontend.statusBar().showMessage(message, 10000)
        return

    message = str(error or "Could not start a new CoT log session.")
    component.logger.warning(message)
    component.frontend.statusBar().showMessage(message, 10000)


async def findGPS_CoordinatesResults(component: object, coordinates=""):
    """
    Returns the GPS coordinate results to the NodeConfigureDialog.
    """
    # Populate Location
    component.frontend.popups["NodeConfigureDialog"].label2_lat_lon_alt.setText(str(coordinates))

    # Enable the Find Button
    component.frontend.popups["NodeConfigureDialog"].pushButton_find.setEnabled(True)


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


async def inspectionReturn(
    component: object,
    node_uid: str = "",
    operation_id: str = "",
    inspection: dict = None,
    final: bool = True,
    timestamp: str = "",
):
    """Route one structured Inspection result into the Inspection workspace."""
    if not isinstance(inspection, dict):
        component.logger.error("Dashboard inspectionReturn received invalid Inspection data.")
        return

    try:
        TSITabSlots.handle_sa_inspection_return(
            component.frontend,
            node_uid=node_uid,
            operation_id=operation_id,
            inspection=inspection,
            final=final,
            timestamp=timestamp,
        )
    except Exception as error:
        component.logger.error(
            f"Failed to process Inspection result: {error}"
        )


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

    try:
        TargetsTabSlots.handle_target_geolocation_detection(component.frontend, detection)
    except Exception as exc:
        component.logger.error(
            f"Failed to update Target geolocation observations: {exc}"
        )        


async def dashboardCoT_Message(component: object, raw_xml: str):
    """
    Receive one CoT message for Tactical parsing.

    Explicitly marked replay messages may also repopulate the Target
    Geolocation observation cache without entering live action workflows.
    """
    try:
        cot_message = fissure.utils.cot_utils.parse_cot_xml(raw_xml)
    except Exception as e:
        component.logger.error(f"Failed to parse Dashboard CoT message: {e}")
        return

    fissure.utils.cot_utils.handle_tactical_cot_message(component, cot_message)

    is_replay = bool(cot_message.get("replay_dashboard"))

    if not is_replay:
        try:
            TSITabSlots.append_tsi_active_detector_detection_from_cot(
                component.frontend,
                cot_message,
            )
        except Exception as e:
            component.logger.error(
                f"Failed to update TSI detector table: {e}"
            )

    if is_replay and cot_message.get("kind") == "detection":
        try:
            detection = fissure.utils.cot_utils.cot_to_native_detection_record(cot_message)
            target_id = str((detection or {}).get("target_id") or "").strip()
            target = (getattr(component.frontend, "tactical_targets", {}) or {}).get(target_id)
            if detection and isinstance(target, dict) and target.get("_replay_only"):
                TargetsTabSlots.handle_target_geolocation_detection(
                    component.frontend,
                    detection,
                )
        except Exception as e:
            component.logger.error(
                f"Failed to update Target geolocation observations from replay: {e}"
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

        try:
            SensorNodesTabSlots.update_sensor_nodes_activity_selected_node_gate(frontend)
        except Exception as e:
            component.logger.debug(
                f"Could not update Sensor Nodes Activity from selected-node state: {e}"
            )

        try:
            SensorNodesPluginsTabSlots.update_sensor_nodes_plugins_selected_node_gate(frontend)
        except Exception as e:
            component.logger.debug(
                f"Could not update Sensor Nodes Plugins from selected-node state: {e}"
            )            
    
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
                TSITabSlots.update_sa_classifier_selected_node_gate(frontend)
            except Exception as e:
                component.logger.debug(
                    f"Could not update Classifier selected-node gate after connection-state change: {e}"
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
        TSITabSlots.update_sa_classifier_status_from_selected_node(
            frontend,
            node_uid=node_uid,
            status=node.get("status", ""),
        )
    except Exception as e:
        component.logger.debug(
            f"Could not update Signal Analysis Classifier status: {e}"
        )        

    try:
        TSITabSlots.update_sa_survey_status_from_selected_node(
            frontend,
            node_uid=node_uid,
            status=node.get("status", ""),
        )
    except Exception as e:
        component.logger.debug(
            f"Could not update Survey status from selected node: {e}"
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

        TacticalTabSlots.update_tactical_node_stream_button_state(frontend)

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

        try:
            TSITabSlots.update_sa_classifier_selected_node_gate(frontend)
        except Exception as e:
            component.logger.debug(
                f"Could not update Classifier gate after selected node removal: {e}"
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



async def sendArtifactsListTakReturn(component: object, node_uid: str = "", artifacts=None):
    """
    Replace or upsert Dashboard Artifact records using the canonical
    manifest-only schema, then route the same complete records to Tactical,
    Conditioner, Feature Extractor, and IQ Record.
    """
    artifacts = artifacts or []
    dashboard = component.frontend

    if not hasattr(dashboard, "tactical_artifacts"):
        dashboard.tactical_artifacts = {}

    normalized_records = []

    for artifact in artifacts:
        if not isinstance(artifact, dict):
            continue

        artifact_id = str(
            artifact.get("id", "") or artifact.get("artifact_id", "") or ""
        ).strip()
        if not artifact_id:
            continue

        files = artifact.get("files")
        relations = artifact.get("relations")
        metadata = artifact.get("metadata")

        if not isinstance(files, list):
            files = []
        if not isinstance(relations, list):
            relations = []
        if not isinstance(metadata, dict):
            metadata = {}

        source_id = str(
            artifact.get("source_id", "")
            or artifact.get("node_uid", "")
            or node_uid
            or ""
        ).strip()
        operation_id = str(
            artifact.get("operation_id", "")
            or metadata.get("operation_id", "")
            or ""
        ).strip()

        normalized = dict(artifact)
        normalized.update(
            {
                "id": artifact_id,
                "artifact_id": artifact_id,
                "node_uid": source_id,
                "source_id": source_id,
                "operation_id": operation_id,
                "name": str(artifact.get("name", "Artifact") or "Artifact"),
                "artifact_type": str(
                    artifact.get("artifact_type", "")
                    or metadata.get("artifact_type", "")
                    or ""
                ),
                "created_at": str(artifact.get("created_at", "") or ""),
                "modified_at": str(artifact.get("modified_at", "") or ""),
                "time": str(
                    artifact.get("modified_at", "")
                    or artifact.get("created_at", "")
                    or ""
                ),
                "files": files,
                "relations": relations,
                "file_count": int(artifact.get("file_count", len(files)) or len(files)),
                "total_size": int(
                    artifact.get(
                        "total_size",
                        sum(
                            int(item.get("size", 0) or 0)
                            for item in files
                            if isinstance(item, dict)
                        ),
                    )
                    or 0
                ),
                "metadata": metadata,
            }
        )

        dashboard.tactical_artifacts[artifact_id] = normalized
        normalized_records.append(normalized)

    selected_node_uid = str(
        getattr(dashboard, "selected_tactical_node_uid", "") or ""
    ).strip()
    if selected_node_uid == str(node_uid or "").strip():
        try:
            TacticalTabSlots.rebuild_tactical_node_artifacts(dashboard, node_uid)
        except Exception as error:
            component.logger.debug(f"Could not rebuild Tactical artifacts: {error}")

    try:
        TSITabSlots.handle_tsi_conditioner_artifact_metadata(
            dashboard, node_uid=node_uid, artifacts=normalized_records
        )
    except Exception as error:
        component.logger.debug(f"Could not route Artifact metadata to Conditioner: {error}")

    try:
        TSITabSlots.handle_tsi_fe_artifact_metadata(
            dashboard, node_uid=node_uid, artifacts=normalized_records
        )
    except Exception as error:
        component.logger.debug(f"Could not route Artifact metadata to Feature Extractor: {error}")

    try:
        TSITabSlots.handle_sa_classifier_artifact_metadata(
            dashboard, node_uid=node_uid, artifacts=normalized_records
        )
    except Exception as error:
        component.logger.debug(f"Could not route Artifact metadata to Classifier: {error}")

    for artifact_record in normalized_records:
        try:
            IQDataTabSlots.handle_iq_record_artifact_complete(dashboard, artifact_record)
        except Exception as error:
            component.logger.debug(f"Could not route Artifact metadata to IQ Record: {error}")

        try:
            TSITabSlots.handle_sa_capture_artifact_complete(dashboard, artifact_record)
        except Exception as error:
            component.logger.debug(
                f"Could not route Artifact metadata to Signal Analysis Capture: {error}"
            )

    try:
        TSITabSlots.handle_sa_inspection_artifact_metadata(
            dashboard, node_uid=node_uid, artifacts=normalized_records
        )
    except Exception as error:
        component.logger.debug(
            f"Could not route Artifact metadata to Signal Analysis Inspection: {error}"
        )

    try:
        from fissure.Dashboard.Slots.TSITabSlots import pd_demodulation

        pd_demodulation.handle_sa_pd_demodulation_artifact_metadata(
            dashboard, node_uid=node_uid, artifacts=normalized_records
        )
    except Exception as error:
        component.logger.debug(f"Could not route Artifact metadata to Demodulation: {error}")

    # Route the same normalized records to Single Action for its Artifact button.
    try:
        from fissure.Dashboard.Slots import SingleActionTabSlots

        SingleActionTabSlots.handle_single_action_artifact_metadata(
            dashboard, node_uid=node_uid, artifacts=normalized_records
        )
    except Exception as error:
        component.logger.debug(f"Could not route Artifact metadata to Single Action: {error}")

    try:
        TSITabSlots.refresh_sa_sois_selected_details(dashboard)
    except Exception as error:
        component.logger.debug(
            f"Could not refresh Signal Analysis SOI evidence: {error}"
        )


async def sendSoisListTakReturn(
    component: object,
    node_uid: str = "",
    sois=None,
):
    """
    Replace the Dashboard SOI cache with HIPRFISR's authoritative records.

    A non-empty node_uid replaces one node's records. A blank node_uid is a
    Signal Analysis global refresh and replaces the entire Dashboard SOI cache.
    """
    frontend = component.frontend
    sois = sois or []
    node_uid = str(node_uid or "").strip()

    if not hasattr(frontend, "tactical_sois"):
        frontend.tactical_sois = {}

    if node_uid:
        stale_keys = [
            soi_key
            for soi_key, record in frontend.tactical_sois.items()
            if isinstance(record, dict)
            and str(record.get("node_uid", "") or "").strip() == node_uid
        ]
    else:
        stale_keys = list(frontend.tactical_sois.keys())

    for soi_key in stale_keys:
        frontend.tactical_sois.pop(soi_key, None)

        try:
            frontend.tactical_map.remove_soi(soi_key)
        except Exception:
            pass

    frontend.sa_sois_bulk_refreshing = True

    try:
        for soi in sois:
            if not isinstance(soi, dict):
                continue

            await soiUpdate(
                component,
                soi=soi,
            )
    finally:
        frontend.sa_sois_bulk_refreshing = False

    selected_node_uid = str(
        getattr(frontend, "selected_tactical_node_uid", "")
        or ""
    ).strip()

    if selected_node_uid and (
        not node_uid
        or selected_node_uid == node_uid
    ):
        try:
            TacticalTabSlots.rebuild_tactical_node_sois(
                frontend,
                selected_node_uid,
            )
        except Exception as error:
            component.logger.debug(
                f"Could not rebuild Tactical SOIs after refresh: {error}"
            )

    try:
        TSITabSlots.refresh_sa_sois_table(
            frontend
        )
    except Exception as error:
        component.logger.debug(
            "Could not refresh Signal Analysis SOIs "
            f"after authoritative SOI refresh: {error}"
        )
    
    try:
        TSITabSlots.refresh_sa_capture_soi_context(
            frontend
        )
    except Exception as error:
        component.logger.debug(
            f"Could not refresh Capture SOI context after SOI refresh: {error}"
        )
    
    try:
        TSITabSlots.refresh_tsi_conditioner_soi_context(frontend)
    except Exception as error:
        component.logger.debug(f"Could not refresh Conditioner SOI context after SOI refresh: {error}")

    try:
        TSITabSlots.refresh_sa_inspection_soi_context(frontend)
    except Exception as error:
        component.logger.debug(
            f"Could not refresh Inspection SOI context after SOI refresh: {error}"
        )

    try:
        from fissure.Dashboard.Slots.TSITabSlots import pd_demodulation
        pd_demodulation.refresh_sa_pd_demodulation_soi_context(frontend)
    except Exception as error:
        component.logger.debug(
            f"Could not refresh Demodulation SOI context: {error}"
        )

    try:
        TSITabSlots.refresh_tsi_conditioner_soi_context(
            frontend
        )
    except Exception as error:
        component.logger.debug(
            f"Could not refresh Conditioner SOI context after SOI refresh: {error}"
        )

    try:
        TSITabSlots.refresh_tsi_fe_input_sois(
            frontend
        )
    except Exception as error:
        component.logger.debug(
            "Could not refresh Feature Extractor SOI selector "
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


def classifierLibraryMatchReturn(
    component: object,
    request_id: str = "",
    frequency_mhz=None,
    matches: list = None,
    error: str = "",
):
    """Route hub-side Classifier library-match results to Signal Analysis."""
    try:
        TSITabSlots.handle_sa_classifier_library_match_results(
            component.frontend,
            request_id=request_id,
            frequency_mhz=frequency_mhz,
            matches=matches or [],
            error=error,
        )
    except Exception as exc:
        component.logger.debug(f"Could not route Classifier library match results: {exc}")


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
    
    if context.startswith("sa.survey"):
        TSITabSlots.handle_sa_survey_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return

    if context.startswith("sa.capture"):
        TSITabSlots.handle_sa_capture_action_query_results(
            frontend,
            node_uid=node_uid,
            context=context,
            actions=actions,
        )
        return
    
    if context.startswith("sa.inspection"):
        TSITabSlots.handle_sa_inspection_action_query_results(
            frontend,
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
    
    if context.startswith("sa.classifier.model"):
        TSITabSlots.handle_sa_classifier_action_query_results(
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
    
    if context.startswith("sa.survey"):
        TSITabSlots.handle_sa_survey_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return

    if context.startswith("sa.capture"):
        TSITabSlots.handle_sa_capture_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
        )
        return
    
    if context.startswith("sa.inspection"):
        TSITabSlots.handle_sa_inspection_action_schema(
            frontend,
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

    if context.startswith("sa.classifier.model"):
        TSITabSlots.handle_sa_classifier_action_schema(
            frontend,
            plugin_name=plugin_name,
            action_name=action_name,
            node_uid=node_uid,
            parameters=schema.get("params", []),
            schema=schema,
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

    try:
        TSITabSlots.refresh_sa_sois_selected_details(
            frontend
        )
    except Exception as error:
        component.logger.debug(
            "Could not refresh selected Signal Analysis SOI details "
            f"after SOI update: {error}"
        )

    if not getattr(frontend, "sa_sois_bulk_refreshing", False):
        try:
            TSITabSlots.refresh_sa_sois_table(frontend)
        except Exception as error:
            component.logger.debug(
                f"Could not refresh Signal Analysis SOIs: {error}"
            )    

        try:
            TSITabSlots.refresh_sa_capture_soi_context(frontend)
        except Exception as error:
            component.logger.debug(
                f"Could not refresh Capture SOI context: {error}"
            )

        try:
            TSITabSlots.refresh_tsi_conditioner_soi_context(frontend)
        except Exception as error:
            component.logger.debug(f"Could not refresh Conditioner SOI context: {error}")

        try:
            TSITabSlots.refresh_tsi_conditioner_soi_context(frontend)
        except Exception as error:
            component.logger.debug(f"Could not refresh Conditioner SOI context: {error}")

        try:
            TSITabSlots.refresh_sa_classifier_context(frontend)
        except Exception as error:
            component.logger.debug(f"Could not refresh Classifier SOI context: {error}")


async def soiDeleted(
    component: object,
    soi_key: str = "",
    node_uid: str = "",
    soi_id: str = "",
    success: bool = False,
):
    """Remove a hub-deleted SOI from Dashboard caches and views."""
    if not success:
        component.logger.warning(
            "HIPRFISR could not delete SOI "
            f"soi_key={soi_key}, soi_id={soi_id}"
        )
        return

    frontend = component.frontend
    soi_key = str(soi_key or "").strip()
    node_uid = str(node_uid or "").strip()
    soi_id = str(soi_id or "").strip()

    if not soi_key and soi_id:
        for candidate_key, record in list(
            getattr(frontend, "tactical_sois", {}).items()
        ):
            if not isinstance(record, dict):
                continue

            if str(record.get("soi_id", "") or "").strip() != soi_id:
                continue

            candidate_node_uid = str(
                record.get("node_uid", "")
                or ""
            ).strip()

            if node_uid and candidate_node_uid != node_uid:
                continue

            soi_key = candidate_key
            break

    removed = None
    if soi_key:
        removed = getattr(frontend, "tactical_sois", {}).pop(
            soi_key,
            None,
        )

        try:
            frontend.tactical_map.remove_soi(soi_key)
        except Exception:
            pass

        if getattr(
            frontend,
            "selected_tactical_node_soi_id",
            None,
        ) == soi_key:
            frontend.selected_tactical_node_soi_id = None

    removed_node_uid = str(
        (removed or {}).get("node_uid", "")
        or node_uid
        or ""
    ).strip()

    selected_node_uid = str(
        getattr(frontend, "selected_tactical_node_uid", "")
        or ""
    ).strip()

    if selected_node_uid and selected_node_uid == removed_node_uid:
        try:
            TacticalTabSlots.rebuild_tactical_node_sois(
                frontend,
                selected_node_uid,
            )
        except Exception as error:
            component.logger.debug(
                f"Could not rebuild Tactical SOIs after delete: {error}"
            )

    try:
        TSITabSlots.refresh_sa_sois_table(frontend)
    except Exception as error:
        component.logger.debug(
            f"Could not refresh Signal Analysis SOIs after delete: {error}"
        )

    try:
        TSITabSlots.refresh_tsi_conditioner_soi_context(frontend)
    except Exception as error:
        component.logger.debug(f"Could not refresh Conditioner SOIs after delete: {error}")

    try:
        TSITabSlots.refresh_tsi_fe_input_sois(frontend)
    except Exception as error:
        component.logger.debug(
            f"Could not refresh Feature Extractor SOIs after delete: {error}"
        )

    try:
        TSITabSlots.refresh_tsi_conditioner_soi_context(frontend)
    except Exception as error:
        component.logger.debug(
            f"Could not refresh Conditioner SOIs after delete: {error}"
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


async def refreshScapyInterfacesResults(
    component: object,
    node_uid="",
    interfaces=None,
):
    """Populate Scapy interfaces returned by the selected Sensor Node."""
    ScapyTabSlots.handle_scapy_interface_results(
        component.frontend,
        node_uid=str(node_uid or ""),
        interfaces=interfaces or [],
    )


async def scapyTransmissionStatus(
    component: object,
    node_uid="",
    operation_id="",
    state="",
    message="",
    packets_sent=0,
    set_rate="",
    started="",
):
    """Update the Scapy tab from Sensor Node transmission state."""
    ScapyTabSlots.handle_scapy_transmission_status(
        component.frontend,
        node_uid=str(node_uid or ""),
        operation_id=str(operation_id or ""),
        state=str(state or ""),
        message=str(message or ""),
        packets_sent=int(packets_sent or 0),
        set_rate=str(set_rate or ""),
        started=str(started or ""),
    )