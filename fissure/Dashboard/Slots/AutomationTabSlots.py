from PyQt5 import QtCore, QtWidgets
import fissure.utils


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationDiscoveryClicked(dashboard: QtCore.QObject):
    """ 
    Changes the automation mode of the system to Discovery.
    """
    pass
    # # Change the Button Colors
    # dashboard.ui.pushButton_automation_manual.setStyleSheet("")
    # dashboard.ui.pushButton_automation_target.setStyleSheet("")
    # dashboard.ui.pushButton_automation_custom.setStyleSheet("")
    # dashboard.ui.pushButton_automation_discovery.setStyleSheet("border: 1px solid darkGray; border-radius: 6px; background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,stop: 0 #ffb477, stop: 1 #db8d4e); min-width: 80px;")

    # # Automation Settings
    # dashboard.ui.label2_automation_automation_mode_description.setText("Mostly automated. System chooses which signals to target and process.")

    # dashboard.ui.checkBox_automation_auto_start_tsi.setChecked(True)
    # dashboard.ui.checkBox_automation_auto_start_tsi.setEnabled(False)

    # dashboard.ui.checkBox_automation_auto_select_sois.setChecked(True)
    # dashboard.ui.checkBox_automation_auto_select_sois.setEnabled(False)
    # _slotAutomationAutoSelectSOIsClicked(dashboard)

    # dashboard.ui.tableWidget_automation_soi_list_priority.setEnabled(True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setVisible(True)

    # dashboard.ui.label2_soi_list_priority.setEnabled(True)
    # dashboard.ui.label2_soi_list_priority.setVisible(True)

    # dashboard.ui.checkBox_automation_auto_start_pd.setChecked(True)
    # dashboard.ui.checkBox_automation_auto_start_pd.setEnabled(False)
    # _slotAutomationAutoStartPD_Clicked(dashboard)

    # dashboard.ui.checkBox_automation_auto_select_pd_flow_graphs.setChecked(True)
    # dashboard.ui.checkBox_automation_auto_select_pd_flow_graphs.setEnabled(False)
    # _slotAutomationAutoSelectPD_FlowGraphsClicked(dashboard)

    # # Targeting Settings
    # dashboard.ui.label2_automation_target_protcol.setEnabled(False)
    # dashboard.ui.comboBox_automation_target_protocol.setEnabled(False)
    # dashboard.ui.comboBox_automation_target_protocol.setCurrentIndex(0)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setColumnHidden(2,True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setRowHidden(1,True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setRowHidden(2,True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.resizeColumnsToContents()
    # dashboard.ui.tableWidget_automation_soi_list_priority.resizeRowsToContents()
    # dashboard.ui.tableWidget_automation_soi_list_priority.horizontalHeader().setStretchLastSection(False)
    # dashboard.ui.tableWidget_automation_soi_list_priority.horizontalHeader().setStretchLastSection(True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,0).setCurrentIndex(0)
    # dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,1).setCurrentIndex(0)
    # dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,0).setEnabled(False)
    # dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,1).setEnabled(False)
    # dashboard.ui.pushButton_automation_soi_priority_add_level.setEnabled(False)
    # dashboard.ui.pushButton_automation_soi_priority_remove_level.setEnabled(False)
    # dashboard.ui.label2_soi_priority_row2.setVisible(False)
    # dashboard.ui.label2_soi_priority_row3.setVisible(False)

    # # System Status
    # if dashboard.active_sensor_node > -1:
    #     dashboard.statusbar_text[dashboard.active_sensor_node][0] = "Discovery"
    #     dashboard.refreshStatusBarText()

    # # Control Over Flow Graph Tab
    # dashboard.ui.frame_flow_graph.setEnabled(False)

    # # Save Automation Mode
    # dashboard.backend.settings['startup_automation_mode'] = "Discovery"


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationTargetClicked(dashboard: QtCore.QObject):
    """ 
    Changes the automation mode of the system to Target.
    """
    pass
    # # Change the Button Colors
    # dashboard.ui.pushButton_automation_manual.setStyleSheet("")
    # dashboard.ui.pushButton_automation_discovery.setStyleSheet("")
    # dashboard.ui.pushButton_automation_custom.setStyleSheet("")
    # dashboard.ui.pushButton_automation_target.setStyleSheet("border: 1px solid darkGray; border-radius: 6px; background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,stop: 0 #ffb477, stop: 1 #db8d4e); min-width: 80px;")

    # # Automation Settings
    # dashboard.ui.label2_automation_automation_mode_description.setText("User-defined specifications. Only pursue targets fitting certain criteria.")

    # dashboard.ui.checkBox_automation_auto_start_tsi.setChecked(True)
    # dashboard.ui.checkBox_automation_auto_start_tsi.setEnabled(False)

    # dashboard.ui.checkBox_automation_auto_select_sois.setChecked(True)
    # dashboard.ui.checkBox_automation_auto_select_sois.setEnabled(False)
    # _slotAutomationAutoSelectSOIsClicked(dashboard)

    # dashboard.ui.tableWidget_automation_soi_list_priority.setEnabled(True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setVisible(True)

    # dashboard.ui.label2_soi_list_priority.setEnabled(True)
    # dashboard.ui.label2_soi_list_priority.setVisible(True)

    # dashboard.ui.checkBox_automation_auto_select_pd_flow_graphs.setChecked(True)
    # dashboard.ui.checkBox_automation_auto_select_pd_flow_graphs.setEnabled(False)
    # _slotAutomationAutoSelectPD_FlowGraphsClicked(dashboard)

    # dashboard.ui.checkBox_automation_auto_start_pd.setChecked(True)
    # dashboard.ui.checkBox_automation_auto_start_pd.setEnabled(False)
    # _slotAutomationAutoStartPD_Clicked(dashboard)

    # # Targeting Settings
    # dashboard.ui.label2_automation_target_protcol.setEnabled(True)
    # dashboard.ui.comboBox_automation_target_protocol.setEnabled(True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setColumnHidden(2,False)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setRowHidden(1,False)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setRowHidden(2,False)
    # dashboard.ui.tableWidget_automation_soi_list_priority.resizeColumnsToContents()
    # dashboard.ui.tableWidget_automation_soi_list_priority.resizeRowsToContents()
    # dashboard.ui.tableWidget_automation_soi_list_priority.horizontalHeader().setStretchLastSection(False)
    # dashboard.ui.tableWidget_automation_soi_list_priority.horizontalHeader().setStretchLastSection(True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(dashboard.ui.tableWidget_automation_soi_list_priority.rowCount()-1,0).setEnabled(True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,1).setEnabled(True)
    # dashboard.ui.pushButton_automation_soi_priority_add_level.setEnabled(True)
    # dashboard.ui.pushButton_automation_soi_priority_remove_level.setEnabled(True)

    # # System Status
    # if dashboard.active_sensor_node > -1:
    #     dashboard.statusbar_text[dashboard.active_sensor_node][0] = "Target"
    #     dashboard.refreshStatusBarText()

    # # Control Over Flow Graph Tab
    # dashboard.ui.frame_flow_graph.setEnabled(False)

    # # Save Automation Mode
    # dashboard.backend.settings['startup_automation_mode'] = "Target"


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationManualClicked(dashboard: QtCore.QObject):
    """ 
    Changes the automation mode of the system to Manual.
    """
    # Change the Button Colors
    dashboard.ui.pushButton_automation_discovery.setStyleSheet("")
    dashboard.ui.pushButton_automation_target.setStyleSheet("")
    dashboard.ui.pushButton_automation_custom.setStyleSheet("")
    dashboard.ui.pushButton_automation_manual.setStyleSheet("border: 1px solid darkGray; border-radius: 6px; background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,stop: 0 #ffb477, stop: 1 #db8d4e); min-width: 80px;")

    # Automation Settings
    dashboard.ui.label2_automation_automation_mode_description.setText("User confirms all phases and can edit parameters.")

    dashboard.ui.checkBox_automation_auto_start_tsi.setChecked(False)
    dashboard.ui.checkBox_automation_auto_start_tsi.setEnabled(False)

    dashboard.ui.checkBox_automation_auto_select_sois.setChecked(False)
    dashboard.ui.checkBox_automation_auto_select_sois.setEnabled(False)
    _slotAutomationAutoSelectSOIsClicked(dashboard)

    dashboard.ui.checkBox_automation_auto_select_pd_flow_graphs.setChecked(False)
    dashboard.ui.checkBox_automation_auto_select_pd_flow_graphs.setEnabled(False)
    _slotAutomationAutoSelectPD_FlowGraphsClicked(dashboard)

    dashboard.ui.checkBox_automation_auto_start_pd.setChecked(False)
    dashboard.ui.checkBox_automation_auto_start_pd.setEnabled(False)
    _slotAutomationAutoStartPD_Clicked(dashboard)

    # Targeting Settings
    dashboard.ui.label2_automation_target_protcol.setEnabled(True)
    dashboard.ui.comboBox_automation_target_protocol.setEnabled(True)

    # System Status
    if dashboard.active_sensor_node > -1:
        dashboard.statusbar_text[dashboard.active_sensor_node][0] = "Manual"
        dashboard.refreshStatusBarText()

    # Control Over Flow Graph Tab
    dashboard.ui.frame_flow_graph.setEnabled(True)

    # Save Automation Mode
    dashboard.backend.settings['startup_automation_mode'] = "Manual"


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationCustomClicked(dashboard: QtCore.QObject):
    """ 
    Changes the automation mode of the system to Custom.
    """
    pass
    # # Change the Button Colors
    # dashboard.ui.pushButton_automation_manual.setStyleSheet("")
    # dashboard.ui.pushButton_automation_discovery.setStyleSheet("")
    # dashboard.ui.pushButton_automation_target.setStyleSheet("")
    # dashboard.ui.pushButton_automation_custom.setStyleSheet("border: 1px solid darkGray; border-radius: 6px; background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,stop: 0 #ffb477, stop: 1 #db8d4e); min-width: 80px;")

    # # Automation Settings
    # dashboard.ui.label2_automation_automation_mode_description.setText("User creates any combination of settings.")

    # dashboard.ui.checkBox_automation_auto_start_tsi.setEnabled(True)

    # dashboard.ui.checkBox_automation_auto_select_sois.setEnabled(True)
    # _slotAutomationAutoSelectSOIsClicked(dashboard)

    # dashboard.ui.checkBox_automation_auto_select_pd_flow_graphs.setEnabled(True)
    # _slotAutomationAutoSelectPD_FlowGraphsClicked(dashboard)

    # dashboard.ui.checkBox_automation_auto_start_pd.setEnabled(True)
    # _slotAutomationAutoStartPD_Clicked(dashboard)

    # # Targeting Settings
    # dashboard.ui.label2_automation_target_protcol.setEnabled(True)
    # dashboard.ui.comboBox_automation_target_protocol.setEnabled(True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setColumnHidden(2,False)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setRowHidden(1,False)
    # dashboard.ui.tableWidget_automation_soi_list_priority.setRowHidden(2,False)
    # dashboard.ui.tableWidget_automation_soi_list_priority.resizeColumnsToContents()
    # dashboard.ui.tableWidget_automation_soi_list_priority.resizeRowsToContents()
    # dashboard.ui.tableWidget_automation_soi_list_priority.horizontalHeader().setStretchLastSection(False)
    # dashboard.ui.tableWidget_automation_soi_list_priority.horizontalHeader().setStretchLastSection(True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(dashboard.ui.tableWidget_automation_soi_list_priority.rowCount()-1,0).setEnabled(True)
    # dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,1).setEnabled(True)
    # dashboard.ui.pushButton_automation_soi_priority_add_level.setEnabled(True)
    # dashboard.ui.pushButton_automation_soi_priority_remove_level.setEnabled(True)

    # # System Status
    # if dashboard.active_sensor_node > -1:
    #     dashboard.statusbar_text[dashboard.active_sensor_node][0] = "Custom"
    #     dashboard.refreshStatusBarText()

    # # Control Over Flow Graph Tab
    # dashboard.ui.frame_flow_graph.setEnabled(True)

    # # Save Automation Mode
    # dashboard.backend.settings['startup_automation_mode'] = "Custom"


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSOI_PriorityCategoryChanged(dashboard: QtCore.QObject):
    """ 
    Changes the filter combobox options when the the category combobox is changed.
    """
    pass
    # # Change the Combobox
    # last_row = dashboard.ui.tableWidget_automation_soi_list_priority.rowCount()-1
    # new_combobox = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
    # dashboard.ui.tableWidget_automation_soi_list_priority.setCellWidget(last_row,1,new_combobox)

    # if dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(last_row,0).currentText() == "Power":
    #     new_combobox.addItem("Highest")
    #     new_combobox.addItem("Lowest")
    #     new_combobox.addItem("Nearest to")
    #     new_combobox.addItem("Greater than")
    #     new_combobox.addItem("Less than")
    # elif dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(last_row,0).currentText() == "Frequency":
    #     new_combobox.addItem("Highest")
    #     new_combobox.addItem("Lowest")
    #     new_combobox.addItem("Nearest to")
    #     new_combobox.addItem("Greater than")
    #     new_combobox.addItem("Less than")
    # elif dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(last_row,0).currentText() == "Modulation":
    #     new_combobox.addItem("Containing")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationReceiveOnlyClicked(dashboard: QtCore.QObject):
    """ 
    Adjusts the Dashboard and HIPRFISR settings to enable/disable transmission capabilities
    """
    pass
    # # Receive-Only (Checked)
    # if dashboard.ui.checkBox_automation_receive_only.isChecked():
    #     dashboard.ui.tabWidget.setTabEnabled(3,False)

    #     # Stop the Running Attack;
    #     if dashboard.ui.pushButton_attack_start_stop.text() == "Stop Attack":
    #         fissure.Dashboard.Slots.AttackTabSlots._slotAttackStartStopAttack(dashboard)

    # # Normal Operation (Unchecked)
    # else:
    #     if dashboard.ui.pushButton_automation_system_start.text() == "Stop":
    #         dashboard.ui.tabWidget.setTabEnabled(3,True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationAutoSelectSOIsClicked(dashboard: QtCore.QObject):
    """ 
    Enables/Disables the auto-selection of SOIs from the list.
    """
    pass
    # # Checked
    # if dashboard.ui.checkBox_automation_auto_select_sois.isChecked():
    #     dashboard.backend.settings['process_SOIs'] = 'True'
    #     dashboard.ui.label2_soi_list_priority.setVisible(True)
    #     dashboard.ui.tableWidget_automation_soi_list_priority.setVisible(True)
    #     dashboard.ui.label2_soi_priority_row1.setVisible(True)
    #     if dashboard.ui.tableWidget_automation_soi_list_priority.rowCount() > 1:
    #         dashboard.ui.label2_soi_priority_row2.setVisible(True)
    #     if dashboard.ui.tableWidget_automation_soi_list_priority.rowCount() > 2:
    #         dashboard.ui.label2_soi_priority_row3.setVisible(True)
    #     dashboard.ui.pushButton_automation_soi_priority_add_level.setVisible(True)
    #     dashboard.ui.pushButton_automation_soi_priority_remove_level.setVisible(True)
    #     dashboard.ui.pushButton_pd_flow_graphs_auto_select.setVisible(True)

    #     # Send Messages to the HIPRFISR if the System is Running
    #     if dashboard.ui.pushButton_automation_system_start.text() == "Stop":
    #         PARAMETERS = {"enabled": False, "priorities": None, "filters": None, "parameters": None}
    #         msg = {
    #             MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
    #             MessageFields.MESSAGE_NAME: "Set Process SOIs",
    #             MessageFields.PARAMETERS: PARAMETERS,
    #         }
    #         self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)
    #         dashboard.backend.settings['SOI_trigger_mode'] = 2
    #         PARAMETERS = {"mode": int(dashboard.backend.settings['SOI_trigger_mode'])}
    #         msg = {
    #                 MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
    #                 MessageFields.MESSAGE_NAME: "SOI Selection Mode",
    #                 MessageFields.PARAMETERS: PARAMETERS,
    #         }
    #         self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)

    # # Unchecked
    # else:
    #     dashboard.backend.settings['process_SOIs'] = 'False'
    #     dashboard.ui.label2_soi_list_priority.setVisible(False)
    #     dashboard.ui.tableWidget_automation_soi_list_priority.setVisible(False)
    #     dashboard.ui.label2_soi_priority_row1.setVisible(False)
    #     dashboard.ui.label2_soi_priority_row2.setVisible(False)
    #     dashboard.ui.label2_soi_priority_row3.setVisible(False)
    #     dashboard.ui.pushButton_automation_soi_priority_add_level.setVisible(False)
    #     dashboard.ui.pushButton_automation_soi_priority_remove_level.setVisible(False)
    #     dashboard.ui.pushButton_pd_flow_graphs_auto_select.setVisible(False)

    #     # Send Messages to the HIPRFISR if the System is Running
    #     if dashboard.ui.pushButton_automation_system_start.text() == "Stop":
    #         PARAMETERS = {"enabled": False, "priorities": None, "filters": None, "parameters": None}
    #         msg = {
    #             MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
    #             MessageFields.MESSAGE_NAME: "Set Process SOIs",
    #             MessageFields.PARAMETERS: PARAMETERS,
    #         }
    #         self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)

    #         dashboard.backend.settings['SOI_trigger_mode'] = 0
    #         PARAMETERS = {"mode": int(dashboard.backend.settings['SOI_trigger_mode'])}
    #         msg = {
    #                 MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
    #                 MessageFields.MESSAGE_NAME: "SOI Selection Mode",
    #                 MessageFields.PARAMETERS: PARAMETERS,
    #         }
    #         self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationLockSearchBandClicked(dashboard: QtCore.QObject):
    """ 
    Enabling this checkbox will allow only one search band to be activated while the system is running.
    """
    pass
    # # Checked
    # if dashboard.ui.checkBox_automation_lock_search_band.isChecked() == True:
    #     dashboard.ui.tableWidget_automation_scan_options.setVisible(True)

    #     # Disable TSI Tab Controls
    #     dashboard.ui.pushButton_tsi_add_band.setEnabled(False)
    #     dashboard.ui.tableWidget_tsi_scan_options.setEnabled(False)
    #     dashboard.ui.spinBox_tsi_sdr_start.setEnabled(False)
    #     dashboard.ui.spinBox_tsi_sdr_end.setEnabled(False)
    #     dashboard.ui.spinBox_tsi_sdr_step.setEnabled(False)
    #     dashboard.ui.doubleSpinBox_tsi_sdr_dwell.setEnabled(False)
    #     dashboard.ui.listWidget_tsi_scan_presets.setEnabled(False)
    #     dashboard.ui.pushButton_tsi_save_preset.setEnabled(False)
    #     dashboard.ui.pushButton_tsi_delete_preset.setEnabled(False)
    #     dashboard.tuning_widget.setEnabled(False)

    #     for txt in dashboard.tuning_widget.axes.texts:
    #         if txt.get_position() == (1,500):
    #             txt.remove()
    #     dashboard.tuning_widget.axes.text(1,500,"LOCKED",fontsize=12,bbox=dict(facecolor='red', alpha=0.5))
    #     dashboard.tuning_widget.draw()

    #     # Delete Any Existing Bands
    #     for x in range(1,10):
    #         fissure.Dashboard.Slots.TSITabSlots._slotTSI_RemoveBandClicked(dashboard)

    #     # Add Band from Automation Tab
    #     dashboard.ui.spinBox_tsi_sdr_start.setValue(int(dashboard.ui.tableWidget_automation_scan_options.item(0,0).text()))
    #     dashboard.ui.spinBox_tsi_sdr_end.setValue(int(dashboard.ui.tableWidget_automation_scan_options.item(0,1).text()))
    #     dashboard.ui.spinBox_tsi_sdr_step.setValue(int(dashboard.ui.tableWidget_automation_scan_options.item(0,2).text()))
    #     dashboard.ui.doubleSpinBox_tsi_sdr_dwell.setValue(int(dashboard.ui.tableWidget_automation_scan_options.item(0,3).text()))
    #     fissure.Dashboard.Slots.TSITabSlots._slotTSI_AddBandClicked(dashboard)
    #     dashboard.ui.pushButton_tsi_remove_band.setEnabled(False)

    # # Unchecked
    # elif dashboard.ui.checkBox_automation_lock_search_band.isChecked() == False:
    #     dashboard.ui.tableWidget_automation_scan_options.setVisible(False)

    #     # Enable TSI Tab Controls
    #     dashboard.ui.pushButton_tsi_add_band.setEnabled(True)
    #     dashboard.ui.tableWidget_tsi_scan_options.setEnabled(True)
    #     dashboard.ui.spinBox_tsi_sdr_start.setEnabled(True)
    #     dashboard.ui.spinBox_tsi_sdr_end.setEnabled(True)
    #     dashboard.ui.spinBox_tsi_sdr_step.setEnabled(True)
    #     dashboard.ui.doubleSpinBox_tsi_sdr_dwell.setEnabled(True)
    #     dashboard.ui.listWidget_tsi_scan_presets.setEnabled(True)
    #     dashboard.ui.pushButton_tsi_save_preset.setEnabled(True)
    #     dashboard.ui.pushButton_tsi_delete_preset.setEnabled(True)
    #     dashboard.tuning_widget.setEnabled(True)

    #     for txt in dashboard.tuning_widget.axes.texts:
    #         if txt.get_position() == (1,500):
    #             txt.remove()
    #     dashboard.tuning_widget.draw()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationAutoStartPD_Clicked(dashboard: QtCore.QObject):
    """ 
    This is called when the "Auto-Start PD" checkbox is clicked.
    """
    pass
    # # Checked
    # if dashboard.ui.checkBox_automation_auto_start_pd.isChecked() == True:
    #     dashboard.ui.label2_pd_status_auto_start_pd.setText("Yes")
    #     #~ dashboard.ui.pushButton_pd_status_start.setVisible(False)

    #     # System is On
    #     if dashboard.ui.pushButton_automation_system_start.text() == "Stop":
    #         # Start PD if Flow Graph is Already Loaded and PD is not Running
    #         if (dashboard.ui.label2_pd_status_flow_graph_status.text() != "") and (dashboard.ui.pushButton_pd_status_start.text() == "Start"):
    #             fissure.Dashboard.Slots.PDTabSlots._slotPD_StatusStartClicked(dashboard)

    # # Unchecked
    # elif dashboard.ui.checkBox_automation_auto_start_pd.isChecked() == False:
    #     dashboard.ui.label2_pd_status_auto_start_pd.setText("No")
    #     #~ dashboard.ui.pushButton_pd_status_start.setVisible(True)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationAutoSelectPD_FlowGraphsClicked(dashboard: QtCore.QObject):
    """ 
    This is called when the "Auto-Load PD Flow Graphs" checkbox is clicked.
    """
    pass
    # # Checked
    # if dashboard.ui.checkBox_automation_auto_select_pd_flow_graphs.isChecked() == True:
    #     dashboard.ui.label2_pd_status_auto_select_pd_flow_graphs.setText("Yes")

    # # Unchecked
    # elif dashboard.ui.checkBox_automation_auto_select_pd_flow_graphs.isChecked() == False:
    #     dashboard.ui.label2_pd_status_auto_select_pd_flow_graphs.setText("No")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationSOI_PriorityAddLevelClicked(dashboard: QtCore.QObject):
    """ 
    Adds a new row to the "SOI Priority" table.
    """
    pass
    # # Current Number of Rows
    # get_rows = dashboard.ui.tableWidget_automation_soi_list_priority.rowCount()

    # # Maximum of Three Rows
    # if get_rows < 3:

    #     # Add the Row
    #     dashboard.ui.tableWidget_automation_soi_list_priority.setRowCount(get_rows+1)

    #     # Create the ComboBoxes and Empty Item
    #     new_combobox = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
    #     dashboard.ui.tableWidget_automation_soi_list_priority.setCellWidget(get_rows,0,new_combobox)
    #     new_combobox2 = QtWidgets.QComboBox(dashboard, objectName='comboBox2_')
    #     dashboard.ui.tableWidget_automation_soi_list_priority.setCellWidget(get_rows,1,new_combobox2)
    #     empty_item1 = QtWidgets.QTableWidgetItem("")
    #     dashboard.ui.tableWidget_automation_soi_list_priority.setItem(get_rows,2,empty_item1)

    #     # Row 1 Exists
    #     if get_rows == 1:
    #         # Show the Label
    #         dashboard.ui.label2_soi_priority_row2.setVisible(True)

    #         # Text for New Row
    #         if dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,0).currentText() == "Power":
    #             new_combobox.addItem("Frequency")
    #             new_combobox.addItem("Modulation")
    #             new_combobox2.addItem("Highest")
    #             new_combobox2.addItem("Lowest")
    #             new_combobox2.addItem("Nearest to")
    #             new_combobox2.addItem("Greater than")
    #             new_combobox2.addItem("Less than")

    #         elif dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,0).currentText() == "Frequency":
    #             new_combobox.addItem("Power")
    #             new_combobox.addItem("Modulation")
    #             new_combobox2.addItem("Highest")
    #             new_combobox2.addItem("Lowest")
    #             new_combobox2.addItem("Nearest to")
    #             new_combobox2.addItem("Greater than")
    #             new_combobox2.addItem("Less than")
    #         elif dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,0).currentText() == "Modulation":
    #             new_combobox.addItem("Power")
    #             new_combobox.addItem("Frequency")
    #             new_combobox2.addItem("Highest")
    #             new_combobox2.addItem("Lowest")
    #             new_combobox2.addItem("Nearest to")
    #             new_combobox2.addItem("Greater than")
    #             new_combobox2.addItem("Less than")

    #     # Row 2 Exists
    #     elif get_rows == 2:
    #         # Show the Label
    #         dashboard.ui.label2_soi_priority_row3.setVisible(True)

    #         # Disable the Add Level Button
    #         dashboard.ui.pushButton_automation_soi_priority_add_level.setEnabled(False)

    #         # Enable the Remove Button
    #         dashboard.ui.pushButton_automation_soi_priority_remove_level.setEnabled(True)

    #         # Text for New Row
    #         if dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,0).currentText() != "Power" and dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(1,0).currentText() != "Power":
    #             new_combobox.addItem("Power")
    #             new_combobox2.addItem("Highest")
    #             new_combobox2.addItem("Lowest")
    #             new_combobox2.addItem("Nearest to")
    #             new_combobox2.addItem("Greater than")
    #             new_combobox2.addItem("Less than")
    #         elif dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,0).currentText() != "Frequency" and dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(1,0).currentText() != "Frequency":
    #             new_combobox.addItem("Frequency")
    #             new_combobox2.addItem("Highest")
    #             new_combobox2.addItem("Lowest")
    #             new_combobox2.addItem("Nearest to")
    #             new_combobox2.addItem("Greater than")
    #             new_combobox2.addItem("Less than")
    #         elif dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(0,0).currentText() != "Modulation" and dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(1,0).currentText() != "Modulation":
    #             new_combobox.addItem("Modulation")
    #             new_combobox2.addItem("Containing")

    #     # Adjust the Table
    #     dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(get_rows-1,0).setEnabled(False)
    #     new_combobox.currentIndexChanged.connect(lambda: _slotSOI_PriorityCategoryChanged(dashboard))
    #     dashboard.ui.tableWidget_automation_soi_list_priority.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationSOI_PriorityRemoveLevelClicked(dashboard: QtCore.QObject):
    """ 
    Removes a row from the "SOI Priority" table.
    """
    pass
    # # Current Number of Rows
    # get_rows = dashboard.ui.tableWidget_automation_soi_list_priority.rowCount()

    # # Minimum of One Row
    # if get_rows > 1:
    #     # Hide the Labels, Enable/Disable the Buttons
    #     if get_rows == 2:
    #         dashboard.ui.label2_soi_priority_row2.setVisible(False)
    #         dashboard.ui.pushButton_automation_soi_priority_remove_level.setEnabled(False)
    #     elif get_rows == 3:
    #         dashboard.ui.label2_soi_priority_row3.setVisible(False)
    #         dashboard.ui.pushButton_automation_soi_priority_add_level.setEnabled(True)

    #     # Remove the Row
    #     dashboard.ui.tableWidget_automation_soi_list_priority.setRowCount(get_rows-1)

    #     # Adjust the Table
    #     dashboard.ui.tableWidget_automation_soi_list_priority.cellWidget(get_rows-2,0).setEnabled(True)
    #     dashboard.ui.tableWidget_automation_soi_list_priority.resizeRowsToContents()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotAutomationSystemResetClicked(dashboard: QtCore.QObject):
    """ 
    This will reset all the tables and data collected thus far back to startup conditions.
    """
    pass
    # # Automation
    # if dashboard.active_sensor_node > -1:
    #     dashboard.statusbar_text[dashboard.active_sensor_node][3] = "Flow Graph Not Loaded"
    #     dashboard.refreshStatusBarText()
    # #~ dashboard.ui.label_current_flow_graph.setText("Flow Graph Not Loaded")
    # #~ dashboard.ui.label_status_attack.setText("Flow Graph Not Loaded")

    # # TSI
    # fissure.Dashboard.Slots.TSITabSlots._slotTSI_ClearWidebandListClicked(dashboard)

    # # Protocol Discovery - Tab 1
    # fissure.Dashboard.Slots.PDTabSlots._slotPD_DemodulationLookupClearClicked(dashboard)
    # dashboard.ui.listWidget_pd_flow_graphs_recommended_fgs.clear()
    # dashboard.ui.textEdit2_pd_status.clear()
    # dashboard.ui.pushButton_pd_status_start.setEnabled(False)
    # dashboard.ui.label2_pd_status_loaded_flow_graph.setText("")
    # dashboard.ui.label2_pd_status_flow_graph_status.setText("")

    # # Protocol Discovery - Flow Graph
    # dashboard.ui.textEdit_pd_flow_graphs_filepath.setPlainText("")
    # dashboard.ui.label2_pd_flow_graphs_status.setText("Not Loaded")
    # dashboard.ui.label3_pd_flow_graphs_description.setText("")
    # dashboard.ui.label3_pd_flow_graphs_default_variables.setText("")
    # dashboard.ui.tableWidget_pd_flow_graphs_current_values.setRowCount(0)
    # dashboard.ui.pushButton_pd_flow_graphs_start_stop.setEnabled(False)
    # dashboard.ui.pushButton_pd_flow_graphs_apply_changes.setEnabled(False)
    # dashboard.ui.pushButton_pd_flow_graphs_restore_defaults.setEnabled(False)
    # dashboard.ui.pushButton_pd_flow_graphs_view.setEnabled(False)

    # # Attack
    # dashboard.ui.pushButton_attack_start_stop.setEnabled(False)
    # dashboard.ui.label2_attack_flow_graph_status.setText("Not Loaded")
    # dashboard.ui.pushButton_attack_apply_changes.setEnabled(False)
    # dashboard.ui.pushButton_attack_restore_defaults.setEnabled(False)
    # dashboard.ui.pushButton_attack_view_flow_graph.setEnabled(False)
    # dashboard.ui.pushButton_attack_single_stage_autorun.setEnabled(False)
    # dashboard.ui.tableWidget1_attack_flow_graph_current_values.setRowCount(0)
    # dashboard.ui.tableWidget1_attack_attack_history.setRowCount(0)
    # dashboard.ui.label2_selected_protocol.setText("")
    # dashboard.ui.label2_attack_fuzzing_selected_protocol.setText("")
    # dashboard.ui.label1_selected_attack.setText("")
    # dashboard.ui.label2_attack_fuzzing_selected_attack.setText("")
    # dashboard.ui.label2_selected_flow_graph.setText("")
    # dashboard.ui.label2_attack_fuzzing_selected_flow_graph.setText("")
    # dashboard.ui.label2_selected_modulation.setText("")
    # dashboard.ui.label2_selected_hardware.setText("")
    # dashboard.ui.label2_attack_fuzzing_selected_modulation.setText("")
    # dashboard.ui.label2_selected_notes.setText("")
    # dashboard.ui.label2_attack_single_stage_file_type.setText("")

