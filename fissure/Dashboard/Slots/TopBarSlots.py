from ..UI_Components import HardwareSelectDialog
from PyQt5 import QtCore, QtWidgets

import time


@QtCore.pyqtSlot(QtCore.QObject, int)
def sensor_node_leftClick(dashboard: QtCore.QObject, node_idx: int):
    button: QtWidgets.QPushButton = getattr(dashboard.ui, f"pushButton_top_node{node_idx+1}")
    dashboard.logger.debug(f"[Sensor Node {node_idx+1}] Clicked")

    button.setChecked(True)
    dashboard.openPopUp("HardwareSelectDialog", HardwareSelectDialog, node_idx)
    button.setChecked(False)


@QtCore.pyqtSlot(QtCore.QObject, int)
def sensor_node_rightClick(dashboard: QtCore.QObject, node_idx: int):
    """ 
    Highlight sensor node on right-click.
    """
    # Unhighlight
    if node_idx == -1:
        dashboard.active_sensor_node = -1
        dashboard.ui.pushButton_top_node1.setStyleSheet("")
        dashboard.configureTSI_Hardware(node_idx)
        dashboard.configurePD_Hardware(node_idx)
        dashboard.configureAttackHardware(node_idx)
        dashboard.configureIQ_Hardware(node_idx)
        dashboard.configureArchiveHardware(node_idx)
        dashboard.statusBar().dialog.label1_sensor_node.setText("No Sensor Nodes Connected")
        dashboard.refreshStatusBarText()
        return
        
    # Highlight
    top_buttons = [dashboard.ui.pushButton_top_node1, dashboard.ui.pushButton_top_node2, dashboard.ui.pushButton_top_node3, dashboard.ui.pushButton_top_node4, dashboard.ui.pushButton_top_node5]
    if str(top_buttons[node_idx].text()) != "New Sensor Node":
        dashboard.active_sensor_node = node_idx
        for n in range(0,5):
            if n == node_idx:
                top_buttons[node_idx].setStyleSheet("color: rgb(0,0,0); border: 2px solid darkGray; border-radius: 10px; border-style: outset; border-color: " + dashboard.backend.settings['color3'] + "; background-color: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,stop: 0 #ffb477, stop: 1 #db8d4e); min-width: 80px;")
            else:
                top_buttons[n].setStyleSheet("")
            
        # TSI
        dashboard.configureTSI_Hardware(node_idx)
        
        # PD
        dashboard.configurePD_Hardware(node_idx)

        # Attack                
        dashboard.configureAttackHardware(node_idx)

        # IQ
        dashboard.configureIQ_Hardware(node_idx)

        # Archive
        dashboard.configureArchiveHardware(node_idx)
        
        # Change Status Bar Text
        dashboard.statusBar().dialog.label1_sensor_node.setText("Sensor Node " + str(node_idx + 1))
        dashboard.refreshStatusBarText()


@QtCore.pyqtSlot(QtCore.QObject)
def start(dashboard: QtCore.QObject):
    """ 
    Starts FISSURE in a particular mode.
    """
    # button: QtWidgets.QPushButton = dashboard.ui.pushButton_automation_system_start
    dashboard.logger.info("[Start] Clicked")
    # button.setChecked(True)
    # time.sleep(1)
    # button.setChecked(False)

    # Turn System On
    if dashboard.ui.pushButton_automation_system_start.text() == "Start":
        dashboard.ui.pushButton_automation_system_start.setText("Stop")
        dashboard.ui.pushButton_automation_system_reset.setEnabled(False)

        # Disable Targeting Group Box
        dashboard.ui.frame_automation_targeting.setEnabled(False)

        # Start TSI
        if dashboard.ui.checkBox_automation_auto_start_tsi.isChecked():
            if dashboard.ui.pushButton_tsi_detector_start.text() == "Start":
                pass
                # self._slotTSI_DetectorStartClicked()

            # Update the SDR Configuration
            #UPDATE_SDRS()

        # Set HIPRFISR Processing of SOIs
        if dashboard.ui.checkBox_automation_auto_select_sois.isChecked() == True:
            pass
            # self.autoSelectSOI()

        elif dashboard.ui.checkBox_automation_auto_select_sois.isChecked() == False:  # Will have to add or delete things for this
            pass
            # PARAMETERS = {"enabled": False, "priorities": None, "filters": None, "parameters": None}
            # msg = {
            #     MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
            #     MessageFields.MESSAGE_NAME: "Set Process SOIs",
            #     MessageFields.PARAMETERS: PARAMETERS,
            # }
            # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)

        # Enable the Tabs
        dashboard.ui.tabWidget.setEnabled(True)
        dashboard.ui.tabWidget.setTabEnabled(1,True)
        dashboard.ui.tabWidget.setTabEnabled(2,True)
        if dashboard.ui.checkBox_automation_receive_only.isChecked() == False:
            dashboard.ui.tabWidget.setTabEnabled(3,True)
        dashboard.ui.tabWidget.setTabEnabled(4,True)
        dashboard.ui.tabWidget.setTabEnabled(5,True)
        dashboard.ui.tabWidget.setTabEnabled(6,True)
        dashboard.ui.tabWidget.setTabEnabled(7,True)
        dashboard.ui.tabWidget.setTabEnabled(8,True)

        # Automation Mode
        if dashboard.backend.settings['startup_automation_mode'] == "Discovery":
            #print("START OF DISCOVERY MODE")

            # Send SOI Selection Mode to HIPRFISR
            dashboard.backend.settings['SOI_trigger_mode'] = 2
            # PARAMETERS = {"mode": int(dashboard.backend.settings['SOI_trigger_mode'])}
            # msg = {
            #         MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
            #         MessageFields.MESSAGE_NAME: "SOI Selection Mode",
            #         MessageFields.PARAMETERS: PARAMETERS,
            # }
            # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)

        # Target Mode
        elif dashboard.backend.settings['startup_automation_mode'] == "Target":
            #print("START OF TARGET MODE")

            # Send SOI Selection Mode to HIPRFISR
            dashboard.backend.settings['SOI_trigger_mode'] = 2
            # PARAMETERS = {"mode": int(dashboard.backend.settings['SOI_trigger_mode'])}
            # msg = {
            #         MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
            #         MessageFields.MESSAGE_NAME: "SOI Selection Mode",
            #         MessageFields.PARAMETERS: PARAMETERS,
            # }
            # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)

        # Manual Mode
        elif dashboard.backend.settings['startup_automation_mode'] == "Manual":
            #print("START OF MANUAL MODE")

            # Send SOI Selection Mode to HIPRFISR
            dashboard.backend.settings['SOI_trigger_mode'] = 0
            # PARAMETERS = {"mode": int(dashboard.backend.settings['SOI_trigger_mode'])}
            # msg = {
            #         MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
            #         MessageFields.MESSAGE_NAME: "SOI Selection Mode",
            #         MessageFields.PARAMETERS: PARAMETERS,
            # }
            # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)

        # Custom Mode
        elif dashboard.backend.settings['startup_automation_mode'] == "Custom":
            #print("START OF CUSTOM MODE")

            # Send SOI Selection Mode to HIPRFISR
            if dashboard.ui.checkBox_automation_auto_select_sois.isChecked():
                dashboard.backend.settings['SOI_trigger_mode'] = 2
                # PARAMETERS = {"mode": int(dashboard.backend.settings['SOI_trigger_mode'])}
                # msg = {
                #         MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
                #         MessageFields.MESSAGE_NAME: "SOI Selection Mode",
                #         MessageFields.PARAMETERS: PARAMETERS,
                # }
                # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)
            else:
                dashboard.backend.settings['SOI_trigger_mode'] = 0
                # PARAMETERS = {"mode": int(sdashboard.backend.settings['SOI_trigger_mode'])}
                # msg = {
                #         MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
                #         MessageFields.MESSAGE_NAME: "SOI Selection Mode",
                #         MessageFields.PARAMETERS: PARAMETERS,
                # }
                # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)

        # Turn on Protocol Discovery
        if dashboard.ui.checkBox_automation_auto_start_pd.isChecked():
            if dashboard.ui.pushButton_pd_status_start.text() == "Start":
                pass
                # self._slotPD_StatusStartClicked()

    # Turn System Off
    else:
        dashboard.ui.pushButton_automation_system_start.setText("Start")
        dashboard.ui.pushButton_automation_system_reset.setEnabled(True)

        # Stop Detectors
        if dashboard.ui.pushButton_tsi_detector_start.text() == "Stop":
            pass
            # self._slotTSI_DetectorStartClicked()
        if dashboard.ui.pushButton_tsi_detector_fixed_start.text() == "Stop":
            pass
            # self._slotTSI_DetectorFixedStartClicked()

        # Stop HIPRFISR Processing of SOIs
        # PARAMETERS = {"enabled": False, "priorities": None, "filters": None, "parameters": None}
        # msg = {
        #         MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
        #         MessageFields.MESSAGE_NAME: "Set Process SOIs",
        #         MessageFields.PARAMETERS: PARAMETERS,
        # }
        # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)

        # Disable the Protocol Discovery
        # msg = {
        #         MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
        #         MessageFields.MESSAGE_NAME: "Stop PD"
        # }
        # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)            
        
        # PARAMETERS = {"value": False}
        # msg = {
        #         MessageFields.IDENTIFIER: Identifiers.DASHBOARD,
        #         MessageFields.MESSAGE_NAME: "Set Auto Start PD",
        #         MessageFields.PARAMETERS: PARAMETERS,
        # }
        # self.hiprfisr_socket.send_msg(MessageTypes.COMMANDS, **msg)

        if dashboard.active_sensor_node > -1:
            dashboard.statusbar_text[dashboard.active_sensor_node][2] = "Not Running"
            dashboard.refreshStatusBarText()
        dashboard.ui.label2_pd_status_pd.setText("Not Running")
        if dashboard.ui.pushButton_pd_status_start.text() == "Stop":
            pass
            # self._slotPD_StatusStartClicked()

        # Turn Off Any Running Flow Graphs
        if dashboard.ui.pushButton_pd_flow_graphs_start_stop.text() == "Stop":
            pass
            # self._slotPD_DemodulationStartStopClicked()
        if dashboard.ui.pushButton_attack_start_stop.text() == "Stop Attack":
            pass
            # self._slotAttackStartStopAttack()
        if dashboard.ui.pushButton_attack_fuzzing_start.text() == "Stop Attack":
            pass
            # self._slotAttackFuzzingStartClicked()
        if dashboard.ui.pushButton_attack_multi_stage_start.text() == "Stop":
            pass
            # self._slotAttackMultiStageStartClicked()

        # Turn Off IQ Recording
        if dashboard.ui.pushButton_iq_record.text() == "Cancel":
            pass
            # self._slotIQ_RecordClicked()

        # Enable Targeting Group Box
        dashboard.ui.frame_automation_targeting.setEnabled(True)

        # Disable the Tabs
        dashboard.ui.tabWidget.setEnabled(False)
        dashboard.ui.tabWidget.setTabEnabled(1,False)
        dashboard.ui.tabWidget.setTabEnabled(2,False)
        dashboard.ui.tabWidget.setTabEnabled(3,False)
        dashboard.ui.tabWidget.setTabEnabled(4,False)
        dashboard.ui.tabWidget.setTabEnabled(5,False)
        dashboard.ui.tabWidget.setTabEnabled(6,False)
        dashboard.ui.tabWidget.setTabEnabled(7,False)
        dashboard.ui.tabWidget.setTabEnabled(8,False)