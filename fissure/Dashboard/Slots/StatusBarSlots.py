from PyQt5 import QtCore, QtWidgets

import fissure.comms
import qasync


@QtCore.pyqtSlot(QtCore.QObject)
def remote_connect_prompt(statusBar: QtCore.QObject):
    """
    Prompt for Remote Connections

    :param statusBar: FISSURE Dashboard StatusBar
    :type statusBar: QtCore.QObject (FissureStatusBar)
    """

    statusBar.session_label.setText("Server:")

    # Hide Buttons
    statusBar.local_button.hide()
    statusBar.remote_button.hide()

    # Show Prompt
    statusBar.addr_prompt.show()
    statusBar.ports_prompt.show()
    statusBar.connect_button.show()
    statusBar.back_button.show()


@QtCore.pyqtSlot(QtCore.QObject)
def back(dashboard: QtCore.QObject):
    """
    Go up one level from Remote click.
    """
    # Hide
    status_bar = dashboard.statusBar()
    status_bar.addr_prompt.hide()
    status_bar.ports_prompt.hide()
    status_bar.connect_button.hide()
    status_bar.back_button.hide()
    status_bar.session_active.hide()

    # Show
    status_bar.local_button.show()
    status_bar.remote_button.show()


@QtCore.pyqtSlot(QtCore.QObject)
def toggle_port_boxes(statusBar: QtCore.QObject):
    """
    Toggle whether the port text boxes are shown, based on the currently selected protocol

    :param statusBar: FISSURE Dashboard StatusBar
    :type statusBar: QtCore.QObject (FissureStatusBar)
    """
    if statusBar.protocol_select.currentText() == "tcp":
        statusBar.addr_box.setText("127.0.0.1")
        statusBar.ports_prompt.show()
    else:
        statusBar.addr_box.setText("fissure")
        statusBar.ports_prompt.hide()


@qasync.asyncSlot(QtCore.QObject)
async def startLocalSession(dashboard: QtCore.QObject):
    """
    Spin up a local HiprFisr instance and connect the Dashboard to it

    :param dashboard: FISSURE Dashboard (Frontend) instance
    :type dashboard: QtCore.QObject (Dashboard)
    """
    status_bar = dashboard.statusBar()
    connecting_button: QtWidgets.QPushButton = status_bar.connecting_button
    local_button: QtWidgets.QPushButton = status_bar.local_button
    remote_button: QtWidgets.QPushButton = status_bar.remote_button
    disconnect_button: QtWidgets.QPushButton = status_bar.disconnect_button

    connecting_button.setText("Starting HIPRFISR")
    connecting_button.show()
    local_button.hide()
    remote_button.hide()
    disconnect_button.hide()

    # Start Server Locally
    # connecting_button.setChecked(True)
    await dashboard.backend.start_local_hiprfisr()
    # connecting_button.setChecked(False)

    # Connect to the local Server
    await connect(dashboard, fissure.comms.Address({"protocol": "ipc", "address": "fissure"}))


@qasync.asyncSlot(QtCore.QObject, fissure.comms.Address)
async def connect(
    dashboard: QtCore.QObject,
    addr: fissure.comms.Address = None,
):
    """
    Connect the dashboard to a remote FISSURE HiprFisr Server

    :param dashboard: FISSURE Dashboard (Frontend) instance
    :type dashboard: QtCore.QObject (Dashboard)
    """
    status_bar = dashboard.statusBar()
    connect_button: QtWidgets.QPushButton = status_bar.connect_button
    if connect_button.isHidden():
        connect_button = status_bar.connecting_button

    dashboard.logger.info(f"[GUI] Connecting to HIPRFISR @ {addr} ...")

    # Connect to HiprFisr
    # connect_button.setChecked(True)
    connect_button.setText("Connecting...")
    await dashboard.backend.connect_to_hiprfisr(addr)
    # connect_button.setChecked(False)

    if dashboard.backend.hiprfisr_connected is True:
        dashboard.logger.info("[GUI] Connected")
        connect_button.setText("Connected!")
        await qasync.asyncio.sleep(1)

        # Update Status Bar
        status_bar.update_session_status(connected=True, addr=addr)

        # Enable Dashboard Buttons
        dashboard.ui.pushButton_top_node1.setEnabled(True)
        dashboard.ui.pushButton_top_node2.setEnabled(True)
        dashboard.ui.pushButton_top_node3.setEnabled(True)
        dashboard.ui.pushButton_top_node4.setEnabled(True)
        dashboard.ui.pushButton_top_node5.setEnabled(True)
        # dashboard.ui.tabWidget.setEnabled(True)
        dashboard.ui.pushButton_automation_system_start.setEnabled(True)
    else:
        # Connection Failed
        connect_button.setText("FAILED")
        dashboard.logger.critical("[GUI] HIPRFISR not connected")
        await qasync.asyncio.sleep(1)
        connect_button.setChecked(False)
        connect_button.setText("Retry")


@qasync.asyncSlot(QtCore.QObject)
async def disconnect_hiprfisr(dashboard: QtCore.QObject):
    """
    Disconnect the dashboard from the FISSURE HiprFisr Server

    :param dashboard: FISSURE Dashboard (Frontend) instance
    :type dashboard: QtCore.QObject (Dashboard)
    """
    status_bar = dashboard.statusBar()
    disconnect_button: QtWidgets.QPushButton = status_bar.disconnect_button
    shutdown_button: QtWidgets.QPushButton = status_bar.shutdown_button

    disconnect_button.setText("Disconnecting")
    shutdown_button.hide()

    dashboard.logger.info("[GUI] Disconnecting from HIPRFISR")

    disconnect_button.setChecked(True)
    await dashboard.backend.disconnect_from_hiprfisr()
    disconnect_button.setChecked(False)

    dashboard.logger.info("[GUI] Disconnected")

    # Update Status Bar
    status_bar.update_session_status(connected=False)

    # Disable Dashboard Buttons
    dashboard.ui.pushButton_top_node1.setEnabled(False)
    dashboard.ui.pushButton_top_node2.setEnabled(False)
    dashboard.ui.pushButton_top_node3.setEnabled(False)
    dashboard.ui.pushButton_top_node4.setEnabled(False)
    dashboard.ui.pushButton_top_node5.setEnabled(False)
    # dashboard.ui.tabWidget.setEnabled(False)
    dashboard.ui.pushButton_automation_system_start.setEnabled(False)


@qasync.asyncSlot(QtCore.QObject)
async def shutdown_hiprfisr(dashboard: QtCore.QObject):
    """
    Send the `shutdown` command to the FISSURE Server, wait for the server to shutdown before closing the dashboard

    :param dashboard: FISSURE Dashboard (Frontend) instance
    :type dashboard: QtCore.QObject (Dashboard)
    """
    status_bar = dashboard.statusBar()
    disconnect_button: QtWidgets.QPushButton = status_bar.disconnect_button
    connecting_button: QtWidgets.QPushButton = status_bar.connecting_button
    shutdown_button: QtWidgets.QPushButton = status_bar.shutdown_button

    disconnect_button.hide()
    connecting_button.hide()
    shutdown_button.setText("Shutting Down")

    dashboard.logger.critical("[GUI] Shutting Down HIPRFISR")

    shutdown_button.setChecked(True)
    await dashboard.backend.shutdown_hiprfisr()
    shutdown_button.setChecked(False)

    # # Shutdown Backend and close the Dashboard
    # dashboard.backend.stop()
    # await qasync.asyncio.sleep(0.5)
    # dashboard.close()

    # Reset visible widgets and status
    status_bar.update_session_status(False, None)


@QtCore.pyqtSlot(str, bool, QtCore.QObject)
def update_component_status(componentName: str, online: bool, statusBar: QtCore.QObject):
    """
    Update Component Status in StatusBar
    """

    status = "OK" if online else "--"

    if componentName.lower() == fissure.comms.Identifiers.HIPRFISR.lower():
        statusBar.hiprfisr.setText(f"HIPRFISR: {status}")
    elif componentName.lower() == fissure.comms.Identifiers.TSI.lower():
        statusBar.tsi.setText(f"TSI: {status}")
    elif componentName.lower() == fissure.comms.Identifiers.PD.lower():
        statusBar.pd.setText(f"PD: {status}")
    elif componentName.lower().startswith(fissure.comms.Identifiers.SENSOR_NODE.lower()):
        node_idx = int(componentName[-1])
        statusBar.sensor_nodes[node_idx].setText(f"SN{node_idx+1}: {status}")
        
