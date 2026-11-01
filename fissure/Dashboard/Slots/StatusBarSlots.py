from PyQt5 import QtCore, QtWidgets

import fissure.comms
import qasync
import asyncio


@QtCore.pyqtSlot(QtCore.QObject)
def remote_connect_prompt(statusBar: QtCore.QObject):
    """
    Prompt for Remote Connections

    :param statusBar: FISSURE Dashboard StatusBar
    :type statusBar: QtCore.QObject (FissureStatusBar)
    """

    statusBar.session_label.setText("Server:")
    statusBar.protocol_select.setEnabled(False)  # lock it so users can't change

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
        statusBar.addr_box.setText("192.168.1.xxx")  # hint for user
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

    # Enable Widgets in retrieveDatabaseCacheReturn()


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

    # # ---- show busy popup ----  # Needs more adjustments to stay up longer
    # dlg = QtWidgets.QProgressDialog("Connecting to HIPRFISR...", None, 0, 0, dashboard)
    # dlg.setWindowTitle("FISSURE")
    # dlg.setWindowModality(QtCore.Qt.ApplicationModal)
    # dlg.setCancelButton(None)
    # dlg.setMinimumDuration(3000)  # 0 means "auto", use >0 to force paint
    # dlg.setAutoClose(False)
    # dlg.setAutoReset(False)
    # dlg.show()

    # # force Qt to process one paint cycle right now
    # QtWidgets.QApplication.processEvents(QtCore.QEventLoop.AllEvents, 100)

    # ---- backend start and async connect ----
    connect_button.setText("Connecting...")
    dashboard.backend.initial_database_retrieval = True
    dashboard.backend.initialize_comms()
    dashboard.backend.start()

    asyncio.create_task(dashboard.backend.connect_to_hiprfisr(addr))

    # ---- async waiter to watch for connection ----
    async def _wait_for_connected():
        for _ in range(100):  # ~5s total
            if dashboard.backend.hiprfisr_connected:
                dashboard.logger.info("[GUI] Connected")
                status_bar.update_session_status(connected=True, addr=addr)
                connect_button.setText("Connected!")
                connect_button.setChecked(False)
                # dlg.close()
                return
            await asyncio.sleep(0.05)
            QtWidgets.QApplication.processEvents()
        # timed out
        dashboard.logger.critical("[GUI] HIPRFISR not connected")
        connect_button.setText("Retry")
        connect_button.setChecked(False)
        # dlg.close()

    asyncio.create_task(_wait_for_connected())


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

    back(dashboard)

    dashboard.logger.info("[GUI] Disconnected")

    # Update Status Bar
    status_bar.update_session_status(connected=False)

    # Disable Tabs
    # dashboard.ui.tabWidget.setEnabled(False)


@qasync.asyncSlot(QtCore.QObject)
async def shutdown_hiprfisr(dashboard: QtCore.QObject):

    status_bar = dashboard.statusBar()
    disconnect_button = status_bar.disconnect_button
    connecting_button = status_bar.connecting_button
    shutdown_button = status_bar.shutdown_button

    disconnect_button.hide()
    connecting_button.hide()
    shutdown_button.setText("Shutting Down")
    shutdown_button.setChecked(True)

    dashboard.logger.critical("[GUI] Shutting Down HIPRFISR")
    
    # Fire backend shutdown — DO NOT WAIT FOR ANY RESPONSE.
    try:
        asyncio.create_task(dashboard.backend.shutdown_hiprfisr())
    except Exception as e:
        dashboard.logger.warning(f"[GUI] Error sending shutdown: {e}")

    # Force backend loop to end
    dashboard.backend.shutdown = True

    shutdown_button.setChecked(False)

    # Continue GUI cleanup
    back(dashboard)
    dashboard.ui.tabWidget.setEnabled(False)
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