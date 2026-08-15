from PyQt5 import QtCore, QtWidgets

# import fissure.comms
import fissure.utils
import qasync
import time
import os
import yaml
import asyncio
import tempfile
import subprocess
import serial.tools.list_ports
import re


@qasync.asyncSlot(QtCore.QObject)
async def refreshClicked(HWSelect: QtCore.QObject):
    """
    Send command to HiprFisr to refresh the list of connected nodes.
    """
    # Send Message to Backend
    await HWSelect.dashboard.backend.nodeRefresh()


@qasync.asyncSlot(QtCore.QObject)
async def selectClicked(HWSelect: QtCore.QObject):
    """
    Select the current connected Sensor Node.

    The Sensor Node must answer nodeSelectIP with its current settings before
    the Dashboard establishes a new selected-node context.
    """
    table = HWSelect.tableWidget_node_list
    row = table.currentRow()

    if row < 0:
        return

    uuid_item = table.item(row, 1)
    connection_item = table.item(row, 5)

    if uuid_item is None or connection_item is None:
        return

    connected_value = connection_item.data(
        QtCore.Qt.UserRole
    )

    if connected_value is None:
        connected = (
            connection_item.text().strip().lower()
            == "connected"
        )
    else:
        connected = bool(connected_value)

    if not connected:
        HWSelect.dashboard.logger.info(
            "[Node Select] Disconnected Sensor Node was not selected."
        )
        return

    node_uuid = str(
        uuid_item.text()
    )

    await HWSelect.dashboard.backend.nodeSelectIP(
        node_uuid
    )

    HWSelect.close()