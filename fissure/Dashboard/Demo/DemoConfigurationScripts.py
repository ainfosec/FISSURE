from PyQt5 import QtCore, QtWidgets
# import random
import os
import fissure.utils
# import csv
# import datetime
import time
# import subprocess
# import qasync
# from fissure.Dashboard.UI_Components.Qt5 import MyMessageBox
# import struct
# import matplotlib.pyplot as plt
import psutil
from fissure.Dashboard.Slots import MenuBarSlots
import asyncio
import qasync


@qasync.asyncSlot(QtCore.QObject)
async def standaloneMenu(dashboard: QtCore.QObject, demo_name: str):
    """ 
    Opens and closes a standalone flow graph, with logging at each step.
    """
    try:
        # Log starting the action
        dashboard.logger.debug(f"Demo Action Started: {demo_name} - Opening GNU Radio Companion")

        # Open GNU Radio Companion using a menu item
        MenuBarSlots._slotMenuStandaloneClapperPlusTransmitClicked(dashboard)
        await asyncio.sleep(4)
        
        # Log closing action
        dashboard.logger.debug(f"Demo Action: {demo_name} - Attempting to Close GNU Radio Companion")
        
        # Close the standalone flow graph
        filepath = os.path.join(
            fissure.utils.get_fg_library_dir(dashboard.backend.os_info),
            "Standalone Flow Graphs", 
            "Clapper_Plus_Transmit.grc"
        )
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['cmdline'] and filepath in proc.info['cmdline']:
                    proc.terminate()
                    proc.wait(timeout=3)
                    dashboard.logger.debug(f"Demo Action: {demo_name} - Successfully Closed GNU Radio Companion")
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired) as inner_error:
                dashboard.logger.warning(f"Demo Warning: Could not terminate process for {demo_name} - {str(inner_error)}")
    except Exception as e:
        # Log any high-level errors
        error_message = f"Error during {demo_name}: {str(e)}"
        dashboard.logger.error(error_message)
        raise  # Re-raise to allow outer function to handle as well


@qasync.asyncSlot(QtCore.QObject)
async def toolsMenu(dashboard: QtCore.QObject, demo_name: str):
    """ 
    Opens a terminal, fills it with text using the expect script, and closes it.
    """
    try:
        dashboard.logger.debug(f"Demo Action Started: {demo_name} - Opening Terminal")
        
        # Call the terminal-opening function
        MenuBarSlots._slotMenuIwlistScanClicked(dashboard)

        # Inform the user that the terminal is left open
        dashboard.logger.info(f"Demo Action: {demo_name} - Terminal opened. Please close it manually when done.")
    except Exception as e:
        dashboard.logger.error(f"Error during {demo_name}: {str(e)}")
        raise


@qasync.asyncSlot(QtCore.QObject)
async def sensorNodeConfiguration(dashboard: QtCore.QObject, demo_name: str):
    """ 
    Asks for local/remote sensor node and hardware, then steps through the sensor node configuration dialog.
    """
    try:
        # Local/Remote
        dashboard.logger.debug(f"Demo Action Started: {demo_name} - Select Local/Remote Sensor Node")
        local_remote_result = await fissure.Dashboard.UI_Components.Qt5.async_listwidget_dialog(
            parent=None, 
            title="Sensor Node Configuration", 
            label="Select Local or Remote:", 
            options=["Local", "Remote"]
        )
        if local_remote_result:
            dashboard.logger.debug("Local or Remote Sensor Node: " + local_remote_result)
        else:
            return

        # Remote IP Address
        if local_remote_result == "Remote":
            ip_result = await fissure.Dashboard.UI_Components.Qt5.async_textedit_dialog(
                parent=None, 
                label_text="Enter IP Address:", 
            )
            if ip_result:
                dashboard.logger.debug("Remote Sensor Node IP Address: " + ip_result)
            else:
                return

        # Simulated/Connected Hardware
        dashboard.logger.debug(f"Demo Action Started: {demo_name} - Select Connected Hardware")
        hardware_options = ["Simulated"] + fissure.utils.hardware.SUPPORTED_HARDWARE
        hardware_result = await fissure.Dashboard.UI_Components.Qt5.async_listwidget_dialog(
            parent=None, 
            title="Sensor Node Configuration", 
            label="Select Hardware:", 
            options=hardware_options
        )
        if hardware_result:
            dashboard.logger.debug("Hardware Selected: " + hardware_result)
        else:
            return
        
        # Open the Dialog


    except Exception as e:
        dashboard.logger.error(f"Error during {demo_name}: {str(e)}")
        raise


@qasync.asyncSlot(QtCore.QObject)
async def lessonsMenu(dashboard: QtCore.QObject, demo_name: str):
    """ 
    Opens a lesson in a browser.
    """
    try:
        dashboard.logger.debug(f"Demo Action Started: {demo_name} - Opening Lesson")
        
        # Call the Z-Wave Lesson function
        MenuBarSlots._slotMenuLessonZ_WaveClicked()

        # Inform the user that the browser is left open
        dashboard.logger.info(f"Demo Action: {demo_name} - Lesson opened. Please close it manually when done.")
    except Exception as e:
        dashboard.logger.error(f"Error during {demo_name}: {str(e)}")
        raise


@qasync.asyncSlot(QtCore.QObject)
async def helpMenu(dashboard: QtCore.QObject, demo_name: str):
    """ 
    Opens sample help menu items.
    """
    try:
        dashboard.logger.debug(f"Demo Action Started: {demo_name} - Opening User Manual")
        
        # Call the User Manual function
        MenuBarSlots._slotMenuHelpUserManualClicked()

        # Inform the user that the browser is left open
        dashboard.logger.info(f"Demo Action: {demo_name} - User Manual opened in browser. Please close it manually when done.")
    except Exception as e:
        dashboard.logger.error(f"Error during {demo_name}: {str(e)}")
        raise