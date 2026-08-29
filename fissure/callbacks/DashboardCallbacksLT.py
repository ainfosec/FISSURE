import fissure.comms
import time
from PyQt5 import QtCore, QtWidgets, QtGui
import yaml
import os
import subprocess
import threading
import ast
import asyncio
from typing import List
import json
import qasync
import datetime

# from fissure.Dashboard.UI_Components.Qt5 import MyMessageBox
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
    SensorNodesPluginsTabSlots,
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


async def recallInfoMeshtasticReturnLT(component: object, tab_index="", nickname="", location="", notes=""):
    """
    Populates the HardwareSelectDialog with the sensor node settings on connect.
    """
    pass
    # if tab_index and 0 <= int(tab_index) < 5:
    #     # Dynamically retrieve all relevant widgets
    #     widget_number = str(int(tab_index)+1)
    #     nickname_widget = getattr(component.frontend.popups["HardwareSelectDialog"], f"textEdit_nickname_{widget_number}")
    #     location_widget = getattr(component.frontend.popups["HardwareSelectDialog"], f"textEdit_location_{widget_number}")
    #     notes_widget = getattr(component.frontend.popups["HardwareSelectDialog"], f"textEdit_notes_{widget_number}")
        
    #     # Set the values
    #     nickname_widget.setPlainText(nickname)
    #     location_widget.setPlainText(location)
    #     notes_widget.setPlainText(notes)


async def recallHardwareMeshtasticReturnLT(component: object, tsi={}):
    """
    Populates the HardwareSelectDialog with the sensor node settings on connect.
    """
    print("HARDWARE RETURN @#$#@$@#$#@$#@")  # TODO
    print(tsi)
    # Pass Sensor Node Settings to HardwareSelectDialog
    # component.frontend.popups["HardwareSelectDialog"].importResults(settings_dict=settings_dict)


async def recallStatusMeshtasticReturnLT(component: object, tab_index="", status=""):
    """
    Populates the HardwareSelectDialog with the sensor node settings on connect.
    """
    pass
    # if tab_index and 0 <= int(tab_index) < 5:
    #     # Open a Text Dialog
    #     ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["HardwareSelectDialog"], status)
    #     return


async def findGPS_CoordinatesResultsLT(component: object, tab_index=0, coordinates=""):
    """
    Returns the GPS coordinate results to the HardwareSelectDialog.
    """
    pass
    # # Populate Location
    # location_widget = [
    #     component.frontend.popups["HardwareSelectDialog"].textEdit_location_1,
    #     component.frontend.popups["HardwareSelectDialog"].textEdit_location_2,
    #     component.frontend.popups["HardwareSelectDialog"].textEdit_location_3,
    #     component.frontend.popups["HardwareSelectDialog"].textEdit_location_4,
    #     component.frontend.popups["HardwareSelectDialog"].textEdit_location_5
    # ]
    # location_widget[int(tab_index)].setPlainText(str(coordinates))

    # # Enable the Find Button
    # find_widgets = [
    #     component.frontend.popups["HardwareSelectDialog"].pushButton_find_1,
    #     component.frontend.popups["HardwareSelectDialog"].pushButton_find_2,
    #     component.frontend.popups["HardwareSelectDialog"].pushButton_find_3,
    #     component.frontend.popups["HardwareSelectDialog"].pushButton_find_4,
    #     component.frontend.popups["HardwareSelectDialog"].pushButton_find_5
    # ]
    # # find_widgets[int(tab_index)].setEnabled(True)


async def hardwareProbeResultsLT(component: object, tab_index=0, output="", height_width=[]):
    """
    Returns the probe results to the HardwareSelectDialog.
    """
    pass
    # # Parse Return String
    # probe_text = output
    
    # # Hide Label
    # scan_results_labels = [
    #     component.frontend.popups["HardwareSelectDialog"].label2_scan_results_probe_1,
    #     component.frontend.popups["HardwareSelectDialog"].label2_scan_results_probe_2,
    #     component.frontend.popups["HardwareSelectDialog"].label2_scan_results_probe_3,
    #     component.frontend.popups["HardwareSelectDialog"].label2_scan_results_probe_4,
    #     component.frontend.popups["HardwareSelectDialog"].label2_scan_results_probe_5
    # ]
    # scan_results_labels[int(tab_index)].setVisible(False)

    # # Enable Probe Button
    # probe_buttons = [
    #     component.frontend.popups["HardwareSelectDialog"].pushButton_scan_results_probe_1,
    #     component.frontend.popups["HardwareSelectDialog"].pushButton_scan_results_probe_2,
    #     component.frontend.popups["HardwareSelectDialog"].pushButton_scan_results_probe_3,
    #     component.frontend.popups["HardwareSelectDialog"].pushButton_scan_results_probe_4,
    #     component.frontend.popups["HardwareSelectDialog"].pushButton_scan_results_probe_5
    # ]
    # probe_buttons[int(tab_index)].setEnabled(True)

    # # Open a Text Dialog
    # ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["HardwareSelectDialog"], probe_text)
    

async def hardwareScanResultsLT(component: object, tab_index=0, hardware_scan_results=[]):
    """
    Returns Auto Scan results to the HardwareSelectDialog.
    """
    pass
    # component.frontend.popups["HardwareSelectDialog"].scanReturn(tab_index=tab_index, all_scan_results=hardware_scan_results)


async def hardwareGuessResultsLT(component: object, tab_index=0, table_row=0, hardware_type="", scan_results="", new_guess_index=0):
    """
    Fills the scan results table row with hardware information in HardwareSelectDialog.
    """
    pass
    # # Fill the Table
    # component.frontend.popups["HardwareSelectDialog"].guessReturn(tab_index, table_row, hardware_type, scan_results, new_guess_index)


async def uptimeMeshtasticReturnLT(component: object, uptime: str):
    """
    Returns the uptime results to the HardwareSelectDialog.
    """
    pass
    # # Open a Text Dialog
    # ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["HardwareSelectDialog"], uptime)


async def memoryMeshtasticReturnLT(component: object, memory: list):
    """
    Returns the memory usage results to the HardwareSelectDialog.
    """
    pass
    # # Open a Text Dialog
    # headers = ["total", "used", "free", "shared", "buff/cache", "available"]
    # memory_string = "\n".join(f"{key}: {value}" for key, value in zip(headers, memory))
    # ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["HardwareSelectDialog"], memory_string)


async def diskMeshtasticReturnLT(component: object, disk: dict):
    """
    Returns the disk usage results to the HardwareSelectDialog.
    """
    pass
    # # Open a Text Dialog
    # disk_string = "\n".join(f"{k}: {v}" for k, v in disk.items())
    # ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["HardwareSelectDialog"], disk_string)


async def cpuMeshtasticReturnLT(component: object, cpu: str):
    """
    Returns the CPU percentage results to the HardwareSelectDialog.
    """
    pass
    # # Open a Text Dialog
    # ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["HardwareSelectDialog"], cpu)


async def processesMeshtasticReturnLT(component: object, processes: str):
    """
    Returns the processes results to the HardwareSelectDialog.
    """
    pass
    # # Open a Text Dialog
    # ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["HardwareSelectDialog"], processes)


async def ifconfigMeshtasticReturnLT(component: object, ifconfig:str):
    """
    Returns the ifconfig results to the HardwareSelectDialog.
    """
    pass
    # # Open a Text Dialog
    # ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["HardwareSelectDialog"], ifconfig)


async def iwconfigMeshtasticReturnLT(component: object, iwconfig:str):
    """
    Returns the iwconfig results to the HardwareSelectDialog.
    """
    pass
    # # Open a Text Dialog
    # ret = await fissure.Dashboard.UI_Components.Qt5.async_ok_dialog(component.frontend.popups["HardwareSelectDialog"], iwconfig)

