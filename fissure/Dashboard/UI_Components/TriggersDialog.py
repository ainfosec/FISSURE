from ..Slots import TriggersDialogSlots
from .UI_Types import UI_Types
from PyQt5 import QtCore, QtWidgets

# import fissure.comms
# import os
# import time
# import yaml


class TriggersDialog(QtWidgets.QDialog, UI_Types.Triggers):

    def __init__(self, parent: QtWidgets.QWidget, dashboard: QtCore.QObject, fissure_tab="", table_values=[]):
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.dashboard = dashboard
        self.setupUi(self)
        self.return_value = []

        # Prevent Resizing/Maximizing
        self.parent.setFixedSize(QtCore.QSize(900, 600))

        # Connect Signals to Slots
        self.__connect_slots__()

        # Fill Comboboxes
        self.comboBox_category.clear()
        self.comboBox_trigger.clear()
        category_list = list(dashboard.backend.library['Triggers'].keys())
        trigger_list = list(dashboard.backend.library['Triggers'][category_list[0]].keys())
        self.comboBox_category.addItems(sorted(category_list))
        # self._slotCategoryChanged()
        TriggersDialogSlots._slotCategoryChanged(self)
        
        # Fill Table
        self.tableWidget_trigger_info.setRowCount(len(table_values))
        for row in range(0,len(table_values)):
            # Filename
            filename_item = QtWidgets.QTableWidgetItem(table_values[row][0])
            filename_item.setTextAlignment(QtCore.Qt.AlignCenter)
            filename_item.setFlags(filename_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.tableWidget_trigger_info.setItem(row,0,filename_item)
            
            # Type
            type_item = QtWidgets.QTableWidgetItem(table_values[row][1])
            type_item.setTextAlignment(QtCore.Qt.AlignCenter)
            type_item.setFlags(type_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.tableWidget_trigger_info.setItem(row,1,type_item)

            # Variable Names
            variable_names_item = QtWidgets.QTableWidgetItem(table_values[row][2])
            variable_names_item.setTextAlignment(QtCore.Qt.AlignCenter)
            variable_names_item.setFlags(variable_names_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.tableWidget_trigger_info.setItem(row,2,variable_names_item)

            # Variable Values
            variable_values_item = QtWidgets.QTableWidgetItem(table_values[row][3])
            variable_values_item.setTextAlignment(QtCore.Qt.AlignCenter)
            variable_values_item.setFlags(variable_values_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.tableWidget_trigger_info.setItem(row,3,variable_values_item)
        
        # Resize the Table
        self.tableWidget_trigger_info.resizeColumnsToContents()
        #self.tableWidget_trigger_info.setColumnWidth(5,300)
        #self.tableWidget_trigger_info.setColumnWidth(6,300)
        self.tableWidget_trigger_info.resizeRowsToContents()
        self.tableWidget_trigger_info.horizontalHeader().setStretchLastSection(False)
        self.tableWidget_trigger_info.horizontalHeader().setStretchLastSection(True)
        
        # Guess Index
        self.guess_index = 0
        self.fissure_tab = fissure_tab
        
        # Hardware Comboboxes
        if (self.fissure_tab == "Single-Stage") or (self.fissure_tab == "Multi-Stage"):
            hardware_widget = dashboard.ui.comboBox_attack_hardware
        elif self.fissure_tab == "Archive Replay":
            hardware_widget = dashboard.ui.comboBox_archive_replay_hardware
        elif self.fissure_tab == "Autorun Playlist":
            hardware_widget = dashboard.ui.comboBox_attack_hardware
        else:
            hardware_widget = dashboard.ui.comboBox_attack_hardware
        for n in range(0,hardware_widget.count()):
            item_text = hardware_widget.itemText(n)
            self.comboBox_rf_x10_demod_hardware.addItem(item_text)
            self.comboBox_rf_plane_spotting_hardware.addItem(item_text)
            self.comboBox_rf_rds_keyword_hardware.addItem(item_text)
            self.comboBox_rf_cellular_tower_hardware.addItem(item_text)
            self.comboBox_rf_power_threshold_hardware.addItem(item_text)


    def __connect_slots__(self):
        """
        Contains the connect functions for all the signals and slots
        """
        # Connect Slots
        self.pushButton_ok.clicked.connect(lambda: TriggersDialogSlots._slotOK_Clicked(self))
        self.pushButton_cancel.clicked.connect(lambda: TriggersDialogSlots._slotCancelClicked(self))
        self.pushButton_view.clicked.connect(lambda: TriggersDialogSlots._slotViewClicked(self))
        self.pushButton_add.clicked.connect(lambda: TriggersDialogSlots._slotAddClicked(self))
        self.pushButton_remove.clicked.connect(lambda: TriggersDialogSlots._slotRemoveClicked(self))
        self.pushButton_filesystem_file_modified_browse.clicked.connect(lambda: TriggersDialogSlots._slotDataFileModifiedBrowseClicked(self))
        self.pushButton_filesystem_folder_modified_browse.clicked.connect(lambda: TriggersDialogSlots._slotDataFolderModifiedBrowseClicked(self))
        self.pushButton_environmental_temperature_validate.clicked.connect(lambda: TriggersDialogSlots._slotEnvironmentalTemperatureValidateClicked(self))
        self.pushButton_environmental_weather_validate.clicked.connect(lambda: TriggersDialogSlots._slotEnvironmentalWeatherValidateClicked(self))
        self.pushButton_environmental_wind_validate.clicked.connect(lambda: TriggersDialogSlots._slotEnvironmentalWindValidateClicked(self))
        self.pushButton_environmental_sunrise_validate.clicked.connect(lambda: TriggersDialogSlots._slotEnvironmentalSunriseValidateClicked(self))
        self.pushButton_rf_detect_ssid_guess.clicked.connect(lambda: TriggersDialogSlots._slotDataDetectSSID_GuessClicked(self))

        self.comboBox_category.currentIndexChanged.connect(lambda: TriggersDialogSlots._slotCategoryChanged(self))
        self.comboBox_trigger.currentIndexChanged.connect(lambda: TriggersDialogSlots._slotTriggerChanged(self))



        
