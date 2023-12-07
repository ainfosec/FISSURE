import os
from PyQt5 import QtWidgets, uic
import yaml
import ast
options_uic = uic.loadUiType(os.path.dirname(os.path.realpath(__file__)) + "/UI/options.ui")[0]

class OptionsDialog(QtWidgets.QDialog, options_uic):
    def __init__(self, parent=None, opening_tab = "Automation", settings_dictionary=None):
        """ First thing that executes.
        """
        QtWidgets.QDialog.__init__(self, parent)
        self.setupUi(self)
        self.return_value = ""

        self.settings_dictionary = settings_dictionary

        # Prevent Resizing/Maximizing
        self.setFixedSize(640, 450)

        # Do SIGNAL/Slots Connections
        self._connectSlots()

        # Change the Current Tab
        if opening_tab == "Automation":
            self.listWidget_options.setCurrentRow(0)
        elif opening_tab == "TSI":
            self.listWidget_options.setCurrentRow(1)
        elif opening_tab == "PD":
            self.listWidget_options.setCurrentRow(2)
        elif opening_tab == "Attack":
            self.listWidget_options.setCurrentRow(3)
        elif opening_tab == "IQ Data":
            self.listWidget_options.setCurrentRow(4)
        elif opening_tab == "Archive":
            self.listWidget_options.setCurrentRow(5)
        elif opening_tab == "Packet Crafter":
            self.listWidget_options.setCurrentRow(6)
        elif opening_tab == "Library":
            self.listWidget_options.setCurrentRow(7)
        elif opening_tab == "Log":
            self.listWidget_options.setCurrentRow(8)
        elif opening_tab == "Hardware":
            self.listWidget_options.setCurrentRow(9)
        else:
            self.listWidget_options.setCurrentRow(10)
        self._slotOptionsListWidgetChanged()

        # Populate the Tables
        tables = [self.tableWidget_options_automation, self.tableWidget_options_tsi, self.tableWidget_options_pd, self.tableWidget_options_attack,
            self.tableWidget_options_iq, self.tableWidget_options_archive, self.tableWidget_options_packet_crafter, self.tableWidget_options_library,
            self.tableWidget_options_log, self.tableWidget_options_hardware, self.tableWidget_options_other]
        for n in range(0,len(tables)):
            for get_row in range(0,tables[n].rowCount()):
                try:
                    get_variable = str(tables[n].verticalHeaderItem(get_row).text())
                    if len(get_variable) > 0:
                        get_value = str(self.settings_dictionary[get_variable])
                        tables[n].setItem(0, get_row, QtWidgets.QTableWidgetItem(get_value))
                except:
                    pass

    def _connectSlots(self):
        """ Contains the connect functions for all the signals and slots.
        """
        self.pushButton_apply.clicked.connect(self._slotOptionsApplyClicked)
        self.pushButton_cancel.clicked.connect(self._slotOptionsCancelClicked)
        self.listWidget_options.currentItemChanged.connect(self._slotOptionsListWidgetChanged)

    def _slotOptionsListWidgetChanged(self):
        """ Changes the index of the stacked widget containing the options.
        """
        # Change StackedWidget
        get_index = self.listWidget_options.currentRow()
        self.stackedWidget_options.setCurrentIndex(get_index)

    def _slotOptionsApplyClicked(self):
        """ The Apply button is clicked in the options dialog.
        """
        # Retrieve Values from Options Dialog
        tables = [self.tableWidget_options_automation, self.tableWidget_options_tsi, self.tableWidget_options_pd, self.tableWidget_options_attack,
            self.tableWidget_options_iq, self.tableWidget_options_archive, self.tableWidget_options_packet_crafter, self.tableWidget_options_library,
            self.tableWidget_options_log, self.tableWidget_options_hardware, self.tableWidget_options_other]
        variable_names = []
        variable_values = []
        for n in range(0,len(tables)):
            for get_row in range(0,tables[n].rowCount()):
                no_row = False
                try:
                    if len(str(tables[n].verticalHeaderItem(get_row).text())) > 0:
                        variable_names.append(str(tables[n].verticalHeaderItem(get_row).text()))
                    else:
                        no_row = True
                except:
                    no_row = True
                if no_row == False:
                    try:
                        if len(str(tables[n].item(get_row,0).text())) > 0:
                            variable_values.append(str(tables[n].item(get_row,0).text()))
                        else:
                            variable_values.append('')
                    except:
                        variable_values.append('')

        # Update Dictionary
        if len(variable_names) == len(variable_values):
            for n in range(0,len(variable_names)):
                # Make Exceptions for Lists
                if variable_names[n] == "disabled_running_flow_graph_variables":
                    self.settings_dictionary[variable_names[n]] = ast.literal_eval(variable_values[n])

                # Otherwise Saved as Strings
                else:
                    self.settings_dictionary[variable_names[n]] = variable_values[n]

        # Dump Dictionary to File
        stream = open(os.path.dirname(os.path.realpath(__file__)) + '/YAML/fissure_config.yaml', 'w')
        yaml.dump(self.settings_dictionary, stream, default_flow_style=False, indent=5)

        # Return Something
        self.return_value = "Ok"
        self.close()

    def _slotOptionsCancelClicked(self):
        """ The Cancel button is clicked in the options dialog.
        """
        self.close()
