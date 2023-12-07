import os
from PyQt5 import QtWidgets, uic

help_menu_uic = uic.loadUiType(os.path.dirname(os.path.realpath(__file__)) + "/UI/help.ui")[0]

class HelpMenuDialog(QtWidgets.QDialog, help_menu_uic):
    def __init__(self,parent):
        """ First thing that executes.
        """
        QtWidgets.QDialog.__init__(self,parent)
        self.setupUi(self)

        # Prevent Resizing/Maximizing
        self.setFixedSize(700, 700)

        # Do SIGNAL/Slots Connections
        self._connectSlots()

    def _connectSlots(self):
        """ Contains the connect functions for all the signals and slots
        """
        # Combo Boxes
        self.comboBox_how_to.currentIndexChanged.connect(self._slotHowToTabChanged)

    def _slotHowToTabChanged(self):
        """ Changes the stacked widget index in the help dialog how to section depending on which item in the combobox is selected.
        """
        # Change the Stacked Widget
        self.stackedWidget_how_to.setCurrentIndex(self.comboBox_how_to.currentIndex())
