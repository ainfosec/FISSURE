import os
from PyQt5 import QtWidgets, uic

custom_color_uic = uic.loadUiType(os.path.dirname(os.path.realpath(__file__)) + "/data/UI/custom_color.ui")[0]

class CustomColor(QtWidgets.QDialog, custom_color_uic):
    def __init__(self, parent):
        """ Allows user to choose values for custom color themes.
        """
        QtWidgets.QDialog.__init__(self,parent)
        self.parent = parent
        self.setupUi(self)
        self.return_value = ""

        # Prevent Resizing/Maximizing
        self.setFixedSize(390, 215)

        # Connect Slots
        self.pushButton_ok.clicked.connect(self._slotOK_Clicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)
        self.pushButton_color1.clicked.connect(self._slotColor1_Clicked)
        self.pushButton_color2.clicked.connect(self._slotColor2_Clicked)
        self.pushButton_color3.clicked.connect(self._slotColor3_Clicked)
        self.pushButton_color4.clicked.connect(self._slotColor4_Clicked)
        self.pushButton_color5.clicked.connect(self._slotColor5_Clicked)

        # Fill in Default Values
        if len(self.parent.dashboard_settings_dictionary['custom_color1']) == 7:
            self.textEdit_color1.setPlainText(str(self.parent.dashboard_settings_dictionary['custom_color1']))
        if len(self.parent.dashboard_settings_dictionary['custom_color2']) == 7:
            self.textEdit_color2.setPlainText(str(self.parent.dashboard_settings_dictionary['custom_color2']))
        if len(self.parent.dashboard_settings_dictionary['custom_color3']) == 7:
            self.textEdit_color3.setPlainText(str(self.parent.dashboard_settings_dictionary['custom_color3']))
        if len(self.parent.dashboard_settings_dictionary['custom_color4']) == 7:
            self.textEdit_color4.setPlainText(str(self.parent.dashboard_settings_dictionary['custom_color4']))
        if len(self.parent.dashboard_settings_dictionary['custom_color5']) == 7:
            self.textEdit_color5.setPlainText(str(self.parent.dashboard_settings_dictionary['custom_color5']))

    def _slotOK_Clicked(self):
        self.return_value = "1"

        # Save the Colors
        get_color1 = str(self.textEdit_color1.toPlainText())
        get_color2 = str(self.textEdit_color2.toPlainText())
        get_color3 = str(self.textEdit_color3.toPlainText())
        get_color4 = str(self.textEdit_color4.toPlainText())
        get_color5 = str(self.textEdit_color5.toPlainText())
        if len(get_color1) == 7:  # "#123456/#RRGGBB"
            self.parent.dashboard_settings_dictionary['custom_color1'] = get_color1
        if len(get_color2) == 7:  # "#123456/#RRGGBB"
            self.parent.dashboard_settings_dictionary['custom_color2'] = get_color2
        if len(get_color3) == 7:  # "#123456/#RRGGBB"
            self.parent.dashboard_settings_dictionary['custom_color3'] = get_color3
        if len(get_color4) == 7:  # "#123456/#RRGGBB"
            self.parent.dashboard_settings_dictionary['custom_color4'] = get_color4
        if len(get_color5) == 7:  # "#123456/#RRGGBB"
            self.parent.dashboard_settings_dictionary['custom_color5'] = get_color5

        self.close()

    def _slotCancelClicked(self):
        self.reject()

    def _slotColor1_Clicked(self):
        """ Opens the color selector for color1.
        """
        # Open the Selector
        get_color = QtWidgets.QColorDialog.getColor()
        if get_color.isValid():
            self.textEdit_color1.setPlainText(str(get_color.name()).upper())

    def _slotColor2_Clicked(self):
        """ Opens the color selector for color2.
        """
        # Open the Selector
        get_color = QtWidgets.QColorDialog.getColor()
        if get_color.isValid():
            self.textEdit_color2.setPlainText(str(get_color.name()).upper())

    def _slotColor3_Clicked(self):
        """ Opens the color selector for color3.
        """
        # Open the Selector
        get_color = QtWidgets.QColorDialog.getColor()
        if get_color.isValid():
            self.textEdit_color3.setPlainText(str(get_color.name()).upper())

    def _slotColor4_Clicked(self):
        """ Opens the color selector for color4.
        """
        # Open the Selector
        get_color = QtWidgets.QColorDialog.getColor()
        if get_color.isValid():
            self.textEdit_color4.setPlainText(str(get_color.name()).upper())

    def _slotColor5_Clicked(self):
        """ Opens the color selector for color5.
        """
        # Open the Selector
        get_color = QtWidgets.QColorDialog.getColor()
        if get_color.isValid():
            self.textEdit_color5.setPlainText(str(get_color.name()).upper())
