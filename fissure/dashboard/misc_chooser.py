import os
from PyQt5 import QtWidgets, uic

misc_chooser_uic = uic.loadUiType(os.path.dirname(os.path.realpath(__file__)) + "/UI/chooser.ui")[0]

class MiscChooser(QtWidgets.QDialog, misc_chooser_uic):
    def __init__(self, parent, label_text, chooser_items):
        """ Multi-purpose combobox.
        """
        QtWidgets.QDialog.__init__(self,parent)
        self.parent = parent
        self.setupUi(self)
        self.return_value = ""

        # Prevent Resizing/Maximizing
        self.setFixedSize(205, 120)

        # Connect Slots
        self.pushButton_ok.clicked.connect(self._slotOK_Clicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)

        # Update Label Text
        self.label1_1.setText(label_text)

        # Update Combobox Items
        self.comboBox_1.addItems(chooser_items)

    def _slotOK_Clicked(self):
        self.return_value = str(self.comboBox_1.currentText())
        self.close()

    def _slotCancelClicked(self):
        self.reject()
