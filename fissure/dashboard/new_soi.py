import os

from PyQt5 import QtWidgets, uic
new_soi_uic = uic.loadUiType(os.path.dirname(os.path.realpath(__file__)) + "/UI/new_soi.ui")[0]

class NewSOI(QtWidgets.QDialog, new_soi_uic):
    def __init__(self, parent):
        """ Creates a new Signal of Interest in Protocol Discovery.
        """
        QtWidgets.QDialog.__init__(self,parent)
        self.parent = parent
        self.setupUi(self)
        self.return_value = ""

        # Prevent Resizing/Maximizing
        self.setFixedSize(380, 300)

        # Connect Slots
        self.pushButton_ok.clicked.connect(self._slotOK_Clicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)

        # Fill in Default Values as Last SOI
        if len(self.parent.target_soi) > 0:
            self.textEdit_frequency.setPlainText(str(self.parent.target_soi[0]))
            self.textEdit_modulation.setPlainText(str(self.parent.target_soi[1]))
            self.textEdit_bandwidth.setPlainText(str(self.parent.target_soi[2]))

            if self.parent.target_soi[3] == "True":
                self.comboBox_continuous.setCurrentIndex(0)
            else:
                self.comboBox_continuous.setCurrentIndex(1)

            self.textEdit_start_frequency.setPlainText(str(self.parent.target_soi[4]))
            self.textEdit_end_frequency.setPlainText(str(self.parent.target_soi[5]))
            self.textEdit_notes.setPlainText(str(self.parent.target_soi[6]))

    def _slotOK_Clicked(self):
        self.return_value = "1"

        # Assemble the Target SOI
        get_frequency = str(self.textEdit_frequency.toPlainText())
        get_modulation = str(self.textEdit_modulation.toPlainText())
        get_bandwidth = str(self.textEdit_bandwidth.toPlainText())
        get_continuous = str(self.comboBox_continuous.currentText())
        get_start_frequency = str(self.textEdit_start_frequency.toPlainText())
        get_end_frequency = str(self.textEdit_end_frequency.toPlainText())
        get_notes = str(self.textEdit_notes.toPlainText())

        self.parent.target_soi = [get_frequency, get_modulation, get_bandwidth, get_continuous, get_start_frequency, get_end_frequency, get_notes]
        self.close()

    def _slotCancelClicked(self):
        self.reject()
