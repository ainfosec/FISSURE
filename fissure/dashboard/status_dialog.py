import os
from PyQt5 import QtWidgets, uic

status_dialog_uic = uic.loadUiType(os.path.dirname(os.path.realpath(__file__)) + "/UI/status.ui")[0]

class StatusDialog(QtWidgets.QFrame, status_dialog_uic):
    def __init__(self, parent):
        """ First thing that executes.
        """
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.setupUi(self)

        # Prevent Resizing/Maximizing
        # ~ self.setFixedSize(700, 500)
