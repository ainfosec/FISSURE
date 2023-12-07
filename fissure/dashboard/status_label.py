from PyQt5 import QtWidgets

class StatusLabel(QtWidgets.QLabel):
    def __init__(self, parent):
        super(StatusLabel, self).__init__(parent)
        self.parent = parent
        self.setMouseTracking(True)
        self.setObjectName('label2_')

    def enterEvent(self, event):
        self.parent.status_dialog.show()

    def leaveEvent(self, event):
        self.parent.status_dialog.hide()
