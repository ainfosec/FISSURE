from PyQt5 import QtWidgets

class CustomStatusBar(QtWidgets.QStatusBar):
    def __init__(self, parent):
        super(CustomStatusBar, self).__init__(parent)
        self.parent = parent
        #self.setAutoFillBackground(True)
        #p = self.palette()
        #p.setColor(self.backgroundRole(), QtGui.QColor(223, 230, 248))
        #self.setPalette(p)
        self.setMouseTracking(True)
        #self.setFont(QtGui.QFont("Ubuntu",10))

    def enterEvent(self, event):
        self.parent.status_dialog.show()

    def leaveEvent(self, event):
        self.parent.status_dialog.hide()