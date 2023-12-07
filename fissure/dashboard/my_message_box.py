from PyQt5 import QtWidgets, QtCore

class MyMessageBox(QtWidgets.QDialog):
    def __init__(self, parent=None, my_text= "", width=480, height=600):
        QtWidgets.QDialog.__init__(self)
        label = QtWidgets.QLabel(self)
        label.setTextInteractionFlags(QtCore.Qt.TextSelectableByMouse)
        label.setText(my_text)
        scroll = QtWidgets.QScrollArea(self)
        scroll.setGeometry(QtCore.QRect(10,20,width,height))
        scroll.setWidget(label)
        scroll.setWidgetResizable(True)
        okButton = QtWidgets.QPushButton(self)
        okButton.clicked.connect(self.closeWindow)
        okButton.setGeometry(QtCore.QRect(int(width/2-40),height+30,100,30))
        okButton.setText("OK")

    def setDimensions(self, new_width, new_height):
        """ Resizes the dialog window.
        """
        self.width = new_width
        height = new_height

    def closeWindow(self):
        self.accept()
