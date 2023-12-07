import os
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar

from PyQt5 import QtCore, QtGui, QtWidgets

from .entropy_mpl_canvas import EntropyMplCanvas

class MyPlotWindow(QtWidgets.QDialog):
    def __init__(self, parent=None, entropy_data = None, width=700, height=700):
        QtWidgets.QDialog.__init__(self)
        #~ label = QtWidgets.QLabel(self)
        #~ label.setText(my_text)
        scroll = QtWidgets.QScrollArea(self)
        scroll.setGeometry(QtCore.QRect(0,0,width,height))
        #~ scroll.setWidget(label)
        scroll.setWidgetResizable(True)
        okButton = QtWidgets.QPushButton(self)
        okButton.clicked.connect(self.closeWindow)
        okButton.setGeometry(QtCore.QRect(300,650,100,30))
        okButton.setText("OK")


        # Create Matplotlib Widget
        entropy_mpl_widget = EntropyMplCanvas(self)
        #~ entropy_mpl_widget.move(0,0)
        entropy_mpl_widget.setGeometry(50,0,600,600)


        # Add a Toolbar
        mpl_toolbar = NavigationToolbar(entropy_mpl_widget, self)
        mpl_toolbar.setGeometry(QtCore.QRect(175, 600, 525, 35))
        icons_buttons = {
            "Home": QtGui.QIcon(os.path.dirname(os.path.realpath(__file__)) + "/Icons/home.png"),
            "Pan": QtGui.QIcon(os.path.dirname(os.path.realpath(__file__)) + "/Icons/move.png"),
            "Zoom": QtGui.QIcon(os.path.dirname(os.path.realpath(__file__)) + "/Icons/zoom_to_rect.png"),
            "Back": QtGui.QIcon(os.path.dirname(os.path.realpath(__file__)) + "/Icons/back.png"),
            "Forward": QtGui.QIcon(os.path.dirname(os.path.realpath(__file__)) + "/Icons/forward.png"),
            "Subplots": QtGui.QIcon(os.path.dirname(os.path.realpath(__file__)) + "/Icons/subplots.png"),
            "Customize": QtGui.QIcon(os.path.dirname(os.path.realpath(__file__)) + "/Icons/qt4_editor_options.png"),
            "Save": QtGui.QIcon(os.path.dirname(os.path.realpath(__file__)) + "/Icons/filesave.png"),
        }
        for action in mpl_toolbar.actions():
            if action.text() in icons_buttons:
                action.setIcon(icons_buttons.get(action.text(), QtGui.QIcon()))

        # Plot the Data
        entropy_mpl_widget.axes.plot(range(0,len(entropy_data)), entropy_data, label='pre (default)', marker='.')
        entropy_mpl_widget.configureAxes("Bit Position Entropy Values",'Bit Position','Entropy',None,None)
        entropy_mpl_widget.draw()

    def closeWindow(self):
        self.accept()
