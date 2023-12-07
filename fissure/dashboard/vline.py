from PyQt5 import QtWidgets

class VLine(QtWidgets.QFrame):
    """ Vertical line for the statusbar.
    """
    # a simple VLine, like the one you get from designer
    def __init__(self, parent):
        super(VLine, self).__init__(parent)
        self.parent = parent
        self.setFrameShape(self.VLine|self.Sunken)
        #self.setMaximumWidth(2)
