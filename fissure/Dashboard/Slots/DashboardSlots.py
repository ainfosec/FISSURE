from PyQt5 import QtCore, QtWidgets, QtGui

import fissure.comms
import qasync
import os
import re

def _slotInterruptHandler(dashboard: QtCore.QObject, signum, frame):
        """ Prevents other programs from running with events like ctrl+c.
        """
        # Close the Program like the X was Clicked
        dashboard.closeEvent(QtGui.QCloseEvent())

