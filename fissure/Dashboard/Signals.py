from PyQt5 import QtCore


class DashboardSignals(QtCore.QObject):
    ComponentStatus: QtCore.pyqtSignal = QtCore.pyqtSignal(
        str, bool, QtCore.QObject
    )  # ComponentName: str, Status: bool, StatusBar: QtCore.QObject
    Shutdown: QtCore.pyqtSignal = QtCore.pyqtSignal(QtCore.QObject)  # DashboardBackend: QtCore.QObject

    def __init__(self):
        super().__init__()
