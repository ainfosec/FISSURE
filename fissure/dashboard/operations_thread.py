import subprocess
from PyQt5 import QtCore

class OperationsThread(QtCore.QThread):
    def __init__(self, cmd, get_cwd, parent=None):
        QtCore.QThread.__init__(self, parent)
        self.cmd = cmd
        self.get_cwd = get_cwd

    def run(self):
        try:
            p1 = subprocess.Popen(self.cmd, shell=True, cwd=self.get_cwd)
            (output, err) = p1.communicate()
            p1.wait()
        except:
            print("FAILURE")