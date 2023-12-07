import sys
import time
from PyQt5 import QtCore, QtGui, QtWidgets

class Console(QtWidgets.QWidget):
    errorSignal = QtCore.pyqtSignal(str) 
    outputSignal = QtCore.pyqtSignal(str)
    def __init__(self):
        super().__init__()
        self.editor = QtWidgets.QPlainTextEdit(self)
        self.editor.setReadOnly(True)

        self.input = QtWidgets.QLineEdit(self)
        self.input.setEchoMode(QtWidgets.QLineEdit.Password)
        self.input.returnPressed.connect(self.onEnter)
        self.enter = QtWidgets.QPushButton("Enter", self)
        self.enter.clicked.connect(self.onEnter)
        
        self.font = QtGui.QFont()
        # self.font.setFamily(editor["editorFont"])
        self.font.setPointSize(12)
        self.layout = QtWidgets.QVBoxLayout()
        self.layout.addWidget(self.editor, 1)
        self.layout.addWidget(self.input)
        self.layout.addWidget(self.enter)
        self.setLayout(self.layout)
        self.output = None
        self.error = None
        self.editor.setFont(self.font)
        self.process = QtCore.QProcess()
        self.process.readyReadStandardError.connect(self.onReadyReadStandardError)
        self.process.readyReadStandardOutput.connect(self.onReadyReadStandardOutput)

    def onEnter(self):
        self.process.write(self.input.text().encode())
        self.input.clear()
        self.process.write("\n".encode())

    def closeEvent(self, event):

        quit_msg = "Are you sure you want to exit the program?"
        reply = QtWidgets.QMessageBox.question(self, 'Message', 
                     quit_msg, QtWidgets.QMessageBox.Yes, QtWidgets.QMessageBox.No)

        if reply == QtWidgets.QMessageBox.Yes:
            self.process.terminate()
            while self.process.state() != QtCore.QProcess.NotRunning:
                QtCore.QCoreApplication.processEvents()
            self.editor.appendPlainText("\n\nProcess terminated")
            current_time = time.time()
            while time.time() < current_time + 2:
                QtCore.QCoreApplication.processEvents()
            event.accept()
        else:
            event.ignore()

    def onReadyReadStandardError(self):
        error = self.process.readAllStandardError().data().decode()
        self.editor.appendPlainText(error)
        self.errorSignal.emit(error)

    def onReadyReadStandardOutput(self):
        result = self.process.readAllStandardOutput().data().decode()
        self.editor.appendPlainText(result)
        self.outputSignal.emit(result)

    def run(self, command):
        """Executes a system command."""
        # clear previous text
        self.editor.clear()
        self.process.start(command)

    

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    w = Console()
    w.show()
    w.errorSignal.connect(lambda error: print(error))
    w.outputSignal.connect(lambda output: print(output))
    #w.run('more ')
    #w.run('ping 8.8.8.8 -c 10')
    w.run("sudo -S id")
    sys.exit(app.exec_())