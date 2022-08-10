#!/usr/bin/python2
#-*- coding: utf-8 -*-
 
"""
Set label text from line edit with 
ok click
"""
 
import sys
from PyQt4 import QtGui#, QtCore
import subprocess
 
class Example(QtGui.QMainWindow):
 
    def __init__(self):
        super(Example, self).__init__()
        
        # Open the GUI
        ip, ok = QtGui.QInputDialog.getText(self, 'Open Sniffer', 'Enter Open Sniffer IP Address:',QtGui.QLineEdit.Normal)
            
        # Ok Clicked
        if ok:
            print ip    
            cmd = 'sensible-browser -new-tab "{}"'.format(ip) 
            proc = subprocess.Popen(cmd, shell=True)
            proc.communicate()
 
        # self.initUI()
 
    # def initUI(self):
 
        # self.qle = QtGui.QLineEdit(self)
        # self.qle.move(120, 5) # re
        # self.qlbl = QtGui.QLabel(self)
        # self.qlbl. setText("IP:")
        # self.qlbl.move(100,5)
        # global sometext
        # sometext = self.qle.text
 
        # btn = QtGui.QPushButton("Ok", self)
        # btn.move(120, 60)
 
        # btn.clicked.connect(self.buttonClicked)
 
        # self.setGeometry(50, 50, 320, 100)
        # self.setWindowTitle("ZigBee IP Input")
        # self.show()
 
    # def buttonClicked(self, sometext):
        # sender = self.sender()
        # ip = (self.qle.text())
        # cmd = 'sensible-browser -new-tab "{}"'.format(ip) 
        # proc = subprocess.Popen(cmd, shell=True)
        # proc.communicate()

def main():
 
    app = QtGui.QApplication(sys.argv)
    ex = Example()
    sys.exit(app.exec_())
    
 
if __name__ == '__main__':
    main()
