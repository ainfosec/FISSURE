import sys
from PyQt4 import QtCore, QtGui, uic
import os
import time

Ui_MainWindow, QtBaseClass = uic.loadUiType("main.ui")

class MonitorModeTool(QtGui.QMainWindow, Ui_MainWindow):
    def __init__(self):
        QtGui.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.setupUi(self)
        self.connect()
        self.refreshInterfaces()
        
        
    def connect(self):
        """ Stores the connect functions
        """
        self.pushButton_monitor_mode_execute.clicked.connect(self.monitorMode)
        self.pushButton_managed_mode_execute.clicked.connect(self.managedMode)
        self.pushButton_refresh_interfaces.clicked.connect(self.refreshInterfaces)
        self.pushButton_aircrack.clicked.connect(self.aircrackStartStop)
        self.pushButton_aircrack_file_open.clicked.connect(self.aircrackFileOpen)
        self.pushButton_modprobe.clicked.connect(self.modprobeClicked)
        
        
    def refreshInterfaces(self):
        """ Loads all available interfaces in the comboboxes.
        """
        print "Refreshing Interfaces"
        
        # Update Interface Comboboxes
        get_interfaces = os.listdir("/sys/class/net/")
        self.comboBox_monitor_mode_interface.clear()
        self.comboBox_managed_mode_interface.clear()
        self.comboBox_aircrack_interface.clear()
        for n in get_interfaces:
            self.comboBox_monitor_mode_interface.addItem(n)
            self.comboBox_managed_mode_interface.addItem(n)
            self.comboBox_aircrack_interface.addItem(n)
       
        # Select the Last Interface by Default
        self.comboBox_monitor_mode_interface.setCurrentIndex(self.comboBox_monitor_mode_interface.count()-1)
        self.comboBox_managed_mode_interface.setCurrentIndex(self.comboBox_managed_mode_interface.count()-1)
        self.comboBox_aircrack_interface.setCurrentIndex(self.comboBox_aircrack_interface.count()-1)
        
        print "Done"
        
        
    def monitorMode(self):
        """ Puts the selected interface into monitor mode.
        """
        # Starting
        self.label_terminal.setText("Starting Monitor Mode")

        # Get Text
        get_interface = str(self.comboBox_monitor_mode_interface.currentText())
        get_channel = str(self.comboBox_monitor_mode_channel.currentText())
        get_disable_network_manager = self.checkBox_monitor_mode_disable_network_manager.isChecked()
        
        # Disable Network Manager
        if get_disable_network_manager == True:
            os.system("sudo service network-manager stop")
            self.label_terminal.setText(str(self.label_terminal.text()) + "\n\tsudo service network-manager stop")
        
        # Put into Monitor Mode        
        os.system("sudo ifconfig " + get_interface + " down")
        self.label_terminal.setText(str(self.label_terminal.text()) + "\n\tsudo ifconfig " + get_interface + " down")
        os.system("sudo iwconfig " + get_interface + " mode monitor")
        self.label_terminal.setText(str(self.label_terminal.text()) + "\n\tsudo iwconfig " + get_interface + " mode monitor")
        os.system("sudo ifconfig " + get_interface + " up")
        self.label_terminal.setText(str(self.label_terminal.text()) + "\n\tsudo ifconfig " + get_interface + " up")
        
        # Set Frequency Channel
        os.system("sudo iwconfig " + get_interface + " channel " + get_channel)
        self.label_terminal.setText(str(self.label_terminal.text()) + "\n\tsudo iwconfig " + get_interface + " channel " + get_channel)

        # Done
        self.label_terminal.setText(str(self.label_terminal.text()) + "\nDone")
        
        # Print "ifconfig" Output
        stdouterr = os.popen4("sudo iwconfig " + get_interface)[1].read()
        self.label_terminal.setText(str(self.label_terminal.text()) + "\n\n" + stdouterr)
        
        
    def managedMode(self):
        """ Puts the selected interface into managed mode and turns on Network Manager.
        """
        # Starting
        self.label_terminal.setText("Starting Managed Mode")
        
        # Get Text
        get_interface = str(self.comboBox_managed_mode_interface.currentText())
        
        # Put into Managed Mode        
        os.system("sudo ifconfig " + get_interface + " down")
        self.label_terminal.setText(str(self.label_terminal.text()) + "\n\tsudo ifconfig " + get_interface + " down")
        os.system("sudo iwconfig " + get_interface + " mode managed")
        self.label_terminal.setText(str(self.label_terminal.text()) + "\n\tsudo iwconfig " + get_interface + " mode managed")
        os.system("sudo ifconfig " + get_interface + " up")
        self.label_terminal.setText(str(self.label_terminal.text()) + "\n\tsudo ifconfig " + get_interface + " up")
        
        # Start Network Manager
        os.system("sudo service network-manager start")
        self.label_terminal.setText(str(self.label_terminal.text()) + "\n\tsudo service network-manager start")
        
        # Done
        self.label_terminal.setText(str(self.label_terminal.text()) + "\nDone")
        
        # Print "ifconfig" Output
        stdouterr = os.popen4("sudo iwconfig " + get_interface)[1].read()
        self.label_terminal.setText(str(self.label_terminal.text()) + "\n\n" + stdouterr)

    def aircrackStartStop(self):
        """ Starts and stops an Aircrack capture.
        """
        print "Starting Aircrack Capture"
        
        get_interface = str(self.comboBox_aircrack_interface.currentText())
        get_channel = str(self.comboBox_aircrack_channel.currentText())
        get_mac_filter = str(self.plainTextEdit_aircrack_mac_filter.toPlainText())
        get_filepath = str(self.plainTextEdit_aircrack_filepath.toPlainText())
        
        # Start Aircrack on Interface (Optional, Sometimes Doesn't Work Right)
        #os.system("sudo airmon-ng start " + get_interface)
        
        # Run Airodump on New Aircrack Interface
        os.system("sudo airodump-ng -c " + get_channel + " -d " + get_mac_filter + " -w " + get_filepath + " --output-format pcap " + get_interface)
                
        print "Done"
        
    def aircrackFileOpen(self):
        """ Opens a dialog to select the filepath for new aircrack captures.
        """
        print "file open clicked"
        dlg = QtGui.QFileDialog()
        dlg.setFileMode(QtGui.QFileDialog.AnyFile)
        dlg.setFilter("CAP (*.cap)")
        filename = QtCore.QStringList
        
        if dlg.exec_():
            filename = dlg.selectedFiles()
            
        self.plainTextEdit_aircrack_filepath.setPlainText(str(str(filename[0])+".cap"))
        
    def modprobeClicked(self):
        """ Runs 'sudo modprobe <driver>'.
        """
        # Issue Command
        get_driver = str(self.plainTextEdit_driver.toPlainText())
        os.system("sudo modprobe " + get_driver)
        
        
if __name__ == "__main__":
    """ main()
    """
    app = QtGui.QApplication(sys.argv)
    window = MonitorModeTool()
    window.show()
    sys.exit(app.exec_())
