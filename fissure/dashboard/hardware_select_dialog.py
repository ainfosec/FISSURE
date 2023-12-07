import os
import subprocess

from PyQt5 import QtWidgets, QtCore, uic
from .my_message_box import MyMessageBox

hardware_select_uic = uic.loadUiType(os.path.dirname(os.path.realpath(__file__)) + "/UI/hardware_select.ui")[0]

class HardwareSelectDialog(QtWidgets.QDialog, hardware_select_uic):
    def __init__(self, parent, mode, hardware, ip, serial, interface, daughterboard):
        """ First thing that executes.
        """
        #super(HardwareSelectDialog, self).__init__(parent)  # Same thing as the line below
        QtWidgets.QDialog.__init__(self,parent)
        self.parent = parent
        self.setupUi(self)

        # Prevent Resizing/Maximizing
        self.setFixedSize(965, 115)

        # Do SIGNAL/Slots Connections
        self._connectSlots()

        # Update Display
        self.label2_mode.setText(mode)
        self.label2_probe.setVisible(False)
        self._slotHardwareChanged()

        if hardware == "Computer":
            self.comboBox_hardware.setCurrentIndex(0)
        elif hardware == "USRP X3x0":
            self.comboBox_hardware.setCurrentIndex(1)
        elif hardware == "USRP B2x0":
            self.comboBox_hardware.setCurrentIndex(2)
        elif hardware == "HackRF":
            self.comboBox_hardware.setCurrentIndex(3)
        elif hardware == "RTL2832U":
            self.comboBox_hardware.setCurrentIndex(4)
        elif hardware == "802.11x Adapter":
            self.comboBox_hardware.setCurrentIndex(5)
        elif hardware == "USRP B20xmini":
            self.comboBox_hardware.setCurrentIndex(6)
        elif hardware == "LimeSDR":
            self.comboBox_hardware.setCurrentIndex(7)
        elif hardware == "bladeRF":
            self.comboBox_hardware.setCurrentIndex(8)
        elif hardware == "Open Sniffer":
            self.comboBox_hardware.setCurrentIndex(9)
        elif hardware == "PlutoSDR":
            self.comboBox_hardware.setCurrentIndex(10)
        elif hardware == "USRP2":
            self.comboBox_hardware.setCurrentIndex(11)
        elif hardware == "USRP N2xx":
            self.comboBox_hardware.setCurrentIndex(12)
        elif hardware == "bladeRF 2.0":
            self.comboBox_hardware.setCurrentIndex(13)

        self.textEdit_ip.setPlainText(ip)
        self.textEdit_ip.setAlignment(QtCore.Qt.AlignCenter)
        self.textEdit_serial.setPlainText(serial)
        self.textEdit_serial.setAlignment(QtCore.Qt.AlignCenter)
        self.textEdit_interface.setPlainText(interface)
        self.textEdit_interface.setAlignment(QtCore.Qt.AlignCenter)

        if "CBX-120" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(0)
        elif "SBX-120" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(1)
        elif "UBX-160" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(2)
        elif "WBX-120" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(3)
        elif "TwinRX" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(4)
        elif "XCVR2450" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(5)
        elif "DBSRX" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(6)
        elif "SBX-40" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(7)
        elif "UBX-40" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(8)
        elif "WBX-40" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(9)
        elif "CBX-40" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(10)
        elif "LFRX" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(11)
        elif "LFTX" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(12)
        elif "BasicRX" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(13)
        elif "BasicTX" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(14)
        elif "TVRX2" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(15)
        elif "RFX400" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(16)
        elif "RFX900" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(17)
        elif "RFX1200" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(18)
        elif "RFX1800" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(19)
        elif "RFX2400" in daughterboard:
            self.comboBox_daughterboard.setCurrentIndex(20)

    def _connectSlots(self):
        """ Contains the connect functions for all the signals and slots
        """
        # Push Buttons
        self.pushButton_ok.clicked.connect(self._slotOK_Clicked)
        self.pushButton_cancel.clicked.connect(self._slotCancelClicked)
        self.pushButton_guess.clicked.connect(self._slotGuessClicked)
        self.pushButton_probe_usrp.clicked.connect(self._slotProbeClicked)
        self.pushButton_apply_to_all.clicked.connect(self._slotApplyToAllClicked)

        # Combo Boxes
        self.comboBox_hardware.currentIndexChanged.connect(self._slotHardwareChanged)

    def _slotOK_Clicked(self):
        """ Save hardware select changes and closes the window.
        """
        if "TSI" in self.label2_mode.text():
            self.parent.dashboard_settings_dictionary['hardware_tsi'] = str(self.comboBox_hardware.currentText())
            self.parent.dashboard_settings_dictionary['hardware_ip_tsi'] = str(self.textEdit_ip.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_serial_tsi'] = str(self.textEdit_serial.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_interface_tsi'] = str(self.textEdit_interface.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_daughterboard_tsi'] = str(self.comboBox_daughterboard.currentText())
            self.parent.configureTSI_Hardware()

        elif "PD" in self.label2_mode.text():
            self.parent.dashboard_settings_dictionary['hardware_pd'] = str(self.comboBox_hardware.currentText())
            self.parent.dashboard_settings_dictionary['hardware_ip_pd'] = str(self.textEdit_ip.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_serial_pd'] = str(self.textEdit_serial.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_interface_pd'] = str(self.textEdit_interface.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_daughterboard_pd'] = str(self.comboBox_daughterboard.currentText())
            self.parent.configurePD_Hardware()

        elif "Attack" in self.label2_mode.text():
            self.parent.dashboard_settings_dictionary['hardware_attack'] = str(self.comboBox_hardware.currentText())
            self.parent.dashboard_settings_dictionary['hardware_ip_attack'] = str(self.textEdit_ip.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_serial_attack'] = str(self.textEdit_serial.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_interface_attack'] = str(self.textEdit_interface.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_daughterboard_attack'] = str(self.comboBox_daughterboard.currentText())
            self.parent.configureAttackHardware()

        elif "IQ" in self.label2_mode.text():
            self.parent.dashboard_settings_dictionary['hardware_iq'] = str(self.comboBox_hardware.currentText())
            self.parent.dashboard_settings_dictionary['hardware_ip_iq'] = str(self.textEdit_ip.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_serial_iq'] = str(self.textEdit_serial.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_interface_iq'] = str(self.textEdit_interface.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_daughterboard_iq'] = str(self.comboBox_daughterboard.currentText())
            self.parent.configureIQ_Hardware()

        elif "Archive" in self.label2_mode.text():
            self.parent.dashboard_settings_dictionary['hardware_archive'] = str(self.comboBox_hardware.currentText())
            self.parent.dashboard_settings_dictionary['hardware_ip_archive'] = str(self.textEdit_ip.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_serial_archive'] = str(self.textEdit_serial.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_interface_archive'] = str(self.textEdit_interface.toPlainText())
            self.parent.dashboard_settings_dictionary['hardware_daughterboard_archive'] = str(self.comboBox_daughterboard.currentText())
            self.parent.configureArchiveHardware()

        self.accept()

    def _slotCancelClicked(self):
        """ Does not save hardware select changes and closes the window.
        """
        self.accept()

    def _slotGuessClicked(self):
        """ Guesses the IP address, serial number, interface, and daughterboard for the current hardware setup.
        """
        if str(self.comboBox_hardware.currentText()) == "Computer":
            pass
        elif str(self.comboBox_hardware.currentText()) == "USRP X3x0":
            self.parent.findX3x0(self.textEdit_ip, self.textEdit_serial, self.comboBox_daughterboard, self.label2_probe)
        elif str(self.comboBox_hardware.currentText()) == "USRP B2x0":
            self.parent.findB2x0(self.textEdit_serial)
        elif str(self.comboBox_hardware.currentText()) == "HackRF":
            self.parent.findHackRF(self.textEdit_serial)
        elif str(self.comboBox_hardware.currentText()) == "RTL2832U":
            pass
        elif str(self.comboBox_hardware.currentText()) == "802.11x Adapter":
            self.parent.find80211x(self.textEdit_interface)
        elif str(self.comboBox_hardware.currentText()) == "USRP B20xmini":
            self.parent.findB20xmini(self.textEdit_serial)
        elif str(self.comboBox_hardware.currentText()) == "LimeSDR":
            self.parent.findLimeSDR(self.textEdit_serial)
        elif str(self.comboBox_hardware.currentText()) == "bladeRF":
            self.parent.find_bladeRF2(self.textEdit_serial)
        elif str(self.comboBox_hardware.currentText()) == "Open Sniffer":
            pass
        elif str(self.comboBox_hardware.currentText()) == "PlutoSDR":
            self.parent.findPlutoSDR(self.textEdit_ip)
        elif str(self.comboBox_hardware.currentText()) == "USRP2":
            self.parent.findUSRP2(self.textEdit_ip, self.textEdit_serial, self.comboBox_daughterboard, self.label2_probe)
        elif str(self.comboBox_hardware.currentText()) == "USRP N2xx":
            self.parent.findUSRP_N2xx(self.textEdit_ip, self.textEdit_serial, self.comboBox_daughterboard, self.label2_probe)
        elif str(self.comboBox_hardware.currentText()) == "bladeRF 2.0":
            self.parent.find_bladeRF2(self.textEdit_serial)

    def _slotProbeClicked(self):
        """ Opens a message box and copies the results of "uhd_usrp_probe xxx.xxx.xxx.xxx"
        """
        if str(self.comboBox_hardware.currentText()) == "USRP X3x0":
            # Get IP Address
            get_ip = str(self.textEdit_ip.toPlainText())

            # Probe
            try:
                self.label2_probe.setVisible(True)
                QtWidgets.QApplication.processEvents()
                proc = subprocess.Popen('uhd_usrp_probe --args="addr=' + get_ip + '" &', shell=True, stdout=subprocess.PIPE, )
                output = proc.communicate()[0].decode()
                self.label2_probe.setVisible(False)
            except:
                self.label2_probe.setVisible(False)
                output = "Error"

            # Create a Dialog Window
            msgBox = MyMessageBox(my_text = output)
            msgBox.exec_()

        elif (str(self.comboBox_hardware.currentText()) == "USRP B2x0") or (str(self.comboBox_hardware.currentText()) == "USRP B20xmini"):
            # Probe
            try:
                self.label2_probe.setVisible(True)
                QtWidgets.QApplication.processEvents()
                proc = subprocess.Popen('uhd_usrp_probe --args="type=b200" &', shell=True, stdout=subprocess.PIPE, )
                output = proc.communicate()[0].decode()
                self.label2_probe.setVisible(False)
            except:
                self.label2_probe.setVisible(False)
                output = "Error"

            # Create a Dialog Window
            msgBox = MyMessageBox(my_text = output)
            msgBox.exec_()

        elif (str(self.comboBox_hardware.currentText()) == "bladeRF"):
            # Probe
            try:
                self.label2_probe.setVisible(True)
                QtWidgets.QApplication.processEvents()
                proc=subprocess.Popen('bladeRF-cli -p &', shell=True, stdout=subprocess.PIPE, )
                output=proc.communicate()[0].decode()
                self.label2_probe.setVisible(False)
            except:
                self.label2_probe.setVisible(False)
                output = "Error"

            # Create a Dialog Window
            msgBox = MyMessageBox(my_text = output, height = 140, width = 400)
            msgBox.exec_()

        elif (str(self.comboBox_hardware.currentText()) == "LimeSDR"):
            # Probe
            try:
                self.label2_probe.setVisible(True)
                QtWidgets.QApplication.processEvents()
                proc=subprocess.Popen('LimeUtil --find &', shell=True, stdout=subprocess.PIPE, )
                output=proc.communicate()[0].decode()
                self.label2_probe.setVisible(False)
            except:
                self.label2_probe.setVisible(False)
                output = "Error"

            # Create a Dialog Window
            msgBox = MyMessageBox(my_text = output, height = 75, width = 700)
            msgBox.exec_()

        elif (str(self.comboBox_hardware.currentText()) == "HackRF"):
            # Probe
            try:
                self.label2_probe.setVisible(True)
                QtWidgets.QApplication.processEvents()
                proc=subprocess.Popen('hackrf_info &', shell=True, stdout=subprocess.PIPE, )
                output=proc.communicate()[0].decode()
                self.label2_probe.setVisible(False)
            except:
                self.label2_probe.setVisible(False)
                output = "Error"

            # Create a Dialog Window
            msgBox = MyMessageBox(my_text = output, height = 300, width = 500)
            msgBox.exec_()

        elif (str(self.comboBox_hardware.currentText()) == "PlutoSDR"):
            # Probe
            try:
                self.label2_probe.setVisible(True)
                QtWidgets.QApplication.processEvents()
                proc=subprocess.Popen('iio_info -n pluto.local &', shell=True, stdout=subprocess.PIPE, )
                output=proc.communicate()[0].decode()
                self.label2_probe.setVisible(False)
            except:
                self.label2_probe.setVisible(False)
                output = "Error"

        elif str(self.comboBox_hardware.currentText()) == "USRP2":
            # Get IP Address
            get_ip = str(self.textEdit_ip.toPlainText())

            # Probe
            try:
                self.label2_probe.setVisible(True)
                QtWidgets.QApplication.processEvents()
                proc = subprocess.Popen('uhd_usrp_probe --args="addr=' + get_ip + '" &', shell=True, stdout=subprocess.PIPE, )
                output = proc.communicate()[0].decode()
                self.label2_probe.setVisible(False)
            except:
                self.label2_probe.setVisible(False)
                output = "Error"

        elif str(self.comboBox_hardware.currentText()) == "USRP N2xx":
            # Get IP Address
            get_ip = str(self.textEdit_ip.toPlainText())

            # Probe
            try:
                self.label2_probe.setVisible(True)
                QtWidgets.QApplication.processEvents()
                proc = subprocess.Popen('uhd_usrp_probe --args="addr=' + get_ip + '" &', shell=True, stdout=subprocess.PIPE, )
                output = proc.communicate()[0].decode()
                self.label2_probe.setVisible(False)
            except:
                self.label2_probe.setVisible(False)
                output = "Error"

            # Create a Dialog Window
            msgBox = MyMessageBox(my_text = output, height = 600, width = 900)
            msgBox.exec_()

        elif (str(self.comboBox_hardware.currentText()) == "bladeRF 2.0"):
            # Probe
            try:
                self.label2_probe.setVisible(True)
                QtWidgets.QApplication.processEvents()
                proc=subprocess.Popen('bladeRF-cli -p &', shell=True, stdout=subprocess.PIPE, )
                output=proc.communicate()[0].decode()
                self.label2_probe.setVisible(False)
            except:
                self.label2_probe.setVisible(False)
                output = "Error"

            # Create a Dialog Window
            msgBox = MyMessageBox(my_text = output, height = 140, width = 400)
            msgBox.exec_()

    def _slotHardwareChanged(self):
        """ Updates display options for selected hardware.
        """
        # Clear Text
        self.textEdit_ip.setPlainText("")
        self.textEdit_serial.setPlainText("")		
        self.textEdit_interface.setPlainText("")
        self.textEdit_ip.setAlignment(QtCore.Qt.AlignCenter)
        self.textEdit_serial.setAlignment(QtCore.Qt.AlignCenter)
        self.textEdit_interface.setAlignment(QtCore.Qt.AlignCenter)

        # Set Visibility
        if str(self.comboBox_hardware.currentText()) == "Computer":
            self.textEdit_ip.setVisible(False)
            self.textEdit_serial.setVisible(False)
            self.pushButton_guess.setVisible(False)     	
            self.pushButton_probe_usrp.setVisible(False)
            self.textEdit_interface.setVisible(False)
            self.comboBox_daughterboard.setVisible(False)
        elif str(self.comboBox_hardware.currentText()) == "USRP X3x0":
            self.textEdit_ip.setVisible(True)
            self.textEdit_serial.setVisible(True)		
            self.pushButton_guess.setVisible(True)
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)	
            self.comboBox_daughterboard.setVisible(True)
        elif str(self.comboBox_hardware.currentText()) == "USRP B2x0":
            self.textEdit_ip.setVisible(False)
            self.textEdit_serial.setVisible(True)
            self.pushButton_guess.setVisible(True)
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)
            self.comboBox_daughterboard.setVisible(False)
        elif str(self.comboBox_hardware.currentText()) == "HackRF":
            self.textEdit_ip.setVisible(False)
            self.textEdit_serial.setVisible(True)
            self.pushButton_guess.setVisible(True)
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)
            self.comboBox_daughterboard.setVisible(False)
        elif str(self.comboBox_hardware.currentText()) == "RTL2832U":
            self.textEdit_ip.setVisible(False)
            self.textEdit_serial.setVisible(False)
            self.pushButton_guess.setVisible(False)
            self.pushButton_probe_usrp.setVisible(False)
            self.textEdit_interface.setVisible(False)
            self.comboBox_daughterboard.setVisible(False)
        elif str(self.comboBox_hardware.currentText()) == "802.11x Adapter":
            self.textEdit_ip.setVisible(False)
            self.textEdit_serial.setVisible(False)
            self.pushButton_guess.setVisible(True)     	
            self.pushButton_probe_usrp.setVisible(False)
            self.textEdit_interface.setVisible(True)
            self.comboBox_daughterboard.setVisible(False)
        elif str(self.comboBox_hardware.currentText()) == "USRP B20xmini":
            self.textEdit_ip.setVisible(False)
            self.textEdit_serial.setVisible(True)
            self.pushButton_guess.setVisible(True)
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)
            self.comboBox_daughterboard.setVisible(False)
        elif str(self.comboBox_hardware.currentText()) == "LimeSDR":
            self.textEdit_ip.setVisible(False)
            self.textEdit_serial.setVisible(True)
            self.pushButton_guess.setVisible(True)
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)
            self.comboBox_daughterboard.setVisible(False)
        elif str(self.comboBox_hardware.currentText()) == "bladeRF":
            self.textEdit_ip.setVisible(False)
            self.textEdit_serial.setVisible(True)
            self.pushButton_guess.setVisible(True)
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)
            self.comboBox_daughterboard.setVisible(False)
        elif str(self.comboBox_hardware.currentText()) == "Open Sniffer":
            self.textEdit_ip.setVisible(True)
            self.textEdit_serial.setVisible(False)
            self.pushButton_guess.setVisible(True)     	
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)
            self.comboBox_daughterboard.setVisible(False)
        elif str(self.comboBox_hardware.currentText()) == "PlutoSDR":
            self.textEdit_ip.setVisible(True)
            self.textEdit_serial.setVisible(False)
            self.pushButton_guess.setVisible(True)     	
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)
            self.comboBox_daughterboard.setVisible(False)
        elif str(self.comboBox_hardware.currentText()) == "USRP2":
            self.textEdit_ip.setVisible(True)
            self.textEdit_serial.setVisible(True)		
            self.pushButton_guess.setVisible(True)
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)	
            self.comboBox_daughterboard.setVisible(True)
        elif str(self.comboBox_hardware.currentText()) == "USRP N2xx":
            self.textEdit_ip.setVisible(True)
            self.textEdit_serial.setVisible(True)		
            self.pushButton_guess.setVisible(True)
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)	
            self.comboBox_daughterboard.setVisible(True)
        elif str(self.comboBox_hardware.currentText()) == "bladeRF 2.0":
            self.textEdit_ip.setVisible(False)
            self.textEdit_serial.setVisible(True)
            self.pushButton_guess.setVisible(True)
            self.pushButton_probe_usrp.setVisible(True)
            self.textEdit_interface.setVisible(False)
            self.comboBox_daughterboard.setVisible(False)

    def _slotApplyToAllClicked(self):
        """ Save the current radio settings to all components.
        """
        # Save for All Four Components
        self.parent.dashboard_settings_dictionary['hardware_tsi'] = str(self.comboBox_hardware.currentText())
        self.parent.dashboard_settings_dictionary['hardware_ip_tsi'] = str(self.textEdit_ip.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_serial_tsi'] = str(self.textEdit_serial.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_interface_tsi'] = str(self.textEdit_interface.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_daughterboard_tsi'] = str(self.comboBox_daughterboard.currentText())
        self.parent.configureTSI_Hardware()

        self.parent.dashboard_settings_dictionary['hardware_pd'] = str(self.comboBox_hardware.currentText())
        self.parent.dashboard_settings_dictionary['hardware_ip_pd'] = str(self.textEdit_ip.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_serial_pd'] = str(self.textEdit_serial.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_interface_pd'] = str(self.textEdit_interface.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_daughterboard_pd'] = str(self.comboBox_daughterboard.currentText())
        self.parent.pushButton_top_pd.setToolTip(self.parent.dashboard_settings_dictionary['hardware_pd'])
        self.parent.configurePD_Hardware()

        self.parent.dashboard_settings_dictionary['hardware_attack'] = str(self.comboBox_hardware.currentText())
        self.parent.dashboard_settings_dictionary['hardware_ip_attack'] = str(self.textEdit_ip.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_serial_attack'] = str(self.textEdit_serial.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_interface_attack'] = str(self.textEdit_interface.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_daughterboard_attack'] = str(self.comboBox_daughterboard.currentText())
        self.parent.pushButton_top_attack.setToolTip(self.parent.dashboard_settings_dictionary['hardware_attack'])
        self.parent.configureAttackHardware()

        self.parent.dashboard_settings_dictionary['hardware_iq'] = str(self.comboBox_hardware.currentText())
        self.parent.dashboard_settings_dictionary['hardware_ip_iq'] = str(self.textEdit_ip.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_serial_iq'] = str(self.textEdit_serial.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_interface_iq'] = str(self.textEdit_interface.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_daughterboard_iq'] = str(self.comboBox_daughterboard.currentText())
        self.parent.pushButton_top_iq.setToolTip(self.parent.dashboard_settings_dictionary['hardware_iq'])
        self.parent.configureIQ_Hardware()

        self.parent.dashboard_settings_dictionary['hardware_archive'] = str(self.comboBox_hardware.currentText())
        self.parent.dashboard_settings_dictionary['hardware_ip_archive'] = str(self.textEdit_ip.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_serial_archive'] = str(self.textEdit_serial.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_interface_archive'] = str(self.textEdit_interface.toPlainText())
        self.parent.dashboard_settings_dictionary['hardware_daughterboard_archive'] = str(self.comboBox_daughterboard.currentText())
        self.parent.pushButton_top_archive.setToolTip(self.parent.dashboard_settings_dictionary['hardware_archive'])
        self.parent.configureArchiveHardware()

        self.accept()