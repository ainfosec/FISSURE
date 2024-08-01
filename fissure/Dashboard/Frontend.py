from .Signals import DashboardSignals
from fissure.Dashboard.Backend import DashboardBackend
from fissure.Dashboard.Slots import (
    ArchiveTabSlots,
    AttackTabSlots,
    AutomationTabSlots,
    DashboardSlots,
    IQDataTabSlots,
    LibraryTabSlots,
    LogTabSlots,
    MenuBarSlots,
    PDTabSlots,
    SensorNodesTabSlots,
    StatusBarSlots,
    TopBarSlots,
    TSITabSlots,
)

from fissure.Dashboard.UI_Components import FissureStatusBar, UI_Types
from fissure.Dashboard.UI_Components.MPL import MPL_IQCanvas, MPLCanvas, MPLTuningCanvas
from fissure.Dashboard.UI_Components.Qt5 import (
    CustomColor,
    JointPlotDialog,
    MiscChooser,
    MyMessageBox,
    MyPlotWindow,
    NewSOI,
    OperationsThread,
    OptionsDialog,
    SigMF_Dialog,
    TreeModel,
    TreeNode,
    TrimSettings,
)
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT
from PyQt5 import QtCore, QtGui, QtWidgets, uic

import asyncio
import datetime
import fissure.comms
import fissure.Server
import fissure.utils
import logging
import numpy
import os
import qasync
import time
import signal
import json
import random

# Base Window Size
WINDOW_WIDTH = 1280
WINDOW_HEIGHT = 1024


class Dashboard(QtWidgets.QMainWindow):
    backend: DashboardBackend
    logger: logging.Logger = fissure.utils.get_logger(f"{fissure.comms.Identifiers.DASHBOARD}.frontend")
    ui: object
    signals: DashboardSignals
    popups = {}
    active_sensor_node: int

    def __init__(self, parent: QtWidgets.QWidget = None):
        self.logger.info("=== INITIALIZING ===")

        super().__init__(parent)
        self.__init_window__()

        # Initialize signals
        self.__init_signals__()

        # Create Backend
        self.backend = DashboardBackend(frontend=self)
        self.backend.start()

        self.server_process = None

        # Closing Variables
        self.all_closed_down = False

        # Start on Welcome Screen
        self.load_screen(DashboardScreen, self)
        self.load_MPL_components()

        # Status Bar and Status Dialog
        self.setStatusBar(FissureStatusBar(self))
        self.statusbar_text = [
            ["", "", "", "", "", "", ""],
            ["", "", "", "", "", "", ""],
            ["", "", "", "", "", "", ""],
            ["", "", "", "", "", "", ""],
            ["", "", "", "", "", "", ""],
        ]

        # Disable Buttons for Disconnected HIPRFISR
        self.ui.pushButton_top_node2.setVisible(False)
        self.ui.pushButton_top_node3.setVisible(False)
        self.ui.pushButton_top_node4.setVisible(False)
        self.ui.pushButton_top_node5.setVisible(False)
        self.ui.pushButton_top_node1.setEnabled(False)
        self.ui.tabWidget.setEnabled(False)
        self.ui.pushButton_automation_system_start.setEnabled(False)

        # Light/Dark Mode Style Sheets
        if self.backend.settings["color_mode"] == "Dark Mode":
            MenuBarSlots.setStyleSheet(self, "dark")
        elif self.backend.settings["color_mode"] == "Custom Mode":
            MenuBarSlots.setStyleSheet(self, "custom")
        else:
            MenuBarSlots.setStyleSheet(self, "light")

        # Remember Configuration
        if self.backend.settings["remember_configuration"] == True:
            self.window.actionRemember_Configuration.setChecked(True)
        else:
            self.window.actionRemember_Configuration.setChecked(False)

        # Load FISSURE Logo
        self.ui.label_diagram.setPixmap(QtGui.QPixmap(os.path.join(fissure.utils.UI_DIR, "Icons", "logo.png")))

        # Initialize Tabs
        TopBarSlots.sensor_node_rightClick(self, -1)
        self.__init_Automation__()
        self.__init_TSI__()
        self.__init_PD__()
        self.__init_Attack__()
        self.__init_IQ__()
        self.__init_Archive__()
        self.__init_Sensor_Nodes__()
        self.__init_Library__()

        # Auto Connect HIPRFISR
        if self.backend.settings["auto_connect_hiprfisr"] == True:
            self.window.actionAuto_Connect_HIPRFISR.setChecked(True)
            StatusBarSlots.startLocalSession(self)
        else:
            self.window.actionAuto_Connect_HIPRFISR.setChecked(False)

        self.logger.info("=== READY ===")


    def __init_Automation__(self):
        """
        Initializes Automation Tab on Dashboard launch.
        """
        # Load and Apply Automation Mode Settings
        if self.backend.settings['startup_automation_mode'] == 'Discovery':
            AutomationTabSlots._slotAutomationDiscoveryClicked(self)
        elif self.backend.settings['startup_automation_mode'] == 'Target':
            AutomationTabSlots._slotAutomationTargetClicked(self)
        elif self.backend.settings['startup_automation_mode'] == 'Manual':
            AutomationTabSlots._slotAutomationManualClicked(self)
        else:
            AutomationTabSlots._slotAutomationCustomClicked(self)

        # Get Protocols
        protocols = fissure.utils.library.getProtocols(self.backend.library)

        # Load Target Protocol Protocols
        self.ui.comboBox_automation_target_protocol.addItems(sorted(protocols))

        # Set up SOI List Priority Table
        self.ui.label2_soi_priority_row2.setVisible(False)
        self.ui.label2_soi_priority_row3.setVisible(False)

        new_combobox1 = QtWidgets.QComboBox(self, objectName='comboBox2_')
        self.ui.tableWidget_automation_soi_list_priority.setCellWidget(0,0,new_combobox1)
        new_combobox1.addItem("Power")
        new_combobox1.addItem("Frequency")
        new_combobox1.addItem("Modulation")
        new_combobox1.currentIndexChanged.connect(lambda: AutomationTabSlots._slotSOI_PriorityCategoryChanged(self))
        new_combobox1.setCurrentIndex(0)

        new_combobox2 = QtWidgets.QComboBox(self, objectName='comboBox2_')
        self.ui.tableWidget_automation_soi_list_priority.setCellWidget(0,1,new_combobox2)
        new_combobox2.addItem("Highest")
        new_combobox2.addItem("Lowest")
        new_combobox2.addItem("Nearest to")
        new_combobox2.addItem("Greater than")
        new_combobox2.addItem("Less than")

        empty_item1 = QtWidgets.QTableWidgetItem("")
        self.ui.tableWidget_automation_soi_list_priority.setItem(0,2,empty_item1)

        self.ui.tableWidget_automation_soi_list_priority.resizeColumnsToContents()
        self.ui.tableWidget_automation_soi_list_priority.resizeRowsToContents()


    def __init_TSI__(self):
        """
        Initializes TSI Tabs on Dashboard launch.
        """
        ##### TSI #####
        self.ui.textEdit_tsi_detector_iq_file_frequency.setPlainText("2400e6")
        self.ui.textEdit_tsi_detector_iq_file_sample_rate.setPlainText("20e6")
        self.ui.textEdit_tsi_detector_fixed_frequency.setPlainText("2412")

        self.target_soi = []

        # Create Preset Dictionary
        self.preset_dictionary = {}
        self.preset_count = 0

        # Create SOI Blacklist
        self.soi_blacklist = []

        # Resize Table Columns and Rows for SDR Configuration Tables
        self.ui.tableWidget_tsi_scan_options.resizeColumnsToContents()
        self.ui.tableWidget_tsi_scan_options.resizeRowsToContents()
        self.ui.tableWidget_tsi_scan_options.horizontalHeader().setFixedHeight(20)

        # Resize Table Columns for Wideband and Narrowband Tables
        self.ui.tableWidget1_tsi_wideband.resizeColumnsToContents()

        # Put the Labels on Top of the Plots
        self.ui.label2_tsi_detector.raise_()

        # Hide Update Configuration Label
        self.ui.label2_tsi_update_configuration.setVisible(False)

        # Tab Width
        # self.tabWidget_tsi_configuration.setStyleSheet("QTabBar::tab { height: 30px; width: 130px;}")

        # Axes Configuration for Detector Widget
        self.wideband_zoom = False
        self.wideband_zoom_start = 0
        self.wideband_zoom_end = 6000e6

        # Under Construction Labels (For Future Reference)
        # self.ui.label_under_construction2.setPixmap(
        #     QtGui.QPixmap(os.path.join(fissure.utils.UI_DIR, "Icons", "under_construction.png"))  
        # )

        # Create Tooltip
        self.ui.tabWidget.setTabToolTip(1, "Target Signal Identification")

        # Update Detector Settings
        TSITabSlots._slotTSI_DetectorChanged(self)

        # Default Detector Simulator File
        self.ui.textEdit_tsi_detector_csv_file.setPlainText(
            os.path.join(fissure.utils.TOOLS_DIR, "TSI_Detector_Sim_Data", "tsi_simulator.csv")
        )

        # Set Conditioner Prefix
        now = datetime.datetime.now()
        self.ui.textEdit_tsi_conditioner_settings_prefix.setPlainText(
            now.strftime("%Y-%m-%d %H:%M:%S").replace(" ", "_") + "_"
        )

        # Set Conditioner Default Directories
        self.ui.comboBox_tsi_conditioner_input_folders.addItem(
            str(os.path.join(fissure.utils.FISSURE_ROOT, "Conditioner Data", "Input"))
        )
        self.ui.comboBox_tsi_conditioner_settings_folder.addItem(
            str(os.path.join(fissure.utils.FISSURE_ROOT, "Conditioner Data", "Output"))
        )
        self.ui.comboBox_tsi_fe_input_folders.addItem(
            str(os.path.join(fissure.utils.FISSURE_ROOT, "Conditioner Data", "Output"))
        )

        # Complete Feature List
        self.all_features = [
            "Mean",
            "Max",
            "Peak",
            "Peak to Peak",
            "RMS",
            "Variance",
            "Standard Deviation",
            "Power",
            "Crest Factor",
            "Pulse Indicator",
            "Margin",
            "Kurtosis",
            "Skewness",
            "Zero Crossings",
            "Samples",
            "Mean of Band Power Spectrum",
            "Max of Band Power Spectrum",
            "Sum of Total Band Power",
            "Peak of Band Power",
            "Standard Deviation of Band Power",
            "Variance of Band Power",
            "Skewness of Band Power",
            "Kurtosis of Band Power",
            "Relative Spectral Peak per Band",
        ]

        # Defaults
        TSITabSlots._slotTSI_FE_SettingsCategoryChanged(self)
        TSITabSlots._slotTSI_FE_SettingsClassificationChanged(self)
        TSITabSlots._slotTSI_ClassifierTrainingCategoryChanged(self)
        TSITabSlots._slotTSI_ClassifierTrainingTechniqueChanged(self)   
        TSITabSlots._slotTSI_ClassifierClassificationCategoryChanged(self)
        TSITabSlots._slotTSI_ClassifierClassificationTechniqueChanged(self)


    def __init_PD__(self):
        """
        Initializes PD Tabs on Dashboard launch.
        """
        ##### Protocol Discovery #####
        self.ui.textEdit_pd_status_min_buffer_size.setPlainText("100")
        self.ui.textEdit_pd_status_buffer_size.setPlainText("262144")
        self.ui.textEdit_pd_status_ip_address.setPlainText("172.16.15.37")
        self.ui.textEdit_pd_status_port.setPlainText("5066")
        self.ui.textEdit_pd_flow_graphs_frequency_margin.setPlainText("0")
        self.ui.textEdit_pd_flow_graphs_bandwidth_margin.setPlainText("0")
        self.ui.textEdit_pd_flow_graphs_start_frequency_margin.setPlainText("0")
        self.ui.textEdit_pd_flow_graphs_end_frequency_margin.setPlainText("0")
        self.ui.textEdit_pd_sniffer_netcat_ip.setPlainText("127.0.0.1")
        self.ui.textEdit_pd_sniffer_netcat_port.setPlainText("55555")

        # Create Tooltip
        self.ui.tabWidget.setTabToolTip(2, "Protocol Discovery")

        # Disable the Tabs
        self.ui.tabWidget_protocol.setTabEnabled(1, False)
        self.ui.tabWidget_protocol.setTabEnabled(2, False)
        # self.ui.tabWidget_protocol.setTabEnabled(3,False)
        # self.ui.tabWidget_protocol.setTabEnabled(4,False)
        # self.ui.tabWidget_protocol.setTabEnabled(5,False)
        # self.ui.tabWidget_protocol.setTabEnabled(6,False)
        # self.ui.tabWidget_protocol.setTabEnabled(7,False)

        # Configure PD\Construct Packet Tables
        self.ui.tableWidget_pd_dissectors.resizeRowsToContents()

        # Get Protocols
        protocols = fissure.utils.library.getProtocols(self.backend.library)

        # Load Protocols into Dissectors Protocol Combobox
        self.ui.comboBox_pd_dissectors_protocol.insertItem(0, "")
        protocols_with_packet_types = []
        for p in protocols:
            if len(fissure.utils.library.getPacketTypes(self.backend.library, p)) > 0:
                protocols_with_packet_types.append(p)
        self.ui.comboBox_pd_dissectors_protocol.addItems(sorted(protocols_with_packet_types))

        # Hide the Dissectors Groupbox
        self.ui.frame_pd_dissectors_editor.setVisible(False)

        # Set the Number of Lines in PD Status Message Text Edit
        self.ui.textEdit2_pd_status.document().setMaximumBlockCount(18)

        # Resize Protocol Discovery Bit Slicing Preamble Stats Table
        self.ui.tableWidget_pd_bit_slicing_preamble_stats.setColumnWidth(1, 97)
        self.ui.tableWidget_pd_bit_slicing_preamble_stats.setColumnWidth(2, 111)
        self.ui.tableWidget_pd_bit_slicing_preamble_stats.setColumnWidth(3, 111)
        self.ui.tableWidget_pd_bit_slicing_preamble_stats.setColumnWidth(4, 121)
        self.ui.tableWidget_pd_bit_slicing_preamble_stats.horizontalHeader().setSectionResizeMode(
            0, QtWidgets.QHeaderView.Stretch
        )

        # Resize Protocol Discovery Bit Slicing Recommended Preamble Table
        # ~ self.tableWidget_pd_bit_slicing_candidate_preambles.setColumnWidth(1,97)
        # ~ self.tableWidget_pd_bit_slicing_candidate_preambles.setColumnWidth(2,111)
        # ~ self.tableWidget_pd_bit_slicing_candidate_preambles.setColumnWidth(3,111)
        # ~ self.tableWidget_pd_bit_slicing_candidate_preambles.setColumnWidth(4,121)
        # ~ self.tableWidget_pd_bit_slicing_candidate_preambles.horizontalHeader().setSectionResizeMode(0,QtWidgets.QHeaderView.Stretch)

        # Set the PD Flow Graph Lookup Not Found Label
        self.ui.label2_pd_flow_graphs_lookup_not_found.setText("")

        # Hide the Calculating Label
        self.ui.label2_pd_bit_slicing_calculating.setVisible(False)

        # # Load "All Flow Graphs" List Widget
        # self._slotPD_DemodHardwareChanged()

        # Bit Slicing Shift Counter
        self.bit_shift_counter = 0
        self.bit_slicing_column_type = []
        self.first_n_packets = None
        self.median_slicing_results = None
        self.candidate_preamble_data = None
        self.suitable_colors = [(204,255,255), (153,255,255), (102,255,255), (51,255,255), (0,255,255), (153,204,255), (153,204,204), \
                           (102,255,204), (102,255,153), (51,255,204), (0,255,204), (0,255,153), \
                           (204,204,153), (204,204,102), (204,204,255), (204,153,102), (204,153,51), (204,204,51), (204,204,0), \
                           (204,255,153), (153,255,204), (153,255,153), (204,255,102), (153,204,153), (51,255,153), (51,255,51), (51,255,102), (0,204,102), (102,204,153), (153,204,102), (204,255,51), (153,255,102), (153,255,51), (102,255,102), (0,238,00), (0,221,0), \
                           (238,238,238), (221,221,221), (204,204,204), (187,187,187), \
                           (255,204,102), (255,204,51), \
                           (255,204,255), (255,204,204), (255,204,153), (255,204,51), \
                           (204,204,255), \
                           (255,255,204), (255,255,153), (255,255,102), (255,255,51), (255,255,0),(255,153,102)]
        random.shuffle(self.suitable_colors)

        # Hide the Unused Bit Slicing Buttons
        self.ui.pushButton_pd_bit_slicing_detect_fields.setVisible(False)
        self.ui.pushButton_pd_bit_slicing_varying.setVisible(False)
        self.ui.pushButton_pd_bit_slicing_recurrent.setVisible(False)
        self.ui.pushButton_pd_bit_slicing_uniform.setVisible(False)

        # Initialize New Detections/Classifications Notification
        self.new_detections = 0
        self.new_classifications = 0

        # Sniffer Port
        self.ui.label2_pd_sniffer_zmq_port.setText(str(self.backend.settings["pd_bits_port"]))
        self.guess_index = 0

        # Load Sniffer Protocols
        self.ui.comboBox_pd_sniffer_protocols.clear()
        protocols_with_demod_fgs = []
        for p in protocols:
            if len(fissure.utils.library.getDemodulationFlowGraphs(self.backend.library, p, "", "")) > 0:
                protocols_with_demod_fgs.append(p)
        self.ui.comboBox_pd_sniffer_protocols.addItems(sorted(protocols_with_demod_fgs))

        # Load Sniffer Test Folder
        self.ui.comboBox_pd_sniffer_test_folders.addItem(
            str(os.path.join(fissure.utils.FISSURE_ROOT, "Crafted Packets", "Defaults"))
        )
        self.ui.comboBox_pd_sniffer_test_folders.addItem(
            str(os.path.join(fissure.utils.FISSURE_ROOT, "Crafted Packets"))
        )
        self.ui.comboBox_pd_sniffer_test_folders.setCurrentIndex(0)

        # Load Protocols into Combobox
        self.ui.comboBox_pd_bit_viewer_protocols.clear()
        self.ui.comboBox_pd_bit_viewer_protocols.addItem("Raw")
        self.ui.comboBox_pd_bit_viewer_protocols.addItems(sorted(protocols_with_packet_types))

        # Common CRC Algorithms
        self.crc_algorithms8 = [
            "Custom",
            "CRC8",
            "CRC8_CDMA2000",
            "CRC8_DARC",
            "CRC8_DVB-S2",
            "CRC8_EBU",
            "CRC8_I-CODE",
            "CRC8_ITU",
            "CRC8_MAXIM",
            "CRC8_ROHC",
            "CRC8_WCDMA",
        ]
        self.crc_algorithms16 = [
            "Custom",
            "CRC16_CCIT_ZERO",
            "CRC16_ARC",
            "CRC16_AUG_CCITT (Z-Wave)",
            "CRC16_BUYPASS",
            "CRC16_CCITT_FALSE",
            "CRC16_CDMA2000",
            "CRC16_DDS_110",
            "CRC16_DECT_R",
            "CRC16_DECT_X",
            "CRC16_DNP",
            "CRC16_EN_13757",
            "CRC16_GENIBUS",
            "CRC16_MAXIM",
            "CRC16_MCRF4XX",
            "CRC16_RIELLO",
            "CRC16_T10_DIF",
            "CRC16_TELEDISK",
            "CRC16_TMS37157",
            "CRC16_USB",
            "CRC16_A",
            "CRC16_KERMIT",
            "CRC16_MODBUS",
            "CRC16_X_25",
            "CRC16_XMODEM",
        ]
        self.crc_algorithms32 = [
            "Custom",
            "CRC32",
            "CRC32_BZIP2",
            "CRC32_C",
            "CRC32_D",
            "CRC32_MPEG-2",
            "CRC32_POSIX",
            "CRC32-32Q",
            "CRC32_JAMCRC",
            "CRC32_XFER",
        ]
        self.ui.comboBox_pd_crc_common_width.setCurrentIndex(0)
        self.ui.comboBox_pd_crc_reveng_width.setCurrentIndex(0)
        self.ui.textEdit_pd_crc_polynomial_common.setPlainText("00")
        self.ui.textEdit_pd_crc_seed_common.setPlainText("00")
        self.ui.textEdit_pd_crc_final_xor_common.setPlainText("00")
        self.ui.textEdit_pd_crc_input_common.setPlainText("12345678")
        self.ui.textEdit_pd_crc_input_reveng.setPlainText("12345678")
        self.ui.textEdit_pd_crc_seed.setPlainText("0000")
        self.ui.textEdit_pd_crc_final_xor.setPlainText("0000")
        self.ui.textEdit_pd_crc_input1.setPlainText("FFFFFFFF")
        self.ui.textEdit_pd_crc_input2.setPlainText("AAAAAAAA")
        self.ui.textEdit_pd_crc_crc1.setPlainText("99CF")
        self.ui.textEdit_pd_crc_crc2.setPlainText("1E95")
        # self._slotPD_CRC_RevEngAlgorithmChanged()


    def __init_Attack__(self):
        """
        Initializes Attack Tabs on Dashboard launch.
        """
        # #### Attack #####
        self.ui.textEdit_attack_fuzzing_seed.setPlainText("0")
        self.ui.textEdit_attack_fuzzing_interval.setPlainText("1")
        self.ui.textEdit_fuzzing_update_period.setPlainText("1")

        # Get Protocols
        protocols = fissure.utils.library.getProtocols(self.backend.library)

        # Load Protocols into Combobox
        self.ui.comboBox_attack_protocols.clear()
        protocols_with_attacks = []
        for p in protocols:
            if len(fissure.utils.library.getAttacks(self.backend.library, p)) > 0:
                protocols_with_attacks.append(p)
        self.ui.comboBox_attack_protocols.addItems(sorted(protocols_with_attacks))

        # Configure Attack TreeWidget
        self.populateAttackTreeWidget()
        self.ui.treeWidget_attack_attacks.expandAll()
        AttackTabSlots._slotAttackProtocols(self)

        # Select Something in Attack Tree Widget
        self.ui.treeWidget_attack_attacks.setCurrentItem(self.ui.treeWidget_attack_attacks.itemAt(0, 0))

        # For Applying Attack Changes
        self.attack_flow_graph_variables = None

        # Guess Interface Index
        self.guess_index_table = 0

        # List of Dynamic Tables
        self.table_list = []

        # #### Attack - Packet Crafter #####
        self.ui.textEdit_packet_scapy_interval.setPlainText(".1")
        self.ui.textEdit_packet_number_of_messages.setPlainText("1")

        # Load Protocols into Combobox
        self.ui.comboBox_packet_protocols.clear()
        protocols_with_packet_types = []
        for p in protocols:
            if len(fissure.utils.library.getPacketTypes(self.backend.library, p)) > 0:
                protocols_with_packet_types.append(p)
        self.ui.comboBox_packet_protocols.addItems(sorted(protocols_with_packet_types))
        self.scapy_data = None


    def __init_IQ__(self):
        """
        Initializes IQ Tabs on Dashboard launch.
        """
        # #### IQ Data  #####
        self.ui.textEdit_iq_timeslot_sample_rate.setPlainText("20")
        self.ui.textEdit_iq_timeslot_period.setPlainText(".005")
        self.ui.textEdit_iq_timeslot_copies.setPlainText("10")
        self.ui.textEdit_iq_filter_start.setPlainText("100000")
        self.ui.textEdit_iq_filter_end.setPlainText("200000")

        self.ui.textEdit_iq_ofdm_sample_rate.setPlainText("20")
        self.ui.textEdit_iq_ofdm_resample_rate.setPlainText("11.2")
        self.ui.textEdit_iq_ofdm_trigger_level.setPlainText("0.5")
        self.ui.textEdit_iq_ofdm_fft_size.setPlainText("1024")
        self.ui.textEdit_iq_ofdm_cp_length.setPlainText("64")
        self.ui.textEdit_iq_ofdm_phase_adjustment1.setPlainText("0")
        self.ui.textEdit_iq_ofdm_phase_adjustment_cycle_start.setPlainText("-200")
        self.ui.textEdit_iq_ofdm_phase_adjustment_cycle.setPlainText("0")
        self.ui.textEdit_iq_ofdm_phase_adjustment_cycle_end.setPlainText("200")
        self.ui.textEdit_iq_ofdm_subcarrier_start.setPlainText("75")
        self.ui.textEdit_iq_ofdm_subcarrier_skip.setPlainText("3")
        self.ui.textEdit_iq_ofdm_subcarrier_end.setPlainText("511")
        self.ui.textEdit_iq_ofdm_phase_adjustment2.setPlainText("0")
        self.ui.textEdit_iq_ofdm_phase_adjustment_cycle_start2.setPlainText("-200")
        self.ui.textEdit_iq_ofdm_phase_adjustment_cycle2.setPlainText("0")
        self.ui.textEdit_iq_ofdm_phase_adjustment_cycle_end2.setPlainText("200")

        self.ui.textEdit_iq_strip_amplitude.setPlainText(".001")
        self.ui.textEdit_iq_strip_output.setPlainText(str(fissure.utils.IQ_RECORDINGS_DIR))

        # Set up IQ Recording Table
        IQDataTabSlots._slotIQ_TabClicked(self, "pushButton1_iq_tab_record")
        self.iq_file_counter = 0
        self.iq_first_file_name = ""
        self.ui.label_iq_folder.setVisible(False)
        self.iq_plot_range_start = 0
        self.iq_plot_range_end = 0

        new_iq_combobox4 = QtWidgets.QComboBox(self, objectName="comboBox2_")
        self.ui.tableWidget_iq_record.setCellWidget(0, 8, new_iq_combobox4)
        new_iq_combobox4.addItem("Complex")
        # new_iq_combobox4.addItem("Float/Float 32")
        # new_iq_combobox4.addItem("Int/Int 32")
        # new_iq_combobox4.addItem("Short/Int 16")
        # new_iq_combobox4.addItem("Byte/Int 8")
        new_iq_combobox4.setFixedSize(150, 49)
        new_iq_combobox4.setCurrentIndex(0)

        self.ui.tableWidget_iq_record.resizeColumnsToContents()
        self.ui.tableWidget_iq_record.setColumnWidth(0, 300)

        # Set up IQ Playback Table
        new_iq_playback_combobox3 = QtWidgets.QComboBox(self, objectName="comboBox2_")
        self.ui.tableWidget_iq_playback.setCellWidget(0, 5, new_iq_playback_combobox3)
        new_iq_playback_combobox3.addItem("Complex")
        # new_iq_combobox4.addItem("Float/Float 32")
        # new_iq_combobox4.addItem("Int/Int 32")
        # new_iq_combobox4.addItem("Short/Int 16")
        # new_iq_combobox4.addItem("Byte/Int 8")
        new_iq_playback_combobox3.setCurrentIndex(0)

        new_iq_playback_combobox4 = QtWidgets.QComboBox(self, objectName="comboBox2_")
        self.ui.tableWidget_iq_playback.setCellWidget(0, 6, new_iq_playback_combobox4)
        new_iq_playback_combobox4.addItem("Yes")
        new_iq_playback_combobox4.addItem("No")
        new_iq_playback_combobox4.setCurrentIndex(0)

        self.ui.tableWidget_iq_playback.resizeColumnsToContents()

        self.ui.pushButton_iq_cursor1.setCheckable(True)
        self.fft_data = None

        # Load the Files in the Listbox
        self.ui.textEdit_iq_record_dir.setPlainText(str(fissure.utils.IQ_RECORDINGS_DIR))
        self.ui.comboBox3_iq_folders.addItem(str(fissure.utils.IQ_RECORDINGS_DIR))
        self.ui.comboBox3_iq_folders.addItem(str(fissure.utils.ARCHIVE_DIR))
        self.ui.comboBox3_iq_folders.setCurrentIndex(0)

        # Hide Range Buttons
        self.ui.pushButton_iq_plot_prev.setVisible(False)
        self.ui.pushButton_iq_plot_next.setVisible(False)

        # Transfer Files
        self.ui.label2_iq_transfer_folder_success.setVisible(False)
        self.ui.label2_iq_transfer_file_success.setVisible(False)

        # Settings Icon
        self.ui.pushButton_iq_FunctionsSettings.setIcon(
            QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons", "settings.png"))
        )

        # Load Inspection File Flow Graphs
        get_inspection_file_fgs = []
        get_inspection_file_fgs.extend(self.backend.library["Inspection Flow Graphs"]["File"])
        for n in sorted(get_inspection_file_fgs, key=str.lower):
            if n != "None":
                self.ui.listWidget_iq_inspection_fg_file.addItem(n)
        self.ui.listWidget_iq_inspection_fg_file.setCurrentRow(0)

        # SigMF Dictionary
        global_dict = {"core:datatype": "cf32_le", "core:version": "1.0.0"}
        captures_dict = {"core:sample_start": "0"}
        self.sigmf_dict = {}
        self.sigmf_dict["global"] = global_dict
        self.sigmf_dict["captures"] = [captures_dict]
        self.sigmf_dict["annotations"] = []

        # OOK Tab Example Values
        self.ui.textEdit_iq_ook_chip0_pattern.setPlainText("0")
        self.ui.textEdit_iq_ook_chip1_pattern.setPlainText("1")
        self.ui.textEdit_iq_ook_burst_interval.setPlainText("20")
        self.ui.textEdit_iq_ook_sample_rate.setPlainText("1")
        self.ui.textEdit_iq_ook_chip0_duration.setPlainText("5")
        self.ui.textEdit_iq_ook_chip1_duration.setPlainText("5")
        self.ui.textEdit_iq_ook_sequence.setPlainText("10101010101010101010")


    def __init_Archive__(self):
        """
        Initializes Archive Tabs on Dashboard launch.
        """
        # #### Archive #####
        self.ui.comboBox3_archive_download_folder.addItem(fissure.utils.ARCHIVE_DIR)
        self.ui.comboBox3_archive_download_folder.addItem(fissure.utils.IQ_RECORDINGS_DIR)
        ArchiveTabSlots._slotArchiveDownloadRefreshClicked(self)
        self.populateArchive()
        self.ui.label2_archive_replay_status.setVisible(False)
        self.ui.tableWidget_archive_replay.setColumnHidden(9, True)
        self.ui.progressBar_archive_datasets.setVisible(False)
        self.archive_database_loop = False
        self.stop_archive_operations = False


    def __init_Sensor_Nodes__(self):
        """
        Initializes Sensor Nodes Tabs on Dashboard launch.
        """
        ##### Sensor Nodes #####
        # Load Autorun Playlists into ComboBox
        SensorNodesTabSlots._slotSensorNodesAutorunRefreshClicked(self)
        tree_model = QtWidgets.QFileSystemModel()
        tree_model.setRootPath(os.path.expanduser("~"))
        self.ui.treeView_sensor_nodes_fn_local_files.setModel(tree_model)
        self.ui.treeView_sensor_nodes_fn_local_files.setRootIndex(tree_model.index(os.path.expanduser("~")))
        self.ui.treeView_sensor_nodes_fn_local_files.setColumnWidth(0, 800)
        self.ui.comboBox_sensor_nodes_fn_local_folder.addItem(os.path.expanduser("~"))
        self.ui.comboBox_sensor_nodes_fn_folder.addItems(
            [
                "/Recordings",
                "/Autorun_Playlists",
                "/Import_Export_Files",
                "/Sensor_Node_Config",
                "/IQ_Data_Playback",
                "/Archive_Replay",
            ]
        )
        self.ui.dateTimeEdit_sensor_nodes_autorun.setDateTime(QtCore.QDateTime.currentDateTime())
        self.ui.textEdit_sensor_nodes_autorun_repetition_interval.setPlainText("-1")


    def __init_Library__(self):
        """
        Initializes Library Tabs on Dashboard launch.
        """
        # #### Library #####
        self.ui.textEdit_library_search_frequency_margin.setPlainText("0")
        self.ui.textEdit_library_search_start_frequency_margin.setPlainText("0")
        self.ui.textEdit_library_search_end_frequency_margin.setPlainText("0")
        self.ui.textEdit_library_search_bandwidth_margin.setPlainText("0")

        # Get Protocols
        protocols = fissure.utils.library.getProtocols(self.backend.library)

        # Load Protocols into Gallery ComboBox
        protocols_with_images = []
        for p in protocols:
            if len(self.findGalleryImages(p)) > 0:
                protocols_with_images.append(p)
        self.ui.comboBox_library_gallery_protocol.addItems(sorted(protocols_with_images))

        # Load Protocols into Add to Library ComboBox
        self.ui.comboBox_library_pd_protocol.addItem("-- New Protocol --")
        self.ui.comboBox_library_pd_protocol.addItems(sorted(protocols))

        # Load Protocols into Search Library ComboBox
        self.ui.comboBox_library_browse_protocol.addItems(sorted(protocols))

        # Configure PD\Construct Packet Tables
        self.ui.tableWidget_library_pd_packet.resizeRowsToContents()

        # Resize the Protocol Discovery Add to Library Table
        self.ui.tableWidget_library_pd_packet.setColumnWidth(0, 125)
        self.ui.tableWidget_library_pd_packet.setColumnWidth(1, 100)
        self.ui.tableWidget_library_pd_packet.setColumnWidth(3, 75)
        self.ui.tableWidget_library_pd_packet.setColumnWidth(4, 130)
        self.ui.tableWidget_library_pd_packet.horizontalHeader().setSectionResizeMode(2, QtWidgets.QHeaderView.Stretch)

        # Hide the Searching Label
        self.ui.label2_library_search_searching.setVisible(False)

        # Set up Add Attack Stacked Widget
        self.ui.comboBox_library_attacks_subcategory.addItems(
            [
                "Denial of Service",
                "Jamming",
                "Spoofing",
                "Sniffing/Snooping",
                "Probe Attacks",
                "Installation of Malware",
                "Misuse of Resources",
            ]
        )

        # Configure Attack TreeWidget
        LibraryTabSlots._slotLibraryBrowseYAML_Changed(self)


    def __init_signals__(self):
        """
        PyQT Signals
        """
        # Accessible Variable
        self.signals = DashboardSignals()


    def __init_window__(self):
        """
        Initializes the window and menubar
        """
        self.window = uic.loadUi(os.path.join(fissure.utils.UI_DIR, "FissureDashboard.ui"))
        self.setMenuBar(self.window.menuBar())

        # Set Title
        self.setWindowTitle("FISSURE Dashboard")

        self.resize(WINDOW_WIDTH, WINDOW_HEIGHT)

        # Operating System Specific Menu Items
        get_os = fissure.utils.get_os_info()  # self.backend.os_info not loaded yet
        if get_os == 'DragonOS FocalX':
            self.window.actionwl_color_picker.setEnabled(False)
            self.window.actionSrsLTE.setEnabled(False)
            self.window.action4G_IMSI_Catcher.setEnabled(False)
            self.window.actionTower_Search.setEnabled(False)
            self.window.actionTower_Search_Part_2.setEnabled(False)
        elif get_os == 'Kali':
            self.window.actionZigbeeOpen_Sniffer.setEnabled(False)
            self.window.actionFALCON.setEnabled(False)
            #self.window.actionLTE_ciphercheck.setEnabled(False)
            self.window.actionOpenCPN.setEnabled(False)
            self.window.actionRTLSDR_Airband.setEnabled(False)
            self.window.actionguidus.setEnabled(False)
            self.window.actionSystemback.setEnabled(False)
            self.window.actiondump978.setEnabled(False)
            self.window.actionOpenWebRX.setEnabled(False)
        elif get_os == 'Raspberry Pi OS':
            self.window.actionZigbeeOpen_Sniffer.setEnabled(False)
            self.window.actionProxmark3.setEnabled(False)
            self.window.actionIIO_Oscilloscope.setEnabled(False)
            self.window.actionqFlipper.setEnabled(False)            
            self.window.actionDump1090.setEnabled(False)
            self.window.actionFALCON.setEnabled(False)
            self.window.actionLTE_ciphercheck.setEnabled(False)
            self.window.actionOpenHAB.setEnabled(False)
            self.window.actionStart_openHAB_Service.setEnabled(False)
            self.window.actionStop_openHAB_Service.setEnabled(False)
            self.window.actionBaudline.setEnabled(False)
            self.window.actionUniversal_Radio_Hacker.setEnabled(False)
            self.window.actionOpenCPN.setEnabled(False)
            self.window.actionSDRTrunk.setEnabled(False)
            self.window.actionSimpleScreenRecorder.setEnabled(False)
            self.window.actionSdrGlut.setEnabled(False)
            self.window.actionRehex.setEnabled(False)
            self.window.actionNETATTACK2.setEnabled(False)
            self.window.actionRouterSploit.setEnabled(False)
            self.window.actionGoogle_Earth_Pro.setEnabled(False)
            self.window.actionViking.setEnabled(False)
            self.window.actionLTE_Cell_Scanner.setEnabled(False)
            self.window.actionAnki.setEnabled(False)
            self.window.actionTrackerjacker.setEnabled(False)
            self.window.actionBTSnifferBREDR.setEnabled(False)
            self.window.actionSigDigger.setEnabled(False)
            self.window.actionSystemback.setEnabled(False)
            self.window.actionguidus.setEnabled(False)
            self.window.actionICE9_Bluetooth_Sniffer.setEnabled(False)
            self.window.actionOpenWebRX.setEnabled(False)
            self.window.actionRadiosonde_auto_rx.setEnabled(False)

        # Disable Menu Items for all maint-3.8 Operating Systems
        if any(keyword == get_os for keyword in fissure.utils.OS_3_8_KEYWORDS):
            self.window.actionwl_color_picker.setEnabled(False)
            self.window.actiontpms_rx.setEnabled(False)
            self.window.actionBaudline.setEnabled(False)

        # Disable Menu Items for all maint-3.10 Operating Systems
        # elif any(keyword == get_os for keyword in fissure.utils.OS_3_10_KEYWORDS):
        else:
            self.window.actionGpick.setEnabled(False)
            self.window.actionNETATTACK2.setEnabled(False)
            self.window.actionLTE_ciphercheck.setEnabled(False)
            self.window.actionIIO_Oscilloscope.setEnabled(False)
            self.window.actionSimpleScreenRecorder.setEnabled(False)
            self.window.actionGr_air_modes.setEnabled(False)
            self.window.actionAiS_TX.setEnabled(False)
            self.window.actionBaudline.setEnabled(False)


    def load_MPL_components(self):
        # Create Tuning Matplotlib Widget
        self.tuning_widget = MPLTuningCanvas(
            self.ui.tab_tsi_sweep,
            dpi=100,
            title="Tuning",
            ylim=400,
            bg_color=self.backend.settings["color2"],
            face_color=self.backend.settings["color5"],
            text_color=self.backend.settings["color4"],
        )
        self.tuning_widget.move(self.ui.frame_tsi_search_bands.pos())
        self.tuning_widget.setGeometry(self.ui.frame_tsi_search_bands.geometry())

        # Create Wideband Matplotlib Widget
        self.wideband_width = 1201
        self.wideband_height = 801
        rgb = tuple(int(self.backend.settings["color2"].lstrip("#")[i : i + 2], 16) for i in (0, 2, 4))
        background_color = (float(rgb[0]) / 255, float(rgb[1]) / 255, float(rgb[2]) / 255)
        self.wideband_data = numpy.ones((self.wideband_height, self.wideband_width, 3)) * (background_color)
        self.matplotlib_widget = MPLCanvas(
            self.ui.tab_tsi_detector,
            dpi=100,
            title="Detector History",
            ylim=400,
            width=self.wideband_width,
            height=self.wideband_height,
            border=[0.08, 0.90, 0.05, 1, 0, 0],
            colorbar_fraction=0.038,
            xlabels=["0", "", "1000", "", "2000", "", "3000", "", "4000", "", "5000", "", "6000"],
            ylabels=["0", "5", "10", "15", "20", "25", "30", "35", "40", "45"],
            bg_color=self.backend.settings["color1"],
            face_color=self.backend.settings["color5"],
            text_color=self.backend.settings["color4"],
        )
        self.matplotlib_widget.move(self.ui.frame_tsi_detector.pos())
        self.matplotlib_widget.setGeometry(self.ui.frame_tsi_detector.geometry())
        self.matplotlib_widget.axes.cla()
        self.matplotlib_widget.axes.imshow(
            self.wideband_data, cmap="rainbow", clim=(-100, 30), extent=[0, 1201, 801, 0]
        )
        self.matplotlib_widget.configureAxes(
            title="Detector History",
            xlabel="Frequency (MHz)",
            ylabel="Time Elapsed (s)",
            xlabels=["0", "", "1000", "", "2000", "", "3000", "", "4000", "", "5000", "", "6000"],
            ylabels=["0", "5", "10", "15", "20", "25", "30", "35", "40"],
            ylim=self.wideband_height,
            background_color=self.backend.settings["color1"],
            face_color=self.backend.settings["color5"],
            text_color=self.backend.settings["color4"],
        )
        self.matplotlib_widget.draw()

        # Create IQ Data Matplotlib Widget
        self.iq_matplotlib_widget = MPL_IQCanvas(
            self.ui.tab_iq_data,
            dpi=100,
            title="IQ Data",
            ylim=400,
            bg_color=self.backend.settings["color2"],
            face_color=self.backend.settings["color5"],
            text_color=self.backend.settings["color4"],
        )
        self.iq_matplotlib_widget.move(self.ui.frame3_iq.pos())
        self.iq_matplotlib_widget.setGeometry(self.ui.frame3_iq.geometry())

        # Add a Toolbar
        self.mpl_toolbar = NavigationToolbar2QT(self.iq_matplotlib_widget, self.ui.tab_iq_data)
        self.mpl_toolbar.setStyleSheet("color:" + self.backend.settings["color4"])
        self.mpl_toolbar.setGeometry(QtCore.QRect(375, 277, 525, 35))
        icons_buttons = {
            "Home": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons", "home.png")),
            "Pan": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons", "move.png")),
            "Zoom": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons", "zoom_to_rect.png")),
            "Back": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons", "back.png")),
            "Forward": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons", "forward.png")),
            "Subplots": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons", "subplots.png")),
            "Customize": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons", "qt4_editor_options.png")),
            "Save": QtGui.QIcon(os.path.join(fissure.utils.UI_DIR, "Icons", "filesave.png")),
        }
        for action in self.mpl_toolbar.actions():
            if action.text() in icons_buttons:
                action.setIcon(icons_buttons.get(action.text(), QtGui.QIcon()))


    @QtCore.pyqtSlot(QtCore.QObject)
    def load_screen(self, screen: QtCore.QObject, dashboard: QtCore.QObject):
        widget = QtWidgets.QWidget()

        self.ui = screen()
        self.ui.setupUi(widget, dashboard)

        self.setCentralWidget(widget)


    @QtCore.pyqtSlot(object)
    def openPopUp(self, key: str, popup: object, *args):
        widget = QtWidgets.QDialog(parent=self)
        ui = popup(widget, self, *args)

        # Save the UI to access later
        self.popups[key] = ui

        # Connect the dialog's finished signal to a slot that removes it from the dictionary
        widget.finished.connect(lambda: self.clearPopUp(key))

        # Insert the popup into the event loop and wait for it to finish
        if ui.exec() == QtWidgets.QDialog.Accepted:
            try:
                return_value = ui.return_value
                return return_value
            except:
                return None
        else:
            return None


    def clearPopUp(self, key):
        if key in self.popups:
            del self.popups[key]
            # print(f"Popup with key '{key}' has been removed.")


    def warningBox(self, message: str, details: str = None):
        msgBox = QtWidgets.QMessageBox()
        msgBox.warning(self, "WARNING", message)
        msgBox.setInformativeText(details)
        msgBox.show()


    async def ask_confirmation(self, message_text):
        """ 
        Used for asynchronous message boxes.
        """
        msg_box = QtWidgets.QMessageBox(self)
        msg_box.setText(message_text)
        msg_box.setStandardButtons(QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No)
        msg_box.setIcon(QtWidgets.QMessageBox.Question)

        loop = asyncio.get_event_loop()
        future = loop.create_future()

        def on_finished(button):
            future.set_result(button)

        msg_box.buttonClicked.connect(on_finished)
        msg_box.show()

        await future

        return msg_box.standardButton(future.result())
    

    async def ask_confirmation_ok(self, message_text, width=None):
        """ 
        Used for asynchronous message boxes. Needs to be its own class to adjust the width.
        """
        msg_box = QtWidgets.QMessageBox(self)
        msg_box.setText(message_text)
        msg_box.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msg_box.setIcon(QtWidgets.QMessageBox.NoIcon)
        # msg_box.setBaseSize(QtCore.QSize(1950, 120))

        # Set the width if provided
        if width:
            pass
            # msg_box.resize(width, msg_box.sizeHint().height())
            # msg_box.setFixedSize(width, msg_box.sizeHint().height())

        loop = asyncio.get_event_loop()
        future = loop.create_future()

        def on_finished(button):
            future.set_result(button)

        msg_box.buttonClicked.connect(on_finished)
        msg_box.show()

        await future

        return msg_box.standardButton(future.result())
    

    def writeSigMF(self, filepath, sigmf_dict):
        """ 
        Writes a SigMF metadata file for a given data file. Move to utils?
        """
        with open(filepath,"w") as outfile:
            json.dump(sigmf_dict, outfile, indent=4)


    def closeEvent(self, event):
        """
        Process close events

        If currently connected to HiprFisr, notify user to end session and ignore event,
        otherwise close gracefully. FIX - closing while HIPRFISR is connecting on startup.
        """        
        # First Close Event
        if self.all_closed_down == False:
            # HIPRFISR Shut Down Already
            if self.backend.stop() is True:
                event.accept()
                self.close()
            
            # Close Connections First
            else:
                asyncio.ensure_future(self.async_close_event())
                event.ignore()

        # All Closed Down, Quick Exit
        else:
            pass


    async def async_close_event(self):
        """
        Needed to shut down Server with async function in StatusBarSlots when closing the Dashboard.
        """
        # Shut Down Local Sensor Node
        for n in range(1,6):
            if (self.backend.settings["sensor_node" + str(n)]["local_remote"].lower() == "local") and (self.backend.sensor_node_connected[n-1] == True):
                await self.backend.disconnect_local_sensor_node(n-1)
                break
        
        # Shut Down Local HIPRFISR
        await StatusBarSlots.shutdown_hiprfisr(self)
        while self.backend.stop() == False:
            await qasync.asyncio.sleep(0.1)
        self.all_closed_down = True
        self.close()


    def hardwareDisplayName(self, hardware_type, sensor_node, component, index):
        """Returns a display name for comboboxes based on provided sensor node hardware information."""
        # Return Display Name Based on Type
        get_hardware_name = ""
        if hardware_type == "Computer":
            get_hardware_name = hardware_type
        elif hardware_type == "USRP X3x0":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][5]
        elif hardware_type == "USRP B2x0":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][3]
        elif hardware_type == "HackRF":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][3]
        elif hardware_type == "RTL2832U":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][3]
        elif hardware_type == "802.11x Adapter":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][4]
        elif hardware_type == "USRP B20xmini":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][3]
        elif hardware_type == "LimeSDR":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][3]
        elif hardware_type == "bladeRF":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][3]
        elif hardware_type == "Open Sniffer":
            get_hardware_name = hardware_type
        elif hardware_type == "PlutoSDR":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][5]
        elif hardware_type == "USRP2":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][5]
        elif hardware_type == "USRP N2xx":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][5]
        elif hardware_type == "bladeRF 2.0":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][3]
        elif hardware_type == "USRP X410":
            get_hardware_name = hardware_type + " - " + self.backend.settings[sensor_node][component][index][5]
        else:
            get_hardware_name = "UNKNOWN HARDWARE"

        return get_hardware_name


    def hardwareDisplayNameLookup(self, display_name, component):
        """Takes in a hardware display name and returns all the sensor node hardware information"""
        # Return Saved Hardware Information
        hardware_type = display_name.split(" - ")[0]
        try:
            second_value = display_name.split(" - ")[1]
        except:
            second_value = ""

        if len(second_value) > 0:
            get_sensor_node = ["sensor_node1", "sensor_node2", "sensor_node3", "sensor_node4", "sensor_node5"]
            sensor_node = get_sensor_node[self.active_sensor_node]
            get_index = 0
            for n in range(0, len(self.backend.settings[sensor_node][component])):
                if hardware_type == "Computer":
                    if second_value == "":  # todo
                        get_index = n
                        break
                elif hardware_type == "USRP X3x0":
                    if second_value == self.backend.settings[sensor_node][component][n][5]:
                        get_index = n
                        break
                elif hardware_type == "USRP B2x0":
                    if second_value == self.backend.settings[sensor_node][component][n][3]:
                        get_index = n
                        break
                elif hardware_type == "HackRF":
                    if second_value == self.backend.settings[sensor_node][component][n][3]:
                        get_index = n
                        break
                elif hardware_type == "RTL2832U":
                    if second_value == self.backend.settings[sensor_node][component][n][3]:
                        get_index = n
                        break
                elif hardware_type == "802.11x Adapter":
                    if second_value == self.backend.settings[sensor_node][component][n][4]:
                        get_index = n
                        break
                elif hardware_type == "USRP B20xmini":
                    if second_value == self.backend.settings[sensor_node][component][n][3]:
                        get_index = n
                        break
                elif hardware_type == "LimeSDR":
                    if second_value == self.backend.settings[sensor_node][component][n][3]:
                        get_index = n
                        break
                elif hardware_type == "bladeRF":
                    if second_value == self.backend.settings[sensor_node][component][n][3]:
                        get_index = n
                        break
                elif hardware_type == "Open Sniffer":
                    if second_value == "":  # todo
                        get_index = n
                        break
                elif hardware_type == "PlutoSDR":
                    if second_value == self.backend.settings[sensor_node][component][n][5]:
                        get_index = n
                        break
                elif hardware_type == "USRP2":
                    if second_value == self.backend.settings[sensor_node][component][n][5]:
                        get_index = n
                        break
                elif hardware_type == "USRP N2xx":
                    if second_value == self.backend.settings[sensor_node][component][n][5]:
                        get_index = n
                        break
                elif hardware_type == "bladeRF 2.0":
                    if second_value == self.backend.settings[sensor_node][component][n][3]:
                        get_index = n
                        break
                elif hardware_type == "USRP X410":
                    if second_value == self.backend.settings[sensor_node][component][n][5]:
                        get_index = n
                        break
                else:
                    pass

            # Return All Saved Values
            ret_type = self.backend.settings[sensor_node][component][get_index][0]
            ret_uid = self.backend.settings[sensor_node][component][get_index][1]
            ret_radio_name = self.backend.settings[sensor_node][component][get_index][2]
            ret_serial = self.backend.settings[sensor_node][component][get_index][3]
            ret_interface = self.backend.settings[sensor_node][component][get_index][4]
            ret_ip = self.backend.settings[sensor_node][component][get_index][5]
            ret_daughterboard = self.backend.settings[sensor_node][component][get_index][6]

            return [ret_type, ret_uid, ret_radio_name, ret_serial, ret_interface, ret_ip, ret_daughterboard]

        else:
            return ["", "", "", "", "", "", ""]


    def configureTSI_Hardware(self, node_number):
        """
        Configures TSI after new sensor node selection.
        """
        # TSI Hardware Comboboxes
        node_number = node_number
        self.ui.comboBox_tsi_detector_sweep_hardware.clear()
        self.ui.comboBox_tsi_detector_fixed_hardware.clear()
        if node_number >= 0:
            get_sensor_node_hardware = []
            get_sensor_node = ["sensor_node1", "sensor_node2", "sensor_node3", "sensor_node4", "sensor_node5"]
            for n in range(0, len(self.backend.settings[get_sensor_node[node_number]]["tsi"])):
                get_type = self.backend.settings[get_sensor_node[node_number]]["tsi"][n][0]
                get_hardware_name = self.hardwareDisplayName(get_type, get_sensor_node[node_number], "tsi", n)
                get_sensor_node_hardware.append(get_hardware_name)
            self.ui.comboBox_tsi_detector_sweep_hardware.addItems(get_sensor_node_hardware)
            self.ui.comboBox_tsi_detector_fixed_hardware.addItems(get_sensor_node_hardware)

            # Refresh Detector Advanced Settings
            TSITabSlots._slotTSI_DetectorChanged(self)


    def configurePD_Hardware(self, node_number):
        """
        Configures PD after new sensor node selection.
        """
        # PD Demod Hardware Combobox
        node_number = node_number
        self.ui.comboBox_pd_demod_hardware.clear()
        if node_number >= 0:
            get_sensor_node_hardware = []
            get_sensor_node = ["sensor_node1", "sensor_node2", "sensor_node3", "sensor_node4", "sensor_node5"]
            for n in range(0, len(self.backend.settings[get_sensor_node[node_number]]["pd"])):
                get_type = self.backend.settings[get_sensor_node[node_number]]["pd"][n][0]
                get_hardware_name = self.hardwareDisplayName(get_type, get_sensor_node[node_number], "pd", n)
                get_sensor_node_hardware.append(get_hardware_name)
            self.ui.comboBox_pd_demod_hardware.addItems(get_sensor_node_hardware)

            # self.ui.textEdit_pd_sniffer_interface.setPlainText(self.backend.settings['hardware_interface_pd'])


    def configureAttackHardware(self, node_number):
        """
        Configures Attack after new sensor node selection.
        """
        # Attack Hardware Combobox
        node_number = node_number
        self.ui.comboBox_attack_hardware.clear()
        if node_number >= 0:
            self.ui.comboBox_attack_hardware.addItem("Computer")
            get_sensor_node_hardware = []
            get_sensor_node = ["sensor_node1", "sensor_node2", "sensor_node3", "sensor_node4", "sensor_node5"]
            for n in range(0, len(self.backend.settings[get_sensor_node[node_number]]["attack"])):
                get_type = self.backend.settings[get_sensor_node[node_number]]["attack"][n][0]
                get_hardware_name = self.hardwareDisplayName(get_type, get_sensor_node[node_number], "attack", n)
                get_sensor_node_hardware.append(get_hardware_name)
            self.ui.comboBox_attack_hardware.addItems(get_sensor_node_hardware)
            if len(get_sensor_node_hardware) > 0:
                self.ui.comboBox_attack_hardware.setCurrentIndex(1)


    def configureIQ_Hardware(self, node_number):
        """
        Configures IQ after new sensor node selection.
        """
        # TSI Hardware Comboboxes
        node_number = node_number
        self.ui.comboBox_iq_record_hardware.clear()
        self.ui.comboBox_iq_playback_hardware.clear()
        self.ui.comboBox_iq_inspection_hardware.clear()
        if node_number >= 0:
            get_sensor_node_hardware = []
            get_sensor_node = ["sensor_node1", "sensor_node2", "sensor_node3", "sensor_node4", "sensor_node5"]
            for n in range(0, len(self.backend.settings[get_sensor_node[node_number]]["archive"])):
                get_type = self.backend.settings[get_sensor_node[node_number]]["archive"][n][0]
                get_hardware_name = self.hardwareDisplayName(get_type, get_sensor_node[node_number], "archive", n)
                get_sensor_node_hardware.append(get_hardware_name)
            self.ui.comboBox_iq_record_hardware.addItems(get_sensor_node_hardware)
            self.ui.comboBox_iq_playback_hardware.addItems(get_sensor_node_hardware)
            self.ui.comboBox_iq_inspection_hardware.addItems(get_sensor_node_hardware)


    def configureArchiveHardware(self, node_number):
        """
        Configures Archive after new hardware selection.
        """
        # Archive Hardware Combobox
        node_number = node_number
        self.ui.comboBox_archive_replay_hardware.clear()
        if node_number >= 0:
            get_sensor_node_hardware = []
            get_sensor_node = ["sensor_node1", "sensor_node2", "sensor_node3", "sensor_node4", "sensor_node5"]
            for n in range(0, len(self.backend.settings[get_sensor_node[node_number]]["archive"])):
                get_type = self.backend.settings[get_sensor_node[node_number]]["archive"][n][0]
                get_hardware_name = self.hardwareDisplayName(get_type, get_sensor_node[node_number], "archive", n)
                get_sensor_node_hardware.append(get_hardware_name)
            self.ui.comboBox_archive_replay_hardware.addItems(get_sensor_node_hardware)


    def refreshStatusBarText(self):
        """
        Refreshes the status bar text after a value is changed for a sensor node.
        """
        # Update Based on Sensor Node
        for n in range(0, self.statusBar().dialog.tableWidget_status_results.rowCount()):
            if self.active_sensor_node == -1:
                self.statusBar().dialog.tableWidget_status_results.item(n, 0).setText(
                    "Connect to sensor node to view status."
                )
            else:
                self.statusBar().dialog.tableWidget_status_results.item(n, 0).setText(
                    self.statusbar_text[self.active_sensor_node][n]
                )


    def populateArchive(self):
        """
        Populates the Archive tables from library.yaml.
        """
        # Populate the File Table
        get_archives = [archive for archive in sorted(self.backend.library["Archive"]["File"])]
        notes_width = 150
        new_font = QtGui.QFont("Times", 10)

        for n in range(0, len(get_archives)):
            # Get File Info
            get_file = str(get_archives[n])
            get_protocol = str(self.backend.library["Archive"]["File"][get_archives[n]]["Protocol"])
            get_date = str(self.backend.library["Archive"]["File"][get_archives[n]]["Date"])
            get_format = str(self.backend.library["Archive"]["File"][get_archives[n]]["Format"])
            get_sample_rate = str(self.backend.library["Archive"]["File"][get_archives[n]]["Sample Rate"])
            get_tuned_frequency = str(self.backend.library["Archive"]["File"][get_archives[n]]["Tuned Frequency"])
            get_samples = str(self.backend.library["Archive"]["File"][get_archives[n]]["Samples"])
            get_size = str(self.backend.library["Archive"]["File"][get_archives[n]]["Size"])
            get_modulation = str(self.backend.library["Archive"]["File"][get_archives[n]]["Modulation"])
            get_notes = str(self.backend.library["Archive"]["File"][get_archives[n]]["Notes"])

            # Find Maximum Note Width
            if len(get_notes) * 10 > notes_width:
                notes_width = len(get_notes) * 10

            # Insert a Row
            self.ui.tableWidget_archive_download.setRowCount(self.ui.tableWidget_archive_download.rowCount() + 1)

            # Populate the Table
            file_item = QtWidgets.QTableWidgetItem(get_file)
            file_item.setFont(new_font)
            self.ui.tableWidget_archive_download.setVerticalHeaderItem(
                self.ui.tableWidget_archive_download.rowCount() - 1, file_item
            )
            protocol_item = QtWidgets.QTableWidgetItem(get_protocol)
            protocol_item.setTextAlignment(QtCore.Qt.AlignCenter)
            protocol_item.setFlags(protocol_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.ui.tableWidget_archive_download.setItem(
                self.ui.tableWidget_archive_download.rowCount() - 1, 0, protocol_item
            )
            date_item = QtWidgets.QTableWidgetItem(get_date)
            date_item.setTextAlignment(QtCore.Qt.AlignCenter)
            date_item.setFlags(date_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.ui.tableWidget_archive_download.setItem(
                self.ui.tableWidget_archive_download.rowCount() - 1, 1, date_item
            )
            format_item = QtWidgets.QTableWidgetItem(get_format)
            format_item.setTextAlignment(QtCore.Qt.AlignCenter)
            format_item.setFlags(format_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.ui.tableWidget_archive_download.setItem(
                self.ui.tableWidget_archive_download.rowCount() - 1, 2, format_item
            )
            sample_rate_item = QtWidgets.QTableWidgetItem(get_sample_rate)
            sample_rate_item.setTextAlignment(QtCore.Qt.AlignCenter)
            sample_rate_item.setFlags(sample_rate_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.ui.tableWidget_archive_download.setItem(
                self.ui.tableWidget_archive_download.rowCount() - 1, 3, sample_rate_item
            )
            tuned_frequency_item = QtWidgets.QTableWidgetItem(get_tuned_frequency)
            tuned_frequency_item.setTextAlignment(QtCore.Qt.AlignCenter)
            tuned_frequency_item.setFlags(tuned_frequency_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.ui.tableWidget_archive_download.setItem(
                self.ui.tableWidget_archive_download.rowCount() - 1, 4, tuned_frequency_item
            )
            samples_item = QtWidgets.QTableWidgetItem(get_samples)
            samples_item.setTextAlignment(QtCore.Qt.AlignCenter)
            samples_item.setFlags(samples_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.ui.tableWidget_archive_download.setItem(
                self.ui.tableWidget_archive_download.rowCount() - 1, 5, samples_item
            )
            size_item = QtWidgets.QTableWidgetItem(get_size)
            size_item.setTextAlignment(QtCore.Qt.AlignCenter)
            size_item.setFlags(size_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.ui.tableWidget_archive_download.setItem(
                self.ui.tableWidget_archive_download.rowCount() - 1, 6, size_item
            )
            modulation_item = QtWidgets.QTableWidgetItem(get_modulation)
            modulation_item.setTextAlignment(QtCore.Qt.AlignCenter)
            modulation_item.setFlags(modulation_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.ui.tableWidget_archive_download.setItem(
                self.ui.tableWidget_archive_download.rowCount() - 1, 7, modulation_item
            )
            notes_item = QtWidgets.QTableWidgetItem(get_notes)
            notes_item.setFlags(notes_item.flags() & ~QtCore.Qt.ItemIsEditable)
            self.ui.tableWidget_archive_download.setItem(
                self.ui.tableWidget_archive_download.rowCount() - 1, 8, notes_item
            )

        # Resize the Table
        # self.ui.statTable.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.ui.tableWidget_archive_download.resizeColumnsToContents()
        self.ui.tableWidget_archive_download.setColumnWidth(8, notes_width)
        self.ui.tableWidget_archive_download.resizeRowsToContents()
        # self.ui.tableWidget_archive_download.horizontalHeader().setSectionResizeMode(8,QtWidgets.QHeaderView.Stretch)
        # self.ui.tableWidget_archive_download.horizontalHeader().setStretchLastSection(False)
        # self.ui.tableWidget_archive_download.horizontalHeader().setStretchLastSection(True)

        # Fill in the Collection Tree View
        headers = ["Collection", "Size", "Files", "Format", "Notes"]
        get_collections = [archive for archive in sorted(self.backend.library["Archive"]["Collection"])]
        tree = []
        for n in range(0, len(get_collections)):
            # Main Collection Folder
            tree.append(
                [
                    0,
                    get_collections[n],
                    self.backend.library["Archive"]["Collection"][get_collections[n]]["Size"],
                    self.backend.library["Archive"]["Collection"][get_collections[n]]["Files"],
                    self.backend.library["Archive"]["Collection"][get_collections[n]]["Format"],
                    self.backend.library["Archive"]["Collection"][get_collections[n]]["Notes"],
                ]
            )

            # Subdirectories
            try:
                get_subdirectories = [
                    subdirectory
                    for subdirectory in sorted(
                        self.backend.library["Archive"]["Collection"][get_collections[n]]["Subdirectories"]
                    )
                ]
                for m in range(0, len(get_subdirectories)):
                    tree.append(
                        [
                            1,
                            get_subdirectories[m],
                            self.backend.library["Archive"]["Collection"][get_collections[n]]["Subdirectories"][
                                get_subdirectories[m]
                            ]["Size"],
                            self.backend.library["Archive"]["Collection"][get_collections[n]]["Subdirectories"][
                                get_subdirectories[m]
                            ]["Files"],
                            self.backend.library["Archive"]["Collection"][get_collections[n]]["Subdirectories"][
                                get_subdirectories[m]
                            ]["Format"],
                            self.backend.library["Archive"]["Collection"][get_collections[n]]["Subdirectories"][
                                get_subdirectories[m]
                            ]["Notes"],
                        ]
                    )

                    # Files
                    get_files = self.backend.library["Archive"]["Collection"][get_collections[n]]["Subdirectories"][
                        get_subdirectories[m]
                    ]["File List"]
                    for k in range(0, len(get_files)):
                        tree.append([2, get_files[k], "", "", "", ""])

            except:
                # Files without a Subdirectory
                get_files = self.backend.library["Archive"]["Collection"][get_collections[n]]["File List"]
                for k in range(0, len(get_files)):
                    tree.append([1, get_files[k], "", "", "", ""])

        # tree = [
        #     [0, "Root", "a", "b", "c", "d"],
        #     [1, "Collection1", "aa", "bb", "cc", "dd"],
        #     [1, "Collection2", "aaa", "bbb", "ccc", "ddd"],
        #     [1, "Collection3", "aaaa", "bbbb", "cccc", "dddd"],
        #     [0, "Root2", "a", "b", "c", "d"],
        #     [1, "Collection11", "aa", "bb", "cc", "dd"],
        # ]
        new_model = TreeModel(headers, tree)
        self.ui.treeView_archive_download_collection.setModel(new_model)

        self.ui.treeView_archive_download_collection.setAnimated(False)
        self.ui.treeView_archive_download_collection.setIndentation(20)
        self.ui.treeView_archive_download_collection.setSortingEnabled(False)

        self.ui.treeView_archive_download_collection.header().setSectionResizeMode(
            0, QtWidgets.QHeaderView.ResizeToContents
        )
        self.ui.treeView_archive_download_collection.header().setSectionResizeMode(
            1, QtWidgets.QHeaderView.ResizeToContents
        )
        self.ui.treeView_archive_download_collection.header().setSectionResizeMode(
            2, QtWidgets.QHeaderView.ResizeToContents
        )
        self.ui.treeView_archive_download_collection.header().setSectionResizeMode(
            3, QtWidgets.QHeaderView.ResizeToContents
        )
        self.ui.treeView_archive_download_collection.header().setSectionResizeMode(
            4, QtWidgets.QHeaderView.ResizeToContents
        )
        # ~ self.ui.treeView_archive_download_collection.header().setDefaultAlignment(
        #     QtCore.Qt.AlignCenter | QtCore.Qt.AlignVCenter
        # )  # Centering item text is difficult


    def errorMessage(self, message_text):
        """
        Creates a popup window with an error message.
        """
        # Create the Message Box
        msgBox = QtWidgets.QMessageBox()
        msgBox.setText(message_text)
        msgBox.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msgBox.setDefaultButton(QtWidgets.QMessageBox.Ok)
        msgBox.exec_()

    
    def colnum_string(self, n):
        """ 
        Converts values from a number-based counting system to a letter-based counting system.
        """
        div=n
        string=""
        temp=0
        while div>0:
            module=(div-1)%26
            string=chr(65+module)+string
            div=int((div-module)/26)
        return string


    def findGalleryImages(self, protocol):
        """
        Returns the names of Gallery images for a protocol.
        """
        # Check for Images
        folder = fissure.utils.GALLERY_DIR
        protocol = protocol.replace(" ", "_")
        protocol_len = len(protocol)
        get_file_names = []
        for fname in sorted(os.listdir(folder)):
            if protocol in fname[0:protocol_len]:
                get_file_names.append(fname)
        return get_file_names


    def fill_item(self, item, value):
        """
        Generic function for filling a treewidget with a dictionary.
        """
        item.setExpanded(True)
        if type(value) is dict:
            for key, val in sorted(value.items()):
                child = QtWidgets.QTreeWidgetItem()
                child.setText(0, str(key))
                item.addChild(child)
                self.fill_item(child, val)
        elif type(value) is list:
            for val in value:
                child = QtWidgets.QTreeWidgetItem()
                item.addChild(child)
                if type(val) is dict:
                    child.setText(0, "[dict]")
                    self.fill_item(child, val)
                elif type(val) is list:
                    child.setText(0, "[list]")
                    self.fill_item(child, val)
                else:
                    child.setText(0, str(val))
                child.setExpanded(True)
        else:
            child = QtWidgets.QTreeWidgetItem()
            child.setText(0, str(value))
            item.addChild(child)


    def updateCRC(self, crc_poly, crc_acc, crc_input, crc_length):
        """
        Calculates CRC for bytes. Used in multiple tabs. Move this function somewhere else?
        """
        # 8-bit CRC
        if crc_length == 8:
            # Convert Hex Byte String to int
            crc_input_int = int(crc_input, 16)
            crc_acc_int = int(crc_acc, 16)
            crc_acc_int = crc_acc_int ^ crc_input_int
            for _ in range(8):
                crc_acc_int <<= 1
                if crc_acc_int & 0x0100:
                    crc_acc_int ^= crc_poly
                # crc &= 0xFF

            # Convert to Hex String
            crc_acc = ("%0.2X" % crc_acc_int)[-2:]

        # 16-bit CRC
        elif crc_length == 16:
            # Convert Hex Byte String to int
            crc_input_int = int(crc_input, 16)
            crc_acc_int = int(crc_acc, 16)
            crc_acc_int = crc_acc_int ^ (crc_input_int << 8)
            for i in range(0, 8):
                if (crc_acc_int & 32768) == 32768:
                    crc_acc_int = crc_acc_int << 1
                    crc_acc_int = crc_acc_int ^ crc_poly
                else:
                    crc_acc_int = crc_acc_int << 1

            # Convert to Hex String
            crc_acc = "%0.4X" % crc_acc_int

            # Keep Only the Last 2 Bytes
            crc_acc = crc_acc[-4:]

        # 32-bit CRC
        elif crc_length == 32:
            crc_input_int = int(crc_input, 16)
            crc_acc = crc_acc ^ crc_input_int
            for _ in range(0, 8):
                mask = -(crc_acc & 1)
                crc_acc = (crc_acc >> 1) ^ (crc_poly & mask)

        return crc_acc


    def checkFrequencyBounds(self, get_frequency, get_hardware, get_daughterboard):
        """ Returns True or False if the frequency is within the bounds of the hardware. Move to utils?
        """
        if get_hardware == "Computer":
            # Frequency Limits
            if (get_frequency >= 1) and (get_frequency <= 6000):
                return True

        elif get_hardware == "USRP X3x0":
            # Frequency Limits
            if get_daughterboard == "CBX-120":
                if (get_frequency >= 1200) and (get_frequency <= 6000):
                    return True
            elif get_daughterboard == "SBX-120":
                if (get_frequency >= 400) and (get_frequency <= 4400):
                    return True
            elif get_daughterboard == "UBX-160":
                if (get_frequency >= 10) and (get_frequency <= 6000):
                    return True
            elif get_daughterboard == "WBX-120":
                if (get_frequency >= 25) and (get_frequency <= 2200):
                    return True
            elif get_daughterboard == "TwinRX":
                if (get_frequency >= 10) and (get_frequency <= 6000):
                    return True

        elif get_hardware == "USRP B2x0":
            # Frequency Limits
            if (get_frequency >= 70) and (get_frequency <= 6000):
                return True

        elif get_hardware == "HackRF":
            # Frequency Limits
            if (get_frequency >= 1) and (get_frequency <= 6000):
                return True

        elif get_hardware == "RTL2832U":
            # Frequency Limits
            if (get_frequency >= 64) and (get_frequency <= 1700):
                return True

        elif get_hardware == "802.11x Adapter":
            # Frequency Limits
            if (get_frequency >= 1) and (get_frequency <= 6000):
                return True

        elif get_hardware == "USRP B20xmini":
            # Frequency Limits
            if (get_frequency >= 70) and (get_frequency <= 6000):
                return True

        elif get_hardware == "LimeSDR":
            # Frequency Limits
            if (get_frequency >= 1) and (get_frequency <= 3800):
                return True

        elif get_hardware == "bladeRF":
            # Frequency Limits
            if (get_frequency >= 280) and (get_frequency <= 3800):
                return True

        elif get_hardware == "Open Sniffer":
            # Frequency Limits
            if (get_frequency >= 1) and (get_frequency <= 6000):
                return True

        elif get_hardware == "PlutoSDR":
            # Frequency Limits
            if (get_frequency >= 325) and (get_frequency <= 3800):
                return True

        elif get_hardware == "USRP2":
            # Frequency Limits
            if get_daughterboard == "XCVR2450":
                if (get_frequency >= 2400) and (get_frequency <= 6000):
                    return True
            elif get_daughterboard == "DBSRX":
                if (get_frequency >= 800) and (get_frequency <= 2300):
                    return True
            elif get_daughterboard == "SBX-40":
                if (get_frequency >= 400) and (get_frequency <= 4400):
                    return True
            elif get_daughterboard == "UBX-40":
                if (get_frequency >= 10) and (get_frequency <= 6000):
                    return True
            elif get_daughterboard == "WBX-40":
                if (get_frequency >= 50) and (get_frequency <= 2200):
                    return True
            elif get_daughterboard == "CBX-40":
                if (get_frequency >= 1200) and (get_frequency <= 6000):
                    return True
            elif get_daughterboard == "LFRX":
                if (get_frequency >= 0) and (get_frequency <= 30):
                    return True
            elif get_daughterboard == "LFTX":
                if (get_frequency >= 0) and (get_frequency <= 30):
                    return True
            elif get_daughterboard == "BasicRX":
                if (get_frequency >= 1) and (get_frequency <= 250):
                    return True
            elif get_daughterboard == "BasicTX":
                if (get_frequency >= 1) and (get_frequency <= 250):
                    return True
            elif get_daughterboard == "TVRX2":
                if (get_frequency >= 50) and (get_frequency <= 860):
                    return True
            elif get_daughterboard == "RFX400":
                if (get_frequency >= 400) and (get_frequency <= 500):
                    return True
            elif get_daughterboard == "RFX900":
                if (get_frequency >= 750) and (get_frequency <= 1050):
                    return True
            elif get_daughterboard == "RFX1200":
                if (get_frequency >= 1150) and (get_frequency <= 1450):
                    return True
            elif get_daughterboard == "RFX1800":
                if (get_frequency >= 1500) and (get_frequency <= 2100):
                    return True
            elif get_daughterboard == "RFX2400":
                if (get_frequency >= 2300) and (get_frequency <= 2900):
                    return True

        elif get_hardware == "USRP N2xx":
            # Frequency Limits
            if get_daughterboard == "XCVR2450":
                if (get_frequency >= 2400) and (get_frequency <= 6000):
                    return True
            elif get_daughterboard == "DBSRX":
                if (get_frequency >= 800) and (get_frequency <= 2300):
                    return True
            elif get_daughterboard == "SBX-40":
                if (get_frequency >= 400) and (get_frequency <= 4400):
                    return True
            elif get_daughterboard == "UBX-40":
                if (get_frequency >= 10) and (get_frequency <= 6000):
                    return True
            elif get_daughterboard == "WBX-40":
                if (get_frequency >= 50) and (get_frequency <= 2200):
                    return True
            elif get_daughterboard == "CBX-40":
                if (get_frequency >= 1200) and (get_frequency <= 6000):
                    return True
            elif get_daughterboard == "LFRX":
                if (get_frequency >= 0) and (get_frequency <= 30):
                    return True
            elif get_daughterboard == "LFTX":
                if (get_frequency >= 0) and (get_frequency <= 30):
                    return True
            elif get_daughterboard == "BasicRX":
                if (get_frequency >= 1) and (get_frequency <= 250):
                    return True
            elif get_daughterboard == "BasicTX":
                if (get_frequency >= 1) and (get_frequency <= 250):
                    return True
            elif get_daughterboard == "TVRX2":
                if (get_frequency >= 50) and (get_frequency <= 860):
                    return True
            elif get_daughterboard == "RFX400":
                if (get_frequency >= 400) and (get_frequency <= 500):
                    return True
            elif get_daughterboard == "RFX900":
                if (get_frequency >= 750) and (get_frequency <= 1050):
                    return True
            elif get_daughterboard == "RFX1200":
                if (get_frequency >= 1150) and (get_frequency <= 1450):
                    return True
            elif get_daughterboard == "RFX1800":
                if (get_frequency >= 1500) and (get_frequency <= 2100):
                    return True
            elif get_daughterboard == "RFX2400":
                if (get_frequency >= 2300) and (get_frequency <= 2900):
                    return True

        elif get_hardware == "bladeRF 2.0":
            # Frequency Limits
            if (get_frequency >= 47) and (get_frequency <= 6000):
                return True

        elif get_hardware == "USRP X410":
            # Frequency Limits
            if get_daughterboard == "ZBX":
                if (get_frequency >= 1) and (get_frequency <= 7200):
                    return True

        # Not in Bounds
        return False
    

    def populateAttackTreeWidget(self):
        """
        This adds the complete list of attacks to the Attack TreeWidget.
        """
        # Populate the Attack TreeWidget
        all_attacks = (
            self.backend.library["Attacks"]["Single-Stage Attacks"]
            + self.backend.library["Attacks"]["Multi-Stage Attacks"]
            + self.backend.library["Attacks"]["Fuzzing Attacks"]
        )
        parent_item_list = []
        prev_level = 0
        for n in range(0, len(all_attacks)):
            # Get the Attack
            current_attack = all_attacks[n].split(",")

            # Create Item
            new_item = QtWidgets.QTreeWidgetItem()
            new_item.setText(0, current_attack[0])
            new_item.setDisabled(True)
            current_level = int(current_attack[1])

            # Update Parent List
            if len(parent_item_list) <= current_level:
                parent_item_list.append(new_item)
            else:
                parent_item_list[current_level] = new_item

            # Add it to Tree
            if current_level == 0:
                self.ui.treeWidget_attack_attacks.addTopLevelItem(new_item)
            else:
                if current_level >= prev_level:
                    parent_item_list[current_level - 1].addChild(new_item)
                elif current_level < prev_level:
                    level_difference = prev_level - current_level
                    parent_item_list[current_level - level_difference].addChild(new_item)

            # Update prev_level
            prev_level = current_level

        # Bold Categories
        iterator = QtWidgets.QTreeWidgetItemIterator(self.ui.treeWidget_attack_attacks)
        while iterator.value():
            item = iterator.value()
            if item.text(0) in self.backend.library["Attack Categories"]:
                if item.text(0) not in ["New Multi-Stage", "Variables"]:
                    item.setFont(0, QtGui.QFont("Times", 11, QtGui.QFont.Bold))
            iterator += 1
    

    def isFloat(self, x):
        """
        Returns "True" if the input is a Float. Returns "False" otherwise. Move this function to another file?
        """
        try:
            float(x)
        except ValueError:
            return False
        return True


class DashboardScreen(UI_Types.Dashboard):
    def setupUi(self, dashboardWidget: QtWidgets.QWidget, dashboardFrontend: QtCore.QObject):
        super().setupUi(dashboardWidget)

        connect_slots(dashboard=dashboardFrontend)


def connect_slots(dashboard: Dashboard):
    """
    Contains the connect functions for all the signals and slots
    """
    connect_menuBar_slots(dashboard)
    connect_top_bar_slots(dashboard)
    connect_dashboard_slots(dashboard)
    connect_tsi_slots(dashboard)
    connect_pd_slots(dashboard)
    connect_iq_slots(dashboard)
    connect_attack_slots(dashboard)
    connect_archive_slots(dashboard)
    connect_sensor_nodes_slots(dashboard)
    connect_library_slots(dashboard)
    connect_log_slots(dashboard)

    dashboard.signals.ComponentStatus.connect(StatusBarSlots.update_component_status)
    dashboard.signals.Shutdown.connect(lambda: wait_for_backend_shutdown(dashboard))


def connect_top_bar_slots(dashboard: Dashboard):
    # Left Click Sensor Node Buttons
    dashboard.ui.pushButton_top_node1.clicked.connect(lambda: TopBarSlots.sensor_node_leftClick(dashboard, node_idx=0))
    dashboard.ui.pushButton_top_node2.clicked.connect(lambda: TopBarSlots.sensor_node_leftClick(dashboard, node_idx=1))
    dashboard.ui.pushButton_top_node3.clicked.connect(lambda: TopBarSlots.sensor_node_leftClick(dashboard, node_idx=2))
    dashboard.ui.pushButton_top_node4.clicked.connect(lambda: TopBarSlots.sensor_node_leftClick(dashboard, node_idx=3))
    dashboard.ui.pushButton_top_node5.clicked.connect(lambda: TopBarSlots.sensor_node_leftClick(dashboard, node_idx=4))

    # Right Click Sensor Node Buttons
    dashboard.ui.pushButton_top_node1.customContextMenuRequested.connect(
        lambda: TopBarSlots.sensor_node_rightClick(dashboard, node_idx=0)
    )
    dashboard.ui.pushButton_top_node2.customContextMenuRequested.connect(
        lambda: TopBarSlots.sensor_node_rightClick(dashboard, node_idx=1)
    )
    dashboard.ui.pushButton_top_node3.customContextMenuRequested.connect(
        lambda: TopBarSlots.sensor_node_rightClick(dashboard, node_idx=2)
    )
    dashboard.ui.pushButton_top_node4.customContextMenuRequested.connect(
        lambda: TopBarSlots.sensor_node_rightClick(dashboard, node_idx=3)
    )
    dashboard.ui.pushButton_top_node5.customContextMenuRequested.connect(
        lambda: TopBarSlots.sensor_node_rightClick(dashboard, node_idx=4)
    )

    dashboard.ui.pushButton_automation_system_start.clicked.connect(lambda: TopBarSlots.start(dashboard))


def connect_dashboard_slots(dashboard: Dashboard):
    signal.signal(signal.SIGINT, lambda signum, frame: DashboardSlots._slotInterruptHandler(dashboard, signum, frame))
    signal.signal(signal.SIGTERM, lambda signum, frame: DashboardSlots._slotInterruptHandler(dashboard, signum, frame))
    signal.signal(signal.SIGQUIT, lambda signum, frame: DashboardSlots._slotInterruptHandler(dashboard, signum, frame))


def connect_menuBar_slots(dashboard: Dashboard):
    # File Menu
    dashboard.window.actionExit.triggered.connect(lambda: MenuBarSlots._slotMenuFileExitClicked(dashboard))

    # View Menu
    dashboard.window.actionLight_Mode.triggered.connect(lambda: MenuBarSlots.setStyleSheet(dashboard, "light"))
    dashboard.window.actionDark_Mode.triggered.connect(lambda: MenuBarSlots.setStyleSheet(dashboard, "dark"))
    dashboard.window.actionCustom_Mode.triggered.connect(lambda: MenuBarSlots.setStyleSheet(dashboard, "custom"))
    dashboard.window.actionRandom.triggered.connect(lambda: MenuBarSlots.setStyleSheet(dashboard, "random"))

    # Options Menu
    dashboard.window.actionAll_Options.triggered.connect(lambda: MenuBarSlots._slotMenuOptionsClicked(dashboard))
    dashboard.window.actionLoad_Configuration.triggered.connect(
        lambda: MenuBarSlots._slotMenuLoadConfigurationClicked(dashboard)
    )
    dashboard.window.actionSave_Configuration.triggered.connect(
        lambda: MenuBarSlots._slotMenuSaveConfigurationClicked(dashboard)
    )
    dashboard.window.actionRemember_Configuration.triggered.connect(
        lambda: MenuBarSlots._slotMenuRememberConfigurationClicked(dashboard)
    )

    # Standalone Menu
    dashboard.window.actionJ2497_demod_method1.triggered.connect(lambda: MenuBarSlots._slotMenuJ2497_DemodMethod1Clicked(dashboard))
    dashboard.window.actionWifi_rx.triggered.connect(lambda: MenuBarSlots._slotMenuWifiRxClicked(dashboard))
    dashboard.window.actionWifi_tx.triggered.connect(lambda: MenuBarSlots._slotMenuWifiTxClicked(dashboard))
    dashboard.window.actionRds_rx.triggered.connect(lambda: MenuBarSlots._slotMenuRdsRxClicked(dashboard))
    dashboard.window.actionRds_tx.triggered.connect(lambda: MenuBarSlots._slotMenuRdsTxClicked(dashboard))
    dashboard.window.actionX10_tx_rx.triggered.connect(lambda: MenuBarSlots._slotMenuX10_TxRxClicked(dashboard))
    dashboard.window.actionWifi_relay.triggered.connect(lambda: MenuBarSlots._slotMenuWifiRelayClicked(dashboard))
    dashboard.window.actionNoise_source.triggered.connect(lambda: MenuBarSlots._slotMenuNoiseSourceClicked(dashboard))
    dashboard.window.actionStandaloneTpms_rx.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneTpmsRxClicked(dashboard))
    dashboard.window.actionStandaloneTpms_tx.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneTpmsTxClicked(dashboard))
    dashboard.window.actionMorseGen.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneMorseGenClicked(dashboard))
    dashboard.window.actionAntenna_test_rx.triggered.connect(lambda: MenuBarSlots._slotMenuAntennaTestRxClicked(dashboard))
    dashboard.window.actionAntenna_test_tx.triggered.connect(lambda: MenuBarSlots._slotMenuAntennaTestTxClicked(dashboard))
    dashboard.window.actionClapper_Plus_Transmit.triggered.connect(
        lambda: MenuBarSlots._slotMenuStandaloneClapperPlusTransmitClicked(dashboard)
    )
    dashboard.window.actionGarage_Door_Transmit.triggered.connect(
        lambda: MenuBarSlots._slotMenuStandaloneGarageDoorTransmitClicked(dashboard)
    )
    dashboard.window.actionGarage_Door_Cycle.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneGarageDoorCycleClicked(dashboard))
    dashboard.window.actionj2497_mod_hackrfdirect.triggered.connect(
        lambda: MenuBarSlots._slotMenuStandaloneJ2497_ModHackRF_Direct_Clicked(dashboard)
    )
    dashboard.window.actionj2497_mod_fl2k.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneJ2497_fl2kClicked(dashboard))
    dashboard.window.actionj2497_mod.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneJ2497_ModClicked(dashboard))
    dashboard.window.actionfrequency_translating.triggered.connect(
        lambda: MenuBarSlots._slotMenuStandaloneFrequencyTranslatingClicked(dashboard)
    )
    dashboard.window.actionpocsagtx.triggered.connect(lambda: MenuBarSlots._slotMenuStandalone_pocsagtxClicked(dashboard))
    dashboard.window.actionAiS_TX.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneAiS_TX_Clicked(dashboard))
    dashboard.window.actionais_rx_demod.triggered.connect(lambda: MenuBarSlots._slotMenuStandalone_ais_rx_demodClicked(dashboard))
    dashboard.window.actiontesla_charge_port.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneTeslaChargePortClicked(dashboard))

    # Tools Menu
    dashboard.window.actionUhd_find_devices.triggered.connect(lambda: MenuBarSlots._slotMenuUHD_FindDevicesClicked(dashboard))
    dashboard.window.actionHackrf_info.triggered.connect(lambda: MenuBarSlots._slotMenuHackrfInfoClicked(dashboard))
    dashboard.window.actionLsusb.triggered.connect(lambda: MenuBarSlots._slotMenuLsusbClicked(dashboard))
    dashboard.window.actionIwconfig.triggered.connect(lambda: MenuBarSlots._slotMenuIwconfigClicked(dashboard))
    dashboard.window.actionMonitorModeTool.triggered.connect(lambda: MenuBarSlots._slotMenuMonitorModeToolClicked(dashboard))
    dashboard.window.actionLoad_bladeRF_FPGA.triggered.connect(
        lambda: MenuBarSlots._slotMenuLoadBladeRF_FPGA_Clicked(dashboard)
    )
    dashboard.window.actionGsm_uplink_downlink.triggered.connect(MenuBarSlots._slotMenuGSM_UplinkDownlinkClicked)
    dashboard.window.actionQSpectrumAnalyzer.triggered.connect(
        lambda: MenuBarSlots._slotMenuQSpectrumAnalyzerClicked(dashboard)
    )
    dashboard.window.actionGQRX.triggered.connect(lambda: MenuBarSlots._slotMenuGQRX_Clicked(dashboard))
    dashboard.window.actionDump1090.triggered.connect(lambda: MenuBarSlots._slotMenuDump1090_Clicked(dashboard))
    dashboard.window.actionRds_rx_2.triggered.connect(lambda: MenuBarSlots._slotMenuRdsRx2Clicked(dashboard))
    dashboard.window.actionIwlist_scan.triggered.connect(lambda: MenuBarSlots._slotMenuIwlistScanClicked(dashboard))
    dashboard.window.actionKismet.triggered.connect(lambda: MenuBarSlots._slotMenuKismetClicked(dashboard))
    dashboard.window.actionLimeSuiteGUI.triggered.connect(lambda: MenuBarSlots._slotMenuLimeSuite_Clicked(dashboard))
    dashboard.window.actionSrsLTE.triggered.connect(lambda: MenuBarSlots._slotMenuSrsLTE_Clicked(dashboard))
    dashboard.window.actionPaint_tx.triggered.connect(MenuBarSlots._slotMenuPaintTxClicked)
    dashboard.window.actionWireshark.triggered.connect(lambda: MenuBarSlots._slotMenuWiresharkClicked(dashboard))
    dashboard.window.actionBluetoothctl.triggered.connect(lambda: MenuBarSlots._slotMenuBluetoothctlClicked(dashboard))
    dashboard.window.actionV2Verifier.triggered.connect(lambda: MenuBarSlots._slotMenuV2VerifierClicked(dashboard))
    dashboard.window.actionV2Verifier_wifi_tx.triggered.connect(MenuBarSlots._slotMenuV2VerifierWifiTxClicked)
    dashboard.window.actionV2Verifier_wifi_rx.triggered.connect(MenuBarSlots._slotMenuV2VerifierWifiRxClicked)
    dashboard.window.actionFALCON.triggered.connect(lambda: MenuBarSlots._slotMenuFALCON_Clicked(dashboard))
    dashboard.window.actionCyberChef.triggered.connect(MenuBarSlots._slotMenuCyberChefClicked)
    dashboard.window.actionESP8266_beacon_spammer.triggered.connect(MenuBarSlots._slotMenuESP8266BeaconSpammerClicked)
    dashboard.window.actionESP32_BLEBeaconSpam.triggered.connect(MenuBarSlots._slotMenuESP32BLE_BeaconSpamClicked)
    dashboard.window.actionMinicom.triggered.connect(lambda: MenuBarSlots._slotMenuMinicomClicked(dashboard))
    dashboard.window.actionPutty.triggered.connect(lambda: MenuBarSlots._slotMenuPuttyClicked(dashboard))
    dashboard.window.actionOpenHAB.triggered.connect(MenuBarSlots._slotMenuOpenHAB_Clicked)
    dashboard.window.actionStart_openHAB_Service.triggered.connect(
        lambda: MenuBarSlots._slotMenuStart_openHAB_ServiceClicked(dashboard)
    )
    dashboard.window.actionStop_openHAB_Service.triggered.connect(
        lambda: MenuBarSlots._slotMenuStop_openHAB_ServiceClicked(dashboard)
    )
    dashboard.window.actionIEEE_802_15_4_transceiver_OQPSK.triggered.connect(
        MenuBarSlots._slotMenuIEEE_802_15_4_transceiver_OQPSK_Clicked
    )
    dashboard.window.actionRtl_zwave_908_42_MHz.triggered.connect(
        lambda: MenuBarSlots._slotMenuRtlZwave908_Clicked(dashboard)
    )
    dashboard.window.actionRtl_zwave_916_MHz.triggered.connect(lambda: MenuBarSlots._slotMenuRtlZwave916_Clicked(dashboard))
    dashboard.window.actionWaving_z_908_42_MHz.triggered.connect(lambda: MenuBarSlots._slotMenuWavingZ_908_Clicked(dashboard))
    dashboard.window.actionWaving_z_916_MHz.triggered.connect(lambda: MenuBarSlots._slotMenuWavingZ_916_Clicked(dashboard))
    dashboard.window.actionZwave_tx.triggered.connect(MenuBarSlots._slotMenuStandaloneZwaveTxClicked)
    dashboard.window.actionZwave_rx.triggered.connect(MenuBarSlots._slotMenuStandaloneZwaveRxClicked)
    dashboard.window.actionLimeUtilUpdate.triggered.connect(lambda: MenuBarSlots._slotMenuLimeUtilUpdateClicked(dashboard))
    dashboard.window.actionBaudline.triggered.connect(lambda: MenuBarSlots._slotMenuBaudlineClicked(dashboard))
    dashboard.window.actionUniversal_Radio_Hacker.triggered.connect(lambda: MenuBarSlots._slotMenuURH_Clicked(dashboard))
    dashboard.window.action4G_IMSI_Catcher.triggered.connect(lambda: MenuBarSlots._slotMenu4G_IMSI_CatcherClicked(dashboard))
    dashboard.window.actionInspectrum.triggered.connect(lambda: MenuBarSlots._slotMenuInspectrumClicked(dashboard))
    dashboard.window.actionOpenCPN.triggered.connect(lambda: MenuBarSlots._slotMenuOpenCPN_Clicked(dashboard))
    dashboard.window.actionGrgsm_scanner.triggered.connect(lambda: MenuBarSlots._slotMenuGrgsm_scannerClicked(dashboard))
    dashboard.window.actionKalibrate.triggered.connect(lambda: MenuBarSlots._slotMenuKalibrateClicked(dashboard))
    dashboard.window.actionTower_Search.triggered.connect(lambda: MenuBarSlots._slotMenuTowerSearchClicked(dashboard))
    dashboard.window.actionTower_Search_Part_2.triggered.connect(
        lambda: MenuBarSlots._slotMenuTowerSearchPart2Clicked(dashboard)
    )
    dashboard.window.actionRetrogram_rtlsdr.triggered.connect(lambda: MenuBarSlots._slotMenuRetrogramRtlSdrClicked(dashboard))
    dashboard.window.actionRTLSDR_Airband.triggered.connect(lambda: MenuBarSlots._slotMenuRTLSDR_AirbandClicked(dashboard))
    dashboard.window.actionRadio_Reference_Database.triggered.connect(
        MenuBarSlots._slotMenuRadioReferenceDatabaseClicked
    )
    dashboard.window.actionSpektrum.triggered.connect(lambda: MenuBarSlots._slotMenuSpektrumClicked(dashboard))
    dashboard.window.actionRtl_test.triggered.connect(lambda: MenuBarSlots._slotMenuRTL_TestClicked(dashboard))
    dashboard.window.actionSDRTrunk.triggered.connect(lambda: MenuBarSlots._slotMenuSDR_TrunkClicked(dashboard))
    dashboard.window.actionAudacity.triggered.connect(lambda: MenuBarSlots._slotMenuAudacityClicked(dashboard))
    dashboard.window.actionSondeHub_Radiosonde_Tracker.triggered.connect(
        MenuBarSlots._slotMenuSondeHubRadiosondeTrackerClicked
    )
    dashboard.window.actionCellmapper.triggered.connect(MenuBarSlots._slotMenuCellmapperClicked)
    dashboard.window.actionAirLink.triggered.connect(MenuBarSlots._slotMenuAirLinkClicked)
    dashboard.window.actionProxmark3.triggered.connect(MenuBarSlots._slotMenuProxmark3_Clicked)
    dashboard.window.actionProxmark3_Cheatsheet.triggered.connect(
        lambda: MenuBarSlots._slotMenuProxmark3_CheatsheetClicked(dashboard)
    )
    dashboard.window.actionEarth_Nullschool.triggered.connect(MenuBarSlots._slotMenuEarthNullschoolClicked)
    dashboard.window.actionCUSF_Landing_Predictor.triggered.connect(MenuBarSlots._slotMenuCUSF_LandingPredictorClicked)
    dashboard.window.actionFlightAware.triggered.connect(MenuBarSlots._slotMenuFlightAwareClicked)
    dashboard.window.actionRadiosonde_auto_rx.triggered.connect(
        lambda: MenuBarSlots._slotMenuRadiosondeAutoRxClicked(dashboard)
    )
    dashboard.window.actionRadiosonde_auto_rx_Config.triggered.connect(
        MenuBarSlots._slotMenuRadiosondeAutoRxConfigClicked
    )
    dashboard.window.actionSQ6KXY_Radiosonde_Tracker.triggered.connect(
        MenuBarSlots._slotMenuSQ6KXY_RadiosondeTrackerClicked
    )
    dashboard.window.actionSdrGlut.triggered.connect(lambda: MenuBarSlots._slotMenuSdrGlutClicked(dashboard))
    dashboard.window.actionCyberChef_Recipes.triggered.connect(MenuBarSlots._slotMenuCyberChefRecipesClicked)
    dashboard.window.actionRehex.triggered.connect(lambda: MenuBarSlots._slotMenuRehexClicked(dashboard))
    dashboard.window.actionZEPASSD.triggered.connect(lambda: MenuBarSlots._slotMenuZEPASSD_Clicked(dashboard))
    dashboard.window.actionIridium_extractor.triggered.connect(
        lambda: MenuBarSlots._slotMenuIridiumExtractorClicked(dashboard)
    )
    dashboard.window.actionIridium_parser.triggered.connect(lambda: MenuBarSlots._slotMenuIridiumParserClicked(dashboard))
    dashboard.window.actionStats_voc.triggered.connect(lambda: MenuBarSlots._slotMenuStatsVocClicked(dashboard))
    dashboard.window.actionIridiumLive.triggered.connect(lambda: MenuBarSlots._slotMenuIridiumLiveClicked(dashboard))
    dashboard.window.actionNETATTACK2.triggered.connect(lambda: MenuBarSlots._slotMenuNETATTACK2_Clicked(dashboard))
    dashboard.window.actionWifite.triggered.connect(lambda: MenuBarSlots._slotMenuWifiteClicked(dashboard))
    dashboard.window.actionRtl_433.triggered.connect(lambda: MenuBarSlots._slotMenuRtl_433_Clicked(dashboard))
    dashboard.window.actionRouterSploit.triggered.connect(lambda: MenuBarSlots._slotMenuRouterSploitClicked(dashboard))
    dashboard.window.actionExploit_Database.triggered.connect(MenuBarSlots._slotMenuExploitDatabaseClicked)
    dashboard.window.actionMetasploit.triggered.connect(lambda: MenuBarSlots._slotMenuMetasploitClicked(dashboard))
    dashboard.window.actionMonitor_rtl433.triggered.connect(lambda: MenuBarSlots._slotMenuMonitor_rtl433_Clicked(dashboard))
    dashboard.window.actionWiGLE_net.triggered.connect(MenuBarSlots._slotMenuWiGLE_Clicked)
    dashboard.window.actionScan_ssid.triggered.connect(lambda: MenuBarSlots._slotMenuScan_SSID_Clicked(dashboard))
    dashboard.window.actionPySim_read.triggered.connect(lambda: MenuBarSlots._slotMenuPySimReadClicked(dashboard))
    dashboard.window.actionPySim_prog.triggered.connect(lambda: MenuBarSlots._slotMenuPySimProgClicked(dashboard))
    dashboard.window.actionMinimodem_rx.triggered.connect(lambda: MenuBarSlots._slotMenuMinimodemRxClicked(dashboard))
    dashboard.window.actionMinimodem_tx.triggered.connect(lambda: MenuBarSlots._slotMenuMinimodemTxClicked(dashboard))
    dashboard.window.actionWSJT_X.triggered.connect(lambda: MenuBarSlots._slotMenuWSJTX_Clicked(dashboard))
    dashboard.window.actionWSPRnet_Map.triggered.connect(MenuBarSlots._slotMenuWSPRnetMapClicked)
    dashboard.window.actionZigbeeOpen_Sniffer.triggered.connect(
        lambda: MenuBarSlots._slotMenuZigbeeOpenSnifferClicked(dashboard)
    )
    dashboard.window.actionVLC.triggered.connect(lambda: MenuBarSlots._slotMenuVLC_Clicked(dashboard))
    dashboard.window.actionSimpleScreenRecorder.triggered.connect(
        lambda: MenuBarSlots._slotMenuSimpleScreenRecorderClicked(dashboard)
    )
    dashboard.window.actionPixie_Dust_List.triggered.connect(MenuBarSlots._slotMenuPixieDustListClicked)
    dashboard.window.actionAudioRecord.triggered.connect(lambda: MenuBarSlots._slotMenuAudioRecordClicked(dashboard))
    dashboard.window.actionGoogle_Earth_Pro.triggered.connect(lambda: MenuBarSlots._slotMenuGoogleEarthProClicked(dashboard))
    dashboard.window.actionGr_air_modes.triggered.connect(lambda: MenuBarSlots._slotMenuGrAirModesClicked(dashboard))
    dashboard.window.actionEsp8266_deauther_ino.triggered.connect(
        lambda: MenuBarSlots._slotMenuESP8266_DeautherInoClicked(dashboard)
    )
    dashboard.window.actionESP8266_Deauther_Web_Interface.triggered.connect(
        MenuBarSlots._slotMenuESP8266_DeautherWebInterfaceClicked
    )
    dashboard.window.actionESP8266_Deauther_Credentials.triggered.connect(
        MenuBarSlots._slotMenuESP8266_DeautherCredentialsClicked
    )
    dashboard.window.actionLow_Earth_Orbit_Visualization.triggered.connect(
        MenuBarSlots._slotMenuLowEarthVisualizationClicked
    )
    dashboard.window.actionLeoLabs_Catalog.triggered.connect(MenuBarSlots._slotMenuLeoLabsCatalogClicked)
    dashboard.window.actionCgps.triggered.connect(lambda: MenuBarSlots._slotMenuCgpsClicked(dashboard))
    dashboard.window.actionGpsdecode.triggered.connect(lambda: MenuBarSlots._slotMenuGpsdecodeClicked(dashboard))
    dashboard.window.actionGpsmon.triggered.connect(lambda: MenuBarSlots._slotMenuGpsmonClicked(dashboard))
    dashboard.window.actionXgps.triggered.connect(lambda: MenuBarSlots._slotMenuXgpsClicked(dashboard))
    dashboard.window.actionXgpsspeed.triggered.connect(lambda: MenuBarSlots._slotMenuXgpsspeedClicked(dashboard))
    dashboard.window.actionViking.triggered.connect(lambda: MenuBarSlots._slotMenuVikingClicked(dashboard))
    dashboard.window.actionPyGPSClient.triggered.connect(lambda: MenuBarSlots._slotMenuPyGPSClientClicked(dashboard))
    dashboard.window.actionRadio_Station_Locator.triggered.connect(MenuBarSlots._slotMenuRadioStationLocator)
    dashboard.window.actionLiveATC_net.triggered.connect(MenuBarSlots._slotMenuLiveATCnetClicked)
    dashboard.window.actionFlightradar24.triggered.connect(MenuBarSlots._slotMenuFlightradar24_Clicked)
    dashboard.window.actionFlightStats.triggered.connect(MenuBarSlots._slotMenuFlightStatsClicked)
    dashboard.window.actionPlane_Finder.triggered.connect(MenuBarSlots._slotMenuPlaneFinderClicked)
    dashboard.window.actionUS_County_Overlays.triggered.connect(MenuBarSlots._slotMenuUS_CountyOverlaysClicked)
    dashboard.window.actionAM_Query.triggered.connect(MenuBarSlots._slotMenuAM_QueryClicked)
    dashboard.window.actionFM_Query.triggered.connect(MenuBarSlots._slotMenuFM_QueryClicked)
    dashboard.window.actionRadio_Garden.triggered.connect(MenuBarSlots._slotMenuRadioGardenClicked)
    dashboard.window.actionDiffchecker.triggered.connect(MenuBarSlots._slotMenuDiffcheckerClicked)
    dashboard.window.actionEvery_Time_Zone.triggered.connect(MenuBarSlots._slotMenuEveryTimeZoneClicked)
    dashboard.window.actionCloudConvert.triggered.connect(MenuBarSlots._slotMenuCloudConvertClicked)
    dashboard.window.actionAcars_demo.triggered.connect(MenuBarSlots._slotMenuAcarsDemoClicked)
    dashboard.window.actionGpredict.triggered.connect(lambda: MenuBarSlots._slotMenuGpredictClicked(dashboard))
    dashboard.window.actionTechInfoDepot.triggered.connect(MenuBarSlots._slotMenuTechInfoDepotClicked)
    dashboard.window.actionWikiDevi.triggered.connect(MenuBarSlots._slotMenuWikiDeviClicked)
    dashboard.window.actionAPT3000.triggered.connect(MenuBarSlots._slotMenuApt3000_Clicked)
    dashboard.window.actionHabhub_tracker.triggered.connect(MenuBarSlots._slotMenuHabhubTrackerClicked)
    dashboard.window.actionFoxtrotGPS.triggered.connect(lambda: MenuBarSlots._slotMenuFoxtrotGPS_Clicked(dashboard))
    dashboard.window.actionGoogle_Maps_APRS.triggered.connect(MenuBarSlots._slotMenuGoogleMapsAPRS_Clicked)
    dashboard.window.actionAPRS_multimon_ng.triggered.connect(lambda: MenuBarSlots._slotMenuAPRSmultimon_ngClicked(dashboard))
    dashboard.window.actionLTE_Cell_Scanner.triggered.connect(lambda: MenuBarSlots._slotMenuLTE_CellScannerClicked(dashboard))
    dashboard.window.actionEsri_Satellite_Map.triggered.connect(MenuBarSlots._slotMenu_esriSatelliteMapClicked)
    dashboard.window.actionBtrx.triggered.connect(lambda: MenuBarSlots._slotMenuBtrxClicked(dashboard))
    dashboard.window.actionBle_dump.triggered.connect(lambda: MenuBarSlots._slotMenuBleDumpTriggered(dashboard))
    dashboard.window.actionFlash_ESP32_Board.triggered.connect(
        lambda: MenuBarSlots._slotMenuFlashESP32_BoardClicked(dashboard)
    )
    dashboard.window.actionBTSnifferBREDR.triggered.connect(lambda: MenuBarSlots._slotMenuBT_SnifferBREDR_Clicked(dashboard))
    dashboard.window.actionHcitool_scan.triggered.connect(lambda: MenuBarSlots._slotMenuHcitoolScanClicked(dashboard))
    dashboard.window.actionSdptool_browse.triggered.connect(lambda: MenuBarSlots._slotMenuSdptoolBrowseClicked(dashboard))
    dashboard.window.actionHcitool_inq.triggered.connect(lambda: MenuBarSlots._slotMenuHcitoolInqClicked(dashboard))
    dashboard.window.actionDevice_Class_List.triggered.connect(MenuBarSlots._slotMenuDeviceClassListClicked)
    dashboard.window.actionBtclassify.triggered.connect(lambda: MenuBarSlots._slotMenuBtclassifyClicked(dashboard))
    dashboard.window.actionL2ping.triggered.connect(lambda: MenuBarSlots._slotMenuL2pingClicked(dashboard))
    dashboard.window.actionBtscanner.triggered.connect(lambda: MenuBarSlots._slotMenuBtscannerClicked(dashboard))
    dashboard.window.actionHcidump.triggered.connect(lambda: MenuBarSlots._slotMenuHcidumpClicked(dashboard))
    dashboard.window.actionFM_Radio_Capture.triggered.connect(MenuBarSlots._slotMenuStandaloneFM_RadioCaptureClicked)
    dashboard.window.actionUhd_image_loader.triggered.connect(lambda: MenuBarSlots._slotMenuUHD_ImageLoaderClicked(dashboard))
    dashboard.window.actionTinyWow.triggered.connect(MenuBarSlots._slotMenuTinyWowClicked)
    dashboard.window.actionGr_paint_Converter.triggered.connect(
        lambda: MenuBarSlots._slotMenuGrPaintConverterClicked(dashboard)
    )
    dashboard.window.actionNrsc5.triggered.connect(lambda: MenuBarSlots._slotMenuNrsc5_Clicked(dashboard))
    dashboard.window.actionHd_tx_usrp.triggered.connect(MenuBarSlots._slotMenuStandaloneHd_tx_usrpClicked)
    dashboard.window.action2022_2026_Technician_Pool.triggered.connect(
        lambda: MenuBarSlots._slotMenu2022_2026_TechnicianPoolClicked(dashboard)
    )
    dashboard.window.actionLicense_Search.triggered.connect(MenuBarSlots._slotMenuLicenseSearchClicked)
    dashboard.window.actionAnki.triggered.connect(lambda: MenuBarSlots._slotMenuAnkiClicked(dashboard))
    dashboard.window.actionAnki_Decks.triggered.connect(MenuBarSlots._slotMenuAnkiDecksClicked)
    dashboard.window.actionAntennaSearch.triggered.connect(MenuBarSlots._slotMenuAntennaSearchClicked)
    dashboard.window.actionCommand_Class_Specification.triggered.connect(
        lambda: MenuBarSlots._slotMenuCommandClassSpecificationClicked(dashboard)
    )
    dashboard.window.actionCommand_Class_List.triggered.connect(MenuBarSlots._slotMenuCommandClassListClicked)
    dashboard.window.actionSCADACore_RF_Line_of_Sight.triggered.connect(
        MenuBarSlots._slotMenuSCADACoreRF_LineOfSightClicked
    )
    dashboard.window.actionOnline_Hex_Converter.triggered.connect(MenuBarSlots._slotMenuOnlineHexConverterClicked)
    dashboard.window.actionExam_Locations.triggered.connect(MenuBarSlots._slotMenuExamLocationsClicked)
    dashboard.window.actionEchoLink_Link_Status.triggered.connect(MenuBarSlots._slotMenuEchoLinkLinkStatusClicked)
    dashboard.window.actionSolarHam.triggered.connect(MenuBarSlots._slotMenuSolarHamClicked)
    dashboard.window.actionBless.triggered.connect(lambda: MenuBarSlots._slotMenuBlessHexEditorClicked(dashboard))
    dashboard.window.actionTrackerjacker.triggered.connect(lambda: MenuBarSlots._slotMenuTrackjackerClicked(dashboard))
    dashboard.window.actionSanitized_IEEE_OUI_Data.triggered.connect(MenuBarSlots._slotMenuSanitizedIEEE_OUI_DataClicked)
    dashboard.window.actionMarineTraffic.triggered.connect(MenuBarSlots._slotMenuMarineTrafficClicked)
    dashboard.window.actionVesselFinder.triggered.connect(MenuBarSlots._slotMenuVesselFinderClicked)
    dashboard.window.actionBoatnerd.triggered.connect(MenuBarSlots._slotMenuBoatnerdClicked)
    dashboard.window.actionCruiseMapper.triggered.connect(MenuBarSlots._slotMenuCruiseMapperClicked)
    dashboard.window.actionADS_B_Exchange.triggered.connect(MenuBarSlots._slotMenuADSB_ExchangeClicked)
    dashboard.window.actionHow_to_File.triggered.connect(MenuBarSlots._slotMenuHowToFileClicked)
    dashboard.window.actionRadioQTH_Available_Call_Signs.triggered.connect(MenuBarSlots._slotMenuRadioQTH_Clicked)
    dashboard.window.actionAE7Q_Available_Call_Signs.triggered.connect(MenuBarSlots._slotMenuAE7Q_Clicked)
    dashboard.window.actionAirgeddon.triggered.connect(lambda: MenuBarSlots._slotMenuAirgeddonClicked(dashboard))
    dashboard.window.actionwhoishere_py_2.triggered.connect(lambda: MenuBarSlots._slotMenuWhoisherePyClicked(dashboard))
    dashboard.window.actionwhoishere_conf.triggered.connect(MenuBarSlots._slotMenuWhoishereConfClicked)
    dashboard.window.actionHydra.triggered.connect(lambda: MenuBarSlots._slotMenuHydraClicked(dashboard))
    dashboard.window.actionSecLists.triggered.connect(MenuBarSlots._slotMenuSecListsClicked)
    dashboard.window.actionssh_login.triggered.connect(lambda: MenuBarSlots._slotMenu_ssh_loginClicked(dashboard))
    dashboard.window.actionMetasploit_Wordlists.triggered.connect(MenuBarSlots._slotMenuMetasploitWordlistsClicked)
    dashboard.window.actionOpenSSH_Username_Enumeration.triggered.connect(
        lambda: MenuBarSlots._slotMenuOpenSSH_UsernameEnumerationClicked(dashboard)
    )
    dashboard.window.action2019_2023_General_Pool.triggered.connect(
        lambda: MenuBarSlots._slotMenu2019_2023_GeneralPoolClicked(dashboard)
    )
    dashboard.window.actionnrsc5_gui.triggered.connect(lambda: MenuBarSlots._slotMenuNrsc5_GuiClicked(dashboard))
    dashboard.window.actionEnscribe.triggered.connect(lambda: MenuBarSlots._slotMenuEnscribeClicked(dashboard))
    dashboard.window.actionOpen_weather.triggered.connect(MenuBarSlots._slotMenuOpenWeatherClicked)
    dashboard.window.actionLTE_ciphercheck.triggered.connect(lambda: MenuBarSlots._slotMenuLTE_ciphercheckClicked(dashboard))
    dashboard.window.actionIIO_Oscilloscope.triggered.connect(
        lambda: MenuBarSlots._slotMenuIIO_OscilloscopeClicked(dashboard)
    )
    dashboard.window.actionSigDigger.triggered.connect(lambda: MenuBarSlots._slotMenuSigDiggerClicked(dashboard))
    dashboard.window.actionham2mon.triggered.connect(lambda: MenuBarSlots._slotMenuHam2monClicked(dashboard))
    dashboard.window.actionQSSTV.triggered.connect(lambda: MenuBarSlots._slotMenuQSSTV_Clicked(dashboard))
    dashboard.window.actionm17_demod.triggered.connect(lambda: MenuBarSlots._slotMenu_m17_demodClicked(dashboard))
    dashboard.window.actionmultimon_ng.triggered.connect(lambda: MenuBarSlots._slotMenuMultimon_ngClicked(dashboard))
    dashboard.window.actionFldigi.triggered.connect(lambda: MenuBarSlots._slotMenuFldigiClicked(dashboard))
    dashboard.window.actiontriq_org.triggered.connect(MenuBarSlots._slotMenuTriqOrgClicked)
    dashboard.window.actionpyFDA.triggered.connect(lambda: MenuBarSlots._slotMenuPyFDA_Clicked(dashboard))
    dashboard.window.actionMorse_Code_Translator.triggered.connect(MenuBarSlots._slotMenuMorseCodeTranslatorClicked)
    dashboard.window.actionPSK_Reporter.triggered.connect(MenuBarSlots._slotMenuPSK_ReporterClicked)
    dashboard.window.actionAmateur_Satellite_Database.triggered.connect(
        MenuBarSlots._slotMenuAmateurSatelliteDatabaseClicked
    )
    dashboard.window.actioncryptii.triggered.connect(MenuBarSlots._slotMenuCryptiiClicked)
    dashboard.window.actionDire_Wolf.triggered.connect(lambda: MenuBarSlots._slotMenuDireWolfClicked(dashboard))
    dashboard.window.actionMeld.triggered.connect(lambda: MenuBarSlots._slotMenuMeldClicked(dashboard))
    dashboard.window.actionhfpropagation_com.triggered.connect(MenuBarSlots._slotMenuHfpropagationClicked)
    dashboard.window.actionWaveDrom.triggered.connect(MenuBarSlots._slotMenuWaveDromClicked)
    dashboard.window.actionPacket_Diagram.triggered.connect(lambda: MenuBarSlots._slotMenuPacketDiagramClicked(dashboard))
    dashboard.window.actionHamClock.triggered.connect(lambda: MenuBarSlots._slotMenuHamClockTriggered(dashboard))
    dashboard.window.actionICE9_Bluetooth_Scanner.triggered.connect(
        lambda: MenuBarSlots._slotMenuICE9_BluetoothSnifferClicked(dashboard)
    )
    dashboard.window.actiondump978.triggered.connect(lambda: MenuBarSlots._slotMenu_dump978_Clicked(dashboard))
    dashboard.window.actionIQEngine.triggered.connect(MenuBarSlots._slotMenuIQEngineClicked)
    dashboard.window.actionrfidpics.triggered.connect(MenuBarSlots._slotMenu_rfidpicsClicked)
    dashboard.window.actionacars_adsbexchange.triggered.connect(MenuBarSlots._slotMenu_acars_adsbexchangeClicked)
    dashboard.window.actionAirframes.triggered.connect(MenuBarSlots._slotMenuAirframesClicked)
    dashboard.window.actionhtop.triggered.connect(lambda: MenuBarSlots._slotMenu_htopClicked(dashboard))
    dashboard.window.actionWSPR_Rocks.triggered.connect(MenuBarSlots._slotMenu_WSPR_RocksClicked)
    dashboard.window.actionwttr_in.triggered.connect(lambda: MenuBarSlots._slotMenu_wttr_inClicked(dashboard))
    dashboard.window.actiongrip.triggered.connect(lambda: MenuBarSlots._slotMenuGripClicked(dashboard))
    dashboard.window.actionArduino.triggered.connect(lambda: MenuBarSlots._slotMenuArduinoClicked(dashboard))
    dashboard.window.actionguidus.triggered.connect(lambda: MenuBarSlots._slotMenu_guidusClicked(dashboard))
    dashboard.window.actionSystemback.triggered.connect(lambda: MenuBarSlots._slotMenuSystembackClicked(dashboard))
    dashboard.window.actionOpenWebRX.triggered.connect(lambda: MenuBarSlots._slotMenuOpenWebRX_Clicked(dashboard))
    dashboard.window.actionTuneIn_Explorer.triggered.connect(MenuBarSlots._slotMenuTuneInExplorerClicked)
    dashboard.window.actionGpick.triggered.connect(lambda: MenuBarSlots._slotMenuGpickClicked(dashboard))
    dashboard.window.actioncomplextoreal_com.triggered.connect(MenuBarSlots._slotMenuLessonComplexToRealClicked)
    dashboard.window.actionSolve_Crypto_with_Force.triggered.connect(MenuBarSlots._slotMenuSolveCryptoWithForceClicked)
    dashboard.window.actionCrackStation.triggered.connect(MenuBarSlots._slotMenuCrackStationClicked)
    dashboard.window.actionGHex.triggered.connect(lambda: MenuBarSlots._slotMenuGHexClicked(dashboard))
    dashboard.window.actionqFlipper.triggered.connect(lambda: MenuBarSlots._slotMenu_qFlipperClicked(dashboard))
    dashboard.window.actionAIVDM_AIVDO_Decoding.triggered.connect(MenuBarSlots._slotMenuAIVDM_AIVDO_DecodingClicked)
    dashboard.window.actionAIS_VDM_VDO_Decoder.triggered.connect(MenuBarSlots._slotMenuAIS_VDM_VDO_DecoderClicked)
    dashboard.window.actionAIS_Online_Decoder.triggered.connect(MenuBarSlots._slotMenuAIS_OnlineDecoderClicked)
    dashboard.window.actionpyais_GitHub.triggered.connect(MenuBarSlots._slotMenu_pyaisGitHubClicked)
    dashboard.window.actionADS_B_Towers.triggered.connect(MenuBarSlots._slotMenuADSB_TowersClicked)
    dashboard.window.actionAPRS_Track_Direct.triggered.connect(MenuBarSlots._slotMenuAPRS_TrackDirectClicked)
    dashboard.window.actionOpenRailwayMap.triggered.connect(MenuBarSlots._slotMenuOpenRailwayMapClicked)
    dashboard.window.actionOrbital_Element_Converter.triggered.connect(
        MenuBarSlots._slotMenuOrbitalElementConverterClicked
    )
    dashboard.window.actionSatellite_Link_Budget.triggered.connect(MenuBarSlots._slotMenuSatelliteLinkBudgetClicked)
    dashboard.window.actionWebSDR.triggered.connect(MenuBarSlots._slotMenuWebSDR_Clicked)
    dashboard.window.actionGPSJAM.triggered.connect(MenuBarSlots._slotMenuGPSJAM_Clicked)
    dashboard.window.actionHF_Propagation_Map.triggered.connect(MenuBarSlots._slotMenuHF_PropagationMapClicked)
    dashboard.window.actionHAMRS.triggered.connect(lambda: MenuBarSlots._slotMenuHAMRS_Clicked(dashboard))
    dashboard.window.actionMLAT_Feeder_Map.triggered.connect(MenuBarSlots._slotMenuMLAT_FeederMapClicked)
    dashboard.window.actionBinwalk.triggered.connect(lambda: MenuBarSlots._slotMenuBinwalkClicked(dashboard))
    dashboard.window.actionN2YO.triggered.connect(MenuBarSlots._slotMenuN2YO_Clicked)
    dashboard.window.actionFind_Satellites.triggered.connect(MenuBarSlots._slotMenuFindSatellitesClicked)
    dashboard.window.actionAGSatTrack.triggered.connect(MenuBarSlots._slotMenuAGSatTrackClicked)
    dashboard.window.actionCelestrak.triggered.connect(MenuBarSlots._slotMenuCelestrakClicked)
    dashboard.window.actionSpot_The_Station.triggered.connect(MenuBarSlots._slotMenuSpotTheStationClicked)
    dashboard.window.actionwl_color_picker.triggered.connect(MenuBarSlots._slotMenuWlColorPickerClicked)
    dashboard.window.actiontpms_rx.triggered.connect(MenuBarSlots._slotMenuTpmsRxClicked)
    
    # Lessons
    dashboard.window.actionLessonOpenBTS.triggered.connect(MenuBarSlots._slotMenuLessonOpenBTS_Clicked)
    dashboard.window.actionLessonLuaDissectors.triggered.connect(MenuBarSlots._slotMenuLessonLuaDissectorsClicked)
    dashboard.window.actionLessonSound_eXchange.triggered.connect(MenuBarSlots._slotMenuLessonSound_eXchangeClicked)
    dashboard.window.actionLessonESP_Boards.triggered.connect(MenuBarSlots._slotMenuESP_BoardClicked)
    dashboard.window.actionLessonRadiosondeTracking.triggered.connect(
        MenuBarSlots._slotMenuLessonRadiosondeTrackingClicked
    )
    dashboard.window.actionLessonRFID.triggered.connect(MenuBarSlots._slotMenuLessonRFID_Clicked)
    dashboard.window.actionLesson_Data_Types.triggered.connect(MenuBarSlots._slotMenuLessonDataTypesClicked)
    dashboard.window.actionLesson_Custom_GNU_Radio_Blocks.triggered.connect(
        MenuBarSlots._slotMenuLessonCustomGNU_RadioBlocksClicked
    )
    dashboard.window.actionLesson_TPMS.triggered.connect(MenuBarSlots._slotMenuLessonTPMS_Clicked)
    dashboard.window.actionLesson_Ham_Radio_Exams.triggered.connect(MenuBarSlots._slotMenuLessonHamRadioExamsClicked)
    dashboard.window.actionLesson_WiFi_Tools.triggered.connect(MenuBarSlots._slotMenuLessonWiFiToolsClicked)
    dashboard.window.actionPySDR_org.triggered.connect(MenuBarSlots._slotMenuHelpPySDR_orgClicked)
    dashboard.window.actionLessonSDR_WithHackRF.triggered.connect(MenuBarSlots._slotMenuLessonSDR_WithHackRF_Clicked)
    dashboard.window.actionGNU_Radio_Tutorials.triggered.connect(MenuBarSlots._slotMenuLessonGNU_RadioTutorialsClicked)
    dashboard.window.actionProgramming_SDRs_with_GNU_Radio.triggered.connect(
        MenuBarSlots._slotMenuLessonProgrammingSDRsClicked
    )
    dashboard.window.actionLearn_SDR.triggered.connect(MenuBarSlots._slotMenuLessonLearnSDR_Clicked)
    dashboard.window.actionLesson_Creating_Bootable_USBs.triggered.connect(
        MenuBarSlots._slotMenuLessonCreatingBootableUSBsClicked
    )
    dashboard.window.actioncemaxecuter_YouTube.triggered.connect(MenuBarSlots._slotMenuCemaxecuterYouTubeClicked)
    dashboard.window.actionIceman_YouTube.triggered.connect(MenuBarSlots._slotMenuIcemanYouTubeClicked)
    dashboard.window.actionHideo_Okawara.triggered.connect(MenuBarSlots._slotMenuLessonHideoOkawaraClicked)

    # Help Menu
    dashboard.window.actionUser_Manual.triggered.connect(MenuBarSlots.openUserManual)
    ##################
    # dashboard.window.actionUser_Manual.triggered.connect(MenuBarSlots._slotMenuHelpUserManualClicked)
    dashboard.window.actionProtocol_Spreadsheet.triggered.connect(MenuBarSlots._slotMenuProtocolSpreadsheetClicked)
    dashboard.window.actionSignal_Identification_Guide.triggered.connect(
        MenuBarSlots._slotMenuSignalIdentificationGuideClicked
    )
    dashboard.window.actionFccID_Lookup.triggered.connect(MenuBarSlots._slotMenuFCC_ID_LookupClicked)
    dashboard.window.actionUS_Frequency_Allocations.triggered.connect(
        lambda: MenuBarSlots._slotMenuUS_FrequencyAllocationsClicked(dashboard)
    )
    dashboard.window.actionRoundup_of_SDRs.triggered.connect(MenuBarSlots._slotMenuRoundup_ofSDRsClicked)
    dashboard.window.actionList_of_SDRs.triggered.connect(MenuBarSlots._slotMenuList_ofSDRsClicked)
    dashboard.window.actionFSPL_Calculator.triggered.connect(MenuBarSlots._slotMenuFSPL_CalculatorClicked)
    dashboard.window.actionProtocol_CSV.triggered.connect(MenuBarSlots._slotMenuProtocolCSV_Clicked)
    dashboard.window.actionAntenna_Comparison.triggered.connect(MenuBarSlots._slotMenuAntennaComparisonClicked)
    dashboard.window.actionWavelength_Calculator.triggered.connect(MenuBarSlots._slotMenuWavelengthCalculatorClicked)
    dashboard.window.actionGitHub_FISSURE.triggered.connect(MenuBarSlots._slotMenuGitHubFISSURE_Clicked)
    dashboard.window.actionGitHub_cpoore1.triggered.connect(MenuBarSlots._slotMenuGitHub_cpoore1_Clicked)
    dashboard.window.actionGitHub_ainfosec.triggered.connect(MenuBarSlots._slotMenuGitHub_ainfosecClicked)
    dashboard.window.actionElectromagnetic_Radiation_Spectrum.triggered.connect(
        MenuBarSlots._slotMenuElectromagneticRadiationSpectrumClicked
    )
    dashboard.window.actionDiscord.triggered.connect(MenuBarSlots._slotMenuHelpDiscordClicked)
    dashboard.window.actionFissureDashboard_ui.triggered.connect(lambda: MenuBarSlots._slotMenuFissureDashboardUiClicked(dashboard))
    dashboard.window.actiondashboard_ui.triggered.connect(
        lambda: MenuBarSlots._slotMenuQtDesignerDashboardUiClicked(dashboard)
    )
    dashboard.window.actionoptions_ui.triggered.connect(lambda: MenuBarSlots._slotMenuQtDesignerOptionsUiClicked(dashboard))
    dashboard.window.actionYouTube.triggered.connect(MenuBarSlots._slotMenuYouTubeClicked)
    dashboard.window.actionRequirements.triggered.connect(MenuBarSlots._slotMenuHelpRequirementsClicked)
    dashboard.window.actionCloning.triggered.connect(MenuBarSlots._slotMenuHelpCloningClicked)
    dashboard.window.actionInstaller.triggered.connect(MenuBarSlots._slotMenuHelpInstallerClicked)
    dashboard.window.actionUninstalling.triggered.connect(MenuBarSlots._slotMenuHelpUninstallingClicked)
    dashboard.window.actionUsage.triggered.connect(MenuBarSlots._slotMenuHelpUsageClicked)
    dashboard.window.actionKnown_Conflicts.triggered.connect(MenuBarSlots._slotMenuHelpKnownConflictsClicked)
    dashboard.window.actionThird_Party_Software_2.triggered.connect(MenuBarSlots._slotMenuHelpThirdPartySoftwareClicked)
    dashboard.window.actionThird_Party_Software_Versions.triggered.connect(
        MenuBarSlots._slotMenuHelpThirdPartySoftwareVersionsClicked
    )
    dashboard.window.actionSupported.triggered.connect(MenuBarSlots._slotMenuHelpHardwareSupportedClicked)
    dashboard.window.actionConfiguring.triggered.connect(MenuBarSlots._slotMenuHelpHardwareConfiguringClicked)
    dashboard.window.actionHelpLimeSDR.triggered.connect(MenuBarSlots._slotMenuHelpHardwareLimeSDR_Clicked)
    dashboard.window.actionHelpNewUSRPX310.triggered.connect(MenuBarSlots._slotMenuHelpHardwareNewUSRPX310_Clicked)
    dashboard.window.actionHelpUpdatingHackRF.triggered.connect(MenuBarSlots._slotMenuHelpHardwareUpdatingHackRFClicked)
    dashboard.window.actionGNU_Radio_Hardware.triggered.connect(
        MenuBarSlots._slotMenuHelpHardwareGNU_RadioHardwareClicked
    )
    dashboard.window.actionCommunications.triggered.connect(MenuBarSlots._slotMenuHelpComponentsCommunicationsClicked)
    dashboard.window.actionLibrary.triggered.connect(MenuBarSlots._slotMenuHelpComponentsLibraryClicked)
    dashboard.window.actionFile_Structure.triggered.connect(MenuBarSlots._slotMenuHelpComponentsFileStructureClicked)
    dashboard.window.actionSupported_Protocols.triggered.connect(
        MenuBarSlots._slotMenuHelpComponentsSupportedProtocolsClicked
    )
    dashboard.window.actionDashboard.triggered.connect(MenuBarSlots._slotMenuHelpComponentsDashboardClicked)
    dashboard.window.actionTarget_Signal_Identification.triggered.connect(
        MenuBarSlots._slotMenuHelpComponentsTSI_Clicked
    )
    dashboard.window.actionProtocol_Discovery.triggered.connect(MenuBarSlots._slotMenuHelpComponentsPD_Clicked)
    dashboard.window.actionFlow_Graph_Script_Executor.triggered.connect(MenuBarSlots._slotMenuHelpComponentsFGE_Clicked)
    dashboard.window.actionHIPRFISR.triggered.connect(MenuBarSlots._slotMenuHelpComponentsHIPRFISR_Clicked)
    dashboard.window.actionHardware_Buttons.triggered.connect(MenuBarSlots._slotMenuHelpOperationHardwareButtonsClicked)
    dashboard.window.actionNetworking_Configuration.triggered.connect(
        MenuBarSlots._slotMenuHelpOperationNetworkingConfigurationClicked
    )
    dashboard.window.actionLessons.triggered.connect(MenuBarSlots._slotMenuHelpOperationLessonsClicked)
    dashboard.window.actionStandalone_Flow_Graphs.triggered.connect(
        MenuBarSlots._slotMenuHelpOperationStandaloneFlowGraphsClicked
    )
    dashboard.window.actionTools.triggered.connect(MenuBarSlots._slotMenuHelpOperationToolsClicked)
    dashboard.window.actionOptions.triggered.connect(MenuBarSlots._slotMenuHelpOperationOptionsClicked)
    dashboard.window.actionView.triggered.connect(MenuBarSlots._slotMenuHelpOperationViewClicked)
    dashboard.window.actionAutomation_Tab.triggered.connect(MenuBarSlots._slotMenuHelpOperationAutomationClicked)
    dashboard.window.actionTSI_Tab.triggered.connect(MenuBarSlots._slotMenuHelpOperationTSI_Clicked)
    dashboard.window.actionPD_Tab.triggered.connect(MenuBarSlots._slotMenuHelpOperationPD_Clicked)
    dashboard.window.actionAttack_Tab.triggered.connect(MenuBarSlots._slotMenuHelpOperationAttackClicked)
    dashboard.window.actionIQ_Data_Tab.triggered.connect(MenuBarSlots._slotMenuHelpOperationIQ_DataClicked)
    dashboard.window.actionArchive_Tab.triggered.connect(MenuBarSlots._slotMenuHelpOperationArchiveClicked)
    dashboard.window.actionPacket_Crafter_Tab.triggered.connect(MenuBarSlots._slotMenuHelpOperationPacketCrafterClicked)
    dashboard.window.actionLibrary_Tab.triggered.connect(MenuBarSlots._slotMenuHelpOperationLibraryClicked)
    dashboard.window.actionLog_Tab.triggered.connect(MenuBarSlots._slotMenuHelpOperationLogClicked)
    dashboard.window.actionStatus_Bar.triggered.connect(MenuBarSlots._slotMenuHelpOperationStatusBarClicked)
    dashboard.window.actionAddingCustomOptions.triggered.connect(
        MenuBarSlots._slotMenuHelpDevelopmentAddingCustomOptionsClicked
    )
    dashboard.window.actionHelpBuiltWith.triggered.connect(MenuBarSlots._slotMenuHelpDevelopmentBuiltWithClicked)
    dashboard.window.actionHelpUploadingFlowGraphs.triggered.connect(
        MenuBarSlots._slotMenuHelpDevelopmentUploadingFlowGraphsClicked
    )
    dashboard.window.actionHelpUploadingPythonScripts.triggered.connect(
        MenuBarSlots._slotMenuHelpDevelopmentUploadingPythonScriptsClicked
    )
    dashboard.window.actionInspection_Flow_Graphs.triggered.connect(
        MenuBarSlots._slotMenuHelpDevelopmentInspectionFlowGraphsClicked
    )
    dashboard.window.actionModifying_Dashboard.triggered.connect(
        MenuBarSlots._slotMenuHelpDevelopmentModifyingDashboardClicked
    )
    dashboard.window.actionHelpAbout.triggered.connect(MenuBarSlots._slotMenuHelpAboutClicked)
    dashboard.window.actionCredits.triggered.connect(MenuBarSlots._slotMenuHelpCreditsClicked)
    dashboard.window.actionFISSURE_Challenge.triggered.connect(MenuBarSlots._slotMenuHelpFISSURE_ChallengeClicked)


def connect_automation_slots(dashboard: Dashboard):
    # Check Box
    dashboard.ui.checkBox_automation_receive_only.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationReceiveOnlyClicked(dashboard)
    )
    dashboard.ui.checkBox_automation_auto_select_sois.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationAutoSelectSOIsClicked(dashboard)
    )
    dashboard.ui.checkBox_automation_lock_search_band.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationLockSearchBandClicked(dashboard)
    )
    dashboard.ui.checkBox_automation_auto_start_pd.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationAutoStartPD_Clicked(dashboard)
    )
    dashboard.ui.checkBox_automation_auto_select_pd_flow_graphs.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationAutoSelectPD_FlowGraphsClicked(dashboard)
    )

    # Push Button
    dashboard.ui.pushButton_automation_soi_priority_add_level.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationSOI_PriorityAddLevelClicked(dashboard)
    )
    dashboard.ui.pushButton_automation_soi_priority_remove_level.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationSOI_PriorityRemoveLevelClicked(dashboard)
    )
    dashboard.ui.pushButton_automation_system_reset.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationSystemResetClicked(dashboard)
    )
    dashboard.ui.pushButton_automation_manual.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationManualClicked(dashboard)
    )
    dashboard.ui.pushButton_automation_discovery.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationDiscoveryClicked(dashboard)
    )
    dashboard.ui.pushButton_automation_target.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationTargetClicked(dashboard)
    )
    dashboard.ui.pushButton_automation_custom.clicked.connect(
        lambda: AutomationTabSlots._slotAutomationCustomClicked(dashboard)
    )

    # Table Widgets
    dashboard.ui.tableWidget_automation_scan_options.cellChanged.connect(
        lambda: AutomationTabSlots._slotAutomationLockSearchBandClicked(dashboard)
    )


def connect_tsi_slots(dashboard: Dashboard):
    # Check Box
    dashboard.ui.checkBox_tsi_conditioner_settings_normalize_output.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerSettingsNormalizeChecked(dashboard)
    )
    dashboard.ui.checkBox_tsi_conditioner_settings_saturation.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerSettingsSaturationChecked(dashboard)
    )
    dashboard.ui.checkBox_tsi_classifier_training_retrain2_manual.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingRetrain2_ManualChecked(dashboard)
    )

    # Combo Box
    dashboard.ui.comboBox_tsi_detector.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_DetectorChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_detector_fixed.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_DetectorFixedChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_input_folders.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFolderChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_settings_isolation_method.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerSettingsIsolationMethodChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_settings_input_source.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerSettingsInputSourceChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_settings_isolation_category.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerSettingsIsolationCategoryChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_input_folders.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_InputFolderChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_settings_classification.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_SettingsClassificationChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_settings_technique.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_SettingsTechniqueChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_settings_input_source.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_SettingsInputSourceChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_settings_category.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_SettingsCategoryChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_detector_sweep_hardware.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_DetectorSweepHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_detector_fixed_hardware.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_DetectorFixedHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_classifier_training_category.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingCategoryChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_classifier_training_model.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingModelChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_classifier_training_technique.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingTechniqueChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_classifier_classification_category.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationCategoryChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_classifier_classification_technique.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationTechniqueChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_classifier_classification_model.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationModelChanged(dashboard)
    )

    # List Widget
    dashboard.ui.listWidget_tsi_scan_presets.currentItemChanged.connect(
        lambda: TSITabSlots._slotTSI_ScanPresetItemChanged(dashboard)
    )
    dashboard.ui.listWidget_tsi_conditioner_input_files.itemDoubleClicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputLoadFileClicked(dashboard)
    )
    dashboard.ui.listWidget_tsi_fe_input_files.itemDoubleClicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputLoadFileClicked(dashboard)
    )

    # Push Button
    dashboard.ui.pushButton_tsi_add_band.clicked.connect(
        lambda: TSITabSlots._slotTSI_AddBandClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_remove_band.clicked.connect(
        lambda: TSITabSlots._slotTSI_RemoveBandClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_save_preset.clicked.connect(
        lambda: TSITabSlots._slotTSI_SavePresetClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_delete_preset.clicked.connect(
        lambda: TSITabSlots._slotTSI_DeletePresetClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_clear_detector_plot.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClearDetectorPlotClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_refresh.clicked.connect(
        lambda: TSITabSlots._slotTSI_RefreshPlotClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_zoom_in.clicked.connect(
        lambda: TSITabSlots._slotTSI_ZoomInClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_advanced_settings.clicked.connect(
        lambda: TSITabSlots._slotTSI_AdvancedSettingsClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_back1.clicked.connect(
        lambda: TSITabSlots._slotTSI_Back1_Clicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_iq_file_browse.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorIQ_FileBrowseClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_search.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorSearchClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_csv_file_browse.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorCSV_FileBrowseClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_csv_file_edit.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorCSV_FileEditClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_folder.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_load_file.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputLoadFileClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_refresh.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_remove.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_rename.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputRenameClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_terminal.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputTerminalClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_preview.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputPreviewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_settings_browse.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerSettingsBrowseClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_settings_now.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerSettingsNowClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_preview.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsPreviewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_folder.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_export.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsExportClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_delete.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsDeleteClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_settings_view.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerSettingsViewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_strip.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsStripClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_strip_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsStripAllClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_refresh.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_delete_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsDeleteAllClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_folder.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_load_file.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputLoadFileClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_refresh.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_remove.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_rename.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputRenameClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_terminal.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputTerminalClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_preview.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputPreviewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_preview.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsPreviewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_plot_column.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsPlotColumnClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_settings_deselect_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_SettingsDeselectAllClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_settings_select_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_SettingsSelectAllClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_export.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsExportClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_plot_avg.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsPlotAvgClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_trim.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsTrimClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_import.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsImportClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_joint_plot.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsJointPlotClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_remove_row.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsRemoveRowClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_remove_col.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsRemoveColClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_clear_wideband_list.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClearWidebandListClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_update.clicked.connect(
        lambda: TSITabSlots._slotTSI_UpdateTSI_Clicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_blacklist_add.clicked.connect(
        lambda: TSITabSlots._slotTSI_BlacklistAddClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_blacklist_remove.clicked.connect(
        lambda: TSITabSlots._slotTSI_BlacklistRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_start.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorStartClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_fixed_start.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorFixedStartClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_operation_start.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerOperationStartClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_operation_start.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_OperationStartClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_import_fe.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingImportFE_Clicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_import.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingImportClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_copy_fe.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingCopyFE_Clicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_remove_row.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingRemoveRowClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_remove_col.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingRemoveColClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_trim.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingTrimClicked(dashboard)
    ) 
    dashboard.ui.pushButton_tsi_classifier_training_export.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingExportClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_plot_col.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingPlotColClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_import.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationImportClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_copy_fe.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationCopyFE_Clicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_remove_row.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationRemoveRowClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_remove_col.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationRemoveColClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_trim.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationTrimClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_plot_col.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationPlotColClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_export.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationExportClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_view.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingViewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_retrain.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingRetrainClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_accuracy_clear.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingAccuracyClearClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_accuracy_export.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingAccuracyExportClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_model_images_view.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingModelImagesViewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_accuracy_remove.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingAccuracyRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_results_save_as.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingResultsSaveAsClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_test.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingTestClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_model_delete.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingModelDeleteClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_results_confusion.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingResultsConfusionClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_model_confusion.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingModelConfusionClicked(dashboard)
    ) 
    dashboard.ui.pushButton_tsi_classifier_training_results_new_model_confusion.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingResultsNewModelConfusionClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_retrain2_refresh.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingRetrain2_RefreshClicked(dashboard)
    ) 
    dashboard.ui.pushButton_tsi_classifier_training_select_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingSelectAllClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_deselect_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingDeselectAllClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_netron.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingNetronClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_training_results_netron.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingResultsNetronClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_view.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationViewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_model_confusion.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationModelConfusionClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_playlist_add.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationPlaylistAddClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_playlist_remove.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationPlaylistRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_playlist_auto_fill.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationAutoFillClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_playlist_start.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationPlaylistStartClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_test.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationTestClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_results_clear.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationResultsClear(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_results_remove_col.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationResultsRemoveColClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_results_model.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationResultsModelClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_results_features.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationRemoveFeaturesClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_confidence_recalculate.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationConfidenceRecalculateClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_netron.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationNetronClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_classifier_classification_results_export.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierClassificationResultsExportClicked(dashboard)
    )

    # Radio Buttons
    dashboard.ui.radioButton_tsi_conditioner_input_extensions_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputExtensionsAllClicked(dashboard)
    )
    dashboard.ui.radioButton_tsi_conditioner_input_extensions_custom.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputExtensionsCustomClicked(dashboard)
    )


def connect_pd_slots(dashboard: Dashboard):
    # Check Box
    dashboard.ui.checkBox_pd_bit_slicing_colors.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingDetectFieldsClicked(dashboard)
    )

    # Combo Box
    dashboard.ui.comboBox_pd_demod_hardware.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_DemodHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_dissectors_protocol.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_DissectorsProtocolChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_dissectors_packet_type.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_DissectorsPacketTypeChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_crc_algorithm.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_CRC_AlgorithmChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_crc_common_width.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_CRC_CommonWidthChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_crc_reveng_width.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_CRC_RevEngWidthChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_crc_reveng_algorithm.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_CRC_RevEngAlgorithmChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_bit_viewer_protocols.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_BitViewerProtocolsChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_bit_viewer_subcategory.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_BitViewerSubcategoryChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_sniffer_protocols.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_SnifferProtocolsChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_sniffer_packet_type.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_SnifferPacketTypeChanged(dashboard)
    )
    dashboard.ui.comboBox_pd_sniffer_test_folders.currentIndexChanged.connect(
        lambda: PDTabSlots._slotPD_SnifferTestFoldersChanged(dashboard)
    )

    # Double Spin Boxes
    dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size.valueChanged.connect(
        lambda: PDTabSlots._slotPD_BitSlicingSpinboxWindowChanged(dashboard)
    )
    dashboard.ui.doubleSpinBox_pd_bit_slicing_window_size_candidates.valueChanged.connect(
        lambda: PDTabSlots._slotPD_BitSlicingSpinboxWindowCandidatesChanged(dashboard)
    )

    # List Widget
    dashboard.ui.listWidget_pd_flow_graphs_recommended_fgs.itemDoubleClicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationLoadSelectedClicked(dashboard)
    )
    dashboard.ui.listWidget_pd_flow_graphs_all_fgs.itemDoubleClicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationLoadSelectedAllClicked(dashboard)
    )

    # Horizontal Sliders
    dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats.valueChanged.connect(
        lambda: PDTabSlots._slotPD_BitSlicingSliderWindowChanged(dashboard)
    )
    dashboard.ui.horizontalSlider_pd_bit_slicing_preamble_stats_candidates.valueChanged.connect(
        lambda: PDTabSlots._slotPD_BitSlicingSliderWindowCandidatesChanged(dashboard)
    )

    # Push Button
    dashboard.ui.pushButton_pd_status_soi_new.clicked.connect(
        lambda: PDTabSlots._slotPD_StatusSOI_NewClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_status_search_library.clicked.connect(
        lambda: PDTabSlots._slotPD_StatusSearchLibraryClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_current_soi.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationCurrentSOI_Clicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_view.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationViewFlowGraphClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_load.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationLoadFlowGraphClicked(dashboard, "")
    )
    dashboard.ui.pushButton_pd_flow_graphs_load_selected.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationLoadSelectedClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_lookup_clear.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationLookupClearClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_restore_defaults.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationRestoreDefaultsClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_load_selected_all.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationLoadSelectedAllClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_detect_fields.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingDetectFieldsClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_refresh.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_remove_field.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingRemoveFieldClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_reset.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingLengthsChanged(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_slice.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingSliceClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_merge_fields.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingMergeFieldsClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_split_fields.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingSplitFieldsClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_shift_left.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingShiftLeftClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_shift_right.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingShiftRightClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_hex.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerHexClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_sort.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerSortClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_send_to_buffer.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerSendToBufferClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_table_sort.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerTableSortClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_fill_table.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerFillTableClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_apply.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerApplyClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_invert.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerInvertClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_differential.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerDifferentialClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_man_enc.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerManEncClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_man_dec.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerManDecClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_undiff0.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerUnDiff0Clicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_undiff1.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerUnDiff1Clicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_viewer_bin.clicked.connect(
        lambda: PDTabSlots._slotPD_BitViewerBinClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_new.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorsNewClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_edit.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorsEditClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_add_field.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorsAddFieldClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_remove_field.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorsRemoveFieldClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_up.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorsUpClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_down.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorsDownClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_preview.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorsPreviewClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_update_all.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorsUpdateAllClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_sniffer_wireshark_80211.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferWireshark80211Clicked(dashboard)
    )
    dashboard.ui.pushButton_pd_sniffer_guess.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferGuessClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_sniffer_netcat.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferNetcatClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_sniffer_test_folder.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferTestFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_sniffer_test_send.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferTestSendClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_crc_start.clicked.connect(
        lambda: PDTabSlots._slotPD_CRC_StartClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_crc_calculate_common.clicked.connect(
        lambda: PDTabSlots._slotPD_CRC_CalculateClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_crc_calculate_reveng.clicked.connect(
        lambda: PDTabSlots._slotPD_CRC_RevEngCalculateClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_plot_entropy.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingPlotEntropyClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_construct.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorsConstructClicked(dashboard, preview = False)
    )
    dashboard.ui.pushButton_pd_status_buffer_apply.clicked.connect(
        lambda: PDTabSlots._slotPD_StatusBufferApplyClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_status_buffer_clear.clicked.connect(
        lambda: PDTabSlots._slotPD_StatusBufferClearClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_status_start.clicked.connect(
        lambda: PDTabSlots._slotPD_StatusStartClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_status_blacklist_soi.clicked.connect(
        lambda: PDTabSlots._slotPD_StatusBlacklistSOI_Clicked(dashboard)
    )
    dashboard.ui.pushButton_pd_status_add_pub.clicked.connect(
        lambda: PDTabSlots._slotPD_StatusAddPubClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_status_remove_pub.clicked.connect(
        lambda: PDTabSlots._slotPD_StatusRemovePubClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_lookup.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationLookupClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_start_stop.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationStartStopClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_apply_changes.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationApplyChangesClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_find_preambles.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingFindPreamblesClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_slice_by_preamble.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingSliceByPreambleClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_insert_field.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingInsertFieldClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_add_to_library.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingAddToLibraryClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_clear_buffer.clicked.connect(
        lambda: PDTabSlots._slotPD_StatusBufferClearClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_search_library.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingSearchLibraryClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_remove.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_dissectors_apply.clicked.connect(
        lambda: PDTabSlots._slotPD_DissectorApplyClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_sniffer_stream.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferStreamClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_sniffer_tagged_stream.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferTaggedStreamClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_sniffer_msg_pdu.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferMsgPduClicked(dashboard)
    )

    # Table Widget
    dashboard.ui.tableWidget_pd_flow_graphs_current_values.cellChanged.connect(
        lambda: PDTabSlots._slotPD_DemodulationCurrentValuesEdited(dashboard)
    )
    dashboard.ui.tableWidget_pd_bit_slicing_lengths.itemSelectionChanged.connect(
        lambda: PDTabSlots._slotPD_BitSlicingLengthsChanged(dashboard)
    )
    dashboard.ui.tableWidget_pd_bit_slicing_candidate_preambles.cellDoubleClicked.connect(
        lambda row, col: PDTabSlots._slotPD_BitSlicingCandidateDoubleClicked(dashboard, row, col)
    )
    dashboard.ui.tableWidget_pd_bit_slicing_preamble_stats.cellDoubleClicked.connect(
        lambda row, col: PDTabSlots._slotPD_BitSlicingAllPreamblesDoubleClicked(dashboard, row, col)
    )
    dashboard.ui.tableWidget_pd_bit_slicing_packets.horizontalHeader().sectionClicked.connect(
        lambda col: PDTabSlots._slotPD_BitSlicingColumnClicked(dashboard, col)
    )
    dashboard.ui.tableWidget_pd_bit_viewer_hex.horizontalHeader().sectionClicked.connect(
        lambda col: PDTabSlots._slotPD_BitViewerColumnClicked(dashboard, col)
    )

    # Text Edit
    dashboard.ui.plainTextEdit_pd_bit_viewer_hex.textChanged.connect(
        lambda: PDTabSlots._slotPD_BitViewerHexChanged(dashboard)
    )
    dashboard.ui.plainTextEdit_pd_bit_viewer_bits.textChanged.connect(
        lambda: PDTabSlots._slotPD_BitViewerBitsChanged(dashboard)
    )   


def connect_iq_slots(dashboard: Dashboard):
    # Check Box
    dashboard.ui.checkBox_iq_record_sigmf.clicked.connect(lambda: IQDataTabSlots._slotIQ_RecordSigMF_Clicked(dashboard))
    dashboard.ui.checkBox_iq_strip_overwrite.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_StripOverwriteClicked(dashboard)
    )

    # Combo Box
    dashboard.ui.comboBox3_iq_folders.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_FoldersChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_normalize_min_max.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_NormalizeMinMaxChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_filter_type.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_FilterTypeChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_record_hardware.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_RecordHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_playback_hardware.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_PlaybackHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_inspection_hardware.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionHardwareChanged(dashboard)
    )

    # Label
    dashboard.ui.label2_iq_end.mousePressEvent = lambda event: IQDataTabSlots._slotIQ_EndLabelClicked(dashboard, event)
    dashboard.ui.label2_iq_start.mousePressEvent = lambda event: IQDataTabSlots._slotIQ_StartLabelClicked(
        dashboard, event
    )

    # List Widget
    dashboard.ui.listWidget_iq_inspection_flow_graphs.itemDoubleClicked.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionFlowGraphClicked(dashboard)
    )
    dashboard.ui.listWidget_iq_inspection_fg_file.itemDoubleClicked.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionFG_FileClicked(dashboard)
    )
    dashboard.ui.listWidget_iq_files.itemDoubleClicked.connect(lambda: IQDataTabSlots._slotIQ_LoadIQ_Data(dashboard))

    # Push Button
    dashboard.ui.pushButton_packet_restore_defaults.clicked.connect(
        lambda: IQDataTabSlots._slotPacketRestoreDefaultsClicked(dashboard)
    )
    dashboard.ui.pushButton1_iq_tab_record.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_record")
    )
    dashboard.ui.pushButton1_iq_tab_playback.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_playback")
    )
    dashboard.ui.pushButton1_iq_tab_inspection.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_inspection")
    )
    dashboard.ui.pushButton1_iq_tab_crop.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_crop")
    )
    dashboard.ui.pushButton1_iq_tab_convert.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_convert")
    )
    dashboard.ui.pushButton1_iq_tab_append.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_append")
    )
    dashboard.ui.pushButton1_iq_tab_transfer.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_transfer")
    )
    dashboard.ui.pushButton1_iq_tab_timeslot.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_timeslot")
    )
    dashboard.ui.pushButton1_iq_tab_overlap.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_overlap")
    )
    dashboard.ui.pushButton1_iq_tab_resample.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_resample")
    )
    dashboard.ui.pushButton1_iq_tab_ofdm.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_ofdm")
    )
    dashboard.ui.pushButton1_iq_tab_normalize.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_normalize")
    )
    dashboard.ui.pushButton1_iq_tab_strip.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_strip")
    )
    dashboard.ui.pushButton1_iq_tab_split.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_split")
    )
    dashboard.ui.pushButton1_iq_tab_ook.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_ook")
    )
    dashboard.ui.pushButton_iq_load_file.clicked.connect(lambda: IQDataTabSlots._slotIQ_LoadIQ_Data(dashboard))
    dashboard.ui.pushButton_iq_dir1.clicked.connect(lambda: IQDataTabSlots._slotIQ_Dir1_Clicked(dashboard))
    dashboard.ui.pushButton_iq_dir2.clicked.connect(lambda: IQDataTabSlots._slotIQ_Dir2_Clicked(dashboard))
    dashboard.ui.pushButton_iq_transfer.clicked.connect(lambda: IQDataTabSlots._slotIQ_TransferClicked(dashboard))
    dashboard.ui.pushButton_iq_record_dir.clicked.connect(lambda: IQDataTabSlots._slotIQ_RecordDirClicked(dashboard))
    dashboard.ui.pushButton_iq_refresh.clicked.connect(lambda: IQDataTabSlots._slotIQ_RefreshClicked(dashboard))
    dashboard.ui.pushButton_iq_crop.clicked.connect(lambda: IQDataTabSlots._slotIQ_CropClicked(dashboard))
    dashboard.ui.pushButton_iq_append_select1.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_AppendSelect1Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_append_select2.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_AppendSelect2Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_append_load1.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_AppendLoad1Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_append_load2.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_AppendLoad2Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_append_append.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_AppendAppendClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_delete.clicked.connect(lambda: IQDataTabSlots._slotIQ_DeleteClicked(dashboard))
    dashboard.ui.pushButton_iq_cursor1.clicked.connect(lambda: IQDataTabSlots._slotIQ_Cursor1Clicked(dashboard))
    dashboard.ui.pushButton_iq_get_range.clicked.connect(lambda: IQDataTabSlots._slotIQ_GetRangeClicked(dashboard))
    dashboard.ui.pushButton_iq_overlap_store1.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OverlapStore1Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_overlap_store2.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OverlapStore2Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_ofdm_subcarrier_add.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OFDM_SubcarrierAddClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_ofdm_subcarrier_remove.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OFDM_SubcarrierRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_ofdm_subcarrier_clear.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OFDM_SubcarrierClearClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_ofdm_subcarrier_add_range.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OFDM_SubcarrierAddRangeClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_playback_record_freq.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_PlaybackRecordFreqClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_playback_record_gain.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_PlaybackRecordGainClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_playback_record_rate.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_PlaybackRecordRateClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_resample.clicked.connect(lambda: IQDataTabSlots._slotIQ_ResampleClicked(dashboard))
    dashboard.ui.pushButton_iq_inspection_fg_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionFlowGraphClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_inspection_fg_file_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionFG_FileClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_inspection_fg_live_view.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionFG_LiveViewClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_inspection_fg_file_view.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionFG_FileViewClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_folder.clicked.connect(lambda: IQDataTabSlots._slotIQ_FolderClicked(dashboard))
    dashboard.ui.pushButton_iq_transfer_file_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TransferFileSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_transfer_file_save_as.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TransferFileSaveAsClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_transfer_file.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TranferFileClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_crop_save_as.clicked.connect(lambda: IQDataTabSlots._slotIQ_CropSaveAsClicked(dashboard))
    dashboard.ui.pushButton_iq_plot_next.clicked.connect(lambda: IQDataTabSlots._slotIQ_PlotNextClicked(dashboard))
    dashboard.ui.pushButton_iq_plot_prev.clicked.connect(lambda: IQDataTabSlots._slotIQ_PlotPrevClicked(dashboard))
    dashboard.ui.pushButton_iq_timeslot_select1.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TimeslotSelect1Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_timeslot_select2.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TimeslotSelect2Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_timeslot_load1.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TimeslotLoad1Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_timeslot_load2.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TimeslotLoad2Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_timeslot_pad.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TimeslotPadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_rename.clicked.connect(lambda: IQDataTabSlots._slotIQ_RenameClicked(dashboard))
    dashboard.ui.pushButton_iq_FunctionsSettings.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_FunctionsSettingsClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_FunctionsLeft.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_FunctionsLeftClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_FunctionsRight.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_FunctionsRightClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert_original_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertOriginalLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert_new_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertNewLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert.clicked.connect(lambda: IQDataTabSlots._slotIQ_ConvertClicked(dashboard))
    dashboard.ui.pushButton_iq_convert_original_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertNewSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert_new_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertOriginalSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert_copy.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertCopyClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_terminal.clicked.connect(lambda: IQDataTabSlots._slotIQ_TerminalClicked(dashboard))
    dashboard.ui.pushButton_iq_normalize_original_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_NormalizeOriginalLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_normalize_new_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_NormalizeNewLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_normalize_copy.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_NormalizeCopyClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_normalize.clicked.connect(lambda: IQDataTabSlots._slotIQ_NormalizeClicked(dashboard))
    dashboard.ui.pushButton_iq_resample_original_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ResampleOriginalLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_resample_new_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ResampleNewLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_resample_original_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ResampleOriginalSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_resample_new_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ResampleNewSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_resample_copy.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ResampleCopyClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_normalize_original_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_NormalizeOriginalSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_normalize_new_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_NormalizeNewSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_gqrx.clicked.connect(lambda: IQDataTabSlots._slotIQ_GqrxClicked(dashboard))
    dashboard.ui.pushButton_iq_inspectrum.clicked.connect(lambda: IQDataTabSlots._slotIQ_InspectrumClicked(dashboard))
    dashboard.ui.pushButton_iq_sigmf.clicked.connect(lambda: IQDataTabSlots._slotIQ_SigMF_Clicked(dashboard))
    dashboard.ui.pushButton_iq_strip.clicked.connect(lambda: IQDataTabSlots._slotIQ_StripClicked(dashboard))
    dashboard.ui.pushButton_iq_strip_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_StripSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_strip_load.clicked.connect(lambda: IQDataTabSlots._slotIQ_StripLoadClicked(dashboard))
    dashboard.ui.pushButton_iq_strip_remove.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_StripRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_strip_choose.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_StripChooseClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_strip_clear.clicked.connect(lambda: IQDataTabSlots._slotIQ_StripClearClicked(dashboard))
    dashboard.ui.pushButton_iq_append_clear.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_AppendClearClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_append_remove.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_AppendRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_append_up.clicked.connect(lambda: IQDataTabSlots._slotIQ_AppendUpClicked(dashboard))
    dashboard.ui.pushButton_iq_append_down.clicked.connect(lambda: IQDataTabSlots._slotIQ_AppendDownClicked(dashboard))
    dashboard.ui.pushButton_iq_append_copy.clicked.connect(lambda: IQDataTabSlots._slotIQ_AppendCopyClicked(dashboard))
    dashboard.ui.pushButton_iq_split_input_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_SplitInputSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_split_input_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_SplitInputLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_split_output_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_SplitOutputSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_split_output_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_SplitOutputLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_split.clicked.connect(lambda: IQDataTabSlots._slotIQ_SplitClicked(dashboard))
    dashboard.ui.pushButton_iq_ook_save.clicked.connect(lambda: IQDataTabSlots._slotIQ_OOK_SaveClicked(dashboard))
    dashboard.ui.pushButton_iq_plot.clicked.connect(lambda: IQDataTabSlots._slotIQ_PlotClicked(dashboard))
    dashboard.ui.pushButton_iq_plot_all.clicked.connect(lambda: IQDataTabSlots._slotIQ_PlotAllClicked(dashboard))
    dashboard.ui.pushButton_iq_magnitude.clicked.connect(lambda: IQDataTabSlots._slotIQ_PlotMagnitudeClicked(dashboard))
    dashboard.ui.pushButton_iq_if.clicked.connect(lambda: IQDataTabSlots._slotIQ_PlotIF_Clicked(dashboard))
    dashboard.ui.pushButton_iq_overlap_plot.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OverlapPlotClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_ofdm_plot_symbol_cp.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OFDM_PlotSymbolCP_Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_ofdm_magnitude.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OFDM_MagnitudeClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_ofdm_cycle_adjustment.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OFDM_CycleAdjustmentClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_ofdm_phase.clicked.connect(lambda: IQDataTabSlots._slotIQ_OFDM_PhaseClicked(dashboard))
    dashboard.ui.pushButton_iq_ofdm_polar.clicked.connect(lambda: IQDataTabSlots._slotIQ_OFDM_PolarClicked(dashboard))
    dashboard.ui.pushButton_iq_ofdm_magnitude2.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OFDM_Magnitude2Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_ofdm_phase2.clicked.connect(lambda: IQDataTabSlots._slotIQ_OFDM_Phase2Clicked(dashboard))
    dashboard.ui.pushButton_iq_ofdm_polar2.clicked.connect(lambda: IQDataTabSlots._slotIQ_OFDM_Polar2Clicked(dashboard))
    dashboard.ui.pushButton_iq_ofdm_cycle_adjustment2.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_OFDM_CycleAdjustment2Clicked(dashboard)
    )
    dashboard.ui.pushButton_iq_spectrogram.clicked.connect(lambda: IQDataTabSlots._slotIQ_SpectrogramClicked(dashboard))
    dashboard.ui.pushButton_iq_fft.clicked.connect(lambda: IQDataTabSlots._slotIQ_FFT_Clicked(dashboard))
    dashboard.ui.pushButton_iq_custom.clicked.connect(lambda: IQDataTabSlots._slotIQ_CustomClicked(dashboard))
    dashboard.ui.pushButton_iq_morse_code.clicked.connect(lambda: IQDataTabSlots._slotIQ_MorseCodeClicked(dashboard))
    dashboard.ui.pushButton_iq_moving_average.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_MovingAverageClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_polar.clicked.connect(lambda: IQDataTabSlots._slotIQ_PolarClicked(dashboard))
    dashboard.ui.pushButton_iq_absolute_value.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_AbsoluteValueClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_differential.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_DifferentialClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_keep1in2.clicked.connect(lambda: IQDataTabSlots._slotIQ_Keep1in2_Clicked(dashboard))
    dashboard.ui.pushButton_iq_phase.clicked.connect(lambda: IQDataTabSlots._slotIQ_PhaseClicked(dashboard))
    dashboard.ui.pushButton_iq_unwrap.clicked.connect(lambda: IQDataTabSlots._slotIQ_UnwrapClicked(dashboard))
    dashboard.ui.pushButton_iq_filter.clicked.connect(lambda: IQDataTabSlots._slotIQ_FilterClicked(dashboard))
    dashboard.ui.pushButton_iq_ook_plot.clicked.connect(lambda: IQDataTabSlots._slotIQ_OOK_PlotClicked(dashboard))
    dashboard.ui.pushButton_iq_record_sigmf.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_RecordSigMF_ConfigureClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_record.clicked.connect(lambda: IQDataTabSlots._slotIQ_RecordClicked(dashboard))
    dashboard.ui.pushButton_iq_playback.clicked.connect(lambda: IQDataTabSlots._slotIQ_PlaybackClicked(dashboard))
    dashboard.ui.pushButton_iq_inspection_fg_start.clicked.connect(lambda: IQDataTabSlots._slotIQ_InspectionFG_StartClicked(dashboard))
    dashboard.ui.pushButton_iq_inspection_fg_file_start.clicked.connect(lambda: IQDataTabSlots._slotIQ_InspectionFG_FileStartClicked(dashboard))
    
    # Table Widget
    dashboard.ui.tableWidget_iq_append.horizontalHeader().sectionClicked.connect(
        lambda col: IQDataTabSlots._slotIQ_AppendColumnClicked(dashboard, col)
    )

    # Text Edit
    dashboard.ui.textEdit_iq_start.textChanged.connect(lambda: IQDataTabSlots._slotIQ_StartChanged(dashboard))
    dashboard.ui.textEdit_iq_end.textChanged.connect(lambda: IQDataTabSlots._slotIQ_EndChanged(dashboard))


def connect_attack_slots(dashboard: Dashboard):
    # Check Box
    dashboard.ui.checkBox_attack_show_all.clicked.connect(lambda: AttackTabSlots._slotAttackProtocols(dashboard))

    # Combo Box
    dashboard.ui.comboBox_packet_protocols.currentIndexChanged.connect(
        lambda: AttackTabSlots._slotPacketProtocols(dashboard)
    )
    dashboard.ui.comboBox_packet_subcategory.currentIndexChanged.connect(
        lambda: AttackTabSlots._slotPacketSubcategory(dashboard)
    )
    dashboard.ui.comboBox_attack_protocols.currentIndexChanged.connect(
        lambda: AttackTabSlots._slotAttackProtocols(dashboard)
    )
    dashboard.ui.comboBox_attack_fuzzing_subcategory.currentIndexChanged.connect(
        lambda: AttackTabSlots._slotAttackFuzzingSubcategory(dashboard)
    )
    dashboard.ui.comboBox_attack_modulation.currentIndexChanged.connect(
        lambda: AttackTabSlots._slotAttackModulationChanged(dashboard)
    )
    dashboard.ui.comboBox_attack_hardware.currentIndexChanged.connect(
        lambda: AttackTabSlots._slotAttackHardwareChanged(dashboard)
    )

    # Push Button
    dashboard.ui.pushButton_packet_restore_defaults.clicked.connect(
        lambda: AttackTabSlots._slotPacketRestoreDefaultsClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_assemble.clicked.connect(
        lambda: AttackTabSlots._slotPacketAssembleClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_save_as.clicked.connect(lambda: AttackTabSlots._slotPacketSaveAs(dashboard))
    dashboard.ui.pushButton_packet_calculate_crcs.clicked.connect(
        lambda: AttackTabSlots._slotPacketCalculateCRCsClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_all_hex.clicked.connect(lambda: AttackTabSlots._slotPacketAllHexClicked(dashboard))
    dashboard.ui.pushButton_packet_all_binary.clicked.connect(
        lambda: AttackTabSlots._slotPacketAllBinaryClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_open.clicked.connect(lambda: AttackTabSlots._slotPacketOpenClicked(dashboard))
    dashboard.ui.pushButton_packet_append.clicked.connect(lambda: AttackTabSlots._slotPacketAppendClicked(dashboard))
    dashboard.ui.pushButton_packet_scapy_show.clicked.connect(
        lambda: AttackTabSlots._slotPacketScapyShowClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_scapy_refresh.clicked.connect(
        lambda: AttackTabSlots._slotPacketScapyRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_scapy_start.clicked.connect(
        lambda: AttackTabSlots._slotPacketScapyStartClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_scapy_load.clicked.connect(
        lambda: AttackTabSlots._slotPacketScapyLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_scapy_ls.clicked.connect(lambda: AttackTabSlots._slotPacketScapyLsClicked(dashboard))
    dashboard.ui.pushButton_packet_comma_separated.clicked.connect(
        lambda: AttackTabSlots._slotPacketCommaSeparatedClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_comma_separated2.clicked.connect(
        lambda: AttackTabSlots._slotPacketCommaSeparatedClicked2(dashboard)
    )
    dashboard.ui.pushButton_packet_pattern1.clicked.connect(
        lambda: AttackTabSlots._slotPacketPattern1Clicked(dashboard)
    )
    dashboard.ui.pushButton_packet_scapy_stop.clicked.connect(
        lambda: AttackTabSlots._slotPacketScapyStopClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_fuzzing_restore_defaults.clicked.connect(
        lambda: AttackTabSlots._slotAttackFuzzingRestoreDefaultsClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_view_flow_graph.clicked.connect(
        lambda: AttackTabSlots._slotAttackViewFlowGraph(dashboard)
    )
    dashboard.ui.pushButton_attack_restore_defaults.clicked.connect(
        lambda: AttackTabSlots._slotAttackRestoreDefaults(dashboard)
    )
    dashboard.ui.pushButton_attack_history_delete.clicked.connect(
        lambda: AttackTabSlots._slotAttackHistoryDeleteClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_fuzzing_all_hex.clicked.connect(
        lambda: AttackTabSlots._slotAttackFuzzingAllHexClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_fuzzing_all_binary.clicked.connect(
        lambda: AttackTabSlots._slotAttackFuzzingAllBinaryClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_multi_stage_add.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageAdd(dashboard)
    )
    dashboard.ui.pushButton_attack_multi_stage_remove.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageRemove(dashboard)
    )
    dashboard.ui.pushButton_attack_multi_stage_up.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageUpClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_multi_stage_down.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageDownClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_multi_stage_generate.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageGenerate(dashboard)
    )
    dashboard.ui.pushButton_attack_multi_stage_load.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageLoadClicked(dashboard, fname="", data_override="")
    )
    dashboard.ui.pushButton_attack_multi_stage_save.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageSaveClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_single_stage_autorun.clicked.connect(
        lambda: AttackTabSlots._slotAttackSingleStageAutorunClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_multi_stage_autorun.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageAutorunClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_single_stage_triggers_edit.clicked.connect(
        lambda: AttackTabSlots._slotAttackSingleStageTriggersEditClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_multi_stage_triggers_edit.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageTriggersEditClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_multi_stage_clear.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageClearClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_fuzzing_select_file.clicked.connect(
        lambda: AttackTabSlots._slotAttackFuzzingSelectFileClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_start_stop.clicked.connect(
        lambda: AttackTabSlots._slotAttackStartStopAttack(dashboard)
    )
    dashboard.ui.pushButton_attack_multi_stage_start.clicked.connect(
        lambda: AttackTabSlots._slotAttackMultiStageStartClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_apply_changes.clicked.connect(
        lambda: AttackTabSlots._slotAttackApplyChangesClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_fuzzing_start.clicked.connect(
        lambda: AttackTabSlots._slotAttackFuzzingStartClicked(dashboard)
    )
    dashboard.ui.pushButton_attack_fuzzing_apply_changes.clicked.connect(
        lambda: AttackTabSlots._slotAttackFuzzingApplyChangesClicked(dashboard)
    )

    # Table Widget
    dashboard.ui.tableWidget1_attack_packet_editor.cellChanged.connect(
        lambda row, col: AttackTabSlots._slotPacketItemChanged(dashboard, row, col)
    )
    dashboard.ui.tableWidget1_attack_flow_graph_current_values.cellChanged.connect(
        lambda: AttackTabSlots._slotAttackCurrentValuesEdited(dashboard)
    )
    dashboard.ui.tableWidget_attack_fuzzing_data_field.cellChanged.connect(
        lambda row, col: AttackTabSlots._slotAttackFuzzingItemChanged(dashboard, row, col)
    )

    # Tree Widget
    dashboard.ui.treeWidget_attack_attacks.itemDoubleClicked.connect(
        lambda: AttackTabSlots._slotAttackTemplatesDoubleClicked(dashboard)
    )


def connect_archive_slots(dashboard: Dashboard):
    # Combo Box
    dashboard.ui.comboBox3_archive_download_folder.currentIndexChanged.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadFolderChanged(dashboard)
    )
    dashboard.ui.comboBox_archive_extension.currentIndexChanged.connect(
        lambda: ArchiveTabSlots._slotArchiveExtensionChanged(dashboard)
    )
    dashboard.ui.comboBox_archive_replay_hardware.currentIndexChanged.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayHardwareChanged(dashboard)
    )

    # List View
    dashboard.ui.listView_archive.doubleClicked.connect(
        lambda index: ArchiveTabSlots._slotArchiveListViewDoubleClicked(dashboard, index)
    )

    # Push Button
    dashboard.ui.pushButton_archive_replay_add.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayAddClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_add.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsAddClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_download_folder.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_download_refresh.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadRefreshClicked(dashboard)
    )  # Is this button needed? Does the listView automatically refresh?
    dashboard.ui.pushButton_archive_download_delete.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadDeleteClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_download.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_download_collection.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadCollectionClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_remove.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_up.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayUpClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_down.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayDownClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_remove_all.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayRemoveAllClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_import_csv.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayImportCSV_Clicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_export_csv.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayExportCSV_Clicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_import.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsImportClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_remove.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_remove_all.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsRemoveAllClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_export.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsExportClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_options.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsOptionsClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_import_csv.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsImportCSV_Clicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_view.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsViewClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_copy.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsCopyClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_open_folder.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsOpenFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_download_collection_collapse_all.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadCollectionCollapseAllClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_new_folder.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveNewFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_folder.clicked.connect(lambda: ArchiveTabSlots._slotArchiveFolderClicked(dashboard))
    dashboard.ui.pushButton_archive_replay_triggers_edit.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayTriggersEditClicked(dashboard)
    )  # Needs Trigger dialog code
    dashboard.ui.pushButton_archive_datasets_start.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsStartClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_start.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayStartClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_regenerate.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsRegenerateClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_download_plot.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadPlotClicked(dashboard)
    )

    # Table Widget
    dashboard.ui.tableWidget_archive_datasets.horizontalHeader().sectionClicked.connect(
        lambda col: ArchiveTabSlots._slotArchiveDatasetsColumnClicked(dashboard, col)
    )

    # Text Edit
    dashboard.ui.textEdit_archive_extension.textChanged.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadRefreshClicked(dashboard)
    )


def connect_sensor_nodes_slots(dashboard: Dashboard):
    # Check Box
    dashboard.ui.checkBox_sensor_nodes_autorun_delay.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodeAutorunDelayChecked(dashboard)
    )

    # Combo Box
    dashboard.ui.comboBox_sensor_nodes_autorun.currentIndexChanged.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunPlaylistsChanged(dashboard)
    )
    dashboard.ui.comboBox_sensor_nodes_fn_local_folder.currentIndexChanged.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalFolderChanged(dashboard)
    )
    dashboard.ui.comboBox_sensor_nodes_fn_folder.currentIndexChanged.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationFolderChanged(dashboard)
    )

    # Push Button
    dashboard.ui.pushButton_sensor_nodes_autorun_remove.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_import.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunImportClicked(dashboard, filepath="")
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_export.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunExportClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_view.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunViewClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_refresh.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_local_delete.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalDeleteClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_local_choose.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalChooseClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_local_unzip.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalUnzipClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_local_view.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalViewClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_triggers_edit.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunTriggersEditClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_start_stop.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunStartStopClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_overwrite.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunOverwriteClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_refresh.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_delete.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationDeleteClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_download.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationDownloadClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_local_transfer.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalTransferClicked(dashboard)
    )


def connect_library_slots(dashboard: Dashboard):
    # Combo Box
    dashboard.ui.comboBox_library_gallery_protocol.currentIndexChanged.connect(
        lambda: LibraryTabSlots._slotLibraryGalleryProtocolChanged(dashboard)
    )
    dashboard.ui.comboBox_library_browse_yaml.currentIndexChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseYAML_Changed(dashboard)
    )
    dashboard.ui.comboBox_library_browse_protocol.currentIndexChanged.connect(
        lambda: LibraryTabSlots._slotLibraryRemoveProtocolChanged(dashboard)
    )
    dashboard.ui.comboBox_library_pd_protocol.currentIndexChanged.connect(
        lambda: LibraryTabSlots._slotPD_AddToLibraryProtocolChanged(dashboard)
    )
    dashboard.ui.comboBox_library_attacks_attack_type.currentIndexChanged.connect(
        lambda: LibraryTabSlots._slotAttackImportAttackTypeChanged(dashboard)
    )
    dashboard.ui.comboBox_library_attacks_file_type.currentIndexChanged.connect(
        lambda: LibraryTabSlots._slotAttackImportFileTypeChanged(dashboard)
    )
    dashboard.ui.comboBox_library_pd_data_type.currentIndexChanged.connect(
        lambda: LibraryTabSlots._slotLibraryAddDataTypeChanged(dashboard)
    )

    # List Widget
    dashboard.ui.listWidget_library_gallery.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryGalleryImageChanged(dashboard)
    )
    dashboard.ui.listWidget_library_browse_attacks.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseAttackChanged(dashboard)
    )
    dashboard.ui.listWidget_library_browse_attacks_modulation.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseAttackModulationChanged(dashboard)
    )
    dashboard.ui.listWidget_library_browse_sois.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseSOIsChanged(dashboard)
    )
    dashboard.ui.listWidget_library_browse_packet_types.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowsePacketTypesChanged(dashboard)
    )
    dashboard.ui.listWidget_library_browse_packet_types2.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowsePacketTypesFieldsChanged(dashboard)
    )
    dashboard.ui.listWidget_library_browse_statistics.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseStatisticsChanged(dashboard)
    )
    dashboard.ui.listWidget_library_browse_demod_fgs_modulation.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseDemodFGsModulationClicked(dashboard)
    )
    dashboard.ui.listWidget_library_browse_demod_fgs_hardware.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseDemodFGsHardwareClicked(dashboard)
    )
    dashboard.ui.listWidget_library_browse_demod_fgs.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseDemodFGsClicked(dashboard)
    )
    dashboard.ui.listWidget_library_browse_sois.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseSOIsClicked(dashboard)
    )
    dashboard.ui.listWidget_library_browse_packet_types.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowsePacketTypesClicked(dashboard)
    )
    dashboard.ui.listWidget_library_browse_modulation_types.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseModulationsClicked(dashboard)
    )
    dashboard.ui.listWidget_library_browse_attacks3.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseAttacksClicked(dashboard)
    )

    # Push Button
    dashboard.ui.pushButton_library_gallery_next.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryGalleryNextClicked(dashboard)
    )
    dashboard.ui.pushButton_library_gallery_open.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryGalleryOpenClicked(dashboard)
    )
    dashboard.ui.pushButton_library_gallery_previous.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryGalleryPreviousClicked(dashboard)
    )
    dashboard.ui.pushButton_library_search_current_soi.clicked.connect(
        lambda: LibraryTabSlots._slotLibrarySearchCurrentSOI_Clicked(dashboard)
    )
    dashboard.ui.pushButton_library_pd_browse.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryAddBrowseClicked(dashboard)
    )

    dashboard.ui.pushButton_library_pd_current_soi.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryAddCurrentSOI_Clicked(dashboard)
    )
    dashboard.ui.pushButton_library_pd_add_field.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryAddAddFieldClicked(dashboard)
    )
    dashboard.ui.pushButton_library_pd_remove_field.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryAddRemoveFieldClicked(dashboard)
    )
    dashboard.ui.pushButton_library_pd_up.clicked.connect(lambda: LibraryTabSlots._slotLibraryAddUpClicked(dashboard))
    dashboard.ui.pushButton_library_pd_down.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryAddDownClicked(dashboard)
    )
    dashboard.ui.pushButton_library_attacks_file.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryAddAttacksSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_library_search_search_library.clicked.connect(
        lambda: LibraryTabSlots._slotLibrarySearchSearchLibraryClicked(dashboard)
    )
    dashboard.ui.pushButton_library_pd_add_to_library.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryAddAddToLibrary_Clicked(dashboard)
    )
    dashboard.ui.pushButton_library_remove_protocol.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryRemoveProtocolClicked(dashboard)
    )
    dashboard.ui.pushButton_library_browse_remove_demod_fg.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseRemoveDemodFG_Clicked(dashboard)
    )
    dashboard.ui.pushButton_library_browse_remove_soi.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseRemoveSOI_Clicked(dashboard)
    )
    dashboard.ui.pushButton_library_browse_remove_packet_type.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseRemovePacketTypeClicked(dashboard)
    )
    dashboard.ui.pushButton_library_browse_remove_modulation.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseRemoveModulationClicked(dashboard)
    )
    dashboard.ui.pushButton_library_attacks_remove.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryRemoveAttacksRemoveClicked(dashboard)
    )

    # Radio Button
    dashboard.ui.radioButton_library_search_binary.clicked.connect(
        lambda: LibraryTabSlots._slotLibrarySearchBinaryClicked(dashboard)
    )
    dashboard.ui.radioButton_library_search_hex.clicked.connect(
        lambda: LibraryTabSlots._slotLibrarySearchHexClicked(dashboard)
    )


def connect_log_slots(dashboard: Dashboard):
    # Push Button
    dashboard.ui.pushButton_log_refresh.clicked.connect(lambda: LogTabSlots._slotLogRefreshClicked(dashboard))
    dashboard.ui.pushButton_log_refresh_permit.clicked.connect(
        lambda: LogTabSlots._slotLogRefreshPermitClicked(dashboard)
    )
    dashboard.ui.pushButton_log_save_all.clicked.connect(lambda: LogTabSlots._slotLogSaveAllClicked(dashboard))
    dashboard.ui.pushButton_log_options.clicked.connect(lambda: LogTabSlots._slotLogOptionsClicked(dashboard))


@qasync.asyncSlot(QtCore.QObject)
async def wait_for_backend_shutdown(dashboard: QtCore.QObject):
    dashboard.logger.critical("WAITING FOR BACKEND SHUTDOWN")
    while dashboard.backend.hiprfisr_connected is True:
        await asyncio.sleep(1)
    dashboard.logger.critical("BACKEND SHUTDOWN COMPLETE")
