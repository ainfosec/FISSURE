from .Signals import DashboardSignals
from fissure.Dashboard.Backend import DashboardBackend
from fissure.Dashboard.Slots import (
    ArchiveTabSlots,
    PacketCrafterTabSlots,
    TargetsTabSlots,
    TacticalTabSlots,
    DashboardSlots,
    FuzzingTabSlots,
    ScapyTabSlots,
    IQDataTabSlots,
    LibraryTabSlots,
    ListeningPostsTabSlots,
    LogTabSlots,
    MenuBarSlots,
    PDTabSlots,
    SensorNodesTabSlots,
    SensorNodesPluginsTabSlots,
    SequentialActionTabSlots,
    SingleActionTabSlots,
    StatusBarSlots,
    TopBarSlots,
    TSITabSlots,
)

from fissure.Dashboard.UI_Components import FissureStatusBar, UI_Types
from fissure.Dashboard.UI_Components.MPL import MPL_IQCanvas, MPLCanvas
from fissure.Dashboard.UI_Components.Qt5 import (
    CustomColor,
    JointPlotDialog,
    MiscChooser,
    MyMessageBox,
    MyPlotWindow,
    NewSOI,
    OperationsThread,
    OptionsDialog,
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
import subprocess

from fissure.Dashboard.UI_Components.TacticalMapView import TacticalMapView

from fissure.utils.selected_node_utils import (
    selected_node_is_local,
    selected_node_is_remote,
    selected_node_is_ip,
    selected_node_is_meshtastic,
)

# Base Window Size
WINDOW_WIDTH = 1280
WINDOW_HEIGHT = 1024


class Dashboard(QtWidgets.QMainWindow):
    backend: DashboardBackend
    # logger: logging.Logger = fissure.utils.get_logger(f"{fissure.comms.Identifiers.DASHBOARD}.frontend")
    ui: object
    signals: DashboardSignals
    popups = {}
    active_sensor_node: int

    def __init__(self, parent: QtWidgets.QWidget = None):
        self.logger = fissure.utils.get_logger(f"{fissure.comms.Identifiers.DASHBOARD}.frontend")
        self.logger.info("=== INITIALIZING ===")

        # Launch Splash Screen
        self.splash = SplashScreen()
        self.splash.show_with_delay(200)  # Helps with flicker
        QtWidgets.QApplication.processEvents()
        
        super().__init__(parent)

        # Initialize signals
        self.__init_signals__()
        self.__init_window__()

        self.server_process = None

        # Create Backend
        self.backend = DashboardBackend(frontend=self)

        # Update Logging Levels
        fissure.utils.update_logging_levels(
            self.logger, 
            self.backend.settings["console_logging_level"], 
            self.backend.settings["file_logging_level"]
        )

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
        self.ui.tabWidget.setEnabled(False)

        # Light/Dark Mode Style Sheets
        if self.backend.settings["color_mode"] == "Dark Mode":
            MenuBarSlots.setStyleSheet(self, "dark")
        elif self.backend.settings["color_mode"] == "Custom Mode":
            MenuBarSlots.setStyleSheet(self, "custom")
        else:
            MenuBarSlots.setStyleSheet(self, "light")

        # Scale Factor
        if fissure.utils.isFloat(self.backend.settings["qt_scale_factor"]):
            if float(self.backend.settings["qt_scale_factor"]) == 1.0:
                self.window.actionScaleFactor1_0x.setChecked(True)
            elif float(self.backend.settings["qt_scale_factor"]) == 1.25:
                self.window.actionScaleFactor1_25x.setChecked(True)
            elif float(self.backend.settings["qt_scale_factor"]) == 1.5:
                self.window.actionScaleFactor1_5x.setChecked(True)
            elif float(self.backend.settings["qt_scale_factor"]) == 2.0:
                self.window.actionScaleFactor2_0x.setChecked(True)
            else:
                self.window.actionScaleFactorCustom.setChecked(True)

        # Remember Configuration
        if self.backend.settings["remember_configuration"] == True:
            self.window.actionRemember_Configuration.setChecked(True)
        else:
            self.window.actionRemember_Configuration.setChecked(False)

        # Hide works in progress
        #self.remove_tab_by_text(self.ui.<tab_widget>, <tab_text>)
        self.remove_tab_by_text(self.ui.tabWidget_library, "Search")

        # Load FISSURE Logo
        self.ui.label_diagram.setPixmap(QtGui.QPixmap(os.path.join(fissure.utils.UI_DIR, "Icons", "logo.png")))
        self.ui.pushButton_demo.setVisible(False)
        self.stop_demo_flag = False

        # Set Initial Tab Positions
        self.ui.tabWidget.setCurrentIndex(0)
        self.ui.tabWidget_signal_analysis.setCurrentIndex(0)
        self.ui.tabWidget_protocol.setCurrentIndex(0)
        self.ui.tabWidget_attack_attack.setCurrentIndex(0)
        self.ui.tabWidget_archive.setCurrentIndex(0)
        self.ui.tabWidget_archive_download.setCurrentIndex(0)
        self.ui.tabWidget_sensor_nodes.setCurrentIndex(0)
        self.ui.tabWidget_library.setCurrentIndex(0)

        # Initialize Selected Node
        self.selected_node_uid = ""
        self.selected_node_ip = ""
        self.selected_node_settings = {}
        self.node_states = {}  # Latest normalized node state received from HIPRFISR.
        self.ui.label_top_launch_local_node_image.setPixmap(QtGui.QPixmap(os.path.join(fissure.utils.UI_DIR, "Icons", "rocket_icon_64x48.png")))
        self.ui.label_top_select_sensor_node_image.setPixmap(QtGui.QPixmap(os.path.join(fissure.utils.UI_DIR, "Icons", "select_node.png")))
        self.ui.label_top_configure_node_image.setPixmap(QtGui.QPixmap(os.path.join(fissure.utils.UI_DIR, "Icons", "configure_node.png")))
        self.ui.frame_top_configure_node.setProperty("selected", "false")
        self.ui.frame_top_configure_node.setProperty("connected", "false")
        self.ui.frame_top_configure_node.setProperty("pressed", "false")
        self.ui.frame_top_configure_node.style().unpolish(self.ui.frame_top_configure_node)
        self.ui.frame_top_configure_node.style().polish(self.ui.frame_top_configure_node)

        # Auto Connect HIPRFISR
        self.hiprfisr_serial_connected = False
        self.active_sensor_node = -1  # Needed for Plugin Loading
        if self.backend.settings["auto_connect_hiprfisr"] == True:
            self.window.actionAuto_Connect_HIPRFISR.setChecked(True)
            StatusBarSlots.startLocalSession(self)
            self.splash.progressBar.setValue(50)
        else:
            self.splash.progressBar.setValue(50)
            self.window.actionAuto_Connect_HIPRFISR.setChecked(False)
            StatusBarSlots.remote_connect_prompt(self.statusBar())
            self.__init2__()            

        self.logger.info("=== READY ===")
        
    
    def __init2__(self):

        # Initialize Tabs
        if self.backend.library != None:
            self.__init_Tactical__()
            self.__init_TSI__()
            self.__init_PD__()
            self.__init_Attack__()
            self.__init_IQ__()
            self.__init_Archive__()
            self.__init_Sensor_Nodes__()
            self.__init_Library__()

        # Hide the Splash Screen
        if self.backend.settings["auto_connect_hiprfisr"] == False:
            self.splash.progressBar.setValue(100)
            QtWidgets.QApplication.processEvents()  # new
            QtCore.QTimer.singleShot(100, self.splash.close)  # new
            QtWidgets.QApplication.processEvents()  # new
        else:
            time.sleep(0.1)
            self.splash.close()

        # Enable the Tabs
        self.ui.tabWidget.setEnabled(True)
        for index in range(self.ui.tabWidget.count()):
            self.ui.tabWidget.setTabEnabled(index, True)

        # Show the Dialog
        self.show()
        self.raise_()          # Needed to maintain taskbar icon if splash screen loses focus
        self.activateWindow()  # Needed to show dialog if splash screen loses focus


    def __init_Tactical__(self):
        """
        Initializes Tactical Tab on Dashboard launch.
        """ 
        # Initialize Variables
        self.tactical_nodes = {}
        self.tactical_alerts = {}
        self.tactical_detections = {}
        self.tactical_targets = {}
        self.tactical_sois = {}
        self.tactical_artifacts = {}
        self.tactical_node_artifact_full_details = False
        self.selected_tactical_node_uid = None
        self.selected_tactical_node_uids = []
        self.selected_tactical_target_id = None
        self.selected_tactical_node_target_id = None
        self.selected_tactical_node_soi_id = None
        self.selected_tactical_node_artifact_id = None

        # Initialize Map Pack
        self.tactical_map = TacticalMapView(
            graphics_view=self.ui.graphicsView,
            parent=self,
            default_map_name="elmira_demo",
        )

        # Refresh Combobox and Map
        TacticalTabSlots._slotTacticalRefreshMapPacks(self)

        # Set up Callbacks
        self.tactical_map.set_node_clicked_callback(
            lambda node_uid: TacticalTabSlots._slotTacticalNodeMapClicked(self, node_uid)
        )
        self.tactical_map.set_alert_clicked_callback(
            lambda alert_uid: TacticalTabSlots._slotTacticalAlertMapClicked(self, alert_uid)
        )
        self.tactical_map.set_detection_clicked_callback(
            lambda detection_uid: TacticalTabSlots._slotTacticalNodeDetectionMapClicked(self, detection_uid)
        )
        self.tactical_map.set_target_clicked_callback(
            lambda target_id: TacticalTabSlots._slotTacticalTargetMapClicked(self, target_id)
        )
        self.tactical_map.set_soi_clicked_callback(
            lambda soi_key: TacticalTabSlots._slotTacticalNodeSoiMapClicked(self, soi_key)
        )

        # Initialize Clear Toolbutton
        self.__init_tactical_clear_menu__()

        # Initialize selected-node detection table context menu.
        TacticalTabSlots.initialize_tactical_node_detection_context_menu(self)

        # Initialize selected-node SOI table context menu.
        TacticalTabSlots.initialize_tactical_node_soi_context_menu(self)

        # Initialize selected-node artifact table context menu.
        TacticalTabSlots.initialize_tactical_node_artifact_context_menu(self)

        # Initialize selected-node target table context menu.
        TacticalTabSlots.initialize_tactical_node_target_context_menu(self)

        # Initialize global Tactical Targets table context menu.
        TacticalTabSlots.initialize_tactical_targets_context_menu(self)

        # Initialize Tactical Ecosystem context menus.
        TacticalTabSlots.initialize_tactical_ecosystem_node_context_menu(self)
        TacticalTabSlots.initialize_tactical_ecosystem_alert_context_menu(self)

        # Tactical selected-detection details panel.
        details_scroll = (
            self.ui.scrollArea_tactical_node_detection_details
        )

        details_widgets = [
            details_scroll,
            details_scroll.viewport(),
            details_scroll.widget(),
            self.ui.label2_tactical_node_detection_details,
        ]

        for widget in details_widgets:
            if widget is None:
                continue

            widget.setProperty(
                "uiRole",
                "detailsPanel",
            )

            widget.style().unpolish(widget)
            widget.style().polish(widget)
            widget.update()
        
        # Tactical selected-SOI details panel.
        soi_details_scroll = (
            self.ui.scrollArea_tactical_node_soi_details
        )

        soi_details_widgets = [
            soi_details_scroll,
            soi_details_scroll.viewport(),
            soi_details_scroll.widget(),
            self.ui.label2_tactical_node_soi_details,
        ]

        for widget in soi_details_widgets:
            if widget is None:
                continue

            widget.setProperty(
                "uiRole",
                "detailsPanel",
            )

            widget.style().unpolish(widget)
            widget.style().polish(widget)
            widget.update()
        
        # Tactical SOI details view mode and context menu.
        self.tactical_node_soi_full_details = False
        TacticalTabSlots.initialize_tactical_node_soi_details_context_menu(self)

        TacticalTabSlots.initialize_tactical_node_artifact_details_context_menu(self)

        # Tactical action-parameter panel.
        parameter_scroll = (
            self.ui.scrollArea_tactical_node_action_parameters
        )

        parameter_widgets = [
            parameter_scroll,
            parameter_scroll.viewport(),
            parameter_scroll.widget(),
        ]

        for widget in parameter_widgets:
            if widget is None:
                continue

            widget.setProperty(
                "uiRole",
                "parameterPanel",
            )

            widget.style().unpolish(widget)
            widget.style().polish(widget)
            widget.update()
        
        # Tactical global Target details panel.
        target_details_scroll = (
            self.ui.scrollArea_tactical_targets_details
        )

        target_details_widgets = [
            target_details_scroll,
            target_details_scroll.viewport(),
            target_details_scroll.widget(),
            self.ui.label2_tactical_targets_details,
        ]

        for widget in target_details_widgets:
            if widget is None:
                continue

            widget.setProperty(
                "uiRole",
                "detailsPanel",
            )

            widget.style().unpolish(widget)
            widget.style().polish(widget)
            widget.update()

        # Tactical Target details view mode and context menu.
        self.tactical_targets_full_details = False
        TacticalTabSlots.initialize_tactical_targets_details_context_menu(self)

        # Global Target data button starts disabled until a Target is selected.
        self.ui.pushButton_tactical_targets_download_data.setText(
            "Download Data"
        )
        self.ui.pushButton_tactical_targets_download_data.setToolTip(
            "Select a Target to download its data."
        )
        self.ui.pushButton_tactical_targets_download_data.setEnabled(
            False
        )

        # Initialize selected Tactical node frame state
        self.ui.frame5_tactical1.setToolTip(
            "Select a Tactical node pin or ecosystem row first."
        )
        self.ui.frame5_tactical1.setProperty("pressed", "false")
        self.ui.frame5_tactical1.setProperty("active", "false")
        self.ui.frame5_tactical1.setProperty("clickable", "false")
        self.ui.frame5_tactical1.setProperty("connected", "true")
        self.ui.frame5_tactical1.setEnabled(False)


    def __init_tactical_clear_menu__(self):
        clear_menu = QtWidgets.QMenu()

        action_clear_alerts = clear_menu.addAction("Clear Alert Pins")
        action_clear_detections = clear_menu.addAction("Clear Detection Pins")
        action_clear_nodes = clear_menu.addAction("Clear Node Pins")
        action_clear_targets = clear_menu.addAction("Clear Target Pins")
        action_clear_sois = clear_menu.addAction("Clear SOI Pins")

        clear_menu.addSeparator()

        action_clear_overlays = clear_menu.addAction("Clear All Pins")

        self.ui.toolButton_tactical_clear.setMenu(clear_menu)
        self.ui.toolButton_tactical_clear.setPopupMode(
            QtWidgets.QToolButton.InstantPopup
        )

        action_clear_alerts.triggered.connect(
            lambda: TacticalTabSlots.clear_tactical_alert_pins(self)
        )

        action_clear_detections.triggered.connect(
            lambda: TacticalTabSlots.clear_tactical_detection_pins(self)
        )

        action_clear_nodes.triggered.connect(
            lambda: TacticalTabSlots.clear_tactical_node_pins(self)
        )

        action_clear_targets.triggered.connect(
            lambda: TacticalTabSlots.clear_tactical_target_pins(self)
        )

        action_clear_sois.triggered.connect(
            lambda: TacticalTabSlots.clear_tactical_soi_pins(self)
        )

        action_clear_overlays.triggered.connect(
            lambda: TacticalTabSlots.clear_tactical_map_pins(self)
        )


    def __init_TSI__(self):
        """
        Initializes Signal Analysis / legacy TSI tabs on Dashboard launch.
        """
        try:
            TSITabSlots.initialize_sa_sois_controls(
                self
            )
        except Exception as e:
            self.logger.debug(
                "Could not initialize Signal Analysis SOIs "
                f"controls: {e}"
            )

        try:
            TSITabSlots.initialize_tsi_detector_controls(
                self
            )
        except Exception as e:
            self.logger.debug(
                "Could not initialize unified TSI "
                f"detector controls: {e}"
            )

        self.target_soi = []
        self.soi_blacklist = []

        try:
            TSITabSlots.initialize_tsi_conditioner_controls(
                self
            )
        except Exception as e:
            self.logger.debug(
                "Could not initialize TSI Conditioner "
                f"controls: {e}"
            )

        try:
            TSITabSlots.initialize_tsi_feature_extractor_controls(
                self
            )
        except Exception as e:
            self.logger.debug(
                "Could not initialize TSI Feature "
                f"Extractor controls: {e}"
            )

        # Legacy Classifier feature list.
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

        # Legacy Classifier defaults.
        TSITabSlots._slotTSI_ClassifierTrainingCategoryChanged(
            self
        )
        TSITabSlots._slotTSI_ClassifierTrainingTechniqueChanged(
            self
        )
        TSITabSlots._slotTSI_ClassifierClassificationCategoryChanged(
            self
        )
        TSITabSlots._slotTSI_ClassifierClassificationTechniqueChanged(
            self
        )


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
            if len(fissure.utils.library.getDemodulationFlowGraphFilenames(self.backend.library, p, "", "", version=fissure.utils.get_library_version())) > 0:
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
        """Initialize Targets & Actions workflows."""
        TargetsTabSlots.initialize_targets_tab(self)
        ListeningPostsTabSlots.initialize_listening_posts_tab(self)
        SingleActionTabSlots.initialize_single_action_tab(self)
        SequentialActionTabSlots.initialize_sequential_actions_tab(self)
        FuzzingTabSlots.initialize_fuzzing_tab(self)
        ScapyTabSlots.initialize_scapy_tab(self)


    def __init_PacketCrafter__(self):
        """Initialize Library Packet Crafter controls."""
        self.ui.textEdit_packet_number_of_messages.setPlainText("1")
        protocols = fissure.utils.library.getProtocols(self.backend.library)
        self.ui.comboBox_packet_protocols.clear()
        protocols_with_packet_types = []

        for protocol in protocols:
            if len(
                fissure.utils.library.getPacketTypes(
                    self.backend.library,
                    protocol,
                )
            ) > 0:
                protocols_with_packet_types.append(protocol)

        self.ui.comboBox_packet_protocols.addItems(
            sorted(protocols_with_packet_types)
        )
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
        self.ui.textEdit_iq_strip_output.setPlainText(
            str(fissure.utils.IQ_RECORDINGS_DIR)
        )

        # IQ Record
        try:
            IQDataTabSlots.initialize_iq_record_controls(
                self
            )
        except Exception:
            self.logger.exception(
                "Could not initialize IQ Record controls."
            )

        # IQ Playback
        try:
            IQDataTabSlots.initialize_iq_playback_controls(
                self
            )
        except Exception:
            self.logger.exception(
                "Could not initialize IQ Playback controls."
            )

        # IQ Inspection
        try:
            IQDataTabSlots.initialize_iq_inspection_controls(
                self
            )
        except Exception:
            self.logger.exception(
                "Could not initialize IQ Inspection controls."
            )

        # Open the IQ Record page and initialize shared IQ file-view state.
        IQDataTabSlots._slotIQ_TabClicked(
            self,
            "pushButton1_iq_tab_record",
        )

        self.ui.label_iq_folder.setVisible(False)
        self.iq_plot_range_start = 0
        self.iq_plot_range_end = 0

        self.ui.pushButton_iq_cursor1.setCheckable(True)
        self.fft_data = None

        # Load the Files in the Listbox
        self.ui.comboBox3_iq_folders.addItem(
            str(fissure.utils.IQ_RECORDINGS_DIR)
        )
        self.ui.comboBox3_iq_folders.addItem(
            str(fissure.utils.ARCHIVE_DIR)
        )
        self.ui.comboBox3_iq_folders.setCurrentIndex(0)

        # Hide Range Buttons
        self.ui.pushButton_iq_plot_prev.setVisible(False)
        self.ui.pushButton_iq_plot_next.setVisible(False)

        # Transfer Files
        self.ui.label2_iq_transfer_folder_success.setVisible(False)
        self.ui.label2_iq_transfer_file_success.setVisible(False)

        # Settings Icon
        self.ui.pushButton_iq_FunctionsSettings.setIcon(
            QtGui.QIcon(
                os.path.join(
                    fissure.utils.UI_DIR,
                    "Icons",
                    "settings.png",
                )
            )
        )

        # IQ Artifact Browser Data Type
        self.ui.comboBox_iq_artifacts_data_type.blockSignals(True)
        self.ui.comboBox_iq_artifacts_data_type.clear()

        for idx in range(
            self.ui.comboBox_iq_data_type.count()
        ):
            self.ui.comboBox_iq_artifacts_data_type.addItem(
                self.ui.comboBox_iq_data_type.itemText(
                    idx
                )
            )

        if (
            self.ui.comboBox_iq_artifacts_data_type.findText(
                "Complex Float 32"
            )
            >= 0
        ):
            self.ui.comboBox_iq_artifacts_data_type.setCurrentText(
                "Complex Float 32"
            )

        self.ui.comboBox_iq_artifacts_data_type.blockSignals(False)

        # Initial local artifact scan
        IQDataTabSlots._slotIQ_ArtifactsRefreshClicked(
            self
        )

        # SigMF Dictionary
        global_dict = {
            "core:datatype": "cf32_le",
            "core:version": "1.0.0",
        }
        captures_dict = {
            "core:sample_start": "0"
        }

        self.sigmf_dict = {}
        self.sigmf_dict["global"] = global_dict
        self.sigmf_dict["captures"] = [
            captures_dict
        ]
        self.sigmf_dict["annotations"] = []

        # OOK Tab Example Values
        self.ui.textEdit_iq_ook_chip0_pattern.setPlainText("0")
        self.ui.textEdit_iq_ook_chip1_pattern.setPlainText("1")
        self.ui.textEdit_iq_ook_burst_interval.setPlainText("20")
        self.ui.textEdit_iq_ook_sample_rate.setPlainText("1")
        self.ui.textEdit_iq_ook_chip0_duration.setPlainText("5")
        self.ui.textEdit_iq_ook_chip1_duration.setPlainText("5")
        self.ui.textEdit_iq_ook_sequence.setPlainText(
            "10101010101010101010"
        )


    def __init_Archive__(self):
        """
        Initializes Archive Tabs on Dashboard launch.
        """
        # #### Archive #####
        self.ui.comboBox3_archive_download_folder.addItem(
            fissure.utils.ARCHIVE_DIR
        )
        self.ui.comboBox3_archive_download_folder.addItem(
            fissure.utils.IQ_RECORDINGS_DIR
        )

        self.populateArchive()

        try:
            ArchiveTabSlots.initialize_archive_replay_controls(
                self
            )
        except Exception:
            self.logger.exception(
                "Could not initialize Archive Replay controls."
            )

        self.ui.tableWidget_archive_replay.setColumnHidden(9, True)
        self.ui.progressBar_archive_datasets.setVisible(False)
        self.archive_database_loop = False
        self.stop_archive_operations = False


    def __init_Sensor_Nodes__(self):
        """Initializes Sensor Nodes tabs on Dashboard launch."""
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

        SensorNodesTabSlots.initialize_sensor_nodes_activity_controls(self)
        SensorNodesTabSlots.initialize_sensor_nodes_autorun_controls(self)
        SensorNodesTabSlots.initialize_sensor_nodes_file_navigation_controls(self)
        SensorNodesPluginsTabSlots.initialize_sensor_nodes_plugins_controls(self)


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

        # Initialize Plugins Editor Comboboxes
        # self.ui.comboBox_library_plugin_select.addItem("-- New Plugin --")  # doesn't exist, replace/delete

        # Hide the Searching Label
        self.ui.label2_library_search_searching.setVisible(False)

        # Refresh Browse Table
        LibraryTabSlots._slotLibraryBrowseChanged(self)

        # Packet Crafter
        self.__init_PacketCrafter__()


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

        # Hide Demo menu while the Dashboard is being reorganized.
        self.window.menuDemo.menuAction().setVisible(False)

        # Set Title
        self.setWindowTitle("FISSURE Dashboard")

        self.resize(WINDOW_WIDTH, WINDOW_HEIGHT)

        # Operating System Specific Menu Items
        get_os = fissure.utils.get_os_info()  # self.backend.os_info not loaded yet
        if get_os == 'DragonOS':
            self.window.actionwl_color_picker.setEnabled(False)
            self.window.actionSrsLTE.setEnabled(False)
            self.window.action4G_IMSI_Catcher.setEnabled(False)
            self.window.actionTower_Search.setEnabled(False)
            self.window.actionTower_Search_Part_2.setEnabled(False)
        elif get_os == 'Kali':
            self.window.actionZigbeeOpen_Sniffer.setEnabled(False)
            self.window.actionFALCON.setEnabled(False)
            # self.window.actionSrsLTE.setEnabled(False)
            #self.window.actionLTE_ciphercheck.setEnabled(False)
            self.window.actionOpenCPN.setEnabled(False)
            self.window.actionRTLSDR_Airband.setEnabled(False)
            self.window.actionguidus.setEnabled(False)
            self.window.actionSystemback.setEnabled(False)
            self.window.actiondump978.setEnabled(False)
            self.window.actionOpenWebRX.setEnabled(False)
            # self.window.actionSigDigger.setEnabled(False)
            self.window.actionFoxtrotGPS.setEnabled(False)
            self.window.actionArduino.setEnabled(False)
            self.window.actionBless.setEnabled(False)
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
            # self.window.actionSdrGlut.setEnabled(False)
            self.window.actionRehex.setEnabled(False)
            self.window.actionNETATTACK2.setEnabled(False)
            self.window.actionRouterSploit.setEnabled(False)
            self.window.actionGoogle_Earth_Pro.setEnabled(False)
            self.window.actionViking.setEnabled(False)
            self.window.actionLTE_Cell_Scanner.setEnabled(False)
            self.window.actionAnki.setEnabled(False)
            self.window.actionTrackerjacker.setEnabled(False)
            self.window.actionBTSnifferBREDR.setEnabled(False)
            # self.window.actionSigDigger.setEnabled(False)
            self.window.actionSystemback.setEnabled(False)
            self.window.actionguidus.setEnabled(False)
            self.window.actionICE9_Bluetooth_Scanner.setEnabled(False)
            self.window.actionOpenWebRX.setEnabled(False)
            self.window.actionRadiosonde_auto_rx.setEnabled(False)
        elif get_os == 'Ubuntu 24.04':
            # self.window.actionSrsLTE.setEnabled(False)
            self.window.action4G_IMSI_Catcher.setEnabled(False)
            # self.window.actionSdrGlut.setEnabled(False)
            self.window.actionFALCON.setEnabled(False)
            self.window.actionNETATTACK2.setEnabled(False)
            # self.window.actionSigDigger.setEnabled(False)
            self.window.actionOpenWebRX.setEnabled(False)
            self.window.actionTower_Search.setEnabled(False)
            self.window.actionTower_Search_Part_2.setEnabled(False)

        # Disable Menu Items for all maint-3.8 Operating Systems
        if any(keyword == get_os for keyword in fissure.utils.OS_3_8_KEYWORDS):
            self.window.actionwl_color_picker.setEnabled(False)
            self.window.actiontpms_rx.setEnabled(False)
            self.window.actionBaudline.setEnabled(False)
            self.window.menuESP32_Bluetooth_Classic_Sniffer.setEnabled(False)

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
            self.window.menuESP32_Bluetooth_Classic_Sniffer.setEnabled(False)


    def load_MPL_components(self):
        # Create Wideband Matplotlib Widget
        self.wideband_width = 1201
        self.wideband_height = 801

        rgb = tuple(
            int(
                self.backend.settings["color2"].lstrip("#")[i:i + 2],
                16,
            )
            for i in (0, 2, 4)
        )

        background_color = (
            float(rgb[0]) / 255,
            float(rgb[1]) / 255,
            float(rgb[2]) / 255,
        )

        self.wideband_data = numpy.ones(
            (
                self.wideband_height,
                self.wideband_width,
                3,
            )
        ) * background_color

        self.matplotlib_widget = MPLCanvas(
            self.ui.tab_tsi_detector,
            dpi=100,
            title="Detector History",
            ylim=400,
            width=self.wideband_width,
            height=self.wideband_height,
            border=[0.08, 0.90, 0.05, 1, 0, 0],
            colorbar_fraction=0.038,
            xlabels=[
                "0",
                "",
                "1000",
                "",
                "2000",
                "",
                "3000",
                "",
                "4000",
                "",
                "5000",
                "",
                "6000",
            ],
            ylabels=[
                "0",
                "5",
                "10",
                "15",
                "20",
                "25",
                "30",
                "35",
                "40",
                "45",
            ],
            bg_color=self.backend.settings["color1"],
            face_color=self.backend.settings["color5"],
            text_color=self.backend.settings["color4"],
        )

        self.matplotlib_widget.move(
            self.ui.frame_tsi_detector.pos()
        )
        self.matplotlib_widget.setGeometry(
            self.ui.frame_tsi_detector.geometry()
        )

        self.matplotlib_widget.axes.cla()
        self.matplotlib_widget.axes.imshow(
            self.wideband_data,
            cmap="rainbow",
            clim=(-100, 30),
            extent=[0, 1201, 801, 0],
        )

        self.matplotlib_widget.configureAxes(
            title="Detector History",
            xlabel="Frequency (MHz)",
            ylabel="Time Elapsed (s)",
            xlabels=[
                "0",
                "",
                "1000",
                "",
                "2000",
                "",
                "3000",
                "",
                "4000",
                "",
                "5000",
                "",
                "6000",
            ],
            ylabels=[
                "0",
                "5",
                "10",
                "15",
                "20",
                "25",
                "30",
                "35",
                "40",
            ],
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

        self.iq_matplotlib_widget.move(
            self.ui.frame3_iq.pos()
        )
        self.iq_matplotlib_widget.setGeometry(
            self.ui.frame3_iq.geometry()
        )

        # Add a Toolbar
        self.mpl_toolbar = NavigationToolbar2QT(
            self.iq_matplotlib_widget,
            self.ui.tab_iq_data,
        )

        self.mpl_toolbar.setStyleSheet(
            "color:" + self.backend.settings["color4"]
        )
        self.mpl_toolbar.setGeometry(
            QtCore.QRect(
                375,
                277,
                525,
                35,
            )
        )

        icons_buttons = {
            "Home": QtGui.QIcon(
                os.path.join(
                    fissure.utils.UI_DIR,
                    "Icons",
                    "home.png",
                )
            ),
            "Pan": QtGui.QIcon(
                os.path.join(
                    fissure.utils.UI_DIR,
                    "Icons",
                    "move.png",
                )
            ),
            "Zoom": QtGui.QIcon(
                os.path.join(
                    fissure.utils.UI_DIR,
                    "Icons",
                    "zoom_to_rect.png",
                )
            ),
            "Back": QtGui.QIcon(
                os.path.join(
                    fissure.utils.UI_DIR,
                    "Icons",
                    "back.png",
                )
            ),
            "Forward": QtGui.QIcon(
                os.path.join(
                    fissure.utils.UI_DIR,
                    "Icons",
                    "forward.png",
                )
            ),
            "Subplots": QtGui.QIcon(
                os.path.join(
                    fissure.utils.UI_DIR,
                    "Icons",
                    "subplots.png",
                )
            ),
            "Customize": QtGui.QIcon(
                os.path.join(
                    fissure.utils.UI_DIR,
                    "Icons",
                    "qt4_editor_options.png",
                )
            ),
            "Save": QtGui.QIcon(
                os.path.join(
                    fissure.utils.UI_DIR,
                    "Icons",
                    "filesave.png",
                )
            ),
        }

        for action in self.mpl_toolbar.actions():
            if action.text() in icons_buttons:
                action.setIcon(
                    icons_buttons.get(
                        action.text(),
                        QtGui.QIcon(),
                    )
                )


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
        # Shut down local sensor node launched from the top-bar workflow.
        await TopBarSlots.stopLocalSensorNode(self, remove_from_hiprfisr=True)
       
        # Shut Down Local HIPRFISR, Disconnect from Remote HIPRFISR
        if self.backend.settings["auto_connect_hiprfisr"] == True:
            await StatusBarSlots.shutdown_hiprfisr(self)
        else:
            await StatusBarSlots.disconnect_hiprfisr(self)
            self.backend.shutdown_complete = True

        while self.backend.stop() == False:
            await qasync.asyncio.sleep(0.1)

        self.all_closed_down = True

        # Wait for Remember Configuration to Write to File
        start_time = time.time()
        timeout = 5  # seconds
        while self.backend.shutdown_complete == False:
            if time.time() - start_time > timeout:
                print("Exit timed out before Remember Configuration could write to file. Settings may not be saved")
                break
            await qasync.asyncio.sleep(0.1)

        self.close()


    def configureTSI_Hardware(self):
        """Refresh TSI selected-node-dependent controls."""
        try:
            TSITabSlots.update_tsi_detector_selected_node_gate(self)
        except Exception as e:
            self.logger.debug(
                "Could not update unified TSI Detector selected-node gate: "
                f"{e}"
            )

        try:
            TSITabSlots.update_tsi_conditioner_method_hardware_combo(self)
            TSITabSlots.update_tsi_conditioner_selected_node_gate(self)
        except Exception as e:
            self.logger.debug(
                "Could not update TSI Conditioner selected-node state: "
                f"{e}"
            )

        try:
            TSITabSlots.update_tsi_fe_selected_node_gate(self)
            TSITabSlots.update_tsi_fe_run_node(self)
            TSITabSlots.update_tsi_fe_locality_controls(self)
        except Exception as e:
            self.logger.debug(
                "Could not update TSI Feature Extractor "
                f"selected-node state: {e}"
            )


    def configurePD_Hardware(self):
        """
        Configures PD after new selected sensor node selection.
        """
        self.ui.comboBox_pd_demod_hardware.clear()

        if not self.selected_node_uid:
            return

        get_sensor_node_hardware = (
            fissure.utils.hardware.selectedNodeHardwareDisplayNames(
                self,
                "pd",
            )
        )

        self.ui.comboBox_pd_demod_hardware.addItems(get_sensor_node_hardware)


    def configureIQ_Hardware(self):
        """
        Configure IQ hardware/source selectors for the selected Sensor Node.

        Record and Playback use the selected node's SDR display names directly.

        IQ Inspection uses a Source selector containing:
            configured SDR hardware + File

        Preserve current selections across periodic node-state refreshes.
        """
        iq_hardware_combos = []

        combo_names = [
            "comboBox_iq_record_hardware",
            "comboBox_iq_playback_hardware",
        ]

        for combo_name in combo_names:
            combo = getattr(
                self.ui,
                combo_name,
                None,
            )

            if combo is not None:
                iq_hardware_combos.append(
                    combo
                )

        get_sensor_node_hardware = []

        if self.selected_node_uid:
            get_sensor_node_hardware = (
                fissure.utils.hardware.selectedNodeHardwareDisplayNames(
                    self,
                    "archive",
                )
            )

        for combo in iq_hardware_combos:
            current_text = str(
                combo.currentText()
                or ""
            ).strip()

            existing_items = [
                str(
                    combo.itemText(
                        index
                    )
                )
                for index in range(
                    combo.count()
                )
            ]

            if existing_items == get_sensor_node_hardware:
                continue

            combo.blockSignals(
                True
            )

            try:
                combo.clear()
                combo.addItems(
                    get_sensor_node_hardware
                )

                if current_text:
                    restored_index = combo.findText(
                        current_text,
                        QtCore.Qt.MatchExactly,
                    )

                    if restored_index >= 0:
                        combo.setCurrentIndex(
                            restored_index
                        )

                    elif combo.count() > 0:
                        combo.setCurrentIndex(
                            0
                        )

                elif combo.count() > 0:
                    combo.setCurrentIndex(
                        0
                    )

            finally:
                combo.blockSignals(
                    False
                )

        inspection_source_combo = getattr(
            self.ui,
            "comboBox_iq_inspection_source",
            None,
        )

        if inspection_source_combo is not None:
            inspection_sources = []

            if (
                self.selected_node_uid
                and selected_node_is_local(
                    self
                )
            ):
                inspection_sources.extend(
                    get_sensor_node_hardware
                )

                inspection_sources.append(
                    "File"
                )

            current_source = str(
                inspection_source_combo.currentText()
                or ""
            ).strip()

            existing_sources = [
                str(
                    inspection_source_combo.itemText(
                        index
                    )
                )
                for index in range(
                    inspection_source_combo.count()
                )
            ]

            if existing_sources != inspection_sources:
                inspection_source_combo.blockSignals(
                    True
                )

                try:
                    inspection_source_combo.clear()
                    inspection_source_combo.addItems(
                        inspection_sources
                    )

                    if current_source:
                        restored_index = (
                            inspection_source_combo.findText(
                                current_source,
                                QtCore.Qt.MatchExactly,
                            )
                        )

                        if restored_index >= 0:
                            inspection_source_combo.setCurrentIndex(
                                restored_index
                            )

                        elif inspection_source_combo.count() > 0:
                            inspection_source_combo.setCurrentIndex(
                                0
                            )

                    elif inspection_source_combo.count() > 0:
                        inspection_source_combo.setCurrentIndex(
                            0
                        )

                finally:
                    inspection_source_combo.blockSignals(
                        False
                    )

        IQDataTabSlots.update_iq_record_selected_node_gate(
            self
        )

        IQDataTabSlots.update_iq_playback_selected_node_gate(
            self
        )

        IQDataTabSlots.update_iq_inspection_selected_node_gate(
            self
        )


    def configureArchiveHardware(self):
        """Refresh Archive Replay hardware without disturbing a stable action selection."""
        hardware_combo = self.ui.comboBox_archive_replay_hardware

        current_node_uid = str(getattr(self, "selected_node_uid", "") or "").strip()
        previous_node_uid = str(getattr(self, "archive_replay_hardware_node_uid", "") or "").strip()
        node_changed = current_node_uid != previous_node_uid
        self.archive_replay_hardware_node_uid = current_node_uid

        hardware_items = []
        if current_node_uid:
            hardware_items = fissure.utils.hardware.selectedNodeHardwareDisplayNames(self, "archive")

        current_hardware = str(hardware_combo.currentText() or "").strip()
        existing_items = [str(hardware_combo.itemText(index)) for index in range(hardware_combo.count())]

        hardware_changed = False

        if existing_items != hardware_items:
            hardware_combo.blockSignals(True)
            try:
                hardware_combo.clear()
                hardware_combo.addItems(hardware_items)

                restore_index = hardware_combo.findText(current_hardware, QtCore.Qt.MatchExactly)
                if restore_index >= 0:
                    hardware_combo.setCurrentIndex(restore_index)
                elif hardware_combo.count() > 0:
                    hardware_combo.setCurrentIndex(0)
            finally:
                hardware_combo.blockSignals(False)

            hardware_changed = str(hardware_combo.currentText() or "").strip() != current_hardware

        if node_changed:
            self.archive_replay_action_catalog = []
            self.archive_replay_filtered_actions = []
            self.archive_replay_action_query_pending = False
            self.archive_replay_action_query_context = ""
            self.archive_replay_action_query_node_uid = ""

        if node_changed or hardware_changed:
            ArchiveTabSlots._slotArchiveReplayActionHardwareChanged(self)

        ArchiveTabSlots.update_archive_replay_selected_node_gate(self)


    def configureSensorNodeHardware(self):
        """Update Sensor Node tab state for the selected Sensor Node."""
        SensorNodesTabSlots.update_sensor_nodes_activity_selected_node_gate(self)
        SensorNodesTabSlots.update_sensor_nodes_autorun_selected_node_gate(self)
        SensorNodesPluginsTabSlots.update_sensor_nodes_plugins_selected_node_gate(self)


    def configureSelectedNodeHardware(self):
        """
        Refreshes hardware combo boxes and selected-node page gates.
        """
        self.configureTSI_Hardware()
        self.configurePD_Hardware()
        SingleActionTabSlots.update_single_action_selected_node_gate(self)
        SequentialActionTabSlots.update_sequential_actions_selected_node_gate(self)
        FuzzingTabSlots.update_fuzzing_selected_node_gate(self)
        ScapyTabSlots.update_scapy_selected_node_gate(self)
        self.configureIQ_Hardware()
        self.configureArchiveHardware()
        self.configureSensorNodeHardware()


    def configureLowThroughputWidgets(self):
        """Refresh Dashboard controls for a low-throughput Sensor Node connection."""
        SingleActionTabSlots.update_single_action_selected_node_gate(self)
        SequentialActionTabSlots.update_sequential_actions_selected_node_gate(self)
        FuzzingTabSlots.update_fuzzing_selected_node_gate(self)
        SensorNodesTabSlots.update_sensor_nodes_autorun_selected_node_gate(self)


    def configureLowThroughputWidgets(self):
        """Refresh Dashboard controls for a low-throughput Sensor Node connection."""
        SingleActionTabSlots.update_single_action_selected_node_gate(self)
        SequentialActionTabSlots.update_sequential_actions_selected_node_gate(self)
        SensorNodesTabSlots.update_sensor_nodes_autorun_selected_node_gate(self)


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
            
    
    def remove_tab_by_text(self, tab_widget, tab_text):
        for i in range(tab_widget.count() - 1, -1, -1):
            if tab_widget.tabText(i).strip() == tab_text:
                tab_widget.removeTab(i)


    def populateArchive(self):
        """
        Populates the Archive tables from library.yaml.
        """
        # Populate the File Table
        get_archive_favorites = fissure.utils.library.getArchiveFavorites(self.backend.library)
        notes_width = 150
        new_font = QtGui.QFont("Times", 10)

        for n in range(0, len(get_archive_favorites)):
            # Get File Info
            get_file = str(get_archive_favorites[n][1])
            get_protocol = str(get_archive_favorites[n][6])
            get_date = str(get_archive_favorites[n][2])
            get_format = str(get_archive_favorites[n][3])
            get_sample_rate = str(get_archive_favorites[n][7])
            get_tuned_frequency = str(get_archive_favorites[n][10])
            get_samples = str(get_archive_favorites[n][8])
            get_size = str(get_archive_favorites[n][9])
            get_modulation = str(get_archive_favorites[n][4])
            get_notes = str(get_archive_favorites[n][5])

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
        get_collection_parent = fissure.utils.library.getArchiveCollectionParent(self.backend.library)
        tree = []
        for n in range(0, len(get_collection_parent)):
            # Main Collection Folder
            tree.append(
                [
                    0,
                    get_collection_parent[n][1],
                    get_collection_parent[n][6],
                    get_collection_parent[n][4],
                    get_collection_parent[n][5],
                    get_collection_parent[n][7],
                ]
            )

            # Subdirectories
            get_subdirectories = fissure.utils.library.getArchiveCollectionSubdirectory(self.backend.library, int(get_collection_parent[n][0]))
            for m in range(0, len(get_subdirectories)):
                tree.append(
                    [
                        1,
                        get_subdirectories[m][1],
                        get_subdirectories[m][6],
                        get_subdirectories[m][4],
                        get_subdirectories[m][5],
                        get_subdirectories[m][7],
                    ]
                )

                # Files
                get_files = get_subdirectories[m][2]
                for k in range(0, len(get_files)):
                    tree.append([2, get_files[k], "", "", "", ""])

            # Collections with Files but no Subdirectory/Children
            get_files = get_collection_parent[n][2]
            if get_files is not None:
                for k in range(0, len(get_files)):
                    tree.append([1, get_files[k], "", "", "", ""])

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
    

class SplashScreen(QtWidgets.QDialog):
    def __init__(self):
        super(SplashScreen, self).__init__()
        self.setWindowTitle("Splash Screen")

        # Remove the window frame
        self.setWindowFlags(QtCore.Qt.FramelessWindowHint)

        # Load and set the image
        self.image_label = QtWidgets.QLabel(self)
        splash_pix = QtGui.QPixmap(os.path.join(fissure.utils.UI_DIR, "Icons", "splash.png"))
        self.image_label.setPixmap(splash_pix)

        # Set the size of the dialog to match the size of the image
        self.resize(splash_pix.size())

        # Create a progress bar
        self.progressBar = QtWidgets.QProgressBar(self)
        self.progressBar.setGeometry(50, int(splash_pix.height() - 30), int(splash_pix.width() - 100), 20)
        self.progressBar.setRange(0, 100)
        self.progressBar.setValue(0)

        # Create a text label for loading message
        self.label = QtWidgets.QLabel("Loading...", self)
        self.label.setStyleSheet("color: #f0f0f0; font-size: 14px; font-weight: bold;")

        # Center the text label within the window
        label_width = self.label.fontMetrics().boundingRect(self.label.text()).width() + 20
        label_height = self.label.fontMetrics().boundingRect(self.label.text()).height()
        
        # Calculate position to center the text
        x_pos = (splash_pix.width() - label_width) / 2
        y_pos = splash_pix.height() - label_height - 35  # Adjusted Y-position for better vertical centering

        # Set the label's position and size
        self.label.setGeometry(int(x_pos), int(y_pos), int(label_width), int(label_height))

        # Center the text inside the label
        self.label.setAlignment(QtCore.Qt.AlignCenter)
    
    def show_with_delay(self, delay_ms: int = 100):
        """Show the splash screen with a slight delay."""
        QtCore.QTimer.singleShot(delay_ms, self.show)


class DashboardScreen(UI_Types.Dashboard):
    def setupUi(self, dashboardWidget: QtWidgets.QWidget, dashboardFrontend: QtCore.QObject):
        super().setupUi(dashboardWidget)

        connect_slots(dashboard=dashboardFrontend)


def connect_slots(
    dashboard: Dashboard,
):
    """Contains the connect functions for all the signals and slots."""
    connect_menuBar_slots(dashboard)
    connect_top_bar_slots(dashboard)
    connect_dashboard_slots(dashboard)
    connect_tactical_slots(dashboard)
    connect_tsi_slots(dashboard)
    connect_pd_slots(dashboard)
    connect_iq_slots(dashboard)
    connect_targets_slots(dashboard)
    connect_listening_posts_slots(dashboard)
    connect_single_action_slots(dashboard)
    connect_sequential_action_slots(dashboard)
    connect_fuzzing_slots(dashboard)
    connect_scapy_slots(dashboard)
    connect_packet_crafter_slots(dashboard)
    connect_archive_slots(dashboard)
    connect_sensor_nodes_slots(dashboard)
    connect_library_slots(dashboard)
    connect_log_slots(dashboard)

    dashboard.signals.ComponentStatus.connect(
        StatusBarSlots.update_component_status
    )
    dashboard.signals.Shutdown.connect(
        lambda: wait_for_backend_shutdown(dashboard)
    )


def connect_top_bar_slots(dashboard: Dashboard):
    dashboard.ui.frame_top_launch_local_node.mousePressEvent = (
        lambda event: TopBarSlots._topFramePressed(dashboard.ui.frame_top_launch_local_node, event)
    )
    dashboard.ui.frame_top_launch_local_node.mouseReleaseEvent = (
        lambda event: TopBarSlots._topFrameReleased(
            dashboard,
            dashboard.ui.frame_top_launch_local_node,
            event,
            TopBarSlots._slotLaunchLocalNodeClicked,
        )
    )
    dashboard.ui.frame_top_select_sensor_node.mousePressEvent = (
        lambda event: TopBarSlots._topFramePressed(dashboard.ui.frame_top_select_sensor_node, event)
    )
    dashboard.ui.frame_top_select_sensor_node.mouseReleaseEvent = (
        lambda event: TopBarSlots._topFrameReleased(
            dashboard,
            dashboard.ui.frame_top_select_sensor_node,
            event,
            TopBarSlots._slotSelectNodeClicked,
        )
    )
    dashboard.ui.frame_top_configure_node.mousePressEvent = (
        lambda event: TopBarSlots._topFramePressed(dashboard.ui.frame_top_configure_node, event)
    )
    dashboard.ui.frame_top_configure_node.mouseReleaseEvent = (
        lambda event: TopBarSlots._topFrameReleased(
            dashboard,
            dashboard.ui.frame_top_configure_node,
            event,
            TopBarSlots._slotConfigureNodeClicked,
        )
    )

    # Demo Mode
    dashboard.ui.pushButton_demo.clicked.connect(lambda: TopBarSlots.demoClicked(dashboard))


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
    dashboard.window.actionScaleFactor1_0x.triggered.connect(lambda: MenuBarSlots._slotMenuViewScaleFactor1_0xClicked(dashboard))
    dashboard.window.actionScaleFactor1_25x.triggered.connect(lambda: MenuBarSlots._slotMenuViewScaleFactor1_25xClicked(dashboard))
    dashboard.window.actionScaleFactor1_5x.triggered.connect(lambda: MenuBarSlots._slotMenuViewScaleFactor1_5xClicked(dashboard))
    dashboard.window.actionScaleFactor2_0x.triggered.connect(lambda: MenuBarSlots._slotMenuViewScaleFactor2_0xClicked(dashboard))
    dashboard.window.actionScaleFactorCustom.triggered.connect(lambda: MenuBarSlots._slotMenuViewScaleFactorCustomClicked(dashboard))

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
    dashboard.window.actionlfm_beacon_transmit.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneLFM_BeaconTransmitClicked(dashboard))

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
    dashboard.window.actionV2Verifier_wifi_tx.triggered.connect(lambda: MenuBarSlots._slotMenuV2VerifierWifiTxClicked(dashboard))
    dashboard.window.actionV2Verifier_wifi_rx.triggered.connect(lambda: MenuBarSlots._slotMenuV2VerifierWifiRxClicked(dashboard))
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
    dashboard.window.actionZwave_tx.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneZwaveTxClicked(dashboard))
    dashboard.window.actionZwave_rx.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneZwaveRxClicked(dashboard))
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
    dashboard.window.actionFM_Radio_Capture.triggered.connect(lambda: MenuBarSlots._slotMenuStandaloneFM_RadioCaptureClicked(dashboard))
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
    dashboard.window.actionIQEngine_Online.triggered.connect(MenuBarSlots._slotMenuIQEngineOnlineClicked)
    dashboard.window.actionIQEngine_Local.triggered.connect(lambda: MenuBarSlots._slotMenuIQEngineLocalClicked(dashboard))
    dashboard.window.actionStop_Local_Docker_Container.triggered.connect(lambda: MenuBarSlots._slotMenuIQEngineStopDockerClicked(dashboard))
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
    dashboard.window.actionGraphing_Calculator.triggered.connect(MenuBarSlots._slotMenuGraphingCalculatorClicked)
    dashboard.window.actionpgAdmin.triggered.connect(MenuBarSlots._slotMenuPgAdminClicked)
    dashboard.window.actionFIRMS.triggered.connect(MenuBarSlots._slotMenuFIRMS_Clicked)
    dashboard.window.actionMeshMap.triggered.connect(MenuBarSlots._slotMenuMeshMapClicked)
    dashboard.window.actionIEEE_OUI_List.triggered.connect(MenuBarSlots._slotMenuIEEE_OUI_ListClicked)
    dashboard.window.actionACARS_Hub.triggered.connect(MenuBarSlots._slotMenuACARS_HubClicked)
    dashboard.window.actionHeyWhatsThat_Path_Profiler.triggered.connect(MenuBarSlots._slotMenuHeyWhatsThatPathProfilerClicked)
    dashboard.window.actionWindy_Route_Planner.triggered.connect(MenuBarSlots._slotMenuWindyRoutePlannerClicked)
    dashboard.window.actionWindy.triggered.connect(MenuBarSlots._slotMenuWindyClicked)
    dashboard.window.actionWebTAK.triggered.connect(MenuBarSlots._slotMenuWebTAK_Clicked)
    dashboard.window.actionTAK_Start_Docker_Containers.triggered.connect(lambda: MenuBarSlots._slotMenuTAK_StartDockerContainersClicked(dashboard))
    dashboard.window.actionTAK_Stop_Docker_Containers.triggered.connect(lambda: MenuBarSlots._slotMenuTAK_StopDockerContainersClicked(dashboard))
    dashboard.window.actionJohn_the_Ripper.triggered.connect(lambda: MenuBarSlots._slotMenuJohnTheRipperClicked(dashboard))
    dashboard.window.actionMobile_Atlas_Creator.triggered.connect(lambda: MenuBarSlots._slotMenuMobileAtlasCreatorClicked(dashboard))

    # Lessons Menu
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
    dashboard.window.actionThe_Signal_Path.triggered.connect(MenuBarSlots._slotMenuLessonTheSignalPathClicked)
    dashboard.window.actionField_Spotter_Map.triggered.connect(MenuBarSlots._slotMenuFieldSpotterClicked)
    dashboard.window.actionPlane_Sailing.triggered.connect(MenuBarSlots._slotMenuPlaneSailingClicked)
    dashboard.window.actionUK_Portable_Ham_Map.triggered.connect(MenuBarSlots._slotMenuUK_PortableHamMapClicked)
    dashboard.window.actionSatelliteMapSpace.triggered.connect(MenuBarSlots._slotMenuSatelliteMapSpaceClicked)
    dashboard.window.actionHamSCI_Resources.triggered.connect(MenuBarSlots._slotMenuLessonHamSCI_ResourcesClicked)
    dashboard.window.actionLesson_Z_Wave.triggered.connect(MenuBarSlots._slotMenuLessonZ_WaveClicked)
    dashboard.window.actionLesson_Ceiling_Fans.triggered.connect(MenuBarSlots._slotMenuLessonCeilingFansClicked)
    dashboard.window.actionTest_Measurement_Fundamentals.triggered.connect(MenuBarSlots._slotMenuLessonTestMeasurementFundamentalsClicked)    

    # Demo Menu
    dashboard.window.actionDemo_All.triggered.connect(lambda: MenuBarSlots._slotMenuDemoAllClicked(dashboard))
    dashboard.window.actionDemo_Configuration_All.triggered.connect(lambda: MenuBarSlots._slotMenuDemoConfigurationAllClicked(dashboard))
    dashboard.window.actionDemo_Configuration_Sensor_Node_Configuration.triggered.connect(lambda: MenuBarSlots._slotMenuDemoConfigurationSensorNodeConfigurationClicked(dashboard))
    dashboard.window.actionDemo_Configuration_Software_Server.triggered.connect(lambda: MenuBarSlots._slotMenuDemoConfigurationSoftwareServerClicked(dashboard))
    dashboard.window.actionDemo_Configuration_View_Menu.triggered.connect(lambda: MenuBarSlots._slotMenuDemoConfigurationViewMenuClicked(dashboard))
    dashboard.window.actionDemo_Configuration_Options_Menu.triggered.connect(lambda: MenuBarSlots._slotMenuDemoConfigurationOptionsMenuClicked(dashboard))
    dashboard.window.actionDemo_Configuration_Standalone_Menu.triggered.connect(lambda: MenuBarSlots._slotMenuDemoConfigurationStandaloneMenuClicked(dashboard))
    dashboard.window.actionDemo_Configuration_Tools_Menu.triggered.connect(lambda: MenuBarSlots._slotMenuDemoConfigurationToolsMenuClicked(dashboard))
    dashboard.window.actionDemo_Configuration_Lessons_Menu.triggered.connect(lambda: MenuBarSlots._slotMenuDemoConfigurationLessonsMenuClicked(dashboard))
    dashboard.window.actionDemo_Configuration_Help_Menu.triggered.connect(lambda: MenuBarSlots._slotMenuDemoConfigurationHelpMenuClicked(dashboard))
    dashboard.window.actionDemo_TSI_All.triggered.connect(lambda: MenuBarSlots._slotMenuDemoTSI_AllClicked(dashboard))
    dashboard.window.actionDemo_TSI_Automation_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoTSI_AutomationTabClicked(dashboard))
    dashboard.window.actionDemo_TSI_Detector_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoTSI_DetectorTabClicked(dashboard))
    dashboard.window.actionDemo_TSI_Conditioner_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoTSI_ConditionerTabClicked(dashboard))
    dashboard.window.actionDemo_TSI_Feature_Extractor_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoTSI_FeatureExtractorTabClicked(dashboard))
    dashboard.window.actionDemo_TSI_Classifier_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoTSI_ClassifierTabClicked(dashboard))
    dashboard.window.actionDemo_TSI_Direction_Finding_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoTSI_DirectionFindingTabClicked(dashboard))
    dashboard.window.actionDemo_PD_All.triggered.connect(lambda: MenuBarSlots._slotMenuDemoPD_AllClicked(dashboard))
    dashboard.window.actionDemo_Attack_All.triggered.connect(lambda: MenuBarSlots._slotMenuDemoAttackAllClicked(dashboard))
    dashboard.window.actionDemo_Attack_Packet_Crafter_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoAttackPacketCrafterTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_All.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataAllClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Data_Viewer.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataDataViewerClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Record_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataRecordTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Playback_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataPlaybackTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Inspection_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataInspectionTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Crop_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataCropTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Convert_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataConvertTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Append_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataAppendTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Transfer_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataTransferTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Timeslot_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataTimeslotTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Overlap_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataOverlapTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Resample_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataResampleTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_OFDM_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataOFDM_TabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Normalize_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataNormalizeTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Strip_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataStripTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_Split_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataSplitTabClicked(dashboard))
    dashboard.window.actionDemo_IQ_Data_OOK_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoIQ_DataOOK_TabClicked(dashboard))
    dashboard.window.actionDemo_Archive_All.triggered.connect(lambda: MenuBarSlots._slotMenuDemoArchiveAllClicked(dashboard))
    dashboard.window.actionDemo_Archive_Download_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoArchiveDownloadTabClicked(dashboard))
    dashboard.window.actionDemo_Archive_Replay_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoArchiveReplayTabClicked(dashboard))
    dashboard.window.actionDemo_Archive_Datasets_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoArchiveDatasetsTabClicked(dashboard))
    dashboard.window.actionDemo_Sensor_Nodes_All.triggered.connect(lambda: MenuBarSlots._slotMenuDemoSensorNodesAllClicked(dashboard))
    dashboard.window.actionDemo_Sensor_Nodes_Autorun_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoSensorNodesAutorunTabClicked(dashboard))
    dashboard.window.actionDemo_Sensor_Nodes_File_Navigation_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoSensorNodesFileNavigationTabClicked(dashboard))
    dashboard.window.actionDemo_Library_All.triggered.connect(lambda: MenuBarSlots._slotMenuDemoLibraryAllClicked(dashboard))
    dashboard.window.actionDemo_Library_Browse_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoLibraryBrowseTabClicked(dashboard))
    dashboard.window.actionDemo_Library_Gallery_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoLibraryGalleryTabClicked(dashboard))
    dashboard.window.actionDemo_Library_Search_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoLibrarySearchTabClicked(dashboard))
    dashboard.window.actionDemo_Library_Add_Tab.triggered.connect(lambda: MenuBarSlots._slotMenuDemoLibraryAddTabClickedClicked(dashboard))
    dashboard.window.actionDemo_Log_All.triggered.connect(lambda: MenuBarSlots._slotMenuDemoLogAllClicked(dashboard))

    # Help Menu
    dashboard.window.actionUser_Manual.triggered.connect(MenuBarSlots._slotMenuHelpUserManualClicked)
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
    dashboard.window.actionHIPRFISR.triggered.connect(MenuBarSlots._slotMenuHelpComponentsHIPRFISR_Clicked)
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
    dashboard.window.actionMenuHelpInstallationRemoteSensorNodeInstallation.triggered.connect(
        MenuBarSlots._slotMenuHelpInstallationRemoteSensorNodeInstallationClicked
    )
    dashboard.window.actionMenuHelpInstallationRemoteSensorNodeUsage.triggered.connect(
        MenuBarSlots._slotMenuHelpInstallationRemoteSensorNodeUsageClicked
    )
    dashboard.window.actionMenuHelpHardwareSupportedSensorNodeHardware.triggered.connect(
        MenuBarSlots._slotMenuHelpHardwareSupportedSensorNodeHardwareClicked
    )
    dashboard.window.actionMenuHelpComponentsSensorNodes.triggered.connect(
        MenuBarSlots._slotMenuHelpComponentsSensorNodesClicked
    )
    dashboard.window.actionMenuHelpOperationSensorNodesTab.triggered.connect(
        MenuBarSlots._slotMenuHelpOperationSensorNodesTabClicked
    )
    dashboard.window.actionMenuHelpOperationTriggers.triggered.connect(
        MenuBarSlots._slotMenuHelpOperationTriggersClicked
    )
    dashboard.window.actionMenuHelpDevelopmentCreatingTriggers.triggered.connect(
        MenuBarSlots._slotMenuHelpDevelopmentCreatingClicked
    )
    dashboard.window.actionMenuHelpOperationStartUpProcedures.triggered.connect(
        MenuBarSlots._slotMenuHelpOperationStartUpProceduresClicked
    )
    dashboard.window.actionFISSURE_Capabilities.triggered.connect(
        MenuBarSlots._slotMenuHelpFISSURE_CapabilitiesClicked
    )
    

def connect_tactical_slots(dashboard: Dashboard):
    # Combo Box
    dashboard.ui.comboBox_tactical_map_pack.currentIndexChanged.connect(
        lambda: TacticalTabSlots._slotTacticalMapPackChanged(dashboard)
    )
    dashboard.ui.comboBox_tactical_node_actions.currentIndexChanged.connect(
        lambda: TacticalTabSlots._slotTacticalNodeActionChanged(dashboard)
    )
    dashboard.ui.comboBox_tactical_node_plugins.currentIndexChanged.connect(
        lambda: TacticalTabSlots._slotTacticalNodePluginChanged(dashboard)
    )
    dashboard.ui.comboBox_tactical_ecosystem_actions.currentIndexChanged.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemActionChanged(dashboard)
    )
    dashboard.ui.comboBox_tactical_ecosystem_plugins.currentIndexChanged.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemPluginChanged(dashboard)
    )

    # Push Button
    dashboard.ui.pushButton_tactical_map_pack_refresh.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalRefreshMapPacks(dashboard)
    )
    dashboard.ui.pushButton_tactical_download_map_pack.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalDownloadMapPack(dashboard)
    )
    dashboard.ui.pushButton_tactical_delete_map_pack.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalDeleteMapPack(dashboard)
    )
    dashboard.ui.pushButton_tactical_ecosystem_select_all.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemSelectAllNodesClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_ecosystem_clear_selection.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemClearSelectionClicked(dashboard)
    )    
    dashboard.ui.pushButton_tactical_node_query.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeQueryClicked(dashboard)
    )   
    dashboard.ui.pushButton_tactical_node_select.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_customize.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeCustomizeClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_execute.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeExecuteClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_stop.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeStopClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_ecosystem_refresh_status.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemRefreshStatusClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_ecosystem_query.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemQueryClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_ecosystem_select.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_ecosystem_customize.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemCustomizeClicked(dashboard)
    )    
    dashboard.ui.pushButton_tactical_ecosystem_execute.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemExecuteClicked(dashboard)
    )    
    dashboard.ui.pushButton_tactical_ecosystem_stop.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemStopClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_targets_refresh_targets.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalTargetsRefreshTargetsClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_targets_refresh_targets.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeTargetsRefreshTargetsClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_targets_query_actions.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeTargetsQueryActionsClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_soi_download_evidence.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeSoisDownloadEvidenceClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_targets_query_actions.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalTargetsQueryActionsClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_detections_promote_to_soi.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeDetectionsPromoteToSoiClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_detections_promote_to_target.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeDetectionsPromoteToTargetClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_soi_promote_to_target.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeSoiPromoteToTargetClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_targets_geolocate.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalTargetsGeolocateClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_artifacts_refresh.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeArtifactsRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_node_artifacts_download.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalNodeArtifactsDownloadClicked(dashboard)
    )
    dashboard.ui.pushButton_tactical_targets_download_data.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalTargetsDownloadDataClicked(dashboard)
    )

    # Table Widget
    dashboard.ui.tableWidget_tactical_ecosystem.itemSelectionChanged.connect(
        lambda: TacticalTabSlots.update_selected_tactical_nodes(dashboard)
    )
    dashboard.ui.tableWidget_tactical_ecosystem.itemDoubleClicked.connect(
        lambda item: TacticalTabSlots._slotTacticalEcosystemNodeRosterDoubleClicked(dashboard, item)
    )
    dashboard.ui.tableWidget_tactical_node_detections.currentCellChanged.connect(
        lambda: TacticalTabSlots._slotTacticalNodeDetectionRowChanged(dashboard)
    )
    dashboard.ui.tableWidget_tactical_node_detections.itemDoubleClicked.connect(
        lambda item: TacticalTabSlots._slotTacticalNodeDetectionDoubleClicked(dashboard, item)
    )
    dashboard.ui.tableWidget_tactical_targets.itemSelectionChanged.connect(
        lambda: TacticalTabSlots._slotTacticalTargetsRowSelectionChanged(dashboard)
    )
    dashboard.ui.tableWidget_tactical_targets.itemDoubleClicked.connect(
        lambda item: TacticalTabSlots._slotTacticalTargetsTableDoubleClicked(dashboard, item)
    )
    dashboard.ui.checkBox_tactical_targets_show_ce_rings.clicked.connect(
        lambda: TacticalTabSlots._slotTacticalTargetsShowCeRingsToggled(dashboard)
    )
    dashboard.ui.tableWidget_tactical_node_targets.itemSelectionChanged.connect(
        lambda: TacticalTabSlots._slotTacticalNodeTargetsRowSelectionChanged(dashboard)
    )
    dashboard.ui.tableWidget_tactical_node_targets.itemDoubleClicked.connect(
        lambda item: TacticalTabSlots._slotTacticalNodeTargetsDoubleClicked(dashboard, item)
    )
    dashboard.ui.tableWidget_tactical_node_sois.itemSelectionChanged.connect(
        lambda: TacticalTabSlots._slotTacticalNodeSoisRowSelectionChanged(dashboard)
    )
    dashboard.ui.tableWidget_tactical_node_sois.itemDoubleClicked.connect(
        lambda item: TacticalTabSlots._slotTacticalNodeSoisDoubleClicked(dashboard, item)
    )
    dashboard.ui.tableWidget_tactical_node_artifacts.itemSelectionChanged.connect(
       lambda: TacticalTabSlots._slotTacticalNodeArtifactsRowSelectionChanged(dashboard)
    )
    dashboard.ui.tableWidget_tactical_ecosystem_alerts.itemSelectionChanged.connect(
        lambda: TacticalTabSlots._slotTacticalEcosystemAlertsRowSelectionChanged(dashboard)
    )
    dashboard.ui.tableWidget_tactical_ecosystem_alerts.itemDoubleClicked.connect(
        lambda item: TacticalTabSlots._slotTacticalEcosystemAlertsDoubleClicked(dashboard, item)
    )

    # Frame
    dashboard.ui.frame5_tactical1.mousePressEvent = (
        lambda event: TacticalTabSlots._clickableFramePressed(
            dashboard.ui.frame5_tactical1,
            event
        )
    )

    dashboard.ui.frame5_tactical1.mouseReleaseEvent = (
        lambda event: TacticalTabSlots._clickableFrameReleased(
            dashboard,
            dashboard.ui.frame5_tactical1,
            event,
            TacticalTabSlots._slotSetTacticalNodeActiveClicked,
        )
    )
    

def connect_tsi_slots(dashboard: Dashboard):
    # Signal Analysis - SOIs
    dashboard.ui.lineEdit_sa_sois_list_search.textChanged.connect(
        lambda _text: TSITabSlots._slotSA_SOIsSearchChanged(
            dashboard
        )
    )
    dashboard.ui.tableWidget_sa_sois_list.itemSelectionChanged.connect(
        lambda: TSITabSlots._slotSA_SOIsListSelectionChanged(
            dashboard
        )
    )
    dashboard.ui.pushButton_sa_sois_list_add_soi.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsAddClicked(
            dashboard
        )
    )
    dashboard.ui.pushButton_sa_sois_list_edit.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsEditClicked(
            dashboard
        )
    )
    dashboard.ui.pushButton_sa_sois_list_delete.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsDeleteClicked(
            dashboard
        )
    )
    dashboard.ui.pushButton_sa_sois_list_merge.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsMergeClicked(
            dashboard
        )
    )
    dashboard.ui.pushButton_sa_sois_list_refresh.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsRefreshClicked(
            dashboard
        )
    )
    dashboard.ui.pushButton_sa_sois_selected_promote_to_target.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsPromoteToTargetClicked(
            dashboard
        )
    )
    dashboard.ui.pushButton_sa_sois_selected_capture.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsWorkflowClicked(
            dashboard,
            "capture",
        )
    )
    dashboard.ui.pushButton_sa_sois_selected_inspect.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsWorkflowClicked(
            dashboard,
            "inspection",
        )
    )
    dashboard.ui.pushButton_sa_sois_selected_classify.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsWorkflowClicked(
            dashboard,
            "classifier",
        )
    )
    dashboard.ui.pushButton_sa_sois_selected_protocol_discovery.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsWorkflowClicked(
            dashboard,
            "protocol_discovery",
        )
    )
    dashboard.ui.pushButton_sa_sois_selected_direction_finding.clicked.connect(
        lambda: TSITabSlots._slotSA_SOIsWorkflowClicked(
            dashboard,
            "direction_finding",
        )
    )
    dashboard.ui.label_sa_sois_evidence_details.linkActivated.connect(
        lambda link: TSITabSlots._slotSA_SOIsEvidenceLinkActivated(
            dashboard,
            link,
        )
    )


    # Check Box
    dashboard.ui.checkBox_tsi_classifier_training_retrain2_manual.clicked.connect(
        lambda: TSITabSlots._slotTSI_ClassifierTrainingRetrain2_ManualChecked(dashboard)
    )

    # Combo Box
    dashboard.ui.comboBox_tsi_conditioner_input_source.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputSourceChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_input_data_type.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputDataTypeChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_run_output_format.currentIndexChanged.connect(
        lambda: TSITabSlots._tsi_conditioner_update_workflow_ribbon(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_run_output_mode.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerRunOutputModeChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_method_category.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerMethodCategoryChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_method_method.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerMethodMethodChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_method_hardware.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerMethodHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_conditioner_method_action.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerMethodActionChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_input_source.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_InputSourceChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_run_soi.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_RunSOIChanged(dashboard)
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
    dashboard.ui.comboBox_tsi_detector_hardware.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_DetectorHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_detector_plugin.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_DetectorPluginChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_detector_method.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_DetectorMethodChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_method_profile.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_MethodProfileChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_method_action.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_MethodActionChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_run_destination.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_RunDestinationChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_input_artifact.currentIndexChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_InputArtifactChanged(dashboard)
    )
    dashboard.ui.comboBox_tsi_fe_input_soi.currentIndexChanged.connect(
            lambda: TSITabSlots._slotTSI_FE_InputSOIChanged(dashboard)
    )

    # List Widget
    dashboard.ui.listWidget_tsi_conditioner_input_files.itemSelectionChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputSelectionChanged(dashboard)
    )
    dashboard.ui.listWidget_tsi_fe_input_files.itemSelectionChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_InputSelectionChanged(dashboard)
    )

    # Push Button
    dashboard.ui.pushButton_tsi_detector_search.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorSearchClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_folder.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_refresh.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_preview.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputPreviewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_frequencies_apply_to_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFrequenciesApplyToAllClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_frequencies_add.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFrequenciesAddClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_frequencies_import_tsi.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFrequenciesImportTsiClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_frequencies_import_tactical.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFrequenciesImportTacticalClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_frequencies_up.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFrequenciesUpClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_frequencies_down.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFrequenciesDownClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_frequencies_remove.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFrequenciesRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_input_frequencies_clear.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputFrequenciesClearClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_folder.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_refresh.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_preview.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputPreviewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_method_query_actions.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_MethodQueryActionsClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_method_query_parameters.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_MethodQueryParametersClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_run_start_stop.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_RunStartStopClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_artifact_refresh.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputArtifactRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_input_soi_refresh.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputSOIRefreshClicked(dashboard)
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
    dashboard.ui.pushButton_tsi_detector_query.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorQueryClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_customize.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorCustomizeClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_start_stop.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorStartStopClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_method_query_actions.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerMethodQueryActionsClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_method_query_parameters.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerMethodQueryParametersClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_run_browse.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerRunBrowseClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_run_now.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerRunNowClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_run_start_stop.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerRunStartStopClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_run_download_artifact.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerRunDownloadArtifactClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_preview.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsPreviewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_delete.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsDeleteClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_folder.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_delete_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsDeleteAllClicked(dashboard)
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
    dashboard.ui.pushButton_tsi_conditioner_results_export.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsExportClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_conditioner_results_promote_to_soi.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerResultsPromoteToSoiClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_open_folder.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsOpenFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_preview.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsPreviewClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_export_csv.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsExportCSVClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_export_json.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsExportJSONClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_plot_feature.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsPlotFeatureClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_results_plot_distribution.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultsPlotDistributionClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_run_soi_refresh.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_RunSOIRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_blacklist.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorBlacklistClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_promote_to_soi.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorPromoteToSoiClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_detector_promote_to_target.clicked.connect(
        lambda: TSITabSlots._slotTSI_DetectorPromoteToTargetClicked(dashboard)
    )
    dashboard.ui.pushButton_tsi_fe_run_download_artifact.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_RunDownloadArtifactClicked(dashboard)
    )
    
    # Radio Buttons
    dashboard.ui.radioButton_tsi_conditioner_input_extensions_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputExtensionsAllClicked(dashboard)
    )
    dashboard.ui.radioButton_tsi_conditioner_input_extensions_custom.clicked.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputExtensionsCustomClicked(dashboard)
    )
    dashboard.ui.radioButton_tsi_fe_input_extensions_all.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputExtensionsAllClicked(dashboard)
    )
    dashboard.ui.radioButton_tsi_fe_input_extensions_custom.clicked.connect(
        lambda: TSITabSlots._slotTSI_FE_InputExtensionsCustomClicked(dashboard)
    )

    # Table Widget
    dashboard.ui.tableWidget_tsi_fe_results.itemSelectionChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_ResultSelectionChanged(dashboard)
    )
    dashboard.ui.tableWidget1_tsi_wideband.customContextMenuRequested.connect(
        lambda position: TSITabSlots._show_tsi_detector_results_context_menu(
            dashboard,
            position,
        )
    )
    dashboard.ui.tableWidget1_tsi_wideband.itemSelectionChanged.connect(
        lambda: TSITabSlots._slotTSI_DetectorResultSelectionChanged(dashboard)
    )

    # Text Edit
    dashboard.ui.textEdit_tsi_conditioner_file_path.textChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputPathEdited(dashboard)
    )
    dashboard.ui.textEdit_tsi_conditioner_file_sample_rate.textChanged.connect(
        lambda: TSITabSlots._slotTSI_ConditionerInputDataTypeChanged(dashboard)
    )
    dashboard.ui.textEdit_tsi_fe_file_path.textChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_InputPathEdited(dashboard)
    )
    dashboard.ui.textEdit_tsi_fe_input_extensions.textChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_InputExtensionsEdited(dashboard)
    )
    dashboard.ui.textEdit_tsi_fe_run_description.textChanged.connect(
        lambda: TSITabSlots._slotTSI_FE_RunDescriptionChanged(dashboard)
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
    # dashboard.ui.pushButton_pd_dissectors_construct.clicked.connect(
    #     lambda: PDTabSlots._slotPD_DissectorsConstructClicked(dashboard, preview = False)
    # )
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
    # dashboard.ui.pushButton_pd_bit_slicing_add_to_library.clicked.connect(
    #     lambda: PDTabSlots._slotPD_BitSlicingAddToLibraryClicked(dashboard)
    # )
    dashboard.ui.pushButton_pd_bit_slicing_clear_buffer.clicked.connect(
        lambda: PDTabSlots._slotPD_StatusBufferClearClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_bit_slicing_search_library.clicked.connect(
        lambda: PDTabSlots._slotPD_BitSlicingSearchLibraryClicked(dashboard)
    )
    # dashboard.ui.pushButton_pd_dissectors_remove.clicked.connect(
    #     lambda: PDTabSlots._slotPD_DissectorRemoveClicked(dashboard)
    # )
    # dashboard.ui.pushButton_pd_dissectors_apply.clicked.connect(
    #     lambda: PDTabSlots._slotPD_DissectorApplyClicked(dashboard)
    # )
    dashboard.ui.pushButton_pd_sniffer_stream.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferStreamClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_sniffer_tagged_stream.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferTaggedStreamClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_sniffer_msg_pdu.clicked.connect(
        lambda: PDTabSlots._slotPD_SnifferMsgPduClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_lookup_view.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationLookupViewClicked(dashboard)
    )
    dashboard.ui.pushButton_pd_flow_graphs_all_fgs_view.clicked.connect(
        lambda: PDTabSlots._slotPD_DemodulationAllFGsViewClicked(dashboard)
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
        lambda: IQDataTabSlots._slotIQ_RecordActionHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_record_plugin.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_RecordPluginChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_record_method.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_RecordMethodChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_playback_hardware.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_PlaybackActionHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_playback_plugin.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_PlaybackPluginChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_playback_method.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_PlaybackMethodChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_inspection_source.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionSourceChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_inspection_plugin.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionPluginChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_inspection_action.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionActionChanged(dashboard)
    )
    dashboard.ui.comboBox_iq_artifacts.currentIndexChanged.connect(
        lambda: IQDataTabSlots._slotIQ_ArtifactsChanged(dashboard)
    )

    # Label
    dashboard.ui.label2_iq_end.mousePressEvent = lambda event: IQDataTabSlots._slotIQ_EndLabelClicked(dashboard, event)
    dashboard.ui.label2_iq_start.mousePressEvent = lambda event: IQDataTabSlots._slotIQ_StartLabelClicked(
        dashboard, event
    )

    # List Widget
    dashboard.ui.listWidget_iq_files.itemDoubleClicked.connect(
        lambda: IQDataTabSlots._slotIQ_LoadIQ_Data(dashboard)
    )
    dashboard.ui.listWidget_iq_artifacts_files.itemDoubleClicked.connect(
        lambda item: IQDataTabSlots._slotIQ_ArtifactFileDoubleClicked(dashboard, item)
    )

    # Push Button
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
    dashboard.ui.pushButton_iq_resample.clicked.connect(lambda: IQDataTabSlots._slotIQ_ResampleClicked(dashboard))
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
    dashboard.ui.pushButton_iq_plot.clicked.connect(lambda: IQDataTabSlots._slotIQ_PlotRangeClicked(dashboard))
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
    dashboard.ui.pushButton_iq_record_query.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_RecordQueryClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_record_customize.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_RecordCustomizeClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_record_start_stop.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_RecordStartStopClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_record_download_artifact.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_RecordDownloadArtifactClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_playback_query.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_PlaybackQueryClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_playback_customize.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_PlaybackCustomizeClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_playback_start_stop.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_PlaybackStartStopClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_inspection_query.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionQueryClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_inspection_customize.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionCustomizeClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_inspection_start_stop.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_InspectionStartStopClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_iqengine.clicked.connect(lambda: IQDataTabSlots._slotIQ_IQEngineClicked(dashboard))
    dashboard.ui.pushButton1_iq_tab_endianness.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_TabClicked(dashboard, button_name="pushButton1_iq_tab_endianness")
    )
    dashboard.ui.pushButton_iq_endianness_clear.clicked.connect(lambda: IQDataTabSlots._slotIQ_EndiannessClearClicked(dashboard))
    dashboard.ui.pushButton_iq_endianness_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_EndiannessSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_endianness_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_EndiannessLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_endianness_remove.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_EndiannessRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_endianness_choose.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_EndiannessChooseClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_endianness.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_EndiannessClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert_clear.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertClearClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert_load.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert_remove.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert_choose.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertChooseClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_demod.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_DemodClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_convert_output_select.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ConvertOutputSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_iq_artifacts_refresh.clicked.connect(
        lambda: IQDataTabSlots._slotIQ_ArtifactsRefreshClicked(dashboard)
    )

    # Table Widget
    dashboard.ui.tableWidget_iq_append.horizontalHeader().sectionClicked.connect(
        lambda col: IQDataTabSlots._slotIQ_AppendColumnClicked(dashboard, col)
    )

    # Text Edit
    dashboard.ui.textEdit_iq_start.textChanged.connect(lambda: IQDataTabSlots._slotIQ_StartChanged(dashboard))
    dashboard.ui.textEdit_iq_end.textChanged.connect(lambda: IQDataTabSlots._slotIQ_EndChanged(dashboard))


def connect_targets_slots(dashboard: Dashboard):
        dashboard.ui.comboBox_ta_target.currentIndexChanged.connect(
            lambda: TargetsTabSlots._slotTargetContextChanged(dashboard)
        )

        dashboard.ui.pushButton_ta_targets_refresh.clicked.connect(
            lambda: TargetsTabSlots._slotTargetsRefreshClicked(dashboard)
        )
        dashboard.ui.pushButton_ta_open_in_tactical.clicked.connect(
            lambda: TargetsTabSlots._slotTargetsOpenInTacticalClicked(dashboard)
        )
        dashboard.ui.pushButton_ta_targets_open_soi.clicked.connect(
            lambda: TargetsTabSlots._slotTargetsOpenSoiClicked(dashboard)
        )
        dashboard.ui.pushButton_ta_targets_copy_target_id.clicked.connect(
            lambda: TargetsTabSlots._slotTargetsCopyTargetIdClicked(dashboard)
        )
        dashboard.ui.pushButton_ta_targets_save_notes.clicked.connect(
            lambda: TargetsTabSlots._slotTargetsSaveNotesClicked(dashboard)
        )
        dashboard.ui.pushButton_ta_targets_download_data.clicked.connect(
            lambda: TargetsTabSlots._slotTargetsDownloadDataClicked(dashboard)
        )
        dashboard.ui.pushButton_ta_targets_recommended_actions_stage.clicked.connect(
            lambda: TargetsTabSlots._slotTargetsRecommendedActionStageClicked(dashboard)
        )
        dashboard.ui.pushButton_ta_targets_recommended_actions_remove.clicked.connect(
            lambda: TargetsTabSlots._slotTargetsRecommendedActionRemoveClicked(dashboard)
        )

        dashboard.ui.tableWidget1_ta_targets.itemSelectionChanged.connect(
            lambda: TargetsTabSlots._slotTargetsRowSelectionChanged(dashboard)
        )
        dashboard.ui.tableWidget1_ta_targets.itemDoubleClicked.connect(
            lambda _item: TargetsTabSlots._slotTargetsOpenInTacticalClicked(dashboard)
        )
        dashboard.ui.tableWidget_ta_targets_history.itemSelectionChanged.connect(
            lambda: TargetsTabSlots._slotTargetsHistorySelectionChanged(dashboard)
        )
        dashboard.ui.tableWidget_ta_targets_recommended_actions.itemSelectionChanged.connect(
            lambda: TargetsTabSlots._slotTargetsRecommendedActionSelectionChanged(dashboard)
        )

        dashboard.ui.textEdit_ta_targets_search.textChanged.connect(
            lambda: TargetsTabSlots._slotTargetsSearchChanged(dashboard)
        )        


def connect_listening_posts_slots(
    dashboard: Dashboard,
):
    dashboard.ui.pushButton_ta_lp_add.clicked.connect(
        lambda: ListeningPostsTabSlots._slotListeningPostsAddClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_lp_edit.clicked.connect(
        lambda: ListeningPostsTabSlots._slotListeningPostsEditClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_lp_remove.clicked.connect(
        lambda: ListeningPostsTabSlots._slotListeningPostsRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_lp_refresh.clicked.connect(
        lambda: ListeningPostsTabSlots._slotListeningPostsRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_lp_start_stop.clicked.connect(
        lambda: ListeningPostsTabSlots._slotListeningPostsStartStopClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_lp_activity_clear.clicked.connect(
        lambda: ListeningPostsTabSlots._slotListeningPostsActivityClearClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_lp_test_scripts.clicked.connect(
        lambda: ListeningPostsTabSlots._slotListeningPostsTestScriptsClicked(dashboard)
    )

    dashboard.ui.tableWidget_ta_lp_setup.itemSelectionChanged.connect(
        lambda: ListeningPostsTabSlots._slotListeningPostsSelectionChanged(dashboard)
    )
    dashboard.ui.tabWidget_attack_attack.currentChanged.connect(
        lambda _index: ListeningPostsTabSlots._slotListeningPostsTabChanged(dashboard)
    )


def connect_single_action_slots(dashboard: Dashboard):
    dashboard.ui.comboBox_ta_single_action_hardware.currentIndexChanged.connect(lambda: SingleActionTabSlots._slotSingleActionHardwareChanged(dashboard))
    dashboard.ui.comboBox_ta_single_action_plugin.currentIndexChanged.connect(lambda: SingleActionTabSlots._slotSingleActionPluginChanged(dashboard))
    dashboard.ui.comboBox_ta_single_action_action.currentIndexChanged.connect(lambda: SingleActionTabSlots._slotSingleActionActionChanged(dashboard))
    dashboard.ui.pushButton_ta_single_action_query.clicked.connect(lambda: SingleActionTabSlots._slotSingleActionQueryClicked(dashboard))
    dashboard.ui.pushButton_ta_single_action_customize.clicked.connect(lambda: SingleActionTabSlots._slotSingleActionCustomizeClicked(dashboard))
    dashboard.ui.pushButton_ta_single_action_detector_add.clicked.connect(lambda: SingleActionTabSlots._slotSingleActionDetectorAddClicked(dashboard))
    dashboard.ui.pushButton_ta_single_action_detector_remove.clicked.connect(lambda: SingleActionTabSlots._slotSingleActionDetectorRemoveClicked(dashboard))
    dashboard.ui.pushButton_ta_single_action_start_stop.clicked.connect(lambda: SingleActionTabSlots._slotSingleActionStartStopClicked(dashboard))


def connect_sequential_action_slots(dashboard: Dashboard):
    dashboard.ui.pushButton_ta_sequential_actions_add.clicked.connect(lambda: SequentialActionTabSlots._slotSequentialActionsAddClicked(dashboard))
    dashboard.ui.pushButton_ta_sequential_actions_duplicate.clicked.connect(lambda: SequentialActionTabSlots._slotSequentialActionsDuplicateClicked(dashboard))
    dashboard.ui.pushButton_ta_sequential_actions_remove.clicked.connect(lambda: SequentialActionTabSlots._slotSequentialActionsRemoveClicked(dashboard))
    dashboard.ui.pushButton_ta_sequential_actions_up.clicked.connect(lambda: SequentialActionTabSlots._slotSequentialActionsUpClicked(dashboard))
    dashboard.ui.pushButton_ta_sequential_actions_down.clicked.connect(lambda: SequentialActionTabSlots._slotSequentialActionsDownClicked(dashboard))
    dashboard.ui.tableWidget_ta_sequential_actions_sequence.itemSelectionChanged.connect(lambda: SequentialActionTabSlots._slotSequentialActionsSelectionChanged(dashboard))
    dashboard.ui.tableWidget_ta_sequential_actions_sequence.cellDoubleClicked.connect(lambda row, column: SequentialActionTabSlots._slotSequentialActionsTableDoubleClicked(dashboard, row, column))
    dashboard.ui.pushButton_ta_sequential_actions_detector_add.clicked.connect(lambda: SequentialActionTabSlots._slotSequentialActionsDetectorAddClicked(dashboard))
    dashboard.ui.pushButton_ta_sequential_actions_detector_remove.clicked.connect(lambda: SequentialActionTabSlots._slotSequentialActionsDetectorRemoveClicked(dashboard))
    dashboard.ui.tableWidget_ta_sequential_actions_detectors.itemSelectionChanged.connect(lambda: SequentialActionTabSlots._slotSequentialActionsDetectorSelectionChanged(dashboard))
    dashboard.ui.pushButton_ta_sequential_actions_start_stop.clicked.connect(lambda: SequentialActionTabSlots._slotSequentialActionsStartStopClicked(dashboard))


def connect_fuzzing_slots(dashboard: Dashboard):
    dashboard.ui.comboBox_ta_fuzzing_protocol.currentIndexChanged.connect(lambda: FuzzingTabSlots._slotFuzzingProtocolChanged(dashboard))
    dashboard.ui.comboBox_ta_fuzzing_packet_type.currentIndexChanged.connect(lambda: FuzzingTabSlots._slotFuzzingPacketTypeChanged(dashboard))
    dashboard.ui.comboBox_ta_fuzzing_hardware.currentIndexChanged.connect(lambda: FuzzingTabSlots._slotFuzzingHardwareChanged(dashboard))
    dashboard.ui.comboBox_ta_fuzzing_plugin.currentIndexChanged.connect(lambda: FuzzingTabSlots._slotFuzzingPluginChanged(dashboard))
    dashboard.ui.comboBox_ta_fuzzing_action.currentIndexChanged.connect(lambda: FuzzingTabSlots._slotFuzzingActionChanged(dashboard))
    dashboard.ui.pushButton_ta_fuzzing_query.clicked.connect(lambda: FuzzingTabSlots._slotFuzzingQueryClicked(dashboard))
    dashboard.ui.pushButton_ta_fuzzing_customize.clicked.connect(lambda: FuzzingTabSlots._slotFuzzingCustomizeClicked(dashboard))
    dashboard.ui.pushButton_ta_fuzzing_restore_defaults.clicked.connect(lambda: FuzzingTabSlots._slotFuzzingRestoreDefaultsClicked(dashboard))
    dashboard.ui.pushButton_ta_fuzzing_all_binary.clicked.connect(lambda: FuzzingTabSlots._slotFuzzingAllBinaryClicked(dashboard))
    dashboard.ui.pushButton_ta_fuzzing_all_hex.clicked.connect(lambda: FuzzingTabSlots._slotFuzzingAllHexClicked(dashboard))
    dashboard.ui.pushButton_ta_fuzzing_start_stop.clicked.connect(lambda: FuzzingTabSlots._slotFuzzingStartStopClicked(dashboard))
    dashboard.ui.tableWidget_ta_fuzzing_fields.cellChanged.connect(lambda row, column: FuzzingTabSlots._slotFuzzingFieldItemChanged(dashboard, row, column))


def connect_scapy_slots(dashboard: Dashboard):
    # Check Box
    dashboard.ui.checkBox_ta_scapy_transmit_loop.toggled.connect(
        lambda checked: ScapyTabSlots._slotScapyLoopToggled(dashboard, checked)
    )

    # Combo Box
    dashboard.ui.comboBox_ta_scapy_layers_editing.currentIndexChanged.connect(
        lambda index: ScapyTabSlots._slotScapyEditingLayerChanged(dashboard, index)
    )

    # Line Edit
    dashboard.ui.lineEdit_ta_scapy_source_search.textChanged.connect(
        lambda text: ScapyTabSlots._slotScapyPresetSearchChanged(dashboard, text)
    )

    # Push Button
    dashboard.ui.pushButton_ta_scapy_stack_add_layer.clicked.connect(
        lambda: ScapyTabSlots._slotScapyAddLayerClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_scapy_stack_remove_layer.clicked.connect(
        lambda: ScapyTabSlots._slotScapyRemoveLayerClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_scapy_stack_move_up.clicked.connect(
        lambda: ScapyTabSlots._slotScapyMoveLayerUpClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_scapy_stack_move_down.clicked.connect(
        lambda: ScapyTabSlots._slotScapyMoveLayerDownClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_scapy_stack_clear_all.clicked.connect(
        lambda: ScapyTabSlots._slotScapyClearAllClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_scapy_layers_reset_layer.clicked.connect(
        lambda: ScapyTabSlots._slotScapyResetLayerClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_scapy_output_save_as.clicked.connect(
        lambda: ScapyTabSlots._slotScapyOutputSaveAsClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_scapy_output_copy.clicked.connect(
        lambda: ScapyTabSlots._slotScapyOutputCopyClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_scapy_transmit_interface_refresh.clicked.connect(
        lambda: ScapyTabSlots._slotScapyInterfaceRefreshClicked(dashboard)
    )
    dashboard.ui.pushButton_ta_scapy_transmit_start_stop.clicked.connect(
        lambda: ScapyTabSlots._slotScapyTransmitStartStopClicked(dashboard)
    )

    # Table Widget
    dashboard.ui.tableWidget_ta_scapy_stack_layers.itemSelectionChanged.connect(
        lambda: ScapyTabSlots._slotScapyStackSelectionChanged(dashboard)
    )
    dashboard.ui.tableWidget_ta_scapy_transmit_interfaces.itemSelectionChanged.connect(
        lambda: ScapyTabSlots._slotScapyInterfaceSelectionChanged(dashboard)
    )

    # Tree Widget
    dashboard.ui.treeWidget_ta_scapy_source_presets.itemClicked.connect(
        lambda item, column: ScapyTabSlots._slotScapyPresetClicked(dashboard, item, column)
    )


def connect_packet_crafter_slots(dashboard: Dashboard):
    """Connect Packet Crafter controls."""
    dashboard.ui.comboBox_packet_protocols.currentIndexChanged.connect(
        lambda: PacketCrafterTabSlots._slotPacketProtocols(dashboard)
    )
    dashboard.ui.comboBox_packet_subcategory.currentIndexChanged.connect(
        lambda: PacketCrafterTabSlots._slotPacketSubcategory(dashboard)
    )

    dashboard.ui.pushButton_packet_restore_defaults.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketRestoreDefaultsClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_assemble.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketAssembleClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_save_as.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketSaveAs(dashboard)
    )
    dashboard.ui.pushButton_packet_calculate_crcs.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketCalculateCRCsClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_all_hex.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketAllHexClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_all_binary.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketAllBinaryClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_open.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketOpenClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_append.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketAppendClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_comma_separated.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketCommaSeparatedClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_comma_separated2.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketCommaSeparatedClicked2(dashboard)
    )
    dashboard.ui.pushButton_packet_pattern1.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketPattern1Clicked(dashboard)
    )
    dashboard.ui.pushButton_packet_import.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketImportClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_export.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketExportClicked(dashboard)
    )
    dashboard.ui.pushButton_packet_open_in_scapy.clicked.connect(
        lambda: PacketCrafterTabSlots._slotPacketOpenInScapyClicked(dashboard)
    )

    dashboard.ui.tableWidget1_attack_packet_editor.cellChanged.connect(
        lambda row, col: PacketCrafterTabSlots._slotPacketItemChanged(
            dashboard,
            row,
            col,
        )
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
        lambda: ArchiveTabSlots._slotArchiveReplayActionHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_archive_replay_plugin.currentIndexChanged.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayPluginChanged(dashboard)
    )
    dashboard.ui.comboBox_archive_replay_method.currentIndexChanged.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayMethodChanged(dashboard)
    )

    # List View
    dashboard.ui.listView_archive.doubleClicked.connect(
        lambda index: ArchiveTabSlots._slotArchiveListViewDoubleClicked(dashboard, index)
    )

    # Push Button
    dashboard.ui.pushButton_archive_replay_query.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayQueryClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_customize.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayCustomizeClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_add.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayAddClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_add.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsAddClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_download_folder.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadFolderClicked(dashboard)
    )
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
    dashboard.ui.pushButton_archive_folder.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_start.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsStartClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_datasets_regenerate.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDatasetsRegenerateClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_download_plot.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadPlotClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_download_preview.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadPreviewClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_download_rename.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveDownloadRenameClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_detector_add.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayDetectorAddClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_detector_remove.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayDetectorRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_archive_replay_start_stop.clicked.connect(
        lambda: ArchiveTabSlots._slotArchiveReplayStartStopClicked(dashboard)
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
    dashboard.ui.checkBox_sensor_nodes_autorun_timing_repeat.toggled.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunTimingRepeatChanged(dashboard)
    )

    # Combo Box
    dashboard.ui.comboBox_sensor_nodes_fn_local_folder.currentIndexChanged.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalFolderChanged(dashboard)
    )
    dashboard.ui.comboBox_sensor_nodes_fn_folder.currentIndexChanged.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationFolderChanged(dashboard)
    )
    dashboard.ui.comboBox_sensor_nodes_autorun_hardware.currentIndexChanged.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunHardwareChanged(dashboard)
    )
    dashboard.ui.comboBox_sensor_nodes_autorun_plugin.currentIndexChanged.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunPluginChanged(dashboard)
    )
    dashboard.ui.comboBox_sensor_nodes_autorun_action.currentIndexChanged.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunActionChanged(dashboard)
    )

    # Push Button
    dashboard.ui.pushButton_sensor_nodes_activity_alerts_clear.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesActivityAlertsClearClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_activity_log_refresh.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesActivityRefreshClicked(dashboard)
    )
    dashboard.ui.tableWidget_sensor_nodes_activity_current_activity.itemSelectionChanged.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesActivityCurrentSelectionChanged(dashboard)
    )
    dashboard.ui.tabWidget.currentChanged.connect(
        lambda _index: SensorNodesTabSlots._slotSensorNodesActivityTabVisibilityChanged(dashboard)
    )
    dashboard.ui.tabWidget_sensor_nodes.currentChanged.connect(
        lambda _index: SensorNodesTabSlots._slotSensorNodesActivityTabVisibilityChanged(dashboard)
    )    
    dashboard.ui.pushButton_sensor_nodes_fn_local_delete.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalDeleteClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_local_choose.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalChooseClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_local_select.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalSelectClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_local_show_in_folder.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalShowInFolderClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_local_unzip.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalUnzipClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_fn_local_view.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesFileNavigationLocalViewClicked(dashboard)
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
    dashboard.ui.pushButton_sensor_nodes_autorun_query.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunQueryClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_customize.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunCustomizeClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_timing_add.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunTimingAddClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_detector_add.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunDetectorAddClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_detector_remove.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunDetectorRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_playlist_remove.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunPlaylistRemoveClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_playlist_clear.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunPlaylistClearClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_playlist_import.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunPlaylistImportClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_playlist_export.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunPlaylistExportClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_playlist_query.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunPlaylistQueryClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_playlist_load.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunPlaylistLoadClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_playlist_save_to_node.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunPlaylistSaveToNodeClicked(dashboard)
    )
    dashboard.ui.pushButton_sensor_nodes_autorun_start_stop.clicked.connect(
        lambda: SensorNodesTabSlots._slotSensorNodesAutorunStartStopClicked(dashboard)
    )

    dashboard.ui.pushButton_sn_plugins_refresh.clicked.connect(
        lambda: SensorNodesPluginsTabSlots._slotSensorNodesPluginsRefreshClicked(
            dashboard
        )
    )
    dashboard.ui.tableWidget_sn_plugins_inventory.itemSelectionChanged.connect(
        lambda: SensorNodesPluginsTabSlots._slotSensorNodesPluginInventorySelectionChanged(
            dashboard
        )
    )
    dashboard.ui.pushButton_sn_plugins_inventory_deploy.clicked.connect(
        lambda: SensorNodesPluginsTabSlots._slotSensorNodesPluginDeployClicked(
            dashboard
        )
    )
    dashboard.ui.pushButton_sn_plugins_inventory_repair.clicked.connect(
        lambda: SensorNodesPluginsTabSlots._slotSensorNodesPluginRepairClicked(
            dashboard
        )
    )
    dashboard.ui.pushButton_sn_plugins_inventory_remove.clicked.connect(
        lambda: SensorNodesPluginsTabSlots._slotSensorNodesPluginRemoveClicked(
            dashboard
        )
    )


def connect_library_slots(dashboard: Dashboard):
    # Combo Box
    dashboard.ui.comboBox_library_gallery_protocol.currentIndexChanged.connect(
        lambda: LibraryTabSlots._slotLibraryGalleryProtocolChanged(dashboard)
    )
    dashboard.ui.comboBox_library_browse.currentIndexChanged.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseChanged(dashboard)
    )
    
    # List Widget
    dashboard.ui.listWidget_library_gallery.currentItemChanged.connect(
        lambda: LibraryTabSlots._slotLibraryGalleryImageChanged(dashboard)
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
    dashboard.ui.pushButton_library_search_search_library.clicked.connect(
        lambda: LibraryTabSlots._slotLibrarySearchSearchLibraryClicked(dashboard)
    )
    dashboard.ui.pushButton_library_browse_pgadmin4.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryBrowsePgAdmin4_Clicked(dashboard)
    )
    dashboard.ui.pushButton_library_browse_delete_row.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseDeleteRowClicked(dashboard)
    )
    dashboard.ui.pushButton_library_browse_refresh.clicked.connect(
        lambda: LibraryTabSlots._slotLibraryBrowseRefreshClicked(dashboard)
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

