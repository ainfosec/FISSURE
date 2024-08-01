from ..Slots import StatusBarSlots
from .UI_Types import UI_Types
from PyQt5 import QtCore, QtGui, QtWidgets
from typing import List

import fissure.comms.Address

WIDGET_HEIGHT = 24
NO_MARGINS = QtCore.QMargins(0, 0, 0, 0)
FIXED_SIZE = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
DEFAULT_FONT = QtGui.QFont("Ubuntu Mono", 10)


class VLine(QtWidgets.QFrame):
    """Vertical line for the statusbar."""

    # a simple VLine, like the one you get from designer
    def __init__(self, parent=None):
        super(VLine, self).__init__(parent)
        self.parent = parent
        self.setFrameShape(self.VLine | self.Sunken)
        # self.setMaximumWidth(2)


class StatusLabel(QtWidgets.QLabel):
    def __init__(self, parent=None):
        super(StatusLabel, self).__init__(parent)
        self.parent = parent
        self.setMouseTracking(True)

    def enterEvent(self, event):
        self.parent.dialog.show()

    def leaveEvent(self, event):
        self.parent.dialog.hide()


class StatusDialog(QtWidgets.QFrame, UI_Types.Status):
    def __init__(self, parent=None):
        """First thing that executes."""
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.setupUi(self)

        # Move and Hide
        self.move(20, 755)
        self.hide()


class FissureStatusBar(QtWidgets.QStatusBar):
    # Formatting/Layout
    session_status: QtWidgets.QWidget
    session_inactive: QtWidgets.QWidget
    session_active: QtWidgets.QWidget

    # Components
    hiprfisr: QtWidgets.QPushButton
    tsi: QtWidgets.QPushButton
    pd: QtWidgets.QPushButton
    sensor_nodes: List[QtWidgets.QPushButton]

    # Sessions
    session_label: QtWidgets.QLabel
    connecting_button: QtWidgets.QPushButton
    local_button: QtWidgets.QPushButton
    remote_button: QtWidgets.QPushButton
    back_button: QtWidgets.QPushButton
    connect_button: QtWidgets.QPushButton
    disconnect_button: QtWidgets.QPushButton
    shutdown_button: QtWidgets.QPushButton

    # Remote Connections
    addr_prompt: QtWidgets.QWidget
    protocol_select: QtWidgets.QComboBox
    addr_box: QtWidgets.QLineEdit
    ports_prompt: QtWidgets.QWidget
    hb_port_box: QtWidgets.QLineEdit
    msg_port_box: QtWidgets.QLineEdit

    # Active Session
    addr_label: QtWidgets.QLabel

    # Dialog
    dialog: StatusDialog

    def __init__(self, parent):
        super(FissureStatusBar, self).__init__(parent)
        self.parent = parent
        self.setMouseTracking(True)

        self.setFont(DEFAULT_FONT)

        self.__init_components__()
        self.__init_session__()
        self.__init_format__()
        self.__connect_slots__()

        self.dialog = StatusDialog(parent=self.window())

    def __init_components__(self):
        """
        Initialize StatusBar Component Widgets
        """
        self.hiprfisr = QtWidgets.QPushButton("HIPRFISR: --", objectName="pushButton_status2")
        self.tsi = QtWidgets.QPushButton("TSI: --", objectName="pushButton_status3")
        self.pd = QtWidgets.QPushButton("PD: --", objectName="pushButton_status4")

        self.hiprfisr.setFlat(True)
        self.tsi.setFlat(True)
        self.pd.setFlat(True)

        # Sensor Nodes
        self.sensor_nodes = []
        for idx in range(5):
            sensor_node = QtWidgets.QPushButton(f"SN{idx+1}: --", objectName=f"pushButton_status{idx+5}")
            sensor_node.setFlat(True)
            self.sensor_nodes.append(sensor_node)

    def __init_session__(self):
        """
        Initialize StatusBar Session Widgets
        """
        self.session_label = QtWidgets.QLabel("Select Session Type:", objectName="label4_status1")
        self.local_button = QtWidgets.QPushButton("Local", objectName="pushButton_status_local")
        self.remote_button = QtWidgets.QPushButton("Remote", objectName="pushButton_status_remote")
        self.back_button = QtWidgets.QPushButton("Back", objectName="pushButton_status_back")
        self.connect_button = QtWidgets.QPushButton("Connect", objectName="pushButton_status_connect")
        self.connecting_button = QtWidgets.QPushButton("", objectName="pushButton_status_connecting")
        self.disconnect_button = QtWidgets.QPushButton("Disconnect", objectName="pushButton_status_disconnect")
        self.shutdown_button = QtWidgets.QPushButton("Shutdown", objectName="pushButton_status_shutdown")

        self.addr_prompt = QtWidgets.QWidget()
        self.protocol_select = QtWidgets.QComboBox(objectName="comboBox_status_protocol")
        self.protocol_select.addItem("tcp")
        self.protocol_select.addItem("ipc")
        self.addr_box = QtWidgets.QLineEdit()

        self.ports_prompt = QtWidgets.QWidget()
        self.hb_port_box = QtWidgets.QLineEdit()
        self.msg_port_box = QtWidgets.QLineEdit()

        self.addr_prompt.setLayout(QtWidgets.QHBoxLayout())
        self.addr_prompt.layout().setContentsMargins(NO_MARGINS)
        self.ports_prompt.setLayout(QtWidgets.QHBoxLayout())
        self.ports_prompt.layout().setContentsMargins(NO_MARGINS)

        self.addr_box.setAlignment(QtCore.Qt.AlignHCenter)
        self.hb_port_box.setAlignment(QtCore.Qt.AlignHCenter)
        self.msg_port_box.setAlignment(QtCore.Qt.AlignHCenter)

        self.addr_label = QtWidgets.QLabel(objectName="label4_status1")

        # Set Default Values
        self.addr_box.setText("127.0.0.1")
        self.hb_port_box.setText("5051")
        self.msg_port_box.setText("5052")
        self.ports_prompt.show()

    def __init_format__(self):
        """
        Initialize StatusBar Formatting
        """
        # Components (Permanent)
        self.addPermanentWidget(VLine())
        self.addPermanentWidget(self.hiprfisr)
        self.addPermanentWidget(VLine())
        self.addPermanentWidget(self.tsi)
        self.addPermanentWidget(VLine())
        self.addPermanentWidget(self.pd)
        self.addPermanentWidget(VLine())

        # Sensor Nodes (Permanent)
        for sensor_node in self.sensor_nodes:
            self.addPermanentWidget(sensor_node)
        self.addPermanentWidget(VLine(self.parent))

        # Session Status (Dynamic)
        self.session_status = QtWidgets.QWidget(self.parent)
        self.session_status.setFixedHeight(WIDGET_HEIGHT)
        self.session_status.setContentsMargins(NO_MARGINS)

        # Session Layout
        self.session_status.setLayout(QtWidgets.QHBoxLayout())
        self.session_status.layout().setContentsMargins(NO_MARGINS)

        # No Active Session
        self.session_inactive = QtWidgets.QWidget(self.session_status)
        self.session_inactive.setLayout(QtWidgets.QHBoxLayout())
        self.session_inactive.layout().setContentsMargins(NO_MARGINS)
        self.session_inactive.layout().addWidget(self.connecting_button)
        self.session_inactive.layout().addWidget(self.local_button)
        self.session_inactive.layout().addWidget(self.remote_button)
        self.session_status.layout().addWidget(self.session_inactive)

        # Protocl/Address Prompt (Static)
        self.addr_prompt.layout().addWidget(self.protocol_select)
        self.addr_prompt.layout().addWidget(QtWidgets.QLabel("://", objectName="label4_status1"))
        self.addr_prompt.layout().addWidget(self.addr_box)

        # Ports Prompt (Dynamic)
        self.ports_prompt.layout().addWidget(QtWidgets.QLabel("hb:", objectName="label4_status1"))
        self.ports_prompt.layout().addWidget(self.hb_port_box)
        self.ports_prompt.layout().addWidget(QtWidgets.QLabel("msg:", objectName="label4_status1"))
        self.ports_prompt.layout().addWidget(self.msg_port_box)

        self.session_inactive.layout().addWidget(self.addr_prompt)
        self.session_inactive.layout().addWidget(self.ports_prompt)
        self.session_inactive.layout().addWidget(self.connect_button)
        self.session_inactive.layout().addWidget(self.back_button)

        # Hide Prompt
        self.addr_prompt.hide()
        self.ports_prompt.hide()
        self.connect_button.hide()
        self.back_button.hide()
        self.local_button.hide()

        # Active Session - Show Address and Disconnect/Shutdown buttons
        self.session_active = QtWidgets.QWidget(self.session_status)
        self.session_active.setLayout(QtWidgets.QHBoxLayout())
        self.session_active.layout().setContentsMargins(NO_MARGINS)
        self.session_active.layout().addWidget(self.addr_label)  # FIX: Needs unique objectName for stylesheets
        self.session_active.layout().addWidget(self.disconnect_button)
        self.session_active.layout().addWidget(self.shutdown_button)
        self.session_status.layout().addWidget(self.session_active)

        # Fixed-Size Widgets
        # self.addr_prompt.setSizePolicy(FIXED_SIZE)
        # self.protocol_select.setSizePolicy(FIXED_SIZE)
        # self.addr_box.setSizePolicy(FIXED_SIZE)
        self.hb_port_box.setMaximumWidth(50)
        self.msg_port_box.setMaximumWidth(50)
        # self.ports_prompt.setSizePolicy(FIXED_SIZE)
        # self.connect_button.setSizePolicy(FIXED_SIZE)


        self.addWidget(VLine())
        self.addWidget(self.session_label)
        self.addWidget(self.session_status)
        self.addWidget(VLine())

        # Start with No Active Session
        self.session_active.hide()

    def __connect_slots__(self):
        self.local_button.clicked.connect(lambda: StatusBarSlots.startLocalSession(self.parent))
        self.remote_button.clicked.connect(lambda: StatusBarSlots.remote_connect_prompt(self))
        self.protocol_select.currentTextChanged.connect(lambda: StatusBarSlots.toggle_port_boxes(self))
        self.addr_box.returnPressed.connect(
            lambda: StatusBarSlots.connect(
                self.parent,
                fissure.comms.Address(
                    protocol=self.protocol_select.currentText(),
                    address=self.addr_box.text(),
                    hb_channel=self.hb_port_box.text(),
                    msg_channel=self.msg_port_box.text(),
                ),
            )
        )
        self.hb_port_box.returnPressed.connect(
            lambda: StatusBarSlots.connect(
                self.parent,
                fissure.comms.Address(
                    protocol=self.protocol_select.currentText(),
                    address=self.addr_box.text(),
                    hb_channel=self.hb_port_box.text(),
                    msg_channel=self.msg_port_box.text(),
                ),
            )
        )
        self.msg_port_box.returnPressed.connect(
            lambda: StatusBarSlots.connect(
                self.parent,
                fissure.comms.Address(
                    protocol=self.protocol_select.currentText(),
                    address=self.addr_box.text(),
                    hb_channel=self.hb_port_box.text(),
                    msg_channel=self.msg_port_box.text(),
                ),
            )
        )
        self.connect_button.clicked.connect(
            lambda: StatusBarSlots.connect(
                self.parent,
                fissure.comms.Address(
                    protocol=self.protocol_select.currentText(),
                    address=self.addr_box.text(),
                    hb_channel=self.hb_port_box.text(),
                    msg_channel=self.msg_port_box.text(),
                ),
            )
        )
        self.back_button.clicked.connect(lambda: StatusBarSlots.back(self.parent))
        self.disconnect_button.clicked.connect(lambda: StatusBarSlots.disconnect_hiprfisr(self.parent))
        self.shutdown_button.clicked.connect(lambda: StatusBarSlots.shutdown_hiprfisr(self.parent))

    def reset_session_inactive(self):
        """
        Reset session prompt widgets to their initial state.

        The following widgets will retain their previous values (for reconnecting):
            - protocol_select
            - addr_box
            - hb_port_box
            - msg_port_box
        """
        self.session_active.hide()    
        self.session_inactive.show()    

        # Reset Label
        self.session_label.setText("Select Session Type:")

        # Reset Buttons
        self.local_button.setText("Local")
        self.connect_button.setText("Connect")

        # Reset visible widgets
        # self.addr_prompt.hide()
        # self.ports_prompt.hide()
        # self.connect_button.hide()
        self.local_button.show()
        self.remote_button.show()

    def reset_session_active(self):
        """
        Reset session active widgets to their initial state
        """
        self.addr_label.setText("")
        self.disconnect_button.setText("Disconnect")
        self.shutdown_button.setText("Shutdown")

    def update_session_status(self, connected: bool, addr: fissure.comms.Address = None):
        if connected is True:
            self.session_label.setText("Server:")
            self.addr_label.setText(str(addr).split()[0])
            self.session_inactive.hide()
            self.session_active.show()

            self.hiprfisr.setText("HIPRFISR: OK")
        else:
            self.reset_session_active()
            self.session_active.hide()

            self.reset_session_inactive()
            self.session_inactive.show()

            self.hiprfisr.setText("HIPRFISR: --")
            self.tsi.setText("TSI: --")
            self.pd.setText("PD: --")

    def enterEvent(self, event):
        self.dialog.show()
        self.dialog.raise_()

    def leaveEvent(self, event):
        self.dialog.hide()