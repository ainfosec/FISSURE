from ..Slots import NodeSelectSlots
from .UI_Types import UI_Types
from PyQt5 import QtCore, QtWidgets, QtGui

import fissure.comms
import os
import time
import yaml


class NodeSelectDialog(QtWidgets.QDialog, UI_Types.Node_Select):

    def __init__(self, parent: QtWidgets.QWidget, dashboard: QtCore.QObject):
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.dashboard = dashboard
        self.setupUi(self)

        # Prevent resizing/maximizing the dialog.
        self.setFixedSize(QtCore.QSize(920, 430))

        # Connect Signals to Slots
        self.__connect_slots__()

        # Refresh
        NodeSelectSlots.refreshClicked(self)

    
    def showEvent(self, event):
        """
        Keep the node selection dialog centered on the Dashboard screen.
        """
        super().showEvent(event)

        parent = self.parentWidget()

        if parent is None:
            parent = getattr(self, "parent", None)

        if parent is None:
            return

        parent_window = parent.window()
        parent_center = parent_window.frameGeometry().center()

        dialog_geometry = self.frameGeometry()
        dialog_geometry.moveCenter(parent_center)

        # Clamp to the same screen as the Dashboard.
        screen = None
        if parent_window.windowHandle() is not None:
            screen = parent_window.windowHandle().screen()

        if screen is not None:
            available = screen.availableGeometry()
            top_left = dialog_geometry.topLeft()

            if top_left.x() < available.left():
                top_left.setX(available.left())
            if top_left.y() < available.top():
                top_left.setY(available.top())
            if dialog_geometry.right() > available.right():
                top_left.setX(available.right() - dialog_geometry.width())
            if dialog_geometry.bottom() > available.bottom():
                top_left.setY(available.bottom() - dialog_geometry.height())

            self.move(top_left)
        else:
            self.move(dialog_geometry.topLeft())


    def __connect_slots__(self):
        """
        Connect dialog controls and keep Select synchronized with the
        connection state of the current row.
        """
        self.pushButton_node_refresh.clicked.connect(
            lambda: NodeSelectSlots.refreshClicked(self)
        )
        self.pushButton_node_select.clicked.connect(
            lambda: NodeSelectSlots.selectClicked(self)
        )
        self.pushButton_cancel.clicked.connect(
            self.close
        )
        self.tableWidget_node_list.itemSelectionChanged.connect(
            self._updateNodeSelectButtonState
        )


    def _updateNodeSelectButtonState(self):
        """
        A new Dashboard-selected-node context requires a live settings return,
        so disconnected nodes remain visible but cannot be selected here.
        """
        table = self.tableWidget_node_list
        row = table.currentRow()

        if row < 0:
            self.pushButton_node_select.setEnabled(False)
            self.pushButton_node_select.setToolTip(
                "Select a connected Sensor Node."
            )
            return

        connection_item = table.item(row, 5)

        if connection_item is None:
            connected = False
        else:
            connected_value = connection_item.data(QtCore.Qt.UserRole)

            if connected_value is None:
                connected = (
                    connection_item.text().strip().lower()
                    == "connected"
                )
            else:
                connected = bool(connected_value)

        self.pushButton_node_select.setEnabled(connected)

        if connected:
            self.pushButton_node_select.setToolTip(
                "Select this Sensor Node."
            )
        else:
            self.pushButton_node_select.setToolTip(
                "Reconnect this Sensor Node before selecting it."
            )

    # def closeEvent(self, event):
    #     """
    #     Close the HW Select window without saving changes
    #     """
    #     # Detect Connect without Saving
    #     if any(self.new_local_connection):
    #         fissure.Dashboard.UI_Components.Qt5.errorMessage("Click Apply or delete local sensor node before cancelling.")
    #         event.ignore()
    #     else:
    #         # Close Window
    #         event.accept()


    def refreshNodes(self, nodes):
        """
        Populate the Sensor Node selection table.

        Disconnected nodes remain visible so their state and last-seen time can
        be inspected, but the Select button is disabled while one is selected.
        """
        table = self.tableWidget_node_list

        if table.columnCount() < 6:
            table.setColumnCount(6)

        connection_header = table.horizontalHeaderItem(5)
        if connection_header is None:
            connection_header = QtWidgets.QTableWidgetItem()
            table.setHorizontalHeaderItem(5, connection_header)
        connection_header.setText("Connection")

        table.setRowCount(0)

        for uuid, info in nodes.items():
            ip = info.get("ip", "—")
            nickname = info.get("nickname", "—")
            assigned_id = info.get("assigned_id", "—")
            last_seen_ts = info.get("last_seen", None)
            connected = bool(info.get("connected", False))

            if last_seen_ts:
                try:
                    delta = max(
                        0.0,
                        time.time() - float(last_seen_ts),
                    )
                    last_seen = f"{delta:.1f} sec ago"
                except (TypeError, ValueError):
                    last_seen = str(last_seen_ts)
            else:
                last_seen = "—"

            connection_text = (
                "Connected"
                if connected
                else "Disconnected"
            )

            row = table.rowCount()
            table.insertRow(row)

            values = [
                nickname,
                uuid,
                ip,
                assigned_id,
                last_seen,
                connection_text,
            ]

            for column, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(str(value))

                if column == 5:
                    item.setData(
                        QtCore.Qt.UserRole,
                        connected,
                    )

                table.setItem(
                    row,
                    column,
                    item,
                )

        table.resizeColumnsToContents()
        table.resizeRowsToContents()
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setStretchLastSection(True)

        if table.rowCount() > 0:
            table.selectRow(0)
            table.setCurrentCell(0, 0)

        self._updateNodeSelectButtonState()