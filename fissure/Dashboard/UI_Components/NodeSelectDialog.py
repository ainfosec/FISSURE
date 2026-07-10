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
        Contains the connect functions for all the signals and slots
        """                    
        # Connect slots
        self.pushButton_node_refresh.clicked.connect(lambda: NodeSelectSlots.refreshClicked(self))
        self.pushButton_node_select.clicked.connect(lambda: NodeSelectSlots.selectClicked(self))
        self.pushButton_cancel.clicked.connect(self.close)


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
        Populate the table for the select sensor node dialog.
        """
        # Dynamic widget lookup
        table = self.tableWidget_node_list

        # Clear existing rows
        table.setRowCount(0)

        # Iterate over nodes dict (uuid → info)
        for uuid, info in nodes.items():
            # Extract fields with fallbacks
            ip            = info.get("ip", "—")
            nickname      = info.get("nickname", "—")
            # network_type  = info.get("network_type", "—")
            assigned_id   = info.get("assigned_id", "—")
            last_seen_ts  = info.get("last_seen", None)
            # connected     = info.get("connected", False)

            # Format last seen
            if last_seen_ts:
                delta = time.time() - last_seen_ts
                last_seen = f"{delta:.1f} sec ago"
            else:
                last_seen = "—"

            # Format connected
            # conn_text = "Yes" if connected else "No"

            # Add row
            row = table.rowCount()
            table.insertRow(row)

            table.setItem(row, 0, QtWidgets.QTableWidgetItem(str(nickname)))
            table.setItem(row, 1, QtWidgets.QTableWidgetItem(str(uuid)))
            table.setItem(row, 2, QtWidgets.QTableWidgetItem(str(ip)))
            # table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(network_type)))
            table.setItem(row, 3, QtWidgets.QTableWidgetItem(str(assigned_id)))
            table.setItem(row, 4, QtWidgets.QTableWidgetItem(str(last_seen)))
            # table.setItem(row, 5, QtWidgets.QTableWidgetItem(str(conn_text)))

        # Resize Table
        table.resizeColumnsToContents()
        table.resizeRowsToContents()
        table.horizontalHeader().setStretchLastSection(False)
        table.horizontalHeader().setStretchLastSection(True)

        if table.rowCount() > 0:
            table.selectRow(0)
            table.setCurrentCell(0, 0)
