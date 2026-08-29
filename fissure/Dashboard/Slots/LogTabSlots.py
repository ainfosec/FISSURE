from PyQt5 import QtCore, QtWidgets, QtGui
import os
import fissure.utils


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLogRefreshClicked(dashboard: QtCore.QObject):
    """ 
    Refresh is clicked in the Log tab
    """
    # Attain Keywords
    bad_words = []
    if dashboard.ui.checkBox_log_heartbeats.isChecked():
        bad_words.append('Heartbeat')
        bad_words.append('heartbeat')
    if dashboard.ui.checkBox_log_tsi.isChecked():
        bad_words.append('fissure.tsi')
    if dashboard.ui.checkBox_log_sensor_node.isChecked():
        bad_words.append('fissure.sensor node')
    if dashboard.ui.checkBox_log_dashboard.isChecked():
        bad_words.append('fissure.dashboard')
    if dashboard.ui.checkBox_log_pd.isChecked():
        bad_words.append('fissure.pd')
    if dashboard.ui.checkBox_log_hiprfisr.isChecked():
        bad_words.append('fissure.hiprfisr')
    if dashboard.ui.checkBox_log_debug.isChecked():
        bad_words.append('[DEBUG]')
    if dashboard.ui.checkBox_log_info.isChecked():
        bad_words.append('[INFO]')
    if dashboard.ui.checkBox_log_warning.isChecked():
        bad_words.append('[WARNING]')
    if dashboard.ui.checkBox_log_error.isChecked():
        bad_words.append('[ERROR]')

    # Remove Lines with Keywords
    event_log_filepath = os.path.join(fissure.utils.LOG_DIR, "event.log")
    filtered_log_lines = []
    with open(event_log_filepath) as oldfile:
        for line in oldfile:
            if not any(bad_word in line for bad_word in bad_words):
                filtered_log_lines.append(line)

    # Display the filtered log content directly in the UI
    temp_log_contents = ''.join(filtered_log_lines)
    dashboard.ui.textEdit2_log.setPlainText(temp_log_contents)
    dashboard.ui.textEdit2_log.moveCursor(QtGui.QTextCursor.End)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLogRefreshPermitClicked(dashboard: QtCore.QObject):
    """ 
    Permit refresh is clicked in the Log tab
    """
    # Attain Keywords
    good_words = []
    if dashboard.ui.checkBox_log_heartbeats_permit.isChecked():
        good_words.append('Heartbeat')
        good_words.append('heartbeat')
    if dashboard.ui.checkBox_log_tsi_permit.isChecked():
        good_words.append('fissure.tsi')
    if dashboard.ui.checkBox_log_sensor_node_permit.isChecked():
        good_words.append('fissure.sensor node')
    if dashboard.ui.checkBox_log_dashboard_permit.isChecked():
        good_words.append('fissure.dashboard')
    if dashboard.ui.checkBox_log_pd_permit.isChecked():
        good_words.append('fissure.pd')
    if dashboard.ui.checkBox_log_hiprfisr_permit.isChecked():
        good_words.append('fissure.hiprfisr')
    if dashboard.ui.checkBox_log_debug_permit.isChecked():
        good_words.append('[DEBUG]')
    if dashboard.ui.checkBox_log_info_permit.isChecked():
        good_words.append('[INFO]')
    if dashboard.ui.checkBox_log_warning_permit.isChecked():
        good_words.append('[WARNING]')
    if dashboard.ui.checkBox_log_error_permit.isChecked():
        good_words.append('[ERROR]')

    # Read and Filter the Log File Content Directly
    event_log_filepath = os.path.join(fissure.utils.LOG_DIR, "event.log")
    filtered_log_lines = []
    with open(event_log_filepath) as oldfile:
        for line in oldfile:
            if any(good_word in line for good_word in good_words):
                filtered_log_lines.append(line)

    # Display the Text
    temp_log_contents = ''.join(filtered_log_lines)
    dashboard.ui.textEdit2_log.setPlainText(temp_log_contents)
    dashboard.ui.textEdit2_log.moveCursor(QtGui.QTextCursor.End)


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLogSaveAllClicked(dashboard: QtCore.QObject):
    """Save selected session log content to a new log file."""
    directory = os.path.join(fissure.utils.LOG_DIR, "Session Logs")

    dialog = QtWidgets.QFileDialog()
    dialog.setDirectory(directory)
    dialog.setFilter(dialog.filter() | QtCore.QDir.Hidden)
    dialog.setDefaultSuffix("log")
    dialog.setAcceptMode(QtWidgets.QFileDialog.AcceptSave)
    dialog.setNameFilters(["Log Files (*.log)"])

    if dialog.exec_() == QtWidgets.QDialog.Accepted:
        fname = str(dialog.selectedFiles()[0])
    else:
        fname = ""

    if not fname:
        return

    if not fname.endswith(".log"):
        fname += ".log"

    event_log_filepath = os.path.join(fissure.utils.LOG_DIR, "event.log")

    with open(fname, "w") as new_file:
        if dashboard.ui.checkBox_log_system_log.isChecked():
            new_file.write("#########################################################################\n")
            new_file.write("############################## System Log ###############################\n")
            new_file.write("#########################################################################\n")
            with open(event_log_filepath) as mylogfile:
                new_file.write(mylogfile.read())

        if dashboard.ui.checkBox_log_session_notes.isChecked():
            new_file.write("#########################################################################\n")
            new_file.write("############################# Session Notes #############################\n")
            new_file.write("#########################################################################\n")
            new_file.write(dashboard.ui.textEdit1_log_notes.toPlainText())


@QtCore.pyqtSlot(QtCore.QObject)
def _slotLogOptionsClicked(dashboard: QtCore.QObject):
    """
    Opens the Options dialog to make it easier to set the log level.
    """
    # Open the Menu
    fissure.Dashboard.Slots.MenuBarSlots._slotMenuOptionsClicked(dashboard)