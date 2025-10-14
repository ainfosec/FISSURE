from PyQt5 import QtCore, QtWidgets
import fissure.utils


@QtCore.pyqtSlot(QtCore.QObject)
def _slotCopyToDataViewerClicked(DemodDlg: QtCore.QObject):
    """
    Confirms with the user, then copies the bitstream from the Bits tab
    into DemodDlg.return_value and closes the dialog.
    """
    bit_text = DemodDlg.textEdit_bits.toPlainText().strip()

    # No data case
    if not bit_text:
        DemodDlg.logger.warning("No bitstream data available to copy.")

        msg = QtWidgets.QMessageBox(DemodDlg)
        msg.setIcon(QtWidgets.QMessageBox.Warning)
        msg.setWindowTitle("No Data")
        msg.setText("No bitstream data is available to send to the Data Viewer.")
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
        msg.setStyleSheet("""
            QPushButton {
                min-width: 80px;
                min-height: 28px;
                padding: 4px 8px;
            }
        """)
        msg.exec_()
        return

    # Confirmation dialog
    confirm = QtWidgets.QMessageBox(DemodDlg)
    confirm.setIcon(QtWidgets.QMessageBox.Question)
    confirm.setWindowTitle("Copy to Data Viewer")
    confirm.setText(
        "This will close the Demodulation window and send the current Bits data "
        "to the Data Viewer.\n\nContinue?"
    )

    yes_button = confirm.addButton(QtWidgets.QMessageBox.Yes)
    no_button = confirm.addButton(QtWidgets.QMessageBox.No)
    confirm.setDefaultButton(no_button)

    # Equal button dimensions
    confirm.setStyleSheet("""
        QPushButton {
            min-width: 100px;
            min-height: 28px;
            padding: 4px 8px;
        }
    """)

    confirm.exec_()

    # If confirmed, close dialog and pass data back
    if confirm.clickedButton() == yes_button:
        DemodDlg.return_value = bit_text
        DemodDlg.logger.info(f"Sent {len(bit_text)} bits to Data Viewer.")
        DemodDlg.accept()
    else:
        DemodDlg.logger.info("Copy to Data Viewer cancelled.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotCopyToClipboardClicked(DemodDlg: QtCore.QObject):
    """
    Copies the text from the currently active data tab (Bits / Hex / ASCII)
    to the system clipboard.
    """
    clipboard = QtWidgets.QApplication.clipboard()
    current_index = DemodDlg.tabWidget_hex.currentIndex()

    # Determine which text box is active
    if current_index == 0:  # Bits tab
        text = DemodDlg.textEdit_bits.toPlainText()
    elif current_index == 1:  # Hex tab
        text = DemodDlg.textEdit_hex.toPlainText()
    elif current_index == 2:  # ASCII tab
        text = DemodDlg.textEdit_ascii.toPlainText()
    else:
        text = ""

    # Copy text if available
    if text.strip():
        clipboard.setText(text)
        DemodDlg.logger.info(f"Copied {len(text)} characters to clipboard.")
    else:
        DemodDlg.logger.warning("No text available to copy from the selected tab.")


@QtCore.pyqtSlot(QtCore.QObject)
def _slotCancelClicked(DemodDlg: QtCore.QObject):
    """The Cancel button is clicked in the dialog."""
    DemodDlg.close()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotInvertBitsClicked(DemodDlg: QtCore.QObject):
    """The Invert Bits checkbox is clicked in the dialog."""
    DemodDlg.extract_bits()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotDiffBitsClicked(DemodDlg: QtCore.QObject):
    """The Diff Bits checkbox is clicked in the dialog."""
    DemodDlg.extract_bits()


# ---------------- Slider Slots ---------------- #

@QtCore.pyqtSlot(QtCore.QObject)
def _slotDecimationChanged(DemodDlg: QtCore.QObject):
    """Update decimation and replot."""
    DemodDlg.decimation = int(DemodDlg.horizontalSlider_decimation.value())

    DemodDlg.doubleSpinBox_decimation.blockSignals(True)
    DemodDlg.doubleSpinBox_decimation.setValue(DemodDlg.decimation)
    DemodDlg.doubleSpinBox_decimation.blockSignals(False)

    DemodDlg._saved_xlim = None
    DemodDlg._saved_ylim = None
    DemodDlg.plot_signal()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotCenterChanged(DemodDlg: QtCore.QObject):
    """Update center line and replot."""
    DemodDlg.center = DemodDlg.horizontalSlider_center.value() / 100.0

    DemodDlg.doubleSpinBox_center.blockSignals(True)
    DemodDlg.doubleSpinBox_center.setValue(DemodDlg.center)
    DemodDlg.doubleSpinBox_center.blockSignals(False)

    DemodDlg.plot_signal()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotThresholdChanged(DemodDlg: QtCore.QObject):
    """Update threshold and replot."""
    DemodDlg.threshold = DemodDlg.horizontalSlider_threshold.value() / 100.0

    DemodDlg.doubleSpinBox_threshold.blockSignals(True)
    DemodDlg.doubleSpinBox_threshold.setValue(DemodDlg.threshold)
    DemodDlg.doubleSpinBox_threshold.blockSignals(False)

    DemodDlg.plot_signal()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSamplesPerSymbolChanged(DemodDlg: QtCore.QObject):
    """Update samples per symbol and replot."""
    DemodDlg.samples_per_symbol = int(DemodDlg.horizontalSlider_samples_per_symbol.value())

    DemodDlg.spinBox_samples_per_symbol.blockSignals(True)
    DemodDlg.spinBox_samples_per_symbol.setValue(DemodDlg.samples_per_symbol)
    DemodDlg.spinBox_samples_per_symbol.blockSignals(False)

    DemodDlg.plot_signal()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSampleOffsetChanged(DemodDlg: QtCore.QObject):
    """Update sample offset (only affects decoding)."""
    DemodDlg.sample_offset = int(DemodDlg.horizontalSlider_sample_offset.value())

    DemodDlg.spinBox_sample_offset.blockSignals(True)
    DemodDlg.spinBox_sample_offset.setValue(DemodDlg.sample_offset)
    DemodDlg.spinBox_sample_offset.blockSignals(False)

    DemodDlg.plot_signal()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotBitShiftChanged(DemodDlg: QtCore.QObject):
    """Update bit shift (only affects decoding)."""
    DemodDlg.bit_shift = int(DemodDlg.horizontalSlider_bit_shift.value())

    DemodDlg.spinBox_bit_shift.blockSignals(True)
    DemodDlg.spinBox_bit_shift.setValue(DemodDlg.bit_shift)
    DemodDlg.spinBox_bit_shift.blockSignals(False)

    DemodDlg.extract_bits()


# ---------------- SpinBox Slots ---------------- #

@QtCore.pyqtSlot(QtCore.QObject)
def _slotSpinBoxDecimationChanged(DemodDlg: QtCore.QObject):
    """Sync spinbox → slider for decimation."""
    DemodDlg.decimation = int(DemodDlg.doubleSpinBox_decimation.value())
    DemodDlg.horizontalSlider_decimation.blockSignals(True)
    DemodDlg.horizontalSlider_decimation.setValue(DemodDlg.decimation)
    DemodDlg.horizontalSlider_decimation.blockSignals(False)
    DemodDlg.plot_signal()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSpinBoxCenterChanged(DemodDlg: QtCore.QObject):
    """Sync spinbox → slider for center line."""
    DemodDlg.center = float(DemodDlg.doubleSpinBox_center.value())
    DemodDlg.horizontalSlider_center.blockSignals(True)
    DemodDlg.horizontalSlider_center.setValue(int(DemodDlg.center * 100))
    DemodDlg.horizontalSlider_center.blockSignals(False)
    DemodDlg.plot_signal()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSpinBoxThresholdChanged(DemodDlg: QtCore.QObject):
    """Sync spinbox → slider for threshold."""
    DemodDlg.threshold = float(DemodDlg.doubleSpinBox_threshold.value())
    DemodDlg.horizontalSlider_threshold.blockSignals(True)
    DemodDlg.horizontalSlider_threshold.setValue(int(DemodDlg.threshold * 100))
    DemodDlg.horizontalSlider_threshold.blockSignals(False)
    DemodDlg.plot_signal()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSpinBoxSamplesPerSymbolChanged(DemodDlg: QtCore.QObject):
    """Sync spinbox → slider for samples per symbol."""
    DemodDlg.samples_per_symbol = int(DemodDlg.spinBox_samples_per_symbol.value())
    DemodDlg.horizontalSlider_samples_per_symbol.blockSignals(True)
    DemodDlg.horizontalSlider_samples_per_symbol.setValue(DemodDlg.samples_per_symbol)
    DemodDlg.horizontalSlider_samples_per_symbol.blockSignals(False)
    DemodDlg.plot_signal()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSpinBoxSampleOffsetChanged(DemodDlg: QtCore.QObject):
    """Sync spinbox → slider for sample offset."""
    DemodDlg.sample_offset = int(DemodDlg.spinBox_sample_offset.value())
    DemodDlg.horizontalSlider_sample_offset.blockSignals(True)
    DemodDlg.horizontalSlider_sample_offset.setValue(DemodDlg.sample_offset)
    DemodDlg.horizontalSlider_sample_offset.blockSignals(False)
    DemodDlg.extract_bits()


@QtCore.pyqtSlot(QtCore.QObject)
def _slotSpinBoxBitShiftChanged(DemodDlg: QtCore.QObject):
    """Sync spinbox → slider for bit shift."""
    DemodDlg.bit_shift = int(DemodDlg.spinBox_bit_shift.value())
    DemodDlg.horizontalSlider_bit_shift.blockSignals(True)
    DemodDlg.horizontalSlider_bit_shift.setValue(DemodDlg.bit_shift)
    DemodDlg.horizontalSlider_bit_shift.blockSignals(False)
    DemodDlg.extract_bits()
