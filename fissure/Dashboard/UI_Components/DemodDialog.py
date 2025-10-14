from ..Slots import DemodDialogSlots
from .UI_Types import UI_Types
from PyQt5 import QtCore, QtWidgets
import fissure.utils
from typing import List

from matplotlib.figure import Figure
from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
import numpy as np
from PyQt5.QtWidgets import QVBoxLayout, QFrame
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar


class DemodDialog(QtWidgets.QDialog, UI_Types.Demod):

    def __init__(self, parent: QtWidgets.QWidget, dashboard: QtCore.QObject, filepath: str, sample_rate: float, signal_data: List):
        QtWidgets.QDialog.__init__(self, parent)
        self.parent = parent
        self.dashboard = dashboard
        self.setupUi(self)
        self.return_value = []

        self.logger = fissure.utils.get_logger(f"{fissure.comms.Identifiers.DASHBOARD}.frontend")

        # Save Values
        self.sample_rate = sample_rate
        self.signal_data = signal_data

        # Prevent Resizing/Maximizing
        self.parent.setFixedSize(QtCore.QSize(1100, 920))

        # Connect Signals to Slots
        self.__connect_slots__()

        # Set Filepath
        self.label2_filepath.setText(filepath)

        # Plot area
        self.fig = Figure(figsize=(5, 3))
        self.canvas = FigureCanvas(self.fig)
        self.ax = self.fig.add_subplot(111)

        layout = QVBoxLayout(self.frame3_iq)
        layout.setContentsMargins(0, 0, 0, 0)
        toolbar = NavigationToolbar(self.canvas, self.frame3_iq)
        layout.addWidget(toolbar)
        layout.addWidget(self.canvas)

        # Persisted view (None until the user zooms/pans)
        self._saved_xlim = None
        self._saved_ylim = None

        # Remember view whenever user finishes a pan/zoom or uses the wheel
        self._cid_release = self.canvas.mpl_connect('button_release_event', self._on_nav_event)
        self._cid_scroll  = self.canvas.mpl_connect('scroll_event', self._on_nav_event)

        # Initialize state from widgets
        self.decimation = int(self.doubleSpinBox_decimation.value())             # keep int until resampling supported
        self.center = float(self.doubleSpinBox_center.value())
        self.threshold = float(self.doubleSpinBox_threshold.value())
        self.samples_per_symbol = int(self.spinBox_samples_per_symbol.value())
        self.sample_offset = int(self.spinBox_sample_offset.value())
        self.bit_shift = int(self.spinBox_bit_shift.value())

        # Initial plot & decode
        self.plot_signal()


    def __connect_slots__(self):
        """
        Contains the connect functions for all the signals and slots
        """
        # Buttons
        self.pushButton_data_viewer.clicked.connect(lambda: DemodDialogSlots._slotCopyToDataViewerClicked(self))
        self.pushButton_clipboard.clicked.connect(lambda: DemodDialogSlots._slotCopyToClipboardClicked(self))
        self.pushButton_cancel.clicked.connect(lambda: DemodDialogSlots._slotCancelClicked(self))

        # Checkboxes
        self.checkBox_invert_bits.clicked.connect(lambda: DemodDialogSlots._slotInvertBitsClicked(self))
        self.checkBox_diff_bits.clicked.connect(lambda: DemodDialogSlots._slotDiffBitsClicked(self))

        # Sliders (update on release to avoid UI churn)
        self.horizontalSlider_decimation.sliderReleased.connect(lambda: DemodDialogSlots._slotDecimationChanged(self))
        self.horizontalSlider_center.sliderReleased.connect(lambda: DemodDialogSlots._slotCenterChanged(self))
        self.horizontalSlider_threshold.sliderReleased.connect(lambda: DemodDialogSlots._slotThresholdChanged(self))
        self.horizontalSlider_samples_per_symbol.sliderReleased.connect(lambda: DemodDialogSlots._slotSamplesPerSymbolChanged(self))
        self.horizontalSlider_sample_offset.sliderReleased.connect(lambda: DemodDialogSlots._slotSampleOffsetChanged(self))
        self.horizontalSlider_bit_shift.sliderReleased.connect(lambda: DemodDialogSlots._slotBitShiftChanged(self))

        # Spinboxes (immediate)
        self.doubleSpinBox_decimation.valueChanged.connect(lambda: DemodDialogSlots._slotSpinBoxDecimationChanged(self))
        self.doubleSpinBox_center.valueChanged.connect(lambda: DemodDialogSlots._slotSpinBoxCenterChanged(self))
        self.doubleSpinBox_threshold.valueChanged.connect(lambda: DemodDialogSlots._slotSpinBoxThresholdChanged(self))
        self.spinBox_samples_per_symbol.valueChanged.connect(lambda: DemodDialogSlots._slotSpinBoxSamplesPerSymbolChanged(self))
        self.spinBox_sample_offset.valueChanged.connect(lambda: DemodDialogSlots._slotSpinBoxSampleOffsetChanged(self))
        self.spinBox_bit_shift.valueChanged.connect(lambda: DemodDialogSlots._slotSpinBoxBitShiftChanged(self))


    def plot_signal(self):
        import numpy as np

        fm_data = np.asarray(self.signal_data)
        fs = float(self.sample_rate)
        decimation = int(self.decimation)
        center = float(self.center)
        threshold = float(self.threshold)
        sps = max(1, int(self.samples_per_symbol))

        if decimation > 1:
            fm_data, fs = self.get_decimated_data()

        t = np.arange(len(fm_data)) / fs

        self.ax.clear()
        self.ax.plot(t, fm_data, linewidth=0.8, color='deepskyblue', label="FM Demod")

        self.ax.grid(True, alpha=0.3)
        self.ax.set_xlabel("Time (s)")
        if str(self.comboBox_demod_type.currentText()) == "FM":
            self.ax.set_ylabel("Frequency deviation (Hz)")
        self.ax.set_title("FM Signal with Threshold and Bit Overlay")

        upper = center + threshold
        lower = center - threshold
        self.ax.axhline(y=center, color='gray', linestyle='--', alpha=0.6, label='Center')
        self.ax.axhline(y=upper, color='orange', linestyle='--', alpha=0.7, label='+Threshold')
        self.ax.axhline(y=lower, color='orange', linestyle='--', alpha=0.7, label='-Threshold')
        self.ax.fill_between(t, lower, upper, color='orange', alpha=0.08)

        if threshold > 0:
            bits = np.zeros(len(fm_data), dtype=int)
            state = 0
            for i, s in enumerate(fm_data):
                if s > upper:
                    state = 1
                elif s < lower:
                    state = 0
                bits[i] = state

            indices = np.arange(sps // 2, len(bits), sps)
            symbol_bits = bits[indices]
            symbol_times = t[indices]

            bit_amp = threshold * 0.7 if threshold != 0 else (np.max(fm_data) - np.min(fm_data)) * 0.05
            bit_wave = center + (symbol_bits * 2 - 1) * bit_amp
            self.ax.plot(symbol_times, bit_wave, color='black', linewidth=1.0, alpha=0.8, label="Detected Bits")

            colors = np.where(symbol_bits == 1, 'green', 'red')
            max_pts = 5000
            if len(symbol_times) > max_pts:
                step = max(1, len(symbol_times) // max_pts)
                self.ax.scatter(symbol_times[::step], bit_wave[::step], c=colors[::step], s=10, zorder=3, label="Sample Points")
            else:
                self.ax.scatter(symbol_times, bit_wave, c=colors, s=10, zorder=3, label="Sample Points")

        # --- Restore user view only if we have one recorded ---
        if self._saved_xlim is not None and self._saved_ylim is not None:
            self.ax.set_xlim(self._saved_xlim)
            self.ax.set_ylim(self._saved_ylim)

        self.ax.legend(loc='upper right', fontsize=8)
        self.canvas.draw_idle()

        self.extract_bits()


    def extract_bits(self):
        """
        Threshold the FM-demodulated signal and extract symbol bits,
        apply inversion, differential decoding, and bit shift,
        then populate text edits. Uses self.* state.
        """
        import numpy as np

        fm_data, _ = self.get_decimated_data()
        fs = float(self.sample_rate)
        center = float(self.center)
        threshold = float(self.threshold)
        sps = max(1, int(self.samples_per_symbol))
        sample_offset = max(0, int(self.sample_offset))
        bit_shift = max(0, int(self.bit_shift))

        # Early exit if threshold disabled
        if threshold <= 0:
            self.textEdit_bits.clear()
            self.textEdit_hex.clear()
            self.textEdit_ascii.clear()
            return

        upper = center + threshold
        lower = center - threshold

        # --- Hysteresis thresholding ---
        bits = np.zeros(len(fm_data), dtype=int)
        state = 0
        for i, s in enumerate(fm_data):
            if s > upper:
                state = 1
            elif s < lower:
                state = 0
            bits[i] = state

        # --- Symbol sampling ---
        start = sample_offset
        if start >= len(bits):
            self.textEdit_bits.clear()
            self.textEdit_hex.clear()
            self.textEdit_ascii.clear()
            return

        indices = np.arange(start, len(bits), sps)
        symbol_bits = bits[indices]
        if symbol_bits.size == 0:
            self.textEdit_bits.clear()
            self.textEdit_hex.clear()
            self.textEdit_ascii.clear()
            return

        # --- Optional bit inversion ---
        if self.checkBox_invert_bits.isChecked():
            symbol_bits = 1 - symbol_bits  # flips 1→0 and 0→1

        # --- Optional differential decoding ---
        if self.checkBox_diff_bits.isChecked():
            # XOR successive bits: diff[n] = bit[n] XOR bit[n-1]
            diff_bits = np.zeros_like(symbol_bits)
            diff_bits[1:] = np.logical_xor(symbol_bits[1:], symbol_bits[:-1])
            symbol_bits = diff_bits.astype(int)

        # --- Convert to string and shift bits ---
        bit_str = ''.join(map(str, symbol_bits.tolist()))
        if 0 < bit_shift < len(bit_str):
            bit_str = bit_str[bit_shift:] + bit_str[:bit_shift]

        # --- Pad to full bytes ---
        rem = len(bit_str) % 8
        if rem:
            bit_str += '0' * (8 - rem)

        # --- Hex & ASCII conversion ---
        hex_str = ''.join(f"{int(bit_str[i:i+8], 2):02X}" for i in range(0, len(bit_str), 8))
        ascii_str = ''.join(
            (chr(v) if 32 <= (v := int(bit_str[i:i+8], 2)) <= 126 else '.')
            for i in range(0, len(bit_str), 8)
        )

        # --- Update GUI fields ---
        self.textEdit_bits.setPlainText(bit_str)
        self.textEdit_hex.setPlainText(hex_str)
        self.textEdit_ascii.setPlainText(ascii_str)


    def _on_nav_event(self, event):
        # Only record if interacting with our axes
        if hasattr(event, "inaxes") and event.inaxes is self.ax:
            self._saved_xlim = self.ax.get_xlim()
            self._saved_ylim = self.ax.get_ylim()


    def get_decimated_data(self):
        """Return FM data and effective sample rate after decimation."""
        fm_data = np.asarray(self.signal_data)
        fs = float(self.sample_rate)
        dec = max(1, int(self.decimation))
        if dec > 1:
            fm_data = fm_data[::dec]
            fs /= dec
        return fm_data, fs