"""Protocol Discovery / Bitstream & Framing UI, plotting and framing results.

Decoding and candidate framing live in a reusable Qt-free utility module.
"""

import inspect
import os

import numpy as np
from PyQt5 import QtCore, QtGui, QtWidgets
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT

import fissure.utils
from fissure.utils.protocol_bitstream import normalize_bits, read_bitstream_file
from fissure.utils.protocol_framing import analyze_bitstream, format_message, preview_hex
from .pd_demodulation import _PDDemodulationCanvas, _pd_style_axes, _pd_theme


_BF_OVERVIEW_BINS = 2000
_BF_MAX_DETAIL_BITS = 12000
_BF_INITIAL_VIEW_BITS = 256


def _bf_set_source(dashboard, source):
    ui = dashboard.ui
    dashboard.sa_pd_bf_source = source
    for name in ("from_demodulation", "artifact", "local_file"):
        button = getattr(ui, "pushButton_sa_pd_bf_input_" + name)
        was_blocked = button.blockSignals(True)
        button.setChecked(source == name)
        button.blockSignals(was_blocked)
    ui.stackedWidget_sa_pd_bf_input_source.setCurrentIndex(
        {"artifact": 0, "local_file": 1, "from_demodulation": 2}[source]
    )


def _bf_clear(dashboard, message="Select a bitstream"):
    dashboard.sa_pd_bf_bits = None
    dashboard.sa_pd_bf_prefix = None
    dashboard.sa_pd_bf_decoded_bits = None
    dashboard.sa_pd_bf_frames = []
    dashboard.sa_pd_bf_analysis = None
    dashboard.sa_pd_bf_metadata = {}
    dashboard.sa_pd_bf_selection = None
    dashboard.sa_pd_bf_view = None
    dashboard.sa_pd_bf_drag_start = None
    for name in ("data_type", "length", "symbol_rate", "timing_available"):
        getattr(dashboard.ui, f"label2_sa_pd_bf_input_{name}").setText("—")
    dashboard.ui.label2_sa_pd_bf_bitstream_selection.setText("—")
    dashboard.ui.label2_sa_pd_bf_messages_count.setText("0 messages")
    dashboard.ui.label2_sa_pd_bf_messages_status.setText(message)
    dashboard.ui.tableWidget_sa_pd_bf_messages.setRowCount(0)
    for name in ("hex", "binary", "ascii"):
        getattr(dashboard.ui, "plainTextEdit_sa_pd_bf_selected_" + name).clear()
    _bf_update_controls(dashboard)
    _bf_draw(dashboard)


def _bf_load_bits(dashboard, bits, source, metadata=None):
    try:
        values = normalize_bits(bits)
    except (TypeError, ValueError) as error:
        _bf_clear(dashboard, str(error))
        return False
    dashboard.sa_pd_bf_bits = values
    dashboard.sa_pd_bf_prefix = np.r_[0, np.cumsum(values, dtype=np.int64)]
    dashboard.sa_pd_bf_decoded_bits = None
    dashboard.sa_pd_bf_frames = []
    dashboard.sa_pd_bf_analysis = None
    dashboard.sa_pd_bf_metadata = dict(metadata or {})
    dashboard.sa_pd_bf_selection = None
    dashboard.sa_pd_bf_drag_start = None
    dashboard.sa_pd_bf_view = (0, min(len(values), _BF_INITIAL_VIEW_BITS))
    _bf_set_source(dashboard, source)
    ui = dashboard.ui
    ui.radioButton_sa_pd_bf_bitstream_raw.setChecked(True)
    ui.label2_sa_pd_bf_input_data_type.setText(str(dashboard.sa_pd_bf_metadata.get("data_type") or "Raw Bits"))
    ui.label2_sa_pd_bf_input_length.setText(f"{len(values):,} bits")
    rate = dashboard.sa_pd_bf_metadata.get("symbol_rate")
    ui.label2_sa_pd_bf_input_symbol_rate.setText(
        f"{float(rate):,.4g} sym/s" if rate is not None and float(rate) > 0 else "—"
    )
    timing = dashboard.sa_pd_bf_metadata.get("sample_centers")
    ui.label2_sa_pd_bf_input_timing_available.setText(
        "No" if timing is None else
        "Estimated" if dashboard.sa_pd_bf_metadata.get("timing_uncertain") else "Yes"
    )
    ui.label2_sa_pd_bf_messages_count.setText("0 messages")
    ui.label2_sa_pd_bf_messages_status.setText("Ready for framing analysis")
    ui.tableWidget_sa_pd_bf_messages.setRowCount(0)
    for name in ("hex", "binary", "ascii"):
        getattr(ui, "plainTextEdit_sa_pd_bf_selected_" + name).clear()
    _bf_update_controls(dashboard)
    _bf_draw(dashboard)
    return True


def load_sa_pd_bf_from_demodulation(dashboard):
    """Transfer the complete recovered candidate, never its 4096-bit preview."""
    result = getattr(dashboard, "sa_pd_demodulation_result", None)
    if not isinstance(result, dict) or result.get("bits") is None:
        _bf_clear(dashboard, "Demodulate a signal first")
        return False
    metadata = {
        "data_type": "Recovered Bits",
        "path": (getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}).get("path"),
        "soi_id": (getattr(dashboard, "sa_pd_demodulation_file_metadata", {}) or {}).get("soi_id"),
        "symbol_rate": result.get("symbol_rate"),
        "modulation": result.get("method"),
        "sample_centers": result.get("centers"),
        "source_sample_rate": result.get("sample_rate"),
        "start_sample": result.get("start_sample"),
        "start_trim": result.get("start_trim"),
        "timing_uncertain": result.get("timing_uncertain"),
    }
    return _bf_load_bits(dashboard, result["bits"], "from_demodulation", metadata)


def open_sa_pd_bf_from_demodulation(dashboard):
    if not load_sa_pd_bf_from_demodulation(dashboard):
        return
    dashboard.ui.tabWidget_protocol.setCurrentWidget(dashboard.ui.tab_sa_pd_bitstream)
    dashboard.ui.tabWidget_signal_analysis.setCurrentWidget(dashboard.ui.tab_protocol_discovery)


def _bf_choose_source(dashboard, source):
    _bf_set_source(dashboard, source)
    if source == "from_demodulation":
        load_sa_pd_bf_from_demodulation(dashboard)
    elif source == "local_file":
        filepath = dashboard.ui.textEdit_sa_pd_bf_input_local_file.toPlainText().strip()
        if filepath and os.path.isfile(filepath):
            _bf_open_local_path(dashboard, filepath)
        else:
            _bf_clear(dashboard, "Choose a bitstream file")
    else:
        _bf_clear(dashboard, "Bitstream Artifacts are not available yet")


def _bf_open_local_path(dashboard, filepath):
    try:
        bits = read_bitstream_file(filepath)
    except (OSError, ValueError, TypeError) as error:
        _bf_clear(dashboard, f"Input error: {error}")
        dashboard.ui.label2_sa_pd_bf_messages_status.setToolTip(str(error))
        return False
    dashboard.ui.textEdit_sa_pd_bf_input_local_file.setPlainText(os.path.abspath(filepath))
    return _bf_load_bits(dashboard, bits, "local_file", {"data_type": "Raw Bits", "path": filepath})


def _bf_browse_local(dashboard):
    path, _selected = QtWidgets.QFileDialog.getOpenFileName(
        dashboard, "Open Bitstream", "",
        "Bitstreams (*.bits *.bit *.txt *.hex *.bin *.dat *.json);;All Files (*)"
    )
    if path:
        _bf_open_local_path(dashboard, path)


def _bf_update_controls(dashboard):
    ui = dashboard.ui
    has_bits = getattr(dashboard, "sa_pd_bf_bits", None) is not None
    has_selection = getattr(dashboard, "sa_pd_bf_selection", None) is not None
    has_decoded = getattr(dashboard, "sa_pd_bf_decoded_bits", None) is not None
    has_frames = bool(getattr(dashboard, "sa_pd_bf_frames", []))
    has_message = bool(ui.tableWidget_sa_pd_bf_messages.selectedItems())
    for name in ("frame_sa_pd_bf_bitstream_small_plot", "frame_sa_pd_bf_bitstream_big_plot"):
        getattr(ui, name).setVisible(has_bits)
    ui.pushButton_sa_pd_bf_bitstream_full.setEnabled(has_bits)
    ui.pushButton_sa_pd_bf_bitstream_zoom.setEnabled(has_bits and has_selection)
    ui.radioButton_sa_pd_bf_bitstream_raw.setEnabled(has_bits)
    ui.radioButton_sa_pd_bf_bitstream_decoded.setEnabled(has_decoded)
    ui.checkBox_sa_pd_bf_bitstream_show_boundaries.setEnabled(has_frames)
    for name in ("encoding", "polarity", "analysis_range", "framing_method",
                 "sync_pattern", "frame_length"):
        getattr(ui, "comboBox_sa_pd_bf_decoding_" + name).setEnabled(has_bits)
    ui.pushButton_sa_pd_bf_decoding_analyze.setEnabled(has_bits)
    ui.pushButton_sa_pd_bf_decoding_reset.setEnabled(has_bits)
    ui.toolButton_sa_pd_bf_decoding_advanced_settings.setEnabled(has_bits)
    ui.comboBox_sa_pd_bf_messages_view.setEnabled(has_frames)
    ui.pushButton_sa_pd_bf_selected_copy.setEnabled(has_message)
    # The two Packet Analysis transfers preserve individual observations.
    # The former unused Compare button now opens the full extracted collection.
    ui.pushButton_sa_pd_bf_selected_open_in_pa.setEnabled(has_message)
    ui.pushButton_sa_pd_bf_selected_open_in_pa.setToolTip(
        "Append selected message row(s) to Packet Analysis"
    )
    ui.pushButton_sa_pd_bf_messages_compare.setEnabled(has_frames)
    ui.pushButton_sa_pd_bf_messages_compare.setToolTip(
        "Append all extracted messages to Packet Analysis, including repeated messages"
    )
    for name in ("pushButton_sa_pd_bf_messages_export",
                 "pushButton_sa_pd_bf_selected_save_as_artifact"):
        getattr(ui, name).setEnabled(False)
    ui.pushButton_sa_pd_bf_input_artifact.setEnabled(False)
    ui.pushButton_sa_pd_bf_input_artifact.setToolTip(
        "No saved bitstream-artifact reader is available yet"
    )
    ui.widget_sa_pd_bf_decoding_settings.setVisible(
        has_bits and ui.toolButton_sa_pd_bf_decoding_advanced_settings.isChecked()
    )


def _bf_mount_plot(frame, toolbar=False, dashboard=None):
    canvas = _PDDemodulationCanvas(frame)
    layout = frame.layout() or QtWidgets.QVBoxLayout(frame)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(0)
    if toolbar:
        canvas.fig.subplots_adjust(left=0.08, right=0.985, bottom=0.19, top=0.93)
        nav = NavigationToolbar2QT(canvas, frame)
        nav.setObjectName("toolbar_sa_pd_bf_bitstream")
        nav.setIconSize(QtCore.QSize(16, 16))
        nav.setFixedHeight(30)
        nav.setMovable(False)
        nav.setFloatable(False)
        icons = {"Home": "home.png", "Back": "back.png", "Forward": "forward.png",
                 "Pan": "move.png", "Zoom": "zoom_to_rect.png", "Save": "filesave.png"}
        for action in nav.actions():
            name = str(action.text() or "")
            if name in {"Subplots", "Customize"}:
                action.setVisible(False)
            elif name in icons:
                path = os.path.join(fissure.utils.UI_DIR, "Icons", icons[name])
                if os.path.isfile(path):
                    action.setIcon(QtGui.QIcon(path))
        layout.addWidget(nav)
        layout.addSpacing(5)
        dashboard.sa_pd_bf_toolbar = nav
    else:
        canvas.fig.subplots_adjust(left=0.045, right=0.985, bottom=0.27, top=0.95)
    layout.addWidget(canvas, 1)
    return canvas


def _bf_current_bits(dashboard):
    decoded = bool(dashboard.ui.radioButton_sa_pd_bf_bitstream_decoded.isChecked())
    result = getattr(dashboard, "sa_pd_bf_decoded_bits", None) if decoded else None
    return result if result is not None else getattr(dashboard, "sa_pd_bf_bits", None)


def _bf_draw(dashboard, preserve_view=False):
    if getattr(dashboard, "sa_pd_bf_overview_canvas", None) is None:
        return
    bits = _bf_current_bits(dashboard)
    overview = dashboard.sa_pd_bf_overview_canvas
    detail = dashboard.sa_pd_bf_detail_canvas
    previous = detail.axes.get_xlim() if preserve_view and detail.axes.has_data() else None
    for canvas in (overview, detail):
        canvas.axes.clear()
        _pd_style_axes(dashboard, canvas)
    if bits is None or not len(bits):
        for canvas in (overview, detail):
            canvas.axes.grid(False)
            canvas.axes.set_xticks([])
            canvas.axes.set_yticks([])
            canvas.draw_idle()
        return
    count = len(bits)
    _bg, _face, _text, _grid, line_color, _q, _if = _pd_theme(dashboard)
    bins = min(_BF_OVERVIEW_BINS, count)
    if count <= bins:
        overview.axes.step(np.arange(count + 1), np.r_[bits, bits[-1]],
                           where="post", color=line_color, linewidth=0.6)
    else:
        edges = np.linspace(0, count, bins + 1).astype(np.int64)
        cumulative = np.r_[0, np.cumsum(bits, dtype=np.int64)]
        density = np.diff(cumulative[edges]) / np.maximum(1, np.diff(edges))
        overview.axes.plot(edges[:-1], density, color=line_color, linewidth=0.75)
    view = dashboard.sa_pd_bf_view or (0, min(count, _BF_INITIAL_VIEW_BITS))
    if previous is not None:
        view = previous
    start = max(0, min(count - 1, int(view[0])))
    stop = max(start + 1, min(count, int(np.ceil(view[1]))))
    dashboard.sa_pd_bf_view = (start, stop)
    overview.axes.axvspan(start, stop, color="#4b91d1", alpha=0.18)
    overview.axes.set_xlim(0, count)
    overview.axes.set_ylim(-0.15, 1.15)
    overview.axes.set_yticks([])
    overview.axes.set_xlabel("")
    selection = getattr(dashboard, "sa_pd_bf_selection", None)
    if selection:
        overview.axes.axvspan(*selection, color="#d78a36", alpha=0.3)
    size = stop - start
    if size <= _BF_MAX_DETAIL_BITS:
        detail.axes.step(np.arange(start, stop + 1), np.r_[bits[start:stop], bits[stop - 1]],
                         where="post", color=line_color, linewidth=0.9)
        detail.axes.set_ylabel("Bit", fontsize=8)
        detail.axes.set_yticks([0, 1])
    else:
        edges = np.linspace(start, stop, min(_BF_OVERVIEW_BINS, size) + 1).astype(np.int64)
        cumulative = np.r_[0, np.cumsum(bits, dtype=np.int64)]
        density = np.diff(cumulative[edges]) / np.maximum(1, np.diff(edges))
        detail.axes.plot(edges[:-1], density, color=line_color, linewidth=0.8)
        detail.axes.set_ylabel("1 density", fontsize=8)
    if selection:
        detail.axes.axvspan(*selection, color="#d78a36", alpha=0.17)
    if (dashboard.ui.radioButton_sa_pd_bf_bitstream_decoded.isChecked()
            and dashboard.ui.checkBox_sa_pd_bf_bitstream_show_boundaries.isChecked()):
        # Do not draw thousands of Matplotlib artists on large recordings.
        frames = getattr(dashboard, "sa_pd_bf_frames", [])
        if len(frames) <= 150:
            for frame in frames:
                overview.axes.axvline(frame["start"], color="#c68020", linewidth=0.7, alpha=0.65)
        displayed = 0
        for frame in frames:
            if frame["end"] < start or frame["start"] > stop:
                continue
            detail.axes.axvline(frame["start"], color="#d98b25", linestyle="--", linewidth=1.0)
            detail.axes.axvline(frame["end"], color="#5eab60", linestyle="--", linewidth=1.0)
            displayed += 1
            if displayed >= 100:
                break
    detail.axes.set_xlim(start, stop)
    detail.axes.set_ylim(-0.15, 1.15)
    # Bit index tick labels already convey the coordinate. Avoid the
    # clipped axis title in the compact FISSURE plot frame.
    detail.axes.set_xlabel("")
    overview.draw_idle()
    detail.draw_idle()


def restyle_sa_pd_bf_canvases(dashboard):
    """Repaint existing data after switching between Light, Dark and Custom."""
    if getattr(dashboard, "sa_pd_bf_initialized", False):
        _bf_draw(dashboard, preserve_view=True)


def _bf_mouse_down(dashboard, event):
    if event.inaxes is None or event.xdata is None or event.button != 1:
        return
    toolbar = getattr(dashboard, "sa_pd_bf_toolbar", None)
    if toolbar is not None and toolbar.mode:
        return
    dashboard.sa_pd_bf_drag_start = (event.canvas, float(event.xdata))


def _bf_mouse_up(dashboard, event):
    origin = getattr(dashboard, "sa_pd_bf_drag_start", None)
    dashboard.sa_pd_bf_drag_start = None
    bits = _bf_current_bits(dashboard)
    if not origin or bits is None or event.xdata is None or origin[0] is not event.canvas:
        return
    count = len(bits)
    a, b = sorted((origin[1], float(event.xdata)))
    if b - a < 1.0:
        if event.canvas is dashboard.sa_pd_bf_overview_canvas:
            width = min(count, max(1, int(dashboard.sa_pd_bf_view[1] - dashboard.sa_pd_bf_view[0])))
            left = max(0, min(count - width, int(event.xdata) - width // 2))
            dashboard.sa_pd_bf_view = (left, left + width)
            _bf_draw(dashboard)
        return
    start = max(0, min(count - 1, int(np.floor(a))))
    stop = max(start + 1, min(count, int(np.ceil(b))))
    dashboard.sa_pd_bf_selection = (start, stop)
    dashboard.ui.label2_sa_pd_bf_bitstream_selection.setText(
        f"Bits {start:,}–{stop - 1:,} ({stop - start:,})"
    )
    _bf_update_controls(dashboard)
    _bf_draw(dashboard)


def _bf_full(dashboard):
    bits = _bf_current_bits(dashboard)
    if bits is not None:
        dashboard.sa_pd_bf_view = (0, len(bits))
        _bf_draw(dashboard)


def _bf_zoom(dashboard):
    selection = getattr(dashboard, "sa_pd_bf_selection", None)
    if selection:
        dashboard.sa_pd_bf_view = selection
        _bf_draw(dashboard)


def initialize_sa_pd_bf_controls(dashboard):
    """Initialize Bitstream & Framing after Demodulation canvases are mounted."""
    ui = dashboard.ui
    dashboard.sa_pd_bf_initialized = False
    dashboard.sa_pd_bf_source = "from_demodulation"
    dashboard.sa_pd_bf_bits = None
    dashboard.sa_pd_bf_prefix = None
    dashboard.sa_pd_bf_decoded_bits = None
    dashboard.sa_pd_bf_selection = None
    dashboard.sa_pd_bf_view = None
    dashboard.sa_pd_bf_drag_start = None
    dashboard.sa_pd_bf_metadata = {}
    dashboard.sa_pd_bf_frames = []
    dashboard.sa_pd_bf_analysis = None
    ui.textEdit_sa_pd_bf_input_local_file.setReadOnly(True)
    ui.tableWidget_sa_pd_bf_messages.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    ui.tableWidget_sa_pd_bf_messages.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
    ui.tableWidget_sa_pd_bf_messages.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    ui.tabWidget_sa_pd_bf_selected.setCurrentIndex(0)
    header = ui.tableWidget_sa_pd_bf_messages.horizontalHeaderItem(5)
    if header is not None:
        header.setText("Boundary Evidence")
        header.setToolTip("Observed preamble, sync, timing-gap, or CRC-16 evidence; not packet validation")
    ui.tableWidget_sa_pd_bf_messages.setColumnWidth(5, 135)
    ui.checkBox_sa_pd_bf_bitstream_show_boundaries.setChecked(True)
    ui.radioButton_sa_pd_bf_bitstream_raw.setChecked(True)
    ui.pushButton_sa_pd_bf_input_from_demodulation.setText("Demodulation")
    ui.pushButton_sa_pd_bf_input_from_demodulation.setToolTip("Use recovered bits from Demodulation")
    ui.toolButton_sa_pd_bf_decoding_advanced_settings.setChecked(False)
    ui.toolButton_sa_pd_bf_decoding_advanced_settings.setArrowType(QtCore.Qt.RightArrow)
    for name, items in (
        ("encoding", ("Auto", "Raw / NRZ", "NRZI", "Manchester", "Differential Manchester")),
        ("polarity", ("Auto", "Normal", "Inverted")),
        ("analysis_range", ("Entire Bitstream", "Selected Region")),
        ("framing_method", ("Auto", "OOK Bursts", "Sync Pattern", "Timing Gaps", "Fixed Length")),
        ("sync_pattern", ("Auto",)),
        ("frame_length", ("Auto",)),
    ):
        combo = getattr(ui, "comboBox_sa_pd_bf_decoding_" + name)
        was_blocked = combo.blockSignals(True)
        combo.clear()
        combo.addItems(items)
        combo.setCurrentIndex(0)
        combo.blockSignals(was_blocked)
    _bf_initialize_advanced(dashboard)
    for name, icon in (
        ("artifact_left", "back.png"), ("artifact_right", "forward.png"),
        ("artifact_file_left", "back.png"), ("artifact_file_right", "forward.png"),
        ("local_file_select", "folder_black.svg"),
    ):
        widget = getattr(ui, "pushButton_sa_pd_bf_input_" + name)
        path = os.path.join(fissure.utils.UI_DIR, "Icons", icon)
        if os.path.isfile(path):
            widget.setIcon(QtGui.QIcon(path))
            widget.setText("")
    dashboard.sa_pd_bf_overview_canvas = _bf_mount_plot(ui.frame_sa_pd_bf_bitstream_small_plot)
    dashboard.sa_pd_bf_detail_canvas = _bf_mount_plot(
        ui.frame_sa_pd_bf_bitstream_big_plot, toolbar=True, dashboard=dashboard
    )
    for canvas in (dashboard.sa_pd_bf_overview_canvas, dashboard.sa_pd_bf_detail_canvas):
        canvas.mpl_connect("button_press_event", lambda event: _bf_mouse_down(dashboard, event))
        canvas.mpl_connect("button_release_event", lambda event: _bf_mouse_up(dashboard, event))
    _bf_set_source(dashboard, "from_demodulation")
    dashboard.sa_pd_bf_initialized = True
    _bf_clear(dashboard)
    # A result might have been completed before this tab was initialized.
    if getattr(dashboard, "sa_pd_demodulation_result", None) is not None:
        load_sa_pd_bf_from_demodulation(dashboard)

    # Packet Analysis is initialized after its preceding stage, without
    # adding more connections or replacing unrelated Frontend functions.
    from .pd_packet_analysis import initialize_sa_pd_pa_controls, open_sa_pd_pa_from_bf

    initialize_sa_pd_pa_controls(dashboard)
    ui.pushButton_sa_pd_bf_selected_open_in_pa.clicked.connect(
        lambda: open_sa_pd_pa_from_bf(dashboard, all_frames=False)
    )
    ui.pushButton_sa_pd_bf_selected_open_in_pa.setText("Open Selected")
    ui.pushButton_sa_pd_bf_messages_compare.setText("Open All")
    ui.pushButton_sa_pd_bf_messages_compare.clicked.connect(
        lambda: open_sa_pd_pa_from_bf(dashboard, all_frames=True)
    )
    _bf_update_controls(dashboard)


def _bf_initialize_advanced(dashboard):
    """Keep method-dependent settings in the existing Designer form layout."""
    ui = dashboard.ui
    layout = ui.formLayout_sa_pd_bf_decoding_settings
    layout.setContentsMargins(2, 0, 2, 0)
    layout.setVerticalSpacing(1)
    layout.setHorizontalSpacing(4)
    controls = {}
    for key, label, minimum, maximum, default in (
        ("min_frame", "Min Frame (bits):", 4, 1_000_000, 16),
        ("max_frame", "Max Frame (bits):", 4, 1_000_000, 4096),
        ("preamble", "Min Preamble (bits):", 8, 1024, 24),
    ):
        caption = QtWidgets.QLabel(label, ui.widget_sa_pd_bf_decoding_settings)
        caption.setObjectName("label2_sa_pd_bf_dynamic_" + key)
        spin = QtWidgets.QSpinBox(ui.widget_sa_pd_bf_decoding_settings)
        spin.setObjectName("spinBox_sa_pd_bf_dynamic_" + key)
        spin.setRange(minimum, maximum)
        spin.setValue(default)
        layout.addRow(caption, spin)
        controls[key] = (caption, spin)
    dashboard.sa_pd_bf_advanced_controls = controls
    _bf_advanced_method_changed(dashboard)


def _bf_advanced_method_changed(dashboard):
    controls = dashboard.sa_pd_bf_advanced_controls
    is_auto = dashboard.ui.comboBox_sa_pd_bf_decoding_framing_method.currentText() == "Auto"
    label, spin = controls["preamble"]
    label.setVisible(is_auto)
    spin.setVisible(is_auto)


def _bf_toggle_advanced(dashboard, checked):
    dashboard.ui.toolButton_sa_pd_bf_decoding_advanced_settings.setArrowType(
        QtCore.Qt.DownArrow if checked else QtCore.Qt.RightArrow
    )
    dashboard.ui.widget_sa_pd_bf_decoding_settings.setVisible(
        checked and dashboard.sa_pd_bf_bits is not None
    )


def _bf_view_changed(dashboard):
    bits = _bf_current_bits(dashboard)
    dashboard.sa_pd_bf_selection = None
    dashboard.ui.label2_sa_pd_bf_bitstream_selection.setText("—")
    dashboard.sa_pd_bf_view = (0, min(len(bits), _BF_INITIAL_VIEW_BITS)) if bits is not None else None
    _bf_update_controls(dashboard)
    _bf_draw(dashboard)


def _bf_run_analysis(dashboard):
    ui = dashboard.ui
    raw = getattr(dashboard, "sa_pd_bf_bits", None)
    if raw is None:
        return
    # Snapshot the ACTUAL visible range before analysis replaces the decoded
    # bitstream. The Matplotlib toolbar can pan/zoom without updating
    # dashboard.sa_pd_bf_view, so read the axes first.
    old_bits = _bf_current_bits(dashboard)
    detail = getattr(dashboard, "sa_pd_bf_detail_canvas", None)
    if detail is not None and detail.axes.has_data():
        visible = detail.axes.get_xlim()
    else:
        visible = getattr(dashboard, "sa_pd_bf_view", None)
    if visible is None:
        visible = (0, len(old_bits))
    old_left, old_right = sorted((float(visible[0]), float(visible[1])))
    old_full = old_left <= 0.5 and old_right >= len(old_bits) - 0.5

    # Express the visible interval in ORIGINAL raw-bit coordinates, because
    # Manchester or differential Manchester can change decoded indices.
    old_analysis = getattr(dashboard, "sa_pd_bf_analysis", None)
    old_decoded = (ui.radioButton_sa_pd_bf_bitstream_decoded.isChecked()
                   and getattr(dashboard, "sa_pd_bf_decoded_bits", None) is not None
                   and isinstance(old_analysis, dict))
    if old_decoded:
        old_stride = max(1, int(old_analysis.get("stride", 1)))
        old_offset = int(old_analysis.get("offset", 0))
        raw_left = old_left * old_stride + old_offset
        raw_right = old_right * old_stride + old_offset
    else:
        raw_left, raw_right = old_left, old_right

    combo = lambda name: getattr(ui, "comboBox_sa_pd_bf_decoding_" + name).currentText().strip()
    scope = getattr(dashboard, "sa_pd_bf_selection", None)
    if combo("analysis_range") == "Selected Region":
        if scope is None:
            ui.label2_sa_pd_bf_messages_status.setText("Select a bit range first")
            return
        # Selection coordinates refer to whichever representation was visible.
        if ui.radioButton_sa_pd_bf_bitstream_decoded.isChecked() and dashboard.sa_pd_bf_analysis:
            old = dashboard.sa_pd_bf_analysis
            scope = (scope[0] * old["stride"] + old["offset"],
                     scope[1] * old["stride"] + old["offset"])
    else:
        scope = (0, len(raw))
    settings = dashboard.sa_pd_bf_advanced_controls
    length_text = combo("frame_length")
    try:
        frame_length = None if not length_text or length_text.lower() == "auto" else int(length_text)
        result = analyze_bitstream(
            raw, encoding=combo("encoding"), polarity=combo("polarity"),
            method=combo("framing_method"),
            sync_pattern=combo("sync_pattern"), frame_length=frame_length,
            start=scope[0], end=scope[1],
            min_frame_bits=settings["min_frame"][1].value(),
            max_frame_bits=settings["max_frame"][1].value(),
            min_preamble_bits=settings["preamble"][1].value(),
            sample_centers=dashboard.sa_pd_bf_metadata.get("sample_centers"),
            modulation=dashboard.sa_pd_bf_metadata.get("modulation"),
            # Only IQ Demodulation supplies defensible RF burst provenance.
            # Local bitstream files must not turn into apparent packet rows.
            rf_capture_segment=(
                getattr(dashboard, "sa_pd_bf_source", "") == "from_demodulation"
                and str(dashboard.sa_pd_bf_metadata.get("modulation") or "").lower() == "fsk"
                and dashboard.sa_pd_bf_metadata.get("sample_centers") is not None
                and (dashboard.sa_pd_bf_metadata.get("start_trim") or 0) > 0
            ),
        )
    except (ValueError, TypeError, OverflowError) as error:
        ui.label2_sa_pd_bf_messages_status.setText("Analysis error: " + str(error))
        ui.label2_sa_pd_bf_messages_status.setToolTip(str(error))
        return
    dashboard.sa_pd_bf_analysis = result
    dashboard.sa_pd_bf_decoded_bits = result["bits"]
    dashboard.sa_pd_bf_frames = result["frames"]
    dashboard.sa_pd_bf_selection = None

    # Analyze is not a navigation command. Preserve Full or the visible raw
    # interval, translating coordinates to the newly decoded bitstream.
    count = len(result["bits"])
    if count:
        if old_full:
            dashboard.sa_pd_bf_view = (0, count)
        else:
            stride = max(1, int(result.get("stride", 1)))
            offset = int(result.get("offset", 0))
            left = (raw_left - offset) / stride
            right = (raw_right - offset) / stride
            start = max(0, min(count - 1, int(np.floor(left))))
            stop = max(start + 1, min(count, int(np.ceil(right))))
            dashboard.sa_pd_bf_view = (start, stop)
    else:
        dashboard.sa_pd_bf_view = None

    ui.label2_sa_pd_bf_bitstream_selection.setText("—")
    # Both members of the exclusive group can emit toggled signals when
    # changing Raw -> Decoded. Block BOTH so _bf_view_changed() cannot reset
    # the viewport to its default 256-bit range.
    raw_button = ui.radioButton_sa_pd_bf_bitstream_raw
    decoded_button = ui.radioButton_sa_pd_bf_bitstream_decoded
    raw_blocked = raw_button.blockSignals(True)
    decoded_blocked = decoded_button.blockSignals(True)
    try:
        decoded_button.setChecked(True)
    finally:
        raw_button.blockSignals(raw_blocked)
        decoded_button.blockSignals(decoded_blocked)
    ui.label2_sa_pd_bf_messages_status.setText(result["status"])
    ui.label2_sa_pd_bf_messages_status.setToolTip(
        f"Decoding: {result['encoding']} / {result['polarity']}. "
        "Standard CRC-16 matches are boundary hypotheses, not verified protocol checksums. "
        + ("Polarity is unresolved. " if result.get("polarity_ambiguous") else "")
        + ("RF capture segment only, not a detected protocol frame. "
           if result.get("unframed") else "")
        + "All frames remain unverified."
    )
    ui.comboBox_sa_pd_bf_decoding_encoding.setToolTip("Selected: " + result["encoding"])
    ui.comboBox_sa_pd_bf_decoding_polarity.setToolTip("Selected: " + result["polarity"])
    _bf_refresh_messages(dashboard)
    _bf_update_controls(dashboard)
    _bf_draw(dashboard)


def _bf_raw_source_span(dashboard, frame):
    """Map a candidate's decoded [start, end) back to original raw chips.

    Prefer per-frame boundaries for region-scoped/mixed decoding; otherwise
    use the analysis-wide stride and offset. Indices are zero-based, and the
    returned end is exclusive. This does NOT establish a protocol delimiter.
    """
    original = getattr(dashboard, "sa_pd_bf_bits", None)
    if original is None:
        return None
    try:
        if frame.get("raw_start") is not None and frame.get("raw_end") is not None:
            begin = int(frame["raw_start"])
            end = int(frame["raw_end"])
        else:
            analysis = getattr(dashboard, "sa_pd_bf_analysis", None) or {}
            stride = max(1, int(analysis.get("stride", 1)))
            offset = int(analysis.get("offset", 0))
            begin = int(frame["start"]) * stride + offset
            end = int(frame["end"]) * stride + offset
    except (TypeError, ValueError, KeyError, OverflowError):
        return None
    if not 0 <= begin < end <= len(original):
        return None
    return begin, end


def _bf_refresh_messages(dashboard):
    ui = dashboard.ui
    table = ui.tableWidget_sa_pd_bf_messages
    frames = getattr(dashboard, "sa_pd_bf_frames", [])
    view = ui.comboBox_sa_pd_bf_messages_view.currentText()
    shown = []
    unique = set()
    for index, frame in enumerate(frames):
        key = (frame["length"], frame["bits"].tobytes())
        if view == "Repeated Messages" and frame["occurrences"] < 2:
            continue
        if view == "Unique Messages":
            if key in unique:
                continue
            unique.add(key)
        shown.append((index, frame))
    blocker = QtCore.QSignalBlocker(table)
    table.setRowCount(len(shown))
    for row, (index, frame) in enumerate(shown):
        values = (str(index + 1), f"{frame['start']:,}", f"{frame['end'] - 1:,}",
                  f"{frame['length']:,}", str(frame["occurrences"]),
                  frame.get("boundary_evidence", frame["origin"].split(" (")[0]),
                  preview_hex(frame["bits"], max_bytes=10))
        raw_span = _bf_raw_source_span(dashboard, frame)
        location_tip = (
            f"Decoded bit positions [{frame['start']}, {frame['end']}) "
            "(end exclusive). "
        )
        if raw_span is not None:
            location_tip += (
                f"Source raw-chip positions [{raw_span[0]}, {raw_span[1]}) "
                f"(inclusive {raw_span[0]}–{raw_span[1] - 1}). "
            )
            if frame.get("crc8_evidence") and raw_span[0] >= 2:
                location_tip += (
                    f"Prior raw chips [{raw_span[0] - 2}, {raw_span[0]}) "
                    "provide the Manchester/differential reference pair; "
                    "the preceding access code remains uncoded in Raw view. "
                )
        else:
            location_tip += "Original raw-chip range unavailable. "
        location_tip += "Candidate boundaries remain unverified."
        for column, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(value)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
            item.setData(QtCore.Qt.UserRole, index)
            if column <= 5:
                item.setTextAlignment(QtCore.Qt.AlignCenter)
            if column in (1, 2):
                item.setToolTip(location_tip)
            if column == 5:
                crc = frame.get("crc_evidence")
                if crc:
                    item.setToolTip(
                        f"{frame['origin']}; {crc['algorithm']} matches {crc['checksum']} "
                        f"at byte {crc['total_bytes']} after skipping {crc['skip_bytes']} "
                        "initial byte(s). Hypothesis only; packet validity unverified. "
                        + location_tip
                    )
                elif frame.get("crc8_evidence"):
                    check = frame["crc8_evidence"]
                    raw_begin = frame.get("raw_start")
                    raw_end = frame.get("raw_end")
                    complement_count = len(frame.get("complement_positions", []))
                    item.setToolTip(
                        f"{frame['origin']}. {check['algorithm']} matches "
                        f"0x{check['value']} at a candidate end. "
                        f"Decoded payload maps to original raw chips "
                        f"[{raw_begin}, {raw_end}); the uncoded prefix is "
                        "retained in Raw view. "
                        f"Inverted-octet observations: {complement_count}. "
                        "Encoding and checksum evidence are hypotheses, "
                        "not proof of packet identity or validity. "
                        + location_tip
                    )
                else:
                    item.setToolTip(
                        ("RF activity interval from Demodulation; this is unframed "
                         "bitstream data, NOT a detected protocol packet."
                         if frame.get("unframed") else
                         f"{frame['origin']}; candidate end is not independently verified.")
                        + " " + location_tip
                    )
            table.setItem(row, column, item)
    table.clearSelection()
    del blocker
    label = "segments" if frames and all(f.get("unframed") for f in frames) else "messages"
    ui.label2_sa_pd_bf_messages_count.setText(
        f"{len(shown):,} / {len(frames):,} {label}"
    )
    for name in ("hex", "binary", "ascii"):
        getattr(ui, "plainTextEdit_sa_pd_bf_selected_" + name).clear()
    ui.label2_sa_pd_bf_bitstream_selection.setToolTip("")
    _bf_update_controls(dashboard)


def _bf_message_selection_changed(dashboard):
    ui = dashboard.ui
    table = ui.tableWidget_sa_pd_bf_messages
    row = table.currentRow()
    cell = table.item(row, 0) if row >= 0 else None
    index = cell.data(QtCore.Qt.UserRole) if cell is not None else None
    frames = getattr(dashboard, "sa_pd_bf_frames", [])
    if index is None or not 0 <= int(index) < len(frames):
        for name in ("hex", "binary", "ascii"):
            getattr(ui, "plainTextEdit_sa_pd_bf_selected_" + name).clear()
        ui.label2_sa_pd_bf_bitstream_selection.setToolTip("")
        _bf_update_controls(dashboard)
        return
    frame = frames[int(index)]
    for name in ("hex", "binary", "ascii"):
        editor = getattr(ui, "plainTextEdit_sa_pd_bf_selected_" + name)
        editor.setPlainText(format_message(frame["bits"], name))
        editor.moveCursor(QtGui.QTextCursor.Start)
    if not ui.radioButton_sa_pd_bf_bitstream_decoded.isChecked():
        blocked = ui.radioButton_sa_pd_bf_bitstream_decoded.blockSignals(True)
        ui.radioButton_sa_pd_bf_bitstream_decoded.setChecked(True)
        ui.radioButton_sa_pd_bf_bitstream_decoded.blockSignals(blocked)
    dashboard.sa_pd_bf_selection = (frame["start"], frame["end"])
    raw_span = _bf_raw_source_span(dashboard, frame)
    selected_label = ui.label2_sa_pd_bf_bitstream_selection
    selected_text = f"Bits {frame['start']:,}–{frame['end'] - 1:,} ({frame['length']:,})"
    source_tip = f"Decoded bits [{frame['start']}, {frame['end']}) (end exclusive)."
    if raw_span is not None:
        source_tip += f" Original raw chips [{raw_span[0]}, {raw_span[1]}) (end exclusive)."
        if (raw_span[0], raw_span[1]) != (frame["start"], frame["end"]):
            selected_text = (
                f"Bits {frame['start']:,}–{frame['end'] - 1:,}; "
                f"raw {raw_span[0]:,}–{raw_span[1] - 1:,}"
            )
        if frame.get("crc8_evidence") and raw_span[0] >= 2:
            source_tip += (
                f" Raw chips [{raw_span[0] - 2}, {raw_span[0]}) "
                "are the Manchester/differential reference pair. "
                "The uncoded access code is available in Raw view."
            )
    source_tip += " Candidate bounds are not protocol-verified."
    selected_label.setText(selected_text)
    selected_label.setToolTip(source_tip)
    margin = max(12, frame["length"] // 8)
    dashboard.sa_pd_bf_view = (max(0, frame["start"] - margin),
                              min(len(dashboard.sa_pd_bf_decoded_bits), frame["end"] + margin))
    _bf_update_controls(dashboard)
    _bf_draw(dashboard)


def _bf_copy_message(dashboard):
    ui = dashboard.ui
    index = ui.tabWidget_sa_pd_bf_selected.currentIndex()
    name = ("hex", "binary", "ascii")[min(2, max(0, index))]
    value = getattr(ui, "plainTextEdit_sa_pd_bf_selected_" + name).toPlainText()
    if value:
        QtWidgets.QApplication.clipboard().setText(value)


def _bf_reset_auto(dashboard):
    ui = dashboard.ui
    raw_bits = getattr(dashboard, "sa_pd_bf_bits", None)
    if raw_bits is None or not len(raw_bits):
        return

    # Keep the region actually visible in the detailed plot, including any
    # zoom/pan performed with the Matplotlib navigation toolbar.
    detail = getattr(dashboard, "sa_pd_bf_detail_canvas", None)
    if detail is not None and detail.axes.has_data():
        visible = detail.axes.get_xlim()
    else:
        visible = getattr(dashboard, "sa_pd_bf_view", None)
    if visible is None:
        visible = (0, len(raw_bits))
    start, stop = sorted((float(visible[0]), float(visible[1])))

    # Decoded and raw bit indices differ for encodings such as Manchester.
    # Convert the viewed range back to raw coordinates BEFORE clearing the
    # analysis. A full decoded view should become a full raw view.
    decoded = getattr(dashboard, "sa_pd_bf_decoded_bits", None)
    analysis = getattr(dashboard, "sa_pd_bf_analysis", None)
    if (ui.radioButton_sa_pd_bf_bitstream_decoded.isChecked()
            and decoded is not None and isinstance(analysis, dict)):
        if start <= 0.5 and stop >= len(decoded) - 0.5:
            start, stop = 0, len(raw_bits)
        else:
            stride = max(1, int(analysis.get("stride", 1)))
            offset = int(analysis.get("offset", 0))
            start = start * stride + offset
            stop = stop * stride + offset

    start = max(0, min(len(raw_bits) - 1, int(np.floor(start))))
    stop = max(start + 1, min(len(raw_bits), int(np.ceil(stop))))

    for name in ("encoding", "polarity", "framing_method", "sync_pattern", "frame_length"):
        combo = getattr(ui, "comboBox_sa_pd_bf_decoding_" + name)
        combo.setCurrentIndex(0)
    ui.comboBox_sa_pd_bf_decoding_analysis_range.setCurrentIndex(0)
    for key, value in (("min_frame", 16), ("max_frame", 4096), ("preamble", 24)):
        dashboard.sa_pd_bf_advanced_controls[key][1].setValue(value)

    dashboard.sa_pd_bf_decoded_bits = None
    dashboard.sa_pd_bf_frames = []
    dashboard.sa_pd_bf_analysis = None
    dashboard.sa_pd_bf_selection = None
    dashboard.sa_pd_bf_view = (start, stop)

    # The radio button is connected to _bf_view_changed(), which normally
    # resets the viewport to the first 256 bits. Suppress that callback here.
    raw_button = ui.radioButton_sa_pd_bf_bitstream_raw
    decoded_button = ui.radioButton_sa_pd_bf_bitstream_decoded
    raw_blocked = raw_button.blockSignals(True)
    decoded_blocked = decoded_button.blockSignals(True)
    try:
        raw_button.setChecked(True)
    finally:
        raw_button.blockSignals(raw_blocked)
        decoded_button.blockSignals(decoded_blocked)

    ui.label2_sa_pd_bf_bitstream_selection.setText("—")
    ui.label2_sa_pd_bf_messages_status.setText("Settings reset. Ready to analyze")
    _bf_refresh_messages(dashboard)
    _bf_update_controls(dashboard)
    _bf_draw(dashboard)


__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value) and value.__module__ == __name__
]
