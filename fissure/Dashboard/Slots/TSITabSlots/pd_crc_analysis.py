"""Signal Analysis / Protocol Discovery / CRC Analysis (PyQt5).

The widget geometry and styled captions are owned by dashboard.ui. This module
populates controls, packet tables and graphics, and handles actions. All signal
connections belong in Frontend.connect_pd_slots(), not in the initializer.
"""

import csv
import inspect
import json
import os

from PyQt5 import QtCore, QtGui, QtWidgets

from fissure.utils import protocol_crc as crc


_FIELDS = ('Trailing field', 'Leading field', 'Separate value')
_COVERAGE = ('Before CRC', 'Entire packet except CRC', 'Skip first 1 bytes',
             'Skip first 2 bytes', 'Skip first 3 bytes', 'Skip first 4 bytes')
_ORDERS = ('Big endian', 'Little endian')
_MAX_PREVIEW = 32


def _show_error(dashboard, error):
    QtWidgets.QMessageBox.warning(dashboard, 'CRC Analysis', str(error))


def _select_combo(combo, value):
    index = combo.findText(str(value))
    if index >= 0:
        combo.setCurrentIndex(index)


def _fill_combo(combo, values):
    blocker = QtCore.QSignalBlocker(combo)
    combo.clear()
    combo.addItems(list(values))
    del blocker


def _status_color(status, palette):
    if status == 'Match':
        return QtGui.QColor('#248b54')
    if status in ('Fail', 'Error', 'Holdout mismatch'):
        return QtGui.QColor('#c34b4b')
    return palette.color(QtGui.QPalette.Text)


def _packet_dialog(dashboard, sample=None):
    """Edit exact bits and per-packet overrides, validating before closing."""
    existing = dict(sample or {})
    dialog = QtWidgets.QDialog(dashboard)
    dialog.setWindowTitle('Edit CRC Packet' if sample else 'Add CRC Packet')
    dialog.resize(620, 490)
    layout = QtWidgets.QVBoxLayout(dialog)
    form = QtWidgets.QFormLayout()
    source = QtWidgets.QLineEdit(existing.get('source', 'Manual'))
    form.addRow('Source:', source)
    data_mode = QtWidgets.QComboBox()
    data_mode.addItems(('Hex', 'Bits'))
    form.addRow('Input format:', data_mode)
    data = QtWidgets.QPlainTextEdit()
    data.setPlaceholderText('Hex: 31 32 33 ... or Bits: 00110001 00110010 ...')
    data.setMinimumHeight(85)
    current_bits = existing.get('bits', '')
    data.setPlainText(crc.hex_preview(current_bits, max_bytes=crc.MAX_PACKET_BITS // 8)
                      if current_bits else '')
    layout.addLayout(form)
    layout.addWidget(data, 1)

    def change_format(index):
        old_mode = 'Bits' if index == 0 else 'Hex'
        try:
            bits = crc.bits_from_input(data.toPlainText(), old_mode)
        except ValueError:
            # Don't destroy the user's in-progress text if it is invalid.
            return
        if index == 1:
            text = ' '.join(bits[i:i+8] for i in range(0, len(bits), 8))
        else:
            text = crc.hex_preview(bits, max_bytes=crc.MAX_PACKET_BITS // 8)
        data.setPlainText(text)

    data_mode.currentIndexChanged.connect(change_format)
    opts = QtWidgets.QFormLayout()
    role = QtWidgets.QComboBox()
    role.addItem('Fit', 'Fit')
    role.addItem('Verify', 'Holdout')
    role.addItem('Ignore', 'Ignore')
    role.setCurrentIndex(max(0, role.findData(existing.get('role', 'Fit'))))
    opts.addRow('Discovery role:', role)
    field = QtWidgets.QComboBox()
    field.addItems(('Use collection setting',) + _FIELDS + ('Custom offset',))
    _select_combo(field, existing.get('crc_source') or 'Use collection setting')
    opts.addRow('CRC source:', field)
    offset = QtWidgets.QSpinBox()
    offset.setRange(0, crc.MAX_PACKET_BITS)
    offset.setValue(int(existing.get('crc_start') or 0))
    opts.addRow('Custom CRC start bit:', offset)
    expected = QtWidgets.QLineEdit()
    expected.setPlaceholderText('For a separate CRC: 4B37')
    if existing.get('expected') is not None:
        expected.setText(f'{existing["expected"]:X}')
    opts.addRow('Separate expected CRC:', expected)
    coverage = QtWidgets.QComboBox()
    coverage.addItems(('Use collection setting',) + _COVERAGE + ('Custom range',))
    if existing.get('coverage') and coverage.findText(existing['coverage']) == -1:
        coverage.addItem(existing['coverage'])
    _select_combo(coverage, existing.get('coverage') or 'Use collection setting')
    opts.addRow('Coverage:', coverage)
    rng = QtWidgets.QHBoxLayout()
    from_bit, to_bit = QtWidgets.QSpinBox(), QtWidgets.QSpinBox()
    for widget in (from_bit, to_bit):
        widget.setRange(0, crc.MAX_PACKET_BITS)
    from_bit.setValue(int(existing.get('coverage_start') or 0))
    to_bit.setValue(int(existing.get('coverage_end') or len(current_bits)))
    rng.addWidget(QtWidgets.QLabel('Start:'))
    rng.addWidget(from_bit)
    rng.addWidget(QtWidgets.QLabel('End (exclusive):'))
    rng.addWidget(to_bit)
    opts.addRow('Custom covered bits:', rng)
    order = QtWidgets.QComboBox()
    order.addItems(('Use collection setting',) + _ORDERS)
    _select_combo(order, existing.get('order') or 'Use collection setting')
    opts.addRow('CRC wire byte order:', order)
    layout.addLayout(opts)
    buttons = QtWidgets.QDialogButtonBox(QtWidgets.QDialogButtonBox.Ok |
                                         QtWidgets.QDialogButtonBox.Cancel)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    result = {}

    def accept_valid():
        try:
            bits = crc.bits_from_input(data.toPlainText(), data_mode.currentText())
            expected_text = expected.text().strip().lower().replace('0x', '').replace(' ', '')
            if expected_text and not all(char in '0123456789abcdef' for char in expected_text):
                raise ValueError('Expected CRC must be hexadecimal')
            expected_value = int(expected_text, 16) if expected_text else None
            source_value = None if field.currentIndex() == 0 else field.currentText()
            # Entering a separate expected CRC must not be silently ignored.
            if source_value is None and expected_value is not None:
                source_value = 'Separate value'
            if source_value == 'Separate value' and expected_value is None:
                raise ValueError('Enter an expected CRC for the Separate value source')
            if source_value not in (None, 'Separate value') and expected_value is not None:
                raise ValueError('For a CRC embedded in the packet, clear Separate expected CRC')
            if source_value == 'Custom offset' and offset.value() + dashboard.sa_pd_crc_model.width > len(bits):
                raise ValueError('CRC field offset and width exceed the packet length')
            if coverage.currentText() == 'Custom range' and not from_bit.value() < to_bit.value() <= len(bits):
                raise ValueError('Covered range must be inside the packet, start < end')
            updated = dict(existing)
            updated.update(bits=bits, source=source.text().strip() or 'Manual',
                           role=role.currentData(), crc_source=source_value,
                           crc_start=offset.value(), expected=expected_value,
                           coverage=(None if coverage.currentIndex() == 0 else coverage.currentText()),
                           coverage_start=from_bit.value(), coverage_end=to_bit.value(),
                           order=(None if order.currentIndex() == 0 else order.currentText()),
                           calculation=None)
            # Reject invalid combinations now rather than failing mysteriously
            # after the user has already closed the editor.
            crc.region(updated, dashboard.sa_pd_crc_model.width,
                       dashboard.ui.comboBox_sa_pd_crc_model_default_crc_field.currentText(),
                       dashboard.ui.comboBox_sa_pd_crc_model_coverage.currentText(),
                       dashboard.ui.comboBox_sa_pd_crc_model_wire_byte_order.currentText())
            result.update(updated)
            dialog.accept()
        except (ValueError, TypeError) as error:
            QtWidgets.QMessageBox.warning(dialog, 'CRC Packet', str(error))

    buttons.accepted.connect(accept_valid)
    return result if dialog.exec_() == QtWidgets.QDialog.Accepted else None


def _active_table(dashboard):
    ui = dashboard.ui
    return (ui.tableWidget_sa_pd_crc_packet if ui.stackedWidget_sa_pd_crc.currentIndex() == 0
            else ui.tableWidget_sa_pd_crc_discover_packet)


def _selected_uids(table):
    selected = []
    for index in table.selectionModel().selectedRows():
        item = table.item(index.row(), 0)
        if item is not None:
            selected.append(item.data(QtCore.Qt.UserRole))
    return selected


def _selected_record(dashboard):
    table = _active_table(dashboard)
    uids = _selected_uids(table)
    if not uids and table.currentRow() >= 0:
        item = table.item(table.currentRow(), 0)
        uids = [item.data(QtCore.Qt.UserRole)] if item else []
    return next((r for r in dashboard.sa_pd_crc_packets if r['uid'] in uids), None)


def _add_packets(dashboard, incoming, append=True):
    if len(incoming) + (len(dashboard.sa_pd_crc_packets) if append else 0) > crc.MAX_SAMPLES:
        _show_error(dashboard, f'CRC Analysis supports up to {crc.MAX_SAMPLES} packets per collection')
        return 0
    if not append:
        dashboard.sa_pd_crc_packets = []
    new_uids = []
    for packet in incoming:
        bits = packet['bits']
        if not isinstance(bits, str):
            bits = ''.join(str(int(x)) for x in bits)
        if not bits or set(bits) - {'0', '1'} or len(bits) > crc.MAX_PACKET_BITS:
            continue
        row = dict(packet)
        row.update(bits=bits, uid=dashboard.sa_pd_crc_next_uid, calculation=None)
        row.setdefault('role', 'Fit')
        row.setdefault('source', 'Imported')
        dashboard.sa_pd_crc_next_uid += 1
        dashboard.sa_pd_crc_packets.append(row)
        new_uids.append(row['uid'])
    dashboard.sa_pd_crc_candidates = []
    _refresh(dashboard, selected=set(new_uids))
    return len(new_uids)


def _refresh(dashboard, selected=None):
    """Redraw two table views backed by one packet collection."""
    ui = dashboard.ui
    selected = set(selected or ())
    if not selected:
        selected.update(_selected_uids(_active_table(dashboard)))
    for is_discover, table in ((False, ui.tableWidget_sa_pd_crc_packet),
                               (True, ui.tableWidget_sa_pd_crc_discover_packet)):
        blocker = QtCore.QSignalBlocker(table)
        table.setRowCount(len(dashboard.sa_pd_crc_packets))
        for i, sample in enumerate(dashboard.sa_pd_crc_packets):
            result = sample.get('calculation') or {}
            width = dashboard.sa_pd_crc_model.width
            observed_value = result.get('observed')
            if is_discover and observed_value is None:
                try:
                    _, observed_value, _, _ = crc.region(
                        sample, width,
                        ui.comboBox_sa_pd_crc_model_default_crc_field.currentText(),
                        ui.comboBox_sa_pd_crc_model_coverage.currentText(),
                        ui.comboBox_sa_pd_crc_model_wire_byte_order.currentText())
                except (ValueError, TypeError):
                    observed_value = sample.get('expected')
            observed = ('—' if observed_value is None else
                        '0x' + crc.crc_hex(observed_value, width))
            if is_discover:
                display_role = ('Verify' if sample.get('role', 'Fit') == 'Holdout'
                                else sample.get('role', 'Fit'))
                values = (str(i + 1), display_role, sample.get('source', ''),
                          crc.hex_preview(sample['bits'], _MAX_PREVIEW), str(len(sample['bits'])),
                          observed, sample.get('crc_source') or 'Default')
            else:
                values = (str(i + 1), sample.get('source', ''),
                          crc.hex_preview(sample['bits'], _MAX_PREVIEW), str(len(sample['bits'])),
                          observed, ('0x' + crc.crc_hex(result['calculated'], width)
                                     if 'calculated' in result else '—'),
                          result.get('status', 'Not Run'))
            for j, value in enumerate(values):
                item = QtWidgets.QTableWidgetItem(value)
                item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
                item.setData(QtCore.Qt.UserRole, sample['uid'])
                # Center identifiers, counts, short CRC values and statuses.
                # Leave sources, packets, and free-text fields left-aligned.
                centered = (0, 1, 2, 4, 5) if is_discover else (0, 1, 3, 4, 5, 6)
                item.setTextAlignment(QtCore.Qt.AlignCenter if j in centered
                                      else QtCore.Qt.AlignLeft | QtCore.Qt.AlignVCenter)
                if is_discover and j == 6:
                    if sample.get('crc_source') == 'Custom offset':
                        tooltip = f"Custom CRC field starting at bit {sample.get('crc_start', 0)}"
                    elif sample.get('crc_source'):
                        tooltip = str(sample['crc_source'])
                    else:
                        tooltip = ('Collection default: uses the selected CRC location '
                                   'unless this packet has its own override')
                    item.setToolTip(tooltip)
                else:
                    item.setToolTip(crc.hex_preview(sample['bits'], max_bytes=150))
                if not is_discover and j == 6:
                    item.setForeground(_status_color(value, table.palette()))
                    # Pastel status backgrounds; dark theme remains legible.
                    dark = table.palette().color(QtGui.QPalette.Base).lightness() < 130
                    if value == 'Match':
                        item.setBackground(QtGui.QColor('#20402e' if dark else '#daf1df'))
                        item.setForeground(QtGui.QColor('#a6e4bb' if dark else '#166039'))
                    elif value in ('Fail', 'Error'):
                        item.setBackground(QtGui.QColor('#4a2729' if dark else '#fae0e0'))
                        item.setForeground(QtGui.QColor('#ffbab8' if dark else '#a32929'))
                if result.get('error') and not is_discover:
                    item.setToolTip(result['error'])
                table.setItem(i, j, item)
        table.clearSelection()
        for i, sample in enumerate(dashboard.sa_pd_crc_packets):
            if sample['uid'] in selected:
                table.selectionModel().select(table.model().index(i, 0),
                    QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows)
        del blocker
    _refresh_counts(dashboard)
    _selection_changed(dashboard)
    _refresh_candidates(dashboard)


def _refresh_counts(dashboard):
    """Display the count and its caption inside each existing statistic label."""
    from collections import Counter

    ui = dashboard.ui
    statuses = [
        (packet.get('calculation') or {}).get('status', 'Not Run')
        for packet in dashboard.sa_pd_crc_packets
    ]
    counts = Counter(statuses)
    statistics = (
        ('packets', len(statuses), 'Packets'),
        ('match', counts['Match'], 'Match'),
        ('fail', counts['Fail'] + counts['Error'], 'Fail'),
        ('calculated', counts['Calculated'], 'Calculated'),
        ('not_run', counts['Not Run'], 'Not Run'),
    )
    for name, number, caption in statistics:
        label = getattr(ui, 'label_sa_pd_crc_results_' + name)
        label.setTextFormat(QtCore.Qt.RichText)
        label.setAlignment(QtCore.Qt.AlignCenter)
        # Inherit all foreground/background colors from the current stylesheet.
        label.setText(
            f'<span style="font-size:14pt;font-weight:700">{number}</span>'
            f'<br/><span style="font-size:8pt">{caption}</span>'
        )


def _draw_inspector(dashboard, sample):
    """Render field boundaries, covered bit ranges and packet details."""
    ui = dashboard.ui
    view = ui.graphicsView_sa_pd_crc_inspector
    old_scene = view.scene()
    scene = QtWidgets.QGraphicsScene(view)
    # Scene items don't inherit CSS text colors, and the Qt widget palette can
    # still contain the previous theme while a new stylesheet is being applied.
    # Read FISSURE's active settings, which are updated before custom widgets.
    settings = dashboard.backend.settings
    background = QtGui.QColor(settings.get('color2', '#FBFBFB'))
    dark = background.lightness() < 130
    scene.setBackgroundBrush(QtGui.QBrush(background))
    ink = QtGui.QColor('#E3EDF7' if dark else '#14395A')
    covered_fill = QtGui.QColor('#326B94' if dark else '#77ADD4')
    covered_text = QtGui.QColor('#FFFFFF' if dark else '#122B3B')
    crc_fill = QtGui.QColor('#99505A' if dark else '#D78D8D')
    crc_text = QtGui.QColor('#FFFFFF' if dark else '#421818')
    view.setScene(scene)
    view.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)
    if old_scene is not None:
        old_scene.deleteLater()
    interpretation = ui.formLayout_sa_pd_crc_inspector_interpretation
    calculation = ui.formLayout_sa_pd_crc_inspector_calculation
    for section, form, title in (
        ('interpretation', interpretation, 'Interpretation'),
        ('calculation', calculation, 'Calculation'),
    ):
        while form.rowCount():
            form.removeRow(0)
        form.setContentsMargins(12, 8, 12, 8)
        form.setHorizontalSpacing(8)
        form.setVerticalSpacing(5)
        heading = QtWidgets.QLabel(title)
        heading.setObjectName('label_sa_pd_crc_inspector_' + section + '_heading')
        heading.setMinimumHeight(22)
        form.addRow(heading)
    if not sample:
        placeholder = scene.addText('Select a packet to inspect its CRC coverage.')
        placeholder.setDefaultTextColor(ink)
        return
    result = sample.get('calculation') or {}
    span, covers = result.get('span'), result.get('covers', [])
    bits = sample['bits']
    count = len(bits)
    chart_width = max(320, view.viewport().width() - 12)
    scene.setSceneRect(0, 0, chart_width, 74)
    # The inspector is intentionally a compact hexadecimal overview. Complete
    # packet data and precise non-byte-aligned inputs remain in Edit Selected.
    shown = crc.hex_preview(bits, 12)
    trailing = count % 8
    if trailing and count > 12 * 8:
        shown += f'  ({trailing} trailing bits)'
    title = scene.addText(f'Packet {count:,} bits  •  Hex: {shown}')
    title.setDefaultTextColor(ink)
    title.setPos(0, 0)
    base_brush = QtGui.QBrush(
        QtGui.QColor('#454C53') if dark else QtGui.QColor('#E2E8ED')
    )
    scene.addRect(0, 30, chart_width, 25, QtGui.QPen(QtCore.Qt.NoPen), base_brush)
    if count:
        for begin, end in covers:
            x, width = chart_width * begin / count, chart_width * (end - begin) / count
            region_item = scene.addRect(x, 30, width, 25, QtGui.QPen(QtCore.Qt.NoPen),
                                        QtGui.QBrush(covered_fill))
            region_item.setToolTip(f'CRC-covered bits {begin}–{end - 1}')
            if width >= 95:
                label = scene.addSimpleText('CRC-covered')
                label.setBrush(covered_text)
                label.setPos(x + 5, 32)
        if span and span[0] is not None:
            x, width = chart_width * span[0] / count, chart_width * (span[1] - span[0]) / count
            crc_item = scene.addRect(x, 30, width, 25, QtGui.QPen(QtCore.Qt.NoPen),
                                     QtGui.QBrush(crc_fill))
            crc_item.setToolTip(f'CRC field bits {span[0]}–{span[1] - 1}')
            if width >= 37:
                label = scene.addSimpleText('CRC')
                label.setBrush(crc_text)
                label.setPos(x + 4, 32)
            # The beginning of the CRC is the most useful missing axis marker.
            if 22 < x < chart_width - 30:
                marker = scene.addSimpleText(str(span[0]))
                marker.setBrush(ink)
                marker.setPos(x - 9, 56)
    for marker, x in (('0', 0), (str(count), chart_width - 24)):
        label = scene.addSimpleText(marker)
        label.setBrush(ink)
        label.setPos(x, 56)
    field = sample.get('crc_source') or ui.comboBox_sa_pd_crc_model_default_crc_field.currentText()
    order = sample.get('order') or ui.comboBox_sa_pd_crc_model_wire_byte_order.currentText()
    region_text = ', '.join(f'{a}–{b - 1}' for a, b in covers) or 'Not calculated'
    if span and span[0] is not None:
        wire_bytes = crc.hex_preview(bits[span[0]:span[1]], max_bytes=16)
        field_text = f'{field} ({span[0]}–{span[1] - 1})'
    else:
        wire_bytes = 'Separate / none'
        field_text = field
    observed = (f'0x{crc.crc_hex(result["observed"], dashboard.sa_pd_crc_model.width)}'
                if result.get('observed') is not None else '—')
    calculated = (f'0x{crc.crc_hex(result["calculated"], dashboard.sa_pd_crc_model.width)}'
                  if 'calculated' in result else '—')
    groups = (
        ('interpretation', interpretation, (
            ('CRC source', field_text),
            ('Wire byte order', order),
            ('Wire bytes', wire_bytes),
            ('Observed CRC', observed),
        )),
        ('calculation', calculation, (
            ('Model', dashboard.sa_pd_crc_model.name),
            ('Covered bits', region_text),
            ('Calculated CRC', calculated),
            ('Result', result.get('status', 'Not Run')),
        )),
    )
    for section, form, rows in groups:
        for i, (caption, value) in enumerate(rows):
            label = QtWidgets.QLabel(caption + ':')
            label.setObjectName(f'label2_sa_pd_crc_inspector_{section}_name_{i}')
            widget = QtWidgets.QLabel(str(value))
            widget.setObjectName(f'label2_sa_pd_crc_inspector_{section}_value_{i}')
            widget.setWordWrap(True)
            if result.get('error') and caption == 'Result':
                widget.setToolTip(result['error'])
            form.addRow(label, widget)


def _selection_changed(dashboard):
    _draw_inspector(dashboard, _selected_record(dashboard))


def _current_model(dashboard):
    ui = dashboard.ui

    def value(field):
        string = field.text().strip().lower().replace('0x', '')
        return int(string, 16)

    try:
        model = crc.CRCModel(
            ui.comboBox_sa_pd_crc_model_algorithm.currentText() or 'Custom',
            ui.spinBox_sa_pd_crc_model_width.value(),
            value(ui.lineEdit_sa_pd_crc_model_polynomial),
            value(ui.lineEdit_sa_pd_crc_model_init),
            ui.comboBox_sa_pd_crc_model_reflect_in.currentText() == 'Yes',
            ui.comboBox_sa_pd_crc_model_reflect_out.currentText() == 'Yes',
            value(ui.lineEdit_sa_pd_crc_model_final_xor),
        )
        selected = ui.comboBox_sa_pd_crc_model_algorithm.currentData()
        if selected is not None and (model.width, model.poly, model.init,
                                     model.refin, model.refout, model.xorout) != (
                                     selected.width, selected.poly, selected.init,
                                     selected.refin, selected.refout, selected.xorout):
            model = crc.CRCModel('Custom', model.width, model.poly, model.init,
                                 model.refin, model.refout, model.xorout)
        return model
    except ValueError as error:
        raise ValueError('Invalid model parameters: ' + str(error)) from error


def sa_pd_crc_model_changed(dashboard):
    ui = dashboard.ui
    selected = ui.comboBox_sa_pd_crc_model_algorithm.currentData()
    if selected is None:
        return
    model = selected
    dashboard.sa_pd_crc_model = model
    for name, value in (('polynomial', model.poly), ('init', model.init), ('final_xor', model.xorout)):
        getattr(ui, 'lineEdit_sa_pd_crc_model_' + name).setText(crc.crc_hex(value, model.width))
    ui.spinBox_sa_pd_crc_model_width.setValue(model.width)
    _select_combo(ui.comboBox_sa_pd_crc_model_reflect_in, 'Yes' if model.refin else 'No')
    _select_combo(ui.comboBox_sa_pd_crc_model_reflect_out, 'Yes' if model.refout else 'No')
    ui.plainTextEdit_sa_pd_crc_results_model_definition.setPlainText(model.definition())
    _invalidate(dashboard)


def _invalidate(dashboard):
    for packet in dashboard.sa_pd_crc_packets:
        packet['calculation'] = None
    dashboard.sa_pd_crc_candidates = []
    _refresh(dashboard)


def sa_pd_crc_model_parameters_changed(dashboard):
    try:
        model = _current_model(dashboard)
    except ValueError:
        return
    selected = dashboard.ui.comboBox_sa_pd_crc_model_algorithm.currentData()
    if selected is not None and (model.width, model.poly, model.init, model.refin,
                                 model.refout, model.xorout) != (
                                 selected.width, selected.poly, selected.init,
                                 selected.refin, selected.refout, selected.xorout):
        model = crc.CRCModel('Custom', model.width, model.poly, model.init,
                             model.refin, model.refout, model.xorout)
    dashboard.sa_pd_crc_model = model
    dashboard.ui.plainTextEdit_sa_pd_crc_results_model_definition.setPlainText(model.definition())
    _invalidate(dashboard)


def _mode(dashboard, discover):
    ui = dashboard.ui
    ui.stackedWidget_sa_pd_crc.setCurrentIndex(1 if discover else 0)
    for widget, active in ((ui.pushButton_sa_pd_crc_top_discover, discover),
                           (ui.pushButton_sa_pd_crc_top_calculate_and_validate, not discover)):
        blocker = QtCore.QSignalBlocker(widget)
        widget.setChecked(active)
        del blocker
    _refresh(dashboard)


def sa_pd_crc_mode(dashboard, discover):
    _mode(dashboard, discover)


def sa_pd_crc_packet_action(dashboard, action):
    if (getattr(dashboard, 'sa_pd_crc_running', False) or
            (getattr(dashboard, 'sa_pd_crc_search_thread', None) and
             dashboard.sa_pd_crc_search_thread.isRunning())):
        _show_error(dashboard, 'Stop the active CRC operation before changing packets')
        return
    if action == 'Add':
        packet = _packet_dialog(dashboard)
        if packet:
            _add_packets(dashboard, [packet])
    elif action == 'Edit Selected':
        existing = _selected_record(dashboard)
        if not existing:
            _show_error(dashboard, 'Select a packet first')
            return
        modified = _packet_dialog(dashboard, existing)
        if modified:
            existing.update(modified)
            _invalidate(dashboard)
    elif action == 'Remove':
        table = _active_table(dashboard)
        uids = set(_selected_uids(table))
        if uids:
            # Keep focus on the next surviving row (or the previous last row).
            removed_indices = [i for i, packet in enumerate(dashboard.sa_pd_crc_packets)
                               if packet['uid'] in uids]
            dashboard.sa_pd_crc_packets = [packet for packet in dashboard.sa_pd_crc_packets
                                           if packet['uid'] not in uids]
            _invalidate(dashboard)
            if dashboard.sa_pd_crc_packets:
                next_index = min(min(removed_indices), len(dashboard.sa_pd_crc_packets) - 1)
                table.selectRow(next_index)
                table.setFocus(QtCore.Qt.OtherFocusReason)
                _selection_changed(dashboard)
    elif action == 'Paste Multiple':
        text, accepted = QtWidgets.QInputDialog.getMultiLineText(
            dashboard, 'Paste CRC Packets',
            'One HEX packet per line; prefix binary with 0b or b:')
        if accepted and text.strip():
            rows = []
            try:
                for i, line in enumerate(text.splitlines(), 1):
                    if not line.strip() or line.lstrip().startswith('#'):
                        continue
                    rows.append({'bits': crc.bits_from_input(line), 'source': f'Pasted {i}'})
            except ValueError as error:
                _show_error(dashboard, f'Line {i}: {error}')
                return
            _add_packets(dashboard, rows)
    elif action == 'Import':
        path, _ = QtWidgets.QFileDialog.getOpenFileName(
            dashboard, 'Import CRC packets', '',
            'Packets and sessions (*.txt *.hex *.bits *.bin *.json);;All files (*)')
        if not path:
            return
        try:
            extension = os.path.splitext(path)[1].lower()
            limit = 10 * 1024 * 1024 if extension == '.json' else 1024 * 1024
            if os.path.getsize(path) > limit:
                raise ValueError('Import exceeds the file size limit')
            session = None
            if extension == '.json':
                with open(path, 'r', encoding='utf-8') as stream:
                    document = json.load(stream)
                if isinstance(document, dict):
                    if (document.get('format') != 'FISSURE CRC Analysis' or
                            document.get('version') != 1):
                        raise ValueError('Unsupported CRC session JSON format or version')
                    session = document
                    records = document.get('packets')
                elif isinstance(document, list):
                    # Older exports contain just packet records and no model.
                    records = document
                else:
                    raise ValueError('Expected a CRC session or an array of packet records')
                if not isinstance(records, list):
                    raise ValueError('JSON packets must be an array')
                if len(records) > crc.MAX_SAMPLES:
                    raise ValueError(f'JSON contains more than {crc.MAX_SAMPLES} packets')
                rows = []
                keys = ('bits', 'source', 'role', 'crc_source', 'crc_start',
                        'expected', 'coverage', 'coverage_start', 'coverage_end', 'order')
                for i, record in enumerate(records, 1):
                    try:
                        if not isinstance(record, dict):
                            raise ValueError('Packet must be an object')
                        bits = record.get('bits')
                        if (not isinstance(bits, str) or not bits or
                                set(bits) - {'0', '1'} or len(bits) > crc.MAX_PACKET_BITS):
                            raise ValueError('bits must be a nonempty binary string within the limit')
                        role = record.get('role', 'Fit')
                        if role not in ('Fit', 'Holdout', 'Ignore'):
                            raise ValueError('Unknown discovery role')
                        if record.get('crc_source') not in (None, 'Trailing field',
                                                           'Leading field', 'Custom offset',
                                                           'Separate value'):
                            raise ValueError('Unknown CRC source')
                        if record.get('order') not in (None,) + _ORDERS:
                            raise ValueError('Unknown CRC byte order')
                        if record.get('coverage') is not None:
                            rule = record['coverage']
                            if (rule not in _COVERAGE + ('Custom range',) and
                                    not (isinstance(rule, str) and rule.startswith('Skip first ') and
                                         rule.endswith(' bytes') and
                                         rule[len('Skip first '):-len(' bytes')].isdigit())):
                                raise ValueError('Unknown coverage rule')
                        row = {key: record[key] for key in keys if key in record}
                        for key in ('crc_start', 'coverage_start', 'coverage_end'):
                            if row.get(key) is not None:
                                row[key] = int(row[key])
                                if not 0 <= row[key] <= crc.MAX_PACKET_BITS:
                                    raise ValueError(key + ' is outside the bit range')
                        if row.get('expected') is not None:
                            row['expected'] = int(row['expected'])
                            if row['expected'] < 0 or row['expected'].bit_length() > crc.MAX_CRC_WIDTH:
                                raise ValueError('Expected CRC exceeds supported width')
                        rows.append(row)
                    except (ValueError, TypeError, OverflowError) as error:
                        raise ValueError(f'JSON packet {i}: {error}') from error
                if session is not None:
                    definition = session.get('model')
                    settings = session.get('settings')
                    if not isinstance(definition, str) or not isinstance(settings, dict):
                        raise ValueError('Session is missing its CRC model or settings')
                    restored_model = crc.parse_model(definition)
                    restored_field = settings.get('crc_field')
                    restored_coverage = settings.get('coverage')
                    restored_order = settings.get('wire_byte_order')
                    if restored_field not in _FIELDS or restored_order not in _ORDERS:
                        raise ValueError('Session has an unsupported CRC field or byte order')
                    if (restored_coverage not in _COVERAGE and
                            not (isinstance(restored_coverage, str) and
                                 restored_coverage.startswith('Skip first ') and
                                 restored_coverage.endswith(' bytes') and
                                 restored_coverage[len('Skip first '):-len(' bytes')].isdigit())):
                        raise ValueError('Session has an unsupported coverage setting')
            elif extension == '.bin':
                with open(path, 'rb') as stream:
                    contents = stream.read()
                rows = [{'bits': ''.join(f'{byte:08b}' for byte in contents),
                         'source': os.path.basename(path)}]
            else:
                with open(path, 'r', encoding='utf-8') as stream:
                    lines = stream.readlines()
                bit_mode = 'Bits' if extension == '.bits' else 'Auto'
                rows = []
                for i, line in enumerate(lines, 1):
                    if not line.strip() or line.lstrip().startswith('#'):
                        continue
                    try:
                        bits = crc.bits_from_input(line, bit_mode)
                    except ValueError as error:
                        raise ValueError(f'Line {i}: {error}') from error
                    rows.append({'bits': bits, 'source': f'{os.path.basename(path)}:{i}'})
            if not rows:
                raise ValueError('File contained no packets')
            if session is not None:
                if dashboard.sa_pd_crc_packets:
                    reply = QtWidgets.QMessageBox.question(
                        dashboard, 'Import CRC session',
                        'Replace the current CRC packets and calculation settings with this session?',
                        QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.Cancel,
                        QtWidgets.QMessageBox.Cancel)
                    if reply != QtWidgets.QMessageBox.Yes:
                        return
                ui = dashboard.ui
                combo = ui.comboBox_sa_pd_crc_model_algorithm
                index = combo.findData(restored_model)
                if index < 0:
                    combo.addItem(restored_model.name, restored_model)
                    index = combo.count() - 1
                blocker = QtCore.QSignalBlocker(combo)
                combo.setCurrentIndex(index)
                del blocker
                sa_pd_crc_model_changed(dashboard)
                for combo, setting in (
                    (ui.comboBox_sa_pd_crc_model_default_crc_field, restored_field),
                    (ui.comboBox_sa_pd_crc_model_coverage, restored_coverage),
                    (ui.comboBox_sa_pd_crc_model_wire_byte_order, restored_order),
                ):
                    if combo.findText(setting) < 0:
                        combo.addItem(setting)
                    blocker = QtCore.QSignalBlocker(combo)
                    _select_combo(combo, setting)
                    del blocker
                _add_packets(dashboard, rows, append=False)
                _mode(dashboard, False)
                sa_pd_crc_calculate(dashboard)
            else:
                _add_packets(dashboard, rows)
        except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as error:
            _show_error(dashboard, error)


def sa_pd_crc_calculate(dashboard):
    ui = dashboard.ui
    if getattr(dashboard, 'sa_pd_crc_search_thread', None) and dashboard.sa_pd_crc_search_thread.isRunning():
        _show_error(dashboard, 'Stop CRC discovery before calculating')
        return
    if dashboard.sa_pd_crc_running:
        dashboard.sa_pd_crc_cancel = True
        return
    if not dashboard.sa_pd_crc_packets:
        _show_error(dashboard, 'Add at least one packet')
        return
    try:
        model = _current_model(dashboard)
    except ValueError as error:
        _show_error(dashboard, error)
        return
    dashboard.sa_pd_crc_model = model
    ui.plainTextEdit_sa_pd_crc_results_model_definition.setPlainText(model.definition())
    dashboard.sa_pd_crc_running = True
    dashboard.sa_pd_crc_cancel = False
    dashboard.sa_pd_crc_cursor = 0
    dashboard.sa_pd_crc_run_model = model
    dashboard.sa_pd_crc_run_field = ui.comboBox_sa_pd_crc_model_default_crc_field.currentText()
    dashboard.sa_pd_crc_run_coverage = ui.comboBox_sa_pd_crc_model_coverage.currentText()
    dashboard.sa_pd_crc_run_order = ui.comboBox_sa_pd_crc_model_wire_byte_order.currentText()
    ui.pushButton_sa_pd_crc_model_calculate_all.setText('Stop')
    _calculate_controls(dashboard, False)
    QtCore.QTimer.singleShot(0, lambda: _calculate_chunk(dashboard))


def _calculate_controls(dashboard, enabled):
    ui = dashboard.ui
    for name in ('algorithm', 'reflect_in', 'reflect_out', 'default_crc_field',
                 'coverage', 'wire_byte_order'):
        getattr(ui, 'comboBox_sa_pd_crc_model_' + name).setEnabled(enabled)
    ui.spinBox_sa_pd_crc_model_width.setEnabled(enabled)
    for name in ('polynomial', 'init', 'final_xor'):
        getattr(ui, 'lineEdit_sa_pd_crc_model_' + name).setEnabled(enabled)


def _calculate_chunk(dashboard):
    ui = dashboard.ui
    if dashboard.sa_pd_crc_cancel:
        dashboard.sa_pd_crc_running = False
        ui.pushButton_sa_pd_crc_model_calculate_all.setText('Calculate All')
        _calculate_controls(dashboard, True)
        _refresh(dashboard)
        return
    field = dashboard.sa_pd_crc_run_field
    coverage = dashboard.sa_pd_crc_run_coverage
    order = dashboard.sa_pd_crc_run_order
    limit = min(dashboard.sa_pd_crc_cursor + 10, len(dashboard.sa_pd_crc_packets))
    for i in range(dashboard.sa_pd_crc_cursor, limit):
        packet = dashboard.sa_pd_crc_packets[i]
        try:
            packet['calculation'] = crc.calculate_sample(packet, dashboard.sa_pd_crc_run_model,
                                                         field, coverage, order)
        except ValueError as error:
            packet['calculation'] = {'status': 'Error', 'error': str(error)}
    dashboard.sa_pd_crc_cursor = limit
    if limit < len(dashboard.sa_pd_crc_packets):
        QtCore.QTimer.singleShot(0, lambda: _calculate_chunk(dashboard))
    else:
        dashboard.sa_pd_crc_running = False
        ui.pushButton_sa_pd_crc_model_calculate_all.setText('Calculate All')
        _calculate_controls(dashboard, True)
        _refresh(dashboard)


class _CRCSearchThread(QtCore.QThread):
    completed = QtCore.pyqtSignal(object, bool, str)

    def __init__(self, samples, models, widths, field, coverage, order,
                 offset_limit, skip_limit, known, extended, parent=None):
        super().__init__(parent)
        self.samples, self.models, self.widths = samples, models, widths
        self.field, self.coverage, self.order = field, coverage, order
        self.offset_limit, self.skip_limit = offset_limit, skip_limit
        self.known, self.extended = known, extended
        self.cancel_requested = False

    def run(self):
        candidates = []
        complete = True
        try:
            if self.known:
                known, finished = crc.search_known(
                    self.samples, self.models, self.widths, self.field,
                    self.coverage, self.order, max_offset_bytes=self.offset_limit,
                    max_skip_bytes=self.skip_limit,
                    cancelled=lambda: self.cancel_requested)
                candidates.extend(known)
                complete &= finished
            if self.extended and complete and not self.cancel_requested:
                more, finished = crc.search_extended(
                    self.samples, self.widths, self.field, self.coverage, self.order,
                    seconds_per_width=12, cancelled=lambda: self.cancel_requested)
                seen = {(row['model'], row['field'], row['coverage'], row['order'])
                        for row in candidates}
                for row in more:
                    key = (row['model'], row['field'], row['coverage'], row['order'])
                    if key not in seen:
                        candidates.append(row)
                        seen.add(key)
                complete &= finished
            self.completed.emit(candidates, complete, '')
        except Exception as error:
            self.completed.emit(candidates, False, str(error))


def sa_pd_crc_discover(dashboard):
    ui = dashboard.ui
    if dashboard.sa_pd_crc_running:
        _show_error(dashboard, 'Stop Calculate All before starting discovery')
        return
    running = getattr(dashboard, 'sa_pd_crc_search_thread', None)
    if running and running.isRunning():
        running.cancel_requested = True
        ui.pushButton_sa_pd_crc_discover_settings_discover_crcs.setText('Stopping...')
        return
    if not dashboard.sa_pd_crc_packets:
        _show_error(dashboard, 'Add multiple packets with embedded or separate CRC values')
        return
    known = ui.checkBox_sa_pd_crc_discover_settings_known_models.isChecked()
    extended = ui.checkBox_sa_pd_crc_discover_settings_extended_search.isChecked()
    if not known and not extended:
        _show_error(dashboard, 'Choose Known RevEng models or Extended polynomial search')
        return
    widths = [width for width in (8, 16, 32) if getattr(
        ui, f'checkBox_sa_pd_crc_discover_settings_{width}bits').isChecked()]
    if ui.checkBox_sa_pd_crc_discover_settings_other.isChecked():
        widths.extend(dashboard.sa_pd_crc_other_widths)
    if not widths:
        _show_error(dashboard, 'Select at least one CRC width')
        return
    field = ui.comboBox_sa_pd_crc_discover_settings_crc_location.currentText()
    coverage = ui.comboBox_sa_pd_crc_discover_settings_coverage.currentText()
    order = ui.comboBox_sa_pd_crc_discover_settings_wire_byte_order.currentText()
    if extended:
        if any(width not in (8, 16) for width in widths):
            _show_error(dashboard, 'Extended RevEng search supports only 8/16-bit widths in this bounded mode. '
                                   'Deselect 32-bit and Other widths.')
            return
        if field in ('Search offsets', 'Search ends') or coverage == 'Search prefix':
            _show_error(dashboard, 'For extended search, choose a fixed CRC location and coverage first. '
                                   'Per-packet custom offsets are supported.')
            return
    worker = _CRCSearchThread([dict(sample) for sample in dashboard.sa_pd_crc_packets],
                              list(dashboard.sa_pd_crc_models), widths, field, coverage,
                              order, dashboard.sa_pd_crc_offset_limit.value(),
                              dashboard.sa_pd_crc_skip_limit.value(), known, extended, dashboard)
    dashboard.sa_pd_crc_search_thread = worker
    ui.pushButton_sa_pd_crc_discover_settings_discover_crcs.setText('Stop')
    ui.pushButton_sa_pd_crc_discover_settings_discover_crcs.setToolTip(
        'Click to cancel. Extended polynomial search has a 12-second limit per width/order.')
    ui.label_sa_pd_crc_discover_candidate_subtitle.setText('Searching…')
    worker.completed.connect(lambda candidates, complete, error: _finish_search(
        dashboard, candidates, complete, error))
    worker.start()


def _finish_search(dashboard, candidates, complete, error):
    """Show useful diagnostics when no model fits all selected Fit packets."""
    dashboard.sa_pd_crc_candidates = candidates
    ui = dashboard.ui
    button = ui.pushButton_sa_pd_crc_discover_settings_discover_crcs
    button.setText('Discover CRCs')
    fits = sum(p.get('role', 'Fit') == 'Fit' for p in dashboard.sa_pd_crc_packets)
    if error:
        summary = 'Search failed; partial results may be shown'
    elif not complete:
        summary = 'Search incomplete (stopped or search limit reached)'
    elif candidates:
        summary = 'Search completed'
    else:
        summary = f'No models matched all {fits} Fit packets'
    if not candidates and complete and not error:
        message = ('0 candidates • No model matched every Fit packet. '
                   'Mark suspect packets Ignore, and reserve a valid Verify packet.')
        tooltip = (summary + '. All pasted packets initially have the Fit role. '
                   'Open Edit Selected to assign Fit, Verify, or Ignore. '
                   'A packet with a deliberately corrupted CRC cannot be a Fit packet.')
    else:
        message = f'{len(candidates)} candidate(s) - {summary}. Select a candidate to inspect.'
        tooltip = summary
    button.setToolTip(tooltip)
    ui.label_sa_pd_crc_discover_candidate_subtitle.setText(message)
    ui.label_sa_pd_crc_discover_candidate_subtitle.setToolTip(tooltip)
    _refresh_candidates(dashboard)
    if error:
        _show_error(dashboard, f'{error}\n\nAny displayed candidates are partial results.')


def _refresh_candidates(dashboard):
    ui = dashboard.ui
    table = ui.tableWidget_sa_pd_crc_discover_candidate
    previous = _selected_candidate(dashboard)
    previous_key = (previous['model'], previous['field'], previous['coverage'], previous['order']) if previous else None
    blocker = QtCore.QSignalBlocker(table)
    table.setRowCount(len(dashboard.sa_pd_crc_candidates))
    to_select = 0
    for i, entry in enumerate(dashboard.sa_pd_crc_candidates):
        model = entry['model']
        key = (model, entry['field'], entry['coverage'], entry['order'])
        if key == previous_key:
            to_select = i
        values = (str(i + 1), model.name, str(model.width), f'0x{model.poly:X}',
                  entry.get('display_field', entry['field']),
                  entry.get('display_coverage', entry['coverage']),
                  f'{entry["fits"]}/{entry.get("fit_total", entry["fits"])}',
                  f'{entry["holdout_matches"]}/{entry["holdout_total"]}'
                  if entry['holdout_total'] else 'Not tested')
        for j, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(value)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
            # Center row number, width, polynomial, and match counts only.
            item.setTextAlignment(QtCore.Qt.AlignCenter)
            item.setToolTip(entry.get('origin', 'RevEng preset') + ': ' + entry['status'] +
                            '\nCRC field: ' + entry.get('display_field', entry['field']) +
                            '\nCoverage: ' + entry.get('display_coverage', entry['coverage']) +
                            '\nWire order: ' + entry.get('display_order', entry['order']))
            table.setItem(i, j, item)
    if dashboard.sa_pd_crc_candidates:
        table.selectRow(to_select)
    del blocker
    sa_pd_crc_candidate_selected(dashboard)


def sa_pd_crc_candidate_selected(dashboard):
    ui = dashboard.ui
    row = ui.tableWidget_sa_pd_crc_discover_candidate.currentRow()
    entry = dashboard.sa_pd_crc_candidates[row] if 0 <= row < len(dashboard.sa_pd_crc_candidates) else None
    model = entry['model'] if entry else None

    wire_order = '—'
    if entry:
        if model.width <= 8 or model.width % 8:
            wire_order = 'N/A'
        else:
            wire_order = entry.get('display_order', entry['order'])
            # Two equally validated interpretations do not establish byte order.
            opposite = 'Little endian' if entry['order'] == 'Big endian' else 'Big endian'
            equally_verified = (entry['holdout_total'] == 0 or
                                entry['holdout_matches'] == entry['holdout_total'])
            if equally_verified and any(
                    other is not entry and other['model'] == model and
                    other['field'] == entry['field'] and
                    other['coverage'] == entry['coverage'] and
                    other['order'] == opposite and
                    other['fits'] == entry['fits'] and
                    other['holdout_total'] == entry['holdout_total'] and
                    other['holdout_matches'] == entry['holdout_matches']
                    for other in dashboard.sa_pd_crc_candidates):
                wire_order = 'Undetermined (both fit)'

    values = {
        'model': model.name if model else '—',
        'width_poly': f'{model.width} bits • 0x{model.poly:X}' if model else '—',
        'init_xor': f'0x{model.init:X} • 0x{model.xorout:X}' if model else '—',
        'reflection': f'Input: {model.refin} • Output: {model.refout}' if model else '—',
        'wire_byte_order': wire_order,
        'crc_field': entry.get('display_field', entry['field']) if entry else '—',
        'coverage': entry.get('display_coverage', entry['coverage']) if entry else '—',
        'fitting_packets': str(entry['fits']) + ' matched (fitting samples only)' if entry else '—',
        'held_out_packets': (f'{entry["holdout_matches"]}/{entry["holdout_total"]} passed verification'
                             if entry and entry['holdout_total'] else 'Not tested' if entry else '—'),
    }
    for key, value in values.items():
        label = getattr(ui, 'label2_sa_pd_crc_discover_selected_' + key)
        label.setText(value)
        if key == 'wire_byte_order':
            label.setToolTip(value)
    for name in ('copy', 'export', 'use_in_calculate'):
        getattr(ui, 'pushButton_sa_pd_crc_discover_candidate_' + name).setEnabled(entry is not None)


def _selected_candidate(dashboard):
    row = dashboard.ui.tableWidget_sa_pd_crc_discover_candidate.currentRow()
    return dashboard.sa_pd_crc_candidates[row] if 0 <= row < len(dashboard.sa_pd_crc_candidates) else None


def sa_pd_crc_candidate_action(dashboard, action):
    entry = _selected_candidate(dashboard)
    if not entry:
        return
    if action == 'Copy':
        QtWidgets.QApplication.clipboard().setText(entry['model'].definition())
    elif action == 'Use':
        ui = dashboard.ui
        combo = ui.comboBox_sa_pd_crc_model_algorithm
        idx = combo.findData(entry['model'])
        if idx < 0:
            combo.addItem(entry['model'].name, entry['model'])
            idx = combo.count() - 1
        # Always apply the model parameters, even when the combo index is
        # unchanged and currentIndexChanged would not be emitted.
        blocker = QtCore.QSignalBlocker(combo)
        combo.setCurrentIndex(idx)
        del blocker
        sa_pd_crc_model_changed(dashboard)
        if entry['field'].startswith('Trailing -'):
            offset = int(entry['field'].split('-')[1].split()[0])
            for sample in dashboard.sa_pd_crc_packets:
                if not sample.get('crc_source'):
                    sample['crc_source'] = 'Custom offset'
                    sample['crc_start'] = len(sample['bits']) - entry['model'].width - offset * 8
            _select_combo(ui.comboBox_sa_pd_crc_model_default_crc_field, 'Trailing field')
        else:
            _select_combo(ui.comboBox_sa_pd_crc_model_default_crc_field, entry['field'])
        cov_combo = ui.comboBox_sa_pd_crc_model_coverage
        if cov_combo.findText(entry['coverage']) < 0:
            cov_combo.addItem(entry['coverage'])
        _select_combo(cov_combo, entry['coverage'])
        _select_combo(ui.comboBox_sa_pd_crc_model_wire_byte_order, entry['order'])
        _mode(dashboard, False)
        sa_pd_crc_calculate(dashboard)
    else:
        _export(dashboard, mode='Discover')


def _export(dashboard, mode='Calculate'):
    path, _ = QtWidgets.QFileDialog.getSaveFileName(
        dashboard, 'Export CRC results', '', 'JSON (*.json);;CSV (*.csv)')
    if not path:
        return
    try:
        records = []
        if mode == 'Discover':
            for entry in dashboard.sa_pd_crc_candidates:
                records.append({**{key: value for key, value in entry.items()
                                   if key != 'model'},
                                'model': entry['model'].definition()})
        else:
            keys = ('source', 'bits', 'role', 'crc_source', 'crc_start',
                    'expected', 'coverage', 'coverage_start', 'coverage_end',
                    'order', 'calculation')
            records = [{key: packet.get(key) for key in keys}
                       for packet in dashboard.sa_pd_crc_packets]
        if path.lower().endswith('.csv'):
            # CSV remains a flat report, not a restorable CRC session.
            with open(path, 'w', newline='', encoding='utf-8') as out:
                rows = [{key: json.dumps(value) if isinstance(value, (dict, list)) else value
                         for key, value in record.items()} for record in records]
                if rows:
                    writer = csv.DictWriter(out, fieldnames=sorted({key for row in rows
                                                                     for key in row}))
                    writer.writeheader()
                    writer.writerows(rows)
        else:
            if mode == 'Discover':
                document = records  # Candidate reports are not session files.
            else:
                ui = dashboard.ui
                document = {
                    'format': 'FISSURE CRC Analysis',
                    'version': 1,
                    'model': _current_model(dashboard).definition(),
                    'settings': {
                        'crc_field': ui.comboBox_sa_pd_crc_model_default_crc_field.currentText(),
                        'coverage': ui.comboBox_sa_pd_crc_model_coverage.currentText(),
                        'wire_byte_order': ui.comboBox_sa_pd_crc_model_wire_byte_order.currentText(),
                    },
                    'packets': records,
                }
            with open(path, 'w', encoding='utf-8') as out:
                json.dump(document, out, indent=2)
    except (OSError, ValueError) as error:
        _show_error(dashboard, error)


def sa_pd_crc_results_action(dashboard, action):
    if action == 'Copy':
        QtWidgets.QApplication.clipboard().setText(
            dashboard.ui.plainTextEdit_sa_pd_crc_results_model_definition.toPlainText())
    else:
        _export(dashboard)


def _switch_to_crc(dashboard):
    dashboard.ui.tabWidget_protocol.setCurrentWidget(dashboard.ui.tab_sa_pd_crc_analysis)
    dashboard.ui.tabWidget_signal_analysis.setCurrentWidget(dashboard.ui.tab_protocol_discovery)


def sa_pd_crc_transfer(dashboard, source):
    incoming = []
    ui = dashboard.ui
    if source == 'BF':
        table = ui.tableWidget_sa_pd_bf_messages
        indices = []
        for row in table.selectionModel().selectedRows():
            item = table.item(row.row(), 0)
            if item is not None:
                indices.append(item.data(QtCore.Qt.UserRole))
        frames = getattr(dashboard, 'sa_pd_bf_frames', [])
        for index in dict.fromkeys(indices):
            if index is not None and 0 <= int(index) < len(frames):
                bits = frames[int(index)].get('bits')
                if bits is not None:
                    incoming.append({'bits': bits, 'source': f'Bitstream & Framing #{int(index)+1}'})
    elif source == 'PA':
        table = ui.tableWidget_sa_pd_pa_input
        lookup = {record['uid']: record for record in getattr(dashboard, 'sa_pd_pa_records', [])}
        for row in table.selectionModel().selectedRows():
            item = table.item(row.row(), 0)
            record = lookup.get(item.data(QtCore.Qt.UserRole)) if item else None
            if record:
                incoming.append({'bits': record['bits'], 'source': record.get('source', 'Packet Analysis'),
                                 'capture': record.get('capture')})
    elif source == 'Comparison':
        table = ui.tableWidget_sa_pd_comparison_collection
        lookup = {record['uid']: record for record in getattr(dashboard, 'sa_pd_comparison_records', [])}
        for row in table.selectionModel().selectedRows():
            item = table.item(row.row(), 0)
            record = lookup.get(item.data(QtCore.Qt.UserRole)) if item else None
            if record:
                incoming.append({'bits': record['bits'], 'source': record.get('source', 'Comparison'),
                                 'capture': record.get('capture')})
    if (getattr(dashboard, 'sa_pd_crc_running', False) or
            (getattr(dashboard, 'sa_pd_crc_search_thread', None) and
             dashboard.sa_pd_crc_search_thread.isRunning())):
        _show_error(dashboard, 'Stop the active CRC operation before transferring packets')
        return
    if not incoming:
        _show_error(dashboard, 'Select one or more packets to transfer')
        return
    if dashboard.sa_pd_crc_packets:
        reply = QtWidgets.QMessageBox.question(
            dashboard, 'Transfer CRC Packets',
            f'Append {len(incoming)} selected packets to the existing CRC collection?',
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No | QtWidgets.QMessageBox.Cancel,
            QtWidgets.QMessageBox.Yes)
        if reply == QtWidgets.QMessageBox.Cancel:
            return
        append = reply == QtWidgets.QMessageBox.Yes
    else:
        append = True
    if _add_packets(dashboard, incoming, append=append):
        _switch_to_crc(dashboard)


def initialize_sa_pd_crc_controls(dashboard):
    """Initial state; all event connections are in Frontend.connect_pd_slots."""
    if getattr(dashboard, 'sa_pd_crc_initialized', False):
        return
    ui = dashboard.ui
    dashboard.sa_pd_crc_packets = []
    dashboard.sa_pd_crc_next_uid = 1
    dashboard.sa_pd_crc_candidates = []
    dashboard.sa_pd_crc_running = False
    dashboard.sa_pd_crc_cancel = False
    dashboard.sa_pd_crc_search_thread = None
    dashboard.sa_pd_crc_other_widths = []
    try:
        models = crc.load_reveng_models()
    except (FileNotFoundError, ValueError, RuntimeError, OSError) as error:
        models = list(crc.FALLBACK_MODELS)
        ui.pushButton_sa_pd_crc_discover_settings_discover_crcs.setToolTip(
            'RevEng not available, using only five bundled models: ' + str(error))
    dashboard.sa_pd_crc_models = models
    for table in (ui.tableWidget_sa_pd_crc_packet, ui.tableWidget_sa_pd_crc_discover_packet):
        table.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
        table.verticalHeader().hide()
        table.verticalHeader().setDefaultSectionSize(23)
        table.horizontalHeader().setStretchLastSection(False)
        table.setAlternatingRowColors(False)
        if table is ui.tableWidget_sa_pd_crc_packet:
            widths = (35, 85, 0, 47, 102, 100, 78)
            stretch_column = 2
        else:
            widths = (35, 58, 90, 0, 48, 95, 107)
            stretch_column = 3
        header = table.horizontalHeader()
        for index, width in enumerate(widths):
            header.setSectionResizeMode(index, QtWidgets.QHeaderView.Fixed)
            if width:
                table.setColumnWidth(index, width)
        header.setSectionResizeMode(stretch_column, QtWidgets.QHeaderView.Stretch)
    table = ui.tableWidget_sa_pd_crc_discover_candidate
    table.horizontalHeaderItem(7).setText('Verify')
    ui.label2_149.setText('Verify packets:')    
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
    table.verticalHeader().hide()
    table.horizontalHeader().setStretchLastSection(True)
    for i, width in enumerate((40, 160, 55, 100, 105, 105, 45, 85)):
        table.setColumnWidth(i, width)
    for combo, values in (
        (ui.comboBox_sa_pd_crc_model_reflect_in, ('No', 'Yes')),
        (ui.comboBox_sa_pd_crc_model_reflect_out, ('No', 'Yes')),
        (ui.comboBox_sa_pd_crc_model_default_crc_field, _FIELDS),
        (ui.comboBox_sa_pd_crc_model_coverage, _COVERAGE),
        (ui.comboBox_sa_pd_crc_model_wire_byte_order, _ORDERS),
        (ui.comboBox_sa_pd_crc_discover_settings_crc_location,
         ('Trailing field', 'Leading field', 'Search ends', 'Search offsets', 'Separate value')),
        (ui.comboBox_sa_pd_crc_discover_settings_coverage,
         ('Before CRC', 'Search prefix', 'Entire packet except CRC')),
        (ui.comboBox_sa_pd_crc_discover_settings_wire_byte_order, ('Auto (both)',) + _ORDERS),
    ):
        _fill_combo(combo, values)
    ui.spinBox_sa_pd_crc_model_width.setRange(1, crc.MAX_CRC_WIDTH)
    combo = ui.comboBox_sa_pd_crc_model_algorithm
    blocker = QtCore.QSignalBlocker(combo)
    combo.clear()
    combo.addItem('Custom', None)
    for model in models:
        combo.addItem(model.name, model)
    del blocker
    default = next((m for m in models if m.name.upper() == 'CRC-16/MODBUS'), models[0])
    _select_combo(combo, default.name)
    dashboard.sa_pd_crc_model = default
    for name, val in (('polynomial', default.poly), ('init', default.init), ('final_xor', default.xorout)):
        getattr(ui, 'lineEdit_sa_pd_crc_model_' + name).setText(crc.crc_hex(val, default.width))
    ui.spinBox_sa_pd_crc_model_width.setValue(default.width)
    _select_combo(ui.comboBox_sa_pd_crc_model_reflect_in, 'Yes' if default.refin else 'No')
    _select_combo(ui.comboBox_sa_pd_crc_model_reflect_out, 'Yes' if default.refout else 'No')
    if default.name.upper() == 'CRC-16/MODBUS':
        _select_combo(ui.comboBox_sa_pd_crc_model_wire_byte_order, 'Little endian')
    ui.plainTextEdit_sa_pd_crc_results_model_definition.setReadOnly(True)
    ui.plainTextEdit_sa_pd_crc_results_model_definition.setPlainText(default.definition())
    for width in (8, 16, 32):
        getattr(ui, f'checkBox_sa_pd_crc_discover_settings_{width}bits').setChecked(width in (8, 16))
    ui.checkBox_sa_pd_crc_discover_settings_known_models.setChecked(True)
    ui.checkBox_sa_pd_crc_discover_settings_extended_search.setChecked(False)
    ui.checkBox_sa_pd_crc_discover_settings_other.setChecked(False)
    advanced = ui.widget_sa_pd_crc_discover_settings_advanced_settings
    form = ui.formLayout_sa_pd_crc_discover_settings_advanced_settings
    form.setContentsMargins(4, 3, 4, 3)
    form.setVerticalSpacing(6)
    dashboard.sa_pd_crc_offset_limit = QtWidgets.QSpinBox()
    dashboard.sa_pd_crc_offset_limit.setRange(0, 16)
    dashboard.sa_pd_crc_offset_limit.setValue(4)
    dashboard.sa_pd_crc_skip_limit = QtWidgets.QSpinBox()
    dashboard.sa_pd_crc_skip_limit.setRange(0, 16)
    dashboard.sa_pd_crc_skip_limit.setValue(4)
    form.addRow('Search CRC offsets (bytes):', dashboard.sa_pd_crc_offset_limit)
    form.addRow('Search prefix skips (bytes):', dashboard.sa_pd_crc_skip_limit)
    for field_widget in (dashboard.sa_pd_crc_offset_limit,
                         dashboard.sa_pd_crc_skip_limit):
        label = form.labelForField(field_widget)
        if label is not None:
            font = label.font()
            font.setPointSize(9)
            label.setFont(font)
    advanced.hide()
    ui.toolButton_sa_pd_crc_discover_settings_advanced_settings.setChecked(False)
    ui.pushButton_sa_pd_crc_top_calculate_and_validate.setCheckable(True)
    ui.pushButton_sa_pd_crc_top_discover.setCheckable(True)
    for name in ('copy', 'export', 'use_in_calculate'):
        getattr(ui, 'pushButton_sa_pd_crc_discover_candidate_' + name).setEnabled(False)
    dashboard.sa_pd_crc_initialized = True
    _mode(dashboard, False)


def restyle_sa_pd_crc_inspector(dashboard):
    """Redraw the graphics scene after FISSURE updates its color settings."""
    if not getattr(dashboard, 'sa_pd_crc_initialized', False):
        return
    _draw_inspector(dashboard, _selected_record(dashboard))


def sa_pd_crc_toggle_advanced(dashboard, checked):
    ui = dashboard.ui
    ui.widget_sa_pd_crc_discover_settings_advanced_settings.setVisible(checked)
    ui.toolButton_sa_pd_crc_discover_settings_advanced_settings.setArrowType(
        QtCore.Qt.DownArrow if checked else QtCore.Qt.RightArrow)


def sa_pd_crc_other_widths(dashboard, checked):
    if not checked:
        dashboard.sa_pd_crc_other_widths = []
        return
    value, accepted = QtWidgets.QInputDialog.getInt(
        dashboard, 'Additional CRC width', 'Width in bits (1–128):', 24, 1, 128, 1)
    if accepted:
        dashboard.sa_pd_crc_other_widths = [value]
        dashboard.ui.checkBox_sa_pd_crc_discover_settings_other.setText(f'Other: {value} bits')
    else:
        dashboard.ui.checkBox_sa_pd_crc_discover_settings_other.setChecked(False)


def sa_pd_crc_selection_changed(dashboard):
    _selection_changed(dashboard)


__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value) and value.__module__ == __name__
]
