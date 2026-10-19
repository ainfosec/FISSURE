"""Protocol Discovery / Packet Analysis: UI state, transfer and presentation.

The protocol analysis engine lives in fissure.utils.protocol_packet_analysis
and has no Qt or Dashboard dependencies. Messages and analyses are session-only.
"""

import inspect
import os

from PyQt5 import QtCore, QtWidgets

from fissure.utils.protocol_bitstream import read_bitstream_file
from fissure.utils.protocol_packet_analysis import (
    MAX_PACKET_BITS, analyze_collection, format_bits_hex, make_packet, parse_packet_text,
)

_PA_DISPLAY_BITS = 512

class _PACenteredCheckDelegate(QtWidgets.QStyledItemDelegate):
    """Center the drawn checkbox and make its entire table cell clickable."""
    def paint(self, painter, option, index):
        state = index.data(QtCore.Qt.CheckStateRole)
        if state is None:
            super().paint(painter, option, index)
            return

        style = option.widget.style() if option.widget else QtWidgets.QApplication.style()
        background = QtWidgets.QStyleOptionViewItem(option)
        self.initStyleOption(background, index)
        background.features &= ~QtWidgets.QStyleOptionViewItem.HasCheckIndicator
        style.drawControl(QtWidgets.QStyle.CE_ItemViewItem, background, painter, option.widget)

        indicator = QtWidgets.QStyleOptionViewItem(option)
        self.initStyleOption(indicator, index)
        width = style.pixelMetric(QtWidgets.QStyle.PM_IndicatorWidth, indicator, option.widget)
        height = style.pixelMetric(QtWidgets.QStyle.PM_IndicatorHeight, indicator, option.widget)
        indicator.rect = QtCore.QRect(
            option.rect.x() + (option.rect.width() - width) // 2,
            option.rect.y() + (option.rect.height() - height) // 2,
            width, height,
        )

        # Qt's checkbox primitive reads State_On/Off/NoChange, not just checkState.
        indicator.state &= ~(QtWidgets.QStyle.State_On |
                             QtWidgets.QStyle.State_Off |
                             QtWidgets.QStyle.State_NoChange)
        if state == QtCore.Qt.Checked:
            indicator.state |= QtWidgets.QStyle.State_On
        elif state == QtCore.Qt.PartiallyChecked:
            indicator.state |= QtWidgets.QStyle.State_NoChange
        else:
            indicator.state |= QtWidgets.QStyle.State_Off

        style.drawPrimitive(QtWidgets.QStyle.PE_IndicatorItemViewItemCheck,
                            indicator, painter, option.widget)

    def editorEvent(self, event, model, option, index):
        if not (index.flags() & QtCore.Qt.ItemIsUserCheckable) or not (index.flags() & QtCore.Qt.ItemIsEnabled):
            return False
        if event.type() in (QtCore.QEvent.MouseButtonPress, QtCore.QEvent.MouseButtonDblClick):
            return bool(event.button() == QtCore.Qt.LeftButton and option.rect.contains(event.pos()))
        if event.type() == QtCore.QEvent.MouseButtonRelease:
            if event.button() != QtCore.Qt.LeftButton or not option.rect.contains(event.pos()):
                return False
        elif event.type() == QtCore.QEvent.KeyPress:
            if event.key() not in (QtCore.Qt.Key_Space, QtCore.Qt.Key_Select):
                return False
        else:
            return False
        old = index.data(QtCore.Qt.CheckStateRole)
        new = QtCore.Qt.Unchecked if old == QtCore.Qt.Checked else QtCore.Qt.Checked
        return model.setData(index, new, QtCore.Qt.CheckStateRole)


class _PACandidateCard(QtWidgets.QFrame):
    def __init__(self, candidate, selected, click, parent=None):
        super().__init__(parent)
        self.setObjectName('frame_sa_pd_pa_candidate_card')
        self.setProperty('paSelected', bool(selected))
        self.setCursor(QtCore.Qt.PointingHandCursor)

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(10, 7, 10, 7)
        layout.setSpacing(3)

        heading = QtWidgets.QHBoxLayout()
        heading.setContentsMargins(0, 0, 0, 0)
        heading.setSpacing(5)
        title = QtWidgets.QLabel(str(candidate.get('protocol') or 'Unidentified protocol'), self)
        title.setObjectName('label_sa_pd_pa_candidate_title')
        title.setWordWrap(True)
        heading.addWidget(title, 1)

        strength = str(candidate.get('strength') or 'Unknown')
        badge = QtWidgets.QLabel(strength, self)
        badge.setObjectName('label_sa_pd_pa_candidate_badge')
        badge.setProperty('paStrength', strength.lower().replace(' ', '_'))
        badge.setAlignment(QtCore.Qt.AlignCenter)
        badge.setMinimumWidth(94)
        badge.setMinimumHeight(21)
        heading.addWidget(badge, 0, QtCore.Qt.AlignTop)
        layout.addLayout(heading)

        subtype = QtWidgets.QLabel(str(candidate.get('message_type') or 'Unknown type'), self)
        subtype.setObjectName('label_sa_pd_pa_candidate_strength')
        subtype.setWordWrap(True)
        layout.addWidget(subtype)

        note = QtWidgets.QLabel(str(candidate.get('summary') or ''), self)
        note.setObjectName('label_sa_pd_pa_candidate_summary')
        note.setWordWrap(True)
        layout.addWidget(note)
        self._click = click

    def mousePressEvent(self, event):
        if event.button() == QtCore.Qt.LeftButton:
            self._click()
        super().mousePressEvent(event)


def initialize_sa_pd_pa_controls(dashboard):
    """Initialize a previously designed Packet Analysis tab exactly once."""
    if getattr(dashboard, 'sa_pd_pa_initialized', False):
        return
    ui = dashboard.ui
    dashboard.sa_pd_pa_records = []
    dashboard.sa_pd_pa_results = {}
    dashboard.sa_pd_pa_next_uid = 1
    dashboard.sa_pd_pa_active_uid = None
    dashboard.sa_pd_pa_candidate_index = 0
    dashboard.sa_pd_pa_analyzing = False
    scroll = ui.scrollArea_sa_pd_pa_results_candidates
    scroll.setWidgetResizable(True)
    scroll.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    content = ui.scrollAreaWidgetContents_sa_pd_pa_results_candidates
    layout = content.layout()
    if layout is None:
        layout = QtWidgets.QVBoxLayout(content)
    layout.setContentsMargins(5, 5, 5, 5)
    layout.setSpacing(7)
    dashboard.sa_pd_pa_candidates_layout = layout

    table = ui.tableWidget_sa_pd_pa_input
    table.setColumnCount(8)
    table.setHorizontalHeaderLabels(('Include', '#', 'Source', 'Capture #', 'Length (bits)',
                                      'Analysis Result', 'Status', 'Notes'))
    table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    table.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
    table.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    table.setSortingEnabled(False)
    table.setWordWrap(False)
    table.verticalHeader().setVisible(False)
    table.verticalHeader().setDefaultSectionSize(22)
    table.horizontalHeader().setFixedHeight(23)
    table.setItemDelegateForColumn(0, _PACenteredCheckDelegate(table))
    for index, width in enumerate((65, 45, 215, 85, 110, 170, 115, 220)):
        table.setColumnWidth(index, width)
    table.horizontalHeader().setStretchLastSection(True)
    table.itemSelectionChanged.connect(lambda: _pa_selection_changed(dashboard))
    table.itemChanged.connect(lambda _item: _pa_update_controls(dashboard))
    for name, callback in (
        ('add_file', _pa_add_files), ('paste_hex_binary', _pa_paste),
        ('select_all', _pa_check_all), ('select_none', _pa_check_none),
        ('delete_selected', _pa_delete_rows), ('clear_all', _pa_clear),
        ('analyze', _pa_analyze_checked),
    ):
        getattr(ui, 'pushButton_sa_pd_pa_input_' + name).clicked.connect(
            lambda _checked=False, fn=callback: fn(dashboard)
        )
    evidence = ui.tableWidget_sa_pd_pa_results_evidence
    evidence.setColumnWidth(0, 140)
    evidence.setColumnWidth(1, 200)
    evidence.setColumnWidth(2, 205)
    evidence.itemSelectionChanged.connect(lambda: _pa_evidence_selected(dashboard))
    decoded = ui.tableWidget_sa_pd_pa_results_fields_decoded_fields
    decoded.itemSelectionChanged.connect(lambda: _pa_field_selected(dashboard))
    bits = ui.tableWidget_sa_pd_pa_results_fields_packet_bits
    bits.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    bits.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectItems)
    bits.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
    bits.horizontalHeader().setStretchLastSection(False)
    bits.horizontalHeader().setMinimumSectionSize(18)
    bits.horizontalHeader().setDefaultSectionSize(20)
    bits.horizontalHeader().setFixedHeight(18)
    bits.verticalHeader().setVisible(False)
    ui.tabWidget_sa_pd_pa_results_candidate_details.setCurrentIndex(0)
    dashboard.sa_pd_pa_initialized = True
    _pa_refresh_table(dashboard)

def _pa_append_packets(dashboard, packets):
    """Append fresh observations, including deliberate duplicate imports."""
    if not getattr(dashboard, 'sa_pd_pa_initialized', False):
        initialize_sa_pd_pa_controls(dashboard)
    if not packets:
        return 0
    last_uid = None
    added = 0
    for entry in packets:
        try:
            packet = make_packet(entry['bits'], source=entry.get('source', 'Unknown'),
                                 capture=entry.get('capture', 1),
                                 metadata=entry.get('metadata'), framing=entry.get('framing'))
        except (ValueError, TypeError, KeyError) as exc:
            dashboard.logger.warning('Packet Analysis skipped invalid import: %s', exc)
            continue
        packet['uid'] = dashboard.sa_pd_pa_next_uid
        dashboard.sa_pd_pa_next_uid += 1
        dashboard.sa_pd_pa_records.append(packet)
        last_uid = packet['uid']
        added += 1
    if added:
        dashboard.sa_pd_pa_active_uid = last_uid
        dashboard.sa_pd_pa_candidate_index = 0
        _pa_refresh_table(dashboard)
    return added


def open_sa_pd_pa_from_bf(dashboard, *, all_frames=False):
    """Transfer original frame records, not preview text or a deduplicated set."""
    frames = list(getattr(dashboard, 'sa_pd_bf_frames', []))
    if not frames:
        return 0
    if all_frames:
        indices = list(range(len(frames)))
    else:
        table = dashboard.ui.tableWidget_sa_pd_bf_messages
        indices = []
        for item in table.selectedItems():
            if item.column() == 0:
                indices.append(item.data(QtCore.Qt.UserRole))
        if not indices and table.currentRow() >= 0:
            cell = table.item(table.currentRow(), 0)
            if cell is not None:
                indices.append(cell.data(QtCore.Qt.UserRole))
        indices = list(dict.fromkeys(int(i) for i in indices if i is not None))
    source_meta = dict(getattr(dashboard, 'sa_pd_bf_metadata', {}) or {})
    source_path = source_meta.get('path')
    if not source_path:
        source_path = (getattr(dashboard, 'sa_pd_demodulation_file_metadata', {}) or {}).get('path')
    source = (os.path.basename(str(source_path)) if source_path else
              str(source_meta.get('soi_name') or source_meta.get('soi_id') or 'Demodulation'))
    analysis = dict(getattr(dashboard, 'sa_pd_bf_analysis', {}) or {})
    metadata = {
        'path': source_path, 'modulation': source_meta.get('modulation'),
        'encoding': analysis.get('encoding'), 'polarity': analysis.get('polarity'),
        'symbol_rate': source_meta.get('symbol_rate'),
        'source': getattr(dashboard, 'sa_pd_bf_source', ''),
    }
    records = []
    for index in indices:
        if not 0 <= index < len(frames):
            continue
        frame = frames[index]
        payload = frame.get('bits')
        if payload is None:
            continue
        # The source coordinates in each frame remain untouched.
        context = {key: value for key, value in frame.items() if key != 'bits'}
        records.append({'bits': payload, 'source': source, 'capture': index + 1,
                        'metadata': metadata, 'framing': context})
    count = _pa_append_packets(dashboard, records)
    if count:
        dashboard.ui.tabWidget_protocol.setCurrentWidget(dashboard.ui.tab_sa_pd_packet_analysis)
        dashboard.ui.tabWidget_signal_analysis.setCurrentWidget(dashboard.ui.tab_protocol_discovery)
    return count


def _pa_add_files(dashboard):
    files, _filter = QtWidgets.QFileDialog.getOpenFileNames(
        dashboard, 'Add Packet Message File', '',
        'Message data (*.hex *.bits *.bit *.bin *.dat *.txt *.json);;All Files (*)'
    )
    packets = []
    for path in files:
        try:
            bits = read_bitstream_file(path)
            if len(bits) > MAX_PACKET_BITS:
                raise ValueError(f'Message exceeds Packet Analysis limit of {MAX_PACKET_BITS:,} bits')
            packets.append({'bits': bits, 'source': os.path.basename(path),
                            'capture': 1, 'metadata': {'path': path, 'source': 'local_file'}})
        except (OSError, ValueError, TypeError) as exc:
            QtWidgets.QMessageBox.warning(dashboard, 'Packet Import', f'{path}\n{exc}')
    _pa_append_packets(dashboard, packets)


def _pa_paste(dashboard):
    text, ok = QtWidgets.QInputDialog.getMultiLineText(
        dashboard, 'Paste Packet Bits',
        'Paste binary (0b...) or hex (0x...). Hex may include trailing zero padding:', ''
    )
    if not ok or not text.strip():
        return
    try:
        # Same normalization and Auto rules as parse_packet_text(). An explicit
        # 0x prefix is needed when the hex contains only digits 0 and 1.
        compact = ''.join(ch for ch in text.strip() if ch not in ' \t\r\n_:,')
        explicit_bin = compact.lower().startswith('0b')
        explicit_hex = compact.lower().startswith('0x')
        digits = compact[2:] if (explicit_bin or explicit_hex) else compact
        is_hex = explicit_hex or (not explicit_bin and bool(set(digits) - {'0', '1'}))
        if is_hex:
            full = parse_packet_text(text)
            bit_count, accepted = QtWidgets.QInputDialog.getInt(
                dashboard, 'Exact Packet Length',
                f'Hex contains {len(full)} bits including possible trailing padding.\n'
                'Enter the exact message length in bits (or keep all bits):',
                len(full), 1, len(full), 1
            )
            if not accepted:
                return
            bits = parse_packet_text(text, bit_length=bit_count)
        else:
            bits = parse_packet_text(text)
    except ValueError as exc:
        QtWidgets.QMessageBox.warning(dashboard, 'Invalid Packet Data', str(exc))
        return
    _pa_append_packets(dashboard, [{'bits': bits, 'source': 'Pasted Message',
                                    'capture': 1, 'metadata': {'source': 'manual'}}])
    

def _pa_refresh_table(dashboard):
    ui = dashboard.ui
    records = dashboard.sa_pd_pa_records
    table = ui.tableWidget_sa_pd_pa_input
    previous_checked = {}
    for row in range(table.rowCount()):
        cell = table.item(row, 0)
        if cell is not None:
            previous_checked[cell.data(QtCore.Qt.UserRole)] = cell.checkState()
    blocker = QtCore.QSignalBlocker(table)
    table.setRowCount(len(records))
    selected_row = -1
    for row, record in enumerate(records):
        uid = record['uid']
        result = dashboard.sa_pd_pa_results.get(uid)
        values = ('', str(row + 1), record['source'], str(record['capture']),
                  str(len(record['bits'])),
                  str(result.get('summary') if result else 'Not analyzed'),
                  'Analyzed' if result else 'Ready', '')
        for col, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(value)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
            if col == 0:
                item.setFlags(item.flags() | QtCore.Qt.ItemIsUserCheckable)
                item.setCheckState(previous_checked.get(uid, QtCore.Qt.Checked))
            item.setData(QtCore.Qt.UserRole, uid)
            if col != 7:
                item.setTextAlignment(QtCore.Qt.AlignCenter)
            if value:
                item.setToolTip(value)
            table.setItem(row, col, item)
        if uid == dashboard.sa_pd_pa_active_uid:
            selected_row = row
    table.clearSelection()
    if selected_row >= 0:
        table.selectRow(selected_row)
    del blocker
    _pa_update_controls(dashboard)
    _pa_show_active(dashboard)

def _pa_checked_uids(dashboard):
    table = dashboard.ui.tableWidget_sa_pd_pa_input
    return {table.item(row, 0).data(QtCore.Qt.UserRole)
            for row in range(table.rowCount())
            if table.item(row, 0) is not None and
            table.item(row, 0).checkState() == QtCore.Qt.Checked}


def _pa_update_controls(dashboard):
    ui = dashboard.ui
    count = len(dashboard.sa_pd_pa_records)
    checked = len(_pa_checked_uids(dashboard))
    ui.label2_sa_pd_pa_input_count.setText(f'{checked} of {count} selected')
    ui.pushButton_sa_pd_pa_input_analyze.setEnabled(checked > 0 and not dashboard.sa_pd_pa_analyzing)
    ui.pushButton_sa_pd_pa_input_select_all.setEnabled(count > 0)
    ui.pushButton_sa_pd_pa_input_select_none.setEnabled(count > 0)
    ui.pushButton_sa_pd_pa_input_clear_all.setEnabled(count > 0)
    ui.pushButton_sa_pd_pa_input_delete_selected.setEnabled(
        bool(ui.tableWidget_sa_pd_pa_input.selectionModel().selectedRows()))


def _pa_check_all(dashboard, checked=True):
    table = dashboard.ui.tableWidget_sa_pd_pa_input
    blocker = QtCore.QSignalBlocker(table)
    for row in range(table.rowCount()):
        cell = table.item(row, 0)
        if cell is not None:
            cell.setCheckState(QtCore.Qt.Checked if checked else QtCore.Qt.Unchecked)
    del blocker
    _pa_update_controls(dashboard)


def _pa_check_none(dashboard):
    _pa_check_all(dashboard, False)


def _pa_delete_rows(dashboard):
    table = dashboard.ui.tableWidget_sa_pd_pa_input
    remove = {table.item(index.row(), 0).data(QtCore.Qt.UserRole)
              for index in table.selectionModel().selectedRows()
              if table.item(index.row(), 0) is not None}
    if not remove:
        return
    dashboard.sa_pd_pa_records = [p for p in dashboard.sa_pd_pa_records if p['uid'] not in remove]
    for uid in remove:
        dashboard.sa_pd_pa_results.pop(uid, None)
    if dashboard.sa_pd_pa_active_uid in remove:
        # The newly active message can have fewer candidate cards.
        dashboard.sa_pd_pa_candidate_index = 0
        dashboard.sa_pd_pa_active_uid = (dashboard.sa_pd_pa_records[0]['uid']
                                          if dashboard.sa_pd_pa_records else None)
    _pa_refresh_table(dashboard)


def _pa_clear(dashboard):
    dashboard.sa_pd_pa_records.clear()
    dashboard.sa_pd_pa_results.clear()
    dashboard.sa_pd_pa_active_uid = None
    _pa_refresh_table(dashboard)


def _pa_selection_changed(dashboard):
    table = dashboard.ui.tableWidget_sa_pd_pa_input
    current = table.currentRow()
    item = table.item(current, 0) if current >= 0 else None
    if item is None:
        _pa_update_controls(dashboard)
        return
    uid = item.data(QtCore.Qt.UserRole)
    if uid != dashboard.sa_pd_pa_active_uid:
        dashboard.sa_pd_pa_active_uid = uid
        dashboard.sa_pd_pa_candidate_index = 0
        _pa_show_active(dashboard)
    _pa_update_controls(dashboard)


def _pa_analyze_checked(dashboard):
    records = dashboard.sa_pd_pa_records
    checked = _pa_checked_uids(dashboard)
    indices = [i for i, packet in enumerate(records) if packet['uid'] in checked]
    if not indices:
        return
    dashboard.sa_pd_pa_analyzing = True
    _pa_update_controls(dashboard)
    try:
        # Read the existing cached Library only. No database I/O or UI coupling
        # occurs inside the pure identification engine.
        backend = getattr(dashboard, 'backend', None)
        library = getattr(backend, 'library', None)
        # Each click starts a new complete analysis for the checked subset.
        fresh = analyze_collection(records, indices, library=library)
    except (ValueError, TypeError, IndexError, KeyError) as exc:
        QtWidgets.QMessageBox.warning(dashboard, 'Packet Analysis', str(exc))
        return
    finally:
        dashboard.sa_pd_pa_analyzing = False
        _pa_update_controls(dashboard)
    dashboard.sa_pd_pa_results = fresh
    dashboard.sa_pd_pa_candidate_index = 0
    _pa_refresh_table(dashboard)

def _pa_clear_candidates(dashboard):
    layout = dashboard.sa_pd_pa_candidates_layout
    while layout.count():
        child = layout.takeAt(0)
        widget = child.widget()
        if widget is not None:
            widget.deleteLater()
    dashboard.ui.tableWidget_sa_pd_pa_results_evidence.setRowCount(0)
    dashboard.ui.tableWidget_sa_pd_pa_results_fields_decoded_fields.setRowCount(0)
    dashboard.ui.tableWidget_sa_pd_pa_results_fields_packet_bits.setRowCount(0)
    dashboard.ui.label_sa_pd_pa_results_evidence_details.setText('—')
    dashboard.ui.label_sa_pd_pa_results_fields_details.setText('—')
    dashboard.ui.label_sa_pd_pa_results_candidate_details_title.setText('Selected Candidate:')
    badge = dashboard.ui.label2_sa_pd_pa_results_candidate_details_badge
    badge.setText('—')
    badge.setProperty('paStrength', 'unknown')
    badge.style().unpolish(badge)
    badge.style().polish(badge)

def _pa_show_active(dashboard):
    _pa_clear_candidates(dashboard)
    uid = dashboard.sa_pd_pa_active_uid
    record = next((r for r in dashboard.sa_pd_pa_records if r['uid'] == uid), None)
    if record is None:
        dashboard.ui.label_sa_pd_pa_results_subtitle.setText('Choose a message to inspect')
        return
    dashboard.ui.label_sa_pd_pa_results_subtitle.setText(
        f"{record['source']} · Capture {record['capture']} · {len(record['bits']):,} bits"
    )
    result = dashboard.sa_pd_pa_results.get(uid)
    if result is None:
        dashboard.ui.label_sa_pd_pa_results_evidence_details.setText('Press Analyze Checked to evaluate this message.')
        return
    for i, candidate in enumerate(result['candidates']):
        card = _PACandidateCard(candidate, i == dashboard.sa_pd_pa_candidate_index,
                                lambda ix=i: _pa_select_candidate(dashboard, ix),
                                dashboard.ui.scrollAreaWidgetContents_sa_pd_pa_results_candidates)
        dashboard.sa_pd_pa_candidates_layout.addWidget(card)
    dashboard.sa_pd_pa_candidates_layout.addStretch(1)
    _pa_show_candidate(dashboard)


def _pa_select_candidate(dashboard, index):
    dashboard.sa_pd_pa_candidate_index = index
    _pa_show_active(dashboard)


def _pa_show_candidate(dashboard):
    """Display the active candidate's checks and bit-accurate fields."""
    result = dashboard.sa_pd_pa_results.get(dashboard.sa_pd_pa_active_uid)
    if not result:
        return
    candidates = result['candidates']
    index = max(0, min(dashboard.sa_pd_pa_candidate_index, len(candidates) - 1))
    # Keep callbacks and row selections on the same bounded candidate.
    dashboard.sa_pd_pa_candidate_index = index
    candidate = candidates[index]
    ui = dashboard.ui
    ui.label_sa_pd_pa_results_candidate_details_title.setText(
        str(candidate['protocol']) + ' · ' + str(candidate.get('message_type') or 'Unknown type')
    )
    strength = str(candidate.get('strength') or 'Unknown')
    badge = ui.label2_sa_pd_pa_results_candidate_details_badge
    badge.setText(strength)
    badge.setProperty('paStrength', strength.lower().replace(' ', '_'))
    badge.style().unpolish(badge)
    badge.style().polish(badge)

    table = ui.tableWidget_sa_pd_pa_results_evidence
    checks = candidate['checks']
    blocker = QtCore.QSignalBlocker(table)
    table.setRowCount(len(checks))
    for row, check in enumerate(checks):
        for col, value in enumerate((check['name'], check['expected'], check['observed'], check['outcome'])):
            cell = QtWidgets.QTableWidgetItem(str(value))
            cell.setFlags(cell.flags() & ~QtCore.Qt.ItemIsEditable)
            cell.setToolTip(str(value) + '\n\n' + str(check.get('explanation') or ''))
            if col == 3:
                cell.setTextAlignment(QtCore.Qt.AlignCenter)
            table.setItem(row, col, cell)
    table.clearSelection()
    del blocker
    source = candidate.get('source')
    if source == 'reference_validator':
        guidance = ('Independent profile evidence: known TPMS CRC and pressure-complement '
                    'checks are evaluated with predeclared parameters. Select a row for details.')
    elif source == 'format_definition':
        if strength == 'Rejected':
            guidance = (
                f"Rejected for format {candidate['format_key']} revision "
                f"{candidate['format_revision']}: a required identity check failed. "
                'This is not a protocol identification. Select Identification decision '
                'or the failed check for details.'
            )
        else:
            guidance = (
                f"Library packet format {candidate['format_key']} revision "
                f"{candidate['format_revision']} ({candidate['definition_validation_status']}). "
                'Checks use stored field positions and predeclared validation rules; '
                'select a row for its evidence. No match percentage is inferred.'
            )
    elif source == 'library_layout':
        guidance = ('Structural candidate only. Field widths match a Library layout, but no '
                    'fixed signature or independent checksum has established protocol identity.')
    else:
        guidance = ('Unidentified data. Select an evidence row to inspect the observations; '
                    'exploratory framing and checksum hypotheses are not proof of identity.')
    ui.label_sa_pd_pa_results_evidence_details.setText(guidance)
    if checks:
        table.selectRow(0)
        _pa_evidence_selected(dashboard)
    record = next((p for p in dashboard.sa_pd_pa_records
                   if p['uid'] == dashboard.sa_pd_pa_active_uid), None)
    if record is not None:
        _pa_show_fields(dashboard, record, candidate)


def _pa_evidence_selected(dashboard):
    result = dashboard.sa_pd_pa_results.get(dashboard.sa_pd_pa_active_uid)
    if not result:
        return
    candidate = result['candidates'][dashboard.sa_pd_pa_candidate_index]
    row = dashboard.ui.tableWidget_sa_pd_pa_results_evidence.currentRow()
    if 0 <= row < len(candidate['checks']):
        check = candidate['checks'][row]
        dashboard.ui.label_sa_pd_pa_results_evidence_details.setText(
            f"{check['name']} · {check['outcome']}\n"
            f"Expected: {check['expected']}    Observed: {check['observed']}\n"
            f"{check.get('explanation') or ''}"
        )

def _pa_show_fields(dashboard, record, candidate):
    """Render exact bit positions and corresponding, color-linked field rows."""
    from PyQt5 import QtGui

    ui = dashboard.ui
    bits = record['bits']
    fields = candidate.get('fields') or []
    view = ui.tableWidget_sa_pd_pa_results_fields_packet_bits
    blocker = QtCore.QSignalBlocker(view)
    visible = min(_PA_DISPLAY_BITS, len(bits))
    view.setRowCount(1)
    view.setColumnCount(visible)
    view.horizontalHeader().setStretchLastSection(False)
    view.setHorizontalHeaderLabels(
        [str(i) if i == 0 or i % 8 == 0 else '' for i in range(visible)]
    )
    palette = ((82, 151, 230), (61, 181, 119), (229, 178, 61),
               (189, 126, 228), (80, 191, 198), (228, 120, 120))
    color_for_bit = {}
    for field_index, field in enumerate(fields):
        start = max(0, int(field['start']))
        stop = min(visible, start + max(0, int(field['length'])))
        for bit_index in range(start, stop):
            color_for_bit[bit_index] = palette[field_index % len(palette)]
    for i in range(visible):
        item = QtWidgets.QTableWidgetItem(str(int(bits[i])))
        item.setTextAlignment(QtCore.Qt.AlignCenter)
        item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
        if i in color_for_bit and candidate.get('source') != 'unknown':
            item.setBackground(QtGui.QColor(*color_for_bit[i], 65))
        item.setToolTip(f'Bit {i} (zero-based)')
        view.setItem(0, i, item)
        header = view.horizontalHeaderItem(i)
        if header is not None:
            header.setToolTip(f'Bit {i} (zero-based)')
    view.setRowHeight(0, 21)
    view.clearSelection()
    del blocker

    table = ui.tableWidget_sa_pd_pa_results_fields_decoded_fields
    blocker = QtCore.QSignalBlocker(table)
    table.setRowCount(len(fields))
    for row, field in enumerate(fields):
        start = max(0, int(field['start']))
        end = min(len(bits), start + max(0, int(field['length'])))
        raw = bits[start:end]
        binary = ''.join(str(int(value)) for value in raw[:128])
        if len(raw) > 128:
            binary += '…'
        hexadecimal = (format_bits_hex(raw[:128]) + ('…' if len(raw) > 128 else '')
                       if len(raw) else '—')
        values = (str(field['name']), str(start), str(len(raw)), binary,
                  hexadecimal, str(field['value']) if field.get('value') is not None else '—',
                  str(field.get('meaning') or '—'))
        for column, value in enumerate(values):
            cell = QtWidgets.QTableWidgetItem(value)
            cell.setFlags(cell.flags() & ~QtCore.Qt.ItemIsEditable)
            cell.setToolTip(f'Bits [{start}, {end}) (end exclusive). {field.get("meaning") or ""}')
            if column in (1, 2, 4):
                cell.setTextAlignment(QtCore.Qt.AlignCenter)
            if candidate.get('source') != 'unknown':
                cell.setBackground(QtGui.QColor(*palette[row % len(palette)],
                                                110 if column == 0 else 28))
            table.setItem(row, column, cell)
    table.clearSelection()
    del blocker
    state = ('Profile checks passed' if candidate.get('verified') else
             'Tentative layout, not a verified identity')
    ui.label_sa_pd_pa_results_fields_details.setText(
        f'{len(bits):,} source bits, zero-based positions. {state}. '
        + (f'First {visible:,} bits shown. ' if len(bits) > visible else '')
        + 'Hex values represent the numeric field value, including non-nibble-aligned fields.'
    )
    if fields:
        table.selectRow(0)
        _pa_field_selected(dashboard)

def _pa_field_selected(dashboard):
    result = dashboard.sa_pd_pa_results.get(dashboard.sa_pd_pa_active_uid)
    if not result:
        return
    candidate = result['candidates'][dashboard.sa_pd_pa_candidate_index]
    fields = candidate.get('fields', [])
    row = dashboard.ui.tableWidget_sa_pd_pa_results_fields_decoded_fields.currentRow()
    if not 0 <= row < len(fields):
        return
    field = fields[row]
    begin = int(field['start'])
    end = begin + int(field['length'])
    ui = dashboard.ui
    view = ui.tableWidget_sa_pd_pa_results_fields_packet_bits
    blocker = QtCore.QSignalBlocker(view)
    view.clearSelection()
    if begin < view.columnCount() and end > begin:
        limit = min(end, view.columnCount())
        select = QtWidgets.QTableWidgetSelectionRange(0, begin, 0, limit - 1)
        view.setRangeSelected(select, True)
        view.scrollToItem(view.item(0, begin))
    del blocker
    raw = next((p['bits'][begin:end] for p in dashboard.sa_pd_pa_records
                if p['uid'] == dashboard.sa_pd_pa_active_uid), [])
    raw_hex = format_bits_hex(raw) if len(raw) else '—'
    decoded = field['value'] if field.get('value') is not None else '—'
    note = 'Verified profile' if candidate.get('verified') else 'Tentative field layout'
    ui.label_sa_pd_pa_results_fields_details.setText(
        f"{field['name']} · bits [{begin}, {end}) · {len(raw)} bits · {note}\n"
        f"Raw hex: 0x{raw_hex}    Decoded: {decoded}\n"
        f"{field.get('meaning') or 'No interpretation available.'}"
    )


__all__ = [
    name
    for name, value in globals().items()
    if inspect.isfunction(value) and value.__module__ == __name__
]
