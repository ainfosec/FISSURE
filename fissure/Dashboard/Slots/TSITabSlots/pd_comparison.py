"""Signal Analysis / Protocol Discovery / Comparison workspace.

Exact bit strings are the authoritative message data; editor text and table
previews are presentations only. No RF hardware, hub messages, or writes to the
Library/SOI are performed here. All positions are MSB-first and zero-based.

Integration: import * from this module in TSITabSlots/__init__.py. Call
initialize_sa_pd_comparison_controls() to configure widgets; connect ALL Qt
signals in Frontend.connect_pd_slots(), using the public sa_pd_comparison_*
functions below. This module performs no signal wiring.
"""

import html
import inspect
import re

from PyQt5 import QtCore, QtGui, QtWidgets

import fissure.utils.library
from fissure.utils.protocol_packet_formats import get_cached_packet_formats


_MAX_EDITOR_BITS = 32768
_MAX_PREVIEW_BITS = 2048
_MAX_MESSAGES = 500
_FILL_OPTIONS = (("Missing position", None), ("0", "0"), ("1", "1"))
_DIFFERENCE_BG = QtGui.QColor(250, 208, 208)
_MISSING_BG = QtGui.QColor(220, 225, 230)


def _editor(dashboard, representation):
    return getattr(dashboard.ui, "plainTextEdit_sa_pd_comparison_editor_" + representation)


def _bits_from_source(bits):
    """Convert numpy bit arrays or a bit string without changing length."""
    if isinstance(bits, str):
        value = bits
    else:
        value = "".join(str(int(bit)) for bit in bits)
    if not value or set(value) - {"0", "1"}:
        raise ValueError("A message must contain binary digits (0 or 1).")
    return value


def _hex_view(bits):
    """Wireshark-style hex dump: byte pairs, two eight-byte groups per row.

    Offsets are explicitly suffixed with ':' so they can be stripped safely
    when the user edits or pastes this text back into the live hex editor.
    A short trailing bit fragment is never padded or dropped.
    """
    whole = len(bits) // 8 * 8
    octets = [f"{int(bits[pos:pos + 8], 2):02X}" for pos in range(0, whole, 8)]
    lines = []
    for offset in range(0, len(octets), 16):
        line = octets[offset:offset + 16]
        left = " ".join(line[:8])
        right = " ".join(line[8:])
        lines.append(f"{offset:04X}:  {left}" + (f"  {right}" if right else ""))
    trailing = bits[whole:]
    if trailing:
        fragment = f"[bits:{trailing}]"
        if lines:
            lines[-1] += "  " + fragment
        else:
            lines.append(fragment)
    return "\n".join(lines)


def _ascii_view(bits):
    whole = len(bits) // 8 * 8
    rendered = []
    for i in range(0, whole, 8):
        val = int(bits[i:i + 8], 2)
        if val == 92:
            rendered.append("\\\\")
        elif val == 91:
            rendered.append("\\x5B")  # Reserve [bits:...] for exact partial-byte suffixes.
        elif 32 <= val <= 126:
            rendered.append(chr(val))
        else:
            rendered.append(f"\\x{val:02X}")
    return "".join(rendered) + (f"[bits:{bits[whole:]}]" if whole < len(bits) else "")


def _parse_editor(text, mode):
    """Parse freely pasted text or the formatted hex dump without bit loss.

    Hex accepts plain digit runs, spaced pairs, or lines beginning with an
    offset like '0010:'. A [bits:101] suffix preserves partial bytes.
    """
    if not text or (mode != "ascii" and not text.strip()):
        return ""
    if mode == "binary":
        value = re.sub(r"\s", "", text)
        if value.lower().startswith("0b"):
            value = value[2:]
        if not re.fullmatch(r"[01]+", value):
            raise ValueError("Binary accepts only 0, 1, and whitespace.")
        return value

    suffix_match = re.search(r"\[bits:([01]{1,7})\]\s*$", text)
    suffix = suffix_match.group(1) if suffix_match else ""
    base = text[:suffix_match.start()] if suffix_match else text
    if mode == "hex":
        # Only explicit '0000:'-style prefixes are considered dump offsets.
        # Raw hex without an offset stays raw data, even when multiline.
        offset = re.compile(r"^[ \t]*[0-9A-Fa-f]{4,8}:[ \t]*")
        lines = [line for line in base.splitlines() if line.strip()]
        if any(offset.match(line) for line in lines):
            if not all(offset.match(line) for line in lines):
                raise ValueError("Every line of an offset hex dump needs an offset.")
            base = "\n".join(offset.sub("", line, count=1) for line in lines)
        value = re.sub(r"[\s_:,]", "", base)
        if value.lower().startswith("0x"):
            value = value[2:]
        if not re.fullmatch(r"[0-9a-fA-F]*", value):
            raise ValueError("Hex accepts 0–9/A–F and optional '0000:' offsets; "
                             "use [bits:101] for incomplete bytes.")
        return "".join(f"{int(char, 16):04b}" for char in value) + suffix

    # The ASCII editor represents raw 8-bit bytes, not Unicode text.
    result = []
    i = 0
    while i < len(base):
        if base[i] == "\\":
            if i + 1 >= len(base):
                raise ValueError("Incomplete ASCII escape.")
            if base[i + 1] == "\\":
                val, skip = 92, 2
            elif base[i + 1] == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", base[i + 2:i + 4]):
                val, skip = int(base[i + 2:i + 4], 16), 4
            else:
                raise ValueError("Use \\\\ or \\xNN to encode escaped ASCII bytes.")
            i += skip
        else:
            val = ord(base[i])
            if val > 255:
                raise ValueError("ASCII view supports byte values 0–255, not Unicode text.")
            i += 1
        result.append(f"{val:08b}")
    return "".join(result) + suffix


def _set_editor(dashboard, bits, *, loaded_uid=None):
    dashboard.sa_pd_comparison_editing_uid = loaded_uid
    dashboard.sa_pd_comparison_active_editor = None
    dashboard.sa_pd_comparison_editor_bits = bits
    dashboard.sa_pd_comparison_editor_invalid = False
    ui = dashboard.ui
    if len(bits) > _MAX_EDITOR_BITS:
        dashboard.sa_pd_comparison_editor_truncated = True
        # Never show a truncated message as if it were safe to commit.
        for mode in ("binary", "hex", "ascii"):
            widget = _editor(dashboard, mode)
            blocker = QtCore.QSignalBlocker(widget)
            widget.setPlainText("Message too large for editor; original remains in collection.")
            widget.setReadOnly(True)
            del blocker
    else:
        dashboard.sa_pd_comparison_editor_truncated = False
        contents = {"binary": " ".join(bits[i:i + 8] for i in range(0, len(bits), 8)),
                    "hex": _hex_view(bits), "ascii": _ascii_view(bits)}
        for mode, text in contents.items():
            widget = _editor(dashboard, mode)
            blocker = QtCore.QSignalBlocker(widget)
            widget.setReadOnly(False)
            widget.setPlainText(text)
            del blocker
    _update_editor_counts(dashboard)


def _update_editor_counts(dashboard):
    bits = dashboard.sa_pd_comparison_editor_bits
    ui = dashboard.ui
    if getattr(dashboard, "sa_pd_comparison_editor_invalid", False):
        ui.label_sa_pd_comparison_editor_binary_bits.setText("Incomplete/invalid input")
    else:
        ui.label_sa_pd_comparison_editor_binary_bits.setText(f"{len(bits):,} bits")
    ui.label_sa_pd_comparison_editor_hex_bytes.setText(
        f"{len(bits) // 8:,} bytes" + (f" + {len(bits) % 8} bits" if len(bits) % 8 else ""))
    ui.label_sa_pd_comparison_editor_ascii_chars.setText(f"{len(bits) // 8:,} chars")
    valid = bool(bits) and not dashboard.sa_pd_comparison_editor_invalid and not dashboard.sa_pd_comparison_editor_truncated
    ui.pushButton_sa_pd_comparison_editor_add_to_comparison.setEnabled(valid)
    ui.pushButton_sa_pd_comparison_editor_update_selected.setEnabled(
        valid and dashboard.sa_pd_comparison_editing_uid is not None)


def _editor_changed(dashboard, mode):
    if getattr(dashboard, "sa_pd_comparison_editor_truncated", False):
        return
    dashboard.sa_pd_comparison_active_editor = mode
    try:
        bits = _parse_editor(_editor(dashboard, mode).toPlainText(), mode)
        if len(bits) > _MAX_EDITOR_BITS:
            raise ValueError(f"Editor limit: {_MAX_EDITOR_BITS:,} bits")
    except ValueError:
        dashboard.sa_pd_comparison_editor_invalid = True
        _update_editor_counts(dashboard)
        return
    dashboard.sa_pd_comparison_editor_invalid = False
    dashboard.sa_pd_comparison_editor_bits = bits
    text = {"binary": " ".join(bits[i:i + 8] for i in range(0, len(bits), 8)),
            "hex": _hex_view(bits), "ascii": _ascii_view(bits)}
    for other in ("binary", "hex", "ascii"):
        if other == mode:
            continue  # Never rewrite the active editor (caret, selection, partial input).
        target = _editor(dashboard, other)
        blocker = QtCore.QSignalBlocker(target)
        target.setPlainText(text[other])
        del blocker
    _update_editor_counts(dashboard)


def _editor_action(dashboard, action):
    if dashboard.sa_pd_comparison_editor_invalid or dashboard.sa_pd_comparison_editor_truncated:
        return
    bits = dashboard.sa_pd_comparison_editor_bits
    if not bits:
        return
    if action == "invert":
        output = "".join("1" if c == "0" else "0" for c in bits)
    elif action == "differential":
        # Preserve original legacy semantics: adjacent XOR, discarding first bit.
        output = "".join(str(int(a != b)) for a, b in zip(bits, bits[1:]))
    elif action.startswith("undiff"):
        prior = action[-1]
        output = [prior]
        for bit in bits:
            prior = str(int(prior != bit))
            output.append(prior)
        output = "".join(output)
    elif action == "manchester_encode":
        output = "".join("01" if c == "0" else "10" for c in bits)
    elif action == "manchester_decode":
        if len(bits) % 2 or any(bits[i:i + 2] not in ("01", "10")
                                for i in range(0, len(bits), 2)):
            QtWidgets.QMessageBox.warning(dashboard, "Manchester Decode",
                                          "Expected even-length 01/10 symbol pairs. Data unchanged.")
            return
        output = "".join("0" if bits[i:i + 2] == "01" else "1"
                         for i in range(0, len(bits), 2))
    else:
        return
    if not output or len(output) > _MAX_EDITOR_BITS:
        QtWidgets.QMessageBox.warning(dashboard, "Message Editor", "Result exceeds editor limit or is empty.")
        return
    _set_editor(dashboard, output, loaded_uid=dashboard.sa_pd_comparison_editing_uid)


def _copy_editor(dashboard, mode):
    if dashboard.sa_pd_comparison_editor_truncated:
        bits = dashboard.sa_pd_comparison_editor_bits
        value = {"binary": bits, "hex": _hex_view(bits), "ascii": _ascii_view(bits)}[mode]
    else:
        value = _editor(dashboard, mode).toPlainText()
    QtWidgets.QApplication.clipboard().setText(value)


def _new_record(dashboard, bits, *, source="Manual", capture=None, notes="", metadata=None, framing=None):
    uid = dashboard.sa_pd_comparison_next_uid
    dashboard.sa_pd_comparison_next_uid += 1
    return {"uid": uid, "bits": bits, "source": str(source), "capture": capture,
            "notes": notes, "metadata": dict(metadata or {}),
            "framing": dict(framing or {}),
            "lead": 0, "tail": 0, "lead_fill": None, "tail_fill": None}


def _record_by_uid(dashboard, uid):
    return next((r for r in dashboard.sa_pd_comparison_records if r["uid"] == uid), None)


def _collection_selected(dashboard):
    """UIDs of highlighted rows; comparison inclusion has no checkboxes."""
    table = dashboard.ui.tableWidget_sa_pd_comparison_collection
    model = table.selectionModel()
    if model is None:
        return set()
    selected = set()
    for index in model.selectedRows():
        item = table.item(index.row(), 0)
        if item is not None:
            selected.add(item.data(QtCore.Qt.UserRole))
    return selected


def _aligned_bits(record):
    """Return comparison positions, with None representing unavailable bits.

    Negative adjustments trim only the comparison representation; positive
    ones insert either a specified filler bit or a missing position.
    """
    bits = list(record["bits"])
    left, right = record["lead"], record["tail"]
    if left < 0:
        bits = bits[min(-left, len(bits)):]
    if right < 0:
        bits = bits[:max(0, len(bits) + right)]
    return ([record["lead_fill"]] * max(0, left)
            + bits + [record["tail_fill"]] * max(0, right))


def _comparison_rows(dashboard):
    checked = dashboard.sa_pd_comparison_active_uids
    records = [r for r in dashboard.sa_pd_comparison_records if r["uid"] in checked]
    if not records:
        return [], {}, 0
    vectors = {r["uid"]: _aligned_bits(r) for r in records}
    width = max(len(vector) for vector in vectors.values())
    right_align = dashboard.ui.comboBox_sa_pd_comparison_collection_alignment.currentText() == "Right"
    for uid, vector in vectors.items():
        missing = [None] * (width - len(vector))
        vectors[uid] = missing + vector if right_align else vector + missing
    return records, vectors, width


def _difference_positions(records, vectors, width):
    differing, missing = set(), set()
    if len(records) < 2:
        return differing, missing
    for position in range(width):
        values = {vectors[r["uid"]][position] for r in records}
        observed = values - {None}
        if len(observed) > 1:
            differing.add(position)
        if None in values:
            missing.add(position)
    return differing, missing


def _render_preview(bits, vector, different, missing, group_size):
    """Color compared differences red and only this row's missing data gray."""
    max_len = min(len(vector), _MAX_PREVIEW_BITS)
    pieces = []
    for begin in range(0, max_len, group_size):
        block = vector[begin:begin + group_size]
        if all(bit is None for bit in block):
            value = "—"
        elif group_size == 1:
            value = block[0] if block[0] is not None else "—"
        elif None in block:
            value = "".join(bit if bit is not None else "·" for bit in block)
        elif group_size == 4:
            value = f"{int(''.join(block), 2):X}" if len(block) == 4 else "".join(block)
        else:
            value = f"{int(''.join(block), 2):02X}" if len(block) == 8 else "".join(block)
        different_here = any(position in different for position in range(begin, begin + len(block)))
        # Missing only applies to the row with absent bits, not to every row
        # sharing that position in the comparison.
        missing_here = any(bit is None for bit in block)
        color = ("background-color:#DCE1E6;color:#202020;" if missing_here else
                 "background-color:#FAD0D0;color:#202020;" if different_here else "")
        pieces.append(f'<span style="{color}">{html.escape(value)}</span>')
    if len(vector) > max_len:
        pieces.append("…")
    return '<span style="font-family:monospace;white-space:pre">' + " ".join(pieces) + '</span>'


class _PreviewDelegate(QtWidgets.QStyledItemDelegate):
    """Paint preview HTML using legible text in both light and dark themes.

    The HTML snippets generated by _render_preview supply their own colors
    for differences and missing bits. Only ordinary preview text is adapted
    to the table background or its blue row-selection highlight.
    """
    def paint(self, painter, option, index):
        item_html = index.data(QtCore.Qt.UserRole + 1)
        if item_html is None:
            super().paint(painter, option, index)
            return

        style = option.widget.style() if option.widget else QtWidgets.QApplication.style()
        opt = QtWidgets.QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ""
        style.drawControl(QtWidgets.QStyle.CE_ItemViewItem, opt, painter, option.widget)

        # QTextDocument does not reliably inherit the QTableWidget stylesheet
        # foreground, so explicitly set it for this Preview column only.
        # Keep selected-row text legible against the blue highlight.
        if opt.state & QtWidgets.QStyle.State_Selected:
            normal_color = QtGui.QColor("#FFFFFF")
        elif opt.palette.color(QtGui.QPalette.Base).lightness() < 128:
            normal_color = QtGui.QColor("#E0E6ED")
        else:
            normal_color = opt.palette.color(QtGui.QPalette.Text)

        document = QtGui.QTextDocument()
        document.setDocumentMargin(0)
        document.setDefaultFont(opt.font)
        document.setHtml(
            f'<span style="color:{normal_color.name()};">{item_html}</span>'
        )
        painter.save()
        painter.setClipRect(option.rect)
        painter.translate(option.rect.x() + 4, option.rect.y() + 2)
        document.drawContents(painter)
        painter.restore()


class _FieldHighlightDelegate(QtWidgets.QStyledItemDelegate):
    """Preserve different/missing field colors when their row is selected.

    Ordinary cells use Qt's standard blue row-selection appearance. Only
    fields explicitly colored by the comparison keep their own background
    and foreground, so a selected mismatch stays red and a gap stays gray.
    """
    def paint(self, painter, option, index):
        brush = index.data(QtCore.Qt.BackgroundRole)
        is_comparison_highlight = (
            isinstance(brush, QtGui.QBrush)
            and brush.style() != QtCore.Qt.NoBrush
            and brush.color() in (_DIFFERENCE_BG, _MISSING_BG)
        )
        if is_comparison_highlight and option.state & QtWidgets.QStyle.State_Selected:
            unselected = QtWidgets.QStyleOptionViewItem(option)
            unselected.state &= ~QtWidgets.QStyle.State_Selected
            super().paint(painter, unselected, index)
            return
        super().paint(painter, option, index)


def _update_collection(dashboard, selected_uids=None):
    """Rebuild collection rows without discarding current multi-row selection."""
    table = dashboard.ui.tableWidget_sa_pd_comparison_collection
    selected = (_collection_selected(dashboard) if selected_uids is None
                else set(selected_uids))
    records = dashboard.sa_pd_comparison_records
    active = dashboard.sa_pd_comparison_active_uids
    rows, vectors, width = _comparison_rows(dashboard)
    different, _missing = _difference_positions(rows, vectors, width)
    group_size = {0: 1, 1: 4, 2: 8}.get(
        dashboard.ui.comboBox_sa_pd_comparison_collection_group.currentIndex(), 8)
    unit = {1: "Bits", 4: "Nibbles", 8: "Hex"}[group_size]
    blocker = QtCore.QSignalBlocker(table)
    table.setRowCount(len(records))
    table.setHorizontalHeaderItem(4, QtWidgets.QTableWidgetItem(f"Preview ({unit})"))
    longest_preview = 0
    valid_selection = set()
    for row, record in enumerate(records):
        uid = record["uid"]
        if uid in selected:
            valid_selection.add(uid)
        source = record["source"]
        if record.get("capture") is not None:
            source += f" (#{record['capture']})"
        note = record["notes"]
        adjustments = []
        for side in ("lead", "tail"):
            count = record[side]
            if count:
                pad = record[side + "_fill"]
                adjustments.append(f"{side} {count:+d}" +
                                   (f" ({pad if pad is not None else 'missing'})"
                                    if count > 0 else ""))
        if adjustments:
            note = (note + "; " if note else "") + ", ".join(adjustments)
        values = (str(row + 1), source, str(len(record["bits"])), note, "")
        for col, text in enumerate(values):
            item = QtWidgets.QTableWidgetItem(text)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
            item.setData(QtCore.Qt.UserRole, uid)
            if col in (0, 2):
                item.setTextAlignment(QtCore.Qt.AlignCenter)
            if col == 4:
                vector = vectors.get(uid, list(record["bits"]))
                longest_preview = max(longest_preview, min(len(vector), _MAX_PREVIEW_BITS))
                item.setData(QtCore.Qt.UserRole + 1,
                             _render_preview(record["bits"], vector,
                                             different if uid in active else set(),
                                             set(), group_size))
                item.setToolTip(_hex_view(record["bits"][:4096]) +
                                (" …" if len(record["bits"]) > 4096 else "") +
                                f"\nOriginal length: {len(record['bits']):,} bits")
            else:
                item.setToolTip(str(text))
            table.setItem(row, col, item)

    # Restore selected ROWS by UID, not by visual position. Sorting is disabled.
    selection = table.selectionModel()
    selection.clearSelection()
    flags = (QtCore.QItemSelectionModel.Select | QtCore.QItemSelectionModel.Rows)
    for row, record in enumerate(records):
        if record["uid"] in valid_selection:
            selection.select(table.model().index(row, 0), flags)
    del blocker

    # The last column is allowed to run beyond the viewport; the horizontal
    # scrollbar can reach the end of each message without truncating it.
    groups = (longest_preview + group_size - 1) // group_size
    sample = ("FF " if group_size == 8 else "F " if group_size == 4 else "1 ")
    fixed_font = QtGui.QFont("Ubuntu Mono", 9)
    fixed_font.setStyleHint(QtGui.QFont.Monospace)
    metrics = QtGui.QFontMetrics(fixed_font)
    wanted = metrics.horizontalAdvance(sample * groups) + 28
    available = table.viewport().width() - sum(table.columnWidth(c) for c in range(4)) - 8
    table.setColumnWidth(4, min(60000, max(250, available, wanted)))
    _update_buttons(dashboard)


def _update_buttons(dashboard):
    ui = dashboard.ui
    count = len(dashboard.sa_pd_comparison_records)
    selected = _collection_selected(dashboard)
    ui.pushButton_sa_pd_comparison_collection_compare_selected.setEnabled(len(selected) >= 2)
    ui.pushButton_sa_pd_comparison_collection_clear_all.setEnabled(count > 0)
    ui.pushButton_sa_pd_comparison_collection_remove_selected.setEnabled(bool(selected))


def _invalidate_comparison(dashboard):
    dashboard.sa_pd_comparison_active_uids = set()
    dashboard.sa_pd_comparison_applied = False
    dashboard.ui.tableWidget_sa_pd_comparison_results.setRowCount(0)
    dashboard.ui.plainTextEdit_sa_pd_comparison_results.setPlainText(
        "Select a Library protocol and packet type, then Apply to compare fields.")


def _editor_entries(dashboard):
    """Recognize a formatted hex dump as one message; plain lines as batches."""
    mode = dashboard.sa_pd_comparison_active_editor
    if mode in ("binary", "hex"):
        source = _editor(dashboard, mode).toPlainText()
        lines = [line for line in source.splitlines() if line.strip()]
        dump_offsets = mode == "hex" and any(
            re.match(r"^[ \t]*[0-9A-Fa-f]{4,8}:", line) for line in lines)
        if len(lines) > 1 and not dump_offsets:
            return [_parse_editor(line, mode) for line in lines]
    return [dashboard.sa_pd_comparison_editor_bits]


def _add_from_editor(dashboard):
    if dashboard.sa_pd_comparison_editor_invalid or dashboard.sa_pd_comparison_editor_truncated:
        QtWidgets.QMessageBox.warning(dashboard, "Comparison", "Enter complete message data first.")
        return
    try:
        entries = _editor_entries(dashboard)
    except ValueError as exc:
        QtWidgets.QMessageBox.warning(dashboard, "Comparison", str(exc))
        return
    if not entries or any(not bits for bits in entries):
        return
    if len(dashboard.sa_pd_comparison_records) + len(entries) > _MAX_MESSAGES:
        QtWidgets.QMessageBox.warning(dashboard, "Comparison", "Message collection limit reached.")
        return
    original = _record_by_uid(dashboard, dashboard.sa_pd_comparison_editing_uid)
    source = (original["source"] + " (edited copy)") if original else "Manual"
    new_records = [
        _new_record(dashboard, bits, source=source,
                    metadata=original["metadata"] if original else None,
                    framing=original["framing"] if original else None,
                    notes="Edited copy" if original else "")
        for bits in entries
    ]
    dashboard.sa_pd_comparison_records.extend(new_records)
    _invalidate_comparison(dashboard)
    _update_collection(dashboard, selected_uids={r["uid"] for r in new_records})
    if len(new_records) == 1:
        _set_editor(dashboard, entries[0], loaded_uid=new_records[0]["uid"])


def _update_from_editor(dashboard):
    uid = dashboard.sa_pd_comparison_editing_uid
    record = _record_by_uid(dashboard, uid)
    if record is None or dashboard.sa_pd_comparison_editor_invalid or dashboard.sa_pd_comparison_editor_truncated:
        return
    if not dashboard.sa_pd_comparison_editor_bits:
        return
    try:
        entries = _editor_entries(dashboard)
    except ValueError as exc:
        QtWidgets.QMessageBox.warning(dashboard, "Update Selected", str(exc))
        return
    if len(entries) != 1:
        QtWidgets.QMessageBox.warning(dashboard, "Update Selected",
                                      "Update Selected accepts one message. Use Add to Comparison "
                                      "to add multiple pasted lines as separate messages.")
        return
    record["bits"] = entries[0]
    record["notes"] = ((record["notes"] + "; ") if record["notes"] else "") + "Edited"
    record.update(lead=0, tail=0, lead_fill=None, tail_fill=None)
    _invalidate_comparison(dashboard)
    _update_collection(dashboard)


def _load_row(dashboard, row):
    table = dashboard.ui.tableWidget_sa_pd_comparison_collection
    item = table.item(row, 0)
    if item is None:
        return
    record = _record_by_uid(dashboard, item.data(QtCore.Qt.UserRole))
    if record:
        _set_editor(dashboard, record["bits"], loaded_uid=record["uid"])


def _remove_selected(dashboard):
    checked = _collection_checked(dashboard)
    if not checked:
        return
    dashboard.sa_pd_comparison_records = [r for r in dashboard.sa_pd_comparison_records if r["uid"] not in checked]
    if dashboard.sa_pd_comparison_editing_uid in checked:
        _set_editor(dashboard, "")
    _invalidate_comparison(dashboard)
    _update_collection(dashboard)


def _clear_all(dashboard):
    if not dashboard.sa_pd_comparison_records:
        return
    if QtWidgets.QMessageBox.question(dashboard, "Clear Message Collection",
            "Remove all messages from the comparison workspace?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
            QtWidgets.QMessageBox.No) != QtWidgets.QMessageBox.Yes:
        return
    dashboard.sa_pd_comparison_records.clear()
    _set_editor(dashboard, "")
    _invalidate_comparison(dashboard)
    _update_collection(dashboard)


def _collection_menu(dashboard, position):
    table = dashboard.ui.tableWidget_sa_pd_comparison_collection
    item = table.itemAt(position)
    if item is None:
        return
    record = _record_by_uid(dashboard, table.item(item.row(), 0).data(QtCore.Qt.UserRole))
    if record is None:
        return
    menu = QtWidgets.QMenu(table)
    menu.addAction("Load in Message Editor", lambda: _load_row(dashboard, item.row()))
    menu.addSeparator()
    for side, title in (("lead", "Leading"), ("tail", "Trailing")):
        sub = menu.addMenu(title + " adjustment")
        for text, fill in _FILL_OPTIONS:
            sub.addAction("Insert " + text + " position", lambda _=False, s=side, f=fill:
                          _adjust_record(dashboard, record, s, 1, f))
        sub.addAction("Exclude one original bit from comparison", lambda _=False, s=side:
                      _adjust_record(dashboard, record, s, -1, None))
    menu.addSeparator()
    menu.addAction("Reset This Message's Alignment", lambda: _reset_record(dashboard, record))
    menu.exec_(table.viewport().mapToGlobal(position))


def _adjust_record(dashboard, record, side, delta, fill):
    value = record[side]
    if delta > 0:
        # Start a new filler run rather than silently mixing 0/1/missing fillers.
        if value > 0 and record[side + "_fill"] != fill:
            value = 0
        record[side] = min(value + 1, 256)
        record[side + "_fill"] = fill
    else:
        record[side] = max(value - 1, -min(256, len(record["bits"])))
    _invalidate_comparison(dashboard)
    _update_collection(dashboard)


def _reset_record(dashboard, record):
    record.update(lead=0, tail=0, lead_fill=None, tail_fill=None)
    _invalidate_comparison(dashboard)
    _update_collection(dashboard)


def _compare_selected(dashboard):
    selected = _collection_selected(dashboard)
    if len(selected) < 2:
        QtWidgets.QMessageBox.information(
            dashboard, "Compare Messages", "Highlight at least two message rows (Ctrl/Shift-click).")
        return
    dashboard.sa_pd_comparison_active_uids = set(selected)
    _update_collection(dashboard)
    if dashboard.ui.comboBox_sa_pd_comparison_results_packet_type.currentText():
        _apply_library(dashboard)
    else:
        _set_library_status(dashboard)


def _protocol_changed(dashboard):
    ui = dashboard.ui
    protocol = ui.comboBox_sa_pd_comparison_results_protocol.currentText()
    packet_combo = ui.comboBox_sa_pd_comparison_results_packet_type
    blocker = QtCore.QSignalBlocker(packet_combo)
    packet_combo.clear()
    if protocol:
        library = dashboard.backend.library
        names = fissure.utils.library.getPacketTypes(library, protocol)
        names += [record["format_name"] for record in dashboard.sa_pd_comparison_formats
                  if record["protocol_name"] == protocol]
        packet_combo.addItem("")
        packet_combo.addItems(sorted(set(names)))
    del blocker
    dashboard.sa_pd_comparison_applied = False
    _set_library_status(dashboard)


def _set_library_status(dashboard):
    ui = dashboard.ui
    protocol = ui.comboBox_sa_pd_comparison_results_protocol.currentText()
    packet = ui.comboBox_sa_pd_comparison_results_packet_type.currentText()
    if not protocol or not packet:
        ui.plainTextEdit_sa_pd_comparison_results.setPlainText(
            "Choose a Library protocol and packet type to interpret the compared messages.")
    else:
        ui.plainTextEdit_sa_pd_comparison_results.setPlainText(
            "Click Apply to interpret the last compared message set using this Library field layout. "
            "A matching layout does not establish protocol identity.")
    ui.tableWidget_sa_pd_comparison_results.setRowCount(0)
    ui.pushButton_sa_pd_comparison_results_apply.setEnabled(bool(protocol and packet))
    _reflow_library(dashboard)


def _reflow_library(dashboard):
    """Collapse only the field-results body, never its protocol selectors.

    These Designer frames use absolute coordinates. In collapsed mode, the
    collection expands downward and the Library *header and controls* move to
    the bottom; selecting a definition restores the Library table/detail body.
    """
    ui = dashboard.ui
    collection = ui.frame_sa_pd_comparison_collection
    result = ui.frame_sa_pd_comparison_results
    expanded = bool(ui.comboBox_sa_pd_comparison_results_protocol.currentText() and
                    ui.comboBox_sa_pd_comparison_results_packet_type.currentText())
    original = dashboard.sa_pd_comparison_geometry
    # Keep enough of the Library frame visible for title, subtitle, selectors and Apply.
    collapsed_height = 90
    gain = 0 if expanded else original["results"].height() - collapsed_height
    original_collection = original["frame"]
    original_results = original["results"]
    collection.setGeometry(original_collection.x(), original_collection.y(),
                           original_collection.width(), original_collection.height() + gain)
    table = ui.tableWidget_sa_pd_comparison_collection
    geo = original["table"]
    table.setGeometry(geo.x(), geo.y(), geo.width(), geo.height() + gain)
    for widget, rect in original["controls"]:
        widget.setGeometry(rect.translated(0, gain))
    result.setGeometry(original_results.x(), original_results.y() + gain,
                       original_results.width(), original_results.height() - gain)
    ui.tableWidget_sa_pd_comparison_results.setVisible(expanded)
    ui.plainTextEdit_sa_pd_comparison_results.setVisible(expanded)


def _library_fields(dashboard, protocol, packet):
    """Prefer an enabled declarative packet format; fall back to legacy field lengths."""
    formats = [row for row in dashboard.sa_pd_comparison_formats
               if row["protocol_name"] == protocol and row["format_name"] == packet]
    if formats:
        row = max(formats, key=lambda item: int(item["revision"]))
        definition = row["definition"]
        return list(definition["fields"]), ("format", row)
    names = fissure.utils.library.getFields(dashboard.backend.library, protocol, packet)
    fields = []
    offset = 0
    for name in names:
        width = int(fissure.utils.library.getFieldData(dashboard.backend.library,
                                                       protocol, packet, name)["Length"])
        if width <= 0:
            raise ValueError("Field lengths must be positive integers.")
        fields.append({"name": name, "start": offset, "length": width})
        offset += width
    return fields, ("legacy", None)


def _field_bits(vector, field):
    if "from_end_bits" in field:
        start = len(vector) - int(field["from_end_bits"])
    else:
        start = int(field["start"])
    width = int(field["length"])
    if start < 0 or start + width > len(vector):
        return start, None
    value = vector[start:start + width]
    return start, value if all(c is not None for c in value) else None


def _format_field_bits(bits):
    if bits is None:
        return "—"
    return f"0x{int(''.join(bits), 2):0{(len(bits) + 3) // 4}X}" if bits else "—"


def _apply_library(dashboard):
    ui = dashboard.ui
    protocol = ui.comboBox_sa_pd_comparison_results_protocol.currentText()
    packet = ui.comboBox_sa_pd_comparison_results_packet_type.currentText()
    if not protocol or not packet:
        _set_library_status(dashboard)
        return
    # Keep the last compared set when a user clicks one row to inspect/edit.
    # Before the first Compare Selected, allow Apply on 2+ highlighted rows.
    current = {r["uid"] for r in dashboard.sa_pd_comparison_records}
    selected = dashboard.sa_pd_comparison_active_uids & current
    if len(selected) < 2:
        selected = _collection_selected(dashboard)
    if len(selected) < 2:
        QtWidgets.QMessageBox.information(
            dashboard, "Library Comparison", "Compare at least two messages first, or highlight two rows.")
        return
    dashboard.sa_pd_comparison_active_uids = set(selected)
    records, _vectors, _width = _comparison_rows(dashboard)
    try:
        fields, kind = _library_fields(dashboard, protocol, packet)
    except (ValueError, KeyError, IndexError, StopIteration, TypeError) as exc:
        QtWidgets.QMessageBox.warning(dashboard, "Library Comparison", str(exc))
        return
    if not fields:
        QtWidgets.QMessageBox.information(dashboard, "Library Comparison", "No fields are defined for this packet type.")
        return
    vectors = {r["uid"]: _aligned_bits(r) for r in records}
    table = ui.tableWidget_sa_pd_comparison_results
    blocker = QtCore.QSignalBlocker(table)
    table.setRowCount(len(fields))
    table.setColumnCount(len(records) + 3)
    table.setHorizontalHeaderLabels(["Field", "Length (bits)"] +
                                    [f"Msg {dashboard.sa_pd_comparison_records.index(r) + 1}"
                                     for r in records] + ["Result"])
    dashboard.sa_pd_comparison_field_details = []
    diffs = 0
    missing_fields = 0
    for row, field in enumerate(fields):
        cells = []
        for record in records:
            start, value = _field_bits(vectors[record["uid"]], field)
            cells.append((start, value))
        available = {"".join(value) for start, value in cells if value is not None}
        missing = any(value is None for start, value in cells)
        different = len(available) > 1
        status = ("Different + missing" if missing and different else
                  "Missing" if missing else "Different" if different else "Match")
        diffs += int(different)
        missing_fields += int(missing)
        values = [str(field.get("name") or field.get("key") or f"Field {row + 1}"),
                  str(field["length"])] + [_format_field_bits(value) for start, value in cells] + [status]
        for col, value in enumerate(values):
            item = QtWidgets.QTableWidgetItem(value)
            item.setFlags(item.flags() & ~QtCore.Qt.ItemIsEditable)
            item.setTextAlignment(QtCore.Qt.AlignCenter if col else QtCore.Qt.AlignVCenter)
            if 2 <= col < 2 + len(records):
                if cells[col - 2][1] is None:
                    item.setBackground(_MISSING_BG)
                    item.setForeground(QtGui.QColor("#202020"))
                elif different:
                    item.setBackground(_DIFFERENCE_BG)
                    item.setForeground(QtGui.QColor("#202020"))
                start, field_value = cells[col - 2]
                item.setToolTip(f"Offset {start}; bits: {''.join(field_value) if field_value else 'missing/incomplete'}")
            table.setItem(row, col, item)
        dashboard.sa_pd_comparison_field_details.append((field, list(zip(records, cells)), status))
    table.setColumnWidth(0, 170)
    table.setColumnWidth(1, 100)
    table.horizontalHeader().setStretchLastSection(True)
    table.verticalHeader().setVisible(False)
    table.clearSelection()
    del blocker
    dashboard.sa_pd_comparison_applied = True
    _update_collection(dashboard)
    ui.plainTextEdit_sa_pd_comparison_results.setPlainText(
        f"{len(records)} messages; {len(fields)} fields; {diffs} varying fields; "
        f"{missing_fields} fields with unavailable bits.\n"
        f"{kind[0].capitalize()} layout only; this is not protocol identification.\n"
        "Select a field row for values and bit offsets.")
    if fields:
        table.selectRow(0)
        _field_selected(dashboard)


def _field_selected(dashboard):
    """Inspect one Library field without repeating long capture names and raw dumps.

    Report exact field-relative bit differences for the compared message set.
    Bit offsets are zero-based, MSB-first, and reflect explicit per-message
    alignment edits (not visual left/right padding in the collection table).
    """
    row = dashboard.ui.tableWidget_sa_pd_comparison_results.currentRow()
    details = dashboard.sa_pd_comparison_field_details
    if not 0 <= row < len(details):
        return

    field, entries, status = details[row]
    name = str(field.get("name") or field.get("key") or f"Field {row + 1}")
    width = int(field["length"])
    record_ids = {r["uid"]: i + 1 for i, r in
                  enumerate(dashboard.sa_pd_comparison_records)}
    available = [bits for _, (_, bits) in entries if bits is not None]
    unique_values = {"".join(bits) for bits in available}
    missing_count = len(entries) - len(available)

    output = [name,
              f"{width} bits  |  {status}",
              f"{len(entries)} messages  |  {len(unique_values)} distinct values"
              + (f"  |  {missing_count} unavailable" if missing_count else "")]

    if isinstance(field.get("description"), str) and field["description"].strip():
        output.append(field["description"].strip())

    output.append("")
    for record, (start, bits) in entries:
        label = f"Msg {record_ids.get(record['uid'], '?')}"
        if bits is None:
            output.extend([f"{label} · unavailable at bit {start}",
                           "  Missing or incomplete field bits", ""])
            continue

        raw = "".join(bits)
        hex_value = _format_field_bits(bits)
        if len(hex_value) > 50:
            hex_value = hex_value[:30] + " … " + hex_value[-12:]
        output.append(f"{label} · bits {start}–{start + width - 1}")
        output.append(f"  Hex: {hex_value}")
        if width <= 64:
            grouped = " ".join(raw[i:i + 4] for i in range(0, width, 4))
            output.append(f"  Bin: {grouped}")
            output.append(f"  Dec: {int(raw, 2):,}")
        else:
            preview = " ".join(raw[i:i + 4] for i in range(0, min(width, 32), 4))
            output.append(f"  Bin (first 32): {preview}" + (" …" if width > 32 else ""))
        output.append("")

    changing = [i for i in range(width)
                if len({bits[i] for bits in available}) > 1]
    if changing:
        limit = 24
        suffix = f" … (+{len(changing) - limit} more)" if len(changing) > limit else ""
        output.append(f"Differing bit positions: {len(changing)} of {width}")
        output.append("  " + ", ".join(map(str, changing[:limit])) + suffix)
    elif missing_count:
        output.append("Available values agree; some messages lack this field.")
    else:
        output.append("All compared values match.")
    output.append("Bit indexes within the field start at 0 (MSB).")

    inspector = dashboard.ui.plainTextEdit_sa_pd_comparison_results
    inspector.setPlainText("\n".join(output))
    inspector.verticalScrollBar().setValue(0)


def open_sa_pd_comparison_from_pa(dashboard):
    """Copy highlighted Packet Analysis rows; Include checkboxes are unrelated."""
    if not getattr(dashboard, "sa_pd_comparison_initialized", False):
        initialize_sa_pd_comparison_controls(dashboard)
    pa_table = dashboard.ui.tableWidget_sa_pd_pa_input
    selected = [row.row() for row in pa_table.selectionModel().selectedRows()]
    if not selected:
        QtWidgets.QMessageBox.information(dashboard, "Compare Messages",
                                          "Highlight one or more Packet Analysis rows to transfer.")
        return 0
    lookup = {record["uid"]: record for record in getattr(dashboard, "sa_pd_pa_records", [])}
    incoming = []
    for index in sorted(set(selected)):
        cell = pa_table.item(index, 0)
        source = lookup.get(cell.data(QtCore.Qt.UserRole)) if cell is not None else None
        if source is None:
            continue
        try:
            bits = _bits_from_source(source["bits"])
        except (ValueError, KeyError, TypeError):
            continue
        incoming.append(_new_record(dashboard, bits, source=source.get("source", "Packet Analysis"),
                                    capture=source.get("capture"), metadata=source.get("metadata"),
                                    framing=source.get("framing"), notes="Packet Analysis"))
    if not incoming:
        return 0
    if len(incoming) > _MAX_MESSAGES:
        QtWidgets.QMessageBox.warning(dashboard, "Comparison", "Import exceeds collection limit.")
        return 0
    if dashboard.sa_pd_comparison_records:
        prompt = QtWidgets.QMessageBox(dashboard)
        prompt.setWindowTitle("Import into Comparison")
        prompt.setText(f"The collection contains {len(dashboard.sa_pd_comparison_records)} messages. "
                       f"How should {len(incoming)} incoming messages be added?")
        append = prompt.addButton("Append", QtWidgets.QMessageBox.AcceptRole)
        replace = prompt.addButton("Replace", QtWidgets.QMessageBox.DestructiveRole)
        prompt.addButton("Cancel", QtWidgets.QMessageBox.RejectRole)
        prompt.exec_()
        clicked = prompt.clickedButton()
        if clicked is replace:
            dashboard.sa_pd_comparison_records.clear()
            _set_editor(dashboard, "")
        elif clicked is not append:
            return 0
    if len(dashboard.sa_pd_comparison_records) + len(incoming) > _MAX_MESSAGES:
        QtWidgets.QMessageBox.warning(dashboard, "Comparison", "Import exceeds collection limit.")
        return 0
    dashboard.sa_pd_comparison_records.extend(incoming)
    _invalidate_comparison(dashboard)
    _update_collection(dashboard, selected_uids={r["uid"] for r in incoming})
    dashboard.ui.tabWidget_protocol.setCurrentWidget(dashboard.ui.tab_sa_pd_comparison)
    dashboard.ui.tabWidget_signal_analysis.setCurrentWidget(dashboard.ui.tab_protocol_discovery)
    return len(incoming)


def initialize_sa_pd_comparison_controls(dashboard):
    """Initialize Comparison presentation, state and Library choices; no wiring."""
    if getattr(dashboard, "sa_pd_comparison_initialized", False):
        return
    ui = dashboard.ui
    dashboard.sa_pd_comparison_records = []
    dashboard.sa_pd_comparison_next_uid = 1
    dashboard.sa_pd_comparison_active_uids = set()
    dashboard.sa_pd_comparison_editing_uid = None
    dashboard.sa_pd_comparison_editor_bits = ""
    dashboard.sa_pd_comparison_active_editor = None
    dashboard.sa_pd_comparison_editor_invalid = False
    dashboard.sa_pd_comparison_editor_truncated = False
    dashboard.sa_pd_comparison_applied = False
    dashboard.sa_pd_comparison_field_details = []
    try:
        dashboard.sa_pd_comparison_formats = get_cached_packet_formats(dashboard.backend.library)
    except (ValueError, KeyError, TypeError) as exc:
        dashboard.logger.warning("Comparison packet format cache invalid: %s", exc)
        dashboard.sa_pd_comparison_formats = []

    ui.comboBox_sa_pd_comparison_collection_group.setCurrentIndex(2)
    ui.comboBox_sa_pd_comparison_collection_alignment.setCurrentIndex(0)
    collection = ui.tableWidget_sa_pd_comparison_collection
    collection.setColumnCount(5)
    collection.setHorizontalHeaderLabels(["#", "Source", "Length (bits)", "Notes", "Preview (Hex)"])
    collection.setItemDelegateForColumn(4, _PreviewDelegate(collection))
    collection.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    collection.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
    collection.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    collection.setSortingEnabled(False)
    collection.setWordWrap(False)
    collection.verticalHeader().setVisible(False)
    collection.verticalHeader().setDefaultSectionSize(25)
    for col, width in enumerate((44, 185, 104, 140, 550)):
        collection.setColumnWidth(col, width)
    collection.horizontalHeader().setStretchLastSection(False)
    collection.setHorizontalScrollMode(QtWidgets.QAbstractItemView.ScrollPerPixel)
    collection.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)

    controls = [ui.comboBox_sa_pd_comparison_collection_group,
                ui.label2_sa_pd_comparison_collection_group,
                ui.comboBox_sa_pd_comparison_collection_alignment,
                ui.label2_sa_pd_comparison_collection_alignment,
                ui.pushButton_sa_pd_comparison_collection_remove_selected,
                ui.pushButton_sa_pd_comparison_collection_clear_all,
                ui.pushButton_sa_pd_comparison_collection_compare_selected]
    dashboard.sa_pd_comparison_geometry = {
        "frame": QtCore.QRect(ui.frame_sa_pd_comparison_collection.geometry()),
        "results": QtCore.QRect(ui.frame_sa_pd_comparison_results.geometry()),
        "table": QtCore.QRect(collection.geometry()),
        "controls": [(w, QtCore.QRect(w.geometry())) for w in controls],
    }
    icon = QtGui.QIcon.fromTheme("edit-copy")
    for mode in ("binary", "hex", "ascii"):
        copy_button = getattr(ui, f"pushButton_sa_pd_comparison_editor_{mode}_copy")
        copy_button.setToolTip("Copy all " + mode + " data")
        if icon.isNull():
            copy_button.setText("⧉")
        else:
            copy_button.setIcon(icon)
        editor = _editor(dashboard, mode)
        editor.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth if mode in ("binary", "ascii")
                               else QtWidgets.QPlainTextEdit.NoWrap)
        editor.setWordWrapMode(QtGui.QTextOption.WrapAtWordBoundaryOrAnywhere if mode == "binary"
                               else QtGui.QTextOption.WrapAnywhere)
        if mode == "binary":
            editor.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    details = ui.plainTextEdit_sa_pd_comparison_results
    details.setReadOnly(True)
    details.setLineWrapMode(QtWidgets.QPlainTextEdit.WidgetWidth)
    details.setWordWrapMode(QtGui.QTextOption.WrapAnywhere)
    details.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
    details.setVerticalScrollBarPolicy(QtCore.Qt.ScrollBarAsNeeded)
    details.setFont(QtGui.QFont("Ubuntu", 9))

    protocol_box = ui.comboBox_sa_pd_comparison_results_protocol
    names = {str(row[1]) for row in dashboard.backend.library.get("packet_types", [])}
    names.update(row["protocol_name"] for row in dashboard.sa_pd_comparison_formats)
    blocker = QtCore.QSignalBlocker(protocol_box)
    protocol_box.clear()
    protocol_box.addItem("")
    protocol_box.addItems(sorted(names))
    del blocker
    results = ui.tableWidget_sa_pd_comparison_results
    results.setItemDelegate(_FieldHighlightDelegate(results))
    results.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
    results.setEditTriggers(QtWidgets.QAbstractItemView.NoEditTriggers)
    results.setSortingEnabled(False)
    _set_editor(dashboard, "")
    dashboard.sa_pd_comparison_initialized = True
    _update_collection(dashboard)
    _set_library_status(dashboard)


# Public Qt slot entry points. All signal connections are owned by Frontend.py.
def sa_pd_comparison_editor_changed(dashboard, representation):
    _editor_changed(dashboard, representation)


def sa_pd_comparison_copy_editor(dashboard, representation):
    _copy_editor(dashboard, representation)


def sa_pd_comparison_transform_editor(dashboard, action):
    _editor_action(dashboard, action)


def sa_pd_comparison_add_from_editor(dashboard):
    _add_from_editor(dashboard)


def sa_pd_comparison_update_from_editor(dashboard):
    _update_from_editor(dashboard)


def sa_pd_comparison_remove_selected(dashboard):
    _remove_selected(dashboard)


def sa_pd_comparison_clear_all(dashboard):
    _clear_all(dashboard)


def sa_pd_comparison_compare_selected(dashboard):
    _compare_selected(dashboard)


def sa_pd_comparison_collection_context_menu(dashboard, position):
    _collection_menu(dashboard, position)


def sa_pd_comparison_load_collection_row(dashboard, row):
    _load_row(dashboard, row)


def sa_pd_comparison_update_buttons(dashboard):
    _update_buttons(dashboard)


def sa_pd_comparison_refresh_collection(dashboard):
    _update_collection(dashboard)


def sa_pd_comparison_protocol_changed(dashboard):
    _protocol_changed(dashboard)


def sa_pd_comparison_packet_type_changed(dashboard):
    _set_library_status(dashboard)


def sa_pd_comparison_apply_library(dashboard):
    _apply_library(dashboard)


def sa_pd_comparison_field_selected(dashboard):
    _field_selected(dashboard)


def sa_pd_comparison_load_external_bits(dashboard, bit_text):
    """Load recovered IQ Demodulation bits into the editable Comparison workbench.

    Do not overwrite the saved collection or silently edit a selected message.
    This loads a new working copy into the editor only.
    """
    try:
        bits = _parse_editor(str(bit_text), "binary")
    except (ValueError, TypeError):
        QtWidgets.QMessageBox.warning(
            dashboard, "Comparison", "Demodulation output is not a valid binary bitstream."
        )
        return False
    if not bits:
        return False
    if len(bits) > _MAX_EDITOR_BITS:
        QtWidgets.QMessageBox.warning(
            dashboard, "Comparison",
            f"The recovered bitstream is too large for the editor ({_MAX_EDITOR_BITS:,} bits maximum).",
        )
        return False
    if not getattr(dashboard, "sa_pd_comparison_initialized", False):
        initialize_sa_pd_comparison_controls(dashboard)
    _set_editor(dashboard, bits, loaded_uid=None)
    dashboard.ui.tabWidget.setCurrentWidget(dashboard.ui.tab_tsi)
    dashboard.ui.tabWidget_signal_analysis.setCurrentWidget(dashboard.ui.tab_protocol_discovery)
    dashboard.ui.tabWidget_protocol.setCurrentWidget(dashboard.ui.tab_sa_pd_comparison)
    return True


__all__ = [
    name for name, value in globals().items()
    if inspect.isfunction(value) and value.__module__ == __name__
]
