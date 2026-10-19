"""Protocol-agnostic, offline bit decoding and *candidate* frame discovery.

No Qt, radio hardware, database or protocol assumptions. Bit positions are
zero-based and half-open in the *decoded* stream. A synchronization match or
preamble is evidence of a boundary, not proof that a packet is valid.
"""

from collections import Counter
import binascii

import numpy as np

from .protocol_bitstream import normalize_bits


MAX_FRAMES = 3000


def parse_sync_pattern(text):
    """Accept 0b-prefixed bits, unprefixed 0/1 strings, or hex bytes/nibbles."""
    value = str(text or "").strip()
    if not value or value.lower() == "auto":
        return None
    is_hex = value.lower().startswith("0x")
    if value.lower().startswith("0b"):
        value = value[2:].replace(" ", "").replace("_", "")
        if not value or any(char not in "01" for char in value):
            raise ValueError("Invalid binary sync pattern")
        bits = value
    else:
        compact = "".join(value.replace("0x", "").replace("0X", "").split()).replace("_", "")
        if not compact:
            raise ValueError("Empty sync pattern")
        if not is_hex and all(char in "01" for char in compact):
            bits = compact
        elif all(char in "0123456789abcdefABCDEF" for char in compact):
            bits = "".join(f"{int(char, 16):04b}" for char in compact)
        else:
            raise ValueError("Sync pattern must contain binary or hexadecimal digits")
    if not 4 <= len(bits) <= 128:
        raise ValueError("Sync pattern must contain 4–128 bits")
    return np.fromiter((int(char) for char in bits), dtype=np.uint8)


def transform_bits(values, encoding="Raw / NRZ", polarity="Normal"):
    """Return decoded bits and raw coordinate mapping (stride, offset, quality)."""
    values = normalize_bits(values)
    bits = 1 - values if polarity == "Inverted" else values
    if encoding == "Raw / NRZ":
        return bits, 1, 0, None
    if encoding == "NRZI":
        previous = np.r_[np.uint8(0), bits[:-1]]
        # Convention: transition -> 0, no transition -> 1.
        return (bits == previous).astype(np.uint8), 1, 0, None
    if encoding not in ("Manchester", "Differential Manchester"):
        raise ValueError(f"Unsupported encoding: {encoding}")
    if len(bits) < 16:
        raise ValueError("Not enough bits for Manchester decoding")
    choices = []
    for offset in (0, 1):
        pairs = bits[offset:offset + ((len(bits) - offset) // 2) * 2].reshape(-1, 2)
        quality = float(np.mean(pairs[:, 0] != pairs[:, 1]))
        choices.append((quality, offset, pairs))
    quality, offset, pairs = max(choices, key=lambda row: (row[0], -row[1]))
    if quality < 0.90:
        raise ValueError(f"Manchester transitions inconsistent ({quality:.0%} valid pairs)")
    if encoding == "Manchester":
        # IEEE convention: 01 -> 0; 10 -> 1.
        decoded = pairs[:, 0].copy()
    else:
        previous = np.r_[bits[offset - 1] if offset else np.uint8(0), pairs[:-1, 1]]
        # Start-of-symbol transition -> 0; no transition -> 1.
        decoded = (pairs[:, 0] == previous).astype(np.uint8)
    return decoded, 2, offset, quality


def find_alternating_preambles(bits, min_bits=24):
    """Maximal contiguous runs of alternating zeros and ones, [start, end)."""
    bits = np.asarray(bits, dtype=np.uint8)
    if len(bits) < min_bits:
        return []
    unchanged = np.flatnonzero(bits[1:] == bits[:-1])
    starts = np.r_[0, unchanged + 1]
    ends = np.r_[unchanged + 1, len(bits)]
    indices = np.flatnonzero((ends - starts) >= min_bits)
    return [(int(starts[i]), int(ends[i])) for i in indices[:MAX_FRAMES]]


def _sync_hits(bits, pattern):
    if pattern is None:
        return []
    haystack = np.asarray(bits, dtype=np.uint8).tobytes()
    needle = np.asarray(pattern, dtype=np.uint8).tobytes()
    hits = []
    position = 0
    while position <= len(haystack) - len(needle) and len(hits) < MAX_FRAMES:
        match = haystack.find(needle, position)
        if match < 0:
            break
        hits.append(match)
        position = match + len(needle)
    return hits


def _timing_spans(sample_centers, start, end, min_length, gap_factor):
    """Find true timing discontinuities, not logical runs of zero bits."""
    if sample_centers is None:
        return []
    centers = np.asarray(sample_centers, dtype=float)
    if centers.ndim != 1 or len(centers) < end:
        return []
    differences = np.diff(centers[start:end])
    positives = differences[np.isfinite(differences) & (differences > 0)]
    if len(positives) < 6:
        return []
    interval = float(np.median(positives))
    cuts = np.flatnonzero(differences > interval * gap_factor) + start + 1
    if len(cuts) == 0:
        return []
    limits = [start] + cuts.tolist() + [end]
    return [(a, b) for a, b in zip(limits, limits[1:]) if b - a >= min_length]


def _ook_burst_spans(raw_bits, start, end, min_length, max_length, *, allow_single=False):
    """Propose OOK on-activity bursts separated by unusually long off runs.

    Raw OOK hard decisions represent energy above threshold as 1. Sustained
    zeros *may* indicate a transmitter-off period; they are not proof of a
    packet boundary. Work on the original polarity so a decoded inversion
    cannot turn off periods into misleading high-activity spans.

    This heuristic intentionally does not run on unknown/FSK bitstreams.
    Returned coordinates are half-open and in raw bit indices.
    """
    raw = np.asarray(raw_bits, dtype=np.uint8)
    if not 0 <= start < end <= len(raw):
        return []
    active = np.flatnonzero(raw[start:end]) + start
    if len(active) < 8:
        return []

    # Short off runs occur between ordinary OOK marks. Find a background
    # run length and require significantly longer off periods to split bursts.
    off_runs = np.diff(active) - 1
    off_runs = off_runs[off_runs > 0]
    if not len(off_runs):
        return []
    short_off = float(np.percentile(off_runs, 50))
    min_idle = max(8, int(np.ceil(short_off * 4.5)))
    cuts = np.flatnonzero(np.diff(active) - 1 >= min_idle)
    firsts = np.r_[0, cuts + 1]
    lasts = np.r_[cuts, len(active) - 1]

    spans = []
    min_marks = max(5, int(np.ceil(min_length * 0.15)))
    for first, last in zip(firsts, lasts):
        a, b = int(active[first]), int(active[last]) + 1
        if not min_length <= b - a <= max_length or last - first + 1 < min_marks:
            continue
        spans.append((a, b))
        if len(spans) >= MAX_FRAMES:
            break

    # One isolated group in a longer stream is plausible only when there is
    # clear idle space on BOTH sides. Avoid treating generic OOK data as a
    # framed packet merely because some zeros occur in its payload.
    if len(spans) == 1 and not allow_single:
        a, b = spans[0]
        if a - start < min_idle or end - b < min_idle:
            return []
    return spans


def _propose_frames(bits, method, start, end, min_length, max_length,
                    preamble_bits, pattern=None, fixed_length=None,
                    sample_centers=None, gap_factor=3.5, ook_spans=None):
    """Return (start, end, origin, sync_match) tentative frame proposals."""
    scope = bits[start:end]
    if method == "Fixed Length":
        if fixed_length is None or fixed_length < 1:
            raise ValueError("Enter a positive frame length")
        return [(index, index + fixed_length, "Fixed length", False)
                for index in range(start, end - fixed_length + 1, fixed_length)][:MAX_FRAMES]
    if method == "Sync Pattern":
        if pattern is None:
            raise ValueError("Enter a sync pattern")
        hits = [start + index for index in _sync_hits(scope, pattern)]
        proposals = []
        for i, pos in enumerate(hits[:MAX_FRAMES]):
            stop = (pos + fixed_length) if fixed_length else (hits[i + 1] if i + 1 < len(hits) else end)
            proposals.append((pos, min(stop, end), "Sync match", True))
        return proposals
    if method == "Timing Gaps":
        spans = _timing_spans(sample_centers, start, end, min_length, gap_factor)
        return [(a, b, "Timing gap", False) for a, b in spans][:MAX_FRAMES]
    if method == "OOK Bursts":
        return [(a, b, "OOK idle run", False) for a, b in (ook_spans or [])][:MAX_FRAMES]
    if method != "Auto":
        raise ValueError(f"Unknown framing method: {method}")

    # True timestamp discontinuities establish better activity boundaries
    # than bit patterns; normally demodulated sample centers are UNIFORM.
    gaps = _timing_spans(sample_centers, start, end, min_length, gap_factor)
    if len(gaps) > 1:
        return [(a, b, "Timing gap", False) for a, b in gaps][:MAX_FRAMES]

    # OOK marks separated by unusually long off runs give useful BURST
    # candidates, not necessarily complete protocol frames. Never apply this
    # to FSK or unknown sources just because their bits contain zeros.
    if ook_spans:
        return [(a, b, "OOK idle run", False) for a, b in ook_spans][:MAX_FRAMES]

    runs = [(start + a, start + b) for a, b in find_alternating_preambles(scope, preamble_bits)]
    proposals = []
    for i, (pre_start, pre_end) in enumerate(runs[:MAX_FRAMES]):
        next_start = runs[i + 1][0] if i + 1 < len(runs) else end
        if next_start - pre_end >= min_length:
            proposals.append((pre_end, next_start, f"Preamble ({pre_end-pre_start} bits)", False))
    return proposals


def _crc16_boundary_hypotheses(bits, start, stop, min_length):
    """Look for standard CRC-16 matches at byte-aligned candidate ends.

    A CRC match supports a *hypothesis* about frame termination and possibly
    bit polarity; it does not establish protocol identity or packet validity.
    No candidate is fabricated when the available evidence is insufficient.
    A small range of leading unprotected bytes accommodates header/sync bytes.
    """
    bit_count = stop - start
    if bit_count < max(80, min_length):
        return []
    # Do not search beyond 512 bytes per candidate or the observed frame end.
    # The search is quadratic if long frames are repeatedly copied, so pack
    # once and slice bytes for each candidate length.
    # A CRC match far inside an otherwise unbounded bitstream is easy to find
    # by chance after trying many algorithms/lengths. Only test ends close
    # to an independently proposed boundary (end-of-burst, next preamble,
    # or timing discontinuity). This deliberately misses cases with long
    # unexplained trailers rather than manufacturing a strong hypothesis.
    if bit_count > 512 * 8:
        return []
    available_bytes = bit_count // 8
    if available_bytes < 10:
        return []
    packed = np.packbits(bits[start:start + available_bytes * 8], bitorder="big").tobytes()
    variants = (("CRC-16/CCITT-FALSE", 0xFFFF),
                ("CRC-16/XMODEM", 0x0000),
                ("CRC-16/SPI-FUJITSU", 0x1D0F))
    matches = []
    earliest_bytes = max(10, (min_length + 7) // 8)
    near_boundary_start = max(earliest_bytes, available_bytes - 8)
    for total_bytes in range(near_boundary_start, available_bytes + 1):
        tail = packed[total_bytes - 2:total_bytes]
        for skip in range(min(4, total_bytes - 10) + 1):
            payload = packed[skip:total_bytes - 2]
            for name, initial in variants:
                computed = binascii.crc_hqx(payload, initial)
                if computed.to_bytes(2, 'big') == tail:
                    matches.append({"end": start + 8 * total_bytes,
                                    "algorithm": name,
                                    "skip_bytes": skip,
                                    "checksum": f"{computed:04X}",
                                    "total_bytes": total_bytes})
    return matches


def _frames(bits, proposals, min_length, max_length, search_crc=False):
    answer = []
    for start, end, origin, sync_match in proposals:
        if end - start < min_length:
            continue
        # Never misrepresent a truncated frame as a complete message.
        if end - start > max_length:
            continue
        crc_matches = (_crc16_boundary_hypotheses(bits, start, end, min_length)
                       if search_crc else [])
        # The shortest supported end is preferred over speculative trailing
        # bytes. If no checksum matches, keep the original tentative boundary.
        best_crc = min(crc_matches,
                       key=lambda row: (row['end'], row['skip_bytes'])) if crc_matches else None
        if best_crc:
            end = best_crc['end']
        data = bits[start:end].copy()
        answer.append({"start": int(start), "end": int(end), "bits": data,
                       "length": len(data), "origin": origin,
                       "sync_match": bool(sync_match), "occurrences": 1,
                       "crc_evidence": best_crc,
                       "boundary_evidence": (
                           "Preamble + CRC" if best_crc and origin.startswith("Preamble") else
                           "CRC-16 match" if best_crc else
                           "Sync match" if sync_match else
                           "Timing gap" if origin == "Timing gap" else
                           "OOK idle run" if origin == "OOK idle run" else
                           "Preamble" if origin.startswith("Preamble") else origin),
                       # A hypothesized checksum is NOT proof of validity.
                       "validated": False})
        if len(answer) >= MAX_FRAMES:
            break
    duplicates = Counter((row["length"], row["bits"].tobytes()) for row in answer)
    for row in answer:
        row["occurrences"] = duplicates[row["length"], row["bits"].tobytes()]
    return answer


def _mixed_manchester_crc8_candidate(raw, start, end, *, pattern=None,
                                     min_frame_bits=16,
                                     max_frame_bits=4096):
    """Find a raw sync/prefix followed by Manchester + differential payload.

    The raw prefix is deliberately NOT Manchester decoded. Search only well
    isolated Manchester runs near the leading RF activity edge, or runs after
    a user-supplied RAW sync. Require a known CRC-8 hypothesis at an end
    supported by the observed Manchester-to-idle transition. These are
    hypotheses about encoding and packet boundaries, not protocol identity.
    """
    values = normalize_bits(raw)
    if end - start < 112:
        return None
    sync_hits = []
    if pattern is not None:
        sync_hits = [start + pos for pos in _sync_hits(values[start:end], pattern)]
        if not sync_hits:
            return None
    # A search of every offset in a long random FSK capture causes spurious
    # CRC matches. In Auto consider only the beginning of a known RF burst.
    if pattern is None:
        chip_starts = range(start, min(end - 112, start + 40) + 1)
    else:
        # Restrict manual searches to a small neighborhood around each real
        # sync hit. Do not scan the intervening megabits of unrelated data.
        chip_starts = sorted({hit + delta for hit in sync_hits[:32]
                              for delta in range(len(pattern) + 2)
                              if hit + delta <= end - 112})

    findings = []
    for chip_start in chip_starts:
        if pattern is None:
            if chip_start - start < 7:
                continue
            prefix = values[max(start, chip_start - 20):chip_start]
            if len(prefix) < 7:
                continue
            # A run of identical raw chips in the immediate preceding region
            # identifies a plausible unencoded access/preamble section.
            if not any(np.all(prefix[i:i + 5] == prefix[i]) for i in range(len(prefix) - 4)):
                continue
        else:
            if not any(hit <= chip_start <= hit + len(pattern) + 1 for hit in sync_hits):
                continue

        available = min((end - chip_start) // 2, max_frame_bits + 8, 8192)
        if available < 56:
            continue
        pairs = values[chip_start:chip_start + available * 2].reshape(-1, 2)
        valid = pairs[:, 0] != pairs[:, 1]
        failures = np.flatnonzero(~valid)
        run_pairs = int(failures[0]) if len(failures) else len(valid)
        if run_pairs < 64:
            continue
        # Prefer a demonstrable trailer/line-code violation rather than
        # inventing a packet end in the middle of a continuous encoded stream.
        trailing = end - (chip_start + 2 * run_pairs)
        if trailing < 2 or trailing > 24:
            continue
        manchester = pairs[:run_pairs, 0].astype(np.uint8)
        # Differential stage: 1 for a decoded transition, 0 for no transition.
        # The first Manchester symbol is a reference, not a payload data bit.
        differential = np.bitwise_xor(manchester[1:], manchester[:-1])
        # Search only near the independently observed end of the Manchester run
        # (up to 4 final bits of ambiguous on-air trailer/padding).
        for final_length in range(max(min_frame_bits, len(differential) - 2),
                                  min(max_frame_bits, len(differential)) + 1):
            if final_length < 40:
                continue
            data = differential[:final_length]
            payload, transmitted = data[:-8], data[-8:]
            observed = int(''.join(str(int(bit)) for bit in transmitted), 2)
            # Common non-reflected 8-bit generator polynomials. This narrow
            # hypothesis set avoids exhaustive CRC-parameter overfitting.
            for polynomial in (0x07, 0x13, 0x1D, 0x31):
                check = 0
                for bit in payload:
                    carry = ((check >> 7) & 1) ^ int(bit)
                    check = ((check << 1) & 255) ^ (polynomial if carry else 0)
                if check != observed:
                    continue
                # A blind CRC-8 sweep can accidentally match random streams.
                # Auto therefore also requires a *separate* structural clue:
                # two adjacent inverted 8-bit fields near the checksum. A
                # user-provided raw sync is itself an independent clue.
                complemented = []
                for pos in range(max(0, len(payload) - 32), len(payload) - 15):
                    tail_bits = len(payload) - (pos + 16)
                    if 4 <= tail_bits <= 16 and np.all(
                            payload[pos:pos + 8] != payload[pos + 8:pos + 16]):
                        complemented.append(pos)
                if pattern is None and not complemented:
                    continue
                if pattern is None:
                    evidence_origin = 'Raw preamble + Manchester + differential'
                else:
                    evidence_origin = 'Raw sync + Manchester + differential'
                finding = {
                    'bits': data.copy(), 'chip_start': chip_start,
                    'raw_start': chip_start + 2,
                    'raw_end': chip_start + (final_length + 1) * 2,
                    'manchester_pairs': run_pairs,
                    'crc8': {'algorithm': f'CRC-8 poly 0x{polynomial:02X}',
                             'value': f'{observed:02X}',
                             'end_raw': chip_start + (final_length + 1) * 2},
                    'origin': evidence_origin,
                    'pattern_matched': bool(pattern is not None),
                    'complement_positions': complemented,
                    'trailing_chips': end - (chip_start + (final_length + 1) * 2),
                }
                # Prefer a checksum close to the observed Manchester end,
                # and choose the earliest plausible byte/bit reference.
                score = (int(pattern is not None) * 40 +
                         int(bool(complemented)) * 10 +
                         final_length * 0.3 -
                         abs(len(differential) - final_length) * 5 -
                         max(0, chip_start - start) * 0.03)
                findings.append((score, finding))

    if not findings:
        return None
    # When several equally convincing CRC8 parameters or start locations
    # compete, do not manufacture a unique interpretation.
    findings.sort(key=lambda item: item[0], reverse=True)
    winner = findings[0][1]
    if len(findings) > 1:
        near = [f for score, f in findings if findings[0][0] - score < 0.08]
        if len({(f['chip_start'], f['raw_end']) for f in near}) > 1:
            return None
    return winner


def _pulse_distance_candidate(raw_bits, start, end, min_length, max_length, polarity="Auto"):
    """Tentatively decode an OOK pulse-spacing train into data bits.

    A prolonged initial mark and gap must precede a train of uniform short
    marks with two well-separated, stable pulse-to-pulse intervals. The
    shorter interval represents 0 by convention, not independently verified
    polarity. No protocol length, byte values or checksum is assumed.
    """
    raw = np.asarray(raw_bits, dtype=np.uint8)
    scope = raw[start:end]
    if len(scope) < max(40, 2 * min_length):
        return None

    changes = np.flatnonzero(np.diff(scope.astype(np.int8))) + 1
    boundaries = np.r_[0, changes, len(scope)]
    highs = [(start + int(boundaries[i]), start + int(boundaries[i + 1]))
             for i in range(len(boundaries) - 1)
             if scope[boundaries[i]] == 1]
    if len(highs) < max(18, min_length // 2 + 1):
        return None

    possibilities = []
    for header_index in range(len(highs) - 17):
        header_start, header_end = highs[header_index]
        data_begin = header_index + 1
        first_start = highs[data_begin][0]
        header_gap = first_start - header_end
        if header_gap < 4:
            continue

        # A long mark + quiet interval followed by short, regular marks.
        possible_marks = highs[data_begin:]
        mark_lengths = np.array([b - a for a, b in possible_marks], dtype=float)
        mark_width = float(np.median(mark_lengths))
        if mark_width < 1 or header_end - header_start < 5 * mark_width:
            continue
        if header_gap < 4 * mark_width:
            continue

        # End the train at a distinct idle gap, if one exists. Do not confuse
        # short/long payload intervals with a new packet delimiter.
        positions = np.array([a for a, _b in possible_marks], dtype=float)
        intervals = np.diff(positions)
        if len(intervals) < 16:
            continue
        typical = float(np.median(intervals))
        breaks = np.flatnonzero(intervals > max(typical * 2.7, typical + 6))
        stop = int(breaks[0] + 1) if len(breaks) else len(possible_marks)
        if stop < max(17, min_length + 1):
            continue
        marks = possible_marks[:stop]
        widths = np.array([b - a for a, b in marks], dtype=float)
        typical_width = float(np.median(widths))
        if max(abs(widths - typical_width)) > max(0.5, typical_width * 0.25):
            continue

        distances = np.diff([a for a, _b in marks]).astype(float)
        unique = sorted(set(distances.tolist()))
        if len(unique) < 2:
            continue
        best = None
        for left, right in zip(unique, unique[1:]):
            boundary = (left + right) / 2
            short = distances[distances < boundary]
            long = distances[distances >= boundary]
            if min(len(short), len(long)) < 3:
                continue
            short_m, long_m = float(np.median(short)), float(np.median(long))
            if not 1.4 <= long_m / max(short_m, 1e-8) <= 4.0:
                continue
            tolerance = max(0.25, 0.18 * short_m)
            if (np.max(abs(short - short_m)) > tolerance or
                    np.max(abs(long - long_m)) > max(0.25, 0.18 * long_m)):
                continue
            error = float(np.mean((short - short_m) ** 2) +
                          np.mean((long - long_m) ** 2))
            if best is None or error < best[0]:
                best = (error, boundary, short_m, long_m)
        if best is None:
            continue

        _error, boundary, short_interval, long_interval = best
        decoded = np.asarray(distances >= boundary, dtype=np.uint8)
        if polarity == "Inverted":
            decoded = 1 - decoded
        if not min_length <= len(decoded) <= max_length:
            continue
        possibilities.append((len(decoded), header_start, marks[0][0], marks[-1][1],
                              decoded, short_interval, long_interval))

    if not possibilities:
        return None
    # Prefer more decoded data, then the earliest unambiguous burst.
    size, header_start, data_start, raw_end, decoded, short, long = max(
        possibilities, key=lambda item: (item[0], -item[1]))
    return {"bits": decoded, "raw_start": data_start, "raw_end": raw_end,
            "header_start": header_start, "short_interval": short,
            "long_interval": long, "inverted": polarity == "Inverted"}


def analyze_bitstream(raw_bits, *, encoding="Auto", polarity="Auto", method="Auto",
                      sync_pattern=None, frame_length=None, start=0, end=None,
                      min_frame_bits=16, max_frame_bits=4096, min_preamble_bits=24,
                      sample_centers=None, gap_factor=3.5, modulation=None,
                      rf_capture_segment=False):
    """Discover candidate boundaries with defensible, source-aware evidence.

    OOK idle-run burst segmentation is eligible only for a known OOK source,
    or when explicitly chosen as the manual framing method. It uses the
    ORIGINAL hard-decision stream, independent of any polarity inversion.
    """
    raw = normalize_bits(raw_bits)
    start = int(start)
    end = len(raw) if end is None else int(end)
    if not (0 <= start < end <= len(raw)):
        raise ValueError("Invalid analysis range")
    min_frame_bits = int(min_frame_bits)
    max_frame_bits = int(max_frame_bits)
    if not (4 <= min_frame_bits <= max_frame_bits <= 1_000_000):
        raise ValueError("Invalid minimum or maximum frame length")
    if not 8 <= int(min_preamble_bits) <= 1024:
        raise ValueError("Minimum preamble must contain 8–1024 bits")
    pattern = parse_sync_pattern(sync_pattern)
    if method == "Sync Pattern" and pattern is None:
        raise ValueError("Enter a sync pattern before using Sync Pattern mode")
    fixed_length = int(frame_length) if frame_length is not None else None
    if fixed_length is not None and not 1 <= fixed_length <= 1_000_000:
        raise ValueError("Invalid frame length")
    # Pulse-distance OOK can encode one data bit per pulse interval, not per
    # recovered OOK chip. Try this only in Auto from an observed OOK source,
    # and require an isolated header plus a stable two-interval pulse train.
    if (method == "Auto" and encoding == "Auto" and
            str(modulation or "").strip().lower() == "ook"):
        distance = _pulse_distance_candidate(
            raw, start, end, min_frame_bits, max_frame_bits, polarity)
        if distance is not None:
            decoded = distance["bits"]
            inverted = distance["inverted"]
            description = (f"Pulse distance ({distance['short_interval']:g}/"
                           f"{distance['long_interval']:g} chips)")
            frame = {"start": 0, "end": len(decoded), "bits": decoded.copy(),
                     "length": len(decoded), "origin": description,
                     "sync_match": False, "occurrences": 1,
                     "crc_evidence": None, "crc8_evidence": None,
                     "boundary_evidence": "Pulse-distance pattern",
                     "raw_start": distance["raw_start"],
                     "raw_end": distance["raw_end"],
                     "validated": False, "unframed": False}
            return {"bits": decoded, "frames": [frame],
                    "encoding": "Pulse Distance", "polarity": (
                        "Inverted" if inverted else "Normal (hypothesis)"),
                    "stride": 1, "offset": 0, "method": method,
                    "status": (f"1 pulse-distance candidate ({len(decoded)} bits); "
                               "short/long spacing decoded; boundary and polarity unverified"),
                    "evidence": 20, "transition_quality": None,
                    "validated": False, "unframed": False,
                    "polarity_ambiguous": polarity == "Auto",
                    "crc_matches": 0, "crc8_matches": 0,
                    "alternatives": []}

    encodings = ("Raw / NRZ", "NRZI", "Manchester", "Differential Manchester") if encoding == "Auto" else (encoding,)
    polarities = ("Normal", "Inverted") if polarity == "Auto" else (polarity,)

    ook_allowed = method == "OOK Bursts" or (method == "Auto" and str(modulation or "").lower() == "ook")
    ook_raw_spans = (_ook_burst_spans(raw, start, end, min_frame_bits, max_frame_bits,
                                     allow_single=method == "OOK Bursts")
                     if ook_allowed else [])
    candidates = []
    last_error = None
    for current_encoding in encodings:
        for current_polarity in polarities:
            try:
                decoded, stride, offset, quality = transform_bits(raw, current_encoding, current_polarity)
                scope_start = max(0, (start - offset + stride - 1) // stride)
                scope_end = min(len(decoded), (end - offset) // stride)
                if scope_end <= scope_start:
                    continue
                centers = sample_centers if stride == 1 else (
                    np.asarray(sample_centers)[offset:offset + len(decoded)*2:2]
                    if sample_centers is not None and len(sample_centers) >= len(raw) else None)
                decoded_ook_spans = []
                for a, b in ook_raw_spans:
                    left = max(scope_start, (a - offset + stride - 1) // stride)
                    right = min(scope_end, (b - offset) // stride)
                    if right - left >= min_frame_bits:
                        decoded_ook_spans.append((left, right))
                proposals = _propose_frames(
                    decoded, method, scope_start, scope_end, min_frame_bits, max_frame_bits,
                    min_preamble_bits, pattern, fixed_length, centers, gap_factor,
                    ook_spans=decoded_ook_spans)
                frames = _frames(decoded, proposals, min_frame_bits, max_frame_bits,
                                 search_crc=(method == "Auto" and fixed_length is None))
                evidence = 20 * len(frames) + 8 * sum(row["occurrences"] > 1 for row in frames)
                evidence += min(20, sum(row["origin"].startswith("Preamble") for row in frames) * 3)
                evidence += 160 * sum(row["crc_evidence"] is not None for row in frames)
                candidates.append((evidence, decoded, stride, offset, quality,
                                   current_encoding, current_polarity, frames))
            except ValueError as error:
                last_error = error
    if not candidates:
        raise ValueError(str(last_error or "No usable decoding interpretation"))
    best = max(candidates, key=lambda item: item[0])
    evidence, decoded, stride, offset, quality, selected_encoding, selected_polarity, frames = best
    competing = [c for c in candidates if c[0] == evidence]
    polarity_ambiguous = (polarity == "Auto" and len({c[6] for c in competing}) > 1)

    # Region-scoped decoding: a raw access code may precede a Manchester
    # payload, whose symbols are then *differentially decoded*. Do NOT use
    # differential Manchester as a substitute for that two-stage pipeline.
    # Preserve independently supported CRC-16/OOK frames over new hypotheses.
    mixed = None
    existing_strong = any(frame.get("crc_evidence") for frame in frames)
    if (not existing_strong and
            str(modulation or "").strip().lower() in ("fsk", "2-fsk") and
            encoding == "Auto" and method in ("Auto", "Sync Pattern") and
            fixed_length is None and
            (bool(rf_capture_segment) or method == "Sync Pattern") and
            (method != "Sync Pattern" or pattern is not None)):
        mixed = _mixed_manchester_crc8_candidate(
            raw, start, end,
            pattern=pattern, min_frame_bits=min_frame_bits,
            max_frame_bits=max_frame_bits)
    if mixed is not None:
        decoded = mixed["bits"]
        stride, offset = 2, mixed["raw_start"]
        selected_encoding = "Manchester → Differential"
        selected_polarity = (polarity if polarity != "Auto" else "Unresolved")
        # Differential payload decoding is invariant under complementing
        # both FSK decisions. It cannot determine transmitter polarity.
        polarity_ambiguous = polarity == "Auto"
        evidence = 210
        frame = {"start": 0, "end": len(decoded), "bits": decoded.copy(),
                 "length": len(decoded), "origin": mixed["origin"],
                 "sync_match": mixed["pattern_matched"],
                 "occurrences": 1, "crc_evidence": None,
                 "crc8_evidence": mixed["crc8"],
                 "boundary_evidence": ("Manch. + CRC-8 + redundancy"
                                       if mixed["complement_positions"] else
                                       "Raw sync + Manchester + CRC-8"),
                 "complement_positions": mixed["complement_positions"],
                 "raw_start": mixed["raw_start"],
                 "raw_end": mixed["raw_end"],
                 "validated": False, "unframed": False}
        status = (f"1 decoded candidate ({len(decoded)} bits); "
                  "Manchester → differential; CRC-8 hypothesis (unverified)")
        return {"bits": decoded, "frames": [frame],
                "encoding": selected_encoding, "polarity": selected_polarity,
                "stride": stride, "offset": offset, "method": method,
                "status": status, "evidence": evidence,
                "transition_quality": 1.0, "validated": False,
                "unframed": False, "polarity_ambiguous": polarity_ambiguous,
                "crc_matches": 0, "crc8_matches": 1,
                "alternatives": []}

    # A known RF activity interval is useful to inspect even when no protocol
    # frame delimiter was found. This is deliberately NOT a discovered frame:
    # use it only for provenance-qualified FSK Demodulation inputs, over the
    # entire provided burst, without user-supplied framing assumptions.
    unframed = False
    capture_context = (bool(rf_capture_segment) and method == "Auto" and
                       str(modulation or "").strip().lower() in ("fsk", "2-fsk") and
                       pattern is None and fixed_length is None and
                       start == 0 and end == len(raw))
    if not frames and capture_context and min_frame_bits <= len(decoded) <= max_frame_bits:
        # With no framing evidence, Auto should not silently choose a
        # nontrivial encoding or polarity merely because of candidate order.
        # Keep the raw hard decisions as the inspectable representation.
        preferred = next((c for c in candidates if c[5] ==
                          ("Raw / NRZ" if encoding == "Auto" else encoding) and
                          c[6] == ("Normal" if polarity == "Auto" else polarity)), None)
        if preferred is not None:
            _, decoded, stride, offset, quality, selected_encoding, selected_polarity, _ = preferred
            frames = _frames(decoded, [(0, len(decoded), "RF capture (unframed)", False)],
                             min_frame_bits, max_frame_bits, search_crc=False)
            if frames:
                frames[0]["unframed"] = True
                frames[0]["boundary_evidence"] = "RF activity only"
                unframed = True
                polarity_ambiguous = polarity == "Auto"

    crc_matches = sum(f["crc_evidence"] is not None for f in frames)
    count_text = f"{len(frames):,} candidate" + ("" if len(frames) == 1 else "s")
    if not frames:
        status = "No supported frame boundaries found; try a sync pattern or fixed length"
    elif unframed:
        status = ("Unframed RF segment; no packet boundary" +
                  ("; polarity unknown" if polarity_ambiguous else ""))
    elif crc_matches:
        status = (f"{count_text}; {crc_matches} CRC-16 end "
                  f"{'match' if crc_matches == 1 else 'matches'}; "
                  f"{selected_polarity.lower()} polarity (unverified)")
    elif all(f["origin"] == "OOK idle run" for f in frames):
        status = (f"{count_text} from OOK off-periods; boundaries unverified" +
                  ("; polarity unresolved" if polarity_ambiguous else ""))
    elif method == "Auto":
        status = (f"{count_text}; end unverified" +
                  ("; polarity unresolved" if polarity_ambiguous else ""))
    else:
        status = f"{count_text} ({method}); boundaries unverified"
    return {"bits": decoded, "frames": frames, "encoding": selected_encoding,
            "polarity": selected_polarity, "stride": stride, "offset": offset,
            "method": method, "status": status, "evidence": evidence,
            "transition_quality": quality, "validated": False,
            "unframed": unframed,
            "polarity_ambiguous": polarity_ambiguous,
            "crc_matches": crc_matches,
            "alternatives": [{"encoding": c[5], "polarity": c[6],
                              "evidence": c[0], "frames": len(c[7]),
                              "crc_matches": sum(f["crc_evidence"] is not None for f in c[7])}
                             for c in sorted(candidates, key=lambda c: c[0], reverse=True)[:8]]}


def preview_hex(bits, max_bytes=32):
    bits = np.asarray(bits, dtype=np.uint8)
    if not len(bits):
        return ""
    data = np.packbits(bits[:max_bytes*8], bitorder="big")
    text = " ".join(f"{b:02X}" for b in data)
    return text + (" ..." if len(bits) > max_bytes*8 else "")


def format_message(bits, mode):
    bits = np.asarray(bits, dtype=np.uint8)
    if mode == "binary":
        chunks = ["".join(str(int(b)) for b in bits[i:i + 8]) for i in range(0, len(bits), 8)]
        return "\n".join(" ".join(chunks[i:i + 8]) for i in range(0, len(chunks), 8))
    raw = np.packbits(bits, bitorder="big").tobytes()
    if mode == "ascii":
        return "".join(chr(c) if 32 <= c < 127 else "." for c in raw)
    return "\n".join(f"{i:04X}   " + " ".join(f"{c:02X}" for c in raw[i:i + 16])
                     for i in range(0, len(raw), 16))
