"""Protocol Discovery packet analysis, independent of Qt, I/O and the Dashboard.

An observation (e.g. a CRC candidate from framing) is not a verified identity.
This first-stage engine deliberately returns unknown protocol identity until a
protocol-specific validator or independently specified library format is wired
in. All bit spans are zero-based and half-open.
"""

from collections import Counter
import math
import re

import numpy as np

from .protocol_bitstream import normalize_bits

MAX_PACKET_BITS = 1_000_000


def parse_packet_text(text, representation="Auto", bit_length=None):
    """Parse pasted bits/hex, optionally removing zero padding from a hex value.

    All-01 Auto input is binary. An exact hexadecimal bit length preserves the
    leftmost N bits; any removed trailing bits must be zero to avoid data loss.
    Prefix 0x / 0b to disambiguate. Offsets remain zero-based, MSB-first.
    """
    text = str(text or '').strip()
    if not text:
        raise ValueError('Enter hexadecimal or binary message data')
    value = re.sub(r'[\s_:,]', '', text)
    explicit_hex = value.lower().startswith('0x')
    explicit_bin = value.lower().startswith('0b')
    if explicit_hex or explicit_bin:
        value = value[2:]
    if not value:
        raise ValueError('No message digits found')
    mode = representation.lower().strip()
    if mode == 'auto':
        mode = 'hex' if explicit_hex else 'binary' if explicit_bin or set(value) <= {'0', '1'} else 'hex'
    if mode in {'binary', 'bits'}:
        if not re.fullmatch(r'[01]+', value):
            raise ValueError('Binary input must contain only 0 and 1')
        if len(value) > MAX_PACKET_BITS:
            raise ValueError('Message is too long')
        if bit_length is not None:
            raise ValueError('Exact bit length is only needed for hexadecimal input')
        return np.frombuffer(value.encode('ascii'), dtype=np.uint8).copy() - 48
    if mode != 'hex':
        raise ValueError('Representation must be Auto, Binary, or Hex')
    if not re.fullmatch('[0-9a-fA-F]+', value):
        raise ValueError('Hex input contains invalid digits')
    full_length = len(value) * 4
    if full_length > MAX_PACKET_BITS:
        raise ValueError('Message is too long')
    bits = np.fromiter((int(bit) for digit in value
                        for bit in f'{int(digit, 16):04b}'), dtype=np.uint8)
    if bit_length is None:
        return bits
    if isinstance(bit_length, bool) or not isinstance(bit_length, int):
        raise ValueError('Exact bit length must be an integer')
    if not 1 <= bit_length <= full_length:
        raise ValueError(f'Exact bit length must be between 1 and {full_length}')
    if np.any(bits[bit_length:]):
        raise ValueError('Trailing bits beyond the requested length are not zero. '
                         'Check the length or paste an exact binary message.')
    return bits[:bit_length].copy()


def make_packet(bits, *, source, capture=1, metadata=None, framing=None):
    values = normalize_bits(bits)
    if len(values) > MAX_PACKET_BITS:
        raise ValueError(f'Messages longer than {MAX_PACKET_BITS:,} bits are not supported in Packet Analysis')
    return {
        'bits': values,
        'source': str(source or 'Manual Input'),
        'capture': max(1, int(capture)),
        'metadata': dict(metadata or {}),
        'framing': dict(framing or {}),
    }


def format_bits_hex(bits):
    """Return numeric, left-zero-padded field hex without falsely right-padding bits.

    For example, a two-bit field '10' is 0x2, not the 0x8 obtained by
    appending two trailing zero bits. The separate bit length remains authoritative.
    """
    array = normalize_bits(bits)
    if not len(array):
        return ''
    text = ''.join(map(str, array.tolist()))
    return f'{int(text, 2):0{(len(text) + 3) // 4}X}'


def _check(name, expected, observed, outcome, explanation, span=None):
    return {'name': name, 'expected': expected, 'observed': observed,
            'outcome': outcome, 'explanation': explanation, 'span': span}


def analyze_packet(packet, peers=(), peer_summary=None, library=None, layout_candidates=None, formats=None):
    """Independently validate packet candidates while retaining observed facts.

    A Library length/field-layout fit is deliberately not an identification.
    Hypotheses found during framing stay hypotheses until the validator proves
    the expected checksum/field invariants with predeclared parameters.
    """
    from .protocol_packet_signatures import (
        validate_tpms_poore, library_layout_candidates,
    )
    from .protocol_packet_formats import (
        analyze_cached_formats, get_cached_packet_formats,
    )

    bits = normalize_bits(packet['bits'])
    meta = packet.get('metadata') or {}
    frame = packet.get('framing') or {}
    modulation = str(meta.get('modulation') or '').strip().upper()
    encoding = str(meta.get('encoding') or '').strip()
    length = len(bits)
    ones = int(bits.sum())
    ratio = (ones / length) if length else 0.0
    entropy = (0.0 if ratio in (0, 1) else
               -ratio * math.log2(ratio) - (1 - ratio) * math.log2(1 - ratio))

    observed = [
        _check('Message length', 'Protocol-dependent', f'{length:,} bits', 'Observed',
               'The extracted packet length is observed, not an independently confirmed format.'),
        _check('Encoding', 'Protocol-dependent', encoding or 'Not specified', 'Observed',
               'This is the encoding selected during Bitstream & Framing, not an independent identification.'),
        _check('Modulation', 'Protocol-dependent', modulation or 'Unavailable', 'Observed',
               'Modulation by itself cannot establish packet type or transmitter identity.'),
    ]
    for source_key, title in (('crc8_evidence', 'Framing CRC-8 hypothesis'),
                              ('crc_evidence', 'Framing CRC-16 hypothesis')):
        hypothesis = frame.get(source_key)
        if isinstance(hypothesis, dict):
            observed.append(_check(
                title, 'Independent known-profile checksum verification',
                str(hypothesis.get('algorithm') or 'Candidate CRC'), 'Hypothesis',
                'Bitstream & Framing inferred this checksum while searching for boundaries. '
                'Its presence is not proof of a protocol identity.'
            ))
    if frame.get('unframed'):
        observed.append(_check('Framing', 'Validated packet boundary',
                               'RF activity segment only', 'Unknown',
                               'The transferred segment has not been established as a full packet.'))
    elif frame:
        observed.append(_check('Framing', 'Validated packet boundary',
                               str(frame.get('origin') or frame.get('boundary_evidence') or 'Candidate'),
                               'Hypothesis', 'Bitstream & Framing reported candidate boundaries.'))
    if peer_summary is not None:
        same_length, same_prefix, prefix_len = peer_summary
        observed.append(_check('Cross-message structure', 'Protocol-dependent',
                               f'{same_length} same-length peers; {same_prefix} share {prefix_len}-bit prefix',
                               'Observed', 'Shared structure is useful context, not independent identification.'))
    elif peers:
        same_length = sum(1 for peer in peers if len(peer['bits']) == length)
        observed.append(_check('Cross-message structure', 'Protocol-dependent',
                               f'{same_length} other same-length messages', 'Observed',
                               'Common message length alone is not specific enough for identification.'))

    # A definition is selected from the cached catalog, not guessed from
    # message length. The same engine can later run on a Sensor Node with a
    # supplied subset; neither path queries PostgreSQL per packet.
    if formats is None:
        formats = get_cached_packet_formats(library)
    known_candidates = analyze_cached_formats(
        bits, formats, metadata=meta, unframed=bool(frame.get('unframed'))
    )
    # Preserve the preexisting TPMS validator during migration. Once its
    # catalog entry is enabled, the data-driven implementation is authoritative.
    registered_tpms = any(
        item['format_key'] == 'tpms.gr_tpms_poore.sensor_status.v1' for item in formats
    )
    tpms = None if registered_tpms else validate_tpms_poore(bits, metadata=meta)
    candidates = list(known_candidates)
    if tpms is not None:
        if frame.get('unframed'):
            tpms['strength'] = 'Possible'
            tpms['verified'] = False
            tpms['summary'] += ' Transferred segment is not independently framed.'
        tpms['checks'].extend(observed[-1:] if peer_summary is not None else [])
        candidates.append(tpms)

    # Reference matches outrank structural-only legacy Packet Crafter layouts.
    # Suppress unrelated same-length layouts when an independent format has
    # passed; these are not competing protocol identifications.
    accepted = [item for item in candidates
                if item['source'] in ('format_definition', 'reference_validator')
                and item['strength'] in ('Strong', 'Possible')]
    if not accepted:
        layouts = (layout_candidates if layout_candidates is not None else
                   library_layout_candidates(bits, library, limit=3))
        for candidate in layouts:
            if any(existing['protocol'].casefold() == candidate['protocol'].casefold()
                   for existing in candidates):
                continue
            candidates.append(candidate)

    fallback = dict(
        protocol='Unidentified protocol', message_type='Not determined',
        strength='Unknown',
        summary=('Captured data with ' + (modulation + ' modulation' if modulation else 'unknown modulation')
                 + '; no other identity assumed.'),
        checks=observed + [_check('Protocol identity', 'Validated signature or parser',
                                  'Not independently established', 'Not evaluated',
                                  'Candidate identity must rest on matching predeclared constraints.')],
        fields=[dict(name='Uninterpreted payload', start=0, length=length, value=None,
                     meaning='Raw bits; field boundaries not verified')],
        verified=False, source='unknown',
    )
    # With no positive identification, show Unknown before the rejected
    # alternatives; keep those alternatives inspectable for failure evidence.
    positively_identified = any(
        item['source'] in ('format_definition', 'reference_validator')
        and item['strength'] != 'Rejected' for item in candidates
    )
    if positively_identified:
        candidates.append(fallback)
    else:
        candidates.insert(0, fallback)
    top = next((item for item in candidates if item['source'] in (
        'format_definition', 'reference_validator')
        and item['strength'] != 'Rejected'), None)
    if top is not None:
        # Avoid embedding the manufacturer's profile name into the collection
        # summary, while retaining a fully qualified name in the candidate.
        summary_protocol = top['protocol'].split(' (', 1)[0]
        summary = f"{summary_protocol} / {top['message_type']} ({top['strength']})"
    else:
        summary = 'Unidentified protocol'
    return dict(summary=summary, candidates=candidates, ones=ones, entropy=entropy)


def analyze_collection(packets, indices, library=None):
    """Recalculate all checked packets with bounded cross-message observations."""
    indices = list(dict.fromkeys(indices))
    selected = [packets[i] for i in indices]
    length_counts = Counter(len(p['bits']) for p in selected)
    prefix_counts = Counter(
        (len(p['bits']), p['bits'][:min(32, len(p['bits']))].tobytes())
        for p in selected
    )
    # Validate/cache catalog definitions once per Analyze Checked click. There
    # is no database round-trip for each message or candidate.
    from .protocol_packet_formats import (
        get_cached_packet_formats, filter_formats_by_length,
    )
    formats = get_cached_packet_formats(library)
    formats_by_length = {}
    # Legacy layout candidates are also prepared once per distinct length.
    from .protocol_packet_signatures import library_layout_candidates
    layouts_by_length = {}
    for packet in selected:
        length = len(packet['bits'])
        if length not in layouts_by_length:
            formats_by_length[length] = filter_formats_by_length(formats, length)
            layouts_by_length[length] = library_layout_candidates(
                packet['bits'], library, limit=3
            )
    results = {}
    for packet in selected:
        length = len(packet['bits'])
        prefix = packet['bits'][:min(32, length)].tobytes()
        stats = (length_counts[length] - 1,
                 prefix_counts[(length, prefix)] - 1,
                 min(32, length)) if len(selected) > 1 else None
        results[packet['uid']] = analyze_packet(
            packet, peer_summary=stats, layout_candidates=layouts_by_length[length],
            formats=formats_by_length[length],
        )
    return results