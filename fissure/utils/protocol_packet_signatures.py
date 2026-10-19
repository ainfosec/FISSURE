"""Independent, Qt-free packet-format validators for Protocol Discovery.

Every candidate exposes the checks behind its ranking. A structural fit from
legacy Library fields is not treated as protocol identity. Bit indices are
zero-based and field ranges are half-open.

Reference implementation for the supported TPMS profile:
https://github.com/cpoore1/gr-tpms_poore (maint-3.10, README)
"""

def _bits_as_text(bits):
    return ''.join(str(int(x)) for x in bits)


def _evidence(name, expected, observed, outcome, explanation, span=None):
    return dict(name=name, expected=str(expected), observed=str(observed),
                outcome=outcome, explanation=explanation, span=span)


def crc8_poore(bits):
    """TPMS CRC-8, poly 0x13, MSB-first, init 0, over 6 zero bits + 58 data bits.

    This function expects exactly the 58 payload bits preceding the CRC. No
    generic CRC polynomial or bit-offset search is performed to claim a match.
    """
    if len(bits) != 58:
        raise ValueError('TPMS CRC input must contain exactly 58 bits')
    crc = 0
    for bit in (0, 0, 0, 0, 0, 0, *[int(x) for x in bits]):
        feedback = ((crc >> 7) ^ bit) & 1
        crc = (crc << 1) & 255
        if feedback:
            crc ^= 0x13
    return crc


def validate_tpms_poore(bits, metadata=None):
    """Recognize the 66-bit TPMS profile described by gr-tpms_poore.

    Length alone never produces a candidate. Both CRC and complementary
    pressure octet are checked using *predefined* parameters. Partial matches
    are explicitly described as possible formats, never confirmed identities.
    """
    if len(bits) != 66:
        return None
    raw = _bits_as_text(bits)
    id_value = int(raw[0:28], 2)
    battery = int(raw[28], 2)
    count = int(raw[29:31], 2)
    unknown1 = int(raw[31], 2)
    unknown2 = int(raw[32], 2)
    self_test = int(raw[33], 2)
    pressure = int(raw[34:42], 2)
    pressure_comp = int(raw[42:50], 2)
    temperature = int(raw[50:58], 2)
    received_crc = int(raw[58:66], 2)
    calculated_crc = crc8_poore(bits[:58])
    crc_ok = received_crc == calculated_crc
    complement_ok = (pressure ^ pressure_comp) == 0xFF
    psi = (pressure - 40) * 0.363
    celsius = temperature - 40
    pressure_plausible = 0 <= psi <= 150
    temp_plausible = -40 <= celsius <= 125
    # A degenerate all-zero record has a trivial CRC=0. Do not identify it.
    # A single independent match is only a tentative candidate when the
    # remaining decoded measurements are plausible.
    if not complement_ok and not (crc_ok and pressure_plausible and temp_plausible):
        return None
    checks = [
        _evidence('Packet length', '66 decoded bits', f'{len(bits)} bits', 'Match',
                  'Matches this specific fixed-width sensor-status profile.', (0, 66)),
        _evidence('Pressure complement', 'Pressure XOR complement = 0xFF',
                  f'0x{pressure:02X} XOR 0x{pressure_comp:02X} = 0x{pressure ^ pressure_comp:02X}',
                  'Match' if complement_ok else 'Mismatch',
                  'An independently specified inverted pressure octet follows the pressure field.', (34, 50)),
        _evidence('CRC-8 / 0x13', f'0x{calculated_crc:02X}', f'0x{received_crc:02X}',
                  'Match' if crc_ok else 'Mismatch',
                  'CRC-8 polynomial 0x13, initial value 0, MSB-first, over six leading zero bits and the first 58 packet bits. Parameters are fixed by the known TPMS profile, not fitted to this packet.', (58, 66)),
        _evidence('Pressure range', '0–150 PSI (plausibility only)', f'{psi:.3f} PSI',
                  'Compatible' if pressure_plausible else 'Mismatch',
                  'A physically plausible value alone does not establish field identity.', (34, 42)),
        _evidence('Temperature range', '-40 to 125 °C (plausibility only)', f'{celsius} °C',
                  'Compatible' if temp_plausible else 'Mismatch',
                  'The stored temperature byte is the Celsius value plus 40.', (50, 58)),
    ]
    modulation = str((metadata or {}).get('modulation') or '').upper()
    if modulation:
        checks.append(_evidence('Modulation context', 'FSK-family transmission', modulation,
                                'Compatible' if 'FSK' in modulation else 'Mismatch',
                                'This context came from demodulation; it is not inferred from packet bytes.'))
    strong = crc_ok and complement_ok and pressure_plausible and temp_plausible
    strength = 'Strong' if strong else 'Possible'
    match_details = ('specified CRC and pressure complement both match' if crc_ok and complement_ok
                     else 'CRC agrees but pressure complement fails' if crc_ok
                     else 'pressure complement agrees but CRC fails')

    def field(name, start, width, value, meaning):
        return dict(name=name, start=start, length=width, value=value, meaning=meaning)

    fields = [
        field('Sensor ID', 0, 28, f'0x{id_value:07X}', '28-bit sensor identifier'),
        field('Battery Status', 28, 1, battery, 'Bit meaning not independently confirmed for this sensor'),
        field('Counter', 29, 2, count, 'Observed two-bit counter; behavior not independently validated'),
        field('Unknown 1', 31, 1, unknown1, 'Undocumented single-bit field'),
        field('Unknown 2', 32, 1, unknown2, 'Undocumented single-bit field'),
        field('Self-Test Flag', 33, 1, self_test, 'Possible self-test failure/rapid pressure change flag'),
        field('Pressure', 34, 8, f'{psi:.3f} PSI', '(raw - 40) × 0.363; profile-specific'),
        field('Pressure Complement', 42, 8, f'0x{pressure_comp:02X}',
              'Bitwise inverse of the pressure byte' if complement_ok else 'Unexpected complement'),
        field('Temperature', 50, 8, f'{celsius} °C', 'Raw byte minus 40'),
        field('CRC-8', 58, 8, 'Valid' if crc_ok else 'Mismatch',
              f'Received 0x{received_crc:02X}; calculated 0x{calculated_crc:02X}'),
    ]
    return dict(protocol='TPMS (gr-tpms_poore profile)', message_type='Sensor status',
                strength=strength, summary=f'66-bit packet; {match_details}.',
                checks=checks, fields=fields, verified=strong, source='reference_validator')


def library_layout_candidates(bits, library, limit=3):
    """Return bounded, unverified layout fits to legacy cached packet_types.

    Existing FISSURE Library rows: [id, protocol, packet_name, dissector,
    field_dict, sort_order]. Default Value is NOT assumed to be a constant.
    Field order is Sort Order; lengths give structure but not a fingerprint.
    """
    if not isinstance(library, dict):
        return []
    rows = library.get('packet_types') or []
    length = len(bits)
    if length < 4 or length > 8192:
        return []
    found = []
    seen = set()
    for row in rows:
        if not isinstance(row, (list, tuple)) or len(row) < 5 or not isinstance(row[4], dict):
            continue
        protocol, name, definitions = str(row[1]), str(row[2]), row[4]
        key = (protocol, name)
        if key in seen or not definitions:
            continue
        parts = []
        try:
            parts = sorted(definitions.items(), key=lambda item: int(item[1].get('Sort Order', 0)))
            sizes = [int(f.get('Length', 0)) for _, f in parts]
        except (ValueError, TypeError, AttributeError):
            continue
        if any(value <= 0 for value in sizes) or sum(sizes) != length:
            continue
        seen.add(key)
        fields = []
        offset = 0
        for field_name, field_data in parts:
            size = int(field_data['Length'])
            fields.append(dict(name=str(field_name), start=offset, length=size,
                               value=None, meaning='Library field layout; interpretation not verified'))
            offset += size
        checks = [
            _evidence('Packet length', f'{length} bits (Library layout)', f'{length} bits', 'Match',
                      'Sum of Library field lengths matches captured length. Other formats may have the same length.', (0, length)),
            _evidence('Library fields', f'{len(fields)} ordered fields', f'{len(fields)} layout fields', 'Compatible',
                      'These are stored names and lengths, not independently observed boundaries.'),
            _evidence('Fixed markers', 'Independent fixed signature', 'No fixed-value semantics stored', 'Not evaluated',
                      'Legacy Default Value entries are editable starting values, not guaranteed constants.'),
            _evidence('Checksum', 'Known algorithm and coverage', 'Not specified by the legacy layout', 'Not evaluated',
                      'A CRC flag alone is insufficient to validate this packet.'),
        ]
        found.append(dict(protocol=protocol, message_type=name, strength='Structural only',
                          summary=f'Library layout fits {length} bits; identity unverified.',
                          checks=checks, fields=fields, verified=False, source='library_layout'))
        if len(found) >= limit:
            break
    return found
