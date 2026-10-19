"""Qt-free, database-independent packet format validation (schema version 1).

The hub loads *enabled* definitions into its existing Library cache. This
module consumes copied rows or dicts, and can also run on a sensor node with a
small versioned bundle. There are no SQL calls, eval(), or protocol-specific
algorithms here. Definitions describe fixed-offset fields and bounded rules.

All bit offsets are zero-based, with [start, start + length) spans.
"""

import hashlib
import json
import re


SCHEMA_VERSION = 1
MAX_FORMAT_JSON_BYTES = 65536
MAX_FORMAT_FIELDS = 256
MAX_FORMAT_CHECKS = 128
FORMAT_COLUMNS = (
    'id', 'format_key', 'protocol_name', 'format_name', 'protocol_id',
    'packet_type_id', 'revision', 'schema_version', 'enabled',
    'validation_status', 'definition', 'reference', 'notes',
    'created_at', 'updated_at',
)
SUPPORTED_RULES = {'complement', 'crc', 'range', 'fixed_bits', 'frame_length', 'counted_pairs'}


def _integer(value, name, *, minimum=0, maximum=1_000_000):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f'{name} must be an integer in [{minimum}, {maximum}]')
    return value


def _number(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f'{name} must be numeric')
    number = float(value)
    if not -1e12 < number < 1e12:
        raise ValueError(f'{name} is out of range')
    return number


def validate_definition(definition):
    """Validate bounded declarative formats, including variable-length frames.

    All offsets are zero-based. A field may use a fixed start or an offset
    counted backwards from the packet end, never both. No Python expressions
    are evaluated from the database.
    """
    if not isinstance(definition, dict):
        raise ValueError('definition must be a JSON object')
    serialized = json.dumps(definition, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    if len(serialized.encode('utf-8')) > MAX_FORMAT_JSON_BYTES:
        raise ValueError('definition exceeds 64 KiB')
    if definition.get('schema_version') != SCHEMA_VERSION:
        raise ValueError(f'unsupported packet format schema_version (expected {SCHEMA_VERSION})')
    length = definition.get('length')
    if not isinstance(length, dict):
        raise ValueError('length must be an object')
    if 'exact_bits' in length:
        minimum = maximum = _integer(length['exact_bits'], 'length.exact_bits', minimum=1)
    else:
        minimum = _integer(length.get('min_bits'), 'length.min_bits', minimum=1)
        maximum = _integer(length.get('max_bits'), 'length.max_bits', minimum=minimum)
    fields = definition.get('fields')
    if not isinstance(fields, list) or not 1 <= len(fields) <= MAX_FORMAT_FIELDS:
        raise ValueError('fields must contain 1 to 256 field definitions')
    known_fields = {}
    for field in fields:
        if not isinstance(field, dict) or not isinstance(field.get('key'), str):
            raise ValueError('each field needs a string key')
        key = field['key']
        if not re.fullmatch(r'[a-z][a-z0-9_]*', key) or key in known_fields:
            raise ValueError(f'duplicate or invalid field key {key!r}')
        if not isinstance(field.get('name'), str) or not field['name'].strip():
            raise ValueError(f'{key}: field needs a nonempty name')
        width = _integer(field.get('length'), f'{key}.length', minimum=1, maximum=4096)
        if ('start' in field) == ('from_end_bits' in field):
            raise ValueError(f'{key}: specify exactly one of start/from_end_bits')
        if 'start' in field:
            start = _integer(field['start'], f'{key}.start')
            if start + width > minimum:
                raise ValueError(f'{key}: field exceeds minimum packet length')
        else:
            trailing = _integer(field['from_end_bits'], f'{key}.from_end_bits', minimum=width)
            if trailing > minimum:
                raise ValueError(f'{key}: end-relative field exceeds minimum packet length')
        render = field.get('render', 'integer')
        if render not in ('hex', 'integer', 'binary', 'linear', 'check_status'):
            raise ValueError(f'{key}: unknown render {render!r}')
        if render == 'linear':
            _number(field.get('offset', 0), f'{key}.offset')
            _number(field.get('scale', 1), f'{key}.scale')
            _integer(field.get('precision', 0), f'{key}.precision', maximum=8)
        if render == 'check_status' and not isinstance(field.get('check'), str):
            raise ValueError(f'{key}: check_status needs a check ID')
        known_fields[key] = field
    checks = definition.get('checks')
    if not isinstance(checks, list) or not 1 <= len(checks) <= MAX_FORMAT_CHECKS:
        raise ValueError('checks must contain 1 to 128 validation rules')
    known_checks = {}
    for rule in checks:
        if not isinstance(rule, dict) or not isinstance(rule.get('id'), str):
            raise ValueError('each check needs a string ID')
        key = rule['id']
        if not re.fullmatch(r'[a-z][a-z0-9_]*', key) or key in known_checks:
            raise ValueError(f'bad or duplicate check ID {key!r}')
        kind = rule.get('type')
        if kind not in SUPPORTED_RULES:
            raise ValueError(f'{key}: unsupported rule {kind!r}')
        if rule.get('category') not in ('identity', 'plausibility'):
            raise ValueError(f'{key}: category must be identity or plausibility')
        if not isinstance(rule.get('name'), str) or not rule['name'].strip():
            raise ValueError(f'{key}: needs a display name')
        if kind in ('complement', 'range', 'frame_length', 'counted_pairs'):
            if rule.get('field') not in known_fields:
                raise ValueError(f'{key}: unknown field')
        if kind == 'complement':
            other = rule.get('complement_field')
            if other not in known_fields or known_fields[other]['length'] != known_fields[rule['field']]['length']:
                raise ValueError(f'{key}: complement fields must exist and be equal widths')
        if kind == 'range':
            if _number(rule.get('min'), f'{key}.min') > _number(rule.get('max'), f'{key}.max'):
                raise ValueError(f'{key}: reversed range')
        if kind == 'fixed_bits':
            start = _integer(rule.get('start'), f'{key}.start')
            pattern = rule.get('value')
            mask = rule.get('mask', '1' * len(pattern)) if isinstance(pattern, str) else None
            if not isinstance(pattern, str) or not pattern or set(pattern) - {'0', '1'}:
                raise ValueError(f'{key}: fixed_bits value must be a nonempty bit string')
            if not isinstance(mask, str) or len(mask) != len(pattern) or set(mask) - {'0', '1'}:
                raise ValueError(f'{key}: fixed_bits mask must match the value bit width')
            if start + len(pattern) > minimum:
                raise ValueError(f'{key}: fixed bit check exceeds minimum packet length')
        if kind == 'crc':
            width = _integer(rule.get('width'), f'{key}.width', minimum=1, maximum=32)
            mask = (1 << width) - 1
            _integer(rule.get('polynomial'), f'{key}.polynomial', minimum=1, maximum=mask)
            _integer(rule.get('init'), f'{key}.init', maximum=mask)
            _integer(rule.get('xor_out', 0), f'{key}.xor_out', maximum=mask)
            _integer(rule.get('leading_zero_bits', 0), f'{key}.leading_zero_bits', maximum=1024)
            data_start = _integer(rule.get('data_start'), f'{key}.data_start')
            field_name = rule.get('checksum_field')
            if field_name not in known_fields or known_fields[field_name]['length'] != width:
                raise ValueError(f'{key}: CRC checksum field missing or incorrect width')
            to_checksum = rule.get('data_end_at_checksum', False)
            if type(to_checksum) is not bool:
                raise ValueError(f'{key}: data_end_at_checksum must be boolean')
            if to_checksum:
                if 'data_length' in rule:
                    raise ValueError(f'{key}: dynamic CRC cannot also specify data_length')
                if 'from_end_bits' not in known_fields[field_name]:
                    raise ValueError(f'{key}: dynamic CRC needs an end-relative checksum field')
                if data_start >= minimum - known_fields[field_name]['from_end_bits']:
                    raise ValueError(f'{key}: dynamic CRC data region is empty')
            else:
                data_length = _integer(rule.get('data_length'), f'{key}.data_length', minimum=1)
                if data_start + data_length > minimum:
                    raise ValueError(f'{key}: invalid CRC data span')
        if kind == 'frame_length':
            _integer(rule.get('exclude_leading_bytes', 0), f'{key}.exclude_leading_bytes',
                     maximum=(minimum // 8) - 1)
            if minimum % 8 or maximum % 8:
                raise ValueError(f'{key}: frame_length requires byte-aligned length bounds')
        if kind == 'counted_pairs':
            overhead = _integer(rule.get('fixed_overhead_bytes'), f'{key}.fixed_overhead_bytes', minimum=1)
            _integer(rule.get('bytes_per_item'), f'{key}.bytes_per_item', minimum=1, maximum=64)
            if overhead * 8 >= minimum:
                raise ValueError(f'{key}: overhead must leave room for items')
        known_checks[key] = rule
    for field in fields:
        if field.get('render') == 'check_status' and field['check'] not in known_checks:
            raise ValueError(f"{field['key']}: unknown check_status rule")
    policy = definition.get('match_policy')
    if not isinstance(policy, dict) or not isinstance(policy.get('candidate_any'), list):
        raise ValueError('match_policy.candidate_any must contain alternatives')
    alternatives = policy['candidate_any']
    if not alternatives or len(alternatives) > 32:
        raise ValueError('match_policy.candidate_any requires 1 to 32 alternatives')
    for branch in alternatives:
        if not isinstance(branch, list) or not branch or any(c not in known_checks for c in branch):
            raise ValueError('candidate_any contains an unknown/empty check branch')
        if not any(known_checks[c]['category'] == 'identity' for c in branch):
            raise ValueError('each candidate branch must require independent identity evidence')
    strong = policy.get('strong_all')
    if not isinstance(strong, list) or not strong or any(c not in known_checks for c in strong):
        raise ValueError('match_policy.strong_all must name known checks')
    if not any(known_checks[c]['category'] == 'identity' for c in strong):
        raise ValueError('strong_all requires identity evidence')
    reject = policy.get('reject_on_failure', [])
    if (not isinstance(reject, list) or any(not isinstance(c, str) or c not in known_checks for c in reject)
            or len(reject) != len(set(reject))):
        raise ValueError('match_policy.reject_on_failure must list distinct known check IDs')
    if any(known_checks[c]['category'] != 'identity' for c in reject):
        raise ValueError('reject_on_failure may only list identity checks')
    return definition


def validate_format_record(record):
    """Validate the distributable record, not just its nested JSON rules."""
    if not isinstance(record, dict):
        raise ValueError('format record must be an object')
    key = record.get('format_key')
    if not isinstance(key, str) or not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,159}', key):
        raise ValueError('format_key requires 1–160 lowercase letters/digits/._-')
    for name in ('protocol_name', 'format_name'):
        if not isinstance(record.get(name), str) or not record[name].strip():
            raise ValueError(f'{key}: missing {name}')
    _integer(record.get('revision'), 'revision', minimum=1)
    if record.get('schema_version') != SCHEMA_VERSION:
        raise ValueError(f'{key}: unsupported schema_version')
    if type(record.get('enabled')) is not bool:
        raise ValueError(f'{key}: enabled must be boolean')
    if record.get('validation_status') not in ('draft', 'experimental', 'verified'):
        raise ValueError(f'{key}: invalid validation_status')
    validate_definition(record.get('definition'))
    return record


def get_cached_packet_formats(library):
    """Normalize current HIPRFISR Library rows; no database access occurs here."""
    if not isinstance(library, dict):
        return []
    records = []
    for row in library.get('packet_formats') or []:
        if isinstance(row, dict):
            record = dict(row)
        elif isinstance(row, (list, tuple)) and len(row) >= len(FORMAT_COLUMNS):
            record = dict(zip(FORMAT_COLUMNS, row))
        else:
            raise ValueError('Malformed packet_formats Library cache row')
        if not record.get('enabled'):
            continue
        definition = record.get('definition')
        if isinstance(definition, str):
            record['definition'] = json.loads(definition)
        validate_format_record(record)
        records.append(record)
    return sorted(records, key=lambda item: item['format_key'])


def _fits_length(definition, bit_count):
    length = definition['length']
    if 'exact_bits' in length:
        return bit_count == length['exact_bits']
    return length['min_bits'] <= bit_count <= length['max_bits']


def filter_formats_by_length(formats, bit_count):
    """Cheap candidate prefilter; filtering never establishes identity."""
    return [record for record in formats
            if _fits_length(record['definition'], bit_count)]


def _crc_msb(bit_text, rule):
    """Generic direct MSB-first CRC, including fixed leading-zero padding."""
    width = rule['width']
    mask = (1 << width) - 1
    value = rule['init']
    text = '0' * rule.get('leading_zero_bits', 0) + bit_text[
        rule['data_start']:rule['data_start'] + rule['data_length']]
    for character in text:
        feedback = ((value >> (width - 1)) ^ int(character)) & 1
        value = (value << 1) & mask
        if feedback:
            value ^= rule['polynomial']
    return value ^ rule.get('xor_out', 0)


def _format_value(field, raw_integer):
    render = field.get('render', 'integer')
    if render == 'hex':
        width = (field['length'] + 3) // 4
        return f'0x{raw_integer:0{width}X}', raw_integer
    if render == 'binary':
        return f'{raw_integer:0{field["length"]}b}', raw_integer
    if render == 'linear':
        transformed = (raw_integer + field.get('offset', 0)) * field.get('scale', 1)
        precision = field.get('precision', 0)
        unit = field.get('unit', '')
        return f'{transformed:.{precision}f}' + (f' {unit}' if unit else ''), transformed
    return raw_integer, raw_integer


def _check_result(rule, bit_text, raw_fields, decoded_fields):
    """Evaluate a declared rule. Structural compatibility never proves identity."""
    kind = rule['type']
    if kind == 'complement':
        field, other = rule['field'], rule['complement_field']
        left, right = raw_fields[field], raw_fields[other]
        width = next(f['length'] for f in decoded_fields if f['key'] == field)
        expected = (1 << width) - 1
        actual = left ^ right
        return actual == expected, f'XOR = 0x{expected:X}', f'0x{left:X} XOR 0x{right:X} = 0x{actual:X}', None
    if kind == 'crc':
        calc_rule = rule
        if rule.get('data_end_at_checksum'):
            checksum = next(f for f in decoded_fields if f['key'] == rule['checksum_field'])
            calc_rule = dict(rule, data_length=checksum['start'] - rule['data_start'])
        calculated = _crc_msb(bit_text, calc_rule)
        received = raw_fields[rule['checksum_field']]
        hex_width = (rule['width'] + 3) // 4
        return (calculated == received, f'0x{calculated:0{hex_width}X}',
                f'0x{received:0{hex_width}X}', (calculated, received))
    if kind == 'range':
        value = next(f['numeric'] for f in decoded_fields if f['key'] == rule['field'])
        lower, upper = rule['min'], rule['max']
        unit = rule.get('unit', '')
        return (lower <= value <= upper, f'{lower} to {upper}' + (f' {unit}' if unit else ''),
                f'{value:g}' + (f' {unit}' if unit else ''), None)
    if kind == 'fixed_bits':
        start, target = rule['start'], rule['value']
        mask = rule.get('mask', '1' * len(target))
        actual = bit_text[start:start + len(target)]
        ok = all(m == '0' or expected == observed for m, expected, observed in zip(mask, target, actual))
        return ok, f'{target} (mask {mask})', actual, None
    if kind == 'frame_length':
        excluded = rule.get('exclude_leading_bytes', 0)
        total = len(bit_text)
        declared = raw_fields[rule['field']]
        actual = (total // 8) - excluded if total % 8 == 0 else None
        return (actual is not None and actual == declared,
                f'{declared} declared frame bytes',
                f'{actual} observed frame bytes' if actual is not None else 'Not byte-aligned', None)
    if kind == 'counted_pairs':
        count = raw_fields[rule['field']]
        overhead = rule['fixed_overhead_bytes']
        width = rule['bytes_per_item']
        expected = overhead + count * width
        actual = len(bit_text) // 8 if len(bit_text) % 8 == 0 else None
        return (actual == expected,
                f'{count} items × {width} bytes + {overhead} overhead = {expected} bytes',
                f'{actual} observed bytes' if actual is not None else 'Not byte-aligned', None)
    raise ValueError(f'unsupported rule {kind}')


def analyze_format(bits, record, metadata=None, *, unframed=False):
    """Evaluate one predeclared format against a complete packet (no brute-force CRC search)."""
    definition = record['definition']
    bit_count = len(bits)
    if not _fits_length(definition, bit_count):
        return None
    raw = ''.join(str(int(b)) for b in bits)
    raw_fields = {}
    decoded_fields = []
    for field in definition['fields']:
        start = field['start'] if 'start' in field else bit_count - field['from_end_bits']
        width = field['length']
        value = int(raw[start:start + width], 2)
        raw_fields[field['key']] = value
        display, numeric = _format_value(field, value)
        decoded_fields.append(dict(key=field['key'], name=field['name'], start=start,
                                   length=width, value=display, numeric=numeric,
                                   meaning=field.get('meaning', '')))
    checks, passed, computed_crc = [], {}, {}
    for rule in definition['checks']:
        ok, expected, observed, extra = _check_result(rule, raw, raw_fields, decoded_fields)
        passed[rule['id']] = ok
        if rule['type'] == 'crc':
            computed_crc[rule['id']] = extra
        outcome = ('Match' if ok else 'Mismatch') if rule['category'] == 'identity' else (
            'Compatible' if ok else 'Mismatch')
        span = None
        if rule['type'] == 'crc':
            field = next(f for f in decoded_fields if f['key'] == rule['checksum_field'])
            span = (field['start'], field['start'] + field['length'])
        elif rule['type'] == 'complement':
            left = next(f for f in decoded_fields if f['key'] == rule['field'])
            right = next(f for f in decoded_fields if f['key'] == rule['complement_field'])
            span = (min(left['start'], right['start']),
                    max(left['start'] + left['length'], right['start'] + right['length']))
        elif rule['type'] in ('range', 'frame_length', 'counted_pairs'):
            field = next(f for f in decoded_fields if f['key'] == rule['field'])
            span = (field['start'], field['start'] + field['length'])
        elif rule['type'] == 'fixed_bits':
            span = (rule['start'], rule['start'] + len(rule['value']))
        checks.append(dict(name=rule['name'], expected=expected, observed=observed,
                           outcome=outcome, explanation=rule.get('explanation', ''), span=span))
    policy = definition['match_policy']
    eligible = any(all(passed[check_id] for check_id in branch)
                   for branch in policy['candidate_any'])
    if not eligible:
        return None
    failed_required = [check_id for check_id in policy.get('reject_on_failure', [])
                       if not passed[check_id]]
    strong = (not failed_required and all(passed[check_id] for check_id in policy['strong_all']))
    strong = strong and record['validation_status'] == 'verified' and not unframed
    strength = 'Rejected' if failed_required else 'Strong' if strong else 'Possible'
    if failed_required:
        rejected_names = [next(rule['name'] for rule in definition['checks'] if rule['id'] == check_id)
                          for check_id in failed_required]
        checks.append(dict(name='Identification decision',
                           expected='All required identity checks pass',
                           observed='Failed: ' + ', '.join(rejected_names), outcome='Rejected',
                           explanation=('This packet fails one or more predeclared identity checks. '
                                        'It may be damaged, misframed, or a different format.'), span=None))
    for field in decoded_fields:
        source = next(f for f in definition['fields'] if f['key'] == field['key'])
        if source.get('render') == 'check_status':
            check_id = source['check']
            field['value'] = 'Valid' if passed[check_id] else 'Mismatch'
            if check_id in computed_crc:
                expected, received = computed_crc[check_id]
                field['meaning'] = f'Received 0x{received:X}; calculated 0x{expected:X}'
        field.pop('numeric', None)
        field.pop('key', None)
    checks.insert(0, dict(name='Packet length',
                          expected=(f"{definition['length']['exact_bits']} bits"
                                    if 'exact_bits' in definition['length'] else
                                    f"{definition['length']['min_bits']}–{definition['length']['max_bits']} bits"),
                          observed=f'{bit_count} bits', outcome='Match',
                          explanation='Matches the predeclared format length constraint.', span=(0, bit_count)))
    modulation = str((metadata or {}).get('modulation') or '').upper()
    context = definition.get('signal_context') or {}
    hints = context.get('modulation_contains_any') or []
    if modulation and hints:
        matches = any(str(hint).upper() in modulation for hint in hints)
        checks.append(dict(name='Modulation context', expected=' / '.join(hints),
                           observed=modulation, outcome='Compatible' if matches else 'Mismatch',
                           explanation='Demodulator context, not independent identity evidence.', span=None))
    if unframed:
        checks.append(dict(name='Frame boundaries', expected='Verified packet boundary',
                           observed='Unframed RF activity segment', outcome='Unknown',
                           explanation='Potential match is downgraded until frame boundaries are confirmed.', span=None))
    definition_digest = hashlib.sha256(json.dumps(definition, sort_keys=True,
        separators=(',', ':'), ensure_ascii=False).encode('utf-8')).hexdigest()
    checks.insert(1, dict(name='Format provenance', expected='Predeclared Library definition',
                          observed=f"{record['format_key']} r{record['revision']}", outcome='Reference',
                          explanation=(f"Validation status: {record['validation_status']}. "
                                       f"Schema version: {record['schema_version']}. "
                                       f"Definition SHA-256: {definition_digest}. "
                                       'Definition status is not packet identity.'), span=None))
    identity = [r for r in definition['checks'] if r['category'] == 'identity']
    passed_identity = sum(passed[r['id']] for r in identity)
    summary = f'{bit_count}-bit packet; {passed_identity}/{len(identity)} predeclared identity checks pass.'
    if failed_required:
        summary += ' Rejected: required check(s) failed: ' + ', '.join(rejected_names) + '.'
    elif unframed:
        summary += ' Boundaries unverified.'
    return dict(protocol=record['protocol_name'], message_type=record['format_name'],
                strength=strength, summary=summary, checks=checks, fields=decoded_fields,
                verified=strong, source='format_definition',
                format_key=record['format_key'], format_revision=record['revision'],
                format_schema_version=record['schema_version'], format_digest=definition_digest,
                definition_validation_status=record['validation_status'])


def analyze_cached_formats(bits, formats, metadata=None, *, unframed=False, limit=12):
    """Identify matching formats; preserve alternatives and avoid percentages."""
    candidates = []
    for record in formats:
        candidate = analyze_format(bits, record, metadata=metadata, unframed=unframed)
        if candidate is not None:
            candidates.append(candidate)
    candidates.sort(key=lambda candidate: (
        {'Strong': 0, 'Possible': 1, 'Rejected': 2}.get(candidate['strength'], 3),
        candidate['definition_validation_status'] != 'verified',
        candidate['format_key'],
    ))
    return candidates[:limit]
