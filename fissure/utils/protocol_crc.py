"""CRC Analysis core. No Qt, RF hardware, database, or global state.

Bit intervals are zero-based, half-open. Bits are in capture order (MSB first
within each displayed octet); incomplete final octets are never padded.

RevEng supplies the standard model catalogue and the discovery engine; local
bitwise evaluation makes per-sample verification fast and supports exact bits.
"""

from dataclasses import dataclass
import os
import re
import shutil
import subprocess

MAX_CRC_WIDTH = 128
MAX_PACKET_BITS = 1_000_000
MAX_SAMPLES = 500
_MODEL_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


@dataclass(frozen=True)
class CRCModel:
    name: str
    width: int
    poly: int
    init: int
    refin: bool
    refout: bool
    xorout: int

    def __post_init__(self):
        if not 1 <= self.width <= MAX_CRC_WIDTH:
            raise ValueError('CRC width must be between 1 and 128 bits')
        limit = 1 << self.width
        if not 0 < self.poly < limit:
            raise ValueError('Polynomial must be nonzero and fit the width')
        if not 0 <= self.init < limit or not 0 <= self.xorout < limit:
            raise ValueError('Init and final XOR must fit the CRC width')

    def definition(self):
        digits = (self.width + 3) // 4
        return (f'width={self.width} poly=0x{self.poly:0{digits}x} '
                f'init=0x{self.init:0{digits}x} refin={str(self.refin).lower()} '
                f'refout={str(self.refout).lower()} '
                f'xorout=0x{self.xorout:0{digits}x} name="{self.name}"')


def parse_model(line):
    """Parse a Williams/RevEng model record, not arbitrary terminal output."""
    fields = dict(_MODEL_RE.findall(line))
    required = {'width', 'poly', 'init', 'refin', 'refout', 'xorout'}
    if not required.issubset(fields):
        raise ValueError('Incomplete RevEng model record')
    return CRCModel(fields.get('name', '(custom)').strip('"'), int(fields['width']),
                    int(fields['poly'], 16), int(fields['init'], 16),
                    fields['refin'].lower() == 'true', fields['refout'].lower() == 'true',
                    int(fields['xorout'], 16))


def reflect(value, width):
    return int(f'{value:0{width}b}'[::-1], 2)


def bits_from_input(text, mode='Auto'):
    """Accept hex by default; explicit 0b:/0b/b: denotes binary.

    A suffix ``[bits:101]`` preserves incomplete last octets in a hex
    representation. The plain value ``10101010`` is eight hex digits, not
    silently reinterpreted as eight binary bits.
    """
    value = str(text).strip()
    if not value:
        raise ValueError('Enter packet data')
    if mode == 'Auto':
        mode = 'Bits' if re.match(r'^(?:0[bB]|[bB]:)', value) else 'Hex'
    if mode == 'Bits':
        value = re.sub(r'^(?:0[bB]|[bB]:)', '', value)
        value = re.sub(r'[\s_,]', '', value)
        if not re.fullmatch('[01]+', value):
            raise ValueError('Binary input contains characters other than 0 and 1')
        result = value
    else:
        suffix = re.search(r'\[bits:([01]+)\]\s*$', value, re.I)
        tail = suffix.group(1) if suffix else ''
        if suffix:
            value = value[:suffix.start()]
        value = re.sub(r'^0[xX]', '', value.strip())
        value = re.sub(r'[\s:,_]', '', value)
        if value and not re.fullmatch('[0-9a-fA-F]+', value):
            raise ValueError('Invalid hexadecimal packet data')
        if not value and not tail:
            raise ValueError('Enter packet data')
        result = ''.join(f'{int(char, 16):04b}' for char in value) + tail
    if len(result) > MAX_PACKET_BITS:
        raise ValueError('Packet exceeds one million bits')
    return result


def hex_preview(bits, max_bytes=32):
    whole = len(bits) // 8 * 8
    text = ' '.join(f'{int(bits[i:i+8], 2):02X}' for i in range(0, min(whole, max_bytes*8), 8))
    if whole > max_bytes*8:
        text += ' ...'
    elif len(bits) > whole:
        text += f' [bits:{bits[whole:]}]'
    return text.strip()


def crc_bits(bits, model):
    """Williams CRC over captured octets, then any exact remaining bits.

    For RefIn each complete input octet is reflected before being shifted into
    the MSB-first register. A short final fragment is processed as single bits;
    it is not fabricated into a byte. RevEng's -a 1 is likewise a bitstream
    operation, separate from its normal -a 8 character interpretation.
    """
    if not bits or set(bits) - {'0', '1'}:
        raise ValueError('CRC input must be nonempty binary data')
    mask = (1 << model.width) - 1
    register = model.init
    full = len(bits) // 8 * 8
    for pos in range(0, len(bits), 8):
        group = bits[pos:min(pos + 8, len(bits))]
        if model.refin and pos < full:
            group = group[::-1]
        for char in group:
            top = ((register >> (model.width - 1)) & 1) ^ int(char)
            register = (register << 1) & mask
            if top:
                register ^= model.poly
    if model.refout:
        register = reflect(register, model.width)
    return (register ^ model.xorout) & mask


def crc_hex(value, width):
    return f'{value:0{(width + 3)//4}X}'


def observed_bits_to_int(bits, order):
    if len(bits) % 8 == 0 and len(bits) > 8 and order == 'Little endian':
        bits = ''.join(bits[i:i+8] for i in reversed(range(0, len(bits), 8)))
    return int(bits, 2)


def region(sample, width, field='Trailing field', coverage='Before CRC', order='Big endian'):
    """Return calculation data, extracted expected value, and field span.

    Per-sample field/coverage overrides take precedence over collection defaults.
    The explicit expected value is numeric (not a wire byte sequence).
    """
    bits = sample['bits']
    if not bits or set(bits) - {'0', '1'}:
        raise ValueError('Invalid packet bits')
    source = sample.get('crc_source') or field
    if source == 'Separate value':
        observed = sample.get('expected')
        if observed is not None and not 0 <= int(observed) < (1 << width):
            raise ValueError('Expected CRC does not fit selected width')
        start, end = None, None
        default_end = len(bits)
    else:
        if len(bits) < width:
            raise ValueError('Packet is shorter than selected CRC width')
        if source == 'Leading field':
            start = 0
        elif source == 'Custom offset':
            start = sample.get('crc_start')
            if start is None:
                raise ValueError('Custom CRC field offset is not specified')
            start = int(start)
        else:
            start = len(bits) - width
        end = start + width
        if start < 0 or end > len(bits):
            raise ValueError('CRC field falls outside packet')
        observed = observed_bits_to_int(bits[start:end], sample.get('order') or order)
        default_end = len(bits) if source == 'Leading field' else start
    rule = sample.get('coverage') or coverage
    if rule == 'Entire packet except CRC':
        data = bits if start is None else bits[:start] + bits[end:]
        covers = [(0, len(bits))] if start is None else [(0, start), (end, len(bits))]
    else:
        if rule == 'Custom range':
            begin = int(sample.get('coverage_start', 0))
            stop = int(sample.get('coverage_end', default_end))
        elif rule.startswith('Skip first '):
            count = int(rule.split()[2])
            begin, stop = count * 8, default_end
        else:
            begin, stop = (end if source == 'Leading field' else 0), default_end
        if begin < 0 or stop > len(bits) or begin >= stop:
            raise ValueError('CRC coverage range is empty or outside packet')
        if start is not None and not (stop <= start or begin >= end):
            raise ValueError('CRC-covered range overlaps the CRC field')
        data, covers = bits[begin:stop], [(begin, stop)]
    if not data:
        raise ValueError('No CRC-covered message bits')
    return data, (None if observed is None else int(observed)), (start, end), covers


def calculate_sample(sample, model, field, coverage, order):
    data, observed, span, covers = region(sample, model.width, field, coverage, order)
    result = crc_bits(data, model)
    return {'calculated': result, 'observed': observed, 'span': span,
            'covers': covers, 'status': ('Calculated' if observed is None else
            'Match' if result == observed else 'Fail')}


def locate_reveng():
    """Prefer user's installed RevEng 3.0.5, then PATH."""
    fixed = os.path.expanduser('~/Installed_by_FISSURE/reveng-3.0.5/bin/i386-linux/reveng')
    return fixed if os.path.isfile(fixed) and os.access(fixed, os.X_OK) else shutil.which('reveng')


def load_reveng_models(executable=None):
    executable = executable or locate_reveng()
    if not executable:
        raise FileNotFoundError('RevEng not found in Installed_by_FISSURE or PATH')
    result = subprocess.run([executable, '-D'], capture_output=True, text=True, timeout=12)
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or 'RevEng -D failed')
    models = []
    for line in result.stdout.splitlines():
        if 'width=' in line and 'poly=' in line:
            try:
                models.append(parse_model(line))
            except ValueError:
                continue
    if not models:
        raise ValueError('RevEng -D returned no CRC models')
    return sorted(models, key=lambda model: (model.width, model.name.lower()))


FALLBACK_MODELS = (
    CRCModel('CRC-8/SMBUS', 8, 0x07, 0, False, False, 0),
    CRCModel('CRC-16/MODBUS', 16, 0x8005, 0xffff, True, True, 0),
    CRCModel('CRC-16/IBM-3740', 16, 0x1021, 0xffff, False, False, 0),
    CRCModel('CRC-32/ISO-HDLC', 32, 0x04c11db7, 0xffffffff, True, True, 0xffffffff),
    CRCModel('CRC-32/ISCSI', 32, 0x1edc6f41, 0xffffffff, True, True, 0xffffffff),
)


def search_known(samples, models, widths, field, coverage, orders,
                 *, max_regions=80, max_offset_bytes=4, max_skip_bytes=4,
                 cancelled=lambda: False):
    """Find matching models without counting packet overrides as new hypotheses.

    A search setting only distinguishes candidates when it changes the actual
    CRC field, covered bits, or wire interpretation for at least one packet.
    """
    fits = [s for s in samples if s.get('role', 'Fit') == 'Fit']
    holdouts = [s for s in samples if s.get('role') == 'Holdout']
    if len(fits) < 2:
        raise ValueError('Discovery needs at least two Fit packets')
    candidates = []
    seen = set()
    checked = 0
    eligible_models = [m for m in models if m.width in widths]
    placements = (['Trailing field', 'Leading field'] if field == 'Search ends'
                  else ['Trailing field'] + [f'Trailing -{n} bytes'
                    for n in range(1, max_offset_bytes + 1)] + ['Leading field']
                  if field == 'Search offsets' else [field])
    coverages = (['Before CRC'] + [f'Skip first {n} bytes'
                  for n in range(1, max_skip_bytes + 1)]
                 if coverage == 'Search prefix' else [coverage])
    byte_orders = ('Big endian', 'Little endian') if orders == 'Auto (both)' else (orders,)
    used_packets = fits + holdouts

    def description(setting, key, names):
        overrides = [sample[key] for sample in used_packets if sample.get(key)]
        if not overrides:
            return setting
        if len(overrides) != len(used_packets):
            return setting + ' + packet overrides'
        values = set(names)
        return ('Per-packet: ' + next(iter(values)) if len(values) == 1
                else 'Per-packet overrides')

    for model in eligible_models:
        for placement in placements:
            for cover in coverages:
                for wire_order in byte_orders:
                    if cancelled() or checked >= max_regions * max(1, len(eligible_models)):
                        return candidates, False
                    checked += 1
                    if model.width <= 8 and wire_order == 'Little endian' and orders == 'Auto (both)':
                        continue

                    def evaluate(sample):
                        actual = dict(sample)
                        default_field = placement
                        if placement.startswith('Trailing -'):
                            default_field = 'Custom offset'
                            if not actual.get('crc_source'):
                                offset = int(placement.split('-')[1].split()[0])
                                actual['crc_source'] = 'Custom offset'
                                actual['crc_start'] = len(actual['bits']) - model.width - offset * 8
                        source = actual.get('crc_source') or default_field
                        rule = actual.get('coverage') or cover
                        order = actual.get('order') or wire_order
                        result = calculate_sample(actual, model, default_field, cover, wire_order)
                        # Use the field and covered bit intervals returned by region(),
                        # not the proposed defaults, to identify a hypothesis.
                        signature = (tuple(result['span']),
                                     tuple(tuple(pair) for pair in result['covers']),
                                     order if model.width > 8 and model.width % 8 == 0
                                     else 'order irrelevant')
                        return result, signature, source, rule, order

                    evaluated = []
                    for sample in fits:
                        try:
                            evaluated.append(evaluate(sample))
                        except (ValueError, TypeError):
                            break
                    if (len(evaluated) != len(fits) or
                            any(row[0]['status'] != 'Match' for row in evaluated)):
                        continue
                    verified = []
                    for sample in holdouts:
                        try:
                            verified.append(evaluate(sample))
                        except (ValueError, TypeError):
                            verified.append(({'status': 'Error'}, ('error', id(sample)),
                                             None, None, None))
                    signature = tuple(row[1] for row in evaluated + verified)
                    key = (model, signature)
                    if key in seen:
                        continue
                    seen.add(key)

                    rows = evaluated + verified
                    field_label = description(placement, 'crc_source', [r[2] for r in rows])
                    coverage_label = description(cover, 'coverage', [r[3] for r in rows])
                    order_label = description(wire_order, 'order', [r[4] for r in rows])
                    # When all packets explicitly specify the same byte order,
                    # choose that honest default when transferring to Calculate.
                    selected_order = wire_order
                    effective_orders = {r[4] for r in rows if r[4] is not None}
                    if (len(effective_orders) == 1 and
                            all(sample.get('order') for sample in used_packets)):
                        selected_order = next(iter(effective_orders))
                    matches = sum(r[0]['status'] == 'Match' for r in verified)
                    status = ('Verified on holdouts' if verified and matches == len(verified)
                              else 'Holdout mismatch' if verified else 'Fit only')
                    candidates.append({'model': model, 'field': placement,
                                       'coverage': cover, 'order': selected_order,
                                       'display_field': field_label,
                                       'display_coverage': coverage_label,
                                       'display_order': order_label,
                                       'fits': len(evaluated), 'fit_total': len(fits),
                                       'holdout_matches': matches,
                                       'holdout_total': len(verified),
                                       'status': status, 'origin': 'RevEng preset'})
    candidates.sort(key=lambda c: (-c['holdout_matches'],
                    c['holdout_total'] > 0 and c['holdout_matches'] != c['holdout_total'],
                    c['model'].width, c['model'].name))
    return candidates, True


def search_extended(samples, widths, field, coverage, order, *, executable=None,
                    seconds_per_width=12, cancelled=lambda: False):
    """Bounded RevEng -s scan for unknown 8/16-bit CRC polynomials.

    Codewords are reconstructed as contiguous message bytes + CRC bytes.
    This mode requires a fixed field/coverage (row overrides are honored),
    and a fully byte-aligned codeword, because RevEng's -s expects combined
    message/CRC pairs and byte order must be unambiguous. Cross-check all
    RevEng candidates locally; a CLI hit alone isn't considered a match.
    """
    import time

    if field in ('Search ends', 'Search offsets') or coverage == 'Search prefix':
        raise ValueError('Extended search needs a fixed CRC location and coverage. '
                         'Use known-model discovery to narrow these first.')
    widths = sorted(set(widths))
    unsupported = [w for w in widths if w not in (8, 16)]
    if unsupported:
        raise ValueError('Extended polynomial search is currently bounded to 8- and 16-bit CRCs. '
                         'Deselect other widths for this run.')
    executable = executable or locate_reveng()
    if not executable:
        raise FileNotFoundError('Extended CRC search requires the RevEng executable')
    fits = [s for s in samples if s.get('role', 'Fit') == 'Fit']
    holdouts = [s for s in samples if s.get('role') == 'Holdout']
    if len(fits) < 3:
        raise ValueError('Extended search requires at least three Fit packets')
    results = []
    complete = True
    for width in widths:
        if cancelled():
            return results, False
        for wire_order in (('Big endian', 'Little endian') if order == 'Auto (both)' and width > 8
                           else ('Big endian',) if order == 'Auto (both)' else (order,)):
            codewords = []
            for sample in fits:
                data, observed, span, _ = region(sample, width, field, coverage, wire_order)
                if observed is None:
                    raise ValueError('Extended search requires an observed CRC on each Fit packet')
                if len(data) % 8 or width % 8:
                    raise ValueError('Extended search requires byte-aligned message and CRC fields')
                order_name = 'little' if wire_order == 'Little endian' else 'big'
                crc_bytes = observed.to_bytes(width // 8, order_name)
                joined = data + ''.join(f'{value:08b}' for value in crc_bytes)
                codewords.append(f'{int(joined, 2):0{len(joined)//4}x}')
            if len(set(codewords)) < 2:
                raise ValueError('Use varying packet contents; identical Fit packets cannot constrain a model')
            # Keep RevEng preset matching enabled. -q 0 covers the full
            # odd-polynomial search space if no preset fits.
            cmd = [executable, '-w', str(width), '-q', '0', '-s'] + codewords
            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                started = time.monotonic()
                while process.poll() is None:
                    if cancelled() or time.monotonic() - started > seconds_per_width:
                        process.terminate()
                        try:
                            process.communicate(timeout=1)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.communicate()
                        complete = False
                        break
                    time.sleep(0.03)
                if not complete:
                    return results, False
                stdout, stderr = process.communicate(timeout=2)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            if process.returncode:
                diagnostic = (stderr or stdout).strip()
                if 'no models found' in diagnostic.lower():
                    # RevEng uses a nonzero exit status for a valid search
                    # that produced zero CRC candidates. Keep searching other
                    # widths/endian interpretations; don't display an error.
                    continue
                raise RuntimeError(diagnostic or 'RevEng extended search failed')
            for line in stdout.splitlines():
                if 'width=' not in line or 'poly=' not in line:
                    continue
                try:
                    model = parse_model(line)
                    fitting = [calculate_sample(s, model, field, coverage, wire_order) for s in fits]
                    if not all(r['status'] == 'Match' for r in fitting):
                        continue
                    held = []
                    for s in holdouts:
                        try:
                            held.append(calculate_sample(s, model, field, coverage, wire_order))
                        except ValueError:
                            held.append({'status': 'Error'})
                    results.append({'model': model, 'field': field, 'coverage': coverage,
                                    'order': wire_order, 'fits': len(fitting), 'fit_total': len(fits),
                                    'holdout_matches': sum(r['status'] == 'Match' for r in held),
                                    'holdout_total': len(held), 'origin': 'RevEng -s',
                                    'status': ('Verified on holdouts' if held and all(r['status'] == 'Match' for r in held)
                                               else 'Holdout mismatch' if held else 'Fit only')})
                except (ValueError, TypeError):
                    continue
    return results, complete