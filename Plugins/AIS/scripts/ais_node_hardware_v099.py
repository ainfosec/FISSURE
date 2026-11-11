"""Resolve an Action's USRP selection from the executing Sensor Node's hardware.

The Sensor Node owns its hardware inventory (YAML: Sensor Node.hardware.sdrs).
The Dashboard schema is static, so a blank serial input is resolved locally when
an Action is dispatched, not guessed or hard-coded into the schema.
"""
from __future__ import annotations

import re


def configured_b210_parameters(component, parameters):
    """Return copied Action parameters with the configured B2x0 UHD serial.

    Explicit serial/device arguments win. A default SDR index is honored when
    it identifies a B2x0. Otherwise exactly one configured B2x0 is accepted.
    No serial is guessed when the node has no configured B2x0.
    """
    p = dict(parameters or {})
    explicit = str(p.get('serial_number') or '').strip()
    args = str(p.get('device_args') or 'type=b200').strip()
    if explicit or re.search(r'(?:^|,)\s*serial\s*=', args):
        return p
    node = (getattr(component, 'settings_dict', {}) or {}).get('Sensor Node', {}) or {}
    hardware = node.get('hardware', {}) or {}
    sdrs = hardware.get('sdrs', {}) or {}
    if isinstance(sdrs, list):
        entries = list(enumerate(sdrs))
    elif isinstance(sdrs, dict):
        entries = list(sdrs.items())
    else:
        entries = []
    candidates = [(str(key), entry) for key, entry in entries
                  if isinstance(entry, dict) and entry.get('type') == 'USRP B2x0']
    if not candidates:
        return p
    preferred = str((hardware.get('defaults') or {}).get('sdr', '')).strip()
    chosen = next((entry for key, entry in candidates if key == preferred), None)
    if chosen is None:
        if len(candidates) > 1:
            raise ValueError('Multiple USRP B2x0 radios configured; set USRP Serial explicitly or select the default SDR in Sensor Node hardware')
        chosen = candidates[0][1]
    serial = str(chosen.get('serial') or '').strip()
    if not serial:
        # If the device has no stored serial, UHD auto-discovery remains possible.
        return p
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', serial):
        raise ValueError('Configured USRP B2x0 serial is invalid')
    p['serial_number'] = serial
    # The B210 loopback does not declare serial_number in its constructor.
    # Write the resolved UHD selector into device_args for all B210 Actions.
    entries = [item.strip() for item in args.split(',') if item.strip()]
    entries = [item for item in entries if not item.startswith('serial=')]
    entries.append('serial=' + serial)
    p['device_args'] = ','.join(entries)
    log = getattr(component, 'logger', None)
    if log is not None:
        log.info('AIS B210: selected configured USRP %s, device_args=%s',
                 chosen.get('radio_name') or 'USRP B2x0', p['device_args'])
    return p
