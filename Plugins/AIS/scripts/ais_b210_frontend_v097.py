"""B210 one-channel device selector: serial, UHD RF subdevice and RX antenna."""
from __future__ import annotations
import re


def make_device_args(device_args='type=b200', serial_number=''):
    args = str(device_args or 'type=b200').strip()
    serial = str(serial_number or '').strip()
    if any(ch in args for ch in '\n\r\x00'):
        raise ValueError('Invalid UHD device args')
    if not args:
        args = 'type=b200'
    if serial:
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', serial):
            raise ValueError('Invalid USRP serial number')
        entries = [x.strip() for x in args.split(',') if x.strip()]
        entries = [x for x in entries if not x.startswith('serial=')]
        entries.append('serial=' + serial)
        args = ','.join(entries)
    return args


def channel_details(rf_channel=0):
    text = str(rf_channel).strip()
    if text in ('0', '0 (A:A)', 'A:A'):
        return 0, 'A:A'
    if text in ('1', '1 (A:B)', 'A:B'):
        return 1, 'A:B'
    raise ValueError('B210 RF channel must be 0 (A:A) or 1 (A:B)')


def configure_subdevice(radio, direction, rf_channel=0):
    _, subdevice = channel_details(rf_channel)
    method = 'set_tx_subdev_spec' if direction == 'tx' else 'set_rx_subdev_spec'
    setter = getattr(radio, method, None)
    if setter is not None:
        setter(subdevice)
    elif subdevice != 'A:A':
        raise RuntimeError('UHD %s lacks %s for B210 channel B' % (direction, method))
    return subdevice


def validate_antenna(rx_antenna='TX/RX'):
    antenna = str(rx_antenna).strip().upper()
    if antenna not in ('TX/RX', 'RX2'):
        raise ValueError('B210 RX antenna must be TX/RX or RX2')
    return antenna
