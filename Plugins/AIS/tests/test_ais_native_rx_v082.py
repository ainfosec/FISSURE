"""v0.8.2: native HackRF/RTL capture for mixed GNU Radio 3.8 installations."""
import asyncio
import importlib.util
import json
import os
from pathlib import Path
import sys

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'operations'))
import ais_osmosdr_hardware as radio


@pytest.mark.parametrize('kind', ['rtl', 'hackrf'])
def test_native_cli_command(kind, monkeypatch, tmp_path):
    monkeypatch.setattr(radio, 'native_rx_executable', lambda device: '/tmp/test_' + device)
    cmd = radio.native_rx_command(kind, tmp_path/'raw.bin', 162e6, 1,
                                  kind + '=0', 35, 16, 20)
    assert cmd[0] == '/tmp/test_' + kind
    assert '-f' in cmd and '162000000' in cmd
    assert '-s' in cmd and '2400000' in cmd
    assert '-n' in cmd and '2400000' in cmd
    if kind == 'rtl':
        assert cmd[-1] == str(tmp_path/'raw.bin')
        assert cmd[cmd.index('-g') + 1] == '35.0'
    else:
        assert cmd[cmd.index('-a') + 1] == '0'
        assert cmd[cmd.index('-l') + 1] == '16'
        assert cmd[cmd.index('-g') + 1] == '20'


@pytest.mark.parametrize('kind', ['rtl', 'hackrf'])
def test_convert_native_iq8_preserves_ais_channel_frequency(kind, tmp_path):
    # Three blocks exercise the decimation boundary overlap handling.
    n = 600_000
    freq = 25000
    t = np.arange(n, dtype=np.float64)
    iq = np.exp(2j*np.pi*freq*t/radio.DEVICE_RATE)
    i = np.rint(iq.real * 64).astype(np.int16)
    q = np.rint(iq.imag * 64).astype(np.int16)
    if kind == 'rtl':
        raw = np.column_stack((i+128, q+128)).astype('u1').tobytes()
    else:
        raw = np.column_stack((i, q)).astype('i1').tobytes()
    infile, outfile = tmp_path/'test.iq8', tmp_path/'test.cf32'
    infile.write_bytes(raw)
    count = radio.convert_native_iq8(infile, outfile, kind, chunk_samples=200000)
    signal = np.fromfile(outfile, dtype=np.complex64)
    assert count == n // 10 == len(signal)
    assert np.mean(abs(signal[100:-100])) > 0.20
    fft = np.fft.fft(signal[2000:22000])
    index = np.argmax(np.abs(fft))
    peak = np.fft.fftfreq(len(fft), d=1/radio.AIS_RATE)[index]
    assert abs(peak - 25_000) < 30


def test_auto_native_capture_end_to_end_with_fake_rtl_binary(monkeypatch, tmp_path):
    # Actual subprocess invocation + IQ8->cf32 resampling; no radio or GNU Radio.
    fake = tmp_path/'rtl_sdr'
    fake.write_text('''#!/usr/bin/env python3
import sys
from pathlib import Path
n = int(sys.argv[sys.argv.index('-n')+1])
# unsigned 8-bit complex constant IQ (no RF)
with open(sys.argv[-1], 'wb') as fp:
    fp.write(bytes((192,128)) * n)
''')
    fake.chmod(0o755)
    monkeypatch.setattr(radio, 'native_rx_executable', lambda device: str(fake))
    output, manifest = tmp_path/'out.cf32', tmp_path/'manifest.json'
    result = radio.run_rx(output, manifest, 'rtl', 162e6, 1, 'rtl=0')
    assert result['samples_received'] == 240000
    assert result['capture_backend'] == 'native_cli_iq8'
    assert result['rf_transmitted'] is False
    assert output.stat().st_size == 240000 * 8
    assert json.loads(manifest.read_text())['samples_received'] == 240000
    assert np.mean(abs(np.fromfile(output, dtype=np.complex64))) > 0.20


def test_auto_legacy_backend_explains_abi_error(monkeypatch, tmp_path):
    monkeypatch.setattr(radio, 'native_rx_executable', lambda _: None)
    monkeypatch.setattr(radio, 'probe', lambda: ('stub',))
    def bad(*args):
        raise RuntimeError('list contains invalid format!')
    monkeypatch.setattr(radio, 'make_rx_graph', bad)
    with pytest.raises(RuntimeError, match='GNU Radio/gr-osmosdr source ABI mismatch'):
        radio.run_rx(tmp_path/'x.cf32', tmp_path/'x.json', 'rtl', 162e6, 1, 'rtl=0')


def test_status_callback_uses_sensor_node_signature(monkeypatch):
    from test_ais_plugin import import_operations
    rec, _ = import_operations(monkeypatch)
    rows=[]
    async def status(node_uid, opid, status_text):
        rows.append((node_uid, opid, status_text))
    op = rec.OperationMain(status_callback=status, node_uid='node-123')
    asyncio.run(op._status('AIS RX capture started'))
    assert rows == [('node-123', op.opid, 'AIS RX capture started')]


def test_status_callback_still_supports_one_argument(monkeypatch):
    from test_ais_plugin import import_operations
    rec, _ = import_operations(monkeypatch)
    rows=[]
    def status(message): rows.append(message)
    op = rec.OperationMain(status_callback=status)
    asyncio.run(op._status('okay'))
    assert rows == ['okay']


def test_auto_native_capture_end_to_end_with_fake_hackrf_binary(monkeypatch, tmp_path):
    fake = tmp_path/'hackrf_transfer'
    fake.write_text('''#!/usr/bin/env python3
import sys
n = int(sys.argv[sys.argv.index('-n')+1])
with open(sys.argv[sys.argv.index('-r')+1], 'wb') as fp:
    fp.write(bytes((60,20)) * n)
''')
    fake.chmod(0o755)
    monkeypatch.setattr(radio, 'native_rx_executable', lambda device: str(fake))
    output, manifest = tmp_path/'out.cf32', tmp_path/'manifest.json'
    result = radio.run_rx(output, manifest, 'hackrf', 162e6, 1, 'hackrf=0',
                          lna_gain=16, vga_gain=20)
    assert result['samples_received'] == 240000
    assert result['capture_backend'] == 'native_cli_iq8'
    assert result['rx_lna_gain_db'] == 16
    assert result['rx_vga_gain_db'] == 20
    assert output.stat().st_size == 240000 * 8
    assert np.mean(abs(np.fromfile(output, dtype=np.complex64))) > 0.20
