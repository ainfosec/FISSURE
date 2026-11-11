"""Regression tests for B210 inventory serial and HackRF native TX isolation."""
import importlib.util
import math
from pathlib import Path
import sys
from types import SimpleNamespace

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'scripts'
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from ais_node_hardware_v099 import configured_b210_parameters
from ais_hackrf_native_tx_v099 import make_hackrf_iq8, hackrf_tx_command
import ais_osmosdr_hardware as hw


class Logger:
    def __init__(self): self.calls = []
    def info(self, *a): self.calls.append(a)


def make_node(default=3, sdrs=None):
    if sdrs is None:
        sdrs = {3: {'type': 'USRP B2x0', 'radio_name': 'USRP B210', 'serial': '30AD2E1'},
                2: {'type': 'HackRF', 'serial': '001122'},
                7: {'type': 'USRP B20xmini', 'serial': 'MINI'}}
    return SimpleNamespace(logger=Logger(), settings_dict={
        'Sensor Node': {'hardware': {'defaults': {'sdr': default}, 'sdrs': sdrs}}})


def test_serial_from_configured_default():
    node = make_node()
    p = configured_b210_parameters(node, {'device_args': 'type=b200', 'serial_number': ''})
    assert p['serial_number'] == '30AD2E1'
    assert p['device_args'] == 'type=b200,serial=30AD2E1'
    assert node.logger.calls


def test_serial_works_if_default_is_other_device_and_one_b210():
    node = make_node(default=7)
    p = configured_b210_parameters(node, {})
    assert p['device_args'].endswith('serial=30AD2E1')


def test_explicit_serial_and_raw_device_args_win():
    node = make_node()
    assert configured_b210_parameters(node, {'serial_number':'EXPLICIT'}) == {'serial_number':'EXPLICIT'}
    p = {'device_args':'type=b200,serial=MANUAL', 'serial_number':''}
    assert configured_b210_parameters(node, p) == p


def test_multiple_b210_needs_default_or_explicit():
    sdrs = {0:{'type':'USRP B2x0','serial':'AAAA'}, 1:{'type':'USRP B2x0','serial':'BBBB'}}
    with pytest.raises(ValueError, match='Multiple'):
        configured_b210_parameters(make_node(default=4,sdrs=sdrs), {})
    assert configured_b210_parameters(make_node(default=1,sdrs=sdrs), {})['serial_number'] == 'BBBB'


def test_native_hackrf_command_gain_and_serial():
    assert hackrf_tx_command('iq.cs8',915e6,20,'hackrf=0',binary='/usr/bin/hackrf_transfer') == [
        '/usr/bin/hackrf_transfer','-t','iq.cs8','-f','915000000','-s','2400000','-x','20','-a','0']
    cmd = hackrf_tx_command('iq.cs8',915e6,20,'hackrf=0000000001',binary='/bin/hackrf_transfer')
    assert cmd[-2:] == ['-d','0000000001']
    with pytest.raises(ValueError, match='serial'):
        hackrf_tx_command('iq.cs8',915e6,20,'hackrf=1',binary='/bin/hackrf_transfer')


def test_native_iq8_shape_and_frequency(tmp_path):
    # Two chunks and a non-DC sinusoid exercise interpolation overlap.
    fs=240000
    n=75000
    iq = np.exp(1j*2*np.pi*25000*np.arange(n)/fs).astype(np.complex64)
    src=tmp_path/'input.cf32'
    iq.tofile(src)
    output=tmp_path/'output.cs8'
    metrics=make_hackrf_iq8(src,output,chunk_samples=24000)
    assert metrics['radio_samples']==n*10
    assert metrics['iq8_bytes']==n*20
    assert metrics['clipped_components']==0
    a=np.fromfile(output,np.int8).reshape(-1,2).astype(np.float32)
    c=a[:,0]+1j*a[:,1]
    # Ignore boundaries and inspect steady-state center samples.
    tone=c[15000:55000]
    diff=tone[1:]*tone[:-1].conj()
    estimate=np.angle(np.mean(diff))*2400000/(2*np.pi)
    assert abs(estimate-25000) < 300
    assert 15 < float(np.max(np.abs(tone))) < 30


def test_native_tx_backend_selected_for_310(monkeypatch):
    fake_gr=SimpleNamespace(version=lambda: '3.10.9.2')
    monkeypatch.setitem(sys.modules, 'gnuradio', SimpleNamespace(gr=fake_gr))
    monkeypatch.setattr(hw.shutil, 'which', lambda tool:'/bin/hackrf_transfer' if tool=='hackrf_transfer' else None)
    assert hw.select_tx_backend('auto') == 'native'
    fake_gr.version=lambda: '3.8.5.0'
    assert hw.select_tx_backend('auto') == 'osmosdr'
    assert hw.select_tx_backend('osmosdr') == 'osmosdr'


def test_native_tx_manifest_with_fake_hackrf_command(monkeypatch, tmp_path):
    """Run helper all the way through external CLI invocation without RF hardware."""
    import json
    import os
    import ais_hackrf_native_tx_v099 as native
    # Fake CLI validates the actual interleaved IQ8 file exists and is nonempty.
    fake = tmp_path / 'hackrf_transfer'
    fake.write_text('''#!/usr/bin/env python3
import os, sys
args=sys.argv
path=args[args.index('-t')+1]
assert os.path.isfile(path) and os.stat(path).st_size > 10000
assert args[args.index('-s')+1]=='2400000'
assert args[args.index('-a')+1]=='0'
print('synthetic CLI completed')
''')
    fake.chmod(0o755)
    lookup = native.shutil.which
    monkeypatch.setattr(native.shutil, 'which', lambda name: str(fake) if name == 'hackrf_transfer' else lookup(name))
    source = tmp_path / 'stimulus.cf32'
    t=np.arange(5000)/240000
    (np.exp(1j*2*np.pi*25000*t)).astype(np.complex64).tofile(source)
    manifest=tmp_path / 'manifest.json'
    result=hw.run_tx(source,manifest,915e6,10,'hackrf=0',tx_backend='native')
    assert result['tx_backend']=='native'
    assert result['native_iq8_stats']['radio_samples']==int((5000+240000+120000)*10)
    assert json.loads(manifest.read_text())['rf_transmitted']
