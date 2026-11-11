"""v0.9.15 HackRF GR3.10 reference receive regressions, no RF device required."""
import ast
import io
from pathlib import Path
import sys
import types

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import ais_native_stream as native
import ais_live_decoder as live


def _params(name):
    tree = ast.parse((ROOT / 'actions.py').read_text())
    payload = next(ast.literal_eval(node.value) for node in tree.body
                   if isinstance(node, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == name for t in node.targets))
    return {p['name']: p for p in payload['params']}


@pytest.mark.parametrize('schema', ['ais_hackrf_receive_schema', 'ais_hackrf_transmit_schema'])
def test_hackrf_device_args_blank_override(schema):
    item = _params(schema)['device_args']
    assert item['default'] == ''
    assert 'optional' in item['description'].lower()


def test_native_hackrf_310_uses_nominal_tune_and_reference_profile(monkeypatch):
    pkg = types.ModuleType('gnuradio')
    pkg.gr = object()
    monkeypatch.setitem(sys.modules, 'gnuradio', pkg)
    from ais_gr_compat import gr_minor_version
    import ais_gr_compat
    monkeypatch.setattr(ais_gr_compat, 'gr_minor_version', lambda _: (10, '3.10-test'))
    seen = {}
    def fake_native(kind, frequency, device_args, gain, lna, vga):
        seen.update(kind=kind, frequency=frequency, args=device_args)
        return ['hackrf_transfer', '-r', '-']
    def fake_stream(kind, command, **kwargs):
        seen.update(**kwargs)
        return 0
    monkeypatch.setattr(native, 'native_stream_command', fake_native)
    monkeypatch.setattr(native, 'run_native_stream', fake_stream)
    assert native.main(['--device', 'hackrf', '--rf-frequency', '915000000',
                        '--device-args', '']) == 0
    assert seen['kind'] == 'hackrf'
    assert seen['frequency'] == 915000000
    assert seen['args'] == 'hackrf=0'  # implicit runtime selection, not a UI default
    assert seen['decoder_rate'] == 200000
    assert seen['receiver_profile'] == 'grc_reference'
    assert '915000000' in seen['hardware_tuning_summary']


def test_native_hackrf_38_preserves_original_dsp(monkeypatch):
    pkg = types.ModuleType('gnuradio')
    pkg.gr = object()
    monkeypatch.setitem(sys.modules, 'gnuradio', pkg)
    import ais_gr_compat
    monkeypatch.setattr(ais_gr_compat, 'gr_minor_version', lambda _: (8, '3.8-test'))
    seen = {}
    def fake_native(kind, frequency, device_args, gain, lna, vga):
        seen['frequency'] = frequency
        return ['hackrf_transfer', '-r', '-']
    def fake_stream(kind, command, **kwargs):
        seen.update(**kwargs)
        return 0
    monkeypatch.setattr(native, 'native_stream_command', fake_native)
    monkeypatch.setattr(native, 'run_native_stream', fake_stream)
    assert native.main(['--device','hackrf','--rf-frequency','915000000']) == 0
    assert seen['frequency'] == 915000000
    assert seen['decoder_rate'] == 240000
    assert seen['receiver_profile'] is None


def test_hackrf_iq8_2400000_to_200000_preserves_ais_channels():
    # Exercise chunk boundaries using data with the two AIS carrier offsets.
    n = 480000
    t = np.arange(n)
    freq = 25000
    carrier = np.exp(2j * np.pi * freq * t / 2400000)
    signal = (np.column_stack((np.rint(carrier.real*50),
                              np.rint(carrier.imag*50))).astype('i1')).tobytes()
    output = io.BytesIO()
    native.STOP.clear()
    delivered = native.stream_decimate(io.BytesIO(signal), output, 'hackrf',
                                       chunk_samples=24000, overlap=1200,
                                       output_rate=native.HACKRF_GR310_RX_RATE)
    rx = np.frombuffer(output.getvalue(), dtype='<c8')
    assert delivered == 40000 == len(rx)
    assert 0.20 < np.mean(abs(rx)) < 0.45
    spectrum = np.fft.fft(rx[4000:24000])
    peak = np.fft.fftfreq(20000, d=1/200000)[np.argmax(abs(spectrum))]
    assert abs(peak - freq) < 20
    for boundary in range(2000, len(rx)-2, 2000):
        assert abs(rx[boundary] - rx[boundary-1]) < 0.30


def test_gr310_stdin_decoder_uses_rotator_profile_without_rate_rewrite(monkeypatch):
    pkg = types.ModuleType('gnuradio')
    pkg.gr = object()
    monkeypatch.setitem(sys.modules, 'gnuradio', pkg)
    monkeypatch.setattr(live, 'gr_minor_version', lambda _: (10, '3.10-test'))
    monkeypatch.setattr(live, 'resolve_ais_module', lambda _: 'gr-ais')
    monkeypatch.setattr(live, 'make_stdin_source', lambda _: 'stdin-source')
    seen = {}
    class Top:
        def start(self): pass
        def wait(self): pass
    def fake_top(*args, **kwargs):
        seen.update(rate=args[1],source=kwargs.get('source'),
                    profile=kwargs.get('receiver_profile'),
                    correction=kwargs.get('frequency_correction_hz'),
                    bandwidth=kwargs.get('loop_bandwidth'), auto=kwargs.get('automatic_frequency_recovery'))
        return Top()
    monkeypatch.setattr(live, 'make_top_block', fake_top)
    assert live.main(['--source', 'stdin', '--sample-rate', '200000',
                      '--receiver-profile', 'grc_reference',
                      '--loop-bandwidth', '0.033']) == 0
    assert seen == {'rate':200000.0, 'source':'stdin-source',
                    'profile':'grc_reference', 'correction':0.0,
                    'bandwidth':0.033, 'auto':True}


def test_3_10_reference_stdin_rejects_wrong_iq_sample_rate(monkeypatch):
    pkg = types.ModuleType('gnuradio')
    pkg.gr = object()
    monkeypatch.setitem(sys.modules, 'gnuradio', pkg)
    monkeypatch.setattr(live, 'gr_minor_version', lambda _: (10, '3.10-test'))
    monkeypatch.setattr(live, 'resolve_ais_module', lambda _: 'gr-ais')
    assert live.main(['--source', 'stdin', '--sample-rate', '240000',
                      '--receiver-profile', 'grc_reference']) == 1
