"""Regression tests for upgrades with a persistent FISSURE Sensor Node."""
import importlib.util
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
for directory in ('scripts', 'operations'):
    sys.path.insert(0, str(ROOT / directory))


@pytest.mark.parametrize('filename', ('ais_osmosdr_receive.py', 'ais_sdr_receive.py'))
def test_hot_update_does_not_reuse_old_stream_runtime(monkeypatch, filename):
    # Simulate a Sensor Node that previously imported the v0.9.15 runtime.
    stale_runtime = types.ModuleType('ais_stream_runtime_v090')
    def stale(*_a, **_kw):
        raise AssertionError('stale run_stream_monitor invoked')
    stale_runtime.run_stream_monitor = stale
    monkeypatch.setitem(sys.modules, 'ais_stream_runtime_v090', stale_runtime)
    filename_path = ROOT / 'operations' / filename
    spec = importlib.util.spec_from_file_location('ais_upgrade_test_' + filename.replace('.', '_'), filename_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    action = module.AISOsmoReceiver if filename == 'ais_osmosdr_receive.py' else module.OperationMain
    active = action.run.__globals__['run_stream_monitor']
    assert active is not stale
    assert Path(active.__code__.co_filename).resolve() == ROOT / 'scripts' / 'ais_stream_runtime_v090.py'
    assert '--frequency-correction-hz' not in active.__globals__['build_stream_command'](
        types.SimpleNamespace(sample_rate=200000,rf_frequency=915000000,device_args='',
                              rx_gain=70,lna_gain=16,vga_gain=16,rf_channel=0,rx_antenna='TX/RX'),
        'hackrf' if filename == 'ais_osmosdr_receive.py' else 'b210')


def test_native_receiver_ignores_retired_legacy_argument(monkeypatch, capsys):
    import ais_native_stream as native
    pkg = types.ModuleType('gnuradio')
    pkg.gr = object()
    monkeypatch.setitem(sys.modules, 'gnuradio', pkg)
    import ais_gr_compat
    monkeypatch.setattr(ais_gr_compat,'gr_minor_version',lambda *_: (10,'3.10-test'))
    seen = {}
    monkeypatch.setattr(native,'native_stream_command', lambda *_: ['hackrf_transfer', '-r', '-'])
    def fake_run(kind, command, **kwargs):
        seen.update(kwargs)
        return 0
    monkeypatch.setattr(native,'run_native_stream',fake_run)
    assert native.main(['--device','hackrf','--rf-frequency','915000000',
                        '--device-args','','--frequency-correction-hz','-3000']) == 0
    assert seen['decoder_rate'] == 200000
    assert 'ignored' in capsys.readouterr().err


def test_b210_decoder_ignores_retired_legacy_argument(monkeypatch, capsys):
    import ais_live_decoder as live
    pkg = types.ModuleType('gnuradio')
    pkg.gr = object()
    monkeypatch.setitem(sys.modules, 'gnuradio', pkg)
    monkeypatch.setattr(live,'gr_minor_version',lambda *_: (10,'3.10-test'))
    monkeypatch.setattr(live,'resolve_ais_module',lambda *_: 'gr-ais')
    monkeypatch.setattr(live,'make_stdin_source',lambda *_: 'stdin-source')
    class FakeGraph:
        def start(self): pass
        def wait(self): pass
    observed = {}
    def fake_graph(*args, **kwargs):
        observed.update(kwargs)
        return FakeGraph()
    monkeypatch.setattr(live,'make_top_block',fake_graph)
    assert live.main(['--source','stdin','--sample-rate','200000',
                      '--receiver-profile','grc_reference',
                      '--frequency-correction-hz','0']) == 0
    assert observed['frequency_correction_hz'] == 0
    assert observed['automatic_frequency_recovery'] is True
    assert 'ignored' in capsys.readouterr().err
