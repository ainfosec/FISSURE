"""Regression tests for streaming-only receive and internal AFC control."""
from pathlib import Path
import ast
import asyncio
import importlib.util
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
for dir_ in ('operations', 'scripts'):
    sys.path.insert(0, str(ROOT / dir_))

import ais_stream_runtime_v090 as runtime
from ais_iq_decoder import make_top_block
from test_ais_plugin import import_operations, FakeArtifactManager


@pytest.mark.parametrize('name,radio', [
    ('ais_usrp_b210_receive', 'b210'),
    ('ais_hackrf_receive', 'hackrf'),
    ('ais_rtlsdr_receive', 'rtl'),
])
@pytest.mark.parametrize('duration', [0, 1, 20, 120, 121, 3600])
def test_receive_all_durations_stream_without_iq(monkeypatch, tmp_path, name, radio, duration):
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location('test_v010_'+name, ROOT/'operations'/ (name+'.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    called = []

    async def fake_stream(op, device):
        called.append((device, op.duration_s))
    monkeypatch.setitem(mod.OperationMain.run.__globals__, 'run_stream_monitor', fake_stream)
    op = mod.OperationMain(duration_s=duration,
                           artifact_manager=FakeArtifactManager(tmp_path))
    asyncio.run(op.run())
    assert called == [(radio, float(duration))]
    assert not hasattr(op, '_capture_and_decode')
    assert not list(tmp_path.rglob('*.cf32'))
    assert not op.artifact_manager.artifacts


@pytest.mark.parametrize('radio', ('b210', 'hackrf', 'rtl'))
def test_user_frequency_correction_not_forwarded_to_process(radio):
    op = types.SimpleNamespace(sample_rate=240000, rf_frequency=915e6,
                               device_args='type=b200' if radio == 'b210' else radio+'=0',
                               rx_gain=35, lna_gain=16, vga_gain=16,
                               rf_channel='0', rx_antenna='TX/RX',
)
    cmd = runtime.build_stream_command(op, radio)
    assert '--frequency-correction-hz' not in cmd
    if radio == 'rtl':
        assert '--rf-channel' not in cmd
        assert '--rx-antenna' not in cmd


def test_offline_decode_correction_moves_both_channel_offsets(monkeypatch):
    connections = []
    offsets = []
    class TB:
        def __init__(self, title): pass
        def connect(self, *args): connections.append(args)
    gr = types.ModuleType('gnuradio.gr')
    gr.top_block = TB
    gr.sizeof_gr_complex = 8
    blocks = types.ModuleType('gnuradio.blocks')
    blocks.file_source = lambda *args: 'file_source'
    pkg = types.ModuleType('gnuradio')
    pkg.gr, pkg.blocks = gr, blocks
    monkeypatch.setitem(sys.modules, 'gnuradio', pkg)
    monkeypatch.setitem(sys.modules, 'gnuradio.gr', gr)
    monkeypatch.setitem(sys.modules, 'gnuradio.blocks', blocks)
    receiver = types.SimpleNamespace(ais_rx=lambda offset, rate, designator:
                                      offsets.append((offset, designator)) or 'receiver')
    make_top_block('/tmp/in.cf32', 240000, 162000000, 'both', 8,
                   receiver, frequency_correction_hz=2700)
    assert offsets == [(-22300, 'A'), (27700, 'B')]
    assert len(connections) == 2


def test_receiver_ui_has_no_legacy_finite_capture_description():
    tree = ast.parse((ROOT/'actions.py').read_text())
    for name in ('ais_usrp_b210_receive_schema', 'ais_hackrf_receive_schema',
                 'ais_rtlsdr_receive_schema'):
        schema = next(ast.literal_eval(n.value) for n in tree.body
                      if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
                      and n.targets[0].id == name)
        params = {p['name']: p for p in schema['params']}
        assert 'saves finite IQ' not in params['duration_s']['description']
        assert 'frequency_correction_hz' not in params
