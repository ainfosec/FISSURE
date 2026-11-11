"""No-RF tests for device-specific GNU Radio 3.8 AIS Actions and rate conversion."""
from __future__ import annotations
import ast
import asyncio
import importlib.util
import json
from pathlib import Path
import struct
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'operations'))
import ais_osmosdr_hardware as radio


def _actions():
    tree = ast.parse((ROOT / 'actions.py').read_text())
    return {target.id: ast.literal_eval(node.value) for node in tree.body
            if isinstance(node, ast.Assign) for target in node.targets
            if isinstance(target, ast.Name) and target.id.endswith('_schema')}


def test_five_hardware_specific_action_schemas():
    actions = _actions()
    for kind in ('ais_usrp_b210_transmit', 'ais_usrp_b210_receive',
                 'ais_hackrf_transmit', 'ais_hackrf_receive', 'ais_rtlsdr_receive'):
        assert kind + '_schema' in actions
        assert (ROOT / 'operations' / (kind + '.py')).is_file()
    assert 'ais_sdr_transmit_schema' not in actions
    assert 'ais_sdr_receive_schema' not in actions
    for kind in ('ais_hackrf_transmit', 'ais_usrp_b210_transmit'):
        params = {x['name']: x for x in actions[kind + '_schema']['params']}
        assert 'save_tx_artifact' not in params  # hidden; Operation default is False
    for kind in ('ais_hackrf_receive', 'ais_rtlsdr_receive'):
        params = {x['name']: x for x in actions[kind + '_schema']['params']}
        assert params['rf_frequency']['default'] == 162000000
    assert {x['name']: x for x in actions['ais_hackrf_transmit_schema']['params']}['tx_gain']['default'] == 40


def test_osmosdr_validators_and_lab_frequency_guard():
    assert radio.validate_tx(915e6, 10, 'hackrf=0') == 'hackrf=0'
    radio.validate_rx('hackrf', 162e6, 20, 'hackrf=0', lna_gain=16, vga_gain=16)
    radio.validate_rx('rtl', 162e6, 20, 'rtl=0', gain=35)
    with pytest.raises(ValueError, match='isolated lab'):
        radio.validate_tx(162e6, 10, 'hackrf=0')
    with pytest.raises(ValueError, match='0..47'):
        radio.validate_tx(915e6, 60, 'hackrf=0')
    with pytest.raises(ValueError, match='beginning with'):
        radio.validate_tx(915e6, 10, 'rtl=0')
    with pytest.raises(ValueError, match='duration'):
        radio.validate_rx('rtl', 162e6, 140, 'rtl=0')


def test_radio_sample_rates_and_graph_edges():
    traces = {'edges': [], 'resamp': [], 'devices': [], 'setters': []}
    class Device:
        def __init__(self, name): self.name = name
        def set_sample_rate(self, rate): traces['setters'].append((self.name, 'rate', rate))
        def set_center_freq(self, freq, chan): traces['setters'].append((self.name, 'freq', freq))
        def set_gain_mode(self, flag, chan): traces['setters'].append((self.name, 'mode', flag))
        def set_gain(self, val, chan): traces['setters'].append((self.name, 'gain', val))
        def set_if_gain(self, val, chan): traces['setters'].append((self.name, 'if', val))
        def set_bb_gain(self, val, chan): traces['setters'].append((self.name, 'bb', val))
    class Osmo:
        @staticmethod
        def source(args): traces['devices'].append(('source', args)); return Device('source')
        @staticmethod
        def sink(args): traces['devices'].append(('sink', args)); return Device('sink')
    class GR:
        sizeof_gr_complex = 8
        @staticmethod
        def top_block(name):
            class TB:
                def connect(self, *args): traces['edges'].append(args)
            return TB()
    class Blocks:
        @staticmethod
        def file_source(*args): return 'file_source'
        @staticmethod
        def multiply_const_cc(*args): return 'scale'
        @staticmethod
        def head(*args): return 'head'
        @staticmethod
        def file_sink(*args): return 'file_sink'
    class Filter:
        @staticmethod
        def rational_resampler_ccc(**kwargs):
            traces['resamp'].append(kwargs)
            return 'resampler'
    runtime = (GR, Blocks, Filter, Osmo, '3.8.fake')
    radio.make_tx_graph('tx.cf32', 915e6, 10, 'hackrf=0', runtime)
    assert traces['resamp'] == [{'interpolation': 10, 'decimation': 1}]
    assert len(traces['edges']) == 1 and len(traces['edges'][0]) == 4
    assert ('sink', 'numchan=1 hackrf=0') in traces['devices']
    assert ('sink', 'rate', 2400000) in traces['setters']
    traces['resamp'].clear()
    radio.make_rx_graph('rx.cf32', 20, 'rtl', 162e6, 'rtl=0', 35, 16, 16, runtime)
    assert traces['resamp'] == [{'interpolation': 1, 'decimation': 10}]
    assert ('source', 'numchan=1 rtl=0') in traces['devices']
    assert ('source', 'gain', 35) in traces['setters']
    traces['resamp'].clear()
    radio.make_rx_graph('rx2.cf32', 20, 'hackrf', 162e6, 'hackrf=0', 35, 24, 30, runtime)
    assert ('source', 'if', 24) in traces['setters']
    assert ('source', 'bb', 30) in traces['setters']


def test_op_classes_import_under_sensor_node(monkeypatch):
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    for name in ('ais_iq_loopback','ais_iq_receive','ais_sdr_transmit','ais_sdr_receive',
                 'ais_osmosdr_receive'):
        if name in sys.modules:
            monkeypatch.delitem(sys.modules, name)
        path = ROOT / 'operations' / (name + '.py')
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, mod)
        spec.loader.exec_module(mod)
    for name in ('ais_usrp_b210_transmit','ais_usrp_b210_receive',
                 'ais_hackrf_transmit','ais_hackrf_receive','ais_rtlsdr_receive'):
        spec = importlib.util.spec_from_file_location(name, ROOT / 'operations' / (name + '.py'))
        mod = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, mod)
        spec.loader.exec_module(mod)
        assert hasattr(mod, 'OperationMain')
    assert sys.modules['ais_hackrf_receive'].OperationMain().radio_kind == 'hackrf'
    assert sys.modules['ais_rtlsdr_receive'].OperationMain().radio_kind == 'rtl'
    assert sys.modules['ais_hackrf_transmit'].OperationMain().tx_gain == 40


def test_hackrf_tx_action_no_artifact_by_default(monkeypatch, tmp_path):
    from test_ais_plugin import import_operations, FakeArtifactManager
    import_operations(monkeypatch)
    # This test loads the class through the FISSURE-like operation module.
    spec = importlib.util.spec_from_file_location('ais_hackrf_transmit', ROOT / 'operations' / 'ais_hackrf_transmit.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, 'require_pyais', lambda: object())
    manager = FakeArtifactManager(tmp_path)
    def create_nmea(self, path):
        path.write_text('!AIVDM,1,1,,A,12vg20@P0tG?pF0EWrD1GQ600000,0*19\n')
        return 1
    async def subprocess(self, cmd, timeout, label, cwd):
        cmd = list(cmd)
        manifest = Path(cmd[cmd.index('--manifest')+1])
        if 'IQ generation' in label:
            Path(cmd[cmd.index('--output')+1]).write_bytes(struct.pack('<ff', .1, .2) * 4000)
            manifest.write_text(json.dumps({'frame_count': 1, 'skipped_nmea_sentences': 0}))
        else:
            assert '--device' in cmd and cmd[cmd.index('--device')+1] == 'hackrf'
            manifest.write_text(json.dumps({'rf_transmitted': True}))
        return 'ok'
    monkeypatch.setattr(mod.OperationMain, '_create_nmea', create_nmea)
    monkeypatch.setattr(mod.OperationMain, 'call_sdr_process', subprocess)
    op = mod.OperationMain(artifact_manager=manager, repeat_count=1)
    asyncio.run(op.run())
    assert manager.artifacts == []


def test_device_exclusion_does_not_block_other_radios():
    from ais_sdr_operation_runtime import AISB210OperationRuntime
    a, b, c = AISB210OperationRuntime(), AISB210OperationRuntime(), AISB210OperationRuntime()
    try:
        a.lock_radio('hackrf')
        with pytest.raises(RuntimeError, match='using the hackrf'):
            b.lock_radio('hackrf')
        c.lock_radio('rtl')
    finally:
        a.unlock_radio()
        b.unlock_radio()
        c.unlock_radio()


def test_lab_band_receiver_marks_targets_simulated():
    from ais_hackrf_receive import OperationMain as HackRF
    from ais_rtlsdr_receive import OperationMain as RTL
    from ais_sdr_receive import OperationMain as B210
    for cls in (HackRF, RTL, B210):
        op = cls(rf_frequency=915000000, simulated_input='false')
        assert op._simulated and op._simulated_source == 'lab_band_rf_replay'
        live = cls(rf_frequency=162000000, simulated_input='false')
        assert not live._simulated


def test_v081_hardware_filters_match_fissure_configured_types():
    tree = ast.parse((ROOT / 'actions.py').read_text())
    mapping = next(ast.literal_eval(node.value) for node in tree.body
                   if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'ACTION_HARDWARE'
                           for target in node.targets))
    assert mapping == {
        'ais_b210_loopback': ['USRP B2x0'],
        'ais_usrp_b210_transmit': ['USRP B2x0'],
        'ais_usrp_b210_receive': ['USRP B2x0'],
        'ais_hackrf_transmit': ['HackRF'],
        'ais_hackrf_receive': ['HackRF'],
        'ais_rtlsdr_receive': ['RTL2832U'],
    }
    assert 'ais_iq_loopback' not in mapping
    assert 'ais_receive' not in mapping


def test_v081_leaf_actions_have_lock_radio_even_with_stale_runtime(monkeypatch):
    """Reproduce user failure: cached v0.7 runtime mixin lacks lock_radio."""
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    from ais_sdr_operation_runtime import AISB210OperationRuntime
    monkeypatch.delattr(AISB210OperationRuntime, 'lock_radio', raising=False)
    monkeypatch.delattr(AISB210OperationRuntime, 'unlock_radio', raising=False)
    # Simulate action file reimported by FISSURE while shared parent may be cached.
    instances = []
    for name, kind in [('ais_hackrf_receive', 'hackrf'),
                       ('ais_rtlsdr_receive', 'rtl'),
                       ('ais_hackrf_transmit', 'hackrf')]:
        spec = importlib.util.spec_from_file_location(
            '_v081_test_' + name, ROOT / 'operations' / (name + '.py'))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        op = module.OperationMain()
        assert op.lock_radio.__func__.__module__ == 'ais_device_lock_v081'
        op.lock_radio(kind)
        instances.append(op)
        assert op._sdr_lock is not None
        with pytest.raises(RuntimeError, match='Another FISSURE AIS Action'):
            duplicate = module.OperationMain()
            duplicate.lock_radio(kind)
        op.unlock_radio()
        assert op._sdr_lock is None
    assert len(instances) == 3


def test_v081_radio_lock_releases_after_failure():
    from ais_device_lock_v081 import lock_radio, unlock_radio
    class Holder:
        _sdr_lock = None
    Holder.lock_radio = lock_radio
    Holder.unlock_radio = unlock_radio
    first, second = Holder(), Holder()
    first.lock_radio('rtl')
    with pytest.raises(RuntimeError, match='using the rtl'):
        second.lock_radio('rtl')
    first.unlock_radio()
    second.lock_radio('rtl')
    second.unlock_radio()
