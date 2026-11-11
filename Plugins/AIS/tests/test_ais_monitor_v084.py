"""v0.8.4: stale-module and bounded session-summary tests (no RF needed)."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
for path in ('operations', 'scripts'):
    if str(ROOT / path) not in sys.path:
        sys.path.insert(0, str(ROOT / path))


def load_leaf(name):
    module_name = '_ais_fresh_v084_' + name
    spec = importlib.util.spec_from_file_location(module_name, ROOT / 'operations' / (name + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.mark.parametrize('name', ('ais_rtlsdr_receive', 'ais_hackrf_receive'))
def test_cached_receiver_and_old_validator_do_not_reject_indefinite_duration(monkeypatch, name):
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    stale_parent = types.ModuleType('ais_osmosdr_receive')
    class OldReceiver:
        def __init__(self, *args, **kwargs):
            raise ValueError('RX duration must be 1..120 seconds')
    stale_parent.AISOsmoReceiver = OldReceiver
    stale_helper = types.ModuleType('ais_osmosdr_hardware')
    def old_validate(*args):
        raise ValueError('RX duration must be 1..120 seconds')
    stale_helper.validate_rx = old_validate
    monkeypatch.setitem(sys.modules, 'ais_osmosdr_receive', stale_parent)
    monkeypatch.setitem(sys.modules, 'ais_osmosdr_hardware', stale_helper)
    leaf = load_leaf(name)
    inst = leaf.OperationMain(duration_s=0)
    assert inst.duration_s == 0
    assert inst.radio_kind == ('rtl' if 'rtlsdr' in name else 'hackrf')
    assert sys.modules['ais_osmosdr_receive'] is stale_parent
    assert sys.modules['ais_osmosdr_hardware'] is stale_helper


def test_cached_b210_receiver_and_helper_do_not_reject_indefinite_duration(monkeypatch):
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    old_parent = types.ModuleType('ais_sdr_receive')
    class OldB210:
        def __init__(self, *args, **kwargs):
            raise ValueError('RX duration must be 1..120 seconds')
    old_parent.OperationMain = OldB210
    old_helper = types.ModuleType('ais_sdr_hardware')
    old_helper.validate_rx = lambda *a: (_ for _ in ()).throw(ValueError('RX duration must be 1..120 seconds'))
    monkeypatch.setitem(sys.modules, 'ais_sdr_receive', old_parent)
    monkeypatch.setitem(sys.modules, 'ais_sdr_hardware', old_helper)
    leaf = load_leaf('ais_usrp_b210_receive')
    inst = leaf.OperationMain(duration_s=0)
    assert inst.duration_s == 0
    assert sys.modules['ais_sdr_receive'] is old_parent
    assert sys.modules['ais_sdr_hardware'] is old_helper


def test_session_summary_single_small_artifact_even_with_many_messages(monkeypatch, tmp_path):
    from test_ais_plugin import import_operations, FakeArtifactManager
    import_operations(monkeypatch)
    from ais_monitor_summary_v084 import create_monitor_summary
    leaf = load_leaf('ais_rtlsdr_receive')
    manager = FakeArtifactManager(tmp_path)
    inst = leaf.OperationMain(duration_s=0, artifact_manager=manager)
    inst._message_count = 1_000_000
    inst._vessels = {
        '200000001': {'count': 600000, 'ship_name': 'BOAT A', 'latitude': 40.72,
                      'longitude': -74.02, 'last_seen': '2026-11-07T19:00:00Z',
                      'published': True, 'last_publish_at': 18.0},
        '200000002': {'count': 400000, 'ship_name': 'BOAT B', 'latitude': 40.73,
                      'longitude': -74.03},
    }
    assert create_monitor_summary(inst, 'rtl', 1000, 'stopped') == 'artifact-test-1'
    assert len(manager.artifacts) == 1
    paths, _, kind, metadata = manager.artifacts[0]
    assert kind == 'ais_rx_monitor_summary'
    assert len(paths) == 1 and paths[0].endswith('.json')
    assert metadata['decoded_messages'] == 1_000_000
    assert metadata['unique_mmsi'] == 2
    assert not metadata['raw_iq_archived']
    data = json.loads(Path(paths[0]).read_text())
    assert len(data['vessels']) == 2
    assert data['vessels'][0]['ship_name'] == 'BOAT A'
    assert 'published' not in data['vessels'][0]
    # No one-million-message list or permanent IQ file is produced.
    assert Path(paths[0]).stat().st_size < 6000
