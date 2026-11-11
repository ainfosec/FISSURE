"""Regression: SensorNode filters __init__ kwargs, silently dropping callbacks on **kwargs leaves."""
import asyncio
import importlib.util
import inspect
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for subdir in ('scripts', 'operations'):
    if str(ROOT / subdir) not in sys.path:
        sys.path.insert(0, str(ROOT / subdir))


from test_ais_plugin import fake_pyais


@pytest.mark.parametrize('action', ['ais_rtlsdr_receive', 'ais_hackrf_receive'])
def test_fissure_constructor_filter_forwards_detection_and_target(
    monkeypatch, fake_pyais, action
):
    from test_ais_plugin import import_operations, fake_encode_dict
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location('test_v092_' + action, ROOT / 'operations' / (action + '.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    init_params = set(inspect.signature(mod.OperationMain.__init__).parameters)
    required = {'node_uid', 'logger', 'detection_callback', 'target_callback',
                'status_callback', 'artifact_manager', 'detection_interval_s'}
    assert required <= init_params

    detections, targets, statuses = [], [], []

    async def send_detection(detection):
        detections.append(detection)

    async def send_target_patch(target_id, patch, history_entry=None, artifact_id=''):
        targets.append((target_id, patch, history_entry))

    async def send_status(node_uid, opid, status_text):
        statuses.append((node_uid, opid, status_text))

    # Faithfully reproduce FISSURE's filtered_parameters constructor handling.
    parameters = {
        'node_uid': 'sensor-d2674c57',
        'detection_callback': send_detection,
        'target_callback': send_target_patch,
        'status_callback': send_status,
        'detection_interval_s': 7,
        'duration_s': 0,
        'rf_frequency': 915000000,
    }
    filtered = {k: v for k, v in parameters.items() if k in init_params}
    op = mod.OperationMain(**filtered)
    assert op.node_uid == 'sensor-d2674c57'
    assert op.detection_callback is send_detection
    assert op.target_callback is send_target_patch
    assert op.status_callback is send_status
    assert op.detection_interval_s == 7
    assert op._simulated is True
    assert op._simulated_source == 'lab_band_rf_replay'

    # This exercises the actual shared NMEA parsing -> Detection -> Target path,
    # without requiring GNU Radio or an SDR for the callback delivery test.
    ais_position = fake_encode_dict({'type': 1, 'mmsi': 200000001,
                                     'lat': 40.722, 'lon': -74.020})[0]

    async def exercise():
        await op._status('receiving')
        await op._receive(ais_position)

    asyncio.run(exercise())
    assert len(statuses) == 1
    assert statuses[0] == ('sensor-d2674c57', op.opid, 'receiving')
    assert len(detections) == 1
    assert detections[0]['node_uid'] == 'sensor-d2674c57'
    assert detections[0]['input_mode'] == 'iq_file'  # direct NMEA parsing before streaming sets source
    assert detections[0]['simulated'] is True
    assert detections[0]['simulation_source'] == 'lab_band_rf_replay'
    assert 'SIMULATED LAB RF REPLAY' in detections[0]['description']
    assert len(targets) == 1
    target_id, patch, history = targets[0]
    assert target_id.startswith('tgt-')
    assert patch['node_uid'] == 'sensor-d2674c57'
    assert patch['simulated'] is True
    assert 'SIMULATED AIS TEST TRAFFIC' in patch['description']
    assert patch['location']['source'] == 'ais_reported'
    assert history['operation_id'] == op.opid
    assert history['simulated'] is True


def test_no_receive_leaf_has_generic_kwargs_silently_swallowing_callbacks():
    for name in ('ais_rtlsdr_receive', 'ais_hackrf_receive'):
        import ast
        tree = ast.parse((ROOT / 'operations' / (name + '.py')).read_text())
        op_class = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == 'OperationMain')
        init = next(n for n in op_class.body if isinstance(n, ast.FunctionDef) and n.name == '__init__')
        assert init.args.kwarg is None
