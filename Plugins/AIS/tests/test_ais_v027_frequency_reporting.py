"""Verify frequency-bearing AIS Detections for every RF/IQ receiver family.

These tests exercise the same NMEA-to-Detection path used on GNU Radio 3.8
and 3.10. Real SDR receiver hardware remains an independent validation.
"""
import asyncio
import importlib.util
from pathlib import Path
import sys
import types

import pytest

ROOT = Path(__file__).resolve().parents[1]
for subdir in ('scripts', 'operations'):
    if str(ROOT / subdir) not in sys.path:
        sys.path.insert(0, str(ROOT / subdir))

from test_ais_plugin import FakeArtifactManager, fake_encode_dict, import_operations, fake_pyais


def leaf(relative, name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'operations' / relative)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.OperationMain


@pytest.mark.parametrize('action', (
    'ais_hackrf_receive.py', 'ais_rtlsdr_receive.py',
    'ais_usrp_b210_receive.py',
))
@pytest.mark.parametrize(('channel', 'expected_hz', 'semantics'), (
    ('A', 914975000., 'nominal_ais_channel_center'),
    ('B', 915025000., 'nominal_ais_channel_center'),
    ('1', 914975000., 'nominal_ais_channel_center'),
    ('2', 915025000., 'nominal_ais_channel_center'),
    ('', 915000000., 'receiver_center_channel_unknown'),
    ('Z', 915000000., 'receiver_center_channel_unknown'),
))
def test_live_receivers_always_report_grounded_frequency(
    monkeypatch, fake_pyais, tmp_path, action, channel, expected_hz, semantics
):
    # No GNU Radio binding is needed for the shared Detection/Target contract.
    import_operations(monkeypatch)
    callback_rows = []
    async def detection_callback(d):
        callback_rows.append(d)
    Receiver = leaf(action, 'ais_v027_' + action.replace('.', '_'))
    op = Receiver(rf_frequency=915000000, detection_callback=detection_callback,
                  artifact_manager=FakeArtifactManager(tmp_path), emit_targets=False)
    sentence = fake_encode_dict({'type': 1, 'mmsi': 200000001,
                                 'lat': 40.722, 'lon': -74.02},
                                radio_channel=channel)[0]
    asyncio.run(op._receive(sentence))
    assert len(callback_rows) == 1
    observation = callback_rows[0]
    assert observation['frequency_hz'] == expected_hz
    assert observation['frequency_mhz'] == expected_hz / 1e6
    assert observation['frequency_semantics'] == semantics
    if channel in ('A', '1', 'B', '2'):
        assert observation['ais_channel'] == ('A' if channel in ('A', '1') else 'B')
    else:
        assert 'ais_channel' not in observation


@pytest.mark.parametrize('rf_center', (162000000., 915000000.))
def test_real_rf_center_is_used_not_the_virtual_iq_center(
    monkeypatch, fake_pyais, tmp_path, rf_center
):
    import_operations(monkeypatch)
    observations = []
    Receiver = leaf('ais_hackrf_receive.py', 'ais_v027_hackrf_center')
    op = Receiver(rf_frequency=rf_center, emit_targets=False,
                  detection_callback=observations.append,
                  artifact_manager=FakeArtifactManager(tmp_path))
    line = fake_encode_dict({'type': 1, 'mmsi': 200000001,
                             'lat': 40.7, 'lon': -74.0}, radio_channel='B')[0]
    asyncio.run(op._receive(line))
    assert observations[0]['frequency_hz'] == rf_center + 25000.


def test_iq_file_uses_its_known_center_but_plain_nmea_does_not(
    monkeypatch, fake_pyais, tmp_path
):
    NMEA, _ = import_operations(monkeypatch)
    rows = []
    IQ = leaf('ais_iq_receive.py', 'ais_v027_iq_file')
    iq = IQ(iq_file='/tmp/known_center.cf32', center_frequency=162000000,
            emit_targets=False, detection_callback=rows.append)
    line_unknown = fake_encode_dict({'type': 1, 'mmsi': 200000001,
                                     'lat': 40.7, 'lon': -74.0}, radio_channel='')[0]
    asyncio.run(iq._receive(line_unknown))
    assert rows[-1]['frequency_hz'] == 162000000.
    assert rows[-1]['frequency_semantics'] == 'receiver_center_channel_unknown'

    line_a = fake_encode_dict({'type': 1, 'mmsi': 200000002,
                               'lat': 40.7, 'lon': -74.0}, radio_channel='A')[0]
    for mode in ('udp', 'file'):
        nmea = NMEA.OperationMain(input_mode=mode, emit_targets=False, detection_callback=rows.append)
        asyncio.run(nmea._receive(line_a))
        assert rows[-1]['channel'] == 'A'
        assert 'frequency_hz' not in rows[-1]
        assert 'frequency_mhz' not in rows[-1]


def test_live_receiver_refreshes_stale_20_04_shared_detection_module(monkeypatch):
    # Reproduce a persistent Sensor Node that held pre-v0.9.25 modules even
    # though the installed leaf Action and its runtime were already newer.
    import_operations(monkeypatch)
    for module_name, rel in (
        ('ais_codec', 'scripts/ais_codec.py'),
        ('ais_receive', 'operations/ais_receive.py'),
        ('ais_iq_receive', 'operations/ais_iq_receive.py'),
    ):
        stale = types.ModuleType(module_name)
        stale.__file__ = str(ROOT / rel)
        stale.FISSURE_AIS_API_REVISION = 'ais-plugin-2026-11-06-v0.5.1'
        monkeypatch.setitem(sys.modules, module_name, stale)
    Receiver = leaf('ais_hackrf_receive.py', 'ais_v027_hot_reload')
    assert Receiver.__bases__[0].__bases__[1].__bases__[0] is sys.modules['ais_receive'].OperationMain
    assert sys.modules['ais_receive'].FISSURE_AIS_API_REVISION.endswith('v1.0')
    assert sys.modules['ais_iq_receive'].FISSURE_AIS_API_REVISION.endswith('v1.0')
