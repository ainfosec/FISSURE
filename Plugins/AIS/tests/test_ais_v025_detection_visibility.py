"""Regression: static AIS reports must not suppress geolocated Detections."""
import asyncio
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for folder in ('scripts', 'operations'):
    if str(ROOT / folder) not in sys.path:
        sys.path.insert(0, str(ROOT / folder))

from test_ais_plugin import FakeArtifactManager, fake_encode_dict, fake_pyais, import_operations


def _receiver(monkeypatch, tmp_path, *, callback):
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location(
        'ais_v025_receive_leaf', ROOT/'operations'/'ais_hackrf_receive.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    op = mod.OperationMain(duration_s=0, rf_frequency=915000000,
                           artifact_manager=FakeArtifactManager(tmp_path),
                           detection_callback=callback)
    return op, mod


def test_stream_sends_position_after_static_first_and_labels_rf_channel(
    monkeypatch, fake_pyais, tmp_path
):
    delivered = []
    async def cb(detection):
        delivered.append(detection)

    op, mod = _receiver(monkeypatch, tmp_path, callback=cb)
    assert op.detection_interval_s == 5
    runtime_ns = mod.OperationMain.run.__globals__['run_stream_monitor'].__globals__
    monkeypatch.setitem(runtime_ns, 'require_pyais', lambda: object())

    # B210 TX first sends BOTH static fragments for each vessel, then
    # position reports. Old shared throttle blocked every subsequent position
    # and the Tactical CoT presentation therefore appeared nearly empty.
    static, positions = [], []
    for index, channel in enumerate(('A','B','A')):
        mmsi = 200000001 + index
        static.extend(fake_encode_dict({'type':5,'mmsi':mmsi,
                                        'shipname':f'FISSURE DEMO {index+1:02}'},
                                       radio_channel=channel))
        positions.extend(fake_encode_dict({'type':1,'mmsi':mmsi,
                                           'lat':40.722 + 0.001*index,
                                           'lon':-74.020}, radio_channel=channel))
    # One repeat from vessel 1 should be rate-limited (not all the positions).
    nmea = '\n'.join(static + positions + positions[:1]) + '\n'
    code = 'import sys,time;sys.stdout.write(%r);sys.stdout.flush();time.sleep(60)' % nmea
    monkeypatch.setitem(runtime_ns, 'build_stream_command',
                        lambda *_: [sys.executable, '-u', '-c', code])

    async def scenario():
        task = asyncio.create_task(op.run())
        for _ in range(40):
            if op._message_count == 7:
                break
            await asyncio.sleep(.025)
        assert op._message_count == 7, 'synthetic messages were not decoded'
        op._stop = True
        await asyncio.wait_for(task, timeout=5)
    asyncio.run(scenario())

    stats = op._rx_detection_delivery
    assert stats['nonposition_generated'] == 3
    assert stats['position_generated'] == 4
    assert stats['nonposition_callback_succeeded'] == 3
    assert stats['position_callback_succeeded'] == 3
    assert stats['position_throttled'] == 1
    assert stats['callback_succeeded'] == 6
    assert len(delivered) == 6
    assert [x['mmsi'] for x in delivered if x['location_valid']] == [
        '200000001','200000002','200000003']
    assert {x['frequency_hz'] for x in delivered if x['channel']=='A'} == {914975000.0}
    assert {x['frequency_hz'] for x in delivered if x['channel']=='B'} == {915025000.0}
    assert all(x['frequency_semantics'] == 'nominal_ais_channel_center' for x in delivered)
    assert all(x['simulated'] for x in delivered)
    assert op.artifact_manager.artifacts[0][3]['detection_delivery'] == stats


def test_nmea_udp_does_not_invent_rf_frequency(monkeypatch, fake_pyais):
    receiving, _ = import_operations(monkeypatch)
    detections = []
    async def cb(d):
        detections.append(d)
    op = receiving.OperationMain(input_mode='udp', detection_callback=cb,
                                 emit_targets=False)
    line = fake_encode_dict({'type':1, 'mmsi':200000001,
                             'lat':40.7, 'lon':-74.0},radio_channel='A')[0]
    asyncio.run(op._receive(line))
    assert len(detections) == 1
    assert detections[0]['channel'] == 'A'
    assert 'frequency_hz' not in detections[0]
