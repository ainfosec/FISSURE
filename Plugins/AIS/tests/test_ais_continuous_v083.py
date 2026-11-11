"""v0.8.3 receiver lifecycle and Action display-name regressions (no RF)."""
import ast
import asyncio
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'operations'))


def _load(name):
    path = ROOT / 'operations' / (name + '.py')
    spec = importlib.util.spec_from_file_location('_ais_083_' + name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_clear_nonhardware_action_names_and_routes():
    code = (ROOT / 'actions.py').read_text()
    tree = ast.parse(code)
    functions = {node.name: node for node in tree.body if isinstance(node, ast.AsyncFunctionDef)}
    expected = {
        'ais_nmea_udp_file_receive': 'ais_receive.py',
        'ais_nmea_udp_simulate': 'ais_simulate.py',
        'ais_iq_file_decode': 'ais_iq_receive.py',
        'ais_iq_offline_loopback': 'ais_iq_loopback.py',
    }
    for action, script in expected.items():
        assert action in functions
        assert action + '_schema' in code
        assert script in ast.unparse(functions[action])
    assert all(old not in functions for old in (
        'ais_receive', 'ais_simulate', 'ais_iq_receive', 'ais_iq_loopback'))


def test_all_hardware_rx_duration_schemas_are_indefinite_by_default():
    tree = ast.parse((ROOT / 'actions.py').read_text())
    schema_map = {}
    for item in tree.body:
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name) and target.id.endswith('_schema'):
                    schema_map[target.id] = ast.literal_eval(item.value)
    for action in ('ais_usrp_b210_receive', 'ais_hackrf_receive', 'ais_rtlsdr_receive'):
        rows = {p['name']: p for p in schema_map[action + '_schema']['params']}
        duration = rows['duration_s']
        assert duration['default'] == 0
        assert duration['min'] == 0
        assert duration['max'] >= 3600
        assert '0' in duration['description']  # Compact UI labels put duration semantics in tooltips.


@pytest.mark.parametrize('module,kind', [
    ('ais_hackrf_receive', 'hackrf'),
    ('ais_rtlsdr_receive', 'rtl'),
    ('ais_sdr_receive', 'b210'),
])
def test_indefinite_dispatches_persistent_stream(module, kind, monkeypatch, tmp_path):
    from test_ais_plugin import import_operations, FakeArtifactManager
    import_operations(monkeypatch)
    mod = _load(module)
    observed = []

    async def fake_stream(op, radio):
        observed.append(radio)
        op._stop = True

    monkeypatch.setitem(mod.OperationMain.run.__globals__, 'run_stream_monitor', fake_stream)
    assert not hasattr(mod.OperationMain, '_capture_and_decode')
    op = mod.OperationMain(duration_s=0, artifact_manager=FakeArtifactManager(tmp_path))
    asyncio.run(op.run())
    assert observed == [kind]


@pytest.mark.parametrize('module', ['ais_rtlsdr_receive', 'ais_sdr_receive'])
def test_multi_hour_duration_is_one_persistent_stream(module, monkeypatch, tmp_path):
    from test_ais_plugin import import_operations, FakeArtifactManager
    import_operations(monkeypatch)
    mod = _load(module)
    called = []

    async def fake_stream(op, radio):
        called.append((radio, op.duration_s))

    monkeypatch.setitem(mod.OperationMain.run.__globals__, 'run_stream_monitor', fake_stream)
    op = mod.OperationMain(duration_s=145, artifact_manager=FakeArtifactManager(tmp_path))
    asyncio.run(op.run())
    assert called == [('rtl' if 'rtl' in module else 'b210', 145)]


def test_finite_receive_never_uses_old_capture_branch(monkeypatch, tmp_path):
    from test_ais_plugin import import_operations, FakeArtifactManager
    import_operations(monkeypatch)
    mod = _load('ais_rtlsdr_receive')
    calls = []
    async def fake_stream(op, radio):
        calls.append((radio, op.duration_s))
        op._stop = True
    monkeypatch.setitem(mod.OperationMain.run.__globals__, 'run_stream_monitor', fake_stream)
    op = mod.OperationMain(duration_s=5, artifact_manager=FakeArtifactManager(tmp_path))
    asyncio.run(op.run())
    assert calls == [('rtl', 5)]
    assert not hasattr(op, '_capture_and_decode')
    assert not list(tmp_path.rglob('*.cf32'))


def test_nmea_udp_duration_zero_stops(monkeypatch, tmp_path):
    from test_ais_plugin import import_operations
    receive, _ = import_operations(monkeypatch)
    monkeypatch.setattr(receive, 'require_pyais', lambda: object())
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    op = receive.OperationMain(duration_s=0, listen_port=port, save_artifact=False)

    async def main():
        task = asyncio.create_task(op.run())
        await asyncio.sleep(.1)
        assert not task.done()
        op._stop = True
        await asyncio.wait_for(task, timeout=2)
    asyncio.run(main())
    assert op._sock is None
