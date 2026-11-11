"""Regression for repeatable lab TX and stopping without hanging or Artifact spam."""
import ast
import asyncio
import importlib.util
import json
from pathlib import Path
import struct
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))

from ais_tx_repeat_v093 import validate_repeat_settings, send_repeated_batches


def test_repeat_validation():
    assert validate_repeat_settings() == (0, 2.0)
    assert validate_repeat_settings('3', '0.5') == (3, 0.5)
    for bad in [-1, 1.5, 10001, 'inf', 'nan', None]:
        with pytest.raises(ValueError, match='Repeat Batches'):
            validate_repeat_settings(bad, 2)
    for bad in [-1, 61, 'inf', 'nan', None]:
        with pytest.raises(ValueError, match='Repeat Pause|Repeat Batches'):
            validate_repeat_settings(0, bad)


def test_action_schemas_default_to_repeat_until_stopped():
    tree = ast.parse((ROOT / 'actions.py').read_text())
    for name in ('ais_usrp_b210_transmit_schema', 'ais_hackrf_transmit_schema'):
        node = next(n for n in tree.body if isinstance(n, ast.Assign)
                    and any(isinstance(t, ast.Name) and t.id == name for t in n.targets))
        params = {p['name']: p for p in ast.literal_eval(node.value)['params']}
        assert params['repeat_count']['default'] == 0
        assert params['repeat_count']['min'] == 0
        assert 'repeat_pause_s' not in params  # internal 2-second safety/default pause
        assert 'save_tx_artifact' not in params  # avoid per-batch waveform artifacts


def test_repeat_helper_finite_and_stop_on_pause():
    class Fake:
        _stop = False
        repeat_count = 3
        repeat_pause_s = 0.0
        tx_batches_completed = 0
        statuses = []
        async def _status(self, msg): self.statuses.append(msg)
    async def batch(index):
        calls.append(index)
    calls=[]
    op=Fake()
    assert asyncio.run(send_repeated_batches(op, batch, 5, 'test')) == 3
    assert calls == [1, 2, 3]
    assert op.tx_batches_completed == 3
    assert any('15 messages total' in s for s in op.statuses)

    class Infinite(Fake):
        repeat_count = 0
        repeat_pause_s = .03
        statuses = []
    async def scenario():
        op=Infinite()
        first = asyncio.Event()
        calls=[]
        async def send(index):
            calls.append(index)
            first.set()
        task=asyncio.create_task(send_repeated_batches(op,send,15,'loop'))
        await asyncio.wait_for(first.wait(), 1)
        await asyncio.sleep(.005)
        op._stop = True
        result=await asyncio.wait_for(task, 1)
        return result, calls
    result, calls = asyncio.run(scenario())
    assert result == 1
    assert calls == [1]


def _import_tx(monkeypatch, name):
    from test_ais_plugin import import_operations
    import_operations(monkeypatch)
    for dependency in ('ais_iq_receive','ais_iq_loopback'):
        spec=importlib.util.spec_from_file_location(dependency, ROOT/'operations'/(dependency+'.py'))
        module=importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules,dependency,module)
        spec.loader.exec_module(module)
    spec=importlib.util.spec_from_file_location('ais_v093_test_'+name,ROOT/'operations'/(name+'.py'))
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize('device', ['b210','hackrf'])
def test_tx_replays_without_regenerating_iq_or_creating_artifacts(monkeypatch, tmp_path, device):
    from test_ais_plugin import FakeArtifactManager
    name = 'ais_usrp_b210_transmit' if device == 'b210' else 'ais_hackrf_transmit'
    module=_import_tx(monkeypatch,name)
    # `ais_usrp_b210_transmit` dynamically loads its shared B210 implementation.
    op_cls=module.OperationMain
    monkeypatch.setitem(op_cls.run.__globals__, 'require_pyais', lambda: object())
    monkeypatch.setattr(op_cls,'_create_nmea', lambda self, path: (path.write_text('!AIVDM,1,1,,A,foo,0*00\n'),1)[1])
    run_calls=[]
    async def fake_process(self,command,timeout,label,cwd):
        args=list(command)
        path=Path(args[args.index('--manifest')+1])
        if 'IQ generation' in label:
            Path(args[args.index('--output')+1]).write_bytes(struct.pack('<ff',.1,.1)*3000)
            path.write_text(json.dumps({'frame_count': 1,'skipped_nmea_sentences':0}))
            run_calls.append('generate')
        else:
            run_calls.append('tx')
            path.write_text(json.dumps({'rf_transmitted': True}))
        return 'ok'
    monkeypatch.setattr(op_cls,'call_sdr_process',fake_process)
    manager=FakeArtifactManager(tmp_path)
    op=op_cls(artifact_manager=manager,repeat_count=3,repeat_pause_s=0)
    asyncio.run(op.run())
    assert run_calls==['generate','tx','tx','tx']
    assert op.tx_batches_completed==3
    assert manager.artifacts==[]


def test_infinite_b210_transmit_stops_after_two_mock_batches(monkeypatch, tmp_path):
    from test_ais_plugin import FakeArtifactManager
    module=_import_tx(monkeypatch,'ais_usrp_b210_transmit')
    op_cls=module.OperationMain
    monkeypatch.setattr(op_cls,'_create_nmea', lambda self,p: (p.write_text('!AIVDM,1,1,,A,foo,0*00\n'),1)[1])
    # Module may have been loaded under unique wrapper name.
    monkeypatch.setitem(op_cls.run.__globals__, 'require_pyais', lambda: object())
    count={'n':0}
    async def fake_process(self,command,timeout,label,cwd):
        path=Path(command[command.index('--manifest')+1])
        if 'IQ generation' in label:
            Path(command[command.index('--output')+1]).write_bytes(struct.pack('<ff',.1,.1)*3000)
            path.write_text(json.dumps({'frame_count':1,'skipped_nmea_sentences':0}))
        else:
            count['n']+=1
            path.write_text(json.dumps({'rf_transmitted':True}))
            if count['n']==2:
                self._stop=True
    monkeypatch.setattr(op_cls,'call_sdr_process',fake_process)
    op=op_cls(artifact_manager=FakeArtifactManager(tmp_path),repeat_count=0,repeat_pause_s=0)
    asyncio.run(op.run())
    assert count['n']==2
    assert op.tx_batches_completed==2
