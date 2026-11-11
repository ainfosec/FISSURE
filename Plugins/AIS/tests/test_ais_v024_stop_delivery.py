"""AIS v0.9.24: native process tree cleanup and Detection callback diagnostics."""
import asyncio
import os
from pathlib import Path
import signal
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for folder in ('scripts', 'operations'):
    if str(ROOT / folder) not in sys.path:
        sys.path.insert(0, str(ROOT / folder))

from ais_sdr_operation_runtime import AISB210OperationRuntime


@pytest.mark.skipif(os.name != 'posix' or not Path('/proc').exists(),
                    reason='Linux-specific owned-process-group test')
def test_stream_stop_kills_wrapper_and_radio_child(tmp_path):
    """A wrapper may exit on SIGTERM while the SDR child keeps running."""
    async def exercise():
        child_pid_file = tmp_path / 'child.pid'
        # The child deliberately ignores SIGTERM. Only group escalation can
        # guarantee it stops; wrapper alone exiting is not enough.
        child_code = (
            'import signal,time;'
            'signal.signal(signal.SIGTERM,signal.SIG_IGN);'
            'time.sleep(60)'
        )
        wrapper_code = (
            'import subprocess,sys,time,pathlib;'
            'child=subprocess.Popen([sys.executable,"-u","-c",sys.argv[2]], '
            'stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);'
            'pathlib.Path(sys.argv[1]).write_text(str(child.pid));'
            'time.sleep(60)'
        )
        proc = await asyncio.create_subprocess_exec(
            sys.executable, '-u', '-c', wrapper_code, str(child_pid_file), child_code,
            start_new_session=True, stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        op = AISB210OperationRuntime()
        op._sdr_proc = proc
        op._sdr_process_group_id = proc.pid
        try:
            for _ in range(100):
                if child_pid_file.exists() and child_pid_file.read_text().strip():
                    break
                await asyncio.sleep(.02)
            assert child_pid_file.exists()
            child_pid = int(child_pid_file.read_text())
            await asyncio.wait_for(op.stop_sdr_process(), timeout=5)
            assert proc.returncode is not None
            for _ in range(50):
                stat = Path('/proc') / str(child_pid) / 'stat'
                if not stat.exists() or stat.read_text().split(') ')[1][0] == 'Z':
                    break
                await asyncio.sleep(.02)
            else:
                pytest.fail('AIS native radio grandchild survived Stop')
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            if proc.returncode is None:
                await proc.wait()
    asyncio.run(exercise())


def test_detection_summary_counts_success_failures_and_throttle(monkeypatch, tmp_path):
    from test_ais_plugin import import_operations, FakeArtifactManager
    import importlib.util
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location(
        'ais_v024_stop_delivery_leaf', ROOT/'operations'/'ais_rtlsdr_receive.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    callbacks = []
    async def detection_cb(item):
        callbacks.append(item['mmsi'])
        if len(callbacks) == 1:
            raise RuntimeError('simulate transient send failure')

    manager = FakeArtifactManager(tmp_path)
    op = mod.OperationMain(duration_s=0, artifact_manager=manager,
                           detection_callback=detection_cb, detection_interval_s=30)
    runtime_ns = mod.OperationMain.run.__globals__['run_stream_monitor'].__globals__
    monkeypatch.setitem(runtime_ns, 'require_pyais', lambda: object())
    wrapper_code = ('import sys,time;'
                    '[sys.stdout.write("!AIVDM,1,1,,A,FAKE,0*00\\n") for _ in range(3)];'
                    'sys.stdout.flush();time.sleep(60)')
    monkeypatch.setitem(runtime_ns, 'build_stream_command',
                        lambda *_: [sys.executable, '-u', '-c', wrapper_code])
    seen = []
    async def fake_receive(line):
        seen.append(line)
        try:
            await op.detection_callback({'mmsi': '123456789'})
        except RuntimeError:
            pass
        op._message_count += 1
        op._vessels['123456789'] = {'count': len(seen), 'ship_name': 'FAKE'}
        if len(seen) == 3:
            op._stop = True
    op._receive = fake_receive

    asyncio.run(asyncio.wait_for(op.run(), timeout=5))
    assert len(seen) == 3
    assert callbacks == ['123456789', '123456789']
    assert op._rx_detection_delivery == {
        'generated': 3, 'callback_succeeded': 1,
        'throttled': 1, 'callback_missing': 0, 'callback_failed': 1,
        'position_generated': 0, 'position_callback_succeeded': 0,
        'position_throttled': 0, 'nonposition_generated': 3,
        'nonposition_callback_succeeded': 1,
    }
    assert len(manager.artifacts) == 1
    assert manager.artifacts[0][3]['detection_delivery'] == op._rx_detection_delivery
