"""AIS v0.9.26: Stop must release the hardware despite a busy callback."""
import asyncio
import importlib.util
from pathlib import Path
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]
for folder in ('scripts', 'operations'):
    if str(ROOT / folder) not in sys.path:
        sys.path.insert(0, str(ROOT / folder))

from test_ais_plugin import FakeArtifactManager, import_operations


def test_stop_terminates_receiver_before_busy_detection_callback_finishes(monkeypatch, tmp_path):
    """Regression: increased v0.9.25 Detection activity delayed the Stop loop."""
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location(
        'ais_v026_busy_stop_leaf', ROOT/'operations'/'ais_hackrf_receive.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    op = mod.OperationMain(duration_s=0, rf_frequency=915e6,
                           artifact_manager=FakeArtifactManager(tmp_path))
    runtime = mod.OperationMain.run.__globals__['run_stream_monitor'].__globals__
    monkeypatch.setitem(runtime, 'require_pyais', lambda: object())
    code = ('import sys,time;'
            'sys.stdout.write("!AIVDM,1,1,,A,FAKE,0*00\\n");'
            'sys.stdout.flush();time.sleep(60)')
    monkeypatch.setitem(runtime, 'build_stream_command',
                        lambda *_: [sys.executable, '-u', '-c', code])
    callback_entered = asyncio.Event()
    callback_completed = asyncio.Event()

    async def slow_message_handler(line):
        callback_entered.set()
        # The operation may be waiting on its Detection/Target callbacks when
        # the Sensor Node receives Stop. Radio shutdown must not wait for this.
        await asyncio.sleep(1.8)
        callback_completed.set()
        op._message_count += 1
        op._vessels['123456789'] = {'count': 1, 'ship_name': 'TEST'}

    op._receive = slow_message_handler

    async def scenario():
        task = asyncio.create_task(op.run())
        await asyncio.wait_for(callback_entered.wait(), timeout=3)
        child = op._sdr_proc
        assert child and child.returncode is None
        op._stop = True
        async def wait_for_hardware_close():
            while child.returncode is None:
                await asyncio.sleep(.02)
        # Without the independent watcher this is ~1.8 seconds, because the
        # original receiver only checks _stop after its pending callback.
        await asyncio.wait_for(wait_for_hardware_close(), timeout=1.2)
        assert not callback_completed.is_set()
        await asyncio.wait_for(task, timeout=6)
        assert callback_completed.is_set()
        assert op._sdr_proc is None
        assert op._sdr_lock is None
        assert len(op.artifact_manager.artifacts) == 1
        assert op.artifact_manager.artifacts[0][3]['completion_reason'] == 'stopped'

    asyncio.run(scenario())


def test_stop_watcher_included_in_stream_cleanup():
    """The Watcher is always cancelled before final process-group teardown."""
    source = (ROOT/'scripts'/'ais_stream_runtime_v090.py').read_text()
    assert 'stop_watcher_task = asyncio.create_task(stop_process_on_request())' in source
    assert 'stop_watcher_task.cancel()' in source
    assert 'await op.stop_sdr_process()' in source
