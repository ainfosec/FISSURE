"""Persistent AIS receive regressions: no SDR hardware/GNU Radio needed."""
import asyncio
import io
import json
import math
from pathlib import Path
import sys

import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
for directory in ('scripts', 'operations'):
    sys.path.insert(0, str(ROOT / directory))

import ais_native_stream as native
import ais_stream_runtime_v090 as runtime


@pytest.mark.parametrize('radio', ('rtl', 'hackrf'))
def test_continuous_native_commands_have_stdout_without_sample_limit(monkeypatch, radio):
    monkeypatch.setattr(native.shutil, 'which', lambda p: '/fake/bin/' + p)
    cmd = native.native_stream_command(radio, 162e6, radio + '=0', 35, 16, 16)
    assert '-n' not in cmd
    assert cmd[0].endswith('rtl_sdr' if radio == 'rtl' else 'hackrf_transfer')
    assert cmd[-1] == '-' if radio == 'rtl' else cmd[cmd.index('-r')+1] == '-'
    assert cmd[cmd.index('-s')+1] == '2400000'
    assert cmd[cmd.index('-f')+1] == '162000000'
    if radio == 'hackrf':
        assert cmd[cmd.index('-a')+1] == '0'  # RF amplifier disabled


@pytest.mark.parametrize('radio', ('rtl', 'hackrf'))
def test_continuous_native_iq_resampling_preserves_channel_and_chunk_boundary(radio):
    # Synthetic 25 kHz carrier (AIS channel offset), multiple chunks.
    n = 260000
    t = np.arange(n)
    s = np.exp(2j*np.pi*25000*t/2400000)
    i, q = (np.rint(s.real*60).astype(np.int16), np.rint(s.imag*60).astype(np.int16))
    if radio == 'rtl':
        raw = np.column_stack((i+128, q+128)).astype('u1').tobytes()
    else:
        raw = np.column_stack((i, q)).astype('i1').tobytes()
    native.STOP.clear()
    sink = io.BytesIO()
    sample_count = native.stream_decimate(io.BytesIO(raw), sink, radio,
                                          chunk_samples=20000, overlap=1000)
    output = np.frombuffer(sink.getvalue(), dtype='<c8')
    assert sample_count == len(output) == n//10
    assert 0.4 < np.sqrt(np.mean(abs(output)**2)) < 0.5
    stable = output[100:-100]
    fft = np.fft.fft(stable[:20000])
    peak = np.fft.fftfreq(20000, 1/240000)[np.argmax(abs(fft))]
    assert abs(peak - 25000) < 15
    # No extra phase jumps at processing boundaries.
    for boundary in range(2000, len(output)-1, 2000):
        assert abs(output[boundary] - output[boundary-1]) < 0.35


def test_live_decoder_reuses_existing_both_channel_graph_and_stdin_source():
    script = (ROOT / 'scripts' / 'ais_live_decoder.py').read_text()
    assert 'make_top_block(None, stream_rate, 162000000.0' in script
    assert "'both'" in script
    assert 'make_b210_source' in script
    assert "source = make_stdin_source(gr)" in script
    assert 'blocks.file_sink' not in script


@pytest.mark.parametrize('device', ('rtl', 'hackrf', 'b210'))
def test_stream_build_command_selects_b210_uhd_or_native(device):
    from types import SimpleNamespace
    op = SimpleNamespace(sample_rate=240000, rf_frequency=162000000,
                         device_args='rtl=0' if device == 'rtl' else 'hackrf=0' if device == 'hackrf' else 'type=b200',
                         rx_gain=35, lna_gain=16, vga_gain=20)
    cmd = runtime.build_stream_command(op, device)
    expected = 'ais_live_decoder.py' if device == 'b210' else 'ais_native_stream.py'
    assert any(expected in token for token in cmd)
    assert '--duration-s' not in cmd
    assert '--rx-gain' in cmd if device != 'hackrf' else '--lna-gain' in cmd
    assert '--frequency-correction-hz' not in cmd
    if device == 'rtl':
        assert '--rf-channel' not in cmd
        assert '--rx-antenna' not in cmd


def test_streaming_operation_stop_creates_one_summary_and_unlocks(monkeypatch, tmp_path):
    from test_ais_plugin import import_operations, FakeArtifactManager
    import importlib.util
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location('ais_leaf_v090', ROOT/'operations'/'ais_rtlsdr_receive.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    op = mod.OperationMain(duration_s=0, artifact_manager=FakeArtifactManager(tmp_path),
                           detection_interval_s=30)
    active_runtime = mod.OperationMain.run.__globals__['run_stream_monitor'].__globals__
    monkeypatch.setitem(active_runtime, 'require_pyais', lambda: object())
    code = (
        'import time,sys,signal\n'
        'def stop(*args): sys.exit(0)\n'
        'signal.signal(signal.SIGTERM, stop)\n'
        "sys.stdout.write('!AIVDM,1,1,,A,FAKE,0*00\\n'); sys.stdout.flush()\n"
        'time.sleep(60)\n'
    )
    monkeypatch.setitem(active_runtime, 'build_stream_command', lambda *_:
                        [sys.executable, '-u', '-c', code])
    messages=[]
    async def fake_receive(line):
        messages.append(line)
        op._message_count += 1
        op._vessels['123456789'] = {'count': 1, 'ship_name': 'FAKE'}
        op._stop = True
    op._receive = fake_receive

    async def exercise():
        await asyncio.wait_for(op.run(), timeout=5)

    asyncio.run(exercise())
    assert len(messages) == 1
    assert len(op.artifact_manager.artifacts) == 1
    files, name, kind, meta = op.artifact_manager.artifacts[0]
    assert kind == 'ais_rx_monitor_summary'
    assert meta['streaming_mode'] is True
    assert meta['capture_gaps_possible'] is False
    assert meta['decoded_messages'] == 1
    assert meta['capture_segments'] == 0
    assert op._sdr_lock is None
    assert op._sdr_proc is None
    assert not list(tmp_path.rglob('*.cf32'))


def test_live_receiver_fails_instead_of_silently_exiting(monkeypatch, tmp_path):
    from test_ais_plugin import import_operations, FakeArtifactManager
    import importlib.util
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location('ais_leaf_early_exit', ROOT/'operations'/'ais_rtlsdr_receive.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    op = mod.OperationMain(duration_s=0, artifact_manager=FakeArtifactManager(tmp_path))
    active_runtime = mod.OperationMain.run.__globals__['run_stream_monitor'].__globals__
    monkeypatch.setitem(active_runtime, 'require_pyais', lambda: object())
    code = 'import sys; print("device unavailable", file=sys.stderr); sys.exit(3)'
    monkeypatch.setitem(active_runtime, 'build_stream_command', lambda *_: [sys.executable, '-u', '-c', code])

    async def exercise():
        with pytest.raises(RuntimeError, match='stream exited 3'):
            await asyncio.wait_for(op.run(), timeout=5)

    asyncio.run(exercise())
    assert op._sdr_lock is None
    assert len(op.artifact_manager.artifacts) == 1
    assert op.artifact_manager.artifacts[0][3]['completion_reason'] == 'error'


def test_long_duration_dispatches_stream_without_temp_iq_capture(monkeypatch, tmp_path):
    from test_ais_plugin import import_operations, FakeArtifactManager
    import importlib.util
    import_operations(monkeypatch)
    spec = importlib.util.spec_from_file_location('ais_leaf_long', ROOT/'operations'/'ais_rtlsdr_receive.py')
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    op = mod.OperationMain(duration_s=145, artifact_manager=FakeArtifactManager(tmp_path))
    async def fake_stream(obj, radio):
        assert obj is op and radio == 'rtl'
    monkeypatch.setitem(mod.OperationMain.run.__globals__, 'run_stream_monitor', fake_stream)
    assert not hasattr(op, '_capture_and_decode')
    asyncio.run(op.run())


def test_native_pipe_forwards_nmea_without_ever_recording_iq(monkeypatch, tmp_path, capfd):
    # Execute the real native -> converter -> decoder subprocess pipeline with
    # fake RF IQ8 bytes and a fake decoder. Test no radio or GNU Radio needed.
    fake_decoder = tmp_path / 'ais_live_decoder.py'
    fake_decoder.write_text('''import sys
payload = sys.stdin.buffer.read(48000)
if len(payload) == 48000:
    sys.stdout.write('!AIVDM,1,1,,A,FAKESTREAM,0*00\\n')
    sys.stdout.flush()
''')
    monkeypatch.setattr(native, 'ROOT', tmp_path)
    samples = 480000
    input_bytes = bytes((192, 128)) * samples
    # The fake source is finite; production native commands have no -n.
    transmitter = [sys.executable, '-u', '-c',
                   'import sys; sys.stdout.buffer.write(bytes((192,128))*480000); '
                   'sys.stdout.buffer.flush()']
    with pytest.raises(RuntimeError, match='unexpectedly|pipe failed'):
        native.run_native_stream('rtl', transmitter)
    stdout, _ = capfd.readouterr()
    assert '!AIVDM,1,1,,A,FAKESTREAM,0*00' in stdout
    assert not list(tmp_path.glob('*.cf32'))
