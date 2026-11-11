"""Regression tests for GNU Radio 3.10 Python-block lifetime / decoder EPIPE diagnostics."""
from pathlib import Path
import gc
import importlib
import sys
import time
import types
import weakref

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))


def test_live_receiver_hierarchies_remain_strongly_referenced(monkeypatch):
    """The GNU Radio 3.10 graph must retain both Python receiver wrappers."""
    import ais_iq_decoder as decoder
    import ais_gr310_receiver as receiver_module

    class FakeTB:
        def __init__(self, *args):
            pass
        def connect(self, *args):
            pass  # no Python references held, as in C++-only connections
    class FakeBlock:
        pass

    fake_gnuradio = types.ModuleType('gnuradio')
    fake_gnuradio.gr = types.SimpleNamespace(top_block=FakeTB)
    fake_gnuradio.blocks = types.SimpleNamespace()
    monkeypatch.setitem(sys.modules, 'gnuradio', fake_gnuradio)

    constructed = []
    def build_rx(*args, **kwargs):
        obj = FakeBlock()
        constructed.append(weakref.ref(obj))
        assert kwargs['carrier_sync'] is True
        return obj
    monkeypatch.setattr(receiver_module, 'make_receiver', build_rx)

    source = FakeBlock()
    graph = decoder.make_top_block(
        None, 200000, 162000000, 'both', 10,
        types.SimpleNamespace(pdu_to_nmea=lambda _: None),
        source=source, receiver_profile='grc_reference',
        automatic_frequency_recovery=True)
    gc.collect()
    assert len(graph._fissure_owned_blocks) == 3  # source, A, B
    assert graph._fissure_owned_blocks[0] is source
    assert all(ref() is not None for ref in constructed)
    del graph
    gc.collect()
    assert all(ref() is None for ref in constructed)


def test_native_broken_pipe_includes_decoder_exit_code(monkeypatch):
    """Do not disguise an exited gr-ais decoder as a HackRF device error."""
    import io
    import ais_native_stream as native

    class BrokenWriter:
        def write(self, value):
            raise BrokenPipeError(32, 'Broken pipe')
        def close(self):
            pass

    class FakeProc:
        def __init__(self, code, *, decoder=False):
            self.code = code
            self.stdin = BrokenWriter()
            self.stdout = io.BytesIO(b'')
            self.stderr = io.BytesIO(b'AIS decoder startup test failure\n' if decoder else b'')
        def poll(self):
            return self.code
        def wait(self, timeout=None):
            return self.code
        def terminate(self):
            self.code = -15
        def kill(self):
            self.code = -9

    calls = []
    commands = []
    def fake_popen(command, **kwargs):
        proc = FakeProc(5 if not calls else None, decoder=not calls)
        commands.append(command)
        calls.append(proc)
        return proc
    monkeypatch.setattr(native.subprocess, 'Popen', fake_popen)
    def broken_stream(raw, sink, kind, **kwargs):
        sink.write(b'0' * 8)
        return 1
    monkeypatch.setattr(native, 'stream_decimate', broken_stream)
    native.STOP.clear()
    with pytest.raises(RuntimeError) as err:
        native.run_native_stream('hackrf', ['fake-hackrf'], decoder_rate=200000,
                                 receiver_profile='grc_reference')
    msg = str(err.value)
    assert 'decoder_exit=5' in msg
    assert 'AIS decoder startup test failure' in msg
    assert commands[0][1:3] == ['-X', 'faulthandler']
    native.STOP.clear()
