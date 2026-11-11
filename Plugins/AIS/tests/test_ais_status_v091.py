"""Regression for the exact FISSURE status error in mixed Tactical/Single Action runs."""
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
from ais_status_runtime_v091 import emit_status


def test_fissure_three_argument_callback_ignores_misleading_signature():
    """v0.9.0 inspect.signature erroneously selected one argument in the field."""
    from types import SimpleNamespace
    seen = []

    async def send_status(node_uid, opid, status_text):
        seen.append((node_uid, opid, status_text))

    # A decorated callback can expose an incorrect __signature__.
    send_status.__signature__ = inspect.Signature([
        inspect.Parameter('message', inspect.Parameter.POSITIONAL_OR_KEYWORD)
    ])
    obj = SimpleNamespace(node_uid='node-42', opid='op-77',
                          status_callback=send_status,
                          logger=__import__('logging').getLogger('test'))
    asyncio.run(emit_status(obj, 'RX streaming'))
    assert seen == [('node-42', 'op-77', 'RX streaming')]


@pytest.mark.parametrize('args_count', [1, 2, 3])
def test_status_adapter_handles_all_supported_callback_arities(args_count):
    from types import SimpleNamespace
    seen = []
    def callback(*args):
        # Signature by closed-over expected arity without exposing varargs.
        if len(args) != args_count:
            raise TypeError('wrong arguments')
        seen.append(args)

    # Use real functions with strict Python parameter counts instead of a *args stub.
    callbacks = {
        1: lambda text: seen.append((text,)),
        2: lambda opid, text: seen.append((opid, text)),
        3: lambda uid, opid, text: seen.append((uid, opid, text)),
    }
    obj = SimpleNamespace(node_uid='n', opid='o', status_callback=callbacks[args_count],
                          logger=__import__('logging').getLogger('test'))
    asyncio.run(emit_status(obj, 'message'))
    assert seen == [tuple(['n', 'o', 'message'][-args_count:])]


@pytest.mark.parametrize('filename', [
    'ais_rtlsdr_receive.py', 'ais_hackrf_receive.py',
    'ais_usrp_b210_receive.py', 'ais_usrp_b210_transmit.py',
    'ais_hackrf_transmit.py',
])
def test_hardware_leaf_status_survives_stale_cached_parent(monkeypatch, filename):
    from test_ais_plugin import import_operations
    receiver, _ = import_operations(monkeypatch)
    async def broken_old_status(self, message):
        raise RuntimeError('stale AIS parent status handler')
    monkeypatch.setattr(receiver.OperationMain, '_status', broken_old_status)
    spec = importlib.util.spec_from_file_location('v091_leaf_'+filename.removesuffix('.py'),
                                                  ROOT / 'operations' / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    received = []

    def send_status(node_uid, opid, status_text):
        received.append((node_uid, opid, status_text))

    op = module.OperationMain(node_uid='node-42', status_callback=send_status)
    asyncio.run(op._status('ready'))
    assert received == [('node-42', op.opid, 'ready')]


def test_internal_callback_typeerror_does_not_retry_or_duplicate(caplog):
    from types import SimpleNamespace
    import logging
    calls = []
    def send_status(node_uid, opid, text):
        calls.append((node_uid, opid, text))
        raise TypeError('internal failure in handler')
    op = SimpleNamespace(node_uid='node', opid='operation', status_callback=send_status,
                         logger=logging.getLogger('AIS-test'))
    asyncio.run(emit_status(op, 'running'))
    assert len(calls) == 1
    assert 'status_callback failed' in caplog.text
