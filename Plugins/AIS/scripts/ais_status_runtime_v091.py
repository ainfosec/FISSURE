"""FISSURE-compatible, cache-independent AIS Action status callback bridge.

SensorNode's callback is send_status(node_uid, opid, status_text).
Small standalone tests may use callback(status_text) or callback(opid, status_text).
Do not use inspect.signature to choose: wrapped callbacks can expose a
misleading __signature__, causing three-argument send_status to receive one.
"""
from __future__ import annotations

import asyncio
import inspect


async def emit_status(operation, message):
    callback = getattr(operation, 'status_callback', None)
    if callback is None:
        return
    msg = str(message)
    args_list = (
        (getattr(operation, 'node_uid', ''), getattr(operation, 'opid', ''), msg),
        (getattr(operation, 'opid', ''), msg),
        (msg,),
    )
    try:
        last_arity_error = None
        for args in args_list:
            try:
                result = callback(*args)
            except TypeError as exc:
                # A bad argument count fails *at the invocation site* and does
                # not enter the callback. Never retry TypeError raised from
                # inside callback code: it may have made side effects already.
                if exc.__traceback__ is not None and exc.__traceback__.tb_next is None:
                    last_arity_error = exc
                    continue
                raise
            if inspect.isawaitable(result):
                return await asyncio.wait_for(result, timeout=3.0)
            return result
        if last_arity_error is not None:
            raise last_arity_error
    except asyncio.CancelledError:
        raise
    except Exception:
        operation.logger.exception('AIS status_callback failed')


class AISStatusMixin:
    """Overrides cached AIS parent modules in long-lived Sensor Nodes."""

    async def _status(self, message):
        return await emit_status(self, message)
