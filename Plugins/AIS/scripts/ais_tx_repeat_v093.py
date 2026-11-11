"""Repeat finite, lab-frequency AIS bursts until Stop or an optional batch limit.

The hardware helpers intentionally remain single-batch, matching the already
verified B210 TX. A single generated IQ waveform is reused for each batch;
no additional waveform or Artifact is generated on every repeat.
"""
from __future__ import annotations

import asyncio
import math


def validate_repeat_settings(repeat_count=0, repeat_pause_s=2.0):
    try:
        count = float(repeat_count)
        pause = float(repeat_pause_s)
    except (ValueError, TypeError, OverflowError):
        raise ValueError('Repeat Batches must be an integer 0..10000 and pause must be 0..60 seconds')
    if not math.isfinite(count) or not count.is_integer() or not 0 <= count <= 10000:
        raise ValueError('Repeat Batches must be an integer 0..10000 (0 = until Stop)')
    if not math.isfinite(pause) or not 0 <= pause <= 60:
        raise ValueError('Repeat Pause must be 0..60 seconds')
    return int(count), pause


async def send_repeated_batches(action, transmit_once, messages_per_batch, label):
    """Run one finite hardware TX batch at a time. Return completed batch count.

    Underlying subprocess is interrupted by call_sdr_process when Action Stop
    sets _stop, preserving the previously validated finite TX path. Yield
    during the pause so Stop works even between two batches.
    """
    batches = 0
    repeat_count, repeat_pause_s = validate_repeat_settings(
        action.repeat_count, action.repeat_pause_s)
    while not action._stop:
        await transmit_once(batches + 1)
        batches += 1
        action.tx_batches_completed = batches
        await action._status('%s: batch %d completed (%d messages total)%s' % (
            label, batches, batches * messages_per_batch,
            '; awaiting Stop' if repeat_count == 0 else ''))
        if repeat_count and batches >= repeat_count:
            break
        deadline = asyncio.get_running_loop().time() + repeat_pause_s
        while not action._stop:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            await asyncio.sleep(min(.2, remaining))
        # Always yield once, even if pause is zero (for fake/device-fast paths).
        await asyncio.sleep(0)
    return batches
