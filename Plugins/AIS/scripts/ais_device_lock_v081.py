"""Per-radio advisory lock for AIS HackRF/RTL-SDR Actions (v0.8.1).

Separate module name deliberately avoids stale Sensor Node imports from
previous plugin releases. These locks apply only to AIS Actions on one host,
not to external programs or the FISSURE-wide resource allocator.
"""
from __future__ import annotations

import fcntl
from pathlib import Path
import tempfile


_ALLOWED_RADIOS = ("hackrf", "rtl")


def lock_radio(self, backend):
    """Claim a radio type for the lifetime of one local AIS Operation."""
    if backend not in _ALLOWED_RADIOS:
        raise ValueError("Unknown AIS radio lock: %s" % backend)
    if getattr(self, "_sdr_lock", None) is not None:
        raise RuntimeError("This AIS Operation already holds a radio lock")
    handle = (Path(tempfile.gettempdir()) / ("fissure_ais_%s.lock" % backend)).open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        raise RuntimeError("Another FISSURE AIS Action is using the %s on this Sensor Node" % backend)
    except BaseException:
        handle.close()
        raise
    self._sdr_lock = handle


def unlock_radio(self):
    """Release the acquired lock, including on failure/Stop paths."""
    handle = getattr(self, "_sdr_lock", None)
    if handle is None:
        return
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()
        self._sdr_lock = None
