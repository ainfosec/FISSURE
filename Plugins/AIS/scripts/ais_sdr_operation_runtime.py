"""Shared Sensor Node process control and B210 device exclusion for AIS Actions.

The lock is the same local advisory lock used by the combined B210 loopback.
It does not reserve a radio used by unrelated GNU Radio applications.
"""
from __future__ import annotations

import asyncio
import fcntl
import os
import signal
from pathlib import Path
import tempfile


class AISB210OperationRuntime:
    _sdr_proc = None
    _sdr_lock = None

    def lock_b210(self):
        handle = (Path(tempfile.gettempdir()) / "fissure_ais_b210_loopback.lock").open("a+")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            raise RuntimeError("Another AIS B210 Action is using this radio on the Sensor Node")
        self._sdr_lock = handle

    def unlock_b210(self):
        handle = self._sdr_lock
        if handle is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()
            self._sdr_lock = None

    async def stop_sdr_process(self):
        """Stop the complete AIS stream tree, not only its Python wrapper.

        Streaming RX spawns a native radio tool and a GNU Radio decoder. The
        parent is launched in its own POSIX session; its descendants inherit
        that process group, allowing Stop to release the SDR reliably.
        Older one-shot commands have no owned group and keep the prior behavior.
        """
        proc = self._sdr_proc
        if proc is None:
            return
        pgid = getattr(self, '_sdr_process_group_id', None)
        if pgid is not None and os.name == 'posix':
            try:
                os.killpg(int(pgid), signal.SIGTERM)
            except ProcessLookupError:
                pass
            # Wait briefly for the radio and decoder to release USB and UHD.
            try:
                if proc.returncode is None:
                    await asyncio.wait_for(proc.wait(), timeout=2.0)
                await asyncio.sleep(0.5)
            finally:
                # A wrapper can exit before one of its children. SIGKILL the
                # *owned* group if any processes survived the grace period.
                try:
                    os.killpg(int(pgid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
                if proc.returncode is None:
                    await proc.wait()
            return
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=4)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

    async def call_sdr_process(self, command, timeout_s, description, cwd):
        proc = await asyncio.create_subprocess_exec(
            *command, cwd=str(cwd), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE)
        self._sdr_proc = proc
        communication = asyncio.create_task(proc.communicate())
        loop = asyncio.get_running_loop()
        expires = loop.time() + float(timeout_s)
        try:
            while not communication.done():
                if self._stop:
                    await self.stop_sdr_process()
                    raise asyncio.CancelledError("AIS Action stopped")
                if loop.time() >= expires:
                    await self.stop_sdr_process()
                    raise TimeoutError("%s timed out" % description)
                await asyncio.wait({communication}, timeout=.2)
            out, err = await communication
            if proc.returncode:
                raise RuntimeError("%s failed (%s): %s %s" % (
                    description, proc.returncode,
                    out.decode("utf-8", "replace")[-750:],
                    err.decode("utf-8", "replace")[-1500:]))
            if self._stop:
                raise asyncio.CancelledError("AIS Action stopped")
            self._sdr_proc = None
            return out.decode("utf-8", "replace")
        finally:
            if proc.returncode is None:
                await self.stop_sdr_process()
            if not communication.done():
                try:
                    await asyncio.wait_for(communication, 5)
                except asyncio.TimeoutError:
                    communication.cancel()
            self._sdr_proc = None

    def lock_radio(self, backend):
        """Exclude same-backend AIS Actions but allow different radios concurrently.

        This is local advisory locking for these AIS Actions, not a global FISSURE
        hardware reservation. A HackRF is half-duplex and cannot RX+TX together.
        """
        if backend not in ('hackrf', 'rtl'):
            raise ValueError('Unknown radio lock: %s' % backend)
        handle = (Path(tempfile.gettempdir()) / ('fissure_ais_%s.lock' % backend)).open('a+')
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            handle.close()
            raise RuntimeError('Another FISSURE AIS Action is using the %s on this Sensor Node' % backend)
        self._sdr_lock = handle

    def unlock_radio(self):
        handle = self._sdr_lock
        if handle is not None:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            handle.close()
            self._sdr_lock = None
