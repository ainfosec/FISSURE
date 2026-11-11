"""HackRF native IQ8 transmission for isolating gr-osmosdr/GR 3.10 issues.

Input is plugin-generated 240 kS/s complex64 AIS baseband. Output is HackRF's
2.4 MS/s interleaved signed IQ8; polyphase interpolation preserves both AIS
channels. Never use this on maritime AIS channels; lab testing only.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile

AIS_RATE = 240000
HACKRF_RATE = 2400000
TX_SCALE = 0.15


def make_hackrf_iq8(input_cf32, iq8_path, chunk_samples=48000):
    """Polyphase-interpolate a cf32 stream to signed interleaved IQ8 at 2.4MS/s.

    Prefix/suffix overlap avoids FIR edge transients between chunks. Complex
    sample count is exactly 10 times the input complex sample count.
    """
    import numpy as np
    from scipy.signal import resample_poly

    src = Path(input_cf32)
    dest = Path(iq8_path)
    if not src.is_file() or src.stat().st_size < 8 or src.stat().st_size % 8:
        raise ValueError('HackRF TX input must be nonempty interleaved complex64')
    chunk_samples = max(1024, int(chunk_samples))
    overlap = 64  # polyphase interpolator spans ~5 source samples
    previous = np.empty(0, dtype=np.complex64)
    written = 0
    peak = 0.0
    clipped = 0
    with src.open('rb') as inp, dest.open('wb') as out:
        while True:
            buf = inp.read(chunk_samples * 8)
            if not buf:
                break
            current = np.frombuffer(buf, dtype='<c8')
            # Peek at the following samples without consuming them.
            future = inp.read(overlap * 8)
            inp.seek(-len(future), os.SEEK_CUR)
            upcoming = np.frombuffer(future, dtype='<c8')
            extended = np.concatenate((previous, current, upcoming))
            interp = resample_poly(extended, up=10, down=1)
            offset = len(previous) * 10
            samples = interp[offset:offset + len(current) * 10]
            if len(samples) != len(current) * 10:
                raise RuntimeError('HackRF TX resampling produced wrong number of samples')
            scaled = samples * (TX_SCALE * 127.0)
            peak = max(peak, float(np.max(np.abs(scaled))))
            clipped += int(np.count_nonzero(np.abs(scaled.real) > 127) + np.count_nonzero(np.abs(scaled.imag) > 127))
            iq8 = np.empty(len(samples) * 2, dtype=np.int8)
            iq8[0::2] = np.rint(np.clip(scaled.real, -127, 127)).astype(np.int8)
            iq8[1::2] = np.rint(np.clip(scaled.imag, -127, 127)).astype(np.int8)
            iq8.tofile(out)
            written += len(samples)
            previous = current[-overlap:].copy()
    if not written or dest.stat().st_size != written * 2:
        raise RuntimeError('HackRF TX IQ8 conversion incomplete')
    return {'radio_samples': written, 'iq8_bytes': dest.stat().st_size,
            'peak_digital_count': peak, 'clipped_components': clipped}


def hackrf_tx_command(input_iq8, frequency, gain, device_args, binary=None):
    import re
    binary = binary or shutil.which('hackrf_transfer')
    if not binary:
        raise RuntimeError('Native HackRF TX requires hackrf_transfer in PATH')
    selector = str(device_args).strip()
    if not selector.startswith('hackrf=') or any(ch in selector for ch in '\r\n\x00'):
        raise ValueError('Expected HackRF device args hackrf=0 or hackrf=<serial>')
    identifier = selector.split('=', 1)[1]
    if ',' in identifier or any(ch.isspace() for ch in identifier):
        raise ValueError('Native HackRF TX requires one HackRF selector')
    cmd = [binary, '-t', str(input_iq8), '-f', str(int(frequency)),
           '-s', str(HACKRF_RATE), '-x', str(int(gain)), '-a', '0']
    if identifier not in ('', '0'):
        if identifier.isdigit() and len(identifier) < 4:
            raise ValueError('For native HackRF TX, use hackrf=<serial>, not a hardware index')
        if not re.fullmatch(r'[A-Za-z0-9_-]{4,64}', identifier):
            raise ValueError('Invalid HackRF serial')
        cmd.extend(['-d', identifier])
    return cmd


def transmit_iq8(input_file, frequency, gain, device_args, timeout_extra_s=20.0):
    """Run one finite native CLI TX batch; SIGTERM cleans up the child group."""
    from ais_b210_rf_hardware import verify_iq_file, prepare_tx_file
    input_path, _ = verify_iq_file(input_file)
    with tempfile.TemporaryDirectory(prefix='fissure_ais_hackrf_tx_') as tmp:
        root = Path(tmp)
        padded = root / 'tx_padded.cf32'
        iq8 = root / 'tx_native.cs8'
        lead, tail, input_samples = prepare_tx_file(input_path, padded, AIS_RATE, lead_s=1.0, tail_s=0.5)
        metrics = make_hackrf_iq8(padded, iq8)
        cmd = hackrf_tx_command(iq8, frequency, gain, device_args)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        original = signal.getsignal(signal.SIGTERM)
        def interrupted(signum, frame):
            raise KeyboardInterrupt('AIS native HackRF TX interrupted')
        signal.signal(signal.SIGTERM, interrupted)
        try:
            stdout, stderr = proc.communicate(timeout=input_samples / AIS_RATE + timeout_extra_s)
            if proc.returncode:
                raise RuntimeError('hackrf_transfer TX exited %s: %s' % (
                    proc.returncode, stderr.decode('utf-8', 'replace')[-1500:]))
            return dict(metrics, lead_samples=lead, tail_samples=tail,
                        tx_input_samples=input_samples,
                        backend='native_hackrf_transfer_iq8',
                        stderr_tail=stderr.decode('utf-8', 'replace')[-600:])
        finally:
            signal.signal(signal.SIGTERM, original)
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    proc.communicate()
