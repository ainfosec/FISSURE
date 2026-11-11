"""Bounded, single-chain AIS carrier recovery without a manual CFO setting.

The native GNU Radio 3.10 demodulator is hardware-tested separately; these
unit tests verify the new lookahead estimator and uninterrupted streaming.
"""
import math
import sys
from pathlib import Path

import numpy as np
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from ais_burst_carrier_sync_v0922 import BurstCarrierCorrector


@pytest.mark.parametrize('offset_hz', [-3000, -2100, 0, 2100, 2700, 3000])
def test_burst_carrier_recovery_corrects_preamble_and_holds_through_silence(offset_hz):
    sample_rate = 38400
    rng = np.random.default_rng(7600 + int(offset_hz))
    n = sample_rate  # one second, contains two synthetic AIS bursts
    data = (rng.normal(size=n) + 1j*rng.normal(size=n)).astype(np.complex64) * 0.002
    length = 1536  # AIS GMSK burst, 40 ms
    starts = [3500, 16000]
    references = []
    for start in starts:
        bits = rng.choice([-1, 1], length//4)
        instant_hz = np.repeat(bits, 4) * 2400.0
        phase = np.cumsum(2*np.pi*instant_hz/sample_rate)
        baseband = np.exp(1j*phase).astype(np.complex64)
        n_idx = np.arange(length)
        osc = np.exp(1j*2*np.pi*offset_hz*n_idx/sample_rate)
        data[start:start+length] += baseband * osc.astype(np.complex64) * 0.3
        references.append(baseband)
    tracker = BurstCarrierCorrector()
    # Arbitrary GNU Radio work lengths, not aligned with estimator boundaries.
    pieces = []
    cursor = 0
    for size in [197, 59, 4096, 111, 7, 672, 4444, 1200, 29, 8035, n]:
        if cursor >= n:
            break
        chunk = data[cursor:cursor+size]
        pieces.append(tracker.process(chunk))
        cursor += len(chunk)
    if cursor < n:
        pieces.append(tracker.process(data[cursor:]))
    output = np.concatenate(pieces)
    assert len(output) == len(data)
    assert tracker.bursts_acquired == len(starts)
    # Verify *entire* transmitted burst, including the preamble, was corrected.
    # Compare with the known transmitted MSK waveform, ignoring only noise.
    for start, ref in zip(starts, references):
        recovered = output[start+tracker.delay_samples:start+tracker.delay_samples+length]
        phase_error = recovered * np.conj(ref)
        residual_hz = np.angle(np.mean(phase_error[1:]*np.conj(phase_error[:-1]))) * sample_rate / (2*np.pi)
        assert abs(residual_hz) < 200.0, (offset_hz, tracker.frequency_hz, residual_hz)
    assert abs(tracker.frequency_hz-offset_hz) <= 150.0


def test_steady_silence_does_not_reacquire_noise():
    rng = np.random.default_rng(88)
    tracker = BurstCarrierCorrector()
    noise = (rng.normal(size=38400) + 1j*rng.normal(size=38400)).astype(np.complex64) * 0.002
    out = tracker.process(noise)
    assert len(out) == len(noise)
    assert tracker.bursts_acquired == 0
    assert tracker.frequency_hz == 0


def test_bad_fft_parameters_rejected():
    with pytest.raises(ValueError):
        BurstCarrierCorrector(delay_samples=128)
    with pytest.raises(ValueError):
        BurstCarrierCorrector(sample_rate=0)


def test_original_native_sync_is_no_longer_required():
    path = Path(__file__).resolve().parents[1] / 'scripts' / 'ais_gr310_receiver.py'
    code = path.read_text()
    assert 'make_sync(gr, designator)' in code
    assert 'square_and_fft_sync_cc(' not in code
