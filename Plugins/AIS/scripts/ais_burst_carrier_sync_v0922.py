"""Single-chain, burst-aware AIS carrier recovery for GNU Radio 3.10.

This is an adaptation of the frequency-estimation idea in gr-ais's
``square_and_fft_sync_cc``: square the GMSK IQ, find spectral peaks spaced
at the AIS symbol rate, and derotate by half their measured frequency.

The older gr-ais implementation uses 1,024-sample FFTs and continuously
re-estimates in noise. AIS bursts are often shorter than 40 ms, so an
estimate calculated late in a packet is of little help to its preamble.

Here a 256-sample estimator runs only on above-noise burst activity, with a
768-sample lookahead/delay. A correction is selected before the buffered
preamble is released, held for the entire burst, and retained through idle
periods. No scanning, parallel decoders, SDR retuning, or IQ files.

Reference: bistromath/gr-ais and bkerler/gr-ais (GPL-3.0-or-later).
"""
from __future__ import annotations

import math
import sys
from collections import deque

import numpy as np


class BurstCarrierCorrector:
    """Sample-rate-preserving carrier correction with bounded lookahead.

    Feed complex64 chunks of any length to ``process``. The output contains
    an initial 768-sample delay, permitting a short FFT estimate to be made
    from samples arriving *after* the start of a burst, while still correcting
    the first buffered preamble samples. Designed for 4-sps/9600-bps AIS.
    """

    def __init__(self, sample_rate=38400.0, bit_rate=9600.0,
                 fft_size=256, update_size=128, delay_samples=768,
                 label='', diagnostics=False):
        self.sample_rate = float(sample_rate)
        self.bit_rate = float(bit_rate)
        self.fft_size = int(fft_size)
        self.update_size = int(update_size)
        self.delay_samples = int(delay_samples)
        self.label = str(label)
        self.diagnostics = bool(diagnostics)
        if not (math.isfinite(self.sample_rate) and self.sample_rate > 0 and
                math.isfinite(self.bit_rate) and self.bit_rate > 0 and
                self.fft_size >= 64 and self.update_size > 0 and
                self.delay_samples >= self.fft_size + self.update_size):
            raise ValueError('Invalid burst carrier synchronizer parameters')
        self._spacing_bins = round(self.fft_size * self.bit_rate / self.sample_rate)
        if not 1 <= self._spacing_bins < self.fft_size // 2:
            raise ValueError('AIS FFT peak separation outside supported range')
        self._fifo = np.zeros(self.delay_samples, dtype=np.complex64)
        self._history = np.zeros(self.fft_size, dtype=np.complex64)
        self._history_count = 0
        self._pending = np.empty(0, dtype=np.complex64)
        self._noise_power = None
        # FIR/PFB startup can begin with near-zero samples. A noise floor
        # initialized from that first chunk remains far too small, causing
        # every subsequent quiet chunk to be marked active forever. Track a
        # rolling low quantile, which recovers once the filter settles and
        # ignores intermittent strong AIS bursts.
        self._power_history = deque(maxlen=300)
        self._quiet_chunks = 0
        self._in_burst = False
        self._corrected_this_burst = False
        self.frequency_hz = 0.0
        self.bursts_acquired = 0
        self._phase = 0.0
        self._window = np.hanning(self.fft_size).astype(np.float32)

    def _frequency_from_samples(self):
        """Reproduce gr-ais's spectral-peak-pair frequency estimator.

        Squaring GMSK IQ creates peaks separated by the 9600 bit/s symbol
        rate. Their midpoint equals twice the carrier-frequency offset.
        Return (offset_hz, spectral_prominence), without changing state.
        """
        if self._history_count < self.fft_size:
            return 0.0, 0.0
        squared = self._history * self._history
        spectrum = np.abs(np.fft.fftshift(np.fft.fft(squared * self._window)))
        sep = self._spacing_bins
        pairs = spectrum[:-sep] + spectrum[sep:]
        peak_idx = int(np.argmax(pairs))
        confidence = float(pairs[peak_idx] / max(np.median(pairs), 1e-15))
        center_bin = peak_idx + sep / 2.0
        # The squared waveform's offset is 2x the original carrier error.
        offset_hz = (center_bin - self.fft_size / 2.0) * (
            self.sample_rate / self.fft_size) / 2.0
        return float(offset_hz), confidence

    def _inspect(self, current):
        n = len(current)
        if n != self.update_size:
            raise ValueError('Frequency estimator requires exact update chunk')
        self._history = np.concatenate((self._history[n:], current))
        self._history_count = min(self.fft_size, self._history_count + n)
        power = float(np.mean(np.abs(current)**2))
        self._power_history.append(power)
        # The 20th percentile converges on the ambient noise level even
        # when a burst occupies part of the observation interval. It also
        # recovers from a zero-filled startup or a first-chunk burst.
        self._noise_power = max(float(np.quantile(
            np.fromiter(self._power_history, dtype=np.float64), 0.2)), 1e-15)
        noise = self._noise_power
        active = power > noise * 8.0
        if active:
            self._quiet_chunks = 0
            if not self._in_burst:
                self._in_burst = True
                self._corrected_this_burst = False
            if not self._corrected_this_burst:
                estimate, confidence = self._frequency_from_samples()
                # Strong bursts in the previous reference capture show peak
                # ratios ~13–20; reject weak/noise-only FFT hypotheses.
                if confidence >= 8.0 and abs(estimate) <= 6000.0:
                    old_frequency = self.frequency_hz
                    self.frequency_hz = estimate
                    self._corrected_this_burst = True
                    self.bursts_acquired += 1
                    if self.diagnostics and (
                            self.bursts_acquired == 1 or
                            abs(self.frequency_hz - old_frequency) >= 150.0):
                        print('AIS RX carrier sync %s: burst=%d correction=%+.0f Hz '
                              'spectral_confidence=%.1f' % (
                                  self.label, self.bursts_acquired,
                                  self.frequency_hz, confidence),
                              file=sys.stderr, flush=True)
        else:
            if self._in_burst:
                self._quiet_chunks += 1
                if self._quiet_chunks >= 2:
                    self._in_burst = False
                    self._corrected_this_burst = False

    def _delay_and_correct(self, current):
        n = len(current)
        if n > self.delay_samples:
            raise ValueError('Internal delay step larger than buffer')
        delayed = self._fifo[:n].copy()
        self._fifo[:-n] = self._fifo[n:]
        self._fifo[-n:] = current
        # Maintain phase continuity, including when an offset is updated
        # between bursts. The delayed preamble already uses the new offset.
        delta = -2.0 * math.pi * self.frequency_hz / self.sample_rate
        phases = self._phase + delta * np.arange(n, dtype=np.float64)
        self._phase = float((self._phase + delta*n) % (2.0*math.pi))
        return np.asarray(delayed * np.exp(1j*phases), dtype=np.complex64)

    def process(self, samples):
        """Return exactly as many samples as provided, without IQ storage."""
        iq = np.asarray(samples, dtype=np.complex64)
        out = np.empty_like(iq)
        cursor = 0
        while cursor < len(iq):
            needed = self.update_size - len(self._pending)
            size = min(needed, len(iq)-cursor)
            current = iq[cursor:cursor+size]
            # Incoming samples must enter the lookahead before the related
            # old samples leave it. Inspection precedes derotation.
            if len(self._pending) == 0 and size == self.update_size:
                self._inspect(current)
                out[cursor:cursor+size] = self._delay_and_correct(current)
            else:
                # If GNU Radio asks for arbitrary work sizes, collect a
                # fixed estimator chunk while still returning equal output.
                self._pending = np.concatenate((self._pending, current))
                if len(self._pending) == self.update_size:
                    self._inspect(self._pending)
                    self._pending = np.empty(0, dtype=np.complex64)
                out[cursor:cursor+size] = self._delay_and_correct(current)
            cursor += size
        return out


def make_sync(gr, label=''):
    """Create a GNU Radio sync_block around the bounded NumPy DSP kernel."""
    class BurstSync(gr.sync_block):
        def __init__(self):
            gr.sync_block.__init__(
                self, name='fissure_ais_burst_carrier_sync_%s' % (label or 'channel'),
                in_sig=[np.complex64], out_sig=[np.complex64])
            self.tracker = BurstCarrierCorrector(label=label, diagnostics=True)

        def work(self, input_items, output_items):
            inp = input_items[0]
            output_items[0][:len(inp)] = self.tracker.process(inp)
            return len(inp)

    return BurstSync()
