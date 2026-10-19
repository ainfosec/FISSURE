"""Experimental native binary OOK and 2-FSK IQ recovery primitives.

No Dashboard, Sensor Node, or network dependency. These algorithms only make
hard-decision bit candidates; they do not recover frames or verify protocols.
"""

import time
import numpy as np


def _smooth(values, width):
    width = int(width or 1)
    if width <= 1:
        return np.asarray(values, dtype=np.float64)
    width = width + (width % 2 == 0)
    values = np.asarray(values, dtype=np.float64)
    padded = np.pad(values, (width // 2, width // 2), mode="edge")
    return np.convolve(padded, np.ones(width) / width, mode="valid")


def _active_region(magnitude, ignore_quiet=True):
    """Trim only obvious idle IQ at both ends, preserving internal off-symbols."""
    if not ignore_quiet:
        return 0, len(magnitude)
    p05, p95 = np.quantile(magnitude, [0.05, 0.95])
    if p95 < 1e-8 or p95 <= p05 * 1.5:
        return 0, len(magnitude)
    # A small moving envelope ignores momentary OOK gaps when locating the burst.
    envelope = _smooth(magnitude, min(21, max(3, len(magnitude) // 100)))
    active = np.flatnonzero(envelope >= (p05 + 0.26 * (p95 - p05)))
    if len(active) < 64:
        return 0, len(magnitude)
    return max(0, int(active[0]) - 8), min(len(magnitude), int(active[-1]) + 9)


def _ook_burst_centers(base, threshold, samples_per_symbol, timing_offset, nominal_centers):
    """Phase-align independent OOK bursts while retaining idle-bit samples.

    A continuous symbol grid can land in the off half of alternating OOK
    bursts when successive transmissions begin at different clock phases.
    Look for well-separated pulse trains, sample each relative to its own
    first rising edge, and keep the original grid in idle regions. A long
    zero run is only *candidate* burst evidence, never proof of a packet.
    """
    levels = np.asarray(base >= threshold, dtype=np.uint8)
    nominal = np.asarray(nominal_centers, dtype=np.float64)
    sps = float(samples_per_symbol)
    if len(levels) < 32 or sps < 3 or len(nominal) < 8:
        return nominal, []

    changes = np.flatnonzero(np.diff(levels.astype(np.int8))) + 1
    edges = np.r_[0, changes, len(levels)]
    lengths = np.diff(edges)
    states = levels[edges[:-1]]
    # Require long, distinct zero intervals, not ordinary multi-symbol zeros.
    high_runs = lengths[states == 1]
    off_runs = lengths[(states == 0) & (lengths >= max(3, 0.25 * sps))]
    if high_runs.size < 6 or off_runs.size < 2:
        return nominal, []
    ordinary_off = float(np.median(off_runs[off_runs <= np.median(off_runs)]))
    gap_limit = max(8.0 * sps, 3.5 * ordinary_off)
    gaps = np.flatnonzero((states == 0) & (lengths >= gap_limit))
    if gaps.size == 0:
        return nominal, []

    # Retain only regions with enough actual pulses to support an independent
    # clock. Boundaries are positions in the trimmed discriminator, not IQ time.
    intervals = []
    lefts = np.r_[0, edges[gaps + 1]]
    rights = np.r_[edges[gaps], len(levels)]
    min_high_width = max(3, int(0.15 * sps))
    for left, right in zip(lefts, rights):
        left, right = int(left), int(right)
        if right - left < 6 * sps:
            continue
        in_region = np.flatnonzero(
            (states == 1) & (edges[:-1] >= left) &
            (edges[:-1] < right) & (lengths >= min_high_width)
        )
        if in_region.size < 3:
            continue
        first_rise = float(edges[in_region[0]])
        first_center = first_rise + (0.5 + float(timing_offset)) * sps
        if not left <= first_center < right:
            continue
        count = int(np.ceil((right - first_center) / sps))
        local = first_center + np.arange(count, dtype=np.float64) * sps
        local = local[(local >= left) & (local < right)]
        if local.size < 4:
            continue
        intervals.append((left, right, local))

    # Never reinterpret an isolated burst or unstructured noise. That leaves
    # the existing continuous-grid behavior unchanged for single packets.
    if len(intervals) < 2:
        return nominal, []

    keep = np.ones(len(nominal), dtype=bool)
    for left, right, _local in intervals:
        keep &= ~((nominal >= left) & (nominal < right))
    centers = np.sort(np.concatenate([nominal[keep]] + [x[2] for x in intervals]))
    spans = []
    for left, right, _local in intervals:
        first = int(np.searchsorted(centers, left, side='left'))
        end = int(np.searchsorted(centers, right, side='left'))
        spans.append(dict(start_sample=left, end_sample=right,
                          start_bit=first, end_bit=end))
    return centers, spans


def _estimate_fsk_edge_grid_clock(levels, sample_rate, min_samples_per_symbol=4):
    """Refine an approximate FSK bit clock from coherent discriminator edges.

    Ordinary edge-run histograms quantize intervals to whole IQ samples and
    can accumulate a one-chip timing slip during a short packet. Fit fractional
    periods using the circular concentration of *all* transition phases.
    Reject incoherent/noisy solutions; this is timing evidence, not framing.
    """
    levels = np.asarray(levels, dtype=np.uint8)
    if levels.ndim != 1 or len(levels) < 128 or sample_rate <= 0:
        return None
    edges = np.flatnonzero(np.diff(levels.astype(np.int8))) + 1
    if len(edges) < 25:
        return None
    rough_rate = estimate_symbol_rate(levels, sample_rate, min_samples_per_symbol)
    if rough_rate is None or not np.isfinite(rough_rate) or rough_rate <= 0:
        return None
    rough_period = float(sample_rate / rough_rate)
    if rough_period < min_samples_per_symbol or edges[-1] - edges[0] < 25 * rough_period:
        return None

    # Remove very short glitches and cap computation for longer recordings.
    separation = max(3, int(rough_period * .20))
    retained = np.r_[True, np.diff(edges) >= separation]
    edges = edges[retained].astype(np.float64)
    if len(edges) < 25:
        return None
    if len(edges) > 1200:
        edges = edges[np.linspace(0, len(edges) - 1, 1200).astype(np.int64)]

    periods = rough_period * np.linspace(.97, 1.03, 481)
    concentrations = np.exp((2j * np.pi) * edges[:, None] / periods[None, :]).mean(axis=0)
    best = int(np.argmax(np.abs(concentrations)))
    coherence = float(np.abs(concentrations[best]))
    if best in (0, len(periods) - 1) or coherence < .82:
        return None
    period = float(periods[best])
    # Transition phase is equivalent modulo 1; the actual symbol sample is
    # one half-symbol later. Match the Dashboard's [-0.49, 0.49] phase range.
    phase = (float(np.angle(concentrations[best]) / (2 * np.pi)) + .5) % 1.0 - .5
    phase = float(np.clip(phase, -.49, .49))
    jitter = float(np.sqrt(max(0., -2. * np.log(max(coherence, 1e-12)))) / (2 * np.pi))
    return dict(rate=float(sample_rate / period), samples_per_symbol=period,
                timing_offset=phase, transition_count=int(len(edges)),
                timing_jitter_fraction=jitter)


def _candidate(signal, sample_rate, method, settings, start_offset):
    """Build a native OOK/FSK candidate, with sync-fit clock evidence if found."""
    magnitude = np.abs(signal).astype(np.float64)
    smoothing = int(settings.get('smoothing') or 5)
    min_sps = max(3, int(settings.get('min_samples_per_symbol') or 4))
    if method == 'ook':
        base = _smooth(magnitude, smoothing)
        low, high = np.percentile(base, [15, 85])
        threshold = float((low + high) / 2)
        if settings.get('method') == 'ook' and settings.get('parameter_2') is not None:
            threshold = float(settings['parameter_2'])
        elif settings.get('method') == 'auto' and settings.get('parameter_3') is not None:
            threshold = float(settings['parameter_3'])
        if high - low < max(high * .04, 1e-9):
            raise ValueError('No useful ASK/OOK magnitude contrast found')
        deviation = None
    else:
        diff = np.angle(signal[1:] * np.conj(signal[:-1])) * sample_rate / (2 * np.pi)
        base = _smooth(np.r_[diff[0], diff], smoothing)
        low, high = np.percentile(base[1:], [20, 80])
        threshold = float((low + high) / 2)
        if settings.get('method') in ('auto', 'fsk') and settings.get('parameter_2') is not None:
            threshold = float(settings['parameter_2'])
        deviation = float((high - low) / 2)
        if deviation < 10:
            raise ValueError('No useful 2-FSK frequency separation found')
    levels = np.asarray(base >= threshold, dtype=np.uint8)
    clock = _estimate_sync_clock(levels, sample_rate, min_sps)
    # For FSK without a long alternating sync, resolve fractional rate drift
    # from coherent frequency-discriminator transitions before sampling bits.
    if method == 'fsk' and clock is None and settings.get('symbol_rate') is None:
        clock = _estimate_fsk_edge_grid_clock(levels, sample_rate, min_sps)
    symbol_rate = settings.get('symbol_rate')
    if symbol_rate is None:
        symbol_rate = clock['rate'] if clock else estimate_symbol_rate(levels, sample_rate, min_sps)
    if symbol_rate is None:
        raise ValueError(f'Could not estimate {method.upper()} symbol rate; set it manually')
    symbol_rate = float(symbol_rate)
    if not np.isfinite(symbol_rate) or symbol_rate <= 0:
        raise ValueError('Invalid symbol rate')
    sps = float(sample_rate / symbol_rate)
    if sps < min_sps:
        raise ValueError(f'Rate estimate implies fewer than {min_sps} samples/symbol')
    if sps > len(signal):
        raise ValueError('Selected region is shorter than one symbol')
    boundaries = np.flatnonzero(np.diff(levels.astype(np.int8))) + 1
    runs = np.diff(np.r_[0, boundaries, len(levels)])
    runs = runs[(runs >= min_sps) & (runs <= len(levels) // 5)]
    coherence = (float(np.mean(np.abs(runs / sps - np.round(runs / sps)) <= .15))
                 if len(runs) >= 8 else 0.)
    if clock and abs(clock['rate'] / symbol_rate - 1) < 0.03:
        coherence = max(coherence, 1. - min(1., clock['timing_jitter_fraction'] * 3.))
    timing_uncertain = (settings.get('symbol_rate') is None and coherence < .68)
    if timing_uncertain and settings.get('method') == 'auto':
        raise ValueError(f'No consistent {method.upper()} clock found; try manual symbol rate')
    timing = settings.get('timing_offset')
    if timing is None:
        timing = (clock['timing_offset'] if clock and abs(clock['rate'] / symbol_rate - 1) < .03
                  else 0.)
    timing = float(timing)
    if not np.isfinite(timing) or not -.49 <= timing <= .49:
        raise ValueError('Timing offset must be within ±0.49 symbol')
    centers = (np.arange(int(np.ceil(len(base) / sps))) + .5 + timing) * sps
    centers = centers[(centers >= 0) & (centers < len(base))]
    burst_regions = []
    if method == 'ook':
        centers, burst_regions = _ook_burst_centers(base, threshold, sps, timing, centers)
    samples = _fractional_samples(base, centers)
    bits = np.asarray(samples >= threshold, dtype=np.uint8)
    if len(bits) < 8:
        raise ValueError('Too few candidate bits recovered')
    transitions = int(np.count_nonzero(np.diff(bits.astype(np.int8))))
    balance = min(float(np.mean(bits)), 1. - float(np.mean(bits)))
    transitions_fraction = transitions / max(1, len(bits) - 1)
    useful = .05 <= transitions_fraction <= .90 and balance > .025
    if not useful and settings.get('symbol_rate') is None:
        if settings.get('method') == 'auto':
            raise ValueError(f'{method.upper()} trial produced implausible candidate bits')
        timing_uncertain = True
    return dict(
        method=method, sample_rate=float(sample_rate), symbol_rate=symbol_rate,
        frequency_offset=(threshold if method == 'fsk' else None),
        frequency_deviation=deviation, threshold=float(threshold),
        samples_per_symbol=sps, bit_count=len(bits), bits=bits, centers=centers,
        base=base, levels=levels, input_count=len(signal), start_trim=int(start_offset),
        timing_offset=timing, burst_regions=burst_regions,
        burst_aware=bool(burst_regions),
        clock_transition_count=int(clock['transition_count']) if clock else 0,
        clock_timing_jitter=(clock['timing_jitter_fraction'] if clock else None),
        transition_fraction=transitions_fraction, bit_balance=balance,
        run_alignment=coherence, timing_uncertain=bool(timing_uncertain),
        candidate_score=float(balance * .55 + min(transitions_fraction, .5) * .45),
    )


def _fractional_samples(values, positions):
    values = np.asarray(values)
    positions = np.asarray(positions, dtype=np.float64)
    index = np.floor(positions).astype(np.int64)
    next_index = np.minimum(index + 1, len(values) - 1)
    fraction = positions - index
    return values[index] + fraction * (values[next_index] - values[index])


def _estimate_sync_clock(levels, sample_rate, min_samples_per_symbol=4):
    """Fit a clock across a run of nearly periodic state transitions.

    Alternating preambles can have threshold-crossing jitter (e.g. 9, 11, 9,
    11 samples for a ten-sample symbol). Regression over *many* transitions
    removes the short-run bias. Do not assume the signal uses a known protocol.
    Return None if no sufficiently long and coherent sequence is detected.
    """
    levels = np.asarray(levels, dtype=np.uint8)
    if levels.ndim != 1 or len(levels) < 128 or sample_rate <= 0:
        return None
    changes = np.flatnonzero(np.diff(levels.astype(np.int8))) + 1
    if changes.size < 25:
        return None
    lengths = np.diff(changes)
    plausible = lengths[(lengths >= max(3, int(min_samples_per_symbol) - 2)) &
                        (lengths <= max(32, len(levels) // 8))]
    if len(plausible) < 24:
        return None
    durations, counts = np.unique(plausible, return_counts=True)
    leaders = durations[np.argsort(counts)[-16:]]
    candidates = np.unique(np.r_[leaders, np.median(plausible)])
    best = None
    for candidate in candidates:
        candidate = float(candidate)
        tolerance = max(2.25, candidate * 0.25)
        mask = (lengths >= max(3.0, candidate - tolerance)) & (lengths <= candidate + tolerance)
        edges = np.flatnonzero(np.diff(np.r_[False, mask, False].astype(np.int8)))
        for begin, finish in zip(edges[::2], edges[1::2]):
            count = int(finish - begin)
            if count < 24:
                continue
            group = changes[begin:finish + 1].astype(np.float64)
            x = np.arange(len(group), dtype=np.float64)
            period, intercept = np.polyfit(x, group, 1)
            if period < min_samples_per_symbol or period > len(levels) / 4:
                continue
            residual = float(np.sqrt(np.mean((group - (period * x + intercept))**2)))
            jitter_fraction = residual / period
            if jitter_fraction > 0.16:
                continue
            # Favor longer alternating sequences, then lower crossing jitter.
            quality = (count, -jitter_fraction)
            if best is None or quality > best['quality']:
                # Centers are placed half a symbol after a transition; the
                # phase is relative to (index + 0.5) * samples_per_symbol.
                phase = ((intercept / period + 0.5) % 1.0) - 0.5
                phase = float(np.clip(phase, -0.49, 0.49))
                best = dict(
                    rate=float(sample_rate / period),
                    samples_per_symbol=float(period),
                    timing_offset=phase,
                    transition_count=count + 1,
                    timing_jitter_fraction=jitter_fraction,
                    start_transition=int(changes[begin]),
                    quality=quality,
                )
    if best is None:
        return None
    best.pop('quality')
    return best


def estimate_symbol_rate(levels, sample_rate, min_samples_per_symbol=4):
    """Estimate a binary clock, preferring a stable alternating transition run.

    Falls back to the exploratory run-length estimate when no coherent run
    exists. The fallback remains unverified and should be qualified by users.
    """
    sync = _estimate_sync_clock(levels, sample_rate, min_samples_per_symbol)
    if sync is not None:
        return sync['rate']
    levels = np.asarray(levels, dtype=np.uint8)
    if levels.ndim != 1 or len(levels) < 128:
        return None
    if not np.isfinite(sample_rate) or sample_rate <= 0:
        return None
    changes = np.flatnonzero(np.diff(levels.astype(np.int8))) + 1
    if len(changes) < 6:
        return None
    runs = np.diff(np.r_[0, changes, len(levels)])
    minimum = max(3, int(min_samples_per_symbol))
    valid = runs[(runs >= minimum) & (runs <= len(levels) // 5)]
    if len(valid) < 6:
        return None
    low_runs = valid[valid <= np.percentile(valid, 55)]
    if len(low_runs) < 4:
        return None
    reference = float(np.median(low_runs))
    if reference < minimum or reference > len(levels) / 4:
        return None
    consistency = np.mean((valid >= reference * .70) & (valid <= reference * 3.3))
    if consistency < .40:
        return None
    return float(sample_rate / reference)


def _auto_fsk_evidence(signal, sample_rate, candidate, smoothing=5):
    """Check if a coherent two-tone discriminator outweighs envelope contrast.

    This is modulation evidence only. It does not validate recovered bits,
    framing, or protocol identity. Favor 2-FSK only when its two tone states
    retain appreciable carrier energy and have stable, separated frequencies.
    """
    rate = candidate.get('symbol_rate')
    threshold = candidate.get('frequency_offset')
    if threshold is None:
        threshold = candidate.get('threshold')
    if rate is None or threshold is None or not np.isfinite(rate) or rate <= 0:
        return dict(prefer_fsk=False)
    sps = float(sample_rate / rate)
    if sps < 3 or len(signal) < 32 * sps:
        return dict(prefer_fsk=False)

    diff = np.angle(signal[1:] * np.conj(signal[:-1])) * sample_rate / (2 * np.pi)
    frequency = _smooth(np.r_[diff[0], diff], smoothing)
    magnitude = _smooth(np.abs(signal), smoothing)
    phase = candidate.get('timing_offset')
    phase = float(phase) if phase is not None else 0.0
    centers = (np.arange(int(np.ceil(len(signal) / sps))) + .5 + phase) * sps
    centers = centers[(centers >= 0) & (centers < len(signal))]
    if len(centers) < 32:
        return dict(prefer_fsk=False)
    f = _fractional_samples(frequency, centers)
    a = _fractional_samples(magnitude, centers)
    high = f >= float(threshold)
    if min(np.count_nonzero(high), np.count_nonzero(~high)) < 12:
        return dict(prefer_fsk=False)

    frequencies = (float(np.median(f[~high])), float(np.median(f[high])))
    dispersion = (float(np.median(np.abs(f[~high] - frequencies[0]))),
                  float(np.median(np.abs(f[high] - frequencies[1]))))
    amplitudes = (float(np.median(a[~high])), float(np.median(a[high])))
    separation = abs(frequencies[1] - frequencies[0])
    tone_contrast = separation / max(sum(dispersion), 1.0)
    carrier_ratio = min(amplitudes) / max(max(amplitudes), 1e-12)
    transitions = int(candidate.get('clock_transition_count') or 0)
    jitter = candidate.get('clock_timing_jitter')
    alignment = float(candidate.get('run_alignment') or 0.)
    clock_ok = transitions >= 25 and (
        (jitter is not None and float(jitter) <= .12) or alignment >= .82
    )
    prefer_fsk = bool(
        clock_ok and carrier_ratio >= .45 and tone_contrast >= 2.5
        and separation >= max(300., .15 * float(rate))
    )
    return dict(prefer_fsk=prefer_fsk, tone_separation_hz=separation,
                tone_contrast=tone_contrast, carrier_ratio=carrier_ratio,
                clock_transition_count=transitions)


def estimate_parameters(data, sample_rate, settings):
    """Estimate parameters without recovering symbols or bits."""
    started = time.monotonic()
    z = np.asarray(data)
    if z.ndim != 1 or not 128 <= len(z) <= 2_000_000 or not np.iscomplexobj(z):
        raise ValueError('Select 128 to 2,000,000 complex IQ samples')
    if not np.isfinite(sample_rate) or sample_rate <= 0 or not np.all(np.isfinite(z)):
        raise ValueError('Valid IQ and positive sample rate required')
    z = np.asarray(z, dtype=np.complex64)
    lo, hi = _active_region(np.abs(z), settings.get('ignore_quiet', True))
    active = z[lo:hi]
    if len(active) < 128:
        raise ValueError('No sufficiently long active signal found')
    magnitude = np.abs(active).astype(np.float64)
    outside = np.r_[z[:max(0, lo-8)], z[min(len(z), hi+8):]]
    burst_strength = (float(np.median(magnitude) / max(np.median(np.abs(outside)), 1e-8))
                      if len(outside) >= 64 else 1.)
    p15, p85 = np.percentile(magnitude, [15, 85])
    contrast = float((p85 - p15) / max(p85, 1e-9))
    smoothing = int(settings.get('smoothing') or 5)
    min_sps = max(3, int(settings.get('min_samples_per_symbol') or 4))
    suggestions = []
    method = str(settings.get('method') or 'auto')
    for candidate_method in (('ook', 'fsk') if method == 'auto' else (method,)):
        if candidate_method == 'ook':
            base = _smooth(magnitude, smoothing)
            low, high = np.percentile(base, [15, 85])
            if high - low < max(high * .04, 1e-9):
                continue
            threshold, offset, deviation = float((low + high) / 2), None, None
        elif candidate_method == 'fsk':
            diff = np.angle(active[1:] * np.conj(active[:-1])) * sample_rate / (2 * np.pi)
            base = _smooth(np.r_[diff[0], diff], smoothing)
            low, high = np.percentile(base[1:], [20, 80])
            deviation = float((high - low) / 2)
            if deviation < 10:
                continue
            threshold, offset = float((low + high) / 2), float((low + high) / 2)
        else:
            continue
        levels = np.asarray(base >= threshold, dtype=np.uint8)
        clock = _estimate_sync_clock(levels, sample_rate, min_sps)
        if candidate_method == 'fsk' and clock is None and settings.get('symbol_rate') is None:
            clock = _estimate_fsk_edge_grid_clock(levels, sample_rate, min_sps)
        rate = clock['rate'] if clock else estimate_symbol_rate(levels, sample_rate, min_sps)
        if rate is not None and burst_strength < 3.0 and not clock:
            changes = np.flatnonzero(np.diff(levels.astype(np.int8))) + 1
            runs = np.diff(np.r_[0, changes, len(levels)])
            valid = runs[runs >= min_sps]
            period = sample_rate / rate
            alignment = (float(np.mean(np.abs(valid / period - np.round(valid / period)) <= .15))
                         if len(valid) >= 8 else 0.)
            if alignment < .68:
                rate = None
        priority = 1. - contrast if candidate_method == 'fsk' else contrast
        suggestions.append(dict(method=candidate_method, symbol_rate=rate,
                                threshold=threshold, frequency_offset=offset,
                                frequency_deviation=deviation,
                                timing_offset=clock['timing_offset'] if clock else None,
                                clock_transition_count=clock['transition_count'] if clock else 0,
                                clock_timing_jitter=clock['timing_jitter_fraction'] if clock else None,
                                priority=priority))
    if not suggestions or (burst_strength < 3 and not any(s['symbol_rate'] is not None for s in suggestions)):
        raise ValueError('No reliable modulation parameters; signal may be noise')
    suggestions.sort(key=lambda item: item['priority'], reverse=True)
    best = suggestions[0]
    auto_evidence = None
    if method == 'auto':
        fsk = next((item for item in suggestions if item['method'] == 'fsk'), None)
        if fsk is not None:
            auto_evidence = _auto_fsk_evidence(
                active, sample_rate, fsk, smoothing=smoothing
            )
            if auto_evidence['prefer_fsk']:
                best = fsk
    note = (f'Envelope contrast {contrast:.2f}; fitted clock transitions: '
            f"{best['clock_transition_count']}.")
    if auto_evidence and auto_evidence['prefer_fsk']:
        note += (f" Strong 2-FSK frequency evidence: "
                 f"{auto_evidence['tone_separation_hz']:,.0f} Hz tone separation, "
                 f"carrier-state amplitude ratio {auto_evidence['carrier_ratio']:.2f}.")
    note += ' Parameter estimate only; no bits/framing/CRC verified.'
    best.update(elapsed=float(time.monotonic() - started),
                candidates=[item['method'] for item in suggestions],
                timing_uncertain=best['symbol_rate'] is None,
                note=note)
    return best


def recover_candidate(data, sample_rate, settings):
    """Recover an unverified OOK/2-FSK candidate with evidence-limited Auto fallback.

    Auto may return a specifically marked *diagnostic* FSK candidate when
    burst-envelope evidence supports FSK but symbol timing is inconsistent.
    This is deliberately not a claim that its bits are decoded correctly.
    """
    started = time.monotonic()
    z = np.asarray(data)
    if z.ndim != 1 or len(z) < 128 or len(z) > 2_000_000:
        raise ValueError("Select between 128 and 2,000,000 IQ samples")
    if not np.iscomplexobj(z):
        raise ValueError("Recovery requires complex IQ samples")
    if not np.isfinite(sample_rate) or sample_rate <= 0:
        raise ValueError("Positive sample rate required")
    z = np.asarray(z, dtype=np.complex64)
    if not np.all(np.isfinite(z)):
        raise ValueError("IQ contains non-finite samples")
    method = str(settings.get("method") or "auto").lower()
    if method not in ("auto", "ook", "fsk"):
        raise ValueError(f"Unsupported modulation: {method}")
    lo, hi = _active_region(np.abs(z), settings.get("ignore_quiet", True))
    trimmed = z[lo:hi]
    if len(trimmed) < 128:
        raise ValueError("Too few active IQ samples to analyze")
    mags = np.abs(trimmed)
    p15, p85 = np.percentile(mags, [15, 85])
    contrast = float((p85-p15) / max(p85, 1e-9))
    has_burst_edge = lo > 0 or hi < len(z)
    successes, errors = [], []
    for trial in (("ook", "fsk") if method == "auto" else (method,)):
        try:
            successes.append(_candidate(trimmed, sample_rate, trial, settings, lo))
        except ValueError as exc:
            errors.append(f"{trial.upper()}: {exc}")

    # Existing threshold/clock checks can reject a real short FSK packet.
    # A burst with low *within-burst* amplitude contrast is enough to offer a
    # tentative FSK discriminator preview, but not a verified bitstream.
    if method == "auto" and not any(x["method"] == "fsk" for x in successes):
        evidence_for_fsk = has_burst_edge and len(trimmed) >= 512 and contrast < 0.48
        if evidence_for_fsk:
            manual_settings = dict(settings, method="fsk")
            try:
                fallback = _candidate(trimmed, sample_rate, "fsk", manual_settings, lo)
            except ValueError as exc:
                errors.append(f"FSK diagnostic: {exc}")
            else:
                fallback["timing_uncertain"] = True
                fallback["diagnostic_only"] = True
                successes.append(fallback)

    if not successes:
        raise ValueError("; ".join(errors))
    if method == "auto":
        preferred = "ook" if contrast > 0.5 else "fsk"
        fsk = next((item for item in successes if item['method'] == 'fsk'
                    and not item.get('diagnostic_only')), None)
        auto_evidence = (_auto_fsk_evidence(trimmed, sample_rate, fsk,
                                           smoothing=int(settings.get('smoothing') or 5))
                         if fsk is not None else dict(prefer_fsk=False))
        if auto_evidence['prefer_fsk']:
            preferred = 'fsk'
        matches = [item for item in successes if item['method'] == preferred]
        result = matches[0] if matches else successes[0]
        note = (f"Auto considered OOK and 2-FSK. Envelope contrast {contrast:.2f}; "
                f"selected {result['method'].upper()}.")
        if auto_evidence['prefer_fsk']:
            note += (f" Coherent 2-FSK discriminator with "
                     f"{auto_evidence['tone_separation_hz']:,.0f} Hz tone separation "
                     f"and carrier-state amplitude ratio "
                     f"{auto_evidence['carrier_ratio']:.2f} outweighs envelope contrast.")
    else:
        result = successes[0]
        note = f"Manual {method.upper()} trial."
    if result.get("diagnostic_only"):
        note += " Tentative FSK preview, symbol clock not reliable."
    result["auto_selection"] = method == "auto"
    result["attempts"] = [(x["method"], x["symbol_rate"], x["candidate_score"]) for x in successes]
    result["elapsed"] = float(time.monotonic() - started)
    result["note"] = (note + " No timing lock, bit-polarity verification, framing or CRC validation.")
    return result


def retime_cached_candidate(result, symbol_rate=None, threshold=None, timing_offset=0.0):
    """Recalculate fractional-sample bit decisions from a cached discriminator.

    Does not repeat IQ preprocessing or modify the original recovered result.
    This is a diagnostic preview, not a validated decoded frame.
    """
    base = np.asarray(result['base'])
    sample_rate = float(result['sample_rate'])
    rate = float(result['symbol_rate'] if symbol_rate is None else symbol_rate)
    level = float(result['threshold'] if threshold is None else threshold)
    phase = float(timing_offset)
    if not np.isfinite(rate) or not 0 < rate <= sample_rate:
        raise ValueError('Symbol rate must be positive and at most the sample rate')
    if not np.isfinite(level) or not -.49 <= phase <= .49:
        raise ValueError('Decision threshold or phase is invalid')
    sps = sample_rate / rate
    count = int(np.ceil(len(base) / sps))
    if count > 250_000:
        raise ValueError('Too many bits for live preview')
    centers = (np.arange(count, dtype=np.float64) + .5 + phase) * sps
    centers = centers[(centers >= 0) & (centers < len(base))]
    burst_regions = []
    if result.get('method') == 'ook':
        centers, burst_regions = _ook_burst_centers(base, level, sps, phase, centers)
    samples = _fractional_samples(base, centers)
    levels = np.asarray(base >= level, dtype=np.uint8)
    bits = np.asarray(samples >= level, dtype=np.uint8)
    if bits.size == 0:
        raise ValueError('Not enough samples for live preview')
    updated = dict(result)
    updated.update(
        symbol_rate=rate, samples_per_symbol=sps,
        threshold=level, timing_offset=phase,
        levels=levels, centers=centers, bits=bits,
        burst_regions=burst_regions, burst_aware=bool(burst_regions),
        bit_count=len(bits), live_preview=True,
        frequency_offset=level if result.get('method') == 'fsk' else None,
    )
    return updated