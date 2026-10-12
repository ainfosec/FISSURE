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
        timing_offset=timing,
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
                                priority=priority))
    if not suggestions or (burst_strength < 3 and not any(s['symbol_rate'] is not None for s in suggestions)):
        raise ValueError('No reliable modulation parameters; signal may be noise')
    suggestions.sort(key=lambda item: item['priority'], reverse=True)
    best = suggestions[0]
    best.update(elapsed=float(time.monotonic() - started),
                candidates=[item['method'] for item in suggestions],
                timing_uncertain=best['symbol_rate'] is None,
                note=(f'Envelope contrast {contrast:.2f}; fitted clock transitions: '
                      f"{best['clock_transition_count']}. Parameter estimate only; "
                      'no bits/framing/CRC verified.'))
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
        matches = [item for item in successes if item["method"] == preferred]
        result = matches[0] if matches else successes[0]
        note = (f"Auto considered OOK and 2-FSK. Preferred {preferred.upper()} "
                f"from active-burst envelope contrast ({contrast:.2f}); "
                f"selected {result['method'].upper()}.")
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
        bit_count=len(bits), live_preview=True,
        frequency_offset=level if result.get('method') == 'fsk' else None,
    )
    return updated