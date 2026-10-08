import csv
import json
from pathlib import Path

import numpy as np


SUPPORTED_REPRESENTATIONS = (
    "auto",
    "pdw_csv",
    "log_video_f32",
    "iq_cf32",
)

PDW_REQUIRED_COLUMNS = {"toa_s"}
PDW_OPTIONAL_COLUMNS = {
    "pulse_width_s",
    "amplitude",
    "carrier_offset_hz",
}


def _finite(values):
    array = np.asarray(values, dtype=float)
    return array[np.isfinite(array)]


def _paired_finite(first, second):
    first = np.asarray(first, dtype=float)
    second = np.asarray(second, dtype=float)
    count = min(len(first), len(second))
    first = first[:count]
    second = second[:count]
    valid = np.isfinite(first) & np.isfinite(second)
    return first[valid], second[valid]


def _stats(values):
    values = _finite(values)
    if not len(values):
        return None

    return {
        "count": int(len(values)),
        "min": float(np.min(values)),
        "max": float(np.max(values)),
        "mean": float(np.mean(values)),
        "median": float(np.median(values)),
        "std": float(np.std(values)),
    }


def _fmt(value, unit=""):
    if value is None:
        return "not observable"
    return f"{value:.6g}{unit}"


def _cluster_levels(values, tolerance_abs=None, tolerance_rel=0.025):
    values = np.sort(_finite(values))
    if not len(values):
        return []

    tolerance = (
        tolerance_abs
        if tolerance_abs is not None
        else max(
            np.median(np.abs(values)) * tolerance_rel,
            1e-15,
        )
    )

    groups = [[float(values[0])]]

    for value in values[1:]:
        if abs(value - np.mean(groups[-1])) <= tolerance:
            groups[-1].append(float(value))
        else:
            groups.append([float(value)])

    return [
        {
            "center": float(np.mean(group)),
            "count": len(group),
            "std": float(np.std(group)),
        }
        for group in groups
    ]


def _pri_behavior(pri):
    pri = _finite(pri)
    if len(pri) < 4:
        return {
            "type": "indeterminate",
            "reason": "too few intervals",
        }

    median = float(np.median(pri))
    standard_deviation = float(np.std(pri))
    coefficient_of_variation = (
        standard_deviation / median
        if median
        else float("inf")
    )

    if coefficient_of_variation < 0.005:
        return {
            "type": "constant",
            "confidence": "high",
            "basis": "PRI coefficient of variation below 0.5%",
        }

    levels = _cluster_levels(
        pri,
        tolerance_abs=max(3e-6, median * 0.015),
    )
    significant = [
        group
        for group in levels
        if group["count"] >= max(3, int(0.03 * len(pri)))
    ]

    if (
        2 <= len(significant) <= 8
        and sum(group["count"] for group in significant) >= 0.9 * len(pri)
    ):
        centers = np.array(
            [group["center"] for group in significant]
        )
        sequence = np.argmin(
            abs(pri[:, None] - centers[None, :]),
            axis=1,
        )

        best_period = None
        best_match = 0.0

        for period in range(
            2,
            min(16, len(sequence) // 3 + 1),
        ):
            match = float(
                np.mean(
                    sequence[period:] == sequence[:-period]
                )
            )
            if match > best_match:
                best_period = period
                best_match = match

        if best_match >= 0.85:
            return {
                "type": "staggered",
                "confidence": "high",
                "levels_s": [float(value) for value in centers],
                "sequence_period_pulses": int(best_period),
                "repeat_match": best_match,
            }

        return {
            "type": "discrete/multi-level",
            "confidence": "medium",
            "levels_s": [float(value) for value in centers],
        }

    if coefficient_of_variation >= 0.02:
        return {
            "type": "jittered/variable",
            "confidence": "medium",
            "basis": (
                "continuous PRI spread without a compact repeating level set"
            ),
            "coefficient_of_variation": coefficient_of_variation,
        }

    return {
        "type": "variable",
        "confidence": "low",
        "basis": (
            "variation exceeds constant threshold but pattern is not clearly "
            "discrete or continuous"
        ),
    }


def _parabolic_peak(values, index):
    """Return a fractional-bin peak using three-point parabolic interpolation."""
    if index <= 0 or index >= len(values) - 1:
        return float(index)

    left = float(values[index - 1])
    center = float(values[index])
    right = float(values[index + 1])
    denominator = left - 2.0 * center + right

    if abs(denominator) <= np.finfo(float).eps:
        return float(index)

    delta = 0.5 * (left - right) / denominator
    delta = max(-0.5, min(0.5, delta))
    return float(index) + delta


def _scan_periodicity(toa, amplitude):
    toa, amplitude = _paired_finite(toa, amplitude)
    count = len(toa)

    if (
        count < 40
        or np.std(amplitude)
        < max(1e-8, 0.02 * abs(np.mean(amplitude)))
    ):
        return {
            "detected": False,
            "reason": "insufficient amplitude variation or pulse count",
        }

    centered = amplitude - np.mean(amplitude)
    window = np.hanning(count)
    windowed = centered * window

    # Preserve the original count-length spectrum for the detection decision.
    # This avoids changing the established behavior merely because the estimate
    # below uses zero padding for finer period resolution.
    coarse_spectrum = np.abs(np.fft.rfft(windowed)) ** 2
    if len(coarse_spectrum) < 4:
        return {
            "detected": False,
            "reason": "insufficient spectral bins",
        }

    coarse_spectrum[0] = 0.0
    coarse_index = int(np.argmax(coarse_spectrum))
    total_power = float(np.sum(coarse_spectrum[1:])) or 1.0
    dominance = float(
        coarse_spectrum[coarse_index] / total_power
    )

    if coarse_index == 0 or dominance < 0.28:
        return {
            "detected": False,
            "reason": "no dominant amplitude periodicity",
            "dominant_fraction": dominance,
        }

    # The original implementation converted the coarse FFT-bin index directly
    # into a period. For short pulse trains that can produce a large error when
    # the true periodicity sits between bins. Refine only the measurement using
    # a zero-padded spectrum around the same coarse spectral neighborhood.
    minimum_fft_size = max(256, count * 16)
    fft_size = 1 << int(
        np.ceil(np.log2(minimum_fft_size))
    )
    refined_spectrum = np.abs(
        np.fft.rfft(windowed, n=fft_size)
    ) ** 2
    refined_spectrum[0] = 0.0

    coarse_frequency = coarse_index / count
    lower_frequency = max(
        1.0 / fft_size,
        (coarse_index - 1.0) / count,
    )
    upper_frequency = min(
        0.5,
        (coarse_index + 1.0) / count,
    )

    lower_index = max(
        1,
        int(np.floor(lower_frequency * fft_size)),
    )
    upper_index = min(
        len(refined_spectrum) - 1,
        int(np.ceil(upper_frequency * fft_size)),
    )

    if upper_index <= lower_index:
        refined_index = coarse_frequency * fft_size
    else:
        search = refined_spectrum[
            lower_index : upper_index + 1
        ]
        peak_index = lower_index + int(np.argmax(search))
        refined_index = _parabolic_peak(
            refined_spectrum,
            peak_index,
        )

    frequency_cycles_per_pulse = refined_index / fft_size
    if frequency_cycles_per_pulse <= 0:
        return {
            "detected": False,
            "reason": "invalid amplitude periodicity estimate",
            "dominant_fraction": dominance,
        }

    period_pulses = 1.0 / frequency_cycles_per_pulse
    median_pri = (
        float(np.median(np.diff(toa)))
        if count > 1
        else None
    )

    return {
        "detected": True,
        "confidence": (
            "medium"
            if dominance < 0.55
            else "high"
        ),
        "period_pulses": period_pulses,
        "period_s": (
            period_pulses * median_pri
            if median_pri
            else None
        ),
        "dominant_fraction": dominance,
    }


def _detect_pulses(samples, sample_rate_hz, iq=False):
    samples = np.asarray(samples)
    envelope = np.abs(samples).astype(
        np.float32,
        copy=False,
    )

    median = float(np.median(envelope))
    mad = float(
        np.median(
            np.abs(envelope - median)
        )
    )
    sigma = 1.4826 * mad
    epsilon = np.finfo(float).eps

    threshold = median + (6.0 if not iq else 5.0) * max(
        sigma,
        epsilon,
    )
    mask = envelope > threshold
    indices = np.flatnonzero(mask)
    segments = []

    max_gap = 2
    minimum_length = max(
        3,
        int(round(sample_rate_hz * 3e-6)),
    )

    if len(indices):
        start = previous = int(indices[0])

        for index in indices[1:]:
            index = int(index)

            if index - previous <= max_gap + 1:
                previous = index
                continue

            if previous - start + 1 >= minimum_length:
                segments.append(
                    (start, previous + 1)
                )

            start = previous = index

        if previous - start + 1 >= minimum_length:
            segments.append(
                (start, previous + 1)
            )

    # Refine edges to a lower threshold to reduce high-threshold pulse-width
    # bias. This remains deliberately conservative until pulse-width handling
    # is validated against more than the synthetic corpus.
    lower_threshold = median + 2.5 * max(
        sigma,
        epsilon,
    )
    refined = []

    for start, end in segments:
        refined_start = start
        while (
            refined_start > 0
            and envelope[refined_start - 1] > lower_threshold
        ):
            refined_start -= 1

        refined_end = end
        while (
            refined_end < len(envelope)
            and envelope[refined_end] > lower_threshold
        ):
            refined_end += 1

        if (
            not refined
            or refined_start > refined[-1][1] + 2
        ):
            refined.append(
                [refined_start, refined_end]
            )
        else:
            refined[-1][1] = max(
                refined[-1][1],
                refined_end,
            )

    return (
        envelope,
        [
            (int(start), int(end))
            for start, end in refined
        ],
        {
            "baseline_median": median,
            "robust_sigma": sigma,
            "detection_threshold": threshold,
        },
    )


def _pulse_arrays(envelope, segments, sample_rate_hz):
    starts = np.array(
        [start for start, _end in segments],
        dtype=float,
    )
    ends = np.array(
        [end for _start, end in segments],
        dtype=float,
    )

    toa = starts / sample_rate_hz
    pulse_width = (ends - starts) / sample_rate_hz

    peak = (
        np.array(
            [
                float(np.max(envelope[start:end]))
                for start, end in segments
            ]
        )
        if segments
        else np.array([])
    )

    mean = (
        np.array(
            [
                float(np.mean(envelope[start:end]))
                for start, end in segments
            ]
        )
        if segments
        else np.array([])
    )

    return toa, pulse_width, peak, mean


def _iq_frequency_features(samples, segments, sample_rate_hz):
    offsets = []
    chirp_slopes = []
    chirp_bandwidths = []
    chirp_r_squared = []

    for start, end in segments:
        pulse = np.asarray(
            samples[start:end],
            dtype=complex,
        )

        if len(pulse) < 6:
            continue

        # Detector transitions are the least reliable samples for phase fits.
        if len(pulse) > 10:
            pulse = pulse[1:-1]

        product = pulse[1:] * np.conj(pulse[:-1])
        offset = float(
            np.angle(np.sum(product))
            * sample_rate_hz
            / (2.0 * np.pi)
        )
        offsets.append(offset)

        if len(pulse) < 12:
            continue

        phase = np.unwrap(np.angle(pulse))
        time_values = np.arange(len(pulse)) / sample_rate_hz
        fit = np.polyfit(
            time_values,
            phase,
            2,
        )
        prediction = np.polyval(
            fit,
            time_values,
        )

        total_variance = float(
            np.sum(
                (phase - np.mean(phase)) ** 2
            )
        )
        residual = float(
            np.sum(
                (phase - prediction) ** 2
            )
        )
        r_squared = (
            1.0 - residual / total_variance
            if total_variance > 0
            else 0.0
        )

        slope = float(fit[0] / np.pi)
        bandwidth = (
            abs(slope)
            * (len(pulse) - 1)
            / sample_rate_hz
        )

        chirp_slopes.append(slope)
        chirp_bandwidths.append(bandwidth)
        chirp_r_squared.append(r_squared)

    result = {
        "pulse_frequency_offset_hz": _stats(offsets),
    }

    if chirp_r_squared:
        r_squared = np.asarray(chirp_r_squared)
        bandwidths = np.asarray(chirp_bandwidths)
        slopes = np.asarray(chirp_slopes)

        supported = (
            (r_squared > 0.93)
            & (
                bandwidths
                > max(15000.0, 0.03 * sample_rate_hz)
            )
        )
        supporting_fraction = float(
            np.mean(supported)
        )

        result["lfm"] = {
            "detected": bool(
                supporting_fraction >= 0.5
            ),
            "supporting_pulse_fraction": supporting_fraction,
            "median_phase_fit_r2": float(
                np.median(r_squared)
            ),
        }

        if supporting_fraction >= 0.5:
            result["lfm"].update(
                {
                    "confidence": (
                        "medium"
                        if supporting_fraction < 0.8
                        else "high"
                    ),
                    "chirp_bandwidth_hz": _stats(
                        bandwidths[supported]
                    ),
                    "chirp_slope_hz_per_s": _stats(
                        slopes[supported]
                    ),
                }
            )
        else:
            result["lfm"]["reason"] = (
                "linear phase-curvature test not supported by a majority "
                "of usable pulses"
            )
    else:
        result["lfm"] = {
            "detected": False,
            "reason": "pulses too short for chirp fit",
        }

    return result, np.asarray(offsets, dtype=float)


def _recover_periodic_grid(
    segments,
    envelope,
    sample_rate_hz,
):
    """Recover weak pulses only when strong detections establish a stable grid."""
    if len(segments) < 30:
        return segments, None

    starts = np.asarray(
        [start for start, _end in segments],
        dtype=int,
    )
    widths = np.asarray(
        [end - start for start, end in segments],
        dtype=int,
    )
    differences = np.diff(starts)

    if not len(differences):
        return segments, None

    first_quartile = np.quantile(
        differences,
        0.25,
    )
    low_differences = differences[
        differences <= first_quartile
    ]
    base_period = int(
        round(
            float(
                np.median(low_differences)
                if len(low_differences)
                else np.min(differences)
            )
        )
    )

    if base_period < max(
        20,
        int(5 * np.median(widths)),
    ):
        return segments, None

    ratio = differences / base_period
    fit = np.abs(
        ratio - np.rint(ratio)
    ) <= 0.02

    if float(np.mean(fit)) < 0.90:
        return segments, None

    grid = np.arange(
        starts[0],
        starts[-1] + base_period // 2,
        base_period,
        dtype=int,
    )

    if (
        len(grid) < 1.20 * len(starts)
        or len(grid) > 3 * len(starts)
    ):
        return segments, None

    width = max(
        3,
        int(round(np.median(widths))),
    )
    recovered = [
        (
            int(grid_start),
            min(
                len(envelope),
                int(grid_start) + width,
            ),
        )
        for grid_start in grid
        if int(grid_start) + width <= len(envelope)
    ]

    return recovered, {
        "method": "stable-periodic-grid",
        "base_period_samples": base_period,
        "strong_detected_pulses": int(
            len(segments)
        ),
        "recovered_grid_pulses": int(
            len(recovered)
        ),
        "grid_interval_fit_fraction": float(
            np.mean(fit)
        ),
        "note": (
            "Weak-pulse recovery applied only because strong detections "
            "established a stable grid and at least 20% of grid slots were "
            "absent from threshold detections."
        ),
    }


def _group_details(
    toa,
    feature,
    tolerance_abs,
    feature_name,
):
    toa, feature = _paired_finite(
        toa,
        feature,
    )

    if len(toa) < 10:
        return []

    levels = _cluster_levels(
        feature,
        tolerance_abs=tolerance_abs,
    )
    significant = [
        group
        for group in levels
        if group["count"]
        >= max(4, int(0.04 * len(feature)))
    ]

    details = []

    for group in significant:
        mask = (
            np.abs(feature - group["center"])
            <= tolerance_abs
        )
        group_toa = np.sort(toa[mask])
        pri = np.diff(group_toa)

        details.append(
            {
                "group_feature": feature_name,
                "feature_center": float(
                    group["center"]
                ),
                "pulse_count": int(
                    np.sum(mask)
                ),
                "pri_s": _stats(pri),
                "pri_behavior": _pri_behavior(pri),
            }
        )

    return details if len(details) >= 2 else []


def _multiple_emitters(
    offsets=None,
    pulse_width=None,
    amplitude=None,
):
    del amplitude  # reserved for future emitter grouping

    evidence = []
    count = 1

    if offsets is not None:
        offsets = _finite(offsets)

    if offsets is not None and len(offsets) >= 10:
        levels = _cluster_levels(
            offsets,
            tolerance_abs=15000.0,
        )
        significant = [
            group
            for group in levels
            if group["count"]
            >= max(4, int(0.04 * len(offsets)))
        ]

        if len(significant) >= 2:
            count = max(count, len(significant))
            evidence.append(
                f"{len(significant)} separated pulse carrier-offset groups"
            )

    if pulse_width is not None:
        pulse_width = _finite(pulse_width)

    if pulse_width is not None and len(pulse_width) >= 10:
        levels = _cluster_levels(
            pulse_width,
            tolerance_abs=4e-6,
        )
        significant = [
            group
            for group in levels
            if group["count"]
            >= max(4, int(0.04 * len(pulse_width)))
        ]

        if len(significant) >= 2:
            count = max(count, len(significant))
            evidence.append(
                f"{len(significant)} separated pulse-width groups"
            )

    return {
        "detected": count >= 2,
        "estimated_groups": (
            int(count)
            if count >= 2
            else None
        ),
        "confidence": (
            "medium"
            if count >= 2
            else None
        ),
        "evidence": (
            evidence
            or ["no strong separated feature groups"]
        ),
    }


def _common(
    toa,
    pulse_width,
    peak,
    mean,
):
    toa = _finite(toa)
    pri = np.diff(toa)
    positive_pri = pri[pri > 0]
    prf = (
        1.0 / positive_pri
        if len(positive_pri) == len(pri)
        else np.array([])
    )

    return {
        "pulse_count": int(len(toa)),
        "pulse_toa_s": [
            float(value)
            for value in toa
        ],
        "pri_s": _stats(pri),
        "prf_hz": _stats(prf),
        "pulse_width_s": _stats(pulse_width),
        "amplitude_peak": _stats(peak),
        "amplitude_mean": _stats(mean),
        "pri_behavior": _pri_behavior(pri),
        "scan_like_amplitude": _scan_periodicity(
            toa,
            peak,
        ),
    }


def _read_pdw_csv(path):
    with open(
        path,
        newline="",
        encoding="utf-8-sig",
    ) as handle:
        reader = csv.DictReader(handle)
        fieldnames = {
            str(name or "").strip()
            for name in (reader.fieldnames or [])
            if str(name or "").strip()
        }

        missing = sorted(
            PDW_REQUIRED_COLUMNS - fieldnames
        )
        if missing:
            raise ValueError(
                "PDW CSV is missing required column(s): "
                + ", ".join(missing)
            )

        rows = list(reader)

    if not rows:
        raise ValueError(
            "PDW CSV contains no data rows."
        )

    return rows, fieldnames


def _pdw_column(
    rows,
    fieldnames,
    name,
    required=False,
):
    if name not in fieldnames:
        if required:
            raise ValueError(
                f"PDW CSV is missing required column: {name}"
            )
        return np.full(
            len(rows),
            np.nan,
            dtype=float,
        )

    values = []

    for row_index, row in enumerate(rows, start=2):
        raw_value = row.get(name)
        try:
            value = float(raw_value)
        except (TypeError, ValueError):
            if required:
                raise ValueError(
                    f"PDW CSV has a non-numeric {name} value on row "
                    f"{row_index}: {raw_value!r}"
                )
            value = float("nan")

        if required and not np.isfinite(value):
            raise ValueError(
                f"PDW CSV has a non-finite {name} value on row "
                f"{row_index}."
            )

        values.append(value)

    return np.asarray(values, dtype=float)


def analyze_pdw(
    path,
    sample_rate_hz=0,
    center_frequency_hz=0,
):
    del sample_rate_hz

    rows, fieldnames = _read_pdw_csv(path)
    toa = _pdw_column(
        rows,
        fieldnames,
        "toa_s",
        required=True,
    )
    pulse_width = _pdw_column(
        rows,
        fieldnames,
        "pulse_width_s",
    )
    amplitude = _pdw_column(
        rows,
        fieldnames,
        "amplitude",
    )
    offsets = _pdw_column(
        rows,
        fieldnames,
        "carrier_offset_hz",
    )

    order = np.argsort(toa)
    toa = toa[order]
    pulse_width = pulse_width[order]
    amplitude = amplitude[order]
    offsets = offsets[order]

    result = _common(
        toa,
        pulse_width,
        amplitude,
        amplitude,
    )

    frequency_stats = _stats(offsets)
    pulse_width_stats = _stats(pulse_width)
    amplitude_stats = _stats(amplitude)

    result.update(
        {
            "representation": "pdw_csv",
            "pdw_columns": sorted(fieldnames),
            "frequency_offset_hz": frequency_stats,
            "rf_frequency_hz": (
                {
                    key: (
                        value + center_frequency_hz
                        if key in {
                            "min",
                            "max",
                            "mean",
                            "median",
                        }
                        else value
                    )
                    for key, value in frequency_stats.items()
                }
                if center_frequency_hz and frequency_stats
                else None
            ),
            "intra_pulse_modulation": {
                "status": "unsupported",
                "reason": (
                    "PDWs contain pulse-level descriptors but no within-pulse "
                    "phase/time series"
                ),
            },
            "lfm": {
                "status": "unsupported",
                "reason": (
                    "cannot independently infer chirp from pulse-level "
                    "descriptors alone"
                ),
            },
            "multiple_emitters": _multiple_emitters(
                offsets,
                pulse_width,
                amplitude,
            ),
            "detector_notes": (
                "TOA/PRI behavior is derived from numeric TOA values; "
                "filename/scenario labels are not used for inference."
            ),
            "emitter_group_details": (
                _group_details(
                    toa,
                    offsets,
                    15000.0,
                    "frequency_offset_hz",
                )
                or _group_details(
                    toa,
                    pulse_width,
                    4e-6,
                    "pulse_width_s",
                )
            ),
        }
    )

    if pulse_width_stats is None:
        result["pulse_width_s"] = {
            "status": "unsupported",
            "reason": "PDW CSV does not contain usable pulse_width_s values",
        }

    if amplitude_stats is None:
        result["amplitude_peak"] = {
            "status": "unsupported",
            "reason": "PDW CSV does not contain usable amplitude values",
        }
        result["amplitude_mean"] = {
            "status": "unsupported",
            "reason": "PDW CSV does not contain usable amplitude values",
        }
        result["scan_like_amplitude"] = {
            "status": "unsupported",
            "reason": "PDW CSV does not contain usable amplitude values",
        }

    if frequency_stats is None:
        result["frequency_offset_hz"] = {
            "status": "unsupported",
            "reason": (
                "PDW CSV does not contain usable carrier_offset_hz values"
            ),
        }

    return result


def _open_raw_samples(path, representation):
    dtype = (
        "<f4"
        if representation == "log_video_f32"
        else "<c8"
    )
    return np.memmap(
        path,
        dtype=dtype,
        mode="r",
    )


def analyze_log(
    path,
    sample_rate_hz,
    center_frequency_hz=0,
):
    del center_frequency_hz

    samples = _open_raw_samples(
        path,
        "log_video_f32",
    )
    envelope, segments, detection = _detect_pulses(
        samples,
        sample_rate_hz,
        iq=False,
    )
    toa, pulse_width, peak, mean = _pulse_arrays(
        envelope,
        segments,
        sample_rate_hz,
    )
    result = _common(
        toa,
        pulse_width,
        peak,
        mean,
    )

    result.update(
        {
            "representation": "log_video_f32",
            "sample_rate_hz": float(sample_rate_hz),
            "duration_s": len(samples) / sample_rate_hz,
            "pulse_detection": detection,
            "frequency_offset_hz": {
                "status": "unsupported",
                "reason": (
                    "detected-envelope/log-video has no carrier phase"
                ),
            },
            "intra_pulse_modulation": {
                "status": "unsupported",
                "reason": (
                    "phase/frequency modulation is not retained in "
                    "envelope-only samples"
                ),
            },
            "lfm": {
                "status": "unsupported",
                "reason": (
                    "phase/frequency sweep is not retained in envelope-only "
                    "samples"
                ),
            },
            "multiple_emitters": _multiple_emitters(
                None,
                pulse_width,
                peak,
            ),
            "emitter_group_details": _group_details(
                toa,
                pulse_width,
                4e-6,
                "pulse_width_s",
            ),
        }
    )

    return result


def analyze_iq(
    path,
    sample_rate_hz,
    center_frequency_hz=0,
):
    samples = _open_raw_samples(
        path,
        "iq_cf32",
    )
    envelope, segments, detection = _detect_pulses(
        samples,
        sample_rate_hz,
        iq=True,
    )
    strong_segments = list(segments)
    strong_toa = np.asarray(
        [
            start / sample_rate_hz
            for start, _end in strong_segments
        ],
        dtype=float,
    )

    segments, recovery = _recover_periodic_grid(
        segments,
        envelope,
        sample_rate_hz,
    )
    detection["periodic_grid_recovery"] = recovery

    toa, pulse_width, peak, mean = _pulse_arrays(
        envelope,
        segments,
        sample_rate_hz,
    )
    result = _common(
        toa,
        pulse_width,
        peak,
        mean,
    )

    frequency_features, offsets = _iq_frequency_features(
        samples,
        strong_segments,
        sample_rate_hz,
    )

    result.update(
        {
            "representation": "iq_cf32",
            "sample_rate_hz": float(sample_rate_hz),
            "duration_s": len(samples) / sample_rate_hz,
            "pulse_detection": detection,
            "frequency_offset_hz": frequency_features[
                "pulse_frequency_offset_hz"
            ],
            "rf_frequency_hz": None,
            "lfm": frequency_features["lfm"],
            "intra_pulse_modulation": {
                "status": "observable",
                "interpretation": (
                    "linear-FM/chirp"
                    if frequency_features["lfm"].get("detected")
                    else "no supported LFM; other modulation not classified"
                ),
            },
            "multiple_emitters": _multiple_emitters(
                offsets,
                None,
                None,
            ),
            "emitter_group_details": (
                _group_details(
                    strong_toa,
                    offsets,
                    15000.0,
                    "frequency_offset_hz",
                )
                or (
                    _group_details(
                        toa,
                        pulse_width,
                        4e-6,
                        "pulse_width_s",
                    )
                    if recovery is None
                    else []
                )
            ),
        }
    )

    frequency_stats = result["frequency_offset_hz"]
    if center_frequency_hz and frequency_stats:
        result["rf_frequency_hz"] = {
            key: (
                value + center_frequency_hz
                if key in {
                    "min",
                    "max",
                    "mean",
                    "median",
                }
                else value
            )
            for key, value in frequency_stats.items()
        }

    return result


def infer_representation(path, requested="auto"):
    requested = str(requested or "auto").strip()

    if requested not in SUPPORTED_REPRESENTATIONS:
        raise ValueError(
            "Unsupported representation selection: "
            f"{requested}"
        )

    if requested != "auto":
        return requested

    lower_path = str(path).lower()

    if lower_path.endswith(".csv"):
        return "pdw_csv"
    if lower_path.endswith((".cf32", ".fc32", ".cfile")):
        return "iq_cf32"
    if lower_path.endswith((".f32", ".rf32")):
        return "log_video_f32"

    raise ValueError(
        "Cannot infer radar representation from the filename. "
        "Choose pdw_csv, log_video_f32, or iq_cf32 explicitly."
    )


def analyze_file(
    path,
    representation="auto",
    sample_rate_hz=0.0,
    center_frequency_hz=0.0,
):
    raw_path = str(path or "").strip()

    if not raw_path:
        raise ValueError(
            "No radar-analysis input file was supplied. Load a file in the "
            "Inspection tab before running the Action."
        )

    resolved_path = Path(raw_path).expanduser().resolve()

    if not resolved_path.exists():
        raise FileNotFoundError(
            f"Radar-analysis input file not found: {resolved_path}"
        )

    if not resolved_path.is_file():
        raise ValueError(
            f"Radar-analysis input path is not a file: {resolved_path}"
        )

    path = str(resolved_path)
    representation = infer_representation(
        path,
        representation,
    )
    sample_rate_hz = float(sample_rate_hz or 0.0)
    center_frequency_hz = float(
        center_frequency_hz or 0.0
    )

    if (
        representation in {
            "log_video_f32",
            "iq_cf32",
        }
        and sample_rate_hz <= 0.0
    ):
        raise ValueError(
            "A positive sample rate is required for raw log-video and IQ "
            "radar analysis. Provide it through Inspection metadata or the "
            "Action parameter."
        )

    if representation == "pdw_csv":
        result = analyze_pdw(
            path,
            sample_rate_hz,
            center_frequency_hz,
        )
    elif representation == "log_video_f32":
        result = analyze_log(
            path,
            sample_rate_hz,
            center_frequency_hz,
        )
    elif representation == "iq_cf32":
        result = analyze_iq(
            path,
            sample_rate_hz,
            center_frequency_hz,
        )
    else:
        raise ValueError(
            f"Unsupported representation: {representation}"
        )

    result["source_file"] = path
    result["center_frequency_hz_metadata"] = (
        center_frequency_hz
        if center_frequency_hz > 0.0
        else None
    )

    unsupported = []
    for key, value in result.items():
        if (
            isinstance(value, dict)
            and value.get("status") == "unsupported"
        ):
            unsupported.append(
                f"{key}: {value.get('reason', 'unsupported')}"
            )

    result["unsupported_or_indeterminate"] = unsupported
    return result


def _result_state(value, detected_key="detected"):
    if not isinstance(value, dict):
        return "indeterminate"

    if value.get("status") == "unsupported":
        return "unsupported/not observable"

    if detected_key not in value:
        return "indeterminate"

    return bool(value.get(detected_key))


def inspection_payload(result, artifact_ids=None):
    pri = result.get("pri_s") or {}
    pulse_width = result.get("pulse_width_s") or {}
    frequency_offset = result.get("frequency_offset_hz") or {}
    scan = result.get("scan_like_amplitude") or {}
    lfm = result.get("lfm") or {}

    values = {
        "Source File": result.get("source_file", ""),
        "Input Representation": result.get("representation", ""),
        "Pulse Count": result.get("pulse_count", 0),
        "PRI Behavior": result.get(
            "pri_behavior",
            {},
        ).get("type", "indeterminate"),
        "PRI Median": _fmt(
            pri.get("median")
            if isinstance(pri, dict)
            else None,
            " s",
        ),
        "PRI Std": _fmt(
            pri.get("std")
            if isinstance(pri, dict)
            else None,
            " s",
        ),
        "PRF Median": _fmt(
            (result.get("prf_hz") or {}).get("median"),
            " Hz",
        ),
        "Pulse Width Median": _fmt(
            pulse_width.get("median")
            if isinstance(pulse_width, dict)
            else None,
            " s",
        ),
        "Frequency Offset Median": (
            _fmt(
                frequency_offset.get("median"),
                " Hz",
            )
            if (
                isinstance(frequency_offset, dict)
                and "median" in frequency_offset
            )
            else "unsupported/not observable"
        ),
        "Scan-like Amplitude Periodicity": _result_state(scan),
        "Scan Period": (
            _fmt(scan.get("period_s"), " s")
            if (
                isinstance(scan, dict)
                and scan.get("detected")
            )
            else "unsupported/not detected"
        ),
        "LFM/Chirp": _result_state(lfm),
        "LFM Bandwidth Median": (
            _fmt(
                (lfm.get("chirp_bandwidth_hz") or {}).get("median"),
                " Hz",
            )
            if (
                isinstance(lfm, dict)
                and lfm.get("detected")
            )
            else (
                "unsupported/not observable"
                if isinstance(lfm, dict)
                and lfm.get("status") == "unsupported"
                else "not detected"
            )
        ),
        "Multiple Emitters": _result_state(
            result.get("multiple_emitters") or {}
        ),
        "Important Observations": summarize(result),
        "Unsupported / Indeterminate": (
            "; ".join(
                result.get(
                    "unsupported_or_indeterminate",
                    [],
                )
            )
            or (
                "None explicitly unsupported beyond limitations noted in "
                "detailed artifact"
            )
        ),
    }

    if artifact_ids:
        values["Artifact IDs"] = ", ".join(
            artifact_id
            for artifact_id in artifact_ids
            if artifact_id
        )

    return {
        "title": "Radar Pulse Analysis",
        "values": values,
    }


def summarize(result):
    observations = []
    pri_behavior = result.get(
        "pri_behavior",
        {},
    )
    observations.append(
        "PRI behavior: "
        f"{pri_behavior.get('type', 'indeterminate')}"
    )

    scan = result.get("scan_like_amplitude", {})
    if scan.get("detected"):
        if scan.get("period_s") is not None:
            observations.append(
                "scan-like amplitude periodicity detected "
                f"(~{scan['period_s']:.6g} s)"
            )
        else:
            observations.append(
                "scan-like amplitude periodicity detected"
            )

    lfm = result.get("lfm", {})
    if lfm.get("detected"):
        bandwidth = (
            lfm.get("chirp_bandwidth_hz")
            or {}
        ).get("median")
        if bandwidth is not None:
            observations.append(
                "LFM/chirp supported by within-pulse IQ phase progression "
                f"(~{bandwidth:.6g} Hz median bandwidth)"
            )
        else:
            observations.append(
                "LFM/chirp supported by within-pulse IQ phase progression"
            )

    multiple_emitters = result.get(
        "multiple_emitters",
        {},
    )
    if multiple_emitters.get("detected"):
        observations.append(
            "multiple feature groups suggest "
            f"{multiple_emitters.get('estimated_groups')} "
            "emitters/components"
        )

    return "; ".join(observations)


def write_markdown(result, path):
    path = Path(path)
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    def line_stats(
        name,
        stats,
        scale=1.0,
        unit="",
    ):
        if (
            not isinstance(stats, dict)
            or "median" not in stats
        ):
            return f"- {name}: unsupported/not observable"

        return (
            f"- {name}: median {stats['median'] * scale:.6g}{unit}, "
            f"mean {stats['mean'] * scale:.6g}{unit}, "
            f"std {stats['std'] * scale:.6g}{unit}, "
            f"range {stats['min'] * scale:.6g}–"
            f"{stats['max'] * scale:.6g}{unit}"
        )

    lines = [
        f"# Radar analysis — {Path(result['source_file']).name}",
        "",
        f"- Source file: `{result['source_file']}`",
        f"- Representation: `{result['representation']}`",
        f"- Pulse count: {result['pulse_count']}",
        line_stats(
            "PRI",
            result.get("pri_s"),
            1e6,
            " µs",
        ),
        line_stats(
            "PRF",
            result.get("prf_hz"),
            1.0,
            " Hz",
        ),
        line_stats(
            "Pulse width",
            result.get("pulse_width_s"),
            1e6,
            " µs",
        ),
        line_stats(
            "Peak amplitude",
            result.get("amplitude_peak"),
        ),
        "",
        "## Interpretation",
        "- PRI sequence: "
        + json.dumps(
            result.get("pri_behavior", {}),
            sort_keys=True,
        ),
        "- Scan-like amplitude periodicity: "
        + json.dumps(
            result.get("scan_like_amplitude", {}),
            sort_keys=True,
        ),
        "- Multiple-emitter indication: "
        + json.dumps(
            result.get("multiple_emitters", {}),
            sort_keys=True,
        ),
        "- Frequency offset: "
        + json.dumps(
            result.get("frequency_offset_hz"),
            sort_keys=True,
        ),
        "- Intra-pulse modulation: "
        + json.dumps(
            result.get("intra_pulse_modulation"),
            sort_keys=True,
        ),
        "- LFM/chirp: "
        + json.dumps(
            result.get("lfm"),
            sort_keys=True,
        ),
        "",
        "## Unsupported / indeterminate",
    ]

    unsupported = result.get(
        "unsupported_or_indeterminate",
        [],
    )
    if unsupported:
        lines.extend(
            f"- {item}"
            for item in unsupported
        )
    else:
        lines.append(
            "- No additional explicitly unsupported fields; see "
            "interpretation limitations above."
        )

    lines.extend(
        [
            "",
            "## Pulse TOAs (s)",
            ", ".join(
                f"{value:.9g}"
                for value in result.get(
                    "pulse_toa_s",
                    [],
                )
            ),
        ]
    )

    path.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )
    return str(path)


def _plot_save(figure, path, created):
    figure.tight_layout()
    figure.savefig(
        path,
        dpi=140,
    )

    import matplotlib.pyplot as plt

    plt.close(figure)
    created.append(str(path))


def write_plots(
    result,
    output_dir,
    raw_path=None,
    sample_rate_hz=0.0,
):
    """Write interpretation plots and return the paths that were created."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    output_directory = Path(output_dir)
    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    stem = Path(result["source_file"]).stem
    created = []
    toa = np.asarray(
        result.get("pulse_toa_s", []),
        dtype=float,
    )

    representation = result.get("representation")
    amplitudes = None
    pulse_widths = None
    samples = None
    segments = None

    if raw_path and representation == "pdw_csv":
        rows, fieldnames = _read_pdw_csv(raw_path)
        raw_toa = _pdw_column(
            rows,
            fieldnames,
            "toa_s",
            required=True,
        )
        order = np.argsort(raw_toa)
        raw_toa = raw_toa[order]

        amplitudes = _pdw_column(
            rows,
            fieldnames,
            "amplitude",
        )[order]
        pulse_widths = _pdw_column(
            rows,
            fieldnames,
            "pulse_width_s",
        )[order]

        if not np.any(np.isfinite(amplitudes)):
            amplitudes = None
        if not np.any(np.isfinite(pulse_widths)):
            pulse_widths = None

    elif (
        raw_path
        and representation in {
            "log_video_f32",
            "iq_cf32",
        }
        and sample_rate_hz > 0.0
    ):
        samples = _open_raw_samples(
            raw_path,
            representation,
        )
        envelope, segments, _detection = _detect_pulses(
            samples,
            sample_rate_hz,
            iq=representation == "iq_cf32",
        )
        _toa, pulse_widths, amplitudes, _means = _pulse_arrays(
            envelope,
            segments,
            sample_rate_hz,
        )

    if (
        amplitudes is not None
        and len(amplitudes) == len(toa)
    ):
        figure = plt.figure(
            figsize=(9, 4)
        )
        plt.plot(
            toa,
            amplitudes,
            ".-",
            markersize=2,
            linewidth=0.6,
        )
        plt.xlabel("Time (s)")
        plt.ylabel("Pulse peak amplitude")
        plt.title("Pulse amplitude versus time")
        plt.grid(
            True,
            alpha=0.25,
        )
        path = output_directory / (
            f"{stem}.amplitude_vs_time.png"
        )
        _plot_save(
            figure,
            path,
            created,
        )

    if len(toa) > 2:
        pri_us = np.diff(toa) * 1e6

        figure = plt.figure(
            figsize=(9, 4)
        )
        plt.plot(
            np.arange(1, len(toa)),
            pri_us,
            ".-",
            markersize=2,
            linewidth=0.6,
        )
        plt.xlabel("Pulse interval index")
        plt.ylabel("PRI (µs)")
        plt.title("PRI versus pulse number")
        plt.grid(
            True,
            alpha=0.25,
        )
        path = output_directory / (
            f"{stem}.pri_sequence.png"
        )
        _plot_save(
            figure,
            path,
            created,
        )

        figure = plt.figure(
            figsize=(7, 4)
        )
        plt.hist(
            pri_us,
            bins=min(
                60,
                max(
                    10,
                    int(np.sqrt(len(pri_us))),
                ),
            ),
        )
        plt.xlabel("PRI (µs)")
        plt.ylabel("Count")
        plt.title("PRI distribution")
        path = output_directory / (
            f"{stem}.pri_distribution.png"
        )
        _plot_save(
            figure,
            path,
            created,
        )

    if pulse_widths is not None:
        finite_widths = _finite(pulse_widths)
        if len(finite_widths):
            figure = plt.figure(
                figsize=(7, 4)
            )
            plt.hist(
                finite_widths * 1e6,
                bins=min(
                    40,
                    max(
                        8,
                        int(
                            np.sqrt(
                                len(finite_widths)
                            )
                        ),
                    ),
                ),
            )
            plt.xlabel("Pulse width (µs)")
            plt.ylabel("Count")
            plt.title("Pulse-width distribution")
            path = output_directory / (
                f"{stem}.pulse_width_distribution.png"
            )
            _plot_save(
                figure,
                path,
                created,
            )

    if (
        raw_path
        and representation == "iq_cf32"
        and sample_rate_hz > 0.0
    ):
        if samples is None:
            samples = _open_raw_samples(
                raw_path,
                representation,
            )

        sample_count = min(
            len(samples),
            262144,
        )
        if sample_count > 1:
            subset = np.asarray(
                samples[:sample_count]
            )
            subset = subset - np.mean(subset)
            spectrum = np.fft.fftshift(
                np.fft.fft(
                    subset * np.hanning(sample_count)
                )
            )
            frequency = (
                np.fft.fftshift(
                    np.fft.fftfreq(
                        sample_count,
                        1.0 / sample_rate_hz,
                    )
                )
                / 1e3
            )

            figure = plt.figure(
                figsize=(9, 4)
            )
            plt.plot(
                frequency,
                20.0
                * np.log10(
                    np.maximum(
                        np.abs(spectrum),
                        1e-12,
                    )
                ),
            )
            plt.xlabel("Baseband offset (kHz)")
            plt.ylabel("Magnitude (dB, relative)")
            plt.title("IQ spectrum")
            plt.grid(
                True,
                alpha=0.25,
            )
            path = output_directory / (
                f"{stem}.iq_spectrum.png"
            )
            _plot_save(
                figure,
                path,
                created,
            )

        if segments is None:
            envelope, segments, _detection = _detect_pulses(
                samples,
                sample_rate_hz,
                iq=True,
            )

        if segments:
            start, end = max(
                segments,
                key=lambda segment: (
                    segment[1] - segment[0]
                ),
            )
            pulse = np.asarray(
                samples[start:end]
            )

            if len(pulse) >= 6:
                instantaneous_frequency = (
                    np.angle(
                        pulse[1:]
                        * np.conj(pulse[:-1])
                    )
                    * sample_rate_hz
                    / (2.0 * np.pi)
                    / 1e3
                )
                time_ms = (
                    start
                    + np.arange(
                        len(instantaneous_frequency)
                    )
                    + 0.5
                ) / sample_rate_hz * 1e3

                figure = plt.figure(
                    figsize=(8, 4)
                )
                plt.plot(
                    time_ms,
                    instantaneous_frequency,
                    ".-",
                )
                plt.xlabel("Time (ms)")
                plt.ylabel(
                    "Instantaneous frequency offset (kHz)"
                )
                plt.title(
                    "Representative pulse instantaneous frequency"
                )
                plt.grid(
                    True,
                    alpha=0.25,
                )
                path = output_directory / (
                    f"{stem}.iq_pulse_inst_frequency.png"
                )
                _plot_save(
                    figure,
                    path,
                    created,
                )

    return created
