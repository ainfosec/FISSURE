"""Parse rtl_power CSV and conservatively prioritize US FM channel centers.

FFT power establishes *analog/occupied-channel candidates*, not HD proof.
The NRSC-5 decoder alone can label an HD Radio station.
"""
import csv
import io
import math
import statistics
from typing import Any, Dict, List, Sequence


def parse_rtl_power_csv(csv_text: str) -> List[Dict[str, float]]:
    """Return measured bin centers and dB values from rtl_power single-shot CSV.

    Output has: date,time,low Hz,high Hz,bin Hz,samples,db,...; tolerate
    multiple tuning spans and repeated sweeps by pooling valid bins.
    """
    bins = []
    for row in csv.reader(io.StringIO(csv_text)):
        if len(row) < 7:
            continue
        try:
            low, high, step = map(float, row[2:5])
            if not all(math.isfinite(x) for x in (low, high, step)) or not 0 < step <= 250000:
                continue
            if high <= low:
                continue
            for i, value in enumerate(row[6:]):
                center = low + (i + 0.5) * step
                if center < low or center > high + step:
                    continue
                power = float(value)
                if math.isfinite(power):
                    bins.append({"frequency_hz": center, "power_db": power})
        except (ValueError, TypeError):
            continue
    return bins


def select_candidates(bins: Sequence[Dict[str, float]], channels_tenths: Sequence[int],
                      threshold_db: float = 6.0, max_candidates: int = 40,
                      min_candidates: int = 12) -> Dict[str, Any]:
    """Rank the measured FM channel centers using excess spectral energy.

    A global low-percentile noise floor is more stable for a congested band
    than comparing immediate neighbors, which may also contain stations.
    Select at least `min_candidates` of the strongest channels to reduce
    sensitivity to uncertain calibrated dB levels. The cap is a scan-time
    limit; channels omitted from a quick survey are never called negative.
    """
    if not channels_tenths:
        raise ValueError("no FM channels requested")
    if not bins:
        raise ValueError("rtl_power produced no valid FFT bins")
    dbs = sorted(item["power_db"] for item in bins)
    floor = dbs[max(0, int(len(dbs) * 0.15) - 1)]
    scored = []
    for tenths in channels_tenths:
        hz = tenths * 100000
        # The center of an FM carrier is a strong indicator of an occupied
        # FM channel. Do not assume occupancy implies a digital sideband.
        nearby = [item["power_db"] for item in bins
                  if abs(item["frequency_hz"] - hz) <= 85000]
        if not nearby:
            raise ValueError("rtl_power did not cover %.1f MHz" % (tenths / 10))
        score = statistics.mean(nearby)
        scored.append({"frequency_mhz": tenths / 10, "power_db": round(score, 2),
                       "above_floor_db": round(score - floor, 2), "selected": False})
    # Always include the strongest stations even when reported power scale
    # is unusual. Cap is explicitly visible in report statistics.
    ranked = sorted(scored, key=lambda row: (-row["above_floor_db"], row["frequency_mhz"]))
    good = [row for row in ranked if row["above_floor_db"] >= threshold_db]
    count = max(min(len(ranked), min_candidates), len(good))
    if max_candidates:
        count = min(count, max_candidates)
    selected = ranked[:count]
    selected_frequencies = {row["frequency_mhz"] for row in selected}
    for row in scored:
        row["selected"] = row["frequency_mhz"] in selected_frequencies
    return {
        "method": "rtl_power_fft_center_energy",
        "noise_floor_db": round(floor, 2),
        "threshold_db": threshold_db,
        "max_candidates": max_candidates,
        "min_candidates": min_candidates,
        "selected_count": count,
        "channel_power": scored,
        "candidate_frequencies_mhz": [row["frequency_mhz"] for row in selected],
        "excluded_frequencies_mhz": [row["frequency_mhz"] for row in scored if not row["selected"]],
        "caveat": ("FFT power indicates occupancy, not HD Radio. Weak stations or "
                   "stations below the configured candidate cap may be omitted."),
    }
