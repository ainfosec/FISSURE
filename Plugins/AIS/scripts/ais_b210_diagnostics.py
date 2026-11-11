#!/usr/bin/env python3
"""Offline inspection and cabled B210 RF-tone diagnostic for the FISSURE AIS plugin.

The tone test is strictly for a verified, isolated, attenuated coaxial
connection. It is not an AIS transmission. It emits a short test tone at a
laboratory RF frequency and checks for its presence in RX2 IQ.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys

import numpy as np


def analyze_capture(iq_path, sample_rate=240000, tone_offset_hz=40000):
    """Measure burst energy and an optional narrowband pilot tone.

    RMS peaks are descriptive, not calibrated RF dBm. Tone search uses a
    per-window FFT and accepts small TX/RX frequency differences.
    """
    path = Path(iq_path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    if path.stat().st_size % 8:
        raise ValueError("IQ file size is not a multiple of complex64 samples")
    samples = np.memmap(str(path), dtype=np.complex64, mode="r")
    if samples.size < int(sample_rate // 4):
        raise ValueError("IQ recording must be at least 250 milliseconds")

    # 20 ms power windows detect GMSK burst activity independent of exact time.
    window = max(256, int(round(sample_rate * .02)))
    number = int(len(samples) // window)
    data = np.asarray(samples[:number * window]).reshape(number, window)
    power = np.mean(data.real.astype(np.float64)**2 + data.imag.astype(np.float64)**2, axis=1)
    rms = np.sqrt(power)
    median_rms = float(np.median(rms))
    max_rms = float(np.max(rms))
    peak_power_over_median_db = 20 * math.log10(max(max_rms, 1e-15) / max(median_rms, 1e-15))

    # Wide-band power tests may miss a low-level tone. Search for a narrow
    # line near the requested offset, and compare its FFT-bin power with the
    # median spectral-bin floor within the same block.
    fft_size = 8192 if sample_rate >= 192000 else 4096
    fft_blocks = min(int(len(samples) // fft_size), 400)
    start = int(max(0, (len(samples) - fft_blocks * fft_size) // 2))
    f = np.fft.fftfreq(fft_size, d=1.0 / sample_rate)
    search = (np.abs(f - tone_offset_hz) <= 5000)
    # This exclusion removes DC and both the positive and negative pilot areas.
    baseline = (np.abs(f) >= 10000) & (np.abs(f) <= sample_rate * .44) & (np.abs(f - tone_offset_hz) >= 10000)
    taper = np.hanning(fft_size).astype(np.float32)
    best_db = -200.0
    best_freq = None
    best_time = None
    for i in range(fft_blocks):
        sl = np.asarray(samples[start + i * fft_size:start + (i + 1) * fft_size])
        spec_power = np.abs(np.fft.fft(sl * taper)) ** 2
        floor = float(np.median(spec_power[baseline])) if np.any(baseline) else 0.0
        if not np.any(search):
            continue
        bins = np.flatnonzero(search)
        peak_i = int(bins[np.argmax(spec_power[search])])
        db = 10.0 * math.log10(max(float(spec_power[peak_i]), 1e-30) / max(floor, 1e-30))
        if db > best_db:
            best_db = db
            best_freq = float(f[peak_i])
            best_time = float((start + i * fft_size) / sample_rate)
    tone_detected = best_db >= 20.0

    return {
        "schema": "fissure.ais.b210_iq_diagnostic.v1",
        "iq_file": str(path),
        "sample_rate_hz": int(sample_rate),
        "duration_s": round(float(len(samples) / sample_rate), 4),
        "sample_count": int(len(samples)),
        "rms_median_fs": round(median_rms, 10),
        "rms_max_fs": round(max_rms, 10),
        "peak_rms_above_median_db": round(peak_power_over_median_db, 2),
        "visible_power_bursts": bool(peak_power_over_median_db >= 6.0),
        "tone_offset_requested_hz": float(tone_offset_hz),
        "tone_best_offset_hz": round(best_freq, 2) if best_freq is not None else None,
        "tone_best_time_s": round(best_time, 3) if best_time is not None else None,
        "tone_peak_over_spectral_floor_db": round(best_db, 2),
        "tone_detected": bool(tone_detected),
        "note": "Baseband IQ amplitude only: this does not measure calibrated RF power or prove TX enabled",
    }


def write_tone(path, rate=240000, tone_offset_hz=40000):
    """2-second finite stimulus: 0.5 s silence + 1.0 s tone + 0.5 s silence."""
    file = Path(path)
    file.parent.mkdir(parents=True, exist_ok=True)
    chunk = np.zeros(int(2 * rate), dtype=np.complex64)
    start = int(round(rate * 0.5))
    length = int(round(rate * 1.0))
    n = np.arange(length, dtype=np.float64)
    # Keep the baseband at unit magnitude; UHD helper applies fixed 0.15 scale.
    chunk[start:start + length] = np.exp(2j * np.pi * tone_offset_hz / rate * n).astype(np.complex64)
    chunk.tofile(str(file))
    return file


def main(argv=None):
    parser = argparse.ArgumentParser(description="AIS B210 receiver IQ inspection and isolated cabled tone test")
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--analyze", metavar="CF32", help="Analyze an existing IQ capture; no RF activity")
    modes.add_argument("--tone-test", action="store_true", help="Transmit a short lab tone into isolated attenuated coax")
    parser.add_argument("--output-dir", default="/tmp/ais_b210_diagnostic")
    parser.add_argument("--sample-rate", type=int, default=240000)
    parser.add_argument("--tone-offset", type=float, default=40000.0)
    parser.add_argument("--rf-frequency", type=float, default=915000000)
    parser.add_argument("--device-args", default="type=b200")
    parser.add_argument("--tx-gain", type=float, default=0)
    parser.add_argument("--rx-gain", type=float, default=20)
    args = parser.parse_args(argv)
    try:
        if args.analyze:
            report = analyze_capture(args.analyze, args.sample_rate, args.tone_offset)
        else:
            from ais_b210_rf_hardware import validate_settings, run
            # Numeric validation only. This cannot validate physical TX/RX input power.
            validate_settings(args.sample_rate, args.rf_frequency, args.tx_gain,
                              args.rx_gain, args.device_args)
            out = Path(args.output_dir).expanduser().resolve()
            out.mkdir(parents=True, exist_ok=True)
            tx_path = write_tone(out / "tx_tone.cf32", args.sample_rate, args.tone_offset)
            rx_path = out / "rx_tone.cf32"
            print("AIS B210 diagnostic: transmitting isolated laboratory test tone, no AIS messages", flush=True)
            run(str(tx_path), str(rx_path), str(out / "rf_manifest.json"),
                sample_rate=args.sample_rate, rf_frequency=args.rf_frequency,
                device_args=args.device_args, tx_gain=args.tx_gain, rx_gain=args.rx_gain)
            report = analyze_capture(rx_path, args.sample_rate, args.tone_offset)
            report["rf_center_frequency_hz"] = float(args.rf_frequency)
            report["test_type"] = "isolated_b210_tone"
            (out / "diagnostics.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        print(json.dumps(report, indent=2, sort_keys=True), flush=True)
        if args.tone_test and not report["tone_detected"]:
            print("Diagnostic did not see the expected tone in RX IQ. Verify the cabled RF path and TX/RX ports.", file=sys.stderr)
            return 2
        return 0
    except (ValueError, RuntimeError, OSError, ImportError) as exc:
        print("AIS B210 diagnostic error: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
