#!/usr/bin/env python3
"""Cabled, isolated USRP B210 AIS baseband TX/RX capture (GNU Radio 3.8).

Consumes pre-generated complex64 AIS IQ (virtual center 162 MHz), transmits
at a separate *lab RF frequency*, and captures simultaneous RX2 complex64 IQ.
No on-air AIS frequencies, no antennas, no repeat, no message generation here.

This helper does not measure RF output or input power; gain settings cannot
replace physical attenuation. Do not connect TX directly to RX without a
verified RF power budget and appropriate physical protection.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
import signal
import sys
import tempfile
import time

from ais_gr_compat import gr_minor_version


class LoopbackConfigError(ValueError):
    pass


# Fixed baseband scale; only RF TX/RX gains are user-facing gain settings.
TX_DIGITAL_SCALE = 0.15


def validate_settings(sample_rate, rf_frequency, tx_gain, rx_gain, device_args=""):
    rate = float(sample_rate)
    freq = float(rf_frequency)
    tx = float(tx_gain)
    rx = float(rx_gain)
    if not (math.isfinite(rate) and 192000 <= rate <= 960000 and int(rate) % 48000 == 0):
        raise LoopbackConfigError("sample rate must be a 48 kHz multiple, 192–960 kS/s")
    if not (math.isfinite(freq) and 500e6 <= freq <= 3000e6):
        raise LoopbackConfigError("lab RF center must be 500 MHz–3 GHz, away from AIS maritime frequencies")
    if not (math.isfinite(tx) and tx >= 0):
        raise LoopbackConfigError("TX gain must be finite and nonnegative; UHD enforces the actual device gain range")
    if not (math.isfinite(rx) and 0 <= rx <= 60):
        raise LoopbackConfigError("RX gain must be 0–60 dB")
    if any(char in str(device_args) for char in "\n\r\x00"):
        raise LoopbackConfigError("invalid UHD device argument")
    return int(rate)


def verify_iq_file(path):
    file = Path(path).expanduser().resolve()
    if not file.is_file():
        raise FileNotFoundError("AIS stimulus IQ not found: %s" % file)
    size = file.stat().st_size
    if size < 8192 or size % 8:
        raise LoopbackConfigError("stimulus is not a nonempty interleaved complex64 file")
    with file.open("rb") as stream:
        # Guard against a stale, entirely empty/zero first sample segment.
        stream.seek(min(size // 2, 2 * 1024 * 1024))
        if not any(stream.read(min(128 * 1024, size // 4))):
            # Long silent gaps are allowed; verify entire file in chunks.
            stream.seek(0)
            if not any(any(block) for block in iter(lambda: stream.read(1024 * 1024), b"")):
                raise LoopbackConfigError("IQ stimulus consists entirely of zeros")
    return file, size // 8


def prepare_tx_file(stimulus, output, sample_rate, lead_s=2.0, tail_s=1.0):
    """Add enough zero-valued complex64 IQ to stabilize RX before the first burst."""
    output = Path(output)
    leading = int(round(sample_rate * lead_s))
    trailing = int(round(sample_rate * tail_s))
    # Avoid a large in-memory allocation for the sample file.
    padding = b"\0" * (min(sample_rate, 65536) * 8)
    with output.open("wb") as dst:
        for count in (leading,):
            remain = count * 8
            while remain:
                portion = padding[:min(remain, len(padding))]
                dst.write(portion)
                remain -= len(portion)
        with Path(stimulus).open("rb") as src:
            while True:
                buf = src.read(1024 * 1024)
                if not buf:
                    break
                dst.write(buf)
        remain = trailing * 8
        while remain:
            portion = padding[:min(remain, len(padding))]
            dst.write(portion)
            remain -= len(portion)
    return leading, trailing, output.stat().st_size // 8


def probe():
    from gnuradio import gr, blocks, uhd  # no radio opened and NO RF TX
    _, version = gr_minor_version(gr)
    if not callable(getattr(uhd, "usrp_source", None)) or not callable(getattr(uhd, "usrp_sink", None)):
        raise RuntimeError("GNU Radio UHD TX/RX blocks are missing")
    return gr, blocks, uhd, version


def make_top_block(tx_file, rx_file, capture_samples, rate, rf_frequency, device_args,
                   tx_gain, rx_gain, tx_amplitude, runtime):
    """One UHD TX and RX device in one finite flow graph; no on-device demodulation."""
    gr, blocks, uhd, _ = runtime
    stream_args = uhd.stream_args(cpu_format="fc32", channels=[0])
    transmitter = uhd.usrp_sink(device_args, stream_args)
    receiver = uhd.usrp_source(device_args, stream_args)
    # Check actual rates instead of silently recording IQ with wrong sample metadata.
    transmitter.set_samp_rate(rate)
    receiver.set_samp_rate(rate)
    actual_tx = float(transmitter.get_samp_rate())
    actual_rx = float(receiver.get_samp_rate())
    if abs(actual_tx - rate) > 1 or abs(actual_rx - rate) > 1:
        raise RuntimeError("B210 changed sample rate: requested %s, actual TX %s, RX %s" % (
            rate, actual_tx, actual_rx))
    transmitter.set_center_freq(rf_frequency, 0)
    receiver.set_center_freq(rf_frequency, 0)
    transmitter.set_gain(tx_gain, 0)
    receiver.set_gain(rx_gain, 0)
    transmitter.set_antenna("TX/RX", 0)
    receiver.set_antenna("RX2", 0)

    source = blocks.file_source(gr.sizeof_gr_complex, str(tx_file), False)
    scale = blocks.multiply_const_cc(tx_amplitude)
    limit = blocks.head(gr.sizeof_gr_complex, int(capture_samples))
    output = blocks.file_sink(gr.sizeof_gr_complex, str(rx_file), False)
    flowgraph = gr.top_block("FISSURE AIS isolated B210 simultaneous TX/RX")
    flowgraph.connect((source, 0), (scale, 0), (transmitter, 0))
    flowgraph.connect((receiver, 0), (limit, 0), (output, 0))
    return flowgraph, output


def run(stimulus, rx_path, manifest_path, sample_rate=240000, rf_frequency=915000000,
        device_args="type=b200", tx_gain=40, rx_gain=40):
    rate = validate_settings(sample_rate, rf_frequency, tx_gain, rx_gain, device_args)
    iq, iq_samples = verify_iq_file(stimulus)
    runtime = probe()  # Validate dependencies BEFORE opening any UHD device.
    output_path = Path(rx_path).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path = Path(manifest_path).expanduser().resolve()
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    # The .partial extension prevents a failed capture from looking complete.
    partial = output_path.with_name(output_path.name + ".partial")
    output_path.unlink(missing_ok=True)
    partial.unlink(missing_ok=True)
    manifest_path.unlink(missing_ok=True)
    graph = None
    sink = None
    started = False
    try:
        with tempfile.TemporaryDirectory(prefix="fissure_ais_b210_") as scratch:
            padded = Path(scratch) / "tx_padded.cf32"
            leading, trailing, tx_samples = prepare_tx_file(iq, padded, rate)
            # Receive for longer than TX, allowing USB stream startup variation.
            capture_samples = tx_samples + 2 * rate
            print("AIS B210: TX/RX -> RX2; RF power budget must be verified physically; %d TX samples; %d RX samples" % (
                tx_samples, capture_samples), flush=True)
            graph, sink = make_top_block(padded, partial, capture_samples, rate,
                                         float(rf_frequency), str(device_args),
                                         float(tx_gain), float(rx_gain),
                                         TX_DIGITAL_SCALE, runtime)
            def shutdown(signum, frame):
                if graph is not None and started:
                    graph.stop()
                raise KeyboardInterrupt("B210 test interrupted")
            previous = signal.signal(signal.SIGTERM, shutdown)
            try:
                start_time = time.monotonic()
                graph.start()
                started = True
                # Do not depend on an infinite UHD source and a finite TX
                # branch both reaching WORK_DONE in GNU Radio 3.8/3.10. Bound the
                # test by the expected TX file duration, then stop both
                # radio streams together. The RX head also caps file size.
                time.sleep((tx_samples / rate) + 3.0)
                graph.stop()
                graph.wait()
                elapsed = time.monotonic() - start_time
            finally:
                signal.signal(signal.SIGTERM, previous)
                if graph is not None and started:
                    graph.stop()
                    graph.wait()
                if sink is not None:
                    try:
                        sink.close()
                    except AttributeError:
                        pass
        if not partial.is_file() or partial.stat().st_size < 8192 or partial.stat().st_size % 8:
            raise RuntimeError("B210 returned no complete complex64 capture")
        received_samples = partial.stat().st_size // 8
        if received_samples < (capture_samples * 95 // 100):
            raise RuntimeError("B210 capture ended early: expected %d, received %d samples" % (
                capture_samples, received_samples))
        partial.replace(output_path)
        result = {
            "schema": "fissure.ais.b210_rf_loopback.v1", "simulated_vessels": True,
            "rf_transmitted": True, "rf_path_verified_by_software": False,
            "maritime_ais_frequency_used": False, "tx_antenna": "TX/RX", "rx_antenna": "RX2",
            "device_args": str(device_args), "rf_center_frequency_hz": float(rf_frequency),
            "virtual_ais_iq_center_hz": 162000000.0,
            "sample_rate_hz": rate, "tx_gain_db": float(tx_gain), "rx_gain_db": float(rx_gain),
            "tx_digital_amplitude": TX_DIGITAL_SCALE,
            "tx_samples": tx_samples, "rx_samples": received_samples,
            "duration_s": round(elapsed, 4), "stimulus_samples": iq_samples,
            "lead_samples": leading, "tail_samples": trailing,
            "decode_status": "pending", "no_antennas_required": True,
            "capture_path": str(output_path),
        }
        manifest_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return result
    finally:
        partial.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="AIS isolated, cabled USRP B210 TX/RX test (NEVER radiate AIS)")
    parser.add_argument("--probe", action="store_true", help="Import-check GNU Radio UHD; no device is opened")
    parser.add_argument("--input", help="pre-generated complex64 AIS IQ file")
    parser.add_argument("--output", help="captured complex64 IQ file")
    parser.add_argument("--manifest", help="capture hardware metadata JSON")
    parser.add_argument("--sample-rate", type=int, default=240000)
    parser.add_argument("--rf-frequency", type=float, default=915000000.0)
    parser.add_argument("--device-args", default="type=b200")
    parser.add_argument("--tx-gain", type=float, default=40)
    parser.add_argument("--rx-gain", type=float, default=40)
    args = parser.parse_args(argv)
    try:
        if args.probe:
            print("AIS B210 readiness: GNU Radio %s, UHD blocks available, NO RF" % probe()[-1])
            return 0
        if not (args.input and args.output and args.manifest):
            parser.error("--input, --output and --manifest are required")
        report = run(args.input, args.output, args.manifest, args.sample_rate, args.rf_frequency,
                     args.device_args, args.tx_gain, args.rx_gain)
        print("AIS B210 capture complete: %d complex samples, %.2f s (cabled RF)" % (
            report["rx_samples"], report["duration_s"]), flush=True)
        return 0
    except KeyboardInterrupt:
        print("AIS B210 interrupted; device streams stopped", file=sys.stderr)
        return 130
    except Exception as exc:
        print("AIS B210 error: %s: %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
