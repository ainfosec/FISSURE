#!/usr/bin/env python3
"""Offline AIS GMSK IQ stimulus generator for GNU Radio 3.8/3.10 (no RF).

Uses a bounded, tested Python AIS LSB-first-octet HDLC/FCS/NRZI frame encoder instead of
legacy AISTX.Build_Frame, whose GNU Radio source stalls on Ubuntu 20.04.
GNU Radio's GMSK modulator then processes 32 packed bytes and writes finite
complex64 IQ bursts at +/-25 kHz around virtual 162 MHz. No SDR hardware.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys
import tempfile

try:
    from ais_codec import checksum_valid
    from ais_rf_framing import build_slot
    from ais_gr_compat import gr_minor_version
except ImportError:
    from scripts.ais_codec import checksum_valid
    from scripts.ais_rf_framing import build_slot
    from scripts.ais_gr_compat import gr_minor_version

CHANNEL_FREQ = {"A": 161_975_000.0, "B": 162_025_000.0}
AIS_POSITION_TYPES = {1, 2, 3, 18}
AIS_SINGLE_SLOT_TYPES = AIS_POSITION_TYPES | {24}


def nmea_single_slot_frame(line):
    """Validate unfragmented position/static report and recover 160/168 payload bits.

    The finite AIS framer accepts *binary digits*, not armored NMEA or the
    NMEA XOR checksum; it computes the over-the-air CRC independently.
    """
    line = line.strip()
    if not checksum_valid(line):
        raise ValueError("NMEA checksum is invalid")
    body = line.split("*", 1)[0].split(",")
    if len(body) != 7 or body[1:3] != ["1", "1"]:
        raise ValueError("only single-sentence AIS reports are supported")
    channel = body[4]
    if channel not in CHANNEL_FREQ:
        raise ValueError("AIS radio channel must be A or B")
    try:
        fill = int(body[6])
    except ValueError:
        raise ValueError("invalid AIS fill-bit count")
    if not 0 <= fill <= 5:
        raise ValueError("invalid AIS fill-bit count")
    bits = []
    for c in body[5]:
        num = ord(c) - 48
        if num > 40:
            num -= 8
        if not 0 <= num < 64:
            raise ValueError("invalid AIS six-bit armored character")
        bits.append(format(num, "06b"))
    payload = "".join(bits)
    if fill:
        payload = payload[:-fill]
    if len(payload) not in (160, 168):
        raise ValueError("only 160-/168-bit AIS single-slot frames supported; got %d bits" % len(payload))
    typ = int(payload[:6], 2)
    if typ not in AIS_SINGLE_SLOT_TYPES:
        raise ValueError("only AIS position and Type 24 static reports supported; got %d" % typ)
    if typ in AIS_POSITION_TYPES and len(payload) != 168:
        raise ValueError("AIS position reports must be 168 bits")
    if typ == 24 and int(payload[38:40], 2) not in (0, 1):
        raise ValueError("AIS Type 24 has an invalid static part")
    mmsi = "%09d" % int(payload[8:38], 2)
    return {"bits": payload, "channel": channel, "message_type": typ,
            "mmsi": mmsi, "nmea": line}


def nmea_position_frame(line):
    """Backwards-compatible position-only helper used by existing tests."""
    frame = nmea_single_slot_frame(line)
    if frame["message_type"] not in AIS_POSITION_TYPES:
        raise ValueError("not an AIS position report")
    return frame


def collect_frames(nmea_file, max_frames=12):
    path = Path(nmea_file).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError("NMEA file not found: %s" % path)
    frames = []
    skipped = 0
    for line in path.read_text(encoding="ascii").splitlines():
        if not line.strip():
            continue
        # Ignore unsupported multi-slot static/voyage reports, not Type 24.
        try:
            frames.append(nmea_single_slot_frame(line))
        except ValueError:
            skipped += 1
        if len(frames) >= max_frames:
            break
    if not frames:
        raise ValueError("No valid single-slot AIS reports found in %s" % path)
    return frames, skipped


def probe():
    from gnuradio import gr, blocks, digital  # noqa: F401
    _, version = gr_minor_version(gr)
    if not callable(getattr(digital, "gmsk_mod", None)):
        raise RuntimeError("GNU Radio digital.gmsk_mod not found")
    return gr, blocks, digital, version


def generate_burst(bits, channel, path, sample_rate, center_freq, runtime):
    """Modulate one finite AIS radio slot, with no repeating OOT source."""
    gr, blocks, digital, _version = runtime
    packed = build_slot(bits)
    source = blocks.vector_source_b(list(packed), False)
    # GNU Radio 3.8/3.10 gmsk_mod unpacks packed input MSB-first.
    modem = digital.gmsk_mod(samples_per_symbol=int(sample_rate // 9600),
                             bt=0.4, verbose=False, log=False)
    frequency_offset = CHANNEL_FREQ[channel] - center_freq
    rotator = blocks.rotator_cc(2.0 * math.pi * frequency_offset / sample_rate)
    sink = blocks.file_sink(gr.sizeof_gr_complex, str(path), False)
    tb = gr.top_block("FISSURE offline AIS finite GMSK modulation")
    tb.connect((source, 0), (modem, 0))
    tb.connect((modem, 0), (rotator, 0))
    tb.connect((rotator, 0), (sink, 0))
    tb.run()
    # Close GNU Radio file sink before checking or reading it.
    try:
        sink.close()
    except AttributeError:
        pass
    del tb, sink, rotator, modem, source
    if not path.is_file():
        raise RuntimeError("GNU Radio did not create the burst file: %s" % path)
    length = path.stat().st_size
    if length < 8 * 512 or length % 8:
        raise RuntimeError("GNU Radio produced an empty/short or malformed burst: %s (%d bytes)" %
                           (path, length))
    if not any(path.read_bytes()):
        raise RuntimeError("GNU Radio produced an all-zero GMSK burst: %s" % path)
    return length // 8


def generate(nmea_file, output_file, sample_rate=240000, center_freq=162000000,
             gap_ms=350, max_frames=12, manifest_file=None):
    sample_rate = int(sample_rate)
    center_freq = float(center_freq)
    if not 192000 <= sample_rate <= 960000 or sample_rate % 48000:
        raise ValueError("sample_rate must be a multiple of 48000 between 192000 and 960000")
    if not math.isfinite(center_freq):
        raise ValueError("center_frequency must be finite")
    if not 150 <= gap_ms <= 2000:
        raise ValueError("gap_ms must be between 150 and 2000")
    if not 1 <= max_frames <= 48:
        raise ValueError("max_frames must be 1 to 48")
    frames, skipped = collect_frames(nmea_file, max_frames)
    for f in frames:
        if abs(CHANNEL_FREQ[f["channel"]] - center_freq) >= sample_rate * 0.4:
            raise ValueError("Channel %s is outside useful IQ bandwidth" % f["channel"])
    runtime = probe()
    output_path = Path(output_file).expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    gap_samples = round(sample_rate * gap_ms / 1000)
    # Silence gives the detector time to reset between independently framed bursts.
    silence = b"\x00" * (gap_samples * 8)
    rows = []
    total_samples = 0
    # Build atomically so a stalled encoder cannot leave a valid-looking
    # recording consisting only of the initial zero-valued padding.
    output_path.unlink(missing_ok=True)
    partial = output_path.with_name(output_path.name + ".partial")
    partial.unlink(missing_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="fissure_ais_bursts_") as temp_dir:
            with partial.open("wb") as out:
                for idx, frame in enumerate(frames):
                    print("AIS IQ: framing/modulating burst %d/%d (%s, MMSI %s)" % (
                          idx + 1, len(frames), frame["channel"], frame["mmsi"]), flush=True)
                    burst_file = Path(temp_dir) / ("ais_%03d.cf32" % idx)
                    burst_samples = generate_burst(frame["bits"], frame["channel"], burst_file,
                                                   sample_rate, center_freq, runtime)
                    data = burst_file.read_bytes()
                    if idx == 0:
                        out.write(silence)
                        total_samples += gap_samples
                    out.write(data)
                    out.write(silence)
                    rows.append({"index": idx, "channel": frame["channel"],
                                 "mmsi": frame["mmsi"], "message_type": frame["message_type"],
                                 "nmea": frame["nmea"], "start_sample": total_samples,
                                 "burst_samples": burst_samples})
                    total_samples += burst_samples + gap_samples
        if not rows or partial.stat().st_size != total_samples * 8:
            raise RuntimeError("Incomplete AIS IQ file; refusing to publish partial recording")
        partial.replace(output_path)
    finally:
        partial.unlink(missing_ok=True)
    manifest = {"schema": "fissure.ais.offline_iq.v1",
                "rf_transmitted": False, "simulated": True,
                "modulator": "finite Python AIS HDLC/FCS/NRZI + GNU Radio GMSK (BT 0.4)",
                "gnuradio_version": runtime[-1], "iq_format": "complex64_le_interleaved_iq",
                "center_frequency_hz": center_freq, "sample_rate_hz": sample_rate,
                "samples": total_samples, "duration_s": total_samples / sample_rate,
                "frame_count": len(rows), "skipped_nmea_sentences": skipped,
                "iq_bytes": output_path.stat().st_size, "frames": rows}
    if manifest_file:
        dest = Path(manifest_file).expanduser().resolve()
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv=None):
    parser = argparse.ArgumentParser(description="Create offline AIS CF32 IQ with finite AIS framing and GNU Radio GMSK (NO RF)")
    parser.add_argument("--probe", action="store_true", help="Check GNU Radio 3.8/3.10 GMSK dependencies")
    parser.add_argument("--input", help="NMEA AIS Type 1/18 position or Type 24 static reports")
    parser.add_argument("--output", help="Output raw complex64 IQ file")
    parser.add_argument("--manifest", default="", help="Optional manifest JSON path")
    parser.add_argument("--sample-rate", type=int, default=240000)
    parser.add_argument("--center-freq", type=float, default=162000000)
    parser.add_argument("--gap-ms", type=int, default=350)
    parser.add_argument("--max-frames", type=int, default=48)
    args = parser.parse_args(argv)
    try:
        if args.probe:
            runtime = probe()
            print("AIS IQ TX readiness OK: GNU Radio %s, finite Python AIS framing + GMSK (offline only)" % runtime[-1])
            return 0
        if not args.input or not args.output:
            parser.error("--input and --output are required")
        manifest = generate(args.input, args.output, args.sample_rate, args.center_freq,
                            args.gap_ms, args.max_frames, args.manifest or None)
        print("AIS IQ generated: %d bursts, %.3f s, %d bytes (NO RF)" % (
            manifest["frame_count"], manifest["duration_s"], manifest["iq_bytes"]))
        return 0
    except Exception as exc:
        print("AIS IQ generator error: %s: %s" % (type(exc).__name__, exc), file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
