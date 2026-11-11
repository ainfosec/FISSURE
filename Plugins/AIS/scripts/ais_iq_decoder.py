#!/usr/bin/env python3
"""Offline gr-ais complex64 IQ receiver for FISSURE (GNU Radio 3.8/3.10).

For GNU Radio 3.8, reuse bmagistro/gr-ais's published ``ais.ais_rx``
receiver hierarchy (which prints decoded NMEA to the process's stdout).
For GNU Radio 3.10, construct the equivalent receiver hierarchy with the
installed bkerler/gr-ais PDU-to-NMEA and standard GNU Radio DSP blocks. No old Flow Graph
Library or generated ais_rx_core.py file is required.

Only received AIS messages are output; there is no SDR or RF transmission.
Raw source format: little-endian complex64, interleaved float32 I/Q.

Portability is validated by mocked compatibility tests. Demodulation still
requires an actual GNU Radio/gr-ais IQ capture test on the target distro.
"""
from __future__ import annotations

import argparse
import math
from pathlib import Path
import sys

from ais_gr_compat import gr_minor_version

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
FISSURE_ROOT = PLUGIN_ROOT.parent.parent
AIS_HZ = {"A": 161_975_000.0, "B": 162_025_000.0}


def resolve_ais_module(gr_minor):
    """Select gr-ais modules installed for the active GNU Radio version."""
    try:
        if gr_minor == 8:
            import ais
            for name in ('ais_rx', 'pdu_to_nmea'):
                if not callable(getattr(ais, name, None)):
                    raise RuntimeError('GNU Radio 3.8 gr-ais missing %s' % name)
        elif gr_minor == 10:
            from gnuradio import ais
            if not callable(getattr(ais, 'ais_rx', None)):
                from ais_gr310_receiver import validate_backend
                validate_backend(ais)
        else:
            raise RuntimeError('Unsupported GNU Radio minor version: %s' % gr_minor)
        return ais
    except ImportError as exc:
        package = 'ais' if gr_minor == 8 else 'gnuradio.ais'
        raise RuntimeError('Cannot import %s for GNU Radio 3.%s: %s' % (
            package, gr_minor, exc)) from exc


def receiver_backend(gr_minor, module):
    if gr_minor == 8:
        return 'ais.ais_rx (3.8)'
    if callable(getattr(module, 'ais_rx', None)):
        return 'gnuradio.ais.ais_rx (3.10)'
    return 'bkerler_core'


def make_top_block(path, sample_rate, center_frequency, channel, gr_minor,
                   ais_module, core_path=None, source=None,
                   frequency_correction_hz=0, loop_bandwidth=None,
                   receiver_profile=None, automatic_frequency_recovery=False):
    """Demodulate AIS channels A/B through the installed gr-ais receiver.

    Each receiver hierarchy owns demodulation, HDLC framing and its NMEA
    printing message port. Both gr-ais implementations take (offset, rate,
    designator), with the same baseband offset sign convention.
    """
    from gnuradio import blocks, gr
    if gr_minor not in (8, 10):
        raise RuntimeError("Unsupported GNU Radio minor version %s" % gr_minor)
    if channel not in ("both", "A", "B"):
        raise ValueError("Invalid AIS channel %r" % channel)
    tb = gr.top_block("FISSURE AIS IQ file receiver")
    if source is None:
        source = blocks.file_source(gr.sizeof_gr_complex, str(path), False)
    # GNU Radio 3.10.9.x can crash when Python streaming blocks are connected
    # but the last Python reference disappears before top_block.stop()/wait().
    # Keep the complete Python-backed receiver hierarchy alive explicitly,
    # including the new AFC sync_block and any message monitor children.
    # See GNU Radio issue #8137 (Python block lifetime / SIGSEGV).
    tb._fissure_owned_blocks = [source]
    # As with GNU Radio 3.8's ais.ais_rx, use exactly one carrier-
    # synchronized decoder per AIS channel.  The old 3.8 chain has
    # square_and_fft_sync_cc before its AGC/preamble stage. The 3.10
    # reference flowgraph bypasses it; the original 1,024-sample un-gated
    # estimator often reacts too late to a short AIS burst. For live 3.10,
    # correct each burst using a short square-and-FFT estimate with lookahead
    # while preserving one decoder per channel and the last valid correction.
    native_carrier_sync = (automatic_frequency_recovery and gr_minor == 10
                           and not callable(getattr(ais_module, 'ais_rx', None)))
    working_source = source
    for designator in ('A', 'B'):
        if channel not in ('both', designator):
            continue
        offset = AIS_HZ[designator] - center_frequency + frequency_correction_hz
        if callable(getattr(ais_module, 'ais_rx', None)):
            receiver = ais_module.ais_rx(offset, sample_rate, designator)
        elif gr_minor == 10:
            from ais_gr310_receiver import make_receiver
            if receiver_profile not in (None, 'grc_reference'):
                raise ValueError('Unknown 3.10 AIS receiver profile %r' % receiver_profile)
            options = {'carrier_sync': native_carrier_sync}
            if receiver_profile == 'grc_reference':
                options.update(loop_bw=0.033 if loop_bandwidth is None else loop_bandwidth,
                               channelizer='rotator')
            elif loop_bandwidth is not None:
                options['loop_bw'] = loop_bandwidth
            receiver = make_receiver(offset, sample_rate, designator,
                                     ais_module, **options)
        else:
            raise RuntimeError('Installed gr-ais lacks compatible receiver hierarchy')
        tb._fissure_owned_blocks.append(receiver)
        tb.connect((working_source, 0), (receiver, 0))
    return tb


def main(argv=None):
    p = argparse.ArgumentParser(description="Decode AIS complex64 IQ with GNU Radio 3.8/3.10 (no RF)")
    p.add_argument("--input", default="", help="Local raw complex64 IQ file")
    p.add_argument("--sample-rate", type=float, default=200000.0, help="IQ sample rate in Hz")
    p.add_argument("--center-freq", type=float, default=162000000.0, help="RF center frequency in Hz")
    p.add_argument("--channel", choices=("both", "A", "B"), default="both")
    p.add_argument("--core-path", default="", help="Deprecated; no longer required by GNU Radio 3.10")
    p.add_argument("--probe", action="store_true", help="Check GNU Radio and matching gr-ais dependencies")
    p.add_argument("--frequency-correction-hz", type=float, default=0.0,
                   help="Signed DSP correction in Hz for offset between independent SDR oscillators")
    a = p.parse_args(argv)

    if not (math.isfinite(a.sample_rate) and 100000 <= a.sample_rate <= 5000000):
        p.error("--sample-rate must be finite, 100000–5000000 Hz")
    if not (math.isfinite(a.center_freq) and 100000000 <= a.center_freq <= 200000000):
        p.error("--center-freq must be finite, 100–200 MHz")

    if not (math.isfinite(a.frequency_correction_hz) and abs(a.frequency_correction_hz) <= 10000):
        p.error("--frequency-correction-hz must be within +/-10000")

    if not a.probe:
        if not a.input:
            p.error("--input is required without --probe")
        path = Path(a.input).expanduser().resolve()
        if not path.is_file():
            p.error("IQ file not found: %s" % path)
        if path.stat().st_size < 8 or path.stat().st_size % 8:
            p.error("IQ file must contain interleaved complex float32 samples (8 bytes/sample)")
    else:
        path = None

    try:
        from gnuradio import gr
        minor, version = gr_minor_version(gr)
        ais_module = resolve_ais_module(minor)
        if a.core_path:
            print("Note: --core-path is obsolete; installed gr-ais blocks are used",
                  file=sys.stderr, flush=True)
        if a.probe:
            print("AIS IQ readiness OK: GNU Radio %s, %s, backend=%s" % (
                version, getattr(ais_module, "__file__", ais_module.__name__),
                receiver_backend(minor, ais_module)),
                file=sys.stderr, flush=True)
            return 0
        tb = make_top_block(path, a.sample_rate, a.center_freq, a.channel,
                            minor, ais_module, frequency_correction_hz=a.frequency_correction_hz)
        tb.start()
        tb.wait()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print("AIS IQ decoder error: %s: %s" % (type(exc).__name__, exc),
              file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
