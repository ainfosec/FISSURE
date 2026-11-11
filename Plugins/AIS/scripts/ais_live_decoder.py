#!/usr/bin/env python3
"""Persistent, no-IQ-file gr-ais demodulator for FISSURE AIS.

Use --source stdin for continuous complex64-le IQ, or --source b210 for
a live UHD source with selectable TX/RX or RX2 antenna.
The same GNU Radio 3.8/3.10 receive hierarchy as ais_iq_decoder is reused.
Decoded NMEA is written to stdout; diagnostics are written to stderr.
"""
from __future__ import annotations

import argparse
import math
import os
import signal
import sys

from ais_iq_decoder import gr_minor_version, resolve_ais_module, make_top_block


def make_stdin_source(gr, numpy_module=None):
    """GNU Radio source reading bounded chunks from a live cf32 stdin pipe.

    The source does not buffer unlimited IQ, and EOF terminates the graph.
    The upstream native capture process remains running throughout the session.
    """
    if numpy_module is None:
        import numpy as np
    else:
        np = numpy_module

    class StdinComplexSource(gr.sync_block):
        def __init__(self):
            gr.sync_block.__init__(self, name='fissure_ais_stdin_complex64',
                                   in_sig=None, out_sig=[np.complex64])
            self.fd = sys.stdin.buffer.fileno()
            self.pending = bytearray()

        def work(self, input_items, output_items):
            out = output_items[0]
            nbytes = len(out) * 8
            while len(self.pending) < 8:
                data = os.read(self.fd, max(8, min(131072, nbytes)))
                if not data:
                    return -1
                self.pending.extend(data)
            if len(self.pending) < nbytes:
                data = os.read(self.fd, nbytes - len(self.pending))
                if data:
                    self.pending.extend(data)
            count = min(len(out), len(self.pending) // 8)
            out[:count] = np.frombuffer(self.pending[:count*8], dtype='<c8')
            del self.pending[:count*8]
            return count

    return StdinComplexSource()


def make_b210_source(uhd, sample_rate, rf_frequency, rx_gain, device_args, rf_channel=0,
                     rx_antenna='TX/RX', rf_tune_offset_hz=0):
    rx = uhd.usrp_source(str(device_args), uhd.stream_args(cpu_format='fc32', channels=[0]))
    from ais_b210_frontend_v097 import configure_subdevice, validate_antenna
    configure_subdevice(rx, 'rx', rf_channel)
    rx.set_samp_rate(sample_rate)
    if abs(float(rx.get_samp_rate()) - sample_rate) > 1:
        raise RuntimeError('B210 RX sample rate mismatch')
    # GNU Radio 3.10 B210 lab test: apply the offset to the UHD tuner,
    # exactly as in the successfully tested standalone AIS flowgraph.
    # Do not apply it a second time in the downstream channelizer.
    tuned_frequency = float(rf_frequency) + float(rf_tune_offset_hz)
    rx.set_center_freq(tuned_frequency, 0)
    measured = getattr(rx, 'get_center_freq', None)
    actual = float(measured(0)) if callable(measured) else tuned_frequency
    print('AIS B210 RX UHD tune: requested=%.0f Hz, offset=%+.0f Hz, target=%.0f Hz, actual=%.0f Hz' % (
        rf_frequency, rf_tune_offset_hz, tuned_frequency, actual),
        file=sys.stderr, flush=True)
    rx.set_gain(rx_gain, 0)
    rx.set_antenna(validate_antenna(rx_antenna), 0)
    return rx


def main(argv=None):
    p = argparse.ArgumentParser(description='Stream AIS gr-ais demodulation with no IQ files')
    p.add_argument('--source', choices=('stdin', 'b210'), required=True)
    p.add_argument('--sample-rate', type=float, default=240000)
    p.add_argument('--rf-frequency', type=float, default=162000000)
    p.add_argument('--device-args', default='type=b200')
    # Ignore this retired internal option if an older launcher survives a hot update.
    # It is not a user Action parameter; GNU Radio 3.10 uses automatic AFC.
    p.add_argument('--frequency-correction-hz', type=float, default=None, help=argparse.SUPPRESS)
    p.add_argument('--rx-gain', type=float, default=70)
    p.add_argument('--rf-channel', default='0')
    p.add_argument('--rx-antenna', default='TX/RX')
    p.add_argument('--receiver-profile', choices=('auto', 'grc_reference'), default='auto',
                   help='GNU Radio 3.10 GRC reference DSP (200 kS/s, rotator channelizer); '
                        '3.8 preserves its existing receiver')
    p.add_argument('--core-path', default='', help='Deprecated, ignored with gr-ais ais_rx')
    p.add_argument('--loop-bandwidth', type=float, default=None,
                   help='Optional 3.10 timing loop bandwidth override for HackRF')
    args = p.parse_args(argv)
    if args.frequency_correction_hz is not None:
        print('AIS live RX compatibility: retired frequency correction argument '
              'ignored; automatic AFC remains enabled', file=sys.stderr, flush=True)
    if not math.isfinite(args.sample_rate) or args.sample_rate < 100000 or args.sample_rate > 5000000:
        p.error('invalid sample rate')
    if not math.isfinite(args.rf_frequency) or not 70e6 <= args.rf_frequency <= 3000e6:
        p.error('invalid RX center frequency')
    if not math.isfinite(args.rx_gain) or args.rx_gain < 0:
        p.error('invalid RX gain')
    if args.loop_bandwidth is not None and (not math.isfinite(args.loop_bandwidth) or
                                             not 0.005 <= args.loop_bandwidth <= 0.2):
        p.error('invalid loop bandwidth')
    try:
        from gnuradio import gr
        minor, version = gr_minor_version(gr)
        module = resolve_ais_module(minor)
        # Version-specific receiver hierarchy is built inside the plugin.
        core = None
        use_grc_reference = (minor == 10 and
                             (args.source == 'b210' or args.receiver_profile == 'grc_reference'))
        # Version 3.10 reference standalone receiver was decoded successfully
        # at 200 kS/s with direct channel rotators and TED BW 0.033. Preserve
        # 3.8's original requested rate and DSP path. Native HackRF must
        # supply 200 kS/s when requesting this profile.
        stream_rate = (200000.0 if args.source == 'b210' and use_grc_reference
                       and args.sample_rate == 240000 else args.sample_rate)
        if args.source == 'stdin' and use_grc_reference and abs(stream_rate - 200000) > 0.5:
            raise ValueError('GNU Radio 3.10 reference stdin profile requires 200000 samples/s')
        loop_bandwidth = 0.033 if use_grc_reference and args.loop_bandwidth is None else args.loop_bandwidth
        if args.source == 'b210':
            from gnuradio import uhd
            # Always tune to the requested center. The 3.10 baseband receiver
            # estimates oscillator error from AIS bursts, without a UI setting.
            tune_offset = 0.0
            source = make_b210_source(uhd, stream_rate, args.rf_frequency,
                                      args.rx_gain, args.device_args, args.rf_channel,
                                      args.rx_antenna, rf_tune_offset_hz=tune_offset)
        else:
            source = make_stdin_source(gr)
        # gr-ais operates at the standard +/-25 kHz AIS channel offsets.
        # For isolated lab replay these offsets are the same around the
        # selected test center, even though the physical RF is not maritime.
        graph = make_top_block(None, stream_rate, 162000000.0, 'both',
                               minor, module, core, source=source,
                               frequency_correction_hz=0,
                               automatic_frequency_recovery=(minor == 10),
                               loop_bandwidth=loop_bandwidth,
                               receiver_profile='grc_reference' if use_grc_reference else None)
        print('AIS streaming decoder started: GNU Radio %s, source=%s, '
              'effective_sample_rate_hz=%.0f, profile=%s, ted_bw=%s, '
              'frequency_control=%s' %
              (version, args.source, stream_rate,
               'grc_reference' if use_grc_reference else 'legacy',
               loop_bandwidth if loop_bandwidth is not None else 'default',
               'burst_square_fft' if minor == 10 and not callable(getattr(module, 'ais_rx', None)) else ('gr310_native' if minor == 10 else 'gr38_native')), file=sys.stderr, flush=True)
        def shutdown(signum, frame):
            graph.stop()
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)
        graph.start()
        graph.wait()
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print('AIS streaming decoder error: %s: %s' % (type(exc).__name__, exc),
              file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
