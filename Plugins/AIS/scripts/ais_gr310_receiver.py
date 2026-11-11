"""GNU Radio 3.10 AIS receive core for bkerler/gr-ais maint-3.10.

Reproduces the enabled AIS DSP blocks in upstream apps/ais_demod.grc
(a GRC hierarchy named ais_rx_core), in Python inside this plugin.  The
installed bkerler OOT provides square_and_fft_sync_cc and pdu_to_nmea,
not an imported ais_rx/ais_demod.  For live GNU Radio 3.10 reception,
use burst-aware square-and-FFT carrier estimation with bounded lookahead.
The installed 3.10 reference flowgraph bypasses its traditional 1,024-sample
carrier estimator; in live AIS traffic it can estimate from noise and lose
a short burst before producing a useful correction. The replacement uses
one synchronized decoder per AIS channel, with no frequency scanning or
parallel acquisition candidates.

Reference (GPL-3.0-or-later):
https://github.com/bkerler/gr-ais/blob/maint-3.10/apps/ais_demod.grc
"""
from __future__ import annotations

import math


def validate_backend(ais):
    """Check the API actually supplied by FISSURE's 3.10 gr-ais fork."""
    required_ais = ('pdu_to_nmea',)
    for name in required_ais:
        if not callable(getattr(ais, name, None)):
            raise RuntimeError(
                'GNU Radio 3.10 gr-ais missing %s; expected bkerler/gr-ais ' 
                'maint-3.10 (installed gnuradio.ais=%s)' %
                (name, getattr(ais, '__file__', '(unknown)')))
    from gnuradio import analog, blocks, digital, filter
    from gnuradio.filter import pfb
    required = {
        'analog.agc3_cc': getattr(analog, 'agc3_cc', None),
        'analog.quadrature_demod_cf': getattr(analog, 'quadrature_demod_cf', None),
        'blocks.not_bb': getattr(blocks, 'not_bb', None),
        'blocks.add_const_bb': getattr(blocks, 'add_const_bb', None),
        'digital.cpmmod_bc': getattr(digital, 'cpmmod_bc', None),
        'digital.modulate_vector_bc': getattr(digital, 'modulate_vector_bc', None),
        'digital.corr_est_cc': getattr(digital, 'corr_est_cc', None),
        'digital.symbol_sync_cc': getattr(digital, 'symbol_sync_cc', None),
        'digital.hdlc_deframer_bp': getattr(digital, 'hdlc_deframer_bp', None),
        'digital.binary_slicer_fb': getattr(digital, 'binary_slicer_fb', None),
        'digital.diff_decoder_bb': getattr(digital, 'diff_decoder_bb', None),
        'filter.freq_xlating_fir_filter_ccf': getattr(filter, 'freq_xlating_fir_filter_ccf', None),
        'filter.fir_filter_ccf': getattr(filter, 'fir_filter_ccf', None),
        'filter.pfb.arb_resampler_ccf': getattr(pfb, 'arb_resampler_ccf', None),
    }
    missing = [name for name, obj in required.items() if not callable(obj)]
    if missing:
        raise RuntimeError('GNU Radio 3.10 missing AIS receive DSP blocks: ' + ', '.join(missing))
    return 'bkerler_core'


def make_receiver(offset, sample_rate, designator, ais, loop_bw=0.05, channelizer='translated_fir', on_frame=None, carrier_sync=False):
    """Make a no-hardware AIS channel receiver, NMEA printed by OOT block.

    Input is complex64 at ``sample_rate`` centered between AIS channels;
    ``offset`` frequency-selects A or B (+/-25 kHz).  The chain performs
    channel translation then the active bkerler AIS receiver core at four
    samples/symbol. ``channelizer='rotator'`` reproduces the known-working
    apps/ais_rx.grc + ais_rx_core.py receive path with NO extra FIR/decimator.
    The old translated_fir path is retained for all other callers.
    For live 3.10 reception, carrier_sync widens the pre-correction
    resampler passband, estimates and corrects CFO at 38.4 kS/s, then
    applies the narrow AIS filter before AGC. No manual frequency control.
    """
    from gnuradio import analog, blocks, digital, filter, gr
    from gnuradio.fft import window
    from gnuradio.filter import pfb
    validate_backend(ais)
    if designator not in ('A', 'B'):
        raise ValueError('AIS channel must be A or B')
    rate = float(sample_rate)
    if not math.isfinite(rate) or rate < 100000:
        raise ValueError('AIS sample rate must be >=100000')
    bit_rate = 9600.0
    bb_sps = 4
    bt = 0.4
    if channelizer not in ('translated_fir', 'rotator'):
        raise ValueError('AIS channelizer must be translated_fir or rotator')
    decimation = max(1, int(rate / (bit_rate * 5))) if channelizer == 'translated_fir' else 1
    channel_rate = rate / decimation
    resample_rate = (bb_sps * bit_rate) / channel_rate
    # Default 0.05 preserves existing decoding behavior for B210, RTL-SDR and
    # offline IQ. HackRF 3.10 streaming explicitly opts into 0.033: the value
    # from the installed fork's top-level apps/ais_rx.grc (ted_bw override).
    loop_bw = float(loop_bw)
    if not 0.005 <= loop_bw <= 0.2:
        raise ValueError('AIS timing loop bandwidth must be within 0.005..0.2')
    threshold = 0.83

    class Receiver(gr.hier_block2):
        def __init__(self):
            gr.hier_block2.__init__(
                self, 'FISSURE AIS 3.10 %s' % designator,
                gr.io_signature(1, 1, gr.sizeof_gr_complex),
                gr.io_signature(0, 0, 0))

            # Match the working gr-ais 3.10 apps/ais_rx.grc reference when
            # requested: its 200 kS/s UHD output enters +/-25 kHz rotators
            # directly, then the core's PFB resampler. Do NOT insert our
            # earlier translating FIR + decimator in that reference profile.
            if channelizer == 'rotator':
                self.channel_filter = blocks.rotator_cc(
                    -2.0 * math.pi * float(offset) / rate, False)
            else:
                # Allow normal SDR oscillator error through the first filter.
                # A narrow channel filter *before* CFO recovery clips a
                # frequency-offset AIS burst irreversibly. The translated
                # frontend is used for RTL-SDR; the B210/HackRF reference
                # profile uses a frequency rotator with no initial FIR.
                frontend_cutoff = 15000 if carrier_sync else 11000
                frontend_transition = 3000 if carrier_sync else 1000
                self.channel_filter = filter.freq_xlating_fir_filter_ccf(
                    decimation, filter.firdes.low_pass(
                        1, rate, frontend_cutoff, frontend_transition),
                    float(offset), rate)

            # Upstream apps/ais_demod.grc (hierarchical 'ais_rx_core'):
            # PFB resample to 4 sps at 9600 baud, AGC, correlate AIS preamble,
            # symbol timing recovery, FM demod, NRZI recovery, HDLC + NMEA.
            nfilts = 64
            # Correct frequency BEFORE applying the narrow AIS channel
            # passband. Previously the PFB resampler filtered at 5.76 kHz,
            # followed by carrier correction; a +2.7 kHz signal offset
            # pushed useful GMSK energy outside that filter. Use a wider
            # 12 kHz passband for the resampler and restore the original
            # 5.76 kHz filter only AFTER carrier correction.
            pre_cfo_cutoff = 12000.0 if carrier_sync else bit_rate * 0.6
            pre_cfo_transition = 2000.0 if carrier_sync else bit_rate * 0.1
            taps = filter.firdes.low_pass(
                nfilts, channel_rate*nfilts,
                pre_cfo_cutoff, pre_cfo_transition, window.WIN_HANN)
            self.resampler = pfb.arb_resampler_ccf(resample_rate, taps, nfilts, 0)
            # The old 3.8 gr-ais receiver used square-and-FFT carrier
            # estimation. Its un-gated 1,024-sample FFT is too slow for
            # ~30-40 ms AIS bursts at 38,400 samples/s. The 3.10 receiver
            # uses a 256-sample peak-pair estimate with a 512-sample
            # lookahead, choosing a correction before releasing the preamble.
            # During silence it holds the last reliable value, instead of
            # estimating a new offset from noise. One decoder per channel.
            if carrier_sync:
                from ais_burst_carrier_sync_v0922 import make_sync
                self.carrier_sync = make_sync(gr, designator)
                self.post_sync_filter = filter.fir_filter_ccf(
                    1, filter.firdes.low_pass(
                        1, bb_sps * bit_rate, bit_rate * 0.6,
                        bit_rate * 0.1, window.WIN_HANN))
            else:
                self.carrier_sync = None
                self.post_sync_filter = None
            self.agc = analog.agc3_cc(1e-1, 1e-2, 1.0, 1.0, 1, 65536)
            preamble = [1, 1, 255, 255] * 7
            modulator = digital.cpmmod_bc(
                analog.cpm.GAUSSIAN, 0.5, bb_sps, int(1/bt)+2, bt)
            preamble_waveform = digital.modulate_vector_bc(
                modulator.to_basic_block(), preamble, [1])
            self.correlator = digital.corr_est_cc(
                preamble_waveform, bb_sps, 6, threshold,
                digital.THRESHOLD_ABSOLUTE)
            self.timing = digital.symbol_sync_cc(
                digital.TED_DANDREA_AND_MENGALI_GEN_MSK,
                bb_sps, loop_bw, 1.0, 0.45, 0.1, 1,
                digital.constellation_bpsk().base(),
                digital.IR_MMSE_8TAP, 128, [])
            self.fm = analog.quadrature_demod_cf(math.pi/2)
            self.slicer = digital.binary_slicer_fb()
            self.diff = digital.diff_decoder_bb(2, digital.DIFF_DIFFERENTIAL)
            self.invert = blocks.not_bb()
            self.fix_bits = blocks.add_const_bb(2)
            self.deframer = digital.hdlc_deframer_bp(11, 64)
            self.nmea = ais.pdu_to_nmea(designator)
            processing = [self, self.channel_filter, self.resampler]
            if self.carrier_sync is not None:
                processing.append(self.carrier_sync)
                processing.append(self.post_sync_filter)
            processing.extend((self.agc, self.correlator, self.timing,
                               self.fm, self.slicer, self.diff, self.invert,
                               self.fix_bits, self.deframer))
            self.connect(*processing)
            if on_frame is None:
                self.msg_connect(self.deframer, 'out', self.nmea, 'print')
            else:
                # The callback receives CRC-valid HDLC frames; failed
                # preamble hypotheses never count as successful acquisition.
                import pmt
                class FrameMonitor(gr.basic_block):
                    def __init__(self):
                        gr.basic_block.__init__(self, name='ais_valid_frame_monitor',
                                                in_sig=None, out_sig=None)
                        port = pmt.intern('in')
                        self.message_port_register_in(port)
                        self.message_port_register_out(pmt.intern('out'))
                        def handle(message):
                            # The callback returns False when another parallel
                            # branch already locked this channel.  Filter its
                            # NMEA before it reaches the shared Sensor Node.
                            if on_frame() is not False:
                                self.message_port_pub(pmt.intern('out'), message)
                        self.set_msg_handler(port, handle)
                self.frame_monitor = FrameMonitor()
                self.msg_connect(self.deframer, 'out', self.frame_monitor, 'in')
                self.msg_connect(self.frame_monitor, 'out', self.nmea, 'print')

    return Receiver()
