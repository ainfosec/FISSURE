#!/usr/bin/env python
#ais_demod.py
#implements a hierarchical class to demodulate GMSK packets as per AIS, including differential decoding and bit inversion for NRZI.
#does not unstuff bits

#modified 4/29/10 to include frequency estimation to center signals at baseband
#eventually will do coherent demodulation
#right now, it does coherent demod, but it's crippled for two reasons.
#first, there's no "reset" input on the gr-trellis VA, so the algorithm doesn't get properly initialized at the start of a packet
#second, there's no provision for phase estimation, so the combined trellis assumes each packet starts at phase=0.
#sometimes it'll cope with this, but it loses a lot of packets

from gnuradio import gr, filter, blocks
from gnuradio import trellis
from gnuradio.filter import window
from gnuradio import digital
from gnuradio import analog
import math
import ais
import random
class ais_demod(gr.hier_block2):
    def __init__(self, options):

        gr.hier_block2.__init__(self, "ais_demod",
                                gr.io_signature(1, 1, gr.sizeof_gr_complex), # Input signature
                                gr.io_signature(1, 1, gr.sizeof_char)) # Output signature

        self._samples_per_symbol = options[ "samples_per_symbol" ]
        self._bits_per_sec = options[ "bits_per_sec" ]
        self._samplerate = self._samples_per_symbol * self._bits_per_sec
        self._clockrec_gain = options[ "clockrec_gain" ]
        self._omega_relative_limit = options[ "omega_relative_limit" ]
        self.fftlen = options[ "fftlen" ]
        self.freq_sync = ais.square_and_fft_sync_cc(self._samplerate, self._bits_per_sec, self.fftlen)
        self.agc = analog.feedforward_agc_cc(512, 2)
        self.preamble = [1,1,0,0]*7
        self.mod = digital.gmsk_mod(self._samples_per_symbol, 0.4)
        self.mod_vector = digital.modulate_vector_bc(self.mod.to_basic_block(), self.preamble, [1])
        self.preamble_detect = ais.corr_est_cc(self.mod_vector,
                                               self._samples_per_symbol,
                                               1, #mark delay
                                               0.9) #threshold
        self.clockrec = ais.msk_timing_recovery_cc(self._samples_per_symbol,
                                                       self._clockrec_gain, #gain
                                                       self._omega_relative_limit, #error lim
                                                       1) #output sps

        sensitivity = (math.pi / 2)
        self.demod = analog.quadrature_demod_cf(sensitivity) #param is gain
        self.slicer = digital.binary_slicer_fb()
        self.diff = digital.diff_decoder_bb(2)
        self.invert = ais.invert() #NRZI signal diff decoded and inverted should give original signal

#        self.connect(self, self.gmsk_sync)

        self.connect(self, self.freq_sync, self.agc, (self.preamble_detect, 0), self.clockrec, self.demod, self.slicer, self.diff, self.invert, self)
