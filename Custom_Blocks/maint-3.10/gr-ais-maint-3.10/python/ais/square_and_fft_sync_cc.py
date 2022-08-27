#!/usr/bin/env python

from gnuradio import gr
from gnuradio import eng_notation
from gnuradio.filter import window
from gnuradio import digital
from gnuradio import fft
from gnuradio import blocks
from gnuradio import analog
from math import pi
from gnuradio import ais


class square_and_fft_sync_cc(gr.hier_block2):
    def __init__(self, samplerate, bits_per_sec, fftlen):
        gr.hier_block2.__init__(self, "square_and_fft_sync_cc",
                                gr.io_signature(1, 1, gr.sizeof_gr_complex), # Input signature
                                gr.io_signature(1, 1, gr.sizeof_gr_complex)) # Output signature

        #this is just the old square-and-fft method
        #ais.freqest is simply looking for peaks spaced bits-per-sec apart
        self.square = blocks.multiply_cc(1)
        self.fftvect = blocks.stream_to_vector(gr.sizeof_gr_complex, fftlen)
        self.fft = fft.fft_vcc(fftlen, True, window.rectangular(fftlen), True)
        self.freqest = ais.freqest(int(samplerate), int(bits_per_sec), fftlen)
        self.repeat = blocks.repeat(gr.sizeof_float, fftlen)
        self.fm = analog.frequency_modulator_fc(-1.0/(float(samplerate)/(2*pi)))
        self.mix = blocks.multiply_cc(1)

        self.connect(self, (self.square, 0))
        self.connect(self, (self.square, 1))
        #this is the feedforward branch
        self.connect(self, (self.mix, 0))
        #this is the feedback branch
        self.connect(self.square, self.fftvect, self.fft, self.freqest, self.repeat, self.fm, (self.mix, 1))
        #and this is the output
        self.connect(self.mix, self)
