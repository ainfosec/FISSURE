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

from gnuradio import gr, filter
from gnuradio import trellis
from gnuradio.filter import window
from gnuradio import digital
from gnuradio import analog
import math
#import scipy.special, numpy
#import fsm_utils
import ais
import gmsk_sync

#make_gmsk uses make_cpm_signals to create GMSK signals for a given samples per symbol and BT.
#based on (copied from) Achilleas Anastasopoulos's test_cpm.py
#uses his method of CPM decomposition
#returns an FSM, a constellation, the required matched filters, N (the length of the required trellis), and f0T (the memoryless modulation component frequency)
def make_gmsk(samples_per_symbol, BT):
    #M, K, P, h, L are fixed for GMSK
    M = 2 #number of bits per symbol
    K = 1
    P = 2 #h=K/P, K and P are relatively prime
    h = (1.0*K)/P
    L = 3
    Q = samples_per_symbol
    frac = 0.99 #fractional energy component deemed necessary to consider in the trellis, for finding dimensionality

    fsm = trellis.fsm(P, M, L)

    tt=numpy.arange(0,L*Q)/(1.0*Q)-L/2.0
    p=(0.5*scipy.special.erfc(2*math.pi*BT*(tt-0.5)/math.sqrt(math.log(2.0))/math.sqrt(2.0))-0.5*scipy.special.erfc(2*math.pi*BT*(tt+0.5)/math.sqrt(math.log(2.0))/math.sqrt(2.0)))/2.0
    p=p/sum(p)*Q/2.0
    q=numpy.cumsum(p)/Q
    q=q/q[-1]/2.0
    (f0T,SS,S,F,Sf,Ff,N) = fsm_utils.make_cpm_signals(K,P,M,L,q,frac)
    constellation = numpy.reshape(numpy.transpose(Sf),N*fsm.O())
    Ffa = numpy.insert(Ff,Q,numpy.zeros(N),axis=0)
    MF = numpy.fliplr(numpy.transpose(Ffa))

    return (fsm, constellation, MF, N, f0T)

def gcd(a, b):
    if a > b: a, b = b, a
    while a > 0: a, b = (b % a), a
    return b

class ais_demod(gr.hier_block2):
    def __init__(self, options):

        gr.hier_block2.__init__(self, "ais_demod",
                                gr.io_signature(1, 1, gr.sizeof_gr_complex), # Input signature
                                gr.io_signature(1, 1, gr.sizeof_char)) # Output signature

        self._samples_per_symbol = options[ "samples_per_symbol" ]
        self._bits_per_sec = options[ "bits_per_sec" ]
        self._samplerate = self._samples_per_symbol * self._bits_per_sec
        self._gain_mu = options[ "gain_mu" ]
        self._mu = options[ "mu" ]
        self._omega_relative_limit = options[ "omega_relative_limit" ]
        self.fftlen = options[ "fftlen" ]

        #right now we are going to hardcode the different options for VA mode here. later on we can use configurable options
        samples_per_symbol_viterbi = 2
        bits_per_symbol = 2
        samples_per_symbol = 6
        samples_per_symbol_clockrec = samples_per_symbol / bits_per_symbol
        BT = 0.4
        data_rate = 9600.0
        samp_rate = options[ "samp_rate" ]

        self.gmsk_sync = gmsk_sync.square_and_fft_sync(self._samplerate, self._bits_per_sec, self.fftlen)

        if(options[ "viterbi" ] is True):
            #calculate the required decimation and interpolation to achieve the desired samples per symbol
            denom = gcd(data_rate*samples_per_symbol, samp_rate)
            cr_interp = int(data_rate*samples_per_symbol/denom)
            cr_decim = int(samp_rate/denom)
            self.resample = filter.rational_resampler_ccc(cr_interp, cr_decim)
            #here we take a different tack and use A.A.'s CPM decomposition technique
            self.clockrec = digital.clock_recovery_mm_cc(samples_per_symbol_clockrec, 0.005*0.005*0.25, 0.5, 0.005, 0.0005) #might have to futz with the max. deviation
            (fsm, constellation, MF, N, f0T) = make_gmsk(samples_per_symbol_viterbi, BT) #calculate the decomposition required for demodulation
            self.costas = digital.costas_loop_cc(0.015, 0.015*0.015*0.25, 100e-6, -100e-6, 4) #does fine freq/phase synchronization. should probably calc the coeffs instead of hardcode them.
            self.streams2stream = blocks.streams_to_stream(int(gr.sizeof_gr_complex*1), int(N))
            self.mf0 = filter.fir_filter_ccc(samples_per_symbol_viterbi, MF[0].conjugate()) #two matched filters for decomposition
            self.mf1 = filter.fir_filter_ccc(samples_per_symbol_viterbi, MF[1].conjugate())
            self.fo = analog.sig_source_c(samples_per_symbol_viterbi, gr.GR_COS_WAVE, -f0T, 1, 0) #the memoryless modulation component of the decomposition
            self.fomult = blocks.multiply_cc(1)
            self.trellis = trellis.viterbi_combined_cb(fsm, int(data_rate), -1, -1, int(N), constellation, trellis.TRELLIS_EUCLIDEAN) #the actual Viterbi decoder

        else:
        #this is probably not optimal and someone who knows what they're doing should correct me
            self.datafiltertaps = filter.firdes.root_raised_cosine(10, #gain
                                                      self._samplerate*16, #sample rate
                                                      self._bits_per_sec, #symbol rate
                                                      0.4, #alpha, same as BT?
                                                      50*16) #no. of taps

            sensitivity = (math.pi / 2) / self._samples_per_symbol
            self.demod = analog.quadrature_demod_cf(sensitivity) #param is gain

            self.clockrec = digital.pfb_clock_sync_ccf(self._samples_per_symbol,
                                                       0.04,
                                                       self.datafiltertaps, 16, 0, 1.15)
            self.tcslicer = digital.digital.binary_slicer_fb()
            self.slicer = digital.binary_slicer_fb()

        self.diff = digital.diff_decoder_bb(2)
        self.invert = ais.invert() #NRZI signal diff decoded and inverted should give original signal

        self.connect(self, self.gmsk_sync)

        if(options[ "viterbi" ] is False):
            self.connect(self.gmsk_sync, self.clockrec, self.demod, self.slicer, self.diff, self.invert, self)

        else:
            self.connect(self.gmsk_sync, self.costas, self.resample, self.clockrec)
            self.connect(self.clockrec, (self.fomult, 0))
            self.connect(self.fo, (self.fomult, 1))
            self.connect(self.fomult, self.mf0)
            self.connect(self.fomult, self.mf1)
            self.connect(self.mf0, (self.streams2stream, 0))
            self.connect(self.mf1, (self.streams2stream, 1))
            self.connect(self.streams2stream, self.trellis, self.diff, self.invert, self)
