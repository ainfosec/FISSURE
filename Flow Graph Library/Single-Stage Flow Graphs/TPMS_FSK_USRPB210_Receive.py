#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Tpms Fsk Usrpb210 Receive
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import analog
from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import math
import time
import tpms_poore


class TPMS_FSK_USRPB210_Receive(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Tpms Fsk Usrpb210 Receive")

        ##################################################
        # Variables
        ##################################################
        self.threshold = threshold = 0.5
        self.serial = serial = "False"
        self.sample_rate = sample_rate = 1e6
        self.rx_usrp_gain = rx_usrp_gain = 70
        self.rx_usrp_frequency = rx_usrp_frequency = 315e6
        self.rx_usrp_channel = rx_usrp_channel = "A:A"
        self.rx_usrp_antenna = rx_usrp_antenna = "TX/RX"
        self.notes = notes = "Decodes TPMS signals (only one format) and prints the output."

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_source_0 = uhd.usrp_source(
        	",".join((serial, "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0.set_subdev_spec(rx_usrp_channel, 0)
        self.uhd_usrp_source_0.set_samp_rate(sample_rate)
        self.uhd_usrp_source_0.set_center_freq(rx_usrp_frequency, 0)
        self.uhd_usrp_source_0.set_gain(rx_usrp_gain, 0)
        self.uhd_usrp_source_0.set_antenna(rx_usrp_antenna, 0)
        self.uhd_usrp_source_0.set_auto_dc_offset(True, 0)
        self.uhd_usrp_source_0.set_auto_iq_balance(True, 0)
        self.tpms_poore_decoder_0 = tpms_poore.decoder()
        self.fir_filter_xxx_1_0 = filter.fir_filter_fff(1, (50*[0.02]))
        self.fir_filter_xxx_1_0.declare_sample_delay(0)
        self.fir_filter_xxx_0 = filter.fir_filter_fff(1, (4*[0.25]))
        self.fir_filter_xxx_0.declare_sample_delay(0)
        self.blocks_threshold_ff_0_0 = blocks.threshold_ff(threshold, threshold, 0)
        self.blocks_threshold_ff_0 = blocks.threshold_ff(-4, -4, 0)
        self.blocks_message_debug_0 = blocks.message_debug()
        self.blocks_keep_one_in_n_0 = blocks.keep_one_in_n(gr.sizeof_float*1, 20)
        self.blocks_float_to_short_1 = blocks.float_to_short(1, 1)
        self.blocks_delay_1 = blocks.delay(gr.sizeof_gr_complex*1, 50)
        self.blocks_complex_to_mag_squared_0_0 = blocks.complex_to_mag_squared(1)
        self.blocks_burst_tagger_1 = blocks.burst_tagger(gr.sizeof_gr_complex)
        self.blocks_burst_tagger_1.set_true_tag('burst',True)
        self.blocks_burst_tagger_1.set_false_tag('burst',False)

        self.analog_quadrature_demod_cf_0 = analog.quadrature_demod_cf(sample_rate/(2*math.pi*80000/8.0))
        self.analog_agc_xx_0 = analog.agc_cc(.05, 1.0, 0)
        self.analog_agc_xx_0.set_max_gain(20)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.tpms_poore_decoder_0, 'out'), (self.blocks_message_debug_0, 'print'))
        self.connect((self.analog_agc_xx_0, 0), (self.blocks_delay_1, 0))
        self.connect((self.analog_quadrature_demod_cf_0, 0), (self.fir_filter_xxx_0, 0))
        self.connect((self.blocks_burst_tagger_1, 0), (self.analog_quadrature_demod_cf_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0_0, 0), (self.fir_filter_xxx_1_0, 0))
        self.connect((self.blocks_delay_1, 0), (self.blocks_burst_tagger_1, 0))
        self.connect((self.blocks_float_to_short_1, 0), (self.blocks_burst_tagger_1, 1))
        self.connect((self.blocks_keep_one_in_n_0, 0), (self.tpms_poore_decoder_0, 0))
        self.connect((self.blocks_threshold_ff_0, 0), (self.blocks_keep_one_in_n_0, 0))
        self.connect((self.blocks_threshold_ff_0_0, 0), (self.blocks_float_to_short_1, 0))
        self.connect((self.fir_filter_xxx_0, 0), (self.blocks_threshold_ff_0, 0))
        self.connect((self.fir_filter_xxx_1_0, 0), (self.blocks_threshold_ff_0_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.analog_agc_xx_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_complex_to_mag_squared_0_0, 0))

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold
        self.blocks_threshold_ff_0_0.set_hi(self.threshold)
        self.blocks_threshold_ff_0_0.set_lo(self.threshold)

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_source_0.set_samp_rate(self.sample_rate)
        self.analog_quadrature_demod_cf_0.set_gain(self.sample_rate/(2*math.pi*80000/8.0))

    def get_rx_usrp_gain(self):
        return self.rx_usrp_gain

    def set_rx_usrp_gain(self, rx_usrp_gain):
        self.rx_usrp_gain = rx_usrp_gain
        self.uhd_usrp_source_0.set_gain(self.rx_usrp_gain, 0)


    def get_rx_usrp_frequency(self):
        return self.rx_usrp_frequency

    def set_rx_usrp_frequency(self, rx_usrp_frequency):
        self.rx_usrp_frequency = rx_usrp_frequency
        self.uhd_usrp_source_0.set_center_freq(self.rx_usrp_frequency, 0)

    def get_rx_usrp_channel(self):
        return self.rx_usrp_channel

    def set_rx_usrp_channel(self, rx_usrp_channel):
        self.rx_usrp_channel = rx_usrp_channel

    def get_rx_usrp_antenna(self):
        return self.rx_usrp_antenna

    def set_rx_usrp_antenna(self, rx_usrp_antenna):
        self.rx_usrp_antenna = rx_usrp_antenna
        self.uhd_usrp_source_0.set_antenna(self.rx_usrp_antenna, 0)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes


def main(top_block_cls=TPMS_FSK_USRPB210_Receive, options=None):

    tb = top_block_cls()
    tb.start()
    try:
        raw_input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
