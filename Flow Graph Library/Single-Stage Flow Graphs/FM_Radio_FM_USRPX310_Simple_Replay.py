#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Fm Radio Fm Usrpx310 Simple Replay
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
import time


class FM_Radio_FM_USRPX310_Simple_Replay(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Fm Radio Fm Usrpx310 Simple Replay")

        ##################################################
        # Variables
        ##################################################
        self.tx_usrp_gain = tx_usrp_gain = 0
        self.tx_usrp_channel = tx_usrp_channel = "B:0"
        self.tx_usrp_antenna = tx_usrp_antenna = "TX/RX"
        self.tx_frequency = tx_frequency = 108e6
        self.sample_rate = sample_rate = 2e6
        self.rx_usrp_gain = rx_usrp_gain = 20
        self.rx_usrp_channel = rx_usrp_channel = "B:0"
        self.rx_usrp_antenna = rx_usrp_antenna = "RX2"
        self.rx_frequency = rx_frequency = 102.5e6
        self.notes = notes = "Relays filtered FM signals to another frequency."
        self.ip_address = ip_address = "192.168.40.2"
        self.frequency_offset = frequency_offset = 0.3e6
        self.audio_gain = audio_gain = 1

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_source_0 = uhd.usrp_source(
        	",".join(("addr=" + ip_address, "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0.set_subdev_spec(rx_usrp_channel, 0)
        self.uhd_usrp_source_0.set_samp_rate(sample_rate)
        self.uhd_usrp_source_0.set_center_freq(rx_frequency+frequency_offset, 0)
        self.uhd_usrp_source_0.set_gain(rx_usrp_gain, 0)
        self.uhd_usrp_source_0.set_antenna(rx_usrp_antenna, 0)
        self.uhd_usrp_source_0.set_auto_dc_offset(True, 0)
        self.uhd_usrp_source_0.set_auto_iq_balance(True, 0)
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
        	",".join(("addr=" + ip_address, "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_sink_0.set_subdev_spec(tx_usrp_channel, 0)
        self.uhd_usrp_sink_0.set_samp_rate(sample_rate)
        self.uhd_usrp_sink_0.set_center_freq(tx_frequency, 0)
        self.uhd_usrp_sink_0.set_gain(tx_usrp_gain, 0)
        self.uhd_usrp_sink_0.set_antenna(tx_usrp_antenna, 0)
        self.rational_resampler_xxx_0 = filter.rational_resampler_ccc(
                interpolation=12,
                decimation=5,
                taps=None,
                fractional_bw=None,
        )
        self.low_pass_filter_0 = filter.fir_filter_ccf(10, firdes.low_pass(
        	1, sample_rate, 75e3, 25e3, firdes.WIN_HAMMING, 6.76))
        self.fractional_resampler_xx_0 = filter.fractional_resampler_ff(0, 48000/sample_rate)
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vff((audio_gain, ))
        self.analog_wfm_tx_0 = analog.wfm_tx(
        	audio_rate=480000,
        	quad_rate=480000,
        	tau=75e-6,
        	max_dev=75e3,
        	fh=-1.0,
        )
        self.analog_wfm_rcv_0 = analog.wfm_rcv(
        	quad_rate=480e3,
        	audio_decimation=10,
        )
        self.analog_sig_source_x_0 = analog.sig_source_c(sample_rate, analog.GR_COS_WAVE, frequency_offset, 1, 0)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_sig_source_x_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.analog_wfm_rcv_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.analog_wfm_tx_0, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.fractional_resampler_xx_0, 0))
        self.connect((self.blocks_multiply_xx_0, 0), (self.low_pass_filter_0, 0))
        self.connect((self.fractional_resampler_xx_0, 0), (self.analog_wfm_tx_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.rational_resampler_xxx_0, 0))
        self.connect((self.rational_resampler_xxx_0, 0), (self.analog_wfm_rcv_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_multiply_xx_0, 0))

    def get_tx_usrp_gain(self):
        return self.tx_usrp_gain

    def set_tx_usrp_gain(self, tx_usrp_gain):
        self.tx_usrp_gain = tx_usrp_gain
        self.uhd_usrp_sink_0.set_gain(self.tx_usrp_gain, 0)


    def get_tx_usrp_channel(self):
        return self.tx_usrp_channel

    def set_tx_usrp_channel(self, tx_usrp_channel):
        self.tx_usrp_channel = tx_usrp_channel

    def get_tx_usrp_antenna(self):
        return self.tx_usrp_antenna

    def set_tx_usrp_antenna(self, tx_usrp_antenna):
        self.tx_usrp_antenna = tx_usrp_antenna
        self.uhd_usrp_sink_0.set_antenna(self.tx_usrp_antenna, 0)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.uhd_usrp_sink_0.set_center_freq(self.tx_frequency, 0)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_source_0.set_samp_rate(self.sample_rate)
        self.uhd_usrp_sink_0.set_samp_rate(self.sample_rate)
        self.low_pass_filter_0.set_taps(firdes.low_pass(1, self.sample_rate, 75e3, 25e3, firdes.WIN_HAMMING, 6.76))
        self.fractional_resampler_xx_0.set_resamp_ratio(48000/self.sample_rate)
        self.analog_sig_source_x_0.set_sampling_freq(self.sample_rate)

    def get_rx_usrp_gain(self):
        return self.rx_usrp_gain

    def set_rx_usrp_gain(self, rx_usrp_gain):
        self.rx_usrp_gain = rx_usrp_gain
        self.uhd_usrp_source_0.set_gain(self.rx_usrp_gain, 0)


    def get_rx_usrp_channel(self):
        return self.rx_usrp_channel

    def set_rx_usrp_channel(self, rx_usrp_channel):
        self.rx_usrp_channel = rx_usrp_channel

    def get_rx_usrp_antenna(self):
        return self.rx_usrp_antenna

    def set_rx_usrp_antenna(self, rx_usrp_antenna):
        self.rx_usrp_antenna = rx_usrp_antenna
        self.uhd_usrp_source_0.set_antenna(self.rx_usrp_antenna, 0)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.uhd_usrp_source_0.set_center_freq(self.rx_frequency+self.frequency_offset, 0)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_frequency_offset(self):
        return self.frequency_offset

    def set_frequency_offset(self, frequency_offset):
        self.frequency_offset = frequency_offset
        self.uhd_usrp_source_0.set_center_freq(self.rx_frequency+self.frequency_offset, 0)
        self.analog_sig_source_x_0.set_frequency(self.frequency_offset)

    def get_audio_gain(self):
        return self.audio_gain

    def set_audio_gain(self, audio_gain):
        self.audio_gain = audio_gain
        self.blocks_multiply_const_vxx_0.set_k((self.audio_gain, ))


def main(top_block_cls=FM_Radio_FM_USRPX310_Simple_Replay, options=None):

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
