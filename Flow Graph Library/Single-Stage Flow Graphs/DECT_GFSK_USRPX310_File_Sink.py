#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Dect Gfsk Usrpx310 File Sink
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import blocks
from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import time


class DECT_GFSK_USRPX310_File_Sink(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Dect Gfsk Usrpx310 File Sink")

        ##################################################
        # Variables
        ##################################################
        self.dect_symbol_rate = dect_symbol_rate = 1.152e6
        self.sample_rate = sample_rate = 3.456e6
        self.rx_usrp_gain = rx_usrp_gain = 20
        self.rx_frequency = rx_frequency = 1923.264e6
        self.recording_length = recording_length = 388*2
        self.payload_len = payload_len = 384
        self.notes = notes = "Records a DECT payload to a file."
        self.header_len = header_len = 16
        self.header_formatter = header_formatter = digital.packet_header_default(388,"packet_len","packet_num",1)
        self.filepath = filepath = "~/FISSURE/Attack Recordings/DECT_Data"
        self.dect_occupied_bandwidth = dect_occupied_bandwidth = dect_symbol_rate  * 1.03
        self.dect_channel_bandwidth = dect_channel_bandwidth = 1.728e6

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_source_0 = uhd.usrp_source(
        	",".join(('"addr="+ip_address', "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0.set_subdev_spec('rx_usrp_channel', 0)
        self.uhd_usrp_source_0.set_samp_rate(sample_rate)
        self.uhd_usrp_source_0.set_center_freq(rx_frequency, 0)
        self.uhd_usrp_source_0.set_gain(rx_usrp_gain, 0)
        self.uhd_usrp_source_0.set_antenna('rx_usrp_antenna', 0)
        self.uhd_usrp_source_0.set_auto_dc_offset(True, 0)
        self.uhd_usrp_source_0.set_auto_iq_balance(True, 0)
        self.digital_packet_headerparser_b_0 = digital.packet_headerparser_b(header_formatter.base())
        self.digital_header_payload_demux_0 = digital.header_payload_demux(
        	  388,
        	  1,
        	  0,
        	  "sandwich",
        	  "go",
        	  False,
        	  gr.sizeof_char,
        	  "rx_time",
                  int(sample_rate),
                  (),
                  0,
            )
        self.digital_gmsk_demod_0 = digital.gmsk_demod(
        	samples_per_symbol=int(sample_rate/dect_symbol_rate),
        	gain_mu=0.175,
        	mu=0.5,
        	omega_relative_limit=0.005,
        	freq_error=0.0,
        	verbose=False,
        	log=False,
        )
        self.digital_correlate_access_code_tag_xx_0 = digital.correlate_access_code_tag_bb('10101010101010101110100110001010', 0, "go")
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_char*1)
        self.blocks_null_sink_0 = blocks.null_sink(gr.sizeof_char*1)
        self.blocks_head_0_0 = blocks.head(gr.sizeof_char*1, recording_length)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_char*1, filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.digital_packet_headerparser_b_0, 'header_data'), (self.digital_header_payload_demux_0, 'header_data'))
        self.connect((self.blocks_head_0_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.digital_header_payload_demux_0, 1))
        self.connect((self.digital_correlate_access_code_tag_xx_0, 0), (self.digital_header_payload_demux_0, 0))
        self.connect((self.digital_gmsk_demod_0, 0), (self.digital_correlate_access_code_tag_xx_0, 0))
        self.connect((self.digital_header_payload_demux_0, 0), (self.blocks_head_0_0, 0))
        self.connect((self.digital_header_payload_demux_0, 1), (self.blocks_null_sink_0, 0))
        self.connect((self.digital_header_payload_demux_0, 0), (self.digital_packet_headerparser_b_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.digital_gmsk_demod_0, 0))

    def get_dect_symbol_rate(self):
        return self.dect_symbol_rate

    def set_dect_symbol_rate(self, dect_symbol_rate):
        self.dect_symbol_rate = dect_symbol_rate
        self.set_dect_occupied_bandwidth(self.dect_symbol_rate  * 1.03)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_source_0.set_samp_rate(self.sample_rate)

    def get_rx_usrp_gain(self):
        return self.rx_usrp_gain

    def set_rx_usrp_gain(self, rx_usrp_gain):
        self.rx_usrp_gain = rx_usrp_gain
        self.uhd_usrp_source_0.set_gain(self.rx_usrp_gain, 0)


    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.uhd_usrp_source_0.set_center_freq(self.rx_frequency, 0)

    def get_recording_length(self):
        return self.recording_length

    def set_recording_length(self, recording_length):
        self.recording_length = recording_length
        self.blocks_head_0_0.set_length(self.recording_length)

    def get_payload_len(self):
        return self.payload_len

    def set_payload_len(self, payload_len):
        self.payload_len = payload_len

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_header_len(self):
        return self.header_len

    def set_header_len(self, header_len):
        self.header_len = header_len

    def get_header_formatter(self):
        return self.header_formatter

    def set_header_formatter(self, header_formatter):
        self.header_formatter = header_formatter

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_sink_0.open(self.filepath)

    def get_dect_occupied_bandwidth(self):
        return self.dect_occupied_bandwidth

    def set_dect_occupied_bandwidth(self, dect_occupied_bandwidth):
        self.dect_occupied_bandwidth = dect_occupied_bandwidth

    def get_dect_channel_bandwidth(self):
        return self.dect_channel_bandwidth

    def set_dect_channel_bandwidth(self, dect_channel_bandwidth):
        self.dect_channel_bandwidth = dect_channel_bandwidth


def main(top_block_cls=DECT_GFSK_USRPX310_File_Sink, options=None):

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
