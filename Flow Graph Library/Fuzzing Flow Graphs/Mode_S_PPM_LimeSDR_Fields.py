#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Mode S Ppm Limesdr Fields
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import blocks
from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import adsb
import fuzzer
import limesdr


class Mode_S_PPM_LimeSDR_Fields(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Mode S Ppm Limesdr Fields")

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 915e6
        self.tx_channel = tx_channel = 0
        self.transmit_interval = transmit_interval = .1
        self.sample_rate = sample_rate = 2e6
        self.library_filepath = library_filepath = "~/FISSURE/YAML/library.yaml"
        self.fuzzing_type = fuzzing_type = "['Random']"
        self.fuzzing_seed = fuzzing_seed = "0"
        self.fuzzing_protocol = fuzzing_protocol = "Mode S"
        self.fuzzing_packet_type = fuzzing_packet_type = "ADS-B Airborne Position - Odd"
        self.fuzzing_min = fuzzing_min = "['0']"
        self.fuzzing_max = fuzzing_max = "['16777215']"
        self.fuzzing_interval = fuzzing_interval = "1"
        self.fuzzing_fields = fuzzing_fields = "['ICAO']"
        self.fuzzing_data = fuzzing_data = "0"

        ##################################################
        # Message Queues
        ##################################################
        adsb_decoder_0_msgq_out = blocks_message_source_0_msgq_in = gr.msg_queue(2)
        adsb_framer_0_msgq_out = adsb_decoder_0_msgq_in = gr.msg_queue(2)

        ##################################################
        # Blocks
        ##################################################
        self.limesdr_sink_0 = limesdr.sink('', int(tx_channel), '', '')
        self.limesdr_sink_0.set_sample_rate(sample_rate)
        self.limesdr_sink_0.set_center_freq(tx_frequency, 0)
        self.limesdr_sink_0.set_bandwidth(5e6,0)
        self.limesdr_sink_0.set_gain(int(tx_gain),0)
        self.limesdr_sink_0.set_antenna(255,0)
        self.limesdr_sink_0.calibrate(5e6, 0)

        self.fuzzer_packet_insert_0 = fuzzer.packet_insert((0, ), int(sample_rate*transmit_interval/8), 0)
        self.fuzzer_fuzzer_0_0 = fuzzer.fuzzer(fuzzing_seed,fuzzing_fields,fuzzing_type,fuzzing_min,fuzzing_max,fuzzing_data,fuzzing_interval,fuzzing_protocol,fuzzing_packet_type, library_filepath)
        self.digital_correlate_access_code_tag_xx_0 = digital.correlate_access_code_tag_bb('1010000101000000', 0, 'adsb_preamble')
        self.blocks_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(8)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_char*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vff((.3, ))
        self.blocks_message_source_0 = blocks.message_source(gr.sizeof_char*1, blocks_message_source_0_msgq_in)
        self.blocks_float_to_complex_0 = blocks.float_to_complex(1)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_char*1, '/dev/stdout', True)
        self.blocks_file_sink_0.set_unbuffered(True)
        self.blocks_char_to_float_0 = blocks.char_to_float(1, 1)
        self.adsb_framer_0 = adsb.framer(tx_msgq=adsb_framer_0_msgq_out)
        self.adsb_decoder_0 = adsb.decoder(rx_msgq=adsb_decoder_0_msgq_in,tx_msgq=adsb_decoder_0_msgq_out,output_type="csv",check_parity=True)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.fuzzer_fuzzer_0_0, 'packet_out'), (self.fuzzer_packet_insert_0, 'packet_in'))
        self.connect((self.blocks_char_to_float_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_float_to_complex_0, 0), (self.limesdr_sink_0, 0))
        self.connect((self.blocks_message_source_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_float_to_complex_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.fuzzer_packet_insert_0, 0))
        self.connect((self.blocks_unpack_k_bits_bb_0, 0), (self.blocks_char_to_float_0, 0))
        self.connect((self.blocks_unpack_k_bits_bb_0, 0), (self.digital_correlate_access_code_tag_xx_0, 0))
        self.connect((self.digital_correlate_access_code_tag_xx_0, 0), (self.adsb_framer_0, 0))
        self.connect((self.fuzzer_packet_insert_0, 0), (self.blocks_unpack_k_bits_bb_0, 0))

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.limesdr_sink_0.set_gain(int(self.tx_gain),0)
        self.limesdr_sink_0.set_gain(int(self.tx_gain),1)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.limesdr_sink_0.set_center_freq(self.tx_frequency, 0)

    def get_tx_channel(self):
        return self.tx_channel

    def set_tx_channel(self, tx_channel):
        self.tx_channel = tx_channel

    def get_transmit_interval(self):
        return self.transmit_interval

    def set_transmit_interval(self, transmit_interval):
        self.transmit_interval = transmit_interval

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate

    def get_library_filepath(self):
        return self.library_filepath

    def set_library_filepath(self, library_filepath):
        self.library_filepath = library_filepath

    def get_fuzzing_type(self):
        return self.fuzzing_type

    def set_fuzzing_type(self, fuzzing_type):
        self.fuzzing_type = fuzzing_type
        self.fuzzer_fuzzer_0_0.set_fuzzing_type(self.fuzzing_type)

    def get_fuzzing_seed(self):
        return self.fuzzing_seed

    def set_fuzzing_seed(self, fuzzing_seed):
        self.fuzzing_seed = fuzzing_seed
        self.fuzzer_fuzzer_0_0.set_fuzzing_seed(self.fuzzing_seed)

    def get_fuzzing_protocol(self):
        return self.fuzzing_protocol

    def set_fuzzing_protocol(self, fuzzing_protocol):
        self.fuzzing_protocol = fuzzing_protocol
        self.fuzzer_fuzzer_0_0.set_fuzzing_protocol(self.fuzzing_protocol)

    def get_fuzzing_packet_type(self):
        return self.fuzzing_packet_type

    def set_fuzzing_packet_type(self, fuzzing_packet_type):
        self.fuzzing_packet_type = fuzzing_packet_type
        self.fuzzer_fuzzer_0_0.set_fuzzing_packet_type(self.fuzzing_packet_type)

    def get_fuzzing_min(self):
        return self.fuzzing_min

    def set_fuzzing_min(self, fuzzing_min):
        self.fuzzing_min = fuzzing_min
        self.fuzzer_fuzzer_0_0.set_fuzzing_min(self.fuzzing_min)

    def get_fuzzing_max(self):
        return self.fuzzing_max

    def set_fuzzing_max(self, fuzzing_max):
        self.fuzzing_max = fuzzing_max
        self.fuzzer_fuzzer_0_0.set_fuzzing_max(self.fuzzing_max)

    def get_fuzzing_interval(self):
        return self.fuzzing_interval

    def set_fuzzing_interval(self, fuzzing_interval):
        self.fuzzing_interval = fuzzing_interval
        self.fuzzer_fuzzer_0_0.set_fuzzing_interval(self.fuzzing_interval)

    def get_fuzzing_fields(self):
        return self.fuzzing_fields

    def set_fuzzing_fields(self, fuzzing_fields):
        self.fuzzing_fields = fuzzing_fields
        self.fuzzer_fuzzer_0_0.set_fuzzing_fields(self.fuzzing_fields)

    def get_fuzzing_data(self):
        return self.fuzzing_data

    def set_fuzzing_data(self, fuzzing_data):
        self.fuzzing_data = fuzzing_data
        self.fuzzer_fuzzer_0_0.set_fuzzing_data(self.fuzzing_data)


def main(top_block_cls=Mode_S_PPM_LimeSDR_Fields, options=None):

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
