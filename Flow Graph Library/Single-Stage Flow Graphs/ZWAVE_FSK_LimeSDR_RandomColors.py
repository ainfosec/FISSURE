#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Zwave Fsk Limesdr Randomcolors
# GNU Radio version: 3.8.1.0

from gnuradio import blocks
from gnuradio import digital
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import limesdr
import zwave_poore

class ZWAVE_FSK_LimeSDR_RandomColors(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Zwave Fsk Limesdr Randomcolors")

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 916e6
        self.tx_channel = tx_channel = 0
        self.string_variables = string_variables = ["home_id","source_node_id","frame_control","destination_node_id"]
        self.source_node_id = source_node_id = "01"
        self.samp_rate = samp_rate = 1e6
        self.repetition_interval = repetition_interval = .15
        self.notes = notes = "Randomly generates a new RGB value for each message. Tested against a Monoprice Z-Wave Plus RGB Smart Bulb."
        self.msg_length = msg_length = 24
        self.home_id = home_id = "fa1c0b48"
        self.frame_control = frame_control = "4108"
        self.destination_node_id = destination_node_id = "02"

        ##################################################
        # Blocks
        ##################################################
        self.zwave_poore_message_generator_pdu_0_0_0_0_0_0_0_0 = zwave_poore.message_generator_pdu(repetition_interval,3,home_id,source_node_id,frame_control,destination_node_id,"33","0505000001000240039c0400")
        self.limesdr_sink_0 = limesdr.sink('', 0, '', 'packet_len')


        self.limesdr_sink_0.set_sample_rate(samp_rate)


        self.limesdr_sink_0.set_center_freq(tx_frequency, 0)

        self.limesdr_sink_0.set_bandwidth(5e6, 0)




        self.limesdr_sink_0.set_gain(int(tx_gain), 0)


        self.limesdr_sink_0.set_antenna(255, 0)


        self.limesdr_sink_0.calibrate(5e6, 0)
        self.digital_gfsk_mod_0 = digital.gfsk_mod(
            samples_per_symbol=10,
            sensitivity=0.25,
            bt=0.65,
            verbose=False,
            log=False)
        self.blocks_tag_gate_0 = blocks.tag_gate(gr.sizeof_gr_complex * 1, False)
        self.blocks_tag_gate_0.set_single_key("")
        self.blocks_stream_to_tagged_stream_0_0 = blocks.stream_to_tagged_stream(gr.sizeof_gr_complex, 1, 10*8*(26+msg_length+4), "packet_len")
        self.blocks_pdu_to_tagged_stream_0 = blocks.pdu_to_tagged_stream(blocks.byte_t, 'packet_len')
        self.blocks_delay_0_0 = blocks.delay(gr.sizeof_gr_complex*1, (10*8*(26+msg_length+4))-24)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.zwave_poore_message_generator_pdu_0_0_0_0_0_0_0_0, 'out'), (self.blocks_pdu_to_tagged_stream_0, 'pdus'))
        self.connect((self.blocks_delay_0_0, 0), (self.blocks_stream_to_tagged_stream_0_0, 0))
        self.connect((self.blocks_pdu_to_tagged_stream_0, 0), (self.digital_gfsk_mod_0, 0))
        self.connect((self.blocks_stream_to_tagged_stream_0_0, 0), (self.limesdr_sink_0, 0))
        self.connect((self.blocks_tag_gate_0, 0), (self.blocks_delay_0_0, 0))
        self.connect((self.digital_gfsk_mod_0, 0), (self.blocks_tag_gate_0, 0))

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.limesdr_sink_0.set_gain(int(self.tx_gain), 0)
        self.limesdr_sink_0.set_gain(int(self.tx_gain), 1)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.limesdr_sink_0.set_center_freq(self.tx_frequency, 0)

    def get_tx_channel(self):
        return self.tx_channel

    def set_tx_channel(self, tx_channel):
        self.tx_channel = tx_channel

    def get_string_variables(self):
        return self.string_variables

    def set_string_variables(self, string_variables):
        self.string_variables = string_variables

    def get_source_node_id(self):
        return self.source_node_id

    def set_source_node_id(self, source_node_id):
        self.source_node_id = source_node_id

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate

    def get_repetition_interval(self):
        return self.repetition_interval

    def set_repetition_interval(self, repetition_interval):
        self.repetition_interval = repetition_interval

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_msg_length(self):
        return self.msg_length

    def set_msg_length(self, msg_length):
        self.msg_length = msg_length
        self.blocks_delay_0_0.set_dly((10*8*(26+self.msg_length+4))-24)
        self.blocks_stream_to_tagged_stream_0_0.set_packet_len(10*8*(26+self.msg_length+4))
        self.blocks_stream_to_tagged_stream_0_0.set_packet_len_pmt(10*8*(26+self.msg_length+4))

    def get_home_id(self):
        return self.home_id

    def set_home_id(self, home_id):
        self.home_id = home_id

    def get_frame_control(self):
        return self.frame_control

    def set_frame_control(self, frame_control):
        self.frame_control = frame_control

    def get_destination_node_id(self):
        return self.destination_node_id

    def set_destination_node_id(self, destination_node_id):
        self.destination_node_id = destination_node_id



def main(top_block_cls=ZWAVE_FSK_LimeSDR_RandomColors, options=None):
    tb = top_block_cls()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()
    try:
        input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
