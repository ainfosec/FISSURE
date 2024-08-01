#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Zwave Fsk Usrpb205Mini Randomcolors
# GNU Radio version: 3.10.7.0

from gnuradio import blocks
from gnuradio import digital
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import gr, pdu
from gnuradio import uhd
import time
import gnuradio.zwave_poore as zwave_poore




class ZWAVE_FSK_USRPB205mini_RandomColors(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Zwave Fsk Usrpb205Mini Randomcolors", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_freq = tx_freq = 916e6
        self.string_variables = string_variables = ["home_id","source_node_id","frame_control","destination_node_id"]
        self.source_node_id = source_node_id = "01"
        self.serial = serial = "False"
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

        self.zwave_poore_message_generator_pdu_0_0_0_0_0_0_0_0 = zwave_poore.message_generator_pdu(repetition_interval, 3, home_id, source_node_id, frame_control, destination_node_id, "33", "0505000001000240039c0400")
        self.uhd_usrp_sink_1_0 = uhd.usrp_sink(
            ",".join((serial, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            'packet_len',
        )
        self.uhd_usrp_sink_1_0.set_samp_rate(1e6)
        self.uhd_usrp_sink_1_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_sink_1_0.set_center_freq(tx_freq, 0)
        self.uhd_usrp_sink_1_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_sink_1_0.set_gain(tx_gain, 0)
        self.pdu_pdu_to_tagged_stream_0 = pdu.pdu_to_tagged_stream(gr.types.byte_t, 'packet_len')
        self.digital_gfsk_mod_0 = digital.gfsk_mod(
            samples_per_symbol=10,
            sensitivity=0.25,
            bt=0.65,
            verbose=False,
            log=False,
            do_unpack=True)
        self.blocks_tag_gate_0 = blocks.tag_gate(gr.sizeof_gr_complex * 1, False)
        self.blocks_tag_gate_0.set_single_key("")
        self.blocks_stream_to_tagged_stream_0_0 = blocks.stream_to_tagged_stream(gr.sizeof_gr_complex, 1, (10*8*(26+msg_length+4)), "packet_len")
        self.blocks_delay_0_0 = blocks.delay(gr.sizeof_gr_complex*1, ((10*8*(26+msg_length+4))-24))


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.zwave_poore_message_generator_pdu_0_0_0_0_0_0_0_0, 'out'), (self.pdu_pdu_to_tagged_stream_0, 'pdus'))
        self.connect((self.blocks_delay_0_0, 0), (self.blocks_stream_to_tagged_stream_0_0, 0))
        self.connect((self.blocks_stream_to_tagged_stream_0_0, 0), (self.uhd_usrp_sink_1_0, 0))
        self.connect((self.blocks_tag_gate_0, 0), (self.blocks_delay_0_0, 0))
        self.connect((self.digital_gfsk_mod_0, 0), (self.blocks_tag_gate_0, 0))
        self.connect((self.pdu_pdu_to_tagged_stream_0, 0), (self.digital_gfsk_mod_0, 0))


    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.uhd_usrp_sink_1_0.set_gain(self.tx_gain, 0)

    def get_tx_freq(self):
        return self.tx_freq

    def set_tx_freq(self, tx_freq):
        self.tx_freq = tx_freq
        self.uhd_usrp_sink_1_0.set_center_freq(self.tx_freq, 0)

    def get_string_variables(self):
        return self.string_variables

    def set_string_variables(self, string_variables):
        self.string_variables = string_variables

    def get_source_node_id(self):
        return self.source_node_id

    def set_source_node_id(self, source_node_id):
        self.source_node_id = source_node_id

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

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
        self.blocks_delay_0_0.set_dly(int(((10*8*(26+self.msg_length+4))-24)))
        self.blocks_stream_to_tagged_stream_0_0.set_packet_len((10*8*(26+self.msg_length+4)))
        self.blocks_stream_to_tagged_stream_0_0.set_packet_len_pmt((10*8*(26+self.msg_length+4)))

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




def main(top_block_cls=ZWAVE_FSK_USRPB205mini_RandomColors, options=None):
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
