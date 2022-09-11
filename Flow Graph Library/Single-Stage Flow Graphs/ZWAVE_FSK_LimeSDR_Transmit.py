#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Zwave Fsk Limesdr Transmit
# GNU Radio version: 3.10.1.1

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
import gnuradio.limesdr as limesdr
import gnuradio.zwave_poore as zwave_poore




class ZWAVE_FSK_LimeSDR_Transmit(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Zwave Fsk Limesdr Transmit", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 916e6
        self.tx_channel = tx_channel = 0
        self.string_variables = string_variables = ["home_id","source_node_id","frame_control","destination_node_id","command_class","command"]
        self.source_node_id = source_node_id = "01"
        self.samp_rate = samp_rate = 1e6
        self.repetition_interval = repetition_interval = 1
        self.notes = notes = "Transmits a Z-Wave message (default is a red light). Tested against a Monoprice Z-Wave Plus RGB Smart Bulb."
        self.msg_length = msg_length = 24
        self.home_id = home_id = "fa1c0b48"
        self.frame_control = frame_control = "410d"
        self.destination_node_id = destination_node_id = "02"
        self.command_class = command_class = "33"
        self.command = command = "05050000010002ff03000400"

        ##################################################
        # Blocks
        ##################################################
        self.zwave_poore_message_generator_pdu_0_0_0_1 = zwave_poore.message_generator_pdu(repetition_interval, 1, home_id, source_node_id, frame_control, destination_node_id, command_class, command)
        self.pdu_pdu_to_tagged_stream_0 = pdu.pdu_to_tagged_stream(gr.types.byte_t, 'packet_len')
        self.limesdr_sink_0 = limesdr.sink('', int(tx_channel), '', 'packet_len')

        self.digital_gfsk_mod_0 = digital.gfsk_mod(
            samples_per_symbol=10,
            sensitivity=0.25,
            bt=0.65,
            verbose=False,
            log=False,
            do_unpack=True)
        self.blocks_tag_gate_0 = blocks.tag_gate(gr.sizeof_gr_complex * 1, False)
        self.blocks_tag_gate_0.set_single_key("")
        self.blocks_stream_to_tagged_stream_0_0 = blocks.stream_to_tagged_stream(gr.sizeof_gr_complex, 1, 10*8*(26+msg_length+4), "packet_len")
        self.blocks_delay_0_0 = blocks.delay(gr.sizeof_gr_complex*1, (10*8*(26+msg_length+4))-24)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.zwave_poore_message_generator_pdu_0_0_0_1, 'out'), (self.pdu_pdu_to_tagged_stream_0, 'pdus'))
        self.connect((self.blocks_delay_0_0, 0), (self.blocks_stream_to_tagged_stream_0_0, 0))
        self.connect((self.blocks_stream_to_tagged_stream_0_0, 0), (self.limesdr_sink_0, 0))
        self.connect((self.blocks_tag_gate_0, 0), (self.blocks_delay_0_0, 0))
        self.connect((self.digital_gfsk_mod_0, 0), (self.blocks_tag_gate_0, 0))
        self.connect((self.pdu_pdu_to_tagged_stream_0, 0), (self.digital_gfsk_mod_0, 0))


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

    def get_command_class(self):
        return self.command_class

    def set_command_class(self, command_class):
        self.command_class = command_class

    def get_command(self):
        return self.command

    def set_command(self, command):
        self.command = command




def main(top_block_cls=ZWAVE_FSK_LimeSDR_Transmit, options=None):
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
