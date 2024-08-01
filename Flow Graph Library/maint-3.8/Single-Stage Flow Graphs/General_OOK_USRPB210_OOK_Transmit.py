#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Not titled yet
# Author: user
# GNU Radio version: 3.8.5.0

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
import ainfosec


class General_OOK_USRPB210_OOK_Transmit(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Not titled yet")

        ##################################################
        # Variables
        ##################################################
        self.string_variables = string_variables = ["chip0_pattern","chip1_pattern","sequence"]
        self.serial = serial = "False"
        self.sequence = sequence = "10101011"
        self.sample_rate = sample_rate = 1e6
        self.repetition_interval_s = repetition_interval_s = 1
        self.number_of_bursts = number_of_bursts = 5
        self.notes = notes = "Generates custom on-off keying signals with repeating bursts at regular intervals."
        self.gain = gain = 70
        self.frequency = frequency = 310.4e6
        self.chip1_pattern = chip1_pattern = "1"
        self.chip1_duration_us = chip1_duration_us = 10
        self.chip0_pattern = chip0_pattern = "0"
        self.chip0_duration_us = chip0_duration_us = 10
        self.channel = channel = "A:A"
        self.burst_interval_us = burst_interval_us = 100
        self.antenna = antenna = "TX/RX"

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
            ",".join((serial, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            '',
        )
        self.uhd_usrp_sink_0.set_subdev_spec(channel, 0)
        self.uhd_usrp_sink_0.set_center_freq(float(frequency), 0)
        self.uhd_usrp_sink_0.set_gain(float(gain), 0)
        self.uhd_usrp_sink_0.set_antenna(antenna, 0)
        self.uhd_usrp_sink_0.set_samp_rate(float(sample_rate))
        self.uhd_usrp_sink_0.set_time_unknown_pps(uhd.time_spec())
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_cc(0.9)
        self.ainfosec_ook_generator_0 = ainfosec.ook_generator(str(chip0_pattern),str(chip1_pattern),float(burst_interval_us),float(sample_rate),float(chip0_duration_us),float(chip1_duration_us),int(number_of_bursts),str(sequence),float(repetition_interval_s))


        ##################################################
        # Connections
        ##################################################
        self.connect((self.ainfosec_ook_generator_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.ainfosec_ook_generator_0, 0))


    def get_string_variables(self):
        return self.string_variables

    def set_string_variables(self, string_variables):
        self.string_variables = string_variables

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sequence(self):
        return self.sequence

    def set_sequence(self, sequence):
        self.sequence = sequence
        self.ainfosec_ook_generator_0.set_sequence(str(self.sequence))

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.ainfosec_ook_generator_0.set_sample_rate(float(self.sample_rate))
        self.uhd_usrp_sink_0.set_samp_rate(float(self.sample_rate))

    def get_repetition_interval_s(self):
        return self.repetition_interval_s

    def set_repetition_interval_s(self, repetition_interval_s):
        self.repetition_interval_s = repetition_interval_s
        self.ainfosec_ook_generator_0.set_repetition_interval(float(self.repetition_interval_s))

    def get_number_of_bursts(self):
        return self.number_of_bursts

    def set_number_of_bursts(self, number_of_bursts):
        self.number_of_bursts = number_of_bursts
        self.ainfosec_ook_generator_0.set_number_of_bursts(int(self.number_of_bursts))

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain
        self.uhd_usrp_sink_0.set_gain(float(self.gain), 0)

    def get_frequency(self):
        return self.frequency

    def set_frequency(self, frequency):
        self.frequency = frequency
        self.uhd_usrp_sink_0.set_center_freq(float(self.frequency), 0)

    def get_chip1_pattern(self):
        return self.chip1_pattern

    def set_chip1_pattern(self, chip1_pattern):
        self.chip1_pattern = chip1_pattern
        self.ainfosec_ook_generator_0.set_chip1_pattern(str(self.chip1_pattern))

    def get_chip1_duration_us(self):
        return self.chip1_duration_us

    def set_chip1_duration_us(self, chip1_duration_us):
        self.chip1_duration_us = chip1_duration_us
        self.ainfosec_ook_generator_0.set_chip1_duration(float(self.chip1_duration_us))

    def get_chip0_pattern(self):
        return self.chip0_pattern

    def set_chip0_pattern(self, chip0_pattern):
        self.chip0_pattern = chip0_pattern
        self.ainfosec_ook_generator_0.set_chip0_pattern(str(self.chip0_pattern))

    def get_chip0_duration_us(self):
        return self.chip0_duration_us

    def set_chip0_duration_us(self, chip0_duration_us):
        self.chip0_duration_us = chip0_duration_us
        self.ainfosec_ook_generator_0.set_chip0_duration(float(self.chip0_duration_us))

    def get_channel(self):
        return self.channel

    def set_channel(self, channel):
        self.channel = channel

    def get_burst_interval_us(self):
        return self.burst_interval_us

    def set_burst_interval_us(self, burst_interval_us):
        self.burst_interval_us = burst_interval_us
        self.ainfosec_ook_generator_0.set_burst_interval(float(self.burst_interval_us))

    def get_antenna(self):
        return self.antenna

    def set_antenna(self, antenna):
        self.antenna = antenna
        self.uhd_usrp_sink_0.set_antenna(self.antenna, 0)





def main(top_block_cls=General_OOK_USRPB210_OOK_Transmit, options=None):
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
