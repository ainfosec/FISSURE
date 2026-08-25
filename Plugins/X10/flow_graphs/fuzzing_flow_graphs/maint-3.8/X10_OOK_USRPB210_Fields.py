#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: X10 Ook Usrpb210 Fields
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
import X10
import fuzzer


class X10_OOK_USRPB210_Fields(gr.top_block):

    def __init__(self, fuzzing_data="0", fuzzing_fields="['Address Code']", fuzzing_interval="5", fuzzing_max="['65535']", fuzzing_min="['0']", fuzzing_packet_type="Default", fuzzing_protocol="X10", fuzzing_seed="0", fuzzing_type="['Random']", packet_types_fields="{}", sample_rate="1000000", serial="False", transmit_interval="4", tx_frequency="310.8e6", tx_usrp_channel="A:A", tx_usrp_gain="70"):
        gr.top_block.__init__(self, "X10 Ook Usrpb210 Fields")

        ##################################################
        # Parameters
        ##################################################
        self.fuzzing_data = fuzzing_data
        self.fuzzing_fields = fuzzing_fields
        self.fuzzing_interval = fuzzing_interval
        self.fuzzing_max = fuzzing_max
        self.fuzzing_min = fuzzing_min
        self.fuzzing_packet_type = fuzzing_packet_type
        self.fuzzing_protocol = fuzzing_protocol
        self.fuzzing_seed = fuzzing_seed
        self.fuzzing_type = fuzzing_type
        self.packet_types_fields = packet_types_fields
        self.sample_rate = sample_rate
        self.serial = serial
        self.transmit_interval = transmit_interval
        self.tx_frequency = tx_frequency
        self.tx_usrp_channel = tx_usrp_channel
        self.tx_usrp_gain = tx_usrp_gain

        ##################################################
        # Variables
        ##################################################
        self.data_code = data_code = "0x00"
        self.address_code = address_code = "0x60"

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
        self.uhd_usrp_sink_0.set_subdev_spec(tx_usrp_channel, 0)
        self.uhd_usrp_sink_0.set_center_freq(float(tx_frequency), 0)
        self.uhd_usrp_sink_0.set_gain(float(tx_usrp_gain), 0)
        self.uhd_usrp_sink_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_sink_0.set_samp_rate(float(sample_rate))
        self.uhd_usrp_sink_0.set_time_unknown_pps(uhd.time_spec())
        self.fuzzer_fuzzer_0_0 = fuzzer.fuzzer(fuzzing_seed,fuzzing_fields,fuzzing_type,fuzzing_min,fuzzing_max,fuzzing_data,fuzzing_interval,fuzzing_protocol,fuzzing_packet_type,packet_types_fields)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_cc(0.9)
        self.X10_msg_gen_fuzzer_0 = X10.msg_gen_fuzzer(float(sample_rate),str(address_code),str(data_code),float(transmit_interval)/2,float(transmit_interval))


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.fuzzer_fuzzer_0_0, 'packet_out'), (self.X10_msg_gen_fuzzer_0, 'fuzzer_in'))
        self.connect((self.X10_msg_gen_fuzzer_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.X10_msg_gen_fuzzer_0, 0))


    def get_fuzzing_data(self):
        return self.fuzzing_data

    def set_fuzzing_data(self, fuzzing_data):
        self.fuzzing_data = fuzzing_data

    def get_fuzzing_fields(self):
        return self.fuzzing_fields

    def set_fuzzing_fields(self, fuzzing_fields):
        self.fuzzing_fields = fuzzing_fields

    def get_fuzzing_interval(self):
        return self.fuzzing_interval

    def set_fuzzing_interval(self, fuzzing_interval):
        self.fuzzing_interval = fuzzing_interval

    def get_fuzzing_max(self):
        return self.fuzzing_max

    def set_fuzzing_max(self, fuzzing_max):
        self.fuzzing_max = fuzzing_max

    def get_fuzzing_min(self):
        return self.fuzzing_min

    def set_fuzzing_min(self, fuzzing_min):
        self.fuzzing_min = fuzzing_min

    def get_fuzzing_packet_type(self):
        return self.fuzzing_packet_type

    def set_fuzzing_packet_type(self, fuzzing_packet_type):
        self.fuzzing_packet_type = fuzzing_packet_type

    def get_fuzzing_protocol(self):
        return self.fuzzing_protocol

    def set_fuzzing_protocol(self, fuzzing_protocol):
        self.fuzzing_protocol = fuzzing_protocol

    def get_fuzzing_seed(self):
        return self.fuzzing_seed

    def set_fuzzing_seed(self, fuzzing_seed):
        self.fuzzing_seed = fuzzing_seed

    def get_fuzzing_type(self):
        return self.fuzzing_type

    def set_fuzzing_type(self, fuzzing_type):
        self.fuzzing_type = fuzzing_type

    def get_packet_types_fields(self):
        return self.packet_types_fields

    def set_packet_types_fields(self, packet_types_fields):
        self.packet_types_fields = packet_types_fields

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.X10_msg_gen_fuzzer_0.set_sample_rate(float(self.sample_rate))
        self.uhd_usrp_sink_0.set_samp_rate(float(self.sample_rate))

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_transmit_interval(self):
        return self.transmit_interval

    def set_transmit_interval(self, transmit_interval):
        self.transmit_interval = transmit_interval
        self.X10_msg_gen_fuzzer_0.set_press_duration(float(self.transmit_interval)/2)
        self.X10_msg_gen_fuzzer_0.set_press_repetition_interval(float(self.transmit_interval))

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.uhd_usrp_sink_0.set_center_freq(float(self.tx_frequency), 0)

    def get_tx_usrp_channel(self):
        return self.tx_usrp_channel

    def set_tx_usrp_channel(self, tx_usrp_channel):
        self.tx_usrp_channel = tx_usrp_channel

    def get_tx_usrp_gain(self):
        return self.tx_usrp_gain

    def set_tx_usrp_gain(self, tx_usrp_gain):
        self.tx_usrp_gain = tx_usrp_gain
        self.uhd_usrp_sink_0.set_gain(float(self.tx_usrp_gain), 0)

    def get_data_code(self):
        return self.data_code

    def set_data_code(self, data_code):
        self.data_code = data_code
        self.X10_msg_gen_fuzzer_0.set_data_code(str(self.data_code))

    def get_address_code(self):
        return self.address_code

    def set_address_code(self, address_code):
        self.address_code = address_code
        self.X10_msg_gen_fuzzer_0.set_address_code(str(self.address_code))




def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--fuzzing-data", dest="fuzzing_data", type=str, default="0",
        help="Set fuzzing_data [default=%(default)r]")
    parser.add_argument(
        "--fuzzing-fields", dest="fuzzing_fields", type=str, default="['Address Code']",
        help="Set fuzzing_fields [default=%(default)r]")
    parser.add_argument(
        "--fuzzing-interval", dest="fuzzing_interval", type=str, default="5",
        help="Set fuzzing_interval [default=%(default)r]")
    parser.add_argument(
        "--fuzzing-max", dest="fuzzing_max", type=str, default="['65535']",
        help="Set fuzzing_max [default=%(default)r]")
    parser.add_argument(
        "--fuzzing-min", dest="fuzzing_min", type=str, default="['0']",
        help="Set fuzzing_min [default=%(default)r]")
    parser.add_argument(
        "--fuzzing-packet-type", dest="fuzzing_packet_type", type=str, default="Default",
        help="Set fuzzing_packet_type [default=%(default)r]")
    parser.add_argument(
        "--fuzzing-protocol", dest="fuzzing_protocol", type=str, default="X10",
        help="Set fuzzing_protocol [default=%(default)r]")
    parser.add_argument(
        "--fuzzing-seed", dest="fuzzing_seed", type=str, default="0",
        help="Set fuzzing_seed [default=%(default)r]")
    parser.add_argument(
        "--fuzzing-type", dest="fuzzing_type", type=str, default="['Random']",
        help="Set fuzzing_type [default=%(default)r]")
    parser.add_argument(
        "--packet-types-fields", dest="packet_types_fields", type=str, default="{}",
        help="Set packet_types_fields [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default="1000000",
        help="Set sample_rate [default=%(default)r]")
    parser.add_argument(
        "--serial", dest="serial", type=str, default="False",
        help="Set serial [default=%(default)r]")
    parser.add_argument(
        "--transmit-interval", dest="transmit_interval", type=str, default="4",
        help="Set transmit_interval [default=%(default)r]")
    parser.add_argument(
        "--tx-frequency", dest="tx_frequency", type=str, default="310.8e6",
        help="Set tx_frequency [default=%(default)r]")
    parser.add_argument(
        "--tx-usrp-channel", dest="tx_usrp_channel", type=str, default="A:A",
        help="Set tx_usrp_channel [default=%(default)r]")
    parser.add_argument(
        "--tx-usrp-gain", dest="tx_usrp_gain", type=str, default="70",
        help="Set tx_usrp_gain [default=%(default)r]")
    return parser


def main(top_block_cls=X10_OOK_USRPB210_Fields, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(fuzzing_data=options.fuzzing_data, fuzzing_fields=options.fuzzing_fields, fuzzing_interval=options.fuzzing_interval, fuzzing_max=options.fuzzing_max, fuzzing_min=options.fuzzing_min, fuzzing_packet_type=options.fuzzing_packet_type, fuzzing_protocol=options.fuzzing_protocol, fuzzing_seed=options.fuzzing_seed, fuzzing_type=options.fuzzing_type, packet_types_fields=options.packet_types_fields, sample_rate=options.sample_rate, serial=options.serial, transmit_interval=options.transmit_interval, tx_frequency=options.tx_frequency, tx_usrp_channel=options.tx_usrp_channel, tx_usrp_gain=options.tx_usrp_gain)

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
