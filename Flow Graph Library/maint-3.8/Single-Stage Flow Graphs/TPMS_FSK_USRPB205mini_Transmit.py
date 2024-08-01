#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Tpms Fsk Usrpb205Mini Transmit
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
from gnuradio import uhd
import time
import tpms_poore

class TPMS_FSK_USRPB205mini_Transmit(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Tpms Fsk Usrpb205Mini Transmit")

        ##################################################
        # Variables
        ##################################################
        self.unknown2 = unknown2 = "0"
        self.unknown1 = unknown1 = "0"
        self.tx_gain = tx_gain = 40
        self.tx_freq = tx_freq = 314.96e6
        self.tire_temperature_c = tire_temperature_c = 20
        self.tire_pressure_psi = tire_pressure_psi = 5
        self.string_variables = string_variables = ["sensor_id","battery_status","counter","unknown1","unknown2","self_test"]
        self.serial = serial = "False"
        self.sensor_id = sensor_id = "528A510"
        self.self_test = self_test = "0"
        self.samp_rate = samp_rate = 1e6
        self.repetition_interval = repetition_interval = 1
        self.notes = notes = "Transmits TPMS signals periodically."
        self.counter = counter = "00"
        self.configuration = configuration = 1
        self.battery_status = battery_status = "0"

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_1_0 = uhd.usrp_sink(
            ",".join((serial, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            'packet_len',
        )
        self.uhd_usrp_sink_1_0.set_center_freq(tx_freq, 0)
        self.uhd_usrp_sink_1_0.set_gain(tx_gain, 0)
        self.uhd_usrp_sink_1_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_sink_1_0.set_samp_rate(1e6)
        self.uhd_usrp_sink_1_0.set_time_unknown_pps(uhd.time_spec())
        self.tpms_poore_message_generator_pdu_0 = tpms_poore.message_generator_pdu(repetition_interval,configuration,sensor_id,battery_status,counter,unknown1,unknown2,self_test,tire_pressure_psi,tire_temperature_c)
        self.digital_gfsk_mod_0 = digital.gfsk_mod(
            samples_per_symbol=100,
            sensitivity=0.25,
            bt=0.65,
            verbose=False,
            log=False)
        self.blocks_tag_gate_0 = blocks.tag_gate(gr.sizeof_gr_complex * 1, False)
        self.blocks_tag_gate_0.set_single_key("")
        self.blocks_stream_to_tagged_stream_0 = blocks.stream_to_tagged_stream(gr.sizeof_gr_complex, 1, 100*8*20, "packet_len")
        self.blocks_pdu_to_tagged_stream_0 = blocks.pdu_to_tagged_stream(blocks.byte_t, 'packet_len')
        self.blocks_delay_0 = blocks.delay(gr.sizeof_gr_complex*1, 15800)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.tpms_poore_message_generator_pdu_0, 'out'), (self.blocks_pdu_to_tagged_stream_0, 'pdus'))
        self.connect((self.blocks_delay_0, 0), (self.blocks_stream_to_tagged_stream_0, 0))
        self.connect((self.blocks_pdu_to_tagged_stream_0, 0), (self.digital_gfsk_mod_0, 0))
        self.connect((self.blocks_stream_to_tagged_stream_0, 0), (self.uhd_usrp_sink_1_0, 0))
        self.connect((self.blocks_tag_gate_0, 0), (self.blocks_delay_0, 0))
        self.connect((self.digital_gfsk_mod_0, 0), (self.blocks_tag_gate_0, 0))

    def get_unknown2(self):
        return self.unknown2

    def set_unknown2(self, unknown2):
        self.unknown2 = unknown2

    def get_unknown1(self):
        return self.unknown1

    def set_unknown1(self, unknown1):
        self.unknown1 = unknown1

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

    def get_tire_temperature_c(self):
        return self.tire_temperature_c

    def set_tire_temperature_c(self, tire_temperature_c):
        self.tire_temperature_c = tire_temperature_c

    def get_tire_pressure_psi(self):
        return self.tire_pressure_psi

    def set_tire_pressure_psi(self, tire_pressure_psi):
        self.tire_pressure_psi = tire_pressure_psi

    def get_string_variables(self):
        return self.string_variables

    def set_string_variables(self, string_variables):
        self.string_variables = string_variables

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sensor_id(self):
        return self.sensor_id

    def set_sensor_id(self, sensor_id):
        self.sensor_id = sensor_id

    def get_self_test(self):
        return self.self_test

    def set_self_test(self, self_test):
        self.self_test = self_test

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

    def get_counter(self):
        return self.counter

    def set_counter(self, counter):
        self.counter = counter

    def get_configuration(self):
        return self.configuration

    def set_configuration(self, configuration):
        self.configuration = configuration

    def get_battery_status(self):
        return self.battery_status

    def set_battery_status(self, battery_status):
        self.battery_status = battery_status



def main(top_block_cls=TPMS_FSK_USRPB205mini_Transmit, options=None):
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
