#!/usr/bin/env python3
"""Headless IQ recorder for a bladeRF 2.0 using GNU Radio's Soapy block."""

from gnuradio import blocks
from gnuradio import gr
from gnuradio import soapy


class iq_recorder_bladerf2(gr.top_block):
    """Record a finite number of complex-float samples from a bladeRF 2.0."""

    def __init__(
        self,
        file_length="100000",
        filepath="",
        ip_address="",
        rx_antenna="",
        rx_channel="",
        rx_frequency="433.32",
        rx_gain="50",
        sample_rate="1",
        serial="0",
    ):
        super().__init__("IQ Recorder bladeRF 2.0", catch_exceptions=True)

        self.file_length = int(file_length)
        self.filepath = str(filepath)
        self.ip_address = str(ip_address)
        self.rx_antenna = str(rx_antenna)
        self.rx_channel = str(rx_channel)
        self.rx_frequency = float(rx_frequency)
        self.rx_gain = float(rx_gain)
        self.sample_rate = float(sample_rate)
        self.serial = str(serial)

        device = "driver=bladerf"
        device_args = "bladerf=" + self.serial
        stream_args = ""
        tune_args = [""]
        settings = [""]

        self.source = soapy.source(
            device,
            "fc32",
            1,
            device_args,
            stream_args,
            tune_args,
            settings,
        )
        self.source.set_sample_rate(0, self.sample_rate * 1e6)
        self.source.set_bandwidth(0, 0.0)
        self.source.set_frequency(0, self.rx_frequency * 1e6)
        self.source.set_frequency_correction(0, 0)
        self.source.set_gain(0, min(max(self.rx_gain, -1.0), 60.0))

        self.skiphead = blocks.skiphead(gr.sizeof_gr_complex, 200000)
        self.head = blocks.head(gr.sizeof_gr_complex, self.file_length)
        self.file_sink = blocks.file_sink(
            gr.sizeof_gr_complex,
            self.filepath,
            False,
        )
        self.file_sink.set_unbuffered(False)

        self.connect((self.source, 0), (self.skiphead, 0))
        self.connect((self.skiphead, 0), (self.head, 0))
        self.connect((self.head, 0), (self.file_sink, 0))
