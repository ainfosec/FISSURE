#!/usr/bin/env python
# vim: set ts=4 sw=4 tw=0 et pm=:

import iridium

import scipy.signal

import gnuradio.filter

from gnuradio import gr
from gnuradio import blocks

import sys
import math


class FlowGraph(gr.top_block):
    def __init__(self, center_frequency, sample_rate, decimation, filename, sample_format=None, threshold=7.0, burst_width=40e3, offline=False, max_queue_len=500,
            handle_multiple_frames_per_burst=False, raw_capture_filename=None, debug_id=None, max_bursts=0, verbose=False, file_info=None, samples_per_symbol=10):
        gr.top_block.__init__(self, "Top Block")
        self.handle_sigint = False
        self._center_frequency = center_frequency
        self._burst_width = burst_width
        self._input_sample_rate = sample_rate
        self._verbose = verbose
        self._threshold = threshold
        self._filename = filename
        self._offline = offline
        self._max_queue_len = max_queue_len
        self._handle_multiple_frames_per_burst = handle_multiple_frames_per_burst

        # Sample rate of the bursts exiting the burst downmix block
        self._burst_sample_rate = 25000 * samples_per_symbol
        assert (self._input_sample_rate / decimation) % self._burst_sample_rate == 0

        self._fft_size = 2**round(math.log(self._input_sample_rate / 1000, 2)) # FFT is approx. 1 ms long
        self._burst_pre_len = 2 * self._fft_size

        # Keep 16 ms of signal after the FFT loses track
        self._burst_post_len = int(self._input_sample_rate * 16e-3)

        # Just to keep the code below a bit more portable
        tb = self

        if decimation > 1:
            self._use_pfb = True

            # We will set up a filter bank with an odd number of outputs and
            # and an over sampling ratio to still get the desired decimation.

            # The goal is to reconstruct signals which (due to Doppler shift) end up
            # on the border of two channels.

            # For this to work the desired decimation must be even.
            if decimation % 2:
                raise RuntimeError("The desired decimation must be 1 or an even number")

            self._channels = decimation + 1
            self._pfb_over_sample_ratio = self._channels / (self._channels - 1.)
            pfb_output_sample_rate = int(round(float(self._input_sample_rate) / self._channels * self._pfb_over_sample_ratio))
            assert pfb_output_sample_rate == self._input_sample_rate / decimation
            assert pfb_output_sample_rate % self._burst_sample_rate == 0


            # The over sampled region of the FIR filter contains half of the signal width and
            # the transition region of the FIR filter.
            # The bandwidth is simply increased by the signal width.
            # A signal which has its center frequency directly on the border of
            # two channels will reconstruct correctly on both channels.
            self._fir_bw = (self._input_sample_rate / self._channels + self._burst_width) / 2

            # The remaining bandwidth inside the over sampled region is used to
            # contain the transition region of the filter.
            # It can be multiplied by two as it is allowed to continue into the
            # transition region of the neighboring channel.
            # Some details can be found here: https://youtu.be/6ngYp8W-AX0?t=2289
            self._fir_tw = (pfb_output_sample_rate / 2 - self._fir_bw) * 2

            # Real world data shows only a minor degradation in performance when
            # doubling the transition width.
            self._fir_tw *= 2

            # If the over sampling ratio is not large enough, there is not
            # enough room to construct a transition region.
            if self._fir_tw < 0:
                raise RuntimeError("PFB over sampling ratio not enough to create a working FIR filter")

            self._pfb_fir_filter = gnuradio.filter.firdes.low_pass_2(1, self._input_sample_rate, self._fir_bw, self._fir_tw, 60)

            # If the transition width approaches 0, the filter size goes up significantly.
            if len(self._pfb_fir_filter) > 300:
                print("Warning: The PFB FIR filter has an abnormal large number of taps:", len(self._pfb_fir_filter), file=sys.stderr)
                print("Consider reducing the decimation factor", file=sys.stderr)


            pfb_input_delay = (len(self._pfb_fir_filter) + 1) // 2 - self._channels / self._pfb_over_sample_ratio
            self._pfb_delay = pfb_input_delay / decimation
            self._channel_sample_rate = pfb_output_sample_rate
            if self._verbose:
                print("self._channels", self._channels, file=sys.stderr)
                print("len(self._pfb_fir_filter)", len(self._pfb_fir_filter), file=sys.stderr)
                print("self._pfb_over_sample_ratio", self._pfb_over_sample_ratio, file=sys.stderr)
                print("self._fir_bw", self._fir_bw, file=sys.stderr)
                print("self._fir_tw", self._fir_tw, file=sys.stderr)
                print("self._channel_sample_rate", self._channel_sample_rate, file=sys.stderr)
        else:
            self._use_pfb = False
            self._channel_sample_rate = self._input_sample_rate
            self._channels = 1

        # After 90 ms there needs to be a pause in the frame sturcture.
        # Let's make that the limit for a detected burst
        self._max_burst_len = int(self._channel_sample_rate * 0.09)

        if self._verbose:
            print("require %.1f dB" % self._threshold, file=sys.stderr)
            print("burst_width: %d Hz" % self._burst_width, file=sys.stderr)


        if self._filename.endswith(".conf"):
            import configparser
            config = configparser.ConfigParser()
            config.read(self._filename)
            items = config.items("osmosdr-source")
            d = {key: value for key, value in items}

            import osmosdr
            if 'device_args' in d:
                source = osmosdr.source(args=d['device_args'])
            else:
                source = osmosdr.source()

            source.set_time_now(osmosdr.time_spec_t.get_system_time())

            source.set_sample_rate(self._input_sample_rate)
            source.set_center_freq(self._center_frequency, 0)

            if 'gain' in d:
                gain = int(d['gain'])
                source.set_gain(gain, 0)
                print("(RF) Gain:", source.get_gain(0), '(Requested %d)' % gain, file=sys.stderr)

            for key, value in d.items():
                if key.endswith("_gain"):
                    gain_option_name = key.split('_')[0]
                    gain_value = int(value)

                    def match_gain(gain, gain_names):
                        for gain_name in gain_names:
                            if gain.lower() == gain_name.lower():
                                return gain_name
                        return None

                    gain_name = match_gain(gain_option_name, source.get_gain_names())

                    if gain_name is not None:
                        source.set_gain(gain_value, gain_name, 0)
                        print(gain_name, "Gain:", source.get_gain(gain_name, 0), '(Requested %d)' % gain_value, file=sys.stderr)
                    else:
                        print("WARNING: Gain", gain_option_name, "not supported by source!", file=sys.stderr)
                        print("Supported gains:", source.get_gain_names(), file=sys.stderr)

            if 'bandwidth' in d:
                self._bandwidth = int(d['bandwidth'])
            else:
                self._bandwidth = 0

            if 'antenna' in d:
                antenna = d['antenna']
                source.set_antenna(antenna, 0)
                print("Antenna:", source.get_antenna(0), '(Requested %s)' % antenna, file=sys.stderr)
            else:
                print("Warning: Setting antenna to", source.get_antenna(0), file=sys.stderr)

            #source.set_freq_corr($corr0, 0)
            #source.set_dc_offset_mode($dc_offset_mode0, 0)
            #source.set_iq_balance_mode($iq_balance_mode0, 0)
            #source.set_gain_mode($gain_mode0, 0)
            #source.set_antenna($ant0, 0)

        else:
            if sample_format == "rtl":
                converter = iridium.iuchar_to_complex()
                itemsize = gr.sizeof_char
                scale = 1
            elif sample_format == "hackrf":
                converter = blocks.interleaved_char_to_complex()
                itemsize = gr.sizeof_char
                scale = 1/128.
            elif sample_format == "sc16":
                converter = blocks.interleaved_short_to_complex()
                itemsize = gr.sizeof_short
                scale = 1/32768.
            elif sample_format == "float":
                converter = None
                itemsize = gr.sizeof_gr_complex
            else:
                raise RuntimeError("Unknown sample format for offline mode given")

            if self._filename == '/dev/stdin':
                file_source = blocks.file_descriptor_source(itemsize=itemsize, fd=0, repeat=False)
            else:
                file_source = blocks.file_source(itemsize=itemsize, filename=self._filename, repeat=False)

            if converter:
                multi = blocks.multiply_const_cc(scale)
                tb.connect(file_source, converter, multi)
                source = multi
            else:
                source = file_source


        self._fft_burst_tagger = iridium.fft_burst_tagger(center_frequency=self._center_frequency,
                                fft_size=self._fft_size,
                                sample_rate=self._input_sample_rate,
                                burst_pre_len=self._burst_pre_len, burst_post_len=self._burst_post_len,
                                burst_width=int(self._burst_width),
                                max_bursts=max_bursts,
                                threshold=self._threshold,
                                history_size=512,
                                offline=self._offline,
                                debug=self._verbose)

        # Initial filter to filter the detected bursts. Runs at burst_sample_rate. Used to decimate the signal.
        input_filter = gnuradio.filter.firdes.low_pass_2(1, self._channel_sample_rate, self._burst_width/2, self._burst_width, 40)
        #input_filter = gnuradio.filter.firdes.low_pass_2(1, self._channel_sample_rate, 42e3/2, 24e3, 40)
        #print len(input_filter)

        # Filter to find the start of the signal. Should be fairly narrow.
        start_finder_filter = gnuradio.filter.firdes.low_pass_2(1, self._burst_sample_rate, 5e3/2, 10e3/2, 60)
        #print len(start_finder_filter)

        self._iridium_qpsk_demod = iridium.iridium_qpsk_demod_cpp(self._channels)
        self._frame_sorter = iridium.frame_sorter()
        self._iridium_frame_printer = iridium.iridium_frame_printer(file_info)

        if raw_capture_filename:
            multi = blocks.multiply_const_cc(32768)
            converter = blocks.complex_to_interleaved_short()
            raw_sink = blocks.file_sink(itemsize=gr.sizeof_short, filename=raw_capture_filename)
            tb.connect(source, multi, converter, raw_sink)

            # Enable the following if not fast enough
            #self._burst_to_pdu_converters = []
            #self._burst_downmixers = []
            #return

        tb.connect(source, self._fft_burst_tagger)
        self._source = source

        if self._use_pfb:
            self._burst_to_pdu_converters = []
            self._burst_downmixers = []
            sinks = []

            for channel in range(self._channels):
                center = channel if channel <= self._channels / 2 else (channel - self._channels)

                # Second and third parameters tell the block where after the PFB it sits.
                relative_center = center / float(self._channels)
                relative_span = 1. / self._channels
                relative_sample_rate = relative_span * self._pfb_over_sample_ratio
                burst_to_pdu_converter = iridium.tagged_burst_to_pdu(self._max_burst_len,
                                            relative_center, relative_span, relative_sample_rate,
                                            -self._pfb_delay,
                                            self._max_queue_len, not self._offline)
                burst_downmixer = iridium.burst_downmix(self._burst_sample_rate,
                                    int(0.007 * self._burst_sample_rate), 0, (input_filter), (start_finder_filter), self._handle_multiple_frames_per_burst)

                if debug_id is not None: burst_downmixer.debug_id(debug_id)

                self._burst_downmixers.append(burst_downmixer)
                self._burst_to_pdu_converters.append(burst_to_pdu_converter)

            #pfb_debug_sinks = [blocks.file_sink(itemsize=gr.sizeof_gr_complex, filename="/tmp/channel-%d.f32"%i) for i in range(self._channels)]
            pfb_debug_sinks = None

            pfb = gnuradio.filter.pfb.channelizer_ccf(numchans=self._channels, taps=self._pfb_fir_filter, oversample_rate=self._pfb_over_sample_ratio)

            tb.connect(self._fft_burst_tagger, pfb)

            for i in range(self._channels):
                tb.connect((pfb, i), self._burst_to_pdu_converters[i])
                if pfb_debug_sinks:
                    tb.connect((pfb, i), pfb_debug_sinks[i])

                tb.msg_connect((self._burst_to_pdu_converters[i], 'cpdus'), (self._burst_downmixers[i], 'cpdus'))
                tb.msg_connect((self._burst_downmixers[i], 'burst_handled'), (self._burst_to_pdu_converters[i], 'burst_handled'))

                tb.msg_connect((self._burst_downmixers[i], 'cpdus'), (self._iridium_qpsk_demod, 'cpdus%d' % i))
        else:
            burst_downmix = iridium.burst_downmix(self._burst_sample_rate, int(0.007 * self._burst_sample_rate), 0, (input_filter), (start_finder_filter), self._handle_multiple_frames_per_burst)
            if debug_id is not None: burst_downmix.debug_id(debug_id)

            burst_to_pdu = iridium.tagged_burst_to_pdu(self._max_burst_len,
                                                        0.0, 1.0, 1.0,
                                                        0,
                                                        self._max_queue_len, not self._offline)

            tb.connect(self._fft_burst_tagger, burst_to_pdu)

            tb.msg_connect((burst_to_pdu, 'cpdus'), (burst_downmix, 'cpdus'))
            tb.msg_connect((burst_downmix, 'burst_handled'), (burst_to_pdu, 'burst_handled'))

            # Final connection to the demodulator. It prints the output to stdout
            tb.msg_connect((burst_downmix, 'cpdus'), (self._iridium_qpsk_demod, 'cpdus'))

            self._burst_downmixers = [burst_downmix]
            self._burst_to_pdu_converters = [burst_to_pdu]

        tb.msg_connect((self._iridium_qpsk_demod, 'pdus'), (self._frame_sorter, 'pdus'))
        tb.msg_connect((self._frame_sorter, 'pdus'), (self._iridium_frame_printer, 'pdus'))


    def get_n_detected_bursts(self):
        return self._fft_burst_tagger.get_n_tagged_bursts()

    def get_sample_count(self):
        return self._fft_burst_tagger.get_sample_count()

    def get_n_handled_bursts(self):
        return self._iridium_qpsk_demod.get_n_handled_bursts()

    def get_n_access_ok_bursts(self):
        return self._iridium_qpsk_demod.get_n_access_ok_bursts()

    def get_n_access_ok_sub_bursts(self):
        return self._iridium_qpsk_demod.get_n_access_ok_sub_bursts()

    def get_queue_size(self):
        size = 0
        for converter in self._burst_to_pdu_converters:
            size += converter.get_output_queue_size()
        return size

    def get_max_queue_size(self):
        size = 0
        for converter in self._burst_to_pdu_converters:
            size += converter.get_output_max_queue_size()
        return size

    def get_n_dropped_bursts(self):
        dropped = 0
        for converter in self._burst_to_pdu_converters:
            dropped += converter.get_n_dropped_bursts()
        for downmix in self._burst_downmixers:
            dropped += downmix.get_n_dropped_bursts()
        return dropped

    def run(self, *args, **kwargs):
        self.start(*args, **kwargs)

        # Work around issue in Ubuntu 20.04 gr-osmosdr
        if "_bandwidth" in self.__dict__:
            self._source.set_bandwidth(self._bandwidth, 0)
            print("Bandwidth:", self._source.get_bandwidth(0), '(Requested %d)' % self._bandwidth, file=sys.stderr)

        try:
            self.wait()
        except KeyboardInterrupt:
            # some magic to get blocks to flush data
            self.lock()
            self._fft_burst_tagger.stop()
            self.unlock()
            # shut down everything
            self._impl.stop()
            self.wait()
