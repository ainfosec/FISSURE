# vim: set ts=4 sw=4 tw=0 et pm=:

import iridium

from gnuradio import gr
from gnuradio import blocks
import gnuradio.filter

import scipy.signal
import numpy as np

import sys
import math
import time
import platform
import multiprocessing
import distutils.util


class FlowGraph(gr.top_block):
    def __init__(self, center_frequency, sample_rate, decimation, filename, sample_format=None, threshold=7.0,
                 burst_width=40e3, offline=False, max_queue_len=500, handle_multiple_frames_per_burst=False,
                 raw_capture_filename=None, debug_id=None, max_bursts=0, verbose=False, file_info="",
                 samples_per_symbol=10, config={}):
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
        self._decimation = decimation

        # Sample rate of the bursts exiting the burst downmix block
        self._burst_sample_rate = 25000 * samples_per_symbol
        if (self._input_sample_rate / self._decimation) % self._burst_sample_rate != 0:
            raise RuntimeError("Selected sample rate and decimation can not be matched. Please try a different combination. Sample rate divided by decimation must be a multiple of %d." % self._burst_sample_rate)

        self._fft_size = 2**round(math.log(self._input_sample_rate / 1000, 2))  # FFT is approx. 1 ms long
        self._burst_pre_len = 2 * self._fft_size

        # Keep 16 ms of signal after the FFT loses track
        self._burst_post_len = int(self._input_sample_rate * 16e-3)

        # Just to keep the code below a bit more portable
        tb = self

        if self._decimation > 1:
            self._use_channelizer = True

            # We will set up a filter bank with an odd number of outputs and
            # and an over sampling ratio to still get the desired decimation.

            # The goal is to reconstruct signals which (due to Doppler shift) end up
            # on the border of two channels.

            # For this to work the desired decimation must be even.
            if self._decimation % 2:
                raise RuntimeError("The desired decimation must be 1 or an even number.")

            self._channels = self._decimation + 1

            if self._decimation >= 8:
                self._use_fft_channelizer = True

                if 2**int(math.log(self._decimation, 2)) != self._decimation:
                    raise RuntimeError("Decimations >= 8 must be a power of two.")
                self._channel_sample_rate = self._input_sample_rate // self._decimation

                # On low end ARM machines we only create a single burst downmixer to not
                # overload the CPU. Rather drop bursts than samples.
                if platform.machine() == 'aarch64' and multiprocessing.cpu_count() == 4:
                    self._n_burst_downmixers = 1
                else:
                    self._n_burst_downmixers = 2
            else:
                self._use_fft_channelizer = False

                self._n_burst_downmixers = self._channels
                self._channelizer_over_sample_ratio = self._channels / (self._channels - 1.)
                channelizer_output_sample_rate = int(round(float(self._input_sample_rate) / self._channels * self._channelizer_over_sample_ratio))
                self._channel_sample_rate = channelizer_output_sample_rate
                assert channelizer_output_sample_rate == self._input_sample_rate / self._decimation
                assert channelizer_output_sample_rate % self._burst_sample_rate == 0

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
                self._fir_tw = (channelizer_output_sample_rate / 2 - self._fir_bw) * 2

                # Real world data shows only a minor degradation in performance when
                # doubling the transition width.
                self._fir_tw *= 2

                # If the over sampling ratio is not large enough, there is not
                # enough room to construct a transition region.
                if self._fir_tw < 0:
                    raise RuntimeError("PFB over sampling ratio not enough to create a working FIR filter. Please try a different decimation.")

                self._pfb_fir_filter = gnuradio.filter.firdes.low_pass_2(1, self._input_sample_rate, self._fir_bw, self._fir_tw, 60)

                # If the transition width approaches 0, the filter size goes up significantly.
                if len(self._pfb_fir_filter) > 300:
                    print("Warning: The PFB FIR filter has an abnormal large number of taps:", len(self._pfb_fir_filter), file=sys.stderr)
                    print("Consider reducing the decimation factor or use a decimation >= 8.", file=sys.stderr)

                pfb_input_delay = (len(self._pfb_fir_filter) + 1) // 2 - self._channels / self._channelizer_over_sample_ratio
                self._channelizer_delay = pfb_input_delay / self._decimation

                if self._verbose:
                    print("self._channels", self._channels, file=sys.stderr)
                    print("len(self._pfb_fir_filter)", len(self._pfb_fir_filter), file=sys.stderr)
                    print("self._channelizer_over_sample_ratio", self._channelizer_over_sample_ratio, file=sys.stderr)
                    print("self._fir_bw", self._fir_bw, file=sys.stderr)
                    print("self._fir_tw", self._fir_tw, file=sys.stderr)
                    print("self._channel_sample_rate", self._channel_sample_rate, file=sys.stderr)
        else:
            self._use_channelizer = False
            self._channel_sample_rate = self._input_sample_rate
            self._channels = 1

        # After 90 ms there needs to be a pause in the frame sturcture.
        # Let's make that the limit for a detected burst
        self._max_burst_len = int(self._channel_sample_rate * 0.09)

        if self._verbose:
            print("require %.1f dB" % self._threshold, file=sys.stderr)
            print("burst_width: %d Hz" % self._burst_width, file=sys.stderr)
            print("source:", config['source'], file=sys.stderr)

        if config['source'] == 'osmosdr':
            d = config["osmosdr-source"]

            # work around https://github.com/gnuradio/gnuradio/issues/5121
            sys.path.append('/usr/local/lib/python3/dist-packages')
            import osmosdr
            if 'device_args' in d:
                source = osmosdr.source(args=d['device_args'])
            else:
                source = osmosdr.source()

            source.set_sample_rate(self._input_sample_rate)
            source.set_center_freq(self._center_frequency, 0)

            # Set a rough time estimate for potential rx_time tags from USRP devices
            # This prevents the output from having bogous time stamps if no GPSDO is available
            source.set_time_now(osmosdr.time_spec_t(time.time()))

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
                bandwidth = int(d['bandwidth'])
                source.set_bandwidth(bandwidth, 0)
                print("Bandwidth:", source.get_bandwidth(0), '(Requested %d)' % bandwidth, file=sys.stderr)
            else:
                source.set_bandwidth(0, 0)
                print("Warning: Setting bandwidth to", source.get_bandwidth(0), file=sys.stderr)

            if 'antenna' in d:
                antenna = d['antenna']
                source.set_antenna(antenna, 0)
                print("Antenna:", source.get_antenna(0), '(Requested %s)' % antenna, file=sys.stderr)
            else:
                print("Warning: Setting antenna to", source.get_antenna(0), file=sys.stderr)

            if 'clock_source' in d:
                print("Setting clock source to:", d['clock_source'], file=sys.stderr)
                source.set_clock_source(d['clock_source'], 0)

            if 'time_source' in d:
                print("Setting time source to:", d['time_source'], file=sys.stderr)
                source.set_time_source(d['time_source'], 0)
                while (time.time() % 1) < 0.4 or (time.time() % 1) > 0.6:
                    pass
                t = time.time()
                source.set_time_next_pps(osmosdr.time_spec_t(int(t) + 1))
                time.sleep(1)

            #source.set_freq_corr($corr0, 0)
            #source.set_dc_offset_mode($dc_offset_mode0, 0)
            #source.set_iq_balance_mode($iq_balance_mode0, 0)
            #source.set_gain_mode($gain_mode0, 0)

        elif config['source'] == 'soapy':
            d = config["soapy-source"]

            try:
                from gnuradio import soapy
            except ImportError:
                raise ImportError("gr-soapy not found. Make sure you are running GNURadio >= 3.9.2.0")

            if 'driver' not in d:
                print("No driver specified for soapy", file=sys.stderr)
                print("Run 'SoapySDRUtil -i' to see available drivers(factories)", file=sys.stderr)
                exit(1)
            dev = 'driver=' + d['driver']

            # Strip quotes
            def sanitize(s):
                if s.startswith('"') and s.endswith('"'):
                    return s.strip('""')
                if s.startswith("'") and s.endswith("'"):
                    return s.strip("''")
                return s

            # Remove all outer quotes from the args if they are present in the config
            if 'device_args' in d:
                dev_args = sanitize(d['device_args'])
            elif 'dev_args' in d:
                dev_args = sanitize(d['dev_args'])
            else:
                dev_args = ''

            stream_args = sanitize(d['stream_args']) if 'stream_args' in d else ''
            tune_args = sanitize(d['tune_args']) if 'tune_args' in d else ''
            other_settings = sanitize(d['other_settings']) if 'other_settings' in d else ''

            # We only support a single channel. Apply tune_args and other_settings to that channel.
            source = soapy.source(dev, "fc32", 1, dev_args, stream_args, [tune_args], [other_settings])

            source.set_sample_rate(0, self._input_sample_rate)
            source.set_frequency(0, self._center_frequency)

            if 'gain' in d:
                gain = int(d['gain'])
                source.set_gain_mode(0, False)  # AGC: OFF
                source.set_gain(0, gain)
                print("Gain:", source.get_gain(0), '(Requested %d)' % gain, file=sys.stderr)

            for key, value in d.items():
                if key.endswith("_gain"):
                    gain_option_name = key.split('_')[0]
                    gain_value = int(value)

                    def match_gain(gain, gain_names):
                        for gain_name in gain_names:
                            if gain.lower() == gain_name.lower():
                                return gain_name
                        return None

                    gain_name = match_gain(gain_option_name, source.list_gains(0))

                    if gain_name is not None:
                        source.set_gain(0, gain_name, gain_value)
                        print(gain_name, "Gain:", source.get_gain(0, gain_name), '(Requested %d)' % gain_value, source.get_gain_range(0, gain_name), file=sys.stderr)
                    else:
                        print("WARNING: Gain", gain_option_name, "not supported by source!", file=sys.stderr)
                        print("Supported gains:", source.list_gains(0), file=sys.stderr)

            if 'bandwidth' in d:
                bandwidth = int(d['bandwidth'])
                source.set_bandwidth(0, bandwidth)
                print("Bandwidth:", source.get_bandwidth(0), '(Requested %d)' % bandwidth, file=sys.stderr)
            else:
                source.set_bandwidth(0, 0)
                print("Warning: Setting bandwidth to", source.get_bandwidth(0), file=sys.stderr)

            if 'antenna' in d:
                antenna = d['antenna']
                source.set_antenna(0, antenna)
                print("Antenna:", source.get_antenna(0), '(Requested %s)' % antenna, file=sys.stderr)
            else:
                print("Warning: Setting antenna to", source.get_antenna(0), file=sys.stderr)

            #source.set_frequency_correction(0, f_corr)
            #source.set_dc_offset_mode(0, True)
            #source.set_dc_offset(0, dc_off)
            #source.set_iq_balance(0, iq_bal)
        elif config['source'] == 'zeromq-sub':
            d = config["zeromq-sub-source"]

            from gnuradio import zeromq

            if 'address' not in d:
                print("No address specified for zeromq sub", file=sys.stderr)
                exit(1)

            pass_tags = False
            if 'pass_tags' in d:
                pass_tags = bool(distutils.util.strtobool(d['pass_tags']))

            timeout = 100
            if 'timeout' in d:
                timeout = int(d['timeout'])

            high_water_mark = -1
            if 'high_water_mark' in d:
                high_water_mark = int(d['high_water_mark'])

            source = zeromq.sub_source(gr.sizeof_gr_complex, 1, d['address'], timeout, pass_tags, high_water_mark, '')

        elif config['source'] == 'uhd':
            d = config["uhd-source"]

            from gnuradio import uhd

            dev_addr = ""
            if "device_addr" in d:
                dev_addr = d['device_addr']
            dev_args = d['device_args']

            cpu_format = 'fc32'
            wire_format = 'sc16'
            stream_args = ""

            stream_args = uhd.stream_args(cpu_format, wire_format, args=stream_args)
            source = uhd.usrp_source(dev_addr + "," + dev_args, stream_args)

            source.set_samp_rate(self._input_sample_rate)
            source.set_center_freq(self._center_frequency)

            if 'gain' in d:
                gain = int(d['gain'])
                source.set_gain(gain, 0)
                print("Gain:", source.get_gain(0), '(Requested %d)' % gain, file=sys.stderr)

            if 'bandwidth' in d:
                bandwidth = int(d['bandwidth'])
                source.set_bandwidth(bandwidth, 0)
                print("Bandwidth:", source.get_bandwidth(0), '(Requested %d)' % bandwidth, file=sys.stderr)
            else:
                source.set_bandwidth(0)
                print("Warning: Setting bandwidth to", source.get_bandwidth(0), file=sys.stderr)

            if 'antenna' in d:
                antenna = d['antenna']
                source.set_antenna(antenna, 0)
                print("Antenna:", source.get_antenna(0), '(Requested %s)' % antenna, file=sys.stderr)
            else:
                print("Warning: Setting antenna to", source.get_antenna(0), file=sys.stderr)

            print("mboard sensors:", source.get_mboard_sensor_names(0), file=sys.stderr)
            #for sensor in source.get_mboard_sensor_names(0):
            #    print(sensor, source.get_mboard_sensor(sensor, 0))

            gpsdo_sources = ('gpsdo', 'jacksonlabs')

            time_source = None
            if 'time_source' in d:
                time_source = d['time_source']
                if time_source in gpsdo_sources:
                    source.set_time_source("gpsdo", 0)
                else:
                    source.set_time_source(time_source, 0)

            clock_source = None
            if 'clock_source' in d:
                clock_source = d['time_source']
                if clock_source in gpsdo_sources:
                    source.set_clock_source("gpsdo", 0)
                else:
                    source.set_clock_source(clock_source, 0)

            if time_source in gpsdo_sources or clock_source in gpsdo_sources:
                print("Waiting for gps_locked...", file=sys.stderr)
                while True:
                    try:
                        if d['time_source'] == "jacksonlabs":
                            servo = source.get_mboard_sensor("gps_servo", 0)
                            # See https://lists.ettus.com/empathy/thread/6ZOCFQSKLHSG2IH3ID7XPWVKHVHZXPBP
                            gps_locked = str(servo).split()[8] == "6"
                        else:
                            gps_locked = source.get_mboard_sensor("gps_locked", 0).to_bool()

                        if gps_locked:
                            break
                    except ValueError as e:
                        print(e, file=sys.stderr)
                        pass
                    time.sleep(1)

                print("gps_locked!", file=sys.stderr)

            if clock_source:
                print("Waiting for ref_locked...", file=sys.stderr)
                while True:
                    try:
                        ref_locked = source.get_mboard_sensor("ref_locked", 0)
                        if ref_locked.to_bool():
                            break
                    except ValueError as e:
                        print(e, file=sys.stderr)
                        pass
                    time.sleep(1)
                print("ref_locked!", file=sys.stderr)

            if time_source:
                if time_source in gpsdo_sources:
                    while True:
                        try:
                            gps_time = uhd.time_spec_t(source.get_mboard_sensor("gps_time").to_int())
                            break
                        except ValueError as e:
                            print(e, file=sys.stderr)
                            pass
                        time.sleep(1)

                    next_pps_time = gps_time + 1
                else:
                    system_time = uhd.time_spec_t(int(time.time()))
                    next_pps_time = system_time + 1

                source.set_time_next_pps(next_pps_time)
                print("Next PPS at", next_pps_time.get_real_secs(), file=sys.stderr)

                print("Sleeping 2 seconds...", file=sys.stderr)
                time.sleep(2)

                # TODO: Check result for plausibility
                print("USRP  time:", source.get_time_last_pps(0).get_real_secs(), file=sys.stderr)
            else:
                # Set a rough time estimate for rx_time tags from the USRP.
                # This prevents the output from having bogous time stamps if no GPSDO is available.
                source.set_time_now(uhd.time_spec_t(time.time()))

            self.source = source

        else:
            if sample_format == "cu8":
                converter = iridium.iuchar_to_complex()
                itemsize = gr.sizeof_char
                scale = 1
                itemtype = np.uint8
            elif sample_format == "ci8":
                converter = blocks.interleaved_char_to_complex()
                itemsize = gr.sizeof_char
                scale = 1 / 128.
                itemtype = np.int8
            elif sample_format == "ci16_le":
                converter = blocks.interleaved_short_to_complex()
                itemsize = gr.sizeof_short
                scale = 1 / 32768.
                itemtype = np.int16
            elif sample_format == "cf32_le":
                converter = None
                itemsize = gr.sizeof_gr_complex
                itemtype = np.complex64
            else:
                raise RuntimeError("Unknown sample format for offline mode given")

            if config['source'] == 'stdin':
                file_source = blocks.file_descriptor_source(itemsize=itemsize, fd=0, repeat=False)
            elif config['source'] == 'object':
                from iridium.file_object_source import file_object_source
                file_source = file_object_source(fileobject=config['object'], itemtype=itemtype)
            else:
                file_source = blocks.file_source(itemsize=itemsize, filename=config['file'], repeat=False)

            self.source = file_source  # XXX: keep reference

            if converter:
                multi = blocks.multiply_const_cc(scale)
                tb.connect(file_source, converter, multi)
                source = multi
            else:
                source = file_source

        self._fft_burst_tagger = iridium.fft_burst_tagger(center_frequency=self._center_frequency,
                                                          fft_size=self._fft_size,
                                                          sample_rate=self._input_sample_rate,
                                                          burst_pre_len=self._burst_pre_len,
                                                          burst_post_len=self._burst_post_len,
                                                          burst_width=int(self._burst_width),
                                                          max_bursts=max_bursts,
                                                          max_burst_len=int(self._input_sample_rate * 0.09),
                                                          threshold=self._threshold,
                                                          history_size=512,
                                                          offline=self._offline,
                                                          debug=self._verbose)
        self._fft_burst_tagger.set_min_output_buffer(1024 * 64)

        # Initial filter to filter the detected bursts. Runs at burst_sample_rate. Used to decimate the signal.
        input_filter = gnuradio.filter.firdes.low_pass_2(1, self._channel_sample_rate, self._burst_width / 2, self._burst_width, 40)
        #input_filter = gnuradio.filter.firdes.low_pass_2(1, self._channel_sample_rate, 42e3/2, 24e3, 40)
        #print len(input_filter)

        # Filter to find the start of the signal. Should be fairly narrow.
        start_finder_filter = gnuradio.filter.firdes.low_pass_2(1, self._burst_sample_rate, 5e3 / 2, 10e3 / 2, 60)
        #print len(start_finder_filter)

        self._iridium_qpsk_demod = iridium.iridium_qpsk_demod(self._channels)
        self._frame_sorter = iridium.frame_sorter()
        self._iridium_frame_printer = iridium.iridium_frame_printer(file_info)

        if raw_capture_filename:
            multi = blocks.multiply_const_cc(32768)
            converter = blocks.complex_to_interleaved_short()
            raw_sink = blocks.file_sink(itemsize=gr.sizeof_short, filename=raw_capture_filename + '.sigmf-data')
            tb.connect(source, multi, converter, raw_sink)

            # Enable the following if not fast enough
            #self._burst_to_pdu_converters = []
            #self._burst_downmixers = []
            #return

        tb.connect(source, self._fft_burst_tagger)

        if self._use_channelizer:
            self._burst_to_pdu_converters = []
            self._burst_downmixers = []
            sinks = []

            for channel in range(self._channels):
                if not self._use_fft_channelizer:
                    center = channel if channel <= self._channels / 2 else (channel - self._channels)
                    relative_center = center / float(self._channels)
                    relative_span = 1. / self._channels
                    relative_sample_rate = relative_span * self._channelizer_over_sample_ratio

                    # Second and third parameters tell the block where after the PFB it sits.
                    burst_to_pdu_converter = iridium.tagged_burst_to_pdu(self._max_burst_len,
                                                                         relative_center,
                                                                         relative_span,
                                                                         relative_sample_rate,
                                                                         -self._channelizer_delay,
                                                                         self._max_queue_len,
                                                                         not self._offline)
                    self._burst_to_pdu_converters.append(burst_to_pdu_converter)

                burst_downmixer = iridium.burst_downmix(self._burst_sample_rate,
                                                        int(0.007 * self._burst_sample_rate),
                                                        0,
                                                        (input_filter),
                                                        (start_finder_filter),
                                                        self._handle_multiple_frames_per_burst)

                if debug_id is not None:
                    burst_downmixer.debug_id(debug_id)

                self._burst_downmixers.append(burst_downmixer)

            channelizer_debug_sinks = []
            #channelizer_debug_sinks = [blocks.file_sink(itemsize=gr.sizeof_gr_complex, filename="/tmp/channel-%d.f32"%i) for i in range(self._channels)]

            if self._use_fft_channelizer:
                if not channelizer_debug_sinks and self._offline:
                    # HACK: if there are no stream outputs active GNURadio has issues terminating the
                    # flowgraph on completion. Connect some dummy sinks to them.
                    channelizer_debug_sinks = [blocks.null_sink(gr.sizeof_gr_complex) for i in range(self._channels)]

                activate_streams = len(channelizer_debug_sinks) > 0
                self._channelizer = iridium.fft_channelizer(1024, self._channels - 1, activate_streams, self._n_burst_downmixers, self._max_burst_len,
                                                            self._max_queue_len * self._n_burst_downmixers, not self._offline)
            else:
                self._channelizer = gnuradio.filter.pfb.channelizer_ccf(numchans=self._channels, taps=self._pfb_fir_filter, oversample_rate=self._channelizer_over_sample_ratio)

            tb.connect(self._fft_burst_tagger, self._channelizer)

            for i in range(self._channels):
                if channelizer_debug_sinks:
                    tb.connect((self._channelizer, i), channelizer_debug_sinks[i])

            for i in range(self._n_burst_downmixers):
                if self._burst_to_pdu_converters:
                    tb.connect((self._channelizer, i), self._burst_to_pdu_converters[i])
                    tb.msg_connect((self._burst_to_pdu_converters[i], 'cpdus'), (self._burst_downmixers[i], 'cpdus'))
                    tb.msg_connect((self._burst_downmixers[i], 'burst_handled'), (self._burst_to_pdu_converters[i], 'burst_handled'))
                else:
                    tb.msg_connect((self._channelizer, 'cpdus%d' % i), (self._burst_downmixers[i], 'cpdus'))
                    tb.msg_connect((self._burst_downmixers[i], 'burst_handled'), (self._channelizer, 'burst_handled'))

                tb.msg_connect((self._burst_downmixers[i], 'cpdus'), (self._iridium_qpsk_demod, 'cpdus%d' % i))
        else:
            burst_downmix = iridium.burst_downmix(self._burst_sample_rate, int(0.007 * self._burst_sample_rate), 0, (input_filter), (start_finder_filter), self._handle_multiple_frames_per_burst)
            if debug_id is not None:
                burst_downmix.debug_id(debug_id)

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
        if self._burst_to_pdu_converters:
            for converter in self._burst_to_pdu_converters:
                size += converter.get_output_queue_size()
        else:
            size += self._channelizer.get_output_queue_size()
        return size

    def get_max_queue_size(self):
        size = 0
        if self._burst_to_pdu_converters:
            for converter in self._burst_to_pdu_converters:
                size += converter.get_output_max_queue_size()
        else:
            size += self._channelizer.get_output_max_queue_size()
        return size

    def get_n_dropped_bursts(self):
        dropped = 0
        if self._burst_to_pdu_converters:
            for converter in self._burst_to_pdu_converters:
                dropped += converter.get_n_dropped_bursts()
        else:
            dropped += self._channelizer.get_n_dropped_bursts()
        for downmix in self._burst_downmixers:
            dropped += downmix.get_n_dropped_bursts()
        return dropped

    def run(self, *args, **kwargs):
        self.start(*args, **kwargs)
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
