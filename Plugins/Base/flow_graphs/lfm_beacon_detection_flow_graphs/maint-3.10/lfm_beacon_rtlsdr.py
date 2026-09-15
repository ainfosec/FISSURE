#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Lfm Beacon Rtlsdr
# GNU Radio version: 3.10.9.2
#
# FISSURE NOTE:
# The matched-filter metric is used only for beacon detection. A separate in-band
# RF power estimate is measured from RTL-SDR samples and reported in dBFS for
# relative ranging/calibration. Independent POWER lines are emitted even when the
# LFM detector does not trigger. Keep this file synchronized with the .grc source.
#

import signal
import sys
import time
from argparse import ArgumentParser

import numpy as np
import pmt
from gnuradio import blocks, gr
from gnuradio import filter
from gnuradio.fft import window
from gnuradio.filter import firdes
from gnuradio import soapy


class LfmBeaconDetector(gr.sync_block):
    """Detect LFM matched-filter peaks and report a separate RF power measurement."""

    def __init__(
        self,
        samp_rate=1e6,
        rx_freq_hz=433e6,
        thresh=15.0,
        min_peak=20.0,
        holdoff_s=0.08,
        peak_window=8000,
        eps=1e-12,
    ):
        gr.sync_block.__init__(
            self,
            name="lfm_beacon_detector",
            in_sig=[np.float32, np.float32],
            out_sig=None,
        )

        self.samp_rate = float(samp_rate)
        self.rx_freq_hz = float(rx_freq_hz)
        self.thresh = float(thresh)
        self.min_peak = float(min_peak)
        self.holdoff_s = float(holdoff_s)
        self.holdoff = int(self.holdoff_s * self.samp_rate)
        self.peak_window = int(peak_window)
        self.eps = float(eps)

        self.n = 0
        self.next_ok = 0
        self.in_peak = False
        self.peak_val = 0.0
        self.peak_power = self.eps
        self.peak_idx = 0
        self.peak_end = 0

        self.message_port_register_out(pmt.intern("det"))

    def set_samp_rate(self, samp_rate):
        self.samp_rate = float(samp_rate)
        self.holdoff = int(self.holdoff_s * self.samp_rate)

    def set_rx_freq_hz(self, rx_freq_hz):
        self.rx_freq_hz = float(rx_freq_hz)

    def set_thresh(self, thresh):
        self.thresh = float(thresh)

    def set_min_peak(self, min_peak):
        self.min_peak = float(min_peak)

    def set_holdoff_s(self, holdoff_s):
        self.holdoff_s = float(holdoff_s)
        self.holdoff = int(self.holdoff_s * self.samp_rate)

    def set_peak_window(self, peak_window):
        self.peak_window = int(peak_window)

    def work(self, input_items, output_items):
        metric = input_items[0]
        rf_power_linear = input_items[1]
        length = min(len(metric), len(rf_power_linear))

        for i in range(length):
            idx = self.n + i
            value = float(metric[i])
            power = max(float(rf_power_linear[i]), self.eps)

            if idx < self.next_ok:
                continue

            if not self.in_peak:
                if value >= self.thresh:
                    self.in_peak = True
                    self.peak_val = value
                    self.peak_power = power
                    self.peak_idx = idx
                    self.peak_end = idx + self.peak_window
                continue

            if value > self.peak_val:
                self.peak_val = value
                self.peak_idx = idx

            if power > self.peak_power:
                self.peak_power = power

            if idx >= self.peak_end:
                if self.peak_val >= self.min_peak:
                    ts = time.time()
                    rf_power_dbfs = 10.0 * np.log10(max(self.peak_power, self.eps))
                    msg = (
                        f"TSI:/LFM Beacon/{self.rx_freq_hz:.1f}/"
                        f"{self.peak_val:.2f}/{ts:.6f}/{rf_power_dbfs:.2f}"
                    )
                    self.message_port_pub(pmt.intern("det"), pmt.intern(msg))

                self.next_ok = self.peak_end + self.holdoff
                self.in_peak = False
                self.peak_val = 0.0
                self.peak_power = self.eps

        self.n += length
        return length


class RfPowerReporter(gr.sync_block):
    """Periodically print in-band RF power independently of beacon detection."""

    def __init__(
        self,
        samp_rate=1e6,
        rx_freq_hz=433e6,
        report_interval_s=0.25,
        eps=1e-12,
    ):
        gr.sync_block.__init__(
            self,
            name="rf_power_reporter",
            in_sig=[np.float32],
            out_sig=None,
        )

        self.samp_rate = float(samp_rate)
        self.rx_freq_hz = float(rx_freq_hz)
        self.report_interval_s = float(report_interval_s)
        self.eps = float(eps)

        self.report_samples = max(1, int(self.report_interval_s * self.samp_rate))
        self.sample_count = 0
        self.sum_power = 0.0
        self.peak_power = self.eps

    def set_samp_rate(self, samp_rate):
        self.samp_rate = float(samp_rate)
        self.report_samples = max(1, int(self.report_interval_s * self.samp_rate))
        self._reset_window()

    def set_rx_freq_hz(self, rx_freq_hz):
        self.rx_freq_hz = float(rx_freq_hz)

    def set_report_interval_s(self, report_interval_s):
        self.report_interval_s = max(0.01, float(report_interval_s))
        self.report_samples = max(1, int(self.report_interval_s * self.samp_rate))
        self._reset_window()

    def _reset_window(self):
        self.sample_count = 0
        self.sum_power = 0.0
        self.peak_power = self.eps

    def _publish_window(self):
        if self.sample_count <= 0:
            return

        avg_power = max(self.sum_power / self.sample_count, self.eps)
        peak_power = max(self.peak_power, self.eps)
        avg_dbfs = 10.0 * np.log10(avg_power)
        peak_dbfs = 10.0 * np.log10(peak_power)
        ts = time.time()

        print(
            f"POWER:/LFM Beacon/{self.rx_freq_hz:.1f}/"
            f"{peak_dbfs:.2f}/{avg_dbfs:.2f}/{ts:.6f}",
            flush=True,
        )
        self._reset_window()

    def work(self, input_items, output_items):
        power = np.asarray(input_items[0], dtype=np.float32)
        pos = 0
        length = len(power)

        while pos < length:
            remaining = self.report_samples - self.sample_count
            take = min(remaining, length - pos)
            chunk = power[pos:pos + take]

            if len(chunk):
                self.sum_power += float(np.sum(chunk, dtype=np.float64))
                self.peak_power = max(self.peak_power, float(np.max(chunk)))
                self.sample_count += len(chunk)

            pos += take

            if self.sample_count >= self.report_samples:
                self._publish_window()

        return length


class lfm_beacon_rtlsdr(gr.top_block):

    def __init__(self, rx_freq_default=433e6, gain_default=40.0, power_report_interval_default=0.25):
        gr.top_block.__init__(self, "Lfm Beacon Rtlsdr", catch_exceptions=True)

        ##################################################
        # Parameters
        ##################################################
        self.rx_freq_default = float(rx_freq_default)
        self.gain_default = float(gain_default)
        self.power_report_interval_default = float(power_report_interval_default)

        ##################################################
        # Variables
        ##################################################
        self.ton = ton = 10e-3
        self.samp_rate = samp_rate = 1e6
        self.bw = bw = 200e3
        self.Nmatch = Nmatch = int(0.25 * ton * samp_rate)
        self.xlating_hz = xlating_hz = -150e3
        self.tperiod = tperiod = 0.1
        self.threshold = threshold = 15
        self.serial = serial = "False"
        self.rx_gain = rx_gain = self.gain_default
        self.rx_freq = rx_freq = self.rx_freq_default
        self.peak_window = peak_window = 8000
        self.notes = notes = "LFM beacon detector with separate received-power measurement."
        self.min_peak = min_peak = 20
        self.matched_taps = matched_taps = np.conjugate(
            np.exp(
                1j
                * 2
                * np.pi
                * np.cumsum(
                    ((-bw / 2) + (bw / ton) * (np.arange(Nmatch) / samp_rate))
                )
                / samp_rate
            )[::-1]
        )
        self.lpf_trans = lpf_trans = bw / 2
        self.lpf_cutoff = lpf_cutoff = bw * 1.2
        self.power_taps = power_taps = firdes.low_pass(
            1.0,
            samp_rate,
            lpf_cutoff,
            lpf_trans,
            window.WIN_HAMMING,
            6.76,
        )
        self.power_avg_len = power_avg_len = max(1, int(0.002 * samp_rate))
        self.power_report_interval_s = power_report_interval_s = self.power_report_interval_default
        self.holdoff_s = holdoff_s = 0.08
        self.eps = eps = 1e-12
        self.avg_len = avg_len = int(0.01 * samp_rate)

        ##################################################
        # Blocks
        ##################################################
        self.soapy_rtlsdr_source_0 = None
        dev = "driver=rtlsdr"
        stream_args = "bufflen=16384"
        tune_args = [""]
        settings = [""]

        def _set_soapy_rtlsdr_source_0_gain_mode(channel, agc):
            self.soapy_rtlsdr_source_0.set_gain_mode(channel, agc)
            if not agc:
                self.soapy_rtlsdr_source_0.set_gain(
                    channel,
                    self._soapy_rtlsdr_source_0_gain_value,
                )

        self.set_soapy_rtlsdr_source_0_gain_mode = _set_soapy_rtlsdr_source_0_gain_mode

        def _set_soapy_rtlsdr_source_0_gain(channel, name, gain):
            self._soapy_rtlsdr_source_0_gain_value = gain
            if not self.soapy_rtlsdr_source_0.get_gain_mode(channel):
                self.soapy_rtlsdr_source_0.set_gain(channel, gain)

        self.set_soapy_rtlsdr_source_0_gain = _set_soapy_rtlsdr_source_0_gain

        def _set_soapy_rtlsdr_source_0_bias(bias):
            if "biastee" in self._soapy_rtlsdr_source_0_setting_keys:
                self.soapy_rtlsdr_source_0.write_setting("biastee", bias)

        self.set_soapy_rtlsdr_source_0_bias = _set_soapy_rtlsdr_source_0_bias

        self.soapy_rtlsdr_source_0 = soapy.source(
            dev,
            "fc32",
            1,
            "",
            stream_args,
            tune_args,
            settings,
        )

        self._soapy_rtlsdr_source_0_setting_keys = [
            a.key for a in self.soapy_rtlsdr_source_0.get_setting_info()
        ]

        self.soapy_rtlsdr_source_0.set_sample_rate(0, samp_rate)
        self.soapy_rtlsdr_source_0.set_frequency(0, rx_freq)
        self.soapy_rtlsdr_source_0.set_frequency_correction(0, 0)
        self.set_soapy_rtlsdr_source_0_bias(bool(False))
        self._soapy_rtlsdr_source_0_gain_value = rx_gain
        self.set_soapy_rtlsdr_source_0_gain_mode(0, bool(False))
        self.set_soapy_rtlsdr_source_0_gain(0, "TUNER", rx_gain)

        # Existing matched-filter detection path.
        self.freq_xlating_fir_filter_xxx_0 = filter.freq_xlating_fir_filter_ccc(
            1,
            matched_taps,
            xlating_hz,
            samp_rate,
        )
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.blocks_moving_average_xx_0 = blocks.moving_average_ff(
            avg_len,
            (1 / avg_len),
            4000,
            1,
        )
        self.blocks_moving_average_xx_1 = blocks.moving_average_ff(
            64,
            (1 / 64),
            4000,
            1,
        )

        # Separate in-band received-power path.
        #
        # This is deliberately not the matched-filter peak. The RTL samples are
        # translated to the same LFM channel, low-pass filtered, converted to
        # magnitude-squared, and averaged for 2 ms. The detector reports the
        # strongest averaged channel power seen during each matched-filter event.
        #
        # The resulting value is relative dBFS, not calibrated dBm.
        self.freq_xlating_fir_filter_power = filter.freq_xlating_fir_filter_ccc(
            1,
            power_taps,
            xlating_hz,
            samp_rate,
        )
        self.blocks_complex_to_mag_squared_power = blocks.complex_to_mag_squared(1)
        self.blocks_moving_average_power = blocks.moving_average_ff(
            power_avg_len,
            (1 / power_avg_len),
            4000,
            1,
        )

        self.lfm_detector = LfmBeaconDetector(
            samp_rate=samp_rate,
            rx_freq_hz=rx_freq,
            thresh=threshold,
            min_peak=min_peak,
            holdoff_s=holdoff_s,
            peak_window=peak_window,
            eps=eps,
        )
        self.rf_power_reporter = RfPowerReporter(
            samp_rate=samp_rate,
            rx_freq_hz=rx_freq,
            report_interval_s=power_report_interval_s,
            eps=eps,
        )
        self.dc_blocker_xx_0 = filter.dc_blocker_cc(32, True)
        self.blocks_message_debug_0 = blocks.message_debug(
            True,
            gr.log_levels.info,
        )

        ##################################################
        # Connections
        ##################################################
        self.msg_connect(
            (self.lfm_detector, "det"),
            (self.blocks_message_debug_0, "print"),
        )

        self.connect(
            (self.soapy_rtlsdr_source_0, 0),
            (self.dc_blocker_xx_0, 0),
        )

        # Detection branch.
        self.connect(
            (self.dc_blocker_xx_0, 0),
            (self.freq_xlating_fir_filter_xxx_0, 0),
        )
        self.connect(
            (self.freq_xlating_fir_filter_xxx_0, 0),
            (self.blocks_complex_to_mag_squared_0, 0),
        )
        self.connect(
            (self.blocks_complex_to_mag_squared_0, 0),
            (self.blocks_moving_average_xx_0, 0),
        )
        self.connect(
            (self.blocks_moving_average_xx_0, 0),
            (self.blocks_moving_average_xx_1, 0),
        )
        self.connect(
            (self.blocks_moving_average_xx_1, 0),
            (self.lfm_detector, 0),
        )

        # RF power branch.
        self.connect(
            (self.dc_blocker_xx_0, 0),
            (self.freq_xlating_fir_filter_power, 0),
        )
        self.connect(
            (self.freq_xlating_fir_filter_power, 0),
            (self.blocks_complex_to_mag_squared_power, 0),
        )
        self.connect(
            (self.blocks_complex_to_mag_squared_power, 0),
            (self.blocks_moving_average_power, 0),
        )
        self.connect(
            (self.blocks_moving_average_power, 0),
            (self.lfm_detector, 1),
        )
        self.connect(
            (self.blocks_moving_average_power, 0),
            (self.rf_power_reporter, 0),
        )

    def get_rx_freq_default(self):
        return self.rx_freq_default

    def set_rx_freq_default(self, rx_freq_default):
        self.rx_freq_default = float(rx_freq_default)
        self.set_rx_freq(self.rx_freq_default)

    def get_gain_default(self):
        return self.gain_default

    def set_gain_default(self, gain_default):
        self.gain_default = float(gain_default)
        self.set_rx_gain(self.gain_default)

    def get_power_report_interval_default(self):
        return self.power_report_interval_default

    def set_power_report_interval_default(self, power_report_interval_default):
        self.power_report_interval_default = float(power_report_interval_default)
        self.set_power_report_interval_s(self.power_report_interval_default)

    def get_ton(self):
        return self.ton

    def set_ton(self, ton):
        self.ton = ton
        self.set_Nmatch(int(0.25 * self.ton * self.samp_rate))
        self.set_matched_taps(
            np.conjugate(
                np.exp(
                    1j
                    * 2
                    * np.pi
                    * np.cumsum(
                        (
                            (-self.bw / 2)
                            + (self.bw / self.ton)
                            * (np.arange(self.Nmatch) / self.samp_rate)
                        )
                    )
                    / self.samp_rate
                )[::-1]
            )
        )

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.set_Nmatch(int(0.25 * self.ton * self.samp_rate))
        self.set_avg_len(int(0.01 * self.samp_rate))
        self.set_power_avg_len(max(1, int(0.002 * self.samp_rate)))
        self.set_matched_taps(
            np.conjugate(
                np.exp(
                    1j
                    * 2
                    * np.pi
                    * np.cumsum(
                        (
                            (-self.bw / 2)
                            + (self.bw / self.ton)
                            * (np.arange(self.Nmatch) / self.samp_rate)
                        )
                    )
                    / self.samp_rate
                )[::-1]
            )
        )
        self.set_power_taps(
            firdes.low_pass(
                1.0,
                self.samp_rate,
                self.lpf_cutoff,
                self.lpf_trans,
                window.WIN_HAMMING,
                6.76,
            )
        )
        self.lfm_detector.set_samp_rate(self.samp_rate)
        self.rf_power_reporter.set_samp_rate(self.samp_rate)
        self.soapy_rtlsdr_source_0.set_sample_rate(0, self.samp_rate)

    def get_bw(self):
        return self.bw

    def set_bw(self, bw):
        self.bw = bw
        self.set_lpf_cutoff(self.bw * 1.2)
        self.set_lpf_trans(self.bw / 2)
        self.set_matched_taps(
            np.conjugate(
                np.exp(
                    1j
                    * 2
                    * np.pi
                    * np.cumsum(
                        (
                            (-self.bw / 2)
                            + (self.bw / self.ton)
                            * (np.arange(self.Nmatch) / self.samp_rate)
                        )
                    )
                    / self.samp_rate
                )[::-1]
            )
        )

    def get_Nmatch(self):
        return self.Nmatch

    def set_Nmatch(self, Nmatch):
        self.Nmatch = Nmatch
        self.set_matched_taps(
            np.conjugate(
                np.exp(
                    1j
                    * 2
                    * np.pi
                    * np.cumsum(
                        (
                            (-self.bw / 2)
                            + (self.bw / self.ton)
                            * (np.arange(self.Nmatch) / self.samp_rate)
                        )
                    )
                    / self.samp_rate
                )[::-1]
            )
        )

    def get_xlating_hz(self):
        return self.xlating_hz

    def set_xlating_hz(self, xlating_hz):
        self.xlating_hz = xlating_hz
        self.freq_xlating_fir_filter_xxx_0.set_center_freq(self.xlating_hz)
        self.freq_xlating_fir_filter_power.set_center_freq(self.xlating_hz)

    def get_tperiod(self):
        return self.tperiod

    def set_tperiod(self, tperiod):
        self.tperiod = tperiod

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold
        self.lfm_detector.set_thresh(self.threshold)

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.set_soapy_rtlsdr_source_0_gain(0, "TUNER", self.rx_gain)

    def get_rx_freq(self):
        return self.rx_freq

    def set_rx_freq(self, rx_freq):
        self.rx_freq = rx_freq
        self.lfm_detector.set_rx_freq_hz(self.rx_freq)
        self.rf_power_reporter.set_rx_freq_hz(self.rx_freq)
        self.soapy_rtlsdr_source_0.set_frequency(0, self.rx_freq)

    def get_peak_window(self):
        return self.peak_window

    def set_peak_window(self, peak_window):
        self.peak_window = peak_window
        self.lfm_detector.set_peak_window(self.peak_window)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_min_peak(self):
        return self.min_peak

    def set_min_peak(self, min_peak):
        self.min_peak = min_peak
        self.lfm_detector.set_min_peak(self.min_peak)

    def get_matched_taps(self):
        return self.matched_taps

    def set_matched_taps(self, matched_taps):
        self.matched_taps = matched_taps
        self.freq_xlating_fir_filter_xxx_0.set_taps(self.matched_taps)

    def get_power_taps(self):
        return self.power_taps

    def set_power_taps(self, power_taps):
        self.power_taps = power_taps
        self.freq_xlating_fir_filter_power.set_taps(self.power_taps)

    def get_lpf_trans(self):
        return self.lpf_trans

    def set_lpf_trans(self, lpf_trans):
        self.lpf_trans = lpf_trans
        self.set_power_taps(
            firdes.low_pass(
                1.0,
                self.samp_rate,
                self.lpf_cutoff,
                self.lpf_trans,
                window.WIN_HAMMING,
                6.76,
            )
        )

    def get_lpf_cutoff(self):
        return self.lpf_cutoff

    def set_lpf_cutoff(self, lpf_cutoff):
        self.lpf_cutoff = lpf_cutoff
        self.set_power_taps(
            firdes.low_pass(
                1.0,
                self.samp_rate,
                self.lpf_cutoff,
                self.lpf_trans,
                window.WIN_HAMMING,
                6.76,
            )
        )

    def get_power_avg_len(self):
        return self.power_avg_len

    def set_power_avg_len(self, power_avg_len):
        self.power_avg_len = max(1, int(power_avg_len))
        self.blocks_moving_average_power.set_length_and_scale(
            self.power_avg_len,
            (1 / self.power_avg_len),
        )

    def get_power_report_interval_s(self):
        return self.power_report_interval_s

    def set_power_report_interval_s(self, power_report_interval_s):
        self.power_report_interval_s = max(0.01, float(power_report_interval_s))
        self.rf_power_reporter.set_report_interval_s(self.power_report_interval_s)

    def get_holdoff_s(self):
        return self.holdoff_s

    def set_holdoff_s(self, holdoff_s):
        self.holdoff_s = holdoff_s
        self.lfm_detector.set_holdoff_s(self.holdoff_s)

    def get_eps(self):
        return self.eps

    def set_eps(self, eps):
        self.eps = eps
        self.lfm_detector.eps = float(self.eps)
        self.rf_power_reporter.eps = float(self.eps)

    def get_avg_len(self):
        return self.avg_len

    def set_avg_len(self, avg_len):
        self.avg_len = avg_len
        self.blocks_moving_average_xx_0.set_length_and_scale(
            self.avg_len,
            (1 / self.avg_len),
        )


def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--rx-freq-default",
        dest="rx_freq_default",
        type=float,
        default=433e6,
        help="Receive frequency in Hz [default=%(default)r]",
    )
    parser.add_argument(
        "--gain-default",
        dest="gain_default",
        type=float,
        default=40.0,
        help="RTL-SDR tuner gain [default=%(default)r]",
    )
    parser.add_argument(
        "--power-report-interval",
        dest="power_report_interval_default",
        type=float,
        default=0.25,
        help="Independent RF power report interval in seconds [default=%(default)r]",
    )
    return parser


def main(top_block_cls=lfm_beacon_rtlsdr, options=None):
    if options is None:
        options = argument_parser().parse_args()

    tb = top_block_cls(
        rx_freq_default=options.rx_freq_default,
        gain_default=options.gain_default,
        power_report_interval_default=options.power_report_interval_default,
    )

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()
    tb.wait()


if __name__ == "__main__":
    main()
