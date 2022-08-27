#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# GR-GSM based transceiver
# Generic (device independent) flow-graph implementation
#
# (C) 2016-2019 by Vadim Yanitskiy <axilirator@gmail.com>
# (C) 2017      by Piotr Krysik <ptrkrysik@gmail.com>
#
# All Rights Reserved
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import pmt
import time
from gnuradio import gsm
import random

from math import pi

from gnuradio import eng_notation
from gnuradio import digital
from gnuradio import blocks
from gnuradio import gr

from gnuradio import filter
from gnuradio.fft import window
from gnuradio.filter import firdes

from .dict_toggle_sign import dict_toggle_sign

class RadioInterface(gr.top_block):
	# PHY specific variables
	rx_freq = None
	tx_freq = None
	osr = 4

	# GSM timings (in microseconds [uS])
	# One timeslot duration is 576.9 μs = 15/26 ms,
	# or 156.25 symbol periods (a symbol period is 48/13 μs)
	GSM_SYM_PERIOD_uS = 48.0 / 13.0
	GSM_TS_PERIOD_uS = GSM_SYM_PERIOD_uS * 156.25
	GSM_UL_DL_SHIFT_uS = -(GSM_TS_PERIOD_uS * 3)

	GSM_SYM_RATE = (1.0 / GSM_SYM_PERIOD_uS) * 1e6
	SAMPLE_RATE = GSM_SYM_RATE * osr

	# Dummy freq. value that is used during initialization
	# basically, the DL freq. of ARFCN 0
	DUMMY_FREQ = 935e6

	# Human-readable description
	def __str__(self):
		return "(generic)"

	def __init__(self, phy_args, phy_sample_rate,
			phy_rx_gain, phy_tx_gain, phy_ppm,
			phy_rx_antenna, phy_tx_antenna,
			phy_freq_offset, trx_bind_addr,
			trx_remote_addr, trx_base_port):

		print("[i] Init %s Radio interface (L:%s:%u <-> R:%s:%u)"
			% (self, trx_bind_addr, trx_base_port + 2,
				trx_remote_addr, trx_base_port + 102))

		# PHY specific variables
		self.sample_rate = phy_sample_rate
		self.rx_gain = phy_rx_gain
		self.tx_gain = phy_tx_gain
		self.ppm = phy_ppm
		self.freq_offset = phy_freq_offset

		self.phy_args = phy_args
		self.rx_antenna = phy_rx_antenna
		self.tx_antenna = phy_tx_antenna

		gr.top_block.__init__(self, "GR-GSM TRX")

		# TRX Burst Interface
		self.trx_burst_if = gsm.trx_burst_if(
			trx_bind_addr, trx_remote_addr,
			str(trx_base_port))

		# RX path definition
		self.phy_init_source()

		self.msg_to_tag_src = gsm.msg_to_tag()

		self.rotator_src = gsm.controlled_rotator_cc(0.0)

		self.lpf = filter.fir_filter_ccf(1, firdes.low_pass(
			1, phy_sample_rate, 125e3, 5e3, window.WIN_HAMMING, 6.76))

		self.gsm_receiver = gsm.receiver(self.osr, ([0]), ([]))

		self.ts_filter = gsm.burst_timeslot_filter(0)
		self.ts_filter.set_policy(gsm.FILTER_POLICY_DROP_ALL)

		# Connections
		self.connect(
			(self._phy_src, 0),
			(self.msg_to_tag_src, 0))

		self.connect(
			(self.msg_to_tag_src, 0),
			(self.rotator_src, 0))

		self.connect(
			(self.rotator_src, 0),
			(self.lpf, 0))

		self.connect(
			(self.lpf, 0),
			(self.gsm_receiver, 0))

		self.msg_connect(
			(self.gsm_receiver, 'C0'),
			(self.ts_filter, 'in'))

		self.msg_connect(
			(self.ts_filter, 'out'),
			(self.trx_burst_if, 'bursts'))


		# TX Path Definition
		self.phy_init_sink()

		self.tx_time_setter = gsm.txtime_setter(
			0xffffffff, 0, 0, 0, 0, 0,
			self.phy_proc_delay + self.GSM_UL_DL_SHIFT_uS * 1e-6)

		self.tx_burst_proc = gsm.preprocess_tx_burst()

		self.pdu_to_tagged_stream = blocks.pdu_to_tagged_stream(
			blocks.byte_t, 'packet_len')

		self.gmsk_mod = gsm.gsm_gmsk_mod(
			BT = 0.3, pulse_duration = 4, sps = self.osr)

		self.burst_shaper = digital.burst_shaper_cc(
			(firdes.window(window.WIN_HANN, 16, 0)),
			0, 20, False, "packet_len")

		self.msg_to_tag_sink = gsm.msg_to_tag()

		self.rotator_sink = gsm.controlled_rotator_cc(0.0)

		# Connections
		self.msg_connect(
			(self.trx_burst_if, 'bursts'),
			(self.tx_time_setter, 'bursts_in'))

		self.msg_connect(
			(self.tx_time_setter, 'bursts_out'),
			(self.tx_burst_proc, 'bursts_in'))

		self.msg_connect(
			(self.tx_burst_proc, 'bursts_out'),
			(self.pdu_to_tagged_stream, 'pdus'))

		self.connect(
			(self.pdu_to_tagged_stream, 0),
			(self.gmsk_mod, 0))

		self.connect(
			(self.gmsk_mod, 0),
			(self.burst_shaper, 0))

		self.connect(
			(self.burst_shaper, 0),
			(self.msg_to_tag_sink, 0))

		self.connect(
			(self.msg_to_tag_sink, 0),
			(self.rotator_sink, 0))

		self.connect(
			(self.rotator_sink, 0),
			(self._phy_sink, 0))


		# RX & TX synchronization
		self.bt_filter = gsm.burst_type_filter([3])
		self.burst_to_fn_time = gsm.burst_to_fn_time()

		# Connections
		self.msg_connect(
			(self.gsm_receiver, 'C0'),
			(self.bt_filter, 'bursts_in'))

		self.msg_connect(
			(self.bt_filter, 'bursts_out'),
			(self.burst_to_fn_time, 'bursts_in'))

		self.msg_connect(
			(self.burst_to_fn_time, 'fn_time_out'),
			(self.tx_time_setter, 'fn_time'))


		# AFC (Automatic Frequency Correction)
		# NOTE: dummy frequency is used during init
		self.gsm_clck_ctrl = gsm.clock_offset_control(
			self.DUMMY_FREQ, phy_sample_rate, osr = self.osr)

		self.dict_toggle_sign = dict_toggle_sign()

		# Connections
		self.msg_connect(
			(self.gsm_receiver, 'measurements'),
			(self.gsm_clck_ctrl, 'measurements'))

		self.msg_connect(
			(self.gsm_clck_ctrl, 'ctrl'),
			(self.msg_to_tag_src, 'msg'))

		self.msg_connect(
			(self.gsm_clck_ctrl, 'ctrl'),
			(self.dict_toggle_sign, 'dict_in'))

		self.msg_connect(
			(self.dict_toggle_sign, 'dict_out'),
			(self.msg_to_tag_sink, 'msg'))

	def phy_init_source(self):
		raise NotImplementedError

	def phy_init_sink(self):
		raise NotImplementedError

	def shutdown(self):
		print("[i] Shutdown Radio interface")
		self.stop()
		self.wait()

	@property
	def ready(self):
		# RX / TX frequencies shall be set
		if self.rx_freq is None:
			return False
		if self.tx_freq is None:
			return False

		return True

	def reset(self):
		# TODO: do we need to reset both RX / TX freq.?
		# self.rx_freq = None
		# self.tx_freq = None
		self.set_ta(0)

	def calc_phase_inc(self, fc):
		return self.ppm / 1.0e6 * 2 * pi * fc / self.sample_rate

	def set_rx_freq(self, fc):
		if self.freq_offset != 0:
			fc += self.freq_offset
			print("[#] Shifting RX freq. to %s (offset is %s)"
				% (eng_notation.num_to_str(fc),
					eng_notation.num_to_str(self.freq_offset)))

		self.rotator_src.set_phase_inc(self.calc_phase_inc(fc))
		self.gsm_clck_ctrl.set_fc(fc)
		self.phy_set_rx_freq(fc)
		self.rx_freq = fc

	def set_tx_freq(self, fc):
		if self.freq_offset != 0:
			fc += self.freq_offset
			print("[#] Shifting TX freq. to %s (offset is %s)"
				% (eng_notation.num_to_str(fc),
					eng_notation.num_to_str(self.freq_offset)))

		self.rotator_sink.set_phase_inc(-self.calc_phase_inc(fc))
		self.phy_set_tx_freq(fc)
		self.tx_freq = fc

	def set_rx_gain(self, gain):
		self.phy_set_rx_gain(gain)
		self.rx_gain = gain

	def set_tx_gain(self, gain):
		self.phy_set_tx_gain(gain)
		self.tx_gain = gain

	def set_slot(self, slot, config):
		print("[i] Configure timeslot filter to: %s"
			% ("drop all" if config == 0 else "tn=%d" % slot))

		if config == 0:
			# Value 0 is used for deactivation
			self.ts_filter.set_policy(gsm.FILTER_POLICY_DROP_ALL)
		else:
			# FIXME: ideally, we should (re)configure the Receiver
			# block, but there is no API for that, and hard-coded
			# timeslot configuration is used...
			self.ts_filter.set_policy(gsm.FILTER_POLICY_DEFAULT)
			self.ts_filter.set_tn(slot)

	def set_ta(self, ta):
		print("[i] Setting TA value %d" % ta)
		advance_time_sec = ta * self.GSM_SYM_PERIOD_uS * 1e-6
		self.tx_time_setter.set_timing_advance(advance_time_sec)

	def measure(self, freq):
		# HACK: generate a random low RSSI value
		return random.randint(-120, -100)
