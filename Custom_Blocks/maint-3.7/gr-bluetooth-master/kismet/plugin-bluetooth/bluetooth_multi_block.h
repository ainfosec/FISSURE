/* -*- c++ -*- */
/*
 * Copyright 2008, 2009 Dominic Spill, Michael Ossmann                                                                                            
 * Copyright 2007 Dominic Spill                                                                                                                   
 * Copyright 2005, 2006 Free Software Foundation, Inc.
 * 
 * This file is part of gr-bluetooth
 * 
 * gr-bluetooth is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * gr-bluetooth is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with gr-bluetooth; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */
//FIXME this file should not be here - copied from gr-bluetooth/src/lib
#ifndef INCLUDED_BLUETOOTH_MULTI_BLOCK_H
#define INCLUDED_BLUETOOTH_MULTI_BLOCK_H

#include <gnuradio/sync_block.h>
#include <stdint.h>
#include <gnuradio/analog/pwr_squelch_cc.h>
#include <gnuradio/filter/freq_xlating_fir_filter_ccf.h>
#include <gnuradio/analog/quadrature_demod_cf.h>
#include <gnuradio/digital/clock_recovery_mm_ff.h>
#include <gnuradio/digital/binary_slicer_fb.h>
#include <gnuradio/filter/mmse_fir_interpolator_ff.h>

/*!
 * \brief Bluetooth multi-channel parent class.
 * \ingroup block
 */
class bluetooth_multi_block : public gr::sync_block
{
protected:
	/* constructor */
	bluetooth_multi_block(double sample_rate, double center_freq, double squelch_threshold);

	/* symbols per second */
	static const int SYMBOL_RATE = 1000000;

	/* length of time slot in symbols */
	static const int SYMBOLS_PER_SLOT = 625;

	/* channel 0 in Hz */
	static const uint32_t BASE_FREQUENCY = 2402000000UL;

	/* channel width in Hz */
	static const int CHANNEL_WIDTH = 1000000;

	/* total number of samples elapsed */
	uint64_t d_cumulative_count;

	/* sample rate of raw input stream */
	double d_sample_rate;

	/* number of raw samples per symbol */
	double d_samples_per_symbol;

	/* number of raw samples per time slot (625 microseconds) */
	double d_samples_per_slot;

	/* center frequency of input stream */
	double d_center_freq;

	/* lowest channel (0-78) we can decode */
	int d_low_channel;

	/* highest channel (0-78) we can decode */
	int d_high_channel;

	/* power squelch threshold normalized for comparison in channel_symbols() */
	double d_squelch_threshold;

	/* decimation rate of digital downconverter */
	int d_ddc_decimation_rate;

	/* mm_cr variables */
	float d_gain_mu;		// gain for adjusting mu
	float d_mu;				// fractional sample position [0.0, 1.0]
	float d_omega_relative_limit;	// used to compute min and max omega
	float d_omega;			// nominal frequency
	float d_gain_omega;		// gain for adjusting omega
	float d_omega_mid;		// average omega
	float d_last_sample;

	/* channel filter coefficients for digital downconverter */
	std::vector<float> d_channel_filter;

	/* quadrature frequency demodulator sensitivity */
	float d_demod_gain;

	/* interpolator M&M clock recovery block */
	gr::filter::mmse_fir_interpolator_ff *d_interp;

	/* M&M clock recovery, adapted from gr_clock_recovery_mm_ff */
	int mm_cr(const float *in, int ninput_items, float *out, int noutput_items);

	/* fm demodulation, taken from gr_quadrature_demod_cf */
	void demod(const gr_complex *in, float *out, int noutput_items);

	/* binary slicer, similar to gr_binary_slicer_fb */
	void slicer(const float *in, char *out, int noutput_items);

	/* produce symbols stream for a particular channel pulled out of the raw samples */
	int channel_symbols(int channel, gr_vector_const_void_star &in, char *out, int ninput_items);

	/* add some number of symbols to the block's history requirement */
	void set_symbol_history(int num_symbols);

	/* set available channels based on d_center_freq and d_sample_rate */
	void set_channels();

	/* returns relative (with respect to d_center_freq) frequency in Hz of given channel */
	double channel_freq(int channel);
};

#endif /* INCLUDED_BLUETOOTH_MULTI_BLOCK_H */
