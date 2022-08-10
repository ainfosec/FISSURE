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
#include "bluetooth_multi_block.h"
#include <gnuradio/io_signature.h>
#include <gnuradio/filter/firdes.h>
#include <math.h>
#include <gnuradio/math.h>

/* constructor */
bluetooth_multi_block::bluetooth_multi_block(double sample_rate, double center_freq, double squelch_threshold)
  : gr::sync_block ("bluetooth multi block",
	      gr::io_signature::make (1, 1, sizeof (gr_complex)),
	      gr::io_signature::make (0, 0, 0))
{
	d_cumulative_count = 0;
	d_sample_rate = sample_rate;
	d_center_freq = center_freq;
	set_channels();
	/*
	 * how many time slots we attempt to decode on each hop:
	 * 1 for now, could be as many as 5 plus a little slop
	 */
	int slots = 1;
	d_samples_per_symbol = sample_rate / SYMBOL_RATE;
	//FIXME make sure that d_samples_per_symbol >= 2 (requirement of clock_recovery_mm_ff)
	d_samples_per_slot = (int) SYMBOLS_PER_SLOT * d_samples_per_symbol;
	int samples_required = (int) slots * d_samples_per_slot;

	/* power squelch: this is crude, but it works */
	d_squelch_threshold = (double) std::pow(10.0, squelch_threshold/10) * d_samples_per_symbol * 68; 

	/* channel filter coefficients */
	double gain = 1;
	double cutoff_freq = 500000;
	double transition_width = 300000;
	d_channel_filter = gr::filter::firdes::low_pass(gain, sample_rate, cutoff_freq, transition_width, gr::filter::firdes::WIN_HANN);
	/* d_channel_filter.size() will be the history requirement of ddc */
	samples_required += (d_channel_filter.size() - 1);

	/* we will decimate by the largest integer that results in enough samples per symbol */
	d_ddc_decimation_rate = (int) d_samples_per_symbol / 2;
	double channel_samples_per_symbol = d_samples_per_symbol / d_ddc_decimation_rate;

	/* fm demodulator */
	d_demod_gain = channel_samples_per_symbol / M_PI_2;

	/* mm_cr variables */
	d_gain_mu = 0.175;
	d_mu = 0.32;
	d_omega_relative_limit = 0.005;
	d_omega = channel_samples_per_symbol;
	d_gain_omega = .25 * d_gain_mu * d_gain_mu;
	d_omega_mid = d_omega;
	d_interp = new gr::filter::mmse_fir_interpolator_ff();
	d_last_sample = 0;
	samples_required += d_ddc_decimation_rate * d_interp->ntaps();

	set_history(samples_required);
}

static inline float
slice(float x)
{
	return x < 0 ? -1.0F : 1.0F;
}

/* M&M clock recovery, adapted from gr_clock_recovery_mm_ff */
int bluetooth_multi_block::mm_cr(const float *in, int ninput_items, float *out, int noutput_items)
{
	unsigned int ii = 0; /* input index */
	int oo = 0; /* output index */
	unsigned int ni = ninput_items - d_interp->ntaps(); /* max input */
	float mm_val;

	while (oo < noutput_items && ii < ni)
	{
		// produce output sample
		out[oo] = d_interp->interpolate (&in[ii], d_mu);
		mm_val = slice(d_last_sample) * out[oo] - slice(out[oo]) * d_last_sample;
		d_last_sample = out[oo];

		d_omega += d_gain_omega * mm_val;
		d_omega = d_omega_mid + gr::branchless_clip(d_omega-d_omega_mid, d_omega_relative_limit);   // make sure we don't walk away
		d_mu += d_omega + d_gain_mu * mm_val;

		ii += (int) floor(d_mu);
		d_mu -= floor(d_mu);
		oo++;
		//FIXME debugging:
		if (ii > 32768) printf("%d, %d, %d, %d\n", oo, noutput_items, ii, ni);
	}

	/* return number of output items produced */
	return oo;
}

/* fm demodulation, taken from gr_quadrature_demod_cf */
void bluetooth_multi_block::demod(const gr_complex *in, float *out, int noutput_items)
{
	int i;
	gr_complex product;

	for (i = 1; i < noutput_items; i++)
	{
		gr_complex product = in[i] * conj (in[i-1]);
		out[i] = d_demod_gain * gr::fast_atan2f(imag(product), real(product));
	}
}

/* binary slicer, similar to gr_binary_slicer_fb */
void bluetooth_multi_block::slicer(const float *in, char *out, int noutput_items)
{
	int i;

	for (i = 0; i < noutput_items; i++)
		out[i] = (in[i] < 0) ? 0 : 1;
}

/* produce symbols stream for a particular channel pulled out of the raw samples */
int bluetooth_multi_block::channel_symbols(int channel, gr_vector_const_void_star &in, char *out, int ninput_items)
{
	/*
	 * squelch: this is a simple check to see if there is enough power in the
	 * first slot to bother looking for a packet.
	 */
	int i;
	double pwr = 0; //total power for the time slot (sum of power of every sample)
	gr_complex *raw_in = (gr_complex *) in[0];
	int last_sq = d_samples_per_symbol * (SYMBOLS_PER_SLOT + 68);
	if (ninput_items < last_sq)
		last_sq = ninput_items;
	for (i = 0; i < last_sq; i++)
		pwr += (raw_in[i].real() * raw_in[i].real() + raw_in[i].imag() * raw_in[i].imag());
	if (pwr < d_squelch_threshold)
		/* not enough power, skip this slot */
		return 0;

	/* ddc */
	double ddc_center_freq = channel_freq(channel);
	gr::filter::freq_xlating_fir_filter_ccf::sptr ddc =
		gr::freq_xlating_fir_filter_ccf::make(d_ddc_decimation_rate, d_channel_filter, ddc_center_freq, d_sample_rate);
	int ddc_noutput_items = ddc->fixed_rate_ninput_to_noutput(ninput_items - (ddc->history() - 1));
	gr_complex ddc_out[ddc_noutput_items];
	gr_vector_void_star ddc_out_vector(1);
	ddc_out_vector[0] = ddc_out;
	ddc_noutput_items = ddc->work(ddc_noutput_items, in, ddc_out_vector);

	/* fm demodulation */
	int demod_noutput_items = ddc_noutput_items - 1;
	float demod_out[demod_noutput_items];
	demod(ddc_out, demod_out, demod_noutput_items);

	/* clock recovery */
	int cr_ninput_items = demod_noutput_items;
	int noutput_items = cr_ninput_items; // poor estimate but probably safe
	float cr_out[noutput_items];
	noutput_items = mm_cr(demod_out, cr_ninput_items, cr_out, noutput_items);

	/* binary slicer */
	slicer(cr_out, out, noutput_items);

	return noutput_items;
}

/* add some number of symbols to the block's history requirement */
void bluetooth_multi_block::set_symbol_history(int num_symbols)
{
	set_history((int) (history() + (num_symbols * d_samples_per_symbol)));
}

/* set available channels based on d_center_freq and d_sample_rate */
void bluetooth_multi_block::set_channels()
{
	/* center frequency described as a fractional channel */
	double center = (d_center_freq - BASE_FREQUENCY) / CHANNEL_WIDTH;
	/* bandwidth in terms of channels */
	double channel_bandwidth = d_sample_rate / CHANNEL_WIDTH;
	/* low edge of our received signal */
	double low_edge = center - (channel_bandwidth / 2);
	/* high edge of our received signal */
	double high_edge = center + (channel_bandwidth / 2);
	/* minimum bandwidth required per channel - ideally 1.0 (1 MHz), but can probably decode with a bit less */
	double min_channel_width = 0.9;

	d_low_channel = (int) (low_edge + (min_channel_width / 2) + 1);
	d_low_channel = (d_low_channel < 0) ? 0 : d_low_channel;

	d_high_channel = (int) (high_edge - (min_channel_width / 2));
	d_high_channel = (d_high_channel > 78) ? 78 : d_high_channel;
}

/* returns relative (with respect to d_center_freq) frequency in Hz of given channel */
double bluetooth_multi_block::channel_freq(int channel)
{
	return BASE_FREQUENCY + (channel * CHANNEL_WIDTH) - d_center_freq;
}
