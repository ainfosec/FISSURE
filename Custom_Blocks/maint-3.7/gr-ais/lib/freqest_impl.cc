/* -*- c++ -*- */
/* 
 * Copyright 2013 <+YOU OR YOUR COMPANY+>.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "freqest_impl.h"

namespace gr {
  namespace ais {

    freqest::sptr
    freqest::make(float sample_rate, int data_rate, int fftlen)
    {
      return gnuradio::get_initial_sptr
        (new freqest_impl(sample_rate, data_rate, fftlen));
    }

    /*
     * The private constructor
     */
    freqest_impl::freqest_impl(float sample_rate, int data_rate, int fftlen)
      : gr::sync_block("freqest",
              gr::io_signature::make(1, 1, sizeof(gr_complex) * fftlen),
              gr::io_signature::make(1, 1, sizeof(float)))
    {
        d_offset = fftlen * (float(data_rate) / float(sample_rate));
        d_binsize = float(sample_rate) / float(fftlen);
    }

    /*
     * Our virtual destructor.
     */
    freqest_impl::~freqest_impl()
    {
    }

    int
    freqest_impl::work (int noutput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const gr_complex *in = (const gr_complex *) input_items[0];
        float *out = (float *) output_items[0];

        unsigned int fftlen = input_signature()->sizeof_stream_item(0) / sizeof(gr_complex);

        float maxenergy = 0;
        unsigned int maxpos = 0;
        float currentenergy;

        //you are responsible for organizing the vector
        for (int i = 0; i < noutput_items; i++) {
            //for each requested output item
            maxenergy = 0;
            for(unsigned int j = 0; j < fftlen - d_offset; j++) {
                //over the entire fft up until the right side of the "window" butts up against the end
                currentenergy = std::abs(in[i*fftlen+j]) + std::abs(in[i*fftlen+j+d_offset]); //sum of the two bins at -datarate/2 and +datarate/2
                if(currentenergy > maxenergy) {
                    maxenergy = currentenergy;
                    maxpos = j + d_offset/2; //add the offset to find the center position
                }
            }
            //now maxpos contains the center bin, and we must translate that to a frequency offset
            out[i] = (float(maxpos) - fftlen/2) * d_binsize/2; //subtract fftlen/2 to center the complex FFT around 0
        }

        return noutput_items;
    }

  } /* namespace ais */
} /* namespace gr */

