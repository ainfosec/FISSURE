/* -*- c++ -*- */
/* 
 * Copyright 2015 Ron Economos.
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
#include "paint_bc_impl.h"
#include <volk/volk.h>
#include <stdio.h>

namespace gr {
  namespace paint {

    paint_bc::sptr
    paint_bc::make(int width, int repeats, int equalization, int randomsrc, int inputs)
    {
      return gnuradio::get_initial_sptr
        (new paint_bc_impl(width, repeats, equalization, randomsrc, inputs));
    }

    /*
     * The private constructor
     */
    paint_bc_impl::paint_bc_impl(int width, int repeats, int equalization, int randomsrc, int inputs)
      : gr::block("paint_bc",
              gr::io_signature::make(inputs, inputs, sizeof(unsigned char)),
              gr::io_signature::make(1, 1, sizeof(gr_complex)))
    {
        double x, sinc, fs = 2000000.0;
        double fstep, f = 0.0;
        line_repeat = repeats;
        image_width = width;
        random_source = randomsrc;
        equalization_enable = equalization;
        ofdm_fft_size = 4096;
        ofdm_fft = new fft::fft_complex(ofdm_fft_size, false, 1);
        normalization = 0.000001;
        pixel_repeat = ofdm_fft_size / image_width;
        int nulls = ofdm_fft_size - (image_width * pixel_repeat);
        left_nulls = nulls / 2;
        right_nulls = nulls / 2;
        if (nulls % 2 == 1)
        {
            left_nulls++;
        }
        fstep = fs / ofdm_fft_size;
        for (int i = 0; i < ofdm_fft_size / 2; i++)
        {
            x = M_PI * f / fs;
            if (i == 0)
            {
                sinc = 1.0;
            }
            else
            {
                sinc = sin(x) / x;
            }
            inverse_sinc[i + (ofdm_fft_size / 2)] = gr_complex(1.0 / sinc, 0.0);
            inverse_sinc[(ofdm_fft_size / 2) - i - 1] = gr_complex(1.0 / sinc, 0.0);
            f = f + fstep;
        }
        set_output_multiple(ofdm_fft_size * line_repeat);
    }

    /*
     * Our virtual destructor.
     */
    paint_bc_impl::~paint_bc_impl()
    {
        delete ofdm_fft;
    }

    void
    paint_bc_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
        ninput_items_required[0] = (noutput_items * (image_width / line_repeat)) / ofdm_fft_size;
        if (random_source == EXTERNAL)
        {
            ninput_items_required[1] = (noutput_items / ofdm_fft_size) * image_width * pixel_repeat;
        }
    }

    int
    paint_bc_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const unsigned char *in = (const unsigned char *) input_items[0];
        const unsigned char *in_rand = (const unsigned char *) input_items[1];
        gr_complex *out = (gr_complex *) output_items[0];
        int consumed = 0;
        int consumed_rand = 0;
        int pixel_index;
        int angle_index;
        int pixels;
        float angle, magnitude;
        gr_complex zero;
        gr_complex *dst;

        zero = gr_complex(0.0, 0.0);

        for (int i = 0; i < noutput_items; i += (ofdm_fft_size * line_repeat))
        {
            pixel_index = 0;
            for (int j = 0; j < image_width; j++)
            {
                magnitude = in[consumed++];
                magnitude += 256.0;
                magnitude = pow(magnitude, 5.0);
                magnitude /= 10000000000.0;
                for (int k = 0; k < pixel_repeat; k++)
                {
                    magnitude_line[pixel_index++] = magnitude;
                }
            }
            for (int lrepeat = 0; lrepeat < line_repeat; lrepeat++)
            {
                for (int j = 0; j < left_nulls; j++)
                {
                    *out++ = zero;
                }
                angle_index = 0;
                for (int j = 0; j < image_width; j++)
                {
                    for (int prepeat = 0; prepeat < pixel_repeat; prepeat++)
                    {
                        if (random_source == INTERNAL)
                        {
                            angle = rand();
                            angle = angle - (RAND_MAX / 2);
                            angle_line[angle_index++] = angle * M_PI / (RAND_MAX / 2);
                        }
                        else
                        {
                            angle = (in_rand[consumed_rand++] << 1) + 1;
                            angle_line[angle_index++] = angle * M_PI / 4.0;
                        }
                    }
                }
                pixels = image_width * pixel_repeat;
                volk_32f_cos_32f(angle_cos, angle_line, pixels);
                volk_32f_sin_32f(angle_sin, angle_line, pixels);
                volk_32f_x2_multiply_32f(angle_cos, angle_cos, magnitude_line, pixels);
                volk_32f_x2_multiply_32f(angle_sin, angle_sin, magnitude_line, pixels);
                volk_32f_x2_interleave_32fc(out, angle_cos, angle_sin, pixels);
                out += pixels;
                for (int j = 0; j < right_nulls; j++)
                {
                    *out++ = zero;
                }
                out -= ofdm_fft_size;
                if (equalization_enable == EQUALIZATION_ON)
                {
                    volk_32fc_x2_multiply_32fc(out, out, inverse_sinc, ofdm_fft_size);
                }
                dst = ofdm_fft->get_inbuf();
                memcpy(&dst[ofdm_fft_size / 2], &out[0], sizeof(gr_complex) * ofdm_fft_size / 2);
                memcpy(&dst[0], &out[ofdm_fft_size / 2], sizeof(gr_complex) * ofdm_fft_size / 2);
                ofdm_fft->execute();
                volk_32fc_s32fc_multiply_32fc(out, ofdm_fft->get_outbuf(), normalization, ofdm_fft_size);
                out += ofdm_fft_size;
            }
        }
        // Tell runtime system how many input items we consumed on
        // each input stream.
        consume (0, consumed);
        if (random_source == EXTERNAL)
        {
            consume (1, consumed_rand);
        }

        // Tell runtime system how many output items we produced.
        return noutput_items;
    }

  } /* namespace paint */
} /* namespace gr */

