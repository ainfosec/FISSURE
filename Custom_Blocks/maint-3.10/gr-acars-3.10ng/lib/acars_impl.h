/* -*- c++ -*- */
/*
 * Copyright 2022 JM Friedt
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

#ifndef INCLUDED_ACARS_ACARS_IMPL_H
#define INCLUDED_ACARS_ACARS_IMPL_H

#include <acars/acars.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

#include <gnuradio/fft/fft.h>
#include <gnuradio/fft/fft_shift.h>

namespace gr {
  namespace acars {

    class acars_impl : public acars
    {
     private:
        int _Ntot;
        int _N;
        float _threshold;
	int _savenum;
        int _decompte;  // accumulate more sentences than needed (in case of a gap)
        float *_d;      // raw data
        float _seuil;   // threshold value (multiply std with this value to detect msg)
        FILE *_FILE;    // output file descriptor
        char *_toutd,*_tout,*_message,*_somme; // digital messages
        void acars_parse (char *message,int ends);
        float remove_avgf(const float *d,float *out,int tot_len);
        void acars_dec(float *d,int N);

     public:
      void set_seuil(float seuil1);
      acars_impl(float seuil, std::string filename, bool saveall);
      ~acars_impl();

    // Where all the action really happens
    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items);
};

} // namespace acars
} // namespace gr

#endif /* INCLUDED_ACARS_ACARS_IMPL_H */
