/* -*- c++ -*- */
/* 
 * Copyright 2016 Free Software Foundation, Inc
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


#include <gnuradio/attributes.h>
#include <cppunit/TestAssert.h>
#include "qa_fft_burst_tagger.h"
#include <iridium/fft_burst_tagger.h>

namespace gr {
  namespace iridium {

    void
    qa_fft_burst_tagger::t1()
    {
      //
      fft_burst_tagger::make(1626000000, /* center_frequency */
                             4096, /* fft_size */
                             1000000, /* sample_rate */
                             4096,  /* burst_pre_len */
                             8*4096,  /* burst_post_len */
                             40,  /* burst_width */
                             0,  /* max_bursts */
                             7.0,  /* threshold */
                             512, /* history_size */
                             false  /*  debug*/);
    }

  } /* namespace iridium */
} /* namespace gr */

