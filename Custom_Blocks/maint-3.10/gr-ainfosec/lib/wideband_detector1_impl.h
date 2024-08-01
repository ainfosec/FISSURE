/* -*- c++ -*- */
/*
 * Copyright 2022 gr-ainfosec author.
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

#ifndef INCLUDED_AINFOSEC_WIDEBAND_DETECTOR1_IMPL_H
#define INCLUDED_AINFOSEC_WIDEBAND_DETECTOR1_IMPL_H

#include <gnuradio/ainfosec/wideband_detector1.h>
#include <zmq.hpp>
#include <list>


namespace gr {
  namespace ainfosec {

    class wideband_detector1_impl : public wideband_detector1
    {
     private:
       std::string my_address;
       float my_rx_freq;
       int my_fft_size;
       float my_sample_rate;
       zmq::context_t *d_context;
       zmq::socket_t  *d_socket;
       int counter;
       float timer_value;
       float max_power;
       float max_power_freq;
       float max_power_bin;
       std::time_t get_timestamp;

     public:
      wideband_detector1_impl(std::string address, float rx_freq, int fft_size, float sample_rate);
      ~wideband_detector1_impl();
       
      bool send(zmq::socket_t& socket, const std::string& string);
      void set_address(std::string address);
      void set_rx_freq(float rx_freq);
      void set_fft_size(int fft_size);
      void set_sample_rate(float sample_rate);      

      // Where all the action really happens
      int work(
              int noutput_items,
              gr_vector_const_void_star &input_items,
              gr_vector_void_star &output_items
      );
    };

  } // namespace ainfosec
} // namespace gr

#endif /* INCLUDED_AINFOSEC_WIDEBAND_DETECTOR1_IMPL_H */

