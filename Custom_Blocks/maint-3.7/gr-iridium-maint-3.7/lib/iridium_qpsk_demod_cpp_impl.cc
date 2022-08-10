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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "iridium.h"

#include <gnuradio/io_signature.h>
#include "iridium_qpsk_demod_cpp_impl.h"
#include <volk/volk.h>
#include <gnuradio/math.h>
#include <stdio.h>

namespace gr {
  namespace iridium {

    iridium_qpsk_demod_cpp::sptr
    iridium_qpsk_demod_cpp::make()
    {
      return gnuradio::get_initial_sptr
        (new iridium_qpsk_demod_cpp_impl());
    }

    /*
     * The private constructor
     */
    iridium_qpsk_demod_cpp_impl::iridium_qpsk_demod_cpp_impl()
      : gr::sync_block("iridium_qpsk_demod_cpp",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
        d_max_burst_size(0),
        d_alpha(1/5.),
        d_magnitude_f(NULL),
        d_burst_after_pll(NULL),
        d_decimated_burst(NULL),
        d_demodulated_burst(NULL),
        d_n_handled_bursts(0),
        d_n_access_ok_bursts(0),
        d_symbol_mapping{0, 1, 2, 3}
    {
      message_port_register_in(pmt::mp("cpdus"));

      message_port_register_out(pmt::mp("pdus"));

      set_msg_handler(pmt::mp("cpdus"), boost::bind(&iridium_qpsk_demod_cpp_impl::handler, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    iridium_qpsk_demod_cpp_impl::~iridium_qpsk_demod_cpp_impl()
    {
      if(d_magnitude_f) {
        volk_free(d_magnitude_f);
      }

      if(d_burst_after_pll) {
        volk_free(d_burst_after_pll);
      }

      if(d_decimated_burst) {
        volk_free(d_decimated_burst);
      }

      if(d_demodulated_burst) {
        volk_free(d_demodulated_burst);
      }
    }

    void iridium_qpsk_demod_cpp_impl::update_buffer_sizes(size_t burst_size)
    {
      if(burst_size > d_max_burst_size) {
        d_max_burst_size = burst_size;

        if(d_magnitude_f) {
          volk_free(d_magnitude_f);
        }
        d_magnitude_f = (float *)volk_malloc(d_max_burst_size * sizeof(float), volk_get_alignment());

        if(d_burst_after_pll) {
          volk_free(d_burst_after_pll);
        }
        d_burst_after_pll = (gr_complex *)volk_malloc(d_max_burst_size * sizeof(gr_complex), volk_get_alignment());

        if(d_decimated_burst) {
          volk_free(d_decimated_burst);
        }
        d_decimated_burst = (gr_complex *)volk_malloc(d_max_burst_size * sizeof(gr_complex), volk_get_alignment());

        if(d_demodulated_burst) {
          volk_free(d_demodulated_burst);
        }
        d_demodulated_burst = (int *)volk_malloc(d_max_burst_size * sizeof(int), volk_get_alignment());

      }
    }

    int iridium_qpsk_demod_cpp_impl::decimate(const gr_complex * in, int size, int sps, gr_complex * out)
    {
      int i, j;
      for(i = 0, j = 0; i < size; i += sps) {
        out[j++] = in[i];
      }
      return j;
    }

    /*
     * Taken from synchronizer_v4_impl.cc of gr-burst
     */
    void iridium_qpsk_demod_cpp_impl::qpskFirstOrderPLL(const gr_complex* x, int size, float alpha, gr_complex* y)
    {
      gr_complex phiHat = gr_complex(1,0);
      gr_complex xHat, er, phiHatT;
      for(int ii=0; ii<size; ii++) {
        // correct w/ estimated phase
        y[ii] = x[ii]*phiHat;

        // demodulating circuit
        if(y[ii].real()>=0 && y[ii].imag()>=0) {
          xHat.real(M_SQRT1_2);
          xHat.imag(M_SQRT1_2);
        } else if(y[ii].real()>=0 && y[ii].imag()<0) {
          xHat.real(M_SQRT1_2);
          xHat.imag(-M_SQRT1_2);
        } else if(y[ii].real()<0 && y[ii].imag()<0) {
          xHat.real(-M_SQRT1_2);
          xHat.imag(-M_SQRT1_2);
        } else {
          xHat.real(-M_SQRT1_2);
          xHat.imag(M_SQRT1_2);
        }

        // loop filter to update phase estimate
        er = std::conj(xHat)*y[ii];
        phiHatT = er/std::abs(er);
        phiHat = std::conj(std::pow(phiHatT, d_alpha)) * phiHat;
        phiHat = phiHat/std::abs(phiHat);
      }
    }


    size_t
    iridium_qpsk_demod_cpp_impl::demod_qpsk(const gr_complex *burst, size_t n_symbols, int * out, float * level, int * confidence)
    {
      int index;
      float sum = 0;
      float max = 0;
      int low_count = 0;
      int n_ok = 0;

      volk_32fc_magnitude_32f(d_magnitude_f, burst, n_symbols);

      for(index = 0; index < n_symbols; index++) {
        sum += d_magnitude_f[index];
        if(max < d_magnitude_f[index]) {
          max = d_magnitude_f[index];
        }

        // demodulating circuit
        if(burst[index].real()>=0 && burst[index].imag()>=0) {
          out[index] = d_symbol_mapping[0];
        } else if(burst[index].real()>=0 && burst[index].imag()<0) {
          out[index] = d_symbol_mapping[3];
        } else if(burst[index].real()<0 && burst[index].imag()<0) {
          out[index] = d_symbol_mapping[2];
        } else {
          out[index] = d_symbol_mapping[1];
        }

        // Keep some quality estimate
        // If the phase is off too much, we lower the reported confidence
        int phase = (gr::fast_atan2f(burst[index]) + M_PI) * 180 / M_PI;
        int offset = 45 - (phase % 90);
        if(offset <= 22) {
          n_ok++;
        }

        if(d_magnitude_f[index] < max / 8.) {
          low_count++;
          if(low_count > 2) {
            break;
          }
        }
      }

      *level = sum / index;
      *confidence = (int) (100. * n_ok / index);
      return index;
    }

    void
    iridium_qpsk_demod_cpp_impl::decode_deqpsk(int * demodulated_burst, size_t n_symbols)
    {
      unsigned int old_sym = 0;
      int bits;
      int i;

      for(i = 0; i < n_symbols; i++){
        unsigned int s = demodulated_burst[i];
        bits = (s - old_sym) % 4;

        if(bits == 0) {
          bits = 0;
        } else if(bits == 1) {
          bits = 2;
        } else if(bits == 2) {
          bits = 3;
        } else {
          bits = 1;
        }

        old_sym = s;
        demodulated_burst[i] = bits;
      }
    }

    void
    iridium_qpsk_demod_cpp_impl::map_symbols_to_bits(const int * demodulated_burst, size_t n_symbols, std::vector<uint8_t> &bits)
    {
      int i;

      bits.clear();

      for(i = 0; i < n_symbols; i++) {
        if(demodulated_burst[i] & 2) {
          bits.push_back(1);
        } else {
          bits.push_back(0);
        }

        if(demodulated_burst[i] & 1) {
          bits.push_back(1);
        } else {
          bits.push_back(0);
        }
      }
    }

    bool
    iridium_qpsk_demod_cpp_impl::check_sync_word(int * demodulated_burst, size_t n_symbols, ::iridium::direction direction)
    {
      if(n_symbols < ::iridium::UW_LENGTH) {
        return false;
      }

      if(direction == ::iridium::direction::DOWNLINK) {
        if(memcmp(demodulated_burst, ::iridium::UW_DL, sizeof(::iridium::UW_DL)) == 0) {
          return true;
        }
      }

      if(direction == ::iridium::direction::UPLINK) {
        if(memcmp(demodulated_burst, ::iridium::UW_UL, sizeof(::iridium::UW_UL)) == 0) {
          return true;
        }
      }

      return false;
    }

    uint64_t
    iridium_qpsk_demod_cpp_impl::get_n_handled_bursts()
    {
      return d_n_handled_bursts;
    }

    uint64_t
    iridium_qpsk_demod_cpp_impl::get_n_access_ok_bursts()
    {
      return d_n_access_ok_bursts;
    }

    void
    iridium_qpsk_demod_cpp_impl::handler(pmt::pmt_t msg)
    {
      pmt::pmt_t samples = pmt::cdr(msg);
      size_t burst_size = pmt::length(samples);
      const gr_complex * burst = (const gr_complex *)pmt::c32vector_elements(samples, burst_size);

      pmt::pmt_t meta = pmt::car(msg);
      float center_frequency = pmt::to_double(pmt::dict_ref(meta, pmt::mp("center_frequency"), pmt::PMT_NIL));
      float sample_rate = pmt::to_double(pmt::dict_ref(meta, pmt::mp("sample_rate"), pmt::PMT_NIL));
      uint64_t id = pmt::to_uint64(pmt::dict_ref(meta, pmt::mp("id"), pmt::PMT_NIL));
      uint64_t offset = pmt::to_uint64(pmt::dict_ref(meta, pmt::mp("offset"), pmt::PMT_NIL));
      int uw_start = pmt::to_long(pmt::dict_ref(meta, pmt::mp("uw_start"), pmt::PMT_NIL));

      int sps = sample_rate / 25000;
      int timestamp = offset / sample_rate * 1000;

      update_buffer_sizes(burst_size);

      // Decimate the burst to one sample per symbol.
      // The first sample is assumed to be the center of the first symbol
      size_t n_symbols = decimate(burst + uw_start, burst_size - uw_start, sps, d_decimated_burst);

#if 1
      // Apply a PLL to the signal to remove any remaining
      // frequency or phase offset
      qpskFirstOrderPLL(d_decimated_burst, n_symbols, d_alpha, d_burst_after_pll);
#else
      memcpy(d_burst_after_pll, d_decimated_burst, n_symbols * sizeof(gr_complex));
#endif

      int confidence;
      float level;
      n_symbols = demod_qpsk(d_burst_after_pll, n_symbols, d_demodulated_burst, &level, &confidence);

      bool dl_uw_ok = check_sync_word(d_demodulated_burst, n_symbols, ::iridium::direction::DOWNLINK);
      bool ul_uw_ok = check_sync_word(d_demodulated_burst, n_symbols, ::iridium::direction::UPLINK);

      d_n_handled_bursts++;

      if(!dl_uw_ok && !ul_uw_ok) {
        // Drop frames which have no valid sync word
        return;
      }

      d_n_access_ok_bursts++;

      decode_deqpsk(d_demodulated_burst, n_symbols);

      map_symbols_to_bits(d_demodulated_burst, n_symbols, d_bits);

      pmt::pmt_t pdu_meta = pmt::make_dict();
      pmt::pmt_t pdu_vector = pmt::init_u8vector(d_bits.size(), d_bits);
      pdu_meta = pmt::dict_add(pdu_meta, pmt::mp("timestamp"), pmt::mp(timestamp));
      pdu_meta = pmt::dict_add(pdu_meta, pmt::mp("center_frequency"), pmt::mp(center_frequency));
      pdu_meta = pmt::dict_add(pdu_meta, pmt::mp("id"), pmt::mp(id));
      pdu_meta = pmt::dict_add(pdu_meta, pmt::mp("confidence"), pmt::mp(confidence));
      pdu_meta = pmt::dict_add(pdu_meta, pmt::mp("level"), pmt::mp(level));
      pdu_meta = pmt::dict_add(pdu_meta, pmt::mp("n_symbols"), pmt::mp((int)n_symbols));
      pdu_meta = pmt::dict_add(pdu_meta, pmt::mp("direction"), pmt::mp((int)(ul_uw_ok?1:0)));

      pmt::pmt_t out_msg = pmt::cons(pdu_meta,
          pdu_vector);
      message_port_pub(pmt::mp("pdus"), out_msg);
    }

    int
    iridium_qpsk_demod_cpp_impl::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {
      return noutput_items;
    }

  } /* namespace iridium */
} /* namespace gr */

